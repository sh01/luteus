#!/usr/bin/env python
#Copyright 2009 Sebastian Hagen
# This file is part of luteus.
#
# luteus is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# luteus is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with luteus.  If not, see <http://www.gnu.org/licenses/>.

import logging

from gonium.event_multiplexing import EventMultiplexer
from gonium.fdm.stream import AsyncLineStream


class IRCProtocolError(ValueError):
   def __init__(self, msg, *args, **kwargs):
      self.msg = msg
      ValueError.__init__(self, *args, **kwargs)


IA_SERVER = 0
IA_NICK = 1

class IRCAddress(bytes):
   def __init__(self, *args, **kwargs):
      bytes.__init__(self, *args, **kwargs)
      if not (b'!' in self):
         if (b'.' in self):
            self.type = IA_SERVER
         else:
            self.type = IA_NICK
            self.nick = self
            self.hostmask = None
            self.user = None
         return
      
      self.type = IA_NICK
      (nick, rest) = self.split(b'!',1)
      self.nick = IRCNick(nick)
      (user, hostmask) = rest.split(b'@',1)
      self.hostmask = hostmask
   
   def target_get(self):
      """Return target bytes sequence"""
      if (self.type == IA_SERVER):
         return self
      return self.nick
   
   def irc_eq(self, other):
      """IRC equality testing"""
      if (self.type != other.type):
         return False
      if (self.type == IA_SERVER):
         return (self == other)
      return (self.nick == other.nick)


class IRCNick(bytes):
   LOWERMAP = bytearray(range(256))
   for i in range(ord(b'A'), ord(b'Z')+1):
      LOWERMAP[i] = ord(chr(i).lower())
   LOWERMAP[ord(b'[')] = ord(b'{')
   LOWERMAP[ord(b']')] = ord(b'}')
   LOWERMAP[ord(b'\\')] = ord(b'|')
   LOWERMAP[ord(b'~')] = ord(b'^')
   LOWERMAP = bytes(LOWERMAP)
   
   def __eq__(self, other):
      return (self.translate(self.LOWERMAP) == other.translate(self.LOWERMAP))
   def __neq__(self, other):
      return not (self == other)
   def __hash__(self):
      return bytes.__hash__(self.translate(self.LOWERMAP))
   # FIXME: add ordering


class IRCMessage:
   """An IRC message, as defined by RFC 2812"""
   def __init__(self, prefix:bytes, command:bytes, parameters:bytes):
      self.prefix = prefix
      self.command = command
      self.parameters = parameters
   
   @classmethod
   def build_from_line(cls, line):
      """Build instance from raw line"""
      line_split = line.split(b' ') # RFC 2812 says this is correct.
      if (line.startswith(b':')):
         prefix = IRCAddress(line_split[0][1:])
         command = line_split[1]
         parameters = line_split[2:]
      else:
         prefix = None
         command = line_split[0]
         parameters = line_split[1:]
      
      i = 0
      while (i < len(parameters)):
         p = parameters[i]
         if not (p.startswith(b':')):
            i += 1
            continue
         parameters[i] = b' '.join([parameters[i][1:]] + parameters[i+1:])
         del(parameters[i+1:])
         break
      return cls(prefix, command, tuple(parameters))
   
   def line_build(self):
      if (self.prefix is None):
         prefix = []
      else:
         prefix = [b':' + self.prefix]
      
      params_out = list(self.parameters)
      params_out[-1] = b':' + params_out[-1]
      
      for param in params_out[:-1]:
         if (b' ' in param):
            raise ValueError('Parameter list {0} contains non-last'
               'parameter containing a space.'.format(params_out))
      
      return b' '.join(prefix + [self.command] + params_out) + b'\r\n'
   
   def __repr__(self):
      return '{0}.build_from_line({1!a})'.format(
         self.__class__.__name__, self.line_build()[:-1])


class IRCChannel:
   def __init__(self, chan):
      self.chan = chan
      self.topic = None
      self.users = None


class IRCClientConnection(AsyncLineStream):
   logger = logging.getLogger('IRCConnection')
   log = logger.log
   
   IRCNICK_INITCHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}'
   
   def __init__(self, *args, nick, username, realname, mode=0, **kwargs):
      if (isinstance(nick, str)):
         nick = nick.encode('ascii')
      if (isinstance(username, str)):
         username = username.encode('ascii')
      if (isinstance(realname, str)):
         realname = realname.encode('ascii')
      self.wnick = nick
      self.nick = nick
      self.realname = realname
      self.username = username
      self.mode = mode
      
      # connection state
      self.motd = None
      self.motd_pending = None
      self.link_done = False
      self.channels = {}
      
      self.em_in_raw = EventMultiplexer(self)
      self.em_in_msg = EventMultiplexer(self)
      self.em_out_msg = EventMultiplexer(self)
      self.em_link_finish = EventMultiplexer(self)
      self.em_shutdown = EventMultiplexer(self)
      AsyncLineStream.__init__(self, *args, lineseps={b'\n', b'\r'}, **kwargs)
      
   def process_input(self, line_data_mv):
      """Process IRC data"""
      line_data = bytearray(bytes(line_data_mv).rstrip(b'\r\n'))
      self.em_in_raw(line_data)
      if (line_data == b''):
         return
      msg = IRCMessage.build_from_line(line_data)
      self.em_in_msg(msg)
      
      got_func = False
      try:
         cmd_str = msg.command.decode('ascii')
      except UnicodeDecodeError:
         pass
      else:
         fn = '_process_msg_{0}'.format(cmd_str)
         try:
            func = getattr(self,fn)
         except AttributeError:
            pass
         else:
            try:
               func(msg)
            except IRCProtocolError as exc:
               self.log(30, 'From {0}: msg {1} failed to parse: {2}'.format(
                  self.peer_address, msg, exc))
            got_func = True
      
      if (got_func is False):
         self.log(20, 'Peer {0} sent unknown message {1}.'.format(self.peer_address, msg))
   
   def send_msg(self, command, *parameters):
      """Send MSG to peer."""
      msg = IRCMessage(None, command, parameters)
      self.em_out_msg(msg)
      line_out = msg.line_build()
      if ((b'\x00' in line_out) or (b'\x0a' in line_out[:-2]) or
         (b'\r' in line_out[:-2])):
         raise ValueError('Trying to send line {0!a}, which contains an invalid'
            ' char.'.format(line_out))
      self.send_bytes((line_out,))
   
   @classmethod
   def irc_build_sock_connect(cls, ed, address, *args, **kwargs):
      def process_connect(__rv):
         rv._process_connect()
      
      rv = cls.build_sock_connect(ed, address,
         connect_callback=process_connect, *args, **kwargs)
      rv.peer_address = address
      return rv
   
   def _pc_check(self, msg, num:int):
      """Throw exception if msg has less than the specified number of
         parameters."""
      if (len(msg.parameters) < num):
         raise IRCProtocolError(msg, 'Insufficient arguments; expected at least'
            ' {0}.'.format(num))
   
   def _process_connect(self):
      """Process connect finish."""
      self.send_msg(b'NICK', self.wnick)
      self.send_msg(b'USER', self.username, str(self.mode).encode('ascii'),
         b'*', self.realname)
      self.nick = IRCNick(self.wnick) # FIXME: figure out how to choose alternatives
   
   def process_close(self):
      """Process connection closing."""
      self.em_shutdown()
   
   def _process_msg_PING(self, msg):
      """Answer PING."""
      self.send_msg(b'PONG', *msg.parameters)
   
   def _process_msg_JOIN(self, msg):
      """Process JOIN message."""
      self._pc_check(msg, 1)
      if ((msg.prefix is None) or (msg.prefix.type != IA_NICK)):
         raise IRCProtocolError('Non-nick trying to join channel.')
      
      # RFC 2812 allows servers to use join-lists in JOIN messages to clients.
      chans = msg.parameters[0].split(b',')
      for chan in chans:
         if (msg.prefix.nick == self.nick):
            # Our join.
            if (chan in self.channels):
               raise IRCProtocolError("Joining channel we're already in.")
            self.channels[chan] = IRCChannel(chan)
            continue
         
         if (not chan in self.channels):
            # Iffy: *IS* this is an error?
            raise IRCProtocolError("JOIN message for channel we aren't on.")
         self.channels[chan].users[msg.prefix.nick] = set()
   
   # connect numerics
   def _process_msg_001(self, msg):
      """Process RPL_WELCOME message."""
      pass
   
   # MOTD
   def _process_msg_375(self, msg):
      """Process MOTD start"""
      self.motd_pending = []
   
   def _process_msg_372(self, msg):
      """Process MOTD line"""
      if (self.motd_pending is None):
         self.log(30, 'From {1}: got MOTD line {0} without preceding 375.'
            'Ignoring.'.format(self.peer_address, msg))
         return
      self._pc_check(msg, 2)
      self.motd_pending.append(msg.parameters[1])
   
   def _process_msg_376(self, msg):
      """Process MOTD end"""
      self.motd = tuple(self.motd_pending)
      self.motd_pending = None
      self.link_done = True
      self.em_link_finish()
   
   # replies to JOIN request
   def _process_msg_331(self, msg):
      """Process RPL_NOTOPIC message"""
      self._pc_check(msg, 2)
      chan = bytes(msg.parameters[1])
      if not (chan in self.channels):
         raise IRCProtocolError(msg, "Not on chan {0!a}.".format(chan))
      self.channels[chan].topic = False
      
   def _process_msg_332(self, msg):
      """Process RPL_TOPIC message"""
      self._pc_check(msg, 3)
      chan = bytes(msg.parameters[1])
      if not (chan in self.channels):
         raise IRCProtocolError(msg, "Not on chan {0!a}.".format(chan))
      self.channels[chan].topic = msg.parameters[2]
   
   def _process_msg_353(self, msg):
      """Process RPL_NAMREPLY message."""
      self._pc_check(msg, 4)
      chan = self.channels[bytes(msg.parameters[2])]
      chan.users = {}
      for nick_str in msg.parameters[3].split(b' '):
         i = 0
         for c in nick_str:
            if (c in self.IRCNICK_INITCHARS):
               break
            i += 1
         nick = IRCNick(nick_str[i:])
         
         chan.users[nick] = set()
         for b in nick_str[:i]:
            chan.users[nick].add(chr(b).encode('ascii'))


def _selftest(target, nick='Zanaffar', username='chimera', realname=b'? ? ?',
      channels=()):
   from gonium.fdm import ED_get
   from gonium._debugging import streamlogger_setup
   
   def link():
      for chan in channels:
         irccc.send_msg(b'JOIN', chan)
   
   streamlogger_setup()
   ed = ED_get()()
   irccc = IRCClientConnection.irc_build_sock_connect(ed, target, nick=nick,
      username=username, realname=realname)
   irccc.em_shutdown.new_listener(ed.shutdown)
   irccc.em_link_finish.new_listener(link)
   ed.event_loop()


if (__name__ == '__main__'):
   import sys
   _selftest((sys.argv[1],6667),channels=(sys.argv[2].encode('ascii'),))
