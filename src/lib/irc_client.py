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


def b2b(bseq):
   return (chr(x).encode('ascii') for x in bseq)


class IRCProtocolError(ValueError):
   def __init__(self, msg, *args, **kwargs):
      self.msg = msg
      ValueError.__init__(self, *args, **kwargs)

# IRC Address Types
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
            self.nick = IRCNick(self)
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
   def __init__(self, chan, topic=None, users=None, modes=None,
         expect_part=False):
      self.chan = chan
      self.topic = topic
      self.users = users
      if (modes is None):
         modes = {}
      self.modes = modes
      self.expect_part = expect_part
   def __repr__(self):
      return '{0}({1}, {2}, {3}, {4}, {5})'.format(self.__class__.__name__,
         self.chan, self.topic, self.users, self.modes, self.expect_part)


class Mode:
   def __init__(self, char, level):
      self.char = char
      self.level = level
   
   def __repr__(self):
      return '{0}({1},{2})'.format(self.__class__.__name__, self.char, self.level)
   def __le__(self, other):
      return (self.level <= other.level)
   def __lt__(self, other):
      return (self.level < other.level)
   def __ge__(self, other):
      return (self.level <= other.level)
   def __gt__(self, other):
      return (self.level > other.level)
   def __eq__(self, other):
      return (self.char == other.char)
   def __neq__(self, other):
      return (self.char != other.char)
   def __hash__(self):
      return hash(self.char)


class ChannelModeParser:
   def __init__(self,
      userflags=((b'o',b'@'),(b'v',b'+')), # flags associated with a nick on the channel
      listmodes=(b'b'),  # modes manipulating list-type channel attributes
      boolmodes=(b'p',b's',b'i',b't',b'n',b'm'),   # boolean channel modes
      strmodes=(b'k'),    # channel modes defined by a string value
      strmodes_opt=(b'l') # same, but unsettable by ommitting the argument
      ):
      self.userflags_set(userflags)
      self.lmodes = frozenset(listmodes)
      self.bmodes = frozenset(boolmodes)
      self.smodes = frozenset(strmodes)
      self.smodes_opt = frozenset(strmodes_opt)
   
   def userflags_set(self, userflags):
      self.uflags2modes = {}
      self.umodes2flags = {}
      self.umodes2umodes = {}
      level = 0
      for (m, flag) in reversed(userflags):
         mode = Mode(m, level)
         self.uflags2modes[flag] = mode
         self.umodes2flags[m] = flag
         self.umodes2umodes[m] = mode
         level += 1
   
   def process_ISUPPORT_PREFIX(self, prefix):
      """Process PREFIX arg value from RPL_ISUPPORT(005) message"""
      if (not prefix.startswith(b'(')):
         raise ValueError('Invalid PREFIX val {0}'.format(prefix))
      i = prefix.index(b')')
      
      modes = prefix[1:i]
      flags = prefix[i+1:]
      if (len(flags) != len(modes)):
         raise ValueError('Invalid PREFIX val {0}'.format(prefix))
      
      self.userflags_set([(e[0],e[1]) for e in zip(b2b(modes),b2b(flags))])
   
   def process_ISUPPORT_CHANMODES(self, chm):
      """Process CHANMODES arg value from RPL_ISUPPORT(005) message"""
      try:
         (chm_l, chm_str, chm_str_opt, chm_bool) = chm.split(b',')
      except ValueError as exc:
         raise IRCProtocolError('Bogus CHANMODES value') from exc
      self.lmodes = frozenset(b2b(chm_l))
      self.bmodes = frozenset(b2b(chm_bool))
      self.smodes = frozenset(b2b(chm_str))
      self.smodes_opt = frozenset(b2b(chm_str_opt))
   
   def chan_init(self, chan):
      for mode in self.bmodes:
         chan.modes[mode] = False
      for mode in self.lmodes:
         chan.modes[mode] = set()
      for mode in self.smodes:
         chan.modes[mode] = None
      for mode in self.smodes_opt:
         chan.modes[mode] = None
   
   def set_chmodes(self, log, chan, modeargs):
      if (len(modeargs) < 1):
         raise IRCProtocolError('Insufficient args for MODE')
      mseq = modeargs[0]
      arg_i = 1
      set = True
      
      try:
         for m in b2b(mseq):
            if (m == b'+'):
               set = True
            elif (m == b'-'):
               set = False
            elif (m in self.bmodes):
               chan.modes[m] = set
            elif (m in self.smodes):
               if (set):
                  chan.modes[m] = modeargs[arg_i]
               else:
                  chan.modes[m] = None
               arg_i += 1
            elif (m in self.smodes_opt):
               if (set):
                  chan.modes[m] = modeargs[arg_i]
                  arg_i += 1
               else:
                  chan.modes[m] = None
            elif (m in self.lmodes):
               if (set):
                  chan.modes[m].add(modeargs[arg_i])
               else:
                  chan.modes[m].remove(modeargs[arg_i])
            elif (m in self.umodes2umodes):
               umode = self.umodes2umodes[m]
               nick = IRCNick(modeargs[arg_i])
               if (set):
                  if (umode in chan.users[nick]):
                     raise IRCProtocolError("Attempting to set present umode")
                  chan.users[nick].add(umode)
               else:
                  try:
                     chan.users[nick].remove(umode)
                  except KeyError as exc:
                     if (max(chan.users[nick]) < umode):
                        raise
                     # This can happen for NAMES prefixes that only indicate
                     # highest-valued user mode. Nothing we can do about it.
               arg_i += 1
            else:
               raise IRCProtocolError('Unknown mode {0}.'.format(m))
      
      except (KeyError, IndexError) as exc:
         raise IRCProtocolError('Failed to parse MODE.') from exc


class IRCClientConnection(AsyncLineStream):
   logger = logging.getLogger('IRCConnection')
   log = logger.log
   
   IRCNICK_INITCHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}'
   
   def __init__(self, *args, nick, username, realname, mode=0, chm_parser=None,
         **kwargs):
      if (isinstance(nick, str)):
         nick = nick.encode('ascii')
      if (isinstance(username, str)):
         username = username.encode('ascii')
      if (isinstance(realname, str)):
         realname = realname.encode('ascii')
      self.wnick = nick
      self.nick = None
      self.realname = realname
      self.username = username
      self.mode = mode
      self.modes = set()
      
      if (chm_parser is None):
         chm_parser = ChannelModeParser()
      self.chm_parser = chm_parser
      
      # connection state
      self.peer = None
      self.link_done = False
      self.motd = None
      self.motd_pending = None
      self.channels = {}
      
      self.em_in_raw = EventMultiplexer(self)
      self.em_in_msg = EventMultiplexer(self)
      self.em_out_msg = EventMultiplexer(self)
      self.em_link_finish = EventMultiplexer(self)
      self.em_shutdown = EventMultiplexer(self)
      self.em_chmode = EventMultiplexer(self)
      
      # called with <nick> (None for self), <chan>.
      self.em_chan_join = EventMultiplexer(self)
      # called with <victim> (None for self), <chan>, <perpetrator> (None for
      # PARTs and self-kicks)
      self.em_chan_leave = EventMultiplexer(self)
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
            if (cmd_str.isdigit()):
               # Numeric replies are always targeted to our nick.
               if (not msg.parameters):
                  self.log(30, 'From {0}: bogus numeric: {1}'.format(
                     self.peer_address, msg))
               else:
                  nick = msg.parameters[0]
                  if (self.nick != nick):
                     if (not (self.nick is None)):
                        self.log(30, 'From {0}: missed a nickchange from {0} '
                           'to {1}.'.format(self.peer_address, self.nick, nick))
                     self.nick = nick
            
            try:
               func(msg)
            except IRCProtocolError as exc:
               self.log(30, 'From {0}: msg {1} failed to parse: {2}'.format(
                  self.peer_address, msg, exc), exc_info=True)
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
      chnns = bytes(msg.parameters[0]).split(b',')
      for chnn in chnns:
         if (msg.prefix.nick == self.nick):
            # Our join.
            if (chnn in self.channels):
               raise IRCProtocolError("Joining channel we're already in.")
            chan = IRCChannel(chnn)
            self.channels[chnn] = chan
            self.chm_parser.chan_init(chan)
            self.em_chan_join(None, chan)
            continue
         
         if (not chnn in self.channels):
            # Iffy: *IS* this is an error?
            raise IRCProtocolError("JOIN message for channel we aren't on.")
         chanusers = self.channels[chnn].users
         if (msg.prefix.nick in chanusers):
            raise IRCProtocolError("User joining channel they are already on.")
         chanusers[msg.prefix.nick] = set()
         self.em_chan_join(msg.prefix.nick, self.channels[chnn])
   
   def _process_msg_PART(self, msg):
      """Process PART message."""
      self._pc_check(msg, 1)
      chans = bytes(msg.parameters[0]).split(b',')
      
      if ((msg.prefix is None) or (msg.prefix.type != IA_NICK)):
         raise IRCPRotocolError('Bogus PART prefix.')
      nick = msg.prefix.nick
      
      if (len(msg.parameters) > 1):
         reason = msg.parameters[1]
      else:
         reason = None
      
      for chnn in chans:
         if (not chnn in self.channels):
            raise IRCProtocolError("PART message for channel we aren't on.")
         chan = self.channels[chnn]
         if (not nick in chan.users):
            raise IRCProtocolError("PARTed user not on channel.")
         
         self.em_chan_leave(nick, chan, None)
         if (nick == self.nick):
            del(self.channels[chnn])
            break
         del(chan.users[nick])
   
   def _process_msg_KICK(self, msg):
      """Process KICK message."""
      self._pc_check(msg, 2)
      # RFC 2812 says that multi-target lists can't occur in this direction;
      # no matter, it's safer to support them anyway.
      chans = bytes(msg.parameters[0]).split(b',')
      nicks = bytes(msg.parameters[1]).split(b',')
      
      for chnn in chans:
         if not (chnn in self.channels):
            raise IRCProtocolError("KICK message for channel we aren't on.")
         
         chan = self.channels[chnn]
         for nick in nicks:
            if (msg.prefix is None):
               perpetrator = self.peer
            elif ((msg.prefix.type == IA_NICK) and (nick == msg.prefix.nick)):
               perpetrator = None
            else:
               perpetrator = msg.prefix
            self.em_chan_leave(nick, chan, perpetrator)
            
            if (nick != self.nick):
               del(chan.users[nick])
            
            if (nick == self.nick):
               # Our part.
               del(self.channels[chnn])
               break
   
   def _process_msg_MODE(self, msg):
      """Process MODE message."""
      self._pc_check(msg, 2)
      victim = bytes(msg.parameters[0])
      if (victim[0] in self.IRCNICK_INITCHARS):
         #nick mode
         if (victim != self.nick):
            raise IRCProtocolError('Bogus target for user mode.')
         set = True
         try:
            for m in msg.parameters[1]:
               if (m == b'+'):
                  set = True
               elif (m == b'-'):
                  set = False
               elif (set):
                  self.modes.add(m)
               else:
                  self.modes.remove(m)
         except KeyError as exc:
            raise IRCProtocolError('Trying to remove unset user mode {0}.'
               ''.format(m)) from KeyError
         return
      
      # channel mode
      try:
         chan = self.channels[victim]
      except KeyError as exc:
         raise IRCProtocolError("Got MODE message for channel {0} I'm not on."
            ''.format(victim)) from exc
      
      self.chm_parser.set_chmodes(self.log, chan, msg.parameters[1:])
      self.em_chmode(chan, msg.parameters)
   
   # connect numerics
   def _process_msg_001(self, msg):
      """Process RPL_WELCOME message."""
      self.peer = (self.peer or msg.prefix)
   
   def _process_msg_004(self, msg):
      """Process RPL_MYINFO message."""
      if ((self.peer is None) and (msg.parameters)):
         self.peer = msg.parameters[0]
   
   def _process_msg_005(self, msg):
      """Process RPL_ISUPPORT message"""
      if (msg.parameters[0] == self.nick):
         args = list(msg.parameters[1:])
      else:
         args = list(msg.parameters)

      # draft-brocklesby-irc-isupport mandates the last argument to be used for
      # a silly human-readable explanation; and indeed this is done by at least
      # some existing implementations. Discard it, if present.
      if (b' ' in args[-1]):
         del(args[-1])
      
      for is_arg in args:
         if (b'=' in is_arg):
            (name,val) = is_arg.split(b'=',1)
            if (val == b''):
               val = True
         elif (is_arg.startswith(b'-')):
            name = is_arg[1:]
            val = False
         else:
            name = is_arg
            val = True
     
         if (name.upper() in (b'PREFIX', b'CHANMODES')):
            if (val is True):
               val = ''
            if (name.upper() == b'PREFIX'):
               self.chm_parser.process_ISUPPORT_PREFIX(val)
               self.log(20, '{0} parsed prefix data from 005.'.format(self))
            else:
               self.chm_parser.process_ISUPPORT_CHANMODES(val)
               self.log(20, '{0} parsed chanmodes data from 005.'.format(self))
   
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
      if (not self.link_done):
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
         for b in b2b(nick_str[:i]):
            chan.users[nick].add(self.chm_parser.uflags2modes[b])

# ---------------------------------------------------------------- test code
class __ChanEcho:
   def __init__(self, conn, chan):
      self.conn = conn
      def ip_ret(n):
         def _info_print(*args, **kwargs):
            if (not conn):
               return
            conn.send_msg(b'PRIVMSG', chan, '{0}: {1} {2}'.format(n, args, kwargs).encode('ascii'))
         
         return _info_print
      
      for name in conn.__dict__:
         if (not name.startswith('em_')):
            continue
         if (name.endswith('_msg') or name.endswith('_raw')):
            continue
         
         getattr(conn, name).new_listener(ip_ret(name))
      

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
   
   if (channels):
      __ChanEcho(irccc, channels[0])
   
   ed.event_loop()


if (__name__ == '__main__'):
   import sys
   _selftest((sys.argv[1],6667),channels=(sys.argv[2].encode('ascii'),))
