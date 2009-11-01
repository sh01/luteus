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

from .event_multiplexing import OrderingEventMultiplexer, ccd
from gonium.fdm.stream import AsyncLineStream

from .irc_num_constants import *
from .s2c_structures import *


def b2b(bseq):
   return (chr(x).encode('ascii') for x in bseq)


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


class QueryFinish(BaseException):
   pass

class _BlockQuery:
   BQTypes = {}
   cmd = None
   start = None
   def __init__(self, msg, callback):
      if not (msg.prefix is None):
         raise ValueError('Need msg with prefix == None.')
      self.msg = msg
      self.callback = callback
      self.active = False
      self.rv = []
   
   @classmethod
   def reg_class(cls, cls_new):
      cmd = cls_new.cmd
      if not (cmd is None):
         cmd = cmd.upper()
      cls.BQTypes[cmd] = cls_new
      return cls_new
   
   @classmethod
   def build(cls, msg, *args, **kwargs):
      try:
         cls_sub = cls.BQTYPES[msg.command.upper()]
      except KeyError:
         cls_sub = cls.BQTYPES[None]
      
      return cls_sub(msg, *args, **kwargs)
   
   def put_req(self, conn):
      conn.send_msg(self.msg.command, self.msg.parameters)
   
   def get_msg_barriers(self, msg):
      raise NotImplementedError('Not done here; use a subclass instead.')
   
   def is_tryagain(self, msg, num):
      return ((num == RPL_TRYAGAIN) and (len(msg.parameters) > 0) and
         (msg.parameters[0].upper() == self.msg.command.upper()))

   def process_data(self, msg):
      if (self.is_tryagain(msg, msg.get_cmd_numeric())):
         # Server didn't feel like processing this command.
         is_start = True
         is_end = True
      else:
         (is_start, is_end) = self.get_msg_barriers(msg)
      
      if (not self.active):
         if (is_start):
            self.active = True
         else:
            return False
      
      self.rv.append(msg)
      if (is_end):
         self.active = False
         self.callback(self)
         raise QueryFinish()
      
      return True

# If it's stupid but it works, it isn't stupid. It is, however, a hack.
# There's various queries whose response blocks don't have an end-marker
# consistent over all common IRC dialects; culprits include LUSERS and ADMIN.
# However, virtually all modern IRC servers implement PONG responses that
# return the first argument as specified in the answered PING; this behaviour
# doesn't at all reflect the descriptions in RFC 1459 or 2812, but can be
# relied upon in practice.
# We can exploit this behaviour to get a clear end-marker for any block request,
# though there is a potential for race conditions here. Filtering out
# non-numeric lines takes care of most of this; spurious numerics are very
# rare.
@_BlockQuery.reg_class
class BlockQueryGeneric(_BlockQuery):
   cmd = None
   def __init__(self, *args, **kwargs):
      import random
      _BlockQuery.__init__(self, *args, **kwargs)
      self.stop_tok = bytes(random.getrandbits(64))
      self.active = False
   
   def put_req(self, conn):
      conn.send_msg(self.msg.command, self.msg.parameters)
      conn.send_msg('PING', (self.stop_tok,))
      self.active = True
   
   def process_data(self, msg):
      if (not self.active):
         return False
      cmd = msg.command
      if (msg.get_cmd_numeric() is None):
         if ((cmd.upper() == 'PONG') and (len(cmd.parameters) > 0) and
             (parameters[0] == self.stop_tok)):
            self.active = False
            self.callback(self)
            raise QueryFinish()
         return False
      
      self.rv.append(msg)
      return True


@_BlockQuery.reg_class
class BlockQueryWHOIS(_BlockQuery):
   cmd = 'WHOIS'
   end_num = 318
   start_nums = set((311,312,313,317,end_num,319))
   
   def __init__(self, msg, *args, **kwargs):
      _BlockQuery.__init__(self, msg, *args, **kwargs)
      pc = len(self.msg.parameters)
      if (pc < 1):
         self.target = None
      else:
         self.target = IRCAddress(self.msg.parameters[(pc > 1)])
   
   def get_msg_barriers(self, msg):
      cmd_i = msg.get_cmd_numeric()
      
      if (cmd_i is None):
         return (False, False)
      
      if (cmd_i == ERR_NONICKNAMEGIVEN):
         if (self.target is None):
            # What was our client thinking?
            return (True, True)
         # This wasn't our fault. Go on.
         return (False, False)
      
      if (len(msg.parameters) < 2):
         return (False, False)
      target = IRCAddress(msg.parameters[1])
      if (target != self.target):
         return (False, False)
      
      if (cmd_i in self.start_nums):
         return (True, (cmd_i == self.end_num))
      return (False, False)


@_BlockQuery.reg_class
class BlockQueryWHOWAS(BlockQueryWHOIS):
   cmd = 'WHOWAS'
   end_num = 369
   start_nums = set((314,312,313,317,end_num,319))
   
   def __init__(self, msg, *args, **kwargs):
      _BlockQuery.__init__(self, msg, *args, **kwargs)
      pc = len(self.msg.parameters)
      if (pc < 1):
         self.target = None
      else:
         self.target = IRCAddress(self.msg.parameters[0])

@_BlockQuery.reg_class
class BlockQueryLINKS(_BlockQuery):
   cmd = 'LINKS'
   def get_msg_barriers(self, msg):
      num = msg.get_cmd_numeric()
      return (num in (ERR_NOSUCHSERVER, RPL_LINKS),
      (num == RPL_ENDOFLINKS))

@_BlockQuery.reg_class
class BlockQueryLIST(_BlockQuery):
   cmd = 'LIST'
   def get_msg_barriers(self, msg):
      num = msg.get_cmd_numeric()
      return (num in (RPL_LISTSTART, RPL_LIST, RPL_LISTEND),
         (num == RPL_LISTEND))


class IRCClientConnection(AsyncLineStream):
   logger = logging.getLogger('IRCConnection')
   log = logger.log
   
   IRCNICK_INITCHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}'
   
   EM_NAMES = ('em_in_raw', 'em_in_msg', 'em_in_msg_ap', 'em_out_msg',
      'em_link_finish', 'em_shutdown', 'em_chmode', 'em_chan_join',
      'em_chan_leave')
   #calling conventions:
   # em_in_raw(msg: bytearray)
   # em_in_msg(msg: IRCMessage)
   # em_link_finish()
   # em_chan_join(nick, chan)
   #   <nick> is None for self-joins
   # em_chan_leave(victim, chan, perpetrator)
   #   <victim> is None for self-leaves
   #   <perpetrator> is None for PARTs and self-kicks
   
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
      
      for name in self.EM_NAMES:
         self.em_new(name)
      
      AsyncLineStream.__init__(self, *args, lineseps={b'\n', b'\r'}, **kwargs)
   
   def em_new(self, attr):
      """Instantiate new EventMultiplexer attribute"""
      setattr(self, attr, OrderingEventMultiplexer(self))
   
   def process_input(self, line_data_mv):
      """Process IRC data"""
      line_data = bytearray(bytes(line_data_mv).rstrip(b'\r\n'))
      if (self.em_in_raw(line_data)):
         return
      if (line_data == b''):
         return
      msg = IRCMessage.build_from_line(line_data)
      if (self.em_in_msg(msg)):
         return
      
      try:
         cmd_str = msg.command.decode('ascii')
      except UnicodeDecodeError:
         self.log(20, 'Peer {0} sent unknown message {1}.'.format(self.peer_address, msg))
      else:
         fn = '_process_msg_{0}'.format(cmd_str)
         try:
            func = getattr(self,fn)
         except AttributeError:
            self.log(20, 'Peer {0} sent unknown message {1}.'.format(self.peer_address, msg))
            
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
               self.log(30, 'From {0}: msg {1} failed to process: {2}'.format(
                  self.peer_address, msg, exc), exc_info=True)
      
      self.em_in_msg_ap(msg)
   
   def send_msg(self, command, *parameters):
      """Send MSG to peer."""
      msg = IRCMessage(None, command, parameters)
      self.em_out_msg(msg)
      line_out = msg.line_build()
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
               try:
                  del(chan.users[nick])
               except KeyError as exc:
                  raise IRCProtocolError('KICKed nick {0!a} not on chan.'.format(nick)) from exc
            
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
      if not (chan in self.channels):
         raise IRCProtocolError(msg, "Not on chan {0!a}.".format(chan))
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
   
   # Things not impacting connection state
   def _process_msg_PRIVMSG(self, msg):
      pass
   def _process_msg_NOTICE(self, msg):
      pass

# ---------------------------------------------------------------- test code
class __ChanEcho:
   def __init__(self, conn, chan):
      self.conn = conn
      def ip_ret(n):
         @ccd(0)
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
   irccc.em_shutdown.new_listener(ccd(1)(ed.shutdown))
   irccc.em_link_finish.new_listener(ccd(1)(link))
   
   if (channels):
      __ChanEcho(irccc, channels[0])
   
   ed.event_loop()


if (__name__ == '__main__'):
   import sys
   _selftest((sys.argv[1],6667),channels=(sys.argv[2].encode('ascii'),))
