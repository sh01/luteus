#!/usr/bin/env python
#Copyright 2009,2010,2012,2013,2016 Sebastian Hagen
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
import time

from collections import deque

from .event_multiplexing import OrderingEventMultiplexer, ccd
from gonium.fdm.stream import AsyncLineStream

from .irc_num_constants import *
from .s2c_structures import *


def b2b(bseq):
   return (chr(x).encode('ascii') for x in bseq)

def build_ping_tok():
   import random
   return ('C{0:x}'.format(random.getrandbits(64)).encode('ascii'))

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
   
   def get_uflagstring(self, modes):
      return b''.join([self.umodes2flags[m.char] for m in reversed(sorted(modes))])
   
   def process_ISUPPORT_PREFIX(self, prefix):
      """Process PREFIX arg value from RPL_ISUPPORT(005) message"""
      if (not prefix.startswith(b'(')):
         raise IRCProtocolError('Invalid PREFIX val {0}'.format(prefix))
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
   
   def set_chmodes(self, pcs, log, chan, modeargs):
      if (len(modeargs) < 1):
         raise IRCProtocolError('Insufficient args for MODE')
      
      modeargs = [bytes(m) for m in modeargs]
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
               nick = pcs.make_cib(modeargs[arg_i])
               user = chan.users[nick]
               # Some IRC servers *will* push redundant MODE messages to clients if indicated through S2S commands, either
               # setting modes that are already present or unsetting ones which are not, so such messages do not imply that
               # we lost sync with the server.
               # This has been observed in practice on EUIRC due to IRC services racing the resynch sequence of a split
               # server.
               if (set):
                  user.add(umode)
               else:
                  user.discard(umode)

               arg_i += 1
            else:
               raise IRCProtocolError('Unknown mode {0}.'.format(m))
      
      except (KeyError, IndexError) as exc:
         raise IRCProtocolError('Failed to parse MODE.') from exc


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
   
   @staticmethod
   def _donothing(*args, **kwargs):
      pass
   
   def void(self):
      self.callback = self._donothing
   
   def timeout(self):
      self.active = False
      self.rv = []
      self.callback(self)
   
   @classmethod
   def reg_class(cls, cls_new):
      for cmd in cls_new.cmds:
         cls.BQTypes[cmd.upper()] = cls_new
      
      return cls_new
   
   @classmethod
   def build(cls, msg, *args, **kwargs):
      return cls.BQTypes[msg.command.upper()](msg, *args, **kwargs)
   
   def put_req(self, conn):
      conn.send_msg(self.msg)
   
   def get_msg_barriers(self, msg):
      raise NotImplementedError('Not done here; use a subclass instead.')
   
   def is_genericfail(self, msg):
      num = msg.get_cmd_numeric()
      if ((num in (RPL_TRYAGAIN, ERR_UNKNOWNCOMMAND, ERR_NEEDMOREPARAMS)) and
         (len(msg.parameters) > 1) and
         (msg.parameters[1].upper() == self.msg.command)):
         # TODO: Some networks (e.g. rizon) do RPL_TRYAGAIN wrong, not specifying the failed command. We should probably
         # account for that at some point.
         return True
      if ((num == ERR_NOTREGISTERED) and (len(msg.parameters) > 0) and
          (msg.parameters[0].upper() == self.msg.command)):
         return True
      return False

   def process_data(self, msg):
      if (self.is_genericfail(msg)):
         # Server didn't like this command.
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
         return 2
      
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
# MAP is a pretty bad offender, too; different ircds don't agree about the
# format of the data lines used, never mind start and end markers. Some limit
# the command to opers, so there's also the fun problem of accounting for all
# possible errors.
@_BlockQuery.reg_class
class BlockQueryGeneric(_BlockQuery):
   cmds = (b'ADMIN', b'LUSERS', b'MAP')
   def __init__(self, *args, **kwargs):
      _BlockQuery.__init__(self, *args, **kwargs)
      self.stop_tok = build_ping_tok()
      self.active = False
   
   def put_req(self, conn):
      conn.send_msg(self.msg)
      conn._send_msg(b'PING', self.stop_tok)
      self.active = True
   
   def process_data(self, msg):
      if (not self.active):
         return False
      cmd = msg.command
      if (self.is_genericfail(msg)):
         # At least some ircds won't even process PINGs before user login,
         # so we should still check for this.
         self.rv.append(msg)
         self.active = False
         self.callback(self)
         return 2
      
      if (msg.get_cmd_numeric() is None):
         if ((cmd == b'PONG') and (len(msg.parameters) == 2) and (msg.parameters[1] == self.stop_tok)):
            self.active = False
            self.callback(self)
            return 2
         return False
      
      self.rv.append(msg)
      return True


@_BlockQuery.reg_class
class BlockQueryWHOIS(_BlockQuery):
   cmds = (b'WHOIS',)
   end_num = RPL_ENDOFWHOIS
   start_nums = set((RPL_WHOISUSER, RPL_WHOISSERVER, RPL_WHOISOPERATOR,
      RPL_WHOISIDLE, end_num, RPL_WHOISCHANNELS))
   
   def __init__(self, msg, *args, **kwargs):
      _BlockQuery.__init__(self, msg, *args, **kwargs)
      pc = len(self.msg.parameters)
      if (pc < 1):
         self.target = None
      else:
         self.target = msg.pcs.make_irc_addr(self.msg.parameters[(pc > 1)])
   
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
      target = msg.pcs.make_irc_addr(msg.parameters[1])
      if (target != self.target):
         return (False, False)
      
      if (cmd_i in self.start_nums):
         return (True, (cmd_i == self.end_num))
      return (False, False)


@_BlockQuery.reg_class
class BlockQueryWHOWAS(BlockQueryWHOIS):
   cmds = (b'WHOWAS',)
   end_num = RPL_ENDOFWHOWAS
   start_nums = set((RPL_WHOWASUSER, RPL_WHOISSERVER, RPL_WHOISOPERATOR,
      RPL_WHOISIDLE, end_num, RPL_WHOISCHANNELS))
   
   def __init__(self, msg, *args, **kwargs):
      _BlockQuery.__init__(self, msg, *args, **kwargs)
      pc = len(self.msg.parameters)
      if (pc < 1):
         self.target = None
      else:
         self.target = msg.pcs.make_irc_addr(self.msg.parameters[0])


@_BlockQuery.reg_class
class BlockQueryLINKS(_BlockQuery):
   cmds = (b'LINKS',)
   def get_msg_barriers(self, msg):
      num = msg.get_cmd_numeric()
      return (num in (ERR_NOSUCHSERVER, RPL_LINKS),
      (num == RPL_ENDOFLINKS))


@_BlockQuery.reg_class
class BlockQueryLIST(_BlockQuery):
   cmds = (b'LIST',)
   def get_msg_barriers(self, msg):
      num = msg.get_cmd_numeric()
      return (num in (RPL_LISTSTART, RPL_LIST, RPL_LISTEND),
         (num == RPL_LISTEND))

@_BlockQuery.reg_class
class BlockQueryWHO(_BlockQuery):
   cmds = (b'WHO',)
   def get_msg_barriers(self, msg):
      num = msg.get_cmd_numeric()
      return (num in (RPL_WHOREPLY, RPL_WHOSPCRPL, RPL_ENDOFWHO), (num == RPL_ENDOFWHO))

class IRCMessageIn(IRCMessage):
   """IRCMessage built from data we got from our uplink, with some additional attached data explaining side effects.

      The additional attributes will not be preserved on copy()."""
   # Set of channels whose state has been affected by this message. (NICK, QUIT, JOIN, PART, KICK)
   affected_channels = None
   # Whether this message indicates we changed our nick. (NICK)
   self_nickchange = None
   def _set_ac(self):
      rv = self.affected_channels = set()
      return rv

class ThroughputLimiter:
   def __init__(self, num, period, step):
      self.n = num
      self.p = period
      self.step = step
      self.win = [0]*(period//step)
      self.widx = 0
      self.c = 0
      self.last_update = time.time()

   def update(self):
      now = time.time()
      pc_0 = int(self.last_update//self.step)
      pc_1 = int(now//self.step)

      delta = pc_1 - pc_0

      if (delta < 1):
         return
      elif (delta >= len(self.win)):
         self.win = [0]*len(self.win)
         self.c = 0
         self.last_update = now
      else:
         w = self.win
         l = len(w)
         idx = self.widx
         c = self.c
         for i in range(delta):
            idx = (idx + 1) % l
            c -= w[idx]
            w[idx] = 0
         self.widx = idx
         self.c = c

      self.last_update = now

   def check(self):
      return (self.c < self.n)

   def bump(self):
      self.c += 1
      self.win[self.widx] += 1


class IRCClientConnection(AsyncLineStream):
   logger = logging.getLogger('IRCClientConnection')
   log = logger.log
   
   # Nicks starting with digits are illegal according to both RFC 1459 and 2812, but have been observed on freenode in the
   # wild, so we allow digits here.
   IRCNICK_INITCHARS = set(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}')
   
   maintenance_delay = 32

   # Freenode capabilities
   FC_IDENTIFY_MSG = 1
   FC_IDENTIFY_CTCP = 2
   
   EM_NAMES = ('em_in_raw', 'em_in_msg', 'em_in_msg_bc', 'em_out_msg',
      'em_link_finish', 'em_shutdown', 'em_chmode', 'em_chan_join',
      'em_chan_leave')
   #calling conventions:
   # Raw lines. Modify to modify what the parser sees.
   # Retval is ignored.
   #    em_in_raw(msg: bytearray)
   #
   # Messages, raw, all of them.
   # Return True to stop any later processing.
   #    em_in_msg(msg: IRCMessage)
   #
   # Message broadcasts; as above, if not eaten by em_in_msg or query slicers.
   # Retval is ignored.
   #    em_in_msg_bc(msg: IRCMessage)
   #
   # em_link_finish()
   # em_chan_join(nick, chan)
   #   <nick> is None for self-joins
   # em_chan_leave(msg, victim, chan, perpetrator)
   #   <victim> is None for self-leaves
   #   <perpetrator> is None for PARTs and self-kicks
   def __init__(self, *args, **kwargs):
      for name in self.EM_NAMES:
        self.em_new(name)
      self.em_in_msg.new_prio_listener(self.process_input_statekeeping)
      self.em_in_msg.new_prio_listener(self.process_input_query_fetch, -1024)

      # connection state
      self.peer = None
      self.link_done = False
      self.motd = None
      self.motd_pending = None
      self.channels = {}
      self.query_queue = deque()
      self.pending_query = None
      self.ping_tok = None
      self.away = False
      self.ts_last_in = time.time()
      self.timer_maintenance = None
      self.timer_push = None
      self.pcs = S2CProtocolCapabilitySet()
      self.pcs.em_argchange.new_prio_listener(self._process_005_update)
      self.out_line_buf = deque()
      
      super().__init__(*args, lineseps={b'\n', b'\r'}, **kwargs)
   
   def start(self, ed, sock, read_r, *, nick, username, realname, mode=0, chm_parser=None, timeout=64, server_password=None, tp_limiter, **kwargs):
      super().start(ed, sock, read_r=read_r)
      
      if (isinstance(nick, str)):
         nick = nick.encode('ascii')
      if (isinstance(username, str)):
         username = username.encode('ascii')
      if (isinstance(realname, str)):
         realname = realname.encode('ascii')
     
      self.server_password = server_password
      self.timeout = timeout + 8
      self.conn_timeout = timeout//2
      self.fc = 0 #freenode capability mask
      self.wnick = nick
      self.nick = None
      self.realname = realname
      self.username = username
      self.mode = mode
      self.modes = set()
      self.tp_limiter = tp_limiter
      self.tpl_delay = tp_limiter.p + 0.0001
      
      if (chm_parser is None):
         chm_parser = ChannelModeParser()
      self.chm_parser = chm_parser
      
      # connection state
      self.ts_last_in = -1
      
      self._chan_autojoin_tried = {}
      self._chan_autojoin_pending = {}
      
      self.timer_maintenance = self._ed.set_timer(self.maintenance_delay, self._perform_maintenance, parent=self, persist=True)
      
      self.sock_set_keepalive(1)
      self.sock_set_keepidle(self.conn_timeout, self.conn_timeout, 2)
   
   def em_new(self, attr):
      """Instantiate new EventMultiplexer attribute"""
      setattr(self, attr, OrderingEventMultiplexer(self))
   
   def _check_queries(self):
      if not (self.pending_query is None):
         return
      if (len(self.query_queue) == 0):
         return
         
         
      self.pending_query = self.query_queue.popleft()
      self.ping_fresh = False
      self.pending_query.put_req(self)
   
   def _send_ping(self):
      self.ping_tok = tok = build_ping_tok()
      self._send_msg(b'PING', tok)
      self.ping_fresh = True
   
   def _perform_maintenance(self):
      self._send_ping()
      idle_time = (time.time() - self.ts_last_in)
      if (idle_time >= self.timeout):
         if (idle_time >= (self.timeout + self.maintenance_delay + 16)):
            # Not likely.
            self.log(30, '{} allegedly {} seconds idle; major clock warp?'.format(self, idle_time))
            self.ts_last_in = time.time()
         else:
            self.log(30, '{} timed out.'.format(self))
            self.close()
   
   def put_msg(self, msg, callback, force_bc=False):
      if (not force_bc):
         try:
            query = _BlockQuery.build(msg, callback)
         except KeyError:
            pass
         else:
            self.query_queue.append(query)
            self._check_queries()
            return query
      
      self.send_msg(msg)
   
   def add_autojoin_channel(self, chan, key=None):
      """Attempt to join a channel on this connection.
         This should only be used by event handlers that do autojoins of
         channels on connection init (hence the name), and all such requests
         will be batched, avoiding attempts to join the same channel several
         times, as well as use of unnecessarily many JOIN lines.
         
         If called several times for the same channel but with different keys,
         the key ultimately used on the join attempt is undefined."""
      chan = self.pcs.make_cib(chan)
      try:
         nonew = (key == self._chan_autojoin_tried[chan])
      except KeyError:
         nonew = False
      
      if (nonew):
         return
      
      timer_set = bool(self._chan_autojoin_pending)
      self._chan_autojoin_pending[chan] = key
      
      if (not timer_set):
         self._ed.set_timer(0, self._autojoin_channels, interval_relative=False)
   
   def _autojoin_channels(self):
      """Send JOINs for channels in self._chan_autojoin_pending"""
      if not (self and self._autojoin_channels):
         return
      
      try:
         msgs = IRCMessage.build_ml_JOIN(None, self._chan_autojoin_pending.items())
         for msg in msgs:
            self.send_msg(msg)
      finally:
         self._chan_autojoin_pending.clear()
   
   def process_input(self, line_data_mv):
      """Process IRC data"""
      # TODO: Move this up the callstack? It's kinda unclean to keep it here.
      self.ts_last_in = time.time()
      
      line_data = bytearray(bytes(line_data_mv).rstrip(b'\r\n'))
      if (self.em_in_raw(line_data)):
         return
      if (line_data == b''):
         return
      msg = IRCMessageIn.build_from_line(line_data, src=self, pcs=self.pcs)
      msg.responded = False
      
      self.em_in_msg(msg)
      if not (msg.is_query_related):
         self.em_in_msg_bc(msg)
   
   def process_input_query_fetch(self, msg):
      """Do query input processing."""
      if (self.pending_query):
         msg.is_query_related = self.pending_query.process_data(msg)
         if (msg.is_query_related == 2):
            self.pending_query = None
            self._check_queries()
      else:
         msg.is_query_related = False
   
   def process_input_statekeeping(self, msg):
      """Do local input processing."""
      try:
         cmd_str = msg.command.decode('ascii')
      except UnicodeDecodeError:
         self.log(30, 'Peer {!r} sent undecodable message {}.'.format(self.peer_address, msg))
      else:
         fn = '_process_msg_' + cmd_str
         try:
            func = getattr(self,fn)
         except AttributeError:
            self.log(10, 'Peer {!r} sent unknown message {}.'.format(self.peer_address, msg))
            
         else:
            if (cmd_str.isdigit()):
               # Numeric replies are always targeted to our nick.
               if (not msg.parameters):
                  self.log(30, 'From {!r}: bogus numeric: {}'.format(self.peer_address, msg))
               else:
                  nick = self.pcs.make_cib(msg.parameters[0])
                  if (self.nick != nick):
                     if (not (self.nick is None)):
                        self.log(30, 'From {!r}: missed a nickchange from {!a} to {!a}.'.format(self.peer_address, self.nick, nick))
                     self.nick = nick
            
            try:
               func(msg)
            except IRCProtocolError as exc:
               self.log(30, 'From {!r}: msg {} failed to process: {!r}'.format(self.peer_address, msg, exc), exc_info=True)
   
   def send_msg(self, msg):
      """Send MSG to peer immediately"""
      self.em_out_msg(msg)
      line_out = msg.line_build()
      self.out_line_buf.append(line_out)
      if (self.timer_push is None):
         self._push_msgs()

   def _push_msgs(self):
      tp = self.tp_limiter
      buf = self.out_line_buf
      tp.update()
      while (buf and tp.check()):
         self.send_bytes((buf.popleft(),))
         tp.bump()

      if (buf):
         self.timer_push = self._ed.set_timer(self.tpl_delay, self._push_msgs, parent=self, persist=False)
      else:
         self.timer_push = None

   def _send_msg(self, command, *parameters):
      """Build MSG and send to peer immediately."""
      msg = IRCMessage(None, command, parameters)
      self.send_msg(msg)
   
   @classmethod
   def irc_build_sock_connect(cls, sa, hostname, port, **kwargs):
      def process_connect(__rv):
         rv._process_connect()
      
      rv = cls(sa.ed, run_start=False, **kwargs)
      rv.connect_async_sock_bydns(sa, hostname, port, connect_callback=process_connect, **kwargs)
      
      rv.peer_address = (hostname, port)
      return rv
   
   def _pc_check(self, msg, num:int):
      """Throw exception if msg has less than the specified number of
         parameters."""
      if (len(msg.parameters) < num):
         raise IRCProtocolError(msg, 'Insufficient arguments; expected at least'
            ' {0}.'.format(num))

   def send_NICK(self, nick):
      self._send_msg(b'NICK', nick)

   def _process_connect(self):
      """Process connect finish."""
      if not (self.server_password is None):
         self._send_msg(b'PASS', self.server_password)

      self.send_NICK(self.wnick)
      self._send_msg(b'USER', self.username, str(self.mode).encode('ascii'), b'*', self.realname)
   
   def process_close(self):
      """Process connection closing."""
      self.log(20, 'process_close() called on 0x{:x}.'.format(id(self)))
      self.em_shutdown()
      
      if not (self.timer_maintenance is None):
        self.timer_maintenance.cancel()
        self.timer_maintenance = None
      if not (self.timer_push is None):
         self.timer_push.cancel()
         self.timer_push = None
   
   def _process_msg_PING(self, msg):
      """Answer PING."""
      self._send_msg(b'PONG', *msg.parameters)
   
   def _process_msg_PONG(self, msg):
      """Process PONG."""
      if (len(msg.parameters) != 2):
         return
      if (msg.parameters[1] != self.ping_tok):
         return
      if (self.ping_fresh and not (self.pending_query is None)):
         self.log(40, 'Query {0} on {1} timed out; switching to emergency broadcasting. Accumulated data: {2}'
            .format(self.pending_query, self, self.pending_query.rv))
         for msg in self.pending_query.rv:
            self.em_in_msg_bc(msg)
         
         self.pending_query.timeout()
         self.pending_query = None
         self._check_queries()
   
   def _process_msg_JOIN(self, msg):
      """Process JOIN message."""
      if ((msg.prefix is None) or (msg.prefix.type != IA_NICK)):
         raise IRCProtocolError('Non-nick trying to join channel.')
      
      chnns = msg.parse_JOIN()
      affected_channels = msg._set_ac()
      for chnn in chnns:
         if (msg.prefix.nick == self.nick):
            # Our join.
            if (chnn in self.channels):
               raise IRCProtocolError("Joining channel we're already in.")
            chan = IRCChannel(chnn, cmp_=self.chm_parser)
            self.channels[chnn] = chan
            self.chm_parser.chan_init(chan)
            self.em_chan_join(None, chan)
            affected_channels.add(chan)
            continue
         
         try:
            chan = self.channels[chnn]
         except KeyError:
            # Iffy: *IS* this is an error?
            raise IRCProtocolError("JOIN message for channel we aren't on.")
         chanusers = chan.users
         if (msg.prefix.nick in chanusers):
            raise IRCProtocolError("User joining channel they are already on.")
         chanusers[msg.prefix.nick] = set()
         self.em_chan_join(msg.prefix.nick, self.channels[chnn])
         affected_channels.add(chan)
   
   def _process_msg_PART(self, msg):
      """Process PART message."""
      chnns = msg.parse_PART()
      
      if ((msg.prefix is None) or (msg.prefix.type != IA_NICK)):
         raise IRCPRotocolError('Bogus PART prefix.')
      nick = msg.prefix.nick
      
      if (len(msg.parameters) > 1):
         reason = msg.parameters[1]
      else:
         reason = None
      
      affected_channels = msg._set_ac()
      for chnn in chnns:
         if (not chnn in self.channels):
            raise IRCProtocolError("PART message for channel we aren't on.")
         chan = self.channels[chnn]
         if (not nick in chan.users):
            raise IRCProtocolError("PARTed user not on channel.")
         
         nick_em = nick
         if (nick == self.nick):
            nick_em = None
         
         self.em_chan_leave(msg, nick_em, chan, None)
         if (nick == self.nick):
            del(self.channels[chnn])
         del(chan.users[nick])
         affected_channels.add(chan)
   
   def _process_msg_QUIT(self, msg):
      """Process QUIT message."""
      if ((msg.prefix is None) or (msg.prefix.type != IA_NICK)):
         raise IRCPRotocolError('Bogus QUIT prefix.')
      nick = msg.prefix.nick
      
      affected_channels = msg._set_ac()
      for chan in self.channels.values():
         if not (nick in chan.users):
            continue
         self.em_chan_leave(msg, nick, chan, nick)
         affected_channels.add(chan)
         del(chan.users[nick])
   
   def _process_msg_KICK(self, msg):
      """Process KICK message."""
      kick_data = msg.parse_KICK()
      
      affected_channels = msg._set_ac()
      # Remember which chans we've parted due to this message, so we don't get confused by other users being kicked out of them
      # after us.
      chnns_left = set()
      for (chnn, nick) in kick_data:
         if (chnn in chnns_left):
            continue
         if not (chnn in self.channels):
            raise IRCProtocolError("KICK message for channel we aren't on.")
         
         chan = self.channels[chnn]
         if (msg.prefix is None):
            perpetrator = self.peer
         elif ((msg.prefix.type == IA_NICK) and (nick == msg.prefix.nick)):
            perpetrator = None
         else:
            perpetrator = msg.prefix
            
         nick_em = nick
         if (nick == self.nick):
            nick_em = None
            
         self.em_chan_leave(msg, nick_em, chan, perpetrator)
         if (nick != self.nick):
            try:
               del(chan.users[nick])
            except KeyError as exc:
               raise IRCProtocolError('KICKed nick {0!a} not on chan.'.format(nick)) from exc
            affected_channels.add(chan)
            continue
         # Our part.
         del(self.channels[chnn])
         chnns_left.add(chnn)
         affected_channels.add(chan)
   
   def _process_msg_MODE(self, msg):
      """Process MODE message."""
      self._pc_check(msg, 2)
      victim = self.pcs.make_cib(msg.parameters[0])
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
         raise IRCProtocolError("Got MODE message for channel {0} I'm not on.".format(victim)) from exc
      
      self.chm_parser.set_chmodes(self.pcs, self.log, chan, msg.parameters[1:])
      self.em_chmode(chan, msg.parameters)
   
   def _process_msg_NICK(self, msg):
      """Process NICK message."""
      if ((msg.prefix is None) or (msg.prefix.type != IA_NICK)):
         raise IRCProtocolError('Non-nick sending NICK.')
      
      self._pc_check(msg, 1)
      old_nick = msg.prefix.nick
      new_nick = self.pcs.make_cib(msg.parameters[0])
      
      if (old_nick == self.nick):
         self.log(20, 'Changed nick from {0} to {1}.'.format(old_nick, new_nick))
         self.nick = new_nick
         msg.self_nickchange = True
      else:
         msg.self_nickchange = False
      
      affected_channels = msg._set_ac()
      for chan in self.channels.values():
         if not (old_nick in chan.users):
            continue
         
         user_data = chan.users[old_nick]
         del(chan.users[old_nick])
         if (new_nick in chan.users):
            self.log(35, 'Apparent nickchange collision: {0!a} changed nick to {1!a} on {2!a} on {3!a}. Overwriting.'.format(old_nick, new_nick, chan, self.peer_address))
         chan.users[new_nick] = user_data
         affected_channels.add(chan)

   def _process_msg_TOPIC(self, msg):
      """Process TOPIC message"""
      self._pc_check(msg, 2)
      chan = self._get_own_chan(msg, msg.parameters[0])
      chan.topic = msg.parameters[1]
   
   # connect numerics
   def _process_msg_001(self, msg):
      """Process RPL_WELCOME message."""
      self.peer = (self.peer or msg.prefix)
   
   def _process_msg_004(self, msg):
      """Process RPL_MYINFO message."""
      if ((self.peer is None) and (msg.parameters)):
         self.peer = self.pcs.make_irc_addr(msg.parameters[0])
   
   def _process_005_update(self, name, val):
      nu = name.upper()
      if (nu == b'PREFIX'):
         self.chm_parser.process_ISUPPORT_PREFIX(val)
         self.log(20, '{0} parsed prefix data from 005.'.format(self))
         return
      
      if (nu == b'CHANMODES'):
         self.chm_parser.process_ISUPPORT_CHANMODES(val)
         self.log(20, '{0} parsed chanmodes data from 005.'.format(self))

      
   def _process_msg_005(self, msg):
      """Process RPL_ISUPPORT message"""
      args = list(msg.parameters[1:])
      self.pcs.parse_msg(msg)
   
   def _process_msg_305(self, msg):
      """Process RPL_UNAWAY message"""
      self.away = False
   
   def _process_msg_306(self, msg):
      """Process RPL_NOWAWAY message"""
      self.away = True
   
   def _process_msg_290(self, msg):
      """Process freenode capability-verify MSG"""
      if (len(msg.parameters) < 2):
         return
      
      cp = msg.parameters[1]
      
      if (cp == b'IDENTIFY-MSG'):
         self.fc |= self.FC_IDENTIFY_MSG
      elif (cp == b'IDENTIFY-CTCP'):
         self.fc |= self.FC_IDENTIFY_CTCP
   
   # MOTD
   def _process_msg_375(self, msg):
      """Process MOTD start"""
      self.motd_pending = []
   
   def _process_msg_372(self, msg):
      """Process MOTD line"""
      if (self.motd_pending is None):
         self.log(30, 'From {}: got MOTD line {} without preceding 375. Ignoring.'.format(self.peer_address, msg))
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
   
   def _process_msg_422(self, msg):
      """Process NOMOTD message."""
      self.motd = False
      self.motd_pending = None
      if (not self.link_done):
         self.link_done = True
         self.em_link_finish()
   
   # Channel-JOIN data dump messages
   def _get_own_chan(self, msg, chnn):
      chnn = self.pcs.make_cib(chnn)
      try:
         rv = self.channels[chnn]
      except KeyError as exc:
         raise IRCProtocolError(msg, "Not on chan {0!a}.".format(chnn)) from exc
      
      return rv
   
   def _process_msg_331(self, msg):
      """Process RPL_NOTOPIC message"""
      self._pc_check(msg, 2)
      chan = self._get_own_chan(msg, msg.parameters[1])
      chan.topic = False
      
   def _process_msg_332(self, msg):
      """Process RPL_TOPIC message"""
      self._pc_check(msg, 3)
      chan = self._get_own_chan(msg, msg.parameters[1])
      chan.topic = msg.parameters[2]
   
   def _process_msg_353(self, msg):
      """Process RPL_NAMREPLY message."""
      self._pc_check(msg, 4)
      chan = self._get_own_chan(msg, msg.parameters[2])
      
      if not (chan.syncing_names):
         chan.syncing_names = True
         chan.users = {}
      
      for nick_str in msg.parameters[3].split():
         i = 0
         for c in nick_str:
            if (c in self.IRCNICK_INITCHARS):
               break
            i += 1
         nick = self.pcs.make_cib(nick_str[i:])
         
         chan.users[nick] = set()
         for b in b2b(nick_str[:i]):
            chan.users[nick].add(self.chm_parser.uflags2modes[b])
   
   def _process_msg_366(self, msg):
      """Process RPL_ENDOFNAMES message."""
      self._pc_check(msg, 2)
      chan = self._get_own_chan(msg, msg.parameters[1])
      chan.syncing_names = False
   
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
            conn._send_msg(b'PRIVMSG', chan, '{0}: {1} {2}'.format(n, args, kwargs).encode('ascii'))
         
         return _info_print
      
      for name in conn.__dict__:
         if (not name.startswith('em_')):
            continue
         if (name.endswith('_msg') or name.endswith('_raw')):
            continue
         
         getattr(conn, name).new_listener(ip_ret(name))
      

def _selftest(target, nick='Zanaffar', username='chimera', realname=b'? ? ?',
      channels=()):
   import pprint
   from gonium.fdm import ED_get
   from gonium._debugging import streamlogger_setup
   
   logging.getLogger('IRCClientConnection').setLevel(20)
   
   def link():
      for chan in channels:
         irccc._send_msg(b'JOIN', chan)
   
   streamlogger_setup()
   ed = ED_get()()
   irccc = IRCClientConnection.irc_build_sock_connect(ed, target, nick=nick,
      username=username, realname=realname)
   irccc.em_shutdown.new_listener(ccd(1)(ed.shutdown))
   irccc.em_link_finish.new_listener(ccd(1)(link))
   
   query_specs = (
      (2, b'LINKS'),
      (3, b'LIST'),
      (4, b'MAP')
   )
   
   queries_answered = 0
   def cb_print(query):
      nonlocal queries_answered
      print(query)
      pprint.pprint(query.rv[:20])
      queries_answered += 1
      if (queries_answered == len(query_specs)):
         print('All done. Shutting down.')
         ed.shutdown()
   
   for (d, cmd) in query_specs:
      ed.set_timer(d, irccc.put_msg, args=(IRCMessage(None, cmd,()), cb_print))
   
   if (channels):
      #__ChanEcho(irccc, channels[0])
      pass
   
   ed.event_loop()


if (__name__ == '__main__'):
   import sys
   _selftest((sys.argv[1],6667),channels=(sys.argv[2].encode('ascii'),))
