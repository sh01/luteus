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

import collections
import logging
import os
import os.path
import time

from .s2c_structures import IRCMessage, IRCCIString


class LogEntry:
   TS_FMT_DEFAULT = '%Y-%m-%dT%H:%M:%S'
   
   def __init__(self, ts=None):
      if (ts is None):
         ts = time.time()
      self.ts = ts
   
   def get_time_str(self, fmt=TS_FMT_DEFAULT, localtime=True):
      if (localtime):
         tt = time.localtime(self.ts)
      else:
         tt = time.gmtime(self.ts)
      
      return time.strftime(fmt, tt)

   def get_replay_target(self, bl_context):
      return bl_context
   
   def get_replay_source(self, lname):
      return lname


class LogLine(LogEntry):
   def __init__(self, msg, src, outgoing, ts=None):
      super().__init__(ts)
      self.msg = msg
      self.src = src
      self.outgoing = outgoing

class ChanLogLine(LogLine):
   pass

class NickLogLine(LogLine):
   def get_replay_target(self, bl_context):
      return self.src
   
   def get_replay_source(self, lname):
      if (self.outgoing):
         return self.msg.parameters[0]
      return self.src

class LogChanSnapshot(LogEntry):
   def __init__(self, chan_data, ts=None):
      super().__init__(ts)
      self.chan_data = chan_data


class LogConnShutdown(LogEntry):
   def __init__(self, peer_addr, ts=None):
      super().__init__(ts)
      self.peer_addr = peer_addr


class BLFormatter:
   def __init__(self, time_fmt=LogEntry.TS_FMT_DEFAULT, time_color=None,
         nmcl_color=None):
      self.time_fmt = time_fmt
      self.set_time_color(time_color)
      self.set_nomsg_channel_line_color(nmcl_color)
   
   def set_time_color(self, c=None):
      if (c is None):
         self.time_cfmt = '{0}'
      else:
         self.time_cfmt = '\x03{0:02}{{0}}\x0f'.format(c)
   
   def set_nomsg_channel_line_color(self, c=None):
      if (c is None):
         self.nmcl_prefix = b''
      else:
         self.nmcl_prefix = '\x03{0:02}'.format(c).encode('ascii')
   
   def format_ts(self, e):
      return self.time_cfmt.format(e.get_time_str(self.time_fmt)).encode('ascii')
   
   def format_line_prefix(self, e, cmd=None):
      src = e.src
      try:
         src = src.nick
      except AttributeError:
         pass
      
      if (cmd is None):
         cmd = e.msg.command
      
      if (isinstance(e, NickLogLine)):
         if (e.outgoing):
            rv =  b'<'
         else:
            rv = b'>'
         if not (cmd in (b'PRIVMSG', b'NOTICE')):
            rv = b' '.join((cmd, rv))
         return rv
      
      if (cmd in (b'PRIVMSG', b'NOTICE')):
         rv = b''.join((b'<', src, b'>'))
      else:
         rv = b' '.join((cmd, src))
      return rv
   
   def format_ctcp(self, e, ctcp_data):
      return b' '.join((self.format_line_prefix(e, b'CTCP'), ctcp_data))
   
   def _make_msgs(self, prefix, chan, tpf, text):
      msg1 = IRCMessage(prefix, b'PRIVMSG', [chan, b' '.join((tpf, text))])
      rv = [msg1]
      la = msg1.parameters[-1]
      lost_chars = msg1.trim_last_arg()
      
      if (lost_chars):
         text_cont = b' '.join((tpf, b'[cont.]', la[-1*lost_chars:]))
         msg2 = IRCMessage(prefix, b'PRIVMSG', [chan, text_cont])
         msg2.trim_last_arg()
         rv.append(msg2)
      
      return rv
   
   def format_entry(self, lname, orig_target, e):
      """Return list of PRIVMSGs to replay given backlog entry originally
         targeted to orig_target with luteus name lname."""
      ctcps = []
      if (isinstance(e, LogLine)):
         if not (e.msg.get_cmd_numeric() is None):
            return []
         
         msg_like = e.msg.command in (b'PRIVMSG', b'NOTICE')
         if not (msg_like):
            text = self.nmcl_prefix
         else:
            text = b''
         
         text += self.format_line_prefix(e)
         
         if (msg_like):
            (tf, ctcps) = e.msg.split_ctcp()
            text_ext = b' ' + b''.join(tf)
            
            if (text_ext == b' '):
               text = None
            else:
               text += text_ext
         else:
            text += self.nmcl_prefix + b' '.join(e.msg.get_notarget_parameters())
      elif (isinstance(e, LogChanSnapshot)):
         return
      elif (isinstance(e, LogConnShutdown)):
         text = "Bouncer disconnected from remote {0!a}.".format(e.peer_addr).encode('ascii')
      else:
         raise TypeError('Unable to process entry {0!a}.'.format(e))
      
      ts_str = self.format_ts(e)
      rt = e.get_replay_target(orig_target)
      rs = e.get_replay_source(lname)
      if (text is None):
         rv = []
      else:
         rv = self._make_msgs(rs, rt, ts_str, text)

      for ctcp in ctcps:
         text = self.format_ctcp(e, ctcp)
         rv.extend(self._make_msgs(rs, rt, ts_str, text))
      
      return rv
   
   def format_backlog(self, bl, lname, orig_target):
      """Return list of privmsgs to format entire backlog."""
      bles = bl.get_bl(orig_target)
      rv = []
      for entry in bles:
         rv.extend(self.format_entry(lname, orig_target, entry))
      
      return rv


class BacklogFile:
   def __init__(self, fn):
      self.fn = fn
      self._open_file()
      
   def _open_file(self):
      fn = self.fn
      try:
         f = open(fn, 'r+b')
      except EnvironmentError:
         try:
            os.makedirs(os.path.dirname(fn))
         except OSError as exc:
            from errno import EEXIST
            if (exc.errno != EEXIST):
               raise
         f = open(fn, 'w+b')
      else:
         f.seek(0,2)
      
      import fcntl
      fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
      
      import pickle
      self.f = f
      self.p = pickle.Pickler(f)
      self.u = pickle.Unpickler(f)

   def put_record(self, o):
      self.p.dump(o)
      self.f.flush()
   
   def get_records(self):
      from pickle import UnpicklingError
      
      self.f.seek(0)
      rv = []
      while (True):
         try:
            o = self.u.load()
         except (UnpicklingError, EOFError):
            break
         rv.append(o)
      
      self.f.seek(0, 2)
      return rv
   
   def clear_records(self):
      self.f.seek(0)
      self.f.truncate(0)
      self.f.flush()
   
   def close(self):
      self.f.close()


class LogFilter:
   def __init__(self):
      self._eat_all_servers = False
      self._eatable_sources = set()
      self._eatable_nicks = set()
   
   def set_eat_servers(self, es):
      self._eat_all_servers = es
   
   def add_filtered_source(self, s):
      self._eatable_sources.add(IRCCIString(s))
   
   def add_filtered_nick(self, n):
      self._eatable_nicks.add(IRCCIString(n))
   
   def __call__(self, ctx, r):
      prefix = r.msg.prefix
      if ((prefix is None) or (prefix.is_server())):
         if (self._eat_all_servers and ()):
            return False
      else:
         if (prefix.nick in self._eatable_nicks):
            return False
      
      if (prefix in self._eatable_sources):
         return False
         
      return True


class _Logger:
   # cmds that don't go to a chan, but should be logged to the same context
   BC_AUXILIARY = (b'NICK', b'QUIT')
   logger = logging.getLogger('_Logger')
   log = logger.log
   def __init__(self, basedir, nc, filter=None):
      if (filter is None):
         filter = LogFilter()
      self.basedir = basedir
      self.nc = nc
      self.filter = filter
      
      self._storage = {}
      
      self.nc.em_in_msg_bc.new_prio_listener(self._process_msg_in, -512)
      self.nc.em_out_msg.new_prio_listener(self._process_msg_out, -512)
      self.nc.em_shutdown.new_prio_listener(self._process_conn_shutdown, -512)
   
   def _get_file(self, chan):
      try:
         rv = self._storage[chan]
      except KeyError:
         rv = self.file_cls(self._get_fn(chan))
         self._storage[chan] = rv
      
      return rv
   
   def _put_record_file(self, ctx, r):
      if not (self.filter(ctx, r)):
         return
      
      self._get_file(ctx).put_record(r)
   
   def _process_conn_shutdown(self):
      r = LogConnShutdown(self.nc.get_peer_address(stale=True))
      for chan in self.nc.get_channels(stale=True):
         self._put_record_file(chan, r)
   
   def _process_msg_in(self, msg):
      src = msg.prefix
      if (src is None):
         src = self.nc.get_peer() or b'?'
      
      self._process_msg(msg, src, False)
      
   def _process_msg_out(self, msg):
      src = msg.prefix
      if (src is None):
         src = self.nc.get_self_nick()
      
      self._process_msg(msg, src, True)
   
   def _process_msg(self, msg, src, outgoing):
      if (outgoing and not (msg.command in (b'PRIVMSG', b'NOTICE'))):
         return
      
      msg2 = msg.copy()
      msg2.src = None
      
      bll = ChanLogLine(msg2, src, outgoing)
      num = msg.get_cmd_numeric()
      
      if (num is None):
         (nicks, chans) = msg.get_targets()
      else:
         nicks = []
         if (num in (332, 333, 366)):
            chans = [msg.parameters[1]]
         elif (num == 353):
            chans = [msg.parameters[2]]
         else:
            chans = []
      
      if (chans):
         for chan in chans:
            self._put_record_file(chan, bll)
      
      if (nicks):
         bll_nick = NickLogLine(msg2, src, outgoing)
         for nick in nicks:
            self._put_record_file(nick, bll_nick)
      
      if not (msg.command.upper() in self.BC_AUXILIARY):
         return
      # Log non-channel commands to chan contexts: NICK and QUIT
      
      chan_map = self.nc.get_channels()
      chans = set(chan_map.keys())
      if ((not (msg.prefix is None)) and (msg.prefix.is_nick())):
         for chan in tuple(chans):
            if (msg.prefix.nick in chan_map[chan].users):
               continue
            chans.remove(chan)
      
      for chan in chans:
         self._put_record_file(chan, bll)
      
   def _get_fn(self, ctx):
      if (ctx is None):
         ctx = b'nicks\x07'
      else:
         ctx = ctx.normalize()
      return os.path.join(self.basedir, self.nc.netname.encode(), ctx)
   

class BackLogger(_Logger):
   file_cls = BacklogFile
   def reset_bl(self, ctx):
      f = self._get_file(ctx)
      f.clear_records()
   
   def get_bl(self, ctx):
      return self._get_file(ctx).get_records()
   
   def _put_record_file(self, ctx, r):
      if (isinstance(r, NickLogLine)):
         ctx = None
      super()._put_record_file(ctx, r)
   

