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

from .s2c_structures import IA_NICK, IRCMessage


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


class LogLine(LogEntry):
   def __init__(self, msg, src, outgoing, ts=None):
      super().__init__(ts)
      self.msg = msg
      self.src = src
      self.outgoing = outgoing


class LogChanSnapshot(LogEntry):
   def __init__(self, chan_data, ts=None):
      super().__init__(ts)
      self.chan_data = chan_data


class LogConnShutdown(LogEntry):
   def __init__(self, peer_addr, ts=None):
      super().__init__(ts)
      self.peer_addr = peer_addr


class BLFormatter:
   def __init__(self, time_fmt=LogEntry.TS_FMT_DEFAULT, time_color=None):
      self.time_fmt = time_fmt
      self.set_time_color(time_color)
   
   def set_time_color(self, c=None):
      if (c is None):
         self.time_cfmt = '{0}'
      else:
         self.time_cfmt = '\x03{0:02}{{0}}\x0f'.format(c)
   
   def format_ts(self, e):
      return self.time_cfmt.format(e.get_time_str(self.time_fmt)).encode('ascii')
   
   def format_sender(self, e):
      src = e.src
      try:
         src = src.nick
      except AttributeError:
         pass
      
      return b''.join((b'<', src, b'>'))
   
   def format_ctcp(self, e, ctcp_data):
      return b' '.join((self.format_sender(e), b'CTCP:', ctcp_data))
   
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
   
   def format_entry(self, prefix, chan, e):
      """Return list of PRIVMSGs to replay given backlog entry to given chan
         with given prefix."""
      ctcps = []
      if (isinstance(e, LogLine)):
         cmd = e.msg.command
         text = b' '.join((cmd, self.format_sender(e)))
         if (cmd in (b'PRIVMSG', b'NOTICE')):
            (tf, ctcps) = e.msg.split_ctcp()
            text_ext = b' ' + b''.join(tf)
            
            if (text_ext == b' '):
               text = None
            else:
               text += text_ext
         else:
            text += b' ' + b' '.join(e.msg.get_notarget_parameters())
      elif (isinstance(e, LogChanSnapshot)):
         return
      elif (isinstance(e, LogConnShutdown)):
         text = "Bouncer disconnected from {0}.".format(e.peer_addr).encode('ascii')
      else:
         raise TypeError('Unable to process entry {0!a}.'.format(e))
      
      ts_str = self.format_ts(e)
      if (text is None):
         rv = []
      else:
         rv = self._make_msgs(prefix, chan, ts_str, text)

      for ctcp in ctcps:
         text = self.format_ctcp(e, ctcp)
         rv.extend(self._make_msgs(prefix, chan, ts_str, text))
      
      return rv
   
   def format_backlog(self, bl, prefix, chan):
      """Return list of privmsgs to format entire backlog."""
      bles = bl.get_bl(chan)
      rv = []
      for entry in bles:
         rv.extend(self.format_entry(prefix, chan, entry))
      
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


class _Logger:
   # cmds that don't go to a chan, but should be logged to the same context
   BC_AUXILIARY = (b'NICK', b'QUIT')
   logger = logging.getLogger('_Logger')
   log = logger.log
   def __init__(self, basedir, nc):
      self.basedir = basedir
      self.nc = nc
      
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
   
   def _process_conn_shutdown(self):
      for chan in self.nc.get_channels():
         self._get_file(chan).put_record(LogConnShutdown(self.nc.get_peer_address()))
   
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
      
      bll = LogLine(msg2, src, outgoing)
      chans = msg.get_chan_targets()
      if not (chans is None):
         for chan in chans:
            self._get_file(chan).put_record(bll)
         return
      
      if not (msg.command.upper() in self.BC_AUXILIARY):
         return
      # Log non-channel commands to chan contexts: NICK and QUIT
      
      chan_map = self.nc.get_channels()
      chans = set(chan_map.keys())
      if ((not (msg.prefix is None)) and (msg.prefix.type == IA_NICK)):
         for chan in tuple(chans):
            if (msg.prefix.nick in chan_map[chan].users):
               continue
            chans.remove(chan)
      
      for chan in chans:
         self._get_file(chan).put_record(bll)
      
   def _get_fn(self, chan):
      return os.path.join(self.basedir, self.nc.netname.encode(), chan)
   

class BackLogger(_Logger):
   file_cls = BacklogFile
   def reset_bl(self, chann):
      f = self._get_file(chan)
      f.clear_records()
      try:
         chan = self.nc.channels[chann]
      except KeyError:
         return
      f.put_record(LogChanSnapshot(chan))
   
   def get_bl(self, chann):
      return self._get_file(chann).get_records()

