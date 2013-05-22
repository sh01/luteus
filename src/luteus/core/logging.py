#!/usr/bin/env python
#Copyright 2009,2010,2013 Sebastian Hagen
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
from weakref import WeakValueDictionary

from .s2c_structures import IRCMessage, IA_SERVER, IRCCIString


class LogEntry:
   TS_FMT_DEFAULT = '%Y-%m-%d %H:%M:%S'
   
   def __init__(self, ts=None):
      if (ts is None):
         ts = time.time()
      self.ts = ts
   
   def get_time_str(self, fmt=None, utc=True):
      if (fmt is None):
         fmt = self.TS_FMT_DEFAULT
      
      if (utc):
         tt = time.gmtime(self.ts)
      else:
         tt = time.localtime(self.ts)
      
      return time.strftime(fmt, tt)
   
   def get_replay_target(self, bl_context):
      return bl_context
   
   def get_replay_source(self, lname):
      return lname


class LogLine(LogEntry):
   msglike_cmds = set((b'PRIVMSG', b'NOTICE'))
   def __init__(self, msg, src, outgoing, ts=None):
      super().__init__(ts)
      self.msg = msg
      self.src = src
      self.outgoing = outgoing

   def is_msglike(self):
      """Return whether this entry is a NOTICE/PRIVMSG."""
      return (self.msg.command in self.msglike_cmds)

class ChanLogLine(LogLine):
   pass

class NickLogLine(LogLine):
   def get_replay_target(self, bl_context):
      return self.src
   
   def get_replay_source(self, lname):
      if (self.outgoing):
         rv = self.msg.parameters[0]
         if not (lname is None):
            rv = self.msg.pcs.make_irc_addr(b''.join((rv, b'!luteususer', b'@', lname)))
         return rv

      return self.src

class LogConnShutdown(LogEntry):
   def __init__(self, peer_addr, ts=None):
      super().__init__(ts)
      self.peer_addr = peer_addr
   
   def get_text(self):
      return ("Bouncer disconnected from remote {0!a}.".format(self.peer_addr).encode('ascii'))

class LogProcessShutdown(LogEntry):
   def get_text(self):
      return b'Luteus process shut down.'

class _LogFormatter:
   cmd_map = {b'ACTION': b'*'}
   
   def __init__(self, time_fmt=None, time_color=None, nmcl_color=None, ctcp_color=None, utc=True):
      self.time_fmt = time_fmt
      self.utc = utc
      
      self.set_time_color(time_color)
      self.set_nomsg_channel_line_color(nmcl_color)
      self.set_ctcp_color(ctcp_color)
   
   def copy(self):
      return type(self)(time_fmt=self.time_fmt, time_color=self._time_color, nmcl_color=self._nmcl_color,
         ctcp_color=self._ctcp_color, utc=self.utc)
   
   def set_utc(self, utc):
      """Set whether to exptress timestamps in UTC."""
      self.utc = utc
   
   # Color setters
   def set_time_color(self, c=None):
      self._time_color = c
      if (c is None):
         self.time_cfmt = '{0}'
      else:
         self.time_cfmt = '\x03{0:02}{{0}}\x0f'.format(c)
   
   def set_ctcp_color(self, c=None):
      self._ctcp_color = c
      if (c is None):
         self.ctcp_prefix = b''
      else:
         self.ctcp_prefix = '\x03{0:02}'.format(c).encode('ascii')
   
   def set_nomsg_channel_line_color(self, c=None):
      self._nmcl_color = c
      if (c is None):
         self.nmcl_prefix = b''
      else:
         self.nmcl_prefix = '\x03{0:02}'.format(c).encode('ascii')
   
   def format_ts(self, e):
      return self.time_cfmt.format(e.get_time_str(self.time_fmt,
         utc=self.utc)).encode('ascii')
   
   def map_cmd_out(self, cmd):
      """Convert cmd string into output form."""
      return self.cmd_map.get(cmd,cmd)
   
   def format_line_prefix(self, e, cmd=None):
      src = e.src
      try:
         src = src.nick
      except AttributeError:
         pass
      
      if (cmd is None):
         cmd = e.msg.command
      
      is_msglike = (cmd in (b'PRIVMSG',b'NOTICE'))
      
      if (isinstance(e, NickLogLine)):
         if (e.outgoing):
            rv =  b'<'
         else:
            rv = b'>'
         if not (is_msglike):
            rv = b' '.join((rv, self.map_cmd_out(cmd)))
         return rv
      
      if (is_msglike):
         rv = b''.join((b'<', src, b'>'))
      else:
         rv = b' '.join((src, self.map_cmd_out(cmd)))
      return rv
   
   def format_ctcp(self, e, ctcp_data):
      if (ctcp_data.startswith(b'ACTION ')):
         cmd = b'ACTION'
         lprefix = b''
         ctcp_data = ctcp_data[7:]
      else:
         cmd = b'CTCP'
         lprefix = self.ctcp_prefix
      return b''.join((lprefix, self.format_line_prefix(e, cmd), b' ', ctcp_data))
   
   def format_entry(self, lname, orig_target, e):
      """Return list of formatted lines to given backlog entry originally
         targeted to orig_target with luteus name lname."""
      ctcps = []
      if (isinstance(e, LogLine)):
         if not (e.msg.get_cmd_numeric() is None):
            return []
         
         msg_like = e.is_msglike()
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
            text += b' '.join([self.nmcl_prefix] + e.msg.get_notarget_parameters())
      else:
         text = e.get_text()
      
      ts_str = self.format_ts(e)
      rt = e.get_replay_target(orig_target)
      rs = e.get_replay_source(lname)
      if (text is None):
         rv = []
      else:
         rv = self._make_lines(rs, rt, ts_str, text)

      for ctcp in ctcps:
         text = self.format_ctcp(e, ctcp)
         rv.extend(self._make_lines(rs, rt, ts_str, text))
      
      return rv
   
   def format_backlog(self, bl, lname, orig_target):
      """Return list of privmsgs to format entire backlog."""
      bles = bl.get_bl(orig_target)
      rv = []
      for entry in bles:
         rv.extend(self.format_entry(lname, orig_target, entry))
      
      return rv


class BLFormatter(_LogFormatter):
   def _make_lines(self, prefix, chan, tpf, text):
      """Turn backlog entry into sequence of PRIVMSGs."""
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


class LogFormatter(_LogFormatter):
   def _make_lines(self, prefix, chan, tpf, text):
      """Turn log entry into log line."""
      return [b' '.join((tpf, text)) + b'\n']

   def format_entry(self, e):
      return b''.join(super().format_entry(None, None, e))


def _get_locked_file(fn, init_mode='r+b'):
   try:
      f = open(fn, init_mode)
   except EnvironmentError:
      dn = os.path.dirname(fn)
      if (dn == b''):
         dn = b'.'
      try:
         os.makedirs(dn)
      except OSError as exc:
         from errno import EEXIST
         if (exc.errno != EEXIST):
            raise
      f = open(fn, 'w+b')
   else:
      f.seek(0,2)
      
   import fcntl
   fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
   return f


class LogFile:
   _OPEN_FILES = WeakValueDictionary()
   
   def __init__(self, fn):
      ap = os.path.abspath(fn)
      _lf = self._OPEN_FILES.get(ap)
      if not (_lf is None):
         if (_lf.f):
            raise ValueError("We've opened file {0!a} for logging purposes already. Aborting.".format(fn))
         else:
            _lf.close()
      
      self._OPEN_FILES[ap] = self
      self.fn = fn
      self._open_file()
      self._ts_last_use = time.time()
      
   def _open_file(self):
      f = _get_locked_file(self.fn)
      self.f = f

   def close(self):
      if (self.f is None):
         return
      self.f.close()
      self.f = None
      ap = os.path.abspath(self.fn)
      del(self._OPEN_FILES[ap])

   def put_record(self, r):
      text = self.format_record(r)
      self.f.write(text)
      self.f.flush()
      self._ts_last_use = time.time()


class BacklogFile(LogFile):
   def __init__(self, fn):
      super().__init__(fn)
      self._discarded_record_count = self._get_init_record()
      self._buffered_record_count = len(self.get_records())
   
   def put_record(self, o):
      self.p.dump(o)
      self._buffered_record_count += 1
      self.f.flush()
      #self._ts_last_use = time.time()
   
   def _get_dcb(self):
      return (self._discarded_record_count + self._buffered_record_count)
   
   def _open_file(self):
      import pickle
      super()._open_file()
      self.p = pickle.Pickler(self.f)
      self.u = pickle.Unpickler(self.f)
   
   def _get_init_record(self):
      self.f.seek(0)
      try:
         rv = self.u.load()
      except EOFError:
         rv = 0
         self.f.seek(0)
         self.p.dump(rv)
      else:
         int(rv)
      return rv
   
   def get_records(self, skip=1):
      self.f.seek(0)
      for i in range(skip):
         self.u.load()
      
      rv = []
      while (True):
         try:
            o = self.u.load()
         except EOFError:
            break
         rv.append(o)
      
      self._ts_last_use = time.time()
      return rv
   
   def _discard_data(self, target_drc):
      import pickle
      
      off = target_drc - self._discarded_record_count
      if (off <= 0):
         return
      
      if (off > self._buffered_record_count):
         raise ValueError("Can't discard {0} records from file {1!a}({2}) having {3} (tdrc: {4} drc: {5}).".format(
            off, self.f, self.f.fileno(), self._buffered_record_count, target_drc, self._discarded_record_count))
      
      fn_tmp = self.fn + b'.tmp'
      f_old = self.f
      f_new = _get_locked_file(fn_tmp, 'w+b')
      
      sdb_new = off
      pickler_new = pickle.Pickler(f_new)
      pickler_new.dump(target_drc)
      for record in self.get_records(off+1):
         pickler_new.dump(record)
      
      os.rename(fn_tmp, self.fn)
      f_new.flush()
      self.f.close()
      self._buffered_record_count -= off
      self._discarded_record_count = target_drc
      
      self.f = f_new
      self.p = pickler_new
      self.u = pickle.Unpickler(self.f)
      self._ts_last_use = time.time()

   def clear_records(self):
      data_off = self._discarded_record_count + self._buffered_record_count
      self._discard_data(data_off)


class RawLogFile(LogFile):
   def __init__(self, fn, utc=True, time_fmt=None):
      self.fn = fn
      self.utc = utc
      self.time_fmt = time_fmt
      super().__init__(fn)
   
   def format_record(self, r):
      rv_l = [r.get_time_str(self.time_fmt, utc=self.utc).encode('ascii'), b' ']
      if (isinstance(r, LogLine)):
         if (r.outgoing):
            rv_l.append(b'< ')
         else:
            rv_l.append(b'> ')
         rv_l.append(r.msg.line_build().rstrip(b'\r\n'))
      else:
         rv_l.append(r.get_text())
      
      rv_l.append(b'\n')
      return b''.join(rv_l)

class HRLogFile(LogFile):
   def __init__(self, fn, formatter):
      self.formatter=formatter
      super().__init__(fn)
   
   def format_record(self, r):
      return self.formatter.format_entry(r)


class LogFilter:
   def __init__(self):
      self._eat_all_servers = False
      self._eatable_sources = set()
      self._eatable_nicks = set()
      self._eat_all_ctcp_out = False
   
   def set_eat_servers(self, es):
      self._eat_all_servers = es
   
   def set_eat_all_ctcp_out(self, b):
      self._eat_all_ctcp_out = b
   
   def add_filtered_source(self, s):
      self._eatable_sources.add(IRCCIString(s))
   
   def add_filtered_nick(self, n):
      self._eatable_nicks.add(IRCCIString(n))
   
   def __call__(self, ctx, r):
      if not (isinstance(r, LogLine)):
         return True
      prefix = r.msg.prefix
      if (r.outgoing):
         if (self._eat_all_ctcp_out):
            (text, ctcps) = r.msg.split_ctcp()
            if (ctcps):
               for tf in text:
                  if (tf):
                     break
               else:
                  for ctcp in ctcps:
                     if (ctcp.startswith(b'ACTION')):
                        break
                  else:
                     return False
      else:
         if ((prefix is None) or prefix.is_server()):
            if (self._eat_all_servers):
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
   maintenance_delay = 60
   file_timeout = 60
   
   def __init__(self, basedir, nc, filter=None):
      if (filter is None):
         filter = LogFilter()
      self.basedir = basedir
      self.nc = nc
      self.filter = filter
      self._storage = {}
      self.maintenance_timer = None
      self._ems_reg()
   
   def _ems_reg(self):
      self.nc.em_in_msg.new_prio_listener(self._process_msg_in, 1)
      self.nc.em_out_msg.new_prio_listener(self._process_msg_out, -512)
      self.nc.em_shutdown.new_prio_listener(self._process_conn_shutdown, -512)
      self.nc.sa.ed.em_shutdown.new_listener(self._process_process_shutdown)
   
   def _do_maintenance(self):
      now = time.time()
      for (ctx,f) in tuple(self._storage.items()):
         delta = now - f._ts_last_use
         if (delta < 0):
            self.log(30, 'File allegedly last accessed {0} seconds into the future; negative clock warp?'.format(-1*delta))
         elif (delta < self.file_timeout):
            continue
         f.close()
         del(self._storage[ctx])
      
      if not (self._storage):
         self.maintenance_timer.cancel()
         self.maintenance_timer = None
   
   def _shedule_maintenance(self):
      if not (self.maintenance_timer is None):
         return
      self.maintenance_timer = self.nc.sa.ed.set_timer(self.maintenance_delay,
         self._do_maintenance, persist=True)
   
   def _get_file(self, chan):
      try:
         rv = self._storage[chan]
      except KeyError:
         rv = self.make_file(self._get_fn(chan))
         self._storage[chan] = rv
         self._shedule_maintenance()
      
      return rv
   
   def _put_record_file(self, ctx, r):
      if not (self.filter(ctx, r)):
         return
      
      self._get_file(ctx).put_record(r)
   
   def _process_process_shutdown(self):
      r = LogProcessShutdown()
      channels = self.nc.get_channels(stale=True)
      if not (channels is None):
         for chan in channels:
            self._put_record_file(chan, r)
      for f in self._storage.values():
         f.close()
      self._storage.clear()

   def _process_conn_shutdown(self):
      r = LogConnShutdown(self.nc.get_peer_address(stale=True))
      for chan in self.nc.get_channels(stale=True):
         self._put_record_file(chan, r)
   
   def _get_src(self, msg, outgoing):
      src = msg.prefix
      if (src is None):
         if (outgoing):
            src = self.nc.get_self_nick()
         else:
            src = self.nc.get_peer()
            if (src is None):
               src = b'?'
            src = msg.pcs.make_irc_addr(src)
            src.type = IA_SERVER
      return src
   
   def _process_msg_in(self, msg):      
      self._process_msg(msg, False)
      
   def _process_msg_out(self, msg):
      self._process_msg(msg, True)
   
   def _preprocess_in_msg(self, msg):
      if (not (msg.command in (b'PRIVMSG', b'NOTICE'))):
         return msg
      if (len(msg.parameters) < 2):
         return msg
      
      
      text = msg.parameters[1]
      (tf, ctcps) = msg.split_ctcp()
         
      for ctcp in ctcps:
         if (not ctcp.startswith(b'ACTION')):
            ctcp_like = True
            break
      else:
         ctcp_like = False
         
      if (ctcp_like and (self.nc.conn.FC_IDENTIFY_CTCP & self.nc.conn.fc) or
         ((not ctcp_like) and (self.nc.conn.FC_IDENTIFY_MSG & self.nc.conn.fc) and
         ((msg.parameters[0] != b'$*') or (msg.command != 'NOTICE')))):
         # Freenode message prefix mangling should have been applied to this
         # line; remove it.
         if (text and (text[0] in b'+-')):
            msg = msg.copy()
            msg.parameters[1] = text[1:]
         else:
            self.log(40, "{0} got message {1} from {2}, which doesn't appear to have undergone freenode prefix mangling even though we expected it. This is ok for this message, but indicates a desync that will most likely lead to silent data corruption elsewhere. FIX THIS!".format(self, msg, self.nc))
      return msg

   @classmethod
   def _map_nick_ctxs(cls, ctx_s):
      return ctx_s

   def _process_msg(self, msg_orig, outgoing):
      rv = set()
      if (not outgoing):
         msg = self._preprocess_in_msg(msg_orig)
      else:
         msg = msg_orig
      
      src = self._get_src(msg, outgoing)
      msg2 = msg.copy()
      msg2.src = None
      
      bll = ChanLogLine(msg2, src, outgoing)
      # Determine logging contexts
      num = msg.get_cmd_numeric()
      if (num is None):
         (nicks, chans) = msg.get_targets()
         if (nicks):
            if (msg_orig.cmd == b'MODE'):
               # Getting self-mode spam in (back)logs is annoying. Drop it here.
               del(nicks[:])
            elif (not outgoing):
               if (src.is_nick()):
                  bll_src = msg.pcs.make_cib(src.nick)
               else:
                  bll_src = msg.pcs.make_cib(src)
               nicks = [bll_src]
      else:
         nicks = []
         if (num in (332, 333, 366)):
            chans = [msg.pcs.make_cib(msg.parameters[1])]
         elif (num == 353):
            chans = [msg.pcs.make_cib(msg.parameters[2])]
         else:
            chans = []
      
      if (chans):
         rv.update(chans)
         for chan in chans:
            self._put_record_file(chan, bll)
      
      if (nicks):
         nicks = self._map_nick_ctxs(nicks)
         rv.update(nicks)
         bll_nick = NickLogLine(msg2, src, outgoing)
         for nick in nicks:
            self._put_record_file(nick, bll_nick)
      
      is_aux = (msg.command in self.BC_AUXILIARY)
      if (is_aux):
         # Log non-channel commands to chan contexts: NICK and QUIT
         for chan in msg_orig.affected_channels:
            rv.add(chan.name)
            self._put_record_file(chan.name, bll)
      
      return (is_aux, rv)
   
   def _get_fn(self, ctx):
      if (ctx is None):
         ctx = b'nicks\x07'
      else:
         ctx = ctx.normalize()
      return os.path.join(self.basedir, self.nc.netname.encode(), ctx)


class RawLogger(_Logger):
   def __init__(self, *args, utc=True, time_fmt=None, **kwargs):
      self.utc = utc
      self.time_fmt = time_fmt
      super().__init__(*args, **kwargs)
   
   def _preprocess_in_msg(self, msg):
      return msg
   
   def make_file(self, fn):
      return RawLogFile(fn, self.utc, self.time_fmt)


class HRLogger(_Logger):
   def __init__(self, formatter, *args, **kwargs):
      if (formatter is None):
         raise Exception
      self.formatter = formatter
      super().__init__(*args, **kwargs)
   
   def make_file(self, fn):
      return HRLogFile(fn, self.formatter)


class BackLogger(_Logger):
   make_file = BacklogFile
   def __init__(self, basedir, bnc, *args, **kwargs):
      self.bnc = bnc
      super().__init__(basedir, bnc.nc, *args, **kwargs)
   
   def reset_bl(self, ctx):
      f = self._get_file(ctx)
      f.clear_records()
   
   def get_bl(self, ctx):
      return self._get_file(ctx).get_records()
   
   @classmethod
   def _map_nick_ctxs(cls, ctx_s):
      return [None]*bool(ctx_s)
   
   def _put_record_file(self, ctx, r):
      super()._put_record_file(ctx, r)


class AutoDiscardingBackLogger(BackLogger):
   """Backlogger which automatically deletes backlog entries after they have been passed to a client."""
   ping_delay_max = 8
   def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)

   def _ems_reg(self):
      self.bnc.em_client_msg_fwd.new_prio_listener(self._process_msg)
      self.bnc.em_client_bl_dump.new_prio_listener(self._process_data_fwd)
      
      self.nc.em_shutdown.new_prio_listener(self._process_conn_shutdown, -512)
      self.nc.sa.ed.em_shutdown.new_listener(self._process_process_shutdown)
   
   def _process_data_fwd(self, ipscs, ctx_s):
      # If we're called, that means the data has been put into the output buffer to one or more of the clients connected to
      # our bouncer. It does not mean that we've actually pushed it out to the network or that the TCP connection is still
      # alive, and as such the client may never actually see it.
      # To reliably avoid data loss, we'll queue a ping to all eligible clients here, and only actually discard the data once
      # we get a reply.
      
      if (ipscs):
         cb_args_s = [(ctx, self._get_file(ctx)._get_dcb()) for ctx in ctx_s]
         def discard_data(ctx, dcb):
            self._get_file(ctx)._discard_data(dcb)
         
         for ipsc in ipscs:
            for cb_args in cb_args_s:
               # Queuing the request at the front means that we get called for our last request associated with this ping
               # *first*. This allows us to be more efficient in discarding the data.
               ipsc.queue_ping(self.ping_delay_max, discard_data, cb_args, front=True)
      
         del(ipsc)
      del(ipscs)

   def _process_msg(self, ipscs, msg, outgoing):
      (is_aux, bl_contexts) = super()._process_msg(msg, outgoing)
      if (is_aux):
         # BNCs (currently) don't filter these messages based on client interest, so we need to check for wanted channels here
         # to prevent spurious backlog message discarding.
         for ipsc in ipscs:
            blc_out = bl_contexts & ipsc.wanted_channels
            self._process_data_fwd((ipsc,), blc_out)
      else:
         self._process_data_fwd(ipscs, bl_contexts)


def _main():
   # BL selftests
   print('===== Performing backlogger selftest. =====')
   print('==== Making backlogger instance. ====')
   bl = BackLogger.__new__(BackLogger)
   bl._ems_reg = lambda: None
   bl._shedule_maintenance = lambda: None
   fn = b'__loggingselftests.bin.tmp'
   bl._get_fn = lambda x: fn
   _Logger.__init__(bl, '.', None)
   
   ctx = IRCCIString(fn)
   ridx = 0
   def pr():
      nonlocal ridx
      bl._put_record_file(ctx, (ridx,))
      ridx += 1
   def rb():
      bl.reset_bl(ctx)
   
   print('==== Executing store/retrieve/reset test. ====')
   for i in range(64):
      dcb_l = []
      for j in range(64):
         for k in range(16):
            pr()
         dcb_l.append(bl._get_file(ctx)._get_dcb())
      
      if (i % 2):
         dcb_l.reverse()
      
      for dcb in dcb_l:
         bl._get_file(ctx)._discard_data(dcb)
   
   print('==== Passed. ====')
   print('===== All done. =====')

if (__name__ == '__main__'):
   _main()
