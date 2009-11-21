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

from .s2c_structures import IA_NICK

class BacklogLine:
   def __init__(self, msg, src, outgoing, ts=None):
      if (ts is None):
         ts = time.time()
      self.ts = ts
      self.msg = msg
      self.outgoing = outgoing

class BacklogChanSnapshot:
   def __init__(self, chan_data):
      self.chan_data = chan_data


class BacklogFile:
   def __init__(self, fn):
      self.fn = fn
      self._open_file()
      
   def _open_file(self):
      fn = self.fn
      try:
         f = open(fn, 'r+b')
      except EnvironmentError:
         os.makedirs(os.path.dirname(fn))
         f = open(fn, 'w+b')
      else:
         f.seek(0,2)
      
      fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcnt.LOCK_NB)
      
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
         except UnpicklingError:
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
      
      self.nc.em_in_msg_bc.new_prio_listener(self._process_msg_in, -1024)
      self.nc.em_out_msg.new_prio_listener(self._process_msg_out, -1024)
   
   def _get_file(self, chan):
      try:
         rv = self._storage[chan]
      except KeyError:
         rv = self.file_cls(self._get_fn(chan))
         self._storage[chan] = rv
      
      return rv
   
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
      bll = BacklogLine(msg, src, outgoing)
      chans = msg.get_chan_targets()
      if not (chans is None):
         for chan in chans:
            self._get_file(chan).put_record(bll)
         return
      
      if not (msg.command.upper() in self.BC_AUXILIARY):
         return
      
      chan_map = self.nc.get_channels()
      chans = set(chan_map.keys())
      if (not (msg.prefix is None) and (msg.prefix.type == IA_NICK)):
         for chan in tuple(chans):
            if (msg.prefix.nick in chan_map[chan].users):
               continue
            chans.remove(chan)
      
      for chan in chans:
         self._get_file(chan).put_record(bll)
      
   
   def _get_fn(self, chan):
      return os.path.join(self.basedir, self.nc.netname, chan)
   

class BackLogger(_Logger):
   file_cls = BacklogFile
   def reset_bl(self, chann):
      f = self._get_file(chan)
      f.clear_records()
      try:
         chan = self.nc.channels[chann]
      except KeyError:
         return
      f.put_record(BacklogChanSnapshot(chan))
   
   def get_bl(self, chann):
      return self._get_file(chann).get_records()

