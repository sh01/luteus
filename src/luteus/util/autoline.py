#!/usr/bin/env python3
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

from collections import deque, ByteString

from ..core.s2c_structures import IRCMessage

class AutoLineSender:
   def __init__(self):
      self._msgs = deque()
      self._mm = deque()
   
   def handle_msg_cb(self, *args, **kwargs):
      pass
   
   def add_line(self, data):
      msg = data
      
      if (isinstance(msg, str)):
         msg = msg.encode('latin-1')
      if (isinstance(data, ByteString)):
         msg = IRCMessage.build_from_line(msg)
      try:
         msg.line_build()
      except Exception as exc:
         raise TypeError("Don't know what to do with {0!a}.".format(data)) from exc
      
      self._msgs.append(msg)
   
   def add_line_maker(self, c):
      self._mm.append(c)
   
   def attach_nc(self, nc, priority=1024):
      def cb():
         self._process_link(nc)
      nc.em_link_finish.new_prio_listener(cb, priority)
   
   def _process_link(self, nc):
      for msg in self._msgs:
         nc.conn.put_msg(msg, self.handle_msg_cb)
         
      for mm in self._mm:
         msg = mm(nc)
         nc.conn.put_msg(msg, self.handle_msg_cb)


def mmm_selfmode(modes):
   m = modes
   if (isinstance(m, str)):
      m = m.encode()
   
   def mm_nick(n):
      return IRCMessage(None, b'MODE', [n, m])
   
   def mm_selfmode(nc):
      return mm_nick(nc.conn.nick)
   
   try:
      mm_nick(b'foo').line_build()
   except Exception as exc:
      raise TypeError("Don't know what to do with {0!a}.".format(modes)) from exc
   
   return mm_selfmode

