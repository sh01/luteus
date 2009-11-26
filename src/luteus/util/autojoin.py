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

class AutoJoiner:
   def __init__(self):
      self.channels = {}
   
   def add_channel(self, chan, key=None):
      if (isinstance(chan, str)):
         chan = chan.encode()
      self.channels[chan] = key
   
   def attach_nc(self, nc, priority=1024):
      def cb():
         self._process_link(nc)
      nc.em_link_finish.new_prio_listener(cb, priority)
   
   def _process_link(self, nc):
      for (chan, key) in self.channels.items():
         nc.conn.add_autojoin_channel(chan, key)

