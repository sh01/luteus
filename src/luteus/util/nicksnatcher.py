#!/usr/bin/env python3
#Copyright 2010,2011 Sebastian Hagen
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

from ..core.s2c_structures import *

class _NickPrefList(list):
   def get_preference(self, val):
      try:
         return self.index(val)
      except IndexError:
         return len(self)


#class NickSnatcher:
   #"""Code for reclaiming nicks not available on initial connect later."""
   #def __init__(self, nc):
      #self.nc = nc
      #self.active = False
      #self.nc.em_link_finish.new_prio_listener(self.process_link)
      #self.nc.em_chan_leave.new_prio_listener(self.process_chan_leave)
      #self.nan = set() #newly available nicks
      #self.nan_process_timer = None
   
   #def nan_process(self):
      #"""Process newly available nicks."""
      #self.nan_process_timer = None
      #current_nick = self.nc.get_self_nick()
      #if (current_nick is None):
         ## No server link. Never mind all of this, then.
         #return
      
      #nicks = _NickPrefList(self.nc.us.nicks.values())
      #cn_i = nicks.get_preference(current_nick)
      
      #best_i = cn_i
      #for nick in self.nan:
         #i = nicks.get_preference(nick)
         #if (i < best_i):
            #best_i = i
      
      #if (cn_i == best_i):
         #return
      
      #self.nc.conn.put_msg(IRCMessage(None, b'NICK', (nicks[best_i],),
         #src=self, pcs=self.nc.conn.pcs), None)
      
      #if (best_i == 0):
         #self.active = False
   
   #def process_chan_leave(self, msg, victim, chan, perpetrator):
      #if (msg.command != b'QUIT'):
         #return
      #self.nan.add(victim)
      #if not (self.nan_process_timer is None):
         #return
      #self.nan_process_timer = nc.sa.ed.set_timer(0, self.nan_proces,
         #interval_relative=False)
   
   #def process_link(self):
      #self.active = bool(self.nc.us.nicks)
      

class NickGhoster:
   def __init__(self, nc):
      self.nc = nc
      self.nc.em_link_finish.new_prio_listener(self.process_link)
      self.target_nick = None
      self.msg_listener = None
      
   def _start_listening(self):
      if not (self.msg_listener is None):
         return
      self.msg_listener = self.nc.em_in_msg_bc.new_prio_listener(self.handle_msg_bc)

   def _stop_listening(self):
      if (self.msg_listener is None):
         return
      self.msg_listener.close()
      self.msg_listener = None
   
   def handle_msg_bc(self, msg):
      """Handle a query CB triggered by a msg sent by us."""
      if not (msg.command == b'NOTICE'):
         return
      
      try:
         src_nick = msg.prefix.nick.lower()
      except AttributeError:
         return
      
      if (src_nick != b'nickserv'):
         return
      
      params = msg.parameters
      if (len(params) < 2):
         return
      
      text = params[1]
      if not ((text == b'Ghost with your nick has been killed.') or
         text.endswith(b' has been ghosted.') or
         text.endswith(b" isn't currently in use.") or
         text.endswith(b' is not online.')):
         return
      
      self.nc.conn.put_msg(IRCMessage(None, b'NICK', (self.target_nick,)), None)
      self.target_nick = None
      self._stop_listening()
   
   def process_link(self):
      current_nick = self.nc.get_self_nick()
      nicks = _NickPrefList(self.nc.us.nicks.values())
      cn_i = nicks.get_preference(current_nick)
      
      for nick in nicks[:cn_i]:
         try:
            nspw = nick.nspw
         except AttributeError:
            continue
         self.target_nick = nick
         self._start_listening()
         self.nc.conn.put_msg(IRCMessage(None, b'NICKSERV',
             (b' '.join((b'GHOST', nick, nspw.encode('ascii'))),), self), None)
         break
      else:
         self.target_nick = None
   
   
