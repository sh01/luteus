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

from gonium.fdm.stream import AsyncLineStream

from .event_multiplexing import OrderingEventMultiplexer
from .s2c_structures import *

class IRCs2cConnection(AsyncLineStream):
   EM_NAMES = ('em_in_raw', 'em_in_msg', 'em_out_msg', 'em_link_finish',
      'em_shutdown')
   
   def __init__(self, *args, **kwargs):
      AsyncLineStream.__init__(self, *args, lineseps={b'\n', b'\r'}, **kwargs)
      self.nick = None
      self.channels = None
      self.auth = 1 #TODO: do this right

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
      self.send_bytes((line_out,))
   
