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

from collections import ByteString
import re

from ..core.s2c_structures import IRCCIString, IRCMessage
from .autoline import arg2msg

class AutoResponder:
   def __init__(self):
      self._cmd_map = {}
   
   def attach_nc(self, nc):
      def cb(msg):
         self._process_msg(nc, msg)
      nc.em_in_msg.new_prio_listener(cb, 1024)

   def handle_msg_cb(self, *args, **kwargs):
      """Handle a query CB triggered by a msg sent by us."""
      pass

   def add_autoresponse_func(self, cmd, line_re, reply_maker):
      """Add function to be called when line_re matches against args of line
         with specified command. It will be called as reply_maker(nc), with the
         relevant network client as the only argument, and should return a
         sequence of IRCMessage instances at that time."""
      line_re_ = line_re
      if (isinstance(line_re_,ByteString)):
         line_re_ = re.compile(line_re_)
      
      try:
         line_re_.search(b'test')
      except Exception as exc:
         raise TypeError("Don't know what to do with {0!a} value for line_re arg.".format(line_re_)) from exc
      
      try:
         ar_data = self._cmd_map[cmd]
      except KeyError:
         ar_data = self._cmd_map[cmd] = list()
      
      ar_data.append((line_re_, reply_maker))
      
   def add_autoresponse_static(self, cmd, line_re, reply):
      """Add a static single-line autoresponder."""
      msg = arg2msg(reply)
      
      def make_reply(*args, **kwargs):
         return [reply]
      
      return self.add_autoresponse_func(self, cmd, line_re, make_reply)
   
   def add_autoresponse_by_nick(self, cmd, line_re, pattern, nick_map):
      """Add nick-specific autoresponse."""
      nick_map_ = {}
      codec = 'latin-1'
      for (nick, val) in nick_map.items():
         IRCMessage.build_from_line(pattern.format(nick=nick.decode(codec), tok=val).encode(codec)).line_build()
         nick_map_[IRCCIString(nick)] = val
      
      def make_reply(nc, msg):
         nick = nc.get_self_nick()
         if not (nick in nick_map_):
            return ()
         tok = nick_map_[nick]
         return (IRCMessage.build_from_line(pattern.format(nick=nick.decode(codec), tok=tok).encode(codec)),)
      
      del(nick_map)
      return self.add_autoresponse_func(cmd, line_re, make_reply)
   
   def _process_msg(self, nc, msg):
      ce = self._cmd_map.get(msg.command, ())
      line = msg.line_build()
      
      for (line_re, reply_maker) in ce:
         m = line_re.search(line)
         if (m is None):
            continue
         msgs = reply_maker(nc, msg)
         for msg in msgs:
            nc.conn.put_msg(msg, self.handle_msg_cb)
      


