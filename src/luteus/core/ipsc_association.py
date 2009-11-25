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

import logging

from .s2c_structures import IRCMessage
from .irc_num_constants import ERR_PASSWDMISMATCH, ERR_NEEDMOREPARAMS


class _LuteusUser:
   def __init__(self, name, password):
      self.name = name
      self.password = password
      self._nets = {}
   
   def add_bnc(self, bnc):
      """Add allowed BNC."""
      nn = bnc.nc.netname
      if (isinstance(nn, str)):
         nn = nn.encode()
      
      if (nn in self._nets):
         raise ValueError("I already have bnc {0!a} for network {1!a}.".format(self._nets[nn], nn))
      
      self._nets[nn] = bnc


class NetUserAssocHandler:
   logger = logging.getLogger()
   log = logger.log
   
   def __init__(self, ed, close_unauthed=True):
      self.ed = ed
      self.users = {}
      self._close_unauthed = close_unauthed
   
   def add_user(self, name, password, *args, **kwargs):
      """Add new user to assoc handler and return it."""
      if (isinstance(name, str)):
         name = name.encode()
      if (isinstance(password, str)):
         password = password.encode()

      if (name in self.users):
         raise ValueError("I already have a user named {0}.".format(name))
      rv = _LuteusUser(name, password, *args, **kwargs)
      self.users[name] = rv
      return rv
   
   def attach_ips(self, ips, priority=1024):
      ips.em_in_msg.new_prio_listener(self._handle_msg)
   
   def _handle_msg(self, conn, msg):
      cmd = msg.command
      if (cmd != b'PASS'):
         self.ed.set_timer(0, self.check_conn, args=(conn,),
            interval_relative=False)
         return
      
      if (len(msg.parameters) < 1):
         conn.send_msg_num(ERR_NEEDMOREPARAMS, cmd, b'Insufficient parameters.')
         return
      
      arg = msg.parameters[0]
      try:
         (netname, username, pw) = arg.split(b':',2)
      except ValueError:
         conn.send_msg_num(ERR_PASSWDMISMATCH, cmd, b'Invalid pass string; I want <netname>:<user>:<password>.')
         return
      
      try:
         user = self.users[username]
      except KeyError:
         conn.send_msg_num(ERR_PASSWDMISMATCH, cmd, b'Auth failed.')
         return
      
      if (user.password != pw):
         conn.send_msg_num(ERR_PASSWDMISMATCH, cmd, b'Auth failed.')
         return
      
      try:
         conn_mgr = user._nets[netname]
      except KeyError:
         conn.send_msg_num(ERR_PASSWDMISMATCH, cmd, b'Unknown netname for this user.')
         return
      
      conn.__conn_mgr = conn_mgr

   def check_conn(self, conn):
      if not (conn.peer_registered()):
         return
      if not (conn.mgr is None):
         return
      
      try:
         conn_mgr = conn.__conn_mgr
      except AttributeError:
         if (not conn):
            return
         elif (self._close_unauthed):
            conn.send_msg_num(ERR_PASSWDMISMATCH, b'*', b'No valid auth performed. Terminating connection.')
            conn.close()
         return
      else:
         del(conn.__conn_mgr)
      
      try:
         conn.take_connection(conn_mgr)
      except IRCPSStateError:
         return
      
      try:
         conn_mgr.take_ips_connection(conn)
      except Exception as exc:
         conn.send_msg(IRCMessage(None, b'ERROR', [b'Internal error; check luteus log for details.']))
         self.log(40, 'Failed to pass on connection {0}; closing it. Error:'
            .format(conn), exc_info=True)
         conn.mgr = None
         conn.close()
