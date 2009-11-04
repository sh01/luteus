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
import time

from gonium.fdm.stream import AsyncLineStream, AsyncSockServer

from .event_multiplexing import OrderingEventMultiplexer, EAT_ALL
from .s2c_structures import *


class DefaultAssocHandler:
   logger = logging.getLogger()
   log = logger.log
   
   def __init__(self, ed, conn_mgr):
      self.ed = ed
      self.cc_timer = None
      self.conn_mgr = conn_mgr
      
   def attach_ips(self, ips, priority=1024):
      ips.em_in_msg.new_prio_listener(self.handle_msg)
   
   def check_conn(self, conn):
      self.cc_timer = None
      if not (conn.peer_registered()):
         return
      
      try:
         rv_exc = conn.take_connection()
      except IRCPSStateError:
         return
      try:
         self.conn_mgr.take_ips_connection(conn)
      except Exception as exc:
         self.log(40, 'Failed to pass on connection {0}; closing it. Error:'
            .format(conn), exc_info=True)
         conn.close()
   
   def handle_msg(self, conn, msg):
      if not (self.cc_timer is None):
         return
      self.cc_timer = self.ed.set_timer(0, self.check_conn, args=(conn,),
         interval_relative=False)
      

class IRCPseudoServer(AsyncSockServer):
   def __init__(self, ed, *args, **kwargs):
      self.ed = ed
      self.start_ts = time.time()
      AsyncSockServer.__init__(self, ed, *args, **kwargs)
      self.em_in_msg = OrderingEventMultiplexer(self)
      self.em_new_conn = OrderingEventMultiplexer(self)
      
      self.els = []
   
   def connect_process(self, sock, addressinfo):
      conn = IRCPseudoServerConnection(self.ed, sock, ssts=self.start_ts)
      def eh(msg):
         if (self.em_in_msg(conn, msg)):
            el.close()
      
      el = conn.em_in_msg.new_prio_listener(eh, -1024)
      self.em_new_conn(conn)
   
   def close(self):
      AsyncSockServer.__close__()
      
      for el in self.els:
         el.close()
      del(self.els[:])
   
   
class IRCPSStateError(Exception):
   pass


class IRCPseudoServerConnection(AsyncLineStream):
   logger = logging.getLogger('IRCPseudoServerConnection')
   log = logger.log
   
   EM_NAMES = ('em_in_raw', 'em_in_msg', 'em_out_msg', 'em_shutdown')
   def __init__(self, *args, ssts, **kwargs):
      AsyncLineStream.__init__(self, *args, lineseps={b'\n', b'\r'}, **kwargs)
      self.associated = False
      self.ssts = ssts
      self.nick = b''
      self.user = None
      self.mode_str = None
      self.realname = None
      
      self.channels = None
      self.self_name = b'luteus.bnc'
      self.peer_address = self.fl.getpeername()[0]
      
      for name in self.EM_NAMES:
         self.em_new(name)
         
      self.em_in_msg.new_prio_listener(self.process_input_statekeeping)
      
   def em_new(self, attr):
      """Instantiate new EventMultiplexer attribute"""
      setattr(self, attr, OrderingEventMultiplexer(self))

   def _pc_check(self, msg, num:int):
      """Throw exception if msg has less than the specified number of
         parameters."""
      if (len(msg.parameters) < num):
         raise IRCProtocolError(msg, 'Insufficient arguments; expected at least'
            ' {0}.'.format(num))

   def process_close(self):
      """Process connection closing."""
      self.em_shutdown()

   def take_connection(self):
      """Try to take this connection.
         Mostly intended for use from IRCPS EMs. Will raise an exception if
         connection has been taken already; otherwise will *return* an
         exception object for caller to raise iff they were called from an
         IRCPS EM."""
      if (self.associated):
         raise IRCPSStateError("Already associated.")
      
      self.associated = True
      return EAT_ALL()

   def process_input(self, line_data_mv):
      """Process IRC data"""
      line_data = bytearray(bytes(line_data_mv).rstrip(b'\r\n'))
      if (self.em_in_raw(line_data)):
         return
      if (line_data == b''):
         return
      msg = IRCMessage.build_from_line(line_data, src=self)
      if (self.em_in_msg(msg)):
         return
      
   def process_input_statekeeping(self, msg):
      """Do local input processing."""
      try:
         cmd_str = msg.command.decode('ascii')
      except UnicodeDecodeError:
         self.log(30, 'Peer {0} sent undecodable message {1}.'.format(self.peer_address, msg))
         return
      
      fn = '_process_msg_{0}'.format(cmd_str)
      try:
         func = getattr(self,fn)
      except AttributeError:
         return
      
      try:
         func(msg)
      except IRCProtocolError as exc:
         self.log(30, 'From {0}: msg {1} failed to parse: {2}'.format(
            self.peer_address, msg, exc), exc_info=True)
      
   
   def send_msg(self, msg):
      """Send MSG to peer."""
      self.em_out_msg(msg)
      line_out = msg.line_build()
      self.send_bytes((line_out,))
   
   def send_msg_num(self, num, *args):
      """Send numeric to peer"""
      cmd = '{0:03}'.format(num).encode('ascii')
      msg = IRCMessage(self.self_name, cmd, (self.nick,) + args)
      self.send_msg(msg)
   
   def send_msg_001(self, netname=b'Cruentus IRC bouncer', ia_user=None):
      if (ia_user is None):
         if (self.nick is None):
            raise ValueError('No nick for peer known.')
         
         ia_user = self.nick + b'!' + self.user + b'@' + self.peer_address.encode('ascii')
      
      self.send_msg_num(1, b'Welcome to ' + netname + b', ' + ia_user)
   
   def send_msg_002(self, host=None, version='foo'):
      if (host is None):
         host = self.fl.getsockname()[0]
      
      self.send_msg_num(2, 'Your host is {0}, running version {1}'
         .format(host, version).encode('ascii'))
   
   def send_msg_003(self, ts=None):
      if (ts is None):
         ts = self.ssts
      
      tstr = time.strftime('%Y-%m-%d', time.gmtime(ts))
      
      self.send_msg_num(3, 'This server was created {0}'.format(tstr)
         .encode('ascii'))
   
   def change_nick(self, newnick):
      """Force nickchange."""
      if (self.nick == newnick):
         return
      self.send_msg(IRCMessage(self.nick, b'NICK', (newnick,)))
      self.nick = newnick
   
   def _process_msg_PING(self, msg):
      """Answer PING."""
      self.send_msg(IRCMessage(self.self_name, b'PONG', msg.parameters[:1]))
      
   def _process_msg_NICK(self, msg):
      """Process NICK."""
      if (self.nick):
         return
      
      if (len(msg.parameters) < 1):
         self.send_msg(IRCMessage(self.self_name, b'431',
            (b'', b'No nickname given.')))
         return
      
      self.nick = msg.parameters[0]
   
   def _process_msg_USER(self, msg):
      """Process USER."""
      if (self.user):
         self.send_msg(IRCMessage(self.self_name, b'462',
            (self.nick, b"You sent a USER line before.")))
         return
      
      if (len(msg.parameters) < 4):
         self.send_msg(IRCMessage(self.send_name, b'461',
            (self.nick, b"Insufficient parameters.")))
      
      self.user = msg.parameters[0]
      self.mode_str = msg.parameters[1]
      self.realname = msg.parameters[3]
   
   def peer_registered(self):
      return bool(self.nick and self.user)
      
