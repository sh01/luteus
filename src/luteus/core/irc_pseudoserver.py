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

class IRCPSStateError(Exception):
   pass


class IRCPseudoServer(AsyncSockServer):
   conn_timeout = 30
   def __init__(self, ed, *args, **kwargs):
      self.ed = ed
      self.start_ts = time.time()
      AsyncSockServer.__init__(self, ed, *args, **kwargs)
      self.em_in_msg = OrderingEventMultiplexer(self)
      self.em_new_conn = OrderingEventMultiplexer(self)
      
      self.els = []
   
   def connect_process(self, sock, addressinfo):
      conn = IRCPseudoServerConnection(self.ed, sock, ssts=self.start_ts)
      conn.sock_set_keepalive(1)
      conn.sock_set_keepidle(self.conn_timeout, self.conn_timeout, 2)
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


class IRCPseudoServerConnection(AsyncLineStream):
   logger = logging.getLogger('IRCPseudoServerConnection')
   log = logger.log
   
   EM_NAMES = ('em_in_raw', 'em_in_msg', 'em_out_msg', 'em_shutdown')
   def __init__(self, *args, ssts, self_name=b'luteus.bnc', **kwargs):
      AsyncLineStream.__init__(self, *args, lineseps={b'\n', b'\r'}, **kwargs)
      self.ts_init = time.time()
      self.mgr = None
      self.ssts = ssts
      self.nick = None
      self.user = None
      self.mode_str = None
      self.realname = None
      self.wanted_channels = set()
      
      self.self_name = self_name
      self.peer_address = self.fl.getpeername()
      
      for name in self.EM_NAMES:
         self.em_new(name)
         
      self.em_in_msg.new_prio_listener(self.process_input_statekeeping)
      
   def em_new(self, attr):
      """Instantiate new EventMultiplexer attribute"""
      setattr(self, attr, OrderingEventMultiplexer(self))

   def process_close(self):
      """Process connection closing."""
      self.em_shutdown()

   def take_connection(self, mgr):
      """Try to take this connection.
         Mostly intended for use from IRCPS EMs. Will raise an exception if
         connection has been taken already."""
      if not (self.mgr is None):
         raise IRCPSStateError("Already associated.")
      
      self.mgr = mgr

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
      except IRCInsufficientParametersError as exc:
         self.send_msg_461(msg.command)
      except IRCProtocolError as exc:
         self.log(30, 'From {0}: msg {1} failed to parse: {2}'.format(
            self.peer_address, msg, exc))
   
   def _pc_check(self, msg, num:int, send_error=False):
      """Throw exception if msg has less than the specified number of
         parameters."""
      if (len(msg.parameters) >= num):
         return
      if (send_error):
         raise IRCInsufficientParametersError(msg, 'Insufficient parameters.')
      raise IRCProtocolError(msg)
   
   def send_msg(self, msg):
      """Send MSG to peer."""
      self.em_out_msg(msg)
      line_out = msg.line_build()
      self.send_bytes((line_out,))
   
   def _get_nick(self):
      rv = self.nick
      if (rv is None):
         rv = b'*'
      return rv
   
   def get_user_ia(self):
      """Return dummy IRCAddress with our nick."""
      rv = IRCAddress(b''.join((self.nick, b'!luteususer', b'@', self.self_name)))
      return rv
   
   def send_msg_num(self, num, *args):
      """Send numeric to peer"""
      cmd = '{0:03}'.format(num).encode('ascii')
      msg = IRCMessage(self.self_name, cmd, (self._get_nick(),) + args)
      self.send_msg(msg)
   
   def send_msg_001(self, netname=b'Cruentus IRC bouncer', ia_user=None):
      if (ia_user is None):
         if (self.nick is None):
            raise ValueError('No nick for peer known.')
         
         ia_user = self.get_unhmask()
      
      self.send_msg_num(1, b''.join((b'Welcome to ', netname, b', ', ia_user)))
   
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
   
   def send_msgs_005(self, isupport_data):
      msgs = isupport_data.get_005_lines(self.nick, self.self_name)
      for msg in msgs:
         self.send_msg(msg)
   
   def send_msg_461(self, cmd):
      self.send_msg(IRCMessage(self.self_name, b'461',
         (self._get_nick(), cmd, b"Insufficient parameters.")))
   
   def change_nick(self, newnick):
      """Force nickchange."""
      if (self.nick == newnick):
         return
      self.send_msg(IRCMessage(self.nick, b'NICK', (newnick,)))
      self.nick = newnick
   
   def wc_add(self, chann):
      """Add channel name to wanted chan set"""
      chann = IRCCIString(chann)
      if (chann in self.wanted_channels):
         return False
      self.wanted_channels.add(chann)
      return True
      
   def wc_remove(self, chann):
      """Remove channel name from wanted chan set"""
      chann = IRCCIString(chann)
      if not (chann in self.wanted_channels):
         return False
      self.wanted_channels.remove(chann)
      return True
   
   def fake_part(self, chan):
      self.send_msg(IRCMessage(self.get_user_ia(), b'PART', (chan,)))
   
   def fake_join(self, chan):
      self.send_msg(IRCMessage(self.get_user_ia(), b'JOIN', (chan,)))
   
   def _process_msg_JOIN(self, msg):
      """Process JOIN."""
      chnns = msg.parse_JOIN()
      if (chnns == 0):
         for chan in self.wanted_channels:
            self.fake_part(chan)
         self.wanted_channels.clear()
         return
      
      for chnn in chnns:
         self.wc_add(chnn)

   def _process_msg_PART(self, msg):
      """Process PART."""
      chnns = msg.parse_PART()
      for chnn in chnns:
         self.fake_part(chnn)
         self.wc_remove(chnn)

   def _process_msg_KICK(self, msg):
      """Process KICK."""
      kick_data = msg.parse_KICK()
      for (chan, nick) in zip(chnns, nicks):
         if (nick != self.nick):
            continue
         self.fake_part(chnn)
         self.wc_remove(chnn)
   
   def _process_msg_PING(self, msg):
      """Answer PING."""
      self.send_msg(IRCMessage(self.self_name, b'PONG', msg.parameters[:1]))
      
   def _process_msg_NICK(self, msg):
      """Process NICK."""
      if (self.nick):
         return
      
      if (len(msg.parameters) < 1):
         self.send_msg(IRCMessage(self.self_name, b'431',
            (self._get_nick(), b'No nickname given.')))
         return
      
      self.nick = msg.parameters[0]
   
   def _process_msg_USER(self, msg):
      """Process USER."""
      if (self.user):
         self.send_msg(IRCMessage(self.self_name, b'462',
            (self._get_nick(), b"You sent a USER line before.")))
         return
      
      self._pc_check(msg, 4, send_error=True)
      self.user = msg.parameters[0]
      self.mode_str = msg.parameters[1]
      self.realname = msg.parameters[3]
   
   def _process_msg_JOIN(self, msg):
      """Process JOIN."""
      chnns = msg.parse_JOIN()
      if (chnns == 0):
         return
      for chnn in chnns:
         self.wc_add(chnn)
   
   def peer_registered(self):
      return bool(self.nick and self.user)
   
   def get_unhmask(self):
      return b''.join((self.nick, b'!', self.user, b'@',
         self.peer_address[0].encode('ascii')))
      
      
