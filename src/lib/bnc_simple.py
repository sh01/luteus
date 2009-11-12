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

from .event_multiplexing import OrderingEventMultiplexer
from .s2c_structures import *
from .irc_num_constants import *


def _reg_em(em_name, priority=0):
   """Function decorator to specify self.nc-em to reg on instance init"""
   def dc(func):
      func.em_name = em_name
      func.em_priority = priority
      return func
   return dc


class SimpleBNC:
   logger = logging.getLogger('SimpleBNC')
   log = logger.log
   
   # *Outgoing* commands to mirror to other client connections
   mirror_cmds = set((b'PRIVMSG', b'NOTICE'))
   mirror_postfix = b'!user@cruentus.bnc'
   
   def __init__(self, network_conn):
      self.nc = network_conn
      self.nick = network_conn.get_self_nick()
      self.pcs = network_conn.get_pcs()
      self.ips_conns = set()
      self.motd = None
      
      self.em_client_in_msg = OrderingEventMultiplexer(self)
      
      for name in dir(self):
         attr = getattr(self, name)
         if not (hasattr(attr, 'em_name')):
            continue
         getattr(self.nc, attr.em_name).new_prio_listener(attr, attr.em_priority)
   
   def put_msg_network(self, msg, cb=lambda *a, **k: None, *args, **kwargs):
      """Send message to network, iff we are currently connected. Else,
         it's silently discarded."""
      c = self.nc.conn
      if not (c):
         return
      c.put_msg(msg, cb, *args, **kwargs)
   
   def _process_query_response(self, conn, query):
      if not (conn):
         return
      
      for rmsg in query.rv:
         conn.send_msg(rmsg)
   
   def _process_ipsc_shutdown(self, conn):
      if not (conn in self.ips_conns):
         self.log(40, 'Got bogus shutdown notification for conn {0}.'.format(conn))
      
      self.ips_conns.remove(conn)
      conn.mgr = None
   
   def _process_potential_nickchange(self):
      newnick = self.nc.get_self_nick()
      if (newnick is None):
         return
      if (self.nick == newnick):
         return
      self.nick = newnick
      for ipsc in self.ips_conns:
         ipsc.change_nick(self.nick)
   
   @_reg_em('em_shutdown', -1024)
   def _process_network_conn_shutdown(self):
      self.pcs = self._get_pcs()
      ex_chans = self.nc.conn.channels
      for ipsc in self.ips_conns:
         for chan in ipsc.wanted_channels:
            if not (chan in ex_chans):
               continue
            ipsc.send_msg(IRCMessage(ipsc.self_name, b'KICK',
               (chan, ipsc.nick, b'Luteus<->network link severed.'), src=self))
   
   @_reg_em('em_link_finish')
   def _process_network_link(self):
      self._process_potential_nickchange()
      self.pcs = self.nc.get_pcs()
      
      # Rejoin wanted chans
      chans_wanted = set()
      for ipsc in self.ips_conns:
         chans_wanted.update(ipsc.wanted_channels)
      
      msgs = list(IRCMessage.build_ml_onearg(b'JOIN', (), (),
         list(chans_wanted), b','))
      for msg in msgs:
         self.put_msg_network(msg)
   
   def _get_pcs(self):
      return (self.nc.get_pcs() or self.pcs)
   
   @_reg_em('em_in_msg_bc')
   def _process_network_bc_msg(self, msg):
      if (msg.command == b'PONG'):
         return
      def chan_filter(chann):
         return (chann in ipsc.wanted_channels)

      for ipsc in self.ips_conns:
         if (not msg.get_chan_targets()):
            msg_out = msg
         else:
            msg_out = msg.copy()
            target_num = msg_out.filter_chan_targets(chan_filter)
            if (target_num < 1):
               continue
         
         ipsc.send_msg(msg_out)
   
   @_reg_em('em_out_msg')
   def _process_network_out_msg(self, msg):
      if not (msg.command in self.mirror_cmds):
         return
      msg2 = msg.copy()
      msg2.prefix = (self.nick + self.mirror_postfix)
      msg2.src = self
      
      def chan_filter(chann):
         return (chann in ipsc.wanted_channels)
      
      for ipsc in self.ips_conns:
         if (msg.src is ipsc):
            continue
         
         if (not msg.get_chan_targets()):
            msg_out = msg2
         else:
            msg_out = msg2.copy()
            target_num = msg_out.filter_chan_targets(chan_filter)
            if (target_num < 1):
               continue
         
         ipsc.send_msg(msg_out)
   
   @_reg_em('em_in_msg')
   def _process_network_msg(self, msg):
      if (msg.command in (b'NICK',)):
         self._process_potential_nickchange()
         return
   
   def _fake_join(self, conn, chnn):
      chan = self.nc.conn.channels[chnn]
      conn.send_msg(IRCMessage(conn.nick + self.mirror_postfix, b'JOIN',
         (chnn,)))
      
      for msg in chan.make_join_msgs(conn.nick, prefix=conn.self_name):
         conn.send_msg(msg)
   
   def _process_client_msg(self, conn, msg):
      msg.eaten = False
      self.em_client_in_msg(conn, msg)
      if (msg.eaten):
         return
      
      if (msg.command in (b'PING',b'QUIT')):
         return
      
      if not (self.nc.conn):
         conn.send_msg_num(RPL_TRYAGAIN, msg.command,
            b"Bouncer disconnected; please wait for reconnect.")
         return
      
      if (msg.command == b'JOIN'):
         jd = msg.parse_JOIN()
         if (jd != 0):
            no_new = True
            for chnn in msg.parse_JOIN():
               if not (chnn in self.nc.conn.channels):
                  no_new = False
                  continue
               self._fake_join(conn, chnn)
            
            if (no_new):
               return
      
      def cb(*args, **kwargs):
         self._process_query_response(conn, *args, **kwargs)
      
      self.nc.conn.put_msg(msg, cb)
   
   def take_ips_connection(self, conn):
      if (not conn):
         return
      
      def process_shutdown():
         self._process_ipsc_shutdown(conn)
      
      def process_msg(msg):
         self._process_client_msg(conn, msg)
      
      conn.em_shutdown.new_prio_listener(process_shutdown)
      conn.em_in_msg.new_prio_listener(process_msg)
      self.ips_conns.add(conn)
      
      conn.send_msg_001()
      conn.send_msg_002()
      conn.send_msg_003()
      conn.send_msgs_005(self.pcs)
      
      if not (self.nick is None):
         conn.change_nick(self.nick)
   
