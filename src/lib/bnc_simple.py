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

from .s2c_structures import *
from .irc_num_constants import *

class SimpleBNC:
   logger = logging.getLogger('SimpleBNC')
   log = logger.log
   
   # *Outgoing* commands to mirror to other client connections
   mirror_cmds = set((b'PRIVMSG', b'NOTICE'))
   mirror_postfix = b'!user@cruentus.bnc'
   
   def __init__(self, network_conn):
      self.nc = network_conn
      self.nick = network_conn.get_self_nick()
      
      network_conn.em_in_msg.new_prio_listener(self._process_network_msg)
      network_conn.em_link_finish.new_prio_listener(self._process_network_link)
      network_conn.em_in_msg_bc.new_prio_listener(self._process_network_bc_msg)
      network_conn.em_out_msg.new_prio_listener(self._process_network_out_msg)
      
      self.ips_conns = set()
      self.motd = None
   
   def _process_query_response(self, conn, query):
      if not (conn):
         return
      
      for rmsg in query.rv:
         conn.send_msg(rmsg)
   
   def _process_ipsc_shutdown(self, conn):
      if not (conn in self.ips_conns):
         self.log(40, 'Got bogus shutdown notification for conn {0}.'.format(conn))
      
      self.ips_conns.remove(conn)
   
   def _process_potential_nickchange(self):
      newnick = self.nc.get_self_nick()
      if (newnick is None):
         return
      if (self.nick == newnick):
         return
      self.nick = newnick
      for ipsc in self.ips_conns:
         ipsc.change_nick(self.nick)

   def _process_network_link(self):
      self._process_potential_nickchange()
   
   def _process_network_bc_msg(self, msg):
      for ipsc in self.ips_conns:
         ipsc.send_msg(msg)
   
   def _process_network_out_msg(self, msg):
      if not (msg.command in self.mirror_cmds):
         return
      msg2 = msg.copy()
      msg2.prefix = (self.nick + self.mirror_postfix)
      
      for ipsc in self.ips_conns:
         if (msg2.src is ipsc):
            continue
         ipsc.send_msg(msg2)
   
   def _process_network_msg(self, msg):
      if (msg.command in (b'NICK',)):
         self._process_potential_nickchange()
         return
   
   def _process_client_msg(self, conn, msg):
      if (msg.command in (b'PING',b'QUIT')):
         return
      
      if not (self.nc.conn):
         conn.send_msg_num(RPL_TRYAGAIN, msg.command,
            b"Bouncer disconnected; please wait for reconnect.")
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
      
      if not (self.nick is None):
         conn.change_nick(self.nick)


def main():
   import sys
   
   from gonium.fdm import ED_get
   from gonium._debugging import streamlogger_setup
   
   from .irc_network_client import IRCClientNetworkLink, IRCUserSpec, IRCServerSpec
   from .irc_pseudoserver import IRCPseudoServer, DefaultAssocHandler
   
   nick = sys.argv[1]
   target_addr = sys.argv[2]
   
   us = IRCUserSpec(
      nicks=(nick.encode('ascii'),),
      username=b'chimera',
      realname=b'Luteus test connection'
   )
   
   ss1 = IRCServerSpec(target_addr, 6667)
   
   streamlogger_setup()
   ed = ED_get()()
   
   nc = IRCClientNetworkLink(ed, us, (ss1,))
   nc.conn_init()
   ips = IRCPseudoServer(ed, (b'127.0.0.1', 6667))
   bnc = SimpleBNC(nc)
   ah = DefaultAssocHandler(ed, bnc)
   ah.attach_ips(ips)
   
   ed.event_loop()

if (__name__ == '__main__'):
   main()
