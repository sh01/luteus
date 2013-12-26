##!/usr/bin/env python
#Copyright 2009,2010 Sebastian Hagen
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

import os.path
import logging

from .event_multiplexing import OrderingEventMultiplexer
from .s2c_structures import *
from .irc_num_constants import *
from .logging import BackLogger, AutoDiscardingBackLogger, BLFormatter, NickLogLine


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
   
   BL_BASEDIR_DEFAULT = os.path.join(b'data', b'backlog')
   #EM calling conventions:
   # Input from connected IRC clients.
   #    em_client_in_msg(msg: IRCMessage)
   #
   # Messages forwarded to connected IRC clients, and the ipscs thet have been forwarded to.
   #    em_client_msg_fwd(ipscs, msg: IRCMessage, outgoing: bool)
   #
   # Dumps of backlog data for specific contexts to a set of ipscs.
   #    em_client_bl_dump(ipscs, bl_contexts: list)

   def __init__(self, network_conn, blf=None, mmlf=None):
      self.nc = network_conn
      self.nick = network_conn.get_self_nick()
      self.pcs = network_conn.get_pcs()
      self.ips_conns = set()
      self.motd = None
      self.bl = None
      if (blf is None):
         blf = BLFormatter()
      if (mmlf is None):
         mmlf = blf.copy()
         mmlf.time_fmt = ''
      
      self.blf = blf
      self.mmlf = mmlf
      
      self.em_client_in_msg = OrderingEventMultiplexer(self)
      self.em_client_msg_fwd = OrderingEventMultiplexer(self)
      self.em_client_bl_dump = OrderingEventMultiplexer(self)
      
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
   
   def _process_potential_nickchange(self, update_peer=True):
      newnick = self.nc.get_self_nick()
      if (newnick is None):
         return
      if (self.nick == newnick):
         return
      self.nick = newnick
      for ipsc in self.ips_conns:
         ipsc.change_nick(self.nick, update_peer=update_peer)
   
   @_reg_em('em_shutdown', -1024)
   def _process_network_conn_shutdown(self):
      self.pcs = self._get_pcs()
      ex_chans = self.nc.conn.channels
      for ipsc in self.ips_conns:
         if (self.nc.conn.away):
            ipsc.send_msg_305()
         
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
         for chan in ipsc.wanted_channels:
            self.nc.conn.add_autojoin_channel(chan)
   
   def _get_pcs(self):
      return (self.nc.get_pcs() or self.pcs)
   
   @_reg_em('em_in_msg_bc')
   def _process_network_bc_msg(self, msg_orig):
      if (msg_orig.command in (b'PING', b'PONG')):
         return
      
      if (msg_orig.self_nickchange):
         self._process_potential_nickchange(False)
      
      def chan_filter(chann):
         return (chann in ipsc.wanted_channels)
      
      for msg in msg_orig.split_by_target():
         if (msg.command == b'ERROR'):
            if (len(msg.parameters) > 0):
               errstr = b' ' + msg.parameters[0]
            else:
               errstr = b''
            
            nick = self.nc.get_self_nick()
            if (nick is None):
              nick = b'*'
            msg2 = IRCMessage(None, b'PRIVMSG',
                  (nick, b'ERROR:' + errstr), src=self,
                  pcs=self.nc.conn.pcs)
            msg2.trim_last_arg()
         elif (msg.prefix is None):
            msg2 = msg.copy()
            msg2.prefix = self.nc.conn.peer
         else:
            msg2 = msg

         ipscs_out = []
         for ipsc in self.ips_conns:
            if (not msg.get_chan_targets()):
               msg_out = msg2
            else:
               msg_out = msg2.copy()
               target_num = msg_out.filter_chan_targets(chan_filter)
               if (target_num < 1):
                  continue
         
            ipsc.send_msg(msg_out)
            ipscs_out.append(ipsc)
         
         self.em_client_msg_fwd(ipscs_out, msg, False)
   
   @_reg_em('em_out_msg')
   def _process_network_out_msg(self, msg_orig):
      if not (msg_orig.command in self.mirror_cmds):
         return
      
      def chan_filter(chann):
         return (chann in ipsc.wanted_channels)
      
      for msg in msg_orig.split_by_target():
         msg2 = msg.copy()
         msg2.src = self
            
         aware_clients = []
         for ipsc in self.ips_conns:
            msg_out = msg2.copy()
            msg_out.prefix = ipsc.get_user_ia()
            
            if (msg.get_chan_targets()):
               target_num = msg_out.filter_chan_targets(chan_filter)
               if (target_num < 1):
                  continue
            
            aware_clients.append(ipsc)
            if (msg.src is ipsc):
               continue
            
            # TODO:
            # This is somewhat ugly; BLFs should probably be renamed now that we also use them for message mirror formatting.
            (nicks, chans) = msg_out.get_targets()
            if (nicks):
               for tnick in nicks:
                  nick_mll = NickLogLine(msg, self.nc.get_self_nick(), True)
                  nmsgs_out = self.mmlf.format_entry(tnick, ipsc.self_name, nick_mll)
                  for nmsg in nmsgs_out:
                     ipsc.send_msg(nmsg)
            
            # TODO:
            # ...and not doing it for chans is a hack, too. Among other things this means we'll still get CTCP reflection in
            # that case ... it's probably not a huge deal in practice, since channel CTCPs are rather rare.
            # Forcing backlog-like mirror formatting for channels would be unnecessarily ugly. If we're to do this, BLFs should
            # get some more config options for nice ts-less formatting first.
            if (chans):
               ipsc.send_msg(msg_out)
   
         self.em_client_msg_fwd(aware_clients, msg, True)
   
   def _fake_join(self, conn, chnn):
      chan = self.nc.conn.channels[chnn]
      conn.fake_join(chnn)
      
      for msg in chan.make_join_msgs(conn.nick, prefix=conn.self_name):
         conn.send_msg(msg)
   
      if not (self.bl is None):
        msgs = self.blf.format_backlog(self.bl, conn.self_name, chnn)
        for msg in msgs:
          conn.send_msg(msg)
        self.em_client_bl_dump((conn,), (chnn,))
   
   def _process_client_msg(self, conn, msg):
      msg.eaten = False
      self.em_client_in_msg(conn, msg)
      if (msg.eaten):
         return
      
      if (msg.command in (b'PING',b'QUIT')):
         return
      
      if (msg.command == b'AWAY'):
         if (msg.parameters):
            away_msg = msg.parameters[0]
            if (away_msg == b''):
               away_msg = None
         else:
            away_msg = None
         self.nc.set_away_msg_default(away_msg)
      
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
               if (chnn in conn.wanted_channels):
                  continue
               self._fake_join(conn, chnn)
            if (no_new):
               return
      
      def cb(*args, **kwargs):
         self._process_query_response(conn, *args, **kwargs)
      
      self.nc.conn.put_msg(msg, cb)
   
   def attach_backlogger(self, basedir=BL_BASEDIR_DEFAULT, filter=None, auto_discard=True):
      if not (self.bl is None):
         raise Exception('Backlogger attached already.')
      if (auto_discard):
         bl_cls = AutoDiscardingBackLogger
      else:
         bl_cls = BackLogger
      self.bl = bl_cls(basedir, self, filter=filter)
   
   def take_ips_connection(self, conn):
      if (not conn):
         return
      
      def process_shutdown():
         self._process_ipsc_shutdown(conn)
      
      def process_msg(msg):
         self._process_client_msg(conn, msg)
      
      conn.em_shutdown.new_prio_listener(process_shutdown)
      conn.em_in_msg.new_prio_listener(process_msg, priority=-1024)
      self.ips_conns.add(conn)
      
      conn.send_msg_001()
      conn.send_msg_002()
      conn.send_msg_003()
      conn.send_msg_004()
      conn.send_msgs_005(self.pcs)
      conn.send_msgs_motd()
      
      if not (self.nick is None):
         conn.change_nick(self.nick)
      
      if (self.nc.get_self_away()):
         conn.send_msg_306()
      
      if (self.bl):
         msgs = self.blf.format_backlog(self.bl, conn.self_name, None)
         for msg in msgs:
            conn.send_msg(msg)
         self.em_client_bl_dump((conn,), (None,))
   
