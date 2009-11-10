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
import socket
from socket import AF_INET
from collections import deque

from .event_multiplexing import OrderingEventMultiplexer
from .s2c_structures import IRCMessage
from .irc_client import IRCClientConnection
from .irc_num_constants import *


def get_irc_nick():
   import random
   return ('C{0:x}'.format(random.getrandbits(32)).encode('ascii'))


class IRCServerSpec:
   def __init__(self, host, port, preference=0, af=AF_INET, src_address=None,
         ssl=False):
      self.host = host
      self.port = port
      self.af = af
      self.saddr = src_address
      self.o = preference
      self.ssl = ssl
   
   def _get_bt(self):
      if (self.saddr is None):
         return None
      return (self.saddr, 0)
   
   def __cmp__(self, other):
      if (self.o > other.o): return 1
      if (self.o < other.o): return -1
      if (id(self) > id(other)): return 1
      if (id(self) < id(other)): return -1
      return 0
   
   def __eq__(self, other):
      return (self is other)
   
   def __ne__(self, other):
      return not (self is other)
   
   def __lt__(self, other):
      return (self.__cmp__(other) < 0)
   def __gt__(self, other):
      return (self.__cmp__(other) > 0)
   def __le__(self, other):
      return (self.__cmp__(other) <= 0)
   def __ge__(self, other):
      return (self.__cmp__(other) >= 0)


class IRCUserSpec:
   def __init__(self, nicks, username, realname, mode=0):
      self.nicks = nicks
      self.username = username
      self.realname = realname
      self.mode = mode
   
   def make_nick_picker(self):
      nick_iter = iter(self.nicks)
      def rv():
         try:
            return nick_iter.__next__()
         except StopIteration:
            return get_irc_nick()
      
      return rv


class StateError(Exception):
   pass


class IRCClientNetworkLink:
   logger = logging.getLogger('IRCClientNetworkLink')
   log = logger.log
   
   ircc_cls = IRCClientConnection
   
   link_timeout = 30
   
   def __init__(self, ed, user_spec, servers, conn_delay_is=10):
      self.ed = ed
      self.us = user_spec
      self.conn = None
      self.conn_els = list()
      
      self.servers = list(servers)
      self.servers.sort()
      self.server_picker = self.make_server_picker()
      
      self.delay_conn_is = conn_delay_is
      self.timer_connect = None
      
      self.em_names = self.ircc_cls.EM_NAMES
      for em_name in self.em_names:
         self.em_new(em_name)
      
      self.em_shutdown.new_prio_listener(self._process_conn_shutdown)
   
   def is_linked(self):
      """Return whether we are linked to the network."""
      if not (self.conn):
         return False
      return self.conn.link_done
   
   def get_self_nick(self):
      """Get currently used nick."""
      if not (self.conn):
         return None
      return self.conn.nick
   
   def get_pcs(self):
      """Get current ISUPPORT data."""
      if not (self.conn):
         return IRCISUPPORTData()
      return self.conn.pcs
   
   def em_new(self, attr):
      """Instantiate new EventMultiplexer attribute"""
      setattr(self, attr, OrderingEventMultiplexer(self))
   
   def make_server_picker(self):
      servers_left = deque(self.servers)
      def rv():
         nonlocal servers_left
         if (not servers_left):
            servers_left = deque(self.servers)
         server = servers_left.popleft()
         return server
      return rv
   
   def _process_link_finish(self, conn):
      """Process link finish on specified connection."""
      if (conn != self.conn):
         self.log(40, 'Unexpected link finish on unknown connection {0!a}.'.format(conn))
         conn.close()
      self.log(20, 'Connection {0!a} finished link.'.format(conn))

   def _process_conn_shutdown(self):
      was_linked = self.conn.link_done
      self.void_active_conn()
      self.shedule_conn_init()
      if (was_linked):
         self.server_picker = self.make_server_picker()
   
   def shedule_conn_init(self):
      if not (self.timer_connect is None):
         return
      
      def cb():
         self.timer_connect = None
         self.conn_init()
      
      self.timer_connect = self.ed.set_timer(self.delay_conn_is, cb)
   
   def conn_init(self):
      if not (self.conn is None):
         raise StateError('Connection attempt in progress already.')
      
      nick_picker = self.us.make_nick_picker()
      nick = nick_picker()
      
      # TODO: Replace this hack job with an async dns lookup call and optional
      # conn binding before connect()
      
      server = self.server_picker()
      target = (server.host, server.port)
      try:
         conn = self.ircc_cls.irc_build_sock_connect(self.ed, target,
            nick=nick, username=self.us.username, realname=self.us.realname,
            mode=self.us.mode, family=server.af, bind_target=server._get_bt())
      except socket.error as exc:
         self.log(30, 'Failed connecting to {0}: {1!a}'.format(target, str(exc)))
         self.shedule_conn_init()
         return
      
      if (server.ssl):
         conn.do_ssl_handshake(lambda: None)
      
      self.log(20, 'Opening connection {0!a} to {1}.'.format(conn, target))
      
      def link_watch(msg):
         if not (msg.get_cmd_numeric() in (ERR_ERRONEUSNICKNAME,
            ERR_NICKNAMEINUSE, ERR_NICKCOLLISION, ERR_UNAVAILRESOURCE)):
            return
         
         # Last nick was rejected, try again.
         nick = nick_picker()
         self.log(20, 'Trying nick {0!a} on connection {1!a}.'.format(nick, conn))
         
         conn.put_msg(IRCMessage(None, b'NICK', (nick,)), None)
         
      def link_watch_finish():
         lwl1.close()
         lwl2.close()
         tt.cancel()
         self._process_link_finish(conn)
         
      lwl1 = conn.em_in_msg.new_prio_listener(link_watch, 512)
      lwl2 = conn.em_link_finish.new_prio_listener(link_watch_finish, 512)
      
      def timeout():
         if not (self.conn is conn):
            self.log(40, 'Bogus timeout call; self.conn is {0!a}, expected {1!a}.'
               .format(self.conn, conn))
            return
         conn.close()
         self.log(30, 'Connection {0!a} timeouted during link.'.format(conn))
      
      tt = self.ed.set_timer(self.link_timeout, timeout, parent=self)
      
      self.conn = conn
      for emn in self.em_names:
         sub_em = getattr(conn, emn)
         sup_em = getattr(self, emn)
         listener = sub_em.new_prio_listener(sup_em, 1024)
         self.conn_els.append(listener)
   
   def void_active_conn(self):
      self.conn = None
      for el in self.conn_els:
         el.close()
      del(self.conn_els[:])
   
   
def _selftest(targethost, tport, username='chimera', realname=b'? ? ?',
      ssl=False):
   import pprint
   from gonium.fdm import ED_get
   from gonium._debugging import streamlogger_setup
   
   logging.getLogger('IRCClientConnection').setLevel(20)
   
   us = IRCUserSpec(nicks=(b'NickServ', b'ChanServ'),
      username=username, realname=realname)
   
   servers = (
      IRCServerSpec('nonexistent.nowhere', 1),
      IRCServerSpec('0.0.0.0', 1),
      IRCServerSpec(targethost, tport, ssl=ssl),
   )
   
   def link():
      print('All done. Shutting down.')
      ed.shutdown()
   
   streamlogger_setup()
   ed = ED_get()()
   
   irccnl = IRCClientNetworkLink(ed, us, servers, conn_delay_is=5)
   irccnl.em_link_finish.new_prio_listener(link)
   
   irccnl.conn_init()
   
   ed.event_loop()


if (__name__ == '__main__'):
   import sys
   if (b'--ssl' in sys.argv):
      ssl = True
      tport = 6697
   else:
      ssl = False
      tport = 6667
   
   _selftest(sys.argv[1], tport, ssl=ssl)


