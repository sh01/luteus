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
from collections import deque

from .s2c_structures import IRCMessage
from .irc_client import IRCClientConnection
from .irc_num_constants import *


def get_irc_nick():
   import random
   return ('C{0:x}'.format(random.getrandbits(32)).encode('ascii'))


class IRCServerSpec:
   def __init__(self, host, port, preference=0):
      self.host = host
      self.port = port
      self.o = preference
   
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
   
   link_timeout = 30
   
   def __init__(self, ed, user_spec, servers, conn_delay_is=10):
      self.ed = ed
      self.us = user_spec
      self.conn = None
      
      self.servers = list(servers)
      self.servers.sort()
      self.server_picker = self.make_server_picker()
      
      self.delay_conn_is = conn_delay_is
      self.timer_connect = None
   
   def make_server_picker(self):
      servers_left = deque(self.servers)
      def rv():
         nonlocal servers_left
         if (not servers_left):
            servers_left = deque(self.servers)
         server = servers_left.popleft()
         return server
      return rv
   
   def link_finish_process(self, conn):
      """Process link finish on specified connection."""
      if (conn != self.conn):
         self.log(40, 'Unexpected link finish on unknown connection {0!a}.'.format(conn))
         conn.close()
      self.log(20, 'Connection {0!a} finished link.'.format(conn))
      
   
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
         conn = IRCClientConnection.irc_build_sock_connect(self.ed, target,
            nick=nick, username=self.us.username, realname=self.us.realname,
            mode=self.us.mode)
      except socket.error as exc:
         self.log(30, 'Failed connecting to {0}: {1!a}'.format(target, str(exc)))
         self.shedule_conn_init()
         return
      
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
         self.link_finish_process(conn)
         
      lwl1 = conn.em_in_msg.new_listener(link_watch)
      lwl2 = conn.em_link_finish.new_listener(link_watch_finish)
      
      def timeout():
         if not (self.conn is conn):
            self.log(40, 'Bogus timeout call; self.conn is {0!a}, expected {1!a}.'
               .format(self.conn, conn))
            return
         conn.close()
         self.log(30, 'Connection {0!a} timeouted during link.'.format(conn))
         self.conn = None
         self.conn_init()
      
      tt = self.ed.set_timer(self.link_timeout, timeout, parent=self)
      
      self.conn = conn
   
   
def _selftest(targethost, username='chimera', realname=b'? ? ?'):
   import pprint
   from gonium.fdm import ED_get
   from gonium._debugging import streamlogger_setup
   
   logging.getLogger('IRCClientConnection').setLevel(20)
   
   us = IRCUserSpec(nicks=(b'NickServ', b'ChanServ'),
      username=username, realname=realname)
   
   servers = (
      IRCServerSpec('nonexistent.nowhere', 1),
      IRCServerSpec('0.0.0.0', 1),
      IRCServerSpec(targethost, 6667)
   )
   
   def link():
      print('All done. Shutting down.')
      ed.shutdown()
   
   streamlogger_setup()
   ed = ED_get()()
   
   irccnl = IRCClientNetworkLink(ed, us, servers, conn_delay_is=5)
   irccnl.conn_init()
   
   ed.event_loop()


if (__name__ == '__main__'):
   import sys
   _selftest(sys.argv[1])


