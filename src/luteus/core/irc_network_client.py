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
import time
from socket import AF_INET, AF_INET6
from collections import deque, OrderedDict

from gonium.dns_resolving.base import QTYPE_A, QTYPE_AAAA
from .event_multiplexing import OrderingEventMultiplexer
from .s2c_structures import IRCCIString, IRCMessage, S2CProtocolCapabilitySet
from .irc_client import IRCClientConnection
from .irc_num_constants import *
from .logging import HRLogger

def get_irc_nick():
   import random
   return ('C{0:x}'.format(random.getrandbits(32)).encode('ascii'))


class SSLSpec:
   try:
      import ssl
   except ImportError:
      PROTOCOL_SSLv23 = CERT_NONE = None
   else:
      from ssl import PROTOCOL_SSLv23, CERT_NONE
   
   basepath = ('ssl',)
   subdir_map = dict(
      certfile = ('ul_self_certs',),
      keyfile = ('ul_self_keys',),
      ca_certs = ('ul_server_certs',)
   )
   
   def __init__(self, use_certfile=False, use_keyfile=False,
         ssl_version=PROTOCOL_SSLv23, cert_reqs=CERT_NONE):
      import ssl
      self.em_handshake_finish = OrderingEventMultiplexer(self)
      self.use_certfile = use_certfile
      self.use_keyfile = use_keyfile
      self.use_ca_certs = (cert_reqs != self.CERT_NONE)
      self.cert_reqs = cert_reqs
      self.ssl_version = ssl_version
   
   def get_ssl_fn(self, tname, host, port):
      import os.path
      from hashlib import sha1
      
      fn = sha1('{0}\x00{1}'.format(host, port).encode('ascii')).hexdigest()
      return os.path.join(*(self.basepath + self.subdir_map[tname] + (fn,)))

   def get_ssl_args(self, host, port):
      ssl_args = ()
      ssl_kwargs = dict(
         cert_reqs = self.cert_reqs,
         ssl_version = self.ssl_version
      )
      
      for varname in ('certfile', 'keyfile', 'ca_certs'):
         if (not getattr(self, 'use_{0}'.format(varname))):
            continue
         ssl_kwargs[varname] = self.get_ssl_fn(varname, host, port)
      
      return (ssl_args, ssl_kwargs)


class IRCServerSpec:
   def __init__(self, host, port, preference=0, af=AF_INET, src_address=None,
         ssl=None, password=None):
      self.host = host
      self.port = port
      self.af = af
      self.saddr = src_address
      self.preference = preference
      self.ssl = ssl
      
      if (isinstance(password, str)):
         password = password.encode()
      if not (password is None):
         bytes(password)
      
      self.password = password
   
   def get_ssl_fn(self, tname):
      return self.ssl.get_ssl_fn(tname, self.host, self.port)
   
   def get_ssl_args(self):
      if (self.ssl is None):
         return None
      return self.ssl.get_ssl_args(self.host, self.port)
   
   def get_dns_qtypes(self):
      if (self.af == AF_INET):
         return (QTYPE_A,)
      if (self.af == AF_INET6):
         return (QTYPE_AAAA,)
      # It better not require DNS lookup, then
      return ()
   
   def _get_bt(self):
      if (self.saddr is None):
         return None
      return (self.saddr, 0)
   
   def __cmp__(self, other):
      if (self.preference > other.preference): return 1
      if (self.preference < other.preference): return -1
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
   
   def __repr__(self):
      return '{0}({1})'.format(self.__class__.__name__,
        ', '.join('{0}={1}'.format(*a) for a in self.__dict__.items()))


class IRCNick(IRCCIString):
   def __new__(cls, nick, **kwargs):
      return super().__new__(cls, nick)
   
   def __init__(self, nick, **kwargs):
      super().__init__(nick)
      for (key,val) in kwargs.items():
         setattr(self, key, val)

   def __format__(self, fs):
      if (fs.endswith('S')):
         rv = self.decode('utf-8', 'surrogateescape')
         return rv.__format__(fs[:-1])
         
      return super().__format__(fs)


class IRCUserSpec:
   def __init__(self, username, realname, mode=0):
      self.nicks = OrderedDict()
      self.username = username
      self.realname = realname
      self.mode = mode
   
   def add_nick(self, nick, **kwargs):
      self.nicks[IRCCIString(nick)] = IRCNick(nick, **kwargs)
   
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
   conn_timeout = 64
   
   def __init__(self, sa, netname, user_spec, servers, conn_delay_is=10):
      self.sa = sa
      self.us = user_spec
      self.conn = None
      self.conn_els = list()
      
      self.servers = list(servers)
      self.servers.sort()
      self.server_picker = self.make_server_picker()
      
      self.delay_conn_is = conn_delay_is
      self.timer_connect = None
      self.timer_timeout = None
      
      self.em_names = self.ircc_cls.EM_NAMES
      em_pre_names = ['em_in_msg', 'em_in_msg_bc']
      self.em_pre_names = [n for n in em_pre_names if n in self.em_names]
      
      for em_name in self.em_names:
         self.em_new(em_name)
      
      for em_name in self.em_pre_names:
         self.em_new(em_name + '_pre')
      
      self.netname = netname
      self.em_shutdown.new_prio_listener(self._process_conn_shutdown)
      self.em_in_msg.new_prio_listener(self._em_setsrc, -1048576)
      
      self.ts_last_link = None
      self.ts_last_unlink = None
      self._away_msg_default = None
   
   def set_away_msg_default(self, reason):
      if not (reason is None):
         bytes(reason)
      if (reason == b''):
         raise ValueError('Away messages have a minimum length of one byte.')
      self._away_msg_default = reason
   
   def _em_setsrc(self, msg):
      msg.src = self
   
   def is_linked(self):
      """Return whether we are linked to the network."""
      if (not self.conn):
         return False
      return self.conn.link_done
   
   def get_self_nick(self):
      """Get currently used nick."""
      if (not self.conn):
         return None
      
      nick = self.conn.nick
      return self.us.nicks.get(nick, nick)
   
   def get_self_away(self):
      """Return whether we are marked as being away."""
      if (not self.conn):
         return False
      return self.conn.away
   
   def get_pcs(self):
      """Get current ISUPPORT data."""
      if (not self.conn):
         return S2CProtocolCapabilitySet()
      return self.conn.pcs
   
   def get_peer(self):
      """Get name of current peer."""
      if (not self.conn):
         return None
      return self.conn.peer
   
   def get_peer_address(self, stale=False):
      """Return address we've connected to."""
      if (not self.conn):
         if ((self.conn is None) or (not stale)):
            return None
      
      return self.conn.peer_address
   
   def get_channels(self, stale=False):
      """Return active channels."""
      if (not self.conn):
         if ((self.conn is None) or (not stale)):
            return None
      return self.conn.channels
   
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
         return
      self.log(20, 'Connection {0!a} finished link.'.format(conn))
      self.ts_last_link = time.time()
      if (self.conn is None):
         return
      
      if not (self._away_msg_default is None):
         msg = IRCMessage(None, b'AWAY', (self._away_msg_default,), src=self, pcs=self.conn.pcs)
         self.conn.send_msg(msg)

   def _process_conn_shutdown(self):
      was_linked = self.conn.link_done
      self.void_active_conn()
      self.shedule_conn_init()
      if not (self.timer_timeout is None):
         self.timer_timeout.cancel()
         self.timer_timeout = None
      if (was_linked):
         self.server_picker = self.make_server_picker()
         self.ts_last_unlink = time.time()
   
   def send_quit(self, reason):
      """Send QUIT message to network."""
      if (self.conn is None):
         return
      
      msg = IRCMessage(None, b'QUIT', (reason,), src=self, pcs=self.conn.pcs)
      self.conn.send_msg(msg)
   
   def shedule_conn_init(self):
      if not (self.timer_connect is None):
         return
      
      def cb():
         self.timer_connect = None
         self.conn_init()
      
      self.timer_connect = self.sa.ed.set_timer(self.delay_conn_is, cb)
   
   def conn_init(self):
      if (len(self.servers) < 1):
         raise Exception('Need at least one server to connect to.')
      
      if not (self.conn is None):
         raise StateError('Connection attempt in progress already.')
      
      if (self.timer_connect):
         self.timer_connect.cancel()
         self.timer_connect = None
      
      nick_picker = self.us.make_nick_picker()
      nick = nick_picker()
      
      server = self.server_picker()

      try:
         conn = self.ircc_cls.irc_build_sock_connect(self.sa, server.host, server.port,
            qtypes=server.get_dns_qtypes(), nick=nick, username=self.us.username,
            realname=self.us.realname, mode=self.us.mode, family=server.af,
            bind_target=server._get_bt(), timeout=self.conn_timeout, server_password=server.password)
      except socket.error as exc:
         self.log(30, 'Failed connecting to {}: {!a}'.format(server, str(exc)))
         self.shedule_conn_init()
         return
      
      ssl_data = server.get_ssl_args()
      if not (ssl_data is None):
         def cb():
            server.ssl.em_handshake_finish(conn)
         conn.do_ssl_handshake(cb, *ssl_data[0], **ssl_data[1])
      
      self.log(20, 'Opening connection {!a} to {!a}:{}.'.format(conn, server.host, server.port))
      
      def link_watch(msg):
         if not (msg.get_cmd_numeric() in (ERR_ERRONEUSNICKNAME,
            ERR_NICKNAMEINUSE, ERR_NICKCOLLISION, ERR_UNAVAILRESOURCE)):
            return
         
         # Last nick was rejected, try again.
         nick = nick_picker()
         self.log(20, 'Trying nick {!a} on connection {!a}.'.format(nick, conn))
         
         conn.put_msg(IRCMessage(None, b'NICK', (nick,)), None)
         
      def link_watch_finish():
         lwl1.close()
         lwl2.close()
         self.timer_timeout.cancel()
         self.timer_timeout = None
         self._process_link_finish(conn)
         
      lwl1 = conn.em_in_msg.new_prio_listener(link_watch, 512)
      lwl2 = conn.em_link_finish.new_prio_listener(link_watch_finish, 512)
      
      def timeout():
         if not (self.conn is conn):
            self.log(40, 'Bogus timeout call; self.conn is {!a}, expected {!a}.'.format(self.conn, conn))
            return
         conn.close()
         self.log(30, 'Connection {!a} timeouted during link.'.format(conn))
      
      self.timer_timeout = self.sa.ed.set_timer(self.link_timeout, timeout, parent=self)
      
      self.conn = conn
      for emn in self.em_names:
         sup_em = getattr(conn, emn)
         sub_em = getattr(self, emn)
         listener = sup_em.new_prio_listener(sub_em, 1024)
         self.conn_els.append(listener)
      
      for emn in self.em_pre_names:
         emn_p = emn + '_pre'
         sup_em = getattr(conn, emn)
         sub_em = getattr(self, emn_p)
         listener = sup_em.new_prio_listener(sub_em, -512)
         self.conn_els.append(listener)
      
      del(listener)
   
   def void_active_conn(self):
      self.conn = None
      for el in self.conn_els:
         el.close()
      del(self.conn_els[:])


def _selftest(targethost, tport, username='chimera', realname=b'? ? ?',
      ssl=None):
   import pprint
   from gonium.service_aggregation import ServiceAggregate
   from gonium._debugging import streamlogger_setup
   
   logging.getLogger('IRCClientConnection').setLevel(20)
   
   us = IRCUserSpec(username=username, realname=realname)
   us.add_nick(b'NickServ')
   us.add_nick(b'ChanServ')
   
   servers = (
      IRCServerSpec('nonexistent.nowhere', 1),
      IRCServerSpec('0.0.0.0', 1),
      IRCServerSpec(targethost, tport, ssl=ssl),
   )
   
   def link():
      print('All done. Shutting down.')
      sa.ed.shutdown()
   
   streamlogger_setup()
   sa = ServiceAggregate()
   sa.add_dnslm()
   
   irccnl = IRCClientNetworkLink(sa, None, us, servers, conn_delay_is=5)
   irccnl.em_link_finish.new_prio_listener(link)
   
   irccnl.conn_init()
   
   sa.ed.event_loop()


if (__name__ == '__main__'):
   import sys
   if ('--ssl' in sys.argv):
      ssl = SSLSpec()
      tport = 6697
   else:
      ssl = None
      tport = 6667
   
   _selftest(sys.argv[1], tport, ssl=ssl)


