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

from gonium.service_aggregation import ServiceAggregate

from .irc_network_client import IRCClientNetworkLink, IRCUserSpec, IRCServerSpec, SSLSpec
from .irc_pseudoserver import IRCPseudoServer, DefaultAssocHandler
from .bnc_simple import SimpleBNC
from .irc_ui import LuteusIRCUI


class LuteusConfig:
   try:
      from ssl import CERT_OPTIONAL, CERT_REQUIRED, CERT_NONE
   except ImportError:
      pass
   
   def __init__(self, sa=None):
      if (sa is None):
         sa = ServiceAggregate()
      self._sa = sa
      self._icncs = []
      self._config_ns = {}
      for name in dir(self):
         if (name.startswith('_')):
            continue
         self._config_ns[name] = getattr(self, name)
      
   def new_network(self, netname, user_spec, servers=[], *args, **kwargs):
      rv = IRCClientNetworkLink(self._sa.ed, netname, user_spec, servers)
      def add_target(*sargs, **skwargs):
         s = IRCServerSpec(*sargs, **skwargs)
         rv.servers.append(s)

      rv.add_target = add_target
      self._icncs.append(rv)
      return rv
   
   def new_target_spec(self, *args, **kwargs):
      return IRCServerSpec(*args, **kwargs)
   
   def new_user_spec(self, *args, **kwargs):
      return IRCUserSpec(*args, **kwargs)
   
   def new_pseudo_server(self, *args, **kwargs):
      return IRCPseudoServer(self._sa.ed, *args, **kwargs)
   
   def new_ssl_spec(self, *args, **kwargs):
      return SSLSpec(*args, **kwargs)
   
   def new_bnc(self, *args, attach_ui=True, **kwargs):
      rv = SimpleBNC(*args, **kwargs)
      if (attach_ui):
         iui = LuteusIRCUI()
         iui.attach_bnc(rv)
      return rv
   
   def attach_ps2bnc_default(self, ps, bnc):
      rv = DefaultAssocHandler(self._sa.ed, bnc)
      rv.attach_ips(ps)
      return rv

   def load_config_by_fn(self, fn):
      file = open(fn)
      file_data = file.read()
      file.close()
      exec(file_data, self._config_ns)

   def _start_connections(self):
      for conn in self._icncs:
         conn.conn_init()
   
   def _get_servers(self):
      rv = []
      for conn in self._icncs:
         for server in conn.servers:
            rv.append(server)
      return rv
   
   def _event_loop(self):
      self._sa.ed.event_loop()

