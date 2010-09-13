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
from .irc_pseudoserver import IRCPseudoServer
from .bnc_simple import SimpleBNC
from .ipsc_association import NetUserAssocHandler
from .irc_ui import LuteusIRCUI


class LuteusConfig:
   from .logging import BLFormatter, LogFormatter, LogFilter, RawLogger, \
      HRLogger
   
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
      
      self.log_formatter_default = self.LogFormatter()
      self.assoc_handler = NetUserAssocHandler(self._sa.ed)
      
      for name in dir(self):
         if (name.startswith('_')):
            continue
         self._config_ns[name] = getattr(self, name)
      
   def new_network(self, netname, user_spec, servers=[],
         raw_log_dir=b'log/irc_raw', hr_log_dir=b'log/irc',
         hr_log_formatter=None, *args, **kwargs):
      
      if (hr_log_formatter is None):
         hr_log_formatter = self.log_formatter_default
      
      rv = IRCClientNetworkLink(self._sa.ed, netname, user_spec, servers)
      
      def add_target(*sargs, **skwargs):
         s = IRCServerSpec(*sargs, **skwargs)
         rv.servers.append(s)

      rv.add_target = add_target
      
      if not (raw_log_dir is None):
         self.RawLogger(basedir=raw_log_dir, nc=rv)
      if not (hr_log_dir is None):
         self.HRLogger(basedir=hr_log_dir, nc=rv, formatter=hr_log_formatter)
      
      self._icncs.append(rv)
      return rv
   
   def new_target_spec(self, *args, **kwargs):
      return IRCServerSpec(*args, **kwargs)
   
   def new_user_spec(self, *args, **kwargs):
      return IRCUserSpec(*args, **kwargs)
   
   def new_pseudo_server(self, *args, **kwargs):
      rv = IRCPseudoServer(self._sa.ed, *args, **kwargs)
      self.assoc_handler.attach_ips(rv)
      return rv
   
   def new_ssl_spec(self, *args, **kwargs):
      return SSLSpec(*args, **kwargs)
   
   def new_bnc(self, *args, attach_ui=True, attach_bl=True, bl_auto_discard=True, filter=None, **kwargs):
      rv = SimpleBNC(*args, **kwargs)
      if (attach_ui):
         iui = LuteusIRCUI(rv)
      if (attach_bl):
         rv.attach_backlogger(filter=filter, auto_discard=bl_auto_discard)
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

