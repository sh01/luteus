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


def main():
   import sys
   
   from gonium.fdm import ED_get
   from gonium._debugging import streamlogger_setup
   
   from .irc_network_client import IRCClientNetworkLink, IRCUserSpec, IRCServerSpec
   from .irc_pseudoserver import IRCPseudoServer, DefaultAssocHandler
   from .bnc_simple import SimpleBNC
   from .irc_ui import LuteusIRCUI
   
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
   iui = LuteusIRCUI()
   iui.attach_bnc(bnc)
   
   ed.event_loop()

if (__name__ == '__main__'):
   main()
