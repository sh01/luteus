#!/usr/bin/env python
#Copyright 2013,2014 Sebastian Hagen
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
import re

from ..core.s2c_structures import IRCMessage


class SimpleBot:
   logger = logging.getLogger('SimpleBot')
   log = logger.log
   
   def __init__(self, network_conn):
      self.nc = network_conn
   
   def send_text(self, targets, text):
     # Think about hard line wrapping here.
     c = self.nc.conn
     if not (c):
       return
     for target in targets:
       msg = IRCMessage(None, b'PRIVMSG', [target, text], src=self, pcs=self.nc.conn.pcs)
       self.put_msg_network(msg)
   
   def put_msg_network(self, msg, cb=lambda *a, **k: None, *args, **kwargs):
      """Send message to network, iff we are currently connected. Else,
         it's silently discarded."""
      c = self.nc.conn
      if not (c):
         return
      c.put_msg(msg, cb, *args, **kwargs)


class TriggerContext:
  def __init__(self, b, envs):
    self.b = b
    # Channels and nicks that this trigger line was sent to that caused it to be received by us. This includes both shared channels and our current nick (but not virtual nicks).
    self.envs = envs

  def output(self, text, width=None):
    # Think about having an option for soft line wrapping here or in a helper method as for irc_ui.
    if (isinstance(text, str)):
      text = text.encode('utf-8','surrogateescape')
    self.b.send_text(self.envs, text)


class TriggeredBot(SimpleBot):
  rep_nick = '^([@]?(?:{})[:]?)'

  def __init__(self, network_conn, virtual_nicks=(), triggers=['!']):
    super().__init__(network_conn)
    self.virtual_nicks = virtual_nicks
    self.nc.em_in_msg_bc.new_prio_listener(self._process_in_msg, 0)
    
    # Test that this works now.
    re.compile(self.rep_nick.format('|'.join(virtual_nicks)).encode('ascii'))
    self.re_trigger = re.compile('^({})'.format('|'.join(triggers)).encode('ascii'))

  def _process_in_msg(self, msg):
    nick = self.nc.get_self_nick()

    if (nick is None):
      # Not connected. Racy business, drop it.
      return
    if (msg.command != b'PRIVMSG'):
      return
    if (len(msg.parameters) != 2):
      return

    def eat_match():
      nonlocal text
      if (m is None):
        return False
      # Trim parsed prefix and any following whitespace from message
      (g,) = m.groups()
      text = text[len(g):].lstrip()
      return True

    text = msg.parameters[1]

    nicks = list(self.virtual_nicks)
    nicks.append(nick.decode('ascii'))

    r = re.compile(self.rep_nick.format('|'.join(nicks)).encode('ascii'))
    m = r.match(text)
    have_nick_prefix = eat_match()

    m = self.re_trigger.match(text)
    have_cmd_prefix = eat_match()

    aimed_at_nick = nick in msg.get_nick_targets()

    if not (aimed_at_nick or have_nick_prefix or have_cmd_prefix):
      # Channel message which doesn't look interesting to us. Bail out.
      return

    argv = text.split()
    if (len(argv) < 1):
      # No command.
      return

    target_envs = []
    chans = self.nc.get_channels()
    for target in msg.get_chan_targets():
      if (target in chans):
        target_envs.append(target)

    if (aimed_at_nick):
      target_envs.append(nick)

    # This looks like a command addressed to us. Prefix cruft has been stripped, let's go parse.
    ctx = TriggerContext(self, target_envs)
  
    ignore_unknown_cmd = not (aimed_at_nick or have_nick_prefix)
    argv = [x.decode('utf-8', 'surrogateescape') for x in argv]
    self.process_cmd(argv[0].upper(), argv, ctx, ignore_unknown_cmd)

  def process_cmd(self, *args, **kwargs):
    pass
