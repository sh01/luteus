#!/usr/bin/env python
#Copyright 2013,2014,2016 Sebastian Hagen
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
from ..core.irc_ui import LuteusUIBase

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
  def __init__(self, b, envs, msg, cmd_text):
    self.b = b
    # Channels and nicks that this trigger line was sent to that caused it to be received by us. This includes both shared channels and our current nick (but not virtual nicks).
    self.envs = envs
    self.msg = msg
    self.cmd_text = cmd_text

  def get_cmd_tail(self, skip):
     """Return trailing fraction of initial commandline invocation, skipping <skip> words from front."""
     if len(self.cmd_text.split()) <= skip:
       return None
     (*_, tail) = self.cmd_text.split(None, skip)
     return tail

  def is_nick_targeted(self):
     if len(self.envs) != 1:
       # Iffy. In principle it could be part-targeted that way.
       return False
     return self.envs[0].is_nick
  
  def output(self, text, width=None, extra_targets=()):
    # Think about having an option for soft line wrapping here or in a helper method as for irc_ui.
    if (isinstance(text, str)):
      text = text.encode('utf-8','surrogateescape')
    
    # Send reply to targeted channels, but don't reflect it back to our nick.
    targets = [env.name for env in self.envs if not env.is_nick]
    if (targets == []):
      p = self.msg.prefix
      if (not (p is None)) and (p.is_nick):
        targets.append(p.target_get())
    targets.extend(extra_targets)
    self.b.send_text(targets, text)

  def get_src(self):
    try:
      return self.msg.prefix.target_get()
    except AttributeError:
      return None


class TriggerUI(LuteusUIBase):
   def __init__(self):
     self.ui_callables = []

   def _get_ui_callables(self):
     return self.ui_callables


class Target:
   def __init__(self, name, is_nick):
      self.name = name
      self.is_nick = is_nick
   

class TriggeredBot(SimpleBot):
  rep_nick = '^([@]?(?:{})[:]?)'

  def __init__(self, network_conn, virtual_nicks=(), triggers=['!']):
    super().__init__(network_conn)
    self.virtual_nicks = virtual_nicks
    self.nc.em_in_msg_bc.new_prio_listener(self._process_in_msg, 0)
    
    # Test that this works now.
    re.compile(self.rep_nick.format('|'.join(virtual_nicks)).encode('ascii'))
    self.re_trigger = re.compile('^({})'.format('|'.join(triggers)).encode('ascii'))
    self.ui = TriggerUI()

  def add_mod(self, mod):
    for name in dir(mod):
      val = getattr(mod, name)
      if (not hasattr(val, 'cmd')):
        continue
      self.ui.ui_callables.append(val)
    self.ui._op_setup()
    return mod

  def check_nick_presence(self, nick):
     """Check if specified nick is in one of our channels."""
     chans = self.nc.get_channels()
     if chans is None:
       return False

     nick = self.nc.get_pcs().make_cib(nick)
     for chan in chans.values():
        modes = chan.users.get(nick)
        if not (modes is None):
          return True
     return False
 
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
    for chan in msg.get_chan_targets():
      if (chan in chans):
        target_envs.append(Target(chan, False))

    if (aimed_at_nick):
      target_envs.append(Target(nick, True))

    # This looks like a command addressed to us. Prefix cruft has been stripped, let's go parse.
    ctx = TriggerContext(self, target_envs, msg, text)

    ignore_unknown_cmd = not (aimed_at_nick or have_nick_prefix)
    argv = [x.decode('utf-8', 'surrogateescape') for x in argv]
    self.ui.process_cmd(argv[0].upper(), argv, ctx, ignore_unknown_cmd)

