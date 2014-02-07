#!/usr/bin/env python
#Copyright 2014 Sebastian Hagen
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

from ..core.irc_ui import LuteusOP, OS, rch

# The first reactive luteus bot UI.
# There's not too much rhyme or reason to this functionality, so it gets a codename.
class MoonMod:
  @classmethod
  def setup(cls, *args, **kwargs):
    from .base import TriggeredBot
    bot = TriggeredBot(*args, **kwargs)
    self = cls()
    self.link_bot(bot)
    return (bot, self)

  @rch("ECHO", "Format args in a python list and throw them back at the requester.")
  def _pc_echo(self, ctx, *args):
    ctx.output(str(args).encode('utf-8'))
