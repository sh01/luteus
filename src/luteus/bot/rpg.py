#!/usr/bin/env python
#Copyright 2016 Sebastian Hagen
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
import random

class ModBase:
  def link_bot(self, bot):
    return bot.add_mod(self)

def get_comment(ctx, skip):
  tail = ctx.get_cmd_tail(skip+1)
  if (tail is None):
    return ''
  return '({})'.format(repr(tail)[1:])


class RPGMod(ModBase):
  @rch("EP", "EclipsePhase die roll")
  def _ep_dice(self, ctx, *args):
    if len(args) < 1:
      ctx.output('Insufficient arguments.')
      return

    comment = get_comment(ctx, 1)
    
    try:
      tval = int(args[0])
    except ValueError:
      ctx.output('Unable to parse target value.')
      return

    roll = random.randint(0,99)
    if roll == 0:
      succ = True
    elif roll == 99:
      succ = False
    else:
      succ = (roll <= tval)

    d0,d1 = divmod(roll,10)
    crit = (d0 == d1)
    margin = abs(roll-tval)

    qualifier = ''
    if (crit):
      qualifier = 'Critical'
    elif (margin >= 30):
      if succ:
        qualifier = 'Excellent'
      else:
        qualifier = 'Severe'
    else:
      qualifier = 'Ordinary'

    succS = ['failure', 'success']

    res = 'EP {}: 1d100={} --> {} {} (Margin {})'.format(comment, roll, qualifier, succS[succ], margin)
    ctx.output(res)

  @rch("INIT", "EclipsePhase VTS init")
  def _ep_init(self, ctx,
      int_:OS('-i', '--int', help="Character INT", type='int'),
      ref:OS('-r', '--ref', help="Characrter REF", type='int'),
      *args):

    roll = random.randint(1,100)
    mod = int(ref)*2+int(int_)
    res = 'INIT {}: 1d100+<mod> --> {}+{} --> {}'.format(get_comment(ctx, 2), roll, mod, roll+mod)
    ctx.output(res)

  @rch("ROLL", "Generic die roll")
  def _roll_die(self, ctx, *args):
    lim = 128
    outs = []
    for arg in args:
      (c, s) = arg.split(b'd')
      c = int(c)
      s = int(s)
      if (c > lim):
        ctx.output('{} is above my dice-count limit of {}. I refuse.'.format(c, lim))
        return
      out = sum((random.randint(1,s) for i in range(c)))
      outs.append('{}d{}={}'.format(c,s,out))
    ctx.output('ROLL: ' + ' '.join(outs))
