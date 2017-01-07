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
import operator
import random
import re

class ModBase:
  def link_bot(self, bot):
    return bot.add_mod(self)

def get_comment(ctx, skip):
  tail = ctx.get_cmd_tail(skip+1)
  if (tail is None):
    return ''
  return '({})'.format(repr(tail)[1:])


xcode_params = ('utf-8', 'surrogateescape')
class TargetError(Exception):
  pass

class SemanticError(Exception):
  pass

class SyntaxError(Exception):
  pass

class CloseParen(Exception):
  pass

class Operator:
  def __init__(self, op, preval):
    self.op = op
    self.a0 = preval
    self.a1 = None

  def __int__(self):
    return self.op(int(self.a0), int(self.a1))


def roll_dice(count, sides):
  """<count>d<sides> dice roll"""
  count = int(count)
  sides = int(sides)
  if (count < 0):
    raise SemanticError('Rolling {} dice is not meaningful.'.format(count))
  if (count > 128):
    raise SemanticError('Excessive dice count: {} > 128.'.format(count))
  if (sides < 1):
    raise SemanticError("I can't roll a {} sided die.".format(sides))
  if (sides > 8192):
    raise SemanticError('Excessive die sides: {} > 8192'.format(sides))

  return sum(random.randint(1,sides) for _ in range(count))


class RollTree:
  operators = {
    b'+': operator.add,
    b'-': operator.sub,
    b'*': operator.mul,
    b'/': operator.floordiv,
    b'd': roll_dice
  }
  RE_NUM = re.compile(b'[0-9]+')

  def __init__(self, data):
    self.data = memoryview(data)
    self.idx = 0

  def getc(self):
    return self.data[self.idx:self.idx+1]

  def eval(self):
    self.idx = 0
    p = self.parse()
    return int(p)

  def parse(self):
    t = None
    def push(val):
      nonlocal t
      if (t is None):
        t = val
        return
      try:
        a1 = t.a1
      except Exception:
        pass
      else:
        if (a1 is None):
          t.a1 = val
          return
      raise SyntaxError('Value collision at {}'.format(idx))

    while (self.idx < len(self.data)):
      idx = self.idx
      c = self.getc()
      self.idx += 1
      # Whitespace
      if (c == b' '):
        continue
      # Parens
      if (c == b'('):
        try:
          self.parse()
        except CloseParen as exc:
          push(exc.val)
          continue
        else:
          raise SyntaxError('Unmatched "(" at {}'.format(idx))
      if (c == b')'):
        cp = CloseParen()
        cp.val = t
        raise cp
      f = self.operators.get(c)

      # Operators
      if not (f is None):
        if (t is None):
          raise SyntaxError('Missing prefix value for infix operator {!a} at {}'.format(bytes(c), idx))
        if (getattr(t, 'a1', True) is None):
          raise SyntaxError('Operator collision with {!a} at {}.'.format(bytes(c), idx))
        t = Operator(f, t)
        continue

      # Numbers
      m = self.RE_NUM.match(self.data, pos=self.idx-1)
      if not (m is None):
        self.idx = m.end()
        push(int(self.data[m.start():self.idx]))
        continue

      raise SyntaxError('Unrecognized character {!a} at {}.'.format(bytes(c), idx))
    return t

def format_src(ctx):
  src = ctx.get_src()
  if (src is None):
    rv = '?'
  else:
    rv = src.decode(*xcode_params)
  return rv


class RPGMod(ModBase):
  _os_targets = OS('-o', '--to', help="Additional targets to send result to (comma-separated).", type='str')
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
  def _ep_init(self, ctx, *,
      int_:OS('-i', '--int', help="Character INT", type='int')=None,
      ref:OS('-r', '--ref', help="Characrter REF", type='int')=None
    ):

    roll = random.randint(1,100)
    mod = int(ref)*2+int(int_)
    res = 'INIT {}: 1d100+<mod> --> {}+{} --> {}'.format(get_comment(ctx, 2), roll, mod, roll+mod)
    ctx.output(res)

  @staticmethod
  def get_targets(targets):
    if (targets is None):
      return []
    return targets.split(b',')
    
  @staticmethod
  def check_targets(ctx, targets):
    for target in targets:
      if not ctx.b.check_nick_presence(target):
        raise TargetError('Unknown target {!a}.'.format(target))
    return True
  
  @rch("ROLL", "Generic die roll")
  def _roll_die(self, ctx, *args, targets:_os_targets=None):
    text = ctx.get_cmd_tail(1)
    (body, *comment_data) = text.split(b'#', 1)

    if (ctx.is_nick_targeted()):
      # Quote full message to counteract cheating
      comment_str = '{}: {}'.format(format_src(ctx), text)
    elif (len(comment_data) == 0):
      comment_str = format_src(ctx)
    else:
      comment_str = comment_data[0].strip().decode(*xcode_params)
      
    comment_str = '({})'.format(comment_str)
    targets = self.get_targets(targets)
    try:
      self.check_targets(ctx, targets)
    except TargetError as exc:
      ctx.output('{}{}: {}'.format(type(exc).__name__, comment_str, exc))
      return
    
    t = RollTree(body)
    try:
      val = t.eval()
    except Exception as exc:
      ctx.output('{}{}: {}'.format(type(exc).__name__, comment_str, exc))
      return

    res = 'ROLL{}: {}'.format(comment_str, val)
    ctx.output(res, extra_targets=targets)

