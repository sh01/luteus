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

import collections
from optparse import OptionParser, Option

from .s2c_structures import *

class LuteusOPBailout(Exception):
   pass

class LuteusOP(OptionParser):
   def __init__(self, *args, **kwargs):
      from io import BytesIO, TextIOWrapper
      self.file_b = BytesIO()
      self.file_t = TextIOWrapper(self.file_b)
      OptionParser.__init__(self, *args, **kwargs)
   
   def exit(self, *args, **kwargs):
      raise LuteusOPBailout()
   
   def _pick_file(self, file):
      if (file is None):
         file = self.file_t
      return file
   
   def print_usage(self, f=None):
      f = self._pick_file(f)
      OptionParser.print_usage(self, f)
      f.flush()
   
   def print_help(self, f=None):
      f = self._pick_file(f)
      OptionParser.print_help(self, f)
      f.flush()
   
   def print_version(self, f=None):
      f = self._pick_file(f)
      OptionParser.print_version(self, self._pick_file(f))
      f.flush()

   def output_lines(self, output):
      """Write lines cached output by calling output(line) for each line."""
      out_val = self.file_b.getvalue()
      if not (out_val):
         return
      out_lines = out_val.strip(b'\n').split(b'\n')
      for line in out_lines:
         output(line)
   
   def clear_output(self):
      """Discard cached output."""
      self.file_b.truncate(0)

class LuteusUICtx:
   def __init__(self, cc, bnc_name):
      self.cc = cc #client connection
      self.bnc_name = bnc_name
   
   def output(self, text):
      msg = IRCMessage(self.bnc_name, b'PRIVMSG', (self.cc.get_unhmask(),
         text))
      self.cc.send_msg(msg)


def _decode_if_valid(s, encoding='ascii'):
   try:
      rv = s.decode(encoding)
   except ValueError:
      rv = s
   return rv

def _encode_if_str(s, encoding='ascii'):
   if (hasattr(s, 'encode')):
      return s.encode(encoding)
   return s

_OptSpec = collections.namedtuple('OptSpec', ('args', 'kwargs'))

class LuteusIRCUI:
   def OS(*args, **kwargs):
      return _OptSpec(list(args), kwargs)
   
   def __init__(self, bnc):
      self.els = set()
      self.bnc = bnc
      self._op_setup()
      self.els.add(bnc.em_client_in_msg.new_prio_listener(self.process_msg))
   
   def _op_setup(self):
      self.ch = ch = {}
      from inspect import getfullargspec
      
      for name in dir(self):
         val = getattr(self, name)
         if (not hasattr(val, 'cmd')):
            continue
         
         as_ = getfullargspec(val)
         defaults = as_.defaults or []
         args = as_.args[2:-1*len(defaults) or None]
         dv = as_.kwonlydefaults or {}
         
         for (a,v) in zip(args, defaults):
            dv[a] = v
         
         if (as_.defaults):
            opt_names = args[-1*len(defaults):]
         else:
            opt_names = []
         
         opt_names += as_.kwonlyargs
         usage = 'usage: %prog [options]' + \
            ''.join(' {0}'.format(a) for a in args)
         if (as_.varargs):
            usage += ' {0}*'.format(as_.varargs)
         
         op = LuteusOP(usage=usage)
         op.prog = val.cmd
         
         for arg in opt_names:
            (oa, okwa) = as_.annotations[arg]
            oa.append('--{0}'.format(arg))
            okwa['default'] = dv[arg]
            opt = Option(*oa, **okwa)
            op.add_option(opt)
         
         if not (as_.varargs is None):
            argc_max = None
         else:
            argc_max = len(args)
         
         self.ch[val.cmd] = (len(args), argc_max, val, op)
   
   def process_msg(self, conn, msg):
      """Process MSG from client."""
      if ((msg.command == b'PRIVMSG') and (len(msg.parameters) > 1) and
         (msg.parameters[0] == conn.self_name)):
         ui_args = msg.parameters[1].split()
      else:
         return
      
      msg.eaten = True
      ctx = LuteusUICtx(conn, conn.self_name)
      
      if (len(ui_args) < 1):
         ctx.output(b'Insufficient tokens: need to specify a command.')
         return
      
      ui_args_str = [_decode_if_valid(a) for a in ui_args]
      self.process_cmd(ui_args_str[0].upper(), ui_args_str, ctx)
   
   def process_cmd(self, cmd, raw_args, ctx):
     try:
        (argc_min, argc_max, func, op) = self.ch[cmd]
     except KeyError:
        ctx.output(b'Unknown command.')
        return
     
     op.clear_output()
     try:
        (opts, args) = op.parse_args(raw_args)
     except LuteusOPBailout:
        op.output_lines(ctx.output)
        return
     
     args = args[1:]
     if ((len(args) < argc_min) or
        ((not (argc_max is None)) and (len(args) > argc_max))):
        # Invalid number of parameters
        op.print_help()
        op.output_lines(ctx.output)
        return
     
     args = [_encode_if_str(a) for a in args]
     kwargs = dict(((key, _encode_if_str(v)) for (key, v) in opts.__dict__.items()))
     func(ctx, *args, **kwargs)
   
   def rch(cmd):
      """Helper: Register command handler func."""
      def d(c):
         c.cmd = cmd
         return c
      return d
   
   @rch("LPART")
   def _pc_connpart(self, ctx, chan):
      cc = ctx.cc
      if not (cc):
         return
      if (b',' in chan):
         ctx.output(b'Invalid chan argument.')
         return
      if (ctx.cc.wc_remove(chan)):
         ctx.cc.send_msg(IRCMessage(ctx.cc.get_unhmask(), b'PART', (chan,
            b'Luteus LPART-triggered fake part.')))
   
   @rch("BLRESET")
   def _pc_blreset(self, ctx, *chans,
      quiet:OS('-q', help="Don't confirm success.", action='store_true')=False,
      nicks:OS('-n', help="Reset nick backlog.", action='store_true')=False,
      activechans:OS(help="Add channels active on this connection to reset set.",
      action='store_true')=False):
      bl = self.bnc.bl
      if (bl is None):
         ctx.output(b'No backlogger active.')
         return
      
      chans = set([IRCCIString(c) for c in chans])
      if (activechans):
         chans.update(ctx.cc.wanted_channels)
      
      if (nicks):
         chans.add(None)
      
      for chan in chans:
         bl.reset_bl(chan)
      
      if (quiet):
         return
      
      if (nicks):
         chans.remove(None)
      
      ctx.output(b'Reset backlog for chans ' + b' '.join(chans) + b'.')
   
   del(rch)
   del(OS)
