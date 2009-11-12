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

from collections import deque
import logging

from .event_multiplexing import OrderingEventMultiplexer


class IRCProtocolError(ValueError):
   def __init__(self, msg, *args, **kwargs):
      self.msg = msg
      ValueError.__init__(self, *args, **kwargs)

class IRCInsufficientParametersError(IRCProtocolError):
   pass

# IRC Address Types
IA_SERVER = 0
IA_NICK = 1

class IRCAddress(bytes):
   def __init__(self, *args, **kwargs):
      bytes.__init__(self)
      if not (b'!' in self):
         if (b'.' in self):
            self.type = IA_SERVER
         else:
            self.type = IA_NICK
            self.nick = IRCCIString(self)
            self.hostmask = None
            self.user = None
         return
      
      self.type = IA_NICK
      (nick, rest) = self.split(b'!',1)
      self.nick = IRCCIString(nick)
      (user, hostmask) = rest.split(b'@',1)
      self.hostmask = hostmask
   
   def target_get(self):
      """Return target bytes sequence"""
      if (self.type == IA_SERVER):
         return self
      return self.nick
   
   def irc_eq(self, other):
      """IRC equality testing"""
      if (self.type != other.type):
         return False
      if (self.type == IA_SERVER):
         return (self == other)
      return (self.nick == other.nick)


class IRCCIString(bytes):
   """Case-insensitive (as defined by RFC2821) string"""
   LOWERMAP = bytearray(range(256))
   for i in range(ord(b'A'), ord(b'Z')+1):
      LOWERMAP[i] = ord(chr(i).lower())
   LOWERMAP[ord(b'[')] = ord(b'{')
   LOWERMAP[ord(b']')] = ord(b'}')
   LOWERMAP[ord(b'\\')] = ord(b'|')
   LOWERMAP[ord(b'~')] = ord(b'^')
   LOWERMAP = bytes(LOWERMAP)
   
   def __eq__(self, other):
      return (self.translate(self.LOWERMAP) == other.translate(self.LOWERMAP))
   def __neq__(self, other):
      return not (self == other)
   def __hash__(self):
      return bytes.__hash__(self.translate(self.LOWERMAP))
   # FIXME: add ordering


class Mode:
   def __init__(self, char, level):
      self.char = char
      self.level = level
   
   def __repr__(self):
      return '{0}({1},{2})'.format(self.__class__.__name__, self.char, self.level)
   def __le__(self, other):
      return (self.level <= other.level)
   def __lt__(self, other):
      return (self.level < other.level)
   def __ge__(self, other):
      return (self.level <= other.level)
   def __gt__(self, other):
      return (self.level > other.level)
   def __eq__(self, other):
      return (self.char == other.char)
   def __neq__(self, other):
      return (self.char != other.char)
   def __hash__(self):
      return hash(self.char)


class S2CProtocolCapabilitySet(dict):
   """S2C protocol capability set, as communicated by ISUPPORT msgs"""
   def __init__(self, *args, **kwargs):
      dict.__init__(self, *args, **kwargs)
      self.em_argchange = OrderingEventMultiplexer(self)
   
   def parse_msg(self, msg):
      args = list(msg.parameters[1:])
      
      if (args and (b' ' in args[-1])):
         # Probably a silly HR explanation of this line, as specified by
         # draft-brocklesby-irc-isupport-03.
         del(args[-1])
      
      for arg in args:
         if (b'=' in arg):
            (name, val) = arg.split(b'=', 1)
            val = bytes(val)
         elif arg.startswith(b'-'):
            name = arg[1:]
            val = False
         else:
            name = arg
            val = True
         
         name = bytes(name)
         if ((not (name in self)) or (self[name] != val)):
            self.em_argchange(name, val)
         
         self[name] = val
   
   def get_argstring(self, name):
      val = self[name]
      if (val is True):
         return name
      if (val is False):
         return (b'-' + name)
      return b''.join((name, b'=', val))
   
   def is_chann(self, tok):
      """Return whether specified token appears to be a channame."""
      try:
         cic = self['CHANTYPES']
      except KeyError:
         cic = b'#&+'
      
      try:
         return (tok[0] in cic)
      except IndexError:
         return False
   
   def get_005_lines(self, nick, prefix=None):
      arglist = [self.get_argstring(name) for name in self]
      rv = IRCMessage.build_ml_args(b'005', (nick,),
         (b'are supported by this server',), arglist, prefix=prefix)
      return rv

class _MultiLineCmdBase:
   def __init__(self, i, args, len_limit, argc_limit):
      self.len_limit = len_limit
      self.msg = None
      self.argc_limit = argc_limit
      self.args = deque(args)
      self.i = i
   
   def set_msg(self, msg):
      self.msg = msg
   
   def __bool__(self):
      return bool(self.args)

class _MultLineCmdArglist(_MultiLineCmdBase):
   def __init__(self, i, args, len_limit, argc_limit):
      super().__init__(i, args, len_limit, argc_limit)
   
   def have_space(self):
      len_new = self.msg.get_line_length() + len(self.args[0]) + 1
      if (len_new > self.len_limit):
         return False
      if (self.argc_limit is None):
         return True
      if (len(self.msg.parameters) >= self.argc_limit):
         return False
      return True
   
   def add(self):
      arg = self.args.popleft()
      if (self.i is None):
         self.msg.parameters.append(arg)
      else:
         self.msg.parameters.insert(self.i, arg)

class _MultiLineCmdOneArg(_MultiLineCmdBase):
   def __init__(self, i, args, len_limit, argc_limit, joinchar):
      super().__init__(i, args, len_limit, argc_limit)
      self.joiner = joinchar
      self.ac = 0
   
   def have_space(self):
      if (self.ac > self.argc_limit):
         return False
      
      arg = self.msg.parameters[self.i or -1]
      if (arg):
         jo = len(self.joiner)
      else:
         jo = 0
      
      len_new = self.msg.get_line_length() + len(self.args[0]) + jo
      if (len_new > self.len_limit):
         return False
      return True
   
   def add(self):
      sub_arg = self.args.popleft()
      p = self.msg.parameters
      i = self.i or -1
      arg = p[i]
      if (arg):
         arg = self.joiner.join((arg, sub_arg))
      else:
         arg = sub_arg
      p[i] = arg
      self.ac += 1

   def set_msg(self, msg):
      super().set_msg(msg)
      self.ac = 0


class IRCMessage:
   """An IRC message, as defined by RFC 2812"""
   logger = logging.getLogger()
   log = logger.log
   
   chan_cmds = set((b'PRIVMSG', b'NOTICE', b'KICK', b'PART', b'JOIN', b'MODE', b'TOPIC'))
   # RFC 1459 and 2812, section 2.3
   LEN_LIMIT = 512
   ARGC_LIMIT = 15
   
   def __init__(self, prefix:bytes, command:bytes, parameters, src=None,
         pcs=S2CProtocolCapabilitySet()):
      self.prefix = prefix
      self.command = command.upper()
      self.parameters = list(parameters)
      self.src = src
      self.pcs = pcs
   
   def copy(self):
      return self.__class__(self.prefix, self.command, self.parameters,
         self.src, self.pcs)
      
   @classmethod
   def build_from_line(cls, line, *args, **kwargs):
      """Build instance from raw line"""
      line_split = bytes(line).split(b' ') # RFC 2812 says this is correct.
      if (line.startswith(b':')):
         prefix = IRCAddress(line_split[0][1:])
         command = line_split[1]
         parameters = line_split[2:]
      else:
         prefix = None
         command = line_split[0]
         parameters = line_split[1:]
      
      i = 0
      while (i < len(parameters)):
         p = parameters[i]
         if (p == b''):
            # Probably a RFC 1459-style message.
            del(parameters[i])
            continue
         
         if not (p.startswith(b':')):
            i += 1
            continue
         parameters[i] = b' '.join([parameters[i][1:]] + parameters[i+1:])
         del(parameters[i+1:])
         break
      return cls(prefix, command, parameters, *args, **kwargs)
   
   @classmethod
   def build_ml_args(cls, cmd, static_args_b, static_args_e, arg_list,
         prefix=None, len_limit=LEN_LIMIT, argc_limit=ARGC_LIMIT):
      msg = IRCMessage(prefix, cmd, list(static_args_b) +
         list(static_args_e))
      
      i = -1*len(static_args_e) or None
      mlc = _MultLineCmdArglist(i, arg_list, len_limit, argc_limit)
      
      return cls.build_mlcmd_msgs(msg, mlc)
   
   @classmethod
   def build_ml_onearg(cls, cmd, static_args_b, static_args_e, subarg_list,
      join_el, prefix=None, len_limit=LEN_LIMIT, argc_limit=ARGC_LIMIT):
   
      msg = IRCMessage(prefix, cmd, list(static_args_b) + [b''] + list(static_args_e))
      i = -1*len(static_args_e) or None
      mlc = _MultiLineCmdOneArg(i, subarg_list, len_limit, argc_limit, join_el)
      return cls.build_mlcmd_msgs(msg, mlc)
   
   @classmethod
   def build_mlcmd_msgs(cls, msg_base, mlc):
      msg = msg_base.copy()
      mlc.set_msg(msg)
      
      ml_base = msg.get_line_length()
      rv = []
      while (mlc):
         if ((msg.parameters != msg_base.parameters) and (not mlc.have_space())):
            rv.append(msg)
            msg = msg_base.copy()
            mlc.set_msg(msg)
         
         mlc.add()
      
      if (msg.parameters != msg_base.parameters):
         rv.append(msg)
      
      return rv
   
   def line_build(self, sanity_check=True):
      if (self.prefix is None):
         prefix = []
      else:
         prefix = [b':' + self.prefix]
      
      params_out = list(self.parameters)
      if (params_out and (b' ' in params_out[-1])):
         params_out[-1] = b':' + params_out[-1]
      
      for param in params_out[:-1]:
         if (b' ' in param):
            raise ValueError('Parameter list {0} contains non-last'
               'parameter containing a space.'.format(params_out))
      
      rv = b' '.join(prefix + [self.command] + params_out) + b'\r\n'
      
      if (sanity_check and ((b'\x00' in rv) or (b'\n' in rv[:-2]) or
            (b'\r' in rv[:-2]))):
         raise ValueError('Would return {0!a}, which contains an invalid char.'
            ''.format(rv))
      
      return rv
   
   def get_cmd_numeric(self):
      try:
         rv = int(self.command)
      except ValueError:
         return None
      return rv
   
   def get_line_length(self):
      if (self.prefix is None):
         rv = 0
      else:
         rv = len(self.prefix) + 2
      
      rv += len(self.command)
      rv += sum([len(p)+1 for p in self.parameters]) # +1 for preceding spaces
      
      if ((self.parameters) and (b' ' in self.parameters[-1])):
         # ':' prefix for last parameter
         rv += 1
      rv += 2 # CRLF
      
      return rv
   
   def parse_JOIN(self):
      if not (self.parameters):
         raise IRCProtocolError(self)
      if ((len(self.parameters) == 1) and (self.parameters[0] == b'0')):
         return 0
      
      rv = {}
      chnns = self.parameters[0].split(b',')
      if (len(self.parameters) > 1):
         keys = self.parameters[1].split(b',')
      else:
         keys = ()
      
      for i in range(len(chnns)):
         chnn = IRCCIString(chnns[i])
         if (i < len(keys)):
            key = keys[i]
         else:
            key = None
         rv[chnn] = key
      
      return rv
   
   def parse_KICK(self):
      if (len(self.parameters) < 2):
         raise IRCProtocolError(self)
      
      chnns = [IRCCIString(b) for b in self.parameters[0].split(b',')]
      nicks = [IRCCIString(b) for b in self.parameters[1].split(b',')]
      if (len(chnns) == 0):
         raise IRCProtocolError(self)
      
      if (len(nicks) == 1):
         nicks *= len(chnns)
      elif (len(nicks) != len(chnns)):
         raise IRCProtocolError(self)
      
      return zip(chnns,nicks)
   
   def get_chan_targets(self):
      """If this message is targeted to one or more channels, return their
         names; else return None."""
      if not (self.command.upper() in self.chan_cmds):
         return None
      if (len(self.parameters) < 1):
         return None
      target_str = self.parameters[0]
      
      targets = target_str.split(b',')
      return [t for t in targets if self.pcs.is_chann(t)]
   
   def filter_chan_targets(self, filt):
      """Adjust chan target set by removing channel-targets for which
         (not filt(chann)). Returns new number of targets."""
      if (len(self.parameters) < 1):
         return
      
      targets_new = []
      for target in self.parameters[0].split(b','):
         if (self.pcs.is_chann(target) and not (filt(target))):
            continue
         targets_new.append(target)
      
      self.parameters[0] = b','.join(targets_new)
      return len(targets_new)
   
   def parse_PART(self):
      if (len(self.parameters) < 1):
         raise IRCProtocolError(self)
      return [IRCCIString(b) for b in self.parameters[0].split(b',')]
   
   def __repr__(self):
      return '{0}.build_from_line({1!a})'.format(
         self.__class__.__name__, self.line_build(sanity_check=False)[:-2])


class IRCChannel:
   def __init__(self, chan, topic=None, users=None, modes=None,
         expect_part=False, cmp_=None):
      self.chan = chan
      self.topic = topic
      self.users = users
      if (modes is None):
         modes = {}
      self.modes = modes
      self.expect_part = expect_part
      self.cmp = cmp_
   
   def make_names_reply(self, target, prefix=None):
      userstrings = []
      for (nick, modes) in self.users.items():
         userstrings.append(self.cmp.get_uflagstring(modes) + nick)
      
      msgs = list(IRCMessage.build_ml_onearg(b'353', (target, b'=', self.chan),
         (), userstrings, b' ', prefix=prefix))
      
      msgs.append(IRCMessage(prefix, b'366', (target, self.chan, b'End of NAMES list')))
      return msgs
   
   def make_join_msgs(self, target, prefix=None):
      if (self.topic is None):
         rv = []
      elif (self.topic is False):
         rv = [IRCMessage(prefix, b'331', (target, self.chan, b'No topic set'))]
      else:
         rv = [IRCMessage(prefix, b'332', (target, self.chan, self.topic))]
      
      rv += self.make_names_reply(target, prefix)
      return rv

   def __repr__(self):
      return '{0}({1}, {2}, {3}, {4}, {5})'.format(self.__class__.__name__,
         self.chan, self.topic, self.users, self.modes, self.expect_part)

