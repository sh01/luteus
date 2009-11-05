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

import logging

class IRCProtocolError(ValueError):
   def __init__(self, msg, *args, **kwargs):
      self.msg = msg
      ValueError.__init__(self, *args, **kwargs)

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
            self.nick = IRCNick(self)
            self.hostmask = None
            self.user = None
         return
      
      self.type = IA_NICK
      (nick, rest) = self.split(b'!',1)
      self.nick = IRCNick(nick)
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


class IRCNick(bytes):
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


class IRCMessage:
   """An IRC message, as defined by RFC 2812"""
   logger = logging.getLogger()
   log = logger.log
   
   LEN_LIMIT = 512
   
   def __init__(self, prefix:bytes, command:bytes, parameters:bytes, src=None):
      self.prefix = prefix
      self.command = command
      self.parameters = parameters
      
      self.src = src
   
   def copy(self):
      return self.__class__(self.prefix, self.command, self.parameters, self.src)
      
   @classmethod
   def build_from_line(cls, line, src=None):
      """Build instance from raw line"""
      line_split = line.split(b' ') # RFC 2812 says this is correct.
      if (line.startswith(b':')):
         prefix = IRCAddress(line_split[0][1:])
         command = line_split[1]
         parameters = line_split[2:]
      else:
         prefix = None
         command = bytes(line_split[0])
         parameters = line_split[1:]
      
      i = 0
      while (i < len(parameters)):
         p = parameters[i]
         if (p == b''):
            del(parameters[i])
            cls.log(20, 'Invalid empty param in line {0!a}; discarding.'.format(line))
            continue
         
         if not (p.startswith(b':')):
            i += 1
            continue
         parameters[i] = b' '.join([parameters[i][1:]] + parameters[i+1:])
         del(parameters[i+1:])
         break
      return cls(prefix, command, tuple(parameters), src=src)
   
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
   
   def __repr__(self):
      return '{0}.build_from_line({1!a})'.format(
         self.__class__.__name__, self.line_build(sanity_check=False)[:-2])


class IRCChannel:
   def __init__(self, chan, topic=None, users=None, modes=None,
         expect_part=False):
      self.chan = chan
      self.topic = topic
      self.users = users
      if (modes is None):
         modes = {}
      self.modes = modes
      self.expect_part = expect_part
   def __repr__(self):
      return '{0}({1}, {2}, {3}, {4}, {5})'.format(self.__class__.__name__,
         self.chan, self.topic, self.users, self.modes, self.expect_part)


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

