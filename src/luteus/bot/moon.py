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

from binascii import b2a_hex
import logging
import os
from os import urandom

from ..core.irc_ui import LuteusOP, OS, rch

# The first reactive luteus bot UI.
# There's not too much rhyme or reason to this functionality, so it gets a codename.
class ModBase:
  def link_bot(self, bot):
    return bot.add_mod(self)


class MoonMod(ModBase):
  @rch("ECHO", "Format args in a python list and throw them back at the requester.")
  def _pc_echo(self, ctx, *args):
    ctx.output(str(list(args)).encode('utf-8'))


def xor_bytes(h0, h1):
  """Take two hex strings, return their xor as a raw byte string."""
  l0 = int(h0, base=16)
  l1 = int(h1, base=16)
  # It's annoying to do this efficiently in python. At least this version is O(n).
  l = l0 ^ l1
  h = '{:0{}x}'.format(l, len(h0))
  return bytes([int(h[i:i+2],16) for i in range(0, len(h), 2)])


class DistributedEntropy:
  logger = logging.getLogger('DistributedEntropy')
  log = logger.log

  timeout = 16
  query_limit = 190
  def __init__(self, bot, peer, join_string):
    self.peer = bytes(peer)
    self.ees = {} # entropy expectations
    self.join_string = join_string
    self.pid = os.getpid()

    nc = bot.nc
    nc.em_in_msg_bc.new_prio_listener(self._process_in_msg, 1024)
    bot.add_mod(self)

  @rch("RSE", "Print raw shared entropy bytestrings.")
  def _pc_rse(self, ctx, *,
      count:OS('-c', help="Count of entropy bytes to generate.", type='int')=16,
      hex:OS('-x', help="Print output as hexadecimal sequence instead of py string.", action='store_true')=False):
    def cb(entropy):
      if (hex):
        entropy = b2a_hex(entropy).decode('ascii')
      ctx.output('SE: {}'.format(entropy))
    self.get_entropy(ctx, count, cb)

  def get_entropy(self, ctx, count, callback):
    from time import time
    if (count > self.query_limit):
      raise ValueError('Requested {!a} > {!a} bytes of entropy.'.format(count, self.query_limit))

    seqnum = (int(time()*1000000) % (self.timeout*1000000))
    ee_id = '{:x}|{:x}'.format(self.pid, seqnum)
    entropy_local = os.urandom(count)
    if (len(entropy_local) != count):
      raise Exception('Failed to generate local entropy.')

    def ee(entropy_remote):
      self.log(20, 'Processing remote entropy: {} {} {}.'.format(ee.peer, ee_id, entropy_remote))
      err = None
      if (len(entropy_remote)/2 != count):
        ctx.output('Wrong length; got {} != {} bytes.'.format(len(entropy_remote)/2, count))
        return

      entropy = xor_bytes(b2a_hex(entropy_local), entropy_remote)
      callback(entropy)

    self.ees[ee_id.encode('ascii')] = ee
    ee.peer = self.peer

    ctx.output('{}{}ES {} {:x}'.format(self.peer.decode('utf-8', 'surrogateescape'), self.join_string, ee_id, count).encode('ascii'))

  def _process_in_msg(self, msg):
    if (msg.command != b'PRIVMSG'):
      return

    text = msg.parameters[1]
    words = text.split()
    if (len(words) != 3):
      return
    if (words[0] != b'ES'):
      return

    ee = self.ees.get(words[1])
    if (ee is None):
      return

    src = msg.prefix
    if ((src is None) or (msg.pcs.make_cib(ee.peer) != src.target_get())):
      return

    del(self.ees[words[1]])
    ee(words[2])
