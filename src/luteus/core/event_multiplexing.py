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

# This file contains luteus-specific EM code.

from copy import copy as copy_
import logging

from gonium.event_multiplexing import EventMultiplexer, EventListener


class _EventEaten(BaseException):
   pass


class ComparableCallable:
   def __init__(self, wrappee, priority):
      self.wrappee = wrappee
      self.priority = priority
   
   def __call__(self, *args, **kwargs):
      return self.wrappee(*args, **kwargs)

   def __cmp__(self, other):
      if (self.priority > other.priority): return 1
      if (self.priority < other.priority): return -1
      if (id(self) > id(other)): return 1
      if (id(self) < id(other)): return -1
      return 0
   
   def __eq__(self, other):
      return (self is other)
   
   def __ne__(self, other):
      return not (self is other)
   def __hash__(self):
      return hash((self.wrappee, self.priority))
   def __lt__(self, other):
      return (self.__cmp__(other) < 0)
   def __gt__(self, other):
      return (self.__cmp__(other) > 0)
   def __le__(self, other):
      return (self.__cmp__(other) <= 0)
   def __ge__(self, other):
      return (self.__cmp__(other) >= 0)
   
   def __str__(self):
      return '{0.__class__.__name__}{1}'.format(self, (self.wrappee, self.priority))

# decorator
def ccd(priority):
   def mc(wrappee):
      return ComparableCallable(wrappee, priority)
   return mc

_dummy_ccd = ccd(0)(None)

class OrderingEventMultiplexer(EventMultiplexer):
   logger = logging.getLogger('OrderingEventMultiplexer')
   log = logger.log
   def _listeners_order(self):
      self.listeners.sort(key=lambda l: l.callback)
   
   def new_prio_listener(self, handler, priority=0):
      return EventListener(self, ccd(priority)(handler))
   
   def _listener_subscribe(self, listener, *args, **kwargs):
      assert((_dummy_ccd <= listener.callback) or (_dummy_ccd > listener.callback))
      EventMultiplexer._listener_subscribe(self, listener, *args, **kwargs)
      self._listeners_order()

   def __call__(self, *args, **kwargs) -> bool:
      """Multiplex event; returns True if the event has been eaten completely."""
      for listener in copy_(self.listeners):
         try:
            listener.callback(*args, **kwargs)
         except BaseException as exc:
            self.log(40, '{0} caught exception in handler call '
               '{1}(*{2}, **{3}):'.format(self, listener.callback, args,
               kwargs), exc_info=True)
         

