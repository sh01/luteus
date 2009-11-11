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


def main():
   import logging
   import optparse
   import os.path
   import sys
   
   from .config import LuteusConfig
   from gonium._debugging import streamlogger_setup
   
   streamlogger_setup()
   logger = logging.getLogger()
   log = logger.log
   
   op = optparse.OptionParser()
   op.add_option('--dir', default='~/.luteus', help='Directory to chdir to', metavar='DIR')
   op.add_option('--config', default='luteus.conf', help='Config file to use', metavar='FILE')
   
   (opts, args) = op.parse_args()
   
   tpath = os.path.expanduser(opts.dir)
   log(20, 'CDing to {0!a}.'.format(tpath))
   os.chdir(tpath)
   conf_fn = opts.config
   
   conf = LuteusConfig()
   log(20, 'Loading config from {0!a}.'.format(conf_fn))
   conf.load_config_by_fn(conf_fn)

   conf._start_connections()
   conf._event_loop()


if (__name__ == '__main__'):
   main()
