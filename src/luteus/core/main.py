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
import os
import socket
import tempfile

def ca_certs_update(conf, write_cas=False, clobber_out=False):
   import ssl
   
   log = logging.getLogger().log
   servers = conf._get_servers()
   
   for server in servers:
      if (server.ssl is None):
         continue
      
      (ssl_args, ssl_kwargs) = server.get_ssl_args()
      
      log(20, 'Trying to connect to {0}.'.format(server))
      
      s = ssl.wrap_socket(socket.socket(server.af), *ssl_args, **ssl_kwargs)
      try:
         s.connect((server.host, server.port))
      except ssl.SSLError as exc:
         log(20, 'Remote failed to auth: {1}'.format(server, exc))
         s.close()
      except socket.error as exc:
         log(30, 'Failed to connect: {1}'.format(server, exc))
         s.close()
         continue
      else:
         log(20, 'Remote authenticated correctly.'.format(server))
         s.close()
         continue
      
      if (not write_cas):
         continue
      
      log(20, 'Attempting to fetch current cert ...'.format(server))
      ssl_kwargs['cert_reqs'] = ssl.CERT_NONE
      s = ssl.wrap_socket(socket.socket(server.af), *ssl_args, **ssl_kwargs)
      try:
         s.connect((server.host, server.port))
      except Exception as exc:
         log(30, 'Failed to connect: {0}'.format(exc))
         s.close()
         continue
      
      cert_data = ssl.DER_cert_to_PEM_cert(s.getpeercert(binary_form=True)).encode('ascii')
      s.close()
      
      if (cert_data is None):
         log(35, "Peer didn't provide a cert this time. They're probably messing with us.")
         continue
      
      tf = tempfile.NamedTemporaryFile(delete=False)
      try:
         tf.write(cert_data)
         tfn = tf.name
         tf.close()
         ssl_kwargs['cert_reqs'] = ssl.CERT_REQUIRED
         ssl_kwargs['ca_certs'] = tfn
         s = ssl.wrap_socket(socket.socket(server.af), *ssl_args, **ssl_kwargs)
         try:
            s.connect((server.host, server.port))
         except Exception as exc:
            log(30, "Failed to connect: {0}".format(exc))
            log(30, "Retrieved a non-working cert for some reason (server cert not self-signed?)")
            ct_failed = True
         else:
            ct_failed = False
         s.close()
      finally:
         os.unlink(tfn)
      
      cfn = server.get_ssl_fn('ca_certs')
      if (not clobber_out):
         cfn += '.from-net'
      if (ct_failed):
         cfn += '.failed'
      
      log(20, 'Writing cert of {0} to {1!a}.'.format(server, cfn))
      
      cfn_d = os.path.dirname(cfn)
      if not (os.path.exists(cfn_d)):
         os.makedirs(cfn_d)
      
      f = open(cfn, 'w+b')
      f.write(cert_data)
      f.close()
      
      log(20, 'Done.'.format(server, cfn))


def main():
   import optparse
   import os.path
   import signal
   import sys
   
   from .config import LuteusConfig
   from gonium._debugging import streamlogger_setup
   from gonium.pid_filing import PidFile
   from gonium.daemon import daemon_fork
   from gonium.posix.signal import SA_RESTART
   
   logger = logging.getLogger()
   log = logger.log
   
   op = optparse.OptionParser()
   op.add_option('--dir', default='~/.luteus', help='Directory to chdir to', metavar='DIR')
   op.add_option('--config', default='luteus.conf', help='Config file to use', metavar='FILE')
   op.add_option('--debug', default=False, action='store_true', help="Don't fork, and log to stderr.")
   
   og_cc = optparse.OptionGroup(op, "Cert-retrieval mode")
   og_cc.add_option('--check-certs', dest='check_certs', action='store_true',
      default=False, help="Check whether SSL CA config works with current remotes, and exit.")
   og_cc.add_option('--write-new-certs', dest='cc_wnc', action='store_true',
      default=False, help="When checking CA config, retrieve currently used certs from peers and write them to disk.")
   og_cc.add_option('--cc-clobber', dest='cc_clobber', action='store_false',
      default=True, help="When writing retrieved CA certs to disk, overwrite cert files. [DANGEROUS]")
   
   op.add_option_group(og_cc)
   
   (opts, args) = op.parse_args()
   
   if (opts.debug or opts.check_certs):
      streamlogger_setup()
   
   tpath = os.path.expanduser(opts.dir)
   log(20, 'CDing to {0!a}.'.format(tpath))
   os.chdir(tpath)
   
   # Best to be paranoid for logs, etc.
   os.umask(0o77)
   
   conf_fn = opts.config
   conf = LuteusConfig()
   log(20, 'Loading config from {0!a}.'.format(conf_fn))
   conf.load_config_by_fn(conf_fn)

   if (opts.check_certs):
      log(20, 'Checking certs of SSL targets.')
      ca_certs_update(conf, opts.cc_wnc, opts.cc_clobber)
      log(20, 'All done.')
      return
   
   pid_file = PidFile()
   pid_file.lock(True)
   
   sa = conf._sa
   
   sa.sc.sighandler_install(signal.SIGTERM, SA_RESTART)
   sa.sc.sighandler_install(signal.SIGINT, SA_RESTART)
   def handle_signals(si_l):
      for si in si_l:
         if ((si.signo == signal.SIGTERM) or (si.signo == signal.SIGINT)):
            sa.ed.shutdown()
            log(50, 'Shutting down on signal {0}.'.format(si.signo))
            break

   sa.sc.handle_signals.new_listener(handle_signals)
   
   if not (opts.debug):
      daemon_fork(pidfile=pid_file)
      import time
   
   log(50, 'Initialization done; starting normal operation.')
   conf._start_connections()
   conf._event_loop()


if (__name__ == '__main__'):
   main()

