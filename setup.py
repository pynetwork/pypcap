#!/usr/bin/env python
#
# $Id$

from distutils.core import setup, Extension
import glob, os, sys

pcap_incdir = pcap_libdir = []
pcap_libs = []

# Try standard installation paths.
if os.path.exists('/usr/include/pcap.h'):
    pcap_libs = [ 'pcap' ]
elif os.path.exists('/usr/include/pcap/pcap.h'):
    pcap_incdir = [ '/usr/include/pcap' ]
    pcap_libs = [ 'pcap' ]
else:
    # Try common installation paths.
    for prefix in [ sys.prefix ] + glob.glob('/opt/libpcap*'):
        if glob.glob('%s/include/pcap*' % prefix):
            if os.path.exists('%s/include/pcap/pcap.h'):
                pcap_incdir = [ '%s/include/pcap' % prefix ]
            else:
                pcap_incdir = [ '%s/include' % prefix ]
            pcap_libdir = [ '%s/lib' % prefix ]
            if os.path.exists('%s/lib/libwpcap.a' % prefix):
                pcap_libs = [ 'wpcap' ]
            else:
                pcap_libs = [ 'pcap' ]
            break

if not pcap_libs:
    raise "couldn't find installed libpcap"

pcap = Extension(name='pcap',
                 sources=[ 'pcap.c' ],
                 include_dirs=pcap_incdir,
                 library_dirs=pcap_libdir,
                 libraries=pcap_libs)

setup(name='pcap',
      version='0.2',
      author='Dug Song',
      url='http://monkey.org/~dugsong/pypcap',
      description='packet capture library',
      ext_modules = [ pcap ])
