#!/usr/bin/env python
#
# $Id$

from distutils.core import setup, Extension
import sys

if 'bsd' in sys.platform:
    pcap_incdir = []
    pcap_libdir = []
else:
    pcap_incdir = [ '%s/include' % sys.prefix ]
    pcap_libdir = [ '%s/lib' % sys.prefix ]

pcap = Extension(name='pcap',
                 sources=[ 'pcap.c' ],
                 include_dirs=pcap_incdir,
                 library_dirs=pcap_libdir,
                 libraries=[ 'pcap' ])

setup(name='pcap',
      version='0.2',
      author='Dug Song',
      url='http://monkey.org/~dugsong/pypcap',
      description='packet capture library',
      ext_modules = [ pcap ])
