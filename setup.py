#!/usr/bin/env python
#
# $Id$

from distutils.core import setup, Extension
import sys

if 'bsd' in sys.platform:
    pcap_incdir = [ ]
    pcap_libdir = [ ]
else:
    pcap_incdir = [ '/usr/local/include' ]
    pcap_libdir = [ '/usr/local/lib' ]

pcap = Extension(name='pcap',
                 sources=[ 'pcap.c' ],
                 include_dirs=pcap_incdir,
                 library_dirs=pcap_libdir,
                 libraries=[ 'pcap' ])

setup(name='pcap',
      version='1.0',
      description='packet capture library',
      author='Dug Song',
      ext_modules = [ pcap ])
