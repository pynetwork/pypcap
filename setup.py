#!/usr/bin/env python
#
# $Id$

from __future__ import with_statement
from setuptools import setup, Extension
import glob
import os
import sys
import re

def recursive_search_dirs(dirs, target_files):
    for d in dirs:
        r = recursive_search(d, target_files)
        if r:
            return r


def recursive_search(path, target_files):
    for root, dirs, files in os.walk(path):
        for filename in files:
            if filename in target_files:
                return os.path.join(root, filename)


dirs = ['/usr', sys.prefix] + glob.glob('/opt/libpcap*') + \
    glob.glob('../libpcap*') + glob.glob('../wpdpack*') + \
    ['/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.8.sdk/'] + \
     glob.glob('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/*')

for d in dirs:
    # This makes sure that we first search inside of */include/pcap
    search_dirs = [os.path.join(d, 'usr', 'include', 'pcap'),
                   os.path.join(d, 'include', 'pcap'),
                   d]

    pcap_h = recursive_search_dirs(search_dirs, ['pcap.h'])
    if pcap_h:
        print "Found pcap headers in %s" % pcap_h
        break

if not pcap_h:
    print "pcap.h not found"
    sys.exit(1)

include_dirs = os.path.dirname(pcap_h)
lib_sub_dirs = [os.path.join(d, sub_dir) \
        for sub_dir in ('lib', 'lib64', \
        'lib/x86_64-linux-gnu', 'lib/i386-linux-gnu', '')]

lib_files = [
        'libpcap.a',
        'libpcap.so',
        'libpcap.dylib',
        'wpcap.lib'
]
lib_file_path = recursive_search_dirs(lib_sub_dirs, lib_files)

print "Found libraries in %s" % lib_file_path

lib_file = os.path.basename(lib_file_path)

extra_compile_args = []
if re.match(r"libpcap\.(a|so|dylib)", lib_file):
    libraries = ('pcap',)
elif lib_file == "wpcap.lib":
    libraries = ('wpcap', 'iphlpapi')
    extra_compile_args = ['-DWIN32', '-DWPCAP']

define_macros = []

if recursive_search_dirs(dirs, ['pcap-int.h']):
    define_macros.append(('HAVE_PCAP_INT_H', 1))
else:
    print "No pcap-int.h found"

pcap_h_file = open(pcap_h).readlines()
for line in pcap_h_file:
    if 'pcap_file(' in line:
        print "found pcap_file function"
        define_macros.append(('HAVE_PCAP_FILE', 1))
    if 'pcap_compile_nopcap(' in line:
        print "found pcap_compile_nopcap function"
        define_macros.append(('HAVE_PCAP_COMPILE_NOPCAP', 1))
    if 'pcap_setnonblock(' in line:
        print "found pcap_setnonblock"
        define_macros.append(('HAVE_PCAP_SETNONBLOCK', 1))


pcap = Extension(
    name='pcap',
    sources=['pcap.c', 'pcap_ex.c'],
    include_dirs=[include_dirs],
    define_macros=define_macros,
    libraries=list(libraries),
    extra_compile_args=extra_compile_args,
)

setup(
    name='pypcap',
    version='1.1.1',
    author='Dug Song',
    author_email='dugsong@monkey.org',
    url='http://monkey.org/~dugsong/pypcap/',
    description='packet capture library',
    ext_modules=[pcap],
)
