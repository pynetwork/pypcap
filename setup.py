#!/usr/bin/env python
#
# $Id$

from __future__ import with_statement
from distutils.core import setup, Extension
from distutils.command import config, clean
from Pyrex.Distutils import build_ext
import cPickle
import glob
import os
import sys

pcap_config = {}
pcap_cache = 'config.pkl'


class FileNotFound(Exception):
    pass


def recursive_search_dirs(dirs, target_files):
    for d in dirs:
        #print "searching %s" % d
        r = recursive_search(d, target_files)
        if r:
            return r
    raise FileNotFound(target_files)


def recursive_search(path, target_files):
    for root, dirs, files in os.walk(path):
        for filename in files:
            #print "Searching for %s %s" % (root, filename)
            if filename in target_files:
                return os.path.join(root, filename)
    return None


class config_pcap(config.config):
    description = 'configure pcap paths'
    user_options = [('with-pcap=', None,
                      'path to pcap build or installation directory')]

    def initialize_options(self):
        config.config.initialize_options(self)
        self.dump_source = 0
        #self.noisy = 0
        self.with_pcap = None

    def _write_config_h(self, cfg):
        # XXX - write out config.h for pcap_ex.c
        d = {}
        include_dir = os.path.join(cfg['include_dirs'][0])
        try:
            with open(os.path.join(include_dir, 'pcap-int.h')) as f:
                d['HAVE_PCAP_INT_H'] = 1
        except IOError:
            print "No pcap-int.h found"

        pcap_h_file = open(os.path.join(include_dir, 'pcap.h')).readlines()
        for line in pcap_h_file:
            if 'pcap_file(' in line:
                print "found pcap_file function"
                d['HAVE_PCAP_FILE'] = 1
            if 'pcap_compile_nopcap(' in line:
                print "found pcap_compile_nopcap function"
                d['HAVE_PCAP_COMPILE_NOPCAP'] = 1
            if 'pcap_setnonblock(' in line:
                print "found pcap_setnonblock"
                d['HAVE_PCAP_SETNONBLOCK'] = 1
        f = open('config.h', 'w')
        for k, v in d.iteritems():
            f.write('#define %s %s\n' % (k, v))
        f.close()

    def pcap_config(self, dirs=[None]):
        cfg = {}
        if not dirs[0]:
            dirs = ['/usr', sys.prefix] + glob.glob('/opt/libpcap*') + \
                glob.glob('../libpcap*') + glob.glob('../wpdpack*') + \
                ['/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.8.sdk/',
                 '/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/*']

        for d in dirs:
            # This makes sure that we first search inside of */include/pcap
            search_dirs = [os.path.join(d, 'usr', 'include', 'pcap'),
                           os.path.join(d, 'include', 'pcap'),
                           d]
            try:
                pcap_h = recursive_search_dirs(search_dirs, ['pcap.h'])
            except:
                continue

            if pcap_h:
                print "Found pcap headers in %s" % pcap_h

                cfg['include_dirs'] = [os.path.dirname(pcap_h)]
                lib_sub_dirs = [os.path.join(d, sub_dir) \
                        for sub_dir in ('lib', 'lib64', \
                        'lib/x86_64-linux-gnu', 'lib/i386-linux-gnu', '')]

                lib_files = {
                        'libpcap.a': 'pcap',
                        'libpcap.so': 'pcap',
                        'libpcap.dylib': 'pcap',
                        'wpcap.lib': 'wpcap'
                }
                lib_file_path = recursive_search_dirs(lib_sub_dirs, lib_files.keys())

                print "Found libraries in %s" % lib_file_path

                lib_file = os.path.basename(lib_file_path)

                cfg['library_dirs'] = [os.path.dirname(lib_file_path)]
                cfg['libraries'] = [lib_files[lib_file]]

                #cfg['libraries'] = [ lib[0] ]
                if lib_file == 'wpcap.lib':
                    cfg['libraries'].append('iphlpapi')
                    cfg['extra_compile_args'] = \
                        ['-DWIN32', '-DWPCAP']

                self._write_config_h(cfg)
                return cfg

        raise Exception("couldn't find pcap build or installation directory")

    def run(self):
        #config.log.set_verbosity(0)
        cPickle.dump(self._pcap_config([self.with_pcap]),
                     open(pcap_cache, 'wb'))
        self.temp_files.append(pcap_cache)


class clean_pcap(clean.clean):
    def run(self):
        clean.clean.run(self)
        if self.all and os.path.exists(pcap_cache):
            print "removing '%s'" % pcap_cache
            os.unlink(pcap_cache)

if len(sys.argv) > 1 and sys.argv[1] == 'build':
    try:
        pcap_config = cPickle.load(open(pcap_cache))
    except IOError:
        print >>sys.stderr, 'run "%s config" first!' % sys.argv[0]
        sys.exit(1)

pcap = Extension(
    name='pcap',
    sources=['pcap.pyx', 'pcap_ex.c'],
    include_dirs=pcap_config.get('include_dirs', ''),
    library_dirs=pcap_config.get('library_dirs', ''),
    libraries=pcap_config.get('libraries', ''),
    extra_compile_args=pcap_config.get('extra_compile_args', '')
)

setup(
    name='pypcap',
    version='1.1',
    author='Dug Song',
    author_email='dugsong@monkey.org',
    url='http://monkey.org/~dugsong/pypcap/',
    description='packet capture library',
    cmdclass={
        'config': config_pcap,
        'clean': clean_pcap,
        'build_ext': build_ext
    },
    ext_modules=[pcap],
    data_files=["pcap_ex.h"],
)
