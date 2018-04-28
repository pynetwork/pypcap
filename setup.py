"""Setup for pycapy"""
from setuptools import setup, Extension
import glob
import os
import sys
import re

PACKAGE = "pypcap"
VERSION = "1.2.1"


def recursive_search_dirs(dirs, target_files):
    """Recursive search directories"""
    for d in dirs:
        r = recursive_search(d, target_files)
        if r:
            return r


def recursive_search(path, target_files):
    """Recursively search for files"""
    for root, _dirs, files in os.walk(path):
        for filename in files:
            if filename in target_files:
                return os.path.join(root, filename)


def get_extension():
    # A list of all the possible search directories
    dirs = ['/usr', sys.prefix] + glob.glob('/opt/libpcap*') + \
        glob.glob('../libpcap*') + glob.glob('../wpdpack*') + \
        glob.glob('/Applications/Xcode.app/Contents/Developer/Platforms/' +
                  'MacOSX.platform/Developer/SDKs/*')

    for d in dirs:
        search_dirs = [
            os.path.join(d, 'local', 'include'),
            os.path.join(d, 'usr', 'include'),
            os.path.join(d, 'include'),
            d
        ]

        pcap_h = recursive_search_dirs(search_dirs, ['pcap.h'])
        if pcap_h:
            print("Found pcap headers in %s" % pcap_h)
            break

    if not pcap_h:
        print("pcap.h not found")
        sys.exit(1)

    include_dirs = [os.path.dirname(pcap_h)]

    # This logic will use the path 'd' that the pcap.h was found in
    is_64bits = sys.maxsize > 2**32
    priority_libs = (
        'lib64',
        'lib/x64',  # wpdpack
        'lib/x86_64-linux-gnu'
    ) if is_64bits else tuple()

    lib_sub_dirs = [
        os.path.join(d, sub_dir)
        for sub_dir in priority_libs + (
            'lib',
            'lib/i386-linux-gnu',
            ''
        )
    ]

    # For Mac OSX the default system pcap lib is in /usr/lib
    lib_sub_dirs.append('/usr/lib')

    lib_files = [
        'libpcap.a',
        'libpcap.so',
        'libpcap.dylib',
        'wpcap.lib'
    ]
    lib_file_path = recursive_search_dirs(lib_sub_dirs, lib_files)

    print("Found libraries in %s" % lib_file_path)

    lib_file = os.path.basename(lib_file_path)
    lib_path = os.path.dirname(lib_file_path)

    extra_compile_args = []
    if re.match(r"libpcap\.(a|so|dylib)", lib_file):
        libraries = ('pcap',)
    elif lib_file == "wpcap.lib":
        libraries = ('wpcap', 'iphlpapi')
        extra_compile_args = ['-DWIN32', '-DWPCAP', '-D_CRT_SECURE_NO_WARNINGS']

    define_macros = []

    pcap_h_file = open(pcap_h).readlines()
    for line in pcap_h_file:
        if 'pcap_file(' in line:
            print("found pcap_file function")
            define_macros.append(('HAVE_PCAP_FILE', 1))
        if 'pcap_compile_nopcap(' in line:
            print("found pcap_compile_nopcap function")
            define_macros.append(('HAVE_PCAP_COMPILE_NOPCAP', 1))
        if 'pcap_setnonblock(' in line:
            print("found pcap_setnonblock")
            define_macros.append(('HAVE_PCAP_SETNONBLOCK', 1))
        if 'pcap_setdirection(' in line:
            print("found pcap_setdirection")
            define_macros.append(('HAVE_PCAP_SETDIRECTION', 1))

    ext = Extension(
        name='pcap',
        sources=['pcap.c', 'pcap_ex.c'],
        include_dirs=include_dirs,
        define_macros=define_macros,
        library_dirs=[lib_path, ],
        libraries=list(libraries),
        extra_compile_args=extra_compile_args
    )
    return ext

setup_args = dict(
    name=PACKAGE,
    version=VERSION,
    author='Dug Song',
    author_email='dugsong@monkey.org',
    url='https://github.com/pynetwork/pypcap',
    description='pypcap -- Python interface to pcap a packet capture library',
    tests_require=['dpkt']
)

if __name__ == "__main__":
    ext = get_extension()
    setup_args['ext_modules'] = [ext]
    setup(**setup_args)
