# pypcap 1.2.1 [2018-04-28]

Added:

- Support create / activate paradigm for pcap objects, and RFMON. See: https://github.com/pynetwork/pypcap/pull/67

# pypcap 1.2.0 [2017-11-15]

Added:

- Python3 support

Fixes:

- Bug in iteration of packets (see: https://github.com/pynetwork/pypcap/issues/49)

# pypcap 1.2.0-rc.1 [2017-09-13]

Adds:

- Python3 support

# pypcap-1.1.6 [2017-05-02]

- fix for finding libpcap on macOS

- drop workaround for missing `pcap_file()`

- make setup.py importable

# pypcap-1.1.5 [2016-04-22]

- fix for immediate mode on linux (#12)

# pypcap-1.1.4 [2015-09-07]

- fix for immediate mode on Mac OS X 10.10

# pypcap-1.1.3 [2015-05-18]

- minor bugfixing

# pypcap-1.1.2 [2015-05-18]

- setdirection() support - from Eddi Linder

- make it possible to install without pyrex

# pypcap-1.1.1 [2013-02-27]

- honor 'immediate' flag to disable buffering under Windows - by Kosma Moczek

- sendpacket() support - by Kosma Moczek

- API CHANGE: require 'cnt' as first parameter to pcap.loop()
  - by Bartosz Skowron

- lookupnet() support - from Joao Medeiros

- findalldevs() support - by Bartosz Skowron

- better support for installing on Fedora, Ubuntu and Mac OS X

# pypcap-1.1

- better lookupdev() on win32, as requested by Zack Payton
  <zack@tek-pros.com>

- add Linux SLL datalink type

- better threading support from A. Nonymous

pypcap-1.0:

- API CHANGE: require 'cnt' as first parameter to pcap.dispatch(),
  shadowing libpcap pcap_dispatch().

- add pcap.{get,set}nonblock(), to work around broken BPF select()
  on certain platforms (MacOS X, older FreeBSD, etc.).

# $Id$
