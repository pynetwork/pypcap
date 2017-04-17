Python PCAP module
------------------

|travis| `Read the Docs <http://pypcap.rtfd.org>`__

This is a simplified object-oriented Python wrapper for libpcap -
the current tcpdump.org version, and the WinPcap port for Windows.

Example use::

    >>> import pcap
    >>> sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
    >>> addr = lambda pkt, offset: '.'.join(str(ord(pkt[i])) for i in xrange(offset, offset + 4)).ljust(16)
    >>> for ts, pkt in sniffer:
    ...     print ts, '\tSRC', addr(pkt, sniffer.dloff + 12), '\tDST', addr(pkt, sniffer.dloff + 16)
    ...


Windows notes
-------------

WinPcap has compatibility issues with Windows 10, therefore
it's recommended to use `Npcap <https://nmap.org/npcap/>`_
(Nmap's packet sniffing library for Windows, based on the WinPcap/Libpcap libraries, but with improved speed, portability, security, and efficiency). Please enable WinPcap API-compatible mode during the library installation.

The sample installation using `Chocolatey <https://chocolatey.org/>`_::

    choco install -y npcap --ia '/winpcap_mode=yes'


Installation
------------

This package requires:

* libpcap-dev

* python-dev

To install run::

    pip install pypcap


Installation from sources
~~~~~~~~~~~~~~~~~~~~~~~~~

Please clone the sources and run::

    python setup.py install

Note for Windows users: Please download the `WinPcap Developer's Pack <https://www.winpcap.org/devel.htm>`_, unpack the archive and put it into the sibling directory as ``wpdpack`` (``setup.py`` will discover it).

Sample procedure in PowerShell::

    cd ..
    wget -usebasicparsing -outfile WpdPack_4_1_2.zip http://www.winpcap.org/install/bin/WpdPack_4_1_2.zip
    unzip WpdPack_4_1_2.zip
    cd pypcap
    python setup.py install


Support
-------

Visit https://github.com/pynetwork/pypcap for help!

.. |travis| image:: https://img.shields.io/travis/pynetwork/pypcap.svg
   :target: https://travis-ci.org/pynetwork/pypcap


Building docs
-------------

To build docs you need the following additional dependencies::

    pip install sphinx mock sphinxcontrib.napoleon

Building bindings
-----------------

To build the C bindings you should ensure you have cython installed and then you should run::

    cython pcap.pyx
