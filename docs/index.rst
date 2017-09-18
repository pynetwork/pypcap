PyPCAP
======
This is a simplified object-oriented Python wrapper for libpcap -
the current tcpdump.org version, and the WinPcap port for Windows.

Example use:
::

    >>> import pcap
    >>> sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
    >>> addr = lambda pkt, offset: '.'.join(str(ord(pkt[i])) for i in range(offset, offset + 4))
    >>> for ts, pkt in sniffer:
    ...     print('%d\tSRC %-16s\tDST %-16s' % (ts, addr(pkt, sniffer.dloff + 12), addr(pkt, sniffer.dloff + 16)))
    ...


Windows notes
-------------

WinPcap has compatibility issues with Windows 10, therefore
it's recommended to use `Npcap <https://nmap.org/npcap/>`_
(Nmap's packet sniffing library for Windows, based on the WinPcap/Libpcap libraries, but with improved speed, portability, security, and efficiency). Please enable WinPcap API-compatible mode during the library installation.


Installation
------------

This package requires:

* libpcap-dev

* python-dev

To install run
::

    pip install pypcap


Installation from sources
~~~~~~~~~~~~~~~~~~~~~~~~~

Please clone the sources and run::

    python setup.py install

Note for Windows users: Please download the `Npcap SDK <https://nmap.org/npcap/>`_, unpack the archive and put it into the sibling directory as ``wpdpack`` (``setup.py`` will discover it).

Sample procedure in PowerShell::

    cd ..
    wget -usebasicparsing -outfile npcap-sdk-0.1.zip https://nmap.org/npcap/dist/npcap-sdk-0.1.zip
    Expand-Archive -LiteralPath npcap-sdk-0.1.zip
    mv npcap-sdk-0.1\npcap-sdk-0.1 wpdpack
    cd pypcap
    python setup.py install


Support
-------

Visit https://github.com/pynetwork/pypcap for help!

Help the Project
----------------
.. toctree::
    :maxdepth: 2

    contributing

Indices and tables
------------------

 * :ref:`genindex`
 * :ref:`modindex`
