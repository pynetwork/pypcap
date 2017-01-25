PyPCAP
======
This is a simplified object-oriented Python wrapper for libpcap -
the current tcpdump.org version, and the WinPcap port for Windows.

Example use:
::

    >>> import pcap
    >>> for ts, pkt in pcap.pcap():
    ...     print ts, `pkt`
    ...

Install
--------

This package requires:

* libpcap-dev

* python-dev

To install run
::

    pip install pypcap


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
