Python PCAP module
------------------

|travis| `Read the Docs <http://pypcap.rtfd.org>`__

This is a simplified object-oriented Python wrapper for libpcap -
the current tcpdump.org version, and the WinPcap port for Windows.

example use:

>>> import pcap
>>> for ts, pkt in pcap.pcap():
...     print ts, `pkt`
...

Install
--------

This package requires:

* libpcap-dev

* python-dev

To install run::

    pip install pypcap




Support
-------

Visit https://github.com/pynetwork/pypcap for help!

.. |travis| image:: https://img.shields.io/travis/pynetwork/pypcap.svg
   :target: https://travis-ci.org/pynetwork/pypcap
