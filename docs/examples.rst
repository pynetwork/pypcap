========
Examples
========
We present a set of examples that hopefully show how you can use Chains to build
flexible pipelines of streaming data.

Lets Print some Packets 
=======================
Printing packets is about the simplest chain you could have. It takes a 

- PacketStreamer() :py:class:`chains.sources.packet_streamer`
- PacketMeta() :py:class:`chains.links.packet_meta`
- ReverseDNS() :py:class:`chains.links.reverse_dns`
- PacketPrinter() :py:class:`chains.sinks.packet_printer`

We link these together in a chain (see what I did there) and we pull the chain.
Pulling the chain will stream data from one component to another which only uses
the memory required to hold one packet. You could literally run this all day every 
day for a year on your home network and never run out of memory.

**Code from examples/simple_packet_print.py**

.. code-block:: python

    # Create the classes
    streamer = packet_streamer.PacketStreamer(iface_name=data_path, max_packets=50)
    meta = packet_meta.PacketMeta()
    rdns = reverse_dns.ReverseDNS()
    printer = packet_printer.PacketPrinter()

    # Set up the chain
    meta.link(streamer)
    rdns.link(meta)
    printer.link(rdns)

    # Pull the chain
    printer.pull()


**Example Output**

.. code-block:: json

    Timestamp: 2015-05-27 01:17:07.919743
    Ethernet Frame: 6c:40:08:89:fc:08 --> 01:00:5e:00:00:fb  (type: 2048)
    Packet: IP 192.168.1.9 --> 224.0.0.251 (len:55 ttl:255) -- Frag(df:0 mf:0 offset:0)
    Domains: LOCAL --> multicast_dns
    Transport: UDP {'dport': 5353, 'sum': 59346, 'sport': 5353, 'data': '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03CTV\x05local\x00\x00\x1c\x80\x01', 'ulen': 35}
    Application: None
    
    Timestamp: 2015-05-27 01:17:07.919926
    Ethernet Frame: 6c:40:08:89:fc:08 --> 33:33:00:00:00:fb  (type: 34525)
    Packet: IP6 fe80::6e40:8ff:fe89:fc08 --> ff02::fb (len:35 ttl:255)
    Domains: LOCAL --> multicast_dns
    Transport: UDP {'dport': 5353, 'sum': 6703, 'sport': 5353, 'data': '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03CTV\x05local\x00\x00\x1c\x80\x01', 'ulen': 35}
    Application: None
    ...


Taggers
=======
Taggers can look at the streaming data and add tags

- PacketStreamer() :py:class:`chains.sources.packet_streamer`
- PacketMeta() :py:class:`chains.links.packet_meta`
- ReverseDNS() :py:class:`chains.links.reverse_dns`
- Tagger() :py:class:`chains.links.tagger`
- PacketPrinter() :py:class:`chains.sinks.packet_printer`

Again we simply link these together in a chain and then pull the chain.

**Code from examples/tag_example.py**

.. code-block:: python

    # Create the classes
    streamer = packet_streamer.PacketStreamer(iface_name=data_path, max_packets=50)
    meta = packet_meta.PacketMeta()
    rdns = reverse_dns.ReverseDNS()
    tags = tagger.Tagger() 
    printer = packet_summary.PacketSummary()

    # Set up the chain
    meta.link(streamer)
    rdns.link(meta)
    tags.link(rdns)
    printer.link(tags)

    # Pull the chain
    printer.pull()


**Example Output**

.. code-block:: json

    2015-05-30 00:34:45 - TCP IP 192.168.1.9(LOCAL) --> 12.226.156.82(NXDOMAIN) TAGS: ['outgoing', 'nxdomain']
    2015-05-30 00:34:45 - TCP IP 12.226.156.82(NXDOMAIN) --> 192.168.1.9(LOCAL) TAGS: ['incoming', 'nxdomain']
    2015-05-30 00:34:45 - TCP IP 192.168.1.9(LOCAL) --> 54.197.119.105(compute-1.amazonaws.com) TAGS: ['outgoing']
    ...
