#!/usr/bin/env python

import getopt, sys
import pcap
from dpkt.ethernet import Ethernet

def usage():
    print >>sys.stderr, 'usage: %s [-i device] [pattern]' % sys.argv[0]
    sys.exit(1)

def main():
    opts, args = getopt.getopt(sys.argv[1:], 'i:h')
    name = None
    for o, a in opts:
        if o == '-i': name = a
        else: usage()
    pc = pcap.pcap(name)
    pc.setfilter(' '.join(args))
    try:
        print 'listening on %s: %s' % (pc.name, pc.filter)
        for ts, pkt in pc:
            print ts, `Ethernet(pkt)`
    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop

if __name__ == '__main__':
    main()
