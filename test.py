#!/usr/bin/env python

import glob, sys, unittest
sys.path.insert(0, glob.glob('build/lib.*')[0])
import pcap

class PcapTestCase(unittest.TestCase):
    def test_pcap_iter(self):
        l = [ (x[0], len(x[1])) for x in pcap.pcap('test.pcap') ]
        assert l == [(1092256609.9265549, 62), (1092256609.9265759, 54), (1092256610.332396, 62), (1092256610.3324161, 54), (1092256610.8330729, 62), (1092256610.8330951, 54)], 'pcap iter'

    def test_pcap_properties(self):
        p = pcap.pcap('test.pcap')
        assert (p.name, p.snaplen, p.dloff, p.filter) == ('test.pcap', 2000, 14, ''), 'pcap properties'

    def test_pcap_errors(self):
        p = pcap.pcap('test.pcap')
        stats_err = "Statistics aren't available from savefiles"
        try:
            print p.stats()
        except OSError, msg:
            assert msg != stats_err, 'pcap_stats'
        assert p.geterr() == stats_err, 'pcap_geterr'

    def __test_pcap_cb(self, method):
        def __cnt_handler(ts, pkt, d):
            d['cnt'] += 1
        p = pcap.pcap('test.pcap')
        d = { 'cnt':0 }
        n = getattr(p, method)(__cnt_handler, d)
        if method == 'dispatch': assert n == 0
        assert d['cnt'] == 6

        def __bad_handler(ts, pkt, arg):
            raise NotImplementedError
        p = pcap.pcap('test.pcap')
        try:
            getattr(p, method)(__bad_handler)
        except NotImplementedError:
            pass

    def test_pcap_dispatch(self):
        self.__test_pcap_cb('dispatch')
        
    def test_pcap_loop(self):
        self.__test_pcap_cb('loop')
        
    def test_pcap_readpkts(self):
        assert len(pcap.pcap('test.pcap').readpkts()) == 6

if __name__ == '__main__':
    unittest.main()
