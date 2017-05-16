import binascii
import os
import struct

# Local imports
import pcap


def relative_file(filename):
    """Find a file that is relative to this python source file

        Args:
            filename: relative file path
        Returns:
            the absolute path to the filename
    """
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)


def test_pcap_iter():
    l = [(x[0], len(x[1])) for x in pcap.pcap(relative_file('test.pcap'))]
    assert l == [
        (1092256609.9265549, 62),
        (1092256609.9265759, 54),
        (1092256610.332396, 62),
        (1092256610.3324161, 54),
        (1092256610.8330729, 62),
        (1092256610.8330951, 54)
    ], 'pcap iter'


def test_pcap_properties():
    p = pcap.pcap(relative_file('test.pcap'))
    assert (p.name, p.snaplen, p.dloff, p.filter) == (
        relative_file('test.pcap'), 2000, 14, ''), 'pcap properties'


def test_pcap_errors():
    p = pcap.pcap(relative_file('test.pcap'))
    try:
        print(p.stats())
    except OSError:
        pass
    assert p.geterr() != '', 'pcap_geterr'


def test_pcap_dispatch():
    def __cnt_handler(ts, pkt, d):
        d['cnt'] += 1
    p = pcap.pcap(relative_file('test.pcap'))
    d = {'cnt': 0}
    n = p.dispatch(-1, __cnt_handler, d)
    assert n == 0
    assert d['cnt'] == 6

    def __bad_handler(ts, pkt):
        raise NotImplementedError
    p = pcap.pcap(relative_file('test.pcap'))
    try:
        p.dispatch(-1, __bad_handler)
    except NotImplementedError:
        pass


def test_pcap_readpkts():
    pkts = pcap.pcap(relative_file('test.pcap')).readpkts()
    assert len(pkts) == 6
    buf = pkts[0][1]
    (dst, src, length) = struct.unpack('>6s6sH', buf[:14])
    assert binascii.hexlify(dst).decode('utf-8') == '000d602dc861'
    assert binascii.hexlify(src).decode('utf-8') == '0002b3056f15'
    assert length == 2048


if __name__ == '__main__':
    test_pcap_iter()
    test_pcap_properties()
    test_pcap_errors()
    test_pcap_dispatch()
    test_pcap_readpkts()
