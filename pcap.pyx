#
# pcap.pyx
#
# $Id$

"""packet capture library

This module provides a high level interface to packet capture systems.
All packets on the network, even those destined for other hosts, are
accessible through this mechanism.
"""

__author__ = 'Dug Song <dugsong@monkey.org>'
__copyright__ = 'Copyright (c) 2004 Dug Song'
__license__ = 'BSD license'
__url__ = 'https://github.com/pynetwork/pypcap'
__version__ = '1.2.0'

import sys
import struct

from cython cimport view
from libc.stdlib cimport free
from libc.string cimport strdup
cimport pcap


cdef object get_buffer(const u_char *pkt, u_int len):
    cdef bytes pkt_view = (<char *>pkt)[:len]
    return pkt_view


cdef void __pcap_handler(u_char *arg, const pcap_pkthdr *hdr, const u_char *pkt) with gil:
    cdef pcap_handler_ctx ctx = <pcap_handler_ctx><void*>arg
    try:
        (<object>ctx.callback)(
            hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
            get_buffer(pkt, hdr.caplen),
            *(<object>ctx.args)
        )
    except:
        ctx.exc = sys.exc_info()


cdef class bpf:
    """bpf(filter, dlt=DLT_RAW) -> BPF filter object"""

    def __init__(self, char *filter, dlt=DLT_RAW):
        if pcap_ex_compile_nopcap(65535, dlt, &self.fcode, filter, 1, 0) < 0:
            raise IOError, 'bad filter'

    def filter(self, buf):
        """Return boolean match for buf against our filter."""
        cdef u_char *p
        cdef Py_ssize_t n
        if PyObject_AsCharBuffer(buf, <const char**>&p, &n) < 0:
            raise TypeError
        return bpf_filter(self.fcode.bf_insns, p, <u_int>n, <u_int>n) != 0

    def __dealloc__(self):
        pcap_freecode(&self.fcode)


cdef class pcap:
    """pcap(name=None, snaplen=65535, promisc=True, timeout_ms=None, immediate=False)  -> packet capture object

    Open a handle to a packet capture descriptor.

    Keyword arguments:
    name      -- name of a network interface or dumpfile to open,
                 or None to open the first available up interface
    snaplen   -- maximum number of bytes to capture for each packet
    promisc   -- boolean to specify promiscuous mode sniffing
    timeout_ms -- requests for the next packet will return None if the timeout
                  (in milliseconds) is reached and no packets were received
                  (Default: no timeout)
    immediate -- disable buffering, if possible
    """

    def __init__(self, name=None, snaplen=65535, promisc=True,
                 timeout_ms=0, immediate=False):
        global dltoff
        cdef char *p

        if not name:
            p = pcap_ex_lookupdev(self.__ebuf)
            if p == NULL:
                raise OSError, self.__ebuf
        else:
            py_byte_name = name.encode('UTF-8')
            p = py_byte_name

        self.__pcap = pcap_open_offline(p, self.__ebuf)
        if not self.__pcap:
            self.__pcap = pcap_open_live(pcap_ex_name(p), snaplen, promisc,
                                         timeout_ms, self.__ebuf)
        if not self.__pcap:
            raise OSError, self.__ebuf

        self.__name = strdup(p)
        self.__filter = strdup("")
        try:
            self.__dloff = dltoff[pcap_datalink(self.__pcap)]
        except KeyError:
            pass
        if immediate and pcap_ex_immediate(self.__pcap) < 0:
            raise OSError, "couldn't enable immediate mode"

    property name:
        """Network interface or dumpfile name."""
        def __get__(self):
            return str(self.__name.decode('UTF-8'))

    property snaplen:
        """Maximum number of bytes to capture for each packet."""
        def __get__(self):
            return pcap_snapshot(self.__pcap)

    property dloff:
        """Datalink offset (length of layer-2 frame header)."""
        def __get__(self):
            return self.__dloff

    property filter:
        """Current packet capture filter."""
        def __get__(self):
            return str(self.__filter.decode('UTF-8'))

    property fd:
        """File descriptor (or Win32 HANDLE) for capture handle."""
        def __get__(self):
            return pcap_ex_fileno(self.__pcap)

    def fileno(self):
        """Return file descriptor (or Win32 HANDLE) for capture handle."""
        return pcap_ex_fileno(self.__pcap)

    def setfilter(self, value, optimize=1):
        """Set BPF-format packet capture filter."""
        cdef bpf_program fcode
        free(self.__filter)
        py_byte_value = value.encode('UTF-8')
        self.__filter = strdup(py_byte_value)
        if pcap_compile(self.__pcap, &fcode, self.__filter, optimize, 0) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        if pcap_setfilter(self.__pcap, &fcode) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        pcap_freecode(&fcode)

    def setdirection(self, direction):
        """Set capture direction."""
        return pcap_ex_setdirection(self.__pcap, direction) == 0

    def setnonblock(self, nonblock=True):
        """Set non-blocking capture mode."""
        pcap_ex_setnonblock(self.__pcap, nonblock, self.__ebuf)

    def getnonblock(self):
        """Return non-blocking capture mode as boolean."""
        ret = pcap_ex_getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise OSError, self.__ebuf
        return ret != 0

    def datalink(self):
        """Return datalink type (DLT_* values)."""
        return pcap_datalink(self.__pcap)

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))

    def readpkts(self):
        """Return a list of (timestamp, packet) tuples received in one buffer."""
        pkts = []
        self.dispatch(-1, self.__add_pkts, pkts)
        return pkts

    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback,
        return the number of packets processed, or 0 for a savefile.

        Arguments:

        cnt      -- number of packets to process;
                    or 0 to process all packets until an error occurs,
                    EOF is reached, or the read times out;
                    or -1 to process all packets received in one buffer
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_handler_ctx ctx = pcap_handler_ctx()
        cdef int n

        ctx.callback = <void *>callback
        ctx.args = <void *>args
        n = pcap_dispatch(self.__pcap, cnt, __pcap_handler, <u_char *><void*>ctx)
        if ctx.exc:
            raise ctx.exc[0], ctx.exc[1], ctx.exc[2]
        return n

    def loop(self, cnt, callback, *args):
        """Processing packets with a user callback during a loop.
        The loop can be exited when cnt value is reached
        or with an exception, including KeyboardInterrupt.

        Arguments:

        cnt      -- number of packets to process;
                    0 or -1 to process all packets until an error occurs,
                    EOF is reached;
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_pkthdr *hdr
        cdef u_char *pkt
        cdef int n
        cdef int i = 1
        pcap_ex_setup(self.__pcap)
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            if n == 1:
                callback(
                    hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                    get_buffer(pkt, hdr.caplen),
                    *args
                )
            elif n == 0:
                continue
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                break
            if i == cnt:
                break
            i = i + 1

    def sendpacket(self, buf):
        """Send a raw network packet on the interface."""
        ret = pcap_sendpacket(self.__pcap, buf, <int>len(buf))
        if ret == -1:
            raise OSError, pcap_geterr(self.__pcap)
        return len(buf)

    def geterr(self):
        """Return the last error message associated with this handle."""
        return pcap_geterr(self.__pcap)

    def stats(self):
        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface."""
        cdef pcap_stat pstat
        if pcap_stats(self.__pcap, &pstat) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    def __iter__(self):
        pcap_ex_setup(self.__pcap)
        return self

    def __next__(self):
        cdef pcap_pkthdr *hdr
        cdef u_char *pkt
        cdef int n
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            if n == 1:
                return (
                    hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                    get_buffer(pkt, hdr.caplen),
                )
            elif n == 0:
                continue
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                raise StopIteration

    def __dealloc__(self):
        if self.__name:
            free(self.__name)
        if self.__filter:
            free(self.__filter)
        if self.__pcap:
            pcap_close(self.__pcap)

def ex_name(char *foo):
    return pcap_ex_name(foo)

def lookupdev():
    """Return the name of a network device suitable for sniffing."""
    cdef char *p
    cdef char ebuf[256]
    p = pcap_ex_lookupdev(ebuf)
    if p == NULL:
        raise OSError, ebuf
    return str(p.decode('UTF-8'))

def findalldevs():
    """Return a list of capture devices."""
    cdef pcap_if_t *devs
    cdef pcap_if_t *curr
    cdef char ebuf[256]

    status = pcap_findalldevs(&devs, ebuf)
    if status:
        raise OSError(ebuf)
    retval = []
    if not devs:
        return retval
    curr = devs
    while 1:
        retval.append(str(curr.name.decode('UTF-8')))
        if not curr.next:
            break
        curr = curr.next
    pcap_freealldevs(devs)
    return retval

def lookupnet(char *dev):
    """
    Return the address and the netmask of a given device
    as network-byteorder integers.
    """
    cdef unsigned int netp
    cdef unsigned int maskp
    cdef char ebuf[256]

    status = pcap_lookupnet(dev, &netp, &maskp, ebuf)
    if status:
        raise OSError(ebuf)
    return struct.pack('I', netp), struct.pack('I', maskp)
