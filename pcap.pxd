#
# pcap.pxd
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


cdef extern from "Python.h":
    int    PyObject_AsCharBuffer(object obj, char **buffer, Py_ssize_t *buffer_len)

ctypedef unsigned int u_int
ctypedef unsigned char u_char

cdef extern from "pcap.h":
    struct bpf_insn:
        int __xxx
    struct bpf_program:
        bpf_insn *bf_insns
    struct bpf_timeval:
        unsigned int tv_sec
        unsigned int tv_usec
    struct pcap_stat:
        unsigned int ps_recv
        unsigned int ps_drop
        unsigned int ps_ifdrop
    struct pcap_pkthdr:
        bpf_timeval ts
        u_int caplen
    ctypedef struct pcap_t:
        int __xxx
    ctypedef struct pcap_if_t # hack for win32
    ctypedef struct pcap_if_t:
        pcap_if_t *next
        char *name

ctypedef void (*pcap_handler)(u_char *arg, const pcap_pkthdr *hdr, const u_char *pkt)

cdef extern from "pcap.h":
    pcap_t *pcap_open_live(char *device, int snaplen, int promisc,
                           int to_ms, char *errbuf)
    pcap_t *pcap_open_offline(char *fname, char *errbuf)
    int     pcap_compile(pcap_t *p, bpf_program *fp, char *str, int optimize,
                         unsigned int netmask)
    int     pcap_setfilter(pcap_t *p, bpf_program *fp)
    void    pcap_freecode(bpf_program *fp)
    int     pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
                          unsigned char *arg)
    unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    int     pcap_datalink(pcap_t *p)
    int     pcap_snapshot(pcap_t *p)
    int     pcap_stats(pcap_t *p, pcap_stat *ps)
    char   *pcap_geterr(pcap_t *p)
    void    pcap_close(pcap_t *p)
    int     bpf_filter(bpf_insn *insns, const u_char *buf, u_int len, u_int caplen)
    int     pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
    void    pcap_freealldevs(pcap_if_t *alldevs)
    int     pcap_lookupnet(char *device,
                           unsigned int *netp,
                           unsigned int *maskp,
                           char *errbuf)
    int     pcap_sendpacket(pcap_t *p, const u_char *buf, int size)

cdef extern from "pcap_ex.h":
    # XXX - hrr, sync with libdnet and libevent
    int     pcap_ex_immediate(pcap_t *p)
    char   *pcap_ex_name(char *name)
    char   *pcap_ex_lookupdev(char *ebuf)
    int     pcap_ex_fileno(pcap_t *p)
    void    pcap_ex_setup(pcap_t *p)
    void    pcap_ex_setnonblock(pcap_t *p, int nonblock, char *ebuf)
    int     pcap_ex_getnonblock(pcap_t *p, char *ebuf)
    int    pcap_ex_setdirection(pcap_t *p, int direction)
    int     pcap_ex_next(pcap_t *p, pcap_pkthdr **hdr, u_char **pkt) nogil
    int     pcap_ex_compile_nopcap(int snaplen, int dlt,
                                   bpf_program *fp, char *str,
                                   int optimize, unsigned int netmask)

cdef class pcap_handler_ctx:
    cdef:
        void *callback
        void *args
        object exc


cdef object get_buffer(const u_char *pkt, u_int len)


cdef void __pcap_handler(u_char *arg, const pcap_pkthdr *hdr, const u_char *pkt) with gil


cdef enum:
    DLT_NULL =  0
    DLT_EN10MB =    1
    DLT_EN3MB =	2
    DLT_AX25 =	3
    DLT_PRONET =    4
    DLT_CHAOS =	5
    DLT_IEEE802 =   6
    DLT_ARCNET =    7
    DLT_SLIP =  8
    DLT_PPP =   9
    DLT_FDDI =  10
    # XXX - Linux
    DLT_LINUX_SLL = 113
    # XXX - OpenBSD
    DLT_PFLOG =	117
    DLT_PFSYNC =    18

    PCAP_D_INOUT = 0
    PCAP_D_IN = 1
    PCAP_D_OUT = 2

IF UNAME_SYSNAME == "OpenBSD":
    cdef enum:
        DLT_LOOP =  12
        DLT_RAW =   14
ELSE:
    cdef enum:
        DLT_LOOP =  108
        DLT_RAW =   12

dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
          DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
          DLT_LOOP:4, DLT_RAW:0, DLT_LINUX_SLL:16 }


cdef class bpf:
    """bpf(filter, dlt=DLT_RAW) -> BPF filter object"""

    cdef bpf_program fcode


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
    cdef pcap_t *__pcap
    cdef char *__name
    cdef char *__filter
    cdef char __ebuf[256]
    cdef int __dloff
