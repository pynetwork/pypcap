# $Id$

all: pcap.c
	python setup.py build

pcap.c: pcap.pyx
	pyrexc pcap.pyx

install:
	python setup.py install

clean:
	rm -rf build

cleandir distclean: clean
	rm -f *.c *~
