# $Id$

PYTHON	= python
#CONFIG_ARGS = --with-pcap=$(HOME)/build/libpcap-0.8.3

# PYTHON = C:\\Python23\\python.exe
# CONFIG_ARGS = --with-pcap=..\\wpdpack

all: pcap.c
	$(PYTHON) setup.py config $(CONFIG_ARGS)
	$(PYTHON) setup.py build

pcap.c: pcap.pyx
	pyrexc pcap.pyx

install:
	$(PYTHON) setup.py install

test:
	$(PYTHON) test.py

clean:
	$(PYTHON) setup.py clean
	rm -rf build

cleandir distclean: clean
	$(PYTHON) setup.py clean -a
	rm -f config.h *~
