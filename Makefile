# $Id$

PYTHON	= python
CONFIG_ARGS =

# PYTHON = C:\\Python23\\python.exe
# CONFIG_ARGS = --with-pcap=..\\wpdpack

all: pcap.c
	$(PYTHON) setup.py config $(CONFIG_ARGS)
	$(PYTHON) setup.py build

pcap.c: pcap.pyx
	pyrexc pcap.pyx

install:
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean

cleandir distclean: clean
	$(PYTHON) setup.py clean -a
	rm -f *~
