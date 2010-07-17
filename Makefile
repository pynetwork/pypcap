# $Id$

PYTHON	= python
#CONFIG_ARGS = --with-pcap=$(HOME)/build/libpcap-0.8.3

# PYTHON = C:\\Python23\\python.exe
# CONFIG_ARGS = --with-pcap=..\\wpdpack

PKGDIR	= pypcap-`egrep version setup.py | cut -f2 -d"'"`
URL	= `egrep url setup.py | cut -f2 -d"'"`

all: pcap.c
	$(PYTHON) setup.py config $(CONFIG_ARGS)
	$(PYTHON) setup.py build

pcap.c: pcap.pyx
	pyrexc pcap.pyx

install:
	$(PYTHON) setup.py install

test:
	$(PYTHON) test.py

doc:
	epydoc -o doc -n pcap -u $(URL) --docformat=plaintext pcap

pkg_win32:
	$(PYTHON) setup.py bdist_wininst

pkg_osx:
	bdist_mpkg --readme=README --license=LICENSE
	mv dist $(PKGDIR)
	hdiutil create -srcfolder $(PKGDIR) $(PKGDIR).dmg
	mv $(PKGDIR) dist

clean:
	$(PYTHON) setup.py clean
	rm -rf build dist

cleandir distclean: clean
	$(PYTHON) setup.py clean -a
	rm -f config.h *~

# mingw32-make fix
.PHONY: install
