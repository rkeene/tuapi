TUAPI_VERSION = $(shell ./build-common.sh version)
TCLCONFIGSH = $(shell find /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /lib /lib64 -name tclConfig.sh -print -quit)
TCL_PACKAGE_PATH = $(shell . "$(TCLCONFIGSH)"; echo "$${TCL_PACKAGE_PATH}" | tr ' ' $$'\n' | grep -v '^ *$$' | head -n 1)
PACKAGE_INSTALL_DIR = $(TCL_PACKAGE_PATH)/tuapi-$(TUAPI_VERSION)

export TCLCONFIGSH

all: tuapi.so pkgIndex.tcl

tuapi.so: build-dyn.sh tuapi.c tuapi.tcl stringify.tcl
	@echo "Using tclConfig.sh = $(TCLCONFIGSH)"
	./build-dyn.sh

pkgIndex.tcl: tuapi.so

install: tuapi.so pkgIndex.tcl
	mkdir -p $(DESTDIR)$(PACKAGE_INSTALL_DIR)
	cp tuapi.so pkgIndex.tcl $(DESTDIR)$(PACKAGE_INSTALL_DIR)

clean:
	rm -f tuapi.so pkgIndex.tcl

distclean: clean

mrproper: distclean
	rm -f tuapi.tcl.h

.PHONY: all install clean distclean mrproper
