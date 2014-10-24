#! /bin/bash

set -e

case "$1" in
	clean|distclean)
		rm -rf out inst
		rm -f libtuapi.a tuapi.o tuapi.so
		rm -f tuapi.tcl.h
		exit 0
		;;
esac

tuapi_version="$(grep Tcl_PkgProvide tuapi.c | awk '{ print $3 }' | sed 's@[");]*@@g')"

./stringify.tcl tuapi.tcl > tuapi.tcl.h
