#! /bin/bash

set -e

tuapi_version="$(grep Tcl_PkgProvide tuapi.c | awk '{ print $3 }' | sed 's@[");]*@@g')"

case "$1" in
	clean|distclean)
		rm -rf out inst
		rm -f libtuapi.a tuapi.o tuapi.so
		rm -f tuapi.tcl.h
		exit 0
		;;
	version)
		echo "${tuapi_version}"
		;;
esac

sed 's@[\\"]@\\&@g;s@^@   "@;s@$@\\n"@' tuapi.tcl > tuapi.tcl.h
