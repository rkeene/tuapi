#! /bin/bash

set -e

case "$1" in
	clean|distclean)
		rm -rf out inst
		rm -f libsystem.a system.o system.so
		rm -f system.tcl.h
		exit 0
		;;
esac

./stringify.tcl system.tcl > system.tcl.h
