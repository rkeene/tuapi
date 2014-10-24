#! /bin/bash

# Perform common build options
. build-common.sh

# Define variables
KITCREATORROOT="$(readlink -f '..')"

# Compile using the same options as Tcl
TCLCONFIGSH='/usr/lib64/tclConfig.sh'

. "${TCLCONFIGSH}"

echo "${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o tuapi.o -c system.c"
eval ${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o tuapi.o -c system.c
ar rcu libtuapi.a tuapi.o
ranlib libtuapi.a
echo 'package ifneeded tuapi '"${tuapi_version}"' [list load {} tuapi]' > pkgIndex.tcl
