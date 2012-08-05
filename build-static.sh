#! /bin/bash

# Perform common build options
. build-common.sh

# Define variables
KITCREATORROOT="$(readlink -f '..')"

# Compile using the same options as Tcl
TCLCONFIGSH='/usr/lib/tclConfig.sh'

. "${TCLCONFIGSH}"

echo "diet ${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o system.o -c system.c"
eval diet ${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o system.o -c system.c
ar rcu libsystem.a system.o
ranlib libsystem.a
