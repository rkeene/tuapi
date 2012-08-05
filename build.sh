#! /bin/bash

# Perform common build options
. build-common.sh

# Define variables
KITCREATORROOT="$(readlink -f '..')"

# Compile using the same options as Tcl
TCLCONFIGSH="${KITCREATORROOT}/tcl/inst/lib/tclConfig.sh"

. "${TCLCONFIGSH}"

echo "${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o system.o -c system.c"
eval ${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o system.o -c system.c
ar rcu libsystem.a system.o
ranlib libsystem.a

mkdir -p inst/lib/system1.0
mkdir -p out/lib/system1.0
cp libsystem.a inst/lib/system1.0
cp pkgIndex.tcl out/lib/system1.0
