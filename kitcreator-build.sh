#! /bin/bash

# Perform common build options
. build-common.sh

# Define variables
KITCREATORROOT="$(readlink -f '..')"

# Compile using the same options as Tcl
TCLCONFIGSH="${KITCREATORROOT}/tcl/inst/lib/tclConfig.sh"

. "${TCLCONFIGSH}"

echo "${TCL_CC} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} -o tuapi.o -c tuapi.c"
eval ${TCL_CC} ${KC_TUAPI_CPPFLAGS} ${KC_TUAPI_CFLAGS} ${TCL_DEFS} ${TCL_INCLUDE_SPEC} ${KC_TUAPI_LDFLAGS} -o tuapi.o -c tuapi.c
ar rcu libtuapi.a tuapi.o
ranlib libtuapi.a

echo 'package ifneeded tuapi '"${tuapi_version}"' [list load {} tuapi]' > pkgIndex.tcl

mkdir -p inst/lib/tuapi-${tuapi_version}
mkdir -p out/lib/tuapi-${tuapi_version}
cp libtuapi.a inst/lib/tuapi-${tuapi_version}
cp pkgIndex.tcl out/lib/tuapi-${tuapi_version}
