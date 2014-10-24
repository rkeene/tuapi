# /bin/bash

# Perform common build options
. build-common.sh

# Compile using the same options as Tcl
if [ -z "${TCLCONFIGSH}" ]; then
	TCLCONFIGSH="$(find /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /lib /lib64 -name tclConfig.sh -print -quit)"
fi

. "${TCLCONFIGSH}"

echo "${TCL_CC} -ggdb3 -fPIC -DPIC -Wall -DUSE_TCL_STUBS=1 ${TCL_DEFS} ${TCL_INCLUDE_SPEC} ${TCL_STUB_LIB_SPEC} -shared -rdynamic -o tuapi.so tuapi.c"
eval ${TCL_CC} -ggdb3 -fPIC -DPIC -Wall -DUSE_TCL_STUBS=1 ${TCL_DEFS} ${TCL_INCLUDE_SPEC} ${TCL_STUB_LIB_SPEC} -shared -rdynamic -o tuapi.so tuapi.c

echo 'package ifneeded tuapi '"${tuapi_version}"' [list load [file join $dir tuapi.so]]' > pkgIndex.tcl
