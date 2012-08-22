# /bin/bash

# Perform common build options
. build-common.sh

# Compile using the same options as Tcl
TCLCONFIGSH="$(find /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /lib /lib64 -name tclConfig.sh -print -quit)"

. "${TCLCONFIGSH}"

echo "${TCL_CC} -fPIC -DPIC -Wall -DUSE_TCL_STUBS=1 ${TCL_DEFS} ${TCL_INCLUDE_SPEC} ${TCL_STUB_LIB_SPEC} -shared -rdynamic -o system.so system.c"
eval ${TCL_CC} -fPIC -DPIC -Wall -DUSE_TCL_STUBS=1 ${TCL_DEFS} ${TCL_INCLUDE_SPEC} ${TCL_STUB_LIB_SPEC} -shared -rdynamic -o system.so system.c
