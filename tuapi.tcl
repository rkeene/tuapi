#! /usr/bin/env tclsh

# Copyright (c) 2014-2017 Roy Keene
# 
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE.

namespace eval ::tuapi {}
namespace eval ::tuapi::helper {}
namespace eval ::tuapi::cache {}

set ::tuapi::_mount_flags(bind) BIND
set ::tuapi::_mount_flags(move) MOVE
set ::tuapi::_mount_flags(remount) REMOUNT
set ::tuapi::_mount_flags(mandlock) MANDLOCK
set ::tuapi::_mount_flags(dirsync) DIRSYNC
set ::tuapi::_mount_flags(noatime) NOATIME
set ::tuapi::_mount_flags(nodiratime) NODIRATIME
set ::tuapi::_mount_flags(relatime) RELATIME
set ::tuapi::_mount_flags(strictatime) STRICTATIME
set ::tuapi::_mount_flags(nodev) NODEV
set ::tuapi::_mount_flags(noexec) NOEXEC
set ::tuapi::_mount_flags(nosuid) NOSUID
set ::tuapi::_mount_flags(ro) RDONLY
set ::tuapi::_mount_flags(silent) SILENT
set ::tuapi::_mount_flags(synchronous) SYNCHRONOUS
set ::tuapi::_mount_flags(sync) SYNCHRONOUS


# Determine where to mount a given device (usually by checking "/etc/fstab")
proc ::tuapi::helper::find_mountpoint {device} {
	set data ""
	catch {
		set fd [open "/etc/fstab"]
		set data [read -nonewline $fd]
		close $fd
	}

	foreach line [split $data "\n"] {
		set line [string trim [regsub {#.*$} $line ""]]
		set line [regsub -all {[ \t][ \t][ \t]*} $line " "]

		set work [split $line]

		set curr_device     [lindex $work 0]
		set curr_mountpoint [lindex $work 1]
		set curr_fstype     [lindex $work 2]
		set curr_opts       [split [lindex $work 3] ","]
		set curr_dumpfreq   [lindex $work 4]
		set curr_fsckpass   [lindex $work 5]


		if {$curr_device == $device || $curr_mountpoint == $device} {
			return [list source $curr_device target $curr_mountpoint fstype $curr_fstype options $curr_opts dumpfreq $curr_dumpfreq fsckpass $curr_fsckpass]
		}
	}

	return -code error "no entry found in \"/etc/fstab\" for \"$device\""
}

proc ::tuapi::mount args {
	set options_list [list]

	for {set idx 0} {$idx < [llength $args]} {incr idx} {
		set curr_arg [lindex $args $idx]

		switch -glob -- $curr_arg {
			"-t" {
				incr idx
				set fstype [lindex $args $idx]
			}
			"-r" {
				lappend options_list "RDONLY"
			}
			"-w" {
				set idx [lsearch -exact $options_list "RDONLY"]
				if {$idx != -1} {
					set options_list [lreplace $options_list $idx $idx]
				}
			}
			"-o" {
				incr idx
				set options [lindex $args $idx]
			}
			"--" {
				incr idx

				break
			}
			"-*" {
				return -code error "unknown option \"$curr_arg\""
			}
			default {
				break
			}
		}
	}

	set args [lrange $args $idx end]

	if {[llength $args] < 1 || [llength $args] > 2} {
		return -code error "wrong # args: should be \"::tuapi::mount ?options? source ?target?\""
	}

	set source [lindex $args 0]

	if {[llength $args] == 2} {
		set target [lindex $args 1]
	} else {
		array set mountinfo [::tuapi::helper::find_mountpoint $source]
		set source $mountinfo(source)
		set target $mountinfo(target)

		if {![info exists fstype]} {
			set fstype $mountinfo(fstype)
		}

		if {![info exists options]} {
			set options $mountinfo(options)
		}
	}

	# Ensure all mount-related parameters have been computed
	if {![info exists fstype]} {
		set fstype "auto"
	}

	if {![info exists options]} {
		set options [list]
	}

	# Process options
	foreach option $options {
		set option_lc [string tolower $option]

		# Special option handling
		switch -- $option_lc {
			"defaults" {
				set options_list [list]
				unset -nocomplain unknown_options

				continue
			}
			"rw" {
				set option_lc "noro"
			}
			"norw" {
				set option_lc "ro"
			}
		}

		# Example: noatime
		if {[info exists ::tuapi::_mount_flags($option_lc)]} {
			lappend options_list $::tuapi::_mount_flags($option_lc)

			continue
		}

		# Example: atime
		if {[info exists ::tuapi::_mount_flags(no$option_lc)]} {
			set idx [lsearch -exact $options_list $::tuapi::_mount_flags(no$option_lc)]
			if {$idx != -1} {
				set options_list [lreplace $options_list $idx $idx]
			}

			continue
		}

		# Example: norelatime
		if {[string match "no*" $option_lc]} {
			set neg_option_lc [string range $option_lc 2 end]

			if {[info exists ::tuapi::_mount_flags($neg_option_lc)]} {
				set idx [lsearch -exact $options_list $::tuapi::_mount_flags($neg_option_lc)]
				if {$idx != -1} {
					set options_list [lreplace $options_list $idx $idx]
				}

				continue
			}
		}

		# Accumulate unknown options
		lappend unknown_options $option
	}

	# Use "swapon" if this is swap
	if {$fstype == "swap"} {
		return [::tuapi::syscall::swapon $source]
	}

	# Otherwise, call "mount" system call
	## If we have accumulated any unknown options, pass them as a
	## comma-seperated value string
	if {[info exists unknown_options]} {
		set data [join $unknown_options ","]

		return [::tuapi::syscall::mount $source $target $fstype $options_list $data]
	}

	return [::tuapi::syscall::mount $source $target $fstype $options_list]
}

proc ::tuapi::umount {dir {flags ""}} {
	return [::tuapi::syscall::umount $dir [string toupper $flags]]
}

proc ::tuapi::kill {pid sig} {
	return [::tuapi::syscall::kill $pid [string toupper $sig]]
}

proc ::tuapi::killpg {pgroup sig} {
	if {$pgroup <= 1} {
		return -code error "invalid process group specified (must be greater than 1)"
	}

	return [::tuapi::syscall::kill -$pgroup [string toupper $sig]]
}

proc ::tuapi::ifconfig args {
	if {[llength $args] == 0} {
		# Return information on all interfaces
		set retlist [list]
		foreach interface [::tuapi::syscall::ifconfig] {
			lappend retlist $interface [::tuapi::syscall::ifconfig $interface]
		}

		return $retlist
	}

	set interface [lindex $args 0]
	set args [lrange $args 1 end]

	array set ifaceinfo [::tuapi::syscall::ifconfig $interface]

	if {[llength $args] == 0} {
		return [array get ifaceinfo]
	}

	for {set idx 0} {$idx < [llength $args]} {incr idx} {
		set opt [lindex $args $idx]

		switch -- $opt {
			"up" {
				if {[info exists ifaceinfo(flags)]} {
					set flags $ifaceinfo(flags)
				} else {
					set flags ""
				}

				foreach newflag [list UP] {
					if {[lsearch -exact $flags $newflag] == -1} {
						lappend flags $newflag
					}
				}

				::tuapi::syscall::ifconfig $interface flags $flags
			}
			"down" {
				if {[info exists ifaceinfo(flags)]} {
					set flags $ifaceinfo(flags)
				} else {
					set flags ""
				}

				set flagidx [lsearch -exact $flags "UP"]
				if {$flagidx != -1} {
					set flags [lreplace $flags $flagidx $flagidx]

					::tuapi::syscall::ifconfig $interface flags $flags
				}
			}
			default {
				incr idx
				set optval [lindex $args $idx]

				::tuapi::syscall::ifconfig $interface $opt $optval
			}
		}
	}
}

proc ::tuapi::helper::foreach_line {fd sep code} {
	while {![eof $fd]} {
		gets $fd line

		regsub { *#.*$} $line {} line

		if {$line == ""} {
			continue
		}

		set line [split $line $sep]

		uplevel 1 [list set line $line]
		uplevel 1 $code
	}
	uplevel 1 [list unset -nocomplain line]
}

proc ::tuapi::helper::recursive_glob {path pattern code {depth 1}} {
	foreach filename [glob -nocomplain -directory $path -type f $pattern] {
		uplevel $depth [list set filename $filename]
		uplevel $depth $code
	}

	incr depth

	foreach dirname [glob -nocomplain -directory $path -type d *] {
		set dirinfo(type) unknown
		catch {
			file lstat $dirname dirinfo
		}

		if {$dirinfo(type) == "link"} {
			continue
		}

		::tuapi::helper::recursive_glob $dirname $pattern $code $depth
	}
}

proc ::tuapi::modprobe args {
	# Process arguments
	set options(call_insmod) 1
	set idx 0
	set nextIsArgs 0
	foreach arg $args {
		if {$nextIsArgs} {
			set options(args) $arg

			set nextIsArgs 0

			incr idx
			continue
		}

		switch -- $arg {
			"-dontload" {
				set options(call_insmod) 0
			}
			"-args" {
				set nextIsArgs 1
			}
			"--" {
				incr idx
				break
			}
			default {
				break
			}
		}

		incr idx
	}
	set args [lrange $args $idx end]

	# Set initial retval
	set retval [list]

	# Set module base directory
	set modules_dir [file join /lib/modules $::tcl_platform(osVersion)]

	# Load device names
	if {![info exists ::tuapi::cache::alias2module]} {
		set devnames_file [file join $modules_dir modules.devname]
		set fd [open $devnames_file]
		::tuapi::helper::foreach_line $fd " " {
			set module [lindex $line 0]
			set device [lindex $line 1]
			set id [lindex $line 2]

			set id_type [string index $id 0]
			set id_type [string map [list "c" "char" "b" "block"] $id_type]
			set id [split [string range $id 1 end] :]
			set id_alias "${id_type}-major-[lindex $id 0]-[lindex $id 1]"

			set "alias2module(/dev/${device})" $module
			set alias2module($id_alias) $module
		}
		close $fd

		# Load aliases
		set aliases_file [file join $modules_dir modules.alias]
		set fd [open $aliases_file]
		::tuapi::helper::foreach_line $fd " " {
			set alias [lindex $line 1]
			set module [lindex $line 2]

			set alias2module($alias) $module
			if {[string match {*\**} $alias]} {
				set alias2module_wildcards($alias) $module
			}
		}
		close $fd

		# Load dependencies
		set deps_file [file join $modules_dir modules.dep]
		set fd [open $deps_file]
		::tuapi::helper::foreach_line $fd ":" {
			set module [string trim [lindex $line 0]]
			set deps [lreverse [split [string trim [join [lrange $line 1 end]]]]]

			set module_basename [file rootname [file tail $module]]
			set module_basename_alt1 [string map [list "_" "-"] $module_basename]
			set module_basename_alt2 [string map [list "-" "_"] $module_basename]

			set alias2module($module_basename) $module
			set alias2module($module_basename_alt1) $module
			set alias2module($module_basename_alt2) $module

			if {[llength $deps] != 0} {
				set module2deps($module) $deps
			}
		}
		close $fd

		set ::tuapi::cache::alias2module [array get alias2module]
		set ::tuapi::cache::alias2module_wildcards [array get alias2module_wildcards]
		set ::tuapi::cache::module2deps [array get module2deps]
	} else {
		array set alias2module $::tuapi::cache::alias2module
		array set alias2module_wildcards $::tuapi::cache::alias2module_wildcards
		array set module2deps $::::tuapi::cache::module2deps
	}

	# Determine list of modules
	set all_modules [list]
	foreach modules $args {
		foreach module $modules {
			lappend all_modules $module
		}
	}

	# Determine what modules to add the arguments to
	if {[info exists options(args)]} {
		foreach arg [split $options(args) " \n\t"] {
			set arg [string trim $arg]
			if {$arg == ""} {
				continue
			}

			if {[string match "*=*" $arg]} {
				set work [split $arg =]

				set name [lindex $work 0]
				set value [join [lrange $work 1 end] =]
			} else {
				set name $arg
				unset -nocomplain value
			}

			if {[string match "*.*" $name]} {
				set work [split $name .]

				set module [lindex $work 0]
				if {$module == ""} {
					set modules [list]
				} else {
					set modules [list $module]
				}

				set name [join [lrange $work 1 end] .]
			} else {
				set modules [list]
			}

			if {[llength $modules] == 0} {
				set modules $all_modules
			}

			foreach module $modules {
				if {[info exists value]} {
					append modules_args($module) "$name=$value "
				} else {
					append modules_args($module) "$name "
				}
			}
		}
	}

	# Load modules
	foreach module $all_modules {
		# If the module is given as an absolute path, ignore the path
		# and process just as we would if the name were given alone
		# This may be wrong, but otherwise dependency matching would
		# be harder
		if {[string index $module 0] == "/" && [file exists $module]} {
			set module [file rootname [file tail $module]]
		}

		for {set try 0} {$try < 100} {incr try} {
			if {![info exists alias2module($module)]} {
				# If no exact match found, process wildcard entries
				set found_wildcard_match 0
				set tmp_matched_modules [list]
				foreach alias [array name alias2module_wildcards] {
					if {[string match $alias $module]} {
						set module $alias2module_wildcards($alias)

						lappend tmp_matched_modules $module

						incr found_wildcard_match 1
					}
				}

				if {!$found_wildcard_match} {
					break
				}

				if {$found_wildcard_match > 1} {
					# Multiple matches, try to pick the best one
					foreach tmp_module $tmp_matched_modules {
						# First, prefer things that do not contain generic
						if {![string match "*generic*" $tmp_module]} {
							set module $tmp_module
						}
					}
				}
			}

			set module $alias2module($module)
		}

		if {[info exists module2deps($module)]} {
			set load $module2deps($module)
		} else {
			set load [list]
		}

		lappend load $module

		foreach module $load {
			if {[string match "/dev/*" $module]} {
				return -code error "Unable to lookup device node module for $module"
			}

			set module [file join $modules_dir $module]

			unset -nocomplain module_args
			set module_short [file rootname [file tail $module]]
			if {[info exists modules_args($module_short)]} {
				set module_args [string trim $modules_args($module_short)]
			}

			if {$options(call_insmod)} {
				if {[catch {
					if {[info exists module_args]} {
						::tuapi::syscall::insmod $module $module_args
					} else {
						::tuapi::syscall::insmod $module
					}
				}]} {
					continue
				}
			}

			lappend retval $module
		}
	}

	return $retval
}

# Scan the various buses attached to the system and load the appropriate
# kernel modules
proc ::tuapi::scan_and_load_kernel_modules args {
	set parameters [list "ata_generic.all_generic_ide=1"]
	foreach arg $args {
		if {[info exists var_to_set]} {
			set $var_to_set $arg

			unset var_to_set

			continue
		}

		if {[info exists var_to_lappend]} {
			lappend $var_to_lappend $arg

			unset var_to_lappend

			continue
		}

		switch -- $arg {
			"-arg" {
				set var_to_lappend parameters
			}
			"-args" {
				set var_to_set parameters
			}
			default {
				return -code error "Unknown option: $arg"
			}
		}
	}

	set modules [list]

	# Determine which modules are already loaded
	foreach module [glob -tails -nocomplain -directory /sys/module -type d *] {
		set alt_module1 [string map [list "_" "-"] $module]
		set alt_module2 [string map [list "-" "_"] $module]

		set loaded($module) 1
		set loaded($alt_module1) 1
		set loaded($alt_module2) 1
	}

	::tuapi::helper::recursive_glob /sys/devices modalias {
		set fd [open $filename r]
		::tuapi::helper::foreach_line $fd "\n" {
			foreach module [::tuapi::modprobe -dontload -- $line] {
				if {[lsearch -exact $modules $module] != -1} {
					continue
				}

				if {![file exists $module]} {
					continue
				}

				set rootname [file rootname [file tail $module]]
				if {[info exists loaded($rootname)]} {
					continue
				}

				lappend modules $module
			}
		}
		close $fd
	}

	set failed_to_load [list]
	set able_to_load [list]
	foreach module $modules {
		if {[::tuapi::modprobe -args $parameters $module] == ""} {
			lappend failed_to_load $module
		} else {
			lappend able_to_load $module
		}
	}

	return [list -failed $failed_to_load -loaded $able_to_load]
}

# Create UNIX-like procs meant to be used interactively
proc ::tuapi::create_unix_commands {} {
	proc ::cat args {
		foreach file $args {
			if {[catch {
				set fd [open $file]
			} err]} {
				puts stderr "Unable to open \"$file\": $err"

				continue
			}

			fcopy $fd stdout
			close $fd
		}
	}

	proc ::ls args {
		set options(long) 0
		set options(one) 0
		set options(skipdot) 1
		set options(norecurseintotopleveldirs) 0

		set idx 0
		foreach arg $args {
			if {[string match "-*" $arg]} {
				set args [lreplace $args $idx $idx]
				if {$arg == "--"} {
					break
				}

				if {[string range $arg 0 1] == "--"} {
					set opts [list [string range $arg 2 end]]
				} else {
					set opts [split [string range $arg 1 end] ""]
				}

				foreach opt $opts {
					switch -- $opt {
						"l" {
							set options(long) 1
							set options(one) 0
						}
						"1" {
							set options(one) 1
							set options(long) 0
						}
						"d" {
							set options(norecurseintotopleveldirs) 1
						}
						"a" {
							set options(skipdot) 0
						}
					}
				}

				continue
			}

			incr idx
		}

		if {[llength $args] == 0} {
			set args [list "."]
		}

		set nodes [list]
		foreach arg $args {
			unset -nocomplain fileinfo
			catch {
				file stat $arg fileinfo
			}

			if {![info exists fileinfo]} {
				puts stderr "No such file or directory: $arg"

				continue
			}

			if {$fileinfo(type) == "directory"} {
				if {$options(norecurseintotopleveldirs)} {
					lappend nodes $arg
				} else {
					lappend nodes {*}[glob -nocomplain -directory $arg -tails *]
				}
			} else {
				lappend nodes $arg
			}

		}

		set newline_required 0
		foreach node $nodes {
			unset -nocomplain fileinfo

			if {$options(one)} {
				puts $node
			} elseif {$options(long)} {
				catch {
					file stat $node fileinfo
				}

				if {![info exists fileinfo]} {
					array set fileinfo [list mode 0 nlink 0 uid -1 gid -1 size 0 mtime 0]
				}

				set date [clock format $fileinfo(mtime) -format {%b %e %H:%M}]

				switch -- $fileinfo(type) {
					"directory" {
						set typeid "d"
					}
					"blockSpecial" {
						set typeid "b"
					}
					"characterSpecial" {
						set typeid "c"
					}
					"file" {
						set typeid "-"
					}
					"socket" {
						set typeid "s"
					}
					default {
						set typeid "?"
					}
				}

				puts [format {%s%04o %5s %6s %6s %10s %12s %s} $typeid [expr {$fileinfo(mode) & 07777}] $fileinfo(nlink) $fileinfo(uid) $fileinfo(gid) $fileinfo(size) $date $node]

			} else {
				puts -nonewline "$node "
				set newline_required 1
			}
		}

		if {$newline_required} {
			puts ""
		}
	}

	proc ::modprobe args {
		::tuapi::modprobe {*}$args
	}

	proc ::ps {} {
		set format {%-6s %5s %5s %3s %5s %-6s %8s %s}
		puts [format $format UID PID PPID C STIME TTY TIME CMD]
		foreach pid [lsort -dictionary [glob -nocomplain -directory /proc -tails {[0-9]*}]] {
			if {![string is integer $pid]} {
				continue
			}

			set procfile [file join /proc $pid]

			unset -nocomplain pidinfo
			catch {
				file stat $procfile pidinfo
			}

			if {![info exists pidinfo]} {
				continue
			}

			set pidinfo(pid) $pid
			set pidinfo(ppid) ?
			set pidinfo(cpuutil) ?
			set pidinfo(starttime) ?
			set pidinfo(tty) ?
			set pidinfo(cputime) ?
			set pidinfo(cmd) ""

			unset -nocomplain fd
			catch {
				set fd [open [file join $procfile cmdline]]
			}
			if {[info exists fd]} {
				set pidinfo(cmd) [string trim [join [split [read $fd] "\0\n\r"]]]
				close $fd
				unset fd
			}
			if {![info exists pidinfo(cmd)] || $pidinfo(cmd) == ""} {
				catch {
					set fd [open [file join $procfile comm]]
				}
				if {[info exists fd]} {
					set pidinfo(cmd) "\[[string trim [join [split [read $fd] "\0\n\r"]]]\]"
					close $fd
				}
			}

			puts [format $format $pidinfo(uid) $pidinfo(pid) $pidinfo(ppid) $pidinfo(cpuutil) $pidinfo(starttime) $pidinfo(tty) $pidinfo(cputime) $pidinfo(cmd)]
		}
	}

	proc ::dmesg {} {
		puts [::tuapi::syscall::klogctl read]
	}

	proc ::ulimit {limit {val ""}} {
		set mapping(-c) [list CORE]
		set mapping(-d) [list DATA]
		set mapping(-e) [list NICE]
		set mapping(-f) [list FSIZE]
		set mapping(-i) [list SIGPENDING]
		set mapping(-l) [list MEMLOCK]
		set mapping(-m) [list RSS]
		set mapping(-n) [list NOFILE]
		set mapping(-q) [list MSGQUEUE]
		set mapping(-r) [list RTPRIO]
		set mapping(-s) [list STACK]
		set mapping(-t) [list CPU]
		set mapping(-u) [list NPROC]
		set mapping(-v) [list AS]
		set mapping(-x) [list LOCKS]
		set help(CORE) {core file size          (blocks, -c)}
		set help(DATA) {data seg size           (kbytes, -d)}
		set help(NICE) {scheduling priority             (-e)}
		set help(FSIZE) {file size               (blocks, -f)}
		set help(SIGPENDING) {pending signals                 (-i)}
		set help(MEMLOCK) {max locked memory       (kbytes, -l)}
		set help(RSS) {max memory size         (kbytes, -m)}
		set help(NOFILE) {open files                      (-n)}
		set help(-p) {pipe size            (512 bytes, -p)}
		set help(MSGQUEUE) {POSIX message queues     (bytes, -q)}
		set help(RTPRIO) {real-time priority              (-r)}
		set help(STACK) {stack size              (kbytes, -s)}
		set help(CPU) {cpu time               (seconds, -t)}
		set help(NPROC) {max user processes              (-u)}
		set help(AS) {virtual memory          (kbytes, -v)}
		set help(LOCKS) {file locks                      (-x)}

		foreach {limitopt limitoptvals} [array get mapping] {
			foreach limitoptval $limitoptvals {
				lappend mapping(-a) $limitoptval
			}
		}

		set opts $mapping($limit)

		if {[llength $opts] != 1 && $val != ""} {
			return -code error "Unable to set multiple limits"
		}

		foreach opt $opts {
			unset -nocomplain optval

			if {$val != ""} {
				catch {
					::tuapi::syscall::rlimit set $opt $val
				}
				set include_help ""
			} else {
				set include_help "$help($opt) "
			}

			catch {
				set optval [::tuapi::syscall::rlimit get $opt]
			}

			if {![info exists optval]} {
				continue
			}

			puts "${include_help}$optval"
		}
	}

	proc ::ifconfig {{ifacelist ""} {config ""}} {
		if {$ifacelist == "" || $ifacelist == "-a"} {
			set ifacelist [tuapi::syscall::ifconfig]
			set config ""
		}

		if {$config != ""} {
			if {[string match "*.*.*.*" [lindex $config 0]]} {
				set config [linsert $config 0 "address"]
			}

			puts [list ::tuapi::ifconfig [lindex $ifacelist 0] {*}$config]
			return [::tuapi::ifconfig [lindex $ifacelist 0] {*}$config]
		}

		foreach iface $ifacelist {
			unset -nocomplain ifaceinfo
			array set ifaceinfo [tuapi::syscall::ifconfig $iface]

			set secondline ""
			foreach {label entry} [list inet address netmask netmask broadcast broadcast] {
				if {![info exists ifaceinfo($entry)]} {
					continue
				}

				append secondline " $label $ifaceinfo($entry)"
			}

			puts "$iface: flags=<[join $ifaceinfo(flags) ,]> mtu $ifaceinfo(mtu) index $ifaceinfo(index)"
			puts "\t[string trim $secondline]"
			if {[info exists ifaceinfo(hwaddr)]} {
				puts "\tether $ifaceinfo(hwaddr)"
			}
		}
	}
}
