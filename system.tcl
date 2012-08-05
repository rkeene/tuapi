#! /usr/bin/env tclsh

namespace eval ::system {}
namespace eval ::system::helper {}

set ::system::_mount_flags(bind) BIND
set ::system::_mount_flags(move) MOVE
set ::system::_mount_flags(remount) REMOUNT
set ::system::_mount_flags(mandlock) MANDLOCK
set ::system::_mount_flags(dirsync) DIRSYNC
set ::system::_mount_flags(noatime) NOATIME
set ::system::_mount_flags(nodiratime) NODIRATIME
set ::system::_mount_flags(relatime) RELATIME
set ::system::_mount_flags(strictatime) STRICTATIME
set ::system::_mount_flags(nodev) NODEV
set ::system::_mount_flags(noexec) NOEXEC
set ::system::_mount_flags(nosuid) NOSUID
set ::system::_mount_flags(ro) RDONLY
set ::system::_mount_flags(silent) SILENT
set ::system::_mount_flags(synchronous) SYNCHRONOUS
set ::system::_mount_flags(sync) SYNCHRONOUS


# Determine where to mount a given device (usually by checking "/etc/fstab")
proc ::system::helper::find_mountpoint {device} {
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

proc ::system::mount args {
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
		return -code error "wrong # args: should be \"::system::mount ?options? source ?target?\""
	}

	set source [lindex $args 0]

	if {[llength $args] == 2} {
		set target [lindex $args 1]
	} else {
		array set mountinfo [::system::helper::find_mountpoint $source]
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
		if {[info exists ::system::_mount_flags($option_lc)]} {
			lappend options_list $::system::_mount_flags($option_lc)

			continue
		}

		# Example: atime
		if {[info exists ::system::_mount_flags(no$option_lc)]} {
			set idx [lsearch -exact $options_list $::system::_mount_flags(no$option_lc)]
			if {$idx != -1} {
				set options_list [lreplace $options_list $idx $idx]
			}

			continue
		}

		# Example: norelatime
		if {[string match "no*" $option_lc]} {
			set neg_option_lc [string range $option_lc 2 end]

			if {[info exists ::system::_mount_flags($neg_option_lc)]} {
				set idx [lsearch -exact $options_list $::system::_mount_flags($neg_option_lc)]
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
		return [::system::syscall::swapon $source]
	}

	# Otherwise, call "mount" system call
	## If we have accumulated any unknown options, pass them as a
	## comma-seperated value string
	if {[info exists unknown_options]} {
		set data [join $unknown_options ","]

		return [::system::syscall::mount $source $target $fstype $options_list $data]
	}

	return [::system::syscall::mount $source $target $fstype $options_list]
}

proc ::system::umount {dir {flags ""}} {
	return [::system::syscall::umount $dir [string toupper $flags]]
}

proc ::system::kill {pid sig} {
	return [::system::syscall::kill $pid [string toupper $sig]]
}

proc ::system::killpg {pgroup sig} {
	if {$pgroup <= 1} {
		return -code error "invalid process group specified (must be greater than 1)"
	}

	return [::system::syscall::kill -$pgroup [string toupper $sig]]
}

proc ::system::ifconfig args {
	if {[llength $args] == 0} {
		# Return information on all interfaces
		set retlist [list]
		foreach interface [::system::syscall::ifconfig] {
			lappend retlist $interface [::system::syscall::ifconfig $interface]
		}

		return $retlist
	}

	set interface [lindex $args 0]
	set args [lrange $args 1 end]

	array set ifaceinfo [::system::syscall::ifconfig $interface]

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

				foreach newflag [list UP RUNNING] {
					if {[lsearch -exact $flags $newflag] == -1} {
						lappend flags $newflag
					}
				}

				::system::syscall::ifconfig $interface flags $flags
			}

		}
	}
}
