#! /usr/bin/env tclsh

puts [exec ./build-dyn.sh]

load ./tuapi.so

#puts [::tuapi::scan_and_load_kernel_modules]

#foreach x [list AS CORE CPU DATA FSIZE LOCKS MEMLOCK MSGQUEUE NICE NOFILE OFILE NPROC RSS RTPRIO RTTIME SIGPENDING STACK] {
#	puts "\t\tcase [format 0x%xLU [::tuapi::internal::hash $x]]: /* $x */"
#	puts "\t\t\tresource_id = RLIMIT_$x;"
#	puts "\t\t\tbreak;"
#}
#exit

foreach iface [tuapi::syscall::ifconfig] {
#lo0:2: flags=2001000849<UP,LOOPBACK,RUNNING,MULTICAST,IPv4,VIRTUAL> mtu 8232 index 1
#        inet 127.0.0.1 netmask ff000000 
#aggr100003:1: flags=201000843<UP,BROADCAST,RUNNING,MULTICAST,IPv4,CoS> mtu 1500 index 2
#        inet 140.194.100.149 netmask ffffff00 broadcast 140.194.100.255

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

#tuapi::syscall::route add 1.2.3.4 255.255.255.255
#tuapi::syscall::ifconfig dummy0 address 1.2.3.4 netmask 255.255.255.0 flags [list UP RUNNING BROADCAST MULTICAST]
