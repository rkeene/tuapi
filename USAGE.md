Tcl UNIX API
============

Linux only, currently.


package require tuapi 0.6

High-level Interfaces
---------------------
	::tuapi::mount
	::tuapi::umount
	::tuapi::kill
	::tuapi::killpg
	::tuapi::ifconfig
	::tuapi::modprobe
	::tuapi::scan_and_load_kernel_modules

Low-level Interfaces (Linux)
----------------------------
	::tuapi::syscall::insmod <filename> ?<args>?
	::tuapi::syscall::rmmod <module>...
	::tuapi::syscall::lsmod (not implemented)
	::tuapi::syscall::hostname ?<hostname>?
	::tuapi::syscall::domainname (not implemented)
	::tuapi::syscall::klogctl {read|clear|console_on|console_off}
	::tuapi::syscall::settimeofday <seconds> <microseconds>
	::tuapi::syscall::losetup <loopdev> <file>
	::tuapi::syscall::eject (not implemented)
	::tuapi::syscall::mount <source> <target> <fstype> <listOfFlags> ?<data>?
	::tuapi::syscall::umount <directory> ?<flags>?
	::tuapi::syscall::swapon <file>
	::tuapi::syscall::swapoff <file>
	::tuapi::syscall::mknod (not implemented)
	::tuapi::syscall::getuid (not implemented)
	::tuapi::syscall::chroot <path>
	::tuapi::syscall::pivot_root <newRoot> <putOld>
	::tuapi::syscall::kill <pid> <signal>
	::tuapi::syscall::waitpid
	::tuapi::syscall::ps (not implemented)
	::tuapi::syscall::execve <file> <args>...
	::tuapi::syscall::rlimit get {AS|CORE|DATA|FSIZE|LOCKS|MEMLOCK|MSGQUEUE|NICE|NOFILE|NPROC|RSS|RTPRIO|RTTIME|SIGPENDING|STACK}
	::tuapi::syscall::rlimit set {AS|CORE|DATA|FSIZE|LOCKS|MEMLOCK|MSGQUEUE|NICE|NOFILE|NPROC|RSS|RTPRIO|RTTIME|SIGPENDING|STACK} <value>
	::tuapi::syscall::rlimit set {AS|CORE|DATA|FSIZE|LOCKS|MEMLOCK|MSGQUEUE|NICE|NOFILE|NPROC|RSS|RTPRIO|RTTIME|SIGPENDING|STACK} soft <value> hard <value>
	::tuapi::syscall::reboot {DISABLE_CAD|ENABLE_CAD|HALT|POWEROFF|RESTART}
	::tuapi::syscall::ifconfig
	::tuapi::syscall::ifconfig <interface>
	::tuapi::syscall::ifconfig <interface> <flags>...
	::tuapi::syscall::route (not implemented)
	::tuapi::syscall::route {add|del} <destination> <netmask> ?<flags>?
	::tuapi::syscall::brctl (not implemented)
	::tuapi::syscall::brctl addbr <bridge>
	::tuapi::syscall::brctl delbr <bridge>
	::tuapi::syscall::brctl addif <bridge> <interface>
	::tuapi::syscall::brctl delif <bridge> <interface>
	::tuapi::syscall::vconfig (not implemented)
	::tuapi::syscall::stty
		Only: size, -raw, raw, -echo, echo
	::tuapi::syscall::socket_unix <path>
	::tuapi::syscall::socket_unix -server <command> <path>
	::tuapi::syscall::tsmf_start_svc <sri> <filenameToExecute> <logfile> <envList> <directoryToStartIn> <umask> <uid> <gid> <timeout>
