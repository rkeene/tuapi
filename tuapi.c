#define _LINUX_SOURCE 1
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/termios.h>
#include <netinet/in.h>
#include <sys/reboot.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/klog.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <tcl.h>

#include <linux/sockios.h>
#include <linux/route.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/loop.h>
#include <linux/fs.h>

#ifndef HOST_NAME_MAX
/* SUSv2 Limit */
#define HOST_NAME_MAX 255
#endif

/* From Linux 2.6 */
#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif
#ifndef MNT_EXPIRE
#define MNT_EXPIRE 4
#endif
#ifndef MS_MOVE
#define MS_MOVE 8192
#endif
#ifndef SYSLOG_ACTION_CLOSE
#define SYSLOG_ACTION_CLOSE 0
#endif
#ifndef SYSLOG_ACTION_OPEN
#define SYSLOG_ACTION_OPEN 1
#endif
#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#endif
#ifndef SYSLOG_ACTION_CLEAR
#define SYSLOG_ACTION_CLEAR 5
#endif
#ifndef SYSLOG_ACTION_CONSOLE_OFF
#define SYSLOG_ACTION_CONSOLE_OFF 6
#endif
#ifndef SYSLOG_ACTION_CONSOLE_ON
#define SYSLOG_ACTION_CONSOLE_ON 7
#endif

/* Simple macros */
#ifndef MAX
#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* User environment, for execve */
extern char **environ;

/* Re-implement these if needed */
#ifdef SYS_init_module
static int init_module(void *val, unsigned long len, const char *args) {
	return(syscall(SYS_init_module, val, len, args));
}
#endif
#ifdef SYS_delete_module
static int delete_module(const char *name, int flags) {
	return(syscall(SYS_delete_module, name, flags));
}
#endif
#ifdef SYS_pivot_root
static int pivot_root(const char *new_root, const char *put_old) {
	return(syscall(SYS_pivot_root, new_root, put_old));
}
#endif

/*
 * Simple hash routine to enable switching on a string to be implemented
 */
static unsigned long tuapi_internal_simplehash(const void *databuf, int datalen) {
	unsigned long retval = 0;
	const unsigned char *data;

	data = databuf;

	for (; datalen > 0; datalen--,data++) {
		retval ^= (retval >> 25) & 0x7F;
		retval <<= 7;
		retval &= (0xFFFFFFFFUL);
		retval ^= *data;
	}

	return(retval);
}

static unsigned long tuapi_internal_simplehash_obj(Tcl_Obj *tcl_data) {
	unsigned long retval;
	char *data;
	int datalen = -1;

	data = Tcl_GetStringFromObj(tcl_data, &datalen);

	retval = tuapi_internal_simplehash(data, datalen);

	return(retval);
}

#if 0
/* NOTUSED: Uncomment when needed: */
static unsigned long tuapi_internal_simplehash_str(const char *data) {
	unsigned long retval;
	int datalen;

	datalen = strlen(data);

	retval = tuapi_internal_simplehash(data, datalen);

	return(retval);
}
#endif

static int tuapi_internalproc_simplehash(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	unsigned long hashval;
	Tcl_Obj *hashval_obj;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::internal::hash value\"", -1));

		return(TCL_ERROR);
	}

	hashval = tuapi_internal_simplehash_obj(objv[1]);

	hashval_obj = Tcl_NewObj();
	Tcl_SetWideIntObj(hashval_obj, hashval);

	Tcl_SetObjResult(interp, hashval_obj);

	return(TCL_OK);
}

static int tuapi_internal_getsock(int *sock_v4_out, int *sock_v6_out) {
	int sock_v4 = -1, sock_v6 = -1;
	int sock;

	if (sock_v4_out == NULL && sock_v6_out == NULL) {
		return(-1);
	}

	if (sock_v4_out != NULL) {
		/*
		 * Check for IPv4 support before trying to create an IPv4 socket to
		 * avoid demand-loading IPv4 (XXX: TODO)
		 */
		sock_v4 = socket(AF_INET, SOCK_DGRAM, 0);
	}

	if (sock_v6_out != NULL) {
		/*
		 * Check for IPv6 support before trying to create an IPv6 socket to
		 * avoid demand-loading IPv6 (XXX: TODO)
		 */
		sock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
	}

	/* Pick a socket to query for the interface list */
	if (sock_v4 == -1 && sock_v6 == -1) {
		return(-1);
	}

	if (sock_v6 != -1) {
		sock = sock_v6;
	} else {
		sock = sock_v4;
	}

	if (sock_v4_out != NULL) {
		*sock_v4_out = sock_v4;
	}

	if (sock_v6_out != NULL) {
		*sock_v6_out = sock_v6;
	}

	return(sock);
}

/*
 * Low-level System Call Wrapper Procedures
 *
 * These procedures should minimally wrap Linux or UNIX system calls to
 * expose to the Tcl-level.  Where possible accept symbolic names rather
 * than numeric values (.e.g, list of values to OR together to get flags).
 */
static int tuapi_mount(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *mountflags_obj, **mountflags_list, *mountflag;
	int mountflags_list_len;
	char *source, *target, *fstype;
	unsigned long mountflags = 0;
	void *data = NULL;
	int mount_ret, tcl_ret;

	if (objc < 5 || objc > 6) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::mount source target fstype mountflags ?data?\"", -1));

		return(TCL_ERROR);
	}

	source = Tcl_GetString(objv[1]);
	target = Tcl_GetString(objv[2]);
	fstype = Tcl_GetString(objv[3]);
	mountflags_obj = objv[4];

	if (objc == 6) {
		data = Tcl_GetString(objv[5]);
	}

	tcl_ret = Tcl_ListObjGetElements(interp, mountflags_obj, &mountflags_list_len, &mountflags_list);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	for (; mountflags_list_len > 0; mountflags_list_len--,mountflags_list++) {
		mountflag = mountflags_list[0];

		switch (tuapi_internal_simplehash_obj(mountflag)) {
#ifdef MS_BIND
			case 0x8526744: /* BIND */
				mountflags |= MS_BIND;
				break;
#endif
#ifdef MS_DIRSYNC
			case 0x2aff41c3: /* DIRSYNC */
				mountflags |= MS_DIRSYNC;
				break;
#endif
#ifdef MS_MANDLOCK
			case 0x410dbcb: /* MANDLOCK */
				mountflags |= MS_MANDLOCK;
				break;
#endif
#ifdef MS_MOVE
			case 0x9b3eb45: /* MOVE */
				mountflags |= MS_MOVE;
				break;
#endif
#ifdef MS_NOATIME
			case 0x1a0f58c5: /* NOATIME */
				mountflags |= MS_NOATIME;
				break;
#endif
#ifdef MS_NODEV
			case 0xe9f120d6: /* NODEV */
				mountflags |= MS_NODEV;
				break;
#endif
#ifdef MS_NODIRATIME
			case 0xde08ff45: /* NODIRATIME */
				mountflags |= MS_NODIRATIME;
				break;
#endif
#ifdef MS_NOEXEC
			case 0xf8b718c3: /* NOEXEC */
				mountflags |= MS_NOEXEC;
				break;
#endif
#ifdef MS_NOSUID
			case 0xfa745ec4: /* NOSUID */
				mountflags |= MS_NOSUID;
				break;
#endif
#ifdef MS_RDONLY
			case 0x49f2ec59: /* RDONLY */
				mountflags |= MS_RDONLY;
				break;
#endif
#ifdef MS_RELATIME
			case 0x481954c5: /* RELATIME */
				mountflags |= MS_RELATIME;
				break;
#endif
#ifdef MS_REMOUNT
			case 0xd9507154: /* REMOUNT */
				mountflags |= MS_REMOUNT;
				break;
#endif
#ifdef MS_SILENT
			case 0x99902954: /* SILENT */
				mountflags |= MS_SILENT;
				break;
#endif
#ifdef MS_STRICTATIME
			case 0x562fa045: /* STRICTATIME */
				mountflags |= MS_STRICTATIME;
				break;
#endif
#ifdef MS_SYNCHRONOUS
			case 0xbf799353: /* SYNCHRONOUS */
			case 0xa766743: /* SYNC */
				mountflags |= MS_SYNCHRONOUS;
				break;
#endif
			default:
				Tcl_SetObjResult(interp, Tcl_ObjPrintf("unknown element in mountflags: \"%s\"", Tcl_GetString(mountflag)));

				return(TCL_ERROR);
		}
	}

	mount_ret = mount(source, target, fstype, mountflags, data);
	if (mount_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj(target, -1));

	return(TCL_OK);
}

static int tuapi_umount(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj **flags, *flag;
	Tcl_Obj *pathname_obj;
	char *pathname;
	int umount2_flags = 0;
	int flags_cnt;
	int chk_ret, tcl_ret;

	if (objc < 2 || objc > 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"tuapi::syscall::umount dir ?flags?\"", -1));

		return(TCL_ERROR);
	}

	pathname_obj = objv[1];
	pathname = Tcl_GetString(pathname_obj);

	/* Set a default return value */
	Tcl_SetObjResult(interp, pathname_obj);

	if (objc == 3) {
		tcl_ret = Tcl_ListObjGetElements(interp, objv[2], &flags_cnt, &flags);
		if (tcl_ret != TCL_OK) {
			return(tcl_ret);
		}

		for (; flags_cnt > 0; flags_cnt--,flags++) {
			flag = flags[0];

			switch (tuapi_internal_simplehash_obj(flag)) {
				case 0x69f4a3c5: /* FORCE */
					umount2_flags |= MNT_FORCE;

					break;
				case 0x5a9173c8: /* DETACH */
					umount2_flags |= MNT_DETACH;

					break;
				case 0x8a137fc5: /* EXPIRE */
					umount2_flags |= MNT_EXPIRE;

					break;
				default:
					Tcl_SetObjResult(interp, Tcl_ObjPrintf("unknown flag \"%s\" specified", Tcl_GetString(flag)));
	
					return(TCL_ERROR);
			}
		}

		chk_ret = umount2(pathname, umount2_flags);

		/* Do not return an error for this case, since it is apparently not exceptional */
		if (chk_ret != 0 && (umount2_flags & MNT_EXPIRE) == MNT_EXPIRE && errno == EAGAIN) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("AGAIN", -1));

			chk_ret = 0;
		}
	} else {
		chk_ret = umount(pathname);
	}

	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_swapon(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *pathname;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"tuapi::syscall::swapon pathname\"", -1));

		return(TCL_ERROR);
	}

	pathname = Tcl_GetString(objv[1]);

	chk_ret = swapon(pathname, 0);
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_swapoff(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *pathname;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"tuapi::syscall::swapoff pathname\"", -1));

		return(TCL_ERROR);
	}

	pathname = Tcl_GetString(objv[1]);

	chk_ret = swapoff(pathname);
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_insmod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Channel fd;
	Tcl_Obj *module_filename, *module_data;
	void *module_data_val;
	const char *module_opts;
	int module_data_len;
	int read_ret, chk_ret;

	if (objc < 2 || objc > 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"tuapi::syscall::insmod filename ?args?\"", -1));

		return(TCL_ERROR);
	}

	module_filename = objv[1];

	fd = Tcl_FSOpenFileChannel(interp, module_filename, "r", 0600);
	if (fd == NULL) {
		return(TCL_ERROR);
	}

	chk_ret = Tcl_SetChannelOption(interp, fd, "-translation", "binary");
	if (chk_ret != TCL_OK) {
		Tcl_Close(interp, fd);

		return(chk_ret);
	}

	module_data = Tcl_NewObj();

	read_ret = Tcl_ReadChars(fd, module_data, -1, 0);

	Tcl_Close(interp, fd);

	if (read_ret <= 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("read failed", -1));

		return(TCL_ERROR);
	}

	module_data_val = Tcl_GetByteArrayFromObj(module_data, &module_data_len);

	if (objc == 3) {
		module_opts = Tcl_GetString(objv[2]);
	} else {
		module_opts = "";
	}

	chk_ret = init_module(module_data_val, module_data_len, module_opts);
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_rmmod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *module;
	int idx;
	int delete_module_ret;

	if (objc < 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"tuapi::syscall::rmmod module ?module...?", -1));

		return(TCL_ERROR);
	}

	for (idx = 1; idx < objc; idx++) {
		module = Tcl_GetString(objv[idx]);

		delete_module_ret = delete_module(module, O_NONBLOCK);
		if (delete_module_ret != 0) {
			Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to remove \"%s\": %s", module, strerror(errno)));

			return(TCL_ERROR);
		}
	}

	return(TCL_OK);
}

static int tuapi_lsmod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_hostname(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char hostname[HOST_NAME_MAX + 1];
	int chk_ret;

	if (objc == 1) {
		/* No arguments given, just return the hostname */
		chk_ret = gethostname(hostname, sizeof(hostname));
		if (chk_ret != 0) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

			return(TCL_ERROR);
		}

		hostname[sizeof(hostname) - 1] = '\0';

		Tcl_SetObjResult(interp, Tcl_NewStringObj(hostname, -1));

		return(TCL_OK);
	}

	if (objc == 2) {
		/* Exactly one argument given, set the hostname */
		strncpy(hostname, Tcl_GetString(objv[1]), sizeof(hostname));
		hostname[sizeof(hostname) - 1] = '\0';

		chk_ret = sethostname(hostname, strlen(hostname));
		if (chk_ret != 0) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

			return(TCL_ERROR);
		}

		Tcl_SetObjResult(interp, Tcl_NewStringObj(hostname, -1));

		return(TCL_OK);
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"hostname ?hostname?\"", -1));

	return(TCL_ERROR);
}

static int tuapi_domainname(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_chroot(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *pathname;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall:chroot pathname\"", -1));

		return(TCL_ERROR);
	}

	pathname = Tcl_GetString(objv[1]);

	chk_ret = chroot(pathname);
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_pivot_root(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *new_root, *put_old;
	int chk_ret;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::pivot_root new_root put_old\"", -1));

		return(TCL_ERROR);
	}

	new_root = Tcl_GetString(objv[1]);
	put_old = Tcl_GetString(objv[2]);

	chk_ret = pivot_root(new_root, put_old);
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_mknod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_setuid(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_WideInt tclUid;
	uid_t uid;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::setuid uid\"", -1));
	}

	chk_ret = Tcl_GetWideIntFromObj(interp, objv[1], &tclUid);
	if (chk_ret != TCL_OK) {
		return(chk_ret);
	}

	uid = tclUid;

	chk_ret = setuid(uid);
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("setuid failed", -1));

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj("", -1));

	return(TCL_OK);
}

static int tuapi_getuid(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	uid_t uid;
	Tcl_WideInt tclUid;

	if (objc != 1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::getuid\"", -1));

		return(TCL_ERROR);
	}

	uid = getuid();
	tclUid = uid;

	Tcl_SetObjResult(interp, Tcl_NewWideIntObj(tclUid));

	return(TCL_OK);
}

static int tuapi_kill(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *signal_obj;

	Tcl_WideInt pid_wide, sig_wide;
	pid_t pid;
	int sig;
	int kill_ret, tcl_ret;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::kill pid sig\"", -1));

		return(TCL_ERROR);
	}

	tcl_ret = Tcl_GetWideIntFromObj(interp, objv[1], &pid_wide);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}
	pid = pid_wide;

	signal_obj = objv[2];

	tcl_ret = Tcl_GetWideIntFromObj(interp, signal_obj, &sig_wide);
	if (tcl_ret != TCL_OK) {
		switch (tuapi_internal_simplehash_obj(signal_obj)) {
			case 0x122ad0: /* HUP */
			case 0x98f364d0: /* SIGHUP */
				sig = SIGHUP;
				break;
			case 0x126754: /* INT */
			case 0x98f32954: /* SIGINT */
				sig = SIGINT;
				break;
			case 0xa3564d4: /* QUIT */
			case 0x7a9242d4: /* SIGQUIT */
				sig = SIGQUIT;
				break;
			case 0x12664c: /* ILL */
			case 0x98f3284c: /* SIGILL */
				sig = SIGILL;
				break;
			case 0xa94a0d0: /* TRAP */
			case 0x7a3386d0: /* SIGTRAP */
				sig = SIGTRAP;
				break;
			case 0x830a954: /* ABRT */
			case 0x78978f54: /* SIGABRT */
				sig = SIGABRT;
				break;
			case 0x1267d4: /* IOT */
			case 0x98f329d4: /* SIGIOT */
				sig = SIGIOT;
				break;
			case 0x10aad3: /* BUS */
			case 0x98f1e4d3: /* SIGBUS */
				sig = SIGBUS;
				break;
			case 0x11a845: /* FPE */
			case 0x98f0e645: /* SIGFPE */
				sig = SIGFPE;
				break;
			case 0x972664c: /* KILL */
			case 0x79d5404c: /* SIGKILL */
				sig = SIGKILL;
				break;
			case 0xab4e931: /* USR1 */
			case 0x7a13cf31: /* SIGUSR1 */
				sig = SIGUSR1;
				break;
			case 0xa7163d6: /* SEGV */
			case 0x7ad645d6: /* SIGSEGV */
				sig = SIGSEGV;
				break;
			case 0xab4e932: /* USR2 */
			case 0x7a13cf32: /* SIGUSR2 */
				sig = SIGUSR2;
				break;
			case 0xa126845: /* PIPE */
			case 0x7ab54e45: /* SIGPIPE */
				sig = SIGPIPE;
				break;
			case 0x833294d: /* ALRM */
			case 0x78940f4d: /* SIGALRM */
				sig = SIGALRM;
				break;
			case 0xa91694d: /* TERM */
			case 0x7a364f4d: /* SIGTERM */
				sig = SIGTERM;
				break;
			case 0x4970e8d4: /* STKFLT */
			case 0x80fefc54: /* SIGSTKFLT */
				sig = SIGSTKFLT;
				break;
			case 0x8722644: /* CHLD */
			case 0x78d50044: /* SIGCHLD */
				sig = SIGCHLD;
				break;
			case 0x873e754: /* CONT */
			case 0x78d4c154: /* SIGCONT */
				sig = SIGCONT;
				break;
			case 0xa7527d0: /* STOP */
			case 0x7ad201d0: /* SIGSTOP */
				sig = SIGSTOP;
				break;
			case 0xa94ea50: /* TSTP */
			case 0x7a33cc50: /* SIGTSTP */
				sig = SIGTSTP;
				break;
			case 0xa9524ce: /* TTIN */
			case 0x7a3202ce: /* SIGTTIN */
				sig = SIGTTIN;
				break;
			case 0xa9527d5: /* TTOU */
			case 0x7a3201d5: /* SIGTTOU */
				sig = SIGTTOU;
				break;
			case 0x156947: /* URG */
			case 0x98f42747: /* SIGURG */
				sig = SIGURG;
				break;
			case 0xb10e855: /* XCPU */
			case 0x7bb7ce55: /* SIGXCPU */
				sig = SIGXCPU;
				break;
			case 0xb11a9da: /* XFSZ */
			case 0x7bb68fda: /* SIGXFSZ */
				sig = SIGXFSZ;
				break;
			case 0x483273cd: /* VTALRM */
			case 0x81bc674d: /* SIGVTALRM */
				sig = SIGVTALRM;
				break;
			case 0xa14a7c6: /* PROF */
			case 0x7ab381c6: /* SIGPROF */
				sig = SIGPROF;
				break;
			case 0x7933a348: /* WINCH */
			case 0x2aa0bf48: /* SIGWINCH */
				sig = SIGWINCH;
				break;
			case 0x24cf: /* IO */
			case 0x3931e64f: /* SIGIO */
				sig = SIGIO;
				break;
			case 0x142bd2: /* PWR */
			case 0x98f565d2: /* SIGPWR */
				sig = SIGPWR;
				break;
			case 0x14ecd3: /* SYS */
			case 0x98f5a2d3: /* SIGSYS */
				sig = SIGSYS;
				break;
			default:
				Tcl_SetObjResult(interp, Tcl_ObjPrintf("unknown signal \"%s\"", Tcl_GetString(signal_obj)));

				return(TCL_ERROR);
		}
	} else {
		sig = sig_wide;
	}

	kill_ret = kill(pid, sig);
	if (kill_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_reboot(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *cmd_obj;
	int cmd;
	int reboot_ret;

	if (objc == 2) {
		cmd_obj = objv[1];

		switch (tuapi_internal_simplehash_obj(cmd_obj)) {
			case 0x2be1946: /* LINUX_REBOOT_CMD_CAD_OFF */
			case 0x666e6344: /* RB_DISABLE_CAD */
			case 0x9e3ce644: /* DISABLE_CAD */
				cmd = RB_DISABLE_CAD;

				break;
			case 0xe8057c4e: /* LINUX_REBOOT_CMD_CAD_ON */
			case 0xf8dc444: /* RB_ENABLE_CAD */
			case 0x1a7d6144: /* ENABLE_CAD */
				cmd = RB_ENABLE_CAD;

				break;
			case 0x95bfa454: /* LINUX_REBOOT_CMD_HALT */
			case 0x3210da4d: /* RB_HALT_SYSTEM */
			case 0xca425f4d: /* HALT_SYSTEM */
			case 0x9106654: /* HALT */
				cmd = RB_HALT_SYSTEM;

				break;
			case 0xdb55d8c6: /* LINUX_REBOOT_CMD_POWER_OFF */
			case 0xf07700c6: /* RB_POWER_OFF */
			case 0x645ce1c6: /* POWER_OFF */
				cmd = 0x4321fedc;

				break;
			case 0x73ff83d4: /* LINUX_REBOOT_CMD_RESTART */
			case 0x3cd0e254: /* RB_AUTOBOOT */
			case 0xb9f8b5d4: /* AUTOBOOT */
			case 0x3a357fd4: /* RESTART */
			case 0x5852add4: /* REBOOT */
				cmd = RB_AUTOBOOT;

				break;
			default:
				Tcl_SetObjResult(interp, Tcl_NewStringObj("unknown or ambiguous subcommand: must be DISABLE_CAD, ENABLE_CAD, HALT, POWER_OFF, or RESTART", -1));

				return(TCL_ERROR);
		}
	} else if (objc == 1) {
		cmd = RB_AUTOBOOT;
	} else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::reboot ?command?", -1));

		return(TCL_ERROR);
	}

	switch (cmd) {
		case RB_ENABLE_CAD:
		case RB_DISABLE_CAD:
			/* No need to sync for these operations */
			break;
		default:
			sync();
			break;
	}

	reboot_ret = reboot(cmd);
	if (reboot_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_set_thread_name(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *name;

	if (objc == 2) {
#ifdef PR_SET_NAME
		name = Tcl_GetString(objv[1]);
		prctl(PR_SET_NAME, (unsigned long) name, 0, 0, 0);
#else
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unsupported", -1));
		return(TCL_ERROR);
#endif
	} else {
#ifdef PR_GET_NAME
		name = malloc(17);

		prctl(PR_GET_NAME, (unsigned long) name, 0, 0, 0);

		Tcl_SetObjResult(interp, Tcl_NewStringObj(name, -1));

		free(name);
#else
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unsupported", -1));
		return(TCL_ERROR);
#endif
	}

	return(TCL_OK);
}

static int tuapi_eject(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_ps(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_execve(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char **argv = NULL;
	char *file;
	int idx;

	if (objc < 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::execve file ?args ...?\"", -1));

		return(TCL_ERROR);
	}

	/* Find executable */
	file = Tcl_GetString(objv[1]);

	/* Generate argument array */
	argv = malloc(sizeof(*argv) * (objc - 1));

	for (idx = 2; idx < objc; idx++) {
		argv[idx - 2] = Tcl_GetString(objv[idx]);
	}
	argv[objc - 2] = NULL;

	/* Pass execution to new file */
	execve(file, argv, environ);

	/* If the new image could not take over, something went wrong -- report error */
	Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

	return(TCL_ERROR);
}

static int tuapi_losetup(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *file, *loopdev;
	int chk_ret;
	int loopfd, filefd;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::losetup loopdev file\"", -1));

		return(TCL_ERROR);
	}

	loopdev = Tcl_GetString(objv[1]);
	file = Tcl_GetString(objv[2]);

	loopfd = open(loopdev, O_RDONLY);
	if (loopfd < 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	if (file[0] != '\0') {
		filefd = open(file, O_RDONLY);
		if (filefd < 0) {
			close(loopfd);

			Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

			return(TCL_ERROR);
		}

		chk_ret = ioctl(loopfd, LOOP_SET_FD, filefd);

		close(filefd);
	} else {
		chk_ret = ioctl(loopfd, LOOP_CLR_FD, 0);
	}

	close(loopfd);

	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static void tuapi_private_append_sockaddr_to_tclobj(Tcl_Interp *interp, Tcl_Obj *list, char *header, struct sockaddr *addr) {
	char addr_buf[INET6_ADDRSTRLEN + INET_ADDRSTRLEN + 1], *chk_inp;

	switch (addr->sa_family) {
		case AF_INET: /* IPv4 */
		case AF_INET6: /* IPv6 */
			switch (addr->sa_family) {
				case AF_INET: /* IPv4 */
					chk_inp = (char *) inet_ntop(addr->sa_family, &((struct sockaddr_in *) addr)->sin_addr, addr_buf, sizeof(addr_buf));
					break;
				case AF_INET6: /* IPv6 */
					chk_inp = (char *) inet_ntop(addr->sa_family, &((struct sockaddr_in6 *) addr)->sin6_addr, addr_buf, sizeof(addr_buf));
					break;
			}

			if (chk_inp == NULL) {
				break;
			}

			if (header) {
				Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(header, -1));
			}

			Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(addr_buf, -1));

			break;
	}

	return;
}

static int tuapi_private_get_sockaddr_from_obj(Tcl_Obj *value, void *target) {
	struct sockaddr_in local_v4;
	struct sockaddr_in6 local_v6;
	const char *addr_str;
	int inetpton_ret;

	addr_str = Tcl_GetString(value);

	memset(&local_v4, 0, sizeof(local_v4));
	inetpton_ret = inet_pton(AF_INET, addr_str, &local_v4.sin_addr);
	if (inetpton_ret == 1) {
		local_v4.sin_family = AF_INET;

		memcpy(target, &local_v4, sizeof(local_v4));

		return(0);
	}

	memset(&local_v6, 0, sizeof(local_v6));
	inetpton_ret = inet_pton(AF_INET6, addr_str, &local_v6.sin6_addr);
	if (inetpton_ret == 1) {
		local_v6.sin6_family = AF_INET6;

		memcpy(target, &local_v6, sizeof(local_v6));

		return(0);
	}

	return(-1);
}

static int tuapi_ifconfig_list(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock) {
	Tcl_Obj *tcl_iface_list;
	struct ifconf ifaces_cfg;
	struct ifreq *iface_req = NULL;
	int iface_req_cnt = 224, iface_req_len;
	int idx, iface_cnt;
	int ioctl_ret, tcl_ret;

	iface_req_len = iface_req_cnt * sizeof(*iface_req);
	iface_req = malloc(iface_req_len);
	if (iface_req == NULL) {
		/* Report failure */
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to allocate memory", -1));

		return(TCL_ERROR);
	}

	ifaces_cfg.ifc_req = iface_req;
	ifaces_cfg.ifc_len = iface_req_len;
	ioctl_ret = ioctl(sock, SIOCGIFCONF, &ifaces_cfg);
	if (ioctl_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("ioctl failed", -1));

		free(iface_req);

		return(TCL_ERROR);
	}

	iface_cnt = ifaces_cfg.ifc_len / sizeof(*iface_req);

	tcl_iface_list = Tcl_NewObj();

	for (idx = 0; idx < iface_cnt; idx++) {
		tcl_ret = Tcl_ListObjAppendElement(interp, tcl_iface_list, Tcl_NewStringObj(iface_req[idx].ifr_name, -1));
		if (tcl_ret != TCL_OK) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to append to list", -1));

			free(iface_req);

			return(TCL_ERROR);
		}
	}

	free(iface_req);

	Tcl_SetObjResult(interp, tcl_iface_list);

	return(TCL_OK);
}

static int tuapi_ifconfig_info(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock, int sock_v4, int sock_v6) {
	Tcl_Obj *retlist, *flags;
	struct ifreq iface_req;
	unsigned char *addr_data;
	const char *link_encap;
	const char *iface;
	int flags_bitmask, flag_broadcast = 0, flag_pointopoint = 0;
	int ioctl_ret;

	retlist = Tcl_NewObj();

	iface = Tcl_GetString(objv[1]);

	if ((strlen(iface) + 1) >= IFNAMSIZ) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("interface name too long", -1));

		return(TCL_ERROR);
	}

	strcpy(iface_req.ifr_name, iface);

	/*
	 * All interfaces should have flags, so use it as a check for interface
	 * existance
	 */
	ioctl_ret = ioctl(sock, SIOCGIFFLAGS, &iface_req);
	if (ioctl_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid interface", -1));

		return(TCL_ERROR);
	}

	/* Create list of flags */
	flags = Tcl_NewObj();
	flags_bitmask = iface_req.ifr_flags;

	if ((flags_bitmask & IFF_UP) == IFF_UP) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("UP", -1));
	}
	if ((flags_bitmask & IFF_BROADCAST) == IFF_BROADCAST) {
		flag_broadcast = 1;

		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("BROADCAST", -1));
	}
	if ((flags_bitmask & IFF_POINTOPOINT) == IFF_POINTOPOINT) {
		flag_pointopoint = 1;

		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("POINTOPOINT", -1));
	}
	if ((flags_bitmask & IFF_DEBUG) == IFF_DEBUG) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("DEBUG", -1));
	}
	if ((flags_bitmask & IFF_LOOPBACK) == IFF_LOOPBACK) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("LOOPBACK", -1));
	}
	if ((flags_bitmask & IFF_NOTRAILERS) == IFF_NOTRAILERS) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("NOTRAILERS", -1));
	}
	if ((flags_bitmask & IFF_RUNNING) == IFF_RUNNING) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("RUNNING", -1));
	}
	if ((flags_bitmask & IFF_NOARP) == IFF_NOARP) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("NOARP", -1));
	}
	if ((flags_bitmask & IFF_PROMISC) == IFF_PROMISC) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("PROMISC", -1));
	}
	if ((flags_bitmask & IFF_ALLMULTI) == IFF_ALLMULTI) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("ALLMULTI", -1));
	}
	if ((flags_bitmask & IFF_MASTER) == IFF_MASTER) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("MASTER", -1));
	}
	if ((flags_bitmask & IFF_SLAVE) == IFF_SLAVE) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("SLAVE", -1));
	}
	if ((flags_bitmask & IFF_MULTICAST) == IFF_MULTICAST) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("MULTICAST", -1));
	}
	if ((flags_bitmask & IFF_PORTSEL) == IFF_PORTSEL) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("PORTSEL", -1));
	}
	if ((flags_bitmask & IFF_AUTOMEDIA) == IFF_AUTOMEDIA) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("AUTOMEDIA", -1));
	}
	if ((flags_bitmask & IFF_DYNAMIC) == IFF_DYNAMIC) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("DYNAMIC", -1));
	}
	if ((flags_bitmask & IFF_LOWER_UP) == IFF_LOWER_UP) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("LOWER_UP", -1));
	}
	if ((flags_bitmask & IFF_DORMANT) == IFF_DORMANT) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("DORMANT", -1));
	}
#ifdef IFF_ECHO
	if ((flags_bitmask & IFF_ECHO) == IFF_ECHO) {
		Tcl_ListObjAppendElement(interp, flags, Tcl_NewStringObj("ECHO", -1));
	}
#endif

	/* Add array-compliant/dict entry to the return list */
	Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj("flags", -1));
	Tcl_ListObjAppendElement(interp, retlist, flags);

	/* Fetch other attributes from the interface */
	ioctl_ret = ioctl(sock, SIOCGIFHWADDR, &iface_req);
	if (ioctl_ret == 0) {
		link_encap = "unknown";

		addr_data = (unsigned char *) iface_req.ifr_hwaddr.sa_data;
		switch (iface_req.ifr_hwaddr.sa_family) {
			case ARPHRD_ETHER:
				link_encap = "ethernet";

				Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj("hwaddr", -1));
				Tcl_ListObjAppendElement(interp, retlist,
				  Tcl_ObjPrintf("%02x:%02x:%02x:%02x:%02x:%02x",
				    addr_data[0],
				    addr_data[1],
				    addr_data[2],
				    addr_data[3],
				    addr_data[4],
				    addr_data[5]
				  )
				);

				break;
			case ARPHRD_AX25:
				link_encap = "ax25";
				break;
			case ARPHRD_PRONET:
				link_encap = "pronet";
				break;
			case ARPHRD_CHAOS:
				link_encap = "chaos";
				break;
			case ARPHRD_IEEE802:
				link_encap = "ieee802";
				break;
			case ARPHRD_ARCNET:
				link_encap = "arcnet";
				break;
			case ARPHRD_APPLETLK:
				link_encap = "appletlk";
				break;
			case ARPHRD_DLCI:
				link_encap = "dlci";
				break;
			case ARPHRD_ATM:
				link_encap = "atm";
				break;
			case ARPHRD_METRICOM:
				link_encap = "metricom";
				break;
			case ARPHRD_IEEE1394:
				link_encap = "ieee1394";
				break;
			case ARPHRD_EUI64:
				link_encap = "eui64";
				break;
			case ARPHRD_INFINIBAND:
				link_encap = "infiniband";
				break;
			case ARPHRD_SLIP:
				link_encap = "slip";
				break;
			case ARPHRD_CSLIP:
				link_encap = "cslip";
				break;
			case ARPHRD_SLIP6:
				link_encap = "slip6";
				break;
			case ARPHRD_CSLIP6:
				link_encap = "cslip6";
				break;
			case ARPHRD_RSRVD:
				link_encap = "rsrvd";
				break;
			case ARPHRD_ADAPT:
				link_encap = "adapt";
				break;
			case ARPHRD_ROSE:
				link_encap = "rose";
				break;
			case ARPHRD_X25:
				link_encap = "x25";
				break;
			case ARPHRD_HWX25:
				link_encap = "hwx25";
				break;
#ifdef ARPHRD_CAN
			case ARPHRD_CAN:
				link_encap = "can";
				break;
#endif
			case ARPHRD_PPP:
				link_encap = "ppp";
				break;
			case ARPHRD_CISCO:
				link_encap = "cisco";
				break;
			case ARPHRD_LAPB:
				link_encap = "lapb";
				break;
			case ARPHRD_DDCMP:
				link_encap = "ddcmp";
				break;
			case ARPHRD_RAWHDLC:
				link_encap = "rawhdlc";
				break;
			case ARPHRD_TUNNEL:
				link_encap = "tunnel";
				break;
			case ARPHRD_TUNNEL6:
				link_encap = "tunnel6";
				break;
			case ARPHRD_FRAD:
				link_encap = "frad";
				break;
			case ARPHRD_SKIP:
				link_encap = "skip";
				break;
			case ARPHRD_LOOPBACK:
				link_encap = "loopback";
				break;
			case ARPHRD_LOCALTLK:
				link_encap = "localtalk";
				break;
			case ARPHRD_FDDI:
				link_encap = "fddi";
				break;
			case ARPHRD_BIF:
				link_encap = "bif";
				break;
			case ARPHRD_SIT:
				link_encap = "sit";
				break;
			case ARPHRD_IPDDP:
				link_encap = "ipddp";
				break;
			case ARPHRD_IPGRE:
				link_encap = "gre";
				break;
			case ARPHRD_PIMREG:
				link_encap = "pimreg";
				break;
			case ARPHRD_HIPPI:
				link_encap = "hippi";
				break;
			case ARPHRD_ASH:
				link_encap = "ash";
				break;
			case ARPHRD_ECONET:
				link_encap = "econet";
				break;
			case ARPHRD_IRDA:
				link_encap = "irda";
				break;
		}

		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj("link_encap", -1));
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj(link_encap, -1));
	}

	ioctl_ret = ioctl(sock, SIOCGIFMETRIC, &iface_req);
	if (ioctl_ret == 0) {
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj("metric", -1));
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewWideIntObj(iface_req.ifr_metric + 1));
	}

	ioctl_ret = ioctl(sock, SIOCGIFMTU, &iface_req);
	if (ioctl_ret == 0) {
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj("mtu", -1));
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewWideIntObj(iface_req.ifr_mtu));
	}

	ioctl_ret = ioctl(sock, SIOCGIFINDEX, &iface_req);
	if (ioctl_ret == 0) {
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewStringObj("index", -1));
		Tcl_ListObjAppendElement(interp, retlist, Tcl_NewWideIntObj(iface_req.ifr_ifindex));
	}

	if (sock_v4 != -1) {
		ioctl_ret = ioctl(sock_v4, SIOCGIFADDR, &iface_req);
		if (ioctl_ret == 0) {
			tuapi_private_append_sockaddr_to_tclobj(interp, retlist, "address", &iface_req.ifr_addr);
		}

		if (flag_pointopoint) {
			/* Point-to-Point interfaces */
			ioctl_ret = ioctl(sock_v4, SIOCGIFDSTADDR, &iface_req);
			if (ioctl_ret == 0) {
				tuapi_private_append_sockaddr_to_tclobj(interp, retlist, "destination", &iface_req.ifr_addr);
			}
		}

		if (flag_broadcast) {
			/* Broadcast interfaces */
			ioctl_ret = ioctl(sock_v4, SIOCGIFBRDADDR, &iface_req);
			if (ioctl_ret == 0) {
				tuapi_private_append_sockaddr_to_tclobj(interp, retlist, "broadcast", &iface_req.ifr_addr);
			}
		}

		ioctl_ret = ioctl(sock_v4, SIOCGIFNETMASK, &iface_req);
		if (ioctl_ret == 0) {
			tuapi_private_append_sockaddr_to_tclobj(interp, retlist, "netmask", &iface_req.ifr_addr);
		}
	}

	Tcl_SetObjResult(interp, retlist);

	return(TCL_OK);
}

static int tuapi_ifconfig_conf(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock, int sock_v4, int sock_v6) {
	Tcl_Obj *option_name_obj, *option_val_obj;
	Tcl_Obj **flags_objv;
	Tcl_WideInt option_val_wide;
	struct ifreq iface_req;
	struct sockaddr *tmp_ioctl_addr;
	const char *iface;
	short flags;
	int flags_objc;
	int tmp_sock, tmp_ioctl;
	int ioctl_ret, tcl_ret, parse_ret;

	iface = Tcl_GetString(objv[1]);

	if ((strlen(iface) + 1) >= IFNAMSIZ) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("interface name too long", -1));

		return(TCL_ERROR);
	}

	objc -= 2;
	objv += 2;

	for (; objc > 0; objc--,objv++) {
		/* Prepare for an ioctl() */
		memset(&iface_req, 0, sizeof(iface_req));
		strcpy(iface_req.ifr_name, iface);
		tmp_ioctl = -1;

		option_name_obj = objv[0];

		if (objc == 1) {
			Tcl_SetObjResult(interp, Tcl_ObjPrintf("option \"%s\" requires an argument", Tcl_GetString(option_name_obj)));

			return(TCL_ERROR);
		}

		objc--;
		objv++;

		option_val_obj = objv[0];

		switch (tuapi_internal_simplehash_obj(option_name_obj)) {
			case 0x6d9870f3: /* flags */
				flags = 0;

				tcl_ret = Tcl_ListObjGetElements(interp, option_val_obj, &flags_objc, &flags_objv);
				if (tcl_ret != TCL_OK) {
					return(tcl_ret);
				}

				for (; flags_objc > 0; flags_objc--,flags_objv++) {
					switch (tuapi_internal_simplehash_obj(flags_objv[0])) {
						case 0x2ad0: /* UP */
							flags |= IFF_UP;
							break;
						case 0x1aef7f54: /* BROADCAST */
							flags |= IFF_BROADCAST;
							break;
						case 0xc252abd4: /* POINTOPOINT */
							flags |= IFF_POINTOPOINT;
							break;
						case 0x48b0a8c7: /* DEBUG */
							flags |= IFF_DEBUG;
							break;
						case 0x4d3dbcd3: /* NOTRAILERS */
							flags |= IFF_NOTRAILERS;
							break;
						case 0xe9773147: /* RUNNING */
							flags |= IFF_RUNNING;
							break;
						case 0xe9f06b50: /* NOARP */
							flags |= IFF_NOARP;
							break;
						case 0xf91323c3: /* PROMISC */
							flags |= IFF_PROMISC;
							break;
						case 0x9b2a1849: /* ALLMULTI */
							flags |= IFF_ALLMULTI;
							break;
						case 0x1a7414d2: /* MASTER */
							flags |= IFF_MASTER;
							break;
						case 0x399069c5: /* SLAVE */
							flags |= IFF_SLAVE;
							break;
						case 0x4de928d4: /* MULTICAST */
							flags |= IFF_MULTICAST;
							break;
						case 0x2a35dc4c: /* PORTSEL */
							flags |= IFF_PORTSEL;
							break;
						case 0xd180ac1: /* AUTOMEDIA */
							flags |= IFF_AUTOMEDIA;
							break;
						case 0xe8ba02c3: /* DYNAMIC */
							flags |= IFF_DYNAMIC;
							break;
						case 0x16c8b4d0: /* LOWER_UP */
							flags |= IFF_LOWER_UP;
							break;
						case 0x293959d4: /* DORMANT */
							flags |= IFF_DORMANT;
							break;
#ifdef IFF_ECHO
						case 0x8b0e44f: /* ECHO */
							flags |= IFF_ECHO;
							break;
#endif
					}
				}

				iface_req.ifr_flags = flags;

				ioctl_ret = ioctl(sock, SIOCSIFFLAGS, &iface_req);
				if (ioctl_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

					return(TCL_ERROR);
				}

				break;
			case 0x5e9d03e3: /* metric */
			case 0x7c3891f2: /* hwaddr */
			case 0xbf72a969: /* addmulti */
			case 0xba708969: /* delmulti */
			case 0xdd876e5: /* name */
					Tcl_SetObjResult(interp, Tcl_ObjPrintf("option \"%s\" unsupported", Tcl_GetString(option_name_obj)));

					return(TCL_ERROR);
				break;
			case 0x1b7a75: /* mtu */
				tcl_ret = Tcl_GetWideIntFromObj(interp, option_val_obj, &option_val_wide);
				if (tcl_ret != TCL_OK) {
					return(tcl_ret);
				}

				iface_req.ifr_mtu = option_val_wide;

				ioctl_ret = ioctl(sock, SIOCSIFMTU, &iface_req);
				if (ioctl_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

					return(TCL_ERROR);
				}

				break;
			case 0x4e9aeaf3: /* address */
				if (tmp_ioctl == -1) {
					tmp_ioctl = SIOCSIFADDR;
					tmp_ioctl_addr = &iface_req.ifr_addr;
				}

			case 0xec05706e: /* destination */
				if (tmp_ioctl == -1) {
					tmp_ioctl = SIOCSIFDSTADDR;
					tmp_ioctl_addr = &iface_req.ifr_dstaddr;
				}

			case 0x3ea7e674: /* broadcast */
				if (tmp_ioctl == -1) {
					tmp_ioctl = SIOCSIFBRDADDR;
					tmp_ioctl_addr = &iface_req.ifr_broadaddr;
				}

			case 0x4d65ee6b: /* netmask */
				if (tmp_ioctl == -1) {
					tmp_ioctl = SIOCSIFNETMASK;
					tmp_ioctl_addr = &iface_req.ifr_netmask;
				}

				parse_ret = tuapi_private_get_sockaddr_from_obj(option_val_obj, tmp_ioctl_addr);
				if (parse_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to parse \"%s\" as an address", Tcl_GetString(option_val_obj)));

					return(TCL_ERROR);
				}

				switch (tmp_ioctl_addr->sa_family) {
					case AF_INET:
						tmp_sock = sock_v4;

						break;
					case AF_INET6:
						tmp_sock = sock_v6;

						break;
					default:
						Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to determine address family of sockaddr", -1));
						return(TCL_ERROR);
				}

				ioctl_ret = ioctl(tmp_sock, tmp_ioctl, &iface_req);
				if (ioctl_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

					return(TCL_ERROR);
				}

				break;
			default:
				Tcl_SetObjResult(interp, Tcl_ObjPrintf("unknown option \"%s\"", Tcl_GetString(option_name_obj)));

				return(TCL_ERROR);
		}
	}

	return(TCL_OK);
}

static int tuapi_ifconfig(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	int sock_v4, sock_v6, sock;
	int retval = TCL_ERROR;

	sock = tuapi_internal_getsock(&sock_v4, &sock_v6);
	if (sock == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create socket", -1));

		return(TCL_ERROR);
	}

	switch (objc) {
		case 0:
		case 1: /* No arguments, list all interfaces */
			retval = tuapi_ifconfig_list(cd, interp, objc, objv, sock);

			break;
		case 2: /* One argument, give information about the interface */
			retval = tuapi_ifconfig_info(cd, interp, objc, objv, sock, sock_v4, sock_v6);

			break;
		default:
			/* Otherwise, configure the interace */
			retval = tuapi_ifconfig_conf(cd, interp, objc, objv, sock, sock_v4, sock_v6);

			break;
	}

	/* Cleanup */
	if (sock_v4 != -1) {
		close(sock_v4);
	}

	if (sock_v6 != -1) {
		close(sock_v6);
	}

	return(retval);
}

static int tuapi_route_list(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock_v4, int sock_v6) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_route_conf(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock_v4, int sock_v6) {
	Tcl_WideInt option_val_wide; 
	Tcl_Obj *operation_obj, *dest_obj, *destmask_obj;
	Tcl_Obj *option_name_obj, *option_val_obj;
	struct rtentry route;
	int sock;
	int ioctl_id;
	int tcl_ret, ioctl_ret, parse_ret;

	if (objc < 4) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::route operation destination destination_mask ?options?\"", -1));

		return(TCL_ERROR);
	}

	/* Clear object values */
	memset(&route, 0, sizeof(route));

	/* Determine operation */
	operation_obj = objv[1];
	switch (tuapi_internal_simplehash_obj(operation_obj)) {
		case 0x187264: /* add */
			ioctl_id = SIOCADDRT;
			break;
		case 0x1932ec: /* del */
		case 0x5d98e965: /* delete */
			ioctl_id = SIOCDELRT;
			break;
		default:
			Tcl_SetObjResult(interp, Tcl_ObjPrintf("bad option \"%s\": must be add, or delete", Tcl_GetString(operation_obj)));

			return(TCL_ERROR);
	}

	/* Set default flags */
	route.rt_flags = RTF_UP;

	/* Parse destination address */
	dest_obj = objv[2];
	parse_ret = tuapi_private_get_sockaddr_from_obj(dest_obj, &route.rt_dst);
	if (parse_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to parse \"%s\" as an address", Tcl_GetString(dest_obj)));

		return(TCL_ERROR);
	}

	/* Parse destination netmask */
	destmask_obj = objv[3];
	parse_ret = tuapi_private_get_sockaddr_from_obj(destmask_obj, &route.rt_genmask);
	if (parse_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to parse \"%s\" as an address", Tcl_GetString(destmask_obj)));

		return(TCL_ERROR);
	}

	if (route.rt_dst.sa_family != route.rt_genmask.sa_family) {
		Tcl_SetObjResult(interp,
		  Tcl_ObjPrintf("destination (\"%s\") and destination_mask (\"%s\") are different classes",
		    Tcl_GetString(dest_obj),
		    Tcl_GetString(destmask_obj)
		  )
		);

		return(TCL_ERROR);
	}

	switch (route.rt_dst.sa_family) {
		case AF_INET: /* IPv4 */
			if (sock_v4 == -1) {
				Tcl_SetObjResult(interp, Tcl_ObjPrintf("address \"%s\" is IPv4, but unable to create IPv4 socket", Tcl_GetString(dest_obj)));

				return(TCL_ERROR);
			}

			if (((struct sockaddr_in *) &route.rt_genmask)->sin_addr.s_addr == INADDR_BROADCAST) {
				route.rt_flags |= RTF_HOST;
			}

			sock = sock_v4;

			break;
		case AF_INET6: /* IPv6 */
			if (sock_v6 == -1) {
				Tcl_SetObjResult(interp, Tcl_ObjPrintf("address \"%s\" is IPv6, but unable to create IPv6 socket", Tcl_GetString(dest_obj)));

				return(TCL_ERROR);
			}

			sock = sock_v6;

			break;
		default:
			Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to determine type of address for \"%s\"", Tcl_GetString(dest_obj)));

			return(TCL_ERROR);
	}

	/* Parse remaining options */
	objc -= 4;
	objv += 4;

	for (; objc > 0; objc--,objv++) {
		option_name_obj = objv[0];

		if (objc < 2) {
			Tcl_SetObjResult(interp, Tcl_ObjPrintf("option \"%s\" requires an argument", Tcl_GetString(option_name_obj)));

			return(TCL_ERROR);
		}

		objc--;
		objv++;

		option_val_obj = objv[0];

		switch (tuapi_internal_simplehash_obj(option_name_obj)) {
			case 0x4c727779: /* gateway */
				parse_ret = tuapi_private_get_sockaddr_from_obj(option_val_obj, &route.rt_gateway);
				if (parse_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to parse \"%s\" as an address", Tcl_GetString(option_val_obj)));

					return(TCL_ERROR);
				}

				route.rt_flags &= (~RTF_HOST);
				route.rt_flags |= RTF_GATEWAY;

				break;
			case 0x1b7a75: /* mtu */
				tcl_ret = Tcl_GetWideIntFromObj(interp, option_val_obj, &option_val_wide);
				if (tcl_ret != TCL_OK) {
					return(tcl_ret);
				}

				route.rt_flags |= RTF_MTU;
				route.rt_mtu = option_val_wide;

				break;
			case 0x5e9d03e3: /* metric */
				tcl_ret = Tcl_GetWideIntFromObj(interp, option_val_obj, &option_val_wide);
				if (tcl_ret != TCL_OK) {
					return(tcl_ret);
				}

				route.rt_metric = option_val_wide;

				break;
			case 0x9dd8e8f7: /* window */
				tcl_ret = Tcl_GetWideIntFromObj(interp, option_val_obj, &option_val_wide);
				if (tcl_ret != TCL_OK) {
					return(tcl_ret);
				}

				route.rt_flags |= RTF_WINDOW;
				route.rt_window = option_val_wide;

				break;
			case 0x1932f6: /* dev */
			case 0x5edbe2e5: /* device */
				route.rt_dev = strdup(Tcl_GetString(option_val_obj));

				break;
			default:
				Tcl_SetObjResult(interp, Tcl_ObjPrintf("bad option \"%s\": must be gateway, mtu, metric, device, or window", Tcl_GetString(option_name_obj)));

				return(TCL_ERROR);
		}
	}

	/* Request route change */
	ioctl_ret = ioctl(sock, ioctl_id, &route);
	if (ioctl_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_route(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	int sock_v4, sock_v6, sock;
	int retval = TCL_ERROR;

	sock = tuapi_internal_getsock(&sock_v4, &sock_v6);
	if (sock == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create socket", -1));

		return(TCL_ERROR);
	}

	switch (objc) {
		case 0:
		case 1: /* No arguments, list all interfaces */
			retval = tuapi_route_list(cd, interp, objc, objv, sock_v4, sock_v6);

			break;
		default:
			/* Otherwise, modify routes */
			retval = tuapi_route_conf(cd, interp, objc, objv, sock_v4, sock_v6);

			break;
	}

	/* Cleanup */
	if (sock_v4 != -1) {
		close(sock_v4);
	}

	if (sock_v6 != -1) {
		close(sock_v6);
	}

	return(retval);
}

static int tuapi_brctl_list(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tuapi_brctl_conf(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock) {
	Tcl_Obj *operation_obj, *bridge_name_obj, *interface_name_obj;
	unsigned long arg[4];
	struct ifreq ifr;
	int ioctl_ret, ioctl_id;
	int add = 0;

	/* Determine operation */
	operation_obj = objv[1];
	switch (tuapi_internal_simplehash_obj(operation_obj)) {
		case 0x1c993272: /* addbr */
			add = 1;
		case 0x4cbb3272: /* delbr */
			if (objc != 3) {
				if (add) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::brctl addbr bridge\"", -1));
				} else {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::brctl delbr bridge\"", -1));
				}

				return(TCL_ERROR);
			}

			bridge_name_obj = objv[2];

			if (add) {
				arg[0] = BRCTL_ADD_BRIDGE;
			} else {
				arg[0] = BRCTL_DEL_BRIDGE;
			}

			arg[1] = (unsigned long) Tcl_GetString(bridge_name_obj);
			arg[2] = 0;

			ioctl_ret = ioctl(sock, SIOCGIFBR, &arg); 

			break;
		case 0x1C9937E6: /* addif */
			add = 1;
		case 0x4cbb37e6: /* delif */
			if (objc != 4) {
				if (add) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::brctl addif bridge interface\"", -1));
				} else {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::brctl delif bridge interface\"", -1));
				}

				return(TCL_ERROR);
			}

			if (add) {
				ioctl_id = SIOCBRADDIF;
			} else {
				ioctl_id = SIOCBRDELIF;
			}

			bridge_name_obj = objv[2];
			interface_name_obj = objv[3];

			memset(&ifr, 0, sizeof(ifr));
			snprintf(ifr.ifr_name, IFNAMSIZ, "%s", Tcl_GetString(interface_name_obj));

			ioctl_ret = ioctl(sock, SIOCGIFINDEX, (void *) &ifr);
			if (ioctl_ret == 0) {
				snprintf(ifr.ifr_name, IFNAMSIZ, "%s", Tcl_GetString(bridge_name_obj));
				ioctl_ret = ioctl(sock, ioctl_id, (void *) &ifr);
			}

			break;
	}

	if (ioctl_ret < 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tuapi_brctl(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	int sock_v4, sock_v6, sock;
	int retval = TCL_ERROR;

	sock = tuapi_internal_getsock(&sock_v4, &sock_v6);
	if (sock == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create socket", -1));

		return(TCL_ERROR);
	}

	switch (objc) {
		case 0:
		case 1: /* No arguments, list all bridges */
			retval = tuapi_brctl_list(cd, interp, objc, objv, sock);

			break;
		default:
			/* Otherwise, modify routes */
			retval = tuapi_brctl_conf(cd, interp, objc, objv, sock);

			break;
	}

	/* Cleanup */
	if (sock_v4 != -1) {
		close(sock_v4);
	}

	if (sock_v6 != -1) {
		close(sock_v6);
	}

	return(retval);
}

static int tuapi_vconfig(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	int sock_v4, sock_v6, sock;
	int retval = TCL_ERROR;

	sock = tuapi_internal_getsock(&sock_v4, &sock_v6);
	if (sock == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create socket", -1));

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	/* Cleanup */
	if (sock_v4 != -1) {
		close(sock_v4);
	}

	if (sock_v6 != -1) {
		close(sock_v6);
	}

	return(retval);
}

static int tuapi_stty(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *obj, *retobj = NULL;
	struct termios terminal_information;
	struct winsize terminal_size;
	unsigned long obj_hash;
	int fd, idx;
	int ioctl_ret;
	int retval = TCL_OK;

	fd = STDIN_FILENO;

	for (idx = 1; idx < objc; idx++) {
		obj = objv[idx];
		obj_hash = tuapi_internal_simplehash_obj(obj);

		switch (obj_hash) {
			case 0xe7a7d65: /* size */
				ioctl_ret = ioctl(fd, TIOCGWINSZ, &terminal_size);
				if (ioctl_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("ioctl failed", -1));

					return(TCL_ERROR);
				}

				if (retobj == NULL) {
					retobj = Tcl_NewObj();
				}

				Tcl_ListObjAppendElement(interp, retobj, Tcl_NewLongObj(terminal_size.ws_row));
				Tcl_ListObjAppendElement(interp, retobj, Tcl_NewLongObj(terminal_size.ws_col));

				break;
			case 0x5bcb0f7: /* -raw */
			case 0x1cb0f7: /* raw */
			case 0xdcb8f56f: /* -echo */
			case 0xcb8f46f: /* echo */
				ioctl_ret = ioctl(fd, TCGETS, &terminal_information);
				if (ioctl_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("ioctl failed", -1));

					return(TCL_ERROR);
				}

				switch (obj_hash) {
					case 0x5bcb0f7: /* -raw */
						terminal_information.c_iflag |= BRKINT | IGNPAR | ISTRIP | ICRNL | IXON;
						terminal_information.c_oflag |= OPOST;
						terminal_information.c_lflag |= ISIG | ICANON;
#if VMIN == VEOF
						terminal_information.c_cc[VEOF] = CEOF;
#endif
#if VTIME == VEOL
						terminal_information.c_cc[VEOL] = CEOL;
#endif
						break;
					case 0x1cb0f7: /* raw */
						terminal_information.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
						terminal_information.c_oflag &= ~OPOST;
						terminal_information.c_lflag &= ~(ISIG | ICANON);
						terminal_information.c_cc[VMIN] = 1;
						terminal_information.c_cc[VTIME] = 0;
						break;
					case 0xdcb8f56f: /* -echo */
						terminal_information.c_lflag &= ~ECHO;
						break;
					case 0xcb8f46f: /* echo */
						terminal_information.c_lflag |= ECHO;
						break;
				}

				ioctl_ret = ioctl(fd, TCSETS, &terminal_information);
				if (ioctl_ret != 0) {
					Tcl_SetObjResult(interp, Tcl_NewStringObj("ioctl failed", -1));

					return(TCL_ERROR);
				}

				break;
			default:
				Tcl_SetObjResult(interp, Tcl_NewStringObj("subcommand not implemented", -1));
				return(TCL_ERROR);
		}
	}

	if (retobj != NULL) {
		Tcl_SetObjResult(interp, retobj);
	}

	return(retval);
}

static int tuapi_rlimit(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *operation_obj, *resource_id_obj, *resource_val_item_obj, *resource_val_itemval_obj, *ret_obj;
	struct rlimit resource_val;
	Tcl_WideInt resource_val_item;
	int resource_id;
	int rlimit_ret, tcl_ret;

	if (objc < 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::rlimit operation resource ?value?\"", -1));

		return(TCL_ERROR);
	}

	operation_obj = objv[1];
	resource_id_obj = objv[2];

	switch (tuapi_internal_simplehash_obj(resource_id_obj)) {
		case 0x20d3LU: /* AS */
			resource_id = RLIMIT_AS;
			break;
		case 0x873e945LU: /* CORE */
			resource_id = RLIMIT_CORE;
			break;
		case 0x10e855LU: /* CPU */
			resource_id = RLIMIT_CPU;
			break;
		case 0x8906a41LU: /* DATA */
			resource_id = RLIMIT_DATA;
			break;
		case 0x6a726f45LU: /* FSIZE */
			resource_id = RLIMIT_FSIZE;
			break;
#ifdef RLIMIT_LOCKS
		case 0xc9f0e7d3LU: /* LOCKS */
			resource_id = RLIMIT_LOCKS;
			break;
#endif
		case 0xd908f7cbLU: /* MEMLOCK */
			resource_id = RLIMIT_MEMLOCK;
			break;
#ifdef RLIMIT_MSGQUEUE
		case 0x57167445LU: /* MSGQUEUE */
			resource_id = RLIMIT_MSGQUEUE;
			break;
#endif
		case 0x9d261c5LU: /* NICE */
			resource_id = RLIMIT_NICE;
			break;
		case 0xf8d35c45LU: /* NOFILE */
		case 0xf8d26445LU: /* OFILE */
			resource_id = RLIMIT_NOFILE;
			break;
		case 0xea14a5c3LU: /* NPROC */
			resource_id = RLIMIT_NPROC;
			break;
		case 0x14a9d3LU: /* RSS */
			resource_id = RLIMIT_RSS;
			break;
#ifdef RLIMIT_RTPRIO
		case 0x4a15ee4fLU: /* RTPRIO */
			resource_id = RLIMIT_RTPRIO;
			break;
#endif
#ifdef RLIMIT_RTTIME
		case 0x4a932c45LU: /* RTTIME */
			resource_id = RLIMIT_RTTIME;
			break;
#endif
#ifdef RLIMIT_SIGPENDING
		case 0x2f390347LU: /* SIGPENDING */
			resource_id = RLIMIT_SIGPENDING;
			break;
#endif
		case 0x3a90634bLU: /* STACK */
			resource_id = RLIMIT_STACK;
			break;
		default:
			Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid resource", -1));

			return(TCL_ERROR);
	}

	if (strcmp(Tcl_GetString(operation_obj), "get") == 0) {
		if (objc != 3) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::rlimit get resource\"", -1));

			return(TCL_ERROR);
		}

		rlimit_ret = getrlimit(resource_id, &resource_val);
		if (rlimit_ret != 0) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("getrlimit() failed", -1));

			return(TCL_ERROR);
		}

		ret_obj = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, ret_obj, Tcl_NewStringObj("soft", -1));
		Tcl_ListObjAppendElement(interp, ret_obj, Tcl_NewWideIntObj(resource_val.rlim_cur));
		Tcl_ListObjAppendElement(interp, ret_obj, Tcl_NewStringObj("hard", -1));
		Tcl_ListObjAppendElement(interp, ret_obj, Tcl_NewWideIntObj(resource_val.rlim_max));

		Tcl_SetObjResult(interp, ret_obj);

		return(TCL_OK);
	}

	if (strcmp(Tcl_GetString(operation_obj), "set") == 0) {
		if (objc != 4) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::rlimit set resource value\"", -1));

			return(TCL_ERROR);
		}

		resource_val_item_obj = objv[3];

		/* Determine if we were asked to set to a simple value, in which case set both hard and soft limits */
		tcl_ret = Tcl_GetWideIntFromObj(NULL, resource_val_item_obj, &resource_val_item);
		if (tcl_ret == TCL_OK) {
			resource_val.rlim_cur = resource_val_item;
			resource_val.rlim_max = resource_val_item;
		} else {
			tcl_ret = Tcl_DictObjGet(NULL, resource_val_item_obj, Tcl_NewStringObj("soft", -1), &resource_val_itemval_obj);
			if (tcl_ret != TCL_OK) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid request", -1));

				return(TCL_ERROR);
			}

			tcl_ret = Tcl_GetWideIntFromObj(NULL, resource_val_itemval_obj, &resource_val_item);
			if (tcl_ret != TCL_OK) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid request", -1));

				return(TCL_ERROR);
			}

			resource_val.rlim_cur = resource_val_item;

			tcl_ret = Tcl_DictObjGet(NULL, resource_val_item_obj, Tcl_NewStringObj("hard", -1), &resource_val_itemval_obj);
			if (tcl_ret != TCL_OK) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid request", -1));

				return(TCL_ERROR);
			}

			tcl_ret = Tcl_GetWideIntFromObj(NULL, resource_val_itemval_obj, &resource_val_item);
			if (tcl_ret != TCL_OK) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid request", -1));

				return(TCL_ERROR);
			}

			resource_val.rlim_max = resource_val_item;
		}

		rlimit_ret = setrlimit(resource_id, &resource_val);
		if (rlimit_ret != 0) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("setrlimit() failed", -1));

			return(TCL_ERROR);
		}

		return(TCL_OK);
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid operation", -1));

	return(TCL_ERROR);
}

static int tuapi_klogctl(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *operation_obj;
	char *buf;
	int buflen;
	int klog_ret;

	if (objc < 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::klogctl operation ...\"", -1));

		return(TCL_ERROR);
	}

	klog_ret = klogctl(SYSLOG_ACTION_OPEN, NULL, 0);
	if (klog_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("klogctl(SYSLOG_ACTION_OPEN, ...) failed", -1));
		return(TCL_ERROR);
	}

	operation_obj = objv[1];
	switch (tuapi_internal_simplehash_obj(operation_obj)) {
		case 0xe5970e4LU: /* read */
			buflen = 256 * 1024;
			buf = malloc(buflen);
			if (buf == NULL) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("malloc failed !", -1));

				return(TCL_ERROR);
			}

			klog_ret = klogctl(SYSLOG_ACTION_READ_ALL, buf, buflen);
			if (klog_ret == -1) {
				free(buf);

				Tcl_SetObjResult(interp, Tcl_NewStringObj("klogctl(SYSLOG_ACTION_READ_ALL, ...) failed", -1));

				return(TCL_ERROR);
			}

			Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) buf, klog_ret));

			free(buf);

			return(TCL_OK);
		case 0x3d9973f2LU: /* clear */
			klog_ret = klogctl(SYSLOG_ACTION_CLEAR, NULL, 0);
			if (klog_ret == -1) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("klogctl(SYSLOG_ACTION_CLEAR, ...) failed", -1));

				return(TCL_ERROR);
			}

			return(TCL_OK);
		case 0x225c336eLU: /* console_on */
			klog_ret = klogctl(SYSLOG_ACTION_CONSOLE_ON, NULL, 0);
			if (klog_ret == -1) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("klogctl(SYSLOG_ACTION_CONSOLE_ON, ...) failed", -1));

				return(TCL_ERROR);
			}

			return(TCL_OK);
		case 0x2e19bbe6LU: /* console_off */
			klog_ret = klogctl(SYSLOG_ACTION_CONSOLE_OFF, NULL, 0);
			if (klog_ret == -1) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("klogctl(SYSLOG_ACTION_CONSOLE_OFF, ...) failed", -1));

				return(TCL_ERROR);
			}

			return(TCL_OK);
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid subcommand", -1));

	return(TCL_ERROR);
}

static int tuapi_waitpid(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	pid_t child;
	int status;

	child = waitpid(-1, &status, WNOHANG);
	if (child < 0) {
		if (errno != ECHILD) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

			return(TCL_ERROR);
		} else {
			child = 0;
		}
	}

	if (child != 0) {
		Tcl_SetObjResult(interp, Tcl_NewWideIntObj(child));
	}

	return(TCL_OK);
}

static int tuapi_settimeofday(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct timeval tv;
	Tcl_WideInt tv_sec_val, tv_usec_val;
	int settimeofday_ret, tcl_ret;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::settimeofday seconds microseconds\"", -1));

		return(TCL_ERROR);
	}

	tcl_ret = Tcl_GetWideIntFromObj(interp, objv[1], &tv_sec_val);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	tcl_ret = Tcl_GetWideIntFromObj(interp, objv[2], &tv_usec_val);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	tv.tv_sec = tv_sec_val;
	tv.tv_usec = tv_usec_val; 

	settimeofday_ret = settimeofday(&tv, NULL);

	if (settimeofday_ret < 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

#ifndef DISABLE_UNIX_SOCKETS
struct tuapi_socket_unix__chan_id {
	int fd;
	Tcl_Channel chan;
};

static int tuapi_socket_unix__chan_close(ClientData id_p, Tcl_Interp *interp) {
	struct tuapi_socket_unix__chan_id *id;
	int fd;

	id = id_p;

	fd = id->fd;

	close(fd);

	free(id);

	return(0);
}

static int tuapi_socket_unix__chan_read(ClientData id_p, char *buf, int bufsize, int *errorCodePtr) {
	struct tuapi_socket_unix__chan_id *id;
	ssize_t read_ret;
	int fd;
	int retval;

	id = id_p;

	fd = id->fd;

	read_ret = read(fd, buf, bufsize);
	if (read_ret < 0) {
		*errorCodePtr = errno;

		return(-1);
	}

	retval = read_ret;

	return(retval);
}

static int tuapi_socket_unix__chan_write(ClientData id_p, const char *buf, int toWrite, int *errorCodePtr) {
	struct tuapi_socket_unix__chan_id *id;
	ssize_t write_ret;
	int fd;
	int bytesWritten;

	id = id_p;

	fd = id->fd;

	bytesWritten = 0;
	while (toWrite) {
		write_ret = write(fd, buf, toWrite);
		if (write_ret == 0) {
			break;
		}

		if (write_ret < 0) {
			*errorCodePtr = errno;

			return(-1);
		}

		toWrite -= write_ret;
		buf += write_ret;
		bytesWritten += write_ret;
	}

	if (bytesWritten == 0) {
		*errorCodePtr = EAGAIN;

		return(-1);
	}

	return(bytesWritten);
}

static void tuapi_socket_unix__chan_eventhandler(ClientData id_p, int mask) {
	struct tuapi_socket_unix__chan_id *id;
	Tcl_Channel chan;

	id = id_p;

	chan = id->chan;

	if (!chan) {
		return;
	}

	Tcl_NotifyChannel(chan, mask);
}

static void tuapi_socket_unix__chan_watch(ClientData id_p, int mask) {
	struct tuapi_socket_unix__chan_id *id;
	int fd;

	id = id_p;

	fd = id->fd;

	Tcl_CreateFileHandler(fd, mask, tuapi_socket_unix__chan_eventhandler, id);

	return;
}

static int tuapi_socket_unix__chan_gethandle(ClientData id_p, int direction, ClientData *handlePtr) {
	struct tuapi_socket_unix__chan_id *id;
	int fd;
	ClientData fd_cd;

	id = id_p;

	fd = id->fd;

	memcpy(&fd_cd, &fd, sizeof(fd));

	*handlePtr = fd_cd;

	return(TCL_OK);
}

static Tcl_Channel tuapi_socket_unix_sock2tclchan(int sock) {
	struct tuapi_socket_unix__chan_id *id;
	static Tcl_ChannelType tcl_chan_type;
	static int tcl_chan_type_init = 0;
	Tcl_Channel tcl_chan;
	char chan_name[32];
	int sock_flags;

	if (!tcl_chan_type_init) {
		tcl_chan_type.typeName = "socket";
		tcl_chan_type.version = TCL_CHANNEL_VERSION_2;
		tcl_chan_type.closeProc = tuapi_socket_unix__chan_close;
		tcl_chan_type.inputProc = tuapi_socket_unix__chan_read;
		tcl_chan_type.outputProc = tuapi_socket_unix__chan_write;
		tcl_chan_type.watchProc = tuapi_socket_unix__chan_watch;
		tcl_chan_type.getHandleProc = tuapi_socket_unix__chan_gethandle;
		tcl_chan_type.seekProc = NULL;
		tcl_chan_type.setOptionProc = NULL;
		tcl_chan_type.getOptionProc = NULL;
		tcl_chan_type.close2Proc = NULL;
		tcl_chan_type.blockModeProc = NULL;
		tcl_chan_type.flushProc = NULL;
		tcl_chan_type.handlerProc = NULL;
		tcl_chan_type.wideSeekProc = NULL;
		tcl_chan_type.threadActionProc = NULL;
		tcl_chan_type.truncateProc = NULL;

		tcl_chan_type_init = 1;
	}

	snprintf(chan_name, sizeof(chan_name), "sock%u", sock);

	id = malloc(sizeof(*id));
	if (id == NULL) {
		return(NULL);
	}

	id->fd = sock;
	id->chan = NULL;

	/* Configure socket as non-blocking */
	sock_flags = fcntl(sock, F_GETFL, 0);
	if (sock_flags == -1) {
		sock_flags = O_NONBLOCK;
	} else {
		sock_flags |= O_NONBLOCK;
	}
	fcntl(sock, F_SETFL, (long) sock_flags);

	/* Create the channel */
	tcl_chan = Tcl_CreateChannel(&tcl_chan_type, chan_name, id, TCL_READABLE | TCL_WRITABLE);

	/* Update the structure passed to each function to include the channel name */
	id->chan = tcl_chan;

	return(tcl_chan);
}

struct tuapi_socket_unix__chan_accept_cd {
	int fd;
	Tcl_Interp *interp;
	Tcl_Obj *command;
};

static void tuapi_socket_unix__chan_accept(ClientData cd_p, int mask) {
	struct tuapi_socket_unix__chan_accept_cd *cd;
	Tcl_Interp *interp;
	Tcl_Channel chan;
	Tcl_Obj *command, *command_to_run_objs[5], *command_to_run;
	int setsockopt_ret;
	int pass_creds_true = 1;
	int fd;
	int sock;

	if ((mask & TCL_READABLE) != TCL_READABLE) {
		return;
	}
	
	cd = cd_p;

	fd = cd->fd;
	interp = cd->interp;
	command = cd->command;

	sock = accept(fd, NULL, NULL);
	if (sock < 0) {
		return;
	}

	chan = tuapi_socket_unix_sock2tclchan(sock);
	if (chan == NULL) {
		close(sock);

		return;
	}

	setsockopt_ret = setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &pass_creds_true, sizeof(pass_creds_true));
	if (setsockopt_ret != 0) {
		close(sock);

		return;
	}

	Tcl_RegisterChannel(interp, chan);

	command_to_run_objs[0] = command;
	command_to_run_objs[1] = Tcl_NewStringObj(Tcl_GetChannelName(chan), -1);
	command_to_run_objs[2] = Tcl_NewStringObj("...uid...", -1); /* XXX: TODO */
	command_to_run_objs[3] = Tcl_NewStringObj("...gid...", -1); /* XXX: TODO */
	command_to_run_objs[4] = Tcl_NewStringObj("...pid...", -1); /* XXX: TODO */
	command_to_run = Tcl_ConcatObj(sizeof(command_to_run_objs) / sizeof(command_to_run_objs[0]), command_to_run_objs);

	Tcl_EvalObjEx(interp, command_to_run, TCL_EVAL_GLOBAL);

	return;
}

static int tuapi_socket_unix_server(ClientData cd, Tcl_Interp *interp, int sock, const char *path, Tcl_Obj *command) {
	struct tuapi_socket_unix__chan_accept_cd *accept_cd;
	struct sockaddr_un dest;
	ssize_t pathlen;
	int bind_ret, listen_ret;

	pathlen = strlen(path) + 1;
	if (pathlen <= 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("path too short", -1));

		return(TCL_ERROR);
	}

	if (pathlen > sizeof(dest.sun_path)) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("path too long", -1));

		return(TCL_ERROR);
	}

	dest.sun_family = AF_UNIX;
	memcpy(dest.sun_path, path, pathlen);

	bind_ret = bind(sock, (struct sockaddr *) &dest, sizeof(dest));
	if (bind_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	listen_ret = listen(sock, 2);
	if (listen_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	accept_cd = malloc(sizeof(*accept_cd));
	if (accept_cd == NULL) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	accept_cd->fd = sock;
	accept_cd->interp = interp;
	accept_cd->command = command;

	Tcl_IncrRefCount(command);

	Tcl_CreateFileHandler(sock, TCL_READABLE, tuapi_socket_unix__chan_accept, accept_cd);

	return(TCL_OK);
}

static int tuapi_socket_unix_client(ClientData cd, Tcl_Interp *interp, int sock, const char *path) {
	Tcl_Channel chan;
	struct sockaddr_un dest;
	ssize_t pathlen;
	int connect_ret, setsockopt_ret;
	int pass_creds_true = 1;

	pathlen = strlen(path) + 1;
	if (pathlen <= 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("path too short", -1));

		return(TCL_ERROR);
	}

	if (pathlen > sizeof(dest.sun_path)) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("path too long", -1));

		return(TCL_ERROR);
	}

	dest.sun_family = AF_UNIX;
	memcpy(dest.sun_path, path, pathlen);

	connect_ret = connect(sock, (struct sockaddr *) &dest, sizeof(dest));
	if (connect_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	setsockopt_ret = setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &pass_creds_true, sizeof(pass_creds_true));
	if (setsockopt_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	chan = tuapi_socket_unix_sock2tclchan(sock);
	if (chan == NULL) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create Tcl channel", -1));

		return(TCL_ERROR);
	}

	Tcl_RegisterChannel(interp, chan);

	Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_GetChannelName(chan), -1));

	return(TCL_OK);
}

static int tuapi_socket_unix(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *path_obj, *command_obj;
	char *path;
	int retval;
	int sock;

	if (objc < 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::socket_unix path\" or \"::tuapi::syscall::socket_unix -server command path\"", -1));

		return(TCL_ERROR);
	}

	path_obj = objv[1];
	path = Tcl_GetString(path_obj);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	if (strcmp(path, "-server") == 0) {
		if (objc != 4) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::socket_unix -server command path\"", -1));

			close(sock);

			return(TCL_ERROR);
		}

		command_obj = objv[2];
		path_obj = objv[3];

		path = Tcl_GetString(path_obj);

		retval = tuapi_socket_unix_server(cd, interp, sock, path, command_obj);
	} else {
		if (objc != 2) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::socket_unix path\"", -1));

			close(sock);

			return(TCL_ERROR);
		}

		retval = tuapi_socket_unix_client(cd, interp, sock, path);
	}

	if (retval != TCL_OK) {
		close(sock);
	}

	return(retval);
}
#else
static int tuapi_socket_unix(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));
	return(TCL_ERROR)
}
#endif

static int tuapi_tsmf_start_svc(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct timeval select_timeout;
	Tcl_WideInt umask_val, timeout_val, uid_val, gid_val;
	Tcl_Obj *filename_obj, *env_obj, *logfile_obj, **env_entry_objv, *cwd_obj, *umask_obj, *uid_obj, *gid_obj;
	Tcl_Obj *sri_obj, *timeout_obj;
	pid_t child, child_pgid = -1, waitpid_ret;
	ssize_t read_ret;
	time_t currtime;
	char *argv[3], *envv[512];
	char *logfile, *filename, *cwd;
	char logmsg[2048];
	fd_set read_fdset;
	int pipe_ret, setsid_ret, execve_ret, tcl_ret, select_ret, chdir_ret;
	int null_fd, log_fd, tmp_fd, max_fd;
	int env_entry_objc;
	int fds[2], fd;
	int status;
	int idx;

	/* 1. Parse arguments */
	/* 1.a. Ensure the correct number of arguments were passed */
	if (objc != 10) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::tuapi::syscall::tsmf_start_svc sri filename logfile env cwd umask uid gid timeout\"", -1));

		return(TCL_ERROR);
	}

	/* 1.b. Identify Tcl_Objs to use for each argument */
	sri_obj = objv[1];
	filename_obj = objv[2];
	logfile_obj = objv[3];
	env_obj = objv[4];
	cwd_obj = objv[5];
	umask_obj = objv[6];
	uid_obj = objv[7];
	gid_obj = objv[8];
	timeout_obj = objv[9];

	/* 1.c. Store string arguments */
	filename = Tcl_GetString(filename_obj);
	logfile = Tcl_GetString(logfile_obj);
	cwd = Tcl_GetString(cwd_obj);

	/* 1.d. Integer objects */
	tcl_ret = Tcl_GetWideIntFromObj(interp, umask_obj, &umask_val);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	tcl_ret = Tcl_GetWideIntFromObj(interp, timeout_obj, &timeout_val);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	tcl_ret = Tcl_GetWideIntFromObj(interp, uid_obj, &uid_val);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	tcl_ret = Tcl_GetWideIntFromObj(interp, gid_obj, &gid_val);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	/* 1.e. Process environment */
	tcl_ret = Tcl_ListObjGetElements(interp, env_obj, &env_entry_objc, &env_entry_objv);
	if (tcl_ret != TCL_OK) {
		return(tcl_ret);
	}

	for (idx = 0; idx < MIN(env_entry_objc, sizeof(envv) / sizeof(envv[0]) - 1); idx++) {
		envv[idx] = Tcl_GetString(env_entry_objv[idx]);
	}
	envv[idx] = NULL;

	/* 2. Create a pipe for communication between the processes */
	pipe_ret = pipe(fds);
	if (pipe_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("pipe failed", -1));

		return(TCL_ERROR);
	}

	/* 3. Fork into a new process */
	child = fork();
	if (child == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("fork failed", -1));

		return(TCL_ERROR);
	}

	if (child != 0) {
		/* 4.parent. Get PGID from child */
		/* 4.parent.a. Open log file */
		log_fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

		/* 4.parent.b. Close write end of pipe -- we are read-only */
		close(fds[1]);
		fd = fds[0];

		/* 4.parent.c. Read process group ID of child from pipe */
		select_timeout.tv_sec = timeout_val;
		select_timeout.tv_usec = 0;

		FD_ZERO(&read_fdset);
		FD_SET(fd, &read_fdset);

		select_ret = select(fd + 1, &read_fdset, NULL, NULL, &select_timeout);
		if (select_ret == 0) {
			/* On timeout, terminate starting process */
			child_pgid = getpgid(child);
			if (child_pgid != -1) {
				kill(-child_pgid, SIGKILL);
			}

			Tcl_SetObjResult(interp, Tcl_NewStringObj("timeout", -1));

			currtime = time(NULL);
			strftime(logmsg, sizeof(logmsg), "[ %b %e %H:%M:%S ", localtime(&currtime));
			write(log_fd, logmsg, strlen(logmsg));

			snprintf(logmsg, sizeof(logmsg), "Method \"start\" timed out after %i seconds ]\n", (int) timeout_val);
			write(log_fd, logmsg, strlen(logmsg));

			close(log_fd);

			return(TCL_ERROR);
		}

		if (select_ret > 0) {
			read_ret = read(fd, &child_pgid, sizeof(child_pgid));
		}

		/* 4.parent.d. Close read end of pipe */
		close(fd);

		/* 4.parent.e. Verify read was meaningful */
		if (read_ret != sizeof(child_pgid)) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("failed to communicate with started service", -1));

			currtime = time(NULL);
			strftime(logmsg, sizeof(logmsg), "[ %b %e %H:%M:%S ", localtime(&currtime));
			write(log_fd, logmsg, strlen(logmsg));

			snprintf(logmsg, sizeof(logmsg), "Method \"start\" failed: communication with started service broken ]\n");
			write(log_fd, logmsg, strlen(logmsg));

			close(log_fd);

			return(TCL_ERROR);
		}

		/* 4.parent.f. If the PGID given is actually an error, return error */
		if (child_pgid == -1) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("service failed to start", -1));

			currtime = time(NULL);
			strftime(logmsg, sizeof(logmsg), "[ %b %e %H:%M:%S ", localtime(&currtime));
			write(log_fd, logmsg, strlen(logmsg));

			snprintf(logmsg, sizeof(logmsg), "Method \"start\" failed ]\n");
			write(log_fd, logmsg, strlen(logmsg));

			close(log_fd);

			return(TCL_ERROR);
		}

		/* 4.parent.g. Return PGID to Tcl */
		Tcl_SetObjResult(interp, Tcl_NewWideIntObj((Tcl_WideInt) child_pgid));

		currtime = time(NULL);
		strftime(logmsg, sizeof(logmsg), "[ %b %e %H:%M:%S ", localtime(&currtime));
		write(log_fd, logmsg, strlen(logmsg));

		snprintf(logmsg, sizeof(logmsg), "Method \"start\" completed, process group = %lu ]\n", (unsigned long) child_pgid);
		write(log_fd, logmsg, strlen(logmsg));

		close(log_fd);

		return(TCL_OK);
	}

	/* 4.child.a. Close read end of pipe -- we only write to it */
	close(fds[0]);
	fd = fds[1];

	/* 5. Create a new session */
	setsid_ret = setsid();
	if (setsid_ret == -1) {
		write(fd, &child_pgid, sizeof(child_pgid));

		_exit(0);
	}

	/* 6. Setup environment */
	/* 6.a. Set umask */
	umask(umask_val);

	/* 6.b. Set working directory */
	chdir_ret = chdir(cwd);
	if (chdir_ret != 0) {
		write(fd, &child_pgid, sizeof(child_pgid));

		_exit(0);
	}

	/* 6.c. Open log file for stderr and stdout */
	log_fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	/* 6.d. Open "/dev/null" for stdin */
	null_fd = open("/dev/null", O_RDONLY);
	if (null_fd < 0 || log_fd <0) {
		write(fd, &child_pgid, sizeof(child_pgid));

		_exit(0);
	}

	/* 6.e. Redirect stdin, stdout, and stderr to null, logs */
	dup2(null_fd, STDIN_FILENO);
	dup2(log_fd, STDOUT_FILENO);
	dup2(log_fd, STDERR_FILENO);

	close(null_fd);
	close(log_fd);

	/* 6.f. Close stray file descriptors */
	max_fd = MAX(MAX(MAX(1024, STDIN_FILENO), STDOUT_FILENO), STDERR_FILENO);
	for (tmp_fd = 0; tmp_fd < max_fd; tmp_fd++) {
		if (tmp_fd == STDIN_FILENO || tmp_fd == STDOUT_FILENO || tmp_fd == STDERR_FILENO) {
			continue;
		}

		if (tmp_fd == fd) {
			continue;
		}

		close(tmp_fd);
	}

	/* 6.g. Switch to appropriate user/group */
	/* 6.g.i. Group */
	setgid(gid_val);

	/* 6.g.ii. User */
	setuid(uid_val);

	/* 7. Create a new process to actually spawn the process */
	child = fork();
	if (child == -1) {
		write(fd, &child_pgid, sizeof(child_pgid));

		_exit(0);
	}

	if (child != 0) {
		/* 7.parent.a. Wait for child process to terminate and collect status */
		waitpid_ret = waitpid(child, &status, 0);
		if (waitpid_ret == -1) {
			status = -1;
		}

		/* 7.parent.b. Set PGID (if successful, -1 otherwise) to pass back to TSMF */
		if (status == 0) {
			child_pgid = getpgid(getpid());
		}
		write(fd, &child_pgid, sizeof(child_pgid));

		close(fd);

		/* 7.parent.c. Write log of result */
		/* Note: We avoid ANSI I/O here in case there is already something in the buffer */
		currtime = time(NULL);
		strftime(logmsg, sizeof(logmsg), "[ %b %e %H:%M:%S ", localtime(&currtime));
		write(STDERR_FILENO, logmsg, strlen(logmsg));

		snprintf(logmsg, sizeof(logmsg), "Method \"start\" exited with status %i ]\n", WEXITSTATUS(status));
		write(STDERR_FILENO, logmsg, strlen(logmsg));

		_exit(0);
	}
	
	/* 7.child.a. Close channel to parent */
	close(fd);

	/* 8. Log attempt to run start method */
	currtime = time(NULL);
	strftime(logmsg, sizeof(logmsg), "[ %b %e %H:%M:%S ", localtime(&currtime));
	write(STDERR_FILENO, logmsg, strlen(logmsg));

	snprintf(logmsg, sizeof(logmsg), "Executing start method (\"%s\") ]\n", filename);
	write(STDERR_FILENO, logmsg, strlen(logmsg));

	/* 9. execve() new image */
	argv[0] = filename;
	argv[1] = "start";
	argv[2] = NULL;
	execve_ret = execve(filename, argv, envv);

	/* 10. Abort if something has gone wrong */
	_exit(execve_ret);

	/* Handle lint-ness */
	return(TCL_ERROR);
	sri_obj = sri_obj;
}

int Tuapi_Init(Tcl_Interp *interp) {
#ifdef USE_TCL_STUBS
	const char *tclInitStubs_ret;

	/* Initialize Stubs */
	tclInitStubs_ret = Tcl_InitStubs(interp, "8.4", 0);
	if (!tclInitStubs_ret) {
		return(TCL_ERROR);
	}
#endif

	/* Kernel maintenance related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::insmod", tuapi_insmod, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::rmmod", tuapi_rmmod, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::lsmod", tuapi_lsmod, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::hostname", tuapi_hostname, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::domainname", tuapi_domainname, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::klogctl", tuapi_klogctl, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::settimeofday", tuapi_settimeofday, NULL, NULL);

	/* Block or char device related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::losetup", tuapi_losetup, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::eject", tuapi_eject, NULL, NULL);

	/* Filesystem related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::mount", tuapi_mount, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::umount", tuapi_umount, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::swapon", tuapi_swapon, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::swapoff", tuapi_swapoff, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::mknod", tuapi_mknod, NULL, NULL);

	/* Process related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::setuid", tuapi_setuid, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::getuid", tuapi_getuid, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::chroot", tuapi_chroot, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::pivot_root", tuapi_pivot_root, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::kill", tuapi_kill, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::waitpid", tuapi_waitpid, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::ps", tuapi_ps, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::execve", tuapi_execve, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::rlimit", tuapi_rlimit, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::reboot", tuapi_reboot, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::set_thread_name", tuapi_set_thread_name, NULL, NULL);

	/* Network related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::ifconfig", tuapi_ifconfig, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::route", tuapi_route, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::brctl", tuapi_brctl, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::vconfig", tuapi_vconfig, NULL, NULL);

	/* Terminal related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::stty", tuapi_stty, NULL, NULL);

	/* Needed commands for basic services Tcl lacks */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::socket_unix", tuapi_socket_unix, NULL, NULL);

	/* Service (TSMF) related commands */
	Tcl_CreateObjCommand(interp, "::tuapi::syscall::tsmf_start_svc", tuapi_tsmf_start_svc, NULL, NULL);

	/* Internal functions */
	Tcl_CreateObjCommand(interp, "::tuapi::internal::hash", tuapi_internalproc_simplehash, NULL, NULL);

	/* Define constants */
	/** Create parent namespace **/
	Tcl_CreateNamespace(interp, "::tuapi::const", NULL, NULL);

	/** Define constants, for real **/
	Tcl_ObjSetVar2(interp, Tcl_NewStringObj("::tuapi::const::HOST_NAME_MAX", -1), NULL, Tcl_NewWideIntObj(HOST_NAME_MAX), TCL_GLOBAL_ONLY);

	/* Create high-level user functions */
	Tcl_Eval(interp,
#include "tuapi.tcl.h" 
	);

	Tcl_PkgProvide(interp, "tuapi", "0.11");

	return(TCL_OK);
}
