#define _LINUX_SOURCE 1
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <tcl.h>

#include <linux/sockios.h>
#include <linux/route.h>
#include <linux/if.h>
#include <linux/if_arp.h>
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

/* User environment, for execve */
extern char **environ;

/* Re-implement these if needed */
#ifdef SYS_init_module
static int init_module(void *val, unsigned long len, const char *args) {
	return(syscall(SYS_init_module, val, len, args));
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
static unsigned long tclsystem_internal_simplehash(const void *databuf, int datalen) {
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

static unsigned long tclsystem_internal_simplehash_obj(Tcl_Obj *tcl_data) {
	unsigned long retval;
	char *data;
	int datalen = -1;

	data = Tcl_GetStringFromObj(tcl_data, &datalen);

	retval = tclsystem_internal_simplehash(data, datalen);

	return(retval);
}

#if 0
/* NOTUSED: Uncomment when needed: */
static unsigned long tclsystem_internal_simplehash_str(const char *data) {
	unsigned long retval;
	int datalen;

	datalen = strlen(data);

	retval = tclsystem_internal_simplehash(data, datalen);

	return(retval);
}
#endif

static int tclsystem_internalproc_simplehash(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	unsigned long hashval;
	Tcl_Obj *hashval_obj;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::internal::hash value\"", -1));

		return(TCL_ERROR);
	}

	hashval = tclsystem_internal_simplehash_obj(objv[1]);

	hashval_obj = Tcl_NewObj();
	Tcl_SetWideIntObj(hashval_obj, hashval);

	Tcl_SetObjResult(interp, hashval_obj);

	return(TCL_OK);
}

/*
 * Low-level System Call Wrapper Procedures
 *
 * These procedures should minimally wrap Linux or UNIX system calls to
 * expose to the Tcl-level.  Where possible accept symbolic names rather
 * than numeric values (.e.g, list of values to OR together to get flags).
 */
static int tclsystem_mount(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *mountflags_obj, **mountflags_list, *mountflag;
	int mountflags_list_len;
	char *source, *target, *fstype;
	unsigned long mountflags = 0;
	void *data = NULL;
	int mount_ret, tcl_ret;

	if (objc < 5 || objc > 6) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall::mount source target fstype mountflags ?data?\"", -1));

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

		switch (tclsystem_internal_simplehash_obj(mountflag)) {
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

static int tclsystem_umount(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj **flags, *flag;
	Tcl_Obj *pathname_obj;
	char *pathname;
	int umount2_flags = 0;
	int flags_cnt;
	int chk_ret, tcl_ret;

	if (objc < 2 || objc > 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"system::syscall::umount dir ?flags?\"", -1));

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

			switch (tclsystem_internal_simplehash_obj(flag)) {
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

static int tclsystem_swapon(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *pathname;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"system::syscall::swapon pathname\"", -1));

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

static int tclsystem_swapoff(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *pathname;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"system::syscall::swapoff pathname\"", -1));

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

static int tclsystem_insmod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Channel fd;
	Tcl_Obj *module_filename, *module_data;
	void *module_data_val;
	int module_data_len;
	int read_ret, chk_ret;

	if (objc < 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"system::syscall::insmod filename ?args ...?\"", -1));

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

	chk_ret = init_module(module_data_val, module_data_len, "");
	if (chk_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(strerror(errno), -1));

		return(TCL_ERROR);
	}

	return(TCL_OK);
}

static int tclsystem_rmmod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_lsmod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_hostname(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
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

static int tclsystem_domainname(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_chroot(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *pathname;
	int chk_ret;

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall:chroot pathname\"", -1));

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

static int tclsystem_pivot_root(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *new_root, *put_old;
	int chk_ret;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall::pivot_root new_root put_old\"", -1));

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

static int tclsystem_mknod(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_getuid(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_kill(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_Obj *signal_obj;

	Tcl_WideInt pid_wide, sig_wide;
	pid_t pid;
	int sig;
	int kill_ret, tcl_ret;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall::kill pid sig\"", -1));

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
		switch (tclsystem_internal_simplehash_obj(signal_obj)) {
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

static int tclsystem_ps(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_execve(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char **argv = NULL;
	char *file;
	int idx;

	if (objc < 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall::execve file ?args ...?\"", -1));

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

static int tclsystem_losetup(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	char *file, *loopdev;
	int chk_ret;
	int loopfd, filefd;

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall::losetup loopdev file\"", -1));

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

static void tclsystem_private_append_sockaddr_to_tclobj(Tcl_Interp *interp, Tcl_Obj *list, char *header, struct sockaddr *addr) {
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

static int tclsystem_private_get_sockaddr_from_obj(Tcl_Obj *value, void *target) {
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

static int tclsystem_ifconfig_list(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock) {
	Tcl_Obj *tcl_iface_list;
	struct ifconf ifaces_cfg;
	struct ifreq *iface_req = NULL;
	int iface_req_cnt = 224, iface_req_len;
	int idx, iface_cnt;
	int ioctl_ret, tcl_ret;

	iface_req_len = iface_req_cnt * sizeof(iface_req);
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

static int tclsystem_ifconfig_info(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock, int sock_v4, int sock_v6) {
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
			case ARPHRD_CAN:
				link_encap = "can";
				break;
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
			tclsystem_private_append_sockaddr_to_tclobj(interp, retlist, "address", &iface_req.ifr_addr);
		}

		if (flag_pointopoint) {
			/* Point-to-Point interfaces */
			ioctl_ret = ioctl(sock_v4, SIOCGIFDSTADDR, &iface_req);
			if (ioctl_ret == 0) {
				tclsystem_private_append_sockaddr_to_tclobj(interp, retlist, "destination", &iface_req.ifr_addr);
			}
		}

		if (flag_broadcast) {
			/* Broadcast interfaces */
			ioctl_ret = ioctl(sock_v4, SIOCGIFBRDADDR, &iface_req);
			if (ioctl_ret == 0) {
				tclsystem_private_append_sockaddr_to_tclobj(interp, retlist, "broadcast", &iface_req.ifr_addr);
			}
		}

		ioctl_ret = ioctl(sock_v4, SIOCGIFNETMASK, &iface_req);
		if (ioctl_ret == 0) {
			tclsystem_private_append_sockaddr_to_tclobj(interp, retlist, "netmask", &iface_req.ifr_addr);
		}
	}

	Tcl_SetObjResult(interp, retlist);

	return(TCL_OK);
}

static int tclsystem_ifconfig_conf(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock, int sock_v4, int sock_v6) {
	Tcl_Obj *option_name_obj, *option_val_obj;
	Tcl_Obj **flags_objv;
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

		switch (tclsystem_internal_simplehash_obj(option_name_obj)) {
			case 0x6d9870f3: /* flags */
				flags = 0;

				tcl_ret = Tcl_ListObjGetElements(interp, option_val_obj, &flags_objc, &flags_objv);
				if (tcl_ret != TCL_OK) {
					return(tcl_ret);
				}

				for (; flags_objc > 0; flags_objc--,flags_objv++) {
					switch (tclsystem_internal_simplehash_obj(flags_objv[0])) {
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
			case 0x1b7a75: /* mtu */
			case 0x7c3891f2: /* hwaddr */
			case 0xbf72a969: /* addmulti */
			case 0xba708969: /* delmulti */
			case 0xdd876e5: /* name */
					Tcl_SetObjResult(interp, Tcl_ObjPrintf("option \"%s\" unsupported", Tcl_GetString(option_name_obj)));

					return(TCL_ERROR);
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

				parse_ret = tclsystem_private_get_sockaddr_from_obj(option_val_obj, tmp_ioctl_addr);
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

static int tclsystem_ifconfig(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	int sock_v4, sock_v6, sock;
	int retval = TCL_ERROR;

	/*
	 * Check for IPv4 support before trying to create an IPv4 socket to
	 * avoid demand-loading IPv4 (XXX: TODO)
	 */
	sock_v4 = socket(AF_INET, SOCK_DGRAM, 0);

	/*
	 * Check for IPv6 support before trying to create an IPv6 socket to
	 * avoid demand-loading IPv6 (XXX: TODO)
	 */
	sock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);

	/* Pick a socket to query for the interface list */
	if (sock_v4 == -1 && sock_v6 == -1) {
		/* Report failure */
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create socket", -1));

		return(TCL_ERROR);
	}

	if (sock_v6 != -1) {
		sock = sock_v6;
	} else {
		sock = sock_v4;
	}

	switch (objc) {
		case 0:
		case 1: /* No arguments, list all interfaces */
			retval = tclsystem_ifconfig_list(cd, interp, objc, objv, sock);

			break;
		case 2: /* One argument, give information about the interface */
			retval = tclsystem_ifconfig_info(cd, interp, objc, objv, sock, sock_v4, sock_v6);

			break;
		default:
			/* Otherwise, configure the interace */
			retval = tclsystem_ifconfig_conf(cd, interp, objc, objv, sock, sock_v4, sock_v6);

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

static int tclsystem_route_list(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock_v4, int sock_v6) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("not implemented", -1));

	return(TCL_ERROR);
}

static int tclsystem_route_conf(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[], int sock_v4, int sock_v6) {
	Tcl_WideInt option_val_wide; 
	Tcl_Obj *operation_obj, *dest_obj, *destmask_obj;
	Tcl_Obj *option_name_obj, *option_val_obj;
	struct rtentry route;
	int sock;
	int ioctl_id;
	int tcl_ret, ioctl_ret, parse_ret;

	if (objc < 4) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"::system::syscall::route operation destination destination_mask ?options?\"", -1));

		return(TCL_ERROR);
	}

	/* Clear object values */
	memset(&route, 0, sizeof(route));

	/* Determine operation */
	operation_obj = objv[1];
	switch (tclsystem_internal_simplehash_obj(operation_obj)) {
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
	parse_ret = tclsystem_private_get_sockaddr_from_obj(dest_obj, &route.rt_dst);
	if (parse_ret != 0) {
		Tcl_SetObjResult(interp, Tcl_ObjPrintf("unable to parse \"%s\" as an address", Tcl_GetString(dest_obj)));

		return(TCL_ERROR);
	}

	/* Parse destination netmask */
	destmask_obj = objv[3];
	parse_ret = tclsystem_private_get_sockaddr_from_obj(destmask_obj, &route.rt_genmask);
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

		switch (tclsystem_internal_simplehash_obj(option_name_obj)) {
			case 0x4c727779: /* gateway */
				parse_ret = tclsystem_private_get_sockaddr_from_obj(option_val_obj, &route.rt_gateway);
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

static int tclsystem_route(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	int sock_v4, sock_v6, sock;
	int retval = TCL_ERROR;

	/*
	 * Check for IPv4 support before trying to create an IPv4 socket to
	 * avoid demand-loading IPv4 (XXX: TODO)
	 */
	sock_v4 = socket(AF_INET, SOCK_DGRAM, 0);

	/*
	 * Check for IPv6 support before trying to create an IPv6 socket to
	 * avoid demand-loading IPv6 (XXX: TODO)
	 */
	sock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);

	/* Pick a socket to query for the interface list */
	if (sock_v4 == -1 && sock_v6 == -1) {
		/* Report failure */
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create socket", -1));

		return(TCL_ERROR);
	}

	if (sock_v6 != -1) {
		sock = sock_v6;
	} else {
		sock = sock_v4;
	}

	switch (objc) {
		case 0:
		case 1: /* No arguments, list all interfaces */
			retval = tclsystem_route_list(cd, interp, objc, objv, sock_v4, sock_v6);

			break;
		default:
			/* Otherwise, modify routes */
			retval = tclsystem_route_conf(cd, interp, objc, objv, sock_v4, sock_v6);

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

int System_Init(Tcl_Interp *interp) {
#ifdef USE_TCL_STUBS
	const char *tclInitStubs_ret;

	/* Initialize Stubs */
	tclInitStubs_ret = Tcl_InitStubs(interp, "8.4", 0);
	if (!tclInitStubs_ret) {
		return(TCL_ERROR);
	}
#endif

	/* Kernel maintenance related commands */
	Tcl_CreateObjCommand(interp, "::system::syscall::insmod", tclsystem_insmod, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::rmmod", tclsystem_rmmod, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::lsmod", tclsystem_lsmod, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::hostname", tclsystem_hostname, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::domainname", tclsystem_domainname, NULL, NULL);

	/* Block or char device related commands */
	Tcl_CreateObjCommand(interp, "::system::syscall::losetup", tclsystem_losetup, NULL, NULL);

	/* Filesystem related commands */
	Tcl_CreateObjCommand(interp, "::system::syscall::mount", tclsystem_mount, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::umount", tclsystem_umount, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::swapon", tclsystem_swapon, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::swapoff", tclsystem_swapoff, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::mknod", tclsystem_mknod, NULL, NULL);

	/* Process related commands */
	Tcl_CreateObjCommand(interp, "::system::syscall::getuid", tclsystem_getuid, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::chroot", tclsystem_chroot, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::pivot_root", tclsystem_pivot_root, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::kill", tclsystem_kill, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::ps", tclsystem_ps, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::execve", tclsystem_execve, NULL, NULL);

	/* Network related commands */
	Tcl_CreateObjCommand(interp, "::system::syscall::ifconfig", tclsystem_ifconfig, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::system::syscall::route", tclsystem_route, NULL, NULL);

	/* Internal functions */
	Tcl_CreateObjCommand(interp, "::system::internal::hash", tclsystem_internalproc_simplehash, NULL, NULL);

	/* Define constants */
	/** Create parent namespace **/
	Tcl_CreateNamespace(interp, "::system::const", NULL, NULL);

	/** Define constants, for real **/
	Tcl_ObjSetVar2(interp, Tcl_NewStringObj("::system::const::HOST_NAME_MAX", -1), NULL, Tcl_NewWideIntObj(HOST_NAME_MAX), TCL_GLOBAL_ONLY);

	/* Create high-level user functions */
	Tcl_Eval(interp,
#include "system.tcl.h" 
	);

	Tcl_PkgProvide(interp, "system", "0.1");

	return(TCL_OK);
}