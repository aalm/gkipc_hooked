/*
 * Copyright (c) 2020 Artturi Alm
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>

#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>

#include <elf.h>
#ifndef __USE_GNU
#define	__USE_GNU
#endif
#include <link.h>

/* */
#include "queue.h"
#define	CTASSERT(x)	extern char _ctassert[(x) ? 1 : -1 ] \
			    __attribute__((__unused__))

#define nitems(_a)   (sizeof((_a)) / sizeof((_a)[0]))

#define	CATNX(a, b)	a ## b
#define	CAT(a, b)	CATNX(a, b)
#define	STRNX(a)	#a
#define	STR(a)		STRNX(a)

bool g_fprintf_passthru = false;
#define	DPRINTF(fmt, ...)					\
		do { if (!g_fprintf_passthru) {			\
			g_fprintf_passthru = true;		\
			fprintf(stderr, fmt, ##__VA_ARGS__);	\
			fflush(stderr);				\
			g_fprintf_passthru = false;		\
		} } while(0)

typedef int	request_t;
/*pedef void	(*abort_t)(void) __attribute__ ((noreturn));*/
typedef void	(*sighandler_t)(int);

static int g_begone = 0;

/* a list of hooked fds ? */
static SLIST_HEAD(, hooked_fd) hooked_fds = SLIST_HEAD_INITIALIZER(hooked_fds);
struct hooked_fd {
	SLIST_ENTRY(hooked_fd)	fds;
	uint32_t		hook_flags;
	int			fd;
	int			flags;
	mode_t			mode;
	char			path_name[];
};

/* something like this is used for passing "KEY"s between threads */
struct xyz {
	uint32_t  xp;
	uint32_t *yp;
	uint32_t *zp;
};

/* hooked typedef & static function pointer definition */
#define	HOOK_LIBC(x, y, z, ...)	\
    typedef x (*CATNX(y,_fp_t))(z, ##__VA_ARGS__); \
    static CATNX(y,_fp_t) CATNX(p_,y) = NULL;
#define	CHK_HOOK_FP(x)	do { \
	if (!CATNX(p_,x)) \
		CATNX(p_,x) = \
		    (CATNX(x,_fp_t))dlsym(RTLD_NEXT, STRNX(x)); \
	} while (0)
#define	HOOK_FP(x)	{ STRNX(x), &(CATNX(p_,x)) }

/* ipc_ typedef & static function pointer definition */
#define	IPC_TDD(x, y, z, ...)	\
    typedef x (*CATNX(y,_fp_t))(z, ##__VA_ARGS__); \
    static CATNX(y,_fp_t) CATNX(ipc_,y) = NULL;
#define	IPC_FPD(x)	{ STRNX(x), &(CATNX(ipc_,x)) }

/* the hooks called by 'ipc'-code */
HOOK_LIBC(sighandler_t,	signal,		int, sighandler_t);
HOOK_LIBC(int,		prctl,		int, void *);
HOOK_LIBC(int,		ioctl,		int, request_t, void *);
HOOK_LIBC(int,		access,		const char *, int);
HOOK_LIBC(int,		open,		const char *, int, mode_t);
HOOK_LIBC(int,		close,		int);
HOOK_LIBC(ssize_t,	read,		int, void *, size_t);
HOOK_LIBC(FILE *,	popen,		const char *, const char *);
HOOK_LIBC(int,		pclose,		FILE *);
HOOK_LIBC(int,		system,		const char *);
HOOK_LIBC(void *,	malloc,		size_t);
HOOK_LIBC(void,		free,		void *);

static void _hookwrap_init(void) __attribute__ ((constructor));
static void _hookwrap_fini(void) __attribute__ ((destructor));

static uint8_t *ipc_elfbuf = NULL;

/* XXX eww, do clean up */
enum {
	HOOK_NOT = 0,
	HOOK__YEP = 0,
	HOOK__RV,
	HOOK__LOOP,
	HOOK__VOID,
	HOOK_YEP = 1u << HOOK__YEP,
	HOOK_RV = 1u << HOOK__RV,
	HOOK_LOOP = 1u << HOOK__LOOP,
	HOOK_VOID = 1u << HOOK__VOID,
	HOOK__PRE = 0,
	HOOK__POST,
	HOOK_PRE = 1u << (24 + HOOK__PRE),
	HOOK_POST = 1u << (24 + HOOK__POST),
};
enum {
	HOOK_SIGNAL,
	HOOK_PRCTL,
	HOOK_OPEN,
	HOOK_CLOSE,
	HOOK_READ,
	HOOK_ACCESS,
	HOOK_IOCTL,
	HOOK_MALLOC,
	HOOK_FREE,
	HOOK_SYSTEM,
	HOOK_POPEN,
	HOOK_PCLOSE,
	HOOK_MAX,
};

static int	hook_state_machine(uint32_t, void *, void *, void *, void *);
static inline int
hook_enter(uint32_t hook, void *rv, void *a0, void *a1, void *a2)
{
	return hook_state_machine(HOOK_PRE | hook, rv, a0, a1, a2);
}
static inline int
hook_leave(uint32_t hook, void *rv, void *a0, void *a1, void *a2)
{
	return hook_state_machine(HOOK_POST | hook, rv, a0, a1, a2);
}

static void		hooked_main(void);
static void		hooked_vNetDevProc(void);
static ssize_t		get_filesz(int);
static int		read_file(const char *, uint8_t **, size_t *);
static uint32_t		ipc_sym_addr(const char *);

static struct {
	const char *name;
	int hook_flags;
	void (*hook_fp)(void);
} prctl_hooks[] = {
	{ "vNetDevProc",	HOOK_LOOP,	&hooked_vNetDevProc },
};
#if 0
static const char *prctl_2behooked[] = {
	"vNetDevProc",
};
static const void *prctl_hookfuncs[] = {
	&hooked_vNetDevProc,
};
CTASSERT(nitems(prctl_2behooked) == nitems(prctl_hookfuncs));
#endif

static struct {
	const char *path;
	int rv;
} access_hooks[] = {
/*	{ "/etc/version.ini",	-1 },*/	/* was just testing with this */
	{ "/bin/mtd_debug",	-1 },
};

/* should somehow link to file_hooks[] */
#if 0
static struct {
	/* XXX */
} read_hooks[] = {
	{},
;
#endif

static struct {
	const char	*cmd;
	uint32_t	 flags;
	int		 rv;
} system_hooks[] = {
	{ "telnetd &",	HOOK_RV,	0 },
};

static struct {
	const char	*cmd;
	uint32_t	 flags;
	int		 rv;
} popen_hooks[] = {
	{ "telnetd &",	HOOK_RV,	0 },
};
static SLIST_HEAD(, hooked_stream) hooked_streams =
	    SLIST_HEAD_INITIALIZER(hooked_streams);
struct hooked_stream {
	SLIST_ENTRY(hooked_stream)	 streams;
	uint32_t			 hook_flags;
	FILE				*stream;
	int				 rv;
	char				 command[];
};

/*
 * this should know what to do...
 */
int
hook_state_machine(uint32_t t_h, void *rv, void *arg0, void *arg1, void *arg2)
{
	static uint32_t hook_states[HOOK_MAX];
	static int hook_states_initialized = 0;
	/* XXX these pointers.. fugly; redo by passing things in a struct? */
	const char **arg0cp = arg0;
	const char **arg1cp = arg1;
	u_int *arg0up = arg0;
	u_int *arg1up = arg1;
	u_int *arg2up = arg2;
	int *arg0ip = arg0;
	int *arg1ip = arg1;
	int *rvp = rv;
	u_int hookarg  = t_h & 0xff000000;
	u_int th = t_h & 0x00ffffff;
	struct hooked_stream *hstream = NULL;
	struct hooked_fd *hfd;
	size_t tmpsz;
	u_int i;

	if (!hook_states_initialized) {
		hook_states_initialized = 1;
		memset(&hook_states[0], 0, sizeof(hook_states));
	}
	if (th >= HOOK_MAX)
		return 0;

	switch (th) {	/* XXX update states ? */
	case HOOK_SIGNAL:
		if (hookarg == HOOK_PRE) {
			DPRINTF("\tsignal signum %d handler %p\n",
			    *arg0ip, *(void **)arg1);
			return *rvp;	/* no op */
		}
		if (hook_states[th] & 1)
			return *rvp;
		if (*arg0ip != 0x13)
			return *rvp;
		DPRINTF("\n  hooking signal() return into hooked_main()\n");
		hook_states[th] |= 1;
		hooked_main();
		return (int)NULL;	/* above should never return */

	case HOOK_PRCTL:
		if (hookarg == HOOK_PRE)
			return 0;	/* no op */
		if (hook_states[th] & 1)
			return *rvp;
		if (*arg0up != PR_SET_NAME || !*(void **)arg1)
			return *rvp;
		/* option == PR_SET_NAME */
		for (i = 0; i < nitems(prctl_hooks); i++) {
			if (strcmp(*arg1cp, prctl_hooks[i].name))
				continue;
			DPRINTF("\n  hooking %s\n", prctl_hooks[i].name);
			hook_states[th] |= 1;
			prctl_hooks[i].hook_fp();
			return -1;	/* above should never return */
		}
		return *rvp;

	case HOOK_IOCTL:
		if (hookarg == HOOK_PRE)
			return *rvp;
		/* XXX check opened fds for path/filename ? */
		/* XXX check req for known netdevice(7) ioctls */
		DPRINTF("\tioctl(%d, %p, %p) == %d\n",
		    *arg0ip, *(void **)arg1, *(void **)arg2, *rvp);
		return *rvp;

	case HOOK_ACCESS:
		/* XXX block some (on entry) ? */
		if (hookarg == HOOK_PRE)
			return 0;
		for (i = 0; i < nitems(access_hooks); i++) {
			if (strcmp(*arg0cp, access_hooks[i].path))
				continue;
			DPRINTF("\n  hooking access(\"%s\", %#x) == %d into %d\n",
			    *arg0cp, *arg1up, *rvp, access_hooks[i].rv);
			*rvp = access_hooks[i].rv;
			return 0;
		}
		DPRINTF("\taccess(\"%s\", %#x) == %d\n",
		    *arg0cp, *arg1up, *rvp);
		return *rvp;

	case HOOK_OPEN:
		if (hookarg == HOOK_PRE)
			return 0;	/* no op .. for now atleast */
		tmpsz = strlen(*arg0cp);
		hfd = p_malloc(sizeof(struct hooked_fd) + tmpsz + 1);
		if (!hfd)
			return *rvp; /* idk., i guess not */
		memset(hfd, 0, sizeof(struct hooked_fd) + tmpsz + 1);
		hfd->hook_flags = 0; /* XXX */
		hfd->fd = *rvp;
		hfd->flags = *arg1ip;
		hfd->mode = *arg2up;
		strcpy(&hfd->path_name[0], *arg0cp);
		SLIST_INSERT_HEAD(&hooked_fds, hfd, fds);
		return *rvp;

	case HOOK_CLOSE:
		if (hookarg == HOOK_PRE)
			return 0;	/* no op .. for now atleast */
		SLIST_FOREACH(hfd, &hooked_fds, fds) {
			if (*arg0ip == hfd->fd)
				break;
		}
		SLIST_REMOVE(&hooked_fds, hfd, hooked_fd, fds);
		p_free(hfd);
		return *rvp;

	case HOOK_READ:
		if (hookarg == HOOK_PRE)
			return 0;
		/* XXX check the list of hooked(by open()) fds here */
		/* XXX work on redirecting the read from somewhere else ? */
		/* XXX dump the read()s to a file ? */
		return *rvp;

	case HOOK_SYSTEM:
		for (i = 0; i < nitems(system_hooks); i++) {
			if (strcmp(*arg0cp, system_hooks[i].cmd))
				continue;
			/* found match - will hook */
			DPRINTF("\n  hooking system(\"%s\") == into %d\n",
			    *arg0cp, system_hooks[i].rv);

			*rvp = hookarg == HOOK_PRE ?
			    HOOK_YEP : system_hooks[i].rv;
			return *rvp;
		}
		if (hookarg == HOOK_PRE)
			return *rvp;
		DPRINTF("\tsystem(\"%s\") == %d\n", *arg0cp, *rvp);
		return *rvp;

	case HOOK_POPEN:
		/*
		 * should we create a file for proper FILE * ?
		 * the function i had in mind just needs non-NULL
		 * pointer, so this reuses hstream below for it.
		 */
		if (hookarg == HOOK_PRE)
		for (i = 0; i < nitems(popen_hooks); i++) {
			if (strcmp(*arg0cp, popen_hooks[i].cmd))
				continue;
			/* found match - will hook */
			tmpsz = strlen(*arg0cp);
			hstream = p_malloc(sizeof(struct hooked_stream) +
			    tmpsz + 1);
			if (!hstream)
				return (int)NULL; /* idk., i guess not */
			memset(hstream, 0, sizeof(struct hooked_stream) + tmpsz + 1);
			DPRINTF("\n  hooking popen(\"%s\", \"%s\") == into %d\n",
			    *arg0cp, *arg1cp, popen_hooks[i].rv);
			hstream->stream = (FILE *)hstream;
			hstream->rv = popen_hooks[i].rv;
			strcpy(&hstream->command[0], *arg0cp);
			SLIST_INSERT_HEAD(&hooked_streams, hstream, streams);
			*(FILE **)rv = hstream->stream;
			break;
		}
		/* XXX oops, figure out if something else got left out too! */
		return *rvp;

	case HOOK_PCLOSE:
		if (hookarg == HOOK_PRE)
			return 0;	/* no op .. for now atleast */

		SLIST_FOREACH(hstream, &hooked_streams, streams) {
			if (*(FILE **)arg0 == hstream->stream)
				continue;
			*rvp = hstream->rv;
			hstream->stream = NULL;
			SLIST_REMOVE(&hooked_streams, hstream, hooked_stream, streams);
			p_free(hstream);
		}
		return *rvp;

	/* could be used to help tracking memory we care about, for free() */
	case HOOK_MALLOC:
		if (hookarg != HOOK_PRE)
			DPRINTF("\tmalloc(%zd) == %p\n", *(size_t *)arg0, *(void **)rvp);
		return *rvp;

	case HOOK_FREE:
		if (hookarg != HOOK_PRE)
			DPRINTF("\tfree(%p)\n", *(void **)arg0);
		/* could dump to a file for later checking.. */
		return *rvp;

	default:
		return 0;
	}
}

sighandler_t
signal(int signum, sighandler_t handler)
{
	sighandler_t rv;

	(void)hook_enter(HOOK_SIGNAL, &rv, &signum, &handler, NULL);
	if (!rv)
		rv = p_signal(signum, handler);
	return (sighandler_t)hook_leave(HOOK_SIGNAL, &rv, &signum, &handler,
	    NULL);
}

/*
 * ipc uses prctl() to set a thread name for atleast most threads very
 * near the beginning of responsible thread functions, so it's easy
 * to distinguish the threads we don't want prctl() returning into,
 * for taking over the control of those, w/o need to touch ipc.
 *
 * for now, we take over only vNetDevProc, which does handle networking.
 */
int
prctl(int option, ...)
{
	int rv = 0;
	va_list args;
	void *argp;

	va_start(args, option);
	argp = va_arg(args, void *);
	va_end(args);

	(void)hook_enter(HOOK_PRCTL, &rv, &option, &argp, NULL);
	if (!rv)
		rv = p_prctl(option, argp);
	return hook_leave(HOOK_PRCTL, &rv, &option, &argp, NULL);
}

int
ioctl(int fd, request_t request, ...)
{
	int rv = 0;
	va_list args;
	void *argp;

	va_start(args, request);
	argp = va_arg(args, void *);
	va_end(args);

	CHK_HOOK_FP(ioctl);
/* XXX */
/*	if (request == 0x8914)
		return -1;*/

	(void)hook_enter(HOOK_IOCTL, &rv, &fd, &request, &argp);
	if (!rv)
		rv = p_ioctl(fd, request, argp);
	return hook_leave(HOOK_IOCTL, &rv, &fd, &request, &argp);
}

int
access(const char *path, int mode)
{
	int rv = 0;

	(void)hook_enter(HOOK_ACCESS, &rv, &path, &mode, NULL);
	if (!rv)
		rv = p_access(path, mode);
	return hook_leave(HOOK_ACCESS, &rv, &path, &mode, NULL);
}

int
open(const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode;
	int rv = 0;

	va_start(args, flags);
	mode = va_arg(args, int);
	va_end(args);

	(void)hook_enter(HOOK_OPEN, &rv, &flags, &mode, NULL);
	if (!rv)
		rv = p_open(pathname, flags, mode);
	return hook_leave(HOOK_OPEN, &rv, &flags, &mode, NULL);
}

int
close(int fd)
{
	int rv = 0;

	(void)hook_enter(HOOK_CLOSE, &rv, &fd, NULL, NULL);
	if (!rv)
		rv = p_close(fd);
	return hook_leave(HOOK_CLOSE, &rv, &fd, NULL, NULL);
}

ssize_t
read(int fd, void *buf, size_t count)
{
	ssize_t rv = 0;

	(void)hook_enter(HOOK_READ, &rv, &fd, &buf, &count);
	if (!rv)
		rv = p_read(fd, buf, count);
	return hook_leave(HOOK_READ, &rv, &fd, &buf, &count);
}

FILE *
popen(const char *command, const char *type)
{
	FILE *rv = NULL;

	(void)hook_enter(HOOK_POPEN, &rv, &command, &type, NULL);
	if (!rv)
		rv = p_popen(command, type);
	DPRINTF("\tpid %d popen(\"%s\", \"%s\") == %p\n",
	    getpid(), command, type, rv);
	return (FILE *)hook_enter(HOOK_POPEN, &rv, &command, &type, NULL);
}

int
pclose(FILE *stream)
{
	int rv = 0;

	(void)hook_enter(HOOK_PCLOSE, &rv, &stream, NULL, NULL);
	if (!rv)
		rv = p_pclose(stream);
	DPRINTF("\tpid %d pclose(%p) == %d\n",  getpid(), stream, rv);
	return hook_leave(HOOK_PCLOSE, &rv, &stream, NULL, NULL);
}

int
system(const char *command)
{
	int rv = 0;

	CHK_HOOK_FP(system);
	(void)hook_enter(HOOK_SYSTEM, &rv, &command, NULL, NULL);
	if (!rv)
		rv = p_system(command);
	DPRINTF("\tpid %d system(\"%s\") == %d\n",  getpid(), command, rv);
	return hook_leave(HOOK_SYSTEM, &rv, &command, NULL, NULL);
}

void *
malloc(size_t size)
{
	void *rv = NULL;

	CHK_HOOK_FP(malloc);

	(void)hook_enter(HOOK_MALLOC, &rv, &size, NULL, NULL);
	if (!rv)
		rv = p_malloc(size);
	return (void *)hook_leave(HOOK_MALLOC, &rv, &size, NULL, NULL);
}

void
free(void *ptr)
{
	int rv = 0;

	CHK_HOOK_FP(free);

	(void)hook_enter(HOOK_FREE, &rv, &ptr, NULL, NULL);
	if (!rv)
		p_free(ptr);
	(void)hook_leave(HOOK_FREE, &rv, &ptr, NULL, NULL);
}

/* allocate memory + read a file */
static int
read_file(const char *path, uint8_t **buf, size_t *len)
{
	ssize_t fs, r, n = 0;
	int fd;

	CHK_HOOK_FP(open);
	CHK_HOOK_FP(read);
	CHK_HOOK_FP(close);

	*buf = NULL;
	if (len)
		*len = 0;

	/* open file */
	if ((fd = p_open(path, O_RDONLY, 0)) < 0)
		return -1;
	/* get file size */
	if ((fs = get_filesz(fd)) <= 0)
		return -1;
	if (len)
		*len = fs;
	/* allocate mem */
	if ((*buf = realloc(NULL, fs)) == NULL)
		goto rfail;

	/* read file */
	while (n < fs) {
		r = p_read(fd, *buf + n, fs);
		if (r < 0)
			goto rfail;
		n += r;
		if (r == 0 && n != fs)
			goto rfail;
	}
	p_close(fd);
	return 0;
rfail:
	if (*buf) {
		p_free(*buf);
		*buf = NULL;
	}
	p_close(fd);
	return -1;
}

static ssize_t
get_filesz(int fd)
{
	ssize_t rv, rsz;
	char tmp[0x400];

	CHK_HOOK_FP(read);

	/* try seeking to the end */
	rv = lseek(fd, 0, SEEK_END);
	if (rv > 0) {
		lseek(fd, 0, SEEK_SET);
		return rv;
	}
	/* nope, read to the end.. */
	for (rv = 0, rsz = 1; rsz > 0; rv += rsz) {
		rsz = p_read(fd, tmp, 0x400);
		if (rsz < 0)
			return -1;
	}
	lseek(fd, 0, SEEK_SET);	/* reset to beginning */
	return rv;
}

static uint32_t
ipc_sym_addr(const char *name)
{
	Elf32_Ehdr *eh = (Elf32_Ehdr *)ipc_elfbuf;
	Elf32_Shdr *sh = (Elf32_Shdr *)&ipc_elfbuf[eh->e_shoff];
	const char *symstp, *symname;
	Elf32_Sym *sym;
	int i, symcnt;

	for (i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type != SHT_SYMTAB &&
		    sh[i].sh_type != SHT_DYNSYM)
			continue;
		if (sh[i].sh_size == 0 ||
		    sh[i].sh_entsize == 0)
			continue; /* print error ? */

		symstp = (char *)&ipc_elfbuf[sh[sh[i].sh_link].sh_offset];
		sym = (Elf32_Sym *)&ipc_elfbuf[sh[i].sh_offset];
		symcnt = sh[i].sh_size / sh[i].sh_entsize;

		for (; symcnt > 0; symcnt--, sym++) {
			symname = (char *)((int)symstp + sym->st_name);
			if (strcmp(symname, name))
				continue;
#if 1
			printf("  [%d]",
			    (sh[i].sh_size / sh[i].sh_entsize) - symcnt);
			printf("\t%u ", sym->st_size);
			printf("\t%p ", (void *)sym->st_value);
			printf("\t%s\n", &symstp[sym->st_name]);
#endif
			if (sym->st_value == 0) {
				printf("%s(..., \"%s\") sym->st_value == 0\n",
				    __func__, &symstp[sym->st_name]);
				exit(1);
			}
			return sym->st_value;
		}
	}
	return 0;
}

/*
 * the symbols in use from the target 'ipc'
 *
 * rnd observations; the naming is broken for some symbols,
 * and you shouldn't trust the 'v', 'fg' 'i' etc. prefixes,
 * but instead manually verify by looking at the disassembly.
 */
/* does check the cmdline params, first in main() */
IPC_TDD(void,		vCMOS_SetSensorType,	u_int);
IPC_TDD(void,		vSetThreadName,		const char *);

/* these get called by vIpcInit() in this order */
IPC_TDD(void,		vGetConfigInfo,		void);
IPC_TDD(void *,		psGetDevDefaultInfo,	void);
IPC_TDD(void *,		pGetDevFunction,	void);
IPC_TDD(void *,		pGetSetting,		void);
IPC_TDD(void,		vSettingInit,		void);
IPC_TDD(void,		vUPG_Init,		void);
IPC_TDD(void,		vGPIO_PinAssignInit,	void);
IPC_TDD(void,		vI2CInit,		void);
IPC_TDD(void,		vUartInit,		void);
IPC_TDD(void,		vGatewayDevTypeInit,	void);
/*C_TDD(void,		vSaveSetting,		void);*/
IPC_TDD(void,		vDevTypeInit,		void);
IPC_TDD(int,		iUSER_Init,		void);
IPC_TDD(int,		iPUSH_Init,		void);
IPC_TDD(void,		vVarInit,		void);
IPC_TDD(void,		vKeyInit,		void);

/* rnd symbols for testing / later use */
IPC_TDD(char *,		pcGetMyUID,		void);
/* fgNET_SetStaticIPWithStr("192.168.88.1", "192.168.88.1", "255.255.255.0", 0, pWifiName); */
IPC_TDD(u_int,		fgNET_SetStaticIPWithStr,
    char *, char *, char *, char *, char *);
#if 0
IPC_TDD(void,		vCMOS_SetSensorType,	uint32_t);
IPC_TDD(int,		iKEY_Get,		struct xyz *);
IPC_TDD(int,		iWDG_feed,		int);
IPC_TDD(uint32_t,	fgKeyCommProc,		uint32_t,
    uint32_t *, uint32_t *);
IPC_TDD(void *,		pGetTimerHandlerHead,	void);
IPC_TDD(void,		vTimerHandler,		void *);
IPC_TDD(void,		vTIMER_TASK_Handle,	int);
IPC_TDD(uint32_t,	dwTimeCurrSec,		uint32_t);
#endif
static struct {
	const char *name;
	void *fp;
} hook_fps[] = {
	HOOK_FP(malloc),
	HOOK_FP(free),
	HOOK_FP(open),
	HOOK_FP(read),
	HOOK_FP(close),
	HOOK_FP(signal),
	HOOK_FP(prctl),
	HOOK_FP(ioctl),
	HOOK_FP(access),
	HOOK_FP(popen),
	HOOK_FP(pclose),
	IPC_FPD(vCMOS_SetSensorType),
	IPC_FPD(vSetThreadName),
	IPC_FPD(vGetConfigInfo),
	IPC_FPD(psGetDevDefaultInfo),
	IPC_FPD(pGetDevFunction),
	IPC_FPD(pGetSetting),
	IPC_FPD(vSettingInit),
	IPC_FPD(vUPG_Init),
	IPC_FPD(vGPIO_PinAssignInit),
	IPC_FPD(vI2CInit),
	IPC_FPD(vUartInit),
	IPC_FPD(vGatewayDevTypeInit),
	IPC_FPD(vDevTypeInit),
	IPC_FPD(pcGetMyUID),
	IPC_FPD(fgNET_SetStaticIPWithStr),
	IPC_FPD(iUSER_Init),
	IPC_FPD(iPUSH_Init),
	IPC_FPD(vVarInit),
};
static void
our_vIpcInit(void)
{
/*	int iVar1;
	int iVar2;
	int iVar3;*/
/* XXX	uint uVar4;*/
/* XXX	uint uVar5;
	char *pcVar6;
	time_t tVar7;
	tm local_60;
	undefined auStack52 [28];
	time_t local_18;
	int local_14;*/

/* XXX	if (iLOG_CheckCapture() == 0)
		DAT_0039072c = 1;*/

/*	vCMOS_SensorTypeInit(); no-op in binary, simply void (){ return; } */

	ipc_vGetConfigInfo();

/*	iVar1 = (int)ipc_psGetDevDefaultInfo();
	iVar2 = (int)ipc_pGetDevFunction();
	iVar3 = (int)ipc_pGetSetting();*/
/* XXX	if ((*(byte *)(iVar1 + 0x140) & 1) != 0) {
		system_cmd("telnetd &");
	}*/

/* XXX	uVar4 = dwGetTimeMS();
	printf("line=%d,costms=%u %s\n",0x30b3,uVar4,"vIpcInit");*/

	ipc_vSettingInit();

/* XXX	vUPG_Init();*/
/* XXX	vGPIO_PinAssignInit();*/
/* XXX	vI2CInit();*/
/* XXX	vUartInit();*/
	ipc_vGatewayDevTypeInit();

/* XXX	if ((*(byte *)(iVar2 + 2) & 0x20) == 0) {
		iVar2 = strcmp((char *)(iVar3 + 0x96b),"admin");
		if (iVar2 == 0) {
			memcpy((char *)(iVar3 + 0x96b),"1234",5);
			memcpy((void *)(iVar1 + 0x148),"1234",5);
			printf("force set privacy pwd to 1234");
			puts("\r");
			vSaveSetting();
		}
	}*/
	ipc_vDevTypeInit();
	ipc_iUSER_Init();
	ipc_iPUSH_Init();

/* XXX	ipc_vVarInit(); segfaults... */

/* XXX	ipc_vKeyInit();*/
/* XXX	vZS_ENCRY_Handle();
	vDELAY_TASK_Init();
	vGpioDevInit();
	vTimerModuleInit();
	iVar2 = pGetDevFunction();
	if ((*(byte *)(iVar2 + 2) & 2) != 0) {
		vStartUartRecv();
	}
	vAudioDevTypeInit();
	iDsaInit();
	vMotorInit();*/

/* XXX	local_60.tm_sec = 0;
	local_60.tm_year = 0x73;
	local_60.tm_mon = 0;
	local_60.tm_mday = 1;
	local_60.tm_hour = 0;
	local_60.tm_min = 0;
	local_18 = mktime(&local_60);
	uVar5 = dwGetRandomData();
	local_18 = local_18 + uVar5 + ((uVar5 >> 4) / 0xd2f) * -54000;
	iVar2 = iRTC_GetTime(auStack52,(uVar5 >> 4) * 0x26d60dd);
	if ((iVar2 == 0) &&
	    (iVar2 = lRtcTimeToTimestamp(auStack52), local_18 < iVar2)) {
		vPrintRtcTime();
		local_18 = iVar2;
	}
	stime(&local_18);
	pcVar6 = ctime(&local_18);
	printf("set time:%s\n",pcVar6);
	fgRock_COMM_SetBasePts();
	uVar4 = dwGetTimeMS();
	printf("line=%d,costms=%u %s\n",0x315a,uVar4,"vIpcInit");
	vRMM_BufferInit();
	fgRMM_Init(0);
	if ((*(byte *)(iVar1 + 0x169) & 0x10) != 0) {
		iVar1 = 399;
		do {
			iVar2 = iDT_GetInitStat();
			if (iVar2 != 0)
				break;
			iVar1 = iVar1 + -1;
			usleep(20000);
		} while (iVar1 != -1);
		printf("rrrr=%d",iVar1);
		puts("\r");
	}*/

/* XXX	uVar4 = dwGetTimeMS();
	printf("line=%d,costms=%u %s\n",0x317b,uVar4,&DAT_002c0f7c);*/
/* XXX	vNetDevInit();*/
/* XXX	uVar4 = dwGetTimeMS();
	printf("line=%d,costms=%u %s\n",0x3187,uVar4,"net e");
	P2P_MISC_StartProc();
	DISK_InitSdCard();
	FILE_LIST_Init();
	vAlarmInit();
	iVar1 = pGetSetting();
	if ((*(byte *)(iVar1 + 3) & 2) == 0) {
		iVar1 = pGetSetting();
		*(byte *)(iVar1 + 3) = *(byte *)(iVar1 + 3) | 2;
		vSaveSetting();
	}
	iVar1 = access("/data/upg_flag_lan.ini",0);
	if (iVar1 == 0) {
		dwGetValueFromFileContentIsNum("/data/upg_flag_lan.ini");
		local_14 = sGetFirmwareVersion();
		remove("/data/upg_flag_lan.ini");
	}
	iVar1 = access("/data/upg_flag_http.ini",0);
	if (iVar1 == 0) {
		iVar1 = dwGetValueFromFileContentIsNum("/data/upg_flag_http.ini");
		local_14 = sGetFirmwareVersion();
		if (iVar1 == local_14) {
			tVar7 = time((time_t *)0x0);
			printf("[%d %s,%s, %d ]=>diff \r\n",
			    tVar7,"ipc.c","vCheckUpgSucessHandle",0x115d);
		} else {
			global_state_ntp_synced_etc._0_1_ =
			    (byte)global_state_ntp_synced_etc | 2;
			tVar7 = time((time_t *)0x0);
			printf("[%d %s,%s, %d ]=>ok \r\n",
			    tVar7,"ipc.c","vCheckUpgSucessHandle",0x1159);
		}
		remove("/data/upg_flag_http.ini");
	}
	iWDG_init(5);
	uVar4 = dwGetTimeMS();
	printf("line=%d,costms=%u %s\n",0x321e,uVar4,"ipc e");
	DAT_003906ff = DAT_003906ff | 0x40;
	return;*/

}

/* not the first symbol i had named myself, and forgotten about */
void
our_vCheckInputPara(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	/* the set sensor type, what most certainly dealt from elsewhere too */;
	ipc_vCMOS_SetSensorType(0x19);
}

static void
hooked_main(void)
{
	static char *fake_argv[] = { "ipc",  "sensortype=sc1135", NULL };

	our_vCheckInputPara(2, &fake_argv[0]);
	ipc_vSetThreadName("main");
	our_vIpcInit();

	printf("  got myuid \"%s\"\n", ipc_pcGetMyUID());

	exit(0);
	while (!g_begone) {
	}
	exit(1);
}

/* XXX TOBEDONE */
static void
hooked_vNetDevProc(void)
{
	int loop_count = 0;

	while (!g_begone) {
		sleep(5);
		if (loop_count++ > 300) {
			loop_count = 0;
/*			if (ipc_))
				ipc_();*/
		}
	}
}

/* these are pretty useless */
static int hookcnt = 0;
static void
_hookwrap_init(void)
{
	u_int i;

	DPRINTF("%s %d\n", __func__, ++hookcnt);
	for (i = 0; i < /*nitems(hook_fps)*/HOOK_MAX; i++) {
		if (!hook_fps[i].name ||
		    !hook_fps[i].fp)
			goto failout;
		*(void **)hook_fps[i].fp =
		    (void *)dlsym(RTLD_NEXT, hook_fps[i].name);
	}

	if (!ipc_elfbuf)
		if (read_file("./ipc", &ipc_elfbuf, NULL) != 0 || !ipc_elfbuf)
			exit(1);

	for (i = HOOK_MAX - 1; i < nitems(hook_fps); i++) {
		if (!hook_fps[i].name ||
		    !hook_fps[i].fp)
			goto failout;
		*(void **)hook_fps[i].fp =
		    (void *)ipc_sym_addr(hook_fps[i].name);
	}
	return;
failout:
	exit(1);
}
static void
_hookwrap_fini(void)
{
	DPRINTF("%s %d\n", __func__, --hookcnt);
	if (ipc_elfbuf)
		p_free(ipc_elfbuf);
	ipc_elfbuf = NULL;
}
