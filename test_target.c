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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <signal.h>

#define nitems(_a)   (sizeof((_a)) / sizeof((_a)[0]))

enum {
	HOOK_PRCTL,
	HOOK_ACCESS,
	HOOK_OPEN,
	HOOK_MALLOC,
	HOOK_READ,
	HOOK_CLOSE,
	HOOK_FREE,
	HOOK_SYSTEM,
	HOOK_IOCTL,
	HOOK_POPEN,
	HOOK_PCLOSE,
	HOOK_SIGNAL,
	HOOK_MAX,
};
typedef int	request_t;
typedef void	(*sighandler_t)(int);

extern char *__progname;

int loopcount = 0;

void
test_func(int lpcnt)
{
	printf("test_func: lpcnt=%d\n", lpcnt);
	exit(lpcnt);
}

struct {
	const char *threadname;
	const char *file2read;
	const char *accesspath;
	const char *systemcmd;
	int signalnum;
} test_args_set[] = {
	{
		"vNetDevProc",
		"./ipc",
		"./ipc",
		"printf asdfg\\n",
		-1,
	},
	{
		"main",
		"./ipc",
		"/bin/mtd_debug",
		"printf fail\\n",
		0x13,
	},
};

int
main(int argc, char **argv)
{
	const char *targ = NULL;
	uint8_t *tmpbuf = NULL;
	size_t tmpsz = 0;
	ssize_t rvsz = 0;
	void *rvp = NULL;
	int fd = -1;
	int tv = -1;
	int rv;
	u_int i;

	printf("%s(\"%s ...\") running;\n", __progname,
	    argc >= 2 ? argv[1] : "");

	for (i = 0; i < nitems(test_args_set); i++) {
		printf("\n:");
		fflush(stdout);
		sleep(1);

	while (loopcount < HOOK_MAX) {
		printf(".");
		fflush(stdout);
		sleep(1);
		switch (loopcount++) {
		case HOOK_PRCTL:
			targ = test_args_set[i].threadname;
			rv = prctl(PR_SET_NAME, targ);
			printf("  prctl(PR_SET_NAME, \"%s\") == %d\n",
			    targ, rv);
			break;

		case HOOK_ACCESS:
			targ = test_args_set[i].accesspath;
			rv = access(targ, 0);
			printf("  access(\"%s\", 0) == %d\n", targ, rv);
			break;

		case HOOK_OPEN:
			targ = test_args_set[i].file2read;
			if ((fd = open(targ, O_RDONLY, 0)) < 0) {
				printf("open() failed\n");
				exit(1);
			}
			printf("  open(\"%s\", ...) == %d\n", targ, fd);
			break;

		case HOOK_MALLOC:
			if ((rvsz = lseek(fd, 0, SEEK_END)) <= 0) {
				printf("lseek() failed\n");
				exit(1);
			}
			lseek(fd, 0, SEEK_SET);
			tmpsz = rvsz;
			tmpbuf = malloc(tmpsz);
			if (tmpbuf)
				printf("  malloc(%zd) == %p\n", tmpsz, tmpbuf);
			break;

		case HOOK_READ:
			if (!tmpbuf || !tmpsz) {
				printf("skipping read(..., %p, %zd)\n",
				    tmpbuf, tmpsz);
				break;
			}
			rv = read(fd, tmpbuf, tmpsz);
			if ((size_t)rv != tmpsz) {
				printf("read() failed\n");
				exit(1);
			}
			printf("  read(%d, %p, ...) == %zd\n",
			    fd, tmpbuf, tmpsz);
			break;

		case HOOK_CLOSE:
			close(fd);
			break;

		case HOOK_FREE:
			if (tmpbuf)
				free(tmpbuf);
			tmpbuf = NULL;
			break;

		case HOOK_SYSTEM:
			targ = test_args_set[i].systemcmd;
			rv = system(targ);
			printf("  system(\"%s\") == %d\n", targ, rv);
			break;

		case HOOK_IOCTL:
			/* XXX */
			break;

		case HOOK_POPEN:
			/* XXX */
		case HOOK_PCLOSE:
			/* XXX */
			break;

		case HOOK_SIGNAL:
			tv = test_args_set[i].signalnum;
			if (tv < 0)
				break;	/* skip */
			if (!(rvp = signal(tv, (sighandler_t)&test_func))) {
				printf("signal() failed\n");
				exit(1);
			}
			printf("  signal(%d, ...) == %p\n", tv, rvp);
			break;
		default:
			break;
		}
	}
		loopcount = 0;
	}
	exit(0);
}
