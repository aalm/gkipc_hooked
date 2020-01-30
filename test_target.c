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
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>

extern char *__progname;

int loopcount = 0;

void
test_func(void)
{
	printf("test_func: loopcount=%d\n", loopcount);
}

int
main(int argc, char **argv)
{
	bool first_run = true;

	test_func();

	loopcount = argc == 1 ? -1 : 10;
	printf("%s(%s) running; loopcount=%d\n", __progname,
	    loopcount == -1 ? "\"\"" : argv[1], loopcount);
	while (loopcount == -1 || --loopcount > 0) {
		printf(".");
		fflush(stdout);
		sleep(3);
		if (first_run) {
			if (!prctl(PR_SET_NAME, "main"))
				printf("prctl == 0\n");
			first_run = false;
		}
	}
	printf("done\n");
	exit(0);
}
