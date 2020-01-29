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
