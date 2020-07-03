#include "../apue.h"
#include <limits.h>
#include <fcntl.h>

int my_dup(int fd, int fd2)
{
	long open_max;
	int start, end;

	if (fd == fd2)
		return fd2;

	open_max = sysconf(_SC_OPEN_MAX);
	if (open_max == -1) {
#if defined (_POSIX_OPEN_MAX)
		open_max = _POSIX_OPEN_MAX;
#elif defined (FOPEN_MAX)
		open_max = FOPEN_MAX;
#else	
		err_sys("failed to get OPEN_MAX ");
#endif
	}
	
	printf("ISO C FOPEN_MAX: %ld \n", FOPEN_MAX);
	printf("POSIX.1 _POSIX_OPEN_MAX: %ld \n", _POSIX_OPEN_MAX);
	printf("XSI sysconf _SC_OPEN_MAX: %ld \n", open_max);

	start = dup(fd);
	if (start == -1)
		err_sys("dup() error! ");

	printf("start: %d \n", start);

	end = start;
	while  (end < fd2) {
		end = dup(fd);
		
		if (end == -1)
			err_sys("dup() error! ");
	}

	if (end == fd2)
		for (int i = end - 1; i >= start; i--)
			close(i);
	else {
		close(start); close(fd2);
		end = dup(fd);

		if (end == -1)
			err_sys("dup() error! ");
	}

	return end;
}

int main(void)
{
	char string[BUFSIZ];
	
	int select;
	int fd = open("hello.txt", O_CREAT | O_WRONLY, 0755);
	if (fd == -1)
		err_sys("open() error! ");
		
	fgets(string, BUFSIZ - 1, stdin);
	scanf("%d", &select);
	my_dup(fd, select);
	
	printf("%s", string);

	close(fd);

	return 0;
}
