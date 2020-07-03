#include "../apue.h"
#include <fcntl.h>

#define TEST_STR ("hello world! \n")

int main(void)
{
	int fd;

	fd = open("test.txt", O_WRONLY | O_CREAT, S_IRWXU);
	if (fd == -1)
		err_sys("open error!");

	for (int i = 0; i < 10; i++) {
		if (lseek(fd, i * (1024 * 10), SEEK_SET) == -1)
			err_sys("lseek error!");

		if (write(fd, TEST_STR, strlen(TEST_STR) + 1) == -1)
			err_sys("write error!");
	}

	if (close(fd) == -1)
		err_sys("close error!");
	return 0;
}
