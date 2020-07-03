#include "../apue.h"
#include <fcntl.h>

int main(int argc, char** argv)
{
	int fd;
	if (argc != 2)
		err_quit("usage: a.out <pathname>");

	if (access(argv[1], R_OK) < 0)
		err_ret("access error for %s", argv[1]);
	else
		printf("read access OK \n");

	if ((fd = open(argv[1], O_RDONLY)) < 0)
		err_ret("open error for %s", argv[1]);
	else
		printf("open for reading OK \n");

	char buf[BUFSIZ];

	fd = read(fd, buf, BUFSIZ);
	fputs(buf, stdout);

	printf("return value is %d \n", fd);

	return 0;
}
