#include "../apue.h"
#include <fcntl.h>

int main(int argc, char** argv)
{
	int target, dest;
	int cnt;
	char buffer[BUFSIZ];

	if (argc != 3)
		err_quit("usage: %s <target> <destination>", argv[0]);

	target = open(argv[1], O_RDONLY, S_IRWXU);
	if (target == -1)
		err_sys("open() target error!");

	dest = open(argv[2], O_WRONLY | O_CREAT, S_IRWXU);
	if (dest == -1)
		err_sys("open() dest error!");

	while ((cnt = read(target, buffer, BUFSIZ)) > 0) {
		if (cnt == -1)
			err_sys("read() error!");
		
		for (int i = 0; i < cnt; i++)
			if (buffer[i] != 0)
				if (write(dest, &buffer[i], 1) == -1)
					err_sys("write error!");
	}

	if (close(target)	== -1
	||	close(dest)		== -1)
		err_sys("close() error!");

	return 0;
}
