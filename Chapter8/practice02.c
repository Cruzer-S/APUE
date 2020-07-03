#include "../apue.h"
#include <dirent.h>
#include <fcntl.h>

int main(void)
{
	DIR* dir_ent;
	int dir_fd;
	int flag;

	if ((dir_ent = opendir("/")) == NULL)
		err_sys("opendir() error");

	if((dir_fd = dirfd(dir_ent)) == -1)
		err_sys("dirfd() error");

	if ((flag = fcntl(dir_fd, F_GETFD, FD_CLOEXEC)) == -1)
		err_sys("fcntl() error");

	printf("FD_CLOEXEC with opendir: %d \n", flag);

	if (closedir(dir_ent) == -1)
		err_sys("closedir() error");

	
	if ((dir_fd = open("/", O_RDONLY | O_DIRECTORY)) == -1)
		err_sys("open() error");

	if ((flag = fcntl(dir_fd, F_GETFD, FD_CLOEXEC)) == -1)
		err_sys("fcntl() error");

	printf("FD_CLOEXEC with open: %d \n", flag);

	if (close(dir_fd) == -1)
		err_sys("close() error");

	return 0;
}
