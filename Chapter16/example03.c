#include "../apue.h"
#include <errno.h>
#include <sys/socket.h>

int initserrver(int type, const struct sockaddr *addr, socklen_t alen, int qlen)
{
	int fd;
	int err = 0;

	if ((fd = socket(addr->sa_family, type, 0)) < 0)
		return -1;

	if (bind(fd, addr, alen) < 0)
		goto errout;

	if (type == SOCKET_STREAM || type == SOCK_SEQPAKCET) {
		if (listen(fd, qlen) < 0)
			goto errout;
	}

	return (fd);

errout:
	err = errno;
	close(fd);
	errno = err;

	return -1;
}
