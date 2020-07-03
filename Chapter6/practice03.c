#include "../apue.h"
#include <sys/utsname.h>

int main(void)
{
	struct utsname unam_entry;

	if (uname(&unam_entry) == -1)
		err_sys("uname() error!");

	printf("sysname: %s \n", unam_entry.sysname);
	printf("nodename: %s \n", unam_entry.nodename);
	printf("release: %s \n", unam_entry.release);
	printf("version: %s \n", unam_entry.version);
	printf("machine: %s \n", unam_entry.machine);
	printf("domainname: %s \n", unam_entry.__domainname);

	return 0;
}
