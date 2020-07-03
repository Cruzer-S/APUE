#include "../apue.h"
#include <sys/wait.h>

int main(void)
{
	pid_t	pid;

	if ((pid = fork()) < 0) {
		err_sys("fork error");
	} else if (pid == 0) {
		if (execl("/sdb/study/APUE/Chapter8/testinterp", 
					"testinterp", "myarg1", "MY ARGS2", (char*)0) < 0)
			err_sys("execle error");
	}

	if (waitpid(pid, NULL, 0) < 0)
		err_sys("wait error");

	return 0;
}
