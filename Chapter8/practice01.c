#include "../apue.h"
#include <signal.h>

void check_termstat(siginfo_t *info)
{
	switch (info->si_signo)
	{
	case SIGCHLD:
		switch (info->si_code)
		{
		case CLD_EXITED:
			printf("Child has exited");
			break;

		case CLD_KILLED:
			printf("Child has terminated abnormally and did not create a core file");
			break;

		case CLD_DUMPED:
			printf("Child has terminated abanormally and created a core file");
			break;

		case CLD_TRAPPED:
			printf("Traced child has trapped");
			break;

		case CLD_STOPPED:
			printf("Child has stopped");
			break;

		case CLD_CONTINUED:
			printf("Stopped child has continued");
			break;
		}
		break;
	}
	printf(", status %d \n", info->si_status);
}

int main(void)
{
	pid_t	pid;
	int		status;
	siginfo_t siginfo;

	if ((pid = fork()) < 0)
		err_sys("fork error");
	else if (pid == 0)
		exit(7);

	if (waitid(P_PID, pid, &siginfo, WEXITED) != 0)
		err_sys("waitid error");
	check_termstat(&siginfo);

	if ((pid = fork()) < 0)
		err_sys("fork error");
	else if (pid == 0)
		abort();

	if (waitid(P_PID, pid, &siginfo, WEXITED) != 0)
		err_sys("wait error");
	check_termstat(&siginfo);

	if ((pid = fork()) < 0)
		err_sys("fork error");
	else if (pid == 0)
		status /= 0;

	if (waitid(P_PID, pid, &siginfo, WEXITED) != 0)
		err_sys("wait error");
	check_termstat(&siginfo);

	return 0;
}
