#include "../apue.h"

static void sig_int(int);

int main(void)
{
	sigset_t	newmask, oldmask, waitmask;

	pr_mask("program start: ");

	if (sigaction(SIGINT, 
					&(const struct sigaction){ .sa_handler = sig_int, .sa_flags = SA_RESTART }
							, NULL) == -1)
		err_sys("signal(SIGINT) error");

	sigemptyset(&waitmask);
	sigaddset(&waitmask, SIGUSR1);
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGINT);

	if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0)
		err_sys("SIG_BLOCK error");

	pr_mask("in critical region: ");

	if (sigsuspend(&waitmask) != -1)
		err_sys("sigsuspend error");

	pr_mask("after return from sigsuspend: ");

	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
		err_sys("SIG_SETMASK error");

	pr_mask("program exit: ");

	return 0;
}

static void sig_int(int signo)
{
	pr_mask("\nin sig_int: ");
}
