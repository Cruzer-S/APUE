#include "../apue.h"
#include <setjmp.h>

static jmp_buf	env_alrm;

static void sig_alrm1(int signo)
{
	// nothing to do
}

unsigned int sleep1(unsigned int seconds)
{
	if (signal(SIGALRM, sig_alrm1) == SIG_ERR)
		return (seconds);

	alarm(seconds);

	pause();

	return alarm(0);
}

static void sig_alrm2(int signo)
{
	longjmp(env_alrm, 1);
}

unsigned int sleep2(unsigned int seconds)
{
	if (signal(SIGALRM, sig_alrm2) == SIG_ERR)
		return (seconds);

	if (setjmp(env_alrm) == 0) {
		alarm(seconds);
		pause();
	}

	return (alarm(0));
}

static void sig_int(int signo)
{
	int				i, j;
	volatile int	k;


	printf("\nsig_int starting \n");
	for (i = 0; i < 300000; i++)
		for (j = 0; j < 4000; j++)
			k += i * j;

	printf("sig_int finished \n");
}

int main(void)
{
	unsigned int	unslept;

	if (signal(SIGINT, sig_int) == SIG_ERR)
		err_sys("signal(SIGINT) error");

	unslept = sleep2(5);

	printf("sleep2 returned: %u \n", unslept);

	return 0;
}
