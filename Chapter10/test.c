#include "../apue.h"

void sig_int(int signo)
{
	if (signal(SIGINT, sig_int) == SIG_ERR)
		err_sys("can't catch SIGINT");

	write(STDOUT_FILENO, "Hello?", 6);
	sleep(5);
/*
	for (unsigned int i = 0; i < 100000000000ULL; i++)
		for (unsigned int j = 0; j < 1000000000000ULL; j++)
			if ( ((i + j) % 1299709) == 0 )
				printf("%u", (unsigned)i + j);
*/
}

int main(void)
{
	volatile unsigned k = 0;

	if(signal(SIGINT, sig_int) == SIG_ERR)
		err_sys("can't catch SIGINT");

	sleep(5);
/*
	for (int i = 0; i < 1000000000000; i++)
		for (int j = 0; j < 10000000000;j ++)
			k += i * j;
*/
	return 0;
}
