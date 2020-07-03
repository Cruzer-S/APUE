#include "../apue.h"

int		globval = 6;		/* 초기화된 자료 구역의 외부 변수 */
char	buf[] = "a write to stdout \n";

int main(void)
{
	int		var;
	pid_t	pid;

	var = 88;
	if (write(STDOUT_FILENO, buf, sizeof(buf) - 1) != (sizeof(buf) - 1))
		err_sys("write error");

	printf("before fork \n");

	if ((pid = fork()) < 0)
		err_sys("fork error");
	else if (pid == 0) {
		globval++;
		var++;
	} else
		sleep(2);

	printf("pid = %ld, glob = %d, var = %d \n"
					, (long)getpid(), globval, var);

	return 0;
}
