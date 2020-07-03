#include "../apue.h"
#include <fcntl.h>

void my_setbuf(FILE *restrict fp, char *restrict buf)
{
	int mode;
	int fd = fileno(fp);

	if (buf == NULL) {
		mode = _IONBF;
	} else {	
		switch (fd)	{
		case STDERR_FILENO:	mode = _IONBF;	break;
		case STDIN_FILENO: 
		case STDOUT_FILENO:	mode = _IOLBF;	break;
		default:			mode = _IOFBF;	break;
		}
	}
	
	setvbuf(fp, buf, mode, BUFSIZ);
}

int main(void)
{
	FILE* fp;
	char* buf;

	buf = (char*)malloc(sizeof(char) * BUFSIZ);
	if (buf == NULL)
		err_sys("malloc() error!");

	// line-buffer applied
	my_setbuf(stdout, buf);
	fputs("hello?", stdout);
	sleep(3);
	printf("\n");

	// non-buffer applied
	my_setbuf(stderr, NULL);
	fputs("hi!", stderr);
	sleep(3);
	printf("\n");

	// full-buffer applied
	if ((fp = fopen("temp.txt", "w+")) == NULL)
		err_sys("fopen() error!");
	
	my_setbuf(fp, buf);
	fputs("Hello Everyone! \n", fp);
	fclose(fp);

	_Exit(0);
}
