#include "../apue.h"

void	pr_stdio(const char *, FILE *);
int		is_unbuffered(FILE *);
int		is_linebuffered(FILE *);
int		buffer_size(FILE *);

int main(void)
{
	FILE	*fp;

	fputs("enter any character \n", stdout);
	if (getchar() == EOF)
		err_sys("getchar error");

	fputs("one line to standard error! \n", stderr);

	pr_stdio("stdin",	stdin);
	pr_stdio("stdout",	stdout);
	pr_stdio("stderr",	stderr);

	if ((fp = fopen("/etc/passwd", "r")) == NULL)
		err_sys("fopen error");

	if (getc(fp) == EOF)
		err_sys("getc error");

	pr_stdio("/etc/passwd", fp);

	return 0;
}

void pr_stdio(const char *name, FILE *fp)
{
	printf("flag: %d \n", (fp->_flags << 16) >> 16);
	printf("_IO_buf_end: %d \n", *((size_t*)(fp->_IO_buf_end)));
	printf("_IO_buf_base: %d \n", *((size_t*)(fp)->_IO_buf_base));

	printf("stream = %s, ", name);
	if 		(is_unbuffered(fp))
		printf("unbuffered");
	else if (is_linebuffered(fp))
		printf("line buffered");
	else /* if neither of above */
		printf("fully buffered");

	printf(", buffer size = %d \n", buffer_size(fp));
}

/*
 * 이하의 코드에는 이식성이 없음.
 */

#if defined(_IO_UNBUFFERED)

int is_unbuffered(FILE *fp)
{
	return (fp->_flags & _IO_UNBUFFERED);
}

int is_linebuffered(FILE *fp)
{
	return (fp->_flags & _IO_LINE_BUF);
}

int buffer_size(FILE *fp)
{
	return (fp->_IO_buf_end - fp->_IO_buf_base);
}

#elif defined (__SNBF)

int is_unbuffered(FILE *fp)
{
	return (fp->_flags & __SNBF);
}

int is_linebuffered(FILE *fp)
{
	return (fp->_flags & __SLBF);
}

int buffer_size(FILE *fp)
{
	return (fp->_bf._size);
}

#elif defined (_IONBF)

#ifdef _LP64
#define _flag __pad5
#define _ptr __pad5
#define _base __pad2
#endif

int is_unbuffered(FILE *fp)
{
	return (fp->_flag & _IONBF);
}

int is_linebuffered(FILE *fp)
{
	return (fp->_flag & _IOLBF);
}

int buffer_size(FILE *fp)
{
#ifdef _LP64
	return (fp->_IO_buf_end - fp->_IO_buf_end);
#else
	return (BUFSIZ);	/* 그냥 추측임 */
#endif
}

#else

#error unknown stdio implementation!

#endif
