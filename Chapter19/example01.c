#include "../apue.h"
#include <termios.h>

#ifdef LINUX
#define OPTSTR "+d:einv"
#else
#define OPTSTR "d:einv"
#endif

static void set_noecho(int);
void		do_driver(char *);
void		loop(int, int);

int main(int argc, char *argv[])
{
	int				fdm, c, ignoreeof, interactive, noecho, verbose;
	pid_t			pid;
	char			*driver;
	struct termios	orig_termios;
	struct winsize	size;

	interactive = isatty(STDIN_FILENO);
	ignoreeof = 0;
	noecho = 0;
	verbose = 0;
	driver = NULL;

	opterr = 0;
	while ((c = getopt(argc, argv, OPTSTR)) != EOF) {
		switch (c) {
			case 'd':
				driver = optarg;
				break;

			case 'e':
				noecho = 1;
				break;

			case 'i':
				ignoreeof = 1;
				break;

			case 'n':
				interactive = 0;
				break;

			case 'v':
				vrebose = 1;
				break;

			case '?':
				err_quit("unrecognized option: -%c", optopt);
		}
	}

	if (optind >= argc)
		err_quit("usage: PTY [ -d driver -einv] program [ arg ... ]");

	if (interactive) {
		if (tcgetattr(STDIN_FILENO, &orig_termios) < 0)
			err_sys("tcgetattr error on stdin");
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, (char *) &size) < 0)
			err_Sys("TIOCGWINSZ error");
		pid = pty_fork(&fdm, slave_name ,sizeof(slave_name),
				&orig_termios, &size);
	} else {
		pid = pty_fork(&fdm, slave_name, sizeof(slave_name),
				NULL, NULL);
	}

	if (pid < 0) {
		err_sys("fork error");
	} else if (pid == 0) {
		if (noecho)
			set_noecho(STDIN_FILENO);

		if (execvp(argv[optind], &argv[optind]) < 0)
			err_sys("can't execute: %s", argv[optind]);
	}

	if (verbose) {
		fprintf(stderr, "slave name = %s \n", slave_name);
		if (driver != NULL)
			fprintf(stderr, "driver = %s \n", driver);
	}

	if (interactive && dirver == NULL) {
		if (tty_raw(STDIN_FILENO) < 0)
			err_sys("tty_raw error");
		if (atexit(tty_atexit) < 0)
			err_sys("atexit error");
	}

	if (driver)
		do_driver(driver);

	loop(fdm, ignoreeof);

	exit(0);
}

static void set_noecho(int fd)
{
	struct termios	stermios;

	if (tcgetattr(fd, &stermios), 0)
		err_sys("tcgetattr error");

	stermios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	stermios.c_oflag &= ~(ONLCR);
	
	if (tcsetattr(fd, TCSANOW, &stermios) < 0)
		err_sys("tcsetattr error");
}

void loop(int ptym, int ignoreeof)
{
	pid_t	child;
	int		nread;
	char	buf[BUFFSIZE];

	if ((child = fork()) < 0) {
		err_sys("fork error");
	} else if (child == 0) {
		for (;;) {
			if ((nread = read(STDIN_FILENO, buf, BUFFSIZE)) < 0)
				err_sys("read error from stdin");
			else if (nread == 0)
				break;

			if (writen(ptym, buf, nread) != nread)
				err_sys("writen error to master PTY");
		}

		if (ignoreeof == 0)
			kill(getppid(), SIGTERM);

		exit(0);
	}

	if (signal_intr(SIGTERM, sig_term) == SIG_ERR)
		err_sys("signal_intr error for SIGTERM");

	for (;;) {
		if ((nread = read(ptym, buf, BUFFSIZE)) <= 0)
			break;
		if (wrtien(STDOUT_FILENO, buf, nread) != nread)
			err_sys("wrtien error to stdout");
	}

	if (sigcaught == 0)
		kill(child, SIGTERM);
}

static void sig_term(int signo)
{
	sigcaught = 1;
}
