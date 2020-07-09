#ifndef _APUE_H_
#define _APUE_H_

#define _POSIX_C_SOURCE 200809L

#if defined(SOLARIS)		/* Solaris 10 */
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 700
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#if defined(MACOS) || !defined(TIOCGWINSZ)
#include <sys/ioctl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <setjmp.h>

#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include <time.h>

#include <syslog.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <string.h>

#define CONTROLLEN CMSG_LEN(sizeof(int))

static struct cmsghdr	*cmptr = NULL;

#define QLEN 10
#define STALE 30

#define CLI_PATH "/var/tmp/"
#define CLI_PERM S_IRWXU

#define MAXSLEEP 128

#define LOCKFILE "/var/run/daemon.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern int lockfile(int);

static struct termios			save_termios;
static int						ttysavefd = -1;
static enum { RESET, RAW, CBREAK }	ttystate = RESET;


#ifdef	PATH_MAX
static long pathmax = PATH_MAX;
#else
static long pathmax = 0;
#endif

static long posix_version = 0;
static long xsi_version = 0;

#define PATH_MAX_GUESS	(1024)

#define MAXLINE	4096

#define FILE_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define DIR_MODE	(FILE_MODE | S_IXUSR | S_IXGRP | S_IXOTH)

typedef void	Sigfunc(int);

#define min(a,b)	((a) < (b) ? (a) : (b))
#define max(a,b)	((a) > (b) ? (a) : (b))

char	*path_alloc(size_t *);
long	open_max(void);

int		set_cloexec(int);
void	clr_fl(int, int);
void	set_fl(int, int);

void	pr_exit(int);

void	pr_mask(const char *);
Sigfunc	*signal_intr(int, Sigfunc *);

void	daemonize(const char *);

void	sleep_us(unsigned int);
ssize_t	readn(int, void *, size_t);
ssize_t	writen(int, const void *, size_t);

int		fd_pipe(int *);
int		recv_fd(int, ssize_t (*func)(int, 
				const void *, size_t));
int		send_fd(int, int);
int		send_err(int, int,
				const char *);

int		serv_listen(const char *);
int		serv_accept(int, uid_t *);
int		cli_conn(const char *);
int		buf_args(char *, int (*func)(int, 
				char**));

int		tty_cbreak(int);
int		tty_raw(int);
int		tty_reset(int);
void	tty_atexit(void);
struct termios	*tty_termios(void);

int		ptym_open(char *, int);
int		ptys_open(char *);
#ifdef TIOCGWINSZ
pid_t	pty_fork(int *, char *, int, const struct termios *,
				const struct winsize *);
#endif

int		lock_reg(int, int, int, off_t, int, off_t);

#define read_lock(fd, offset, whence, len) \
			lock_reg((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))
#define	read_lock(fd, offset, whence, len) \
			lock_reg((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))
#define write_lock(fd, offset, whence, len) \
			lock_reg((fd), F_SETLKW, F_WRLCK, (offset), (whence), (len))
#define un_lock(fd, offset, whence, len) \
			lock_reg((fd), F_SETLK, F_UNLCK, (offset), (whence), (len))

pid_t	lock_test(int, int, off_t, int, off_t);

#define is_read_lockable(fd, offset, whence, len) \
			(lock_test((fd)), F_RDLCK, (offset), (whence), (len) == 0)
#define is_write_lockable(fd, offset, whence, len) \
			(lock_test((fd), F_WRLCK, (offset), (whence), (len)) == 0)

void	err_msg(const char *, ...);
void	err_dump(const char *, ...) __attribute__((noreturn));
void	err_quit(const char *, ...) __attribute__((noreturn));
void	err_cont(int, const char *, ...);
void	err_exit(int, const char *, ...) __attribute__((noreturn));
void	err_ret(const char *, ...);
void	err_sys(const char *, ...) __attribute__((noreturn));

void	log_msg(const char *, ...);
void	log_open(const char *, int, int);
void	log_quit(const char *, ...) __attribute__((noreturn));
void	log_ret(const char *, ...);
void	log_sys(const char *, ...) __attribute__((noreturn));
void	log_exit(int, const char *, ...) __attribute__((noreturn));

void	TELL_WAIT(void);
void	TELL_PARENT(pid_t);
void	TELL_CHILD(pid_t);
void	WAIT_PARENT(void);
void	WAIT_CHILD(void);

static void err_doit(int, int, const char *, va_list);

void err_ret(const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
}

void err_sys(const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
	exit(1);
}
void err_cont(int error, const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
}
void err_exit(int error, const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);

	exit(1);
}
void err_dump(const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
	abort();
	exit(1);
}
void err_msg(const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
}
void err_quit(const char *fmt, ...)
{
	va_list		ap;
	
	va_start(ap, fmt);
	err_doit(1, errno, fmt, ap);
	va_end(ap);
	exit(1);
}

static void err_doit(int errnoflag, int error, const char *fmt, va_list ap)
{
	char	buf[MAXLINE];
	vsnprintf(buf, MAXLINE-1, fmt, ap);
	if (errnoflag)
		snprintf(buf+strlen(buf), MAXLINE-strlen(buf)-1, " : %s",
			strerror(error));
	strcat(buf, "\n");
	fflush(stdout);
	fputs(buf, stderr);
	fflush(NULL);
}

char* path_alloc(size_t* sizep)
{
	char*	ptr;
	size_t	size;

	if (posix_version == 0)
		posix_version = sysconf(_SC_VERSION);

	if (xsi_version == 0)
		xsi_version = sysconf(_SC_XOPEN_VERSION);

	if (pathmax == 0) {
		errno = 0;
		if ((pathmax = pathconf("/", _PC_PATH_MAX)) < 0)
			pathmax = PATH_MAX_GUESS;
		else
			err_sys("pathconf error for _PC_PATH_MAX");
	} else {
		pathmax++;
	}

	if ((posix_version < 200112L) && (xsi_version < 4))
		size = pathmax + 1;
	else
		size = pathmax;

	if ((ptr = malloc(size)) == NULL)
		err_sys("malloc error for pathname");

	if (sizep != NULL)
		*sizep = size;

	return (ptr);
}

void pr_exit(int status)
{
	if (WIFEXITED (status))
		printf("normal termination, exit status = %d \n",
				WEXITSTATUS (status));
	else if (WIFSIGNALED(status))
		printf("abnormal termination, signal number = %d %s \n", 
				WTERMSIG(status),
#ifdef WCOREDUMP
				WCOREDUMP(status) ? "(core file generated)" : ""
#else
				""
#endif
		);
	else if (WIFSTOPPED(status))
		printf("child stopped, signal number = %d \n", WSTOPSIG(status));
}

int system(const char *cmdstring)
{
	pid_t	pid;
	int		status;

	if (cmdstring == NULL)
		return 1;

	if ((pid = fork()) < 0) {
		status = -1;
	} else if (pid == 0) {
		execl("/bin/sh", "sh", "-c", cmdstring, (char*) 0);
		_exit(127);
	} else {
		while (waitpid(pid, &status, 0) < 0) {
			if (errno != EINTR) {
				status = -1;
				break;
			}
		}
	}

	return status;
}

void pr_mask(const char *str)
{
	sigset_t	sigset;
	int			errno_save;

	errno_save = errno;
	if (sigprocmask(0, NULL, &sigset) < 0) {
		err_ret("sigprocmask error");
	} else {
		printf("%s", str);
		if (sigismember(&sigset, SIGINT))
			printf(" SIGINT");
		if (sigismember(&sigset, SIGQUIT))
			printf(" SIGQUIT");
		if (sigismember(&sigset, SIGUSR1))
			printf(" SIGUSR1");
		if (sigismember(&sigset, SIGALRM))
			printf(" SIGALRM");

		printf("\n");
	}

	errno = errno_save;
}

void daemonize(const char *cmd)
{
	int					fd0, fd1, fd2;
	pid_t				pid;
	struct rlimit		rl;
	struct sigaction 	sa;

	umask(0);

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		err_quit("%s: can't get file limit", cmd);

	if ((pid = fork()) < 0)
		err_quit("%s: can't fork", cmd);
	else if (pid != 0)
		exit(0);
	setsid();

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		err_quit("%s: can't ignore SIGHUP", cmd);

	if ((pid = fork()) < 0)
		err_quit("%s: can't ignore SIGHUP", cmd);
	else if (pid != 0)
		exit(0);

	if (chdir("/") < 0)
		err_quit("%s: can't change directory to /", cmd);

	if (rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;
	
	for (int i = 0; i < rl.rlim_max; i++)
		close(i);

	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	openlog(cmd, LOG_CONS, LOG_DAEMON);
	if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
		syslog(
			LOG_ERR, "unexpected file descriptors %d %d %d",
												fd0, fd1, fd2
		);

		exit(1);
	}
}

int already_running(void)
{
	int		fd;
	char	buf[16];

	fd = open(LOCKFILE, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0) {
		syslog(LOG_ERR, "can't open %s: %s", LOCKFILE, strerror(errno));
		exit(1);
	}

	if (lockfile(fd) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			close (fd);
			return 1;
		}

		syslog(LOG_ERR, "can't lock %s: %s", LOCKFILE, strerror(errno));
		exit(1);
	}
	ftruncate(fd, 0);
	sprintf(buf, "%ld", (long)getpid());
	write(fd, buf, strlen(buf) + 1);

	return 0;
}

void set_fl(int fd, int flags)
{
	int		val;

	if ((val = fcntl(fd, F_GETFL, 0)) < 0)
		err_sys("fcntl F_GETFL error");

	val |= flags;

	if (fcntl(fd, F_SETFL, val) < 0)
		err_sys("fcntl F_SETFL error");
}

void clr_fl(int fd, int flags)
{
	int		val;

	if ((val = fcntl(fd, F_GETFL, 0)) < 0);

	val &= ~flags;

	if (fcntl(fd, F_SETFL, val) < 0)
		err_sys("fcntl F_SETFL error");
}

int lockfile(int fd)
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	return (fcntl(fd, F_SETLK, &fl));
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
	struct flock	lock;

	lock.l_type = type;
	lock.l_start = offset;
	lock.l_whence = whence;
	lock.l_len = len;

	return (fcntl(fd, cmd, &lock));
}

pid_t lock_test(int fd, int type, off_t offset, int whence, off_t len)
{
	struct flock	lock;

	lock.l_type = type;
	lock.l_start = offset;
	lock.l_whence = whence;
	lock.l_len = len;

	if (fcntl(fd, F_GETLK, &lock) < 0)
		err_sys("fcntl error");

	if (lock.l_type == F_UNLCK)
		return 0;

	return lock.l_pid;
}

static volatile sig_atomic_t sigflag;

static sigset_t newmask, oldmask, zeromask;

static void sig_usr(int signo)
{
	sigflag = 1;
}

void TELL_WAIT(void)
{
	if (signal(SIGUSR1, sig_usr) == SIG_ERR)
		err_sys("signal(SIGUSR1) error");

	if (signal(SIGUSR2, sig_usr) == SIG_ERR)
		err_sys("signal(SIGUSR2) error");

	sigemptyset(&zeromask);
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGUSR1);
	sigaddset(&newmask, SIGUSR2);

	if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0)
		err_sys("SIG_BLOCK error");
}

void TELL_PARENT(pid_t pid)
{
	kill(pid, SIGUSR2);
}

void WAIT_PARENT(void)
{
	while (sigflag == 0)
		sigsuspend(&zeromask);

	sigflag = 0;

	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
		err_sys("SIG_SETMASK error");
}

void TELL_CHILD(pid_t pid)
{
	kill(pid, SIGUSR1);
}

void WAIT_CHILD(void)
{
	while (sigflag == 0)
		sigsuspend(&zeromask);
	sigflag = 0;

	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
		err_sys("SIG_SETMASK error");
}

int connect_retry(int domain, int type, int protocol, const struct sockaddr *addr, socklen_t alen)
{
	int numsec, fd;

	for (numsec = 1; numsec <= MAXSLEEP; numsec <<= 1) {
		if ((fd = socket(domain, type, protocol)) < 0)
			return -1;

		if (connect(fd, addr, alen) == 0) {
			return fd;
		}

		close (fd);

		if (numsec <= MAXSLEEP / 2)
			sleep(numsec);
	}

	return -1;
}

int initserver(int type, const struct sockaddr *addr, socklen_t alen, int qlen)
{
	int fd;
	int err = 0;

	if ((fd = socket(addr->sa_family, type, 0)) < 0)
		return -1;

	if (bind(fd, addr, alen) < 0)
		goto errout;

	if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
		if (listen(fd, qlen) < 0)
			goto errout;
	}

	return (fd);

errout:
	err = errno;
	close(fd);
	errno = err;

	return -1;
}

int fd_pipe(int fd[2])
{
	return (socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
}

int serv_listen(const char *name)
{
	int					fd, len, err, rval;
	struct sockaddr_un	un;

	if (strlen(name) >= sizeof(un.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -2;

	unlink(name);

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, name);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(name);

	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		rval = -3;
		goto errout;
	}

	if (listen(fd, QLEN) < 0) {
		rval = -4;
		goto errout;
	}

	return fd;

errout:
	err = errno;
	close(fd);
	errno = err;

	return rval;
}

int serv_accept(int listenfd, uid_t *uidptr)
{
	int					clifd, err, rval;
	socklen_t			len;
	time_t				staletime;
	struct sockaddr_un	un;
	struct stat			statbuf;
	char				*name;

	if ((name = malloc(sizeof(un.sun_path) + 1)) == NULL)
		return -1;

	len = sizeof(un);
	if ((clifd = accept(listenfd, (struct sockaddr *)&un, &len)) < 0) {
		free(name);
		return -2;
	}

	len -= offsetof(struct sockaddr_un, sun_path);
	memcpy(name, un.sun_path, len);
	name[len] = 0;

	if (stat(name, &statbuf) < 0) {
		rval = -3;
		goto errout;
	}


#ifdef S_ISSOCK
	if (S_ISSOCK(statbuf.st_mode) == 0) {
		rval = -4;
		goto errout;
	}
#endif

	if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) ||
		(statbuf.st_mode & S_IRWXU) != S_IRWXU) {
		rval = -5;
		goto errout;
	}

	staletime = time(NULL) - STALE;
	if (statbuf.st_atime < staletime ||
		statbuf.st_ctime < staletime ||
		statbuf.st_mtime < staletime) {
		rval = -6;
		goto errout;
	}

	if (uidptr != NULL)
		*uidptr = statbuf.st_uid;

	unlink(name);
	free(name);
	
	return (clifd);

errout:
	err = errno;
	close(clifd);
	free(name);
	errno = err;

	return (rval);
}

int cli_conn(const char *name)
{
	int					fd, len, err, rval;
	struct sockaddr_un	un, sun;
	int					do_unlink = 0;

	if (strlen(name) >= sizeof(un.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	sprintf(un.sun_path, "%s%05ld", CLI_PATH, (long)getpid());
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);

	unlink(un.sun_path);

	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		rval = -2;
		goto errout;
	}

	if (chmod(un.sun_path, CLI_PERM) < 0) {
		rval = -3;
		do_unlink = 1;
		goto errout;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, name);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(name);
	if (connect(fd, (struct sockaddr *)&sun, len) < 0) {
		rval = -4;
		do_unlink = 1;
		goto errout;
	}

	return fd;

errout:
	err = errno;
	close(fd);
	if (do_unlink)
		unlink(un.sun_path);

	errno = err;
	
	return rval;
}

int send_err(int fd, int errcode, const char *msg)
{
	int		n;

	if ((n = strlen(msg)) > 0)
		if (writen(fd, msg, n) != n)
			return -1;

	if (errcode >= 0)
		errcode = -1;

	if (send_fd(fd, errcode) < 0)
		return -1;

	return 0;
}


int send_fd(int fd, int fd_to_send)
{
	struct iovec	iov[1];
	struct msghdr	msg;
	char			buf[2];

	iov[0].iov_base = buf;
	iov[0].iov_len 	= 2;
	msg.msg_iov 	= iov;
	msg.msg_iovlen	= 1;
	msg.msg_name	= NULL;
	msg.msg_namelen	= 0;

	if (fd_to_send < 0) {
		msg.msg_control		= NULL;
		msg.msg_controllen	= 0;
		buf[1] = -fd_to_send;

		if (buf[1] == 0)
			buf[1] = 1;

	} else {
		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return -1;

		cmptr->cmsg_level	= SOL_SOCKET;
		cmptr->cmsg_type	= SCM_RIGHTS;
		cmptr->cmsg_len		= CONTROLLEN;
		msg.msg_control		= cmptr;
		msg.msg_controllen	= CONTROLLEN;

		*(int *)CMSG_DATA(cmptr) = fd_to_send;

		buf[1] = 0;
	}

	buf[0] = 0;

	if (sendmsg(fd, &msg, 0) != 2)
		return -1;

	return 0;
}

int recv_fd(int fd, ssize_t (*userfunc)(int, const void *, size_t))
{
	int				newfd, nr, status;
	char			*ptr;
	char			buf[MAXLINE];
	struct iovec	iov[1];
	struct msghdr	msg;

	status = -1;
	for (;;) {
		iov[0].iov_base	= buf;
		iov[0].iov_len	= sizeof(buf);
		msg.msg_iov		= iov;
		msg.msg_iovlen	= 1;
		msg.msg_name	= NULL;
		msg.msg_namelen	= 0;

		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return -1;

		msg.msg_control		= cmptr;
		msg.msg_controllen	= CONTROLLEN;

		if ((nr = recvmsg(fd, &msg, 0)) < 0) {
			err_ret("recvmsg error");
			return -1;
		} else if (nr == 0) {
			err_ret("connection closed by server");
			return -1;
		}

		for (ptr = buf; ptr < &buf[nr]; ) {
			if (*ptr++ == 0) {
				if (ptr != &buf[nr - 1])
					err_dump("message format error");
				status = *ptr & 0xFF;

				if (status == 0) {
					if (msg.msg_controllen < CONTROLLEN)
						err_dump("status = 0 but no fd");

					newfd = *(int *)CMSG_DATA(cmptr);
				} else {
					newfd = -status;
				}

				nr -= 2;
			}
		}

		if (nr > 0 && (*userfunc)(STDERR_FILENO, buf, nr) != nr)
			return -1;

		if (status >= 0)
			return newfd;
	}
}

ssize_t readn(int fd, void *ptr, size_t n)
{
	size_t		nleft;
	ssize_t		nread;

	nleft = n;
	while (nleft > 0) {
		if ((nread = read(fd, ptr, nleft)) < 0) {
			if (nleft == n)
				return -1;
			else
				break;
		} else if (nread == 0) {
			break;
		}

		nleft	-= nread;
		ptr		+= nread;
	}

	return (n - nleft);
}

ssize_t writen(int fd, const void *ptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;

	nleft = n;
	while (nleft > 0) {
		if ((nwritten = write(fd, ptr, nleft)) < 0) {
			if (nleft == n)
				return -1;
			else
				break;
		} else if (nwritten == 0) {
			break;
		}

		nleft	-= nwritten;
		ptr		+= nwritten;
	}

	return (n - nleft);
}

int tty_cbreak(int fd)
{
	int				err;
	struct termios	buf;

	if (ttystate != RESET) {
		errno = EINVAL;
		return -1;
	}

	if (tcgetattr(fd, &buf) < 0)
		return -1;

	save_termios = buf;

	buf.c_lflag &= ~(ECHO | ICANON);

	buf.c_cc[VMIN] = 1;
	buf.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSAFLUSH, &buf) < 0)
		return -1;

	if (tcgetattr(fd, &buf) < 0) {
		err = errno;
		tcsetattr(fd, TCSAFLUSH, &save_termios);
		errno = err;
		return -1;
	}

	if ((buf.c_lflag & (ECHO | ICANON)) || buf.c_cc[VMIN] != 1 ||
			buf.c_cc[VTIME] != 0) {
		tcsetattr(fd, TCSAFLUSH, &save_termios);
		errno = EINVAL;
		return -1;
	}

	ttystate = CBREAK;
	ttysavefd = fd;

	return 0;
}

int tty_raw(int fd)
{
	int				err;
	struct termios 	buf;

	if (ttystate != RESET) {
		errno = EINVAL;
		return -1;
	}

	if (tcgetattr(fd, &buf) < 0)
		return -1;

	save_termios = buf;

	buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

	buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

	buf.c_cflag &= ~(CSIZE | PARENB);

	buf.c_cflag |= CS8;

	buf.c_oflag &= ~(OPOST);

	buf.c_cc[VMIN] = 1;
	buf.c_cc[VTIME] = 0;
	if (tcsetattr(fd, TCSAFLUSH, &buf) < 0)
		return -1;

	if (tcgetattr(fd, &buf) < 0) {
		err = errno;
		tcsetattr(fd, TCSAFLUSH, &save_termios);
		errno = err;

		return -1;
	}

	if ((buf.c_lflag & (ECHO | ICANON | IEXTEN | ISIG)) ||
		(buf.c_iflag & (BRKINT | ICRNL | INPCK | ISTRIP | IXON)) ||
		(buf.c_cflag & (CSIZE | PARENB | CS8)) != CS8 ||
		(buf.c_oflag & OPOST) || buf.c_cc[VMIN] != 1 ||
		buf.c_cc[VTIME] != 0) {
		tcsetattr(fd, TCSAFLUSH, &save_termios);
		errno = EINVAL;
		return -1;
	}

	ttystate = RAW;
	ttysavefd = fd;
	
	return 0;
}

int tty_reset(int fd)
{
	if (ttystate == RESET)
		return 0;

	if (tcsetattr(fd, TCSAFLUSH, &save_termios) < 0)
		return -1;

	ttystate = RESET;

	return 0;
}

void tty_atexit(void)
{
	if (ttysavefd >= 0)
		tty_reset(ttysavefd);

}

struct termios *tty_termios(void)
{
	return (&save_termios);
}

#endif
