#include "../apue.h"
#include "../palloc.h"
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

typedef struct _file_entry {
	long reg;
	long dir;
	long blk;
	long chr;
	long fifo;
	long slink;
	long sock;

	long unregistered;
} file_entry;

void add_entry(file_entry* entry, mode_t type)
{
	switch (type & S_IFMT) 
	{
	case S_IFREG:	entry->reg++;	break;
	case S_IFBLK:	entry->blk++;	break;
	case S_IFCHR:	entry->chr++;	break;
	case S_IFIFO:	entry->fifo++;	break;
	case S_IFLNK:	entry->slink++;	break;
	case S_IFSOCK:	entry->sock++;	break;
	case S_IFDIR:	entry->dir++;	break;
	default: entry->unregistered;	break;
	}
}

long sum_entry(file_entry* entry)
{
	return 
		entry->reg 		+ 	entry->blk		+
		entry->chr 		+ 	entry->fifo		+
		entry->slink	+	entry->sock		+
		entry->dir		+	entry->unregistered
	;		
}

static void myftw(int fd, file_entry* fent)
{
	struct stat statbuf;
	struct dirent *dirp;
	DIR *dp;

	if (fchdir(fd) == -1)
		err_sys("chdir() error!");

	dp = fdopendir(fd);
	if (dp == NULL)
		err_sys("fdopendir() error!");

	while ((dirp = readdir(dp)) != NULL)
	{
		if (strcmp(dirp->d_name, ".") == 0
		||	strcmp(dirp->d_name, "..") == 0)
			continue;

		add_entry(fent, statbuf.st_mode);

		if (lstat(dirp->d_name, &statbuf) == -1)
			err_sys("lstat() error!");

		if (S_ISDIR(statbuf.st_mode)) {
			int temp = open(dirp->d_name, O_RDONLY);
			if (temp == -1)
				err_ret("open() error!: %s", dirp->d_name);
			else {
				myftw(temp, fent);
				close(temp);

				if (chdir("..") == -1)
					err_ret("chdir() error!");
			}
		}
	}
}

void show_all_entry(file_entry* fent)
{
	long total = sum_entry(fent);

	printf("regular files	= %7ld, %5.2f %% \n", fent->reg,
				fent->reg * 100.0 / total);
	printf("directories	= %7ld, %5.2f %% \n", fent->dir,
				fent->dir * 100.0 / total);
	printf("block special	= %7ld, %5.2f %% \n", fent->blk,
				fent->blk * 100.0 / total);
	printf("char special	= %7ld, %5.2f %% \n", fent->chr,
				fent->chr * 100.0 / total);
	printf("FIFOs		= %7ld, %5.2f %% \n", fent->fifo,
				fent->fifo * 100.0 / total);
	printf("symbolic link	= %7ld, %5.2f %% \n", fent->slink,
				fent->slink * 100.0 / total);
	printf("sockets		= %7ld, %5.2f %% \n\n", fent->sock,
				fent->sock * 100.0 / total);
}

int main(int argc, char** argv)
{
	int fd;
	file_entry fent = { 0, 0, 0, 0, 0, 0, 0, 0 };

	if (argc != 2)
		err_quit("usage: %s <pathname>", argv[0]);

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		err_sys("failed to open %s", argv[1]);

	myftw(fd, &fent);
	close(fd);

	show_all_entry(&fent);

	return 0;
}
