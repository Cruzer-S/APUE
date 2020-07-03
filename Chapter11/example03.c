#include "../apue.h"
#include <pthread.h>
#include <stdint.h>

void cleanup(void* args)
{
	intptr_t arg = (intptr_t)args;

	printf("cleanup: ");

	printf("thread %d %s handler \n", 
			(arg / 10 == 1) ? (1) : (2),
			(arg % 10 == 1) ? ("first") : ("second")
	);
}

void *thr_fn(void *args)
{
	intptr_t arg = (intptr_t)args;

	printf("thread %ld start \n", arg);
	
	pthread_cleanup_push(cleanup, (void*)(arg * 10 + 1));
	pthread_cleanup_push(cleanup, (void*)(arg * 10 + 2));
	printf("thread %ld push complete\n", arg);

	if (arg)
//		return (void*)1;
		pthread_exit((void*)arg);

	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);

	return (void*)1;
}

int main(void)
{
	int			err;
	pthread_t	tid1, tid2;
	void		*tret;

	err = pthread_create(&tid1, NULL, thr_fn, (void*)1);
	if (err != 0)
		err_exit(err, "can't create thread 1");

	err = pthread_create(&tid2, NULL, thr_fn, (void*)2);
	if (err != 0)
		err_exit(err, "can't create thread 2");

	err = pthread_join(tid1, &tret);
	if (err != 0)
		err_exit(err, "can't join with thread 1");
	printf("thread 1 exit code %ld \n", (long)tret);

	err = pthread_join(tid2, &tret);
	if (err != 0)
		err_exit(err, "can't join with thread 2");
	printf("thread 2 exit code %ld \n", (long)tret);

	return 0;
}
