/*============================================================================= 
 *     FileName: ThreadBase.h
 *         Desc: 
 *       Author: licaibiao 
 *   LastChange: 2017-05-3  
 * =============================================================================*/ 

#ifndef THREADBASE_H_
#define THREADBASE_H_

extern "C"{
#include <pthread.h>
#include <stdio.h>
}

class ThreadBase {
public:
	ThreadBase();
	virtual ~ThreadBase();

	int start();
	int stop();//ֻ��stopFlag��Ƕ��run()����Ч
	int isStop();
	int isStart();
	int join();
	virtual void run()=0;
private:
	static void *thread_proxy_func(void *args);
	int stopFlag;//1ֹͣ
	int startFlag;//1��ʼ
	pthread_t tid;
};

#endif /* THREADBASE_H_ */
