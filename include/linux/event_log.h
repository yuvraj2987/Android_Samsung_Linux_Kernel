#include <linux/time.h>

int log_event_dropped(int minor,int count);
int log_dev_opened (int minor,const char* name);
int log_event_generated(int minor,int count);
int log_event_consumed(int minor,int pid,int count);
//int log_request_event_latency(int minor,int pid, struct timeval diff);
int log_request_event_latency(int minor,int pid, struct timeval diff,int nevents);
