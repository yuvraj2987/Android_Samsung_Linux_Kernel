#include <linux/time.h>
#include <linux/ioctl.h>

#define MAX_INPUT_DEVICE 16 
//for now we are logging for a fixed number of processes.
#define MAX_PID (1<<4)
#define MAX_LONG  (~((unsigned long)0))
//Number of latencies to record for each process.
//Incresing it's size making kernel to not boot.
#define MAX_REQS  (1<<4)
#define MAX_NAME   (1<<8)
#define END_MARK   MAX_INPUT_DEVICE


/*
The freq of input devices is quite enough that in a few
second they can oveflow the MAX_LONG, so keeping an overflow_count
with the number. Therfore, actual count will be "so total 
count = count +MAX_INT*(oveflow_count+MAX_INT*overflow_overflow_count);*/

struct safe_count_type{
    unsigned long count;
    unsigned long overflow_count;
    //overflow can itself overflow.
    unsigned long overflow_overflow_count;
    //so total count = count +MAX_INT*(oveflow_count+MAX_INT*
    //overflow_overflow_count);

};


typedef struct safe_count_type safe_count;

/*
  Represents count of consumed events by an process(pid). 
 */
struct consume_event_counts{
    safe_count counts;
    unsigned int pid;
};


struct user_event_log{
    //time stamp when logging is initiated first time.
    char name[MAX_NAME];
    struct timeval dev_opened_time;
    
    //number of events dropped.
    safe_count event_dropped;
    //total number of events generated for this device.
    safe_count event_generated;

    //consumed events base upon  process id.
    struct consume_event_counts event_consumed[MAX_PID];
    //avg. latency for each process.
    /*
    struct timeval latency_list[MAX_PID];
    */
    struct timeval avg;
    //number process using this device.
    unsigned int ncount;
    //device is closed?.
    int bclosed;

};

struct user_args{
    struct user_event_log *p;//[out]args.
    unsigned int minor;//[in] args.
};

/*IOCTL codes for user space*/
#define LOG_IOC_MAGIC             9
/*fill the array with the device minor numbers*/
#define LGETDEVS           _IOR(LOG_IOC_MAGIC,0x01,unsigned char[MAX_INPUT_DEVICE])
/*get information for device which has minor number */
#define LGETDEVINFO  _IOR(LOG_IOC_MAGIC,0x02,struct user_args)
