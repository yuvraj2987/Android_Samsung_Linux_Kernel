#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <linux/event_log.h>
#include <linux/user_event_log.h>


MODULE_AUTHOR("Manish_Amit_Satish");
MODULE_DESCRIPTION("evdevlog_core");
MODULE_LICENSE("GPL");


#define LOG_FREQ_HZ  30*HZ //0.5 sec  

//dumping the log in every 1/2 sec.
#define PRINT_DELAY jiffies+LOG_FREQ_HZ


/*
 *Device specific stuff.
 */
DEFINE_SPINLOCK(spinlock);
static dev_t first; // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl; // Global variable for the device class
const char* log_dev_name   = "event_log_dev";
const char* class_name =  "eventlog";



/*
  A simple buffer to hold the latencies for a pid.
*/

struct latency_t{
    struct timeval delay;
    int nevents;
};
struct buffer_t{
    unsigned int items; //no of items in the buffer.
    unsigned int dropped_cnt;//Number of time buffer overflowed.
    unsigned int pid;//pid of the process.
//    struct timeval latency[MAX_REQS];//An array of latency.
    struct latency_t latency[MAX_REQS];
};



/*
  Each instance of this structure represents one
  device for which logging needs to be done.
*/
struct input_event_logger_type{
    //time stamp when logging is initiated first time.
    const char* name;
    struct timeval dev_opened_time;
    
    //number of events dropped.
    safe_count event_dropped;
    //total number of events generated for this device.
    safe_count event_generated;

    //event consumed based upon the process id.
    struct consume_event_counts event_consumed[MAX_PID];

    /*helps in indexing into consumed array */
    int ptopid[MAX_PID];
/*we do have one buffer for each PID/Process.*/
    struct buffer_t latency_list[MAX_PID];
    
    //device is closed?.
    int bclosed;
/*number of processes using this device.*/
    unsigned int ncount;
};

struct input_event_logger_type input_logger_list[MAX_INPUT_DEVICE]={
    {
	.event_dropped   = {.count=0,.overflow_count=0,.overflow_overflow_count=0},
	.event_generated = {.count=0,.overflow_count=0,.overflow_overflow_count=0},
	.event_consumed = {{{.count=0,.overflow_count=0,.overflow_overflow_count=0},.pid=0}},
	.latency_list   = {{.items=0,.dropped_cnt=0,.pid=0} },
	.bclosed = 1
    }
    
};

/*minor number of devices being logged.*/
unsigned char minors[MAX_INPUT_DEVICE];
/*Number of devices being logged*/
unsigned int ndevices=0;

//A timer to decide when to dump log
//on the screen.
struct timer_list log_timer;

/*
  Puts a timeval instance in the buffer.
 */
/*
static void push_buffer(struct buffer_t* pbuffer, struct timeval* diff){
    if(pbuffer==NULL)
	return;
    if(pbuffer->items == MAX_REQS){
	//Drop all items;
	pbuffer->items=0;
	pbuffer->dropped_cnt++;
    }
    pbuffer->latency[pbuffer->items++]=*diff;
    return;
    }*/

static void push_buffer(struct buffer_t* pbuffer, struct latency_t* p){
    if(pbuffer==NULL)
	return;
    if(pbuffer->items == MAX_REQS){
	//Drop all items;
	pbuffer->items=0;
	pbuffer->dropped_cnt++;
    }
    
    pbuffer->latency[pbuffer->items].delay=p->delay;
    pbuffer->latency[pbuffer->items].nevents=p->nevents;
    pbuffer->items++;
    return;
}

static void cal_avg_latency(struct input_event_logger_type *plog,struct timeval* pavg ){
    long int sec=0,usec=0;
    int i=0,j=0,total=0,events=0;
    struct buffer_t* pbuff;
    for( j=0;j< (plog->ncount);j++){
	pbuff = &(plog->latency_list[plog->ptopid[j]]);
	for(i=0;i<pbuff->items;i++){
	    events = pbuff->latency[i].nevents;
	    total+=events;
	    sec+=(pbuff->latency[i].delay.tv_sec*events);
	    usec+=(pbuff->latency[i].delay.tv_usec*events);
	}
    }
    pavg->tv_sec = sec/total;
    pavg->tv_usec = usec/total;
    return ;
}

static void increase_safe_count(safe_count* psafe_count,unsigned int cnt){
    unsigned long rem = MAX_LONG-psafe_count->count;
    if(rem>=cnt){
	psafe_count->count+=cnt;
	return;
    }
    
    psafe_count->count=cnt-rem;

    if(psafe_count->overflow_count!=MAX_LONG){
	psafe_count->overflow_count++;
	return;
    }
    psafe_count->overflow_count=0;
    psafe_count->overflow_overflow_count++;
    return;
}
int log_event_dropped(int minor,int count){
    if(input_logger_list[minor].bclosed)
	return 0;
    increase_safe_count(&input_logger_list[minor].event_dropped,count);
    return 0;
}

//May be in interrupt context.
int log_event_generated(int minor,int count){
    if(input_logger_list[minor].bclosed)
	return 1;
    increase_safe_count(&input_logger_list[minor].event_generated,count);
    return 0;
    
}
int log_event_consumed(int minor,int pid,int count){
    int pid_index = 0;
    int* pold_pid=0; 
    struct input_event_logger_type* plogger = &input_logger_list[minor];
    if(plogger->bclosed)
	return 0;
    pid_index = pid % MAX_PID;
    
    pold_pid = &plogger->event_consumed[pid_index].pid;
    if(*pold_pid==0){
	/*means it is a new entry.*/
	*pold_pid= pid;
	plogger->ptopid[plogger->ncount++] = pid_index;
    }

    increase_safe_count(&plogger->event_consumed[pid_index].counts,count);
    return 0;
}
/*
int log_request_event_latency(int minor,int pid, struct timeval diff){
    int pid_index=0;
    struct buffer_t* pbuffer=NULL;
    if(input_logger_list[minor].bclosed)
	return 0;
    pid_index = pid%MAX_PID;
    pbuffer = &input_logger_list[minor].latency_list[pid_index];
    if(pbuffer){
	pbuffer->pid = pid;
	push_buffer(pbuffer,&diff);
    }

    return 0;
    }*/



int log_request_event_latency(int minor,int pid, struct timeval diff,int nevents){
    int pid_index=0;
    struct buffer_t* pbuffer=NULL;
    struct latency_t temp;
    if(input_logger_list[minor].bclosed)
	return 0;
    pid_index = pid%MAX_PID;
    pbuffer = &input_logger_list[minor].latency_list[pid_index];
    if(pbuffer){
	pbuffer->pid = pid;
	temp.delay = diff;
	temp.nevents = nevents;
	push_buffer(pbuffer,&temp);
    }
    	return 0;
}



static void init_safe_count(safe_count* psafe,unsigned long count,unsigned long overflow_count,unsigned long oo_count){
    
    if(psafe==NULL)
	return ;
    psafe->count = count;
    psafe->overflow_count=overflow_count;
    psafe->overflow_overflow_count=oo_count;
    return;
}

/*
  initialize everthing first time.
 */
static void init_logger(void){
    struct input_event_logger_type* p=NULL;
    struct consume_event_counts* pce=NULL; 
    struct buffer_t* pbuffer=NULL; 
    int i=0,j=0;
    for( i=0;i<MAX_INPUT_DEVICE;i++){
	p = &input_logger_list[i];
	p->ncount=0;
	if(p){
	    init_safe_count(&p->event_dropped,0,0,0);
	    init_safe_count(&p->event_generated,0,0,0);
	    for(j=0;j<MAX_PID;j++){
		pce = &p->event_consumed[j];
		/*initially pointing to nothing*/
		p->ptopid[j] = -1;
		if(pce){
		    init_safe_count(&pce->counts,0,0,0);
		    pce->pid=0;
		}

	    }
	    for(j=0;j<MAX_PID;j++){
		pbuffer  = &p->latency_list[j];
		if(pbuffer){
		    pbuffer->items=0;
		    pbuffer->dropped_cnt=0;
		    pbuffer->pid = 0;
		    //latnecy.
		}

	    }
	    
	    //initially cloase all devices.
	    p->bclosed = 1;
	}
	

    }

}

/*
  this function can be considered as a registeration 
  method. now this logging framework is only capable
  of logging to input subsystem.so only indexing 
  based upon the minor number(later we can extend to include
  major number also).
*/
int log_dev_opened(int minor,const char* name){
    struct input_event_logger_type* plogger=NULL;
    struct timespec ts;
    plogger=&input_logger_list[minor];
    plogger->bclosed=0;
    //get an time stamp for the device.
    ktime_get_ts(&ts);
    
    plogger->dev_opened_time.tv_sec = ts.tv_sec;
    plogger->dev_opened_time.tv_usec = ts.tv_nsec/NSEC_PER_USEC;
    plogger->name = name;
    minors[ndevices++] = minor;
    init_safe_count(&plogger->event_dropped,0,0,0);
    init_safe_count(&plogger->event_generated,0,0,0);
    return 0;
}

//Aware of not writing any variable in this
//routine as it is not syncronized yet.
/*
static void dump_log(unsigned long data){
    struct input_event_logger_type* p;
    struct buffer_t* pbuffer;
    int i=0,j=0,k=0,index=0;
    char buff[1000];
    for( i=0;i<MAX_INPUT_DEVICE;i++){
	p= &input_logger_list[i];
	if(p->bclosed==0){
	    pr_info("dev_no:%d,event_dropped:%lu,event_generated:%lu",i,p->event_dropped.count,p->event_generated.count);
	}else{
	    //check next device.
	    continue;
	}
	for( j=0;j<MAX_PID;j++){
	    if(p->event_consumed[j].pid){
		pr_info("pid=%u,dev_no:%d,event_consumed:%lu",
			p->event_consumed[j].pid,i,p->event_consumed[j].counts.count);
	    }
	    
	}
	for(j=0;j<MAX_PID;j++){
	    pbuffer = &p->latency_list[j];
	    if(pbuffer->pid){
		index=0;
		for(k=0;k<pbuffer->items;k++){
		    //pr_info("%l",pstack->latency[k].tv_usec);
		    index+=sprintf(buff+index,"%ld.%06ld,",pbuffer->latency[k].tv_sec,pbuffer->latency[k].tv_usec);
		}
		if( buff!=NULL && index){
		    buff[index]=0;
		    pr_info("pid=%u,dev_no:%d,latencies:%s",pbuffer->pid,i,buff);
		    index=0;
		}
	    }
	 
	}
    }
    //again resetting the timer.
    mod_timer(&log_timer,PRINT_DELAY);
    return;
}
*/

static int evdev_log_open(struct inode *inode, struct file *file){
    pr_info("Hey!!someone opened me\n");
    return 0;

}


static int fill_device_minors(unsigned int size,void __user *p){
    unsigned char end_mark=END_MARK ;
    unsigned char __user *pbuffer = (unsigned char __user *)p;
    if(copy_to_user(pbuffer,minors,ndevices*sizeof(minors[0]))){
	return -EFAULT;
    }
    /*to mark end */
    if(copy_to_user(&pbuffer[ndevices],&end_mark,sizeof(end_mark))){
	return -EFAULT;
    }
    return 0;
}

struct input_event_logger_type input_log;
struct user_event_log klog;

static int fill_user_log(void __user *p){

    int len=0,ncount=0;
    int i=0,index=0;
    unsigned int minor = 0;
    struct user_args kargs;
    struct user_args __user *puargs = (struct user_args __user *)p;
    struct user_event_log __user *puser_log;
    struct timeval avg;
    /*first copy the args to kernel*/
    if(copy_from_user(&kargs,puargs,sizeof(struct user_args)))
	return -EFAULT;

    puser_log = (struct user_event_log __user *)(kargs.p);
    /*read the minor*/
    minor = kargs.minor;
    


    /*just copy it to temp buffer.*/
    spin_lock(&spinlock);
    memcpy(&input_log,&input_logger_list[minor],
	   sizeof(struct input_event_logger_type));
    spin_unlock(&spinlock);

    /*Now fill klog*/
    len = strlen(input_log.name)+1;
    memcpy(klog.name,input_log.name,len);
    klog.name[len]=0;
    
        
    klog.dev_opened_time = input_log.dev_opened_time;

    /*copy events dropped & event generated.*/
    len = sizeof(safe_count);
    memcpy(&klog.event_dropped,
		 &input_log.event_dropped,len);
    memcpy(&klog.event_generated,
	   &input_log.event_generated,len);

    /*event_consumed per process.*/
    ncount = input_log.ncount;
    for(i=0;i<ncount;i++){
	index = input_log.ptopid[i];
	memcpy(&klog.event_consumed[i],
		     &input_log.event_consumed[index],sizeof(struct consume_event_counts));
	
    }

    /*copy the number of processes using this devices.*/
    memcpy(&klog.ncount,
	   &input_log.ncount,sizeof(unsigned int));
    /*copy whether device is closed or not*/
    memcpy(&klog.bclosed,
	   &input_log.bclosed,sizeof(int));
    
    cal_avg_latency(&input_log,&avg);
    klog.avg.tv_sec=avg.tv_sec; 
    klog.avg.tv_usec=avg.tv_usec; 
    /*
     *Will do latency later.
     */

    /*
     *Now spill everthing in puser_log
     */

    if( copy_to_user(puser_log,&klog,sizeof(struct user_event_log))){
	return -EFAULT;

    }


    return 0;
}




static long evdev_log_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    unsigned int size = _IOC_SIZE(cmd);
        
    pr_info("LGETDEVS with cmd=%u\n",LGETDEVS);
    pr_info("LGETDEVINFO wirh cmd=%u\n",LGETDEVINFO);

    pr_info("ioctl called wirh cmd=%u\n",cmd);
    switch(cmd){
    case LGETDEVS:
	return fill_device_minors(size,(void __user *)arg);
	break;
    case LGETDEVINFO:
	return fill_user_log((void __user *)arg);
	break;
    default:
	return -EACCES;
    }
    
    return 0;
    
}
static int evdev_log_release(struct inode *inode, struct file *file){
    pr_info("hey someone tried to close me");
    return 0;

}



//only implementing IOCTL for this device.
static const struct file_operations evdev_fops = {
    .owner		= THIS_MODULE,
    .open		= evdev_log_open,
    .release	        = evdev_log_release,
    .unlocked_ioctl	= evdev_log_ioctl,
};

static int __init event_log_init(void){
    //here we need to register this subsystem to sysfs.
    //init timer.(will do it later)

    /*
     *Do device specific registration.
     */
    pr_info("event_log_device has been called.");

    /*allcoate major and minor number for the device.
     and create and entry in /proc/devices*/
    if (alloc_chrdev_region(&first, 0, 1, log_dev_name) < 0){
	return -1;
    }
    
    /*create a seperate class for this device.*/
    if ((cl = class_create(THIS_MODULE,class_name)) == NULL){
	unregister_chrdev_region(first, 1);
	return -1;
    }
    
    /*create an entry in /proc/devices*/
    if (device_create(cl, NULL, first, NULL,log_dev_name) == NULL){
	class_destroy(cl);
	unregister_chrdev_region(first, 1);
	return -1;
    }
    cdev_init(&c_dev, &evdev_fops);
    if (cdev_add(&c_dev, first, 1) == -1){
	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);
	return -1;
    }
    
    /*init the logger.*/
    init_logger();
    
    /*init_timer(&log_timer);
    log_timer.expires= PRINT_DELAY;
    log_timer.data = 0;
    log_timer.function=dump_log;
    add_timer(&log_timer);*/
    return 0;

}
static void __init event_log_exit(void){
    //remove the subsystem.
    return ;
}

subsys_initcall(event_log_init);
module_exit(event_log_exit);
