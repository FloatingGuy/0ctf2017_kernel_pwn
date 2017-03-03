#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#define DEBUG

#ifdef DEBUG
#define LOG(...) printk(KERN_INFO __VA_ARGS__)
#elif
#define LOG(...) ((void) 0)
#endif

/* magic number */
#define NOTE_MAGIC  0xdeadc0dedeadbeef
#define EDIT_TIME   0xa11ab11bc11cd11d
#define EDIT_NOTE   0x1ee12ee23ee34ee4

/* knote functions */
#define NOTE_ADD 0
#define NOTE_DELETE 1
#define NOTE_EDIT

static bool device_inuse;
static DEFINE_MUTEX(hlist_lock);
static DEFINE_HASHTABLE(notes, 16);

struct note_t {
    unsigned long magic;
    unsigned long year, month, day;
    unsigned long h, m, s;
    unsigned long epoch;
    void *buf;
    struct hlist_node next;
};

struct note_io_t {
    unsigned long year, month, day;
    unsigned long h, m, s;
    void __user *buf; 
};

struct time_io_t {
    int magic;
    unsigned long year, month, day;
    unsigned long h, m, s;
};

struct buf_io_t {
    int magic;
    void __user *buf;
};
    
unsigned long inline get_epoch(struct note_t *note)
{
    int days[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int i;
    unsigned long yday = 0;

    if ((note->year % 4 == 0 && note->year % 100 != 0)
       || (note->year % 400 == 0))
        days[2] += 1

    for (i = 1; i < note->month; ++i)
        yday += days[i];
    yday += note->day;

    return note->s + note->m * 60 + note->h * 3600 + yday * 86400
        + (note->year-70) * 31536000 + ((note->year - 69) / 4) * 86400 
        - ((note->year - 1) / 100) * 86400 + ((note->year + 299) / 400) * 86400;
}

static void *buf;
long test(void)
{
	int i;
	unsigned long magic;

	buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	LOG("allocate: 0x%08lx\n", (unsigned long)buf);
	for (i = 0; i < 100; ++i) {
		magic = *(unsigned long *)(buf + BUFFER_SIZE + i * 8);
		LOG("+%x: 0x%08lx\n", i * 8, magic);	
		// if (magic == 0x5401) {
	//		printk("hit!\n");
//		}
	}

	return 0;
}

void alloc_note(void)
{
    
}

static long note_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	LOG("ioctl device\n");
	switch(cmd) {
		case 0:
			ret = test();
			break;
		default:
			break;
	}
	return ret;
}

static int note_open(struct inode *inode, struct file *file)
{
	device_inuse = true;
	LOG("open device\n");
	return 0;
}

static int note_release(struct inode *inode, struct file *file)
{
	device_inuse = false;
	LOG("close device\n");
	return 0;
}

struct file_operations note_fops = {
	owner: THIS_MODULE,
	open: note_open,
	release: note_release,
	unlocked_ioctl: note_ioctl,
};

static int __init init_note(void)
{
	int ret;
	ret = register_chrdev(1337, "knote", &note_fops);
	LOG("register device: %d\n", ret);

	return ret;
}

static void __exit exit_note(void)
{
	unregister_chrdev(1337, "knote");
	LOG("exit.\n");
}

module_init(init_note);
module_exit(exit_note);

MODULE_LICENSE("GPL");

