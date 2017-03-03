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

#define BUFFER_SIZE 1024
static bool device_inuse;
static DEFINE_MUTEX(hlist_lock);

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

