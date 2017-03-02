#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#define DEBUG

#ifdef DEBUG
#define LOG(...) printk(KERN_INFO __VA_ARGS__)
#elif
#define LOG(...) ((void) 0)
#endif

static bool device_inuse;
static DEFINE_MUTEX(hlist_lock);

static long note_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	LOG("ioctl device\n");
	return 0;
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

void 
static int __init init_note(void)
{
	int ret;
	ret = register_chrdev(1337, "knote", &note_fops);
	LOG("register device: %d\n", ret);

	test();

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

