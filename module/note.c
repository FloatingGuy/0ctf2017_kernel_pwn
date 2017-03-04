#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/rbtree.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/errno.h>
#define DEBUG

#ifdef DEBUG
#define LOG(...) printk(KERN_INFO __VA_ARGS__)
#elif
#define LOG(...) ((void) 0)
#endif

/* magic number */
#define NOTE_MAGIC  0xdeadbeef
#define EDIT_TIME   0xa11ab11bc11cd11d
#define EDIT_NOTE   0x1ee12ee23ee34ee4

/* knote functions */
#define NOTE_ADD 0
#define NOTE_DELETE 1
#define NOTE_READ 2
#define NOTE_EDIT 3

/* consts */
#define BUFFER_SIZE 1024

static bool device_inuse;
static unsigned long cnt;
static DEFINE_MUTEX(hlist_lock);
static DEFINE_HASHTABLE(notes, 3);
static struct rb_root slot_cache = RB_ROOT;

struct slot_t {
	struct rb_node node;
	unsigned long addr;
};

struct date_t {
	unsigned long year, month, day;
	unsigned long h, m, s;
};

struct note_t {
    unsigned long magic;
	struct date_t date;
    unsigned long epoch;
    void *buf;
    struct hlist_node next;
};

struct note_io_t {
	struct date_t date;
	unsigned long buf_size;
    void __user *buf; 
};

struct delete_io_t {
	unsigned long magic;
	struct date_t date;
};

struct read_io_t {
	unsigned long magic;
	struct date_t date;
	unsigned long buf_size;
	void __user *buf;
}

struct time_io_t {
    unsigned long cmd;
	unsigned long magic;
	struct date_t date;
	struct date_t new_date;
};

struct buf_io_t {
	unsigned long cmd;
    unsigned long magic;
	struct date_t date;
	unsigned long buf_size;
    void __user *buf;
};
   
bool slot_insert(struct rb_root *root, struct slot_t *slot)
{
	struct rb_node **p = &(root->rb_node), *parent = NULL;

	while (*p) {
		struct slot_t *cur = container_of(*p, struct slot_t, node);
		parent = *p;

		if (slot->addr < cur->addr)
			p = &((*p)->rb_left);
		else if (slot->addr > cur->addr)
			p = &((*p)->rb_right);
		else
			return false;
	}

	rb_link_node(&slot->node, parent, p);
	rb_insert_color(&slot->node, root);

	return true;
}

bool slot_search(struct rb_root *root, unsigned long addr)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct slot_t *cur = container_of(node, struct slot_t, node);
		if (addr < cur->addr)
			node = node->rb_left;
		else if (addr > cur->addr)
			node = node->rb_right;
		else
			return true;
	}

	return false;
}

bool slot_delete(struct rb_root *root, unsigned long addr)
{
	struct slot_t *slot = slot_search(root, addr);

	if (slot) {
		rb_erase(&slot->node, root);
		kfree(slot);
		return true;
	}

	return false;
}

unsigned long inline get_epoch(struct date_t *date)
{
    int days[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int i;
    unsigned long yday = 0;

    if ((date->year % 4 == 0 && date->year % 100 != 0)
       || (date->year % 400 == 0))
        days[2] += 1;

    for (i = 1; i < date->month; ++i)
        yday += days[i];
    yday += date->day;

    return date->s + date->m * 60 + date->h * 3600 + yday * 86400
        + (date->year-70) * 31536000 + ((date->year - 69) / 4) * 86400 
        - ((date->year - 1) / 100) * 86400 + ((date->year + 299) / 400) * 86400;
}

/*
long test(void)
{
	int i;
	struct slot_t *p;

	for (i = 1; i < 20; i += 2)
	{
		p = kmalloc(sizeof(struct slot_t), GFP_KERNEL);
		p->addr = i;

		slot_insert(&slot_cache, p);
	}

	LOG("search %d result: %d\n", 3, slot_search(&slot_cache, 3));
	LOG("search %d result: %d\n", 17, slot_search(&slot_cache, 17));
	LOG("search %d result: %d\n", 6, slot_search(&slot_cache, 6));
	LOG("search %d result: %d\n", 22, slot_search(&slot_cache, 22));

	return 0;
}
*/

void put_note(struct note_t *note)
{
	if (note->buf) {
		/* first remove from rb tree */
		slot_delete(&slot_cache, (unsigned long)note->buf);
		kfree(note->buf);
	}
	
	kfree(note);	
}

struct note_t *find_note(unsigned long epoch, unsigned long magic)
{
	struct note_t *note;

	hash_for_each_possible(notes, note, next, epoch) {
		if (note->magic == magic)
			return note;
	}

	return NULL;
}

struct note_t *alloc_note(void)
{
	bool ret;
	struct note_t *note = NULL;
	struct slot_t *slot = NULL;

	LOG("sizeof note: %d\n", sizeof(struct note_t));	
	note = kmalloc(sizeof(struct note_t), GFP_KERNEL);
	if (!note)
		goto out;

	note->magic = NOTE_MAGIC;

	note->buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!note->buf) 
		goto free_note;
	
	slot = kmalloc(sizeof(struct slot_t), GFP_KERNEL);
	if (!slot)
		goto free_buf;
	slot->addr = (unsigned long)note->buf;

	ret = slot_insert(&slot_cache, slot);
	if (ret)	
		goto out;

free_slot:
	LOG("insert fail!\n");
	kfree(slot);

free_buf:
	LOG("slot malloc fail!\n");
	kfree(note->buf);

free_note:
	LOG("buf malloc fail!\n");
	kfree(note);	
	note = NULL;

out:
	return note;
}

int delete_note(unsigned long arg)
{
	struct delete_io_t io;
	struct note_t *note;
	unsigned long epoch;
	int ret;
		
	ret = copy_from_user((void *)&io, (void __user *)arg, sizeof(struct delete_io_t));
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	epoch = get_epoch(&(io.date));
	note = find_note(epoch, io.magic);
	if (!note) {
		ret = -EINVAL;
		goto out;
	}
	
	put_note(note);
	
out:
	return ret;
}

int edit_note_buf(unsigned long arg)
{
	int ret;
	struct note_t *note;

	LOG("edit note buf\n");		
		
}

int edit_note(unsigned long arg)
{
	unsigned long cmd;
	int ret = 0;

	get_user(cmd, (unsigned long *)arg);

	if (cmd == EDIT_NOTE)
		return edit_note_buf(arg);
	else if (cmd == EDIT_TIME)
		return edit_note_time(arg);
	else
		return -EINVAL;
}

int read_note(unsigned long arg)
{
	struct read_io_t io;
	struct note_t *note;
	unsigned long epoch;
	int ret;

	ret = copy_from_user((void *)&io, (void __user *)arg, sizeof(struct read_io_t));
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	epoch = get_epoch(&(io.date));
	note = get_note(epoch, io.magic);

	if (!note) {
		ret = -EINVAL;
		goto out;
	}

	if (io.buf_size > BUFFER_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	return copy_to_user(io.buf, note->buf, io.buf_size);

out:
	return ret;
}

int add_note(unsigned long arg)
{
	struct note_io_t io;
	struct note_t *note;
	int ret;

	ret = copy_from_user((void *)&io, 
					(void __user *)arg,
					sizeof(struct note_io_t));
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	note = alloc_note();	
	if (!note) {
		ret = -ENOMEM;
		goto free_note;
	}

	note->magic = NOTE_MAGIC + (cnt++);
	memcpy(&(note->date), &(io.date), sizeof(struct date_t));
	note->epoch = get_epoch(note);

	if (io.buf_size > BUFFER_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	ret = copy_from_user(note->buf, io.buf, io.buf_size); 
	if (ret) {
		ret = -EINVAL;
		goto free_note;
	}

	hash_add(notes, &note->next, note->epoch);	
	return 0;

free_note:
	put_note(note);

out:
	return ret;
}

static long note_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	LOG("ioctl device\n");
	switch(cmd) {
		case NOTE_ADD:
			ret = add_note(arg);
			break;
		case NOTE_DELETE:
			ret = delete_note(arg);
			break;
		case NOTE_READ:
			ret = read_note(arg);
		default:
			ret = 
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

	cnt = 0;

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

