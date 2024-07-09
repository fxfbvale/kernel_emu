#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <asm/pgtable_types.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <linux/init.h>
#include <asm/set_memory.h>

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("vale");
MODULE_DESCRIPTION("A kernel module with a buffer overflow vulnerability.");

char * message_receiver [0x1000];

static int device_open(struct inode *inode, struct file *filp)
{
    	printk(KERN_ALERT "Device opened.\n");
  	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    	printk(KERN_ALERT "Device closed.\n");
  	return 0;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off) {
    int ret;
    char tmp_buffer[200];
   
    ret = copy_from_user(message_receiver, buf, len);

    if (ret)
		  return -EFAULT;

    memcpy(tmp_buffer, message_receiver, len);


    printk(KERN_ALERT "Yes? %s", tmp_buffer);

    return 0;
}

static struct file_operations fops = {
  	.write = device_write,
  	.open = device_open,
  	.release = device_release
};

struct proc_dir_entry *proc_entry = NULL;

int init_module(void)
{
  proc_entry = proc_create("bof", 0666, NULL, &fops);
  printk(KERN_ALERT "/proc/bof created\n");
  return 0;
}

void cleanup_module(void)
{
	if (proc_entry) proc_remove(proc_entry);
    printk(KERN_ALERT "/proc/bof reomved\n");

}
