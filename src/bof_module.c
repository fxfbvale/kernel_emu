#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>


MODULE_LICENSE("GPL"); 

char leak[128];
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
    char buffer[100];

    printk(KERN_INFO "Testing...");
    memcpy(buffer, buf, 0x100);

    printk(KERN_INFO "Yes? %s", buffer);

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
