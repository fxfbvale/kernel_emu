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

void read_proc_kallsyms(void)
{
  // read in the /proc/kallsyms file
  loff_t offset = 0;
  struct file *leak_fd;
  leak_fd = filp_open("/proc/kallsyms", O_RDONLY, 0);
  kernel_read(leak_fd, leak, 128, &offset);
  filp_close(leak_fd, NULL);
  printk(KERN_ALERT "leak: %s\n", leak);

}


static long proc_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
  read_proc_kallsyms();

	int ret = 0;	
  ret = copy_to_user(buffer, leak, 128);

	if (ret)
		return -EFAULT;
	return ret;
}

static struct file_operations fops = {
  	.read = proc_read,
  	.open = device_open,
  	.release = device_release
};

struct proc_dir_entry *proc_entry = NULL;

int init_module(void)
{
  proc_entry = proc_create("leak", 0666, NULL, &fops);
  printk(KERN_ALERT "/proc/leak created\n");
  return 0;
}

void cleanup_module(void)
{
	if (proc_entry) proc_remove(proc_entry);
  printk(KERN_ALERT "/proc/leak reomved\n");
}
