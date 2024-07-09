#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

#define LEAK_SIZE 21

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("vale");
MODULE_DESCRIPTION("A simple kernel module that leaks the address of kernel_listen.");

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
  /**
   * read in the /proc/kallsyms file
   * 
   * grep -n kernel_listen /proc/kallsyms | head -n 1 | cut -d: -f1
      39720

   
   - Number of bytes until kernel_listen
   * head -n 39720 /proc/kallsyms | wc -c
      1591068
  */
  loff_t offset = 1591068;
  struct file *leak_fd;
  leak_fd = filp_open("/proc/kallsyms", O_RDONLY, 0);
  kernel_read(leak_fd, leak, 16, &offset);
  filp_close(leak_fd, NULL);
}


static long proc_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
  read_proc_kallsyms();

	int ret = 0;
  char leak_str[LEAK_SIZE];
  unsigned long leak_ul;
  kstrtoul(leak, 16, &leak_ul);
  snprintf(leak_str, LEAK_SIZE, "%lu", leak_ul);
  ret = copy_to_user(buffer, leak_str, LEAK_SIZE);

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
