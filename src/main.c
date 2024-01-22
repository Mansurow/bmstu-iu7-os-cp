#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mansurov Vladislav");
MODULE_DESCRIPTION("Program");
MODULE_VERSION("Version 1.0");

static int __init md_init(void)
{
    printk(KERN_INFO "INFO: Hello World!\n");

    return 0;
}

static void __exit md_exit(void)
{
    printk(KERN_INFO "INFO: Good buy!\n");
}

module_init(md_init);
module_exit(md_exit);