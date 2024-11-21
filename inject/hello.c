// hello.c
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hash");
MODULE_DESCRIPTION("Hello World");

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, world!\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Bye!\n");
}

module_init(hello_init);
module_exit(hello_exit);
