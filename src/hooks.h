#ifndef __HOOKS_H_
#define __HOOKS_H_

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#include "utils.h"

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

void remove_hooks(void); 
int install_hooks(void);

extern char signal_logs[LOG_SIZE];

#endif