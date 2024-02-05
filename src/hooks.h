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
#include <linux/ipc.h>
#include <linux/signal.h>
#include <linux/sem.h>
#include <linux/shm.h>

#include "utils.h"
#include "list.h"

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
extern plist pipe_info_list;
extern semlist *sem_info_list;
extern shmlist *shm_info_list;
#endif