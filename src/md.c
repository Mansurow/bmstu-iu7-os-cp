#include <linux/delay.h>
#include <linux/init.h>
#include <linux/init_task.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>

#include <linux/sched/signal.h>

#include <linux/types.h>
#include <linux/ipc.h>
#include <linux/signal.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mansurov Vladislav");
MODULE_DESCRIPTION("MONITORING PROCCESS");
MODULE_VERSION("1.0");

#define PREFIX        "[MONITORING]"
#define FORTUNEPREFIX "[FORTUNE]"
#define GENERALPREFIX "[GENERAL]"
#define SIGNALPREFIX  "[SIGNAL]"
#define SEMPREFIX     "[SEMAFORE]"
#define SHMPREFIX     "[SHM]"
#define PIPEPREFIX    "[PIPE]"

#define PID_MAX 4194304
#define LOG_SIZE 262144

// TODO: добавить папку для вывода сигналов, семафоров... для каждого pid отдельно...
#define FILENAME "signals"
#define DIRNAME  "monitoring"
#define FILEPATH DIRNAME "/" FILENAME

static struct proc_dir_entry *proc_file = NULL;
static struct proc_dir_entry *proc_dir = NULL;

struct monitoring_signal_struct
{
    int count_received; // количество полученных сигналов
    int count_sent; // количество отправленных сигналов  
};

struct monitoring_task_struct
{
    struct monitoring_signal_struct m_signal[_NSIG];
};

static struct monitoring_task_struct mtasks[PID_MAX];

static const char *signal_names[] = {
    "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP",
    "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1",
    "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM",
    "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP",
    "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ",
    "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR",
    "SIGSYS",  "", "", "SIGRTMIN", "SIGRTMIN+1", "SIGRTMIN+2", "SIGRTMIN+3",
    "SIGRTMIN+4", "SIGRTMIN+5", "SIGRTMIN+6", "SIGRTMIN+7", "SIGRTMIN+8",
    "SIGRTMIN+9", "SIGRTMIN+10", "SIGRTMIN+11", "SIGRTMIN+12", "SIGRTMIN+13",
    "SIGRTMIN+14", "SIGRTMIN+15", "SIGRTMAX-14", "SIGRTMAX-13", "SIGRTMAX-12",
    "SIGRTMAX-11", "SIGRTMAX-10", "SIGRTMAX-9", "SIGRTMAX-8", "SIGRTMAX-7",
    "SIGRTMAX-6", "SIGRTMAX-5", "SIGRTMAX-4", "SIGRTMAX-3", "SIGRTMAX-2",
    "SIGRTMAX-1", "SIGRTMAX",
};


static char log[LOG_SIZE] = { "HELLO WORLD!\n" };

static pid_t target_pid = 20403;

static int check_overflow(char *fString, char *sString, int maxSize)
{
    int sumLen = strlen(fString) + strlen(sString);

    if (sumLen >= maxSize)
    {
        printk(KERN_ERR "%s not enough space in log (%d needed but %d available)\n", PREFIX, sumLen, maxSize);

        return -ENOMEM;
    }

    return 0;
}

static void init_mtasks(void)
{
    int pid;

    for (pid = 0; pid < PID_MAX; ++pid) {
        int signo;

        for (signo = 0; signo < _NSIG; ++signo) {
            mtasks[pid].m_signal[signo].count_received = 0;
            mtasks[pid].m_signal[signo].count_sent = 0;
        }
    }
}

static void print_sem(struct task_struct *task)
{
    // struct task_struct *p = current;
    // struct list_head *pos;

    // down_read(&p->mm->mmap_sem);

    // printk(KERN_INFO "Process ID: %d\n", task->pid);
    // printk(KERN_INFO "Semafores:\n");

    // list_for_each(pos, &p->mm->mmap_list) {
    //     struct vm_area_struct *vma = container_of(pos, struct vm_area_struct, vm_mmap);

    //     if (vma->vm_flags & VM_SHARED) {
    //         printk(KERN_INFO "Start: %lx, End: %lx\n", vma->vm_start, vma->vm_end);
    //     }
    // }

    // up_read(&p->mm->mmap_sem);
}

static void print_page(struct page *page)
{
    int page_type = (int)page->page_type;
    int ref_count = page_ref_count(page);
    int map_count = atomic_read(&page->_mapcount);

    printk(KERN_INFO "%s[PAGE]: type: %d, ref_count: %d, map_count: %d\n",
           PREFIX, page_type, ref_count, map_count);
}

static int walk_page_table(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t* p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;

    struct page *page = NULL;

    pgd = pgd_offset(mm, vaddr);

    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 1;

    p4d = p4d_offset(pgd, vaddr);

    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 1;

    pud = pud_offset(p4d, vaddr);

    if (pud_none(*pud) || pud_bad(*pud))
        return 1;

    pmd = pmd_offset(pud, vaddr);

    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return 1;

    ptep = pte_offset_map(pmd, vaddr);

    if (!ptep)
        return 1;

    pte = *ptep;
    page = pte_page(pte);

    if (page)
        print_page(page);

    pte_unmap(ptep);
    return 0;
}    

static void print_info_mm(pid_t pid, struct mm_struct *info_about_mem)
{
    if (info_about_mem == NULL)
    {
        pr_info("%s[Memory][%d]: нет доступа\n", PREFIX, pid);
        return;
    }


    atomic_t mm_users; 
	int counter;

	mm_users = info_about_mem->mm_users; /* Счетчик использования адресного пространства */
	counter = mm_users.counter;

	unsigned long total_vm_old = info_about_mem->total_vm;
	unsigned long locked_vm_old = info_about_mem->locked_vm;
	int map_count_old = info_about_mem->map_count;
	unsigned long all_brk_old = info_about_mem->brk - info_about_mem->start_brk;

	printk(KERN_INFO "%s[Memory][%d]: Количество процессов, в которых используется данное адресное пространство: %d", PREFIX, pid, counter);

	printk(KERN_INFO "%s[Memory][%d]: Общее количество страниц памяти = %lu ", PREFIX, pid, total_vm_old);
	printk(KERN_INFO "%s[Memory][%d]: Количество заблокированных страниц памяти = %lu ", PREFIX, pid, locked_vm_old);
	printk(KERN_INFO "%s[Memory][%d]: Количество областей памяти: %d", PREFIX, pid, map_count_old);

	printk(KERN_INFO "%s[Memory][%d]: Используется сегментом кучи: %lu", PREFIX, pid, all_brk_old);
	printk(KERN_INFO "%s[Memory][%d]: Используется сегментом кода: %lu", PREFIX, pid, info_about_mem->end_code - info_about_mem->start_code);
	printk(KERN_INFO "%s[Memory][%d]: Используется сегментом данных: %lu", PREFIX, pid, info_about_mem->end_data - info_about_mem->start_data);

    // struct vm_area_struct *vma = info_about_mem->mmap;

    // unsigned long vaddr;
    // int page_number = 0;

    // for (; vma != NULL; vma = vma->vm_next)
    // {
    //     for (vaddr = vma->vm_start; vaddr < vma->vm_end; vaddr += PAGE_SIZE)
    //     {
    //         printk(KERN_INFO "%s[Memory][%d]: номер таблицы %d.\n",
    //                PREFIX, pid, page_number++);

    //         if (walk_page_table(info_about_mem, vaddr) != 0)
    //         {
    //             printk(KERN_INFO "%s[Memory][%d]: страница нет в таблице.\n",
    //                    PREFIX, pid); 
    //         }
    //     }
    // }
}

static void print_signal_info(int signo, struct k_sigaction *ka) {

    int index = signo - 1;
    if (ka->sa.sa_handler == SIG_DFL) 
    {
        pr_info("Default action for signal %d (%s)\n", signo, signal_names[index]);
    } 
    else if (ka->sa.sa_handler == SIG_IGN) 
    {
        pr_info("Signal %d (%s) ignored\n", signo), signal_names[index];
    } 
    else 
    {
        pr_info("Custom handler for signal %d (%s)\n", signo, signal_names[index]);
        // pr_info("Handler Address: 0x%lx\n", (unsigned long)ka->sa.sa_handler);
        // pr_info("Flags: %ld\n", ka->sa.sa_flags);
    }
}

static void print_general_info(struct task_struct *task)
{
    pr_info("%s[GENERAL]: " 
            "pid: %d, ppid: %d, pgid: %d, name: %s\nprio: %d, static prio: %d, normal prio: %d, realtime_prio: %d\n"
            "delay: %lld\n"
            "utime: %lld ticks, stime: %lld ticks\n"
            "Sched_rt_entity: timeout: %ld, watchdog_stamp: %ld, time_slice:%ld\n", 
            PREFIX,
            task->pid, task->parent->pid, task->group_leader->pid, task->comm,
            task->prio, task->static_prio, task->normal_prio, task->rt_priority,
            task->sched_info.run_delay, task->utime, task->stime,
            task->rt.watchdog_stamp, task->rt.time_slice);
} 

static void print_signals(struct task_struct *task)
{
    struct sighand_struct *sighand = task->sighand;

    // for (int signo = 1; signo < _NSIG; ++signo) {
    //     struct k_sigaction *ka = &sighand->action[signo-1];
    //     print_signal_info(signo, ka);
    // }

    struct signal_struct *sig = task->signal;
    struct sigpending *pending = &sig->shared_pending;
    struct sigqueue *q;

    list_for_each_entry(q, &pending->list, list) {
        pr_info("Received signal %d from PID %d\n", q->info.si_signo, q->info.si_pid);
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_kill)(const struct pt_regs *);

static asmlinkage int hook_sys_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    // mtasks[current->pid].m_signal[signo].count_sent++;
    // mtasks[pid].m_signal[signo].count_received++;

    real_sys_kill(regs);
    return 0;
}
#else
static asmlinkage long (*real_sys_kill)(pid_t pid, int sig);

static asmlinkage int hook_sys_kill(pid_t pid, int sig)
{
    printk(KERN_INFO "Сигнал отправлен %d (%s) процессу %d\n", sig, signal_names[sig], pid);

    real_sys_kill(pid, sig);
    return 0;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)   \
{                                               \
    .name = SYSCALL_NAME(_name),                \
    .function = (_function),                    \
    .original = (_original),                    \
}

static struct ftrace_hook hooks[] = {
    HOOK("sys_kill",  hook_sys_kill,  &real_sys_kill),
};


static int monitoring_open(struct inode *spInode, struct file *spFile)
{
    printk(KERN_INFO "fortune: open called\n");
    return 0;
}


static int monitoring_release(struct inode *spInode, struct file *spFile)
{
    printk(KERN_INFO "fortune: release called\n");
    return 0;
}


static ssize_t monitoring_write(struct file *file, const char __user *buf, size_t len, loff_t *fPos)
{
    printk(KERN_INFO "fortune: write called\n");

    return 0;
}


static ssize_t monitoring_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    if (*fPos > 0)
        return 0;

    printk(KERN_INFO "fortune: read called\n");

    ssize_t logLen = strlen(log);

    printk(KERN_INFO "%s read called\n", PREFIX);

    if (copy_to_user(buf, log, logLen))
    {
        printk(KERN_ERR "%s copy_to_user error\n", PREFIX);

        return -EFAULT;
    }

    *fPos += logLen;

    return logLen;
}

static struct proc_ops fops = {
    .proc_open = monitoring_open,
    .proc_read = monitoring_read,
    .proc_write = monitoring_write,
    .proc_release = monitoring_release,
};

static int __init md_init(void)
{
    

    // struct task_struct *task = &init_task; 

    // struct task_struct *task = pid_task(find_vpid(target_pid), PIDTYPE_PID);;
    // if (!task) {
    //     pr_err("Process with PID %d not found\n", target_pid);
    //     return -ESRCH;
    // }

    // do {
    //     printk(KERN_INFO "%s[GENERAL]: " 
    //         "pid: %d, ppid: %d, pgid: %d, name: %s\nprio: %d, static prio: %d, normal prio: %d, realtime_prio: %d\n"
    //         "delay: %lld\n"
    //         "utime: %lld ticks, stime: %lld ticks\n"
    //         "Sched_rt_entity: timeout: %ld, watchdog_stamp: %ld, time_slice:%ld\n", 
    //         PREFIX,
    //         task->pid, task->parent->pid, task->group_leader->pid, task->comm,
    //         task->prio, task->static_prio, task->normal_prio, task->rt_priority,
    //         task->sched_info.run_delay, task->utime, task->stime,
    //         task->rt.watchdog_stamp, task->rt.time_slice);
     
    //     if (task->mm != NULL)
    //     {
    //         print_info_mm(task->pid, task->mm);
    //     }
    //     else
    //     {
    //         printk(KERN_INFO "%s[Memory][%d]: нет доступа", PREFIX, task->pid);
    //     }
    //     printk(KERN_INFO "\n");

    // } while ((task = next_task(task)) != &init_task);
     
    // print_general_info(task); 
    // print_info_mm(task->pid, task->mm);
    // print_signals(task);

    if ((proc_dir = proc_mkdir(DIRNAME, NULL)) == NULL)
    {
        printk(KERN_ERR "proc_mkdir error\n");
        if (proc_file != NULL)
            remove_proc_entry(FILENAME, proc_dir);

        if (proc_dir != NULL)
            remove_proc_entry(DIRNAME, NULL);

        return -ENOMEM;
    }

    if (!(proc_file= proc_create(FILENAME, 0666, proc_dir, &fops)))
    {
        printk(KERN_ERR "%s proc_create error\n", PREFIX);

        if (proc_file != NULL)
            remove_proc_entry(FILENAME, proc_dir);

        if (proc_dir != NULL)
            remove_proc_entry(DIRNAME, NULL);

        return -ENOMEM;
    }


    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
    {
        if (proc_file != NULL)
            remove_proc_entry(FILENAME, proc_dir);

        if (proc_dir != NULL)
            remove_proc_entry(DIRNAME, NULL);
        return err;
    }

    // init_mtasks();

    pr_info("%s: module loaded!\n", PREFIX);

    return 0;
}

static void __exit md_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    if (proc_file != NULL)
        remove_proc_entry(FILENAME, proc_dir);

    if (proc_dir != NULL)
        remove_proc_entry(DIRNAME, NULL);

    pr_info("%s: module unloaded!\n", PREFIX);
}

module_init(md_init);
module_exit(md_exit);