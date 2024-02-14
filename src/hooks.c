#include "hooks.h"

extern char signal_logs[LOG_SIZE] = { 0 };

extern plist pipe_info_list = { 
    .len = 0,
    .head = NULL,
    .tail = NULL
};

extern semlist *sem_info_list = NULL;
extern shmlist *shm_info_list = NULL;

static DEFINE_SPINLOCK(signal_logs_lock);
static DEFINE_SPINLOCK(pipe_lock);
static DEFINE_SPINLOCK(sem_lock);
static DEFINE_SPINLOCK(shm_lock);

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

// SYS_KILL
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_kill)(const struct pt_regs *);

static asmlinkage int hook_sys_kill(const struct pt_regs *regs)
{
    int res = real_sys_kill(regs);

	pid_t pid = regs->di;
	int sig = regs->si;

	if (res == 0 && sig > 0)
	{
		char currentString[TEMP_STRING_SIZE];
		
		memset(currentString, 0, TEMP_STRING_SIZE);	
		snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d sent signal %s to process %d\n", current->pid, signal_names[sig], pid);

		spin_lock(&signal_logs_lock);

		strcat(signal_logs, currentString); 

		spin_unlock(&signal_logs_lock);

		printk(KERN_INFO "%s%s: Process %d sent signal %s to process %d\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig], pid);
		
	}

    return res;
}
#else
static asmlinkage long (*real_sys_kill)(pid_t pid, int sig);

static asmlinkage int hook_sys_kill(pid_t pid, int sig)
{
    int res = real_sys_kill(pid, sig);

	if (res == 0)
	{
		char currentString[TEMP_STRING_SIZE];

		memset(currentString, 0, TEMP_STRING_SIZE);	
		snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d sent signal %s to process %d\n", current->pid, signal_names[sig], pid);

		spin_lock(&signal_logs_lock);

		strcat(signal_logs, currentString); 

		spin_unlock(&signal_logs_lock);

		pr_info("%s%s: Process %d sent signal %s to process %d\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig], pid);
	}

    return res;
}
#endif

// SYS_SIGNAL
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_signal)(const struct pt_regs *);

static asmlinkage int hook_sys_signal(const struct pt_regs *regs)
{
    pid_t sig = regs->di;

    char currentString[TEMP_STRING_SIZE];

    memset(currentString, 0, TEMP_STRING_SIZE);	
	snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d assign own handler for signal %s\n", current->pid, signal_names[sig]);

	spin_lock(&signal_logs_lock);

	strcat(signal_logs, currentString); 

	spin_unlock(&signal_logs_lock);

	printk(KERN_INFO "%s%s: Proccess %d assign own handler for signal %s\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig]);

    real_sys_signal(regs);

    return 0;
}
#else
static asmlinkage long (*real_sys_signal)(int sig, __sighandler_t handler);

static asmlinkage int hook_sys_signal(int sig, __sighandler_t handler);
{
	char currentString[TEMP_STRING_SIZE];

    memset(currentString, 0, TEMP_STRING_SIZE);	
	snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d assign own handler for signal %s\n", current->pid, signal_names[sig]);

	spin_lock(&signal_logs_lock);

	strcat(signal_logs, currentString); 

	spin_unlock(&signal_logs_lock);

	printk(KERN_INFO "%s%s: Proccess %d assign own handler for signal %s\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig]);

    real_sys_signal(sig, handler);
    return 0;
}
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

// SYS_SEMGET
static void get_sem_info(int semid, int nsems, int semflg)
{
	spin_lock(&sem_lock);

	for (int semnum = 0; semnum < nsems; semnum++)
	{
		sem_info_t info = {
			.semid = semid,
			.semnum = semnum + 1,
			.pid = current->pid,
			.semflg = semflg,
			.lastcmd = -1,
			.value = -1
		};

		push_bask_semlist(sem_info_list, info);
	}

	spin_unlock(&sem_lock);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_semget)(const struct pt_regs *);

static asmlinkage int hook_sys_semget(const struct pt_regs *regs)
{
    int semid = real_sys_semget(regs);

	key_t key = regs->di;
	int nsems = regs->si;
	int semflg = regs->dx;

	if (semid == -1)
	{
		pr_err("%s%s: Proccess %d can't create or get %d semafores\n", PREFIX, SEMPREFIX, current->pid, nsems);
	}
	else
	{
		get_sem_info(semid, nsems, semflg);
		pr_info("%s%s: Proccess %d create or get %d semafores with semid %d\n", PREFIX, SEMPREFIX, current->pid, nsems, semid);
	}

    return semid;
}
#else
static asmlinkage long (*real_sys_semget)(key_t key, int nsems, int semflg);

static asmlinkage int hook_sys_semget(key_t key, int nsems, int semflg)
{
    int semid = real_sys_semget(key, nsems, semflg);

	if (semid == -1)
	{
		pr_err("%s%s: Proccess %d can't create or get %d semafores\n", PREFIX, SEMPREFIX, current->pid, nsems);
	}
	else
	{
		get_sem_info(semid, nsems, semflg);
		pr_info("%s%s: Proccess %d create or get %d semafores with semid %d\n", PREFIX, SEMPREFIX, current->pid, nsems, semid);
	}

    return semid;
}
#endif

// SYS_SEMOP
static void update_semop_info(int semid, struct sembuf __user *sops)
{
	spin_lock(&sem_lock);

	semnode *head = sem_info_list->head;

	for(;head; head = head->next)
	{
		if (head->info.semid == semid && head->info.semnum == sops->sem_num)
		{
			head->info.value += sops->sem_op;
		} 
	}

	spin_unlock(&sem_lock);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_semop)(const struct pt_regs *);

static asmlinkage int hook_sys_semop(const struct pt_regs *regs)
{
    int res = real_sys_semop(regs);

	int semid = regs->di;
	struct sembuf __user *sops = regs->si;
	unsigned nsops = regs->dx;
	
	if (res == -1)
	{
		pr_err("%s%s: Proccess %d can't operate with %d semafore on semid %d\n", PREFIX, SEMPREFIX, current->pid, sops->sem_num, semid);
	}
	else
	{
		update_semop_info(semid, sops);
		pr_info("%s%s: Proccess %d operate with %d semafore on semid %d\n", PREFIX, SEMPREFIX, current->pid, sops->sem_num, semid);
	}

    return res;
}
#else
static asmlinkage long (*real_sys_semop)(int semid, struct sembuf __user *sops, unsigned nsops);

static asmlinkage int hook_sys_semop(int semid, struct sembuf __user *sops, unsigned nsops)
{
    int res = real_sys_semop(semid, sops, nsops);

	if (res == -1)
	{
		pr_err("%s%s: Proccess %d can't operate with %d semafore on semid %d\n", PREFIX, SEMPREFIX, current->pid, sops->sem_num, semid);
	}
	else
	{
		update_semop_info(semid, sops);
		pr_info("%s%s: Proccess %d operate with %d semafore on semid %d\n", PREFIX, SEMPREFIX, current->pid, sops->sem_num, semid);
	}
    return res;
}
#endif

// SYS_SEMTIMEDOP
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_semtimedop)(const struct pt_regs *);

static asmlinkage int hook_sys_semtimedop(const struct pt_regs *regs)
{
    int res = real_sys_semtimedop(regs);

	int semid = regs->di;
	struct sembuf __user *sops = regs->si;
	unsigned nsops = regs->dx;

	pr_info("%s%s: Proccess %d operate with %d semafore on semid %d\n", PREFIX, SEMPREFIX, current->pid, sops->sem_num, semid);

    return res;
}
#else
static asmlinkage long (*real_sys_semtimedop)(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout);

static asmlinkage int hook_sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout)
{
    int res = real_sys_semtimedop(semid, sops, nsops, timeout);

	pr_info("%s%s: Proccess %d operate with %d semafore on semid %d\n", PREFIX, SEMPREFIX, current->pid, sops->sem_num, semid);

    return res;
}
#endif


// SYS_SEMCTL
static void update_semctl_info(int semid, int semnum, int cmd, unsigned long arg)
{
	spin_lock(&sem_lock);	
	
	semnode *head = sem_info_list->head;

	ushort *values = NULL;

	if (cmd == SETALL || cmd == GETALL)
		values = (ushort *) arg;

	for(;head; head = head->next)
	{
		if (head->info.semid == semid)
		{
			if (cmd == SETVAL && head->info.semnum == semnum + 1)
				head->info.value = arg;
			else if (cmd == SETALL || cmd == GETALL)
			{
				head->info.value = values[head->info.semnum - 1];	
			} 	

			head->info.lastcmd = cmd;
		} 
	}
	spin_unlock(&sem_lock);

	pr_info("%s%s: Proccess %d semctl with %d semafore on semid %d, value: %d\n", PREFIX, SEMPREFIX, current->pid, semnum, semid, arg);

}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_semctl)(const struct pt_regs *);

static asmlinkage int hook_sys_semctl(const struct pt_regs *regs)
{
    int res = real_sys_semctl(regs);

	int semid = regs->di;
	int semnum = regs->si;
	int cmd = regs->dx;
	unsigned long arg = regs->r10;

	if (res == 0)
		update_semctl_info(semid, semnum, cmd, arg);

    return res;
}
#else
static asmlinkage long (*real_sys_semctl)(int semid, int semnum, int cmd, unsigned long arg);

static asmlinkage int hook_sys_semctl(int semid, int semnum, int cmd, unsigned long arg)
{
    int res = real_sys_semctl(semid, semnum, cmd, arg);

	if (res == 0)
		update_semctl_info(semid, semnum, cmd, arg);

    return res;
}
#endif

// SYS_PIPE
static void get_pipe_info(int __user *fildes)
{
	spin_lock(&pipe_lock);

	push_bask_plist(&pipe_info_list, current->pid, fildes, NULL);

	spin_unlock(&pipe_lock);

	pr_info("%s%s: Proccess %d create pipe fd: %p\n", PREFIX, PIPEPREFIX, current->pid, fildes);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_pipe)(const struct pt_regs *);

static asmlinkage int hook_sys_pipe(const struct pt_regs *regs)
{
    int res = real_sys_pipe(regs);

	int __user *fildes = regs->di;

	if (res == 0)
	{
		get_pipe_info(fildes);
	}

    return res;
}
#else
static asmlinkage long (*real_sys_pipe)(int __user *fildes);

static asmlinkage int hook_sys_pipe(int __user *fildes)
{
    int res = real_sys_pipe(fildes);

	if (res == 0)
	{
		get_pipe_info(fildes);
	}

    return res;
}
#endif

// SYS_PIPE2
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_pipe2)(const struct pt_regs *);

static asmlinkage int hook_sys_pipe2(const struct pt_regs *regs)
{
    int res = real_sys_pipe2(regs);

	int __user *fildes = regs->di;

	if (res == 0)
	{
		get_pipe_info(fildes);
	}

    return res;
}
#else
static asmlinkage long (*real_sys_pipe2)(int __user *fildes, int flags);

static asmlinkage int hook_sys_pipe2(int __user *fildes, int flags)
{
    int res = real_sys_pipe2(fildes, flags);

	if (res == 0)
	{
		get_pipe_info(fildes);
	}

    return res;
}
#endif

// SYS_CLOSE
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_close)(const struct pt_regs *);

static asmlinkage int hook_sys_close(const struct pt_regs *regs)
{
    int res = real_sys_close(regs);

	unsigned int *fd = regs->di;

	if (res == 0)
	{
		pr_info("%s%s: Proccess %d close fd: %p\n", PREFIX, PIPEPREFIX, current->pid, fd);
	}

    return res;
}
#else
static asmlinkage long (*real_sys_pipe2)(unsigned int fd);

static asmlinkage int hook_sys_close(unsigned int fd)
{
    int res = real_sys_close(fd);

	if (res == 0)
	{
		pr_info("%s%s: Proccess %d close fd: %p\n", PREFIX, PIPEPREFIX, current->pid, fd);
	}

    return res;
}
#endif

// SYS_SHMGET
static void get_shm_info(int shmid, size_t size, int shmflg)
{
	spin_lock(&shm_lock);

	shm_info_t info = {
		.pid = current->pid,
		.shmid = shmid,
		.size = size,
		.addr = NULL,
		.lastcmd = -1,
		// .shmflg = shmflg
	};

	push_bask_shmlist(shm_info_list, info);

	spin_unlock(&shm_lock);
}
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_shmget)(const struct pt_regs *);

static asmlinkage int hook_sys_shmget(const struct pt_regs *regs)
{
    int shmid = real_sys_shmget(regs);

	key_t key = regs->di;
	size_t size = regs->si;
	int flag = regs->dx;

	if (shmid == -1)
	{

	}
	else
	{
		get_shm_info(shmid, size, flag);

		pr_info("%s%s: Proccess %d create or get shm %d on %lu size\n", PREFIX, SHMPREFIX, current->pid, shmid, size);
	}
    return shmid;
}
#else
static asmlinkage long (*real_sys_shmget)(key_t key, size_t size, int flag);

static asmlinkage int hook_sys_shmget(key_t key, size_t size, int flag)
{
    int shmid = real_sys_shmget(key, size, flag);

	if (shmid == -1)
	{

	}
	else
	{
		get_shm_info(shmid, size, flag);

		pr_info("%s%s: Proccess %d create or get shm %d on %lu size\n", PREFIX, SHMPREFIX, current->pid, shmid, size);
	}

    return shmid;
}
#endif

// SYS_SHMAT
static void update_shmat_info(int shmid, char __user *shmaddr, int shmflg)
{
	spin_lock(&shm_lock);

	shmnode* node = get_shmnode(shm_info_list, current->pid);

	if (node != NULL)
	{
		node->info.addr = shmaddr;
	}	
	else
	{
		shmnode *node = get_first_shmnode(shm_info_list, shmid);

		size_t size = 0;

		if (node != NULL)
			size = node->info.size;

		shm_info_t info = {
			.pid = current->pid,
			.shmid = shmid,
			.size = 0,
			.addr = shmaddr,
			.lastcmd = -1,
			// .shmflg = node->info.shmflg
		};

		push_bask_shmlist(shm_info_list, info);
	}
	spin_unlock(&shm_lock);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_shmat)(const struct pt_regs *);

static asmlinkage long hook_sys_shmat(const struct pt_regs *regs)
{
	int shmid = regs->di;
	// char __user *shmaddr = regs->si;
	int shmflg = regs->dx;

	long addr = real_sys_shmat(regs);

	if (addr < 0)
	{

	} 
	else
	{
		update_shmat_info(shmid, addr, shmflg);
		pr_info("%s%s: Proccess %d was attached to %d shm - addr - %lu\n", PREFIX, SHMPREFIX, current->pid, shmid, addr);
	}

    return addr;
}
#else
static asmlinkage long (*real_sys_shmat)(int shmid, char __user *shmaddr, int shmflg);

static asmlinkage long hook_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	long addr = real_sys_shmat(shmid, shmaddr, shmflg);	

    unsigned long addr = real_sys_shmat(shmid, shmaddr, shmflg);

	pr_info("%s%s: Proccess %d was attached to %d shm - addr: %lu\n", PREFIX, SHMPREFIX, current->pid, shmid, addr);

    return addr;
}
#endif

// SYS_SHMDT
static void update_shmdt_info(char __user *shmaddr)
{
	spin_lock(&shm_lock);

	shmnode* node = get_shmnode(shm_info_list, current->pid);

	if (node != NULL)
	{
		node->info.addr = NULL;
	}

	spin_unlock(&shm_lock);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_shmdt)(const struct pt_regs *);

static asmlinkage int hook_sys_shmdt(const struct pt_regs *regs)
{
    int res = real_sys_shmdt(regs);

	char __user *shmaddr = regs->di;

	if (res < 0)
	{

	}
	else
	{
		update_shmdt_info(shmaddr);

		pr_info("%s%s: Proccess %d was detached shm - addr: %x\n", PREFIX, SHMPREFIX, current->pid, shmaddr);
	}

    return res;
}
#else
static asmlinkage long (*real_sys_shmdt)(char __user *shmaddr);

static asmlinkage int real_sys_shmdt(char __user *shmaddr)
{
    int res = real_sys_shmdt(shmaddr);

	if (res < 0)
	{

	}
	else
	{
		update_shmdt_info(shmaddr);

		pr_info("%s%s: Proccess %d was detached shm - addr: %x\n", PREFIX, SHMPREFIX, current->pid, shmaddr);
	}

    return res;
}
#endif

// SYS_SHCTL
static void update_shmctl_info(int shmid, int cmd, struct shmid_ds __user *buf)
{
	spin_lock(&shm_lock);

	shmnode* head = shm_info_list->head;

	for (; head; head = head->next)
	{
		if (head->info.shmid == shmid)
		{
			head->info.lastcmd = cmd;
		}
	}

	spin_unlock(&shm_lock);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_shmctl)(const struct pt_regs *);

static asmlinkage int hook_sys_shmctl(const struct pt_regs *regs)
{
    int res = real_sys_shmctl(regs);

	int shmid = regs->di;
	int cmd = regs->si;
	struct shmid_ds __user *buf = regs->dx;

	if (res < 0)
	{

	}
	else
	{
		update_shmctl_info(shmid, cmd, buf);
		pr_info("%s%s: Proccess %d was ctl %d shm, cmd: %d\n", PREFIX, SHMPREFIX, current->pid, shmid, cmd);
	}
    return res;
}
#else
static asmlinkage long (*real_sys_shmctl)(int shmid, int cmd, struct shmid_ds __user *buf);

static asmlinkage int real_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
    int res = real_sys_shmctl(shmid, cmd, buf);

	pr_info("%s%s: Proccess %d was ctl %d shm, cmd: %d\n", PREFIX, SHMPREFIX, current->pid, shmid, cmd);

    return res;
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
	HOOK("sys_signal",  hook_sys_signal,  &real_sys_signal),
	HOOK("sys_semget",  hook_sys_semget,  &real_sys_semget),
  	HOOK("sys_semop",  hook_sys_semop,  &real_sys_semop),
	HOOK("sys_semctl",  hook_sys_semctl,  &real_sys_semctl),
	HOOK("sys_pipe",  hook_sys_pipe, &real_sys_pipe),
	HOOK("sys_pipe2",  hook_sys_pipe2, &real_sys_pipe2),
	// HOOK("sys_close",  hook_sys_close, &real_sys_close),
	HOOK("sys_shmget",  hook_sys_shmget, &real_sys_shmget),
	HOOK("sys_shmat",  hook_sys_shmat, &real_sys_shmat),
	HOOK("sys_shmdt",  hook_sys_shmdt, &real_sys_shmdt),
	HOOK("sys_old_shmctl",  hook_sys_shmctl, &real_sys_shmctl),
	HOOK("sys_shmctl",  hook_sys_shmctl, &real_sys_shmctl),
};

int install_hooks()
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

void remove_hooks()
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}