#include "hooks.h"

extern char signal_logs[LOG_SIZE] = { 0 };

static DEFINE_SPINLOCK(signal_logs_lock);
static DEFINE_SPINLOCK(msignal_lock);

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

	if (res == 0)
	{
		pid_t pid = regs->di;
		int sig = regs->si;

		char currentString[TEMP_STRING_SIZE];

		if (sig > 0)
		{
			memset(currentString, 0, TEMP_STRING_SIZE);	
			snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d sent signal %s to process %d\n", current->pid, signal_names[sig], pid);

			spin_lock(&signal_logs_lock);

			strcat(signal_logs, currentString); 

			spin_unlock(&signal_logs_lock);

			printk(KERN_INFO "%s%s: Process %d sent signal %s to process %d\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig], pid);
		}
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
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_semget)(const struct pt_regs *);

static asmlinkage int hook_sys_semget(const struct pt_regs *regs)
{
    int semid = real_sys_semget(regs);

	key_t key = regs->di;
	int nsem = regs->si;
	int semflg = regs->dx;

	pr_info("%s%s: sem create or get with semid: %d\n", PREFIX, SEMPREFIX, semid);

	// if (res == 0)
	// {
	// 	pid_t pid = regs->di;
	// 	int sig = regs->si;

	// 	char currentString[TEMP_STRING_SIZE];

	// 	if (sig > 0)
	// 	{
	// 		memset(currentString, 0, TEMP_STRING_SIZE);	
	// 		snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d sent signal %s to process %d\n", current->pid, signal_names[sig], pid);

	// 		spin_lock(&signal_logs_lock);

	// 		strcat(signal_logs, currentString); 

	// 		spin_unlock(&signal_logs_lock);

	// 		printk(KERN_INFO "%s%s: Process %d sent signal %s to process %d\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig], pid);
	// 	}
	// }

    return semid;
}
#else
static asmlinkage long (*real_sys_semget)(key_t key, int nsems, int semflg);

static asmlinkage int hook_sys_semget(key_t key, int nsems, int semflg)
{
    int semid = real_sys_semget(key, nsems, semflg);

	// if (res == 0)
	// {
	// 	char currentString[TEMP_STRING_SIZE];

	// 	memset(currentString, 0, TEMP_STRING_SIZE);	
	// 	snprintf(currentString, TEMP_STRING_SIZE, "Proccess %d sent signal %s to process %d\n", current->pid, signal_names[sig], pid);

	// 	spin_lock(&signal_logs_lock);

	// 	strcat(signal_logs, currentString); 

	// 	spin_unlock(&signal_logs_lock);

	// 	pr_info("%s%s: Process %d sent signal %s to process %d\n", PREFIX, SIGNALPREFIX, current->pid, signal_names[sig], pid);
	// }

    return semid;
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
	HOOK("sys_semget",  hook_sys_semget,  &real_sys_semget)
};

int install_hooks()
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

void remove_hooks()
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}