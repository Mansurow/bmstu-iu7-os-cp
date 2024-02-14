struct semid_ds {
	struct ipc_perm	sem_perm;
	__kernel_old_time_t sem_otime;
	__kernel_old_time_t sem_ctime;
	struct sem	*sem_base;
	struct sem_queue *sem_pending;
	struct sem_queue **sem_pending_last;
	struct sem_undo	*undo;
	unsigned short	sem_nsems;
};

struct sembuf {
	unsigned short  sem_num;
	short		    sem_op;
	short		    sem_flg;	
};

struct sem {
	int	semval;
	struct pid       *sempid;
	spinlock_t	     lock;
	struct list_head pending_alter; 
	struct list_head pending_const;
	time64_t	     sem_otime;
} ____cacheline_aligned_in_smp;

struct sem_array {
	struct kern_ipc_perm	sem_perm;
	time64_t		    sem_ctime;
	struct list_head	pending_alter;
	struct list_head	pending_const;
	struct list_head	list_id;
	int			        sem_nsems;
	int			        complex_count;
	unsigned int		use_global_lock;

	struct sem		sems[];
} __randomize_layout;

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

/* One queue for each sleeping process in the system. */
struct sem_queue {
	struct list_head	list;	 /* queue of pending operations */
	struct task_struct	*sleeper; /* this process */
	struct sem_undo		*undo;	 /* undo structure */
	struct pid		    *pid;	 /* process id of requesting process */
	int			        status;	 /* completion status of operation */
	struct sembuf		*sops;	 /* array of pending operations */
	struct sembuf		*blocking; /* the operation that blocked */
	int			        nsops;	 /* number of operations */
	bool			    alter;	 /* does *sops alter the array? */
	bool                dupsop;	 /* sops on more than one sem_num */
};

struct sem_undo_list {
	refcount_t		refcnt;
	spinlock_t		lock;
	struct list_head	list_proc;
};

/* Each task has a list of undo requests. They are executed automatically
 * when the process exits.
 */
struct sem_undo {
	struct list_head	list_proc;	/* per-process list: *
						 * all undos from one process
						 * rcu protected */
	struct rcu_head		    rcu;		/* rcu struct for sem_undo */
	struct sem_undo_list	*ulp;		/* back ptr to sem_undo_list */
	struct list_head	     list_id;	/* per semaphore array list:
						 * all undos for one array */
	int			    semid;		/* semaphore set identifier */
	short			*semadj;	/* array of adjustments */
						/* one per semaphore */
};

/* sem_undo_list controls shared access to the list of sem_undo structures
 * that may be shared among all a CLONE_SYSVSEM task group.
 */
struct sem_undo_list {
	refcount_t		refcnt;
	spinlock_t		lock;
	struct list_head	list_proc;
};

int semget(key_t key, int numb_sem, int flag);
int semctl(int semid, int semnum, int cmd, union semun arg);
int semop(int semid, struct sembuf *sop, unsigned nsop);

union semun {
   int val;               
   struct semid_ds *buf;  
   ushort *array;         
   struct seminfo *__buf;
};

/* linux/syscalls.h */
/* ipc/sem.c */
asmlinkage long sys_semget(key_t key, int nsems, int semflg);
asmlinkage long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);
asmlinkage long sys_old_semctl(int semid, int semnum, int cmd, unsigned long arg);
asmlinkage long sys_semtimedop(int semid, struct sembuf __user *sops,
				unsigned nsops,
				const struct __kernel_timespec __user *timeout);
asmlinkage long sys_semtimedop_time32(int semid, struct sembuf __user *sops,
				unsigned nsops,
				const struct old_timespec32 __user *timeout);
asmlinkage long sys_semop(int semid, struct sembuf __user *sops,
				unsigned nsops);

/* for __ARCH_WANT_SYS_IPC */
long ksys_semtimedop(int semid, struct sembuf __user *tsops,
		     unsigned int nsops,
		     const struct __kernel_timespec __user *timeout);
long ksys_semget(key_t key, int nsems, int semflg);
long ksys_old_semctl(int semid, int semnum, int cmd, unsigned long arg);
long compat_ksys_semtimedop(int semid, struct sembuf __user *tsems,
			    unsigned int nsops,
			    const struct old_timespec32 __user *timeout);

// Реализация SEMAFORES

SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
{
	return ksys_semget(key, nsems, semflg);
}

SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops,
		unsigned, nsops)
{
	return do_semtimedop(semid, tsops, nsops, NULL);
}

SYSCALL_DEFINE4(semctl, int, semid, int, semnum, int, cmd, unsigned long, arg)
{
	return ksys_semctl(semid, semnum, cmd, arg, IPC_64);
}

SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
		unsigned int, nsops, const struct __kernel_timespec __user *, timeout)
{
	return ksys_semtimedop(semid, tsops, nsops, timeout);
}

#ifdef CONFIG_COMPAT_32BIT_TIME
long compat_ksys_semtimedop(int semid, struct sembuf __user *tsems,
			    unsigned int nsops,
			    const struct old_timespec32 __user *timeout)
{
	if (timeout) {
		struct timespec64 ts;
		if (get_old_timespec32(&ts, timeout))
			return -EFAULT;
		return do_semtimedop(semid, tsems, nsops, &ts);
	}
	return do_semtimedop(semid, tsems, nsops, NULL);
}

SYSCALL_DEFINE4(semtimedop_time32, int, semid, struct sembuf __user *, tsems,
		       unsigned int, nsops,
		       const struct old_timespec32 __user *, timeout)
{
	return compat_ksys_semtimedop(semid, tsems, nsops, timeout);
}
#endif


long ksys_semget(key_t key, int nsems, int semflg)
{
	struct ipc_namespace *ns;
	static const struct ipc_ops sem_ops = {
		.getnew = newary,
		.associate = security_sem_associate,
		.more_checks = sem_more_checks,
	};
	struct ipc_params sem_params;

	ns = current->nsproxy->ipc_ns;

	if (nsems < 0 || nsems > ns->sc_semmsl)
		return -EINVAL;

	sem_params.key = key;
	sem_params.flg = semflg;
	sem_params.u.nsems = nsems;

	return ipcget(ns, &sem_ids(ns), &sem_ops, &sem_params);
}

long ksys_semtimedop(int semid, struct sembuf __user *tsops,
		     unsigned int nsops, const struct __kernel_timespec __user *timeout)
{
	if (timeout) {
		struct timespec64 ts;
		if (get_timespec64(&ts, timeout))
			return -EFAULT;
		return do_semtimedop(semid, tsops, nsops, &ts);
	}
	return do_semtimedop(semid, tsops, nsops, NULL);
}

static long ksys_semctl(int semid, int semnum, int cmd, unsigned long arg, int version)
{
	struct ipc_namespace *ns;
	void __user *p = (void __user *)arg;
	struct semid64_ds semid64;
	int err;

	if (semid < 0)
		return -EINVAL;

	ns = current->nsproxy->ipc_ns;

	switch (cmd) {
	case IPC_INFO:
	case SEM_INFO:
		return semctl_info(ns, semid, cmd, p);
	case IPC_STAT:
	case SEM_STAT:
	case SEM_STAT_ANY:
		err = semctl_stat(ns, semid, cmd, &semid64);
		if (err < 0)
			return err;
		if (copy_semid_to_user(p, &semid64, version))
			err = -EFAULT;
		return err;
	case GETALL:
	case GETVAL:
	case GETPID:
	case GETNCNT:
	case GETZCNT:
	case SETALL:
		return semctl_main(ns, semid, semnum, cmd, p);
	case SETVAL: {
		int val;
#if defined(CONFIG_64BIT) && defined(__BIG_ENDIAN)
		/* big-endian 64bit */
		val = arg >> 32;
#else
		/* 32bit or little-endian 64bit */
		val = arg;
#endif
		return semctl_setval(ns, semid, semnum, val);
	}
	case IPC_SET:
		if (copy_semid_from_user(&semid64, p, version))
			return -EFAULT;
		fallthrough;
	case IPC_RMID:
		return semctl_down(ns, semid, cmd, &semid64);
	default:
		return -EINVAL;
	}
}

static long do_semtimedop(int semid, struct sembuf __user *tsops,
		unsigned nsops, const struct timespec64 *timeout)
{
	struct sembuf fast_sops[SEMOPM_FAST];
	struct sembuf *sops = fast_sops;
	struct ipc_namespace *ns;
	int ret;

	ns = current->nsproxy->ipc_ns;
	if (nsops > ns->sc_semopm)
		return -E2BIG;
	if (nsops < 1)
		return -EINVAL;

	if (nsops > SEMOPM_FAST) {
		sops = kvmalloc_array(nsops, sizeof(*sops), GFP_KERNEL);
		if (sops == NULL)
			return -ENOMEM;
	}

	if (copy_from_user(sops, tsops, nsops * sizeof(*tsops))) {
		ret =  -EFAULT;
		goto out_free;
	}

	ret = __do_semtimedop(semid, sops, nsops, timeout, ns);

out_free:
	if (sops != fast_sops)
		kvfree(sops);

	return ret;
}

long ksys_semtimedop(int semid, struct sembuf __user *tsops,
		     unsigned int nsops, const struct __kernel_timespec __user *timeout)
{
	if (timeout) {
		struct timespec64 ts;
		if (get_timespec64(&ts, timeout))
			return -EFAULT;
		return do_semtimedop(semid, tsops, nsops, &ts);
	}
	return do_semtimedop(semid, tsops, nsops, NULL);
}

// Реализация SHM