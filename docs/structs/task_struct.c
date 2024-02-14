struct task_struct {
	unsigned int __state;

	unsigned int flags;

	int				prio;
	int				static_prio;
	int				normal_prio;
	unsigned int    rt_priority;

	struct sched_entity	        se;
	struct sched_rt_entity		rt;
	struct sched_dl_entity		dl;
	const struct sched_class	*sched_class;

	struct sched_statistics  stats;

	unsigned int			policy;

	struct sched_info		sched_info;

	struct list_head		tasks;

	struct mm_struct		*mm;
	struct mm_struct		*active_mm;

	int				exit_state;
	int				exit_code;
	int				exit_signal;

	pid_t				pid;
	pid_t				tgid;

	struct task_struct __rcu	*real_parent;
	/* Recipient of SIGCHLD, wait4() reports: */
	struct task_struct __rcu	*parent;
	/* Children/sibling form the list of natural children:*/
	struct list_head		children;
	struct list_head		sibling;
	struct task_struct		*group_leader;
	/* PID/PID hash table linkage. */
	struct pid			*thread_pid;
	struct hlist_node		pid_links[PIDTYPE_MAX];
	struct list_head		thread_group;
	struct list_head		thread_node;

	u64				utime;
	u64				stime;
	u64				gtime;
	u64				start_time;
	u64				start_boottime;

	char				comm[TASK_COMM_LEN];

#ifdef CONFIG_SYSVIPC
	struct sysv_sem			sysvsem;
	struct sysv_shm			sysvshm;
#endif

	/* Signal handlers: */
	struct signal_struct		*signal;
	struct sighand_struct __rcu		*sighand;
	struct sigpending		pending;
};