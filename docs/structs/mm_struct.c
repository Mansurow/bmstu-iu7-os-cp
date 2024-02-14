struct mm_struct {
    struct vm_area_struct *mmap;    /* list of VMAs */
	struct rb_root mm_rb;
    ...
    unsigned long mmap_base;	
	...
	unsigned long task_size;	    /* size of task vm space */
	unsigned long highest_vm_end;	/* highest vma end address */
	pgd_t * pgd;
    ...
	atomic_t mm_users;
	atomic_t mm_count; 
    ...
	int map_count;			/* number of VMAs */
	spinlock_t page_table_lock; 
	struct rw_semaphore mmap_lock;
    ...
	struct list_head mmlist;
    ...
    unsigned long total_vm;	 /* Total pages mapped */
    unsigned long locked_vm; /* Pages that have PG_mlocked set */
    atomic64_t    pinned_vm; /* Refcount permanently increased */
    unsigned long data_vm; /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
    unsigned long exec_vm; /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
    unsigned long stack_vm;	 /* VM_STACK */
    ...
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;
    ...
    /*
    * Special counters, in some configurations protected by the
    * page_table_lock, in other configurations by being atomic.
    */
    struct mm_rss_stat rss_stat;
    ...
	unsigned long flags; /* Must use atomic bitops to access */
};