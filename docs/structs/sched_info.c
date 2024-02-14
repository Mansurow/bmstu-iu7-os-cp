struct sched_info {
#ifdef CONFIG_SCHED_INFO
	unsigned long			pcount;
	unsigned long long		run_delay;
	unsigned long long		last_arrival;
	unsigned long long		last_queued;
#endif
};