/* Значение __state: */
#define TASK_RUNNING			 0x00000000
#define TASK_INTERRUPTIBLE		 0x00000001
#define TASK_UNINTERRUPTIBLE	 0x00000002
#define __TASK_STOPPED			 0x00000004
#define __TASK_TRACED			 0x00000008
/* Значения exit_state: */
#define EXIT_DEAD			     0x00000010
#define EXIT_ZOMBIE			     0x00000020
#define EXIT_TRACE			    (EXIT_ZOMBIE | EXIT_DEAD)
/* Значение __state: */
#define TASK_PARKED			     0x00000040
#define TASK_DEAD			     0x00000080
#define TASK_WAKEKILL			 0x00000100
#define TASK_WAKING			     0x00000200
#define TASK_NOLOAD			     0x00000400
#define TASK_NEW			     0x00000800
#define TASK_RTLOCK_WAIT		 0x00001000
#define TASK_FREEZABLE			 0x00002000
#define __TASK_FREEZABLE_UNSAFE	 (0x00004000 * IS_ENABLED(CONFIG_LOCKDEP))
#define TASK_FROZEN			     0x00008000
#define TASK_STATE_MAX			 0x00010000
#define TASK_ANY			    (TASK_STATE_MAX-1)
#define TASK_KILLABLE			(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED			__TASK_TRACED
#define TASK_IDLE			(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)
#define TASK_NORMAL			(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
#define TASK_REPORT			(TASK_RUNNING | TASK_INTERRUPTIBLE | \
					 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
					 __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
					 TASK_PARKED)

#define task_is_running(task)		(READ_ONCE((task)->__state) == TASK_RUNNING)

#define task_is_traced(task)		((READ_ONCE(task->jobctl) & JOBCTL_TRACED) != 0)
#define task_is_stopped(task)		((READ_ONCE(task->jobctl) & JOBCTL_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	((READ_ONCE(task->jobctl) & (JOBCTL_STOPPED | JOBCTL_TRACED)) != 0)
