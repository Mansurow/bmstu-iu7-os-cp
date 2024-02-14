#include <linux/delay.h>
#include <linux/init.h>
#include <linux/init_task.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include <linux/sched/signal.h>

#include <linux/types.h>
#include <linux/ipc.h>
#include <linux/signal.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>

#include "hooks.h"
#include "list.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mansurov Vladislav");
MODULE_DESCRIPTION("MONITORING PROCCESS");
MODULE_VERSION("1.0");

#define MAINDIRNAME  "monitoring"
#define LOGSDIRNAME  "logs"

#define GENERALFILENAME  "general"
#define SIGNALFILENAME   "signals"
#define SIGHANDFILENAME  "sighands"
#define SEMFILENAME      "sem"
#define SHMFILENAME      "shm"
#define PIPEFILENAME     "pipe"
#define MEMORYFILENAME   "memory"
#define MAPSFILENAME     "maps"

static struct proc_dir_entry *proc_main_dir = NULL;
static struct proc_dir_entry *proc_logs_dir = NULL;

static struct proc_dir_entry *proc_general_file = NULL;
static struct proc_dir_entry *proc_signal_logs_file = NULL;
static struct proc_dir_entry *proc_signal_file = NULL;
static struct proc_dir_entry *proc_sighand_file = NULL;
static struct proc_dir_entry *proc_memory_file = NULL;
static struct proc_dir_entry *proc_maps_file = NULL;
static struct proc_dir_entry *proc_pipe_file = NULL;
static struct proc_dir_entry *proc_sem_file = NULL;
static struct proc_dir_entry *proc_shm_file = NULL;

static int mt_pid = -1;

static char general_info[LOG_SIZE] = { 0 };
static char sighand_info[LOG_SIZE] = { 0 };
static char memory_info[LOG_SIZE] = { 0 };
static char maps_info[LOG_SIZE] = { 0 };
static char pipes_info[LOG_SIZE] = { 0 };
static char sem_info[LOG_SIZE] = { 0 };
static char shm_info[LOG_SIZE] = { 0 };

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

struct task_struct *find_task_struct(pid_t pid)
{
	struct task_struct *current_task = &init_task;

	do {
		if (current_task->pid == pid)
		{
			return current_task;
		}
	} while ((current_task = next_task(current_task)) != &init_task);

	return NULL;
}

static void cmd_to_str(char *cmdname, int cmd)
{
    if (cmd == IPC_STAT)
    {
        sprintf(cmdname, "%s", "IPC_STAT");
    } 
    else if (cmd == IPC_SET)
    {
        sprintf(cmdname, "%s", "IPC_SET");
    }
    else if (cmd == IPC_RMID)
    {
        sprintf(cmdname, "%s", "IPC_RMID");
    }
    else if (cmd == GETALL)
    {
        sprintf(cmdname, "%s", "GETALL");
    }
    else if (cmd== GETNCNT)
    {
        sprintf(cmdname, "%s", "GETNCNT");
    }
    else if (cmd == GETPID)
    {
        sprintf(cmdname, "%s", "GETPID");
    }
    else if (cmd == GETVAL)
    {
        sprintf(cmdname, "%s", "GETZCNT");
    }
    else if (cmd == GETVAL)
    {
        sprintf(cmdname, "%s", "GETZCNT");
    }
    else if (cmd == SETALL)
    {
        sprintf(cmdname, "%s", "SETALL");
    }
    else if (cmd == SETVAL)
    {
        sprintf(cmdname, "%s", "SETVAL");
    }
    else 
    {
        sprintf(cmdname, "%s", "?");
    }
}

static ssize_t show_general_info(void)
{
    int strlen = 0;

    strlen += sprintf(general_info + strlen, "%7s %7s %7s %7s %10s %7s %7s %7s %7s %7s %14s %14s %14s %7s\n", 
        "PPID", "PID", "STATE", "ESTATE", "FLAGS", "POLICY", "PRIO", "SPRIO", "NPRIO", "PRPRIO", "UTIME", "STIME", "DELAY", "COMM");

    struct task_struct *task = &init_task;

    do 
    {
        strlen += sprintf(general_info + strlen, "%7d %7d %7d %7d %10x %7d %7d %7d %7d %7d %14llu %14llu %14llu\t%s\n",
                        task->parent->pid, task->pid, task->__state, task->exit_state, task->flags,
                        task->policy, task->prio, task->static_prio, task->normal_prio, task->rt_priority,
                        task->utime, task->stime, task->sched_info.run_delay,
                        task->comm);  
    }
    while ((task = next_task(task)) != &init_task);

    return strlen;
} 

static int general_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: general_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int general_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: general_release called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t general_write(struct file *file, const char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: general_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t general_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: general_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen  = show_general_info();

    if (copy_to_user(buf, general_info, strlen))
    {
        printk(KERN_ERR "%s%s: copy_to_user error\n", PREFIX, FORTUNEPREFIX);

        return -EFAULT;
    }

    *fPos += strlen;

    memset(general_info, 0, LOG_SIZE);

    return strlen;
}


static int sighand_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: signal_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int sighand_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: signal_releases called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t sighand_write(struct file *file, const char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: signal_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t sighand_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: signal_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen = 0;

    strlen += sprintf(sighand_info + strlen, "%7s\t%14s\t%8s\t%7s\t%7s\n", "PID", "SIGNAL", "FLAGS", "HANDLER");

    struct task_struct *task = &init_task;

    do 
    {
        for (int signo = 1; signo < _NSIG; ++signo) {
            struct k_sigaction *ka = &task->sighand->action[signo - 1];

            if (ka->sa.sa_handler > 1)
            {
                strlen += sprintf(sighand_info + strlen, "%7d %14s %7lu 0x%x\n", task->pid, signal_names[signo], ka->sa.sa_flags, ka->sa.sa_handler);
            }
        }
    }
    while ((task = next_task(task)) != &init_task);


    if (copy_to_user(buf, sighand_info, strlen))
    {
        printk(KERN_ERR "%s: copy_to_user error\n", PREFIX);

        return -EFAULT;
    }

    *fPos += strlen;

    memset(sighand_info, 0, LOG_SIZE);

    return strlen;
}


static int signal_logs_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: signal_logs_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int signal_logs_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: signal_logs_releases called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t signal_logs_write(struct file *file, const char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: signal_logs_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t signal_logs_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: signal_logs_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t logLen = strlen(signal_logs);

    printk(KERN_INFO "%s: read called\n", PREFIX);

    if (copy_to_user(buf, signal_logs, logLen))
    {
        printk(KERN_ERR "%s: copy_to_user error\n", PREFIX);

        return -EFAULT;
    }

    *fPos += logLen;

    return logLen;
}


static int memory_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: memory_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int memory_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: memory_releases called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t memory_write(struct file *file, const char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: memory_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t memory_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: memory_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen = 0;

    strlen += sprintf(memory_info + strlen, "%7s %7s %10s %10s %10s %10s %10s %7s %10s %10s %10s %10s %10s\n", 
        "PID", "MMUSERS", "TOTAL VM", "LOCKED VM", "DATA VM", "EXEC VM", "STACK VM", "MAPS", "HEAP", "CODE", "DATA", "ARGS", "ENV");

    struct task_struct *task = &init_task;

    do 
    {
        struct mm_struct *mm = task->mm;

        if (mm != NULL)
        {
            unsigned long brk = mm->brk - mm->start_brk; 
            unsigned long code = mm->end_code - mm->start_code;   
            unsigned long data = mm->end_data - mm->start_data;
            unsigned long args = mm->arg_end - mm->arg_start;
            unsigned long env = mm->env_end - mm->env_start;

            strlen += sprintf(memory_info + strlen, "%7d %7d %10lu %10lu %10lu %10lu %10lu %7d %10lu %10lu %10lu %10lu %10lu\n", 
                task->pid, mm->mm_users.counter, mm->total_vm, mm->locked_vm, mm->data_vm, mm->exec_vm, mm->stack_vm, mm->map_count, brk, code, data, args, env);
        }
    }
    while ((task = next_task(task)) != &init_task);

    printk(KERN_INFO "%s: read called\n", PREFIX);

    if (copy_to_user(buf, memory_info, strlen))
    {
        printk(KERN_ERR "%s: copy_to_user error\n", PREFIX);

        return -EFAULT;
    }

    *fPos += strlen;

    memset(memory_info, 0, LOG_SIZE);

    return strlen;
}


static int maps_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: maps_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int maps_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: maps_release called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t maps_write(struct file *file, const char __user *ubuf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: maps_write called\n", PREFIX, FORTUNEPREFIX);

    char kbuf[10];
    if (copy_from_user(kbuf, ubuf, len))
    {
        printk(KERN_ERR "%s%s: copy_from_user error\n", PREFIX, FORTUNEPREFIX);
        return -EFAULT;
    }
    kbuf[len - 1] = 0;

    sscanf(kbuf, "%d", &mt_pid);

    return len;
}

static ssize_t maps_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: maps_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen = 0;

    struct task_struct *task = find_task_struct(mt_pid);

    if (task == NULL || mt_pid == -1)
    {
        strlen += sprintf(maps_info + strlen, "Process with pid %d doesn't exist\n", mt_pid);
    }
    else
    {
        strlen += sprintf(maps_info + strlen, "%7s %21s %14s %14s %10s\n", "PID", "addr-addr", "Flags", "BYTES", "PAGES");

        struct mm_struct *mm = task->mm;

        if (mm == NULL)
        {
            strlen += sprintf(maps_info + strlen, "%7d %20s %14s %14s %10s\n", task->pid, "?-?", "?", "?", "?");
        }
        else
        {
            // 5.19.0 и меньше версия ядра, в 6+ убрали по причине оптимизации
            struct vm_area_struct *vma = mm->mmap;

            if (vma == NULL)
            {
                strlen += sprintf(maps_info + strlen, "%7d %20s %14s %14s %10s\n", task->pid, "?-?", "?", "?", "?");
            }
            else 
            {
                for (; vma != NULL; vma = vma->vm_next)
                {
                    unsigned long bytes = vma->vm_end - vma->vm_start;
                    int pages = bytes / 4096;

                    strlen += sprintf(maps_info + strlen, "%7d %10x-%10x %14ld %14lu %10d\n", 
                        task->pid, vma->vm_start, vma->vm_end, vma->vm_flags, bytes, pages);
                }
            }
        }
    }
    
    if (copy_to_user(buf, maps_info, strlen))
    {
        printk(KERN_ERR "%s%s: copy_to_user error\n", PREFIX, FORTUNEPREFIX);

        return -EFAULT;
    }

    memset(maps_info, 0, LOG_SIZE);

    *fPos += strlen;

    return strlen;
}


static int pipe_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: pipe_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int pipe_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: pipe_release called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t pipe_write(struct file *file, const char __user *ubuf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: pipe_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t pipe_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: pipe_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen = 0;

    strlen += sprintf(pipes_info + strlen, "%7s %18s %7s\n", "PID", "FD", "COUNT");
    
    pnode *head = pipe_info_list.head;

    char temp[TEMP_STRING_SIZE] = { 0 };

    for (; head; head = head->next)
    {
        int count = 0;
        ssize_t clen = 0;

        // childnode_t *chead = head->children; 

        struct list_head *pos;
        struct task_struct *task, *curtask;

        curtask = find_task_struct(head->ppid);

        if (curtask == NULL)
        {
            continue;
        }

        int index = 0;
        pid_t tmp_pid;
        list_for_each(pos, &(curtask->children))
        {
        	task = list_entry(pos, struct task_struct, sibling);
        	tmp_pid = task->pid;
            if (count < 10)
                clen += sprintf(temp + clen, "%d,", tmp_pid);
            else if (count == 11)
                clen += sprintf(temp + clen, "...");
            count++;
        }

        // for (; chead; chead = chead->next)
        // {
        //     clen += sprintf(temp + clen, "%d,", chead->pid);
        //     count++;
        // }

        strlen += sprintf(pipes_info + strlen, "%7d %18llu %7d %s\n",
            head->ppid, head->fd, count, temp);

        memset(temp, 0, TEMP_STRING_SIZE);     
    }

    if (copy_to_user(buf, pipes_info, strlen))
    {
        printk(KERN_ERR "%s%s: copy_to_user error\n", PREFIX, FORTUNEPREFIX);

        return -EFAULT;
    }

    // memset(pipes_info, 0, LOG_SIZE);

    *fPos += strlen;

    return strlen;
}


static int sem_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: sem_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int sem_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: sem_release called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t sem_write(struct file *file, const char __user *ubuf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: sen_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t sem_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: sem_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen = 0;

    strlen += sprintf(sem_info + strlen, "%7s %7s %7s %7s %7s %7s\n", "PID", "SEMID", "SEMNUM", "FLAGS", "CMD", "VALUE");
    
    semnode *head = sem_info_list->head;
    for (; head; head = head->next)
    {
        char command[10] = { 0 };    
        cmd_to_str(command, head->info.lastcmd);

        strlen += sprintf(sem_info + strlen, "%7d %7d %7d %7d %7s %7d\n",
            head->info.pid, head->info.semid, head->info.semnum, head->info.semflg, command, head->info.value);    
    }

    if (copy_to_user(buf, sem_info, strlen))
    {
        printk(KERN_ERR "%s%s: copy_to_user error\n", PREFIX, FORTUNEPREFIX);

        return -EFAULT;
    }

    memset(sem_info, 0, LOG_SIZE);

    *fPos += strlen;

    return strlen;
}


static int shm_open(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: shm_open called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static int shm_release(struct inode *spInode, struct file *spFile)
{
    pr_info("%s%s: shm_release called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t shm_write(struct file *file, const char __user *ubuf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: shm_write called\n", PREFIX, FORTUNEPREFIX);

    return 0;
}

static ssize_t shm_read(struct file *file, char __user *buf, size_t len, loff_t *fPos)
{
    pr_info("%s%s: shm_read called\n", PREFIX, FORTUNEPREFIX);

    if (*fPos > 0)
        return 0;

    ssize_t strlen = 0;

    strlen += sprintf(shm_info + strlen, "%7s %7s %10s %14s %7s\n", "PID", "SHMID", "CMD", "SIZE", "ADDR");
    
    shmnode *head = shm_info_list->head;
    for (; head; head = head->next)
    {
        char command[10] = { 0 };    
        cmd_to_str(command, head->info.lastcmd);

        if (head->info.addr == NULL)
        {
            strlen += sprintf(shm_info + strlen, "%7d %7d %10s %14llu %s\n",
                head->info.pid, head->info.shmid, command, head->info.size, "?"); 
        }
        else
        { 
            strlen += sprintf(shm_info + strlen, "%7d %7d %10s %14llu 0x%p\n",
                head->info.pid, head->info.shmid, command, head->info.size, head->info.addr);
        }
    }

    if (copy_to_user(buf, shm_info, strlen))
    {
        printk(KERN_ERR "%s%s: copy_to_user error\n", PREFIX, FORTUNEPREFIX);

        return -EFAULT;
    }

    memset(shm_info, 0, LOG_SIZE);

    *fPos += strlen;

    return strlen;
}


static struct proc_ops signal_logs_ops = {
    .proc_open = signal_logs_open,
    .proc_read = signal_logs_read,
    .proc_write = signal_logs_write,
    .proc_release = signal_logs_release,
};

static struct proc_ops sighand_ops = {
    .proc_open = sighand_open,
    .proc_read = sighand_read,
    .proc_write = sighand_write,
    .proc_release = sighand_release,
};

static struct proc_ops memory_ops = {
    .proc_open = memory_open,
    .proc_read = memory_read,
    .proc_write = memory_write,
    .proc_release = memory_release,
};

static struct proc_ops maps_ops = {
    .proc_open = maps_open,
    .proc_read = maps_read,
    .proc_write = maps_write,
    .proc_release = maps_release,
};

static struct proc_ops general_ops = {
    .proc_open = general_open,
    .proc_read = general_read,
    .proc_write = general_write,
    .proc_release = general_release,
};

static struct proc_ops pipe_ops = {
    .proc_open = pipe_open,
    .proc_read = pipe_read,
    .proc_write = pipe_write,
    .proc_release = pipe_release,
};

static struct proc_ops sem_ops = {
    .proc_open = sem_open,
    .proc_read = sem_read,
    .proc_write = sem_write,
    .proc_release = sem_release,
};

static struct proc_ops shm_ops = {
    .proc_open = shm_open,
    .proc_read = shm_read,
    .proc_write = shm_write,
    .proc_release = shm_release,
};

static void free_proc(void)
{
    if (proc_signal_logs_file != NULL)
        remove_proc_entry(SIGNALFILENAME, proc_logs_dir);

    if (proc_logs_dir != NULL)
        remove_proc_entry(LOGSDIRNAME, proc_main_dir);

    if (proc_sighand_file != NULL)
        remove_proc_entry(SIGHANDFILENAME, proc_main_dir); 

    if (proc_pipe_file != NULL)
        remove_proc_entry(PIPEFILENAME, proc_main_dir);

    if (proc_sem_file != NULL)
        remove_proc_entry(SEMFILENAME, proc_main_dir);

    if (proc_shm_file != NULL)
        remove_proc_entry(SHMFILENAME, proc_main_dir);         

    if (proc_memory_file != NULL)
        remove_proc_entry(MEMORYFILENAME, proc_main_dir); 

    if (proc_maps_file != NULL)
        remove_proc_entry(MAPSFILENAME, proc_main_dir);

    if (proc_general_file != NULL)
        remove_proc_entry(GENERALFILENAME, proc_main_dir);    

    if (proc_main_dir != NULL)
        remove_proc_entry(MAINDIRNAME, NULL);
}

static void free_lists(void)
{
    free_plist(&pipe_info_list);
    free_semlist(sem_info_list);
    free_shmlist(shm_info_list);

    kfree(sem_info_list);
    kfree(shm_info_list);
}


static int init_proc(void)
{
    if ((proc_main_dir = proc_mkdir(MAINDIRNAME, NULL)) == NULL)
    {
        printk(KERN_ERR "create main dir error\n");

        return -ENOMEM;
    }

    if (!(proc_general_file = proc_create(GENERALFILENAME, 0666, proc_main_dir, &general_ops)))
    {
        printk(KERN_ERR "%s: create general file error\n", PREFIX);

        return -ENOMEM;
    }

    if (!(proc_sem_file = proc_create(SEMFILENAME, 0666, proc_main_dir, &sem_ops)))
    {
        printk(KERN_ERR "%s: create sem file error\n", PREFIX);

        return -ENOMEM;
    }

    if (!(proc_shm_file = proc_create(SHMFILENAME, 0666, proc_main_dir, &shm_ops)))
    {
        printk(KERN_ERR "%s: create shm file error\n", PREFIX);

        return -ENOMEM;
    }

    if (!(proc_pipe_file = proc_create(PIPEFILENAME, 0666, proc_main_dir, &pipe_ops)))
    {
        printk(KERN_ERR "%s: create pipe file error\n", PREFIX);

        return -ENOMEM;
    }

    if (!(proc_memory_file = proc_create(MEMORYFILENAME, 0666, proc_main_dir, &memory_ops)))
    {
        printk(KERN_ERR "%s: create memory file error\n", PREFIX);

        return -ENOMEM;
    }

    if (!(proc_maps_file = proc_create(MAPSFILENAME, 0666, proc_main_dir, &maps_ops)))
    {
        printk(KERN_ERR "%s: create maps for process file error\n", PREFIX);

        return -ENOMEM;
    }

    if (!(proc_sighand_file = proc_create(SIGHANDFILENAME, 0666, proc_main_dir, &sighand_ops)))
    {
        printk(KERN_ERR "%s: create signals file error\n", PREFIX);

        return -ENOMEM;
    }

    if ((proc_logs_dir = proc_mkdir(LOGSDIRNAME, proc_main_dir)) == NULL)
    {
        printk(KERN_ERR "create main dir error\n");

        return -ENOMEM;
    }

    if (!(proc_signal_logs_file = proc_create(SIGNALFILENAME, 0666, proc_logs_dir, &signal_logs_ops)))
    {
        printk(KERN_ERR "%s create signal logs file error\n", PREFIX);

        return -ENOMEM;
    }

    return 0;
}

static int alloc_lists(void)
{
    sem_info_list = (semlist *) kmalloc(sizeof(semlist), GFP_KERNEL);
    if (sem_info_list == NULL)
    {
        return -1;
    }

    shm_info_list = (shmlist *) kmalloc(sizeof(shmlist), GFP_KERNEL);
    if (shm_info_list == NULL)
    {
        return -1;
    }


    init_semlist(sem_info_list);
    init_shmlist(shm_info_list);

    return 0;
}


static int __init md_init(void)
{
    int err;

    err = alloc_lists();
    if (err)
    {
        return err;
    }

    err = init_proc();
    if (err)
    {
        free_proc();
        free_lists();
        return err;
    }

    err = install_hooks();
    if(err)
    {
        printk(KERN_ERR "%s install_hooks error\n", PREFIX);
        free_proc();
        free_lists();

        return err;
    }

    pr_info("%s: module loaded!\n", PREFIX);

    return 0;
}

static void __exit md_exit(void)
{
    remove_hooks();
    free_proc();
    free_lists();

    pr_info("%s: module unloaded!\n", PREFIX);
}

module_init(md_init);
module_exit(md_exit);