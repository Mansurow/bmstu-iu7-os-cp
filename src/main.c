#include <linux/delay.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sem.h>
#include <linux/sched/signal.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mansurov Vladislav");
MODULE_DESCRIPTION("Program");
MODULE_VERSION("Version 1.0");

#define PREFIX "~~[TASK INFO]~~"

// static void print_signals(struct sigpending *pending)
// {
//     printk(KERN_INFO "Signals in pending state:\n");
    
//     struct sigqueue *entry;
//     struct list_head *pos = pending->list.next;

//     for (; pos != &pending->list; pos = pos->next) {
//         entry = list_entry(pos, struct sigqueue, list);
//         printk(KERN_INFO "Signal %d is pending\n", entry->info);
//     }
// }

// static void print_sem(struct sysv_sem *sem)
// {
//     printk(KERN_INFO "Semaphores:\n");
    
//     struct sem_undo_list *undo_entry = sem->undo_list;
//     struct sem_queue *sem_entry;

    
//     // Итерация по списку struct sem_queue внутри struct sem_undo_list
//     list_for_each_entry(sem_entry, &undo_entry->list_proc, list) {
//         printk(KERN_INFO "Semaphore %d\n", sem_entry->undo->semid);
//     }

//      list_for_each_entry(undo_entry, head, list_proc) {
        

        
//     }
// }

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

    // struct vm_area_struct *vma = info_about_mem->mmap_base;

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

static int __init md_init(void)
{
    struct task_struct *task = &init_task; 

    do {
        printk(KERN_INFO "%s[GENERAL]: " 
            "pid: %d, ppid: %d, pgid: %d, name: %s\nprio: %d, static prio: %d, normal prio: %d, realtime_prio: %d\n"
            "delay: %lld\n"
            "utime: %lld ticks, stime: %lld ticks\n"
            "Sched_rt_entity: timeout: %ld, watchdog_stamp: %ld, time_slice:%ld\n", 
            PREFIX,
            task->pid, task->parent->pid, task->group_leader->pid, task->comm,
            task->prio, task->static_prio, task->normal_prio, task->rt_priority,
            task->sched_info.run_delay, task->utime, task->stime,
            task->rt.watchdog_stamp, task->rt.time_slice);
     
        if (task->mm != NULL)
        {
            print_info_mm(task->pid, task->mm);
        }
        else
        {
            printk(KERN_INFO "%s[Memory][%d]: нет доступа", PREFIX, task->pid);
        }
        printk(KERN_INFO "\n");

    } while ((task = next_task(task)) != &init_task);


    return 0;
}

static void __exit md_exit(void)
{
    printk(KERN_INFO "%s Good buy!\n", PREFIX);
}

module_init(md_init);
module_exit(md_exit);