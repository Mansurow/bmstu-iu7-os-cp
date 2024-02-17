#include "list.h"

signode *create_signode(siginfo data)
{
    signode *node  = (signode *) kmalloc(sizeof(signode), GFP_KERNEL);
    if (node != NULL)
    {
        node->info = data;
        node->next = NULL;
    }
    return node;
}

void init_siglist(siglist * list)
{
    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

int push_back_siglist(siglist *list, siginfo data)
{
    if (list == NULL)
    {
        return -1;
    }

    signode *node = create_signode(data);
    if (node == NULL)
    {
        return -1;
    }

    if (list->head == NULL && list->tail == NULL)
    {
        list->head = node;
    }
    else
    {
        signode *tail = list->head;
        for (;tail->next; tail = tail->next);
        tail->next = node;
        node->prev = tail;
    } 

    list->tail = node;   
    list->len++;

    return 0;
}

signode *get_signode(siglist *list, pid_t pid)
{
    signode* node = NULL;

    if (list != NULL)
    {
        bool flag = false;
        signode* head = list->head;
        
        for(; head && !flag; head = head->next)
        {
            if (head->info.pid == pid)
            {
                node = head;
                flag = true;
            }
        } 
    }

    return node;
}

void free_siglist(siglist *list)
{
    if (list != NULL && list->head != NULL)
    {
        signode *next_elem;

        for (;list->head; list->head = next_elem)
        {
            next_elem = list->head->next;
            kfree(list->head);
        }
        list->len = 0;
        list->head = NULL;
        list->tail = NULL;
    }
}


pnode *create_pnode(pid_t ppid, int *fd)
{
    pnode *node  = (pnode *) kmalloc(sizeof(pnode), GFP_KERNEL);
    if (node != NULL)
    {
        node->ppid = ppid;
        node->fd = fd;
        node->next = NULL;
    }
    return node;
}

void init_plist(plist *list)
{
    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

int push_bask_plist(plist *list, pid_t ppid, int *fd)
{
    if (list == NULL)
    {
        return -1;
    }

    pnode *node = create_pnode(ppid, fd);
    if (node == NULL)
    {
        return -1;
    }

    if (list->head == NULL)
    {
        list->head = node;
    }
    else
    {
        pnode *tail = list->head;
        for (;tail->next; tail = tail->next)
        {
            if (tail->ppid == ppid)
            {
                kfree(node);
                return -1;
            }
        }
        tail->next = node;
    }

    list->tail = node;   
    list->len++;

    return 0;
}

void pop_plist(plist *list, pid_t pid, int *fd)
{
    if (list != NULL  && list->head != NULL)
    {
        pnode *head = list->head;
        for (; head;head = head->next)
        {
            if (head->ppid == pid && head->fd == fd)
            {
                pnode *pop = head;

                kfree(pop);

                break;
            }
        }
    }
}

void free_plist(plist *list)
{
    if (list != NULL && list->head != NULL)
    {
        pnode *next_elem;

        for (;list->head; list->head = next_elem)
        {
            next_elem = list->head->next;
            kfree(list->head);
        }
        list->len = 0;
        list->head = NULL;
        list->tail = NULL;
    }
}


semnode *create_semnode(sem_info_t data)
{
    semnode *node  = (semnode *) kmalloc(sizeof(semnode), GFP_KERNEL);
    if (node != NULL)
    {
        node->info = data;
        node->next = NULL;
        node->prev = NULL;
    }
    return node;
}

void init_semlist(semlist *list)
{
    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

int push_bask_semlist(semlist *list, sem_info_t data)
{
    if (list == NULL)
    {
        return -1;
    }

    semnode *node = create_semnode(data);
    if (node == NULL)
    {
        return -1;
    }

    if (list->head == NULL && list->tail == NULL)
    {
        list->head = node;
    }
    else
    {
        semnode *tail = list->head;
        for (;tail->next; tail = tail->next);
        tail->next = node;
        node->prev = tail;
    } 

    list->tail = node;   
    list->len++;

    return 0;
}

void pop_semlist(semlist *list, int semid)
{
    if (list != NULL)
    {
        semnode *head = list->head;

        for(;head; head = head->next)
        {
            if (head->info.semid == semid)
            {
                semnode *prev = head->prev;
                semnode *curr = head;
                semnode *next = head->next;

                if (prev == NULL && next == NULL)
                {
                    list->head = NULL;
                    list->tail = NULL;
                } 
                else if (prev == NULL)
                {
                    next->prev = prev;
                    list->head = next;
                }
                else if (next == NULL)
                {
                    prev->next = next;
                    list->tail = prev;
                } else
                {
                    prev->next = next;
                    next->prev = prev;
                }
                kfree(curr);
                list->len--;	
            }
        }
    }
}

void free_semlist(semlist *list) 
{
    if (list != NULL && list->head != NULL)
    {
        semnode *next_elem;

        for (;list->head; list->head = next_elem)
        {
            next_elem = list->head->next;
            kfree(list->head);
        }
        list->len = 0;
        list->head = NULL;
        list->tail = NULL;
    }
}

shmnode *create_shmnode(shm_info_t data)
{
    shmnode *node  = (shmnode *) kmalloc(sizeof(shmnode), GFP_KERNEL);
    if (node != NULL)
    {
        node->info = data;
        node->next = NULL;
        node->prev = NULL;
    }
    return node;
}

void init_shmlist(shmlist *list)
{
    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

shmnode* get_shmnode(shmlist *list, pid_t pid)
{
    shmnode* node = NULL;

    if (list != NULL)
    {
        if (list->tail->info.pid == pid)
        {
            node = list->tail;
        }
        else
        {
            bool flag = false;
            shmnode* head = list->head;
            
            for(; head && !flag; head = head->next)
            {
                if (head->info.pid == pid)
                {
                    node = head;
                    flag = true;
                }
            } 
        }
    }

    return node;
}

shmnode* get_first_shmnode(shmlist *list, int shmid)
{
    shmnode* node = NULL;

    if (list != NULL)
    {
        bool flag = false;
        shmnode* head = list->head;
        
        for(; head && !flag; head = head->next)
        {
            if (head->info.shmid == shmid)
            {
                node = head;
                flag = true;
            }
        } 
    }

    return node;
}

int push_bask_shmlist(shmlist *list, shm_info_t data)
{
    if (list == NULL)
    {
        return -1;
    }

    shmnode *mainnode = get_first_shmnode(list, data.shmid);
    if (mainnode != NULL)
    {
        data.size = mainnode->info.size;
    }

    shmnode *node = create_shmnode(data);
    if (node == NULL)
    {
        return -1;
    }

    if (list->head == NULL && list->tail == NULL)
    {
        list->head = node;
    }
    else
    {   

        shmnode *tail = list->head;
        for (;tail->next; tail = tail->next);

        tail->next = node;
        node->prev = tail;
    } 

    list->tail = node;   
    list->len++;

    return 0;
}

void pop_shmid_shmlist(shmlist *list, int shmid)
{
    if (list != NULL)
    {
        shmnode *head = list->head;

        for(;head; head = head->next)
        {
            if (head->info.shmid == shmid)
            {
                shmnode *prev = head->prev;
                shmnode *curr = head;
                shmnode *next = head->next;

                if (prev == NULL && next == NULL)
                {
                    list->head = NULL;
                    list->tail = NULL;
                } 
                else if (prev == NULL)
                {
                    next->prev = prev;
                    list->head = next;
                }
                else if (next == NULL)
                {
                    prev->next = next;
                    list->tail = prev;
                } else
                {
                    prev->next = next;
                    next->prev = prev;
                }
                kfree(curr);
                list->len--;	
            }
        }
    }
}

void pop_pid_shmlist(shmlist *list, pid_t pid)
{
    if (list != NULL)
    {
        shmnode *head = list->head;

        for(;head; head = head->next)
        {
            if (head->info.pid == pid)
            {
                shmnode *prev = head->prev;
                shmnode *curr = head;
                shmnode *next = head->next;

                if (prev == NULL && next == NULL)
                {
                    list->head = NULL;
                    list->tail = NULL;
                } 
                else if (prev == NULL)
                {
                    next->prev = prev;
                    list->head = next;
                }
                else if (next == NULL)
                {
                    prev->next = next;
                    list->tail = prev;
                } else
                {
                    prev->next = next;
                    next->prev = prev;
                }
                kfree(curr);
                list->len--;	
            }
        }
    }
}

void free_shmlist(shmlist *list) 
{
    if (list != NULL && list->head != NULL)
    {
        shmnode *next_elem;

        for (;list->head; list->head = next_elem)
        {
            next_elem = list->head->next;
            kfree(list->head);
        }
        list->len = 0;
        list->head = NULL;
        list->tail = NULL;
    }
}