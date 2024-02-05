#include "list.h"

pnode *create_pnode(pid_t ppid, int *fd, childnode_t *child_list)
{
    pnode *node  = (pnode *) kmalloc(sizeof(pnode), GFP_KERNEL);
    if (node != NULL)
    {
        node->ppid = ppid;
        node->fd = fd;
        node->children = child_list;
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

int push_bask_plist(plist *list, pid_t ppid, int *fd, childnode_t *child_list)
{
    if (list == NULL)
    {
        return -1;
    }

    pnode *node = create_pnode(ppid, fd, child_list);
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
                free_childlist(&node->children);
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

void pop_plist(plist *list, int *fd)
{
    if (list != NULL  && list->head != NULL)
    {
        pnode *head = list->head;
        for (; head;head = head->next)
        {
            if (head->fd == fd)
            {
                pnode *pop = head;

                free_childlist(&pop->children);
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
            free_childlist(&(list->head->children));
            kfree(list->head);
        }
        list->len = 0;
        list->head = NULL;
        list->tail = NULL;
    }
}


childnode_t *create_childnode(pid_t pid)
{
    childnode_t *node  = (childnode_t *) kmalloc(sizeof(childnode_t), GFP_KERNEL);
    if (node != NULL)
    {
        node->pid = pid;
    }
    return node;
}

int push_bask_childlist(childnode_t **head, pid_t pid)
{
    if (head == NULL)
    {
        return -1;
    }

    childnode_t *node = create_childnode(pid);
    if (node == NULL)
    {
        return -1;
    }

    if (*head == NULL)
    {
        *head = node;
    }
    else
    {
        childnode_t *tail = *head;
        for (;tail->next; tail = tail->next);
        tail->next = node;
    }

    return 0;
}

void free_childlist(childnode_t **head)
{
    if (head != NULL && *head != NULL)
    {
        childnode_t *next_elem;

        for (;*head; *head = next_elem)
        {
            next_elem = (*head)->next;
            kfree(*head);
        }
        *head = NULL;
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

