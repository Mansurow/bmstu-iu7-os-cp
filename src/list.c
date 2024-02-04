#include "list.h"

pnode *create_node(pid_t ppid, int *fd, childnode_t *child_list)
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

childnode_t *create_childnode(pid_t pid)
{
    childnode_t *node  = (childnode_t *) kmalloc(sizeof(childnode_t), GFP_KERNEL);
    if (node != NULL)
    {
        node->pid = pid;
    }
    return node;
}

void init_plist(plist *list)
{
    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

// bool is_empty(struct list_t *list)
// {
//     return list == NULL || list->head == NULL;
// }

int push_bask_plist(plist *list, pid_t ppid, int *fd, childnode_t *child_list)
{
    if (list == NULL)
    {
        return -1;
    }

    pnode *node = create_node(ppid, fd, child_list);
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