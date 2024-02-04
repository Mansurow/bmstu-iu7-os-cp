#ifndef __SIGNAL_LIST_H_
#define __SIGNAL_LIST_H_

#include <linux/types.h>
#include <linux/ipc.h>
#include <linux/signal.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/slab.h>

#include "utils.h"

typedef struct monitoring_signal_t
{
    int pid;            // pid процесса
    int sig;            // сигнал 
    int count_received; // количество полученных сигналов
    int count_sent;     // количество отправленных сигналов  
} monitoring_signal_t;

struct monitoring_pipe_t
{
    pid_t ppid;
    int *fd;
};

struct monitoring_pipe_array
{
    int count;
    struct monitoring_pipe_t array[LOG_SIZE];
};

typedef struct children_node_t
{
    pid_t pid;
    struct children_node_t *next;   
} childnode_t;

typedef struct pipe_node_t
{
    pid_t ppid;
    int *fd;
    int count;
    childnode_t *children;
    struct pipe_node_t *next;
} pnode;

typedef struct pipe_list_t 
{
    size_t len;
    struct pipe_node_t *head;
    struct pipe_node_t *tail;
} plist;

pnode *create_pnode(pid_t ppid, int *fd, childnode_t *child_list);
childnode_t *create_childnode(pid_t pid);

void init_plist(plist *list);
int push_bask_plist(plist *list, pid_t ppid, int *fd, childnode_t *child_list);
int push_bask_childlist(childnode_t **head, pid_t pid);
void pop_plist(plist *list, int *fd);

void free_plist(plist *list);
void free_childlist(childnode_t **head);

#endif