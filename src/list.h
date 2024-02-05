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

typedef struct children_node_t
{
    pid_t pid;
    struct children_node_t *next;   
} childnode_t;


typedef struct sem_info_t
{
    int semid;
    int semnum;
    pid_t pid;
    int semflg;
    int lastcmd;
    int value;
} sem_info_t;

typedef struct sem_node_t
{
    struct sem_info_t info;
    struct sem_node_t *next;
    struct sem_node_t *prev;
} semnode;

typedef struct sem_list_t 
{
    size_t len;
    struct sem_node_t *head;
    struct sem_node_t *tail;
} semlist;


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


childnode_t *create_childnode(pid_t pid);
int push_bask_childlist(childnode_t **head, pid_t pid);
void free_childlist(childnode_t **head);

pnode *create_pnode(pid_t ppid, int *fd, childnode_t *child_list);
void init_plist(plist *list);
int push_bask_plist(plist *list, pid_t ppid, int *fd, childnode_t *child_list);
void pop_plist(plist *list, int *fd);
void free_plist(plist *list);

semnode *create_semnode(sem_info_t data);
int push_bask_semlist(semlist *list, sem_info_t data);
void pop_semlist(semlist *list, int semid);
void free_semlist(semlist *list);


#endif