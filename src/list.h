#ifndef __SIGNAL_LIST_H_
#define __SIGNAL_LIST_H_

#include <linux/types.h>
#include <linux/ipc.h>
#include <linux/signal.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/slab.h>

#include "utils.h"

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

typedef struct shm_info_t
{
    pid_t pid;
    int shmid;
    unsigned long size;
    char __user *addr;
    int lastcmd;   
} shm_info_t;

typedef struct shm_node_t
{
    struct shm_info_t info;
    struct shm_node_t *next;
    struct shm_node_t *prev;
} shmnode;

typedef struct shm_list_t 
{
    size_t len;
    struct shm_node_t *head;
    struct shm_node_t *tail;
} shmlist;

childnode_t *create_childnode(pid_t pid);
int push_bask_childlist(childnode_t **head, pid_t pid);
void free_childlist(childnode_t **head);

pnode *create_pnode(pid_t ppid, int *fd, childnode_t *child_list);
void init_plist(plist *list);
int push_bask_plist(plist *list, pid_t ppid, int *fd, childnode_t *child_list);
void pop_plist(plist *list, int *fd);
void free_plist(plist *list);

semnode *create_semnode(sem_info_t data);
void init_semlist(semlist *list);
int push_bask_semlist(semlist *list, sem_info_t data);
void pop_semlist(semlist *list, int semid);
void free_semlist(semlist *list);

shmnode *create_shmnode(shm_info_t data);
void init_shmlist(shmlist *list);
shmnode* get_first_shmnode(shmlist *list, int shmid);
shmnode* get_shmnode(shmlist *list, pid_t pid);
int push_bask_shmlist(shmlist *list, shm_info_t data);
void pop_shmid_shmlist(shmlist *list, int shmid);
void pop_pid_shmlist(shmlist *list, pid_t pid);
void free_shmlist(shmlist *list);

#endif