#ifndef __SIGNAL_LIST_H_
#define __SIGNAL_LIST_H_

#include <linux/types.h>
#include <linux/ipc.h>
#include <linux/signal.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/slab.h>

#include "utils.h"

typedef struct signal_info_t
{
    pid_t pid;
    int sig;
    int send_count;
    int receive_count;
} siginfo;

typedef struct signal_node_t
{
    struct signal_info_t info;
    struct signal_node_t *next;
    struct signal_node_t *prev;
} signode;

typedef struct signal_list_t
{
    size_t len;
    struct signal_node_t *head;
    struct signal_node_t *tail;
} siglist;

typedef struct pipe_node_t
{
    pid_t ppid;
    int *fd;
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

signode *create_signode(siginfo data);
void init_siglist(siglist * list);
int push_back_siglist(siglist *list, siginfo data);
signode *get_signode(siglist *list, pid_t pid);
void free_siglist(siglist *list);

pnode *create_pnode(pid_t ppid, int *fd);
void init_plist(plist *list);
int push_bask_plist(plist *list, pid_t ppid, int *fd);
void pop_plist(plist *list, pid_t pid, int *fd);
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