#ifndef __SIGNAL_LIST_H_
#define __SIGNAL_LIST_H_

typedef struct monitoring_signal_t
{
    int pid;            // pid процесса
    int sig;            // сигнал 
    int count_received; // количество полученных сигналов
    int count_sent;     // количество отправленных сигналов  
} monitoring_signal_t;

typedef struct monitoring_signal_list_t
{
    int size;
    int len;
    monitoring_signal_t *array;
    int k;
} monitoring_signal_list_t;


int alloc_msignal_list(monitoring_signal_list_t *list, int size, int k);
int append_msignal_list(monitoring_signal_list_t *list, monitoring_signal_t *msignal);
monitoring_signal_t *pop_msignal_list(monitoring_signal_list_t *list);
void free_msignal_list(monitoring_signal_list_t *list);

#endif