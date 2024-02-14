#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void signal_handler(int signo) {
    if (signo == SIGUSR1) {
        printf("Received SIGUSR1 signal\n");
    }
}

int main() {
    signal(SIGUSR1, signal_handler);

    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (child_pid == 0) {
        printf("PID: %d , PPID: %d \n", getpid(), getppid());
        printf("Child: Waiting for signal from parent...\n");
        pause();
        printf("Child: Signal received. Exiting.\n");

    } else {
        printf("Parent: Sending SIGUSR1 signal to child...\n");
        sleep(1);
        kill(child_pid, SIGUSR1);
        
        waitpid(child_pid, NULL, 0);
        printf("Parent: Child process has exited. Exiting.\n");
    }
    
    return 0;
}