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
    // Регистрация обработчика сигнала
    signal(SIGUSR1, signal_handler);

    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (child_pid == 0) {
        // Код для дочернего процесса
        printf("PID: %d , PPID: %d \n", getpid(), getppid());
        // Ожидание сигнала от родительского процесса
        printf("Child: Waiting for signal from parent...\n");
        pause(); // Приостанавливаем выполнение, ожидая получение сигнала
        printf("Child: Signal received. Exiting.\n");

    } else {
        // Код для родительского процесса

        // Отправка сигнала дочернему процессу
        printf("Parent: Sending SIGUSR1 signal to child...\n");
        sleep(1); // Даем дочернему процессу время для ожидания
        kill(child_pid, SIGUSR1);

        // Ждем завершения дочернего процесса
        waitpid(child_pid, NULL, 0);
        printf("Parent: Child process has exited. Exiting.\n");
    }
    
    

    return 0;
}