#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

int main() {
    int pipefd[2];
    char buf[32];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(1);
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child: Consumer
        close(pipefd[1]);
        read(pipefd[0], buf, sizeof(buf));
        printf("Child received: %s\n", buf);
        close(pipefd[0]);
        exit(0);
    } else {
        // Parent: Producer
        close(pipefd[0]);
        const char *msg = "IPC_DATA_031";
        write(pipefd[1], msg, strlen(msg) + 1);
        close(pipefd[1]);
        wait(NULL);
        printf("Parent finished.\n");
    }
    return 0;
}
