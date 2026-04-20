#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buffer[64];
    ssize_t nread;
    int fd;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        return 1;
    }
    nread = read(fd, buffer, sizeof(buffer) - 1);
    if (nread < 0) {
        close(fd);
        return 1;
    }
    buffer[nread] = '\0';
    printf("%s\n", buffer);
    close(fd);
    return 0;
}
