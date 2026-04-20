#define _DEFAULT_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int i;
    for (i = 0; i < 20; ++i) {
        printf("counter=%d\n", i);
        usleep(10000);
    }
    return 0;
}
