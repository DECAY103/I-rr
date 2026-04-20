#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

int main(void) {
    unsigned int value = 0;
    if (getrandom(&value, sizeof(value), 0) != (ssize_t) sizeof(value)) {
        return 1;
    }
    printf("random=%u\n", value);
    return 0;
}
