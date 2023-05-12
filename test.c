#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "mpool.h"
#define N 100000

int main()
{
    printf("%ld\n", sizeof(slab_t));
    void **p = malloc(N * sizeof(void *));

    for (size_t i = 0; i < N; i++) {
        printf("%ld\n", i);
        p[i] = malloc(16);
        if (!p[i]) {
            exit(1);
        }
    }

    for (size_t i = 0; i < N; i++) {
        printf("%ld\n", i);
        free(p[i]);
    }
    printf("PASS\n");
    return 0;
}