#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *p = malloc(4096 * 4);
    if (!p)
        return 1;

    {
        // in-place shrink
        void *q = realloc(p, 4096 * 2);
        // if (q != p) return 2;

        // in-place shrink
        q = realloc(q, 4096);
        // if (q != p) return 3;

        // in-place expand
        q = realloc(q, 4096 * 2);
        // if (q != p) return 4;

        // in-place expand
        q = realloc(q, 4096 * 4);
        // if (q != p) return 5;

        // in-place expand
        q = realloc(q, 4096 * 8);
        // if (q != p) return 6;

        // in-place expand
        q = realloc(q, 4096 * 64);
        // if (q != p) return 7;

        free(q);
    }

    return 0;
}
