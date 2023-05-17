#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "list.h"
#include "mpool.h"
#include "rb.h"

#define MAP_ANONYMOUS 0x20
#define MAX_SMALL 512
#define SMALL_POOL_SIZE 4096 * 1024 * 2


// Metadata structure for managing allocated memory blocks
typedef struct metadata {
    struct metadata *next, *prev;
    size_t size;
    void *ptr;
} metadata_t;

// Red-black tree structure for managing large memory allocations
typedef rb_tree(comb_t) large_tree;

// Main structure for managing memory allocations
typedef struct {
    large_tree *large_used_tree;
    metadata_t *last_node;
    size_t page_size;
    pthread_mutex_t mutex;
    comb_t *tab;
    size_t pool_size;
    size_t pool_free_space;
} malloc_t;

/* PUBLIC API */
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
