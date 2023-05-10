#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "rb.h"

#define MAP_ANONYMOUS 0x20
#define MAX_SMALL 512

struct large_;
typedef struct large_ large_t;

typedef struct metadata {
    struct metadata *next, *prev;
    size_t size;
    void *ptr;
} metadata_t;

struct large_ {
    size_t size;
    void *ptr;
    rb_node(large_t) link;
};

typedef rb_tree(large_t) large_tree;

typedef struct {
    large_tree *large_used_tree;
    metadata_t *last_node;
    size_t page_size;
    pthread_mutex_t mutex;
    void *ptr;
} malloc_t;



/* API */
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
