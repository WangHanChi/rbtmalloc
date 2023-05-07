#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

typedef enum rbcolor { BLACK = 0, RED = 1 } rbcolor_t;
#define MAP_ANONYMOUS   0x20

typedef struct metadata {
    struct metadata *next, *prev;
    size_t size;
    void *ptr;
} metadata_t;

typedef size_t t_key;
typedef metadata_t t_value;

typedef struct rbnode {
    size_t size;
    size_t free;
    metadata_t *next, *prev;
    t_key key;
    t_value **tab_values;
    size_t size_tab;
    size_t n_active;
    rbcolor_t color;
    struct rbnode *left, *right;
} rbnode_t;

typedef struct {
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
