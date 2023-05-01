#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

typedef enum rbcolor { BLACK = 0, RED = 1 } rbcolor_t;
#define MAP_ANONYMOUS   0x20

typedef struct metadata {
    struct metadata *next, *prev;
    size_t size;
#ifdef MMAP
    void *ptr;
#else 
    size_t free;
#endif
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
#ifdef MMAP
    void *ptr;
#else
    void *end_in_page;
    void *first_block;
    rbnode_t *root_rbtree;
    size_t page_remaining;
#endif
} malloc_t;

#if __SIZE_WIDTH__ == 64
#define YFREE 0xDEADBEEF5EBA571E
#define NFREE 0x5EBA571EDEADBEEF
#define ALIGN_BYTES(x) ((((x - 1) >> 4) << 4) + 16)
#else
#define YFREE 0x5EBA571E
#define NFREE 0xDEADBEEF
#define ALIGN_BYTES(x) ((((x - 1) >> 3) << 3) + 8)
#endif

#define SIZE_TAB_VALUES (256)
#define META_SIZE ALIGN_BYTES((sizeof(metadata_t)))
#define GET_PAYLOAD(x) ((void *) ((size_t) x + META_SIZE))
#define GET_NODE(x) ((void *) ((size_t) x - META_SIZE))
#define SIZE_DEFAULT_BLOCK (32)
#define IS_VALID(x) \
    (((metadata_t *) x)->free == YFREE || ((metadata_t *) x)->free == NFREE)
#define IS_FREE(x) ((x) ? (((metadata_t *) x)->free == YFREE) : (0))
#define IS_RED(x) ((x) ? (((rbnode_t *) x)->color == RED) : (0))
#define MY_COMPARE(k1, k2) (((k1 == k2) ? (0) : ((k1 < k2) ? (-1) : (1))))

extern const char *__progname;

/* API */
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
