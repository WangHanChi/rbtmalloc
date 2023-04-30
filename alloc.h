#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

typedef enum rbcolor { BLACK = 0, RED = 1 } rbcolor_t;

typedef struct metadata {
    size_t size;
    size_t free;
    struct metadata *next, *prev;
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
    rbnode_t *root_rbtree;
    metadata_t *last_node;
    void *end_in_page;
    void *first_block;
    int page_size;
    pthread_mutex_t mutex;
    size_t page_remaining;
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

/* RBT operation */
static inline void flip_color(rbnode_t *node);
static rbnode_t *rotate_left(rbnode_t *left);
static rbnode_t *rotate_right(rbnode_t *right);
static rbnode_t *balance(rbnode_t *node);
static rbnode_t *move_red_to_left(rbnode_t *node);
static rbnode_t *move_red_to_right(rbnode_t *node);
static bool insert_node(rbnode_t *node, metadata_t *);
static rbnode_t *new_rbtree(metadata_t *node);
static rbnode_t *insert_this(rbnode_t *node, metadata_t *);
static rbnode_t *new_rbtree(metadata_t *node);
static rbnode_t *remove_node(rbnode_t *node, t_key key, rbnode_t *tmp);
static rbnode_t *remove_key(rbnode_t *node, t_key key);
static rbnode_t *remove_node(rbnode_t *node, t_key key, rbnode_t *tmp);
static rbnode_t *remove_k(rbnode_t *node, t_key key);
static rbnode_t *get_key(rbnode_t *node, t_key key);
static rbnode_t *remove_from_freed_list(rbnode_t *node, metadata_t *meta);


/* memory operation */
static bool resize_tab_values(metadata_t **old, rbnode_t *node);
static rbnode_t *insert_in_freed_list(rbnode_t *node, metadata_t *);
static void *get_heap(size_t size);
static void *alloc_tab(size_t size);
static bool resize_tab_values(metadata_t **old, rbnode_t *node);
static rbnode_t *remove_min(rbnode_t *node);
static inline rbnode_t *min(rbnode_t *node);
static inline rbnode_t *find_best(rbnode_t *node, size_t size);
static metadata_t *search_freed_block(rbnode_t *node, size_t size);
static void *split_block(metadata_t *node, size_t size);
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void *free_realloc(void *ptr);
static void invalid_pointer(void *ptr);
static void double_free(void *ptr);
static metadata_t *fusion(metadata_t *first, metadata_t *second);
static inline metadata_t *try_fusion(metadata_t *node);
static inline void change_break(metadata_t *node);
static size_t get_new_page(size_t size);
static void *get_in_page(size_t size);
