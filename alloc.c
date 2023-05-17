#include "alloc.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "list.h"
#include "mpool.h"

// Define malloc_t structure
static malloc_t g_info = {
    .last_node = NULL,
    .page_size = 4096,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .pool_size = 0,
    .pool_free_space = 0,
};

// Compare function for sorting comb_t structures based on their addresses
static int large_addr_comp(const comb_t *a, const comb_t *b)
{
    uintptr_t a_addr = (uintptr_t) a;
    uintptr_t b_addr = (uintptr_t) b;
    return (a_addr > b_addr) - (a_addr < b_addr);
}

// Define a red-black tree based on large_tree_ structure with comb_t
// as the value type and large_addr_comp as the comparison function
rb_gen(static, large_tree_, large_tree, comb_t, link, large_addr_comp)
    large_tree tree;

// Define a list head using the LIST_HEAD macro
LIST_HEAD(slab_head);
static comb_t sm_first;

// Include mmap library
#include <sys/mman.h>

// Internel function declarations
void *mmap_malloc(size_t size);
void *mmap_calloc(size_t nmemb, size_t size);
void *mmap_realloc(void *ptr, size_t size);
void mmap_free(void *ptr);

// Allocate memory using mmap
void *mmap_malloc(size_t size)
{
    if (size == 0)
        return NULL;
    if (g_info.last_node != NULL)
        pthread_mutex_lock(&g_info.mutex);

    void *return_pointer = NULL;
    return_pointer = mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (g_info.last_node == NULL) {
        g_info.last_node =
            mmap(NULL, sizeof(metadata_t), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        g_info.last_node->next = NULL;
        g_info.last_node->prev = NULL;
        g_info.last_node->ptr = NULL;
        g_info.last_node->size = 0;

        pthread_mutex_init(&g_info.mutex, NULL);
        pthread_mutex_lock(&g_info.mutex);
    }

    metadata_t *cur = g_info.last_node;

    while (cur->next != NULL) {
        cur = cur->next;
    }

    metadata_t *new = mmap(NULL, sizeof(metadata_t), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    cur->next = new;
    new->prev = cur;

    cur = new;
    cur->next = NULL;
    cur->size = size;
    cur->ptr = return_pointer;

    pthread_mutex_unlock(&g_info.mutex);

#ifdef DEBUG
    fprintf(stderr, "malloc(%ld) = %p\n", size, return_pointer);
#endif

    if (return_pointer == (void *) -1)
        return NULL;
    return return_pointer;
}

// Free memory allocated using mmap
void mmap_free(void *ptr)
{
#ifdef DEBUG
    fprintf(stderr, "free(%p)\n", ptr);
#endif

    if (ptr == NULL)
        return;

    pthread_mutex_lock(&g_info.mutex);

    metadata_t *cur = g_info.last_node;

    while (cur != NULL && cur->ptr != ptr) {
        cur = cur->next;
    }

    if (cur == NULL) {
        pthread_mutex_unlock(&g_info.mutex);
        return;
    }

    metadata_t *prev = cur->prev;
    metadata_t *next = cur->prev;
    if (prev != NULL) {
        prev->next = next;
    } else {
        g_info.last_node = next;
    }
    if (next != NULL) {
        next->prev = prev;
    }

    pthread_mutex_unlock(&g_info.mutex);
    munmap(cur->ptr, cur->size);
    munmap(cur, sizeof(metadata_t));
}

// Allocate memory and initialize it to zero using mmap
void *mmap_calloc(size_t nmemb, size_t size)
{
    if (nmemb == 0 || size == 0)
        return NULL;

    size_t realsize = nmemb * size;
    void *return_pointer = mmap_malloc(realsize);

#ifdef DEBUG
    fprintf(stderr, "calloc(%ld, %ld) = %p\n", nmemb, size, return_pointer);
#endif

    return return_pointer;
}

// Reallocate memory using mmap
void *mmap_realloc(void *ptr, size_t size)
{
    void *newptr = mmap_malloc(size);
#ifdef DEBUG
    fprintf(stderr, "realloc(%p, %ld) = %p\n", ptr, size, newptr);
#endif
    if (ptr == NULL)
        return newptr;

    pthread_mutex_lock(&g_info.mutex);

    metadata_t *old = g_info.last_node;
    while (old != NULL && old->ptr != ptr)
        old = old->next;

    pthread_mutex_unlock(&g_info.mutex);

    if (old == NULL) {
        mmap_free(newptr);
        return NULL;
    }

    if (newptr == NULL) {
        return NULL;
    }
    memcpy(newptr, ptr, old->size);

    mmap_free(ptr);

    return newptr;
}

// Internel function declarations
bool pool_init(void *addr, size_t size);
void *pool_malloc(size_t size);
void *pool_calloc(size_t nmemb, size_t size);
void *pool_realloc(void *addr, size_t size);
void pool_free(void *addr);

void block_try_merge(struct list_head *head,
                     struct list_head *node1,
                     struct list_head *node2)
{
    if (node1 == head || node2 == head)
        return;

    comb_t *n1 = container_of(node1, comb_t, list);
    comb_t *n2 = container_of(node2, comb_t, list);
    uintptr_t loc = (uintptr_t) (&n1->ptr + n1->size);
    if (loc == (uintptr_t) n2) {
        list_del(node2);
        n1->size += word_size + n2->size;
        g_info.pool_free_space += word_size;
    }
}


// Initialize the memory pool
bool pool_init(void *addr, size_t size)
{
    if (!addr) /* not a valid memory address */
        return false;

    if (size <= header_size) /* size is too small, can notstore a header */
        return false;

    g_info.pool_size = size - word_size;
    g_info.pool_free_space = size - word_size;
    g_info.tab = &sm_first;
    g_info.tab->list = slab_head;
    comb_t *current = (comb_t *) addr;
    current->size = g_info.pool_free_space;
    list_add(&current->list, &g_info.tab->list);
    return true;
}

// Allocate memory from the pool
void *pool_malloc(size_t size)
{
    if (size <= 0)
        return NULL;

    if (g_info.tab != NULL)
        pthread_mutex_lock(&g_info.mutex);

    size_t _size = round_up(size);
    if (g_info.tab == NULL) {
        void *ptr = mmap(NULL, SMALL_POOL_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        bool check = pool_init(ptr, SMALL_POOL_SIZE);
        assert(check);  // for debug
        pthread_mutex_init(&g_info.mutex, NULL);
        pthread_mutex_lock(&g_info.mutex);
    }

    if (g_info.pool_free_space <= (_size + header_size))
        return NULL;

    comb_t *ret = get_loc_to_place(&g_info.tab->list, _size);
    if (!ret)
        return NULL;

    comb_t *new_block = (comb_t *) ((void *) &ret->ptr + _size);
    new_block->size = ret->size - word_size - _size;
    ret->allsize = _size + sizeof(comb_t) - sizeof(void *);
    ret->size = _size;
    list_replace(&ret->list, &new_block->list);
    g_info.pool_free_space -= _size;
    g_info.pool_free_space -= (sizeof(comb_t) - sizeof(void *));
    pthread_mutex_unlock(&g_info.mutex);

#ifdef DEBUG
    fprintf(stderr, "malloc(%ld) = %p, block size = (%ld)\nremain(%ld)\n", size,
            &ret->ptr, ret->allsize, g_info.pool_free_space);
#endif

    return &ret->ptr;
}

// Allocate and zero-initialize memory from the pool
void *pool_calloc(size_t nmemb, size_t size)
{
    void *ptr = pool_malloc(size);
    if (!ptr)
        return NULL;

    memset(ptr, 0, nmemb);
    return ptr;
}

// Reallocate memory in the pool
void *pool_realloc(void *addr, size_t size)
{
    void *ptr = pool_malloc(size);
    if (!ptr)
        return NULL;

    memcpy(ptr, addr, size);
    pool_free(addr);
    return ptr;
}

// Free memory in the pool
void pool_free(void *addr)
{
#ifdef DEBUG
    fprintf(stderr, "free(%p)\n", addr);
#endif

    if (addr == NULL)
        return;
    pthread_mutex_lock(&g_info.mutex);
    comb_t *target = container_of(addr, comb_t, ptr);
    g_info.pool_free_space += target->allsize;
    struct list_head *target_after = get_loc_to_free(&g_info.tab->list, addr);
    list_insert_before(&target->list, target_after);
    block_try_merge(&g_info.tab->list, &target->list, target->list.next);
    block_try_merge(&g_info.tab->list, target->list.prev, &target->list);

#ifdef DEBUG
    fprintf(stderr, "remain:%ld | page size:%ld\n", g_info.pool_free_space,
            g_info.pool_size);
#endif

    pthread_mutex_unlock(&g_info.mutex);
}

// Internel function declarations
void *tree_malloc(size_t size);
void *tree_calloc(size_t nmemb, size_t size);
void *tree_realloc(void *ptr, size_t size);
void tree_free(void *ptr);

#define PAGE_SIZE 4096
#define log2_PAGE_SIZE 12

// Round up a given value to the nearest multiple of the page size
size_t round_up_page(const size_t x)
{
    return ((x + (PAGE_SIZE)) >> log2_PAGE_SIZE) << log2_PAGE_SIZE;
}


static int n = 0;
// Function to delete a node in the tree, used as a callback
void node_delete(comb_t *node, void *data)
{
    (void) data;  // This is to avoid compiler warning
    printf("Key : %p is %d | size:%ld\n", node, n++, node->size);
}

// Function pointer to the node_delete function
void (*cb)(comb_t *, void *) = node_delete;

// Allocate memory from the Red-Black Tree
void *tree_malloc(size_t size)
{
    if (size == 0)
        return NULL;
    if (g_info.large_used_tree != NULL)
        pthread_mutex_lock(&g_info.mutex);

    void *return_pointer = NULL;
    size_t round_up_size = round_up_page(size + sizeof(comb_t));
    return_pointer = mmap(NULL, round_up_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (g_info.large_used_tree == NULL) {
        large_tree_new(&tree);
        g_info.large_used_tree = &tree;
        pthread_mutex_init(&g_info.mutex, NULL);
        pthread_mutex_lock(&g_info.mutex);
    }

#ifdef DEBUG
    n = 0;
    large_tree_destroy(g_info.large_used_tree, cb, NULL);
#endif

    comb_t *new = (comb_t *) return_pointer;

    new->size = size;
    new->allsize = round_up_size;
    new->ptr = (void *) new + sizeof(size_t) + sizeof(size_t) +
               sizeof(rb_node(comb_t));
    large_tree_insert(g_info.large_used_tree, new);

#ifdef DEBUG
    fprintf(stderr, "ROOT -> %p | tree -> %p\n", g_info.large_used_tree, &tree);
    fprintf(stderr,
            "new : %p | new->size : %ld | new->ptr : %p | &new->ptr : %p\n",
            new, new->size, new->ptr, &new->ptr);
    fprintf(stderr, "the left : %p | the right : %p\n",
            g_info.large_used_tree->root->link.left,
            g_info.large_used_tree->root->link.right_red);
    fprintf(stderr, "the root is %p\n", g_info.large_used_tree->root);
#endif

    pthread_mutex_unlock(&g_info.mutex);

#ifdef DEBUG
    n = 0;
    large_tree_destroy(g_info.large_used_tree, cb, NULL);
#endif

#ifdef DEBUG
    fprintf(stderr, "malloc(%ld) = %p, total size = %ld\n\n", size, &new->ptr,
            round_up_size);
#endif

    if (return_pointer == (void *) -1)
        return NULL;
    return &new->ptr;
}

// Free memory in the Red-Black Tree
void tree_free(void *ptr)
{
#ifdef DEBUG
    fprintf(stderr, "free(%p)\n\n", ptr);
#endif

    if (ptr == NULL)
        return;

    pthread_mutex_lock(&g_info.mutex);

    comb_t *remove = container_of(ptr, comb_t, ptr);
#ifdef DEBUG
    n = 0;
    large_tree_destroy(g_info.large_used_tree, cb, NULL);
#endif
    large_tree_remove(g_info.large_used_tree, remove);

#ifdef DEBUG
    n = 0;
    large_tree_destroy(g_info.large_used_tree, cb, NULL);
#endif
    pthread_mutex_unlock(&g_info.mutex);

    munmap(remove, remove->allsize);
}

// Allocate and zero-initialize memory from the Red-Black Tree
void *tree_calloc(size_t nmemb, size_t size)
{
    if (nmemb == 0 || size == 0)
        return NULL;

    size_t realsize = nmemb * size;
    void *return_pointer = tree_malloc(realsize);

#ifdef DEBUG
    fprintf(stderr, "calloc(%ld, %ld) = %p\n", nmemb, size, return_pointer);
#endif

    return return_pointer;
}

// Reallocate memory from the Red-Black Tree
void *tree_realloc(void *ptr, size_t size)
{
    comb_t *remove = container_of(ptr, comb_t, ptr);
    if (remove == NULL) {
        printf("REALLOC ERROR !\n");
        return NULL;
    }
    if (remove->size > size) {
        remove->size = size;
        return &remove->ptr;
    }

    void *newptr = tree_malloc(size);
    if (newptr == NULL) {
        return NULL;
    }

#ifdef DEBUG
    fprintf(stderr, "realloc(%p, %ld) = %p\n", ptr, size, newptr);
#endif

    if (ptr == NULL)
        return newptr;

    pthread_mutex_lock(&g_info.mutex);

    pthread_mutex_unlock(&g_info.mutex);

    if (remove == NULL) {
        tree_free(newptr);
        return NULL;
    }

#ifdef DEBUG
    n = 0;
    large_tree_destroy(g_info.large_used_tree, cb, NULL);
#endif

    memcpy(newptr, ptr, remove->size);
    tree_free(ptr);
    return newptr;
}

// Allocate memory based on the size
void *malloc(size_t size)
{
    if (size <= MAX_SMALL) {
        // Allocate memory from the small memory pool
        return pool_malloc(size);
    } else {
        // Allocate memory from the tree-based memory pool
        return tree_malloc(size);
    }
}

// Free memory pointed to by the given pointer
void free(void *ptr)
{
    // Get the corresponding comb_t structure from the pointer
    comb_t *select = container_of(ptr, comb_t, ptr);
    if (select->size <= MAX_SMALL) {
        // Free memory in the small memory pool
        pool_free(ptr);
    } else {
        // Free memory in the tree-based memory pool
        tree_free(ptr);
    }
}

// Allocate and zero-initialize memory based on the number of elements and size
void *calloc(size_t nmemb, size_t size)
{
    if (nmemb * size <= MAX_SMALL) {
        // Allocate and zero-initialize memory from the small memory pool
        return pool_calloc(nmemb, size);
    } else if (nmemb * size > MAX_SMALL) {
        // Allocate and zero-initialize memory from the tree-based memory pool
        return tree_calloc(nmemb, size);
    } else {
        printf("SomeThing wrong!\n");
        return NULL;
    }
}

// Reallocate memory based on the pointer and size
void *realloc(void *ptr, size_t size)
{
    // Get the corresponding comb_t structure from the pointer
    comb_t *select = container_of(ptr, comb_t, ptr);
    if (select->size <= MAX_SMALL && size <= MAX_SMALL) {
        // Reallocate memory within the small memory pool
        return pool_realloc(ptr, size);
    } else if (select->size <= MAX_SMALL && size > MAX_SMALL) {
        // Reallocate memory from small pool to tree-based memory pool
        void *retptr = tree_malloc(size);
        memcpy(retptr, select->ptr, select->size);
        free(select->ptr);
        return retptr;
    } else if (select->size > MAX_SMALL && size <= MAX_SMALL) {
        // Reallocate memory within the tree-based memory pool
        return tree_realloc(ptr, size);
    } else if (select->size > MAX_SMALL && size > MAX_SMALL) {
        // Reallocate memory within the tree-based memory pool
        return tree_realloc(ptr, size);
    } else {
        printf("Something Wrong!\n");
        return NULL;
    }
}
