#include "alloc.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mpool.h"
#include "list.h"


static malloc_t g_info = {
    .last_node = NULL,
    .page_size = 4096,
    .mutex = NULL,
    .pool_size = 0,
    .pool_free_space = 0,
    .ptr = NULL,
};


LIST_HEAD(slab_head);
static slab_t sm_first;

#include <sys/mman.h>  // mmap

void *mmap_malloc(size_t size);
void *mmap_calloc(size_t nmemb, size_t size);
void *mmap_realloc(void *ptr, size_t size);
void mmap_free(void *ptr);

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

void *mmap_calloc(size_t nmemb, size_t size)
{
    if (nmemb == 0 || size == 0)
        return NULL;

    size_t realsize = nmemb * size;
    void *return_pointer = malloc(realsize);

#ifdef DEBUG
    fprintf(stderr, "calloc(%ld, %ld) = %p\n", nmemb, size, return_pointer);
#endif

    return return_pointer;
}

void *mmap_realloc(void *ptr, size_t size)
{
    void *newptr = malloc(size);
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
        free(newptr);
        return NULL;
    }

    if (newptr == NULL) {
        return NULL;
    }
    // copy last block to new block
    memcpy(newptr, ptr, old->size);

    // free old block
    free(ptr);

    return newptr;
}

bool pool_init(void *addr, size_t size);
void *pool_malloc(size_t size);
void *pool_calloc(size_t nmemb, size_t size);
void *pool_realloc(void *addr, size_t size);
void pool_free(void *addr);

void block_try_merge(struct list_head *head, struct list_head *node1, struct list_head *node2)
{
    if (node1 == head || node2 == head)
        return;

    slab_t *n1 = container_of(node1, slab_t, list);
    slab_t *n2 = container_of(node2, slab_t, list);
    uintptr_t loc = (uintptr_t) (&n1->ptr + n1->size);
    if (loc == (uintptr_t) n2) {
        list_del(node2);
        n1->size += word_size + n2->size;
        g_info.pool_free_space += word_size;
    }
}
    


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
    slab_t *current = (slab_t *) addr;
    current->size = g_info.pool_free_space;
    list_add(&current->list, &g_info.tab->list);
    return true;
}

void *pool_malloc(size_t size)
{
    if (size <= 0)
        return NULL;

    size_t _size = round_up(size);
    if(g_info.tab == NULL){
        void *ptr = mmap(NULL, SMALL_POOL_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        bool check = pool_init(ptr, SMALL_POOL_SIZE);
        assert(check);      // for debug
    }

    if (g_info.pool_free_space <= (_size + header_size))
        return NULL;

    slab_t *ret = get_loc_to_place(&g_info.tab->list, _size);
    if (!ret)
        return NULL;

    // slab_t *new_block = (slab_t *) (&ret->ptr + _size);
    slab_t *new_block = (slab_t *) ((void *)&ret->ptr + _size + sizeof(slab_t));
    new_block->size = ret->size - word_size - _size;
    ret->size = _size;
    list_replace(&ret->list, &new_block->list);
    g_info.pool_free_space -= _size;
    g_info.pool_free_space -= word_size;
    g_info.pool_free_space -= sizeof(slab_t);
#ifdef DEBUG
    fprintf(stderr, "malloc(%ld) = %p\nremain(%ld)\n", size, &ret->ptr, g_info.pool_free_space);
#endif
    return &ret->ptr;
}

void *pool_calloc(size_t nmemb, size_t size)
{
    void *ptr = pool_malloc(size);
    if (!ptr)
        return NULL;

    memset(ptr, 0, nmemb);
    return ptr;
}

void *pool_realloc(void *addr, size_t size)
{
    void *ptr = pool_malloc(size);
    if (!ptr)
        return NULL;

    memcpy(ptr, addr, size);
    pool_free(addr);
    return ptr;
}

void pool_free(void *addr)
{
#ifdef DEBUG
    fprintf(stderr, "free(%p)\n", addr);
#endif
    slab_t *target = container_of(addr, slab_t, ptr);
    g_info.pool_free_space += target->size;
    struct list_head *target_after = get_loc_to_free(&g_info.tab->list, addr);
    list_insert_before(&target->list, target_after);
    block_try_merge(&g_info.tab->list, &target->list, target->list.next);
    block_try_merge(&g_info.tab->list, target->list.prev, &target->list);
    printf("remain:%ld | page size:%ld\n", g_info.pool_free_space, g_info.pool_size);
}



void *malloc(size_t size)
{
    return pool_malloc(size);
}

void free(void *ptr)
{
    // mmap_free(ptr);
    pool_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    return pool_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    return pool_realloc(ptr, size);
}
