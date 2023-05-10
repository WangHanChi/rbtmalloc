#include "alloc.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static malloc_t g_info = {
    .last_node = NULL,
    .page_size = 4096,
    .mutex = NULL,
    .ptr = NULL,
};


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
    metadata_t *next = cur->next;
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



void *malloc(size_t size)
{
    return mmap_malloc(size);
}

void free(void *ptr)
{
    mmap_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    return mmap_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    return mmap_realloc(ptr, size);
}
