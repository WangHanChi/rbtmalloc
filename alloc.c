#include <pthread.h>
#include "alloc.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static inline void flip_color(rbnode_t *node)
{
    assert(node);
    node->color = !(node->color);
    node->left->color = !(node->left->color);
    node->right->color = !(node->right->color);
}

static rbnode_t *rotate_left(rbnode_t *left)
{
    if (!left)
        return NULL;

    rbnode_t *right = left->right;
    left->right = right->left;
    right->left = left;
    right->color = left->color;
    left->color = RED;
    return right;
}

static rbnode_t *rotate_right(rbnode_t *right)
{
    if (!right)
        return NULL;

    rbnode_t *left = right->left;
    right->left = left->right;
    left->right = right;
    left->color = right->color;
    right->color = RED;
    return left;
}

static rbnode_t *balance(rbnode_t *node)
{
    if (IS_RED(node->right))
        node = rotate_left(node);
    if (IS_RED(node->left) && IS_RED(node->left->left))
        node = rotate_right(node);
    if (IS_RED(node->left) && IS_RED(node->right))
        flip_color(node);
    return node;
}

static rbnode_t *move_red_to_left(rbnode_t *node)
{
    flip_color(node);
    if (node && node->right && IS_RED(node->right->left)) {
        node->right = rotate_right(node->right);
        node = rotate_left(node);
        flip_color(node);
    }
    return node;
}

static rbnode_t *move_red_to_right(rbnode_t *node)
{
    flip_color(node);
    if (node && node->left && IS_RED(node->left->left)) {
        node = rotate_right(node);
        flip_color(node);
    }
    return node;
}

static bool insert_node(rbnode_t *node, metadata_t *new)
{
    size_t i = 0;
    metadata_t **tmp = node->tab_values;
    size_t size = node->size_tab;
    if (node->n_active == size) {
        i = node->n_active;
        if (!resize_tab_values(tmp, node))
            return false;
    } else {
        while (i < size && tmp[i])
            i++;
    }
    node->n_active++;
    ;
    node->tab_values[i] = new;
    return true;
}

static rbnode_t *insert_this(rbnode_t *node, metadata_t *new)
{
    if (!node)
        return new_rbtree(new);

    int res = MY_COMPARE(new->size, node->key);
    if (res == 0) {
        if (!insert_node(node, new))
            return NULL;
    } else if (res < 0)
        node->left = insert_this(node->left, new);
    else
        node->right = insert_this(node->right, new);
    if (IS_RED(node->right) && !IS_RED(node->left))
        node = rotate_left(node);
    if (IS_RED(node->left) && IS_RED(node->left->left))
        node = rotate_right(node);
    if (IS_RED(node->left) && IS_RED(node->right))
        flip_color(node);
    return node;
}

static rbnode_t *insert_in_freed_list(rbnode_t *node, metadata_t *new)
{
    node = insert_this(node, new);
    if (node)
        node->color = BLACK;
    new->free = YFREE;
    return node;
}

static rbnode_t g_rbnode_basis = {
    0, YFREE, NULL, NULL, 0, NULL, SIZE_TAB_VALUES, 1, RED, NULL, NULL,
};

static void *alloc_tab(size_t size)
{
    void *new;
    size_t true_size = ALIGN_BYTES(META_SIZE + (sizeof(new) * size));
    new = get_heap(true_size);
    if (new)
        memset(GET_PAYLOAD(new), 0, true_size - META_SIZE);
    return new;
}

static rbnode_t *new_rbtree(metadata_t *node)
{
    rbnode_t *new;
    if (!(new = get_heap(ALIGN_BYTES(sizeof(*new)))))
        return NULL;
    memcpy(&(new->size_tab), &(g_rbnode_basis.size_tab), sizeof(size_t) * 5);
    new->key = node->size;
    if ((new->tab_values = GET_PAYLOAD(alloc_tab(SIZE_TAB_VALUES))) ==
        (void *) META_SIZE)
        return NULL;
    new->tab_values[0] = node;
    return new;
}

static bool resize_tab_values(metadata_t **old, rbnode_t *node)
{
    metadata_t **new;
    size_t size = (node->size_tab) << 1;
    if ((new = GET_PAYLOAD(alloc_tab(size))) == (void *) META_SIZE)
        return false;
    memcpy(new, old, (size >> 1) * sizeof(*new));
    ((metadata_t *) GET_NODE(node->tab_values))->free = YFREE;
    node->tab_values = new;
    node->size_tab = size;
    return true;
}

static rbnode_t *remove_min(rbnode_t *node)
{
    if (!node)
        return NULL;
    if (!node->left) {
        node->free = YFREE;
        return NULL;
    }
    if (!IS_RED(node->left) && !IS_RED(node->left->left))
        node = move_red_to_left(node);
    node->left = remove_min(node->left);
    return balance(node);
}

static inline rbnode_t *min(rbnode_t *node)
{
    if (!node)
        return NULL;

    while (node->left)
        node = node->left;
    return node;
}

static rbnode_t *remove_key(rbnode_t *node, t_key key)
{
    if (!node)
        return NULL;

    rbnode_t *tmp = NULL;
    if (MY_COMPARE(key, node->key) == -1) {
        if (node->left) {
            if (!IS_RED(node->left) && !IS_RED(node->left->left))
                node = move_red_to_left(node);
            node->left = remove_key(node->left, key);
        }
    } else if (!(node = remove_node(node, key, tmp)))
        return NULL;
    return balance(node);
}

static rbnode_t *remove_node(rbnode_t *node, t_key key, rbnode_t *tmp)
{
    if (IS_RED(node->left))
        node = rotate_right(node);
    if (!MY_COMPARE(key, node->key) && !node->right) {
        node->free = YFREE;
        return NULL;
    }
    if (node->right) {
        if (!IS_RED(node->right) && !IS_RED(node->right->left))
            node = move_red_to_right(node);
        if (!MY_COMPARE(key, node->key)) {
            tmp = min(node->right);
            node->tab_values = tmp->tab_values;
            node->size_tab = tmp->size_tab;
            node->key = tmp->key;
            node->right = remove_min(node->right);
            node->n_active = tmp->n_active;
        } else
            node->right = remove_key(node->right, key);
    }
    return node;
}

static rbnode_t *remove_k(rbnode_t *node, t_key key)
{
    node = remove_key(node, key);
    if (node)
        node->color = BLACK;
    return node;
}

static rbnode_t *get_key(rbnode_t *node, t_key key)
{
    while (node) {
        int cmp;
        if (!(cmp = MY_COMPARE(key, node->key)))
            return (node);
        node = ((cmp < 0) ? node->left : node->right);
    }
    return NULL;
}

static rbnode_t *remove_from_freed_list(rbnode_t *node, metadata_t *meta)
{
    rbnode_t *tmp;
    if ((tmp = get_key(node, meta->size))) {
        meta->free = NFREE;
        metadata_t **tab = tmp->tab_values;
        size_t size = tmp->size_tab;
        for (size_t i = 0; i < size; i++) {
            if (tab[i] == meta) {
                tab[i] = NULL;
                tmp->n_active--;
                if (tmp->n_active == 0)
                    return remove_k(node, meta->size);
                return node;
            }
        }
    }
    return NULL;
}

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static malloc_t g_info = {
    .root_rbtree = NULL,
    .last_node = NULL,
    .end_in_page = NULL,
    .first_block = NULL,
    .page_size = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .page_remaining = 0,
};

static inline rbnode_t *find_best(rbnode_t *node, size_t size)
{
    rbnode_t *tmp = NULL;
    while (node) {
        if (node->key >= size) {
            tmp = node;
            node = node->left;
        } else
            node = node->right;
    }
    return tmp;
}

static metadata_t *search_freed_block(rbnode_t *node, size_t size)
{
    rbnode_t *tmp = find_best(node, size);
    if (tmp) {
        size_t size_tab = tmp->size_tab;
        metadata_t **tab = tmp->tab_values;
        for (size_t i = 0; i < size_tab; i++) {
            if (tab[i])
                return tab[i];
        }
    }
    return NULL;
}

static void *split_block(metadata_t *node, size_t size)
{
    g_info.root_rbtree = remove_from_freed_list(g_info.root_rbtree, node);
    if (node->size > size + sizeof(size_t) &&
        node->size - size > sizeof(rbnode_t) + SIZE_DEFAULT_BLOCK) {
        metadata_t *new = (void *) node + size;
        new->size = node->size - size;
        new->free = YFREE;
        new->prev = node;
        new->next = node->next;
        node->next = new;
        node->size = size;
        if (new->next)
            new->next->prev = new;
        g_info.root_rbtree = insert_in_freed_list(g_info.root_rbtree, new);
    }
    return node;
}

void *malloc(size_t size)
{
    metadata_t *tmp;
    void *ptr;

    pthread_mutex_lock(&g_info.mutex);
    if (size < SIZE_DEFAULT_BLOCK)
        size = SIZE_DEFAULT_BLOCK;
    size = ALIGN_BYTES(size) + META_SIZE;
    if (!g_info.page_size)
        g_info.page_size = getpagesize();
    if ((tmp = search_freed_block(g_info.root_rbtree, size)))
        ptr = split_block(tmp, size);
    else
        ptr = get_heap(size);
    pthread_mutex_unlock(&g_info.mutex);
    return ptr ? (GET_PAYLOAD(ptr)) : NULL;
}

static void invalid_pointer(void *ptr)
{
    printf("Error in '%s': free(): invalid pointer: %p\n",
           ((__progname) ? (__progname) : ("Unknow")), ptr);
    abort();
}

static void double_free(void *ptr)
{
    printf("Error in '%s': free(): double free: %p\n",
           ((__progname) ? (__progname) : ("Unknow")), ptr);
    abort();
}

static metadata_t *fusion(metadata_t *first, metadata_t *second)
{
    first->size += second->size;
    first->next = second->next;
    if (first->next)
        first->next->prev = first;
    else
        g_info.last_node = first;
    return first;
}

static inline metadata_t *try_fusion(metadata_t *node)
{
    while (IS_FREE(node->prev)) {
        g_info.root_rbtree =
            remove_from_freed_list(g_info.root_rbtree, node->prev);
        node = fusion(node->prev, node);
    }
    while (IS_FREE(node->next)) {
        g_info.root_rbtree =
            remove_from_freed_list(g_info.root_rbtree, node->next);
        node = fusion(node, node->next);
    }
    return node;
}

static inline void change_break(metadata_t *node)
{
    size_t pages_to_remove;

    if (node->prev) {
        node->prev->next = NULL;
        g_info.last_node = node->prev;
        g_info.end_in_page = (void *) g_info.last_node + g_info.last_node->size;
    } else {
        g_info.end_in_page = g_info.last_node;
        g_info.last_node = NULL;
    }
    g_info.page_remaining += node->size;
    pages_to_remove = g_info.page_remaining / g_info.page_size;
    /* FIXME: sbrk is deprecated */
    brk((sbrk(0) - (pages_to_remove * g_info.page_size)));
    g_info.page_remaining =
        g_info.page_remaining - (pages_to_remove * g_info.page_size);
}

void free(void *ptr)
{
    if (!ptr)
        return;

    pthread_mutex_lock(&g_info.mutex);
    metadata_t *node = GET_NODE(ptr);
    if (ptr < g_info.first_block || ptr > g_info.end_in_page || !IS_VALID(node))
        invalid_pointer(ptr);
    if (node->free == YFREE)
        double_free(ptr);
    node = try_fusion(node);
    if (!node->next)
        change_break(node);
    else
        g_info.root_rbtree = insert_in_freed_list(g_info.root_rbtree, node);
    pthread_mutex_unlock(&g_info.mutex);
}

void *calloc(size_t nmemb, size_t size)
{
    if (!nmemb || !size)
        return NULL;

    void *ptr;
    if (!(ptr = malloc(size * nmemb)))
        return NULL;

    pthread_mutex_lock(&g_info.mutex);
    memset(ptr, 0, ALIGN_BYTES(size * nmemb));
    pthread_mutex_unlock(&g_info.mutex);
    return ptr;
}

void *free_realloc(void *ptr)
{
    free(ptr);
    return NULL;
}

void *realloc(void *ptr, size_t size)
{
    if (!ptr)
        return malloc(size);
    if (!size)
        return free_realloc(ptr);

    ptr = (void *) ptr - META_SIZE;
    metadata_t *tmp = (metadata_t *) ptr;
    metadata_t *new = ptr;
    if (size + META_SIZE > tmp->size) {
        if (!(new = malloc(size)))
            return NULL;

        size = ALIGN_BYTES(size);
        pthread_mutex_lock(&g_info.mutex);
        memcpy(new, (void *) ptr + META_SIZE,
               (size <= tmp->size) ? (size) : (tmp->size));
        pthread_mutex_unlock(&g_info.mutex);
        free((void *) ptr + META_SIZE);
    } else
        new = GET_PAYLOAD(new);
    return new;
}

static size_t get_new_page(size_t size)
{
    size_t pages = ((size / g_info.page_size) + 1) * g_info.page_size;
    /* FIXME: sbrk is deprecated */
    if (!g_info.end_in_page) {
        if ((g_info.end_in_page = sbrk(0)) == (void *) -1)
            return (size_t) -1;
        g_info.first_block = g_info.end_in_page;
    }
    if (sbrk(pages) == (void *) -1) {
        errno = ENOMEM;
        return (size_t) -1;
    }
    return pages;
}

static void *get_in_page(size_t size)
{
    metadata_t *new = g_info.end_in_page;
    new->size = size;
    new->free = NFREE;
    new->next = NULL;
    new->prev = g_info.last_node;
    if (g_info.last_node)
        g_info.last_node->next = new;
    g_info.last_node = new;
    g_info.end_in_page = (void *) new + size;
    return new;
}

static void *get_heap(size_t size)
{
    size_t tmp;

    if (g_info.page_remaining < size) {
        if ((tmp = get_new_page(size)) == (size_t) -1)
            return NULL;
        g_info.page_remaining += tmp;
    }
    g_info.page_remaining -= size;
    return get_in_page(size);
}
