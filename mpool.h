#pragma once

#include <stdbool.h>
#include "list.h"

typedef struct slab{
    size_t size;
    void *ptr;
    struct list_head list;
} slab_t;

#define word_size       8
#define log2_word_size  3
#define header_size     sizeof(slab_t)


slab_t *get_loc_to_place(struct list_head *head, int place);
struct list_head *get_loc_to_free(struct list_head *head, void *addr);
void list_replace(struct list_head *from, struct list_head *to);
void list_insert_before(struct list_head *node, struct list_head *after);
size_t round_up(const size_t x);
void list_replace(struct list_head *from, struct list_head *to);