#pragma once

#include <stdbool.h>
#include "list.h"
#include "rb.h"

// Forward declaration of structures
struct comb_;
typedef struct comb_ comb_t;

#define word_size 8
#define log2_word_size 3
#define header_size sizeof(comb_t)

struct large_;
typedef struct large_ large_t;

// Structure representing a memory block
struct comb_ {
    size_t size;
    size_t allsize;
    union {
        struct list_head list;
        rb_node(comb_t) link;
    };
    void *ptr;
};

// Function prototypes
comb_t *get_loc_to_place(struct list_head *head, int place);
struct list_head *get_loc_to_free(struct list_head *head, void *addr);
void list_replace(struct list_head *from, struct list_head *to);
void list_insert_before(struct list_head *node, struct list_head *after);
size_t round_up(const size_t x);
void list_replace(struct list_head *from, struct list_head *to);