#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "list.h"
#include "mpool.h"


/* Round up a size to the next multiple of 32 or 64 bits size (4 bytes or 8
 * bytes size) */
size_t round_up(const size_t x)
{
    return ((x + (word_size - 1)) >> log2_word_size) << log2_word_size;
}

void list_replace(struct list_head *from, struct list_head *to)
{
    *to = *from;
    to->next->prev = to;
    to->prev->next = to;
}

/* Search for a free space to place a new block */
comb_t *get_loc_to_place(struct list_head *head, int size)
{
    comb_t *node;
    list_for_each_entry (node, head, list) {
        if (node->size >= (size + header_size))
            return node;
    }
    return NULL;
}

/* Parses the free blocks to find the place to set the one under release.
 * Useful to update the linked list correctly and fast its parsing.
 *
 * Follows the different cases to handle:
 * ┌───────┬────────────────────────────────────────────┐
 * │Block 0│          ~~~~~~~~ Free ~~~~~~~~~           │
 * └───────┴────────────────────────────────────────────┘
 * ┌────────────────────────────────────────────┬───────┐
 * │          ~~~~~~~~ Free ~~~~~~~~~           │Block 0│
 * └────────────────────────────────────────────┴───────┘
 * ┌───────────────┬───────┬───────────────────────────┐
 * │ ~~~ Free ~~~  │Block 0│  ~~~~~~~~ Free ~~~~~~~~   │
 * └───────────────┴───────┴───────────────────────────┘
 * ┌───────┬────────────────────────────────────┬───────┐
 * │Block 0│      ~~~~~~~~ Free ~~~~~~~~~       │Block 1│
 * └───────┴────────────────────────────────────┴───────┘
 * ┌───────┬───────┬────────────────────┬───────┬────────┬───────┬───────┐
 * │Block 0│Block 1│   ~~~ Free ~~~     │Block 2│~ Free ~│Block 3│Block 4│
 * └───────┴───────┴────────────────────┴───────┴────────┴───────┴───────┘
 * ┌────────┬───────┬───────┬────────────────────┬───────┬────────┐
 * │~ Free ~│Block 0│Block 1│   ~~~ Free ~~~     │Block 2│~ Free ~│
 * └────────┴───────┴───────┴────────────────────┴───────┴────────┘
 *
 *   @addr: pointer to an address to release
 * Returns:
 *   a pointer to the location where to place the block to release. The place
 *   to use can be on the left or on the right of address passed. If no place
 *   found, returns NULL.
 */
struct list_head *get_loc_to_free(struct list_head *head, void *addr)
{
    /* In case the free block is monolithic, just return its address */
    if (list_is_singular(head))
        return head->prev;

    comb_t *target = container_of(addr, comb_t, ptr);
    comb_t *node = NULL;

    list_for_each_entry (node, head, list) {
        if ((uintptr_t) target < (uintptr_t) node)
            break;
    }

    return &node->list;
}

void list_insert_before(struct list_head *node, struct list_head *after)
{
    struct list_head *prev = after->prev;
    node->prev = prev;
    node->next = after;
    after->prev = node;
    prev->next = node;
}
