/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Per-rule expression trees of large rule sets. A yx_integer_expr carries
 * YX_INTEGER_EXPR_LIMIT inline nodes (32 KiB); one per rule made loading
 * 100,000 rules touch gigabytes. The store keeps each tree's fields and its
 * used inline nodes, and rebuilds one full tree (the scratch) for the rule
 * being read: open copies a parked tree into the scratch, close copies the
 * scratch, with every change made to it, back. Owned pointers (extra nodes,
 * bindings, loop failures) move with the tree. Inline nodes past count are
 * zero in the scratch, as in a tree that was zero-initialized. */
#ifndef YX_SERIALIZATION_TREE_STORE_H
#define YX_SERIALIZATION_TREE_STORE_H
#include <stddef.h>

typedef struct yx_tree_store {
    unsigned char **parked; /* head bytes, then inline nodes [0, count) */
    size_t *sizes; /* bytes of each parked block */
    size_t count;
    yx_integer_expr *scratch;
    size_t open, zeroed; /* rule held by the scratch (SIZE_MAX: none); nodes past count to clear */
} yx_tree_store;

#define YX_TREE_HEAD_BEFORE offsetof(yx_integer_expr, nodes)
#define YX_TREE_HEAD_AFTER_AT (offsetof(yx_integer_expr, nodes) + sizeof(((yx_integer_expr *)0)->nodes))
#define YX_TREE_HEAD_AFTER (sizeof(yx_integer_expr) - YX_TREE_HEAD_AFTER_AT)
#define YX_TREE_HEAD (YX_TREE_HEAD_BEFORE + YX_TREE_HEAD_AFTER)

static bool yx_tree_store_init(yx_tree_store *s, size_t count)
{
    memset(s, 0, sizeof(*s));
    s->open = SIZE_MAX;
    s->parked = calloc(count ? count : 1, sizeof(*s->parked));
    s->sizes = calloc(count ? count : 1, sizeof(*s->sizes));
    s->scratch = calloc(1, sizeof(*s->scratch));
    if (!s->parked || !s->sizes || !s->scratch) {
        free(s->parked);
        free(s->sizes);
        free(s->scratch);
        memset(s, 0, sizeof(*s));
        return false;
    }
    s->count = count;
    return true;
}

static size_t yx_tree_inline_nodes(const yx_integer_expr *tree)
{
    return tree->extra_nodes ? 0 : tree->count;
}

/* Moves the scratch into entry i, which takes its owned pointers. */
static bool yx_tree_store_park(yx_tree_store *s, size_t i)
{
    yx_integer_expr *t = s->scratch;
    /* A decoder reserves for the rest of a function body, which holds the
     * later rules of the chunk too: a tree that fits half the inline nodes
     * goes back to them, a larger one keeps twice its size (both leave room
     * for the nodes a later emission adds). */
    if (t->extra_nodes && t->count <= YX_INTEGER_EXPR_LIMIT / 2) {
        if (t->count) memcpy(t->nodes, t->extra_nodes, t->count * sizeof(yx_integer_expr_node));
        free(t->extra_nodes); t->extra_nodes = NULL; t->node_capacity = 0;
    } else if (t->extra_nodes && t->count <= SIZE_MAX / 2 / sizeof(yx_integer_expr_node) &&
               t->count * 2 < t->node_capacity) {
        yx_integer_expr_node *fit = realloc(t->extra_nodes, t->count * 2 * sizeof(*fit));
        if (fit) { t->extra_nodes = fit; t->node_capacity = t->count * 2; }
    }
    /* The failed loop decodes a decode remembers only spare it work: a
     * parked tree is not decoded again. */
    free(t->loop_failures);
    t->loop_failures = NULL; t->loop_failure_count = t->loop_failure_capacity = 0;
    size_t nodes = yx_tree_inline_nodes(t);
    if (i >= s->count || nodes > (SIZE_MAX - YX_TREE_HEAD) / sizeof(yx_integer_expr_node)) return false;
    size_t size = YX_TREE_HEAD + nodes * sizeof(yx_integer_expr_node);
    /* A block of the same size is rewritten in place. */
    unsigned char *block = s->parked[i] && s->sizes[i] == size ? s->parked[i] : realloc(s->parked[i], size);
    if (!block) return false;
    s->sizes[i] = size;
    memcpy(block, t, YX_TREE_HEAD_BEFORE);
    memcpy(block + YX_TREE_HEAD_BEFORE, (const unsigned char *)t + YX_TREE_HEAD_AFTER_AT, YX_TREE_HEAD_AFTER);
    if (nodes) memcpy(block + YX_TREE_HEAD, t->nodes, nodes * sizeof(yx_integer_expr_node));
    s->parked[i] = block;
    if (t->count > s->zeroed) s->zeroed = t->count;
    /* The scratch no longer owns the moved pointers. */
    t->extra_nodes = NULL; t->node_capacity = 0;
    t->bindings = NULL; t->binding_count = t->binding_capacity = 0;
    t->loop_failures = NULL; t->loop_failure_count = t->loop_failure_capacity = 0;
    s->open = SIZE_MAX;
    return true;
}

/* Clears the scratch to a zero-initialized tree without freeing anything:
 * the pointers it held belong to a parked entry. */
static void yx_tree_store_clear(yx_tree_store *s)
{
    yx_integer_expr *t = s->scratch;
    size_t zeroed = t->count > s->zeroed ? t->count : s->zeroed;
    if (zeroed > YX_INTEGER_EXPR_LIMIT) zeroed = YX_INTEGER_EXPR_LIMIT;
    memset(t, 0, YX_TREE_HEAD_BEFORE);
    memset((unsigned char *)t + YX_TREE_HEAD_AFTER_AT, 0, YX_TREE_HEAD_AFTER);
    memset(t->nodes, 0, zeroed * sizeof(yx_integer_expr_node));
    s->zeroed = 0;
    s->open = SIZE_MAX;
}

/* An entry still open is parked before the scratch is reused, so its owned
 * pointers are never lost or left stale in its parked copy. */
static void yx_tree_store_settle(yx_tree_store *s)
{
    if (s->open != SIZE_MAX) (void)yx_tree_store_park(s, s->open);
}

/* The scratch as a zero-initialized tree, to decode a new entry into. */
static yx_integer_expr *yx_tree_store_fresh(yx_tree_store *s)
{
    yx_tree_store_settle(s);
    yx_tree_store_clear(s);
    return s->scratch;
}

/* The scratch as a copy of from (*scratch = *from), for a from whose inline
 * nodes past its count are zero and which owns no pointers. */
static yx_integer_expr *yx_tree_store_copy(yx_tree_store *s, const yx_integer_expr *from)
{
    yx_integer_expr *t = yx_tree_store_fresh(s);
    size_t nodes = yx_tree_inline_nodes(from);
    if (nodes > YX_INTEGER_EXPR_LIMIT) return NULL;
    memcpy(t, from, YX_TREE_HEAD_BEFORE);
    memcpy((unsigned char *)t + YX_TREE_HEAD_AFTER_AT, (const unsigned char *)from + YX_TREE_HEAD_AFTER_AT,
           YX_TREE_HEAD_AFTER);
    if (nodes) memcpy(t->nodes, from->nodes, nodes * sizeof(yx_integer_expr_node));
    s->zeroed = from->count;
    return t;
}

/* Entry i in the scratch; close puts it back. A missing entry opens as a
 * zero-initialized tree. */
static yx_integer_expr *yx_tree_store_open(yx_tree_store *s, size_t i)
{
    yx_tree_store_settle(s);
    const unsigned char *block = i < s->count ? s->parked[i] : NULL;
    if (!block) {
        yx_tree_store_clear(s);
        if (i >= s->count) return NULL;
        s->open = i;
        return s->scratch;
    }
    /* As yx_tree_store_clear followed by the copy: the head and the copied
     * nodes are overwritten, so only the stale nodes after them are cleared. */
    yx_integer_expr *t = s->scratch;
    size_t stale = t->count > s->zeroed ? t->count : s->zeroed;
    if (stale > YX_INTEGER_EXPR_LIMIT) stale = YX_INTEGER_EXPR_LIMIT;
    memcpy(t, block, YX_TREE_HEAD_BEFORE);
    memcpy((unsigned char *)t + YX_TREE_HEAD_AFTER_AT, block + YX_TREE_HEAD_BEFORE, YX_TREE_HEAD_AFTER);
    size_t nodes = yx_tree_inline_nodes(t);
    if (nodes > YX_INTEGER_EXPR_LIMIT) {
        memset(t->nodes, 0, stale * sizeof(yx_integer_expr_node));
        s->zeroed = 0;
        s->open = SIZE_MAX;
        return NULL;
    }
    if (nodes) memcpy(t->nodes, block + YX_TREE_HEAD, nodes * sizeof(yx_integer_expr_node));
    if (stale > nodes) memset(t->nodes + nodes, 0, (stale - nodes) * sizeof(yx_integer_expr_node));
    s->zeroed = t->count;
    s->open = i;
    return t;
}

static bool yx_tree_store_close(yx_tree_store *s, size_t i)
{
    if (s->open != i) return false;
    return yx_tree_store_park(s, i);
}

/* Destroys every parked tree as yx_integer_expr_destroy would. */
static void yx_tree_store_destroy(yx_tree_store *s)
{
    if (!s->parked) return;
    yx_tree_store_settle(s);
    for (size_t i = 0; i < s->count; ++i) {
        if (!s->parked[i]) continue;
        yx_integer_expr *t = yx_tree_store_open(s, i);
        if (t) yx_integer_expr_destroy(t);
        free(s->parked[i]);
        s->parked[i] = NULL;
        s->open = SIZE_MAX;
    }
    free(s->parked);
    free(s->sizes);
    free(s->scratch);
    memset(s, 0, sizeof(*s));
}

/* A dense array of trees or a store, read one tree at a time. */
typedef struct yx_tree_list {
    yx_integer_expr *dense;
    yx_tree_store *store;
} yx_tree_list;

static yx_integer_expr *yx_tree_list_open(yx_tree_list *list, size_t i)
{
    return list->dense ? &list->dense[i] : yx_tree_store_open(list->store, i);
}

static bool yx_tree_list_close(yx_tree_list *list, size_t i)
{
    return list->dense ? true : yx_tree_store_close(list->store, i);
}
#endif
