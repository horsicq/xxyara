/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* regex-automata 0.4.18's intermediate Thompson NFA builder. The event tree
 * preserves emission order: Unicode-state cache hashes include absolute IDs. */
typedef enum {
    YX_NFA_EMPTY, YX_NFA_LITERAL, YX_NFA_CLASS, YX_NFA_LOOK,
    YX_NFA_CAPTURE, YX_NFA_CONCAT, YX_NFA_ALT, YX_NFA_REPEAT
} yx_regex_nfa_kind;

/* Arena blocks; allocations are zeroed, 16-byte aligned and freed only
 * all together. */
typedef struct yx_regex_nfa_allocation {
    struct yx_regex_nfa_allocation *next;
    size_t used, size;
} yx_regex_nfa_allocation;
#define YX_REGEX_NFA_BLOCK_HEADER ((sizeof(yx_regex_nfa_allocation) + 15) & ~(size_t)15)

struct yx_regex_nfa_arena {
    yx_regex_nfa_allocation *allocations;
    bool failed;
};

typedef struct yx_regex_nfa_link {
    yx_regex_nfa_node *node;
    struct yx_regex_nfa_link *next;
} yx_regex_nfa_link;

#ifdef XXYARA_NATIVE_REGEX
typedef yx_re_range yx_regex_nfa_range;
#else
typedef struct {
    uint32_t first, last;
} yx_regex_nfa_range;
#endif

struct yx_regex_nfa_node {
    yx_regex_nfa_kind kind;
    yx_regex_nfa_link *first, *last;
    yx_regex_nfa_node *child;
    size_t count, lower, upper;
    bool unbounded, unicode, zero, nullable, anchored, literal, greedy;
    unsigned char *bytes;
    yx_regex_nfa_range *ranges;
    uint32_t look;
};

static yx_regex_nfa_node *yx_regex_nfa_normalize_alt(yx_regex_nfa_arena *arena,
                                                     yx_regex_nfa_node *node);

static void *yx_regex_nfa_alloc(yx_regex_nfa_arena *arena, size_t bytes)
{
    if (!arena || arena->failed || bytes > SIZE_MAX - YX_REGEX_NFA_BLOCK_HEADER - 16)
        return NULL;
    bytes = bytes ? (bytes + 15) & ~(size_t)15 : 16;
    yx_regex_nfa_allocation *head = arena->allocations;
    if (head && head->size - head->used >= bytes) {
        void *p = (unsigned char *)head + YX_REGEX_NFA_BLOCK_HEADER + head->used;
        head->used += bytes;
        return p;
    }
    /* Blocks grow from 2 KiB to 64 KiB; a large request gets its own block
     * behind the current one, which stays open for small requests. */
    size_t size = head ? head->size * 2 : 2048;
    if (size > 65536) size = 65536;
    bool own = bytes > size / 4;
    if (own) size = bytes;
    yx_regex_nfa_allocation *a = calloc(1, YX_REGEX_NFA_BLOCK_HEADER + size);
    if (!a) { arena->failed = true; return NULL; }
    a->size = size;
    a->used = bytes;
    if (own && head) { a->next = head->next; head->next = a; }
    else { a->next = head; arena->allocations = a; }
    return (unsigned char *)a + YX_REGEX_NFA_BLOCK_HEADER;
}

static void yx_regex_nfa_free(yx_regex_nfa_arena *arena)
{
    while (arena->allocations) {
        yx_regex_nfa_allocation *a = arena->allocations;
        arena->allocations = a->next;
        free(a);
    }
}

static yx_regex_nfa_node *yx_regex_nfa_new(yx_regex_nfa_arena *arena,
                                          yx_regex_nfa_kind kind)
{
    yx_regex_nfa_node *node = yx_regex_nfa_alloc(arena, sizeof(*node));
    if (node) { node->kind = kind; node->zero = node->nullable = kind == YX_NFA_EMPTY; }
    return node;
}

static yx_regex_nfa_node *yx_regex_nfa_literal(yx_regex_nfa_arena *arena,
                                               const unsigned char *bytes, size_t count)
{
    yx_regex_nfa_node *node = yx_regex_nfa_new(arena, count ? YX_NFA_LITERAL : YX_NFA_EMPTY);
    if (node) {
        node->literal = true;
        node->count = count;
        node->bytes = yx_regex_nfa_alloc(arena, count);
        if (node->bytes) memcpy(node->bytes, bytes, count);
    }
    return node;
}

static void yx_regex_nfa_append(yx_regex_nfa_arena *arena,
                                  yx_regex_nfa_node *list, yx_regex_nfa_node *node)
{
    if (!list || !node || (arena && arena->failed)) return;
    if (node->kind == list->kind) {
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            yx_regex_nfa_append(arena, list, l->node);
        return;
    }
    if (list->kind == YX_NFA_CONCAT && node->kind == YX_NFA_EMPTY) return;
    yx_regex_nfa_link *link = yx_regex_nfa_alloc(arena, sizeof(*link));
    if (!link) return;
    link->node = node;
    if (list->last) list->last->next = link;
    else list->first = link;
    list->last = link;
    ++list->count;
}

static yx_regex_nfa_node *yx_regex_nfa_list_finish(yx_regex_nfa_arena *arena,
                                                   yx_regex_nfa_node *node)
{
    if (!node || (arena && arena->failed)) return NULL;
    if (!node->count) return yx_regex_nfa_new(arena, YX_NFA_EMPTY);
    if (node->count == 1) return node->first->node;
    if (node->kind == YX_NFA_CONCAT) {
        for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
            if (l->node->kind != YX_NFA_LITERAL) continue;
            yx_regex_nfa_link *end = l->next;
            size_t length = l->node->count, count = 1;
            while (end && end->node->kind == YX_NFA_LITERAL) {
                length += end->node->count; ++count; end = end->next;
            }
            if (count > 1) {
                unsigned char *bytes = yx_regex_nfa_alloc(arena, length);
                if (!bytes) return node;
                size_t at = 0;
                for (yx_regex_nfa_link *part = l; part != end; part = part->next) {
                    memcpy(bytes + at, part->node->bytes, part->node->count);
                    at += part->node->count;
                }
                l->node = yx_regex_nfa_literal(arena, bytes, length);
                l->next = end;
                node->count -= count - 1;
                if (!end) node->last = l;
            }
        }
        if (node->count == 1) return node->first->node;
    } else {
        yx_regex_nfa_node *normalized = yx_regex_nfa_normalize_alt(arena, node);
        if (normalized != node) return normalized;
    }
    node->zero = node->nullable = node->literal = true;
    node->anchored = node->kind == YX_NFA_ALT;
    bool prefix = true;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
        yx_regex_nfa_node *sub = l->node;
        node->zero &= sub->zero;
        node->literal &= sub->literal;
        if (node->kind == YX_NFA_ALT) {
            if (l == node->first) node->nullable = sub->nullable;
            else node->nullable |= sub->nullable;
            node->anchored &= sub->anchored;
        } else {
            node->nullable &= sub->nullable;
            if (prefix) node->anchored |= sub->anchored;
            prefix &= sub->zero;
        }
    }
    return node;
}

static yx_regex_nfa_node *yx_regex_nfa_set(yx_regex_nfa_arena *arena,
                                           const unsigned char set[256], bool unicode)
{
    yx_regex_nfa_node *node = yx_regex_nfa_new(arena, YX_NFA_CLASS);
    if (!node) return NULL;
    size_t count = 0, points = 0;
    unsigned singleton = 0;
    for (unsigned i = 0; i < 256; ++i) if (set[i]) {
        ++points; singleton = i;
        if (!i || !set[i - 1]) ++count;
    }
    if (points == 1) {
        unsigned char bytes[4];
        unsigned width = unicode ? yx_regex_size_encode(singleton, bytes) : 1;
        if (!unicode) bytes[0] = (unsigned char)singleton;
        return yx_regex_nfa_literal(arena, bytes, width);
    }
    node->unicode = unicode;
    node->count = count;
    node->ranges = yx_regex_nfa_alloc(arena, count * sizeof(*node->ranges));
    if (!node->ranges) return node;
    size_t at = 0;
    for (unsigned i = 0; i < 256; ++i) if (set[i]) {
        unsigned first = i;
        while (i + 1 < 256 && set[i + 1]) ++i;
        node->ranges[at++] = (yx_regex_nfa_range){first, i};
    }
    return node;
}

#ifdef XXYARA_NATIVE_REGEX
static yx_regex_nfa_node *yx_regex_nfa_ranges(yx_regex_nfa_arena *arena,
                                              const yx_re_range *ranges,
                                              size_t count, bool unicode)
{
    if (count == 1 && ranges[0].first == ranges[0].last) {
        unsigned char bytes[4];
        unsigned width = unicode || ranges[0].first > 255 ?
            yx_regex_size_encode(ranges[0].first, bytes) : 1;
        if (width == 1) bytes[0] = (unsigned char)ranges[0].first;
        return yx_regex_nfa_literal(arena, bytes, width);
    }
    yx_regex_nfa_node *node = yx_regex_nfa_new(arena, YX_NFA_CLASS);
    if (node) {
        node->unicode = unicode;
        node->count = count;
        node->ranges = yx_regex_nfa_alloc(arena, count * sizeof(*node->ranges));
        if (node->ranges) for (size_t i = 0; i < count; ++i)
            node->ranges[i] = (yx_regex_nfa_range){ranges[i].first, ranges[i].last};
    }
    return node;
}
#endif

static yx_regex_nfa_node *yx_regex_nfa_wrap(yx_regex_nfa_arena *arena,
                                            yx_regex_nfa_kind kind,
                                            yx_regex_nfa_node *child)
{
    yx_regex_nfa_node *node = yx_regex_nfa_new(arena, kind);
    if (node && child) {
        node->child = child;
        node->zero = child->zero; node->nullable = child->nullable;
        node->anchored = child->anchored;
    }
    return node;
}

static bool yx_regex_nfa_equal(const yx_regex_nfa_node *a,
                                const yx_regex_nfa_node *b)
{
    if (a == b) return true;
    if (!a || !b || a->kind != b->kind || a->count != b->count) return false;
    switch (a->kind) {
    case YX_NFA_EMPTY: return true;
    case YX_NFA_LOOK: return a->look == b->look;
    case YX_NFA_LITERAL: return !memcmp(a->bytes, b->bytes, a->count);
    case YX_NFA_CLASS:
        if (a->unicode != b->unicode) return false;
        for (size_t i = 0; i < a->count; ++i)
            if (a->ranges[i].first != b->ranges[i].first ||
                a->ranges[i].last != b->ranges[i].last) return false;
        return true;
    case YX_NFA_CAPTURE: return false; /* Capture indexes differ. */
    case YX_NFA_REPEAT:
        return a->lower == b->lower && a->upper == b->upper &&
            a->unbounded == b->unbounded && a->greedy == b->greedy &&
            yx_regex_nfa_equal(a->child, b->child);
    default: {
        yx_regex_nfa_link *x = a->first, *y = b->first;
        while (x && y) {
            if (!yx_regex_nfa_equal(x->node, y->node)) return false;
            x = x->next; y = y->next;
        }
        return !x && !y;
    }
    }
}

static int yx_regex_nfa_range_compare(const void *a, const void *b)
{
    const yx_regex_nfa_range *x = a, *y = b;
    return x->first < y->first ? -1 : x->first > y->first ? 1 :
        x->last < y->last ? -1 : x->last > y->last;
}

static bool yx_regex_nfa_singleton(const yx_regex_nfa_node *node, uint32_t *cp)
{
    if (node->kind != YX_NFA_LITERAL || !node->count || node->count > 4) return false;
    const unsigned char *s = node->bytes;
    size_t width = s[0] < 128 ? 1 : s[0] >= 0xc2 && s[0] < 0xe0 ? 2 :
        s[0] >= 0xe0 && s[0] < 0xf0 ? 3 : s[0] >= 0xf0 && s[0] < 0xf5 ? 4 : 0;
    if (node->count != width) return false;
    uint32_t point = s[0] & (width == 1 ? 127u : (1u << (7 - width)) - 1);
    for (size_t i = 1; i < width; ++i) {
        if ((s[i] & 0xc0) != 0x80) return false;
        point = (point << 6) | (s[i] & 63);
    }
    if ((width == 2 && point < 128) || (width == 3 && point < 0x800) ||
        (width == 4 && point < 0x10000) || point > 0x10ffff ||
        (point >= 0xd800 && point <= 0xdfff)) return false;
    *cp = point; return true;
}

static yx_regex_nfa_node *yx_regex_nfa_normalize_alt(yx_regex_nfa_arena *arena,
                                                     yx_regex_nfa_node *node)
{
    bool chars = true, bytes = true, classes = true, unicode_classes = true;
    bool byte_classes = true;
    size_t ranges_count = 0;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
        yx_regex_nfa_node *sub = l->node;
        uint32_t cp;
        chars &= yx_regex_nfa_singleton(sub, &cp);
        bytes &= sub->kind == YX_NFA_LITERAL && sub->count == 1;
        classes &= sub->kind == YX_NFA_CLASS;
        if (sub->kind == YX_NFA_CLASS) {
            bool ascii = !sub->count || sub->ranges[sub->count - 1].last < 128;
            unicode_classes &= sub->unicode || ascii;
            byte_classes &= !sub->unicode || ascii;
            ranges_count += sub->count;
        }
    }
    if (chars || bytes || (classes && (unicode_classes || byte_classes))) {
        yx_regex_nfa_node *merged = yx_regex_nfa_new(arena, YX_NFA_CLASS);
        if (!merged) return node;
        merged->unicode = chars || (classes && unicode_classes);
        size_t count = classes ? ranges_count : node->count;
        merged->ranges = yx_regex_nfa_alloc(arena, count * sizeof(*merged->ranges));
        if (!merged->ranges) return node;
        size_t at = 0;
        for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
            if (classes) {
                for (size_t i = 0; i < l->node->count; ++i)
                    merged->ranges[at++] = l->node->ranges[i];
            } else {
                uint32_t cp = l->node->bytes[0];
                if (chars) (void)yx_regex_nfa_singleton(l->node, &cp);
                merged->ranges[at++] = (yx_regex_nfa_range){cp, cp};
            }
        }
        qsort(merged->ranges, at, sizeof(*merged->ranges), yx_regex_nfa_range_compare);
        for (size_t i = 0; i < at; ++i) {
            yx_regex_nfa_range range = merged->ranges[i];
            if (merged->count && range.first <= merged->ranges[merged->count - 1].last + 1) {
                if (range.last > merged->ranges[merged->count - 1].last)
                    merged->ranges[merged->count - 1].last = range.last;
            } else merged->ranges[merged->count++] = range;
        }
        if (merged->count == 1 && merged->ranges[0].first == merged->ranges[0].last) {
            unsigned char encoded[4];
            unsigned width = merged->unicode ?
                yx_regex_size_encode(merged->ranges[0].first, encoded) : 1;
            if (!merged->unicode) encoded[0] = (unsigned char)merged->ranges[0].first;
            return yx_regex_nfa_literal(arena, encoded, width);
        }
        return merged;
    }
    yx_regex_nfa_node *first = node->first->node;
    if (first->kind != YX_NFA_CONCAT) return node;
    size_t common = first->count;
    for (yx_regex_nfa_link *l = node->first->next; l && common; l = l->next) {
        if (l->node->kind != YX_NFA_CONCAT) return node;
        yx_regex_nfa_link *a = first->first, *b = l->node->first;
        size_t count = 0;
        while (a && b && count < common && yx_regex_nfa_equal(a->node, b->node)) {
            ++count; a = a->next; b = b->next;
        }
        common = count;
    }
    if (!common) return node;
    yx_regex_nfa_node *prefix = yx_regex_nfa_new(arena, YX_NFA_CONCAT);
    yx_regex_nfa_node *suffixes = yx_regex_nfa_new(arena, YX_NFA_ALT);
    yx_regex_nfa_link *part = first->first;
    for (size_t i = 0; i < common; ++i, part = part->next)
        yx_regex_nfa_append(arena, prefix, part->node);
    for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
        yx_regex_nfa_node *suffix = yx_regex_nfa_new(arena, YX_NFA_CONCAT);
        part = l->node->first;
        for (size_t i = 0; i < common; ++i) part = part->next;
        for (; part; part = part->next) yx_regex_nfa_append(arena, suffix, part->node);
        yx_regex_nfa_append(arena, suffixes, yx_regex_nfa_list_finish(arena, suffix));
    }
    yx_regex_nfa_append(arena, prefix, yx_regex_nfa_list_finish(arena, suffixes));
    return yx_regex_nfa_list_finish(arena, prefix);
}

typedef struct {
    size_t bytes;
    uint32_t states;
    bool failed;
} yx_regex_nfa_emitter;

static void yx_regex_nfa_emit(yx_regex_nfa_emitter *p, size_t states, size_t heap)
{
    p->bytes = yx_regex_pike_size_add(p->bytes,
        yx_regex_pike_size_add(yx_regex_pike_size_mul(states, 32), heap));
    if (states > UINT32_MAX - p->states) p->failed = true;
    else p->states += (uint32_t)states;
}

/* Ordered literal trie, including unary unions and match-separated chunks:
 * regex-automata's literal_trie.rs:151-235. */
typedef struct yx_regex_nfa_trie_edge {
    unsigned char byte;
    struct yx_regex_nfa_trie *child;
    struct yx_regex_nfa_trie_edge *next;
} yx_regex_nfa_trie_edge;

typedef struct yx_regex_nfa_trie_chunk {
    yx_regex_nfa_trie_edge *first, *last;
    size_t count;
    struct yx_regex_nfa_trie_chunk *next;
} yx_regex_nfa_trie_chunk;

typedef struct yx_regex_nfa_trie {
    yx_regex_nfa_trie_chunk *first, *last;
    bool matched;
} yx_regex_nfa_trie;

static yx_regex_nfa_trie *yx_regex_nfa_trie_new(yx_regex_nfa_arena *arena)
{
    yx_regex_nfa_trie *trie = yx_regex_nfa_alloc(arena, sizeof(*trie));
    if (trie) trie->first = trie->last = yx_regex_nfa_alloc(arena, sizeof(*trie->first));
    return trie;
}

static void yx_regex_nfa_literal_copy(const yx_regex_nfa_node *node,
                                       unsigned char *bytes, size_t *used)
{
    if (node->kind == YX_NFA_LITERAL) {
        memcpy(bytes + *used, node->bytes, node->count);
        *used += node->count;
    } else if (node->kind == YX_NFA_CONCAT) {
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            yx_regex_nfa_literal_copy(l->node, bytes, used);
    }
}

static size_t yx_regex_nfa_literal_length(const yx_regex_nfa_node *node)
{
    if (node->kind == YX_NFA_LITERAL) return node->count;
    size_t count = 0;
    if (node->kind == YX_NFA_CONCAT)
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            count = yx_regex_pike_size_add(count, yx_regex_nfa_literal_length(l->node));
    return count;
}

static void yx_regex_nfa_trie_insert(yx_regex_nfa_arena *arena,
                                      yx_regex_nfa_trie *trie,
                                      const unsigned char *bytes, size_t count)
{
    for (size_t i = 0; i < count && trie && trie->last; ++i) {
        yx_regex_nfa_trie_edge *edge = trie->last->first;
        while (edge && edge->byte != bytes[i]) edge = edge->next;
        if (!edge) {
            edge = yx_regex_nfa_alloc(arena, sizeof(*edge));
            if (!edge) return;
            edge->byte = bytes[i]; edge->child = yx_regex_nfa_trie_new(arena);
            if (trie->last->last) trie->last->last->next = edge;
            else trie->last->first = edge;
            trie->last->last = edge; ++trie->last->count;
        }
        trie = edge->child;
    }
    if (!trie || !trie->last) return;
    bool leaf = true;
    for (yx_regex_nfa_trie_chunk *c = trie->first; c; c = c->next)
        leaf &= c->count == 0;
    if (leaf && trie->matched) return;
    trie->matched = true;
    yx_regex_nfa_trie_chunk *chunk = yx_regex_nfa_alloc(arena, sizeof(*chunk));
    if (chunk) { trie->last->next = chunk; trie->last = chunk; }
}

static void yx_regex_nfa_trie_emit(yx_regex_nfa_emitter *p,
                                    const yx_regex_nfa_trie *trie)
{
    typedef struct {
        const yx_regex_nfa_trie_chunk *chunk;
        const yx_regex_nfa_trie_edge *edge;
        size_t alternatives;
    } frame;
    size_t capacity = 32, depth = 1;
    frame *stack = malloc(capacity * sizeof(*stack));
    if (!stack) { p->failed = true; return; }
    stack[0] = (frame){trie->first, trie->first->first, 0};
    while (depth && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT) {
        frame *f = &stack[depth - 1];
        if (f->edge) {
            const yx_regex_nfa_trie_edge *e = f->edge;
            f->edge = e->next;
            bool leaf = true;
            for (yx_regex_nfa_trie_chunk *sub = e->child->first; sub; sub = sub->next)
                leaf &= sub->count == 0;
            if (!leaf) {
                if (depth == capacity) {
                    if (capacity > SIZE_MAX / 2 / sizeof(*stack)) {
                        p->failed = true; break;
                    }
                    capacity *= 2;
                    frame *grown = realloc(stack, capacity * sizeof(*stack));
                    if (!grown) { p->failed = true; break; }
                    stack = grown;
                }
                stack[depth++] = (frame){e->child->first, e->child->first->first, 0};
            }
            continue;
        }
        if (f->chunk->count) {
            yx_regex_nfa_emit(p, 1, f->chunk->count > 1 ? 8 * f->chunk->count : 0);
            ++f->alternatives;
        }
        if (f->chunk->next) {
            ++f->alternatives;
            f->chunk = f->chunk->next;
            f->edge = f->chunk->first;
        } else {
            yx_regex_nfa_emit(p, 1, 4 * f->alternatives);
            --depth;
        }
    }
    free(stack);
}

static void yx_regex_nfa_compile(yx_regex_nfa_emitter *p,
                                  const yx_regex_nfa_node *node);

static void yx_regex_nfa_compile_alt(yx_regex_nfa_emitter *p,
                                      const yx_regex_nfa_node *node)
{
    bool literals = true;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next)
        literals &= l->node->literal;
    if (literals) {
        yx_regex_nfa_arena arena = {0};
        yx_regex_nfa_trie *trie = yx_regex_nfa_trie_new(&arena);
        for (yx_regex_nfa_link *l = node->first; l && !arena.failed; l = l->next) {
            size_t count = yx_regex_nfa_literal_length(l->node), used = 0;
            unsigned char *bytes = yx_regex_nfa_alloc(&arena, count);
            if (!bytes) break;
            yx_regex_nfa_literal_copy(l->node, bytes, &used);
            yx_regex_nfa_trie_insert(&arena, trie, bytes, count);
        }
        yx_regex_nfa_emit(p, 1, 0);
        if (!arena.failed) yx_regex_nfa_trie_emit(p, trie);
        else p->failed = true;
        yx_regex_nfa_free(&arena);
        return;
    }
    size_t index = 0;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
        yx_regex_nfa_compile(p, l->node);
        if (++index == 2) yx_regex_nfa_emit(p, 2, 8);
        else if (index > 2) yx_regex_nfa_emit(p, 0, 4);
        if (p->bytes > YX_REGEX_NFA_SIZE_LIMIT) break;
    }
}

static void yx_regex_nfa_compile_repeat(yx_regex_nfa_emitter *p,
                                         const yx_regex_nfa_node *node)
{
    const yx_regex_nfa_node *child = node->child;
    size_t lower = node->lower, upper = node->upper;
    if (node->unbounded) {
        if (!lower && !child->nullable) {
            yx_regex_nfa_emit(p, 1, 0);
            yx_regex_nfa_compile(p, child);
            yx_regex_nfa_emit(p, 0, 8);
        } else if (!lower) {
            yx_regex_nfa_compile(p, child);
            yx_regex_nfa_emit(p, 3, 16);
        } else {
            for (size_t i = 0; i < lower && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT; ++i)
                yx_regex_nfa_compile(p, child);
            yx_regex_nfa_emit(p, 1, 8);
        }
    } else if (!lower && upper == 1) {
        yx_regex_nfa_emit(p, 1, 0);
        yx_regex_nfa_compile(p, child);
        yx_regex_nfa_emit(p, 1, 8);
    } else {
        if (!lower) yx_regex_nfa_emit(p, 1, 0);
        for (size_t i = 0; i < lower && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT; ++i)
            yx_regex_nfa_compile(p, child);
        if (lower < upper) {
            yx_regex_nfa_emit(p, 1, 0);
            for (size_t i = lower; i < upper && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT; ++i) {
                yx_regex_nfa_emit(p, 1, 0);
                yx_regex_nfa_compile(p, child);
                yx_regex_nfa_emit(p, 0, 8);
            }
        }
    }
}

static void yx_regex_nfa_compile(yx_regex_nfa_emitter *p,
                                  const yx_regex_nfa_node *node)
{
    if (!node || p->failed || p->bytes > YX_REGEX_NFA_SIZE_LIMIT) return;
    switch (node->kind) {
    case YX_NFA_EMPTY: case YX_NFA_LOOK:
        yx_regex_nfa_emit(p, 1, 0); break;
    case YX_NFA_LITERAL:
        yx_regex_nfa_emit(p, node->count, 0); break;
    case YX_NFA_CLASS:
#ifdef XXYARA_NATIVE_REGEX
        if (node->unicode && node->count && node->ranges[node->count - 1].last > 127) {
            size_t states = 0;
            size_t bytes = yx_regex_nfa_unicode_class_at(
                (const yx_re_range *)node->ranges, node->count, p->states, &states);
            p->bytes = yx_regex_pike_size_add(p->bytes, bytes);
            p->states += (uint32_t)states;
            break;
        }
#endif
        yx_regex_nfa_emit(p, 2, 8 * node->count); break;
    case YX_NFA_CAPTURE:
        yx_regex_nfa_emit(p, 1, 0);
        yx_regex_nfa_compile(p, node->child);
        yx_regex_nfa_emit(p, 1, 0); break;
    case YX_NFA_CONCAT:
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            yx_regex_nfa_compile(p, l->node);
        break;
    case YX_NFA_ALT: yx_regex_nfa_compile_alt(p, node); break;
    case YX_NFA_REPEAT: yx_regex_nfa_compile_repeat(p, node); break;
    }
}

static size_t yx_regex_nfa_size(const yx_regex_nfa_node *node)
{
    yx_regex_nfa_emitter p = {0};
    /* The search prefix has three states and 16 heap bytes. A required start
     * assertion replaces it by one empty state (compiler.rs:981-998). */
    yx_regex_nfa_emit(&p, node && node->anchored ? 1 : 3,
                     node && node->anchored ? 0 : 16);
    yx_regex_nfa_emit(&p, 1, 0);
    yx_regex_nfa_compile(&p, node);
    yx_regex_nfa_emit(&p, 2, 0);
    return p.failed ? YX_REGEX_NFA_SIZE_LIMIT + 1 : p.bytes;
}
