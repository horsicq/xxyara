/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* The meta engine also builds a reverse Thompson NFA with shrink(false) and
 * WhichCaptures::None: regex-automata 0.4.18 meta/{regex,strategy}.rs:3329,517.
 * Its Unicode classes use compiler.rs:1531-1567's bounded suffix cache, not
 * the forward compiler's compact UTF-8 DFA. Included after regex_size_nfa.inc. */
#ifndef XXYARA_REGEX_SIZE_REVERSE_INC
#define XXYARA_REGEX_SIZE_REVERSE_INC

typedef struct {
    uint32_t from, state;
    unsigned char first, last;
} yx_regex_nfa_suffix_entry;

typedef struct {
    yx_regex_nfa_emitter *emitter;
    yx_regex_nfa_suffix_entry cache[1000];
    uint32_t target;
} yx_regex_nfa_suffix;

static void yx_regex_nfa_reverse_sequence(yx_regex_nfa_suffix *p,
                                           uint32_t first, uint32_t last)
{
    unsigned char a[4], b[4];
    unsigned width = yx_regex_size_encode(first, a);
    (void)yx_regex_size_encode(last, b);
    uint32_t end = p->target;
    for (unsigned i = 0; i < width; ++i) {
        /* map.rs:282-293 hashes (from, start, end), in that order. Keeping
         * absolute builder IDs matters because a collision evicts a suffix. */
        uint64_t hash = UINT64_C(14695981039346656037);
        hash = (hash ^ end) * UINT64_C(1099511628211);
        hash = (hash ^ a[i]) * UINT64_C(1099511628211);
        hash = (hash ^ b[i]) * UINT64_C(1099511628211);
        yx_regex_nfa_suffix_entry *entry = &p->cache[hash % 1000];
        if (entry->state && entry->from == end &&
            entry->first == a[i] && entry->last == b[i]) {
            end = entry->state;
        } else {
            uint32_t state = p->emitter->states;
            yx_regex_nfa_emit(p->emitter, 1, 0);
            *entry = (yx_regex_nfa_suffix_entry){end, state, a[i], b[i]};
            end = state;
        }
    }
    /* Each UTF-8 sequence patches one additional alternative into Union. */
    yx_regex_nfa_emit(p->emitter, 0, 4);
}

static void yx_regex_nfa_reverse_range(yx_regex_nfa_suffix *p,
                                        uint32_t first, uint32_t last)
{
    if (first > last || p->emitter->failed ||
        p->emitter->bytes > YX_REGEX_NFA_SIZE_LIMIT) return;
    if (first < 0xe000 && last > 0xd7ff) {
        yx_regex_nfa_reverse_range(p, first, 0xd7ff);
        yx_regex_nfa_reverse_range(p, 0xe000, last); return;
    }
    static const uint32_t maxima[] = {0x7f, 0x7ff, 0xffff};
    for (unsigned i = 0; i < 3; ++i) if (first <= maxima[i] && last > maxima[i]) {
        yx_regex_nfa_reverse_range(p, first, maxima[i]);
        yx_regex_nfa_reverse_range(p, maxima[i] + 1, last); return;
    }
    for (unsigned i = 1; i < 4 && last > 127; ++i) {
        uint32_t mask = (1u << (6 * i)) - 1;
        if ((first & ~mask) != (last & ~mask)) {
            if (first & mask) {
                yx_regex_nfa_reverse_range(p, first, first | mask);
                yx_regex_nfa_reverse_range(p, (first | mask) + 1, last); return;
            }
            if ((last & mask) != mask) {
                yx_regex_nfa_reverse_range(p, first, (last & ~mask) - 1);
                yx_regex_nfa_reverse_range(p, last & ~mask, last); return;
            }
        }
    }
    yx_regex_nfa_reverse_sequence(p, first, last);
}

static void yx_regex_nfa_reverse_class(yx_regex_nfa_emitter *p,
                                        const yx_regex_nfa_node *node)
{
    if (!node->unicode || !node->count || node->ranges[node->count - 1].last < 128) {
        yx_regex_nfa_emit(p, 2, 8 * node->count); return;
    }
    yx_regex_nfa_suffix *suffix = calloc(1, sizeof(*suffix));
    if (!suffix) { p->failed = true; return; }
    suffix->emitter = p;
    /* c_unicode_class_reverse_with_suffix emits Union, then Empty. */
    suffix->target = p->states + 1;
    yx_regex_nfa_emit(p, 2, 0);
    for (size_t i = 0; i < node->count; ++i)
        yx_regex_nfa_reverse_range(suffix, node->ranges[i].first, node->ranges[i].last);
    free(suffix);
}

static void yx_regex_nfa_reverse_compile(yx_regex_nfa_emitter *p,
                                          const yx_regex_nfa_node *node);

static void yx_regex_nfa_reverse_alt(yx_regex_nfa_emitter *p,
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
            for (size_t i = 0; i < count / 2; ++i) {
                unsigned char swap = bytes[i]; bytes[i] = bytes[count - i - 1];
                bytes[count - i - 1] = swap;
            }
            yx_regex_nfa_trie_insert(&arena, trie, bytes, count);
        }
        yx_regex_nfa_emit(p, 1, 0);
        if (!arena.failed) yx_regex_nfa_trie_emit(p, trie);
        else p->failed = true;
        yx_regex_nfa_free(&arena); return;
    }
    size_t index = 0;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
        yx_regex_nfa_reverse_compile(p, l->node);
        if (++index == 2) yx_regex_nfa_emit(p, 2, 8);
        else if (index > 2) yx_regex_nfa_emit(p, 0, 4);
        if (p->bytes > YX_REGEX_NFA_SIZE_LIMIT) break;
    }
}

static void yx_regex_nfa_reverse_repeat(yx_regex_nfa_emitter *p,
                                         const yx_regex_nfa_node *node)
{
    const yx_regex_nfa_node *child = node->child;
    size_t lower = node->lower, upper = node->upper;
    if (node->unbounded) {
        if (!lower && !child->nullable) {
            yx_regex_nfa_emit(p, 1, 0);
            yx_regex_nfa_reverse_compile(p, child);
            yx_regex_nfa_emit(p, 0, 8);
        } else if (!lower) {
            yx_regex_nfa_reverse_compile(p, child);
            yx_regex_nfa_emit(p, 3, 16);
        } else {
            for (size_t i = 0; i < lower && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT; ++i)
                yx_regex_nfa_reverse_compile(p, child);
            yx_regex_nfa_emit(p, 1, 8);
        }
    } else if (!lower && upper == 1) {
        yx_regex_nfa_emit(p, 1, 0);
        yx_regex_nfa_reverse_compile(p, child);
        yx_regex_nfa_emit(p, 1, 8);
    } else {
        if (!lower) yx_regex_nfa_emit(p, 1, 0);
        for (size_t i = 0; i < lower && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT; ++i)
            yx_regex_nfa_reverse_compile(p, child);
        if (lower < upper) {
            yx_regex_nfa_emit(p, 1, 0);
            for (size_t i = lower; i < upper && p->bytes <= YX_REGEX_NFA_SIZE_LIMIT; ++i) {
                yx_regex_nfa_emit(p, 1, 0);
                yx_regex_nfa_reverse_compile(p, child);
                yx_regex_nfa_emit(p, 0, 8);
            }
        }
    }
}

static void yx_regex_nfa_reverse_compile(yx_regex_nfa_emitter *p,
                                          const yx_regex_nfa_node *node)
{
    if (!node || p->failed || p->bytes > YX_REGEX_NFA_SIZE_LIMIT) return;
    switch (node->kind) {
    case YX_NFA_EMPTY: case YX_NFA_LOOK:
        yx_regex_nfa_emit(p, 1, 0); break;
    case YX_NFA_LITERAL:
        yx_regex_nfa_emit(p, node->count, 0); break;
    case YX_NFA_CLASS: yx_regex_nfa_reverse_class(p, node); break;
    case YX_NFA_CAPTURE: yx_regex_nfa_reverse_compile(p, node->child); break;
    case YX_NFA_CONCAT: {
        if (node->count > SIZE_MAX / sizeof(yx_regex_nfa_node *)) {
            p->failed = true; break;
        }
        const yx_regex_nfa_node **children = malloc(node->count * sizeof(*children));
        if (!children && node->count) { p->failed = true; break; }
        size_t count = 0;
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            children[count++] = l->node;
        while (count) yx_regex_nfa_reverse_compile(p, children[--count]);
        free(children); break;
    }
    case YX_NFA_ALT: yx_regex_nfa_reverse_alt(p, node); break;
    case YX_NFA_REPEAT: yx_regex_nfa_reverse_repeat(p, node); break;
    }
}

static bool yx_regex_nfa_end_anchored(const yx_regex_nfa_node *node)
{
    if (!node) return false;
    if (node->kind == YX_NFA_LOOK) {
        /* The parser hashes source spelling starting with the multiline bit.
         * '$' anchors absolutely only outside multiline; '\z' always does. */
        return node->look == 36 || node->look == 3158 || node->look == 4247;
    }
    if (node->kind == YX_NFA_CAPTURE || (node->kind == YX_NFA_REPEAT && node->lower))
        return yx_regex_nfa_end_anchored(node->child);
    if (node->kind == YX_NFA_ALT) {
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            if (!yx_regex_nfa_end_anchored(l->node)) return false;
        return node->count != 0;
    }
    if (node->kind == YX_NFA_CONCAT) {
        bool anchored = false;
        for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
            if (!l->node->zero) anchored = false;
            anchored |= yx_regex_nfa_end_anchored(l->node);
        }
        return anchored;
    }
    return false;
}

static size_t yx_regex_nfa_reverse_size(const yx_regex_nfa_node *node)
{
    yx_regex_nfa_emitter p = {0};
    bool anchored = yx_regex_nfa_end_anchored(node);
    yx_regex_nfa_emit(&p, anchored ? 1 : 3, anchored ? 0 : 16);
    yx_regex_nfa_reverse_compile(&p, node);
    yx_regex_nfa_emit(&p, 1, 0);
    return p.failed ? YX_REGEX_NFA_SIZE_LIMIT + 1 : p.bytes;
}
#endif
