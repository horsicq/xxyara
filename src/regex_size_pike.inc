/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* The pattern compiler selects literal/mask extraction, FastVM, then PikeVM.
 * The limits belong to the selected representation, not to the regexp text. */
typedef struct { size_t bytes[2], splits[2]; } yx_regex_vm_size;

static bool yx_regex_vm_any(const yx_regex_nfa_node *node, bool newline)
{
    if (!node || node->kind != YX_NFA_CLASS) return false;
    uint32_t last = node->unicode ? 0x10ffff : 255;
    if (newline) return node->count == 1 && !node->ranges[0].first &&
                        node->ranges[0].last == last;
    return node->count == 2 && !node->ranges[0].first && node->ranges[0].last == 9 &&
           node->ranges[1].first == 11 && node->ranges[1].last == last;
}

static bool yx_regex_vm_mask(const yx_regex_nfa_node *node)
{
    if (!node || node->kind != YX_NFA_CLASS || node->unicode) return false;
    unsigned char set[256] = {0};
    for (size_t i = 0; i < node->count; ++i)
        for (uint32_t j = node->ranges[i].first; j <= node->ranges[i].last && j < 256; ++j)
            set[j] = 1;
    return yx_regex_size_masked(set);
}

static size_t yx_regex_vm_minimum(const yx_regex_nfa_node *node)
{
    if (!node) return 0;
    switch (node->kind) {
    case YX_NFA_EMPTY: case YX_NFA_LOOK: return 0;
    case YX_NFA_LITERAL: return node->count;
    case YX_NFA_CLASS:
        if (!node->count) return 0;
        if (!node->unicode) return 1;
        { unsigned char bytes[4]; return yx_regex_size_encode(node->ranges[0].first, bytes); }
    case YX_NFA_CAPTURE: return yx_regex_vm_minimum(node->child);
    case YX_NFA_REPEAT:
        return yx_regex_pike_size_mul(node->lower, yx_regex_vm_minimum(node->child));
    case YX_NFA_CONCAT: case YX_NFA_ALT: {
        size_t length = node->kind == YX_NFA_ALT ? SIZE_MAX : 0;
        for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
            size_t sub = yx_regex_vm_minimum(l->node);
            if (node->kind == YX_NFA_CONCAT) length = yx_regex_pike_size_add(length, sub);
            else if (sub < length) length = sub;
        }
        return length == SIZE_MAX ? 0 : length;
    }
    }
    return 0;
}

static yx_regex_vm_size yx_regex_vm_thompson(const yx_regex_nfa_node *node)
{
    yx_regex_vm_size size = {{0, 0}, {0, 0}};
    if (!node) return size;
    switch (node->kind) {
    case YX_NFA_EMPTY: break;
    case YX_NFA_LITERAL:
        size.bytes[0] = node->count;
        for (size_t i = 0; i < node->count; ++i)
            if (node->bytes[i] == 0xaa) ++size.bytes[0];
        size.bytes[1] = size.bytes[0]; break;
    case YX_NFA_LOOK:
        size.bytes[0] = size.bytes[1] = 2; break;
    case YX_NFA_CAPTURE: return yx_regex_vm_thompson(node->child);
    case YX_NFA_CLASS:
        if (yx_regex_vm_any(node, true)) {
            size.bytes[0] = size.bytes[1] = 2;
        } else if (!node->unicode || !node->count || node->ranges[node->count - 1].last < 128) {
            size_t bytes = !node->unicode && yx_regex_vm_mask(node) ? 4 :
                           node->count < 4 ? 3 + 2 * node->count : 34;
            size.bytes[0] = size.bytes[1] = bytes;
        } else {
            size_t bytes = 0, sequences = 0;
            for (size_t i = 0; i < node->count; ++i)
                yx_regex_size_utf8(node->ranges[i].first, node->ranges[i].last,
                                     &bytes, &sequences);
            size.bytes[0] = size.bytes[1] = sequences > 255 ? YX_REGEX_PIKE_SIZE_LIMIT + 1 :
                yx_regex_pike_size_add(bytes, sequences > 1 ? 10 * sequences - 1 : 0);
            size.splits[0] = size.splits[1] = sequences > 1;
        }
        break;
    case YX_NFA_CONCAT: case YX_NFA_ALT:
        for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
            yx_regex_vm_size child = yx_regex_vm_thompson(l->node);
            for (unsigned i = 0; i < 2; ++i) {
                size.bytes[i] = yx_regex_pike_size_add(size.bytes[i], child.bytes[i]);
                size.splits[i] = yx_regex_pike_size_add(size.splits[i], child.splits[i]);
            }
        }
        if (node->kind == YX_NFA_ALT) for (unsigned i = 0; i < 2; ++i) {
            size.bytes[i] = yx_regex_pike_size_add(size.bytes[i], 10 * node->count - 1);
            size.splits[i] = yx_regex_pike_size_add(size.splits[i], 1);
        }
        break;
    case YX_NFA_REPEAT: {
        yx_regex_vm_size child = yx_regex_vm_thompson(node->child);
        for (unsigned parent = 0; parent < 2; ++parent) {
            bool loop = !node->unbounded && node->upper > 10 && !parent;
            size_t copies = node->unbounded ? (node->lower ? node->lower : 1) :
                            loop ? (node->lower ? 2 : 1) : node->upper;
            size_t overhead = node->unbounded ? (node->lower ? 8 : 14) :
                loop ? (node->lower <= 1 ? 22 : 14) :
                yx_regex_pike_size_mul(8, node->upper - node->lower);
            size_t splits = node->unbounded ? 1 : loop ? node->lower <= 1 :
                            node->upper - node->lower;
            size.bytes[parent] = yx_regex_pike_size_add(
                yx_regex_pike_size_mul(child.bytes[loop ? 1 : 0], copies), overhead);
            size.splits[parent] = yx_regex_pike_size_add(
                yx_regex_pike_size_mul(child.splits[loop ? 1 : 0], copies), splits);
        }
        break;
    }
    }
    return size;
}

/* Atom quality also decides whether FastVM is used. Masked pieces try
 * windows of 1..4 bytes; literal pieces try four bytes (or their short tail).
 * Only the first 32768 bytes are searched (atoms/quality.rs:399-463). */
typedef struct {
    size_t run, payload, atom, scanned;
    unsigned char bytes[4], masks[4];
    int best[4], quality;
    bool best_valid[4], has_piece;
    bool masked, incompatible, large;
} yx_regex_fast_size;

static int yx_regex_fast_window(const yx_regex_fast_size *p, size_t width)
{
    int quality = 0;
    unsigned unique = 0;
    unsigned char first = p->bytes[(p->scanned - width) % 4];
    for (size_t i = 0; i < width; ++i) {
        size_t at = (p->scanned - width + i) % 4;
        unsigned char byte = p->bytes[at], mask = p->masks[at];
        if (mask != 255) {
            unsigned ones = 0;
            for (unsigned m = mask; m; m >>= 1) ones += m & 1;
            quality += !mask ? -13 : (int)(3 * ones) - 8;
        } else {
            quality += !byte ? 6 : byte == 0x20 || byte == 0x90 ||
                byte == 0xcc || byte == 0xff ? 12 :
                (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ? 18 : 20;
            bool seen = false;
            for (size_t j = 0; j < i; ++j) {
                size_t prior = (p->scanned - width + j) % 4;
                if (p->masks[prior] == 255 && p->bytes[prior] == byte) seen = true;
            }
            if (!seen) ++unique;
        }
    }
    if (unique == 1)
        quality += !first || first == 0x20 || first == 0x90 ||
            first == 0xcc || first == 0xff ? -5 : 2;
    else quality += 2 * (int)unique;
    return quality;
}

static void yx_regex_fast_feed(yx_regex_fast_size *p, unsigned char byte,
                                unsigned char mask)
{
    p->run = yx_regex_pike_size_add(p->run, 1);
    p->masked |= mask != 255;
    if (p->scanned == 32768) return;
    p->bytes[p->scanned % 4] = byte;
    p->masks[p->scanned % 4] = mask;
    ++p->scanned;
    for (size_t width = 1; width <= 4 && width <= p->scanned; ++width) {
        int quality = yx_regex_fast_window(p, width);
        if (!p->best_valid[width - 1] || quality > p->best[width - 1]) {
            p->best[width - 1] = quality;
            p->best_valid[width - 1] = true;
        }
    }
}

static void yx_regex_fast_atom(const yx_regex_fast_size *p, int *quality,
                                size_t *length)
{
    *quality = INT_MIN; *length = 0;
    if (!p->scanned) return;
    if (!p->masked) {
        *length = p->scanned < 4 ? p->scanned : 4;
        *quality = p->scanned < 4 ? yx_regex_fast_window(p, p->scanned) : p->best[3];
        return;
    }
    for (size_t width = 1; width <= 4; ++width) {
        size_t actual = p->scanned < width ? p->scanned : width;
        int q = p->best_valid[width - 1] ? p->best[width - 1] :
            yx_regex_fast_window(p, p->scanned);
        if (q > *quality || (q == *quality && actual < *length)) {
            *quality = q; *length = actual;
        }
    }
}

static void yx_regex_fast_choose(yx_regex_fast_size *p, int quality, size_t atom)
{
    if (!p->has_piece || quality > p->quality) {
        p->has_piece = true; p->quality = quality; p->atom = atom;
    }
}

static void yx_regex_fast_finish(yx_regex_fast_size *p, bool alternative)
{
    if (p->run > UINT16_MAX) p->large = true;
    int quality; size_t atom;
    yx_regex_fast_atom(p, &quality, &atom);
    if (alternative) {
        p->payload = yx_regex_pike_size_add(p->payload,
            yx_regex_pike_size_add(3, yx_regex_pike_size_mul(p->run, p->masked ? 2 : 1)));
        if (!p->has_piece || quality < p->quality) p->quality = quality;
        if (!p->has_piece || atom < p->atom) p->atom = atom;
        p->has_piece = true;
    } else if (p->run) yx_regex_fast_choose(p, quality, atom);
    p->run = p->scanned = 0; p->masked = false;
    memset(p->best_valid, 0, sizeof(p->best_valid));
}

static void yx_regex_fast_visit(yx_regex_fast_size *p,
                                 const yx_regex_nfa_node *node, bool in_alt)
{
    if (!node || p->incompatible) return;
    switch (node->kind) {
    case YX_NFA_EMPTY: break;
    case YX_NFA_LITERAL:
        for (size_t i = 0; i < node->count; ++i) yx_regex_fast_feed(p, node->bytes[i], 255);
        break;
    case YX_NFA_CAPTURE: yx_regex_fast_visit(p, node->child, in_alt); break;
    case YX_NFA_CONCAT:
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            yx_regex_fast_visit(p, l->node, in_alt);
        break;
    case YX_NFA_LOOK: p->incompatible = true; break;
    case YX_NFA_REPEAT:
        if (in_alt || (!yx_regex_vm_any(node->child, true) &&
                       !yx_regex_vm_any(node->child, false))) {
            p->incompatible = true; break;
        }
        if (!node->unbounded && node->lower == node->upper && node->upper <= 8 &&
            yx_regex_vm_any(node->child, true)) {
            for (size_t i = 0; i < node->upper; ++i) yx_regex_fast_feed(p, 0, 0);
        } else yx_regex_fast_finish(p, false);
        break;
    case YX_NFA_CLASS:
        if (yx_regex_vm_mask(node)) {
            uint32_t first = node->ranges[0].first;
            uint32_t last = node->ranges[node->count - 1].last;
            yx_regex_fast_feed(p, (unsigned char)first, (unsigned char)~(first ^ last));
        } else if (!in_alt && !node->unicode && node->count) {
            yx_regex_fast_finish(p, false);
            yx_regex_fast_size alternatives = {0};
            for (size_t i = 0; i < node->count; ++i) {
                uint32_t first = node->ranges[i].first, last = node->ranges[i].last;
                uint32_t bits = first ^ last, combinations = 1;
                for (; bits; bits >>= 1) if (bits & 1) combinations *= 2;
                if ((first & last) != first || combinations != last - first + 1) {
                    p->incompatible = true; break;
                }
                yx_regex_fast_feed(&alternatives, (unsigned char)first,
                    (unsigned char)~(first ^ last));
                yx_regex_fast_finish(&alternatives, true);
            }
            if (!p->incompatible) {
                p->large |= alternatives.large || alternatives.payload > UINT16_MAX;
                yx_regex_fast_choose(p, alternatives.quality, alternatives.atom);
            }
        } else p->incompatible = true;
        break;
    case YX_NFA_ALT: {
        if (in_alt) { p->incompatible = true; break; }
        yx_regex_fast_finish(p, false);
        yx_regex_fast_size alternatives = {0};
        for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
            yx_regex_fast_visit(&alternatives, l->node, true);
            yx_regex_fast_finish(&alternatives, true);
        }
        p->incompatible |= alternatives.incompatible;
        p->large |= alternatives.large || alternatives.payload > UINT16_MAX;
        yx_regex_fast_choose(p, alternatives.quality, alternatives.atom);
        break;
    }
    }
}

static bool yx_regex_vm_literal_alternation(const yx_regex_nfa_node *node)
{
    if (!node) return false;
    if (node->kind == YX_NFA_CAPTURE) node = node->child;
    if (!node) return false;
    if (node->kind == YX_NFA_LITERAL) return true;
    if (node->kind != YX_NFA_ALT) return false;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next)
        if (!l->node->literal) return false;
    return true;
}

static bool yx_regex_vm_mask_literal(const yx_regex_nfa_node *node)
{
    if (!node) return false;
    switch (node->kind) {
    case YX_NFA_LITERAL: return true;
    case YX_NFA_CAPTURE: return yx_regex_vm_mask_literal(node->child);
    case YX_NFA_CLASS: return yx_regex_vm_mask(node);
    case YX_NFA_REPEAT:
        return !node->unbounded && node->upper == node->lower && node->lower <= 200 &&
               yx_regex_vm_any(node->child, true);
    case YX_NFA_CONCAT:
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            if (!yx_regex_vm_mask_literal(l->node)) return false;
        return true;
    default: return false;
    }
}

static bool yx_regex_vm_too_many(const yx_regex_nfa_node *node)
{
    if (!node) return false;
    if (node->kind == YX_NFA_ALT && node->count > 255) return true;
    if (node->kind == YX_NFA_CAPTURE || node->kind == YX_NFA_REPEAT)
        return yx_regex_vm_too_many(node->child);
    if (node->kind == YX_NFA_CONCAT || node->kind == YX_NFA_ALT)
        for (yx_regex_nfa_link *l = node->first; l; l = l->next)
            if (yx_regex_vm_too_many(l->node)) return true;
    return false;
}

static bool yx_regex_vm_piece_large(const yx_regex_nfa_node *node, unsigned modifiers,
                                       const char **label)
{
    if (yx_regex_vm_literal_alternation(node) ||
        (!(modifiers & (YX_MOD_NOCASE | YX_MOD_WIDE)) && yx_regex_vm_mask_literal(node)))
        return false;
    if (yx_regex_vm_too_many(node)) {
        *label = "too many alternatives in alternation (max: 255)";
        return true;
    }
    yx_regex_fast_size fast = {0};
    yx_regex_fast_visit(&fast, node, false);
    yx_regex_fast_finish(&fast, false);
    if (!fast.incompatible) {
        if (fast.large) { *label = "regexp is too large"; return true; }
        if (fast.atom >= 2) return false;
    }
    yx_regex_vm_size size = yx_regex_vm_thompson(node);
    bool large = yx_regex_pike_size_add(size.bytes[0], 2) > YX_REGEX_PIKE_SIZE_LIMIT ||
                 size.splits[0] > 8191;
    if (large) *label = "regexp is too large";
    return large;
}

static bool yx_regex_vm_size_large(yx_regex_nfa_arena *arena,
                                    const yx_regex_nfa_node *node, unsigned modifiers,
                                    const char **label)
{
    if (!node || node->kind != YX_NFA_CONCAT)
        return yx_regex_vm_piece_large(node, modifiers, label);
    /* HIR::split_at_large_gaps only splits a top-level concatenation, and
     * requires at least two bytes on both sides of a removed gap. */
    yx_regex_nfa_node *chunks = yx_regex_nfa_new(arena, YX_NFA_CONCAT);
    yx_regex_nfa_node *pieces = yx_regex_nfa_new(arena, YX_NFA_ALT);
    yx_regex_nfa_node *last_gap = NULL;
    for (yx_regex_nfa_link *l = node->first; l; l = l->next) {
        yx_regex_nfa_node *item = l->node;
        if (item->kind == YX_NFA_REPEAT &&
            (item->unbounded || item->upper > 200) && yx_regex_vm_any(item->child, true)) {
            yx_regex_nfa_node *head = yx_regex_nfa_list_finish(arena, chunks);
            if (yx_regex_vm_minimum(head) >= 2) {
                yx_regex_nfa_link *link = yx_regex_nfa_alloc(arena, sizeof(*link));
                if (!link) return false;
                link->node = head;
                if (pieces->last) pieces->last->next = link; else pieces->first = link;
                pieces->last = link; ++pieces->count;
                chunks = yx_regex_nfa_new(arena, YX_NFA_CONCAT);
                last_gap = item;
                continue;
            }
        }
        yx_regex_nfa_append(arena, chunks, item);
    }
    yx_regex_nfa_node *tail = yx_regex_nfa_list_finish(arena, chunks);
    if (!pieces->count) return yx_regex_vm_piece_large(node, modifiers, label);
    if (tail && tail->kind == YX_NFA_EMPTY) {
        /* A trailing arbitrary gap is discarded by HIR chaining. */
    } else if (yx_regex_vm_minimum(tail) < 2) {
        yx_regex_nfa_node *merged = yx_regex_nfa_new(arena, YX_NFA_CONCAT);
        yx_regex_nfa_append(arena, merged, pieces->last->node);
        if (last_gap) yx_regex_nfa_append(arena, merged, last_gap);
        yx_regex_nfa_append(arena, merged, tail);
        pieces->last->node = yx_regex_nfa_list_finish(arena, merged);
    } else if (yx_regex_vm_piece_large(tail, modifiers, label)) return true;
    for (yx_regex_nfa_link *l = pieces->first; l; l = l->next)
        if (yx_regex_vm_piece_large(l->node, modifiers, label)) return true;
    return false;
}
