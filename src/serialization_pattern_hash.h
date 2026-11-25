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

/* Upstream (lib/src/compiler/mod.rs, Compiler::build) inserts the filesize
 * bounds and header constraints of its FxHashMaps in the iteration order of
 * `patterns: FxHashMap<Pattern, PatternId>`. That order follows the
 * derive(Hash) of ir::Pattern under rustc-hash 2.1's FxHasher, with the HIR
 * hashed by re::hir::HirHasher (a pre-order walk of regex-syntax 0.8 kinds),
 * in a hashbrown table (SSE2 groups) grown from empty. Included after the
 * Thompson HIR builder. */
#ifndef XXYARA_SERIALIZATION_PATTERN_HASH_H
#define XXYARA_SERIALIZATION_PATTERN_HASH_H

typedef struct yx_fxh {
    uint64_t hash;
} yx_fxh;

static void yx_fxh_add(yx_fxh *h, uint64_t value)
{
    h->hash = (h->hash + value) * UINT64_C(0xf1357aea2e62a9c5);
}
static uint64_t yx_fxh_finish(const yx_fxh *h)
{
    return h->hash << 26 | h->hash >> 38;
}
/* The low and high halves of the 128-bit product, XOR-ed (multiply_mix). */
static uint64_t yx_fxh_mix(uint64_t x, uint64_t y)
{
    uint64_t a = x & 0xffffffffu, b = x >> 32, c = y & 0xffffffffu, d = y >> 32;
    uint64_t ac = a * c, ad = a * d, bc = b * c, bd = b * d;
    uint64_t middle = (ac >> 32) + (ad & 0xffffffffu) + (bc & 0xffffffffu);
    uint64_t low = (ac & 0xffffffffu) | middle << 32;
    uint64_t high = bd + (ad >> 32) + (bc >> 32) + (middle >> 32);
    return low ^ high;
}
static uint64_t yx_fxh_le(const uint8_t *bytes, size_t width)
{
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}
/* rustc-hash 2.1 hash_bytes. */
static uint64_t yx_fxh_bytes(const uint8_t *bytes, size_t length)
{
    uint64_t s0 = UINT64_C(0x243f6a8885a308d3), s1 = UINT64_C(0x13198a2e03707344);
    if (length <= 16) {
        if (length >= 8) {
            s0 ^= yx_fxh_le(bytes, 8);
            s1 ^= yx_fxh_le(bytes + length - 8, 8);
        } else if (length >= 4) {
            s0 ^= yx_fxh_le(bytes, 4);
            s1 ^= yx_fxh_le(bytes + length - 4, 4);
        } else if (length) {
            s0 ^= bytes[0];
            s1 ^= (uint64_t)bytes[length - 1] << 8 | bytes[length / 2];
        }
    } else {
        for (size_t at = 0; at < length - 16; at += 16) {
            uint64_t x = yx_fxh_le(bytes + at, 8), y = yx_fxh_le(bytes + at + 8, 8);
            uint64_t t = yx_fxh_mix(s0 ^ x, UINT64_C(0xa4093822299f31d0) ^ y);
            s0 = s1;
            s1 = t;
        }
        s0 ^= yx_fxh_le(bytes + length - 16, 8);
        s1 ^= yx_fxh_le(bytes + length - 8, 8);
    }
    return yx_fxh_mix(s0, s1) ^ (uint64_t)length;
}
/* Hasher::write, then the [u8]/Vec<u8>/BString hash (length prefix) and the
 * str hash (0xff terminator). */
static void yx_fxh_write(yx_fxh *h, const uint8_t *bytes, size_t length)
{
    yx_fxh_add(h, yx_fxh_bytes(bytes, length));
}
static void yx_fxh_slice(yx_fxh *h, const uint8_t *bytes, size_t length)
{
    yx_fxh_add(h, length);
    yx_fxh_write(h, bytes, length);
}
static void yx_fxh_str(yx_fxh *h, const char *text)
{
    yx_fxh_write(h, (const uint8_t *)text, strlen(text));
    yx_fxh_add(h, 0xff);
}

/* HirHasher over the regex-syntax shaped Thompson HIR. */
static bool yx_fxh_hir(yx_fxh *h, const yx_tr_node *n, unsigned depth)
{
    /* HirKind: Empty, Literal, Class, Look, Repetition, Capture, Concat, Alternation. */
    static const uint8_t kinds[] = {0, 1, 2, 3, 6, 7, 4, 5, 2};
    if (!n || depth > 1024 || (unsigned)n->kind >= sizeof(kinds)) return false;
    yx_fxh_add(h, kinds[n->kind]);
    if (n->kind == YX_TR_LITERAL) yx_fxh_slice(h, n->bytes, n->length);
    else if (n->kind == YX_TR_CLASS) {
        yx_fxh_add(h, n->unicode_class ? 0 : 1);
        for (unsigned b = 0; b < 256; ++b) {
            if (!yx_tr_has(n->bitmap, b)) continue;
            unsigned first = b;
            while (b + 1 < 256 && yx_tr_has(n->bitmap, b + 1)) ++b;
            yx_fxh_add(h, first);
            yx_fxh_add(h, b);
        }
    } else if (n->kind == YX_TR_SCALAR_CLASS) {
        const yx_re_range *ranges = (const yx_re_range *)n->bytes;
        yx_fxh_add(h, 0);
        for (size_t i = 0; i < n->length; ++i) {
            /* A range of chars across the surrogate gap is one range. */
            yx_fxh_add(h, ranges[i].first);
            if (yx_u8_joins(n, ranges, n->length, i)) ++i;
            yx_fxh_add(h, ranges[i].last);
        }
    } else if (n->kind == YX_TR_REPEAT) {
        yx_fxh_add(h, n->minimum);
        if (yx_tr_unbounded(n)) yx_fxh_add(h, 0);
        else {
            yx_fxh_add(h, 1);
            yx_fxh_add(h, n->maximum);
        }
        yx_fxh_add(h, n->greedy);
    }
    for (size_t i = 0; i < n->count; ++i)
        if (!yx_fxh_hir(h, n->children[i], depth + 1)) return false;
    return true;
}

/* A signature of a regexp pattern's HIR alone (0 when the HIR is not modeled). */
static uint64_t yx_pattern_hir_signature(const YRX_PATTERN *p)
{
    yx_fxh h = {0};
    if (!p->regexp) return 0;
    yx_tr_parser parser = {
        .text = (const uint8_t *)p->regexp, .length = strlen(p->regexp), .dotall = (p->modifiers & YX_MOD_DOTALL) != 0, .nocase = (p->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&parser);
    bool ok = root && !parser.failed && !parser.oom && parser.at == parser.length && yx_fxh_hir(&h, root, 0);
    yx_tr_destroy(root);
    return ok ? yx_fxh_finish(&h) | 1 : 0;
}

/* The per-rule values upstream stores in a Pattern before it is interned. */
typedef struct yx_pattern_hash_state {
    bool anchored, non_anchorable;
    uint64_t offset;
    uint8_t lower_kind, upper_kind; /* 0 included, 1 excluded, 2 unbounded */
    int64_t lower, upper;
    uint8_t header_kind; /* 0 unconstrained, 1 unsatisfiable, 2 constrained */
    const uint8_t *header;
    size_t header_length;
    uint64_t limit; /* 0: no fast-scan limit (None) */
} yx_pattern_hash_state;

static void yx_fxh_bound(yx_fxh *h, uint8_t kind, int64_t value)
{
    yx_fxh_add(h, kind);
    if (kind < 2) yx_fxh_add(h, (uint64_t)value);
}
/* derive(Hash) for ir::Pattern. False when the pattern's HIR is not modeled. */
static bool yx_pattern_fx_hash(const YRX_PATTERN *p, const yx_pattern_hash_state *s, uint64_t *out)
{
    yx_fxh h = {0};
    uint16_t flags = 0;
    bool text = p->kind == YX_PATTERN_TEXT, regex = p->kind == YX_PATTERN_REGEX;
    if (!text && !regex && p->kind != YX_PATTERN_HEX) return false;
    if (!(p->kind == YX_PATTERN_HEX)) {
        if (p->modifiers & YX_MOD_WIDE) flags |= p->modifiers & YX_MOD_ASCII ? 0x02 : 0x01;
        if (p->modifiers & YX_MOD_NOCASE) flags |= 0x04;
        if (p->modifiers & YX_MOD_FULLWORD) flags |= 0x40;
    }
    if (text) {
        if (p->modifiers & YX_MOD_BASE64) flags |= 0x08;
        if (p->modifiers & YX_MOD_BASE64WIDE) flags |= 0x10;
        if (p->modifiers & YX_MOD_XOR) flags |= 0x20;
    }
    if (p->modifiers & YX_MOD_PRIVATE) flags |= 0x80;
    if (s->non_anchorable) flags |= 0x100;
    yx_fxh_add(&h, text ? 0 : regex ? 1 : 2);
    yx_fxh_add(&h, flags);
    if (text) yx_fxh_slice(&h, p->bytes, p->length);
    else {
        yx_writer hex_text = {0};
        const char *regexp = p->regexp;
        if (!regex) {
            if (!p->hex_atoms || !yx_tr_hex_regex(&hex_text, p->hex_atoms, p->hex_atom_count, 0) || !yx_put_u8(&hex_text, 0)) {
                free(hex_text.data);
                return false;
            }
            regexp = (const char *)hex_text.data;
        }
        if (!regexp) return false;
        yx_tr_parser parser = {.text = (const uint8_t *)regexp,
                               .length = strlen(regexp),
                               .dotall = regex ? (p->modifiers & YX_MOD_DOTALL) != 0 : true,
                               .nocase = regex && (p->modifiers & YX_MOD_NOCASE) != 0};
        yx_tr_node *root = yx_tr_expression(&parser);
        bool ok = root && !parser.failed && !parser.oom && parser.at == parser.length && yx_fxh_hir(&h, root, 0);
        yx_tr_destroy(root);
        free(hex_text.data);
        if (!ok) return false;
    }
    yx_fxh_add(&h, s->anchored);
    if (s->anchored) yx_fxh_add(&h, s->offset);
    if (text) {
        yx_fxh_add(&h, (p->modifiers & YX_MOD_XOR) != 0);
        if (p->modifiers & YX_MOD_XOR) {
            yx_fxh_add(&h, p->xor_min);
            yx_fxh_add(&h, p->xor_max);
            yx_fxh_add(&h, 0);
        }
        yx_fxh_add(&h, p->base64_alphabet != NULL);
        if (p->base64_alphabet) yx_fxh_str(&h, p->base64_alphabet);
        yx_fxh_add(&h, p->base64wide_alphabet != NULL);
        if (p->base64wide_alphabet) yx_fxh_str(&h, p->base64wide_alphabet);
    }
    yx_fxh_bound(&h, s->lower_kind, s->lower);
    yx_fxh_bound(&h, s->upper_kind, s->upper);
    yx_fxh_add(&h, s->header_kind);
    if (s->header_kind == 2) yx_fxh_slice(&h, s->header, s->header_length);
    yx_fxh_add(&h, s->limit != 0);
    if (s->limit) yx_fxh_add(&h, s->limit);
    *out = yx_fxh_finish(&h);
    return true;
}

/* Bucket order of a hashbrown table built by inserting items 0..count-1 in
 * that sequence (group width 16, growth from an empty table). */
static void yx_fx_table_place(size_t *slots, size_t buckets, const uint64_t *hashes, size_t item)
{
    size_t pos = (size_t)hashes[item] & (buckets - 1), stride = 0;
    for (;;) {
        for (size_t i = 0; i < (buckets < 16 ? buckets : 16); ++i) {
            size_t at = (pos + i) & (buckets - 1);
            if (slots[at] == SIZE_MAX) {
                slots[at] = item;
                return;
            }
        }
        stride += 16;
        pos = (pos + stride) & (buckets - 1);
    }
}
static bool yx_fx_table_order(const uint64_t *hashes, size_t count, size_t *order)
{
    size_t buckets = 0, *slots = NULL, used = 0;
    for (size_t item = 0; item < count; ++item) {
        size_t capacity = buckets < 8 ? (buckets ? buckets - 1 : 0) : buckets / 8 * 7;
        if (item + 1 > capacity) {
            size_t wanted = item + 1, next;
            if (buckets && capacity + 1 > wanted) wanted = capacity + 1;
            if (wanted < 4) next = 4;
            else if (wanted < 8) next = 8;
            else {
                next = 1;
                while (next < wanted * 8 / 7) {
                    if (next > SIZE_MAX / 2 / sizeof(*slots)) {
                        free(slots);
                        return false;
                    }
                    next <<= 1;
                }
            }
            size_t *grown = malloc(next * sizeof(*grown));
            if (!grown) {
                free(slots);
                return false;
            }
            for (size_t i = 0; i < next; ++i) grown[i] = SIZE_MAX;
            for (size_t i = 0; i < buckets; ++i)
                if (slots[i] != SIZE_MAX) yx_fx_table_place(grown, next, hashes, slots[i]);
            free(slots);
            slots = grown;
            buckets = next;
        }
        yx_fx_table_place(slots, buckets, hashes, item);
    }
    for (size_t i = 0; i < buckets; ++i)
        if (slots[i] != SIZE_MAX) order[used++] = slots[i];
    free(slots);
    return used == count;
}

#endif
