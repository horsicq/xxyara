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

/*
 * The FastVM instruction encoding, pattern splitting and atom quality rules
 * follow lib/src/re/fast and lib/src/compiler/atoms in YARA-X v1.21.0.
 *
 * Copyright (c) 2024. The YARA-X Authors. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef YX_SERIALIZATION_FAST_H
#define YX_SERIALIZATION_FAST_H

/* Native FastVM compiler: split pattern pieces, select independently scored
 * masked atoms, and emit forward/backward verifier instructions. */

#define YX_FAST_MAX_ATOMS 16384

typedef struct yx_fast_literal { uint8_t *bytes, *mask; size_t length; bool force_masked; } yx_fast_literal;
typedef struct yx_fast_piece {
    uint8_t kind; /* 1 literal, 3 fixed jump, 4 ranged jump, 7 flat alternatives */
    bool newline, unbounded;
    uint32_t minimum, maximum;
    yx_fast_literal *alternatives;
    size_t alternative_count;
} yx_fast_piece;
typedef struct yx_fast_program {
    yx_fast_piece *pieces;
    size_t count, capacity;
    yx_writer bytes, mask;
    yx_archive_regexp_atom *atoms;
    size_t atom_count;
    yx_writer code;
    uint16_t flags;
    bool nocase, force_regexp, encoded_counts;
    /* Allocated length of atoms; the vector grows up to YX_FAST_MAX_ATOMS. */
    size_t atom_capacity;
} yx_fast_program;
/* A zeroed atom vector for up to YX_FAST_MAX_ATOMS atoms, as the former
 * calloc of the whole bound, but grown on demand: zeroing that bound for
 * every pattern dominated hex and regexp compiles. Callers start from an
 * empty vector; atoms past atom_count are never read. */
static bool yx_fast_atoms_start(yx_fast_program *p)
{
    size_t capacity = p->atom_count > 16 ? p->atom_count : 16;
    p->atoms = calloc(capacity, sizeof(*p->atoms));
    p->atom_capacity = p->atoms ? capacity : 0;
    return p->atoms != NULL;
}
static bool yx_fast_atoms_push(yx_fast_program *p, const yx_archive_regexp_atom *atom)
{
    if (p->atom_count == YX_FAST_MAX_ATOMS) return false;
    if (p->atom_count >= p->atom_capacity) {
        size_t next = p->atom_capacity ? p->atom_capacity * 2 : 16;
        if (next > YX_FAST_MAX_ATOMS) next = YX_FAST_MAX_ATOMS;
        if (next <= p->atom_count) next = p->atom_count + 1;
        yx_archive_regexp_atom *grown = realloc(p->atoms, next * sizeof(*grown));
        if (!grown) return false;
        memset(grown + p->atom_count, 0, (next - p->atom_count) * sizeof(*grown));
        p->atoms = grown;
        p->atom_capacity = next;
    }
    p->atoms[p->atom_count++] = *atom;
    return true;
}

static void yx_fast_literal_destroy(yx_fast_literal *literal)
{ free(literal->bytes); free(literal->mask); memset(literal, 0, sizeof(*literal)); }
static void yx_fast_program_destroy(yx_fast_program *p)
{
    for (size_t i = 0; i < p->count; ++i) {
        for (size_t j = 0; j < p->pieces[i].alternative_count; ++j) yx_fast_literal_destroy(&p->pieces[i].alternatives[j]);
        free(p->pieces[i].alternatives);
    }
    free(p->pieces); free(p->bytes.data); free(p->mask.data); free(p->atoms); free(p->code.data); free(p);
}
/* Match upstream's growable piece vector instead of limiting hex patterns
 * to 255 jumps. Decoding is additionally bounded by the input code length. */
static bool yx_fast_piece_reserve(yx_fast_program *p)
{
    if (p->count < p->capacity) return true;
    size_t capacity = p->capacity ? p->capacity * 2 : 16;
    if (capacity < p->capacity || capacity > SIZE_MAX / sizeof(*p->pieces)) return false;
    yx_fast_piece *pieces = realloc(p->pieces, capacity * sizeof(*pieces));
    if (!pieces) return false;
    memset(pieces + p->capacity, 0, (capacity - p->capacity) * sizeof(*pieces));
    p->pieces = pieces; p->capacity = capacity; return true;
}
static bool yx_fast_flush(yx_fast_program *p)
{
    if (!p->bytes.used) return true;
    if (!yx_fast_piece_reserve(p) || p->bytes.used > UINT16_MAX) return false;
    yx_fast_piece *piece = &p->pieces[p->count++];
    piece->kind = 1; piece->alternatives = calloc(1, sizeof(*piece->alternatives));
    if (!piece->alternatives) return false;
    piece->alternative_count = 1;
    piece->alternatives[0] = (yx_fast_literal){p->bytes.data,p->mask.data,p->bytes.used,false};
    p->bytes = (yx_writer){0}; p->mask = (yx_writer){0}; return true;
}
static bool yx_fast_append(yx_fast_program *p, uint8_t value, uint8_t mask)
{
    return p->bytes.used < UINT16_MAX && yx_put_u8(&p->bytes, value & mask) && yx_put_u8(&p->mask, mask);
}
static bool yx_fast_jump(yx_fast_program *p, uint32_t minimum, uint32_t maximum, bool newline, bool unbounded)
{
    if (!unbounded && minimum > maximum) return false;
    if (!unbounded && minimum == maximum && maximum <= 8 && newline) {
        for (uint32_t i = 0; i < minimum; ++i) if (!yx_fast_append(p, 0, 0)) return false;
        return true;
    }
    if (!yx_fast_flush(p) || !yx_fast_piece_reserve(p)) return false;
    yx_fast_piece *piece = &p->pieces[p->count++];
    piece->kind = !unbounded && minimum == maximum ? 3 : 4; piece->newline = newline;
    piece->minimum = minimum; piece->maximum = maximum; piece->unbounded = unbounded;
    return true;
}
static bool yx_fast_class(yx_fast_program *p, const bool members[256]);
/* Hex patterns reach FastVM as regex-syntax HIR. Its smart constructors
 * merge adjacent literals, collapse an alternation of single characters,
 * single bytes or classes into one class, and lift common prefixes. The
 * FastVM splitter then walks the simplified tree. Because `DF 85` is one
 * UTF-8 character, `( 1B | DF 85 )` becomes a Unicode class, which FastVM
 * rejects before emitting code, while `( E8 | FF 15 )` stays an alternation. */
typedef enum { YX_HH_EMPTY, YX_HH_LITERAL, YX_HH_CLASS, YX_HH_UCLASS, YX_HH_REPEAT, YX_HH_CONCAT, YX_HH_ALT } yx_hh_kind;
typedef struct yx_hh {
    yx_hh_kind kind;
    uint8_t *bytes; size_t length;      /* literal bytes */
    uint8_t bitmap[32];                 /* byte class */
    uint32_t *chars; size_t char_count; /* sorted code points of a Unicode class */
    uint32_t minimum, maximum; bool unbounded; /* repetition of any byte */
    struct yx_hh **subs; size_t count;
} yx_hh;
static void yx_hh_free(yx_hh *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->count; ++i) yx_hh_free(h->subs[i]);
    free(h->subs); free(h->bytes); free(h->chars); free(h);
}
static void yx_hh_free_all(yx_hh **subs, size_t count)
{ for (size_t i = 0; i < count; ++i) yx_hh_free(subs[i]); free(subs); }
static yx_hh *yx_hh_new(yx_hh_kind kind)
{ yx_hh *h = calloc(1, sizeof(*h)); if (h) h->kind = kind; return h; }
static bool yx_hh_bit(const uint8_t bitmap[32], unsigned b) { return (bitmap[b >> 3] >> (b & 7)) & 1u; }
static bool yx_hh_equal(const yx_hh *a, const yx_hh *b)
{
    if (a->kind != b->kind || a->length != b->length || a->char_count != b->char_count || a->count != b->count ||
        a->minimum != b->minimum || a->maximum != b->maximum || a->unbounded != b->unbounded ||
        memcmp(a->bitmap, b->bitmap, sizeof(a->bitmap)) ||
        (a->length && memcmp(a->bytes, b->bytes, a->length)) ||
        (a->char_count && memcmp(a->chars, b->chars, a->char_count * sizeof(*a->chars)))) return false;
    for (size_t i = 0; i < a->count; ++i) if (!yx_hh_equal(a->subs[i], b->subs[i])) return false;
    return true;
}
static yx_hh *yx_hh_literal(const uint8_t *bytes, size_t length)
{
    yx_hh *h = yx_hh_new(length ? YX_HH_LITERAL : YX_HH_EMPTY);
    if (!h || !length) return h;
    h->bytes = malloc(length);
    if (!h->bytes) { free(h); return NULL; }
    memcpy(h->bytes, bytes, length); h->length = length; return h;
}
static size_t yx_hh_utf8(uint32_t ch, uint8_t out[4])
{
    if (ch < 0x80) { out[0] = (uint8_t)ch; return 1; }
    if (ch < 0x800) { out[0] = (uint8_t)(0xc0 | ch >> 6); out[1] = (uint8_t)(0x80 | (ch & 63)); return 2; }
    if (ch < 0x10000) {
        out[0] = (uint8_t)(0xe0 | ch >> 12); out[1] = (uint8_t)(0x80 | ((ch >> 6) & 63));
        out[2] = (uint8_t)(0x80 | (ch & 63)); return 3;
    }
    out[0] = (uint8_t)(0xf0 | ch >> 18); out[1] = (uint8_t)(0x80 | ((ch >> 12) & 63));
    out[2] = (uint8_t)(0x80 | ((ch >> 6) & 63)); out[3] = (uint8_t)(0x80 | (ch & 63)); return 4;
}
/* A literal that is exactly one valid UTF-8 scalar value. */
static bool yx_hh_single_char(const uint8_t *s, size_t n, uint32_t *ch)
{
    if (n == 1 && s[0] < 0x80) { *ch = s[0]; return true; }
    if (n == 2 && s[0] >= 0xc2 && s[0] <= 0xdf && (s[1] & 0xc0) == 0x80) {
        *ch = ((uint32_t)(s[0] & 31) << 6) | (s[1] & 63); return true;
    }
    if (n == 3 && (s[0] & 0xf0) == 0xe0 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80 &&
        (s[0] != 0xe0 || s[1] >= 0xa0) && (s[0] != 0xed || s[1] < 0xa0)) {
        *ch = ((uint32_t)(s[0] & 15) << 12) | ((uint32_t)(s[1] & 63) << 6) | (s[2] & 63); return true;
    }
    if (n == 4 && s[0] >= 0xf0 && s[0] <= 0xf4 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80 &&
        (s[3] & 0xc0) == 0x80 && (s[0] != 0xf0 || s[1] >= 0x90) && (s[0] != 0xf4 || s[1] < 0x90)) {
        *ch = ((uint32_t)(s[0] & 7) << 18) | ((uint32_t)(s[1] & 63) << 12) | ((uint32_t)(s[2] & 63) << 6) | (s[3] & 63);
        return true;
    }
    return false;
}
/* Hir::class: an empty class never occurs in hex patterns; a class of one
 * byte or one character is a literal. */
static yx_hh *yx_hh_class(const uint8_t bitmap[32])
{
    unsigned count = 0, last = 0;
    for (unsigned b = 0; b < 256; ++b) if (yx_hh_bit(bitmap, b)) { ++count; last = b; }
    if (!count) return NULL;
    if (count == 1) { uint8_t byte = (uint8_t)last; return yx_hh_literal(&byte, 1); }
    yx_hh *h = yx_hh_new(YX_HH_CLASS);
    if (h) memcpy(h->bitmap, bitmap, 32);
    return h;
}
static int yx_hh_char_cmp(const void *a, const void *b)
{ uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b; return x < y ? -1 : x > y; }
static yx_hh *yx_hh_uclass(uint32_t *chars, size_t count)
{
    qsort(chars, count, sizeof(*chars), yx_hh_char_cmp);
    size_t unique = 0;
    for (size_t i = 0; i < count; ++i) if (!unique || chars[unique - 1] != chars[i]) chars[unique++] = chars[i];
    if (unique == 1) {
        uint8_t utf8[4]; size_t n = yx_hh_utf8(chars[0], utf8); free(chars);
        return yx_hh_literal(utf8, n);
    }
    yx_hh *h = yx_hh_new(YX_HH_UCLASS);
    if (!h) { free(chars); return NULL; }
    h->chars = chars; h->char_count = unique; return h;
}
/* Hir::concat: flatten nested concatenations, merge adjacent literals and
 * drop empty expressions. Takes ownership of subs. */
static yx_hh *yx_hh_concat(yx_hh **subs, size_t count)
{
    yx_hh *h = yx_hh_new(YX_HH_CONCAT);
    yx_writer literal = {0};
    bool ok = h != NULL;
    yx_hh **items = NULL; size_t used = 0, capacity = 0;
    for (size_t i = 0; ok && i < count; ++i) {
        yx_hh *sub = subs[i]; subs[i] = NULL;
        yx_hh **parts = &sub; size_t part_count = 1;
        if (sub->kind == YX_HH_CONCAT) { parts = sub->subs; part_count = sub->count; }
        for (size_t j = 0; ok && j < part_count; ++j) {
            yx_hh *part = parts[j];
            if (part->kind == YX_HH_LITERAL) { ok = yx_put_bytes(&literal, part->bytes, part->length); continue; }
            if (part->kind == YX_HH_EMPTY) continue;
            if (literal.used) {
                yx_hh *merged = yx_hh_literal(literal.data, literal.used); literal.used = 0;
                if (!merged) { ok = false; break; }
                if (used == capacity) {
                    size_t next = capacity ? capacity * 2 : 4;
                    yx_hh **larger = realloc(items, next * sizeof(*larger));
                    if (!larger) { yx_hh_free(merged); ok = false; break; }
                    items = larger; capacity = next;
                }
                items[used++] = merged;
            }
            if (used == capacity) {
                size_t next = capacity ? capacity * 2 : 4;
                yx_hh **larger = realloc(items, next * sizeof(*larger));
                if (!larger) { ok = false; break; }
                items = larger; capacity = next;
            }
            items[used++] = part; parts[j] = NULL;
        }
        yx_hh_free(sub);
    }
    if (ok && literal.used) {
        yx_hh *merged = yx_hh_literal(literal.data, literal.used);
        if (!merged) ok = false;
        else if (used == capacity) {
            yx_hh **larger = realloc(items, (capacity + 1) * sizeof(*larger));
            if (!larger) { yx_hh_free(merged); ok = false; } else { items = larger; items[used++] = merged; }
        } else items[used++] = merged;
    }
    free(literal.data);
    for (size_t i = 0; i < count; ++i) yx_hh_free(subs[i]);
    free(subs);
    if (!ok) { yx_hh_free_all(items, used); yx_hh_free(h); return NULL; }
    if (!used) { free(items); h->kind = YX_HH_EMPTY; return h; }
    if (used == 1) { yx_hh *only = items[0]; free(items); yx_hh_free(h); return only; }
    h->subs = items; h->count = used; return h;
}
static yx_hh *yx_hh_alternation(yx_hh **subs, size_t count);
/* lift_common_prefix: every branch is a concatenation with a common prefix. */
static yx_hh *yx_hh_lift_prefix(yx_hh **subs, size_t count, bool *lifted)
{
    *lifted = false;
    if (count <= 1 || subs[0]->kind != YX_HH_CONCAT || !subs[0]->count) return NULL;
    size_t prefix = subs[0]->count;
    for (size_t i = 1; i < count; ++i) {
        if (subs[i]->kind != YX_HH_CONCAT) return NULL;
        size_t common = 0;
        while (common < prefix && common < subs[i]->count && yx_hh_equal(subs[0]->subs[common], subs[i]->subs[common]))
            ++common;
        prefix = common;
        if (!prefix) return NULL;
    }
    *lifted = true;
    yx_hh **suffixes = calloc(count, sizeof(*suffixes));
    yx_hh **head = calloc(prefix + 1, sizeof(*head));
    if (!suffixes || !head) { free(suffixes); free(head); yx_hh_free_all(subs, count); return NULL; }
    for (size_t i = 0; i < count; ++i) {
        yx_hh *branch = subs[i];
        size_t rest = branch->count - prefix;
        yx_hh **tail = calloc(rest ? rest : 1, sizeof(*tail));
        if (!tail) {
            for (size_t j = 0; j < i; ++j) yx_hh_free(suffixes[j]);
            free(suffixes); yx_hh_free_all(head, prefix + 1); yx_hh_free_all(subs, count); return NULL;
        }
        for (size_t j = 0; j < branch->count; ++j) {
            if (j >= prefix) tail[j - prefix] = branch->subs[j];
            else if (!i) head[j] = branch->subs[j];
            else yx_hh_free(branch->subs[j]);
            branch->subs[j] = NULL;
        }
        branch->count = 0; yx_hh_free(branch); subs[i] = NULL;
        suffixes[i] = yx_hh_concat(tail, rest);
        if (!suffixes[i]) {
            for (size_t j = 0; j < i; ++j) yx_hh_free(suffixes[j]);
            free(suffixes); yx_hh_free_all(head, prefix + 1); yx_hh_free_all(subs, count); return NULL;
        }
    }
    free(subs);
    head[prefix] = yx_hh_alternation(suffixes, count);
    if (!head[prefix]) { yx_hh_free_all(head, prefix + 1); return NULL; }
    return yx_hh_concat(head, prefix + 1);
}
/* Hir::alternation. Takes ownership of subs. */
static yx_hh *yx_hh_alternation(yx_hh **subs, size_t count)
{
    yx_hh **items = NULL; size_t used = 0;
    for (size_t i = 0; i < count; ++i) used += subs[i]->kind == YX_HH_ALT ? subs[i]->count : 1;
    items = calloc(used ? used : 1, sizeof(*items));
    if (!items) { yx_hh_free_all(subs, count); return NULL; }
    used = 0;
    for (size_t i = 0; i < count; ++i) {
        if (subs[i]->kind == YX_HH_ALT) {
            for (size_t j = 0; j < subs[i]->count; ++j) items[used++] = subs[i]->subs[j];
            subs[i]->count = 0; yx_hh_free(subs[i]);
        } else items[used++] = subs[i];
    }
    free(subs);
    if (used == 1) { yx_hh *only = items[0]; free(items); return only; }
    bool chars = true, bytes = true, uclasses = true, bclasses = true;
    for (size_t i = 0; i < used; ++i) {
        const yx_hh *h = items[i]; uint32_t ch;
        if (h->kind != YX_HH_LITERAL || !yx_hh_single_char(h->bytes, h->length, &ch)) chars = false;
        if (h->kind != YX_HH_LITERAL || h->length != 1) bytes = false;
        if (h->kind == YX_HH_CLASS) {
            for (unsigned b = 128; b < 256; ++b) if (yx_hh_bit(h->bitmap, b)) uclasses = false;
        } else if (h->kind == YX_HH_UCLASS) {
            if (h->chars[h->char_count - 1] >= 128) bclasses = false;
        } else uclasses = bclasses = false;
    }
    yx_hh *result = NULL;
    if (chars || uclasses) {
        size_t total = 0;
        for (size_t i = 0; i < used; ++i) {
            if (items[i]->kind == YX_HH_LITERAL || items[i]->kind == YX_HH_UCLASS)
                total += items[i]->kind == YX_HH_LITERAL ? 1 : items[i]->char_count;
            else for (unsigned b = 0; b < 128; ++b) total += yx_hh_bit(items[i]->bitmap, b);
        }
        uint32_t *set = malloc((total ? total : 1) * sizeof(*set));
        if (set) {
            size_t n = 0;
            for (size_t i = 0; i < used; ++i) {
                const yx_hh *h = items[i]; uint32_t ch;
                if (h->kind == YX_HH_LITERAL) { yx_hh_single_char(h->bytes, h->length, &ch); set[n++] = ch; }
                else if (h->kind == YX_HH_UCLASS) for (size_t j = 0; j < h->char_count; ++j) set[n++] = h->chars[j];
                else for (unsigned b = 0; b < 128; ++b) if (yx_hh_bit(h->bitmap, b)) set[n++] = b;
            }
            result = yx_hh_uclass(set, n);
        }
    } else if (bytes || bclasses) {
        uint8_t bitmap[32] = {0};
        for (size_t i = 0; i < used; ++i) {
            const yx_hh *h = items[i];
            if (h->kind == YX_HH_LITERAL) bitmap[h->bytes[0] >> 3] |= (uint8_t)(1u << (h->bytes[0] & 7));
            else if (h->kind == YX_HH_UCLASS)
                for (size_t j = 0; j < h->char_count; ++j) bitmap[h->chars[j] >> 3] |= (uint8_t)(1u << (h->chars[j] & 7));
            else for (size_t j = 0; j < 32; ++j) bitmap[j] |= h->bitmap[j];
        }
        result = yx_hh_class(bitmap);
    } else {
        bool lifted;
        result = yx_hh_lift_prefix(items, used, &lifted);
        if (lifted) return result;
        result = yx_hh_new(YX_HH_ALT);
        if (!result) { yx_hh_free_all(items, used); return NULL; }
        result->subs = items; result->count = used; return result;
    }
    yx_hh_free_all(items, used);
    return result;
}
static yx_hh *yx_hh_from_hex(const yx_hex_atom *atoms, size_t count, unsigned depth)
{
    if (depth > 64) return NULL;
    yx_hh **subs = calloc(count ? count : 1, sizeof(*subs));
    size_t used = 0;
    if (!subs) return NULL;
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_atom *atom = &atoms[i];
        yx_hh *h = NULL;
        if (atom->kind == YX_HEX_BYTE) {
            uint8_t bitmap[32] = {0};
            if (atom->mask == 255 && !atom->negated) h = yx_hh_literal(&atom->value, 1);
            else {
                for (unsigned b = 0; b < 256; ++b)
                    if ((((uint8_t)b & atom->mask) == (atom->value & atom->mask)) != atom->negated)
                        bitmap[b >> 3] |= (uint8_t)(1u << (b & 7));
                h = yx_hh_class(bitmap);
            }
        } else if (atom->kind == YX_HEX_JUMP) {
            /* hex2hir coalesces consecutive jumps into one repetition. */
            uint32_t minimum = atom->minimum, maximum = atom->maximum;
            bool unbounded = maximum == UINT32_MAX && !atom->finite_maximum;
            while (i + 1 < count && atoms[i + 1].kind == YX_HEX_JUMP) {
                const yx_hex_atom *next = &atoms[++i];
                if (next->minimum > UINT32_MAX - minimum) { yx_hh_free_all(subs, used); return NULL; }
                minimum += next->minimum;
                if (unbounded || (next->maximum == UINT32_MAX && !next->finite_maximum)) unbounded = true;
                else if (next->maximum > UINT32_MAX - maximum) { yx_hh_free_all(subs, used); return NULL; }
                else maximum += next->maximum;
            }
            if (!unbounded && minimum == 1 && maximum == 1) {
                uint8_t bitmap[32]; memset(bitmap, 255, sizeof(bitmap)); h = yx_hh_class(bitmap);
            } else if (!unbounded && !maximum) {
                h = yx_hh_new(YX_HH_EMPTY);
            } else {
                h = yx_hh_new(YX_HH_REPEAT);
                if (h) { h->minimum = minimum; h->maximum = maximum; h->unbounded = unbounded; }
            }
        } else if (atom->kind == YX_HEX_ALTERNATIVE && atom->branch_count) {
            yx_hh **branches = calloc(atom->branch_count, sizeof(*branches));
            if (branches) {
                size_t built = 0;
                for (; built < atom->branch_count; ++built) {
                    branches[built] = yx_hh_from_hex(atom->branches[built].atoms, atom->branches[built].count, depth + 1);
                    if (!branches[built]) break;
                }
                if (built == atom->branch_count) h = yx_hh_alternation(branches, built);
                else yx_hh_free_all(branches, built);
            }
        }
        if (!h) { yx_hh_free_all(subs, used); return NULL; }
        subs[used++] = h;
    }
    return yx_hh_concat(subs, used);
}
/* re::fast::compiler::PatternSplitter over the simplified HIR. */
typedef struct {
    yx_fast_program *p;
    yx_fast_literal *alternatives;
    size_t alternative_count;
    bool in_alternation, in_repetition;
} yx_hh_splitter;
static bool yx_hh_take_alternative(yx_hh_splitter *s)
{
    yx_fast_program *p = s->p;
    if (s->alternative_count == 256) return false;
    yx_fast_literal *literal = &s->alternatives[s->alternative_count++];
    literal->length = p->bytes.used;
    literal->bytes = p->bytes.used ? p->bytes.data : malloc(1);
    literal->mask = p->bytes.used ? p->mask.data : malloc(1);
    if (!p->bytes.used) { free(p->bytes.data); free(p->mask.data); }
    p->bytes = (yx_writer){0}; p->mask = (yx_writer){0};
    return literal->bytes && literal->mask;
}
static bool yx_hh_split(yx_hh_splitter *s, const yx_hh *h)
{
    yx_fast_program *p = s->p;
    switch (h->kind) {
    case YX_HH_LITERAL:
        for (size_t i = 0; i < h->length; ++i) if (!yx_fast_append(p, h->bytes[i], 255)) return false;
        return true;
    case YX_HH_UCLASS:
        return s->in_repetition;
    case YX_HH_CLASS: {
        if (s->in_repetition) return true;
        unsigned first = 256, last = 0, count = 0;
        for (unsigned b = 0; b < 256; ++b) if (yx_hh_bit(h->bitmap, b)) { if (first == 256) first = b; last = b; ++count; }
        /* class_to_masked_byte */
        unsigned negated = first ^ last, bits = 0; bool cube = true;
        for (unsigned b = 0; b < 256; ++b) if (yx_hh_bit(h->bitmap, b) && (b & first) != first) cube = false;
        for (unsigned k = 0; k < 8; ++k) bits += (negated >> k) & 1u;
        if (cube && (1u << bits) == count) return yx_fast_append(p, (uint8_t)first, (uint8_t)~negated);
        if (s->in_alternation) return false;
        /* class_to_masked_bytes_alternation: every range is a bit cube. */
        yx_fast_literal *items = calloc(256, sizeof(*items));
        size_t n = 0; bool ok = items != NULL;
        for (unsigned b = 0; ok && b < 256;) {
            if (!yx_hh_bit(h->bitmap, b)) { ++b; continue; }
            unsigned end = b;
            while (end + 1 < 256 && yx_hh_bit(h->bitmap, end + 1)) ++end;
            unsigned range_negated = b ^ end, range_bits = 0;
            for (unsigned k = 0; k < 8; ++k) range_bits += (range_negated >> k) & 1u;
            if ((b & end) != b || (1u << range_bits) != end - b + 1) ok = false;
            else {
                items[n].bytes = malloc(1); items[n].mask = malloc(1); items[n].length = 1; items[n].force_masked = true;
                if (!items[n].bytes || !items[n].mask) ok = false;
                else { items[n].bytes[0] = (uint8_t)b; items[n].mask[0] = (uint8_t)~range_negated; }
                ++n;
            }
            b = end + 1;
        }
        if (!ok || !yx_fast_flush(p) || !yx_fast_piece_reserve(p)) {
            for (size_t i = 0; items && i < n; ++i) yx_fast_literal_destroy(&items[i]);
            free(items); return false;
        }
        yx_fast_piece *piece = &p->pieces[p->count++];
        piece->kind = 7; piece->alternatives = items; piece->alternative_count = n;
        return true;
    }
    case YX_HH_REPEAT: {
        if (s->in_repetition || s->in_alternation) return false;
        /* Jumps only repeat any byte; hex jumps accept newlines. */
        if (!h->unbounded && h->minimum == h->maximum && h->maximum <= 8) {
            for (uint32_t i = 0; i < h->minimum; ++i) if (!yx_fast_append(p, 0, 0)) return false;
            return true;
        }
        if (!yx_fast_flush(p) || !yx_fast_piece_reserve(p)) return false;
        yx_fast_piece *piece = &p->pieces[p->count++];
        piece->kind = !h->unbounded && h->minimum == h->maximum ? 3 : 4; piece->newline = true;
        piece->minimum = h->minimum; piece->maximum = h->unbounded ? UINT32_MAX : h->maximum;
        piece->unbounded = h->unbounded;
        return true;
    }
    case YX_HH_CONCAT:
        for (size_t i = 0; i < h->count; ++i) if (!yx_hh_split(s, h->subs[i])) return false;
        return true;
    case YX_HH_ALT: {
        if (s->in_repetition || s->in_alternation || h->count > 255 || !yx_fast_flush(p)) return false;
        s->in_alternation = true; s->alternative_count = 0;
        s->alternatives = calloc(256, sizeof(*s->alternatives));
        if (!s->alternatives) return false;
        bool ok = true;
        for (size_t i = 0; ok && i < h->count; ++i) {
            if (i) ok = yx_hh_take_alternative(s);
            if (ok) ok = yx_hh_split(s, h->subs[i]);
        }
        if (ok) ok = yx_hh_take_alternative(s);
        if (ok && !yx_fast_piece_reserve(p)) ok = false;
        if (ok) {
            yx_fast_piece *piece = &p->pieces[p->count++];
            piece->kind = 7; piece->alternatives = s->alternatives; piece->alternative_count = s->alternative_count;
        } else {
            for (size_t i = 0; i < s->alternative_count; ++i) yx_fast_literal_destroy(&s->alternatives[i]);
            free(s->alternatives);
        }
        s->alternatives = NULL; s->alternative_count = 0; s->in_alternation = false;
        return ok;
    }
    case YX_HH_EMPTY:
        return true;
    }
    return false;
}
static bool yx_fast_hex_sequence(yx_fast_program *p, const yx_hex_atom *atoms, size_t count)
{
    yx_hh *hir = yx_hh_from_hex(atoms, count, 0);
    if (!hir) return false;
    yx_hh_splitter splitter = {.p = p};
    bool ok = yx_hh_split(&splitter, hir) && yx_fast_flush(p);
    yx_hh_free(hir);
    return ok;
}
static int yx_fast_quality(const uint8_t *bytes, const uint8_t *mask, size_t length)
{
    int quality = 0, unique = 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t value = bytes[i], m = mask[i];
        if (m != 255) {
            unsigned bits = 0;
            for (unsigned k = 0; k < 8; ++k) bits += (m >> k) & 1u;
            quality += bits ? (int)(3 * bits) - 8 : -13;
        } else {
            quality += value == 0 ? 6 : value == 0x20 || value == 0x90 || value == 0xcc || value == 0xff ? 12 :
                (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ? 18 : 20;
            bool seen = false;
            for (size_t j = 0; j < i; ++j) if (mask[j] == 255 && bytes[j] == value) seen = true;
            if (!seen) ++unique;
        }
    }
    if (unique == 1) {
        uint8_t first = bytes[0];
        quality += first == 0 || first == 0x20 || first == 0x90 || first == 0xcc || first == 0xff ? -5 : 2;
    } else quality += 2 * unique;
    return quality;
}
static int yx_fast_best_atom(const yx_fast_literal *literal, size_t *offset, size_t *width)
{
    if (!literal->length) return INT_MIN;
    bool masked = literal->force_masked;
    for (size_t i = 0; i < literal->length; ++i) if (literal->mask[i] != 255) masked = true;
    size_t limit = literal->length < 4 ? literal->length : 4;
    int best = INT_MIN; *offset = 0; *width = 0;
    for (size_t n = masked ? 1 : limit; n <= limit; ++n)
        for (size_t i = 0; i <= literal->length - n; ++i) {
            int quality = yx_fast_quality(literal->bytes + i, literal->mask + i, n);
            if (quality > best) { best = quality; *offset = i; *width = n; }
        }
    return best;
}
static bool yx_fast_u16(yx_writer *w, size_t value)
{ return value <= UINT16_MAX && yx_put_u8(w, (uint8_t)value) && yx_put_u8(w, (uint8_t)(value >> 8)); }
/* Since format v12, FastVM jump bounds occupy four little-endian bytes.
 * Literal and alternation lengths remain u16. */
static bool yx_fast_u32(yx_writer *w, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) if (!yx_put_u8(w, (uint8_t)(value >> (8 * i)))) return false;
    return true;
}
static bool yx_fast_emit_literal(yx_writer *w, const yx_fast_literal *literal)
{
    bool masked = literal->force_masked;
    for (size_t i = 0; i < literal->length; ++i) if (literal->mask[i] != 255) masked = true;
    return yx_put_u8(w, masked ? 2 : 1) && yx_fast_u16(w, literal->length) &&
        yx_put_bytes(w, literal->bytes, literal->length) && (!masked || yx_put_bytes(w, literal->mask, literal->length));
}
static bool yx_fast_emit_piece(yx_writer *w, const yx_fast_piece *piece)
{
    if (piece->kind == 1) return yx_fast_emit_literal(w, &piece->alternatives[0]);
    if (piece->kind == 3 || piece->kind == 4)
        return yx_put_u8(w, (uint8_t)(piece->kind + (piece->newline ? 0 : 2))) &&
            yx_fast_u32(w, piece->minimum) &&
            (piece->kind == 3 || yx_fast_u32(w, piece->unbounded ? 0 : piece->maximum));
    if (piece->kind != 7 || !yx_put_u8(w, 7)) return false;
    size_t at = w->used;
    if (!yx_fast_u16(w, 0)) return false;
    for (size_t i = 0; i < piece->alternative_count; ++i) if (!yx_fast_emit_literal(w, &piece->alternatives[i])) return false;
    size_t size = w->used - at - 2;
    if (size > UINT16_MAX) return false;
    w->data[at] = (uint8_t)size; w->data[at + 1] = (uint8_t)(size >> 8); return true;
}
static bool yx_fast_atom_combinations(yx_fast_program *p, const yx_fast_literal *literal,
    size_t offset, size_t width, size_t index, yx_archive_regexp_atom *atom)
{
    if (index == width) return yx_fast_atoms_push(p, atom);
    if (index >= sizeof(atom->bytes) || offset > literal->length || index >= literal->length - offset) return false;
    uint8_t mask = literal->mask[offset + index], value = literal->bytes[offset + index] & mask;
    for (unsigned byte = 0; byte < 256; ++byte)
        if (((uint8_t)byte & mask) == value) {
            atom->bytes[index] = (uint8_t)byte;
            if (!yx_fast_atom_combinations(p, literal, offset, width, index + 1, atom)) return false;
        }
    return true;
}
/* A long gap only creates a chain when both adjacent accumulated pieces
 * contain at least two required bytes. Short final pieces merge backwards. */
static bool yx_fast_requires_chain(const yx_fast_program *p)
{
    size_t fragments = 0, minimum = 0;
    for (size_t i = 0; i < p->count; ++i) {
        const yx_fast_piece *piece = &p->pieces[i];
        if ((piece->kind == 3 || piece->kind == 4) && piece->newline &&
            piece->maximum > 200 && minimum >= 2) {
            ++fragments; minimum = 0; continue;
        }
        size_t width = piece->minimum;
        if (piece->alternative_count) {
            width = SIZE_MAX;
            for (size_t j = 0; j < piece->alternative_count; ++j)
                if (piece->alternatives[j].length < width) width = piece->alternatives[j].length;
        }
        if (minimum < 2) minimum += width;
    }
    return fragments > (minimum < 2 ? 1u : 0u);
}
static bool yx_fast_compile_mode(yx_fast_program *p, bool chain_fragment)
{
    int quality = INT_MIN; size_t best = 0;
    bool fixed_only = true;
    if (!chain_fragment && !p->encoded_counts && yx_fast_requires_chain(p)) return false;
    for (size_t i = 0; i < p->count; ++i) {
        const yx_fast_piece *piece = &p->pieces[i]; int worst = INT_MAX;
        /* try_extract_literal_with_mask only absorbs fixed any-byte jumps of
         * at most PATTERN_CHAINING_THRESHOLD (200) bytes. */
        if (piece->kind == 4 || piece->kind == 7 ||
            (piece->kind == 3 && (!piece->newline || piece->minimum > 200))) fixed_only = false;
        if (!piece->alternative_count) continue;
        for (size_t j = 0; j < piece->alternative_count; ++j) {
            size_t offset, width; int q = yx_fast_best_atom(&piece->alternatives[j], &offset, &width);
            if (q < worst) worst = q;
        }
        if (worst > quality) { quality = worst; best = i; }
    }
    /* The reference chooses a literal or masked-literal sub-pattern first. */
    if ((!chain_fragment && ((fixed_only || (p->count == 1 && p->pieces[0].kind == 7)) && !p->force_regexp)) || quality == INT_MIN) return false;
    size_t forward;
    if (best) {
        for (size_t i = best; i > 0; --i) if (!yx_fast_emit_piece(&p->code, &p->pieces[i - 1])) return false;
        if (!yx_put_u8(&p->code, 0)) return false;
    }
    forward = p->code.used;
    for (size_t i = best; i < p->count; ++i) if (!yx_fast_emit_piece(&p->code, &p->pieces[i])) return false;
    if (!yx_put_u8(&p->code, 0)) return false;
    if (!yx_fast_atoms_start(p)) return false;
    const yx_fast_piece *piece = &p->pieces[best];
    for (size_t i = 0; i < piece->alternative_count; ++i) {
        const yx_fast_literal *literal = &piece->alternatives[i]; size_t offset, width;
        yx_fast_best_atom(literal, &offset, &width);
        if (width < 2 || offset > UINT16_MAX) return false;
        yx_archive_regexp_atom atom = {0};
        atom.length = width; atom.backtrack = (uint16_t)offset; atom.exact = p->count == 1 && width == literal->length;
        atom.has_forward = true; atom.forward = forward; atom.has_backward = best != 0; atom.backward = 0;
        if (!yx_fast_atom_combinations(p, literal, offset, width, 0, &atom)) return false;
    }
    return p->atom_count != 0;
}

static bool yx_fast_compile(yx_fast_program *p)
{ return yx_fast_compile_mode(p, false); }

/* Reduce byte classes to the same masked-byte representation used by the
 * verifier. Non-cubic classes are accepted only when each contiguous range
 * is a complete aligned bit cube. */
static bool yx_fast_class_mask(const bool members[256], uint8_t *value, uint8_t *mask)
{
    unsigned first = 256, last = 0, count = 0, bits = 0;
    for (unsigned i = 0; i < 256; ++i) if (members[i]) { if (first == 256) first = i; last = i; ++count; }
    if (!count) return false;
    unsigned varying = first ^ last;
    for (unsigned i = 0; i < 8; ++i) bits += (varying >> i) & 1u;
    if ((1u << bits) != count) return false;
    for (unsigned i = 0; i < 256; ++i) if (members[i] && (i & first) != first) return false;
    *value = (uint8_t)first; *mask = (uint8_t)~varying; return true;
}
static bool yx_fast_class(yx_fast_program *p, const bool members[256])
{
    uint8_t value, mask;
    if (yx_fast_class_mask(members, &value, &mask)) return yx_fast_append(p, value, mask);
    return false;
}
static int yx_fast_hex_digit(unsigned char c)
{ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static bool yx_fast_regex_byte(const char **cursor, uint8_t *value)
{
    const unsigned char *s = (const unsigned char *)*cursor;
    if (!*s) return false;
    unsigned byte = *s++;
    if (byte == '\\') {
        byte = *s++;
        if (!byte) return false;
        if (byte == 'x') {
            if (!s[0] || !s[1]) return false;
            int a = yx_fast_hex_digit(s[0]), b = yx_fast_hex_digit(s[1]);
            if (a < 0 || b < 0) return false;
            byte = (unsigned)(a * 16 + b); s += 2;
        } else if (byte == 'n') byte = '\n';
        else if (byte == 'r') byte = '\r';
        else if (byte == 't') byte = '\t';
        else if (byte == 'f') byte = '\f';
        else if (byte == 'a') byte = 7;
        else if (isalnum(byte)) return false;
    }
    *value = (uint8_t)byte; *cursor = (const char *)s; return true;
}
static bool yx_fast_regex_class(const char **cursor, bool members[256], bool nocase)
{
    const char *s = *cursor; bool negate = false;
    if (*s++ != '[') return false;
    if (*s == '^') { negate = true; ++s; }
    bool any = false;
    while (*s && (*s != ']' || !any)) {
        uint8_t first, last;
        if (!yx_fast_regex_byte(&s, &first)) return false;
        last = first;
        if (*s == '-' && s[1] && s[1] != ']') {
            ++s; if (!yx_fast_regex_byte(&s, &last) || last < first) return false;
        }
        for (unsigned i = first; i <= last; ++i) members[i] = true;
        any = true;
    }
    if (*s++ != ']' || !any) return false;
    if (nocase) for (unsigned i = 'A'; i <= 'Z'; ++i)
        if (members[i] || members[i + 32]) members[i] = members[i + 32] = true;
    if (negate) for (size_t i = 0; i < 256; ++i) members[i] = !members[i];
    *cursor = s; return true;
}
static bool yx_fast_number(const char **cursor, uint32_t *value)
{
    const char *s = *cursor; uint32_t n = 0;
    if (!isdigit((unsigned char)*s)) return false;
    do { unsigned digit = (unsigned)(*s++ - '0'); if (n > (UINT32_MAX - digit) / 10) return false; n = n * 10 + digit; } while (isdigit((unsigned char)*s));
    *cursor = s; *value = n; return true;
}
static bool yx_fast_regex_group(yx_fast_program *p, const char **cursor, bool dotall)
{
    const char *s = *cursor;
    if (*s++ != '(') return false;
    if (s[0] == '?' && s[1] == ':') s += 2;
    yx_fast_literal *alternatives = calloc(256,sizeof(*alternatives));
    size_t count = 0; bool ok = false; yx_writer bytes = {0}, masks = {0};
    if (!alternatives) return false;
    for (;;) {
        if (!*s || count == 256) goto done;
        if (*s == '|' || *s == ')') {
            alternatives[count++] = (yx_fast_literal){bytes.data,masks.data,bytes.used,false};
            bytes = (yx_writer){0}; masks = (yx_writer){0};
            if (*s++ == ')') break;
            continue;
        }
        uint8_t value, mask = 255;
        if (*s == '[') {
            bool members[256] = {false};
            if (!yx_fast_regex_class(&s,members,p->nocase) || !yx_fast_class_mask(members,&value,&mask)) goto done;
        } else if (*s == '.' && dotall) { ++s; value = 0; mask = 0; }
        else {
            if (strchr(".()|*+?{}^$",*s) || !yx_fast_regex_byte(&s,&value)) goto done;
            if (p->nocase && value < 128 && isalpha(value)) { value &= 0xdf; mask = 0xdf; }
        }
        if (!yx_put_u8(&bytes,value) || !yx_put_u8(&masks,mask)) goto done;
    }
    if (count == 1) {
        for (size_t i = 0; i < alternatives[0].length; ++i)
            if (!yx_fast_append(p,alternatives[0].bytes[i],alternatives[0].mask[i])) goto done;
    } else {
        if (p->nocase) {
            size_t prefix = 0;
            for (;;) {
                bool shared = prefix < alternatives[0].length;
                for (size_t i = 1; i < count && shared; ++i)
                    if (prefix >= alternatives[i].length || alternatives[i].bytes[prefix] != alternatives[0].bytes[prefix] ||
                        alternatives[i].mask[prefix] != alternatives[0].mask[prefix]) shared = false;
                if (!shared) break;
                if (!yx_fast_append(p, alternatives[0].bytes[prefix], alternatives[0].mask[prefix])) goto done;
                ++prefix;
            }
            if (prefix) for (size_t i = 0; i < count; ++i) {
                alternatives[i].length -= prefix;
                memmove(alternatives[i].bytes, alternatives[i].bytes + prefix, alternatives[i].length);
                memmove(alternatives[i].mask, alternatives[i].mask + prefix, alternatives[i].length);
            }
        }
        bool singles = true, empty = true, scalars = true;
        for (size_t i = 0; i < count; ++i) {
            uint32_t ch;
            if (alternatives[i].length != 1) singles = false;
            if (alternatives[i].length) empty = false;
            if (!yx_hh_single_char(alternatives[i].bytes, alternatives[i].length, &ch)) scalars = false;
            for (size_t k = 0; k < alternatives[i].length; ++k)
                if (alternatives[i].mask[k] != 0xff) scalars = false;
        }
        /* Classes produced by joining one-byte alternatives retain the
         * upstream Unicode-class representation and use Thompson, as does an
         * alternation of UTF-8 scalars (Hir::alternation's singleton_chars).
         * Empty alternatives are legal inside a nonempty concatenation. */
        if (singles || scalars) goto done;
        if (empty) { *cursor = s; ok = true; goto done; }
        {
            if (!yx_fast_flush(p) || !yx_fast_piece_reserve(p)) goto done;
            yx_fast_piece *piece = &p->pieces[p->count++]; piece->kind = 7;
            piece->alternatives = alternatives; piece->alternative_count = count;
            alternatives = NULL; count = 0;
        }
    }
    *cursor = s; ok = true;
done:
    for (size_t i = 0; i < count; ++i) yx_fast_literal_destroy(&alternatives[i]);
    free(alternatives); free(bytes.data); free(masks.data); return ok;
}
/* Flag-only dotall groups disappear from regex-syntax's HIR. Keep the
 * lexical flag state while lowering their surrounding FastVM sequence. */
static bool yx_fast_dotall_group(const char **cursor, bool *dotall, char end)
{
    const char *s = *cursor;
    if (s[0] != '(' || s[1] != '?') return false;
    s += 2;
    bool negate = false, any = false, enabled = *dotall;
    while (*s == 's' || *s == '-') {
        if (*s++ == '-') negate = true;
        else { enabled = !negate; any = true; }
    }
    if (!any || *s != end) return false;
    *cursor = s + 1; *dotall = enabled;
    return true;
}
static bool yx_fast_dotall_flag(const char **cursor, bool *dotall)
{ return yx_fast_dotall_group(cursor, dotall, ')'); }
/* Scoped flags disappear from HIR as well. Recurse into the sequence with
 * local flag state so that the enclosing dotall setting resumes afterwards. */
static bool yx_fast_regex_sequence(yx_fast_program *p, const char **cursor,
    bool dotall, bool scoped, bool *repeated, bool *greedy, unsigned depth)
{
    const char *s = *cursor;
    if (depth > 64) return false;
    while (*s && (!scoped || *s != ')')) {
        if (yx_fast_dotall_flag(&s, &dotall)) continue;
        const char *group = s; bool enabled = dotall;
        if (yx_fast_dotall_group(&group, &enabled, ':')) {
            if (!yx_fast_regex_sequence(p, &group, enabled, true, repeated, greedy, depth + 1)) return false;
            s = group; continue;
        }
        if (*s == '.') {
            uint32_t minimum = 1, maximum = 1; bool repetition = false, unbounded = false; ++s;
            if (*s == '*' || *s == '+' || *s == '?') {
                minimum = *s == '+' ? 1 : 0; unbounded = *s != '?'; maximum = unbounded ? UINT32_MAX : 1; ++s; repetition = true;
            } else if (*s == '{') {
                ++s; if (!yx_fast_number(&s, &minimum)) return false; maximum = minimum;
                if (*s == ',') { ++s; unbounded = *s == '}'; maximum = UINT32_MAX; if (!unbounded && !yx_fast_number(&s, &maximum)) return false; }
                if (*s++ != '}') return false;
                repetition = true;
            }
            if (repetition) {
                *repeated = true; if (*s == '?') { *greedy = false; ++s; }
                if (!maximum) continue;
                if (minimum == 1 && maximum == 1 && !dotall) return false;
                if (!yx_fast_jump(p, minimum, maximum, dotall, unbounded)) return false;
            } else if (dotall) { if (!yx_fast_append(p, 0, 0)) return false; }
            else { /* A bare dot is a two-range byte class, which FastVM cannot encode. */ return false; }
        } else if (*s == '[') {
            bool members[256] = {false};
            if (!yx_fast_regex_class(&s, members, p->nocase) || !yx_fast_class(p, members)) return false;
        } else if (*s == '(') {
            if (!yx_fast_regex_group(p,&s,dotall)) return false;
        } else {
            if (strchr("()|*+?{}^$", *s)) return false;
            uint8_t byte; if (!yx_fast_regex_byte(&s, &byte)) return false;
            uint8_t mask = p->nocase && byte < 128 && isalpha(byte) ? 0xdf : 255;
            if (!yx_fast_append(p, byte, mask)) return false;
        }
    }
    if (scoped) { if (*s != ')') return false; ++s; }
    *cursor = s; return true;
}
static bool yx_fast_regex(yx_fast_program *p, const char *source, bool dotall)
{
    while (yx_fast_dotall_flag(&source, &dotall)) {}
    /* The HIR admits an alternation at the root as well as inside a group. */
    size_t depth = 0; bool in_class = false, root_alternative = false;
    for (size_t i = 0; source[i]; ++i) {
        if (source[i] == '\\' && source[i + 1]) { ++i; continue; }
        if (source[i] == '[' && !in_class) in_class = true;
        else if (source[i] == ']' && in_class) in_class = false;
        else if (!in_class) {
            if (source[i] == '(') ++depth;
            else if (source[i] == ')' && depth) --depth;
            else if (source[i] == '|' && !depth) root_alternative = true;
        }
    }
    if (root_alternative) {
        size_t length = strlen(source); char *group = malloc(length + 3);
        if (!group) return false;
        group[0] = '('; memcpy(group + 1, source, length); group[length + 1] = ')'; group[length + 2] = 0;
        const char *cursor = group;
        bool ok = yx_fast_regex_group(p, &cursor, dotall) && !*cursor && yx_fast_flush(p);
        free(group); p->flags = 64; return ok;
    }
    const char *s = source; bool repeated = false, greedy = true;
    if (!yx_fast_regex_sequence(p, &s, dotall, false, &repeated, &greedy, 0)) return false;
    p->flags = (uint16_t)(64 | (repeated && greedy ? 32 : 0));
    return yx_fast_flush(p);
}
static bool yx_fast_rule(const YRX_RULES *rules)
{
    if (!rules || !rules->rules || rules->rule_count != 1 || rules->import_count || rules->global_count) return false;
    const YRX_RULE *rule = &rules->rules[0];
    if (!rule->identifier || !yx_valid_rule_name(rule->identifier) || !strcmp(rule->identifier, "default") ||
        (rule->namespace_name && strcmp(rule->namespace_name,"default")) || rule->is_private || rule->is_global ||
        rule->tag_count || rule->metadata_count || rule->pattern_count != 1 || !rule->patterns) return false;
    const YRX_PATTERN *pattern = &rule->patterns[0];
    return (pattern->kind == YX_PATTERN_HEX || pattern->kind == YX_PATTERN_REGEX) &&
        !(pattern->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD)) &&
        pattern->identifier && pattern->identifier[0] == '$' && yx_valid_rule_name(pattern->identifier + 1) &&
        yx_regex_direct_condition(rule->condition_text, pattern->identifier);
}
static bool yx_fast_masked_atoms(yx_fast_program *p, const yx_fast_literal *literal)
{
    size_t offset, width; yx_fast_literal masked = *literal; masked.force_masked = true;
    /* best_range_in_masked_bytes reads the first 32 KiB only
     * (MAX_ATOM_SEARCH_BYTES, atoms/quality.rs). */
    if (masked.length > 32768) masked.length = 32768;
    yx_fast_best_atom(&masked,&offset,&width);
    if (!width || offset > UINT16_MAX) return false;
    for (;;) {
        size_t combinations = 1;
        for (size_t i = 0; i < width; ++i) {
            unsigned zeros = 0; for (unsigned bit = 0; bit < 8; ++bit) zeros += !(literal->mask[offset + i] & (1u << bit));
            if (combinations > ((size_t)YX_FAST_MAX_ATOMS >> zeros)) { combinations = YX_FAST_MAX_ATOMS + 1; break; }
            combinations *= (size_t)1 << zeros;
        }
        if (combinations <= YX_FAST_MAX_ATOMS) break;
        --width; while (width && !literal->mask[offset + width - 1]) --width;
        if (!width) return false;
    }
    if (!yx_fast_atoms_start(p)) return false;
    yx_archive_regexp_atom atom = {0}; atom.length = width; atom.backtrack = (uint16_t)offset;
    atom.exact = width == literal->length;
    return yx_fast_atom_combinations(p,literal,offset,width,0,&atom);
}
static bool yx_fast_zeroes(yx_writer *writer,size_t length)
{
    if(length>SIZE_MAX-writer->used)return false;
    size_t end=writer->used+length;
    if(end>writer->capacity) {
        uint8_t *grown=realloc(writer->data,end);
        if(!grown)return false;
        writer->data=grown;writer->capacity=end;
    }
    if(length)memset(writer->data+writer->used,0,length);
    writer->used=end;return true;
}
/* Whether a regexp has a capturing group: `(` not followed by `?`, or a
 * named group. regex-syntax keeps Capture nodes, so `a(x)b` is no HIR
 * literal; Hir::try_extract_literal_with_mask still reads it, with a mask of
 * 0xff bytes only. */
static bool yx_fast_regexp_has_capture(const char *regexp)
{
    bool in_class = false;
    for (const char *s = regexp; s && *s; ++s) {
        if (*s == '\\' && s[1]) { ++s; continue; }
        if (in_class) { if (*s == ']') in_class = false; continue; }
        if (*s == '[') {
            in_class = true;
            if (s[1] == '^') ++s;
            if (s[1] == ']') ++s;
            continue;
        }
        if (*s == '(' && (s[1] != '?' || s[2] == '<' || (s[2] == 'P' && s[3] == '<'))) return true;
    }
    return false;
}
static yx_ser_result yx_fast_masked_encode(yx_fast_program *p, const YRX_RULE *rule,
    const YRX_PATTERN *pattern, const uint8_t *wasm, size_t wasm_length, uint8_t **data, size_t *length)
{
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE)) return YX_SER_UNSUPPORTED;
    yx_writer bytes = {0}, masks = {0}; yx_ser_result result = YX_SER_UNSUPPORTED; bool masked = false;
    for (size_t i = 0; i < p->count; ++i) {
        const yx_fast_piece *piece = &p->pieces[i];
        if (piece->kind == 1) {
            const yx_fast_literal *literal = &piece->alternatives[0];
            if (!yx_put_bytes(&bytes,literal->bytes,literal->length) || !yx_put_bytes(&masks,literal->mask,literal->length)) { result = YX_SER_NO_MEMORY; goto done; }
        } else if (piece->kind == 3 && piece->newline && piece->minimum <= 200) {
            /* A longer fixed jump makes the pattern a FastVM regexp. */
            if(!yx_fast_zeroes(&bytes,piece->minimum)||!yx_fast_zeroes(&masks,piece->minimum)) {
                result=YX_SER_NO_MEMORY;goto done;
            }
        } else goto done;
    }
    for (size_t i = 0; i < masks.used; ++i) if (masks.data[i] != 255) masked = true;
    if ((!masked && !(pattern->kind == YX_PATTERN_REGEX && yx_fast_regexp_has_capture(pattern->regexp))) ||
        !bytes.used) goto done;
    yx_fast_literal literal = {bytes.data,masks.data,bytes.used,true};
    if (!yx_fast_masked_atoms(p,&literal)) goto done;
    result = yx_pattern_envelope_encode(rule->identifier,pattern->identifier,(uint8_t)pattern->kind,
        (p->flags & 32) | ((pattern->modifiers & YX_MOD_FULLWORD) ? 24 : 0),wasm,wasm_length,p->atoms,p->atom_count,NULL,0,bytes.data,masks.data,bytes.used,data,length);
done:
    free(bytes.data); free(masks.data); return result;
}
/* Wide regexp verifiers retain their original bytecode. Only the search
 * atoms and their backtrack distances are expanded to interleaved bytes. */
static bool yx_fast_widen_atoms(yx_fast_program *p, bool ascii_wide)
{
    size_t count = p->atom_count * (ascii_wide ? 2u : 1u);
    if (count > YX_FAST_MAX_ATOMS) return false;
    yx_archive_regexp_atom *atoms = calloc(count, sizeof(*atoms));
    if (!atoms) { yx_walk_no_memory = true; return false; }
    for (size_t i = 0; i < p->atom_count; ++i) {
        const yx_archive_regexp_atom *from = &p->atoms[i];
        if (from->length > 4 || from->backtrack > UINT16_MAX / 2) { free(atoms); return false; }
        atoms[i] = *from; memset(atoms[i].bytes, 0, sizeof(atoms[i].bytes));
        for (size_t j = 0; j < from->length; ++j) atoms[i].bytes[j * 2] = from->bytes[j];
        atoms[i].length *= 2; atoms[i].backtrack *= 2;
        if (ascii_wide) { atoms[p->atom_count + i] = *from; atoms[p->atom_count + i].subpattern = 1; }
    }
    free(p->atoms); p->atoms = atoms; p->atom_count = count; p->atom_capacity = count; return true;
}
/* The FastVM pieces of a regexp: the text lowering, or FastVM's splitter
 * over the parsed HIR for other flag spellings (serialization_thompson_vm.h). */
static bool yx_tv_fast_pieces(yx_fast_program **program, const YRX_PATTERN *pattern);
static int yx_tv_alternation_literal(const YRX_PATTERN *pattern);
static yx_ser_result yx_encode_fast_regex(const YRX_RULES *rules, bool vba_order, uint8_t **data, size_t *length)
{
    if (!yx_fast_rule(rules)) return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule = &rules->rules[0]; const YRX_PATTERN *pattern = &rule->patterns[0];
    yx_fast_program *p = calloc(1, sizeof(*p));
    if (!p) return YX_SER_NO_MEMORY;
    p->flags = 64; p->nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool parsed = pattern->kind == YX_PATTERN_HEX
        ? yx_fast_hex_sequence(p, pattern->hex_atoms, pattern->hex_atom_count)
        : pattern->regexp && yx_tv_fast_pieces(&p, pattern);
    if (!p) return YX_SER_NO_MEMORY;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    uint8_t wasm[sizeof(yx_single_text_pattern_wasm)];
    memcpy(wasm, yx_single_text_pattern_wasm, sizeof(wasm));
    if (!parsed && pattern->kind == YX_PATTERN_HEX && !pattern->hex_has_jump && pattern->bytes &&
        pattern->mask && pattern->length > UINT16_MAX &&
        !(pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE))) {
        /* A hex pattern of bytes and masked bytes beyond FastVM's u16
         * pieces: Hir::try_extract_literal_with_mask (re/hir.rs) has no
         * length limit, so it is a LiteralWithMask sub-pattern
         * (compiler/mod.rs c_regexp_pattern). A plain literal is left to the
         * literal codec. */
        bool masked = false;
        uint8_t *bytes = malloc(pattern->length);
        if (!bytes) { yx_fast_program_destroy(p); return YX_SER_NO_MEMORY; }
        for (size_t i = 0; i < pattern->length; ++i) {
            bytes[i] = pattern->bytes[i] & pattern->mask[i];
            if (pattern->mask[i] != 255) masked = true;
        }
        yx_fast_literal literal = {bytes, pattern->mask, pattern->length, true};
        if (masked && (!vba_order || yx_reorder_pattern_wasm(wasm, sizeof(wasm), true)) &&
            yx_fast_masked_atoms(p, &literal))
            result = yx_pattern_envelope_encode(rule->identifier, pattern->identifier, (uint8_t)pattern->kind,
                (pattern->modifiers & YX_MOD_FULLWORD) ? 24 : 0, wasm, sizeof(wasm), p->atoms, p->atom_count,
                NULL, 0, bytes, pattern->mask, pattern->length, data, length);
        free(bytes);
        yx_fast_program_destroy(p);
        return result;
    }
    /* FastVM's splitter reads through capture groups and takes masked
     * bytes, so /(caf)e|zz/ and /ab[\x30-\x3f]|zzz/ are one alternation
     * piece, but Hir::is_alternation_literal (lib/src/re/hir.rs) is false
     * for them: c_regexp compiles them with FastVM instead of
     * c_alternation_literal. */
    if (parsed && (pattern->kind == YX_PATTERN_REGEX || pattern->kind == YX_PATTERN_HEX) && p->count == 1 && p->pieces[0].kind == 7) {
        if (pattern->kind == YX_PATTERN_REGEX) {
            int literal = yx_tv_alternation_literal(pattern);
            if (literal < 0) { yx_fast_program_destroy(p); return YX_SER_NO_MEMORY; }
            if (!literal) p->force_regexp = true;
        } else {
            size_t j, k;
            for (j = 0; j < p->pieces[0].alternative_count; ++j) {
                const yx_fast_literal *literal = &p->pieces[0].alternatives[j];
                for (k = 0; k < literal->length; ++k) {
                    if (literal->mask[k] != 255) {
                        p->force_regexp = true;
                        break;
                    }
                }
                if (p->force_regexp) break;
            }
        }
    }
    if (parsed && (!vba_order || yx_reorder_pattern_wasm(wasm,sizeof(wasm),true))) {
        result = yx_fast_masked_encode(p,rule,pattern,wasm,sizeof(wasm),data,length);
        if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE)) {
            for (size_t i = 0; i < p->count; ++i) {
                if (p->pieces[i].kind == 3 && p->pieces[i].newline) p->force_regexp = true;
                for (size_t j = 0; j < p->pieces[i].alternative_count; ++j) {
                    const yx_fast_literal *literal = &p->pieces[i].alternatives[j];
                    for (size_t k = 0; k < literal->length; ++k)
                        if (literal->mask[k] != 255) p->force_regexp = true;
                }
            }
        }
        bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
        bool ascii_wide = wide && (pattern->modifiers & YX_MOD_ASCII) != 0;
        if (result == YX_SER_UNSUPPORTED && !p->atoms && yx_fast_compile(p) &&
            (!wide || yx_fast_widen_atoms(p,ascii_wide)))
            result = yx_regexp_variants_encode(rule->identifier,pattern->identifier,(uint8_t)pattern->kind,
                p->flags | (wide ? 1 : 0) | (p->nocase ? 2 : 0) |
                ((pattern->modifiers & YX_MOD_FULLWORD) ? 24 : 0),ascii_wide,
                wasm,sizeof(wasm),p->atoms,p->atom_count,p->code.data,p->code.used,data,length);
    }
    yx_fast_program_destroy(p); return result;
}

static bool yx_fast_read_u16(const uint8_t *code, size_t end, size_t *at, uint16_t *value)
{
    if (*at > end || end - *at < 2) return false;
    *value = (uint16_t)(code[*at] | ((uint16_t)code[*at + 1] << 8)); *at += 2; return true;
}
static bool yx_fast_read_u32(const uint8_t *code, size_t end, size_t *at, uint32_t *value)
{
    if (*at > end || end - *at < 4) return false;
    *value = (uint32_t)code[*at] | ((uint32_t)code[*at + 1] << 8) |
        ((uint32_t)code[*at + 2] << 16) | ((uint32_t)code[*at + 3] << 24);
    *at += 4; return true;
}
static bool yx_fast_read_literal(const uint8_t *code, size_t end, size_t *at, yx_fast_literal *literal)
{
    uint16_t n; if (*at >= end) return false;
    uint8_t kind = code[(*at)++];
    if ((kind != 1 && kind != 2) || !yx_fast_read_u16(code,end,at,&n) || (!n && kind != 1) ||
        n > end - *at || (kind == 2 && n > (end - *at) / 2)) return false;
    literal->length = n; literal->bytes = malloc(n ? n : 1); literal->mask = malloc(n ? n : 1);
    if (!literal->bytes || !literal->mask) return false;
    memcpy(literal->bytes,code + *at,n); *at += n;
    if (kind == 2) { memcpy(literal->mask,code + *at,n); *at += n; }
    else memset(literal->mask,255,n);
    literal->force_masked = kind == 2;
    for (size_t i = 0; i < n; ++i) if ((literal->bytes[i] & literal->mask[i]) != literal->bytes[i]) return false;
    return true;
}
static bool yx_fast_read_sequence(yx_fast_program *p, const uint8_t *code, size_t end, size_t *at)
{
    while (*at < end && code[*at]) {
        if (!yx_fast_piece_reserve(p)) return false;
        uint8_t opcode = code[*at]; yx_fast_piece *piece = &p->pieces[p->count++];
        if (opcode == 1 || opcode == 2) {
            piece->kind = 1; piece->alternatives = calloc(1,sizeof(*piece->alternatives));
            if (!piece->alternatives) return false;
            piece->alternative_count = 1;
            if (!yx_fast_read_literal(code,end,at,piece->alternatives)) return false;
        } else if (opcode >= 3 && opcode <= 6) {
            ++*at; piece->kind = opcode < 5 ? opcode : (uint8_t)(opcode - 2); piece->newline = opcode < 5;
            uint32_t minimum,maximum;
            if (!yx_fast_read_u32(code,end,at,&minimum)) return false;
            maximum = minimum;
            if (piece->kind == 4 && !yx_fast_read_u32(code,end,at,&maximum)) return false;
            piece->minimum = minimum; piece->maximum = maximum;
            piece->unbounded = piece->kind == 4 && maximum == 0;
            if(piece->unbounded)piece->maximum=UINT32_MAX;
            p->encoded_counts = true;
        } else if (opcode == 7) {
            ++*at; uint16_t n;
            if (!yx_fast_read_u16(code,end,at,&n) || !n || n > end - *at) return false;
            size_t alternatives_end = *at + n; piece->kind = 7;
            piece->alternatives = calloc(256,sizeof(*piece->alternatives));
            if (!piece->alternatives) return false;
            while (*at < alternatives_end) {
                if (piece->alternative_count == 256) return false;
                yx_fast_literal *literal = &piece->alternatives[piece->alternative_count++];
                if (!yx_fast_read_literal(code,alternatives_end,at,literal)) return false;
            }
            if (piece->alternative_count < 2) return false;
        } else return false;
    }
    if (*at >= end || code[(*at)++] != 0) return false;
    return true;
}
static bool yx_fast_source_byte(yx_writer *source, uint8_t byte)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t value[] = {'\\','x',(uint8_t)hex[byte >> 4],(uint8_t)hex[byte & 15]};
    return yx_put_bytes(source,value,sizeof(value));
}
static bool yx_fast_source_literal(yx_writer *source, const yx_fast_literal *literal, bool hex)
{
    static const char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < literal->length; ++i) {
        uint8_t mask = literal->mask[i], value = literal->bytes[i];
        if(!mask) {
            size_t run=1;
            while(run<literal->length-i&&!literal->mask[i+run])++run;
            /* A jump cannot start or end a hex pattern: edge runs stay `??`. */
            if(run>8 && !(hex && (i==0 || i+run==literal->length))) {
                char token[64];int count=snprintf(token,sizeof(token),hex?"[%zu] ":"[\\x00-\\xff]{%zu}",run);
                if(count<0||(size_t)count>=sizeof(token)||!yx_put_bytes(source,token,(size_t)count))return false;
                i+=run-1;continue;
            }
        }
        if (hex) {
            if (mask != 255 && mask != 240 && mask != 15 && mask != 0) {
                if (!yx_put_u8(source,'(')) return false;
                bool first = true;
                for (unsigned byte = 0; byte < 256; ++byte) if (((uint8_t)byte & mask) == value) {
                    if (!first && !yx_put_u8(source,'|')) return false;
                    uint8_t token[] = {(uint8_t)digits[byte >> 4],(uint8_t)digits[byte & 15],' '};
                    if (!yx_put_bytes(source,token,sizeof(token))) return false;
                    first = false;
                }
                if (!yx_put_u8(source,')') || !yx_put_u8(source,' ')) return false;
                continue;
            }
            uint8_t token[] = {(uint8_t)((mask & 240) ? digits[value >> 4] : '?'),
                (uint8_t)((mask & 15) ? digits[value & 15] : '?'),' '};
            if (!yx_put_bytes(source,token,sizeof(token))) return false;
        } else if (mask == 255) {
            if (!yx_fast_source_byte(source,value)) return false;
        } else {
            if (!yx_put_u8(source,'[')) return false;
            for (unsigned byte = 0; byte < 256; ++byte)
                if (((uint8_t)byte & mask) == value && !yx_fast_source_byte(source,(uint8_t)byte)) return false;
            if (!yx_put_u8(source,']')) return false;
        }
    }
    return true;
}
static bool yx_fast_source(yx_fast_program *p, bool hex, yx_writer *source, bool *dotall)
{
    bool newline = false, no_newline = false;
    for (size_t i = 0; i < p->count; ++i) if (p->pieces[i].kind == 3 || p->pieces[i].kind == 4) {
        if (p->pieces[i].newline) newline = true; else no_newline = true;
    }
    bool mixed = newline && no_newline;
    if (mixed && hex) return false;
    *dotall = newline;
    for (size_t i = 0; i < p->count; ++i) {
        const yx_fast_piece *piece = &p->pieces[i];
        if (piece->kind == 1) {
            if (!yx_fast_source_literal(source,&piece->alternatives[0],hex)) return false;
        } else if (piece->kind == 7) {
            /* A regexp that is one alternation of literals is a FastVM
             * regexp only with a capture group in a branch (/(caf)e|zz/):
             * the first branch gets one, so the source is no alternation
             * literal either. */
            bool branch_capture = !hex && p->count == 1;
            if (!yx_put_u8(source,'(')) return false;
            for (size_t j = 0; j < piece->alternative_count; ++j) {
                if ((j && !yx_put_u8(source,'|')) || (branch_capture && !j && !yx_put_u8(source,'(')) ||
                    !yx_fast_source_literal(source,&piece->alternatives[j],hex) ||
                    (branch_capture && !j && !yx_put_u8(source,')'))) return false;
            }
            if (!yx_put_u8(source,')') || (hex && !yx_put_u8(source,' '))) return false;
        } else {
            char token[48]; int length;
            if (hex && !piece->newline) return false;
            /* Mixed jump modes require a local override of the surrounding
             * dotall modifier; scoped flags retain that per-jump HIR state. */
            bool scoped = mixed && !piece->newline;
            /* A leading unbounded any-byte jump spelled `.{n,}` under the s
             * modifier is an arbitrary regexp prefix (E045); the same byte
             * class written as `[\x00-\xff]` is not. */
            bool any_class = !hex && piece->newline && piece->unbounded && i == 0;
            if (scoped && !yx_put_bytes(source,"(?-s:",5)) return false;
            if (piece->kind == 3) length = snprintf(token,sizeof(token),hex ? "[%u] " : ".{%u}",piece->minimum);
            else if (!piece->unbounded) length = snprintf(token,sizeof(token),hex ? "[%u-%u] " : ".{%u,%u}",piece->minimum,
                piece->maximum>piece->minimum?piece->maximum:piece->maximum+65536u);
            else length = snprintf(token,sizeof(token),hex ? "[%u-] " : any_class ? "[\\x00-\\xff]{%u,}" : ".{%u,}",
                piece->minimum);
            if (length < 0 || (size_t)length >= sizeof(token) || !yx_put_bytes(source,token,(size_t)length) ||
                (!hex && !(p->flags & 32) && !yx_put_u8(source,'?')) ||
                (scoped && !yx_put_u8(source,')'))) return false;
        }
    }
    return true;
}
static yx_ser_result yx_decode_masked_pattern(const uint8_t *data, size_t length,
    yx_ser_rule **rules, size_t *rule_count)
{
    yx_archive_regexp_envelope e; yx_fast_program *p = NULL; yx_writer source = {0};
    uint8_t *expected = NULL; size_t expected_length = 0; yx_ser_result result = YX_SER_UNSUPPORTED;
    if (!yx_pattern_envelope_read(data,length,&e)) return result;
    if (e.variant != 1 || !e.literal_length || (e.flags & ~56u) || ((e.flags & 24u) && (e.flags & 24u) != 24u) || e.code_length || e.wasm_length != sizeof(yx_single_text_pattern_wasm)) goto done;
    p = calloc(1,sizeof(*p)); if (!p) { result = YX_SER_NO_MEMORY; goto done; }
    yx_fast_literal literal = {(uint8_t *)e.literal,(uint8_t *)e.mask,e.literal_length,true};
    if (!yx_fast_masked_atoms(p,&literal) || !yx_fast_source_literal(&source,&literal,e.pattern_kind == YX_PATTERN_HEX)) goto done;
    for (unsigned order = 0; order < 2; ++order) {
        uint8_t wasm[sizeof(yx_single_text_pattern_wasm)]; memcpy(wasm,yx_single_text_pattern_wasm,sizeof(wasm));
        if (order && !yx_reorder_pattern_wasm(wasm,sizeof(wasm),true)) continue;
        result = yx_pattern_envelope_encode(e.names[2],e.names[1],e.pattern_kind,e.flags,wasm,sizeof(wasm),
            p->atoms,p->atom_count,NULL,0,e.literal,e.mask,e.literal_length,&expected,&expected_length);
        if (result != YX_SER_SUCCESS) goto done;
        bool matches = expected_length == e.archive_length && !memcmp(expected,data,expected_length);
        free(expected); expected = NULL;
        if (matches) {
            yx_ser_rule *decoded = calloc(1,sizeof(*decoded)); if (!decoded) { result = YX_SER_NO_MEMORY; goto done; }
            decoded->namespace_name = e.names[0]; e.names[0] = NULL;
            decoded->pattern_identifier = e.names[1]; e.names[1] = NULL;
            decoded->identifier = e.names[2]; e.names[2] = NULL;
            decoded->pattern_bytes = source.data; source.data = NULL; decoded->pattern_length = source.used;
            decoded->single_text_pattern = true; decoded->single_regex_fast = e.pattern_kind == YX_PATTERN_REGEX;
            decoded->single_hex_fast = e.pattern_kind == YX_PATTERN_HEX;
            decoded->preserve_serialized_prefix = true; decoded->truth = true;
            decoded->fullword_single_pattern = (e.flags & 24u) != 0;
            *rules = decoded; *rule_count = 1; result = YX_SER_SUCCESS; goto done;
        }
    }
    result = YX_SER_UNSUPPORTED;
done:
    free(expected); free(source.data); if (p) yx_fast_program_destroy(p);
    yx_regexp_envelope_destroy(&e); return result;
}
static yx_ser_result yx_decode_fast_regex(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    yx_archive_regexp_envelope e; yx_fast_program *p = NULL; yx_writer source = {0};
    uint8_t *expected = NULL; size_t expected_length = 0; yx_ser_rule *decoded = NULL;
    yx_ser_result result = YX_SER_UNSUPPORTED; bool dotall = false;
    if (!yx_regexp_envelope_read(data,length,&e)) return yx_decode_masked_pattern(data,length,rules,rule_count);
    if (!(e.flags & 64u) || (e.flags & ~123u) || ((e.flags & 24u) && (e.flags & 24u) != 24u) ||
        (e.pattern_kind == YX_PATTERN_HEX && e.flags != 64) ||
        e.wasm_length != sizeof(yx_single_text_pattern_wasm) || !e.atom_count || !e.atoms[0].has_forward) goto done;
    p = calloc(1,sizeof(*p)); if (!p) { result = YX_SER_NO_MEMORY; goto done; }
    p->flags = e.flags; p->force_regexp = (e.flags & 3u) != 0; size_t forward = e.atoms[0].forward, at = 0;
    if (forward >= e.code_length) goto done;
    if (e.atoms[0].has_backward) {
        if (e.atoms[0].backward || !forward || !yx_fast_read_sequence(p,e.code,forward,&at) || at != forward) goto done;
        for (size_t i = 0; i < p->count / 2; ++i) {
            yx_fast_piece swap = p->pieces[i]; p->pieces[i] = p->pieces[p->count - i - 1]; p->pieces[p->count - i - 1] = swap;
        }
    } else if (forward) goto done;
    if (!yx_fast_read_sequence(p,e.code,e.code_length,&at) || at != e.code_length) goto done;
    /* A regexp archived as one FastVM alternation piece (yx_encode_fast_regex). */
    if ((e.pattern_kind == YX_PATTERN_REGEX || e.pattern_kind == YX_PATTERN_HEX) && p->count == 1 && p->pieces[0].kind == 7) p->force_regexp = true;
    if (!yx_fast_compile(p) ||
        !yx_fast_source(p,e.pattern_kind == YX_PATTERN_HEX,&source,&dotall) ||
        ((e.flags & 1u) && !yx_fast_widen_atoms(p,e.ascii_wide))) goto done;
    for (unsigned order = 0; order < 2; ++order) {
        uint8_t wasm[sizeof(yx_single_text_pattern_wasm)]; memcpy(wasm,yx_single_text_pattern_wasm,sizeof(wasm));
        if (order && !yx_reorder_pattern_wasm(wasm,sizeof(wasm),true)) continue;
        result = yx_regexp_variants_encode(e.names[2],e.names[1],e.pattern_kind,e.flags,e.ascii_wide,wasm,sizeof(wasm),
            p->atoms,p->atom_count,p->code.data,p->code.used,&expected,&expected_length);
        if (result != YX_SER_SUCCESS) goto done;
        bool matches = expected_length == e.archive_length && !memcmp(expected,data,expected_length);
        free(expected); expected = NULL;
        if (matches) {
            decoded = calloc(1,sizeof(*decoded)); if (!decoded) { result = YX_SER_NO_MEMORY; goto done; }
            decoded->namespace_name = e.names[0]; e.names[0] = NULL;
            decoded->pattern_identifier = e.names[1]; e.names[1] = NULL;
            decoded->identifier = e.names[2]; e.names[2] = NULL;
            decoded->pattern_bytes = source.data; source.data = NULL; decoded->pattern_length = source.used;
            decoded->single_text_pattern = true; decoded->single_regex_fast = e.pattern_kind == YX_PATTERN_REGEX;
            decoded->single_hex_fast = e.pattern_kind == YX_PATTERN_HEX;
            decoded->single_regex_dotall = dotall; decoded->truth = true;
            decoded->preserve_serialized_prefix = true;
            decoded->fullword_single_pattern = (e.flags & 24u) != 0;
            decoded->wide_single_pattern = (e.flags & 1u) != 0;
            decoded->ascii_wide_single_pattern = e.ascii_wide;
            decoded->nocase_single_pattern = (e.flags & 2u) != 0;
            *rules = decoded; *rule_count = 1; decoded = NULL; result = YX_SER_SUCCESS; goto done;
        }
    }
    result = YX_SER_UNSUPPORTED;
done:
    if (decoded) yx_ser_rules_destroy(decoded,1);
    free(expected); free(source.data); if (p) yx_fast_program_destroy(p);
    yx_regexp_envelope_destroy(&e); return result;
}

#endif
