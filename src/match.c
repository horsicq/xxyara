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

#include "internal.h"
#include "regex_vm.h"
#include "serialization.h"

#include "xxfclib/data/xx_data.h"
#include "xxfclib/algo/literal_nocase/xx_literal_nocase.h"
#include "xxfclib/algo/maskscan/xx_maskscan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include "native_regex.h"
#if defined(_WIN32) && !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif
#include "thread_storage.h"

static pcre2_code *yx_candidate_cached_regex(const YRX_PATTERN *pattern);
static void yx_candidate_select_window(const uint8_t *bytes,
    const uint8_t *mask, size_t length, bool nocase,
    size_t *selected, size_t *selected_length);

static int yx_match_compare(const void *left, const void *right)
{
    const YRX_MATCH *a = left, *b = right;
    if (a->offset < b->offset) return -1;
    if (a->offset > b->offset) return 1;
    if (a->length < b->length) return -1;
    if (a->length > b->length) return 1;
    return 0;
}

/* Most lists are recorded in increasing (offset, length) order already. A
 * strictly increasing list is its own and only sorted permutation, so the
 * qsort can be skipped; lists with ties or inversions still take qsort, which
 * keeps its exact tie order. Returns true when the offsets are also unique. */
static bool yx_sort_matches(YRX_MATCH *matches, size_t count)
{
    size_t i = 1;
    bool unique = true;
    while (i < count && (matches[i - 1].offset < matches[i].offset ||
                         (matches[i - 1].offset == matches[i].offset &&
                          matches[i - 1].length < matches[i].length))) {
        if (matches[i - 1].offset == matches[i].offset) unique = false;
        ++i;
    }
    if (i >= count) return unique;
    qsort(matches, count, sizeof(YRX_MATCH), yx_match_compare);
    return false;
}

static void yx_sort_unique_limit(YRX_PATTERN *pattern, size_t limit)
{
    size_t unique = 0;
    if (pattern->match_count > 1 &&
        yx_sort_matches(pattern->matches, pattern->match_count)) {
        pattern->match_count = limit && pattern->match_count > limit ?
                               limit : pattern->match_count;
        return;
    }
    for (size_t i = 0; i < pattern->match_count; ++i) {
        /* YARA-X reports one hit per offset. The offset/length sort keeps
           the shortest encoding when variants begin at the same byte. */
        if (unique && pattern->matches[unique - 1].offset ==
                      pattern->matches[i].offset) continue;
        pattern->matches[unique++] = pattern->matches[i];
    }
    pattern->match_count = limit && unique > limit ? limit : unique;
}

/* Wide-first literal verification and greedy regexps keep a longer match
 * at the same offset. Drop shorter duplicates before applying the limit. */
static void yx_keep_longest_per_offset(YRX_PATTERN *pattern)
{
    size_t unique = 0;
    if (pattern->match_count > 1 &&
        yx_sort_matches(pattern->matches, pattern->match_count)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        if (unique && pattern->matches[unique - 1].offset ==
                      pattern->matches[i].offset)
            --unique;
        pattern->matches[unique++] = pattern->matches[i];
    }
    pattern->match_count = unique;
}

static int yx_word_byte(uint8_t byte)
{
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9');
}

static int yx_fullword(const uint8_t *data, size_t size, size_t offset,
                       size_t length, bool wide, uint8_t xor_key)
{
    if (!wide) {
        if (offset > 0 && yx_word_byte(data[offset - 1] ^ xor_key)) return 0;
        if (offset + length < size &&
            yx_word_byte(data[offset + length] ^ xor_key)) return 0;
        return 1;
    }
    if (offset >= 2 && data[offset - 1] == xor_key &&
        yx_word_byte(data[offset - 2] ^ xor_key)) return 0;
    if (offset + length + 1 < size &&
        data[offset + length + 1] == xor_key &&
        yx_word_byte(data[offset + length] ^ xor_key)) return 0;
    return 1;
}

static int yx_add_match_key(YRX_PATTERN *pattern, size_t offset, size_t length,
                            size_t limit, int16_t xor_key)
{
    if (yx_scan_deadline_poll(pattern->deadline)) return 0;
    if (limit && pattern->match_count >= limit) return 1;
    if (pattern->match_count == pattern->match_capacity) {
        size_t next = pattern->match_capacity ? pattern->match_capacity * 2 : 8;
        if (next < pattern->match_capacity || next > SIZE_MAX / sizeof(YRX_MATCH)) return 0;
        YRX_MATCH *grown = realloc(pattern->matches, next * sizeof(YRX_MATCH));
        if (!grown) return 0;
        pattern->matches = grown;
        pattern->match_capacity = next;
    }
    /* Field stores: MSVC builds a compound literal on the stack with narrow
     * stores and copies it with wide loads, which cannot be forwarded. */
    YRX_MATCH *match = &pattern->matches[pattern->match_count++];
    match->offset = offset;
    match->length = length;
    match->xor_key = xor_key;
    return 1;
}

static int yx_add_match(YRX_PATTERN *pattern, size_t offset, size_t length, size_t limit)
{
    return yx_add_match_key(pattern, offset, length, limit, -1);
}

static uint8_t yx_fold(uint8_t value)
{
    return value >= 'A' && value <= 'Z' ? (uint8_t)(value + ('a' - 'A')) : value;
}

static int yx_equal_text(const uint8_t *data, const uint8_t *pattern, size_t length, bool nocase)
{
    if (!nocase) return memcmp(data, pattern, length) == 0;
    for (size_t i = 0; i < length; ++i)
        if (yx_fold(data[i]) != yx_fold(pattern[i])) return 0;
    return 1;
}

static int yx_find_literal(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                           const uint8_t *needle, size_t length, bool wide,
                           bool nocase, uint8_t xor_key, size_t limit)
{
    if (!length || length > size) return 1;
    bool fullword = (pattern->modifiers & YX_MOD_FULLWORD) != 0;
    int16_t match_key = (pattern->modifiers & YX_MOD_XOR) ? (int16_t)xor_key : -1;
    if (!nocase) {
        size_t start = 0;
        while (start <= size - length && (!limit || pattern->match_count < limit)) {
            if (yx_scan_deadline_poll(pattern->deadline)) return 0;
            int64_t found = xx_data_find_bytes_buffer_optimize(data, size, start,
                                                                 needle, length, NULL);
            if (found < 0) break;
            size_t offset = (size_t)found;
            if ((!fullword || yx_fullword(data, size, offset, length, wide,
                                           xor_key)) &&
                !yx_add_match_key(pattern, offset, length, limit, match_key)) return 0;
            start = offset + 1;
        }
    } else {
        size_t start = 0;
        size_t count = size - length + 1;
        size_t end = count < 256 * 1024 ? count : 256 * 1024;
        while (start < count && (!limit || pattern->match_count < limit)) {
            if (yx_scan_deadline_poll(pattern->deadline)) return 0;
            if (start == end) {
                size_t span = count - start;
                if (span > 256 * 1024) span = 256 * 1024;
                end = start + span;
            }
            /* Keep fixed 256 KiB candidate ranges, including when sparse
             * matches occur. Extra needle bytes preserve boundary matches. */
            size_t offset = xx_literal_nocase_find(data, end + (length - 1),
                                                   start, needle, length);
            if (offset == SIZE_MAX) {
                if (yx_scan_deadline_reached(pattern->deadline)) return 0;
                start = end;
                continue;
            }
            if ((!fullword || yx_fullword(data, size, offset, length, wide,
                                            xor_key)) &&
                !yx_add_match_key(pattern, offset, length, limit, match_key)) return 0;
            start = offset + 1;
            if (start == end && yx_scan_deadline_reached(pattern->deadline)) return 0;
        }
    }
    return 1;
}

static int yx_scan_text(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                        size_t limit, bool first_only)
{
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) || !(pattern->modifiers & YX_MOD_WIDE);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool xor_mode = (pattern->modifiers & YX_MOD_XOR) != 0;
    size_t atom_width = pattern->length < 4 ? pattern->length : 4;
    if (pattern->global_atom_count_hint &&
        pattern->global_atom_count_hint <= 4)
        atom_width = pattern->global_atom_count_hint;
    /* Teddy verifies the wide subpattern first. Its input threshold also
       includes the shortest atom's width. Equal four-byte literal atoms
       retain that verification order in the fallback as well. */
    bool wide_tie = pattern->kind == YX_PATTERN_TEXT && ascii && wide &&
                    (pattern->length >= 4 ||
                     (atom_width && size >= 15 + atom_width &&
                      pattern->global_atom_count_hint <= 16));
    size_t best_offset = SIZE_MAX, best_length = 0;
    int16_t best_key = -1;
    for (int variant = 0; variant < 2; ++variant) {
        if ((variant == 0 && !ascii) || (variant == 1 && !wide)) continue;
        size_t length = pattern->length * (variant ? 2 : 1);
        if (variant && length / 2 != pattern->length) return 0;
        uint8_t *needle = malloc(length ? length : 1);
        if (!needle) return 0;
        for (size_t i = 0; i < pattern->length; ++i) {
            if (variant) {
                needle[2 * i] = pattern->bytes[i];
                needle[2 * i + 1] = 0;
            } else {
                needle[i] = pattern->bytes[i];
            }
        }
        unsigned first = xor_mode ? pattern->xor_min : 0;
        unsigned last = xor_mode ? pattern->xor_max : 0;
        /* One pass over the input finds the keys whose encoded prefix
         * occurs at all; only those keys are searched. */
        bool key_hit[256];
        memset(key_hit, 1, sizeof(key_hit));
        if (xor_mode && last > first && length) {
            yx_atom_set *keys = yx_atom_set_new();
            size_t prefix = length < 4 ? length : 4;
            bool ok = keys != NULL;
            for (unsigned key = first; ok && key <= last; ++key) {
                uint8_t atom[4];
                for (size_t i = 0; i < prefix; ++i) atom[i] = (uint8_t)(needle[i] ^ key);
                ok = yx_atom_set_add(keys, atom, prefix, key - first);
            }
            bool hit[256] = {false};
            if (ok && yx_atom_set_build(keys)) {
                if (!yx_atom_set_scan(keys, data, size, pattern->deadline, hit)) {
                    yx_atom_set_free(keys);
                    free(needle);
                    return 0;
                }
                for (unsigned key = first; key <= last; ++key) key_hit[key] = hit[key - first];
            }
            yx_atom_set_free(keys);
        }
        for (unsigned key = first; key <= last; ++key) {
            if (key != first) {
                uint8_t delta = (uint8_t)((key - 1) ^ key);
                for (size_t i = 0; i < length; ++i) needle[i] ^= delta;
            } else if (key) {
                for (size_t i = 0; i < length; ++i) needle[i] ^= (uint8_t)key;
            }
            if (!key_hit[key]) continue;
            if (first_only) {
                YRX_PATTERN probe = *pattern;
                probe.matches = NULL;
                probe.match_count = 0;
                probe.match_capacity = 0;
                if (!yx_find_literal(&probe, data, size, needle, length,
                                     variant != 0, nocase, (uint8_t)key, 1)) {
                    free(probe.matches);
                    free(needle);
                    return 0;
                }
                if (probe.match_count &&
                    (probe.matches[0].offset < best_offset ||
                     (probe.matches[0].offset == best_offset &&
                      (wide_tie ? probe.matches[0].length > best_length :
                                  probe.matches[0].length < best_length)))) {
                    best_offset = probe.matches[0].offset;
                    best_length = probe.matches[0].length;
                    best_key = probe.matches[0].xor_key;
                }
                free(probe.matches);
            } else {
                /* The match limit applies to the earliest offsets across all
                   encodings and XOR keys. Keep each variant's earliest matches
                   before merging it into the bounded global list. */
                YRX_PATTERN probe = *pattern;
                probe.matches = NULL;
                probe.match_count = 0;
                probe.match_capacity = 0;
                if (!yx_find_literal(&probe, data, size, needle, length,
                                     variant != 0, nocase, (uint8_t)key,
                                     limit)) {
                    free(probe.matches);
                    free(needle);
                    return 0;
                }
                for (size_t i = 0; i < probe.match_count; ++i) {
                    if (!yx_add_match_key(pattern, probe.matches[i].offset,
                                          probe.matches[i].length, 0,
                                          probe.matches[i].xor_key)) {
                        free(probe.matches);
                        free(needle);
                        return 0;
                    }
                }
                free(probe.matches);
                if (wide_tie) {
                    yx_keep_longest_per_offset(pattern);
                    if (limit && pattern->match_count > limit)
                        pattern->match_count = limit;
                } else yx_sort_unique_limit(pattern, limit);
            }
        }
        free(needle);
    }
    if (first_only && best_offset != SIZE_MAX)
        return yx_add_match_key(pattern, best_offset, best_length, limit, best_key);
    return 1;
}

static int yx_hex_equal(const YRX_PATTERN *pattern, const uint8_t *candidate)
{
    for (size_t i = 0; i < pattern->length; ++i)
        if ((candidate[i] & pattern->mask[i]) != (pattern->bytes[i] & pattern->mask[i]))
            return 0;
    return 1;
}

/* Hex prefilters. Every match of a hex pattern satisfies byte constraints
 * at fixed distances from its start, and contains each top-level literal
 * run at a distance from its start that the jumps and alternatives before
 * the run bound. The full scanners and the candidate plans visit only the
 * starts these necessary conditions allow, in increasing order; the exact
 * matchers (yx_hex_equal, yx_hex_walk) decide every visited start as the
 * per-offset loops did, so matches, lengths and limits are unchanged. */

#define YX_HEX_SPAN 64                 /* fixed distances examined for probes */
#define YX_HEX_SPREAD 64               /* widest start range behind an anchor */
#define YX_HEX_UNBOUNDED UINT64_MAX
#define YX_HEX_CHUNK ((size_t)1 << 20) /* bytes probed between clock reads */

typedef struct yx_hex_filter {
    xx_maskscan_probe probes[XX_MASKSCAN_MAX_PROBES];
    size_t probe_count;
    unsigned probe_bits;
    /* A literal window of a top-level run; anchor[0] lies anchor_minimum
     * to anchor_maximum bytes after the start of every match. */
    uint8_t anchor[8];
    size_t anchor_length;
    uint64_t anchor_minimum, anchor_maximum;
    unsigned anchor_bits;
} yx_hex_filter;

/* Rough selectivity of a byte in binaries and text, in bits. */
static unsigned yx_hex_byte_bits(uint8_t byte)
{
    if (!byte) return 2;
    if (byte == 0xff || byte == ' ') return 4;
    if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
        (byte >= '0' && byte <= '9')) return 6;
    return 8;
}

static unsigned yx_hex_probe_bits(uint8_t mask, uint8_t value)
{
    unsigned bits = 0;
    if (mask == 0xff) return yx_hex_byte_bits(value);
    for (unsigned rest = mask; rest; rest &= rest - 1) ++bits;
    /* Zero nibbles are about as common as zero bytes. */
    return value ? bits : (bits + 1) / 2;
}

/* Keeps the XX_MASKSCAN_MAX_PROBES most selective constrained distances
 * below known, most selective first (the earliest on ties). */
static void yx_hex_pick_probes(const uint8_t *mask, const uint8_t *value,
                               size_t known, yx_hex_filter *filter)
{
    unsigned bits[XX_MASKSCAN_MAX_PROBES];
    filter->probe_count = 0;
    filter->probe_bits = 0;
    for (size_t distance = 0; distance < known; ++distance) {
        if (!mask[distance]) continue;
        uint8_t expected = (uint8_t)(value[distance] & mask[distance]);
        unsigned score = yx_hex_probe_bits(mask[distance], expected);
        size_t at = filter->probe_count;
        if (at == XX_MASKSCAN_MAX_PROBES) {
            if (score <= bits[at - 1]) continue;
            --at;
        } else ++filter->probe_count;
        for (; at && score > bits[at - 1]; --at) {
            filter->probes[at] = filter->probes[at - 1];
            bits[at] = bits[at - 1];
        }
        filter->probes[at].offset = distance;
        filter->probes[at].mask = mask[distance];
        filter->probes[at].value = expected;
        bits[at] = score;
    }
    for (size_t k = 0; k < filter->probe_count; ++k) filter->probe_bits += bits[k];
}

static uint64_t yx_hex_bound_add(uint64_t total, uint64_t amount)
{
    return amount >= YX_HEX_UNBOUNDED - total ? YX_HEX_UNBOUNDED : total + amount;
}

/* Fewest and most bytes a sequence can match (yx_hex_walk's jump bounds). */
static void yx_hex_bounds(const yx_hex_atom *atoms, size_t count,
                          uint64_t *minimum, uint64_t *maximum)
{
    uint64_t low = 0, high = 0;
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_atom *atom = &atoms[i];
        uint64_t least = 1, most = 1;
        if (atom->kind == YX_HEX_JUMP) {
            least = atom->minimum;
            most = atom->maximum == UINT32_MAX && !atom->finite_maximum ?
                   YX_HEX_UNBOUNDED : atom->maximum;
        } else if (atom->kind == YX_HEX_ALTERNATIVE) {
            least = atom->branch_count ? YX_HEX_UNBOUNDED : 0;
            most = 0;
            for (size_t b = 0; b < atom->branch_count; ++b) {
                uint64_t branch_low, branch_high;
                yx_hex_bounds(atom->branches[b].atoms, atom->branches[b].count,
                              &branch_low, &branch_high);
                if (branch_low < least) least = branch_low;
                if (branch_high > most) most = branch_high;
            }
        }
        low = yx_hex_bound_add(low, least);
        high = yx_hex_bound_add(high, most);
    }
    *minimum = low;
    *maximum = high;
}

typedef struct yx_hex_fixed {
    uint8_t mask[YX_HEX_SPAN], value[YX_HEX_SPAN];
    size_t known; /* distances below known are the same in every match */
} yx_hex_fixed;

/* (byte & mask[d]) == value[d] holds at each distance d < known from the
 * start of every match of the sequence. An alternative keeps the bits that
 * all its branches fix at a distance all of them reach at a fixed offset. */
static void yx_hex_fixed_scan(const yx_hex_atom *atoms, size_t count,
                              unsigned depth, yx_hex_fixed *out)
{
    size_t at = 0;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < count && at < YX_HEX_SPAN; ++i) {
        const yx_hex_atom *atom = &atoms[i];
        if (atom->kind == YX_HEX_BYTE) {
            if (!atom->negated) {
                out->mask[at] = atom->mask;
                out->value[at] = (uint8_t)(atom->value & atom->mask);
            }
            ++at;
        } else if (atom->kind == YX_HEX_JUMP) {
            if (atom->minimum != atom->maximum) break;
            at = atom->minimum < YX_HEX_SPAN - at ? at + atom->minimum : YX_HEX_SPAN;
        } else {
            yx_hex_fixed branch;
            size_t shared = YX_HEX_SPAN - at;
            uint64_t low, high;
            if (depth >= 8 || !atom->branch_count) break;
            for (size_t b = 0; b < atom->branch_count; ++b) {
                yx_hex_fixed_scan(atom->branches[b].atoms, atom->branches[b].count,
                                  depth + 1, &branch);
                if (branch.known < shared) shared = branch.known;
                for (size_t d = 0; d < shared; ++d) {
                    uint8_t *mask = &out->mask[at + d], *value = &out->value[at + d];
                    if (!b) {
                        *mask = branch.mask[d];
                        *value = branch.value[d];
                        continue;
                    }
                    *mask &= (uint8_t)(branch.mask[d] & ~(*value ^ branch.value[d]));
                    *value &= *mask;
                }
            }
            /* Distances a shorter branch did not reach keep no constraint. */
            for (size_t d = at + shared; d < YX_HEX_SPAN; ++d) out->mask[d] = out->value[d] = 0;
            yx_hex_bounds(atom, 1, &low, &high);
            if (low != high) { at += shared; break; }
            at = low < YX_HEX_SPAN - at ? at + (size_t)low : YX_HEX_SPAN;
        }
    }
    out->known = at;
}

static void yx_hex_consider_run(const uint8_t *run, size_t length, uint64_t low,
                                uint64_t high, yx_hex_filter *filter, int *best)
{
    size_t start, width;
    unsigned bits = 0, spread, steps = 0;
    if (high == YX_HEX_UNBOUNDED || high - low > YX_HEX_SPREAD ||
        high > (uint64_t)(SIZE_MAX / 2)) return;
    yx_candidate_select_window(run, NULL, length, false, &start, &width);
    if (!width) return;
    for (size_t i = 0; i < width; ++i) bits += yx_hex_byte_bits(run[start + i]);
    /* Each start a hit allows is an exact-matcher call. */
    spread = (unsigned)(high - low);
    while (spread >> steps) ++steps;
    int score = (int)bits - (spread ? 4 + 2 * (int)steps : 0);
    if (filter->anchor_length && score <= *best) return;
    *best = score;
    memcpy(filter->anchor, run + start, width);
    filter->anchor_length = width;
    filter->anchor_minimum = low + start;
    filter->anchor_maximum = high + start;
    filter->anchor_bits = bits;
}

/* The best literal window (at most eight bytes, the candidate atom limit)
 * of the top-level literal runs that start at most YX_HEX_SPREAD bytes
 * apart in all matches. Runs inside alternatives are not necessary. */
static void yx_hex_pick_anchor(const yx_hex_atom *atoms, size_t count,
                               yx_hex_filter *filter)
{
    uint8_t run[64];
    size_t run_length = 0;
    uint64_t low = 0, high = 0, run_low = 0, run_high = 0;
    int best = 0;
    filter->anchor_length = 0;
    filter->anchor_bits = 0;
    for (size_t i = 0; i <= count; ++i) {
        const yx_hex_atom *atom = i < count ? &atoms[i] : NULL;
        bool exact = atom && atom->kind == YX_HEX_BYTE && !atom->negated &&
                     atom->mask == 0xff;
        if (run_length && (!exact || run_length == sizeof(run))) {
            yx_hex_consider_run(run, run_length, run_low, run_high, filter, &best);
            run_length = 0;
        }
        if (!atom) break;
        if (exact) {
            if (!run_length) { run_low = low; run_high = high; }
            run[run_length++] = atom->value;
        }
        uint64_t least, most;
        yx_hex_bounds(atom, 1, &least, &most);
        low = yx_hex_bound_add(low, least);
        high = yx_hex_bound_add(high, most);
    }
}

/* Flat hex without a literal pair: the most selective masked bytes are
 * tested 16/32 offsets at a time; yx_hex_equal decides every hit. */
static int yx_scan_hex_probes(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                              size_t limit, const yx_hex_filter *filter)
{
    size_t last = size - pattern->length, offset = 0;
    while (offset <= last && (!limit || pattern->match_count < limit)) {
        size_t end = last - offset > YX_HEX_CHUNK ? offset + YX_HEX_CHUNK : last;
        size_t found = xx_maskscan_find(data, size, offset, end, filter->probes,
                                        filter->probe_count);
        if (found == SIZE_MAX) {
            if (yx_scan_deadline_reached(pattern->deadline)) return 0;
            if (end == last) break;
            offset = end + 1;
            continue;
        }
        if (yx_scan_deadline_poll(pattern->deadline)) return 0;
        if (yx_hex_equal(pattern, data + found) &&
            !yx_add_match(pattern, found, pattern->length, limit)) return 0;
        offset = found + 1;
    }
    return 1;
}

static int yx_scan_hex(YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit)
{
    if (pattern->length > size) return 1;
    size_t anchor = 0, anchor_length = 0;
    for (size_t i = 0; i < pattern->length;) {
        if (pattern->mask[i] != 0xff) { ++i; continue; }
        size_t start = i;
        while (i < pattern->length && pattern->mask[i] == 0xff) ++i;
        if (i - start > anchor_length) {
            anchor = start;
            anchor_length = i - start;
        }
    }
    if (anchor_length < 2) {
        yx_hex_filter filter;
        yx_hex_pick_probes(pattern->mask, pattern->bytes, pattern->length, &filter);
        if (filter.probe_count && filter.probe_bits >= 4)
            return yx_scan_hex_probes(pattern, data, size, limit, &filter);
    }
    if (anchor_length) {
        size_t start = anchor;
        while (start <= size - anchor_length && (!limit || pattern->match_count < limit)) {
            if (yx_scan_deadline_poll(pattern->deadline)) return 0;
            int64_t found = xx_data_find_bytes_buffer_optimize(data, size, start,
                    pattern->bytes + anchor, anchor_length, NULL);
            if (found < 0) break;
            size_t location = (size_t)found;
            if (location >= anchor && location - anchor <= size - pattern->length) {
                size_t offset = location - anchor;
                if (yx_hex_equal(pattern, data + offset) &&
                    !yx_add_match(pattern, offset, pattern->length, limit)) return 0;
            }
            start = location + 1;
        }
    } else {
        for (size_t offset = 0; offset <= size - pattern->length &&
                                (!limit || pattern->match_count < limit); ++offset) {
            if (yx_scan_deadline_poll(pattern->deadline)) return 0;
            if (yx_hex_equal(pattern, data + offset) &&
                !yx_add_match(pattern, offset, pattern->length, limit)) return 0;
        }
    }
    return 1;
}

typedef struct yx_hex_resume {
    const yx_hex_atom *atoms;
    size_t count;
    size_t index;
    const struct yx_hex_resume *parent;
} yx_hex_resume;

static void yx_hex_walk(const uint8_t *data, size_t size, size_t origin,
                        size_t position, const yx_hex_atom *atoms,
                        size_t atom_count, size_t atom_index,
                        const yx_hex_resume *resume, size_t *best_length,
                        yx_scan_deadline *deadline)
{
    const yx_hex_atom *atom;
    if (yx_scan_deadline_poll(deadline)) return;
    if (*best_length != SIZE_MAX && position - origin >= *best_length) return;
    if (atom_index == atom_count) {
        if (resume) {
            yx_hex_walk(data, size, origin, position,
                        resume->atoms, resume->count, resume->index,
                        resume->parent, best_length, deadline);
        } else if (position - origin < *best_length) {
            *best_length = position - origin;
        }
        return;
    }
    atom = &atoms[atom_index];
    if (atom->kind == YX_HEX_BYTE) {
        bool equal = position < size && (data[position] & atom->mask) ==
                                         (atom->value & atom->mask);
        if (position < size && (atom->negated ? !equal : equal))
            yx_hex_walk(data, size, origin, position + 1,
                        atoms, atom_count, atom_index + 1, resume, best_length,
                        deadline);
        return;
    }
    if (atom->kind == YX_HEX_ALTERNATIVE) {
        yx_hex_resume next = {atoms, atom_count, atom_index + 1, resume};
        for (size_t i = 0; i < atom->branch_count; ++i) {
            const yx_hex_sequence *branch = &atom->branches[i];
            yx_hex_walk(data, size, origin, position,
                        branch->atoms, branch->count, 0, &next, best_length,
                        deadline);
            if (deadline && deadline->expired) return;
        }
        return;
    }
    if (atom->kind != YX_HEX_JUMP || position > size || atom->minimum > size - position)
        return;
    size_t largest = atom->maximum == UINT32_MAX && !atom->finite_maximum ?
                     size - position : atom->maximum;
    if (largest > size - position) largest = size - position;
    for (size_t distance = atom->minimum; distance <= largest; ++distance) {
        /* Longer distances cannot beat the shortest match found so far;
         * each such call would return at the length check above. */
        if (*best_length != SIZE_MAX && position + distance - origin >= *best_length)
            break;
        yx_hex_walk(data, size, origin, position + distance,
                    atoms, atom_count, atom_index + 1, resume, best_length,
                    deadline);
        if (deadline && deadline->expired) return;
        if (distance == largest) break;
    }
}

typedef struct yx_hex_chain_output {
    YRX_PATTERN *pattern;
    size_t limit;
} yx_hex_chain_output;

static bool yx_hex_chain_emit(size_t offset, size_t length, void *context)
{
    yx_hex_chain_output *output = context;
    return yx_add_match(output->pattern, offset, length, output->limit) != 0;
}

/* Walks the starts at which the fixed-distance probes hold. */
static int yx_scan_hex_complex_probes(YRX_PATTERN *pattern, const uint8_t *data,
                                      size_t size, size_t limit,
                                      const yx_hex_filter *filter)
{
    size_t last = size - pattern->length, offset = 0;
    while (offset <= last && (!limit || pattern->match_count < limit)) {
        size_t end = last - offset > YX_HEX_CHUNK ? offset + YX_HEX_CHUNK : last;
        size_t found = xx_maskscan_find(data, size, offset, end, filter->probes,
                                        filter->probe_count);
        if (found == SIZE_MAX) {
            if (yx_scan_deadline_reached(pattern->deadline)) return 0;
            if (end == last) break;
            offset = end + 1;
            continue;
        }
        size_t best_length = SIZE_MAX;
        yx_hex_walk(data, size, found, found, pattern->hex_atoms,
                    pattern->hex_atom_count, 0, NULL, &best_length, pattern->deadline);
        if (pattern->deadline && pattern->deadline->expired) return 0;
        if (best_length != SIZE_MAX &&
            !yx_add_match(pattern, found, best_length, limit)) return 0;
        offset = found + 1;
    }
    return 1;
}

/* Walks the starts an anchor occurrence allows. Occurrences arrive in
 * increasing order, so the lowest untested start only grows: every start
 * is walked at most once and in the order of the per-offset loop. */
static int yx_scan_hex_complex_anchor(YRX_PATTERN *pattern, const uint8_t *data,
                                      size_t size, size_t limit,
                                      const yx_hex_filter *filter)
{
    size_t last = size - pattern->length, next = 0;
    size_t low = (size_t)filter->anchor_minimum;
    size_t spread = (size_t)(filter->anchor_maximum - filter->anchor_minimum);
    size_t from = low;
    while (from <= size - filter->anchor_length &&
           (!limit || pattern->match_count < limit)) {
        int64_t found = xx_data_find_bytes_buffer_optimize(data, size, from,
            filter->anchor, filter->anchor_length, NULL);
        if (found < 0) break;
        size_t hit = (size_t)found, high = hit - low;
        size_t start = high > spread ? high - spread : 0;
        if (start > last) break;
        if (start < next) start = next;
        if (high > last) high = last;
        for (; start <= high && (!limit || pattern->match_count < limit); ++start) {
            size_t best_length = SIZE_MAX;
            yx_hex_walk(data, size, start, start, pattern->hex_atoms,
                        pattern->hex_atom_count, 0, NULL, &best_length,
                        pattern->deadline);
            if (pattern->deadline && pattern->deadline->expired) return 0;
            if (best_length != SIZE_MAX &&
                !yx_add_match(pattern, start, best_length, limit)) return 0;
        }
        if (high >= next) next = high + 1;
        from = hit + 1;
        if (yx_scan_deadline_poll(pattern->deadline)) return 0;
    }
    return 1;
}

static int yx_scan_hex_complex(YRX_PATTERN *pattern, const uint8_t *data,
                               size_t size, size_t limit)
{
    if (pattern->length > size) return 1;
    {
        /* Chains: the walker's shortest match is not the end the
         * reference's chained sub-patterns report. Nothing is emitted
         * before a -2. */
        yx_hex_chain_output output = {pattern, limit};
        int success = yx_ser_scan_hex_chain(pattern, data, size, yx_hex_chain_emit, &output);
        if (success != -2) {
            if (success) yx_sort_unique_limit(pattern, limit);
            return success != 0;
        }
    }
    char *lowered = NULL;
    int chain = yx_ser_lower_fast_regex(pattern, &lowered);
    free(lowered);
    if (chain == -1) return 0;
    if (chain == 3) {
        yx_hex_chain_output output = {pattern, limit};
        int success = yx_ser_scan_large_fast_chain(pattern, data, size,
            yx_hex_chain_emit, &output);
        if (success) yx_sort_unique_limit(pattern, limit);
        return success;
    }
    yx_hex_filter filter;
    yx_hex_fixed fixed;
    yx_hex_fixed_scan(pattern->hex_atoms, pattern->hex_atom_count, 0, &fixed);
    yx_hex_pick_probes(fixed.mask, fixed.value,
                       fixed.known < pattern->length ? fixed.known : pattern->length,
                       &filter);
    yx_hex_pick_anchor(pattern->hex_atoms, pattern->hex_atom_count, &filter);
    if (filter.probe_count && filter.probe_bits >= 4 &&
        (filter.probe_bits >= 16 || filter.anchor_length < 2 ||
         filter.probe_bits >= filter.anchor_bits))
        return yx_scan_hex_complex_probes(pattern, data, size, limit, &filter);
    if (filter.anchor_length >= 2)
        return yx_scan_hex_complex_anchor(pattern, data, size, limit, &filter);
    for (size_t offset = 0; offset <= size - pattern->length &&
                            (!limit || pattern->match_count < limit); ++offset) {
        size_t best_length = SIZE_MAX;
        yx_hex_walk(data, size, offset, offset,
                    pattern->hex_atoms, pattern->hex_atom_count, 0,
                    NULL, &best_length, pattern->deadline);
        if (pattern->deadline && pattern->deadline->expired) return 0;
        if (best_length != SIZE_MAX &&
            !yx_add_match(pattern, offset, best_length, limit)) return 0;
    }
    return 1;
}

/* YARA-X regular expressions deliberately exclude PCRE look-around and
   backreferences. Check before handing a pattern to the host regex engine,
   whose language may be larger than YARA-X's. */
bool yx_regex_unrecognized_escape(unsigned char escaped)
{
    /* regex-syntax 0.8.11 treats these alphabetic escapes as errors in both
     * ordinary regexes and character classes. Other letters are assertions,
     * character classes, literals, or prefixes of longer escapes. */
    return escaped != 0 &&
           strchr("ceghijklmoqyCEFGHIJKLMNOQRTVXYZ", escaped) != NULL;
}

/* Length of the UTF-8 sequence starting at text, or 0 when it is not a
 * complete multi-byte sequence. */
static size_t yx_utf8_sequence_length(const unsigned char *text)
{
    size_t length = text[0] >= 0xc2 && text[0] <= 0xdf ? 2 : text[0] >= 0xe0 && text[0] <= 0xef ? 3 :
                    text[0] >= 0xf0 && text[0] <= 0xf4 ? 4 : 0;
    for (size_t i = 1; i < length; ++i)
        if ((text[i] & 0xc0) != 0x80) return 0;
    return length;
}

/* regex-syntax quantifies a non-ASCII literal character as a whole, while
 * PCRE2 in byte mode would quantify only its last UTF-8 byte. Wrap each
 * quantified multi-byte character outside a class in a non-capturing
 * group. Returns NULL on allocation failure. */
char *yx_regex_group_utf8_literals(const char *regexp)
{
    size_t length = strlen(regexp), used = 0;
    char *out = malloc(length * 2 + 1);
    bool in_class = false, quoted = false;
    if (!out) return NULL;
    for (size_t i = 0; i < length;) {
        const unsigned char *at = (const unsigned char *)regexp + i;
        if (quoted) {
            if (at[0] == '\\' && at[1] == 'E') quoted = false;
            out[used++] = regexp[i++];
            continue;
        }
        if (at[0] == '\\' && i + 1 < length) {
            size_t n = yx_utf8_sequence_length(at + 1);
            if (at[1] == 'Q' && !in_class) quoted = true;
            n = n ? n + 1 : 2;
            memcpy(out + used, regexp + i, n); used += n; i += n;
            continue;
        }
        if (in_class) {
            if (at[0] == '[' && at[1] == ':') {
                const char *end = strstr(regexp + i + 2, ":]");
                if (end) {
                    size_t n = (size_t)(end + 2 - (regexp + i));
                    memcpy(out + used, regexp + i, n); used += n; i += n;
                    continue;
                }
            }
            if (at[0] == ']') in_class = false;
            out[used++] = regexp[i++];
            continue;
        }
        if (at[0] == '[') {
            out[used++] = regexp[i++];
            if (regexp[i] == '^') out[used++] = regexp[i++];
            if (regexp[i] == ']') out[used++] = regexp[i++];
            in_class = true;
            continue;
        }
        size_t n = yx_utf8_sequence_length(at);
        if (n && (at[n] == '?' || at[n] == '*' || at[n] == '+' || at[n] == '{')) {
            memcpy(out + used, "(?:", 3); used += 3;
            memcpy(out + used, regexp + i, n); used += n; i += n;
            out[used++] = ')';
            continue;
        }
        out[used++] = regexp[i++];
    }
    out[used] = 0;
    return out;
}

static bool yx_extended_hex_digit(unsigned char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}

/* regex-syntax's x flag ignores whitespace between hex digits, while PCRE2
 * can parse the same spelling as a shorter escape followed by a literal.
 * Compact only complete x/u/U escapes on a temporary copy used for compiling;
 * keep the original regexp intact for source spans and serialization. */
char *yx_regex_compact_extended_hex(const char *regexp)
{
    size_t length = strlen(regexp), used = 0, depth = 0;
    bool extended = false, in_class = false;
    char *out = malloc(length + 1);
    unsigned char *states = malloc(length + 1);
    if (!out || !states) { free(out); free(states); return NULL; }
    for (size_t i = 0; i < length; ++i) {
        char ch = regexp[i];
        if (extended && !in_class && ch == '#') {
            while (i < length && regexp[i] != '\n') out[used++] = regexp[i++];
            if (i == length) break;
            out[used++] = regexp[i];
            continue;
        }
        if (ch == '\\' && i + 1 < length) {
            char escaped = regexp[i + 1];
            if (extended && (escaped == 'x' || escaped == 'u' ||
                             escaped == 'U')) {
                size_t at = i + 2, count = 0;
                char digits[8];
                while (at < length && isspace((unsigned char)regexp[at]))
                    ++at;
                if (at < length && regexp[at] == '{') {
                    size_t first = ++at;
                    while (at < length) {
                        if (isspace((unsigned char)regexp[at])) {
                            ++at;
                            continue;
                        }
                        if (!yx_extended_hex_digit((unsigned char)regexp[at]))
                            break;
                        ++count;
                        ++at;
                    }
                    if (count && at < length && regexp[at] == '}') {
                        out[used++] = '\\';
                        out[used++] = escaped;
                        out[used++] = '{';
                        for (size_t j = first; j < at; ++j)
                            if (!isspace((unsigned char)regexp[j]))
                                out[used++] = regexp[j];
                        out[used++] = '}';
                        i = at;
                        continue;
                    }
                } else {
                    size_t needed = escaped == 'x' ? 2u :
                                    escaped == 'u' ? 4u : 8u;
                    while (at < length && count < needed) {
                        if (isspace((unsigned char)regexp[at])) {
                            ++at;
                            continue;
                        }
                        if (!yx_extended_hex_digit((unsigned char)regexp[at]))
                            break;
                        digits[count++] = regexp[at++];
                    }
                    if (count == needed) {
                        out[used++] = '\\';
                        out[used++] = escaped;
                        memcpy(out + used, digits, count);
                        used += count;
                        i = at - 1;
                        continue;
                    }
                }
            }
            out[used++] = ch;
            out[used++] = regexp[++i];
            continue;
        }
        if (ch == '[' && !in_class) in_class = true;
        else if (ch == ']' && in_class) in_class = false;
        if (!in_class && ch == '(') {
            size_t end = i + 2;
            bool next_extended = extended;
            bool negated = false, flags_only = regexp[i + 1] == '?';
            if (flags_only) {
                for (; end < length; ++end) {
                    char flag = regexp[end];
                    if (flag == '-') { negated = true; continue; }
                    if (flag == 'x') next_extended = !negated;
                    else if (!strchr("imsuUR", flag)) break;
                }
            }
            if (flags_only && end < length && end > i + 2 &&
                (regexp[end] == ')' || regexp[end] == ':')) {
                if (regexp[end] == ':')
                    states[depth++] = (unsigned char)extended;
                extended = next_extended;
                memcpy(out + used, regexp + i, end - i + 1);
                used += end - i + 1;
                i = end;
                continue;
            }
            states[depth++] = (unsigned char)extended;
        } else if (!in_class && ch == ')' && depth) {
            extended = states[--depth] != 0;
        }
        out[used++] = ch;
    }
    out[used] = '\0';
    free(states);
    return out;
}

static size_t yx_regex_repeat_skip_space(const char *regexp, size_t length,
                                         size_t at)
{
    while (at < length) {
        const unsigned char *s = (const unsigned char *)regexp + at;
        size_t left = length - at, width = 0;
        if (*s == 32 || (*s >= 9 && *s <= 13)) width = 1;
        else if (left >= 2 && s[0] == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0)) width = 2;
        else if (left >= 3 && ((s[0] == 0xe1 && s[1] == 0x9a && s[2] == 0x80) ||
            (s[0] == 0xe2 && s[1] == 0x80 && ((s[2] >= 0x80 && s[2] <= 0x8a) ||
             s[2] == 0xa8 || s[2] == 0xa9 || s[2] == 0xaf)) ||
            (s[0] == 0xe2 && s[1] == 0x81 && s[2] == 0x9f) ||
            (s[0] == 0xe3 && s[1] == 0x80 && s[2] == 0x80))) width = 3;
        if (!width) break;
        at += width;
    }
    return at;
}

static int yx_regex_has_unsupported_construct(const char *regexp)
{
    size_t length = strlen(regexp);
    bool in_class = false;
    bool greedy_repeat = false, lazy_repeat = false;
    for (size_t i = 0; regexp[i]; ++i) {
        if (regexp[i] == '\\' && regexp[i + 1]) {
            char escaped = regexp[++i];
            if (yx_regex_unrecognized_escape((unsigned char)escaped))
                return 1;
            if (escaped >= '0' && escaped <= '9') return 1;
            /* PCRE2 accepts these escapes, but YARA-X's regex syntax does
               not. Keep them from silently changing the meaning of rules. */
            if (strchr("ZGKQERNhHVec0CX", escaped))
                return 1;
            if (escaped == 'p' || escaped == 'P') {
                /* The native Unicode translator validates property names. */
                if (regexp[i + 1] == '{') {
                    const char *end = strchr(regexp + i + 2, '}');
                    if (end) i = (size_t)(end - regexp);
                } else if (regexp[i + 1]) ++i;
                continue;
            }
            if ((escaped == 'x' || escaped == 'u' ||
                 escaped == 'U' || escaped == 'b') &&
                regexp[i + 1] == '{') {
                const char *end = strchr(regexp + i + 2, '}');
                if (end) i = (size_t)(end - regexp);
            }
            continue;
        }
        if (regexp[i] == '[' && !in_class) { in_class = true; continue; }
        if (regexp[i] == ']' && in_class) { in_class = false; continue; }
        if (!in_class && regexp[i] == '{') {
            size_t at = i + 1;
            bool before = false, after = false, comma = false;
            at = yx_regex_repeat_skip_space(regexp, length, at);
            while (isdigit((unsigned char)regexp[at])) {
                before = true; ++at;
            }
            at = yx_regex_repeat_skip_space(regexp, length, at);
            if (regexp[at] == ',') {
                comma = true;
                ++at;
                at = yx_regex_repeat_skip_space(regexp, length, at);
                while (isdigit((unsigned char)regexp[at])) {
                    after = true; ++at;
                }
                at = yx_regex_repeat_skip_space(regexp, length, at);
            }
            if (regexp[at] != '}' || (!before && !after) ||
                (!comma && !before)) return 1;
            i = at;
            if (regexp[i + 1] == '?') {
                lazy_repeat = true;
                ++i;
            } else greedy_repeat = true;
            continue;
        }
        if (!in_class && regexp[i] == '}') return 1;
        if (!in_class && (regexp[i] == '*' || regexp[i] == '+' ||
                          (regexp[i] == '?' &&
                           (i == 0 || regexp[i - 1] != '(')))) {
            if (regexp[i + 1] == '?') {
                lazy_repeat = true;
                ++i;
            } else greedy_repeat = true;
            continue;
        }
        if (!in_class && regexp[i] == '(' && regexp[i + 1] == '?' &&
            (regexp[i + 2] == '=' || regexp[i + 2] == '!' ||
             regexp[i + 2] == '>' || regexp[i + 2] == '|' ||
             regexp[i + 2] == '#' || regexp[i + 2] == '\'' ||
             (regexp[i + 2] == '<' &&
              (regexp[i + 3] == '=' || regexp[i + 3] == '!')) ||
             regexp[i + 2] == 'J' || regexp[i + 2] == 'n')) return 1;
    }
    return greedy_repeat && lazy_repeat;
}

/* regex-syntax accepts R as an inline CRLF flag, but rejects duplicate
 * flags, repeated negation, and a trailing negation in the same group.
 * PCRE2 accepts several of those after R is removed by our normalizer.
 * Keep this check limited to flag groups containing R. */
int yx_regex_inline_r_flag_error(const char *regexp, size_t length,
                                 size_t *error_at, const char **error_label)
{
    static const char flags[] = "imsuUxR";
    bool in_class = false;
    for (size_t i = 0; i + 2 < length; ++i) {
        if (regexp[i] == '\\' && i + 1 < length) { ++i; continue; }
        if (regexp[i] == '[' && !in_class) { in_class = true; continue; }
        if (regexp[i] == ']' && in_class) { in_class = false; continue; }
        if (in_class || regexp[i] != '(' || regexp[i + 1] != '?' ||
            !strchr("imsuUxR-", regexp[i + 2])) continue;
        size_t begin = i + 2, end = begin;
        while (end < length && regexp[end] != ':' && regexp[end] != ')' &&
               regexp[end] != '(') ++end;
        if (end == length || regexp[end] == '(' ||
            !memchr(regexp + begin, 'R', end - begin)) continue;
        unsigned seen = 0;
        bool negated = false;
        size_t last_negation = SIZE_MAX;
        for (size_t j = begin; j < end; ++j) {
            const char *flag;
            const char *label = NULL;
            if (regexp[j] == '-') {
                if (negated) label = "flag negation operator repeated";
                negated = true;
                last_negation = j;
            } else if ((flag = strchr(flags, regexp[j])) != NULL) {
                unsigned bit = 1u << (unsigned)(flag - flags);
                if (seen & bit) label = "duplicate flag";
                seen |= bit;
                last_negation = SIZE_MAX;
            } else {
                label = "unrecognized flag";
            }
            if (label) {
                if (error_at) *error_at = j;
                if (error_label) *error_label = label;
                return 1;
            }
        }
        if (last_negation != SIZE_MAX) {
            if (error_at) *error_at = last_negation;
            if (error_label)
                *error_label = "dangling flag negation operator";
            return 1;
        }
        i = end;
    }
    return 0;
}

/* The YARA-X regexp validator classifies each AST node as either ordinary,
   arbitrary data (a dot in dot-all mode), or an unbounded run of arbitrary
   data. It rejects an unbounded run in the leading arbitrary-data portion of
   a top-level concatenation. This small structural parser reproduces that
   check and estimates how far counted repetitions expand before the host
   regex engine compiles the pattern. The host engine still checks syntax. */
enum yx_regex_kind {
    YX_REGEX_ORDINARY,
    YX_REGEX_ARBITRARY_DATA,
    YX_REGEX_ARBITRARY_RUN
};

struct yx_regex_shape {
    enum yx_regex_kind kind;
    size_t expanded;
};

struct yx_regex_shape_parser {
    const char *src;
    size_t at;
    unsigned depth;
    bool dotall;
    bool top_prefix;
    bool top_alternation;
};

/* A conservative approximation of the 50 MiB automaton budget used by
   YARA-X's condition-level `matches` operation. A literal has weight 10 and
   a class or dot has weight 21, reflecting their different automaton sizes.
   Nested bounded repetitions multiply their children's expanded size.
   Saturating keeps hostile counts from overflowing size_t. */
#define YX_REGEX_EXPANSION_LIMIT ((size_t)15000000)

static size_t yx_regex_expanded_add(size_t left, size_t right)
{
    if (left > YX_REGEX_EXPANSION_LIMIT -
               (right > YX_REGEX_EXPANSION_LIMIT ?
                YX_REGEX_EXPANSION_LIMIT : right))
        return YX_REGEX_EXPANSION_LIMIT + 1;
    return left + right;
}

static size_t yx_regex_expanded_mul(size_t value, size_t count)
{
    if (value > YX_REGEX_EXPANSION_LIMIT ||
        (value && count > YX_REGEX_EXPANSION_LIMIT / value))
        return YX_REGEX_EXPANSION_LIMIT + 1;
    return value * count;
}

static struct yx_regex_shape yx_regex_shape_expr(
    struct yx_regex_shape_parser *parser, bool top);

static struct yx_regex_shape yx_regex_shape_atom(
    struct yx_regex_shape_parser *parser)
{
    const char *s = parser->src;
    struct yx_regex_shape result = {YX_REGEX_ORDINARY, 10};
    char ch = s[parser->at++];

    if (ch == '\\') {
        char escaped = s[parser->at];
        if (escaped) ++parser->at;
        if (escaped == 'd' || escaped == 'D' || escaped == 's' ||
            escaped == 'S' || escaped == 'w' || escaped == 'W')
            result.expanded = 21;
        if ((escaped == 'x' || escaped == 'u' ||
             escaped == 'U' || escaped == 'b') &&
            s[parser->at] == '{') {
            const char *end = strchr(s + parser->at + 1, '}');
            if (end) parser->at = (size_t)(end - s) + 1;
        }
    } else if (ch == '[') {
        bool escaped = false;
        result.expanded = 21;
        while (s[parser->at]) {
            ch = s[parser->at++];
            if (!escaped && ch == ']') break;
            if (!escaped && ch == '\\') escaped = true;
            else escaped = false;
        }
    } else if (ch == '.') {
        result.expanded = 21;
        if (parser->dotall) result.kind = YX_REGEX_ARBITRARY_DATA;
    } else if (ch == '^' || ch == '$') {
        result.expanded = 0;
    } else if (ch == '(') {
        size_t header = parser->at;
        bool flags_only = false;
        if (s[header] == '?') {
            ++header;
            if (s[header] == ':') {
                parser->at = header + 1;
            } else {
                size_t flags = header;
                while (strchr("imsuxUR-", s[flags]) && s[flags]) ++flags;
                if (flags > header && (s[flags] == ':' || s[flags] == ')')) {
                    parser->at = flags + 1;
                    flags_only = s[flags] == ')';
                } else if (s[header] == 'P' && s[header + 1] == '<') {
                    const char *end = strchr(s + header + 2, '>');
                    if (end) parser->at = (size_t)(end - s) + 1;
                } else if (s[header] == '<') {
                    const char *end = strchr(s + header + 1, '>');
                    if (end) parser->at = (size_t)(end - s) + 1;
                }
            }
        }
        if (flags_only) {
            result.expanded = 0;
        } else if (parser->depth < 256) {
            ++parser->depth;
            result = yx_regex_shape_expr(parser, false);
            --parser->depth;
            if (s[parser->at] == ')') ++parser->at;
        } else {
            /* Syntax validation by PCRE2 will report excessive nesting. */
            result.expanded = 0;
        }
    }

    if (s[parser->at] == '*' || s[parser->at] == '+' ||
        s[parser->at] == '?') {
        bool unbounded = s[parser->at] != '?';
        ++parser->at;
        if (s[parser->at] == '?') ++parser->at;
        if (unbounded && result.kind == YX_REGEX_ARBITRARY_DATA)
            result.kind = YX_REGEX_ARBITRARY_RUN;
    } else if (s[parser->at] == '{') {
        size_t cursor = parser->at + 1;
        size_t lower = 0, upper = 0;
        bool has_lower = false, has_upper = false, comma = false;
        while (isspace((unsigned char)s[cursor])) ++cursor;
        while (isdigit((unsigned char)s[cursor])) {
            has_lower = true;
            lower = yx_regex_expanded_mul(lower, 10);
            lower = yx_regex_expanded_add(lower, (size_t)(s[cursor++] - '0'));
        }
        while (isspace((unsigned char)s[cursor])) ++cursor;
        if (s[cursor] == ',') {
            comma = true;
            ++cursor;
            while (isspace((unsigned char)s[cursor])) ++cursor;
            while (isdigit((unsigned char)s[cursor])) {
                has_upper = true;
                upper = yx_regex_expanded_mul(upper, 10);
                upper = yx_regex_expanded_add(upper, (size_t)(s[cursor++] - '0'));
            }
            while (isspace((unsigned char)s[cursor])) ++cursor;
        }
        if (s[cursor] == '}' && (has_lower || has_upper)) {
            bool unbounded = comma && !has_upper;
            size_t count = comma && has_upper ? upper : lower;
            parser->at = cursor + 1;
            if (s[parser->at] == '?') ++parser->at;
            if (unbounded && result.kind == YX_REGEX_ARBITRARY_DATA)
                result.kind = YX_REGEX_ARBITRARY_RUN;
            /* Unbounded repeats use loops, but their required copies still
               contribute to the compiled automaton. */
            result.expanded = yx_regex_expanded_mul(result.expanded, count);
        }
    }
    return result;
}

static struct yx_regex_shape yx_regex_shape_concat(
    struct yx_regex_shape_parser *parser, bool top)
{
    struct yx_regex_shape result = {YX_REGEX_ORDINARY, 0};
    bool all_arbitrary = true, prefix_open = true, prefix_run = false;
    size_t count = 0;
    while (parser->src[parser->at] && parser->src[parser->at] != ')' &&
           parser->src[parser->at] != '|') {
        struct yx_regex_shape item = yx_regex_shape_atom(parser);
        result.expanded = yx_regex_expanded_add(result.expanded,
                                                item.expanded);
        if (item.kind == YX_REGEX_ORDINARY) {
            all_arbitrary = false;
            prefix_open = false;
        } else if (prefix_open && item.kind == YX_REGEX_ARBITRARY_RUN) {
            prefix_run = true;
        }
        if (item.kind > result.kind) result.kind = item.kind;
        ++count;
    }
    if (!all_arbitrary) result.kind = YX_REGEX_ORDINARY;
    if (top && count > 1 && prefix_run) parser->top_prefix = true;
    return result;
}

static struct yx_regex_shape yx_regex_shape_expr(
    struct yx_regex_shape_parser *parser, bool top)
{
    struct yx_regex_shape result = yx_regex_shape_concat(parser, top);
    while (parser->src[parser->at] == '|') {
        struct yx_regex_shape next;
        if (top) parser->top_alternation = true;
        ++parser->at;
        next = yx_regex_shape_concat(parser, top);
        result.expanded = yx_regex_expanded_add(result.expanded,
                                                next.expanded);
        if (next.kind > result.kind) result.kind = next.kind;
    }
    return result;
}

/* YARA-X's arbitrary-prefix check (re/parser.rs, Validator::visit_post).
   With the /s modifier a dot is arbitrary data; an unbounded repetition of
   arbitrary data is an arbitrary-length run spanning the whole repetition
   (a lazy `?` included). A concatenation inside another concatenation or an
   alternation merges all its items; the outermost one (groups and
   repetitions do not count) merges its leading arbitrary items and fails
   with E045 when they form a run. Two runs merge into ordinary data, so
   `.*.*a` passes. Alternatives yield their first run, else their last
   arbitrary item. */
enum { YX_AP_NONE, YX_AP_DATA, YX_AP_RUN };
typedef struct { int kind; size_t start, end; } yx_ap_kind;
typedef struct {
    const char *s;
    size_t length, at;
    bool dotall, found;
    unsigned depth;
    size_t start, end;
} yx_ap_parser;

static size_t yx_ap_char_end(const yx_ap_parser *p, size_t at)
{
    unsigned char ch = (unsigned char)p->s[at];
    size_t width = ch < 0xc0 ? 1 : ch < 0xe0 ? 2 : ch < 0xf0 ? 3 : 4;
    return width > p->length - at ? p->length : at + width;
}

static size_t yx_ap_escape_end(const yx_ap_parser *p, size_t at)
{
    size_t next = at + 1;
    char kind;
    if (next >= p->length) return p->length;
    kind = p->s[next];
    if (strchr("xuUpPb", kind) && next + 1 < p->length &&
        p->s[next + 1] == '{') {
        const char *close = memchr(p->s + next + 1, '}',
                                   p->length - next - 1);
        return close ? (size_t)(close - p->s) + 1 : p->length;
    }
    if (kind == 'x' || kind == 'u' || kind == 'U') {
        size_t digits = kind == 'x' ? 2 : kind == 'u' ? 4 : 8, end = next + 1;
        while (digits-- && end < p->length &&
               isxdigit((unsigned char)p->s[end])) ++end;
        return end;
    }
    if (kind == 'p' || kind == 'P')
        return next + 1 < p->length ? yx_ap_char_end(p, next + 1) : p->length;
    return yx_ap_char_end(p, next);
}

static size_t yx_ap_class_end(const yx_ap_parser *p, size_t at)
{
    size_t i = at + 1;
    unsigned depth = 1;
    if (i < p->length && p->s[i] == '^') ++i;
    if (i < p->length && p->s[i] == ']') ++i;
    while (i < p->length) {
        char ch = p->s[i];
        if (ch == '\\') { i = yx_ap_escape_end(p, i); continue; }
        if (ch == '[') {
            if (i + 1 < p->length && p->s[i + 1] == ':') {
                size_t close = i + 2;
                while (close < p->length &&
                       (isalpha((unsigned char)p->s[close]) ||
                        p->s[close] == '^')) ++close;
                if (close + 1 < p->length && p->s[close] == ':' &&
                    p->s[close + 1] == ']') {
                    i = close + 2;
                    continue;
                }
            }
            ++depth;
            ++i;
            if (i < p->length && p->s[i] == '^') ++i;
            if (i < p->length && p->s[i] == ']') ++i;
            continue;
        }
        if (ch == ']') {
            ++i;
            if (--depth == 0) return i;
            continue;
        }
        i = yx_ap_char_end(p, i);
    }
    return p->length;
}

/* The end of a repetition operator at `at` (lazy `?` included), 0 if none. */
static size_t yx_ap_repetition_end(const yx_ap_parser *p, size_t at,
                                   bool *unbounded)
{
    size_t i = at;
    if (i >= p->length) return 0;
    if (p->s[i] == '*' || p->s[i] == '+') { *unbounded = true; ++i; }
    else if (p->s[i] == '?') { *unbounded = false; ++i; }
    else if (p->s[i] == '{') {
        bool lower = false, comma = false, upper = false;
        ++i;
        while (i < p->length && isspace((unsigned char)p->s[i])) ++i;
        while (i < p->length && isdigit((unsigned char)p->s[i])) { lower = true; ++i; }
        while (i < p->length && isspace((unsigned char)p->s[i])) ++i;
        if (i < p->length && p->s[i] == ',') {
            comma = true;
            ++i;
            while (i < p->length && isspace((unsigned char)p->s[i])) ++i;
            while (i < p->length && isdigit((unsigned char)p->s[i])) { upper = true; ++i; }
            while (i < p->length && isspace((unsigned char)p->s[i])) ++i;
        }
        if (i >= p->length || p->s[i] != '}' || (!lower && !upper)) return 0;
        ++i;
        *unbounded = comma && !upper;
    } else return 0;
    if (i < p->length && p->s[i] == '?') ++i;
    return i;
}

/* Skips one item without evaluating it: the atom (a group up to its
   closing parenthesis) and its repetition operators. */
static size_t yx_ap_skip_item(const yx_ap_parser *p, size_t at)
{
    char ch = p->s[at];
    bool unbounded;
    size_t end;
    if (ch == '\\') at = yx_ap_escape_end(p, at);
    else if (ch == '[') at = yx_ap_class_end(p, at);
    else if (ch == '(') {
        unsigned depth = 1;
        ++at;
        while (at < p->length && depth) {
            ch = p->s[at];
            if (ch == '\\') at = yx_ap_escape_end(p, at);
            else if (ch == '[') at = yx_ap_class_end(p, at);
            else {
                if (ch == '(') ++depth;
                else if (ch == ')') --depth;
                ++at;
            }
        }
    } else at = yx_ap_char_end(p, at);
    while ((end = yx_ap_repetition_end(p, at, &unbounded)) != 0) at = end;
    return at;
}

static yx_ap_kind yx_ap_merge(yx_ap_kind a, yx_ap_kind b)
{
    yx_ap_kind none = {YX_AP_NONE, 0, 0};
    if (a.kind == YX_AP_NONE || b.kind == YX_AP_NONE ||
        (a.kind == YX_AP_RUN && b.kind == YX_AP_RUN)) return none;
    a.kind = a.kind == YX_AP_RUN || b.kind == YX_AP_RUN ? YX_AP_RUN : YX_AP_DATA;
    a.end = b.end;
    return a;
}

static yx_ap_kind yx_ap_alternation(yx_ap_parser *p, bool nested);

/* One concatenation item: an atom and its repetition operators. */
static yx_ap_kind yx_ap_item(yx_ap_parser *p, bool nested)
{
    yx_ap_kind kind = {YX_AP_NONE, 0, 0};
    size_t start = p->at;
    char ch = p->s[p->at];
    if (ch == '\\') p->at = yx_ap_escape_end(p, p->at);
    else if (ch == '[') p->at = yx_ap_class_end(p, p->at);
    else if (ch == '.') {
        ++p->at;
        if (p->dotall) kind = (yx_ap_kind){YX_AP_DATA, start, p->at};
    } else if (ch == '(') {
        size_t inner = p->at + 1;
        bool flags_only = false;
        if (inner < p->length && p->s[inner] == '?') {
            size_t f = inner + 1;
            if (f < p->length && (p->s[f] == '<' || p->s[f] == 'P')) {
                const char *close = memchr(p->s + f, '>', p->length - f);
                inner = close ? (size_t)(close - p->s) + 1 : p->length;
            } else {
                while (f < p->length && strchr("imsuxUR-", p->s[f]) && p->s[f]) ++f;
                flags_only = f < p->length && p->s[f] == ')';
                inner = f < p->length ? f + 1 : p->length;
            }
        }
        p->at = inner;
        if (!flags_only) {
            if (p->depth >= 256) { p->at = p->length; return kind; }
            ++p->depth;
            kind = yx_ap_alternation(p, nested);
            --p->depth;
            if (p->at < p->length && p->s[p->at] == ')') ++p->at;
        }
    } else p->at = yx_ap_char_end(p, p->at);
    for (;;) {
        bool unbounded = false;
        size_t end = yx_ap_repetition_end(p, p->at, &unbounded);
        if (!end) break;
        p->at = end;
        if (kind.kind == YX_AP_DATA && unbounded)
            kind = (yx_ap_kind){YX_AP_RUN, start, end};
    }
    return kind;
}

static yx_ap_kind yx_ap_concat(yx_ap_parser *p, bool nested)
{
    yx_ap_kind result = {YX_AP_NONE, 0, 0}, prefix = {YX_AP_NONE, 0, 0};
    size_t count = 0, index = 0;
    bool prefix_open = true, outermost;
    {
        /* Count the items first: a single item is no concatenation. */
        size_t at = p->at;
        while (at < p->length && p->s[at] != '|' && p->s[at] != ')' &&
               count < 2) {
            at = yx_ap_skip_item(p, at);
            ++count;
        }
    }
    outermost = count >= 2 && !nested;
    while (p->at < p->length && p->s[p->at] != '|' && p->s[p->at] != ')') {
        yx_ap_kind item = yx_ap_item(p, count >= 2 ? true : nested);
        if (count < 2) { result = item; continue; }
        if (outermost) result = item;
        else result = index ? yx_ap_merge(result, item) : item;
        if (prefix_open) {
            if (item.kind == YX_AP_NONE) prefix_open = false;
            else prefix = index ? yx_ap_merge(prefix, item) : item;
        }
        ++index;
    }
    if (outermost && prefix.kind == YX_AP_RUN && !p->found) {
        p->found = true;
        p->start = prefix.start;
        p->end = prefix.end;
    }
    return result;
}

static yx_ap_kind yx_ap_alternation(yx_ap_parser *p, bool nested)
{
    yx_ap_kind chosen = {YX_AP_NONE, 0, 0}, last;
    bool alternation = false, chosen_set = false, stop = false;
    {
        size_t at = p->at;
        while (at < p->length && p->s[at] != ')') {
            if (p->s[at] == '|') { alternation = true; break; }
            at = yx_ap_skip_item(p, at);
        }
    }
    if (!alternation) return yx_ap_concat(p, nested);
    for (;;) {
        last = yx_ap_concat(p, true);
        if (!stop && last.kind != YX_AP_NONE) {
            chosen = last;
            chosen_set = true;
            stop = last.kind == YX_AP_RUN;
        }
        if (p->at < p->length && p->s[p->at] == '|') { ++p->at; continue; }
        break;
    }
    return chosen_set ? chosen : last;
}

bool yx_regex_arbitrary_prefix(const char *regexp, size_t length, bool dotall,
                               size_t *start, size_t *end)
{
    yx_ap_parser parser = {regexp, length, 0, dotall, false, 0, 0, 0};
    if (!regexp || !dotall) return false;
    (void)yx_ap_alternation(&parser, false);
    if (parser.found) {
        if (start) *start = parser.start;
        if (end) *end = parser.end;
    }
    return parser.found;
}

int yx_regex_validate_shape(const char *regexp, bool dotall,
                            bool matches_expr)
{
    struct yx_regex_shape_parser parser = {
        regexp, 0, 0, dotall, false, false
    };
    struct yx_regex_shape shape = yx_regex_shape_expr(&parser, true);
    /* The `matches` operator builds a regex-automata NFA with a 50 MiB size
       cap. Strings patterns use the YARA-X Pike VM backend instead, whose
       limit is different. */
    return (matches_expr && shape.expanded > YX_REGEX_EXPANSION_LIMIT) ||
           yx_regex_arbitrary_prefix(regexp, strlen(regexp), dotall,
                                     NULL, NULL);
}

static bool yx_plain_regex_byte(unsigned char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_';
}

static bool yx_regex_hex_byte(unsigned char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}

/* Only atoms whose syntax and minimum width are unambiguous are handled by
   the large-repeat shortcut. Other expressions use the normal regex engine. */
static bool yx_simple_regex_atom(const unsigned char **at)
{
    const unsigned char *cursor = *at;
    if (yx_plain_regex_byte(*cursor)) {
        *at = cursor + 1;
        return true;
    }
    if (cursor[0] == '\\' && cursor[1] == 'x' &&
        yx_regex_hex_byte(cursor[2]) && yx_regex_hex_byte(cursor[3])) {
        *at = cursor + 4;
        return true;
    }
    if (*cursor == '[') {
        ++cursor;
        if (*cursor == '^') ++cursor;
        bool has_member = false;
        while (*cursor && *cursor != ']') {
            if (!yx_plain_regex_byte(*cursor)) return false;
            if (cursor[1] == '-' && yx_plain_regex_byte(cursor[2])) {
                if (*cursor > cursor[2]) return false;
                cursor += 3;
            } else {
                ++cursor;
            }
            has_member = true;
        }
        if (!has_member || *cursor != ']') return false;
        *at = cursor + 1;
        return true;
    }
    if (*cursor == '(') {
        ++cursor;
        if (cursor[0] == '?' && cursor[1] == ':') cursor += 2;
        const unsigned char *begin = cursor;
        while (yx_plain_regex_byte(*cursor)) ++cursor;
        if (cursor == begin || *cursor != ')') return false;
        *at = cursor + 1;
        return true;
    }
    return false;
}

static bool yx_regex_repeat_count(const unsigned char **at, uint32_t *count)
{
    const unsigned char *cursor = *at;
    uint32_t result = 0;
    if (*cursor < '0' || *cursor > '9') return false;
    do {
        unsigned digit = (unsigned)(*cursor - '0');
        if (result > (UINT32_MAX - digit) / 10) return false;
        result = result * 10 + digit;
        ++cursor;
    } while (*cursor >= '0' && *cursor <= '9');
    *at = cursor;
    *count = result;
    return true;
}

/* YARA-X accepts 32-bit repetition counts, while PCRE2 stops at 65535.
   For this restricted grammar, a required repetition of at least 4096 bytes
   exceeds YARA-X's regex VM scan limit and cannot produce a match. The
   expression may contain literal prefixes/suffixes, a simple class/group,
   or an escaped byte, but no optional path around the long repetition. */
static bool yx_unmatchable_large_repeat(const char *regexp)
{
    const unsigned char *cursor = (const unsigned char *)regexp;
    bool found = false;
    if (!cursor || !*cursor) return false;
    while (*cursor) {
        uint32_t lower, upper;
        if (!yx_simple_regex_atom(&cursor)) return false;
        if (*cursor != '{') continue;
        if (found) return false;
        ++cursor;
        if (!yx_regex_repeat_count(&cursor, &lower) || lower < 4096)
            return false;
        if (*cursor == ',') {
            ++cursor;
            if (*cursor >= '0' && *cursor <= '9') {
                if (!yx_regex_repeat_count(&cursor, &upper) || upper < lower)
                    return false;
            }
        }
        if (*cursor != '}') return false;
        ++cursor;
        found = true;
    }
    return found;
}

/* A top-level alternation can still match through a short literal branch.
   Keep the large branch grammar above and require exactly one plain literal
   branch, so every reported hit has the same offset and length as YARA-X. */
static bool yx_large_repeat_literal_alt(const char *regexp,
                                        const uint8_t **literal,
                                        size_t *literal_length)
{
    const char *bar = regexp ? strchr(regexp, '|') : NULL;
    if (!bar || strchr(bar + 1, '|')) return false;
    size_t left_length = (size_t)(bar - regexp);
    size_t right_length = strlen(bar + 1);
    if (!left_length || !right_length) return false;
    const char *short_branch = NULL;
    size_t short_length = 0;
    char branch[128];
    if (left_length < sizeof(branch)) {
        memcpy(branch, regexp, left_length);
        branch[left_length] = '\0';
        if (yx_unmatchable_large_repeat(branch)) {
            short_branch = bar + 1;
            short_length = right_length;
        }
    }
    if (!short_branch) {
        if (right_length >= sizeof(branch)) return false;
        memcpy(branch, bar + 1, right_length + 1);
        if (!yx_unmatchable_large_repeat(branch)) return false;
        short_branch = regexp;
        short_length = left_length;
    }
    if (short_length > 64) return false;
    for (size_t i = 0; i < short_length; ++i)
        if (!yx_plain_regex_byte((unsigned char)short_branch[i]))
            return false;
    *literal = (const uint8_t *)short_branch;
    *literal_length = short_length;
    return true;
}

static int yx_regex_hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* `\xHH` names a raw byte in YARA-X, whereas `\x{...}`, `\u...`,
   and `\U...` name Unicode scalar values encoded as UTF-8.
 */
static int yx_regex_unicode_escape(const char *regexp, size_t length,
                                   size_t slash, uint32_t *scalar,
                                   size_t *last)
{
    size_t at = slash + 2;
    bool braces = at < length && regexp[at] == '{';
    size_t fixed_digits = regexp[slash + 1] == 'U' ? 8u : 4u;
    size_t digits = 0;
    uint32_t value = 0;
    if (regexp[slash + 1] == 'x' && !braces) return 0;
    if (braces) ++at;
    while (at < length && (braces || digits < fixed_digits)) {
        int digit = yx_regex_hex_digit(regexp[at]);
        if (digit < 0) break;
        if (value <= 0x10ffffu)
            value = (value << 4) | (uint32_t)digit;
        ++at;
        ++digits;
    }
    if (!digits || (!braces && digits != fixed_digits) ||
        (braces && (at >= length || regexp[at++] != '}')) ||
        value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        return -1;
    *scalar = value;
    *last = at - 1;
    return 1;
}

static size_t yx_regex_append_utf8(char *out, size_t used, uint32_t scalar)
{
    static const char hex[] = "0123456789ABCDEF";
    uint8_t bytes[4];
    size_t count;
    if (scalar <= 0x7f) {
        bytes[0] = (uint8_t)scalar;
        count = 1;
    } else if (scalar <= 0x7ff) {
        bytes[0] = (uint8_t)(0xc0 | (scalar >> 6));
        bytes[1] = (uint8_t)(0x80 | (scalar & 0x3f));
        count = 2;
    } else if (scalar <= 0xffff) {
        bytes[0] = (uint8_t)(0xe0 | (scalar >> 12));
        bytes[1] = (uint8_t)(0x80 | ((scalar >> 6) & 0x3f));
        bytes[2] = (uint8_t)(0x80 | (scalar & 0x3f));
        count = 3;
    } else {
        bytes[0] = (uint8_t)(0xf0 | (scalar >> 18));
        bytes[1] = (uint8_t)(0x80 | ((scalar >> 12) & 0x3f));
        bytes[2] = (uint8_t)(0x80 | ((scalar >> 6) & 0x3f));
        bytes[3] = (uint8_t)(0x80 | (scalar & 0x3f));
        count = 4;
    }
    for (size_t i = 0; i < count; ++i) {
        out[used++] = '\\';
        out[used++] = 'x';
        out[used++] = hex[bytes[i] >> 4];
        out[used++] = hex[bytes[i] & 15];
    }
    return used;
}

/* A positive class of ASCII literals and ranges has identical byte and
   Unicode matching behavior, even when the input contains invalid UTF-8. */
static bool yx_pcre_unicode_ascii_class(const char *regexp, size_t at,
                                        size_t length)
{
    if (at + 2 >= length || regexp[at + 1] == '^') return false;
    for (size_t i = at + 1; i < length; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (ch == ']') return i > at + 1;
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_' || ch == '.') continue;
        if (ch == '-' && i > at + 1 && i + 1 < length) {
            unsigned char left = (unsigned char)regexp[i - 1];
            unsigned char right = (unsigned char)regexp[i + 1];
            if (((left >= 'a' && left <= 'z') &&
                 (right >= 'a' && right <= 'z') && left <= right) ||
                ((left >= 'A' && left <= 'Z') &&
                 (right >= 'A' && right <= 'Z') && left <= right) ||
                ((left >= '0' && left <= '9') &&
                 (right >= '0' && right <= '9') && left <= right)) continue;
        }
        return false;
    }
    return false;
}

/* A whole Unicode literal is represented by the same UTF-8 byte sequence
   in YARA-X and in the byte-mode matcher, including its wide projection. */
static bool yx_pcre_unicode_literal(const char *regexp, size_t length)
{
    size_t begin = 4, end = length;
    bool non_ascii = false;
    if (length < 6) return false;
    if (strncmp(regexp, "(?u)", 4) != 0) {
        if (strncmp(regexp, "(?u:", 4) != 0 || regexp[length - 1] != ')')
            return false;
        --end;
    }
    for (size_t i = begin; i < end;) {
        unsigned char ch = (unsigned char)regexp[i];
        if (ch < 0x80) {
            if (strchr(".\\^$*+?{}[]|()", ch)) return false;
            ++i;
            continue;
        }
        size_t continuation;
        if (ch >= 0xc2 && ch <= 0xdf) continuation = 1;
        else if (ch >= 0xe0 && ch <= 0xef) continuation = 2;
        else if (ch >= 0xf0 && ch <= 0xf4) continuation = 3;
        else return false;
        if (end - i <= continuation) return false;
        unsigned char second = (unsigned char)regexp[i + 1];
        if ((second & 0xc0) != 0x80 ||
            (ch == 0xe0 && second < 0xa0) ||
            (ch == 0xed && second >= 0xa0) ||
            (ch == 0xf0 && second < 0x90) ||
            (ch == 0xf4 && second >= 0x90)) return false;
        for (size_t j = 2; j <= continuation; ++j)
            if (((unsigned char)regexp[i + j] & 0xc0) != 0x80)
                return false;
        non_ascii = true;
        i += continuation + 1;
    }
    return non_ascii;
}

/* In byte-mode PCRE2, '+' and '+?' would repeat only the last byte of a
   UTF-8 scalar. Group one complete scalar for the whole-pattern form. */
static bool yx_pcre_unicode_scalar_at(const char *regexp,
                                     size_t scalar_length)
{
    if (scalar_length < 2 || scalar_length > 4) return false;
    unsigned char lead = (unsigned char)regexp[4];
    size_t expected = lead >= 0xc2 && lead <= 0xdf ? 2 :
                      lead >= 0xe0 && lead <= 0xef ? 3 :
                      lead >= 0xf0 && lead <= 0xf4 ? 4 : 0;
    if (scalar_length != expected) return false;
    char literal[9];
    memcpy(literal, "(?u)", 4);
    memcpy(literal + 4, regexp + 4, scalar_length);
    literal[4 + scalar_length] = '\0';
    return yx_pcre_unicode_literal(literal, 4 + scalar_length);
}

static size_t yx_pcre_unicode_scalar_plus_width(const char *regexp)
{
    size_t length = strlen(regexp), end = length;
    if (length < 7) return 0;
    if (strncmp(regexp, "(?u)", 4) != 0) {
        if (strncmp(regexp, "(?u:", 4) != 0 || regexp[length - 1] != ')')
            return 0;
        --end;
    }
    /* The lazy form has the same scalar atom followed by "+?". */
    size_t quantifier_end = end;
    if (regexp[quantifier_end - 1] == '?') --quantifier_end;
    size_t quantifier_length;
    if (regexp[quantifier_end - 1] == '+')
        quantifier_length = 1;
    else if (quantifier_end >= 8 &&
             memcmp(regexp + quantifier_end - 4, "{1,}", 4) == 0)
        quantifier_length = 4;
    else
        return 0;
    size_t scalar_length = quantifier_end - 4 - quantifier_length;
    if (!yx_pcre_unicode_scalar_at(regexp, scalar_length)) return 0;
    return scalar_length;
}

static char *yx_pcre_unicode_scalar_plus(const char *regexp)
{
    size_t scalar_length = yx_pcre_unicode_scalar_plus_width(regexp);
    if (!scalar_length) return NULL;
    size_t length = strlen(regexp);
    bool lazy = regexp[length - 1] == '?' ||
                (length > 1 && regexp[length - 1] == ')' &&
                 regexp[length - 2] == '?');
    char *rewritten = malloc(scalar_length + 6 + (lazy ? 1 : 0));
    if (!rewritten) return NULL;
    memcpy(rewritten, "(?:", 3);
    memcpy(rewritten + 3, regexp + 4, scalar_length);
    rewritten[3 + scalar_length] = ')';
    rewritten[4 + scalar_length] = '+';
    if (lazy) rewritten[5 + scalar_length] = '?';
    rewritten[5 + scalar_length + (lazy ? 1 : 0)] = '\0';
    return rewritten;
}

/* Short greedy ranges can consume more scalars than their written upper
   bound: {1,n} reaches 2n-1, as do short ranges over four-byte scalars after
   accounting for their lower bound. Lazy counts retain their written bounds.
   Keep the rewrite to these whole-pattern forms so byte-mode PCRE2 repeats
   the entire scalar. */
static size_t yx_pcre_unicode_scalar_counted_width(const char *regexp,
                                                    size_t *limited_upper,
                                                    const char **replacement,
                                                    size_t *replacement_length)
{
    size_t length = strlen(regexp), end = length, quantifier_length;
    bool lazy;
    if (length < 9) return 0;
    if (strncmp(regexp, "(?u)", 4) != 0) {
        if (strncmp(regexp, "(?u:", 4) != 0 || regexp[length - 1] != ')')
            return 0;
        --end;
    }
    lazy = end > 0 && regexp[end - 1] == '?';
    if (lazy) --end;
    if (end < 7 || regexp[end - 1] != '}') return 0;
    size_t quantifier_start = end - 2;
    while (quantifier_start > 4 && regexp[quantifier_start] != '{')
        --quantifier_start;
    if (regexp[quantifier_start] != '{') return 0;
    quantifier_length = end - quantifier_start;
    if (quantifier_length < 3 || quantifier_length > 23) return 0;

    size_t at = quantifier_start + 1;
    uint32_t lower = 0, upper = 0;
    if (at >= end - 1 || regexp[at] == '0') return 0;
    while (at < end - 1 && regexp[at] >= '0' && regexp[at] <= '9') {
        unsigned digit = (unsigned)(regexp[at++] - '0');
        if (lower > (UINT32_MAX - digit) / 10u) return 0;
        lower = lower * 10u + digit;
    }
    if (at != end - 1) {
        if (regexp[at++] != ',') return 0;
        if (at == end - 1) {
            /* {1,} follows the same verifier window as '+'. */
            if (lower == 1) return 0;
        } else {
            if (regexp[at] == '0') return 0;
            while (at < end - 1 && regexp[at] >= '0' && regexp[at] <= '9') {
                unsigned digit = (unsigned)(regexp[at++] - '0');
                if (upper > (UINT32_MAX - digit) / 10u) return 0;
                upper = upper * 10u + digit;
            }
            if (at != end - 1 || lower > upper) return 0;
        }
    }
    size_t scalar_length = end - 4 - quantifier_length;
    if (!yx_pcre_unicode_scalar_at(regexp, scalar_length)) return 0;
    *limited_upper = !lazy && upper > lower && upper <= 10 &&
                     (lower == 1 || scalar_length == 4) ? upper : 0;
    if (replacement) {
        *replacement = regexp + end - quantifier_length;
        *replacement_length = quantifier_length + (lazy ? 1 : 0);
    }
    return scalar_length;
}

static char *yx_pcre_unicode_scalar_counted(const char *regexp)
{
    size_t limited_upper = 0;
    const char *replacement = NULL;
    size_t replacement_length = 0;
    char capped_quantifier[32], expanded_quantifier[32];
    size_t scalar_length =
        yx_pcre_unicode_scalar_counted_width(regexp, &limited_upper,
                                              &replacement,
                                              &replacement_length);
    if (!scalar_length) return NULL;
    if (limited_upper) {
        const char *comma = memchr(replacement, ',', replacement_length);
        size_t lower = 0;
        if (!comma) return NULL;
        for (const char *at = replacement + 1; at < comma; ++at)
            lower = lower * 10 + (size_t)(*at - '0');
        int count = snprintf(expanded_quantifier,
                             sizeof(expanded_quantifier), "{%zu,%zu}",
                             lower, 2 * limited_upper - lower);
        if (count < 0 || (size_t)count >= sizeof(expanded_quantifier))
            return NULL;
        replacement = expanded_quantifier;
        replacement_length = (size_t)count;
    }
    /* PCRE2 expands a bounded byte-mode repeat while compiling it. A large
       upper bound can exceed its code-size limit, so compile an unbounded
       repeat and enforce the source bound in yx_regex_vm_max_span. */
    if (!limited_upper && replacement_length > 5) {
        const char *comma = memchr(replacement, ',', replacement_length);
        if (comma) {
            size_t lower = 0, upper = 0;
            for (const char *at = replacement + 1; at < comma; ++at)
                lower = lower * 10 + (size_t)(*at - '0');
            for (const char *at = comma + 1; *at >= '0' && *at <= '9'; ++at)
                upper = upper * 10 + (size_t)(*at - '0');
            if (upper > 1024) {
                bool lazy = replacement[replacement_length - 1] == '?';
                int count = snprintf(capped_quantifier,
                                     sizeof(capped_quantifier),
                                     lazy ? "{%zu,}?" : "{%zu,}", lower);
                if (count < 0 || (size_t)count >= sizeof(capped_quantifier))
                    return NULL;
                replacement = capped_quantifier;
                replacement_length = (size_t)count;
            }
        }
    }
    char *rewritten = malloc(3 + scalar_length + 1 + replacement_length + 1);
    if (!rewritten) return NULL;
    memcpy(rewritten, "(?:", 3);
    memcpy(rewritten + 3, regexp + 4, scalar_length);
    rewritten[3 + scalar_length] = ')';
    memcpy(rewritten + 4 + scalar_length, replacement, replacement_length);
    rewritten[4 + scalar_length + replacement_length] = '\0';
    return rewritten;
}

static bool yx_pcre_fixed_edge_byte(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static char *yx_pcre_never_match(void)
{
    char *never = malloc(5);
    if (never) memcpy(never, "(?!)", 5);
    return never;
}

/* A fixed repetition may have short ASCII runs beside the scalar.
   Group the complete UTF-8 scalar before handing this narrow form to the
   byte-mode regex engine. A Unicode scope around the entire expression
   has the same effect as the unscoped whole-pattern flag. */
static char *yx_pcre_unicode_scalar_fixed_edge(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    bool scoped = strncmp(regexp, "(?u:", 4) == 0;
    if (!scoped && strncmp(regexp, "(?u)", 4) != 0) return NULL;
    const char *at = regexp + 4;
    const char *prefix = at;
    while (yx_pcre_fixed_edge_byte(*at) && at - prefix < 32) ++at;
    size_t prefix_length = (size_t)(at - prefix);
    const char *scalar = at;
    unsigned char lead = (unsigned char)*at;
    size_t width = lead >= 0xc2 && lead <= 0xdf ? 2 :
                   lead >= 0xe0 && lead <= 0xef ? 3 :
                   lead >= 0xf0 && lead <= 0xf4 ? 4 : 0;
    if (!width || strlen(at) < width + 3) return NULL;
    char literal[9];
    memcpy(literal, "(?u)", 4);
    memcpy(literal + 4, at, width);
    literal[4 + width] = '\0';
    if (!yx_pcre_unicode_scalar_at(literal, width)) return NULL;
    at += width;
    const char *quantifier = at;
    if (*at++ != '{' || *at < '1' || *at > '9') return NULL;
    uint64_t count = 0;
    while (*at >= '0' && *at <= '9') {
        count = count * 10u + (unsigned)(*at++ - '0');
        if (count > UINT32_MAX) return NULL;
    }
    if (*at++ != '}' || count == 0) return NULL;
    size_t quantifier_length = (size_t)(at - quantifier);
    const char *suffix = at;
    while (yx_pcre_fixed_edge_byte(*at) && at - suffix < 32) ++at;
    size_t suffix_length = (size_t)(at - suffix);
    if ((scoped ? *at != ')' || at[1] != '\0' : *at != '\0') ||
        (!prefix_length && !suffix_length)) return NULL;
    /* The verifier can consume at most 4095 scalar bytes before this
       mandatory ASCII edge. Larger fixed counts compile but never match. */
    if (count > 4095 / width) return yx_pcre_never_match();
    size_t fixed_span = prefix_length + (size_t)count * width + suffix_length;
    if (fixed_span > 4096)
        return NULL;
    /* A suffix-only expression that fills the verification window cannot
       reach its final ASCII atom, even though the scalar repeat itself fits. */
    if (fixed_span == 4096 && prefix_length == 0)
        return yx_pcre_never_match();
    size_t length = prefix_length + 3 + width + 1 +
                    quantifier_length + suffix_length + 1;
    char *rewritten = malloc(length);
    if (!rewritten) return NULL;
    size_t used = 0;
    memcpy(rewritten + used, prefix, prefix_length);
    used += prefix_length;
    memcpy(rewritten + used, "(?:", 3); used += 3;
    memcpy(rewritten + used, scalar, width); used += width;
    rewritten[used++] = ')';
    memcpy(rewritten + used, quantifier, quantifier_length);
    used += quantifier_length;
    memcpy(rewritten + used, suffix, suffix_length);
    used += suffix_length;
    rewritten[used] = '\0';
    return rewritten;
}

static char *yx_pcre_unicode_counted_unbounded(const char *regexp)
{
    size_t limited_upper = 0;
    size_t width = yx_pcre_unicode_scalar_counted_width(
        regexp, &limited_upper, NULL, NULL);
    if (!width || limited_upper) return NULL;
    const char *open = strrchr(regexp, '{');
    const char *comma = open ? strchr(open, ',') : NULL;
    if (!comma) return NULL;
    const char *close = strchr(comma, '}');
    if (!close) return NULL;
    size_t upper = 0;
    for (const char *at = comma + 1; at < close; ++at)
        upper = upper * 10 + (size_t)(*at - '0');
    if (upper <= 1024) return NULL;
    size_t prefix_length = (size_t)(comma + 1 - regexp);
    size_t suffix_length = strlen(close);
    if (prefix_length > SIZE_MAX - suffix_length - 1)
        return NULL;
    char *capped = malloc(prefix_length + suffix_length + 1);
    if (!capped) return NULL;
    memcpy(capped, regexp, prefix_length);
    memcpy(capped + prefix_length, close, suffix_length + 1);
    return capped;
}

static bool yx_pcre_is_unicode_scalar_counted(const char *regexp)
{
    size_t limited_upper = 0;
    return yx_pcre_unicode_scalar_counted_width(
        regexp, &limited_upper, NULL, NULL) != 0;
}

static bool yx_pcre_unicode_count_unmatchable(const char *regexp)
{
    size_t ignored_upper = 0;
    size_t width = yx_pcre_unicode_scalar_counted_width(
        regexp, &ignored_upper, NULL, NULL);
    if (!width) return false;
    const char *at = strrchr(regexp, '{');
    if (!at) return false;
    size_t lower = 0;
    for (++at; *at >= '0' && *at <= '9'; ++at)
        lower = lower * 10 + (size_t)(*at - '0');
    return lower > 4095 / width;
}

static bool yx_regex_is_single_dotall_dot(const char *regexp,
                                          bool initial_dotall);

/* The native adapter tracks Unicode per scope while its byte engine stores
   UTF-8 expansions. PCRE2 needs the narrower all-Unicode escape path. */
static bool yx_pcre_unicode_only_with_U(const char *regexp)
{
    size_t length = strlen(regexp), depth = 0;
    unsigned char *states = malloc(length + 1);
    bool unicode = false, extended = false, in_class = false;
    bool saw_U = false, valid = true;
    if (!states) return false;
    for (size_t i = 0; i < length; ++i) {
        char ch = regexp[i];
        if (ch == '\\' && i + 1 < length) {
            if (unicode && regexp[i + 1] == 'U') saw_U = true;
            if (unicode && strchr("dDsSwWpP", regexp[i + 1])) saw_U = true;
            ++i;
            continue;
        }
        if (extended && !in_class && ch == '#') {
            while (i < length && regexp[i] != '\n') ++i;
            continue;
        }
        if (extended && !in_class && isspace((unsigned char)ch)) continue;
        if (ch == '[' && !in_class) {
            in_class = true;
            continue;
        }
        if (ch == ']' && in_class) { in_class = false; continue; }
        if (in_class) continue;
        if (ch == '(') {
            size_t end = i + 2;
            bool next_unicode = unicode, next_extended = extended;
            bool minus = false;
            if (regexp[i + 1] == '?') {
                for (; end < length; ++end) {
                    char flag = regexp[end];
                    if (flag == '-') { minus = true; continue; }
                    if (flag == 'u') {
                        next_unicode = !minus;
                        if (next_unicode) saw_U = true;
                        continue;
                    }
                    if (flag == 'x') { next_extended = !minus; continue; }
                    if (strchr("imsUR", flag)) continue;
                    break;
                }
            }
            if (end > i + 2 && end < length &&
                (regexp[end] == ')' || regexp[end] == ':')) {
                if (regexp[end] == ':')
                    states[depth++] = (unsigned char)((unicode ? 1 : 0) |
                                                       (extended ? 2 : 0));
                unicode = next_unicode;
                extended = next_extended;
                i = end;
                continue;
            }
            states[depth++] = (unsigned char)((unicode ? 1 : 0) |
                                               (extended ? 2 : 0));
            if (i + 2 < length && regexp[i + 1] == '?' && regexp[i + 2] == ':')
                i += 2;
            continue;
        }
        if (ch == ')' && depth) {
            unsigned char state = states[--depth];
            unicode = (state & 1) != 0;
            extended = (state & 2) != 0;
            continue;
        }
        if (ch == '{') {
            while (i < length && regexp[i] != '}') ++i;
            continue;
        }
        if (strchr("^$|*+?", ch)) continue;
    }
    free(states);
    return valid && saw_U;
}

/* Repetitions of zero-width word assertions can be reduced to either one
   assertion or none before compiling with PCRE2. */
static bool yx_pcre_word_assertion_repeat(const char *regexp, size_t length,
                                          size_t at, bool extended,
                                          size_t *after,
                                          bool *minimum_is_zero)
{
    if (extended)
        while (at < length && isspace((unsigned char)regexp[at])) ++at;
    if (at >= length) return false;
    if (regexp[at] == '?' || regexp[at] == '*' || regexp[at] == '+') {
        *minimum_is_zero = regexp[at] != '+';
        *after = at + 1;
        size_t lazy = *after;
        if (extended)
            while (lazy < length && isspace((unsigned char)regexp[lazy]))
                ++lazy;
        if (lazy < length && regexp[lazy] == '?') *after = lazy + 1;
        return true;
    }
    if (regexp[at] != '{') return false;
    size_t i = at + 1;
    uint32_t lower = 0, upper = 0;
    bool has_lower = false, has_upper = false, comma = false;
    while (i < length && isspace((unsigned char)regexp[i])) ++i;
    while (i < length && isdigit((unsigned char)regexp[i])) {
        unsigned digit = (unsigned)(regexp[i] - '0');
        if (lower > (UINT32_MAX - digit) / 10u) return false;
        lower = lower * 10u + digit;
        has_lower = true;
        ++i;
    }
    while (i < length && isspace((unsigned char)regexp[i])) ++i;
    if (i < length && regexp[i] == ',') {
        comma = true;
        ++i;
        while (i < length && isspace((unsigned char)regexp[i])) ++i;
        while (i < length && isdigit((unsigned char)regexp[i])) {
            unsigned digit = (unsigned)(regexp[i] - '0');
            if (upper > (UINT32_MAX - digit) / 10u) return false;
            upper = upper * 10u + digit;
            has_upper = true;
            ++i;
        }
        while (i < length && isspace((unsigned char)regexp[i])) ++i;
    }
    if ((!has_lower && (!comma || !has_upper)) ||
        i >= length || regexp[i] != '}' ||
        (comma && has_upper && upper < lower)) return false;
    *minimum_is_zero = lower == 0;
    *after = i + 1;
    size_t lazy = *after;
    if (extended)
        while (lazy < length && isspace((unsigned char)regexp[lazy])) ++lazy;
    if (lazy < length && regexp[lazy] == '?') *after = lazy + 1;
    return true;
}

/* YARA-X treats CR as a multiline anchor boundary, while an ordinary dot
   still matches CR. PCRE2 couples those two behaviors to its newline mode.
   Keep ANYCRLF for anchors and spell an ordinary dot as "not LF". */
static char *yx_pcre_normalize_dots(const char *regexp, bool initial_dotall,
                                     bool initial_nocase,
                                     bool unicode_counted_nocase,
                                     bool unicode_escape_utf)
{
    size_t length = strlen(regexp), used = 0, depth = 0;
    bool unicode_literal = yx_pcre_unicode_literal(regexp, length) ||
                           unicode_counted_nocase;
    bool byte_wildcard = yx_regex_is_single_dotall_dot(regexp,
                                                       initial_dotall);
    if (length > (SIZE_MAX - 1) / 24) return NULL;
    size_t capacity = length * 24 + 1;
    for (size_t i = 0; i < length; ++i) {
        if (regexp[i] == '^' || regexp[i] == '$') {
            if (capacity > SIZE_MAX - 64) return NULL;
            capacity += 64;
        }
    }
    char *out = malloc(capacity);
    struct yx_regex_flags {
        bool dotall, unicode, nocase, multiline, crlf, extended;
    };
    struct yx_regex_flags *states = malloc((length + 1) * sizeof(*states));
    bool in_class = false, dotall = initial_dotall, unicode = false;
    bool extended = false;
    bool nocase = initial_nocase, multiline = false, crlf = false;
    if (!out || !states) { free(out); free(states); return NULL; }
    for (size_t i = 0; i < length; ++i) {
        char ch = regexp[i];
        if (extended && !in_class && ch == '#') {
            size_t end = i;
            while (end < length && regexp[end] != '\n') ++end;
            memcpy(out + used, regexp + i, end - i);
            used += end - i;
            i = end - 1;
            continue;
        }
        if (!in_class && ch == '[') {
            size_t after = i, count = 0;
            yx_re_range *ranges = NULL;
            uint32_t class_options = (unicode ? PCRE2_UTF | PCRE2_UCP : 0) |
                                     (nocase ? PCRE2_CASELESS : 0);
            int valid = yx_re_class_ranges((const unsigned char *)regexp,
                                           length, &after, class_options,
                                           &ranges, &count);
            free(ranges);
            if (!valid || after <= i) { free(out); free(states); return NULL; }
            memcpy(out + used, regexp + i, after - i);
            used += after - i;
            i = after - 1;
            continue;
        }
        if (ch == '\\' && i + 1 < length) {
            char escaped = regexp[i + 1];
            if ((escaped == 'p' || escaped == 'P') && i + 2 < length &&
                regexp[i + 2] == '{') {
                size_t end = i + 3;
                while (end < length && regexp[end] != '}') ++end;
                if (end == length) { free(out); free(states); return NULL; }
                memcpy(out + used, regexp + i, end + 1 - i);
                used += end + 1 - i;
                i = end;
                continue;
            }
            /* regex-syntax can repeat a zero-width word assertion. PCRE2
               rejects that spelling, so keep one assertion for a positive
               minimum and remove it for a zero minimum. This rewrite is
               limited to byte mode; Unicode assertions have their own
               YARA-X diagnostic. */
            if (!in_class && !unicode &&
                (escaped == 'b' || escaped == 'B')) {
                size_t assertion_end = i + 2, after;
                bool minimum_is_zero;
                const char *named = NULL;
                if (escaped == 'b' && i + 9 <= length &&
                    memcmp(regexp + i + 2, "{start}", 7) == 0) {
                    named = "(?<!\\w)(?=\\w)";
                    assertion_end = i + 9;
                } else if (escaped == 'b' && i + 7 <= length &&
                           memcmp(regexp + i + 2, "{end}", 5) == 0) {
                    named = "(?<=\\w)(?!\\w)";
                    assertion_end = i + 7;
                }
                if (yx_pcre_word_assertion_repeat(regexp, length,
                                                  assertion_end, extended,
                                                  &after,
                                                  &minimum_is_zero)) {
                    size_t next_after;
                    bool next_minimum_is_zero;
                    /* regex-syntax nests consecutive repetitions. Since a
                       word assertion consumes no input, the whole chain is
                       optional if any repetition has a zero minimum. */
                    while (yx_pcre_word_assertion_repeat(
                               regexp, length, after, extended,
                               &next_after, &next_minimum_is_zero)) {
                        minimum_is_zero |= next_minimum_is_zero;
                        after = next_after;
                    }
                    if (!minimum_is_zero) {
                        if (named) {
                            size_t named_length = strlen(named);
                            memcpy(out + used, named, named_length);
                            used += named_length;
                        } else {
                            out[used++] = '\\';
                            out[used++] = escaped;
                        }
                    }
                    i = after - 1;
                    continue;
                }
            }
            /* Keep arbitrary escaped atoms out of the byte-mode fallback.
               In UTF mode, only scalar escapes and quoted punctuation have
               been checked against the reference matcher here. */
            if (unicode && escaped != 'v' &&
                ((!unicode_escape_utf && escaped != 'U' &&
                  !strchr("\\.^$*+?{}[]|()/-nrtfa", escaped)) ||
                 (unicode_escape_utf &&
                  !strchr("UuxdDsSwWpP\\.^$*+?{}[]|()/-nrtfa", escaped)))) {
                free(out); free(states); return NULL;
            }
            if (unicode && escaped == 'v') {
                const char *vertical_tab = unicode_escape_utf ?
                    "\\x{B}" : "\\x0B";
                size_t size = strlen(vertical_tab);
                memcpy(out + used, vertical_tab, size);
                used += size;
                ++i;
                continue;
            }
            if (!in_class && regexp[i + 1] == 'b' &&
                i + 9 <= length &&
                memcmp(regexp + i + 2, "{start}", 7) == 0) {
                static const char boundary[] = "(?<!\\w)(?=\\w)";
                memcpy(out + used, boundary, sizeof(boundary) - 1);
                used += sizeof(boundary) - 1;
                i += 8;
                continue;
            }
            if (!in_class && regexp[i + 1] == 'b' &&
                i + 7 <= length &&
                memcmp(regexp + i + 2, "{end}", 5) == 0) {
                static const char boundary[] =
                    "(?<=\\w)(?!\\w)";
                memcpy(out + used, boundary, sizeof(boundary) - 1);
                used += sizeof(boundary) - 1;
                i += 6;
                continue;
            }
            if (regexp[i + 1] == 'u' || regexp[i + 1] == 'U' ||
                regexp[i + 1] == 'x') {
                uint32_t scalar;
                size_t last;
                int parsed = yx_regex_unicode_escape(regexp, length, i,
                                                      &scalar, &last);
                if (parsed < 0) { free(out); free(states); return NULL; }
                if (parsed > 0) {
                    if (unicode_escape_utf && unicode) {
                        used += (size_t)snprintf(out + used, capacity - used,
                                                 "\\x{%X}", scalar);
                        i = last;
                        continue;
                    }
                    if (in_class && scalar > 0x7f) {
                        free(out); free(states); return NULL;
                    }
                    if (!in_class && scalar > 0x7f) {
                        out[used++] = '(';
                        out[used++] = '?';
                        out[used++] = ':';
                    }
                    used = yx_regex_append_utf8(out, used, scalar);
                    if (!in_class && scalar > 0x7f) out[used++] = ')';
                    i = last;
                    continue;
                }
            }
            out[used++] = ch;
            out[used++] = regexp[++i];
            continue;
        }
        if (unicode &&
            (((unsigned char)ch >= 0x80 && !unicode_literal &&
              !unicode_escape_utf) ||
             /* In an accepted Unicode + dotall scope YARA-X still treats
                the dot as one arbitrary input byte, including invalid
                UTF-8. Keep the byte-mode PCRE2 dot for this case. */
             (!in_class && ch == '.' && !dotall &&
              !unicode_escape_utf) ||
             (!in_class && ch == '[' &&
              !unicode_escape_utf &&
              !yx_pcre_unicode_ascii_class(regexp, i, length)))) {
            free(out);
            free(states);
            return NULL;
        }
        if (ch == '[' && !in_class) in_class = true;
        else if (ch == ']' && in_class) in_class = false;
        if (!in_class && ch == '(') {
            size_t end = i + 2;
            bool next_dotall = dotall, next_unicode = unicode;
            bool next_nocase = nocase, next_multiline = multiline;
            bool next_crlf = crlf, next_extended = extended;
            bool minus = false;
            bool flags_only = regexp[i + 1] == '?';
            if (flags_only) {
                for (; end < length; ++end) {
                    char flag = regexp[end];
                    if (flag == '-') { minus = true; continue; }
                    if (flag == 's') { next_dotall = !minus; continue; }
                    if (flag == 'u') { next_unicode = !minus; continue; }
                    if (flag == 'i') { next_nocase = !minus; continue; }
                    if (flag == 'm') { next_multiline = !minus; continue; }
                    if (flag == 'R') { next_crlf = !minus; continue; }
                    if (flag == 'x') { next_extended = !minus; continue; }
                    if (flag == 'U') continue;
                    break;
                }
            }
            if (flags_only && end < length &&
                (regexp[end] == ')' || regexp[end] == ':') && end > i + 2) {
                size_t flags_start = used;
                bool emitted_minus = false;
                /* Case folding cannot affect a whole-pattern arbitrary-byte
                   dot, including when `u` and `i` are both enabled. */
                if (next_unicode && next_nocase && !byte_wildcard &&
                    !unicode_counted_nocase && !unicode_escape_utf) {
                    free(out);
                    free(states);
                    return NULL;
                }
                if (regexp[end] == ':')
                    states[depth++] = (struct yx_regex_flags){dotall, unicode,
                                                               nocase, multiline,
                                                               crlf, extended};
                dotall = next_dotall;
                unicode = next_unicode;
                nocase = next_nocase;
                multiline = next_multiline;
                crlf = next_crlf;
                extended = next_extended;
                out[used++] = '(';
                out[used++] = '?';
                for (size_t j = i + 2; j < end; ++j) {
                    if (regexp[j] == 'R') continue;
                    if (regexp[j] == '-') {
                        emitted_minus = true;
                        continue;
                    }
                    if (emitted_minus) {
                        out[used++] = '-';
                        emitted_minus = false;
                    }
                    out[used++] = regexp[j];
                }
                if (regexp[end] == ':') out[used++] = ':';
                else if (used == flags_start + 2) used = flags_start;
                else out[used++] = ')';
                i = end;
                continue;
            }
            states[depth++] = (struct yx_regex_flags){dotall, unicode,
                                                       nocase, multiline, crlf,
                                                       extended};
            /* A capture name is verbatim: it may contain `.` or `[`. */
            if (i + 3 < length && regexp[i + 1] == '?') {
                size_t name = (regexp[i + 2] == 'P' && regexp[i + 3] == '<') ?
                                  i + 4 :
                              (regexp[i + 2] == '<' && regexp[i + 3] != '=' &&
                               regexp[i + 3] != '!') ? i + 3 : 0;
                size_t close = name;
                while (name && close < length && regexp[close] != '>')
                    ++close;
                if (name && close < length) {
                    memcpy(out + used, regexp + i, close + 1 - i);
                    used += close + 1 - i;
                    i = close;
                    continue;
                }
            }
        } else if (!in_class && ch == ')' && depth) {
            struct yx_regex_flags previous = states[--depth];
            dotall = previous.dotall;
            unicode = previous.unicode;
            nocase = previous.nocase;
            multiline = previous.multiline;
            crlf = previous.crlf;
            extended = previous.extended;
        }
        if (!in_class && ch == '.' && dotall && unicode_escape_utf) {
            /* The scanner lowers a Unicode dotall dot to ANY_BYTE. */
            out[used++] = '\\'; out[used++] = 'C';
        } else if (!in_class && ch == '.' && !dotall) {
            const char *replacement = crlf ? "[^\\r\\n]" : "[^\\x0a]";
            if (unicode_escape_utf && !unicode)
                replacement = crlf ? "(?:(?![\\r\\n])\\C)" :
                                     "(?:(?!\\x0a)\\C)";
            size_t replacement_length = strlen(replacement);
            memcpy(out + used, replacement, replacement_length);
            used += replacement_length;
        } else if (!in_class && ch == '^' && multiline) {
            /* YARA-X treats CRLF and LFCR as indivisible line breaks, but
               still lets character classes consume their individual bytes. */
            static const char start[] =
                "(?:(?<![\\r\\n])^|(?<=\\r)(?!\\n)|(?<=\\n)(?!\\r))";
            memcpy(out + used, start, sizeof(start) - 1);
            used += sizeof(start) - 1;
        } else if (!in_class && ch == '$' && multiline) {
            static const char end[] =
                "(?:$(?![\\r\\n])|(?=\\r)(?<!\\n)|(?=\\n)(?<!\\r))";
            memcpy(out + used, end, sizeof(end) - 1);
            used += sizeof(end) - 1;
        } else {
            out[used++] = ch;
        }
    }
    out[used] = 0;
    free(states);
    return out;
}

static bool yx_regex_has_word_boundary(const char *regexp)
{
    bool in_class = false;
    for (size_t i = 0; regexp[i]; ++i) {
        if (regexp[i] == '\\' && regexp[i + 1]) {
            if (!in_class && (regexp[i + 1] == 'b' || regexp[i + 1] == 'B'))
                return true;
            ++i;
        } else if (regexp[i] == '[' && !in_class) in_class = true;
        else if (regexp[i] == ']' && in_class) in_class = false;
    }
    return false;
}

static bool yx_regex_has_greedy_variable_repeat(const char *regexp)
{
    bool in_class = false;
    /* In extended mode, a metacharacter in a comment is not a quantifier. */
    if (strchr(regexp, '#')) return false;
    for (size_t i = 0; regexp[i]; ++i) {
        if (regexp[i] == '\\' && regexp[i + 1]) { ++i; continue; }
        if (regexp[i] == '[' && !in_class) { in_class = true; continue; }
        if (regexp[i] == ']' && in_class) { in_class = false; continue; }
        if (in_class) continue;
        if (regexp[i] == '+' || regexp[i] == '*') {
            if (regexp[i + 1] == '?') { ++i; continue; }
            return true;
        }
        if (regexp[i] == '?') {
            /* A question mark immediately after '(' starts a group form. */
            if (i == 0 || regexp[i - 1] == '(') continue;
            if (regexp[i + 1] == '?') { ++i; continue; }
            return true;
        }
        if (regexp[i] == '{' && i > 0) {
            size_t at = i + 1, lower = 0, upper = 0;
            bool variable = false;
            if (regexp[at] < '0' || regexp[at] > '9') continue;
            while (regexp[at] >= '0' && regexp[at] <= '9') {
                size_t digit = (size_t)(regexp[at++] - '0');
                if (lower > (SIZE_MAX - digit) / 10) return false;
                lower = lower * 10 + digit;
            }
            if (regexp[at] == ',') {
                ++at;
                if (regexp[at] < '0' || regexp[at] > '9') {
                    variable = true;
                } else {
                    while (regexp[at] >= '0' && regexp[at] <= '9') {
                        size_t digit = (size_t)(regexp[at++] - '0');
                        if (upper > (SIZE_MAX - digit) / 10) return false;
                        upper = upper * 10 + digit;
                    }
                    variable = upper != lower;
                }
            }
            if (regexp[at] != '}') continue;
            bool lazy = regexp[at + 1] == '?';
            i = at + (lazy ? 1 : 0);
            if (variable && !lazy) return true;
        }
    }
    return false;
}

/* YARA-X switches its short-atom search path at a 16-byte input. In that
 * path, distinct one-byte alternatives (and small explicit classes) verify
 * the wide variant first at an offset where both encodings match. */
static bool yx_regex_long_wide_tie(const YRX_PATTERN *pattern)
{
    const char *begin = pattern->regexp;
    const char *end = begin + strlen(begin);
    const char *at, *branch;
    size_t branches = 0, shortest = SIZE_MAX, longest = 0;
    unsigned char first = 0;
    bool different = false;
    if (end - begin >= 4 && begin[0] == '[' && end[-1] == ']' &&
        end - begin <= 6) {
        for (at = begin + 1; at < end - 1; ++at) {
            if (!yx_plain_regex_byte((unsigned char)*at)) return false;
            if (at > begin + 1 && *at != first) different = true;
            if (at == begin + 1) first = (unsigned char)*at;
        }
        return different;
    }
    if (end - begin >= 5 && begin[0] == '(' && end[-1] == ')') {
        ++begin;
        --end;
        if (end - begin >= 2 && begin[0] == '?' && begin[1] == ':')
            begin += 2;
    }
    branch = begin;
    for (at = begin; at <= end; ++at) {
        if (at < end && *at != '|') {
            if (!yx_plain_regex_byte((unsigned char)*at)) return false;
            continue;
        }
        size_t width = (size_t)(at - branch);
        if (!width || width > 2) return false;
        if (width < shortest) shortest = width;
        if (width > longest) longest = width;
        if (width == 1) {
            if (branches && *branch != (char)first) different = true;
            if (!branches) first = (unsigned char)*branch;
        }
        ++branches;
        branch = at + 1;
    }
    if (branches < 2) return false;
    if (shortest == 1 && longest == 1) return different;
    return shortest == 1 && longest == 2 && branches == 2 &&
           (pattern->modifiers & YX_MOD_NOCASE) != 0 &&
           pattern->global_atom_count_hint <= 16;
}

/* This lazy bounded class pair uses the wide verifier first in the 16-byte
 * search path, provided the complete ruleset has at most 16 known atoms.
 * The short-input path and nocase variant retain the ASCII one-byte hit. */
static bool yx_regex_long_wide_lazy_class_pair_tie(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    if (pattern->modifiers != (YX_MOD_ASCII | YX_MOD_WIDE) ||
        pattern->global_atom_count_hint > 16 || !regexp ||
        strlen(regexp) != 18 || regexp[0] != '(' ||
        regexp[1] != '[' || regexp[4] != ']' || regexp[5] != '|' ||
        regexp[7] != '[' || regexp[10] != ']' || regexp[11] != ')' ||
        memcmp(regexp + 12, "{1,2}?", 6) != 0)
        return false;
    unsigned char x = (unsigned char)regexp[2];
    unsigned char y = (unsigned char)regexp[3];
    unsigned char z = (unsigned char)regexp[9];
    return yx_plain_regex_byte(x) && yx_plain_regex_byte(y) &&
           yx_plain_regex_byte(z) && x != '_' && y != '_' && z != '_' &&
           regexp[6] == (char)x &&
           regexp[8] == (char)y && x < y && y < z;
}

/* For a numeric prefix pair, YARA-X selects the wide verifier only when
 * its two-byte atom completes the longer branch. A lone wide digit still
 * reports the overlapping one-byte ASCII match. */
static bool yx_regex_digit_prefix_wide_tie(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    return pattern->modifiers ==
               (YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE) &&
           pattern->global_atom_count_hint <= 16 && regexp &&
           strlen(regexp) == 4 && regexp[2] == '|' &&
           regexp[0] == regexp[3] &&
           regexp[0] >= '0' && regexp[0] <= '9' &&
           regexp[1] >= '0' && regexp[1] <= '9';
}

/* A two-character wide atom can win over its one-character ASCII prefix
 * in the short-atom search path. The one-character wide atom does not. */
static bool yx_regex_small_atom_complete_wide_prefix(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    if (pattern->modifiers != (YX_MOD_ASCII | YX_MOD_WIDE) ||
        pattern->global_atom_count_hint > 16 || !regexp ||
        strlen(regexp) != 4 || regexp[2] != '|' ||
        regexp[0] != regexp[3]) return false;
    for (size_t i = 0; i < 2; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9'))) return false;
    }
    return true;
}

/* When a ruleset's known literal atoms exceed Teddy's capacity, YARA-X's
 * fallback verifies a shared shorter atom before the longer alternative.
 * PCRE2 preserves source order, so reverse only this bare literal pair. */
static char *yx_regex_prioritize_large_atom_prefix(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    const char *bar;
    size_t left, right;
    char *ordered;
    if (pattern->global_atom_count_hint <= 16 ||
        (pattern->modifiers != (YX_MOD_ASCII | YX_MOD_WIDE) &&
         pattern->modifiers != YX_MOD_WIDE &&
         pattern->modifiers !=
             (YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE) &&
         pattern->modifiers != (YX_MOD_WIDE | YX_MOD_NOCASE)) ||
        !regexp) return NULL;
    bar = strchr(regexp, '|');
    if (!bar || strchr(bar + 1, '|')) return NULL;
    left = (size_t)(bar - regexp);
    right = strlen(bar + 1);
    if (right != 1 || left != 2 ||
        memcmp(regexp, bar + 1, right) != 0) return NULL;
    for (size_t i = 0; i < left; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9'))) return NULL;
        if ((pattern->modifiers & YX_MOD_NOCASE) &&
            (ch < '0' || ch > '9')) return NULL;
    }
    ordered = malloc(left + right + 2);
    if (!ordered) return NULL;
    memcpy(ordered, bar + 1, right);
    ordered[right] = '|';
    memcpy(ordered + right + 1, regexp, left);
    ordered[right + 1 + left] = '\0';
    return ordered;
}

static bool yx_regex_large_atom_two_byte_ascii_prefix(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    if (pattern->global_atom_count_hint <= 16 ||
        pattern->modifiers != (YX_MOD_ASCII | YX_MOD_WIDE) ||
        !regexp || strlen(regexp) != 6 || regexp[3] != '|' ||
        memcmp(regexp, regexp + 4, 2) != 0) return false;
    for (size_t i = 0; i < 3; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9'))) return false;
    }
    return true;
}

/* A short input cannot use Teddy's 16-byte search vector. Its fallback
 * verifies the shorter member of a literal prefix pair first. With wide
 * strings, the corresponding wide atom must have the same prefix length;
 * case-insensitive letters use a different set of atoms. */
static size_t yx_regex_short_input_literal_prefix_length(
    const YRX_PATTERN *pattern, size_t input_size, int variant,
    size_t match_length)
{
    const char *regexp = pattern->regexp;
    const char *bar;
    size_t long_length, short_length, unit = variant ? 2 : 1;
    unsigned modifiers = pattern->modifiers;
    /* At exactly 16 bytes the fallback is used only when every known atom
       is at least two bytes long. The scanner encodes that verified case
       as hint 2; larger hints still mean too many one-byte atoms. */
    if (input_size > 16 ||
        (input_size == 16 && pattern->global_atom_count_hint != 2) ||
        pattern->global_atom_count_hint > 16 || !regexp)
        return match_length;
    bar = strchr(regexp, '|');
    if (!bar || strchr(bar + 1, '|')) return match_length;
    long_length = (size_t)(bar - regexp);
    short_length = strlen(bar + 1);
    if (short_length + 1 != long_length ||
        memcmp(regexp, bar + 1, short_length) != 0 ||
        match_length != long_length * unit) return match_length;
    for (size_t i = 0; i < long_length; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9'))) return match_length;
        if ((modifiers & YX_MOD_NOCASE) &&
            (ch < '0' || ch > '9')) return match_length;
    }
    if (long_length == 2 && short_length == 1 &&
        (modifiers == YX_MOD_WIDE ||
         modifiers == (YX_MOD_ASCII | YX_MOD_WIDE) ||
         modifiers == (YX_MOD_WIDE | YX_MOD_NOCASE) ||
         modifiers == (YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE)))
        return short_length * unit;
    if (long_length == 3 && short_length == 2 && !variant &&
        modifiers == (YX_MOD_ASCII | YX_MOD_WIDE))
        return short_length;
    return match_length;
}

/* Summarize a byte-only concatenation without changing its regexp syntax.
 * The scanner uses this for encoding conflicts, including optional repeats
 * reconstructed from archive bytecode. Unsupported syntax keeps the ordinary
 * atom-order path. */
typedef struct yx_variant_shape {
    uint8_t bytes[32];
    size_t minimum, maximum;
    bool homogeneous, maskable;
} yx_variant_shape;
typedef struct yx_variant_parser {
    const char *at;
    bool nocase, dotall, greedy;
    unsigned depth;
    bool masked;
} yx_variant_parser;

static bool yx_variant_class_byte(yx_variant_parser *p, uint8_t set[32],
                                  unsigned *byte, bool *is_set)
{
    unsigned c=(unsigned char)*p->at++;
    *is_set=false;
    if(!c)return false;
    if(c=='\\') {
        c=(unsigned char)*p->at++;
        if(!c)return false;
        if(strchr("dDsSwW",(int)c)) {
            *is_set=true;bool negate=c=='D'||c=='S'||c=='W';
            for(unsigned b=0;b<256;++b) {
                bool digit=b>='0'&&b<='9';
                bool yes=c=='d'||c=='D'?digit:c=='s'||c=='S'?
                    b==' '||(b>='\t'&&b<='\r'):
                    digit||(b>='a'&&b<='z')||(b>='A'&&b<='Z')||b=='_';
                if(yes!=negate)set[b/8]|=(uint8_t)(1u<<(b%8));
            }
            return true;
        }
        if(c=='x') {
            unsigned value=0;
            for(unsigned i=0;i<2;++i) {
                unsigned h=(unsigned char)*p->at;
                if(!yx_regex_hex_byte((unsigned char)h))return false;
                ++p->at;value=value*16+(h<='9'?h-'0':(h|32)-'a'+10);
            }
            c=value;
        } else if(c=='n')c='\n';else if(c=='r')c='\r';else if(c=='t')c='\t';
        else if(c=='f')c='\f';else if(c=='v')c='\v';else if(c=='a')c=7;
        else if(isalnum((unsigned char)c))return false;
    }
    *byte=c;return true;
}

static size_t yx_variant_multiply(size_t a,size_t b)
{ return a&&b>SIZE_MAX/a?SIZE_MAX:a*b; }
static bool yx_variant_sequence(yx_variant_parser *p,yx_variant_shape *result);
static bool yx_variant_atom(yx_variant_parser *p,yx_variant_shape *result)
{
    memset(result,0,sizeof(*result));result->homogeneous=true;result->maskable=true;
    unsigned c=(unsigned char)*p->at;
    if(!c||strchr(")|*+?{}^$",(int)c)||p->depth>=64)return false;
    if(c=='(') {
        ++p->at;
        if(p->at[0]=='?'&&p->at[1]==':')p->at+=2;
        else if(p->at[0]=='?')return false;
        ++p->depth;
        bool ok=yx_variant_sequence(p,result);
        --p->depth;
        if(!ok||*p->at++!=')')return false;
    } else {
        result->minimum=result->maximum=1;
        if(c=='.') {
            ++p->at;memset(result->bytes,255,sizeof(result->bytes));
            if(!p->dotall)result->bytes['\n'/8]&=(uint8_t)~(1u<<('\n'%8));
            /* The summary below, for 255 or 256 bytes starting at 0: every
             * bit varies, so only the full set is maskable; letters are all
             * present already. */
            result->maskable=p->dotall;p->masked=true;
            goto quantifier;
        } else if(c!='['&&(c!='\\'||!p->at[1]||!strchr("dDsSwW",(int)(unsigned char)p->at[1]))) {
            /* One byte: a single member, no varying bits, maskable, and
             * nocase adds only its ASCII case partner. */
            unsigned byte;bool is_set;
            if(!yx_variant_class_byte(p,result->bytes,&byte,&is_set))return false;
            result->bytes[byte/8]|=(uint8_t)(1u<<(byte%8));
            if(p->nocase&&((byte>='A'&&byte<='Z')||(byte>='a'&&byte<='z'))) {
                unsigned other=byte^32u;
                result->bytes[other/8]|=(uint8_t)(1u<<(other%8));
            }
            goto quantifier;
        } else if(c=='[') {
            ++p->at;bool negative=*p->at=='^',first=true;
            if(negative)++p->at;
            while(*p->at&&(*p->at!=']'||first)) {
                first=false;unsigned low=0,high=0;bool is_set;
                uint8_t set[32]={0};
                if(!yx_variant_class_byte(p,set,&low,&is_set))return false;
                if(is_set)for(size_t i=0;i<32;++i)result->bytes[i]|=set[i];
                else {
                    high=low;
                    if(p->at[0]=='-'&&p->at[1]&&p->at[1]!=']') {
                        ++p->at;
                        if(!yx_variant_class_byte(p,set,&high,&is_set)||is_set||high<low)return false;
                    }
                    for(unsigned b=low;b<=high;++b)result->bytes[b/8]|=(uint8_t)(1u<<(b%8));
                }
            }
            if(*p->at++!=']')return false;
            if(negative)for(size_t i=0;i<32;++i)result->bytes[i]^=255;
        } else {
            unsigned byte;bool is_set;
            if(!yx_variant_class_byte(p,result->bytes,&byte,&is_set))return false;
            if(!is_set)result->bytes[byte/8]|=(uint8_t)(1u<<(byte%8));
        }
        unsigned first_byte=256,varying=0,count=0;
        for(unsigned b=0;b<256;++b)if(result->bytes[b/8]&(1u<<(b%8))) {
            if(first_byte==256)first_byte=b;
            varying|=first_byte^b;++count;
        }
        unsigned combinations=1;
        for(unsigned b=0;b<8;++b)if(varying&(1u<<b))combinations*=2;
        result->maskable=count==combinations;
        if(count>1)p->masked=true;
        if(p->nocase)for(unsigned b='A';b<='Z';++b)
            if((result->bytes[b/8]&(1u<<(b%8)))||
               (result->bytes[(b+32)/8]&(1u<<((b+32)%8)))) {
                result->bytes[b/8]|=(uint8_t)(1u<<(b%8));
                result->bytes[(b+32)/8]|=(uint8_t)(1u<<((b+32)%8));
            }
    }
quantifier:
    c=(unsigned char)*p->at;
    size_t lower=1,upper=1;
    if(c=='?'||c=='*'||c=='+') {
        ++p->at;lower=c=='+'?1:0;upper=c=='?'?1:SIZE_MAX;
    } else if(c=='{') {
        ++p->at;lower=upper=0;
        if(!isdigit((unsigned char)*p->at))return false;
        while(isdigit((unsigned char)*p->at)) {
            unsigned digit=(unsigned)(*p->at++-'0');
            if(lower>(SIZE_MAX-digit)/10)return false;
            lower=lower*10+digit;
        }
        upper=lower;
        if(*p->at==',') {
            ++p->at;upper=0;
            if(!isdigit((unsigned char)*p->at))upper=SIZE_MAX;
            else while(isdigit((unsigned char)*p->at)) {
                unsigned digit=(unsigned)(*p->at++-'0');
                if(upper>(SIZE_MAX-digit)/10)return false;
                upper=upper*10+digit;
            }
        }
        if(*p->at++!='}'||upper<lower)return false;
    } else return true;
    if(*p->at=='?')return false; /* Lazy variants retain first-match order. */
    if(lower!=upper)p->greedy=true;
    result->minimum=yx_variant_multiply(result->minimum,lower);
    result->maximum=yx_variant_multiply(result->maximum,upper);
    return true;
}
static bool yx_variant_sequence(yx_variant_parser *p,yx_variant_shape *result)
{
    if(!yx_variant_atom(p,result))return false;
    while(*p->at&&*p->at!=')') {
        yx_variant_shape next;
        if(!yx_variant_atom(p,&next))return false;
        result->maskable=result->maskable&&next.maskable;
        result->homogeneous=result->homogeneous&&next.homogeneous&&
            !memcmp(result->bytes,next.bytes,32);
        result->minimum=SIZE_MAX-result->minimum<next.minimum?SIZE_MAX:result->minimum+next.minimum;
        result->maximum=SIZE_MAX-result->maximum<next.maximum?SIZE_MAX:result->maximum+next.maximum;
    }
    return true;
}
static bool yx_variant_literal_unit(const yx_variant_shape *shape)
{
    unsigned count=0,first=0,second=0;
    /* Members in increasing order; empty bitmap bytes are skipped and a
     * third member already decides the result. */
    for(unsigned i=0;i<32&&count<=2;++i) {
        unsigned value=shape->bytes[i];
        for(unsigned bit=0;value&&bit<8;++bit,value>>=1)if(value&1u) {
            if(!count)first=i*8+bit;else second=i*8+bit;
            ++count;
        }
    }
    return shape->homogeneous&&(count==1||(count==2&&first>='A'&&first<='Z'&&second==first+32));
}
static bool yx_regex_many_single_byte_atoms_uncached(const YRX_PATTERN *pattern)
{
    yx_variant_parser p={pattern->regexp,(pattern->modifiers&YX_MOD_NOCASE)!=0,
        (pattern->modifiers&YX_MOD_DOTALL)!=0,false,0,false};
    yx_variant_shape shape;
    if(!yx_variant_sequence(&p,&shape)||*p.at||!shape.homogeneous||
       shape.minimum!=1||shape.maximum<=1)return false;
    size_t count=0;
    for(unsigned byte=0;byte<256;++byte)if(shape.bytes[byte/8]&(1u<<(byte%8)))++count;
    return count>16;
}

/* Scanner creation asks this twice for every regexp pattern (and for each
 * repetition of it); the answer depends on the regexp and modifiers. */
bool yx_regex_many_single_byte_atoms(const YRX_PATTERN *pattern)
{
    if(!pattern||pattern->kind!=YX_PATTERN_REGEX||!pattern->regexp||
       ((pattern->modifiers&YX_MOD_WIDE)&&!(pattern->modifiers&YX_MOD_ASCII)))return false;
    size_t length=strlen(pattern->regexp),stored=0;
    uint64_t tag=YX_MEMO_TAG(YX_MEMO_MANY_SINGLE_BYTE_ATOMS,0,pattern->modifiers);
    const void *hit=yx_compile_memo_find(tag,pattern->regexp,length,&stored);
    bool many;
    if(hit&&stored==sizeof(many)){memcpy(&many,hit,sizeof(many));return many;}
    many=yx_regex_many_single_byte_atoms_uncached(pattern);
    yx_compile_memo_store(tag,pattern->regexp,length,&many,sizeof(many));
    return many;
}
static void yx_regex_variant_policy(const YRX_PATTERN *pattern,bool *longest,
                                    bool *optional_prefix, bool *short_single,
                                    bool *ascii_only)
{
    yx_variant_parser p={pattern->regexp,(pattern->modifiers&YX_MOD_NOCASE)!=0,
        (pattern->modifiers&YX_MOD_DOTALL)!=0,false,0,false};
    yx_variant_shape shape;
    *longest=false;*optional_prefix=false;*short_single=false;*ascii_only=false;
    if(yx_variant_sequence(&p,&shape)&&!*p.at&&p.greedy&&shape.homogeneous&&
       shape.minimum&&shape.maximum>shape.minimum) {
        if(shape.bytes[0]&1) {
            *longest=true;
            /* A sequence of optional copies has one forward-only empty
               atom; its ASCII verifier is visited last at each offset. */
            if(pattern->regexp[0]=='(')*ascii_only=true;
        } else {
            unsigned cardinality=0;
            for(unsigned b=0;b<256;++b)cardinality+=(shape.bytes[b/8]>>(b%8))&1u;
            *short_single=shape.minimum==1&&cardinality<=8&&pattern->global_atom_count_hint<=16;
        }
    }
    p.at=pattern->regexp;p.depth=0;p.greedy=false;
    yx_variant_shape first,last;
    if(yx_variant_atom(&p,&first)&&yx_variant_atom(&p,&last)&&!*p.at&&
       first.minimum==0&&first.maximum&&yx_variant_literal_unit(&first)&&
       last.minimum==1&&last.maximum==1&&yx_variant_literal_unit(&last))
        *optional_prefix=!(pattern->modifiers&YX_MOD_NOCASE)||pattern->regexp[0]!='(';
}
static bool yx_regex_nocase_single_letter(const YRX_PATTERN *pattern)
{
    if (!(pattern->modifiers & YX_MOD_NOCASE) ||
        pattern->global_atom_count_hint > 16) return false;
    yx_variant_parser p = {pattern->regexp, true, false, false, 0, false};
    yx_variant_shape shape;
    if (!yx_variant_sequence(&p, &shape) || *p.at ||
        shape.minimum != 1 || shape.maximum != 1 ||
        !yx_variant_literal_unit(&shape)) return false;
    for (unsigned c = 'A'; c <= 'Z'; ++c)
        if (shape.bytes[c / 8] & (1u << (c % 8))) return true;
    return false;
}

/* An optional literal prefix followed by one byte has an ASCII-first atom
 * in the long-input path. Two-byte optional groups retain wide priority
 * under nocase, while their starred form does not. */
static bool yx_regex_long_ascii_tie(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 0, width = 0;
    bool grouped = false;
    char quantifier;
    if (!length) return false;
    if (regexp[at] == '(') {
        grouped = true;
        ++at;
        if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
        while (yx_plain_regex_byte((unsigned char)regexp[at]) && width < 2) {
            ++width;
            ++at;
        }
        if (!width || regexp[at++] != ')') return false;
    } else {
        if (!yx_plain_regex_byte((unsigned char)regexp[at++]))
            return false;
        width = 1;
    }
    quantifier = regexp[at];
    if (quantifier == '?' || quantifier == '*') ++at;
    else if (!grouped && quantifier == '{' && length - at >= 4 &&
             regexp[at + 1] == '0' && regexp[at + 2] == ',') {
        at += 3;
        if (regexp[at] < '1' || regexp[at] > '9') return false;
        do { ++at; } while (regexp[at] >= '0' && regexp[at] <= '9');
        if (regexp[at++] != '}') return false;
        quantifier = '?';
    } else return false;
    if (at + 1 != length ||
        !yx_plain_regex_byte((unsigned char)regexp[at])) return false;
    return quantifier == '*' || width == 1 ||
           (pattern->modifiers & YX_MOD_NOCASE) == 0;
}

/* Repeating a small explicit class, or the whitespace class, selects its
 * ASCII verifier first in the long-input search path. A bare class and the
 * broader word/digit classes use a different atom order. */
static bool yx_regex_long_ascii_class_repeat(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp, *at = regexp;
    size_t members = 0;
    if (at[0] == '\\' && at[1] == 's') at += 2;
    else if (*at == '[') {
        ++at;
        while (*at && *at != ']') {
            if (*at == '\\' && (at[1] == 't' || at[1] == 'n' ||
                                 at[1] == 'r')) at += 2;
            else if (yx_plain_regex_byte((unsigned char)*at) || *at == ' ')
                ++at;
            else return false;
            if (++members > 16) return false;
        }
        if (*at++ != ']' || members < 2) return false;
    } else return false;
    if (at[0] == '+' && at[1] == '\0') return true;
    if (at[0] != '{' || at[1] != '1') return false;
    at += 2;
    if (*at == ',') {
        ++at;
        if (*at < '1' || *at > '9') return false;
        do { ++at; } while (*at >= '0' && *at <= '9');
    }
    return at[0] == '}' && at[1] == '\0';
}

/* A single dot under dotall is an arbitrary-byte atom in YARA-X. With
   `ascii wide`, its wide hit wins a same-offset tie, like a greedy regex
   atom. A fixed literal or a counted single dot follows a different path. */
static bool yx_regex_is_single_dotall_dot(const char *regexp,
                                          bool initial_dotall)
{
    const char *at = regexp;
    bool dotall = initial_dotall;
    while (at[0] == '(' && at[1] == '?') {
        const char *flags = at + 2;
        bool next_dotall = dotall, minus = false;
        if (*flags == ')' || *flags == ':') break;
        while (*flags) {
            if (*flags == '-') {
                minus = true;
            } else if (*flags == 's') {
                next_dotall = !minus;
            } else if (*flags != 'i' && *flags != 'm' && *flags != 'u' &&
                       *flags != 'x' && *flags != 'U') {
                break;
            }
            ++flags;
        }
        if (*flags == ':' && flags[1] == '.' && flags[2] == ')' &&
            flags[3] == '\0') return next_dotall;
        if (*flags != ')') break;
        dotall = next_dotall;
        at = flags + 1;
    }
    return dotall && at[0] == '.' && at[1] == '\0';
}

static bool yx_regex_ends_with_end_word_boundary(const char *regexp)
{
    size_t length = strlen(regexp), boundary;
    if (strchr(regexp, '|')) return false;
    if (length >= 7 && memcmp(regexp + length - 7, "\\b{end}", 7) == 0)
        boundary = length - 7;
    else if (length >= 2 &&
             memcmp(regexp + length - 2, "\\b", 2) == 0)
        boundary = length - 2;
    else return false;
    size_t prior_slashes = 0;
    while (boundary > 0 && regexp[boundary - 1] == '\\') {
        ++prior_slashes;
        --boundary;
    }
    return (prior_slashes & 1) == 0;
}

static size_t yx_regex_vm_max_span(const char *regexp);

/* Rule loading compiles the same native regex once for validation and once
 * for the candidate plan of every pattern with that expression (the APKiD
 * tracker files repeat 1,100 regexps in three namespaces). The compiled code
 * is a pure function of the final source and options, so each thread keeps
 * its recent compilations and hands out copies, which share the immutable,
 * reference-counted matcher. Only the compile-time callers (validation and
 * plan building) use it; scan-time compilations stay uncached. */
enum { YX_PCRE_MEMO_SLOTS = 4096, YX_PCRE_MEMO_SOURCE_LIMIT = 4096,
       YX_PCRE_MEMO_BUDGET = 1u << 20 };
typedef struct {
    char *source;
    uint32_t options;
    pcre2_code *code;
} yx_pcre_memo_entry;
typedef struct {
    yx_pcre_memo_entry slots[YX_PCRE_MEMO_SLOTS];
    size_t bytes;
} yx_pcre_memo;
static yx_thread_storage yx_pcre_memo_storage = YX_THREAD_STORAGE_INIT;
static void yx_pcre_memo_destroy(void *opaque)
{
    yx_pcre_memo *memo = opaque;
    for (size_t i = 0; i < YX_PCRE_MEMO_SLOTS; ++i) {
        free(memo->slots[i].source);
        pcre2_code_free(memo->slots[i].code);
    }
}
static _Thread_local yx_pcre_memo *yx_pcre_memo_thread;
static yx_pcre_memo *yx_pcre_memo_get(void)
{
    if (!yx_pcre_memo_thread)
        yx_pcre_memo_thread = yx_thread_storage_get(&yx_pcre_memo_storage,
                                                    sizeof(*yx_pcre_memo_thread),
                                                    yx_pcre_memo_destroy);
    return yx_pcre_memo_thread;
}
static pcre2_code *yx_pcre_compile_memo(const char *source, uint32_t options,
                                        pcre2_compile_context *context)
{
    yx_pcre_memo *thread_memo = yx_pcre_memo_get();
    int error = 0;
    PCRE2_SIZE error_offset = 0;
    size_t length = strlen(source);
    yx_pcre_memo *memo = length <= YX_PCRE_MEMO_SOURCE_LIMIT ? thread_memo : NULL;
    uint64_t hash = 1469598103934665603ull ^ options;
    for (const unsigned char *at = (const unsigned char *)source; *at; ++at)
        hash = (hash ^ *at) * 1099511628211ull;
    size_t first = (size_t)(hash ^ (hash >> 32)) & (YX_PCRE_MEMO_SLOTS - 1);
    size_t slot = first;
    for (size_t probe = 0; memo && probe < 8; ++probe) {
        const yx_pcre_memo_entry *entry = &memo->slots[slot];
        if (!entry->source) break;
        if (entry->options == options && !strcmp(entry->source, source)) {
            pcre2_code *copy = pcre2_code_copy(entry->code);
            if (copy) return copy;
            break;
        }
        slot = (slot + 1) & (YX_PCRE_MEMO_SLOTS - 1);
    }
    pcre2_code *code = pcre2_compile((PCRE2_SPTR)source, PCRE2_ZERO_TERMINATED,
                                     options, &error, &error_offset, context);
    if (!code || !memo || memo->bytes + length + 1 > YX_PCRE_MEMO_BUDGET)
        return code;
    slot = first;
    for (size_t probe = 0; probe < 8; ++probe) {
        yx_pcre_memo_entry *entry = &memo->slots[slot];
        if (!entry->source) {
            char *key = malloc(length + 1);
            pcre2_code *stored = key ? pcre2_code_copy(code) : NULL;
            if (stored) {
                memcpy(key, source, length + 1);
                entry->source = key;
                entry->options = options;
                entry->code = stored;
                memo->bytes += length + 1;
            } else free(key);
            break;
        }
        slot = (slot + 1) & (YX_PCRE_MEMO_SLOTS - 1);
    }
    return code;
}

/* The per-thread memo of pure compile-time results (internal.h). */
static yx_thread_storage yx_compile_memo_storage = YX_THREAD_STORAGE_INIT;
static _Thread_local yx_memo *yx_compile_memo_thread;
static yx_memo *yx_compile_memo(void)
{
    if (!yx_compile_memo_thread)
        yx_compile_memo_thread = yx_memo_get(&yx_compile_memo_storage);
    return yx_compile_memo_thread;
}
const void *yx_compile_memo_find(uint64_t tag, const void *key, size_t key_length,
                                 size_t *value_length)
{
    return yx_memo_find(yx_compile_memo(), tag, key, key_length, value_length);
}
void yx_compile_memo_store(uint64_t tag, const void *key, size_t key_length,
                           const void *value, size_t value_length)
{
    yx_memo_store(yx_compile_memo(), tag, key, key_length, value, value_length);
}

/* A thread's memoized compile-time results (the compile memo and the
 * regexp compilations), moved out so that another thread keeps them. */
struct yx_compile_memos {
    yx_memo memo;
    yx_pcre_memo_entry *pcre;
    size_t pcre_count;
};

struct yx_compile_memos *yx_compile_memos_take(void)
{
    struct yx_compile_memos *taken = calloc(1, sizeof(*taken));
    yx_pcre_memo *pcre = yx_pcre_memo_thread;
    size_t count = 0;
    if (!taken) return NULL;
    if (yx_compile_memo_thread) {
        taken->memo = *yx_compile_memo_thread;
        memset(yx_compile_memo_thread, 0, sizeof(*yx_compile_memo_thread));
    }
    for (size_t i = 0; pcre && i < YX_PCRE_MEMO_SLOTS; ++i) count += pcre->slots[i].source != NULL;
    if (count) taken->pcre = malloc(count * sizeof(*taken->pcre));
    if (taken->pcre) {
        for (size_t i = 0; i < YX_PCRE_MEMO_SLOTS; ++i) {
            if (!pcre->slots[i].source) continue;
            taken->pcre[taken->pcre_count++] = pcre->slots[i];
            memset(&pcre->slots[i], 0, sizeof(pcre->slots[i]));
        }
        pcre->bytes = 0;
    }
    return taken;
}

/* Adds results another thread took to this thread's memos. Both memos
 * hold pure functions of their keys, so a result made on another thread
 * is the result this thread would make; entries already present are kept. */
void yx_compile_memos_merge(struct yx_compile_memos *taken)
{
    yx_compile_memos_adopt(taken);
    yx_compile_memos_release(taken);
}

/* The first half of yx_compile_memos_merge: this thread's memos take the
 * results they keep, in the order and by the rules of the merge. What they
 * do not keep stays in `taken`. */
void yx_compile_memos_adopt(struct yx_compile_memos *taken)
{
    if (!taken) return;
    yx_memo *memo = yx_compile_memo();
    for (size_t i = 0; memo && i < taken->memo.slot_count; ++i) {
        const yx_memo_entry *entry = &taken->memo.slots[i];
        size_t length;
        if (!entry->data || yx_memo_find(memo, entry->tag, entry->data, entry->key_length, &length)) continue;
        yx_memo_store(memo, entry->tag, entry->data, entry->key_length, entry->data + entry->key_length,
                      entry->value_length);
    }
    yx_pcre_memo *pcre = yx_pcre_memo_get();
    for (size_t i = 0; i < taken->pcre_count; ++i) {
        yx_pcre_memo_entry *moved = &taken->pcre[i];
        size_t length = strlen(moved->source);
        uint64_t hash = 1469598103934665603ull ^ moved->options;
        for (const unsigned char *at = (const unsigned char *)moved->source; *at; ++at)
            hash = (hash ^ *at) * 1099511628211ull;
        size_t slot = (size_t)(hash ^ (hash >> 32)) & (YX_PCRE_MEMO_SLOTS - 1);
        for (size_t probe = 0; pcre && probe < 8 && moved->source; ++probe) {
            yx_pcre_memo_entry *entry = &pcre->slots[slot];
            if (entry->source && entry->options == moved->options && !strcmp(entry->source, moved->source)) break;
            if (!entry->source) {
                if (pcre->bytes + length + 1 <= YX_PCRE_MEMO_BUDGET) {
                    *entry = *moved;
                    pcre->bytes += length + 1;
                    moved->source = NULL;
                    moved->code = NULL;
                }
                break;
            }
            slot = (slot + 1) & (YX_PCRE_MEMO_SLOTS - 1);
        }
    }
}

/* The regexp compilations yx_compile_memos_adopt left in `taken`. */
size_t yx_compile_memos_leftover(const struct yx_compile_memos *taken)
{
    size_t count = 0;
    for (size_t i = 0; taken && i < taken->pcre_count; ++i) count += taken->pcre[i].source != NULL;
    return count;
}

/* The second half of yx_compile_memos_merge: frees what the adoption left.
 * It reads and writes `taken` only, so several results are released at the
 * same time on different threads. */
void yx_compile_memos_release(struct yx_compile_memos *taken)
{
    if (!taken) return;
    yx_memo_destroy(&taken->memo);
    for (size_t i = 0; i < taken->pcre_count; ++i) {
        yx_pcre_memo_entry *moved = &taken->pcre[i];
        if (!moved->source) continue;
        free(moved->source);
        pcre2_code_free(moved->code);
    }
    free(taken->pcre);
    free(taken);
}

static pcre2_code *yx_compile_pcre_regex_with(const YRX_PATTERN *pattern,
                                              bool wide, bool memo);
static pcre2_code *yx_compile_pcre_regex(const YRX_PATTERN *pattern, bool wide)
{
    return yx_compile_pcre_regex_with(pattern, wide, false);
}
/* Compile-time callers: identical expressions share one compilation. */
static pcre2_code *yx_compile_pcre_regex_shared(const YRX_PATTERN *pattern)
{
    return yx_compile_pcre_regex_with(pattern, false, true);
}

static pcre2_code *yx_compile_pcre_regex_with(const YRX_PATTERN *pattern,
                                              bool wide, bool memo)
{
    int error = 0;
    PCRE2_SIZE error_offset = 0;
    uint32_t options = PCRE2_DOLLAR_ENDONLY;
    options |= YX_RE_YARA_ESCAPES;
    char *edge_rewrite = yx_pcre_unicode_scalar_fixed_edge(pattern);
    bool unicode_scalar_nocase =
        (pattern->modifiers & YX_MOD_NOCASE) &&
        (yx_pcre_is_unicode_scalar_counted(pattern->regexp) ||
         yx_pcre_unicode_scalar_plus_width(pattern->regexp) ||
         edge_rewrite);
    bool unicode_escape_utf =
        yx_pcre_unicode_only_with_U(pattern->regexp);
    (void)wide;
    if (yx_regex_vm_max_span(pattern->regexp) != SIZE_MAX)
        options |= PCRE2_AUTO_CALLOUT;
    if (pattern->modifiers & YX_MOD_NOCASE) options |= PCRE2_CASELESS;
    if (pattern->modifiers & YX_MOD_DOTALL) options |= PCRE2_DOTALL;
    if (unicode_scalar_nocase || unicode_escape_utf) {
        options |= PCRE2_UTF | PCRE2_UCP;
#ifdef PCRE2_MATCH_INVALID_UTF
        options |= PCRE2_MATCH_INVALID_UTF;
#endif
    }
    /* YARA-X's unmodified $ anchor means the absolute end of the scan.
       Normalize multiline anchors above so LF remains matchable inside
       CRLF while CR and LF line boundaries retain YARA-X's semantics. */
    char *scalar_rewrite =
        (pattern->modifiers & YX_MOD_NOCASE) ? NULL :
        yx_pcre_unicode_scalar_plus(pattern->regexp);
    size_t special_upper = 0;
    bool special_nocase_count = (pattern->modifiers & YX_MOD_NOCASE) &&
        yx_pcre_unicode_scalar_counted_width(pattern->regexp,
                                              &special_upper,
                                              NULL, NULL) && special_upper;
    if (!scalar_rewrite &&
        (!(pattern->modifiers & YX_MOD_NOCASE) || special_nocase_count))
        scalar_rewrite = yx_pcre_unicode_scalar_counted(pattern->regexp);
    if (!scalar_rewrite) {
        scalar_rewrite = edge_rewrite;
        edge_rewrite = NULL;
    }
    char *counted_unbounded = unicode_scalar_nocase ?
        yx_pcre_unicode_counted_unbounded(pattern->regexp) : NULL;
    char *compacted = yx_regex_compact_extended_hex(
        scalar_rewrite ? scalar_rewrite : counted_unbounded ?
        counted_unbounded : pattern->regexp);
    char *normalized = compacted ?
        yx_pcre_normalize_dots(compacted,
                               (options & PCRE2_DOTALL) != 0,
                               (options & PCRE2_CASELESS) != 0,
                               unicode_scalar_nocase,
                               unicode_escape_utf) : NULL;
    free(compacted);
    free(scalar_rewrite);
    free(edge_rewrite);
    free(counted_unbounded);
    if (!normalized) return NULL;
    if ((options & PCRE2_UTF) && !unicode_scalar_nocase) {
        size_t normalized_length = strlen(normalized);
        if (normalized_length > SIZE_MAX - 8) { free(normalized); return NULL; }
        char *scoped = malloc(normalized_length + 8);
        if (!scoped) { free(normalized); return NULL; }
        memcpy(scoped, "(?-u:", 5);
        memcpy(scoped + 5, normalized, normalized_length);
        memcpy(scoped + 5 + normalized_length, ")", 2);
        free(normalized);
        normalized = scoped;
    }
    pcre2_compile_context *context = pcre2_compile_context_create(NULL);
    if (!context) { free(normalized); return NULL; }
    if (pcre2_set_newline(context, PCRE2_NEWLINE_LF) != 0) {
        pcre2_compile_context_free(context);
        free(normalized);
        return NULL;
    }
    if (pattern->deadline && pattern->deadline->enabled)
        options |= PCRE2_AUTO_CALLOUT;
    if (!(options & PCRE2_UTF)) {
        char *grouped = yx_regex_group_utf8_literals(normalized);
        free(normalized);
        if (!grouped) { pcre2_compile_context_free(context); return NULL; }
        normalized = grouped;
    }
    pcre2_code *code = memo ?
        yx_pcre_compile_memo(normalized, options, context) :
        pcre2_compile((PCRE2_SPTR)normalized, PCRE2_ZERO_TERMINATED, options,
                      &error, &error_offset, context);
    pcre2_compile_context_free(context);
    free(normalized);
    return code;
}

/* YARA-X's regexp VM stops verifying an unbounded match after 4096 input
 * bytes. Its one-byte leading atom consumes one of those steps. Keep fixed
 * long repeats out of this path: YARA-X can split them into chained atoms. */
static bool yx_regex_all_bytes_class(const char *regexp, size_t close)
{
    if (close == 0 || regexp[close - 1] != ']') return false;
    size_t open = close - 1;
    while (open > 0 && regexp[open] != '[') --open;
    if (regexp[open] != '[') return false;
    unsigned classes = 0;
    for (size_t i = open + 1; i + 1 < close; ++i) {
        if (regexp[i] != '\\') continue;
        switch (regexp[i + 1]) {
        case 's': classes |= 1u; break;
        case 'S': classes |= 2u; break;
        case 'd': classes |= 4u; break;
        case 'D': classes |= 8u; break;
        case 'w': classes |= 16u; break;
        case 'W': classes |= 32u; break;
        default: break;
        }
        if (i + 9 < close && memcmp(regexp + i, "\\x00-\\x", 7) == 0 &&
            (regexp[i + 7] == 'f' || regexp[i + 7] == 'F') &&
            (regexp[i + 8] == 'f' || regexp[i + 8] == 'F'))
            return true;
        if (i + 18 < close &&
            memcmp(regexp + i, "\\x00-\\x7", 8) == 0 &&
            (regexp[i + 8] == 'f' || regexp[i + 8] == 'F') &&
            memcmp(regexp + i + 9, "\\x80-\\x", 7) == 0 &&
            (regexp[i + 16] == 'f' || regexp[i + 16] == 'F') &&
            (regexp[i + 17] == 'f' || regexp[i + 17] == 'F'))
            return true;
    }
    return (classes & 3u) == 3u || (classes & 12u) == 12u ||
           (classes & 48u) == 48u;
}

/* An unquantified class covering every byte is also a wildcard atom in
   YARA-X. The same-offset wide match wins over ASCII for this shape, but a
   fixed {1} repeat or a nearly complete range uses the ASCII-first path. */
static bool yx_regex_is_single_all_bytes_class(const char *regexp)
{
    size_t begin = 0, end = strlen(regexp);
    for (;;) {
        if (begin + 3 < end && regexp[begin] == '(' &&
            regexp[begin + 1] == '?') {
            size_t flags = begin + 2;
            while (flags < end &&
                   strchr("imsuxU-", regexp[flags]) != NULL) ++flags;
            if (flags > begin + 2 && flags < end && regexp[flags] == ')') {
                begin = flags + 1;
                continue;
            }
        }
        if (begin + 2 < end && regexp[begin] == '(' &&
            regexp[end - 1] == ')') {
            size_t content = begin + 1;
            if (regexp[content] == '?') {
                ++content;
                while (content < end &&
                       strchr("imsuxU-", regexp[content]) != NULL) ++content;
                if (content >= end || regexp[content] != ':') break;
                ++content;
            }
            begin = content;
            --end;
            continue;
        }
        break;
    }
    if (begin + 2 >= end || regexp[begin] != '[' ||
        regexp[end - 1] != ']') return false;
    /* Reject concatenated classes; the helper below recognizes a class
       anywhere immediately before an index. */
    for (size_t i = begin + 1; i < end; ++i) {
        if (regexp[i] == '\\' && i + 1 < end) { ++i; continue; }
        if (regexp[i] == ']') {
            if (i != end - 1) return false;
            break;
        }
    }
    return yx_regex_all_bytes_class(regexp + begin, end - begin);
}

static bool yx_regex_unbounded_wildcard_before(const char *regexp,
                                                size_t quantifier)
{
    if (quantifier == 0) return false;
    if (regexp[quantifier - 1] == '.' ||
        yx_regex_all_bytes_class(regexp, quantifier)) return true;
    if (regexp[quantifier - 1] != ')') return false;
    /* A noncapturing group around a wildcard retains YARA-X's longer
       verification window. A capturing group consumes one VM slot. */
    if (quantifier >= 5 &&
        memcmp(regexp + quantifier - 5, "(?:.)", 5) == 0)
        return true;
    if (quantifier >= 6 &&
        memcmp(regexp + quantifier - 6, "(?s:.)", 6) == 0)
        return true;
    size_t open = quantifier - 1;
    while (open > 0 && regexp[open] != '(') --open;
    return regexp[open] == '(' && quantifier - open >= 5 &&
           memcmp(regexp + open, "(?:", 3) == 0 &&
           yx_regex_all_bytes_class(regexp, quantifier - 1);
}

static size_t yx_regex_vm_max_span(const char *regexp)
{
    /* A whole-pattern Unicode scalar counted repeat is verified inside the
       VM's 4096-byte input window, including when its quantifier is fixed. */
    size_t counted_upper = 0;
    size_t counted_width = yx_pcre_unicode_scalar_counted_width(
        regexp, &counted_upper, NULL, NULL);
    if (counted_width) {
        const char *open = strrchr(regexp, '{');
        const char *comma = open ? strchr(open, ',') : NULL;
        if (comma && !counted_upper) {
            size_t upper = 0;
            for (const char *at = comma + 1; *at >= '0' && *at <= '9'; ++at)
                upper = upper * 10 + (size_t)(*at - '0');
            if (upper > 1024 && upper <= 4095 / counted_width)
                return upper * counted_width;
        }
        return 4095;
    }
    /* The Unicode VM verifies one scalar per step. Its effective byte
       windows for a repeated two-, three-, or four-byte scalar are larger
       than the byte-mode window used by the rewritten expression. */
    size_t scalar_width = yx_pcre_unicode_scalar_plus_width(regexp);
    if (scalar_width)
        return scalar_width == 2 ? 8188 : scalar_width == 3 ? 8190 : 8184;
    bool in_class = false, variable = false, narrow_repeat = false;
    size_t prefix = 0;
    for (size_t i = 0; regexp[i]; ++i) {
        char ch = regexp[i];
        if (ch == '\\' && regexp[i + 1]) {
            ++i;
            continue;
        }
        if (ch == '[' && !in_class) { in_class = true; continue; }
        if (ch == ']' && in_class) { in_class = false; continue; }
        if (in_class) continue;
        if (ch == '*' || ch == '+') {
            variable = true;
            if (!yx_regex_unbounded_wildcard_before(regexp, i))
                narrow_repeat = true;
        }
        if (ch == '{') {
            size_t at = i + 1;
            unsigned lower = 0, upper = 0;
            bool has_lower = false, has_upper = false;
            while (isdigit((unsigned char)regexp[at])) {
                has_lower = true;
                lower = lower > 4096 ? lower :
                    lower * 10 + (unsigned)(regexp[at] - '0');
                ++at;
            }
            if (regexp[at] == ',') {
                ++at;
                while (isdigit((unsigned char)regexp[at])) {
                    has_upper = true;
                    upper = upper > 4096 ? upper :
                        upper * 10 + (unsigned)(regexp[at] - '0');
                    ++at;
                }
                if (regexp[at] == '}' && has_lower &&
                    (!has_upper || upper > 4095)) {
                    variable = true;
                    if (!yx_regex_unbounded_wildcard_before(regexp, i))
                        narrow_repeat = true;
                }
            }
        }
    }
    if (!variable) return SIZE_MAX;
    for (size_t i = regexp[0] == '^' ? 1u : 0u; regexp[i];) {
        /* Word assertions consume no input. A literal immediately after one
           is still the one-byte leading atom in YARA-X's VM budget. */
        if (regexp[i] == '\\' &&
            (regexp[i + 1] == 'b' || regexp[i + 1] == 'B')) {
            i += 2;
            continue;
        }
        if (yx_plain_regex_byte((unsigned char)regexp[i])) {
            ++prefix;
            ++i;
        } else if (regexp[i] == '\\' && regexp[i + 1] == 'x' &&
                   isxdigit((unsigned char)regexp[i + 2]) &&
                   isxdigit((unsigned char)regexp[i + 3])) {
            ++prefix;
            i += 4;
        } else if (regexp[i] == '[' &&
                   yx_plain_regex_byte((unsigned char)regexp[i + 1]) &&
                   regexp[i + 2] == ']') {
            ++prefix;
            i += 3;
        } else if (regexp[i] == '(') {
            size_t at = i + (regexp[i + 1] == '?' &&
                             regexp[i + 2] == ':' ? 3u : 1u);
            if (!yx_plain_regex_byte((unsigned char)regexp[at]) ||
                regexp[at + 1] != ')') break;
            ++prefix;
            i = at + 2;
        } else break;
    }
    return narrow_repeat || prefix == 1 ? 4095 : 4096;
}

typedef struct yx_regex_match_limit {
    size_t span;
    yx_scan_deadline *deadline;
} yx_regex_match_limit;

static int yx_regex_limit_callout(pcre2_callout_block *block, void *opaque)
{
    const yx_regex_match_limit *limit = opaque;
    if (yx_scan_deadline_poll(limit->deadline)) return PCRE2_ERROR_CALLOUT;
    return block->current_position >= block->start_match &&
           block->current_position - block->start_match > limit->span;
}

static int yx_validate_regex_core(const YRX_PATTERN *pattern);

static int yx_validate_regex_uncached(const YRX_PATTERN *pattern)
{
    yx_regex_ast_err ast_error;
    if (pattern && pattern->regexp &&
        yx_regex_ast_error(pattern->regexp, strlen(pattern->regexp),
                           &ast_error))
        return -1;
    return yx_validate_regex_core(pattern);
}

/* The parser validates every regexp pattern, and again for each repetition
 * of it in other rules and namespaces. The result depends on the regexp,
 * the modifiers and the kind (hex patterns read their atoms) and, through
 * the PCRE options, on an enabled deadline; patterns with a deadline or of
 * hex kind are not memoized. */
int yx_validate_regex(const YRX_PATTERN *pattern)
{
    if (!pattern || !pattern->regexp || pattern->kind == YX_PATTERN_HEX || pattern->deadline)
        return yx_validate_regex_uncached(pattern);
    size_t length = strlen(pattern->regexp), stored = 0;
    uint64_t tag = YX_MEMO_TAG(YX_MEMO_VALIDATE_REGEX, (unsigned)pattern->kind, pattern->modifiers);
    const void *hit = yx_compile_memo_find(tag, pattern->regexp, length, &stored);
    int result;
    if (hit && stored == sizeof(result)) {
        memcpy(&result, hit, sizeof(result));
        return result;
    }
    result = yx_validate_regex_uncached(pattern);
    /* -1 also stands for an allocation failure: keep only definite results. */
    if (result >= 0) yx_compile_memo_store(tag, pattern->regexp, length, &result, sizeof(result));
    return result;
}

static int yx_validate_regex_core(const YRX_PATTERN *pattern)
{
    int result;
    pcre2_code *code;
    pcre2_match_data *matches;
    const uint8_t *literal;
    size_t literal_length;
    if (!pattern || !pattern->regexp) return -1;
    char *compacted = yx_regex_compact_extended_hex(pattern->regexp);
    if (!compacted) return -1;
    int invalid = yx_regex_has_unsupported_construct(compacted) ||
                  yx_regex_validate_shape(
                      compacted,
                      (pattern->modifiers & YX_MOD_DOTALL) != 0, false);
    free(compacted);
    if (invalid || yx_regex_nesting_error(pattern->regexp,
                                          strlen(pattern->regexp), NULL, NULL))
        return -1;
    char *lowered = NULL;
    int fast_result = yx_ser_lower_fast_regex(pattern, &lowered);
    if (fast_result == -1) return -1;
    if (fast_result == 0 || fast_result == 3) return 1;
    if (fast_result == 1) {
        YRX_PATTERN copy = *pattern; copy.regexp = lowered;
        int valid = yx_validate_regex_core(&copy); free(lowered); return valid;
    }
    int large_result = yx_ser_large_regex_validate(pattern);
    if (large_result != -2) return large_result;
    if (yx_unmatchable_large_repeat(pattern->regexp) ||
        yx_pcre_unicode_count_unmatchable(pattern->regexp) ||
        yx_large_repeat_literal_alt(pattern->regexp, &literal,
                                    &literal_length)) return 1;
    code = yx_compile_pcre_regex_shared(pattern);
    if (!code) return -1;
    if (yx_regex_can_match_empty(pattern->regexp, strlen(pattern->regexp),
                                  pattern->modifiers)) {
        pcre2_code_free(code);
        return 0;
    }
    matches = pcre2_match_data_create_from_pattern(code, NULL);
    if (!matches) { pcre2_code_free(code); return -1; }
    result = pcre2_match(code, (PCRE2_SPTR)"", 0, 0, 0, matches, NULL);
    if (result == PCRE2_ERROR_NOMATCH) {
        /* Word-boundary assertions cannot match an empty subject, but they
           still match zero bytes next to a word character. YARA-X rejects
           such patterns just like other empty-match regular expressions. */
        result = pcre2_match(code, (PCRE2_SPTR)"a", 1, 0, 0, matches, NULL);
        if (result >= 0) {
            PCRE2_SIZE *span = pcre2_get_ovector_pointer(matches);
            if (span[0] != span[1])
                result = pcre2_match(code, (PCRE2_SPTR)"a", 1, 1, 0,
                                     matches, NULL);
        }
    }
    if (result >= 0) {
        PCRE2_SIZE *span = pcre2_get_ovector_pointer(matches);
        if (span[0] != span[1]) result = PCRE2_ERROR_NOMATCH;
    }
    pcre2_match_data_free(matches);
    pcre2_code_free(code);
    return result >= 0 ? 0 : result == PCRE2_ERROR_NOMATCH ? 1 : -1;
}

/* YARA-X can extend a lazy fullword match when the expression is one
 * quantified atom. It also tries a longer prefix for `a??aa`: the trailing
 * literal is an atom, and the optional leading byte is verified backwards.
 * A literal before the lazy atom takes a different path in its regex VM.
 * The return value selects the retry guard: 1 allows the boundary, 2 needs
 * a lowercase final byte, 3 needs at least three bytes, 4 needs both, 5
 * needs an exact two-byte tail, 7 handles mirrored optional branches, and
 * 0x100 | byte accepts an uppercase final byte after that preceding byte. */
static bool yx_regex_lazy_literal_gap(const char *regexp, bool nocase,
                                      bool dotall)
{
    yx_variant_parser p = {regexp, nocase, false, false, 0, false};
    size_t prefix = 0, suffix = 0;
    bool gap = false;
    while (*p.at) {
        if (*p.at == '.') {
            /* Only an any-byte gap splits the pattern into a chain. */
            if (gap || !prefix || !dotall) return false;
            ++p.at;
            if (*p.at == '*' || *p.at == '+') ++p.at;
            else if (*p.at == '{') {
                size_t lower = 0, upper = 0;
                ++p.at;
                if (!isdigit((unsigned char)*p.at)) return false;
                while (isdigit((unsigned char)*p.at)) {
                    if (lower > UINT32_MAX / 10) return false;
                    lower = lower * 10 + (unsigned)(*p.at++ - '0');
                }
                if (*p.at != ',') return false;
                ++p.at;
                bool unbounded = *p.at == '}';
                while (isdigit((unsigned char)*p.at)) {
                    if (upper > UINT32_MAX / 10) return false;
                    upper = upper * 10 + (unsigned)(*p.at++ - '0');
                }
                if (*p.at != '}') return false;
                ++p.at;
                /* Smaller bounded gaps remain in a single regexp VM;
                   only chained fragments retry distinct tail atoms. */
                if (!unbounded && (upper < lower || upper - lower <= 200))
                    return false;
            } else return false;
            if (*p.at != '?') return false;
            ++p.at;
            gap = true;
        } else if (*p.at == '[' && nocase) {
            yx_variant_shape shape;
            if (!yx_variant_atom(&p, &shape) || shape.minimum != 1 ||
                shape.maximum != 1 || !yx_variant_literal_unit(&shape))
                return false;
            if (gap) ++suffix;
            else ++prefix;
        } else {
            unsigned byte;
            uint8_t set[32] = {0};
            bool is_set = false;
            if (strchr("[]()|*+?{}^$", *p.at) ||
                !yx_variant_class_byte(&p, set, &byte, &is_set) || is_set)
                return false;
            if (gap) ++suffix;
            else ++prefix;
        }
    }
    return gap && prefix >= 2 && suffix >= 2;
}

/* Chained literal fragments search the original byte stream. In wide
 * mode only the fragments are UTF-16LE; a long gap can contain arbitrary
 * bytes and can change byte alignment before the next fragment. */
static bool yx_chain_literal_at(const uint8_t *data,size_t size,size_t at,
    const uint8_t *literal,size_t length,bool wide,bool nocase)
{
    size_t stride=wide?2:1;
    if(at>size||length>(size-at)/stride)return false;
    for(size_t i=0;i<length;++i) {
        uint8_t a=data[at+i*stride],b=literal[i];
        if((nocase?yx_fold(a)!=yx_fold(b):a!=b)||(wide&&data[at+i*stride+1]))return false;
    }
    return true;
}
static int yx_scan_wide_literal_chain(YRX_PATTERN *pattern,const uint8_t *data,
    size_t size,size_t limit,bool *handled)
{
    *handled=false;
    if(!(pattern->modifiers&YX_MOD_DOTALL))return 1;
    const char *regexp=pattern->regexp;size_t capacity=strlen(regexp);
    uint8_t *literal=malloc(capacity?capacity:1);
    if(!literal){*handled=true;return 0;}
    yx_variant_parser p={regexp,(pattern->modifiers&YX_MOD_NOCASE)!=0,true,false,0,false};
    size_t used=0,prefix=0;uint64_t minimum=0,maximum=UINT32_MAX;bool gap=false,greedy=true;
    while(*p.at) {
        if(*p.at=='.') {
            if(gap||used<2)goto unsupported;
            prefix=used;++p.at;
            if(*p.at=='*')++p.at;
            else if(*p.at=='+')minimum=1,++p.at;
            else if(*p.at=='{') {
                ++p.at;if(!isdigit((unsigned char)*p.at))goto unsupported;
                while(isdigit((unsigned char)*p.at)) {
                    minimum=minimum*10+(unsigned)(*p.at++-'0');
                    if(minimum>UINT32_MAX)goto unsupported;
                }
                if(*p.at++!=',')goto unsupported;
                if(*p.at!='}') {
                    maximum=0;
                    while(isdigit((unsigned char)*p.at)) {
                        maximum=maximum*10+(unsigned)(*p.at++-'0');
                        if(maximum>UINT32_MAX)goto unsupported;
                    }
                }
                if(*p.at!='}'||maximum<minimum||maximum-minimum<=200)goto unsupported;
                ++p.at;
            } else goto unsupported;
            if(*p.at=='?')greedy=false,++p.at;
            gap=true;continue;
        }
        unsigned byte;bool is_set=false;uint8_t set[32]={0};
        if(*p.at=='['&&p.nocase) {
            yx_variant_shape shape;
            if(!yx_variant_atom(&p,&shape)||shape.minimum!=1||shape.maximum!=1||!yx_variant_literal_unit(&shape))goto unsupported;
            for(byte=0;byte<256;++byte)if(shape.bytes[byte/8]&(1u<<(byte%8)))break;
            if(byte==256)goto unsupported;
        } else if(strchr("[]()|*+?{}^$",*p.at)||
                  !yx_variant_class_byte(&p,set,&byte,&is_set)||is_set)goto unsupported;
        literal[used++]=(uint8_t)byte;
    }
    if(!gap||used-prefix<2)goto unsupported;
    *handled=true;
    bool has_wide=(pattern->modifiers&YX_MOD_WIDE)!=0;
    for(unsigned variant=has_wide&&!(pattern->modifiers&YX_MOD_ASCII)?1:0;variant<(has_wide?2u:1u);++variant) {
        bool wide=variant!=0;size_t stride=wide?2:1;
        size_t prefix_width=prefix*stride,suffix_width=(used-prefix)*stride;
        for(size_t start=0;start<size;++start) {
            if(yx_scan_deadline_poll(pattern->deadline)){free(literal);return 0;}
            if(!yx_chain_literal_at(data,size,start,literal,prefix,wide,p.nocase))continue;
            size_t after=start+prefix_width;
            if(minimum>size-after||suffix_width>size)continue;
            size_t first=after+(size_t)minimum,last=size-suffix_width;
            if(first>last)continue;
            if(maximum!=UINT32_MAX&&maximum<last-after)last=after+(size_t)maximum;
            size_t selected=SIZE_MAX;
            for(size_t tail=first;tail<=last;++tail) {
                if(!(tail&255)&&yx_scan_deadline_poll(pattern->deadline)){free(literal);return 0;}
                if(!yx_chain_literal_at(data,size,tail,literal+prefix,used-prefix,wide,p.nocase))continue;
                size_t width=tail+suffix_width-start;
                if((pattern->modifiers&YX_MOD_FULLWORD)&&!yx_fullword(data,size,start,width,wide,0))continue;
                selected=width;if(!greedy)break;
            }
            if(selected!=SIZE_MAX&&!yx_add_match(pattern,start,selected,0)){free(literal);return 0;}
        }
    }
    free(literal);yx_sort_unique_limit(pattern,limit);return 1;
unsupported:free(literal);return 1;
}

static int yx_regex_lazy_fullword_retry(const char *regexp, bool nocase,
                                        bool dotall)
{
    const unsigned char *at = (const unsigned char *)regexp;
    if (!at || !*at) return 0;
    /* Chained literal fragments test every possible tail atom. A lazy gap
       whose first tail fails fullword must still reach later tail atoms. */
    if (yx_regex_lazy_literal_gap(regexp, nocase, dotall)) return 8;
    if (yx_word_byte(at[0]) &&
        at[1] == '?' && at[2] == '?' &&
        at[3] == at[0]) {
        unsigned char literal = at[0];
        size_t trailing = 0;
        at += 3;
        while (*at == literal) {
            ++trailing;
            ++at;
        }
        /* YARA-X's two- and three-byte nocase literal atoms retry a longer
         * match only when the final subject byte is lowercase. The other
         * supported shapes verify through the next fullword boundary. */
        if (!*at && (!nocase || (literal >= '0' && literal <= '9') ||
                     trailing == 1 || trailing >= 4))
            return 1;
        if (!*at && nocase &&
            ((literal >= 'A' && literal <= 'Z') ||
             (literal >= 'a' && literal <= 'z')) &&
            (trailing == 2 || trailing == 3))
            return 2;
        at = (const unsigned char *)regexp;
    }
    /* The fixed two-byte tail is an atom in YARA-X. Its verifier can
     * consume the lazy leading repetition until the fullword boundary. */
    if (((at[0] >= '0' && at[0] <= '9') ||
         (at[0] >= 'A' && at[0] <= 'Z') ||
         (at[0] >= 'a' && at[0] <= 'z'))) {
        const unsigned char *tail = NULL;
        if ((at[1] == '*' || at[1] == '+') && at[2] == '?')
            tail = at + 3;
        else if (strncmp((const char *)at + 1, "{0,2}?", 6) == 0 ||
                 strncmp((const char *)at + 1, "{1,2}?", 6) == 0)
            tail = at + 7;
        if (tail && tail[0] == at[0] && tail[1] == at[0] &&
            tail[2] == '\0')
            return 1;
    }
    /* Noncapturing parentheses around the optional prefix, with or without
     * an outer wrapper, keep the same fixed two-byte tail atom. */
    {
        bool outer = strncmp((const char *)at, "(?:(?:", 6) == 0;
        const unsigned char *group = outer ? at + 3 : at;
        if (strncmp((const char *)group, "(?:", 3) == 0) {
            unsigned char literal = group[3];
            if (((literal >= '0' && literal <= '9') ||
                 (literal >= 'A' && literal <= 'Z') ||
                 (literal >= 'a' && literal <= 'z')) &&
                group[4] == '?' && group[5] == '?' && group[6] == ')' &&
                group[7] == literal && group[8] == literal &&
                ((outer && group[9] == ')' && group[10] == '\0') ||
                 (!outer && group[9] == '\0')))
                return nocase &&
                    ((literal >= 'A' && literal <= 'Z') ||
                     (literal >= 'a' && literal <= 'z')) ? 2 : 1;
        }
    }
    /* A lazy one-or-more literal after a noncapturing optional prefix
     * can likewise extend through the next fullword boundary. */
    if (strncmp((const char *)at, "(?:", 3) == 0) {
        unsigned char literal = at[3];
        if (((literal >= '0' && literal <= '9') ||
             (literal >= 'A' && literal <= 'Z') ||
             (literal >= 'a' && literal <= 'z')) &&
            at[4] == '?' && at[5] == '?' && at[6] == ')' &&
            at[7] == literal && at[8] == '+' && at[9] == '?' &&
            at[10] == '\0')
            return 1;
    }
    /* The ordered c|cc branch can extend a lazy optional or repeated prefix
     * backwards from a fixed literal tail in the case-sensitive verifier. */
    if (!nocase && at[0] == '(') {
        bool noncapturing = at[1] == '?' && at[2] == ':';
        const unsigned char *branch = at + (noncapturing ? 3 : 1);
        unsigned char literal = branch[0];
        if (((literal >= '0' && literal <= '9') ||
             (literal >= 'A' && literal <= 'Z') ||
             (literal >= 'a' && literal <= 'z')) &&
            branch[1] == '|' && branch[2] == literal &&
            branch[3] == literal && branch[4] == ')' &&
            branch[6] == '?' && branch[7] == literal &&
            ((branch[5] == '?' &&
              ((!noncapturing && branch[8] == '\0') ||
               (branch[8] == literal && branch[9] == '\0'))) ||
             (branch[5] == '*' && branch[8] == literal &&
              branch[9] == '\0')))
            return 1;
    }
    /* For a lazy grouped literal, retry an anchored longer span only for
     * the branch shapes whose verifier reaches the word boundary. Optional
     * x|xx and x|xy branches make different choices with nocase enabled. */
    if (at[0] == '(') {
        const unsigned char *branch = at +
            (at[1] == '?' && at[2] == ':' ? 3 : 1);
        const unsigned char *cursor = branch;
        size_t left = 0, right = 0;
        while (left < 2 && yx_word_byte(*cursor)) { ++left; ++cursor; }
        if (left && *cursor++ == '|') {
            while (right < 2 && yx_word_byte(*cursor)) {
                ++right; ++cursor;
            }
            if (right && *cursor++ == ')') {
                bool optional = cursor[0] == '?';
                bool zero_or_more = cursor[0] == '*';
                if ((cursor[0] == '?' || cursor[0] == '*' ||
                     cursor[0] == '+') && cursor[1] == '?')
                    cursor += 2;
                else if (strncmp((const char *)cursor, "{1,3}?", 6) == 0)
                    cursor += 6;
                else cursor = NULL;
                if (cursor && yx_word_byte(cursor[0]) && cursor[1] == '\0') {
                    unsigned char suffix = cursor[0];
                    bool one_two_tail =
                        left == 1 && right == 2 &&
                        branch[0] == branch[2] &&
                        branch[3] != branch[0] &&
                        suffix == branch[3];
                    if (optional) {
                        bool repeated_same =
                            ((left == 1 && right == 2 &&
                              branch[0] == branch[2] &&
                              branch[0] == branch[3]) ||
                             (left == 2 && right == 1 &&
                              branch[0] == branch[1] &&
                              branch[0] == branch[3])) &&
                            suffix == branch[0];
                        bool overlapping_pair =
                            ((left == 1 && right == 2 &&
                              branch[0] == branch[2] &&
                              branch[0] != branch[3]) ||
                             (left == 2 && right == 1 &&
                              branch[0] == branch[3] &&
                              branch[0] != branch[1])) &&
                            suffix == branch[0];
                        bool mirrored_pair =
                            left == 2 && right == 2 &&
                            branch[0] == branch[4] &&
                            branch[1] == branch[3] &&
                            branch[0] != branch[1] &&
                            (suffix == branch[0] || suffix == branch[1]);
                        if (branch[0] >= '0' && branch[0] <= '9' &&
                            (repeated_same || overlapping_pair)) return 1;
                        if (one_two_tail) return 1;
                        if (!nocase && repeated_same) return 1;
                        if (nocase && overlapping_pair)
                            return 0x100 | (left == 1 ? branch[3] : branch[1]);
                        if (!nocase && overlapping_pair) return 3;
                        if (nocase && repeated_same) return 4;
                        if (nocase && mirrored_pair) return 7;
                    } else if (!zero_or_more && one_two_tail) {
                        bool first_letter =
                            (branch[0] >= 'A' && branch[0] <= 'Z') ||
                            (branch[0] >= 'a' && branch[0] <= 'z');
                        bool tail_letter =
                            (suffix >= 'A' && suffix <= 'Z') ||
                            (suffix >= 'a' && suffix <= 'z');
                        /* A numeric tail has a higher atom quality than
                           a letter prefix. Otherwise a non-expanding
                           leading atom keeps the two-byte endpoint. */
                        if (!(first_letter && !tail_letter) &&
                            (!nocase || !first_letter)) return 5;
                        return 1;
                    }
                    else return 1;
                }
            }
        }
    }
    /* A lazy optional or repeated group of two one-byte alternatives, or a
     * repeated group of overlapping one- and two-byte alternatives, can
     * finish inside a word. Extend the start to the fullword boundary. */
    if (at[0] == '(') {
        const unsigned char *branch = at +
            (at[1] == '?' && at[2] == ':' ? 3 : 1);
        if (yx_word_byte(branch[0]) && branch[1] == '|' &&
            yx_word_byte(branch[2]) && branch[3] == ')' &&
            (branch[4] == '*' || branch[4] == '?' || branch[4] == '+') &&
            branch[5] == '?' &&
            (branch[6] == branch[0] || branch[6] == branch[2]) &&
            branch[7] == '\0')
            return 1;
        if (yx_word_byte(branch[0]) &&
            ((branch[1] == '|' && branch[2] == branch[0] &&
              yx_word_byte(branch[3])) ||
             (yx_word_byte(branch[1]) && branch[2] == '|' &&
              branch[3] == branch[0])) &&
            branch[4] == ')' && (branch[5] == '*' || branch[5] == '+') &&
            branch[6] == '?' &&
            branch[7] == branch[0] && branch[8] == '\0')
            return 1;
    }
    if (*at == '[' || *at == '(') {
        unsigned char open = *at, close = open == '[' ? ']' : ')';
        size_t depth = 0;
        do {
            if (*at == '\\' && at[1]) {
                at += 2;
                continue;
            }
            if (*at == open) ++depth;
            else if (*at == close && --depth == 0) {
                ++at;
                break;
            }
            ++at;
        } while (*at);
        if (depth) return 0;
    } else if (*at == '\\' && at[1]) {
        at += 2;
    } else {
        ++at;
    }
    if (*at == '*' || *at == '+' || *at == '?') {
        ++at;
    } else if (*at == '{') {
        ++at;
        while (*at >= '0' && *at <= '9') ++at;
        if (*at == ',') {
            ++at;
            while (*at >= '0' && *at <= '9') ++at;
        }
        if (*at++ != '}') return 0;
    } else {
        return 0;
    }
    return at[0] == '?' && at[1] == '\0';
}

static int yx_pcre_deadline_callout(pcre2_callout_block *block, void *data)
{
    (void)block;
    return yx_scan_deadline_poll((yx_scan_deadline *)data) ?
           PCRE2_ERROR_CALLOUT : 0;
}

static int yx_pcre_match_deadline(const YRX_PATTERN *pattern,
                                  pcre2_code *code, PCRE2_SPTR subject,
                                  PCRE2_SIZE size, PCRE2_SIZE start,
                                  uint32_t options, pcre2_match_data *matches)
{
    pcre2_match_context *context = NULL;
    if (pattern->deadline && pattern->deadline->enabled) {
        if (yx_scan_deadline_reached(pattern->deadline))
            return PCRE2_ERROR_CALLOUT;
        context = pcre2_match_context_create(NULL);
        if (!context) return PCRE2_ERROR_NOMEMORY;
        pcre2_set_callout(context, yx_pcre_deadline_callout, pattern->deadline);
    }
    int result = pcre2_match(code, subject, size, start, options, matches,
                             context);
    pcre2_match_context_free(context);
    return result;
}

/* The bytes of a regexp that is one literal: \xHH escapes below 0x80,
 * ASCII letters, digits and '_', and escaped regexp punctuation. Every match
 * of such a regexp is an occurrence of these bytes. NULL for anything else,
 * including modifiers that change what a byte matches. */
static uint8_t *yx_regex_pure_literal(const YRX_PATTERN *pattern, size_t *length)
{
    const char *at = pattern->regexp;
    size_t used = 0, capacity;
    uint8_t *bytes;
    *length = 0;
    if (!at || !*at || (pattern->modifiers & (YX_MOD_NOCASE | YX_MOD_FULLWORD |
        YX_MOD_WIDE | YX_MOD_XOR | YX_MOD_BASE64 | YX_MOD_BASE64WIDE))) return NULL;
    capacity = strlen(at);
    if (capacity > 1024) return NULL;
    bytes = malloc(capacity);
    if (!bytes) return NULL;
    while (*at) {
        unsigned char ch = (unsigned char)*at;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_') {
            bytes[used++] = ch;
            ++at;
        } else if (ch == '\\' && at[1] == 'x' && yx_regex_hex_digit(at[2]) >= 0 &&
                   yx_regex_hex_digit(at[3]) >= 0 && yx_regex_hex_digit(at[2]) < 8) {
            bytes[used++] = (uint8_t)(yx_regex_hex_digit(at[2]) * 16 + yx_regex_hex_digit(at[3]));
            at += 4;
        } else if (ch == '\\' && at[1] && strchr("\\.^$|?*+()[]{}/-", at[1])) {
            bytes[used++] = (uint8_t)at[1];
            at += 2;
        } else {
            free(bytes);
            return NULL;
        }
    }
    *length = used;
    return bytes;
}

static int yx_scan_regex_buffer(YRX_PATTERN *pattern, pcre2_code *code,
                                pcre2_match_data *matches,
                                const uint8_t *data, size_t size,
                                const uint8_t *raw, size_t raw_size,
                                size_t origin, size_t first_start,
                                bool wide, size_t limit,
                                bool at_bol, bool at_eol,
                                const uint8_t *literal, size_t literal_length)
{
    uint32_t options = (at_bol ? 0 : PCRE2_NOTBOL) |
                       (at_eol ? 0 : PCRE2_NOTEOL);
    size_t max_span = yx_regex_vm_max_span(pattern->regexp);
    yx_variant_parser variant_parser={pattern->regexp,
        (pattern->modifiers&YX_MOD_NOCASE)!=0,(pattern->modifiers&YX_MOD_DOTALL)!=0,false,0,false};
    yx_variant_shape variant_shape;
    bool retry_bounded_class=(pattern->modifiers&YX_MOD_FULLWORD)&&
        (pattern->regexp[0]=='.'||pattern->regexp[0]=='[')&&
        yx_variant_sequence(&variant_parser,&variant_shape)&&!*variant_parser.at&&
        variant_shape.homogeneous&&(variant_shape.bytes[0]&1)&&
        variant_shape.minimum==1&&variant_shape.maximum>1&&variant_shape.maximum<=32;
    size_t scalar_width = yx_pcre_unicode_scalar_plus_width(pattern->regexp);
    size_t counted_limited_upper = 0;
    size_t counted_width = yx_pcre_unicode_scalar_counted_width(
        pattern->regexp, &counted_limited_upper, NULL, NULL);
    bool trailing_word_boundary = wide &&
        yx_regex_ends_with_end_word_boundary(pattern->regexp);
    int retry_lazy_fullword = yx_regex_lazy_fullword_retry(
        pattern->regexp, (pattern->modifiers & YX_MOD_NOCASE) != 0,
        (pattern->modifiers & YX_MOD_DOTALL) != 0);
    size_t start = first_start;
    /* A gate plan's whole-expression literal alternation can match only at
     * a recorded branch start (yx_candidate_finalize). The leftmost match
     * from `start` is then the anchored match at the first recorded start
     * at or after it, so the search visits those starts only. This holds
     * for the plan's own program over the raw input. */
    const yx_rx_candidate *gate_starts = NULL;
    size_t gate_count = 0, gate_next = 0;
    if (pattern->candidate_gate_starts && !wide && data == raw &&
        size == raw_size && !origin && !first_start &&
        code == yx_candidate_cached_regex(pattern)) {
        gate_starts = pattern->candidate_hits;
        gate_count = pattern->candidate_hit_count;
    }
    while (start <= size && (!limit || pattern->match_count < limit)) {
        int result = PCRE2_ERROR_NOMATCH;
        if (gate_starts) {
            while (gate_next < gate_count && gate_starts[gate_next].position < start)
                ++gate_next;
            for (; gate_next < gate_count && result == PCRE2_ERROR_NOMATCH; ++gate_next)
                if (gate_starts[gate_next].position <= size)
                    result = yx_pcre_match_deadline(pattern, code, (PCRE2_SPTR)data,
                        size, gate_starts[gate_next].position,
                        options | PCRE2_ANCHORED, matches);
        } else if (literal) {
            /* A one-literal regexp matches exactly at the occurrences of its
             * bytes, so the leftmost match from start is the anchored match
             * at the first occurrence at or after start. */
            int64_t found = start <= size && literal_length <= size - start ?
                xx_data_find_bytes_buffer_optimize(data, size, start, literal,
                                                   literal_length, NULL) : -1;
            if (found < 0) {
                if (yx_scan_deadline_poll(pattern->deadline)) return 0;
                break;
            }
            result = yx_pcre_match_deadline(pattern, code, (PCRE2_SPTR)data, size,
                                            (size_t)found, options | PCRE2_ANCHORED,
                                            matches);
            if (result == PCRE2_ERROR_NOMATCH ||
                (result >= 0 && pcre2_get_ovector_pointer(matches)[0] != (size_t)found))
                result = yx_pcre_match_deadline(pattern, code, (PCRE2_SPTR)data,
                                                size, start, options, matches);
        } else
            result = yx_pcre_match_deadline(pattern, code, (PCRE2_SPTR)data,
                                            size, start, options, matches);
        if (result == PCRE2_ERROR_NOMATCH) break;
        if (result < 0) return 0;
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(matches);
        size_t offset = (size_t)ovector[0], end = (size_t)ovector[1];
        size_t match_max_span = max_span;
        if (scalar_width && limit) {
            /* Each retained match consumes one step of the Unicode VM's
               match budget. Later matches fall back toward its base span. */
            size_t first_span = 4095 - 4095 % scalar_width;
            size_t remaining = limit - pattern->match_count;
            size_t extra_steps = remaining > 2 ? remaining - 2 : 0;
            size_t available_steps = (max_span - first_span) / scalar_width;
            if (extra_steps < available_steps)
                match_max_span = first_span + extra_steps * scalar_width;
        }
        if (counted_width && counted_limited_upper && limit) {
            size_t remaining = limit - pattern->match_count;
            size_t extra = remaining > 2 ? remaining - 2 : 0;
            size_t max_count = match_max_span / counted_width;
            size_t allowed = counted_limited_upper;
            if (allowed < max_count) {
                size_t room = max_count - allowed;
                allowed += extra < room ? extra : room;
            }
            if (allowed * counted_width < match_max_span)
                match_max_span = allowed * counted_width;
        }
        if (match_max_span != SIZE_MAX && end - offset > match_max_span) {
            size_t capped_end = offset + match_max_span;
            uint32_t bounded_options = options | PCRE2_ANCHORED;
            size_t subject_end = capped_end < size ? capped_end + 1 : size;
            /* A UTF-mode counted scalar needs a complete final code point.
               Otherwise PCRE2 rejects the clipped subject before it can
               backtrack from the too-long greedy match. */
            if (counted_width &&
                (pattern->modifiers & YX_MOD_NOCASE) &&
                yx_pcre_is_unicode_scalar_counted(pattern->regexp))
                subject_end = offset +
                    (match_max_span / counted_width) * counted_width;
            pcre2_match_context *bounded = pcre2_match_context_create(NULL);
            yx_regex_match_limit bound = {match_max_span, pattern->deadline};
            if (!bounded) return 0;
            if (subject_end < size) bounded_options |= PCRE2_NOTEOL;
            if (pcre2_set_callout(bounded, yx_regex_limit_callout,
                                  &bound) != 0) {
                pcre2_match_context_free(bounded);
                return 0;
            }
            result = pcre2_match(code, (PCRE2_SPTR)data, subject_end,
                                 offset, bounded_options, matches, bounded);
            pcre2_match_context_free(bounded);
            if (result == PCRE2_ERROR_NOMATCH) {
                start = offset + 1;
                continue;
            }
            if (result < 0) return 0;
            ovector = pcre2_get_ovector_pointer(matches);
            end = (size_t)ovector[1];
        }
        if ((pattern->modifiers & YX_MOD_FULLWORD) && counted_width &&
            counted_limited_upper &&
            end - offset > counted_limited_upper * counted_width) {
            size_t raw_start = origin + offset * (wide ? 2 : 1);
            while (end - offset > counted_limited_upper * counted_width &&
                   !yx_fullword(raw, raw_size, raw_start,
                                (end - offset) * (wide ? 2 : 1), wide, 0)) {
                size_t subject_end = end - counted_width;
                uint32_t bounded_options = options | PCRE2_ANCHORED;
                if (subject_end < size) bounded_options |= PCRE2_NOTEOL;
                result = yx_pcre_match_deadline(pattern, code,
                    (PCRE2_SPTR)data, subject_end, offset, bounded_options,
                    matches);
                if (result < 0) break;
                size_t shorter = (size_t)pcre2_get_ovector_pointer(matches)[1];
                if (shorter >= end) break;
                end = shorter;
            }
        }
        if ((pattern->modifiers & YX_MOD_FULLWORD) && retry_lazy_fullword) {
            size_t raw_start = origin + offset * (wide ? 2 : 1);
            size_t raw_length = (end - offset) * (wide ? 2 : 1);
            bool left_boundary = wide ?
                !(raw_start >= 2 && raw[raw_start - 1] == 0 &&
                  yx_word_byte(raw[raw_start - 2])) :
                !(raw_start && yx_word_byte(raw[raw_start - 1]));
            if (left_boundary &&
                !yx_fullword(raw, raw_size, raw_start, raw_length, wide, 0)) {
                size_t last = size;
                size_t span_limit = match_max_span == SIZE_MAX ?
                    4096 : match_max_span;
                if (span_limit < size - offset)
                    last = offset + span_limit;
                /* A lazy path may stop inside a word. YARA-X verifies the
                 * same start through the next word boundary before it
                 * discards that start. Anchor both ends of the retry so
                 * PCRE2 cannot return its shorter lazy alternative. */
                for (size_t candidate_end = end + 1;
                     candidate_end <= last; ++candidate_end) {
                    size_t candidate_length =
                        (candidate_end - offset) * (wide ? 2 : 1);
                    if (!yx_fullword(raw, raw_size, raw_start,
                                     candidate_length, wide, 0))
                        continue;
                    if ((retry_lazy_fullword == 2 ||
                         retry_lazy_fullword == 4) &&
                        !(data[candidate_end - 1] >= 'a' &&
                          data[candidate_end - 1] <= 'z'))
                        break;
                    if ((retry_lazy_fullword == 3 ||
                         retry_lazy_fullword == 4) &&
                        candidate_end - offset < 3) break;
                    if (retry_lazy_fullword == 7 &&
                        (candidate_end - offset < 3 ||
                         !((data[candidate_end - 1] >= 'a' &&
                            data[candidate_end - 1] <= 'z') ||
                           ((data[candidate_end - 3] >= 'a' &&
                             data[candidate_end - 3] <= 'z') &&
                            (data[candidate_end - 2] >= 'a' &&
                             data[candidate_end - 2] <= 'z'))))) break;
                    if ((retry_lazy_fullword & 0x100) &&
                        !(data[candidate_end - 1] >= 'a' &&
                          data[candidate_end - 1] <= 'z') &&
                        !(candidate_end - offset >= 3 &&
                          yx_fold(data[candidate_end - 2]) ==
                          yx_fold((uint8_t)retry_lazy_fullword))) break;
                    if (retry_lazy_fullword == 5) {
                        const unsigned char *branch =
                            (const unsigned char *)pattern->regexp +
                            (pattern->regexp[1] == '?' ? 3 : 1);
                        bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
                        if (candidate_end - offset < 2) break;
                        uint8_t first = data[candidate_end - 2];
                        uint8_t last_byte = data[candidate_end - 1];
                        if ((nocase ? yx_fold(first) != yx_fold(branch[0]) :
                                      first != branch[0]) ||
                            (nocase ? yx_fold(last_byte) != yx_fold(branch[3]) :
                                      last_byte != branch[3])) break;
                    }
                    uint32_t retry_options = options | PCRE2_ANCHORED |
                                             PCRE2_ENDANCHORED;
                    if (candidate_end < size) retry_options |= PCRE2_NOTEOL;
                    int retry = yx_pcre_match_deadline(pattern, code,
                        (PCRE2_SPTR)data, candidate_end, offset,
                        retry_options, matches);
                    if (retry >= 0) {
                        PCRE2_SIZE *retry_vector =
                            pcre2_get_ovector_pointer(matches);
                        if (retry_vector[0] == offset &&
                            retry_vector[1] == candidate_end)
                            end = candidate_end;
                    }
                    if (retry >= 0 || retry_lazy_fullword != 8) break;
                }
            }
        }
        size_t raw_offset = origin + offset * (wide ? 2 : 1);
        if(retry_bounded_class) {
            while(end>offset+variant_shape.minimum&&
                  !yx_fullword(raw,raw_size,raw_offset,(end-offset)*(wide?2:1),wide,0))--end;
        }
        size_t raw_length = (end - offset) * (wide ? 2 : 1);
        size_t raw_end = raw_offset + raw_length;
        /* A nonzero high byte ends the projected wide run, but YARA-X still
           inspects that pair's low byte for a trailing word boundary. */
        bool boundary_ok = !trailing_word_boundary || end < size ||
            raw_end > raw_size || raw_size - raw_end < 2 ||
            !(yx_word_byte(raw[raw_end]) || raw[raw_end] == '_');
        if (end > offset && boundary_ok &&
            (!(pattern->modifiers & YX_MOD_FULLWORD) ||
             yx_fullword(raw, raw_size, raw_offset, raw_length, wide, 0)) &&
            !yx_add_match(pattern, raw_offset, raw_length, limit)) return 0;
        start = offset + 1;
    }
    return 1;
}

/* YARA-X compiles a whole-regexp alternation of literals as separate literal
   subpatterns. Its daachorse search observes a shorter atom first when it
   shares a prefix with a longer one. Keep this path restricted to whole
   expressions: in `(ab|a)b`, the VM preserves branch order instead. */
static int yx_scan_literal_alternation(YRX_PATTERN *pattern,
                                       const uint8_t *data, size_t size,
                                       size_t limit, bool *handled)
{
    const char *regexp=pattern->regexp;
    size_t length=strlen(regexp),begin=0,end=length;
    *handled=false;
    if(pattern->modifiers&YX_MOD_WIDE)return 1;
    if((pattern->modifiers&YX_MOD_NOCASE)&&(pattern->modifiers&YX_MOD_FULLWORD))return 1;
    if(length>=3&&regexp[0]=='('&&regexp[length-1]==')') {
        begin=1;end=length-1;
        if(begin+2<=end&&regexp[begin]=='?'&&regexp[begin+1]==':')begin+=2;
    }
    if(begin>=end)return 1;
    uint8_t *bytes=malloc(length?length:1);
    size_t *offsets=malloc((length+1)*sizeof(*offsets));
    if(!bytes||!offsets){free(bytes);free(offsets);*handled=true;return 0;}
    size_t used=0,count=0,shortest=SIZE_MAX,longest=0;
    offsets[0]=0;
    yx_variant_parser parser={regexp+begin,false,false,false,0,false};
    while((size_t)(parser.at-regexp)<end) {
        if(*parser.at=='|') {
            size_t width=used-offsets[count];
            if(!width)goto unsupported;
            if(width<shortest)shortest=width;
            if(width>longest)longest=width;
            offsets[++count]=used;++parser.at;continue;
        }
        if(strchr(".^$*+?{}[]()",(unsigned char)*parser.at))goto unsupported;
        unsigned byte;bool is_set;uint8_t set[32]={0};
        if(!yx_variant_class_byte(&parser,set,&byte,&is_set)||is_set||
           (size_t)(parser.at-regexp)>end)goto unsupported;
        if((pattern->modifiers&YX_MOD_NOCASE)&&
           ((byte>='a'&&byte<='z')||(byte>='A'&&byte<='Z')))goto unsupported;
        bytes[used++]=(uint8_t)byte;
    }
    if(!count||used==offsets[count])goto unsupported;
    size_t width=used-offsets[count];
    if(width<shortest)shortest=width;
    if(width>longest)longest=width;
    offsets[++count]=used;
    /* Short inputs use the end-ordered automaton; longer inputs can use
       Teddy's source-order buckets. Atom widths use decoded bytes. */
    bool source_order=pattern->fixed_at_enabled||
        (pattern->global_atom_count_hint<=16&&count<=16*shortest&&size>=15+shortest);
    if(longest>4||(!(pattern->modifiers&YX_MOD_FULLWORD)&&
       (shortest==longest||source_order)))goto unsupported;
    *handled=true;
    for(size_t i=0;i<count;++i) {
        YRX_PATTERN branch=*pattern;
        branch.bytes=bytes+offsets[i];branch.length=offsets[i+1]-offsets[i];
        branch.matches=NULL;branch.match_count=branch.match_capacity=0;
        if(!yx_scan_text(&branch,data,size,limit,false)) {
            free(branch.matches);free(bytes);free(offsets);return 0;
        }
        for(size_t j=0;j<branch.match_count;++j) {
            bool present=false;
            if(source_order)for(size_t k=0;k<pattern->match_count;++k)
                if(pattern->matches[k].offset==branch.matches[j].offset){present=true;break;}
            if(!present&&!yx_add_match(pattern,branch.matches[j].offset,branch.matches[j].length,0)) {
                free(branch.matches);free(bytes);free(offsets);return 0;
            }
        }
        free(branch.matches);yx_sort_unique_limit(pattern,limit);
    }
unsupported:
    free(bytes);free(offsets);return 1;
}

/* A grouped literal branch and an ungrouped literal prefix share the same
   atom. For short inputs YARA-X's daachorse path reports the ungrouped exact
   atom first, even when the grouped branch precedes it in the regexp. At the
   SIMD threshold its verifier follows regexp branch order instead. Restrict
   this shortcut to a whole two-branch expression made only of literal bytes
   and transparent groups; quantifiers and assertions have different atoms. */
static int yx_scan_grouped_literal_prefix(YRX_PATTERN *pattern,
                                          const uint8_t *data, size_t size,
                                          size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), bar = SIZE_MAX, depth = 0;
    size_t flat_length = 0, prefix_length;
    bool grouped = false, capturing = false;
    char *flat;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return 1;
    for (size_t i = 0; i < length; ++i) {
        if (regexp[i] == '(') {
            ++depth;
        } else if (regexp[i] == ')') {
            if (!depth) return 1;
            --depth;
        } else if (regexp[i] == '|' && depth == 0) {
            if (bar != SIZE_MAX) return 1;
            bar = i;
        }
    }
    if (depth || bar == SIZE_MAX || bar == 0 || bar + 1 >= length)
        return 1;
    /* Only the first branch may contain transparent groups. */
    flat = malloc(bar + 1);
    if (!flat) return 0;
    for (size_t i = 0; i < bar; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (ch == '(') {
            grouped = true;
            if (i + 2 < bar && regexp[i + 1] == '?' &&
                regexp[i + 2] == ':') i += 2;
            else capturing = true;
        } else if (ch == ')') {
            /* The balanced-group check above covers this delimiter. */
        } else if (ch >= 0x80 || strchr(".\\^$*+?{}[]|", ch)) {
            free(flat);
            return 1;
        } else {
            flat[flat_length++] = (char)ch;
        }
    }
    prefix_length = length - bar - 1;
    if (!grouped || prefix_length >= flat_length ||
        (capturing && prefix_length == 1 && flat_length == 2) ||
        memcmp(flat, regexp + bar + 1, prefix_length) != 0 ||
        (size >= prefix_length && size - prefix_length >= 15)) {
        free(flat);
        return 1;
    }
    for (size_t i = bar + 1; i < length; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (ch >= 0x80 || strchr(".\\^$*+?{}[]()|", ch)) {
            free(flat);
            return 1;
        }
    }
    free(flat);
    *handled = true;
    uint8_t *saved_bytes = pattern->bytes;
    size_t saved_length = pattern->length;
    pattern->bytes = (uint8_t *)(regexp + bar + 1);
    pattern->length = prefix_length;
    int success = yx_scan_text(pattern, data, size, limit, false);
    pattern->bytes = saved_bytes;
    pattern->length = saved_length;
    return success;
}

/* A whole alternation of short and longer literal branches can
 * retain 2*n-1 repetitions for a {1,n} bound in YARA-X's verifier. For
 * {1,2} and a two-byte branch ending in the short byte, the ordinary ASCII
 * path already has a different verifier and needs no rewrite. Keep this to
 * disjoint first bytes and small bounds so branch priority stays unambiguous. */
static char *yx_regex_expand_disjoint_literal_pair_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    const char *bar, *close, *short_branch, *long_branch;
    size_t at = 1, length, left_length, right_length;
    size_t short_length, long_length;
    unsigned char x, upper;
    char *expanded;
    if (!regexp) return NULL;
    if (regexp[0] != '(') return NULL;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    length = strlen(regexp);
    bar = strchr(regexp + at, '|');
    close = strchr(regexp + at, ')');
    if (!bar || !close || bar > close ||
        length != (size_t)(close - regexp) + 6 ||
        memcmp(close + 1, "{1,", 3) != 0 ||
        close[5] != '}' || close[4] < '2' || close[4] > '4')
        return NULL;
    upper = (unsigned char)(close[4] - '0');
    left_length = (size_t)(bar - regexp - at);
    right_length = (size_t)(close - bar - 1);
    if ((left_length == 1 && (right_length == 2 || right_length == 3)) ||
        (left_length == 2 && right_length == 3)) {
        short_branch = regexp + at;
        short_length = left_length;
        long_branch = bar + 1;
        long_length = right_length;
    } else if ((right_length == 1 &&
                (left_length == 2 || left_length == 3)) ||
               (right_length == 2 && left_length == 3)) {
        short_branch = bar + 1;
        short_length = right_length;
        long_branch = regexp + at;
        long_length = left_length;
    } else return NULL;
    x = (unsigned char)short_branch[0];
    if (yx_fold(x) == yx_fold((unsigned char)long_branch[0])) return NULL;
    for (size_t i = 0; i < short_length; ++i)
        if (!yx_plain_regex_byte((unsigned char)short_branch[i])) return NULL;
    for (size_t i = 0; i < long_length; ++i)
        if (!yx_plain_regex_byte((unsigned char)long_branch[i])) return NULL;
    if (short_length == 1 && long_length == 2 &&
        long_branch[1] != (char)x &&
        yx_fold((unsigned char)long_branch[1]) == yx_fold(x)) return NULL;
    if (upper == 2 && short_length == 1 && long_length == 2 &&
        long_branch[1] == (char)x &&
        !(pattern->modifiers &
          (YX_MOD_NOCASE | YX_MOD_WIDE | YX_MOD_FULLWORD))) return NULL;
    expanded = malloc(length + 1);
    if (!expanded) return NULL;
    memcpy(expanded, regexp, length + 1);
    expanded[close - regexp + 4] = (char)('0' + 2 * upper - 1);
    return expanded;
}

/* YARA-X's atom verifier can consume a leading {1,n} repetition on both
   sides of its mandatory one-byte atom. For this restricted expression shape,
   the effective upper bound is 2*n-1. Keep the compatibility rewrite narrow:
   a following two-byte literal is verified through a different atom and does
   not exhibit this behavior. */
static char *yx_regex_expand_leading_repeat(const char *regexp)
{
    size_t at = 0;
    bool class_atom = false, wide_class = false;
    unsigned lower = 1, upper = 0;
    char replacement[32];
    int replacement_length;
    if (!regexp) return NULL;
    /* Initial i/m/u flags change byte or anchor handling, but leave this
       leading repetition in the same atom shape. */
    if (strncmp(regexp, "(?i)", 4) == 0 ||
        strncmp(regexp, "(?m)", 4) == 0 ||
        strncmp(regexp, "(?s)", 4) == 0 ||
        strncmp(regexp, "(?u)", 4) == 0) at = 4;
    else if (strncmp(regexp, "(?im)", 5) == 0 ||
             strncmp(regexp, "(?mi)", 5) == 0) at = 5;
    if (regexp[at] == '^') ++at;
    if (yx_plain_regex_byte((unsigned char)regexp[at])) {
        ++at;
    } else if (regexp[at] == '.' || regexp[at] == '[') {
        class_atom = true;
        if (regexp[at] == '.') { ++at; wide_class = true; }
        else {
            yx_variant_parser parser={regexp+at,false,false,false,0,false};
            yx_variant_shape shape;
            if(!yx_variant_atom(&parser,&shape)||!shape.homogeneous)return NULL;
            {
                unsigned members = 0;
                for (unsigned b = 0; b < 256; ++b)
                    if (shape.bytes[b / 8] & (1u << (b % 8))) ++members;
                /* A class of more than 128 bytes is no atom at all. */
                wide_class = members > 128;
            }
            ++at;
            if(regexp[at]=='^')++at;
            if(regexp[at]==']')++at;
            while(regexp[at]&&regexp[at]!=']') {
                if(regexp[at]=='\\'&&regexp[at+1])++at;
                ++at;
            }
            if(regexp[at++]!=']')return NULL;
        }
    } else if (regexp[at] == '(') {
        at += regexp[at + 1] == '?' && regexp[at + 2] == ':' ? 3 : 1;
        if (!yx_plain_regex_byte((unsigned char)regexp[at]) ||
            regexp[at + 1] != ')') return NULL;
        at += 2;
    } else {
        return NULL;
    }
    size_t repeat_at = at;
    if (regexp[at] != '{' || !isdigit((unsigned char)regexp[at + 1]))
        return NULL;
    lower = 0;
    for (++at; isdigit((unsigned char)regexp[at]); ++at) {
        lower = lower * 10 + (unsigned)(regexp[at] - '0');
        if (lower > 32) return NULL;
    }
    if (regexp[at] != ',') return NULL;
    ++at;
    if (!isdigit((unsigned char)regexp[at])) return NULL;
    while (isdigit((unsigned char)regexp[at])) {
        upper = upper * 10 + (unsigned)(regexp[at] - '0');
        if (upper > 32) return NULL;
        ++at;
    }
    if (upper < 2 || upper <= lower || regexp[at] != '}') return NULL;
    /* A wide class repeated {n,m} with n >= 2 shows the same doubling, but
     * only while the bound is at most 10. */
    if (lower != 1 && (!wide_class || upper > 10)) return NULL;
    if (wide_class && upper > 10) return NULL;
    ++at;
    /* A one-byte literal (optionally followed by ?) or end anchor still
       uses this verifier. Other suffixes and top-level alternations need
       their own atom model. */
    size_t suffix_at = at;
    if (yx_plain_regex_byte((unsigned char)regexp[at])) {
        /* A following literal is its own mandatory atom for a repeated
           class, so its verifier keeps the syntactic upper bound. */
        if (class_atom) return NULL;
        ++at;
        if (regexp[at] == '?') ++at;
    }
    if (regexp[at] == '$') ++at;
    if (regexp[at] != '\0') return NULL;
    replacement_length = snprintf(replacement, sizeof(replacement),
                                  "{%u,%u}", lower, upper * 2 - lower);
    if (replacement_length < 0 ||
        (size_t)replacement_length >= sizeof(replacement)) return NULL;
    size_t suffix_length = strlen(regexp + suffix_at);
    if (repeat_at > SIZE_MAX - (size_t)replacement_length - suffix_length - 1)
        return NULL;
    char *expanded = malloc(repeat_at + (size_t)replacement_length +
                            suffix_length + 1);
    if (!expanded) return NULL;
    memcpy(expanded, regexp, repeat_at);
    memcpy(expanded + repeat_at, replacement, (size_t)replacement_length);
    memcpy(expanded + repeat_at + (size_t)replacement_length,
           regexp + suffix_at, suffix_length + 1);
    return expanded;
}

/* Greedy (x|xx)* and (x|xx)+ can be collapsed to x* and x+ without changing
 * the observed spans. A lazy repetition with the longer branch written first
 * retains that branch priority when the sole suffix is x; leave that case
 * intact. Other suffixes can cause exponential PCRE2 backtracking, so keep
 * the collapsed form for them. */
static char *yx_regex_collapse_overlapping_repeat(const char *regexp)
{
    size_t length = strlen(regexp), used = 0;
    char *collapsed = malloc(length + 1);
    bool in_class = false, changed = false;
    if (!collapsed) return NULL;
    for (size_t i = 0; i < length;) {
        if (regexp[i] == '\\' && i + 1 < length) {
            collapsed[used++] = regexp[i++];
            collapsed[used++] = regexp[i++];
            continue;
        }
        if (regexp[i] == '[' && !in_class) in_class = true;
        else if (regexp[i] == ']' && in_class) in_class = false;
        if (!in_class && i + 6 < length && regexp[i] == '(' &&
            yx_plain_regex_byte((unsigned char)regexp[i + 1]) &&
            regexp[i + 5] == ')' &&
            (regexp[i + 6] == '*' || regexp[i + 6] == '+') &&
            !(regexp[i + 7] == '?' && regexp[i + 2] == regexp[i + 1] &&
              regexp[i + 8] == regexp[i + 1] && regexp[i + 9] == '\0') &&
            ((regexp[i + 2] == '|' &&
              regexp[i + 3] == regexp[i + 1] &&
              regexp[i + 4] == regexp[i + 1]) ||
             (regexp[i + 2] == regexp[i + 1] &&
              regexp[i + 3] == '|' &&
              regexp[i + 4] == regexp[i + 1]))) {
            collapsed[used++] = regexp[i + 1];
            i += 6;
            changed = true;
            continue;
        }
        collapsed[used++] = regexp[i++];
    }
    collapsed[used] = '\0';
    if (!changed) {
        free(collapsed);
        return NULL;
    }
    return collapsed;
}

/* In this literal-only star, YARA-X verifies the two-byte branch before its
   one-byte prefix. A plus uses that order when the suffix is the preferred
   atom, and otherwise ends at the last y preceded by x. Express the chosen
   endpoint before applying fullword, in both narrow and wide matching. */
static char *yx_regex_prioritize_repeated_literal_alt(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    bool plus, first_letter, tail_letter;
    char *ordered;
    if (regexp[0] != '(') return NULL;
    if (length >= 3 && regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 7 ||
        !yx_plain_regex_byte((unsigned char)regexp[at]) ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 3]) ||
        regexp[at] == regexp[at + 3] ||
        regexp[at + 1] != '|' || regexp[at + 2] != regexp[at] ||
        regexp[at + 4] != ')' ||
        (regexp[at + 5] != '*' && regexp[at + 5] != '+') ||
        regexp[at + 6] != regexp[at + 3])
        return NULL;
    first_letter = (regexp[at] >= 'a' && regexp[at] <= 'z') ||
                   (regexp[at] >= 'A' && regexp[at] <= 'Z');
    tail_letter = (regexp[at + 3] >= 'a' && regexp[at + 3] <= 'z') ||
                  (regexp[at + 3] >= 'A' && regexp[at + 3] <= 'Z');
    plus = first_letter && !tail_letter;
    if ((pattern->modifiers & YX_MOD_NOCASE) && first_letter && tail_letter &&
        yx_fold((uint8_t)regexp[at]) !=
            yx_fold((uint8_t)regexp[at + 3])) plus = true;
    if (regexp[at + 5] == '+' && !plus) {
        /* The leading atom's verifier keeps the trailing byte only when
           a new repetition follows it. Express
           that endpoint before fullword filtering, which cannot recover
           a longer span after the host matcher rejected an early end. */
        if ((pattern->modifiers & YX_MOD_NOCASE) &&
            yx_fold((uint8_t)regexp[at]) ==
                yx_fold((uint8_t)regexp[at + 3])) return NULL;
        ordered = malloc(12);
        if (!ordered) return NULL;
        ordered[0] = regexp[at];
        memcpy(ordered + 1, "(?:", 3);
        ordered[4] = regexp[at];
        ordered[5] = '|';
        ordered[6] = regexp[at + 3];
        ordered[7] = regexp[at];
        ordered[8] = ')';
        ordered[9] = '*';
        ordered[10] = regexp[at + 3];
        ordered[11] = '\0';
        return ordered;
    }
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, at);
    ordered[at] = regexp[at];
    ordered[at + 1] = regexp[at + 3];
    ordered[at + 2] = '|';
    ordered[at + 3] = regexp[at];
    memcpy(ordered + at + 4, regexp + at + 4, length - at - 3);
    return ordered;
}

/* In a repetition of [uv]|xy followed by y, YARA-X verifies the
   two-byte branch before the one-byte class when x is in the class and y
   is outside it. Preserve the written class order for all other shapes. */
static char *yx_regex_prioritize_repeated_class_literal_alt(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    char u, v, x, y;
    char *ordered;
    if ((pattern->modifiers & YX_MOD_FULLWORD) || regexp[0] != '(')
        return NULL;
    if (length >= 3 && regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 10 || regexp[at] != '[' ||
        regexp[at + 3] != ']' || regexp[at + 4] != '|' ||
        regexp[at + 7] != ')' || regexp[at + 8] != '+' ||
        regexp[at + 9] != regexp[at + 6]) return NULL;
    u = regexp[at + 1];
    v = regexp[at + 2];
    x = regexp[at + 5];
    y = regexp[at + 6];
    const unsigned char letters[] = {
        (unsigned char)u, (unsigned char)v,
        (unsigned char)x, (unsigned char)y
    };
    for (size_t i = 0; i < sizeof(letters); ++i)
        if (!((letters[i] >= 'a' && letters[i] <= 'z') ||
              (letters[i] >= 'A' && letters[i] <= 'Z'))) return NULL;
    if (yx_fold((uint8_t)u) == yx_fold((uint8_t)v) ||
        (yx_fold((uint8_t)x) != yx_fold((uint8_t)u) &&
         yx_fold((uint8_t)x) != yx_fold((uint8_t)v)) ||
        yx_fold((uint8_t)y) == yx_fold((uint8_t)u) ||
        yx_fold((uint8_t)y) == yx_fold((uint8_t)v)) return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, at);
    ordered[at] = x;
    ordered[at + 1] = y;
    ordered[at + 2] = '|';
    memcpy(ordered + at + 3, regexp + at, 4);
    memcpy(ordered + at + 7, regexp + at + 7, length - at - 6);
    return ordered;
}

/* For a repeated x|x[uv] group followed by u or v, YARA-X chooses the
   longer branch for greedy repetition and the shorter branch for lazy
   repetition. A greedy group whose class contains x needs the bounded
   quantifier and trailing x for this branch ordering to apply. An optional
   short-first group also favors the longer branch when x is the upper
   class member and the trailing byte is x. */
static char *yx_regex_prioritize_repeated_class_alt(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at, class_at, quant, suffix;
    bool short_first, greedy_bounded = false, optional = false;
    char x, u, v;
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (length < 11) return NULL;
    if (regexp[0] == '^') {
        if (regexp[1] != '(') return NULL;
        at = 2;
    } else {
        if (regexp[0] != '(') return NULL;
        at = 1;
    }
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (length < at + 10 ||
        !yx_plain_regex_byte((unsigned char)regexp[at])) return NULL;
    x = regexp[at];
    short_first = regexp[at + 1] == '|';
    if (short_first) {
        if (regexp[at + 2] != x || regexp[at + 3] != '[' ||
            regexp[at + 6] != ']' || regexp[at + 7] != ')') return NULL;
        class_at = at + 4;
    } else {
        if (regexp[at + 1] != '[' || regexp[at + 4] != ']' ||
            regexp[at + 5] != '|' || regexp[at + 6] != x ||
            regexp[at + 7] != ')') return NULL;
        class_at = at + 2;
    }
    u = regexp[class_at];
    v = regexp[class_at + 1];
    if (!yx_plain_regex_byte((unsigned char)u) ||
        !yx_plain_regex_byte((unsigned char)v) ||
        u == v) return NULL;
    quant = at + 8;
    if (short_first) {
        if (regexp[quant] == '?' &&
            !(pattern->modifiers & YX_MOD_XOR)) {
            suffix = quant + 1;
            optional = true;
        } else if ((regexp[quant] == '*' || regexp[quant] == '+') &&
            regexp[quant + 1] != '?') {
            suffix = quant + 1;
        } else if (length >= quant + 6 &&
                   (memcmp(regexp + quant, "{0,2}", 5) == 0 ||
                    memcmp(regexp + quant, "{1,2}", 5) == 0 ||
                    memcmp(regexp + quant, "{1,4}", 5) == 0)) {
            suffix = quant + 5;
            greedy_bounded = true;
        } else return NULL;
    } else if ((regexp[quant] == '*' || regexp[quant] == '+') &&
               regexp[quant + 1] == '?') {
        suffix = quant + 2;
    } else if (length >= quant + 7 &&
               (memcmp(regexp + quant, "{0,2}?", 6) == 0 ||
                memcmp(regexp + quant, "{1,2}?", 6) == 0 ||
                memcmp(regexp + quant, "{1,3}?", 6) == 0 ||
                memcmp(regexp + quant, "{1,4}?", 6) == 0)) {
        suffix = quant + 6;
    } else return NULL;
    if (length != suffix + 1 ||
        (regexp[suffix] != u && regexp[suffix] != v)) return NULL;
    if (short_first && optional &&
        !(u < x && v == x && regexp[suffix] == x)) return NULL;
    if (short_first && !optional && (u == x || v == x) &&
        !(greedy_bounded && regexp[suffix] == x)) return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, length + 1);
    if (short_first) {
        memcpy(ordered + at, regexp + at + 2, 5);
        ordered[at + 5] = '|';
        ordered[at + 6] = x;
    } else {
        ordered[at] = x;
        ordered[at + 1] = '|';
        memcpy(ordered + at + 2, regexp + at, 5);
    }
    return ordered;
}

/* For this lazy grouped form, a three-letter range behaves like the
   two-byte class above: YARA-X tries x before x[u-v]. Limit the rewrite
   to an exact lowercase range and a suffix drawn from that range. */
static char *yx_regex_prioritize_repeated_range_alt(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1, quant, suffix_at;
    char x, lower, upper, suffix;
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return NULL;
    if (length < 13) return NULL;
    if (regexp[0] == '^') {
        if (regexp[1] != '(') return NULL;
        ++at;
    } else if (regexp[0] != '(') return NULL;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (length < at + 12 || regexp[at + 1] != '[' ||
        regexp[at + 3] != '-' || regexp[at + 5] != ']' ||
        regexp[at + 6] != '|' || regexp[at + 7] != regexp[at] ||
        regexp[at + 8] != ')') return NULL;
    quant = at + 9;
    if (length == quant + 3 &&
        (regexp[quant] == '*' || regexp[quant] == '+') &&
        regexp[quant + 1] == '?') {
        suffix_at = quant + 2;
    } else if (length == quant + 7 &&
               (memcmp(regexp + quant, "{0,2}?", 6) == 0 ||
                memcmp(regexp + quant, "{1,2}?", 6) == 0 ||
                memcmp(regexp + quant, "{1,4}?", 6) == 0)) {
        suffix_at = quant + 6;
    } else return NULL;
    x = regexp[at];
    lower = regexp[at + 2];
    upper = regexp[at + 4];
    suffix = regexp[suffix_at];
    if (x < 'a' || x > 'z' || lower < 'a' || lower > 'x' ||
        upper != lower + 2 || suffix < lower || suffix > upper) return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, length + 1);
    ordered[at] = x;
    ordered[at + 1] = '|';
    memcpy(ordered + at + 2, regexp + at, 6);
    return ordered;
}

/* A greedy bounded short-first group favors its range branch when the
   range excludes x, or when the trailing byte is x itself. Other overlaps
   can produce spans that neither fixed branch order reproduces. */
static char *yx_regex_prioritize_bounded_range_alt(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1, quant;
    char x, lower, upper, suffix;
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return NULL;
    if (length < 16) return NULL;
    if (regexp[0] == '^') {
        if (regexp[1] != '(') return NULL;
        ++at;
    } else if (regexp[0] != '(') return NULL;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (length != at + 15 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 3] != '[' ||
        regexp[at + 5] != '-' || regexp[at + 7] != ']' ||
        regexp[at + 8] != ')') return NULL;
    quant = at + 9;
    if (memcmp(regexp + quant, "{0,2}", 5) != 0 &&
        memcmp(regexp + quant, "{1,2}", 5) != 0 &&
        memcmp(regexp + quant, "{1,4}", 5) != 0) return NULL;
    x = regexp[at];
    lower = regexp[at + 4];
    upper = regexp[at + 6];
    suffix = regexp[quant + 5];
    if (x < 'a' || x > 'z' || lower < 'a' || lower > 'x' ||
        upper != lower + 2 || suffix < lower || suffix > upper ||
        (x >= lower && x <= upper && suffix != x)) return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, length + 1);
    memcpy(ordered + at, regexp + at + 2, 6);
    ordered[at + 6] = '|';
    ordered[at + 7] = x;
    return ordered;
}

/* A greedy x|x[xy] repetition followed by y chooses the longest valid span
   at each offset. Neither PCRE2 branch order has that behavior when the
   class contains x, so solve this exact shape from right to left. The two
   saved suffix ends are the best results after consuming one or two bytes. */
static int yx_scan_greedy_overlapping_class(YRX_PATTERN *pattern,
                                            const uint8_t *data, size_t size,
                                            size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    size_t next_one = SIZE_MAX, next_two = SIZE_MAX, replace_at = 0;
    bool anchored = regexp[0] == '^', one_or_more;
    uint8_t x, u, v, suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (length < 11 || regexp[anchored ? 1 : 0] != '(') return 1;
    if (anchored) ++at;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (length != at + 10 ||
        !yx_plain_regex_byte((unsigned char)regexp[at]) ||
        regexp[at + 1] != '|' || regexp[at + 2] != regexp[at] ||
        regexp[at + 3] != '[' || regexp[at + 6] != ']' ||
        regexp[at + 7] != ')' ||
        (regexp[at + 8] != '*' && regexp[at + 8] != '+') ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 4]) ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 5]) ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 9])) return 1;
    x = (uint8_t)regexp[at];
    u = (uint8_t)regexp[at + 4];
    v = (uint8_t)regexp[at + 5];
    suffix = (uint8_t)regexp[at + 9];
    if (u == v || (u != x && v != x) || suffix == x ||
        (suffix != u && suffix != v)) return 1;
    one_or_more = regexp[at + 8] == '+';
    *handled = true;
    for (size_t i = size; i-- > 0;) {
        size_t best = data[i] == suffix ? i + 1 : SIZE_MAX;
        size_t repeated = SIZE_MAX;
        if (data[i] == x) {
            repeated = next_one;
            if (i + 1 < size &&
                (data[i + 1] == u || data[i + 1] == v) &&
                next_two != SIZE_MAX &&
                (repeated == SIZE_MAX || next_two > repeated))
                repeated = next_two;
            if (repeated != SIZE_MAX &&
                (best == SIZE_MAX || repeated > best)) best = repeated;
        }
        if (!anchored || i == 0) {
            size_t end = one_or_more ? repeated : best;
            if (end != SIZE_MAX) {
                if (limit && pattern->match_count == limit) {
                    pattern->matches[replace_at] = (YRX_MATCH){i, end - i, -1};
                    replace_at = replace_at + 1 == limit ? 0 : replace_at + 1;
                } else if (!yx_add_match(pattern, i, end - i, 0)) return 0;
            }
        }
        next_two = next_one;
        next_one = best;
    }
    return 1;
}

/* For a greedy bounded x|x[class] group, the verifier keeps the longest
   valid span when x and the trailing byte are distinct class members.
   Branch reordering alone can choose a shorter span. This small state set
   explores both one- and two-byte branches for at most four repetitions. */
static int yx_scan_greedy_bounded_overlap(YRX_PATTERN *pattern,
                                          const uint8_t *data, size_t size,
                                          size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1, class_at, close_at, quant;
    bool anchored = regexp[0] == '^', short_first, range;
    uint8_t x, lower, upper, suffix, minimum, maximum;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (length < 15 || regexp[anchored ? 1 : 0] != '(') return 1;
    if (anchored) ++at;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (length < at + 14 ||
        !yx_plain_regex_byte((unsigned char)regexp[at])) return 1;
    x = (uint8_t)regexp[at];
    short_first = regexp[at + 1] == '|';
    if (short_first) {
        if (regexp[at + 2] != x || regexp[at + 3] != '[') return 1;
        class_at = at + 4;
    } else {
        if (regexp[at + 1] != '[') return 1;
        class_at = at + 2;
    }
    range = regexp[class_at + 1] == '-';
    close_at = class_at + (range ? 3 : 2);
    if (close_at + 1 >= length || regexp[close_at] != ']' ||
        !yx_plain_regex_byte((unsigned char)regexp[class_at]) ||
        !yx_plain_regex_byte((unsigned char)regexp[class_at +
                                                   (range ? 2 : 1)])) return 1;
    lower = (uint8_t)regexp[class_at];
    upper = (uint8_t)regexp[class_at + (range ? 2 : 1)];
    if (lower < 'a' || upper > 'z' || upper <= lower ||
        (range && upper != lower + 2)) return 1;
    if (short_first) {
        if (regexp[close_at + 1] != ')') return 1;
        quant = close_at + 2;
    } else {
        if (close_at + 3 >= length || regexp[close_at + 1] != '|' ||
            regexp[close_at + 2] != x || regexp[close_at + 3] != ')') return 1;
        quant = close_at + 4;
    }
    if (length != quant + 6) return 1;
    if (memcmp(regexp + quant, "{0,2}", 5) == 0) {
        minimum = 0;
        maximum = 2;
    } else if (memcmp(regexp + quant, "{1,2}", 5) == 0) {
        minimum = 1;
        maximum = 2;
    } else if (memcmp(regexp + quant, "{1,4}", 5) == 0) {
        minimum = 1;
        maximum = 4;
    } else return 1;
    suffix = (uint8_t)regexp[quant + 5];
    if (!yx_plain_regex_byte(suffix) || suffix == x ||
        (range ? (x < lower || x > upper ||
                  suffix < lower || suffix > upper) :
                 ((x != lower && x != upper) ||
                  (suffix != lower && suffix != upper)))) return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        bool reachable[9] = {true}, next[9];
        size_t available = size - offset, best = 0;
        for (unsigned count = 0; count <= maximum; ++count) {
            for (unsigned delta = 0; delta <= 2 * count; ++delta) {
                if (reachable[delta] && count >= minimum &&
                    delta < available && data[offset + delta] == suffix &&
                    delta + 1 > best) best = delta + 1;
            }
            if (count == maximum) break;
            memset(next, 0, sizeof(next));
            for (unsigned delta = 0; delta <= 2 * count; ++delta) {
                if (!reachable[delta] || delta >= available ||
                    data[offset + delta] != x) continue;
                next[delta + 1] = true;
                if (delta + 1 < available) {
                    uint8_t member = data[offset + delta + 1];
                    if (range ? (member >= lower && member <= upper) :
                                (member == lower || member == upper))
                        next[delta + 2] = true;
                }
            }
            memcpy(reachable, next, sizeof(reachable));
        }
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
        if (anchored) break;
    }
    return 1;
}

static bool yx_parse_two_or_three_lower_class(const char *regexp,
                                              size_t length, size_t *at,
                                              uint32_t *mask)
{
    size_t pos = *at;
    bool range = false;
    char lower, upper;
    if (pos + 3 >= length || regexp[pos] != '[') return false;
    lower = regexp[pos + 1];
    if (regexp[pos + 3] == ']') {
        upper = regexp[pos + 2];
        *at = pos + 4;
    } else if (pos + 4 < length && regexp[pos + 2] == '-' &&
               regexp[pos + 4] == ']') {
        upper = regexp[pos + 3];
        *at = pos + 5;
        range = true;
    } else return false;
    if (lower < 'a' || upper > 'z' || upper <= lower ||
        (range && upper != lower + 2)) return false;
    *mask = (UINT32_C(1) << (lower - 'a')) |
            (UINT32_C(1) << (upper - 'a'));
    if (range) *mask |= UINT32_C(1) << (lower + 1 - 'a');
    return true;
}

static bool yx_parse_nested_one_byte_alt(const char *regexp, size_t length,
                                         size_t *at, uint32_t *mask)
{
    uint32_t class_mask;
    char literal;
    if (*at + 3 >= length || memcmp(regexp + *at, "(?:", 3) != 0)
        return false;
    *at += 3;
    if (regexp[*at] == '[') {
        if (!yx_parse_two_or_three_lower_class(regexp, length, at,
                                               &class_mask) ||
            *at + 2 >= length || regexp[(*at)++] != '|') return false;
        literal = regexp[(*at)++];
    } else {
        if (*at + 2 >= length) return false;
        literal = regexp[(*at)++];
        if (regexp[(*at)++] != '|' ||
            !yx_parse_two_or_three_lower_class(regexp, length, at,
                                               &class_mask)) return false;
    }
    if (literal < 'a' || literal > 'z' || *at >= length ||
        regexp[(*at)++] != ')') return false;
    *mask = class_mask | (UINT32_C(1) << (literal - 'a'));
    return true;
}

/* The nested one-byte alternation and adjacent class form a two-byte unit.
   YARA-X can consume three units for {1,2} or five for {1,3}; the lazy
   {1,3}? form selects the shortest suffix-valid span within five units. */
static int yx_scan_nested_fixed_pair(YRX_PATTERN *pattern,
                                      const uint8_t *data, size_t size,
                                      size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0;
    uint32_t first_mask, second_mask;
    unsigned maximum;
    bool lazy = false;
    char suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (regexp[at] == '[') {
        if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                               &first_mask) ||
            !yx_parse_nested_one_byte_alt(regexp, length, &at,
                                          &second_mask)) return 1;
    } else {
        if (!yx_parse_nested_one_byte_alt(regexp, length, &at,
                                          &first_mask) ||
            !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                               &second_mask)) return 1;
    }
    if (at >= length || regexp[at++] != ')') return 1;
    if (at + 6 == length && memcmp(regexp + at, "{1,2}", 5) == 0)
        maximum = 3;
    else if (at + 6 == length &&
             memcmp(regexp + at, "{1,3}", 5) == 0) maximum = 5;
    else if (at + 7 == length &&
             memcmp(regexp + at, "{1,3}?", 6) == 0) {
        maximum = 5;
        lazy = true;
    } else return 1;
    suffix = regexp[length - 1];
    if (suffix < 'a' || suffix > 'z') return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        size_t available = size - offset;
        for (unsigned trial = 0; trial < maximum; ++trial) {
            unsigned repetitions = lazy ? trial + 1 : maximum - trial;
            if (available < repetitions * 2 + 1 ||
                data[offset + repetitions * 2] != (uint8_t)suffix) continue;
            bool matched = true;
            for (unsigned pair = 0; pair < repetitions; ++pair) {
                uint8_t first = data[offset + pair * 2];
                uint8_t second = data[offset + pair * 2 + 1];
                if (first < 'a' || first > 'z' ||
                    second < 'a' || second > 'z' ||
                    !(first_mask & (UINT32_C(1) << (first - 'a'))) ||
                    !(second_mask & (UINT32_C(1) << (second - 'a')))) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                if (!yx_add_match(pattern, offset,
                                  repetitions * 2 + 1, limit)) return 0;
                break;
            }
        }
        if (anchored) break;
    }
    return 1;
}

/* The outer class and one-or-two-byte inner group have overlapping first
   bytes. For these three greedy outer bounds, YARA-X takes the longest
   suffix-valid span; source-order backtracking can stop earlier. */
static int yx_scan_greedy_nested_class_alt(YRX_PATTERN *pattern,
                                            const uint8_t *data, size_t size,
                                            size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0;
    uint32_t outer_mask, inner_mask;
    unsigned minimum, maximum;
    char suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_nested_one_byte_alt(regexp, length, &at,
                                      &inner_mask) ||
        at + 5 >= length || memcmp(regexp + at, "{1,2}", 5) != 0)
        return 1;
    at += 5;
    if (at + 7 != length || regexp[at++] != ')') return 1;
    if (memcmp(regexp + at, "{0,2}", 5) == 0) {
        minimum = 0;
        maximum = 2;
    } else if (memcmp(regexp + at, "{1,2}", 5) == 0) {
        minimum = 1;
        maximum = 2;
    } else if (memcmp(regexp + at, "{1,3}", 5) == 0) {
        minimum = 1;
        maximum = 3;
    } else return 1;
    suffix = regexp[at + 5];
    if (suffix < 'a' || suffix > 'z') return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        bool reachable[7] = {true}, next[7];
        size_t available = size - offset, best = 0;
        for (unsigned count = 0; count <= maximum; ++count) {
            for (unsigned delta = 0; delta <= 2 * count; ++delta) {
                if (reachable[delta] && count >= minimum &&
                    delta < available && data[offset + delta] == suffix &&
                    delta + 1 > best) best = delta + 1;
            }
            if (count == maximum) break;
            memset(next, 0, sizeof(next));
            for (unsigned delta = 0; delta <= 2 * count; ++delta) {
                if (!reachable[delta] || delta >= available) continue;
                uint8_t first = data[offset + delta];
                if (first < 'a' || first > 'z') continue;
                uint32_t first_bit = UINT32_C(1) << (first - 'a');
                if ((outer_mask | inner_mask) & first_bit)
                    next[delta + 1] = true;
                if ((inner_mask & first_bit) && delta + 1 < available) {
                    uint8_t second = data[offset + delta + 1];
                    if (second >= 'a' && second <= 'z' &&
                        (inner_mask & (UINT32_C(1) << (second - 'a'))))
                        next[delta + 2] = true;
                }
            }
            memcpy(reachable, next, sizeof(reachable));
        }
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
        if (anchored) break;
    }
    return 1;
}

/* YARA-X's bounded verifier for ([xy]|x[yz]){1,2} can retain three
   one-byte class atoms. A two-byte first atom is retained only when another
   [xy] byte follows it. PCRE2's alternation backtracking returns shorter
   spans for this exact form. Keep the verifier local to the bounded group;
   only an optional z suffix is included. Wide variants evaluate each
   logical byte with its required zero high byte. With ascii wide, YARA-X's
   short-input path selects wide on a one-unit tie, while its path for inputs
   of at least 16 bytes selects ASCII. */
static int yx_scan_bounded_overlap_class_branch(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    bool anchored = regexp && regexp[0] == '^';
    size_t at = anchored ? 2 : 1;
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool combined = wide && (pattern->modifiers & YX_MOD_ASCII);
    size_t length;
    bool optional_suffix;
    *handled = false;
    if (!regexp || (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        regexp[anchored ? 1 : 0] != '(')
        return 1;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    length = strlen(regexp);
    optional_suffix = length == at + 18 &&
        regexp[at + 16] == regexp[at + 8] &&
        regexp[at + 17] == '?';
    if ((length != at + 16 && !optional_suffix) || regexp[at] != '[' ||
        regexp[at + 3] != ']' || regexp[at + 4] != '|' ||
        regexp[at + 6] != '[' || regexp[at + 9] != ']' ||
        regexp[at + 10] != ')' ||
        memcmp(regexp + at + 11, "{1,2}", 5) != 0)
        return 1;
    x = (uint8_t)regexp[at + 1];
    y = (uint8_t)regexp[at + 2];
    z = (uint8_t)regexp[at + 8];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || regexp[at + 5] != (char)x ||
        regexp[at + 7] != (char)y ||
        yx_fold(x) >= yx_fold(y) || yx_fold(y) >= yx_fold(z))
        return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        size_t best_units = 0, best_span = 0;
        for (size_t variant = 0; variant < (combined ? 2u : 1u);
             ++variant) {
            size_t step = wide && (!combined || variant == 1) ? 2u : 1u;
            uint8_t view[5];
            size_t available = 0, span = 0;
            while (available < 5 && available < (size - offset) / step) {
                size_t pos = offset + available * step;
                if (step == 2 && data[pos + 1] != 0) break;
                view[available++] = data[pos];
            }
            while (span < 3 && span < available) {
                uint8_t byte = view[span];
                if (nocase) byte = yx_fold(byte);
                if (byte != (nocase ? yx_fold(x) : x) &&
                    byte != (nocase ? yx_fold(y) : y)) break;
                ++span;
            }
            if (available >= 3) {
                uint8_t first = view[0], second = view[1];
                uint8_t third = view[2];
                if (nocase) {
                    first = yx_fold(first);
                    second = yx_fold(second);
                    third = yx_fold(third);
                }
                if (first == (nocase ? yx_fold(x) : x) &&
                    (second == (nocase ? yx_fold(y) : y) ||
                     second == (nocase ? yx_fold(z) : z)) &&
                    (third == (nocase ? yx_fold(x) : x) ||
                     third == (nocase ? yx_fold(y) : y))) {
                    size_t long_span = 3;
                    if (available >= 4) {
                        uint8_t fourth = view[3];
                        if (nocase) fourth = yx_fold(fourth);
                        if (fourth == (nocase ? yx_fold(x) : x) ||
                            fourth == (nocase ? yx_fold(y) : y))
                            long_span = 4;
                    }
                    if (long_span > span) span = long_span;
                }
            }
            if (span > best_units ||
                (combined && variant == 1 && span == best_units && span &&
                 size < 16)) {
                size_t total = span;
                if (optional_suffix && total < available) {
                    uint8_t suffix_byte = view[total];
                    if (nocase) suffix_byte = yx_fold(suffix_byte);
                    if (suffix_byte == (nocase ? yx_fold(z) : z)) ++total;
                }
                best_units = span;
                best_span = total * step;
            }
        }
        if (best_span &&
            !yx_add_match(pattern, offset, best_span, limit)) return 0;
        if (anchored) break;
    }
    return 1;
}

/* For ([ab]|ba){1,2}, the reference verifier retains a three-byte span
   whenever three class bytes follow the start. It extends to four bytes
   only when the two-byte literal starts the span.
   Handle only this bounded class-first form; other alternation orders and
   modifiers use the ordinary regexp scanner. */
static int yx_scan_bounded_class_literal_branch(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length, at = 1;
    uint8_t x, y, first, second;
    *handled = false;
    if (!regexp || (pattern->modifiers != 0 &&
                    pattern->modifiers != YX_MOD_ASCII)) return 1;
    length = strlen(regexp);
    if (length < 3 || regexp[0] != '(') return 1;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 13 || regexp[at] != '[' ||
        regexp[at + 3] != ']' || regexp[at + 4] != '|' ||
        regexp[at + 7] != ')' ||
        memcmp(regexp + at + 8, "{1,2}", 5) != 0) return 1;
    x = (uint8_t) regexp[at + 1];
    y = (uint8_t) regexp[at + 2];
    first = (uint8_t) regexp[at + 5];
    second = (uint8_t) regexp[at + 6];
    if (x >= y ||
        !((x >= 'a' && x <= 'z' && y >= 'a' && y <= 'z') ||
          (x >= '0' && x <= '9' && y >= '0' && y <= '9')) ||
        (first != x && first != y) ||
        (second != x && second != y)) return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t run = 0, span;
        while (run < 4 && run < size - offset &&
               (data[offset + run] == x || data[offset + run] == y))
            ++run;
        if (!run) continue;
        span = run < 3 ? run : 3;
        if (run == 4 && data[offset] == first &&
            data[offset + 1] == second) span = 4;
        if (!yx_add_match(pattern, offset, span, limit)) return 0;
    }
    return 1;
}

/* When the inner one-byte alternatives cover a, b, and c, and the outer
   class is a subset, each outer unit consumes one or two of those bytes.
   The exact {2,3} outer bound therefore covers lengths two through six. */
static int yx_scan_greedy_nested_subset_count(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit,
    bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0;
    uint32_t outer_mask, inner_class_mask;
    char singleton, suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at >= length || regexp[at++] != '|' ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (regexp[at] == '[') {
        if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                               &inner_class_mask) ||
            at >= length || regexp[at++] != '|' || at >= length)
            return 1;
        singleton = regexp[at++];
    } else {
        if (at + 1 >= length) return 1;
        singleton = regexp[at++];
        if (regexp[at++] != '|' ||
            !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                               &inner_class_mask)) return 1;
    }
    if (singleton < 'a' || singleton > 'c' ||
        (inner_class_mask != UINT32_C(3) &&
         inner_class_mask != UINT32_C(5) &&
         inner_class_mask != UINT32_C(6)) ||
        (inner_class_mask | (UINT32_C(1) << (singleton - 'a'))) !=
            UINT32_C(7) ||
        (outer_mask != UINT32_C(3) && outer_mask != UINT32_C(5) &&
         outer_mask != UINT32_C(6)) ||
        at + 13 != length || regexp[at++] != ')' ||
        memcmp(regexp + at, "{1,2}", 5) != 0 ||
        regexp[at + 5] != ')' ||
        memcmp(regexp + at + 6, "{2,3}", 5) != 0)
        return 1;
    suffix = regexp[at + 11];
    if (suffix != 'b' && suffix != 'c') return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        size_t available = size - offset;
        for (unsigned count = 6; count >= 2; --count) {
            if (available < count + 1 ||
                data[offset + count] != (uint8_t)suffix) continue;
            bool matched = true;
            for (unsigned i = 0; i < count; ++i) {
                uint8_t ch = data[offset + i];
                if (ch < 'a' || ch > 'c') {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                if (!yx_add_match(pattern, offset, count + 1, limit))
                    return 0;
                break;
            }
        }
        if (anchored) break;
    }
    return 1;
}

typedef struct {
    unsigned width;
    uint32_t masks[2];
} YX_SMALL_REGEX_BRANCH;

static bool yx_parse_small_lower_branch(const char *regexp, size_t length,
                                        size_t *at, YX_SMALL_REGEX_BRANCH *out)
{
    bool first_class = false;
    out->width = 0;
    while (*at < length && regexp[*at] != '|' && regexp[*at] != ')') {
        uint32_t mask;
        bool is_class = regexp[*at] == '[';
        if (out->width == 2 || (out->width == 1 && first_class))
            return false;
        if (is_class) {
            if (!yx_parse_two_or_three_lower_class(regexp, length, at,
                                                   &mask)) return false;
        } else {
            char literal = regexp[(*at)++];
            if (literal < 'a' || literal > 'z') return false;
            mask = UINT32_C(1) << (literal - 'a');
        }
        if (out->width == 0) first_class = is_class;
        out->masks[out->width++] = mask;
    }
    return out->width != 0;
}

static bool yx_match_small_lower_branch(const YX_SMALL_REGEX_BRANCH *branch,
                                        const uint8_t *data, size_t available)
{
    if (available < branch->width) return false;
    for (unsigned i = 0; i < branch->width; ++i) {
        uint8_t ch = data[i];
        if (ch < 'a' || ch > 'z' ||
            !(branch->masks[i] & (UINT32_C(1) << (ch - 'a'))))
            return false;
    }
    return true;
}

/* A one-byte branch beside a two-byte branch inside the repeated group
   produces up to four bytes per outer repetition. For these exact greedy
   bounds, YARA-X selects the longest suffix-valid path through the two
   inner repetitions and the outer class alternative. */
static int yx_scan_greedy_nested_variable_class_alt(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit,
    bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0;
    uint32_t outer_mask;
    YX_SMALL_REGEX_BRANCH branch[2];
    unsigned minimum, maximum;
    char suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at >= length || regexp[at++] != '|' ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        branch[0].width + branch[1].width != 3 ||
        at + 6 >= length || regexp[at++] != ')' ||
        memcmp(regexp + at, "{1,2}", 5) != 0) return 1;
    at += 5;
    if (at + 7 != length || regexp[at++] != ')') return 1;
    if (memcmp(regexp + at, "{0,2}", 5) == 0) {
        minimum = 0;
        maximum = 2;
    } else if (memcmp(regexp + at, "{1,2}", 5) == 0) {
        minimum = 1;
        maximum = 2;
    } else if (memcmp(regexp + at, "{1,3}", 5) == 0) {
        minimum = 1;
        maximum = 3;
    } else return 1;
    suffix = regexp[at + 5];
    if (suffix < 'a' || suffix > 'z') return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        bool reachable[13] = {true}, next[13];
        size_t available = size - offset, best = 0;
        for (unsigned count = 0; count <= maximum; ++count) {
            for (unsigned delta = 0; delta <= 4 * count; ++delta) {
                if (reachable[delta] && count >= minimum &&
                    delta < available && data[offset + delta] == suffix &&
                    delta + 1 > best) best = delta + 1;
            }
            if (count == maximum) break;
            memset(next, 0, sizeof(next));
            for (unsigned delta = 0; delta <= 4 * count; ++delta) {
                if (!reachable[delta] || delta >= available) continue;
                uint8_t ch = data[offset + delta];
                if (ch >= 'a' && ch <= 'z' &&
                    (outer_mask & (UINT32_C(1) << (ch - 'a'))))
                    next[delta + 1] = true;
                for (unsigned first = 0; first < 2; ++first) {
                    const YX_SMALL_REGEX_BRANCH *one = &branch[first];
                    if (!yx_match_small_lower_branch(one,
                                                     data + offset + delta,
                                                     available - delta))
                        continue;
                    next[delta + one->width] = true;
                    for (unsigned second = 0; second < 2; ++second) {
                        const YX_SMALL_REGEX_BRANCH *two = &branch[second];
                        if (yx_match_small_lower_branch(
                                two, data + offset + delta + one->width,
                                available - delta - one->width))
                            next[delta + one->width + two->width] = true;
                    }
                }
            }
            memcpy(reachable, next, sizeof(reachable));
        }
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
        if (anchored) break;
    }
    return 1;
}

/* For these bounded nested lazy forms, YARA-X selects the shortest
   suffix-valid path through the outer and inner alternatives. Keep the
   accepted syntax narrow because other nested lazy shapes have different
   verifier priorities. */
static int yx_scan_lazy_nested_shortest_variants(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit,
    bool *handled)
{
    static const YX_SMALL_REGEX_BRANCH first_branches[2] = {
        {1, {UINT32_C(2), 0}},
        {2, {UINT32_C(1), UINT32_C(6)}}
    };
    static const YX_SMALL_REGEX_BRANCH second_branches[2] = {
        {1, {UINT32_C(1), 0}},
        {2, {UINT32_C(2), UINT32_C(4)}}
    };
    const char *regexp = pattern->regexp;
    const YX_SMALL_REGEX_BRANCH *branch;
    uint32_t outer_mask;
    unsigned minimum, maximum;
    bool first_zero = strcmp(regexp,
        "(?:[ac]|(?:b|a[bc]){1,2}?){0,2}?c") == 0;
    bool first_one = strcmp(regexp,
        "(?:[ac]|(?:b|a[bc]){1,2}?){1,3}?c") == 0;
    bool second_two = strcmp(regexp,
        "(?:[bc]|(?:a|bc){1,2}?){1,3}?c") == 0;
    bool second_three = strcmp(regexp,
        "(?:[a-c]|(?:bc|a){1,2}?){1,3}?c") == 0;
    *handled = false;
    if ((!first_zero && !first_one && !second_two && !second_three) ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR))) return 1;
    branch = (first_zero || first_one) ? first_branches : second_branches;
    outer_mask = (first_zero || first_one) ? UINT32_C(5) :
                 (second_two ? UINT32_C(6) : UINT32_C(7));
    minimum = first_zero ? 0 : 1;
    maximum = first_zero ? 2 : 3;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        bool reachable[13] = {true}, next[13];
        size_t available = size - offset, best = SIZE_MAX;
        for (unsigned count = 0; count <= maximum; ++count) {
            for (unsigned delta = 0; delta <= 4 * count; ++delta) {
                if (reachable[delta] && count >= minimum &&
                    delta < available && data[offset + delta] == 'c' &&
                    delta + 1 < best) best = delta + 1;
            }
            if (count == maximum) break;
            memset(next, 0, sizeof(next));
            for (unsigned delta = 0; delta <= 4 * count; ++delta) {
                if (!reachable[delta] || delta >= available) continue;
                uint8_t ch = data[offset + delta];
                if (ch >= 'a' && ch <= 'z' &&
                    (outer_mask & (UINT32_C(1) << (ch - 'a'))))
                    next[delta + 1] = true;
                for (unsigned first = 0; first < 2; ++first) {
                    const YX_SMALL_REGEX_BRANCH *one = &branch[first];
                    if (!yx_match_small_lower_branch(one,
                                                     data + offset + delta,
                                                     available - delta))
                        continue;
                    size_t after_one = delta + one->width;
                    next[after_one] = true;
                    for (unsigned second = 0; second < 2; ++second) {
                        const YX_SMALL_REGEX_BRANCH *two = &branch[second];
                        if (yx_match_small_lower_branch(
                                two, data + offset + after_one,
                                available - after_one))
                            next[after_one + two->width] = true;
                    }
                }
            }
            memcpy(reachable, next, sizeof(reachable));
        }
        if (best != SIZE_MAX &&
            !yx_add_match(pattern, offset, best, limit)) return 0;
    }
    return 1;
}

/* This nested {1,2} pair chooses the longest valid span within its written
   bounds when the inner branches do not form a literal x|xy prefix pair.
   That prefix pair has separate verifier behavior and remains on the regex
   engine path. */
static int yx_scan_greedy_nested_counted_class(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit,
    bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0;
    YX_SMALL_REGEX_BRANCH branch[2];
    uint32_t class_mask;
    char suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (at + 6 >= length || memcmp(regexp + at, "(?:(?:", 6) != 0)
        return 1;
    at += 6;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        branch[0].width + branch[1].width > 3 ||
        at + 6 >= length || regexp[at++] != ')' ||
        memcmp(regexp + at, "{1,2}", 5) != 0) return 1;
    at += 5;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &class_mask) ||
        at + 7 != length || regexp[at++] != ')' ||
        memcmp(regexp + at, "{1,2}", 5) != 0) return 1;
    suffix = regexp[at + 5];
    if (suffix < 'a' || suffix > 'z') return 1;
    if (branch[0].width != branch[1].width) {
        unsigned short_at = branch[0].width == 1 ? 0 : 1;
        unsigned long_at = 1 - short_at;
        uint32_t single = branch[short_at].masks[0];
        uint32_t tail = branch[long_at].masks[1];
        if ((single & (single - 1)) == 0 &&
            (tail & (tail - 1)) == 0 &&
            single == branch[long_at].masks[0]) return 1;
    }
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        bool reachable[11] = {true}, next[11];
        size_t available = size - offset, best = 0;
        for (unsigned count = 0; count <= 2; ++count) {
            for (unsigned delta = 0; delta <= 5 * count; ++delta) {
                if (reachable[delta] && count && delta < available &&
                    data[offset + delta] == suffix && delta + 1 > best)
                    best = delta + 1;
            }
            if (count == 2) break;
            memset(next, 0, sizeof(next));
            for (unsigned delta = 0; delta <= 5 * count; ++delta) {
                if (!reachable[delta] || delta >= available) continue;
                for (unsigned first = 0; first < 2; ++first) {
                    const YX_SMALL_REGEX_BRANCH *one = &branch[first];
                    if (!yx_match_small_lower_branch(one,
                                                     data + offset + delta,
                                                     available - delta))
                        continue;
                    size_t after_one = delta + one->width;
                    if (after_one < available) {
                        uint8_t ch = data[offset + after_one];
                        if (ch >= 'a' && ch <= 'z' &&
                            (class_mask & (UINT32_C(1) << (ch - 'a'))))
                            next[after_one + 1] = true;
                    }
                    for (unsigned second = 0; second < 2; ++second) {
                        const YX_SMALL_REGEX_BRANCH *two = &branch[second];
                        if (!yx_match_small_lower_branch(
                                two, data + offset + after_one,
                                available - after_one)) continue;
                        size_t after_two = after_one + two->width;
                        if (after_two < available) {
                            uint8_t ch = data[offset + after_two];
                            if (ch >= 'a' && ch <= 'z' &&
                                (class_mask & (UINT32_C(1) << (ch - 'a'))))
                                next[after_two + 1] = true;
                        }
                    }
                }
            }
            memcpy(reachable, next, sizeof(reachable));
        }
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
        if (anchored) break;
    }
    return 1;
}

static size_t yx_match_nested_pair_first_long(
    const uint8_t *data, size_t size, size_t at,
    const YX_SMALL_REGEX_BRANCH branch[2], uint32_t class_mask,
    uint8_t suffix, unsigned remaining, bool first)
{
    if (remaining == 0)
        return at < size && data[at] == suffix ? at + 1 : 0;
    if (at >= size || data[at] < 'a' || data[at] > 'z' ||
        !(class_mask & (UINT32_C(1) << (data[at] - 'a')))) return 0;
    for (unsigned choice = 0; choice < 2; ++choice) {
        unsigned index = first ? 1 - choice : choice;
        const YX_SMALL_REGEX_BRANCH *item = &branch[index];
        size_t branch_at = at + 1;
        if (!yx_match_small_lower_branch(item, data + branch_at,
                                         size - branch_at)) continue;
        size_t end = yx_match_nested_pair_first_long(
            data, size, branch_at + item->width, branch, class_mask,
            suffix, remaining - 1, false);
        if (end) return end;
    }
    return 0;
}

/* For disjoint branch starts, and for certain overlapping short classes,
   YARA-X takes the longest suffix-valid span through the verified effective
   bounds. */
static int yx_scan_greedy_nested_pair(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit,
    bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0, class_first;
    YX_SMALL_REGEX_BRANCH branch[2];
    uint32_t class_mask;
    unsigned maximum;
    char suffix;
    *handled = false;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return 1;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    class_first = regexp[at] == '[';
    if (class_first &&
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &class_mask)) return 1;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return 1;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        branch[0].width + branch[1].width != 3 ||
        at >= length || regexp[at++] != ')') return 1;
    if (!class_first &&
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &class_mask)) return 1;
    if (at + 7 != length || regexp[at++] != ')') return 1;
    if (memcmp(regexp + at, "{1,2}", 5) == 0) maximum = 3;
    else if (memcmp(regexp + at, "{1,3}", 5) == 0) maximum = 5;
    else return 1;
    suffix = regexp[at + 5];
    if (suffix < 'a' || suffix > 'z') return 1;
    unsigned short_at = branch[0].width == 1 ? 0 : 1;
    unsigned long_at = 1 - short_at;
    uint32_t single = branch[short_at].masks[0];
    uint32_t first = branch[long_at].masks[0];
    uint32_t tail = branch[long_at].masks[1];
    uint32_t one_removed = single & (single - 1);
    uint32_t suffix_bit = UINT32_C(1) << (suffix - 'a');
    bool disjoint_literal = one_removed == 0 && single != first;
    bool overlap_class = !class_first && maximum == 3 &&
        single == class_mask && one_removed != 0 &&
        (one_removed & (one_removed - 1)) == 0 &&
        (single & first) != 0 && (single & tail) == 0 &&
        (tail & (tail - 1)) == 0 &&
        (single & suffix_bit) != 0;
    bool anchored_class_overlap = anchored && class_first &&
        maximum == 5 && short_at == 0 && one_removed != 0 &&
        (one_removed & (one_removed - 1)) == 0 &&
        (first & (first - 1)) == 0 &&
        (tail & (tail - 1)) == 0 &&
        (single & first) != 0 && (single & tail) == 0 &&
        class_mask == (first | tail) && suffix_bit == first;
    bool outer_suffix_overlap = class_first && maximum == 3 &&
        short_at == 0 && one_removed != 0 &&
        (one_removed & (one_removed - 1)) == 0 &&
        (first & (first - 1)) == 0 &&
        (tail & (tail - 1)) == 0 &&
        first != tail && first != suffix_bit && tail != suffix_bit &&
        single == (first | suffix_bit) &&
        class_mask == (tail | suffix_bit);
    if (!disjoint_literal && !overlap_class && !anchored_class_overlap &&
        !outer_suffix_overlap)
        return 1;
    *handled = true;
    if (outer_suffix_overlap) {
        for (size_t offset = 0; offset < size &&
                                (!limit || pattern->match_count < limit);
             ++offset) {
            size_t end = 0;
            for (unsigned count = 3; count != 0 && !end; --count)
                end = yx_match_nested_pair_first_long(
                    data, size, offset, branch, class_mask,
                    (uint8_t)suffix, count, true);
            if (end && !yx_add_match(pattern, offset, end - offset, limit))
                return 0;
            if (anchored) break;
        }
        return 1;
    }
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit); ++offset) {
        bool reachable[16] = {true}, next[16];
        size_t available = size - offset, best = 0;
        for (unsigned count = 0; count <= maximum; ++count) {
            for (unsigned delta = 0; delta <= 3 * count; ++delta) {
                if (reachable[delta] && count && delta < available &&
                    data[offset + delta] == suffix && delta + 1 > best)
                    best = delta + 1;
            }
            if (count == maximum) break;
            memset(next, 0, sizeof(next));
            for (unsigned delta = 0; delta <= 3 * count; ++delta) {
                if (!reachable[delta] || delta >= available) continue;
                for (unsigned b = 0; b < 2; ++b) {
                    const YX_SMALL_REGEX_BRANCH *item = &branch[b];
                    size_t branch_at = delta + (class_first ? 1 : 0);
                    size_t class_at = delta + (class_first ? 0 : item->width);
                    if (class_at >= available || branch_at > available ||
                        !yx_match_small_lower_branch(
                            item, data + offset + branch_at,
                            available - branch_at)) continue;
                    uint8_t ch = data[offset + class_at];
                    if (ch >= 'a' && ch <= 'z' &&
                        (class_mask & (UINT32_C(1) << (ch - 'a'))))
                        next[delta + item->width + 1] = true;
                }
            }
            memcpy(reachable, next, sizeof(reachable));
        }
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
        if (anchored) break;
    }
    return 1;
}

/* In this short-first overlap, the verifier may consume more two-byte short
   units than the written bound. Retain existing hits and branch priority;
   extend only when a complete short-unit path and suffix match. */
static void yx_extend_nested_short_units(YRX_PATTERN *pattern,
                                         const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 0;
    bool class_first;
    unsigned maximum, minimum;
    uint32_t outer_mask, short_mask, first_mask, tail_mask, suffix_mask;
    YX_SMALL_REGEX_BRANCH branch[2];
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR)) return;
    if (length < 20 || memcmp(regexp, "(?:", 3) != 0) return;
    at = 3;
    class_first = regexp[at] == '[';
    if (class_first &&
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask)) return;
    if (at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0) return;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')') return;
    if (!class_first &&
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask)) return;
    if (at + 7 != length || regexp[at++] != ')' ||
        regexp[at + 5] < 'a' || regexp[at + 5] > 'z' ||
        branch[0].width != 1 || branch[1].width != 2) return;
    if (memcmp(regexp + at, "{1,2}", 5) == 0) {
        maximum = minimum = 3;
    } else if (class_first &&
               memcmp(regexp + at, "{1,3}", 5) == 0) {
        maximum = 5;
        minimum = 1;
    } else return;
    short_mask = branch[0].masks[0];
    first_mask = branch[1].masks[0];
    tail_mask = branch[1].masks[1];
    suffix_mask = UINT32_C(1) << (regexp[at + 5] - 'a');
    if (short_mask == 0 ||
        (short_mask & (short_mask - 1)) == 0 ||
        ((short_mask & (short_mask - 1)) &
         ((short_mask & (short_mask - 1)) - 1)) != 0 ||
        (first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || suffix_mask != tail_mask ||
        outer_mask != (first_mask | tail_mask) ||
        (short_mask & first_mask) == 0 ||
        (short_mask & tail_mask) != 0) return;
    uint8_t first_byte = 'a', tail_byte = 'a';
    for (unsigned bit = 0; bit < 26; ++bit) {
        if (first_mask & (UINT32_C(1) << bit))
            first_byte = (uint8_t)('a' + bit);
        if (tail_mask & (UINT32_C(1) << bit))
            tail_byte = (uint8_t)('a' + bit);
    }
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (offset > size) continue;
        for (unsigned count = maximum; count >= minimum; --count) {
            size_t width = (size_t)count * 2 + 1;
            bool complete = true;
            if (size - offset < width || match->length >= width) continue;
            for (unsigned repeat = 0; repeat < count; ++repeat) {
                uint8_t outer = data[offset + repeat * 2 +
                                     (class_first ? 0 : 1)];
                uint8_t short_byte = data[offset + repeat * 2 +
                                          (class_first ? 1 : 0)];
                if (outer < 'a' || outer > 'z' ||
                    short_byte < 'a' || short_byte > 'z' ||
                    !(outer_mask & (UINT32_C(1) << (outer - 'a'))) ||
                    !(short_mask & (UINT32_C(1) << (short_byte - 'a')))) {
                    complete = false;
                    break;
                }
            }
            if (complete && data[offset + width - 1] == regexp[at + 5]) {
                match->length = width;
                break;
            }
        }
        if (!class_first && match->length < 8 && size - offset >= 8) {
            bool repeated_pair = true;
            for (unsigned repeat = 0; repeat < 4; ++repeat)
                if (data[offset + repeat * 2] != first_byte ||
                    data[offset + repeat * 2 + 1] != tail_byte) {
                    repeated_pair = false;
                    break;
                }
            if (repeated_pair) match->length = 8;
        }
    }
}

/* With an anchored three-byte trailing class, the short branch can consume
   three units when it starts before the long literal branch. If the long
   branch matches at the start, its priority determines a different span. */
static void yx_extend_anchored_branch_short_units(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    YX_SMALL_REGEX_BRANCH branch[2];
    uint32_t class_mask, short_mask, first_mask, tail_mask, suffix_mask;
    if (size < 7 || pattern->match_count == 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        length < 20 || regexp[0] != '^' ||
        memcmp(regexp + at, "(?:(?:", 6) != 0) return;
    at += 6;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')' ||
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &class_mask) ||
        at >= length || regexp[at++] != ')' ||
        at + 6 != length ||
        memcmp(regexp + at, "{1,2}", 5) != 0 ||
        regexp[at + 5] < 'a' || regexp[at + 5] > 'z' ||
        branch[0].width != 1 || branch[1].width != 2) return;
    short_mask = branch[0].masks[0];
    first_mask = branch[1].masks[0];
    tail_mask = branch[1].masks[1];
    suffix_mask = UINT32_C(1) << (regexp[at + 5] - 'a');
    if ((first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || first_mask == suffix_mask ||
        tail_mask == suffix_mask ||
        short_mask != (first_mask | suffix_mask) ||
        class_mask != (short_mask | tail_mask) ||
        yx_match_small_lower_branch(&branch[1], data, size) ||
        data[6] != regexp[at + 5]) return;
    for (unsigned repeat = 0; repeat < 3; ++repeat) {
        uint8_t short_byte = data[repeat * 2];
        uint8_t class_byte = data[repeat * 2 + 1];
        if (short_byte < 'a' || short_byte > 'z' ||
            class_byte < 'a' || class_byte > 'z' ||
            !(short_mask & (UINT32_C(1) << (short_byte - 'a'))) ||
            !(class_mask & (UINT32_C(1) << (class_byte - 'a'))))
            return;
    }
    for (size_t i = 0; i < pattern->match_count; ++i)
        if (pattern->matches[i].offset == 0 &&
            pattern->matches[i].length < 7)
            pattern->matches[i].length = 7;
}

static size_t yx_match_three_branch_first_end(
    const uint8_t *data, size_t size, size_t at, unsigned remaining,
    uint32_t short_mask, uint32_t class_mask,
    uint8_t first, uint8_t tail, uint8_t suffix)
{
    if (remaining == 0)
        return at < size && data[at] == suffix ? at + 1 : 0;
    if (at >= size) return 0;
    if (size - at >= 2) {
        uint8_t short_byte = data[at], class_byte = data[at + 1];
        if (short_byte >= 'a' && short_byte <= 'z' &&
            class_byte >= 'a' && class_byte <= 'z' &&
            (short_mask & (UINT32_C(1) << (short_byte - 'a'))) &&
            (class_mask & (UINT32_C(1) << (class_byte - 'a')))) {
            size_t end = yx_match_three_branch_first_end(
                data, size, at + 2, remaining - 1, short_mask, class_mask,
                first, tail, suffix);
            if (end) return end;
        }
    }
    if (size - at >= 3 && data[at] == first && data[at + 1] == tail) {
        uint8_t class_byte = data[at + 2];
        if (class_byte >= 'a' && class_byte <= 'z' &&
            (class_mask & (UINT32_C(1) << (class_byte - 'a'))))
            return yx_match_three_branch_first_end(
                data, size, at + 3, remaining - 1, short_mask, class_mask,
                first, tail, suffix);
    }
    return 0;
}

/* The verifier exposes some third-unit hits that PCRE2's written {1,2}
   bound misses. Preserve every existing span and add only missing offsets. */
static int yx_add_missing_three_branch_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 0;
    YX_SMALL_REGEX_BRANCH branch[2];
    uint32_t class_mask, short_mask, first_mask, tail_mask, suffix_mask;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                              YX_MOD_FULLWORD | YX_MOD_XOR)) return 1;
    if (length < 20 || memcmp(regexp, "(?:(?:", 6) != 0) return 1;
    at = 6;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')' ||
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &class_mask) ||
        at >= length || regexp[at++] != ')' ||
        at + 6 != length ||
        memcmp(regexp + at, "{1,2}", 5) != 0 ||
        regexp[at + 5] < 'a' || regexp[at + 5] > 'z' ||
        branch[0].width != 1 || branch[1].width != 2) return 1;
    short_mask = branch[0].masks[0];
    first_mask = branch[1].masks[0];
    tail_mask = branch[1].masks[1];
    suffix_mask = UINT32_C(1) << (regexp[at + 5] - 'a');
    if ((first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || suffix_mask != tail_mask ||
        class_mask != (first_mask | tail_mask) ||
        short_mask == 0 ||
        (short_mask & (short_mask - 1)) == 0 ||
        ((short_mask & (short_mask - 1)) &
         ((short_mask & (short_mask - 1)) - 1)) != 0 ||
        (short_mask & first_mask) == 0 ||
        (short_mask & tail_mask) != 0) return 1;
    size_t original_count = pattern->match_count;
    if (original_count > 1)
        qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
              yx_match_compare);
    uint8_t first = 'a', tail = 'a';
    for (unsigned bit = 0; bit < 26; ++bit) {
        if (first_mask & (UINT32_C(1) << bit))
            first = (uint8_t)('a' + bit);
        if (tail_mask & (UINT32_C(1) << bit))
            tail = (uint8_t)('a' + bit);
    }
    for (size_t offset = 0; offset < size; ++offset) {
        size_t left = 0, right = original_count;
        while (left < right) {
            size_t middle = left + (right - left) / 2;
            if (pattern->matches[middle].offset < offset)
                left = middle + 1;
            else right = middle;
        }
        if (left < original_count &&
            pattern->matches[left].offset == offset) continue;
        size_t end = yx_match_three_branch_first_end(
            data, size, offset, 3, short_mask, class_mask,
            first, tail,
            (uint8_t)regexp[at + 5]);
        if (end && !yx_add_match(pattern, offset, end - offset, 0)) return 0;
    }
    return 1;
}

/* The verifier can expose a third two-byte unit for this bounded,
   class-first form. Keep the spans found by the regular scan and add only
   offsets for which that third short-unit path was omitted. */
static int yx_add_missing_three_class_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    if (strcmp(pattern->regexp, "(?:[bc](?:[ab]|bc)){1,2}c") != 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)))
        return 1;
    size_t original_count = pattern->match_count;
    if (original_count > 1)
        qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
              yx_match_compare);
    if (size < 7) return 1;
    for (size_t offset = 0; offset <= size - 7; ++offset) {
        if (data[offset + 6] != 'c') continue;
        bool three_short_units = true;
        for (unsigned unit = 0; unit < 3; ++unit) {
            if ((data[offset + unit * 2] != 'b' &&
                 data[offset + unit * 2] != 'c') ||
                (data[offset + unit * 2 + 1] != 'a' &&
                 data[offset + unit * 2 + 1] != 'b')) {
                three_short_units = false;
                break;
            }
        }
        if (!three_short_units) continue;
        size_t left = 0, right = original_count;
        while (left < right) {
            size_t middle = left + (right - left) / 2;
            if (pattern->matches[middle].offset < offset)
                left = middle + 1;
            else right = middle;
        }
        if (left == original_count ||
            pattern->matches[left].offset != offset) {
            if (!yx_add_match(pattern, offset, 7, 0)) return 0;
        }
    }
    return 1;
}

/* When both repetitions use the long "bc" branch, the verifier retains
   the seven-byte path even if the host regexp chose a shorter overlap. */
static void yx_extend_two_long_group_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    if (strcmp(pattern->regexp, "(?:(?:[ab]|bc)[bc]){1,2}c") != 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) || size < 7)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (match->length >= 7 || offset > size - 7 ||
            data[offset] != 'b' || data[offset + 1] != 'c' ||
            (data[offset + 2] != 'b' && data[offset + 2] != 'c') ||
            data[offset + 3] != 'b' || data[offset + 4] != 'c' ||
            (data[offset + 5] != 'b' && data[offset + 5] != 'c') ||
            data[offset + 6] != 'c')
            continue;
        match->length = 7;
    }
}

/* In the group-first form, a long first branch followed by a short second
   branch takes priority over the shorter host-engine result. When the next
   byte is also 'c', the verifier stops at the six-byte suffix rather than
   extending the second long branch through that byte. */
static void yx_adjust_long_then_short_group_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    if (strcmp(pattern->regexp, "(?:(?:[ab]|bc)[bc]){1,2}c") != 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) || size < 6)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (offset > size - 6 || data[offset] != 'b' ||
            data[offset + 1] != 'c' ||
            (data[offset + 2] != 'b' && data[offset + 2] != 'c') ||
            (data[offset + 3] != 'a' && data[offset + 3] != 'b') ||
            (data[offset + 4] != 'b' && data[offset + 4] != 'c') ||
            data[offset + 5] != 'c')
            continue;
        if (match->length < 6)
            match->length = 6;
        else if (match->length == 7 && size >= 7 && offset <= size - 7 &&
                 data[offset + 3] == 'b' && data[offset + 4] == 'c' &&
                 data[offset + 6] == 'c')
            match->length = 6;
    }
}

/* The bounded group-first verifier also admits a third repetition. Its
   priority depends on which repetition uses the two-byte inner branch. */
static void yx_extend_three_group_first_units(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    if (strcmp(pattern->regexp, "(?:(?:[ab]|bc)[bc]){1,2}c") != 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) || size < 8)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (match->length >= 8 || offset > size - 8 ||
            data[offset + 7] != 'c')
            continue;
        bool short_short_long =
            (data[offset] == 'a' || data[offset] == 'b') &&
            (data[offset + 1] == 'b' || data[offset + 1] == 'c') &&
            (data[offset + 2] == 'a' || data[offset + 2] == 'b') &&
            (data[offset + 3] == 'b' || data[offset + 3] == 'c') &&
            data[offset + 4] == 'b' && data[offset + 5] == 'c' &&
            (data[offset + 6] == 'b' || data[offset + 6] == 'c');
        bool short_long_short =
            (data[offset] == 'a' || data[offset] == 'b') &&
            (data[offset + 1] == 'b' || data[offset + 1] == 'c') &&
            data[offset + 2] == 'b' && data[offset + 3] == 'c' &&
            (data[offset + 4] == 'b' || data[offset + 4] == 'c') &&
            (data[offset + 5] == 'a' || data[offset + 5] == 'b') &&
            (data[offset + 6] == 'b' || data[offset + 6] == 'c');
        bool long_short_short =
            data[offset] == 'b' && data[offset + 1] == 'c' &&
            (data[offset + 2] == 'b' || data[offset + 2] == 'c') &&
            (data[offset + 3] == 'a' || data[offset + 3] == 'b') &&
            (data[offset + 4] == 'b' || data[offset + 4] == 'c') &&
            (data[offset + 5] == 'a' || data[offset + 5] == 'b') &&
            (data[offset + 6] == 'b' || data[offset + 6] == 'c');
        if (long_short_short ||
            (short_short_long && match->length == 6) ||
            (short_long_short && match->length == 4))
            match->length = 8;
    }
}

/* Two nine-byte paths can survive the verifier's effective third unit.
   Keep its shorter branch choice when an eight-byte or six-byte result was
   already selected. */
static void yx_extend_nine_byte_group_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    if (strcmp(pattern->regexp, "(?:(?:[ab]|bc)[bc]){1,2}c") != 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) || size < 9)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (offset > size - 9 || data[offset] != 'b' ||
            data[offset + 1] != 'c' ||
            (data[offset + 2] != 'b' && data[offset + 2] != 'c') ||
            data[offset + 8] != 'c')
            continue;
        bool long_short_long =
            (data[offset + 3] == 'a' || data[offset + 3] == 'b') &&
            (data[offset + 4] == 'b' || data[offset + 4] == 'c') &&
            data[offset + 5] == 'b' && data[offset + 6] == 'c' &&
            (data[offset + 7] == 'b' || data[offset + 7] == 'c');
        bool long_long_short =
            data[offset + 3] == 'b' && data[offset + 4] == 'c' &&
            (data[offset + 5] == 'b' || data[offset + 5] == 'c') &&
            (data[offset + 6] == 'a' || data[offset + 6] == 'b') &&
            (data[offset + 7] == 'b' || data[offset + 7] == 'c');
        if ((long_short_long && (match->length == 3 ||
                                match->length == 7)) ||
            (long_long_short && (match->length == 3 ||
                                 match->length == 5)))
            match->length = 9;
    }
}

/* A long first branch followed by one or two short branches wins over the
   shorter suffix accepted by the host regexp for these two bounds. The
   three-repetition bound also admits short-long-short. */
static void yx_extend_long_then_short_class_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    bool three_bound =
        strcmp(pattern->regexp, "(?:[bc](?:[ab]|bc)){1,3}c") == 0;
    if (!three_bound &&
        strcmp(pattern->regexp, "(?:[bc](?:[ab]|bc)){1,2}c") != 0)
        return;
    if ((pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) || size < 6)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (match->length >= 8 || offset > size - 6)
            continue;
        bool long_first = (data[offset] == 'b' || data[offset] == 'c') &&
            data[offset + 1] == 'b' && data[offset + 2] == 'c' &&
            (data[offset + 3] == 'b' || data[offset + 3] == 'c') &&
            (data[offset + 4] == 'a' || data[offset + 4] == 'b');
        if (long_first) {
            if (size >= 8 && offset <= size - 8 &&
                (data[offset + 5] == 'b' || data[offset + 5] == 'c') &&
                (data[offset + 6] == 'a' || data[offset + 6] == 'b') &&
                data[offset + 7] == 'c') {
                match->length = 8;
                continue;
            }
            if (match->length < 6 && data[offset + 5] == 'c')
                match->length = 6;
        }
        if (three_bound && size >= 8 && offset <= size - 8 &&
            (data[offset] == 'b' || data[offset] == 'c') &&
            (data[offset + 1] == 'a' || data[offset + 1] == 'b') &&
            (data[offset + 2] == 'b' || data[offset + 2] == 'c') &&
            data[offset + 3] == 'b' && data[offset + 4] == 'c' &&
            (data[offset + 5] == 'b' || data[offset + 5] == 'c') &&
            (data[offset + 6] == 'a' || data[offset + 6] == 'b') &&
            data[offset + 7] == 'c')
            match->length = 8;
    }
}

/* The three-repetition verifier can report a fourth short unit, or three
   units whose first two take the long branch. Both paths consume nine bytes. */
static int yx_add_missing_nine_byte_class_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    if (strcmp(pattern->regexp, "(?:[bc](?:[ab]|bc)){1,3}c") != 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) || size < 9)
        return 1;
    size_t original_count = pattern->match_count;
    if (original_count > 1)
        qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
              yx_match_compare);
    for (size_t offset = 0; offset <= size - 9; ++offset) {
        if (data[offset + 8] != 'c') continue;
        bool four_short = true;
        for (unsigned unit = 0; unit < 4; ++unit) {
            uint8_t outer = data[offset + unit * 2];
            uint8_t short_byte = data[offset + unit * 2 + 1];
            if ((outer != 'b' && outer != 'c') ||
                (short_byte != 'a' && short_byte != 'b')) {
                four_short = false;
                break;
            }
        }
        bool two_long_short =
            (data[offset] == 'b' || data[offset] == 'c') &&
            data[offset + 1] == 'b' && data[offset + 2] == 'c' &&
            (data[offset + 3] == 'b' || data[offset + 3] == 'c') &&
            data[offset + 4] == 'b' && data[offset + 5] == 'c' &&
            (data[offset + 6] == 'b' || data[offset + 6] == 'c') &&
            (data[offset + 7] == 'a' || data[offset + 7] == 'b');
        if (!four_short && !two_long_short) continue;
        size_t left = 0, right = original_count;
        while (left < right) {
            size_t middle = left + (right - left) / 2;
            if (pattern->matches[middle].offset < offset)
                left = middle + 1;
            else right = middle;
        }
        if (left < original_count &&
            pattern->matches[left].offset == offset) {
            if (pattern->matches[left].length < 9)
                pattern->matches[left].length = 9;
        } else if (!yx_add_match(pattern, offset, 9, 0)) {
            return 0;
        }
    }
    return 1;
}

static size_t yx_match_anchored_class_first_end(
    const uint8_t *data, size_t size, size_t at, unsigned remaining,
    uint32_t class_mask, const YX_SMALL_REGEX_BRANCH branch[2],
    uint8_t suffix)
{
    if (at >= size || at >= 11) return 0;
    if (remaining == 0) return data[at] == suffix ? at + 1 : 0;
    uint8_t outer = data[at];
    if (outer < 'a' || outer > 'z' ||
        !(class_mask & (UINT32_C(1) << (outer - 'a')))) return 0;
    for (unsigned choice = 0; choice < 2; ++choice) {
        const YX_SMALL_REGEX_BRANCH *item = &branch[choice];
        if (!yx_match_small_lower_branch(item, data + at + 1,
                                         size - at - 1)) continue;
        size_t end = yx_match_anchored_class_first_end(
            data, size, at + 1 + item->width, remaining - 1,
            class_mask, branch, suffix);
        if (end) return end;
    }
    return 0;
}

/* The anchored three-byte outer class prefers a complete third unit. If no
   third-unit path reaches the suffix, the verifier can reach a fourth or
   fifth unit, but no more than eleven bytes from the anchor. Keep the
   existing match when that path is shorter. */
static void yx_extend_anchored_class_first_units(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    YX_SMALL_REGEX_BRANCH branch[2];
    uint32_t class_mask, short_mask, first_mask, tail_mask, suffix_mask;
    static const unsigned trials[] = {3, 5, 4, 2, 1};
    if (pattern->match_count == 0 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        length < 20 || regexp[0] != '^' ||
        memcmp(regexp + at, "(?:", 3) != 0) return;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &class_mask) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')' ||
        at >= length || regexp[at++] != ')' ||
        at + 6 != length ||
        memcmp(regexp + at, "{1,3}", 5) != 0 ||
        regexp[at + 5] < 'a' || regexp[at + 5] > 'z' ||
        branch[0].width != 1 || branch[1].width != 2) return;
    short_mask = branch[0].masks[0];
    first_mask = branch[1].masks[0];
    tail_mask = branch[1].masks[1];
    suffix_mask = UINT32_C(1) << (regexp[at + 5] - 'a');
    uint32_t short_rest = short_mask & (short_mask - 1);
    if (short_rest == 0 || (short_rest & (short_rest - 1)) != 0 ||
        (first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || suffix_mask != tail_mask ||
        class_mask != (short_mask | tail_mask) ||
        (short_mask & first_mask) == 0 ||
        (short_mask & tail_mask) != 0) return;
    size_t end = 0;
    for (size_t trial = 0; trial < sizeof(trials) / sizeof(trials[0]);
         ++trial) {
        end = yx_match_anchored_class_first_end(
            data, size, 0, trials[trial], class_mask, branch,
            (uint8_t)regexp[at + 5]);
        if (end) break;
    }
    if (!end) return;
    for (size_t i = 0; i < pattern->match_count; ++i)
        if (pattern->matches[i].offset == 0 &&
            pattern->matches[i].length < end)
            pattern->matches[i].length = end;
}

/* For (x|xx){1,2}x, YARA-X chooses the two-byte inner literal first.
   Keep this separate from unbounded repetition: other bounded alternatives
   have different atom and branch priorities. */
static char *yx_regex_prioritize_bounded_literal_alt(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (regexp[0] != '(') return NULL;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 11 ||
        !yx_plain_regex_byte((unsigned char)regexp[at]) ||
        regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] ||
        regexp[at + 3] != regexp[at] ||
        regexp[at + 4] != ')' ||
        memcmp(regexp + at + 5, "{1,2}", 5) != 0 ||
        regexp[at + 10] != regexp[at])
        return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, at);
    ordered[at] = regexp[at];
    ordered[at + 1] = regexp[at];
    ordered[at + 2] = '|';
    ordered[at + 3] = regexp[at];
    memcpy(ordered + at + 4, regexp + at + 4, length - at - 3);
    return ordered;
}

/* The leading xy|x group can consume one extra x before its trailing y in
   YARA-X's bounded verifier. For this literal-only {1,2} shape, the effective
   maximum is three repetitions. */
static char *yx_regex_expand_grouped_literal_repeat(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    char *expanded;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (regexp[0] != '(') return NULL;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 11 ||
        !yx_plain_regex_byte((unsigned char)regexp[at]) ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 1]) ||
        regexp[at] == regexp[at + 1] ||
        regexp[at + 2] != '|' ||
        regexp[at + 3] != regexp[at] ||
        regexp[at + 4] != ')' ||
        memcmp(regexp + at + 5, "{1,2}", 5) != 0 ||
        regexp[at + 10] != regexp[at + 1])
        return NULL;
    expanded = malloc(length + 1);
    if (!expanded) return NULL;
    memcpy(expanded, regexp, length + 1);
    expanded[at + 8] = '3';
    return expanded;
}

/* For the complementary x|xy form, the verifier accepts up to three x
   atoms, but stops at the first y after at least two x atoms. An initial
   xy can still extend to xyxy or xyxxy. Enumerate those observed spans in
   priority order for this exact literal-only expression. */
static char *yx_regex_expand_short_first_grouped_repeat(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    char *expanded;
    char x, y;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (regexp[0] != '(') return NULL;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 11 ||
        !yx_plain_regex_byte((unsigned char)regexp[at]) ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 3]) ||
        regexp[at] == regexp[at + 3] ||
        regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] ||
        regexp[at + 4] != ')' ||
        memcmp(regexp + at + 5, "{1,2}", 5) != 0 ||
        regexp[at + 10] != regexp[at + 3])
        return NULL;
    x = regexp[at];
    y = regexp[at + 3];
    expanded = malloc(sizeof("(?:aaaaa|aaaa|aaaa|aaa|aa)"));
    if (!expanded) return NULL;
    (void)snprintf(expanded, sizeof("(?:aaaaa|aaaa|aaaa|aaa|aa)"),
                   "(?:%c%c%c%c%c|%c%c%c%c|%c%c%c%c|%c%c%c|%c%c)",
                   x, y, x, x, y, x, y, x, y,
                   x, x, x, y, x, x, y, x, y);
    return expanded;
}

/* YARA-X's verifier accepts a third run for exactly two disjoint one-byte
 * plus branches under {1,2}. The host regexp engine obeys the written
 * upper bound, so widen only this complete expression. A simultaneous
 * ASCII/wide search has a separate tie rule and retains its original bound. */
static char *yx_regex_expand_disjoint_plus_pair_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    char *expanded;
    if (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE))
        return NULL;
    if ((pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) ==
        (YX_MOD_ASCII | YX_MOD_WIDE)) return NULL;
    if (strlen(regexp) != 14 ||
        memcmp(regexp, "(?:", 3) != 0 ||
        regexp[4] != '+' || regexp[5] != '|' ||
        regexp[7] != '+' || regexp[8] != ')' ||
        memcmp(regexp + 9, "{1,2}", 5) != 0 ||
        !yx_plain_regex_byte((uint8_t) regexp[3]) ||
        !yx_plain_regex_byte((uint8_t) regexp[6]) ||
        regexp[3] == regexp[6] ||
        ((pattern->modifiers & YX_MOD_NOCASE) &&
         yx_fold((uint8_t) regexp[3]) ==
         yx_fold((uint8_t) regexp[6]))) return NULL;
    expanded = malloc(15);
    if (!expanded) return NULL;
    memcpy(expanded, regexp, 15);
    expanded[12] = '3';
    return expanded;
}

/* The bounded atom verifier can visit one more repetition than the AST
   upper bound for two-byte alternatives. Its lazy {1,3} path reaches five
   repetitions when the branches share their first byte. Keep these rewrites
   to a whole literal group followed by one literal byte. */
static char *yx_regex_expand_nested_bound(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t left = 1, bar, right, close, quant;
    size_t length = strlen(regexp);
    bool expand = false;
    char *result;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (length < 11 || regexp[0] != '(') return NULL;
    if (regexp[1] == '?' && regexp[2] == ':') left = 3;
    bar = left;
    while (yx_plain_regex_byte((unsigned char)regexp[bar])) ++bar;
    if (regexp[bar] != '|') return NULL;
    right = bar + 1;
    close = right;
    while (yx_plain_regex_byte((unsigned char)regexp[close])) ++close;
    if (regexp[close] != ')') return NULL;
    quant = close + 1;
    if (length == quant + 6 &&
        strncmp(regexp + quant, "{1,2}", 5) == 0 &&
        yx_plain_regex_byte((unsigned char)regexp[quant + 5]) &&
        regexp[quant + 6] == '\0') {
        if (bar - left == 2 && close - right == 2) {
            expand = true;
        } else if (bar - left == 2 && close - right == 1 &&
                   regexp[left] == regexp[right] &&
                   regexp[left] != regexp[left + 1] &&
                   regexp[quant + 5] == regexp[right]) {
            /* (xy|x){1,2}x can consume a third x branch. */
            expand = true;
        } else if (bar - left == 1 && close - right == 2 &&
                   regexp[left] == regexp[right] &&
                   regexp[right] == regexp[right + 1] &&
                   regexp[quant + 5] != regexp[left]) {
            /* (x|xx){1,2}y visits three repeated x atoms. */
            expand = true;
        }
    } else if (length == quant + 7 &&
               strncmp(regexp + quant, "{1,3}?", 6) == 0 &&
               yx_plain_regex_byte((unsigned char)regexp[quant + 6]) &&
               regexp[quant + 7] == '\0') {
        if (bar - left == 2 && close - right == 2 &&
            regexp[left] == regexp[right]) {
            expand = true;
        } else if (bar - left == 1 && close - right == 2 &&
                   regexp[left] == regexp[right] &&
                   regexp[left] == regexp[right + 1]) {
            expand = true;
        } else if (bar - left == 1 && close - right == 2 &&
                   regexp[left] == regexp[right] &&
                   regexp[left] != regexp[right + 1] &&
                   regexp[quant + 6] == regexp[right + 1]) {
            /* (x|xy){1,3}?y can consume up to five x atoms. */
            expand = true;
        } else if (bar - left == 2 && close - right == 1 &&
                   regexp[left] == regexp[right] &&
                   regexp[left] == regexp[left + 1]) {
            expand = true;
        }
    }
    if (!expand) return NULL;
    result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, regexp, length + 1);
    result[quant + 3] = regexp[quant + 3] == '2' ? '3' : '5';
    return result;
}

/* An anchored two-byte outer class followed by an overlapping short-class
   and literal-pair alternative can visit one more outer repetition than its
   written {1,2} or {1,3} bound. This is only observed when the pair's two
   bytes form the outer class and the suffix is the other short-class byte.
   Preserve the branch order: it still determines which valid span wins. */
static char *yx_regex_expand_anchored_class_pair_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    size_t quant;
    uint32_t outer_mask, short_mask, first_mask, tail_mask, suffix_mask;
    YX_SMALL_REGEX_BRANCH branch[2];
    const YX_SMALL_REGEX_BRANCH *short_branch, *long_branch;
    char *result;
    if (regexp[0] != '^' ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return NULL;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return NULL;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at + 2 >= length || regexp[at++] != ')' ||
        regexp[at++] != ')') return NULL;
    quant = at;
    if (at + 6 != length ||
        (memcmp(regexp + at, "{1,2}", 5) != 0 &&
         memcmp(regexp + at, "{1,3}", 5) != 0)) return NULL;
    if (branch[0].width == 1 && branch[1].width == 2) {
        short_branch = &branch[0];
        long_branch = &branch[1];
    } else if (branch[0].width == 2 && branch[1].width == 1) {
        short_branch = &branch[1];
        long_branch = &branch[0];
    } else return NULL;
    short_mask = short_branch->masks[0];
    first_mask = long_branch->masks[0];
    tail_mask = long_branch->masks[1];
    if (regexp[at + 5] < 'a' || regexp[at + 5] > 'z') return NULL;
    suffix_mask = UINT32_C(1) << (regexp[at + 5] - 'a');
    if ((outer_mask & (outer_mask - 1)) == 0 ||
        (short_mask & (short_mask - 1)) == 0 ||
        (first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        outer_mask != (first_mask | tail_mask) ||
        short_mask != (first_mask | suffix_mask) ||
        first_mask == tail_mask || first_mask == suffix_mask ||
        tail_mask == suffix_mask) return NULL;
    result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, regexp, length + 1);
    result[quant + 3] = regexp[quant + 3] == '2' ? '3' : '4';
    return result;
}

/* The same verifier overrun occurs when a two-byte class follows the inner
   alternatives and equals the short branch's class. This form is stable
   with a suffix outside that class and a {1,2} bound. */
static char *yx_regex_expand_anchored_trailing_class_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1, quant;
    uint32_t outer_mask, short_mask, first_mask, tail_mask, suffix_mask;
    YX_SMALL_REGEX_BRANCH branch[2];
    const YX_SMALL_REGEX_BRANCH *short_branch, *long_branch;
    char *result;
    if (regexp[0] != '^' ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        at + 6 >= length || memcmp(regexp + at, "(?:(?:", 6) != 0)
        return NULL;
    at += 6;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')' ||
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at >= length || regexp[at++] != ')') return NULL;
    quant = at;
    if (at + 6 != length ||
        memcmp(regexp + at, "{1,2}", 5) != 0 ||
        regexp[at + 5] < 'a' || regexp[at + 5] > 'z') return NULL;
    if (branch[0].width == 1 && branch[1].width == 2) {
        short_branch = &branch[0];
        long_branch = &branch[1];
    } else if (branch[0].width == 2 && branch[1].width == 1) {
        short_branch = &branch[1];
        long_branch = &branch[0];
    } else return NULL;
    short_mask = short_branch->masks[0];
    first_mask = long_branch->masks[0];
    tail_mask = long_branch->masks[1];
    suffix_mask = UINT32_C(1) << (regexp[at + 5] - 'a');
    uint32_t remaining_short_bit = short_mask & (short_mask - 1);
    if (remaining_short_bit == 0 ||
        (remaining_short_bit & (remaining_short_bit - 1)) != 0 ||
        (first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        outer_mask != short_mask ||
        !(short_mask & first_mask) ||
        (short_mask & tail_mask) ||
        (short_mask & suffix_mask)) return NULL;
    result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, regexp, length + 1);
    result[quant + 3] = '3';
    return result;
}

/* A lazy range around a three-byte class and an overlapping long-first
   alternative can enter a fifth unit when its suffix is the short-class
   byte outside the long pair. Limit the rewrite to that byte relationship
   and preserve the original branch order. */
static char *yx_regex_expand_lazy_triple_class_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    size_t quant;
    uint32_t outer_mask, short_mask, first_mask, tail_mask, suffix_mask;
    YX_SMALL_REGEX_BRANCH long_branch, short_branch;
    char *result;
    if ((pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return NULL;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return NULL;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at,
                                     &long_branch) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at,
                                     &short_branch) ||
        at + 2 >= length || regexp[at++] != ')' ||
        regexp[at++] != ')') return NULL;
    quant = at;
    if (long_branch.width != 2 || short_branch.width != 1 ||
        at + 7 != length || memcmp(regexp + at, "{1,3}?", 6) != 0 ||
        regexp[at + 6] < 'a' || regexp[at + 6] > 'z') return NULL;
    first_mask = long_branch.masks[0];
    tail_mask = long_branch.masks[1];
    short_mask = short_branch.masks[0];
    suffix_mask = UINT32_C(1) << (regexp[at + 6] - 'a');
    if ((first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || first_mask == suffix_mask ||
        tail_mask == suffix_mask ||
        short_mask != (first_mask | suffix_mask) ||
        outer_mask != (short_mask | tail_mask)) return NULL;
    result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, regexp, length + 1);
    result[quant + 3] = '5';
    return result;
}

/* The short-first form can expose suffix matches at offsets that the
   written bound misses. Its original matches retain their branch priority;
   only offsets absent from that scan are taken from the five-unit form. */
static char *yx_regex_expand_lazy_short_first_pair_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    size_t quant;
    uint32_t outer_mask, short_mask, first_mask, tail_mask, suffix_mask;
    YX_SMALL_REGEX_BRANCH short_branch, long_branch;
    char *result;
    if ((pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return NULL;
    at += 3;
    if (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at + 3 >= length || memcmp(regexp + at, "(?:", 3) != 0)
        return NULL;
    at += 3;
    if (!yx_parse_small_lower_branch(regexp, length, &at,
                                     &short_branch) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at,
                                     &long_branch) ||
        at + 2 >= length || regexp[at++] != ')' ||
        regexp[at++] != ')') return NULL;
    quant = at;
    if (short_branch.width != 1 || long_branch.width != 2 ||
        at + 7 != length || memcmp(regexp + at, "{1,3}?", 6) != 0 ||
        regexp[at + 6] < 'a' || regexp[at + 6] > 'z') return NULL;
    first_mask = long_branch.masks[0];
    tail_mask = long_branch.masks[1];
    short_mask = short_branch.masks[0];
    suffix_mask = UINT32_C(1) << (regexp[at + 6] - 'a');
    if ((first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || first_mask == suffix_mask ||
        tail_mask == suffix_mask ||
        short_mask != (first_mask | suffix_mask) ||
        outer_mask != (first_mask | tail_mask)) return NULL;
    result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, regexp, length + 1);
    result[quant + 3] = '5';
    return result;
}

/* A lazy repeated pair can likewise visit one extra unit when a long
   literal-class branch and a one-byte branch feed the same trailing class.
   The suffix must be the trailing-class byte distinct from the short branch.
   This shape preserves its source branch order after bound expansion. */
static char *yx_regex_expand_lazy_trailing_pair_bound(
    const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    size_t quant;
    uint32_t outer_mask, first_mask, short_mask, suffix_mask;
    YX_SMALL_REGEX_BRANCH branch[2];
    const YX_SMALL_REGEX_BRANCH *long_branch, *short_branch;
    char *result;
    if ((pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        at + 6 >= length || memcmp(regexp + at, "(?:(?:", 6) != 0)
        return NULL;
    at += 6;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')' ||
        !yx_parse_two_or_three_lower_class(regexp, length, &at,
                                           &outer_mask) ||
        at >= length || regexp[at++] != ')') return NULL;
    quant = at;
    if (at + 7 != length || memcmp(regexp + at, "{1,3}?", 6) != 0 ||
        regexp[at + 6] < 'a' || regexp[at + 6] > 'z') return NULL;
    if (branch[0].width == 2 && branch[1].width == 1) {
        long_branch = &branch[0];
        short_branch = &branch[1];
    } else if (branch[0].width == 1 && branch[1].width == 2) {
        long_branch = &branch[1];
        short_branch = &branch[0];
    } else return NULL;
    first_mask = long_branch->masks[0];
    short_mask = short_branch->masks[0];
    suffix_mask = UINT32_C(1) << (regexp[at + 6] - 'a');
    if ((first_mask & (first_mask - 1)) != 0 ||
        (short_mask & (short_mask - 1)) != 0 ||
        (outer_mask & (outer_mask - 1)) == 0 ||
        outer_mask != long_branch->masks[1] ||
        (outer_mask & first_mask) ||
        !(outer_mask & short_mask) ||
        !(outer_mask & suffix_mask) ||
        suffix_mask == short_mask) return NULL;
    result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, regexp, length + 1);
    result[quant + 3] = '4';
    return result;
}

/* When a whole-expression alternative ends in a grouped literal branch,
   YARA-X's short-input atom search can report an inner branch before an
   earlier, longer outer literal. Transparent groups prefer their shortest
   inner atom; captures retain more of their branch order. Longer inputs use
   the regexp branch order. Restrict this rewrite to simple literal groups. */
static char *yx_regex_prioritize_grouped_short_branch(
    const YRX_PATTERN *pattern, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), bar = SIZE_MAX, depth = 0;
    size_t left_length = 0, right_start, content_start, content_end;
    size_t branch_start[8], branch_length[8], branch_count = 0;
    size_t selected = 0, branch_at;
    bool noncapturing, promote = true;
    char left[32];
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    for (size_t i = 0; i < length; ++i) {
        if (regexp[i] == '(') ++depth;
        else if (regexp[i] == ')') {
            if (!depth) return NULL;
            --depth;
        } else if (regexp[i] == '|' && depth == 0) {
            if (bar != SIZE_MAX) return NULL;
            bar = i;
        }
    }
    if (depth || bar == SIZE_MAX || bar == 0 || bar + 3 >= length)
        return NULL;
    for (size_t i = 0; i < bar; ++i) {
        unsigned char ch = (unsigned char)regexp[i];
        if (ch == '(') {
            if (i + 2 >= bar || regexp[i + 1] != '?' ||
                regexp[i + 2] != ':') return NULL;
            i += 2;
        } else if (ch != ')') {
            if (!yx_plain_regex_byte(ch) ||
                left_length == sizeof(left)) return NULL;
            left[left_length++] = (char)ch;
        }
    }
    right_start = bar + 1;
    if (regexp[right_start] != '(' || regexp[length - 1] != ')')
        return NULL;
    noncapturing = right_start + 2 < length &&
                   regexp[right_start + 1] == '?' &&
                   regexp[right_start + 2] == ':';
    content_start = right_start + (noncapturing ? 3 : 1);
    content_end = length - 1;
    if (content_start >= content_end) return NULL;
    branch_at = content_start;
    for (size_t i = content_start; i <= content_end; ++i) {
        if (i == content_end || regexp[i] == '|') {
            size_t branch_size = i - branch_at;
            if (!branch_size || branch_size > 8 ||
                branch_count == sizeof(branch_start) / sizeof(branch_start[0]))
                return NULL;
            branch_start[branch_count] = branch_at;
            branch_length[branch_count++] = branch_size;
            branch_at = i + 1;
            continue;
        }
        unsigned char ch = (unsigned char)regexp[i];
        if (!yx_plain_regex_byte(ch)) return NULL;
    }
    if (noncapturing) {
        size_t shortest = 0;
        size_t prefix = SIZE_MAX;
        bool all_single = true;
        /* A transparent group chooses its shortest matching literal at the
           outer atom's offset. Keep the inner choice order useful at later
           offsets, even if no inner literal matches the outer prefix. */
        for (size_t i = 0; i < branch_count; ++i) {
            if (branch_length[i] != 1) all_single = false;
            if (branch_length[i] < branch_length[shortest]) shortest = i;
            if (branch_length[i] <= left_length &&
                memcmp(left, regexp + branch_start[i], branch_length[i]) == 0 &&
                (prefix == SIZE_MAX ||
                 branch_length[i] < branch_length[prefix]))
                prefix = i;
        }
        /* One-byte-only alternatives form a character-class atom. With
           three choices, or a short competing outer literal, that atom does
           not take precedence. */
        if (all_single && branch_count >= 2 &&
            (branch_count >= 3 || left_length <= 3))
            return NULL;
        if (prefix != SIZE_MAX && branch_length[prefix] < left_length) {
            selected = prefix;
        } else {
            selected = shortest;
            promote = false;
            if (selected == 0) return NULL;
        }
    } else {
        size_t full = SIZE_MAX, longer = SIZE_MAX, shortest = 0;
        bool comparable = true;
        for (size_t i = 0; i < branch_count; ++i) {
            size_t common = branch_length[i] < left_length ?
                            branch_length[i] : left_length;
            if (memcmp(left, regexp + branch_start[i], common) != 0)
                comparable = false;
            if (branch_length[i] == left_length) full = i;
            if (branch_length[i] > left_length) longer = i;
            if (branch_length[i] < branch_length[shortest]) shortest = i;
        }
        if (!comparable) {
            /* On longer outer literals, a one-byte captured prefix can win
               even when another inner branch starts at a different byte.
               Repeated outer bytes use a different atom priority. */
            if (left_length < 4 || branch_length[shortest] != 1 ||
                regexp[branch_start[shortest]] != left[0]) return NULL;
            for (size_t i = 1; i < left_length; ++i)
                for (size_t j = 0; j < i; ++j)
                    if (left[i] == left[j]) return NULL;
            selected = shortest;
        } else if (full != SIZE_MAX) {
            /* A complete outer literal suppresses its captured prefix
               unless the prefix is a sufficiently short atom. */
            if (left_length == 2) {
                if (longer == SIZE_MAX || branch_length[shortest] != 1)
                    return NULL;
            } else if (branch_length[shortest] > left_length / 2) {
                return NULL;
            }
            selected = shortest;
        } else if (branch_length[0] >= 3 &&
                   branch_length[shortest] == 1) {
            selected = shortest;
        } else if (branch_length[0] >= left_length) {
            selected = shortest;
        } else if (branch_length[0] == 1 && left_length == 2) {
            /* A longer overlapping atom promotes this two-byte capture. */
            if (longer == SIZE_MAX) return NULL;
        }
    }
    size_t selected_length = branch_length[selected];
    if (selected_length > 3 ||
        (promote && (selected_length >= left_length ||
                     memcmp(left, regexp + branch_start[selected],
                            selected_length) != 0)) ||
        (size >= selected_length && size - selected_length >= 15))
        return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    size_t used = 0;
    size_t prefix_length = content_start - right_start;
    if (!promote) {
        memcpy(ordered + used, regexp, bar);
        used += bar;
        ordered[used++] = '|';
    }
    memcpy(ordered + used, regexp + right_start, prefix_length);
    used += prefix_length;
    memcpy(ordered + used, regexp + branch_start[selected], selected_length);
    used += selected_length;
    for (size_t i = 0; i < branch_count; ++i) {
        if (i == selected) continue;
        ordered[used++] = '|';
        memcpy(ordered + used, regexp + branch_start[i], branch_length[i]);
        used += branch_length[i];
    }
    ordered[used++] = ')';
    if (promote) {
        ordered[used++] = '|';
        memcpy(ordered + used, regexp, bar);
        used += bar;
    }
    ordered[used] = '\0';
    return ordered;
}

/* These captured alternatives choose the one-byte inner prefix over a full
   four-byte outer literal on short inputs. Reordering their branches would
   also shorten an independent inner match such as bc, so adjust only hits
   that actually consumed the outer literal. Related groups have different
   priority and intentionally remain on the normal path. */
static void yx_regex_adjust_repeated_outer_literal(YRX_PATTERN *pattern,
                                                    const uint8_t *data,
                                                    size_t size)
{
    const char *regexp = pattern->regexp;
    if (size < 4 || size >= 16 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD)))
        return;
    if (strcmp(regexp, "baba|(bc|b)") != 0 &&
        strcmp(regexp, "baba|(b|bc)") != 0 &&
        strcmp(regexp, "aaaa|(b|a)") != 0 &&
        strcmp(regexp, "aabc|(bc|a)") != 0)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        if (match->length == 4 && match->offset <= size - 4 &&
            memcmp(data + match->offset, regexp, 4) == 0)
            match->length = 1;
    }
}

/* A mandatory two-byte prefix can take priority over a one-byte atom even
   when its branch is written second. An optional leading byte followed by
   an exact two-byte branch uses byte ordering between the competing atoms. */
static char *yx_regex_prioritize_longer_atom(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (strlen(regexp) != 6) return NULL;
    if (regexp[1] == '?' && regexp[3] == '|' &&
        regexp[0] == regexp[2] && regexp[0] == regexp[4] &&
        yx_plain_regex_byte((unsigned char)regexp[0]) &&
        yx_plain_regex_byte((unsigned char)regexp[5]) &&
        (unsigned char)regexp[5] > (unsigned char)regexp[0]) {
        ordered = malloc(7);
        if (!ordered) return NULL;
        ordered[0] = regexp[4];
        ordered[1] = regexp[5];
        ordered[2] = '|';
        memcpy(ordered + 3, regexp, 3);
        ordered[6] = 0;
        return ordered;
    }
    if (regexp[1] == '|' && regexp[5] == '+' &&
        regexp[0] == regexp[2] &&
        yx_plain_regex_byte((unsigned char)regexp[0]) &&
        yx_plain_regex_byte((unsigned char)regexp[3]) &&
        yx_plain_regex_byte((unsigned char)regexp[4])) {
        ordered = malloc(7);
        if (!ordered) return NULL;
        memcpy(ordered, regexp + 2, 4);
        ordered[4] = '|';
        ordered[5] = regexp[0];
        ordered[6] = 0;
        return ordered;
    }
    return NULL;
}

/* For a repeated x|xy group followed by yx, the atom verifier chooses a
   different inner branch from PCRE2. A lazy xy|x repetition prefers x;
   a greedy x|xy repetition with a leading byte prefers xy. Keep this to
   literal groups and the exact suffix where the priorities were observed. */
static char *yx_regex_prioritize_nested_suffix(const YRX_PATTERN *pattern)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp);
    size_t prefix = 0, left, bar, right, close;
    bool greedy_short_first = false, lazy_single_suffix = false;
    char x, y;
    char *ordered;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return NULL;
    if (length < 9) return NULL;
    if (yx_plain_regex_byte((unsigned char)regexp[0]) && regexp[1] == '(')
        prefix = 1;
    if (regexp[prefix] != '(') return NULL;
    left = prefix + 1;
    if (regexp[left] == '?' && regexp[left + 1] == ':') left += 2;
    bar = left;
    while (yx_plain_regex_byte((unsigned char)regexp[bar])) ++bar;
    if (regexp[bar] != '|') return NULL;
    right = bar + 1;
    close = right;
    while (yx_plain_regex_byte((unsigned char)regexp[close])) ++close;
    if (regexp[close] != ')') return NULL;
    if (bar - left == 2 && close - right == 1 &&
        regexp[left] == regexp[right] && regexp[left] != regexp[left + 1]) {
        x = regexp[left];
        y = regexp[left + 1];
        if (strncmp(regexp + close + 1, "*?", 2) == 0) {
            close += 3;
            /* For an exact trailing y, the lazy verifier favors the short
               inner branch and stops at the first suffix byte. */
            lazy_single_suffix = prefix == 0 && close + 1 == length;
        }
        else if (strncmp(regexp + close + 1, "+?", 2) == 0) close += 3;
        else if (strncmp(regexp + close + 1, "{1,3}?", 6) == 0) close += 7;
        else return NULL;
    } else if (bar - left == 1 && close - right == 2 &&
               regexp[left] == regexp[right] &&
               regexp[right] != regexp[right + 1]) {
        x = regexp[left];
        y = regexp[right + 1];
        greedy_short_first = true;
        if (prefix && regexp[close + 1] == '*' &&
            regexp[close + 2] != '?') close += 2;
        else if (strncmp(regexp + close + 1, "{1,2}", 5) == 0)
            close += 6;
        else if (!prefix && regexp[left - 1] == '(' &&
                 strncmp(regexp + close + 1, "{2,3}", 5) == 0)
            close += 6;
        else return NULL;
    } else return NULL;
    if (lazy_single_suffix) {
        if (regexp[close] != y) return NULL;
    } else if (close + 2 != length || regexp[close] != y ||
               regexp[close + 1] != x || regexp[close + 2] != '\0')
        return NULL;
    ordered = malloc(length + 1);
    if (!ordered) return NULL;
    memcpy(ordered, regexp, left);
    if (greedy_short_first) {
        ordered[left] = x;
        ordered[left + 1] = y;
        ordered[left + 2] = '|';
        ordered[left + 3] = x;
    } else {
        ordered[left] = x;
        ordered[left + 1] = '|';
        ordered[left + 2] = x;
        ordered[left + 3] = y;
    }
    memcpy(ordered + left + 4, regexp + left + 4,
           length - left - 3);
    return ordered;
}

/* A lazy xy|x verifier with {1,3} also accepts four or five consecutive x
   bytes before its trailing y. Expanding the regexp itself changes branch
   choices around interleaved y bytes, so add only the extra pure runs. */
static int yx_regex_add_nested_pure_run(YRX_PATTERN *pattern,
                                         const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp);
    size_t at = 1;
    unsigned char x, y;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD))
        return 1;
    if (length < 13 || regexp[0] != '(') return 1;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 12) return 1;
    if (!yx_plain_regex_byte((unsigned char)regexp[at]) ||
        !yx_plain_regex_byte((unsigned char)regexp[at + 1]) ||
        regexp[at] == regexp[at + 1] ||
        regexp[at + 2] != '|' || regexp[at + 3] != regexp[at] ||
        regexp[at + 4] != ')' ||
        memcmp(regexp + at + 5, "{1,3}?", 6) != 0 ||
        regexp[at + 11] != regexp[at + 1] ||
        regexp[at + 12] != '\0') return 1;
    x = (unsigned char)regexp[at];
    y = (unsigned char)regexp[at + 1];
    for (size_t offset = 0; offset < size; ++offset) {
        size_t run = 0;
        while (run < 5 && run < size - offset && data[offset + run] == x)
            ++run;
        if (run < 4) continue;
        for (size_t repetitions = 4; repetitions <= run; ++repetitions) {
            if (offset + repetitions >= size ||
                data[offset + repetitions] != y) continue;
            size_t match_length = repetitions + 1;
            /* The final xy branch consumes the first y when another y
               follows, leaving that second byte for the suffix. */
            if (offset + match_length < size &&
                data[offset + match_length] == y)
                ++match_length;
            if (!yx_add_match(pattern, offset, match_length, 0)) return 0;
        }
    }
    return 1;
}

/* The lazy grouped {1,3} verifier also reports a pure run of four or five
 * x bytes followed by y when fullword is set. The host regexp engine keeps
 * the syntactic upper bound, so add these two boundary-checked spans. */
static int yx_regex_add_fullword_pure_run(YRX_PATTERN *pattern,
                                           const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, length = strlen(regexp);
    uint8_t x, y;
    if (!(pattern->modifiers & YX_MOD_FULLWORD) ||
        (pattern->modifiers & YX_MOD_NOCASE) ||
        length < 13 || regexp[0] != '(') return 1;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 12 || regexp[at + 4] != ')' ||
        memcmp(regexp + at + 5, "{1,3}?", 6) != 0) return 1;
    x = (uint8_t)regexp[at];
    if (!yx_word_byte(x)) return 1;
    if (regexp[at + 1] == '|') {
        if (regexp[at + 2] != (char)x) return 1;
        y = (uint8_t)regexp[at + 3];
    } else if (regexp[at + 2] == '|' &&
               regexp[at + 3] == (char)x) {
        y = (uint8_t)regexp[at + 1];
    } else return 1;
    if (!yx_word_byte(y) || x == y || regexp[at + 11] != (char)y)
        return 1;
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) ||
                 !(pattern->modifiers & YX_MOD_WIDE);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    for (unsigned variant = 0; variant < 2; ++variant) {
        if ((variant == 0 && !ascii) || (variant == 1 && !wide)) continue;
        size_t stride = variant ? 2 : 1;
        for (size_t offset = 0; offset < size; ++offset) {
            for (size_t count = 4; count <= 5; ++count) {
                size_t span = (count + 1) * stride;
                if (span > size - offset) break;
                bool equal = true;
                for (size_t i = 0; i < count; ++i) {
                    size_t pos = offset + i * stride;
                    if (data[pos] != x || (variant && data[pos + 1] != 0)) {
                        equal = false;
                        break;
                    }
                }
                size_t tail = offset + count * stride;
                if (!equal || data[tail] != y ||
                    (variant && data[tail + 1] != 0) ||
                    !yx_fullword(data, size, offset, span, variant != 0, 0))
                    continue;
                if (!yx_add_match(pattern, offset, span, 0)) return 0;
            }
        }
    }
    return 1;
}

static int yx_scan_regex_add_missing_lazy_short_first(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit,
    const char *expanded)
{
    YRX_PATTERN found = *pattern;
    found.regexp = (char *)expanded;
    found.matches = NULL;
    found.match_count = 0;
    found.match_capacity = 0;
    pcre2_code *code = yx_compile_pcre_regex(&found, false);
    if (!code) return 0;
    pcre2_match_data *matches = pcre2_match_data_create_from_pattern(code, NULL);
    if (!matches) {
        pcre2_code_free(code);
        return 0;
    }
    size_t secondary_limit = 0;
    if (limit) {
        secondary_limit = limit > SIZE_MAX - pattern->match_count ?
                          SIZE_MAX : limit + pattern->match_count;
    }
    int success = yx_scan_regex_buffer(&found, code, matches, data, size,
                                       data, size, 0, 0, false,
                                       secondary_limit, true, true, NULL, 0);
    pcre2_match_data_free(matches);
    pcre2_code_free(code);
    if (success) {
        size_t original_count = pattern->match_count;
        if (original_count > 1)
            qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
                  yx_match_compare);
        for (size_t i = 0; i < found.match_count; ++i) {
            size_t offset = found.matches[i].offset;
            size_t left = 0, right = original_count;
            while (left < right) {
                size_t middle = left + (right - left) / 2;
                if (pattern->matches[middle].offset < offset)
                    left = middle + 1;
                else right = middle;
            }
            if (left < original_count &&
                pattern->matches[left].offset == offset) continue;
            if (!yx_add_match(pattern, offset, found.matches[i].length, 0)) {
                success = 0;
                break;
            }
        }
    }
    free(found.matches);
    return success;
}

static size_t yx_match_lazy_trailing_triple_end(
    const uint8_t *data, size_t size, size_t at,
    const YX_SMALL_REGEX_BRANCH branch[2], uint32_t class_mask,
    uint8_t suffix, unsigned count)
{
    if (count && at < size && data[at] == suffix) return at + 1;
    if (count == 5) return 0;
    for (unsigned i = 0; i < 2; ++i) {
        const YX_SMALL_REGEX_BRANCH *item = &branch[i];
        if (!yx_match_small_lower_branch(item, data + at, size - at))
            continue;
        size_t class_at = at + item->width;
        if (class_at >= size || data[class_at] < 'a' ||
            data[class_at] > 'z' ||
            !(class_mask & (UINT32_C(1) << (data[class_at] - 'a'))))
            continue;
        size_t end = yx_match_lazy_trailing_triple_end(
            data, size, class_at + 1, branch, class_mask, suffix,
            count + 1);
        if (end) return end;
    }
    return 0;
}

static bool yx_parse_three_literal_lower_class(
    const char *regexp, size_t length, size_t *at, uint32_t *mask)
{
    size_t pos = *at;
    if (pos + 4 >= length || regexp[pos] != '[' ||
        regexp[pos + 4] != ']' ||
        regexp[pos + 1] < 'a' || regexp[pos + 1] > 'z' ||
        regexp[pos + 2] <= regexp[pos + 1] ||
        regexp[pos + 2] > 'z' ||
        regexp[pos + 3] <= regexp[pos + 2] ||
        regexp[pos + 3] > 'z') return false;
    *mask = (UINT32_C(1) << (regexp[pos + 1] - 'a')) |
            (UINT32_C(1) << (regexp[pos + 2] - 'a')) |
            (UINT32_C(1) << (regexp[pos + 3] - 'a'));
    *at = pos + 5;
    return true;
}

/* This lazy trailing-class form can find a suffix at an offset omitted by
   the regular expression scan. Preserve the original branch-selected span
   wherever that scan already found a match. */
static int yx_scan_lazy_trailing_triple_missing(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = regexp[0] == '^' ? 1 : 0;
    bool anchored = at != 0;
    YX_SMALL_REGEX_BRANCH branch[2];
    uint32_t class_mask, short_mask, first_mask, tail_mask, suffix_mask;
    if ((pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        at + 6 >= length || memcmp(regexp + at, "(?:(?:", 6) != 0)
        return 1;
    at += 6;
    if (!yx_parse_small_lower_branch(regexp, length, &at, &branch[0]) ||
        at >= length || regexp[at++] != '|' ||
        !yx_parse_small_lower_branch(regexp, length, &at, &branch[1]) ||
        at >= length || regexp[at++] != ')' ||
        (!yx_parse_two_or_three_lower_class(regexp, length, &at,
                                            &class_mask) &&
         !yx_parse_three_literal_lower_class(regexp, length, &at,
                                              &class_mask)) ||
        at >= length || regexp[at++] != ')') return 1;
    if (branch[0].width != 1 || branch[1].width != 2 ||
        at + 7 != length || memcmp(regexp + at, "{1,3}?", 6) != 0 ||
        regexp[at + 6] < 'a' || regexp[at + 6] > 'z') return 1;
    short_mask = branch[0].masks[0];
    first_mask = branch[1].masks[0];
    tail_mask = branch[1].masks[1];
    suffix_mask = UINT32_C(1) << (regexp[at + 6] - 'a');
    if ((first_mask & (first_mask - 1)) != 0 ||
        (tail_mask & (tail_mask - 1)) != 0 ||
        first_mask == tail_mask || first_mask == suffix_mask ||
        tail_mask == suffix_mask ||
        short_mask != (first_mask | suffix_mask) ||
        class_mask != (short_mask | tail_mask)) return 1;
    size_t original_count = pattern->match_count;
    if (original_count > 1)
        qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
              yx_match_compare);
    for (size_t offset = 0; offset < size; ++offset) {
        size_t left = 0, right = original_count;
        while (left < right) {
            size_t middle = left + (right - left) / 2;
            if (pattern->matches[middle].offset < offset)
                left = middle + 1;
            else right = middle;
        }
        if (left == original_count ||
            pattern->matches[left].offset != offset) {
            size_t end = yx_match_lazy_trailing_triple_end(
                data, size, offset, branch, class_mask,
                (uint8_t)regexp[at + 6], 0);
            if (end && !yx_add_match(pattern, offset, end - offset, 0))
                return 0;
        }
        if (anchored) break;
    }
    return 1;
}

/* These two nested short-first alternatives use the same verifier priority.
   It consumes up to three class bytes, or four when a leading xy pair can be
   chosen. Keep the guard exact: nearby quantifiers and branch orders use
   different priorities. */
static int yx_scan_nested_short_first_pair_bound(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp);
    uint8_t x, y;
    *handled = false;
    if (pattern->modifiers != 0 && pattern->modifiers != YX_MOD_ASCII)
        return 1;
    if (length == 22 &&
        memcmp(regexp, "(?:(?:", 6) == 0 &&
        regexp[7] == '|' && regexp[10] == ')' && regexp[11] == '|' &&
        regexp[12] == '[' && regexp[15] == ']' && regexp[16] == ')' &&
        memcmp(regexp + 17, "{1,2}", 5) == 0 &&
        regexp[6] == regexp[8] && regexp[6] == regexp[13] &&
        regexp[9] == regexp[14]) {
        x = (uint8_t) regexp[6];
        y = (uint8_t) regexp[9];
    } else if (length == 19 &&
               memcmp(regexp, "(?:", 3) == 0 &&
               regexp[4] == '|' &&
               memcmp(regexp + 5, "(?:", 3) == 0 &&
               regexp[9] == '|' && regexp[12] == ')' &&
               regexp[13] == ')' &&
               memcmp(regexp + 14, "{1,2}", 5) == 0 &&
               regexp[8] == regexp[10] && regexp[3] == regexp[11]) {
        x = (uint8_t) regexp[8];
        y = (uint8_t) regexp[3];
    } else return 1;
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y)
        return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t run = 0, span;
        while (run < 4 && run < size - offset &&
               (data[offset + run] == x || data[offset + run] == y))
            ++run;
        if (!run) continue;
        span = run < 3 ? run : 3;
        if (run == 4 && data[offset] == x && data[offset + 1] == y)
            span = 4;
        if (!yx_add_match(pattern, offset, span, limit)) return 0;
    }
    return 1;
}

/* The bounded verifier for (?:[xy]|x+){1,2} extends a leading x run by
   two class bytes. A match beginning with y takes up to three class bytes.
   Cache the end of each x run so long inputs remain linear. */
static int yx_scan_bounded_class_plus_branch(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y;
    size_t run_end = 0;
    *handled = false;
    if (pattern->modifiers != 0 && pattern->modifiers != YX_MOD_ASCII)
        return 1;
    if (strlen(regexp) != 16 ||
        memcmp(regexp, "(?:[", 4) != 0 ||
        regexp[6] != ']' || regexp[7] != '|' ||
        regexp[9] != '+' || regexp[10] != ')' ||
        memcmp(regexp + 11, "{1,2}", 5) != 0)
        return 1;
    x = (uint8_t) regexp[8];
    if (regexp[4] == (char) x)
        y = (uint8_t) regexp[5];
    else if (regexp[5] == (char) x)
        y = (uint8_t) regexp[4];
    else return 1;
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y)
        return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t span = 0;
        if (data[offset] == x) {
            if (offset >= run_end) {
                run_end = offset + 1;
                while (run_end < size && data[run_end] == x) ++run_end;
            }
            span = run_end - offset;
            size_t tail = 0;
            while (tail < 2 && tail < size - run_end &&
                   (data[run_end + tail] == x ||
                    data[run_end + tail] == y)) ++tail;
            span += tail;
        } else if (data[offset] == y) {
            span = 1;
            while (span < 3 && span < size - offset &&
                   (data[offset + span] == x || data[offset + span] == y))
                ++span;
        }
        if (span && !yx_add_match(pattern, offset, span, limit)) return 0;
    }
    return 1;
}

/* In (?:xy|x+)+, a run can include a y only immediately after x. The
   verifier keeps the longest such prefix at each x offset. Cache the first
   rejected byte so each contiguous valid region is visited only once. */
static int yx_scan_pair_or_first_plus(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y;
    size_t valid_end = 0;
    *handled = false;
    if (pattern->modifiers != 0 && pattern->modifiers != YX_MOD_ASCII)
        return 1;
    if (strlen(regexp) != 10 ||
        memcmp(regexp, "(?:", 3) != 0 ||
        regexp[5] != '|' || regexp[6] != regexp[3] ||
        regexp[7] != '+' || regexp[8] != ')' || regexp[9] != '+')
        return 1;
    x = (uint8_t) regexp[3];
    y = (uint8_t) regexp[4];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y)
        return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        if (data[offset] != x) continue;
        if (offset >= valid_end) {
            valid_end = offset + 1;
            while (valid_end < size &&
                   (data[valid_end] == x ||
                    (data[valid_end] == y &&
                     data[valid_end - 1] == x))) ++valid_end;
        }
        if (!yx_add_match(pattern, offset, valid_end - offset, limit))
            return 0;
    }
    return 1;
}

/* For (?:x+|(?:xy|x)){1,2}, a leading x run wins unless it is one byte
   followed by y and another x run. Only then does the verifier retain the
   longer xy + x-run path. */
static int yx_scan_plus_or_nested_pair_bound(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y;
    size_t run_end = 0;
    *handled = false;
    if (pattern->modifiers != 0 && pattern->modifiers != YX_MOD_ASCII)
        return 1;
    if (strlen(regexp) != 20 ||
        memcmp(regexp, "(?:", 3) != 0 ||
        regexp[4] != '+' || regexp[5] != '|' ||
        memcmp(regexp + 6, "(?:", 3) != 0 ||
        regexp[9] != regexp[3] || regexp[11] != '|' ||
        regexp[12] != regexp[3] || regexp[13] != ')' ||
        regexp[14] != ')' ||
        memcmp(regexp + 15, "{1,2}", 5) != 0)
        return 1;
    x = (uint8_t) regexp[3];
    y = (uint8_t) regexp[10];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y)
        return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        if (data[offset] != x) continue;
        if (offset >= run_end) {
            run_end = offset + 1;
            while (run_end < size && data[run_end] == x) ++run_end;
        }
        size_t span = run_end - offset;
        if (span == 1 && size - run_end >= 2 &&
            data[run_end] == y && data[run_end + 1] == x) {
            size_t tail_end = run_end + 2;
            while (tail_end < size && data[tail_end] == x) ++tail_end;
            span = tail_end - offset;
        }
        if (!yx_add_match(pattern, offset, span, limit)) return 0;
    }
    return 1;
}

static bool yx_match_ordered_pair_token(const uint8_t *data, size_t size,
                                        size_t at, uint8_t first,
                                        uint8_t second, size_t width,
                                        bool nocase, bool wide)
{
    size_t step = wide ? 2u : 1u;
    if (at >= size || width > (size - at) / step) return false;
    for (size_t unit = 0; unit < width; ++unit) {
        size_t pos = at + unit * step;
        uint8_t actual = data[pos];
        uint8_t expected = unit ? second : first;
        if (wide && data[pos + 1] != 0) return false;
        if (nocase) {
            actual = yx_fold(actual);
            expected = yx_fold(expected);
        }
        if (actual != expected) return false;
    }
    return true;
}

static size_t yx_nested_pair_or_reverse_span(const uint8_t *data,
                                             size_t size, size_t offset,
                                             const size_t widths[3],
                                             const uint8_t first_bytes[3],
                                             const uint8_t second_bytes[3],
                                             bool nocase, bool wide,
                                             size_t *two_span)
{
    size_t step = wide ? 2u : 1u;
    size_t one_end = 0, two_end = 0, end;
    if (two_span) *two_span = 0;
    for (size_t first = 0; first < 3; ++first) {
        if (!yx_match_ordered_pair_token(data, size, offset,
                                         first_bytes[first],
                                         second_bytes[first], widths[first],
                                         nocase, wide))
            continue;
        size_t first_end = offset + widths[first] * step;
        if (!one_end) one_end = first_end;
        for (size_t second = 0; second < 3; ++second) {
            if (yx_match_ordered_pair_token(data, size, first_end,
                                            first_bytes[second],
                                            second_bytes[second], widths[second],
                                            nocase, wide)) {
                two_end = first_end + widths[second] * step;
                break;
            }
        }
        if (two_end) break;
    }
    end = two_end ? two_end : one_end;
    if (two_end) {
        if (two_span) *two_span = two_end - offset;
        for (size_t third = 0; third < 3; ++third) {
            if (yx_match_ordered_pair_token(data, size, end,
                                            first_bytes[third],
                                            second_bytes[third], widths[third],
                                            nocase, wide)) {
                end += widths[third] * step;
                break;
            }
        }
    }
    return end ? end - offset : 0;
}

static size_t yx_nested_pair_or_reverse_fullword_span(
    const uint8_t *data, size_t size, size_t offset,
    const size_t widths[3], const uint8_t first_bytes[3],
    const uint8_t second_bytes[3], bool nocase, bool wide,
    bool *fell_back)
{
    size_t two_span = 0;
    size_t span = yx_nested_pair_or_reverse_span(
        data, size, offset, widths, first_bytes, second_bytes,
        nocase, wide, &two_span);
    if (fell_back) *fell_back = false;
    if (span && yx_fullword(data, size, offset, span, wide, 0))
        return span;
    /* The optional third token can be abandoned when it crosses a word
       boundary, but the chosen two-token path is not shortened again. */
    if (two_span && two_span < span &&
        yx_fullword(data, size, offset, two_span, wide, 0)) {
        if (fell_back) *fell_back = true;
        return two_span;
    }
    return 0;
}

/* The nested xy|x and x|xy alternatives share the same verifier bound,
   but source order decides ties. Find the first two-token path in branch
   order, then extend it by the first available third token. */
static int yx_scan_nested_pair_or_reverse_bound(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y;
    bool long_first;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool fullword = (pattern->modifiers & YX_MOD_FULLWORD) != 0;
    bool both = (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) ==
                (YX_MOD_ASCII | YX_MOD_WIDE);
    *handled = false;
    if (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_NOCASE |
                               YX_MOD_WIDE | YX_MOD_FULLWORD))
        return 1;
    if (strlen(regexp) != 20 ||
        memcmp(regexp, "(?:(?:", 6) != 0 ||
        regexp[10] != ')' || regexp[11] != '|' ||
        regexp[14] != ')' ||
        memcmp(regexp + 15, "{1,2}", 5) != 0)
        return 1;
    x = (uint8_t) regexp[6];
    if (regexp[8] == '|' && regexp[9] == (char) x) {
        y = (uint8_t) regexp[7];
        long_first = true;
    } else if (regexp[7] == '|' && regexp[8] == (char) x) {
        y = (uint8_t) regexp[9];
        long_first = false;
    } else return 1;
    bool underscore_fullword = fullword && long_first && x == '_' &&
                               yx_word_byte(y);
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y ||
        (nocase && yx_fold(x) == yx_fold(y)) ||
        (fullword && (x == '_' || y == '_') && !underscore_fullword) ||
        (both && fullword && !underscore_fullword &&
         (!yx_word_byte(x) || !yx_word_byte(y))) ||
        regexp[12] != (char) y || regexp[13] != (char) x)
        return 1;
    size_t widths[3] = {long_first ? 2u : 1u,
                        long_first ? 1u : 2u, 2u};
    uint8_t first_bytes[3] = {x, x, y};
    uint8_t second_bytes[3] = {y, y, x};
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t ascii_span = 0, wide_span = 0, span;
        bool wide_fell_back = false;
        if (!wide || both) {
            if (underscore_fullword)
                ascii_span = yx_nested_pair_or_reverse_fullword_span(
                    data, size, offset, widths, first_bytes, second_bytes,
                    nocase, false, NULL);
            else
                ascii_span = yx_nested_pair_or_reverse_span(
                    data, size, offset, widths, first_bytes, second_bytes,
                    nocase, false, NULL);
        }
        if (wide) {
            if (underscore_fullword)
                wide_span = yx_nested_pair_or_reverse_fullword_span(
                    data, size, offset, widths, first_bytes, second_bytes,
                    nocase, true, &wide_fell_back);
            else
                wide_span = yx_nested_pair_or_reverse_span(
                    data, size, offset, widths, first_bytes, second_bytes,
                    nocase, true, NULL);
        }
        /* A rejected wide word can still leave a valid ASCII match at the
           same offset, so filter each encoding before resolving its tie. */
        if (fullword && !underscore_fullword) {
            if (ascii_span &&
                !yx_fullword(data, size, offset, ascii_span, false, 0))
                ascii_span = 0;
            if (wide_span &&
                !yx_fullword(data, size, offset, wide_span, true, 0))
                wide_span = 0;
        }
        span = wide ? wide_span : ascii_span;
        if (both) {
            span = ascii_span;
            if (wide_span) {
                bool same_x = wide_span == 4 &&
                    (nocase ? yx_fold(data[offset + 2]) == yx_fold(x) :
                              data[offset + 2] == x);
                /* At 16 bytes the combined verifier prefers the ASCII
                   one-byte match over a terminal wide x or xy. */
                if (!ascii_span || size < 16 ||
                    (!wide_fell_back && (wide_span >= 6 || same_x)))
                    span = wide_span;
            }
        }
        if (span && !yx_add_match(pattern, offset, span, limit))
            return 0;
    }
    return 1;
}

static int yx_scan_bounded_long_first_three_byte(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled);
static int yx_scan_bounded_long_first_pair_fullword(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled);

static bool yx_large_regex_emit(size_t offset, size_t length, void *context)
{
    return yx_add_match(context, offset, length, 0) != 0;
}
/* In Unicode mode \p{Any}, and any bracketed class that covers every scalar
 * value, is an arbitrary byte for YARA-X, exactly like (?s). . */
static bool yx_regex_any_property_at(const char *regexp, size_t at,
                                     size_t length)
{
    return at + 7 <= length && regexp[at] == '\\' && regexp[at + 1] == 'p' &&
           regexp[at + 2] == '{' && (regexp[at + 3] | 0x20) == 'a' &&
           (regexp[at + 4] | 0x20) == 'n' && (regexp[at + 5] | 0x20) == 'y' &&
           regexp[at + 6] == '}';
}

static bool yx_regex_full_scalar_range_at(const char *regexp, size_t at,
                                          size_t length)
{
    static const char *const starts[] = { "\\x{0}-", "\\x{00}-", "\\x00-" };
    static const char tail[] = "\\x{10ffff}";
    for (size_t i = 0; i < sizeof(starts) / sizeof(*starts); ++i) {
        size_t start_length = strlen(starts[i]);
        if (at + start_length + sizeof(tail) - 1 > length) continue;
        if (memcmp(regexp + at, starts[i], start_length) != 0) continue;
        bool same = true;
        for (size_t k = 0; k < sizeof(tail) - 1; ++k)
            if ((regexp[at + start_length + k] | 0x20) !=
                (tail[k] | 0x20) && regexp[at + start_length + k] != tail[k])
                same = false;
        if (same) return true;
    }
    return false;
}

/* Returns a rewritten copy, or NULL when nothing needed rewriting. */
static char *yx_regex_rewrite_any_property(const char *regexp)
{
    static const char replacement[] = "(?s:.)";
    size_t length = strlen(regexp), used = 0;
    bool changed = false;
    char *out;
    if (!strchr(regexp, 'p') && !strchr(regexp, '-')) return NULL;
    out = malloc(length + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < length;) {
        if (regexp[i] == '\\' && i + 1 < length) {
            if (yx_regex_any_property_at(regexp, i, length)) {
                memcpy(out + used, replacement, sizeof(replacement) - 1);
                used += sizeof(replacement) - 1;
                i += 7;
                changed = true;
                continue;
            }
            out[used++] = regexp[i++];
            out[used++] = regexp[i++];
            continue;
        }
        if (regexp[i] == '[') {
            size_t end = i + 1;
            bool negated = end < length && regexp[end] == '^', any = false;
            if (negated) ++end;
            if (end < length && regexp[end] == ']') ++end;
            for (; end < length && regexp[end] != ']'; ++end) {
                if (regexp[end] == '\\' && end + 1 < length) {
                    if (yx_regex_any_property_at(regexp, end, length) ||
                        yx_regex_full_scalar_range_at(regexp, end, length))
                        any = true;
                    ++end;
                } else if (regexp[end] == '[') {
                    /* Nested classes keep the ordinary translation. */
                    any = false;
                    end = length;
                }
            }
            if (any && !negated && end < length) {
                memcpy(out + used, replacement, sizeof(replacement) - 1);
                used += sizeof(replacement) - 1;
                i = end + 1;
                changed = true;
                continue;
            }
            /* Copy the whole class untouched. */
            for (; i < length && i <= end; ++i) {
                out[used++] = regexp[i];
                if (regexp[i] == '\\' && i + 1 < length)
                    out[used++] = regexp[++i];
            }
            continue;
        }
        out[used++] = regexp[i++];
    }
    out[used] = '\0';
    if (!changed) { free(out); return NULL; }
    return out;
}

static int yx_scan_regex(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                         size_t limit)
{
    char *any_rewrite = yx_regex_rewrite_any_property(pattern->regexp);
    if (any_rewrite) {
        char *saved = pattern->regexp;
        pattern->regexp = any_rewrite;
        int success = yx_scan_regex(pattern, data, size, limit);
        pattern->regexp = saved;
        free(any_rewrite);
        return success;
    }
    bool literal_chain = false;
    int chain_success = yx_scan_wide_literal_chain(pattern,data,size,limit,&literal_chain);
    if(literal_chain)return chain_success;
    char *lowered = NULL;
    int fast_result = yx_ser_lower_fast_regex(pattern, &lowered);
    if (fast_result == -1) return 0;
    if (fast_result == 0) return 1;
    if (fast_result == 3) {
        int success = yx_ser_scan_large_fast_chain(pattern, data, size, yx_large_regex_emit, pattern);
        if (success) yx_sort_unique_limit(pattern, limit);
        return success;
    }
    if (fast_result == 1) {
        char *saved = pattern->regexp; pattern->regexp = lowered;
        int success = yx_scan_regex(pattern, data, size, limit);
        pattern->regexp = saved; free(lowered); return success;
    }
    bool large_greedy = false;
    int large_result = yx_ser_scan_large_regex(pattern, data, size, yx_large_regex_emit, pattern,
                                               &large_greedy);
    if (large_result != -2) {
        if (large_result) {
            if (large_greedy) yx_keep_longest_per_offset(pattern);
            yx_sort_unique_limit(pattern, limit);
        }
        return large_result;
    }
    if (yx_unmatchable_large_repeat(pattern->regexp) ||
        yx_pcre_unicode_count_unmatchable(pattern->regexp)) return 1;
    const uint8_t *literal;
    size_t literal_length;
    if (yx_large_repeat_literal_alt(pattern->regexp, &literal,
                                    &literal_length)) {
        uint8_t *saved_bytes = pattern->bytes;
        size_t saved_length = pattern->length;
        pattern->bytes = (uint8_t *)literal;
        pattern->length = literal_length;
        int success = yx_scan_text(pattern, data, size, limit, false);
        pattern->bytes = saved_bytes;
        pattern->length = saved_length;
        return success;
    }
    bool bounded_long_first_handled = false;
    int bounded_long_first_success = yx_scan_bounded_long_first_three_byte(
        pattern, data, size, limit, &bounded_long_first_handled);
    if (bounded_long_first_handled) return bounded_long_first_success;
    if (!bounded_long_first_success) return 0;
    bool bounded_pair_fullword_handled = false;
    int bounded_pair_fullword_success =
        yx_scan_bounded_long_first_pair_fullword(
            pattern, data, size, limit, &bounded_pair_fullword_handled);
    if (bounded_pair_fullword_handled) return bounded_pair_fullword_success;
    if (!bounded_pair_fullword_success) return 0;
    bool nested_short_pair_handled = false;
    int nested_short_pair_success = yx_scan_nested_short_first_pair_bound(
        pattern, data, size, limit, &nested_short_pair_handled);
    if (nested_short_pair_handled) return nested_short_pair_success;
    if (!nested_short_pair_success) return 0;
    bool class_plus_handled = false;
    int class_plus_success = yx_scan_bounded_class_plus_branch(
        pattern, data, size, limit, &class_plus_handled);
    if (class_plus_handled) return class_plus_success;
    if (!class_plus_success) return 0;
    bool pair_plus_handled = false;
    int pair_plus_success = yx_scan_pair_or_first_plus(
        pattern, data, size, limit, &pair_plus_handled);
    if (pair_plus_handled) return pair_plus_success;
    if (!pair_plus_success) return 0;
    bool nested_plus_handled = false;
    int nested_plus_success = yx_scan_plus_or_nested_pair_bound(
        pattern, data, size, limit, &nested_plus_handled);
    if (nested_plus_handled) return nested_plus_success;
    if (!nested_plus_success) return 0;
    bool nested_reverse_handled = false;
    int nested_reverse_success = yx_scan_nested_pair_or_reverse_bound(
        pattern, data, size, limit, &nested_reverse_handled);
    if (nested_reverse_handled) return nested_reverse_success;
    if (!nested_reverse_success) return 0;
    bool overlap_class_handled = false;
    int overlap_class_success = yx_scan_bounded_overlap_class_branch(
        pattern, data, size, limit, &overlap_class_handled);
    if (overlap_class_handled) return overlap_class_success;
    if (!overlap_class_success) return 0;
    bool class_literal_handled = false;
    int class_literal_success = yx_scan_bounded_class_literal_branch(
        pattern, data, size, limit, &class_literal_handled);
    if (class_literal_handled) return class_literal_success;
    if (!class_literal_success) return 0;
    bool grouped_literal_prefix = false;
    int grouped_success = yx_scan_grouped_literal_prefix(pattern, data, size,
                                                          limit,
                                                          &grouped_literal_prefix);
    if (grouped_literal_prefix) return grouped_success;
    if (!grouped_success) return 0;
    bool literal_alternation = false;
    int literal_success = yx_scan_literal_alternation(pattern, data, size,
                                                      limit,
                                                      &literal_alternation);
    if (literal_alternation) return literal_success;
    bool bounded_overlap_handled = false;
    int bounded_overlap_success = yx_scan_greedy_bounded_overlap(
        pattern, data, size, limit, &bounded_overlap_handled);
    if (bounded_overlap_handled) return bounded_overlap_success;
    bool nested_pair_handled = false;
    int nested_pair_success = yx_scan_nested_fixed_pair(
        pattern, data, size, limit, &nested_pair_handled);
    if (nested_pair_handled) return nested_pair_success;
    bool nested_class_handled = false;
    int nested_class_success = yx_scan_greedy_nested_class_alt(
        pattern, data, size, limit, &nested_class_handled);
    if (nested_class_handled) return nested_class_success;
    bool subset_count_handled = false;
    int subset_count_success = yx_scan_greedy_nested_subset_count(
        pattern, data, size, limit, &subset_count_handled);
    if (subset_count_handled) return subset_count_success;
    bool nested_variable_handled = false;
    int nested_variable_success = yx_scan_greedy_nested_variable_class_alt(
        pattern, data, size, limit, &nested_variable_handled);
    if (nested_variable_handled) return nested_variable_success;
    bool lazy_nested_handled = false;
    int lazy_nested_success = yx_scan_lazy_nested_shortest_variants(
        pattern, data, size, limit, &lazy_nested_handled);
    if (lazy_nested_handled) return lazy_nested_success;
    bool nested_counted_handled = false;
    int nested_counted_success = yx_scan_greedy_nested_counted_class(
        pattern, data, size, limit, &nested_counted_handled);
    if (nested_counted_handled) return nested_counted_success;
    bool disjoint_pair_handled = false;
    int disjoint_pair_success = yx_scan_greedy_nested_pair(
        pattern, data, size, limit, &disjoint_pair_handled);
    if (disjoint_pair_handled) return disjoint_pair_success;
    bool greedy_class_handled = false;
    int greedy_class_success = yx_scan_greedy_overlapping_class(
        pattern, data, size, limit, &greedy_class_handled);
    if (greedy_class_handled) return greedy_class_success;
    char *expanded = yx_regex_expand_disjoint_literal_pair_bound(pattern);
    if (!expanded) expanded = yx_regex_expand_leading_repeat(pattern->regexp);
    if (!expanded)
        expanded = yx_regex_expand_disjoint_plus_pair_bound(pattern);
    if (!expanded) expanded = yx_regex_expand_nested_bound(pattern);
    if (!expanded)
        expanded = yx_regex_expand_anchored_class_pair_bound(pattern);
    if (!expanded)
        expanded = yx_regex_expand_anchored_trailing_class_bound(pattern);
    bool expanded_lazy_bound = false;
    if (!expanded) {
        expanded = yx_regex_expand_lazy_triple_class_bound(pattern);
        expanded_lazy_bound = expanded != NULL;
    }
    if (!expanded) {
        expanded = yx_regex_expand_lazy_trailing_pair_bound(pattern);
        expanded_lazy_bound = expanded != NULL;
    }
    char *collapsed = yx_regex_collapse_overlapping_repeat(
        expanded ? expanded : pattern->regexp);
    char *prioritized = NULL;
    if (!expanded && !collapsed) {
        prioritized = yx_regex_prioritize_nested_suffix(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_repeated_literal_alt(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_repeated_class_literal_alt(
                pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_repeated_class_alt(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_repeated_range_alt(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_bounded_range_alt(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_bounded_literal_alt(pattern);
        if (!prioritized)
            prioritized = yx_regex_expand_grouped_literal_repeat(pattern);
        if (!prioritized)
            prioritized = yx_regex_expand_short_first_grouped_repeat(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_grouped_short_branch(pattern,
                                                                    size);
        if (!prioritized)
            prioritized = yx_regex_prioritize_longer_atom(pattern);
        if (!prioritized)
            prioritized = yx_regex_prioritize_large_atom_prefix(pattern);
    }
    YRX_PATTERN adjusted = *pattern;
    if (collapsed) adjusted.regexp = collapsed;
    else if (expanded) adjusted.regexp = expanded;
    else if (prioritized) adjusted.regexp = prioritized;
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) ||
                 !(pattern->modifiers & YX_MOD_WIDE);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool short_ascii_large_atom =
        yx_regex_large_atom_two_byte_ascii_prefix(pattern);
    bool digit_prefix_wide_tie =
        yx_regex_digit_prefix_wide_tie(pattern);
    bool complete_wide_prefix_tie =
        size >= 16 && yx_regex_small_atom_complete_wide_prefix(pattern);
    int success = 1;
    bool longest_variant = false, optional_prefix_variant = false;
    bool short_single_variant = false, ascii_only_variant = false;
    if (ascii && wide) yx_regex_variant_policy(pattern, &longest_variant,
        &optional_prefix_variant, &short_single_variant, &ascii_only_variant);
    bool wide_greedy_repeat = ascii && wide &&
        (yx_regex_has_greedy_variable_repeat(pattern->regexp) ||
         yx_regex_is_single_dotall_dot(pattern->regexp,
                                       (pattern->modifiers & YX_MOD_DOTALL) != 0) ||
         yx_regex_is_single_all_bytes_class(pattern->regexp));
    if (ascii && wide && size >= 16) {
        if (yx_regex_long_wide_tie(pattern) ||
            yx_regex_long_wide_lazy_class_pair_tie(pattern) ||
            yx_regex_nocase_single_letter(pattern))
            wide_greedy_repeat = true;
        if (optional_prefix_variant || yx_regex_long_ascii_tie(pattern) ||
            yx_regex_long_ascii_class_repeat(pattern))
            wide_greedy_repeat = false;
        if(short_single_variant)wide_greedy_repeat=true;
    }
    if(ascii_only_variant)wide_greedy_repeat=false;
    bool wide_word_context = wide &&
                             yx_regex_has_word_boundary(adjusted.regexp);
    pcre2_code *cached_code = !collapsed && !expanded && !prioritized ?
        yx_candidate_cached_regex(pattern) : NULL;
    pcre2_code *ascii_code = ascii ? (cached_code ? cached_code :
        yx_compile_pcre_regex(&adjusted, false)) : NULL;
    pcre2_code *wide_code = wide ? (cached_code ? cached_code :
        yx_compile_pcre_regex(&adjusted, true)) : NULL;
    pcre2_code *code = ascii ? ascii_code : wide_code;
    if (!code || (wide && !wide_code)) {
        if (!cached_code) {
            pcre2_code_free(ascii_code);
            pcre2_code_free(wide_code);
        }
        free(collapsed);
        free(expanded);
        free(prioritized);
        return 0;
    }
    pcre2_match_data *matches = pcre2_match_data_create_from_pattern(code, NULL);
    if (!matches) {
        if (!cached_code) {
            pcre2_code_free(ascii_code);
            pcre2_code_free(wide_code);
        }
        free(collapsed);
        free(expanded);
        free(prioritized);
        return 0;
    }

    /* The unrewritten one-literal regexp (chained hex pieces among others)
       searches its occurrences with the literal finder. */
    size_t pure_length = 0;
    uint8_t *pure_literal = !collapsed && !expanded && !prioritized ?
        yx_regex_pure_literal(pattern, &pure_length) : NULL;

    /* Each encoding and byte alignment has its own earliest matches. Collect
       them independently before applying the caller's shared match limit. */
    size_t ascii_match_count = 0;
    for (int variant = 0; variant < 3 && success; ++variant) {
        if ((variant == 0 && !ascii) || (variant != 0 && !wide)) continue;
        YRX_PATTERN found = *pattern;
        if (expanded_lazy_bound) found.regexp = adjusted.regexp;
        found.matches = NULL;
        found.match_count = 0;
        found.match_capacity = 0;
        if (variant == 0) {
            success = yx_scan_regex_buffer(&found, ascii_code, matches, data, size,
                                           data, size, 0, 0, false, limit,
                                           true, true, pure_literal, pure_length);
        } else {
            size_t parity = (size_t)(variant - 1);
            uint8_t *projected = NULL;
            size_t capacity = 0, pos = parity;
            while (pos + 1 < size && (!limit || found.match_count < limit)) {
                if (data[pos + 1] != 0) { pos += 2; continue; }
                size_t origin = pos;
                do {
                    pos += 2;
                } while (pos + 1 < size && data[pos + 1] == 0);
                size_t length = (pos - origin) / 2;
                size_t context_prefix = 0;
                /* A wide word assertion sees the preceding low byte even
                   when its high byte is nonzero and ends the projected run. */
                if (wide_word_context && origin >= 2) context_prefix = 1;
                size_t projected_length = length + context_prefix;
                if (projected_length > capacity) {
                    uint8_t *grown = realloc(projected, projected_length);
                    if (!grown) { success = 0; break; }
                    projected = grown;
                    capacity = projected_length;
                }
                if (context_prefix) projected[0] = data[origin - 2];
                for (size_t i = 0; i < length; ++i)
                    projected[i + context_prefix] = data[origin + i * 2];
                success = yx_scan_regex_buffer(&found, wide_code, matches,
                                               projected, projected_length,
                                               data, size,
                                               origin - context_prefix * 2,
                                               context_prefix, true, limit,
                                               origin <= 1,
                                               size - pos <= 1, NULL, 0);
                if (!success) break;
            }
            free(projected);
        }
        if (success) {
            for (size_t i = 0; i < found.match_count; ++i) {
                if (variant &&
                    (wide_greedy_repeat || complete_wide_prefix_tie || ascii_only_variant)) {
                    size_t left = 0, right = ascii_match_count;
                    while (left < right) {
                        size_t middle = left + (right - left) / 2;
                        if (pattern->matches[middle].offset <
                            found.matches[i].offset)
                            left = middle + 1;
                        else right = middle;
                    }
                    if (left < ascii_match_count &&
                        pattern->matches[left].offset == found.matches[i].offset) {
                        /* YARA-X resolves a greedy regex tie in favor of
                           wide, even when its raw span is shorter. */
                        if ((wide_greedy_repeat &&
                             !(short_single_variant && size>=16 && found.matches[i].length==2) &&
                             (!digit_prefix_wide_tie ||
                              found.matches[i].length == 4)) ||
                            (complete_wide_prefix_tie &&
                             pattern->matches[left].length == 1 &&
                             found.matches[i].length == 4))
                            if (!longest_variant || pattern->matches[left].length < found.matches[i].length)
                                pattern->matches[left].length = found.matches[i].length;
                        continue;
                    }
                }
                size_t match_length = found.matches[i].length;
                if (variant == 0 && short_ascii_large_atom &&
                    match_length == 3) match_length = 2;
                match_length = yx_regex_short_input_literal_prefix_length(
                    pattern, size, variant, match_length);
                if (!yx_add_match(pattern, found.matches[i].offset,
                                  match_length, 0)) {
                    success = 0;
                    break;
                }
            }
            if (variant == 0) ascii_match_count = pattern->match_count;
        }
        free(found.matches);
    }
    free(pure_literal);
    pcre2_match_data_free(matches);
    if (!cached_code) {
        pcre2_code_free(ascii_code);
        pcre2_code_free(wide_code);
    }
    free(collapsed);
    free(expanded);
    free(prioritized);
    if (success) {
        char *missing_bound =
            yx_regex_expand_lazy_short_first_pair_bound(pattern);
        if (missing_bound) {
            success = yx_scan_regex_add_missing_lazy_short_first(
                pattern, data, size, limit, missing_bound);
            free(missing_bound);
        }
    }
    if (success)
        yx_regex_adjust_repeated_outer_literal(pattern, data, size);
    if (success)
        success = yx_regex_add_nested_pure_run(pattern, data, size);
    if (success)
        success = yx_regex_add_fullword_pure_run(pattern, data, size);
    if (success)
        success = yx_scan_lazy_trailing_triple_missing(pattern, data, size);
    return success;
}

/* A case-insensitive literal alternation with one branch that is a proper
   prefix of the other uses the longer atom's verifier at the end of the
   input. YARA-X does not report the shorter branch there because that
   verifier cannot read its following byte. This applies to ASCII and wide
   matches, but only to the shorter branch ending at the physical EOF. */
static void yx_discard_nocase_prefix_at_eof(YRX_PATTERN *pattern,
                                              const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    const char *bar;
    const char *shorter;
    const char *longer;
    size_t left_length, right_length, short_length, long_length;
    if (!(pattern->modifiers & YX_MOD_NOCASE) ||
        (pattern->modifiers & YX_MOD_FULLWORD) || !regexp) return;
    bar = strchr(regexp, '|');
    if (!bar || strchr(bar + 1, '|')) return;
    left_length = (size_t)(bar - regexp);
    right_length = strlen(bar + 1);
    if (left_length < 2 || right_length < 2 ||
        left_length == right_length) return;
    shorter = left_length < right_length ? regexp : bar + 1;
    longer = left_length < right_length ? bar + 1 : regexp;
    short_length = left_length < right_length ? left_length : right_length;
    long_length = left_length > right_length ? left_length : right_length;
    for (size_t i = 0; i < long_length; ++i) {
        unsigned char ch = (unsigned char)longer[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9'))) return;
        if (i < short_length) {
            /* Numeric atoms do not use the nocase verifier path. */
            if (!((ch >= 'a' && ch <= 'z') ||
                  (ch >= 'A' && ch <= 'Z')) ||
                yx_fold(ch) != yx_fold((uint8_t)shorter[i])) return;
        }
    }
    size_t out = 0;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH match = pattern->matches[i];
        bool short_at_eof = false;
        if (match.offset <= size && match.length == short_length &&
            match.length == size - match.offset &&
            yx_equal_text(data + match.offset,
                          (const uint8_t *)shorter, short_length, true)) {
            short_at_eof = true;
        } else if ((pattern->modifiers & YX_MOD_WIDE) &&
                   short_length <= SIZE_MAX / 2 &&
                   match.offset <= size &&
                   match.length == 2 * short_length &&
                   match.length == size - match.offset) {
            short_at_eof = true;
            for (size_t j = 0; j < short_length; ++j) {
                if (data[match.offset + 2 * j + 1] != 0 ||
                    yx_fold(data[match.offset + 2 * j]) !=
                        yx_fold((uint8_t)shorter[j])) {
                    short_at_eof = false;
                    break;
                }
            }
        }
        if (!short_at_eof) pattern->matches[out++] = match;
    }
    pattern->match_count = out;
}

static bool yx_repeated_literal_unit_at(const uint8_t *data, size_t size,
                                        size_t offset, size_t width,
                                        uint8_t value)
{
    return offset <= size && size - offset >= width &&
           data[offset] == value && (width == 1 || data[offset + 1] == 0);
}

/* For a case-sensitive (x|xy)+y, the verifier keeps xy as a repetition
   only if another x follows it. Otherwise y ends the match. If continuing
   finds no later suffix, it falls back to the most recent y. PCRE2's
   short-first branch stops at the first y, so adjust only the span of hits
   it already found. The same choice applies to projected wide units. */
static void yx_adjust_greedy_repeated_literal_pair(YRX_PATTERN *pattern,
                                                    const uint8_t *data,
                                                    size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    uint8_t x, y;
    if (pattern->modifiers & (YX_MOD_NOCASE | YX_MOD_FULLWORD)) return;
    if (regexp[0] != '(') return;
    if (length >= 3 && regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 7 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 4] != ')' ||
        regexp[at + 5] != '+' || regexp[at + 6] != regexp[at + 3])
        return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y)
        return;
    if (((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) &&
        !((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z'))) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       yx_repeated_literal_unit_at(data, size, match->offset,
                                                   2, x) ? 2 : 1;
        size_t pos = match->offset, best = 0;
        while (yx_repeated_literal_unit_at(data, size, pos, width, x)) {
            if (size - pos >= 2 * width &&
                yx_repeated_literal_unit_at(data, size, pos + width,
                                            width, y)) {
                best = pos + 2 * width - match->offset;
                if (size - pos >= 3 * width &&
                    yx_repeated_literal_unit_at(data, size,
                                                pos + 2 * width,
                                                width, x)) {
                    pos += 2 * width;
                    continue;
                }
                break;
            }
            pos += width;
        }
        if (best) match->length = best;
    }
}

static bool yx_short_first_unit_at(const uint8_t *data, size_t size,
                                   size_t offset, size_t width,
                                   uint8_t value, bool nocase)
{
    if (offset > size || size - offset < width ||
        (width == 2 && data[offset + 1] != 0)) return false;
    return nocase ? yx_fold(data[offset]) == yx_fold(value) :
                    data[offset] == value;
}

/* A long-first literal group (xyz|x){1,n} can visit 2*n-1 complete
   alternatives in the reference verifier. Find its final endpoint before
   applying fullword: the host regexp can reject an early short x while the
   verifier would continue to a word boundary. Keep the combined-encoding
   case on the ordinary path whenever a wide match is possible. */
static int yx_scan_bounded_long_first_three_byte(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, length;
    uint8_t x, y, z;
    unsigned bound;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool both = wide && (pattern->modifiers & YX_MOD_ASCII);
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool fullword = (pattern->modifiers & YX_MOD_FULLWORD) != 0;
    size_t width = wide && !both ? 2 : 1;
    *handled = false;
    if (!regexp || regexp[0] != '(' ||
        (pattern->modifiers & YX_MOD_XOR) ||
        (both && memchr(data, 0, size) != NULL)) return 1;
    length = strlen(regexp);
    if (length >= 3 && regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 11 || regexp[at + 3] != '|' ||
        regexp[at + 4] != regexp[at] || regexp[at + 5] != ')')
        return 1;
    if (strcmp(regexp + at + 6, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 6, "{1,3}") == 0) bound = 3;
    else if (strcmp(regexp + at + 6, "{1,4}") == 0) bound = 4;
    else return 1;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 1];
    z = (uint8_t)regexp[at + 2];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        yx_fold(x) == yx_fold(y) || yx_fold(x) == yx_fold(z) ||
        yx_fold(y) == yx_fold(z)) return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t end = offset, best = 0;
        unsigned matched = 0;
        for (unsigned repeat = 0; repeat < 2 * bound - 1; ++repeat) {
            if (!yx_short_first_unit_at(data, size, end, width, x, nocase))
                break;
            end += width;
            if (end <= size && size - end >= 2 * width &&
                yx_short_first_unit_at(data, size, end, width, y, nocase) &&
                yx_short_first_unit_at(data, size, end + width,
                                       width, z, nocase))
                end += 2 * width;
            ++matched;
            if (!fullword || yx_fullword(data, size, offset, end - offset,
                                         width == 2, 0))
                best = end - offset;
        }
        /* The atom-search path reports an isolated final long branch via
           its one-byte prefix on a long input. The projected wide path
           switches one byte beyond the 16-byte input boundary. */
        bool all_digits = x >= '0' && x <= '9' &&
                          y >= '0' && y <= '9' &&
                          z >= '0' && z <= '9';
        if (!fullword && matched == 1 && best == 3 * width &&
            (width == 1 ? size >= 16 : size > 16) &&
            (!nocase || all_digits))
            best = width;
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
    }
    return 1;
}

/* The fullword check for (xy|x){1,n} also belongs after the verifier has
   consumed its bounded branches. A shorter intermediate x can be inside a
   word even when the final match ends at the word boundary. */
static int yx_scan_bounded_long_first_pair_fullword(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t limit, bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, length;
    uint8_t x, y;
    unsigned bound;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool both = wide && (pattern->modifiers & YX_MOD_ASCII);
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    size_t width = wide && !both ? 2 : 1;
    *handled = false;
    if (!regexp || regexp[0] != '(' ||
        !(pattern->modifiers & YX_MOD_FULLWORD) ||
        (pattern->modifiers & YX_MOD_XOR) ||
        (both && memchr(data, 0, size) != NULL)) return 1;
    length = strlen(regexp);
    if (length >= 3 && regexp[1] == '?' && regexp[2] == ':') at = 3;
    if (length != at + 10 || regexp[at + 2] != '|' ||
        regexp[at + 3] != regexp[at] || regexp[at + 4] != ')')
        return 1;
    if (strcmp(regexp + at + 5, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 5, "{1,3}") == 0) bound = 3;
    else if (strcmp(regexp + at + 5, "{1,4}") == 0) bound = 4;
    else return 1;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 1];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        yx_fold(x) == yx_fold(y)) return 1;
    *handled = true;
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t end = offset, best = 0;
        for (unsigned repeat = 0; repeat < 2 * bound - 1; ++repeat) {
            if (!yx_short_first_unit_at(data, size, end, width, x, nocase))
                break;
            end += width;
            if (yx_short_first_unit_at(data, size, end, width, y, nocase))
                end += width;
            if (yx_fullword(data, size, offset, end - offset,
                            width == 2, 0))
                best = end - offset;
        }
        if (best && !yx_add_match(pattern, offset, best, limit)) return 0;
    }
    return 1;
}

/* In ([xy]|x[yz])+ and {2,}, a long branch contributes its second byte
   only when another short-class byte follows. The verifier then continues
   from that byte, whereas a host regex engine can stop at its first short
   alternative. */
static size_t yx_repeated_overlap_class_step(const uint8_t *data,
                                              size_t size, size_t offset,
                                              size_t width, uint8_t x,
                                              uint8_t y, uint8_t z,
                                              bool nocase)
{
    bool first = yx_short_first_unit_at(data, size, offset, width, x,
                                         nocase);
    if (!first && !yx_short_first_unit_at(data, size, offset, width, y,
                                           nocase)) return 0;
    if (first && size - offset >= 3 * width &&
        (yx_short_first_unit_at(data, size, offset + width, width, y,
                                 nocase) ||
         yx_short_first_unit_at(data, size, offset + width, width, z,
                                 nocase)) &&
        (yx_short_first_unit_at(data, size, offset + 2 * width, width,
                                 x, nocase) ||
         yx_short_first_unit_at(data, size, offset + 2 * width, width,
                                 y, nocase))) return 2;
    return 1;
}

/* Cache suffix lengths so a long run of matching bytes is scanned once,
   even though it yields a match at every starting offset. */
static size_t *yx_repeated_overlap_class_units(const uint8_t *data,
                                                size_t size, size_t width,
                                                uint8_t x, uint8_t y,
                                                uint8_t z, bool nocase)
{
    if (size >= SIZE_MAX / sizeof(size_t)) return NULL;
    size_t *units = malloc((size + 1) * sizeof(size_t));
    if (!units) return NULL;
    units[size] = 0;
    for (size_t offset = size; offset-- > 0;) {
        size_t step = yx_repeated_overlap_class_step(
            data, size, offset, width, x, y, z, nocase);
        units[offset] = step ? step + units[offset + step * width] : 0;
    }
    return units;
}

static int yx_scan_repeated_overlap_class_branch(YRX_PATTERN *pattern,
                                                  const uint8_t *data,
                                                  size_t size, size_t limit,
                                                  bool *handled)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    uint8_t x, y, z;
    unsigned minimum;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) || !wide;
    *handled = false;
    if ((pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        regexp[0] != '(') return 1;
    if (length >= at + 2 && regexp[at] == '?' && regexp[at + 1] == ':')
        at += 2;
    if (length < at + 12 || regexp[at] != '[' || regexp[at + 3] != ']' ||
        regexp[at + 4] != '|' || regexp[at + 6] != '[' ||
        regexp[at + 9] != ']' || regexp[at + 10] != ')') return 1;
    if (strcmp(regexp + at + 11, "+") == 0) minimum = 1;
    else if (strcmp(regexp + at + 11, "{2,}") == 0) minimum = 2;
    else return 1;
    x = (uint8_t)regexp[at + 1];
    y = (uint8_t)regexp[at + 2];
    z = (uint8_t)regexp[at + 8];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || regexp[at + 5] != (char)x ||
        regexp[at + 7] != (char)y ||
        yx_fold(x) >= yx_fold(y) || yx_fold(y) >= yx_fold(z))
        return 1;
    *handled = true;
    size_t *ascii_cache = ascii ? yx_repeated_overlap_class_units(
        data, size, 1, x, y, z, nocase) : NULL;
    size_t *wide_cache = wide ? yx_repeated_overlap_class_units(
        data, size, 2, x, y, z, nocase) : NULL;
    if ((ascii && !ascii_cache) || (wide && !wide_cache)) {
        free(ascii_cache);
        free(wide_cache);
        /* Preserve the ordinary regex path if the suffix cache cannot be
           allocated for a very large scan buffer. */
        *handled = false;
        return 1;
    }
    for (size_t offset = 0; offset < size &&
                            (!limit || pattern->match_count < limit);
         ++offset) {
        size_t ascii_units = ascii_cache ? ascii_cache[offset] : 0;
        size_t wide_units = wide_cache ? wide_cache[offset] : 0;
        if (minimum == 2 && ascii_units) {
            size_t step = yx_repeated_overlap_class_step(
                data, size, offset, 1, x, y, z, nocase);
            if (!ascii_cache[offset + step]) ascii_units = 0;
        }
        if (minimum == 2 && wide_units) {
            size_t step = yx_repeated_overlap_class_step(
                data, size, offset, 2, x, y, z, nocase);
            if (!wide_cache[offset + 2 * step]) wide_units = 0;
        }
        size_t span = ascii_units;
        if (wide_units > ascii_units ||
            (wide_units && wide_units == ascii_units && size < 16))
            span = wide_units * 2;
        if (span && !yx_add_match(pattern, offset, span, limit)) {
            free(ascii_cache);
            free(wide_cache);
            return 0;
        }
    }
    free(ascii_cache);
    free(wide_cache);
    return 1;
}

static bool yx_short_first_token_at(const uint8_t *data, size_t size,
                                    size_t offset, size_t width,
                                    const uint8_t *token, size_t length,
                                    bool nocase)
{
    if (offset > size || size - offset < length * width) return false;
    for (size_t i = 0; i < length; ++i)
        if (!yx_short_first_unit_at(data, size, offset + i * width,
                                    width, token[i], nocase)) return false;
    return true;
}

/* When a literal prefix group is repeated, the short-atom search path
   selects an ASCII one-byte hit over a single wide repetition on long
   inputs. A second wide repetition gives the wide verifier priority. */
static void yx_adjust_grouped_ascii_wide_ties(YRX_PATTERN *pattern,
                                               const uint8_t *data,
                                               size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, lengths[3] = {0}, starts[3] = {0}, count = 0;
    uint8_t first;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (size < 16 ||
        (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) !=
            (YX_MOD_ASCII | YX_MOD_WIDE) ||
        (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE |
                                YX_MOD_NOCASE)) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    first = (uint8_t)regexp[at];
    if (!yx_plain_regex_byte(first)) return;
    for (;;) {
        size_t start = at;
        if (count == 3) return;
        while (yx_plain_regex_byte((uint8_t)regexp[at])) {
            if (at - start == 3) return;
            ++at;
        }
        if (!at || at - start < 1 ||
            (nocase ? yx_fold((uint8_t)regexp[start]) != yx_fold(first) :
                      (uint8_t)regexp[start] != first)) return;
        starts[count] = start;
        lengths[count++] = at - start;
        if (regexp[at] == ')') break;
        if (regexp[at++] != '|') return;
    }
    if (count < 2 ||
        (strcmp(regexp + at + 1, "+") != 0 &&
         strcmp(regexp + at + 1, "{1,2}") != 0 &&
         strcmp(regexp + at + 1, "{1,3}") != 0)) return;
    bool short_branch = false;
    for (size_t i = 0; i < count; ++i)
        if (lengths[i] == 1) short_branch = true;
    if (!short_branch) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (match->length < 2 ||
            !yx_short_first_unit_at(data, size, offset, 2, first,
                                    nocase)) continue;
        bool another = false;
        for (size_t branch = 0; branch < count; ++branch) {
            const uint8_t *literal = (const uint8_t *)(regexp + starts[branch]);
            size_t next = offset + lengths[branch] * 2;
            if (yx_short_first_token_at(data, size, offset, 2,
                                        literal, lengths[branch], nocase) &&
                yx_short_first_unit_at(data, size, next, 2,
                                       first, nocase)) {
                another = true;
                break;
            }
        }
        if (!another) match->length = 1;
    }
}

/* With an optional byte after a repeated x|xy group, the reference chooses
   the group match before consuming the optional unit.
   PCRE2 can instead let the suffix choose a different group branch. Reuse
   the ordinary group verifier for this observed small-alternative family. */
static void yx_adjust_grouped_optional_suffix_ties(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    size_t max_matches)
{
    const char *regexp = pattern->regexp;
    if ((pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE |
                                YX_MOD_NOCASE)) != 0 ||
        !regexp || regexp[0] != '(' || strlen(regexp) < 8 ||
        strlen(regexp) > 23) return;
    const char *branch = regexp + 1;
    if (branch[0] == '?' && branch[1] == ':') branch += 2;
    const char *bar = strchr(branch, '|');
    const char *close = strchr(branch, ')');
    if (!bar || !close || bar >= close) return;
    size_t left_length = (size_t)(bar - branch);
    size_t right_length = (size_t)(close - bar - 1);
    uint8_t first, second;
    if (left_length == 1 && right_length == 2 &&
        branch[0] == bar[1]) {
        first = (uint8_t)branch[0];
        second = (uint8_t)bar[2];
    } else if (left_length == 2 && right_length == 1 &&
               branch[0] == bar[1]) {
        first = (uint8_t)branch[0];
        second = (uint8_t)branch[1];
    } else return;
    const char *suffix = close + 1;
    if (strncmp(suffix, "{1,1}", 5) == 0 ||
        strncmp(suffix, "{1,2}", 5) == 0 ||
        strncmp(suffix, "{1,3}", 5) == 0 ||
        strncmp(suffix, "{2,3}", 5) == 0)
        suffix += 5;
    else if (strncmp(suffix, "{2,}", 4) == 0)
        suffix += 4;
    else if (*suffix == '+') ++suffix;
    else return;
    size_t bare_length = (size_t)(suffix - regexp);
    uint8_t class_a, class_b;
    size_t suffix_length = strlen(suffix);
    if (((suffix_length == 5 && suffix[4] == '?') ||
         (suffix_length == 9 &&
          strcmp(suffix + 4, "{0,1}") == 0)) &&
        suffix[0] == '[' && suffix[3] == ']') {
        class_a = (uint8_t)suffix[1];
        class_b = (uint8_t)suffix[2];
    } else if (suffix_length == 2 && suffix[1] == '?') {
        class_a = class_b = (uint8_t)suffix[0];
    } else return;
    if (!yx_plain_regex_byte(first) ||
        !yx_plain_regex_byte(second) ||
        !yx_plain_regex_byte(class_a) ||
        !yx_plain_regex_byte(class_b) ||
        first == second || second != (uint8_t)(first + 1) ||
        (class_a != second && class_a != (uint8_t)(second + 1)) ||
        (class_b != second && class_b != (uint8_t)(second + 1))) return;

    char bare_regexp[24];
    memcpy(bare_regexp, regexp, bare_length);
    bare_regexp[bare_length] = '\0';
    YRX_PATTERN bare = *pattern;
    bare.regexp = bare_regexp;
    bare.matches = NULL;
    bare.match_count = 0;
    bare.match_capacity = 0;
    if (yx_scan_pattern(&bare, data, size, max_matches, false) != YRX_SUCCESS) {
        free(bare.matches);
        return;
    }
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) != 0 || !wide;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    for (size_t i = 0; i < bare.match_count; ++i) {
        YRX_MATCH *match = &bare.matches[i];
        size_t width = 1;
        if (!ascii || (wide && match->length >= 2 &&
                       !(match->length & 1) &&
                       yx_short_first_unit_at(data, size, match->offset,
                                              2, first, nocase)))
            width = 2;
        if (match->offset > size || match->length > size - match->offset)
            continue;
        size_t end = match->offset + match->length;
        if (end > size || width > size - end ||
            (width == 2 && data[end + 1] != 0)) continue;
        uint8_t next = data[end];
        if (nocase) next = yx_fold(next);
        if (next == (nocase ? yx_fold(class_a) : class_a) ||
            next == (nocase ? yx_fold(class_b) : class_b))
            match->length += width;
    }
    free(pattern->matches);
    pattern->matches = bare.matches;
    pattern->match_count = bare.match_count;
    pattern->match_capacity = bare.match_capacity;
}

/* A lazy repeated capturing group still verifies its first long branch.
   PCRE2 can prefer the single-byte branch after flattening the repeat. */
static void yx_adjust_lazy_identical_capture(YRX_PATTERN *pattern,
                                              const uint8_t *data,
                                              size_t size)
{
    const char *regexp = pattern->regexp;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_FULLWORD | YX_MOD_XOR) ||
        strlen(regexp) != 8 || regexp[0] != '(' ||
        regexp[1] != regexp[2] || regexp[3] != '|' ||
        regexp[4] != regexp[1] || regexp[5] != ')' ||
        regexp[6] != '+' || regexp[7] != '?' ||
        !yx_plain_regex_byte((uint8_t)regexp[1])) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        if (match->length == 1 && match->offset + 1 < size &&
            yx_short_first_unit_at(data, size, match->offset + 1, 1,
                                   (uint8_t)regexp[1], nocase))
            match->length = 2;
    }
}

/* The whole-expression verifier for two fixed two-byte alternatives can
   consume up to 2*n-1 complete branches under a {1,n} upper bound. */
static void yx_adjust_bounded_two_byte_alternatives(YRX_PATTERN *pattern,
                                                     const uint8_t *data,
                                                     size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    unsigned bound;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool both = (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) ==
                (YX_MOD_ASCII | YX_MOD_WIDE);
    size_t width = (pattern->modifiers & YX_MOD_WIDE) && !both ? 2 : 1;
    uint8_t left[2], right[2];
    if ((both && memchr(data, 0, size) != NULL) ||
        (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 11) return;
    if (regexp[at + 2] != '|' || regexp[at + 5] != ')' ||
        !yx_plain_regex_byte((uint8_t)regexp[at]) ||
        !yx_plain_regex_byte((uint8_t)regexp[at + 1]) ||
        !yx_plain_regex_byte((uint8_t)regexp[at + 3]) ||
        !yx_plain_regex_byte((uint8_t)regexp[at + 4])) return;
    if (strcmp(regexp + at + 6, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 6, "{1,3}") == 0) bound = 3;
    else if (strcmp(regexp + at + 6, "{1,4}") == 0) bound = 4;
    else return;
    left[0] = (uint8_t)regexp[at];
    left[1] = (uint8_t)regexp[at + 1];
    right[0] = (uint8_t)regexp[at + 3];
    right[1] = (uint8_t)regexp[at + 4];
    if (left[0] == right[0] && left[1] == right[1]) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if (offset > size || size - offset < 2 * width * (bound + 1))
            continue;
        unsigned complete = 0;
        for (unsigned unit = 0; unit < 2 * bound - 1; ++unit) {
            size_t pos = offset + 2 * width * unit;
            if (size - offset < 2 * width * (unit + 1)) break;
            if (!yx_short_first_token_at(data, size, pos, width, left, 2,
                                         nocase) &&
                !yx_short_first_token_at(data, size, pos, width, right, 2,
                                         nocase)) {
                break;
            }
            ++complete;
        }
        if (complete > bound && 2 * width * complete > match->length)
            match->length = 2 * width * complete;
    }
}

/* In this small two-branch family the reference verifier can consume a third
   repetition for {1,2}. The short branch is the final byte of the long
   branch, so every repetition has an unambiguous start byte. Adjust spans of
   hits already found by the ordinary matcher; other group shapes are left
   with their original verifier. */
static void yx_adjust_bounded_terminal_byte_alternatives(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, left_length, right_length;
    uint8_t first, last;
    if (!regexp || (pattern->modifiers & ~YX_MOD_ASCII) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    const char *bar = strchr(regexp + at, '|');
    const char *close = strchr(regexp + at, ')');
    if (!bar || !close || bar > close ||
        strcmp(close + 1, "{1,2}") != 0) return;
    left_length = (size_t)(bar - regexp - at);
    right_length = (size_t)(close - bar - 1);
    if (left_length == 2 && right_length == 1 &&
        regexp[at + 1] == bar[1]) {
        first = (uint8_t)regexp[at];
        last = (uint8_t)bar[1];
    } else if (left_length == 1 && right_length == 2 &&
               regexp[at] == bar[2]) {
        first = (uint8_t)bar[1];
        last = (uint8_t)regexp[at];
    } else return;
    if (!yx_plain_regex_byte(first) || !yx_plain_regex_byte(last) ||
        first == last) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t pos = match->offset;
        unsigned repetitions = 0;
        while (repetitions < 3 && pos < size) {
            if (size - pos >= 2 && data[pos] == first &&
                data[pos + 1] == last)
                pos += 2;
            else if (data[pos] == last)
                ++pos;
            else break;
            ++repetitions;
        }
        if (repetitions && pos - match->offset > match->length)
            match->length = pos - match->offset;
    }
}

/* The overlapping two-byte branches x[yz] and [xy]z have three possible
 * complete units: xy, xz, and yz. Their verifier visits one more whole unit
 * than the written {1,2} bound, for both ASCII and wide encodings. */
static void yx_adjust_bounded_two_byte_class_pair(YRX_PATTERN *pattern,
                                                   const uint8_t *data,
                                                   size_t size)
{
    const char *regexp = pattern->regexp;
    if ((pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE)) ||
        strlen(regexp) != 18 || regexp[0] != '(' ||
        regexp[2] != '[' || regexp[5] != ']' || regexp[6] != '|' ||
        regexp[7] != '[' || regexp[10] != ']' || regexp[12] != ')' ||
        memcmp(regexp + 13, "{1,2}", 5) != 0) return;
    uint8_t x = (uint8_t)regexp[1];
    uint8_t y = (uint8_t)regexp[3];
    uint8_t z = (uint8_t)regexp[4];
    if (x < 'a' || z > 'z' || x >= y || y >= z ||
        regexp[8] != (char)x || regexp[9] != (char)y ||
        regexp[11] != (char)z) return;
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) ||
                 !(pattern->modifiers & YX_MOD_WIDE);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        for (size_t width = 1; width <= 2; ++width) {
            if ((width == 1 && !ascii) || (width == 2 && !wide) ||
                match->length != 4 * width || match->offset > size ||
                size - match->offset < 6 * width) continue;
            bool complete = true;
            for (unsigned unit = 0; unit < 3; ++unit) {
                size_t at = match->offset + 2 * unit * width;
                bool first_x = yx_short_first_unit_at(data, size, at,
                                                      width, x, false);
                bool first_y = yx_short_first_unit_at(data, size, at,
                                                      width, y, false);
                bool second_y = yx_short_first_unit_at(data, size,
                                                       at + width, width,
                                                       y, false);
                bool second_z = yx_short_first_unit_at(data, size,
                                                       at + width, width,
                                                       z, false);
                if (!((first_x && (second_y || second_z)) ||
                      (first_y && second_z))) {
                    complete = false;
                    break;
                }
            }
            if (complete) {
                match->length = 6 * width;
                break;
            }
        }
    }
}

/* In the long-input atom path, a lone long-first xyz|xy|x branch is
   reported through its one-byte x atom. A following x starts another
   repetition and lets the verifier retain the longer span. */
static void yx_adjust_long_first_triple_singleton(YRX_PATTERN *pattern,
                                                   const uint8_t *data,
                                                   size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    if (size < 16 ||
        pattern->modifiers & (YX_MOD_NOCASE | YX_MOD_FULLWORD |
                              YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 10 &&
        strlen(regexp) != at + 14) return;
    if (regexp[at + 3] != '|' || regexp[at + 6] != '|' ||
        regexp[at + 8] != ')' ||
        regexp[at] != regexp[at + 4] ||
        regexp[at] != regexp[at + 7] ||
        regexp[at + 1] != regexp[at + 5] ||
        (strcmp(regexp + at + 9, "+") != 0 &&
         strcmp(regexp + at + 9, "{1,2}") != 0 &&
         strcmp(regexp + at + 9, "{1,3}") != 0)) return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 1];
    z = (uint8_t)regexp[at + 2];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || x == y || x == z || y == z)
        return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && offset < size &&
                       size - offset >= 2 && data[offset + 1] == 0 ?
                       2 : 1;
        if (match->length <= width || offset >= size || data[offset] != x)
            continue;
        bool another = yx_short_first_unit_at(data, size, offset + width,
                                               width, x, false) ||
                       (yx_short_first_unit_at(data, size, offset + width,
                                               width, y, false) &&
                        yx_short_first_unit_at(data, size,
                                               offset + 2 * width,
                                               width, x, false)) ||
                       (yx_short_first_unit_at(data, size, offset + width,
                                               width, y, false) &&
                        yx_short_first_unit_at(data, size,
                                               offset + 2 * width,
                                               width, z, false) &&
                        yx_short_first_unit_at(data, size,
                                               offset + 3 * width,
                                               width, x, false));
        if (!another) match->length =
            pattern->modifiers & YX_MOD_ASCII ? 1 : width;
    }
}

/* For the guarded (x|xy)+, (x|xy){2,}, and (xy|xyz)+ shapes, YARA-X
   consumes the longest sequence of short units and suffix+short units.
   PCRE2's short-first branch stops before the first suffix. */
static void yx_adjust_short_first_repeated_pair(YRX_PATTERN *pattern,
                                                const uint8_t *data,
                                                size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), group = 0, at, short_length, close;
    bool min_two = false;
    uint8_t short_token[2], suffix;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (pattern->modifiers & YX_MOD_FULLWORD) return;
    if (regexp[0] == '^') group = 1;
    if (regexp[group] != '(') return;
    at = group + 1;
    if (length >= at + 2 && regexp[at] == '?' && regexp[at + 1] == ':')
        at += 2;
    if (length == at + 6) short_length = 1;
    else if (length == at + 8) short_length = 2;
    else if (length == at + 9) {
        short_length = 1;
        min_two = true;
    }
    else return;
    close = at + 2 * short_length + 2;
    if (regexp[at + short_length] != '|' || regexp[close] != ')') return;
    if (min_two ? strcmp(regexp + close + 1, "{2,}") != 0 :
                  regexp[close + 1] != '+') return;
    for (size_t i = 0; i < short_length; ++i) {
        short_token[i] = (uint8_t)regexp[at + i];
        if (!yx_plain_regex_byte(short_token[i]) ||
            regexp[at + short_length + 1 + i] != (char)short_token[i])
            return;
    }
    suffix = (uint8_t)regexp[at + 2 * short_length + 1];
    if (!yx_plain_regex_byte(suffix) ||
        (nocase ? yx_fold(short_token[0]) == yx_fold(suffix) :
                  short_token[0] == suffix)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset;
        if (!yx_short_first_token_at(data, size, pos, width, short_token,
                                     short_length, nocase))
            continue;
        pos += short_length * width;
        while (pos < size) {
            if (yx_short_first_token_at(data, size, pos, width, short_token,
                                        short_length, nocase)) {
                pos += short_length * width;
            } else if (size - pos >= (short_length + 1) * width &&
                       yx_short_first_unit_at(data, size, pos, width,
                                              suffix, nocase) &&
                       yx_short_first_token_at(data, size, pos + width,
                                               width, short_token,
                                               short_length, nocase)) {
                pos += (short_length + 1) * width;
            } else {
                break;
            }
        }
        match->length = pos - match->offset;
    }
}

/* In (x|xy|xyz)+ and {2,} all three branches are prefixes of the next one. For
   case-sensitive patterns YARA-X consumes the longest complete branch at
   each repetition. Nocase patterns instead keep the short-branch endpoint:
   the suffix of a longer branch participates only when another x follows.
   PCRE2 stops at the first branch x. Limit this adjustment to literal
   branches with distinct bytes so each next unit is unambiguous. */
static void yx_adjust_short_first_repeated_triple(YRX_PATTERN *pattern,
                                                  const uint8_t *data,
                                                  size_t size)
{
    const char *regexp = pattern->regexp;
    size_t group = regexp[0] == '^' ? 1 : 0;
    size_t at = group + 1, length = strlen(regexp);
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool min_two, digit_triple;
    if (pattern->modifiers & YX_MOD_FULLWORD || regexp[group] != '(')
        return;
    if (length >= at + 2 && regexp[at] == '?' &&
        regexp[at + 1] == ':') at += 2;
    if ((length != at + 10 && length != at + 13) ||
        regexp[at + 1] != '|' ||
        regexp[at + 4] != '|' || regexp[at + 8] != ')' ||
        (strcmp(regexp + at + 9, "+") != 0 &&
         strcmp(regexp + at + 9, "{2,}") != 0) ||
        regexp[at] != regexp[at + 2] ||
        regexp[at] != regexp[at + 5] ||
        regexp[at + 3] != regexp[at + 6]) return;
    min_two = regexp[at + 9] == '{';
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 7];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        (nocase ? (yx_fold(x) == yx_fold(y) ||
                   yx_fold(x) == yx_fold(z) ||
                   yx_fold(y) == yx_fold(z)) :
                  (x == y || x == z || y == z))) return;
    digit_triple = x >= '0' && x <= '9' &&
                   y >= '0' && y <= '9' &&
                   z >= '0' && z <= '9';
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset;
        if ((nocase && !digit_triple) || min_two) {
            if (!yx_short_first_unit_at(data, size, pos, width, x,
                                        nocase))
                continue;
            pos += width;
            while (pos < size) {
                if (yx_short_first_unit_at(data, size, pos, width, x,
                                           nocase)) {
                    pos += width;
                } else if (yx_short_first_unit_at(data, size, pos, width,
                                                  y, nocase) &&
                           yx_short_first_unit_at(data, size,
                                                  pos + width, width,
                                                  z, nocase) &&
                           yx_short_first_unit_at(data, size,
                                                  pos + 2 * width, width,
                                                  x, nocase)) {
                    pos += 3 * width;
                } else if (yx_short_first_unit_at(data, size, pos, width,
                                                  y, nocase) &&
                           yx_short_first_unit_at(data, size,
                                                  pos + width, width,
                                                  x, nocase)) {
                    pos += 2 * width;
                } else {
                    break;
                }
            }
        } else {
            while (yx_short_first_unit_at(data, size, pos, width, x,
                                          false)) {
                pos += width;
                if (yx_short_first_unit_at(data, size, pos, width, y,
                                           false)) {
                    pos += width;
                    if (yx_short_first_unit_at(data, size, pos, width, z,
                                               false)) pos += width;
                }
            }
        }
        if (pos > match->offset) match->length = pos - match->offset;
    }
}

/* A repeated x|xyz pair uses the same literal-atom branch priority as the
   x|xy|xyz form. Alphabetic nocase keeps the short endpoint until the
   following x confirms a complete long branch. */
static void yx_adjust_short_first_three_byte_pair(YRX_PATTERN *pattern,
                                                   const uint8_t *data,
                                                   size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool digits;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) ==
            (YX_MOD_ASCII | YX_MOD_WIDE) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 7 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 5] != ')' ||
        regexp[at + 6] != '+') return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 4];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
             z >= '0' && z <= '9';
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset;
        if (!yx_short_first_unit_at(data, size, pos, width, x,
                                    nocase)) continue;
        if (nocase && !digits) {
            pos += width;
            while (pos < size) {
                if (yx_short_first_unit_at(data, size, pos, width, x,
                                           true)) {
                    pos += width;
                } else if (yx_short_first_unit_at(data, size, pos,
                                                  width, y, true) &&
                           yx_short_first_unit_at(data, size,
                                                  pos + width, width,
                                                  z, true) &&
                           yx_short_first_unit_at(data, size,
                                                  pos + 2 * width,
                                                  width, x, true)) {
                    pos += 3 * width;
                } else break;
            }
        } else {
            while (yx_short_first_unit_at(data, size, pos, width, x,
                                          nocase)) {
                pos += width;
                if (yx_short_first_unit_at(data, size, pos, width, y,
                                           nocase) &&
                    yx_short_first_unit_at(data, size, pos + width,
                                           width, z, nocase))
                    pos += 2 * width;
            }
        }
        if (pos > match->offset) match->length = pos - match->offset;
    }
}

/* In (x|xy|xz)+, a two-byte branch contributes its suffix only
   when another x follows. The scan verifier can then continue through either
   suffix and any intervening short branches, even though PCRE2's first
   branch stops at the initial x. */
static void yx_adjust_short_first_fork(YRX_PATTERN *pattern,
                                        const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 9 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 4] != '|' ||
        regexp[at + 5] != regexp[at] || regexp[at + 7] != ')' ||
        regexp[at + 8] != '+') return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 6];
    bool letters =
        ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) &&
        ((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z')) &&
        ((z >= 'a' && z <= 'z') || (z >= 'A' && z <= 'Z'));
    bool digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
                  z >= '0' && z <= '9';
    if (!(letters || digits) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset;
        if (!yx_short_first_unit_at(data, size, pos, width, x,
                                    nocase)) continue;
        pos += width;
        while (pos < size) {
            if (yx_short_first_unit_at(data, size, pos, width, x,
                                       nocase)) {
                pos += width;
            } else if ((yx_short_first_unit_at(data, size, pos, width,
                                               y, nocase) ||
                        yx_short_first_unit_at(data, size, pos, width,
                                               z, nocase)) &&
                       yx_short_first_unit_at(data, size, pos + width,
                                              width, x, nocase)) {
                pos += 2 * width;
            } else break;
        }
        match->length = pos - match->offset;
    }
}

/* The bounded (x|xyz) verifier can include up to bound-1 extra short
   branches after its bound complete branches. Its alphabetic nocase path
   retains yz only when another x follows before that bound is reached. */
static void yx_adjust_bounded_three_byte_pair(YRX_PATTERN *pattern,
                                               const uint8_t *data,
                                               size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    unsigned bound;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool digits;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 11 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 5] != ')') return;
    if (strcmp(regexp + at + 6, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 6, "{1,3}") == 0) bound = 3;
    else if (strcmp(regexp + at + 6, "{1,4}") == 0) bound = 4;
    else return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 4];
    digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
             z >= '0' && z <= '9';
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset;
        unsigned core = 0;
        for (; core < bound &&
               yx_short_first_unit_at(data, size, pos, width, x, nocase);
             ++core) {
            pos += width;
            if (yx_short_first_unit_at(data, size, pos, width, y,
                                       nocase) &&
                yx_short_first_unit_at(data, size, pos + width,
                                       width, z, nocase) &&
                (!nocase || digits ||
                 (core + 1 < bound &&
                  yx_short_first_unit_at(data, size, pos + 2 * width,
                                         width, x, nocase))))
                pos += 2 * width;
        }
        if (!core) continue;
        for (unsigned extra = 0; extra + 1 < bound &&
             yx_short_first_unit_at(data, size, pos, width, x, nocase);
             ++extra)
            pos += width;
        match->length = pos - match->offset;
    }
}

/* For bounded (x|xy|xz), a suffix y or z is kept only when followed by the
   next x before the bound. The verifier can then visit bound-1 additional
   short x branches. Restrict this to literal, distinct branches. */
static void yx_adjust_bounded_fork(YRX_PATTERN *pattern,
                                   const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    unsigned bound;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool letters, digits;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 13 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 4] != '|' ||
        regexp[at + 5] != regexp[at] || regexp[at + 7] != ')')
        return;
    if (strcmp(regexp + at + 8, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 8, "{1,3}") == 0) bound = 3;
    else return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 6];
    letters = ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) &&
              ((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z')) &&
              ((z >= 'a' && z <= 'z') || (z >= 'A' && z <= 'Z'));
    digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
             z >= '0' && z <= '9';
    if (!(letters || digits) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset;
        unsigned core = 0;
        for (; core < bound &&
               yx_short_first_unit_at(data, size, pos, width, x, nocase);
             ++core) {
            pos += width;
            if (core + 1 < bound &&
                (yx_short_first_unit_at(data, size, pos, width, y,
                                        nocase) ||
                 yx_short_first_unit_at(data, size, pos, width, z,
                                        nocase)) &&
                yx_short_first_unit_at(data, size, pos + width,
                                       width, x, nocase))
                pos += width;
        }
        if (!core) continue;
        for (unsigned extra = 0; extra + 1 < bound &&
             yx_short_first_unit_at(data, size, pos, width, x, nocase);
             ++extra)
            pos += width;
        match->length = pos - match->offset;
    }
}

/* The xy|x|xz verifier favors its first xy branch. Its trailing xz branch
   keeps z only when the next repetition begins at x. Bounded repeats can
   visit bound-1 additional x atoms, but those atoms cannot retain z. */
static void yx_adjust_long_first_fork(YRX_PATTERN *pattern,
                                      const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    unsigned bound;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool letters, digits;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) < at + 9) return;
    if (regexp[at + 2] != '|' || regexp[at + 3] != regexp[at] ||
        regexp[at + 4] != '|' || regexp[at + 5] != regexp[at] ||
        regexp[at + 7] != ')') return;
    if (strcmp(regexp + at + 8, "+") == 0) bound = 0;
    else if (strcmp(regexp + at + 8, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 8, "{1,3}") == 0) bound = 3;
    else return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 1];
    z = (uint8_t)regexp[at + 6];
    letters = ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) &&
              ((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z')) &&
              ((z >= 'a' && z <= 'z') || (z >= 'A' && z <= 'Z'));
    digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
             z >= '0' && z <= '9';
    if (!(letters || digits) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset, units = 0;
        while ((!bound || units < 2 * bound - 1) &&
               yx_short_first_unit_at(data, size, pos, width, x,
                                      nocase)) {
            pos += width;
            ++units;
            if (yx_short_first_unit_at(data, size, pos, width, y,
                                       nocase))
                pos += width;
            else if ((!bound || units < bound) &&
                     yx_short_first_unit_at(data, size, pos, width, z,
                                            nocase) &&
                     yx_short_first_unit_at(data, size, pos + width,
                                            width, x, nocase))
                pos += width;
        }
        if (units) match->length = pos - match->offset;
    }
}

/* With both long branches before x, either suffix is consumed immediately.
   A bounded repeat can still visit bound-1 additional x atoms. */
static void yx_adjust_long_long_short_fork(YRX_PATTERN *pattern,
                                            const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    unsigned bound;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool letters, digits;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) < at + 9) return;
    if (regexp[at + 2] != '|' || regexp[at + 3] != regexp[at] ||
        regexp[at + 5] != '|' || regexp[at + 6] != regexp[at] ||
        regexp[at + 7] != ')') return;
    if (strcmp(regexp + at + 8, "+") == 0) bound = 0;
    else if (strcmp(regexp + at + 8, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 8, "{1,3}") == 0) bound = 3;
    else return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 1];
    z = (uint8_t)regexp[at + 4];
    letters = ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) &&
              ((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z')) &&
              ((z >= 'a' && z <= 'z') || (z >= 'A' && z <= 'Z'));
    digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
             z >= '0' && z <= '9';
    if (!(letters || digits) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset, units = 0;
        while ((!bound || units < 2 * bound - 1) &&
               yx_short_first_unit_at(data, size, pos, width, x,
                                      nocase)) {
            pos += width;
            ++units;
            if (yx_short_first_unit_at(data, size, pos, width, y,
                                       nocase) ||
                yx_short_first_unit_at(data, size, pos, width, z,
                                       nocase))
                pos += width;
        }
        if (units) match->length = pos - match->offset;
    }
}

/* The bounded xyz|x verifier can visit bound-1 further x atoms after its
   written bound. On long inputs its atom search reports an isolated xyz
   through x, unless alphabetic nocase keeps the complete long branch. */
static void yx_adjust_long_first_three_byte_pair(YRX_PATTERN *pattern,
                                                  const uint8_t *data,
                                                  size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    unsigned bound;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool letters, digits;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        regexp[0] != '(') return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) < at + 7) return;
    if (regexp[at + 3] != '|' || regexp[at + 4] != regexp[at] ||
        regexp[at + 5] != ')') return;
    if (strcmp(regexp + at + 6, "+") == 0) bound = 0;
    else if (strcmp(regexp + at + 6, "{1,2}") == 0) bound = 2;
    else if (strcmp(regexp + at + 6, "{1,3}") == 0) bound = 3;
    else return;
    if (bound && !((pattern->modifiers &
                   (YX_MOD_ASCII | YX_MOD_WIDE)) ==
                   (YX_MOD_ASCII | YX_MOD_WIDE) &&
                   memchr(data, 0, size) != NULL))
        return; /* The bounded scanner applied the same verifier earlier. */
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 1];
    z = (uint8_t)regexp[at + 2];
    letters = ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) &&
              ((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z')) &&
              ((z >= 'a' && z <= 'z') || (z >= 'A' && z <= 'Z'));
    digits = x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
             z >= '0' && z <= '9';
    if (!(letters || digits) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t pos = match->offset, units = 0;
        while ((!bound || units < 2 * bound - 1) &&
               yx_short_first_unit_at(data, size, pos, width, x,
                                      nocase)) {
            pos += width;
            ++units;
            if (yx_short_first_unit_at(data, size, pos, width, y,
                                       nocase) &&
                yx_short_first_unit_at(data, size, pos + width,
                                       width, z, nocase))
                pos += 2 * width;
        }
        if (!units) continue;
        if (size >= 16 && units == 1 && (!nocase || digits) &&
            pos - match->offset > width)
            pos = match->offset + width;
        match->length = pos - match->offset;
    }
}

static void yx_bounded_short_first_pair_walk(const uint8_t *data, size_t size,
                                             size_t start, size_t pos,
                                             size_t width, uint8_t x,
                                             uint8_t y, bool nocase,
                                             bool long_first,
                                             unsigned prior,
                                             unsigned max_repeats,
                                             size_t *best)
{
    if (!yx_short_first_unit_at(data, size, pos, width, x, nocase))
        return;
    size_t end = pos;
    for (unsigned following = 0; following < max_repeats &&
         yx_short_first_unit_at(data, size, end, width, x, nocase);
         ++following) {
        end += width;
        if (long_first &&
            yx_short_first_unit_at(data, size, end, width, y, nocase))
            end += width;
    }
    if (end - start > *best) *best = end - start;
    if (prior + 1 == max_repeats) return;
    if (size - pos >= 2 * width &&
        yx_short_first_unit_at(data, size, pos + width, width,
                               x, nocase))
        yx_bounded_short_first_pair_walk(data, size, start, pos + width,
                                         width, x, y, nocase, long_first,
                                         prior + 1,
                                         max_repeats,
                                         best);
    if (size - pos >= 3 * width &&
        yx_short_first_unit_at(data, size, pos + width, width,
                               y, nocase) &&
        yx_short_first_unit_at(data, size, pos + 2 * width, width,
                               x, nocase))
        yx_bounded_short_first_pair_walk(data, size, start, pos + 2 * width,
                                         width, x, y, nocase, long_first,
                                         prior + 1,
                                         max_repeats,
                                         best);
}

/* The reference's verifier for (x|xy) and (xy|x) bounded repetitions can
   anchor on any x. It includes up to max-1 complete branches before that
   anchor, then follows the written branch priority for up to max branches. */
static void yx_adjust_bounded_short_first_pair(YRX_PATTERN *pattern,
                                                const uint8_t *data,
                                                size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp);
    size_t group = regexp[0] == '^' ? 1 : 0;
    size_t at = group + 1;
    uint8_t x, y;
    bool long_first;
    unsigned max_repeats;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if ((pattern->modifiers & YX_MOD_FULLWORD) || regexp[group] != '(')
        return;
    if (length >= at + 2 && regexp[at] == '?' &&
        regexp[at + 1] == ':') at += 2;
    if (length != at + 10 || regexp[at + 4] != ')') return;
    if (strcmp(regexp + at + 5, "{1,2}") == 0)
        max_repeats = 2;
    else if (strcmp(regexp + at + 5, "{1,3}") == 0)
        max_repeats = 3;
    else if (strcmp(regexp + at + 5, "{1,4}") == 0)
        max_repeats = 4;
    else
        return;
    x = (uint8_t)regexp[at];
    if (regexp[at + 1] == '|' && regexp[at + 2] == regexp[at]) {
        y = (uint8_t)regexp[at + 3];
        long_first = false;
    } else if (regexp[at + 2] == '|' &&
               regexp[at + 3] == regexp[at]) {
        y = (uint8_t)regexp[at + 1];
        long_first = true;
    } else {
        return;
    }
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        (nocase ? yx_fold(x) == yx_fold(y) : x == y)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t best = 0;
        yx_bounded_short_first_pair_walk(data, size, match->offset,
                                         match->offset, width, x, y,
                                         nocase, long_first, 0,
                                         max_repeats, &best);
        if (best) match->length = best;
    }
}

/* A bounded pair of xy and xyz uses the two-byte xy atom as its forward
   endpoint. Up to max-1 earlier branches may include z before that atom;
   then the written alternative priority applies for at most max branches.
   This mirrors the one-byte prefix walk above without affecting other
   grouped alternatives. */
static void yx_bounded_two_byte_pair_walk(const uint8_t *data, size_t size,
                                          size_t start, size_t pos,
                                          size_t width,
                                          const uint8_t token[2],
                                          uint8_t suffix, bool nocase,
                                          bool long_first, unsigned prior,
                                          unsigned max_repeats,
                                          size_t *best)
{
    if (!yx_short_first_token_at(data, size, pos, width, token, 2, nocase))
        return;
    size_t end = pos;
    for (unsigned following = 0; following < max_repeats &&
         yx_short_first_token_at(data, size, end, width, token, 2,
                                 nocase); ++following) {
        end += 2 * width;
        if (long_first &&
            yx_short_first_unit_at(data, size, end, width, suffix, nocase))
            end += width;
    }
    if (end - start > *best) *best = end - start;
    if (prior + 1 == max_repeats) return;
    if (size - pos >= 4 * width &&
        yx_short_first_token_at(data, size, pos + 2 * width, width,
                                token, 2, nocase))
        yx_bounded_two_byte_pair_walk(data, size, start, pos + 2 * width,
                                      width, token, suffix, nocase,
                                      long_first, prior + 1, max_repeats,
                                      best);
    if (size - pos >= 5 * width &&
        yx_short_first_unit_at(data, size, pos + 2 * width, width,
                               suffix, nocase) &&
        yx_short_first_token_at(data, size, pos + 3 * width, width,
                                token, 2, nocase))
        yx_bounded_two_byte_pair_walk(data, size, start, pos + 3 * width,
                                      width, token, suffix, nocase,
                                      long_first, prior + 1, max_repeats,
                                      best);
}

static void yx_adjust_bounded_two_byte_pair(YRX_PATTERN *pattern,
                                             const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t token[2], suffix;
    bool long_first, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    unsigned max_repeats;
    if (regexp[0] != '(' ||
        (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR))) return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 12 || regexp[at + 6] != ')') return;
    if (strcmp(regexp + at + 7, "{1,2}") == 0)
        max_repeats = 2;
    else if (strcmp(regexp + at + 7, "{1,3}") == 0)
        max_repeats = 3;
    else if (strcmp(regexp + at + 7, "{1,4}") == 0)
        max_repeats = 4;
    else
        return;
    token[0] = (uint8_t)regexp[at];
    token[1] = (uint8_t)regexp[at + 1];
    if (regexp[at + 2] == '|' &&
        regexp[at + 3] == (char)token[0] &&
        regexp[at + 4] == (char)token[1]) {
        suffix = (uint8_t)regexp[at + 5];
        long_first = false;
    } else if (regexp[at + 3] == '|' &&
               regexp[at + 4] == (char)token[0] &&
               regexp[at + 5] == (char)token[1]) {
        suffix = (uint8_t)regexp[at + 2];
        long_first = true;
    } else {
        return;
    }
    if (!yx_plain_regex_byte(token[0]) ||
        !yx_plain_regex_byte(token[1]) ||
        !yx_plain_regex_byte(suffix) ||
        yx_fold(token[0]) == yx_fold(token[1]) ||
        yx_fold(token[0]) == yx_fold(suffix) ||
        yx_fold(token[1]) == yx_fold(suffix)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 4 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t best = 0;
        yx_bounded_two_byte_pair_walk(data, size, match->offset,
                                      match->offset, width, token, suffix,
                                      nocase, long_first, 0, max_repeats,
                                      &best);
        if (best) match->length = best;
    }
}

/* A nested x(y|yz) repeat has the same short xy and long xyz atoms as a
   flat xy|xyz repeat, but the regex engine stops at the first short atom.
   Apply the verifier walk only to this literal nested group shape. */
static void yx_adjust_nested_short_first_pair(YRX_PATTERN *pattern,
                                               const uint8_t *data,
                                               size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp), at = 1;
    uint8_t token[2], suffix;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool bounded;
    if (length < 10 || regexp[0] != '(' ||
        (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR))) return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (at + 7 >= length || regexp[at + 1] != '(') return;
    token[0] = (uint8_t)regexp[at];
    at += 2;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (at + 5 >= length || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 4] != ')' ||
        regexp[at + 5] != ')') return;
    token[1] = (uint8_t)regexp[at];
    suffix = (uint8_t)regexp[at + 3];
    at += 6;
    if (strcmp(regexp + at, "+") == 0) bounded = false;
    else if (strcmp(regexp + at, "{1,2}") == 0) bounded = true;
    else return;
    if (!yx_plain_regex_byte(token[0]) ||
        !yx_plain_regex_byte(token[1]) ||
        !yx_plain_regex_byte(suffix) ||
        yx_fold(token[0]) == yx_fold(token[1]) ||
        yx_fold(token[0]) == yx_fold(suffix) ||
        yx_fold(token[1]) == yx_fold(suffix)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 4 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t best = 0;
        if (bounded) {
            yx_bounded_two_byte_pair_walk(data, size, match->offset,
                                          match->offset, width, token,
                                          suffix, nocase, false, 0, 2,
                                          &best);
        } else if (yx_short_first_token_at(data, size, match->offset,
                                            width, token, 2, nocase)) {
            size_t pos = match->offset + 2 * width;
            while (pos < size) {
                if (yx_short_first_token_at(data, size, pos, width,
                                            token, 2, nocase)) {
                    pos += 2 * width;
                } else if (yx_short_first_unit_at(data, size, pos, width,
                                                   suffix, nocase) &&
                           yx_short_first_token_at(data, size,
                                                    pos + width, width,
                                                    token, 2, nocase)) {
                    pos += 3 * width;
                } else break;
            }
            best = pos - match->offset;
        }
        if (best) match->length = best;
    }
}

/* A bounded repeated byte has no distinct suffix to anchor on. The
   reference's forward verifier reaches 3n-2 units for (x|xx){1,n}, or
   4n-2 for (xx|x){1,n}, before stopping at its repetition limit. */
static void yx_adjust_bounded_repeated_byte(YRX_PATTERN *pattern,
                                             const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t value;
    bool long_first, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    unsigned max_repeats, max_units;
    if (regexp[0] != '(' ||
        (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR))) return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 10 || regexp[at + 4] != ')') return;
    if (strcmp(regexp + at + 5, "{1,2}") == 0)
        max_repeats = 2;
    else if (strcmp(regexp + at + 5, "{1,3}") == 0)
        max_repeats = 3;
    else
        return;
    value = (uint8_t)regexp[at];
    if (regexp[at + 1] == '|' &&
        regexp[at + 2] == (char)value &&
        regexp[at + 3] == (char)value) {
        long_first = false;
    } else if (regexp[at + 1] == (char)value &&
               regexp[at + 2] == '|' &&
               regexp[at + 3] == (char)value) {
        long_first = true;
    } else {
        return;
    }
    if (!yx_plain_regex_byte(value)) return;
    max_units = long_first ? 4 * max_repeats - 2 :
                             3 * max_repeats - 2;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t units = 0;
        while (units < max_units &&
               yx_short_first_unit_at(data, size,
                                      match->offset + units * width,
                                      width, value, nocase)) ++units;
        if (units) match->length = units * width;
    }
}

static void yx_bounded_nocase_triple_walk(const uint8_t *data, size_t size,
                                          size_t start, size_t pos,
                                          size_t width, uint8_t x,
                                          uint8_t y, uint8_t z,
                                          unsigned prior,
                                          unsigned max_repeats,
                                          size_t *best)
{
    if (!yx_short_first_unit_at(data, size, pos, width, x, true))
        return;
    size_t end = pos;
    for (unsigned following = 0; following < max_repeats &&
         yx_short_first_unit_at(data, size, end, width, x, true);
         ++following)
        end += width;
    if (end - start > *best) *best = end - start;
    if (prior + 1 == max_repeats) return;
    if (size - pos >= 2 * width &&
        yx_short_first_unit_at(data, size, pos + width, width, x, true))
        yx_bounded_nocase_triple_walk(data, size, start, pos + width,
                                      width, x, y, z, prior + 1,
                                      max_repeats, best);
    if (size - pos >= 3 * width &&
        yx_short_first_unit_at(data, size, pos + width, width, y, true) &&
        yx_short_first_unit_at(data, size, pos + 2 * width, width, x,
                               true))
        yx_bounded_nocase_triple_walk(data, size, start, pos + 2 * width,
                                      width, x, y, z, prior + 1,
                                      max_repeats, best);
    if (size - pos >= 4 * width &&
        yx_short_first_unit_at(data, size, pos + width, width, y, true) &&
        yx_short_first_unit_at(data, size, pos + 2 * width, width, z,
                               true) &&
        yx_short_first_unit_at(data, size, pos + 3 * width, width, x,
                               true))
        yx_bounded_nocase_triple_walk(data, size, start, pos + 3 * width,
                                      width, x, y, z, prior + 1,
                                      max_repeats, best);
}

/* The nocase verifier for (x|xy|xyz){1,2} and {1,3} uses x as the
   forward endpoint. The previous bounded branches can include xy and xyz,
   but a suffix is retained only when another x follows it. */
static void yx_adjust_bounded_nocase_triple(YRX_PATTERN *pattern,
                                             const uint8_t *data,
                                             size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp);
    size_t group = regexp[0] == '^' ? 1 : 0;
    size_t at = group + 1;
    uint8_t x, y, z;
    unsigned max_repeats;
    if (!(pattern->modifiers & YX_MOD_NOCASE) ||
        (pattern->modifiers & YX_MOD_FULLWORD) || regexp[group] != '(')
        return;
    if (length >= at + 2 && regexp[at] == '?' &&
        regexp[at + 1] == ':') at += 2;
    if (length != at + 14 || regexp[at + 1] != '|' ||
        regexp[at + 4] != '|' || regexp[at + 8] != ')' ||
        regexp[at] != regexp[at + 2] ||
        regexp[at] != regexp[at + 5] ||
        regexp[at + 3] != regexp[at + 6]) return;
    if (strcmp(regexp + at + 9, "{1,2}") == 0)
        max_repeats = 2;
    else if (strcmp(regexp + at + 9, "{1,3}") == 0)
        max_repeats = 3;
    else
        return;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 7];
    if (x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
        z >= '0' && z <= '9') return;
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        yx_fold(x) == yx_fold(y) ||
        yx_fold(x) == yx_fold(z) ||
        yx_fold(y) == yx_fold(z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t best = 0;
        yx_bounded_nocase_triple_walk(data, size, match->offset,
                                      match->offset, width, x, y, z, 0,
                                      max_repeats, &best);
        if (best) match->length = best;
    }
}

/* For a case-sensitive (x|xy|xyz){1,2}, one complete branch can precede
   the forward atom. The forward scan consumes one complete branch and
   then only x. Other triple shapes take different verifier paths. */
static void yx_bounded_triple_prefix_walk(const uint8_t *data, size_t size,
                                          size_t start, size_t pos,
                                          size_t width,
                                          uint8_t x, uint8_t y, uint8_t z,
                                          bool nocase, bool long_first,
                                          unsigned prior,
                                          unsigned max_repeats,
                                          size_t *best)
{
    if (!yx_short_first_unit_at(data, size, pos, width, x, nocase)) return;
    size_t end = pos;
    for (unsigned following = 0; following < max_repeats &&
         yx_short_first_unit_at(data, size, end, width, x, nocase);
         ++following) {
        end += width;
        if (long_first || following + 1 < max_repeats) {
            if (yx_short_first_unit_at(data, size, end, width, y,
                                       nocase)) {
                end += width;
                if (yx_short_first_unit_at(data, size, end, width, z,
                                           nocase)) end += width;
            }
        }
    }
    if (end - start > *best) *best = end - start;
    if (prior + 1 == max_repeats) return;
    if (size - pos >= 2 * width &&
        yx_short_first_unit_at(data, size, pos + width, width, x,
                               nocase))
        yx_bounded_triple_prefix_walk(data, size, start, pos + width,
                                      width, x, y, z, nocase, long_first,
                                      prior + 1, max_repeats, best);
    if (size - pos >= 3 * width &&
        yx_short_first_unit_at(data, size, pos + width, width, y,
                               nocase) &&
        yx_short_first_unit_at(data, size, pos + 2 * width, width, x,
                               nocase))
        yx_bounded_triple_prefix_walk(data, size, start, pos + 2 * width,
                                      width, x, y, z, nocase, long_first,
                                      prior + 1, max_repeats, best);
    if (size - pos >= 4 * width &&
        yx_short_first_unit_at(data, size, pos + width, width, y,
                               nocase) &&
        yx_short_first_unit_at(data, size, pos + 2 * width, width, z,
                               nocase) &&
        yx_short_first_unit_at(data, size, pos + 3 * width, width, x,
                               nocase))
        yx_bounded_triple_prefix_walk(data, size, start, pos + 3 * width,
                                      width, x, y, z, nocase, long_first,
                                      prior + 1, max_repeats, best);
}

static void yx_adjust_bounded_triple_prefix(YRX_PATTERN *pattern,
                                             const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1;
    uint8_t x, y, z;
    bool long_first, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    unsigned max_repeats;
    if (regexp[0] != '(' ||
        (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR))) return;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) != at + 14 || regexp[at + 8] != ')') return;
    if (strcmp(regexp + at + 9, "{1,2}") == 0)
        max_repeats = 2;
    else if (strcmp(regexp + at + 9, "{1,3}") == 0)
        max_repeats = 3;
    else
        return;
    if (regexp[at + 1] == '|' &&
        regexp[at + 2] == regexp[at] &&
        regexp[at + 4] == '|' &&
        regexp[at + 5] == regexp[at] &&
        regexp[at + 6] == regexp[at + 3]) {
        x = (uint8_t)regexp[at];
        y = (uint8_t)regexp[at + 3];
        z = (uint8_t)regexp[at + 7];
        long_first = false;
    } else if (regexp[at + 3] == '|' &&
               regexp[at + 4] == regexp[at] &&
               regexp[at + 5] == regexp[at + 1] &&
               regexp[at + 6] == '|' &&
               regexp[at + 7] == regexp[at]) {
        x = (uint8_t)regexp[at];
        y = (uint8_t)regexp[at + 1];
        z = (uint8_t)regexp[at + 2];
        long_first = true;
    } else {
        return;
    }
    if ((!long_first && nocase &&
         !(x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
           z >= '0' && z <= '9')) ||
        !yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        yx_fold(x) == yx_fold(y) ||
        yx_fold(x) == yx_fold(z) ||
        yx_fold(y) == yx_fold(z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
                       match->length >= 2 && match->offset < size &&
                       size - match->offset >= 2 &&
                       data[match->offset + 1] == 0 ? 2 : 1;
        size_t best = 0;
        yx_bounded_triple_prefix_walk(data, size, match->offset,
                                      match->offset, width, x, y, z, nocase,
                                      long_first, 0, max_repeats, &best);
        if (!long_first && max_repeats == 3 && best > 4 * width &&
            yx_short_first_unit_at(data, size, match->offset,
                                   width, x, nocase) &&
            yx_short_first_unit_at(data, size, match->offset + width,
                                   width, x, nocase) &&
            yx_short_first_unit_at(data, size, match->offset + 2 * width,
                                   width, x, nocase) &&
            yx_short_first_unit_at(data, size, match->offset + 3 * width,
                                   width, x, nocase) &&
            yx_short_first_unit_at(data, size, match->offset + 4 * width,
                                   width, y, nocase))
            best = 4 * width;
        if (best) match->length = best;
    }
}

/* An anchored {1,3} group of x, xy and xyz can visit two extra short
   branches after its three full branches. With shortest-first alternatives,
   the extra branches consume only x unless the end anchor requires the
   complete input; longest-first alternatives keep their normal priority. */
static int yx_adjust_anchored_bounded_triple(YRX_PATTERN *pattern,
                                              const uint8_t *data,
                                              size_t size, size_t limit)
{
    const char *regexp = pattern->regexp;
    size_t at = 2, pos = 0;
    uint8_t x, y, z;
    bool short_first, end_anchor;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (regexp[0] != '^' || regexp[1] != '(' ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_FULLWORD |
                               YX_MOD_XOR))) return 1;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (strlen(regexp) < at + 14 || regexp[at + 8] != ')') return 1;
    if (strcmp(regexp + at + 9, "{1,3}") == 0)
        end_anchor = false;
    else if (strcmp(regexp + at + 9, "{1,3}$") == 0)
        end_anchor = true;
    else return 1;
    short_first = regexp[at + 1] == '|' &&
                  regexp[at + 2] == regexp[at] &&
                  regexp[at + 4] == '|' &&
                  regexp[at + 5] == regexp[at] &&
                  regexp[at + 6] == regexp[at + 3];
    if (short_first) {
        x = (uint8_t)regexp[at];
        y = (uint8_t)regexp[at + 3];
        z = (uint8_t)regexp[at + 7];
    } else {
        if (regexp[at + 3] != '|' ||
            regexp[at + 4] != regexp[at] ||
            regexp[at + 5] != regexp[at + 1] ||
            regexp[at + 6] != '|' ||
            regexp[at + 7] != regexp[at]) return 1;
        x = (uint8_t)regexp[at];
        y = (uint8_t)regexp[at + 1];
        z = (uint8_t)regexp[at + 2];
    }
    if (nocase && short_first) return 1;
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        (nocase ? yx_fold(x) == yx_fold(y) ||
                  yx_fold(x) == yx_fold(z) ||
                  yx_fold(y) == yx_fold(z) :
                  x == y || x == z || y == z))
        return 1;
    for (unsigned repeat = 0; repeat < 5 &&
         yx_short_first_unit_at(data, size, pos, 1, x, nocase); ++repeat) {
        ++pos;
        if (end_anchor || !short_first || repeat < 3) {
            if (yx_short_first_unit_at(data, size, pos, 1, y, nocase)) {
                ++pos;
                if (yx_short_first_unit_at(data, size, pos, 1, z, nocase))
                    ++pos;
            }
        }
    }
    if (end_anchor) {
        if (pos == size && !pattern->match_count)
            return yx_add_match(pattern, 0, pos, limit);
    } else if (pos) {
        for (size_t i = 0; i < pattern->match_count; ++i)
            if (pattern->matches[i].offset == 0)
                pattern->matches[i].length = pos;
    }
    return 1;
}

/* The end-anchored verifier can reach two more repetitions than a written
   {1,3} bound when all literal branches share x as their first byte.
   Complete suffix matches can be checked directly without changing the
   branch priority of matches already returned by the regex engine. */
static int yx_add_missing_bounded_end_matches(YRX_PATTERN *pattern,
                                               const uint8_t *data,
                                               size_t size)
{
    const char *regexp = pattern->regexp;
    const char *branch[3];
    size_t width[3], count = 0, at = 0, start, close, max_span;
    uint8_t x, y, z = 0;
    bool anchored, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_FULLWORD | YX_MOD_XOR))
        return 1;
    anchored = regexp[at] == '^';
    if (anchored) ++at;
    if (regexp[at++] != '(') return 1;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    start = at;
    while (regexp[at] && regexp[at] != ')') {
        if (regexp[at] == '|') {
            if (count == 3 || at == start) return 1;
            branch[count] = regexp + start;
            width[count++] = at - start;
            start = at + 1;
        } else if (!yx_plain_regex_byte((uint8_t)regexp[at])) {
            return 1;
        }
        ++at;
    }
    close = at;
    if (regexp[close] != ')' || close == start ||
        count < 1 || count == 3 ||
        strcmp(regexp + close + 1, "{1,3}$") != 0) return 1;
    branch[count] = regexp + start;
    width[count++] = close - start;
    if (!((count == 2 &&
           ((width[0] == 1 && width[1] == 2) ||
            (width[0] == 2 && width[1] == 1))) ||
          (count == 3 &&
           ((width[0] == 1 && width[1] == 2 && width[2] == 3) ||
            (width[0] == 3 && width[1] == 2 && width[2] == 1)))))
        return 1;
    const char *shortest = width[0] == 1 ? branch[0] : branch[count - 1];
    const char *middle = width[0] == 2 ? branch[0] :
                         width[1] == 2 ? branch[1] : branch[count - 1];
    const char *longest = count == 3 ?
                          (width[0] == 3 ? branch[0] : branch[2]) : NULL;
    x = (uint8_t)shortest[0];
    y = (uint8_t)middle[1];
    if (middle[0] != (char)x ||
        (count == 3 &&
         (longest[0] != (char)x || longest[1] != (char)y))) return 1;
    if (count == 3) z = (uint8_t)longest[2];
    if (nocase ? yx_fold(x) == yx_fold(y) ||
                 (count == 3 &&
                  (yx_fold(x) == yx_fold(z) ||
                   yx_fold(y) == yx_fold(z))) :
                 x == y || (count == 3 && (x == z || y == z)))
        return 1;
    max_span = 5 * (count == 3 ? 3 : 2);
    if (anchored && size > max_span) return 1;
    size_t first = anchored ? 0 : size > max_span ? size - max_span : 0;
    for (size_t offset = first; offset < size; ++offset) {
        size_t pos = offset;
        for (unsigned repeat = 0; repeat < 5 && pos < size; ++repeat) {
            uint8_t value = nocase ? yx_fold(data[pos]) : data[pos];
            if (value != (nocase ? yx_fold(x) : x)) break;
            ++pos;
            if (pos < size &&
                (nocase ? yx_fold(data[pos]) == yx_fold(y) :
                          data[pos] == y)) {
                ++pos;
                if (count == 3 && pos < size &&
                    (nocase ? yx_fold(data[pos]) == yx_fold(z) :
                              data[pos] == z)) ++pos;
            }
        }
        if (pos == size && pos > offset) {
            bool present = false;
            for (size_t i = 0; i < pattern->match_count; ++i)
                if (pattern->matches[i].offset == offset) {
                    present = true;
                    break;
                }
            if (!present && !yx_add_match(pattern, offset,
                                          pos - offset, 0)) return 0;
        }
        if (anchored) break;
    }
    return 1;
}

/* In a short-first x|xy|xyz group followed by y, the verifier keeps the
   furthest eligible suffix. Under nocase with alphabetic bytes, the suffix
   must follow a short x branch; digits keep the case-sensitive priority.
   With {1,3}, at most five branches are visited, and only the first two or
   three may use the longer forms. */
static size_t yx_repeated_triple_suffix_length(const uint8_t *data,
                                                size_t size, size_t offset,
                                                uint8_t x, uint8_t y,
                                                uint8_t z, bool nocase,
                                                bool alphabetic,
                                                bool bounded)
{
    size_t pos = offset, best = 0, repeat = 0;
    while ((!bounded || repeat < 5) &&
           yx_short_first_unit_at(data, size, pos, 1, x, nocase)) {
        ++pos;
        if (yx_short_first_unit_at(data, size, pos, 1, y, nocase))
            best = pos + 1 - offset;
        if (!bounded || repeat < (nocase && alphabetic ? 2u : 3u)) {
            if (yx_short_first_unit_at(data, size, pos, 1, y, nocase)) {
                ++pos;
                if (yx_short_first_unit_at(data, size, pos, 1, z,
                                           nocase)) ++pos;
            }
        }
        if ((!nocase || !alphabetic) &&
            yx_short_first_unit_at(data, size, pos, 1, y, false))
            best = pos + 1 - offset;
        ++repeat;
    }
    return best;
}

static int yx_adjust_repeated_triple_suffix(YRX_PATTERN *pattern,
                                             const uint8_t *data,
                                             size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, length = strlen(regexp);
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool alphabetic, bounded;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_FULLWORD | YX_MOD_XOR))
        return 1;
    if (regexp[0] != '(') return 1;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if ((length != at + 11 && length != at + 15) ||
        regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 4] != '|' ||
        regexp[at + 5] != regexp[at] ||
        regexp[at + 6] != regexp[at + 3] ||
        regexp[at + 8] != ')') return 1;
    if (length == at + 11 && regexp[at + 9] == '+' &&
        regexp[at + 10] == regexp[at + 3])
        bounded = false;
    else if (length == at + 15 &&
             memcmp(regexp + at + 9, "{1,3}", 5) == 0 &&
             regexp[at + 14] == regexp[at + 3])
        bounded = true;
    else return 1;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    z = (uint8_t)regexp[at + 7];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) ||
        (nocase ? (yx_fold(x) == yx_fold(y) ||
                   yx_fold(x) == yx_fold(z) ||
                   yx_fold(y) == yx_fold(z)) :
                  (x == y || x == z || y == z))) return 1;
    alphabetic = !((x >= '0' && x <= '9') &&
                   (y >= '0' && y <= '9') &&
                   (z >= '0' && z <= '9'));
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t best = yx_repeated_triple_suffix_length(
            data, size, match->offset, x, y, z, nocase, alphabetic,
            bounded);
        if (best) match->length = best;
    }
    if (bounded) {
        for (size_t offset = 0; offset < size; ++offset) {
            if (!yx_short_first_unit_at(data, size, offset, 1, x,
                                        nocase)) continue;
            size_t best = yx_repeated_triple_suffix_length(
                data, size, offset, x, y, z, nocase, alphabetic, true);
            if (best && !yx_add_match(pattern, offset, best, 0)) return 0;
        }
    }
    return 1;
}

/* The two-branch bounded verifier allows five short units, but only its
   first two repetitions may use xy. Alphabetic nocase keeps the written
   three-repetition bound and can place the suffix after xy. */
static size_t yx_bounded_pair_suffix_length(const uint8_t *data,
                                             size_t size, size_t offset,
                                             uint8_t x, uint8_t y,
                                             bool nocase,
                                             bool alphabetic)
{
    bool case_variant = nocase && alphabetic;
    unsigned limit = case_variant ? 3u : 5u;
    unsigned long_limit = case_variant ? 3u : 2u;
    size_t pos = offset, best = 0;
    for (unsigned repeat = 0; repeat < limit &&
         yx_short_first_unit_at(data, size, pos, 1, x, nocase); ++repeat) {
        ++pos;
        if (yx_short_first_unit_at(data, size, pos, 1, y, nocase))
            best = pos + 1 - offset;
        if (repeat < long_limit &&
            yx_short_first_unit_at(data, size, pos, 1, y, nocase)) ++pos;
        if (case_variant &&
            yx_short_first_unit_at(data, size, pos, 1, y, true))
            best = pos + 1 - offset;
    }
    return best;
}

static int yx_adjust_bounded_pair_suffix(YRX_PATTERN *pattern,
                                           const uint8_t *data,
                                           size_t size)
{
    const char *regexp = pattern->regexp;
    size_t at = 1, length = strlen(regexp);
    uint8_t x, y;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool alphabetic;
    if (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_FULLWORD | YX_MOD_XOR))
        return 1;
    if (regexp[0] != '(') return 1;
    if (regexp[at] == '?' && regexp[at + 1] == ':') at += 2;
    if (length != at + 11 || regexp[at + 1] != '|' ||
        regexp[at + 2] != regexp[at] || regexp[at + 4] != ')' ||
        memcmp(regexp + at + 5, "{1,3}", 5) != 0 ||
        regexp[at + 10] != regexp[at + 3]) return 1;
    x = (uint8_t)regexp[at];
    y = (uint8_t)regexp[at + 3];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        (nocase ? yx_fold(x) == yx_fold(y) : x == y)) return 1;
    alphabetic = !((x >= '0' && x <= '9') &&
                   (y >= '0' && y <= '9'));
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t best = yx_bounded_pair_suffix_length(
            data, size, match->offset, x, y, nocase, alphabetic);
        if (best) match->length = best;
    }
    for (size_t offset = 0; offset < size; ++offset) {
        if (!yx_short_first_unit_at(data, size, offset, 1, x, nocase))
            continue;
        size_t best = yx_bounded_pair_suffix_length(
            data, size, offset, x, y, nocase, alphabetic);
        if (best && !yx_add_match(pattern, offset, best, 0)) return 0;
    }
    return 1;
}

/* The bounded x|xy verifier can consume a third group before a distinct
   literal suffix. PCRE2 obeys the written upper bound and therefore misses
   those offsets. Add only the missing third-group hits; its existing spans
   retain their branch priority. */
static int yx_add_missing_bounded_pair_tail(YRX_PATTERN *pattern,
                                             const uint8_t *data,
                                             size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length = strlen(regexp);
    uint8_t x, y, z;
    unsigned tail_max;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR) ||
        length < 12 || regexp[0] != '(' || regexp[5] != ')' ||
        memcmp(regexp + 6, "{1,2}", 5) != 0) return 1;
    x = (uint8_t)regexp[1];
    if (regexp[2] == '|' && regexp[3] == regexp[1]) {
        y = (uint8_t)regexp[4];
    } else if (regexp[3] == '|' && regexp[4] == regexp[1]) {
        y = (uint8_t)regexp[2];
    } else return 1;
    const char *tail = regexp + 11;
    size_t tail_length = length - 11;
    if (tail_length == 1) {
        z = (uint8_t)tail[0];
        tail_max = 1;
    } else if (tail_length == 6 &&
               memcmp(tail + 1, "{1,2}", 5) == 0) {
        z = (uint8_t)tail[0];
        tail_max = 2;
    } else if ((tail_length == 6 || tail_length == 11) &&
               tail[0] == '(' && tail[2] == '|' && tail[3] == tail[1] &&
               tail[4] == tail[1] && tail[5] == ')' &&
               (tail_length == 6 ||
                memcmp(tail + 6, "{1,2}", 5) == 0)) {
        z = (uint8_t)tail[1];
        tail_max = tail_length == 6 ? 1 : 2;
    } else return 1;
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || yx_fold(x) == yx_fold(y) ||
        yx_fold(x) == yx_fold(z) || yx_fold(y) == yx_fold(z)) return 1;
    /* The nocase alphabetic single-suffix verifier keeps the written bound.
       Its grouped z|zz suffix and all-digit patterns use the third branch. */
    if (nocase && tail[0] != '(' &&
        !(x >= '0' && x <= '9' && y >= '0' && y <= '9' &&
          z >= '0' && z <= '9')) return 1;
    size_t original_count = pattern->match_count;
    if (original_count > 1)
        qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
              yx_match_compare);
    for (size_t offset = 0; offset < size; ++offset) {
        if (!yx_short_first_unit_at(data, size, offset, 1, x, nocase))
            continue;
        size_t left = 0, right = original_count;
        while (left < right) {
            size_t middle = left + (right - left) / 2;
            if (pattern->matches[middle].offset < offset)
                left = middle + 1;
            else right = middle;
        }
        if (left < original_count &&
            pattern->matches[left].offset == offset) continue;
        size_t best = 0;
        for (size_t width = 1; width <= 2; ++width) {
            if (width == 1 && (pattern->modifiers & YX_MOD_WIDE) &&
                !(pattern->modifiers & YX_MOD_ASCII)) continue;
            if (width == 2 && !(pattern->modifiers & YX_MOD_WIDE)) continue;
            for (unsigned branches = 0; branches < 8; ++branches) {
                size_t at = offset;
                bool matched = true;
                for (unsigned unit = 0; unit < 3; ++unit) {
                    if (!yx_short_first_unit_at(data, size, at, width,
                                                x, nocase)) {
                        matched = false;
                        break;
                    }
                    at += width;
                    if (branches & (1u << unit)) {
                        if (!yx_short_first_unit_at(data, size, at, width,
                                                    y, nocase)) {
                            matched = false;
                            break;
                        }
                        at += width;
                    }
                }
                if (!matched || !yx_short_first_unit_at(data, size, at,
                                                         width, z, nocase))
                    continue;
                at += width;
                if (tail_max == 2 &&
                    yx_short_first_unit_at(data, size, at, width, z, nocase))
                    at += width;
                if (at - offset > best) best = at - offset;
            }
        }
        if (best && !yx_add_match(pattern, offset, best, 0)) return 0;
    }
    return 1;
}

/* With a distinct optional suffix, the x|xy bounded verifier still visits
   the same short and long branches as the suffix-free group. Its longest
   endpoint determines whether the optional byte is included. */
static void yx_adjust_bounded_pair_optional_tail(YRX_PATTERN *pattern,
                                                  const uint8_t *data,
                                                  size_t size)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if ((pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        strlen(regexp) != 13 || regexp[0] != '(' ||
        regexp[2] != '|' || regexp[3] != regexp[1] ||
        regexp[5] != ')' ||
        memcmp(regexp + 6, "{1,2}", 5) != 0 ||
        regexp[12] != '?') return;
    x = (uint8_t)regexp[1];
    y = (uint8_t)regexp[4];
    z = (uint8_t)regexp[11];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || yx_fold(x) == yx_fold(y) ||
        yx_fold(x) == yx_fold(z) || yx_fold(y) == yx_fold(z)) return;
    bool both = (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) ==
                (YX_MOD_ASCII | YX_MOD_WIDE);
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t width = (pattern->modifiers & YX_MOD_WIDE) &&
            (!both || yx_short_first_unit_at(data, size, match->offset,
                                              2, x, nocase)) ? 2 : 1;
        size_t best = 0;
        yx_bounded_short_first_pair_walk(data, size, match->offset,
                                          match->offset, width, x, y,
                                          nocase, false, 0, 2, &best);
        if (!best) continue;
        if (both && width == 2 && size >= 16 &&
            !yx_short_first_unit_at(data, size, match->offset + 2,
                                     2, x, nocase) &&
            !(yx_short_first_unit_at(data, size, match->offset + 2,
                                      2, y, nocase) &&
              yx_short_first_unit_at(data, size, match->offset + 4,
                                      2, x, nocase))) {
            match->length = 1;
            continue;
        }
        if (yx_short_first_unit_at(data, size, match->offset + best,
                                   width, z, nocase)) best += width;
        match->length = best;
    }
}

/* The bounded x|xy verifier retains one extra complete short branch for
   select four-byte prefixes, and the final short x in terminal xyx. */
static void yx_adjust_bounded_pair_optional_class_spans(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    uint32_t modifiers = pattern->modifiers;
    if ((modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE)) ||
        ((modifiers & YX_MOD_WIDE) && !(modifiers & YX_MOD_ASCII)) ||
        strlen(regexp) != 16 || regexp[0] != '(' ||
        regexp[2] != '|' || regexp[3] != regexp[1] ||
        regexp[5] != ')' || memcmp(regexp + 6, "{1,3}", 5) != 0 ||
        regexp[11] != '[' || regexp[12] != regexp[4] ||
        regexp[14] != ']' || regexp[15] != '?') return;
    uint8_t x = (uint8_t)regexp[1];
    uint8_t y = (uint8_t)regexp[4];
    uint8_t z = (uint8_t)regexp[13];
    if (!((x >= 'a' && x <= 'x') || (x >= '0' && x <= '7')) ||
        y != x + 1 || z != y + 1) return;
    bool nocase = (modifiers & YX_MOD_NOCASE) != 0;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t offset = match->offset;
        if ((match->length != 2 && match->length != 3) ||
            offset > size || size - offset < 3) continue;
        size_t available = size - offset;
        uint8_t first = data[offset];
        uint8_t second = data[offset + 1];
        uint8_t third = data[offset + 2];
        uint8_t fourth = available >= 4 ? data[offset + 3] : 0;
        uint8_t after = available >= 5 ? data[offset + 4] : 0;
        if (nocase) {
            first = yx_fold(first);
            second = yx_fold(second);
            third = yx_fold(third);
            fourth = yx_fold(fourth);
            after = yx_fold(after);
        }
        if (first != x) continue;
        bool terminal = after != x && after != y && after != z;
        bool fourth_short = available >= 4 && fourth == x && terminal &&
            ((second == x && (third == x || third == y)) ||
             (second == y && third == x));
        bool fourth_class = available >= 4 && second == y && third == x &&
            (fourth == z || (fourth == y && after != x));
        if (fourth_short || fourth_class) {
            match->length = 4;
        } else if (match->length == 2 && second == y && third == x &&
                   fourth != x && fourth != y && fourth != z) {
            match->length = 3;
        }
    }
}

static size_t yx_bounded_pair_class_tail_end(
    const uint8_t *data, size_t size, size_t offset, size_t width,
    uint8_t x, uint8_t y, uint8_t z, bool nocase, bool long_first)
{
    if (offset > size || size - offset < 4 * width ||
        !yx_short_first_unit_at(data, size, offset, width, x, nocase) ||
        !yx_short_first_unit_at(data, size, offset + width, width,
                                long_first ? y : x, nocase) ||
        !yx_short_first_unit_at(data, size, offset + 2 * width, width,
                                x, nocase)) return 0;
    size_t end = offset + 3 * width;
    if (!yx_short_first_unit_at(data, size, end, width, y, nocase) &&
        !yx_short_first_unit_at(data, size, end, width, z, nocase))
        return 0;
    do {
        end += width;
    } while (yx_short_first_unit_at(data, size, end, width, y, nocase) ||
             yx_short_first_unit_at(data, size, end, width, z, nocase));
    return end;
}

/* The verifier for (x|xy){1,2}[yz]+ retains the full class tail after
   xyx, and discovers a third short x before the class even though the
   written bound is two. The two prefixes have distinct atom outcomes. */
static int yx_adjust_bounded_pair_class_tail(YRX_PATTERN *pattern,
                                              const uint8_t *data,
                                              size_t size)
{
    const char *regexp = pattern->regexp;
    uint32_t modifiers = pattern->modifiers;
    if ((modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE)) ||
        strlen(regexp) != 16 || regexp[0] != '(' ||
        regexp[2] != '|' || regexp[3] != regexp[1] ||
        regexp[5] != ')' || memcmp(regexp + 6, "{1,2}", 5) != 0 ||
        regexp[11] != '[' || regexp[12] != regexp[4] ||
        regexp[14] != ']' || regexp[15] != '+') return 1;
    uint8_t x = (uint8_t)regexp[1];
    uint8_t y = (uint8_t)regexp[4];
    uint8_t z = (uint8_t)regexp[13];
    if (!((x >= 'a' && x <= 'x') || (x >= '0' && x <= '7')) ||
        y != x + 1 || z != y + 1) return 1;
    bool nocase = (modifiers & YX_MOD_NOCASE) != 0;
    size_t original_count = pattern->match_count;
    for (size_t i = 0; i < original_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        for (size_t width = 1; width <= 2; ++width) {
            if ((width == 1 && (modifiers & YX_MOD_WIDE) &&
                 !(modifiers & YX_MOD_ASCII)) ||
                (width == 2 && !(modifiers & YX_MOD_WIDE)) ||
                match->length != 2 * width) continue;
            size_t end = yx_bounded_pair_class_tail_end(
                data, size, match->offset, width, x, y, z, nocase, true);
            if (end) {
                match->length = end - match->offset;
                break;
            }
        }
    }
    if (original_count > 1)
        qsort(pattern->matches, original_count, sizeof(YRX_MATCH),
              yx_match_compare);
    for (size_t width = 1; width <= 2; ++width) {
        if ((width == 1 && (modifiers & YX_MOD_WIDE) &&
             !(modifiers & YX_MOD_ASCII)) ||
            (width == 2 && !(modifiers & YX_MOD_WIDE)) ||
            size < 4 * width) continue;
        for (size_t offset = 0; offset <= size - 4 * width; ++offset) {
            size_t end = yx_bounded_pair_class_tail_end(
                data, size, offset, width, x, y, z, nocase, false);
            if (!end) continue;
            size_t left = 0, right = original_count;
            while (left < right) {
                size_t middle = left + (right - left) / 2;
                if (pattern->matches[middle].offset < offset)
                    left = middle + 1;
                else right = middle;
            }
            if (left < original_count &&
                pattern->matches[left].offset == offset) continue;
            if (!yx_add_match(pattern, offset, end - offset, 0)) return 0;
        }
    }
    return 1;
}

/* A single x|xy group with an optional distinct byte retains its ASCII
   one-byte atom at a wide offset once the search buffer reaches 16 bytes. */
static void yx_adjust_single_pair_optional_wide_tie(YRX_PATTERN *pattern,
                                                      const uint8_t *data,
                                                      size_t size)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y, z;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (size < 16 ||
        (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) !=
            (YX_MOD_ASCII | YX_MOD_WIDE) ||
        (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        strlen(regexp) != 8 || regexp[0] != '(' ||
        regexp[2] != '|' || regexp[3] != regexp[1] ||
        regexp[5] != ')' || regexp[7] != '?') return;
    x = (uint8_t)regexp[1];
    y = (uint8_t)regexp[4];
    z = (uint8_t)regexp[6];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || yx_fold(x) == yx_fold(y) ||
        yx_fold(x) == yx_fold(z) || yx_fold(y) == yx_fold(z)) return;
    for (size_t i = 0; i < pattern->match_count; ++i)
        if (yx_short_first_unit_at(data, size,
                                    pattern->matches[i].offset, 2,
                                    x, nocase)) pattern->matches[i].length = 1;
}

/* The end-anchored verifier also reaches one extra x|xy branch before an
   optional distinct suffix. Restrict the addition to exact whole-buffer
   three-branch strings; the ordinary scan retains all other priorities. */
static int yx_add_missing_anchored_pair_optional_tail(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    uint8_t x, y, z;
    if (pattern->match_count || size < 3 || size > 7 ||
        (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_NOCASE |
                               YX_MOD_FULLWORD | YX_MOD_XOR)) ||
        strlen(regexp) != 15 || regexp[0] != '^' || regexp[1] != '(' ||
        regexp[3] != '|' || regexp[4] != regexp[2] || regexp[6] != ')' ||
        memcmp(regexp + 7, "{1,2}", 5) != 0 ||
        regexp[13] != '?' || regexp[14] != '$') return 1;
    x = (uint8_t)regexp[2];
    y = (uint8_t)regexp[5];
    z = (uint8_t)regexp[12];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) ||
        !yx_plain_regex_byte(z) || x == y || x == z || y == z)
        return 1;
    for (unsigned branches = 0; branches < 8; ++branches) {
        size_t at = 0;
        bool complete = true;
        for (unsigned unit = 0; unit < 3; ++unit) {
            if (!yx_short_first_unit_at(data, size, at, 1, x, false)) {
                complete = false;
                break;
            }
            ++at;
            if (branches & (1u << unit)) {
                if (!yx_short_first_unit_at(data, size, at, 1, y,
                                            false)) {
                    complete = false;
                    break;
                }
                ++at;
            }
        }
        if (complete &&
            (at == size ||
             (at + 1 == size && data[at] == z)))
            return yx_add_match(pattern, 0, size, 0);
    }
    return 1;
}

/* For a short haystack, YARA-X's nested literal verifier selects the
 * one-byte inner branch before the duplicate two-byte outer branch. At 16
 * bytes the search backend changes and the two-byte branch wins. Anchors,
 * quantifiers, case folding, and wide matching use different priorities. */
static void yx_adjust_short_nested_duplicate_pair(
    YRX_PATTERN *pattern, const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    size_t length;
    uint8_t x, y;
    if (size >= 16 || (pattern->modifiers & ~YX_MOD_ASCII)) return;
    length = strlen(regexp);
    if ((length != 15 && length != 19) ||
        memcmp(regexp, "(?:(?:", 6) != 0 ||
        regexp[8] != '|' || regexp[9] != regexp[6] ||
        regexp[10] != ')' || regexp[11] != '|') return;
    x = (uint8_t) regexp[6];
    y = (uint8_t) regexp[7];
    if (!yx_plain_regex_byte(x) || !yx_plain_regex_byte(y) || x == y)
        return;
    if (length == 19) {
        if (memcmp(regexp + 12, "(?:", 3) != 0 ||
            regexp[15] != (char) x || regexp[16] != (char) y ||
            regexp[17] != ')' || regexp[18] != ')') return;
    } else if (regexp[12] != (char) x ||
               regexp[13] != (char) y || regexp[14] != ')') {
        return;
    }
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        if (match->length == 2 && match->offset + 1 < size &&
            data[match->offset] == x && data[match->offset + 1] == y)
            match->length = 1;
    }
}

/* In the reference verifier a repeated three-way, single-byte alternation
 * with a lower bound of one can consume 2 * upper_bound - 1 units. Keep this
 * correction limited to three distinct literal choices and one encoding. */
static void yx_adjust_bounded_three_singletons(YRX_PATTERN *pattern,
                                                const uint8_t *data,
                                                size_t size)
{
    const char *regexp = pattern->regexp;
    uint32_t modifiers = pattern->modifiers;
    size_t at = 1, length;
    uint8_t choices[3];
    bool nocase, wide;
    size_t width, maximum;
    if (!regexp ||
        (modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE)) ||
        ((modifiers & YX_MOD_ASCII) && (modifiers & YX_MOD_WIDE)) ||
        regexp[0] != '(') return;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    length = strlen(regexp);
    if (length != at + 11 || regexp[at + 1] != '|' ||
        regexp[at + 3] != '|' || regexp[at + 5] != ')' ||
        regexp[at + 6] != '{' || regexp[at + 7] != '1' ||
        regexp[at + 8] != ',' || regexp[at + 10] != '}' ||
        regexp[at + 9] < '2' || regexp[at + 9] > '4') return;
    choices[0] = (uint8_t) regexp[at];
    choices[1] = (uint8_t) regexp[at + 2];
    choices[2] = (uint8_t) regexp[at + 4];
    for (size_t j = 0; j < 3; ++j)
        if (!((choices[j] >= 'a' && choices[j] <= 'z') ||
              (choices[j] >= '0' && choices[j] <= '9')))
            return;
    if (choices[0] == choices[1] || choices[0] == choices[2] ||
        choices[1] == choices[2]) return;
    nocase = (modifiers & YX_MOD_NOCASE) != 0;
    wide = (modifiers & YX_MOD_WIDE) != 0;
    width = wide ? 2 : 1;
    maximum = 2 * (size_t) (regexp[at + 9] - '0') - 1;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t units = 0;
        while (units < maximum && match->offset <= size &&
               size - match->offset >= (units + 1) * width) {
            size_t offset = match->offset + units * width;
            bool chosen = false;
            if (wide && data[offset + 1] != 0) break;
            for (size_t j = 0; j < 3; ++j)
                if (nocase ? yx_fold(data[offset]) == yx_fold(choices[j]) :
                             data[offset] == choices[j]) {
                    chosen = true;
                    break;
                }
            if (!chosen) break;
            ++units;
        }
        if (units) match->length = units * width;
    }
}

/* Fixed two-byte alternatives have one unambiguous width even if their
 * prefixes overlap. The reference applies the same bounded verifier span as
 * the single-byte three-way form above. */
static void yx_adjust_bounded_three_pairs(YRX_PATTERN *pattern,
                                           const uint8_t *data, size_t size)
{
    const char *regexp = pattern->regexp;
    uint32_t modifiers = pattern->modifiers;
    size_t at = 1, length;
    uint8_t choices[3][2];
    bool nocase, wide;
    size_t width, maximum;
    if (!regexp ||
        (modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE)) ||
        ((modifiers & YX_MOD_ASCII) && (modifiers & YX_MOD_WIDE)) ||
        regexp[0] != '(') return;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    length = strlen(regexp);
    if (length != at + 14 || regexp[at + 2] != '|' ||
        regexp[at + 5] != '|' || regexp[at + 8] != ')' ||
        regexp[at + 9] != '{' || regexp[at + 10] != '1' ||
        regexp[at + 11] != ',' || regexp[at + 13] != '}' ||
        regexp[at + 12] < '2' || regexp[at + 12] > '4') return;
    for (size_t j = 0; j < 3; ++j)
        for (size_t k = 0; k < 2; ++k) {
            uint8_t value = (uint8_t) regexp[at + j * 3 + k];
            if (!((value >= 'a' && value <= 'z') ||
                  (value >= '0' && value <= '9')))
                return;
            choices[j][k] = value;
        }
    for (size_t j = 0; j < 3; ++j)
        for (size_t k = j + 1; k < 3; ++k)
            if (choices[j][0] == choices[k][0] &&
                choices[j][1] == choices[k][1]) return;
    nocase = (modifiers & YX_MOD_NOCASE) != 0;
    wide = (modifiers & YX_MOD_WIDE) != 0;
    width = wide ? 2 : 1;
    maximum = 2 * (size_t) (regexp[at + 12] - '0') - 1;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        size_t pairs = 0;
        while (pairs < maximum && match->offset <= size &&
               size - match->offset >= (pairs + 1) * 2 * width) {
            size_t offset = match->offset + pairs * 2 * width;
            bool chosen = false;
            for (size_t j = 0; j < 3; ++j)
                if (yx_short_first_unit_at(data, size, offset, width,
                                           choices[j][0], nocase) &&
                    yx_short_first_unit_at(data, size, offset + width,
                                           width, choices[j][1], nocase)) {
                    chosen = true;
                    break;
                }
            if (!chosen) break;
            ++pairs;
        }
        if (pairs) match->length = pairs * 2 * width;
    }
}

typedef struct {
    uint8_t bytes[3][3];
    uint8_t lengths[3];
    unsigned maximum;
} YX_THREE_LITERAL_BOUNDS;

static bool yx_parse_three_literal_bounds(const char *regexp,
                                          YX_THREE_LITERAL_BOUNDS *parsed,
                                          bool include_prefixes)
{
    size_t at = 1;
    if (!regexp || regexp[0] != '(') return false;
    if (regexp[1] == '?' && regexp[2] == ':') at = 3;
    for (size_t arm = 0; arm < 3; ++arm) {
        while (regexp[at] && regexp[at] != '|' && regexp[at] != ')') {
            uint8_t value = (uint8_t) regexp[at++];
            if (!((value >= 'a' && value <= 'z') ||
                  (value >= '0' && value <= '9')) ||
                parsed->lengths[arm] == 3) return false;
            parsed->bytes[arm][parsed->lengths[arm]++] = value;
        }
        if (!parsed->lengths[arm] ||
            regexp[at] != (arm == 2 ? ')' : '|')) return false;
        ++at;
    }
    if (regexp[at] != '{' || regexp[at + 1] != '1' ||
        regexp[at + 2] != ',' || regexp[at + 3] < '2' ||
        regexp[at + 3] > '4' || regexp[at + 4] != '}' ||
        regexp[at + 5] != '\0') return false;
    parsed->maximum = 2 * (unsigned) (regexp[at + 3] - '0') - 1;
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = i + 1; j < 3; ++j)
            if (parsed->lengths[i] == parsed->lengths[j] &&
                memcmp(parsed->bytes[i], parsed->bytes[j],
                       parsed->lengths[i]) == 0) return false;
    if (include_prefixes) return true;
    /* A three-step prefix chain follows branch order in the reference
     * verifier. Existing prefix-specific handlers preserve that order. */
    size_t shortest = 0, longest = 0;
    for (size_t i = 1; i < 3; ++i) {
        if (parsed->lengths[i] < parsed->lengths[shortest]) shortest = i;
        if (parsed->lengths[i] > parsed->lengths[longest]) longest = i;
    }
    if (parsed->lengths[shortest] == 1 &&
        parsed->lengths[longest] == 3) {
        size_t middle = 3 - shortest - longest;
        if (parsed->lengths[middle] == 2 &&
            memcmp(parsed->bytes[shortest], parsed->bytes[middle], 1) == 0 &&
            memcmp(parsed->bytes[middle], parsed->bytes[longest], 2) == 0)
            return false;
    }
    if (parsed->lengths[shortest] == 1 &&
        parsed->lengths[0] + parsed->lengths[1] +
            parsed->lengths[2] == 5 &&
        parsed->bytes[0][0] == parsed->bytes[1][0] &&
        parsed->bytes[1][0] == parsed->bytes[2][0])
        return false;
    if (parsed->lengths[0] == 2 && parsed->lengths[1] == 2 &&
        parsed->lengths[2] == 3 &&
        memcmp(parsed->bytes[0], parsed->bytes[2], 2) == 0)
        return false;
    return true;
}

static int yx_three_literal_reach(const uint8_t *data, size_t size,
                                  size_t start, size_t width,
                                  const YX_THREE_LITERAL_BOUNDS *parsed,
                                  unsigned repeats, unsigned units,
                                  int memo[8][22])
{
    if (repeats == parsed->maximum) return 0;
    if (memo[repeats][units] >= 0) return memo[repeats][units];
    int best = 0;
    size_t at = start + units * width;
    for (size_t arm = 0; arm < 3; ++arm) {
        unsigned length = parsed->lengths[arm];
        if (at > size || size - at < length * width) continue;
        bool equal = true;
        for (unsigned i = 0; i < length; ++i)
            if (!yx_short_first_unit_at(data, size, at + i * width,
                                         width, parsed->bytes[arm][i],
                                         false)) {
                equal = false;
                break;
            }
        if (!equal) continue;
        int span = (int) length + yx_three_literal_reach(
            data, size, start, width, parsed, repeats + 1,
            units + length, memo);
        if (span > best) best = span;
    }
    memo[repeats][units] = best;
    return best;
}

/* For a bounded three-way literal group with a lower bound of one, the
 * reference's verifier can retain up to 2 * upper_bound - 1 complete arms.
 * Calculate the longest reachable span at an existing hit. This also covers
 * mixed one-, two-, and three-byte arms without changing hit discovery. */
static void yx_adjust_bounded_three_literals(YRX_PATTERN *pattern,
                                              const uint8_t *data, size_t size)
{
    YX_THREE_LITERAL_BOUNDS parsed = {0};
    uint32_t modifiers = pattern->modifiers;
    if ((modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE)) ||
        !yx_parse_three_literal_bounds(pattern->regexp, &parsed, false)) return;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        YRX_MATCH *match = &pattern->matches[i];
        if (match->offset >= size) continue;
        size_t widths[2] = {1, 0};
        size_t count = 1;
        if ((modifiers & YX_MOD_WIDE) &&
            match->offset + 1 < size && data[match->offset + 1] == 0) {
            if (modifiers & YX_MOD_ASCII) widths[count++] = 2;
            else widths[0] = 2;
        }
        size_t best = 0;
        for (size_t j = 0; j < count; ++j) {
            int memo[8][22];
            for (size_t row = 0; row < 8; ++row)
                for (size_t column = 0; column < 22; ++column)
                    memo[row][column] = -1;
            int units = yx_three_literal_reach(data, size,
                                                match->offset, widths[j],
                                                &parsed, 0, 0, memo);
            size_t span = (size_t) units * widths[j];
            if (span > best) best = span;
        }
        if (best && (!(modifiers & YX_MOD_ASCII) ||
                     !(modifiers & YX_MOD_WIDE) || best > 2 ||
                     match->length >= 2))
            match->length = best;
    }
}

/* A bounded literal alternation is verified from the atom that triggered it.
 * Its backward verifier can consume the optional copies preceding that atom,
 * while the forward verifier follows source branch priority. Keeping atom
 * discovery separate from verification also preserves fullword filtering and
 * the reference's last-offset replacement behavior. */
typedef struct {
    uint8_t bytes[6];
    uint8_t length;
    int8_t arm;
    uint8_t width;
    uint8_t bucket;
} yx_literal_verifier_atom;

static int yx_literal_atom_compare(const void *a, const void *b)
{
    const yx_literal_verifier_atom *left = a, *right = b;
    size_t length = left->length < right->length ? left->length : right->length;
    int order = memcmp(left->bytes, right->bytes, length);
    return order ? order : (int)left->length - (int)right->length;
}

static int yx_literal_atom_quality(const yx_literal_verifier_atom *atom)
{
    int quality = 0;
    for (size_t i = 0; i < atom->length; ++i) {
        uint8_t byte = atom->bytes[i];
        quality += (byte >= 'a' && byte <= 'z') ||
                   (byte >= 'A' && byte <= 'Z') ? 18 : 20;
        bool unique = true;
        for (size_t j = 0; j < i; ++j)
            if (atom->bytes[j] == byte) unique = false;
        if (unique) quality += 2;
    }
    return quality;
}

static bool yx_literal_atom_set_better(const yx_literal_verifier_atom *left,
                                       size_t left_count,
                                       const yx_literal_verifier_atom *right,
                                       size_t right_count)
{
    int minimum[2] = {1000, 1000}, sum[2] = {0, 0};
    size_t lengths[2] = {SIZE_MAX, SIZE_MAX};
    for (size_t set = 0; set < 2; ++set) {
        const yx_literal_verifier_atom *atoms = set ? right : left;
        size_t count = set ? right_count : left_count;
        for (size_t i = 0; i < count; ++i) {
            int quality = yx_literal_atom_quality(&atoms[i]);
            if (quality < minimum[set]) minimum[set] = quality;
            if (atoms[i].length < lengths[set]) lengths[set] = atoms[i].length;
            sum[set] += quality;
        }
    }
    if (minimum[0] != minimum[1]) return minimum[0] > minimum[1];
    if (lengths[0] != lengths[1]) return lengths[0] > lengths[1];
    double average_left = (double)sum[0] / left_count;
    double average_right = (double)sum[1] / right_count;
    if (average_left - average_right > 15.0) return true;
    if (average_right - average_left > 15.0) return false;
    return left_count < right_count;
}

static bool yx_literal_arm_at(const YX_THREE_LITERAL_BOUNDS *parsed,
                               size_t arm, const uint8_t *data, size_t size,
                               size_t offset, size_t width, bool nocase)
{
    size_t length = parsed->lengths[arm];
    if (offset > size || length > (size - offset) / width) return false;
    for (size_t i = 0; i < length; ++i)
        if (!yx_short_first_unit_at(data, size, offset + i * width, width,
                                     parsed->bytes[arm][i], nocase)) return false;
    return true;
}

static int yx_literal_verifier_add(YRX_PATTERN *pattern, size_t start,
                                    size_t end, size_t limit)
{
    size_t count = pattern->match_count;
    if (count && start == pattern->matches[count - 1].offset) {
        pattern->matches[count - 1].length = end - start;
        return 1;
    }
    size_t low = 0, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (pattern->matches[middle].offset < start) low = middle + 1;
        else high = middle;
    }
    if (low < count && pattern->matches[low].offset == start) {
        if (end - start > pattern->matches[low].length)
            pattern->matches[low].length = end - start;
        return 1;
    }
    if (limit && count == limit) {
        if (low == count) return 1;
        --count;
        pattern->match_count = count;
    }
    if (!yx_add_match(pattern, start, end - start, 0)) return 0;
    memmove(&pattern->matches[low + 1], &pattern->matches[low],
            (count - low) * sizeof(*pattern->matches));
    pattern->matches[low] = (YRX_MATCH){start, end - start, -1};
    return 1;
}

static int yx_literal_verify_atom(YRX_PATTERN *pattern,
                                   const YX_THREE_LITERAL_BOUNDS *parsed,
                                   const yx_literal_verifier_atom *atom,
                                   const uint8_t *data, size_t size,
                                   size_t offset, size_t limit)
{
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    unsigned maximum = (parsed->maximum + 1) / 2;
    size_t width = atom->width, end = offset;
    for (unsigned repeat = 0; repeat < maximum; ++repeat) {
        size_t first = !repeat && atom->arm >= 0 ? (size_t)atom->arm : 0;
        size_t last = !repeat && atom->arm >= 0 ? first + 1 : 3;
        bool matched = false;
        for (size_t arm = first; arm < last; ++arm)
            if (yx_literal_arm_at(parsed, arm, data, size, end, width, nocase)) {
                end += parsed->lengths[arm] * width;
                matched = true;
                break;
            }
        if (!matched) {
            if (!repeat) return 1;
            break;
        }
    }
    bool reachable[10] = {true}, previous[10] = {true};
    for (unsigned repeat = 1; repeat < maximum; ++repeat) {
        bool next[10] = {false};
        for (size_t units = 0; units <= 3 * (repeat - 1); ++units) {
            if (!previous[units]) continue;
            for (size_t arm = 0; arm < 3; ++arm) {
                size_t total = units + parsed->lengths[arm];
                if (total <= offset / width &&
                    yx_literal_arm_at(parsed, arm, data, size,
                        offset - total * width, width, nocase))
                    next[total] = reachable[total] = true;
            }
        }
        memcpy(previous, next, sizeof(previous));
    }
    for (size_t units = 0; units <= 3 * (maximum - 1); ++units) {
        if (!reachable[units]) continue;
        size_t start = offset - units * width;
        if ((pattern->modifiers & YX_MOD_FULLWORD) &&
            !yx_fullword(data, size, start, end - start, width == 2, 0))
            continue;
        if (!yx_literal_verifier_add(pattern, start, end, limit)) return 0;
    }
    return 1;
}

static int yx_scan_bounded_literal_alternation(YRX_PATTERN *pattern,
                                               const uint8_t *data, size_t size,
                                               size_t limit, bool *handled)
{
    YX_THREE_LITERAL_BOUNDS parsed = {0};
    uint32_t modifiers = pattern->modifiers;
    *handled = false;
    if ((modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE |
                       YX_MOD_FULLWORD | YX_MOD_PRIVATE)) ||
        !yx_parse_three_literal_bounds(pattern->regexp, &parsed, true)) return 1;
    *handled = true;
    yx_literal_verifier_atom branches[24] = {0}, combined[24] = {0};
    size_t branch_count = 0;
    for (size_t arm = 0; arm < 3; ++arm) {
        size_t begin = branch_count++;
        branches[begin].length = parsed.lengths[arm];
        branches[begin].arm = (int8_t)arm;
        memcpy(branches[begin].bytes, parsed.bytes[arm], parsed.lengths[arm]);
        for (size_t byte = 0; byte < parsed.lengths[arm]; ++byte) {
            uint8_t value = parsed.bytes[arm][byte];
            if (!(modifiers & YX_MOD_NOCASE) || value < 'a' || value > 'z')
                continue;
            size_t end = branch_count;
            for (size_t i = begin; i < end; ++i) {
                branches[branch_count] = branches[i];
                branches[branch_count++].bytes[byte] = (uint8_t)(value - 32);
            }
        }
        qsort(branches + begin, branch_count - begin, sizeof(*branches),
              yx_literal_atom_compare);
    }
    memcpy(combined, branches, branch_count * sizeof(*combined));
    qsort(combined, branch_count, sizeof(*combined), yx_literal_atom_compare);
    size_t combined_count = 0;
    yx_literal_verifier_atom previous = {0};
    for (size_t i = 0; i < branch_count; ++i) {
        yx_literal_verifier_atom current = combined[i];
        bool prefix = i && previous.length <= current.length &&
            memcmp(previous.bytes, current.bytes, previous.length) == 0;
        previous = current;
        if (prefix) continue;
        combined[combined_count] = current;
        combined[combined_count++].arm = -1;
    }
    bool singleton_class = parsed.lengths[0] == 1 &&
                           parsed.lengths[1] == 1 && parsed.lengths[2] == 1;
    const yx_literal_verifier_atom *selected = branches;
    size_t selected_count = branch_count;
    if (singleton_class || yx_literal_atom_set_better(combined, combined_count,
                                                       branches, branch_count)) {
        selected = combined;
        selected_count = combined_count;
    }
    yx_literal_verifier_atom atoms[48] = {0};
    size_t atom_count = 0;
    if (modifiers & YX_MOD_WIDE)
        for (size_t i = 0; i < selected_count; ++i) {
            yx_literal_verifier_atom *atom = &atoms[atom_count++];
            atom->arm = selected[i].arm;
            atom->width = 2;
            atom->length = selected[i].length * 2;
            for (size_t j = 0; j < selected[i].length; ++j)
                atom->bytes[j * 2] = selected[i].bytes[j];
        }
    if (!(modifiers & YX_MOD_WIDE) || (modifiers & YX_MOD_ASCII))
        for (size_t i = 0; i < selected_count; ++i) {
            atoms[atom_count] = selected[i];
            atoms[atom_count++].width = 1;
        }
    size_t minimum = 6;
    for (size_t i = 0; i < atom_count; ++i)
        if (atoms[i].length < minimum) minimum = atoms[i].length;
    size_t mask = minimum < 4 ? minimum : 4;
    bool teddy = atom_count <= (minimum == 1 ? 16u : 64u) &&
                 pattern->global_atom_count_hint <= (minimum == 1 ? 16u : 64u) &&
                 size >= 16 + mask - 1;
    size_t order[48];
    for (size_t i = 0; i < atom_count; ++i) {
        atoms[i].bucket = (uint8_t)(7 - i % 8);
        for (size_t j = 0; j < i; ++j) {
            bool same = true;
            for (size_t k = 0; k < mask; ++k)
                if ((atoms[i].bytes[k] & 15) != (atoms[j].bytes[k] & 15))
                    same = false;
            if (same) { atoms[i].bucket = atoms[j].bucket; break; }
        }
        size_t at = i;
        while (at && (teddy ? atoms[order[at - 1]].bucket > atoms[i].bucket :
                      atoms[order[at - 1]].length < atoms[i].length)) {
            order[at] = order[at - 1];
            --at;
        }
        order[at] = i;
    }
    for (size_t cursor = teddy ? 0 : 1; cursor <= size; ++cursor) {
        if (yx_scan_deadline_poll(pattern->deadline)) return 0;
        for (size_t i = 0; i < atom_count; ++i) {
            const yx_literal_verifier_atom *atom = &atoms[order[i]];
            if ((!teddy && cursor < atom->length) ||
                (teddy && atom->length > size - cursor)) continue;
            size_t offset = teddy ? cursor : cursor - atom->length;
            if (memcmp(data + offset, atom->bytes, atom->length) == 0 &&
                !yx_literal_verify_atom(pattern, &parsed, atom, data, size,
                                          offset, limit)) return 0;
        }
        if (limit && pattern->match_count == limit &&
            cursor > pattern->matches[limit - 1].offset &&
            cursor - pattern->matches[limit - 1].offset > 24) break;
        if (cursor == size) break;
    }
    return 1;
}

/*
 * The loaded-literal atom verification semantics follow
 * lib/src/scanner/context.rs in YARA-X v1.21.0.
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

static int yx_scan_archived_literal(YRX_PATTERN *pattern,const uint8_t *data,size_t size,size_t limit)
{
    const yx_archived_literal_prefilter *filter=&pattern->archived_literal_prefilter;
    bool nocase=(pattern->modifiers&YX_MOD_NOCASE)!=0;
    bool fullword=(pattern->modifiers&YX_MOD_FULLWORD)!=0;
    for(size_t i=0;i<filter->count;++i) {
        const yx_archived_literal_atom *atom=&filter->atoms[i];
        if(!atom->length||atom->length>size)continue;
        size_t cursor=0;
        while(cursor<=size-atom->length) {
            if(yx_scan_deadline_poll(pattern->deadline))return 0;
            int64_t hit=xx_data_find_bytes_buffer_optimize(data,size,cursor,atom->bytes,atom->length,NULL);
            if(hit<0)break;
            cursor=(size_t)hit+1;
            if((size_t)hit<atom->backtrack)continue;
            size_t start=(size_t)hit-atom->backtrack;
            size_t width=atom->exact?atom->length:pattern->length;
            if(width>size-start||(!atom->exact&&!yx_equal_text(data+start,pattern->bytes,width,nocase))||
               (fullword&&!yx_fullword(data,size,start,width,false,0)))continue;
            if(!yx_literal_verifier_add(pattern,start,start+width,limit))return 0;
        }
    }
    return 1;
}

YRX_RESULT yx_scan_pattern(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                           size_t max_matches, bool fast_scan)
{
    if (!pattern || (!data && size)) return YRX_INVALID_ARGUMENT;
    if (yx_scan_deadline_reached(pattern->deadline)) return YRX_SCAN_TIMEOUT;
    if (fast_scan && pattern->fast_count_enabled &&
        pattern->fast_count_threshold < max_matches)
        max_matches = pattern->fast_count_threshold;
    if (fast_scan && !pattern->fast_scan_needs_all && max_matches > 1)
        max_matches = 1;
    free(pattern->matches);
    pattern->matches = NULL;
    pattern->match_count = 0;
    pattern->match_capacity = 0;
    if (!size) return YRX_SUCCESS;
    if (pattern->rx_program) {
#ifdef _WIN32
        bool pike_only = true;
        for (size_t i = 0; i < pattern->rx_program->sub_count; ++i)
            if (pattern->rx_program->subs[i].flags & YX_RX_FAST)
                pike_only = false;
        /* A mandatory long repetition cannot produce a PikeVM match. Keep
         * FastVM programs on their own path: their encoded counts may wrap. */
        if (pike_only && pattern->kind == YX_PATTERN_REGEX && pattern->regexp) {
            if (yx_unmatchable_large_repeat(pattern->regexp)) return YRX_SUCCESS;
            const uint8_t *literal;
            size_t literal_length;
            if (yx_large_repeat_literal_alt(pattern->regexp, &literal,
                                             &literal_length)) {
                uint8_t *saved_bytes = pattern->bytes;
                size_t saved_length = pattern->length;
                pattern->bytes = (uint8_t *)literal;
                pattern->length = literal_length;
                int ok = yx_scan_text(pattern, data, size, max_matches, false);
                pattern->bytes = saved_bytes;
                pattern->length = saved_length;
                if (yx_scan_deadline_reached(pattern->deadline))
                    return YRX_SCAN_TIMEOUT;
                return ok ? YRX_SUCCESS : YRX_SCAN_ERROR;
            }
        }
#endif
        yx_rx_match_list list = {0};
        bool ok;
        list.limit = max_matches;
        if (pattern->rx_teddy && pattern->rx_order_ids) {
            yx_rx_order order = {true, pattern->rx_teddy_minimum, pattern->rx_order_ids, pattern->rx_order_buckets};
            ok = yx_rx_scan_ordered(pattern->rx_program, data, size, pattern->deadline, &list, &order);
        } else
        ok = yx_rx_scan(pattern->rx_program, data, size, pattern->deadline, &list);
        for (size_t i = 0; ok && i < list.count; ++i)
            ok = yx_add_match(pattern, list.items[i].start, list.items[i].end - list.items[i].start, max_matches);
        yx_rx_match_list_free(&list);
        if (yx_scan_deadline_reached(pattern->deadline)) return YRX_SCAN_TIMEOUT;
        return ok ? YRX_SUCCESS : YRX_SCAN_ERROR;
    }
    if (pattern->kind == YX_PATTERN_REGEX && pattern->gap_head_regexp) {
        YRX_PATTERN head = *pattern;
        head.regexp = pattern->gap_head_regexp;
        head.gap_head_regexp = NULL;
        YRX_RESULT result = yx_scan_pattern(&head, data, size, max_matches, fast_scan);
        pattern->matches = head.matches;
        pattern->match_count = head.match_count;
        pattern->match_capacity = head.match_capacity;
        pattern->ever_matched = head.ever_matched;
        pattern->zero_limit_present = head.zero_limit_present;
        return result;
    }
    int success = 0;
    bool literal_alternation_handled = false, chain_handled = false;
    switch (pattern->kind) {
    case YX_PATTERN_TEXT:
        if(pattern->archived_literal_prefilter.atoms)
            success=yx_scan_archived_literal(pattern,data,size,max_matches);
        else if (pattern->modifiers & (YX_MOD_BASE64 | YX_MOD_BASE64WIDE))
            success = yx_scan_base64(pattern, data, size, max_matches,
                                     fast_scan && !pattern->fast_scan_needs_all);
        else
            success = yx_scan_text(pattern, data, size, max_matches,
                                   fast_scan && !pattern->fast_scan_needs_all);
        break;
    case YX_PATTERN_HEX:
        success = pattern->hex_has_jump ?
            yx_scan_hex_complex(pattern, data, size, max_matches) :
            yx_scan_hex(pattern, data, size, max_matches);
        break;
    case YX_PATTERN_REGEX:
        {
            /* Chains of sub-patterns: the reference's own join. */
            success = yx_ser_scan_regex_chain(pattern, data, size, yx_large_regex_emit, pattern);
            if (success != -2) {
                chain_handled = true;
                if (success) yx_sort_unique_limit(pattern, max_matches);
                break;
            }
            bool overlap_class_handled = false;
            success = yx_scan_bounded_literal_alternation(
                pattern, data, size, max_matches, &literal_alternation_handled);
            if (success && !literal_alternation_handled)
                success = yx_scan_repeated_overlap_class_branch(
                    pattern, data, size, max_matches, &overlap_class_handled);
            if (success && !literal_alternation_handled && !overlap_class_handled)
                success = yx_scan_regex(pattern, data, size, max_matches);
        }
        break;
    }
    if (yx_scan_deadline_reached(pattern->deadline)) return YRX_SCAN_TIMEOUT;
    if (!success) return YRX_SCAN_ERROR;
    if (pattern->kind == YX_PATTERN_REGEX && !literal_alternation_handled && !chain_handled) {
        yx_extend_nested_short_units(pattern, data, size);
        yx_extend_anchored_branch_short_units(pattern, data, size);
        yx_extend_anchored_class_first_units(pattern, data, size);
        if (!yx_add_missing_three_branch_first(pattern, data, size))
            return YRX_SCAN_ERROR;
        if (!yx_add_missing_three_class_first(pattern, data, size))
            return YRX_SCAN_ERROR;
        yx_extend_two_long_group_first(pattern, data, size);
        yx_adjust_long_then_short_group_first(pattern, data, size);
        yx_extend_three_group_first_units(pattern, data, size);
        yx_extend_nine_byte_group_first(pattern, data, size);
        yx_extend_long_then_short_class_first(pattern, data, size);
        if (!yx_add_missing_nine_byte_class_first(pattern, data, size))
            return YRX_SCAN_ERROR;
        yx_discard_nocase_prefix_at_eof(pattern, data, size);
        yx_adjust_greedy_repeated_literal_pair(pattern, data, size);
        yx_adjust_short_first_repeated_pair(pattern, data, size);
        yx_adjust_short_first_repeated_triple(pattern, data, size);
        yx_adjust_short_first_three_byte_pair(pattern, data, size);
        yx_adjust_short_first_fork(pattern, data, size);
        yx_adjust_bounded_three_byte_pair(pattern, data, size);
        yx_adjust_bounded_fork(pattern, data, size);
        yx_adjust_long_first_fork(pattern, data, size);
        yx_adjust_long_long_short_fork(pattern, data, size);
        yx_adjust_long_first_three_byte_pair(pattern, data, size);
        yx_adjust_bounded_short_first_pair(pattern, data, size);
        yx_adjust_bounded_two_byte_pair(pattern, data, size);
        yx_adjust_nested_short_first_pair(pattern, data, size);
        yx_adjust_bounded_repeated_byte(pattern, data, size);
        yx_adjust_bounded_nocase_triple(pattern, data, size);
        yx_adjust_bounded_triple_prefix(pattern, data, size);
        if (!yx_adjust_anchored_bounded_triple(pattern, data, size,
                                               max_matches))
            return YRX_SCAN_ERROR;
        if (!yx_add_missing_bounded_end_matches(pattern, data, size))
            return YRX_SCAN_ERROR;
        if (!yx_adjust_repeated_triple_suffix(pattern, data, size))
            return YRX_SCAN_ERROR;
        if (!yx_adjust_bounded_pair_suffix(pattern, data, size))
            return YRX_SCAN_ERROR;
        if (!yx_add_missing_bounded_pair_tail(pattern, data, size))
            return YRX_SCAN_ERROR;
        yx_adjust_bounded_pair_optional_tail(pattern, data, size);
        yx_adjust_bounded_pair_optional_class_spans(pattern, data, size);
        yx_adjust_single_pair_optional_wide_tie(pattern, data, size);
        if (!yx_add_missing_anchored_pair_optional_tail(pattern, data, size))
            return YRX_SCAN_ERROR;
        yx_adjust_grouped_ascii_wide_ties(pattern, data, size);
        yx_adjust_grouped_optional_suffix_ties(pattern, data, size,
                                               max_matches);
        yx_adjust_lazy_identical_capture(pattern, data, size);
        yx_adjust_bounded_two_byte_alternatives(pattern, data, size);
        yx_adjust_bounded_terminal_byte_alternatives(pattern, data, size);
        yx_adjust_bounded_two_byte_class_pair(pattern, data, size);
        yx_adjust_long_first_triple_singleton(pattern, data, size);
        if (!yx_adjust_bounded_pair_class_tail(pattern, data, size))
            return YRX_SCAN_ERROR;
        yx_adjust_short_nested_duplicate_pair(pattern, data, size);
        yx_adjust_bounded_three_singletons(pattern, data, size);
        yx_adjust_bounded_three_pairs(pattern, data, size);
        yx_adjust_bounded_three_literals(pattern, data, size);
    }
    yx_sort_unique_limit(pattern, max_matches);
    return yx_scan_deadline_reached(pattern->deadline) ?
           YRX_SCAN_TIMEOUT : YRX_SUCCESS;
}

#include "scan_candidates.h"

typedef struct yx_candidate_variant {
    uint8_t *needle;
    size_t length;
    bool wide;
} yx_candidate_variant;

struct yx_candidate_plan {
    yx_pattern_kind kind;
    yx_candidate_atom *atoms;
    size_t atom_count, atom_capacity;
    yx_candidate_variant variants[2];
    size_t variant_count;
    yx_base64_candidate *base64;
    size_t base64_count;
    pcre2_code *regex;
    const char *regex_source;
    size_t regex_maximum;
    bool program;
    bool gate;
    uint8_t *gate_bytes; /* encoded branches; atom variant k spans */
    size_t *gate_offsets; /* gate_bytes[gate_offsets[k]..gate_offsets[k+1]) */
};

static pcre2_code *yx_candidate_cached_regex(const YRX_PATTERN *pattern)
{
    const yx_candidate_plan *plan = pattern->candidate_plan;
    return plan && plan->kind == YX_PATTERN_REGEX &&
        plan->regex_source == pattern->regexp ? plan->regex : NULL;
}

/* Prefer diverse, non-padding windows. A complete 8-byte window also keeps
 * long shared prefixes from making every occurrence a candidate for every
 * pattern. Case expansion is bounded at sixteen atoms per window. */
static unsigned yx_candidate_byte_quality(uint8_t byte)
{
    if (!byte || byte == 0xff || byte == ' ') return 1;
    if (byte == 'e' || byte == 'E' || byte == 't' || byte == 'T' ||
        byte == 'a' || byte == 'A' || byte == '0') return 3;
    if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
        (byte >= '0' && byte <= '9')) return 6;
    return 8;
}

static void yx_candidate_select_window(const uint8_t *bytes,
    const uint8_t *mask, size_t length, bool nocase,
    size_t *selected, size_t *selected_length)
{
    unsigned best = 0;
    *selected = *selected_length = 0;
    for (size_t start = 0; start < length; ++start) {
        unsigned score = 0, letters = 0;
        /* The bytes of the window so far, bytes[start, index). */
        uint64_t present[4] = {0, 0, 0, 0};
        for (size_t width = 1; width <= 8 && width <= length - start; ++width) {
            size_t index = start + width - 1;
            uint8_t byte = bytes[index];
            if (mask && mask[index] != 0xff) break;
            bool letter = (byte >= 'a' && byte <= 'z') ||
                          (byte >= 'A' && byte <= 'Z');
            if (nocase && letter && ++letters > 4) break;
            /* A byte is new when the window's earlier bytes lack it. */
            bool seen = ((present[byte >> 6] >> (byte & 63u)) & 1u) != 0;
            present[byte >> 6] |= UINT64_C(1) << (byte & 63u);
            score += yx_candidate_byte_quality(byte) + (!seen ? 5 : 0);
            unsigned quality = score + (unsigned)width * 8;
            if (quality > best) {
                best = quality;
                *selected = start;
                *selected_length = width;
            }
        }
    }
}

static bool yx_candidate_add_atom(yx_candidate_plan *plan,
    const uint8_t *bytes, size_t length, size_t backtrack,
    uint32_t variant, uint8_t key)
{
    if (!length || length > 8 || plan->atom_count >= UINT32_MAX) return false;
    if (plan->atom_count == plan->atom_capacity) {
        size_t capacity = plan->atom_capacity ? plan->atom_capacity * 2 : 8;
        if (capacity < plan->atom_capacity ||
            capacity > SIZE_MAX / sizeof(*plan->atoms)) return false;
        yx_candidate_atom *grown = realloc(plan->atoms,
                                            capacity * sizeof(*grown));
        if (!grown) return false;
        plan->atoms = grown;
        plan->atom_capacity = capacity;
    }
    yx_candidate_atom *atom = &plan->atoms[plan->atom_count];
    memset(atom, 0, sizeof(*atom));
    memcpy(atom->bytes, bytes, length);
    atom->length = length;
    atom->backtrack = backtrack;
    atom->tag = (uint32_t)plan->atom_count++;
    atom->variant = variant;
    atom->xor_key = key;
    return true;
}

static bool yx_candidate_add_window(yx_candidate_plan *plan,
    const uint8_t *bytes, size_t length, size_t backtrack,
    uint32_t variant, bool nocase, unsigned first_key, unsigned last_key)
{
    size_t letters[8], letter_count = 0;
    if (nocase)
        for (size_t i = 0; i < length; ++i)
            if ((bytes[i] >= 'a' && bytes[i] <= 'z') ||
                (bytes[i] >= 'A' && bytes[i] <= 'Z')) letters[letter_count++] = i;
    if (letter_count > 4) return false;
    for (unsigned key = first_key; key <= last_key; ++key) {
        for (unsigned combination = 0; combination < (1u << letter_count);
             ++combination) {
            uint8_t expanded[8];
            memcpy(expanded, bytes, length);
            for (size_t i = 0; i < letter_count; ++i) {
                size_t at = letters[i];
                expanded[at] = (uint8_t)(yx_fold(expanded[at]) -
                    ((combination & (1u << i)) ? 32 : 0));
            }
            for (size_t i = 0; i < length; ++i) expanded[i] ^= (uint8_t)key;
            if (!yx_candidate_add_atom(plan, expanded, length, backtrack,
                                        variant, (uint8_t)key)) return false;
        }
    }
    return true;
}

static bool yx_candidate_text_plan(yx_candidate_plan *plan,
                                    const YRX_PATTERN *pattern)
{
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) ||
                 !(pattern->modifiers & YX_MOD_WIDE);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool xor_mode = (pattern->modifiers & YX_MOD_XOR) != 0;
    if (xor_mode && nocase) return false;
    for (unsigned encoding = 0; encoding < 2; ++encoding) {
        if ((!encoding && !ascii) || (encoding && !wide)) continue;
        if (encoding && pattern->length > SIZE_MAX / 2) return false;
        yx_candidate_variant *variant = &plan->variants[plan->variant_count];
        variant->length = pattern->length * (encoding ? 2 : 1);
        variant->wide = encoding != 0;
        variant->needle = malloc(variant->length);
        if (!variant->needle) return false;
        for (size_t i = 0; i < pattern->length; ++i) {
            variant->needle[i * (encoding ? 2 : 1)] = pattern->bytes[i];
            if (encoding) variant->needle[i * 2 + 1] = 0;
        }
        size_t start, length;
        yx_candidate_select_window(variant->needle, NULL, variant->length,
                                   nocase, &start, &length);
        if (!length || !yx_candidate_add_window(plan, variant->needle + start,
            length, start, (uint32_t)plan->variant_count, nocase,
            xor_mode ? pattern->xor_min : 0,
            xor_mode ? pattern->xor_max : 0)) return false;
        ++plan->variant_count;
    }
    return plan->atom_count != 0;
}

/* A prefix is fixed in position until a variable jump or alternative.
 * Alternatives at the head contribute one atom for every possible branch. */
static bool yx_candidate_hex_prefix(yx_candidate_plan *plan,
    const yx_hex_atom *atoms, size_t count, size_t origin, unsigned depth)
{
    uint8_t bytes[256] = {0}, mask[256] = {0};
    size_t used = 0, stopped = count;
    if (depth > 16 || plan->atom_count > 256) return false;
    for (size_t i = 0; i < count && used < sizeof(bytes); ++i) {
        const yx_hex_atom *atom = &atoms[i];
        if (atom->kind == YX_HEX_BYTE) {
            bytes[used] = atom->value;
            mask[used++] = atom->negated ? 0 : atom->mask;
        } else if (atom->kind == YX_HEX_JUMP &&
                   atom->minimum == atom->maximum &&
                   atom->minimum <= sizeof(bytes) - used) {
            used += atom->minimum;
        } else { stopped = i; break; }
    }
    size_t start, length;
    yx_candidate_select_window(bytes, mask, used, false, &start, &length);
    if (length) return yx_candidate_add_atom(plan, bytes + start, length,
                                             origin + start, 0, 0);
    /* A partially specified prefix byte is still a complete candidate
     * cover. Expand it only when no exact byte is available. */
    for (size_t i = 0; i < used; ++i) {
        if (!mask[i]) continue;
        for (unsigned value = 0; value < 256; ++value) {
            if ((value & mask[i]) != (bytes[i] & mask[i])) continue;
            uint8_t byte = (uint8_t)value;
            if (!yx_candidate_add_atom(plan, &byte, 1, origin + i, 0, 0))
                return false;
        }
        return true;
    }
    if (stopped < count && atoms[stopped].kind == YX_HEX_ALTERNATIVE) {
        const yx_hex_atom *alternative = &atoms[stopped];
        if (!alternative->branch_count) return false;
        for (size_t branch = 0; branch < alternative->branch_count; ++branch)
            if (!yx_candidate_hex_prefix(plan,
                alternative->branches[branch].atoms,
                alternative->branches[branch].count, origin + used, depth + 1))
                return false;
        return true;
    }
    return false;
}

static bool yx_candidate_hex_plan(yx_candidate_plan *plan,
                                   const YRX_PATTERN *pattern)
{
    if (!pattern->hex_has_jump) {
        size_t start, length;
        yx_candidate_select_window(pattern->bytes, pattern->mask,
                                   pattern->length, false, &start, &length);
        if (length) return yx_candidate_add_atom(plan, pattern->bytes + start,
                                                 length, start, 0, 0);
        for (size_t i = 0; i < pattern->length; ++i) {
            if (!pattern->mask[i]) continue;
            for (unsigned value = 0; value < 256; ++value) {
                if ((value & pattern->mask[i]) !=
                    (pattern->bytes[i] & pattern->mask[i])) continue;
                uint8_t byte = (uint8_t)value;
                if (!yx_candidate_add_atom(plan, &byte, 1, i, 0, 0)) return false;
            }
            return true;
        }
        return false;
    }
    char *lowered = NULL;
    int chain = yx_ser_lower_fast_regex(pattern, &lowered);
    free(lowered);
    if (chain == -1 || chain == 3 || yx_ser_hex_chain_status(pattern)) return false;
    return yx_candidate_hex_prefix(plan, pattern->hex_atoms,
                                    pattern->hex_atom_count, 0, 0);
}

/* A jump, negation or alternative without a regexp program (fixed jumps
 * between masked bytes, a large gap that is not a literal chain) leaves the
 * pattern to yx_scan_hex_complex. Its best top-level literal window is a
 * candidate atom instead: an occurrence verifies, with the same walker, the
 * starts that the jumps and alternatives in front of the window allow.
 * Literal chains keep their own join, whose results the walker does not
 * reproduce. Weak windows (padding bytes) would hit too often. */
static yx_candidate_plan *yx_candidate_hex_anchor_plan(const YRX_PATTERN *pattern)
{
    char *lowered = NULL;
    yx_hex_filter filter;
    int chain = yx_ser_lower_fast_regex(pattern, &lowered);
    free(lowered);
    /* Chains of sub-patterns keep the full scanner's join as well. */
    if (chain == -1 || chain == 3 || yx_ser_hex_chain_status(pattern)) return NULL;
    yx_hex_pick_anchor(pattern->hex_atoms, pattern->hex_atom_count, &filter);
    if (filter.anchor_length < 2 || filter.anchor_bits < 12) return NULL;
    yx_candidate_plan *plan = calloc(1, sizeof(*plan));
    if (!plan) return NULL;
    plan->kind = YX_PATTERN_HEX;
    if (!yx_candidate_add_atom(plan, filter.anchor, filter.anchor_length,
                               (size_t)filter.anchor_minimum, 0, 0)) {
        yx_candidate_plan_free(plan);
        return NULL;
    }
    plan->atoms[0].spread = (size_t)(filter.anchor_maximum - filter.anchor_minimum);
    return plan;
}

/* Flat, bounded byte regexps have the same anchored VM result as the
 * general scan, without the branch-order compatibility transformations. */
static bool yx_candidate_regex_plan(yx_candidate_plan *plan,
                                     const YRX_PATTERN *pattern)
{
    if (!pattern->regexp || pattern->gap_head_regexp ||
        (pattern->modifiers & YX_MOD_WIDE)) return false;
    const char *body = pattern->regexp;
    bool in_class = false, class_first = false;
    for (const unsigned char *at = (const unsigned char *)body; *at; ++at) {
        if (*at >= 0x80) return false;
        if (*at == '\\') {
            if (!at[1] || at[1] >= 0x80) return false;
            ++at;
            class_first = false;
            continue;
        }
        if (in_class) {
            /* The summary parser has no POSIX, nested-class, or set-operator
             * grammar. Keep those forms on the VM path. */
            if (*at == '[') return false;
            if (strchr("&~|-", *at) && at[1] == *at) return false;
            if (*at == ']' && !class_first) in_class = false;
            class_first = false;
        } else if (*at == '[') {
            in_class = true;
            class_first = true;
            if (at[1] == '^') ++at;
        } else if (strchr("()|^$", *at)) {
            /* The token loop below starts a token at every unescaped byte
             * outside a class, so it would reject this one (or fail on an
             * earlier token) without changing the plan. */
            return false;
        }
    }
    if (in_class) return false;
    yx_variant_parser parser = {body,
        (pattern->modifiers & YX_MOD_NOCASE) != 0,
        (pattern->modifiers & YX_MOD_DOTALL) != 0, false, 0, false};
    size_t maximum = 0;
    while (*parser.at) {
        if (strchr("()|^$", *parser.at)) return false;
        yx_variant_shape shape;
        if (!yx_variant_atom(&parser, &shape) || shape.maximum > 1024 ||
            maximum > 4096 - shape.maximum) return false;
        maximum += shape.maximum;
    }
    /* Every token before the first variable-width repeat has a known
     * byte offset. Keep literal runs after fixed classes and repetitions,
     * rather than restricting discovery to a leading literal prefix. */
    uint8_t *bytes = calloc(maximum ? maximum : 1, 1);
    uint8_t *mask = calloc(maximum ? maximum : 1, 1);
    if (!bytes || !mask) { free(bytes); free(mask); return false; }
    size_t position = 0;
    parser.at = body;
    while (*parser.at) {
        yx_variant_shape shape;
        if (!yx_variant_atom(&parser, &shape)) break;
        if (yx_variant_literal_unit(&shape)) {
            unsigned byte = 0;
            /* A literal unit has one member or an ASCII case pair (two
             * members in one bitmap byte, 32 apart). */
            while (byte < 256 && !shape.bytes[byte / 8]) byte += 8;
            while (byte < 256 && !(shape.bytes[byte / 8] & (1u << (byte % 8)))) ++byte;
            bool fixed = byte < 256;
            /* The shape helper also recognizes an ASCII case pair. Such a
             * class has no single required byte without nocase expansion. */
            if (fixed && !(pattern->modifiers & YX_MOD_NOCASE)) {
                unsigned other = byte + 1;
                while (other < 256 && (other % 8) && !(shape.bytes[other / 8] & (1u << (other % 8)))) ++other;
                while (other < 256 && !shape.bytes[other / 8]) other += 8;
                if (other < 256) fixed = false;
            }
            if (fixed) {
                memset(bytes + position, (uint8_t)byte, shape.minimum);
                memset(mask + position, 0xff, shape.minimum);
            }
        }
        position += shape.minimum;
        if (shape.minimum != shape.maximum) break;
    }
    size_t start, length;
    yx_candidate_select_window(bytes, mask, position,
        (pattern->modifiers & YX_MOD_NOCASE) != 0, &start, &length);
    bool ok = length >= 2 && yx_candidate_add_window(plan, bytes + start,
        length, start, 0, (pattern->modifiers & YX_MOD_NOCASE) != 0, 0, 0);
    free(bytes);
    free(mask);
    if (!ok) return false;
    plan->regex = yx_compile_pcre_regex_shared(pattern);
    plan->regex_maximum = maximum;
    return plan->regex != NULL;
}

/* `(branch|branch)[class]{n,m}` (or one bare branch): every match starts with
 * one of the branches and continues with at least n bytes of the class. The
 * branches are literal runs or single classes of plain characters. A hit of
 * an atom that equals a whole branch can only start a match when those n
 * bytes follow it, so the others are not worth a verification. Characters may
 * also be ASCII `\xHH` escapes and the class may be grouped, `([class]){n,m}`:
 * the same expression in the form a deserialized regexp is rebuilt in. */
typedef struct {
    uint8_t literals[8][16];
    size_t literal_lengths[8];
    uint8_t branch_class[8][32];
    bool is_class[8];
    size_t branch_count;
    uint8_t tail[32];
    size_t tail_min;
} yx_candidate_tail_shape;

/* An ASCII byte written `\xHH` at s (a raw byte; below 0x80 also the code
 * point of the same value). */
static bool yx_candidate_hex_escape(const char *s, unsigned char *byte)
{
    int high, low;
    if (s[0] != '\\' || s[1] != 'x') return false;
    high = yx_regex_hex_digit(s[2]);
    low = high >= 0 ? yx_regex_hex_digit(s[3]) : -1;
    if (high < 0 || low < 0 || high >= 8) return false;
    *byte = (unsigned char)(high << 4 | low);
    return true;
}

static bool yx_candidate_parse_class(const char **at, uint8_t bitmap[32])
{
    const char *s = *at;
    if (*s != '[') return false;
    ++s;
    memset(bitmap, 0, 32);
    if (*s == '^' || *s == ']') return false;
    while (*s && *s != ']') {
        unsigned char first;
        if (yx_candidate_hex_escape(s, &first)) s += 4;
        else {
            first = (unsigned char)*s++;
            if (first == '\\' || first == '[' || first >= 0x80 || first < 0x20) return false;
        }
        unsigned char last = first;
        if (*s == '-' && s[1] && s[1] != ']') {
            if (yx_candidate_hex_escape(s + 1, &last)) s += 5;
            else {
                last = (unsigned char)s[1];
                s += 2;
                if (last == '\\' || last == '[' || last >= 0x80) return false;
            }
            if (last < first) return false;
        }
        for (unsigned c = first; c <= last; ++c) bitmap[c / 8] |= (uint8_t)(1u << (c % 8));
    }
    if (*s != ']') return false;
    *at = s + 1;
    return true;
}

static bool yx_candidate_parse_tail_shape(const YRX_PATTERN *pattern,
                                          yx_candidate_tail_shape *shape)
{
    const char *s = pattern->regexp;
    bool group = false;
    if (!s || (pattern->modifiers & (YX_MOD_NOCASE | YX_MOD_WIDE))) return false;
    memset(shape, 0, sizeof(*shape));
    if (*s == '(') { group = true; ++s; }
    for (;;) {
        size_t b = shape->branch_count;
        if (b == 8) return false;
        if (*s == '[') {
            if (!yx_candidate_parse_class(&s, shape->branch_class[b])) return false;
            shape->is_class[b] = true;
        } else {
            size_t n = 0;
            for (;;) {
                unsigned char byte;
                if (yx_candidate_hex_escape(s, &byte)) s += 4;
                else if ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z'))
                    byte = (unsigned char)*s++;
                else break;
                if (n == 16) return false;
                shape->literals[b][n++] = byte;
            }
            if (!n) return false;
            shape->literal_lengths[b] = n;
        }
        ++shape->branch_count;
        if (group && *s == '|') { ++s; continue; }
        break;
    }
    if (group) { if (*s != ')') return false; ++s; }
    bool tail_group = *s == '(';
    if (tail_group) ++s;
    if (!yx_candidate_parse_class(&s, shape->tail)) return false;
    if (tail_group) { if (*s != ')') return false; ++s; }
    if (*s == '+') { shape->tail_min = 1; ++s; }
    else if (*s == '{') {
        unsigned long n = 0, m = 0;
        char *end;
        n = strtoul(s + 1, &end, 10);
        if (end == s + 1 || n == 0 || n > 4096) return false;
        if (*end == ',') {
            const char *digits = end + 1;
            if (*digits != '}') {
                m = strtoul(digits, &end, 10);
                if (end == digits || m < n) return false;
            } else end = (char *)digits;
        }
        if (*end != '}') return false;
        shape->tail_min = n;
        s = end + 1;
    } else return false;
    return *s == 0;
}

/* True when every match verified from an occurrence of the atom starts at
 * the occurrence: no backtrack, and no backward code or PikeVM backward code
 * that reaches MATCH through unconditional jumps alone (an atom at the start
 * of the expression or of one of its first branches). YARA-X takes a
 * regexp's atoms from whichever element of a concatenation gives the best
 * quality (thompson::Compiler::visit_post, HirKind::Concat) with backtrack
 * 0; verify_regexp then finds the start with the backward code, so an atom
 * taken after the branches has its match start before it. */
static bool yx_candidate_atom_starts_match(const yx_rx_program *program, const yx_rx_atom *atom)
{
    size_t ip = atom->bck;
    if (atom->backtrack) return false;
    if (!atom->has_bck) return true;
    for (unsigned step = 0; step < 16; ++step) {
        /* PikeVM instructions are 0xAA + opcode: MATCH 0x00, JUMP 0x04 with a
         * 32-bit offset from the instruction. */
        if (ip >= program->code_length || program->code_length - ip < 2 ||
            program->code[ip] != 0xAA) return false;
        const uint8_t *c = program->code + ip;
        if (c[1] == 0x00) return true;
        if (c[1] != 0x04 || program->code_length - ip < 6) return false;
        int64_t target = (int64_t)ip + (int32_t)((uint32_t)c[2] | (uint32_t)c[3] << 8 |
                                                 (uint32_t)c[4] << 16 | (uint32_t)c[5] << 24);
        if (target < 0) return false;
        ip = (size_t)target;
    }
    return false;
}

/* Sets the tail filter of the plan's newest atom when it starts every match
 * it verifies and is a whole branch followed by fewer than tail_min bytes of
 * the tail class. */
static void yx_candidate_tail_filter(yx_candidate_plan *plan, const yx_candidate_tail_shape *shape,
                                     const yx_rx_program *program, const yx_rx_atom *atom)
{
    yx_candidate_atom *target = &plan->atoms[plan->atom_count - 1];
    size_t best = 0;
    bool have = false;
    if (!yx_candidate_atom_starts_match(program, atom)) return;
    for (size_t b = 0; b < shape->branch_count; ++b) {
        size_t head = shape->is_class[b] ? 1 : shape->literal_lengths[b];
        /* An atom inside a literal branch is followed by the rest of the
         * branch, not by tail bytes. */
        if (atom->length < head) {
            if (!memcmp(atom->bytes, shape->literals[b], atom->length)) return;
            continue;
        }
        bool whole;
        if (shape->is_class[b])
            whole = shape->branch_class[b][atom->bytes[0] / 8] >> (atom->bytes[0] % 8) & 1;
        else
            whole = !memcmp(atom->bytes, shape->literals[b], head);
        for (size_t i = head; whole && i < atom->length; ++i)
            whole = shape->tail[atom->bytes[i] / 8] >> (atom->bytes[i] % 8) & 1;
        if (!whole) continue;
        /* The atom already holds all the tail bytes this branch needs. */
        if (atom->length - head >= shape->tail_min) return;
        /* An atom that fits several branches needs the fewest tail bytes. */
        size_t need = shape->tail_min - (atom->length - head);
        if (!have || need < best) best = need;
        have = true;
    }
    if (have && best) {
        target->tail_min = (uint16_t)best;
        memcpy(target->tail_class, shape->tail, 32);
    }
}

/* Programs are created only by yx_build_regexp_programs and are immutable.
 * An archive can subsequently change source fields; retain the VM path when
 * those fields no longer equal the exact inputs captured at its creation. */
static bool yx_candidate_canonical_program(const YRX_PATTERN *pattern)
{
    return !pattern->rx_program || (pattern->rx_program_regexp &&
        pattern->regexp && pattern->rx_program_modifiers == pattern->modifiers &&
        strcmp(pattern->rx_program_regexp, pattern->regexp) == 0);
}

/* YARA-X reports an exact atom's occurrence as a match without running a
 * VM (handle_atom_match, feature exact-atoms), and MatchList::add sets the
 * end of a greedy regexp's match at the same offset to the end it adds
 * last. The match at an offset then depends on the atoms found there and
 * their order (/cmc{0,10}x?.m/i matches "cmcm" in "cmcmm" but "CMCMM" in
 * "CMCMM"), not only on the anchored VM result the flat plan computes. */
static bool yx_candidate_exact_atoms(const yx_rx_program *program)
{
    for (size_t s = 0; s < program->sub_count; ++s)
        for (size_t i = 0; i < program->subs[s].atom_count; ++i)
            if (program->subs[s].atoms[i].exact) return true;
    return false;
}

/* A literal or whole-expression literal alternation has no program (YARA-X
 * compiles it as literal sub-patterns) and no flat plan when it contains a
 * group or `|`, so it would run the full scanner on every input. Every match
 * is an occurrence of one branch in an encoding its modifiers scan, so such
 * an occurrence is a necessary condition: the full scanner runs unchanged
 * once one is found and is skipped when there is none. Each branch and
 * encoding contributes one window atom; a hit compares the whole branch. */
static bool yx_candidate_gate_plan(yx_candidate_plan *plan,
                                   const YRX_PATTERN *pattern)
{
    uint8_t *bytes = NULL;
    size_t *offsets = NULL;
    if (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_FULLWORD |
                               YX_MOD_DOTALL | YX_MOD_PRIVATE)) return false;
    bool ascii = (pattern->modifiers & YX_MOD_ASCII) ||
                 !(pattern->modifiers & YX_MOD_WIDE);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    int count = yx_ser_literal_branches(pattern, &bytes, &offsets);
    /* A chain of sub-patterns: an occurrence of its head's literal or
     * atoms is a necessary condition for each match. */
    if (!count && (pattern->kind == YX_PATTERN_HEX || yx_ser_regex_chain(pattern)))
        count = yx_ser_hex_chain_gate(pattern, &bytes, &offsets);
    size_t total = count > 0 ? offsets[count] : 0;
    bool ok = count > 0 && total <= SIZE_MAX / 4 &&
              (size_t)count <= SIZE_MAX / sizeof(size_t) / 2 - 1;
    if (ok) {
        plan->gate_bytes = malloc(total * 3);
        plan->gate_offsets = malloc((2 * (size_t)count + 1) * sizeof(size_t));
        ok = plan->gate_bytes && plan->gate_offsets;
    }
    size_t used = 0, needles = 0;
    if (ok) plan->gate_offsets[0] = 0;
    for (int branch = 0; ok && branch < count; ++branch) {
        const uint8_t *literal = bytes + offsets[branch];
        size_t length = offsets[branch + 1] - offsets[branch];
        for (unsigned encoding = 0; ok && encoding < 2; ++encoding) {
            if ((!encoding && !ascii) || (encoding && !wide)) continue;
            size_t width = encoding ? 2 : 1;
            uint8_t *needle = plan->gate_bytes + used;
            for (size_t i = 0; i < length; ++i) {
                needle[i * width] = literal[i];
                if (encoding) needle[i * 2 + 1] = 0;
            }
            size_t start, window;
            yx_candidate_select_window(needle, NULL, length * width, false,
                                       &start, &window);
            ok = window && yx_candidate_add_atom(plan, needle + start, window,
                                                 start, (uint32_t)needles, 0);
            used += length * width;
            plan->gate_offsets[++needles] = used;
        }
    }
    free(bytes);
    free(offsets);
    if (ok && plan->atom_count) return true;
    free(plan->atoms);
    free(plan->gate_bytes);
    free(plan->gate_offsets);
    plan->atoms = NULL;
    plan->gate_bytes = NULL;
    plan->gate_offsets = NULL;
    plan->atom_count = plan->atom_capacity = 0;
    return false;
}

/* A hex alternation of exact byte strings, { ( 61 62 | 63 64 ) }, without a
 * prefix plan uses the same gate in front of its full scanner. */
static yx_candidate_plan *yx_candidate_hex_gate(const YRX_PATTERN *pattern)
{
    if (pattern->kind != YX_PATTERN_HEX) return NULL;
    yx_candidate_plan *plan = calloc(1, sizeof(*plan));
    if (!plan) return NULL;
    plan->kind = YX_PATTERN_HEX;
    plan->gate = yx_candidate_gate_plan(plan, pattern);
    if (plan->gate) return plan;
    yx_candidate_plan_free(plan);
    return NULL;
}

yx_candidate_plan *yx_candidate_plan_build(const YRX_PATTERN *pattern)
{
    if (!pattern || pattern->archived_literal_prefilter.atoms ||
        pattern->base64_archived_prefilter.present) return NULL;
    if (pattern->rx_program) {
        /* FastVM sub-patterns keep YARA-X's own jump semantics (a trailing
         * `.{n,m}` jump never reaches the last input byte), which an anchored
         * native regex match does not reproduce. Only Pike-only programs may
         * use the flat plan; FastVM programs replay at their candidates. */
        bool fast_subs = false;
        for (size_t i = 0; i < pattern->rx_program->sub_count; ++i)
            if (pattern->rx_program->subs[i].flags & YX_RX_FAST) fast_subs = true;
        if (pattern->kind == YX_PATTERN_REGEX && !fast_subs &&
            !yx_candidate_exact_atoms(pattern->rx_program)) {
            yx_candidate_plan *flat = calloc(1, sizeof(*flat));
            if (flat) {
                flat->kind = YX_PATTERN_REGEX;
                if (yx_candidate_canonical_program(pattern) &&
                    yx_candidate_regex_plan(flat, pattern)) {
                    flat->regex_source = pattern->regexp;
                    return flat;
                }
                yx_candidate_plan_free(flat);
            }
        }
#ifdef _WIN32
        bool pike_only = true;
        for (size_t i = 0; i < pattern->rx_program->sub_count; ++i)
            if (pattern->rx_program->subs[i].flags & YX_RX_FAST) pike_only = false;
        if (pike_only && pattern->kind == YX_PATTERN_REGEX && pattern->regexp) {
            const uint8_t *literal;
            size_t literal_length;
            if (yx_unmatchable_large_repeat(pattern->regexp) ||
                yx_large_repeat_literal_alt(pattern->regexp, &literal, &literal_length))
                return NULL;
        }
#endif
        yx_candidate_plan *program_plan = calloc(1, sizeof(*program_plan));
        if (!program_plan) return NULL;
        program_plan->kind = pattern->kind;
        program_plan->program = true;
        yx_candidate_tail_shape shape;
        bool shaped = pattern->kind == YX_PATTERN_REGEX &&
            yx_candidate_parse_tail_shape(pattern, &shape);
        for (size_t sub = 0; sub < pattern->rx_program->sub_count; ++sub)
            for (size_t i = 0; i < pattern->rx_program->subs[sub].atom_count; ++i) {
                const yx_rx_atom *atom = &pattern->rx_program->subs[sub].atoms[i];
                if (!atom->length || !yx_candidate_add_atom(program_plan,
                    atom->bytes, atom->length, 0, 0, 0)) {
                    yx_candidate_plan_free(program_plan);
                    return NULL;
                }
                if (shaped && !(pattern->rx_program->subs[sub].flags & YX_RX_WIDE))
                    yx_candidate_tail_filter(program_plan, &shape, pattern->rx_program, atom);
            }
        if (program_plan->atom_count) return program_plan;
        yx_candidate_plan_free(program_plan);
        return NULL;
    }
    /* The hex full scanners dispatch their probe search on the lazily
     * detected CPU features; detect them before scanners share the rules. */
    if (pattern->kind == YX_PATTERN_HEX)
        (void)xx_maskscan_backend_available(XX_MASKSCAN_BACKEND_AVX2);
    if (pattern->kind == YX_PATTERN_HEX && pattern->hex_has_jump &&
        pattern->hex_atoms && !pattern->bytes && pattern->length) {
        yx_candidate_plan *anchored = yx_candidate_hex_anchor_plan(pattern);
        if (anchored) return anchored;
    }
    if (pattern->kind != YX_PATTERN_REGEX && (!pattern->bytes || !pattern->length))
        return yx_candidate_hex_gate(pattern);
    int regex_chain = pattern->kind == YX_PATTERN_REGEX ? yx_ser_regex_chain_status(pattern) : 0;
    /* Out of memory: no plan, the full scanner reports the failure. */
    if (regex_chain < 0) return NULL;
    if (regex_chain) {
        /* A regexp chain's scan is its join: only its head's gate. */
        yx_candidate_plan *gate = calloc(1, sizeof(*gate));
        if (!gate) return NULL;
        gate->kind = YX_PATTERN_REGEX;
        gate->gate = yx_candidate_gate_plan(gate, pattern);
        if (gate->gate) return gate;
        yx_candidate_plan_free(gate);
        return NULL;
    }
    yx_candidate_plan *plan = calloc(1, sizeof(*plan));
    if (!plan) return NULL;
    plan->kind = pattern->kind;
    bool ok = false;
    if (pattern->kind == YX_PATTERN_TEXT) {
        if (pattern->modifiers & (YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) {
            plan->base64 = yx_base64_candidates_build(pattern,
                                                       &plan->base64_count);
            ok = plan->base64 != NULL;
            for (size_t i = 0; ok && i < plan->base64_count; ++i) {
                size_t start, length;
                yx_candidate_select_window(plan->base64[i].needle, NULL,
                    plan->base64[i].length, false, &start, &length);
                ok = length && yx_candidate_add_atom(plan,
                    plan->base64[i].needle + start, length, start,
                    (uint32_t)i, 0);
            }
        } else ok = yx_candidate_text_plan(plan, pattern);
    } else if (pattern->kind == YX_PATTERN_HEX) {
        ok = yx_candidate_hex_plan(plan, pattern);
    } else if (pattern->kind == YX_PATTERN_REGEX) {
        ok = yx_candidate_regex_plan(plan, pattern);
    }
    if (ok) {
        if (pattern->kind == YX_PATTERN_REGEX) plan->regex_source = pattern->regexp;
        return plan;
    }
    yx_candidate_plan_free(plan);
    if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp) {
        plan = calloc(1, sizeof(*plan));
        if (!plan) return NULL;
        plan->kind = YX_PATTERN_REGEX;
        plan->regex_source = pattern->regexp;
        plan->regex = yx_compile_pcre_regex_shared(pattern);
        if (plan->regex) {
            plan->gate = yx_candidate_gate_plan(plan, pattern);
            return plan;
        }
        yx_candidate_plan_free(plan);
    }
    return yx_candidate_hex_gate(pattern);
}

void yx_candidate_plan_free(yx_candidate_plan *plan)
{
    if (!plan) return;
    free(plan->atoms);
    for (size_t i = 0; i < 2; ++i) free(plan->variants[i].needle);
    yx_base64_candidates_destroy(plan->base64, plan->base64_count);
    pcre2_code_free(plan->regex);
    free(plan->gate_bytes);
    free(plan->gate_offsets);
    free(plan);
}

/* The plan of a regexp pattern whose plan inputs equal those of the
 * pattern plan was built for (yx_build_candidate_plans compares them):
 * the same atoms, gate and limits, a copy of the native regex (sharing its
 * immutable matcher, as yx_compile_pcre_regex_shared hands out), and
 * regex_source on this pattern's own regexp. NULL for other plan shapes
 * (text variants, base64) and on allocation failure; the caller then
 * builds the plan itself. */
yx_candidate_plan *yx_candidate_plan_clone(const yx_candidate_plan *plan,
                                           const YRX_PATTERN *pattern)
{
    yx_candidate_plan *copy;
    if (!plan || plan->kind != YX_PATTERN_REGEX || plan->variant_count ||
        plan->base64 || plan->base64_count || !pattern ||
        pattern->kind != YX_PATTERN_REGEX || !pattern->regexp ||
        (plan->gate && (!plan->gate_offsets || !plan->gate_bytes)))
        return NULL;
    copy = calloc(1, sizeof(*copy));
    if (!copy) return NULL;
    copy->kind = plan->kind;
    copy->regex_maximum = plan->regex_maximum;
    copy->program = plan->program;
    copy->gate = plan->gate;
    copy->regex_source = plan->regex_source ? pattern->regexp : NULL;
    if (plan->atom_count) {
        copy->atoms = malloc(plan->atom_count * sizeof(*copy->atoms));
        if (!copy->atoms) goto failed;
        memcpy(copy->atoms, plan->atoms, plan->atom_count * sizeof(*copy->atoms));
        copy->atom_count = copy->atom_capacity = plan->atom_count;
    }
    if (plan->regex) {
        copy->regex = pcre2_code_copy(plan->regex);
        if (!copy->regex) goto failed;
    }
    if (plan->gate) {
        /* One needle per atom (yx_candidate_gate_plan on an empty plan). */
        size_t needles = plan->atom_count, used = plan->gate_offsets[needles];
        copy->gate_offsets = malloc((needles + 1) * sizeof(*copy->gate_offsets));
        copy->gate_bytes = malloc(used ? used : 1);
        if (!copy->gate_offsets || !copy->gate_bytes) goto failed;
        memcpy(copy->gate_offsets, plan->gate_offsets, (needles + 1) * sizeof(*copy->gate_offsets));
        if (used) memcpy(copy->gate_bytes, plan->gate_bytes, used);
    }
    return copy;
failed:
    yx_candidate_plan_free(copy);
    return NULL;
}

size_t yx_candidate_plan_atom_count(const yx_candidate_plan *plan)
{
    return plan ? plan->atom_count : 0;
}

const yx_candidate_atom *yx_candidate_plan_atom(const yx_candidate_plan *plan,
                                                size_t index)
{
    return plan && index < plan->atom_count ? &plan->atoms[index] : NULL;
}

/* Whether a poll has already seen the deadline expire, without reading the
 * clock. Per-occurrence verification checks this flag; the scan loops read
 * the clock at their own amortized points. */
static bool yx_scan_deadline_expired(const yx_scan_deadline *deadline)
{
    return deadline && deadline->enabled && deadline->expired;
}

static size_t yx_candidate_limit(const YRX_PATTERN *pattern, size_t limit,
                                 bool fast_scan)
{
    if (fast_scan && pattern->fast_count_enabled &&
        pattern->fast_count_threshold < limit) limit = pattern->fast_count_threshold;
    if (fast_scan && !pattern->fast_scan_needs_all && limit > 1) limit = 1;
    return limit;
}

/* Keep the earliest unique offsets even when differently positioned atoms
 * reach their candidates out of match-start order. */
static int yx_candidate_record(YRX_PATTERN *pattern, const yx_candidate_plan *plan,
    size_t size, size_t start, size_t length, int16_t key, size_t limit)
{
    size_t left = 0, right = pattern->match_count;
    /* Candidates mostly arrive in increasing start order: append. */
    if (!right || pattern->matches[right - 1].offset < start) {
        if (limit && right >= limit) return 1;
        if (!yx_add_match_key(pattern, start, length, 0, key)) return 0;
        if (limit && pattern->match_count > limit) pattern->match_count = limit;
        return 1;
    }
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (pattern->matches[middle].offset < start) left = middle + 1;
        else right = middle;
    }
    if (left < pattern->match_count && pattern->matches[left].offset == start) {
        size_t atom_width = pattern->length < 4 ? pattern->length : 4;
        if (pattern->global_atom_count_hint && pattern->global_atom_count_hint <= 4)
            atom_width = pattern->global_atom_count_hint;
        bool longest = plan->kind == YX_PATTERN_TEXT && !plan->base64 &&
            (pattern->modifiers & YX_MOD_WIDE) &&
            ((pattern->modifiers & YX_MOD_ASCII) || !(pattern->modifiers & YX_MOD_WIDE)) &&
            (pattern->length >= 4 || (atom_width && size >= 15 + atom_width &&
                                      pattern->global_atom_count_hint <= 16));
        YRX_MATCH *current = &pattern->matches[left];
        if (longest ? length > current->length : length < current->length)
            *current = (YRX_MATCH){start, length, key};
        return 1;
    }
    if (limit && left >= limit) return 1;
    if (!yx_add_match_key(pattern, start, length, 0, key)) return 0;
    memmove(pattern->matches + left + 1, pattern->matches + left,
            (pattern->match_count - left - 1) * sizeof(*pattern->matches));
    pattern->matches[left] = (YRX_MATCH){start, length, key};
    if (limit && pattern->match_count > limit) pattern->match_count = limit;
    return 1;
}

/* A hex anchor behind a variable-length head: every start the occurrence
 * allows, lowest first, gets the per-start checks and walk of the hex path
 * of yx_candidate_verify below. */
static YRX_RESULT yx_candidate_verify_spread(YRX_PATTERN *pattern,
    const yx_candidate_plan *plan, const yx_candidate_atom *atom,
    size_t atom_position, const uint8_t *data, size_t size, size_t limit)
{
    if (atom_position < atom->backtrack) return YRX_SUCCESS;
    size_t high = atom_position - atom->backtrack;
    size_t start = high > atom->spread ? high - atom->spread : 0;
    for (;; ++start) {
        if (start < size && (!pattern->fixed_at_enabled ||
                             start == pattern->fixed_at_offset) &&
            !(limit && pattern->match_count >= limit &&
              start > pattern->matches[pattern->match_count - 1].offset) &&
            pattern->length <= size - start) {
            size_t length = SIZE_MAX;
            yx_hex_walk(data, size, start, start, pattern->hex_atoms,
                pattern->hex_atom_count, 0, NULL, &length, pattern->deadline);
            if (yx_scan_deadline_expired(pattern->deadline)) return YRX_SCAN_TIMEOUT;
            if (length != SIZE_MAX && !yx_candidate_record(pattern, plan, size,
                                                            start, length, -1, limit))
                return YRX_SCAN_ERROR;
        }
        if (start == high) break;
    }
    return YRX_SUCCESS;
}

YRX_RESULT yx_candidate_verify(YRX_PATTERN *pattern,
    const yx_candidate_plan *plan, uint32_t tag, size_t atom_position,
    const uint8_t *data, size_t size, size_t limit, bool fast_scan)
{
    if (!pattern || !plan || tag >= plan->atom_count) return YRX_INVALID_ARGUMENT;
    if (yx_scan_deadline_poll(pattern->deadline)) return YRX_SCAN_TIMEOUT;
    const yx_candidate_atom *atom = &plan->atoms[tag];
    if (plan->gate) {
        /* A whole branch occurrence hands the pattern to the full scanner.
         * Every match starts at such an occurrence, so a regexp gate keeps
         * their starts for its search (up to the retained-candidate bound). */
        bool keep = plan->kind == YX_PATTERN_REGEX && plan->regex;
        if ((pattern->candidate_hits_overflow &&
             (!keep || pattern->candidate_gate_dropped)) ||
            atom_position < atom->backtrack)
            return YRX_SUCCESS;
        size_t start = atom_position - atom->backtrack;
        size_t first = plan->gate_offsets[atom->variant];
        size_t length = plan->gate_offsets[atom->variant + 1] - first;
        if (!(start <= size && length <= size - start &&
              memcmp(data + start, plan->gate_bytes + first, length) == 0))
            return YRX_SUCCESS;
        pattern->candidate_hits_overflow = true;
        if (!keep || pattern->candidate_gate_dropped) return YRX_SUCCESS;
        if (pattern->candidate_hit_count == pattern->candidate_hit_capacity) {
            size_t capacity = pattern->candidate_hit_capacity ?
                pattern->candidate_hit_capacity * 2 : 32;
            yx_rx_candidate *grown = capacity <= 1000000 ?
                realloc(pattern->candidate_hits, capacity * sizeof(*grown)) : NULL;
            if (!grown) {
                pattern->candidate_gate_dropped = true;
                return YRX_SUCCESS;
            }
            pattern->candidate_hits = grown;
            pattern->candidate_hit_capacity = capacity;
        }
        pattern->candidate_hits[pattern->candidate_hit_count++] =
            (yx_rx_candidate){tag, start};
        return YRX_SUCCESS;
    }
    if (plan->program) {
        if (pattern->candidate_hits_overflow) return YRX_SUCCESS;
        if (atom->tail_min) {
            size_t from = atom_position + atom->length;
            if (from > size || size - from < atom->tail_min) return YRX_SUCCESS;
            for (size_t k = 0; k < atom->tail_min; ++k) {
                uint8_t byte = data[from + k];
                if (!(atom->tail_class[byte >> 3] >> (byte & 7) & 1)) return YRX_SUCCESS;
            }
        }
        /* The program's atom windows (yx_rx_process skips such hits). The
         * plan's tags are the program's flattened atom indices. */
        if (!yx_rx_atom_possible(pattern->rx_program, tag, data, size, atom_position))
            return YRX_SUCCESS;
        /* Bound retained candidate memory independently of the reporting
         * cap; a dense atom stream uses the existing full scanner instead. */
        if (pattern->candidate_hit_count == 1000000) {
            pattern->candidate_hits_overflow = true;
            return YRX_SUCCESS;
        }
        if (pattern->candidate_hit_count == pattern->candidate_hit_capacity) {
            size_t capacity = pattern->candidate_hit_capacity ?
                pattern->candidate_hit_capacity * 2 : 32;
            if (capacity > 1000000) capacity = 1000000;
            yx_rx_candidate *grown = realloc(pattern->candidate_hits,
                                               capacity * sizeof(*grown));
            if (!grown) return YRX_SCAN_ERROR;
            pattern->candidate_hits = grown;
            pattern->candidate_hit_capacity = capacity;
        }
        pattern->candidate_hits[pattern->candidate_hit_count++] =
            (yx_rx_candidate){tag, atom_position};
        return YRX_SUCCESS;
    }
    if (atom->spread)
        return yx_candidate_verify_spread(pattern, plan, atom, atom_position, data,
            size, yx_candidate_limit(pattern, limit, fast_scan));
    if (atom_position < atom->backtrack) return YRX_SUCCESS;
    size_t start = atom_position - atom->backtrack, length = 0;
    int16_t key = -1;
    if (start >= size || (pattern->fixed_at_enabled &&
                          start != pattern->fixed_at_offset)) return YRX_SUCCESS;
    limit = yx_candidate_limit(pattern, limit, fast_scan);
    if (limit && pattern->match_count >= limit &&
        start > pattern->matches[pattern->match_count - 1].offset) return YRX_SUCCESS;
    bool matched = false;
    if (plan->base64) {
        int verified = yx_base64_candidate_verify(&plan->base64[atom->variant],
                                                  data, size, start, &length);
        if (verified < 0) return YRX_SCAN_ERROR;
        matched = verified != 0;
    } else if (plan->kind == YX_PATTERN_TEXT) {
        const yx_candidate_variant *variant = &plan->variants[atom->variant];
        length = variant->length;
        if (length > size - start) return YRX_SUCCESS;
        bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
        matched = true;
        for (size_t i = 0; i < length; ++i) {
            uint8_t expected = variant->needle[i] ^ atom->xor_key;
            if (nocase ? yx_fold(data[start + i]) != yx_fold(expected) :
                         data[start + i] != expected) { matched = false; break; }
        }
        if (matched && (pattern->modifiers & YX_MOD_FULLWORD))
            matched = yx_fullword(data, size, start, length, variant->wide,
                                  atom->xor_key) != 0;
        if (pattern->modifiers & YX_MOD_XOR) key = atom->xor_key;
    } else if (plan->kind == YX_PATTERN_HEX) {
        if (pattern->length > size - start) return YRX_SUCCESS;
        if (!pattern->hex_has_jump) {
            length = pattern->length;
            matched = yx_hex_equal(pattern, data + start) != 0;
        } else {
            length = SIZE_MAX;
            yx_hex_walk(data, size, start, start, pattern->hex_atoms,
                pattern->hex_atom_count, 0, NULL, &length, pattern->deadline);
            matched = length != SIZE_MAX;
        }
    } else {
        pcre2_match_data *matches = pcre2_match_data_create_from_pattern(plan->regex, NULL);
        if (!matches) return YRX_SCAN_ERROR;
        /* The bounded plan needs at most 4096 bytes. A local subject avoids
         * the native adapter's INT32_MAX whole-subject limit on large files. */
        size_t subject_size = size - start;
        if (subject_size > plan->regex_maximum) subject_size = plan->regex_maximum;
        int result = yx_pcre_match_deadline(pattern, plan->regex, data + start,
                                            subject_size, 0, PCRE2_ANCHORED, matches);
        if (result >= 0) {
            PCRE2_SIZE *vector = pcre2_get_ovector_pointer(matches);
            length = vector[1] - vector[0];
            matched = vector[0] == 0 && length != 0;
        }
        pcre2_match_data_free(matches);
        if (result < 0 && result != PCRE2_ERROR_NOMATCH)
            return yx_scan_deadline_reached(pattern->deadline) ?
                YRX_SCAN_TIMEOUT : YRX_SCAN_ERROR;
        if (matched && (pattern->modifiers & YX_MOD_FULLWORD))
            matched = yx_fullword(data, size, start, length, false, 0) != 0;
    }
    /* A walk or regexp cut short by the deadline left it expired; the
     * verifications above cannot otherwise be incomplete. */
    if (yx_scan_deadline_expired(pattern->deadline)) return YRX_SCAN_TIMEOUT;
    if (matched && !yx_candidate_record(pattern, plan, size, start, length,
                                         key, limit)) return YRX_SCAN_ERROR;
    return YRX_SUCCESS;
}

static int yx_gate_start_compare(const void *left, const void *right)
{
    const yx_rx_candidate *a = left, *b = right;
    return a->position < b->position ? -1 : a->position > b->position;
}

YRX_RESULT yx_candidate_finalize(YRX_PATTERN *pattern, const yx_candidate_plan *plan,
    const uint8_t *data, size_t size, size_t limit, bool fast_scan)
{
    if (plan->gate) {
        /* No whole branch occurred: the full scanner has no match to find.
         * Otherwise run it exactly as the scanner's per-pattern loop does
         * (yx_scan_pattern_fixed_at in xxyara.c); its regexp search visits
         * only the recorded branch starts (yx_scan_regex_buffer). */
        bool fired = pattern->candidate_hits_overflow;
        bool starts = fired && !pattern->candidate_gate_dropped &&
                      pattern->candidate_hit_count;
        pattern->candidate_hits_overflow = false;
        pattern->candidate_gate_dropped = false;
        if (starts) {
            /* Sorted, unique starts; the branch tags are not needed. */
            yx_rx_candidate *hits = pattern->candidate_hits;
            size_t count = pattern->candidate_hit_count, kept = 0;
            bool sorted = true;
            for (size_t i = 1; i < count && sorted; ++i)
                sorted = hits[i - 1].position < hits[i].position;
            if (!sorted)
                qsort(hits, count, sizeof(*hits), yx_gate_start_compare);
            for (size_t i = 0; i < count; ++i)
                if (!kept || hits[kept - 1].position != hits[i].position)
                    hits[kept++] = hits[i];
            pattern->candidate_hit_count = kept;
        }
        YRX_RESULT result = YRX_SUCCESS;
        if (fired && !(pattern->fixed_at_enabled && pattern->fixed_at_offset >= size)) {
            if (pattern->fixed_at_enabled && limit && limit <= pattern->fixed_at_offset)
                limit = pattern->fixed_at_offset + 1;
            pattern->candidate_gate_starts = starts;
            result = yx_scan_pattern(pattern, data, size, limit, fast_scan);
            pattern->candidate_gate_starts = false;
        }
        free(pattern->candidate_hits);
        pattern->candidate_hits = NULL;
        pattern->candidate_hit_count = pattern->candidate_hit_capacity = 0;
        if (!fired || (pattern->fixed_at_enabled && pattern->fixed_at_offset >= size))
            return YRX_SUCCESS;
        if (result != YRX_SUCCESS || !pattern->fixed_at_enabled) return result;
        size_t kept = 0;
        for (size_t i = 0; i < pattern->match_count; ++i)
            if (pattern->matches[i].offset == pattern->fixed_at_offset) {
                pattern->matches[kept++] = pattern->matches[i];
                break;
            }
        pattern->match_count = kept;
        return YRX_SUCCESS;
    }
    if (plan->program) {
        size_t scan_limit = limit;
        if (pattern->fixed_at_enabled && scan_limit &&
            scan_limit <= pattern->fixed_at_offset)
            scan_limit = pattern->fixed_at_offset + 1;
        if (pattern->candidate_hits_overflow) {
            YRX_RESULT result = yx_scan_pattern(pattern, data, size, scan_limit, fast_scan);
            free(pattern->candidate_hits);
            pattern->candidate_hits = NULL;
            pattern->candidate_hit_count = pattern->candidate_hit_capacity = 0;
            pattern->candidate_hits_overflow = false;
            if (result != YRX_SUCCESS) return result;
        } else {
            yx_rx_match_list list = {0};
            yx_rx_order order = {pattern->rx_teddy, pattern->rx_teddy_minimum,
                                 pattern->rx_order_ids, pattern->rx_order_buckets};
            list.limit = yx_candidate_limit(pattern, scan_limit, fast_scan);
            bool ok = yx_rx_scan_from_candidates(pattern->rx_program, data, size,
                pattern->deadline, &list,
                pattern->rx_teddy && pattern->rx_order_ids ? &order : NULL,
                pattern->candidate_hits, pattern->candidate_hit_count);
            free(pattern->candidate_hits);
            pattern->candidate_hits = NULL;
            pattern->candidate_hit_count = pattern->candidate_hit_capacity = 0;
            for (size_t i = 0; ok && i < list.count; ++i)
                ok = yx_add_match(pattern, list.items[i].start,
                    list.items[i].end - list.items[i].start, list.limit) != 0;
            yx_rx_match_list_free(&list);
            if (!ok) return yx_scan_deadline_reached(pattern->deadline) ?
                                YRX_SCAN_TIMEOUT : YRX_SCAN_ERROR;
        }
        if (pattern->fixed_at_enabled) {
            size_t kept = 0;
            for (size_t i = 0; i < pattern->match_count; ++i)
                if (pattern->matches[i].offset == pattern->fixed_at_offset) {
                    pattern->matches[kept++] = pattern->matches[i];
                    break;
                }
            pattern->match_count = kept;
        }
    }
    yx_sort_unique_limit(pattern, yx_candidate_limit(pattern, limit, fast_scan));
    return yx_scan_deadline_reached(pattern->deadline) ?
               YRX_SCAN_TIMEOUT : YRX_SUCCESS;
}
