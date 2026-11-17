/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
#include "native_regex.h"
#include "serialization.h"
#include "regex_vm.h"
#include "xxfclib/regex/xx_regex.h"
#include "xxfclib/regex/xx_regex_unicode16.h"
#include "xxfclib/rt/xx_rt.h"
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct yx_native_regex {
    xx_regex *regex;
    uint32_t options;
    unsigned special;
    /* Immutable Boolean search program, shared by evaluations of the node. */
    uint8_t *search;
    size_t search_length;
};
typedef struct { char *data; size_t size, capacity; } re_text;
static bool append(re_text *out, const char *text, size_t size)
{
    if (size > SIZE_MAX - out->size - 1) return false;
    size_t needed = out->size + size + 1;
    if (needed > out->capacity) {
        size_t capacity = out->capacity ? out->capacity : 128;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) { capacity = needed; break; }
            capacity *= 2;
        }
        char *grown = realloc(out->data, capacity);
        if (!grown) return false;
        out->data = grown; out->capacity = capacity;
    }
    if (size) memcpy(out->data + out->size, text, size);
    out->size += size; out->data[out->size] = 0; return true;
}
static bool put(re_text *out, const char *text) { return append(out, text, strlen(text)); }
static bool byte(re_text *out, unsigned value)
{
    char text[5]; snprintf(text, sizeof(text), "\\x%02X", value & 255);
    return append(out, text, 4);
}
static size_t decode(const unsigned char *data, size_t length, uint32_t *scalar)
{
    if (!length) return 0;
    uint32_t cp = data[0]; size_t width;
    if (cp < 128) { *scalar = cp; return 1; }
    if (cp >= 0xc2 && cp <= 0xdf) { width = 2; cp &= 31; }
    else if (cp >= 0xe0 && cp <= 0xef) { width = 3; cp &= 15; }
    else if (cp >= 0xf0 && cp <= 0xf4) { width = 4; cp &= 7; }
    else return 0;
    if (width > length) return 0;
    for (size_t i = 1; i < width; ++i) {
        if ((data[i] & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (data[i] & 63);
    }
    if ((width == 2 && cp < 128) || (width == 3 && cp < 0x800) ||
        (width == 4 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
    *scalar = cp; return width;
}
static bool scalar(re_text *out, uint32_t cp, bool grouped)
{
    unsigned char bytes[4]; size_t n;
    if (cp < 128) { bytes[0] = (unsigned char)cp; n = 1; }
    else if (cp < 0x800) { bytes[0] = (unsigned char)(0xc0 | (cp >> 6)); bytes[1] = 0x80 | (cp & 63); n = 2; }
    else if (cp < 0x10000 && !(cp >= 0xd800 && cp <= 0xdfff)) {
        bytes[0] = (unsigned char)(0xe0 | (cp >> 12)); bytes[1] = 0x80 | ((cp >> 6) & 63); bytes[2] = 0x80 | (cp & 63); n = 3;
    } else if (cp <= 0x10ffff && cp >= 0x10000) {
        bytes[0] = (unsigned char)(0xf0 | (cp >> 18)); bytes[1] = 0x80 | ((cp >> 12) & 63);
        bytes[2] = 0x80 | ((cp >> 6) & 63); bytes[3] = 0x80 | (cp & 63); n = 4;
    } else return false;
    if (grouped && !put(out, "(?:")) return false;
    for (size_t i = 0; i < n; ++i) if (!byte(out, bytes[i])) return false;
    return !grouped || put(out, ")");
}
static int hex(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

typedef yx_re_range re_range;
typedef struct { re_range *ranges; size_t count, capacity; } re_set;
/* regex-syntax 0.8.11's Unicode 16.0.0 tables live in xxfclib
 * (xx_regex_unicode16.h). */

static bool set_has(const re_set *set, uint32_t point)
{
    size_t first = 0, last = set->count;
    while (first < last) {
        size_t middle = first + (last - first) / 2;
        if (set->ranges[middle].last < point) first = middle + 1;
        else last = middle;
    }
    return first < set->count && set->ranges[first].first <= point;
}

static bool set_add(re_set *set, uint32_t first, uint32_t last)
{
    size_t begin = 0, end;
    if (first > last || last > 0x10ffff) return false;
    while (begin < set->count && set->ranges[begin].last + 1 < first) ++begin;
    end = begin;
    while (end < set->count && set->ranges[end].first <= last + 1) {
        if (set->ranges[end].first < first) first = set->ranges[end].first;
        if (set->ranges[end].last > last) last = set->ranges[end].last;
        ++end;
    }
    if (begin == end && set->count == set->capacity) {
        size_t capacity = set->capacity ? set->capacity * 2 : 8;
        if (capacity < set->capacity || capacity > SIZE_MAX / sizeof(*set->ranges)) return false;
        re_range *grown = realloc(set->ranges, capacity * sizeof(*grown));
        if (!grown) return false;
        set->ranges = grown; set->capacity = capacity;
    }
    memmove(set->ranges + begin + 1, set->ranges + end,
            (set->count - end) * sizeof(*set->ranges));
    set->count = set->count - (end - begin) + 1;
    set->ranges[begin] = (re_range){first, last};
    return true;
}

static bool set_union(re_set *set, const re_set *other)
{
    for (size_t i = 0; i < other->count; ++i)
        if (!set_add(set, other->ranges[i].first, other->ranges[i].last)) return false;
    return true;
}

/* yx_re_class_ranges_gap: sets model regex-syntax's ranges of chars. A range
 * of chars either has no surrogate or spans the whole gap (its u32 range
 * then holds every surrogate); [\x{0}-\x{D7FF}\x{E000}-\x{10FFFF}] stays two
 * ranges, as IntervalSet::canonicalize compares u32 bounds. */
static _Thread_local bool re_keep_gap;

/* Drops the surrogates of ranges that do not span the gap. */
static bool set_gap_trim(re_set *set)
{
    size_t used = 0;
    for (size_t i = 0; i < set->count; ++i) {
        re_range range = set->ranges[i];
        if (range.first >= 0xd800 && range.first <= 0xdfff) range.first = 0xe000;
        if (range.last >= 0xd800 && range.last <= 0xdfff) range.last = 0xd7ff;
        if (range.first <= range.last) set->ranges[used++] = range;
    }
    set->count = used;
    return true;
}

/* IntervalSet::negate over chars: char increment and decrement skip the
 * surrogates, and Interval::create swaps reversed bounds, so the complement
 * of ...-\x{D7FF} \x{E000}-... has the range \x{D7FF}-\x{E000}. The ranges
 * are appended in order without merging when `ranges` is given (a top-level
 * negated class is not canonicalized again), else added to the set. */
static bool set_invert_chars(re_set *set, re_set *ranges)
{
    re_set complement = {0};
    size_t count = set->count;
    if (!set_gap_trim(set)) return false;
    count = set->count;
    for (size_t i = 0; i <= count; ++i) {
        uint32_t first, last;
        if (!count) { first = 0; last = 0x10ffff; if (i) break; }
        else if (i == 0) {
            if (set->ranges[0].first == 0) continue;
            first = 0;
            last = set->ranges[0].first == 0xe000 ? 0xd7ff : set->ranges[0].first - 1;
        } else if (i == count) {
            if (set->ranges[count - 1].last == 0x10ffff) continue;
            first = set->ranges[count - 1].last == 0xd7ff ? 0xe000 : set->ranges[count - 1].last + 1;
            last = 0x10ffff;
        } else {
            first = set->ranges[i - 1].last == 0xd7ff ? 0xe000 : set->ranges[i - 1].last + 1;
            last = set->ranges[i].first == 0xe000 ? 0xd7ff : set->ranges[i].first - 1;
            if (first > last) { uint32_t swap = first; first = last; last = swap; }
        }
        if (!ranges) {
            if (!set_add(&complement, first, last)) goto failed;
            continue;
        }
        if (complement.count == complement.capacity) {
            size_t capacity = complement.capacity ? complement.capacity * 2 : 8;
            re_range *grown = realloc(complement.ranges, capacity * sizeof(*grown));
            if (!grown) goto failed;
            complement.ranges = grown; complement.capacity = capacity;
        }
        complement.ranges[complement.count++] = (re_range){first, last};
    }
    if (ranges) { *ranges = complement; return true; }
    free(set->ranges); *set = complement; return true;
failed:
    free(complement.ranges); return false;
}

static bool set_invert(re_set *set)
{
    re_set complement = {0};
    uint32_t first = 0;
    if (re_keep_gap) return set_invert_chars(set, NULL);
    for (size_t i = 0; i < set->count; ++i) {
        if (first < set->ranges[i].first &&
            !set_add(&complement, first, set->ranges[i].first - 1)) goto failed;
        first = set->ranges[i].last + 1;
    }
    if (first <= 0x10ffff && !set_add(&complement, first, 0x10ffff)) goto failed;
    free(set->ranges); *set = complement; return true;
failed:
    free(complement.ranges); return false;
}

static bool set_fold(re_set *set)
{
    /* regex-syntax's table already contains every member of each simple
     * case-fold equivalence class (Unicode 16.0.0, not the host Unicode). */
    re_set additions = {0};
    size_t fold_count;
    const xx_regex_unicode16_fold *folds = xx_regex_unicode16_folds(&fold_count);
    for (size_t i = 0; i < fold_count; ++i) {
        const xx_regex_unicode16_fold *fold = folds + i;
        if (!set_has(set, fold->from)) continue;
        for (size_t j = 0; j < fold->count; ++j)
            if (!set_add(&additions, fold->to[j], fold->to[j])) {
                free(additions.ranges); return false;
            }
    }
    bool ok = set_union(set, &additions);
    free(additions.ranges); return ok;
}

static bool set_fold_mode(re_set *set, bool unicode)
{
    if (unicode) return set_fold(set);
    for (uint32_t cp = 'A'; cp <= 'Z'; ++cp)
        if ((set_has(set, cp) || set_has(set, cp + 32)) &&
            (!set_add(set, cp, cp) || !set_add(set, cp + 32, cp + 32))) return false;
    return true;
}

static bool set_intersect(re_set *set, const re_set *other)
{
    re_set result = {0}; size_t i = 0, j = 0;
    while (i < set->count && j < other->count) {
        uint32_t first = set->ranges[i].first > other->ranges[j].first ?
                         set->ranges[i].first : other->ranges[j].first;
        uint32_t last = set->ranges[i].last < other->ranges[j].last ?
                        set->ranges[i].last : other->ranges[j].last;
        if (first <= last && !set_add(&result, first, last)) {
            free(result.ranges); return false;
        }
        if (set->ranges[i].last < other->ranges[j].last) ++i; else ++j;
    }
    free(set->ranges); *set = result; return true;
}

static bool set_difference(re_set *set, const re_set *other)
{
    re_set result = {0}; size_t j = 0;
    for (size_t i = 0; i < set->count; ++i) {
        uint32_t first = set->ranges[i].first, last = set->ranges[i].last;
        while (j < other->count && other->ranges[j].last < first) ++j;
        for (size_t k = j; k < other->count && other->ranges[k].first <= last; ++k) {
            if (first < other->ranges[k].first &&
                !set_add(&result, first, other->ranges[k].first - 1)) goto failed;
            if (other->ranges[k].last >= last) { first = last + 1; break; }
            first = other->ranges[k].last + 1;
        }
        if (first <= last && !set_add(&result, first, last)) goto failed;
    }
    free(set->ranges); *set = result; return true;
failed:
    free(result.ranges); return false;
}

static bool set_symmetric(re_set *set, re_set *other)
{
    re_set common = {0};
    bool ok = set_union(&common, set) && set_intersect(&common, other) &&
              set_union(set, other) && set_difference(set, &common);
    free(common.ranges); return ok;
}

static bool set_domain(re_set *set, bool unicode)
{
    if (unicode && re_keep_gap) return set_gap_trim(set);
    re_range valid[] = {{0, unicode ? 0xd7ffu : 255u}, {0xe000, 0x10ffff}};
    re_set domain = {valid, unicode ? 2u : 1u, 2u};
    return set_intersect(set, &domain);
}

static size_t encode(uint32_t cp, unsigned char bytes[4])
{
    if (cp < 0x80) { bytes[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800) { bytes[0] = (unsigned char)(0xc0 | (cp >> 6)); bytes[1] = 0x80 | (cp & 63); return 2; }
    if (cp < 0x10000) {
        bytes[0] = (unsigned char)(0xe0 | (cp >> 12)); bytes[1] = 0x80 | ((cp >> 6) & 63); bytes[2] = 0x80 | (cp & 63); return 3;
    }
    bytes[0] = (unsigned char)(0xf0 | (cp >> 18)); bytes[1] = 0x80 | ((cp >> 12) & 63);
    bytes[2] = 0x80 | ((cp >> 6) & 63); bytes[3] = 0x80 | (cp & 63); return 4;
}

static bool byte_range(re_text *out, unsigned first, unsigned last)
{
    return first == last ? byte(out, first) :
        put(out, "[") && byte(out, first) && put(out, "-") && byte(out, last) && put(out, "]");
}

/* An interval of equally long UTF-8 encodings is a lexicographic byte
 * interval. Split only its two boundary prefixes; the middle prefixes share
 * unrestricted continuation bytes. This keeps even whole-plane classes small. */
static bool encoded_range(re_text *out, const unsigned char *first,
                           const unsigned char *last, size_t width, size_t at)
{
    if (at == width) return true;
    if (first[at] == last[at])
        return byte(out, first[at]) && encoded_range(out, first, last, width, at + 1);
    if (at + 1 == width) return byte_range(out, first[at], last[at]);
    unsigned char low_end[4], high_start[4];
    memcpy(low_end, first, width); memcpy(high_start, last, width);
    for (size_t i = at + 1; i < width; ++i) { low_end[i] = 0xbf; high_start[i] = 0x80; }
    if (!put(out, "(?:") || !byte(out, first[at]) ||
        !encoded_range(out, first, low_end, width, at + 1)) return false;
    if (first[at] + 1u < last[at]) {
        if (!put(out, "|") || !byte_range(out, first[at] + 1, last[at] - 1)) return false;
        for (size_t i = at + 1; i < width; ++i)
            if (!byte_range(out, 0x80, 0xbf)) return false;
    }
    return put(out, "|") && byte(out, last[at]) &&
        encoded_range(out, high_start, last, width, at + 1) && put(out, ")");
}

static bool emit_set(re_text *out, const re_set *set)
{
    static const re_range valid[] = {
        {0, 0x7f}, {0x80, 0x7ff}, {0x800, 0xd7ff},
        {0xe000, 0xffff}, {0x10000, 0x10ffff}
    };
    bool emitted = false;
    /* The scalar fold closure is explicit. Byte-engine case conversion must
     * not change any byte of a multibyte UTF-8 encoding. */
    if (!put(out, "(?-i:(?:")) return false;
    for (size_t i = 0; i < set->count; ++i) {
        for (size_t j = 0; j < sizeof(valid) / sizeof(valid[0]); ++j) {
            uint32_t first = set->ranges[i].first > valid[j].first ? set->ranges[i].first : valid[j].first;
            uint32_t last = set->ranges[i].last < valid[j].last ? set->ranges[i].last : valid[j].last;
            unsigned char first_bytes[4], last_bytes[4];
            if (first > last) continue;
            if (emitted && !put(out, "|")) return false;
            size_t width = encode(first, first_bytes);
            encode(last, last_bytes);
            if (!encoded_range(out, first_bytes, last_bytes, width, 0)) return false;
            emitted = true;
        }
    }
    /* A surrogate-only class is the empty set of Unicode scalars. */
    if (!emitted && !put(out, "(?!)")) return false;
    return put(out, "))");
}

static bool emit_scalar(re_text *out, uint32_t cp, bool nocase)
{
    re_set set = {0};
    bool ok = set_add(&set, cp, cp) && (!nocase || set_fold(&set)) && emit_set(out, &set);
    free(set.ranges); return ok;
}

char *yx_re_ranges_pattern(const yx_re_range *ranges, size_t count)
{
    re_text out = {0};
    re_set set = {(re_range *)ranges, count, count};
    if (!emit_set(&out, &set)) { free(out.data); return NULL; }
    return out.data;
}

#define UT_FIND(table, name) xx_regex_unicode16_find(XX_REGEX_UNICODE16_##table, name)

static char *property_normalize(const char *name, size_t length)
{
    char *result = malloc(length + 4); size_t used = 0, at = 0;
    if (!result) return NULL;
    bool is = length >= 2 && (name[0] == 'i' || name[0] == 'I') &&
                              (name[1] == 's' || name[1] == 'S');
    if (is) at = 2;
    for (; at < length; ++at) {
        unsigned char ch = (unsigned char)name[at];
        if (ch == ' ' || ch == '_' || ch == '-' || ch >= 128) continue;
        result[used++] = ch >= 'A' && ch <= 'Z' ? (char)(ch + 32) : (char)ch;
    }
    if (is && used == 1 && result[0] == 'c') {
        memcpy(result, "isc", 3); used = 3;
    }
    result[used] = 0; return result;
}

/* Return a table index, or -1 for an unknown property and -2 for an
 * unknown property value. Age is the cumulative union through that table. */
static int property_lookup(const char *name, size_t length, bool *negative, bool *age)
{
    size_t split = 0, value = 0; int found = -1;
    *age = false;
    while (split < length && name[split] != '=' && name[split] != ':' &&
           !(name[split] == '!' && split + 1 < length && name[split + 1] == '=')) ++split;
    char *key = property_normalize(name, split);
    if (!key) return -1;
    int prop = UT_FIND(PROPERTY_NAMES, key);
    if (split == length) {
        /* cf, sc and lc are general categories, even though those aliases
         * also denote unsupported Unicode mapping/catalogue properties. */
        if (prop >= 0 && strcmp(key, "cf") && strcmp(key, "sc") && strcmp(key, "lc")) {
            char id[16]; snprintf(id, sizeof(id), "%d", prop);
            found = UT_FIND(BINARY_PROPERTIES, id);
        } else {
            found = UT_FIND(GENERAL_CATEGORY, key);
            if (found == -1) found = UT_FIND(SCRIPT, key);
        }
    } else if (prop >= 0) {
        value = split + 1;
        if (name[split] == '!') { *negative = !*negative; ++value; }
        char *val = property_normalize(name + value, length - value);
        if (!val) { free(key); return -1; }
        /* Only the enumerated properties have value tables; Age values are
         * cumulative. */
        xx_regex_unicode16_names values = xx_regex_unicode16_property_values((uint32_t)prop);
        if (values != XX_REGEX_UNICODE16_NAMES_COUNT) found = xx_regex_unicode16_find(values, val);
        if (values == XX_REGEX_UNICODE16_AGE) *age = true;
        if (found < 0) found = -2;
        free(val);
    }
    free(key); return found;
}

const char *yx_re_property_error(const char *name, size_t length)
{
    bool negative = false, age;
    int id = property_lookup(name, length, &negative, &age);
    return id >= 0 ? NULL : id == -2 ? "Unicode property value not found" :
                                     "Unicode property not found";
}

static bool add_table(re_set *set, uint32_t id)
{
    const xx_regex_unicode16_table *table = xx_regex_unicode16_table_at(id);
    if (!table) return false;
    for (size_t i = 0; i < table->count; ++i)
        if (!set_add(set, table->ranges[i].first, table->ranges[i].last)) return false;
    /* The tables are split at the surrogate gap; regex-syntax's hold one
     * range of chars across it (Any, Other, Unknown). */
    for (size_t i = 0; re_keep_gap && i + 1 < set->count; ++i)
        if (set->ranges[i].last == 0xd7ff && set->ranges[i + 1].first == 0xe000)
            return set_add(set, 0xd7ff, 0xe000);
    return true;
}

static bool property_base(re_set *set, const char *name, size_t length, bool *negative)
{
    bool age; int id = property_lookup(name, length, negative, &age);
    if (id < 0) return false;
    if (age) {
        size_t age_count;
        const uint32_t *ages = xx_regex_unicode16_ages(&age_count);
        for (size_t i = 0; i < age_count; ++i) {
            if (!add_table(set, ages[i])) return false;
            if (ages[i] == (uint32_t)id) break;
        }
    } else if (!add_table(set, (uint32_t)id)) return false;
    return set_domain(set, true);
}

static bool property(re_set *set, const char *name, size_t length)
{
    bool negative = false;
    return property_base(set, name, length, &negative) &&
           (!negative || set_invert(set)) && set_domain(set, true);
}

int yx_re_property_ranges(const char *name, size_t length, int negative,
                          yx_re_range **ranges, size_t *count)
{
    re_set set = {0};
    if (!ranges || !count || !name) return 0;
    *ranges = NULL; *count = 0;
    if (!property(&set, name, length) || (negative && !set_invert(&set)) ||
        !set_domain(&set, true)) { free(set.ranges); return 0; }
    *ranges = set.ranges; *count = set.count; return 1;
}

static bool property_escape(re_set *set, const unsigned char *pattern,
                             size_t length, size_t *at, bool negative, bool nocase)
{
    size_t start = *at, end;
    if (start == length) return false;
    if (pattern[start] == '{') {
        ++start;
        end = start;
        while (end < length && pattern[end] != '}') ++end;
        if (end == length) return false;
        *at = end + 1;
    } else { end = start + 1; *at = end; }
    /* regex-syntax folds the positive property before either spelling of
     * negation (P or !=). Folding its complement could add letters back. */
    return property_base(set, (const char *)pattern + start, end - start, &negative) &&
           (!nocase || set_fold(set)) && (!negative || set_invert(set)) &&
           set_domain(set, true);
}

static int capture_name_status(re_text *names, const unsigned char *name,
                                 size_t length)
{
    size_t at = 0;
    if (!length) return 0;
    while (at < length) {
        uint32_t cp;
        size_t width = decode(name + at, length - at, &cp);
        if (!width || !(cp == '_' ||
            xx_regex_unicode_property(cp, XX_REGEX_UNICODE_ALPHABETIC) ||
            (at && (cp == '.' || cp == '[' || cp == ']' ||
                    xx_regex_unicode_property(cp, XX_REGEX_UNICODE_NUMERIC)))))
            return 0;
        at += width;
    }
    for (at = 0; at < names->size;) {
        size_t previous = strlen(names->data + at);
        if (previous == length && !memcmp(names->data + at, name, length))
            return 0;
        at += previous + 1;
    }
    return append(names, (const char *)name, length) && append(names, "", 1) ? 1 : -1;
}
static bool capture_name(re_text *names, const unsigned char *name, size_t length)
{
    return capture_name_status(names, name, length) == 1;
}
int yx_re_capture_name_append(char **names, size_t *used, size_t *capacity,
                               const unsigned char *name, size_t length)
{
    re_text registry = {*names, *used, *capacity};
    int status = capture_name_status(&registry, name, length);
    *names = registry.data; *used = registry.size; *capacity = registry.capacity;
    return status;
}

static bool shorthand(re_set *set, unsigned char escape, bool ucp)
{
    unsigned char lower = escape | 0x20;
    if (ucp) {
        size_t id = xx_regex_unicode16_class_table(
            lower == 'd' ? XX_REGEX_UNICODE16_DECIMAL :
            lower == 's' ? XX_REGEX_UNICODE16_SPACE : XX_REGEX_UNICODE16_WORD);
        if (id > UINT32_MAX || !add_table(set, (uint32_t)id)) return false;
    } else if (lower == 'd') {
        if (!set_add(set, '0', '9')) return false;
    } else if (lower == 's') {
        if (!set_add(set, 9, 13) || !set_add(set, 32, 32)) return false;
    } else if (lower == 'w') {
        if (!set_add(set, '0', '9') || !set_add(set, 'A', 'Z') ||
            !set_add(set, '_', '_') || !set_add(set, 'a', 'z')) return false;
    } else return false;
    return escape == lower || set_invert(set);
}

/* Read one Unicode class atom. Set-valued escapes cannot be range endpoints. */
static bool class_atom(const unsigned char *pattern, size_t length, size_t *at,
                         uint32_t *cp, bool *single, re_set *set, bool ucp,
                         bool nocase)
{
    if (*at >= length) return false;
    unsigned char ch = pattern[(*at)++];
    *single = true;
    if (ch != '\\') {
        size_t width = decode(pattern + *at - 1, length - *at + 1, cp);
        if (!width) return false;
        *at += width - 1; return true;
    }
    if (*at >= length) return false;
    ch = pattern[(*at)++];
    if (strchr("dDsSwW", ch)) { *single = false; return shorthand(set, ch, ucp); }
    if (ch == 'p' || ch == 'P') {
        *single = false;
        return property_escape(set, pattern, length, at, ch == 'P', nocase);
    }
    if (ch == 'x' || ch == 'u' || ch == 'U') {
        uint32_t value = 0; size_t digits = 0;
        size_t required = ch == 'u' ? 4 : ch == 'U' ? 8 : 2;
        bool braced = *at < length && pattern[*at] == '{';
        if (braced) ++*at;
        while (*at < length && (braced ? pattern[*at] != '}' : digits < required)) {
            int digit = hex(pattern[(*at)++]);
            if (digit < 0 || value > (0x10ffffu - (unsigned)digit) / 16) return false;
            value = value * 16 + (unsigned)digit; ++digits;
        }
        if ((braced && (*at >= length || !digits || pattern[(*at)++] != '}')) ||
            (!braced && digits != required) || (value >= 0xd800 && value <= 0xdfff)) return false;
        *cp = value; return true;
    }
    const char *escapes = "abfnrtv", *found = strchr(escapes, ch);
    static const unsigned values[] = {7, 8, 12, 10, 13, 9, 11};
    if (found) { *cp = values[found - escapes]; return true; }
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) return false;
    if (ch < 128) { *cp = ch; return true; }
    --*at;
    size_t width = decode(pattern + *at, length - *at, cp);
    if (!width) return false;
    *at += width; return true;
}

/* Character classes use regex-syntax's grammar: implicit unions bind more
 * tightly than the equally-ranked, left-associative &&, -- and ~~ operators.
 * Fold operands before set operations (e.g. (?i)[a--A] is empty). */
typedef struct {
    const unsigned char *text;
    size_t length, at, depth;
    bool unicode, ucp, nocase, extended, source_dialect;
} re_class_parser;
/* yx_re_class_ranges_gap: the outermost class's negation is left to the
 * caller (re_negated tells whether it has one). */
static _Thread_local bool re_defer_negation, re_negated;

static bool class_parse(re_class_parser *, re_set *);
static size_t repeat_space(const unsigned char *, size_t, size_t, bool);

static void class_space(re_class_parser *p)
{
    if (p->extended && p->source_dialect)
        p->at = repeat_space(p->text, p->length, p->at, true);
}

static bool class_posix(re_class_parser *p, re_set *set)
{
    static const struct { const char *name; const char *ranges; } names[] = {
        {"alnum", "AZaz09"}, {"alpha", "AZaz"}, {"ascii", "\0\177"},
        {"blank", "\t\t  "}, {"cntrl", "\0\37\177\177"}, {"digit", "09"},
        {"graph", "!~"}, {"lower", "az"}, {"print", " ~"},
        {"punct", "!/:@[`{~"}, {"space", "\t\r  "}, {"upper", "AZ"},
        {"word", "AZaz09__"}, {"xdigit", "AFaf09"}
    };
    size_t at = p->at + 2;
    if (at >= p->length || p->text[p->at + 1] != ':') return false;
    bool negative = p->text[at] == '^';
    if (negative) ++at;
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i) {
        size_t n = strlen(names[i].name);
        if (n + 2 > p->length - at || memcmp(p->text + at, names[i].name, n) ||
            memcmp(p->text + at + n, ":]", 2)) continue;
        const unsigned char *ranges = (const unsigned char *)names[i].ranges;
        size_t count = !strcmp(names[i].name, "ascii") ? 2 :
                       !strcmp(names[i].name, "cntrl") ? 4 : strlen(names[i].ranges);
        for (size_t j = 0; j < count; j += 2)
            if (!set_add(set, ranges[j], ranges[j + 1])) return false;
        if ((p->nocase && !set_fold_mode(set, p->unicode)) ||
            (negative && !set_invert(set)) || !set_domain(set, p->unicode)) return false;
        p->at = at + n + 2; return true;
    }
    return false;
}

static bool class_set_atom(re_class_parser *p, re_set *set, bool *single, uint32_t *cp)
{
    if (p->at >= p->length) return false;
    if (p->text[p->at] == '[') {
        *single = false;
        if (p->at + 1 < p->length && p->text[p->at + 1] == ':' && class_posix(p, set)) return true;
        if (p->source_dialect) return class_parse(p, set);
        /* A normalized PCRE class has flat grammar: '[' is a literal,
         * including when it begins a range in an ASCII punctuation set. */
    }
    if (!p->unicode && !p->source_dialect) {
        if (p->text[p->at] >= 128) {
            *single = true; *cp = p->text[p->at++]; return true;
        }
        if (p->text[p->at] == '\\' && p->at + 1 < p->length && p->text[p->at + 1] >= 128) {
            *single = true; *cp = p->text[p->at + 1]; p->at += 2; return true;
        }
    }
    /* Raw Unicode literals inside a byte class are forbidden; byte hex
     * escapes remain legal and are interpreted as bytes, including 80..FF. */
    if (!p->unicode && p->text[p->at] >= 128) return false;
    if (!p->unicode && p->text[p->at] == '\\' && p->at + 1 < p->length &&
        (p->text[p->at + 1] == 'p' || p->text[p->at + 1] == 'P')) return false;
    size_t begin = p->at;
    if (!class_atom(p->text, p->length, &p->at, cp, single, set, p->ucp,
                    p->nocase && p->unicode)) return false;
    if (*single && !p->unicode && *cp >= 128 &&
        !(p->text[begin] == '\\' && p->text[begin + 1] == 'x' &&
          begin + 2 < p->length &&
          (p->text[begin + 2] != '{' || (!p->source_dialect && *cp <= 255)))) return false;
    return true;
}

static bool class_union(re_class_parser *p, re_set *set, bool *first)
{
    while (p->at < p->length) {
        class_space(p);
        if (p->at == p->length) break;
        unsigned char ch = p->text[p->at];
        if ((ch == ']' && !*first) ||
            (p->source_dialect && (!*first || ch != '-') && p->at + 1 < p->length &&
             strchr("&-~", ch) && p->text[p->at + 1] == ch)) break;
        re_set atom = {0}; uint32_t cp = 0; bool single;
        *first = false;
        if (!class_set_atom(p, &atom, &single, &cp)) { free(atom.ranges); return false; }
        class_space(p);
        if (p->at + 1 < p->length && p->text[p->at] == '-' &&
            p->text[p->at + 1] != ']' &&
            (!p->source_dialect || p->text[p->at + 1] != '-')) {
            re_set endpoint = {0}; uint32_t last = 0; bool literal;
            ++p->at;
            class_space(p);
            bool ok = class_set_atom(p, &endpoint, &literal, &last);
            free(endpoint.ranges);
            if (!ok || !single || !literal || cp > last || !set_add(&atom, cp, last)) {
                free(atom.ranges); return false;
            }
        } else if (single && !p->nocase && !atom.count) {
            /* One scalar: the atom set would be {cp}; clip it to the class
             * domain and add it directly instead of building three sets. */
            free(atom.ranges);
            if (cp > 0x10ffff) return false;
            if ((p->unicode ? cp <= 0xd7ff || cp >= 0xe000 : cp <= 255) && !set_add(set, cp, cp)) return false;
            continue;
        } else if (single && !set_add(&atom, cp, cp)) { free(atom.ranges); return false; }
        bool ok = (!p->nocase || set_fold_mode(&atom, p->unicode)) &&
                  set_domain(&atom, p->unicode) && set_union(set, &atom);
        free(atom.ranges);
        if (!ok) return false;
    }
    return true;
}

static bool class_parse(re_class_parser *p, re_set *set)
{
    if (p->at >= p->length || p->text[p->at++] != '[' || ++p->depth > 250) return false;
    class_space(p);
    bool negative = p->at < p->length && p->text[p->at] == '^', first = true;
    if (negative) ++p->at;
    if (!class_union(p, set, &first)) return false;
    while (p->source_dialect && p->at + 1 < p->length && strchr("&-~", p->text[p->at]) &&
           p->text[p->at] == p->text[p->at + 1]) {
        unsigned char op = p->text[p->at]; re_set other = {0};
        p->at += 2; first = false;
        bool ok = class_union(p, &other, &first);
        if (ok) ok = op == '&' ? set_intersect(set, &other) :
                     op == '-' ? set_difference(set, &other) : set_symmetric(set, &other);
        if (ok && re_keep_gap) ok = set_gap_trim(set);
        free(other.ranges);
        if (!ok) return false;
    }
    if (p->at >= p->length || p->text[p->at++] != ']') return false;
    if (negative && re_defer_negation && p->depth == 1) {
        re_negated = true;
        negative = false;
    }
    if ((negative && !set_invert(set)) || !set_domain(set, p->unicode)) return false;
    --p->depth; return true;
}

static bool emit_byte_set(re_text *out, const re_set *set)
{
    if (!set->count) return put(out, "(?!)");
    if (!put(out, "(?-i:[")) return false;
    for (size_t i = 0; i < set->count; ++i) {
        if (!byte(out, set->ranges[i].first)) return false;
        if (set->ranges[i].last != set->ranges[i].first &&
            (!put(out, "-") || !byte(out, set->ranges[i].last))) return false;
    }
    return put(out, "])");
}

static bool unicode_class(re_text *out, const unsigned char *pattern, size_t length,
                            size_t *position, bool nocase, bool ucp,
                            re_set *capture)
{
    re_set set = {0};
    re_class_parser p = {pattern, length, *position, 0, true, ucp, nocase, false, true};
    if (!class_parse(&p, &set)) { free(set.ranges); return false; }
    if (capture) *capture = set;
    else {
        bool ok = emit_set(out, &set); free(set.ranges);
        if (!ok) return false;
    }
    *position = p.at - 1; return true;
}

int yx_re_class_ranges(const unsigned char *pattern, size_t length,
                       size_t *position, uint32_t options,
                       yx_re_range **ranges, size_t *count)
{
    re_set set = {0}; size_t at;
    bool unicode = (options & PCRE2_UTF) != 0;
    if (!pattern || !position || !ranges || !count || *position >= length) return 0;
    at = *position; *ranges = NULL; *count = 0;
    if (pattern[at] == '[') {
        re_class_parser p = {pattern, length, at, 0, unicode,
                            (options & PCRE2_UCP) != 0, (options & PCRE2_CASELESS) != 0,
                            (options & PCRE2_EXTENDED) != 0, true};
        if (!class_parse(&p, &set)) goto failed;
        at = p.at;
    } else {
        uint32_t cp; bool single;
        if (!unicode && pattern[at] == '\\' && at + 1 < length &&
            (pattern[at + 1] == 'p' || pattern[at + 1] == 'P')) goto failed;
        if (!class_atom(pattern, length, &at, &cp, &single, &set,
                        (options & PCRE2_UCP) != 0,
                        unicode && (options & PCRE2_CASELESS) != 0)) goto failed;
        if (single && !set_add(&set, cp, cp)) goto failed;
        if ((options & PCRE2_CASELESS) && !set_fold_mode(&set, unicode)) goto failed;
        if (!set_domain(&set, unicode)) goto failed;
    }
    *position = at; *ranges = set.ranges; *count = set.count; return 1;
failed:
    free(set.ranges); return 0;
}

/* yx_re_class_ranges for a Unicode class, with regex-syntax's ranges of
 * chars: the ranges are returned split at the surrogate gap as before, and
 * *gap_split tells whether a range ending at \x{D7FF} and the one starting at
 * \x{E000} are two ranges of the class (false: one range across the gap).
 * A negated outermost class keeps IntervalSet::negate's ranges unmerged. */
int yx_re_class_ranges_gap(const unsigned char *pattern, size_t length,
                           size_t *position, uint32_t options,
                           yx_re_range **ranges, size_t *count, bool *gap_split)
{
    re_set set = {0}, listed = {0};
    size_t at, used = 0;
    yx_re_range *out = NULL;
    bool crossing = false;
    if (!pattern || !position || !ranges || !count || !gap_split || *position >= length ||
        !(options & PCRE2_UTF)) return 0;
    at = *position; *ranges = NULL; *count = 0; *gap_split = false;
    re_keep_gap = true;
    if (pattern[at] == '[') {
        re_class_parser p = {pattern, length, at, 0, true,
                            (options & PCRE2_UCP) != 0, (options & PCRE2_CASELESS) != 0,
                            (options & PCRE2_EXTENDED) != 0, true};
        bool parsed;
        re_defer_negation = true; re_negated = false;
        parsed = class_parse(&p, &set);
        re_defer_negation = false;
        if (!parsed) goto failed;
        at = p.at;
        if (re_negated) {
            if (!set_invert_chars(&set, &listed)) goto failed;
            free(set.ranges); set = listed; listed = (re_set){0};
        }
    } else {
        uint32_t cp; bool single;
        if (!class_atom(pattern, length, &at, &cp, &single, &set,
                        (options & PCRE2_UCP) != 0, (options & PCRE2_CASELESS) != 0)) goto failed;
        if (single && !set_add(&set, cp, cp)) goto failed;
        if ((options & PCRE2_CASELESS) && !set_fold_mode(&set, true)) goto failed;
        if (!set_domain(&set, true)) goto failed;
    }
    re_keep_gap = false;
    out = malloc((set.count ? set.count * 2 : 1) * sizeof(*out));
    if (!out) { free(set.ranges); return 0; }
    for (size_t i = 0; i < set.count; ++i) {
        if (set.ranges[i].first <= 0xd7ff && set.ranges[i].last >= 0xe000) {
            out[used++] = (yx_re_range){set.ranges[i].first, 0xd7ff};
            out[used++] = (yx_re_range){0xe000, set.ranges[i].last};
            crossing = true;
        } else out[used++] = set.ranges[i];
    }
    for (size_t i = 0; !crossing && i + 1 < used; ++i)
        if (out[i].last == 0xd7ff && out[i + 1].first == 0xe000) *gap_split = true;
    free(set.ranges);
    *position = at; *ranges = out; *count = used; return 1;
failed:
    re_keep_gap = false;
    free(set.ranges); free(listed.ranges); return 0;
}

/* A Unicode scalar has variable UTF-8 width. The byte backend requires each
 * lookbehind to have fixed width, so test its one- through four-byte cases
 * separately. Positive lookbehinds are alternatives; negative ones all hold. */
static bool unicode_lookbehind(re_text *out, const unsigned char *pattern,
                                size_t length, size_t *position, bool nocase,
                                bool ucp)
{
    static const re_range widths[] = {
        {0, 0x7f}, {0x80, 0x7ff}, {0x800, 0xffff}, {0x10000, 0x10ffff}
    };
    size_t at = *position + 4;
    bool negative = pattern[*position + 3] == '!';
    bool emitted = false, ok = false;
    re_set set = {0};
    if (!unicode_class(NULL, pattern, length, &at, nocase, ucp, &set) ||
        at + 1 >= length || pattern[at + 1] != ')') goto done;
    if (!put(out, "(?:")) goto done;
    for (size_t i = 0; i < sizeof(widths) / sizeof(*widths); ++i) {
        re_set part = {0};
        for (size_t j = 0; j < set.count; ++j) {
            uint32_t first = set.ranges[j].first > widths[i].first ?
                             set.ranges[j].first : widths[i].first;
            uint32_t last = set.ranges[j].last < widths[i].last ?
                            set.ranges[j].last : widths[i].last;
            if (first <= last && !set_add(&part, first, last)) {
                free(part.ranges); goto done;
            }
        }
        if (part.count) {
            bool written = (!emitted || negative || put(out, "|")) &&
                put(out, negative ? "(?<!" : "(?<=") &&
                emit_set(out, &part) && put(out, ")");
            free(part.ranges);
            if (!written) goto done;
            emitted = true;
        } else free(part.ranges);
    }
    if (!emitted && !negative && !put(out, "(?!)")) goto done;
    if (!put(out, ")")) goto done;
    *position = at + 1;
    ok = true;
done:
    free(set.ranges); return ok;
}

/* regex-syntax permits Unicode whitespace around decimal bounds. Verbose
 * mode also skips whitespace and comments between their digits. */
static size_t repeat_space(const unsigned char *pattern, size_t length,
                           size_t at, bool extended)
{
    while (at < length) {
        if (extended && pattern[at] == '#') {
            while (at < length && pattern[at] != '\n') ++at;
            continue;
        }
        uint32_t cp;
        size_t width = decode(pattern + at, length - at, &cp);
        if (!width || !((cp >= 9 && cp <= 13) || cp == 32 || cp == 0x85 ||
            cp == 0xa0 || cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200a) ||
            cp == 0x2028 || cp == 0x2029 || cp == 0x202f || cp == 0x205f ||
            cp == 0x3000)) break;
        at += width;
    }
    return at;
}

static size_t repeat_decimal(const unsigned char *pattern, size_t length,
                             size_t at, bool extended)
{
    while (at < length && pattern[at] >= '0' && pattern[at] <= '9') {
        ++at;
        if (extended) at = repeat_space(pattern, length, at, true);
    }
    return at;
}

static bool repeat_bound(re_text *out, const unsigned char *pattern,
                         size_t begin, size_t end, bool extended)
{
    uint32_t value = 0;
    while (begin < end) {
        unsigned digit = (unsigned)(pattern[begin] - '0');
        /* The native engine saturates large counts instead of rejecting
         * them. YARA-X's syntax accepts only unsigned 32-bit bounds. */
        if (value > (UINT32_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
        if (!append(out, (const char *)pattern + begin, 1)) return false;
        ++begin;
        if (extended) begin = repeat_space(pattern, end, begin, true);
    }
    return true;
}

/* Return zero for a non-repetition, one on success, and -1 on invalid bounds
 * or allocation failure. Leave other malformed syntax to the caller. */
static int counted_repeat(re_text *out, const unsigned char *pattern,
                          size_t length, size_t *position, bool extended)
{
    size_t at = repeat_space(pattern, length, *position + 1, extended);
    size_t lower = at, lower_end, upper = 0, upper_end = 0;
    bool range = false;
    at = repeat_decimal(pattern, length, at, extended);
    lower_end = at;
    at = repeat_space(pattern, length, at, extended);
    if (at < length && pattern[at] == ',') {
        range = true;
        upper = at = repeat_space(pattern, length, at + 1, extended);
        at = repeat_decimal(pattern, length, at, extended);
        upper_end = at;
        at = repeat_space(pattern, length, at, extended);
    }
    if (at >= length || pattern[at] != '}' ||
        (lower == lower_end && (!range || upper == upper_end))) return 0;
    if (!put(out, "{") ||
        !(lower == lower_end ? put(out, "0") :
          repeat_bound(out, pattern, lower, lower_end, extended)) ||
        (range && (!put(out, ",") ||
         !repeat_bound(out, pattern, upper, upper_end, extended))) ||
        !put(out, "}")) return -1;
    *position = at;
    return 1;
}

/* The byte backend has no Unicode flag. Keep the remaining flags and
 * remove u without leaving dangling '-' or an invalid empty (?...) header. */
static bool emit_flags(re_text *out, const unsigned char *pattern, size_t begin, size_t end)
{
    char positive[16], negative[16]; size_t np = 0, nn = 0; bool negate = false;
    for (size_t i = begin; i < end; ++i) {
        unsigned char ch = pattern[i];
        if (ch == '-') { negate = true; continue; }
        if (ch == 'u' || ch == 'U') continue;
        if (negate) { if (nn == sizeof(negative)) return false; negative[nn++] = (char)ch; }
        else { if (np == sizeof(positive)) return false; positive[np++] = (char)ch; }
    }
    if (!np && !nn) return put(out, pattern[end] == ':' ? "(?:" : "(?:)");
    return put(out, "(?") && append(out, positive, np) &&
           (!nn || (put(out, "-") && append(out, negative, nn))) &&
           append(out, (const char *)pattern + end, 1);
}

/* Translate Unicode atoms into bounded UTF-8 byte expressions. Each expanded
 * atom remains grouped, so repetition and captures retain scalar semantics. */
static char *translate(const unsigned char *pattern, size_t length, uint32_t options)
{
    typedef struct { bool nocase, dotall, extended, multiline, unicode, ucp, ungreedy; } re_flags;
    re_text out = {0}, names = {0}; bool in_class = false;
    
    re_flags flags = {(options & PCRE2_CASELESS) != 0,
                      (options & PCRE2_DOTALL) != 0, false, false,
                      (options & PCRE2_UTF) != 0, (options & PCRE2_UCP) != 0};
    size_t depth = 0;
    if (length > SIZE_MAX / sizeof(re_flags) - 1) return NULL;
    re_flags *states = malloc((length + 1) * sizeof(*states));
    if (!states) return NULL;
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = pattern[i];
        if (flags.unicode && !in_class && i + 4 < length && ch == '(' &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<' &&
            (pattern[i + 3] == '=' || pattern[i + 3] == '!') &&
            pattern[i + 4] == '[') {
            if (!unicode_lookbehind(&out, pattern, length, &i, flags.nocase,
                                     flags.ucp)) goto failed;
            continue;
        }
        if (!in_class && flags.extended && ch == '#') {
            size_t end = i;
            while (end < length && pattern[end] != '\n' && pattern[end] != '\r') ++end;
            if (!append(&out, (const char *)pattern + i, end - i)) goto failed;
            i = end - 1; continue;
        }
        if (!in_class && ch == '(') {
            size_t end = i + 2;
            bool negate = false, any = false;
            re_flags next = flags;
            if (i + 1 < length && pattern[i + 1] == '?') {
                while (end < length) {
                    unsigned char flag = pattern[end];
                    if (flag == '-') { negate = true; ++end; continue; }
                    if (flag == 'i') next.nocase = !negate;
                    else if (flag == 's') next.dotall = !negate;
                    else if (flag == 'x') next.extended = !negate;
                    else if (flag == 'm') next.multiline = !negate;
                    else if (flag == 'u') next.unicode = next.ucp = !negate;
                    else if (flag == 'U') next.ungreedy = !negate;
                    else break;
                    any = true; ++end;
                }
                if (any && end < length && (pattern[end] == ':' || pattern[end] == ')')) {
                    if (pattern[end] == ':') states[depth++] = flags;
                    flags = next;
                    if (!emit_flags(&out, pattern, i + 2, end)) goto failed;
                    i = end; continue;
                }
                if (i + 2 < length && pattern[i + 2] == '#') {
                    end = i + 3;
                    while (end < length && pattern[end] != ')') ++end;
                    if (end == length || !append(&out, (const char *)pattern + i, end - i + 1)) goto failed;
                    i = end; continue;
                }
                if (i + 2 < length && (pattern[i + 2] == '\'' ||
                    (pattern[i + 2] == '<' && i + 3 < length && pattern[i + 3] != '=' && pattern[i + 3] != '!') ||
                    (pattern[i + 2] == 'P' && i + 3 < length && pattern[i + 3] == '<'))) {
                    unsigned char terminator = pattern[i + 2] == '\'' ? '\'' : '>';
                    size_t name = i + (pattern[i + 2] == 'P' ? 4 : 3);
                    end = name;
                    while (end < length && pattern[end] != terminator) ++end;
                    /* The byte engine has numbered captures only. Validate
                     * names and duplicates before retaining their indices. */
                    if (end == length ||
                        !capture_name(&names, pattern + name, end - name) ||
                        !put(&out, "(")) goto failed;
                    states[depth++] = flags; i = end; continue;
                }
            }
            states[depth++] = flags;
            /* The '?' of a group header such as `(?:` is no quantifier: the
             * U flag below must not give it a lazy suffix (`(??:`). */
            if (flags.ungreedy && i + 1 < length && pattern[i + 1] == '?') {
                if (!put(&out, "(?")) goto failed;
                ++i; continue;
            }
        } else if (!in_class && ch == ')' && depth) flags = states[--depth];
        if (!in_class && ch == '[') {
            re_set set = {0};
            re_class_parser p = {pattern, length, i, 0, flags.unicode, flags.ucp,
                                 flags.nocase, flags.extended,
                                 (options & YX_RE_YARA_ESCAPES) != 0};
            bool ok = class_parse(&p, &set) &&
                      (flags.unicode ? emit_set(&out, &set) : emit_byte_set(&out, &set));
            free(set.ranges);
            if (!ok) goto failed;
            i = p.at - 1; continue;
        }
        if (ch == '\\' && i + 1 < length) {
            unsigned char escape = pattern[i + 1];
            if ((escape == 'b' || escape == 'B') && !in_class && flags.unicode)
                goto failed;
            if (escape == 'b' && !in_class && length - i >= 9 &&
                !memcmp(pattern + i + 2, "{start}", 7)) {
                if (!put(&out, "(?<![A-Za-z0-9_])(?=[A-Za-z0-9_])")) goto failed;
                i += 8;
            } else if (escape == 'b' && !in_class && length - i >= 7 &&
                       !memcmp(pattern + i + 2, "{end}", 5)) {
                if (!put(&out, "(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])")) goto failed;
                i += 6;
            } else if (escape == 'b' && !in_class && length - i >= 14 &&
                !memcmp(pattern + i + 2, "{start-half}", 12)) {
                if (!put(&out, "(?<![A-Za-z0-9_])")) goto failed;
                i += 13;
            } else if (escape == 'b' && !in_class && length - i >= 12 &&
                       !memcmp(pattern + i + 2, "{end-half}", 10)) {
                if (!put(&out, "(?![A-Za-z0-9_])")) goto failed;
                i += 11;
            } else if ((escape == 'A' || escape == 'z') && !in_class) {
                if (!put(&out, escape == 'A' ? "(?-m:^)" : "(?-m:$)")) goto failed;
                ++i;
            } else if (escape == 'C' && !in_class) {
                if (!put(&out, "[\\x00-\\xFF]")) goto failed;
                ++i;
            } else if (escape == 'x' || escape == 'u' || escape == 'U' || escape == 'a' ||
                       (flags.unicode && escape != 'b' && strchr("fnrtv", escape))) {
                uint32_t cp; size_t at = i; bool single; re_set unused = {0};
                bool ok = class_atom(pattern, length, &at, &cp, &single, &unused, false, false);
                free(unused.ranges);
                if (!ok || !single) goto failed;
                if (flags.unicode) { if (!emit_scalar(&out, cp, flags.nocase)) goto failed; }
                else if (escape == 'u' || escape == 'U' ||
                         (escape == 'x' && (options & YX_RE_YARA_ESCAPES) &&
                          i + 2 < length && pattern[i + 2] == '{')) {
                    if (!scalar(&out, cp, true)) goto failed;
                } else if (cp <= 255) { if (!byte(&out, cp)) goto failed; }
                else if (in_class || !scalar(&out, cp, true)) goto failed;
                i = at - 1;
            } else if (strchr("dDsSwW", escape)) {
                re_set set = {0};
                bool ok = shorthand(&set, escape, flags.ucp) &&
                    (!flags.nocase || set_fold_mode(&set, flags.unicode)) &&
                    set_domain(&set, flags.unicode) &&
                    (flags.unicode ? emit_set(&out, &set) : emit_byte_set(&out, &set));
                free(set.ranges);
                if (!ok) goto failed;
                ++i;
            } else if ((escape == 'p' || escape == 'P') && flags.unicode) {
                re_set set = {0}; size_t at = i + 2;
                bool ok = property_escape(&set, pattern, length, &at,
                                           escape == 'P', flags.nocase) && emit_set(&out, &set);
                free(set.ranges);
                if (!ok) goto failed;
                i = at - 1;
            } else if (escape == 'p' || escape == 'P' || escape == 'C') {
                goto failed;
            } else if ((escape == 's' || escape == 'S') && !in_class) {
                if (!put(&out, escape == 's' ? "[ \\t\\n\\r\\f\\v]" : "[^ \\t\\n\\r\\f\\v]")) goto failed;
                ++i;
            } else {
                if (!append(&out, "\\", 1) || !append(&out, (const char *)&escape, 1)) goto failed;
                ++i;
            }
            continue;
        }
        if (!in_class && flags.multiline && (ch == '^' || ch == '$')) {
            /* PCRE2 is configured for LF line endings. The byte engine also
             * treats CR as a newline unless these anchors are explicit. */
            if (!put(&out, ch == '^' ? "(?:(?-m:^)|(?<=\\x0A))" :
                                      "(?:(?-m:$)|(?=\\x0A))")) goto failed;
            continue;
        }
        if (flags.unicode && !in_class && ch == '.') {
            re_set set = {0};
            bool ok = flags.dotall ? set_add(&set, 0, 0x10ffff) :
                set_add(&set, 0, 9) && set_add(&set, 11, 0x10ffff);
            ok = ok && emit_set(&out, &set); free(set.ranges);
            if (!ok) goto failed;
            continue;
        }
        if (!in_class && ch == '{') {
            int result = counted_repeat(&out, pattern, length, &i, flags.extended);
            if (result < 0) goto failed;
            if (result) {
                /* The U flag swaps a quantifier and its lazy suffix. */
                if (flags.ungreedy) {
                    if (i + 1 < length && pattern[i + 1] == '?') ++i;
                    else if (!put(&out, "?")) goto failed;
                }
                continue;
            }
        }
        if (!in_class && flags.ungreedy && (ch == '*' || ch == '+' || ch == '?')) {
            if (!append(&out, (const char *)&ch, 1)) goto failed;
            if (i + 1 < length && pattern[i + 1] == '?') ++i;
            else if (!put(&out, "?")) goto failed;
            continue;
        }
        if (!in_class && (ch >= 128 ||
            (flags.unicode && flags.nocase && ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))))) {
            uint32_t cp; size_t width = decode(pattern + i, length - i, &cp);
            if (!width || !emit_scalar(&out, cp, flags.unicode && flags.nocase)) goto failed;
            i += width - 1; continue;
        }
        if (!append(&out, (const char *)&ch, 1)) goto failed;
    }
    if (in_class || (!out.data && !put(&out, ""))) goto failed;
    free(states); free(names.data);
    return out.data;
failed: free(states); free(names.data); free(out.data); return NULL;
}

/* regex-syntax parses a second quantifier as a repetition of the preceding
 * repetition. The byte engine accepts one quantifier per atom, so make that
 * nesting explicit after translation. A following '?' remains a lazy suffix.
 * Group only the preceding atom; captures and alternatives keep their scope. */
static char *stacked_repeats(const char *pattern)
{
    typedef struct { size_t start; bool extended, zero, assertion; } re_group;
    size_t length = strlen(pattern), depth = 0, atom = SIZE_MAX;
    re_text out = {0}; bool extended = false, repeated = false;
    bool zero = true, atom_zero = false;
    if (length > SIZE_MAX / sizeof(re_group) - 1) return NULL;
    re_group *groups = malloc((length + 1) * sizeof(*groups));
    if (!groups) return NULL;
    for (size_t i = 0; i < length;) {
        unsigned char ch = (unsigned char)pattern[i];
        if (extended && (ch == '#' || ch == ' ' || (ch >= 9 && ch <= 13))) {
            size_t end = i + 1;
            if (ch == '#') while (end < length && pattern[end] != '\n') ++end;
            if (!append(&out, pattern + i, end - i)) goto failed;
            i = end; continue;
        }
        if (ch == '*' || ch == '+' || ch == '?' || ch == '{') {
            size_t end = i + 1;
            if (ch == '{') {
                /* Counted bounds have already been canonicalized by
                 * translate(). Named assertions and malformed braces must
                 * never be mistaken for an optional repetition. */
                if (end == length || pattern[end] < '0' || pattern[end] > '9')
                    goto failed;
                while (end < length && pattern[end] >= '0' && pattern[end] <= '9') ++end;
                if (end < length && pattern[end] == ',') {
                    ++end;
                    while (end < length && pattern[end] >= '0' && pattern[end] <= '9') ++end;
                }
                if (end == length || pattern[end] != '}') goto failed;
                ++end;
            }
            if (atom == SIZE_MAX) goto failed;
            size_t lazy = end;
            if (extended && ch == '{') lazy = repeat_space((const unsigned char *)pattern,
                                              length, lazy, true);
            bool lazy_suffix = lazy < length && pattern[lazy] == '?';
            if (atom_zero) {
                bool optional = ch == '*' || ch == '?';
                if (ch == '{') {
                    optional = true;
                    for (size_t digit = i + 1; digit < end &&
                         pattern[digit] >= '0' && pattern[digit] <= '9'; ++digit)
                        if (pattern[digit] != '0') optional = false;
                }
                /* Repeating an assertion-only HIR is idempotent. Keep its
                 * groups for capture numbering, and suppress it at min=0. */
                if (optional) {
                    size_t previous = out.size;
                    if (!put(&out, "(?:){0}")) goto failed;
                    memmove(out.data + atom + 3, out.data + atom, previous - atom);
                    memcpy(out.data + atom, "(?:", 3);
                    memcpy(out.data + previous + 3, "){0}", 4);
                }
                i = lazy_suffix ? lazy + 1 : end;
                repeated = false; continue;
            }
            if (repeated) {
                size_t previous = out.size;
                if (!put(&out, "(?:)")) goto failed;
                memmove(out.data + atom + 3, out.data + atom, previous - atom);
                memcpy(out.data + atom, "(?:", 3);
                out.data[previous + 3] = ')';
            }
            if (!append(&out, pattern + i, end - i)) goto failed;
            /* Counted repetitions permit verbose trivia before lazy '?';
             * the simple operators require an immediately adjacent suffix. */
            if (lazy_suffix) {
                if (!append(&out, pattern + end, lazy - end + 1)) goto failed;
                end = lazy + 1;
            }
            i = end; repeated = true; continue;
        }
        if (ch == '(') {
            size_t end = i + 1; bool next = extended, flags = false, assertion = false;
            if (end < length && pattern[end] == '?') {
                ++end;
                if (end < length && pattern[end] == '#') {
                    while (end < length && pattern[end] != ')') ++end;
                    if (end == length || !append(&out, pattern + i, end - i + 1))
                        goto failed;
                    i = end + 1; continue;
                }
                bool negate = false;
                while (end < length) {
                    char flag = pattern[end];
                    if (flag == '-') { negate = true; ++end; continue; }
                    if (!strchr("imsxU", flag)) break;
                    if (flag == 'x') next = !negate;
                    flags = true; ++end;
                }
                if (flags && end < length && pattern[end] == ')') {
                    if (!append(&out, pattern + i, end - i + 1)) goto failed;
                    extended = next; i = end + 1; continue;
                }
                if (end < length && (pattern[end] == ':' || pattern[end] == '=' ||
                    pattern[end] == '!')) {
                    assertion = pattern[end] != ':'; ++end;
                }
                else if (end + 1 < length && pattern[end] == '<' &&
                    (pattern[end + 1] == '=' || pattern[end + 1] == '!')) {
                    assertion = true; end += 2;
                }
            }
            groups[depth++] = (re_group){out.size, extended, zero, assertion};
            extended = next; atom = SIZE_MAX; repeated = false;
            zero = true;
            if (!append(&out, pattern + i, end - i)) goto failed;
            i = end; continue;
        }
        if (ch == ')') {
            if (!depth || !append(&out, pattern + i, 1)) goto failed;
            re_group group = groups[--depth];
            atom = group.start; extended = group.extended; repeated = false;
            atom_zero = group.assertion || zero; zero = group.zero && atom_zero;
            ++i; continue;
        }
        if (ch == '|') {
            if (!append(&out, pattern + i, 1)) goto failed;
            atom = SIZE_MAX; repeated = false; ++i; continue;
        }
        size_t end = i + 1;
        if (ch == '\\') {
            if (end == length) goto failed;
            ++end;
            if (pattern[i + 1] == 'x') {
                if (length - end < 2) goto failed;
                end += 2;
            }
        } else if (ch == '[') {
            if (end < length && pattern[end] == '^') ++end;
            if (end < length && pattern[end] == ']') ++end;
            while (end < length && pattern[end] != ']') {
                if (pattern[end] == '\\' && end + 1 < length) ++end;
                ++end;
            }
            if (end == length) goto failed;
            ++end;
        }
        atom = out.size; repeated = false;
        atom_zero = ch == '^' || ch == '$' ||
                    (ch == '\\' && (pattern[i + 1] == 'b' || pattern[i + 1] == 'B'));
        zero = zero && atom_zero;
        if (!append(&out, pattern + i, end - i)) goto failed;
        i = end;
    }
    if (depth || (!out.data && !put(&out, ""))) goto failed;
    free(groups); return out.data;
failed:
    free(groups); free(out.data); return NULL;
}

pcre2_compile_context *yx_re_compile_context_create(void *unused)
{ (void)unused; return calloc(1, sizeof(pcre2_compile_context)); }
void yx_re_compile_context_free(pcre2_compile_context *context) { free(context); }
int yx_re_set_newline(pcre2_compile_context *context, unsigned newline)
{ return context && newline == PCRE2_NEWLINE_LF ? 0 : -1; }
pcre2_code *yx_re_compile(PCRE2_SPTR pattern, size_t length, uint32_t options,
    int *error, size_t *offset, pcre2_compile_context *context)
{
    (void)context; if (error) *error = 0; if (offset) *offset = 0;
    if (!pattern) return NULL;
    if (length == SIZE_MAX) length = strlen((const char *)pattern);
    pcre2_code *code = calloc(1, sizeof(*code)); if (!code) return NULL;
    code->options = options;
    const char *digits = "\\A\\p{Nd}\\z";
    const char *identifier = "\\A(?:_|\\p{Alphabetic})(?:_|\\p{Alphabetic}|\\p{N})*\\z";
    if (length == strlen(digits) && !memcmp(pattern, digits, length)) code->special = 1;
    else if (length == strlen(identifier) && !memcmp(pattern, identifier, length)) code->special = 2;
    else {
        char *translated = translate(pattern, length, options), *diagnostic = NULL;
        char *source = translated ? stacked_repeats(translated) : NULL;
        free(translated);
        char flags[2] = {options & PCRE2_CASELESS ? 'i' : 0, 0};
        if (source) code->regex = xx_regex_compile_n_options(source, strlen(source), flags,
            strlen(flags), XX_REGEX_RAW_BYTES | XX_REGEX_SCANNER_DIALECT |
            (options & PCRE2_DOTALL ? XX_REGEX_DOTALL : 0), &diagnostic);
        free(source); xx_rt_free(diagnostic);
        if (!code->regex) { if (error) *error = 1; free(code); return NULL; }
    }
    return code;
}
void yx_re_code_free(pcre2_code *code)
{ if (code) { xx_regex_free(code->regex); free(code->search); free(code); } }
pcre2_code *yx_re_code_copy(const pcre2_code *code)
{
    if (!code) return NULL;
    pcre2_code *copy = malloc(sizeof(*copy));
    if (copy) {
        *copy = *code; copy->regex = xx_regex_ref(code->regex);
        copy->search = NULL;
        if (code->search) {
            copy->search = malloc(code->search_length);
            if (!copy->search) { yx_re_code_free(copy); return NULL; }
            memcpy(copy->search, code->search, code->search_length);
        }
    }
    return copy;
}
int yx_re_code_set_source(pcre2_code *code, const char *source, size_t length,
                           bool nocase, bool dotall)
{
    uint8_t *program = NULL;
    size_t program_length = 0;
    if (!code) return 0;
    int status = yx_ser_search_program(source, length, dotall, nocase,
                                       &program, &program_length);
    if (status != 1) return status;
    free(code->search);
    code->search = program; code->search_length = program_length;
    return 1;
}
int yx_re_code_search(const pcre2_code *code, const unsigned char *text,
                       size_t length, yx_scan_deadline *deadline)
{
    if (!code || !code->search || (!text && length)) return -1;
    return yx_rx_pike_search(code->search, code->search_length,
                              text ? text : (const unsigned char *)"", length,
                              deadline);
}
pcre2_code *yx_re_compile_search(const char *source, size_t length,
                                  bool nocase, bool dotall, int *status)
{
    pcre2_code *code = calloc(1, sizeof(*code));
    if (!code) { *status = -1; return NULL; }
    *status = yx_re_code_set_source(code, source, length, nocase, dotall);
    if (*status != 1) { yx_re_code_free(code); return NULL; }
    return code;
}
pcre2_match_data *yx_re_match_data_create_from_pattern(const pcre2_code *code, void *unused)
{
    (void)unused; if (!code) return NULL;
    pcre2_match_data *data = calloc(1, sizeof(*data)); if (!data) return NULL;
    data->count = 2 * ((size_t)xx_regex_ngroups(code->regex) + 1);
    data->captures = malloc(data->count * sizeof(*data->captures));
    data->offsets = malloc(data->count * sizeof(*data->offsets));
    if (!data->captures || !data->offsets) { yx_re_match_data_free(data); return NULL; }
    return data;
}
void yx_re_match_data_free(pcre2_match_data *data)
{ if (data) { free(data->captures); free(data->offsets); free(data); } }
size_t *yx_re_get_ovector_pointer(pcre2_match_data *data) { return data ? data->offsets : NULL; }
pcre2_match_context *yx_re_match_context_create(void *unused)
{ (void)unused; return calloc(1, sizeof(pcre2_match_context)); }
void yx_re_match_context_free(pcre2_match_context *context) { free(context); }
int yx_re_set_callout(pcre2_match_context *context,
    int (*callout)(pcre2_callout_block *, void *), void *user)
{ if (!context) return -1; context->callout = callout; context->user = user; return 0; }
static int path_control(void *opaque, size_t start, size_t position)
{
    pcre2_match_context *context = opaque;
    pcre2_callout_block block = {position, start};
    return context->callout(&block, context->user);
}
static bool search_abort(void *opaque)
{
    /* Deadline callbacks ignore offsets; bounded-match callbacks return a
     * positive value for rejected paths, never a cancellation here. */
    return path_control(opaque, 0, 0) < 0;
}
static int special_match(const pcre2_code *code, PCRE2_SPTR text, size_t length)
{
    size_t at = 0, count = 0;
    while (at < length) {
        uint32_t cp; size_t width = decode(text + at, length - at, &cp);
        if (!width) return PCRE2_ERROR_NOMATCH;
        if (code->special == 1) {
            if (count || !xx_regex_unicode_property(cp, XX_REGEX_UNICODE_DECIMAL)) return PCRE2_ERROR_NOMATCH;
        } else if (cp != '_' && !xx_regex_unicode_property(cp, XX_REGEX_UNICODE_ALPHABETIC) &&
                   (!count || !xx_regex_unicode_property(cp, XX_REGEX_UNICODE_NUMERIC))) return PCRE2_ERROR_NOMATCH;
        at += width; ++count;
    }
    return count ? 1 : PCRE2_ERROR_NOMATCH;
}
int yx_re_match(const pcre2_code *code, PCRE2_SPTR text, size_t length, size_t start,
    uint32_t options, pcre2_match_data *data, pcre2_match_context *context)
{
    if (!code || !text || !data || !data->captures || !data->offsets ||
        start > length || length > INT32_MAX ||
        data->count < 2 * ((size_t)xx_regex_ngroups(code->regex) + 1))
        return PCRE2_ERROR_BADDATA;
    for (size_t i = 0; i < data->count; ++i) data->offsets[i] = SIZE_MAX;
    if (code->special) {
        int result = start ? PCRE2_ERROR_NOMATCH : special_match(code, text, length);
        if (result >= 0) { data->offsets[0] = 0; data->offsets[1] = length; }
        return result;
    }
    uint32_t combined = options | code->options;
    unsigned flags = (combined & PCRE2_ANCHORED ? XX_REGEX_ANCHORED : 0) |
        (combined & PCRE2_ENDANCHORED ? XX_REGEX_ENDANCHORED : 0) |
        (options & PCRE2_NOTBOL ? XX_REGEX_NOTBOL : 0) |
        (options & PCRE2_NOTEOL ? XX_REGEX_NOTEOL : 0);
    bool control = context && context->callout;
    xx_regex_exec_status result = xx_regex_exec_controlled(code->regex, (const char *)text,
        length, start, data->captures, flags, control ? search_abort : NULL, context,
        control ? path_control : NULL, context);
    if (result == XX_REGEX_EXEC_MATCH) {
        for (size_t i = 0; i < data->count; ++i)
            if (data->captures[i] >= 0) data->offsets[i] = (size_t)data->captures[i];
        return (int)(data->count / 2);
    }
    if (result == XX_REGEX_EXEC_CANCELLED) return PCRE2_ERROR_CALLOUT;
    if (result == XX_REGEX_EXEC_NO_MEMORY) return PCRE2_ERROR_NOMEMORY;
    if (result == XX_REGEX_EXEC_BUDGET) return PCRE2_ERROR_MATCHLIMIT;
    if (result == XX_REGEX_EXEC_INVALID) return PCRE2_ERROR_BADDATA;
    return PCRE2_ERROR_NOMATCH;
}
int yx_re_dfa_match(const pcre2_code *code, PCRE2_SPTR text, size_t length, size_t start,
    uint32_t options, pcre2_match_data *data, pcre2_match_context *context, int *workspace, size_t size)
{
    /* The native engine reports bounded exhaustion explicitly. It has no
     * unbounded retry that could turn an incomplete search into a miss. */
    (void)workspace; (void)size;
    return yx_re_match(code, text, length, start, options, data, context);
}
