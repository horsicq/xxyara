/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* Sizes of the HIR emitted by regex-syntax 0.8.11. Keep both Thompson
 * contexts: only the immediately enclosing counted loop disables REPEAT.
 * Instruction layouts: lib/src/re/thompson/{compiler,instr}.rs, YARA-X 1.23. */
#define YX_REGEX_PIKE_SIZE_LIMIT ((size_t)128 * 1024)
#define YX_REGEX_NFA_SIZE_LIMIT ((size_t)50 * 1024 * 1024)

typedef struct yx_regex_nfa_node yx_regex_nfa_node;
typedef struct yx_regex_nfa_arena yx_regex_nfa_arena;

typedef struct {
    size_t bytes[2], splits[2], nfa, alternatives;
    bool zero, nullable, byte_class, unicode_class, literal;
    unsigned char set[256];
    yx_regex_nfa_node *node;
} yx_regex_pike_size;

typedef struct {
    const char *body;
    size_t length, at;
    unsigned depth;
    bool extended, insensitive, dotall, unicode, valid, multiline, ungreedy;
    yx_regex_nfa_arena *arena;
} yx_regex_pike_size_parser;

static size_t yx_regex_pike_size_add(size_t a, size_t b)
{
    size_t cap = YX_REGEX_NFA_SIZE_LIMIT + 1;
    return a >= cap || b >= cap - a ? cap : a + b;
}

static size_t yx_regex_pike_size_mul(size_t a, size_t b)
{
    size_t cap = YX_REGEX_NFA_SIZE_LIMIT + 1;
    return !a || !b ? 0 : a >= cap || b > cap / a ? cap : a * b;
}

static size_t yx_regex_size_whitespace(yx_regex_pike_size_parser *p)
{
    if (p->at >= p->length) return 0;
    if (p->body[p->at] == '\v' || p->body[p->at] == '\f') return 1;
    /* Check the slice before yx_space_bytes can inspect continuation bytes.
     * The caller may provide a slice without any readable trailing bytes. */
    unsigned char lead = (unsigned char)p->body[p->at];
    size_t remaining = p->length - p->at;
    if ((lead == 0xc2 && remaining < 2) ||
        ((lead == 0xe1 || lead == 0xe2 || lead == 0xe3) && remaining < 3))
        return 0;
    size_t width = yx_space_bytes(p->body + p->at);
    return width <= p->length - p->at ? width : 0;
}

static void yx_regex_pike_size_space(yx_regex_pike_size_parser *p)
{
    while (p->extended && p->at < p->length) {
        size_t width = yx_regex_size_whitespace(p);
        if (width) p->at += width;
        else if (p->body[p->at] == '#') {
            while (p->at < p->length && p->body[p->at] != '\n') ++p->at;
        } else break;
    }
}

static void yx_regex_size_bound_space(yx_regex_pike_size_parser *p)
{
    size_t width;
    do {
        while ((width = yx_regex_size_whitespace(p)) != 0) p->at += width;
        size_t prior = p->at;
        yx_regex_pike_size_space(p);
        if (p->at == prior) break;
    } while (p->at < p->length);
}

static bool yx_regex_pike_size_decimal(yx_regex_pike_size_parser *p,
                                       size_t *number)
{
    bool found = false;
    *number = 0;
    for (;;) {
        yx_regex_pike_size_space(p);
        if (p->at == p->length ||
            !isdigit((unsigned char)p->body[p->at])) break;
        unsigned digit = (unsigned)(p->body[p->at++] - '0');
        if (*number > (UINT32_MAX - digit) / 10u) {
            p->valid = false;
            *number = UINT32_MAX;
        } else *number = *number * 10u + digit;
        found = true;
    }
    return found;
}

static yx_regex_pike_size yx_regex_size_empty(void)
{
    yx_regex_pike_size s = {0};
    s.zero = s.nullable = true;
    s.nfa = 32;
    return s;
}

static bool yx_regex_size_masked(const unsigned char set[256])
{
    unsigned first = 256, last = 0, count = 0, bits = 0;
    for (unsigned i = 0; i < 256; ++i) if (set[i]) {
        if (first == 256) first = i;
        last = i;
        ++count;
    }
    if (!count) return false;
    for (unsigned i = 0; i < 256; ++i)
        if (set[i] && (i & first) != first) return false;
    for (unsigned mask = first ^ last; mask; mask >>= 1) bits += mask & 1;
    return count == (1u << bits);
}

static yx_regex_pike_size yx_regex_size_byte_class(
    const unsigned char set[256], bool unicode)
{
    yx_regex_pike_size s = {0};
    unsigned ranges = 0, count = 0, literal = 0;
    s.byte_class = true;
    s.unicode_class = unicode;
    memcpy(s.set, set, 256);
    /* Skip empty eight-byte blocks; most classes here are one byte. */
    for (unsigned block = 0; block < 256; block += 8) {
        uint64_t word;
        memcpy(&word, set + block, sizeof(word));
        if (!word) continue;
        for (unsigned i = block; i < block + 8; ++i) if (set[i]) {
            if (!i || !set[i - 1]) ++ranges;
            ++count;
            literal = i;
        }
    }
    size_t bytes = count == 1 ? (literal == 0xaa ? 2 : 1) :
        !unicode && yx_regex_size_masked(set) ? (count == 256 ? 2 : 4) :
        ranges < 4 ? 3 + 2 * ranges : 34;
    s.bytes[0] = s.bytes[1] = bytes;
    s.nfa = count == 1 ? 32 : 64 + 8 * ranges;
    s.literal = count == 1;
    return s;
}

static unsigned yx_regex_size_encode(uint32_t cp, unsigned char out[4])
{
    if (cp < 128) { out[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800) {
        out[0] = (unsigned char)(0xc0 | (cp >> 6));
        out[1] = (unsigned char)(0x80 | (cp & 63)); return 2;
    }
    if (cp < 0x10000) {
        out[0] = (unsigned char)(0xe0 | (cp >> 12));
        out[1] = (unsigned char)(0x80 | ((cp >> 6) & 63));
        out[2] = (unsigned char)(0x80 | (cp & 63)); return 3;
    }
    out[0] = (unsigned char)(0xf0 | (cp >> 18));
    out[1] = (unsigned char)(0x80 | ((cp >> 12) & 63));
    out[2] = (unsigned char)(0x80 | ((cp >> 6) & 63));
    out[3] = (unsigned char)(0x80 | (cp & 63)); return 4;
}

#ifdef XXYARA_NATIVE_REGEX
typedef struct {
    unsigned char first, last;
    uint32_t next;
} yx_regex_nfa_transition;

typedef struct {
    yx_regex_nfa_transition transitions[256];
    size_t count;
    bool pending;
    unsigned char first, last;
} yx_regex_nfa_utf8_node;

typedef struct {
    yx_regex_nfa_transition *transitions;
    size_t count;
    uint32_t state;
} yx_regex_nfa_utf8_entry;

typedef struct {
    yx_regex_nfa_utf8_node nodes[4];
    yx_regex_nfa_utf8_entry *cache;
    size_t depth, bytes;
    uint32_t next, target;
    bool valid;
} yx_regex_nfa_utf8;

/* regex-automata compiler.rs:1783-1897 constructs a compact UTF-8 DFA.
 * Preserve its bounded 10,000-slot cache and FNV hash, including sparse
 * transitions that eventually become byte-range states in the final NFA. */
static uint32_t yx_regex_nfa_utf8_compile(yx_regex_nfa_utf8 *p,
                                         yx_regex_nfa_utf8_node *node)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < node->count; ++i) {
        yx_regex_nfa_transition *t = &node->transitions[i];
        hash = (hash ^ t->first) * UINT64_C(1099511628211);
        hash = (hash ^ t->last) * UINT64_C(1099511628211);
        hash = (hash ^ t->next) * UINT64_C(1099511628211);
    }
    yx_regex_nfa_utf8_entry *entry = &p->cache[hash % 10000];
    bool same = entry->transitions && entry->count == node->count;
    for (size_t i = 0; same && i < node->count; ++i) {
        const yx_regex_nfa_transition *a = &entry->transitions[i];
        const yx_regex_nfa_transition *b = &node->transitions[i];
        same = a->first == b->first && a->last == b->last && a->next == b->next;
    }
    if (same) return entry->state;
    yx_regex_nfa_transition *copy = malloc(node->count * sizeof(*copy));
    if (!copy && node->count) { p->valid = false; return 0; }
    memcpy(copy, node->transitions, node->count * sizeof(*copy));
    free(entry->transitions);
    entry->transitions = copy;
    entry->count = node->count;
    entry->state = p->next++;
    p->bytes = yx_regex_pike_size_add(p->bytes, 32 + 8 * node->count);
    return entry->state;
}

static void yx_regex_nfa_utf8_freeze(yx_regex_nfa_utf8_node *node,
                                     uint32_t next)
{
    if (node->pending) {
        yx_regex_nfa_transition *t = &node->transitions[node->count++];
        t->first = node->first; t->last = node->last; t->next = next;
        node->pending = false;
    }
}

static void yx_regex_nfa_utf8_compile_from(yx_regex_nfa_utf8 *p, size_t from)
{
    uint32_t next = p->target;
    while (from + 1 < p->depth) {
        yx_regex_nfa_utf8_node *node = &p->nodes[--p->depth];
        yx_regex_nfa_utf8_freeze(node, next);
        next = yx_regex_nfa_utf8_compile(p, node);
    }
    yx_regex_nfa_utf8_freeze(&p->nodes[p->depth - 1], next);
}

static void yx_regex_nfa_utf8_sequence(yx_regex_nfa_utf8 *p,
                                        uint32_t first, uint32_t last)
{
    unsigned char a[4], b[4];
    unsigned width = yx_regex_size_encode(first, a);
    (void)yx_regex_size_encode(last, b);
    size_t prefix = 0;
    while (prefix < width && prefix < p->depth &&
           p->nodes[prefix].pending && p->nodes[prefix].first == a[prefix] &&
           p->nodes[prefix].last == b[prefix]) ++prefix;
    yx_regex_nfa_utf8_compile_from(p, prefix);
    yx_regex_nfa_utf8_node *node = &p->nodes[p->depth - 1];
    node->first = a[prefix]; node->last = b[prefix]; node->pending = true;
    for (size_t i = prefix + 1; i < width; ++i) {
        node = &p->nodes[p->depth++];
        memset(node, 0, sizeof(*node));
        node->first = a[i]; node->last = b[i]; node->pending = true;
    }
}

static void yx_regex_nfa_utf8_range(yx_regex_nfa_utf8 *p,
                                     uint32_t first, uint32_t last)
{
    if (first > last || !p->valid) return;
    if (first < 0xe000 && last > 0xd7ff) {
        yx_regex_nfa_utf8_range(p, first, 0xd7ff);
        yx_regex_nfa_utf8_range(p, 0xe000, last); return;
    }
    static const uint32_t maxima[] = {0x7f, 0x7ff, 0xffff};
    for (unsigned i = 0; i < 3; ++i) if (first <= maxima[i] && last > maxima[i]) {
        yx_regex_nfa_utf8_range(p, first, maxima[i]);
        yx_regex_nfa_utf8_range(p, maxima[i] + 1, last); return;
    }
    for (unsigned i = 1; i < 4 && last > 127; ++i) {
        uint32_t mask = (1u << (6 * i)) - 1;
        if ((first & ~mask) != (last & ~mask)) {
            if (first & mask) {
                yx_regex_nfa_utf8_range(p, first, first | mask);
                yx_regex_nfa_utf8_range(p, (first | mask) + 1, last); return;
            }
            if ((last & mask) != mask) {
                yx_regex_nfa_utf8_range(p, first, (last & ~mask) - 1);
                yx_regex_nfa_utf8_range(p, last & ~mask, last); return;
            }
        }
    }
    yx_regex_nfa_utf8_sequence(p, first, last);
}

static size_t yx_regex_nfa_unicode_class_at(const yx_re_range *ranges,
                                             size_t count, uint32_t target,
                                             size_t *states)
{
    if (count == 1 && ranges[0].first == ranges[0].last) {
        unsigned char bytes[4];
        *states = yx_regex_size_encode(ranges[0].first, bytes);
        return 32 * *states;
    }
    yx_regex_nfa_utf8 p = {0};
    p.cache = calloc(10000, sizeof(*p.cache));
    if (!p.cache) return YX_REGEX_NFA_SIZE_LIMIT + 1;
    /* The standalone compiler emits its three-state search prefix and the
     * implicit capture start before visiting the Unicode class. */
    p.depth = 1; p.bytes = 32; p.next = target + 1;
    p.target = target; p.valid = true;
    for (size_t i = 0; i < count; ++i)
        yx_regex_nfa_utf8_range(&p, ranges[i].first, ranges[i].last);
    yx_regex_nfa_utf8_compile_from(&p, 0);
    (void)yx_regex_nfa_utf8_compile(&p, &p.nodes[0]);
    for (size_t i = 0; i < 10000; ++i) free(p.cache[i].transitions);
    free(p.cache);
    *states = p.next - target;
    return p.valid ? p.bytes : YX_REGEX_NFA_SIZE_LIMIT + 1;
}

static size_t yx_regex_nfa_unicode_class(const yx_re_range *ranges, size_t count)
{
    size_t states = 0;
    return yx_regex_nfa_unicode_class_at(ranges, count, 4, &states);
}
#endif

/* Port of regex-syntax's Utf8Sequences::next. Range subdivision, rather
 * than codepoint enumeration, is essential for (?u). and Unicode classes. */
static void yx_regex_size_utf8(uint32_t first, uint32_t last,
                                size_t *bytes, size_t *sequences)
{
    if (first > last || *sequences > 255) return;
    if (first < 0xe000 && last > 0xd7ff) {
        yx_regex_size_utf8(first, 0xd7ff, bytes, sequences);
        yx_regex_size_utf8(0xe000, last, bytes, sequences); return;
    }
    static const uint32_t maxima[] = {0x7f, 0x7ff, 0xffff};
    for (unsigned i = 0; i < 3; ++i) if (first <= maxima[i] && last > maxima[i]) {
        yx_regex_size_utf8(first, maxima[i], bytes, sequences);
        yx_regex_size_utf8(maxima[i] + 1, last, bytes, sequences); return;
    }
    for (unsigned i = 1; i < 4 && last > 127; ++i) {
        uint32_t mask = (1u << (6 * i)) - 1;
        if ((first & ~mask) != (last & ~mask)) {
            if (first & mask) {
                yx_regex_size_utf8(first, first | mask, bytes, sequences);
                yx_regex_size_utf8((first | mask) + 1, last, bytes, sequences);
                return;
            }
            if ((last & mask) != mask) {
                yx_regex_size_utf8(first, (last & ~mask) - 1, bytes, sequences);
                yx_regex_size_utf8(last & ~mask, last, bytes, sequences); return;
            }
        }
    }
    unsigned char a[4], b[4];
    unsigned width = yx_regex_size_encode(first, a);
    (void)yx_regex_size_encode(last, b);
    for (unsigned i = 0; i < width; ++i) {
        unsigned char set[256] = {0};
        for (unsigned j = a[i]; j <= b[i]; ++j) set[j] = 1;
        yx_regex_pike_size part = yx_regex_size_byte_class(set, false);
        *bytes = yx_regex_pike_size_add(*bytes, part.bytes[0]);
    }
    ++*sequences;
}

#include "regex_size_nfa.inc"
#include "regex_size_reverse.inc"
#include "regex_size_pike.inc"

static yx_regex_pike_size yx_regex_pike_size_expr(yx_regex_pike_size_parser *p);

static yx_regex_pike_size yx_regex_pike_size_atom(yx_regex_pike_size_parser *p)
{
    yx_regex_pike_size s = {0};
    size_t start = p->at;
    unsigned char ch = (unsigned char)p->body[p->at++];
    if (ch == '(') {
        bool old_x = p->extended, old_i = p->insensitive;
        bool old_s = p->dotall, old_u = p->unicode, old_m = p->multiline;
        bool old_g = p->ungreedy;
        bool flags_only = false, capture = true;
        if (p->at < p->length && p->body[p->at] == '?') {
            ++p->at;
            capture = false;
            if (p->at == p->length) p->valid = false;
            else if (p->body[p->at] == ':') ++p->at;
            else if (p->body[p->at] == '<' || p->body[p->at] == 'P') {
                capture = true;
                while (p->at < p->length && p->body[p->at] != '>') ++p->at;
                if (p->at < p->length) ++p->at;
                else p->valid = false;
            } else {
                bool negative = false;
                size_t header = p->at;
                while (p->at < p->length && strchr("imsuxUR-", p->body[p->at])) {
                    char flag = p->body[p->at++];
                    if (flag == '-') negative = true;
                    else if (flag == 'x') p->extended = !negative;
                    else if (flag == 'i') p->insensitive = !negative;
                    else if (flag == 's') p->dotall = !negative;
                    else if (flag == 'u') p->unicode = !negative;
                    else if (flag == 'm') p->multiline = !negative;
                    else if (flag == 'U') p->ungreedy = !negative;
                }
                if (p->at == header || p->at == p->length ||
                    (p->body[p->at] != ':' && p->body[p->at] != ')')) p->valid = false;
                else flags_only = p->body[p->at++] == ')';
            }
        }
        if (flags_only) s = yx_regex_size_empty();
        else if (++p->depth > 256) p->valid = false;
        else {
            s = yx_regex_pike_size_expr(p);
            --p->depth;
            if (p->at < p->length && p->body[p->at] == ')') ++p->at;
            else p->valid = false;
            if (capture) {
                s.nfa = yx_regex_pike_size_add(s.nfa, 64);
                s.node = yx_regex_nfa_wrap(p->arena, YX_NFA_CAPTURE, s.node);
                s.byte_class = s.literal = false;
                s.alternatives = 0;
            }
            p->extended = old_x; p->insensitive = old_i;
            p->dotall = old_s; p->unicode = old_u;
            p->multiline = old_m;
            p->ungreedy = old_g;
        }
    } else if (ch == '^' || ch == '$' ||
               (ch == '\\' && p->at < p->length &&
                strchr("bBAz", p->body[p->at]))) {
        if (ch == '\\') {
            char escape = p->body[p->at++];
            if (escape == 'b' && p->at < p->length && p->body[p->at] == '{' &&
                p->at + 1 < p->length && !isdigit((unsigned char)p->body[p->at + 1])) {
                while (p->at < p->length && p->body[p->at] != '}') ++p->at;
                if (p->at < p->length) ++p->at; else p->valid = false;
            }
        }
        s.bytes[0] = s.bytes[1] = 2; s.nfa = 32;
        s.zero = s.nullable = true;
        s.node = yx_regex_nfa_new(p->arena, YX_NFA_LOOK);
        if (s.node) {
            s.node->zero = s.node->nullable = true;
            s.node->anchored = (ch == '^' && !p->multiline) ||
                (ch == '\\' && p->body[start + 1] == 'A');
            s.node->look = p->multiline ? 1 : 0;
            for (size_t i = start; i < p->at; ++i)
                s.node->look = s.node->look * 33u + (unsigned char)p->body[i];
        }
    } else if (strchr("*+?{}]", ch)) p->valid = false;
    else if (ch >= 128 && !p->unicode) {
        size_t width = ch >= 0xc2 && ch < 0xe0 ? 2 : ch >= 0xe0 && ch < 0xf0 ? 3 :
            ch >= 0xf0 && ch < 0xf5 ? 4 : 0;
        if (!width || width > p->length - start) p->valid = false;
        else {
            size_t bytes = width;
            for (size_t i = 1; i < width; ++i) {
                unsigned char byte = (unsigned char)p->body[start + i];
                if ((byte & 0xc0) != 0x80) p->valid = false;
                if (byte == 0xaa) ++bytes;
            }
            p->at = start + width;
            s.bytes[0] = s.bytes[1] = bytes; s.nfa = 32 * width;
            s.literal = true;
            s.node = yx_regex_nfa_literal(p->arena,
                (const unsigned char *)p->body + start, width);
        }
    }
    else {
        unsigned char set[256] = {0};
        if (ch == '.' && !p->unicode) {
            memset(set, 1, 256);
            if (!p->dotall) set['\n'] = 0;
            s = yx_regex_size_byte_class(set, false);
        } else {
#ifdef XXYARA_NATIVE_REGEX
            yx_re_range *ranges = NULL;
            size_t count = 0, at = start;
            uint32_t options = (p->unicode ? PCRE2_UTF | PCRE2_UCP : 0) |
                               (p->insensitive ? PCRE2_CASELESS : 0);
            bool scalar_escape = !p->unicode && ch == '\\' && start + 1 < p->length &&
                (p->body[start + 1] == 'u' || p->body[start + 1] == 'U' ||
                 (p->body[start + 1] == 'x' && start + 2 < p->length &&
                  p->body[start + 2] == '{'));
            /* A plain ASCII byte or an escaped ASCII punctuation character
             * outside Unicode and extended scopes: the class parser would
             * return exactly that byte (no folding applies to non-letters). */
            unsigned plain = 256;
            if (!p->unicode && !p->extended) {
                if (ch && ch < 128 && ch != '\\' && ch != '[' && ch != '.') plain = ch;
                else if (ch == '\\' && start + 1 < p->length) {
                    unsigned char escaped = (unsigned char)p->body[start + 1];
                    if (escaped && escaped < 128 && !isalnum(escaped)) plain = escaped;
                }
                if (plain < 256 && p->insensitive && isalpha((int)plain)) plain = 256;
            }
            if (plain < 256) {
                yx_re_range one = {plain, plain};
                set[plain] = 1;
                s = yx_regex_size_byte_class(set, false);
                s.node = yx_regex_nfa_ranges(p->arena, &one, 1, false);
                p->at = start + (ch == '\\' ? 2 : 1);
            } else if (ch == '.') {
                yx_re_range dots[2] = {{0, p->dotall ? 0x10ffff : 9},
                                      {11, 0x10ffff}};
                size_t bytes = 0, sequences = 0;
                for (size_t i = 0; i < (p->dotall ? 1u : 2u); ++i)
                    yx_regex_size_utf8(dots[i].first, dots[i].last, &bytes, &sequences);
                s.bytes[0] = s.bytes[1] = yx_regex_pike_size_add(bytes,
                    sequences > 1 ? 10 * sequences - 1 : 0);
                s.splits[0] = s.splits[1] = sequences > 1;
                s.nfa = yx_regex_nfa_unicode_class(dots, p->dotall ? 1u : 2u);
                s.node = yx_regex_nfa_ranges(p->arena, dots, p->dotall ? 1u : 2u, true);
                if (p->dotall) {
                    s.bytes[0] = s.bytes[1] = 2;
                    s.splits[0] = s.splits[1] = 0;
                }
            } else if (yx_re_class_ranges((const unsigned char *)p->body,
                        p->length, &at, scalar_escape ? PCRE2_UTF : options, &ranges, &count)) {
                /* u/U escapes are scalar literals even when Unicode classes
                 * are disabled. Only ASCII case folding applies in byte mode. */
                if (scalar_escape && count == 1 && ranges[0].last < 128 && p->insensitive) {
                    free(ranges); ranges = NULL; at = start;
                    if (!yx_re_class_ranges((const unsigned char *)p->body,
                            p->length, &at, options, &ranges, &count)) p->valid = false;
                }
                bool class_unicode = p->unicode ||
                    (scalar_escape && count == 1 && ranges[0].first >= 128);
                bool ascii = !count || ranges[count - 1].last < (class_unicode ? 128u : 256u);
                if (ascii) {
                    for (size_t i = 0; i < count; ++i)
                        for (uint32_t j = ranges[i].first; j <= ranges[i].last; ++j) set[j] = 1;
                    s = yx_regex_size_byte_class(set, class_unicode);
                } else {
                    size_t bytes = 0, sequences = 0;
                    for (size_t i = 0; i < count; ++i)
                        yx_regex_size_utf8(ranges[i].first, ranges[i].last, &bytes, &sequences);
                    s.bytes[0] = s.bytes[1] = sequences > 255 ? YX_REGEX_PIKE_SIZE_LIMIT + 1 :
                        yx_regex_pike_size_add(bytes, sequences > 1 ? 10 * sequences - 1 : 0);
                    s.splits[0] = s.splits[1] = sequences > 1;
                    s.nfa = yx_regex_nfa_unicode_class(ranges, count);
                }
                s.node = yx_regex_nfa_ranges(p->arena, ranges, count, class_unicode);
                p->at = at;
            } else p->valid = false;
            free(ranges);
#else
            /* The PCRE2 build retains its own full syntax validation. */
            if (ch == '\\' && p->at < p->length) ch = (unsigned char)p->body[p->at++];
            if (ch == '[') {
                while (p->at < p->length && p->body[p->at] != ']') ++p->at;
                if (p->at < p->length) ++p->at;
                p->valid = false;
            }
            set[ch] = 1;
            s = yx_regex_size_byte_class(set, false);
#endif
        }
    }
    if (!s.node && s.byte_class)
        s.node = yx_regex_nfa_set(p->arena, s.set, s.unicode_class);
    if (!s.node && s.zero && !s.bytes[0])
        s.node = yx_regex_nfa_new(p->arena, YX_NFA_EMPTY);
    yx_regex_pike_size_space(p);
    while (p->valid && p->at < p->length && strchr("*+?{", p->body[p->at])) {
        size_t lower = 0, upper = 0;
        bool unbounded = false;
        char repeat = p->body[p->at++];
        if (repeat == '*') unbounded = true;
        else if (repeat == '+') { lower = 1; unbounded = true; }
        else if (repeat == '?') upper = 1;
        else {
            yx_regex_size_bound_space(p);
            bool has_lower = yx_regex_pike_size_decimal(p, &lower);
            yx_regex_size_bound_space(p);
            if (p->at < p->length && p->body[p->at] == ',') {
                ++p->at; yx_regex_size_bound_space(p);
                bool has_upper = yx_regex_pike_size_decimal(p, &upper);
                unbounded = !has_upper;
                if (!has_lower && !has_upper) p->valid = false;
            } else { upper = lower; if (!has_lower) p->valid = false; }
            yx_regex_size_bound_space(p);
            if (p->at < p->length && p->body[p->at] == '}') ++p->at;
            else p->valid = false;
            if (!unbounded && upper < lower) p->valid = false;
        }
        yx_regex_pike_size_space(p);
        bool greedy = !p->ungreedy;
        if (p->at < p->length && p->body[p->at] == '?') {
            ++p->at; greedy = !greedy;
        }
        if (s.zero) {
            lower = lower ? 1 : 0; upper = unbounded || upper ? 1 : 0;
            unbounded = false;
        }
        yx_regex_pike_size child = s;
        if (!unbounded && !upper) {
            s = yx_regex_size_empty();
            s.node = yx_regex_nfa_new(p->arena, YX_NFA_EMPTY);
            continue;
        }
        if (!unbounded && lower == 1 && upper == 1) continue;
        s.byte_class = s.literal = false;
        s.alternatives = 0;
        for (unsigned parent = 0; parent < 2; ++parent) {
            bool loop = !unbounded && upper > 10 && !parent;
            size_t copies = unbounded ? (lower ? lower : 1) : loop ? (lower ? 2 : 1) : upper;
            unsigned context = loop ? 1 : 0;
            size_t overhead = unbounded ? (lower ? 8 : 14) : loop ?
                (lower <= 1 ? 22 : 14) : 8 * (upper - lower);
            size_t splits = unbounded ? 1 : loop ? lower <= 1 : upper - lower;
            s.bytes[parent] = yx_regex_pike_size_add(
                yx_regex_pike_size_mul(child.bytes[context], copies), overhead);
            s.splits[parent] = yx_regex_pike_size_add(
                yx_regex_pike_size_mul(child.splits[context], copies), splits);
        }
        if (unbounded) s.nfa = yx_regex_pike_size_add(
            yx_regex_pike_size_mul(child.nfa, lower ? lower : 1),
            !lower && child.nullable ? 112 : 40);
        else if (lower == upper) s.nfa = yx_regex_pike_size_mul(child.nfa, upper);
        else if (!lower && upper == 1)
            s.nfa = yx_regex_pike_size_add(child.nfa, 72);
        else s.nfa = yx_regex_pike_size_add(yx_regex_pike_size_mul(child.nfa, upper),
            yx_regex_pike_size_add(yx_regex_pike_size_mul(40, upper - lower), 32 + (!lower ? 32 : 0)));
        s.nullable = !lower || child.nullable;
        s.node = yx_regex_nfa_wrap(p->arena, YX_NFA_REPEAT, child.node);
        if (s.node) {
            s.node->lower = lower; s.node->upper = upper;
            s.node->greedy = greedy;
            s.node->unbounded = unbounded; s.node->nullable = s.nullable;
            if (!lower) s.node->anchored = false;
        }
    }
    return s;
}

static yx_regex_pike_size yx_regex_pike_size_expr(yx_regex_pike_size_parser *p)
{
    yx_regex_pike_size total = {0}, branch = yx_regex_size_empty();
    yx_regex_nfa_node *sequence = yx_regex_nfa_new(p->arena, YX_NFA_CONCAT);
    yx_regex_nfa_node *choices = yx_regex_nfa_new(p->arena, YX_NFA_ALT);
    unsigned char all[256] = {0};
    size_t alternatives = 0, atoms = 0;
    bool class_union = true, unicode = false, literals = true;
    total.zero = total.nullable = true;
    for (;;) {
        yx_regex_pike_size_space(p);
        bool end = p->at == p->length || p->body[p->at] == ')';
        if (end || p->body[p->at] == '|') {
            branch.node = yx_regex_nfa_list_finish(p->arena, sequence);
            yx_regex_nfa_append(p->arena, choices, branch.node);
            if (!branch.byte_class) class_union = false;
            else for (unsigned i = 0; i < 256; ++i) all[i] |= branch.set[i];
            unicode |= branch.unicode_class;
            literals &= branch.literal;
            for (unsigned i = 0; i < 2; ++i) {
                total.bytes[i] = yx_regex_pike_size_add(total.bytes[i],
                    branch.bytes[i] - (branch.alternatives ? 10 * branch.alternatives - 1 : 0));
                total.splits[i] = yx_regex_pike_size_add(total.splits[i],
                    branch.splits[i] - (branch.alternatives ? 1 : 0));
            }
            total.nfa = yx_regex_pike_size_add(total.nfa,
                branch.nfa - (branch.alternatives ? 64 + 4 * branch.alternatives : 0));
            total.zero &= branch.zero;
            if (!alternatives) total.nullable = branch.nullable;
            else total.nullable |= branch.nullable;
            alternatives += branch.alternatives ? branch.alternatives : 1;
            if (end) break;
            ++p->at; branch = yx_regex_size_empty(); atoms = 0;
            sequence = yx_regex_nfa_new(p->arena, YX_NFA_CONCAT);
            continue;
        }
        size_t before = p->at;
        yx_regex_pike_size atom = yx_regex_pike_size_atom(p);
        if (p->at == before) { p->valid = false; break; }
        if (atom.zero && atom.bytes[0] == 0 && atom.nfa == 32) continue;
        yx_regex_nfa_append(p->arena, sequence, atom.node);
        if (!atoms++) branch = atom;
        else {
            for (unsigned i = 0; i < 2; ++i) {
                branch.bytes[i] = yx_regex_pike_size_add(branch.bytes[i], atom.bytes[i]);
                branch.splits[i] = yx_regex_pike_size_add(branch.splits[i], atom.splits[i]);
            }
            branch.nfa = yx_regex_pike_size_add(branch.nfa, atom.nfa);
            branch.zero &= atom.zero; branch.nullable &= atom.nullable;
            branch.byte_class = branch.literal = false;
            branch.alternatives = 0;
        }
    }
    if (alternatives == 1) return branch;
    if (class_union) {
        yx_regex_pike_size result = yx_regex_size_byte_class(all, unicode || literals);
        result.node = yx_regex_nfa_list_finish(p->arena, choices);
        return result;
    }
    for (unsigned i = 0; i < 2; ++i) {
        total.bytes[i] = yx_regex_pike_size_add(total.bytes[i], 10 * alternatives - 1);
        total.splits[i] = yx_regex_pike_size_add(total.splits[i], 1);
    }
    total.nfa = yx_regex_pike_size_add(total.nfa, 64 + 4 * alternatives);
    total.alternatives = alternatives;
    total.node = yx_regex_nfa_list_finish(p->arena, choices);
    return total;
}

/* Both results of one pike-size walk: the size error label (a string
 * literal, or NULL) and whether the regexp can match empty data. The parser
 * asks for the label and validation for nullability, for every regexp and
 * each repetition of it, so the pair is memoized per (body, modifiers), the
 * walk's only inputs. */
typedef struct {
    const char *label;
    bool nullable;
} yx_regex_pike_summary;

static yx_regex_pike_summary yx_regex_pike_size_summary(const char *body, size_t length,
                                                        unsigned modifiers)
{
    yx_regex_pike_summary summary = {NULL, false};
    uint64_t tag = YX_MEMO_TAG(YX_MEMO_PIKE_SIZE, 0, modifiers);
    size_t stored = 0;
    const void *hit = yx_compile_memo_find(tag, body, length, &stored);
    if (hit && stored == sizeof(summary)) {
        memcpy(&summary, hit, sizeof(summary));
        return summary;
    }
    yx_regex_nfa_arena arena = {0};
    yx_regex_pike_size_parser p = {body, length, 0, 0, false,
        (modifiers & YX_MOD_NOCASE) != 0, (modifiers & YX_MOD_DOTALL) != 0,
        false, true};
    p.arena = &arena;
    yx_regex_pike_size s = yx_regex_pike_size_expr(&p);
    if (p.valid && p.at == length && !arena.failed) {
        summary.nullable = s.nullable;
        (void)yx_regex_vm_size_large(&arena, s.node, modifiers, &summary.label);
    }
    /* An allocation failure is not kept. */
    bool keep = !arena.failed;
    yx_regex_nfa_free(&arena);
    if (keep) yx_compile_memo_store(tag, body, length, &summary, sizeof(summary));
    return summary;
}

static const char *yx_regex_pike_size_error(const char *body, size_t length,
                                              unsigned modifiers)
{
    return yx_regex_pike_size_summary(body, length, modifiers).label;
}

static bool yx_regex_pike_size_large(const char *body, size_t length,
                                      unsigned modifiers)
{
    return yx_regex_pike_size_error(body, length, modifiers) != NULL;
}

bool yx_regex_can_match_empty(const char *body, size_t length,
                              unsigned modifiers)
{
    return yx_regex_pike_size_summary(body, length, modifiers).nullable;
}

/* Condition expressions use regex-automata's NFA, whose intermediate x64
 * builder states occupy 32 bytes. Its 50 MiB limit is independent of the
 * instruction and split-ID limits imposed by the pattern PikeVM compiler. */
bool yx_regex_automata_size_large(const char *body, size_t length,
                                  unsigned modifiers)
{
    yx_regex_nfa_arena arena = {0};
    yx_regex_pike_size_parser p = {body, length, 0, 0, false,
        (modifiers & YX_MOD_NOCASE) != 0, (modifiers & YX_MOD_DOTALL) != 0,
        false, true};
    p.arena = &arena;
    yx_regex_pike_size s = yx_regex_pike_size_expr(&p);
    /* meta/literal.rs:29-80 selects Aho-Corasick for at least 3000 plain
     * literal alternatives, without building either Thompson NFA. */
    bool literal_search = s.node && s.node->kind == YX_NFA_ALT && s.node->count >= 3000;
    for (yx_regex_nfa_link *l = literal_search ? s.node->first : NULL; l; l = l->next)
        literal_search &= l->node->literal;
    bool large = p.valid && p.at == length && !arena.failed && !literal_search &&
        (yx_regex_nfa_size(s.node) > YX_REGEX_NFA_SIZE_LIMIT ||
         yx_regex_nfa_reverse_size(s.node) > YX_REGEX_NFA_SIZE_LIMIT);
    yx_regex_nfa_free(&arena);
    return large;
}
