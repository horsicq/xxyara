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

/* Regexp sub-patterns for the scanner. The sub-pattern kind follows
 * c_regexp_pattern in YARA-X v1.21.0: a chain for large any-byte gaps, a
 * literal or alternation of literals, a literal with mask, and otherwise a
 * regexp for FastVM or PikeVM. Only the last kind is built here; it uses the
 * same compilers as the archive writer, so atoms and code match the
 * reference's compiled rules. Included by serialization.c. */
#ifndef XXYARA_SERIALIZATION_ENGINE_H
#define XXYARA_SERIALIZATION_ENGINE_H

#include "regex_vm.h"

static bool yx_se_any_byte(const yx_tr_node *node)
{
    /* re::hir::any_byte also accepts a Unicode class of every scalar. */
    if (node && node->kind == YX_TR_SCALAR_CLASS) return yx_u8_any(node);
    if (!node || node->kind != YX_TR_CLASS || node->unicode_class) return false;
    for (unsigned b = 0; b < 256; ++b) if (!yx_tr_has(node->bitmap, b)) return false;
    return true;
}

static uint64_t yx_se_minimum_length(const yx_tr_node *node)
{
    uint64_t total = 0, best = UINT64_MAX;
    switch (node->kind) {
    case YX_TR_LITERAL: return node->length;
    case YX_TR_CLASS: return 1;
    /* ClassUnicode::minimum_len: the UTF-8 length of its first scalar. */
    case YX_TR_SCALAR_CLASS: {
        uint32_t first = node->length ? ((const yx_re_range *)node->bytes)[0].first : 0;
        return first < 0x80 ? 1 : first < 0x800 ? 2 : first < 0x10000 ? 3 : 4;
    }
    case YX_TR_REPEAT: {
        uint64_t child = node->count ? yx_se_minimum_length(node->children[0]) : 0;
        return child && node->minimum > UINT64_MAX / child ? UINT64_MAX : child * node->minimum;
    }
    case YX_TR_CONCAT:
        for (size_t i = 0; i < node->count; ++i) {
            uint64_t child = yx_se_minimum_length(node->children[i]);
            total = child > UINT64_MAX - total ? UINT64_MAX : total + child;
        }
        return total;
    case YX_TR_ALT:
        for (size_t i = 0; i < node->count; ++i) {
            uint64_t child = yx_se_minimum_length(node->children[i]);
            if (child < best) best = child;
        }
        return node->count ? best : 0;
    case YX_TR_CAPTURE: return node->count ? yx_se_minimum_length(node->children[0]) : 0;
    default: return 0;
    }
}

/* split_at_large_gaps: whether any split or trailing-gap removal applies.
 * A last chunk shorter than 2 bytes rejoins the previous piece with its
 * gap, so ab(?s:.)+c and { 61 62 [-] 63 } remain one regexp. */
static bool yx_se_has_large_gap(const yx_tr_node *root)
{
    uint64_t chunk_minimum = 0;
    bool chunks = false;
    size_t pieces = 0;
    if (root->kind != YX_TR_CONCAT) return false;
    for (size_t i = 0; i < root->count; ++i) {
        const yx_tr_node *item = root->children[i];
        if (item->kind == YX_TR_REPEAT && item->count && yx_se_any_byte(item->children[0])) {
            uint64_t maximum = yx_tr_unbounded(item) ? UINT32_MAX : item->maximum;
            if (chunks && maximum > 200) {
                if (chunk_minimum >= 2) {
                    ++pieces; chunks = false; chunk_minimum = 0;
                    continue;
                }
                /* The short chunk and the gap merge into the next chunk. */
                chunk_minimum += yx_se_minimum_length(item);
                continue;
            }
        }
        chunks = true;
        chunk_minimum += yx_se_minimum_length(item);
    }
    /* A trailing gap is dropped (yx_ser_gap_head_regexp); a last chunk is a
     * piece of its own only when it matches at least 2 bytes. */
    return pieces && (!chunks || pieces > 1 || chunk_minimum >= 2);
}

static bool yx_se_alternation_literal(const yx_tr_node *node)
{
    if (node->kind == YX_TR_CAPTURE && node->count) node = node->children[0];
    if (node->kind == YX_TR_LITERAL) return true;
    if (node->kind != YX_TR_ALT) return false;
    for (size_t i = 0; i < node->count; ++i)
        if (node->children[i]->kind != YX_TR_LITERAL) return false;
    return true;
}

/* try_extract_literal_with_mask, without the atom-size check. */
static bool yx_se_masked_literal(const yx_tr_node *node)
{
    switch (node->kind) {
    case YX_TR_LITERAL: return true;
    case YX_TR_REPEAT:
        /* Only fixed any-byte gaps of at most PATTERN_CHAINING_THRESHOLD
         * (200) bytes become mask bytes; a longer one is a FastVM jump,
         * which its 4096-byte scan limit bounds. */
        return node->count && !yx_tr_unbounded(node) && node->minimum == node->maximum &&
               node->minimum <= 200 && yx_se_any_byte(node->children[0]);
    case YX_TR_CONCAT: case YX_TR_CAPTURE:
        for (size_t i = 0; i < node->count; ++i)
            if (!yx_se_masked_literal(node->children[i])) return false;
        return true;
    case YX_TR_CLASS: {
        unsigned first = 256, last = 0, count = 0, bits = 0;
        if (node->unicode_class) return false;
        for (unsigned b = 0; b < 256; ++b) if (yx_tr_has(node->bitmap, b)) { if (first == 256) first = b; last = b; ++count; }
        if (!count) return false;
        for (unsigned b = 0; b < 256; ++b) if (yx_tr_has(node->bitmap, b) && (b & first) != first) return false;
        for (unsigned k = 0; k < 8; ++k) bits += ((first ^ last) >> k) & 1u;
        return (1u << bits) == count;
    }
    default: return false;
    }
}

static bool yx_se_atoms(yx_rx_sub *sub, const yx_archive_regexp_atom *atoms, size_t count, bool wide)
{
    sub->atoms = calloc(count ? count : 1, sizeof(*sub->atoms));
    if (!sub->atoms) return false;
    sub->atom_count = count;
    for (size_t i = 0; i < count; ++i) {
        const yx_archive_regexp_atom *from = &atoms[i];
        yx_rx_atom *to = &sub->atoms[i];
        if (from->length > (wide ? 4u : 8u)) return false;
        for (size_t j = 0; j < from->length; ++j) {
            if (wide) { to->bytes[2 * j] = from->bytes[j]; to->bytes[2 * j + 1] = 0; }
            else to->bytes[j] = from->bytes[j];
        }
        to->length = (uint8_t)(from->length * (wide ? 2 : 1));
        to->backtrack = (size_t)from->backtrack * (wide ? 2 : 1);
        to->exact = from->exact;
        to->has_fwd = from->has_forward;
        to->has_bck = from->has_backward;
        to->fwd = from->forward;
        to->bck = from->backward;
    }
    return true;
}

/* re::fast::compiler::PatternSplitter over the regexp HIR: literals and
 * masked bytes accumulate, any-byte repetitions become jumps, and one
 * level of alternation of such sequences becomes an alternation piece.
 * Captures are transparent; look-around and Unicode classes are not
 * FastVM-compatible. */
typedef struct {
    yx_fast_program *p;
    yx_fast_literal *alternatives;
    size_t alternative_count;
    bool in_alternation, in_repetition;
} yx_ft_splitter;

static bool yx_ft_class(yx_ft_splitter *s, const yx_tr_node *node)
{
    yx_fast_program *p = s->p;
    unsigned first = 256, last = 0, count = 0, bits = 0;
    bool cube = true;
    for (unsigned b = 0; b < 256; ++b) if (yx_tr_has(node->bitmap, b)) { if (first == 256) first = b; last = b; ++count; }
    if (!count) return false;
    /* class_to_masked_byte */
    for (unsigned b = 0; b < 256; ++b) if (yx_tr_has(node->bitmap, b) && (b & first) != first) cube = false;
    for (unsigned k = 0; k < 8; ++k) bits += ((first ^ last) >> k) & 1u;
    if (cube && (1u << bits) == count) return yx_fast_append(p, (uint8_t)first, (uint8_t)~(first ^ last));
    if (s->in_alternation) return false;
    /* class_to_masked_bytes_alternation: every range is a bit cube. */
    yx_fast_literal *items = calloc(256, sizeof(*items));
    size_t n = 0;
    bool ok = items != NULL;
    for (unsigned b = 0; ok && b < 256;) {
        if (!yx_tr_has(node->bitmap, b)) { ++b; continue; }
        unsigned end = b, range_bits = 0;
        while (end + 1 < 256 && yx_tr_has(node->bitmap, end + 1)) ++end;
        for (unsigned k = 0; k < 8; ++k) range_bits += ((b ^ end) >> k) & 1u;
        if ((b & end) != b || (1u << range_bits) != end - b + 1) ok = false;
        else {
            items[n].bytes = malloc(1); items[n].mask = malloc(1); items[n].length = 1; items[n].force_masked = true;
            if (!items[n].bytes || !items[n].mask) ok = false;
            else { items[n].bytes[0] = (uint8_t)b; items[n].mask[0] = (uint8_t)~(b ^ end); }
            ++n;
        }
        b = end + 1;
    }
    if (!ok || !yx_fast_flush(p) || !yx_fast_piece_reserve(p)) {
        for (size_t i = 0; items && i < n; ++i) yx_fast_literal_destroy(&items[i]);
        free(items);
        return false;
    }
    yx_fast_piece *piece = &p->pieces[p->count++];
    piece->kind = 7; piece->alternatives = items; piece->alternative_count = n;
    return true;
}

static bool yx_ft_take_alternative(yx_ft_splitter *s)
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

static bool yx_ft_split(yx_ft_splitter *s, const yx_tr_node *node, size_t depth)
{
    yx_fast_program *p = s->p;
    if (depth > 250) return false;
    switch (node->kind) {
    case YX_TR_EMPTY: return true;
    case YX_TR_LITERAL:
        for (size_t i = 0; i < node->length; ++i) if (!yx_fast_append(p, node->bytes[i], 255)) return false;
        return true;
    case YX_TR_CLASS:
        if (s->in_repetition) return true;
        return !node->unicode_class && yx_ft_class(s, node);
    /* A Unicode class is FastIncompatible unless it is the gap of a
     * repetition, which the repetition has checked. */
    case YX_TR_SCALAR_CLASS: return s->in_repetition;
    case YX_TR_LOOK: return false;
    case YX_TR_CAPTURE: case YX_TR_CONCAT:
        for (size_t i = 0; i < node->count; ++i) if (!yx_ft_split(s, node->children[i], depth + 1)) return false;
        return true;
    case YX_TR_REPEAT: {
        if (s->in_repetition || s->in_alternation || !node->count) return false;
        const yx_tr_node *sub = node->children[0];
        bool newline, unbounded = yx_tr_unbounded(node);
        if (!yx_tr_gap_class(sub, &newline)) return false;
        if (!yx_fast_jump(p, node->minimum, unbounded ? UINT32_MAX : node->maximum, newline, unbounded)) return false;
        s->in_repetition = true;
        bool ok = yx_ft_split(s, sub, depth + 1);
        s->in_repetition = false;
        return ok;
    }
    case YX_TR_ALT: {
        if (s->in_repetition || s->in_alternation || node->count > 255 || !yx_fast_flush(p)) return false;
        s->in_alternation = true; s->alternative_count = 0;
        s->alternatives = calloc(256, sizeof(*s->alternatives));
        if (!s->alternatives) return false;
        bool ok = true;
        for (size_t i = 0; ok && i < node->count; ++i) {
            if (i) ok = yx_ft_take_alternative(s);
            if (ok) ok = yx_ft_split(s, node->children[i], depth + 1);
        }
        if (ok) ok = yx_ft_take_alternative(s);
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
    }
    return false;
}

/* The FastVM pieces of a regexp, as yx_fast_regex builds them. */
static bool yx_ft_regex(yx_fast_program *p, const yx_tr_node *root, bool greedy)
{
    yx_ft_splitter splitter = {.p = p};
    bool ok = yx_ft_split(&splitter, root, 0) && yx_fast_flush(p);
    p->flags = (uint16_t)(64 | (greedy ? 32 : 0));
    return ok;
}

/* split_at_large_gaps when its only effect is dropping a trailing gap:
 * a top-level concatenation that ends in an any-byte repetition spanning
 * more than 200 bytes after a head of at least 2 bytes, with no other
 * split. YARA-X then compiles the head alone, so /ab.*\/s matches "ab".
 * Returns the head's source text, or NULL. */
char *yx_ser_gap_head_regexp(const YRX_PATTERN *pattern)
{
    if (!pattern || pattern->kind != YX_PATTERN_REGEX || !pattern->regexp) return NULL;
    bool dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    const char *text = pattern->regexp;
    size_t length = strlen(text);
    char *head = NULL;
    yx_tr_parser parser = {.text = (const uint8_t *)text, .length = length, .dotall = dotall, .nocase = nocase};
    yx_tr_node *root = yx_tr_expression(&parser);
    if (!root || parser.failed || parser.oom || parser.at != length || root->kind != YX_TR_CONCAT) goto done;
    uint64_t chunk_minimum = 0;
    bool chunks = false;
    size_t pieces = 0;
    for (size_t i = 0; i < root->count; ++i) {
        const yx_tr_node *item = root->children[i];
        if (item->kind == YX_TR_REPEAT && item->count && yx_se_any_byte(item->children[0]) && chunks) {
            uint64_t maximum = yx_tr_unbounded(item) ? UINT32_MAX : item->maximum;
            if (maximum > 200) {
                if (chunk_minimum >= 2) { ++pieces; chunks = false; chunk_minimum = 0; continue; }
                chunk_minimum += yx_se_minimum_length(item);
                continue;
            }
        }
        chunks = true;
        chunk_minimum += yx_se_minimum_length(item);
    }
    if (chunks || pieces != 1) goto done;
    const yx_tr_node *gap = root->children[root->count - 1];
    /* The gap is the last child of the flattened top-level concatenation,
     * also inside a scoped group such as (?s:ab.+): the head is the source
     * without the gap's own text (yx_tr_atom's span of it, which covers a
     * group that holds only the gap), so its flags stay as they were. */
    if (gap->start < gap->end && gap->end <= length) {
        size_t k = length - (gap->end - gap->start);
        char *candidate = malloc(k + 1);
        if (!candidate) goto done;
        memcpy(candidate, text, gap->start);
        memcpy(candidate + gap->start, text + gap->end, length - gap->end);
        candidate[k] = 0;
        yx_tr_parser prefix = {.text = (const uint8_t *)candidate, .length = k, .dotall = dotall, .nocase = nocase};
        yx_tr_node *rest = yx_tr_expression(&prefix);
        /* The head keeps every child but the gap. */
        bool complete = rest && !prefix.failed && !prefix.oom && prefix.at == k &&
            (root->count == 2 ? rest->kind == root->children[0]->kind :
             rest->kind == YX_TR_CONCAT && rest->count == root->count - 1);
        /* The head keeps the pattern's greediness (set_greedy), which a
         * regexp or masked-literal head carries as its GreedyRegexp flag. A
         * head without quantifiers of a greedy pattern gets a greedy empty
         * repetition, which adds nothing to the HIR. */
        bool marker = complete && parser.saw_greedy && !parser.saw_lazy && !prefix.saw_greedy &&
                      !yx_se_alternation_literal(rest);
        yx_tr_destroy(rest);
        if (marker) {
            /* In the gap's place, where the gap's own flags apply: text
             * after it can be an extended-mode comment (/(?s)ab.+(?x)#c/),
             * which would swallow a marker appended to the end. */
            static const char mark[] = "(?:){1}";
            size_t n = sizeof(mark) - 1;
            char *marked = realloc(candidate, k + n + 1);
            if (!marked) { free(candidate); goto done; }
            memmove(marked + gap->start + n, marked + gap->start, k - gap->start + 1);
            memcpy(marked + gap->start, mark, n);
            candidate = marked;
        }
        if (complete) head = candidate;
        else free(candidate);
    }
done:
    yx_tr_destroy(root);
    return head;
}

/* YARA-X drops a trailing gap while compiling (split_at_large_gaps), so the
 * compiled rules hold only the head: /(?s)ab.+/ and /(?s:\bab.+)/ are
 * archived exactly as /ab/ and /\bab/. A copy of rules whose regexp
 * patterns with such a gap are their heads; false when there is none (or
 * *failed on allocation failure). Release it with yx_ser_gap_heads_free. */
static void yx_ser_gap_heads_free(const YRX_RULES *rules, YRX_RULES *copy);
static bool yx_ser_gap_heads(const YRX_RULES *rules, YRX_RULES *copy, bool *failed)
{
    YRX_RULE *copies = NULL;
    *failed = false;
    for (size_t i = 0; rules && rules->rules && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            const YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            char *head = NULL;
            if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp && pattern->gap_head_regexp) {
                size_t n = strlen(pattern->gap_head_regexp) + 1;
                if (!(head = malloc(n))) goto failure;
                memcpy(head, pattern->gap_head_regexp, n);
            } else if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp)
                head = yx_ser_gap_head_regexp(pattern);
            if (!head) continue;
            if (!copies) {
                copies = malloc(rules->rule_count * sizeof(*copies));
                if (!copies) { free(head); goto failure; }
                memcpy(copies, rules->rules, rules->rule_count * sizeof(*copies));
            }
            if (copies[i].patterns == rules->rules[i].patterns) {
                YRX_PATTERN *patterns = malloc(rules->rules[i].pattern_count * sizeof(*patterns));
                if (!patterns) { free(head); goto failure; }
                memcpy(patterns, rules->rules[i].patterns, rules->rules[i].pattern_count * sizeof(*patterns));
                copies[i].patterns = patterns;
            }
            copies[i].patterns[j].regexp = head;
            copies[i].patterns[j].gap_head_regexp = NULL;
        }
    if (!copies) return false;
    *copy = *rules;
    copy->rules = copies;
    return true;
failure:
    if (copies) {
        YRX_RULES partial = *rules;
        partial.rules = copies;
        yx_ser_gap_heads_free(rules, &partial);
    }
    *failed = true;
    return false;
}

static void yx_ser_gap_heads_free(const YRX_RULES *rules, YRX_RULES *copy)
{
    for (size_t i = 0; i < rules->rule_count; ++i) {
        if (copy->rules[i].patterns == rules->rules[i].patterns) continue;
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j)
            if (copy->rules[i].patterns[j].regexp != rules->rules[i].patterns[j].regexp)
                free(copy->rules[i].patterns[j].regexp);
        free(copy->rules[i].patterns);
    }
    free(copy->rules);
    copy->rules = NULL;
}

/* Source spellings the archive codecs do not read, rewritten to equivalent ones before encoding:
 * - a Unicode scalar escape outside a class in a byte-mode regexp (`\x{e9}`, `\u00e9`, `\U000000e9`) is the
 *   literal of the scalar's UTF-8 bytes (regex-syntax Literal), so /a\x{e9}+/ is archived as /a(?:\xc3\xa9)+/;
 * - a `for`/`with` variable whose identifier has non-ASCII (Unicode Nd) digits: variable names are not part of
 *   the archive, so each gets an ASCII name (a prefix that occurs in no condition and no rule name, then the
 *   identifier's bytes in hex, so no two names can meet). Identifiers that name a rule are kept.
 * A copy of rules with the rewritten texts; false when nothing changes (or *failed on allocation failure).
 * Release it with yx_ser_spellings_free. */
static int yx_ser_hex_digit(unsigned char c)
{ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
/* NULL when the text stays as it is; *failed on allocation failure. */
static char *yx_ser_scalar_regexp(const char *text, bool *failed)
{
    if (!text || (!strstr(text, "\\x{") && !strstr(text, "\\u") && !strstr(text, "\\U"))) return NULL;
    yx_writer out = {0};
    bool unicode[64]; size_t depth = 0, class_depth = 0; bool changed = false;
    unicode[0] = false;
    for (const unsigned char *at = (const unsigned char *)text; *at;) {
        if (*at == '\\' && at[1]) {
            uint32_t scalar = 0; size_t width = 0;
            if (!class_depth && !unicode[depth]) {
                if (at[1] == 'x' && at[2] == '{') {
                    size_t i = 3, digits = 0;
                    while (yx_ser_hex_digit(at[i]) >= 0 && digits < 8) {
                        scalar = scalar << 4 | (uint32_t)yx_ser_hex_digit(at[i]); ++i; ++digits;
                    }
                    if (digits && at[i] == '}') width = i + 1;
                } else if (at[1] == 'u' || at[1] == 'U') {
                    size_t digits = at[1] == 'u' ? 4 : 8, i = 0;
                    while (i < digits && yx_ser_hex_digit(at[2 + i]) >= 0) {
                        scalar = scalar << 4 | (uint32_t)yx_ser_hex_digit(at[2 + i]); ++i;
                    }
                    if (i == digits) width = 2 + digits;
                }
            }
            if (width && scalar <= 0x10ffff && !(scalar >= 0xd800 && scalar <= 0xdfff)) {
                uint8_t utf8[4]; size_t n = 0; char piece[8];
                if (scalar < 0x80) utf8[n++] = (uint8_t)scalar;
                else if (scalar < 0x800) {
                    utf8[n++] = (uint8_t)(0xc0 | scalar >> 6); utf8[n++] = (uint8_t)(0x80 | (scalar & 0x3f));
                } else if (scalar < 0x10000) {
                    utf8[n++] = (uint8_t)(0xe0 | scalar >> 12); utf8[n++] = (uint8_t)(0x80 | (scalar >> 6 & 0x3f));
                    utf8[n++] = (uint8_t)(0x80 | (scalar & 0x3f));
                } else {
                    utf8[n++] = (uint8_t)(0xf0 | scalar >> 18); utf8[n++] = (uint8_t)(0x80 | (scalar >> 12 & 0x3f));
                    utf8[n++] = (uint8_t)(0x80 | (scalar >> 6 & 0x3f)); utf8[n++] = (uint8_t)(0x80 | (scalar & 0x3f));
                }
                if (n > 1 && !yx_put_bytes(&out, "(?:", 3)) goto no_memory;
                for (size_t i = 0; i < n; ++i) {
                    snprintf(piece, sizeof(piece), "\\x%02x", utf8[i]);
                    if (!yx_put_bytes(&out, piece, 4)) goto no_memory;
                }
                if (n > 1 && !yx_put_u8(&out, ')')) goto no_memory;
                at += width; changed = true;
                continue;
            }
            if (!yx_put_bytes(&out, at, 2)) goto no_memory;
            at += 2;
            continue;
        }
        if (class_depth) {
            if (*at == '[') {
                if (at[1] == ':') {
                    /* A POSIX class name: copy through its `:]`. */
                    const char *end = strstr((const char *)at + 2, ":]");
                    if (end) {
                        size_t n = (size_t)(end + 2 - (const char *)at);
                        if (!yx_put_bytes(&out, at, n)) goto no_memory;
                        at += n;
                        continue;
                    }
                }
                ++class_depth;
            } else if (*at == ']') --class_depth;
        } else if (*at == '[') {
            class_depth = 1;
            if (!yx_put_u8(&out, *at++)) goto no_memory;
            if (*at == '^' && !yx_put_u8(&out, *at++)) goto no_memory;
            if (*at == ']' && !yx_put_u8(&out, *at++)) goto no_memory;
            continue;
        } else if (*at == '(') {
            bool inherited = unicode[depth];
            if (at[1] == '?' && at[2] != 'P' && at[2] != '<' && at[2] != '\'') {
                /* `(?flags)` changes the enclosing group, `(?flags:` opens one. */
                size_t i = 2; bool value = inherited, negative = false;
                for (; at[i] && at[i] != ')' && at[i] != ':'; ++i) {
                    if (at[i] == '-') negative = true;
                    else if (at[i] == 'u') value = !negative;
                }
                if (at[i] == ')') {
                    /* Copy the whole flag item: its `)` closes no group. */
                    unicode[depth] = value;
                    if (!yx_put_bytes(&out, at, i + 1)) goto no_memory;
                    at += i + 1;
                    continue;
                }
                inherited = value;
            }
            if (depth + 1 >= sizeof(unicode) / sizeof(unicode[0])) goto unchanged;
            unicode[++depth] = inherited;
        } else if (*at == ')') { if (depth) --depth; }
        if (!yx_put_u8(&out, *at++)) goto no_memory;
    }
    if (!changed) goto unchanged;
    if (!yx_put_u8(&out, 0)) goto no_memory;
    return (char *)out.data;
no_memory:
    *failed = true;
unchanged:
    free(out.data);
    return NULL;
}
static bool yx_ser_ident_byte(unsigned char c)
{ return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c >= 0x80; }
static bool yx_ser_has_non_ascii(const char *text)
{
    for (const unsigned char *at = (const unsigned char *)text; at && *at; ++at)
        if (*at >= 0x80) return true;
    return false;
}
/* The rule names with non-ASCII bytes (usually none), collected once, and the prefix of the new names. */
typedef struct yx_ser_variable_names {
    const char **rule_names;
    size_t rule_name_count;
    char prefix[24];
} yx_ser_variable_names;
/* NULL when the text stays as it is; *failed on allocation failure. */
static char *yx_ser_ascii_variables(const yx_ser_variable_names *names, const char *text, bool *failed)
{
    if (!text || !yx_ser_has_non_ascii(text)) return NULL;
    yx_writer out = {0}; bool changed = false;
    size_t prefix_length = strlen(names->prefix);
    for (const unsigned char *at = (const unsigned char *)text; *at;) {
        if (*at == '"') {
            const unsigned char *end = at + 1;
            while (*end && *end != '"') end += *end == '\\' && end[1] ? 2 : 1;
            if (*end) ++end;
            if (!yx_put_bytes(&out, at, (size_t)(end - at))) goto no_memory;
            at = end;
            continue;
        }
        /* Comments are not expected in a condition text; keep such a text as it is. */
        if (*at == '/' && (at[1] == '/' || at[1] == '*')) goto unchanged;
        if (*at == '$' || *at == '#' || *at == '@' || *at == '!' || *at == '.') {
            /* Pattern identifiers and field names keep their spelling. */
            const unsigned char *end = at + 1;
            while (yx_ser_ident_byte(*end)) ++end;
            if (!yx_put_bytes(&out, at, (size_t)(end - at))) goto no_memory;
            at = end;
            continue;
        }
        if (!yx_ser_ident_byte(*at)) {
            if (!yx_put_u8(&out, *at++)) goto no_memory;
            continue;
        }
        const unsigned char *end = at; bool plain = true;
        while (yx_ser_ident_byte(*end)) { plain &= *end < 0x80; ++end; }
        size_t length = (size_t)(end - at);
        bool rule_name = false;
        for (size_t i = 0; !plain && i < names->rule_name_count && !rule_name; ++i)
            rule_name = strlen(names->rule_names[i]) == length && !memcmp(names->rule_names[i], at, length);
        if (length == 7 && !memcmp(at, "matches", 7)) {
            /* Copy a following regexp literal untouched. */
            const unsigned char *next = end;
            while (*next == ' ' || *next == '\t' || *next == '\r' || *next == '\n') ++next;
            if (*next == '/') {
                ++next;
                while (*next && *next != '/') next += *next == '\\' && next[1] ? 2 : 1;
                if (*next) ++next;
                end = next;
                length = (size_t)(end - at);
            }
        }
        if (plain || rule_name) { if (!yx_put_bytes(&out, at, length)) goto no_memory; }
        else {
            if (!yx_put_bytes(&out, names->prefix, prefix_length)) goto no_memory;
            for (size_t i = 0; i < length; ++i) {
                char piece[4];
                snprintf(piece, sizeof(piece), "%02x", at[i]);
                if (!yx_put_bytes(&out, piece, 2)) goto no_memory;
            }
            changed = true;
        }
        at = end;
    }
    if (!changed) goto unchanged;
    if (!yx_put_u8(&out, 0)) goto no_memory;
    return (char *)out.data;
no_memory:
    *failed = true;
unchanged:
    free(out.data);
    return NULL;
}
static void yx_ser_spellings_free(const YRX_RULES *rules, YRX_RULES *copy)
{
    for (size_t i = 0; i < rules->rule_count; ++i) {
        if (copy->rules[i].condition_text != rules->rules[i].condition_text) free(copy->rules[i].condition_text);
        if (copy->rules[i].patterns == rules->rules[i].patterns) continue;
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            if (copy->rules[i].patterns[j].regexp != rules->rules[i].patterns[j].regexp)
                free(copy->rules[i].patterns[j].regexp);
            if (copy->rules[i].patterns[j].gap_head_regexp != rules->rules[i].patterns[j].gap_head_regexp)
                free(copy->rules[i].patterns[j].gap_head_regexp);
        }
        free(copy->rules[i].patterns);
    }
    free(copy->rules);
    copy->rules = NULL;
}
static bool yx_ser_spellings(const YRX_RULES *rules, YRX_RULES *copy, bool *failed)
{
    YRX_RULE *copies = NULL;
    yx_ser_variable_names names = {0};
    bool variables = false;
    *failed = false;
    for (size_t i = 0; rules && rules->rules && i < rules->rule_count && !variables; ++i)
        variables = yx_ser_has_non_ascii(rules->rules[i].condition_text);
    if (variables) {
        /* A prefix no condition and no rule name contains: a new name can meet no existing identifier. */
        names.rule_names = malloc(rules->rule_count * sizeof(*names.rule_names));
        if (!names.rule_names) goto failure;
        for (size_t i = 0; i < rules->rule_count; ++i)
            if (yx_ser_has_non_ascii(rules->rules[i].identifier))
                names.rule_names[names.rule_name_count++] = rules->rules[i].identifier;
        for (unsigned attempt = 0;; ++attempt) {
            bool used = false;
            snprintf(names.prefix, sizeof(names.prefix), "yxv%u_", attempt);
            for (size_t i = 0; i < rules->rule_count && !used; ++i)
                used = (rules->rules[i].condition_text && strstr(rules->rules[i].condition_text, names.prefix)) ||
                       (rules->rules[i].identifier && strstr(rules->rules[i].identifier, names.prefix));
            if (!used) break;
        }
    }
    for (size_t i = 0; rules && rules->rules && i < rules->rule_count; ++i) {
        char *condition = variables ? yx_ser_ascii_variables(&names, rules->rules[i].condition_text, failed) : NULL;
        if (*failed) goto failure;
        if (condition) {
            if (!copies) {
                copies = malloc(rules->rule_count * sizeof(*copies));
                if (!copies) { free(condition); goto failure; }
                memcpy(copies, rules->rules, rules->rule_count * sizeof(*copies));
            }
            copies[i].condition_text = condition;
        }
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            const YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            char *regexp = pattern->kind == YX_PATTERN_REGEX ? yx_ser_scalar_regexp(pattern->regexp, failed) : NULL;
            if (*failed) goto failure;
            if (!regexp) continue;
            if (!copies) {
                copies = malloc(rules->rule_count * sizeof(*copies));
                if (!copies) { free(regexp); goto failure; }
                memcpy(copies, rules->rules, rules->rule_count * sizeof(*copies));
            }
            if (copies[i].patterns == rules->rules[i].patterns) {
                YRX_PATTERN *patterns = malloc(rules->rules[i].pattern_count * sizeof(*patterns));
                if (!patterns) { free(regexp); goto failure; }
                memcpy(patterns, rules->rules[i].patterns, rules->rules[i].pattern_count * sizeof(*patterns));
                copies[i].patterns = patterns;
            }
            copies[i].patterns[j].regexp = regexp;
            if (pattern->gap_head_regexp) {
                char *head = yx_ser_scalar_regexp(pattern->gap_head_regexp, failed);
                if (*failed) goto failure;
                if (head) copies[i].patterns[j].gap_head_regexp = head;
            }
        }
    }
    free((void *)names.rule_names);
    if (!copies) return false;
    *copy = *rules;
    copy->rules = copies;
    return true;
failure:
    free((void *)names.rule_names);
    if (copies) {
        YRX_RULES partial = *rules;
        partial.rules = copies;
        yx_ser_spellings_free(rules, &partial);
    }
    *failed = true;
    return false;
}

/* Forward guards (yx_rx_guard) for PikeVM atoms. They change no atom, no
 * code and no verification order: YARA-X's atom choice and its verification
 * windows are part of the scan result, since a match longer than one window
 * is only found from an atom near its middle. A guard only skips atom
 * occurrences whose verification cannot add a match.
 *
 * The forward program from an atom is a graph of consuming instructions and
 * epsilon moves (splits, jumps, repeats, assertions). For a byte set `stop`
 * such that every consuming instruction reached before one that meets `stop`
 * lies outside it, each one that meets it lies inside it, and Match is not
 * reached first, every forward match reads a run of bytes of those earlier
 * instructions (`run`) and then one byte of `stop`. Without such a set, a
 * literal read from a single-byte instruction that every path to Match
 * passes must start where the run of the bytes read before it has not ended
 * (yx_sg_literal_bytes, yx_sg_literal_run). Repeat counts, thread priority
 * and assertions only remove paths, so ignoring them keeps the conditions
 * necessary. */
enum { YX_SG_NODES = 1024, YX_SG_CANDIDATES = 64, YX_SG_SUCCESSORS = 256, YX_SG_MIN_REJECTED = 64,
       YX_SG_STARTS = 16 };
typedef struct {
    size_t ip;
    uint8_t set[32];
    int kind; /* 0 consuming, 1 epsilon, 2 match */
    size_t first, count;
} yx_sg_node;
typedef struct {
    const uint8_t *code;
    size_t length;
    yx_sg_node *nodes;
    size_t node_count;
    size_t *edges; /* successor ips, then node indices */
    size_t edge_count, edge_capacity;
} yx_sg_graph;

static bool yx_sg_target(size_t ip, int32_t offset, size_t length, size_t *target)
{
    int64_t to = (int64_t)ip + offset;
    if (to < 0 || (uint64_t)to >= length) return false;
    *target = (size_t)to;
    return true;
}

static int32_t yx_sg_i32(const uint8_t *p)
{
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

/* One PikeVM instruction as regex_vm.c decodes it: its byte set or its
 * epsilon successors. -1 for an unknown or truncated instruction. */
static int yx_sg_decode(const uint8_t *code, size_t length, size_t ip, uint8_t set[32],
                        size_t *next, size_t *count)
{
    const uint8_t *c = code + ip;
    size_t n = length - ip;
    *count = 0;
    memset(set, 0, 32);
    if (ip >= length) return -1;
    if (c[0] != 0xaa || (n >= 2 && c[1] == 0xaa)) {
        set[c[0] >> 3] = (uint8_t)(1u << (c[0] & 7));
        next[(*count)++] = ip + (c[0] == 0xaa ? 2 : 1);
        return next[0] < length ? 0 : -1;
    }
    if (n < 2) return -1;
    switch (c[1]) {
    case 0x00: return 2;
    case 0x01: case 0x02:
        if (n < 8 || !yx_sg_target(ip, yx_sg_i32(c + 4), length, &next[1])) return -1;
        next[0] = ip + 8; *count = 2;
        return next[0] < length ? 1 : -1;
    case 0x03:
        if (n < 5 || n - 5 < (size_t)c[4] * 4 || c[4] > YX_SG_SUCCESSORS) return -1;
        for (size_t k = 0; k < c[4]; ++k)
            if (!yx_sg_target(ip, yx_sg_i32(c + 5 + 4 * k), length, &next[(*count)++])) return -1;
        return 1;
    case 0x04:
        if (n < 6 || !yx_sg_target(ip, yx_sg_i32(c + 2), length, &next[0])) return -1;
        *count = 1;
        return 1;
    case 0x05: memset(set, 255, 32); next[(*count)++] = ip + 2; break;
    case 0x06:
        if (n < 4) return -1;
        for (unsigned b = 0; b < 256; ++b) if ((b & c[3]) == c[2]) yx_tr_set(set, b);
        next[(*count)++] = ip + 4;
        break;
    case 0x07:
        if (n < 3) return -1;
        for (unsigned b = 0; b < 256; ++b) if ((b >= 'A' && b <= 'Z' ? b + 32 : b) == c[2]) yx_tr_set(set, b);
        next[(*count)++] = ip + 3;
        break;
    case 0x08:
        if (n < 34) return -1;
        memcpy(set, c + 2, 32);
        next[(*count)++] = ip + 34;
        break;
    case 0x09:
        if (n < 3 || n - 3 < (size_t)c[2] * 2) return -1;
        for (size_t k = 0; k < c[2]; ++k)
            for (unsigned b = c[3 + 2 * k]; b <= c[4 + 2 * k]; ++b) yx_tr_set(set, b);
        next[(*count)++] = ip + 3 + 2 * (size_t)c[2];
        break;
    case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f: case 0x12: case 0x13:
        next[(*count)++] = ip + 2;
        return next[0] < length ? 1 : -1;
    case 0x10: case 0x11:
        if (n < 14 || !yx_sg_target(ip, yx_sg_i32(c + 2), length, &next[1])) return -1;
        next[0] = ip + 14; *count = 2;
        return next[0] < length ? 1 : -1;
    default: return -1;
    }
    return next[0] < length ? 0 : -1;
}

/* The instructions reachable from start, with successor indices. */
static bool yx_sg_build(yx_sg_graph *g, size_t start)
{
    enum { SLOTS = 4 * YX_SG_NODES };
    size_t next[YX_SG_SUCCESSORS], *slots = malloc(SLOTS * sizeof(*slots));
    bool ok = false;
    g->nodes = calloc(YX_SG_NODES, sizeof(*g->nodes));
    if (!g->nodes || !slots) goto done;
    /* ip -> node index + 1, open addressing. */
    memset(slots, 0, SLOTS * sizeof(*slots));
    g->nodes[0].ip = start;
    g->node_count = 1;
    slots[(start * 2654435761u) & (SLOTS - 1)] = 1;
    for (size_t i = 0; i < g->node_count; ++i) {
        yx_sg_node *node = &g->nodes[i];
        size_t count;
        node->kind = yx_sg_decode(g->code, g->length, node->ip, node->set, next, &count);
        if (node->kind < 0) goto done;
        node->first = g->edge_count;
        node->count = count;
        if (g->edge_count + count > g->edge_capacity) {
            size_t capacity = (g->edge_count + count) * 2;
            size_t *edges = realloc(g->edges, capacity * sizeof(*edges));
            if (!edges) goto done;
            g->edges = edges;
            g->edge_capacity = capacity;
        }
        for (size_t k = 0; k < count; ++k) {
            size_t slot = (next[k] * 2654435761u) & (SLOTS - 1);
            while (slots[slot] && g->nodes[slots[slot] - 1].ip != next[k]) slot = (slot + 1) & (SLOTS - 1);
            if (!slots[slot]) {
                if (g->node_count == YX_SG_NODES) goto done;
                g->nodes[g->node_count].ip = next[k];
                slots[slot] = ++g->node_count;
            }
            g->edges[g->edge_count++] = slots[slot] - 1;
        }
    }
    ok = true;
done:
    free(slots);
    return ok;
}

static bool yx_sg_meets(const uint8_t a[32], const uint8_t b[32])
{
    for (size_t i = 0; i < 32; ++i) if (a[i] & b[i]) return true;
    return false;
}

static bool yx_sg_within(const uint8_t a[32], const uint8_t b[32])
{
    for (size_t i = 0; i < 32; ++i) if (a[i] & ~b[i]) return false;
    return true;
}

static unsigned yx_sg_popcount(const uint8_t set[32])
{
    unsigned count = 0;
    for (size_t i = 0; i < 32; i += 8) {
        uint64_t word;
        memcpy(&word, set + i, sizeof(word));
        word -= (word >> 1) & 0x5555555555555555ull;
        word = (word & 0x3333333333333333ull) + ((word >> 2) & 0x3333333333333333ull);
        word = (word + (word >> 4)) & 0x0f0f0f0f0f0f0f0full;
        count += (unsigned)((word * 0x0101010101010101ull) >> 56);
    }
    return count;
}

/* The run set for stop, or false when stop is no barrier. */
static bool yx_sg_barrier(const yx_sg_graph *g, const uint8_t stop[32], uint8_t run[32], size_t *stack,
                          uint8_t *seen)
{
    size_t used = 0;
    memset(run, 0, 32);
    memset(seen, 0, g->node_count);
    stack[used++] = 0;
    seen[0] = 1;
    while (used) {
        const yx_sg_node *node = &g->nodes[stack[--used]];
        if (node->kind == 2) return false;
        if (node->kind == 0) {
            if (yx_sg_meets(node->set, stop)) {
                if (!yx_sg_within(node->set, stop)) return false;
                continue;
            }
            for (size_t i = 0; i < 32; ++i) run[i] |= node->set[i];
        }
        for (size_t k = 0; k < node->count; ++k) {
            size_t to = g->edges[node->first + k];
            if (seen[to]) continue;
            seen[to] = 1;
            stack[used++] = to;
        }
    }
    return true;
}

/* Whether the guard tells anything about an occurrence of the atom: it
 * does unless the atom's own bytes already end the run with a stop byte or
 * hold the literal. */
static bool yx_sg_useful(const yx_rx_guard *guard, const yx_rx_atom *atom)
{
    if (guard->literal_length) {
        for (size_t i = 0; i + guard->literal_length <= atom->length; ++i)
            if (!memcmp(atom->bytes + i, guard->literal, guard->literal_length)) return false;
        return true;
    }
    for (size_t i = 0; i < atom->length; ++i) {
        unsigned b = atom->bytes[i];
        if (guard->run[b >> 3] >> (b & 7) & 1) continue;
        return !(guard->stop[b >> 3] >> (b & 7) & 1);
    }
    return true;
}

/* The single byte a consuming node reads, or -1. */
static int yx_sg_byte(const yx_sg_node *node)
{
    int byte = -1;
    if (node->kind != 0) return -1;
    for (unsigned i = 0; i < 32; ++i) {
        unsigned bits = node->set[i], b = 0;
        if (!bits) continue;
        if (byte >= 0 || (bits & (bits - 1))) return -1;
        while (!(bits >> b & 1)) ++b;
        byte = (int)(i * 8 + b);
    }
    return byte;
}

/* The literal form of the guard. Every match passes a consuming node that
 * dominates Match; from a single-byte one the code reads a fixed literal
 * (consuming nodes have one successor; single-successor epsilon nodes are
 * skipped). The run is every byte read before that node. */
static bool yx_sg_literal_bytes(const yx_sg_graph *g, size_t first, yx_rx_guard *trial)
{
    size_t at = first;
    memset(trial, 0, sizeof(*trial));
    while (trial->literal_length < sizeof(trial->literal)) {
        int byte = yx_sg_byte(&g->nodes[at]);
        if (byte < 0) break;
        trial->literal[trial->literal_length++] = (uint8_t)byte;
        at = g->edges[g->nodes[at].first];
        for (size_t hops = 0; hops < g->node_count && g->nodes[at].kind == 1 && g->nodes[at].count == 1; ++hops)
            at = g->edges[g->nodes[at].first];
    }
    return trial->literal_length >= 3;
}

/* The dominance half of the literal guard for yx_sg_literal_bytes's
 * literal: false when first does not dominate Match, else adds the run. */
static bool yx_sg_literal_run(const yx_sg_graph *g, size_t first, yx_rx_guard *trial, size_t *stack, uint8_t *seen)
{
    size_t used = 0;
    memset(seen, 0, g->node_count);
    stack[used++] = 0;
    seen[0] = 1;
    while (used) {
        size_t index = stack[--used];
        const yx_sg_node *node = &g->nodes[index];
        if (index == first) continue;
        if (node->kind == 2) return false; /* first does not dominate Match */
        if (node->kind == 0) for (size_t i = 0; i < 32; ++i) trial->run[i] |= node->set[i];
        for (size_t k = 0; k < node->count; ++k) {
            size_t to = g->edges[node->first + k];
            if (seen[to]) continue;
            seen[to] = 1;
            stack[used++] = to;
        }
    }
    return true;
}

/* The guard of the forward program at start for the given atoms: the
 * barrier useful to the most atoms, then the one that rejects the most byte
 * values (at least YX_SG_MIN_REJECTED). */
static bool yx_sg_guard(const uint8_t *code, size_t length, size_t start, const yx_rx_atom *const *atoms,
                        size_t atom_count, yx_rx_guard *guard)
{
    yx_sg_graph g = {code, length, NULL, 0, NULL, 0, 0};
    uint8_t (*candidates)[32] = NULL;
    size_t *stack = NULL, candidate_count = 0, best_useful = 0;
    uint8_t *seen = NULL;
    unsigned best = 0;
    if (!yx_sg_build(&g, start)) goto done;
    candidates = calloc(YX_SG_CANDIDATES, sizeof(*candidates));
    stack = malloc(g.node_count * sizeof(*stack));
    seen = malloc(g.node_count);
    if (!candidates || !stack || !seen) goto done;
    for (size_t i = 0; i < g.node_count; ++i) {
        const yx_sg_node *node = &g.nodes[i];
        size_t c = 0;
        if (node->kind != 0 || yx_sg_popcount(node->set) > 256 - YX_SG_MIN_REJECTED) continue;
        while (c < candidate_count && memcmp(candidates[c], node->set, 32)) ++c;
        if (c < candidate_count) continue;
        if (candidate_count == YX_SG_CANDIDATES) break;
        memcpy(candidates[candidate_count++], node->set, 32);
    }
    for (size_t c = 0; c < candidate_count; ++c) {
        yx_rx_guard trial;
        size_t useful = 0;
        memset(&trial, 0, sizeof(trial));
        if (!yx_sg_barrier(&g, candidates[c], trial.run, stack, seen)) continue;
        memcpy(trial.stop, candidates[c], 32);
        unsigned rejected = 256 - yx_sg_popcount(trial.run) - yx_sg_popcount(trial.stop);
        if (rejected < YX_SG_MIN_REJECTED) continue;
        for (size_t a = 0; a < atom_count; ++a) useful += yx_sg_useful(&trial, atoms[a]);
        if (!useful || useful < best_useful || (useful == best_useful && rejected <= best)) continue;
        best_useful = useful;
        best = rejected;
        *guard = trial;
    }
    /* Without a barrier, the longest literal useful to the most atoms. */
    for (size_t i = 0; !best && i < g.node_count; ++i) {
        yx_rx_guard trial;
        size_t useful = 0;
        if (yx_sg_byte(&g.nodes[i]) < 0 || !yx_sg_literal_bytes(&g, i, &trial)) continue;
        /* A literal's usefulness reads only the literal (yx_sg_useful), so
         * a candidate that cannot replace the guard skips the dominance
         * search (yx_sg_literal_run) as it would be rejected after it. */
        for (size_t a = 0; a < atom_count; ++a) useful += yx_sg_useful(&trial, atoms[a]);
        if (!useful || useful < best_useful ||
            (useful == best_useful && trial.literal_length <= guard->literal_length)) continue;
        if (!yx_sg_literal_run(&g, i, &trial, stack, seen)) continue;
        best_useful = useful;
        *guard = trial;
    }
done:
    free(g.nodes); free(g.edges); free(candidates); free(stack); free(seen);
    return best_useful != 0;
}

/* Guards for the inexact atoms of PikeVM sub-patterns that read the input
 * byte by byte (FastVM code and wide input are left alone). Atoms with the
 * same forward program share one guard, set on the atoms it is useful to.
 * Without memory there are none, which changes nothing but speed. */
static void yx_se_guards(yx_rx_program *out)
{
    size_t total = 0, used = 0, kept = 0;
    for (size_t s = 0; s < out->sub_count; ++s) total += out->subs[s].atom_count;
    if (!total) return;
    size_t starts[YX_SG_STARTS], *owner = malloc(total * sizeof(*owner));
    yx_rx_atom **atoms = malloc(total * sizeof(*atoms));
    const yx_rx_atom **group = malloc(total * sizeof(*group));
    yx_rx_guard *guards = calloc(YX_SG_STARTS, sizeof(*guards));
    if (!owner || !atoms || !group || !guards) goto done;
    /* Distinct forward offsets. */
    for (size_t s = 0, index = 0; s < out->sub_count; ++s)
        for (size_t a = 0; a < out->subs[s].atom_count; ++a, ++index) {
            yx_rx_atom *atom = &out->subs[s].atoms[a];
            size_t k = 0;
            atoms[index] = atom;
            owner[index] = SIZE_MAX;
            if ((out->subs[s].flags & (YX_RX_FAST | YX_RX_WIDE)) || atom->exact || !atom->has_fwd) continue;
            while (k < used && starts[k] != atom->fwd) ++k;
            if (k == used) {
                if (used == YX_SG_STARTS) continue;
                starts[used++] = atom->fwd;
            }
            owner[index] = k;
        }
    for (size_t k = 0; k < used; ++k) {
        size_t n = 0;
        for (size_t i = 0; i < total; ++i) if (owner[i] == k) group[n++] = atoms[i];
        if (!yx_sg_guard(out->code, out->code_length, starts[k], group, n, &guards[kept])) continue;
        for (size_t i = 0; i < total; ++i)
            if (owner[i] == k && yx_sg_useful(&guards[kept], atoms[i])) atoms[i]->guard = &guards[kept];
        ++kept;
    }
    if (kept) {
        out->guards = guards;
        out->guard_count = kept;
        guards = NULL;
    }
done:
    free(owner); free(atoms); free(group); free(guards);
}

/* Returns 1 with a program, 0 when the pattern is not a regexp
 * sub-pattern (or not handled), -1 on allocation failure. */
int yx_ser_regexp_program(const YRX_PATTERN *pattern, yx_rx_program *out)
{
    bool hex = pattern && pattern->kind == YX_PATTERN_HEX;
    yx_writer hex_text = {0}, leftover = {0};
    yx_tr_node *root = NULL;
    yx_fast_program *fast = NULL;
    yx_tr_program thompson = {0};
    yx_archive_regexp_atom *atoms = NULL;
    size_t atom_count = 0;
    unsigned flags = 0;
    int result = 0;
    memset(out, 0, sizeof(*out));
    if (!pattern || (!hex && (pattern->kind != YX_PATTERN_REGEX || !pattern->regexp)) ||
        (hex && !pattern->hex_atoms) ||
        (pattern->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE |
                                YX_MOD_FULLWORD | YX_MOD_PRIVATE))) return 0;
    bool dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0, ascii = (pattern->modifiers & YX_MOD_ASCII) != 0;
    const char *regexp = pattern->gap_head_regexp ? pattern->gap_head_regexp : pattern->regexp;
    if (hex) {
        if (!yx_tr_hex_regex(&hex_text, pattern->hex_atoms, pattern->hex_atom_count, 0) ||
            !yx_put_u8(&hex_text, 0)) { result = hex_text.data ? 0 : -1; goto done; }
        regexp = (const char *)hex_text.data;
    }
    yx_tr_parser parser = {.text = (const uint8_t *)regexp, .length = strlen(regexp),
                           .dotall = dotall, .nocase = nocase};
    root = yx_tr_expression(&parser);
    if (!root || parser.failed || parser.oom || parser.at != parser.length) {
        result = parser.oom ? -1 : 0; goto done;
    }
    if (yx_se_has_large_gap(root) || yx_se_alternation_literal(root) ||
        (!nocase && !wide && yx_se_masked_literal(root))) goto done;
    /* FastVM first, as yx_encode_fast_regex decides. */
    fast = calloc(1, sizeof(*fast));
    if (!fast) { result = -1; goto done; }
    fast->flags = 64;
    fast->nocase = nocase;
    bool parsed = hex ? yx_fast_hex_sequence(fast, pattern->hex_atoms, pattern->hex_atom_count)
                      : yx_ft_regex(fast, root, parser.saw_greedy && !parser.saw_lazy);
    /* The literal and masked-literal sub-pattern kinds were ruled out
     * above, so FastVM compiles whatever its splitter accepts. */
    fast->force_regexp = true;
    if (parsed && yx_fast_compile(fast)) {
        out->code = malloc(fast->code.used ? fast->code.used : 1);
        if (!out->code) { result = -1; goto done; }
        if (fast->code.used) memcpy(out->code, fast->code.data, fast->code.used);
        out->code_length = fast->code.used;
        atoms = fast->atoms;
        atom_count = fast->atom_count;
        flags = YX_RX_FAST | (fast->flags & 32u ? YX_RX_GREEDY : 0);
    } else {
        if (parsed && !fast->code.used) goto done; /* a literal or chain path */
        bool greedy = false;
        /* FastVM is incompatible, or it emitted its verifier and then
         * rejected atoms shorter than two bytes; those bytes stay in front
         * of the Thompson program. */
        if (parsed) { leftover = fast->code; fast->code = (yx_writer){0}; }
        if (!yx_tr_compile(regexp, dotall, nocase, &thompson, &greedy)) goto done;
        size_t total = leftover.used + thompson.forward.used + thompson.backward.used;
        out->code = malloc(total ? total : 1);
        atoms = calloc(thompson.atoms.count ? thompson.atoms.count : 1, sizeof(*atoms));
        if (!out->code || !atoms) { result = -1; goto done; }
        /* An empty writer has no buffer; memcpy needs one even for 0 bytes. */
        if (leftover.used) memcpy(out->code, leftover.data, leftover.used);
        if (thompson.forward.used)
            memcpy(out->code + leftover.used, thompson.forward.data, thompson.forward.used);
        if (thompson.backward.used)
            memcpy(out->code + leftover.used + thompson.forward.used, thompson.backward.data, thompson.backward.used);
        out->code_length = total;
        atom_count = thompson.atoms.count;
        for (size_t i = 0; i < atom_count; ++i) {
            const yx_tr_atom_entry *from = &thompson.atoms.items[i];
            memcpy(atoms[i].bytes, from->bytes, from->length);
            atoms[i].length = from->length;
            atoms[i].exact = from->exact;
            atoms[i].has_forward = atoms[i].has_backward = true;
            atoms[i].forward = leftover.used + from->forward;
            atoms[i].backward = leftover.used + thompson.forward.used + from->backward;
        }
        flags = (!hex && greedy) ? YX_RX_GREEDY : 0;
    }
    if (nocase) flags |= YX_RX_NOCASE;
    if (pattern->modifiers & YX_MOD_FULLWORD) flags |= YX_RX_FULLWORD_LEFT | YX_RX_FULLWORD_RIGHT;
    if (wide) {
        yx_rx_sub *sub = &out->subs[out->sub_count++];
        sub->flags = flags | YX_RX_WIDE;
        if (!yx_se_atoms(sub, atoms, atom_count, true)) { result = -1; goto done; }
    }
    if (!wide || ascii) {
        yx_rx_sub *sub = &out->subs[out->sub_count++];
        sub->flags = flags;
        if (!yx_se_atoms(sub, atoms, atom_count, false)) { result = -1; goto done; }
    }
    yx_se_guards(out);
    result = yx_rx_program_prepare(out) ? 1 : -1;
done:
    if (result != 1) yx_rx_program_free(out);
    if (atoms && (!fast || atoms != fast->atoms)) free(atoms);
    if (fast) yx_fast_program_destroy(fast);
    yx_tr_program_free(&thompson);
    yx_tr_destroy(root);
    free(hex_text.data);
    free(leftover.data);
    return result;
}

/* The program of an archive's own code and atoms. The sub-patterns, their
 * flags and atoms and the code are the archive's; the guards, the index and
 * the windows are derived from them as yx_ser_regexp_program derives them. */
int yx_ser_archived_regexp_program(const yx_archived_regexp *archived, yx_rx_program *out)
{
    const yx_archived_regexp_atom *from = (const yx_archived_regexp_atom *)(archived + 1);
    size_t total = 0;
    memset(out, 0, sizeof(*out));
    if (archived->sub_count > 2) return -1;
    for (size_t s = 0; s < archived->sub_count; ++s) total += archived->atom_count[s];
    out->code = malloc(archived->code_length ? archived->code_length : 1);
    if (!out->code) goto failed;
    if (archived->code_length) memcpy(out->code, from + total, archived->code_length);
    out->code_length = archived->code_length;
    for (size_t s = 0; s < archived->sub_count; ++s) {
        yx_rx_sub *sub = &out->subs[s];
        size_t count = archived->atom_count[s];
        sub->flags = archived->flags[s];
        sub->atoms = calloc(count ? count : 1, sizeof(*sub->atoms));
        if (!sub->atoms) goto failed;
        out->sub_count = s + 1;
        sub->atom_count = count;
        for (size_t i = 0; i < count; ++i, ++from) {
            yx_rx_atom *to = &sub->atoms[i];
            memcpy(to->bytes, from->bytes, sizeof(to->bytes));
            to->length = from->length;
            to->backtrack = from->backtrack;
            to->exact = from->exact;
            to->has_fwd = from->has_fwd;
            to->has_bck = from->has_bck;
            to->fwd = from->fwd;
            to->bck = from->bck;
        }
    }
    yx_se_guards(out);
    if (yx_rx_program_prepare(out)) return 1;
failed:
    yx_rx_program_free(out);
    return -1;
}

/* A copy of a program that yx_ser_regexp_program built, for a pattern with
 * the same inputs (kind, regexp, gap head, modifiers): the code, the
 * sub-patterns' atoms, the guards (each atom's guard rebased into the
 * copy) and the atom index, which yx_rx_program_prepare rebuilds from the
 * atoms. Returns 1, or -1 on allocation failure (out is then empty). */
int yx_ser_regexp_program_copy(const yx_rx_program *from, yx_rx_program *out)
{
    memset(out, 0, sizeof(*out));
    out->code = malloc(from->code_length ? from->code_length : 1);
    if (!out->code) goto failed;
    if (from->code_length) memcpy(out->code, from->code, from->code_length);
    out->code_length = from->code_length;
    if (from->guard_count) {
        out->guards = malloc(from->guard_count * sizeof(*out->guards));
        if (!out->guards) goto failed;
        memcpy(out->guards, from->guards, from->guard_count * sizeof(*out->guards));
        out->guard_count = from->guard_count;
    }
    for (size_t s = 0; s < from->sub_count && s < 2; ++s) {
        const yx_rx_sub *sub = &from->subs[s];
        yx_rx_sub *to = &out->subs[s];
        to->flags = sub->flags;
        to->atoms = malloc((sub->atom_count ? sub->atom_count : 1) * sizeof(*to->atoms));
        if (!to->atoms) goto failed;
        out->sub_count = s + 1;
        if (sub->atom_count) memcpy(to->atoms, sub->atoms, sub->atom_count * sizeof(*to->atoms));
        else memset(to->atoms, 0, sizeof(*to->atoms));
        to->atom_count = sub->atom_count;
        for (size_t a = 0; a < sub->atom_count; ++a)
            if (sub->atoms[a].guard)
                to->atoms[a].guard = out->guards + (sub->atoms[a].guard - from->guards);
    }
    if (yx_rx_program_prepare(out)) return 1;
failed:
    yx_rx_program_free(out);
    return -1;
}

/* The branches of a regexp or hex pattern that yx_ser_regexp_program leaves
 * without a program because it is one literal or a whole-expression
 * alternation of literals (YARA-X compiles those as literal sub-patterns,
 * e.g. /ab|cd/ or { ( 61 62 | 63 64 ) }). Branch k is
 * (*bytes)[(*offsets)[k] .. (*offsets)[k+1]). Returns the branch count, 0
 * when the regexp has another shape or an empty branch, -1 on allocation
 * failure. Every match of such a regexp is an occurrence of one branch. */
int yx_ser_literal_branches(const YRX_PATTERN *pattern, uint8_t **bytes, size_t **offsets)
{
    yx_writer hex_text = {0};
    *bytes = NULL;
    *offsets = NULL;
    if (!pattern) return 0;
    const char *regexp = pattern->regexp;
    if (pattern->kind == YX_PATTERN_HEX) {
        /* The hex form yx_ser_regexp_program parses for the same decision. */
        if (!pattern->hex_atoms) return 0;
        if (!yx_tr_hex_regex(&hex_text, pattern->hex_atoms, pattern->hex_atom_count, 0) ||
            !yx_put_u8(&hex_text, 0)) {
            int failed = hex_text.data ? 0 : -1;
            free(hex_text.data);
            return failed;
        }
        regexp = (const char *)hex_text.data;
    } else if (pattern->kind != YX_PATTERN_REGEX || !regexp || pattern->gap_head_regexp)
        return 0;
    yx_tr_parser parser = {.text = (const uint8_t *)regexp,
                           .length = strlen(regexp),
                           .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                           .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&parser);
    int result = 0;
    if (!root || parser.failed || parser.oom || parser.at != parser.length) {
        result = parser.oom ? -1 : 0;
        goto done;
    }
    if (!yx_se_alternation_literal(root)) goto done;
    const yx_tr_node *node = root;
    if (node->kind == YX_TR_CAPTURE && node->count) node = node->children[0];
    size_t count = node->kind == YX_TR_LITERAL ? 1 : node->count, total = 0;
    for (size_t i = 0; i < count; ++i) {
        const yx_tr_node *branch = node->kind == YX_TR_LITERAL ? node : node->children[i];
        if (!branch->length || branch->length > SIZE_MAX - total) goto done;
        total += branch->length;
    }
    if (!count || count >= INT_MAX) goto done;
    *bytes = malloc(total);
    *offsets = malloc((count + 1) * sizeof(**offsets));
    if (!*bytes || !*offsets) {
        free(*bytes); free(*offsets);
        *bytes = NULL; *offsets = NULL;
        result = -1;
        goto done;
    }
    (*offsets)[0] = 0;
    for (size_t i = 0; i < count; ++i) {
        const yx_tr_node *branch = node->kind == YX_TR_LITERAL ? node : node->children[i];
        memcpy(*bytes + (*offsets)[i], branch->bytes, branch->length);
        (*offsets)[i + 1] = (*offsets)[i] + branch->length;
    }
    result = (int)count;
done:
    yx_tr_destroy(root);
    free(hex_text.data);
    return result;
}

/* One Literal sub-pattern of c_alternation_literal: the literal as it is
 * searched (wide: every byte followed by a zero), and its best atom
 * (best_atom_in_bytes: exact when it is the whole literal) or, with nocase,
 * that atom's case combinations. */
static bool yx_se_literal_item(yx_rx_literal *item, const uint8_t *bytes, size_t length, bool wide,
                               unsigned flags)
{
    size_t encoded = length * (wide ? 2 : 1), offset = 0, width = 0, letters = 0, count;
    uint8_t *masks = malloc(encoded ? encoded : 1), atom[8];
    memset(item, 0, sizeof(*item));
    item->bytes = malloc(encoded ? encoded : 1);
    if (!item->bytes || !masks) { free(masks); return false; }
    for (size_t i = 0; i < length; ++i) {
        if (wide) { item->bytes[2 * i] = bytes[i]; item->bytes[2 * i + 1] = 0; }
        else item->bytes[i] = bytes[i];
    }
    item->length = encoded;
    item->sub.flags = flags | (wide ? YX_RX_WIDE : 0);
    memset(masks, 255, encoded);
    yx_fast_literal literal = {item->bytes, masks, encoded, false};
    yx_fast_best_atom(&literal, &offset, &width);
    free(masks);
    if (!width || width > sizeof(atom)) return false;
    memcpy(atom, item->bytes + offset, width);
    if (flags & YX_RX_NOCASE)
        for (size_t i = 0; i < width; ++i) {
            if (atom[i] >= 'A' && atom[i] <= 'Z') atom[i] = (uint8_t)(atom[i] + 32);
            if (atom[i] >= 'a' && atom[i] <= 'z') ++letters;
        }
    count = (size_t)1 << letters;
    item->sub.atoms = calloc(count, sizeof(*item->sub.atoms));
    if (!item->sub.atoms) return false;
    item->sub.atom_count = count;
    /* CaseCombinations: lowercase before uppercase, the last byte varying
     * fastest. */
    for (size_t bits = 0; bits < count; ++bits) {
        yx_rx_atom *to = &item->sub.atoms[bits];
        size_t letter = letters;
        for (size_t i = width; i-- > 0;) {
            to->bytes[i] = atom[i];
            if ((flags & YX_RX_NOCASE) && atom[i] >= 'a' && atom[i] <= 'z') {
                --letter;
                if ((bits >> (letters - 1 - letter)) & 1u) to->bytes[i] = (uint8_t)(atom[i] - 32);
            }
        }
        to->length = (uint8_t)width;
        to->backtrack = offset;
        to->exact = width == encoded;
    }
    return true;
}

yx_rx_literals *yx_ser_literal_set(const YRX_PATTERN *pattern)
{
    uint8_t *bytes = NULL;
    size_t *offsets = NULL;
    yx_rx_literals *set = NULL;
    if (!pattern || (pattern->kind != YX_PATTERN_REGEX && pattern->kind != YX_PATTERN_HEX) ||
        (pattern->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE |
                                YX_MOD_FULLWORD | YX_MOD_PRIVATE))) return NULL;
    int count = yx_ser_literal_branches(pattern, &bytes, &offsets);
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    bool raw = !wide || (pattern->modifiers & YX_MOD_ASCII) != 0;
    unsigned flags = ((pattern->modifiers & YX_MOD_NOCASE) ? YX_RX_NOCASE : 0) |
                     ((pattern->modifiers & YX_MOD_FULLWORD) ? YX_RX_FULLWORD_LEFT | YX_RX_FULLWORD_RIGHT : 0);
    bool ok = count >= 2;
    if (ok) {
        set = calloc(1, sizeof(*set));
        if (set) set->items = calloc((size_t)count * 2, sizeof(*set->items));
        ok = set && set->items;
    }
    /* Per branch the raw literal, then the wide one. */
    for (int branch = 0; ok && branch < count; ++branch) {
        const uint8_t *literal = bytes + offsets[branch];
        size_t length = offsets[branch + 1] - offsets[branch];
        for (unsigned encoding = 0; ok && encoding < 2; ++encoding) {
            if (encoding ? !wide : !raw) continue;
            ok = yx_se_literal_item(&set->items[set->count], literal, length, encoding != 0, flags);
            /* A failed item still owns what it allocated. */
            ++set->count;
        }
    }
    free(bytes);
    free(offsets);
    if (!ok) { yx_rx_literals_free(set); set = NULL; }
    return set;
}

/* The reference's automaton atoms for one pattern, in insertion order:
 * regexp sub-patterns from their program, and plain, nocase, wide or ascii
 * literals as c_literal_pattern builds them. Other kinds are not modeled. */
static bool yx_se_push_atom(yx_rx_atom **atoms, size_t *count, size_t *capacity, const uint8_t *bytes,
                            size_t length)
{
    if (length > 8) return false;
    if (*count == *capacity) {
        size_t next = *capacity ? *capacity * 2 : 16;
        yx_rx_atom *grown = realloc(*atoms, next * sizeof(*grown));
        if (!grown) return false;
        *atoms = grown;
        *capacity = next;
    }
    memset(&(*atoms)[*count], 0, sizeof(**atoms));
    memcpy((*atoms)[*count].bytes, bytes, length);
    (*atoms)[*count].length = (uint8_t)length;
    ++*count;
    return true;
}

/* Chains of sub-patterns (serialization_hir_chain.h). */
static int yx_hc_reference_atoms(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count);
static int yx_hc_chain_status(const YRX_PATTERN *pattern);
static bool yx_hc_is_chain(const YRX_PATTERN *pattern);

int yx_ser_pattern_reference_atoms_status(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count)
{
    size_t capacity = 0;
    *atoms = NULL;
    *count = 0;
    if (!pattern) return 0;
    if (pattern->rx_program) {
        const yx_rx_program *program = pattern->rx_program;
        for (size_t s = 0; s < program->sub_count; ++s)
            for (size_t a = 0; a < program->subs[s].atom_count; ++a)
                if (!yx_se_push_atom(atoms, count, &capacity, program->subs[s].atoms[a].bytes,
                                     program->subs[s].atoms[a].length)) goto fail;
        return 1;
    }
    if (pattern->rx_literals) {
        const yx_rx_literals *set = pattern->rx_literals;
        for (size_t s = 0; s < set->count; ++s)
            for (size_t a = 0; a < set->items[s].sub.atom_count; ++a)
                if (!yx_se_push_atom(atoms, count, &capacity, set->items[s].sub.atoms[a].bytes,
                                     set->items[s].sub.atoms[a].length)) goto fail;
        return 1;
    }
    if (pattern->kind == YX_PATTERN_REGEX) {
        int chain = yx_hc_chain_status(pattern);
        if (chain < 0) return chain;
        if (!chain) {
            /* A regexp that is one literal, also in a capture group
             * (c_alternation_literal), has the atoms of that text literal. */
            YRX_PATTERN text;
            uint8_t *bytes = NULL;
            size_t length = 0;
            int literal = yx_tv_regexp_literal(pattern, true, &bytes, &length);
            if (literal != 1) return literal;
            memset(&text, 0, sizeof(text));
            text.kind = YX_PATTERN_TEXT; text.bytes = bytes; text.length = length;
            text.modifiers = pattern->modifiers & ~(unsigned)YX_MOD_DOTALL;
            literal = yx_ser_pattern_reference_atoms_status(&text, atoms, count);
            free(bytes);
            return literal;
        }
    }
    if (pattern->kind == YX_PATTERN_HEX && !pattern->hex_has_jump && pattern->bytes && pattern->mask &&
        pattern->length && !(pattern->modifiers & ~(unsigned)YX_MOD_PRIVATE)) {
        bool literal = true;
        for (size_t i = 0; literal && i < pattern->length; ++i) literal = pattern->mask[i] == 0xff;
        if (literal) {
            YRX_PATTERN text;
            memset(&text, 0, sizeof(text));
            text.kind = YX_PATTERN_TEXT; text.bytes = pattern->bytes; text.length = pattern->length;
            return yx_ser_pattern_reference_atoms_status(&text, atoms, count);
        }
    }
    if (pattern->kind == YX_PATTERN_HEX || pattern->kind == YX_PATTERN_REGEX)
        return yx_hc_reference_atoms(pattern, atoms, count);
    if (pattern->kind != YX_PATTERN_TEXT || !pattern->length ||
        (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD | YX_MOD_PRIVATE)))
        return 0;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0, ascii = (pattern->modifiers & YX_MOD_ASCII) != 0;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    for (unsigned variant = 0; variant < 2; ++variant) {
        bool as_wide = variant == 0;
        if (as_wide ? !wide : (wide && !ascii)) continue;
        size_t length = pattern->length * (as_wide ? 2 : 1);
        uint8_t *bytes = malloc(length), *masks = malloc(length);
        if (!bytes || !masks) { free(bytes); free(masks); goto fail; }
        for (size_t i = 0; i < pattern->length; ++i) {
            if (as_wide) { bytes[2 * i] = pattern->bytes[i]; bytes[2 * i + 1] = 0; }
            else bytes[i] = pattern->bytes[i];
        }
        memset(masks, 255, length);
        yx_fast_literal literal = {bytes, masks, length, false};
        size_t offset = 0, width = 0;
        yx_fast_best_atom(&literal, &offset, &width);
        uint8_t atom[8];
        memcpy(atom, bytes + offset, width);
        free(bytes); free(masks);
        if (!nocase) {
            if (!yx_se_push_atom(atoms, count, &capacity, atom, width)) goto fail;
            continue;
        }
        /* CaseCombinations: a cartesian product over the lowercased atom,
         * lowercase before uppercase, the last byte varying fastest. */
        size_t letters = 0;
        for (size_t i = 0; i < width; ++i) {
            if (atom[i] >= 'A' && atom[i] <= 'Z') atom[i] = (uint8_t)(atom[i] + 32);
            if (atom[i] >= 'a' && atom[i] <= 'z') ++letters;
        }
        for (size_t bits = 0; bits < ((size_t)1 << letters); ++bits) {
            uint8_t combination[8];
            size_t letter = letters;
            for (size_t i = width; i-- > 0;) {
                combination[i] = atom[i];
                if (atom[i] >= 'a' && atom[i] <= 'z') {
                    --letter;
                    if ((bits >> (letters - 1 - letter)) & 1u) combination[i] = (uint8_t)(atom[i] - 32);
                }
            }
            if (!yx_se_push_atom(atoms, count, &capacity, combination, width)) goto fail;
        }
    }
    return 1;
fail:
    free(*atoms);
    *atoms = NULL;
    *count = 0;
    return -1;
}

bool yx_ser_pattern_reference_atoms(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count)
{
    return yx_ser_pattern_reference_atoms_status(pattern, atoms, count) == 1;
}

/* Boolean conditions need no captures, atom selection, reverse program or
 * repetition counters. A count held outside the NFA instruction pointer would
 * merge distinct paths in an unanchored search, so finite bounds are unrolled.
 * The search VM tracks split instruction addresses, not serialized split IDs;
 * these private programs can therefore exceed the scanner's 8192-ID limit. */
#define YX_CS_PROGRAM_LIMIT ((size_t)50 * 1024 * 1024)
static int yx_cs_append(yx_writer *out, const void *data, size_t length)
{
    if (out->used > YX_CS_PROGRAM_LIMIT || length > YX_CS_PROGRAM_LIMIT - out->used)
        return 0;
    return yx_put_bytes(out, data, length) ? 1 : -1;
}
static int yx_cs_emit(const yx_tr_node *node, yx_writer *out, size_t depth)
{
    /* The source AST is limited to 250 before lowering. A generated scalar
     * byte AST has its own 250 limit, so allow both beneath the same root. */
    if (!node || depth > 512 || out->used > YX_CS_PROGRAM_LIMIT - 16) return 0;
    if (node->kind == YX_TR_EMPTY) return 1;
    if (node->kind == YX_TR_LITERAL) {
        for (size_t i = 0; i < node->length; ++i) {
            int status = yx_cs_append(out, node->bytes + i, 1);
            if (status != 1) return status;
            if (node->bytes[i] == 0xaa && (status = yx_cs_append(out, node->bytes + i, 1)) != 1)
                return status;
        }
        return 1;
    }
    if (node->kind == YX_TR_CLASS)
        return yx_tr_class_code(out, node->bitmap, false) ? 1 : -1;
    if (node->kind == YX_TR_LOOK)
        return yx_tr_instr(out, node->look, 0, 0) ? 1 : -1;
    if (node->kind == YX_TR_CONCAT || node->kind == YX_TR_CAPTURE) {
        for (size_t i = 0; i < node->count; ++i) {
            int status = yx_cs_emit(node->children[i], out, depth + 1);
            if (status != 1) return status;
        }
        return 1;
    }
    if (node->kind == YX_TR_ALT) {
        size_t *jumps = node->count > 1 ? calloc(node->count - 1, sizeof(*jumps)) : NULL;
        if (node->count > 1 && !jumps) return -1;
        int status = 1;
        for (size_t i = 0; i < node->count; ++i) {
            size_t branch = out->used;
            if (i + 1 < node->count && !yx_tr_instr(out, 1, 0, 0)) { status = -1; break; }
            status = yx_cs_emit(node->children[i], out, depth + 1);
            if (status != 1) break;
            if (i + 1 < node->count) {
                jumps[i] = out->used;
                if (!yx_tr_instr(out, 4, 0, 0) || !yx_tr_patch(out, branch, 4, out->used)) {
                    status = -1; break;
                }
            }
        }
        if (status == 1)
            for (size_t i = 0; i + 1 < node->count; ++i)
                if (!yx_tr_patch(out, jumps[i], 2, out->used)) { status = 0; break; }
        free(jumps);
        return status;
    }
    if (node->kind == YX_TR_REPEAT && node->count == 1) {
        yx_writer child = {0};
        int status = yx_cs_emit(node->children[0], &child, depth + 1);
        if (status != 1 || !child.used) { free(child.data); return status; }
        size_t remaining = YX_CS_PROGRAM_LIMIT - out->used;
        uint64_t required = (uint64_t)node->minimum * child.used;
        uint64_t tail = yx_tr_unbounded(node) ? 14u + child.used :
            (uint64_t)(node->maximum - node->minimum) * (8u + child.used);
        if (required > remaining || tail > remaining - required) {
            free(child.data); return 0;
        }
        for (uint32_t i = 0; i < node->minimum; ++i) {
            status = yx_cs_append(out, child.data, child.used);
            if (status != 1) goto repeat_done;
        }
        if (yx_tr_unbounded(node)) {
            size_t branch = out->used;
            if (!yx_tr_instr(out, 2, 0, 0)) { status = -1; goto repeat_done; }
            status = yx_cs_append(out, child.data, child.used);
            if (status != 1) goto repeat_done;
            size_t jump = out->used;
            if (!yx_tr_instr(out, 4, 0, 0) || !yx_tr_patch(out, jump, 2, branch) ||
                !yx_tr_patch(out, branch, 4, out->used)) status = -1;
        } else {
            size_t end = out->used + (size_t)tail;
            for (uint32_t i = node->minimum; i < node->maximum; ++i) {
                size_t branch = out->used;
                if (!yx_tr_instr(out, 2, 0, 0) || !yx_tr_patch(out, branch, 4, end)) {
                    status = -1; break;
                }
                status = yx_cs_append(out, child.data, child.used);
                if (status != 1) break;
            }
        }
repeat_done:
        free(child.data);
        return status;
    }
    return 0;
}

int yx_ser_search_program(const char *regexp, size_t length, bool dotall,
                           bool nocase, uint8_t **code, size_t *code_length)
{
    yx_tr_parser parser = {.text = (const uint8_t *)regexp, .length = length,
                           .dotall = dotall, .nocase = nocase, .condition_only = true};
    yx_tr_node *root = NULL;
    yx_writer program = {0};
    int status = 0;
    *code = NULL; *code_length = 0;
    if (!regexp || strlen(regexp) != length) return 0;
    root = yx_tr_expression(&parser);
    if (parser.oom) { status = -1; goto done; }
    if (!root || parser.failed || parser.at != parser.length) goto done;
    /* An explicit lazy any-byte prefix implements unanchored search, including
     * invalid UTF-8 bytes around Unicode-scoped atoms and empty end matches. */
    if (!yx_tr_instr(&program, 2, 0, 0) || !yx_tr_instr(&program, 5, 0, 0) ||
        !yx_tr_instr(&program, 4, 0, 0) || !yx_tr_patch(&program, 10, 2, 0) ||
        !yx_tr_patch(&program, 0, 4, program.used)) { status = -1; goto done; }
    status = yx_cs_emit(root, &program, 0);
    if (status == 1 && !yx_tr_instr(&program, 0, 0, 0)) status = -1;
    if (status == 1) {
        *code = program.data; *code_length = program.used; program.data = NULL;
    }
done:
    yx_tr_destroy(root);
    free(parser.capture_names);
    free(program.data);
    return status;
}

#undef YX_CS_PROGRAM_LIMIT

/* The slow_pattern model of Compiler::c_rule and Compiler::c_regexp in
 * YARA-X 1.23.0 (lib/src/compiler/mod.rs, lib/src/re/hir.rs). It walks
 * the regexp HIR as the compiler does; it is never used to build scanner
 * code. */

/* is_slow_pattern_bytes: a single byte, or only 0x00, 0x90 or 0xff bytes. */
static bool yx_ss_slow_bytes(const uint8_t *bytes, size_t length)
{
    if (length == 1) return true;
    if (!length || (bytes[0] != 0x00 && bytes[0] != 0x90 && bytes[0] != 0xff)) return false;
    for (size_t i = 1; i < length; ++i) if (bytes[i] != bytes[0]) return false;
    return true;
}

/* The bytes and mask of Hir::try_extract_literal_with_mask: literals, byte
 * classes that are one masked byte, and fixed any-byte gaps of at most 200
 * bytes, through concatenations and capture groups. */
static bool yx_ss_masked_bytes(const yx_tr_node *node, yx_writer *bytes, yx_writer *mask,
                               size_t depth)
{
    unsigned first = 256, last = 0, count = 0, bits = 0;
    if (depth > 250) return false;
    switch (node->kind) {
    case YX_TR_LITERAL:
        for (size_t i = 0; i < node->length; ++i)
            if (!yx_put_u8(bytes, node->bytes[i]) || !yx_put_u8(mask, 0xff)) return false;
        return true;
    case YX_TR_REPEAT:
        if (!node->count || yx_tr_unbounded(node) || node->minimum != node->maximum ||
            node->minimum > 200 || !yx_se_any_byte(node->children[0])) return false;
        for (uint32_t i = 0; i < node->minimum; ++i)
            if (!yx_put_u8(bytes, 0) || !yx_put_u8(mask, 0)) return false;
        return true;
    case YX_TR_CONCAT: case YX_TR_CAPTURE:
        for (size_t i = 0; i < node->count; ++i)
            if (!yx_ss_masked_bytes(node->children[i], bytes, mask, depth + 1)) return false;
        return true;
    case YX_TR_CLASS:
        /* class_to_masked_byte accepts byte classes only. */
        if (node->unicode_class) return false;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(node->bitmap, b)) { if (first == 256) first = b; last = b; ++count; }
        if (!count) return false;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(node->bitmap, b) && (b & first) != first) return false;
        for (unsigned k = 0; k < 8; ++k) bits += ((first ^ last) >> k) & 1u;
        if ((1u << bits) != count) return false;
        return yx_put_u8(bytes, (uint8_t)first) && yx_put_u8(mask, (uint8_t)~(first ^ last));
    default:
        return false;
    }
}

/* Hir::try_extract_literal_with_mask succeeds when the pattern is a masked
 * literal whose best masked atom keeps a byte after MaskedAtom::trim cuts
 * it down to MAX_ATOMS_PER_REGEXP (16,384) mask combinations. */
static int yx_ss_masked_literal(const yx_tr_node *node)
{
    yx_writer bytes = {0}, mask = {0};
    int result = 0;
    if (yx_ss_masked_bytes(node, &bytes, &mask, 0) && bytes.used) {
        /* best_range_in_masked_bytes searches the first 32,768 bytes. */
        size_t length = bytes.used < 32768 ? bytes.used : 32768, offset = 0, width = 0;
        yx_fast_literal literal = {bytes.data, mask.data, length, true};
        yx_fast_best_atom(&literal, &offset, &width);
        for (;;) {
            uint64_t combinations = 1;
            for (size_t i = 0; i < width; ++i) {
                unsigned zeros = 0;
                for (unsigned k = 0; k < 8; ++k) zeros += !((mask.data[offset + i] >> k) & 1u);
                combinations <<= zeros;
                if (combinations > 16384) break;
            }
            if (combinations <= 16384 || !width) break;
            --width;
            while (width && mask.data[offset + width - 1] == 0x00) --width;
        }
        result = width != 0;
    }
    free(bytes.data);
    free(mask.data);
    return result;
}

/* The atoms of a LiteralWithMask sub-pattern (a regexp or hex pattern
 * without nocase or wide that try_extract_literal_with_mask accepts): the
 * mask combinations of its best masked atom. 1 with the atoms, 0 for
 * another pattern, -1 without memory. */
static int yx_ss_masked_atoms(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count, size_t *capacity)
{
    yx_writer hex_text = {0}, bytes = {0}, mask = {0};
    yx_tr_node *root = NULL;
    int result = 0;
    const char *regexp = pattern->regexp;
    if (pattern->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_FULLWORD | YX_MOD_PRIVATE)) return 0;
    if (pattern->kind == YX_PATTERN_HEX) {
        if (!pattern->hex_atoms) return 0;
        if (!yx_tr_hex_regex(&hex_text, pattern->hex_atoms, pattern->hex_atom_count, 0) ||
            !yx_put_u8(&hex_text, 0)) { result = hex_text.data ? 0 : -1; goto done; }
        regexp = (const char *)hex_text.data;
    } else if (pattern->kind != YX_PATTERN_REGEX || !regexp || pattern->gap_head_regexp) return 0;
    yx_tr_parser parser = {.text = (const uint8_t *)regexp, .length = strlen(regexp),
                           .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0};
    root = yx_tr_expression(&parser);
    if (!root || parser.failed || parser.oom || parser.at != parser.length) {
        result = parser.oom ? -1 : 0; goto done;
    }
    if (yx_se_has_large_gap(root) || yx_se_alternation_literal(root) || !yx_se_masked_literal(root)) goto done;
    if (!yx_ss_masked_bytes(root, &bytes, &mask, 0) || !bytes.used) goto done;
    {
        /* best_range_in_masked_bytes searches the first 32,768 bytes;
         * MaskedAtom::trim cuts the atom down to 16,384 combinations. */
        size_t length = bytes.used < 32768 ? bytes.used : 32768, offset = 0, width = 0;
        uint64_t combinations = 1;
        yx_fast_literal literal = {bytes.data, mask.data, length, true};
        yx_fast_best_atom(&literal, &offset, &width);
        for (;;) {
            combinations = 1;
            for (size_t i = 0; i < width; ++i) {
                unsigned zeros = 0;
                for (unsigned k = 0; k < 8; ++k) zeros += !((mask.data[offset + i] >> k) & 1u);
                combinations <<= zeros;
                if (combinations > 16384) break;
            }
            if (combinations <= 16384 || !width) break;
            --width;
            while (width && mask.data[offset + width - 1] == 0x00) --width;
        }
        if (!width || width > 8) goto done;
        for (uint64_t n = 0; n < combinations; ++n) {
            uint8_t atom[8];
            uint64_t rest = n;
            for (size_t i = width; i-- > 0;) {
                uint8_t fixed = mask.data[offset + i], value = (uint8_t)(bytes.data[offset + i] & fixed);
                for (unsigned k = 0; k < 8; ++k)
                    if (!((fixed >> k) & 1u)) { value |= (uint8_t)((rest & 1u) << k); rest >>= 1; }
                atom[i] = value;
            }
            if (!yx_se_push_atom(atoms, count, capacity, atom, width)) { result = -1; goto done; }
        }
        result = 1;
    }
done:
    yx_tr_destroy(root);
    free(hex_text.data); free(bytes.data); free(mask.data);
    return result;
}

/* The atoms of a text literal with xor or base64 modifiers, as
 * c_literal_pattern adds them: for the wide form, then the plain one, the
 * best atom under every xor key, or the best atoms of the three base64
 * forms (base64_patterns), plain and then wide. */
static int yx_ss_encoded_text_atoms(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count,
                                    size_t *capacity)
{
    static const char standard[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0, ascii = (pattern->modifiers & YX_MOD_ASCII) != 0;
    bool xored = (pattern->modifiers & YX_MOD_XOR) != 0;
    unsigned base64 = pattern->modifiers & (YX_MOD_BASE64 | YX_MOD_BASE64WIDE);
    if (!pattern->bytes || !pattern->length || xored == (base64 != 0) ||
        (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_FULLWORD | YX_MOD_PRIVATE | YX_MOD_XOR |
                                YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) ||
        (base64 && pattern->length < 2) || pattern->length > (SIZE_MAX - 16) / 8) return 0;
    size_t room = pattern->length * 2 + 2, encoded_room = (room / 3 + 1) * 4 * 2;
    size_t mask_room = encoded_room > room ? encoded_room : room;
    uint8_t *plain = malloc(room), *encoded = malloc(encoded_room), *masks = malloc(mask_room);
    int result = 1;
    if (!plain || !encoded || !masks) { result = -1; goto done; }
    memset(masks, 255, mask_room);
    for (unsigned variant = 0; result == 1 && variant < 2; ++variant) {
        bool as_wide = variant == 0;
        if (as_wide ? !wide : (wide && !ascii)) continue;
        size_t length = pattern->length * (as_wide ? 2 : 1), offset = 0, width = 0;
        /* Two bytes in front for the base64 forms of "XX" + s and "X" + s. */
        plain[0] = plain[1] = 'X';
        for (size_t i = 0; i < pattern->length; ++i) {
            if (as_wide) { plain[2 + 2 * i] = pattern->bytes[i]; plain[2 + 2 * i + 1] = 0; }
            else plain[2 + i] = pattern->bytes[i];
        }
        if (xored) {
            yx_fast_literal literal = {plain + 2, masks, length, false};
            yx_fast_best_atom(&literal, &offset, &width);
            for (unsigned key = pattern->xor_min; result == 1 && key <= pattern->xor_max; ++key) {
                uint8_t atom[8];
                for (size_t i = 0; i < width; ++i) atom[i] = (uint8_t)(plain[2 + offset + i] ^ key);
                if (!yx_se_push_atom(atoms, count, capacity, atom, width)) result = -1;
            }
            continue;
        }
        for (unsigned kind = 0; result == 1 && kind < 2; ++kind) {
            const char *alphabet = kind ? pattern->base64wide_alphabet : pattern->base64_alphabet;
            if (!(base64 & (kind ? YX_MOD_BASE64WIDE : YX_MOD_BASE64))) continue;
            if (!alphabet) alphabet = standard;
            if (strlen(alphabet) != 64) { result = 0; break; }
            for (size_t skip = 0; result == 1 && skip < 3; ++skip) {
                const uint8_t *in = plain + skip;
                size_t n = length + 2 - skip, used = 0;
                for (size_t i = 0; i < n; i += 3) {
                    uint32_t group = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) |
                                     (i + 2 < n ? in[i + 2] : 0);
                    size_t symbols = n - i >= 3 ? 4 : n - i + 1;
                    for (size_t k = 0; k < symbols; ++k)
                        encoded[used++] = (uint8_t)alphabet[(group >> (18 - 6 * k)) & 63u];
                }
                size_t begin = skip == 0 ? 3 : skip == 1 ? 2 : 0, end = used - (n % 3 ? 1 : 0);
                if (end <= begin) { result = 0; break; }
                size_t form = end - begin;
                if (kind) {
                    /* The base64 form as a wide string, in place from its end. */
                    memmove(encoded, encoded + begin, form);
                    for (size_t i = form; i-- > 0;) { encoded[2 * i] = encoded[i]; encoded[2 * i + 1] = 0; }
                    begin = 0;
                    form *= 2;
                }
                yx_fast_literal literal = {encoded + begin, masks, form, false};
                yx_fast_best_atom(&literal, &offset, &width);
                if (!yx_se_push_atom(atoms, count, capacity, encoded + begin + offset, width)) result = -1;
            }
        }
    }
done:
    free(plain); free(encoded); free(masks);
    return result;
}

/* The atoms the reference's search holds for one pattern, for the count
 * that decides between Teddy and Aho-Corasick (yx_view_atom_order):
 * yx_ser_pattern_reference_atoms_status, and the kinds it leaves out whose
 * atoms no caller orders matches by. */
int yx_ser_search_atoms_status(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count)
{
    size_t capacity = 0;
    int result = yx_ser_pattern_reference_atoms_status(pattern, atoms, count);
    if (result || !pattern) return result;
    *atoms = NULL;
    *count = 0;
    if (pattern->kind == YX_PATTERN_TEXT) result = yx_ss_encoded_text_atoms(pattern, atoms, count, &capacity);
    else if (!pattern->rx_program && !pattern->rx_chain)
        result = yx_ss_masked_atoms(pattern, atoms, count, &capacity);
    if (result != 1) {
        free(*atoms);
        *atoms = NULL;
        *count = 0;
    }
    return result;
}

/* Hir::is_alternation_literal: a literal or an alternation of literals,
 * optionally inside one capture group. regex-syntax turns an alternation
 * of single characters into a Unicode class, which does not qualify. */
static bool yx_ss_alternation_literal(const yx_tr_node *node)
{
    if (node->kind == YX_TR_CAPTURE && node->count == 1) node = node->children[0];
    if (node->kind == YX_TR_LITERAL) return node->length != 0;
    if (node->kind != YX_TR_ALT || node->unicode_class || !node->count) return false;
    for (size_t i = 0; i < node->count; ++i)
        if (node->children[i]->kind != YX_TR_LITERAL) return false;
    return true;
}

/* FastVM rejects Unicode classes anywhere in the regexp. */
static bool yx_ss_unicode_class(const yx_tr_node *node, size_t depth)
{
    if (depth > 250 || node->kind == YX_TR_SCALAR_CLASS ||
        ((node->kind == YX_TR_CLASS || node->kind == YX_TR_ALT) && node->unicode_class))
        return true;
    for (size_t i = 0; i < node->count; ++i)
        if (yx_ss_unicode_class(node->children[i], depth + 1)) return true;
    return false;
}

/* Whether parsing text for the warning classifier (warning_only) yields
 * the same tree as yx_tr_compile's parse: warning_only only changes the
 * u flag, the \u, \U and \x{...} escapes and \b{...} boundaries. */
static bool yx_ss_warning_neutral(const char *text)
{
    for (size_t i = 0; text[i]; ++i) {
        if (text[i] == '\\') {
            char next = text[i + 1];
            if (!next) break;
            if (next == 'u' || next == 'U' || ((next == 'x' || next == 'b') && text[i + 2] == '{')) return false;
            ++i;
        } else if (text[i] == '(' && text[i + 1] == '?') {
            for (size_t j = i + 2; text[j] && strchr("imsxuUR-", text[j]); ++j)
                if (text[j] == 'u') return false;
        }
    }
    return true;
}
/* The atom lengths of Compiler::c_regexp: FastVM first, then the Thompson
 * compiler when FastVM rejects the regexp or its shortest atom is under
 * two bytes. Returns 1, 0 when not modeled, -1 on allocation failure.
 * regexp: the source the whole of node was parsed from (with the pattern's
 * dotall and nocase), or NULL. When the warning parse of regexp equals the
 * scanner's, the Thompson atoms come from yx_tr_compile, whose per-thread
 * cache then also serves the scanner program built from the same source. */
static int yx_ss_regexp_atoms(const yx_tr_node *node, const YRX_PATTERN *hex,
                              const char *regexp, bool dotall, bool nocase,
                              size_t *count, size_t *minimum, size_t *maximum)
{
    yx_fast_program *fast;
    yx_tr_program program = {0};
    unsigned split = 0;
    bool ok;
    *count = 0; *minimum = SIZE_MAX; *maximum = 0;
    if (!yx_ss_unicode_class(node, 0)) {
        fast = calloc(1, sizeof(*fast));
        if (!fast) return -1;
        fast->flags = 64;
        fast->force_regexp = true;
        ok = hex ? yx_fast_hex_sequence(fast, hex->hex_atoms, hex->hex_atom_count)
                 : yx_ft_regex(fast, node, false);
        if (ok && yx_fast_compile_mode(fast, true)) {
            *count = fast->atom_count;
            for (size_t i = 0; i < fast->atom_count; ++i) {
                if (fast->atoms[i].length < *minimum) *minimum = fast->atoms[i].length;
                if (fast->atoms[i].length > *maximum) *maximum = fast->atoms[i].length;
            }
            yx_fast_program_destroy(fast);
            return 1;
        }
        yx_fast_program_destroy(fast);
    }
    if (regexp && yx_ss_warning_neutral(regexp)) {
        /* yx_tr_compile adds the zero-length atom itself when the program
         * has none, which the count below also assumes. */
        bool greedy;
        ok = yx_tr_compile(regexp, dotall, nocase, &program, &greedy);
    } else
        ok = yx_tr_compile_node(node, &program, &split, 0, false, false) &&
             yx_tr_fold_events(&program.events, &program.atoms);
    if (ok) {
        /* No atoms: a single zero-length atom covers the regexp. */
        *count = program.atoms.count ? program.atoms.count : 1;
        if (!program.atoms.count) *minimum = 0;
        for (size_t i = 0; i < program.atoms.count; ++i) {
            if (program.atoms.items[i].length < *minimum) *minimum = program.atoms.items[i].length;
            if (program.atoms.items[i].length > *maximum) *maximum = program.atoms.items[i].length;
        }
    }
    yx_tr_program_free(&program);
    return ok ? 1 : 0;
}

/* c_regexp's rule: no atoms, a single atom shorter than 2 bytes, an atom
 * shorter than 2 bytes, or more than 2700 atoms of exactly 2 bytes. A
 * single empty atom is the exceptionally extreme case (2). */
static uint8_t yx_ss_classify(size_t count, size_t minimum, size_t maximum)
{
    if (!count) return 1;
    if (count == 1) return minimum == 0 ? 2 : minimum < 2 ? 1 : 0;
    if (minimum < 2) return 1;
    return minimum == 2 && maximum == 2 && count > 2700 ? 1 : 0;
}

static int yx_ss_call(const yx_tr_node *node, const YRX_PATTERN *hex, const char *regexp,
                      bool dotall, bool nocase, uint8_t *calls, size_t *call_count)
{
    size_t count, minimum, maximum;
    int result = yx_ss_regexp_atoms(node, hex, regexp, dotall, nocase, &count, &minimum, &maximum);
    if (result == 1) calls[(*call_count)++] = yx_ss_classify(count, minimum, maximum);
    return result;
}

/* Compiler::c_rule's slow_pattern decisions for a regexp or hex pattern:
 * *literal_slow when its HIR is one literal that is_slow_pattern_bytes
 * reports, and one entry in *calls per c_regexp call of c_regexp_pattern,
 * in order (0 not slow, 1 slow, 2 slow with the extreme note). A pattern
 * split at large gaps compiles each piece that is not a literal; a literal,
 * an alternation of literals and a masked literal (without nocase or wide)
 * are not compiled by c_regexp. Returns 1, 0 when the pattern is outside
 * the parser's grammar, -1 on allocation failure; the caller frees *calls. */
static int yx_ser_slow_pattern_uncached(const YRX_PATTERN *pattern, bool *literal_slow,
                                        uint8_t **calls, size_t *call_count)
{
    bool hex = pattern && pattern->kind == YX_PATTERN_HEX;
    yx_writer hex_text = {0};
    yx_tr_node *root = NULL;
    size_t *starts = NULL, *ends = NULL, pieces = 0;
    int result = 0;
    *literal_slow = false;
    *calls = NULL;
    *call_count = 0;
    if (!pattern || (!hex && (pattern->kind != YX_PATTERN_REGEX || !pattern->regexp)) ||
        (hex && !pattern->hex_atoms)) return 0;
    bool dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0;
    bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    const char *regexp = pattern->regexp;
    if (hex) {
        if (!yx_tr_hex_regex(&hex_text, pattern->hex_atoms, pattern->hex_atom_count, 0) ||
            !yx_put_u8(&hex_text, 0)) goto done;
        regexp = (const char *)hex_text.data;
    }
    yx_tr_parser parser = {.text = (const uint8_t *)regexp, .length = strlen(regexp),
                           .dotall = dotall, .nocase = nocase, .warning_only = true};
    root = yx_tr_expression(&parser);
    if (!root || parser.failed || parser.oom || parser.at != parser.length) {
        result = parser.oom ? -1 : 0;
        goto done;
    }
    if (root->kind == YX_TR_LITERAL) *literal_slow = yx_ss_slow_bytes(root->bytes, root->length);
    *calls = malloc(root->count + 1);
    starts = malloc((root->count + 1) * sizeof(*starts));
    ends = malloc((root->count + 1) * sizeof(*ends));
    if (!*calls || !starts || !ends) { result = -1; goto done; }
    /* Hir::split_at_large_gaps: a top-level concatenation splits at any-byte
     * gaps longer than 200 bytes when the piece before the gap matches at
     * least 2 bytes; a short final piece rejoins the previous one, and a
     * trailing gap is dropped. */
    starts[0] = 0;
    ends[0] = root->count;
    pieces = 1;
    if (root->kind == YX_TR_CONCAT) {
        size_t chunk = 0;
        bool chunk_empty = true;
        pieces = 0;
        for (size_t i = 0; i < root->count; ++i) {
            const yx_tr_node *item = root->children[i];
            if (item->kind == YX_TR_REPEAT && item->count && !chunk_empty &&
                (yx_tr_unbounded(item) ? UINT32_MAX : item->maximum) > 200 &&
                yx_se_any_byte(item->children[0])) {
                uint64_t minimum = 0;
                for (size_t j = chunk; j < i; ++j) {
                    uint64_t length = yx_se_minimum_length(root->children[j]);
                    minimum = length > UINT64_MAX - minimum ? UINT64_MAX : minimum + length;
                }
                if (minimum >= 2) {
                    starts[pieces] = chunk;
                    ends[pieces++] = i;
                    chunk = i + 1;
                    chunk_empty = true;
                    continue;
                }
            }
            chunk_empty = false;
        }
        if (!chunk_empty) {
            uint64_t minimum = 0;
            for (size_t j = chunk; j < root->count; ++j) {
                uint64_t length = yx_se_minimum_length(root->children[j]);
                minimum = length > UINT64_MAX - minimum ? UINT64_MAX : minimum + length;
            }
            if (!pieces || minimum >= 2) {
                starts[pieces] = chunk;
                ends[pieces++] = root->count;
            } else ends[pieces - 1] = root->count;
        }
    }
    for (size_t i = 0; i < pieces; ++i) {
        yx_tr_node fragment = {.kind = YX_TR_CONCAT, .children = root->children + starts[i],
                               .count = ends[i] - starts[i]};
        const yx_tr_node *node = &fragment;
        bool whole = root->kind != YX_TR_CONCAT ||
                     (starts[i] == 0 && ends[i] == root->count);
        int status;
        if (whole) node = root;
        else if (fragment.count == 1) node = fragment.children[0];
        else for (size_t j = 0; j < fragment.count; ++j) fragment.has_look |= fragment.children[j]->has_look;
        if (pieces > 1) {
            /* c_chain: each piece that is not a literal goes to c_regexp. */
            if (node->kind == YX_TR_LITERAL) continue;
            status = yx_ss_call(node, NULL, NULL, false, false, *calls, call_count);
        } else {
            if (yx_ss_alternation_literal(node)) break;
            if (!nocase && !wide) {
                status = yx_ss_masked_literal(node);
                if (status < 0) { result = -1; goto done; }
                if (status) break;
            }
            status = yx_ss_call(node, hex && whole ? pattern : NULL, whole ? regexp : NULL,
                                dotall, nocase, *calls, call_count);
        }
        if (status != 1) { result = status; goto done; }
    }
    result = 1;
done:
    if (result != 1) {
        free(*calls);
        *calls = NULL;
        *call_count = 0;
        *literal_slow = false;
    }
    free(starts);
    free(ends);
    yx_tr_destroy(root);
    free(hex_text.data);
    return result;
}

/* The classification of a regexp pattern depends only on its regexp and
 * modifiers; repetitions in other rules and namespaces reuse it (hex
 * patterns, which read their atoms, are classified every time). The memo
 * holds the result, literal_slow, and the calls; allocation failures are
 * not kept. */
typedef struct {
    int result;
    bool literal_slow;
    size_t call_count;
} yx_ss_memo_value;

int yx_ser_slow_pattern(const YRX_PATTERN *pattern, bool *literal_slow,
                        uint8_t **calls, size_t *call_count)
{
    unsigned char value[sizeof(yx_ss_memo_value) + 256];
    yx_ss_memo_value head;
    size_t length, stored = 0;
    uint64_t tag;
    const void *hit;
    int result;
    if (!pattern || pattern->kind != YX_PATTERN_REGEX || !pattern->regexp)
        return yx_ser_slow_pattern_uncached(pattern, literal_slow, calls, call_count);
    length = strlen(pattern->regexp);
    tag = YX_MEMO_TAG(YX_MEMO_SLOW_PATTERN, (unsigned)pattern->kind, pattern->modifiers);
    hit = yx_compile_memo_find(tag, pattern->regexp, length, &stored);
    if (hit && stored >= sizeof(head)) {
        memcpy(&head, hit, sizeof(head));
        if (stored == sizeof(head) + head.call_count) {
            *literal_slow = head.literal_slow;
            *calls = NULL;
            *call_count = 0;
            if (head.result == 1) {
                *calls = malloc(head.call_count + 1);
                if (!*calls) {
                    *literal_slow = false;
                    return -1;
                }
                if (head.call_count)
                    memcpy(*calls, (const unsigned char *)hit + sizeof(head), head.call_count);
                *call_count = head.call_count;
            }
            return head.result;
        }
    }
    result = yx_ser_slow_pattern_uncached(pattern, literal_slow, calls, call_count);
    if (result >= 0 && *call_count <= 256) {
        head.result = result;
        head.literal_slow = *literal_slow;
        head.call_count = *call_count;
        memcpy(value, &head, sizeof(head));
        if (*call_count) memcpy(value + sizeof(head), *calls, *call_count);
        yx_compile_memo_store(tag, pattern->regexp, length, value, sizeof(head) + *call_count);
    }
    return result;
}
#include "serialization_hir_chain.h"
#endif
