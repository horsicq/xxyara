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
 * The instruction encoding, repetition lowering and atom selection follow
 * lib/src/re/thompson and lib/src/compiler/atoms in YARA-X v1.21.0.
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

/* Recursive Thompson bytecode compiler for the pinned YARA-X instruction
 * format. Included by serialization.c after the shared pattern envelope. */
#ifndef XXYARA_SERIALIZATION_THOMPSON_H
#define XXYARA_SERIALIZATION_THOMPSON_H

#include "native_regex.h"

typedef enum {
    YX_TR_EMPTY,
    YX_TR_LITERAL,
    YX_TR_CLASS,
    YX_TR_LOOK,
    YX_TR_CONCAT,
    YX_TR_ALT,
    YX_TR_REPEAT,
    YX_TR_CAPTURE,
    YX_TR_SCALAR_CLASS
} yx_tr_kind;
typedef struct yx_tr_node {
    yx_tr_kind kind;
    struct yx_tr_node **children;
    size_t count;
    uint8_t *bytes;
    size_t length;
    uint8_t bitmap[32], look;
    uint32_t minimum, maximum;
    bool greedy, has_look, unicode_class, finite_maximum;
    /* YX_TR_SCALAR_CLASS: the range ending at U+D7FF and the range starting
     * at U+E000 are two ranges of the class ([\x{0}-\x{D7FF}\x{E000}-\x{10FFFF}]),
     * not regex-syntax's one range of chars across the surrogate gap. */
    bool gap_split;
    /* The source text yx_tr_atom read for the node, quantifiers included;
     * meaningful only while the node is the atom's own result. */
    size_t start, end;
} yx_tr_node;
static bool yx_tr_unbounded(const yx_tr_node *node)
{
    return node->maximum == UINT32_MAX && !node->finite_maximum;
}
typedef struct {
    const uint8_t *text;
    size_t at, length, depth;
    bool failed, oom, dotall, nocase, saw_greedy, saw_lazy, stacked, extended;
    bool warning_only, unicode;
    bool condition_only, multiline, crlf, ungreedy;
    /* Keep alternations of scalar literals (decoded-code checks count the
     * literal bytes of both directions). */
    bool literal_alternations;
    char *capture_names;
    size_t capture_names_length, capture_names_capacity;
} yx_tr_parser;
static void yx_tr_destroy(yx_tr_node *node)
{
    if (!node) return;
    for (size_t i = 0; i < node->count; ++i) yx_tr_destroy(node->children[i]);
    free(node->children);
    free(node->bytes);
    free(node);
}
static yx_tr_node *yx_tr_new(yx_tr_parser *p, yx_tr_kind kind)
{
    yx_tr_node *node = calloc(1, sizeof(*node));
    if (!node) p->oom = true;
    else node->kind = kind;
    return node;
}
/* Assertion-only HIR has no capture or backreference side effects in the
 * scanner VM. Repeating it is idempotent: a positive minimum needs one
 * evaluation, while a zero minimum permits the empty expression. */
static bool yx_tr_zero_width(const yx_tr_node *node)
{
    if (!node) return false;
    if (node->kind == YX_TR_EMPTY || node->kind == YX_TR_LOOK) return true;
    if (node->kind != YX_TR_CONCAT && node->kind != YX_TR_ALT && node->kind != YX_TR_CAPTURE && node->kind != YX_TR_REPEAT) return false;
    for (size_t i = 0; i < node->count; ++i)
        if (!yx_tr_zero_width(node->children[i])) return false;
    return true;
}
static bool yx_tr_child(yx_tr_parser *p, yx_tr_node *node, yx_tr_node *child)
{
    if (!node || !child || node->count >= 65535) {
        p->failed = true;
        return false;
    }
    yx_tr_node **items = realloc(node->children, (node->count + 1) * sizeof(*items));
    if (!items) {
        p->oom = true;
        return false;
    }
    node->children = items;
    node->children[node->count++] = child;
    node->has_look |= child->has_look;
    return true;
}
/* Smart constructors flatten grouping-only concatenations/alternations and
 * merge adjacent literals before bytecode and atom extraction see the HIR. */
static bool yx_tr_join_child(yx_tr_parser *p, yx_tr_node *node, yx_tr_node *child)
{
    if (node->kind == child->kind && (node->kind == YX_TR_CONCAT || node->kind == YX_TR_ALT)) {
        for (size_t i = 0; i < child->count; ++i) {
            if (!yx_tr_join_child(p, node, child->children[i])) return false;
            child->children[i] = NULL;
        }
        child->count = 0;
        yx_tr_destroy(child);
        return true;
    }
    if (node->kind == YX_TR_CONCAT && node->count && child->kind == YX_TR_LITERAL && node->children[node->count - 1]->kind == YX_TR_LITERAL) {
        yx_tr_node *previous = node->children[node->count - 1];
        if (child->length > SIZE_MAX - previous->length) {
            p->oom = true;
            return false;
        }
        uint8_t *bytes = realloc(previous->bytes, previous->length + child->length);
        if (!bytes) {
            p->oom = true;
            return false;
        }
        memcpy(bytes + previous->length, child->bytes, child->length);
        previous->bytes = bytes;
        previous->length += child->length;
        yx_tr_destroy(child);
        return true;
    }
    return yx_tr_child(p, node, child);
}
static yx_tr_node *yx_tr_finish_concat(yx_tr_node *node)
{
    if (!node->count) node->kind = YX_TR_EMPTY;
    else if (node->count == 1) {
        yx_tr_node *child = node->children[0];
        node->count = 0;
        yx_tr_destroy(node);
        return child;
    }
    return node;
}
static bool yx_tr_equal(const yx_tr_node *a, const yx_tr_node *b)
{
    /* Capture indices affect upstream HIR equality. Conservatively avoid
     * factoring captures, whose numbering is unnecessary for matching. */
    if (a->kind == YX_TR_CAPTURE || a->kind != b->kind || a->count != b->count || a->length != b->length || a->minimum != b->minimum || a->maximum != b->maximum ||
        a->finite_maximum != b->finite_maximum || a->greedy != b->greedy || a->look != b->look || a->unicode_class != b->unicode_class || a->gap_split != b->gap_split ||
        memcmp(a->bitmap, b->bitmap, 32) || (a->length && memcmp(a->bytes, b->bytes, a->length * (a->kind == YX_TR_SCALAR_CLASS ? sizeof(yx_re_range) : 1))))
        return false;
    for (size_t i = 0; i < a->count; ++i)
        if (!yx_tr_equal(a->children[i], b->children[i])) return false;
    return true;
}
static void yx_tr_set(uint8_t bitmap[32], unsigned byte)
{
    bitmap[byte >> 3] |= (uint8_t)(1u << (byte & 7));
}
static bool yx_tr_has(const uint8_t bitmap[32], unsigned byte)
{
    return (bitmap[byte >> 3] & (uint8_t)(1u << (byte & 7))) != 0;
}
static yx_tr_node *yx_tr_byte(yx_tr_parser *p, unsigned byte)
{
    yx_tr_node *node = yx_tr_new(p, p->nocase && byte < 128 && isalpha((int)byte) ? YX_TR_CLASS : YX_TR_LITERAL);
    if (!node) return NULL;
    if (node->kind == YX_TR_CLASS) {
        yx_tr_set(node->bitmap, (unsigned)tolower((int)byte));
        yx_tr_set(node->bitmap, (unsigned)toupper((int)byte));
    } else {
        node->bytes = malloc(1);
        if (!node->bytes) {
            p->oom = true;
            yx_tr_destroy(node);
            return NULL;
        }
        node->bytes[0] = (uint8_t)byte;
        node->length = 1;
    }
    return node;
}
static bool yx_tr_escape(yx_tr_parser *p, uint8_t bitmap[32], unsigned *value, bool *is_class, uint8_t *look)
{
    if (p->at == p->length) return false;
    unsigned c = p->text[p->at++];
    *is_class = false;
    *look = 0;
    /* regex-syntax permits superfluous escapes only for ASCII characters.
     * A raw UTF-8 scalar remains valid without a preceding backslash. */
    if (p->condition_only && c >= 128) return false;
    if (c == 'x') {
        if (p->length - p->at < 2) return false;
        unsigned v = 0;
        for (size_t i = 0; i < 2; ++i) {
            unsigned d = p->text[p->at++];
            if (d >= '0' && d <= '9') d -= '0';
            else if (d >= 'a' && d <= 'f') d = d - 'a' + 10;
            else if (d >= 'A' && d <= 'F') d = d - 'A' + 10;
            else return false;
            v = v * 16 + d;
        }
        *value = v;
        return true;
    }
    if (c == 'd' || c == 'D' || c == 'w' || c == 'W' || c == 's' || c == 'S') {
        unsigned low = (unsigned)tolower((int)c);
        for (unsigned b = 0; b < 256; ++b) {
            bool match = low == 'd'   ? (b >= '0' && b <= '9')
                         : low == 'w' ? ((b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_')
                                      : b == ' ' || (b >= 9 && b <= 13);
            if ((c == low) == match) yx_tr_set(bitmap, b);
        }
        *is_class = true;
        return true;
    }
    if (c == 'b' && (p->warning_only || p->condition_only) && p->at < p->length && p->text[p->at] == '{') {
        static const char *const boundaries[] = {"{start}", "{end}", "{start-half}", "{end-half}"};
        for (size_t i = 0; i < sizeof(boundaries) / sizeof(*boundaries); ++i) {
            size_t n = strlen(boundaries[i]);
            if (n <= p->length - p->at && !memcmp(p->text + p->at, boundaries[i], n)) {
                p->at += n;
                if (p->condition_only) {
                    *look = (uint8_t)(24 + i);
                    return true;
                }
                break;
            }
        }
    }
    if (c == 'b' || c == 'B' || c == 'A' || c == 'z') {
        *look = c == 'b' ? 12 : c == 'B' ? 13 : c == 'A' ? 10 : 11;
        return true;
    }
    if (c == 'n') c = '\n';
    else if (c == 'r') c = '\r';
    else if (c == 't') c = '\t';
    else if (c == 'f') c = '\f';
    else if (c == 'v') c = '\v';
    else if (c == 'a') c = 7;
    else if (isalnum((int)c)) return false;
    *value = c;
    return true;
}
static yx_tr_node *yx_tr_expression(yx_tr_parser *p);
static void yx_tr_repeat_space(yx_tr_parser *p)
{
    while (p->at < p->length) {
        const uint8_t *s = p->text + p->at;
        size_t left = p->length - p->at, width = 0;
        if (*s == 32 || (*s >= 9 && *s <= 13)) width = 1;
        else if (left >= 2 && s[0] == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0)) width = 2;
        else if (left >= 3 && ((s[0] == 0xe1 && s[1] == 0x9a && s[2] == 0x80) ||
                               (s[0] == 0xe2 && s[1] == 0x80 && ((s[2] >= 0x80 && s[2] <= 0x8a) || s[2] == 0xa8 || s[2] == 0xa9 || s[2] == 0xaf)) ||
                               (s[0] == 0xe2 && s[1] == 0x81 && s[2] == 0x9f) || (s[0] == 0xe3 && s[1] == 0x80 && s[2] == 0x80)))
            width = 3;
        if (!width) break;
        p->at += width;
    }
}
static void yx_tr_skip_space(yx_tr_parser *p)
{
    if (!p->extended) return;
    for (;;) {
        yx_tr_repeat_space(p);
        if (p->at == p->length || p->text[p->at] != '#') break;
        while (p->at < p->length && p->text[p->at] != '\n') ++p->at;
    }
}
/* Condition regexps use the scalar resolver already shared with the native
 * parser, then parse its exact UTF-8 byte expansion. Scanner serialization and
 * warning classification keep their existing AST and instruction choices. */
static yx_tr_node *yx_tr_condition_ranges(yx_tr_parser *p, const yx_re_range *ranges, size_t count)
{
#ifdef XXYARA_NATIVE_REGEX
    if (!count) return yx_tr_new(p, YX_TR_CLASS);
    char *text = yx_re_ranges_pattern(ranges, count);
    if (!text) {
        p->oom = true;
        return NULL;
    }
    /* The rule's AST depth is validated separately. These generated UTF-8
     * groups must not consume the source expression's remaining depth, and
     * their byte alternations stay branches of the search program. */
    yx_tr_parser lowered = {.text = (const uint8_t *)text, .length = strlen(text), .literal_alternations = true};
    yx_tr_node *node = yx_tr_expression(&lowered);
    if (!node || lowered.failed || lowered.at != lowered.length) {
        yx_tr_destroy(node);
        node = NULL;
        p->failed = true;
    }
    if (lowered.oom) p->oom = true;
    free(text);
    return node;
#else
    (void)ranges;
    (void)count;
    p->failed = true;
    return NULL;
#endif
}
/* The literal of one Unicode scalar: its UTF-8 bytes. */
static yx_tr_node *yx_tr_scalar_literal(yx_tr_parser *p, uint32_t value)
{
    if (value < 0x80) return yx_tr_byte(p, value);
    yx_tr_node *node = yx_tr_new(p, YX_TR_LITERAL);
    if (!node) return NULL;
    node->bytes = malloc(4);
    if (!node->bytes) {
        p->oom = true;
        yx_tr_destroy(node);
        return NULL;
    }
    if (value < 0x800) {
        node->bytes[0] = (uint8_t)(0xc0 | (value >> 6));
        node->bytes[1] = (uint8_t)(0x80 | (value & 0x3f));
        node->length = 2;
    } else if (value < 0x10000) {
        node->bytes[0] = (uint8_t)(0xe0 | (value >> 12));
        node->bytes[1] = (uint8_t)(0x80 | ((value >> 6) & 0x3f));
        node->bytes[2] = (uint8_t)(0x80 | (value & 0x3f));
        node->length = 3;
    } else {
        node->bytes[0] = (uint8_t)(0xf0 | (value >> 18));
        node->bytes[1] = (uint8_t)(0x80 | ((value >> 12) & 0x3f));
        node->bytes[2] = (uint8_t)(0x80 | ((value >> 6) & 0x3f));
        node->bytes[3] = (uint8_t)(0x80 | (value & 0x3f));
        node->length = 4;
    }
    return node;
}

static yx_tr_node *yx_tr_condition_scalar(yx_tr_parser *p, size_t start)
{
#ifdef XXYARA_NATIVE_REGEX
    yx_re_range *ranges = NULL;
    size_t count = 0, at = start;
    /* In a byte scope scalar escapes still encode UTF-8, but case folding is
     * ASCII only. A scalar below 128 can use the regular byte constructor. */
    if (!yx_re_class_ranges(p->text, p->length, &at, PCRE2_UTF, &ranges, &count)) return NULL;
    yx_tr_node *node =
        count == 1 && ranges[0].first == ranges[0].last && ranges[0].first < 128 ? yx_tr_byte(p, ranges[0].first) : yx_tr_condition_ranges(p, ranges, count);
    free(ranges);
    p->at = at;
    return node;
#else
    (void)p;
    (void)start;
    return NULL;
#endif
}
static yx_tr_node *yx_tr_scalar_atom(yx_tr_parser *p, size_t start)
{
    yx_re_range *ranges = NULL;
    size_t count = 0, at = start;
    bool gap_split = false;
    uint32_t options = PCRE2_UTF | PCRE2_UCP | (p->nocase ? PCRE2_CASELESS : 0) | (p->extended ? PCRE2_EXTENDED : 0);
    if (p->condition_only ? !yx_re_class_ranges(p->text, p->length, &at, options, &ranges, &count)
                          : !yx_re_class_ranges_gap(p->text, p->length, &at, options, &ranges, &count, &gap_split))
        return NULL;
    if (p->condition_only) {
        yx_tr_node *node = yx_tr_condition_ranges(p, ranges, count);
        free(ranges);
        p->at = at;
        return node;
    }
    /* Hir::class makes a class of one scalar the literal of it. */
    if (count == 1 && ranges[0].first == ranges[0].last) {
        uint32_t value = ranges[0].first;
        free(ranges);
        p->at = at;
        return yx_tr_scalar_literal(p, value);
    }
    /* In patterns, a Unicode class of ASCII scalars is a byte class that
     * keeps its Unicode kind (ClassUnicode::to_byte_class): the Thompson
     * compiler emits it without the masked-byte form and FastVM rejects it.
     * The empty class is Hir::fail, a byte class. */
    if (!p->warning_only && (!count || ranges[count - 1].last < 0x80)) {
        yx_tr_node *node = yx_tr_new(p, YX_TR_CLASS);
        if (!node) {
            free(ranges);
            return NULL;
        }
        for (size_t i = 0; i < count; ++i)
            for (uint32_t b = ranges[i].first; b <= ranges[i].last; ++b) yx_tr_set(node->bitmap, (unsigned)b);
        node->unicode_class = count != 0;
        free(ranges);
        p->at = at;
        return node;
    }
    yx_tr_node *node = yx_tr_new(p, YX_TR_SCALAR_CLASS);
    if (!node) {
        free(ranges);
        return NULL;
    }
    node->bytes = (uint8_t *)ranges;
    node->length = count;
    p->at = at;
    node->gap_split = gap_split;
    return node;
}

/* regex-syntax reads `\x{...}`, `\u` and `\U` escapes as Unicode scalars
 * (only the two-digit `\xNN` form is a byte). Outside Unicode mode a scalar
 * above 0x7f is the literal of its UTF-8 bytes. Only the warning
 * classifier reads these escapes; the escape letter is at `p->at`. */
static yx_tr_node *yx_tr_scalar_escape(yx_tr_parser *p)
{
    unsigned kind = p->text[p->at++];
    size_t digits = kind == 'x' ? 2 : kind == 'u' ? 4 : 8, count = 0;
    uint32_t value = 0;
    bool brace = p->at < p->length && p->text[p->at] == '{';
    if (brace) ++p->at;
    while (p->at < p->length && (brace ? p->text[p->at] != '}' : count < digits)) {
        unsigned d = p->text[p->at];
        if (d >= '0' && d <= '9') d -= '0';
        else if (d >= 'a' && d <= 'f') d = d - 'a' + 10;
        else if (d >= 'A' && d <= 'F') d = d - 'A' + 10;
        else {
            p->failed = true;
            return NULL;
        }
        if (value > 0x10ffff) {
            p->failed = true;
            return NULL;
        }
        value = value * 16 + d;
        ++count;
        ++p->at;
    }
    if (brace) {
        if (p->at == p->length || !count) {
            p->failed = true;
            return NULL;
        }
        ++p->at;
    } else if (count != digits) {
        p->failed = true;
        return NULL;
    }
    if (value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
        p->failed = true;
        return NULL;
    }
    return yx_tr_scalar_literal(p, value);
}

/* A byte class made only of \xHH escapes, `[\x41\x42...]` starting at `at`
 * (just after the '['): its bitmap and the position after the ']'. Without
 * case folding and extended syntax the class parser reads each escape as
 * one byte, so the set is exactly the listed bytes. */
static bool yx_tr_byte_list_class(const yx_tr_parser *p, size_t at, uint8_t bitmap[32], size_t *end)
{
    memset(bitmap, 0, 32);
    if (at >= p->length || p->text[at] != '\\') return false;
    while (at + 4 <= p->length && p->text[at] == '\\' && p->text[at + 1] == 'x') {
        unsigned v = 0;
        for (size_t i = 2; i < 4; ++i) {
            unsigned d = p->text[at + i];
            if (d >= '0' && d <= '9') d -= '0';
            else if (d >= 'a' && d <= 'f') d = d - 'a' + 10;
            else if (d >= 'A' && d <= 'F') d = d - 'A' + 10;
            else return false;
            v = v * 16 + d;
        }
        yx_tr_set(bitmap, v);
        at += 4;
        if (at < p->length && p->text[at] == ']') {
            *end = at + 1;
            return true;
        }
    }
    return false;
}
static yx_tr_node *yx_tr_atom(yx_tr_parser *p)
{
    if (p->at >= p->length || p->depth > 250) {
        p->failed = true;
        return NULL;
    }
    size_t atom_start = p->at;
    unsigned c = p->text[p->at++];
    yx_tr_node *node = NULL;
    if (c == '(') {
        bool capture = true;
        bool saved_nocase = p->nocase, saved_dotall = p->dotall, saved_extended = p->extended;
        bool saved_unicode = p->unicode;
        bool saved_multiline = p->multiline, saved_crlf = p->crlf;
        bool saved_ungreedy = p->ungreedy;
        if (p->at < p->length && p->text[p->at] == '?') {
            ++p->at;
            if (p->at < p->length && (p->text[p->at] == '<' || (p->text[p->at] == 'P' && p->at + 1 < p->length && p->text[p->at + 1] == '<'))) {
                if (p->text[p->at] == 'P') ++p->at;
                size_t name = ++p->at;
                while (p->at < p->length && p->text[p->at] != '>') ++p->at;
                if (p->at == p->length) goto invalid;
#ifdef XXYARA_NATIVE_REGEX
                if (p->condition_only) {
                    int status = yx_re_capture_name_append(&p->capture_names, &p->capture_names_length, &p->capture_names_capacity, p->text + name, p->at - name);
                    if (status <= 0) {
                        if (status < 0) p->oom = true;
                        goto invalid;
                    }
                }
#else
                (void)name;
#endif
                ++p->at;
            } else {
                bool negate = false, any = false;
                while (p->at < p->length) {
                    unsigned flag = p->text[p->at];
                    if (flag == '-') {
                        negate = true;
                        ++p->at;
                        continue;
                    }
                    if (flag == 'i') p->nocase = !negate;
                    else if (flag == 's') p->dotall = !negate;
                    else if (flag == 'x') p->extended = !negate;
                    /* u makes classes and literals Unicode scalars; the
                     * Thompson compiler emits their UTF-8 sequences. */
                    else if (flag == 'u') p->unicode = !negate;
                    /* m and R only change `^`, `$` and `.`; YARA-X accepts
                     * both in patterns as well as in conditions. */
                    else if (flag == 'm') p->multiline = !negate;
                    else if (flag == 'R') p->crlf = !negate;
                    /* U swaps the meaning of a quantifier and its `?` suffix. */
                    else if (flag == 'U') p->ungreedy = !negate;
                    else break;
                    any = true;
                    ++p->at;
                }
                if (any && p->at < p->length && p->text[p->at] == ')') {
                    ++p->at;
                    return yx_tr_new(p, YX_TR_EMPTY);
                }
                if (p->at == p->length || p->text[p->at++] != ':') goto invalid;
                capture = false;
            }
        }
        ++p->depth;
        node = yx_tr_expression(p);
        --p->depth;
        if (!node || p->at == p->length || p->text[p->at++] != ')') goto invalid;
        p->nocase = saved_nocase;
        p->dotall = saved_dotall;
        p->extended = saved_extended;
        p->unicode = saved_unicode;
        p->multiline = saved_multiline;
        p->crlf = saved_crlf;
        p->ungreedy = saved_ungreedy;
        if (capture) {
            yx_tr_node *parent = yx_tr_new(p, YX_TR_CAPTURE);
            if (!yx_tr_child(p, parent, node)) {
                yx_tr_destroy(parent);
                goto invalid;
            }
            node = parent;
        }
    } else if (c == '[' && p->unicode) {
        node = yx_tr_scalar_atom(p, p->at - 1);
    } else if (c == '[') {
        /* All scanner compilers consume the same normalized class set.
         * Nested brackets and &&/--/~~ use regex-syntax's class grammar.
         * Unicode-scoped atoms use the native fallback, selected by this
         * byte compiler's unsupported u flag. */
        size_t at = p->at - 1, count = 0;
        yx_re_range *ranges = NULL;
        uint8_t listed[32];
        if (!p->nocase && !p->extended && yx_tr_byte_list_class(p, p->at, listed, &at)) {
            /* A list of \xHH escapes, as yx_tr_hex_regex writes masked hex
             * bytes: the byte set the class parser would return. */
            node = yx_tr_new(p, YX_TR_CLASS);
            if (!node) return NULL;
            p->at = at;
            memcpy(node->bitmap, listed, 32);
        } else {
            if (!yx_re_class_ranges(p->text, p->length, &at, (p->nocase ? PCRE2_CASELESS : 0) | (p->extended ? PCRE2_EXTENDED : 0), &ranges, &count)) goto invalid;
            node = yx_tr_new(p, YX_TR_CLASS);
            if (!node) {
                free(ranges);
                return NULL;
            }
            p->at = at;
            for (size_t i = 0; i < count; ++i)
                for (uint32_t b = ranges[i].first; b <= ranges[i].last; ++b) yx_tr_set(node->bitmap, (unsigned)b);
            free(ranges);
        }
        unsigned cardinality = 0, singleton = 0;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(node->bitmap, b)) {
                ++cardinality;
                singleton = b;
            }
        if (cardinality == 1) {
            yx_tr_destroy(node);
            node = yx_tr_byte(p, singleton);
        }
    } else if (c == '.' && p->condition_only && p->unicode) {
        yx_re_range ranges[4] = {{0, 0xd7ff}, {0xe000, 0x10ffff}};
        size_t count = 2;
        if (!p->dotall) {
            ranges[0] = (yx_re_range){0, 9};
            ranges[1] = (yx_re_range){11, p->crlf ? 12 : 0xd7ff};
            ranges[2] = (yx_re_range){p->crlf ? 14 : 0xe000, p->crlf ? 0xd7ff : 0x10ffff};
            count = 3;
            if (p->crlf) {
                ranges[3] = (yx_re_range){0xe000, 0x10ffff};
                count = 4;
            }
        }
        node = yx_tr_condition_ranges(p, ranges, count);
    } else if (c == '.' && p->unicode) {
        /* (?u). is every scalar value but `\n` (and `\r` with R); (?us).
         * is every one. */
        static const yx_re_range ranges[] = {{0, 9}, {11, 0xd7ff}, {0xe000, 0x10ffff}};
        static const yx_re_range crlf_ranges[] = {{0, 9}, {11, 12}, {14, 0xd7ff}, {0xe000, 0x10ffff}};
        static const yx_re_range dotall_ranges[] = {{0, 0xd7ff}, {0xe000, 0x10ffff}};
        const yx_re_range *chosen = p->dotall ? dotall_ranges : p->crlf ? crlf_ranges : ranges;
        size_t chosen_count = p->dotall ? 2 : p->crlf ? 4 : 3;
        node = yx_tr_new(p, YX_TR_SCALAR_CLASS);
        if (!node) return NULL;
        node->bytes = malloc(chosen_count * sizeof(*chosen));
        if (!node->bytes) {
            p->oom = true;
            yx_tr_destroy(node);
            return NULL;
        }
        memcpy(node->bytes, chosen, chosen_count * sizeof(*chosen));
        node->length = chosen_count;
    } else if (c == '.') {
        node = yx_tr_new(p, YX_TR_CLASS);
        if (!node) return NULL;
        memset(node->bitmap, 255, 32);
        if (!p->dotall) node->bitmap[1] &= (uint8_t)~4u;
        /* (?R). is [^\n\r]. */
        if (p->crlf && !p->dotall) node->bitmap[1] &= (uint8_t)~32u;
    } else if (c == '^' || c == '$') {
        node = yx_tr_new(p, YX_TR_LOOK);
        if (!node) return NULL;
        /* Multi-line anchors (Look::StartLF/StartCRLF, EndLF/EndCRLF) are
         * the PikeVM's LINE_START and LINE_END in patterns; conditions keep
         * the search program's own LF and CRLF looks. */
        node->look = p->multiline ? (uint8_t)(p->condition_only ? (p->crlf ? 22 : 20) + (c == '$') : (c == '^' ? 0x12 : 0x13)) : (uint8_t)(c == '^' ? 10 : 11);
        node->has_look = true;
    } else if (c == '\\' && p->unicode && p->at < p->length && strchr("dDsSwWpPxuU", p->text[p->at])) {
        node = yx_tr_scalar_atom(p, p->at - 1);
    } else if (c == '\\' && p->condition_only && !p->unicode && p->at < p->length &&
               (p->text[p->at] == 'u' || p->text[p->at] == 'U' || (p->text[p->at] == 'x' && p->at + 1 < p->length && p->text[p->at + 1] == '{'))) {
        node = yx_tr_condition_scalar(p, p->at - 1);
    } else if (c == '\\' && p->warning_only && p->at < p->length &&
               (p->text[p->at] == 'u' || p->text[p->at] == 'U' || (p->text[p->at] == 'x' && p->at + 1 < p->length && p->text[p->at + 1] == '{'))) {
        node = yx_tr_scalar_escape(p);
    } else if (c == '\\') {
        size_t escape_start = p->at - 1;
        uint8_t bm[32] = {0}, look = 0;
        bool cls;
        unsigned value = 0;
        /* YARA-X rejects \b and \B in Unicode mode. */
        if (!p->warning_only && p->unicode && p->at < p->length && (p->text[p->at] == 'b' || p->text[p->at] == 'B')) goto invalid;
        if (!yx_tr_escape(p, bm, &value, &cls, &look)) goto invalid;
        if (look || cls) {
            node = yx_tr_new(p, look ? YX_TR_LOOK : YX_TR_CLASS);
            if (!node) return NULL;
            node->look = look;
            node->has_look = look != 0;
            memcpy(node->bitmap, bm, 32);
        } else if (p->unicode) node = yx_tr_scalar_atom(p, escape_start);
        else node = yx_tr_byte(p, value);
    } else if (c == '*' || c == '+' || c == '?' || c == '{' || c == '}') goto invalid;
    else if (p->unicode) node = yx_tr_scalar_atom(p, p->at - 1);
    else if (c >= 0xc2 && c <= 0xf4) {
        /* regex-syntax reads a non-ASCII character as one literal, so a
         * quantifier applies to all of its UTF-8 bytes. */
        size_t n = c <= 0xdf ? 2 : c <= 0xef ? 3 : 4, k = 1;
        while (k < n && p->at + k - 1 < p->length && (p->text[p->at + k - 1] & 0xc0) == 0x80) ++k;
        if (k < n) node = yx_tr_byte(p, c);
        else {
            node = yx_tr_new(p, YX_TR_LITERAL);
            if (!node) return NULL;
            node->bytes = malloc(n);
            if (!node->bytes) {
                p->oom = true;
                yx_tr_destroy(node);
                return NULL;
            }
            memcpy(node->bytes, p->text + p->at - 1, n);
            node->length = n;
            p->at += n - 1;
        }
    } else node = yx_tr_byte(p, c);
    if (!node) return NULL;
    /* regex-syntax nests consecutive quantifiers. A '?' immediately after
     * one quantifier is its lazy suffix; later quantifiers wrap that HIR. */
    size_t repetitions = 0;
    yx_tr_skip_space(p);
    while (p->at < p->length && strchr("*+?{", p->text[p->at])) {
        if (++repetitions > 1) p->stacked = true;
        uint32_t min, max;
        bool unbounded = false;
        c = p->text[p->at++];
        if (c == '*') {
            min = 0;
            max = UINT32_MAX;
            unbounded = true;
        } else if (c == '+') {
            min = 1;
            max = UINT32_MAX;
            unbounded = true;
        } else if (c == '?') {
            min = 0;
            max = 1;
        } else {
            uint64_t number = 0;
            bool digit = false;
            yx_tr_repeat_space(p);
            while (p->at < p->length && isdigit(p->text[p->at])) {
                digit = true;
                number = number * 10 + p->text[p->at++] - '0';
                if (number > UINT32_MAX) goto invalid;
            }
            bool lower = digit;
            min = max = (uint32_t)number;
            yx_tr_repeat_space(p);
            if (p->at < p->length && p->text[p->at] == ',') {
                ++p->at;
                number = 0;
                digit = false;
                yx_tr_repeat_space(p);
                while (p->at < p->length && isdigit(p->text[p->at])) {
                    digit = true;
                    number = number * 10 + p->text[p->at++] - '0';
                    if (number > UINT32_MAX) goto invalid;
                }
                if (!lower && !digit) goto invalid;
                max = digit ? (uint32_t)number : UINT32_MAX;
                unbounded = !digit;
                yx_tr_repeat_space(p);
            } else if (!lower) goto invalid;
            if (p->at == p->length || p->text[p->at++] != '}' || max < min) goto invalid;
        }
        if (c == '{') yx_tr_skip_space(p);
        bool suffix = p->at < p->length && p->text[p->at] == '?';
        bool greedy = p->ungreedy ? suffix : !suffix;
        if (suffix) ++p->at;
        /* YARA-X's validator and its `greedy` flag read the quantifier's own
         * suffix, not the effect of the U flag. */
        if (suffix) p->saw_lazy = true;
        else p->saw_greedy = true;
        yx_tr_skip_space(p);
        bool zero_width = yx_tr_zero_width(node);
        if (max == 0 || (!min && zero_width)) {
            yx_tr_destroy(node);
            node = yx_tr_new(p, YX_TR_EMPTY);
            if (!node) return NULL;
            continue;
        }
        if ((min == 1 && max == 1) || zero_width) continue;
        yx_tr_node *parent = yx_tr_new(p, YX_TR_REPEAT);
        if (!yx_tr_child(p, parent, node)) {
            yx_tr_destroy(parent);
            goto invalid;
        }
        parent->minimum = min;
        parent->maximum = max;
        parent->greedy = greedy;
        parent->finite_maximum = max == UINT32_MAX && !unbounded;
        node = parent;
    }
    node->start = atom_start;
    node->end = p->at;
    return node;
invalid:
    p->failed = true;
    yx_tr_destroy(node);
    return NULL;
}
/* The byte of a literal atom at `at` that yx_tr_atom would turn into a
 * one-byte LITERAL node without a quantifier (a plain byte, an escaped
 * ASCII punctuation character, \n-style escapes or \xHH), and the atom's
 * width. Anything else, including a following quantifier, returns false. */
static bool yx_tr_plain_literal(const yx_tr_parser *p, size_t at, uint8_t *value, size_t *width)
{
    unsigned c = p->text[at], v;
    size_t n = 1;
    if (c == '\\') {
        if (at + 1 >= p->length) return false;
        unsigned e = p->text[at + 1];
        n = 2;
        if (e == 'x') {
            if (p->length - at < 4) return false;
            v = 0;
            for (size_t i = 2; i < 4; ++i) {
                unsigned d = p->text[at + i];
                if (d >= '0' && d <= '9') d -= '0';
                else if (d >= 'a' && d <= 'f') d = d - 'a' + 10;
                else if (d >= 'A' && d <= 'F') d = d - 'A' + 10;
                else return false;
                v = v * 16 + d;
            }
            n = 4;
        } else if (e == 'n') v = '\n';
        else if (e == 'r') v = '\r';
        else if (e == 't') v = '\t';
        else if (e == 'f') v = '\f';
        else if (e == 'v') v = '\v';
        else if (e == 'a') v = 7;
        else if (e >= 128 || isalnum((int)e)) return false;
        else v = e;
    } else {
        if (c == '(' || c == ')' || c == '|' || c == '[' || c == '.' || c == '^' || c == '$' || c == '*' || c == '+' || c == '?' || c == '{' || c == '}' ||
            (c >= 0xc2 && c <= 0xf4))
            return false;
        v = c;
    }
    if (p->nocase && v < 128 && isalpha((int)v)) return false;
    if (at + n < p->length) {
        unsigned next = p->text[at + n];
        if (!next || next == '*' || next == '+' || next == '?' || next == '{') return false;
    }
    *value = (uint8_t)v;
    *width = n;
    return true;
}
static yx_tr_node *yx_tr_concat(yx_tr_parser *p)
{
    yx_tr_node *node = yx_tr_new(p, YX_TR_CONCAT);
    if (!node) return NULL;
    /* Runs of plain literal bytes are appended in one step: the same tree
     * yx_tr_atom and yx_tr_join_child build one byte at a time. Scopes
     * with extended, Unicode or condition syntax keep the general path. */
    bool fast = !p->extended && !p->unicode && !p->condition_only;
    for (;;) {
        yx_tr_skip_space(p);
        if (p->at == p->length || p->text[p->at] == ')' || p->text[p->at] == '|') break;
        uint8_t value;
        size_t width;
        if (fast && !p->unicode && !p->extended && p->depth <= 250 && yx_tr_plain_literal(p, p->at, &value, &width)) {
            /* Measure the run, then decode it into the literal's buffer. */
            size_t used = 1, at = p->at + width;
            while (at < p->length && yx_tr_plain_literal(p, at, &value, &width)) {
                ++used;
                at += width;
            }
            yx_tr_node *previous = node->count ? node->children[node->count - 1] : NULL, *child = NULL;
            if (!previous || previous->kind != YX_TR_LITERAL) {
                child = yx_tr_new(p, YX_TR_LITERAL);
                if (!child) {
                    yx_tr_destroy(node);
                    return NULL;
                }
                previous = child;
            }
            uint8_t *bytes = realloc(previous->bytes, previous->length + used);
            if (!bytes) {
                p->oom = true;
                yx_tr_destroy(child);
                yx_tr_destroy(node);
                return NULL;
            }
            previous->bytes = bytes;
            for (size_t i = 0; i < used; ++i) {
                yx_tr_plain_literal(p, p->at, &bytes[previous->length++], &width);
                p->at += width;
            }
            if (child && !yx_tr_child(p, node, child)) {
                yx_tr_destroy(child);
                yx_tr_destroy(node);
                return NULL;
            }
            continue;
        }
        yx_tr_node *child = yx_tr_atom(p);
        if (!child) {
            yx_tr_destroy(node);
            return NULL;
        }
        if (child->kind == YX_TR_EMPTY) {
            yx_tr_destroy(child);
            continue;
        }
        if (!yx_tr_join_child(p, node, child)) {
            yx_tr_destroy(child);
            yx_tr_destroy(node);
            return NULL;
        }
    }
    return yx_tr_finish_concat(node);
}
/* regex-syntax merges an alternation of scalar literals into one Unicode
 * class. For separated singleton ranges its UTF-8 instruction sequence is
 * the same N-way split, but atoms start at the class entry, not a branch. */
static bool yx_tr_unicode_literal_class(yx_tr_node *parent)
{
    bool nonascii = false;
    for (size_t i = 0; i < parent->count; ++i) {
        yx_tr_node *a = parent->children[i];
        uint32_t ca;
        if (a->kind != YX_TR_LITERAL || !yx_hh_single_char(a->bytes, a->length, &ca)) return false;
        if (ca >= 128) nonascii = true;
        for (size_t j = 0; j < i; ++j) {
            yx_tr_node *b = parent->children[j];
            uint32_t cb;
            if (!yx_hh_single_char(b->bytes, b->length, &cb) || ca == cb || ca + 1 == cb || cb + 1 == ca) return false;
        }
    }
    if (!nonascii || parent->count < 2) return false;
    for (size_t i = 0; i < parent->count; ++i)
        for (size_t j = i + 1; j < parent->count; ++j) {
            yx_tr_node *a = parent->children[i], *b = parent->children[j];
            uint32_t ca, cb;
            if (!yx_hh_single_char(a->bytes, a->length, &ca) || !yx_hh_single_char(b->bytes, b->length, &cb)) return false;
            if (cb < ca) {
                parent->children[i] = b;
                parent->children[j] = a;
            }
        }
    return true;
}
static int yx_tr_range_cmp(const void *x, const void *y)
{
    const yx_re_range *a = x, *b = y;
    return a->first < b->first ? -1 : a->first > b->first;
}
/* Hir::alternation: an alternation of scalar literals (singleton_chars) with
 * a non-ASCII one, or of classes with a Unicode one (class_chars), is one
 * Unicode class (regex-syntax issue #1088 makes this happen without the u
 * flag too). The caller merges the byte forms. NULL when neither applies. */
static yx_tr_node *yx_tr_unicode_alternation(yx_tr_parser *p, const yx_tr_node *parent)
{
    bool scalars = true, classes = true, unicode = false, joined = false;
    size_t total = 0, count = 0;
    for (size_t i = 0; i < parent->count; ++i) {
        const yx_tr_node *child = parent->children[i];
        uint32_t cp;
        if (child->kind == YX_TR_LITERAL && yx_hh_single_char(child->bytes, child->length, &cp)) {
            classes = false;
            unicode |= cp >= 0x80;
            total += 1;
        } else if (child->kind == YX_TR_SCALAR_CLASS) {
            const yx_re_range *own = (const yx_re_range *)child->bytes;
            /* A range across the surrogate gap stays one in the union. */
            for (size_t k = 0; !child->gap_split && k + 1 < child->length; ++k)
                if (own[k].last == 0xd7ff && own[k + 1].first == 0xe000) joined = true;
            scalars = false;
            unicode = true;
            total += child->length;
        } else if (child->kind == YX_TR_CLASS) {
            /* ClassBytes::to_unicode_class: ASCII byte classes only. */
            scalars = false;
            total += 64;
            for (unsigned b = 128; b < 256; ++b)
                if (yx_tr_has(child->bitmap, b)) classes = false;
        } else scalars = classes = false;
    }
    if (!unicode || (!scalars && !classes)) return NULL;
    yx_re_range *ranges = malloc(total * sizeof(*ranges));
    if (!ranges) {
        p->oom = true;
        return NULL;
    }
    for (size_t i = 0; i < parent->count; ++i) {
        const yx_tr_node *child = parent->children[i];
        uint32_t cp;
        if (child->kind == YX_TR_LITERAL && yx_hh_single_char(child->bytes, child->length, &cp)) ranges[count++] = (yx_re_range){cp, cp};
        else if (child->kind == YX_TR_SCALAR_CLASS) {
            memcpy(ranges + count, child->bytes, child->length * sizeof(*ranges));
            count += child->length;
        } else
            for (unsigned b = 0; b < 128; ++b)
                if (yx_tr_has(child->bitmap, b)) {
                    unsigned first = b;
                    while (b + 1 < 128 && yx_tr_has(child->bitmap, b + 1)) ++b;
                    ranges[count++] = (yx_re_range){first, b};
                }
    }
    qsort(ranges, count, sizeof(*ranges), yx_tr_range_cmp);
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        if (used && ranges[i].first <= ranges[used - 1].last + 1) {
            if (ranges[i].last > ranges[used - 1].last) ranges[used - 1].last = ranges[i].last;
        } else ranges[used++] = ranges[i];
    }
    yx_tr_node *node;
    if (used == 1 && ranges[0].first == ranges[0].last) {
        node = yx_tr_scalar_literal(p, ranges[0].first);
        free(ranges);
    } else if ((node = yx_tr_new(p, YX_TR_SCALAR_CLASS)) != NULL) {
        node->bytes = (uint8_t *)ranges;
        node->length = used;
        for (size_t k = 0; !joined && k + 1 < used; ++k)
            if (ranges[k].last == 0xd7ff && ranges[k + 1].first == 0xe000) node->gap_split = true;
    } else free(ranges);
    return node;
}
static yx_tr_node *yx_tr_finish_alternation(yx_tr_parser *p, yx_tr_node *parent)
{
    yx_tr_node *node;
    bool literals = true, classes = true, ascii = true;
    for (size_t i = 0; i < parent->count; ++i) {
        yx_tr_node *child = parent->children[i];
        if (child->kind != YX_TR_CLASS) classes = false;
        if (child->kind != YX_TR_LITERAL || child->length != 1) literals = false;
        if (child->kind == YX_TR_LITERAL && child->length == 1 && child->bytes[0] >= 128) ascii = false;
        if (child->kind == YX_TR_CLASS)
            for (unsigned b = 128; b < 256; ++b)
                if (yx_tr_has(child->bitmap, b)) ascii = false;
    }
    if (literals || classes) {
        node = yx_tr_new(p, YX_TR_CLASS);
        if (node) node->unicode_class = ascii;
        if (node)
            for (size_t i = 0; i < parent->count; ++i) {
                yx_tr_node *child = parent->children[i];
                if (child->kind == YX_TR_LITERAL) yx_tr_set(node->bitmap, child->bytes[0]);
                else
                    for (size_t b = 0; b < 32; ++b) node->bitmap[b] |= child->bitmap[b];
            }
        yx_tr_destroy(parent);
        /* Hir::class turns a one-byte class into a literal. */
        unsigned members = 0, member = 0;
        for (unsigned b = 0; node && b < 256; ++b)
            if (yx_tr_has(node->bitmap, b)) {
                ++members;
                member = b;
            }
        if (node && members == 1) {
            uint8_t *bytes = malloc(1);
            if (!bytes) {
                p->oom = true;
                yx_tr_destroy(node);
                return NULL;
            }
            bytes[0] = (uint8_t)member;
            memset(node->bitmap, 0, sizeof(node->bitmap));
            node->kind = YX_TR_LITERAL;
            node->bytes = bytes;
            node->length = 1;
            node->unicode_class = false;
        }
        return node;
    }
    /* Condition regexps keep their search program's literal branches. */
    if (!p->condition_only && !p->literal_alternations) {
        node = yx_tr_unicode_alternation(p, parent);
        if (node || p->oom) {
            yx_tr_destroy(parent);
            return node;
        }
    }
    if (yx_tr_unicode_literal_class(parent)) parent->unicode_class = true;
    size_t prefix = parent->count && parent->children[0]->kind == YX_TR_CONCAT ? parent->children[0]->count : 0;
    for (size_t i = 1; prefix && i < parent->count; ++i) {
        yx_tr_node *branch = parent->children[i];
        if (branch->kind != YX_TR_CONCAT) {
            prefix = 0;
            break;
        }
        if (prefix > branch->count) prefix = branch->count;
        size_t j = 0;
        while (j < prefix && yx_tr_equal(parent->children[0]->children[j], branch->children[j])) ++j;
        prefix = j;
    }
    if (prefix) {
        yx_tr_node *joined = yx_tr_new(p, YX_TR_CONCAT);
        if (!joined) {
            yx_tr_destroy(parent);
            return NULL;
        }
        for (size_t i = 0; i < parent->count; ++i) {
            yx_tr_node *branch = parent->children[i];
            for (size_t j = 0; j < prefix; ++j) {
                yx_tr_node *child = branch->children[j];
                branch->children[j] = NULL;
                if (i) yx_tr_destroy(child);
                else if (!yx_tr_join_child(p, joined, child)) {
                    yx_tr_destroy(child);
                    yx_tr_destroy(joined);
                    yx_tr_destroy(parent);
                    return NULL;
                }
            }
            branch->count -= prefix;
            memmove(branch->children, branch->children + prefix, branch->count * sizeof(*branch->children));
            parent->children[i] = yx_tr_finish_concat(branch);
        }
        parent = yx_tr_finish_alternation(p, parent);
        if (!parent || !yx_tr_join_child(p, joined, parent)) {
            yx_tr_destroy(parent);
            yx_tr_destroy(joined);
            return NULL;
        }
        return yx_tr_finish_concat(joined);
    }
    return parent;
}
static yx_tr_node *yx_tr_expression(yx_tr_parser *p)
{
    yx_tr_node *node = yx_tr_concat(p);
    if (!node || p->at == p->length || p->text[p->at] != '|') return node;
    yx_tr_node *parent = yx_tr_new(p, YX_TR_ALT);
    if (!parent || !yx_tr_join_child(p, parent, node)) {
        yx_tr_destroy(node);
        yx_tr_destroy(parent);
        return NULL;
    }
    while (p->at < p->length && p->text[p->at] == '|') {
        ++p->at;
        node = yx_tr_concat(p);
        if (!node || !yx_tr_join_child(p, parent, node)) {
            yx_tr_destroy(node);
            yx_tr_destroy(parent);
            return NULL;
        }
    }
    return yx_tr_finish_alternation(p, parent);
}

typedef struct {
    uint8_t bytes[4], length;
    bool exact;
    size_t forward, backward;
} yx_tr_atom_entry;
typedef struct {
    yx_tr_atom_entry *items;
    size_t count;
    bool infinite;
} yx_tr_atoms;
static void yx_tr_atoms_free(yx_tr_atoms *a)
{
    free(a->items);
    *a = (yx_tr_atoms){0};
}
static bool yx_tr_atoms_add(yx_tr_atoms *a, yx_tr_atom_entry item)
{
    if (a->count >= 16384) {
        a->infinite = true;
        return true;
    }
    yx_tr_atom_entry *items = realloc(a->items, (a->count + 1) * sizeof(*items));
    if (!items) return false;
    a->items = items;
    a->items[a->count++] = item;
    return true;
}
/* Each byte's score: 6 for 0, 12 for 32, 0x90, 0xcc and 255, 18 for an
 * ASCII letter and 20 for any other byte. */
static const uint8_t yx_tr_byte_score[256] = {
    6,  20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 12, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 20, 20, 20, 20, 20, 20, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 12, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 12, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 12,
};
static int yx_tr_quality_bytes(const uint8_t *bytes, size_t length)
{
    if (!length) return INT_MIN;
    int score = 0, unique = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned b = bytes[i];
        size_t j = 0;
        score += yx_tr_byte_score[b];
        while (j < i && bytes[j] != b) ++j;
        if (j == i) ++unique;
    }
    if (unique == 1) {
        unsigned b = bytes[0];
        score += b == 0 || b == 32 || b == 0x90 || b == 0xcc || b == 255 ? -5 : 2;
    } else score += 2 * unique;
    return score;
}
static int yx_tr_quality(const yx_tr_atom_entry *a)
{
    return yx_tr_quality_bytes(a->bytes, a->length);
}
/* Atom selection of the YARA-X v1.21.0 Thompson compiler. yx_sq models
 * regex_syntax::hir::literal::Seq, yx_ex_* its prefix Extractor configured
 * as re::thompson::Compiler::new does, and yx_aq the AtomsQuality order.
 * Candidates are recorded as events in visiting order and folded at the
 * end with the compiler's best_atoms_stack semantics. */
/* concat_seq crosses up to fourteen multi-literal sequences before it
 * truncates, so literals are kept up to YX_SQ_BYTES bytes. */
#define YX_SQ_BYTES 72
typedef struct {
    uint8_t bytes[YX_SQ_BYTES];
    uint8_t length;
    bool exact;
} yx_sq_lit;
typedef struct {
    yx_sq_lit *items;
    size_t count, capacity;
    bool infinite;
} yx_sq;
enum {
    YX_SQ_LIMIT_TOTAL = 16384,
    YX_SQ_LITERAL_LEN = 4,
    YX_SQ_REPEAT = 4,
    YX_SQ_CLASS = 256
};
/* The literal buffers of sequences are recycled per thread: one compilation
 * builds and drops many sequences of thousands of literals, and blocks of
 * that size come from the heap's locked large-block path, freshly committed
 * each time. yx_sq_buffer gives a buffer of at least count literals with
 * unspecified contents (*capacity is its size in literals) and
 * yx_sq_buffer_release takes one back; only the memory's origin changes. */
enum {
    YX_SQ_POOL_SLOTS = 8,
    YX_SQ_POOL_MINIMUM = 64,
    YX_SQ_POOL_MAXIMUM = 32768
};
typedef struct {
    void *items[YX_SQ_POOL_SLOTS];
    size_t capacity[YX_SQ_POOL_SLOTS];
} yx_sq_pool;
static yx_thread_storage yx_sq_pool_storage = YX_THREAD_STORAGE_INIT;
static void yx_sq_pool_destroy(void *opaque)
{
    yx_sq_pool *pool = opaque;
    for (size_t i = 0; i < YX_SQ_POOL_SLOTS; ++i) free(pool->items[i]);
}
static yx_sq_pool *yx_sq_pool_get(void)
{
    static _Thread_local yx_sq_pool *thread_pool;
    if (!thread_pool) thread_pool = yx_thread_storage_get(&yx_sq_pool_storage, sizeof(*thread_pool), yx_sq_pool_destroy);
    return thread_pool;
}
static void *yx_sq_buffer(size_t count, size_t size, size_t *capacity)
{
    if (count >= YX_SQ_POOL_MINIMUM && count <= YX_SQ_POOL_MAXIMUM) {
        yx_sq_pool *pool = yx_sq_pool_get();
        size_t best = YX_SQ_POOL_SLOTS;
        /* The smallest kept buffer that is large enough. */
        for (size_t i = 0; pool && i < YX_SQ_POOL_SLOTS; ++i)
            if (pool->items[i] && pool->capacity[i] >= count && (best == YX_SQ_POOL_SLOTS || pool->capacity[i] < pool->capacity[best])) best = i;
        if (best != YX_SQ_POOL_SLOTS) {
            void *items = pool->items[best];
            *capacity = pool->capacity[best];
            pool->items[best] = NULL;
            pool->capacity[best] = 0;
            return items;
        }
    }
    if (count > SIZE_MAX / size) return NULL;
    *capacity = count;
    return malloc(count * size);
}
static void yx_sq_buffer_release(void *items, size_t capacity)
{
    if (items && capacity >= YX_SQ_POOL_MINIMUM && capacity <= YX_SQ_POOL_MAXIMUM) {
        yx_sq_pool *pool = yx_sq_pool_get();
        size_t smallest = 0;
        for (size_t i = 0; pool && i < YX_SQ_POOL_SLOTS; ++i) {
            if (!pool->items[i]) {
                pool->items[i] = items;
                pool->capacity[i] = capacity;
                return;
            }
            if (pool->capacity[i] < pool->capacity[smallest]) smallest = i;
        }
        /* A full pool keeps its larger buffers. */
        if (pool && pool->capacity[smallest] < capacity) {
            void *dropped = pool->items[smallest];
            pool->items[smallest] = items;
            pool->capacity[smallest] = capacity;
            items = dropped;
        }
    }
    free(items);
}
static void yx_sq_free(yx_sq *s)
{
    yx_sq_buffer_release(s->items, s->capacity);
    *s = (yx_sq){0};
}
static void yx_sq_make_infinite(yx_sq *s)
{
    yx_sq_free(s);
    s->infinite = true;
}
/* Nothing reads a literal's bytes past its length, so copies and
 * comparisons take only those (literals are mostly one to four bytes). */
static void yx_sq_lit_copy(yx_sq_lit *to, const yx_sq_lit *from)
{
    to->length = from->length;
    to->exact = from->exact;
    for (size_t i = 0; i < from->length; ++i) to->bytes[i] = from->bytes[i];
}
static bool yx_sq_same_bytes(const yx_sq_lit *a, const yx_sq_lit *b)
{
    if (a->length != b->length) return false;
    for (size_t i = 0; i < a->length; ++i)
        if (a->bytes[i] != b->bytes[i]) return false;
    return true;
}
static bool yx_sq_raw_push(yx_sq *s, const yx_sq_lit *lit)
{
    if (s->count == s->capacity) {
        size_t next = s->capacity ? s->capacity * 2 : 4, capacity;
        yx_sq_lit *items;
        if (next < YX_SQ_POOL_MINIMUM) {
            items = realloc(s->items, next * sizeof(*items));
            if (!items) return false;
            capacity = next;
        } else {
            items = yx_sq_buffer(next, sizeof(*items), &capacity);
            if (!items) return false;
            if (s->count) memcpy(items, s->items, s->count * sizeof(*items));
            yx_sq_buffer_release(s->items, s->capacity);
        }
        s->items = items;
        s->capacity = capacity;
    }
    yx_sq_lit_copy(&s->items[s->count++], lit);
    return true;
}
static bool yx_sq_lit_equal(const yx_sq_lit *a, const yx_sq_lit *b)
{
    return a->exact == b->exact && yx_sq_same_bytes(a, b);
}
static bool yx_sq_push(yx_sq *s, const yx_sq_lit *lit)
{
    if (s->infinite) return true;
    if (s->count && yx_sq_lit_equal(&s->items[s->count - 1], lit)) return true;
    return yx_sq_raw_push(s, lit);
}
static bool yx_sq_singleton_empty(yx_sq *s)
{
    yx_sq_lit empty = {.exact = true};
    *s = (yx_sq){0};
    return yx_sq_raw_push(s, &empty);
}
static void yx_sq_make_inexact(yx_sq *s)
{
    for (size_t i = 0; i < s->count; ++i) s->items[i].exact = false;
}
static void yx_sq_dedup(yx_sq *s)
{
    size_t used = 0;
    for (size_t i = 0; i < s->count; ++i) {
        yx_sq_lit *kept = used ? &s->items[used - 1] : NULL;
        if (kept && yx_sq_same_bytes(kept, &s->items[i])) {
            if (kept->exact != s->items[i].exact) kept->exact = false;
            continue;
        }
        /* Until the first duplicate every item stays where it is. */
        if (used != i) yx_sq_lit_copy(&s->items[used], &s->items[i]);
        ++used;
    }
    s->count = used;
}
static void yx_sq_keep_first(yx_sq *s, size_t length)
{
    for (size_t i = 0; i < s->count; ++i)
        if (length < s->items[i].length) {
            s->items[i].exact = false;
            s->items[i].length = (uint8_t)length;
        }
}
static bool yx_sq_is_inexact(const yx_sq *s)
{
    if (s->infinite) return true;
    for (size_t i = 0; i < s->count; ++i)
        if (s->items[i].exact) return false;
    return true;
}
/* min_literal_len / max_literal_len: false for None. */
static bool yx_sq_min_len(const yx_sq *s, size_t *length)
{
    if (s->infinite || !s->count) return false;
    *length = SIZE_MAX;
    for (size_t i = 0; i < s->count; ++i)
        if (s->items[i].length < *length) *length = s->items[i].length;
    return true;
}
static bool yx_sq_max_len(const yx_sq *s, size_t *length)
{
    if (s->infinite || !s->count) return false;
    *length = 0;
    for (size_t i = 0; i < s->count; ++i)
        if (s->items[i].length > *length) *length = s->items[i].length;
    return true;
}
static bool yx_sq_copy(yx_sq *to, const yx_sq *from)
{
    *to = (yx_sq){.infinite = from->infinite};
    if (!from->count) return true;
    to->items = yx_sq_buffer(from->count, sizeof(*to->items), &to->capacity);
    if (!to->items) {
        to->capacity = 0;
        return false;
    }
    memcpy(to->items, from->items, from->count * sizeof(*to->items));
    to->count = from->count;
    return true;
}
static size_t yx_sq_mul(size_t a, size_t b)
{
    return a && b > SIZE_MAX / a ? SIZE_MAX : a * b;
}
/* Seq::cross_forward, reading other only. */
static bool yx_sq_cross_from(yx_sq *self, const yx_sq *other)
{
    size_t minimum;
    if (other->infinite) {
        if (yx_sq_min_len(self, &minimum) && minimum == 0) yx_sq_make_infinite(self);
        else yx_sq_make_inexact(self);
        return true;
    }
    if (self->infinite) return true;
    yx_sq result = {0};
    /* The product is known up front; only the bytes in use are copied. */
    size_t total = 0;
    for (size_t i = 0; i < self->count; ++i) total += self->items[i].exact ? other->count : 1;
    if (total) {
        result.items = yx_sq_buffer(total, sizeof(*result.items), &result.capacity);
        if (!result.items) return false;
    }
    /* The product, deduplicated as it is built: each literal is merged into
     * the last one kept when their bytes are equal, as yx_sq_dedup's single
     * left-to-right pass over the whole product would merge it. */
    for (size_t i = 0; i < self->count; ++i) {
        const yx_sq_lit *a = &self->items[i];
        if (!a->exact) {
            yx_sq_lit *kept = result.count ? &result.items[result.count - 1] : NULL;
            if (kept && yx_sq_same_bytes(kept, a)) {
                if (kept->exact != a->exact) kept->exact = false;
            } else yx_sq_lit_copy(&result.items[result.count++], a);
            continue;
        }
        for (size_t j = 0; j < other->count; ++j) {
            const yx_sq_lit *b = &other->items[j];
            yx_sq_lit *lit = &result.items[result.count];
            size_t take = b->length;
            if (take > (size_t)YX_SQ_BYTES - a->length) goto fail;
            lit->length = (uint8_t)(a->length + take);
            lit->exact = b->exact;
            for (size_t k = 0; k < a->length; ++k) lit->bytes[k] = a->bytes[k];
            for (size_t k = 0; k < take; ++k) lit->bytes[a->length + k] = b->bytes[k];
            yx_sq_lit *kept = result.count ? &result.items[result.count - 1] : NULL;
            if (kept && yx_sq_same_bytes(kept, lit)) {
                if (kept->exact != lit->exact) kept->exact = false;
            } else ++result.count;
        }
    }
    yx_sq_free(self);
    *self = result;
    return true;
fail:
    yx_sq_free(&result);
    return false;
}
/* Seq::cross_forward; other is drained (an infinite other is left as is). */
static bool yx_sq_cross_forward(yx_sq *self, yx_sq *other)
{
    if (other->infinite) return yx_sq_cross_from(self, other);
    if (!yx_sq_cross_from(self, other)) return false;
    yx_sq_free(other);
    return true;
}
/* Seq::union; other is drained. */
static bool yx_sq_union(yx_sq *self, yx_sq *other)
{
    if (other->infinite) {
        yx_sq_make_infinite(self);
        return true;
    }
    if (self->infinite) {
        yx_sq_free(other);
        return true;
    }
    for (size_t i = 0; i < other->count; ++i)
        if (!yx_sq_raw_push(self, &other->items[i])) return false;
    yx_sq_free(other);
    yx_sq_dedup(self);
    return true;
}
static bool yx_ex_cross(yx_sq *self, yx_sq *other)
{
    if (!self->infinite && !other->infinite && yx_sq_mul(self->count, other->count) > YX_SQ_LIMIT_TOTAL) yx_sq_make_infinite(other);
    if (!yx_sq_cross_forward(self, other)) return false;
    yx_sq_keep_first(self, YX_SQ_LITERAL_LEN);
    return true;
}
static bool yx_ex_union(yx_sq *self, yx_sq *other)
{
    if (!self->infinite && !other->infinite && self->count + other->count > YX_SQ_LIMIT_TOTAL) {
        yx_sq_keep_first(self, 4);
        yx_sq_keep_first(other, 4);
        yx_sq_dedup(self);
        yx_sq_dedup(other);
        if (self->count + other->count > YX_SQ_LIMIT_TOTAL) yx_sq_make_infinite(other);
    }
    return yx_sq_union(self, other);
}
static bool yx_ex_extract(const yx_tr_node *node, yx_sq *out, size_t depth)
{
    *out = (yx_sq){0};
    if (depth > 250) return false;
    switch (node->kind) {
        case YX_TR_EMPTY:
        case YX_TR_LOOK: return yx_sq_singleton_empty(out);
        case YX_TR_LITERAL: {
            yx_sq_lit lit = {.exact = true};
            lit.length = (uint8_t)(node->length < YX_SQ_LITERAL_LEN ? node->length : YX_SQ_LITERAL_LEN);
            memcpy(lit.bytes, node->bytes, lit.length);
            if (node->length > lit.length) lit.exact = false;
            if (!yx_sq_raw_push(out, &lit)) return false;
            yx_sq_keep_first(out, YX_SQ_LITERAL_LEN);
            return true;
        }
        case YX_TR_SCALAR_CLASS: {
            const yx_re_range *ranges = (const yx_re_range *)node->bytes;
            uint64_t count = 0;
            for (size_t i = 0; i < node->length; ++i) {
                count += ranges[i].last - ranges[i].first + 1;
                /* ClassUnicodeRange::len of a range across the surrogate gap. */
                if (!node->gap_split && i + 1 < node->length && ranges[i].last == 0xd7ff && ranges[i + 1].first == 0xe000) count += 0x800;
            }
            if (count > YX_SQ_CLASS) {
                yx_sq_make_infinite(out);
                return true;
            }
            for (size_t i = 0; i < node->length; ++i)
                for (uint32_t cp = ranges[i].first; cp <= ranges[i].last; ++cp) {
                    yx_sq_lit lit = {.exact = true};
                    if (cp < 0x80) {
                        lit.bytes[0] = (uint8_t)cp;
                        lit.length = 1;
                    } else if (cp < 0x800) {
                        lit.bytes[0] = (uint8_t)(0xc0 | (cp >> 6));
                        lit.bytes[1] = (uint8_t)(0x80 | (cp & 63));
                        lit.length = 2;
                    } else if (cp < 0x10000) {
                        lit.bytes[0] = (uint8_t)(0xe0 | (cp >> 12));
                        lit.bytes[1] = (uint8_t)(0x80 | ((cp >> 6) & 63));
                        lit.bytes[2] = (uint8_t)(0x80 | (cp & 63));
                        lit.length = 3;
                    } else {
                        lit.bytes[0] = (uint8_t)(0xf0 | (cp >> 18));
                        lit.bytes[1] = (uint8_t)(0x80 | ((cp >> 12) & 63));
                        lit.bytes[2] = (uint8_t)(0x80 | ((cp >> 6) & 63));
                        lit.bytes[3] = (uint8_t)(0x80 | (cp & 63));
                        lit.length = 4;
                    }
                    if (!yx_sq_push(out, &lit)) {
                        yx_sq_free(out);
                        return false;
                    }
                }
            return true;
        }
        case YX_TR_CLASS:
            for (unsigned b = 0; b < 256; ++b)
                if (yx_tr_has(node->bitmap, b)) {
                    yx_sq_lit lit = {.bytes = {(uint8_t)b}, .length = 1, .exact = true};
                    if (!yx_sq_push(out, &lit)) {
                        yx_sq_free(out);
                        return false;
                    }
                }
            return true;
        case YX_TR_CAPTURE: return yx_ex_extract(node->children[0], out, depth + 1);
        case YX_TR_CONCAT:
            if (!yx_sq_singleton_empty(out)) return false;
            for (size_t i = 0; i < node->count; ++i) {
                yx_sq child;
                if (yx_sq_is_inexact(out)) break;
                if (!yx_ex_extract(node->children[i], &child, depth + 1) || !yx_ex_cross(out, &child)) {
                    yx_sq_free(&child);
                    yx_sq_free(out);
                    return false;
                }
            }
            return true;
        case YX_TR_ALT:
            for (size_t i = 0; i < node->count; ++i) {
                yx_sq child;
                if (out->infinite) break;
                if (!yx_ex_extract(node->children[i], &child, depth + 1) || !yx_ex_union(out, &child)) {
                    yx_sq_free(&child);
                    yx_sq_free(out);
                    return false;
                }
            }
            return true;
        case YX_TR_REPEAT: {
            yx_sq sub, seq;
            if (!yx_ex_extract(node->children[0], &sub, depth + 1)) return false;
            if (node->minimum == 0) {
                yx_sq empty;
                if (yx_tr_unbounded(node) || node->maximum != 1) yx_sq_make_inexact(&sub);
                if (!yx_sq_singleton_empty(&empty)) {
                    yx_sq_free(&sub);
                    return false;
                }
                if (!node->greedy) {
                    yx_sq swap = sub;
                    sub = empty;
                    empty = swap;
                }
                if (!yx_ex_union(&sub, &empty)) {
                    yx_sq_free(&sub);
                    yx_sq_free(&empty);
                    return false;
                }
                *out = sub;
                return true;
            }
            if (!yx_sq_singleton_empty(&seq)) {
                yx_sq_free(&sub);
                return false;
            }
            uint32_t times = node->minimum < YX_SQ_REPEAT ? node->minimum : YX_SQ_REPEAT;
            for (uint32_t i = 0; i < times; ++i) {
                yx_sq copy;
                if (yx_sq_is_inexact(&seq)) break;
                if (!yx_sq_copy(&copy, &sub) || !yx_ex_cross(&seq, &copy)) {
                    yx_sq_free(&copy);
                    yx_sq_free(&seq);
                    yx_sq_free(&sub);
                    return false;
                }
            }
            bool fixed = !yx_tr_unbounded(node) && node->minimum == node->maximum;
            if (!fixed || node->minimum > YX_SQ_REPEAT) yx_sq_make_inexact(&seq);
            yx_sq_free(&sub);
            *out = seq;
            return true;
        }
        default: return false;
    }
}
/* optimize_seq. Literals are grouped by their prefix without the last
 * byte; a group seen with all 256 final bytes collapses into one inexact
 * prefix at the position of its first literal. */
static uint64_t yx_sq_prefix_hash(const yx_sq_lit *lit)
{
    uint64_t hash = 1469598103934665603ull ^ lit->length;
    for (size_t i = 0; i + 1u < lit->length; ++i) hash = (hash ^ lit->bytes[i]) * 1099511628211ull;
    return hash ^ (hash >> 29);
}
static bool yx_sq_optimize(yx_sq *seq)
{
    if (seq->infinite || seq->count <= 1) return true;
    /* A group collapses only when all 256 final bytes occur under one
     * prefix, which takes at least 256 literals. */
    if (seq->count < 256) {
        yx_sq_dedup(seq);
        return true;
    }
    {
        /* A full group needs all 256 final bytes among the literals of one
         * length; without such a length no group collapses. (Per-thread
         * scratch keeps the recursive compiler's frames small.) */
        static _Thread_local uint8_t finals[YX_SQ_BYTES + 1][32];
        bool possible = false;
        memset(finals, 0, sizeof(finals));
        for (size_t i = 0; i < seq->count; ++i) {
            const yx_sq_lit *lit = &seq->items[i];
            if (lit->length) yx_tr_set(finals[lit->length], lit->bytes[lit->length - 1]);
        }
        for (size_t length = 1; length <= YX_SQ_BYTES && !possible; ++length) {
            possible = true;
            for (size_t b = 0; b < 32 && possible; ++b) possible = finals[length][b] == 255;
        }
        if (!possible) {
            yx_sq_dedup(seq);
            return true;
        }
    }
    size_t *table = NULL, *group = malloc(seq->count * sizeof(*group));
    uint8_t(*bitmaps)[32] = NULL;
    bool *full = NULL, *pending = NULL, ok = false, any = false;
    size_t used = 0, groups = 0, slots = 16;
    if (!group) goto done;
    for (size_t i = 0; i < seq->count; ++i) {
        group[i] = SIZE_MAX;
        if (seq->items[i].length) ++used;
    }
    while (slots < used * 2) slots *= 2;
    table = malloc(slots * sizeof(*table));
    bitmaps = calloc(used ? used : 1, sizeof(*bitmaps));
    if (!table || !bitmaps) goto done;
    for (size_t i = 0; i < slots; ++i) table[i] = SIZE_MAX;
    /* Literals are grouped by length and by every byte but the last. */
    for (size_t i = 0; i < seq->count; ++i) {
        const yx_sq_lit *lit = &seq->items[i];
        if (!lit->length) continue;
        size_t slot = (size_t)yx_sq_prefix_hash(lit) & (slots - 1u);
        while (table[slot] != SIZE_MAX) {
            const yx_sq_lit *other = &seq->items[table[slot]];
            if (other->length == lit->length && !memcmp(other->bytes, lit->bytes, lit->length - 1u)) break;
            slot = (slot + 1u) & (slots - 1u);
        }
        if (table[slot] == SIZE_MAX) {
            table[slot] = i;
            group[i] = groups++;
        } else group[i] = group[table[slot]];
        yx_tr_set(bitmaps[group[i]], lit->bytes[lit->length - 1]);
    }
    full = calloc(groups ? groups : 1, sizeof(*full));
    pending = calloc(groups ? groups : 1, sizeof(*pending));
    if (!full || !pending) goto done;
    for (size_t g = 0; g < groups; ++g) {
        full[g] = pending[g] = true;
        for (size_t b = 0; b < 32; ++b)
            if (bitmaps[g][b] != 255) full[g] = pending[g] = false;
        any |= full[g];
    }
    if (!any) {
        yx_sq_dedup(seq);
        ok = true;
        goto done;
    }
    yx_sq result = {0};
    for (size_t i = 0; i < seq->count; ++i) {
        const yx_sq_lit *lit = &seq->items[i];
        if (group[i] != SIZE_MAX && full[group[i]]) {
            if (pending[group[i]]) {
                yx_sq_lit prefix = *lit;
                prefix.length = (uint8_t)(lit->length - 1u);
                prefix.exact = false;
                pending[group[i]] = false;
                if (!yx_sq_push(&result, &prefix)) {
                    yx_sq_free(&result);
                    goto done;
                }
            }
        } else if (!yx_sq_push(&result, lit)) {
            yx_sq_free(&result);
            goto done;
        }
    }
    yx_sq_free(seq);
    *seq = result;
    yx_sq_dedup(seq);
    ok = true;
done:
    free(table);
    free(group);
    free(bitmaps);
    free(full);
    free(pending);
    return ok;
}
static int yx_sq_lit_cmp(const void *x, const void *y)
{
    const yx_sq_lit *a = x, *b = y;
    size_t n = a->length < b->length ? a->length : b->length;
    int order = memcmp(a->bytes, b->bytes, n);
    if (order) return order;
    if (a->length != b->length) return a->length < b->length ? -1 : 1;
    return (int)a->exact - (int)b->exact;
}
/* The yx_sq_lit_cmp order of a literal of at most seven bytes as one
 * integer: the bytes zero-padded (a shorter literal sorts first among equal
 * padded bytes, exactly as memcmp over the common length followed by the
 * length comparison orders them), then the length, then exact. */
static uint64_t yx_sq_lit_key(const yx_sq_lit *lit)
{
    uint64_t key = 0;
    for (size_t i = 0; i < lit->length; ++i) key |= (uint64_t)lit->bytes[i] << (56 - 8 * i);
    return key | ((uint64_t)lit->length << 1) | (lit->exact ? 1u : 0u);
}
/* Sorts seq->items in yx_sq_lit_cmp order. Literals that compare equal are
 * identical in their visible bytes, length and exact flag, so any correct
 * sort gives the same sequence as qsort. Short literals are sorted as
 * integer keys with a radix sort; longer ones keep the qsort path. */
static void yx_sq_sort(yx_sq *seq)
{
    size_t n = seq->count;
    if (n < 2) return;
    bool short_literals = true, sorted = true;
    for (size_t i = 0; i < n && short_literals; ++i) short_literals = seq->items[i].length <= 7;
    if (short_literals) {
        uint64_t *keys = malloc(2 * n * sizeof(*keys));
        if (keys) {
            uint64_t *tmp = keys + n;
            for (size_t i = 0; i < n; ++i) {
                keys[i] = yx_sq_lit_key(&seq->items[i]);
                if (i && keys[i - 1] > keys[i]) sorted = false;
            }
            if (sorted) {
                free(keys);
                return;
            }
            if (n <= 24) {
                for (size_t i = 1; i < n; ++i) {
                    uint64_t k = keys[i];
                    size_t j = i;
                    while (j && keys[j - 1] > k) {
                        keys[j] = keys[j - 1];
                        --j;
                    }
                    keys[j] = k;
                }
            } else {
                /* LSD radix sort over the byte digits that differ. */
                size_t(*counts)[256] = calloc(8, sizeof(*counts));
                if (!counts) {
                    free(keys);
                    goto fallback;
                }
                for (size_t i = 0; i < n; ++i)
                    for (unsigned d = 0; d < 8; ++d) ++counts[d][(keys[i] >> (8 * d)) & 255];
                for (unsigned d = 0; d < 8; ++d) {
                    size_t *c = counts[d], total = 0;
                    if (c[(keys[0] >> (8 * d)) & 255] == n) continue;
                    for (unsigned b = 0; b < 256; ++b) {
                        size_t v = c[b];
                        c[b] = total;
                        total += v;
                    }
                    for (size_t i = 0; i < n; ++i) tmp[c[(keys[i] >> (8 * d)) & 255]++] = keys[i];
                    uint64_t *swap = keys;
                    keys = tmp;
                    tmp = swap;
                }
                free(counts);
                if (keys > tmp) {
                    memcpy(tmp, keys, n * sizeof(*keys));
                    keys = tmp;
                }
            }
            for (size_t i = 0; i < n; ++i) {
                yx_sq_lit *lit = &seq->items[i];
                uint64_t k = keys[i];
                lit->length = (uint8_t)((k >> 1) & 7u);
                lit->exact = (k & 1u) != 0;
                for (size_t b = 0; b < 7; ++b) lit->bytes[b] = (uint8_t)(k >> (56 - 8 * b));
            }
            free(keys);
            return;
        }
    }
fallback:
    qsort(seq->items, n, sizeof(*seq->items), yx_sq_lit_cmp);
}
/* seq_to_atoms: false with *none for an infinite sequence. */
static bool yx_sq_to_atoms(yx_sq *seq, bool *none)
{
    *none = false;
    if (!yx_sq_optimize(seq)) return false;
    if (seq->infinite) {
        *none = true;
        return true;
    }
    yx_sq_sort(seq);
    size_t used = 0;
    for (size_t i = 0; i < seq->count; ++i)
        if (!used || !yx_sq_lit_equal(&seq->items[used - 1], &seq->items[i])) {
            if (used != i) yx_sq_lit_copy(&seq->items[used], &seq->items[i]);
            ++used;
        }
    seq->count = used;
    if (used > 1) {
        bool *remove = calloc(used, sizeof(*remove)), *inexact = calloc(used, sizeof(*inexact));
        if (!remove || !inexact) {
            free(remove);
            free(inexact);
            return false;
        }
        for (size_t i = 0; i + 1 < used; ++i) {
            const yx_sq_lit *a = &seq->items[i], *b = &seq->items[i + 1];
            bool prefix = b->length >= a->length;
            for (size_t k = 0; prefix && k < a->length; ++k) prefix = a->bytes[k] == b->bytes[k];
            if (prefix && a->length == b->length) remove[i + 1] = true;
            else if (prefix) {
                inexact[i] = true;
                remove[i + 1] = true;
            }
        }
        size_t kept = 0;
        for (size_t i = 0; i < used; ++i) {
            if (inexact[i]) seq->items[i].exact = false;
            if (!remove[i]) {
                if (kept != i) yx_sq_lit_copy(&seq->items[kept], &seq->items[i]);
                ++kept;
            }
        }
        seq->count = kept;
        free(remove);
        free(inexact);
    }
    return true;
}
/* concat_seq over seqs[0..count]: false with *none when it yields None. */
static bool yx_sq_concat(const yx_sq *seqs, size_t count, yx_sq *out, bool *none)
{
    size_t length;
    *none = true;
    *out = (yx_sq){0};
    if (!count || seqs[0].infinite) return true;
    if (seqs[0].count == 256 && yx_sq_max_len(&seqs[0], &length) && length == 1) return true;
    size_t considered = count;
    while (considered && yx_sq_min_len(&seqs[considered - 1], &length) && length == 0) --considered;
    size_t added = 0, total = 0;
    if (!yx_sq_singleton_empty(out)) return false;
    for (size_t i = 0; i < considered; ++i) {
        size_t minimum;
        if (!yx_sq_min_len(&seqs[i], &minimum)) break;
        if (out->infinite || yx_sq_mul(out->count, seqs[i].count) > YX_SQ_LIMIT_TOTAL) break;
        if (!yx_sq_cross_from(out, &seqs[i])) {
            yx_sq_free(out);
            return false;
        }
        ++added;
        total += minimum;
        if (total >= 4 || yx_sq_is_inexact(out)) break;
    }
    if (added < count) yx_sq_make_inexact(out);
    yx_sq_keep_first(out, 4);
    if (!yx_sq_optimize(out)) {
        yx_sq_free(out);
        return false;
    }
    *none = out->infinite;
    if (*none) yx_sq_free(out);
    return true;
}
typedef struct {
    size_t exact, inexact, min_length;
    int min_quality;
    int64_t sum;
} yx_aq;
static yx_aq yx_aq_min(void)
{
    return (yx_aq){0, 0, 0, INT_MIN, INT64_MIN};
}
static int64_t yx_aq_add(int64_t a, int64_t b)
{
    if (b > 0 && a > INT64_MAX - b) return INT64_MAX;
    if (b < 0 && a < INT64_MIN - b) return INT64_MIN;
    return a + b;
}
static size_t yx_aq_count_add(size_t a, size_t b)
{
    return a > SIZE_MAX - b ? SIZE_MAX : a + b;
}
static int yx_tr_quality(const yx_tr_atom_entry *a);
/* atom_quality: the best four-byte window, or the whole of a shorter
 * literal. */
static int yx_aq_bytes_quality(const uint8_t *bytes, size_t length)
{
    int best = INT_MIN;
    if (length < 4) return yx_tr_quality_bytes(bytes, length);
    for (size_t at = 0; at + 4 <= length; ++at) {
        int quality = yx_tr_quality_bytes(bytes + at, 4);
        if (quality > best) best = quality;
    }
    return best;
}
static yx_aq yx_aq_of(const yx_sq_lit *lits, size_t count)
{
    yx_aq q = {0, 0, SIZE_MAX, INT_MAX, 0};
    for (size_t i = 0; i < count; ++i) {
        int quality = yx_aq_bytes_quality(lits[i].bytes, lits[i].length);
        if (lits[i].exact) ++q.exact;
        else ++q.inexact;
        q.sum = yx_aq_add(q.sum, quality);
        if (quality < q.min_quality) q.min_quality = quality;
        if (lits[i].length < q.min_length) q.min_length = lits[i].length;
    }
    return q;
}
static void yx_aq_merge(yx_aq *a, const yx_aq *b)
{
    a->exact = yx_aq_count_add(a->exact, b->exact);
    a->inexact = yx_aq_count_add(a->inexact, b->inexact);
    a->sum = yx_aq_add(a->sum, b->sum);
    if (b->min_length < a->min_length) a->min_length = b->min_length;
    if (b->min_quality < a->min_quality) a->min_quality = b->min_quality;
}
static size_t yx_aq_atoms(const yx_aq *q)
{
    return yx_aq_count_add(q->exact, q->inexact);
}
static double yx_aq_avg(const yx_aq *q)
{
    return (double)q->sum / (double)(q->exact + q->inexact);
}
static int64_t yx_aq_total_key(double value)
{
    int64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    bits ^= (int64_t)(((uint64_t)(bits >> 63)) >> 1);
    return bits;
}
/* Ord for AtomsQuality. */
static int yx_aq_cmp(const yx_aq *a, const yx_aq *b)
{
    size_t diff = a->min_length > b->min_length ? a->min_length - b->min_length : b->min_length - a->min_length;
    if (diff == 1) {
        size_t na = yx_aq_atoms(a), nb = yx_aq_atoms(b);
        if (na > 0 && yx_sq_mul(na, 256) == nb && yx_aq_avg(a) * 2.0 >= yx_aq_avg(b)) return 1;
        if (nb > 0 && yx_sq_mul(nb, 256) == na && yx_aq_avg(b) * 2.0 >= yx_aq_avg(a)) return -1;
    }
    if (a->min_quality != b->min_quality) return a->min_quality < b->min_quality ? -1 : 1;
    if (a->min_length != b->min_length) return a->min_length < b->min_length ? -1 : 1;
    double qa = yx_aq_avg(a), qb = yx_aq_avg(b);
    if (fabs(qa - qb) > 15.0) {
        int64_t ka = yx_aq_total_key(qa), kb = yx_aq_total_key(qb);
        return ka < kb ? -1 : ka > kb ? 1 : 0;
    }
    if (a->inexact != b->inexact) return b->inexact < a->inexact ? -1 : 1;
    return b->exact < a->exact ? -1 : b->exact > a->exact ? 1 : 0;
}
enum {
    YX_TR_EV_CANDIDATE,
    YX_TR_EV_ALT_BEGIN,
    YX_TR_EV_ALT_NEXT,
    YX_TR_EV_ALT_END
};
typedef struct {
    unsigned kind;
    size_t alternatives;
    yx_tr_atom_entry *atoms;
    size_t count;
} yx_tr_event;
typedef struct {
    yx_tr_event *items;
    size_t count, capacity;
} yx_tr_events;
static void yx_tr_events_free(yx_tr_events *e)
{
    for (size_t i = 0; i < e->count; ++i) free(e->items[i].atoms);
    free(e->items);
    *e = (yx_tr_events){0};
}
static bool yx_tr_events_push(yx_tr_events *e, yx_tr_event event)
{
    if (e->count == e->capacity) {
        size_t next = e->capacity ? e->capacity * 2 : 8;
        yx_tr_event *items = realloc(e->items, next * sizeof(*items));
        if (!items) {
            free(event.atoms);
            return false;
        }
        e->items = items;
        e->capacity = next;
    }
    e->items[e->count++] = event;
    return true;
}
static bool yx_tr_events_marker(yx_tr_events *e, unsigned kind, size_t alternatives)
{
    return yx_tr_events_push(e, (yx_tr_event){.kind = kind, .alternatives = alternatives});
}
/* Moves the events of a child program, shifting its code locations. */
static bool yx_tr_events_take(yx_tr_events *to, yx_tr_events *from, size_t forward, size_t backward)
{
    for (size_t i = 0; i < from->count; ++i) {
        yx_tr_event event = from->items[i];
        for (size_t a = 0; a < event.count; ++a) {
            event.atoms[a].forward += forward;
            event.atoms[a].backward += backward;
        }
        from->items[i].atoms = NULL;
        if (!yx_tr_events_push(to, event)) {
            for (size_t j = i + 1; j < from->count; ++j) {
                free(from->items[j].atoms);
                from->items[j].atoms = NULL;
            }
            return false;
        }
    }
    free(from->items);
    *from = (yx_tr_events){0};
    return true;
}
static void yx_tr_events_shift(yx_tr_events *e, size_t forward, size_t backward)
{
    for (size_t i = 0; i < e->count; ++i)
        for (size_t a = 0; a < e->items[i].count; ++a) {
            e->items[i].atoms[a].forward += forward;
            e->items[i].atoms[a].backward += backward;
        }
}
static void yx_tr_events_shift_backward(yx_tr_events *e, size_t adjustment)
{
    for (size_t i = 0; i < e->count; ++i)
        for (size_t a = 0; a < e->items[i].count; ++a) e->items[i].atoms[a].backward += adjustment;
}
static int yx_tr_entry_cmp(const void *x, const void *y)
{
    const yx_tr_atom_entry *a = x, *b = y;
    size_t n = a->length < b->length ? a->length : b->length;
    int order = memcmp(a->bytes, b->bytes, n);
    if (order) return order;
    if (a->length != b->length) return a->length < b->length ? -1 : 1;
    return (int)a->exact - (int)b->exact;
}
/* The candidate of one HIR node: atoms from a sequence (or a literal's best
 * atom), made inexact below the top level or under look-around. */
static bool yx_tr_candidate(yx_tr_events *e, const yx_sq_lit *lits, size_t count, size_t forward, size_t backward, bool can_be_exact)
{
    if (!count) return true;
    yx_tr_atom_entry *atoms = calloc(count, sizeof(*atoms));
    if (!atoms) return false;
    for (size_t i = 0; i < count; ++i) {
        if (lits[i].length > 4) {
            free(atoms);
            return false;
        }
        memcpy(atoms[i].bytes, lits[i].bytes, lits[i].length);
        atoms[i].length = lits[i].length;
        atoms[i].exact = lits[i].exact && can_be_exact;
        atoms[i].forward = forward;
        atoms[i].backward = backward;
    }
    /* Sequences come from yx_sq_to_atoms, sorted and free of duplicates:
     * skip the sort when the inexact entries are already strictly ordered
     * (sorting would leave them as they are and remove nothing). */
    bool sorted = true;
    for (size_t i = 1; sorted && !can_be_exact && i < count; ++i) sorted = yx_tr_entry_cmp(&atoms[i - 1], &atoms[i]) < 0;
    if (!can_be_exact && count > 1 && !sorted) {
        qsort(atoms, count, sizeof(*atoms), yx_tr_entry_cmp);
        size_t used = 0;
        for (size_t i = 0; i < count; ++i)
            if (!used || yx_tr_entry_cmp(&atoms[used - 1], &atoms[i])) atoms[used++] = atoms[i];
        count = used;
    }
    return yx_tr_events_push(e, (yx_tr_event){.kind = YX_TR_EV_CANDIDATE, .atoms = atoms, .count = count});
}
static yx_aq yx_tr_entries_quality(const yx_tr_atom_entry *atoms, size_t count)
{
    yx_aq q = {0, 0, SIZE_MAX, INT_MAX, 0};
    for (size_t i = 0; i < count; ++i) {
        int quality = yx_tr_quality(&atoms[i]);
        if (atoms[i].exact) ++q.exact;
        else ++q.inexact;
        q.sum = yx_aq_add(q.sum, quality);
        if (quality < q.min_quality) q.min_quality = quality;
        if (atoms[i].length < q.min_length) q.min_length = atoms[i].length;
    }
    return q;
}
/* best_atoms_stack over the recorded events. */
static bool yx_tr_fold_events(yx_tr_events *e, yx_tr_atoms *result)
{
    typedef struct {
        yx_tr_atom_entry *atoms;
        size_t count;
        yx_aq quality;
    } yx_tr_best;
    yx_tr_best *stack = malloc(sizeof(*stack));
    size_t depth = 1, capacity = 1;
    bool ok = false;
    if (!stack) return false;
    stack[0] = (yx_tr_best){NULL, 0, yx_aq_min()};
    for (size_t i = 0; i < e->count; ++i) {
        yx_tr_event *event = &e->items[i];
        if (event->kind == YX_TR_EV_CANDIDATE) {
            yx_aq q = yx_tr_entries_quality(event->atoms, event->count);
            yx_tr_best *top = &stack[depth - 1];
            if (yx_aq_cmp(&q, &top->quality) > 0) {
                free(top->atoms);
                *top = (yx_tr_best){event->atoms, event->count, q};
                event->atoms = NULL;
                event->count = 0;
            }
        } else if (event->kind == YX_TR_EV_ALT_BEGIN || event->kind == YX_TR_EV_ALT_NEXT) {
            if (depth == capacity) {
                yx_tr_best *grown = realloc(stack, capacity * 2 * sizeof(*grown));
                if (!grown) goto done;
                stack = grown;
                capacity *= 2;
            }
            stack[depth++] = (yx_tr_best){NULL, 0, yx_aq_min()};
        } else {
            size_t n = event->alternatives, first = depth - n, total = 0;
            if (!n || n >= depth) goto done;
            yx_aq merged = stack[first].quality;
            for (size_t j = first; j < depth; ++j) {
                if (j > first) yx_aq_merge(&merged, &stack[j].quality);
                total += stack[j].count;
            }
            yx_tr_best *top = &stack[first - 1];
            if (total <= YX_SQ_LIMIT_TOTAL && yx_aq_cmp(&top->quality, &merged) < 0) {
                yx_tr_atom_entry *atoms = calloc(total ? total : 1, sizeof(*atoms));
                if (!atoms) goto done;
                size_t at = 0;
                for (size_t j = first; j < depth; ++j) {
                    if (stack[j].count) memcpy(atoms + at, stack[j].atoms, stack[j].count * sizeof(*atoms));
                    at += stack[j].count;
                }
                free(top->atoms);
                *top = (yx_tr_best){atoms, total, merged};
            }
            for (size_t j = first; j < depth; ++j) free(stack[j].atoms);
            depth = first;
        }
    }
    if (depth != 1) goto done;
    *result = (yx_tr_atoms){0};
    result->items = stack[0].atoms;
    result->count = stack[0].count;
    stack[0].atoms = NULL;
    ok = true;
done:
    for (size_t j = 0; j < depth; ++j) free(stack[j].atoms);
    free(stack);
    return ok;
}

typedef struct {
    yx_writer forward, backward;
    yx_tr_atoms atoms;
    yx_tr_events events;
} yx_tr_program;
static void yx_tr_program_free(yx_tr_program *p)
{
    free(p->forward.data);
    free(p->backward.data);
    yx_tr_atoms_free(&p->atoms);
    yx_tr_events_free(&p->events);
    memset(p, 0, sizeof(*p));
}
static bool yx_tr_u32(yx_writer *w, uint32_t value)
{
    uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    return yx_put_bytes(w, bytes, 4);
}
static bool yx_tr_instr(yx_writer *w, unsigned op, unsigned id, unsigned alternatives)
{
    if (!yx_put_u8(w, 0xaa) || !yx_put_u8(w, (uint8_t)op)) return false;
    if (op >= 1 && op <= 3) {
        if (id >= 8192 || !yx_put_u8(w, (uint8_t)id) || !yx_put_u8(w, (uint8_t)(id >> 8))) return false;
        if (op == 3 && (alternatives > 255 || !yx_put_u8(w, (uint8_t)alternatives))) return false;
    }
    if (op >= 1 && op <= 4)
        for (size_t i = 0; i < (op == 3 ? alternatives : 1); ++i)
            if (!yx_tr_u32(w, 0)) return false;
    return true;
}
static bool yx_tr_pair(yx_tr_program *p, unsigned op, unsigned *split, unsigned n)
{
    unsigned id = *split;
    if (op >= 1 && op <= 3) ++*split;
    return yx_tr_instr(&p->forward, op, id, n) && yx_tr_instr(&p->backward, op, id, n);
}
static bool yx_tr_patch(yx_writer *w, size_t at, size_t field, size_t target)
{
    if (target > INT32_MAX || at > INT32_MAX || at + field + 4 > w->used) return false;
    uint32_t delta = (uint32_t)((int64_t)target - (int64_t)at);
    for (size_t i = 0; i < 4; ++i) w->data[at + field + i] = (uint8_t)(delta >> (8 * i));
    return true;
}
static size_t yx_tr_instruction_size(const uint8_t *code, size_t size)
{
    if (!size) return 0;
    if (code[0] != 0xaa) return 1;
    if (size < 2) return 0;
    unsigned op = code[1];
    size_t n;
    if (op == 0xaa) n = 2;
    else if (op == 1 || op == 2) n = 8;
    else if (op == 3) {
        if (size < 5) return 0;
        n = 5 + 4 * code[4];
    } else if (op == 4) n = 6;
    else if (op == 6) n = 4;
    else if (op == 7) n = 3;
    else if (op == 8) n = 34;
    else if (op == 9) {
        if (size < 3) return 0;
        n = 3 + 2 * code[2];
    } else if (op == 16 || op == 17) n = 14;
    else if (op <= 19) n = 2;
    else return 0;
    return n <= size ? n : 0;
}
static bool yx_tr_clone_one(yx_writer *to, const yx_writer *from, unsigned start, unsigned *next)
{
    size_t base = to->used;
    if (!yx_put_bytes(to, from->data, from->used)) return false;
    for (size_t at = 0; at < from->used;) {
        size_t n = yx_tr_instruction_size(from->data + at, from->used - at);
        if (!n) return false;
        if (from->data[at] == 0xaa && from->data[at + 1] >= 1 && from->data[at + 1] <= 3) {
            if (start >= 8192) return false;
            to->data[base + at + 2] = (uint8_t)start;
            to->data[base + at + 3] = (uint8_t)(start++ >> 8);
        }
        at += n;
    }
    *next = start;
    return true;
}
static bool yx_tr_clone(yx_tr_program *to, const yx_tr_program *from, unsigned *split)
{
    unsigned next_f, next_b;
    if (!yx_tr_clone_one(&to->forward, &from->forward, *split, &next_f) || !yx_tr_clone_one(&to->backward, &from->backward, *split, &next_b) || next_f != next_b)
        return false;
    *split = next_f;
    return true;
}
static bool yx_tr_class_code(yx_writer *w, const uint8_t bitmap[32], bool unicode_class)
{
    unsigned low = 255, high = 0, count = 0, ranges = 0;
    for (unsigned b = 0; b < 256; ++b)
        if (yx_tr_has(bitmap, b)) {
            low &= b;
            high |= b;
            ++count;
            if (!b || !yx_tr_has(bitmap, b - 1)) ++ranges;
        }
    if (count == 256) return yx_tr_instr(w, 5, 0, 0);
    uint8_t mask = (uint8_t)~(low ^ high);
    unsigned combinations = 1;
    for (unsigned bit = 1; bit <= 128; bit <<= 1)
        if (!(mask & bit)) combinations *= 2;
    if (!unicode_class && count && count == combinations) return yx_tr_instr(w, 6, 0, 0) && yx_put_u8(w, (uint8_t)low) && yx_put_u8(w, mask);
    if (ranges >= 4) return yx_tr_instr(w, 8, 0, 0) && yx_put_bytes(w, bitmap, 32);
    if (!yx_tr_instr(w, 9, 0, 0) || !yx_put_u8(w, (uint8_t)ranges)) return false;
    for (unsigned b = 0; b < 256; ++b)
        if (yx_tr_has(bitmap, b)) {
            unsigned first = b;
            while (b < 255 && yx_tr_has(bitmap, b + 1)) ++b;
            if (!yx_put_u8(w, (uint8_t)first) || !yx_put_u8(w, (uint8_t)b)) return false;
        }
    return true;
}
#include "serialization_utf8.h"
/* During one compilation, the depth-0 extraction of a node that the generic
 * branch below compiled is kept until its parent compiles: a concatenation
 * extracts each of its children again with the same arguments, a pure
 * function of the child, and takes the kept sequence instead. Each node
 * drops what its subtree kept once it has read its children's sequences. */
typedef struct {
    const yx_tr_node *node;
    yx_sq seq;
} yx_ex_kept;
typedef struct {
    yx_ex_kept *items;
    size_t count, capacity;
} yx_ex_memo;
static _Thread_local yx_ex_memo *yx_ex_memo_active;
static size_t yx_ex_memo_mark(void)
{
    return yx_ex_memo_active ? yx_ex_memo_active->count : 0;
}
static void yx_ex_memo_truncate(size_t count)
{
    yx_ex_memo *memo = yx_ex_memo_active;
    while (memo && memo->count > count) yx_sq_free(&memo->items[--memo->count].seq);
}
static void yx_ex_memo_keep(const yx_tr_node *node, const yx_sq *seq)
{
    yx_ex_memo *memo = yx_ex_memo_active;
    if (!memo || seq->infinite || seq->count < 2) return;
    if (memo->count == memo->capacity) {
        size_t next = memo->capacity ? memo->capacity * 2 : 16;
        yx_ex_kept *items = realloc(memo->items, next * sizeof(*items));
        if (!items) return;
        memo->items = items;
        memo->capacity = next;
    }
    if (!yx_sq_copy(&memo->items[memo->count].seq, seq)) return;
    memo->items[memo->count++].node = node;
}
/* The first entry of node from *from on, taken. A taken entry keeps no node,
 * so it matches none: *from moves past the entries before it when all of
 * them are taken, and a concatenation, which takes its children's entries
 * in order, searches each child from the first entry not taken (a search
 * from its mark restarted at the first entry and made a flat concatenation
 * of n classes quadratic). Only the generic branch keeps entries, never for
 * a literal or a concatenation, so those find none at once. */
static bool yx_ex_memo_take(const yx_tr_node *node, size_t *from, yx_sq *out)
{
    yx_ex_memo *memo = yx_ex_memo_active;
    bool all_taken = true;
    if (node->kind == YX_TR_LITERAL || node->kind == YX_TR_CONCAT) return false;
    for (size_t i = *from; memo && i < memo->count; ++i) {
        if (memo->items[i].node == node) {
            *out = memo->items[i].seq;
            memo->items[i].seq = (yx_sq){0};
            memo->items[i].node = NULL;
            if (all_taken) *from = i + 1;
            return true;
        }
        if (memo->items[i].node) all_taken = false;
    }
    return false;
}
static bool yx_tr_compile_node(const yx_tr_node *node, yx_tr_program *out, unsigned *split, size_t depth, bool zero, bool counted)
{
    if (depth > 250) return false;
    size_t memo_mark = yx_ex_memo_mark();
    yx_tr_program *children = NULL;
    size_t *fstarts = NULL, *bends = NULL;
    size_t *split_f = NULL, *split_b = NULL;
    size_t start_f = 0, start_b = 0;
    bool ok = false;
    if (node->kind == YX_TR_LITERAL) {
        for (size_t i = 0; i < node->length; ++i) {
            uint8_t f = node->bytes[i], b = node->bytes[node->length - i - 1];
            if (!yx_put_u8(&out->forward, f) || (f == 0xaa && !yx_put_u8(&out->forward, f)) || !yx_put_u8(&out->backward, b) ||
                (b == 0xaa && !yx_put_u8(&out->backward, b)))
                goto done;
        }
    } else if (node->kind == YX_TR_SCALAR_CLASS) {
        /* A Unicode class of every scalar is any_byte, ANY_BYTE; others are
         * their UTF-8 sequences. */
        if (yx_u8_any(node)) {
            if (!yx_tr_instr(&out->forward, 5, 0, 0) || !yx_tr_instr(&out->backward, 5, 0, 0)) goto done;
        } else if (!yx_u8_class_code((const yx_re_range *)node->bytes, node->length, out, split)) goto done;
    } else if (node->kind == YX_TR_CLASS) {
        if (!yx_tr_class_code(&out->forward, node->bitmap, node->unicode_class) || !yx_tr_class_code(&out->backward, node->bitmap, node->unicode_class)) goto done;
    } else if (node->kind == YX_TR_LOOK) {
        if (!yx_tr_pair(out, node->look, split, 0)) goto done;
    } else if (node->count) {
        children = calloc(node->count, sizeof(*children));
        fstarts = calloc(node->count, sizeof(*fstarts));
        bends = calloc(node->count, sizeof(*bends));
        if (!children || !fstarts || !bends) goto done;
        bool repeat_counted = node->kind == YX_TR_REPEAT && !counted && !yx_tr_unbounded(node) && node->maximum > 10;
        bool prefix_split = node->kind == YX_TR_REPEAT && node->minimum == 0;
        if (node->kind == YX_TR_ALT) {
            if (!yx_tr_pair(out, 3, split, (unsigned)node->count)) goto done;
        } else if (prefix_split) {
            if (!yx_tr_pair(out, node->greedy ? 1 : 2, split, 0)) goto done;
        }
        start_f = out->forward.used;
        start_b = out->backward.used;
        for (size_t i = 0; i < node->count; ++i) {
            if (!yx_tr_compile_node(node->children[i], &children[i], split, depth + 1, zero || prefix_split, repeat_counted || counted)) goto done;
            fstarts[i] = out->forward.used;
            if (!yx_put_bytes(&out->forward, children[i].forward.data, children[i].forward.used)) goto done;
            if (node->kind != YX_TR_CONCAT) {
                size_t bstart = out->backward.used;
                if (!yx_put_bytes(&out->backward, children[i].backward.data, children[i].backward.used)) goto done;
                bends[i] = out->backward.used;
                yx_tr_events_shift(&children[i].events, fstarts[i], bstart);
            }
            if (node->kind == YX_TR_ALT && i + 1 < node->count)
                if (!yx_tr_pair(out, 4, split, 0)) goto done;
        }
        if (node->kind == YX_TR_CONCAT) {
            for (size_t i = node->count; i-- > 0;) {
                size_t bstart = out->backward.used;
                if (!yx_put_bytes(&out->backward, children[i].backward.data, children[i].backward.used)) goto done;
                bends[i] = out->backward.used;
                yx_tr_events_shift(&children[i].events, fstarts[i], bstart);
            }
        } else if (node->kind == YX_TR_ALT) {
            for (size_t i = 0; i < node->count; ++i) {
                size_t bstart = bends[i] - children[i].backward.used;
                if (!yx_tr_patch(&out->forward, 0, 5 + 4 * i, fstarts[i]) || !yx_tr_patch(&out->backward, 0, 5 + 4 * i, bstart)) goto done;
                if (i + 1 < node->count && (!yx_tr_patch(&out->forward, fstarts[i] + children[i].forward.used, 2, out->forward.used) ||
                                            !yx_tr_patch(&out->backward, bends[i], 2, out->backward.used)))
                    goto done;
            }
        } else if (node->kind == YX_TR_REPEAT) {
            const uint32_t min = node->minimum, max = node->maximum;
            yx_tr_program *child = &children[0];
            size_t adjustment = 0;
            if (yx_tr_unbounded(node) && min == 0) {
                size_t jf = out->forward.used, jb = out->backward.used;
                if (!yx_tr_pair(out, 4, split, 0) || !yx_tr_patch(&out->forward, 0, 4, out->forward.used) || !yx_tr_patch(&out->backward, 0, 4, out->backward.used) ||
                    !yx_tr_patch(&out->forward, jf, 2, 0) || !yx_tr_patch(&out->backward, jb, 2, 0))
                    goto done;
            } else if (yx_tr_unbounded(node)) {
                size_t lf = 0, lb = 0;
                for (uint32_t i = 1; i + 1 < min; ++i) {
                    lf = out->forward.used;
                    lb = out->backward.used;
                    if (!yx_tr_clone(out, child, split)) goto done;
                }
                size_t sf = out->forward.used, sb = out->backward.used;
                if (!yx_tr_pair(out, node->greedy ? 2 : 1, split, 0) || !yx_tr_patch(&out->forward, sf, 4, lf) || !yx_tr_patch(&out->backward, sb, 4, lb)) goto done;
                if (min > 1) {
                    if (!yx_tr_clone(out, child, split)) goto done;
                    adjustment = (min - 1) * child->backward.used + 8;
                }
            } else if (repeat_counted) {
                if (!min) {
                    size_t rf = out->forward.used, rb = out->backward.used;
                    if (!yx_tr_pair(out, node->greedy ? 16 : 17, split, 0) || !yx_tr_u32(&out->forward, 0) || !yx_tr_u32(&out->forward, 0) ||
                        !yx_tr_u32(&out->forward, max) || !yx_tr_u32(&out->backward, 0) || !yx_tr_u32(&out->backward, 0) || !yx_tr_u32(&out->backward, max) ||
                        !yx_tr_patch(&out->forward, rf, 2, start_f) || !yx_tr_patch(&out->backward, rb, 2, start_b) ||
                        !yx_tr_patch(&out->forward, 0, 4, out->forward.used) || !yx_tr_patch(&out->backward, 0, 4, out->backward.used))
                        goto done;
                } else {
                    yx_tr_program tail = {0};
                    if ((min == 1 && !yx_tr_pair(&tail, node->greedy ? 1 : 2, split, 0)) || !yx_tr_clone(&tail, child, split)) {
                        yx_tr_program_free(&tail);
                        goto done;
                    }
                    size_t rf = tail.forward.used, rb = tail.backward.used;
                    if (!yx_tr_pair(&tail, node->greedy ? 16 : 17, split, 0) || !yx_tr_u32(&tail.forward, 0) || !yx_tr_u32(&tail.forward, min - 1) ||
                        !yx_tr_u32(&tail.forward, max - 1) || !yx_tr_u32(&tail.backward, 0) || !yx_tr_u32(&tail.backward, min - 1) ||
                        !yx_tr_u32(&tail.backward, max - 1) || !yx_tr_patch(&tail.forward, rf, 2, min == 1 ? 8 : 0) ||
                        !yx_tr_patch(&tail.backward, rb, 2, min == 1 ? 8 : 0) ||
                        (min == 1 && (!yx_tr_patch(&tail.forward, 0, 4, tail.forward.used) || !yx_tr_patch(&tail.backward, 0, 4, tail.backward.used))) ||
                        !yx_put_bytes(&out->forward, tail.forward.data, tail.forward.used)) {
                        yx_tr_program_free(&tail);
                        goto done;
                    }
                    yx_writer reversed = {0};
                    if (!yx_put_bytes(&reversed, tail.backward.data, tail.backward.used) || !yx_put_bytes(&reversed, out->backward.data, out->backward.used)) {
                        free(reversed.data);
                        yx_tr_program_free(&tail);
                        goto done;
                    }
                    adjustment = tail.backward.used;
                    free(out->backward.data);
                    out->backward = reversed;
                    yx_tr_program_free(&tail);
                }
            } else {
                size_t splits = 0, capacity = max - min;
                if (capacity) {
                    split_f = calloc(capacity, sizeof(*split_f));
                    split_b = calloc(capacity, sizeof(*split_b));
                    if (!split_f || !split_b) goto done;
                }
                if (!min) {
                    split_f[splits] = 0;
                    split_b[splits++] = 0;
                }
                for (uint32_t i = 1; i < min; ++i)
                    if (!yx_tr_clone(out, child, split)) goto done;
                for (uint32_t i = min ? min : 1; i < max; ++i) {
                    split_f[splits] = out->forward.used;
                    split_b[splits++] = out->backward.used;
                    if (!yx_tr_pair(out, node->greedy ? 1 : 2, split, 0) || !yx_tr_clone(out, child, split)) goto done;
                }
                for (size_t i = 0; i < splits; ++i)
                    if (!yx_tr_patch(&out->forward, split_f[i], 4, out->forward.used) || !yx_tr_patch(&out->backward, split_b[i], 4, out->backward.used)) goto done;
                if (min > 1) adjustment = (min - 1) * child->backward.used;
            }
            yx_tr_events_shift_backward(&child->events, adjustment);
        }
        if (node->kind == YX_TR_ALT && node->unicode_class)
            for (size_t i = 0; i < node->count; ++i) yx_tr_events_free(&children[i].events);
        if (node->kind == YX_TR_ALT && !node->unicode_class && !yx_tr_events_marker(&out->events, YX_TR_EV_ALT_BEGIN, 0)) goto done;
        for (size_t i = 0; i < node->count; ++i) {
            if (node->kind == YX_TR_ALT && !node->unicode_class && i && !yx_tr_events_marker(&out->events, YX_TR_EV_ALT_NEXT, 0)) goto done;
            if (!yx_tr_events_take(&out->events, &children[i].events, 0, 0)) goto done;
        }
        if (node->kind == YX_TR_ALT && !node->unicode_class && !yx_tr_events_marker(&out->events, YX_TR_EV_ALT_END, node->count)) goto done;
    }
    if (zero || (node->kind == YX_TR_REPEAT && node->minimum == 0)) {
        ok = true;
        goto done;
    }
    bool can_be_exact = !depth && !node->has_look;
    if (node->kind == YX_TR_CONCAT) {
        /* The best concat_seq over each suffix of the children. */
        yx_sq *seqs = calloc(node->count, sizeof(*seqs)), best = {0};
        yx_aq best_quality = yx_aq_min();
        size_t best_at = 0, memo_from = memo_mark;
        bool seq_ok = seqs != NULL, have = false, none;
        for (size_t i = 0; seq_ok && i < node->count; ++i)
            seq_ok = yx_ex_memo_take(node->children[i], &memo_from, &seqs[i]) || yx_ex_extract(node->children[i], &seqs[i], 0);
        yx_ex_memo_truncate(memo_mark);
        for (size_t start = 0; seq_ok && start < node->count; ++start) {
            yx_sq seq;
            if (!yx_sq_concat(seqs + start, node->count - start, &seq, &none)) {
                seq_ok = false;
                break;
            }
            if (none) continue;
            if (start) yx_sq_make_inexact(&seq);
            yx_aq quality = yx_aq_of(seq.items, seq.count);
            if (yx_aq_cmp(&quality, &best_quality) > 0) {
                best_quality = quality;
                yx_sq_free(&best);
                best = seq;
                have = true;
                best_at = start;
            } else yx_sq_free(&seq);
        }
        if (seqs)
            for (size_t i = 0; i < node->count; ++i) yx_sq_free(&seqs[i]);
        free(seqs);
        if (seq_ok && have)
            seq_ok = yx_sq_to_atoms(&best, &none) && (none || yx_tr_candidate(&out->events, best.items, best.count, fstarts[best_at], bends[best_at], can_be_exact));
        yx_sq_free(&best);
        if (!seq_ok) goto done;
    } else if (node->kind == YX_TR_LITERAL) {
        size_t offset = 0, width = 0, forward = 0;
        if (!yx_best_text_atom(node->bytes, node->length, &offset, &width) || width > 4) goto done;
        yx_sq_lit lit = {.length = (uint8_t)width, .exact = width == node->length};
        memcpy(lit.bytes, node->bytes + offset, width);
        for (size_t i = 0; i < offset; ++i) forward += node->bytes[i] == 0xaa ? 2 : 1;
        if (!yx_tr_candidate(&out->events, &lit, 1, forward, out->backward.used - forward, can_be_exact)) goto done;
    } else {
        yx_sq seq;
        yx_ex_memo_truncate(memo_mark);
        bool none, seq_ok = yx_ex_extract(node, &seq, 0);
        if (seq_ok) yx_ex_memo_keep(node, &seq);
        seq_ok = seq_ok && yx_sq_to_atoms(&seq, &none) &&
                 (none || yx_tr_candidate(&out->events, seq.items, seq.count, node->kind == YX_TR_REPEAT ? start_f : 0, out->backward.used, can_be_exact));
        yx_sq_free(&seq);
        if (!seq_ok) goto done;
    }
    ok = true;
done:
    if (children)
        for (size_t i = 0; i < node->count; ++i) yx_tr_program_free(&children[i]);
    free(children);
    free(fstarts);
    free(bends);
    free(split_f);
    free(split_b);
    return ok;
}
static bool yx_tr_compile_uncached(const char *regexp, bool dotall, bool nocase, yx_tr_program *program, bool *greedy)
{
    yx_tr_parser parser = {.text = (const uint8_t *)regexp, .length = strlen(regexp), .dotall = dotall, .nocase = nocase};
    yx_tr_node *root = yx_tr_expression(&parser);
    unsigned split = 0;
    yx_ex_memo memo = {0}, *outer_memo = yx_ex_memo_active;
    yx_ex_memo_active = &memo;
    bool ok = root && !parser.failed && !parser.oom && parser.at == parser.length && yx_tr_compile_node(root, program, &split, 0, false, false);
    yx_ex_memo_truncate(0);
    free(memo.items);
    yx_ex_memo_active = outer_memo;
    if (ok) ok = yx_tr_fold_events(&program->events, &program->atoms);
    /* Only the folded atoms are used once the events are folded; dropping
     * them keeps cached programs small and their copies cheap. */
    yx_tr_events_free(&program->events);
    if (ok && !program->atoms.count) ok = yx_tr_atoms_add(&program->atoms, (yx_tr_atom_entry){.backward = program->backward.used});
    if (ok) ok = yx_tr_pair(program, 0, &split, 0);
    *greedy = parser.saw_greedy && !parser.saw_lazy;
    yx_tr_destroy(root);
    return ok;
}

/* A rule is compiled several times from the same source while it is loaded
 * (warning classifier, atom quality, program build, archive verification),
 * and the atom extraction dominates each of those. The result is a pure
 * function of (source, dotall, nocase), so each thread keeps its recent
 * successful compilations of small programs and hands out deep copies. */
enum {
    YX_TR_CACHE_SLOTS = 2048,
    YX_TR_CACHE_PROGRAM_LIMIT = 1u << 20,
    YX_TR_CACHE_BUDGET = 32u << 20
};
typedef struct {
    char *regexp;
    bool dotall, nocase, greedy;
    yx_tr_program program;
} yx_tr_cache_entry;
typedef struct {
    yx_tr_cache_entry slots[YX_TR_CACHE_SLOTS];
    size_t bytes;
} yx_tr_cache;
static yx_thread_storage yx_tr_cache_storage = YX_THREAD_STORAGE_INIT;
static void yx_tr_cache_destroy(void *opaque)
{
    yx_tr_cache *cache = opaque;
    for (size_t i = 0; i < YX_TR_CACHE_SLOTS; ++i) {
        free(cache->slots[i].regexp);
        yx_tr_program_free(&cache->slots[i].program);
    }
}
static size_t yx_tr_cache_hash(const char *regexp, bool dotall, bool nocase)
{
    uint64_t hash = 1469598103934665603ull ^ (dotall ? 1u : 0u) ^ (nocase ? 2u : 0u);
    for (const unsigned char *at = (const unsigned char *)regexp; *at; ++at) hash = (hash ^ *at) * 1099511628211ull;
    return (size_t)(hash ^ (hash >> 32));
}
static bool yx_tr_writer_copy(yx_writer *to, const yx_writer *from)
{
    *to = (yx_writer){0};
    if (!from->used) return true;
    to->data = malloc(from->used);
    if (!to->data) return false;
    memcpy(to->data, from->data, from->used);
    to->used = to->capacity = from->used;
    return true;
}
static bool yx_tr_program_copy(yx_tr_program *to, const yx_tr_program *from)
{
    *to = (yx_tr_program){0};
    if (!yx_tr_writer_copy(&to->forward, &from->forward) || !yx_tr_writer_copy(&to->backward, &from->backward)) goto failed;
    to->atoms.count = from->atoms.count;
    to->atoms.infinite = from->atoms.infinite;
    if (from->atoms.count) {
        to->atoms.items = malloc(from->atoms.count * sizeof(*to->atoms.items));
        if (!to->atoms.items) goto failed;
        memcpy(to->atoms.items, from->atoms.items, from->atoms.count * sizeof(*to->atoms.items));
    }
    if (from->events.count) {
        to->events.items = calloc(from->events.count, sizeof(*to->events.items));
        if (!to->events.items) goto failed;
        to->events.capacity = from->events.count;
        for (size_t i = 0; i < from->events.count; ++i) {
            const yx_tr_event *source = &from->events.items[i];
            yx_tr_event *target = &to->events.items[i];
            *target = *source;
            target->atoms = NULL;
            if (source->atoms && source->count) {
                target->atoms = malloc(source->count * sizeof(*target->atoms));
                if (!target->atoms) {
                    to->events.count = i + 1;
                    goto failed;
                }
                memcpy(target->atoms, source->atoms, source->count * sizeof(*target->atoms));
            }
            to->events.count = i + 1;
        }
    }
    return true;
failed:
    yx_tr_program_free(to);
    return false;
}
/* Cache size in bytes, or SIZE_MAX when the program is too large to keep. */
static size_t yx_tr_program_weight(const yx_tr_program *p)
{
    size_t weight = p->forward.used + p->backward.used + p->atoms.count * sizeof(yx_tr_atom_entry);
    for (size_t i = 0; i < p->events.count; ++i) weight += sizeof(yx_tr_event) + p->events.items[i].count * sizeof(yx_tr_atom_entry);
    return weight;
}
static bool yx_tr_compile(const char *regexp, bool dotall, bool nocase, yx_tr_program *program, bool *greedy)
{
    static _Thread_local yx_tr_cache *thread_cache;
    if (!thread_cache) thread_cache = yx_thread_storage_get(&yx_tr_cache_storage, sizeof(*thread_cache), yx_tr_cache_destroy);
    yx_tr_cache *cache = thread_cache;
    size_t hash = yx_tr_cache_hash(regexp, dotall, nocase), slot = hash & (YX_TR_CACHE_SLOTS - 1);
    if (cache)
        for (size_t probe = 0; probe < 8; ++probe, slot = (slot + 1) & (YX_TR_CACHE_SLOTS - 1)) {
            const yx_tr_cache_entry *entry = &cache->slots[slot];
            if (!entry->regexp) break;
            if (entry->dotall == dotall && entry->nocase == nocase && !strcmp(entry->regexp, regexp)) {
                if (!yx_tr_program_copy(program, &entry->program)) break;
                *greedy = entry->greedy;
                return true;
            }
        }
    if (!yx_tr_compile_uncached(regexp, dotall, nocase, program, greedy)) return false;
    size_t weight = cache ? yx_tr_program_weight(program) : 0;
    if (cache && weight <= YX_TR_CACHE_PROGRAM_LIMIT && cache->bytes + weight <= YX_TR_CACHE_BUDGET) {
        slot = hash & (YX_TR_CACHE_SLOTS - 1);
        for (size_t probe = 0; probe < 8; ++probe, slot = (slot + 1) & (YX_TR_CACHE_SLOTS - 1)) {
            yx_tr_cache_entry *entry = &cache->slots[slot];
            if (entry->regexp) continue;
            char *key = malloc(strlen(regexp) + 1);
            yx_tr_program stored;
            if (key && yx_tr_program_copy(&stored, program)) {
                memcpy(key, regexp, strlen(regexp) + 1);
                entry->regexp = key;
                entry->dotall = dotall;
                entry->nocase = nocase;
                entry->greedy = *greedy;
                entry->program = stored;
                cache->bytes += weight;
            } else free(key);
            break;
        }
    }
    return true;
}

static bool yx_se_masked_literal(const yx_tr_node *);
/* Complete atom warning classifier for scopes/properties outside the byte
 * serializer grammar. Its scalar AST is never used to build scanner code. */
int yx_re_slow_pattern(const unsigned char *body, size_t length, bool nocase, bool dotall, bool *slow, bool *extreme)
{
    if (!body || !slow || !extreme) return 0;
    /* Keep the established literal/class/FastVM warning decisions. This
     * fallback fills precisely the unsupported Unicode and named-boundary
     * parts of the byte serializer's grammar. */
    bool needed = false, forced_class_path = false, flag_wrapper = false;
    size_t class_depth = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = body[i];
        if (ch == '\\' && i + 1 < length) {
            if (!class_depth && body[i + 1] == 'b' && i + 2 < length && body[i + 2] == '{') needed = true;
            ++i;
            continue;
        }
        if (ch == '[') {
            size_t first = i + 1;
            if (first < length && body[first] == '^') ++first;
            if (class_depth || (first < length && body[first] == ']')) {
                needed = forced_class_path = true;
            }
            ++class_depth;
            continue;
        }
        if (ch == ']' && class_depth) {
            --class_depth;
            continue;
        }
        if (class_depth && i + 1 < length && strchr("&-~", ch) && body[i + 1] == ch) {
            needed = true;
            continue;
        }
        if (!class_depth && ch == '(' && i + 1 < length && body[i + 1] == '?') {
            for (size_t j = i + 2; j < length && strchr("imsxuUR-", body[j]); ++j) {
                if (body[j] == 'u' || body[j] == 'x') {
                    needed = flag_wrapper = true;
                    break;
                }
            }
        }
    }
    if (!needed) return 0;
    yx_tr_parser parser = {.text = body, .length = length, .nocase = nocase, .dotall = dotall, .warning_only = true};
    yx_tr_node *root = yx_tr_expression(&parser);
    const yx_tr_node *bare = root;
    size_t captures = 0;
    while (bare && bare->kind == YX_TR_CAPTURE && bare->count) {
        ++captures;
        bare = bare->children[0];
    }
    bool singleton_scalar = false;
    if (bare && bare->kind == YX_TR_SCALAR_CLASS && bare->length == 1) {
        const yx_re_range *range = (const yx_re_range *)bare->bytes;
        singleton_scalar = range->first == range->last;
    }
    bool pooled_literal = bare && ((bare->kind == YX_TR_LITERAL && (captures || (!forced_class_path && !flag_wrapper))) || (captures && singleton_scalar));
    bool pooled_mask = bare && bare->kind != YX_TR_LITERAL && !nocase && yx_se_masked_literal(root);
    if (bare && !parser.stacked && (pooled_literal || pooled_mask) && !parser.failed && !parser.oom && parser.at == parser.length) {
        /* A capture wrapper does not force the literal sub-pattern into
         * the regexp compiler. Even one-byte pooled literals are warning-free. */
        *slow = *extreme = false;
        yx_tr_destroy(root);
        return 1;
    }
    yx_tr_program program = {0};
    unsigned split = 0;
    bool ok = root && !parser.failed && !parser.oom && parser.at == parser.length && yx_tr_compile_node(root, &program, &split, 0, false, false) &&
              yx_tr_fold_events(&program.events, &program.atoms);
    if (ok) {
        size_t minimum = SIZE_MAX, maximum = 0;
        for (size_t i = 0; i < program.atoms.count; ++i) {
            size_t n = program.atoms.items[i].length;
            if (n < minimum) minimum = n;
            if (n > maximum) maximum = n;
        }
        *extreme = !program.atoms.count || minimum == 0;
        *slow = *extreme || minimum < 2 || (minimum == 2 && maximum == 2 && program.atoms.count > 2700);
    }
    yx_tr_destroy(root);
    yx_tr_program_free(&program);
    return ok ? 1 : 0;
}
static bool yx_tr_any_class(const yx_tr_node *node)
{
    if (node->kind != YX_TR_CLASS || node->unicode_class) return false;
    for (unsigned b = 0; b < 256; ++b)
        if (b != 10 && !yx_tr_has(node->bitmap, b)) return false;
    return true;
}
static bool yx_tr_needs_thompson(const yx_tr_node *node, bool in_alternation, bool in_repetition)
{
    if (node->kind == YX_TR_LOOK || node->unicode_class) return true;
    /* FastVM ignores a Unicode class only as the gap of a repetition. */
    if (node->kind == YX_TR_SCALAR_CLASS) return !in_repetition || !yx_tr_gap_class(node, NULL);
    if (node->kind == YX_TR_REPEAT && (in_alternation || in_repetition || !yx_tr_gap_class(node->children[0], NULL) || node->minimum > UINT16_MAX ||
                                       (!yx_tr_unbounded(node) && node->maximum > UINT16_MAX)))
        return true;
    if (node->kind == YX_TR_ALT) {
        if (in_alternation || in_repetition) return true;
        for (size_t i = 0; i < node->count; ++i)
            if (node->children[i]->kind == YX_TR_EMPTY) return true;
    }
    if (node->kind == YX_TR_CLASS) {
        if (in_repetition && yx_tr_any_class(node)) return false;
        unsigned first = 256, last = 0, count = 0;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(node->bitmap, b)) {
                if (first == 256) first = b;
                last = b;
                ++count;
            }
        unsigned combinations = 1;
        for (unsigned bit = 1; bit <= 128; bit <<= 1)
            if ((first ^ last) & bit) combinations *= 2;
        if (count != combinations) return true;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(node->bitmap, b) && (b & first) != first) return true;
    }
    for (size_t i = 0; i < node->count; ++i)
        if (yx_tr_needs_thompson(node->children[i], in_alternation || node->kind == YX_TR_ALT, in_repetition || node->kind == YX_TR_REPEAT)) return true;
    return false;
}
static bool yx_tr_failed_fast_sequence(const yx_tr_node *node, yx_writer *code)
{
    if (node->kind == YX_TR_CONCAT || node->kind == YX_TR_CAPTURE) {
        for (size_t i = 0; i < node->count; ++i)
            if (!yx_tr_failed_fast_sequence(node->children[i], code)) return false;
        return true;
    }
    bool newline;
    if (node->kind != YX_TR_REPEAT || !yx_tr_gap_class(node->children[0], &newline)) return false;
    bool fixed = !yx_tr_unbounded(node) && node->minimum == node->maximum;
    uint8_t op = (newline ? 3 : 5) + (fixed ? 0 : 1);
    return yx_put_u8(code, op) && yx_fast_u32(code, node->minimum) && (fixed || yx_fast_u32(code, yx_tr_unbounded(node) ? 0 : node->maximum));
}
static bool yx_tr_only_any_classes(const yx_tr_node *node)
{
    if (node->kind == YX_TR_CLASS) return yx_tr_any_class(node);
    if (node->kind != YX_TR_CONCAT && node->kind != YX_TR_CAPTURE && node->kind != YX_TR_REPEAT) return false;
    for (size_t i = 0; i < node->count; ++i)
        if (!yx_tr_only_any_classes(node->children[i])) return false;
    return node->count != 0;
}
static bool yx_tr_text(yx_writer *w, const char *text);
static bool yx_tr_hex_text(yx_writer *w, uint8_t byte);
static bool yx_tr_hex_regex(yx_writer *text, const yx_hex_atom *atoms, size_t count, size_t depth)
{
    if (depth > 250) return false;
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_atom *a = &atoms[i];
        if (a->kind == YX_HEX_BYTE) {
            if (a->mask == 255 && !a->negated) {
                if (!yx_tr_hex_text(text, a->value)) return false;
            } else {
                /* "[" + one \xHH per matching byte + "]", written at once
                 * (from a per-thread buffer: this function recurses). */
                static const char digits[] = "0123456789abcdef";
                static _Thread_local char list[2 + 256 * 4];
                size_t used = 0;
                list[used++] = '[';
                for (unsigned b = 0; b < 256; ++b) {
                    bool match = (b & a->mask) == (a->value & a->mask);
                    if (match == a->negated) continue;
                    list[used++] = '\\';
                    list[used++] = 'x';
                    list[used++] = digits[b >> 4];
                    list[used++] = digits[b & 15];
                }
                list[used++] = ']';
                if (!yx_put_bytes(text, list, used)) return false;
            }
        } else if (a->kind == YX_HEX_ALTERNATIVE) {
            if (!yx_tr_text(text, "(?:")) return false;
            for (size_t j = 0; j < a->branch_count; ++j)
                if ((j && !yx_tr_text(text, "|")) || !yx_tr_hex_regex(text, a->branches[j].atoms, a->branches[j].count, depth + 1)) return false;
            if (!yx_tr_text(text, ")")) return false;
        } else if (a->kind == YX_HEX_JUMP) {
            uint64_t min = a->minimum, max = a->maximum == UINT32_MAX && !a->finite_maximum ? UINT64_MAX : a->maximum;
            while (i + 1 < count && atoms[i + 1].kind == YX_HEX_JUMP) {
                const yx_hex_atom *next = &atoms[++i];
                min += next->minimum;
                max = max == UINT64_MAX || (next->maximum == UINT32_MAX && !next->finite_maximum) ? UINT64_MAX : max + next->maximum;
            }
            char quantifier[64];
            if (min > UINT32_MAX || (max != UINT64_MAX && max > UINT32_MAX)) return false;
            if (max == UINT64_MAX) snprintf(quantifier, sizeof(quantifier), "{%u,}?", (unsigned)min);
            else snprintf(quantifier, sizeof(quantifier), "{%u,%u}?", (unsigned)min, (unsigned)max);
            if (!yx_tr_text(text, "[\\x00-\\xff]") || !yx_tr_text(text, quantifier)) return false;
        } else return false;
    }
    return true;
}
static bool yx_ft_regex(yx_fast_program *p, const yx_tr_node *root, bool greedy);
/* FastVM emits its verifier before rejecting atoms shorter than two
 * bytes. Those unreferenced bytes remain in the canonical archive when the
 * compiler retries with Thompson. */
static bool yx_tr_failed_fast_regexp(const yx_tr_node *root, const char *regexp, bool dotall, bool nocase, const YRX_PATTERN *hex, yx_writer *code)
{
    yx_fast_program *fast = calloc(1, sizeof(*fast));
    if (!fast) return false;
    fast->nocase = nocase;
    fast->force_regexp = true;
    bool parsed = hex ? yx_fast_hex_sequence(fast, hex->hex_atoms, hex->hex_atom_count) : yx_fast_regex(fast, regexp, dotall);
    /* The text lowering reads (?s) groups only. Other flag spellings ((?m),
     * (?sm), (?s-u), (?u) ...) take FastVM's splitter over the parsed HIR,
     * as the scanner's program builder does; its code does not depend on
     * greediness. */
    if (!parsed && !hex && root) {
        yx_fast_program_destroy(fast);
        fast = calloc(1, sizeof(*fast));
        if (!fast) return false;
        fast->nocase = nocase;
        parsed = yx_ft_regex(fast, root, false);
        fast->force_regexp = true;
    }
    bool failed = parsed && !yx_fast_compile(fast) && fast->code.used != 0;
    if (failed) {
        *code = fast->code;
        fast->code = (yx_writer){0};
    }
    yx_fast_program_destroy(fast);
    return failed;
}
/* Bytes that a failed FastVM attempt leaves in front of the Thompson
 * program. Empty when FastVM rejects the pattern before emitting code. */
static bool yx_tr_fast_leftover(const yx_tr_node *root, const char *regexp, bool dotall, bool nocase, const YRX_PATTERN *hex, yx_writer *code)
{
    *code = (yx_writer){0};
    bool failed_fast = root && yx_tr_failed_fast_regexp(root, regexp, dotall, nocase, hex, code);
    if (!failed_fast) failed_fast = root && yx_tr_failed_fast_sequence(root, code) && code->used && yx_put_u8(code, 0);
    if (!failed_fast) {
        free(code->data);
        *code = (yx_writer){0};
    }
    return failed_fast;
}
/* Whether YARA-X compiles the pattern with Thompson rather than FastVM. A
 * hex pattern whose simplified HIR the FastVM splitter rejects goes to
 * Thompson even when the regexp tree alone looks FastVM-compatible. */
static bool yx_tr_uses_thompson(const yx_tr_node *root, bool failed_fast, const YRX_PATTERN *hex)
{
    if (failed_fast) return true;
    if (!hex) return yx_tr_needs_thompson(root, false, false);
    yx_fast_program *fast = calloc(1, sizeof(*fast));
    if (!fast) return false;
    bool parsed = yx_fast_hex_sequence(fast, hex->hex_atoms, hex->hex_atom_count);
    yx_fast_program_destroy(fast);
    return !parsed;
}
static yx_ser_result yx_encode_thompson_regex(const YRX_RULES *rules, bool vba_order, uint8_t **data, size_t *length)
{
    if (!rules || rules->rule_count != 1 || rules->import_count || rules->global_count) return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule = &rules->rules[0];
    if (rule->pattern_count != 1 || rule->is_private || rule->is_global || rule->tag_count || rule->metadata_count ||
        (rule->namespace_name && strcmp(rule->namespace_name, "default")))
        return YX_SER_UNSUPPORTED;
    const YRX_PATTERN *pattern = &rule->patterns[0];
    bool hex = pattern->kind == YX_PATTERN_HEX;
    if ((!hex && (pattern->kind != YX_PATTERN_REGEX || !pattern->regexp)) ||
        (pattern->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD)) ||
        !yx_regex_direct_condition(rule->condition_text, pattern->identifier))
        return YX_SER_UNSUPPORTED;
    yx_writer hex_text = {0};
    const char *regexp = pattern->regexp;
    if (hex) {
        if (!pattern->hex_atoms || !yx_tr_hex_regex(&hex_text, pattern->hex_atoms, pattern->hex_atom_count, 0) || !yx_put_u8(&hex_text, 0)) {
            free(hex_text.data);
            return YX_SER_UNSUPPORTED;
        }
        regexp = (char *)hex_text.data;
    }
    yx_tr_parser eligibility = {.text = (const uint8_t *)regexp,
                                .length = strlen(regexp),
                                .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                                .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&eligibility);
    yx_writer code = {0};
    bool failed_fast = root && yx_tr_fast_leftover(root, regexp, eligibility.dotall, eligibility.nocase, hex ? pattern : NULL, &code);
    bool supported =
        root && !eligibility.failed && !eligibility.oom && eligibility.at == eligibility.length && yx_tr_uses_thompson(root, failed_fast, hex ? pattern : NULL);
    yx_tr_destroy(root);
    if (!supported) {
        free(code.data);
        free(hex_text.data);
        return YX_SER_UNSUPPORTED;
    }
    yx_tr_program program = {0};
    bool greedy = false;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    yx_archive_regexp_atom *atoms = NULL;
    uint8_t wasm[sizeof(yx_single_text_pattern_wasm)];
    if (!yx_tr_compile(regexp, (pattern->modifiers & YX_MOD_DOTALL) != 0, (pattern->modifiers & YX_MOD_NOCASE) != 0, &program, &greedy)) goto done;
    bool ascii_wide = (pattern->modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)) == (YX_MOD_ASCII | YX_MOD_WIDE);
    size_t atom_count = program.atoms.count * (ascii_wide ? 2 : 1);
    atoms = calloc(atom_count, sizeof(*atoms));
    if (!atoms) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < program.atoms.count; ++i) {
        const yx_tr_atom_entry *from = &program.atoms.items[i];
        if (pattern->modifiers & YX_MOD_WIDE) {
            for (size_t j = 0; j < from->length; ++j) atoms[i].bytes[j * 2] = from->bytes[j];
            atoms[i].length = from->length * 2;
        } else {
            memcpy(atoms[i].bytes, from->bytes, from->length);
            atoms[i].length = from->length;
        }
        atoms[i].exact = from->exact;
        atoms[i].has_forward = atoms[i].has_backward = true;
        atoms[i].forward = code.used + from->forward;
        atoms[i].backward = code.used + program.forward.used + from->backward;
        if (ascii_wide) {
            yx_archive_regexp_atom *ascii = &atoms[program.atoms.count + i];
            *ascii = atoms[i];
            ascii->subpattern = 1;
            memcpy(ascii->bytes, from->bytes, from->length);
            ascii->length = from->length;
        }
    }
    if (!yx_put_bytes(&program.forward, program.backward.data, program.backward.used)) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    if (!yx_put_bytes(&code, program.forward.data, program.forward.used)) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    memcpy(wasm, yx_single_text_pattern_wasm, sizeof(wasm));
    if (vba_order && !yx_reorder_pattern_wasm(wasm, sizeof(wasm), true)) goto done;
    status = yx_regexp_variants_encode(rule->identifier, pattern->identifier, hex ? 1 : 2,
                                       (!hex && greedy ? 32 : 0) | ((pattern->modifiers & YX_MOD_NOCASE) ? 2 : 0) | ((pattern->modifiers & YX_MOD_FULLWORD) ? 24 : 0) |
                                           ((pattern->modifiers & YX_MOD_WIDE) ? 1 : 0),
                                       ascii_wide, wasm, sizeof(wasm), atoms, atom_count, code.data, code.used, data, length);
done:
    free(code.data);
    free(hex_text.data);
    free(atoms);
    yx_tr_program_free(&program);
    return status;
}
static int32_t yx_tr_read_i32(const uint8_t *p)
{
    uint32_t value = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return value <= INT32_MAX ? (int32_t)value : (int32_t)((int64_t)value - INT64_C(4294967296));
}
static bool yx_tr_text(yx_writer *w, const char *text)
{
    return yx_put_bytes(w, text, strlen(text));
}
static bool yx_tr_hex_text(yx_writer *w, uint8_t byte)
{
    static const char hex[] = "0123456789abcdef";
    char text[4] = {'\\', 'x', hex[byte >> 4], hex[byte & 15]};
    return yx_put_bytes(w, text, 4);
}
static bool yx_tr_wrap(yx_writer *w, size_t start, const char *suffix)
{
    if (start > w->used || !yx_put_u8(w, 0)) return false;
    memmove(w->data + start + 1, w->data + start, w->used - start - 1);
    w->data[start] = '(';
    return yx_tr_text(w, ")") && yx_tr_text(w, suffix);
}
static bool yx_tr_cloned_region(const uint8_t *a, const uint8_t *b, size_t length)
{
    for (size_t at = 0; at < length;) {
        size_t width = yx_tr_instruction_size(a + at, length - at);
        if (!width || width != yx_tr_instruction_size(b + at, length - at)) return false;
        bool split = a[at] == 0xaa && a[at + 1] >= 1 && a[at + 1] <= 3;
        if (split) {
            if (memcmp(a + at, b + at, 2) || memcmp(a + at + 4, b + at + 4, width - 4)) return false;
        } else if (memcmp(a + at, b + at, width)) return false;
        at += width;
    }
    return true;
}
/* With roll set, YARA-X's emission of e{n,} (n >= 2: n - 2 copies of e, then
 * `l1: e; split l1` and one more copy of e) is decoded as e{n,} instead of
 * as copies around (e)+: both compile to the same code but not to the same
 * atoms (visit_post_repetition). */
static bool yx_tr_decode_region_mode(const uint8_t *code, size_t begin, size_t end, yx_writer *text, size_t depth, bool roll)
{
    if (depth > 250 || end < begin || end - begin > 1048576) return false;
    size_t *positions = malloc((end - begin + 1) * sizeof(*positions));
    if (!positions) return false;
    for (size_t i = 0; i <= end - begin; ++i) positions[i] = SIZE_MAX;
    bool ok = false;
    for (size_t at = begin; at < end;) {
        positions[at - begin] = text->used;
        size_t width = yx_tr_instruction_size(code + at, end - at);
        if (!width) goto done;
        if (code[at] != 0xaa || code[at + 1] == 0xaa) {
            if (!yx_tr_hex_text(text, code[at])) goto done;
            at += width;
            continue;
        }
        unsigned op = code[at + 1];
        if (op == 3) {
            unsigned count = code[at + 4];
            if (count < 2) goto done;
            int64_t first = (int64_t)at + yx_tr_read_i32(code + at + 5);
            int64_t second = (int64_t)at + yx_tr_read_i32(code + at + 9);
            if (first != (int64_t)(at + width) || second < first + 6 || second > (int64_t)end || code[second - 6] != 0xaa || code[second - 5] != 4) goto done;
            int64_t finish = second - 6 + yx_tr_read_i32(code + second - 4);
            if (finish < second || finish > (int64_t)end || !yx_tr_text(text, "(")) goto done;
            for (unsigned i = 0; i < count; ++i) {
                int64_t start = (int64_t)at + yx_tr_read_i32(code + at + 5 + 4 * i);
                int64_t stop = i + 1 == count ? finish : (int64_t)at + yx_tr_read_i32(code + at + 5 + 4 * (i + 1)) - 6;
                if (start < first || stop < start || stop > finish || (i && !yx_tr_text(text, "|")) ||
                    !yx_tr_decode_region_mode(code, (size_t)start, (size_t)stop, text, depth + 1, roll))
                    goto done;
                if (i + 1 < count && (code[stop] != 0xaa || code[stop + 1] != 4 || stop + yx_tr_read_i32(code + stop + 2) != finish)) goto done;
            }
            if (!yx_tr_text(text, ")")) goto done;
            at = (size_t)finish;
            continue;
        }
        if (op == 1 || op == 2) {
            int64_t target = (int64_t)at + yx_tr_read_i32(code + at + 4);
            if (target < (int64_t)begin || target > (int64_t)end || target == (int64_t)at) goto done;
            if (target < (int64_t)at) {
                size_t start = positions[(size_t)target - begin];
                size_t unit = at - (size_t)target, after = at + width;
                if (roll && start != SIZE_MAX && start <= text->used && unit <= end - after && yx_tr_cloned_region(code + (size_t)target, code + after, unit)) {
                    size_t copies = 0, previous = (size_t)target;
                    while (previous >= begin + unit && positions[previous - unit - begin] != SIZE_MAX &&
                           yx_tr_cloned_region(code + previous - unit, code + (size_t)target, unit)) {
                        ++copies;
                        previous -= unit;
                    }
                    size_t body = text->used - start, first = positions[previous - begin];
                    bool atomic = unit == yx_tr_instruction_size(code + (size_t)target, unit) &&
                                  (code[target] != 0xaa || code[target + 1] == 0xaa || (code[target + 1] >= 5 && code[target + 1] <= 9));
                    char quantifier[48];
                    snprintf(quantifier, sizeof(quantifier), "%s{%zu,}%s", atomic ? "" : ")", copies + 2, op == 2 ? "" : "?");
                    /* Reserve room for "(?:", then keep one copy of the body. */
                    if (first > start || !yx_tr_text(text, "(?:")) goto done;
                    text->used -= 3;
                    memmove(text->data + first + (atomic ? 0 : 3), text->data + start, body);
                    if (!atomic) memcpy(text->data + first, "(?:", 3);
                    text->used = first + (atomic ? 0 : 3) + body;
                    if (!yx_tr_text(text, quantifier)) goto done;
                    /* Only the start of the rolled repetition stays addressable. */
                    for (size_t i = previous - begin + 1; i < after + unit - begin; ++i) positions[i] = SIZE_MAX;
                    positions[previous - begin] = first;
                    at = after + unit;
                    continue;
                }
                if (start == SIZE_MAX || !yx_tr_wrap(text, start, op == 2 ? "+" : "+?")) goto done;
                for (size_t i = (size_t)target - begin; i <= at - begin; ++i)
                    if (positions[i] != SIZE_MAX && positions[i] > start) ++positions[i];
                at += width;
                continue;
            }
            if (target < (int64_t)(at + width)) goto done;
            size_t stop = (size_t)target;
            bool star = stop >= at + width + 6 && code[stop - 6] == 0xaa && code[stop - 5] == 4 && (int64_t)stop - 6 + yx_tr_read_i32(code + stop - 4) == (int64_t)at;
            if (star) stop -= 6;
            /* Small bounded repeats are unrolled as nested optional copies.
             * Restore their count instead of introducing capture groups:
             * the scanner's atom verifier windows depend on that structure. */
            if (!star && at + width < stop) {
                size_t unit = at + width;
                size_t unit_width = yx_tr_instruction_size(code + unit, stop - unit);
                bool atomic = unit_width && (code[unit] != 0xaa || code[unit + 1] == 0xaa || (code[unit + 1] >= 5 && code[unit + 1] <= 9));
                size_t copies = 1, next = unit + unit_width;
                while (atomic && next < stop) {
                    if (stop - next < 8 + unit_width || code[next] != 0xaa || code[next + 1] != op || (int64_t)next + yx_tr_read_i32(code + next + 4) != (int64_t)stop ||
                        memcmp(code + next + 8, code + unit, unit_width)) {
                        atomic = false;
                        break;
                    }
                    ++copies;
                    next += 8 + unit_width;
                }
                if (atomic && next == stop) {
                    size_t mandatory = 0, previous = at;
                    while (previous >= begin + unit_width && positions[previous - unit_width - begin] != SIZE_MAX &&
                           !memcmp(code + previous - unit_width, code + unit, unit_width)) {
                        ++mandatory;
                        previous -= unit_width;
                    }
                    if (copies > 1 || mandatory) {
                        char quantifier[64];
                        snprintf(quantifier, sizeof(quantifier), "{%zu,%zu}%s", mandatory, mandatory + copies, op == 2 ? "?" : "");
                        if (mandatory) text->used = positions[previous - begin];
                        if (!yx_tr_decode_region_mode(code, unit, unit + unit_width, text, depth + 1, roll) || !yx_tr_text(text, quantifier)) goto done;
                        at = (size_t)target;
                        continue;
                    }
                }
            }
            if (!yx_tr_text(text, "(") || !yx_tr_decode_region_mode(code, at + width, stop, text, depth + 1, roll) ||
                !yx_tr_text(text, star ? (op == 1 ? ")*" : ")*?") : (op == 1 ? ")?" : ")??")))
                goto done;
            at = (size_t)target;
            continue;
        }
        if (op == 16 || op == 17) {
            int64_t target = (int64_t)at + yx_tr_read_i32(code + at + 2);
            uint32_t minimum = (uint32_t)yx_tr_read_i32(code + at + 6);
            uint32_t maximum = (uint32_t)yx_tr_read_i32(code + at + 10);
            if (target < (int64_t)begin || target >= (int64_t)at || !maximum || minimum > maximum) goto done;
            size_t start = positions[(size_t)target - begin];
            /* A counted repetition with a positive minimum emits one copy
             * before its counted tail. Restore that original repetition:
             * leaving the first copy separate can put a ten-copy tail below
             * the compiler's counted-repeat threshold and change VM priority. */
            size_t unit_width = at - (size_t)target;
            if (minimum && maximum < UINT32_MAX && (size_t)target - begin >= unit_width && positions[(size_t)target - unit_width - begin] != SIZE_MAX &&
                yx_tr_cloned_region(code + (size_t)target - unit_width, code + (size_t)target, unit_width)) {
                size_t previous = positions[(size_t)target - unit_width - begin];
                if (start == SIZE_MAX || previous > start || start > text->used) goto done;
                size_t body_length = text->used - start;
                memmove(text->data + previous, text->data + start, body_length);
                text->used = previous + body_length;
                start = previous;
                ++minimum;
                ++maximum;
                for (size_t i = (size_t)target - unit_width - begin; i <= at - begin; ++i)
                    if (positions[i] != SIZE_MAX && positions[i] >= previous) positions[i] = previous;
            }
            char suffix[64];
            snprintf(suffix, sizeof(suffix), "{%u,%u}%s", minimum ? minimum : 1, maximum, op == 17 ? "?" : "");
            if (start == SIZE_MAX || !yx_tr_wrap(text, start, suffix)) goto done;
            for (size_t i = (size_t)target - begin; i <= at - begin; ++i)
                if (positions[i] != SIZE_MAX && positions[i] > start) ++positions[i];
        } else if (op == 5) {
            if (!yx_tr_text(text, "[\\x00-\\xff]")) goto done;
        } else if (op == 6 || op == 7 || op == 8 || op == 9) {
            uint8_t bitmap[32] = {0};
            if (op == 6) {
                for (unsigned b = 0; b < 256; ++b)
                    if ((b & code[at + 3]) == code[at + 2]) yx_tr_set(bitmap, b);
            } else if (op == 7) {
                unsigned b = code[at + 2];
                yx_tr_set(bitmap, b);
                if (b < 128 && isalpha((int)b)) yx_tr_set(bitmap, b ^ 32);
            } else if (op == 8) memcpy(bitmap, code + at + 2, 32);
            else {
                for (unsigned i = 0; i < code[at + 2]; ++i) {
                    unsigned low = code[at + 3 + 2 * i], high = code[at + 4 + 2 * i];
                    if (low > high) goto done;
                    for (unsigned b = low; b <= high; ++b) yx_tr_set(bitmap, b);
                }
            }
            /* A range opcode may originate from an optimized Unicode
             * literal alternation. Preserve that distinction when its byte
             * class would otherwise be emitted as a mask opcode. */
            unsigned low = 255, high = 0, count = 0;
            for (unsigned b = 0; b < 256; ++b)
                if (yx_tr_has(bitmap, b)) {
                    low &= b;
                    high |= b;
                    ++count;
                }
            unsigned combinations = 1;
            for (unsigned bit = 1; bit <= 128; bit <<= 1)
                if ((low ^ high) & bit) combinations *= 2;
            bool alternatives = op == 9 && count == combinations;
            /* Hir::fail, the empty class ((?u)[\x{E001}&&\x{80}]): CLASS_RANGES
             * without ranges. */
            if (!count) {
                if (op != 9 || !yx_tr_text(text, "[^\\x00-\\xff]")) goto done;
                at += width;
                continue;
            }
            if (!yx_tr_text(text, alternatives ? "(" : "[")) goto done;
            bool first = true;
            for (unsigned b = 0; b < 256; ++b)
                if (yx_tr_has(bitmap, b)) {
                    unsigned start = b;
                    if (!alternatives)
                        while (b < 255 && yx_tr_has(bitmap, b + 1)) ++b;
                    if ((alternatives && !first && !yx_tr_text(text, "|")) || !yx_tr_hex_text(text, (uint8_t)start) ||
                        (b > start && (!yx_tr_text(text, "-") || !yx_tr_hex_text(text, (uint8_t)b))))
                        goto done;
                    first = false;
                }
            if (first || !yx_tr_text(text, alternatives ? ")" : "]")) goto done;
        } else if (op >= 10 && op <= 15) {
            static const char *const assertions[] = {"^", "$", "\\b", "\\B", "\\b", "\\b"};
            if (!yx_tr_text(text, assertions[op - 10])) goto done;
        } else if (op == 0x12 || op == 0x13) {
            /* LINE_START and LINE_END: the multi-line anchors. */
            if (!yx_tr_text(text, op == 0x12 ? "(?m:^)" : "(?m:$)")) goto done;
        } else goto done;
        at += width;
    }
    ok = text->used <= 1048576;
done:
    free(positions);
    return ok;
}
static bool yx_tr_decode_region(const uint8_t *code, size_t begin, size_t end, yx_writer *text, size_t depth)
{
    return yx_tr_decode_region_mode(code, begin, end, text, depth, false);
}
static bool yx_tr_any_span(const yx_tr_node *node, uint64_t *min, uint64_t *max)
{
    *min = *max = 0;
    if (node->kind == YX_TR_CLASS) {
        for (size_t i = 0; i < 32; ++i)
            if (node->bitmap[i] != 255) return false;
        *min = *max = 1;
        return true;
    }
    if (yx_u8_any(node)) {
        *min = *max = 1;
        return true;
    }
    if (node->kind == YX_TR_CAPTURE) return yx_tr_any_span(node->children[0], min, max);
    if (node->kind == YX_TR_REPEAT) {
        uint64_t low, high;
        if (!yx_tr_any_span(node->children[0], &low, &high)) return false;
        *min = low * node->minimum;
        *max = high == UINT64_MAX || yx_tr_unbounded(node) ? UINT64_MAX : high * node->maximum;
        return *min <= UINT32_MAX && (*max == UINT64_MAX || *max <= UINT32_MAX);
    }
    if (node->kind == YX_TR_CONCAT) {
        for (size_t i = 0; i < node->count; ++i) {
            uint64_t low, high;
            if (!yx_tr_any_span(node->children[i], &low, &high)) return false;
            *min += low;
            *max = high == UINT64_MAX || *max == UINT64_MAX ? UINT64_MAX : *max + high;
            if (*min > UINT32_MAX || (*max != UINT64_MAX && *max > UINT32_MAX)) return false;
        }
        return true;
    }
    return node->kind == YX_TR_EMPTY;
}
static bool yx_tr_hex_source(const yx_tr_node *node, yx_writer *text)
{
    uint64_t min, max;
    if (yx_tr_any_span(node, &min, &max)) {
        if (!max) return true;
        char token[64];
        if (min == 1 && max == 1) return yx_tr_text(text, "?? ");
        if (max == UINT64_MAX) snprintf(token, sizeof(token), "[%u-] ", (unsigned)min);
        else if (min == max) snprintf(token, sizeof(token), "[%u] ", (unsigned)min);
        else snprintf(token, sizeof(token), "[%u-%u] ", (unsigned)min, (unsigned)max);
        return yx_tr_text(text, token);
    }
    if (node->kind == YX_TR_LITERAL) {
        for (size_t i = 0; i < node->length; ++i) {
            char token[4];
            snprintf(token, sizeof(token), "%02x ", node->bytes[i]);
            if (!yx_tr_text(text, token)) return false;
        }
        return true;
    }
    if (node->kind == YX_TR_CLASS) {
        bool first = true;
        if (!yx_tr_text(text, "(")) return false;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(node->bitmap, b)) {
                char token[4];
                snprintf(token, sizeof(token), "%02x ", b);
                if ((!first && !yx_tr_text(text, "| ")) || !yx_tr_text(text, token)) return false;
                first = false;
            }
        return !first && yx_tr_text(text, ") ");
    }
    if (node->kind == YX_TR_CONCAT || node->kind == YX_TR_CAPTURE || node->kind == YX_TR_ALT) {
        bool alt = node->kind == YX_TR_ALT;
        if (alt && !yx_tr_text(text, "(")) return false;
        for (size_t i = 0; i < node->count; ++i)
            if ((alt && i && !yx_tr_text(text, "| ")) || !yx_tr_hex_source(node->children[i], text)) return false;
        return !alt || yx_tr_text(text, ") ");
    }
    return false;
}
/* Decode the forward Thompson program that starts at begin. The text is
 * NUL-terminated regexp source, or hex source for hex patterns. */
static bool yx_tr_decode_forward(const yx_archive_regexp_envelope *e, size_t begin, bool jump_gap, yx_writer *out, yx_writer *raw, yx_writer *raw_backward)
{
    yx_writer text = {0}, backward = {0};
    size_t forward_end = begin;
    bool ok = false;
    while (forward_end < e->code_length) {
        size_t n = yx_tr_instruction_size(e->code + forward_end, e->code_length - forward_end);
        if (!n) goto done;
        if (e->code[forward_end] == 0xaa && e->code[forward_end + 1] == 0) break;
        forward_end += n;
    }
    /* Reconstruct the executable expression, while validating every other
     * archive byte against the schema. Equivalent expressions need not
     * reproduce the producer's repetition unrolling or atom choices. */
    if (forward_end + 2 >= e->code_length || !yx_tr_decode_region(e->code, begin, forward_end, &text, 0) || !yx_put_u8(&text, 0) || e->code_length < forward_end + 4 ||
        e->code[e->code_length - 2] != 0xaa || e->code[e->code_length - 1] != 0 || !yx_tr_decode_region(e->code, forward_end + 2, e->code_length - 2, &backward, 0))
        goto done;
    if (jump_gap) {
        if (!yx_put_u8(&backward, 0)) goto done;
        yx_tr_parser parser = {.text = backward.data, .length = backward.used - 1};
        yx_tr_node *node = yx_tr_expression(&parser);
        bool valid = node && !parser.failed && !parser.oom && parser.at == parser.length && yx_tr_only_any_classes(node);
        yx_tr_destroy(node);
        if (!valid) goto done;
        --backward.used;
    }
    if ((raw && !yx_put_bytes(raw, text.data, text.used)) || (raw_backward && (!yx_put_bytes(raw_backward, backward.data, backward.used) || !yx_put_u8(raw_backward, 0))))
        goto done;
    if (e->pattern_kind == 1) {
        /* Hex source keeps its alternatives as written. */
        yx_tr_parser parser = {.text = text.data, .length = text.used - 1, .literal_alternations = true};
        yx_tr_node *node = yx_tr_expression(&parser);
        yx_writer hex = {0};
        bool valid = node && !parser.failed && !parser.oom && parser.at == parser.length && yx_tr_hex_source(node, &hex) && yx_put_u8(&hex, 0);
        yx_tr_destroy(node);
        if (!valid) {
            free(hex.data);
            goto done;
        }
        free(text.data);
        text = hex;
    }
    *out = text;
    text = (yx_writer){0};
    ok = true;
done:
    free(text.data);
    free(backward.data);
    return ok;
}
/* Recompile the decoded pattern as the reconstructed rule declares it and
 * require that its failed-FastVM residue equals the archive's prefix. */
static bool yx_tr_region_text(const yx_writer *code, yx_writer *text, size_t *end)
{
    size_t at = *end;
    while (at < code->used) {
        size_t n = yx_tr_instruction_size(code->data + at, code->used - at);
        if (!n) return false;
        if (code->data[at] == 0xaa && code->data[at + 1] == 0) break;
        at += n;
    }
    bool ok = at + 2 <= code->used && yx_tr_decode_region(code->data, *end, at, text, 0) && yx_put_u8(text, 0);
    *end = at + 2;
    return ok;
}
/* Mandatory byte occurrences of a decoded program: literal bytes counted
 * through concatenations, alternation branches and minimum repetition
 * counts. Optional parts contribute nothing. */
static void yx_tr_mandatory_bytes(const yx_tr_node *node, uint64_t factor, uint64_t counts[256])
{
    if (!factor) return;
    if (node->kind == YX_TR_LITERAL) {
        for (size_t i = 0; i < node->length; ++i) counts[node->bytes[i]] += factor;
    } else if (node->kind == YX_TR_REPEAT) {
        if (node->minimum && node->count) yx_tr_mandatory_bytes(node->children[0], factor > UINT32_MAX ? factor : factor * node->minimum, counts);
    } else if (node->kind == YX_TR_CONCAT || node->kind == YX_TR_CAPTURE || node->kind == YX_TR_ALT) {
        for (size_t i = 0; i < node->count; ++i) yx_tr_mandatory_bytes(node->children[i], factor, counts);
    }
}
/* The forward and backward programs encode one pattern in both directions,
 * so they need the same bytes. Residue bytes misread as pattern bytes appear
 * only in the forward program. Text that the regexp parser cannot read
 * falls back to counting the \\xHH spellings of the decoded bytes. */
static bool yx_tr_same_literals(const char *a, const char *b)
{
    uint64_t counts[2][256] = {{0}};
    bool parsed = true;
    if (!a || !b) return false;
    for (unsigned side = 0; side < 2 && parsed; ++side) {
        const char *text = side ? b : a;
        yx_tr_parser parser = {.text = (const uint8_t *)text, .length = strlen(text), .literal_alternations = true};
        yx_tr_node *node = yx_tr_expression(&parser);
        parsed = node && !parser.failed && !parser.oom && parser.at == parser.length;
        if (parsed) yx_tr_mandatory_bytes(node, 1, counts[side]);
        yx_tr_destroy(node);
    }
    /* The parser factors a prefix that alternatives share, and the two
     * programs list their alternatives in opposite directions: a suffix that
     * the forward ones share is a factored prefix of the backward ones. The
     * \\xHH spellings of the decoded bytes then decide. */
    if (!parsed || memcmp(counts[0], counts[1], sizeof(counts[0]))) {
        memset(counts, 0, sizeof(counts));
        for (unsigned side = 0; side < 2; ++side)
            for (const char *p = side ? b : a; *p; ++p) {
                if (p[0] != '\\' || !p[1]) continue;
                if (p[1] == 'x' && isxdigit((unsigned char)p[2]) && isxdigit((unsigned char)p[3])) {
                    char digits[3] = {p[2], p[3], 0};
                    ++counts[side][strtoul(digits, NULL, 16)];
                    p += 3;
                } else ++p;
            }
    }
    return !memcmp(counts[0], counts[1], sizeof(counts[0]));
}
static bool yx_tr_leftover_matches(const yx_archive_regexp_envelope *e, const char *text, size_t prefix, bool check_residue, const yx_writer *raw)
{
    yx_writer source = {0}, hex_text = {0}, code = {0};
    YRX_RULES *rules = NULL;
    bool ok = false;
    if (!text) return false;
    if (!yx_tr_text(&source, e->pattern_kind == 1 ? "rule r { strings: $a = { " : "rule r { strings: $a = /") || !yx_tr_text(&source, text) ||
        !yx_tr_text(&source, e->pattern_kind == 1 ? " }" : ((e->flags & 2u) ? "/ nocase" : "/")) || !yx_tr_text(&source, " condition: $a }") || !yx_put_u8(&source, 0))
        goto done;
    if (yx_compile_quiet((const char *)source.data, &rules) != YRX_SUCCESS || !rules || rules->rule_count != 1 || rules->rules[0].pattern_count != 1) goto done;
    const YRX_PATTERN *pattern = &rules->rules[0].patterns[0];
    bool hex = pattern->kind == YX_PATTERN_HEX;
    const char *regexp = pattern->regexp;
    if (hex) {
        if (!pattern->hex_atoms || !yx_tr_hex_regex(&hex_text, pattern->hex_atoms, pattern->hex_atom_count, 0) || !yx_put_u8(&hex_text, 0)) goto done;
        regexp = (const char *)hex_text.data;
    } else if (pattern->kind != YX_PATTERN_REGEX || !regexp) goto done;
    /* Without a residue to check or a raw program to compare, the result is
     * decided here: the rest only computes values that nothing reads. */
    if (!check_residue && !raw) {
        ok = true;
        goto done;
    }
    yx_tr_parser eligibility = {.text = (const uint8_t *)regexp,
                                .length = strlen(regexp),
                                .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                                .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&eligibility);
    bool failed_fast = yx_tr_fast_leftover(root, regexp, eligibility.dotall, eligibility.nocase, hex ? pattern : NULL, &code);
    /* The archive holds a Thompson program, so the pattern must be one that
     * the FastVM compiler rejects, exactly as the encoder decides. */
    bool thompson =
        root && !eligibility.failed && !eligibility.oom && eligibility.at == eligibility.length && yx_tr_uses_thompson(root, failed_fast, hex ? pattern : NULL);
    yx_tr_destroy(root);
    ok = !check_residue || (thompson && code.used == prefix && (!prefix || !memcmp(code.data, e->code, prefix)));
    if (ok && raw) {
        /* A pattern rebuilt from the residue must describe the archived
         * forward program: compile it and compare literal byte counts. */
        yx_tr_program program = {0};
        bool greedy = false;
        yx_writer forward = {0};
        size_t end = 0;
        ok = yx_tr_compile(regexp, eligibility.dotall, eligibility.nocase, &program, &greedy) && yx_tr_region_text(&program.forward, &forward, &end) &&
             yx_tr_same_literals((const char *)forward.data, (const char *)raw->data);
        free(forward.data);
        yx_tr_program_free(&program);
    }
done:
    yrx_rules_destroy(rules);
    free(source.data);
    free(hex_text.data);
    free(code.data);
    return ok;
}
/* Rebuild a pattern from the pieces of a FastVM residue. The first
 * sequence is the backward verifier when a second one follows; it lists
 * the pieces before the atom piece in reverse order. */
static bool yx_tr_residue_source(const yx_archive_regexp_envelope *e, size_t first_end, size_t end, yx_writer *out)
{
    yx_fast_program *p = calloc(1, sizeof(*p));
    size_t at = 0;
    bool ok = false, dotall = false;
    if (!p) return false;
    p->flags = e->flags & 32u;
    if (!yx_fast_read_sequence(p, e->code, e->code_length, &at) || at != first_end) goto done;
    if (end != first_end) {
        for (size_t i = 0; i < p->count / 2; ++i) {
            yx_fast_piece swap = p->pieces[i];
            p->pieces[i] = p->pieces[p->count - i - 1];
            p->pieces[p->count - i - 1] = swap;
        }
        if (!yx_fast_read_sequence(p, e->code, e->code_length, &at) || at != end) goto done;
    }
    /* Regexp jumps that exclude newlines need the reconstructed rule's
     * default dot; a dotall reconstruction is not representable here. */
    ok = yx_fast_source(p, e->pattern_kind == 1, out, &dotall) && (e->pattern_kind == 1 || !dotall) && yx_put_u8(out, 0);
done:
    yx_fast_program_destroy(p);
    return ok;
}
/* Whether the rule the loader rebuilds from a decoded regexp compiles back
 * to exactly this single-pattern archive (with either wasm profile). */
static bool yx_tr_reproduces(const yx_archive_regexp_envelope *e, const uint8_t *data, const char *text)
{
    yx_writer source = {0};
    YRX_RULES *rules = NULL;
    bool same = false;
    if (!text || !e->names[1] || !e->names[2]) return false;
    if (!yx_tr_text(&source, "rule ") || !yx_tr_text(&source, e->names[2]) || !yx_tr_text(&source, " { strings: ") || !yx_tr_text(&source, e->names[1]) ||
        !yx_tr_text(&source, " = /") || !yx_tr_text(&source, text) || !yx_tr_text(&source, "/") || ((e->flags & 24u) && !yx_tr_text(&source, " fullword")) ||
        ((e->flags & 1u) && !yx_tr_text(&source, " wide")) || (e->ascii_wide && !yx_tr_text(&source, " ascii")) || ((e->flags & 2u) && !yx_tr_text(&source, " nocase")) ||
        !yx_tr_text(&source, " condition: ") || !yx_tr_text(&source, e->names[1]) || !yx_tr_text(&source, " }") || !yx_put_u8(&source, 0))
        goto done;
    if (yx_compile_quiet((const char *)source.data, &rules) != YRX_SUCCESS || !rules) goto done;
    for (unsigned profile = 0; profile < 2 && !same; ++profile) {
        uint8_t *encoded = NULL;
        size_t encoded_length = 0;
        if (yx_encode_thompson_regex(rules, profile != 0, &encoded, &encoded_length) == YX_SER_SUCCESS)
            same = encoded_length == e->archive_length && !memcmp(encoded, data, encoded_length);
        free(encoded);
    }
done:
    yrx_rules_destroy(rules);
    free(source.data);
    return same;
}
/* One \xHH escape at t: its value, or -1. */
static int yx_tr_hex_escape(const char *t)
{
    int value = 0;
    if (t[0] != '\\' || t[1] != 'x') return -1;
    for (unsigned k = 2; k < 4; ++k) {
        char c = t[k];
        if (c >= '0' && c <= '9') value = value * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') value = value * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') value = value * 16 + (c - 'A' + 10);
        else return -1;
    }
    return value;
}
/* A regexp of at most 1024 characters made of \xHH bytes and positive
 * classes of \xHH bytes and ascending \xHH-\xHH ranges only, with at least
 * one byte and one class. The rule `$a = /text/` (with or without nocase)
 * always compiles to one regexp pattern: the text has no syntax to reject
 * and no construct that can be too large. */
static bool yx_tr_plain_regexp(const char *t)
{
    size_t bytes = 0, classes = 0;
    const char *start = t;
    while (*t) {
        if (*t == '[') {
            size_t items = 0;
            ++t;
            while (*t != ']') {
                int low = yx_tr_hex_escape(t), high;
                if (low < 0) return false;
                t += 4;
                if (*t == '-') {
                    high = yx_tr_hex_escape(t + 1);
                    if (high < low) return false;
                    t += 5;
                }
                ++items;
            }
            if (!items) return false;
            ++t;
            ++classes;
        } else {
            if (yx_tr_hex_escape(t) < 0) return false;
            t += 4;
            ++bytes;
        }
    }
    return bytes && classes && (size_t)(t - start) <= 1024;
}
/* The forward program at begin, decoded with e{n,} repetitions rolled up. */
static bool yx_tr_roll_forward(const yx_archive_regexp_envelope *e, size_t begin, yx_writer *out)
{
    size_t forward_end = begin;
    while (forward_end < e->code_length) {
        size_t n = yx_tr_instruction_size(e->code + forward_end, e->code_length - forward_end);
        if (!n) return false;
        if (e->code[forward_end] == 0xaa && e->code[forward_end + 1] == 0) break;
        forward_end += n;
    }
    return forward_end < e->code_length && yx_tr_decode_region_mode(e->code, begin, forward_end, out, 0, true) && yx_put_u8(out, 0);
}
static yx_ser_result yx_decode_thompson_regex(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    yx_archive_regexp_envelope envelope = {0};
    yx_writer text = {0};
    uint8_t *expected = NULL;
    size_t expected_length = 0;
    yx_ser_rule *decoded = NULL;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    if (!yx_regexp_envelope_read(data, length, &envelope)) return status;
    if ((envelope.pattern_kind != 1 && envelope.pattern_kind != 2) || (envelope.flags & ~59u) || (envelope.pattern_kind == 1 && envelope.flags) ||
        ((envelope.flags & 24u) && (envelope.flags & 24u) != 24u))
        goto done;
    /* A failed FastVM attempt may leave one or two unreferenced verifier
     * sequences (backward, then forward) or a jump-only program in front of
     * the Thompson program. Every candidate boundary is checked by
     * recomputing that residue from the decoded pattern, so a misplaced
     * boundary cannot turn verifier bytes into pattern bytes. */
    size_t candidates[4] = {0}, candidate_count = 1, gap_end = 0;
    while (gap_end < envelope.code_length && envelope.code[gap_end] >= 3 && envelope.code[gap_end] <= 6) {
        size_t width = (envelope.code[gap_end] == 3 || envelope.code[gap_end] == 5) ? 5 : 9;
        if (width >= envelope.code_length - gap_end) {
            gap_end = 0;
            break;
        }
        gap_end += width;
    }
    if (gap_end && gap_end < envelope.code_length && !envelope.code[gap_end]) {
        bool unused = true;
        for (size_t i = 0; i < envelope.atom_count; ++i)
            if (envelope.atoms[i].length > ((envelope.flags & 1u) ? 2u : 1u) || !envelope.atoms[i].has_forward || !envelope.atoms[i].has_backward ||
                envelope.atoms[i].forward <= gap_end || envelope.atoms[i].backward <= gap_end)
                unused = false;
        if (unused) candidates[candidate_count++] = gap_end + 1;
    }
    if (candidate_count == 1 && envelope.code_length && envelope.code[0] >= 1 && envelope.code[0] <= 7) {
        size_t sequence_end = 0;
        for (unsigned sequence = 0; sequence < 2; ++sequence) {
            yx_fast_program *prefix = calloc(1, sizeof(*prefix));
            if (!prefix) {
                status = YX_SER_NO_MEMORY;
                goto done;
            }
            bool parsed = sequence_end < envelope.code_length && envelope.code[sequence_end] >= 1 && envelope.code[sequence_end] <= 7 &&
                          yx_fast_read_sequence(prefix, envelope.code, envelope.code_length, &sequence_end) && sequence_end < envelope.code_length;
            yx_fast_program_destroy(prefix);
            if (!parsed) break;
            bool unused = true;
            for (size_t i = 0; i < envelope.atom_count && unused; ++i)
                if (!envelope.atoms[i].has_forward || !envelope.atoms[i].has_backward || envelope.atoms[i].forward < sequence_end ||
                    envelope.atoms[i].backward < sequence_end)
                    unused = false;
            if (!unused) break;
            candidates[candidate_count++] = sequence_end;
        }
    }
    /* Longer residues are tried first; the empty residue is the last resort. */
    bool decoded_forward = false, decoded_gap = false;
    size_t decoded_begin = 0;
    for (size_t c = candidate_count; c-- > 0 && !decoded_forward;) {
        yx_writer raw = {0}, raw_backward = {0};
        bool gap = gap_end && candidates[c] == gap_end + 1, residue = candidates[c] && !gap;
        decoded_begin = candidates[c];
        decoded_gap = gap;
        free(text.data);
        text = (yx_writer){0};
        decoded_forward = yx_tr_decode_forward(&envelope, candidates[c], gap, &text, &raw, &raw_backward);
        decoded_forward = decoded_forward && yx_tr_same_literals((const char *)raw.data, (const char *)raw_backward.data);
        if (decoded_forward && residue && envelope.pattern_kind == 1) {
            /* The residue keeps distinctions that the Thompson program loses,
             * e.g. `?? [3-6]` versus `[4-7]`. Prefer it for hex patterns. */
            yx_writer rebuilt = {0};
            bool exact = yx_tr_residue_source(&envelope, candidates[1], candidates[c], &rebuilt) &&
                         yx_tr_leftover_matches(&envelope, (const char *)rebuilt.data, candidates[c], true, &raw);
            if (exact) {
                free(text.data);
                text = rebuilt;
            } else {
                free(rebuilt.data);
                decoded_forward = yx_tr_leftover_matches(&envelope, (const char *)text.data, candidates[c], true, NULL);
            }
        } else if (decoded_forward) {
            /* Hex patterns have an exact FastVM model, so their residue must
             * match; regexp text decoded from Thompson code is a lowered
             * form whose FastVM residue can differ from the original's.
             * For a regexp the call only asks whether the decoded text
             * compiles as one regexp pattern, which a plain text
             * (yx_tr_plain_regexp) always does: it is not compiled. Verify
             * builds (-DXXYARA_VERIFY_LOAD) compile it and abort when it
             * does not. */
            bool plain = envelope.pattern_kind == 2 && text.data && yx_tr_plain_regexp((const char *)text.data);
#ifdef XXYARA_VERIFY_LOAD
            if (plain && !yx_tr_leftover_matches(&envelope, (const char *)text.data, candidates[c], false, NULL)) {
                fprintf(stderr, "XXYARA_VERIFY_LOAD: plain regexp does not compile: `%s`\n", (const char *)text.data);
                abort();
            }
#endif
            if (!plain) decoded_forward = yx_tr_leftover_matches(&envelope, (const char *)text.data, candidates[c], envelope.pattern_kind == 1 && !gap, NULL);
        }
        free(raw.data);
        free(raw_backward.data);
    }
    if (!decoded_forward) goto done;
    /* An equivalent spelling can still differ in its atoms, and the atoms
     * decide which matches the 4096-byte scan limit cuts: `[a-z]{2,}` gives
     * 4095-byte matches on a long run where `([a-z])+[a-z]` gives longer
     * ones. A rolled-up spelling replaces the decoded text only when it, and
     * not the decoded text, recompiles to this very archive. The rolled-up
     * spelling is decoded first (a pure read of the program): without one,
     * or when it is the decoded text itself (no e{n,} repetition), the text
     * stays whatever the two recompiles say, so they are skipped. */
    if (envelope.pattern_kind == 2 && !decoded_gap) {
        yx_writer rolled = {0};
        if (yx_tr_roll_forward(&envelope, decoded_begin, &rolled) && strcmp((const char *)rolled.data, (const char *)text.data) &&
            !yx_tr_reproduces(&envelope, data, (const char *)text.data) && yx_tr_reproduces(&envelope, data, (const char *)rolled.data)) {
            free(text.data);
            text = rolled;
        } else free(rolled.data);
    }
    for (size_t profile = 0; profile < 2; ++profile) {
        uint8_t wasm[sizeof(yx_single_text_pattern_wasm)];
        memcpy(wasm, yx_single_text_pattern_wasm, sizeof(wasm));
        if (profile && !yx_reorder_pattern_wasm(wasm, sizeof(wasm), true)) goto done;
        free(expected);
        expected = NULL;
        status = yx_regexp_variants_encode(envelope.names[2], envelope.names[1], envelope.pattern_kind, envelope.flags, envelope.ascii_wide, wasm, sizeof(wasm),
                                           envelope.atoms, envelope.atom_count, envelope.code, envelope.code_length, &expected, &expected_length);
        if (status == YX_SER_NO_MEMORY) goto done;
        if (status == YX_SER_SUCCESS && expected_length == envelope.archive_length && memcmp(data, expected, expected_length) == 0) break;
        status = YX_SER_UNSUPPORTED;
    }
    if (status != YX_SER_SUCCESS) goto done;
    decoded = calloc(1, sizeof(*decoded));
    if (!decoded) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    decoded->namespace_name = envelope.names[0];
    envelope.names[0] = NULL;
    decoded->pattern_identifier = envelope.names[1];
    envelope.names[1] = NULL;
    decoded->identifier = envelope.names[2];
    envelope.names[2] = NULL;
    decoded->pattern_bytes = text.data;
    decoded->pattern_length = text.used - 1;
    text.data = NULL;
    decoded->single_text_pattern = true;
    decoded->preserve_serialized_prefix = true;
    decoded->single_regex_thompson = envelope.pattern_kind == 2;
    decoded->fullword_single_pattern = (envelope.flags & 24u) != 0;
    decoded->wide_single_pattern = (envelope.flags & 1u) != 0;
    decoded->ascii_wide_single_pattern = envelope.ascii_wide;
    decoded->nocase_single_pattern = (envelope.flags & 2u) != 0;
    decoded->single_hex_thompson = envelope.pattern_kind == 1;
    decoded->truth = true;
    *rules = decoded;
    *rule_count = 1;
    decoded = NULL;
done:
    free(expected);
    free(text.data);
    yx_regexp_envelope_destroy(&envelope);
    if (decoded) yx_ser_rules_destroy(decoded, 1);
    return status;
}
#endif
