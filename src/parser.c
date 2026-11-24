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
#include "scan_candidates.h"
#include "regex_vm.h"
#include "condition.h"
#include "serialization.h"
#include "syntax_check.h"
#include "warning_suppression.h"
#include "xxfclib/regex/xx_regex_unicode16.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vt_schema.h"

/* Condition diagnostics carry identifiers, which have no length limit in
 * YARA-X: these buffers hold any identifier up to 4095 bytes. */
#define YX_CONDITION_DETAIL_SIZE 8192
#define YX_CONDITION_NAME_SIZE 4096

typedef struct {
    YRX_COMPILER *compiler;
    const char *begin;
    const char *at;
    const char *origin;
    size_t source_serial;
    bool unterminated_comment;
    const char *unterminated_comment_start;
    bool recoverable_unknown_identifier;
    bool recoverable_empty_rule;
    bool recoverable_condition_syntax;
    bool recoverable_bad_initial_section;
    bool recoverable_rule_keyword;
    bool suppress_missing_condition_recovery;
    bool recoverable_invalid_regexp;
    bool unclosed_regexp;
    bool recoverable_invalid_pattern;
    bool recoverable_slow_error;
    bool recover_inside_hex;
    const char *current_pattern_identifier;
    const char *modifier_start[9];
    const char *modifier_end[9];
    bool pending_slow_loop_error;
    size_t slow_loop_start;
    size_t slow_loop_end;
    /* Where an E047 statement starts: YARA-X has already warned about the
     * loops before it when the variable frame does not fit. */
    const char *too_many_variables_at;
    /* The modules this source imported so far, each with its latest
     * import statement (duplicate_import). */
    struct yx_seen_imports *seen_imports;
    /* Line number of line_cursor, so declaration lines are counted
     * incrementally instead of from the start of the source. */
    const char *line_cursor;
    size_t line_number;
} yx_parser;

static int yx_error(yx_parser *p, const char *message)
{
    size_t line = 1;
    for (const char *s = p->begin; s < p->at; ++s)
        if (*s == '\n') ++line;
    snprintf(p->compiler->error, sizeof(p->compiler->error), "%s:%zu: %s",
             p->origin ? p->origin : "<source>", line, message);
    return 0;
}

static int yx_syntax_label(yx_parser *p, const char *start,
                           const char *end, const char *label)
{
    if (!yx_compiler_syntax_error(p->compiler, p->begin, p->origin,
                                  (size_t)(start - p->begin),
                                  (size_t)(end - p->begin), label))
        return yx_error(p, "out of memory recording syntax error");
    return 0;
}

static int yx_syntax_expected(yx_parser *p, const char *start,
                               const char *end, const char *expected)
{
    char label[256];
    size_t length = (size_t)(end - start);
    if (length > 15)
        snprintf(label, sizeof(label), "expecting %s", expected);
    else if (length)
        snprintf(label, sizeof(label), "expecting %s, found `%.*s`",
                 expected, (int)length, start);
    else
        snprintf(label, sizeof(label), "expecting %s, found end of file",
                 expected);
    return yx_syntax_label(p, start, end, label);
}

static char *yx_duplicate(const char *data, size_t length)
{
    char *result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, data, length);
    result[length] = 0;
    return result;
}

/* Rust's lexer treats Unicode White_Space as a token separator. Keep the
 * number of source bytes here: diagnostic spans remain byte indexed. */
static size_t yx_space_bytes(const char *at)
{
    const unsigned char *bytes = (const unsigned char *)at;
    if (bytes[0] == ' ' || bytes[0] == '\t' ||
        bytes[0] == '\r' || bytes[0] == '\n') return 1;
    if (bytes[0] == 0xc2 && bytes[1] &&
        (bytes[1] == 0x85 || bytes[1] == 0xa0)) return 2;
    if (bytes[0] == 0xe1 && bytes[1] == 0x9a && bytes[2] == 0x80)
        return 3;
    if (bytes[0] == 0xe2 && bytes[1] && bytes[2]) {
        if (bytes[1] == 0x80 &&
            ((bytes[2] >= 0x80 && bytes[2] <= 0x8a) ||
             bytes[2] == 0xa8 || bytes[2] == 0xa9 ||
             bytes[2] == 0xaf)) return 3;
        if (bytes[1] == 0x81 && bytes[2] == 0x9f) return 3;
    }
    if (bytes[0] == 0xe3 && bytes[1] == 0x80 && bytes[2] == 0x80)
        return 3;
    return 0;
}

static void yx_space(yx_parser *p)
{
    for (;;) {
        size_t width;
        while ((width = yx_space_bytes(p->at)) != 0) p->at += width;
        if (p->at[0] == '/' && p->at[1] == '/') {
            p->at += 2;
            while (*p->at && *p->at != '\n') ++p->at;
        } else if (p->at[0] == '/' && p->at[1] == '*') {
            const char *comment_start = p->at;
            p->at += 2;
            while (*p->at && !(p->at[0] == '*' && p->at[1] == '/')) ++p->at;
            if (*p->at) p->at += 2;
            else {
                p->unterminated_comment = true;
                p->unterminated_comment_start = comment_start;
            }
        } else {
            break;
        }
    }
}

static int yx_word_char(int c)
{
    return isalnum((unsigned char)c) || c == '_';
}

/* YARA-X's identifier regexes are ([[:alpha:]]|_)([[:alpha:]]|\d|_)*, where
 * logos compiles \d Unicode-aware against regex-syntax 0.8.11's Unicode 16 Nd
 * table (see yx_sc_word_char in syntax_check.c). Returns the byte width of
 * the identifier-continuation character at `at` (ASCII alnum or _, or an Nd
 * digit), or 0. */
static size_t yx_ident_continue_width(const char *at)
{
    const unsigned char *s = (const unsigned char *)at;
    const xx_regex_unicode16_table *nd;
    uint32_t cp;
    size_t width, i, lo, hi;
    if (s[0] < 0x80) return isalnum(s[0]) || s[0] == '_' ? 1 : 0;
    if (s[0] >= 0xc2 && s[0] <= 0xdf) { width = 2; cp = s[0] & 0x1f; }
    else if (s[0] >= 0xe0 && s[0] <= 0xef) { width = 3; cp = s[0] & 0x0f; }
    else if (s[0] >= 0xf0 && s[0] <= 0xf4) { width = 4; cp = s[0] & 0x07; }
    else return 0;
    for (i = 1; i < width; ++i) {
        if ((s[i] & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3f);
    }
    nd = xx_regex_unicode16_table_at(
        xx_regex_unicode16_class_table(XX_REGEX_UNICODE16_DECIMAL));
    if (cp < 0x80 || !nd) return 0;
    for (lo = 0, hi = nd->count; lo < hi;) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < nd->ranges[mid].first) hi = mid;
        else if (cp > nd->ranges[mid].last) lo = mid + 1;
        else return width;
    }
    return 0;
}

/* Width of the identifier-continuation character ending at `at`, or 0. */
static size_t yx_ident_continue_width_before(const char *start, const char *at)
{
    const char *lead;
    size_t width;
    if (at <= start) return 0;
    lead = at - 1;
    while (lead > start && ((unsigned char)*lead & 0xc0) == 0x80 &&
           at - lead < 4)
        --lead;
    width = yx_ident_continue_width(lead);
    return width && lead + width == at ? width : 0;
}

static const char *yx_syntax_token_end(const char *start)
{
    const char *end = start;
    if (!*end) return end;
    if (isalpha((unsigned char)*end) || *end == '_') {
        ++end;
        for (;;) {
            size_t width = yx_ident_continue_width(end);
            if (!width) break;
            end += width;
        }
    } else if (*end == '$' && yx_ident_continue_width(end + 1)) {
        ++end;
        for (;;) {
            size_t width = yx_ident_continue_width(end);
            if (!width) break;
            end += width;
        }
    } else if (*end == '?' && (yx_word_char(end[1]) || end[1] == ':')) {
        ++end;
        if (*end == ':') ++end;
        else {
            for (;;) {
                size_t width = yx_ident_continue_width(end);
                if (!width) break;
                end += width;
            }
            if (*end == '?') ++end;
        }
    } else if (isdigit((unsigned char)*end)) {
        if (*end == '0' && end[1] == 'x' &&
            isxdigit((unsigned char)end[2])) {
            end += 2;
            do { ++end; } while (isxdigit((unsigned char)*end) || *end == '_');
            return end;
        }
        if (*end == '0' && end[1] == 'o' &&
            end[2] >= '0' && end[2] <= '7') {
            end += 2;
            do { ++end; } while ((*end >= '0' && *end <= '7') || *end == '_');
            return end;
        }
        do { ++end; } while (isdigit((unsigned char)*end) || *end == '_');
    } else if (*end == '"') {
        ++end;
        while (*end && *end != '"' && *end != '\n') {
            if (*end == '\\' && end[1]) ++end;
            ++end;
        }
        if (*end == '"') ++end;
    } else if ((unsigned char)*end >= 0x80) {
        /* A malformed non-ASCII token is reported as one run through the
         * next Unicode whitespace, including adjacent ASCII punctuation. */
        while (*end && yx_space_bytes(end) == 0) ++end;
    } else {
        ++end;
    }
    return end;
}

static const char *yx_syntax_regexp_token_end(const char *start)
{
    const char *end = start + 1;
    while (*end && *end != '/' && *end != '\n') {
        if (*end == '\\' && end[1]) ++end;
        ++end;
    }
    if (*end != '/') return yx_syntax_token_end(start);
    ++end;
    while (isalpha((unsigned char)*end)) ++end;
    return end;
}

static int yx_keyword(yx_parser *p, const char *word)
{
    yx_space(p);
    size_t n = strlen(word);
    if (strncmp(p->at, word, n) != 0 || yx_ident_continue_width(p->at + n))
        return 0;
    p->at += n;
    return 1;
}

static int yx_section(yx_parser *p, const char *name)
{
    const char *saved = p->at;
    if (yx_keyword(p, name)) {
        yx_space(p);
        if (*p->at == ':') {
            ++p->at;
            return 1;
        }
    }
    p->at = saved;
    return 0;
}

static int yx_expect(yx_parser *p, char ch)
{
    yx_space(p);
    if (*p->at != ch) {
        char message[64];
        snprintf(message, sizeof(message), "expected '%c'", ch);
        return yx_error(p, message);
    }
    ++p->at;
    return 1;
}

static char *yx_ident(yx_parser *p)
{
    yx_space(p);
    if (!(isalpha((unsigned char)*p->at) || *p->at == '_')) return NULL;
    const char *start = p->at++;
    for (;;) {
        size_t width = yx_ident_continue_width(p->at);
        if (!width) break;
        p->at += width;
    }
    return yx_duplicate(start, (size_t)(p->at - start));
}

static int yx_reserved_identifier(const char *name)
{
    static const char *const keywords[] = {
        "all", "and", "any", "ascii", "at", "base64", "base64wide",
        "condition", "contains", "defined", "endswith", "entrypoint", "false",
        "filesize", "for", "fullword", "global", "icontains",
        "iendswith", "iequals", "import", "in", "include", "istartswith",
        "matches", "meta", "nocase", "none", "not", "of", "or",
        "private", "rule", "startswith", "strings", "them", "true",
        "wide", "with", "xor"
    };
    for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); ++i)
        if (strcmp(name, keywords[i]) == 0) return 1;
    return 0;
}

static int yx_hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int yx_push_byte(uint8_t **bytes, size_t *length, size_t *capacity, uint8_t value)
{
    if (*length == *capacity) {
        size_t next = *capacity ? *capacity * 2 : 16;
        uint8_t *grown = realloc(*bytes, next);
        if (!grown) return 0;
        *bytes = grown;
        *capacity = next;
    }
    (*bytes)[(*length)++] = value;
    return 1;
}

/* Every sequence is built here from an empty one, so its capacity follows
 * from its count: 4, then doubled at each power of two (one realloc per atom
 * made long hex patterns quadratic). */
static int yx_push_hex_atom(yx_hex_sequence *sequence, yx_hex_atom atom)
{
    size_t count = sequence->count;
    if (count >= SIZE_MAX / sizeof(yx_hex_atom)) return 0;
    if (count == 0 || (count >= 4 && (count & (count - 1)) == 0)) {
        size_t capacity = count ? count * 2 : 4;
        yx_hex_atom *grown;
        if (capacity > SIZE_MAX / sizeof(yx_hex_atom)) return 0;
        grown = realloc(sequence->atoms, capacity * sizeof(*grown));
        if (!grown) return 0;
        sequence->atoms = grown;
    }
    sequence->atoms[sequence->count++] = atom;
    return 1;
}

static void yx_free_hex_atoms(yx_hex_atom *atoms, size_t count)
{
    if (!atoms) return;
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < atoms[i].branch_count; ++j)
            yx_free_hex_atoms(atoms[i].branches[j].atoms,
                              atoms[i].branches[j].count);
        free(atoms[i].branches);
    }
    free(atoms);
}

static size_t yx_escape_character_bytes(const char *at)
{
    unsigned char first = (unsigned char)*at;
    size_t length = first < 0x80 ? 1 :
                    (first & 0xe0) == 0xc0 ? 2 :
                    (first & 0xf0) == 0xe0 ? 3 :
                    (first & 0xf8) == 0xf0 ? 4 : 1;
    for (size_t i = 1; i < length; ++i)
        if (((unsigned char)at[i] & 0xc0) != 0x80) return i;
    return length;
}

static int yx_report_invalid_escape(yx_parser *p, const char *backslash,
                                    bool hexadecimal)
{
    size_t length = 1 + yx_escape_character_bytes(backslash + 1);
    if (!yx_compiler_invalid_escape_error(
            p->compiler, p->begin, p->origin,
            (size_t)(backslash - p->begin),
            (size_t)(backslash - p->begin) + length, hexadecimal))
        return yx_error(p, "out of memory recording invalid escape");
    return 0;
}

static uint8_t *yx_string(yx_parser *p, size_t *length)
{
    yx_space(p);
    if (*p->at != '"') {
        yx_error(p, "expected quoted string");
        return NULL;
    }
    const char *literal_start = p->at;
    bool multiline = strncmp(p->at, "\"\"\"", 3) == 0;
    p->at += multiline ? 3 : 1;
    uint8_t *bytes = NULL;
    size_t count = 0, capacity = 0;
    while (*p->at && !(multiline ?
           strncmp(p->at, "\"\"\"", 3) == 0 : *p->at == '"')) {
        if (*p->at == '"' || (!multiline && *p->at == '\n')) {
            free(bytes);
            yx_syntax_label(p, literal_start, p->at,
                            "unclosed literal string");
            return NULL;
        }
        uint8_t value = (uint8_t)*p->at++;
        if (value == '\\') {
            const char *backslash = p->at - 1;
            char escape = *p->at++;
            switch (escape) {
            case '0': value = 0; break;
            case 'n': value = '\n'; break;
            case 'r': value = '\r'; break;
            case 't': value = '\t'; break;
            case '"': value = '"'; break;
            case '\\': value = '\\'; break;
            case 'x': {
                if (!p->at[0] || !p->at[1]) {
                    free(bytes);
                    yx_report_invalid_escape(p, backslash, true);
                    return NULL;
                }
                int hi = yx_hex_digit(p->at[0]);
                int lo = yx_hex_digit(p->at[1]);
                if (hi < 0 || lo < 0) {
                    free(bytes);
                    yx_report_invalid_escape(p, backslash, true);
                    return NULL;
                }
                value = (uint8_t)((hi << 4) | lo);
                p->at += 2;
                break;
            }
            default:
                free(bytes);
                yx_report_invalid_escape(p, backslash, false);
                return NULL;
            }
        }
        if (!yx_push_byte(&bytes, &count, &capacity, value)) {
            free(bytes);
            yx_error(p, "out of memory");
            return NULL;
        }
    }
    if (!(multiline ? strncmp(p->at, "\"\"\"", 3) == 0 :
          *p->at == '"')) {
        free(bytes);
        yx_syntax_label(p, literal_start, p->at,
                        "unclosed literal string");
        return NULL;
    }
    p->at += multiline ? 3 : 1;
    uint8_t *grown = realloc(bytes, count + 1);
    if (!grown) {
        free(bytes);
        yx_error(p, "out of memory");
        return NULL;
    }
    grown[count] = 0;
    *length = count;
    return grown;
}

/* Import paths, include paths, and Base64 alphabets are names rather than
 * decoded text literals. Their quoted form must not contain any escape. */
static bool yx_reject_escaped_name_string(yx_parser *p)
{
    const char *start, *cursor;
    bool escaped = false;
    yx_space(p);
    if (*p->at != '"') return false;
    start = p->at;
    cursor = start + 1;
    while (*cursor && *cursor != '\n') {
        if (*cursor == '\\') {
            escaped = true;
            if (cursor[1]) { cursor += 2; continue; }
            break;
        }
        if (*cursor == '"') {
            if (!escaped) return false;
            p->at = cursor + 1;
            if (!yx_compiler_unexpected_escape_sequence_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(start - p->begin),
                    (size_t)(p->at - p->begin)))
                yx_error(p, "out of memory recording unexpected escape");
            p->recoverable_invalid_pattern = true;
            return true;
        }
        ++cursor;
    }
    return false;
}

static int yx_metadata_digit(char ch, unsigned radix)
{
    int digit = yx_hex_digit(ch);
    return digit >= 0 && (unsigned)digit < radix ? digit : -1;
}

static int yx_metadata_number(yx_parser *p, YRX_METADATA *metadata)
{
    const char *start = p->at;
    const char *at = start;
    unsigned radix = 10;
    bool negative = *at == '-';
    bool floating = false;
    uint64_t magnitude = 0, multiplier = 1;
    const char *literal;
    /* The minus sign is a token of its own: blanks may follow it. */
    if (negative) {
        ++at;
        while (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n') ++at;
    }
    literal = at;
    if (at[0] == '0' && (at[1] == 'x' || at[1] == 'o')) {
        radix = at[1] == 'x' ? 16 : 8;
        at += 2;
    }
    if (yx_metadata_digit(*at, radix) < 0)
        return yx_syntax_expected(
            p, p->at, yx_syntax_token_end(p->at),
            "`-`, INTEGER, FLOAT, STRING, `true` or `false`");
    const char *digits = at;
    while (yx_metadata_digit(*at, radix) >= 0 || *at == '_') ++at;
    /* A float literal's fraction is `([0-9_]+_*)+`: `1._` is 1.0. */
    if (radix == 10 && *at == '.' &&
        (yx_metadata_digit(at[1], 10) >= 0 || at[1] == '_')) {
        floating = true;
        ++at;
        while (yx_metadata_digit(*at, 10) >= 0 || *at == '_') ++at;
    }
    if (floating) {
        size_t length = (size_t)(at - start);
        char *clean = malloc(length + 1);
        if (!clean) return yx_error(p, "out of memory");
        size_t used = 0;
        /* The sign, then the literal without blanks or underscores. */
        if (negative) clean[used++] = '-';
        for (const char *s = literal; s < at; ++s)
            if (*s != '_') clean[used++] = *s;
        clean[used] = 0;
        char *end;
        double value = strtod(clean, &end);
        bool valid = end == clean + used;
        free(clean);
        if (!valid) return yx_error(p, "invalid metadata number");
        metadata->value_type = YRX_F64;
        metadata->value.f64 = value;
    } else {
        const char *digits_end = at;
        bool overflow = false;
        if (radix == 10 && (at[0] == 'K' || at[0] == 'M') && at[1] == 'B') {
            multiplier = at[0] == 'K' ? 1024 : 1024 * 1024;
            at += 2;
        }
        for (const char *s = digits; s < digits_end; ++s) {
            int digit = yx_metadata_digit(*s, radix);
            if (digit < 0) continue;
            if (magnitude > ((uint64_t)INT64_MAX - (unsigned)digit) / radix) {
                overflow = true;
                break;
            }
            magnitude = magnitude * radix + (unsigned)digit;
        }
        if (overflow || magnitude > (uint64_t)INT64_MAX / multiplier) {
            if (!yx_compiler_invalid_integer_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(literal - p->begin), (size_t)(at - p->begin),
                    "[-9223372036854775808, 9223372036854775807]"))
                return yx_error(p, "out of memory recording integer error");
            p->at = at;
            p->recoverable_unknown_identifier = false;
            return 0;
        }
        magnitude *= multiplier;
        metadata->value_type = YRX_I64;
        metadata->value.i64 = negative ? -(int64_t)magnitude : (int64_t)magnitude;
    }
    p->at = at;
    return 1;
}

static int yx_hex_bound(yx_parser *p, uint32_t *value)
{
    const char *literal_start = p->at;
    const char *at = p->at;
    unsigned base = 10;
    uint32_t result = 0;
    bool seen = false, overflow = false;
    if (at[0] == '0' && (at[1] == 'x' || at[1] == 'X')) {
        base = 16;
        at += 2;
    } else if (at[0] == '0' && (at[1] == 'o' || at[1] == 'O')) {
        base = 8;
        at += 2;
    }
    for (;;) {
        int digit = yx_hex_digit(*at);
        if (digit < 0 || (unsigned)digit >= base) break;
        if (!overflow) {
            if (result > (UINT32_MAX - (unsigned)digit) / base)
                overflow = true;
            else result = result * base + (unsigned)digit;
        }
        ++at;
        seen = true;
    }
    if (!seen) return yx_error(p, "invalid hex jump bound");
    p->at = at;
    if (overflow) {
        if (yx_compiler_invalid_integer_error(
                p->compiler, p->begin, p->origin,
                (size_t)(literal_start - p->begin),
                (size_t)(at - p->begin), "[0, 4294967295]"))
            p->recoverable_invalid_pattern = true;
        return 0;
    }
    *value = result;
    return 1;
}

static int yx_invalid_pattern(yx_parser *p, const char *start,
                              const char *end, const char *label,
                              const char *note)
{
    if (!p->current_pattern_identifier ||
        !yx_compiler_invalid_pattern_error(
            p->compiler, p->current_pattern_identifier, p->begin, p->origin,
            (size_t)(start - p->begin), (size_t)(end - p->begin),
            label, note))
        return 0;
    p->recoverable_invalid_pattern = true;
    return 0;
}

static int yx_warn_jump_run(yx_parser *p, const char *start,
                            const char *end, uint64_t lower, uint64_t upper,
                            bool has_lower, bool has_upper)
{
    return yx_compiler_consecutive_jumps_warning(
        p->compiler, p->current_pattern_identifier, p->begin, p->origin,
        (size_t)(start - p->begin), (size_t)(end - p->begin), lower, upper,
        has_lower, has_upper);
}

static int yx_parse_hex_sequence(yx_parser *p, yx_hex_sequence *sequence,
                                  unsigned depth, bool *complex);

static int yx_parse_hex_alternative(yx_parser *p, yx_hex_atom *atom,
                                     unsigned depth, bool *complex)
{
    ++p->at; /* '(' */
    atom->kind = YX_HEX_ALTERNATIVE;
    *complex = true;
    for (;;) {
        yx_hex_sequence branch = {0};
        yx_hex_sequence *grown;
        if (!yx_parse_hex_sequence(p, &branch, depth + 1, complex)) {
            yx_free_hex_atoms(branch.atoms, branch.count);
            goto failure;
        }
        yx_space(p);
        if (!branch.count) {
            yx_free_hex_atoms(branch.atoms, branch.count);
            yx_error(p, "empty hex alternative");
            goto failure;
        }
        if (atom->branch_count >= SIZE_MAX / sizeof(yx_hex_sequence)) {
            yx_free_hex_atoms(branch.atoms, branch.count);
            yx_error(p, "too many hex alternatives");
            goto failure;
        }
        grown = realloc(atom->branches, (atom->branch_count + 1) * sizeof(*grown));
        if (!grown) {
            yx_free_hex_atoms(branch.atoms, branch.count);
            yx_error(p, "out of memory");
            goto failure;
        }
        atom->branches = grown;
        atom->branches[atom->branch_count++] = branch;
        if (*p->at == '|') { ++p->at; continue; }
        if (*p->at == ')') { ++p->at; break; }
        if (*p->at == '}')
            yx_syntax_expected(p, p->at, p->at + 1,
                                "`[`, BYTE, `(`, `|` or `)`");
        else
            yx_error(p, "unterminated hex alternative");
        goto failure;
    }
    return 1;
failure:
    for (size_t i = 0; i < atom->branch_count; ++i)
        yx_free_hex_atoms(atom->branches[i].atoms, atom->branches[i].count);
    free(atom->branches);
    atom->branches = NULL;
    atom->branch_count = 0;
    return 0;
}

static int yx_parse_hex_sequence(yx_parser *p, yx_hex_sequence *sequence,
                                  unsigned depth, bool *complex)
{
    bool jump_run = false;
    bool jump_run_has_lower = false;
    bool jump_run_zero_max = true;
    bool jump_run_unbounded = false;
    /* Coalescing adds the bounds as u32 (hex2hir.rs); an overflow is an
     * error before any warning about the run. */
    bool jump_run_overflow = false;
    const char *jump_run_start = NULL;
    const char *jump_run_end = NULL;
    uint64_t jump_run_lower = 0, jump_run_upper = 0;
    size_t jump_run_count = 0;
    /* The syntax check reports alternatives nested beyond YARA-X's
     * MAX_CST_DEPTH (497 levels) as "nesting limit reached"; this bound
     * only protects the recursion when that check could not run. */
    if (depth > 1024) return yx_error(p, "hex alternatives are nested too deeply");
    for (;;) {
        yx_hex_atom atom = {0};
        yx_space(p);
        if (*p->at == '}' || *p->at == ')' || *p->at == '|') {
            if (jump_run_overflow)
                return yx_invalid_pattern(
                    p, jump_run_start, jump_run_end,
                    "jump exceeds maximum allowed bound (4294967295)",
                    "consecutive jumps were coalesced into a single one");
            if (jump_run_count >= 2 &&
                !yx_warn_jump_run(p, jump_run_start, jump_run_end,
                                  jump_run_lower, jump_run_upper,
                                  jump_run_has_lower, !jump_run_unbounded))
                return 0;
            if (sequence->count &&
                sequence->atoms[sequence->count - 1].kind == YX_HEX_JUMP)
                return *p->at == '}' ?
                    yx_syntax_expected(p, p->at, p->at + 1,
                                        "`[`, BYTE or `(`") :
                    yx_error(p, "hex jump cannot end a subpattern");
            return 1;
        }
        if (!*p->at) return yx_error(p, "unterminated hex pattern");
        if (*p->at != '[') {
            if (jump_run_overflow)
                return yx_invalid_pattern(
                    p, jump_run_start, jump_run_end,
                    "jump exceeds maximum allowed bound (4294967295)",
                    "consecutive jumps were coalesced into a single one");
            if (jump_run_count >= 2 &&
                !yx_warn_jump_run(p, jump_run_start, jump_run_end,
                                  jump_run_lower, jump_run_upper,
                                  jump_run_has_lower, !jump_run_unbounded))
                return 0;
            if (jump_run && jump_run_has_lower && jump_run_zero_max)
                return yx_invalid_pattern(
                    p, jump_run_start, jump_run_end,
                    "zero-length jumps are useless, remove it", NULL);
            jump_run = false;
            jump_run_has_lower = false;
            jump_run_zero_max = true;
            jump_run_unbounded = false;
            jump_run_overflow = false;
            jump_run_start = jump_run_end = NULL;
            jump_run_lower = jump_run_upper = 0;
            jump_run_count = 0;
        }
        if (*p->at == '(') {
            if (!yx_parse_hex_alternative(p, &atom, depth, complex)) return 0;
        } else if (*p->at == '[') {
            uint32_t lower = 0, upper = 0;
            bool lower_present, upper_present = true;
            const char *jump_start = p->at;
            if (!sequence->count)
                return yx_syntax_expected(p, p->at, p->at + 1,
                                           "BYTE or `(`");
            ++p->at;
            yx_space(p);
            lower_present = isdigit((unsigned char)*p->at) != 0;
            if (lower_present && !yx_hex_bound(p, &lower)) return 0;
            yx_space(p);
            if (*p->at == '-') {
                ++p->at;
                yx_space(p);
                if (isdigit((unsigned char)*p->at)) {
                    if (!yx_hex_bound(p, &upper)) return 0;
                    atom.finite_maximum = upper == UINT32_MAX;
                } else {
                    upper = UINT32_MAX;
                    upper_present = false;
                }
            } else {
                if (!lower_present) return yx_error(p, "invalid hex jump");
                upper = lower;
                atom.finite_maximum = upper == UINT32_MAX;
            }
            if (upper < lower) {
                char label[160];
                snprintf(label, sizeof(label),
                         "lower bound (%llu) is greater than upper bound (%llu)",
                         (unsigned long long)(jump_run_lower + lower),
                         (unsigned long long)(jump_run_upper + upper));
                if (*p->at == ']') {
                    if (jump_run_count &&
                        !yx_warn_jump_run(p, jump_run_start, p->at + 1,
                                          jump_run_lower + lower,
                                          jump_run_upper + upper,
                                          jump_run_has_lower || lower_present,
                                          !jump_run_unbounded && upper_present))
                        return 0;
                    return yx_invalid_pattern(
                        p, jump_run_start ? jump_run_start : jump_start,
                        p->at + 1, label,
                        jump_run_start ?
                        "consecutive jumps were coalesced into a single one" :
                        NULL);
                }
                return yx_error(p, "invalid hex jump range");
            }
            yx_space(p);
            if (*p->at != ']') {
                if (*p->at == '-')
                    return yx_syntax_expected(p, p->at, p->at + 1, "`]`");
                return yx_error(p, "expected ']'");
            }
            ++p->at;
            if (!jump_run_start) jump_run_start = jump_start;
            jump_run_end = p->at;
            if (jump_run_lower + lower > UINT32_MAX ||
                (!jump_run_unbounded && upper_present &&
                 jump_run_upper + upper > UINT32_MAX))
                jump_run_overflow = true;
            jump_run_lower += lower;
            jump_run_upper += upper;
            ++jump_run_count;
            jump_run = true;
            jump_run_has_lower |= lower_present;
            jump_run_unbounded |= !upper_present;
            jump_run_zero_max &= upper == 0;
            atom.kind = YX_HEX_JUMP;
            atom.minimum = lower;
            atom.maximum = upper;
            *complex = true;
        } else {
            int hi, lo;
            const char *byte_start = p->at;
            if (*p->at == '~') { atom.negated = true; *complex = true; ++p->at; }
            hi = *p->at == '?' ? -1 : yx_hex_digit(*p->at);
            if (hi < 0 && *p->at != '?') {
                const char *end = atom.negated ? byte_start + 1 :
                    yx_syntax_token_end(byte_start);
                const char *expected = sequence->count ?
                    "`[`, BYTE, `(` or `}`" : "BYTE or `(`";
                return yx_syntax_expected(p, byte_start, end, expected);
            }
            ++p->at;
            lo = *p->at == '?' ? -1 : yx_hex_digit(*p->at);
            if (lo < 0 && *p->at != '?') {
                const char *expected = sequence->count ?
                    "`[`, BYTE, `(` or `}`" : "BYTE or `(`";
                if (!atom.negated &&
                    strncmp(byte_start, "condition", 9) == 0 &&
                    !yx_word_char(byte_start[9])) {
                    yx_parser section_probe = *p;
                    section_probe.at = byte_start + 9;
                    yx_syntax_expected(p, byte_start, section_probe.at,
                                       expected);
                    yx_space(&section_probe);
                    if (*section_probe.at != ':')
                        yx_syntax_expected(
                            p, section_probe.at,
                            yx_syntax_token_end(section_probe.at), "`:`");
                    return 0;
                }
                return yx_syntax_expected(
                    p, byte_start,
                    atom.negated ? byte_start + 1 :
                    yx_syntax_token_end(byte_start), expected);
            }
            ++p->at;
            atom.kind = YX_HEX_BYTE;
            atom.value = (uint8_t)(((hi < 0 ? 0 : hi) << 4) | (lo < 0 ? 0 : lo));
            atom.mask = (uint8_t)((hi < 0 ? 0 : 0xf0) | (lo < 0 ? 0 : 0x0f));
            if (atom.negated && !atom.mask)
                return yx_invalid_pattern(
                    p, byte_start, p->at,
                    "negation of `??` is not allowed", NULL);
        }
        if (!yx_push_hex_atom(sequence, atom)) {
            for (size_t i = 0; i < atom.branch_count; ++i)
                yx_free_hex_atoms(atom.branches[i].atoms, atom.branches[i].count);
            free(atom.branches);
            return yx_error(p, "out of memory");
        }
    }
}

static size_t yx_hex_minimum(const yx_hex_atom *atoms, size_t count)
{
    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t amount = 0;
        if (atoms[i].kind == YX_HEX_BYTE) amount = 1;
        else if (atoms[i].kind == YX_HEX_JUMP) amount = atoms[i].minimum;
        else {
            amount = SIZE_MAX;
            for (size_t j = 0; j < atoms[i].branch_count; ++j) {
                size_t branch = yx_hex_minimum(atoms[i].branches[j].atoms,
                                               atoms[i].branches[j].count);
                if (branch < amount) amount = branch;
            }
        }
        if (amount > SIZE_MAX - total) return SIZE_MAX;
        total += amount;
    }
    return total;
}

static int yx_hex_pattern(yx_parser *p, YRX_PATTERN *pattern)
{
    yx_hex_sequence sequence = {0};
    bool complex = false;
    size_t minimum;
    p->recover_inside_hex = true;
    if (!yx_expect(p, '{')) return 0;
    if (!yx_parse_hex_sequence(p, &sequence, 0, &complex)) goto failure;
    yx_space(p);
    if (*p->at != '}') {
        yx_error(p, "unexpected delimiter in hex pattern");
        goto failure;
    }
    ++p->at;
    if (!sequence.count) {
        yx_syntax_expected(p, p->at - 1, p->at, "BYTE or `(`");
        goto failure;
    }
    minimum = yx_hex_minimum(sequence.atoms, sequence.count);
    if (minimum == 0 || minimum == SIZE_MAX) {
        yx_error(p, "hex pattern can match an empty or oversized span");
        goto failure;
    }
    pattern->hex_atoms = sequence.atoms;
    pattern->hex_atom_count = sequence.count;
    pattern->hex_has_jump = complex;
    pattern->length = minimum;
    if (!complex) {
        pattern->bytes = malloc(sequence.count);
        pattern->mask = malloc(sequence.count);
        if (!pattern->bytes || !pattern->mask)
            return yx_error(p, "out of memory");
        for (size_t i = 0; i < sequence.count; ++i) {
            pattern->bytes[i] = sequence.atoms[i].value;
            pattern->mask[i] = sequence.atoms[i].mask;
        }
    }
    p->recover_inside_hex = false;
    return 1;
failure:
    yx_free_hex_atoms(sequence.atoms, sequence.count);
    return 0;
}

static bool yx_later_condition_section(const yx_parser *p);
static bool yx_later_condition_missing_colon(const yx_parser *p);

/* YARA-X's relaxed regexp mode removes an unrecognized escape and treats
 * malformed repetition braces as literals. An unmatched closing brace is a
 * literal in both modes. Keep this copy separate from the source text, which
 * diagnostics still use for their original positions. */
static bool yx_relaxed_valid_repeat(const char *body, size_t length,
                                    size_t start, size_t *end,
                                    bool *missing_lower, bool *overflow)
{
    size_t at = start + 1;
    uint64_t lower = 0, upper = 0;
    bool upper_present = false;
    *missing_lower = false;
    *overflow = false;
    if (at >= length) return false;
    if (isdigit((unsigned char)body[at])) {
        do {
            unsigned digit = (unsigned)(body[at++] - '0');
            if (lower > (UINT32_MAX - digit) / 10u) {
                *overflow = true;
                return false;
            }
            lower = lower * 10u + digit;
        } while (at < length && isdigit((unsigned char)body[at]));
    } else if (body[at] == ',' && at + 1 < length &&
               isdigit((unsigned char)body[at + 1])) {
        *missing_lower = true;
    } else {
        return false;
    }
    if (at < length && body[at] == ',') {
        ++at;
        while (at < length && isdigit((unsigned char)body[at])) {
            unsigned digit = (unsigned)(body[at++] - '0');
            if (upper > (UINT32_MAX - digit) / 10u) {
                *overflow = true;
                return false;
            }
            upper = upper * 10u + digit;
            upper_present = true;
        }
        if (upper_present && upper < lower) return false;
    }
    if (at >= length || body[at] != '}') return false;
    *end = at;
    return true;
}

_Thread_local bool yx_condition_relaxed_regexps;

char *yx_normalize_regexp_braces(const char *body, bool relaxed)
{
    size_t length = strlen(body), used = 0, pending_open = 0;
    bool in_class = false;
    char *out;
    if (length > (SIZE_MAX - 1) / 2) return NULL;
    out = malloc(length * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < length; ++i) {
        char ch = body[i];
        if (ch == '\\' && i + 1 < length) {
            unsigned char escaped = (unsigned char)body[++i];
            /* regex-syntax rejects assertions inside a class
             * (ClassEscapeInvalid); relaxed mode drops their backslash. */
            if (relaxed && in_class && escaped && strchr("bBAz<>", escaped)) {
                out[used++] = (char)escaped;
                continue;
            }
            if (!relaxed || !yx_regex_unrecognized_escape(escaped))
                out[used++] = '\\';
            out[used++] = (char)escaped;
            continue;
        }
        if (ch == '[' && !in_class) in_class = true;
        else if (ch == ']' && in_class) in_class = false;
        if (!in_class && ch == '{') {
            size_t end;
            bool missing_lower, overflow;
            if (yx_relaxed_valid_repeat(body, length, i, &end,
                                        &missing_lower, &overflow)) {
                size_t count = end - i + 1;
                if (relaxed && missing_lower) {
                    out[used++] = '{';
                    out[used++] = '0';
                    ++i;
                    --count;
                }
                memcpy(out + used, body + i, count);
                used += count;
                i = end;
                continue;
            }
            if (overflow && relaxed) {
                free(out);
                return yx_duplicate(body, length);
            }
            if (relaxed) out[used++] = '\\';
            else ++pending_open;
        } else if (!in_class && ch == '}') {
            if (relaxed || pending_open == 0) out[used++] = '\\';
            else --pending_open;
        }
        out[used++] = ch;
    }
    out[used] = '\0';
    return out;
}

static bool yx_pattern_modifier_name(const char *start, size_t length)
{
    static const char *const names[] = {
        "ascii", "wide", "nocase", "fullword", "xor", "base64",
        "base64wide", "private"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (strlen(names[i]) == length &&
            memcmp(start, names[i], length) == 0) return true;
    return false;
}

static int yx_regex_pattern(yx_parser *p, YRX_PATTERN *pattern)
{
    const char *slash = p->at;
    ++p->at;
    const char *start = p->at;
    while (*p->at && *p->at != '/' && *p->at != '\n') {
        if (*p->at == '\\' && p->at[1] && p->at[1] != '\n') p->at += 2;
        else ++p->at;
    }
    if (*p->at != '/') {
        const char *end = p->at;
        if (*end == '\n' && end > start && end[-1] == '\r') --end;
        yx_syntax_label(p, slash, end, "unclosed regular expression");
        return 0;
    }
    pattern->regexp = yx_duplicate(start, (size_t)(p->at - start));
    if (!pattern->regexp) return yx_error(p, "out of memory");
    ++p->at;
    const char *suffix_start = p->at;
    const char *suffix_end = suffix_start;
    while (yx_word_char(*suffix_end)) ++suffix_end;
    for (unsigned suffixes = 0;
         suffixes < 2 && (*p->at == 'i' || *p->at == 's');
         ++suffixes) {
        if (*p->at == 'i') pattern->modifiers |= YX_MOD_NOCASE;
        if (*p->at == 's') pattern->modifiers |= YX_MOD_DOTALL;
        ++p->at;
    }
    if (isalpha((unsigned char)*p->at)) {
        if (p->at - suffix_start >= 2) return 1;
        if (yx_compiler_invalid_regexp_modifier_error(
                p->compiler, p->begin, p->origin,
                (size_t)(p->at - p->begin),
                (size_t)(p->at + 1 - p->begin)))
            p->recoverable_invalid_regexp = true;
        /* The regexp token consumes two letters at most.  A digit or
           underscore directly after its first invalid letter starts the
           following token instead. */
        const char *remaining = suffix_start + 2;
        if (p->at == suffix_start &&
            (isdigit((unsigned char)p->at[1]) || p->at[1] == '_'))
            remaining = p->at + 1;
        if (remaining < suffix_end) {
            const char *recovery_end = yx_syntax_token_end(remaining);
            if (recovery_end > suffix_end) recovery_end = suffix_end;
            size_t remaining_length = (size_t)(recovery_end - remaining);
            yx_parser probe = *p;
            probe.at = suffix_end;
            if (!yx_pattern_modifier_name(remaining, remaining_length) &&
                !(remaining_length == 9 &&
                  memcmp(remaining, "condition", 9) == 0) &&
                (yx_later_condition_section(&probe) ||
                 yx_later_condition_missing_colon(&probe)))
                yx_syntax_expected(p, remaining, recovery_end,
                    "pattern modifier, pattern identifier or `condition`");
            /* A numeric token can be followed immediately by the section
               keyword. Recovery then expects its colon at the next token. */
            if (isdigit((unsigned char)*remaining) &&
                (size_t)(suffix_end - recovery_end) == 9 &&
                memcmp(recovery_end, "condition", 9) == 0 &&
                yx_later_condition_section(&probe)) {
                yx_space(&probe);
                if (*probe.at && *probe.at != '}')
                    yx_syntax_expected(p, probe.at,
                        yx_syntax_token_end(probe.at), "`:`");
            }
        }
        return 0;
    }
    return 1;
}

static int yx_xor_byte(yx_parser *p, unsigned *value)
{
    const char *literal_start = p->at;
    const char *at = p->at;
    unsigned radix = 10;
    unsigned parsed = 0;
    bool has_digit = false, overflow = false;
    if (at[0] == '0' && (at[1] == 'x' || at[1] == 'o')) {
        radix = at[1] == 'x' ? 16 : 8;
        at += 2;
    }
    for (;;) {
        int digit = yx_hex_digit((unsigned char)*at);
        if (digit >= 0 && (unsigned)digit < radix) {
            has_digit = true;
            if (!overflow) {
                if (parsed > (255u - (unsigned)digit) / radix)
                    overflow = true;
                else parsed = parsed * radix + (unsigned)digit;
            }
            ++at;
        } else if (*at == '_' && has_digit) {
            ++at;
        } else {
            break;
        }
    }
    if (!has_digit) return 0;
    p->at = at;
    if (overflow) {
        if (yx_compiler_invalid_integer_error(
                p->compiler, p->begin, p->origin,
                (size_t)(literal_start - p->begin),
                (size_t)(at - p->begin), "[0, 255]"))
            p->recoverable_invalid_pattern = true;
        return 0;
    }
    *value = parsed;
    return 1;
}

static int yx_parse_modifiers(yx_parser *p, YRX_PATTERN *pattern)
{
    bool inline_nocase = pattern->kind == YX_PATTERN_REGEX &&
                         (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool explicit_nocase = false;
    for (;;) {
        const char *saved = p->at;
        char *word = yx_ident(p);
        if (!word) return 1;
        const char *modifier_start = p->at - strlen(word);
        /* The modifier's span ends with its word, or with the `)` closing
         * its arguments: never past whitespace or a comment after it. */
        const char *token_end = p->at;
        unsigned bit = 0;
        if (strcmp(word, "ascii") == 0) bit = YX_MOD_ASCII;
        else if (strcmp(word, "wide") == 0) bit = YX_MOD_WIDE;
        else if (strcmp(word, "nocase") == 0) bit = YX_MOD_NOCASE;
        else if (strcmp(word, "fullword") == 0) bit = YX_MOD_FULLWORD;
        else if (strcmp(word, "xor") == 0) bit = YX_MOD_XOR;
        else if (strcmp(word, "base64") == 0) bit = YX_MOD_BASE64;
        else if (strcmp(word, "base64wide") == 0) bit = YX_MOD_BASE64WIDE;
        else if (strcmp(word, "private") == 0) bit = YX_MOD_PRIVATE;
        if (!bit) {
            free(word);
            p->at = saved;
            return 1;
        }
        if ((pattern->modifiers & bit) &&
            !(bit == YX_MOD_NOCASE && inline_nocase && !explicit_nocase)) {
            const char *modifier_end = p->at;
            const char *argument = p->at;
            while (isspace((unsigned char)*argument)) ++argument;
            if (*argument == '(') {
                const char *closing = strchr(argument, ')');
                if (closing) modifier_end = closing + 1;
            }
            if (yx_compiler_duplicate_modifier_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(modifier_start - p->begin),
                    (size_t)(modifier_end - p->begin)))
                p->recoverable_invalid_pattern = true;
            free(word);
            return 0;
        }
        pattern->modifiers |= bit;
        unsigned modifier_index = 0;
        while ((1u << modifier_index) != bit) ++modifier_index;
        p->modifier_start[modifier_index] = modifier_start;
        if (bit == YX_MOD_NOCASE) explicit_nocase = true;
        if (bit == YX_MOD_BASE64 || bit == YX_MOD_BASE64WIDE) {
            char **alphabet = bit == YX_MOD_BASE64 ?
                &pattern->base64_alphabet : &pattern->base64wide_alphabet;
            yx_space(p);
            if (*p->at == '(') {
                const char *start;
                unsigned char seen[128] = {0};
                ++p->at;
                if (yx_reject_escaped_name_string(p)) {
                    free(word);
                    return 0;
                }
                yx_space(p);
                if (*p->at != '"') {
                    free(word);
                    return yx_error(p, "expected base64 alphabet string");
                }
                start = ++p->at;
                while (*p->at && *p->at != '"') {
                    if (*p->at == '\\') {
                        free(word);
                        return yx_error(p, "escape sequences are not allowed in a base64 alphabet");
                    }
                    ++p->at;
                }
                if (*p->at != '"') {
                    free(word);
                    return yx_error(p, "unterminated base64 alphabet");
                }
                if ((size_t) (p->at - start) != 64) {
                    if (yx_compiler_invalid_base64_alphabet_error(
                            p->compiler, p->begin, p->origin,
                            (size_t)(start - 1 - p->begin),
                            (size_t)(p->at + 1 - p->begin),
                            "invalid length - must be 64 bytes"))
                        p->recoverable_invalid_pattern = true;
                    ++p->at;
                    free(word);
                    return 0;
                }
                for (size_t i = 0; i < 64; ++i) {
                    unsigned char byte = (unsigned char) start[i];
                    if (byte < 32 || byte > 126 || byte == '=' || seen[byte]) {
                        char label[64];
                        snprintf(label, sizeof(label), "%s byte: 0x%02x",
                                 byte == '=' ? "reserved" :
                                 byte < 128 && seen[byte] ?
                                 "duplicated" : "invalid",
                                 byte);
                        if (yx_compiler_invalid_base64_alphabet_error(
                                p->compiler, p->begin, p->origin,
                                (size_t)(start - 1 - p->begin),
                                (size_t)(p->at + 1 - p->begin), label))
                            p->recoverable_invalid_pattern = true;
                        ++p->at;
                        free(word);
                        return 0;
                    }
                    seen[byte] = 1;
                }
                *alphabet = yx_duplicate(start, 64);
                if (!*alphabet) {
                    free(word);
                    return yx_error(p, "out of memory");
                }
                ++p->at;
                if (!yx_expect(p, ')')) {
                    free(word);
                    return 0;
                }
                token_end = p->at;
            }
        }
        if (bit == YX_MOD_XOR) {
            pattern->xor_min = 0;
            pattern->xor_max = 255;
            yx_space(p);
            if (*p->at == '(') {
                ++p->at;
                yx_space(p);
                unsigned min;
                if (!yx_xor_byte(p, &min)) {
                    free(word);
                    if (p->recoverable_invalid_pattern) return 0;
                    return yx_error(p, "invalid xor range");
                }
                yx_space(p);
                unsigned max = min;
                if (*p->at == '-') {
                    ++p->at;
                    yx_space(p);
                    if (!yx_xor_byte(p, &max)) {
                        free(word);
                        if (p->recoverable_invalid_pattern) return 0;
                        return yx_error(p, "invalid xor range");
                    }
                    if (max < min) {
                        yx_space(p);
                        if (*p->at == ')' &&
                            yx_compiler_invalid_range_error(
                                p->compiler, p->begin, p->origin,
                                (size_t)(modifier_start - p->begin),
                                (size_t)(p->at + 1 - p->begin),
                                (int64_t)min, (int64_t)max)) {
                            p->recoverable_invalid_pattern = true;
                            free(word);
                            return 0;
                        }
                        free(word);
                        return yx_error(p, "invalid xor range");
                    }
                }
                if (!yx_expect(p, ')')) {
                    free(word);
                    return 0;
                }
                token_end = p->at;
                pattern->xor_min = (uint8_t)min;
                pattern->xor_max = (uint8_t)max;
            }
        }
        p->modifier_end[modifier_index] = token_end;
        free(word);
    }
}

/* Indexes over one rule's patterns while its strings section is parsed.
 * The duplicate identifier and duplicate value checks scanned every earlier
 * pattern, quadratic in the pattern count; from YX_PATTERN_INDEX_MINIMUM
 * patterns on they use open-addressed tables instead. A table entry is
 * unique per key (identifiers are unique, values keep only the first of
 * equal patterns), so a lookup returns the lowest index the scans found.
 * capacity is the allocated length of rule->patterns. */
#define YX_PATTERN_INDEX_MINIMUM 16

typedef struct yx_pattern_table {
    size_t *slots; /* pattern index + 1; 0 is an empty slot */
    uint64_t *hashes;
    size_t slot_count;
    size_t count;
    bool built;
} yx_pattern_table;

typedef struct yx_pattern_index {
    size_t capacity;
    yx_pattern_table identifiers;
    yx_pattern_table values;
} yx_pattern_index;

static uint64_t yx_pattern_hash_bytes(uint64_t hash, const void *data,
                                      size_t length)
{
    const uint8_t *bytes = (const uint8_t *) data;
    for (size_t i = 0; i < length; ++i)
        hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    return hash;
}

static uint64_t yx_pattern_hash_word(uint64_t hash, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        hash = (hash ^ (uint8_t) (value >> (8 * i))) * UINT64_C(1099511628211);
    return hash;
}

static uint64_t yx_pattern_hash_string(uint64_t hash, const char *string)
{
    if (!string) return yx_pattern_hash_word(hash, 0);
    hash = yx_pattern_hash_word(hash, 1);
    return yx_pattern_hash_bytes(hash, string, strlen(string));
}

static uint64_t yx_pattern_identifier_hash(const char *identifier)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (const unsigned char *at = (const unsigned char *) identifier; *at; ++at)
        hash = (hash ^ *at) * UINT64_C(1099511628211);
    return hash;
}

/* Hashes exactly the fields yx_same_pattern_value compares (hex atoms only
 * at the top level), so equal values hash equally. */
static uint64_t yx_pattern_value_hash(const YRX_PATTERN *pattern)
{
    unsigned modifiers = pattern->modifiers;
    uint64_t hash = UINT64_C(1469598103934665603);
    if (!(modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)))
        modifiers |= YX_MOD_ASCII;
    hash = yx_pattern_hash_word(hash, (uint64_t) pattern->kind);
    hash = yx_pattern_hash_word(hash, modifiers);
    hash = yx_pattern_hash_word(hash, (uint64_t) pattern->xor_min << 8 |
                                      pattern->xor_max);
    hash = yx_pattern_hash_string(hash, pattern->base64_alphabet);
    hash = yx_pattern_hash_string(hash, pattern->base64wide_alphabet);
    if (pattern->kind == YX_PATTERN_TEXT) {
        hash = yx_pattern_hash_word(hash, pattern->length);
        return yx_pattern_hash_bytes(hash, pattern->bytes, pattern->length);
    }
    if (pattern->kind == YX_PATTERN_REGEX)
        return yx_pattern_hash_string(hash, pattern->regexp);
    hash = yx_pattern_hash_word(hash, pattern->hex_atom_count);
    for (size_t i = 0; i < pattern->hex_atom_count; ++i) {
        const yx_hex_atom *atom = &pattern->hex_atoms[i];
        hash = yx_pattern_hash_word(hash, (uint64_t) atom->kind << 32 |
                                          (uint64_t) atom->value << 24 |
                                          (uint64_t) atom->mask << 16 |
                                          (uint64_t) atom->negated << 8 |
                                          (uint64_t) atom->finite_maximum);
        hash = yx_pattern_hash_word(hash, (uint64_t) atom->minimum << 32 |
                                          atom->maximum);
        hash = yx_pattern_hash_word(hash, atom->branch_count);
    }
    return hash;
}

static void yx_pattern_table_free(yx_pattern_table *table)
{
    free(table->slots);
    free(table->hashes);
    memset(table, 0, sizeof(*table));
}

/* The caller checked that no entry with an equal key exists. */
static bool yx_pattern_table_insert(yx_pattern_table *table, size_t index,
                                    uint64_t hash)
{
    size_t at;
    if ((table->count + 1) * 2 > table->slot_count) {
        size_t slot_count = table->slot_count ? table->slot_count * 2 : 64;
        size_t *slots;
        uint64_t *hashes;
        while ((table->count + 1) * 2 > slot_count) slot_count *= 2;
        slots = (size_t *) calloc(slot_count, sizeof(*slots));
        hashes = (uint64_t *) malloc(slot_count * sizeof(*hashes));
        if (!slots || !hashes) {
            free(slots);
            free(hashes);
            return false;
        }
        for (size_t i = 0; i < table->slot_count; ++i) {
            if (!table->slots[i]) continue;
            at = (size_t) table->hashes[i] & (slot_count - 1);
            while (slots[at]) at = (at + 1) & (slot_count - 1);
            slots[at] = table->slots[i];
            hashes[at] = table->hashes[i];
        }
        free(table->slots);
        free(table->hashes);
        table->slots = slots;
        table->hashes = hashes;
        table->slot_count = slot_count;
    }
    at = (size_t) hash & (table->slot_count - 1);
    while (table->slots[at]) at = (at + 1) & (table->slot_count - 1);
    table->slots[at] = index + 1;
    table->hashes[at] = hash;
    ++table->count;
    return true;
}

static size_t yx_pattern_identifier_find(const yx_pattern_table *table,
                                         const YRX_RULE *rule,
                                         const char *identifier,
                                         uint64_t hash)
{
    if (!table->slot_count) return SIZE_MAX;
    for (size_t at = (size_t) hash & (table->slot_count - 1); table->slots[at];
         at = (at + 1) & (table->slot_count - 1)) {
        size_t i = table->slots[at] - 1;
        if (table->hashes[at] == hash &&
            strcmp(rule->patterns[i].identifier, identifier) == 0) return i;
    }
    return SIZE_MAX;
}

static bool yx_same_pattern_value(const YRX_PATTERN *first,
                                  const YRX_PATTERN *second);

static size_t yx_pattern_value_find(const yx_pattern_table *table,
                                    const YRX_RULE *rule,
                                    const YRX_PATTERN *pattern, uint64_t hash)
{
    if (!table->slot_count) return SIZE_MAX;
    for (size_t at = (size_t) hash & (table->slot_count - 1); table->slots[at];
         at = (at + 1) & (table->slot_count - 1)) {
        size_t i = table->slots[at] - 1;
        if (table->hashes[at] == hash &&
            yx_same_pattern_value(&rule->patterns[i], pattern)) return i;
    }
    return SIZE_MAX;
}

static int yx_append_pattern(yx_parser *p, YRX_RULE *rule, YRX_PATTERN *pattern,
                             yx_pattern_index *index)
{
    yx_pattern_table *identifiers = &index->identifiers;
    bool anonymous = strcmp(pattern->identifier, "$") == 0;
    size_t existing = SIZE_MAX;
    uint64_t hash = 0;
    if (!identifiers->built && rule->pattern_count >= YX_PATTERN_INDEX_MINIMUM) {
        for (size_t i = 0; i < rule->pattern_count; ++i)
            if (strcmp(rule->patterns[i].identifier, "$") != 0 &&
                !yx_pattern_table_insert(
                    identifiers, i,
                    yx_pattern_identifier_hash(rule->patterns[i].identifier)))
                return yx_error(p, "out of memory");
        identifiers->built = true;
    }
    if (!anonymous && identifiers->built) {
        hash = yx_pattern_identifier_hash(pattern->identifier);
        existing = yx_pattern_identifier_find(identifiers, rule,
                                              pattern->identifier, hash);
    } else if (!anonymous) {
        for (size_t i = 0; i < rule->pattern_count; ++i)
            if (strcmp(rule->patterns[i].identifier, pattern->identifier) == 0) {
                existing = i;
                break;
            }
    }
    if (existing != SIZE_MAX) {
        if (yx_compiler_duplicate_pattern_error(
                p->compiler, pattern->identifier, p->begin, p->origin,
                pattern->declaration_start, pattern->declaration_end,
                rule->patterns[existing].declaration_start,
                rule->patterns[existing].declaration_end))
            p->recoverable_invalid_pattern = true;
        return 0;
    }
    if (rule->pattern_count >= index->capacity) {
        size_t capacity = rule->pattern_count < 8 ? 8 : rule->pattern_count * 2;
        YRX_PATTERN *grown;
        if (capacity > SIZE_MAX / sizeof(*grown)) return yx_error(p, "out of memory");
        grown = realloc(rule->patterns, capacity * sizeof(*grown));
        if (!grown) return yx_error(p, "out of memory");
        rule->patterns = grown;
        index->capacity = capacity;
    }
    rule->patterns[rule->pattern_count++] = *pattern;
    memset(pattern, 0, sizeof(*pattern));
    if (!anonymous && identifiers->built &&
        !yx_pattern_table_insert(identifiers, rule->pattern_count - 1, hash))
        return yx_error(p, "out of memory");
    return 1;
}

static bool yx_same_hex_atoms(const yx_hex_atom *first,
                              const yx_hex_atom *second, size_t count,
                              unsigned depth)
{
    if (depth > 32) return false;
    for (size_t i = 0; i < count; ++i) {
        if (first[i].kind != second[i].kind ||
            first[i].value != second[i].value ||
            first[i].mask != second[i].mask ||
            first[i].negated != second[i].negated ||
            first[i].minimum != second[i].minimum ||
            first[i].maximum != second[i].maximum ||
            first[i].finite_maximum != second[i].finite_maximum ||
            first[i].branch_count != second[i].branch_count)
            return false;
        for (size_t branch = 0; branch < first[i].branch_count; ++branch) {
            const yx_hex_sequence *a = &first[i].branches[branch];
            const yx_hex_sequence *b = &second[i].branches[branch];
            if (a->count != b->count ||
                !yx_same_hex_atoms(a->atoms, b->atoms, a->count, depth + 1))
                return false;
        }
    }
    return true;
}

static bool yx_same_optional_string(const char *first, const char *second)
{
    return (!first && !second) ||
           (first && second && strcmp(first, second) == 0);
}

static bool yx_same_pattern_value(const YRX_PATTERN *first,
                                  const YRX_PATTERN *second)
{
    unsigned first_modifiers = first->modifiers;
    unsigned second_modifiers = second->modifiers;
    if (!(first_modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)))
        first_modifiers |= YX_MOD_ASCII;
    if (!(second_modifiers & (YX_MOD_ASCII | YX_MOD_WIDE)))
        second_modifiers |= YX_MOD_ASCII;
    if (first->kind != second->kind ||
        first_modifiers != second_modifiers ||
        first->xor_min != second->xor_min ||
        first->xor_max != second->xor_max ||
        !yx_same_optional_string(first->base64_alphabet,
                                 second->base64_alphabet) ||
        !yx_same_optional_string(first->base64wide_alphabet,
                                 second->base64wide_alphabet))
        return false;
    if (first->kind == YX_PATTERN_TEXT)
        return first->length == second->length &&
               memcmp(first->bytes, second->bytes, first->length) == 0;
    if (first->kind == YX_PATTERN_REGEX)
        return yx_same_optional_string(first->regexp, second->regexp);
    return first->hex_atom_count == second->hex_atom_count &&
           yx_same_hex_atoms(first->hex_atoms, second->hex_atoms,
                             first->hex_atom_count, 0);
}

static int yx_warn_duplicate_pattern_value(yx_parser *p,
                                            const YRX_RULE *rule,
                                            yx_pattern_index *index)
{
    const YRX_PATTERN *duplicate = &rule->patterns[rule->pattern_count - 1];
    yx_pattern_table *values = &index->values;
    size_t first = 0, last = rule->pattern_count - 1;
    if (!values->built && last >= YX_PATTERN_INDEX_MINIMUM) {
        /* Keep the first pattern of every distinct value. */
        for (size_t i = 0; i < last; ++i) {
            uint64_t hash = yx_pattern_value_hash(&rule->patterns[i]);
            if (yx_pattern_value_find(values, rule, &rule->patterns[i], hash) == SIZE_MAX &&
                !yx_pattern_table_insert(values, i, hash)) return 0;
        }
        values->built = true;
    }
    if (values->built) {
        uint64_t hash = yx_pattern_value_hash(duplicate);
        first = yx_pattern_value_find(values, rule, duplicate, hash);
        if (first == SIZE_MAX) {
            if (!yx_pattern_table_insert(values, last, hash)) return 0;
            return 1;
        }
        last = first + 1;
    }
    for (size_t i = first; i < last; ++i) {
        const YRX_PATTERN *existing = &rule->patterns[i];
        size_t duplicate_start, existing_start;
        if (!yx_same_pattern_value(existing, duplicate)) continue;
        duplicate_start = duplicate->kind == YX_PATTERN_HEX ?
            duplicate->literal_start : duplicate->declaration_start;
        existing_start = existing->kind == YX_PATTERN_HEX ?
            existing->literal_start : existing->declaration_start;
        return yx_compiler_duplicate_pattern_value_warning(
            p->compiler, existing->identifier, p->begin, p->origin,
            duplicate_start, duplicate->kind == YX_PATTERN_HEX ?
                duplicate->literal_end : duplicate->pattern_end,
            existing_start, existing->kind == YX_PATTERN_HEX ?
                existing->literal_end : existing->pattern_end);
    }
    return 1;
}

#include "native_regex.h"
#include "regex_nest.inc"
#include "regex_ast_error.inc"
#include "regex_size.inc"

/* The Validator (re/parser.rs) visits repetitions in pre-order: the
 * outermost and leftmost first. The first one fixes the greediness; the
 * first later one that differs is the error, both spans reported. */
static bool yx_mixed_greediness_spans(const char *body, size_t length,
                                     size_t *greedy_start, size_t *greedy_end,
                                     size_t *lazy_start, size_t *lazy_end)
{
    size_t *groups = malloc((length ? length : 1) * sizeof(*groups));
    size_t *rep_starts = malloc((length ? length : 1) * sizeof(*rep_starts));
    size_t *rep_ends = malloc((length ? length : 1) * sizeof(*rep_ends));
    bool *rep_lazy = malloc((length ? length : 1) * sizeof(*rep_lazy));
    size_t depth = 0, atom_start = SIZE_MAX, rep_count = 0;
    size_t first = SIZE_MAX, other = SIZE_MAX;
    if (!groups || !rep_starts || !rep_ends || !rep_lazy) {
        free(groups); free(rep_starts); free(rep_ends); free(rep_lazy);
        return false;
    }
    for (size_t i = 0; i < length;) {
        unsigned char c = (unsigned char)body[i];
        if (c == '\\' && i + 1 < length) {
            atom_start = i;
            i += 2;
            continue;
        }
        if (c == '[') {
            size_t j = i + 1;
            if (j < length && body[j] == '^') ++j;
            if (j < length && body[j] == ']') ++j;
            while (j < length && body[j] != ']') {
                if (body[j] == '\\' && j + 1 < length) ++j;
                ++j;
            }
            atom_start = i;
            i = j < length ? j + 1 : length;
            continue;
        }
        if (c == '(') {
            groups[depth++] = i;
            atom_start = SIZE_MAX;
            ++i;
            continue;
        }
        if (c == ')') {
            atom_start = depth ? groups[--depth] : SIZE_MAX;
            ++i;
            continue;
        }
        if (c == '|' || c == '^' || c == '$') {
            atom_start = SIZE_MAX;
            ++i;
            continue;
        }
        if (c == '?' && i && body[i - 1] == '(') {
            ++i;
            continue;
        }
        if (c == '*' || c == '+' || c == '?' || c == '{') {
            size_t quantifier_end = i + 1;
            bool lazy;
            if (c == '{') {
                size_t j = i + 1;
                bool digits = false;
                while (j < length && isdigit((unsigned char)body[j])) {
                    digits = true;
                    ++j;
                }
                if (j < length && body[j] == ',') {
                    ++j;
                    while (j < length && isdigit((unsigned char)body[j])) {
                        digits = true;
                        ++j;
                    }
                }
                if (!digits || j >= length || body[j] != '}') {
                    atom_start = i++;
                    continue;
                }
                quantifier_end = j + 1;
            }
            lazy = quantifier_end < length && body[quantifier_end] == '?';
            if (lazy) ++quantifier_end;
            if (atom_start != SIZE_MAX) {
                rep_starts[rep_count] = atom_start;
                rep_ends[rep_count] = quantifier_end;
                rep_lazy[rep_count++] = lazy;
            }
            /* A subsequent quantifier repeats the complete previous
             * repetition. Its diagnostic span starts at the same atom. */
            i = quantifier_end;
            continue;
        }
        atom_start = i++;
    }
    /* Pre-order: by start, an enclosing repetition before the ones inside
     * it (a wider span at the same start). */
    for (size_t i = 0; i < rep_count; ++i)
        if (first == SIZE_MAX || rep_starts[i] < rep_starts[first] ||
            (rep_starts[i] == rep_starts[first] && rep_ends[i] > rep_ends[first]))
            first = i;
    for (size_t i = 0; first != SIZE_MAX && i < rep_count; ++i) {
        if (rep_lazy[i] == rep_lazy[first]) continue;
        if (other == SIZE_MAX || rep_starts[i] < rep_starts[other] ||
            (rep_starts[i] == rep_starts[other] && rep_ends[i] > rep_ends[other]))
            other = i;
    }
    if (other != SIZE_MAX) {
        size_t greedy = rep_lazy[first] ? other : first;
        size_t lazy = rep_lazy[first] ? first : other;
        *greedy_start = rep_starts[greedy];
        *greedy_end = rep_ends[greedy];
        *lazy_start = rep_starts[lazy];
        *lazy_end = rep_ends[lazy];
    }
    free(groups);
    free(rep_starts);
    free(rep_ends);
    free(rep_lazy);
    return other != SIZE_MAX;
}

static bool yx_regex_incomplete_trailing_escape(const char *body,
                                                size_t length)
{
    size_t slashes = 0;
    if (length < 2 || !strchr("xuUpP", body[length - 1])) return false;
    for (size_t i = length - 1; i > 0 && body[i - 1] == '\\'; --i)
        ++slashes;
    return (slashes & 1u) != 0;
}

typedef struct {
    size_t start;
    size_t end;
    const char *label;
} yx_regex_escape_issue;

/* regex-syntax consumes whitespace between the characters of an escape when
 * the x flag is active. In particular, a partial hex escape must be checked
 * against the original regexp, before PCRE2 can accept it as a different
 * escape. */
static size_t yx_regex_escape_skip_space(const char *body, size_t length,
                                         size_t at, bool extended)
{
    if (!extended) return at;
    while (at < length) {
        if (isspace((unsigned char)body[at])) { ++at; continue; }
        if (body[at] != '#') break;
        while (at < length && body[at] != '\n') ++at;
    }
    return at;
}

/* Return the first malformed x/u/U escape or a Unicode class used in byte
 * mode.  1 means an issue was found, 0 means none, -1 means allocation failed.
 * This deliberately leaves valid escapes to the existing regexp engine. */
static int yx_regex_escape_syntax_issue(const char *body, size_t length,
                                        yx_regex_escape_issue *issue)
{
    unsigned char *states = malloc(length + 1);
    size_t depth = 0, class_depth = 0;
    bool unicode = false, extended = false, in_class = false;
    if (!states) return -1;
    for (size_t i = 0; i < length; ++i) {
        char ch = body[i];
        if (ch == '\\' && i + 1 < length) {
            char escaped = body[i + 1];
            if (escaped == 'p' || escaped == 'P' ||
                escaped == 'x' || escaped == 'u' || escaped == 'U') {
                size_t at = yx_regex_escape_skip_space(
                    body, length, i + 2, extended);
                if (at == length) {
                    issue->start = issue->end = length;
                    issue->label = "incomplete escape sequence, reached end "
                                   "of pattern prematurely";
                    free(states);
                    return 1;
                }
                if (escaped == 'p' || escaped == 'P') {
                    if (body[at] == '{') {
                        ++at;
                        while (at < length && body[at] != '}') {
                            at = yx_regex_escape_skip_space(
                                body, length, at + 1, extended);
                        }
                        if (at == length) {
                            issue->start = issue->end = length;
                            issue->label = "incomplete escape sequence, "
                                           "reached end of pattern prematurely";
                            free(states);
                            return 1;
                        }
                    } else if (body[at] == '\\') {
                        issue->start = at;
                        issue->end = at + 1;
                        issue->label = "invalid Unicode character class";
                        free(states);
                        return 1;
                    }
                    if (!unicode) {
                        issue->start = i;
                        issue->end = at + 1;
                        issue->label = "Unicode not allowed here";
                        free(states);
                        return 1;
                    }
                    i = at;
                    continue;
                }
                if (body[at] == '{') {
                    size_t brace = at, first = at + 1;
                    uint32_t scalar = 0;
                    at = yx_regex_escape_skip_space(
                        body, length, first, extended);
                    first = at;
                    while (at < length && body[at] != '}') {
                        int digit = yx_hex_digit((unsigned char)body[at]);
                        if (digit < 0) {
                            issue->start = at;
                            issue->end = at + 1;
                            issue->label = "invalid hexadecimal digit";
                            free(states);
                            return 1;
                        }
                        if (scalar <= 0x10FFFFu)
                            scalar = scalar * 16u + (unsigned)digit;
                        at = yx_regex_escape_skip_space(
                            body, length, at + 1, extended);
                    }
                    if (at == length) {
                        issue->start = brace;
                        issue->end = length;
                        issue->label = "incomplete escape sequence, reached "
                                       "end of pattern prematurely";
                        free(states);
                        return 1;
                    }
                    if (at == first) {
                        issue->start = brace;
                        issue->end = at + 1;
                        issue->label = "hexadecimal literal empty";
                        free(states);
                        return 1;
                    }
                    if (scalar > 0x10FFFFu ||
                        (scalar >= 0xD800u && scalar <= 0xDFFFu)) {
                        issue->start = first;
                        issue->end = at;
                        issue->label = "hexadecimal literal is not a "
                                       "Unicode scalar value";
                        free(states);
                        return 1;
                    }
                    /* In a byte-mode character class only ASCII scalars are
                     * allowed; \x{..}, \u and \U escapes above 0x7F are
                     * rejected, while (?u) Unicode classes accept them. */
                    if (in_class && !unicode && scalar > 0x7Fu) {
                        issue->start = i;
                        issue->end = at + 1;
                        issue->label = "Unicode not allowed here";
                        free(states);
                        return 1;
                    }
                    i = at;
                    continue;
                }
                unsigned digits = escaped == 'x' ? 2u :
                                  escaped == 'u' ? 4u : 8u;
                size_t first = at;
                uint32_t scalar = 0;
                for (unsigned j = 0; j < digits; ++j) {
                    int digit;
                    if (at == length) {
                        issue->start = issue->end = length;
                        issue->label = "incomplete escape sequence, reached "
                                       "end of pattern prematurely";
                        free(states);
                        return 1;
                    }
                    digit = yx_hex_digit((unsigned char)body[at]);
                    if (digit < 0) {
                        issue->start = at;
                        issue->end = at + 1;
                        issue->label = "invalid hexadecimal digit";
                        free(states);
                        return 1;
                    }
                    if (scalar <= 0x10FFFFu)
                        scalar = scalar * 16u + (unsigned)digit;
                    at = yx_regex_escape_skip_space(
                        body, length, at + 1, extended);
                }
                if (scalar > 0x10FFFFu ||
                    (scalar >= 0xD800u && scalar <= 0xDFFFu)) {
                    issue->start = first;
                    issue->end = at;
                    issue->label = "hexadecimal literal is not a Unicode "
                                   "scalar value";
                    free(states);
                    return 1;
                }
                /* The fixed-width \xNN form is a byte escape and stays valid
                 * in classes at any value; \uNNNN and \UNNNNNNNN are Unicode
                 * escapes, rejected in byte-mode classes above 0x7F. */
                if (escaped != 'x' && in_class && !unicode &&
                    scalar > 0x7Fu) {
                    issue->start = i;
                    issue->end = at;
                    issue->label = "Unicode not allowed here";
                    free(states);
                    return 1;
                }
                i = at - 1;
                continue;
            }
            ++i;
            continue;
        }
        if (extended && !in_class && (isspace((unsigned char)ch) ||
                                      ch == '#')) {
            i = yx_regex_escape_skip_space(body, length, i, true) - 1;
            continue;
        }
        /* Classes nest ([a[b]], [a&&[b]]) and an ASCII class [:name:] or
         * [:^name:] inside a class is one item, so a `]` closes only the
         * innermost class. A `]` right after `[` or `[^` is a literal. */
        if (ch == '[' && in_class && i + 1 < length && body[i + 1] == ':') {
            size_t at = i + 2;
            if (at < length && body[at] == '^') ++at;
            while (at < length && isalpha((unsigned char)body[at])) ++at;
            if (at + 1 < length && body[at] == ':' && body[at + 1] == ']') {
                i = at + 1;
                continue;
            }
        }
        if (ch == '[') {
            in_class = true;
            ++class_depth;
            if (i + 1 < length && body[i + 1] == '^') ++i;
            if (i + 1 < length && body[i + 1] == ']') ++i;
            continue;
        }
        if (ch == ']' && in_class) { in_class = --class_depth != 0; continue; }
        if (in_class) {
            /* A literal non-ASCII character is rejected in a byte-mode
             * class with the same error YARA-X reports for braced escapes
             * above 0x7F; (?u) Unicode classes accept it. */
            if (!unicode && (unsigned char)ch >= 0x80) {
                size_t at = i + 1;
                while (at < length &&
                       ((unsigned char)body[at] & 0xc0) == 0x80)
                    ++at;
                issue->start = i;
                issue->end = at;
                issue->label = "Unicode not allowed here";
                free(states);
                return 1;
            }
            continue;
        }
        if (ch == '(') {
            size_t at = i + 2;
            bool next_unicode = unicode, next_extended = extended;
            bool negated = false, valid = body[i + 1] == '?';
            if (valid) {
                for (; at < length; ++at) {
                    char flag = body[at];
                    if (flag == '-') { negated = true; continue; }
                    if (flag == 'u') next_unicode = !negated;
                    else if (flag == 'x') next_extended = !negated;
                    else if (!strchr("imsUR", flag)) break;
                }
            }
            if (valid && at > i + 2 && at < length &&
                (body[at] == ')' || body[at] == ':')) {
                if (body[at] == ':')
                    states[depth++] = (unsigned char)((unicode ? 1 : 0) |
                                                       (extended ? 2 : 0));
                unicode = next_unicode;
                extended = next_extended;
                i = at;
                continue;
            }
            states[depth++] = (unsigned char)((unicode ? 1 : 0) |
                                               (extended ? 2 : 0));
        } else if (ch == ')' && depth) {
            unsigned char state = states[--depth];
            unicode = (state & 1) != 0;
            extended = (state & 2) != 0;
        }
    }
    free(states);
    return 0;
}

static int yx_report_regex_escape_issue(yx_parser *p, const char *body,
                                        size_t length)
{
    yx_regex_escape_issue issue;
    int result = yx_regex_escape_syntax_issue(body, length, &issue);
    if (result <= 0) return result;
    /* regex-syntax completes its AST parse before checking whether a Unicode
     * class is permitted in byte mode. Preserve the earlier diagnostics for
     * unknown escapes, backreferences, and malformed inline R flags. */
    if (yx_regex_inline_r_flag_error(body, length, NULL, NULL)) return 0;
    {
        yx_regex_ast_err ast_error;
        if (yx_regex_ast_error(body, length, &ast_error)) return 0;
    }
    for (size_t i = 0; i + 1 < length; ++i) {
        if (body[i] != '\\') continue;
        unsigned char escaped = (unsigned char)body[i + 1];
        if ((escaped >= '0' && escaped <= '9') ||
            yx_regex_unrecognized_escape(escaped))
            return 0;
        ++i;
    }
    size_t base = (size_t)(body - p->begin);
    if (!yx_compiler_invalid_regexp_error(
            p->compiler, p->begin, p->origin,
            base + issue.start, base + issue.end, issue.label, NULL))
        return -1;
    p->recoverable_invalid_regexp = true;
    return 1;
}

static bool yx_word_assertion_name(const char *name, size_t length,
                                   const char *expected)
{
    return strlen(expected) == length && memcmp(name, expected, length) == 0;
}

static const char yx_unknown_word_assertion_label[] =
    "unrecognized special word boundary assertion, valid choices are: "
    "start, end, start-half or end-half";
static const char yx_invalid_word_assertion_label[] =
    "special word boundary assertion is either unclosed or contains "
    "an invalid character";
static const char yx_empty_word_brace_label[] =
    "found either the beginning of a special word boundary or a bounded "
    "repetition on a \\b with an opening brace, but no closing brace";
static const char yx_word_repeat_decimal_label[] =
    "repetition quantifier expects a valid decimal";
static const char yx_word_repeat_overflow_label[] =
    "decimal literal invalid";
static const char yx_word_repeat_unclosed_label[] =
    "unclosed counted repetition";
static const char yx_word_repeat_decimal_note[] =
    "did you mean `\\{` instead of `{`?";

/* A missing lower bound is a valid counted repetition when the upper bound
 * is a decimal value, including zero. Leave overflowing counts to the
 * ordinary regexp diagnostic path. */
static bool yx_word_comma_repeat(const char *body, size_t length,
                                 size_t brace)
{
    size_t at = brace + 1;
    uint32_t upper = 0;
    bool has_upper = false;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    if (at >= length || body[at++] != ',') return false;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    while (at < length && isdigit((unsigned char)body[at])) {
        unsigned digit = (unsigned)(body[at] - '0');
        if (upper > (UINT32_MAX - digit) / 10u) return false;
        upper = upper * 10u + digit;
        has_upper = true;
        ++at;
    }
    while (at < length && isspace((unsigned char)body[at])) ++at;
    return has_upper && at < length && body[at] == '}';
}

/* regex-syntax parses the upper decimal before checking the closing brace.
 * Its u32 conversion highlights the digits (and skipped spaces in extended
 * mode) when the value overflows. */
static bool yx_word_comma_repeat_overflow(const char *body, size_t length,
                                           size_t brace, bool extended,
                                           size_t *digit_at, size_t *width)
{
    size_t at = brace + 1;
    uint32_t upper = 0;
    bool has_upper = false, overflow = false;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    if (at >= length || body[at++] != ',') return false;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    size_t start = at;
    while (at < length && isdigit((unsigned char)body[at])) {
        unsigned digit = (unsigned)(body[at] - '0');
        if (upper > (UINT32_MAX - digit) / 10u) overflow = true;
        if (!overflow) upper = upper * 10u + digit;
        has_upper = true;
        ++at;
        if (extended)
            while (at < length && isspace((unsigned char)body[at])) ++at;
    }
    size_t end = at;
    if (!has_upper || !overflow) return false;
    *digit_at = start;
    *width = end - start;
    return true;
}

/* After parsing `{,N`, regex-syntax expects `}`. A second comma is reported
 * on the opening brace through the complete upper decimal, before parsing
 * anything after that comma. */
static bool yx_word_comma_second_separator(const char *body, size_t length,
                                            size_t brace, bool extended,
                                            size_t *width)
{
    size_t at = brace + 1;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    if (at >= length || body[at++] != ',') return false;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    bool has_upper = false;
    while (at < length && isdigit((unsigned char)body[at])) {
        has_upper = true;
        ++at;
        if (extended)
            while (at < length && isspace((unsigned char)body[at])) ++at;
    }
    while (at < length && isspace((unsigned char)body[at])) ++at;
    if (!has_upper || at >= length || body[at] != ',') return false;
    *width = at - brace;
    return true;
}

/* regex-syntax first finds an empty lower decimal at the comma. If the next
 * character is not `}`, an empty upper decimal is reported there. At `}`,
 * extended mode (or no intervening space) uses the saved lower error. */
static bool yx_word_comma_empty_upper(const char *body, size_t length,
                                      size_t brace, bool extended,
                                      size_t *error_at)
{
    size_t at = brace + 1;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    if (at >= length || body[at] != ',') return false;
    size_t comma = at++;
    size_t upper_start = at;
    while (at < length && isspace((unsigned char)body[at])) ++at;
    if (at >= length || isdigit((unsigned char)body[at])) return false;
    *error_at = body[at] == '}' && (extended || at == upper_start) ?
        comma : at;
    return true;
}

static bool yx_regex_bad_prefix_before(const char *body, size_t before)
{
    size_t depth = 0;
    for (size_t i = 0; i < before; ++i) {
        if (body[i] == '\\' && i + 1 < before) {
            unsigned char escaped = (unsigned char)body[++i];
            if ((escaped >= '0' && escaped <= '9') ||
                yx_regex_unrecognized_escape(escaped)) return true;
        } else if (body[i] == '(') {
            ++depth;
        } else if (body[i] == ')') {
            if (!depth) return true;
            --depth;
        }
    }
    return false;
}

/* regex-syntax reports an unclosed `{,N` from the opening brace through the
 * parsed upper decimal. Inspect the regexp copy so a `}` in the surrounding
 * rule cannot be mistaken for the counted repetition's closing brace. */
static bool yx_unclosed_word_comma_repeat(const char *regexp, size_t length,
                                          size_t *brace_at, size_t *width)
{
    size_t group_depth = 0;
    if (memchr(regexp, '[', length) || memchr(regexp, '#', length))
        return false;
    for (size_t i = 0; i + 3 < length; ++i) {
        if (regexp[i] == '(') { ++group_depth; continue; }
        if (regexp[i] == ')') {
            if (!group_depth) return false;
            --group_depth;
            continue;
        }
        if (regexp[i] != '\\') continue;
        if ((regexp[i + 1] >= '0' && regexp[i + 1] <= '9') ||
            yx_regex_unrecognized_escape((unsigned char)regexp[i + 1]))
            return false;
        if (regexp[i + 1] != 'b' && regexp[i + 1] != 'B') {
            ++i;
            continue;
        }
        if (regexp[i + 2] != '{' || regexp[i + 3] != ',') {
            ++i;
            continue;
        }
        size_t at = i + 4;
        uint32_t upper = 0;
        bool has_upper = false, overflow = false;
        while (at < length && isspace((unsigned char)regexp[at])) ++at;
        while (at < length && isdigit((unsigned char)regexp[at])) {
            unsigned digit = (unsigned)(regexp[at] - '0');
            if (upper > (UINT32_MAX - digit) / 10u) overflow = true;
            if (!overflow) upper = upper * 10u + digit;
            has_upper = true;
            ++at;
        }
        if (overflow || !has_upper) { ++i; continue; }
        while (at < length && isspace((unsigned char)regexp[at])) ++at;
        if (at < length && regexp[at] == '}') {
            ++i;
            continue;
        }
        *brace_at = i + 2;
        *width = at - *brace_at;
        return true;
    }
    return false;
}

/* Regex-syntax checks a braced word assertion name before the Unicode-mode
 * validator. Track inline flags by group while finding either diagnostic. */
static bool yx_word_assertion_issue(const char *body, size_t length,
                                    const char **location, size_t *width,
                                    const char **label)
{
    struct yx_inline_flags { bool unicode, extended; };
    bool unicode = false, extended = false, in_class = false;
    struct yx_inline_flags *states =
        malloc((length ? length : 1) * sizeof(*states));
    size_t depth = 0;
    const char *unicode_at = NULL;
    size_t unicode_width = 0;
    if (!states) return false;
    for (size_t i = 0; i < length; ++i) {
        if (extended && !in_class && body[i] == '#') {
            while (i < length && body[i] != '\n') ++i;
            continue;
        }
        if (body[i] == '\\' && i + 1 < length) {
            char escaped = body[i + 1];
            if (escaped == 'b' || (!in_class && escaped == 'B')) {
                size_t span = 2;
                size_t empty_at = 0;
                if (!in_class && escaped == 'b' && i + 3 == length &&
                    body[i + 2] == '{' &&
                    !yx_regex_bad_prefix_before(body, i)) {
                    *location = body + i;
                    *width = 3;
                    *label = yx_empty_word_brace_label;
                    free(states);
                    return true;
                }
                if (!in_class && i + 2 < length && body[i + 2] == '{' &&
                    yx_word_comma_empty_upper(
                        body, length, i + 2, extended, &empty_at) &&
                    !yx_regex_bad_prefix_before(body, i)) {
                    *location = body + empty_at;
                    *width = 0;
                    *label = yx_word_repeat_decimal_label;
                    free(states);
                    return true;
                }
                size_t digit_at = 0, digit_width = 0;
                if (!in_class && i + 2 < length && body[i + 2] == '{' &&
                    yx_word_comma_repeat_overflow(
                        body, length, i + 2, extended, &digit_at,
                        &digit_width) &&
                    !yx_regex_bad_prefix_before(body, i)) {
                    *location = body + digit_at;
                    *width = digit_width;
                    *label = yx_word_repeat_overflow_label;
                    free(states);
                    return true;
                }
                /* A brace after `\B` is a malformed repeat, not part of
                 * the word assertion. Its syntax error takes precedence. */
                if (escaped == 'B' && i + 2 < length && body[i + 2] == '{') {
                    if (unicode && !unicode_at &&
                        yx_word_comma_repeat(body, length, i + 2)) {
                        unicode_at = body + i;
                        unicode_width = 2;
                    }
                    ++i;
                    continue;
                }
                if (escaped == 'b' && i + 2 < length && body[i + 2] == '{') {
                    size_t repeat_width = 0;
                    if (!in_class && yx_word_comma_second_separator(
                            body, length, i + 2, extended,
                            &repeat_width) &&
                        !yx_regex_bad_prefix_before(body, i)) {
                        *location = body + i + 2;
                        *width = repeat_width;
                        *label = yx_word_repeat_unclosed_label;
                        free(states);
                        return true;
                    }
                    if (yx_word_comma_repeat(body, length, i + 2)) {
                        if (unicode && !in_class && !unicode_at) {
                            unicode_at = body + i;
                            unicode_width = 2;
                        }
                        ++i;
                        continue;
                    }
                    size_t unclosed_at = 0, unclosed_width = 0;
                    if (!in_class &&
                        yx_unclosed_word_comma_repeat(
                            body, length, &unclosed_at, &unclosed_width) &&
                        unclosed_at == i + 2) {
                        *location = body + unclosed_at;
                        *width = unclosed_width;
                        *label = yx_word_repeat_unclosed_label;
                        free(states);
                        return true;
                    }
                    size_t begin = i + 3, end = begin;
                    unsigned char first = begin < length ?
                        (unsigned char)body[begin] : 0;
                    size_t decimal = begin;
                    while (decimal < length &&
                           isspace((unsigned char)body[decimal])) ++decimal;
                    if (decimal < length &&
                        isdigit((unsigned char)body[decimal])) {
                        size_t at = decimal;
                        while (at < length &&
                               isdigit((unsigned char)body[at])) ++at;
                        while (at < length &&
                               isspace((unsigned char)body[at])) ++at;
                        if (at < length && body[at] == ',') {
                            ++at;
                            while (at < length &&
                                   isspace((unsigned char)body[at])) ++at;
                            while (at < length &&
                                   isdigit((unsigned char)body[at])) ++at;
                            while (at < length &&
                                   isspace((unsigned char)body[at])) ++at;
                        }
                        if (at < length && body[at] == '}' && unicode &&
                            !in_class && !unicode_at) {
                            unicode_at = body + i;
                            unicode_width = 2;
                        }
                        ++i;
                        continue;
                    }
                    if (!yx_regex_bad_prefix_before(body, i) &&
                        strchr(body + begin, '}') &&
                        !((first >= 'a' && first <= 'z') ||
                          (first >= 'A' && first <= 'Z') ||
                          first == '-' || (first >= '0' && first <= '9'))) {
                        *location = body + decimal;
                        if (first == ',' && decimal < length &&
                            body[decimal] == ',') {
                            size_t upper = decimal + 1;
                            while (upper < length &&
                                   isspace((unsigned char)body[upper]))
                                ++upper;
                            if (upper < length && body[upper] != '}' &&
                                !isdigit((unsigned char)body[upper]))
                                *location = body + upper;
                        }
                        *width = 0;
                        *label = yx_word_repeat_decimal_label;
                        free(states);
                        return true;
                    }
                    while (end < length) {
                        unsigned char ch = (unsigned char)body[end];
                        if ((ch >= 'a' && ch <= 'z') ||
                            (ch >= 'A' && ch <= 'Z') || ch == '-') {
                            ++end;
                            continue;
                        }
                        break;
                    }
                    if (end > begin &&
                        (end == length || body[end] != '}') &&
                        !yx_regex_bad_prefix_before(body, i)) {
                        *location = body + i + 2;
                        *width = end - (i + 2);
                        *label = yx_invalid_word_assertion_label;
                        free(states);
                        return true;
                    }
                    if (end == begin) { ++i; continue; }
                    size_t name_length = end - begin;
                    bool start = yx_word_assertion_name(
                        body + begin, name_length, "start");
                    bool finish = yx_word_assertion_name(
                        body + begin, name_length, "end");
                    if (!start && !finish &&
                        !yx_word_assertion_name(
                            body + begin, name_length, "start-half") &&
                        !yx_word_assertion_name(
                            body + begin, name_length, "end-half")) {
                        *location = body + begin;
                        *width = name_length;
                        *label = yx_unknown_word_assertion_label;
                        free(states);
                        return true;
                    }
                    if (!unicode) {
                        ++i;
                        continue;
                    }
                    span = end - i + 1;
                }
                if (in_class) { ++i; continue; }
                if (unicode && !unicode_at) {
                    unicode_at = body + i;
                    unicode_width = span;
                }
            }
            ++i;
            continue;
        }
        if (body[i] == '[' && !in_class) { in_class = true; continue; }
        if (body[i] == ']' && in_class) { in_class = false; continue; }
        if (in_class) continue;
        if (body[i] == '(') {
            if (i + 2 < length && body[i + 1] == '?') {
                size_t end = i + 2;
                bool next_unicode = unicode, negated = false;
                bool next_extended = extended;
                while (end < length && strchr("imsuxUR-", body[end])) {
                    if (body[end] == '-') negated = true;
                    else if (body[end] == 'u') next_unicode = !negated;
                    else if (body[end] == 'x') next_extended = !negated;
                    ++end;
                }
                if (end > i + 2 && end < length &&
                    (body[end] == ')' || body[end] == ':')) {
                    if (body[end] == ':')
                        states[depth++] =
                            (struct yx_inline_flags){unicode, extended};
                    unicode = next_unicode;
                    extended = next_extended;
                    i = end;
                    continue;
                }
            }
            states[depth++] = (struct yx_inline_flags){unicode, extended};
        } else if (body[i] == ')' && depth) {
            struct yx_inline_flags prior = states[--depth];
            unicode = prior.unicode;
            extended = prior.extended;
        }
    }
    free(states);
    if (!unicode_at) return false;
    *location = unicode_at;
    *width = unicode_width;
    *label = "this is unsupported in Unicode regular expressions";
    return true;
}

static bool yx_regex_class_unclosed(const char *body, size_t length,
                                     const char **location, size_t *width)
{
    size_t *opens = malloc((length + 1) * sizeof(*opens));
    unsigned char *first = calloc(length + 1, 1);
    size_t depth = 0;
    if (!opens || !first) { free(opens); free(first); return false; }
    for (size_t i = 0; i < length; ++i) {
        if (body[i] == '\\' && i + 1 < length) {
            if (depth) first[depth - 1] = 0;
            ++i; continue;
        }
        if (body[i] == '[') {
            if (depth) first[depth - 1] = 0;
            opens[depth] = i; first[depth++] = 1;
        } else if (depth && body[i] == '^' && i == opens[depth - 1] + 1) {
            continue;
        } else if (depth && body[i] == ']' && !first[depth - 1]) --depth;
        else if (depth) first[depth - 1] = 0;
    }
    if (depth) {
        size_t at = opens[depth - 1];
        *location = body + at;
        *width = at + 1 < length && body[at + 1] == ']' ? 2 :
            at + 2 < length && body[at + 1] == '^' && body[at + 2] == ']' ? 3 : 1;
    }
    free(opens); free(first);
    return depth != 0;
}

/* HIR translation errors occur after syntax and the AST nesting limit.
 * Resolve against the original scopes so backend normalization cannot
 * change either the property name or the source span. */
static bool yx_regex_unicode_issue(const char *body, size_t length,
                                    const char **location, size_t *width,
                                    const char **label)
{
    unsigned char *states = calloc(length + 1, 1);
    size_t depth = 0, classes = 0;
    bool unicode = false, extended = false;
    if (!states) return false;
    for (size_t i = 0; i < length; ++i) {
        if (extended && body[i] == '#') {
            while (i < length && body[i] != '\n') ++i;
            if (i == length) break;
        }
        if (body[i] == '\\' && i + 1 < length) {
            char escaped = body[i + 1];
            if (escaped == 'p' || escaped == 'P') {
                size_t begin = i + 2, end = begin + 1, after = end;
                if (begin < length && body[begin] == '{') {
                    ++begin; end = begin;
                    while (end < length && body[end] != '}') ++end;
                    after = end < length ? end + 1 : end;
                }
                const char *issue = !unicode ? "Unicode not allowed here" : NULL;
                if (!issue && begin < length && end <= length)
                    issue = yx_re_property_error(body + begin, end - begin);
                if (issue) {
                    *location = body + i; *width = after - i; *label = issue;
                    free(states); return true;
                }
                i = after ? after - 1 : i + 1;
            } else ++i;
            continue;
        }
        if (body[i] == '[') { ++classes; continue; }
        if (body[i] == ']' && classes) { --classes; continue; }
        if (classes) {
            if (!unicode && (unsigned char)body[i] >= 128) {
                *location = body + i; *width = 1;
                *label = "Unicode not allowed here";
                free(states); return true;
            }
            continue;
        }
        if (body[i] == '(') {
            size_t end = i + 2;
            bool next_unicode = unicode, next_extended = extended, negated = false;
            if (i + 1 < length && body[i + 1] == '?') {
                while (end < length && strchr("imsuxUR-", body[end])) {
                    char flag = body[end++];
                    if (flag == '-') negated = true;
                    else if (flag == 'u') next_unicode = !negated;
                    else if (flag == 'x') next_extended = !negated;
                }
                if (end > i + 2 && end < length &&
                    (body[end] == ':' || body[end] == ')')) {
                    if (body[end] == ':') states[depth++] =
                        (unsigned char)((unicode ? 1 : 0) | (extended ? 2 : 0));
                    unicode = next_unicode; extended = next_extended;
                    i = end; continue;
                }
            }
            states[depth++] = (unsigned char)((unicode ? 1 : 0) | (extended ? 2 : 0));
        } else if (body[i] == ')' && depth) {
            unsigned char prior = states[--depth];
            unicode = (prior & 1) != 0; extended = (prior & 2) != 0;
        }
    }
    free(states); return false;
}

/* Bytes of the UTF-8 character at `at` (1 for an invalid lead byte). */
static size_t yx_regex_utf8_length(const char *at, size_t available)
{
    unsigned char lead = (unsigned char)*at;
    size_t length = lead >= 0xF0 && lead <= 0xF7 ? 4 :
                    lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
    if (lead >= 0xF8) length = 1;
    return length <= available ? length : available ? available : 1;
}

static int yx_report_pattern_regexp_error(yx_parser *p,
                                          const YRX_PATTERN *pattern,
                                          const char *pattern_start,
                                          const char *literal_start,
                                          const char *literal_end,
                                          int validation)
{
    const char *body = literal_start + 1;
    size_t length = strlen(pattern->regexp);
    const char *location = NULL;
    const char *arbitrary = NULL;
    size_t width = 1;
    size_t arbitrary_width = 0;
    const char *label = NULL;
    const char *note = NULL;
    char escape_note[128];
    yx_regex_ast_err ast_error;
    bool ast_found = false;
    if (validation < 0 && (pattern->modifiers & YX_MOD_DOTALL)) {
        size_t prefix_start, prefix_end;
        if (yx_regex_arbitrary_prefix(body, length, true,
                                      &prefix_start, &prefix_end)) {
            arbitrary = body + prefix_start;
            arbitrary_width = prefix_end - prefix_start;
        }
    }
    size_t alternatives = 0;
    for (size_t i = 0; i < length; ++i) {
        if (body[i] == '\\' && i + 1 < length) { ++i; continue; }
        if (body[i] == '[') {
            while (++i < length && body[i] != ']')
                if (body[i] == '\\' && i + 1 < length) ++i;
            continue;
        }
        if (body[i] == '|') ++alternatives;
    }
    if (alternatives > 255) {
        location = pattern_start;
        width = (size_t)(literal_end - pattern_start);
        label = "too many alternatives in alternation (max: 255)";
    } else if (validation == 0) {
        location = pattern_start;
        width = (size_t)(literal_end - pattern_start);
        label = "this regexp can match empty strings";
    } else {
        size_t unclosed_at;
        /* regex-syntax parses the whole AST before translating it, so its
         * first syntax error wins over every later-stage diagnostic. */
        ast_found = yx_regex_ast_error(body, length, &ast_error);
        if (ast_found) {
            location = body + ast_error.start;
            width = ast_error.end - ast_error.start;
            label = ast_error.label;
            if (ast_error.note[0]) {
                snprintf(escape_note, sizeof(escape_note), "%s",
                         ast_error.note);
                note = escape_note;
            }
        } else if (yx_unclosed_word_comma_repeat(pattern->regexp, length,
                                          &unclosed_at, &width)) {
            location = body + unclosed_at;
            label = "unclosed counted repetition";
            note = yx_word_repeat_decimal_note;
        } else if (yx_word_assertion_issue(body, length, &location, &width,
                                           &label) &&
            label == yx_word_repeat_decimal_label)
            note = yx_word_repeat_decimal_note;
        if (!label && length && body[0] == '{') {
            location = body;
            width = 0;
            label = "repetition operator missing expression";
            note = "did you mean `\\{` instead of `{`?";
        }
        size_t group_depth = 0;
        for (size_t i = 0; !label && i < length; ++i) {
            if (body[i] == '\\' && i + 1 < length) {
                unsigned char escaped = (unsigned char)body[i + 1];
                if (escaped >= 0x80) {
                    size_t char_length = yx_regex_utf8_length(body + i + 1,
                                                              length - i - 1);
                    location = body + i;
                    width = 1 + char_length;
                    label = "unrecognized escape sequence";
                    snprintf(escape_note, sizeof(escape_note),
                             "did you mean `\\\\%.*s` instead of `\\%.*s`?",
                             (int)char_length, body + i + 1,
                             (int)char_length, body + i + 1);
                    note = escape_note;
                    break;
                }
                if ((escaped >= '0' && escaped <= '9') ||
                    yx_regex_unrecognized_escape(escaped)) {
                    location = body + i;
                    width = 2;
                    if (escaped >= '0' && escaped <= '9')
                        label = "backreferences are not supported";
                    else {
                        label = "unrecognized escape sequence";
                        snprintf(escape_note, sizeof(escape_note),
                                 "did you mean `\\\\%c` instead of `\\%c`?",
                                 escaped, escaped);
                        note = escape_note;
                    }
                    break;
                }
                if ((escaped == 'p' || escaped == 'P') &&
                    i + 2 < length && body[i + 2] == '{') {
                    i += 2;
                    while (i < length && body[i] != '}') ++i;
                    continue;
                }
                ++i;
                continue;
            }
            if (body[i] == '[') {
                size_t close = i + 1;
                if (close < length && body[close] == '^') ++close;
                /* The first ']' is a member, including after negation. */
                if (close < length && body[close] == ']') ++close;
                while (close < length && body[close] != ']') {
                    if (body[close] == '\\' && close + 1 < length) {
                        unsigned char escaped =
                            (unsigned char)body[close + 1];
                        if (escaped >= 0x80) {
                            size_t char_length = yx_regex_utf8_length(
                                body + close + 1, length - close - 1);
                            location = body + close;
                            width = 1 + char_length;
                            label = "unrecognized escape sequence";
                            snprintf(escape_note, sizeof(escape_note),
                                     "did you mean `\\\\%.*s` instead of `\\%.*s`?",
                                     (int)char_length, body + close + 1,
                                     (int)char_length, body + close + 1);
                            note = escape_note;
                            break;
                        }
                        if ((escaped >= '0' && escaped <= '9') ||
                            yx_regex_unrecognized_escape(escaped)) {
                            location = body + close;
                            width = 2;
                            if (escaped >= '0' && escaped <= '9')
                                label = "backreferences are not supported";
                            else {
                                label = "unrecognized escape sequence";
                                snprintf(escape_note, sizeof(escape_note),
                                         "did you mean `\\\\%c` instead of `\\%c`?",
                                         escaped, escaped);
                                note = escape_note;
                            }
                            break;
                        }
                        ++close;
                    }
                    ++close;
                }
                if (label) break;
                if (close == length) {
                    location = body + i;
                    if (i + 1 < length && body[i + 1] == ']') width = 2;
                    else if (i + 2 < length && body[i + 1] == '^' &&
                             body[i + 2] == ']') width = 3;
                    label = "unclosed character class";
                    break;
                }
                for (size_t j = i + 1; j + 2 < close; ++j) {
                    /* `[a-\d]`: a range ends in a literal. */
                    if (body[j] != '\\' && body[j + 1] == '-' &&
                        body[j + 2] == '\\' && j + 3 < close &&
                        strchr("dDwWsSpP", body[j + 3])) {
                        location = body + j + 2;
                        width = 2;
                        if ((body[j + 3] == 'p' || body[j + 3] == 'P') &&
                            j + 4 < length && body[j + 4] == '{') {
                            const char *brace = memchr(body + j + 4, '}',
                                                       length - j - 4);
                            if (brace)
                                width = (size_t)(brace + 1 - (body + j + 2));
                        } else if (body[j + 3] == 'p' || body[j + 3] == 'P')
                            width = j + 4 < length ? 3 : 2;
                        label = "invalid range boundary, must be a literal";
                        break;
                    }
                    if (body[j + 1] == '-' && body[j + 2] != '-' &&
                        (unsigned char)body[j] > (unsigned char)body[j + 2]) {
                        location = body + j;
                        width = 3;
                        label = "invalid character class range, the start must be <= the end";
                        break;
                    }
                }
                i = close;
                continue;
            }
            if (body[i] == '(') {
                if (i + 2 < length && body[i + 1] == '?' &&
                    (body[i + 2] == '=' || body[i + 2] == '!' ||
                     (i + 3 < length && body[i + 2] == '<' &&
                      (body[i + 3] == '=' || body[i + 3] == '!')))) {
                    location = body + i;
                    width = body[i + 2] == '<' ? 4 : 3;
                    label = "look-around, including look-ahead and look-behind, is not supported";
                    break;
                }
                /* `(?q)`: regex-syntax knows the flags i, m, s, U, u, x
                 * and R. Named groups and `(?:` are not flags. */
                if (i + 2 < length && body[i + 1] == '?' &&
                    body[i + 2] != '<' && body[i + 2] != 'P' &&
                    body[i + 2] != ':') {
                    for (size_t f = i + 2; f < length && body[f] != ':' &&
                                           body[f] != ')'; ++f) {
                        if (!strchr("imsUuxR-", body[f])) {
                            location = body + f;
                            width = yx_regex_utf8_length(body + f, length - f);
                            label = "unrecognized flag";
                            break;
                        }
                    }
                    if (label) break;
                }
                ++group_depth;
                continue;
            }
            if (body[i] == ')') {
                if (!group_depth) {
                    location = body + i;
                    label = "unopened group";
                    break;
                }
                --group_depth;
                continue;
            }
            if (body[i] == '{') {
                size_t close = i + 1;
                while (close < length && body[close] != '}') ++close;
                location = body + i;
                if (close == length) {
                    size_t decimal = i + 1;
                    while (decimal < length &&
                           isdigit((unsigned char)body[decimal])) ++decimal;
                    if (decimal < length && body[decimal] == ',') {
                        ++decimal;
                        if (decimal < length &&
                            !isdigit((unsigned char)body[decimal])) {
                            location = body + decimal;
                            width = 0;
                            label = "repetition quantifier expects a valid decimal";
                        } else while (decimal < length &&
                                      isdigit((unsigned char)body[decimal]))
                            ++decimal;
                    } else if (decimal == i + 1 && decimal < length) {
                        location = body + decimal;
                        width = 0;
                        label = "repetition quantifier expects a valid decimal";
                    }
                    if (!label) {
                        width = decimal - i;
                        label = "unclosed counted repetition";
                    }
                } else if (body[i + 1] == ',' &&
                           !(i >= 2 && body[i - 2] == '\\' &&
                             (body[i - 1] == 'B' || body[i - 1] == 'b'))) {
                    /* YARA-X parses with empty_min_range: `{,N}` is a valid
                     * repetition, so later errors surface; a missing upper
                     * bound is reported where its decimal was expected. */
                    size_t upper = i + 2;
                    if (upper < close && isdigit((unsigned char)body[upper])) {
                        while (upper < close &&
                               isdigit((unsigned char)body[upper])) ++upper;
                        if (upper == close) {
                            location = NULL;
                            i = close;
                            continue;
                        }
                        width = upper - i;
                        label = "unclosed counted repetition";
                    } else {
                        location = body + upper;
                        width = 0;
                        label = "repetition quantifier expects a valid decimal";
                    }
                } else if (!isdigit((unsigned char)body[i + 1])) {
                    location = body + i + 1;
                    if (body[i + 1] == ',' && i >= 2 &&
                        body[i - 2] == '\\' && body[i - 1] == 'B') {
                        size_t slash = i - 2, slash_count = 0;
                        do {
                            ++slash_count;
                        } while (slash > 0 && body[--slash] == '\\');
                        if (slash_count & 1u) {
                            size_t upper = i + 2;
                            while (upper < close &&
                                   isspace((unsigned char)body[upper]))
                                ++upper;
                            if (upper < close && body[upper] != '}' &&
                                !isdigit((unsigned char)body[upper]))
                                location = body + upper;
                        }
                    }
                    width = 0;
                    label = "repetition quantifier expects a valid decimal";
                } else {
                    size_t decimal = i + 1;
                    uint64_t lower = 0, upper = 0;
                    size_t start = decimal;
                    while (decimal < close &&
                           isdigit((unsigned char)body[decimal])) {
                        if (lower <= UINT32_MAX)
                            lower = lower * 10u +
                                    (unsigned)(body[decimal] - '0');
                        ++decimal;
                    }
                    if (lower > UINT32_MAX) {
                        location = body + start;
                        width = decimal - start;
                        label = "decimal literal invalid";
                    } else if (decimal < close && body[decimal] != ',') {
                        location = body + i;
                        width = decimal - i;
                        label = "unclosed counted repetition";
                    } else if (decimal < close) {
                        ++decimal;
                        if (decimal < close &&
                            !isdigit((unsigned char)body[decimal])) {
                            location = body + decimal;
                            width = 0;
                            label = "repetition quantifier expects a valid decimal";
                        } else if (decimal < close) {
                            start = decimal;
                            while (decimal < close &&
                                   isdigit((unsigned char)body[decimal])) {
                                if (upper <= UINT32_MAX)
                                    upper = upper * 10u +
                                            (unsigned)(body[decimal] - '0');
                                ++decimal;
                            }
                            if (upper > UINT32_MAX) {
                                location = body + start;
                                width = decimal - start;
                                label = "decimal literal invalid";
                            } else if (decimal < close) {
                                location = body + i;
                                width = decimal - i;
                                label = "unclosed counted repetition";
                            } else if (upper < lower) {
                                location = body + i;
                                width = close - i + 1;
                                label = "invalid repetition count range, the start must be <= the end";
                            }
                        }
                    }
                    if (!label)
                        location = NULL;
                }
                if (label) {
                    if (strcmp(label, "decimal literal invalid") != 0)
                        note = "did you mean `\\{` instead of `{`?";
                    break;
                }
            }
        }
        if (!label && yx_regex_incomplete_trailing_escape(body, length)) {
            location = body + length;
            width = 0;
            label = "incomplete escape sequence, reached end of pattern "
                    "prematurely";
        }
        if (!label) {
            const char *opening = NULL;
            unsigned depth = 0;
            for (size_t i = 0; i < length; ++i) {
                if (body[i] == '\\' && i + 1 < length) { ++i; continue; }
                if (body[i] == '(') { if (!depth) opening = body + i; ++depth; }
                else if (body[i] == ')' && depth) --depth;
            }
            if (depth && opening) {
                location = opening;
                label = "unclosed group";
            }
        }
        if (!label && yx_regex_class_unclosed(body, length, &location, &width))
            label = "unclosed character class";
        const char *size_label = yx_regex_pike_size_error(body, length, pattern->modifiers);
        size_t nest_at = 0, nest_width = 0;
        if ((!label || strcmp(label, "this is unsupported in Unicode regular expressions") == 0) &&
            yx_regex_nesting_error(body, length, &nest_at, &nest_width)) {
            location = body + nest_at;
            width = nest_width;
            label = "exceed the maximum number of nested parentheses/brackets (250)";
            note = NULL;
        }
        if (!label) (void)yx_regex_unicode_issue(body, length, &location, &width, &label);
        if (size_label && !ast_found && (!label || strcmp(label,
                "exceed the maximum number of nested parentheses/brackets (250)") != 0)) {
            /* The span of the whole pattern, its modifiers included (those
             * of this declaration end after its literal). */
            const char *span_end = literal_end;
            for (size_t modifier = 0; modifier < 9; ++modifier)
                if (p->modifier_end[modifier] && p->modifier_end[modifier] > span_end)
                    span_end = p->modifier_end[modifier];
            location = pattern_start;
            width = (size_t)(span_end - pattern_start);
            label = size_label;
            note = NULL;
        }
    }
    if (!label && arbitrary) {
        size_t start = (size_t)(arbitrary - p->begin);
        if (!yx_compiler_arbitrary_regexp_prefix_error(
                p->compiler, p->begin, p->origin,
                start, start + arbitrary_width)) return 0;
        p->recoverable_invalid_regexp = true;
        return 1;
    }
    if (!label || !location) return 0;
    if (!yx_compiler_invalid_regexp_error(
            p->compiler, p->begin, p->origin,
            (size_t)(location - p->begin),
            (size_t)(location - p->begin) + width, label, note))
        return 0;
    p->recoverable_invalid_regexp = true;
    return 1;
}

/* A hex pattern compiles through regex-syntax's Hir: consecutive exact bytes
 * form one literal, other bytes are classes. Hir::alternation folds
 * alternatives that are all single bytes or classes into one class and lifts
 * a common prefix of concatenations; the Thompson and Fast compilers reject
 * an alternation that keeps more than 255 alternatives (E014). */
typedef struct { const yx_hex_atom *atoms; size_t count; } yx_hex_span;

static bool yx_hex_exact(const yx_hex_atom *atom)
{
    return atom->kind == YX_HEX_BYTE && atom->mask == 0xff && !atom->negated;
}

/* The end of the Hir element that starts at atoms[at]: a run of exact
 * bytes, or one atom. */
static size_t yx_hex_element_end(const yx_hex_span *span, size_t at)
{
    if (!yx_hex_exact(&span->atoms[at])) return at + 1;
    while (at < span->count && yx_hex_exact(&span->atoms[at])) ++at;
    return at;
}

static bool yx_hex_elements_equal(const yx_hex_span *a, size_t a_at,
                                  size_t a_end, const yx_hex_span *b,
                                  size_t b_at, size_t b_end)
{
    if (a_end - a_at != b_end - b_at) return false;
    for (size_t i = 0; i < a_end - a_at; ++i) {
        const yx_hex_atom *x = &a->atoms[a_at + i], *y = &b->atoms[b_at + i];
        if (x->kind != YX_HEX_BYTE || y->kind != YX_HEX_BYTE ||
            x->value != y->value || x->mask != y->mask ||
            x->negated != y->negated) return false;
    }
    return true;
}

static bool yx_hex_sequence_alternations_fit(const yx_hex_atom *atoms,
                                             size_t count, unsigned depth);

/* Whether a branch compiles to one byte class: a masked or negated byte, or
 * a group whose alternatives are all single exact bytes or all classes. */
static bool yx_hex_branch_is_class(const yx_hex_span *branch, unsigned depth)
{
    const yx_hex_atom *atom;
    bool bytes = true, classes = true;
    if (branch->count != 1 || depth > 64) return false;
    atom = &branch->atoms[0];
    if (atom->kind == YX_HEX_BYTE) return !yx_hex_exact(atom);
    if (atom->kind != YX_HEX_ALTERNATIVE) return false;
    for (size_t i = 0; i < atom->branch_count; ++i) {
        yx_hex_span inner = {atom->branches[i].atoms, atom->branches[i].count};
        if (!(inner.count == 1 && yx_hex_exact(&inner.atoms[0]))) bytes = false;
        if (!yx_hex_branch_is_class(&inner, depth + 1)) classes = false;
    }
    return bytes || classes;
}

static bool yx_hex_alternation_fits(const yx_hex_span *branches, size_t count,
                                    unsigned depth)
{
    bool bytes = true, classes = true, concats = true;
    size_t prefix = 0;
    if (depth > 64 || count <= 255) return true;
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_span *branch = &branches[i];
        bool single = branch->count &&
                      yx_hex_element_end(branch, 0) == branch->count;
        /* All single exact bytes, or all byte classes, fold into one class
         * (singleton_bytes, class_bytes); a mix of both does not. */
        if (!(branch->count == 1 && yx_hex_exact(&branch->atoms[0])))
            bytes = false;
        if (!yx_hex_branch_is_class(branch, depth)) classes = false;
        if (single || !branch->count) concats = false;
    }
    if (bytes || classes) return true;
    if (concats) {
        /* Common leading Hir elements of every alternative. */
        for (;;) {
            size_t end;
            bool common = prefix < branches[0].count;
            if (common) {
                end = yx_hex_element_end(&branches[0], prefix);
                for (size_t i = 1; i < count && common; ++i)
                    common = prefix < branches[i].count &&
                             yx_hex_element_end(&branches[i], prefix) == end &&
                             yx_hex_elements_equal(&branches[0], prefix, end,
                                                   &branches[i], prefix, end);
            }
            if (!common) break;
            prefix = end;
        }
        if (prefix) {
            yx_hex_span *suffixes = malloc(count * sizeof(*suffixes));
            bool fits;
            if (!suffixes) return true;
            for (size_t i = 0; i < count; ++i) {
                suffixes[i].atoms = branches[i].atoms + prefix;
                suffixes[i].count = branches[i].count - prefix;
            }
            fits = yx_hex_alternation_fits(suffixes, count, depth + 1);
            free(suffixes);
            return fits;
        }
    }
    return false;
}

static bool yx_hex_sequence_alternations_fit(const yx_hex_atom *atoms,
                                             size_t count, unsigned depth)
{
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_atom *atom = &atoms[i];
        yx_hex_span *branches;
        bool fits;
        if (atom->kind != YX_HEX_ALTERNATIVE) continue;
        for (size_t j = 0; j < atom->branch_count; ++j)
            if (!yx_hex_sequence_alternations_fit(atom->branches[j].atoms,
                                                  atom->branches[j].count,
                                                  depth + 1)) return false;
        branches = malloc((atom->branch_count ? atom->branch_count : 1) *
                          sizeof(*branches));
        if (!branches) return true;
        for (size_t j = 0; j < atom->branch_count; ++j) {
            branches[j].atoms = atom->branches[j].atoms;
            branches[j].count = atom->branches[j].count;
        }
        fits = yx_hex_alternation_fits(branches, atom->branch_count, depth);
        free(branches);
        if (!fits) return false;
    }
    return true;
}

/* Whether an alternative is a literal for Hir::alternation: exact bytes, or
 * a nested alternation of literals, which Hir::alternation flattens (a
 * nested alternation of single bytes is a class instead). */
static bool yx_hex_branch_is_literal(const yx_hex_sequence *branch,
                                     unsigned depth)
{
    const yx_hex_atom *atom;
    bool bytes = true;
    size_t i;
    if (!branch->count || depth > 64) return false;
    for (i = 0; i < branch->count; ++i)
        if (!yx_hex_exact(&branch->atoms[i])) break;
    if (i == branch->count) return true;
    atom = &branch->atoms[0];
    if (branch->count != 1 || atom->kind != YX_HEX_ALTERNATIVE ||
        !atom->branch_count) return false;
    if (atom->branch_count == 1)
        return yx_hex_branch_is_literal(&atom->branches[0], depth + 1);
    for (i = 0; i < atom->branch_count; ++i) {
        if (!(atom->branches[i].count == 1 &&
              yx_hex_exact(&atom->branches[i].atoms[0]))) bytes = false;
        if (!yx_hex_branch_is_literal(&atom->branches[i], depth + 1))
            return false;
    }
    return !bytes;
}

/* A hex pattern that is one alternation of literals is not compiled by the
 * Thompson or Fast compiler: c_regexp_pattern (compiler/mod.rs) hands a
 * pattern whose Hir is_alternation_literal to c_alternation_literal, which
 * takes any number of alternatives. */
static bool yx_hex_pattern_is_literal_alternation(const yx_hex_atom *atoms,
                                                  size_t count)
{
    if (count != 1 || atoms[0].kind != YX_HEX_ALTERNATIVE) return false;
    for (size_t i = 0; i < atoms[0].branch_count; ++i)
        if (!yx_hex_branch_is_literal(&atoms[0].branches[i], 0)) return false;
    return true;
}

static int yx_parse_strings_indexed(yx_parser *p, YRX_RULE *rule,
                                    yx_pattern_index *index)
{
    for (;;) {
        yx_space(p);
        if (*p->at != '$') return 1;
        const char *pattern_start = p->at;
        const char *text_literal_start = NULL;
        const char *text_literal_end = NULL;
        const char *hex_literal_start = NULL;
        const char *hex_literal_end = NULL;
        const char *regex_literal_start = NULL;
        const char *regex_literal_end = NULL;
        ++p->at;
        YRX_PATTERN pattern = {0};
        /* A pattern name is $ followed by ([[:alpha:]]|\d|_)*, so a Unicode
         * decimal digit may introduce it ($٠). yx_ident keeps the legacy
         * leading-space behavior for the ordinary ASCII names. */
        const char *name_start = p->at;
        size_t name_width = yx_ident_continue_width(p->at);
        char *name;
        if (name_width) {
            do {
                p->at += name_width;
                name_width = yx_ident_continue_width(p->at);
            } while (name_width);
            name = yx_duplicate(name_start, (size_t)(p->at - name_start));
        } else {
            name = yx_ident(p);
        }
        if (!name) name = yx_duplicate("", 0);
        if (!name) return yx_error(p, "out of memory");
        pattern.identifier = malloc(strlen(name) + 2);
        if (!pattern.identifier) {
            free(name);
            return yx_error(p, "out of memory");
        }
        pattern.identifier[0] = '$';
        strcpy(pattern.identifier + 1, name);
        pattern.declaration_start = (size_t)(pattern_start - p->begin);
        pattern.declaration_end = pattern.declaration_start +
                                  strlen(pattern.identifier);
        p->current_pattern_identifier = pattern.identifier;
        for (size_t i = 0; i < sizeof(p->modifier_start) / sizeof(p->modifier_start[0]); ++i)
            p->modifier_start[i] = p->modifier_end[i] = NULL;
        free(name);
        yx_space(p);
        if (*p->at != '=') {
            if (*p->at == '"') {
                const char *end = p->at + 1;
                while (*end && *end != '\n' && *end != '"') {
                    if (*end == '\\' && end[1] && end[1] != '\n')
                        ++end;
                    ++end;
                }
                if (*end != '"') {
                    yx_syntax_label(p, p->at, end,
                                    "unclosed literal string");
                    goto failure;
                }
            }
            const char *token_end = yx_syntax_token_end(p->at);
            if (*p->at == '/')
                token_end = yx_syntax_regexp_token_end(p->at);
            else if ((*p->at == '<' || *p->at == '>' ||
                      *p->at == '!') && p->at[1] == '=')
                token_end = p->at + 2;
            yx_syntax_expected(p, p->at, token_end, "`=`");
            if ((size_t)(token_end - p->at) == 9 &&
                memcmp(p->at, "condition", 9) == 0) {
                yx_parser section_probe = *p;
                section_probe.at = token_end;
                yx_space(&section_probe);
                if (*section_probe.at != ':') {
                    const char *next_end = *section_probe.at == '/' ?
                        yx_syntax_regexp_token_end(section_probe.at) :
                        yx_syntax_token_end(section_probe.at);
                    yx_syntax_expected(p, section_probe.at, next_end, "`:`");
                }
            }
            goto failure;
        }
        if (p->at[1] == '=') {
            yx_syntax_expected(p, p->at, p->at + 2, "`=`");
            goto failure;
        }
        ++p->at;
        yx_space(p);
        if (p->unterminated_comment) {
            yx_syntax_label(p, p->unterminated_comment_start, p->at,
                            "unclosed comment");
            yx_syntax_expected(p, p->at, p->at, "`condition`");
            goto failure;
        }
        if (*p->at == '"') {
            pattern.kind = YX_PATTERN_TEXT;
            text_literal_start = p->at;
            pattern.bytes = yx_string(p, &pattern.length);
            if (!pattern.bytes) goto failure;
            text_literal_end = p->at;
            if (!pattern.length) {
                yx_invalid_pattern(p, text_literal_start, text_literal_end,
                                   "this pattern is too short", NULL);
                goto failure;
            }
        } else if (*p->at == '{') {
            pattern.kind = YX_PATTERN_HEX;
            hex_literal_start = p->at;
            if (!yx_hex_pattern(p, &pattern)) goto failure;
            hex_literal_end = p->at;
            if (!yx_hex_pattern_is_literal_alternation(pattern.hex_atoms,
                                                       pattern.hex_atom_count) &&
                !yx_hex_sequence_alternations_fit(pattern.hex_atoms,
                                                  pattern.hex_atom_count, 0)) {
                if (yx_compiler_invalid_regexp_error(
                        p->compiler, p->begin, p->origin,
                        (size_t)(hex_literal_start - p->begin),
                        (size_t)(hex_literal_end - p->begin),
                        "too many alternatives in alternation (max: 255)",
                        NULL))
                    p->recoverable_invalid_regexp = true;
                else yx_error(p, "out of memory recording regexp error");
                goto failure;
            }
        } else if (*p->at == '/') {
            pattern.kind = YX_PATTERN_REGEX;
            regex_literal_start = p->at;
            if (!yx_regex_pattern(p, &pattern)) goto failure;
            regex_literal_end = p->at;
        } else {
            if (strncmp(p->at, "\xe2\x80\x9c", 3) == 0) {
                const char *token_end = p->at + 3;
                while (*token_end &&
                       strncmp(token_end, "\xe2\x80\x9d", 3) != 0)
                    ++token_end;
                if (*token_end) token_end += 3;
                yx_syntax_expected(p, p->at, token_end,
                                   "STRING, regexp or `{`");
                p->at = token_end;
                yx_space(p);
                if (!*p->at)
                    yx_syntax_expected(p, p->at, p->at, "`condition`");
                goto failure;
            }
            const char *invalid_start = p->at;
            const char *invalid_end = yx_syntax_token_end(invalid_start);
            yx_syntax_expected(p, invalid_start, invalid_end,
                               "STRING, regexp or `{`");
            if ((size_t)(invalid_end - invalid_start) == 9 &&
                memcmp(invalid_start, "condition", 9) == 0) {
                yx_parser section_probe = *p;
                section_probe.at = invalid_end;
                yx_space(&section_probe);
                if (*section_probe.at != ':') {
                    yx_syntax_expected(p, section_probe.at,
                                       yx_syntax_token_end(section_probe.at),
                                       "`:`");
                    /* The parser has already treated this keyword as a
                     * malformed condition section. Do not add an unrelated
                     * missing-condition error at end of file. */
                    p->suppress_missing_condition_recovery = true;
                }
            }
            goto failure;
        }
        if (!yx_parse_modifiers(p, &pattern)) goto failure;
        if (pattern.kind == YX_PATTERN_REGEX &&
            (pattern.modifiers &
             (YX_MOD_XOR | YX_MOD_BASE64 | YX_MOD_BASE64WIDE))) {
            unsigned index = 4;
            for (unsigned candidate = 5; candidate <= 6; ++candidate) {
                if (p->modifier_start[candidate] &&
                    (!p->modifier_start[index] ||
                     p->modifier_start[candidate] < p->modifier_start[index]))
                    index = candidate;
            }
            if (p->modifier_start[index] &&
                yx_compiler_invalid_modifier_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(p->modifier_start[index] - p->begin),
                    (size_t)(p->modifier_end[index] - p->begin),
                    "this modifier can't be applied to a regexp"))
                p->recoverable_invalid_pattern = true;
            goto failure;
        }
        if ((pattern.modifiers & (YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) &&
            (pattern.modifiers & (YX_MOD_XOR | YX_MOD_FULLWORD | YX_MOD_NOCASE))) {
            unsigned base64_bit = (pattern.modifiers & YX_MOD_BASE64WIDE) ?
                6 : 5;
            unsigned other_bit = (pattern.modifiers & YX_MOD_NOCASE) ? 2 :
                                 (pattern.modifiers & YX_MOD_XOR) ? 4 : 3;
            const char *base64_name = base64_bit == 6 ? "base64wide" : "base64";
            const char *other_name = other_bit == 2 ? "nocase" :
                                     other_bit == 4 ? "xor" : "fullword";
            if (p->modifier_start[base64_bit] && p->modifier_start[other_bit] &&
                yx_compiler_invalid_modifier_combination_error(
                    p->compiler, p->begin, p->origin,
                    base64_name,
                    (size_t)(p->modifier_start[base64_bit] - p->begin),
                    (size_t)(p->modifier_end[base64_bit] - p->begin),
                    other_name,
                    (size_t)(p->modifier_start[other_bit] - p->begin),
                    (size_t)(p->modifier_end[other_bit] - p->begin)))
                p->recoverable_invalid_pattern = true;
            goto failure;
        }
        if (pattern.kind == YX_PATTERN_TEXT &&
            (pattern.modifiers & YX_MOD_XOR) &&
            (pattern.modifiers & YX_MOD_NOCASE)) {
            if (p->modifier_start[4] && p->modifier_start[2] &&
                yx_compiler_invalid_modifier_combination_error(
                    p->compiler, p->begin, p->origin, "xor",
                    (size_t)(p->modifier_start[4] - p->begin),
                    (size_t)(p->modifier_end[4] - p->begin), "nocase",
                    (size_t)(p->modifier_start[2] - p->begin),
                    (size_t)(p->modifier_end[2] - p->begin)))
                p->recoverable_invalid_pattern = true;
            goto failure;
        }
        if (pattern.kind == YX_PATTERN_HEX &&
            (pattern.modifiers & ~YX_MOD_PRIVATE)) {
            for (unsigned index = 0; index < 9; ++index) {
                if (!p->modifier_start[index] || index == 8) continue;
                if (yx_compiler_invalid_modifier_error(
                        p->compiler, p->begin, p->origin,
                        (size_t)(p->modifier_start[index] - p->begin),
                        (size_t)(p->modifier_end[index] - p->begin),
                        "this modifier can't be applied to a hex pattern"))
                    p->recoverable_invalid_pattern = true;
                break;
            }
            goto failure;
        }
        if ((pattern.modifiers & YX_MOD_XOR) && pattern.kind != YX_PATTERN_TEXT) {
            yx_error(p, "this pattern modifier is not supported yet");
            goto failure;
        }
        if (hex_literal_start &&
            !yx_compiler_text_as_hex_warning(
                p->compiler, &pattern, p->begin, p->origin,
                (size_t)(hex_literal_start - p->begin),
                (size_t)(hex_literal_end - p->begin))) {
            yx_error(p, "out of memory recording text-as-hex warning");
            goto failure;
        }
        if (pattern.modifiers & (YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) {
            if (pattern.kind != YX_PATTERN_TEXT) {
                yx_error(p, "base64 modifiers require a text pattern");
                goto failure;
            }
            if (pattern.length < 3) {
                if (text_literal_start)
                    yx_invalid_pattern(
                        p, text_literal_start, text_literal_end,
                        "this pattern is too short",
                        (pattern.modifiers & YX_MOD_BASE64) ?
                        "`base64` requires that pattern is at least 3 bytes long" :
                        "`base64wide` requires that pattern is at least 3 bytes long");
                else yx_error(p, "base64 pattern must be at least 3 bytes long");
                goto failure;
            }
        }
        if (pattern.kind == YX_PATTERN_REGEX) {
            if (p->modifier_start[2]) {
                const char *closing_slash =
                    regex_literal_start + 1 + strlen(pattern.regexp);
                const char *inline_i = NULL;
                for (const char *suffix = closing_slash + 1;
                     suffix < regex_literal_end; ++suffix)
                    if (*suffix == 'i') inline_i = suffix;
                if (inline_i &&
                    !yx_compiler_redundant_case_modifier_warning(
                        p->compiler, p->begin, p->origin,
                        (size_t)(inline_i - p->begin),
                        (size_t)(p->modifier_start[2] - p->begin),
                        (size_t)(p->modifier_end[2] - p->begin))) {
                    yx_error(p, "out of memory recording modifier warning");
                    goto failure;
                }
            }
            size_t flag_at;
            const char *flag_label;
            if (yx_regex_inline_r_flag_error(
                    pattern.regexp, strlen(pattern.regexp),
                    &flag_at, &flag_label)) {
                size_t source_at =
                    (size_t)(regex_literal_start + 1 - p->begin) + flag_at;
                if (yx_compiler_invalid_regexp_error(
                        p->compiler, p->begin, p->origin,
                        source_at, source_at + 1, flag_label, NULL))
                    p->recoverable_invalid_regexp = true;
                else yx_error(p, "out of memory recording regexp error");
                goto failure;
            }
            int escape_issue = yx_report_regex_escape_issue(
                p, regex_literal_start + 1, strlen(pattern.regexp));
            if (escape_issue != 0) {
                if (escape_issue < 0)
                    yx_error(p, "out of memory recording regexp error");
                goto failure;
            }
            const char *word_at = NULL, *word_label = NULL;
            size_t word_width = 0;
            if (yx_word_assertion_issue(
                    pattern.regexp, strlen(pattern.regexp), &word_at,
                    &word_width, &word_label) &&
                (word_label == yx_unknown_word_assertion_label ||
                 word_label == yx_invalid_word_assertion_label ||
                 word_label == yx_empty_word_brace_label ||
                 word_label == yx_word_repeat_decimal_label ||
                 word_label == yx_word_repeat_overflow_label ||
                 word_label == yx_word_repeat_unclosed_label)) {
                size_t source_at =
                    (size_t)(regex_literal_start + 1 - p->begin) +
                    (size_t)(word_at - pattern.regexp);
                if (yx_compiler_invalid_regexp_error(
                        p->compiler, p->begin, p->origin, source_at,
                        source_at + word_width, word_label,
                        (word_label == yx_word_repeat_decimal_label ||
                         word_label == yx_word_repeat_unclosed_label) ?
                        yx_word_repeat_decimal_note : NULL))
                    p->recoverable_invalid_regexp = true;
                else yx_error(p, "out of memory recording regexp error");
                goto failure;
            }
            if (yx_regex_pike_size_large(pattern.regexp,
                                         strlen(pattern.regexp),
                                         pattern.modifiers)) {
                if (!yx_report_pattern_regexp_error(
                        p, &pattern, pattern_start, regex_literal_start,
                        regex_literal_end, -1))
                    yx_error(p, "invalid regular expression");
                goto failure;
            }
            {
                char *normalized = yx_normalize_regexp_braces(
                    pattern.regexp,
                    (p->compiler->flags & YRX_RELAXED_RE_SYNTAX) != 0);
                if (!normalized) {
                    yx_error(p, "out of memory relaxing regular expression");
                    goto failure;
                }
                if (strcmp(normalized, pattern.regexp) != 0) {
                    YRX_PATTERN trial = pattern;
                    trial.regexp = normalized;
                    if (yx_validate_regex(&trial) >= 0) {
                        free(pattern.regexp);
                        pattern.regexp = normalized;
                        normalized = NULL;
                    }
                }
                free(normalized);
            }
            int regex_status = yx_validate_regex(&pattern);
            if (regex_status == 0) {
                if (!yx_report_pattern_regexp_error(
                        p, &pattern, pattern_start, regex_literal_start,
                        p->at, regex_status))
                    yx_error(p, "regular expression can match empty data");
                goto failure;
            }
            if (regex_status < 0) {
                size_t greedy_start = 0, greedy_end = 0;
                size_t lazy_start = 0, lazy_end = 0;
                yx_regex_ast_err first_syntax_error;
                if (!yx_regex_ast_error(pattern.regexp,
                                        strlen(pattern.regexp),
                                        &first_syntax_error) &&
                    yx_mixed_greediness_spans(
                        pattern.regexp, strlen(pattern.regexp),
                        &greedy_start, &greedy_end,
                        &lazy_start, &lazy_end)) {
                    size_t body_start =
                        (size_t)(regex_literal_start + 1 - p->begin);
                    if (yx_compiler_mixed_greediness_error(
                            p->compiler, p->begin, p->origin,
                            body_start + greedy_start,
                            body_start + greedy_end,
                            body_start + lazy_start,
                            body_start + lazy_end))
                        p->recoverable_invalid_regexp = true;
                    else yx_error(p, "out of memory recording regexp error");
                    goto failure;
                }
                if (!yx_report_pattern_regexp_error(
                        p, &pattern, pattern_start, regex_literal_start,
                        regex_literal_end, regex_status))
                    yx_error(p, "invalid regular expression");
                goto failure;
            }
        }
        pattern.literal_start = (size_t)((text_literal_start ?
            text_literal_start : hex_literal_start ? hex_literal_start :
            regex_literal_start) - p->begin);
        pattern.literal_end = (size_t)((text_literal_end ?
            text_literal_end : hex_literal_end ? hex_literal_end :
            regex_literal_end) - p->begin);
        pattern.pattern_end = pattern.literal_end;
        for (size_t modifier = 0; modifier < 9; ++modifier)
            if (p->modifier_end[modifier] &&
                (size_t)(p->modifier_end[modifier] - p->begin) >
                    pattern.pattern_end)
                pattern.pattern_end =
                    (size_t)(p->modifier_end[modifier] - p->begin);
        if (!yx_append_pattern(p, rule, &pattern, index)) goto failure;
        if (!yx_warn_duplicate_pattern_value(p, rule, index))
            return yx_error(p, "out of memory recording duplicate pattern warning");
        p->current_pattern_identifier = NULL;
        /* MAX_PATTERNS_PER_RULE (ast2ir.rs): checked after the pattern's
         * own errors and its duplicate-value warning. */
        if (rule->pattern_count > 100000) {
            if (!yx_compiler_too_many_patterns_error(
                    p->compiler, p->begin, p->origin, rule->declaration_start,
                    rule->declaration_start + strlen(rule->identifier)))
                return yx_error(p, "out of memory recording too many patterns");
            p->recoverable_invalid_pattern = true;
            return 0;
        }
        continue;
failure:
        p->current_pattern_identifier = NULL;
        free(pattern.identifier);
        free(pattern.bytes);
        free(pattern.mask);
        yx_free_hex_atoms(pattern.hex_atoms, pattern.hex_atom_count);
        free(pattern.regexp);
        free(pattern.base64_alphabet);
        free(pattern.base64wide_alphabet);
        return 0;
    }
}

static int yx_parse_strings(yx_parser *p, YRX_RULE *rule)
{
    yx_pattern_index index;
    int result;
    memset(&index, 0, sizeof(index));
    index.capacity = rule->pattern_count;
    result = yx_parse_strings_indexed(p, rule, &index);
    yx_pattern_table_free(&index.identifiers);
    yx_pattern_table_free(&index.values);
    return result;
}

static int yx_append_tag(yx_parser *p, YRX_RULE *rule, char *tag)
{
    for (size_t i = 0; i < rule->tag_count; ++i)
        if (strcmp(rule->tags[i], tag) == 0) {
            size_t end = (size_t)(p->at - p->begin);
            size_t start = end - strlen(tag);
            if (!yx_compiler_duplicate_tag_error(p->compiler, tag, p->begin,
                                                 p->origin, start, end))
                return yx_error(p, "out of memory recording duplicate tag");
            return 0;
        }
    char **grown = realloc(rule->tags, (rule->tag_count + 1) * sizeof(*grown));
    if (!grown) return yx_error(p, "out of memory");
    rule->tags = grown;
    rule->tags[rule->tag_count++] = tag;
    return 1;
}

static int yx_append_metadata(yx_parser *p, YRX_RULE *rule, YRX_METADATA *metadata)
{
    YRX_METADATA *grown = realloc(rule->metadata, (rule->metadata_count + 1) * sizeof(*grown));
    if (!grown) return yx_error(p, "out of memory");
    rule->metadata = grown;
    rule->metadata[rule->metadata_count++] = *metadata;
    return 1;
}

static int yx_parse_meta(yx_parser *p, YRX_RULE *rule)
{
    size_t width = 0;
    for (;;) {
        yx_space(p);
        const char *section_start = p->at;
        if (!*p->at)
            return yx_syntax_expected(
                p, p->at, p->at,
                rule->metadata_count ? "identifier or `condition`" :
                                       "identifier");
        if (*p->at == '}' || yx_section(p, "strings") || yx_section(p, "condition")) {
            p->at = section_start;
            return 1;
        }
        const char *name_start = p->at;
        char *name = yx_ident(p);
        if (!name)
            return yx_syntax_expected(
                p, p->at, yx_syntax_token_end(p->at),
                rule->metadata_count ?
                    "identifier, `strings` or `condition`" : "identifier");
        if (yx_reserved_identifier(name)) {
            bool section_keyword = strcmp(name, "strings") == 0 ||
                                   strcmp(name, "condition") == 0;
            yx_parser section_probe = *p;
            yx_space(&section_probe);
            if (section_keyword && *section_probe.at != ':') {
                const char *token_end =
                    yx_syntax_token_end(section_probe.at);
                if (*section_probe.at == '$') {
                    token_end = section_probe.at + 1;
                    while ((width = yx_ident_continue_width(token_end)) != 0)
                        token_end += width;
                }
                if (!rule->metadata_count)
                    yx_syntax_expected(p, name_start, p->at,
                                       "identifier");
                yx_syntax_expected(p, section_probe.at, token_end, "`:`");
                p->at = section_probe.at;
                p->suppress_missing_condition_recovery = true;
                free(name);
                return 0;
            }
            bool duplicate_meta_section = rule->metadata_count &&
                                          strcmp(name, "meta") == 0;
            free(name);
            return yx_syntax_expected(p, name_start, p->at,
                                      duplicate_meta_section ?
                                      "identifier, `strings` or `condition`" :
                                      "identifier");
        }
        if (!yx_expect(p, '=')) {
            free(name);
            const char *token_end = yx_syntax_token_end(p->at);
            if (*p->at == '$') {
                token_end = p->at + 1;
                while ((width = yx_ident_continue_width(token_end)) != 0)
                    token_end += width;
            }
            yx_syntax_expected(p, p->at, token_end, "`=`");
            if ((size_t)(token_end - p->at) == 9 &&
                memcmp(p->at, "condition", 9) == 0) {
                yx_parser section_probe = *p;
                section_probe.at = token_end;
                yx_space(&section_probe);
                if (*section_probe.at != ':')
                    yx_syntax_expected(
                        p, section_probe.at,
                        yx_syntax_token_end(section_probe.at), "`:`");
            }
            return 0;
        }
        YRX_METADATA metadata = {0};
        metadata.identifier = name;
        yx_space(p);
        if (*p->at == '"') {
            size_t length = 0;
            const char *literal_start = p->at;
            uint8_t *value = yx_string(p, &length);
            if (!value) { free(name); return 0; }
            if (memchr(literal_start, '\\',
                       (size_t)(p->at - literal_start))) {
                metadata.value_type = YRX_BYTES;
                metadata.value.bytes.data = value;
                metadata.value.bytes.length = length;
            } else {
                metadata.value_type = YRX_STRING;
                metadata.value.string = (const char *)value;
            }
        } else if (yx_keyword(p, "true")) {
            metadata.value_type = YRX_BOOLEAN;
            metadata.value.boolean = true;
        } else if (yx_keyword(p, "false")) {
            metadata.value_type = YRX_BOOLEAN;
            metadata.value.boolean = false;
        } else {
            if (!yx_metadata_number(p, &metadata)) {
                free(name);
                return 0;
            }
        }
        if (!yx_append_metadata(p, rule, &metadata)) {
            free((void *)metadata.identifier);
            if (metadata.value_type == YRX_STRING)
                free((void *)metadata.value.string);
            if (metadata.value_type == YRX_BYTES)
                free((void *)metadata.value.bytes.data);
            return 0;
        }
    }
}

typedef struct {
    yx_parser *parser;
    const YRX_RULE *rule;
} yx_condition_symbols;

static bool yx_condition_identifier_exists(void *user_data, const char *identifier)
{
    const yx_condition_symbols *symbols = user_data;
    const YRX_RULES *rules = symbols->parser->compiler->rules;
    for (size_t i = 0; i < rules->global_count; ++i)
        if (strcmp(rules->globals[i].name, identifier) == 0) return true;
    for (size_t i = 0; i < rules->rule_count; ++i)
        if (strcmp(rules->rules[i].identifier, identifier) == 0 &&
            rules->rules[i].namespace_index == symbols->rule->namespace_index)
            return true;
    for (size_t i = 0; i < rules->import_count; ++i)
        if (strcmp(rules->imports[i], identifier) == 0 &&
            strcmp(identifier, "vt") != 0) return true;
    return false;
}

static bool yx_unknown_field_lookup_condition_error(yx_parser *p,
                                                      const char *start,
                                                      const char *detail);
static int yx_function_value_error(yx_parser *p, const char *start,
                                   const char *at, const char *path,
                                   size_t path_length);

/* Matches a dotted module path where the source may have spaces around a
 * dot (`pe. x`). Returns the source end, or NULL; *mapped receives the
 * source position of name[name_offset], a segment start. */
static const char *yx_dotted_path_match(const char *at, const char *limit,
                                        const char *name, size_t length,
                                        size_t name_offset,
                                        const char **mapped)
{
    size_t i = 0;
    if (mapped) *mapped = NULL;
    while (i < length) {
        if (i == name_offset && mapped) *mapped = at;
        if (name[i] == '.') {
            while (at < limit && isspace((unsigned char)*at)) ++at;
            if (at >= limit || *at != '.') return NULL;
            ++at;
            ++i;
            while (at < limit && isspace((unsigned char)*at)) ++at;
            continue;
        }
        if (at >= limit || *at != name[i]) return NULL;
        ++at;
        ++i;
    }
    if (i == name_offset && mapped) *mapped = at;
    return at;
}

static bool yx_unknown_module_condition_error(yx_parser *p,
                                               const char *start,
                                               const char *detail)
{
    const char *name = NULL, *cursor;
    size_t name_length = 0, path_length = 0;
    char identifier[YX_CONDITION_NAME_SIZE];
    bool unsupported_field = false, found = false;
    if (yx_unknown_field_lookup_condition_error(p, start, detail)) return true;
    if (strncmp(detail, "unsupported module function '", 29) == 0)
        name = detail + 29, unsupported_field = true;
    else if (strncmp(detail, "unsupported module field '", 26) == 0)
        name = detail + 26, unsupported_field = true;
    else if (strncmp(detail, "unsupported indexed module field '", 34) == 0)
        name = detail + 34, unsupported_field = true;
    else if (strncmp(detail, "module is not imported: '", 25) == 0)
        name = detail + 25;
    if (!name) return false;
    while (name[path_length] && name[path_length] != '\'')
        ++path_length;
    /* A path longer than the detail buffer arrives cut off: keep its whole
     * members, the first unknown one comes long before the cut. */
    if (!name[path_length])
        while (path_length && name[--path_length] != '.') {}
    while (name[name_length] && name[name_length] != '.' &&
           name[name_length] != '\'') ++name_length;
    if (!name_length || name_length >= sizeof(identifier)) return false;
    memcpy(identifier, name, name_length);
    identifier[name_length] = '\0';
    cursor = start;
    while (cursor < p->at) {
        if (cursor + 1 < p->at && cursor[0] == '/' &&
            cursor[1] == '/') {
            cursor += 2;
            while (cursor < p->at && *cursor != '\n') ++cursor;
            continue;
        }
        if (cursor + 1 < p->at && cursor[0] == '/' &&
            cursor[1] == '*') {
            cursor += 2;
            while (cursor + 1 < p->at &&
                   !(cursor[0] == '*' && cursor[1] == '/')) ++cursor;
            cursor = cursor + 1 < p->at ? cursor + 2 : p->at;
            continue;
        }
        if (*cursor == '"' || *cursor == '\'') {
            char quote = *cursor++;
            while (cursor < p->at && *cursor != quote) {
                if (*cursor == '\\' && cursor + 1 < p->at) ++cursor;
                ++cursor;
            }
            if (cursor < p->at) ++cursor;
            continue;
        }
        if (*cursor == '/') {
            const char *word_end = cursor;
            const char *word_start;
            bool in_class = false;
            while (word_end > start &&
                   isspace((unsigned char)word_end[-1])) --word_end;
            word_start = word_end;
            while (word_start > start &&
                   isalpha((unsigned char)word_start[-1])) --word_start;
            if ((size_t)(word_end - word_start) == 7 &&
                memcmp(word_start, "matches", 7) == 0) {
                ++cursor;
                while (cursor < p->at) {
                    if (*cursor == '\\' && cursor + 1 < p->at) {
                        cursor += 2;
                        continue;
                    }
                    if (*cursor == '[') in_class = true;
                    else if (*cursor == ']') in_class = false;
                    else if (*cursor == '/' && !in_class) {
                        ++cursor;
                        break;
                    }
                    ++cursor;
                }
                continue;
            }
        }
        if (cursor == start ||
            !(isalnum((unsigned char)cursor[-1]) || cursor[-1] == '_')) {
            const char *matched = yx_dotted_path_match(cursor, p->at, name,
                                                       path_length, 0, NULL);
            if (matched && (matched == p->at || *matched == '(' ||
                            *matched == '[' ||
                            !yx_ident_continue_width(matched))) {
                found = true;
                break;
            }
        }
        ++cursor;
    }
    if (!found) return false;
    if (unsupported_field && name_length < path_length &&
        name[name_length] == '.') {
        int function_value = yx_function_value_error(p, start, cursor,
                                                     name, path_length);
        if (function_value < 0) return false;
        if (function_value) {
            p->recoverable_unknown_identifier = true;
            return true;
        }
    }
    if (unsupported_field && name_length < path_length &&
        name[name_length] == '.') {
        bool imported = false;
        for (size_t i = 0; i < p->compiler->rules->import_count; ++i)
            if (strcmp(p->compiler->rules->imports[i], identifier) == 0) {
                imported = true;
                break;
            }
        if (imported) {
            size_t member_offset = name_length + 1;
            if ((strncmp(name, "pe.rich_signature.", 18) == 0 ||
                 strncmp(name, "pe.overlay.", 11) == 0) &&
                path_length > member_offset)
                member_offset = strncmp(name, "pe.rich_signature.", 18) == 0 ?
                    18 : 11;
            /* Walk the schema: E008 on the first member it lacks, E002 on a
             * field that is not a structure but has a member read from it
             * (`pe.machine.x`). Modules outside the schema keep E008 on
             * their first member. */
            {
                size_t walk = name_length + 1;
                char prefix[YX_CONDITION_NAME_SIZE];
                while (walk < path_length) {
                    size_t walk_end = walk;
                    const char *type, *walk_at = NULL;
                    while (walk_end < path_length && name[walk_end] != '.')
                        ++walk_end;
                    if (walk_end >= sizeof(prefix)) break;
                    memcpy(prefix, name, walk_end);
                    prefix[walk_end] = '\0';
                    type = yx_mo_schema_path_type_name(prefix, false, NULL);
                    if (!type) {
                        /* A module constant (`math.MEAN_BYTES`,
                         * `pe.MACHINE_I386`) is a scalar too. */
                        bool floating = false;
                        if (walk_end < path_length &&
                            yx_condition_module_constant(prefix, &floating))
                            type = floating ? "float" : "integer";
                    }
                    if (!type) {
                        if (walk > member_offset) member_offset = walk;
                        break;
                    }
                    if (walk_end >= path_length) break;
                    if (strcmp(type, "struct") != 0) {
                        (void)yx_dotted_path_match(cursor, p->at, name,
                                                   path_length, walk, &walk_at);
                        if (!walk_at) break;
                        if (!yx_compiler_wrong_type_error(
                                p->compiler, p->begin, p->origin,
                                (size_t)(walk_at - p->begin),
                                (size_t)(walk_at - p->begin) + (walk_end - walk),
                                "`struct`", type)) return false;
                        p->recoverable_unknown_identifier = true;
                        return true;
                    }
                    walk = walk_end + 1;
                }
            }
            const char *member_end = name + member_offset;
            {
                size_t width;
                while ((width = yx_ident_continue_width(member_end)) != 0)
                    member_end += width;
            }
            size_t member_length = (size_t)(member_end - name - member_offset);
            const char *member_at = NULL;
            (void)yx_dotted_path_match(cursor, p->at, name, path_length,
                                       member_offset, &member_at);
            if (member_length && member_length < sizeof(identifier) &&
                member_at) {
                char field[YX_CONDITION_NAME_SIZE];
                memcpy(field, name + member_offset, member_length);
                field[member_length] = '\0';
                if (!yx_compiler_unknown_module_field_error(
                        p->compiler, field, p->begin, p->origin,
                        (size_t)(member_at - p->begin),
                        (size_t)(member_at - p->begin) + member_length))
                    return false;
                p->recoverable_unknown_identifier = true;
                return true;
            }
        }
    }
    /* A member read from a rule, which is a boolean (`a.x`). */
    if (name_length < path_length && name[name_length] == '.') {
        const YRX_RULES *rules = p->compiler->rules;
        for (size_t i = 0; i < rules->rule_count; ++i)
            if (strcmp(rules->rules[i].identifier, identifier) == 0 &&
                rules->rules[i].namespace_index ==
                    p->compiler->current_namespace_index) {
                if (!yx_compiler_wrong_type_error(
                        p->compiler, p->begin, p->origin,
                        (size_t)(cursor - p->begin),
                        (size_t)(cursor - p->begin) + name_length,
                        "`struct`", "boolean")) return false;
                p->recoverable_unknown_identifier = true;
                return true;
            }
    }
    if (!yx_compiler_unknown_identifier_error(
            p->compiler, identifier, p->begin, p->origin,
            (size_t)(cursor - p->begin),
            (size_t)(cursor - p->begin) + name_length)) return false;
    p->recoverable_unknown_identifier = true;
    return true;
}

static bool yx_unknown_pattern_condition_error(yx_parser *p,
                                               const char *start,
                                               const char *detail)
{
    static const char prefix[] = "unknown pattern '$";
    const char *name, *cursor;
    size_t name_length;
    char pattern[YX_CONDITION_NAME_SIZE];
    if (strncmp(detail, prefix, sizeof(prefix) - 1) != 0) return false;
    name = detail + sizeof(prefix) - 1;
    name_length = strlen(name);
    if (name_length < 2 || name[name_length - 1] != '\'' ||
        name_length >= sizeof(pattern) - 1) return false;
    --name_length;
    cursor = start;
    while (cursor < p->at) {
        if (cursor + 1 < p->at && cursor[0] == '/' &&
            cursor[1] == '/') {
            cursor += 2;
            while (cursor < p->at && *cursor != '\n') ++cursor;
            continue;
        }
        if (cursor + 1 < p->at && cursor[0] == '/' &&
            cursor[1] == '*') {
            cursor += 2;
            while (cursor + 1 < p->at &&
                   !(cursor[0] == '*' && cursor[1] == '/')) ++cursor;
            cursor = cursor + 1 < p->at ? cursor + 2 : p->at;
            continue;
        }
        if (*cursor == '"' || *cursor == '\'') {
            char quote = *cursor++;
            while (cursor < p->at && *cursor != quote) {
                if (*cursor == '\\' && cursor + 1 < p->at) ++cursor;
                ++cursor;
            }
            if (cursor < p->at) ++cursor;
            continue;
        }
        if (*cursor == '/') {
            const char *word_end = cursor;
            const char *word_start;
            bool in_class = false;
            while (word_end > start &&
                   isspace((unsigned char)word_end[-1])) --word_end;
            word_start = word_end;
            while (word_start > start &&
                   isalpha((unsigned char)word_start[-1])) --word_start;
            if ((size_t)(word_end - word_start) == 7 &&
                memcmp(word_start, "matches", 7) == 0) {
                ++cursor;
                while (cursor < p->at) {
                    if (*cursor == '\\' && cursor + 1 < p->at) {
                        cursor += 2;
                        continue;
                    }
                    if (*cursor == '[') in_class = true;
                    else if (*cursor == ']') in_class = false;
                    else if (*cursor == '/' && !in_class) {
                        ++cursor;
                        break;
                    }
                    ++cursor;
                }
                continue;
            }
        }
        if ((*cursor == '$' || *cursor == '#' || *cursor == '@' ||
             *cursor == '!') &&
            (size_t)(p->at - cursor) > name_length &&
            memcmp(cursor + 1, name, name_length) == 0 &&
            !yx_ident_continue_width(cursor + name_length + 1)) {
            pattern[0] = *cursor;
            memcpy(pattern + 1, name, name_length);
            pattern[name_length + 1] = '\0';
            if (!yx_compiler_unknown_pattern_error(
                    p->compiler, pattern, p->begin, p->origin,
                    (size_t)(cursor - p->begin),
                    (size_t)(cursor - p->begin) + name_length + 1))
                return false;
            p->recoverable_unknown_identifier = true;
            return true;
        }
        ++cursor;
    }
    return false;
}

static const char *yx_condition_skip_noncode(const char *cursor,
                                              const char *start,
                                              const char *end)
{
    if (cursor + 1 < end && cursor[0] == '/' && cursor[1] == '/') {
        cursor += 2;
        while (cursor < end && *cursor != '\n') ++cursor;
        return cursor;
    }
    if (cursor + 1 < end && cursor[0] == '/' && cursor[1] == '*') {
        cursor += 2;
        while (cursor + 1 < end && !(cursor[0] == '*' && cursor[1] == '/'))
            ++cursor;
        return cursor + 1 < end ? cursor + 2 : end;
    }
    if (*cursor == '"' || *cursor == '\'') {
        char quote = *cursor++;
        while (cursor < end && *cursor != quote) {
            if (*cursor == '\\' && cursor + 1 < end) ++cursor;
            ++cursor;
        }
        return cursor < end ? cursor + 1 : end;
    }
    if (*cursor == '/') {
        const char *word_end = cursor;
        const char *word_start;
        bool in_class = false;
        while (word_end > start && isspace((unsigned char)word_end[-1]))
            --word_end;
        word_start = word_end;
        while (word_start > start && isalpha((unsigned char)word_start[-1]))
            --word_start;
        if ((size_t)(word_end - word_start) != 7 ||
            memcmp(word_start, "matches", 7) != 0) return cursor;
        ++cursor;
        while (cursor < end) {
            if (*cursor == '\\' && cursor + 1 < end) {
                cursor += 2;
                continue;
            }
            if (*cursor == '[') in_class = true;
            else if (*cursor == ']') in_class = false;
            else if (*cursor == '/' && !in_class) return cursor + 1;
            ++cursor;
        }
        return end;
    }
    return cursor;
}

static bool yx_anonymous_pattern_condition_error(yx_parser *p,
                                                  const char *start,
                                                  const char *detail)
{
    const char *cursor = start;
    char label[96];
    static const char prefix[] = "anonymous pattern reference requires for-of";
    size_t at;
    if (strncmp(detail, prefix, sizeof(prefix) - 1) != 0) return false;
    /* The detail carries the reference the validation rejected. */
    if (sscanf(detail + sizeof(prefix) - 1, " span:%zu", &at) == 1 &&
        at < (size_t)(p->at - start))
        cursor = start + at;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        if ((*cursor == '!' || *cursor == '#' ||
             *cursor == '$' || *cursor == '@') &&
            !(*cursor == '!' && cursor[1] == '=') &&
            (cursor + 1 == p->at || !yx_ident_continue_width(cursor + 1))) {
            snprintf(label, sizeof(label),
                     "this `%c` is outside of the body of a `for .. of` statement",
                     *cursor);
            if (!yx_compiler_syntax_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(cursor - p->begin),
                    (size_t)(cursor - p->begin) + 1, label)) return false;
            p->recoverable_unknown_identifier = true;
            return true;
        }
        ++cursor;
    }
    return false;
}

static bool yx_pattern_set_filter_condition_error(yx_parser *p,
                                                   const char *start,
                                                   const char *detail)
{
    const char *cursor = start, *unexpected = NULL;
    const char *word = NULL;
    char label[32];
    if (strstr(detail, "'at' and 'in' require a pattern or pattern count") == NULL)
        return false;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        if ((size_t)(p->at - cursor) >= 2 &&
            (memcmp(cursor, "at", 2) == 0 ||
             memcmp(cursor, "in", 2) == 0) &&
            (cursor == start || !yx_ident_continue_width_before(start, cursor)) &&
            (cursor + 2 == p->at || !yx_ident_continue_width(cursor + 2))) {
            unexpected = cursor;
            word = cursor[0] == 'a' ? "at" : "in";
            cursor += 2;
            continue;
        }
        ++cursor;
    }
    if (!unexpected) return false;
    snprintf(label, sizeof(label), "unexpected `%s`", word);
    if (!yx_compiler_syntax_error(p->compiler, p->begin, p->origin,
                                  (size_t)(unexpected - p->begin),
                                  (size_t)(unexpected - p->begin) + 2,
                                  label)) return false;
    p->recoverable_unknown_identifier = true;
    return true;
}

typedef enum {
    YX_DIAG_WORD, YX_DIAG_INTEGER, YX_DIAG_FLOAT,
    YX_DIAG_STRING, YX_DIAG_SYMBOL
} yx_diag_token_kind;

typedef struct {
    const char *start;
    const char *end;
    yx_diag_token_kind kind;
} yx_diag_token;

static bool yx_diag_token_is(const yx_diag_token *token, const char *word)
{
    size_t length = strlen(word);
    return (size_t)(token->end - token->start) == length &&
           memcmp(token->start, word, length) == 0;
}

static bool yx_diag_plain_identifier(const yx_diag_token *token)
{
    char name[64];
    size_t length = (size_t)(token->end - token->start);
    if (token->kind != YX_DIAG_WORD || !length ||
        length >= sizeof(name) ||
        !(isalpha((unsigned char)*token->start) ||
          *token->start == '_')) return false;
    memcpy(name, token->start, length);
    name[length] = '\0';
    return !yx_reserved_identifier(name) && strcmp(name, "entrypoint") != 0;
}

static bool yx_condition_diag_tokens(const char *start, const char *end,
                                     yx_diag_token **out, size_t *count)
{
    const char *cursor = start;
    yx_diag_token *tokens = NULL;
    size_t used = 0, capacity = 0;
    while (cursor < end) {
        yx_diag_token token = {0};
        const char *next;
        if (isspace((unsigned char)*cursor)) { ++cursor; continue; }
        if (cursor + 1 < end && cursor[0] == '/' && cursor[1] == '/') {
            cursor += 2;
            while (cursor < end && *cursor != '\n') ++cursor;
            continue;
        }
        if (cursor + 1 < end && cursor[0] == '/' && cursor[1] == '*') {
            cursor += 2;
            while (cursor + 1 < end && !(cursor[0] == '*' && cursor[1] == '/'))
                ++cursor;
            cursor = cursor + 1 < end ? cursor + 2 : end;
            continue;
        }
        token.start = cursor;
        if (*cursor == '"') {
            token.kind = YX_DIAG_STRING;
            ++cursor;
            while (cursor < end && *cursor != '"') {
                if (*cursor == '\\' && cursor + 1 < end) ++cursor;
                ++cursor;
            }
            if (cursor < end) ++cursor;
        } else if (isdigit((unsigned char)*cursor)) {
            token.kind = YX_DIAG_INTEGER;
            if (cursor + 2 < end && cursor[0] == '0' &&
                (cursor[1] == 'x' || cursor[1] == 'X' ||
                 cursor[1] == 'o' || cursor[1] == 'O')) {
                cursor += 2;
                while (cursor < end &&
                       (isalnum((unsigned char)*cursor) || *cursor == '_'))
                    ++cursor;
            } else {
                while (cursor < end &&
                       (isdigit((unsigned char)*cursor) || *cursor == '_'))
                    ++cursor;
                if (cursor + 1 < end && cursor[0] == '.' &&
                    isdigit((unsigned char)cursor[1])) {
                    token.kind = YX_DIAG_FLOAT;
                    ++cursor;
                    while (cursor < end &&
                           (isdigit((unsigned char)*cursor) || *cursor == '_'))
                        ++cursor;
                }
            }
        } else if (*cursor == '!' && cursor + 1 < end && cursor[1] == '=') {
            token.kind = YX_DIAG_SYMBOL;
            cursor += 2;
        } else if (isalpha((unsigned char)*cursor) || *cursor == '_' ||
                   *cursor == '$' || *cursor == '#' ||
                   *cursor == '@' || *cursor == '!') {
            token.kind = YX_DIAG_WORD;
            ++cursor;
            while (cursor < end) {
                size_t width = yx_ident_continue_width(cursor);
                if (!width) break;
                cursor += width;
            }
        } else {
            token.kind = YX_DIAG_SYMBOL;
            ++cursor;
            if (cursor < end &&
                ((token.start[0] == '<' && (*cursor == '<' || *cursor == '=')) ||
                 (token.start[0] == '>' && (*cursor == '>' || *cursor == '=')) ||
                 (token.start[0] == '=' && *cursor == '=') ||
                 (token.start[0] == '.' && *cursor == '.')))
                ++cursor;
        }
        token.end = cursor;
        if (used == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 32;
            yx_diag_token *grown;
            if (next_capacity < capacity ||
                next_capacity > SIZE_MAX / sizeof(*tokens)) {
                free(tokens);
                return false;
            }
            grown = realloc(tokens, next_capacity * sizeof(*tokens));
            if (!grown) { free(tokens); return false; }
            tokens = grown;
            capacity = next_capacity;
        }
        tokens[used++] = token;
        next = cursor;
        if (token.kind == YX_DIAG_SYMBOL && token.start[0] == '/' &&
            used >= 2 && yx_diag_token_is(&tokens[used - 2], "matches")) {
            bool in_class = false;
            while (next < end) {
                if (*next == '\\' && next + 1 < end) { next += 2; continue; }
                if (*next == '[') in_class = true;
                else if (*next == ']') in_class = false;
                else if (*next == '/' && !in_class) { ++next; break; }
                ++next;
            }
            tokens[used - 1].end = next;
            cursor = next;
        }
    }
    *out = tokens;
    *count = used;
    return true;
}

/* Canonical module names can differ from aliases in the source. Locate the
 * first unresolved member by its ordinal, ignoring fields inside indices. */
static bool yx_unknown_field_lookup_condition_error(yx_parser *p,
                                                      const char *start,
                                                      const char *detail)
{
    size_t source_start, source_end, ordinal, count = 0, member = 0, brackets = 0;
    size_t receiver = SIZE_MAX;
    yx_diag_token *tokens = NULL;
    char field[YX_CONDITION_NAME_SIZE], type[16] = "";
    bool ok = false, lookup = false;
    /* A member read from a field that is not a structure: E002 on that
     * field (`name` in `pe.sections[0].name.x`), on the whole lookup when
     * the value is an item (`v["k"]` in `v["k"].x`). A lookup in a value
     * that is no array or map: E002 on the lookup's primary. Ordinal 0 is
     * the span's first word, a `with` binding. */
    bool typed = sscanf(detail, "module member type:%zu:%zu:%zu:%15[^:]:%4095s",
                        &source_start, &source_end, &ordinal, type,
                        field) == 5;
    if (!typed)
        typed = lookup =
            sscanf(detail, "module lookup type:%zu:%zu:%zu:%15[^:]:%4095s",
                   &source_start, &source_end, &ordinal, type, field) == 5;
    if (!typed) type[0] = '\0';
    if ((!typed &&
         sscanf(detail, "module unknown field:%zu:%zu:%zu:%4095s",
                &source_start, &source_end, &ordinal, field) != 4) ||
        (!ordinal && !typed) || source_start >= source_end ||
        source_end > (size_t)(p->at - start) ||
        !yx_condition_diag_tokens(start + source_start, start + source_end,
                                  &tokens, &count)) return false;
    if (!ordinal) {
        if (count && tokens[0].kind == YX_DIAG_WORD) receiver = 0;
    } else {
        for (size_t i = 0; i < count; ++i) {
            if (yx_diag_token_is(&tokens[i], "[")) { ++brackets; continue; }
            if (yx_diag_token_is(&tokens[i], "]")) {
                if (brackets) --brackets;
                continue;
            }
            if (brackets || !yx_diag_token_is(&tokens[i], ".") ||
                i + 1 == count || tokens[i + 1].kind != YX_DIAG_WORD) continue;
            if (++member != ordinal) continue;
            if (yx_diag_token_is(&tokens[i + 1], field)) receiver = i + 1;
            break;
        }
        /* An unknown member the ordinal misses: its first `.member`. */
        for (size_t i = 0; receiver == SIZE_MAX && !typed && i + 1 < count; ++i)
            if (yx_diag_token_is(&tokens[i], ".") &&
                tokens[i + 1].kind == YX_DIAG_WORD &&
                yx_diag_token_is(&tokens[i + 1], field)) receiver = i + 1;
    }
    if (receiver != SIZE_MAX) {
        const char *span_start = tokens[receiver].start;
        const char *span_end = tokens[receiver].end;
        if (lookup) span_start = tokens[0].start;
        else if (typed && receiver + 1 < count &&
                 yx_diag_token_is(&tokens[receiver + 1], "[")) {
            size_t depth = 0;
            for (size_t i = receiver + 1; i < count; ++i) {
                if (yx_diag_token_is(&tokens[i], "[")) ++depth;
                else if (yx_diag_token_is(&tokens[i], "]") && !--depth) {
                    span_start = tokens[0].start;
                    span_end = tokens[i].end;
                    break;
                }
            }
        }
        ok = typed ?
            yx_compiler_wrong_type_error(
                p->compiler, p->begin, p->origin,
                (size_t)(span_start - p->begin), (size_t)(span_end - p->begin),
                lookup ? "`array` or `map`" : "`struct`", type) != 0 :
            yx_compiler_unknown_module_field_error(
                p->compiler, field, p->begin, p->origin,
                (size_t)(span_start - p->begin),
                (size_t)(span_end - p->begin)) != 0;
    }
    free(tokens);
    if (ok) p->recoverable_unknown_identifier = true;
    return ok;
}

/* Module functions are values of type function when referenced without a
 * call. `help` marks those with a signature that takes no arguments or
 * returns a bool: bool_expr_from_ast then suggests calling them (measured
 * with the official yr.exe 1.23.0). */
static const struct { const char *path; bool help; } yx_module_functions[] = {
    {"console.hex", true}, {"console.log", true}, {"crx.permhash", true},
    {"cuckoo.filesystem.file_access", false},
    {"cuckoo.network.dns_lookup", false}, {"cuckoo.network.host", false},
    {"cuckoo.network.http_get", false}, {"cuckoo.network.http_post", false},
    {"cuckoo.network.http_request", false},
    {"cuckoo.network.http_user_agent", false},
    {"cuckoo.network.tcp", false}, {"cuckoo.network.udp", false},
    {"cuckoo.registry.key_access", false}, {"cuckoo.sync.mutex", false},
    {"dex.checksum", true}, {"dex.contains_class", true},
    {"dex.contains_method", true}, {"dex.contains_string", true},
    {"dex.signature", true}, {"elf.import_md5", true}, {"elf.telfhash", true},
    {"hash.checksum32", false}, {"hash.crc32", false}, {"hash.md5", false},
    {"hash.sha1", false}, {"hash.sha256", false},
    {"macho.dylib_hash", true}, {"macho.entitlement_hash", true},
    {"macho.entry_point_for_arch", false}, {"macho.export_hash", true},
    {"macho.file_index_for_arch", false}, {"macho.has_dylib", true},
    {"macho.has_entitlement", true}, {"macho.has_export", true},
    {"macho.has_import", true}, {"macho.has_rpath", true},
    {"macho.import_hash", true}, {"macho.symhash", true},
    {"math.abs", false}, {"math.count", false}, {"math.deviation", false},
    {"math.entropy", false}, {"math.in_range", true}, {"math.max", false},
    {"math.mean", false}, {"math.min", false}, {"math.mode", true},
    {"math.monte_carlo_pi", false}, {"math.percentage", false},
    {"math.serial_correlation", false}, {"math.to_number", false},
    {"math.to_string", false}, {"pe.calculate_checksum", true},
    {"pe.delayed_import_rva", false}, {"pe.exports", true},
    {"pe.exports_index", false}, {"pe.imphash", true},
    {"pe.import_rva", false}, {"pe.imports", true},
    {"pe.is_32bit", true}, {"pe.is_64bit", true}, {"pe.is_dll", true},
    {"pe.language", true}, {"pe.locale", true}, {"pe.offset_to_rva", false},
    {"pe.rich_signature.toolid", false}, {"pe.rich_signature.version", false},
    {"pe.rva_to_offset", false}, {"pe.section_index", false},
    {"string.length", false}, {"string.to_int", false}, {"time.now", true}
};

bool yx_module_function_path(const char *path, size_t length, bool *help)
{
    for (size_t i = 0; i < sizeof(yx_module_functions) /
                           sizeof(*yx_module_functions); ++i)
        if (strlen(yx_module_functions[i].path) == length &&
            !memcmp(yx_module_functions[i].path, path, length)) {
            if (help) *help = yx_module_functions[i].help;
            return true;
        }
    return false;
}

static bool yx_diag_token_in(const yx_diag_token *token,
                             const char *const *words, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (yx_diag_token_is(token, words[i])) return true;
    return false;
}

/* The binding strength of the operator a token spells, and the types its
 * operands may have (check_type in ast2ir.rs); 0 for any other token. */
static unsigned yx_function_operand_operator(const yx_diag_token *token,
                                             const char **accepted)
{
    static const struct {
        const char *spelling;
        unsigned precedence;
        const char *accepted;
    } operators[] = {
        {"*", 11, "`float` or `integer`"}, {"\\", 11, "`float` or `integer`"},
        {"%", 11, "`integer`"},
        {"+", 10, "`float` or `integer`"}, {"-", 10, "`float` or `integer`"},
        {"<<", 9, "`integer`"}, {">>", 9, "`integer`"},
        {"&", 8, "`integer`"}, {"^", 7, "`integer`"}, {"|", 6, "`integer`"},
        {"<", 5, "`float`, `integer`, or `string`"},
        {"<=", 5, "`float`, `integer`, or `string`"},
        {">", 5, "`float`, `integer`, or `string`"},
        {">=", 5, "`float`, `integer`, or `string`"},
        {"!=", 4, "`float`, `integer`, or `string`"},
        {"==", 4, "`boolean`, `float`, `integer`, or `string`"},
        {"contains", 4, "`string`"}, {"icontains", 4, "`string`"},
        {"startswith", 4, "`string`"}, {"istartswith", 4, "`string`"},
        {"endswith", 4, "`string`"}, {"iendswith", 4, "`string`"},
        {"iequals", 4, "`string`"}, {"matches", 4, "`string`"}
    };
    if (!token) return 0;
    for (size_t i = 0; i < sizeof(operators) / sizeof(operators[0]); ++i)
        if (yx_diag_token_is(token, operators[i].spelling)) {
            *accepted = operators[i].accepted;
            return operators[i].precedence;
        }
    return 0;
}

/* A module function referenced without a call (E002). Where a bool is
 * expected (the condition, a `for`/`with` body, an `of` tuple item) the
 * label says "a function" and may suggest the call; as an operand of
 * `not`, `defined`, `and`, `or` or a comparison it says `function`, and
 * `and`/`or` also warn non_bool_expr. Other contexts are not modeled.
 * Returns 1 when recorded, 0 when not applicable, -1 on failure. */
static int yx_function_value_error_at(yx_parser *p, const char *start,
                                      const char *at, size_t path_length,
                                      bool help);

static int yx_function_value_error(yx_parser *p, const char *start,
                                   const char *at, const char *path,
                                   size_t path_length)
{
    for (size_t i = 0; i < sizeof(yx_module_functions) /
                           sizeof(*yx_module_functions); ++i)
        if (strlen(yx_module_functions[i].path) == path_length &&
            !memcmp(yx_module_functions[i].path, path, path_length))
            return yx_function_value_error_at(p, start, at, path_length,
                                              yx_module_functions[i].help);
    return 0;
}

/* The same for the `path_length` bytes at `at`, which name a function:
 * its path, or a `with` name that stands for it. */
static int yx_function_value_error_at(yx_parser *p, const char *start,
                                      const char *at, size_t path_length,
                                      bool help)
{
    static const char *const logical[] = {"and", "or"};
    static const char *const unary[] = {"not", "defined"};
    static const char *const comparisons[] = {
        "==", "!=", "<", "<=", ">", ">=", "contains", "icontains",
        "startswith", "istartswith", "endswith", "iendswith", "iequals",
        "matches"
    };
    yx_diag_token *tokens = NULL;
    const yx_diag_token *before, *after;
    /* The operand types of the operator the function is an operand of. */
    const char *accepted = "`boolean`, `float`, `integer`, or `string`";
    size_t count = 0, first = SIZE_MAX, last = SIZE_MAX, begin, end;
    bool operand, warn = false, boolean = false;
    char snippet[256];
    int result = 0;
    if (path_length >= sizeof(snippet) - 3) return 0;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count)) return -1;
    for (size_t i = 0; i < count; ++i) {
        if (tokens[i].start == at) first = i;
        if (first != SIZE_MAX && tokens[i].end == at + path_length) {
            last = i;
            break;
        }
    }
    if (first == SIZE_MAX || last == SIZE_MAX) goto done;
    /* Parentheses add no node. */
    while (first > 0 && last + 1 < count &&
           yx_diag_token_is(&tokens[first - 1], "(") &&
           yx_diag_token_is(&tokens[last + 1], ")")) {
        --first;
        ++last;
    }
    before = first > 0 ? &tokens[first - 1] : NULL;
    after = last + 1 < count ? &tokens[last + 1] : NULL;
    operand = (before && yx_diag_token_in(before, unary, 2)) ||
              (before && yx_diag_token_in(before, comparisons, 14)) ||
              (after && yx_diag_token_in(after, comparisons, 14));
    if (!(before && yx_diag_token_in(before, unary, 2))) {
        /* The operator that binds the function: a unary `-` or `~` in
         * front of it, or else the stronger of its two neighbours (the
         * left one when they are equal). */
        const char *before_accepted = NULL, *after_accepted = NULL;
        unsigned before_strength =
            yx_function_operand_operator(before, &before_accepted);
        unsigned after_strength =
            yx_function_operand_operator(after, &after_accepted);
        const yx_diag_token *previous = first > 1 ? &tokens[first - 2] : NULL;
        bool prefix = before &&
            (yx_diag_token_is(before, "-") || yx_diag_token_is(before, "~")) &&
            (!previous || (previous->kind == YX_DIAG_SYMBOL &&
                           !yx_diag_token_is(previous, ")") &&
                           !yx_diag_token_is(previous, "]")) ||
             (previous->kind == YX_DIAG_WORD &&
              (yx_diag_token_in(previous, unary, 2) ||
               yx_diag_token_in(previous, logical, 2) ||
               yx_diag_token_in(previous, comparisons, 14))));
        if (prefix) {
            accepted = yx_diag_token_is(before, "~") ?
                "`integer`" : "`float` or `integer`";
            operand = true;
        } else if (before_strength || after_strength) {
            accepted = before_strength >= after_strength ? before_accepted :
                                                           after_accepted;
            /* The right operand of `matches` is a regexp. */
            if (before_strength >= after_strength &&
                yx_diag_token_is(before, "matches"))
                accepted = "`regexp`";
            operand = true;
        }
    }
    /* `not`, `defined` and comparisons bind tighter than `and`/`or`. */
    warn = !operand &&
           ((before && yx_diag_token_in(before, logical, 2)) ||
            (after && yx_diag_token_in(after, logical, 2)));
    if (!operand && !warn) {
        if (!before && !after) boolean = true;
        else if (before && yx_diag_token_is(before, ":")) boolean = true;
        else if (before && after &&
                 (yx_diag_token_is(before, "(") || yx_diag_token_is(before, ",")) &&
                 (yx_diag_token_is(after, ")") || yx_diag_token_is(after, ","))) {
            /* An item of `<quantifier> of (...)`. */
            size_t depth = 0, i = first;
            while (i-- > 0) {
                if (yx_diag_token_is(&tokens[i], ")")) ++depth;
                else if (yx_diag_token_is(&tokens[i], "(")) {
                    if (!depth) break;
                    --depth;
                }
            }
            boolean = i < first && i > 0 && yx_diag_token_is(&tokens[i - 1], "of");
        }
        if (!boolean) goto done;
    }
    begin = (size_t)(at - p->begin);
    end = begin + path_length;
    if (boolean) {
        snprintf(snippet, sizeof(snippet), "%.*s()", (int)path_length, at);
        {
            char help_text[300];
            snprintf(help_text, sizeof(help_text), "you probably meant %s",
                     snippet);
            result = (help ?
                      yx_compiler_wrong_type_help_error(
                          p->compiler, p->begin, p->origin, begin, end,
                          "`bool`", "a function", help_text) :
                      yx_compiler_wrong_type_error(
                          p->compiler, p->begin, p->origin, begin, end,
                          "`bool`", "a function")) ? 1 : -1;
        }
    } else {
        if (warn && !yx_compiler_nonbool_function_warning(
                p->compiler, p->begin, p->origin, begin, end)) {
            result = -1;
            goto done;
        }
        result = yx_compiler_wrong_type_error(
            p->compiler, p->begin, p->origin, begin, end,
            accepted, "function") ? 1 : -1;
    }
done:
    free(tokens);
    return result;
}

/* The reference lexer does not accept scientific notation. It first emits
 * the decimal integer or float, then an identifier beginning at `e`/`E`.
 * Remember that boundary so a later condition-parser failure can be rendered
 * at the identifier, without treating a hexadecimal digit as an exponent. */
static bool yx_exponent_suffix(const char *start, const char *suffix)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool found = false;
    if ((*suffix != 'e' && *suffix != 'E') ||
        suffix == start || !isdigit((unsigned char)suffix[-1]) ||
        !yx_condition_diag_tokens(start, suffix, &tokens, &count))
        return false;
    if (count) {
        const yx_diag_token *number = &tokens[count - 1];
        found = (number->kind == YX_DIAG_INTEGER ||
                 number->kind == YX_DIAG_FLOAT) &&
                number->end == suffix &&
                !((size_t)(number->end - number->start) >= 2 &&
                  number->start[0] == '0' &&
                  (number->start[1] == 'x' || number->start[1] == 'X' ||
                   number->start[1] == 'o' || number->start[1] == 'O'));
    }
    free(tokens);
    return found;
}

static bool yx_exponent_notation_syntax_error(yx_parser *p,
                                               const char *start,
                                               const char *suffix)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0, open = SIZE_MAX, depth = 0;
    const char *expected = NULL;
    bool call = false, grouped, range_lower = false, range_upper = false;
    bool comparison = false, arithmetic = false;
    bool logical = false, remainder = false;
    if (!suffix || !yx_condition_diag_tokens(start, suffix, &tokens, &count) ||
        !count || tokens[count - 1].end != suffix) {
        free(tokens);
        return false;
    }
    for (size_t i = count; i > 0; --i) {
        if (yx_diag_token_is(&tokens[i - 1], ")")) ++depth;
        else if (yx_diag_token_is(&tokens[i - 1], "(")) {
            if (!depth) { open = i - 1; break; }
            --depth;
        }
    }
    grouped = open != SIZE_MAX;
    if (grouped && open > 0 && yx_diag_token_is(&tokens[open - 1], "in")) {
        bool quantifier = false;
        for (size_t i = 0; i + 1 < open; ++i)
            if (yx_diag_token_is(&tokens[i], "for")) {
                quantifier = true;
                break;
            }
        if (quantifier && count == open + 2)
            range_lower = true;
        else if (quantifier && count >= open + 4 &&
                 yx_diag_token_is(&tokens[count - 2], ".."))
            range_upper = true;
    }
    if (grouped && open > 0 &&
        tokens[open - 1].kind == YX_DIAG_WORD &&
        tokens[open - 1].end == tokens[open].start) {
        const yx_diag_token *name = &tokens[open - 1];
        call = !yx_diag_token_is(name, "in") &&
               !yx_diag_token_is(name, "of") &&
               !yx_diag_token_is(name, "and") &&
               !yx_diag_token_is(name, "or") &&
               !yx_diag_token_is(name, "not");
    }
    if (count >= 2) {
        const yx_diag_token *before = &tokens[count - 2];
        comparison = yx_diag_token_is(before, "==") ||
            yx_diag_token_is(before, "!=") ||
            yx_diag_token_is(before, "<") ||
            yx_diag_token_is(before, "<=") ||
            yx_diag_token_is(before, ">") ||
            yx_diag_token_is(before, ">=");
        remainder = yx_diag_token_is(before, "%");
        logical = yx_diag_token_is(before, "and") ||
            yx_diag_token_is(before, "or") ||
            yx_diag_token_is(before, "not");
        arithmetic = yx_diag_token_is(before, "+") ||
            yx_diag_token_is(before, "-") ||
            yx_diag_token_is(before, "*") ||
            yx_diag_token_is(before, "/") ||
            yx_diag_token_is(before, "<<") ||
            yx_diag_token_is(before, ">>") ||
            yx_diag_token_is(before, "&") ||
            yx_diag_token_is(before, "|") ||
            yx_diag_token_is(before, "^");
        if (arithmetic && yx_diag_token_is(before, "-")) {
            /* A prefix minus belongs to the number, not to an expression
             * on its left. */
            arithmetic = count >= 3 &&
                (tokens[count - 3].kind == YX_DIAG_INTEGER ||
                 tokens[count - 3].kind == YX_DIAG_FLOAT ||
                 yx_diag_token_is(&tokens[count - 3], ")") ||
                 yx_diag_token_is(&tokens[count - 3], "]"));
        }
    }
    if (range_lower)
        expected = "operator, `.`, `,` or `)`";
    else if (range_upper)
        expected = "operator or `)`";
    else if (grouped && open > 0 && count == open + 2 &&
        (yx_diag_token_is(&tokens[open - 1], "==") ||
         yx_diag_token_is(&tokens[open - 1], "!=") ||
         yx_diag_token_is(&tokens[open - 1], "<") ||
         yx_diag_token_is(&tokens[open - 1], ">") ||
         yx_diag_token_is(&tokens[open - 1], "<=") ||
         yx_diag_token_is(&tokens[open - 1], ">=")))
        expected = "operator or `)`";
    else if (call)
        expected = comparison ? "operator, expression, `,` or `)`" :
            arithmetic ? "operator, `of`, expression, `,` or `)`" :
            "`%`, operator, `of`, expression, `,` or `)`";
    else if (comparison)
        expected = grouped ? "operator, expression or `)`" :
                             "operator, expression or `}`";
    else if (remainder)
        expected = grouped ? "operator, `)` or expression" :
                             "operator, expression or `}`";
    else if (logical)
        expected = grouped ? "`%`, operator, `of`, expression or `)`" :
                             "`%`, operator, `of`, expression or `}`";
    else if (arithmetic)
        expected = grouped ? "operator, `)`, `of` or expression" :
                             "operator, `of`, expression or `}`";
    else
        expected = grouped ? "operator, `)`, `%`, `of` or expression" :
                             "`%`, operator, `of`, expression or `}`";
    free(tokens);
    yx_syntax_expected(p, suffix, yx_syntax_token_end(suffix), expected);
    return true;
}

typedef struct {
    yx_parser *parser;
    const char *start, *limit;
} yx_loop_iterations_context;

static bool yx_condition_loop_iterations_warning(size_t start, size_t end,
                                                 uint64_t iterations,
                                                 void *user)
{
    yx_loop_iterations_context *context = user;
    yx_parser *p = context->parser;
    size_t offset = (size_t)(context->start - p->begin);
    if (end > (size_t)(p->at - context->start)) return true;
    if (context->limit && context->start + start >= context->limit) return true;
    return yx_compiler_too_many_iterations_warning(
        p->compiler, p->begin, p->origin, offset + start, offset + end,
        iterations) != 0;
}

/* too_many_iterations from the parsed condition (condition.c,
 * yx_condition_visit_loop_iterations). Loops starting at or after `limit`
 * (when not NULL) are not reported: YARA-X warns about a loop before
 * compiling its body, so the loops that enclose or precede a failing
 * statement have already been reported. */
static bool yx_condition_warn_too_many_iterations(yx_parser *p,
                                                   const YRX_RULE *rule,
                                                   const char *start,
                                                   const char *limit)
{
    yx_loop_iterations_context context = {p, start, limit};
    return yx_condition_visit_loop_iterations(
        rule->condition, yx_condition_loop_iterations_warning, &context);
}

/* Where in the source YARA-X is when it raises a condition warning, for
 * the kinds whose order against an `of` expression's warnings is known:
 * a recorded point (warning_point_keys in internal.h); `<n> of` asking for
 * more items than there are, the whole rule's invariant_expr (raised after
 * the condition) and the label of the kinds raised at their label. */
/* A recorded point by its key, for a binary search of the first point
 * recorded for a warning. */
typedef struct {
    uintptr_t key;
    size_t index;
} yx_warning_point_record;

static int yx_warning_point_compare(const void *a, const void *b)
{
    const yx_warning_point_record *left = a, *right = b;
    if (left->key != right->key) return left->key < right->key ? -1 : 1;
    return left->index < right->index ? -1 : left->index > right->index;
}

/* `sorted`, when given, lists the compiler's recorded points (those of the
 * condition being compiled) by key, then by index. */
static bool yx_warning_raise_position(const YRX_COMPILER *compiler,
                                      const char *warning,
                                      const yx_warning_point_record *sorted,
                                      size_t *position)
{
    const char *span = strstr(warning, "\"span\":{\"start\":");
    size_t start, end;
    if (sorted) {
        size_t low = 0, high = compiler->warning_point_count;
        while (low < high) {
            size_t middle = low + (high - low) / 2;
            if (sorted[middle].key < (uintptr_t)warning) low = middle + 1;
            else high = middle;
        }
        if (low < compiler->warning_point_count &&
            sorted[low].key == (uintptr_t)warning) {
            *position = compiler->warning_point_values[sorted[low].index];
            return true;
        }
    } else {
        for (size_t i = 0; i < compiler->warning_point_count; ++i)
            if (compiler->warning_point_keys[i] == warning) {
                *position = compiler->warning_point_values[i];
                return true;
            }
    }
    if (!yx_compiler_json_span(compiler, span, &start, &end)) return false;
    if (strstr(warning, "\"type\":\"InvariantBooleanExpression\"")) {
        *position = strstr(warning, "the expression requires ") ?
                    start : SIZE_MAX;
        return true;
    }
    if (strstr(warning, "\"type\":\"AmbiguousExpression\"")) {
        *position = end;
        return true;
    }
    if (strstr(warning, "\"type\":\"PotentiallyUnsatisfiableExpression\"")) {
        /* Raised before the anchor's expression: its second label. */
        span = strstr(span + 1, "\"span\":{\"start\":");
        return yx_compiler_json_span(compiler, span, position, NULL);
    }
    if (strstr(warning, "\"type\":\"TooManyIterations\"") ||
        strstr(warning, "\"type\":\"UnsatisfiableExpression\"") ||
        strstr(warning, "\"type\":\"BooleanIntegerComparison\"") ||
        strstr(warning, "\"type\":\"NonBooleanAsBoolean\"") ||
        strstr(warning, "\"type\":\"DeprecatedField\"")) {
        *position = start;
        return true;
    }
    return false;
}

/* YARA-X raises ambiguous_expr and the potentially unsatisfiable
 * expression while it compiles their `of` expression (ast2ir.rs
 * of_expr_from_ast). Moves each warning from `first` on before the first
 * warning of this condition that is raised later in the source. */
typedef struct {
    size_t key, arrival;
    char *warning;
} yx_warning_order_record;

static int yx_warning_order_compare(const void *a, const void *b)
{
    const yx_warning_order_record *left = a, *right = b;
    if (left->key != right->key) return left->key < right->key ? -1 : 1;
    return left->arrival < right->arrival ? -1 : left->arrival > right->arrival;
}

static void yx_order_of_warnings(YRX_COMPILER *compiler,
                                 size_t first_condition_warning, size_t first)
{
    /* Moving each warning from `first` on before the first earlier warning
     * raised after its position x puts it behind every warning whose
     * running maximum of positions is at most x. So each warning gets a
     * key, x when it moves and the running maximum when it stays, and the
     * order is the stable sort by that key. The points are those of this
     * condition (the parser resets them for each one). */
    size_t count = compiler->warning_count, n, begin, maximum = 0;
    yx_warning_order_record *records;
    yx_warning_point_record *sorted = NULL;
    char **warnings;
    bool any = false;
    if (first >= count || first_condition_warning > first) return;
    n = count - first_condition_warning;
    begin = first - first_condition_warning;
    warnings = compiler->warnings + first_condition_warning;
    records = (yx_warning_order_record *)malloc(n * sizeof(*records));
    if (compiler->warning_point_count)
        sorted = (yx_warning_point_record *)malloc(
            compiler->warning_point_count * sizeof(*sorted));
    if (!records || (compiler->warning_point_count && !sorted)) {
        /* Out of memory: the same order, slowly. */
        free(records); free(sorted);
        for (size_t i = first; i < compiler->warning_count; ++i) {
            size_t position;
            if (!yx_warning_raise_position(compiler, compiler->warnings[i],
                                           NULL, &position)) continue;
            for (size_t j = first_condition_warning; j < i; ++j) {
                size_t other;
                if (yx_warning_raise_position(compiler, compiler->warnings[j],
                                              NULL, &other) && other > position) {
                    char *saved = compiler->warnings[i];
                    memmove(compiler->warnings + j + 1, compiler->warnings + j,
                            (i - j) * sizeof(*compiler->warnings));
                    compiler->warnings[j] = saved;
                    break;
                }
            }
        }
        return;
    }
    for (size_t i = 0; i < compiler->warning_point_count; ++i) {
        sorted[i].key = (uintptr_t)compiler->warning_point_keys[i];
        sorted[i].index = i;
    }
    if (sorted)
        qsort(sorted, compiler->warning_point_count, sizeof(*sorted),
              yx_warning_point_compare);
    for (size_t i = 0; i < n; ++i) {
        size_t position = 0;
        bool known = yx_warning_raise_position(compiler, warnings[i], sorted,
                                               &position);
        if (known && i >= begin && any && maximum > position) {
            records[i].key = position;
        } else {
            if (known && (!any || position > maximum)) maximum = position;
            if (known) any = true;
            records[i].key = any ? maximum : 0;
        }
        records[i].arrival = i;
        records[i].warning = warnings[i];
    }
    qsort(records, n, sizeof(*records), yx_warning_order_compare);
    for (size_t i = 0; i < n; ++i) warnings[i] = records[i].warning;
    free(records);
    free(sorted);
}

typedef struct {
    yx_parser *parser;
    const char *start;
    size_t error_end;
} yx_anchored_quantifier_context;

static bool yx_condition_anchored_quantifier_warning(size_t quantifier_start,
                                                     size_t quantifier_end,
                                                     size_t anchor_start,
                                                     size_t anchor_end,
                                                     void *user)
{
    yx_anchored_quantifier_context *context = user;
    yx_parser *p = context->parser;
    size_t offset = (size_t)(context->start - p->begin);
    if (anchor_end > (size_t)(p->at - context->start)) return true;
    /* Raised once the items are compiled and before the anchor is: an error
     * that ends before the anchor leaves it out. */
    if (context->error_end != SIZE_MAX &&
        offset + anchor_start >= context->error_end) return true;
    return yx_compiler_unsatisfiable_pattern_at_warning(
        p->compiler, p->begin, p->origin, offset + quantifier_start,
        offset + quantifier_end, offset + anchor_start,
        offset + anchor_end) != 0;
}

/* `<quantifier> of <pattern set> at <expr>` from the parsed condition
 * (condition.c, yx_condition_visit_anchored_quantifiers). `error_end` is
 * where the condition's error ends, SIZE_MAX when it has none. */
static bool yx_condition_warn_unsatisfiable_at(yx_parser *p,
                                                const YRX_RULE *rule,
                                                const char *start,
                                                size_t error_end)
{
    yx_anchored_quantifier_context context = {p, start, error_end};
    const char **names = NULL;
    bool ok;
    if (rule->pattern_count) {
        names = (const char **)malloc(rule->pattern_count * sizeof(*names));
        if (!names) return false;
        for (size_t i = 0; i < rule->pattern_count; ++i)
            names[i] = rule->patterns[i].identifier;
    }
    ok = yx_condition_visit_anchored_quantifiers(
        rule->condition, names, rule->pattern_count,
        yx_condition_anchored_quantifier_warning, &context);
    free((void *)names);
    return ok;
}

typedef struct {
    yx_parser *parser;
    const char *start;
    size_t error_start;
} yx_zero_quantifier_context;

static bool yx_condition_zero_quantifier_warning(size_t quantifier_start,
                                                 size_t quantifier_end,
                                                 size_t end, size_t raised,
                                                 void *user)
{
    yx_zero_quantifier_context *context = user;
    yx_parser *p = context->parser;
    size_t offset = (size_t)(context->start - p->begin);
    size_t count = p->compiler->warning_count;
    if (end > (size_t)(p->at - context->start)) return true;
    /* Raised once the items are compiled and before the anchor is: an
     * error in the anchor comes after it. */
    if (context->error_start != SIZE_MAX &&
        offset + raised > context->error_start) return true;
    return yx_compiler_ambiguous_expr_warning(
        p->compiler, p->begin, p->origin, offset + quantifier_start,
        offset + quantifier_end, offset + end) != 0 &&
        yx_compiler_warning_raised_at(p->compiler, count, offset + raised);
}

static bool yx_condition_excess_quantifier_warning(size_t start, size_t end,
                                                   size_t raised,
                                                   int64_t required,
                                                   size_t available,
                                                   void *user)
{
    yx_zero_quantifier_context *context = user;
    yx_parser *p = context->parser;
    size_t offset = (size_t)(context->start - p->begin);
    if (end > (size_t)(p->at - context->start)) return true;
    if (context->error_start != SIZE_MAX &&
        offset + raised > context->error_start) return true;
    return yx_compiler_excess_quantifier_warning(
        p->compiler, p->begin, p->origin, offset + start, offset + end,
        offset + raised, required, available) != 0;
}

/* `0 of ...` from the parsed condition: the span runs from the quantifier
 * (inside any parentheses) to the last item or the anchor, as YARA-X's
 * `of` expression span. */
static bool yx_condition_warn_ambiguous_zero_of(yx_parser *p,
                                                 const YRX_RULE *rule,
                                                 const char *start,
                                                 size_t error_start)
{
    yx_zero_quantifier_context context = {p, start, error_start};
    const char **names = NULL;
    bool ok;
    /* With `<n> of` asking for more items than there are (ast2ir.rs
     * of_expr_from_ast, for_of_expr_from_ast), in one walk: an inner
     * expression's warnings come before those of the one around it. */
    if (rule->pattern_count) {
        names = (const char **)malloc(rule->pattern_count * sizeof(*names));
        if (!names) return false;
        for (size_t i = 0; i < rule->pattern_count; ++i)
            names[i] = rule->patterns[i].identifier;
    }
    ok = yx_condition_visit_of_quantifiers(
        rule->condition, names, rule->pattern_count,
        yx_condition_zero_quantifier_warning,
        yx_condition_excess_quantifier_warning, &context);
    free((void *)names);
    return ok;
}

typedef struct {
    yx_parser *parser;
    const char *start;
} yx_pattern_set_context;

static bool yx_condition_pattern_set_warning(const char *pattern,
    size_t set_start, size_t set_end,
    size_t first_start, size_t first_end, bool first_wildcard,
    size_t second_start, size_t second_end, bool second_wildcard, void *user)
{
    yx_pattern_set_context *context = user;
    yx_parser *p = context->parser;
    const char *base = context->start;
    size_t offset = (size_t)(context->start - p->begin);
    size_t set_length = set_end - set_start;
    size_t first_length = first_end - first_start;
    size_t second_length = second_end - second_start;
    /* Names exclude a wildcard's `*` (and any space before it); spans are
     * relative to the condition. */
    while (set_length && (base[set_start + set_length - 1] == '*' ||
                          isspace((unsigned char)base[set_start + set_length - 1])))
        --set_length;
    while (first_wildcard && first_length &&
           (base[first_start + first_length - 1] == '*' ||
            isspace((unsigned char)base[first_start + first_length - 1])))
        --first_length;
    while (second_wildcard && second_length &&
           (base[second_start + second_length - 1] == '*' ||
            isspace((unsigned char)base[second_start + second_length - 1])))
        --second_length;
    return yx_compiler_unintended_pattern_in_set_warning(
        p->compiler, p->begin, p->origin, pattern,
        base + set_start, set_length,
        base + first_start, first_length,
        first_wildcard, offset + first_start, offset + first_end,
        base + second_start, second_length,
        second_wildcard, offset + second_start, offset + second_end) != 0;
}

/* unintended_pattern_in_set from the parsed condition's conjunctive
 * branches (condition.c, yx_condition_visit_pattern_sets). */
static bool yx_condition_warn_overlapping_pattern_sets(yx_parser *p,
                                                        const YRX_RULE *rule,
                                                        const char *start)
{
    yx_pattern_set_context context = {p, start};
    const char **names = NULL;
    bool ok;
    /* A warning that will not be shown needs no analysis. */
    if (yx_compiler_warning_skipped(p->compiler, "unintended_pattern_in_set")) return true;
    if (rule->pattern_count) {
        names = (const char **)malloc(rule->pattern_count * sizeof(*names));
        if (!names) return false;
        for (size_t i = 0; i < rule->pattern_count; ++i)
            names[i] = rule->patterns[i].identifier;
    }
    ok = yx_condition_visit_pattern_sets(rule->condition, names,
                                         rule->pattern_count,
                                         yx_condition_pattern_set_warning,
                                         &context);
    free((void *)names);
    return ok;
}

/* Boolean literals are complete expressions in a YARA-X condition. Its
 * grammar rejects a following comparison operator, and rejects a boolean
 * literal as the right operand of a comparison, before type checking. */
static bool yx_boolean_comparison_syntax_error(yx_parser *p,
                                               const char *start,
                                               const char *detail,
                                               bool condition_compiled)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool diagnosed = false;
    if (!condition_compiled &&
        strcmp(detail, "mismatching operand types") != 0)
        return false;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    for (size_t i = 1; i + 1 < count; ++i) {
        bool left_boolean, right_boolean;
        if (!yx_diag_token_is(&tokens[i], "==") &&
            !yx_diag_token_is(&tokens[i], "!=") &&
            !yx_diag_token_is(&tokens[i], "<") &&
            !yx_diag_token_is(&tokens[i], "<=") &&
            !yx_diag_token_is(&tokens[i], ">") &&
            !yx_diag_token_is(&tokens[i], ">=")) continue;
        left_boolean = yx_diag_token_is(&tokens[i - 1], "true") ||
                       yx_diag_token_is(&tokens[i - 1], "false");
        right_boolean = yx_diag_token_is(&tokens[i + 1], "true") ||
                        yx_diag_token_is(&tokens[i + 1], "false");
        if (left_boolean) {
            yx_syntax_expected(p, tokens[i].start, tokens[i].end,
                               "operator or `}`");
            diagnosed = true;
            break;
        }
        if (right_boolean) {
            yx_syntax_expected(p, tokens[i + 1].start, tokens[i + 1].end,
                               "expression or identifier");
            diagnosed = true;
            break;
        }
    }
    free(tokens);
    return diagnosed;
}

static bool yx_known_function_arguments_error(yx_parser *p,
                                              const char *start,
                                              const char *detail)
{
    /* The accepted argument combinations YARA-X lists for each function,
     * in its order. */
    static const struct { const char *path; const char *combinations; } functions[] = {
        {"console.hex", "(integer)\n(string, integer)"},
        {"console.log", "(boolean)\n(float)\n(integer)\n(string, boolean)\n(string, float)\n(string, integer)\n(string, integer, integer)\n(string, string)\n(integer, integer)\n(string)"},
        {"crx.permhash", "()"},
        {"cuckoo.filesystem.file_access", "(regexp)"},
        {"cuckoo.network.dns_lookup", "(regexp)"},
        {"cuckoo.network.host", "(regexp)"},
        {"cuckoo.network.http_get", "(regexp)"},
        {"cuckoo.network.http_post", "(regexp)"},
        {"cuckoo.network.http_request", "(regexp)"},
        {"cuckoo.network.http_user_agent", "(regexp)"},
        {"cuckoo.network.tcp", "(regexp, integer)"},
        {"cuckoo.network.udp", "(regexp, integer)"},
        {"cuckoo.registry.key_access", "(regexp)"},
        {"cuckoo.sync.mutex", "(regexp)"},
        {"dex.checksum", "()"},
        {"dex.contains_class", "(string)"},
        {"dex.contains_method", "(string)"},
        {"dex.contains_string", "(string)"},
        {"dex.signature", "()"},
        {"elf.import_md5", "()"},
        {"elf.telfhash", "()"},
        {"float32", "(integer)"},
        {"float32be", "(integer)"},
        {"float64", "(integer)"},
        {"float64be", "(integer)"},
        {"hash.checksum32", "(integer, integer)\n(string)"},
        {"hash.crc32", "(integer, integer)\n(string)"},
        {"hash.md5", "(integer, integer)\n(string)"},
        {"hash.sha1", "(integer, integer)\n(string)"},
        {"hash.sha256", "(integer, integer)\n(string)"},
        {"int16", "(integer)"},
        {"int16be", "(integer)"},
        {"int32", "(integer)"},
        {"int32be", "(integer)"},
        {"int64", "(integer)"},
        {"int64be", "(integer)"},
        {"int8", "(integer)"},
        {"int8be", "(integer)"},
        {"macho.dylib_hash", "()"},
        {"macho.entitlement_hash", "()"},
        {"macho.entry_point_for_arch", "(integer, integer)\n(integer)"},
        {"macho.export_hash", "()"},
        {"macho.file_index_for_arch", "(integer, integer)\n(integer)"},
        {"macho.has_dylib", "(string)"},
        {"macho.has_entitlement", "(string)"},
        {"macho.has_export", "(string)"},
        {"macho.has_import", "(string)"},
        {"macho.has_rpath", "(string)"},
        {"macho.import_hash", "()"},
        {"macho.symhash", "()"},
        {"math.abs", "(integer)"},
        {"math.count", "(integer, integer, integer)\n(integer)"},
        {"math.deviation", "(integer, integer, float)\n(string, float)"},
        {"math.entropy", "(integer, integer)\n(string)"},
        {"math.in_range", "(float, float, float)\n(integer, integer, integer)"},
        {"math.max", "(integer, integer)"},
        {"math.mean", "(integer, integer)\n(string)"},
        {"math.min", "(integer, integer)"},
        {"math.mode", "()\n(integer, integer)"},
        {"math.monte_carlo_pi", "(integer, integer)\n(string)"},
        {"math.percentage", "(integer, integer, integer)\n(integer)"},
        {"math.serial_correlation", "(integer, integer)\n(string)"},
        {"math.to_number", "(boolean)"},
        {"math.to_string", "(integer, integer)\n(integer)"},
        {"pe.calculate_checksum", "()"},
        {"pe.delayed_import_rva", "(string, string)\n(string, integer)"},
        {"pe.exports", "(regexp)\n(string)\n(integer)"},
        {"pe.exports_index", "(regexp)\n(string)\n(integer)"},
        {"pe.imphash", "()"},
        {"pe.import_rva", "(string, string)\n(string, integer)"},
        {"pe.imports", "(regexp, regexp)\n(string, string)\n(string, integer)\n(string)\n(integer, regexp, regexp)\n(integer, string, string)\n(integer, string, integer)\n(integer, string)"},
        {"pe.is_32bit", "()"},
        {"pe.is_64bit", "()"},
        {"pe.is_dll", "()"},
        {"pe.language", "(integer)"},
        {"pe.locale", "(integer)"},
        {"pe.offset_to_rva", "(integer)"},
        {"pe.rich_signature.toolid", "(integer, integer)\n(integer)"},
        {"pe.rich_signature.version", "(integer, integer)\n(integer)"},
        {"pe.rva_to_offset", "(integer)"},
        {"pe.section_index", "(string)\n(integer)"},
        {"string.length", "(string)"},
        {"string.to_int", "(string, integer)\n(string)"},
        {"time.now", "()"},
        {"uint16", "(integer)"},
        {"uint16be", "(integer)"},
        {"uint32", "(integer)"},
        {"uint32be", "(integer)"},
        {"uint64", "(integer)"},
        {"uint64be", "(integer)"},
        {"uint8", "(integer)"},
        {"uint8be", "(integer)"},
        /* vt.net.EnrichedIP / EnrichedDomain methods (vt/mod.rs). */
        {"vt.metadata.itw.domain.permutation_of", "(string)\n(string, integer)"},
        {"vt.metadata.itw.ip.in_range", "(string)"},
        {"vt.net.domain.permutation_of", "(string)\n(string, integer)"},
        {"vt.net.ip.in_range", "(string)"}
    };
    static const char prefix[] = "wrong arguments for '";
    const char *path = NULL, *combinations = NULL, *name, *name_end;
    char note[512];
    size_t call_offset = 0;
    /* The call names the function through a `with` declaration: the name
     * at the call's offset is the alias. */
    bool alias = false;
    if (strncmp(detail, prefix, sizeof(prefix) - 1) != 0) return false;
    name = detail + sizeof(prefix) - 1;
    name_end = strchr(name, '\'');
    if (!name_end) return false;
    /* The failing call's offset in the condition, when known. */
    if (name_end[1] == ' ' && name_end[2] == '@') {
        char *offset_end = NULL;
        call_offset = (size_t)strtoull(name_end + 3, &offset_end, 10);
        alias = offset_end && strcmp(offset_end, " alias") == 0;
    }
    else if (name_end[1]) return false;
    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); ++i) {
        if (strlen(functions[i].path) == (size_t)(name_end - name) &&
            memcmp(functions[i].path, name, (size_t)(name_end - name)) == 0) {
            path = functions[i].path;
            combinations = functions[i].combinations;
            break;
        }
    }
    if (!path) return false;
    snprintf(note, sizeof(note), "accepted argument combinations:\n\n%s", combinations);
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool diagnosed = false;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count)) return false;
    for (size_t i = 0; i < count; ++i) {
        const char *part = path;
        size_t open = i;
        if ((size_t)(tokens[i].start - start) < call_offset) continue;
        if (alias) {
            if ((size_t)(tokens[i].start - start) != call_offset ||
                tokens[i].kind != YX_DIAG_WORD) break;
            part = "";
            open = i + 1;
        }
        while (*part && open < count) {
            size_t length = *part == '.' ? 1 : strcspn(part, ".");
            if ((size_t)(tokens[open].end - tokens[open].start) != length ||
                memcmp(tokens[open].start, part, length) != 0) break;
            part += length;
            ++open;
        }
        if (*part || open >= count || !yx_diag_token_is(&tokens[open], "(")) continue;
        size_t depth = 1;
        for (size_t j = open + 1; j < count; ++j) {
            if (yx_diag_token_is(&tokens[j], "(")) ++depth;
            else if (yx_diag_token_is(&tokens[j], ")") && --depth == 0) {
                diagnosed = yx_compiler_wrong_arguments_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(tokens[open].start - p->begin),
                    (size_t)(tokens[j].end - p->begin), note) != 0;
                if (diagnosed) p->recoverable_unknown_identifier = true;
                break;
            }
        }
        break;
    }
    free(tokens);
    return diagnosed;
}

static bool yx_unknown_function_condition_error(yx_parser *p,
                                                const YRX_RULE *rule,
                                                const char *start,
                                                const char *detail)
{
    static const char prefix[] = "unsupported function '";
    const char *quoted = strstr(detail, prefix);
    const char *end;
    /* func_call_from_ast: a called symbol that is no function is E002 with
     * the symbol's type: a module is a struct, a rule a boolean. */
    const char *symbol_type = NULL;
    const YRX_RULES *rules = p->compiler->rules;
    yx_diag_token *tokens = NULL;
    size_t count = 0, length;
    bool diagnosed = false;
    if (!quoted || strncmp(detail, "at byte ", 8) != 0) return false;
    quoted += sizeof(prefix) - 1;
    end = strchr(quoted, '\'');
    if (!end || end[1] || end == quoted) return false;
    length = (size_t)(end - quoted);
    if (memchr(quoted, '.', length)) return false;
    /* The parser stopped at the `(` of the call. */
    size_t open_offset = (size_t)strtoull(detail + 8, NULL, 10);
    for (size_t i = 0; !symbol_type && i < rules->rule_count; ++i)
        if (strlen(rules->rules[i].identifier) == length &&
            memcmp(rules->rules[i].identifier, quoted, length) == 0 &&
            rules->rules[i].namespace_index == rule->namespace_index &&
            &rules->rules[i] != rule)
            symbol_type = "boolean";
    for (size_t i = 0; !symbol_type && i < rules->import_count; ++i)
        if (strlen(rules->imports[i]) == length &&
            memcmp(rules->imports[i], quoted, length) == 0) {
            if (length == 2 && memcmp(quoted, "vt", 2) == 0) return false;
            symbol_type = "struct";
        }
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    {
        /* The call the parser stopped at, when the name is called earlier
         * too (where a `with` declares it). */
        bool located = false;
        for (size_t i = 0; i + 1 < count && !located; ++i)
            located = tokens[i].kind == YX_DIAG_WORD &&
                (size_t)(tokens[i].end - tokens[i].start) == length &&
                memcmp(tokens[i].start, quoted, length) == 0 &&
                yx_diag_token_is(&tokens[i + 1], "(") &&
                (size_t)(tokens[i + 1].start - start) == open_offset;
        if (!located) open_offset = SIZE_MAX;
    }
    for (size_t i = 0; i + 1 < count; ++i) {
        if (tokens[i].kind != YX_DIAG_WORD ||
            (size_t)(tokens[i].end - tokens[i].start) != length ||
            memcmp(tokens[i].start, quoted, length) != 0 ||
            !yx_diag_token_is(&tokens[i + 1], "(")) continue;
        if (open_offset != SIZE_MAX &&
            (size_t)(tokens[i + 1].start - start) != open_offset) continue;
        char name[YX_CONDITION_NAME_SIZE];
        if (length >= sizeof(name)) break;
        memcpy(name, quoted, length);
        name[length] = '\0';
        diagnosed = symbol_type ?
            yx_compiler_wrong_type_error(
                p->compiler, p->begin, p->origin,
                (size_t)(tokens[i].start - p->begin),
                (size_t)(tokens[i].end - p->begin),
                "`function`", symbol_type) != 0 :
            yx_compiler_unknown_identifier_error(
                p->compiler, name, p->begin, p->origin,
                (size_t)(tokens[i].start - p->begin),
                (size_t)(tokens[i].end - p->begin)) != 0;
        if (diagnosed) p->recoverable_unknown_identifier = true;
        break;
    }
    free(tokens);
    return diagnosed;
}

static bool yx_vt_module_value_condition_error(yx_parser *p,
                                               const char *start,
                                               const char *detail)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool bare;
    if (strcmp(detail, "vt module used as value") != 0 ||
        !yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    bare = count == 1 && yx_diag_token_is(&tokens[0], "vt");
    for (size_t i = 0; i < count; ++i) {
        bool ok;
        if (!yx_diag_token_is(&tokens[i], "vt")) continue;
        ok = yx_compiler_wrong_type_error(
            p->compiler, p->begin, p->origin,
            (size_t)(tokens[i].start - p->begin),
            (size_t)(tokens[i].end - p->begin),
            bare ? "`bool`" : "`boolean`, `float`, `integer`, or `string`",
            bare ? "a struct" : "struct") != 0;
        free(tokens);
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    free(tokens);
    return false;
}

/* A `with` name that stands for a function, read without a call (E002):
 * the function value's diagnostics, at the name. */
static bool yx_function_alias_value_condition_error(yx_parser *p,
                                                    const char *start,
                                                    const char *detail)
{
    size_t value_start, value_end;
    char path[YX_CONDITION_NAME_SIZE];
    bool help = false;
    int result;
    if (sscanf(detail, "function alias value span:%zu:%zu:%127s",
               &value_start, &value_end, path) != 3 ||
        value_start >= value_end || value_end > (size_t)(p->at - start))
        return false;
    /* `valid_on`, the method of a signature, returns a bool. */
    if (strcmp(path, "valid_on") == 0) help = true;
    else (void)yx_module_function_path(path, strlen(path), &help);
    result = yx_function_value_error_at(p, start, start + value_start,
                                        value_end - value_start, help);
    if (result < 0) return false;
    if (!result &&
        !yx_compiler_wrong_type_error(
            p->compiler, p->begin, p->origin,
            (size_t)(start - p->begin) + value_start,
            (size_t)(start - p->begin) + value_end,
            "`boolean`, `float`, `integer`, or `string`", "function"))
        return false;
    p->recoverable_unknown_identifier = true;
    return true;
}

static bool yx_wrong_type_condition_error(yx_parser *p,
                                          const char *start,
                                          const char *detail)
{
    size_t typed_start, typed_end;
    char expected_type[96], actual_type[32];
    /* The parser reports member reads from call results and lookups with
     * its byte position in front. */
    const char *typed = strstr(detail, "wrong type span:");
    if (typed &&
        sscanf(typed, "wrong type span:%zu:%zu:%95[^:]:%31[^:]",
               &typed_start, &typed_end, expected_type, actual_type) == 4 &&
        typed_start < typed_end && typed_end <= (size_t)(p->at - start)) {
        bool ok = yx_compiler_wrong_type_error(p->compiler, p->begin,
            p->origin, (size_t)(start - p->begin) + typed_start,
            (size_t)(start - p->begin) + typed_end,
            expected_type, actual_type) != 0;
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    size_t collection_start, collection_end;
    char collection_type[16];
    if (sscanf(detail, "collection operand span %zu..%zu %15s",
               &collection_start, &collection_end, collection_type) == 3 &&
        collection_start < collection_end &&
        collection_end <= (size_t)(p->at - start) &&
        (strcmp(collection_type, "struct") == 0 ||
         strcmp(collection_type, "array") == 0)) {
        bool ok = yx_compiler_wrong_type_error(p->compiler, p->begin, p->origin,
            (size_t)(start - p->begin) + collection_start,
            (size_t)(start - p->begin) + collection_end,
            "`boolean`, `float`, `integer`, or `string`", collection_type);
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    yx_diag_token *tokens = NULL;
    size_t count = 0, chosen = SIZE_MAX;
    const char *span_start, *span_end;
    const char *expected = NULL, *actual = NULL;
    bool unbound_read = strncmp(detail, "unbound read function '", 23) == 0;
    bool shadowed_read = strncmp(detail,
                                "read function shadowed by global '",
                                34) == 0;
    bool recognized = strcmp(detail, "wrong arithmetic type") == 0 ||
        strcmp(detail, "wrong integer operand type") == 0 ||
        strcmp(detail, "wrong string operand type") == 0 ||
        strcmp(detail, "wrong regexp operand type") == 0 ||
        strcmp(detail, "regular expression is not valid here") == 0 ||
        strstr(detail, "expected regular expression after 'matches'") != NULL ||
        strcmp(detail, "wrong pattern offset type") == 0 ||
        strcmp(detail, "pattern match index has wrong type") == 0 ||
        strcmp(detail, "wrong quantifier type") == 0 ||
        unbound_read || shadowed_read;
    if (!recognized || !yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    if (unbound_read || shadowed_read) {
        const char *name = strchr(detail, '\'');
        const char *end = name ? strchr(name + 1, '\'') : NULL;
        size_t length = name && end ? (size_t)(end - name - 1) : 0;
        if (!length) { free(tokens); return false; }
        ++name;
        for (size_t j = 0; j < count; ++j)
            if (tokens[j].kind == YX_DIAG_WORD &&
                (size_t)(tokens[j].end - tokens[j].start) == length &&
                memcmp(tokens[j].start, name, length) == 0) {
                chosen = j;
                break;
            }
        if (chosen == SIZE_MAX) { free(tokens); return false; }
        if (shadowed_read) {
            expected = "`function`";
            actual = "integer";
            for (size_t j = 0; j < p->compiler->rules->global_count; ++j) {
                const yx_global *global = &p->compiler->rules->globals[j];
                if (strlen(global->name) != length ||
                    memcmp(global->name, name, length) != 0) continue;
                switch (global->type) {
                case YX_GLOBAL_BOOL: actual = "boolean"; break;
                case YX_GLOBAL_INT: actual = "integer"; break;
                case YX_GLOBAL_FLOAT: actual = "float"; break;
                case YX_GLOBAL_STR: actual = "string"; break;
                case YX_GLOBAL_ARRAY: actual = "array"; break;
                case YX_GLOBAL_STRUCT: actual = "struct"; break;
                }
                break;
            }
        } else {
            expected = "`bool`";
            actual = "a function";
            for (size_t j = 0; j < count; ++j) {
                if (j == chosen || yx_diag_token_is(&tokens[j], "(") ||
                    yx_diag_token_is(&tokens[j], ")")) continue;
                expected = "`boolean`, `float`, `integer`, or `string`";
                actual = "function";
                if (yx_diag_token_is(&tokens[j], "contains") ||
                    yx_diag_token_is(&tokens[j], "icontains") ||
                    yx_diag_token_is(&tokens[j], "startswith") ||
                    yx_diag_token_is(&tokens[j], "istartswith") ||
                    yx_diag_token_is(&tokens[j], "endswith") ||
                    yx_diag_token_is(&tokens[j], "iendswith") ||
                    yx_diag_token_is(&tokens[j], "matches"))
                    expected = "`string`";
                else if (yx_diag_token_is(&tokens[j], "!") ||
                         yx_diag_token_is(&tokens[j], "<") ||
                         yx_diag_token_is(&tokens[j], ">") ||
                         yx_diag_token_is(&tokens[j], "<=") ||
                         yx_diag_token_is(&tokens[j], ">="))
                    expected = "`float`, `integer`, or `string`";
                else if (yx_diag_token_is(&tokens[j], "+") ||
                         yx_diag_token_is(&tokens[j], "-") ||
                         yx_diag_token_is(&tokens[j], "*") ||
                         yx_diag_token_is(&tokens[j], "/"))
                    expected = "`float` or `integer`";
                if (strcmp(expected,
                           "`boolean`, `float`, `integer`, or `string`") != 0)
                    break;
            }
        }
        bool ok = yx_compiler_wrong_type_error(
            p->compiler, p->begin, p->origin,
            (size_t)(tokens[chosen].start - p->begin),
            (size_t)(tokens[chosen].end - p->begin), expected, actual) != 0;
        free(tokens);
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    if (strcmp(detail, "regular expression is not valid here") == 0) {
        const char *cursor = start;
        const char *end;
        bool in_class = false;
        while (cursor < p->at &&
               (isspace((unsigned char)*cursor) || *cursor == '(')) ++cursor;
        if (cursor >= p->at || *cursor != '/') { free(tokens); return false; }
        end = cursor + 1;
        while (end < p->at) {
            if (*end == '\\' && end + 1 < p->at) { end += 2; continue; }
            if (*end == '[') in_class = true;
            else if (*end == ']') in_class = false;
            else if (*end == '/' && !in_class) break;
            ++end;
        }
        if (end >= p->at) { free(tokens); return false; }
        ++end;
        for (unsigned flags = 0;
             flags < 2 && (*end == 'i' || *end == 's'); ++flags) ++end;
        bool ok = yx_compiler_wrong_type_error(
            p->compiler, p->begin, p->origin,
            (size_t)(cursor - p->begin), (size_t)(end - p->begin),
            "`bool`", "a regexp") != 0;
        free(tokens);
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    if (strcmp(detail, "wrong arithmetic type") == 0) {
        expected = "`float` or `integer`"; actual = "string";
        for (size_t i = 0; i < count; ++i)
            if (tokens[i].kind == YX_DIAG_STRING) { chosen = i; break; }
        if (chosen == SIZE_MAX) {
            for (size_t i = 1; i < count; ++i) {
                const char *end;
                bool in_class = false;
                bool ok;
                if (tokens[i].kind != YX_DIAG_SYMBOL ||
                    *tokens[i].start != '/' ||
                    (!yx_diag_token_is(&tokens[i - 1], "+") &&
                     !yx_diag_token_is(&tokens[i - 1], "-") &&
                     !yx_diag_token_is(&tokens[i - 1], "*"))) continue;
                end = tokens[i].start + 1;
                while (end < p->at && *end != '\n') {
                    if (*end == '\\' && end + 1 < p->at) {
                        end += 2;
                        continue;
                    }
                    if (*end == '[') in_class = true;
                    else if (*end == ']') in_class = false;
                    else if (*end == '/' && !in_class) break;
                    ++end;
                }
                if (end >= p->at || *end != '/') continue;
                ++end;
                for (unsigned flags = 0; flags < 2 && end < p->at &&
                     (*end == 'i' || *end == 's'); ++flags) ++end;
                ok = yx_compiler_wrong_type_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(tokens[i].start - p->begin),
                    (size_t)(end - p->begin), expected, "regexp") != 0;
                free(tokens);
                if (ok) p->recoverable_unknown_identifier = true;
                return ok;
            }
        }
    } else if (strcmp(detail, "wrong integer operand type") == 0) {
        expected = "`integer`"; actual = "float";
        for (size_t i = 0; i < count; ++i)
            if (tokens[i].kind == YX_DIAG_FLOAT) { chosen = i; break; }
    } else if (strcmp(detail, "wrong string operand type") == 0) {
        expected = "`string`"; actual = "integer";
        for (size_t i = 0; i < count; ++i)
            if (tokens[i].kind == YX_DIAG_INTEGER) { chosen = i; break; }
    } else if (strcmp(detail, "wrong regexp operand type") == 0) {
        expected = "`string`";
        for (size_t i = 0; i < count; ++i)
            if (yx_diag_token_is(&tokens[i], "matches") && i > 0 &&
                tokens[i - 1].kind == YX_DIAG_INTEGER) {
                chosen = i - 1; actual = "integer"; break;
            }
    } else if (strstr(detail, "expected regular expression after 'matches'")) {
        expected = "`regexp`"; actual = "string";
        for (size_t i = 0; i + 1 < count; ++i)
            if (yx_diag_token_is(&tokens[i], "matches") &&
                tokens[i + 1].kind == YX_DIAG_STRING) {
                chosen = i + 1; break;
            }
    } else if (strcmp(detail, "wrong pattern offset type") == 0) {
        expected = "`integer`";
        for (size_t i = 0; i < count; ++i) {
            if (!yx_diag_token_is(&tokens[i], "at") &&
                !yx_diag_token_is(&tokens[i], "in")) continue;
            for (size_t j = i + 1; j < count; ++j) {
                if (tokens[j].kind == YX_DIAG_STRING ||
                    tokens[j].kind == YX_DIAG_FLOAT) {
                    chosen = j;
                    actual = tokens[j].kind == YX_DIAG_STRING ? "string" : "float";
                    break;
                }
                if (yx_diag_token_is(&tokens[j], "and") ||
                    yx_diag_token_is(&tokens[j], "or")) break;
            }
            if (chosen != SIZE_MAX) break;
        }
    } else if (strcmp(detail, "pattern match index has wrong type") == 0) {
        expected = "`integer`"; actual = "string";
        for (size_t i = 0; i + 2 < count; ++i)
            if (yx_diag_token_is(&tokens[i], "[") &&
                tokens[i + 1].kind == YX_DIAG_STRING &&
                yx_diag_token_is(&tokens[i + 2], "]")) {
                chosen = i + 1; break;
            }
    } else if (strcmp(detail, "wrong quantifier type") == 0) {
        expected = "`integer`";
        for (size_t i = 0; i < count; ++i)
            if (tokens[i].kind == YX_DIAG_STRING ||
                tokens[i].kind == YX_DIAG_FLOAT) {
                chosen = i;
                actual = tokens[i].kind == YX_DIAG_STRING ? "string" : "float";
                break;
            }
    }
    if (chosen == SIZE_MAX || !expected || !actual) { free(tokens); return false; }
    span_start = tokens[chosen].start;
    span_end = tokens[chosen].end;
    if (strcmp(detail, "wrong integer operand type") == 0) {
        for (size_t i = 0; i < chosen; ++i) {
            if (!yx_diag_token_is(&tokens[i], "<<") &&
                !yx_diag_token_is(&tokens[i], ">>")) continue;
            if (i + 1 <= chosen) {
                span_start = tokens[i + 1].start;
                for (size_t j = chosen + 1; j < count; ++j) {
                    if (yx_diag_token_is(&tokens[j], "==") ||
                        yx_diag_token_is(&tokens[j], "and") ||
                        yx_diag_token_is(&tokens[j], "or") ||
                        yx_diag_token_is(&tokens[j], ")")) break;
                    span_end = tokens[j].end;
                }
            }
            break;
        }
    }
    bool ok = yx_compiler_wrong_type_error(
        p->compiler, p->begin, p->origin,
        (size_t)(span_start - p->begin), (size_t)(span_end - p->begin),
        expected, actual) != 0;
    free(tokens);
    if (ok) p->recoverable_unknown_identifier = true;
    return ok;
}

static const char *yx_diag_literal_type(const yx_diag_token *token)
{
    if (token->kind == YX_DIAG_INTEGER) return "integer";
    if (token->kind == YX_DIAG_FLOAT) return "float";
    if (token->kind == YX_DIAG_STRING) return "string";
    return NULL;
}

static bool yx_diag_integer_read_name(const yx_diag_token *token)
{
    static const char *const names[] = {
        "int8", "uint8", "int16", "uint16", "int32", "uint32",
        "int8be", "uint8be", "int16be", "uint16be", "int32be",
        "uint32be", "int64", "int64be", "uint64", "uint64be"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (yx_diag_token_is(token, names[i])) return true;
    return false;
}

static const char *yx_diag_loop_variable_type(const yx_diag_token *tokens,
                                              size_t count, size_t index)
{
    if (tokens[index].kind != YX_DIAG_WORD) return NULL;
    for (size_t i = 0; i + 4 < count; ++i) {
        if (!yx_diag_token_is(&tokens[i], "for")) continue;
        for (size_t j = i + 1; j + 3 < count; ++j) {
            if (!yx_diag_token_is(&tokens[j], "in")) continue;
            if (j <= i + 1 ||
                tokens[j - 1].end - tokens[j - 1].start !=
                    tokens[index].end - tokens[index].start ||
                memcmp(tokens[j - 1].start, tokens[index].start,
                       (size_t)(tokens[index].end - tokens[index].start)) != 0)
                break;
            if (yx_diag_token_is(&tokens[j + 1], "("))
                return yx_diag_literal_type(&tokens[j + 2]);
            break;
        }
    }
    return NULL;
}

/* The expression parser can reject an integer comparison with a hash digest
 * before symbol validation runs. Diagnose missing imports, simple invalid
 * argument lists, and valid digest calls at their reference source spans. */
static bool yx_hash_digest_integer_comparison_error(yx_parser *p,
                                                    const YRX_RULE *rule,
                                                    const char *start,
                                                    const char *detail)
{
    static const char arguments_note[] =
        "accepted argument combinations:\n\n(integer, integer)\n(string)";
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    if ((strcmp(detail, "mismatching operand types") != 0 &&
         strncmp(detail, "mismatching types:", 18) != 0 &&
         strncmp(detail, "wrong arguments for 'hash.", 26) != 0) ||
        !yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    for (size_t i = 1; i + 5 < count; ++i) {
        bool integer_left = false;
        const yx_diag_token *module = &tokens[i + 1];
        const yx_diag_token *method = &tokens[i + 3];
        if (!(yx_diag_token_is(&tokens[i], "==") ||
              yx_diag_token_is(&tokens[i], "!=") ||
              yx_diag_token_is(&tokens[i], "<") ||
              yx_diag_token_is(&tokens[i], "<=") ||
              yx_diag_token_is(&tokens[i], ">") ||
              yx_diag_token_is(&tokens[i], ">=")) ||
            !yx_diag_token_is(module, "hash") ||
            !yx_diag_token_is(&tokens[i + 2], ".") ||
            !(yx_diag_token_is(method, "md5") ||
              yx_diag_token_is(method, "sha1") ||
              yx_diag_token_is(method, "sha256")) ||
            !yx_diag_token_is(&tokens[i + 4], "(")) continue;
        size_t close = SIZE_MAX, depth = 1;
        for (size_t j = i + 5; j < count; ++j) {
            if (yx_diag_token_is(&tokens[j], "(")) ++depth;
            else if (yx_diag_token_is(&tokens[j], ")") && --depth == 0) {
                close = j;
                break;
            }
        }
        if (close == SIZE_MAX) continue;
        if (i == 1 &&
            (tokens[0].kind == YX_DIAG_INTEGER ||
             yx_diag_token_is(&tokens[0], "filesize")))
            integer_left = true;
        else if (i >= 4 &&
                 yx_diag_integer_read_name(&tokens[0]) &&
                 yx_diag_token_is(&tokens[1], "(") &&
                 yx_diag_token_is(&tokens[i - 1], ")")) {
            size_t depth = 0;
            for (size_t j = 1; j < i; ++j) {
                if (yx_diag_token_is(&tokens[j], "(")) ++depth;
                else if (yx_diag_token_is(&tokens[j], ")") &&
                         depth && --depth == 0) {
                    integer_left = j == i - 1;
                    break;
                }
            }
        }
        if (!integer_left) continue;
        bool imported = false;
        for (size_t j = 0; j < p->compiler->rules->import_count; ++j)
            if (strcmp(p->compiler->rules->imports[j], "hash") == 0)
                imported = true;
        bool string_argument = close == i + 6 &&
            tokens[i + 5].kind == YX_DIAG_STRING;
        bool integer_pair = close == i + 8 &&
            (tokens[i + 5].kind == YX_DIAG_INTEGER ||
             yx_diag_token_is(&tokens[i + 5], "filesize")) &&
            yx_diag_token_is(&tokens[i + 6], ",") &&
            (tokens[i + 7].kind == YX_DIAG_INTEGER ||
             yx_diag_token_is(&tokens[i + 7], "filesize"));
        bool wrong_arguments = close == i + 5 ||
            (close == i + 6 &&
             (tokens[i + 5].kind == YX_DIAG_INTEGER ||
              yx_diag_token_is(&tokens[i + 5], "filesize"))) ||
            (close == i + 8 &&
             tokens[i + 5].kind == YX_DIAG_STRING &&
             yx_diag_token_is(&tokens[i + 6], ",") &&
             tokens[i + 7].kind == YX_DIAG_STRING);
        if (imported && !string_argument && !integer_pair &&
            !wrong_arguments) continue;
        bool ok;
        if (!imported) {
            yx_condition_symbols symbols = {p, rule};
            if (yx_condition_identifier_exists(&symbols, "hash")) continue;
            ok = yx_compiler_unknown_identifier_error(
                p->compiler, "hash", p->begin, p->origin,
                (size_t)(module->start - p->begin),
                (size_t)(module->end - p->begin)) != 0;
        } else if (wrong_arguments) {
            ok = yx_compiler_wrong_arguments_error(
                p->compiler, p->begin, p->origin,
                (size_t)(tokens[i + 4].start - p->begin),
                (size_t)(tokens[close].end - p->begin),
                arguments_note) != 0;
        } else {
            ok = yx_compiler_mismatching_types_error(
                p->compiler, p->begin, p->origin,
                (size_t)(tokens[0].start - p->begin),
                (size_t)(tokens[i - 1].end - p->begin), "integer",
                (size_t)(method->start - p->begin),
                (size_t)(tokens[close].end - p->begin), "string") != 0;
        }
        free(tokens);
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    free(tokens);
    return false;
}

static bool yx_mismatching_types_condition_error(yx_parser *p,
                                                const char *start,
                                                const char *detail)
{
    size_t left_start, left_end, right_start, right_end;
    char left_type[32], right_type[32];
    if (sscanf(detail, "mismatching types:%zu:%zu:%31[^:]:%zu:%zu:%31[^:]",
               &left_start, &left_end, left_type,
               &right_start, &right_end, right_type) == 6 &&
        left_start < left_end && left_end <= right_start &&
        right_start < right_end && right_end <= (size_t)(p->at - start)) {
        size_t offset = (size_t)(start - p->begin);
        bool ok = yx_compiler_mismatching_types_error(p->compiler, p->begin,
            p->origin, offset + left_start, offset + left_end, left_type,
            offset + right_start, offset + right_end, right_type) != 0;
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    yx_diag_token *tokens = NULL;
    size_t count = 0, first = SIZE_MAX, second = SIZE_MAX;
    const char *first_type = NULL, *second_type = NULL;
    const char *first_start = NULL, *first_end = NULL;
    const char *second_start = NULL, *second_end = NULL;
    bool ok;
    if (strcmp(detail, "mismatching operand types") != 0 &&
        strcmp(detail, "mismatching tuple types") != 0) return false;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count)) return false;
    if (strcmp(detail, "mismatching operand types") == 0) {
        for (size_t i = 1; i + 1 < count; ++i) {
            if (!yx_diag_token_is(&tokens[i], "==") &&
                !yx_diag_token_is(&tokens[i], "!=") &&
                !yx_diag_token_is(&tokens[i], ">") &&
                !yx_diag_token_is(&tokens[i], ">=") &&
                !yx_diag_token_is(&tokens[i], "<") &&
                !yx_diag_token_is(&tokens[i], "<=")) continue;
            first = i - 1;
            second = i + 1;
            first_start = tokens[first].start;
            first_end = tokens[first].end;
            second_start = tokens[second].start;
            second_end = tokens[second].end;
            first_type = yx_diag_literal_type(&tokens[first]);
            second_type = yx_diag_literal_type(&tokens[second]);
            if (first_type && first >= 1 &&
                yx_diag_token_is(&tokens[first - 1], "-") &&
                (first == 1 || yx_diag_token_is(&tokens[first - 2], "(")))
                first_start = tokens[first - 1].start;
            if (!second_type && yx_diag_token_is(&tokens[second], "-") &&
                second + 1 < count &&
                tokens[second + 1].kind == YX_DIAG_INTEGER) {
                second_type = "integer";
                second_end = tokens[second + 1].end;
            }
            if (!first_type && yx_diag_token_is(&tokens[first], "filesize"))
                first_type = "integer";
            if (!second_type && yx_diag_token_is(&tokens[second], "filesize"))
                second_type = "integer";
            if (!first_type && first >= 2 &&
                yx_diag_token_is(&tokens[first - 2], "test_proto2") &&
                yx_diag_token_is(&tokens[first - 1], ".") &&
                yx_diag_token_is(&tokens[first], "requires_foo_and_bar")) {
                first_type = "integer";
                first_start = tokens[first - 2].start;
            }
            if (!second_type && second + 2 < count &&
                yx_diag_token_is(&tokens[second], "test_proto2") &&
                yx_diag_token_is(&tokens[second + 1], ".") &&
                yx_diag_token_is(&tokens[second + 2], "requires_foo_and_bar")) {
                second_type = "integer";
                second_end = tokens[second + 2].end;
            }
            if (!first_type && first >= 3 &&
                yx_diag_token_is(&tokens[first], ")") &&
                yx_diag_token_is(&tokens[first - 2], "(") &&
                yx_diag_integer_read_name(&tokens[first - 3])) {
                first_type = "integer";
                first_start = tokens[first - 3].start;
            }
            if (!second_type && second + 3 < count &&
                yx_diag_integer_read_name(&tokens[second]) &&
                yx_diag_token_is(&tokens[second + 1], "(") &&
                yx_diag_token_is(&tokens[second + 3], ")")) {
                second_type = "integer";
                second_end = tokens[second + 3].end;
            }
            if (!first_type)
                first_type = yx_diag_loop_variable_type(tokens, count, first);
            if (!second_type)
                second_type = yx_diag_loop_variable_type(tokens, count, second);
            if (first_type && second_type && strcmp(first_type, second_type))
                break;
            first = second = SIZE_MAX;
        }
    } else {
        for (size_t i = 0; i + 2 < count; ++i) {
            if (!yx_diag_token_is(&tokens[i], "in") ||
                !yx_diag_token_is(&tokens[i + 1], "(")) continue;
            size_t previous = SIZE_MAX;
            const char *previous_type = NULL;
            for (size_t j = i + 2; j < count; ++j) {
                if (yx_diag_token_is(&tokens[j], ")")) break;
                const char *type = yx_diag_literal_type(&tokens[j]);
                if (!type) continue;
                if (previous_type && strcmp(previous_type, type)) {
                    first = previous;
                    second = j;
                    first_type = previous_type;
                    second_type = type;
                    break;
                }
                previous = j;
                previous_type = type;
            }
            if (first != SIZE_MAX) break;
        }
    }
    if (first == SIZE_MAX || second == SIZE_MAX ||
        !first_type || !second_type) { free(tokens); return false; }
    if (!first_start) first_start = tokens[first].start;
    if (!first_end) first_end = tokens[first].end;
    if (!second_start) second_start = tokens[second].start;
    if (!second_end) second_end = tokens[second].end;
    ok = yx_compiler_mismatching_types_error(
        p->compiler, p->begin, p->origin,
        (size_t)(first_start - p->begin),
        (size_t)(first_end - p->begin), first_type,
        (size_t)(second_start - p->begin),
        (size_t)(second_end - p->begin), second_type) != 0;
    free(tokens);
    if (ok) p->recoverable_unknown_identifier = true;
    return ok;
}

static bool yx_assignment_mismatch_condition_error(yx_parser *p,
                                                   const char *start,
                                                   const char *detail)
{
    size_t expects, produces, binding_start, binding_end;
    size_t iterable_start, iterable_end;
    if (sscanf(detail, "assignment mismatch:%zu:%zu:%zu:%zu:%zu:%zu",
               &expects, &produces, &binding_start, &binding_end,
               &iterable_start, &iterable_end) == 6 &&
        binding_start < binding_end && binding_end <= iterable_start &&
        iterable_start < iterable_end &&
        iterable_end <= (size_t)(p->at - start)) {
        size_t offset = (size_t)(start - p->begin);
        bool ok = yx_compiler_assignment_mismatch_error(p->compiler,
            p->begin, p->origin, offset + binding_start,
            offset + binding_end, expects, offset + iterable_start,
            offset + iterable_end, produces) != 0;
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool ok = false;
    if (!strstr(detail, "expected ')'") ||
        !yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    for (size_t i = 3; i + 2 < count; ++i) {
        size_t end_index = SIZE_MAX;
        size_t depth = 0;
        bool range = false;
        if (!yx_diag_token_is(&tokens[i], "in") ||
            !yx_diag_token_is(&tokens[i - 2], ",") ||
            tokens[i - 3].kind != YX_DIAG_WORD ||
            tokens[i - 1].kind != YX_DIAG_WORD ||
            !yx_diag_token_is(&tokens[i + 1], "(")) continue;
        for (size_t j = i + 1; j < count; ++j) {
            if (yx_diag_token_is(&tokens[j], "(")) ++depth;
            else if (yx_diag_token_is(&tokens[j], ")")) {
                if (--depth == 0) { end_index = j; break; }
            } else if (depth == 1 && yx_diag_token_is(&tokens[j], "..")) {
                range = true;
            }
        }
        if (end_index == SIZE_MAX || end_index <= i + 2) continue;
        const char *iterable_start = range ? tokens[i + 1].start :
            tokens[i + 2].start;
        const char *iterable_end = range ? tokens[end_index].end :
            tokens[end_index - 1].end;
        ok = yx_compiler_assignment_mismatch_error(
            p->compiler, p->begin, p->origin,
            (size_t)(tokens[i - 3].start - p->begin),
            (size_t)(tokens[i - 1].end - p->begin), 2,
            (size_t)(iterable_start - p->begin),
            (size_t)(iterable_end - p->begin), 1) != 0;
        break;
    }
    free(tokens);
    if (ok) p->recoverable_unknown_identifier = true;
    return ok;
}

static bool yx_parse_range_bound(const char **cursor, const char *end,
                                 int64_t *value)
{
    const char *at = *cursor;
    uint64_t magnitude = 0;
    uint64_t limit;
    unsigned radix = 10;
    bool negative = false, digit_seen = false;
    if (at < end && (*at == '-' || *at == '+')) {
        negative = *at == '-';
        ++at;
    }
    limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    if (end - at >= 2 && at[0] == '0' &&
        (at[1] == 'x' || at[1] == 'X' ||
         at[1] == 'o' || at[1] == 'O')) {
        radix = at[1] == 'x' || at[1] == 'X' ? 16 : 8;
        at += 2;
    }
    while (at < end) {
        int digit = yx_hex_digit((unsigned char)*at);
        if (*at == '_' && digit_seen) { ++at; continue; }
        if (digit < 0 || (unsigned)digit >= radix) break;
        digit_seen = true;
        if (magnitude > (limit - (unsigned)digit) / radix) return false;
        magnitude = magnitude * radix + (unsigned)digit;
        ++at;
    }
    if (!digit_seen) return false;
    if (negative)
        *value = magnitude == (uint64_t)INT64_MAX + 1 ?
                 INT64_MIN : -(int64_t)magnitude;
    else
        *value = (int64_t)magnitude;
    *cursor = at;
    return true;
}

static bool yx_invalid_range_condition_error(yx_parser *p,
                                             const char *start,
                                             const char *detail)
{
    const char *cursor = start;
    if (strncmp(detail, "invalid range span ", 19) == 0) {
        /* Bounds that are constant through `with` variables: the validation
         * gives their span and values; the range is the `(..)` around. */
        size_t first, last;
        long long lower, upper;
        const char *open, *close;
        if (sscanf(detail, "invalid range span %zu..%zu %lld %lld",
                   &first, &last, &lower, &upper) != 4 || first >= last ||
            last > (size_t)(p->at - start)) return false;
        open = start + first;
        close = start + last;
        while (open > start && isspace((unsigned char)open[-1])) --open;
        while (close < p->at && isspace((unsigned char)*close)) ++close;
        if (open > start && open[-1] == '(' && close < p->at && *close == ')') {
            --open;
            ++close;
        } else {
            open = start + first;
            close = start + last;
        }
        if (!yx_compiler_invalid_range_error(p->compiler, p->begin, p->origin,
                                             (size_t)(open - p->begin),
                                             (size_t)(close - p->begin),
                                             (int64_t)lower, (int64_t)upper))
            return false;
        p->recoverable_unknown_identifier = true;
        return true;
    }
    if (strcmp(detail, "invalid range") != 0) return false;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        if (*cursor == '(') {
            const char *end = cursor + 1;
            int64_t lower, upper;
            while (end < p->at && isspace((unsigned char)*end)) ++end;
            if (yx_parse_range_bound(&end, p->at, &lower)) {
                while (end < p->at && isspace((unsigned char)*end)) ++end;
                if (p->at - end >= 2 && end[0] == '.' && end[1] == '.') {
                    end += 2;
                    while (end < p->at && isspace((unsigned char)*end)) ++end;
                    if (yx_parse_range_bound(&end, p->at, &upper)) {
                        while (end < p->at && isspace((unsigned char)*end)) ++end;
                        if (end < p->at && *end == ')' && lower > upper) {
                            if (!yx_compiler_invalid_range_error(
                                    p->compiler, p->begin, p->origin,
                                    (size_t)(cursor - p->begin),
                                    (size_t)(end + 1 - p->begin),
                                    lower, upper)) return false;
                            p->recoverable_unknown_identifier = true;
                            return true;
                        }
                    }
                }
            }
        }
        ++cursor;
    }
    return false;
}

static bool yx_folded_number_out_of_range_error(yx_parser *p,
                                                const char *start,
                                                const char *detail)
{
    const char *span = strstr(detail, "number out of range span ");
    size_t relative_start, relative_end;
    int consumed = 0;
    if (!span ||
        sscanf(span, "number out of range span %zu..%zu%n",
               &relative_start, &relative_end, &consumed) != 2 ||
        consumed == 0 || relative_start >= relative_end ||
        relative_end > (size_t)(p->at - start))
        return false;
    if (!yx_compiler_number_out_of_range_error(
            p->compiler, p->begin, p->origin,
            (size_t)(start - p->begin) + relative_start,
            (size_t)(start - p->begin) + relative_end,
            strstr(detail, "non-negative number out of range") ?
            "[0-9223372036854775807]" :
            strstr(detail, "positive number out of range") ?
            "[1-9223372036854775807]" :
            "[-9223372036854775808-9223372036854775807]"))
        return false;
    p->recoverable_unknown_identifier = true;
    return true;
}

static bool yx_invalid_integer_condition_span(const char *start,
                                              const char *end,
                                              const char **span_start,
                                              const char **span_end)
{
    const char *cursor = start;
    while (cursor < end) {
        const char *next = yx_condition_skip_noncode(cursor, start, end);
        if (next != cursor) { cursor = next; continue; }
        if (isdigit((unsigned char)*cursor) &&
            (cursor == start ||
             !yx_ident_continue_width_before(start, cursor))) {
            const char *number_start = cursor;
            unsigned base = 10;
            uint64_t value = 0;
            bool overflow = false;
            if (cursor + 2 < end && cursor[0] == '0' &&
                (cursor[1] == 'x' || cursor[1] == 'X')) {
                base = 16;
                cursor += 2;
            } else if (cursor + 2 < end && cursor[0] == '0' &&
                       (cursor[1] == 'o' || cursor[1] == 'O')) {
                base = 8;
                cursor += 2;
            }
            while (cursor < end) {
                int digit = yx_hex_digit((unsigned char)*cursor);
                if (*cursor == '_') { ++cursor; continue; }
                if (digit < 0 || (unsigned)digit >= base) break;
                if (!overflow) {
                    if (value > (UINT64_MAX - (unsigned)digit) /
                                base)
                        overflow = true;
                    else value = value * base + (unsigned)digit;
                }
                ++cursor;
            }
            if (base == 10 && cursor + 1 < end && cursor[0] == '.' &&
                isdigit((unsigned char)cursor[1])) {
                cursor += 2;
                while (cursor < end &&
                       (isdigit((unsigned char)*cursor) || *cursor == '_'))
                    ++cursor;
                continue;
            }
            if (base == 10 && cursor + 1 < end &&
                (cursor[0] == 'K' || cursor[0] == 'M') && cursor[1] == 'B') {
                uint64_t multiplier = cursor[0] == 'K' ? 1024 : 1024 * 1024;
                if (value > UINT64_MAX / multiplier) overflow = true;
                cursor += 2;
            }
            if (overflow) {
                *span_start = number_start;
                *span_end = cursor;
                return true;
            }
            continue;
        }
        ++cursor;
    }
    return false;
}

static bool yx_invalid_integer_condition_error(yx_parser *p,
                                               const char *start,
                                               const char *detail)
{
    const char *span_start, *span_end;
    const char *span = strstr(detail, " span ");
    size_t relative_start, relative_end;
    if (!strstr(detail, "literal overflows")) return false;
    if (span && sscanf(span, " span %zu..%zu", &relative_start,
                       &relative_end) == 2 && relative_start < relative_end &&
        relative_end <= (size_t)(p->at - start)) {
        span_start = start + relative_start;
        span_end = start + relative_end;
    } else if (!yx_invalid_integer_condition_span(start, p->at,
                                                   &span_start, &span_end))
        return false;
    if (!yx_compiler_invalid_integer_error(
            p->compiler, p->begin, p->origin,
            (size_t)(span_start - p->begin),
            (size_t)(span_end - p->begin),
            "[-9223372036854775808, 18446744073709551615]"))
        return false;
    p->recoverable_unknown_identifier = true;
    return true;
}

static bool yx_invalid_escape_condition_error(yx_parser *p,
                                              const char *start,
                                              const char *detail)
{
    bool hexadecimal = strstr(detail, "invalid hexadecimal string escape") != NULL;
    const char *cursor = start;
    if (!hexadecimal && !strstr(detail, "unsupported string escape"))
        return false;
    while (cursor < p->at) {
        if (*cursor == '"') {
            ++cursor;
            while (cursor < p->at && *cursor != '"') {
                if (*cursor == '\\' && cursor + 1 < p->at) {
                    const char *backslash = cursor;
                    char escaped = cursor[1];
                    bool bad_hex = escaped == 'x' &&
                        (cursor + 3 >= p->at ||
                         yx_hex_digit(cursor[2]) < 0 ||
                         yx_hex_digit(cursor[3]) < 0);
                    bool bad_other = escaped != 'x' &&
                        escaped != 'n' && escaped != 'r' &&
                        escaped != 't' && escaped != '0' &&
                        escaped != '"' &&
                        escaped != '\\';
                    if ((hexadecimal && bad_hex) ||
                        (!hexadecimal && bad_other)) {
                        size_t length = 1 +
                            yx_escape_character_bytes(backslash + 1);
                        if (!yx_compiler_invalid_escape_error(
                                p->compiler, p->begin, p->origin,
                                (size_t)(backslash - p->begin),
                                (size_t)(backslash - p->begin) + length,
                                hexadecimal)) return false;
                        p->recoverable_unknown_identifier = true;
                        return true;
                    }
                    cursor += escaped == 'x' && !bad_hex ? 4 : 2;
                    continue;
                }
                ++cursor;
            }
            if (cursor < p->at) ++cursor;
            continue;
        }
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        cursor = next != cursor ? next : cursor + 1;
    }
    return false;
}

static bool yx_condition_regexp_error(yx_parser *p,
                                      const char *start,
                                      const char *detail)
{
    const char *cursor = start;
    bool unsupported = strstr(detail,
                              "unsupported regular expression construct") != NULL;
    if (!unsupported && !strstr(detail, "invalid regular expression"))
        return false;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        bool is_matches = (size_t)(p->at - cursor) >= 7 &&
            memcmp(cursor, "matches", 7) == 0 &&
            (cursor == start || !yx_ident_continue_width_before(start, cursor)) &&
            (cursor + 7 == p->at || !yx_ident_continue_width(cursor + 7));
        if (is_matches || (*cursor == '=' &&
            (cursor == start || cursor[-1] != '=') &&
            (cursor + 1 == p->at || cursor[1] != '=')) ||
            *cursor == '(' || *cursor == ',') {
            const char *literal = cursor + (is_matches ? 7 : 1);
            while (literal < p->at && isspace((unsigned char)*literal))
                ++literal;
            if (literal >= p->at || *literal != '/') { ++cursor; continue; }
            const char *end = literal + 1;
            while (end < p->at) {
                if (*end == '\\' && end + 1 < p->at) { end += 2; continue; }
                if (*end == '/') break;
                ++end;
            }
            if (end >= p->at) return false;
            const char *body = literal + 1;
            size_t flag_at;
            const char *flag_label;
            {
                /* regex-syntax's AST parser reports before every later
                 * check, whichever construct the condition parser tripped
                 * over. */
                yx_regex_ast_err first_error;
                if (yx_regex_ast_error(body, (size_t)(end - body),
                                       &first_error)) {
                    size_t source_at = (size_t)(body - p->begin);
                    if (!yx_compiler_invalid_regexp_error(
                            p->compiler, p->begin, p->origin,
                            source_at + first_error.start,
                            source_at + first_error.end, first_error.label,
                            first_error.note[0] ? first_error.note : NULL))
                        return false;
                    p->recoverable_unknown_identifier = true;
                    return true;
                }
            }
            if (yx_regex_inline_r_flag_error(
                    body, (size_t)(end - body), &flag_at,
                    &flag_label)) {
                size_t source_at = (size_t)(body - p->begin) + flag_at;
                if (!yx_compiler_invalid_regexp_error(
                        p->compiler, p->begin, p->origin,
                        source_at, source_at + 1, flag_label, NULL))
                    return false;
                p->recoverable_unknown_identifier = true;
                return true;
            }
            if (unsupported) {
                bool regex_class = false;
                yx_regex_ast_err ast_error;
                if (yx_regex_ast_error(body, (size_t)(end - body),
                                       &ast_error)) {
                    size_t source_at = (size_t)(body - p->begin);
                    if (!yx_compiler_invalid_regexp_error(
                            p->compiler, p->begin, p->origin,
                            source_at + ast_error.start,
                            source_at + ast_error.end, ast_error.label,
                            ast_error.note[0] ? ast_error.note : NULL))
                        return false;
                    p->recoverable_unknown_identifier = true;
                    return true;
                }
                for (const char *at = body; at < end; ++at) {
                    size_t marker_length = 0;
                    if (*at == '\\' && at + 1 < end) {
                        if (at[1] >= '0' && at[1] <= '9') {
                            if (!yx_compiler_invalid_regexp_error(
                                    p->compiler, p->begin, p->origin,
                                    (size_t)(at - p->begin),
                                    (size_t)(at - p->begin) + 2,
                                    "backreferences are not supported",
                                    NULL)) return false;
                            p->recoverable_unknown_identifier = true;
                            return true;
                        }
                        if (yx_regex_unrecognized_escape(
                                (unsigned char)at[1])) {
                            char note[96];
                            snprintf(note, sizeof(note),
                                     "did you mean `\\\\%c` instead of "
                                     "`\\%c`?", at[1], at[1]);
                            if (!yx_compiler_invalid_regexp_error(
                                    p->compiler, p->begin, p->origin,
                                    (size_t)(at - p->begin),
                                    (size_t)(at - p->begin) + 2,
                                    "unrecognized escape sequence",
                                    note)) return false;
                            p->recoverable_unknown_identifier = true;
                            return true;
                        }
                        ++at;
                        continue;
                    }
                    if (*at == '[' && !regex_class) {
                        regex_class = true;
                        continue;
                    }
                    if (*at == ']' && regex_class) {
                        regex_class = false;
                        continue;
                    }
                    if (regex_class) continue;
                    if (*at != '(' || at + 2 >= end || at[1] != '?')
                        continue;
                    if (at[2] == '=' || at[2] == '!') marker_length = 3;
                    else if (at + 3 < end && at[2] == '<' &&
                             (at[3] == '=' || at[3] == '!'))
                        marker_length = 4;
                    if (!marker_length) {
                        bool invalid_flag = at[2] == '>' || at[2] == '|' ||
                                            at[2] == '(' || at[2] == '#' ||
                                            at[2] == '0' || at[2] == '&' ||
                                            at[2] == '\'' ||
                                            (at + 3 < end && at[2] == 'P' &&
                                             at[3] == '=');
                        if (!invalid_flag) continue;
                        if (!yx_compiler_invalid_regexp_error(
                                p->compiler, p->begin, p->origin,
                                (size_t)(at + 2 - p->begin),
                                (size_t)(at + 3 - p->begin),
                                "unrecognized flag", NULL)) return false;
                        p->recoverable_unknown_identifier = true;
                        return true;
                    }
                    if (!yx_compiler_invalid_regexp_error(
                            p->compiler, p->begin, p->origin,
                            (size_t)(at - p->begin),
                            (size_t)(at - p->begin) + marker_length,
                            "look-around, including look-ahead and "
                            "look-behind, is not supported", NULL))
                        return false;
                    p->recoverable_unknown_identifier = true;
                    return true;
                }
                cursor = end + 1;
                continue;
            }
            if (yx_regex_incomplete_trailing_escape(
                    body, (size_t)(end - body))) {
                size_t source_at = (size_t)(end - p->begin);
                if (!yx_compiler_invalid_regexp_error(
                        p->compiler, p->begin, p->origin,
                        source_at, source_at,
                        "incomplete escape sequence, reached end of "
                        "pattern prematurely", NULL)) return false;
                p->recoverable_unknown_identifier = true;
                return true;
            }
            for (const char *at = body; at < end; ++at) {
                if (*at == '\\' && at + 1 < end) { ++at; continue; }
                if (*at == '[') {
                    while (++at < end && *at != ']')
                        if (*at == '\\' && at + 1 < end) ++at;
                    continue;
                }
                if (*at != '{') continue;
                const char *number = at + 1;
                while (number < end && isdigit((unsigned char)*number)) {
                    const char *first = number;
                    uint64_t value = 0;
                    while (number < end && isdigit((unsigned char)*number)) {
                        if (value <= UINT32_MAX)
                            value = value * 10u +
                                    (unsigned)(*number - '0');
                        ++number;
                    }
                    if (value > UINT32_MAX) {
                        if (!yx_compiler_invalid_regexp_error(
                                p->compiler, p->begin, p->origin,
                                (size_t)(first - p->begin),
                                (size_t)(number - p->begin),
                                "decimal literal invalid", NULL)) return false;
                        p->recoverable_unknown_identifier = true;
                        return true;
                    }
                    if (number >= end || *number != ',') break;
                    ++number;
                }
            }
            const char *literal_end = end + 1;
            bool insensitive = false;
            while (literal_end < p->at &&
                   (*literal_end == 'i' || *literal_end == 's')) {
                if (*literal_end == 'i') insensitive = true;
                ++literal_end;
            }
            if (yx_regex_nesting_error(body, (size_t)(end - body), NULL, NULL) ||
                !yx_regex_automata_size_large(
                    body, (size_t)(end - body),
                    (insensitive ? YX_MOD_NOCASE : 0) |
                    ((literal_end > end + 1 && memchr(end + 1, 's',
                        (size_t)(literal_end - end - 1))) ? YX_MOD_DOTALL : 0))) {
                /* Otherwise the regexp's error is labelled as in a
                 * pattern: the same parser compiles both. */
                if (!unsupported) {
                    YRX_PATTERN trial;
                    int status;
                    memset(&trial, 0, sizeof(trial));
                    trial.regexp = yx_duplicate(body, (size_t)(end - body));
                    if (!trial.regexp) return false;
                    for (const char *flag = end + 1; flag < literal_end; ++flag)
                        trial.modifiers |= *flag == 'i' ? YX_MOD_NOCASE :
                                                          YX_MOD_DOTALL;
                    status = yx_validate_regex(&trial);
                    /* Only a pattern rejects a regexp matching nothing. */
                    if (status < 0) {
                        size_t errors = p->compiler->error_diagnostic_json ?
                            strlen(p->compiler->error_diagnostic_json) : 0;
                        int reported = yx_report_pattern_regexp_error(
                            p, &trial, literal, literal, literal_end, status);
                        free(trial.regexp);
                        if (reported && p->compiler->error_diagnostic_json &&
                            strlen(p->compiler->error_diagnostic_json) > errors) {
                            p->recoverable_unknown_identifier = true;
                            return true;
                        }
                        return false;
                    }
                    free(trial.regexp);
                }
                cursor = literal_end;
                continue;
            }
            if (!yx_compiler_invalid_regexp_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(literal - p->begin),
                    (size_t)(literal_end - p->begin),
                    "regex is too large", NULL)) return false;
            p->recoverable_unknown_identifier = true;
            return true;
        }
        ++cursor;
    }
    return false;
}

static bool yx_empty_pattern_set_condition_error(yx_parser *p,
                                                 const char *start,
                                                 const char *detail)
{
    static const char selector_prefix[] = "unknown pattern selector '";
    const char *needle = NULL, *cursor;
    size_t length = 0;
    char note[512];
    if (strcmp(detail, "pattern set contains no patterns") == 0) {
        needle = "them";
        length = 4;
        snprintf(note, sizeof(note),
                 "this rule doesn't define any patterns");
    } else if (strncmp(detail, selector_prefix,
                       sizeof(selector_prefix) - 1) == 0) {
        const char *last = detail + strlen(detail) - 1;
        needle = detail + sizeof(selector_prefix) - 1;
        if (*last != '\'' || last <= needle) return false;
        length = (size_t)(last - needle);
        if (length > 256 ||
            snprintf(note, sizeof(note),
                     "`%.*s` doesn't match any pattern identifier",
                     (int)length, needle) >= (int)sizeof(note)) return false;
    } else {
        return false;
    }
    cursor = start;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) {
            cursor = next;
            continue;
        }
        if ((size_t)(p->at - cursor) >= length &&
            memcmp(cursor, needle, length) == 0 &&
            (cursor == start || !yx_ident_continue_width_before(start, cursor)) &&
            (cursor + length == p->at ||
             !yx_ident_continue_width(cursor + length))) {
            if (!yx_compiler_empty_pattern_set_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(cursor - p->begin),
                    (size_t)(cursor - p->begin) + length, note)) return false;
            p->recoverable_unknown_identifier = true;
            return true;
        }
        ++cursor;
    }
    return false;
}

/* Locate the source span of a constant negative shift count. The condition
 * parser has already determined that the count is negative; this small
 * evaluator only chooses the corresponding source label, including a simple
 * folded sum such as `(0 - 1)`. */
static bool yx_shift_sum_atom(const char **cursor, const char *end,
                              int64_t *number)
{
    const char *at = *cursor;
    bool negative = false;
    unsigned base = 10;
    uint64_t magnitude = 0;
    size_t digits = 0;
    while (at < end && isspace((unsigned char)*at)) ++at;
    while (at < end && (*at == '-' || *at == '+')) {
        if (*at == '-') negative = !negative;
        ++at;
        while (at < end && isspace((unsigned char)*at)) ++at;
    }
    if (at + 1 < end && at[0] == '0' &&
        (at[1] == 'x' || at[1] == 'X')) {
        base = 16;
        at += 2;
    }
    while (at < end) {
        unsigned digit;
        if (*at >= '0' && *at <= '9') digit = (unsigned)(*at - '0');
        else if (base == 16 && *at >= 'a' && *at <= 'f')
            digit = (unsigned)(*at - 'a' + 10);
        else if (base == 16 && *at >= 'A' && *at <= 'F')
            digit = (unsigned)(*at - 'A' + 10);
        else break;
        if (digit >= base || magnitude >
            (((uint64_t)INT64_MAX + (negative ? 1u : 0u)) - digit) / base)
            return false;
        magnitude = magnitude * base + digit;
        ++digits;
        ++at;
    }
    if (!digits) return false;
    *number = negative ?
        (magnitude == (uint64_t)INT64_MAX + 1u ? INT64_MIN :
         -(int64_t)magnitude) : (int64_t)magnitude;
    *cursor = at;
    return true;
}

static bool yx_shift_simple_sum(const char *begin, const char *end,
                                int64_t *value)
{
    const char *at = begin;
    int64_t total, term;
    if (!yx_shift_sum_atom(&at, end, &total)) return false;
    while (at < end) {
        char operation;
        while (at < end && isspace((unsigned char)*at)) ++at;
        if (at == end) break;
        operation = *at++;
        if ((operation != '+' && operation != '-') ||
            !yx_shift_sum_atom(&at, end, &term)) return false;
        if (operation == '+') {
            if ((term > 0 && total > INT64_MAX - term) ||
                (term < 0 && total < INT64_MIN - term)) return false;
            total += term;
        } else {
            if ((term < 0 && total > INT64_MAX + term) ||
                (term > 0 && total < INT64_MIN + term)) return false;
            total -= term;
        }
    }
    *value = total;
    return true;
}

static bool yx_negative_shift_span(const char *start, const char *end,
                                   const char **label_start,
                                   const char **label_end)
{
    const char *cursor = start;
    while (cursor + 1 < end) {
        const char *next = yx_condition_skip_noncode(cursor, start, end);
        if (next != cursor) { cursor = next; continue; }
        if ((cursor[0] != '<' && cursor[0] != '>') ||
            cursor[1] != cursor[0]) {
            ++cursor;
            continue;
        }
        const char *first = cursor + 2, *last;
        int64_t count;
        while (first < end && isspace((unsigned char)*first)) ++first;
        if (first == end) return false;
        if (*first == '(') {
            const char *inner = first + 1;
            unsigned depth = 1;
            last = inner;
            while (last < end && depth) {
                if (*last == '(') ++depth;
                else if (*last == ')') --depth;
                if (depth) ++last;
            }
            if (depth) return false;
            first = inner;
            while (first < last && isspace((unsigned char)*first)) ++first;
            while (last > first && isspace((unsigned char)last[-1])) --last;
            /* A following arithmetic operator extends the shift operand.
               Leave that less common form to the general diagnostic path. */
            const char *after = last + 1;
            while (after < end && isspace((unsigned char)*after)) ++after;
            if (after < end && (*after == '+' || *after == '-')) {
                cursor = after;
                continue;
            }
        } else {
            last = first;
            while (last < end && *last != '=' && *last != '<' &&
                   *last != '>' && *last != '!' && *last != ')' &&
                   *last != '&' && *last != '|') ++last;
            while (last > first && isspace((unsigned char)last[-1])) --last;
        }
        if (first < last && yx_shift_simple_sum(first, last, &count) &&
            count < 0) {
            *label_start = first;
            *label_end = last;
            return true;
        }
        cursor += 2;
    }
    return false;
}

static bool yx_unexpected_negative_condition_error(yx_parser *p,
                                                    const char *start,
                                                    const char *detail)
{
    const char *cursor = start;
    const char *label_start, *label_end;
    const char *span = strstr(detail, " span ");
    size_t relative_start, relative_end;
    int consumed = 0;
    if (!strstr(detail, "unexpected negative shift count") &&
        !strstr(detail, "unexpected negative number") &&
        strcmp(detail, "unexpected negative array index") != 0 &&
        strcmp(detail, "unexpected negative pattern offset") != 0)
        return false;
    if (span &&
        sscanf(span, " span %zu..%zu%n",
               &relative_start, &relative_end, &consumed) == 2 &&
        consumed != 0 && relative_start < relative_end &&
        relative_end <= (size_t)(p->at - start)) {
        label_start = start + relative_start;
        label_end = start + relative_end;
    } else if (strstr(detail, "unexpected negative shift count") &&
               yx_negative_shift_span(start, p->at,
                                      &label_start, &label_end)) {
        /* Older condition errors do not carry a parsed source span. */
    } else {
        label_start = NULL;
        label_end = NULL;
    }
    if (label_start) {
        if (!yx_compiler_unexpected_negative_error(
                p->compiler, p->begin, p->origin,
                (size_t)(label_start - p->begin),
                (size_t)(label_end - p->begin))) return false;
        p->recoverable_unknown_identifier = true;
        return true;
    }
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) {
            cursor = next;
            continue;
        }
        if (*cursor == '-' && cursor + 1 < p->at &&
            isdigit((unsigned char)cursor[1])) {
            const char *end = cursor + 2;
            for (;;) {
                size_t width = yx_ident_continue_width(end);
                if (!width || end + width > p->at) break;
                end += width;
            }
            if (!yx_compiler_unexpected_negative_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(cursor - p->begin),
                    (size_t)(end - p->begin))) return false;
            p->recoverable_unknown_identifier = true;
            return true;
        }
        ++cursor;
    }
    return false;
}

static bool yx_number_out_of_range_condition_error(yx_parser *p,
                                                    const char *start,
                                                    const char *detail)
{
    bool match_index = strcmp(detail, "pattern match index is out of range") == 0;
    bool percentage = strcmp(detail, "percent out of range") == 0;
    const char *cursor = start;
    size_t span_start, span_end;
    int consumed = 0;
    /* The validator gives the constant's span: YARA-X labels the folded
     * expression without its parentheses (`~0` in `@a[(~0)]`). */
    if ((sscanf(detail, "pattern match index is out of range span:%zu:%zu%n",
                &span_start, &span_end, &consumed) == 2 ||
         sscanf(detail, "percent out of range span:%zu:%zu%n",
                &span_start, &span_end, &consumed) == 2) &&
        detail[consumed] == '\0' && span_start < span_end &&
        span_end <= (size_t)(p->at - start)) {
        const char *first = start + span_start, *last = start + span_end;
        for (;;) {
            const char *inner = first, *inner_end = last;
            while (inner < inner_end && isspace((unsigned char)*inner)) ++inner;
            while (inner_end > inner && isspace((unsigned char)inner_end[-1]))
                --inner_end;
            size_t depth = 1;
            const char *scan;
            if (inner_end - inner < 2 || *inner != '(' || inner_end[-1] != ')')
                break;
            /* Only one pair of parentheses around the whole text. */
            for (scan = inner + 1; scan < inner_end - 1 && depth; ++scan) {
                if (*scan == '(') ++depth;
                else if (*scan == ')') --depth;
            }
            if (!depth) break;
            first = inner + 1;
            last = inner_end - 1;
        }
        while (first < last && isspace((unsigned char)*first)) ++first;
        while (last > first && isspace((unsigned char)last[-1])) --last;
        if (first < last) {
            if (!yx_compiler_number_out_of_range_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(first - p->begin), (size_t)(last - p->begin),
                    strncmp(detail, "percent", 7) == 0 ?
                        "[0-100]" : "[1-9223372036854775807]")) return false;
            p->recoverable_unknown_identifier = true;
            return true;
        }
    }
    if (strncmp(detail, "pattern match index is out of range span:", 41) == 0)
        match_index = true;
    if (strncmp(detail, "percent out of range span:", 26) == 0)
        percentage = true;
    if (!match_index && !percentage) return false;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        if (match_index && *cursor == '[') {
            const char *number = cursor + 1;
            const char *end;
            const char *prefix = cursor;
            bool negative = false, zero = true;
            while (number < p->at && isspace((unsigned char)*number)) ++number;
            end = number;
            if (end < p->at && (*end == '-' || *end == '+')) {
                negative = *end == '-';
                ++end;
            }
            if (end < p->at && isdigit((unsigned char)*end)) {
                do {
                    if (*end != '0' && *end != '_') zero = false;
                    ++end;
                } while (end < p->at &&
                         (isdigit((unsigned char)*end) || *end == '_'));
                next = end;
                while (next < p->at && isspace((unsigned char)*next)) ++next;
                for (;;) {
                    size_t width = yx_ident_continue_width_before(start, prefix);
                    if (!width) break;
                    prefix -= width;
                }
                if (next < p->at && *next == ']' &&
                    prefix > start &&
                    (prefix[-1] == '@' || prefix[-1] == '!') &&
                    (negative || zero)) {
                    if (!yx_compiler_number_out_of_range_error(
                            p->compiler, p->begin, p->origin,
                            (size_t)(number - p->begin),
                            (size_t)(end - p->begin),
                            "[1-9223372036854775807]")) return false;
                    p->recoverable_unknown_identifier = true;
                    return true;
                }
            }
        }
        if (percentage && isdigit((unsigned char)*cursor) &&
            (cursor == start ||
             !yx_ident_continue_width_before(start, cursor))) {
            const char *number = cursor, *end = cursor;
            unsigned value = 0;
            while (end < p->at &&
                   (isdigit((unsigned char)*end) || *end == '_')) {
                if (*end != '_') {
                    unsigned digit = (unsigned)(*end - '0');
                    value = value > 100 ? 101 :
                            value * 10 + digit > 100 ? 101 :
                            value * 10 + digit;
                }
                ++end;
            }
            next = end;
            while (next < p->at && isspace((unsigned char)*next)) ++next;
            if (next < p->at && *next == '%' && value > 100) {
                if (!yx_compiler_number_out_of_range_error(
                        p->compiler, p->begin, p->origin,
                        (size_t)(number - p->begin),
                        (size_t)(end - p->begin), "[0-100]")) return false;
                p->recoverable_unknown_identifier = true;
                return true;
            }
            cursor = end;
            continue;
        }
        ++cursor;
    }
    return false;
}

static bool yx_too_many_variables_condition_error(yx_parser *p,
                                                  const char *start,
                                                  const char *detail)
{
    const char *cursor = start;
    const char *first_binding;
    const char *bindings_end = NULL;
    const char *span_start;
    const char *span_end;
    size_t binding_count = 1;
    size_t depth = 0;
    size_t relative_start, relative_end;
    int consumed = 0;
    /* The condition validator names the statement whose variable frame
     * does not fit, relative to the condition. */
    if (sscanf(detail, "too many variables span %zu..%zu%n",
               &relative_start, &relative_end, &consumed) == 2 &&
        detail[consumed] == '\0' && relative_start < relative_end &&
        relative_end <= (size_t)(p->at - start)) {
        if (!yx_compiler_too_many_variables_error(
                p->compiler, p->begin, p->origin,
                (size_t)(start - p->begin) + relative_start,
                (size_t)(start - p->begin) + relative_end))
            return false;
        p->too_many_variables_at = start + relative_start;
        p->recoverable_unknown_identifier = true;
        return true;
    }
    if (strcmp(detail, "too many variables") != 0) return false;
    while (cursor < p->at && isspace((unsigned char)*cursor)) ++cursor;
    if (p->at - cursor < 4 || memcmp(cursor, "with", 4) != 0 ||
        (cursor + 4 < p->at && yx_ident_continue_width(cursor + 4)))
        return false;
    cursor += 4;
    while (cursor < p->at && isspace((unsigned char)*cursor)) ++cursor;
    first_binding = cursor;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        if (*cursor == '(' || *cursor == '[' || *cursor == '{') ++depth;
        else if ((*cursor == ')' || *cursor == ']' || *cursor == '}') && depth)
            --depth;
        else if (*cursor == ',' && depth == 0) ++binding_count;
        else if (*cursor == ':' && depth == 0) {
            bindings_end = cursor;
            break;
        }
        ++cursor;
    }
    if (!bindings_end) return false;
    if (binding_count > 2048) {
        span_start = first_binding;
        span_end = bindings_end;
        while (span_end > span_start &&
               isspace((unsigned char)span_end[-1])) --span_end;
    } else {
        cursor = bindings_end + 1;
        while (cursor < p->at && isspace((unsigned char)*cursor)) ++cursor;
        if (cursor == p->at || *cursor != '(') return false;
        ++cursor;
        while (cursor < p->at && isspace((unsigned char)*cursor)) ++cursor;
        span_start = cursor;
        depth = 1;
        while (cursor < p->at) {
            const char *next = yx_condition_skip_noncode(cursor, start, p->at);
            if (next != cursor) { cursor = next; continue; }
            if (*cursor == '(') ++depth;
            else if (*cursor == ')' && --depth == 0) break;
            ++cursor;
        }
        if (cursor == p->at) return false;
        span_end = cursor;
        while (span_end > span_start &&
               isspace((unsigned char)span_end[-1])) --span_end;
        /* The `of` node's location ends at its pattern set, before the
         * closing parenthesis. Loop nodes include their closing parenthesis. */
        if (isdigit((unsigned char)*span_start) && span_end > span_start &&
            span_end[-1] == ')') --span_end;
    }
    if (span_start == span_end ||
        !yx_compiler_too_many_variables_error(
            p->compiler, p->begin, p->origin,
            (size_t)(span_start - p->begin), (size_t)(span_end - p->begin)))
        return false;
    p->recoverable_unknown_identifier = true;
    return true;
}

static bool yx_condition_after_call_open(const char *start,
                                          const char *token)
{
    const char *open = token;
    while (open > start && isspace((unsigned char)open[-1])) --open;
    if (open == start || open[-1] != '(') return false;
    const char *name_end = open - 1;
    while (name_end > start && isspace((unsigned char)name_end[-1]))
        --name_end;
    const char *name_start = name_end;
    for (;;) {
        size_t width = yx_ident_continue_width_before(start, name_start);
        if (!width) break;
        name_start -= width;
    }
    if (name_start == name_end ||
        !(isalpha((unsigned char)*name_start) || *name_start == '_'))
        return false;
    size_t length = (size_t)(name_end - name_start);
    char name[64];
    if (length >= sizeof(name)) return false;
    memcpy(name, name_start, length);
    name[length] = '\0';
    return !yx_reserved_identifier(name);
}

static bool yx_condition_has_module_tail(yx_parser *p, const char *start,
                                         const char *end)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool imported = false;
    if (!yx_condition_diag_tokens(start, end, &tokens, &count) || !count) {
        free(tokens);
        return false;
    }
    size_t first = count - 1;
    if (tokens[first].kind != YX_DIAG_WORD) goto done;
    while (first >= 2 && yx_diag_token_is(&tokens[first - 1], ".") &&
           tokens[first - 2].kind == YX_DIAG_WORD)
        first -= 2;
    size_t length = (size_t)(tokens[first].end - tokens[first].start);
    for (size_t i = 0; i < p->compiler->rules->import_count; ++i)
        if (strlen(p->compiler->rules->imports[i]) == length &&
            memcmp(p->compiler->rules->imports[i], tokens[first].start,
                   length) == 0) {
            imported = true;
            break;
        }
done:
    free(tokens);
    return imported;
}

static bool yx_condition_syntax_error(yx_parser *p, const char *start,
                                      const char *detail)
{
    size_t offset = 0;
    int suffix_offset = 0;
    const char *token;
    const char *expected = NULL;
    const char *token_end_override = NULL;
    if (sscanf(detail, "at byte %zu: %n", &offset, &suffix_offset) != 1 ||
        !suffix_offset || offset > (size_t)(p->at - start)) return false;
    token = start + offset;
    /* The condition parser names the token and the expectation. */
    if (strncmp(detail + suffix_offset, "syntax-expected ", 16) == 0) {
        size_t length = 0;
        int consumed = 0;
        if (sscanf(detail + suffix_offset + 16, "%zu %n", &length, &consumed) == 1 && consumed &&
            length <= (size_t)(p->at - token)) {
            yx_syntax_expected(p, token, token + length, detail + suffix_offset + 16 + consumed);
            return true;
        }
    }
    if (strncmp(detail + suffix_offset, "unexpected token '", 18) == 0 ||
        strcmp(detail + suffix_offset, "expected ')'") == 0) {
        if (strcmp(detail + suffix_offset, "expected ')'") == 0 &&
            token == p->at && *token == '}') {
            yx_diag_token *tokens = NULL;
            size_t count = 0;
            if (!yx_condition_diag_tokens(start, token, &tokens, &count))
                return false;
            if (count) {
                const yx_diag_token *last = &tokens[count - 1];
                if (last->kind == YX_DIAG_WORD && *last->start == '$')
                    expected = "`at`, `in`, operator or `)`";
                else {
                    size_t depth = 0;
                    bool function_call = false;
                    for (size_t i = count; i > 0; --i) {
                        const yx_diag_token *current = &tokens[i - 1];
                        if (yx_diag_token_is(current, ")")) ++depth;
                        else if (yx_diag_token_is(current, "(")) {
                            if (depth) --depth;
                            else {
                                function_call = i > 1 &&
                                    tokens[i - 2].kind == YX_DIAG_WORD &&
                                    tokens[i - 2].end == current->start &&
                                    !yx_diag_token_is(&tokens[i - 2], "and") &&
                                    !yx_diag_token_is(&tokens[i - 2], "or");
                                break;
                            }
                        }
                    }
                    expected = function_call ?
                        "operator, expression, `,` or `)`" :
                        "operator, expression or `)`";
                }
            }
            free(tokens);
        }
        if (*token == '/') {
            const char *literal_end = token + 1;
            yx_diag_token *tokens = NULL;
            size_t count = 0;
            size_t paren_depth = 0;
            /* A closed slash token is a regexp literal in YARA-X's lexer,
             * even where the grammar rejects it (such as after filesize).
             * Its diagnostic covers the whole literal, including at most
             * two single-letter modifiers. */
            while (literal_end < p->at && *literal_end != '\n') {
                if (*literal_end == '\\' && literal_end + 1 < p->at) {
                    literal_end += 2;
                    continue;
                }
                if (*literal_end == '/') break;
                ++literal_end;
            }
            if (literal_end >= p->at || *literal_end != '/') return false;
            ++literal_end;
            for (unsigned flags = 0; flags < 2 &&
                 literal_end < p->at &&
                 ((unsigned char)*literal_end >= 'a' &&
                  (unsigned char)*literal_end <= 'z'); ++flags)
                ++literal_end;
            if (!yx_condition_diag_tokens(start, token, &tokens, &count))
                return false;
            for (size_t i = 0; i < count; ++i) {
                if (yx_diag_token_is(&tokens[i], "(")) ++paren_depth;
                else if (yx_diag_token_is(&tokens[i], ")") && paren_depth)
                    --paren_depth;
            }
            if (count) {
                const yx_diag_token *last = &tokens[count - 1];
                if (yx_diag_token_is(last, "true") ||
                    yx_diag_token_is(last, "false"))
                    expected = "operator or `}`";
                else if (*last->start == '/' && count >= 2 &&
                         yx_diag_token_is(&tokens[count - 2], "matches"))
                    expected = "operator, expression or `}`";
                else if (paren_depth &&
                         (last->kind == YX_DIAG_INTEGER ||
                          yx_diag_token_is(last, "filesize")))
                    expected = "operator, `)`, `%`, `of` or expression";
                else if (last->kind == YX_DIAG_INTEGER && count >= 2 &&
                         (yx_diag_token_is(&tokens[count - 2], "+") ||
                          yx_diag_token_is(&tokens[count - 2], "-") ||
                          yx_diag_token_is(&tokens[count - 2], "*") ||
                          yx_diag_token_is(&tokens[count - 2], "\\")))
                    expected = "operator, `of`, expression or `}`";
                else if (last->kind == YX_DIAG_INTEGER ||
                         last->kind == YX_DIAG_STRING ||
                         yx_diag_token_is(last, "filesize"))
                    expected = "`%`, operator, `of`, expression or `}`";
            }
            free(tokens);
            if (!expected) return false;
            yx_syntax_expected(p, token, literal_end, expected);
            return true;
        }
        if (*token == '"') expected = "operator or `}`";
    } else if (strcmp(detail + suffix_offset,
                      "expected ']' after global index") == 0) {
        if (*token == ')') {
            expected = "`(`, `[`, expression, operator or `]`";
        } else {
            /* The condition parser may stop at the unclosed index and
             * report its end, while the source parser points at the first
             * comparator after a complete call inside that index. */
            yx_diag_token *tokens = NULL;
            size_t count = 0, bracket_depth = 0, paren_depth = 0;
            if (!yx_condition_diag_tokens(start, p->at, &tokens, &count))
                return false;
            for (size_t i = 0; i < count; ++i) {
                if (yx_diag_token_is(&tokens[i], "[")) {
                    ++bracket_depth;
                    continue;
                }
                if (yx_diag_token_is(&tokens[i], "]")) {
                    if (bracket_depth) --bracket_depth;
                    continue;
                }
                if (yx_diag_token_is(&tokens[i], "(")) {
                    ++paren_depth;
                    continue;
                }
                if (yx_diag_token_is(&tokens[i], ")")) {
                    if (paren_depth) --paren_depth;
                    continue;
                }
                if (!bracket_depth || paren_depth || i == 0 ||
                    !yx_diag_token_is(&tokens[i - 1], ")") ||
                    !(yx_diag_token_is(&tokens[i], ">") ||
                      yx_diag_token_is(&tokens[i], "<") ||
                      yx_diag_token_is(&tokens[i], ">=") ||
                      yx_diag_token_is(&tokens[i], "<=") ||
                      yx_diag_token_is(&tokens[i], "==") ||
                      yx_diag_token_is(&tokens[i], "!=") ||
                      yx_diag_token_is(&tokens[i], ",") ||
                      yx_diag_token_is(&tokens[i], "and") ||
                      yx_diag_token_is(&tokens[i], "or"))) continue;
                size_t depth = 0;
                for (size_t j = i; j > 0; --j) {
                    if (yx_diag_token_is(&tokens[j - 1], ")")) ++depth;
                    else if (yx_diag_token_is(&tokens[j - 1], "(")) {
                        if (--depth == 0) {
                            if (j >= 2 &&
                                tokens[j - 2].kind == YX_DIAG_WORD &&
                                tokens[j - 2].end == tokens[j - 1].start) {
                                token = tokens[i].start;
                                token_end_override = tokens[i].end;
                                expected = "expression, operator or `]`";
                            }
                            break;
                        }
                    }
                }
                if (expected) break;
            }
            free(tokens);
        }
    } else if (strcmp(detail + suffix_offset,
                      "expected ')' after read offset") == 0 &&
               *token == ',') {
        /* The read function parser stops after its first argument. The
         * reference parser still diagnoses a malformed second expression. */
        ++token;
        while (token < p->at && isspace((unsigned char)*token)) ++token;
        if (*token == '.' || *token == '>' || *token == ':' ||
            *token == '=' || *token == ')' || *token == '?')
            expected = "expression or identifier";
        if (*token == '?' && token[1] == ')')
            token_end_override = token + 2;
    } else if (strcmp(detail + suffix_offset,
                      "expected ')' after module arguments") == 0) {
        yx_diag_token *tokens = NULL;
        size_t count = 0;
        if (yx_condition_diag_tokens(start, token, &tokens, &count) && count) {
            const yx_diag_token *last = &tokens[count - 1];
            if (last->kind == YX_DIAG_INTEGER ||
                yx_diag_token_is(last, "filesize"))
                expected = "`%`, operator, `of`, expression, `,` or `)`";
            else if (last->kind == YX_DIAG_FLOAT)
                expected = "operator, expression, `,` or `)`";
            else if (last->kind == YX_DIAG_WORD &&
                     *last->start != '$')
                expected = "`(`, `[`, expression, `%`, operator, `of`, `,` or `)`";
        }
        free(tokens);
    } else if (strcmp(detail + suffix_offset, "expected an expression") == 0) {
        if (*token == ')') {
            const char *before = token;
            while (before > start && isspace((unsigned char)before[-1]))
                --before;
            if (before > start && before[-1] == '+') {
                const char *plus = before - 1;
                before = plus;
                while (before > start && isspace((unsigned char)before[-1]))
                    --before;
                if (before > start && before[-1] == ',') {
                    token = plus;
                    expected = "expression or identifier";
                }
            }
        }
        if (*token == '.' || *token == '>' || *token == '<' || *token == ':' ||
            *token == '=' || *token == ',' || *token == ')' ||
            *token == '*' || *token == '+' || *token == '\\' ||
            (unsigned char)*token >= 0x80) {
            if (*token != ')' && yx_condition_after_call_open(start, token))
                expected = "expression, identifier or `)`";
            else
                expected = "expression or identifier";
        }
        else if (isalpha((unsigned char)*token) || *token == '_') {
            const char *end = yx_syntax_token_end(token);
            size_t length = (size_t)(end - token);
            char word[32];
            if (length < sizeof(word)) {
                memcpy(word, token, length);
                word[length] = '\0';
                if (yx_reserved_identifier(word))
                    expected = yx_condition_after_call_open(start, token) ?
                        "expression, identifier or `)`" :
                        "expression or identifier";
            }
        }
    } else if (strcmp(detail + suffix_offset,
                      "expected module member name") == 0 ||
               strcmp(detail + suffix_offset,
                      "expected indexed module field name") == 0 ||
               strcmp(detail + suffix_offset,
                      "expected nested module field name") == 0 ||
               strcmp(detail + suffix_offset,
                      "expected indexed field name") == 0 ||
               strcmp(detail + suffix_offset,
                      "expected indexed global field name") == 0) {
        if (*token) expected = "identifier";
    } else if (strcmp(detail + suffix_offset,
                      "unsupported character '?'") == 0 &&
               *token == '?') {
        expected = yx_condition_after_call_open(start, token) ?
            "expression, identifier or `)`" :
            "expression or identifier";
        if (token[1] == ')') token_end_override = token + 2;
        else if (token[1] == '.') {
            const char *end = token + 2;
            while (*end && !isspace((unsigned char)*end) &&
                   *end != ')' && *end != '}') {
                if (*end++ == ',') {
                    token_end_override = end;
                    break;
                }
            }
        }
    }
    if (strncmp(detail + suffix_offset, "unexpected token '", 18) == 0 &&
        (*token == '"' || *token == '$' || *token == ')' ||
         *token == ':' || *token == '{') &&
        yx_condition_has_module_tail(p, start, token))
        expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
    if (!expected &&
        strncmp(detail + suffix_offset, "unexpected token '", 18) == 0) {
        yx_diag_token *tokens = NULL;
        size_t count = 0, paren_depth = 0;
        if (!yx_condition_diag_tokens(start, token, &tokens, &count))
            return false;
        for (size_t i = 0; i < count; ++i) {
            if (yx_diag_token_is(&tokens[i], "(")) ++paren_depth;
            else if (yx_diag_token_is(&tokens[i], ")") && paren_depth)
                --paren_depth;
        }
        if (count) {
            const yx_diag_token *last = &tokens[count - 1];
            if (yx_diag_token_is(last, "true") ||
                yx_diag_token_is(last, "false"))
                expected = "operator or `}`";
            else if (paren_depth &&
                     (last->kind == YX_DIAG_INTEGER ||
                      yx_diag_token_is(last, "filesize")))
                expected = "operator, `)`, `%`, `of` or expression";
            else if (last->kind == YX_DIAG_INTEGER ||
                     yx_diag_token_is(last, "filesize")) {
                if (count >= 2 &&
                    (yx_diag_token_is(&tokens[count - 2], ">") ||
                     yx_diag_token_is(&tokens[count - 2], "<") ||
                     yx_diag_token_is(&tokens[count - 2], "==") ||
                     yx_diag_token_is(&tokens[count - 2], "=")))
                    expected = "operator, expression or `}`";
                else if (count >= 2 &&
                         (yx_diag_token_is(&tokens[count - 2], "+") ||
                          yx_diag_token_is(&tokens[count - 2], "-") ||
                          yx_diag_token_is(&tokens[count - 2], "*")))
                    expected = "operator, `of`, expression or `}`";
                else
                    expected = "`%`, operator, `of`, expression or `}`";
            }
            else if (!paren_depth && last->kind == YX_DIAG_STRING &&
                     (yx_word_char(*token) || *token == '$'))
                expected = "`%`, operator, `of`, expression or `}`";
            else if (!paren_depth && last->kind == YX_DIAG_WORD &&
                     *last->start == '$')
                expected = "`at`, `in`, operator or `}`";
            else if (!paren_depth && count >= 2 &&
                     last->kind == YX_DIAG_WORD &&
                     yx_diag_token_is(&tokens[count - 2], "."))
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            else if (!paren_depth && last->kind == YX_DIAG_WORD &&
                     *last->start != '$' &&
                     !yx_diag_token_is(last, "and") &&
                     !yx_diag_token_is(last, "or"))
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            else if (paren_depth && last->kind == YX_DIAG_WORD &&
                     *last->start != '$' &&
                     !yx_diag_token_is(last, "and") &&
                     !yx_diag_token_is(last, "or"))
                expected = "`(`, `[`, expression, `%`, operator, `of`, `,` or `)`";
            else if (*token == '=' && last->kind == YX_DIAG_WORD)
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            else if (yx_diag_token_is(last, ")")) {
                size_t depth = 1;
                for (size_t i = count - 1; i > 0; --i) {
                    const yx_diag_token *before = &tokens[i - 1];
                    if (yx_diag_token_is(before, ")")) ++depth;
                    else if (yx_diag_token_is(before, "(") && --depth == 0) {
                        bool dotted_call = i >= 4 &&
                            tokens[i - 2].kind == YX_DIAG_WORD &&
                            yx_diag_token_is(&tokens[i - 3], ".") &&
                            tokens[i - 4].kind == YX_DIAG_WORD;
                        if (dotted_call ||
                            yx_condition_has_module_tail(p, start,
                                                         before->start))
                            expected = "expression, `%`, operator, `of` or `}`";
                        break;
                    }
                }
            } else if (last->kind == YX_DIAG_STRING && *token == '.')
                expected = "operator, expression or `}`";
        }
        free(tokens);
    }
    if (!expected) return false;
    if (*token == '?' && !token_end_override) {
        const char *end = yx_syntax_token_end(token);
        if (*end == '(') {
            const char *argument = end + 1;
            while (isdigit((unsigned char)*argument)) ++argument;
            if (argument > end + 1 && *argument == ',')
                token_end_override = argument + 1;
        }
    }
    if ((unsigned char)*token >= 0x80 && !token_end_override) {
        const char *end = token;
        while (*end && !isspace((unsigned char)*end)) ++end;
        token_end_override = end;
    }
    yx_syntax_expected(p, token,
                       token_end_override ? token_end_override :
                                            yx_syntax_token_end(token),
                       expected);
    return true;
}

static const char *yx_unknown_identifier_search_start(const char *start,
                                                       const char *end,
                                                       const char *name,
                                                       size_t name_length)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    unsigned char *bound = NULL;
    const char *search_start = start;
    if (!yx_condition_diag_tokens(start, end, &tokens, &count)) return start;
    bound = calloc(count ? count : 1, sizeof(*bound));
    if (!bound) { free(tokens); return start; }
    for (size_t i = 1; i + 1 < count; ++i) {
        bool binding_for, binding_with;
        size_t depth = 0, colon = SIZE_MAX, body_depth = 0;
        if (tokens[i].kind != YX_DIAG_WORD ||
            (size_t)(tokens[i].end - tokens[i].start) != name_length ||
            memcmp(tokens[i].start, name, name_length) != 0) continue;
        binding_for = i >= 2 && yx_diag_token_is(&tokens[i - 2], "for") &&
                      yx_diag_token_is(&tokens[i + 1], "in");
        binding_with = yx_diag_token_is(&tokens[i - 1], "with") &&
                       yx_diag_token_is(&tokens[i + 1], "=");
        if (!binding_for && !binding_with) continue;
        bound[i] = 1;
        for (size_t j = i + 2; j < count; ++j) {
            if (yx_diag_token_is(&tokens[j], "(")) ++depth;
            else if (yx_diag_token_is(&tokens[j], ")") && depth) --depth;
            else if (yx_diag_token_is(&tokens[j], ":") && !depth) {
                colon = j;
                break;
            }
        }
        if (colon == SIZE_MAX || colon + 1 >= count ||
            !yx_diag_token_is(&tokens[colon + 1], "(")) continue;
        for (size_t j = colon + 1; j < count; ++j) {
            if (yx_diag_token_is(&tokens[j], "(")) ++body_depth;
            else if (yx_diag_token_is(&tokens[j], ")") &&
                     --body_depth == 0) {
                for (size_t k = colon + 1; k <= j; ++k) bound[k] = 1;
                break;
            }
        }
    }
    for (size_t i = 0; i < count; ++i) {
        if (!bound[i] && tokens[i].kind == YX_DIAG_WORD &&
            (size_t)(tokens[i].end - tokens[i].start) == name_length &&
            memcmp(tokens[i].start, name, name_length) == 0) {
            search_start = tokens[i].start;
            break;
        }
    }
    free(bound);
    free(tokens);
    return search_start;
}

static bool yx_test_proto_method_condition_error(yx_parser *p,
                                                 const char *start,
                                                 const char *detail)
{
    size_t begin, end;
    char function[80];
    if (sscanf(detail, "test proto unknown field:%zu:%zu:%79s",
               &begin, &end, function) == 3 && begin < end &&
        end <= (size_t)(p->at - start)) {
        size_t offset = (size_t)(start - p->begin);
        bool ok = yx_compiler_unknown_module_field_error(p->compiler,
            function, p->begin, p->origin, offset + begin, offset + end) != 0;
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    if (sscanf(detail, "test proto arguments:%zu:%zu:%79s",
               &begin, &end, function) == 3 && begin < end &&
        end <= (size_t)(p->at - start)) {
        const char *arguments = strcmp(function, "add") == 0 ?
            "(float, float)\n(integer, integer)" :
            strcmp(function, "head") == 0 ||
            strcmp(function, "valid_on") == 0 ? "(integer)" :
            strcmp(function, "uppercase") == 0 ||
            strcmp(function, "to_int") == 0 ||
            strcmp(function, "nested_method_with_arg") == 0 ? "(string)" : "()";
        char note[192];
        snprintf(note, sizeof(note), "accepted argument combinations:\n\n%s",
                 arguments);
        size_t offset = (size_t)(start - p->begin);
        bool ok = yx_compiler_wrong_arguments_error(p->compiler, p->begin,
            p->origin, offset + begin, offset + end, note) != 0;
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    if (sscanf(detail, "test proto method span:%zu:%zu", &begin, &end) == 2 &&
        begin < end && end <= (size_t)(p->at - start)) {
        size_t offset = (size_t)(start - p->begin);
        bool ok = yx_compiler_method_binding_error(p->compiler, p->begin,
            p->origin, offset + begin, offset + end) != 0;
        if (ok) p->recoverable_unknown_identifier = true;
        return ok;
    }
    return false;
}

typedef struct {
    yx_parser *parser;
    const char *start;
    /* The condition's own non_bool_expr, raised once it validates. */
    bool root_pending;
    size_t root_start, root_end, root_point;
    const char *root_type;
} yx_type_warning_context;

static bool yx_condition_type_warning(const char *kind,
    size_t start, size_t end, size_t other_start, size_t other_end,
    const char *type, void *user)
{
    yx_type_warning_context *context = user;
    yx_parser *p = context->parser;
    size_t offset = (size_t)(context->start - p->begin);
    if (end > (size_t)(p->at - context->start) ||
        other_end > (size_t)(p->at - context->start)) return false;
    if (strcmp(kind, "non_bool_root") == 0) {
        if (p->pending_slow_loop_error) return true;
        context->root_pending = true;
        context->root_start = start;
        context->root_end = end;
        context->root_point = other_end;
        context->root_type = type;
        return true;
    }
    /* With YRX_ERROR_ON_SLOW_LOOP the first potentially slow loop is the
     * rule's error (E034, reported once the rule is parsed); YARA-X stops
     * compiling the condition there, so later typed warnings are dropped. */
    if (p->pending_slow_loop_error) return true;
    if (strcmp(kind, "potentially_slow_loop") == 0 &&
        (p->compiler->flags & YRX_ERROR_ON_SLOW_LOOP)) {
        p->pending_slow_loop_error = true;
        p->slow_loop_start = offset + start;
        p->slow_loop_end = offset + end;
        return true;
    }
    /* A module function referenced without a call is a function value;
     * its non_bool_expr and E002 come from yx_function_value_error. */
    if (strcmp(kind, "non_bool_expr") == 0)
        for (size_t i = 0; i < sizeof(yx_module_functions) /
                                sizeof(yx_module_functions[0]); ++i)
            if (strlen(yx_module_functions[i].path) == end - start &&
                memcmp(context->start + start, yx_module_functions[i].path,
                       end - start) == 0) return true;
    return yx_compiler_type_warning(p->compiler, p->begin, p->origin,
        kind, offset + start, offset + end,
        offset + other_start, offset + other_end, type) != 0;
}

static bool yx_condition_integer_warning(const char *kind,
    size_t start, size_t end, size_t other_start, size_t other_end,
    const char *type, void *user)
{
    if (strncmp(kind, "unsigned_unary_op:", 18) != 0 &&
        strncmp(kind, "sign_conversion:", 16) != 0) return true;
    return yx_condition_type_warning(kind, start, end, other_start, other_end,
                                     type, user);
}

static bool yx_test_proto_acl_condition_error(yx_parser *p, const char *start,
                                               const char *detail)
{
    static const char prefix[] = "test proto ACL ";
    const char *feature, *title, *label;
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    bool result = false;
    if (strncmp(detail, prefix, sizeof(prefix) - 1) != 0) return false;
    feature = detail + sizeof(prefix) - 1;
    if (strcmp(feature, "foo") == 0) {
        title = "foo is required";
        label = "this field was used without foo";
    } else if (strcmp(feature, "bar") == 0) {
        title = "bar is required";
        label = "this field was used without bar";
    } else if (strcmp(feature, "baz") == 0) {
        title = "baz is forbidden";
        label = "this field was used with baz";
    } else return false;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    for (size_t i = 0; i + 2 < count; ++i)
        if (yx_diag_token_is(&tokens[i], "test_proto2") &&
            yx_diag_token_is(&tokens[i + 1], ".") &&
            yx_diag_token_is(&tokens[i + 2], "requires_foo_and_bar")) {
            result = yx_compiler_custom_error(p->compiler, title, label,
                p->begin, p->origin,
                (size_t)(tokens[i + 2].start - p->begin),
                (size_t)(tokens[i + 2].end - p->begin)) != 0;
            if (result) p->recoverable_unknown_identifier = true;
            break;
        }
    free(tokens);
    return result;
}

static bool yx_vt_condition_error(yx_parser *p, const char *start,
                                  const char *detail)
{
    size_t acl_index = SIZE_MAX;
    bool feature_acl = sscanf(detail, "vt access %zu", &acl_index) == 1 &&
        acl_index < sizeof(yx_vt_acls) / sizeof(yx_vt_acls[0]);
    bool unknown_access = strncmp(detail, "vt unknown '", 12) == 0;
    bool function_access = strncmp(detail, "vt function '", 13) == 0;
    if (feature_acl || unknown_access || function_access) {
        yx_diag_token *tokens = NULL;
        size_t count = 0;
        const char *path = feature_acl ? yx_vt_acls[acl_index].path :
                           strchr(detail, '\'') + 1;
        size_t path_length = feature_acl ? strlen(path) : strcspn(path, "'");
        size_t wanted = path_length;
        yx_vt_type type = YX_VT_STRUCT;
        if (!feature_acl) {
            size_t valid = 2;
            for (size_t f = 0; f < sizeof(yx_vt_fields) / sizeof(yx_vt_fields[0]); ++f) {
                size_t length = strlen(yx_vt_fields[f].path);
                if (length <= path_length && length > valid &&
                    memcmp(path, yx_vt_fields[f].path, length) == 0 &&
                    (length == path_length || path[length] == '.')) {
                    valid = length;
                    type = yx_vt_fields[f].type;
                }
            }
            if (unknown_access && valid < path_length) {
                wanted = valid + 1;
                while (wanted < path_length && path[wanted] != '.') ++wanted;
            }
        }
        const char *alias_path = strstr(detail, "' alias '");
        if (alias_path) {
            const char *canonical = strchr(detail, '\'') + 1;
            size_t canonical_length = strcspn(canonical, "'");
            alias_path += strlen("' alias '");
            size_t alias_length = strcspn(alias_path, "'");
            if (canonical_length >= wanted &&
                canonical_length - wanted <= alias_length) {
                wanted = alias_length - (canonical_length - wanted);
                path = alias_path;
                path_length = alias_length;
            }
        }
        if (!yx_condition_diag_tokens(start, p->at, &tokens, &count))
            return false;
        bool result = false;
        for (size_t i = 0; i < count; ++i) {
            size_t root_length = 0;
            while (root_length < wanted && path[root_length] != '.') ++root_length;
            if ((size_t)(tokens[i].end - tokens[i].start) != root_length ||
                memcmp(tokens[i].start, path, root_length) != 0) continue;
            size_t component = 0, token = i, last = i;
            while (component < wanted && token < count) {
                size_t end = component;
                while (end < wanted && path[end] != '.') ++end;
                if ((size_t)(tokens[token].end - tokens[token].start) !=
                        end - component ||
                    memcmp(tokens[token].start, path + component,
                           end - component) != 0) break;
                last = token;
                component = end;
                if (component == wanted) break;
                if (token + 2 >= count ||
                    !yx_diag_token_is(&tokens[token + 1], ".")) break;
                ++component;
                token += 2;
            }
            if (component != wanted) continue;
            size_t begin = (size_t)(tokens[last].start - p->begin);
            size_t end = (size_t)(tokens[last].end - p->begin);
            if (feature_acl)
                result = yx_compiler_custom_error(p->compiler,
                    yx_vt_acls[acl_index].title, yx_vt_acls[acl_index].label,
                    p->begin, p->origin, begin, end) != 0;
            else if (function_access)
                result = yx_compiler_wrong_type_error(p->compiler,
                    p->begin, p->origin, begin,
                    end, "`function`", type == YX_VT_STRING ? "string" :
                    type == YX_VT_INT ? "integer" :
                    type == YX_VT_BOOL ? "boolean" :
                    type == YX_VT_FLOAT ? "float" : "struct") != 0;
            else {
                char name[128];
                size_t length = (size_t)(tokens[last].end - tokens[last].start);
                if (length >= sizeof(name)) break;
                memcpy(name, tokens[last].start, length);
                name[length] = '\0';
                result = yx_compiler_unknown_module_field_error(p->compiler,
                    name, p->begin, p->origin, begin, end) != 0;
            }
            if (result) p->recoverable_unknown_identifier = true;
            break;
        }
        free(tokens);
        return result;
    }
    static const char acl_net[] = "vt ACL net '";
    static const char acl_metadata[] = "vt ACL metadata '";
    static const char acl_behaviour[] = "vt ACL behaviour '";
    static const char unknown[] = "unknown vt field '";
    static const char enum_struct[] = "vt enum struct '";
    static const char enum_function[] = "vt enum function '";
    const char *path_start;
    const char *field = NULL;
    const char *cursor;
    size_t path_length, field_length;
    bool acl = true, primitive = false, primitive_call = false;

    if (strncmp(detail, acl_net, sizeof(acl_net) - 1) == 0) {
        path_start = detail + sizeof(acl_net) - 1;
        field = "net";
    } else if (strncmp(detail, acl_metadata,
                       sizeof(acl_metadata) - 1) == 0) {
        path_start = detail + sizeof(acl_metadata) - 1;
        field = "metadata";
    } else if (strncmp(detail, acl_behaviour,
                       sizeof(acl_behaviour) - 1) == 0) {
        path_start = detail + sizeof(acl_behaviour) - 1;
        field = "behaviour";
    } else if (strncmp(detail, unknown, sizeof(unknown) - 1) == 0) {
        path_start = detail + sizeof(unknown) - 1;
        acl = false;
    } else if (strncmp(detail, enum_struct,
                       sizeof(enum_struct) - 1) == 0) {
        path_start = detail + sizeof(enum_struct) - 1;
        acl = false;
        primitive = true;
    } else if (strncmp(detail, enum_function,
                       sizeof(enum_function) - 1) == 0) {
        path_start = detail + sizeof(enum_function) - 1;
        acl = false;
        primitive = true;
        primitive_call = true;
    } else {
        return false;
    }
    path_length = strlen(path_start);
    if (path_length < 4 || path_start[path_length - 1] != '\'' ||
        strncmp(path_start, "vt.", 3) != 0)
        return false;
    --path_length;
    if (!acl) {
        /* The enum and message names that lead to the member
         * (`Domain.Permutation.`). */
        const char *member = path_start + 3;
        for (;;) {
            const char *dot = memchr(member, '.',
                (size_t)(path_start + path_length - member));
            if (!dot || !yx_ser_vt_enum_scope(path_start,
                                              (size_t)(dot - path_start)))
                break;
            member = dot + 1;
        }
        field = member;
    }
    field_length = acl ? strlen(field) :
                   path_length - (size_t)(field - path_start);
    if (!acl) {
        const char *dot = memchr(field, '.', field_length);
        if (dot) field_length = (size_t)(dot - field);
    }
    if (!field_length) return false;
    cursor = start;
    while (cursor < p->at) {
        const char *next = yx_condition_skip_noncode(cursor, start, p->at);
        if (next != cursor) { cursor = next; continue; }
        if ((size_t)(p->at - cursor) >= path_length &&
            memcmp(cursor, path_start, path_length) == 0 &&
            (cursor == start ||
             !yx_ident_continue_width_before(start, cursor)) &&
            (cursor + path_length == p->at ||
             !yx_ident_continue_width(cursor + path_length))) {
            const char *label = cursor + (acl ? 3 :
                                         (size_t)(field - path_start));
            char field_name[128];
            int result;
            if (field_length >= sizeof(field_name)) return false;
            memcpy(field_name, field, field_length);
            field_name[field_length] = '\0';
            if (primitive)
                result = yx_compiler_wrong_type_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(label - p->begin),
                    (size_t)(label + field_length - p->begin),
                    primitive_call ? "`function`" : "`struct`", "integer");
            else if (acl)
                result = yx_compiler_vt_acl_error(
                    p->compiler, field_name, p->begin, p->origin,
                    (size_t)(label - p->begin),
                    (size_t)(label + field_length - p->begin));
            else
                result = yx_compiler_unknown_module_field_error(
                    p->compiler, field_name, p->begin, p->origin,
                    (size_t)(label - p->begin),
                    (size_t)(label + field_length - p->begin));
            if (result) p->recoverable_unknown_identifier = true;
            return result != 0;
        }
        ++cursor;
    }
    return false;
}

/* In a condition regexp the lexer stops at the first unescaped slash, even
 * when that slash is inside a character class. The condition parser below is
 * deliberately more permissive while locating the rule's closing brace, so
 * handle the tokens following such a slash before compiling the condition. */
/* The lexer's regexp token ends at the first slash even inside a bracketed
 * class; report the error the full regexp parser finds in that token. */
static int yx_report_class_slash_regexp(yx_parser *p, const char *regexp_start,
                                        const char *closing_slash)
{
    YRX_PATTERN trial;
    const char *suffix = closing_slash + 1;
    int status, reported = 0;
    memset(&trial, 0, sizeof(trial));
    trial.regexp = yx_duplicate(regexp_start + 1,
                                (size_t)(closing_slash - regexp_start - 1));
    if (!trial.regexp) return 0;
    for (unsigned n = 0; n < 2 && (*suffix == 'i' || *suffix == 's');
         ++n, ++suffix)
        trial.modifiers |= *suffix == 'i' ? YX_MOD_NOCASE : YX_MOD_DOTALL;
    status = yx_validate_regex(&trial);
    if (status < 0) {
        size_t errors = p->compiler->error_diagnostic_json ?
            strlen(p->compiler->error_diagnostic_json) : 0;
        reported = yx_report_pattern_regexp_error(p, &trial, regexp_start,
                                                  regexp_start, suffix,
                                                  status) &&
                   p->compiler->error_diagnostic_json &&
                   strlen(p->compiler->error_diagnostic_json) > errors;
    }
    free(trial.regexp);
    return reported;
}

/* Number of parentheses still open in the condition at `stop`. */
static unsigned yx_open_parens_before(const char *start, const char *stop)
{
    unsigned open = 0;
    const char *cursor = start;
    while (cursor < stop) {
        const char *next = yx_condition_skip_noncode(cursor, start, stop);
        if (next != cursor) { cursor = next; continue; }
        if (*cursor == '(') ++open;
        else if (*cursor == ')' && open) --open;
        ++cursor;
    }
    return open;
}

static int yx_condition_class_slash_error(yx_parser *p,
                                          const char *regexp_start,
                                          const char *closing_slash,
                                          bool after_matches,
                                          bool function_argument,
                                          unsigned open_parens)
{
    const char *cursor = closing_slash + 1;
    const char *invalid_modifier = NULL;
    const char *unexpected;
    const char *unexpected_end;
    const char *recovery_at;
    bool unclosed_following_regexp = false;
    const char *expected = after_matches ? "operator, expression or `}`" :
        function_argument ? "`%`, operator, `of`, expression, `,` or `)`" :
                            "`%`, operator, `of`, expression or `}`";
    unsigned modifiers = 0;
    while (modifiers < 2 &&
           (((unsigned char)*cursor >= 'A' &&
             (unsigned char)*cursor <= 'Z') ||
            ((unsigned char)*cursor >= 'a' &&
             (unsigned char)*cursor <= 'z'))) {
        if (*cursor != 'i' && *cursor != 's' && !invalid_modifier)
            invalid_modifier = cursor;
        ++cursor;
        ++modifiers;
    }
    while (isspace((unsigned char)*cursor)) ++cursor;
    unexpected = cursor;
    unexpected_end = yx_syntax_token_end(unexpected);
    if (*unexpected == '/' && unexpected[1] != '/' &&
        unexpected[1] != '*') {
        const char *end = unexpected + 1;
        while (*end && *end != '\n') {
            if (*end == '\\' && end[1] && end[1] != '\n') {
                end += 2;
                continue;
            }
            if (*end == '/') break;
            ++end;
        }
        if (*end == '/') {
            unexpected_end = end + 1;
            for (unsigned flags = 0; flags < 2 &&
                 (((unsigned char)*unexpected_end >= 'A' &&
                   (unsigned char)*unexpected_end <= 'Z') ||
                  ((unsigned char)*unexpected_end >= 'a' &&
                   (unsigned char)*unexpected_end <= 'z')); ++flags)
                ++unexpected_end;
        } else {
            unexpected_end = end;
            unclosed_following_regexp = true;
        }
    }
    /* A `)` closing an open group and a `,` between call arguments are valid
     * continuations: the lexer's regexp token is complete and only the
     * regexp itself is wrong. */
    if (*unexpected == '}' || !*unexpected ||
        (*unexpected == ')' && (function_argument || open_parens)) ||
        (*unexpected == ',' && function_argument)) {
        if (!*unexpected) {
            p->at = unexpected;
            p->recoverable_invalid_regexp = true;
            return yx_syntax_expected(p, unexpected, unexpected, expected);
        }
        if (invalid_modifier) {
            if (!yx_compiler_invalid_regexp_modifier_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(invalid_modifier - p->begin),
                    (size_t)(invalid_modifier + 1 - p->begin)))
                return yx_error(p, "out of memory recording regexp error");
        } else if (!yx_report_class_slash_regexp(p, regexp_start,
                                                   closing_slash)) {
            const char *opening = strchr(regexp_start + 1, '[');
            if (!opening || !yx_compiler_invalid_regexp_error(
                    p->compiler, p->begin, p->origin,
                    (size_t)(opening - p->begin),
                    (size_t)(opening + 1 + (opening[1] == '^' && opening[2] != '-') -
                              p->begin),
                    "unclosed character class", NULL))
                return yx_error(p, "out of memory recording regexp error");
        }
        p->at = unexpected;
        p->recoverable_invalid_regexp = true;
        return 0;
    }
    /* A later slash which has no mate on this line consumes the closing
     * brace as an unknown regexp token. Recovery then reaches end of file. */
    recovery_at = unexpected_end;
    if (unclosed_following_regexp) {
        recovery_at = unexpected_end;
    } else {
        const char *scan = unexpected_end;
        while (*scan && *scan != '\n' && *scan != '}') {
            if (*scan == '/' && scan[1] != '/' && scan[1] != '*') {
                const char *mate = scan + 1;
                while (*mate && *mate != '\n' && *mate != '/') {
                    if (*mate == '\\' && mate[1] && mate[1] != '\n')
                        mate += 2;
                    else
                        ++mate;
                }
                if (*mate != '/') {
                    while (*scan && *scan != '\n') ++scan;
                    recovery_at = scan;
                    break;
                }
                scan = mate + 1;
                continue;
            }
            ++scan;
        }
    }
    if (invalid_modifier &&
        (function_argument == false) && strchr(recovery_at, '}')) {
        if (!yx_compiler_invalid_regexp_modifier_error(
                p->compiler, p->begin, p->origin,
                (size_t)(invalid_modifier - p->begin),
                (size_t)(invalid_modifier + 1 - p->begin)))
            return yx_error(p, "out of memory recording regexp error");
    }
    if (unclosed_following_regexp)
        yx_syntax_label(p, unexpected, unexpected_end,
                        "unclosed regular expression");
    else
        yx_syntax_expected(p, unexpected, unexpected_end, expected);
    p->at = recovery_at;
    p->recoverable_invalid_regexp = true;
    p->unclosed_regexp = unclosed_following_regexp ||
        recovery_at != unexpected_end;
    return 0;
}

static bool yx_condition_open_brace_error(yx_parser *p, const char *start)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    const char *expected = NULL;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    if (!count)
        expected = "expression or identifier";
    else {
        const yx_diag_token *last = &tokens[count - 1];
        if (yx_diag_token_is(last, "."))
            expected = "identifier";
        else if (yx_condition_has_module_tail(p, start, p->at))
            expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
        else if (yx_diag_plain_identifier(last)) {
            size_t depth = 0, open_index = count;
            for (size_t i = count; i > 0; --i) {
                if (yx_diag_token_is(&tokens[i - 1], ")")) ++depth;
                else if (yx_diag_token_is(&tokens[i - 1], "(")) {
                    if (depth) --depth;
                    else { open_index = i - 1; break; }
                }
            }
            if (open_index == count)
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            else if (open_index > 0 &&
                     yx_diag_plain_identifier(&tokens[open_index - 1]))
                expected = "`(`, `[`, expression, `%`, operator, `of`, `,` or `)`";
        }
        else if (yx_diag_token_is(last, "filesize") ||
                 last->kind == YX_DIAG_INTEGER)
            expected = "`%`, operator, `of`, expression or `}`";
        else if (yx_diag_token_is(last, ")"))
            expected = "expression, `%`, operator, `of` or `}`";
        else if (yx_diag_token_is(last, ">") ||
                 yx_diag_token_is(last, "<") ||
                 yx_diag_token_is(last, "+") ||
                 yx_diag_token_is(last, "-") ||
                 yx_diag_token_is(last, "and") ||
                 yx_diag_token_is(last, "or"))
            expected = "expression or identifier";
    }
    free(tokens);
    if (!expected) return false;
    yx_syntax_expected(p, p->at, p->at + 1, expected);
    return true;
}

static bool yx_condition_call_member_error(yx_parser *p, const char *start)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0, depth = 0, open_index = 0;
    const char *next = p->at + 1;
    while (isspace((unsigned char)*next)) ++next;
    if (*next != '>' ||
        !yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    if (!count || !yx_diag_token_is(&tokens[count - 1], ")"))
        goto done;
    for (size_t i = count; i > 0; --i) {
        if (yx_diag_token_is(&tokens[i - 1], ")")) ++depth;
        else if (yx_diag_token_is(&tokens[i - 1], "(") && --depth == 0) {
            open_index = i - 1;
            break;
        }
    }
    if (!depth && open_index > 0 &&
        yx_diag_plain_identifier(&tokens[open_index - 1])) {
        free(tokens);
        yx_syntax_expected(p, next, next + 1, "identifier");
        return true;
    }
done:
    free(tokens);
    return false;
}

/* A new operand directly after a completed call inside an argument list is
 * a syntax error even if the call or its arguments contain unknown names.
 * Diagnose that token before semantic validation can stop at those names. */
static bool yx_adjacent_call_operand_syntax_error(yx_parser *p,
                                                  const char *start)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0, paren_depth = 0;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count)) return false;
    for (size_t i = 0; i < count; ++i) {
        const yx_diag_token *current = &tokens[i];
        if (yx_diag_token_is(current, "(")) { ++paren_depth; continue; }
        if (yx_diag_token_is(current, ")")) {
            if (paren_depth) --paren_depth;
            continue;
        }
        if (i == 0 || !paren_depth ||
            !yx_diag_token_is(&tokens[i - 1], ")") ||
            (current->kind != YX_DIAG_WORD &&
             current->kind != YX_DIAG_INTEGER &&
             current->kind != YX_DIAG_FLOAT &&
             current->kind != YX_DIAG_STRING) ||
            yx_diag_token_is(current, "and") ||
            yx_diag_token_is(current, "or") ||
            yx_diag_token_is(current, "at") ||
            yx_diag_token_is(current, "in") ||
            yx_diag_token_is(current, "of") ||
            yx_diag_token_is(current, "contains") ||
            yx_diag_token_is(current, "matches") ||
            yx_diag_token_is(current, "startswith") ||
            yx_diag_token_is(current, "endswith") ||
            yx_diag_token_is(current, "icontains") ||
            yx_diag_token_is(current, "istartswith") ||
            yx_diag_token_is(current, "iendswith")) continue;
        /* Only an argument list counts: the innermost open parenthesis
         * around the operand must belong to a call. `(for uint8(0) i in
         * ...)` puts the loop variable after a call inside a group. */
        {
            size_t open_depth = 0;
            bool argument_list = false;
            for (size_t j = i; j > 0; --j) {
                if (yx_diag_token_is(&tokens[j - 1], ")")) ++open_depth;
                else if (yx_diag_token_is(&tokens[j - 1], "(")) {
                    if (open_depth) { --open_depth; continue; }
                    argument_list = j >= 2 && tokens[j - 2].kind == YX_DIAG_WORD &&
                                    tokens[j - 2].end == tokens[j - 1].start;
                    break;
                }
            }
            if (!argument_list) continue;
        }
        size_t depth = 0;
        for (size_t j = i; j > 0; --j) {
            if (yx_diag_token_is(&tokens[j - 1], ")")) ++depth;
            else if (yx_diag_token_is(&tokens[j - 1], "(")) {
                if (--depth == 0) {
                    if (j >= 2 &&
                        tokens[j - 2].kind == YX_DIAG_WORD &&
                        tokens[j - 2].end == tokens[j - 1].start) {
                        yx_syntax_expected(p, current->start,
                                           current->end,
                                           "expression, `%`, operator, `of`, `,` or `)`");
                        free(tokens);
                        return true;
                    }
                    break;
                }
            }
        }
    }
    free(tokens);
    return false;
}

static bool yx_pattern_operator_syntax_error(yx_parser *p,
                                             const char *start)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    if (!yx_condition_diag_tokens(start, p->at, &tokens, &count)) return false;
    for (size_t i = 0; i + 1 < count; ++i) {
        if (tokens[i].kind != YX_DIAG_WORD || *tokens[i].start != '$')
            continue;
        const yx_diag_token *op = &tokens[i + 1];
        if (!yx_diag_token_is(op, "<") && !yx_diag_token_is(op, "<=") &&
            !yx_diag_token_is(op, ">") && !yx_diag_token_is(op, ">=") &&
            !yx_diag_token_is(op, "==") && !yx_diag_token_is(op, "!=") &&
            !yx_diag_token_is(op, "+") && !yx_diag_token_is(op, "-") &&
            !yx_diag_token_is(op, "*"))
            continue;
        if (yx_diag_token_is(op, "*") &&
            (i + 2 >= count ||
             yx_diag_token_is(&tokens[i + 2], ")") ||
             yx_diag_token_is(&tokens[i + 2], ",")))
            continue;
        size_t depth = 0;
        size_t open = SIZE_MAX;
        for (size_t j = i; j > 0; --j) {
            if (yx_diag_token_is(&tokens[j - 1], ")")) ++depth;
            else if (yx_diag_token_is(&tokens[j - 1], "(")) {
                if (depth) --depth;
                else { open = j - 1; break; }
            }
        }
        const char *expected = "`at`, `in`, operator or `}`";
        if (open != SIZE_MAX) {
            bool function_call = open > 0 &&
                tokens[open - 1].kind == YX_DIAG_WORD &&
                tokens[open - 1].end == tokens[open].start &&
                !yx_diag_token_is(&tokens[open - 1], "and") &&
                !yx_diag_token_is(&tokens[open - 1], "or");
            expected = function_call ?
                "`at`, `in`, operator, `,` or `)`" :
                "`at`, `in`, operator or `)`";
        }
        yx_syntax_expected(p, op->start, op->end, expected);
        free(tokens);
        return true;
    }
    free(tokens);
    return false;
}

static bool yx_chained_comparison_unknown_identifier_error(
    yx_parser *p, const YRX_RULE *rule, const char *start,
    const char *detail)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    if ((strcmp(detail, "mismatching operand types") != 0 &&
         strncmp(detail, "mismatching types:", 18) != 0 &&
         strncmp(detail, "wrong type span:", 16) != 0) ||
        !yx_condition_diag_tokens(start, p->at, &tokens, &count)) return false;
    yx_condition_symbols symbols = {p, rule};
    /* The second comparison can follow a compound right operand such as a
     * module call. A leading bare identifier still takes precedence over a
     * later operand-type error, as it does for two adjacent identifiers. */
    if (count >= 5 && tokens[0].kind == YX_DIAG_WORD &&
        (yx_diag_token_is(&tokens[1], "<") ||
         yx_diag_token_is(&tokens[1], "<=") ||
         yx_diag_token_is(&tokens[1], ">") ||
         yx_diag_token_is(&tokens[1], ">=") ||
         yx_diag_token_is(&tokens[1], "==") ||
         yx_diag_token_is(&tokens[1], "!="))) {
        size_t nested = 0;
        bool chained = false;
        for (size_t i = 2; i < count; ++i) {
            if (yx_diag_token_is(&tokens[i], "(") ||
                yx_diag_token_is(&tokens[i], "[")) { ++nested; continue; }
            if (yx_diag_token_is(&tokens[i], ")") ||
                yx_diag_token_is(&tokens[i], "]")) {
                if (nested) --nested;
                continue;
            }
            if (nested) continue;
            if (yx_diag_token_is(&tokens[i], "and") ||
                yx_diag_token_is(&tokens[i], "or")) break;
            if (yx_diag_token_is(&tokens[i], "<") ||
                yx_diag_token_is(&tokens[i], "<=") ||
                yx_diag_token_is(&tokens[i], ">") ||
                yx_diag_token_is(&tokens[i], ">=") ||
                yx_diag_token_is(&tokens[i], "==") ||
                yx_diag_token_is(&tokens[i], "!=")) {
                chained = true;
                break;
            }
        }
        if (chained) {
            size_t candidates[] = {0, 2};
            for (size_t i = 0; i < sizeof(candidates) /
                 sizeof(candidates[0]); ++i) {
                const yx_diag_token *operand = &tokens[candidates[i]];
                char name[YX_CONDITION_NAME_SIZE];
                size_t length = (size_t)(operand->end - operand->start);
                if (operand->kind != YX_DIAG_WORD || !length ||
                    length >= sizeof(name) ||
                    !(isalpha((unsigned char)*operand->start) ||
                      *operand->start == '_') ||
                    yx_diag_integer_read_name(operand)) continue;
                memcpy(name, operand->start, length);
                name[length] = '\0';
                if (strcmp(name, "filesize") == 0 ||
                    strcmp(name, "entrypoint") == 0 ||
                    yx_reserved_identifier(name) ||
                    yx_condition_identifier_exists(&symbols, name)) continue;
                if (!yx_compiler_unknown_identifier_error(
                        p->compiler, name, p->begin, p->origin,
                        (size_t)(operand->start - p->begin),
                        (size_t)(operand->end - p->begin))) {
                    free(tokens);
                    return false;
                }
                p->recoverable_unknown_identifier = true;
                free(tokens);
                return true;
            }
        }
    }
    for (size_t i = 0; i + 4 < count; ++i) {
        const yx_diag_token *left = &tokens[i];
        const yx_diag_token *right = &tokens[i + 2];
        if (left->kind != YX_DIAG_WORD || right->kind != YX_DIAG_WORD ||
            (!yx_diag_token_is(&tokens[i + 1], "<") &&
             !yx_diag_token_is(&tokens[i + 1], "<=") &&
             !yx_diag_token_is(&tokens[i + 1], ">") &&
             !yx_diag_token_is(&tokens[i + 1], ">=") &&
             !yx_diag_token_is(&tokens[i + 1], "==") &&
             !yx_diag_token_is(&tokens[i + 1], "!=")) ||
            (!yx_diag_token_is(&tokens[i + 3], "<") &&
             !yx_diag_token_is(&tokens[i + 3], "<=") &&
             !yx_diag_token_is(&tokens[i + 3], ">") &&
             !yx_diag_token_is(&tokens[i + 3], ">=") &&
             !yx_diag_token_is(&tokens[i + 3], "==") &&
             !yx_diag_token_is(&tokens[i + 3], "!="))) continue;
        const yx_diag_token *operands[] = {left, right};
        for (size_t j = 0; j < 2; ++j) {
            const yx_diag_token *operand = operands[j];
            size_t length = (size_t)(operand->end - operand->start);
            char name[YX_CONDITION_NAME_SIZE];
            if (!length || length >= sizeof(name) ||
                !(isalpha((unsigned char)*operand->start) ||
                  *operand->start == '_')) continue;
            memcpy(name, operand->start, length);
            name[length] = '\0';
            if (strcmp(name, "filesize") == 0 ||
                strcmp(name, "entrypoint") == 0 ||
                yx_reserved_identifier(name) ||
                yx_condition_identifier_exists(&symbols, name)) continue;
            if (!yx_compiler_unknown_identifier_error(
                    p->compiler, name, p->begin, p->origin,
                    (size_t)(operand->start - p->begin),
                    (size_t)(operand->end - p->begin))) {
                free(tokens);
                return false;
            }
            p->recoverable_unknown_identifier = true;
            free(tokens);
            return true;
        }
    }
    free(tokens);
    return false;
}

/* Unknown calls can stop the expression parser before it reaches a missing
 * closing parenthesis. When a comparison inside an unfinished call ends at
 * the rule brace, the source syntax error takes precedence. */
static bool yx_unclosed_call_comparison_syntax_error(yx_parser *p,
                                                     const char *start,
                                                     const char *detail)
{
    yx_diag_token *tokens = NULL;
    size_t count = 0, unmatched_closes = 0;
    bool unmatched_call = false;
    if (*p->at != '}' || !strstr(detail, "unsupported function '") ||
        !yx_condition_diag_tokens(start, p->at, &tokens, &count))
        return false;
    if (count < 3 ||
        (tokens[count - 1].kind != YX_DIAG_INTEGER &&
         tokens[count - 1].kind != YX_DIAG_FLOAT) ||
        !(yx_diag_token_is(&tokens[count - 2], "<") ||
          yx_diag_token_is(&tokens[count - 2], "<=") ||
          yx_diag_token_is(&tokens[count - 2], ">") ||
          yx_diag_token_is(&tokens[count - 2], ">=") ||
          yx_diag_token_is(&tokens[count - 2], "==") ||
          yx_diag_token_is(&tokens[count - 2], "!="))) {
        free(tokens);
        return false;
    }
    for (size_t i = count; i > 0; --i) {
        if (yx_diag_token_is(&tokens[i - 1], ")")) ++unmatched_closes;
        else if (yx_diag_token_is(&tokens[i - 1], "(")) {
            if (unmatched_closes) --unmatched_closes;
            else if (i >= 2 &&
                     tokens[i - 2].kind == YX_DIAG_WORD &&
                     tokens[i - 2].end == tokens[i - 1].start) {
                unmatched_call = true;
                break;
            }
        }
    }
    free(tokens);
    if (!unmatched_call) return false;
    yx_syntax_expected(p, p->at, p->at + 1,
                       "operator, expression, `,` or `)`");
    return true;
}

/* The input ends inside a condition: after an operator or an opening
 * delimiter YARA-X expects an operand, and inside an unclosed `(` or `[`
 * the closing delimiter takes the place of the rule's `}`. */
static const char *yx_condition_eof_expected(const yx_diag_token *tokens,
                                             size_t count,
                                             const char *expected)
{
    static const char *const operand_before[] = {
        "(", "[", ",", "not", "~", "..", "defined", "==", "!=", "<=", ">=",
        "=", "in", "of", "at", "\\", "%", "&", "|", "^", "<<", ">>",
        "contains", "icontains", "startswith", "istartswith", "endswith",
        "iendswith", "iequals", "matches"
    };
    const yx_diag_token *last = &tokens[count - 1];
    size_t stack[64], depth = 0, opener, closed = SIZE_MAX;
    bool call, range = false;
    for (size_t i = 0; i < count; ++i) {
        if (yx_diag_token_is(&tokens[i], "(") ||
            yx_diag_token_is(&tokens[i], "[")) {
            if (depth == sizeof(stack) / sizeof(*stack)) return expected;
            stack[depth++] = i;
        } else if ((yx_diag_token_is(&tokens[i], ")") ||
                    yx_diag_token_is(&tokens[i], "]")) && depth) {
            closed = stack[--depth];
        }
    }
    if (yx_diag_token_is(last, "(") && count >= 2 &&
        (yx_diag_plain_identifier(&tokens[count - 2]) ||
         yx_diag_token_is(&tokens[count - 2], ":")))
        return "expression, identifier or `)`";
    if ((yx_diag_token_is(last, "(") || yx_diag_token_is(last, ",")) &&
        depth && stack[depth - 1] &&
        yx_diag_token_is(&tokens[stack[depth - 1] - 1], "of"))
        return "pattern identifier, expression or identifier";
    if (yx_diag_token_is(last, ":")) return "`(`";
    if (yx_diag_token_is(last, "%")) return "`of`, expression or identifier";
    if (yx_diag_token_is(last, ")") && closed != SIZE_MAX && closed &&
        yx_diag_token_is(&tokens[closed - 1], "in")) {
        for (size_t i = closed - 1; i-- > 0;) {
            if (yx_diag_token_is(&tokens[i], ":")) break;
            if (yx_diag_token_is(&tokens[i], "for")) return "`:`";
        }
    }
    if (!depth && yx_diag_token_is(last, "]") && closed != SIZE_MAX &&
        closed && yx_diag_plain_identifier(&tokens[closed - 1]))
        return "expression, `%`, operator, `of` or `}`";
    for (size_t i = 0; i < sizeof(operand_before) / sizeof(*operand_before); ++i)
        if (yx_diag_token_is(last, operand_before[i]))
            return "expression or identifier";
    if (yx_diag_token_is(last, "-") &&
        (count == 1 || tokens[count - 2].kind == YX_DIAG_SYMBOL))
        return "expression or identifier";
    if (!depth) return expected;
    opener = stack[depth - 1];
    if (*tokens[opener].start == '[')
        return last->kind == YX_DIAG_INTEGER || strcmp(expected, "operator or `}`") == 0 ?
               "operator or `]`" : expected;
    call = opener && yx_diag_plain_identifier(&tokens[opener - 1]);
    for (size_t i = opener + 1; i < count; ++i)
        if (yx_diag_token_is(&tokens[i], "..")) range = true;
    if (last->kind == YX_DIAG_INTEGER && call)
        return "`%`, operator, `of`, expression, `,` or `)`";
    if (last->kind == YX_DIAG_INTEGER && opener && !range &&
        yx_diag_token_is(&tokens[opener - 1], "in"))
        return "operator, `.`, `,` or `)`";
    if (last->kind == YX_DIAG_INTEGER && opener && range &&
        yx_diag_token_is(&tokens[opener - 1], "in"))
        return "operator or `)`";
    if (last->kind == YX_DIAG_WORD && *last->start == '$' && opener &&
        yx_diag_token_is(&tokens[opener - 1], "of"))
        return "`*`, `,`, `)` or operator";
    if (last->kind == YX_DIAG_STRING || last->kind == YX_DIAG_FLOAT ||
        strcmp(expected, "`%`, operator, `of`, expression or `}`") == 0)
        return "operator, `)`, `%`, `of` or expression";
    if (strcmp(expected, "operator or `}`") == 0) return "operator or `)`";
    if (strcmp(expected, "operator, expression or `}`") == 0)
        return "operator, expression or `)`";
    if (strcmp(expected, "operator, `of`, expression or `}`") == 0)
        return "operator, `)`, `of` or expression";
    if (strcmp(expected, "`(`, `[`, expression, `%`, operator, `of` or `}`") == 0)
        return "`(`, `[`, expression, operator, `)`, `%` or `of`";
    return expected;
}
static int yx_parse_condition_in_scope(yx_parser *p, YRX_RULE *rule)
{
    yx_space(p);
    const char *start = p->at;
    const char *first_closed_value_slash = NULL;
    const char *first_exponent_suffix = NULL;
    size_t nested_braces = 0;
    while (*p->at) {
        if (p->at[0] == '/' && p->at[1] == '*') {
            p->at += 2;
            while (*p->at && !(p->at[0] == '*' && p->at[1] == '/')) ++p->at;
            if (!*p->at) return yx_error(p, "unterminated comment in condition");
            p->at += 2;
        } else if (p->at[0] == '/' && p->at[1] == '/') {
            p->at += 2;
            while (*p->at && *p->at != '\n') ++p->at;
        } else if (*p->at == '"') {
            const char *quote = p->at;
            ++p->at;
            while (*p->at && *p->at != '"' && *p->at != '\n') {
                if (*p->at == '\\' && p->at[1] && p->at[1] != '\n') ++p->at;
                ++p->at;
            }
            if (*p->at != '"') {
                /* A literal string cannot span lines. */
                const char *end = p->at;
                if (*end == '\n' && end > quote + 1 && end[-1] == '\r') --end;
                yx_syntax_label(p, quote, end, "unclosed literal string");
                return 0;
            }
            ++p->at;
        } else if (*p->at == '/') {
            /* The lexer treats a slash as the start of a regexp literal even
             * where the condition grammar will later reject that literal.
             * Scan it before locating the rule's closing brace so an
             * unterminated regexp reports the same source span. */
            const char *regexp_start = p->at;
            bool in_class = false;
            bool unclosed_line = false;
            const char *word_end = p->at;
            const char *word_start;
            bool after_numeric_value;
            while (word_end > start && isspace((unsigned char)word_end[-1]))
                --word_end;
            word_start = word_end;
            while (word_start > start && isalpha((unsigned char)word_start[-1]))
                --word_start;
            after_numeric_value = word_end > start &&
                (isdigit((unsigned char)word_end[-1]) ||
                 ((size_t)(word_end - word_start) == 8 &&
                  memcmp(word_start, "filesize", 8) == 0 &&
                  (word_start == start ||
                   !yx_ident_continue_width_before(start, word_start))));
            if ((size_t)(word_end - word_start) != 7 ||
                memcmp(word_start, "matches", 7) != 0) {
                /* Keep the ordinary condition diagnostic for a closed
                 * regexp in an invalid expression. The lexer still owns
                 * the unclosed case, including a slash after arithmetic. */
                const char *end = p->at + 1;
                bool in_candidate_class = false;
                while (*end && *end != '\n') {
                    if (*end == '\\' && end[1]) { end += 2; continue; }
                    if (*end == '[') in_candidate_class = true;
                    else if (*end == ']') in_candidate_class = false;
                    if (after_numeric_value) in_candidate_class = false;
                    if (*end == '/' && in_candidate_class) {
                        bool function_argument = word_end > start &&
                            (word_end[-1] == '(' || word_end[-1] == ',');
                        return yx_condition_class_slash_error(
                            p, regexp_start, end, false, function_argument,
                            yx_open_parens_before(start, regexp_start));
                    }
                    if (*end == '/' && !in_candidate_class) break;
                    ++end;
                }
                if (*end == '/') {
                    const char *suffix = end + 1;
                    bool regexp_operand = word_end == start ||
                        (word_end > start &&
                         (word_end[-1] == '(' || word_end[-1] == ',' ||
                          word_end[-1] == '+' || word_end[-1] == '-' ||
                          word_end[-1] == '*')) ||
                        ((size_t)(word_end - word_start) == 3 &&
                         memcmp(word_start, "not", 3) == 0);
                    if (regexp_operand) {
                        for (unsigned flags = 0; flags < 2 &&
                             (*suffix == 'i' || *suffix == 's'); ++flags)
                            ++suffix;
                        if (isalpha((unsigned char)*suffix)) {
                            if (yx_compiler_invalid_regexp_modifier_error(
                                    p->compiler, p->begin, p->origin,
                                    (size_t)(suffix - p->begin),
                                    (size_t)(suffix + 1 - p->begin)))
                                p->recoverable_invalid_regexp = true;
                            return 0;
                        }
                    }
                    if (after_numeric_value && !first_closed_value_slash)
                        first_closed_value_slash = regexp_start;
                    p->at = end + 1;
                    continue;
                }
            }
            ++p->at;
            while (*p->at) {
                if (*p->at == '\n') { unclosed_line = true; break; }
                if (*p->at == '\\' && p->at[1]) { p->at += 2; continue; }
                if (*p->at == '[') in_class = true;
                else if (*p->at == ']') in_class = false;
                else if (*p->at == '/') {
                    if (in_class) {
                        bool after_matches =
                            (size_t)(word_end - word_start) == 7 &&
                            memcmp(word_start, "matches", 7) == 0;
                        bool function_argument =
                            word_end > start &&
                            (word_end[-1] == '(' || word_end[-1] == ',');
                        return yx_condition_class_slash_error(
                            p, regexp_start, p->at,
                            after_matches, function_argument,
                            yx_open_parens_before(start, regexp_start));
                    }
                    break;
                }
                ++p->at;
            }
            if (!*p->at || unclosed_line) {
                if (first_closed_value_slash) {
                    char detail[96];
                    snprintf(detail, sizeof(detail),
                             "at byte %zu: unexpected token '/'",
                             (size_t)(first_closed_value_slash - start));
                    if (yx_condition_syntax_error(p, start, detail)) {
                        p->recoverable_invalid_regexp = true;
                        p->unclosed_regexp = true;
                        return 0;
                    }
                }
                if (in_class) {
                    const char *opening = strchr(regexp_start + 1, '[');
                    if (opening && yx_compiler_invalid_regexp_error(
                            p->compiler, p->begin, p->origin,
                            (size_t)(opening - p->begin),
                            (size_t)(opening - p->begin) + 1 +
                                (opening[1] == '^' && opening[2] != '-'),
                            "unclosed character class", NULL)) {
                        p->recoverable_invalid_regexp = true;
                        return 0;
                    }
                }
                p->recoverable_invalid_regexp = true;
                p->unclosed_regexp = true;
                if (first_exponent_suffix &&
                    yx_exponent_notation_syntax_error(
                        p, start, first_exponent_suffix)) return 0;
                return yx_syntax_label(p, regexp_start, p->at,
                                       "unclosed regular expression");
            }
            ++p->at;
            const char *suffix = p->at;
            for (unsigned flags = 0;
                 flags < 2 && (*suffix == 'i' || *suffix == 's');
                 ++flags) ++suffix;
            if (isalpha((unsigned char)*suffix)) {
                if (yx_compiler_invalid_regexp_modifier_error(
                        p->compiler, p->begin, p->origin,
                        (size_t)(suffix - p->begin),
                        (size_t)(suffix + 1 - p->begin)))
                    p->recoverable_invalid_regexp = true;
                return 0;
            }
            int escape_issue = yx_report_regex_escape_issue(
                p, regexp_start + 1,
                (size_t)(p->at - regexp_start - 2));
            if (escape_issue != 0) {
                if (escape_issue < 0)
                    yx_error(p, "out of memory recording regexp error");
                return 0;
            }
        } else if (*p->at == '{') {
            if (yx_condition_open_brace_error(p, start)) {
                if (!strchr(p->at + 1, '}')) {
                    const char *end = p->begin + strlen(p->begin);
                    yx_syntax_expected(p, end, end, "`}`");
                }
                return 0;
            }
            ++nested_braces;
            ++p->at;
        } else if (*p->at == '}') {
            if (!nested_braces) break;
            --nested_braces;
            ++p->at;
        } else if (*p->at == '.' &&
                   yx_condition_call_member_error(p, start)) {
            return 0;
        } else {
            if (!first_exponent_suffix &&
                (*p->at == 'e' || *p->at == 'E') &&
                yx_exponent_suffix(start, p->at))
                first_exponent_suffix = p->at;
            ++p->at;
        }
    }
    if (*p->at != '}') {
        const char *expected = "operator or `}`";
        yx_diag_token *tokens = NULL;
        size_t count = 0;
        char *fragment = yx_duplicate(start, (size_t)(p->at - start));
        if (fragment) {
            char detail[YX_CONDITION_DETAIL_SIZE] = {0};
            yx_condition *condition =
                yx_condition_compile(fragment, detail, sizeof(detail));
            if (condition) yx_condition_destroy(condition);
            if (!condition && yx_condition_syntax_error(p, start, detail)) {
                free(fragment);
                return yx_syntax_expected(p, p->at, p->at, "`}`");
            }
            free(fragment);
        }
        bool tokenized = yx_condition_diag_tokens(start, p->at, &tokens, &count);
        if (tokenized && count) {
            const yx_diag_token *last = &tokens[count - 1];
            if (count >= 3 &&
                (last->kind == YX_DIAG_WORD ||
                 last->kind == YX_DIAG_INTEGER ||
                 yx_diag_token_is(last, "?")) &&
                (tokens[count - 2].kind == YX_DIAG_INTEGER ||
                 tokens[count - 2].kind == YX_DIAG_FLOAT) &&
                (yx_diag_token_is(&tokens[count - 3], ">") ||
                 yx_diag_token_is(&tokens[count - 3], "<") ||
                 yx_diag_token_is(&tokens[count - 3], ">=") ||
                 yx_diag_token_is(&tokens[count - 3], "<="))) {
                yx_syntax_expected(p, last->start, last->end,
                                   "operator, expression or `}`");
                expected = "`}`";
            }
            if (count >= 2 && yx_diag_token_is(last, "-") &&
                tokens[count - 2].kind == YX_DIAG_WORD &&
                *tokens[count - 2].start == '$') {
                yx_syntax_expected(p, last->start, last->end,
                                   "`at`, `in`, operator or `}`");
                expected = "`}`";
            }
            if (count >= 2 &&
                (yx_diag_token_is(last, "and") ||
                 yx_diag_token_is(last, "or"))) {
                expected = "expression or identifier";
            } else if (count >= 2 &&
                       (yx_diag_token_is(last, "+") ||
                        yx_diag_token_is(last, "-") ||
                        yx_diag_token_is(last, "*") ||
                        yx_diag_token_is(last, ">") ||
                        yx_diag_token_is(last, "<"))) {
                const yx_diag_token *previous = &tokens[count - 2];
                if (previous->kind == YX_DIAG_INTEGER ||
                    previous->kind == YX_DIAG_FLOAT ||
                    (previous->kind == YX_DIAG_WORD &&
                     *previous->start != '$' &&
                     !yx_diag_token_is(previous, "true") &&
                     !yx_diag_token_is(previous, "false")) ||
                    yx_diag_token_is(previous, ")") ||
                    yx_diag_token_is(previous, "]") ||
                    previous->kind == YX_DIAG_STRING)
                    expected = "expression or identifier";
                else
                    expected = "`}`";
            } else if (last->kind == YX_DIAG_INTEGER ||
                yx_diag_token_is(last, "filesize")) {
                if (count >= 2 &&
                    (yx_diag_token_is(&tokens[count - 2], ">") ||
                     yx_diag_token_is(&tokens[count - 2], "<") ||
                     yx_diag_token_is(&tokens[count - 2], "==") ||
                     yx_diag_token_is(&tokens[count - 2], "=")))
                    expected = "operator, expression or `}`";
                else if (count >= 2 &&
                         (yx_diag_token_is(&tokens[count - 2], "+") ||
                          yx_diag_token_is(&tokens[count - 2], "-") ||
                          yx_diag_token_is(&tokens[count - 2], "*")))
                    expected = "operator, `of`, expression or `}`";
                else
                    expected = "`%`, operator, `of`, expression or `}`";
            } else if (last->kind == YX_DIAG_FLOAT) {
                expected = "operator, expression or `}`";
            } else if (last->kind == YX_DIAG_WORD &&
                       yx_condition_has_module_tail(p, start, p->at)) {
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            } else if (count >= 2 && last->kind == YX_DIAG_WORD &&
                       yx_diag_token_is(&tokens[count - 2], ".")) {
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            } else if (yx_diag_token_is(last, "entrypoint")) {
                expected = "`%`, operator, `of`, expression or `}`";
            } else if (yx_diag_plain_identifier(last)) {
                expected = "`(`, `[`, expression, `%`, operator, `of` or `}`";
            }
            if (!*p->at)
                expected = yx_condition_eof_expected(tokens, count, expected);
        } else if (!*p->at && tokenized) {
            expected = "expression or identifier";
        }
        free(tokens);
        return yx_syntax_expected(p, p->at, p->at, expected);
    }
    rule->condition_text = yx_duplicate(start, (size_t)(p->at - start));
    if (!rule->condition_text) return yx_error(p, "out of memory");
    if (yx_pattern_operator_syntax_error(p, start)) return 0;
    int ignored = yx_compiler_skip_ignored_rule(
        p->compiler, rule->condition_text, rule->identifier,
        rule->namespace_name, p->begin, p->origin,
        (size_t)(start - p->begin));
    if (ignored < 0) return 0;
    if (ignored) { ++p->at; return 2; }
    if (yx_adjacent_call_operand_syntax_error(p, start)) return 0;
    char detail[YX_CONDITION_DETAIL_SIZE] = {0};
    yx_condition *failed_condition = NULL;
    yx_condition_relaxed_regexps = (p->compiler->flags & YRX_RELAXED_RE_SYNTAX) != 0;
    rule->condition = yx_condition_compile_diagnostics(rule->condition_text,
        detail, sizeof(detail), &failed_condition);
    yx_condition_relaxed_regexps = false;
    if (failed_condition) {
        yx_type_warning_context context = {p, start, false, 0, 0, 0, NULL};
        const YRX_RULES *warning_rules = p->compiler->rules;
        bool warning_ok = yx_condition_visit_type_warnings(failed_condition,
            (const char *const *)warning_rules->imports, warning_rules->import_count,
            warning_rules, rule->namespace_index, &p->compiler->rule_name_cache,
            yx_condition_integer_warning, &context);
        yx_condition_destroy(failed_condition);
        if (!warning_ok) return yx_error(p, "out of memory recording type warning");
    }
    if (yx_boolean_comparison_syntax_error(p, start, detail,
                                           rule->condition != NULL)) return 0;
    if (!rule->condition) {
        size_t failure_offset = SIZE_MAX, error_end;
        size_t error_mark = p->compiler->error_diagnostic_json ?
            strlen(p->compiler->error_diagnostic_json) : 0;
        if (first_exponent_suffix &&
            sscanf(detail, "at byte %zu:", &failure_offset) == 1 &&
            failure_offset ==
                (size_t)(first_exponent_suffix - start) &&
            yx_exponent_notation_syntax_error(
                p, start, first_exponent_suffix)) goto condition_failed;
        if (yx_unclosed_call_comparison_syntax_error(p, start, detail))
            goto condition_failed;
        if (strstr(detail, "unexpected end of condition") && *p->at == '}')
            return yx_syntax_expected(p, p->at, p->at + 1,
                                      "expression or identifier");
        if (yx_folded_number_out_of_range_error(p, start, detail)) goto condition_failed;
        /* A closed pair of slashes is one regexp token to YARA-X's lexer.
         * If an earlier integer literal overflows, the grammar reports that
         * token before the integer diagnostic. */
        if (first_closed_value_slash &&
            strstr(detail, "integer literal overflows")) {
            const char *invalid_start, *invalid_end;
            if (yx_invalid_integer_condition_span(
                    start, first_closed_value_slash,
                    &invalid_start, &invalid_end)) {
                char syntax_detail[96];
                snprintf(syntax_detail, sizeof(syntax_detail),
                         "at byte %zu: unexpected token '/'",
                         (size_t)(first_closed_value_slash - start));
                if (yx_condition_syntax_error(p, start, syntax_detail))
                    goto condition_failed;
            }
        }
        if (yx_invalid_integer_condition_error(p, start, detail)) goto condition_failed;
        if (yx_invalid_escape_condition_error(p, start, detail)) goto condition_failed;
        if (yx_condition_regexp_error(p, start, detail)) goto condition_failed;
        if (yx_pattern_set_filter_condition_error(p, start, detail)) goto condition_failed;
        if (yx_anonymous_pattern_condition_error(p, start, detail)) goto condition_failed;
        if (yx_wrong_type_condition_error(p, start, detail)) goto condition_failed;
        if (yx_hash_digest_integer_comparison_error(p, rule, start, detail))
            goto condition_failed;
        if (yx_mismatching_types_condition_error(p, start, detail)) goto condition_failed;
        if (yx_assignment_mismatch_condition_error(p, start, detail)) goto condition_failed;
        if (yx_unknown_function_condition_error(p, rule, start, detail)) goto condition_failed;
        if (yx_unexpected_negative_condition_error(p, start, detail)) goto condition_failed;
        if (yx_test_proto_acl_condition_error(p, start, detail)) goto condition_failed;
        if (yx_test_proto_method_condition_error(p, start, detail)) goto condition_failed;
        if (yx_vt_condition_error(p, start, detail)) goto condition_failed;
        if (yx_vt_module_value_condition_error(p, start, detail)) goto condition_failed;
        if (yx_unknown_module_condition_error(p, start, detail)) goto condition_failed;
        if (yx_unknown_pattern_condition_error(p, start, detail)) goto condition_failed;
        if (yx_empty_pattern_set_condition_error(p, start, detail)) goto condition_failed;
        if (yx_condition_syntax_error(p, start, detail)) goto condition_failed;
        return yx_error(p, detail[0] ? detail : "invalid condition");
condition_failed:
        if (yx_compiler_semantic_error_end(p->compiler, error_mark, &error_end) &&
            !yx_compiler_warn_deprecated_before(
                p->compiler, rule->condition_text, p->begin, p->origin,
                (size_t)(start - p->begin), error_end,
                p->compiler->warning_count))
            return yx_error(p, "out of memory recording deprecated field");
        return 0;
    }
    size_t first_type_warning = p->compiler->warning_count, first_of_warning;
    yx_type_warning_context warning_context = {p, start, false, 0, 0, 0, NULL};
    const YRX_RULES *warning_rules = p->compiler->rules;
    p->compiler->warning_point_count = 0;
    bool warning_ok = yx_condition_visit_type_warnings(rule->condition,
            (const char *const *)warning_rules->imports, warning_rules->import_count,
            warning_rules, rule->namespace_index, &p->compiler->rule_name_cache,
            yx_condition_type_warning, &warning_context);
    if (!warning_ok) return yx_error(p, "out of memory recording type warning");
    const char *bare_end = p->at;
    while (bare_end > start && isspace((unsigned char)bare_end[-1]))
        --bare_end;
    for (size_t i = 0; i < p->compiler->rules->import_count; ++i) {
        const char *module = p->compiler->rules->imports[i];
        size_t length = strlen(module);
        if ((size_t)(bare_end - start) != length ||
            memcmp(start, module, length) != 0) continue;
        if (!yx_compiler_wrong_type_error(
                p->compiler, p->begin, p->origin,
                (size_t)(start - p->begin),
                (size_t)(bare_end - p->begin),
                "`bool`", "a struct"))
            return yx_error(p, "out of memory recording module type error");
        p->recoverable_unknown_identifier = true;
        return 0;
    }
    const char **pattern_names = NULL;
    if (rule->pattern_count) {
        if (rule->pattern_count > SIZE_MAX / sizeof(*pattern_names))
            return yx_error(p, "too many patterns");
        pattern_names = malloc(rule->pattern_count * sizeof(*pattern_names));
        if (!pattern_names) return yx_error(p, "out of memory");
        for (size_t i = 0; i < rule->pattern_count; ++i)
            pattern_names[i] = rule->patterns[i].identifier;
    }
    yx_condition_symbols symbols = {p, rule};
    size_t converted_end = 0;
    bool valid = yx_condition_validate(rule->condition, pattern_names,
                                       rule->pattern_count,
                                       (const char *const *)p->compiler->rules->imports,
                                       p->compiler->rules->import_count,
                                       (const char *const *)p->compiler->enabled_features,
                                       p->compiler->enabled_feature_count,
                                       p->compiler->rules->globals,
                                       p->compiler->rules->global_count,
                                       yx_condition_identifier_exists,
                                       &symbols, detail, sizeof(detail),
                                       &converted_end);
    free(pattern_names);
    if (!valid) {
        static const char prefix[] = "unknown identifier '";
        size_t error_start, error_end, error_mark = p->compiler->error_diagnostic_json ?
            strlen(p->compiler->error_diagnostic_json) : 0;
        static const char unused_prefix[] = "unused pattern '";
        size_t name_length;
        char *name;
        const char *cursor;
        {
            size_t begin, end;
            char identifier[YX_CONDITION_NAME_SIZE];
            if (sscanf(detail, "unknown identifier span:%zu:%zu:%4095s",
                       &begin, &end, identifier) == 3 && begin < end &&
                end <= (size_t)(p->at - start)) {
                size_t offset = (size_t)(start - p->begin);
                if (!yx_compiler_unknown_identifier_error(p->compiler,
                        identifier, p->begin, p->origin,
                        offset + begin, offset + end))
                    return yx_error(p, "out of memory recording identifier");
                p->recoverable_unknown_identifier = true;
                goto validation_failed;
            }
        }
        if (strncmp(detail, unused_prefix, sizeof(unused_prefix) - 1) == 0) {
            const char *unused_name = detail + sizeof(unused_prefix) - 1;
            size_t length = strlen(unused_name);
            if (length && unused_name[length - 1] == '\'') {
                for (size_t i = 0; i < rule->pattern_count; ++i) {
                    const YRX_PATTERN *pattern = &rule->patterns[i];
                    if (strlen(pattern->identifier) == length - 1 &&
                        memcmp(pattern->identifier, unused_name,
                               length - 1) == 0) {
                        /* YARA-X checks for unused patterns after the
                         * whole condition: its own non_bool_expr and
                         * invariant_expr come first. */
                        if (warning_context.root_pending &&
                            !yx_condition_type_warning("non_bool_expr",
                                warning_context.root_start,
                                warning_context.root_end, 0,
                                warning_context.root_point,
                                warning_context.root_type, &warning_context))
                            return yx_error(p, "out of memory recording type warning");
                        warning_context.root_pending = false;
                        if (!yx_compiler_warn_invariant_condition(
                                p->compiler, rule->condition_text,
                                rule, p->begin, p->origin,
                                (size_t)(start - p->begin), first_type_warning)) return 0;
                        if (!yx_condition_warn_too_many_iterations(p, rule, start, NULL))
                            return yx_error(p, "out of memory recording loop warning");
                        first_of_warning = p->compiler->warning_count;
                        if (!yx_condition_warn_ambiguous_zero_of(p, rule, start, SIZE_MAX))
                            return yx_error(p, "out of memory recording expression warning");
                        if (!yx_condition_warn_unsatisfiable_at(p, rule, start, SIZE_MAX))
                            return yx_error(p, "out of memory recording expression warning");
                        yx_order_of_warnings(p->compiler, first_type_warning,
                                             first_of_warning);
                        if (!yx_condition_warn_overlapping_pattern_sets(p, rule, start))
                            return yx_error(p, "out of memory recording pattern-set warning");
                        if (!yx_compiler_unused_pattern_error(
                                p->compiler, pattern->identifier,
                                p->begin, p->origin,
                                pattern->declaration_start,
                                pattern->declaration_end))
                            return yx_error(p, "out of memory recording unused pattern");
                        p->recoverable_unknown_identifier = true;
                        return 0;
                    }
                }
            }
        }
        if (yx_unexpected_negative_condition_error(p, start, detail)) goto validation_failed;
        if (yx_folded_number_out_of_range_error(p, start, detail)) goto validation_failed;
        if (yx_number_out_of_range_condition_error(p, start, detail)) goto validation_failed;
        if (yx_invalid_range_condition_error(p, start, detail)) goto validation_failed;
        if (yx_too_many_variables_condition_error(p, start, detail)) goto validation_failed;
        if (yx_anonymous_pattern_condition_error(p, start, detail)) goto validation_failed;
        if (yx_pattern_set_filter_condition_error(p, start, detail)) goto validation_failed;
        if (yx_known_function_arguments_error(p, start, detail)) goto validation_failed;
        if (yx_chained_comparison_unknown_identifier_error(
                p, rule, start, detail)) goto validation_failed;
        if (yx_function_alias_value_condition_error(p, start, detail)) goto validation_failed;
        if (yx_wrong_type_condition_error(p, start, detail)) goto validation_failed;
        if (yx_hash_digest_integer_comparison_error(p, rule, start, detail))
            goto validation_failed;
        if (yx_mismatching_types_condition_error(p, start, detail)) goto validation_failed;
        if (yx_assignment_mismatch_condition_error(p, start, detail)) goto validation_failed;
        if (yx_test_proto_acl_condition_error(p, start, detail)) goto validation_failed;
        if (yx_test_proto_method_condition_error(p, start, detail)) goto validation_failed;
        if (yx_vt_condition_error(p, start, detail)) goto validation_failed;
        if (yx_vt_module_value_condition_error(p, start, detail)) goto validation_failed;
        if (yx_unknown_module_condition_error(p, start, detail)) goto validation_failed;
        if (yx_unknown_pattern_condition_error(p, start, detail)) goto validation_failed;
        if (yx_empty_pattern_set_condition_error(p, start, detail)) goto validation_failed;
        if (strncmp(detail, prefix, sizeof(prefix) - 1) != 0)
            return yx_error(p, detail[0] ? detail :
                            "invalid condition symbols");
        name = detail + sizeof(prefix) - 1;
        name_length = strlen(name);
        if (!name_length || name[name_length - 1] != '\'')
            return yx_error(p, detail);
        --name_length;
        name[name_length] = '\0';
        cursor = yx_unknown_identifier_search_start(start, p->at,
                                                     name, name_length);
        while (cursor < p->at) {
            const char *word = cursor;
            if (cursor[0] == '/' && cursor + 1 < p->at &&
                cursor[1] == '/') {
                cursor += 2;
                while (cursor < p->at && *cursor != '\n') ++cursor;
                continue;
            }
            if (cursor[0] == '/' && cursor + 1 < p->at &&
                cursor[1] == '*') {
                cursor += 2;
                while (cursor + 1 < p->at &&
                       !(cursor[0] == '*' && cursor[1] == '/')) ++cursor;
                cursor = cursor + 1 < p->at ? cursor + 2 : p->at;
                continue;
            }
            if (*cursor == '"' || *cursor == '\'') {
                char quote = *cursor++;
                while (cursor < p->at && *cursor != quote) {
                    if (*cursor == '\\' && cursor + 1 < p->at) ++cursor;
                    ++cursor;
                }
                if (cursor < p->at) ++cursor;
                continue;
            }
            if (!(isalnum((unsigned char)*cursor) || *cursor == '_')) {
                ++cursor;
                continue;
            }
            while (cursor < p->at &&
                   (isalnum((unsigned char)*cursor) || *cursor == '_'))
                ++cursor;
            if ((size_t)(cursor - word) == name_length &&
                memcmp(word, name, name_length) == 0) {
                int reported = strcmp(name, "entrypoint") == 0 ?
                    yx_compiler_entrypoint_unsupported_error(
                        p->compiler, p->begin, p->origin,
                        (size_t)(word - p->begin),
                        (size_t)(cursor - p->begin)) :
                    yx_compiler_unknown_identifier_error(
                        p->compiler, name, p->begin, p->origin,
                        (size_t)(word - p->begin),
                        (size_t)(cursor - p->begin));
                if (!reported)
                    return yx_error(p, "out of memory recording identifier");
                p->recoverable_unknown_identifier = true;
                goto validation_failed;
            }
        }
        return yx_error(p, detail);
validation_failed:
        /* The source offset up to which YARA-X has converted the condition
         * when it fails (an operation's operands before their types). */
        if (converted_end) converted_end += (size_t)(start - p->begin);
        if (yx_compiler_semantic_error_span(p->compiler, error_mark,
                                            &error_start, &error_end)) {
            size_t first_expression_warning;
            yx_compiler_drop_warnings_after(p->compiler, first_type_warning,
                                            error_mark, error_start,
                                            error_end, converted_end);
            /* YARA-X raised these while compiling the operands before the
             * failing one: keep those that end before the error. */
            /* An operation's operands are all converted before their types
             * are checked (converted_end). */
            first_expression_warning = p->compiler->warning_count;
            if (!yx_condition_warn_ambiguous_zero_of(p, rule, start,
                    converted_end > error_start ? converted_end : error_start))
                return yx_error(p, "out of memory recording expression warning");
            if (!yx_condition_warn_unsatisfiable_at(p, rule, start,
                    converted_end > error_end ? converted_end : error_end))
                return yx_error(p, "out of memory recording expression warning");
            yx_order_of_warnings(p->compiler, first_type_warning,
                                 first_expression_warning);
        }
        if (p->too_many_variables_at) {
            const char *limit = p->too_many_variables_at;
            p->too_many_variables_at = NULL;
            if (!yx_condition_warn_too_many_iterations(p, rule, start, limit))
                return yx_error(p, "out of memory recording loop warning");
        } else if (yx_compiler_semantic_error_span(p->compiler, error_mark,
                                                   &error_start, &error_end) &&
                   error_start >= (size_t)(start - p->begin)) {
            /* for_in_expr_from_ast warns about a loop before compiling its
             * body: the loops starting before the error, or before the end
             * of the operands converted with it, were reported, where the
             * conversion met them. */
            size_t first_loop_warning = p->compiler->warning_count;
            size_t limit = converted_end > error_start ? converted_end : error_start;
            if (!yx_condition_warn_too_many_iterations(p, rule, start, p->begin + limit))
                return yx_error(p, "out of memory recording loop warning");
            yx_compiler_order_raised_warnings(p->compiler, first_type_warning,
                                              first_loop_warning);
        }
        if (yx_compiler_semantic_error_end(p->compiler, error_mark, &error_end) &&
            !yx_compiler_warn_deprecated_before(
                p->compiler, rule->condition_text, p->begin, p->origin,
                (size_t)(start - p->begin),
                converted_end > error_end ? converted_end : error_end,
                first_type_warning))
            return yx_error(p, "out of memory recording deprecated field");
        return 0;
    }
    /* unused_identifier comes from the typed condition walk above; the
     * condition's own non_bool_expr closes it. */
    if (warning_context.root_pending &&
        !yx_condition_type_warning("non_bool_expr", warning_context.root_start,
                                   warning_context.root_end, 0,
                                   warning_context.root_point,
                                   warning_context.root_type, &warning_context))
        return yx_error(p, "out of memory recording type warning");
    if (!yx_compiler_warn_invariant_condition(
            p->compiler, rule->condition_text, rule,
            p->begin, p->origin, (size_t)(start - p->begin),
            first_type_warning)) return 0;
    /* potentially_slow_loop comes from the typed condition walk above. */
    if (p->pending_slow_loop_error) {
        ++p->at;
        return 1;
    }
    if (!yx_condition_warn_too_many_iterations(p, rule, start, NULL))
        return yx_error(p, "out of memory recording loop warning");
    first_of_warning = p->compiler->warning_count;
    if (!yx_condition_warn_ambiguous_zero_of(p, rule, start, SIZE_MAX))
        return yx_error(p, "out of memory recording expression warning");
    if (!yx_condition_warn_unsatisfiable_at(p, rule, start, SIZE_MAX))
        return yx_error(p, "out of memory recording expression warning");
    yx_order_of_warnings(p->compiler, first_type_warning, first_of_warning);
    if (!yx_condition_warn_overlapping_pattern_sets(p, rule, start))
        return yx_error(p, "out of memory recording pattern-set warning");
    ++p->at;
    return 1;
}

static int yx_parse_condition(yx_parser *p, YRX_RULE *rule)
{
    YRX_RULES *rules = p->compiler->rules;
    char **imports = rules->imports;
    size_t import_count = rules->import_count;
    if (!rules->import_namespace_indices || !import_count)
        return yx_parse_condition_in_scope(p, rule);
    char **visible = malloc(import_count * sizeof(*visible));
    if (!visible) return yx_error(p, "out of memory recording module scope");
    size_t count = 0;
    for (size_t i = 0; i < import_count; ++i)
        if (rules->import_namespace_indices[i] == p->compiler->current_namespace_index)
            visible[count++] = imports[i];
    rules->imports = visible;
    rules->import_count = count;
    int result = yx_parse_condition_in_scope(p, rule);
    rules->imports = imports;
    rules->import_count = import_count;
    free(visible);
    return result;
}

static int yx_capture_rule_declaration(yx_parser *p, YRX_RULE *rule)
{
    const char *start = p->at - strlen(rule->identifier);
    const char *line_start = start;
    const char *line_end;
    size_t line = 1;
    while (line_start > p->begin && line_start[-1] != '\n') --line_start;
    const char *cursor = p->begin;
    if (p->line_cursor && p->line_cursor >= p->begin && p->line_cursor <= line_start) {
        cursor = p->line_cursor;
        line = p->line_number;
    }
    for (; cursor < line_start; ++cursor)
        if (*cursor == '\n') ++line;
    p->line_cursor = line_start;
    p->line_number = line;
    line_end = strchr(start, '\n');
    if (!line_end) line_end = p->begin + strlen(p->begin);
    if (*line_end == '\n' && line_end > line_start && line_end[-1] == '\r')
        --line_end;
    rule->declaration_line = yx_duplicate(line_start,
                                           (size_t)(line_end - line_start));
    rule->declaration_origin = yx_duplicate(p->origin ? p->origin : "line",
                                             strlen(p->origin ? p->origin : "line"));
    if (!rule->declaration_line || !rule->declaration_origin) return 0;
    rule->declaration_origin_explicit =
        p->compiler->current_origin_explicit;
    rule->declaration_line_number = line;
    rule->declaration_column = (size_t)(start - line_start) + 1;
    rule->declaration_start = (size_t)(start - p->begin);
    rule->declaration_end = (size_t)(p->at - p->begin);
    rule->declaration_source_serial = p->source_serial;
    return 1;
}

/* YARA-X checks a rule's name before compiling its body: a name taken by
 * an earlier rule of the namespace (E012), or by a built-in function, a
 * global or a module imported in the namespace so far (E013), drops the
 * whole rule. Returns 1 after recording the error, -1 out of memory. */
static int yx_rule_name_conflict(yx_parser *p, const YRX_RULE *rule)
{
    static const char *const builtins[] = {
        "uint8", "uint16", "uint32", "uint8be", "uint16be", "uint32be",
        "uint64", "uint64be", "int64", "int64be",
        "int8", "int16", "int32", "int8be", "int16be", "int32be",
        "float32", "float64", "float32be", "float64be"
    };
    YRX_RULES *rules = p->compiler->rules;
    const char *name = rule->identifier;
    size_t length = strlen(name);
    bool duplicate = true, conflict = false;
    if (!yx_rule_name_cache_contains(&p->compiler->rule_name_cache, rules,
                                     rule->namespace_index, name, &duplicate))
        duplicate = true;
    for (size_t i = 0; duplicate && i < rules->rule_count; ++i)
        if (strcmp(rules->rules[i].identifier, name) == 0 &&
            rules->rules[i].namespace_index == rule->namespace_index)
            return yx_compiler_duplicate_rule_error(
                p->compiler, rule, &rules->rules[i], p->begin) ? 1 : -1;
    for (size_t i = 0; !conflict && i < sizeof(builtins) / sizeof(*builtins); ++i)
        conflict = strcmp(name, builtins[i]) == 0;
    for (size_t i = 0; !conflict && i < rules->global_count; ++i)
        conflict = rules->globals[i].name &&
                   strncmp(rules->globals[i].name, name, length) == 0 &&
                   (!rules->globals[i].name[length] ||
                    rules->globals[i].name[length] == '.');
    for (size_t i = 0; !conflict && i < rules->import_count; ++i)
        conflict = (!rules->import_namespace_indices ||
                    rules->import_namespace_indices[i] == rule->namespace_index) &&
                   strcmp(rules->imports[i], name) == 0;
    if (!conflict) return 0;
    return yx_compiler_conflicting_rule_error(
        p->compiler, name, p->begin, p->origin, rule->declaration_start,
        rule->declaration_start + length) ? 1 : -1;
}

static int yx_append_rule(yx_parser *p, YRX_RULE *rule,
                          size_t initial_warning_count)
{
    YRX_RULES *rules = p->compiler->rules;
    bool duplicate = true;
    if (!yx_rule_name_cache_contains(&p->compiler->rule_name_cache, rules, rule->namespace_index,
                                     rule->identifier, &duplicate))
        duplicate = true;
    for (size_t i = 0; duplicate && i < rules->rule_count; ++i)
        if (strcmp(rules->rules[i].identifier, rule->identifier) == 0 &&
            rules->rules[i].namespace_index == rule->namespace_index) {
            while (p->compiler->warning_count > initial_warning_count)
                free(p->compiler->warnings[--p->compiler->warning_count]);
            if (!yx_compiler_duplicate_rule_error(p->compiler, rule,
                                                   &rules->rules[i], p->begin))
                return yx_error(p, "out of memory recording duplicate rule");
            return 0;
        }
    if (!rules->rules || rules->rule_count >= rules->rule_capacity) {
        size_t capacity = rules->rule_count < 8 ? 8 :
            rules->rule_count <= SIZE_MAX / 2 ? rules->rule_count * 2 : SIZE_MAX;
        YRX_RULE *grown;
        if (capacity > SIZE_MAX / sizeof(*grown)) return yx_error(p, "out of memory");
        grown = realloc(rules->rules, capacity * sizeof(*grown));
        if (!grown) return yx_error(p, "out of memory");
        rules->rules = grown;
        rules->rule_capacity = capacity;
    }
    rules->rules[rules->rule_count++] = *rule;
    memset(rule, 0, sizeof(*rule));
    return 1;
}

static bool yx_recover_next_rule_keyword(yx_parser *p);

static const char *yx_find_later_condition_value(const yx_parser *p)
{
    const char *cursor = p->at;
    while (*cursor) {
        if (cursor[0] == '/' && cursor[1] == '/') {
            cursor += 2;
            while (*cursor && *cursor != '\n') ++cursor;
            continue;
        }
        if (cursor[0] == '/' && cursor[1] == '*') {
            cursor += 2;
            while (*cursor && !(cursor[0] == '*' && cursor[1] == '/'))
                ++cursor;
            if (*cursor) cursor += 2;
            continue;
        }
        if (*cursor == '"' || *cursor == '\'') {
            bool triple = cursor[0] == '"' && cursor[1] == '"' &&
                          cursor[2] == '"';
            char quote = *cursor;
            cursor += triple ? 3 : 1;
            while (*cursor &&
                   (triple ? strncmp(cursor, "\"\"\"", 3) != 0 :
                             *cursor != quote && *cursor != '\n')) {
                if (*cursor == '\\' && cursor[1]) ++cursor;
                ++cursor;
            }
            if (*cursor && *cursor != '\n') cursor += triple ? 3 : 1;
            continue;
        }
        if ((cursor == p->begin ||
             !yx_ident_continue_width_before(p->begin, cursor)) &&
            strncmp(cursor, "condition", 9) == 0 &&
            !yx_ident_continue_width(cursor + 9)) {
            const char *after = cursor + 9;
            while (isspace((unsigned char)*after)) ++after;
            if (*after == ':') return after + 1;
        }
        ++cursor;
    }
    return NULL;
}

static bool yx_later_condition_section(const yx_parser *p)
{
    return yx_find_later_condition_value(p) != NULL;
}

static bool yx_later_condition_missing_colon(const yx_parser *p)
{
    const char *end = p->begin + strlen(p->begin);
    for (const char *cursor = p->at; cursor < end; ++cursor) {
        const char *next = yx_condition_skip_noncode(cursor, p->at, end);
        if (next != cursor) {
            cursor = next - 1;
            continue;
        }
        if ((cursor == p->begin ||
             !yx_ident_continue_width_before(p->begin, cursor)) &&
            end - cursor >= 9 &&
            memcmp(cursor, "condition", 9) == 0 &&
            !yx_ident_continue_width(cursor + 9)) {
            yx_parser probe = *p;
            probe.at = cursor + 9;
            yx_space(&probe);
            if (*probe.at == '$' && yx_ident_continue_width(probe.at + 1))
                return true;
        }
    }
    return false;
}

static void yx_missing_condition_recovery(yx_parser *p)
{
    /* An unclosed string can consume the rest of the source (including bare
     * CR separators). The reference still reports the absent condition at
     * EOF after the literal error. */
    if (!*p->at &&
        !strstr(p->compiler->error, "unclosed literal string")) return;
    yx_parser probe = *p;
    /* A `rule` token inside a malformed hex pattern is not the start of a
     * later rule and must not hide a missing-condition diagnostic. */
    if (!p->recover_inside_hex && yx_recover_next_rule_keyword(&probe)) {
        const char *after_rule = probe.at + 4;
        while (isspace((unsigned char)*after_rule)) ++after_rule;
        if (*after_rule != ':') return;
    }
    if (yx_later_condition_section(p)) return;
    char first_error[sizeof(p->compiler->error)];
    const char *end = p->begin + strlen(p->begin);
    memcpy(first_error, p->compiler->error, sizeof(first_error));
    yx_syntax_expected(p, end, end, "`condition`");
    memcpy(p->compiler->error, first_error, sizeof(first_error));
}

static void yx_tag_section_recovery(yx_parser *p, const char *body)
{
    yx_parser probe = *p;
    bool meta_section, strings_section;
    if (!*body) {
        yx_syntax_expected(p, body, body, "`{`");
        return;
    }
    probe.at = body + 1;
    yx_space(&probe);
    const char *section = probe.at;
    meta_section = yx_section(&probe, "meta") != 0;
    strings_section = !meta_section &&
                      yx_section(&probe, "strings") != 0;
    if (!meta_section && !strings_section) {
        if (!yx_section(&probe, "condition"))
            yx_syntax_expected(p, section, yx_syntax_token_end(section),
                               "`meta`, `strings` or `condition`");
        return;
    }

    /* A malformed tag does not prevent the reference parser from reporting
     * independent syntax errors in later rule sections. Probe those sections
     * with a disposable rule, keeping only syntax diagnostics. */
    char first_error[sizeof(p->compiler->error)];
    memcpy(first_error, p->compiler->error, sizeof(first_error));
    size_t initial_diagnostics = p->compiler->error_diagnostic_json ?
        strlen(p->compiler->error_diagnostic_json) : 0;
    size_t initial_warnings = p->compiler->warning_count;
    YRX_RULE scratch = {0};
    bool have_strings = strings_section;
    bool sections_ok = true;
    if (meta_section) {
        sections_ok = yx_parse_meta(&probe, &scratch) != 0;
        if (sections_ok)
            have_strings = yx_section(&probe, "strings") != 0;
    }
    if (sections_ok && have_strings) {
        sections_ok = yx_parse_strings(&probe, &scratch) != 0;
        if (!sections_ok && !yx_later_condition_section(&probe))
            yx_missing_condition_recovery(&probe);
        if (sections_ok) {
            yx_space(&probe);
            const char *unexpected = probe.at;
            if (*unexpected && *unexpected != '}' &&
                !yx_section(&probe, "condition")) {
                yx_syntax_expected(p, unexpected,
                                   yx_syntax_token_end(unexpected),
                                   "pattern modifier or pattern identifier");
                yx_missing_condition_recovery(&probe);
            }
        }
    }
    yx_free_rule(&scratch);
    for (size_t i = initial_warnings; i < p->compiler->warning_count; ++i)
        free(p->compiler->warnings[i]);
    p->compiler->warning_count = initial_warnings;
    if (p->compiler->error_diagnostic_json &&
        !strstr(p->compiler->error_diagnostic_json + initial_diagnostics,
                "\"code\":\"E001\""))
        p->compiler->error_diagnostic_json[initial_diagnostics] = 0;
    memcpy(p->compiler->error, first_error, sizeof(first_error));
}

static void yx_missing_rule_body_recovery(yx_parser *p)
{
    const char *cursor = p->at;
    const char *end = p->begin + strlen(p->begin);
    while (cursor < end) {
        const char *next = yx_condition_skip_noncode(cursor, p->at, end);
        if (next != cursor) { cursor = next; continue; }
        if (*cursor == '{') {
            yx_tag_section_recovery(p, cursor);
            return;
        }
        ++cursor;
    }
    yx_syntax_expected(p, end, end, "`{`");
}

static bool yx_recover_rule_end(yx_parser *p);

static void yx_secondary_condition_syntax_recovery(yx_parser *p)
{
    const char *value = yx_find_later_condition_value(p);
    if (!value) return;
    yx_parser end_probe = *p;
    yx_recover_rule_end(&end_probe);
    if (value >= end_probe.at) return;
    while (value < end_probe.at && isspace((unsigned char)*value)) ++value;
    char *fragment = yx_duplicate(value, (size_t)(end_probe.at - value));
    if (!fragment) return;
    char detail[YX_CONDITION_DETAIL_SIZE] = {0};
    yx_condition *condition = yx_condition_compile(fragment, detail,
                                                    sizeof(detail));
    free(fragment);
    if (condition) { yx_condition_destroy(condition); return; }
    size_t offset = 0;
    int suffix_offset = 0;
    if (sscanf(detail, "at byte %zu: %n", &offset, &suffix_offset) != 1 ||
        !suffix_offset || offset >= (size_t)(end_probe.at - value) ||
        strncmp(detail + suffix_offset, "unexpected token '", 18) != 0)
        return;
    const char *unexpected = value + offset;
    yx_diag_token *tokens = NULL;
    size_t count = 0;
    if (!yx_condition_diag_tokens(value, unexpected, &tokens, &count) ||
        !count) { free(tokens); return; }
    const yx_diag_token *last = &tokens[count - 1];
    const char *expected = NULL;
    if (last->kind == YX_DIAG_WORD && *last->start == '$' &&
        (isalpha((unsigned char)*unexpected) || *unexpected == '_'))
        expected = "`at`, `in` or operator";
    else if ((last->kind == YX_DIAG_INTEGER ||
              yx_diag_token_is(last, "filesize")) &&
             (isdigit((unsigned char)*unexpected) ||
              *unexpected == '$'))
        expected = "`%`, operator, `of` or expression";
    else if (last->kind == YX_DIAG_INTEGER && *unexpected == '.')
        expected = "operator or expression";
    else if (last->kind == YX_DIAG_WORD && *unexpected == '{')
        expected = "`(`, `[`, expression, `%`, operator or `of`";
    free(tokens);
    if (expected)
        yx_syntax_expected(p, unexpected,
                           yx_syntax_token_end(unexpected), expected);
}

/* After a syntax error in an earlier rule section, the reference parser can
 * still finish a valid condition. If an invalid top-level token follows that
 * rule, its recovery reports the closing brace as a second condition error.
 * A following declaration or end of file commits the recovery normally. */
static void yx_trailing_token_condition_recovery(yx_parser *p)
{
    if (strncmp(p->compiler->error, "error[E001]:", 12) != 0) return;
    yx_parser end_probe = *p;
    if (!yx_recover_rule_end(&end_probe) || *end_probe.at != '}') return;
    yx_parser next_probe = end_probe;
    ++next_probe.at;
    yx_space(&next_probe);
    if (!*next_probe.at || next_probe.unterminated_comment) return;
    static const char *const declarations[] = {
        "global", "private", "rule", "import", "include"
    };
    for (size_t i = 0; i < sizeof(declarations) / sizeof(declarations[0]);
         ++i) {
        yx_parser declaration_probe = next_probe;
        if (yx_keyword(&declaration_probe, declarations[i])) return;
    }

    const char *value = yx_find_later_condition_value(p);
    if (!value || value >= end_probe.at) return;
    char *fragment = yx_duplicate(value, (size_t)(end_probe.at - value));
    if (!fragment) return;
    char detail[YX_CONDITION_DETAIL_SIZE] = {0};
    yx_condition *condition = yx_condition_compile(fragment, detail,
                                                    sizeof(detail));
    free(fragment);
    if (!condition) return;
    yx_condition_destroy(condition);

    yx_diag_token *tokens = NULL;
    size_t count = 0;
    if (!yx_condition_diag_tokens(value, end_probe.at, &tokens, &count) ||
        !count) { free(tokens); return; }
    const yx_diag_token *last = &tokens[count - 1];
    const char *expected = NULL;
    if (last->kind == YX_DIAG_WORD && *last->start == '$')
        expected = "`at`, `in` or operator";
    else if (yx_diag_token_is(last, "true") ||
             yx_diag_token_is(last, "false") ||
             yx_diag_token_is(last, ")"))
        expected = "operator";
    else if (last->kind == YX_DIAG_INTEGER ||
             yx_diag_token_is(last, "filesize")) {
        if (count >= 2 &&
            (yx_diag_token_is(&tokens[count - 2], ">") ||
             yx_diag_token_is(&tokens[count - 2], "<") ||
             yx_diag_token_is(&tokens[count - 2], "==") ||
             yx_diag_token_is(&tokens[count - 2], "!=")))
            expected = "operator or expression";
        else if (count >= 2 &&
                 (yx_diag_token_is(&tokens[count - 2], "+") ||
                  yx_diag_token_is(&tokens[count - 2], "-") ||
                  yx_diag_token_is(&tokens[count - 2], "*")))
            expected = "operator, `of` or expression";
        else
            expected = "`%`, operator, `of` or expression";
    }
    free(tokens);
    if (!expected) return;
    char first_error[sizeof(p->compiler->error)];
    memcpy(first_error, p->compiler->error, sizeof(first_error));
    yx_syntax_expected(p, end_probe.at, end_probe.at + 1, expected);
    memcpy(p->compiler->error, first_error, sizeof(first_error));
}

/* If an earlier section failed, an unclosed rule can still have a readable
 * condition section. Parse it with a disposable rule to recover the syntax
 * diagnostics at end of file without changing the rule being compiled. */
static bool yx_unclosed_later_condition_recovery(yx_parser *p)
{
    yx_parser end_probe = *p;
    yx_recover_rule_end(&end_probe);
    if (*end_probe.at) return false;
    const char *value = yx_find_later_condition_value(p);
    if (!value || value > end_probe.at) return false;
    /* Earlier malformed braces can make rule-end recovery consume the real
     * closing brace as a nested one. Restrict this EOF probe to conditions
     * with no later brace token at all. */
    if (strchr(value, '}')) return false;

    char first_error[sizeof(p->compiler->error)];
    memcpy(first_error, p->compiler->error, sizeof(first_error));
    yx_parser condition_probe = *p;
    condition_probe.at = value;
    yx_space(&condition_probe);
    if (!*condition_probe.at) {
        yx_syntax_expected(p, condition_probe.at, condition_probe.at,
                           "expression or identifier");
    } else {
        yx_diag_token *tokens = NULL;
        size_t count = 0;
        bool trailing_pattern_operator = false;
        if (yx_condition_diag_tokens(value, end_probe.at, &tokens, &count) &&
            count >= 2) {
            const yx_diag_token *last = &tokens[count - 1];
            const yx_diag_token *previous = &tokens[count - 2];
            trailing_pattern_operator =
                previous->kind == YX_DIAG_WORD &&
                *previous->start == '$' &&
                (yx_diag_token_is(last, "+") ||
                 yx_diag_token_is(last, "-") ||
                 yx_diag_token_is(last, "*"));
            if (trailing_pattern_operator)
                yx_syntax_expected(p, last->start, last->end,
                                   "`at`, `in` or operator");
        }
        free(tokens);
        if (!trailing_pattern_operator)
            yx_secondary_condition_syntax_recovery(p);
        YRX_RULE scratch = {0};
        yx_parse_condition(&condition_probe, &scratch);
        yx_free_rule(&scratch);
    }
    memcpy(p->compiler->error, first_error, sizeof(first_error));
    return true;
}

/* A malformed metadata value can precede an independent syntax error in a
 * later strings section. Inspect that section without changing the rule being
 * compiled, and retain only syntax diagnostics from the probe. */
static void yx_later_strings_syntax_recovery(yx_parser *p)
{
    yx_parser end_probe = *p;
    if (!yx_recover_rule_end(&end_probe)) return;
    const char *end = end_probe.at;
    for (const char *cursor = p->at; cursor < end; ++cursor) {
        const char *next = yx_condition_skip_noncode(cursor, p->at, end);
        if (next != cursor) {
            cursor = next - 1;
            continue;
        }
        if (cursor > p->at &&
            yx_ident_continue_width_before(p->at, cursor)) continue;
        if (end - cursor < 8 || strncmp(cursor, "strings", 7) != 0 ||
            yx_ident_continue_width(cursor + 7)) continue;
        yx_parser probe = *p;
        probe.at = cursor;
        if (!yx_section(&probe, "strings")) continue;
        yx_space(&probe);
        char first_error[sizeof(p->compiler->error)];
        memcpy(first_error, p->compiler->error, sizeof(first_error));
        if (*probe.at != '$') {
            const char *token_end = yx_syntax_token_end(probe.at);
            if (*probe.at == '?' && probe.at[1] == '$' &&
                yx_ident_continue_width(probe.at + 2)) {
                token_end = probe.at + 2;
                for (;;) {
                    size_t width = yx_ident_continue_width(token_end);
                    if (!width) break;
                    token_end += width;
                }
            }
            yx_syntax_expected(p, probe.at, token_end,
                               "pattern identifier");
            memcpy(p->compiler->error, first_error, sizeof(first_error));
            return;
        }

        size_t first_warning_count = p->compiler->warning_count;
        size_t first_diagnostic_length =
            p->compiler->error_diagnostic_json ?
            strlen(p->compiler->error_diagnostic_json) : 0;
        YRX_RULE scratch = {0};
        bool strings_ok = yx_parse_strings(&probe, &scratch) != 0;
        if (strings_ok && scratch.pattern_count) {
            yx_space(&probe);
            const char *unexpected = probe.at;
            yx_parser section_probe = probe;
            if (*unexpected &&
                !yx_keyword(&section_probe, "condition"))
                yx_syntax_expected(p, unexpected,
                                   yx_syntax_token_end(unexpected),
                                   "pattern modifier or pattern identifier");
        }
        yx_free_rule(&scratch);
        for (size_t i = first_warning_count;
             i < p->compiler->warning_count; ++i)
            free(p->compiler->warnings[i]);
        p->compiler->warning_count = first_warning_count;
        bool found_syntax_error = p->compiler->error_diagnostic_json &&
            strstr(p->compiler->error_diagnostic_json +
                   first_diagnostic_length, "\"code\":\"E001\"");
        if (p->compiler->error_diagnostic_json && !found_syntax_error)
            p->compiler->error_diagnostic_json[first_diagnostic_length] = 0;
        if (found_syntax_error) {
            yx_parser condition_probe = *p;
            condition_probe.at = probe.at;
            const char *condition_value =
                yx_find_later_condition_value(&condition_probe);
            if (condition_value && condition_value < end) {
                condition_probe.at = condition_value;
                yx_space(&condition_probe);
                if (*condition_probe.at == '}')
                    yx_syntax_expected(p, condition_probe.at,
                                       condition_probe.at + 1,
                                       "expression or identifier");
            }
        }
        memcpy(p->compiler->error, first_error, sizeof(first_error));
        return;
    }
}

/* After a metadata syntax error, the lexer can still identify later section
 * keywords whose colon is missing. Limit this recovery to unmistakable
 * section values, so words inside patterns do not create extra diagnostics. */
static bool yx_later_section_colon_recovery(yx_parser *p,
                                             bool condition_only)
{
    yx_parser end_probe = *p;
    if (!yx_recover_rule_end(&end_probe) || *end_probe.at != '}') return false;
    const char *end = end_probe.at;
    size_t nested_braces = 0;
    for (const char *cursor = p->at; cursor < end; ++cursor) {
        const char *next = yx_condition_skip_noncode(cursor, p->at, end);
        if (next != cursor) {
            cursor = next - 1;
            continue;
        }
        if (*cursor == '{') { ++nested_braces; continue; }
        if (*cursor == '}') {
            if (nested_braces) --nested_braces;
            continue;
        }
        if (nested_braces || cursor <= p->at ||
            yx_ident_continue_width_before(p->at, cursor)) continue;
        if (*cursor == '/') {
            const char *before = cursor;
            while (before > p->at && isspace((unsigned char)before[-1]))
                --before;
            if (before > p->at && before[-1] == '=') {
                const char *regexp_end = yx_syntax_regexp_token_end(cursor);
                if (regexp_end > cursor + 1 && regexp_end <= end) {
                    cursor = regexp_end - 1;
                    continue;
                }
            }
        }
        size_t name_length = 0;
        bool condition = false;
        if (!condition_only && end - cursor >= 7 &&
            strncmp(cursor, "strings", 7) == 0 &&
            !yx_ident_continue_width(cursor + 7)) name_length = 7;
        else if (end - cursor >= 9 &&
                 strncmp(cursor, "condition", 9) == 0 &&
                 !yx_ident_continue_width(cursor + 9)) {
            name_length = 9;
            condition = true;
        }
        if (!name_length) continue;
        yx_parser probe = *p;
        probe.at = cursor + name_length;
        yx_space(&probe);
        if (*probe.at == '$' &&
            (isalpha((unsigned char)probe.at[1]) || probe.at[1] == '_')) {
            char first_error[sizeof(p->compiler->error)];
            memcpy(first_error, p->compiler->error, sizeof(first_error));
            yx_syntax_expected(p, probe.at,
                               yx_syntax_token_end(probe.at), "`:`");
            memcpy(p->compiler->error, first_error, sizeof(first_error));
            return true;
        }
        if (condition && probe.at == end && *probe.at == '}') {
            char first_error[sizeof(p->compiler->error)];
            memcpy(first_error, p->compiler->error, sizeof(first_error));
            yx_syntax_expected(p, probe.at, probe.at + 1, "`:`");
            memcpy(p->compiler->error, first_error, sizeof(first_error));
            return true;
        }
    }
    return false;
}

/* After a reserved word in the rule-name slot, the reference parser also
 * tries that token as the beginning of the next top-level statement. Keep
 * those follow-on syntax errors while retaining the rule-name error as the
 * compiler's primary error. */
static void yx_reserved_rule_name_recovery(yx_parser *p, const char *name)
{
    yx_parser probe = *p;
    const char *at, *end;
    char first_error[sizeof(p->compiler->error)];
    const char *other_modifier = NULL;
    const char *expected = NULL;

    if (strcmp(name, "global") == 0) {
        other_modifier = "private";
        expected = "`private` or `rule`";
    } else if (strcmp(name, "private") == 0) {
        other_modifier = "global";
        expected = "`global` or `rule`";
    } else if (strcmp(name, "import") != 0 &&
               strcmp(name, "include") != 0) {
        return;
    }

    memcpy(first_error, p->compiler->error, sizeof(first_error));
    yx_space(&probe);
    at = probe.at;
    if (other_modifier) {
        if (yx_keyword(&probe, "rule")) goto done;
        probe.at = at;
        if (yx_keyword(&probe, other_modifier)) {
            yx_space(&probe);
            if (yx_keyword(&probe, "rule")) goto done;
            at = probe.at;
            expected = "`rule`";
        }
        end = yx_syntax_token_end(at);
        yx_syntax_expected(p, at, end, expected);
    } else if (*at != '"') {
        end = yx_syntax_token_end(at);
        yx_syntax_expected(p, at, end, "STRING");
        probe.at = at;
        if (*at && !yx_keyword(&probe, "rule"))
            yx_syntax_label(p, at, end,
                            "expecting import statement or rule definition");
    }
done:
    memcpy(p->compiler->error, first_error, sizeof(first_error));
}

static int yx_parse_rule_unlimited(yx_parser *p, bool is_private,
                                   bool is_global);

/* YARA-X keeps the first `max_warnings` warnings in the order it raises
 * them (compiler/mod.rs, Warnings::add). A rule's warnings are collected by
 * several passes and then ordered, so the limit applies once the rule's
 * warnings are in that order. */
static int yx_parse_rule(yx_parser *p, bool is_private, bool is_global)
{
    YRX_COMPILER *compiler = p->compiler;
    size_t limit = compiler->max_warnings;
    int result;
    if (compiler->warning_count >= limit)
        return yx_parse_rule_unlimited(p, is_private, is_global);
    compiler->max_warnings = SIZE_MAX;
    result = yx_parse_rule_unlimited(p, is_private, is_global);
    compiler->max_warnings = limit;
    while (compiler->warning_count > limit)
        free(compiler->warnings[--compiler->warning_count]);
    return result;
}

static int yx_parse_rule_unlimited(yx_parser *p, bool is_private,
                                   bool is_global)
{
    YRX_RULE rule = {0};
    size_t initial_warning_count = p->compiler->warning_count;
    size_t initial_error_length = p->compiler->error_diagnostic_json ?
        strlen(p->compiler->error_diagnostic_json) : 0;
    p->pending_slow_loop_error = false;
    rule.is_private = is_private;
    rule.is_global = is_global;
    rule.identifier = yx_ident(p);
    if (!rule.identifier) {
        int result = yx_syntax_expected(
            p, p->at, yx_syntax_token_end(p->at), "identifier");
        yx_parser probe = *p;
        if (yx_recover_next_rule_keyword(&probe)) {
            p->recoverable_rule_keyword = true;
            p->at = probe.at;
        }
        return result;
    }
    if (!yx_capture_rule_declaration(p, &rule)) goto memory_failure;
    if (yx_reserved_identifier(rule.identifier)) {
        const char *name_start = p->at - strlen(rule.identifier);
        yx_syntax_expected(p, name_start, p->at, "identifier");
        yx_reserved_rule_name_recovery(p, rule.identifier);
        if (strcmp(rule.identifier, "rule") == 0) {
            p->recoverable_rule_keyword = true;
            p->at = name_start;
        }
        goto failure;
    }
    rule.namespace_name = yx_duplicate(p->compiler->current_namespace ? p->compiler->current_namespace : "default",
                                       strlen(p->compiler->current_namespace ? p->compiler->current_namespace : "default"));
    if (!rule.namespace_name) goto memory_failure;
    rule.namespace_index = p->compiler->current_namespace_index;
    switch (yx_rule_name_conflict(p, &rule)) {
    case 0: break;
    case 1: goto failure;
    default: goto memory_failure;
    }
    yx_space(p);
    if (*p->at == ':') {
        ++p->at;
        while (1) {
            const char *tag_start;
            yx_space(p);
            tag_start = p->at;
            char *tag = yx_ident(p);
            if (!tag) break;
            if (yx_reserved_identifier(tag)) {
                free(tag);
                yx_syntax_expected(p, tag_start, p->at,
                                   rule.tag_count ? "identifier or `{`" :
                                                    "identifier");
                const char *body = p->at;
                while (*body && *body != '{') ++body;
                yx_tag_section_recovery(p, body);
                goto failure;
            }
            if (!yx_append_tag(p, &rule, tag)) { free(tag); goto failure; }
        }
        if (!rule.tag_count) {
            yx_syntax_expected(p, p->at, yx_syntax_token_end(p->at),
                               "identifier");
            if (*p->at == '{') yx_tag_section_recovery(p, p->at);
            else yx_missing_rule_body_recovery(p);
            goto failure;
        }
    }
    yx_space(p);
    if (*p->at != '{') {
        bool recovered_tag_section = false;
        const char *token_end = yx_syntax_token_end(p->at);
        if (p->at[0] == '?' && p->at[1] &&
            !isspace((unsigned char)p->at[1]) && token_end == p->at + 1)
            token_end = p->at + 2;
        yx_syntax_expected(p, p->at, token_end,
                           rule.tag_count ? "identifier or `{`" :
                                            "`:` or `{`");
        if (strncmp(p->at, "rule", 4) == 0 &&
            !yx_ident_continue_width(p->at + 4))
            p->recoverable_rule_keyword = true;
        if (rule.tag_count &&
            (*p->at == ':' || *p->at == '?' ||
             isdigit((unsigned char)*p->at))) {
            const char *body = p->at;
            while (*body && *body != '{') ++body;
            yx_tag_section_recovery(p, body);
            recovered_tag_section = true;
        }
        if (rule.tag_count && !recovered_tag_section)
            yx_missing_rule_body_recovery(p);
        goto failure;
    }
    ++p->at;
    bool seen_meta = false, seen_strings = false, seen_condition = false;
    while (!seen_condition) {
        yx_space(p);
        const char *section_start = p->at;
        if (yx_section(p, "meta")) {
            if (seen_meta || seen_strings) {
                yx_error(p, "meta section is duplicated or out of order");
                goto failure;
            }
            seen_meta = true;
            if (!yx_parse_meta(p, &rule)) {
                yx_parser section_probe = *p;
                if (strncmp(p->compiler->error, "error[E001]:", 12) == 0 &&
                    yx_section(&section_probe, "condition"))
                    p->recoverable_bad_initial_section = true;
                if (strncmp(p->compiler->error, "error[E001]:", 12) == 0)
                    yx_later_strings_syntax_recovery(p);
                if (strncmp(p->compiler->error, "error[E001]:", 12) == 0)
                    yx_later_section_colon_recovery(p, false);
                if (strncmp(p->compiler->error, "error[E001]:", 12) == 0)
                    yx_unclosed_later_condition_recovery(p);
                yx_trailing_token_condition_recovery(p);
                if (!p->suppress_missing_condition_recovery &&
                    (rule.metadata_count || *p->at == '}') &&
                    strncmp(p->compiler->error, "error[E001]:", 12) == 0)
                    yx_missing_condition_recovery(p);
                goto failure;
            }
            if (!rule.metadata_count) {
                yx_syntax_expected(p, p->at, yx_syntax_token_end(p->at),
                                   "identifier");
                if (*p->at == '}') yx_missing_condition_recovery(p);
                goto failure;
            }
        } else if (yx_section(p, "strings")) {
            if (seen_strings) {
                yx_syntax_expected(p, section_start,
                                   yx_syntax_token_end(section_start),
                                   "pattern modifier, pattern identifier or `condition`");
                yx_missing_condition_recovery(p);
                goto failure;
            }
            seen_strings = true;
            const char *strings_start = p->at;
            if (!yx_parse_strings(p, &rule)) {
                /* The strings error can precede a condition header whose
                   colon is missing. Report that later token before deciding
                   whether the rule is missing its condition entirely. */
                bool recovered_colon =
                    yx_later_section_colon_recovery(p, true);
                yx_parser condition_probe = *p;
                condition_probe.at = strings_start;
                if (!recovered_colon &&
                    !p->suppress_missing_condition_recovery &&
                    strncmp(p->compiler->error, "error[E001]:", 12) == 0 &&
                    !yx_later_condition_section(&condition_probe))
                    yx_missing_condition_recovery(p);
                else if (!recovered_colon &&
                         strncmp(p->compiler->error, "error[E001]:", 12) == 0 &&
                         !yx_unclosed_later_condition_recovery(p))
                    yx_secondary_condition_syntax_recovery(p);
                yx_trailing_token_condition_recovery(p);
                goto failure;
            }
            if (!rule.pattern_count) {
                yx_syntax_expected(p, p->at, yx_syntax_token_end(p->at),
                                   "pattern identifier");
                if (!p->suppress_missing_condition_recovery)
                    yx_missing_condition_recovery(p);
                if (yx_later_condition_section(p) &&
                    !yx_unclosed_later_condition_recovery(p))
                    yx_secondary_condition_syntax_recovery(p);
                goto failure;
            }
        } else if (yx_section(p, "condition")) {
            int condition_result;
            seen_condition = true;
            condition_result = yx_parse_condition(p, &rule);
            if (!condition_result) {
                /* c_rule checks literal patterns (text, or a regexp or hex
                 * pattern whose HIR is one literal) for common byte
                 * repetitions even when the condition fails semantic
                 * validation; atom-quality slow_pattern warnings come from
                 * compiling the patterns, which a failing rule never
                 * reaches. Syntax errors stop before both. */
                if (rule.condition &&
                    strncmp(p->compiler->error, "error[E001]:", 12) != 0) {
                    for (size_t i = 0; i < rule.pattern_count; ++i) {
                        int result = yx_compiler_slow_pattern_warning(
                            p->compiler, &rule, &rule.patterns[i],
                            p->begin, p->origin, false);
                        if (!result) goto memory_failure;
                        if (result == 2) {
                            p->recoverable_slow_error = true;
                            break;
                        }
                    }
                }
                if (*p->at == '}' &&
                    strncmp(p->compiler->error, "error[E001]:", 12) == 0)
                    p->recoverable_condition_syntax = true;
                goto failure;
            }
            if (condition_result == 2) {
                yx_free_rule(&rule);
                return 1;
            }
        } else {
            static const char *section_names[] = {
                "meta", "strings", "condition"
            };
            for (size_t i = 0; i < sizeof(section_names) /
                 sizeof(section_names[0]); ++i) {
                if (seen_strings && i != 2) continue;
                yx_parser section_probe = *p;
                if (!yx_keyword(&section_probe, section_names[i])) continue;
                yx_space(&section_probe);
                if (*section_probe.at == ':') continue;
                const char *token_end = yx_syntax_token_end(section_probe.at);
                if (*section_probe.at == '$') {
                    size_t width;
                    token_end = section_probe.at + 1;
                    while ((width = yx_ident_continue_width(token_end)) != 0)
                        token_end += width;
                }
                yx_syntax_expected(p, section_probe.at, token_end, "`:`");
                p->at = section_probe.at;
                if (i == 0)
                    yx_later_strings_syntax_recovery(p);
                if (i == 1)
                    yx_secondary_condition_syntax_recovery(p);
                if (i != 2)
                    yx_missing_condition_recovery(p);
                goto failure;
            }
            bool after_strings = seen_strings;
            if (!after_strings && !seen_meta && *p->at == '}')
                p->recoverable_empty_rule = true;
            if (!after_strings && !seen_meta && *p->at && *p->at != '}')
                p->recoverable_bad_initial_section = true;
            const char *expected = after_strings ?
                "pattern modifier, pattern identifier or `condition`" :
                seen_meta ? "identifier, `strings` or `condition`" :
                *p->at ? "`meta`, `strings` or `condition`" :
                         "`condition`";
            const char *unexpected_end = yx_syntax_token_end(p->at);
            if (p->at[0] == '?' && p->at[1] == ':')
                unexpected_end = p->at + 2;
            yx_syntax_expected(
                p, p->at, unexpected_end, expected);
            bool recovered_colon = after_strings &&
                yx_later_section_colon_recovery(p, true);
            if (!after_strings && !seen_meta && *p->at) {
                yx_parser end_probe = *p;
                bool found_closing_brace = yx_recover_rule_end(&end_probe);
                if (!*end_probe.at && !found_closing_brace)
                    yx_syntax_expected(p, end_probe.at, end_probe.at, "`}`");
            }
            bool later_condition = false;
            if ((after_strings || seen_meta) && p->at[0] == '?' &&
                p->at[1] == ':') {
                for (const char *cursor = p->at + 2;
                     *cursor && *cursor != '}'; ++cursor) {
                    yx_parser condition_probe = *p;
                    condition_probe.at = cursor;
                    if (yx_section(&condition_probe, "condition")) {
                        later_condition = true;
                        break;
                    }
                }
            }
            if ((after_strings || seen_meta) && !later_condition &&
                !recovered_colon)
                yx_missing_condition_recovery(p);
            if ((after_strings || seen_meta) &&
                yx_later_condition_section(p) &&
                !yx_unclosed_later_condition_recovery(p) && after_strings)
                yx_secondary_condition_syntax_recovery(p);
            goto failure;
        }
    }
    /* Compiler::c_rule: the literal check of every pattern, the condition's
     * error, then c_regexp for each regexp or hex pattern it compiles. */
    for (size_t i = 0; i < rule.pattern_count; ++i) {
        int result = yx_compiler_slow_pattern_warning(
            p->compiler, &rule, &rule.patterns[i], p->begin, p->origin,
            false);
        if (result == 2) {
            p->recoverable_slow_error = true;
            goto failure;
        }
        if (!result) goto memory_failure;
    }
    if (p->pending_slow_loop_error) {
        int result = yx_compiler_potentially_slow_loop_warning(
            p->compiler, p->begin, p->origin,
            p->slow_loop_start, p->slow_loop_end);
        if (result == 2) {
            p->recoverable_slow_error = true;
            goto failure;
        }
        if (!result) goto memory_failure;
    }
    for (size_t i = 0; i < rule.pattern_count; ++i) {
        int result = yx_compiler_slow_pattern_warning(
            p->compiler, &rule, &rule.patterns[i], p->begin, p->origin,
            true);
        if (result == 2) {
            p->recoverable_slow_error = true;
            goto failure;
        }
        if (!result) goto memory_failure;
    }
    /* E048, the last check before the rule is added: its emitted code. */
    if (rule.condition) {
        const char **names = NULL;
        uint64_t size;
        if (rule.pattern_count) {
            names = malloc(rule.pattern_count * sizeof(*names));
            if (!names) goto memory_failure;
            for (size_t i = 0; i < rule.pattern_count; ++i)
                names[i] = rule.patterns[i].identifier;
        }
        size = yx_condition_wasm_size(
            rule.condition, rule.is_global, names, rule.pattern_count,
            p->compiler->rules->globals, p->compiler->rules->global_count);
        free(names);
        if (size > UINT64_C(100000)) {
            if (!yx_compiler_condition_too_large_error(
                    p->compiler, p->begin, p->origin, rule.declaration_start,
                    rule.declaration_start + strlen(rule.identifier)))
                goto memory_failure;
            /* The rule was parsed to its end: continue after it. */
            p->recoverable_slow_error = true;
            goto failure;
        }
        /* Constant absorption drops the console calls YARA-X never emits. */
        yx_condition_drop_absorbed_console_calls(rule.condition);
    }
    if (!yx_append_rule(p, &rule, initial_warning_count)) goto failure;
    return 1;
memory_failure:
    yx_error(p, "out of memory");
failure:
    if (p->compiler->error_diagnostic_json &&
        strlen(p->compiler->error_diagnostic_json) > initial_error_length &&
        strstr(p->compiler->error_diagnostic_json + initial_error_length,
               "\"code\":\"E001\"") != NULL) {
        size_t retained = initial_warning_count;
        for (size_t i = initial_warning_count;
             i < p->compiler->warning_count; ++i) {
            if (strstr(p->compiler->warnings[i],
                       "\"type\":\"RedundantCaseModifier\"") != NULL ||
                strstr(p->compiler->warnings[i],
                       "\"type\":\"TextPatternAsHex\"") != NULL ||
                strstr(p->compiler->warnings[i],
                       "\"type\":\"DuplicatePatternValue\"") != NULL)
                free(p->compiler->warnings[i]);
            else
                p->compiler->warnings[retained++] = p->compiler->warnings[i];
        }
        p->compiler->warning_count = retained;
    }
    yx_free_rule(&rule);
    return 0;
}

void yx_free_rule(YRX_RULE *rule)
{
    if (!rule) return;
    free(rule->identifier);
    free(rule->namespace_name);
    free(rule->declaration_line);
    free(rule->declaration_origin);
    for (size_t i = 0; i < rule->tag_count; ++i) free(rule->tags[i]);
    free(rule->tags);
    for (size_t i = 0; i < rule->metadata_count; ++i) {
        free((void *)rule->metadata[i].identifier);
        if (rule->metadata[i].value_type == YRX_STRING)
            free((void *)rule->metadata[i].value.string);
        if (rule->metadata[i].value_type == YRX_BYTES)
            free((void *)rule->metadata[i].value.bytes.data);
    }
    free(rule->metadata);
    for (size_t i = 0; i < rule->pattern_count; ++i) {
        YRX_PATTERN *pattern = &rule->patterns[i];
        free(pattern->identifier);
        free(pattern->bytes);
        free(pattern->mask);
        yx_free_hex_atoms(pattern->hex_atoms, pattern->hex_atom_count);
        free(pattern->regexp);
        free(pattern->gap_head_regexp);
        free(pattern->base64_alphabet);
        free(pattern->base64wide_alphabet);
        free(pattern->archived_literal_prefilter.atoms);
        free(pattern->archived_regexp);
        free(pattern->matches);
        yx_candidate_plan_free(pattern->candidate_plan);
        free(pattern->rx_program_regexp);
        if (pattern->rx_program) {
            yx_rx_program_free(pattern->rx_program);
            free(pattern->rx_program);
        }
        yx_ser_chain_free(pattern->rx_chain);
    }
    free(rule->patterns);
    yx_condition_destroy(rule->condition);
    free(rule->condition_text);
    memset(rule, 0, sizeof(*rule));
}

static void yx_free_rule_global_object(yx_global_object *object);

static void yx_free_rule_global_array(yx_global_array *array)
{
    if (!array) return;
    for (size_t i = 0; i < array->count; ++i) {
        if (array->element_type == YX_GLOBAL_STR)
            free(array->items[i].string.data);
        else if (array->element_type == YX_GLOBAL_STRUCT)
            yx_free_rule_global_object(array->items[i].object);
    }
    free(array->items);
    free(array);
}

static void yx_free_rule_global_object(yx_global_object *object)
{
    if (!object) return;
    for (size_t i = 0; i < object->count; ++i) {
        free(object->fields[i].name);
        if (object->fields[i].type == YX_GLOBAL_STR)
            free(object->fields[i].value.string.data);
        else if (object->fields[i].type == YX_GLOBAL_ARRAY)
            yx_free_rule_global_array(object->fields[i].value.array);
        else if (object->fields[i].type == YX_GLOBAL_STRUCT)
            yx_free_rule_global_object(object->fields[i].value.object);
    }
    free(object->fields);
    free(object);
}

void yx_free_rules(YRX_RULES *rules)
{
    if (!rules) return;
    for (size_t i = 0; i < rules->rule_count; ++i) yx_free_rule(&rules->rules[i]);
    free(rules->rules);
    for (size_t i = 0; i < rules->import_count; ++i) free(rules->imports[i]);
    free(rules->imports);
    if(rules->import_namespaces)for(size_t i=0;i<rules->import_count;++i)free(rules->import_namespaces[i]);
    free(rules->import_namespaces);free(rules->import_rule_indices);free(rules->import_namespace_indices);
    for (size_t i = 0; i < rules->namespace_count; ++i) free(rules->namespace_names[i]);
    free(rules->namespace_names);
    free(rules->source);
    for (size_t i = 0; i < rules->global_count; ++i) {
        free(rules->globals[i].name);
        if (rules->globals[i].type == YX_GLOBAL_STR) free(rules->globals[i].value.string.data);
        else if (rules->globals[i].type == YX_GLOBAL_ARRAY)
            yx_free_rule_global_array(rules->globals[i].value.array);
        else if (rules->globals[i].type == YX_GLOBAL_STRUCT)
            yx_free_rule_global_object(rules->globals[i].value.object);
    }
    free(rules->globals);
    free(rules);
}

static bool yx_recover_rule_end(yx_parser *p)
{
    size_t nested_braces = p->recover_inside_hex ? 1 : 0;
    bool saw_closing_brace = false;
    p->recover_inside_hex = false;
    while (*p->at) {
        if (p->at[0] == '/' && p->at[1] == '/') {
            p->at += 2;
            while (*p->at && *p->at != '\n') ++p->at;
        } else if (p->at[0] == '/' && p->at[1] == '*') {
            p->at += 2;
            while (*p->at && !(p->at[0] == '*' && p->at[1] == '/'))
                ++p->at;
            if (*p->at) p->at += 2;
        } else if (*p->at == '"' || *p->at == '\'') {
            char quote = *p->at++;
            while (*p->at && *p->at != quote) {
                if (*p->at == '\\' && p->at[1]) ++p->at;
                ++p->at;
            }
            if (*p->at) ++p->at;
        } else if (*p->at == '{') {
            ++nested_braces;
            ++p->at;
        } else if (*p->at == '}') {
            saw_closing_brace = true;
            if (!nested_braces) return true;
            --nested_braces;
            ++p->at;
        } else {
            ++p->at;
        }
    }
    return saw_closing_brace;
}

static bool yx_recover_next_rule_keyword(yx_parser *p)
{
    const char *cursor = p->at;
    while (*cursor) {
        if (cursor[0] == '/' && cursor[1] == '/') {
            cursor += 2;
            while (*cursor && *cursor != '\n') ++cursor;
            continue;
        }
        if (cursor[0] == '/' && cursor[1] == '*') {
            cursor += 2;
            while (*cursor && !(cursor[0] == '*' && cursor[1] == '/'))
                ++cursor;
            if (*cursor) cursor += 2;
            continue;
        }
        if (*cursor == '"' || *cursor == '\'') {
            bool triple = cursor[0] == '"' && cursor[1] == '"' &&
                          cursor[2] == '"';
            char quote = *cursor;
            cursor += triple ? 3 : 1;
            while (*cursor &&
                   (triple ? strncmp(cursor, "\"\"\"", 3) != 0 :
                             *cursor != quote && *cursor != '\n')) {
                if (*cursor == '\\' && cursor[1]) ++cursor;
                ++cursor;
            }
            if (*cursor && *cursor != '\n') cursor += triple ? 3 : 1;
            continue;
        }
        if ((cursor == p->begin ||
             !yx_ident_continue_width_before(p->begin, cursor)) &&
            strncmp(cursor, "rule", 4) == 0 &&
            !yx_ident_continue_width(cursor + 4)) {
            p->at = cursor;
            return true;
        }
        ++cursor;
    }
    return false;
}

/* A malformed import can contain a stray quote before the next line.  The
 * ordinary token-aware recovery treats that quote as a string extending to
 * EOF, although the import itself cannot span lines. */
static bool yx_recover_rule_after_import_line(yx_parser *p)
{
    yx_parser probe = *p;
    if (yx_recover_next_rule_keyword(&probe)) {
        p->at = probe.at;
        return true;
    }
    const char *line_end = strchr(p->at, '\n');
    if (!line_end) return false;
    probe = *p;
    probe.at = line_end + 1;
    if (!yx_recover_next_rule_keyword(&probe)) return false;
    p->at = probe.at;
    return true;
}

/* The end of a rule that parsed but failed to compile: the brace closing
 * its body, skipping strings, regexps, comments and hex pattern braces. */
static const char *yx_rule_source_end(const char *at)
{
    size_t depth = 0;
    while (*at) {
        if (at[0] == '/' && at[1] == '/') {
            while (*at && *at != '\n') ++at;
            continue;
        }
        if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
            continue;
        }
        if (*at == '"' || (*at == '/' && depth)) {
            char quote = *at;
            bool in_class = false;
            for (++at; *at && *at != '\n'; ++at) {
                if (*at == '\\' && at[1]) { ++at; continue; }
                if (quote == '/' && *at == '[') in_class = true;
                else if (quote == '/' && *at == ']') in_class = false;
                else if (*at == quote && !in_class) break;
            }
            if (*at == quote) ++at;
            continue;
        }
        if (*at == '{') ++depth;
        else if (*at == '}' && depth && --depth == 0) return at + 1;
        ++at;
    }
    return NULL;
}

/* YARA-X drops a rule that fails and compiles the rest of the source. A rule
 * that parsed and failed with a compile error ends at its closing brace;
 * after a parser error, compilation resumes at the next `rule` keyword. */
static bool yx_recover_failed_rule(yx_parser *p, const char *rule_start,
                                   size_t diagnostics)
{
    static const char *const parse_codes[] = {
        "E001", "E027", "E028", "E029", "E030", "E031"
    };
    const char *json = p->compiler->error_diagnostic_json, *code, *end;
    bool parse_phase = false;
    if (!json || strlen(json) <= diagnostics ||
        strncmp(p->compiler->error, "error[E", 7) != 0) return false;
    code = strstr(json + diagnostics, "\"code\":\"");
    if (!code) return false;
    for (size_t i = 0; i < sizeof(parse_codes) / sizeof(*parse_codes); ++i)
        if (strncmp(code + 8, parse_codes[i], 4) == 0) parse_phase = true;
    if (parse_phase &&
        (strstr(json + diagnostics, "\"text\":\"unclosed literal string\"") ||
         strstr(json + diagnostics, "\"text\":\"unclosed regular expression\""))) {
        /* The rest of the line is the unclosed token. The parser then skips
         * tokens to the first `}`, nested or not, as the end of the rule. */
        const char *at = p->at < rule_start ? rule_start : p->at;
        yx_parser probe;
        at += strcspn(at, "\n");
        while (*at && *at != '}') {
            if (at[0] == '/' && at[1] == '/') { at += strcspn(at, "\n"); continue; }
            if (at[0] == '/' && at[1] == '*') {
                at += 2;
                while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
                if (*at) at += 2;
                continue;
            }
            if (*at == '"') {
                for (++at; *at && *at != '"' && *at != '\n'; ++at)
                    if (*at == '\\' && at[1] && at[1] != '\n') ++at;
                if (*at == '"') ++at;
                continue;
            }
            ++at;
        }
        p->at = at;
        if (!*at && strstr(json + diagnostics, "found end of file\"")) return true;
        if (!*at) {
            char first_error[sizeof(p->compiler->error)];
            memcpy(first_error, p->compiler->error, sizeof(first_error));
            yx_syntax_expected(p, at, at, "`}`");
            memcpy(p->compiler->error, first_error, sizeof(first_error));
            return true;
        }
        p->at = at + 1;
        probe = *p;
        yx_space(&probe);
        if (*probe.at && !yx_keyword(&probe, "rule") &&
            !yx_keyword(&probe, "private") && !yx_keyword(&probe, "global") &&
            !yx_keyword(&probe, "import") && !yx_keyword(&probe, "include")) {
            probe = *p;
            if (yx_recover_next_rule_keyword(&probe)) p->at = probe.at;
            else p->at += strlen(p->at);
        }
        return true;
    }
    if (parse_phase) {
        yx_parser probe = *p;
        if (probe.at < rule_start) probe.at = rule_start;
        if (probe.at == rule_start) probe.at += strcspn(probe.at, "{");
        if (yx_recover_next_rule_keyword(&probe)) p->at = probe.at;
        else p->at += strlen(p->at);
        return true;
    }
    end = yx_rule_source_end(rule_start);
    if (!end || end < p->at) return false;
    p->at = end;
    return true;
}

static YRX_RESULT yx_parse_source_items(YRX_COMPILER *compiler,
                                        const char *source,
                                        const char *origin,
                                        const yx_sc_result *syntax);

/* Span::MAX (u32::MAX): YARA-X's tokenizer rejects a source of that many
 * bytes or more. Only tests lower the limit. */
static size_t yx_source_size_limit = (size_t)UINT32_MAX;

void yx_set_source_size_limit(size_t limit)
{
    yx_source_size_limit = limit ? limit : (size_t)UINT32_MAX;
}

size_t yx_get_source_size_limit(void)
{
    return yx_source_size_limit;
}

/* A large source split into chunks of whole lines, checked on several
 * threads. The checker reads top-level items one after the other, each from
 * a fresh state, and an item ends with a token that cannot continue it, so
 * when every chunk checks without an error each chunk boundary is an item
 * boundary of the whole source and the whole source has no error either
 * (out of fuel, the whole check reports none for the rest). yx_parse_source
 * then uses no syntax result, as after the whole check. When a chunk has an
 * error or cannot be checked, the whole source is checked as before. */
typedef struct {
    const uint8_t *source;
    const size_t *bounds;
    bool *clean;
} yx_sc_chunks;

static void yx_sc_chunk_task(size_t index, void *context)
{
    const yx_sc_chunks *chunks = context;
    yx_sc_result result;
    bool checked = yx_syntax_check(chunks->source + chunks->bounds[index],
                                   chunks->bounds[index + 1] - chunks->bounds[index], &result);
    chunks->clean[index] = checked && !result.error_count;
    if (checked) yx_sc_result_free(&result);
}

enum { YX_SC_CHUNK_BYTES = 256u << 10 };

/* Whether a line starts like a top-level item. Any line start may bound a
 * chunk (the chunks decide by themselves whether the split holds); one that
 * starts an item keeps a rule of several lines in one chunk, so the chunks of
 * such a source check clean instead of leaving it to the whole check. */
static bool yx_sc_item_line(const char *line, size_t left)
{
    static const char *const words[] = {"rule ", "private ", "global ", "import ", "include "};
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
        size_t width = strlen(words[i]);
        if (left >= width && !memcmp(line, words[i], width)) return true;
    }
    return false;
}

static bool yx_syntax_check_chunked(const char *source, size_t length, yx_sc_result *result)
{
    unsigned threads = yx_parallel_threads(length / YX_SC_CHUNK_BYTES, 1);
    size_t *bounds = threads > 1 ? malloc((threads + 1) * sizeof(*bounds)) : NULL;
    bool *clean = threads > 1 ? calloc(threads, sizeof(*clean)) : NULL;
    size_t count = 0;
    bool all = bounds && clean;
    if (all) {
        bounds[0] = 0;
        for (unsigned i = 1; i < threads; ++i) {
            size_t at = length / threads * i;
            if (at <= bounds[count]) at = bounds[count] + 1;
            while (at < length && source[at - 1] != '\n') ++at;
            /* The next line that starts an item, when there is one. */
            for (size_t item = at; item < length;) {
                const char *newline;
                if (yx_sc_item_line(source + item, length - item)) { at = item; break; }
                newline = memchr(source + item, '\n', length - item);
                if (!newline) break;
                item = (size_t)(newline - source) + 1;
            }
            if (at < length) bounds[++count] = at;
        }
        bounds[++count] = length;
        all = count > 1;
    }
    if (all) {
        yx_sc_chunks chunks = {(const uint8_t *)source, bounds, clean};
        yx_parallel_run(count, (unsigned)count, yx_sc_chunk_task, &chunks);
        for (size_t i = 0; i < count; ++i) all = all && clean[i];
    }
    free(bounds);
    free(clean);
    if (all) {
#ifdef XXYARA_VERIFY_LOAD
        /* The whole check must find no error either. */
        if (!yx_syntax_check((const uint8_t *)source, length, result) || result->error_count) {
            fprintf(stderr, "XXYARA_VERIFY_LOAD: clean chunks of a source with syntax errors\n");
            abort();
        }
        yx_sc_result_free(result);
#endif
        memset(result, 0, sizeof(*result));
        return true;
    }
    return yx_syntax_check((const uint8_t *)source, length, result);
}

YRX_RESULT yx_parse_source(YRX_COMPILER *compiler, const char *source, const char *origin)
{
    size_t start;
    YRX_RESULT result;
    yx_sc_result syntax;
    yx_suppression_scope text_scope;
    bool checked;
    if (!compiler || !compiler->rules || !source) return YRX_INVALID_ARGUMENT;
    start = compiler->error_diagnostic_json ?
        strlen(compiler->error_diagnostic_json) : 0;
    /* A source that is too large is not tokenized at all: the only error
     * is a syntax error at 0..0, and no rule is compiled. */
    if (strlen(source) >= yx_source_size_limit) {
        if (!yx_compiler_syntax_error(compiler, source, origin, 0, 0,
                                      "source file is too large"))
            snprintf(compiler->error, sizeof(compiler->error),
                     "out of memory recording syntax error");
        yx_compiler_order_source_diagnostics(compiler, start, origin);
        yx_compiler_first_source_error(compiler, start);
        return YRX_SYNTAX_ERROR;
    }
    /* With syntax errors, YARA-X's parser decides which items are dropped
     * and what is reported for them; the remaining items compile as
     * usual. */
    /* The diagnostics of this source measure it, find lines in it and
     * look for suppression comments once instead of once each. */
    yx_suppression_scope_begin_text(&text_scope, source);
    checked = yx_syntax_check_chunked(source, strlen(source), &syntax);
    result = yx_parse_source_items(compiler, source, origin,
                                   checked && syntax.error_count ? &syntax : NULL);
    if (checked) yx_sc_result_free(&syntax);
    yx_compiler_order_source_diagnostics(compiler, start, origin);
    yx_suppression_scope_end(&text_scope);
    if (result == YRX_SYNTAX_ERROR) yx_compiler_first_source_error(compiler, start);
    return result;
}

/* Reports the syntax errors of items up to `item`, once each. */
static bool yx_report_syntax_errors(yx_parser *p, const yx_sc_result *syntax,
                                    size_t *next_error, size_t item,
                                    char *first_error)
{
    bool reported = false;
    while (*next_error < syntax->error_count &&
           syntax->errors[*next_error].item <= item) {
        const yx_sc_error *error = &syntax->errors[(*next_error)++];
        YRX_COMPILER *compiler = p->compiler;
        int recorded = 1;
        switch (error->code) {
        case 27:
            recorded = yx_compiler_invalid_integer_error(
                compiler, p->begin, p->origin, error->start, error->end,
                error->message);
            break;
        case 29:
            recorded = yx_compiler_invalid_escape_error(
                compiler, p->begin, p->origin, error->start, error->end,
                error->message[0] == 'x');
            break;
        case 30:
            recorded = yx_compiler_invalid_regexp_modifier_error(
                compiler, p->begin, p->origin, error->start, error->end);
            break;
        case 31:
            recorded = yx_compiler_unexpected_escape_sequence_error(
                compiler, p->begin, p->origin, error->start, error->end);
            break;
        default:
            yx_syntax_label(p, p->begin + error->start, p->begin + error->end,
                            error->message);
        }
        if (!recorded)
            snprintf(compiler->error, sizeof(compiler->error),
                     "out of memory recording syntax error");
        if (!first_error[0])
            memcpy(first_error, p->compiler->error, sizeof(p->compiler->error));
        reported = true;
    }
    return reported;
}

typedef struct { char *name; size_t start, end; } yx_seen_import;
struct yx_seen_imports { yx_seen_import *items; size_t count; };

/* Compiler::c_items warns about a module imported again by the same source
 * (before importing it), naming the previous import of that module. */
static bool yx_note_import(yx_parser *p, const char *name, size_t start,
                           size_t end)
{
    struct yx_seen_imports *seen = p->seen_imports;
    yx_seen_import *grown;
    if (!seen) return true;
    for (size_t i = 0; i < seen->count; ++i) {
        if (strcmp(seen->items[i].name, name) != 0) continue;
        if (!yx_compiler_duplicate_import_warning(
                p->compiler, name, p->begin, p->origin, seen->items[i].start,
                seen->items[i].end, start, end))
            return false;
        seen->items[i].start = start;
        seen->items[i].end = end;
        return true;
    }
    grown = realloc(seen->items, (seen->count + 1) * sizeof(*grown));
    if (!grown) return false;
    seen->items = grown;
    grown[seen->count].name = yx_duplicate(name, strlen(name));
    if (!grown[seen->count].name) return false;
    grown[seen->count].start = start;
    grown[seen->count].end = end;
    ++seen->count;
    return true;
}

static YRX_RESULT yx_parse_source_items_in(YRX_COMPILER *compiler,
                                           const char *source,
                                           const char *origin,
                                           const yx_sc_result *syntax,
                                           struct yx_seen_imports *imports);

static YRX_RESULT yx_parse_source_items(YRX_COMPILER *compiler,
                                        const char *source,
                                        const char *origin,
                                        const yx_sc_result *syntax)
{
    struct yx_seen_imports imports = {0};
    YRX_RESULT result = yx_parse_source_items_in(compiler, source, origin,
                                                 syntax, &imports);
    for (size_t i = 0; i < imports.count; ++i) free(imports.items[i].name);
    free(imports.items);
    return result;
}

static YRX_RESULT yx_parse_source_items_in(YRX_COMPILER *compiler,
                                           const char *source,
                                           const char *origin,
                                           const yx_sc_result *syntax,
                                           struct yx_seen_imports *imports)
{
    if (!compiler || !compiler->rules || !source) return YRX_INVALID_ARGUMENT;
    yx_parser p = {.compiler = compiler, .begin = source, .at = source,
                   .origin = origin,
                   .source_serial = ++compiler->next_source_serial,
                   .seen_imports = imports};
    bool had_errors = false;
    bool previous_statement_was_rule = false;
    char first_recoverable_error[sizeof(compiler->error)] = {0};
    size_t syntax_item = 0, syntax_error = 0;
    compiler->error[0] = 0;
    while (1) {
        yx_space(&p);
        if (syntax) {
            /* Items YARA-X drops are skipped, as are the tokens its
             * recovery discards after an item. */
            size_t offset = (size_t)(p.at - source);
            bool skip = false;
            if (p.unterminated_comment) {
                p.unterminated_comment = false;
                offset = strlen(source);
                p.at = source + offset;
            }
            while (syntax_item < syntax->item_count) {
                const yx_sc_item *item = &syntax->items[syntax_item];
                if (offset >= item->full_end && item->full_end > item->start) {
                    if (yx_report_syntax_errors(&p, syntax, &syntax_error,
                                                syntax_item,
                                                first_recoverable_error))
                        had_errors = true;
                    ++syntax_item;
                    continue;
                }
                if (offset >= item->start &&
                    (item->dropped || offset >= item->end)) {
                    yx_report_syntax_errors(&p, syntax, &syntax_error,
                                            syntax_item,
                                            first_recoverable_error);
                    had_errors = true;
                    p.at = source + item->full_end;
                    ++syntax_item;
                    skip = true;
                }
                break;
            }
            if (skip) continue;
            if (!*p.at) {
                if (yx_report_syntax_errors(&p, syntax, &syntax_error,
                                            SIZE_MAX,
                                            first_recoverable_error))
                    had_errors = true;
            }
        }
        if (p.unterminated_comment) {
            yx_syntax_label(
                &p, p.unterminated_comment_start, p.at,
                compiler->rules->rule_count ? "unclosed comment" :
                "expecting import statement or rule definition");
            return YRX_SYNTAX_ERROR;
        }
        if (!*p.at) {
            if (had_errors && first_recoverable_error[0])
                memcpy(compiler->error, first_recoverable_error,
                       sizeof(first_recoverable_error));
            return had_errors ? YRX_SYNTAX_ERROR : YRX_SUCCESS;
        }
        const char *statement_start = p.at;
        if (yx_keyword(&p, "import")) {
            previous_statement_was_rule = false;
            size_t length = 0;
            if (yx_reject_escaped_name_string(&p)) {
                /* The quoted name has been consumed. Continue compiling
                 * later declarations after a recorded E031, but stop if
                 * recording the diagnostic itself failed. */
                if (strncmp(compiler->error, "error[E031]:", 12) != 0)
                    return YRX_SYNTAX_ERROR;
                p.recoverable_invalid_pattern = false;
                had_errors = true;
                continue;
            }
            yx_space(&p);
            if (*p.at != '"') {
                const char *token_end = yx_syntax_token_end(p.at);
                yx_syntax_expected(&p, p.at, token_end, "STRING");
                had_errors = true;
                if (!*p.at) return YRX_SYNTAX_ERROR;
                if (strncmp(p.at, "rule", 4) == 0 &&
                    !yx_ident_continue_width(p.at + 4)) continue;
                yx_syntax_label(&p, p.at, token_end,
                                "expecting import statement or rule definition");
                if (!yx_recover_rule_after_import_line(&p))
                    return YRX_SYNTAX_ERROR;
                continue;
            }
            const char *name_start = p.at;
            uint8_t *name = yx_string(&p, &length);
            int policy;
            if (!name) {
                if (*p.at == '\n') {
                    yx_parser probe = p;
                    if (yx_recover_rule_after_import_line(&probe)) {
                        yx_syntax_label(&p, name_start, p.at,
                                        "expecting import statement or rule definition");
                        p.at = probe.at;
                        had_errors = true;
                        continue;
                    }
                }
                if (strstr(compiler->error, "unclosed literal string") != NULL)
                    yx_syntax_label(&p, name_start, p.at,
                                    "expecting import statement or rule definition");
                return YRX_SYNTAX_ERROR;
            }
            if (!yx_note_import(&p, (const char *)name,
                                (size_t)(statement_start - source),
                                (size_t)(p.at - source))) {
                free(name);
                yx_error(&p, "out of memory recording duplicate import");
                return YRX_SYNTAX_ERROR;
            }
            policy = yx_compiler_check_import(
                compiler, (const char *) name, source, origin,
                (size_t)(statement_start - source), (size_t)(p.at - source));
            if (!policy) { free(name); return YRX_SYNTAX_ERROR; }
            if (policy == 2) { free(name); continue; }
            if (policy == 3) { free(name); had_errors = true; continue; }
            if (policy == 4) {
                if (!first_recoverable_error[0])
                    memcpy(first_recoverable_error, compiler->error,
                           sizeof(first_recoverable_error));
                had_errors = true;
            }
            char **grown = realloc(compiler->rules->imports,
                                   (compiler->rules->import_count + 1) * sizeof(char *));
            if (!grown) {
                free(name);
                yx_error(&p, "out of memory");
                return YRX_SYNTAX_ERROR;
            }
            compiler->rules->imports = grown;
            size_t *positions=realloc(compiler->rules->import_rule_indices,(compiler->rules->import_count+1)*sizeof(*positions));
            if(!positions){free(name);yx_error(&p,"out of memory");return YRX_SYNTAX_ERROR;}
            compiler->rules->import_rule_indices=positions;
            size_t *scope_indices=realloc(compiler->rules->import_namespace_indices,(compiler->rules->import_count+1)*sizeof(*scope_indices));
            if(!scope_indices){free(name);yx_error(&p,"out of memory");return YRX_SYNTAX_ERROR;}
            compiler->rules->import_namespace_indices=scope_indices;
            char **namespaces=realloc(compiler->rules->import_namespaces,(compiler->rules->import_count+1)*sizeof(*namespaces));
            if(!namespaces){free(name);yx_error(&p,"out of memory");return YRX_SYNTAX_ERROR;}
            compiler->rules->import_namespaces=namespaces;
            const char *ns_name=compiler->current_namespace?compiler->current_namespace:"default";
            char *ns=yx_duplicate(ns_name,strlen(ns_name));
            if(!ns){free(name);yx_error(&p,"out of memory");return YRX_SYNTAX_ERROR;}
            size_t index=compiler->rules->import_count;
            positions[index]=compiler->rules->rule_count;scope_indices[index]=compiler->current_namespace_index;namespaces[index]=ns;
            compiler->rules->imports[compiler->rules->import_count++] = (char *)name;
            continue;
        }
        if (yx_keyword(&p, "include")) {
            previous_statement_was_rule = false;
            const char *include_start = p.at - strlen("include");
            size_t filename_length = 0;
            size_t include_line = 1;
            size_t initial_diagnostics;
            if (yx_reject_escaped_name_string(&p)) {
                if (strncmp(compiler->error, "error[E031]:", 12) != 0)
                    return YRX_SYNTAX_ERROR;
                p.recoverable_invalid_pattern = false;
                had_errors = true;
                continue;
            }
            uint8_t *filename = yx_string(&p, &filename_length);
            YRX_RESULT result;
            if (!filename) return YRX_SYNTAX_ERROR;
            for (const char *cursor = p.begin; cursor < include_start; ++cursor)
                if (*cursor == '\n') ++include_line;
            initial_diagnostics = compiler->error_diagnostic_json ?
                strlen(compiler->error_diagnostic_json) : 0;
            result = yx_include_source(compiler, (const char *) filename,
                                       filename_length, source, origin,
                                       include_line,
                                       (size_t)(statement_start - source),
                                       (size_t)(p.at - source));
            free(filename);
            if (result != YRX_SUCCESS) {
                /* Structured source errors are recoverable: the reference
                 * compiler continues with later parent rules. A failure
                 * without a new diagnostic (including allocation failure)
                 * must still stop compilation. */
                if (result == YRX_SYNTAX_ERROR &&
                    strncmp(compiler->error, "error[E", 7) == 0 &&
                    compiler->error_diagnostic_json &&
                    strlen(compiler->error_diagnostic_json) >
                        initial_diagnostics) {
                    if (!first_recoverable_error[0])
                        memcpy(first_recoverable_error, compiler->error,
                               sizeof(first_recoverable_error));
                    had_errors = true;
                    continue;
                }
                return result;
            }
            continue;
        }
        bool is_private = false, is_global = false;
        for (;;) {
            if (yx_keyword(&p, "private")) {
                if (is_private) {
                    const char *at = p.at - strlen("private");
                    yx_syntax_expected(&p, at, p.at,
                                       "`global` or `rule`");
                    if (!yx_recover_next_rule_keyword(&p))
                        return YRX_SYNTAX_ERROR;
                    had_errors = true;
                    break;
                }
                is_private = true;
            } else if (yx_keyword(&p, "global")) {
                if (is_global) {
                    const char *at = p.at - strlen("global");
                    yx_syntax_expected(&p, at, p.at,
                                       "`private` or `rule`");
                    if (!yx_recover_next_rule_keyword(&p))
                        return YRX_SYNTAX_ERROR;
                    had_errors = true;
                    break;
                }
                is_global = true;
            }
            else break;
        }
        if (!yx_keyword(&p, "rule")) {
            const char *end = yx_syntax_token_end(p.at);
            if (is_private && !is_global)
                yx_syntax_expected(&p, p.at, end, "`global` or `rule`");
            else if (is_global && !is_private)
                yx_syntax_expected(&p, p.at, end, "`private` or `rule`");
            else
                if (previous_statement_was_rule)
                    yx_syntax_expected(
                        &p, p.at, end,
                        "`global`, `private`, `rule`, `import` or `include`");
                else
                    yx_syntax_label(
                        &p, p.at, end,
                        "expecting import statement or rule definition");
            if (!yx_recover_next_rule_keyword(&p))
                return YRX_SYNTAX_ERROR;
            had_errors = true;
            (void)yx_keyword(&p, "rule");
        }
        size_t rule_diagnostics = compiler->error_diagnostic_json ?
            strlen(compiler->error_diagnostic_json) : 0;
        if (!yx_parse_rule(&p, is_private, is_global)) {
            if (p.recoverable_slow_error) {
                p.recoverable_slow_error = false;
                if (!first_recoverable_error[0])
                    memcpy(first_recoverable_error, compiler->error,
                           sizeof(first_recoverable_error));
                had_errors = true;
                continue;
            }
            if (p.recoverable_rule_keyword) {
                p.recoverable_rule_keyword = false;
                had_errors = true;
                continue;
            }
            if (p.recoverable_bad_initial_section) {
                yx_parser probe = p;
                yx_recover_rule_end(&probe);
                if (*probe.at == '}') {
                    ++probe.at;
                    yx_space(&probe);
                    const char *next_rule = probe.at;
                    if (yx_keyword(&probe, "rule")) {
                        p.recoverable_bad_initial_section = false;
                        had_errors = true;
                        p.at = next_rule;
                        continue;
                    }
                }
            }
            if ((p.recoverable_empty_rule ||
                 p.recoverable_condition_syntax) && *p.at == '}') {
                yx_parser probe = p;
                ++probe.at;
                yx_space(&probe);
                if (yx_keyword(&probe, "rule")) {
                    p.recoverable_empty_rule = false;
                    p.recoverable_condition_syntax = false;
                    had_errors = true;
                    ++p.at;
                    continue;
                }
            }
            if (p.recoverable_invalid_regexp ||
                p.recoverable_invalid_pattern) {
                yx_parser probe = p;
                bool later_rule = p.unclosed_regexp &&
                                  yx_recover_next_rule_keyword(&probe);
                p.recoverable_invalid_regexp = false;
                p.recoverable_invalid_pattern = false;
                yx_recover_rule_end(&p);
                if (*p.at == '}') {
                    had_errors = true;
                    p.unclosed_regexp = false;
                    ++p.at;
                    continue;
                }
                if (p.unclosed_regexp && !later_rule && !*p.at) {
                    char first_error[sizeof(compiler->error)];
                    memcpy(first_error, compiler->error,
                           sizeof(first_error));
                    yx_syntax_expected(&p, p.at, p.at, "`}`");
                    memcpy(compiler->error, first_error,
                           sizeof(first_error));
                }
            }
            if (p.recoverable_unknown_identifier && *p.at == '}') {
                if (!first_recoverable_error[0])
                    memcpy(first_recoverable_error, compiler->error,
                           sizeof(first_recoverable_error));
                p.recoverable_unknown_identifier = false;
                had_errors = true;
                previous_statement_was_rule = true;
                ++p.at;
                continue;
            }
            if (yx_recover_failed_rule(&p, statement_start, rule_diagnostics)) {
                if (!first_recoverable_error[0])
                    memcpy(first_recoverable_error, compiler->error,
                           sizeof(first_recoverable_error));
                had_errors = true;
                previous_statement_was_rule = true;
                continue;
            }
            return YRX_SYNTAX_ERROR;
        }
        previous_statement_was_rule = true;
    }
}
