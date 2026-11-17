/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "cli_regex.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include "native_regex.h"

typedef struct {
    char *text;
    size_t length, capacity;
} yx_rx_buffer;
typedef struct {
    bool i, m, s, u, x, R, U;
} yx_rx_flags;
typedef struct {
    size_t start, end;
} yx_rx_name;
typedef struct {
    const char *text;
    size_t length, at, depth;
    bool bytes, byte_engine;
    size_t class_depth;
    yx_cli_regex_error *error, semantic;
    yx_rx_name *names;
    size_t name_count;
} yx_rx_parser;
/* Identifies a handful of Unicode-wide classes whose repeated Thompson-NFA
 * size (forward AND reverse, regex-automata 0.4.18's builder) is known
 * exactly (see yx_rx_repeat), so {min,max} on them can be checked against
 * the real upstream size limit instead of the generic fallback estimate. */
enum {
    YX_RX_REPEAT_COST_NONE = 0,
    YX_RX_REPEAT_COST_WORD,       /* \w */
    YX_RX_REPEAT_COST_NOT_WORD,   /* \W */
    YX_RX_REPEAT_COST_DIGIT,      /* \d (Unicode) */
    YX_RX_REPEAT_COST_NOT_DIGIT,  /* \D (Unicode) */
    YX_RX_REPEAT_COST_SPACE,      /* \s (Unicode) */
    YX_RX_REPEAT_COST_NOT_SPACE,  /* \S (Unicode) */
    YX_RX_REPEAT_COST_DOT,        /* . (no (?s), no (?R)) */
    YX_RX_REPEAT_COST_PROP_L,     /* \pL / \p{L} */
    YX_RX_REPEAT_COST_PROP_NOT_L, /* \PL / \P{L} */
    YX_RX_REPEAT_COST_PROP_N,     /* \pN / \p{N} */
    YX_RX_REPEAT_COST_PROP_NOT_N  /* \PN / \P{N} */
};
typedef struct {
    char *text;
    bool literal;
    unsigned point;
    size_t start, end;
    int repeat_cost_kind;
} yx_rx_atom;

static char *yx_rx_format(const char *format, ...)
{
    va_list ap, copy;
    va_start(ap, format);
    va_copy(copy, ap);
    int length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    char *result = length < 0 ? NULL : malloc((size_t)length + 1);
    if (result)
        vsnprintf(result, (size_t)length + 1, format, ap);
    va_end(ap);
    return result;
}
static bool yx_rx_append(yx_rx_buffer *out, const char *text)
{
    size_t length = strlen(text);
    if (length > SIZE_MAX - out->length - 1)
        return false;
    if (out->length + length + 1 > out->capacity) {
        size_t capacity = out->length + length + 64;
        char *grown = realloc(out->text, capacity);
        if (!grown)
            return false;
        out->text = grown;
        out->capacity = capacity;
    }
    memcpy(out->text + out->length, text, length + 1);
    out->length += length;
    return true;
}
static void yx_rx_error(yx_rx_parser *p, size_t start, size_t end,
                        const char *message)
{
    if (p->error->message[0])
        return;
    snprintf(p->error->message, sizeof(p->error->message), "%s", message);
    p->error->start = start;
    p->error->end = end;
}
static void yx_rx_semantic(yx_rx_parser *p, size_t start, size_t end,
                           const char *message)
{
    if (p->semantic.message[0])
        return;
    snprintf(p->semantic.message, sizeof(p->semantic.message), "%s", message);
    p->semantic.start = start;
    p->semantic.end = end;
}
static void yx_rx_nesting_error(yx_rx_parser *p, size_t start,
                                char open, char close)
{
    size_t end = start + 1, nesting = 1;
    while (end < p->length && nesting) {
        char c = p->text[end++];
        if (c == '\\' && end < p->length) ++end;
        else if (c == open) ++nesting;
        else if (c == close) --nesting;
    }
    yx_rx_error(p, start, end,
        "exceed the maximum number of nested parentheses/brackets (250)");
}

static char *yx_rx_oom(yx_rx_parser *p)
{
    yx_rx_error(p, p->at, p->at, "out of memory");
    return NULL;
}
static unsigned yx_rx_point(yx_rx_parser *p)
{
    unsigned c = (unsigned char)p->text[p->at++];
    unsigned count = c < 0xc0 ? 0 : c < 0xe0 ? 1 : c < 0xf0 ? 2 : 3;
    if (!count)
        return c;
    c &= (1u << (6 - count)) - 1;
    while (count-- && p->at < p->length)
        c = (c << 6) | ((unsigned char)p->text[p->at++] & 63);
    return c;
}
static void yx_rx_space(yx_rx_parser *p, yx_rx_flags flags)
{
    if (!flags.x)
        return;
    while (p->at < p->length) {
        if (strchr(" \t\r\n\v\f", p->text[p->at]) && p->text[p->at])
            ++p->at;
        else if (p->text[p->at] == '#')
            while (p->at < p->length && p->text[p->at] != '\n')
                ++p->at;
        else
            break;
    }
}
/* A byte-regex may mix Unicode atoms and explicit non-Unicode atoms. Encode
 * the Unicode atoms as byte-range alternatives before giving them to PCRE. */
static size_t yx_rx_utf8(unsigned point, unsigned char bytes[4])
{
    if (point < 0x80) {
        bytes[0] = (unsigned char)point;
        return 1;
    }
    size_t length = point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
    for (size_t i = length - 1; i; --i) {
        bytes[i] = (unsigned char)(0x80 | (point & 63));
        point >>= 6;
    }
    bytes[0] = (unsigned char)((length == 2   ? 0xc0
                                : length == 3 ? 0xe0
                                              : 0xf0) |
                               point);
    return length;
}
static bool yx_rx_byte_span(yx_rx_buffer *out, unsigned low, unsigned high)
{
    char text[32];
    if (low == high)
        snprintf(text, sizeof(text), "\\x%02x", low);
    else
        snprintf(text, sizeof(text), "[\\x%02x-\\x%02x]", low, high);
    return yx_rx_append(out, text);
}
static bool yx_rx_byte_range(yx_rx_buffer *out, const unsigned char *low,
                             const unsigned char *high, size_t length)
{
    if (!length)
        return true;
    if (low[0] == high[0])
        return yx_rx_byte_span(out, low[0], low[0]) &&
               yx_rx_byte_range(out, low + 1, high + 1, length - 1);
    if (length == 1)
        return yx_rx_byte_span(out, low[0], high[0]);
    unsigned char minimum[4] = {0x80, 0x80, 0x80, 0x80};
    unsigned char maximum[4] = {0xbf, 0xbf, 0xbf, 0xbf};
    if (!yx_rx_append(out, "(?:") || !yx_rx_byte_span(out, low[0], low[0]) ||
        !yx_rx_byte_range(out, low + 1, maximum, length - 1))
        return false;
    if (low[0] + 1 < high[0]) {
        if (!yx_rx_append(out, "|") ||
            !yx_rx_byte_span(out, low[0] + 1, high[0] - 1))
            return false;
        for (size_t i = 1; i < length; ++i)
            if (!yx_rx_byte_span(out, 0x80, 0xbf))
                return false;
    }
    return yx_rx_append(out, "|") && yx_rx_byte_span(out, high[0], high[0]) &&
           yx_rx_byte_range(out, minimum, high + 1, length - 1) &&
           yx_rx_append(out, ")");
}
static bool yx_rx_scalar_range(yx_rx_buffer *out, unsigned low, unsigned high)
{
    static const unsigned limits[] = {0x7f,   0x7ff,  0xd7ff,
                                      0xdfff, 0xffff, 0x10ffff};
    while (low <= high) {
        if (low >= 0xd800 && low <= 0xdfff) {
            low = 0xe000;
            continue;
        }
        unsigned end = high;
        for (size_t i = 0; i < sizeof(limits) / sizeof(*limits); ++i)
            if (low <= limits[i] && end > limits[i]) {
                end = limits[i];
                break;
            }
        unsigned char first[4], last[4];
        size_t length = yx_rx_utf8(low, first);
        yx_rx_utf8(end, last);
        if (out->length && !yx_rx_append(out, "|"))
            return false;
        if (!yx_rx_byte_range(out, first, last, length))
            return false;
        low = end + 1;
    }
    return true;
}
static char *yx_rx_unicode_bytes(yx_rx_parser *p, char *pattern)
{
    if (!p->byte_engine || !pattern)
        return pattern;
    int error;
    PCRE2_SIZE offset;
    pcre2_code *code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                     PCRE2_UTF | PCRE2_UCP | PCRE2_ANCHORED |
                                         PCRE2_ENDANCHORED,
                                     &error, &offset, NULL);
    if (!code)
        return pattern; /* A deferred semantic error owns this case. */
    pcre2_match_data *match = pcre2_match_data_create_from_pattern(code, NULL);
    if (!match) {
        pcre2_code_free(code);
        free(pattern);
        return yx_rx_oom(p);
    }
    yx_rx_buffer out = {0};
    unsigned start = UINT32_MAX;
    bool ok = true;
    for (unsigned point = 0; point <= 0x110000; ++point) {
        bool matched = false;
        if (point <= 0x10ffff && !(point >= 0xd800 && point <= 0xdfff)) {
            unsigned char data[4];
            size_t length = yx_rx_utf8(point, data);
            matched = pcre2_match(code, data, length, 0, 0, match, NULL) >= 0;
        }
        if (matched && start == UINT32_MAX)
            start = point;
        else if (!matched && start != UINT32_MAX) {
            if (!yx_rx_scalar_range(&out, start, point - 1)) {
                ok = false;
                break;
            }
            start = UINT32_MAX;
        }
    }
    pcre2_match_data_free(match);
    pcre2_code_free(code);
    free(pattern);
    char *result =
        ok ? yx_rx_format(out.length ? "(?:%s)" : "(?!)", out.text) : NULL;
    free(out.text);
    return result ? result : yx_rx_oom(p);
}
static char *yx_rx_literal(unsigned point, yx_rx_flags flags)
{
    return yx_rx_format(flags.i ? "(?i:\\x{%x})" : "\\x{%x}", point);
}
static char *yx_rx_class_named(char c, yx_rx_flags flags)
{
    const char *body;
    switch (tolower((unsigned char)c)) {
    case 'd':
        body = flags.u ? "\\p{Nd}" : "0-9";
        break;
    case 's':
        body = flags.u
                   ? "\\x{9}-\\x{d}\\x{20}\\x{85}\\x{a0}\\x{1680}\\x{2000}-\\x{"
                     "200a}\\x{2028}\\x{2029}\\x{202f}\\x{205f}\\x{3000}"
                   : "\\x{9}-\\x{d}\\x{20}";
        break;
    default:
        body = flags.u ? "\\p{Alphabetic}\\p{M}\\p{Nd}\\p{Pc}\\x{200c}\\x{200d}"
                       : "A-Za-z0-9_";
        break;
    }
    return yx_rx_format("[%s%s]", isupper((unsigned char)c) ? "^" : "", body);
}
static char *yx_rx_boundary(yx_rx_parser *p, yx_rx_flags flags,
                            const char *kind)
{
    char *word = yx_rx_class_named('w', flags), *result = NULL;
    if (flags.u)
        word = yx_rx_unicode_bytes(p, word);
    if (!word)
        return NULL;
    if (strcmp(kind, "start") == 0)
        result = yx_rx_format("(?<!%s)(?=%s)", word, word);
    else if (strcmp(kind, "end") == 0)
        result = yx_rx_format("(?<=%s)(?!%s)", word, word);
    else if (strcmp(kind, "start-half") == 0)
        result = yx_rx_format("(?<!%s)", word);
    else if (strcmp(kind, "end-half") == 0)
        result = yx_rx_format("(?!%s)", word);
    else if (strcmp(kind, "B") == 0)
        result = yx_rx_format("(?:(?<=%s)(?=%s)|(?<!%s)(?!%s))", word, word,
                              word, word);
    else
        result = yx_rx_format("(?:(?<!%s)(?=%s)|(?<=%s)(?!%s))", word, word,
                              word, word);
    free(word);
    return result;
}
static char *yx_rx_property(yx_rx_parser *p, size_t start, const char *name,
                            size_t length, bool negate, yx_rx_flags flags)
{
    char property[160];
    size_t out = 0;
    for (size_t i = 0; i < length && out + 1 < sizeof(property); ++i)
        if (name[i] != '_' && name[i] != '-' &&
            !isspace((unsigned char)name[i]))
            property[out++] = name[i];
    property[out] = 0;
    const char *value = property;
    char *equals = strchr(property, '=');
    if (equals) {
        *equals++ = 0;
        if (strcmp(property, "gc") == 0 ||
            strcmp(property, "GeneralCategory") == 0 ||
            strcmp(property, "generalcategory") == 0)
            value = equals;
        else if (strcmp(property, "Script") == 0 ||
                 strcmp(property, "script") == 0 || strcmp(property, "sc") == 0)
            value = equals;
        else {
            equals[-1] = '=';
            value = property;
        }
    }
    if (strncmp(value, "Is", 2) == 0)
        value += 2;
    /* Rust matches property names loosely (case, `_`, `-` and spaces
     * ignored). The PCRE2 shim lacks the binary White_Space property, so
     * spell it as the `\s` class it equals (aliases WSpace and space). */
    char loose[160];
    size_t loose_length = 0;
    for (const char *at = value; *at && loose_length + 1 < sizeof(loose); ++at)
        loose[loose_length++] = (char)tolower((unsigned char)*at);
    loose[loose_length] = 0;
    if (strcmp(loose, "whitespace") == 0 || strcmp(loose, "wspace") == 0 ||
        strcmp(loose, "space") == 0) {
        if (!flags.u)
            yx_rx_semantic(p, start, p->at, "Unicode not allowed here");
        char *spaces = yx_rx_class_named(negate ? 'S' : 's', flags);
        return spaces ? spaces : yx_rx_oom(p);
    }
    const char *alias = value;
    if (strcmp(value, "Letter") == 0)
        alias = "L";
    else if (strcmp(value, "Number") == 0)
        alias = "N";
    else if (strcmp(value, "DecimalNumber") == 0)
        alias = "Nd";
    else if (strcmp(value, "LowercaseLetter") == 0)
        alias = "Ll";
    else if (strcmp(value, "UppercaseLetter") == 0)
        alias = "Lu";
    else if (strcmp(value, "Mark") == 0)
        alias = "M";
    else if (strcmp(value, "Punctuation") == 0)
        alias = "P";
    else if (strcmp(value, "Separator") == 0)
        alias = "Z";
    else if (strcmp(value, "Symbol") == 0)
        alias = "S";
    char *result = strcmp(alias, "ASCII") == 0
                       ? yx_rx_format("[%s\\x{0}-\\x{7f}]", negate ? "^" : "")
                       : yx_rx_format("\\%c{%s}", negate ? 'P' : 'p', alias);
    if (!result)
        return yx_rx_oom(p);
    int code;
    PCRE2_SIZE offset;
    pcre2_code *compiled =
        pcre2_compile((PCRE2_SPTR)result, PCRE2_ZERO_TERMINATED,
                      PCRE2_UTF | PCRE2_UCP, &code, &offset, NULL);
    if (!flags.u)
        yx_rx_semantic(p, start, p->at, "Unicode not allowed here");
    else if (!compiled)
        yx_rx_semantic(p, start, p->at, "Unicode property not found");
    pcre2_code_free(compiled);
    return result;
}
static yx_rx_atom yx_rx_escape(yx_rx_parser *p, yx_rx_flags flags,
                               bool in_class)
{
    yx_rx_atom atom = {0};
    atom.start = p->at++;
    if (p->at == p->length) {
        yx_rx_error(
            p, atom.start, p->at,
            "incomplete escape sequence, reached end of pattern prematurely");
        return atom;
    }
    unsigned char c = (unsigned char)p->text[p->at++];
    if (c >= '0' && c <= '9') {
        yx_rx_error(p, atom.start, p->at, "backreferences are not supported");
        return atom;
    }
    if (strchr("dDsSwW", c)) {
        atom.text = yx_rx_class_named(c, flags);
        if (!flags.u && !p->bytes && isupper(c))
            yx_rx_semantic(p, atom.start, p->at,
                           "pattern can match invalid UTF-8");
        /* The exact per-repetition NFA cost below is only known for these
         * classes under Unicode mode (upstream's default); (?-u) rewrites
         * them to small ASCII-only ranges that are never expensive. */
        if (flags.u)
            switch (c) {
            case 'w': atom.repeat_cost_kind = YX_RX_REPEAT_COST_WORD; break;
            case 'W': atom.repeat_cost_kind = YX_RX_REPEAT_COST_NOT_WORD; break;
            case 'd': atom.repeat_cost_kind = YX_RX_REPEAT_COST_DIGIT; break;
            case 'D': atom.repeat_cost_kind = YX_RX_REPEAT_COST_NOT_DIGIT; break;
            case 's': atom.repeat_cost_kind = YX_RX_REPEAT_COST_SPACE; break;
            case 'S': atom.repeat_cost_kind = YX_RX_REPEAT_COST_NOT_SPACE; break;
            default: break;
            }
    } else if (c == 'p' || c == 'P') {
        size_t begin = p->at, end = begin;
        if (p->at < p->length && p->text[p->at] == '{') {
            begin = ++p->at;
            while (p->at < p->length && p->text[p->at] != '}')
                ++p->at;
            end = p->at;
            if (p->at == p->length) {
                yx_rx_error(p, p->at, p->at,
                            "incomplete escape sequence, reached end of "
                            "pattern prematurely");
                return atom;
            }
            ++p->at;
        } else if (p->at < p->length) {
            yx_rx_point(p);
            end = p->at;
        } else {
            yx_rx_error(p, p->at, p->at,
                        "incomplete escape sequence, reached end of pattern "
                        "prematurely");
            return atom;
        }
        atom.text = yx_rx_property(p, atom.start, p->text + begin, end - begin,
                                   c == 'P', flags);
        /* Only the plain Letter/Number general categories have a known
         * exact repetition cost below; other properties fall back to the
         * generic estimate. */
        if (flags.u && atom.text)
            if (strcmp(atom.text, "\\p{L}") == 0)
                atom.repeat_cost_kind = YX_RX_REPEAT_COST_PROP_L;
            else if (strcmp(atom.text, "\\P{L}") == 0)
                atom.repeat_cost_kind = YX_RX_REPEAT_COST_PROP_NOT_L;
            else if (strcmp(atom.text, "\\p{N}") == 0)
                atom.repeat_cost_kind = YX_RX_REPEAT_COST_PROP_N;
            else if (strcmp(atom.text, "\\P{N}") == 0)
                atom.repeat_cost_kind = YX_RX_REPEAT_COST_PROP_NOT_N;
    } else if ((c == 'b' || c == 'B' || c == '<' || c == '>') && !in_class) {
        char kind[24] = {(char)c, 0};
        if (c == '<')
            strcpy(kind, "start");
        if (c == '>')
            strcpy(kind, "end");
        if (c == 'b' && p->at < p->length && p->text[p->at] == '{') {
            size_t begin = ++p->at;
            while (p->at < p->length && p->text[p->at] != '}')
                ++p->at;
            size_t length = p->at - begin;
            if (length >= sizeof(kind))
                length = sizeof(kind) - 1;
            memcpy(kind, p->text + begin, length);
            kind[length] = 0;
            if (strcmp(kind, "start") && strcmp(kind, "end") &&
                strcmp(kind, "start-half") && strcmp(kind, "end-half")) {
                yx_rx_error(
                    p, begin, p->at,
                    "unrecognized special word boundary assertion, valid "
                    "choices are: start, end, start-half or end-half");
                return atom;
            }
            if (p->at < p->length)
                ++p->at;
        }
        atom.text = yx_rx_boundary(p, flags, kind);
    } else if ((c == 'A' || c == 'z') && !in_class)
        atom.text = yx_rx_format("\\%c", c);
    else if (c == 'x' || c == 'u' || c == 'U') {
        unsigned value = 0;
        size_t begin = p->at, count = c == 'x' ? 2 : c == 'u' ? 4 : 8;
        bool braced = p->at < p->length && p->text[p->at] == '{';
        if (braced) {
            begin = ++p->at;
            count = SIZE_MAX;
        }
        size_t digits = 0;
        while (digits < count && p->at < p->length &&
               !(braced && p->text[p->at] == '}')) {
            char digit = p->text[p->at];
            if (!isxdigit((unsigned char)digit)) {
                yx_rx_error(p, p->at, p->at + 1, "invalid hexadecimal digit");
                return atom;
            }
            if (value <= 0x110000)
                value =
                    value * 16 +
                    (digit <= '9' ? digit - '0'
                                  : tolower((unsigned char)digit) - 'a' + 10);
            ++p->at;
            ++digits;
        }
        if ((!braced && digits < count) || (braced && p->at == p->length)) {
            yx_rx_error(p, braced && !digits ? p->at - 1 : p->at, p->at,
                        "incomplete escape sequence, reached end of pattern "
                        "prematurely");
            return atom;
        }
        size_t end = p->at;
        if (braced)
            ++p->at;
        if (!digits) {
            yx_rx_error(p, begin - 1, p->at, "hexadecimal literal empty");
            return atom;
        }
        if (value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
            yx_rx_error(p, begin, end,
                        "hexadecimal literal is not a Unicode scalar value");
            return atom;
        }
        atom.literal = true;
        atom.point = value;
        bool byte_escape = c == 'x' && !braced;
        if (!flags.u && value >= 128) {
            if (!byte_escape && in_class)
                yx_rx_semantic(p, atom.start, p->at,
                               "Unicode not allowed here");
            else if (byte_escape && !p->bytes)
                yx_rx_semantic(p, atom.start, p->at,
                               "pattern can match invalid UTF-8");
        }
        atom.text = yx_rx_literal(value, flags);
        if (!flags.u && !in_class && !byte_escape && value >= 128)
            atom.text = yx_rx_unicode_bytes(p, atom.text);
    } else {
        unsigned point = c;
        switch (c) {
        case 'a':
            point = 7;
            break;
        case 'f':
            point = 12;
            break;
        case 't':
            point = 9;
            break;
        case 'n':
            point = 10;
            break;
        case 'r':
            point = 13;
            break;
        case 'v':
            point = 11;
            break;
        default:
            if (isalnum(c) || c == '_' || c >= 128) {
                yx_rx_error(p, atom.start, p->at,
                            "unrecognized escape sequence");
                return atom;
            }
        }
        atom.literal = true;
        atom.point = point;
        atom.text = yx_rx_literal(point, flags);
    }
    if (flags.u && !in_class && (atom.literal || strchr("dDsSwWpP", c)))
        atom.text = yx_rx_unicode_bytes(p, atom.text);
    atom.end = p->at;
    if (!atom.text && !p->error->message[0])
        yx_rx_oom(p);
    return atom;
}
static char *yx_rx_class(yx_rx_parser *, yx_rx_flags);
static yx_rx_atom yx_rx_class_atom(yx_rx_parser *p, yx_rx_flags flags)
{
    yx_rx_atom result = {0};
    result.start = p->at;
    if (p->text[p->at] == '\\')
        return yx_rx_escape(p, flags, true);
    if (p->text[p->at] == '[') {
        /* An unknown POSIX name is a nested literal class in Rust syntax. */
        if (p->at + 2 < p->length && p->text[p->at + 1] == ':') {
            static const struct {
                const char *name, *body;
            } classes[] = {{"alnum", "A-Za-z0-9"},
                           {"alpha", "A-Za-z"},
                           {"ascii", "\\x{0}-\\x{7f}"},
                           {"blank", "\\t "},
                           {"cntrl", "\\x{0}-\\x{1f}\\x{7f}"},
                           {"digit", "0-9"},
                           {"graph", "!-~"},
                           {"lower", "a-z"},
                           {"print", " -~"},
                           {"punct", "!-/:-@[-`{-~"},
                           {"space", "\\x{9}-\\x{d} "},
                           {"upper", "A-Z"},
                           {"word", "A-Za-z0-9_"},
                           {"xdigit", "A-Fa-f0-9"}};
            size_t begin = p->at + 2;
            bool negate = p->text[begin] == '^';
            begin += negate;
            for (size_t i = 0; i < sizeof(classes) / sizeof(*classes); ++i) {
                size_t len = strlen(classes[i].name);
                if (begin + len + 2 <= p->length &&
                    !memcmp(p->text + begin, classes[i].name, len) &&
                    !memcmp(p->text + begin + len, ":]", 2)) {
                    p->at = begin + len + 2;
                    result.text = yx_rx_format("[%s%s]", negate ? "^" : "",
                                               classes[i].body);
                    result.end = p->at;
                    return result;
                }
            }
        }
        result.text = yx_rx_class(p, flags);
    } else {
        result.literal = true;
        result.point = yx_rx_point(p);
        if (!flags.u && result.point >= 128)
            yx_rx_semantic(p, result.start, p->at, "Unicode not allowed here");
        result.text = yx_rx_literal(result.point, flags);
    }
    result.end = p->at;
    return result;
}
static char *yx_rx_class_union(yx_rx_parser *p, yx_rx_flags flags, bool *first)
{
    yx_rx_buffer out = {0};
    while (p->at < p->length) {
        yx_rx_space(p, flags);
        if (p->at == p->length)
            break;
        char c = p->text[p->at];
        if ((c == ']' && !*first) ||
            ((!*first || c != '-') && p->at + 1 < p->length &&
             strchr("&-~", c) && p->text[p->at + 1] == c))
            break;
        *first = false;
        yx_rx_atom left = yx_rx_class_atom(p, flags);
        if (!left.text) {
            free(out.text);
            return NULL;
        }
        yx_rx_space(p, flags);
        if (p->at + 1 < p->length && p->text[p->at] == '-' &&
            p->text[p->at + 1] != ']' && p->text[p->at + 1] != '-') {
            ++p->at;
            yx_rx_space(p, flags);
            yx_rx_atom right = yx_rx_class_atom(p, flags);
            if (!right.text) {
                free(left.text);
                free(out.text);
                return NULL;
            }
            if (!left.literal || !right.literal) {
                yx_rx_atom *bad = !left.literal ? &left : &right;
                yx_rx_error(p, bad->start, bad->end,
                            "invalid range boundary, must be a literal");
            } else if (left.point > right.point)
                yx_rx_error(p, left.start, right.end,
                            "invalid character class range, the start must be "
                            "<= the end");
            char *range = yx_rx_format(flags.i ? "(?i:[\\x{%x}-\\x{%x}])"
                                               : "[\\x{%x}-\\x{%x}]",
                                       left.point, right.point);
            free(left.text);
            free(right.text);
            left.text = range;
        }
        if ((out.length && !yx_rx_append(&out, "|")) || !left.text ||
            !yx_rx_append(&out, left.text)) {
            free(left.text);
            free(out.text);
            return yx_rx_oom(p);
        }
        free(left.text);
        if (p->error->message[0]) {
            free(out.text);
            return NULL;
        }
    }
    char *result =
        out.length ? yx_rx_format("(?:%s)", out.text) : yx_rx_format("(?!)");
    free(out.text);
    return result;
}
static char *yx_rx_class(yx_rx_parser *p, yx_rx_flags flags)
{
    size_t start = p->at++;
    ++p->class_depth;
    if (p->class_depth + p->depth > 250) {
        yx_rx_nesting_error(p, start, '[', ']');
        return NULL;
    }
    yx_rx_space(p, flags);
    bool negate = p->at < p->length && p->text[p->at] == '^';
    if (negate)
        ++p->at;
    bool first = true;
    char *left = yx_rx_class_union(p, flags, &first);
    if (!left)
        return NULL;
    while (p->at + 1 < p->length && strchr("&-~", p->text[p->at]) &&
           p->text[p->at] == p->text[p->at + 1]) {
        char op = p->text[p->at];
        p->at += 2;
        first = false;
        char *right = yx_rx_class_union(p, flags, &first);
        if (!right) {
            free(left);
            return NULL;
        }
        char *combined = op == '&'   ? yx_rx_format("(?=%s)%s", left, right)
                         : op == '-' ? yx_rx_format("(?!%s)%s", right, left)
                                     : yx_rx_format("(?:(?!%s)%s|(?!%s)%s)",
                                                    right, left, left, right);
        free(left);
        free(right);
        left = combined;
        if (!left)
            return yx_rx_oom(p);
    }
    if (p->at == p->length || p->text[p->at] != ']') {
        size_t end = start + 1;
        if (p->length - start <= 3 && p->length &&
            p->text[p->length - 1] == ']')
            end = p->length;
        yx_rx_error(p, start, end, "unclosed character class");
        free(left);
        return NULL;
    }
    ++p->at;
    if (negate) {
        char *other = yx_rx_format("(?!(?:%s))[\\s\\S]", left);
        free(left);
        left = other;
        if (!flags.u && !p->bytes)
            yx_rx_semantic(p, start, p->at, "pattern can match invalid UTF-8");
    }
    --p->class_depth;
    if (flags.u && !p->class_depth)
        left = yx_rx_unicode_bytes(p, left);
    return left;
}
static char *yx_rx_expr(yx_rx_parser *, yx_rx_flags, size_t);
static char *yx_rx_group(yx_rx_parser *p, yx_rx_flags *flags, bool *only_flags)
{
    size_t start = p->at++;
    yx_rx_flags inner = *flags;
    bool capture = true;
    if (++p->depth + p->class_depth > 250) {
        yx_rx_nesting_error(p, start, '(', ')');
        return NULL;
    }
    if (p->at < p->length && p->text[p->at] == '?') {
        ++p->at;
        capture = false;
        if (p->at < p->length &&
            (p->text[p->at] == '=' || p->text[p->at] == '!' ||
             (p->text[p->at] == '<' && p->at + 1 < p->length &&
              strchr("=!", p->text[p->at + 1])))) {
            yx_rx_error(
                p, start, p->at + (p->text[p->at] == '<' ? 2 : 1),
                "look-around, including look-ahead and look-behind, is not "
                "supported");
            return NULL;
        }
        if (p->at < p->length &&
            (p->text[p->at] == '<' ||
             (p->text[p->at] == 'P' && p->at + 1 < p->length &&
              p->text[p->at + 1] == '<'))) {
            p->at += p->text[p->at] == 'P' ? 2 : 1;
            size_t begin = p->at;
            while (p->at < p->length && p->text[p->at] != '>') {
                unsigned char c = (unsigned char)p->text[p->at];
                if (!(c == '_' || isalpha(c) || c >= 128 ||
                      (p->at > begin &&
                       (isdigit(c) || c == '.' || c == '[' || c == ']')))) {
                    yx_rx_error(p, p->at, p->at + 1,
                                "invalid capture group character");
                    return NULL;
                }
                yx_rx_point(p);
            }
            if (p->at == p->length) {
                yx_rx_error(p, p->at, p->at, "unclosed capture group name");
                return NULL;
            }
            if (p->at == begin) {
                yx_rx_error(p, begin, begin, "empty capture group name");
                return NULL;
            }
            for (size_t i = 0; i < p->name_count; ++i)
                if (p->names[i].end - p->names[i].start == p->at - begin &&
                    !memcmp(p->text + p->names[i].start, p->text + begin,
                            p->at - begin)) {
                    yx_rx_error(p, begin, p->at,
                                "duplicate capture group name");
                    p->error->has_secondary = true;
                    p->error->secondary_start = p->names[i].start;
                    p->error->secondary_end = p->names[i].end;
                    return NULL;
                }
            yx_rx_name *grown =
                realloc(p->names, (p->name_count + 1) * sizeof(*grown));
            if (!grown)
                return yx_rx_oom(p);
            p->names = grown;
            p->names[p->name_count++] = (yx_rx_name){begin, p->at};
            ++p->at;
            capture = true;
        } else if (p->at < p->length && p->text[p->at] == ':')
            ++p->at;
        else {
            bool negative = false, any = false;
            size_t positions[128];
            for (size_t i = 0; i < 128; ++i)
                positions[i] = SIZE_MAX;
            size_t dash = SIZE_MAX;
            bool afterdash = false;
            while (p->at < p->length && p->text[p->at] != ')' &&
                   p->text[p->at] != ':') {
                unsigned char c = (unsigned char)p->text[p->at];
                if (c == '-') {
                    if (dash != SIZE_MAX) {
                        yx_rx_error(p, p->at, p->at + 1,
                                    "flag negation operator repeated");
                        p->error->has_secondary = true;
                        p->error->secondary_start = dash;
                        p->error->secondary_end = dash + 1;
                        return NULL;
                    }
                    dash = p->at++;
                    negative = true;
                    afterdash = false;
                    continue;
                }
                bool *field = NULL;
                switch (c) {
                case 'i':
                    field = &inner.i;
                    break;
                case 'm':
                    field = &inner.m;
                    break;
                case 's':
                    field = &inner.s;
                    break;
                case 'u':
                    field = &inner.u;
                    break;
                case 'x':
                    field = &inner.x;
                    break;
                case 'R':
                    field = &inner.R;
                    break;
                case 'U':
                    field = &inner.U;
                    break;
                }
                if (!field) {
                    yx_rx_error(p, p->at, p->at + 1, "unrecognized flag");
                    return NULL;
                }
                if (positions[c] != SIZE_MAX) {
                    yx_rx_error(p, p->at, p->at + 1, "duplicate flag");
                    p->error->has_secondary = true;
                    p->error->secondary_start = positions[c];
                    p->error->secondary_end = positions[c] + 1;
                    return NULL;
                }
                positions[c] = p->at++;
                *field = !negative;
                any = true;
                afterdash = true;
            }
            if (dash != SIZE_MAX && !afterdash) {
                yx_rx_error(p, dash, dash + 1,
                            "dangling flag negation operator");
                return NULL;
            }
            if (p->at == p->length) {
                yx_rx_error(p, any ? p->at : start, any ? p->at : start + 1,
                            any ? "expected flag but got end of regex"
                                : "unclosed group");
                return NULL;
            }
            if (!any) {
                yx_rx_error(p, start + 1, start + 2,
                            "repetition operator missing expression");
                return NULL;
            }
            if (p->text[p->at++] == ')') {
                *flags = inner;
                *only_flags = true;
                --p->depth;
                return yx_rx_format("");
            }
        }
    }
    char *body = yx_rx_expr(p, inner, start);
    if (!body)
        return NULL;
    if (p->at == p->length || p->text[p->at] != ')') {
        yx_rx_error(p, start, start + 1, "unclosed group");
        free(body);
        return NULL;
    }
    ++p->at;
    --p->depth;
    if (!capture && !*body) return body;
    char *result = yx_rx_format(capture ? "(%s)" : "(?:%s)", body);
    free(body);
    return result;
}
/* Exact largest-still-OK repetition count for a handful of Unicode-wide
 * classes, i.e. the largest N for which both the forward AND the reverse
 * Thompson NFA that regex-automata 0.4.18 builds for the single pattern
 * `<class>{N}` stay within upstream's real 10 MiB (10485760-byte) default
 * size_limit. Ported by instrumenting the pinned regex-automata 0.4.18
 * source (nfa/thompson/builder.rs Builder::memory_usage, the quantity
 * check_size_limit() actually compares, which is the *draft* builder size,
 * not the smaller, already-compacted final NFA::memory_usage()) and
 * bisecting N for each class with the real regex::Regex / regex::bytes::Regex
 * construction (meta::Config::nfa_size_limit default = 10*(1<<20)), via a
 * local offline cargo build against the exact cached crate versions YARA-X
 * 1.23.0 pins (regex 1.13.1, regex-automata 0.4.18, regex-syntax 0.8.11).
 * In every one of these classes the reverse direction (compiled with
 * shrink=false, per meta::Regex's Core::new, using the "naive but reuse
 * common suffixes" UTF-8 automaton rather than forward's always-minimal
 * trie) is the binding constraint, so the limits below already fold in
 * both directions. Classes not listed here (arbitrary \p{...} properties,
 * user-written ranges, etc.) fall back to the generic estimate below. */
static uint64_t yx_rx_repeat_cost_limit(int kind)
{
    switch (kind) {
    case YX_RX_REPEAT_COST_WORD: return 209;
    case YX_RX_REPEAT_COST_NOT_WORD: return 225;
    case YX_RX_REPEAT_COST_DIGIT: return 2046;
    case YX_RX_REPEAT_COST_NOT_DIGIT: return 822;
    case YX_RX_REPEAT_COST_SPACE: return 15419;
    case YX_RX_REPEAT_COST_NOT_SPACE: return 5448;
    case YX_RX_REPEAT_COST_DOT: return 10485;
    case YX_RX_REPEAT_COST_PROP_L: return 244;
    case YX_RX_REPEAT_COST_PROP_NOT_L: return 244;
    case YX_RX_REPEAT_COST_PROP_N: return 1074;
    case YX_RX_REPEAT_COST_PROP_NOT_N: return 512;
    default: return UINT64_MAX;
    }
}
static char *yx_rx_repeat(yx_rx_parser *p, yx_rx_flags flags, char *atom,
                          int repeat_cost_kind)
{
    while (p->at < p->length) {
        yx_rx_space(p, flags);
        if (p->at == p->length)
            break;
        size_t start = p->at;
        char c = p->text[p->at];
        if (!strchr("*+?{", c) || !c)
            break;
        char quantifier[80];
        bool simple_literal = strncmp(atom, "\\x{", 3) == 0 &&
                              strchr(atom, '}') == atom + strlen(atom) - 1;
        uint64_t large_min = 0, large_max = 0;
        bool large_count = false, large_unlimited = false;
        bool zero_count = false;
        if (c != '{') {
            quantifier[0] = c;
            quantifier[1] = 0;
            ++p->at;
        } else {
            ++p->at;
            yx_rx_flags count_flags = flags;
            count_flags.x = true;
            yx_rx_space(p, count_flags);
            uint64_t min = 0, max = 0;
            size_t begin = p->at;
            if (p->at == p->length) {
                yx_rx_error(p, start, p->at, "unclosed counted repetition");
                break;
            }
            if (!isdigit((unsigned char)p->text[p->at])) {
                yx_rx_error(p, p->at, p->at,
                            "repetition quantifier expects a valid decimal");
                break;
            }
            while (p->at < p->length &&
                   isdigit((unsigned char)p->text[p->at])) {
                if (min <= UINT32_MAX)
                    min = min * 10 + (unsigned)(p->text[p->at] - '0');
                ++p->at;
            }
            if (min > UINT32_MAX) {
                yx_rx_error(p, begin, p->at, "decimal literal invalid");
                break;
            }
            yx_rx_space(p, count_flags);
            bool comma = p->at < p->length && p->text[p->at] == ',';
            bool unlimited = false;
            max = min;
            if (comma) {
                ++p->at;
                yx_rx_space(p, count_flags);
                begin = p->at;
                max = 0;
                if (p->at == p->length) {
                    yx_rx_error(p, start, p->at, "unclosed counted repetition");
                    break;
                }
                unlimited = p->text[p->at] == '}';
                if (!unlimited && !isdigit((unsigned char)p->text[p->at])) {
                    yx_rx_error(
                        p, p->at, p->at,
                        "repetition quantifier expects a valid decimal");
                    break;
                }
                while (p->at < p->length &&
                       isdigit((unsigned char)p->text[p->at])) {
                    if (max <= UINT32_MAX)
                        max = max * 10 + (unsigned)(p->text[p->at] - '0');
                    ++p->at;
                }
                if (max > UINT32_MAX) {
                    yx_rx_error(p, begin, p->at, "decimal literal invalid");
                    break;
                }
                yx_rx_space(p, count_flags);
            }
            if (p->at == p->length || p->text[p->at] != '}') {
                yx_rx_error(p, start, p->at, "unclosed counted repetition");
                break;
            }
            ++p->at;
            if (comma && !unlimited && min > max) {
                yx_rx_error(p, start, p->at,
                            "invalid repetition count range, the start must be "
                            "<= the end");
                break;
            }
            zero_count = !unlimited && max == 0;
            /* Each retained single-byte literal adds one 32-byte NFA state;
             * the pinned engine reserves seven states for the unanchored
             * search. */
            uint64_t exact_limit = yx_rx_repeat_cost_limit(repeat_cost_kind);
            uint64_t limit = exact_limit != UINT64_MAX ? exact_limit
                             : simple_literal ? 10485760 / 32 - 7 : 1000000;
            if (*atom && !zero_count &&
                (min > limit || (!unlimited && max > limit)))
                p->semantic.size_limit = true;
            if (*atom && !zero_count && simple_literal && !p->semantic.size_limit &&
                (min > 65535 || (!unlimited && max > 65535))) {
                large_count = true;
                large_min = min;
                large_max = max;
                large_unlimited = unlimited;
            }
            if (!comma)
                snprintf(quantifier, sizeof(quantifier), "{%u}", (unsigned)min);
            else if (unlimited)
                snprintf(quantifier, sizeof(quantifier), "{%u,}",
                         (unsigned)min);
            else
                snprintf(quantifier, sizeof(quantifier), "{%u,%u}",
                         (unsigned)min, (unsigned)max);
        }
        yx_rx_space(p, flags);
        bool lazy = p->at < p->length && p->text[p->at] == '?';
        if (lazy)
            ++p->at;
        char *repeated = NULL;
        if (zero_count || !*atom) {
            /* HIR removes repetitions of an empty expression. Keeping a
             * zero-count child here needlessly expands later nested counts
             * in the native matcher, even though the result is empty. */
            repeated = yx_rx_format("");
        } else if (large_count) {
            yx_rx_buffer pieces = {0};
            for (uint64_t remaining = large_min; remaining;) {
                unsigned count =
                    remaining > 65535 ? 65535 : (unsigned)remaining;
                char *piece = yx_rx_format("%s{%u}", atom, count);
                bool ok = piece && yx_rx_append(&pieces, piece);
                free(piece);
                if (!ok) {
                    free(pieces.text);
                    free(atom);
                    return yx_rx_oom(p);
                }
                remaining -= count;
            }
            uint64_t optional = large_unlimited ? 0 : large_max - large_min;
            do {
                unsigned count = optional > 65535 ? 65535 : (unsigned)optional;
                char *piece = large_unlimited
                                  ? yx_rx_format("%s*%s", atom,
                                                 lazy != flags.U ? "?" : "")
                                  : yx_rx_format("%s{0,%u}%s", atom, count,
                                                 lazy != flags.U ? "?" : "");
                bool ok = piece && yx_rx_append(&pieces, piece);
                free(piece);
                if (!ok) {
                    free(pieces.text);
                    free(atom);
                    return yx_rx_oom(p);
                }
                optional -= count;
            } while (optional);
            repeated = yx_rx_format("(?:%s)", pieces.text);
            free(pieces.text);
        } else
            repeated =
                yx_rx_format(simple_literal ? "%s%s%s" : "(?:%s)%s%s", atom,
                             quantifier, lazy != flags.U ? "?" : "");
        free(atom);
        atom = repeated;
        if (!atom)
            return yx_rx_oom(p);
    }
    if (p->error->message[0]) {
        free(atom);
        return NULL;
    }
    return atom;
}
static char *yx_rx_expr(yx_rx_parser *p, yx_rx_flags flags, size_t group_start)
{
    yx_rx_buffer out = {0};
    while (p->at < p->length) {
        yx_rx_space(p, flags);
        if (p->at == p->length)
            break;
        size_t start = p->at;
        unsigned char c = (unsigned char)p->text[p->at];
        char *atom = NULL;
        bool only_flags = false;
        int repeat_cost_kind = YX_RX_REPEAT_COST_NONE;
        if (c == ')') {
            if (group_start == SIZE_MAX)
                yx_rx_error(p, p->at, p->at + 1, "unopened group");
            break;
        }
        if (c == '|') {
            ++p->at;
            if (!yx_rx_append(&out, "|"))
                goto oom;
            continue;
        }
        if (strchr("*+?{", c) && c) {
            yx_rx_error(p, p->at, p->at + 1,
                        "repetition operator missing expression");
            break;
        }
        if (c == '(')
            atom = yx_rx_group(p, &flags, &only_flags);
        else if (c == '[')
            atom = yx_rx_class(p, flags);
        else if (c == '\\') {
            yx_rx_atom parsed = yx_rx_escape(p, flags, false);
            atom = parsed.text;
            repeat_cost_kind = parsed.repeat_cost_kind;
        } else if (c == '.') {
            ++p->at;
            if (flags.u && !flags.s && !flags.R)
                repeat_cost_kind = YX_RX_REPEAT_COST_DOT;
            atom = yx_rx_format(flags.s   ? "[\\s\\S]"
                                : flags.R ? "[^\\r\\n]"
                                          : "[^\\n]");
            if (!flags.u && !p->bytes)
                yx_rx_semantic(p, start, p->at,
                               "pattern can match invalid UTF-8");
            if (flags.u)
                atom = yx_rx_unicode_bytes(p, atom);
        } else if (c == '^' || c == '$') {
            ++p->at;
            if (!flags.m)
                atom = yx_rx_format(c == '^' ? "\\A" : "\\z");
            else if (c == '^')
                atom = yx_rx_format(flags.R ? "(?:\\A|(?<=\\n)|(?<=\\r)(?!\\n))"
                                            : "(?:\\A|(?<=\\n))");
            else
                atom = yx_rx_format(flags.R ? "(?:\\z|(?=\\r)|(?<!\\r)(?=\\n))"
                                            : "(?:\\z|(?=\\n))");
        } else {
            unsigned point = yx_rx_point(p);
            atom = yx_rx_literal(point, flags);
            if (p->byte_engine && (point >= 128 || (flags.u && flags.i)))
                atom = yx_rx_unicode_bytes(p, atom);
        }
        if (!atom) {
            if (!p->error->message[0])
                yx_rx_oom(p);
            break;
        }
        if (!only_flags)
            atom = yx_rx_repeat(p, flags, atom, repeat_cost_kind);
        if (!atom)
            break;
        bool ok = yx_rx_append(&out, atom);
        free(atom);
        if (!ok)
            goto oom;
    }
    if (p->error->message[0]) {
        free(out.text);
        return NULL;
    }
    if (!out.text)
        out.text = yx_rx_format("");
    return out.text;
oom:
    free(out.text);
    return yx_rx_oom(p);
}
bool yx_cli_regex_translate(const char *pattern, size_t length, bool bytes_mode,
                            yx_cli_regex *result, yx_cli_regex_error *error)
{
    memset(result, 0, sizeof(*result));
    memset(error, 0, sizeof(*error));
    yx_rx_parser parser = {0};
    parser.text = pattern;
    parser.length = length;
    parser.bytes = bytes_mode;
    parser.error = error;
    /* Use the byte engine only when a flag group can disable Unicode.
     * Ordinary Unicode metadata regexes can use PCRE's invalid-UTF skipping. */
    for (size_t i = 0; bytes_mode && i + 2 < length; ++i) {
        if (pattern[i] == '\\') {
            ++i;
            continue;
        }
        if (pattern[i] != '(' || pattern[i + 1] != '?')
            continue;
        bool negative = false;
        for (size_t j = i + 2;
             j < length && strchr("imsuxRU-", pattern[j]) && pattern[j]; ++j) {
            if (pattern[j] == '-')
                negative = true;
            else if (negative && pattern[j] == 'u')
                parser.byte_engine = true;
        }
    }
    yx_rx_flags flags = {0};
    flags.u = true;
    char *translated = yx_rx_expr(&parser, flags, SIZE_MAX);
    free(parser.names);
    if (!error->message[0] &&
        (parser.semantic.message[0] || parser.semantic.size_limit))
        *error = parser.semantic;
    if (error->message[0] || error->size_limit) {
        free(translated);
        return false;
    }
    if (!translated) {
        snprintf(error->message, sizeof(error->message), "out of memory");
        return false;
    }
    result->pattern = translated;
    result->length = strlen(translated);
    result->options =
        PCRE2_DOLLAR_ENDONLY |
        (parser.byte_engine ? 0
                            : PCRE2_UTF | PCRE2_UCP |
                                  (bytes_mode ? PCRE2_MATCH_INVALID_UTF : 0));
    return true;
}
void yx_cli_regex_free(yx_cli_regex *result)
{
    if (!result)
        return;
    free(result->pattern);
    memset(result, 0, sizeof(*result));
}
