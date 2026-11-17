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
 * The tokenizer, token stream and parser follow parser/src/tokenizer/mod.rs,
 * parser/src/parser/token_stream.rs and parser/src/parser/mod.rs in YARA-X
 * v1.21.0.
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
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

#include "syntax_check.h"
#include "xxfclib/regex/xx_regex_unicode16.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Token ids, in the order of tokenizer/tokens.rs. */
enum {
    T_ALL_KW, T_AND_KW, T_ANY_KW, T_ASCII_KW, T_AT_KW, T_BASE64_KW,
    T_BASE64WIDE_KW, T_CONDITION_KW, T_CONTAINS_KW, T_DEFINED_KW,
    T_ENDSWITH_KW, T_ENTRYPOINT_KW, T_FALSE_KW, T_FILESIZE_KW, T_FOR_KW,
    T_FULLWORD_KW, T_GLOBAL_KW, T_ICONTAINS_KW, T_IENDSWITH_KW,
    T_IEQUALS_KW, T_IMPORT_KW, T_IN_KW, T_INCLUDE_KW, T_ISTARTSWITH_KW,
    T_MATCHES_KW, T_META_KW, T_NOCASE_KW, T_NONE_KW, T_NOT_KW, T_OF_KW,
    T_OR_KW, T_PRIVATE_KW, T_RULE_KW, T_STARTSWITH_KW, T_STRINGS_KW,
    T_THEM_KW, T_TRUE_KW, T_WIDE_KW, T_XOR_KW, T_WITH_KW,
    T_SHL, T_SHR, T_EQ, T_NE, T_LT, T_LE, T_GT, T_GE,
    T_AMPERSAND, T_ASTERISK, T_BACKSLASH, T_CARET, T_COLON, T_COMMA, T_DOT,
    T_EQUAL, T_HYPHEN, T_PERCENT, T_PIPE, T_PLUS, T_TILDE,
    T_L_BRACE, T_R_BRACE, T_L_BRACKET, T_R_BRACKET, T_L_PAREN, T_R_PAREN,
    T_REGEXP, T_FLOAT_LIT, T_INTEGER_LIT, T_STRING_LIT, T_IDENT,
    T_PATTERN_IDENT, T_PATTERN_COUNT, T_PATTERN_LENGTH, T_PATTERN_OFFSET,
    T_HEX_BYTE, T_COMMENT, T_NEWLINE, T_WHITESPACE, T_UNKNOWN,
    T_INVALID_UTF8,
    T_END = 0xff
};

/* TokenId::description(). The missing backtick after `startswith and the
 * bare & are upstream's. */
static const char *const yx_sc_descriptions[] = {
    "`all`", "`and`", "`any`", "`ascii`", "`at`", "`base64`",
    "`base64wide`", "`condition`", "`contains`", "`defined`",
    "`endswith`", "`entrypoint`", "`false`", "`filesize`", "`for`",
    "`fullword`", "`global`", "`icontains`", "`iendswith`", "`iequals`",
    "`import`", "`in`", "`include`", "`istartswith`", "`matches`", "`meta`",
    "`nocase`", "`none`", "`not`", "`of`", "`or`", "`private`", "`rule`",
    "`startswith", "`strings`", "`them`", "`true`", "`wide`", "`xor`",
    "`with`",
    "`<<`", "`>>`", "`==`", "`!=`", "`<`", "`<=`", "`>`", "`>=`",
    "&", "`*`", "`\\`", "`^`", "`:`", "`,`", "`.`", "`=`", "`-`", "`%`",
    "`|`", "`+`", "`~`",
    "`{`", "`}`", "`[`", "`]`", "`(`", "`)`",
    "regexp", "FLOAT", "INTEGER", "STRING", "identifier",
    "pattern identifier", "pattern count", "pattern length",
    "pattern offset", "BYTE", "comment", "newline", "whitespace", "unknown",
    "invalid UTF-8"
};

static const struct { const char *word; uint8_t id; } yx_sc_keywords[] = {
    {"all", T_ALL_KW}, {"and", T_AND_KW}, {"any", T_ANY_KW},
    {"ascii", T_ASCII_KW}, {"at", T_AT_KW}, {"base64", T_BASE64_KW},
    {"base64wide", T_BASE64WIDE_KW}, {"condition", T_CONDITION_KW},
    {"contains", T_CONTAINS_KW}, {"defined", T_DEFINED_KW},
    {"endswith", T_ENDSWITH_KW}, {"entrypoint", T_ENTRYPOINT_KW},
    {"false", T_FALSE_KW}, {"filesize", T_FILESIZE_KW}, {"for", T_FOR_KW},
    {"fullword", T_FULLWORD_KW}, {"global", T_GLOBAL_KW},
    {"icontains", T_ICONTAINS_KW}, {"iendswith", T_IENDSWITH_KW},
    {"iequals", T_IEQUALS_KW}, {"import", T_IMPORT_KW}, {"in", T_IN_KW},
    {"include", T_INCLUDE_KW}, {"istartswith", T_ISTARTSWITH_KW},
    {"matches", T_MATCHES_KW}, {"meta", T_META_KW},
    {"nocase", T_NOCASE_KW}, {"none", T_NONE_KW}, {"not", T_NOT_KW},
    {"of", T_OF_KW}, {"or", T_OR_KW}, {"private", T_PRIVATE_KW},
    {"rule", T_RULE_KW}, {"startswith", T_STARTSWITH_KW},
    {"strings", T_STRINGS_KW}, {"them", T_THEM_KW}, {"true", T_TRUE_KW},
    {"wide", T_WIDE_KW}, {"xor", T_XOR_KW}, {"with", T_WITH_KW}
};

typedef struct { uint8_t id; size_t start, end; } yx_sc_token;

enum { MODE_NORMAL, MODE_HEX, MODE_JUMP };

/* ------------------------------------------------------------------------
 * Tokenizer
 * --------------------------------------------------------------------- */

static bool yx_sc_alpha(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static bool yx_sc_digit(uint8_t c) { return c >= '0' && c <= '9'; }

static bool yx_sc_word(uint8_t c)
{
    return yx_sc_alpha(c) || yx_sc_digit(c) || c == '_';
}

/* Width of the identifier-continuation character at `s` (ASCII letter,
 * digit, underscore or Unicode decimal digit), or 0. `\\d` in the
 * tokenizer's identifier regexes is Unicode-aware: logos compiles it with
 * regex-syntax 0.8.11, whose Unicode 16 Nd table xxfclib keeps. */
static size_t yx_sc_word_char(const uint8_t *s, size_t n)
{
    uint32_t cp;
    size_t width;
    const xx_regex_unicode16_table *nd;
    if (!n) return 0;
    if (yx_sc_word(s[0])) return 1;
    if (s[0] < 0xc2) return 0;
    if (s[0] < 0xe0) { width = 2; cp = s[0] & 0x1f; }
    else if (s[0] < 0xf0) { width = 3; cp = s[0] & 0x0f; }
    else if (s[0] < 0xf5) { width = 4; cp = s[0] & 0x07; }
    else return 0;
    if (n < width) return 0;
    for (size_t i = 1; i < width; ++i) {
        if ((s[i] & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3f);
    }
    /* ASCII digits are handled above; their overlong forms are no digits. */
    nd = xx_regex_unicode16_table_at(
        xx_regex_unicode16_class_table(XX_REGEX_UNICODE16_DECIMAL));
    if (cp < 0x80 || !nd) return 0;
    for (size_t lo = 0, hi = nd->count; lo < hi;) {
        size_t mid = (lo + hi) / 2;
        if (cp < nd->ranges[mid].first) hi = mid;
        else if (cp > nd->ranges[mid].last) lo = mid + 1;
        else return width;
    }
    return 0;
}

static bool yx_sc_hex(uint8_t c)
{
    return yx_sc_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Length of the Whitespace token's characters at `s`: space, tab, U+00A0,
 * U+2000-U+200A, U+202F and U+205F. */
static size_t yx_sc_space_char(const uint8_t *s, size_t n)
{
    if (!n) return 0;
    if (s[0] == ' ' || s[0] == '\t') return 1;
    if (n >= 2 && s[0] == 0xc2 && s[1] == 0xa0) return 2;
    if (n >= 3 && s[0] == 0xe2 && s[1] == 0x80 &&
        ((s[2] >= 0x80 && s[2] <= 0x8a) || s[2] == 0xaf)) return 3;
    if (n >= 3 && s[0] == 0xe2 && s[1] == 0x81 && s[2] == 0x9f) return 3;
    return 0;
}

/* Rust's char::is_whitespace (Unicode White_Space) at `s`. */
static size_t yx_sc_unicode_space(const uint8_t *s, size_t n)
{
    size_t width = yx_sc_space_char(s, n);
    if (width) return width;
    if (s[0] >= 0x09 && s[0] <= 0x0d) return 1;
    if (n >= 2 && s[0] == 0xc2 && s[1] == 0x85) return 2;
    if (n >= 3 && s[0] == 0xe1 && s[1] == 0x9a && s[2] == 0x80) return 3;
    if (n >= 3 && s[0] == 0xe2 && s[1] == 0x80 &&
        (s[2] == 0xa8 || s[2] == 0xa9)) return 3;
    if (n >= 3 && s[0] == 0xe3 && s[1] == 0x80 && s[2] == 0x80) return 3;
    return 0;
}

/* Length of the valid UTF-8 sequence at `s`, or 0. */
static size_t yx_sc_utf8(const uint8_t *s, size_t n)
{
    size_t width;
    if (!n) return 0;
    if (s[0] < 0x80) return 1;
    if (s[0] >= 0xc2 && s[0] <= 0xdf) width = 2;
    else if (s[0] >= 0xe0 && s[0] <= 0xef) width = 3;
    else if (s[0] >= 0xf0 && s[0] <= 0xf4) width = 4;
    else return 0;
    if (n < width) return 0;
    for (size_t i = 1; i < width; ++i)
        if ((s[i] & 0xc0) != 0x80) return 0;
    if (width == 3 && s[0] == 0xe0 && s[1] < 0xa0) return 0;
    if (width == 3 && s[0] == 0xed && s[1] >= 0xa0) return 0;
    if (width == 4 && s[0] == 0xf0 && s[1] < 0x90) return 0;
    if (width == 4 && s[0] == 0xf4 && s[1] >= 0x90) return 0;
    return width;
}

typedef struct yx_sc_lexer {
    const uint8_t *s;
    size_t n;
    size_t cursor;
    int mode;
} yx_sc_lexer;

static size_t yx_sc_spaces(const uint8_t *s, size_t n, size_t at)
{
    size_t end = at, width;
    while ((width = yx_sc_space_char(s + end, n - end)) != 0) end += width;
    return end;
}

/* The end of the closed block comment at `at`, or 0. */
static size_t yx_sc_block_comment(const uint8_t *s, size_t n, size_t at)
{
    for (size_t i = at + 2; i + 1 < n; ++i)
        if (s[i] == '*' && s[i + 1] == '/') return i + 2;
    return 0;
}

/* NormalToken. Sets *id and returns the token's end; on a lexing error
 * returns 0 and sets *progress to where logos stopped. */
static size_t yx_sc_lex_normal(const uint8_t *s, size_t n, size_t at,
                               uint8_t *id, size_t *progress)
{
    uint8_t c = s[at];
    size_t end, width;
    *progress = at + 1;
    if ((width = yx_sc_space_char(s + at, n - at)) != 0) {
        *id = T_WHITESPACE;
        return yx_sc_spaces(s, n, at);
    }
    if (c == '\n') { *id = T_NEWLINE; return at + 1; }
    if (c == '\r') {
        *id = T_NEWLINE;
        return at + 1 < n && s[at + 1] == '\n' ? at + 2 : at + 1;
    }
    if (c == '/') {
        if (at + 1 < n && s[at + 1] == '/') {
            end = at + 2;
            while (end < n && s[end] != '\n') ++end;
            *id = T_COMMENT;
            return end;
        }
        if (at + 1 < n && s[at + 1] == '*') {
            end = yx_sc_block_comment(s, n, at);
            if (end) { *id = T_COMMENT; return end; }
            *progress = n;
            return 0;
        }
        /* Regexp: the first character is not `*`, `/` or a newline. */
        end = at + 1;
        for (bool first = true; end < n; first = false) {
            if (s[end] == '\n') break;
            if (s[end] == '\\') {
                if (end + 1 >= n || s[end + 1] == '\n') { ++end; break; }
                end += 2;
                continue;
            }
            if (s[end] == '/') {
                if (first) break;
                ++end;
                for (int i = 0; i < 2 && end < n && yx_sc_alpha(s[end]); ++i)
                    ++end;
                *id = T_REGEXP;
                return end;
            }
            ++end;
        }
        *progress = end;
        return 0;
    }
    if (c == '"') {
        size_t string_end = 0, multi_end = 0;
        end = at + 1;
        while (end < n) {
            if (s[end] == '"') { string_end = end + 1; break; }
            if (s[end] == '\n') break;
            if (s[end] == '\\') {
                if (end + 1 >= n || s[end + 1] == '\n') { ++end; break; }
                end += 2;
                continue;
            }
            ++end;
        }
        if (!string_end) *progress = end;
        if (at + 2 < n && s[at + 1] == '"' && s[at + 2] == '"') {
            for (size_t i = at + 3; i < n;) {
                if (s[i] == '\\') {
                    if (i + 1 >= n || s[i + 1] == '\n') break;
                    i += 2;
                    continue;
                }
                if (s[i] == '"') {
                    if (i + 2 < n && s[i + 1] == '"' && s[i + 2] == '"')
                        multi_end = i + 3;
                    break;
                }
                ++i;
            }
        }
        if (multi_end > string_end) { *id = T_STRING_LIT; return multi_end; }
        if (string_end) { *id = T_STRING_LIT; return string_end; }
        return 0;
    }
    if (c == '$' || c == '#' || c == '@' || c == '!') {
        if (c == '!' && at + 1 < n && s[at + 1] == '=') {
            *id = T_NE;
            return at + 2;
        }
        end = at + 1;
        while (end < n && (width = yx_sc_word_char(s + end, n - end)) != 0)
            end += width;
        *id = c == '$' ? T_PATTERN_IDENT : c == '#' ? T_PATTERN_COUNT :
              c == '@' ? T_PATTERN_OFFSET : T_PATTERN_LENGTH;
        return end;
    }
    if (yx_sc_alpha(c) || c == '_') {
        end = at + 1;
        while (end < n && (width = yx_sc_word_char(s + end, n - end)) != 0)
            end += width;
        *id = T_IDENT;
        for (size_t i = 0; i < sizeof(yx_sc_keywords) / sizeof(*yx_sc_keywords); ++i)
            if (strlen(yx_sc_keywords[i].word) == end - at &&
                memcmp(yx_sc_keywords[i].word, s + at, end - at) == 0)
                *id = yx_sc_keywords[i].id;
        return end;
    }
    if (yx_sc_digit(c)) {
        size_t decimal = at, best;
        while (decimal < n && (yx_sc_digit(s[decimal]) || s[decimal] == '_'))
            ++decimal;
        best = decimal;
        *id = T_INTEGER_LIT;
        if (decimal + 1 < n && (s[decimal] == 'K' || s[decimal] == 'M') &&
            s[decimal + 1] == 'B')
            best = decimal + 2;
        if (decimal + 1 < n && s[decimal] == '.' &&
            (yx_sc_digit(s[decimal + 1]) || s[decimal + 1] == '_')) {
            end = decimal + 1;
            while (end < n && (yx_sc_digit(s[end]) || s[end] == '_')) ++end;
            if (end > best) { best = end; *id = T_FLOAT_LIT; }
        }
        if (c == '0' && at + 2 < n && (s[at + 1] == 'x' || s[at + 1] == 'o')) {
            bool hex = s[at + 1] == 'x';
            end = at + 2;
            if (hex ? yx_sc_hex(s[end]) : (s[end] >= '0' && s[end] <= '7')) {
                while (end < n && ((hex ? yx_sc_hex(s[end]) :
                                    (s[end] >= '0' && s[end] <= '7')) ||
                                   s[end] == '_'))
                    ++end;
                if (end > best) { best = end; *id = T_INTEGER_LIT; }
            }
        }
        return best;
    }
    switch (c) {
    case '<':
        if (at + 1 < n && s[at + 1] == '<') { *id = T_SHL; return at + 2; }
        if (at + 1 < n && s[at + 1] == '=') { *id = T_LE; return at + 2; }
        *id = T_LT; return at + 1;
    case '>':
        if (at + 1 < n && s[at + 1] == '>') { *id = T_SHR; return at + 2; }
        if (at + 1 < n && s[at + 1] == '=') { *id = T_GE; return at + 2; }
        *id = T_GT; return at + 1;
    case '=':
        if (at + 1 < n && s[at + 1] == '=') { *id = T_EQ; return at + 2; }
        *id = T_EQUAL; return at + 1;
    case '&': *id = T_AMPERSAND; return at + 1;
    case '*': *id = T_ASTERISK; return at + 1;
    case '\\': *id = T_BACKSLASH; return at + 1;
    case ':': *id = T_COLON; return at + 1;
    case ',': *id = T_COMMA; return at + 1;
    case '.': *id = T_DOT; return at + 1;
    case '+': *id = T_PLUS; return at + 1;
    case '-': *id = T_HYPHEN; return at + 1;
    case '%': *id = T_PERCENT; return at + 1;
    case '|': *id = T_PIPE; return at + 1;
    case '^': *id = T_CARET; return at + 1;
    case '~': *id = T_TILDE; return at + 1;
    case '{': *id = T_L_BRACE; return at + 1;
    case '}': *id = T_R_BRACE; return at + 1;
    case '(': *id = T_L_PAREN; return at + 1;
    case ')': *id = T_R_PAREN; return at + 1;
    case '[': *id = T_L_BRACKET; return at + 1;
    case ']': *id = T_R_BRACKET; return at + 1;
    default: return 0;
    }
}

/* HexPatternToken; 0 when nothing matches. */
static size_t yx_sc_lex_hex(const uint8_t *s, size_t n, size_t at,
                            uint8_t *id)
{
    uint8_t c = s[at];
    size_t end;
    if (yx_sc_space_char(s + at, n - at)) {
        *id = T_WHITESPACE;
        return yx_sc_spaces(s, n, at);
    }
    if (c == '\n') { *id = T_NEWLINE; return at + 1; }
    if (c == '\r') {
        *id = T_NEWLINE;
        return at + 1 < n && s[at + 1] == '\n' ? at + 2 : at + 1;
    }
    if (c == '/' && at + 1 < n && s[at + 1] == '/') {
        end = at + 2;
        while (end < n && s[end] != '\n') ++end;
        *id = T_COMMENT;
        return end;
    }
    if (c == '/' && at + 1 < n && s[at + 1] == '*') {
        end = yx_sc_block_comment(s, n, at);
        if (end) *id = T_COMMENT;
        return end;
    }
    end = at + (c == '~');
    if (end + 1 < n && (yx_sc_hex(s[end]) || s[end] == '?') &&
        (yx_sc_hex(s[end + 1]) || s[end + 1] == '?')) {
        *id = T_HEX_BYTE;
        return end + 2;
    }
    switch (c) {
    case '|': *id = T_PIPE; return at + 1;
    case '(': *id = T_L_PAREN; return at + 1;
    case ')': *id = T_R_PAREN; return at + 1;
    case '[': *id = T_L_BRACKET; return at + 1;
    case ']': *id = T_R_BRACKET; return at + 1;
    default: return 0;
    }
}

/* HexJumpToken; 0 when nothing matches. */
static size_t yx_sc_lex_jump(const uint8_t *s, size_t n, size_t at,
                             uint8_t *id)
{
    uint8_t c = s[at];
    size_t end;
    if (yx_sc_space_char(s + at, n - at)) {
        *id = T_WHITESPACE;
        return yx_sc_spaces(s, n, at);
    }
    if (c == '\n') { *id = T_NEWLINE; return at + 1; }
    if (c == '\r') {
        *id = T_NEWLINE;
        return at + 1 < n && s[at + 1] == '\n' ? at + 2 : at + 1;
    }
    if (c == '-') { *id = T_HYPHEN; return at + 1; }
    if (!yx_sc_digit(c)) return 0;
    *id = T_INTEGER_LIT;
    end = at;
    while (end < n && yx_sc_digit(s[end])) ++end;
    if (c == '0' && at + 2 < n && s[at + 1] == 'x' && yx_sc_hex(s[at + 2])) {
        size_t hex = at + 2;
        while (hex < n && yx_sc_hex(s[hex])) ++hex;
        if (hex > end) end = hex;
    }
    if (c == '0' && at + 2 < n && s[at + 1] == 'o' &&
        s[at + 2] >= '0' && s[at + 2] <= '7') {
        size_t octal = at + 2;
        while (octal < n && s[octal] >= '0' && s[octal] <= '7') ++octal;
        if (octal > end) end = octal;
    }
    return end;
}

/* Tokenizer::next_token. */
static bool yx_sc_next(yx_sc_lexer *lexer, yx_sc_token *token)
{
    const uint8_t *s = lexer->s;
    size_t n = lexer->n, at, end, progress;
    uint8_t id = T_UNKNOWN;
    for (;;) {
        at = lexer->cursor;
        if (at >= n) return false;
        if (lexer->mode == MODE_HEX) {
            end = yx_sc_lex_hex(s, n, at, &id);
            if (!end) { lexer->mode = MODE_NORMAL; continue; }
            break;
        }
        if (lexer->mode == MODE_JUMP) {
            end = yx_sc_lex_jump(s, n, at, &id);
            if (!end) { lexer->mode = MODE_HEX; continue; }
            break;
        }
        end = yx_sc_lex_normal(s, n, at, &id, &progress);
        if (!end) {
            /* unexpected_token: the valid UTF-8 prefix up to the first
             * whitespace, or the bytes logos consumed if longer. */
            size_t valid = at, width;
            if (!yx_sc_utf8(s + at, n - at)) {
                id = T_INVALID_UTF8;
                end = at + 1;
                break;
            }
            while (valid < n && (width = yx_sc_utf8(s + valid, n - valid)) &&
                   !yx_sc_unicode_space(s + valid, n - valid))
                valid += width;
            id = T_UNKNOWN;
            end = progress > valid ? progress : valid;
        }
        break;
    }
    token->id = id;
    token->start = at;
    token->end = end;
    lexer->cursor = end;
    return true;
}

/* ------------------------------------------------------------------------
 * Parser
 * --------------------------------------------------------------------- */

/* ST_MAX_DEPTH is State::MaxDepthReached (YARA-X v1.23.0): backtracking
 * stops until unwinding returns to a top-level rule section. */
enum { ST_OK, ST_FAILURE, ST_OUT_OF_FUEL, ST_MAX_DEPTH };
/* Node kinds. EXPR and TERM keep the values 2 and 3, the two kinds the
 * failure cache encodes in its keys; the condition kinds after them let
 * the AST depth check rebuild the condition's shape. */
enum {
    K_NODE, K_ERROR, K_EXPR, K_TERM,
    K_CONDITION_BLK, K_BOOLEAN_EXPR, K_BOOLEAN_TERM, K_PRIMARY_EXPR,
    K_FUNC_CALL, K_FOR_EXPR, K_OF_EXPR, K_WITH_EXPR, K_WITH_DECLS,
    K_WITH_DECL, K_QUANTIFIER, K_ITERABLE, K_RANGE, K_EXPR_TUPLE,
    K_BOOLEAN_EXPR_TUPLE, K_PATTERN_IDENT_TUPLE
};
enum { EV_BEGIN, EV_END, EV_TOKEN };

/* Where a literal token appears, which decides how the AST builder
 * converts it. */
enum { CTX_NONE, CTX_EXPR, CTX_META, CTX_UTF8, CTX_U8, CTX_U32 };

typedef struct { uint8_t type, kind, id, context; size_t start, end; } yx_sc_event;

typedef struct {
    size_t start, end;
    uint8_t id;
    const char *descriptions[48];
    size_t count;
} yx_sc_expected;

typedef struct { size_t start, end; char *message; } yx_sc_pending;

typedef struct { uint64_t key; uint32_t generation; } yx_sc_cache_entry;

/* A slot of the expected-token index: the entry's position, valid while
 * the generation is current. */
typedef struct { size_t index; uint32_t generation; } yx_sc_expected_slot;

/* MAX_CST_DEPTH, also MAX_AST_DEPTH (parser/src/parser/mod.rs). */
#define YX_SC_MAX_CST_DEPTH 1000
/* A safety net only: ST_MAX_DEPTH keeps the recursion near
 * YX_SC_MAX_CST_DEPTH. */
#define YX_SC_MAX_DEPTH 4000

typedef struct yx_sc {
    yx_sc_lexer lexer;
    yx_sc_token *tokens;
    size_t token_base, token_count, token_capacity, current;
    int state;
    size_t opt_depth, not_depth, depth;
    yx_sc_event *events;
    size_t event_count, event_capacity;
    size_t *open_begins;
    size_t open_count, open_capacity;
    yx_sc_expected *expected;
    size_t expected_count, expected_capacity;
    /* Hash index over `expected` by (start, end, id); upstream keeps these
     * errors in a hash map, and long conditions add one per token. Every
     * reset of `expected` starts a new generation. */
    yx_sc_expected_slot *expected_index;
    size_t expected_index_capacity;
    uint32_t expected_generation;
    struct { size_t start, end; } *unexpected;
    size_t unexpected_count, unexpected_capacity;
    yx_sc_pending *pending;
    size_t pending_count, pending_capacity;
    /* The failure cache: an open addressing set whose entries belong to
     * the generation in which they were added; clearing the cache starts a
     * new generation. */
    yx_sc_cache_entry *cache;
    size_t cache_count, cache_capacity;
    uint32_t cache_generation;
    size_t fuel;
    bool broken;
    uint8_t context;
    yx_sc_result *result;
} yx_sc;

typedef struct { const uint8_t *ids; size_t count; } yx_sc_set;

#define SET(...) (&(const yx_sc_set){ (const uint8_t[]){ __VA_ARGS__ }, \
    sizeof((const uint8_t[]){ __VA_ARGS__ }) })

#define FAILED(p) ((p)->state != ST_OK)

/* The slot for one more top-level item. The vector grows geometrically, with
 * its capacity implied by the count (4, then doubled at each power of two):
 * one realloc per item made checking large sources quadratic. NULL when out
 * of memory; the item count is unchanged. */
static yx_sc_item *yx_sc_item_slot(yx_sc_result *result)
{
    size_t n = result->item_count;
    if (n == 0 || (n >= 4 && (n & (n - 1)) == 0)) {
        size_t next = n ? n * 2 : 4;
        yx_sc_item *grown;
        if (next > SIZE_MAX / sizeof(*grown)) return NULL;
        grown = realloc(result->items, next * sizeof(*grown));
        if (!grown) return NULL;
        result->items = grown;
    }
    return &result->items[n];
}

static bool yx_sc_grow(void **items, size_t *capacity, size_t needed,
                       size_t size)
{
    size_t next;
    void *grown;
    if (needed <= *capacity) return true;
    next = *capacity ? *capacity * 2 : 64;
    while (next < needed) next *= 2;
    grown = realloc(*items, next * size);
    if (!grown) return false;
    *items = grown;
    *capacity = next;
    return true;
}

static bool yx_sc_set_contains(const yx_sc_set *set, uint8_t id)
{
    for (size_t i = 0; i < set->count; ++i)
        if (set->ids[i] == id) return true;
    return false;
}

static bool yx_sc_trivia_token(const yx_sc_token *token)
{
    return token->id == T_NEWLINE || token->id == T_WHITESPACE ||
           token->id == T_COMMENT;
}

/* TokenStream::peek_token. */
static const yx_sc_token *yx_sc_peek_token(yx_sc *p, size_t n)
{
    size_t wanted = p->current + n;
    while (wanted >= p->token_base + p->token_count) {
        yx_sc_token token;
        if (!yx_sc_next(&p->lexer, &token)) return NULL;
        if (!yx_sc_grow((void **)&p->tokens, &p->token_capacity,
                        p->token_count + 1, sizeof(*p->tokens))) {
            p->broken = true;
            return NULL;
        }
        p->tokens[p->token_count++] = token;
    }
    return &p->tokens[wanted - p->token_base];
}

static void yx_sc_set_state(yx_sc *p, int state)
{
    if (p->state != ST_OUT_OF_FUEL && p->state != ST_MAX_DEPTH)
        p->state = state;
}

static yx_sc_event *yx_sc_push_event(yx_sc *p, uint8_t type, uint8_t kind,
                                     size_t end)
{
    yx_sc_event *event;
    if (!yx_sc_grow((void **)&p->events, &p->event_capacity,
                    p->event_count + 1, sizeof(*p->events))) {
        p->broken = true;
        return NULL;
    }
    event = &p->events[p->event_count++];
    memset(event, 0, sizeof(*event));
    event->type = type;
    event->kind = kind;
    event->end = end;
    return event;
}

/* Consumes the next token and appends it to the output. */
static void yx_sc_bump(yx_sc *p)
{
    const yx_sc_token *token = yx_sc_peek_token(p, 0);
    yx_sc_event *event;
    if (!token) return;
    ++p->current;
    event = yx_sc_push_event(p, EV_TOKEN, 0, token->end);
    if (!event) return;
    event->id = token->id;
    event->start = token->start;
    event->context = p->context;
}

static const yx_sc_token *yx_sc_peek_non_trivia(yx_sc *p)
{
    for (size_t i = 0;; ++i) {
        const yx_sc_token *token = yx_sc_peek_token(p, i);
        if (!token) return NULL;
        if (!yx_sc_trivia_token(token)) return token;
    }
}

static void yx_sc_trivia(yx_sc *p)
{
    const yx_sc_token *token;
    if (FAILED(p)) return;
    while ((token = yx_sc_peek_token(p, 0)) != NULL && yx_sc_trivia_token(token))
        yx_sc_bump(p);
}

typedef struct { size_t token, event; } yx_sc_bookmark;

static yx_sc_bookmark yx_sc_mark(yx_sc *p)
{
    yx_sc_bookmark bookmark = { p->current, p->event_count };
    return bookmark;
}

static void yx_sc_restore(yx_sc *p, const yx_sc_bookmark *bookmark)
{
    p->current = bookmark->token;
    p->event_count = bookmark->event;
}

static void yx_sc_clear_expected(yx_sc *p);
static bool yx_sc_add_pending(yx_sc *p, size_t start, size_t end,
                              const char *text);

static void yx_sc_begin(yx_sc *p, uint8_t kind)
{
    yx_sc_trivia(p);
    if (p->depth == YX_SC_MAX_CST_DEPTH && p->state == ST_OK) {
        /* Only the nesting error is reported: speculative errors of
         * earlier branches are dropped. */
        const yx_sc_token *token = yx_sc_peek_non_trivia(p);
        size_t start = token ? token->start : p->lexer.n;
        size_t end = token ? token->end : p->lexer.n;
        bool present = false;
        p->state = ST_MAX_DEPTH;
        yx_sc_clear_expected(p);
        for (size_t i = 0; i < p->pending_count; ++i)
            if (p->pending[i].start == start && p->pending[i].end == end)
                present = true;
        if (!present && !yx_sc_add_pending(p, start, end, "nesting limit reached"))
            p->broken = true;
    }
    if (p->fuel) --p->fuel;
    else p->state = ST_OUT_OF_FUEL;
    if (++p->depth > YX_SC_MAX_DEPTH) p->broken = true;
    if (!yx_sc_grow((void **)&p->open_begins, &p->open_capacity,
                    p->open_count + 1, sizeof(*p->open_begins))) {
        p->broken = true;
        return;
    }
    p->open_begins[p->open_count++] = p->event_count;
    yx_sc_push_event(p, EV_BEGIN, kind, 0);
}

static size_t yx_sc_last_token_end(const yx_sc *p)
{
    for (size_t i = p->event_count; i-- > 0;)
        if (p->events[i].type == EV_TOKEN) return p->events[i].end;
    return 0;
}

static void yx_sc_output_end(yx_sc *p, bool error)
{
    size_t begin;
    if (!p->open_count) { p->broken = true; return; }
    begin = p->open_begins[--p->open_count];
    if (error) {
        /* An empty node is removed. */
        if (begin == p->event_count - 1) { --p->event_count; return; }
        p->events[begin].kind = K_ERROR;
    }
    yx_sc_push_event(p, EV_END, p->events[begin].kind, yx_sc_last_token_end(p));
}

/* Forgets the expected and unexpected token errors. */
static void yx_sc_clear_expected(yx_sc *p)
{
    p->expected_count = p->unexpected_count = 0;
    if (++p->expected_generation == 0) {
        if (p->expected_index)
            memset(p->expected_index, 0,
                   p->expected_index_capacity * sizeof(*p->expected_index));
        p->expected_generation = 1;
    }
}

static size_t yx_sc_expected_hash(size_t start, size_t end, uint8_t id)
{
    uint64_t key = (uint64_t)start * UINT64_C(0x9e3779b97f4a7c15) ^
                   ((uint64_t)end << 17) ^ id;
    key ^= key >> 33;
    key *= UINT64_C(0xff51afd7ed558ccd);
    key ^= key >> 33;
    return (size_t)key;
}

/* Adds expected[index] to the hash index, growing it as needed. */
static bool yx_sc_index_expected(yx_sc *p, size_t index)
{
    size_t mask, i;
    if ((index + 1) * 2 > p->expected_index_capacity) {
        size_t capacity = p->expected_index_capacity ?
                          p->expected_index_capacity * 2 : 256;
        yx_sc_expected_slot *grown;
        while ((index + 1) * 2 > capacity) capacity *= 2;
        if (capacity > SIZE_MAX / sizeof(*grown)) return false;
        grown = calloc(capacity, sizeof(*grown));
        if (!grown) return false;
        free(p->expected_index);
        p->expected_index = grown;
        p->expected_index_capacity = capacity;
        /* Re-index the earlier entries of this generation. */
        mask = capacity - 1;
        for (size_t j = 0; j < index; ++j) {
            const yx_sc_expected *entry = &p->expected[j];
            for (i = yx_sc_expected_hash(entry->start, entry->end, entry->id) & mask;
                 grown[i].generation == p->expected_generation;
                 i = (i + 1) & mask) {}
            grown[i].index = j;
            grown[i].generation = p->expected_generation;
        }
    }
    mask = p->expected_index_capacity - 1;
    for (i = yx_sc_expected_hash(p->expected[index].start,
                                 p->expected[index].end,
                                 p->expected[index].id) & mask;
         p->expected_index[i].generation == p->expected_generation;
         i = (i + 1) & mask) {}
    p->expected_index[i].index = index;
    p->expected_index[i].generation = p->expected_generation;
    return true;
}

static void yx_sc_add_expected(yx_sc *p, size_t start, size_t end,
                               uint8_t id, const yx_sc_set *set,
                               const char *description)
{
    yx_sc_expected *entry = NULL;
    if (p->expected_index_capacity) {
        size_t mask = p->expected_index_capacity - 1;
        for (size_t i = yx_sc_expected_hash(start, end, id) & mask;
             p->expected_index[i].generation == p->expected_generation;
             i = (i + 1) & mask) {
            yx_sc_expected *candidate = &p->expected[p->expected_index[i].index];
            if (candidate->start == start && candidate->end == end &&
                candidate->id == id) {
                entry = candidate;
                break;
            }
        }
    }
    if (!entry) {
        if (!yx_sc_grow((void **)&p->expected, &p->expected_capacity,
                        p->expected_count + 1, sizeof(*p->expected))) {
            p->broken = true;
            return;
        }
        entry = &p->expected[p->expected_count];
        entry->start = start;
        entry->end = end;
        entry->id = id;
        entry->count = 0;
        if (!yx_sc_index_expected(p, p->expected_count)) {
            p->broken = true;
            return;
        }
        ++p->expected_count;
    }
    for (size_t i = 0; i < (description ? 1 : set->count); ++i) {
        const char *text = description ? description :
                           yx_sc_descriptions[set->ids[i]];
        bool present = false;
        for (size_t j = 0; j < entry->count; ++j)
            if (strcmp(entry->descriptions[j], text) == 0) present = true;
        if (!present && entry->count < sizeof(entry->descriptions) /
                                       sizeof(*entry->descriptions))
            entry->descriptions[entry->count++] = text;
    }
}

#if defined(__GNUC__) || defined(__clang__)
static char *yx_sc_format(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
#endif

static char *yx_sc_format(const char *format, ...)
{
    va_list args, copy;
    int length;
    char *text;
    va_start(args, format);
    va_copy(copy, args);
    length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (length < 0 || !(text = malloc((size_t)length + 1))) {
        va_end(args);
        return NULL;
    }
    vsnprintf(text, (size_t)length + 1, format, args);
    va_end(args);
    return text;
}

/* Appends a copy of `text` to the pending errors. */
static bool yx_sc_add_pending(yx_sc *p, size_t start, size_t end,
                              const char *text)
{
    char *message = yx_sc_format("%s", text);
    if (!message ||
        !yx_sc_grow((void **)&p->pending, &p->pending_capacity,
                    p->pending_count + 1, sizeof(*p->pending))) {
        free(message);
        return false;
    }
    p->pending[p->pending_count].start = start;
    p->pending[p->pending_count].end = end;
    p->pending[p->pending_count].message = message;
    ++p->pending_count;
    return true;
}

/* ParserImpl::handle_errors. */
static void yx_sc_handle_errors(yx_sc *p)
{
    yx_sc_expected *expected = NULL;
    size_t unexpected = SIZE_MAX, start, end;
    const char *actual;
    size_t actual_length;
    char *message = NULL, *list = NULL;
    /* Of several errors at the largest offset, the last one is used. */
    for (size_t i = 0; i < p->expected_count; ++i)
        if (!expected || p->expected[i].start >= expected->start)
            expected = &p->expected[i];
    for (size_t i = 0; i < p->unexpected_count; ++i)
        if (unexpected == SIZE_MAX ||
            p->unexpected[i].start >= p->unexpected[unexpected].start)
            unexpected = i;
    if (unexpected != SIZE_MAX &&
        (!expected || p->unexpected[unexpected].start > expected->start)) {
        start = p->unexpected[unexpected].start;
        end = p->unexpected[unexpected].end;
        expected = NULL;
    } else if (expected) {
        start = expected->start;
        end = expected->end;
    } else {
        yx_sc_clear_expected(p);
        return;
    }
    for (size_t i = 0; i < p->pending_count; ++i)
        if (p->pending[i].start == start && p->pending[i].end == end) {
            yx_sc_clear_expected(p);
            return;
        }
    actual = (const char *)p->lexer.s + start;
    actual_length = end - start;
    if (expected) {
        if (expected->id == T_UNKNOWN && actual_length >= 2 &&
            memcmp(actual, "/*", 2) == 0)
            message = yx_sc_format("unclosed comment");
        else if (expected->id == T_UNKNOWN && actual_length && *actual == '"')
            message = yx_sc_format("unclosed literal string");
        else if (expected->id == T_UNKNOWN && actual_length && *actual == '/')
            message = yx_sc_format("unclosed regular expression");
        else {
            const char *last = expected->descriptions[expected->count - 1];
            size_t size = 1;
            for (size_t i = 0; i + 1 < expected->count; ++i)
                size += strlen(expected->descriptions[i]) + 2;
            list = malloc(size);
            if (!list) { p->broken = true; return; }
            list[0] = 0;
            for (size_t i = 0; i + 1 < expected->count; ++i) {
                if (i) strcat(list, ", ");
                strcat(list, expected->descriptions[i]);
            }
            if (expected->count == 1) {
                if (!actual_length)
                    message = yx_sc_format("expecting %s, found end of file", last);
                else if (actual_length > 15)
                    message = yx_sc_format("expecting %s", last);
                else
                    message = yx_sc_format("expecting %s, found `%.*s`", last,
                                           (int)actual_length, actual);
            } else if (!actual_length)
                message = yx_sc_format("expecting %s or %s, found end of file",
                                       list, last);
            else if (actual_length > 15)
                message = yx_sc_format("expecting %s or %s", list, last);
            else
                message = yx_sc_format("expecting %s or %s, found `%.*s`", list,
                                       last, (int)actual_length, actual);
            free(list);
        }
    } else if (!actual_length) {
        message = yx_sc_format("unexpected end of file");
    } else {
        message = yx_sc_format("unexpected `%.*s`", (int)actual_length, actual);
    }
    yx_sc_clear_expected(p);
    if (!message ||
        !yx_sc_grow((void **)&p->pending, &p->pending_capacity,
                    p->pending_count + 1, sizeof(*p->pending))) {
        free(message);
        p->broken = true;
        return;
    }
    p->pending[p->pending_count].start = start;
    p->pending[p->pending_count].end = end;
    p->pending[p->pending_count].message = message;
    ++p->pending_count;
}

static void yx_sc_end(yx_sc *p)
{
    if (p->depth) --p->depth;
    if (p->state == ST_MAX_DEPTH) {
        yx_sc_output_end(p, true);
    } else if (FAILED(p)) {
        if (p->opt_depth == 0) yx_sc_handle_errors(p);
        yx_sc_output_end(p, true);
    } else {
        yx_sc_output_end(p, false);
    }
}

static void yx_sc_recover(yx_sc *p, const yx_sc_set *set)
{
    const yx_sc_token *token;
    bool state_was_ok, in_set;
    if (p->state == ST_OUT_OF_FUEL) return;
    /* After the nesting limit, recovery waits until unwinding is back in
     * a top-level rule section. */
    if (p->state == ST_MAX_DEPTH && p->depth > 1) return;
    state_was_ok = p->state == ST_OK;
    p->state = ST_OK;
    token = yx_sc_peek_non_trivia(p);
    if (!token) return;
    in_set = yx_sc_set_contains(set, token->id);
    if (!p->pending_count && !in_set)
        yx_sc_add_expected(p, token->start, token->end, token->id, set, NULL);
    if (!state_was_ok || !in_set) yx_sc_handle_errors(p);
    if (!in_set) {
        yx_sc_trivia(p);
        yx_sc_begin(p, K_ERROR);
        yx_sc_bump(p);
        while ((token = yx_sc_peek_non_trivia(p)) != NULL &&
               !yx_sc_set_contains(set, token->id)) {
            yx_sc_trivia(p);
            yx_sc_bump(p);
        }
        yx_sc_end(p);
    }
}

static void yx_sc_expect_d(yx_sc *p, const yx_sc_set *set,
                           const char *description)
{
    const yx_sc_token *token;
    size_t start, end;
    uint8_t id;
    bool match;
    if (FAILED(p)) return;
    token = yx_sc_peek_non_trivia(p);
    if (!token) {
        start = end = p->lexer.n;
        id = T_UNKNOWN;
        match = false;
    } else {
        start = token->start;
        end = token->end;
        id = token->id;
        match = yx_sc_set_contains(set, id);
    }
    if (p->not_depth > 0 && match) {
        if (!yx_sc_grow((void **)&p->unexpected, &p->unexpected_capacity,
                        p->unexpected_count + 1, sizeof(*p->unexpected))) {
            p->broken = true;
            return;
        }
        p->unexpected[p->unexpected_count].start = start;
        p->unexpected[p->unexpected_count].end = end;
        ++p->unexpected_count;
    } else if (p->not_depth == 0 && !match) {
        yx_sc_add_expected(p, start, end, id, set, description);
    }
    if (match) {
        yx_sc_trivia(p);
        yx_sc_bump(p);
    } else {
        yx_sc_set_state(p, ST_FAILURE);
    }
}

static void yx_sc_expect(yx_sc *p, const yx_sc_set *set)
{
    yx_sc_expect_d(p, set, NULL);
}

typedef void (*yx_sc_rule)(yx_sc *p);

static void yx_sc_opt(yx_sc *p, yx_sc_rule rule)
{
    yx_sc_bookmark bookmark;
    if (FAILED(p)) return;
    bookmark = yx_sc_mark(p);
    yx_sc_trivia(p);
    ++p->opt_depth;
    rule(p);
    --p->opt_depth;
    if (p->state == ST_FAILURE || p->state == ST_MAX_DEPTH) {
        yx_sc_set_state(p, ST_OK);
        yx_sc_restore(p, &bookmark);
    }
}

static void yx_sc_opt_expect(yx_sc *p, const yx_sc_set *set)
{
    yx_sc_bookmark bookmark;
    if (FAILED(p)) return;
    bookmark = yx_sc_mark(p);
    yx_sc_trivia(p);
    ++p->opt_depth;
    yx_sc_expect(p, set);
    --p->opt_depth;
    if (p->state == ST_FAILURE || p->state == ST_MAX_DEPTH) {
        yx_sc_set_state(p, ST_OK);
        yx_sc_restore(p, &bookmark);
    }
}

static void yx_sc_not(yx_sc *p, yx_sc_rule rule)
{
    yx_sc_bookmark bookmark;
    if (FAILED(p)) return;
    bookmark = yx_sc_mark(p);
    yx_sc_trivia(p);
    ++p->not_depth;
    rule(p);
    --p->not_depth;
    if (p->state == ST_OK) p->state = ST_FAILURE;
    else if (p->state == ST_FAILURE) p->state = ST_OK;
    yx_sc_restore(p, &bookmark);
}

static void yx_sc_if_next(yx_sc *p, const yx_sc_set *set, yx_sc_rule rule)
{
    const yx_sc_token *token;
    if (FAILED(p)) return;
    token = yx_sc_peek_non_trivia(p);
    if (!token) return;
    if (yx_sc_set_contains(set, token->id)) {
        yx_sc_trivia(p);
        rule(p);
    } else {
        yx_sc_add_expected(p, token->start, token->end, token->id, set, NULL);
    }
}

static void yx_sc_then(yx_sc *p, yx_sc_rule rule)
{
    if (FAILED(p)) return;
    yx_sc_trivia(p);
    rule(p);
}

static void yx_sc_n_or_more(yx_sc *p, size_t n, yx_sc_rule rule)
{
    if (FAILED(p)) return;
    for (size_t i = 0; i < n; ++i) {
        yx_sc_trivia(p);
        rule(p);
        if (FAILED(p)) return;
    }
    for (;;) {
        yx_sc_bookmark bookmark = yx_sc_mark(p);
        yx_sc_trivia(p);
        ++p->opt_depth;
        rule(p);
        --p->opt_depth;
        if (FAILED(p) || p->broken) {
            yx_sc_set_state(p, ST_OK);
            yx_sc_restore(p, &bookmark);
            break;
        }
    }
}

static void yx_sc_zero_or_more(yx_sc *p, yx_sc_rule rule)
{
    yx_sc_n_or_more(p, 0, rule);
}

static void yx_sc_one_or_more(yx_sc *p, yx_sc_rule rule)
{
    yx_sc_n_or_more(p, 1, rule);
}

static size_t yx_sc_cache_slot(uint64_t key, size_t mask)
{
    key ^= key >> 33;
    key *= UINT64_C(0xff51afd7ed558ccd);
    key ^= key >> 33;
    return (size_t)key & mask;
}

static bool yx_sc_cache_has(const yx_sc *p, uint64_t key)
{
    size_t mask, i;
    if (!p->cache_capacity) return false;
    mask = p->cache_capacity - 1;
    for (i = yx_sc_cache_slot(key, mask);; i = (i + 1) & mask) {
        if (p->cache[i].generation != p->cache_generation) return false;
        if (p->cache[i].key == key) return true;
    }
}

/* Forgets every cached failure (the parser clears its cache after each
 * top-level item). */
static void yx_sc_cache_clear(yx_sc *p)
{
    p->cache_count = 0;
    if (++p->cache_generation == 0) {
        if (p->cache) memset(p->cache, 0, p->cache_capacity * sizeof(*p->cache));
        p->cache_generation = 1;
    }
}

static bool yx_sc_cache_add(yx_sc *p, uint64_t key)
{
    size_t mask, i;
    if ((p->cache_count + 1) * 2 > p->cache_capacity) {
        size_t capacity = p->cache_capacity ? p->cache_capacity * 2 : 1024;
        yx_sc_cache_entry *old = p->cache, *grown;
        size_t old_capacity = p->cache_capacity;
        if (capacity > SIZE_MAX / sizeof(*p->cache)) return false;
        grown = calloc(capacity, sizeof(*grown));
        if (!grown) return false;
        p->cache = grown;
        p->cache_capacity = capacity;
        p->cache_count = 0;
        mask = capacity - 1;
        for (size_t j = 0; j < old_capacity; ++j) {
            const yx_sc_cache_entry *entry = &old[j];
            if (entry->generation != p->cache_generation) continue;
            for (i = yx_sc_cache_slot(entry->key, mask);
                 p->cache[i].generation == p->cache_generation;
                 i = (i + 1) & mask) {}
            p->cache[i].key = entry->key;
            p->cache[i].generation = p->cache_generation;
            ++p->cache_count;
        }
        free(old);
    }
    mask = p->cache_capacity - 1;
    for (i = yx_sc_cache_slot(key, mask);; i = (i + 1) & mask) {
        if (p->cache[i].generation != p->cache_generation) break;
        if (p->cache[i].key == key) return true;
    }
    p->cache[i].key = key;
    p->cache[i].generation = p->cache_generation;
    ++p->cache_count;
    return true;
}

static void yx_sc_cached(yx_sc *p, uint8_t kind, yx_sc_rule rule)
{
    uint64_t key;
    if (FAILED(p)) return;
    key = ((uint64_t)p->current << 2) | kind;
    if (yx_sc_cache_has(p, key)) {
        yx_sc_set_state(p, ST_FAILURE);
        return;
    }
    rule(p);
    if (p->state == ST_FAILURE && !yx_sc_cache_add(p, key))
        p->broken = true;
}

typedef struct { yx_sc_bookmark bookmark; bool matched; } yx_sc_alt;

static void yx_sc_alt_begin(yx_sc *p, yx_sc_alt *alt)
{
    alt->bookmark = yx_sc_mark(p);
    alt->matched = false;
}

static void yx_sc_alt_try(yx_sc *p, yx_sc_alt *alt, yx_sc_rule rule)
{
    if (FAILED(p) || alt->matched) return;
    yx_sc_trivia(p);
    ++p->opt_depth;
    rule(p);
    --p->opt_depth;
    if (p->state == ST_OK) {
        alt->matched = true;
    } else if (p->state == ST_FAILURE || p->state == ST_MAX_DEPTH) {
        yx_sc_set_state(p, ST_OK);
        yx_sc_restore(p, &alt->bookmark);
    }
}

static void yx_sc_alt_end(yx_sc *p, yx_sc_alt *alt)
{
    yx_sc_set_state(p, alt->matched ? ST_OK : ST_FAILURE);
}

static void yx_sc_enter_mode(yx_sc *p, int mode)
{
    if (FAILED(p)) return;
    p->lexer.mode = mode;
}

/* ------------------------------------------------------------------------
 * Grammar rules, in the order of parser/src/parser/mod.rs.
 * --------------------------------------------------------------------- */

static void yx_sc_rule_mods(yx_sc *p);
static void yx_sc_rule_tags(yx_sc *p);
static void yx_sc_meta_blk(yx_sc *p);
static void yx_sc_meta_def(yx_sc *p);
static void yx_sc_patterns_blk(yx_sc *p);
static void yx_sc_pattern_def(yx_sc *p);
static void yx_sc_pattern_mods(yx_sc *p);
static void yx_sc_pattern_mod(yx_sc *p);
static void yx_sc_hex_pattern(yx_sc *p);
static void yx_sc_hex_sub_pattern(yx_sc *p);
static void yx_sc_hex_alternative(yx_sc *p);
static void yx_sc_hex_jump(yx_sc *p);
static void yx_sc_condition_blk(yx_sc *p);
static void yx_sc_boolean_expr(yx_sc *p);
static void yx_sc_boolean_term(yx_sc *p);
static void yx_sc_at_or_in(yx_sc *p);
static void yx_sc_expr(yx_sc *p);
static void yx_sc_func_call(yx_sc *p);
static void yx_sc_range(yx_sc *p);
static void yx_sc_term(yx_sc *p);
static void yx_sc_primary_expr(yx_sc *p);
static void yx_sc_for_expr(yx_sc *p);
static void yx_sc_of_expr(yx_sc *p);
static void yx_sc_with_expr(yx_sc *p);
static void yx_sc_with_declarations(yx_sc *p);
static void yx_sc_with_declaration(yx_sc *p);
static void yx_sc_quantifier(yx_sc *p);
static void yx_sc_iterable(yx_sc *p);
static void yx_sc_boolean_expr_tuple(yx_sc *p);
static void yx_sc_expr_tuple(yx_sc *p);
static void yx_sc_pattern_ident_tuple(yx_sc *p);

#define RECOVERY_TOP SET(T_GLOBAL_KW, T_PRIVATE_KW, T_RULE_KW, T_IMPORT_KW, \
                         T_INCLUDE_KW)

static void yx_sc_import_stmt(yx_sc *p)
{
    uint8_t context = p->context;
    p->context = CTX_UTF8;
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_IMPORT_KW));
    yx_sc_expect(p, SET(T_STRING_LIT));
    yx_sc_end(p);
    p->context = context;
}

static void yx_sc_include_stmt(yx_sc *p)
{
    uint8_t context = p->context;
    p->context = CTX_UTF8;
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_INCLUDE_KW));
    yx_sc_expect(p, SET(T_STRING_LIT));
    yx_sc_end(p);
    p->context = context;
}

static void yx_sc_rule_decl(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_opt(p, yx_sc_rule_mods);
    yx_sc_expect(p, SET(T_RULE_KW));
    yx_sc_expect(p, SET(T_IDENT));
    yx_sc_if_next(p, SET(T_COLON), yx_sc_rule_tags);
    yx_sc_expect(p, SET(T_L_BRACE));
    yx_sc_if_next(p, SET(T_META_KW), yx_sc_meta_blk);
    yx_sc_if_next(p, SET(T_STRINGS_KW), yx_sc_patterns_blk);
    yx_sc_then(p, yx_sc_condition_blk);
    yx_sc_expect(p, SET(T_R_BRACE));
    yx_sc_end(p);
}

static void yx_sc_rule_mods_private(yx_sc *p)
{
    yx_sc_expect(p, SET(T_PRIVATE_KW));
    yx_sc_opt_expect(p, SET(T_GLOBAL_KW));
}

static void yx_sc_rule_mods_global(yx_sc *p)
{
    yx_sc_expect(p, SET(T_GLOBAL_KW));
    yx_sc_opt_expect(p, SET(T_PRIVATE_KW));
}

static void yx_sc_rule_mods(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_NODE);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_rule_mods_private);
    yx_sc_alt_try(p, &alt, yx_sc_rule_mods_global);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_expect_ident(yx_sc *p) { yx_sc_expect(p, SET(T_IDENT)); }

static void yx_sc_rule_tags(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_COLON));
    yx_sc_one_or_more(p, yx_sc_expect_ident);
    yx_sc_end(p);
    yx_sc_recover(p, SET(T_L_BRACE));
}

static void yx_sc_meta_blk(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_META_KW));
    yx_sc_expect(p, SET(T_COLON));
    yx_sc_one_or_more(p, yx_sc_meta_def);
    yx_sc_end(p);
    yx_sc_recover(p, SET(T_STRINGS_KW, T_CONDITION_KW));
}

static void yx_sc_meta_number(yx_sc *p)
{
    yx_sc_opt_expect(p, SET(T_HYPHEN));
    yx_sc_expect(p, SET(T_INTEGER_LIT, T_FLOAT_LIT));
}

static void yx_sc_meta_other(yx_sc *p)
{
    yx_sc_expect(p, SET(T_STRING_LIT, T_TRUE_KW, T_FALSE_KW));
}

static void yx_sc_meta_def(yx_sc *p)
{
    yx_sc_alt alt;
    uint8_t context = p->context;
    p->context = CTX_META;
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_IDENT));
    yx_sc_expect(p, SET(T_EQUAL));
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_meta_number);
    yx_sc_alt_try(p, &alt, yx_sc_meta_other);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
    p->context = context;
}

static void yx_sc_patterns_blk(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_STRINGS_KW));
    yx_sc_expect(p, SET(T_COLON));
    yx_sc_one_or_more(p, yx_sc_pattern_def);
    yx_sc_end(p);
    yx_sc_recover(p, SET(T_CONDITION_KW));
}

static void yx_sc_expect_string(yx_sc *p) { yx_sc_expect(p, SET(T_STRING_LIT)); }
static void yx_sc_expect_regexp(yx_sc *p) { yx_sc_expect(p, SET(T_REGEXP)); }

static void yx_sc_pattern_def(yx_sc *p)
{
    yx_sc_alt alt;
    uint8_t context = p->context;
    p->context = CTX_EXPR;
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_PATTERN_IDENT));
    yx_sc_expect(p, SET(T_EQUAL));
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_expect_string);
    yx_sc_alt_try(p, &alt, yx_sc_expect_regexp);
    yx_sc_alt_try(p, &alt, yx_sc_hex_pattern);
    yx_sc_alt_end(p, &alt);
    yx_sc_opt(p, yx_sc_pattern_mods);
    yx_sc_end(p);
    p->context = context;
}

static void yx_sc_pattern_mods(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_one_or_more(p, yx_sc_pattern_mod);
    yx_sc_end(p);
}

#define PATTERN_MODIFIER "pattern modifier"

static void yx_sc_pattern_mod_simple(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_ASCII_KW, T_WIDE_KW, T_NOCASE_KW, T_PRIVATE_KW,
                          T_FULLWORD_KW), PATTERN_MODIFIER);
}

static void yx_sc_base64_alphabet(yx_sc *p)
{
    uint8_t context = p->context;
    yx_sc_expect(p, SET(T_L_PAREN));
    p->context = CTX_UTF8;
    yx_sc_then(p, yx_sc_expect_string);
    p->context = context;
    if (FAILED(p)) return;
    yx_sc_expect(p, SET(T_R_PAREN));
}

static void yx_sc_pattern_mod_base64(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_BASE64_KW, T_BASE64WIDE_KW), PATTERN_MODIFIER);
    yx_sc_if_next(p, SET(T_L_PAREN), yx_sc_base64_alphabet);
}

static void yx_sc_expect_integer(yx_sc *p) { yx_sc_expect(p, SET(T_INTEGER_LIT)); }

static void yx_sc_xor_upper(yx_sc *p)
{
    yx_sc_expect(p, SET(T_HYPHEN));
    yx_sc_then(p, yx_sc_expect_integer);
}

static void yx_sc_xor_range(yx_sc *p)
{
    uint8_t context = p->context;
    yx_sc_expect(p, SET(T_L_PAREN));
    if (FAILED(p)) return;
    p->context = CTX_U8;
    yx_sc_trivia(p);
    yx_sc_expect(p, SET(T_INTEGER_LIT));
    yx_sc_if_next(p, SET(T_HYPHEN), yx_sc_xor_upper);
    p->context = context;
    yx_sc_expect(p, SET(T_R_PAREN));
}

static void yx_sc_pattern_mod_xor(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_XOR_KW), PATTERN_MODIFIER);
    yx_sc_if_next(p, SET(T_L_PAREN), yx_sc_xor_range);
}

static void yx_sc_pattern_mod(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_NODE);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_pattern_mod_simple);
    yx_sc_alt_try(p, &alt, yx_sc_pattern_mod_base64);
    yx_sc_alt_try(p, &alt, yx_sc_pattern_mod_xor);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_hex_pattern(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_L_BRACE));
    yx_sc_enter_mode(p, MODE_HEX);
    yx_sc_then(p, yx_sc_hex_sub_pattern);
    yx_sc_expect(p, SET(T_R_BRACE));
    yx_sc_end(p);
}

static void yx_sc_expect_hex_byte(yx_sc *p) { yx_sc_expect(p, SET(T_HEX_BYTE)); }

static void yx_sc_hex_piece(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_expect_hex_byte);
    yx_sc_alt_try(p, &alt, yx_sc_hex_alternative);
    yx_sc_alt_end(p, &alt);
}

static void yx_sc_hex_jumps_and_piece(yx_sc *p)
{
    yx_sc_zero_or_more(p, yx_sc_hex_jump);
    yx_sc_hex_piece(p);
}

static void yx_sc_hex_sub_pattern(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_hex_piece(p);
    yx_sc_zero_or_more(p, yx_sc_hex_jumps_and_piece);
    yx_sc_end(p);
}

static void yx_sc_hex_alternative_more(yx_sc *p)
{
    yx_sc_expect(p, SET(T_PIPE));
    yx_sc_then(p, yx_sc_hex_sub_pattern);
}

static void yx_sc_hex_alternative(yx_sc *p)
{
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_then(p, yx_sc_hex_sub_pattern);
    yx_sc_zero_or_more(p, yx_sc_hex_alternative_more);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_hex_range_jump(yx_sc *p)
{
    yx_sc_opt_expect(p, SET(T_INTEGER_LIT));
    yx_sc_expect(p, SET(T_HYPHEN));
    yx_sc_opt_expect(p, SET(T_INTEGER_LIT));
}

static void yx_sc_hex_jump(yx_sc *p)
{
    yx_sc_alt alt;
    uint8_t context = p->context;
    p->context = CTX_U32;
    yx_sc_begin(p, K_NODE);
    yx_sc_expect(p, SET(T_L_BRACKET));
    yx_sc_enter_mode(p, MODE_JUMP);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_hex_range_jump);
    yx_sc_alt_try(p, &alt, yx_sc_expect_integer);
    yx_sc_alt_end(p, &alt);
    yx_sc_expect(p, SET(T_R_BRACKET));
    yx_sc_end(p);
    p->context = context;
}

static void yx_sc_condition_expr(yx_sc *p)
{
    yx_sc_boolean_expr(p);
    yx_sc_recover(p, SET(T_R_BRACE));
}

static void yx_sc_condition_blk(yx_sc *p)
{
    p->context = CTX_EXPR;
    yx_sc_begin(p, K_CONDITION_BLK);
    yx_sc_expect(p, SET(T_CONDITION_KW));
    yx_sc_expect(p, SET(T_COLON));
    yx_sc_then(p, yx_sc_condition_expr);
    yx_sc_end(p);
    yx_sc_recover(p, SET(T_R_BRACE));
}

static void yx_sc_boolean_more(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_AND_KW, T_OR_KW), "operator");
    yx_sc_then(p, yx_sc_boolean_term);
}

static void yx_sc_boolean_expr(yx_sc *p)
{
    yx_sc_begin(p, K_BOOLEAN_EXPR);
    yx_sc_then(p, yx_sc_boolean_term);
    yx_sc_zero_or_more(p, yx_sc_boolean_more);
    yx_sc_end(p);
}

#define EXPRESSION "expression"

static void yx_sc_term_pattern(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_PATTERN_IDENT), EXPRESSION);
    yx_sc_if_next(p, SET(T_AT_KW, T_IN_KW), yx_sc_at_or_in);
}

static void yx_sc_term_bool(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_TRUE_KW, T_FALSE_KW), EXPRESSION);
}

static void yx_sc_term_not(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_NOT_KW, T_DEFINED_KW), EXPRESSION);
    yx_sc_then(p, yx_sc_boolean_term);
}

static void yx_sc_comparison(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_EQ, T_NE, T_LE, T_LT, T_GE, T_GT, T_CONTAINS_KW,
                          T_ICONTAINS_KW, T_STARTSWITH_KW, T_ISTARTSWITH_KW,
                          T_ENDSWITH_KW, T_IENDSWITH_KW, T_IEQUALS_KW,
                          T_MATCHES_KW), EXPRESSION);
    yx_sc_then(p, yx_sc_expr);
}

static void yx_sc_term_comparisons(yx_sc *p)
{
    yx_sc_expr(p);
    yx_sc_zero_or_more(p, yx_sc_comparison);
}

static void yx_sc_term_paren(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_L_PAREN), EXPRESSION);
    yx_sc_then(p, yx_sc_boolean_expr);
    yx_sc_expect(p, SET(T_R_PAREN));
}

static void yx_sc_boolean_term(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_BOOLEAN_TERM);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_term_pattern);
    yx_sc_alt_try(p, &alt, yx_sc_term_bool);
    yx_sc_alt_try(p, &alt, yx_sc_term_not);
    yx_sc_alt_try(p, &alt, yx_sc_for_expr);
    yx_sc_alt_try(p, &alt, yx_sc_of_expr);
    yx_sc_alt_try(p, &alt, yx_sc_with_expr);
    yx_sc_alt_try(p, &alt, yx_sc_term_comparisons);
    yx_sc_alt_try(p, &alt, yx_sc_term_paren);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_at_expr(yx_sc *p)
{
    yx_sc_expect(p, SET(T_AT_KW));
    yx_sc_then(p, yx_sc_expr);
}

static void yx_sc_in_range(yx_sc *p)
{
    yx_sc_expect(p, SET(T_IN_KW));
    yx_sc_then(p, yx_sc_range);
}

static void yx_sc_at_or_in(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_at_expr);
    yx_sc_alt_try(p, &alt, yx_sc_in_range);
    yx_sc_alt_end(p, &alt);
}

static void yx_sc_operator_term(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_PLUS, T_HYPHEN, T_ASTERISK, T_BACKSLASH,
                          T_PERCENT, T_SHL, T_SHR, T_AMPERSAND, T_PIPE,
                          T_CARET), "operator");
    yx_sc_then(p, yx_sc_term);
}

static void yx_sc_expr_body(yx_sc *p)
{
    yx_sc_begin(p, K_EXPR);
    yx_sc_then(p, yx_sc_term);
    yx_sc_zero_or_more(p, yx_sc_operator_term);
    yx_sc_end(p);
}

static void yx_sc_expr(yx_sc *p)
{
    yx_sc_cached(p, K_EXPR, yx_sc_expr_body);
}

static void yx_sc_more_boolean_args(yx_sc *p)
{
    yx_sc_expect(p, SET(T_COMMA));
    yx_sc_then(p, yx_sc_boolean_expr);
}

static void yx_sc_call_args(yx_sc *p)
{
    yx_sc_boolean_expr(p);
    yx_sc_zero_or_more(p, yx_sc_more_boolean_args);
}

static void yx_sc_func_call(yx_sc *p)
{
    yx_sc_begin(p, K_FUNC_CALL);
    yx_sc_expect(p, SET(T_IDENT));
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_opt(p, yx_sc_call_args);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_range(yx_sc *p)
{
    yx_sc_begin(p, K_RANGE);
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_then(p, yx_sc_expr);
    yx_sc_expect(p, SET(T_DOT));
    yx_sc_expect(p, SET(T_DOT));
    yx_sc_then(p, yx_sc_expr);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_term_literal(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_FLOAT_LIT, T_INTEGER_LIT, T_STRING_LIT, T_REGEXP,
                          T_FILESIZE_KW, T_ENTRYPOINT_KW), EXPRESSION);
}

static void yx_sc_term_count(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_PATTERN_COUNT), EXPRESSION);
    yx_sc_if_next(p, SET(T_IN_KW), yx_sc_in_range);
}

static void yx_sc_offset_index(yx_sc *p)
{
    yx_sc_expect(p, SET(T_L_BRACKET));
    if (FAILED(p)) return;
    yx_sc_trivia(p);
    yx_sc_expr(p);
    yx_sc_expect(p, SET(T_R_BRACKET));
}

static void yx_sc_term_offset(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_PATTERN_OFFSET, T_PATTERN_LENGTH), EXPRESSION);
    yx_sc_if_next(p, SET(T_L_BRACKET), yx_sc_offset_index);
}

static void yx_sc_term_minus(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_HYPHEN), EXPRESSION);
    yx_sc_then(p, yx_sc_term);
}

static void yx_sc_term_bitwise_not(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_TILDE), EXPRESSION);
    yx_sc_then(p, yx_sc_term);
}

static void yx_sc_term_expr_paren(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_L_PAREN), EXPRESSION);
    yx_sc_then(p, yx_sc_expr);
    yx_sc_expect(p, SET(T_R_PAREN));
}

static void yx_sc_dot_primary(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_DOT), EXPRESSION);
    yx_sc_then(p, yx_sc_primary_expr);
}

static void yx_sc_term_primary(yx_sc *p)
{
    yx_sc_primary_expr(p);
    yx_sc_zero_or_more(p, yx_sc_dot_primary);
}

static void yx_sc_term_body(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_TERM);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_term_literal);
    yx_sc_alt_try(p, &alt, yx_sc_term_count);
    yx_sc_alt_try(p, &alt, yx_sc_term_offset);
    yx_sc_alt_try(p, &alt, yx_sc_term_minus);
    yx_sc_alt_try(p, &alt, yx_sc_term_bitwise_not);
    yx_sc_alt_try(p, &alt, yx_sc_term_expr_paren);
    yx_sc_alt_try(p, &alt, yx_sc_term_primary);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_term(yx_sc *p)
{
    yx_sc_cached(p, K_TERM, yx_sc_term_body);
}

static void yx_sc_primary_index(yx_sc *p)
{
    yx_sc_expect(p, SET(T_IDENT));
    yx_sc_expect(p, SET(T_L_BRACKET));
    yx_sc_then(p, yx_sc_expr);
    yx_sc_expect(p, SET(T_R_BRACKET));
}

static void yx_sc_primary_expr(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_PRIMARY_EXPR);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_func_call);
    yx_sc_alt_try(p, &alt, yx_sc_primary_index);
    yx_sc_alt_try(p, &alt, yx_sc_expect_ident);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_expect_them(yx_sc *p) { yx_sc_expect(p, SET(T_THEM_KW)); }

static void yx_sc_them_or_tuple(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_expect_them);
    yx_sc_alt_try(p, &alt, yx_sc_pattern_ident_tuple);
    yx_sc_alt_end(p, &alt);
}

static void yx_sc_for_of(yx_sc *p)
{
    yx_sc_expect(p, SET(T_OF_KW));
    yx_sc_them_or_tuple(p);
}

static void yx_sc_more_idents(yx_sc *p)
{
    yx_sc_expect(p, SET(T_COMMA));
    yx_sc_expect(p, SET(T_IDENT));
}

static void yx_sc_for_in(yx_sc *p)
{
    yx_sc_expect(p, SET(T_IDENT));
    yx_sc_zero_or_more(p, yx_sc_more_idents);
    yx_sc_expect(p, SET(T_IN_KW));
    yx_sc_iterable(p);
}

static void yx_sc_body_expr(yx_sc *p)
{
    yx_sc_boolean_expr(p);
    yx_sc_recover(p, SET(T_R_PAREN));
}

static void yx_sc_for_expr(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_FOR_EXPR);
    yx_sc_expect_d(p, SET(T_FOR_KW), EXPRESSION);
    yx_sc_then(p, yx_sc_quantifier);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_for_of);
    yx_sc_alt_try(p, &alt, yx_sc_for_in);
    yx_sc_alt_end(p, &alt);
    yx_sc_expect(p, SET(T_COLON));
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_then(p, yx_sc_body_expr);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_of_set(yx_sc *p)
{
    yx_sc_them_or_tuple(p);
    yx_sc_if_next(p, SET(T_AT_KW, T_IN_KW), yx_sc_at_or_in);
}

static void yx_sc_expect_at_or_in(yx_sc *p)
{
    yx_sc_expect(p, SET(T_AT_KW, T_IN_KW));
}

static void yx_sc_of_tuple(yx_sc *p)
{
    yx_sc_boolean_expr_tuple(p);
    yx_sc_not(p, yx_sc_expect_at_or_in);
}

static void yx_sc_of_expr(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_OF_EXPR);
    yx_sc_then(p, yx_sc_quantifier);
    yx_sc_expect(p, SET(T_OF_KW));
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_of_set);
    yx_sc_alt_try(p, &alt, yx_sc_of_tuple);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_with_expr(yx_sc *p)
{
    yx_sc_begin(p, K_WITH_EXPR);
    yx_sc_expect_d(p, SET(T_WITH_KW), EXPRESSION);
    yx_sc_then(p, yx_sc_with_declarations);
    yx_sc_expect(p, SET(T_COLON));
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_then(p, yx_sc_body_expr);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_more_declarations(yx_sc *p)
{
    yx_sc_expect(p, SET(T_COMMA));
    yx_sc_with_declaration(p);
}

static void yx_sc_with_declarations(yx_sc *p)
{
    yx_sc_begin(p, K_WITH_DECLS);
    yx_sc_then(p, yx_sc_with_declaration);
    yx_sc_zero_or_more(p, yx_sc_more_declarations);
    yx_sc_end(p);
    yx_sc_recover(p, SET(T_COLON, T_L_PAREN));
}

static void yx_sc_with_declaration(yx_sc *p)
{
    yx_sc_begin(p, K_WITH_DECL);
    yx_sc_expect(p, SET(T_IDENT));
    yx_sc_expect(p, SET(T_EQUAL));
    yx_sc_then(p, yx_sc_expr);
    yx_sc_end(p);
}

static void yx_sc_quantifier_keyword(yx_sc *p)
{
    yx_sc_expect_d(p, SET(T_ALL_KW, T_NONE_KW, T_ANY_KW), EXPRESSION);
}

static void yx_sc_expect_percent(yx_sc *p) { yx_sc_expect(p, SET(T_PERCENT)); }

static void yx_sc_quantifier_percent(yx_sc *p)
{
    yx_sc_term(p);
    yx_sc_expect_percent(p);
}

static void yx_sc_quantifier_expr(yx_sc *p)
{
    yx_sc_expr(p);
    yx_sc_not(p, yx_sc_expect_percent);
}

static void yx_sc_quantifier(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_QUANTIFIER);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_quantifier_keyword);
    yx_sc_alt_try(p, &alt, yx_sc_quantifier_percent);
    yx_sc_alt_try(p, &alt, yx_sc_quantifier_expr);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_iterable(yx_sc *p)
{
    yx_sc_alt alt;
    yx_sc_begin(p, K_ITERABLE);
    yx_sc_alt_begin(p, &alt);
    yx_sc_alt_try(p, &alt, yx_sc_range);
    yx_sc_alt_try(p, &alt, yx_sc_expr_tuple);
    yx_sc_alt_try(p, &alt, yx_sc_expr);
    yx_sc_alt_end(p, &alt);
    yx_sc_end(p);
}

static void yx_sc_boolean_expr_tuple(yx_sc *p)
{
    yx_sc_begin(p, K_BOOLEAN_EXPR_TUPLE);
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_then(p, yx_sc_boolean_expr);
    yx_sc_zero_or_more(p, yx_sc_more_boolean_args);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_more_exprs(yx_sc *p)
{
    yx_sc_expect(p, SET(T_COMMA));
    yx_sc_then(p, yx_sc_expr);
}

static void yx_sc_expr_tuple(yx_sc *p)
{
    yx_sc_begin(p, K_EXPR_TUPLE);
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_then(p, yx_sc_expr);
    yx_sc_zero_or_more(p, yx_sc_more_exprs);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

static void yx_sc_more_pattern_idents(yx_sc *p)
{
    yx_sc_expect(p, SET(T_COMMA));
    yx_sc_expect(p, SET(T_PATTERN_IDENT));
    yx_sc_opt_expect(p, SET(T_ASTERISK));
}

static void yx_sc_pattern_ident_tuple(yx_sc *p)
{
    yx_sc_begin(p, K_PATTERN_IDENT_TUPLE);
    yx_sc_expect(p, SET(T_L_PAREN));
    yx_sc_expect(p, SET(T_PATTERN_IDENT));
    yx_sc_opt_expect(p, SET(T_ASTERISK));
    yx_sc_zero_or_more(p, yx_sc_more_pattern_idents);
    yx_sc_expect(p, SET(T_R_PAREN));
    yx_sc_end(p);
}

/* ------------------------------------------------------------------------
 * AST depth: Builder::check_ast_depth in parser/src/ast/cst2ast.rs
 * (YARA-X v1.23.0). Flat operator chains have shallow CSTs but build deep
 * BinaryExpr/NAryExpr trees, so the AST builder also bounds the depth of
 * every condition. The condition's AST shape is rebuilt from the CST
 * events: Pratt precedence, n-ary flattening of `and`, `or`, `+`, `-`,
 * `*`, `\` and `%`, minus/integer literal folding and the coalescing of
 * dotted primary expressions, so the reported node and span are the ones
 * of a depth-first traversal of the upstream AST.
 * --------------------------------------------------------------------- */

enum { A_LEAF, A_INTEGER, A_IDENT, A_UNARY, A_BINARY, A_NARY, A_CALL,
       A_LOOKUP, A_OTHER };

#define YX_SC_AST_NONE SIZE_MAX

typedef struct {
    size_t start, end;
    size_t first, last, next;
    uint8_t kind, op;
    /* A_INTEGER: 0 zero, 1 positive, 2 negative, 3 unsigned (above
     * i64::MAX), 4 unsigned 2^63. */
    uint8_t sign;
} yx_sc_ast;

typedef struct {
    const yx_sc *p;
    size_t at, end;
    yx_sc_ast *nodes;
    size_t count, capacity;
    /* The CST did not have the expected shape, or an allocation failed. */
    bool failed;
    /* The AST builder rejects the rule before checking its depth. */
    bool aborted;
} yx_sc_ab;

typedef size_t (*yx_sc_ab_operand)(yx_sc_ab *b);

static const yx_sc_event *yx_sc_ab_peek(yx_sc_ab *b)
{
    while (b->at < b->end) {
        const yx_sc_event *event = &b->p->events[b->at];
        if (event->type == EV_TOKEN && (event->id == T_WHITESPACE ||
            event->id == T_NEWLINE || event->id == T_COMMENT)) {
            ++b->at;
            continue;
        }
        return event;
    }
    return NULL;
}

static bool yx_sc_ab_is_token(yx_sc_ab *b, uint8_t id)
{
    const yx_sc_event *event = yx_sc_ab_peek(b);
    return event && event->type == EV_TOKEN && event->id == id;
}

static bool yx_sc_ab_is_begin(yx_sc_ab *b, uint8_t kind)
{
    const yx_sc_event *event = yx_sc_ab_peek(b);
    return event && event->type == EV_BEGIN && event->kind == kind;
}

/* Consumes a token, returning its event, or fails. */
static const yx_sc_event *yx_sc_ab_token(yx_sc_ab *b, uint8_t id)
{
    if (!yx_sc_ab_is_token(b, id)) { b->failed = true; return NULL; }
    return &b->p->events[b->at++];
}

static bool yx_sc_ab_node_event(yx_sc_ab *b, uint8_t type, uint8_t kind)
{
    const yx_sc_event *event = yx_sc_ab_peek(b);
    if (!event || event->type != type || event->kind != kind) {
        b->failed = true;
        return false;
    }
    ++b->at;
    return true;
}

static bool yx_sc_ab_begin(yx_sc_ab *b, uint8_t kind)
{
    return yx_sc_ab_node_event(b, EV_BEGIN, kind);
}

static bool yx_sc_ab_end(yx_sc_ab *b, uint8_t kind)
{
    return yx_sc_ab_node_event(b, EV_END, kind);
}

static size_t yx_sc_ab_node(yx_sc_ab *b, uint8_t kind, size_t start,
                            size_t end)
{
    yx_sc_ast *node;
    if (!yx_sc_grow((void **)&b->nodes, &b->capacity, b->count + 1,
                    sizeof(*b->nodes))) {
        b->failed = true;
        return YX_SC_AST_NONE;
    }
    node = &b->nodes[b->count];
    memset(node, 0, sizeof(*node));
    node->kind = kind;
    node->start = start;
    node->end = end;
    node->first = node->last = node->next = YX_SC_AST_NONE;
    return b->count++;
}

static void yx_sc_ab_append(yx_sc_ab *b, size_t parent, size_t child)
{
    yx_sc_ast *node = &b->nodes[parent];
    b->nodes[child].next = YX_SC_AST_NONE;
    if (node->last == YX_SC_AST_NONE) node->first = child;
    else b->nodes[node->last].next = child;
    node->last = child;
}

static void yx_sc_ab_prepend(yx_sc_ab *b, size_t parent, size_t child)
{
    yx_sc_ast *node = &b->nodes[parent];
    b->nodes[child].next = node->first;
    node->first = child;
    if (node->last == YX_SC_AST_NONE) node->last = child;
}

/* Removes and returns the first child. */
static size_t yx_sc_ab_detach_first(yx_sc_ab *b, size_t parent)
{
    yx_sc_ast *node = &b->nodes[parent];
    size_t child = node->first;
    if (child == YX_SC_AST_NONE) return child;
    node->first = b->nodes[child].next;
    if (node->last == child) node->last = YX_SC_AST_NONE;
    b->nodes[child].next = YX_SC_AST_NONE;
    return child;
}

static size_t yx_sc_ab_leaf(yx_sc_ab *b, uint8_t kind)
{
    const yx_sc_event *event = &b->p->events[b->at++];
    return yx_sc_ab_node(b, kind, event->start, event->end);
}

static size_t yx_sc_ab_unary(yx_sc_ab *b, size_t start, size_t operand)
{
    size_t node = yx_sc_ab_node(b, A_UNARY, start, b->nodes[operand].end);
    if (node != YX_SC_AST_NONE) yx_sc_ab_append(b, node, operand);
    return node;
}

/* Binding powers of the Pratt parser (Builder::pratt_parser). */
static bool yx_sc_ab_binding_power(uint8_t id, unsigned *left,
                                   unsigned *right)
{
    unsigned power;
    switch (id) {
    case T_OR_KW: power = 1; break;
    case T_AND_KW: power = 3; break;
    case T_EQ: case T_NE: case T_CONTAINS_KW: case T_ICONTAINS_KW:
    case T_STARTSWITH_KW: case T_ISTARTSWITH_KW: case T_ENDSWITH_KW:
    case T_IENDSWITH_KW: case T_IEQUALS_KW: case T_MATCHES_KW:
        power = 5; break;
    case T_LT: case T_LE: case T_GT: case T_GE: power = 7; break;
    case T_PIPE: power = 9; break;
    case T_CARET: power = 11; break;
    case T_AMPERSAND: power = 13; break;
    case T_SHL: case T_SHR: power = 15; break;
    case T_PLUS: case T_HYPHEN: power = 17; break;
    case T_ASTERISK: case T_BACKSLASH: case T_PERCENT: power = 19; break;
    case T_DOT: power = 21; break;
    default: return false;
    }
    *left = power;
    *right = power + 1;
    return true;
}

/* Operators whose same-operator left operand is extended (NAryExpr). */
static bool yx_sc_ab_nary(uint8_t id)
{
    return id == T_OR_KW || id == T_AND_KW || id == T_PLUS ||
           id == T_HYPHEN || id == T_ASTERISK || id == T_BACKSLASH ||
           id == T_PERCENT || id == T_DOT;
}

static size_t yx_sc_ab_combine(yx_sc_ab *b, uint8_t op, size_t lhs,
                               size_t rhs)
{
    size_t node;
    bool nary = yx_sc_ab_nary(op);
    if (nary && b->nodes[lhs].kind == A_NARY && b->nodes[lhs].op == op) {
        yx_sc_ab_append(b, lhs, rhs);
        b->nodes[lhs].end = b->nodes[rhs].end;
        return lhs;
    }
    node = yx_sc_ab_node(b, nary ? A_NARY : A_BINARY, b->nodes[lhs].start,
                         b->nodes[rhs].end);
    if (node == YX_SC_AST_NONE) return node;
    b->nodes[node].op = op;
    yx_sc_ab_append(b, node, lhs);
    yx_sc_ab_append(b, node, rhs);
    return node;
}

static size_t yx_sc_ab_pratt(yx_sc_ab *b, yx_sc_ab_operand operand,
                             unsigned minimum)
{
    size_t lhs = operand(b);
    while (lhs != YX_SC_AST_NONE) {
        const yx_sc_event *event = yx_sc_ab_peek(b);
        unsigned left, right;
        uint8_t op;
        size_t rhs;
        if (!event || event->type == EV_END) break;
        if (event->type != EV_TOKEN ||
            !yx_sc_ab_binding_power(event->id, &left, &right)) {
            b->failed = true;
            return YX_SC_AST_NONE;
        }
        if (left < minimum) break;
        op = event->id;
        ++b->at;
        rhs = yx_sc_ab_pratt(b, operand, right);
        if (rhs == YX_SC_AST_NONE) return rhs;
        lhs = yx_sc_ab_combine(b, op, lhs, rhs);
    }
    return lhs;
}

static size_t yx_sc_ab_boolean_expr(yx_sc_ab *b);
static size_t yx_sc_ab_expr(yx_sc_ab *b);
static size_t yx_sc_ab_term(yx_sc_ab *b);

/* RANGE: appends both bounds to `parent` and returns the closing paren's
 * end (0 on failure). */
static size_t yx_sc_ab_range(yx_sc_ab *b, size_t parent)
{
    const yx_sc_event *close;
    size_t lower, upper;
    if (!yx_sc_ab_begin(b, K_RANGE) || !yx_sc_ab_token(b, T_L_PAREN)) return 0;
    if ((lower = yx_sc_ab_expr(b)) == YX_SC_AST_NONE) return 0;
    if (!yx_sc_ab_token(b, T_DOT) || !yx_sc_ab_token(b, T_DOT)) return 0;
    if ((upper = yx_sc_ab_expr(b)) == YX_SC_AST_NONE) return 0;
    if (!(close = yx_sc_ab_token(b, T_R_PAREN)) || !yx_sc_ab_end(b, K_RANGE))
        return 0;
    yx_sc_ab_append(b, parent, lower);
    yx_sc_ab_append(b, parent, upper);
    return close->end;
}

/* `at <expr>` or `in <range>` after a pattern or an `of` expression:
 * appends the anchor's expressions and returns its end, or 0 when there
 * is no anchor (or on failure). */
static size_t yx_sc_ab_anchor(yx_sc_ab *b, size_t parent)
{
    if (yx_sc_ab_is_token(b, T_AT_KW)) {
        size_t expr;
        ++b->at;
        if ((expr = yx_sc_ab_expr(b)) == YX_SC_AST_NONE) return 0;
        yx_sc_ab_append(b, parent, expr);
        return b->nodes[expr].end;
    }
    if (yx_sc_ab_is_token(b, T_IN_KW)) {
        ++b->at;
        return yx_sc_ab_range(b, parent);
    }
    return 0;
}

/* LiteralInteger: i64 first, then u64 (signed_or_unsigned_integer_lit);
 * a literal outside both aborts the rule. */
static size_t yx_sc_ab_integer(yx_sc_ab *b)
{
    const yx_sc_event *event = &b->p->events[b->at];
    const uint8_t *s = b->p->lexer.s;
    size_t at = event->start, end = event->end, node;
    uint64_t value = 0, multiplier = 1, base = 10;
    bool fits = true;
    if (end - at >= 2 && (s[end - 2] == 'K' || s[end - 2] == 'M') &&
        s[end - 1] == 'B') {
        multiplier = s[end - 2] == 'K' ? 1024 : 1024 * 1024;
        end -= 2;
    }
    if (end - at > 2 && s[at] == '0' && (s[at + 1] == 'x' || s[at + 1] == 'o')) {
        base = s[at + 1] == 'x' ? 16 : 8;
        at += 2;
    }
    for (; at < end && fits; ++at) {
        unsigned digit;
        if (s[at] == '_') continue;
        digit = yx_sc_digit(s[at]) ? (unsigned)(s[at] - '0') :
                (unsigned)((s[at] | 0x20) - 'a' + 10);
        if (value > (UINT64_MAX - digit) / base) fits = false;
        else value = value * base + digit;
    }
    if (fits && value > UINT64_MAX / multiplier) fits = false;
    if (!fits) {
        b->aborted = true;
        return YX_SC_AST_NONE;
    }
    value *= multiplier;
    node = yx_sc_ab_leaf(b, A_INTEGER);
    if (node == YX_SC_AST_NONE) return node;
    b->nodes[node].sign = value == 0 ? 0 : value <= INT64_MAX ? 1 :
                          value == UINT64_C(0x8000000000000000) ? 4 : 3;
    return node;
}

/* `-` <term>: a positive integer literal that is not parenthesized folds
 * into a negative literal. */
static size_t yx_sc_ab_minus(yx_sc_ab *b, size_t start, size_t operand)
{
    yx_sc_ast *node = &b->nodes[operand];
    if (node->kind == A_INTEGER &&
        !memchr(b->p->lexer.s + start, '(', node->end - start)) {
        if (node->sign == 1 || node->sign == 4) {
            node->sign = 2;
            node->start = start;
            return operand;
        }
        if (node->sign == 3) {
            b->aborted = true;
            return YX_SC_AST_NONE;
        }
    }
    return yx_sc_ab_unary(b, start, operand);
}

static size_t yx_sc_ab_call(yx_sc_ab *b)
{
    const yx_sc_event *ident, *close;
    size_t node;
    if (!yx_sc_ab_begin(b, K_FUNC_CALL) ||
        !(ident = yx_sc_ab_token(b, T_IDENT)))
        return YX_SC_AST_NONE;
    node = yx_sc_ab_node(b, A_CALL, ident->start, ident->end);
    if (node == YX_SC_AST_NONE || !yx_sc_ab_token(b, T_L_PAREN))
        return YX_SC_AST_NONE;
    while (yx_sc_ab_is_begin(b, K_BOOLEAN_EXPR)) {
        size_t argument = yx_sc_ab_boolean_expr(b);
        if (argument == YX_SC_AST_NONE) return argument;
        yx_sc_ab_append(b, node, argument);
        if (yx_sc_ab_is_token(b, T_COMMA)) ++b->at;
    }
    if (!(close = yx_sc_ab_token(b, T_R_PAREN)) || !yx_sc_ab_end(b, K_FUNC_CALL))
        return YX_SC_AST_NONE;
    b->nodes[node].end = close->end;
    return node;
}

static size_t yx_sc_ab_primary(yx_sc_ab *b)
{
    size_t node;
    if (!yx_sc_ab_begin(b, K_PRIMARY_EXPR)) return YX_SC_AST_NONE;
    if (yx_sc_ab_is_begin(b, K_FUNC_CALL)) node = yx_sc_ab_call(b);
    else if (yx_sc_ab_is_token(b, T_IDENT)) node = yx_sc_ab_leaf(b, A_IDENT);
    else { b->failed = true; return YX_SC_AST_NONE; }
    if (node == YX_SC_AST_NONE) return node;
    if (yx_sc_ab_is_token(b, T_L_BRACKET)) {
        const yx_sc_event *close;
        size_t index, lookup;
        ++b->at;
        if ((index = yx_sc_ab_expr(b)) == YX_SC_AST_NONE ||
            !(close = yx_sc_ab_token(b, T_R_BRACKET)))
            return YX_SC_AST_NONE;
        lookup = yx_sc_ab_node(b, A_LOOKUP, b->nodes[node].start, close->end);
        if (lookup == YX_SC_AST_NONE) return lookup;
        yx_sc_ab_append(b, lookup, node);
        yx_sc_ab_append(b, lookup, index);
        node = lookup;
    }
    if (!yx_sc_ab_end(b, K_PRIMARY_EXPR)) return YX_SC_AST_NONE;
    return node;
}

/* The coalescing of consecutive dot-separated primary expressions; returns
 * the merged node, or YX_SC_AST_NONE when `x` and `y` stay separate. */
static size_t yx_sc_ab_coalesce(yx_sc_ab *b, size_t x, size_t y)
{
    uint8_t kx = b->nodes[x].kind, ky = b->nodes[y].kind;
    bool field = kx == A_NARY && b->nodes[x].op == T_DOT;
    size_t node, primary;
    if (kx == A_IDENT && ky == A_IDENT) {
        node = yx_sc_ab_node(b, A_NARY, b->nodes[x].start, b->nodes[y].end);
        if (node == YX_SC_AST_NONE) return node;
        b->nodes[node].op = T_DOT;
        yx_sc_ab_append(b, node, x);
        yx_sc_ab_append(b, node, y);
        return node;
    }
    if (field && ky == A_IDENT) {
        yx_sc_ab_append(b, x, y);
        b->nodes[x].end = b->nodes[y].end;
        return x;
    }
    if ((field || kx == A_IDENT) && ky == A_CALL) {
        /* The object of a method call; FuncCall's span does not cover
         * it. */
        yx_sc_ab_prepend(b, y, x);
        return y;
    }
    if ((field || kx == A_IDENT) && ky == A_LOOKUP) {
        primary = yx_sc_ab_detach_first(b, y);
        if (field) {
            yx_sc_ab_append(b, x, primary);
            b->nodes[x].end = b->nodes[primary].end;
            node = x;
        } else {
            node = yx_sc_ab_node(b, A_NARY, b->nodes[x].start,
                                 b->nodes[primary].end);
            if (node == YX_SC_AST_NONE) return node;
            b->nodes[node].op = T_DOT;
            yx_sc_ab_append(b, node, x);
            yx_sc_ab_append(b, node, primary);
        }
        yx_sc_ab_prepend(b, y, node);
        b->nodes[y].start = b->nodes[node].start;
        return y;
    }
    return YX_SC_AST_NONE;
}

/* PRIMARY_EXPR (`.` PRIMARY_EXPR)* */
static size_t yx_sc_ab_primary_chain(yx_sc_ab *b)
{
    size_t *items = NULL, count = 0, capacity = 0, acc, result;
    acc = yx_sc_ab_primary(b);
    while (acc != YX_SC_AST_NONE && yx_sc_ab_is_token(b, T_DOT)) {
        size_t next, merged;
        ++b->at;
        if ((next = yx_sc_ab_primary(b)) == YX_SC_AST_NONE) { acc = next; break; }
        merged = yx_sc_ab_coalesce(b, acc, next);
        if (b->failed) { acc = YX_SC_AST_NONE; break; }
        if (merged != YX_SC_AST_NONE) { acc = merged; continue; }
        if (!yx_sc_grow((void **)&items, &capacity, count + 1, sizeof(*items))) {
            b->failed = true;
            acc = YX_SC_AST_NONE;
            break;
        }
        items[count++] = acc;
        acc = next;
    }
    if (acc == YX_SC_AST_NONE || !count) { free(items); return acc; }
    result = yx_sc_ab_node(b, A_NARY, b->nodes[items[0]].start, b->nodes[acc].end);
    if (result != YX_SC_AST_NONE) {
        b->nodes[result].op = T_DOT;
        for (size_t i = 0; i < count; ++i) yx_sc_ab_append(b, result, items[i]);
        yx_sc_ab_append(b, result, acc);
    }
    free(items);
    return result;
}

static size_t yx_sc_ab_term(yx_sc_ab *b)
{
    const yx_sc_event *event;
    size_t node = YX_SC_AST_NONE, start;
    if (!yx_sc_ab_begin(b, K_TERM)) return node;
    event = yx_sc_ab_peek(b);
    if (event && event->type == EV_BEGIN && event->kind == K_PRIMARY_EXPR) {
        node = yx_sc_ab_primary_chain(b);
    } else if (event && event->type == EV_TOKEN) {
        start = event->start;
        switch (event->id) {
        case T_FLOAT_LIT: case T_STRING_LIT: case T_REGEXP:
        case T_FILESIZE_KW: case T_ENTRYPOINT_KW:
            node = yx_sc_ab_leaf(b, A_LEAF);
            break;
        case T_INTEGER_LIT:
            node = yx_sc_ab_integer(b);
            break;
        case T_PATTERN_COUNT:
            node = yx_sc_ab_leaf(b, A_OTHER);
            if (node != YX_SC_AST_NONE && yx_sc_ab_is_token(b, T_IN_KW)) {
                size_t end;
                ++b->at;
                if (!(end = yx_sc_ab_range(b, node))) return YX_SC_AST_NONE;
                b->nodes[node].end = end;
            }
            break;
        case T_PATTERN_OFFSET: case T_PATTERN_LENGTH:
            node = yx_sc_ab_leaf(b, A_OTHER);
            if (node != YX_SC_AST_NONE && yx_sc_ab_is_token(b, T_L_BRACKET)) {
                const yx_sc_event *close;
                size_t index;
                ++b->at;
                if ((index = yx_sc_ab_expr(b)) == YX_SC_AST_NONE ||
                    !(close = yx_sc_ab_token(b, T_R_BRACKET)))
                    return YX_SC_AST_NONE;
                yx_sc_ab_append(b, node, index);
                b->nodes[node].end = close->end;
            }
            break;
        case T_TILDE:
            ++b->at;
            if ((node = yx_sc_ab_term(b)) != YX_SC_AST_NONE)
                node = yx_sc_ab_unary(b, start, node);
            break;
        case T_HYPHEN:
            ++b->at;
            if ((node = yx_sc_ab_term(b)) != YX_SC_AST_NONE)
                node = yx_sc_ab_minus(b, start, node);
            break;
        case T_L_PAREN:
            ++b->at;
            node = yx_sc_ab_expr(b);
            if (node != YX_SC_AST_NONE && !yx_sc_ab_token(b, T_R_PAREN))
                node = YX_SC_AST_NONE;
            break;
        default:
            b->failed = true;
            break;
        }
    } else {
        b->failed = true;
    }
    if (node == YX_SC_AST_NONE || !yx_sc_ab_end(b, K_TERM)) return YX_SC_AST_NONE;
    return node;
}

static size_t yx_sc_ab_expr(yx_sc_ab *b)
{
    size_t node;
    if (!yx_sc_ab_begin(b, K_EXPR)) return YX_SC_AST_NONE;
    node = yx_sc_ab_pratt(b, yx_sc_ab_term, 0);
    if (node == YX_SC_AST_NONE || !yx_sc_ab_end(b, K_EXPR)) return YX_SC_AST_NONE;
    return node;
}

/* QUANTIFIER: appends a percentage or expression quantifier to `parent`;
 * `*start`/`*end` receive the quantifier's span. */
static bool yx_sc_ab_quantifier(yx_sc_ab *b, size_t parent, size_t *start,
                                size_t *end)
{
    size_t node;
    if (!yx_sc_ab_begin(b, K_QUANTIFIER)) return false;
    if (yx_sc_ab_is_token(b, T_ALL_KW) || yx_sc_ab_is_token(b, T_NONE_KW) ||
        yx_sc_ab_is_token(b, T_ANY_KW)) {
        const yx_sc_event *event = &b->p->events[b->at++];
        *start = event->start;
        *end = event->end;
    } else {
        if (yx_sc_ab_is_begin(b, K_TERM)) {
            if ((node = yx_sc_ab_term(b)) == YX_SC_AST_NONE ||
                !yx_sc_ab_token(b, T_PERCENT))
                return false;
        } else if ((node = yx_sc_ab_expr(b)) == YX_SC_AST_NONE) {
            return false;
        }
        *start = b->nodes[node].start;
        *end = b->nodes[node].end;
        yx_sc_ab_append(b, parent, node);
    }
    return yx_sc_ab_end(b, K_QUANTIFIER);
}

/* PATTERN_IDENT_TUPLE: the span from the first item to the last one. */
static bool yx_sc_ab_pattern_tuple(yx_sc_ab *b, size_t *start, size_t *end)
{
    bool first = true;
    if (!yx_sc_ab_begin(b, K_PATTERN_IDENT_TUPLE) ||
        !yx_sc_ab_token(b, T_L_PAREN))
        return false;
    for (;;) {
        const yx_sc_event *ident = yx_sc_ab_token(b, T_PATTERN_IDENT);
        if (!ident) return false;
        if (first) *start = ident->start;
        first = false;
        *end = ident->end;
        if (yx_sc_ab_is_token(b, T_ASTERISK)) *end = b->p->events[b->at++].end;
        if (!yx_sc_ab_is_token(b, T_COMMA)) break;
        ++b->at;
    }
    return yx_sc_ab_token(b, T_R_PAREN) && yx_sc_ab_end(b, K_PATTERN_IDENT_TUPLE);
}

static size_t yx_sc_ab_for(yx_sc_ab *b)
{
    const yx_sc_event *keyword, *close;
    size_t node, start = 0, end = 0, body;
    if (!yx_sc_ab_begin(b, K_FOR_EXPR) || !(keyword = yx_sc_ab_token(b, T_FOR_KW)))
        return YX_SC_AST_NONE;
    node = yx_sc_ab_node(b, A_OTHER, keyword->start, keyword->end);
    if (node == YX_SC_AST_NONE || !yx_sc_ab_quantifier(b, node, &start, &end))
        return YX_SC_AST_NONE;
    if (yx_sc_ab_is_token(b, T_OF_KW)) {
        ++b->at;
        if (yx_sc_ab_is_token(b, T_THEM_KW)) ++b->at;
        else if (!yx_sc_ab_pattern_tuple(b, &start, &end)) return YX_SC_AST_NONE;
    } else {
        for (;;) {
            if (!yx_sc_ab_token(b, T_IDENT)) return YX_SC_AST_NONE;
            if (yx_sc_ab_is_token(b, T_COMMA)) { ++b->at; continue; }
            if (!yx_sc_ab_token(b, T_IN_KW)) return YX_SC_AST_NONE;
            break;
        }
        if (!yx_sc_ab_begin(b, K_ITERABLE)) return YX_SC_AST_NONE;
        if (yx_sc_ab_is_begin(b, K_RANGE)) {
            if (!yx_sc_ab_range(b, node)) return YX_SC_AST_NONE;
        } else if (yx_sc_ab_is_begin(b, K_EXPR_TUPLE)) {
            ++b->at;
            if (!yx_sc_ab_token(b, T_L_PAREN)) return YX_SC_AST_NONE;
            for (;;) {
                size_t item = yx_sc_ab_expr(b);
                if (item == YX_SC_AST_NONE) return item;
                yx_sc_ab_append(b, node, item);
                if (!yx_sc_ab_is_token(b, T_COMMA)) break;
                ++b->at;
            }
            if (!yx_sc_ab_token(b, T_R_PAREN) || !yx_sc_ab_end(b, K_EXPR_TUPLE))
                return YX_SC_AST_NONE;
        } else {
            size_t item = yx_sc_ab_expr(b);
            if (item == YX_SC_AST_NONE) return item;
            yx_sc_ab_append(b, node, item);
        }
        if (!yx_sc_ab_end(b, K_ITERABLE)) return YX_SC_AST_NONE;
    }
    if (!yx_sc_ab_token(b, T_COLON) || !yx_sc_ab_token(b, T_L_PAREN) ||
        (body = yx_sc_ab_boolean_expr(b)) == YX_SC_AST_NONE ||
        !(close = yx_sc_ab_token(b, T_R_PAREN)) || !yx_sc_ab_end(b, K_FOR_EXPR))
        return YX_SC_AST_NONE;
    yx_sc_ab_append(b, node, body);
    b->nodes[node].end = close->end;
    return node;
}

static size_t yx_sc_ab_of(yx_sc_ab *b)
{
    size_t node, start = 0, end = 0, items_end = 0, anchor;
    if (!yx_sc_ab_begin(b, K_OF_EXPR)) return YX_SC_AST_NONE;
    node = yx_sc_ab_node(b, A_OTHER, 0, 0);
    if (node == YX_SC_AST_NONE || !yx_sc_ab_quantifier(b, node, &start, &end) ||
        !yx_sc_ab_token(b, T_OF_KW))
        return YX_SC_AST_NONE;
    if (yx_sc_ab_is_token(b, T_THEM_KW)) {
        items_end = b->p->events[b->at++].end;
    } else if (yx_sc_ab_is_begin(b, K_PATTERN_IDENT_TUPLE)) {
        size_t items_start;
        if (!yx_sc_ab_pattern_tuple(b, &items_start, &items_end))
            return YX_SC_AST_NONE;
    } else {
        if (!yx_sc_ab_begin(b, K_BOOLEAN_EXPR_TUPLE) || !yx_sc_ab_token(b, T_L_PAREN))
            return YX_SC_AST_NONE;
        for (;;) {
            size_t item = yx_sc_ab_boolean_expr(b);
            if (item == YX_SC_AST_NONE) return item;
            yx_sc_ab_append(b, node, item);
            items_end = b->nodes[item].end;
            if (!yx_sc_ab_is_token(b, T_COMMA)) break;
            ++b->at;
        }
        if (!yx_sc_ab_token(b, T_R_PAREN) || !yx_sc_ab_end(b, K_BOOLEAN_EXPR_TUPLE))
            return YX_SC_AST_NONE;
    }
    anchor = yx_sc_ab_anchor(b, node);
    if (b->failed || !yx_sc_ab_end(b, K_OF_EXPR)) return YX_SC_AST_NONE;
    b->nodes[node].start = start;
    b->nodes[node].end = anchor ? anchor : items_end;
    return node;
}

static size_t yx_sc_ab_with(yx_sc_ab *b)
{
    const yx_sc_event *keyword, *close;
    size_t node, body;
    if (!yx_sc_ab_begin(b, K_WITH_EXPR) || !(keyword = yx_sc_ab_token(b, T_WITH_KW)))
        return YX_SC_AST_NONE;
    node = yx_sc_ab_node(b, A_OTHER, keyword->start, keyword->end);
    if (node == YX_SC_AST_NONE || !yx_sc_ab_begin(b, K_WITH_DECLS))
        return YX_SC_AST_NONE;
    for (;;) {
        size_t expr;
        if (!yx_sc_ab_begin(b, K_WITH_DECL) || !yx_sc_ab_token(b, T_IDENT) ||
            !yx_sc_ab_token(b, T_EQUAL) ||
            (expr = yx_sc_ab_expr(b)) == YX_SC_AST_NONE ||
            !yx_sc_ab_end(b, K_WITH_DECL))
            return YX_SC_AST_NONE;
        yx_sc_ab_append(b, node, expr);
        if (!yx_sc_ab_is_token(b, T_COMMA)) break;
        ++b->at;
    }
    if (!yx_sc_ab_end(b, K_WITH_DECLS) || !yx_sc_ab_token(b, T_COLON) ||
        !yx_sc_ab_token(b, T_L_PAREN) ||
        (body = yx_sc_ab_boolean_expr(b)) == YX_SC_AST_NONE ||
        !(close = yx_sc_ab_token(b, T_R_PAREN)) || !yx_sc_ab_end(b, K_WITH_EXPR))
        return YX_SC_AST_NONE;
    yx_sc_ab_append(b, node, body);
    b->nodes[node].end = close->end;
    return node;
}

static size_t yx_sc_ab_boolean_term(yx_sc_ab *b)
{
    const yx_sc_event *event;
    size_t node = YX_SC_AST_NONE, start;
    if (!yx_sc_ab_begin(b, K_BOOLEAN_TERM)) return node;
    event = yx_sc_ab_peek(b);
    if (event && event->type == EV_TOKEN) {
        start = event->start;
        switch (event->id) {
        case T_TRUE_KW: case T_FALSE_KW:
            node = yx_sc_ab_leaf(b, A_LEAF);
            break;
        case T_NOT_KW: case T_DEFINED_KW:
            ++b->at;
            if ((node = yx_sc_ab_boolean_term(b)) != YX_SC_AST_NONE)
                node = yx_sc_ab_unary(b, start, node);
            break;
        case T_L_PAREN:
            ++b->at;
            node = yx_sc_ab_boolean_expr(b);
            if (node != YX_SC_AST_NONE && !yx_sc_ab_token(b, T_R_PAREN))
                node = YX_SC_AST_NONE;
            break;
        case T_PATTERN_IDENT: {
            size_t end;
            node = yx_sc_ab_leaf(b, A_OTHER);
            if (node == YX_SC_AST_NONE) break;
            end = yx_sc_ab_anchor(b, node);
            if (b->failed) node = YX_SC_AST_NONE;
            else if (end) b->nodes[node].end = end;
            break;
        }
        default:
            b->failed = true;
            break;
        }
    } else if (event && event->type == EV_BEGIN) {
        switch (event->kind) {
        case K_FOR_EXPR: node = yx_sc_ab_for(b); break;
        case K_OF_EXPR: node = yx_sc_ab_of(b); break;
        case K_WITH_EXPR: node = yx_sc_ab_with(b); break;
        case K_EXPR: node = yx_sc_ab_pratt(b, yx_sc_ab_expr, 0); break;
        default: b->failed = true; break;
        }
    } else {
        b->failed = true;
    }
    if (node == YX_SC_AST_NONE || !yx_sc_ab_end(b, K_BOOLEAN_TERM))
        return YX_SC_AST_NONE;
    return node;
}

static size_t yx_sc_ab_boolean_expr(yx_sc_ab *b)
{
    size_t node;
    if (!yx_sc_ab_begin(b, K_BOOLEAN_EXPR)) return YX_SC_AST_NONE;
    node = yx_sc_ab_pratt(b, yx_sc_ab_boolean_term, 0);
    if (node == YX_SC_AST_NONE || !yx_sc_ab_end(b, K_BOOLEAN_EXPR))
        return YX_SC_AST_NONE;
    return node;
}

static int yx_sc_literal_error_at(yx_sc *p, size_t stop, bool record);

/* Adds the pending "nesting limit reached" error of a rule whose condition
 * AST is deeper than MAX_AST_DEPTH. The rule's own node must be free of
 * errors and literal errors (those abort the AST builder first). Returns
 * false on allocation failure. */
static bool yx_sc_check_ast_depth(yx_sc *p)
{
    yx_sc_ab b;
    size_t close = SIZE_MAX, condition = SIZE_MAX, tokens = 0, depth = 0;
    size_t root, *stack = NULL, stack_count = 0, stack_capacity = 0;
    size_t found = YX_SC_AST_NONE;
    bool ok = true;
    if (!p->event_count || p->events[0].type != EV_BEGIN ||
        p->events[0].kind != K_NODE)
        return true;
    for (size_t i = 0; i < p->event_count; ++i) {
        const yx_sc_event *event = &p->events[i];
        if (event->type == EV_BEGIN) {
            if (event->kind == K_ERROR) return true;
            if (event->kind == K_CONDITION_BLK && depth == 1) condition = i;
            ++depth;
        } else if (event->type == EV_END) {
            if (--depth == 0) { close = i; break; }
        } else if (condition != SIZE_MAX && event->id != T_WHITESPACE &&
                   event->id != T_NEWLINE && event->id != T_COMMENT) {
            ++tokens;
        }
    }
    /* Every AST node owns at least one token, so a condition with at most
     * MAX_AST_DEPTH tokens cannot be too deep. */
    if (close == SIZE_MAX || condition == SIZE_MAX ||
        tokens <= YX_SC_MAX_CST_DEPTH)
        return true;
    for (size_t i = 0; i < p->pending_count; ++i)
        if (p->pending[i].start < p->events[close].end) return true;
    switch (yx_sc_literal_error_at(p, p->events[close].end, false)) {
    case 0: break;
    case 1: return true;
    default: return false;
    }
    memset(&b, 0, sizeof(b));
    b.p = p;
    b.at = condition + 1;
    b.end = close;
    if (!yx_sc_ab_token(&b, T_CONDITION_KW) || !yx_sc_ab_token(&b, T_COLON) ||
        (root = yx_sc_ab_boolean_expr(&b)) == YX_SC_AST_NONE) {
        free(b.nodes);
        return true;
    }
    /* Depth-first: a node's first child is entered before its next
     * sibling. The stack holds (node, depth) pairs. */
    if (!yx_sc_grow((void **)&stack, &stack_capacity, 2, sizeof(*stack))) {
        ok = false;
    } else {
        stack[stack_count++] = root;
        stack[stack_count++] = 1;
    }
    while (ok && stack_count) {
        size_t level = stack[--stack_count], node = stack[--stack_count];
        if (level > YX_SC_MAX_CST_DEPTH) { found = node; break; }
        if (!yx_sc_grow((void **)&stack, &stack_capacity, stack_count + 4,
                        sizeof(*stack))) {
            ok = false;
            break;
        }
        if (b.nodes[node].next != YX_SC_AST_NONE) {
            stack[stack_count++] = b.nodes[node].next;
            stack[stack_count++] = level;
        }
        if (b.nodes[node].first != YX_SC_AST_NONE) {
            stack[stack_count++] = b.nodes[node].first;
            stack[stack_count++] = level + 1;
        }
    }
    if (ok && found != YX_SC_AST_NONE) {
        /* Before the errors of tokens recovery discarded after the rule. */
        ok = yx_sc_add_pending(p, b.nodes[found].start, b.nodes[found].end,
                               "nesting limit reached");
        if (ok && p->pending_count > 1) {
            yx_sc_pending error = p->pending[p->pending_count - 1];
            memmove(p->pending + 1, p->pending,
                    (p->pending_count - 1) * sizeof(*p->pending));
            p->pending[0] = error;
        }
    }
    free(stack);
    free(b.nodes);
    return ok;
}

/* ------------------------------------------------------------------------
 * Top level
 * --------------------------------------------------------------------- */

static bool yx_sc_add_error_code(yx_sc *p, size_t start, size_t end,
                                 char *message, int code);

static bool yx_sc_add_error(yx_sc *p, size_t start, size_t end,
                            char *message)
{
    return yx_sc_add_error_code(p, start, end, message, 0);
}

static bool yx_sc_add_error_code(yx_sc *p, size_t start, size_t end,
                                 char *message, int code)
{
    yx_sc_result *result = p->result;
    yx_sc_error *grown;
    if (!message) return false;
    grown = realloc(result->errors, (result->error_count + 1) * sizeof(*grown));
    if (!grown) { free(message); return false; }
    result->errors = grown;
    grown[result->error_count].start = start;
    grown[result->error_count].end = end;
    grown[result->error_count].message = message;
    grown[result->error_count].item = result->item_count;
    grown[result->error_count].code = code;
    ++result->error_count;
    return true;
}

/* The integer literal's value fits [0, maximum] (negative values do not
 * occur: a minus sign is a separate token). */
static bool yx_sc_integer_fits(const uint8_t *s, size_t start, size_t end,
                               uint64_t maximum)
{
    uint64_t value = 0, multiplier = 1, base = 10;
    size_t at = start;
    if (end - start >= 2 && (s[end - 2] == 'K' || s[end - 2] == 'M') &&
        s[end - 1] == 'B') {
        multiplier = s[end - 2] == 'K' ? 1024 : 1024 * 1024;
        end -= 2;
    }
    if (end - at > 2 && s[at] == '0' && (s[at + 1] == 'x' || s[at + 1] == 'o')) {
        base = s[at + 1] == 'x' ? 16 : 8;
        at += 2;
    }
    for (; at < end; ++at) {
        unsigned digit;
        if (s[at] == '_') continue;
        digit = yx_sc_digit(s[at]) ? (unsigned)(s[at] - '0') :
                (unsigned)((s[at] | 0x20) - 'a' + 10);
        if (value > (maximum - digit) / base) return false;
        value = value * base + digit;
    }
    return value <= maximum / multiplier;
}

/* Records a literal error, or only reports that there is one. Returns 1
 * when recorded (or found), -1 on allocation failure. */
static int yx_sc_literal_found(yx_sc *p, bool record, size_t start,
                               size_t end, char *message, int code)
{
    if (!record) { free(message); return 1; }
    return yx_sc_add_error_code(p, start, end, message, code) ? 1 : -1;
}

/* The first literal error before `stop`, in the order the AST builder
 * converts literals: it aborts the rule at the first one. Returns 0 when
 * there is none, 1 when there is one (recorded when `record` is set) and
 * -1 on allocation failure. */
static int yx_sc_literal_error_at(yx_sc *p, size_t stop, bool record)
{
    const uint8_t *s = p->lexer.s;
    for (size_t i = 0; i < p->event_count; ++i) {
        const yx_sc_event *event = &p->events[i];
        if (event->type != EV_TOKEN) continue;
        if (event->start >= stop) break;
        if (event->id == T_INTEGER_LIT && event->context != CTX_NONE) {
            const char *range = "[-9223372036854775808, 9223372036854775807]";
            uint64_t maximum = INT64_MAX;
            /* signed_or_unsigned_integer_lit: an expression's literal may
             * be any i64 or u64. */
            if (event->context == CTX_EXPR) {
                maximum = UINT64_MAX;
                range = "[-9223372036854775808, 18446744073709551615]";
            }
            if (event->context == CTX_U8) { maximum = 255; range = "[0, 255]"; }
            if (event->context == CTX_U32) {
                maximum = UINT32_MAX;
                range = "[0, 4294967295]";
            }
            if (!yx_sc_integer_fits(s, event->start, event->end, maximum))
                return yx_sc_literal_found(p, record, event->start, event->end,
                                           yx_sc_format("%s", range), 27);
        } else if (event->id == T_STRING_LIT && event->context != CTX_NONE) {
            size_t quotes = event->end - event->start >= 6 &&
                            s[event->start + 1] == '"' &&
                            s[event->start + 2] == '"' ? 3 : 1;
            size_t at = event->start + quotes, end = event->end - quotes;
            for (; at < end; ++at) {
                size_t width;
                if (s[at] != '\\') continue;
                if (event->context == CTX_UTF8)
                    return yx_sc_literal_found(p, record, event->start, event->end,
                                               yx_sc_format("%s", ""), 31);
                if (strchr("\\nrt0\"", s[at + 1])) { ++at; continue; }
                if (s[at + 1] == 'x') {
                    if (at + 3 < end && yx_sc_hex(s[at + 2]) &&
                        yx_sc_hex(s[at + 3])) { at += 3; continue; }
                    return yx_sc_literal_found(p, record, at, at + 2,
                                               yx_sc_format("x"), 29);
                }
                width = yx_sc_utf8(s + at + 1, end - at - 1);
                if (!width) width = 1;
                return yx_sc_literal_found(p, record, at, at + 1 + width,
                                           yx_sc_format("%s", ""), 29);
            }
        } else if (event->id == T_REGEXP && event->context != CTX_NONE) {
            size_t close = event->end;
            while (close > event->start && s[close - 1] != '/') --close;
            for (size_t at = close; at < event->end; ++at)
                if (s[at] != 'i' && s[at] != 's')
                    return yx_sc_literal_found(p, record, at, at + 1,
                                               yx_sc_format("%c", s[at]), 30);
        }
    }
    return 0;
}

static bool yx_sc_literal_error(yx_sc *p, size_t stop)
{
    return yx_sc_literal_error_at(p, stop, true) >= 0;
}

static void yx_sc_top_level_item(yx_sc *p)
{
    const yx_sc_token *token = yx_sc_peek_token(p, 0);
    if (!token) { yx_sc_set_state(p, ST_FAILURE); return; }
    switch (token->id) {
    case T_IMPORT_KW: yx_sc_import_stmt(p); return;
    case T_INCLUDE_KW: yx_sc_include_stmt(p); return;
    case T_GLOBAL_KW: case T_PRIVATE_KW: case T_RULE_KW:
        yx_sc_rule_decl(p);
        yx_sc_recover(p, RECOVERY_TOP);
        return;
    default:
        if (!yx_sc_add_error(p, token->start, token->end,
                             yx_sc_format("expecting import statement or rule definition"))) {
            p->broken = true;
            return;
        }
        if (!yx_sc_grow((void **)&p->open_begins, &p->open_capacity,
                        p->open_count + 1, sizeof(*p->open_begins))) {
            p->broken = true;
            return;
        }
        p->open_begins[p->open_count++] = p->event_count;
        yx_sc_push_event(p, EV_BEGIN, K_ERROR, 0);
        while ((token = yx_sc_peek_non_trivia(p)) != NULL &&
               token->id != T_GLOBAL_KW && token->id != T_PRIVATE_KW &&
               token->id != T_RULE_KW) {
            yx_sc_trivia(p);
            yx_sc_bump(p);
        }
        yx_sc_output_end(p, false);
        yx_sc_set_state(p, ST_FAILURE);
        return;
    }
}

void yx_sc_result_free(yx_sc_result *result)
{
    if (!result) return;
    for (size_t i = 0; i < result->error_count; ++i)
        free(result->errors[i].message);
    free(result->errors);
    free(result->items);
    memset(result, 0, sizeof(*result));
}

bool yx_syntax_check(const uint8_t *source, size_t length,
                     yx_sc_result *result)
{
    yx_sc p;
    bool ok = true;
    memset(&p, 0, sizeof(p));
    memset(result, 0, sizeof(*result));
    p.lexer.s = source;
    p.lexer.n = length;
    p.lexer.mode = MODE_NORMAL;
    p.fuel = 100000000;
    p.cache_generation = 1;
    p.expected_generation = 1;
    p.result = result;
    while (!p.broken && p.state != ST_OUT_OF_FUEL &&
           yx_sc_peek_token(&p, 0) != NULL) {
        const yx_sc_token *first;
        size_t start, main_end = 0, errors_before = result->error_count;
        bool dropped = false;
        /* No bookmark is open between items: drop consumed tokens. */
        if (p.current > p.token_base) {
            size_t consumed = p.current - p.token_base;
            memmove(p.tokens, p.tokens + consumed,
                    (p.token_count - consumed) * sizeof(*p.tokens));
            p.token_count -= consumed;
            p.token_base = p.current;
        }
        p.event_count = 0;
        p.open_count = 0;
        p.depth = 0;
        yx_sc_trivia(&p);
        first = yx_sc_peek_token(&p, 0);
        if (!first) break;
        start = first->start;
        p.event_count = 0;
        yx_sc_top_level_item(&p);
        /* The AST builder bounds the depth of a well-formed condition. */
        if (!p.broken && p.state != ST_OUT_OF_FUEL && !yx_sc_check_ast_depth(&p))
            p.broken = true;
        /* A rule YARA-X drops still reports the first literal error before
         * its first syntax error or error node. */
        if (!p.broken && p.event_count && p.events[0].type == EV_BEGIN &&
            p.events[0].kind != K_ERROR) {
            size_t stop = SIZE_MAX, depth = 0, node_end = SIZE_MAX;
            for (size_t i = errors_before; i < result->error_count; ++i)
                if (result->errors[i].start < stop) stop = result->errors[i].start;
            for (size_t i = 0; i < p.pending_count; ++i)
                if (p.pending[i].start < stop) stop = p.pending[i].start;
            /* The first token inside an ERROR node within the item's node,
             * and where that node ends. */
            for (size_t i = 0, error_depth = 0; i < p.event_count; ++i) {
                if (p.events[i].type == EV_BEGIN) {
                    ++depth;
                    if (p.events[i].kind == K_ERROR && !error_depth)
                        error_depth = depth;
                } else if (p.events[i].type == EV_END) {
                    if (depth && --depth == 0) { node_end = p.events[i].end; break; }
                } else if (error_depth) {
                    if (p.events[i].start < stop) stop = p.events[i].start;
                    error_depth = 0;
                }
            }
            if (stop < node_end) ok = yx_sc_literal_error(&p, stop);
        }
        /* flush_errors */
        yx_sc_clear_expected(&p);
        for (size_t i = 0; i < p.pending_count; ++i) {
            if (!ok || !yx_sc_add_error(&p, p.pending[i].start, p.pending[i].end,
                                        p.pending[i].message)) {
                if (ok) p.pending[i].message = NULL;
                free(p.pending[i].message);
                ok = false;
            }
        }
        p.pending_count = 0;
        yx_sc_cache_clear(&p);
        /* The next item starts afresh, even after the nesting limit; once
         * out of fuel the parser stops. */
        if (p.state != ST_OUT_OF_FUEL) p.state = ST_OK;
        if (!ok) break;
        /* The item's node is the first one; a nested ERROR node or the
         * node itself being an error drops it. Recovery after the node
         * only adds discarded tokens. */
        if (p.event_count && p.events[0].type == EV_BEGIN) {
            size_t depth = 0, i;
            for (i = 0; i < p.event_count; ++i) {
                if (p.events[i].type == EV_BEGIN) {
                    ++depth;
                    if (p.events[i].kind == K_ERROR) dropped = true;
                } else if (p.events[i].type == EV_END && --depth == 0) {
                    main_end = p.events[i].end;
                    break;
                }
            }
            if (i == p.event_count) main_end = yx_sc_last_token_end(&p);
        } else {
            dropped = true;
            main_end = yx_sc_last_token_end(&p);
        }
        if (result->error_count > errors_before &&
            result->errors[errors_before].start < main_end)
            dropped = true;
        {
            yx_sc_item *item = yx_sc_item_slot(result);
            if (!item) { ok = false; break; }
            item->start = start;
            item->end = main_end > start ? main_end : start;
            item->full_end = yx_sc_last_token_end(&p);
            if (item->full_end < item->end)
                item->full_end = item->end;
            item->dropped = dropped;
            ++result->item_count;
        }
    }
    if (ok && !p.broken && p.state == ST_OUT_OF_FUEL) {
        /* Out of fuel, the parser ignores the rest of the source: one
         * dropped item without errors covers it. */
        const yx_sc_token *rest = yx_sc_peek_non_trivia(&p);
        if (rest) {
            yx_sc_item *item = yx_sc_item_slot(result);
            if (!item) {
                ok = false;
            } else {
                item->start = rest->start;
                item->end = p.lexer.n;
                item->full_end = p.lexer.n;
                item->dropped = true;
                ++result->item_count;
            }
        }
    }
    if (p.broken) ok = false;
    for (size_t i = 0; i < p.pending_count; ++i) free(p.pending[i].message);
    free(p.pending);
    free(p.tokens);
    free(p.events);
    free(p.open_begins);
    free(p.expected);
    free(p.expected_index);
    free(p.unexpected);
    free(p.cache);
    if (!ok) yx_sc_result_free(result);
    return ok;
}
