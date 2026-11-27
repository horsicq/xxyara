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

#include "warning_suppression.h"

#include "xxfclib/regex/xx_regex_unicode16.h"

#include <stdlib.h>
#include <string.h>

/* The model is YARA-X's WarningSuppressionHook (lib/src/compiler/wsh.rs)
 * over the token stream of parser/src/tokenizer/mod.rs: a comment covers
 * the tokens before it on its line; a comment with no code before it
 * covers the rule or pattern definition that starts next, or else the
 * tokens of the next line that has any. Warnings::add then drops a warning
 * when one covered span contains one whole label. The spans of a source
 * are collected once while a scope is open for it (a compile of that
 * source, one pass of the CLI over a file). */

typedef enum yx_suppress_kind {
    YX_SUPPRESS_END,
    YX_SUPPRESS_SPACE,
    YX_SUPPRESS_NEWLINE,
    YX_SUPPRESS_COMMENT,
    YX_SUPPRESS_PATTERN_IDENT,
    YX_SUPPRESS_EQUAL,
    YX_SUPPRESS_LBRACE,
    YX_SUPPRESS_RBRACE,
    YX_SUPPRESS_RULE_WORD, /* global, private or rule */
    YX_SUPPRESS_CONDITION,
    YX_SUPPRESS_OTHER
} yx_suppress_kind;

typedef struct yx_suppress_lexer {
    const uint8_t *source;
    size_t length, at;
    bool hex;            /* hex pattern or hex jump mode */
    unsigned definition; /* 1 after `$x`, 2 after `$x =` */
} yx_suppress_lexer;

typedef struct yx_suppress_token {
    yx_suppress_kind kind;
    size_t start, end;
} yx_suppress_token;

static size_t yx_suppress_decode(const uint8_t *at, size_t left, uint32_t *scalar)
{
    uint8_t lead;
    size_t width;
    uint32_t value, least;
    if (!left) return 0;
    lead = at[0];
    if (lead < 0x80) {
        *scalar = lead;
        return 1;
    }
    if (lead >= 0xc2 && lead <= 0xdf) {
        width = 2;
        value = lead & 0x1f;
        least = 0x80;
    } else if (lead >= 0xe0 && lead <= 0xef) {
        width = 3;
        value = lead & 0x0f;
        least = 0x800;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
        width = 4;
        value = lead & 0x07;
        least = 0x10000;
    } else return 0;
    if (left < width) return 0;
    for (size_t i = 1; i < width; ++i) {
        if ((at[i] & 0xc0) != 0x80) return 0;
        value = (value << 6) | (at[i] & 0x3f);
    }
    if (value < least || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return 0;
    *scalar = value;
    return width;
}

static bool yx_suppress_in_class(uint32_t scalar, xx_regex_unicode16_class cls)
{
    const xx_regex_unicode16_table *table = xx_regex_unicode16_table_at(xx_regex_unicode16_class_table(cls));
    size_t low = 0, high;
    if (!table) return false;
    high = table->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (scalar < table->ranges[middle].first) high = middle;
        else if (scalar > table->ranges[middle].last) low = middle + 1;
        else return true;
    }
    return false;
}

static bool yx_suppress_alpha(uint8_t ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

static bool yx_suppress_ident_char(uint8_t ch)
{
    return yx_suppress_alpha(ch) || (ch >= '0' && ch <= '9') || ch == '_';
}

/* Width of one identifier-continuation character, or 0: the tokenizer's
 * identifier regexes take `\d` Unicode-aware (any Nd digit). */
static size_t yx_suppress_ident_width(const uint8_t *at, size_t left)
{
    uint32_t scalar;
    size_t width;
    if (!left) return 0;
    if (at[0] < 0x80) return yx_suppress_ident_char(at[0]) ? 1 : 0;
    width = yx_suppress_decode(at, left, &scalar);
    return width && yx_suppress_in_class(scalar, XX_REGEX_UNICODE16_DECIMAL) ? width : 0;
}

/* Width of one character of the tokenizer's Whitespace token, or 0. */
static size_t yx_suppress_blank(const uint8_t *at, size_t left)
{
    uint32_t scalar;
    size_t width;
    if (!left) return 0;
    if (at[0] == ' ' || at[0] == '\t') return 1;
    if (at[0] < 0x80) return 0;
    width = yx_suppress_decode(at, left, &scalar);
    if (!width) return 0;
    if (scalar == 0xa0 || scalar == 0x1680 || (scalar >= 0x2000 && scalar <= 0x200a) || scalar == 0x202f || scalar == 0x205f || scalar == 0x3000) return width;
    return 0;
}

/* End of the token Tokenizer::unexpected_token builds: the text up to the
 * next white space, and at least one character. */
static size_t yx_suppress_unknown_end(const uint8_t *source, size_t length, size_t at)
{
    size_t end = at;
    while (end < length) {
        uint32_t scalar;
        size_t width = yx_suppress_decode(source + end, length - end, &scalar);
        if (!width) {
            if (end == at) ++end;
            break;
        }
        if (yx_suppress_in_class(scalar, XX_REGEX_UNICODE16_SPACE)) {
            if (end == at) end += width;
            break;
        }
        end += width;
    }
    return end;
}

/* End of a block comment that starts at `at`, or 0 when it is not closed. */
static size_t yx_suppress_block_end(const uint8_t *source, size_t length, size_t at)
{
    for (size_t i = at + 2; i + 1 < length; ++i)
        if (source[i] == '*' && source[i + 1] == '/') return i + 2;
    return 0;
}

/* End of the string literal that starts at `at`, or 0. */
static size_t yx_suppress_string_end(const uint8_t *source, size_t length, size_t at)
{
    size_t i;
    if (at + 2 < length && source[at + 1] == '"' && source[at + 2] == '"') {
        for (i = at + 3; i < length;) {
            if (source[i] == '\\') {
                if (i + 1 >= length || source[i + 1] == '\n') break;
                i += 2;
            } else if (source[i] == '"') {
                if (i + 2 < length && source[i + 1] == '"' && source[i + 2] == '"') return i + 3;
                break;
            } else ++i;
        }
        return at + 2; /* the empty literal "" */
    }
    for (i = at + 1; i < length;) {
        if (source[i] == '\\') {
            if (i + 1 >= length || source[i + 1] == '\n') return 0;
            i += 2;
        } else if (source[i] == '"') return i + 1;
        else if (source[i] == '\n') return 0;
        else ++i;
    }
    return 0;
}

/* End of the regular expression that starts at `at`, or 0. */
static size_t yx_suppress_regexp_end(const uint8_t *source, size_t length, size_t at)
{
    size_t i = at + 1, modifiers = 0;
    if (i >= length || source[i] == '*' || source[i] == '/' || source[i] == '\n') return 0;
    while (i < length) {
        if (source[i] == '\\') {
            if (i + 1 >= length || source[i + 1] == '\n') return 0;
            i += 2;
        } else if (source[i] == '\n') return 0;
        else if (source[i] == '/') {
            ++i;
            while (modifiers < 2 && i < length && yx_suppress_alpha(source[i])) {
                ++i;
                ++modifiers;
            }
            return i;
        } else ++i;
    }
    return 0;
}

static bool yx_suppress_word_is(const uint8_t *source, size_t start, size_t end, const char *word)
{
    size_t n = strlen(word);
    return end - start == n && memcmp(source + start, word, n) == 0;
}

static yx_suppress_token yx_suppress_next(yx_suppress_lexer *lexer)
{
    const uint8_t *source = lexer->source;
    size_t length = lexer->length, at = lexer->at, end, width;
    yx_suppress_token token;
    uint8_t ch;
    token.start = at;
    token.kind = YX_SUPPRESS_OTHER;
    if (at >= length) {
        token.kind = YX_SUPPRESS_END;
        token.end = at;
        return token;
    }
    ch = source[at];
    end = at + 1;
    if (ch == '\n' || ch == '\r') {
        if (ch == '\r' && end < length && source[end] == '\n') ++end;
        token.kind = YX_SUPPRESS_NEWLINE;
    } else if ((width = yx_suppress_blank(source + at, length - at)) != 0) {
        end = at + width;
        while ((width = yx_suppress_blank(source + end, length - end)) != 0) end += width;
        token.kind = YX_SUPPRESS_SPACE;
    } else if (ch == '/' && end < length && source[end] == '/') {
        while (end < length && source[end] != '\n') ++end;
        token.kind = YX_SUPPRESS_COMMENT;
    } else if (ch == '/' && end < length && source[end] == '*' && (width = yx_suppress_block_end(source, length, at)) != 0) {
        end = width;
        token.kind = YX_SUPPRESS_COMMENT;
    } else if (lexer->hex) {
        /* Anything a hex pattern or a jump cannot hold sends the tokenizer
         * back to normal mode, where the same text is read again. */
        if (!(yx_suppress_ident_char(ch) || ch == '?' || ch == '~' || ch == '|' || ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == '-')) {
            lexer->hex = false;
            return yx_suppress_next(lexer);
        }
    } else if (ch == '/') {
        end = yx_suppress_regexp_end(source, length, at);
        if (!end) end = yx_suppress_unknown_end(source, length, at);
    } else if (ch == '"') {
        end = yx_suppress_string_end(source, length, at);
        if (!end) end = yx_suppress_unknown_end(source, length, at);
    } else if (ch == '$' || ch == '#' || ch == '@' || ch == '!') {
        if (ch == '!' && end < length && source[end] == '=') ++end;
        else {
            while (end < length && (width = yx_suppress_ident_width(source + end, length - end)) != 0) end += width;
            if (ch == '$') token.kind = YX_SUPPRESS_PATTERN_IDENT;
        }
    } else if (yx_suppress_alpha(ch) || ch == '_') {
        while (end < length && (width = yx_suppress_ident_width(source + end, length - end)) != 0) end += width;
        if (yx_suppress_word_is(source, at, end, "rule") || yx_suppress_word_is(source, at, end, "global") || yx_suppress_word_is(source, at, end, "private"))
            token.kind = YX_SUPPRESS_RULE_WORD;
        else if (yx_suppress_word_is(source, at, end, "condition")) token.kind = YX_SUPPRESS_CONDITION;
    } else if (ch == '=') {
        if (end < length && source[end] == '=') ++end;
        else token.kind = YX_SUPPRESS_EQUAL;
    } else if (ch == '{') {
        token.kind = YX_SUPPRESS_LBRACE;
    } else if (ch == '}') {
        token.kind = YX_SUPPRESS_RBRACE;
    } else if (ch >= 0x80 || ch < 0x20 || ch == 0x7f || ch == '\'' || ch == '`' || ch == ';' || ch == '?') {
        end = yx_suppress_unknown_end(source, length, at);
    }
    /* The parser switches to hex pattern mode after the `{` that follows
     * `$identifier =`. */
    if (token.kind != YX_SUPPRESS_SPACE && token.kind != YX_SUPPRESS_NEWLINE && token.kind != YX_SUPPRESS_COMMENT) {
        if (token.kind == YX_SUPPRESS_PATTERN_IDENT) lexer->definition = 1;
        else if (token.kind == YX_SUPPRESS_EQUAL && lexer->definition == 1) lexer->definition = 2;
        else {
            if (token.kind == YX_SUPPRESS_LBRACE && lexer->definition == 2) lexer->hex = true;
            lexer->definition = 0;
        }
    }
    token.end = end;
    lexer->at = end;
    return token;
}

static yx_suppress_token yx_suppress_next_code(yx_suppress_lexer *lexer)
{
    yx_suppress_token token;
    do token = yx_suppress_next(lexer);
    while (token.kind == YX_SUPPRESS_SPACE || token.kind == YX_SUPPRESS_NEWLINE || token.kind == YX_SUPPRESS_COMMENT);
    return token;
}

/* End of the rule declaration whose first token was just read. */
static size_t yx_suppress_rule_end(yx_suppress_lexer lexer, size_t fallback)
{
    for (;;) {
        bool hex = lexer.hex;
        yx_suppress_token token = yx_suppress_next_code(&lexer);
        if (token.kind == YX_SUPPRESS_END) return fallback;
        fallback = token.end;
        /* The `}` of a hex pattern is read in normal mode, right after the
         * tokenizer left hex mode for it. */
        if (token.kind == YX_SUPPRESS_RBRACE && !hex && !lexer.hex) return token.end;
    }
}

/* End of the pattern definition whose identifier was just read: its last
 * token before the next definition, the condition or the rule's end. */
static size_t yx_suppress_definition_end(yx_suppress_lexer lexer, size_t fallback)
{
    size_t end = fallback;
    for (;;) {
        bool hex = lexer.hex;
        yx_suppress_token token = yx_suppress_next_code(&lexer);
        if (token.kind == YX_SUPPRESS_END || token.kind == YX_SUPPRESS_CONDITION || (token.kind == YX_SUPPRESS_RBRACE && !hex)) return end;
        if (token.kind == YX_SUPPRESS_PATTERN_IDENT) {
            yx_suppress_lexer ahead = lexer;
            if (yx_suppress_next_code(&ahead).kind == YX_SUPPRESS_EQUAL) return end;
        }
        end = token.end;
    }
}

static bool yx_suppress_table_add(yx_suppression_table *table, size_t id_start, size_t id_end, size_t start, size_t end)
{
    yx_suppression *item;
    if (table->count == table->capacity) {
        size_t next = table->capacity ? table->capacity * 2 : 16;
        yx_suppression *grown;
        if (next <= table->capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = (yx_suppression *)realloc(table->items, next * sizeof(*grown));
        if (!grown) return false;
        table->items = grown;
        table->capacity = next;
    }
    item = &table->items[table->count++];
    item->id_start = id_start;
    item->id_end = id_end;
    item->start = start;
    item->end = end;
    return true;
}

/* The bounds of the capture of the first match of `suppress: ([\w\s,]+)`
 * in the comment source[begin..end); false when the regexp finds none. */
static bool yx_suppress_capture(const uint8_t *source, size_t begin, size_t end, size_t *first, size_t *last)
{
    static const char marker[] = "suppress: ";
    const size_t marker_length = sizeof(marker) - 1;
    for (size_t at = begin; at + marker_length < end; ++at) {
        size_t stop;
        if (memcmp(source + at, marker, marker_length) != 0) continue;
        stop = at + marker_length;
        while (stop < end) {
            uint32_t scalar;
            size_t width = yx_suppress_decode(source + stop, end - stop, &scalar);
            if (!width || !(scalar == ',' || yx_suppress_in_class(scalar, XX_REGEX_UNICODE16_WORD) || yx_suppress_in_class(scalar, XX_REGEX_UNICODE16_SPACE))) break;
            stop += width;
        }
        if (stop == at + marker_length) continue;
        *first = at + marker_length;
        *last = stop;
        return true;
    }
    return false;
}

/* Records that the comment source[begin..end) covers [start, stop): one
 * entry for each id, the comma separated, trimmed items of the capture. */
static bool yx_suppress_record(yx_suppression_table *table, const uint8_t *source, size_t begin, size_t end, size_t start, size_t stop)
{
    size_t capture, capture_end;
    if (!yx_suppress_capture(source, begin, end, &capture, &capture_end)) return true;
    for (size_t item = capture; item <= capture_end;) {
        size_t first = item, last, comma = item;
        while (comma < capture_end && source[comma] != ',') ++comma;
        last = comma;
        while (first < last) {
            uint32_t scalar;
            size_t width = yx_suppress_decode(source + first, last - first, &scalar);
            if (!width || !yx_suppress_in_class(scalar, XX_REGEX_UNICODE16_SPACE)) break;
            first += width;
        }
        while (last > first) {
            uint32_t scalar;
            size_t back = last - 1, width;
            while (back > first && (source[back] & 0xc0) == 0x80) --back;
            width = yx_suppress_decode(source + back, last - back, &scalar);
            if (width != last - back || !yx_suppress_in_class(scalar, XX_REGEX_UNICODE16_SPACE)) break;
            last = back;
        }
        if (last > first && !yx_suppress_table_add(table, first, last, start, stop)) return false;
        item = comma + 1;
    }
    return true;
}

typedef struct yx_suppress_comment {
    size_t begin, end;
} yx_suppress_comment;

/* Every suppression of a source: what each `suppress:` comment names and
 * the code it covers. False when memory runs out. */
static bool yx_suppress_collect(const uint8_t *source, size_t length, yx_suppression_table *table)
{
    /* Comments with no code before them, waiting for the code they cover. */
    yx_suppress_comment *waiting = NULL;
    size_t waiting_count = 0, waiting_capacity = 0;
    bool line_has_span = false, in_rule = false, ok = false;
    size_t line_start = 0, line_end = 0, rule_end = 0;
    yx_suppress_lexer lexer;
    table->items = NULL;
    table->count = table->capacity = 0;
    if (!source) return true;
    {
        /* Only a comment with `suppress: ` suppresses anything. */
        const uint8_t *scan = source, *stop = source + length;
        bool marker = false;
        while (!marker && stop - scan >= 10 && (scan = memchr(scan, 's', (size_t)(stop - scan - 9))) != NULL) {
            if (memcmp(scan, "suppress: ", 10) == 0) marker = true;
            else ++scan;
        }
        if (!marker) return true;
    }
    lexer.source = source;
    lexer.length = length;
    lexer.at = 0;
    lexer.hex = false;
    lexer.definition = 0;
    for (;;) {
        yx_suppress_token token = yx_suppress_next(&lexer);
        size_t span_start = 0, span_end = 0;
        bool give = false;
        if (token.kind == YX_SUPPRESS_SPACE) continue;
        if (token.kind == YX_SUPPRESS_NEWLINE || token.kind == YX_SUPPRESS_END) {
            if (waiting_count && line_has_span) {
                for (size_t i = 0; i < waiting_count; ++i)
                    if (!yx_suppress_record(table, source, waiting[i].begin, waiting[i].end, line_start, line_end)) goto done;
                waiting_count = 0;
            }
            line_has_span = false;
            if (token.kind == YX_SUPPRESS_END) break;
            continue;
        }
        if (token.kind == YX_SUPPRESS_COMMENT) {
            size_t first, last;
            if (!yx_suppress_capture(source, token.start, token.end, &first, &last)) continue;
            if (line_has_span) {
                if (!yx_suppress_record(table, source, token.start, token.end, line_start, line_end)) goto done;
                continue;
            }
            if (waiting_count == waiting_capacity) {
                size_t next = waiting_capacity ? waiting_capacity * 2 : 8;
                yx_suppress_comment *grown;
                if (next <= waiting_capacity || next > SIZE_MAX / sizeof(*grown)) goto done;
                grown = (yx_suppress_comment *)realloc(waiting, next * sizeof(*grown));
                if (!grown) goto done;
                waiting = grown;
                waiting_capacity = next;
            }
            waiting[waiting_count].begin = token.start;
            waiting[waiting_count++].end = token.end;
            continue;
        }
        /* The first token of a rule declaration or of a pattern definition
         * gives the whole construct to the comments that wait. */
        if (!in_rule && token.kind == YX_SUPPRESS_RULE_WORD) {
            in_rule = true;
            rule_end = yx_suppress_rule_end(lexer, token.end);
            span_start = token.start;
            span_end = rule_end;
            give = waiting_count != 0;
        } else if (in_rule && token.kind == YX_SUPPRESS_PATTERN_IDENT && waiting_count) {
            yx_suppress_lexer ahead = lexer;
            if (yx_suppress_next_code(&ahead).kind == YX_SUPPRESS_EQUAL) {
                span_start = token.start;
                span_end = yx_suppress_definition_end(lexer, token.end);
                give = true;
            }
        }
        if (give) {
            for (size_t i = 0; i < waiting_count; ++i)
                if (!yx_suppress_record(table, source, waiting[i].begin, waiting[i].end, span_start, span_end)) goto done;
            waiting_count = 0;
        }
        if (in_rule && token.end >= rule_end) in_rule = false;
        if (!line_has_span) {
            line_has_span = true;
            line_start = token.start;
        }
        line_end = token.end;
    }
    ok = true;
done:
    free(waiting);
    if (!ok) {
        free(table->items);
        table->items = NULL;
        table->count = table->capacity = 0;
    }
    return ok;
}

/* Warnings::add: one span recorded for the code holds the whole label
 * (Span::contains: both of its ends lie inside). */
static bool yx_suppress_match(const yx_suppression_table *table, const uint8_t *source, const char *code, size_t label_start, size_t label_end)
{
    const size_t code_length = strlen(code);
    const size_t last = label_end ? label_end - 1 : 0;
    for (size_t i = 0; i < table->count; ++i) {
        const yx_suppression *item = &table->items[i];
        if (label_start >= item->start && label_start < item->end && last >= item->start && last < item->end && item->id_end - item->id_start == code_length &&
            memcmp(source + item->id_start, code, code_length) == 0)
            return true;
    }
    return false;
}

#ifdef _MSC_VER
#define YX_SUPPRESS_THREAD_LOCAL __declspec(thread)
#else
#define YX_SUPPRESS_THREAD_LOCAL _Thread_local
#endif

/* The sources whose warnings are being raised on this thread, innermost
 * first. */
static YX_SUPPRESS_THREAD_LOCAL yx_suppression_scope *yx_suppress_scopes;

void yx_suppression_scope_begin(yx_suppression_scope *scope, const uint8_t *source, size_t length)
{
    scope->source = source;
    scope->length = length;
    scope->table.items = NULL;
    scope->table.count = scope->table.capacity = 0;
    scope->state = 0;
    scope->parent = yx_suppress_scopes;
    scope->text = false;
    scope->lines = NULL;
    scope->line_count = 0;
    scope->line_state = 0;
    yx_suppress_scopes = scope;
}

void yx_suppression_scope_begin_text(yx_suppression_scope *scope, const char *source)
{
    yx_suppression_scope_begin(scope, (const uint8_t *)source, source ? strlen(source) : 0);
    scope->text = source != NULL;
}

void yx_suppression_scope_end(yx_suppression_scope *scope)
{
    /* Scopes nest: this one is the innermost. */
    if (yx_suppress_scopes == scope) yx_suppress_scopes = scope->parent;
    free(scope->table.items);
    scope->table.items = NULL;
    scope->table.count = scope->table.capacity = 0;
    free(scope->lines);
    scope->lines = NULL;
    scope->line_count = 0;
    scope->line_state = 0;
}

static yx_suppression_scope *yx_text_scope(const char *source)
{
    for (yx_suppression_scope *scope = yx_suppress_scopes; scope; scope = scope->parent)
        if (scope->text && scope->source == (const uint8_t *)source) return scope;
    return NULL;
}

void *yx_suppression_scopes_current(void)
{
    return yx_suppress_scopes;
}

void yx_suppression_scopes_adopt(void *scopes)
{
    yx_suppress_scopes = (yx_suppression_scope *)scopes;
}

size_t yx_source_text_length(const char *source)
{
    yx_suppression_scope *scope = yx_text_scope(source);
    return scope ? scope->length : strlen(source);
}

static bool yx_text_scope_lines(yx_suppression_scope *scope)
{
    const uint8_t *at, *end;
    size_t count = 1, used = 0;
    if (scope->line_state) return scope->line_state == 1;
    scope->line_state = 2;
    at = scope->source;
    end = scope->source + scope->length;
    while (at < end && (at = (const uint8_t *)memchr(at, '\n', (size_t)(end - at)))) {
        ++count;
        ++at;
    }
    if (count > SIZE_MAX / sizeof(*scope->lines)) return false;
    scope->lines = (size_t *)malloc(count * sizeof(*scope->lines));
    if (!scope->lines) return false;
    scope->lines[used++] = 0;
    at = scope->source;
    while (at < end && (at = (const uint8_t *)memchr(at, '\n', (size_t)(end - at)))) {
        ++at;
        scope->lines[used++] = (size_t)(at - scope->source);
    }
    scope->line_count = used;
    scope->line_state = 1;
    return true;
}

size_t yx_source_line_of(const char *source, size_t offset, const char **line_start)
{
    yx_suppression_scope *scope = yx_text_scope(source);
    size_t line = 1;
    if (scope && offset <= scope->length && yx_text_scope_lines(scope)) {
        /* The lines starting at or before `offset`: a newline before
         * `offset` starts a line at or before it. */
        size_t low = 0, high = scope->line_count;
        while (low < high) {
            size_t middle = low + (high - low) / 2;
            if (scope->lines[middle] <= offset) low = middle + 1;
            else high = middle;
        }
        *line_start = source + scope->lines[low - 1];
        return low;
    }
    *line_start = source;
    for (size_t i = 0; i < offset; ++i)
        if (source[i] == '\n') {
            ++line;
            *line_start = source + i + 1;
        }
    return line;
}

bool yx_warning_suppressed_span(const uint8_t *source, size_t length, const char *code, size_t label_start, size_t label_end)
{
    yx_suppression_table table;
    bool suppressed;
    if (!source || !code || label_start >= length) return false;
    for (yx_suppression_scope *scope = yx_suppress_scopes; scope; scope = scope->parent) {
        if (scope->source != source || scope->length != length) continue;
        /* Collected at the first question about this source. */
        if (scope->state == 0) scope->state = yx_suppress_collect(source, length, &scope->table) ? 1 : 2;
        if (scope->state != 1) break;
        return yx_suppress_match(&scope->table, source, code, label_start, label_end);
    }
    if (!yx_suppress_collect(source, length, &table)) return false;
    suppressed = yx_suppress_match(&table, source, code, label_start, label_end);
    free(table.items);
    return suppressed;
}

bool yx_warning_suppressed(const uint8_t *source, size_t length, const char *code, size_t warning_start)
{
    return yx_warning_suppressed_span(source, length, code, warning_start, warning_start + 1);
}
