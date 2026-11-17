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

#include <ctype.h>
#include <string.h>

static bool yx_suppress_word(uint8_t ch)
{
    return isalnum(ch) || ch == '_';
}

static size_t yx_suppress_quoted(const uint8_t *source, size_t length,
                                 size_t at)
{
    uint8_t quote = source[at++];
    while (at < length) {
        if (source[at] == '\\' && at + 1 < length) { at += 2; continue; }
        if (source[at++] == quote) break;
    }
    return at;
}

static size_t yx_suppress_line_end(const uint8_t *source, size_t length,
                                    size_t at)
{
    while (at < length && source[at] != '\n' && source[at] != '\r') ++at;
    return at;
}

static size_t yx_suppress_comment_end(const uint8_t *source, size_t length,
                                       size_t at)
{
    if (at + 1 >= length || source[at] != '/') return at;
    if (source[at + 1] == '/')
        return yx_suppress_line_end(source, length, at + 2);
    if (source[at + 1] == '*') {
        at += 2;
        while (at + 1 < length &&
               !(source[at] == '*' && source[at + 1] == '/')) ++at;
        return at + 1 < length ? at + 2 : length;
    }
    return at;
}

static bool yx_suppress_regex_follows(const uint8_t *source, size_t at)
{
    size_t before = at;
    while (before && isspace(source[before - 1])) --before;
    if (before && source[before - 1] == '=') return true;
    return before >= 7 &&
           memcmp(source + before - 7, "matches", 7) == 0 &&
           (before == 7 || !yx_suppress_word(source[before - 8]));
}

static size_t yx_suppress_regex_end(const uint8_t *source, size_t length,
                                    size_t at)
{
    bool character_class = false;
    ++at;
    while (at < length) {
        if (source[at] == '\\' && at + 1 < length) { at += 2; continue; }
        if (source[at] == '[') character_class = true;
        else if (source[at] == ']') character_class = false;
        else if (source[at] == '/' && !character_class) return at + 1;
        ++at;
    }
    return length;
}

static size_t yx_suppress_next_code(const uint8_t *source, size_t length,
                                     size_t at)
{
    while (at < length) {
        size_t next;
        if (isspace(source[at])) { ++at; continue; }
        next = yx_suppress_comment_end(source, length, at);
        if (next != at) { at = next; continue; }
        break;
    }
    return at;
}

static bool yx_suppress_is_word(const uint8_t *source, size_t length,
                                size_t at, const char *word)
{
    size_t n = strlen(word);
    return at + n <= length && memcmp(source + at, word, n) == 0 &&
           (at == 0 || !yx_suppress_word(source[at - 1])) &&
           (at + n == length || !yx_suppress_word(source[at + n]));
}

static bool yx_suppress_is_rule(const uint8_t *source, size_t length,
                                size_t at)
{
    while (yx_suppress_is_word(source, length, at, "private") ||
           yx_suppress_is_word(source, length, at, "global")) {
        while (at < length && yx_suppress_word(source[at])) ++at;
        at = yx_suppress_next_code(source, length, at);
    }
    return yx_suppress_is_word(source, length, at, "rule");
}

static size_t yx_suppress_rule_end(const uint8_t *source, size_t length,
                                   size_t at)
{
    size_t depth = 0;
    bool opened = false;
    while (at < length) {
        size_t next;
        if (source[at] == '"' || source[at] == '\'') {
            at = yx_suppress_quoted(source, length, at);
            continue;
        }
        next = yx_suppress_comment_end(source, length, at);
        if (next != at) { at = next; continue; }
        if (source[at] == '/' && yx_suppress_regex_follows(source, at)) {
            at = yx_suppress_regex_end(source, length, at);
            continue;
        }
        if (source[at] == '{') { ++depth; opened = true; }
        else if (source[at] == '}' && depth && --depth == 0)
            return at + 1;
        ++at;
    }
    return opened ? length : at;
}

static size_t yx_suppress_pattern_end(const uint8_t *source, size_t length,
                                      size_t at)
{
    size_t line_end = yx_suppress_line_end(source, length, at);
    size_t equals = at;
    while (equals < line_end && source[equals] != '=') ++equals;
    if (equals == line_end) return line_end;
    ++equals;
    while (equals < length && (source[equals] == ' ' ||
           source[equals] == '\t')) ++equals;
    if (equals >= length || source[equals] != '{') return line_end;
    return yx_suppress_rule_end(source, length, equals);
}

static bool yx_suppress_names_code(const uint8_t *source, size_t begin,
                                   size_t end, const char *code)
{
    const size_t code_length = strlen(code);
    for (size_t at = begin; at + 9 <= end; ++at) {
        size_t item;
        if (memcmp(source + at, "suppress:", 9) != 0) continue;
        item = at + 9;
        while (item < end) {
            size_t first, last;
            while (item < end && isspace(source[item])) ++item;
            first = item;
            while (item < end && yx_suppress_word(source[item])) ++item;
            last = item;
            if (last == first) break;
            if (last - first == code_length &&
                memcmp(source + first, code, code_length) == 0) return true;
            while (item < end && isspace(source[item])) ++item;
            if (item >= end || source[item] != ',') break;
            ++item;
        }
    }
    return false;
}

bool yx_warning_suppressed(const uint8_t *source, size_t length,
                           const char *code, size_t warning_start)
{
    size_t at = 0, line_begin = 0;
    if (!source || !code || warning_start >= length) return false;
    {
        /* Only a comment naming the code after `suppress:` suppresses it;
         * a source without that marker suppresses nothing. */
        const uint8_t *scan = source, *stop = source + length;
        bool marker = false;
        while (!marker && stop - scan >= 9 &&
               (scan = memchr(scan, 's', (size_t)(stop - scan - 8))) != NULL) {
            if (memcmp(scan, "suppress:", 9) == 0) marker = true;
            else ++scan;
        }
        if (!marker) return false;
    }
    while (at < length) {
        size_t end, content_begin, content_end;
        bool has_code = false;
        if (source[at] == '\n' || source[at] == '\r') {
            line_begin = at + 1;
            ++at;
            continue;
        }
        if (source[at] == '"' || source[at] == '\'') {
            at = yx_suppress_quoted(source, length, at);
            continue;
        }
        if (source[at] == '/' && at + 1 < length &&
            source[at + 1] != '/' && source[at + 1] != '*' &&
            yx_suppress_regex_follows(source, at)) {
            end = yx_suppress_regex_end(source, length, at);
            for (size_t i = at; i < end; ++i)
                if (source[i] == '\n' || source[i] == '\r') line_begin = i + 1;
            at = end;
            continue;
        }
        end = yx_suppress_comment_end(source, length, at);
        if (end == at) { ++at; continue; }
        content_begin = at + 2;
        content_end = end;
        if (source[at + 1] == '*' && content_end >= 2)
            content_end -= 2;
        if (yx_suppress_names_code(source, content_begin,
                                   content_end, code)) {
            size_t start, stop;
            for (size_t i = line_begin; i < at; ++i)
                if (!isspace(source[i])) { has_code = true; break; }
            if (has_code) {
                start = line_begin;
                while (start < at && isspace(source[start])) ++start;
                stop = at;
            } else {
                start = yx_suppress_next_code(source, length, end);
                if (start >= length) return false;
                if (yx_suppress_is_rule(source, length, start))
                    stop = yx_suppress_rule_end(source, length, start);
                else if (source[start] == '$')
                    stop = yx_suppress_pattern_end(source, length, start);
                else stop = yx_suppress_line_end(source, length, start);
            }
            if (warning_start >= start && warning_start < stop) return true;
        }
        for (size_t i = at; i < end; ++i)
            if (source[i] == '\n' || source[i] == '\r') line_begin = i + 1;
        at = end;
    }
    return false;
}
