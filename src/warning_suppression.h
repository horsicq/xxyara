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

#ifndef XXYARA_WARNING_SUPPRESSION_H
#define XXYARA_WARNING_SUPPRESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A suppression comment applies to the code before it on its line or, with
 * no code before it, to the pattern definition or rule declaration that
 * starts next, or else to the next line of code. A warning is suppressed
 * when one such span holds one whole label of it. */
bool yx_warning_suppressed_span(const uint8_t *source, size_t length, const char *code, size_t label_start, size_t label_end);

/* One id named by a `suppress:` comment (offsets of the id in the source)
 * and the code that comment covers. */
typedef struct yx_suppression {
    size_t id_start, id_end;
    size_t start, end;
} yx_suppression;

typedef struct yx_suppression_table {
    yx_suppression *items;
    size_t count, capacity;
} yx_suppression_table;

/* While a scope is open on this thread, the questions about its source
 * (the same pointer and length) share one scan of that source, made at
 * the first question. Scopes nest and end in reverse order; the source
 * must not change or move while its scope is open. */
typedef struct yx_suppression_scope {
    const uint8_t *source;
    size_t length;
    yx_suppression_table table;
    int state; /* 0 not collected, 1 collected, 2 failed */
    struct yx_suppression_scope *parent;
    bool text;     /* length == strlen(source) */
    size_t *lines; /* line start offsets, built on demand */
    size_t line_count;
    int line_state; /* 0 not built, 1 built, 2 failed */
} yx_suppression_scope;

void yx_suppression_scope_begin(yx_suppression_scope *scope, const uint8_t *source, size_t length);
void yx_suppression_scope_end(yx_suppression_scope *scope);

/* A scope over a NUL-terminated source text: while it is open on this
 * thread, the questions below about that text (the same pointer) are
 * answered from one measurement and one line index instead of a scan per
 * question. The text must not change while its scope is open. */
void yx_suppression_scope_begin_text(yx_suppression_scope *scope, const char *source);

/* strlen(source). */
size_t yx_source_text_length(const char *source);

/* The 1-based line holding `offset` (1 plus the newlines before it) and,
 * in *line_start, the start of that line. `offset` is at most the text
 * length. */
size_t yx_source_line_of(const char *source, size_t offset, const char **line_start);

/* The same for a label of which only the start is known. */
bool yx_warning_suppressed(const uint8_t *source, size_t length, const char *code, size_t warning_start);

#endif
