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

/* Syntax check with the tokenizer, grammar, backtracking, expected-token
 * bookkeeping and error recovery of the yara-x-parser crate in YARA-X
 * v1.21.0, so syntax errors get YARA-X's spans and messages. */
#ifndef XXYARA_SYNTAX_CHECK_H
#define XXYARA_SYNTAX_CHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A syntax error (code 0, E001) or the literal error YARA-X reports for a
 * dropped rule before its first syntax error: 27 (invalid integer, message
 * is the range), 29 (invalid escape sequence, message "x" for `\x`), 30
 * (invalid regexp modifier) or 31 (unexpected escape sequence). */
typedef struct yx_sc_error {
    size_t start, end;
    char *message;
    size_t item;
    int code;
} yx_sc_error;

/* A top-level item: an import, include or rule, or source that is none of
 * them. `end` is where the item's own node ends; `full_end` also covers the
 * tokens that recovery discarded after it. A dropped item is not compiled. */
typedef struct yx_sc_item {
    size_t start, end, full_end;
    bool dropped;
} yx_sc_item;

typedef struct yx_sc_result {
    yx_sc_error *errors;
    size_t error_count;
    yx_sc_item *items;
    size_t item_count;
} yx_sc_result;

/* Returns false when the check could not complete (allocation failure,
 * nesting or fuel limits); the result is then empty. */
bool yx_syntax_check(const uint8_t *source, size_t length,
                     yx_sc_result *result);
void yx_sc_result_free(yx_sc_result *result);

#ifdef __cplusplus
}
#endif

#endif
