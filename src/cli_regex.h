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

#ifndef XXYARA_CLI_REGEX_H
#define XXYARA_CLI_REGEX_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct yx_cli_regex_error {
    char message[256];
    size_t start, end;
    size_t secondary_start, secondary_end;
    bool has_secondary, size_limit;
} yx_cli_regex_error;
typedef struct yx_cli_regex {
    char *pattern;
    size_t length;
    uint32_t options;
} yx_cli_regex;
/* The input remains caller-owned. A successful result owns its translated
 * pattern; release it with yx_cli_regex_free. Errors carry original UTF-8
 * byte spans, with exclusive ends. No diagnostic is printed here. */
bool yx_cli_regex_translate(const char *pattern, size_t length, bool bytes_mode,
                            yx_cli_regex *result, yx_cli_regex_error *error);
void yx_cli_regex_free(yx_cli_regex *result);
#endif
