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

#ifndef XXYARA_MODULE_STRING_H
#define XXYARA_MODULE_STRING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Implements string.length(str). Length counts bytes, including embedded NUL
 * and invalid UTF-8. False is reserved for invalid C arguments or a length
 * that cannot be represented as an i64. */
bool yx_string_length(const uint8_t *bytes, size_t size, int64_t *out);

/* Implements string.to_int(str) and string.to_int(str, base). False is
 * YARA-X's undefined result: invalid syntax, non-ASCII/invalid UTF-8 input,
 * unsupported base, or signed 64-bit overflow. A NULL bytes pointer with
 * size zero represents an empty string and therefore returns false. */
bool yx_string_to_int(const uint8_t *bytes, size_t size, int64_t *out);
bool yx_string_to_int_base(const uint8_t *bytes, size_t size, int64_t base,
                           int64_t *out);

#endif
