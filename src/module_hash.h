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

#ifndef XXYARA_MODULE_HASH_H
#define XXYARA_MODULE_HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    YX_HASH_MD5,
    YX_HASH_SHA1,
    YX_HASH_SHA256,
    YX_HASH_CRC32,
    YX_HASH_CHECKSUM32
} yx_hash_algorithm;

typedef struct {
    /* MD5, SHA-1, and SHA-256 use lowercase hexadecimal, NUL terminated.
     * For CRC32 and checksum32, text_length is zero and number is populated. */
    char text[65];
    size_t text_length;
    uint32_t number;
} yx_hash_value;

/* Hash exactly `size` bytes, including embedded NULs. A NULL bytes pointer
 * with size zero denotes the empty string. False means invalid arguments or
 * a digest backend failure. */
bool yx_hash_bytes(yx_hash_algorithm algorithm, const uint8_t *bytes,
                   size_t size, yx_hash_value *out);

/* Hash [offset, offset + size) in scanned_data. False means YARA-X's
 * undefined value: negative or out-of-bounds ranges are not truncated.
 * offset == scanned_size with size == 0 is valid. */
bool yx_hash_range(yx_hash_algorithm algorithm, const uint8_t *scanned_data,
                   size_t scanned_size, int64_t offset, int64_t size,
                   yx_hash_value *out);

void yx_hash_cache_reset(void);
bool yx_hash_cache_get(yx_hash_algorithm algorithm, int64_t offset, int64_t size,
                        yx_hash_value *out);
void yx_hash_cache_put(yx_hash_algorithm algorithm, int64_t offset, int64_t size,
                        const yx_hash_value *value);

#endif
