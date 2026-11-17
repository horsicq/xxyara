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

#ifndef XXYARA_MODULE_MAGIC_H
#define XXYARA_MODULE_MAGIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One cache belongs to one scanned byte sequence. Zero-initialize it before
 * the first call, reset it before a new scan, and destroy it when finished.
 * Results remain valid until reset/destroy and contain UTF-8 text, matching
 * YARA-X's lossy conversion of libmagic's C string results. */
typedef struct {
    void *cookie;
    char *file_type;
    size_t file_type_length;
    char *mime_type;
    size_t mime_type_length;
} yx_magic_cache;

void yx_magic_cache_reset(yx_magic_cache *cache);
void yx_magic_cache_destroy(yx_magic_cache *cache);
yx_magic_cache *yx_magic_thread_cache(void);
void yx_magic_thread_cache_reset(void);

/* Implements magic.type() and magic.mime_type() for exactly `size` scanned
 * bytes, including embedded NULs. A NULL data pointer is valid only for an
 * empty scan. False means the YARA-X undefined value (or invalid arguments).
 * Both functions cache successful results, including an empty result. */
bool yx_magic_type(yx_magic_cache *cache, const uint8_t *data, size_t size,
                   const char **out, size_t *out_length);
bool yx_magic_mime_type(yx_magic_cache *cache, const uint8_t *data, size_t size,
                        const char **out, size_t *out_length);

#endif
