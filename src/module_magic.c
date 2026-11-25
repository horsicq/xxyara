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

#include "module_magic.h"
#include "thread_storage.h"

#include <magic.h>

#include <stdlib.h>
#include <string.h>

static yx_thread_storage yx_magic_storage = YX_THREAD_STORAGE_INIT;
static _Thread_local yx_magic_cache *yx_magic_tls;
static void yx_magic_thread_destroy(void *pointer)
{
    yx_magic_tls = NULL;
    yx_magic_cache_destroy(pointer);
}
yx_magic_cache *yx_magic_thread_cache(void)
{
    if (!yx_magic_tls) yx_magic_tls = yx_thread_storage_get(&yx_magic_storage, sizeof(*yx_magic_tls), yx_magic_thread_destroy);
    return yx_magic_tls;
}
void yx_magic_thread_cache_reset(void)
{
    yx_magic_cache_reset(yx_magic_tls);
}

void yx_magic_cache_reset(yx_magic_cache *cache)
{
    if (!cache) return;
    free(cache->file_type);
    free(cache->mime_type);
    cache->file_type = NULL;
    cache->mime_type = NULL;
    cache->file_type_length = 0;
    cache->mime_type_length = 0;
}

void yx_magic_cache_destroy(yx_magic_cache *cache)
{
    if (!cache) return;
    yx_magic_cache_reset(cache);
    if (cache->cookie) magic_close((magic_t)cache->cookie);
    cache->cookie = NULL;
}

/* Rust's magic crate converts the libmagic result with CStr::to_string_lossy.
 * Most libmagic descriptions are already ASCII, but text extracted from a
 * file can contain malformed UTF-8. Keep the returned string valid UTF-8. */
static char *yx_magic_utf8_lossy(const char *source, size_t *out_length)
{
    const unsigned char *bytes = (const unsigned char *)source;
    size_t source_length = strlen(source), length = 0, i = 0;
    char *result;

    if (source_length > (SIZE_MAX - 1) / 3) return NULL;
    result = malloc(source_length * 3 + 1);
    if (!result) return NULL;
    while (i < source_length) {
        unsigned char first = bytes[i];
        size_t width = 0, valid = 1;
        if (first < 0x80) {
            result[length++] = (char)first;
            ++i;
            continue;
        }
        if (first >= 0xC2 && first <= 0xDF) width = 2;
        else if (first >= 0xE0 && first <= 0xEF) width = 3;
        else if (first >= 0xF0 && first <= 0xF4) width = 4;
        if (width) {
            while (valid < width && i + valid < source_length) {
                unsigned char current = bytes[i + valid];
                if (current < 0x80 || current > 0xBF) break;
                if (valid == 1 &&
                    ((first == 0xE0 && current < 0xA0) || (first == 0xED && current > 0x9F) || (first == 0xF0 && current < 0x90) || (first == 0xF4 && current > 0x8F)))
                    break;
                ++valid;
            }
            if (valid == width) {
                memcpy(result + length, bytes + i, width);
                length += width;
                i += width;
                continue;
            }
        }
        result[length++] = (char)0xEF;
        result[length++] = (char)0xBF;
        result[length++] = (char)0xBD;
        i += valid;
    }
    result[length] = '\0';
    *out_length = length;
    return result;
}

static bool yx_magic_get(yx_magic_cache *cache, const uint8_t *data, size_t size, bool mime, const char **out, size_t *out_length)
{
    static const uint8_t empty = 0;
    char **slot;
    size_t *slot_length;
    const char *description;
    magic_t cookie;

    if (out) *out = NULL;
    if (out_length) *out_length = 0;
    if (!cache || !out || !out_length || (!data && size)) return false;
    slot = mime ? &cache->mime_type : &cache->file_type;
    slot_length = mime ? &cache->mime_type_length : &cache->file_type_length;
    if (*slot) {
        *out = *slot;
        *out_length = *slot_length;
        return true;
    }
    if (!cache->cookie) {
        cookie = magic_open(MAGIC_NONE);
        if (!cookie) return false;
        if (magic_load(cookie, NULL) != 0) {
            magic_close(cookie);
            return false;
        }
        cache->cookie = cookie;
    }
    cookie = (magic_t)cache->cookie;
    if (magic_setflags(cookie, mime ? MAGIC_MIME_TYPE : MAGIC_NONE) != 0) return false;
    description = magic_buffer(cookie, data ? data : &empty, size);
    if (!description) return false;
    *slot = yx_magic_utf8_lossy(description, slot_length);
    if (!*slot) return false;
    *out = *slot;
    *out_length = *slot_length;
    return true;
}

bool yx_magic_type(yx_magic_cache *cache, const uint8_t *data, size_t size, const char **out, size_t *out_length)
{
    return yx_magic_get(cache, data, size, false, out, out_length);
}

bool yx_magic_mime_type(yx_magic_cache *cache, const uint8_t *data, size_t size, const char **out, size_t *out_length)
{
    return yx_magic_get(cache, data, size, true, out, out_length);
}
