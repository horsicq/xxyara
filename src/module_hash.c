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

#include "module_hash.h"
#include "thread_storage.h"

#include <xxfclib/algo/bytestats/xx_bytestats.h>
#include <xxfclib/algo/crc/xx_crc.h>
#include <xxfclib/algo/md5/xx_md5.h>
#include <xxfclib/algo/sha/xx_sha.h>

#include <string.h>

typedef struct {
    yx_hash_algorithm algorithm;
    int64_t offset, size;
    yx_hash_value value;
    bool occupied;
} yx_hash_cache_entry;
typedef struct {
    yx_hash_cache_entry *entries;
    size_t count, capacity;
} yx_hash_cache;
static yx_thread_storage yx_hash_storage = YX_THREAD_STORAGE_INIT;
static _Thread_local yx_hash_cache *yx_hash_thread_cache;

static size_t yx_hash_cache_bucket(yx_hash_algorithm algorithm, int64_t offset, int64_t size, size_t capacity)
{
    uint64_t key = (uint64_t)offset ^ ((uint64_t)size + UINT64_C(0x9e3779b97f4a7c15));
    key ^= (uint64_t)algorithm * UINT64_C(0x517cc1b727220a95);
    key = (key ^ (key >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    key = (key ^ (key >> 27)) * UINT64_C(0x94d049bb133111eb);
    return (size_t)(key ^ (key >> 31)) & (capacity - 1);
}

static void yx_hash_cache_destroy(void *pointer)
{
    yx_hash_cache *cache = pointer;
    yx_hash_thread_cache = NULL;
    free(cache->entries);
}

void yx_hash_cache_reset(void)
{
    yx_hash_cache *cache = yx_hash_thread_cache;
    if (!cache) return;
    if (cache->count) memset(cache->entries, 0, cache->capacity * sizeof(*cache->entries));
    cache->count = 0;
}

bool yx_hash_cache_get(yx_hash_algorithm algorithm, int64_t offset, int64_t size, yx_hash_value *out)
{
    yx_hash_cache *cache = yx_hash_thread_cache;
    if (!out || !cache || !cache->count) return false;
    size_t bucket = yx_hash_cache_bucket(algorithm, offset, size, cache->capacity);
    while (cache->entries[bucket].occupied) {
        const yx_hash_cache_entry *entry = &cache->entries[bucket];
        if (entry->algorithm == algorithm && entry->offset == offset && entry->size == size) {
            *out = entry->value;
            return true;
        }
        bucket = (bucket + 1) & (cache->capacity - 1);
    }
    return false;
}

void yx_hash_cache_put(yx_hash_algorithm algorithm, int64_t offset, int64_t size, const yx_hash_value *value)
{
    if (!yx_hash_thread_cache) yx_hash_thread_cache = yx_thread_storage_get(&yx_hash_storage, sizeof(*yx_hash_thread_cache), yx_hash_cache_destroy);
    yx_hash_cache *cache = yx_hash_thread_cache;
    if (!cache || !value) return;
    if (cache->count >= cache->capacity / 2) {
        size_t capacity = cache->capacity ? cache->capacity * 2 : 16;
        if (capacity < cache->capacity || capacity > SIZE_MAX / sizeof(*cache->entries)) return;
        yx_hash_cache_entry *entries = calloc(capacity, sizeof(*entries));
        if (!entries) return;
        for (size_t i = 0; i < cache->capacity; ++i) {
            if (!cache->entries[i].occupied) continue;
            const yx_hash_cache_entry *entry = &cache->entries[i];
            size_t bucket = yx_hash_cache_bucket(entry->algorithm, entry->offset, entry->size, capacity);
            while (entries[bucket].occupied) bucket = (bucket + 1) & (capacity - 1);
            entries[bucket] = *entry;
        }
        free(cache->entries);
        cache->entries = entries;
        cache->capacity = capacity;
    }
    size_t bucket = yx_hash_cache_bucket(algorithm, offset, size, cache->capacity);
    while (cache->entries[bucket].occupied) {
        yx_hash_cache_entry *entry = &cache->entries[bucket];
        if (entry->algorithm == algorithm && entry->offset == offset && entry->size == size) {
            entry->value = *value;
            return;
        }
        bucket = (bucket + 1) & (cache->capacity - 1);
    }
    cache->entries[bucket] = (yx_hash_cache_entry){algorithm, offset, size, *value, true};
    ++cache->count;
}

/* Reflected CRC-32/ISO-HDLC, matching YARA-X's crc32fast::hash. xxfclib
 * folds bulk data with PCLMULQDQ and uses slice-by-8 tables otherwise. */
static uint32_t yx_crc32(const uint8_t *bytes, size_t size)
{
    return xx_crc32_calc(0, bytes, size);
}

/* YARA-X sums the bytes modulo 2^32. */
static uint32_t yx_checksum32(const uint8_t *bytes, size_t size)
{
    return (uint32_t)xx_bytestats_sum(bytes, size);
}

bool yx_hash_bytes(yx_hash_algorithm algorithm, const uint8_t *bytes, size_t size, yx_hash_value *out)
{
    uint8_t digest[XX_SHA256_DIGEST_SIZE];
    unsigned digest_size;
    bool hashed;
    static const char hexadecimal[] = "0123456789abcdef";
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!bytes && size) return false;
    if (algorithm == YX_HASH_CRC32) {
        out->number = yx_crc32(bytes, size);
        return true;
    }
    if (algorithm == YX_HASH_CHECKSUM32) {
        out->number = yx_checksum32(bytes, size);
        return true;
    }
    switch (algorithm) {
        case YX_HASH_MD5:
            digest_size = XX_MD5_DIGEST_SIZE;
            hashed = xx_md5_memory(bytes, size, digest);
            break;
        case YX_HASH_SHA1:
            digest_size = XX_SHA1_DIGEST_SIZE;
            hashed = xx_sha1_memory(bytes, size, digest);
            break;
        case YX_HASH_SHA256:
            digest_size = XX_SHA256_DIGEST_SIZE;
            hashed = xx_sha256_memory(bytes, size, digest);
            break;
        default: return false;
    }
    if (!hashed) return false;
    for (unsigned i = 0; i < digest_size; ++i) {
        out->text[2 * i] = hexadecimal[digest[i] >> 4];
        out->text[2 * i + 1] = hexadecimal[digest[i] & 15];
    }
    out->text[2 * digest_size] = '\0';
    out->text_length = digest_size * 2;
    return true;
}

bool yx_hash_range(yx_hash_algorithm algorithm, const uint8_t *scanned_data, size_t scanned_size, int64_t offset, int64_t size, yx_hash_value *out)
{
    const uint8_t *slice;
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if ((!scanned_data && scanned_size) || offset < 0 || size < 0 || (uint64_t)offset > scanned_size || (uint64_t)size > scanned_size - (uint64_t)offset) return false;
    slice = scanned_data ? scanned_data + (size_t)offset : NULL;
    return yx_hash_bytes(algorithm, slice, (size_t)size, out);
}
