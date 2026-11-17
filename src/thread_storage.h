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

#ifndef XXYARA_THREAD_STORAGE_H
#define XXYARA_THREAD_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Owned per-thread objects need a destructor, unlike scalar _Thread_local
 * storage. The block keeps the destructor separate from its aligned payload. */
#ifdef _MSC_VER
/* The MSVC C library omits C11 max_align_t. These members cover its
 * fundamental C object alignments without depending on C++ headers. */
typedef union { long double number; void *pointer; int64_t integer; } yx_thread_alignment;
#else
typedef max_align_t yx_thread_alignment;
#endif
typedef struct {
    void (*destroy)(void *);
    yx_thread_alignment alignment;
    unsigned char data[];
} yx_thread_block;

#ifdef _WIN32
#include <windows.h>
typedef struct { SRWLOCK lock; DWORD key; bool initialized; } yx_thread_storage;
#define YX_THREAD_STORAGE_INIT { SRWLOCK_INIT, FLS_OUT_OF_INDEXES, false }
static VOID CALLBACK yx_thread_block_destroy(PVOID pointer)
#else
#include <pthread.h>
typedef struct { pthread_mutex_t lock; pthread_key_t key; bool initialized; } yx_thread_storage;
#define YX_THREAD_STORAGE_INIT { PTHREAD_MUTEX_INITIALIZER, 0, false }
static void yx_thread_block_destroy(void *pointer)
#endif
{
    yx_thread_block *block = pointer;
    if (!block) return;
    if (block->destroy) block->destroy(block->data);
    free(block);
}

static inline void *yx_thread_storage_get(yx_thread_storage *storage, size_t size,
                                           void (*destroy)(void *))
{
    yx_thread_block *block;
    if (size > SIZE_MAX - offsetof(yx_thread_block, data)) return NULL;
#ifdef _WIN32
    AcquireSRWLockExclusive(&storage->lock);
    if (!storage->initialized) {
        storage->key = FlsAlloc(yx_thread_block_destroy);
        storage->initialized = storage->key != FLS_OUT_OF_INDEXES;
    }
    bool initialized = storage->initialized;
    ReleaseSRWLockExclusive(&storage->lock);
    if (!initialized) return NULL;
    block = FlsGetValue(storage->key);
#else
    if (pthread_mutex_lock(&storage->lock)) return NULL;
    if (!storage->initialized)
        storage->initialized = pthread_key_create(&storage->key, yx_thread_block_destroy) == 0;
    bool initialized = storage->initialized;
    pthread_mutex_unlock(&storage->lock);
    if (!initialized) return NULL;
    block = pthread_getspecific(storage->key);
#endif
    if (block) return block->data;
    block = calloc(1, offsetof(yx_thread_block, data) + size);
    if (!block) return NULL;
    block->destroy = destroy;
#ifdef _WIN32
    if (!FlsSetValue(storage->key, block)) {
#else
    if (pthread_setspecific(storage->key, block)) {
#endif
        free(block);
        return NULL;
    }
    return block->data;
}

/* Per-thread memo of pure compile-time results: a value of at most
 * YX_MEMO_VALUE_LIMIT bytes keyed by (tag, key bytes). The tag names the
 * function and carries its scalar inputs (modifiers, flags); the key bytes
 * are its text input. Rule sets repeat patterns across rules and namespaces
 * (APKiD: 4,488 pattern declarations, 1,835 distinct), so the validators
 * look their results up here first. A memoized function must be a pure
 * function of its tag and key; the memo then changes nothing but speed.
 * The open-addressing table doubles at half load up to YX_MEMO_MAX_SLOTS
 * and is cleared when that or YX_MEMO_BUDGET bytes would be exceeded. */
enum { YX_MEMO_MIN_SLOTS = 1024, YX_MEMO_MAX_SLOTS = 1 << 17, YX_MEMO_KEY_LIMIT = 4096,
       YX_MEMO_VALUE_LIMIT = 4096, YX_MEMO_BUDGET = 16u << 20 };
typedef struct {
    uint64_t hash, tag;
    size_t key_length, value_length;
    unsigned char *data; /* key bytes, then value bytes */
} yx_memo_entry;
typedef struct {
    yx_memo_entry *slots;
    size_t slot_count, count, bytes;
} yx_memo;

static inline void yx_memo_clear(yx_memo *memo)
{
    for (size_t i = 0; i < memo->slot_count; ++i) free(memo->slots[i].data);
    if (memo->slot_count) memset(memo->slots, 0, memo->slot_count * sizeof(*memo->slots));
    memo->count = memo->bytes = 0;
}

static inline void yx_memo_destroy(void *opaque)
{
    yx_memo *memo = (yx_memo *)opaque;
    yx_memo_clear(memo);
    free(memo->slots);
    memo->slots = NULL;
    memo->slot_count = 0;
}

static inline yx_memo *yx_memo_get(yx_thread_storage *storage)
{
    return (yx_memo *)yx_thread_storage_get(storage, sizeof(yx_memo), yx_memo_destroy);
}

static inline uint64_t yx_memo_hash(uint64_t tag, const void *key, size_t key_length)
{
    const unsigned char *at = (const unsigned char *)key;
    uint64_t hash = 1469598103934665603ull ^ (tag * 0x9E3779B97F4A7C15ull);
    for (size_t i = 0; i < key_length; ++i) hash = (hash ^ at[i]) * 1099511628211ull;
    return hash ^ (hash >> 29);
}

/* The stored value, or NULL. It stays valid until the next yx_memo_store
 * on this memo; callers copy it out at once. */
static inline const void *yx_memo_find(const yx_memo *memo, uint64_t tag, const void *key,
                                       size_t key_length, size_t *value_length)
{
    uint64_t hash;
    size_t mask, slot;
    if (!memo || !memo->slot_count || key_length > YX_MEMO_KEY_LIMIT) return NULL;
    hash = yx_memo_hash(tag, key, key_length);
    mask = memo->slot_count - 1;
    for (slot = (size_t)hash & mask; memo->slots[slot].data; slot = (slot + 1) & mask) {
        const yx_memo_entry *entry = &memo->slots[slot];
        if (entry->hash == hash && entry->tag == tag && entry->key_length == key_length &&
            (!key_length || !memcmp(entry->data, key, key_length))) {
            *value_length = entry->value_length;
            return entry->data + key_length;
        }
    }
    return NULL;
}

/* Rehashes into slot_count slots (a power of two above twice the count). */
static inline bool yx_memo_resize(yx_memo *memo, size_t slot_count)
{
    yx_memo_entry *slots = (yx_memo_entry *)calloc(slot_count, sizeof(*slots));
    if (!slots) return false;
    for (size_t i = 0; i < memo->slot_count; ++i) {
        size_t slot;
        if (!memo->slots[i].data) continue;
        for (slot = (size_t)memo->slots[i].hash & (slot_count - 1); slots[slot].data;
             slot = (slot + 1) & (slot_count - 1)) {}
        slots[slot] = memo->slots[i];
    }
    free(memo->slots);
    memo->slots = slots;
    memo->slot_count = slot_count;
    return true;
}

static inline void yx_memo_store(yx_memo *memo, uint64_t tag, const void *key, size_t key_length,
                                 const void *value, size_t value_length)
{
    uint64_t hash;
    size_t mask, slot, size = key_length + value_length;
    unsigned char *data;
    if (!memo || key_length > YX_MEMO_KEY_LIMIT || value_length > YX_MEMO_VALUE_LIMIT) return;
    if ((memo->count + 1) * 2 > memo->slot_count) {
        size_t next = memo->slot_count ? memo->slot_count * 2 : YX_MEMO_MIN_SLOTS;
        if (next > YX_MEMO_MAX_SLOTS) yx_memo_clear(memo);
        else if (!yx_memo_resize(memo, next)) return;
    }
    if (memo->bytes + size > YX_MEMO_BUDGET) yx_memo_clear(memo);
    hash = yx_memo_hash(tag, key, key_length);
    mask = memo->slot_count - 1;
    for (slot = (size_t)hash & mask; memo->slots[slot].data; slot = (slot + 1) & mask) {}
    data = (unsigned char *)malloc(size ? size : 1);
    if (!data) return;
    if (key_length) memcpy(data, key, key_length);
    if (value_length) memcpy(data + key_length, value, value_length);
    memo->slots[slot].hash = hash;
    memo->slots[slot].tag = tag;
    memo->slots[slot].key_length = key_length;
    memo->slots[slot].value_length = value_length;
    memo->slots[slot].data = data;
    memo->bytes += size;
    ++memo->count;
}
#endif
