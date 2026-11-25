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

/*
 * The virtual machines, atom verification and match list follow
 * lib/src/re/thompson/pikevm.rs, lib/src/re/fast/fastvm.rs,
 * lib/src/re/mod.rs (WideIter), lib/src/scanner/context.rs and
 * lib/src/scanner/matches.rs in YARA-X v1.21.0.
 *
 * Copyright (c) 2024. The YARA-X Authors. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "regex_vm.h"

#include <xxfclib/algo/byteset/xx_byteset.h>
#include <xxfclib/algo/literal/xx_literal.h>

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif
#include "thread_storage.h"

#define YX_RX_SCAN_LIMIT 4096u
#define YX_RX_PREFIX 0xAA

#if defined(_MSC_VER)
#define YX_RX_INLINE static __forceinline
#define YX_RX_NOINLINE static __declspec(noinline)
#elif defined(__GNUC__)
#define YX_RX_INLINE static inline __attribute__((always_inline))
#define YX_RX_NOINLINE static __attribute__((noinline))
#else
#define YX_RX_INLINE static inline
#define YX_RX_NOINLINE static
#endif

/* ------------------------------------------------------------------ */
/* Input iterators (slice iterators and WideIter).                     */

typedef struct {
    const uint8_t *data;
    size_t at, end;          /* forward: at..end; backward: begin..at */
    bool backwards, wide, zero_first;
    size_t valid_pairs;
    bool has_error;
    size_t error_pos;
} yx_rx_iter;

static void yx_rx_iter_init(yx_rx_iter *it, const uint8_t *data, size_t begin,
                            size_t end, bool backwards, bool wide,
                            bool zero_first)
{
    memset(it, 0, sizeof(*it));
    it->data = data;
    it->backwards = backwards;
    it->wide = wide;
    it->zero_first = zero_first;
    if (backwards) { it->at = end; it->end = begin; }
    else { it->at = begin; it->end = end; }
}

/* The PikeVM's iterators are specialised by direction and width: callers
 * pass the iterator's own `backwards` and `wide` as compile-time constants.
 * A backward iterator is always the zero_first WideIter (see
 * yx_pikevm_try_match), so `backwards` also selects the byte order. */
YX_RX_INLINE int yx_rx_iter_raw(yx_rx_iter *it, bool backwards)
{
    if (backwards) {
        if (it->at <= it->end) return -1;
        return it->data[--it->at];
    }
    if (it->at >= it->end) return -1;
    return it->data[it->at++];
}

YX_RX_INLINE int yx_rx_iter_next(yx_rx_iter *it, bool backwards, bool wide)
{
    int first, second;
    if (!wide) return yx_rx_iter_raw(it, backwards);
    first = yx_rx_iter_raw(it, backwards);
    if (first < 0) return -1;
    second = yx_rx_iter_raw(it, backwards);
    if (second < 0) return -1;
    if (backwards) {
        if (first != 0 && !it->has_error) { it->has_error = true; it->error_pos = it->valid_pairs; }
        ++it->valid_pairs;
        return second;
    }
    if (second != 0 && !it->has_error) { it->has_error = true; it->error_pos = it->valid_pairs; }
    ++it->valid_pairs;
    return first;
}

/* ------------------------------------------------------------------ */
/* PikeVM.                                                             */

enum {
    YX_PI_MATCH = 0x00, YX_PI_SPLIT_A = 0x01, YX_PI_SPLIT_B = 0x02,
    YX_PI_SPLIT_N = 0x03, YX_PI_JUMP = 0x04, YX_PI_ANY_BYTE = 0x05,
    YX_PI_MASKED_BYTE = 0x06, YX_PI_NOCASE = 0x07, YX_PI_BITMAP = 0x08,
    YX_PI_RANGES = 0x09, YX_PI_START = 0x0A, YX_PI_END = 0x0B,
    YX_PI_WORD_BOUNDARY = 0x0C, YX_PI_WORD_BOUNDARY_NEG = 0x0D,
    YX_PI_WORD_START = 0x0E, YX_PI_WORD_END = 0x0F,
    YX_PI_REPEAT_GREEDY = 0x10, YX_PI_REPEAT_NON_GREEDY = 0x11,
    YX_PI_LINE_START = 0x12, YX_PI_LINE_END = 0x13,
    /* Boolean-search assertions use regex-automata's condition semantics. */
    YX_PI_SEARCH_START_LF = 0x14, YX_PI_SEARCH_END_LF = 0x15,
    YX_PI_SEARCH_START_CRLF = 0x16, YX_PI_SEARCH_END_CRLF = 0x17,
    YX_PI_SEARCH_WORD_START = 0x18, YX_PI_SEARCH_WORD_END = 0x19,
    YX_PI_SEARCH_WORD_START_HALF = 0x1A, YX_PI_SEARCH_WORD_END_HALF = 0x1B,
    /* Not opcodes: decoder results that fit the one-byte op table. */
    YX_PI_BYTE = 0x1C, YX_PI_BYTES = 0x1D, YX_PI_INVALID = 0xFF
};

typedef struct { int op; size_t size; } yx_pi_instr;

static int32_t yx_rx_i32(const uint8_t *p)
{
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}
static uint32_t yx_rx_u32(const uint8_t *p) { return (uint32_t)yx_rx_i32(p); }
static uint16_t yx_rx_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static bool yx_pi_is_bytes_run(const uint8_t *c, size_t n)
{
    if (n >= 4 && c[0] == YX_RX_PREFIX && c[1] == YX_RX_PREFIX &&
        c[2] == YX_RX_PREFIX && c[3] == YX_RX_PREFIX) return true;
    if (n >= 3 && c[0] == YX_RX_PREFIX && c[1] == YX_RX_PREFIX && c[2] != YX_RX_PREFIX) return true;
    if (n >= 3 && c[0] != YX_RX_PREFIX && c[1] == YX_RX_PREFIX && c[2] == YX_RX_PREFIX) return true;
    if (n >= 2 && c[0] != YX_RX_PREFIX && c[1] != YX_RX_PREFIX) return true;
    return false;
}

/* InstrParser::decode_instr. Returns false for code that is out of bounds. */
static bool yx_pi_decode(const uint8_t *code, size_t length, size_t ip,
                         bool literal_runs, yx_pi_instr *out)
{
    const uint8_t *c = code + ip;
    size_t n = length - ip;
    if (ip >= length) return false;
    if (c[0] == YX_RX_PREFIX && n >= 2 && c[1] != YX_RX_PREFIX) {
        switch (c[1]) {
        case YX_PI_ANY_BYTE: case YX_PI_START: case YX_PI_END: case YX_PI_LINE_START:
        case YX_PI_LINE_END: case YX_PI_WORD_BOUNDARY: case YX_PI_WORD_BOUNDARY_NEG:
        case YX_PI_WORD_START: case YX_PI_WORD_END: case YX_PI_MATCH:
        case YX_PI_SEARCH_START_LF: case YX_PI_SEARCH_END_LF:
        case YX_PI_SEARCH_START_CRLF: case YX_PI_SEARCH_END_CRLF:
        case YX_PI_SEARCH_WORD_START: case YX_PI_SEARCH_WORD_END:
        case YX_PI_SEARCH_WORD_START_HALF: case YX_PI_SEARCH_WORD_END_HALF:
            *out = (yx_pi_instr){c[1], 2}; return true;
        case YX_PI_MASKED_BYTE: if (n < 4) return false; *out = (yx_pi_instr){c[1], 4}; return true;
        case YX_PI_NOCASE: if (n < 3) return false; *out = (yx_pi_instr){c[1], 3}; return true;
        case YX_PI_JUMP: if (n < 6) return false; *out = (yx_pi_instr){c[1], 6}; return true;
        case YX_PI_SPLIT_A: case YX_PI_SPLIT_B: if (n < 8) return false; *out = (yx_pi_instr){c[1], 8}; return true;
        case YX_PI_SPLIT_N:
            if (n < 5 || n - 5 < (size_t)c[4] * 4) return false;
            *out = (yx_pi_instr){c[1], 5 + (size_t)c[4] * 4}; return true;
        case YX_PI_REPEAT_GREEDY: case YX_PI_REPEAT_NON_GREEDY:
            if (n < 14) return false;
            *out = (yx_pi_instr){c[1], 14}; return true;
        case YX_PI_RANGES:
            if (n < 3 || n - 3 < (size_t)c[2] * 2) return false;
            *out = (yx_pi_instr){c[1], 3 + (size_t)c[2] * 2}; return true;
        case YX_PI_BITMAP: if (n < 34) return false; *out = (yx_pi_instr){c[1], 34}; return true;
        default: return false;
        }
    }
    if (literal_runs && yx_pi_is_bytes_run(c, n)) { *out = (yx_pi_instr){YX_PI_BYTES, 0}; return true; }
    if (c[0] == YX_RX_PREFIX) {
        if (n < 2) return false;
        *out = (yx_pi_instr){YX_PI_BYTE, 2}; return true;
    }
    *out = (yx_pi_instr){YX_PI_BYTE, 1};
    return true;
}

/* One decoded instruction per code offset, filled on first use by a VM
 * run. Any offset may be a jump target, so the table covers every byte. */
enum { YX_PF_DECODED = 1, YX_PF_RUN = 2, YX_PF_CONSUMING = 4 };
typedef struct {
    uint8_t op;       /* yx_pi_decode without literal runs; YX_PI_INVALID */
    uint8_t flags;    /* YX_PF_RUN: yx_pi_decode with literal runs is BYTES */
    uint16_t size;
} yx_pi_op;

#define YX_PI_LOCAL_THREADS 32

typedef struct { uint32_t ip, count; } yx_pi_thread;
/* The first YX_PI_LOCAL_THREADS entries live in the vector itself. */
typedef struct {
    yx_pi_thread *items;
    size_t used, capacity;
    yx_pi_thread local[YX_PI_LOCAL_THREADS];
} yx_pi_threads;

typedef struct yx_pikevm {
    const uint8_t *code;
    size_t code_length;
    /* Per call: the op table and, for the scan VM, the closure membership
     * stamps (marks[ip] == mark_gen while ip is in the list being built). */
    yx_pi_op *ops;
    uint32_t *marks;
    uint32_t mark_gen;
    void *tables;
    /* Scan VM, per call: memoised epsilon closures (yx_pi_memo_build).
     * memo_index[ip] is 0 when unknown, 1 when not memoised,
     * YX_PI_MEMO_KEYED and above when the closure depends on the repeat
     * count (then memo_direct and memo_keys/memo_values map (ip, count) to
     * a memo value), otherwise the offset in memo_items of the closure's
     * entries, which follow their number and the closure's stack pops. */
    uint32_t *memo_index, *memo_items;
    size_t memo_used, memo_capacity;
    uint64_t *memo_keys;
    uint32_t *memo_values, *memo_direct;
    size_t memo_slots, memo_keyed, memo_blocks;
    yx_pi_threads threads, next, stack;
    uint64_t executed[8192 / 64];
    /* Words of `executed` that hold a bit; clearing them is all a closure
     * needs, instead of zeroing the whole kilobyte for every input byte. */
    uint8_t executed_words_used[8192 / 64];
    unsigned executed_used;
    /* Boolean programs mark every visited instruction offset once per
     * input position; archive split IDs and scanner thread priority stay separate. */
    uint64_t *search_executed;
    yx_pi_threads executed_words;
    bool failed;
    /* Condition regexps search the whole input and stop at the first match. */
    bool unlimited;
    yx_scan_deadline *deadline;
    unsigned steps;
} yx_pikevm;

YX_RX_INLINE bool yx_pi_poll(yx_pikevm *vm)
{
    if (vm->deadline && !(++vm->steps & 1023u) &&
        yx_scan_deadline_reached(vm->deadline)) {
        vm->failed = true;
        return true;
    }
    return false;
}

/* Growth of the original vector: 32 entries, then doubling. */
YX_RX_NOINLINE bool yx_pi_grow(yx_pi_threads *v)
{
    size_t capacity;
    yx_pi_thread *items;
    if (!v->capacity) {
        v->items = v->local;
        v->capacity = YX_PI_LOCAL_THREADS;
        return true;
    }
    if (v->capacity > SIZE_MAX / 2 / sizeof(*v->items)) return false;
    capacity = v->capacity * 2;
    if (v->items == v->local) {
        items = malloc(capacity * sizeof(*items));
        if (items) memcpy(items, v->local, v->used * sizeof(*items));
    } else items = realloc(v->items, capacity * sizeof(*items));
    if (!items) return false;
    v->items = items;
    v->capacity = capacity;
    return true;
}

YX_RX_INLINE bool yx_pi_push(yx_pi_threads *v, uint32_t ip, uint32_t count)
{
    if (v->used == v->capacity && !yx_pi_grow(v)) return false;
    v->items[v->used++] = (yx_pi_thread){ip, count};
    return true;
}

static void yx_pi_threads_free(yx_pi_threads *v)
{
    if (v->items != v->local) free(v->items);
    v->items = NULL;
    v->used = v->capacity = 0;
}

static void yx_pikevm_free(yx_pikevm *vm)
{
    yx_pi_threads_free(&vm->threads);
    yx_pi_threads_free(&vm->next);
    yx_pi_threads_free(&vm->stack);
    yx_pi_threads_free(&vm->executed_words);
    free(vm->tables);
    free(vm->memo_index);
    free(vm->memo_items);
    free(vm->memo_keys);
    free(vm->memo_values);
    free(vm->memo_direct);
    vm->memo_index = vm->memo_items = vm->memo_values = vm->memo_direct = NULL;
    vm->memo_keys = NULL;
    vm->memo_used = vm->memo_capacity = vm->memo_slots = vm->memo_keyed = vm->memo_blocks = 0;
    vm->tables = NULL;
    vm->ops = NULL;
    vm->marks = NULL;
    vm->search_executed = NULL;
}

/* Decodes ip into the op table. ip < code_length. */
YX_RX_NOINLINE yx_pi_op yx_pi_fill(yx_pikevm *vm, uint32_t ip)
{
    yx_pi_instr instr;
    yx_pi_op op = {YX_PI_INVALID, YX_PF_DECODED, 0};
    if (yx_pi_decode(vm->code, vm->code_length, ip, false, &instr)) {
        op.op = (uint8_t)instr.op;
        op.size = (uint16_t)instr.size;
        switch (instr.op) {
        case YX_PI_ANY_BYTE: case YX_PI_BYTE: case YX_PI_MASKED_BYTE: case YX_PI_NOCASE:
        case YX_PI_BITMAP: case YX_PI_RANGES: case YX_PI_MATCH:
            op.flags |= YX_PF_CONSUMING;
            break;
        default:
            break;
        }
        /* With literal runs only BYTE offsets decode differently. */
        if (yx_pi_decode(vm->code, vm->code_length, ip, true, &instr) && instr.op == YX_PI_BYTES)
            op.flags |= YX_PF_RUN;
    }
    vm->ops[ip] = op;
    return op;
}

YX_RX_INLINE yx_pi_op yx_pi_fetch(yx_pikevm *vm, uint32_t ip)
{
    yx_pi_op op = vm->ops[ip];
    if (!(op.flags & YX_PF_DECODED)) op = yx_pi_fill(vm, ip);
    return op;
}

/* Starts an empty closure list for the scan VM. */
YX_RX_INLINE void yx_pi_new_list(yx_pikevm *vm)
{
    if (vm->unlimited) return;
    if (++vm->mark_gen == 0) {
        memset(vm->marks, 0, vm->code_length * sizeof(*vm->marks));
        vm->mark_gen = 1;
    }
}

/* The Boolean search shares this set across all epsilon closures feeding
 * one input position. Sparse clearing keeps its cost proportional to active
 * instructions, including for a large program searching a short subject. */
static bool yx_pi_search_clear(yx_pikevm *vm)
{
    for (size_t i = 0; i < vm->executed_words.used; ++i) {
        if (yx_pi_poll(vm)) return false;
        vm->search_executed[vm->executed_words.items[i].ip] = 0;
    }
    vm->executed_words.used = 0;
    return true;
}

static bool yx_pi_word(int c)
{
    return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static uint32_t yx_pi_offset(uint32_t ip, int32_t offset)
{
    int64_t target = (int64_t)ip + offset;
    return target < 0 ? 0 : (uint32_t)target;
}

/* epsilon_closure. Bytes are -1 when absent. */
YX_RX_NOINLINE void yx_pi_closure(yx_pikevm *vm, uint32_t start, uint32_t rep_count,
                                  int curr, int prev, bool backwards, yx_pi_threads *closure)
{
    if (!vm->unlimited) {
        for (unsigned i = 0; i < vm->executed_used; ++i)
            vm->executed[vm->executed_words_used[i]] = 0;
        vm->executed_used = 0;
    }
    vm->stack.used = 0;
    if (!yx_pi_push(&vm->stack, start, rep_count)) { vm->failed = true; return; }
    while (vm->stack.used) {
        if (yx_pi_poll(vm)) return;
        yx_pi_thread t = vm->stack.items[--vm->stack.used];
        yx_pi_op instr;
        const uint8_t *c;
        bool accept = false;
        if (vm->unlimited) {
            size_t id = t.ip;
            uint64_t mask = (uint64_t)1 << (id & 63);
            if (id >= vm->code_length) { vm->failed = true; return; }
            if (vm->search_executed[id >> 6] & mask) continue;
            if (!vm->search_executed[id >> 6] &&
                !yx_pi_push(&vm->executed_words, (uint32_t)(id >> 6), 0)) {
                vm->failed = true;
                return;
            }
            vm->search_executed[id >> 6] |= mask;
        }
        if (t.ip >= vm->code_length) { vm->failed = true; return; }
        instr = yx_pi_fetch(vm, t.ip);
        c = vm->code + t.ip;
        switch (instr.op) {
        case YX_PI_ANY_BYTE: case YX_PI_BYTE: case YX_PI_MASKED_BYTE:
        case YX_PI_NOCASE: case YX_PI_BITMAP: case YX_PI_RANGES: case YX_PI_MATCH:
            /* First insertion of an ip wins, as with a linear search. */
            if (!vm->unlimited) {
                if (vm->marks[t.ip] == vm->mark_gen) continue;
                vm->marks[t.ip] = vm->mark_gen;
            }
            if (!yx_pi_push(closure, t.ip, t.count)) { vm->failed = true; return; }
            continue;
        case YX_PI_SPLIT_A: case YX_PI_SPLIT_B: case YX_PI_SPLIT_N: {
            if (!vm->unlimited) {
                unsigned id = (unsigned)yx_rx_u16(c + 2) & 8191u;
                uint64_t mask = (uint64_t)1 << (id & 63);
                if (vm->executed[id >> 6] & mask) continue;
                if (!vm->executed[id >> 6]) vm->executed_words_used[vm->executed_used++] = (uint8_t)(id >> 6);
                vm->executed[id >> 6] |= mask;
            }
            if (instr.op == YX_PI_SPLIT_A) {
                if (!yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 4)), t.count) ||
                    !yx_pi_push(&vm->stack, t.ip + (uint32_t)instr.size, t.count)) { vm->failed = true; return; }
            } else if (instr.op == YX_PI_SPLIT_B) {
                if (!yx_pi_push(&vm->stack, t.ip + (uint32_t)instr.size, t.count) ||
                    !yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 4)), t.count)) { vm->failed = true; return; }
            } else {
                for (size_t k = c[4]; k-- > 0;)
                    if (!yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 5 + 4 * k)), t.count)) {
                        vm->failed = true; return;
                    }
            }
            continue;
        }
        case YX_PI_REPEAT_GREEDY: case YX_PI_REPEAT_NON_GREEDY: {
            uint32_t min = yx_rx_u32(c + 6), max = yx_rx_u32(c + 10), count = t.count + 1;
            uint32_t loop = yx_pi_offset(t.ip, yx_rx_i32(c + 2)), next = t.ip + (uint32_t)instr.size;
            bool ok = true;
            if (instr.op == YX_PI_REPEAT_GREEDY) {
                if (count >= min) ok = yx_pi_push(&vm->stack, next, 0);
                if (ok && count < max) ok = yx_pi_push(&vm->stack, loop, count);
            } else {
                if (count < max) ok = yx_pi_push(&vm->stack, loop, count);
                if (ok && count >= min) ok = yx_pi_push(&vm->stack, next, 0);
            }
            if (!ok) { vm->failed = true; return; }
            continue;
        }
        case YX_PI_JUMP:
            if (!yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 2)), t.count)) { vm->failed = true; return; }
            continue;
        case YX_PI_START:
            accept = (!backwards && prev < 0) || (backwards && curr < 0);
            break;
        case YX_PI_END:
            accept = (!backwards && curr < 0) || (backwards && prev < 0);
            break;
        case YX_PI_LINE_START:
            if (!backwards) {
                if (prev < 0) accept = true;
                else if ((prev == '\n' || prev == '\r') && curr < 0) accept = true;
                else if (prev == '\n') accept = curr != '\r';
                else if (prev == '\r') accept = curr != '\n';
            } else {
                if (curr < 0) accept = true;
                else if (prev < 0 && (curr == '\n' || curr == '\r')) accept = true;
                else if (prev >= 0 && curr == '\n') accept = prev != '\r';
                else if (prev >= 0 && curr == '\r') accept = prev != '\n';
            }
            break;
        case YX_PI_LINE_END:
            if (!backwards) {
                if (curr < 0) accept = true;
                /* Upstream tests a tab here, not a carriage return. */
                else if (prev < 0 && (curr == '\n' || curr == '\t')) accept = true;
                else if (prev >= 0 && curr == '\n') accept = prev != '\r';
                else if (prev >= 0 && curr == '\r') accept = prev != '\n';
            } else {
                if (prev < 0) accept = true;
                else if (prev == '\n' && curr >= 0) accept = curr != '\r';
                else if (prev == '\r' && curr >= 0) accept = curr != '\n';
            }
            break;
        case YX_PI_SEARCH_START_LF: case YX_PI_SEARCH_END_LF:
        case YX_PI_SEARCH_START_CRLF: case YX_PI_SEARCH_END_CRLF:
        case YX_PI_SEARCH_WORD_START: case YX_PI_SEARCH_WORD_END:
        case YX_PI_SEARCH_WORD_START_HALF: case YX_PI_SEARCH_WORD_END_HALF: {
            int p = backwards ? curr : prev, n = backwards ? prev : curr;
            switch (instr.op) {
            case YX_PI_SEARCH_START_LF: accept = p < 0 || p == '\n'; break;
            case YX_PI_SEARCH_END_LF: accept = n < 0 || n == '\n'; break;
            case YX_PI_SEARCH_START_CRLF:
                accept = p < 0 || p == '\n' || (p == '\r' && n != '\n'); break;
            case YX_PI_SEARCH_END_CRLF:
                accept = n < 0 || n == '\r' || (n == '\n' && p != '\r'); break;
            case YX_PI_SEARCH_WORD_START: accept = !yx_pi_word(p) && yx_pi_word(n); break;
            case YX_PI_SEARCH_WORD_END: accept = yx_pi_word(p) && !yx_pi_word(n); break;
            case YX_PI_SEARCH_WORD_START_HALF: accept = !yx_pi_word(p); break;
            default: accept = !yx_pi_word(n); break;
            }
            break;
        }
        case YX_PI_WORD_START: {
            int p = backwards ? curr : prev, n = backwards ? prev : curr;
            if (p >= 0 && n >= 0) accept = !yx_pi_word(p) && yx_pi_word(n);
            else if (p < 0 && n >= 0) accept = yx_pi_word(n);
            break;
        }
        case YX_PI_WORD_END: {
            if (!backwards) {
                if (prev >= 0 && curr >= 0) accept = yx_pi_word(prev) && !yx_pi_word(curr);
                else if (prev >= 0 && curr < 0) accept = yx_pi_word(prev);
            } else {
                /* (true, Some(c), Some(p)) and (true, Some(p), None). */
                if (prev >= 0 && curr >= 0) accept = yx_pi_word(curr) && !yx_pi_word(prev);
                else if (prev >= 0 && curr < 0) accept = yx_pi_word(prev);
            }
            break;
        }
        case YX_PI_WORD_BOUNDARY: case YX_PI_WORD_BOUNDARY_NEG:
            if (prev >= 0 && curr >= 0) accept = yx_pi_word(prev) != yx_pi_word(curr);
            else if (prev >= 0) accept = yx_pi_word(prev);
            else if (curr >= 0) accept = yx_pi_word(curr);
            if (instr.op == YX_PI_WORD_BOUNDARY_NEG) accept = !accept;
            break;
        default:
            vm->failed = true;
            return;
        }
        if (accept && !yx_pi_push(&vm->stack, t.ip + (uint32_t)instr.size, t.count)) {
            vm->failed = true; return;
        }
    }
}

#define YX_PI_MEMO_IPS 64u
#define YX_PI_MEMO_LIMIT ((size_t)1 << 20)     /* memo_items entries */
#define YX_PI_MEMO_SLOTS ((size_t)1 << 18)     /* hash table slots */
/* memo_index values from YX_PI_MEMO_KEYED up: the closure depends on the
 * repeat count. KEYED | block: counts below YX_PI_MEMO_COUNTS have their memo
 * value in memo_direct[block * YX_PI_MEMO_COUNTS + count], others are in the
 * hash table; YX_PI_MEMO_HASHED: all are in the hash table. */
#define YX_PI_MEMO_KEYED 0x80000000u
#define YX_PI_MEMO_HASHED 0xFFFFFFFFu
#define YX_PI_MEMO_COUNTS 64u
#define YX_PI_MEMO_BLOCKS 1024u
#define YX_PI_MEMO_PAIRS 0x80000000u   /* entry count flag: (ip, count) pairs */

/* memo_keys/memo_values: open addressing, (ip << 32 | count) -> memo value. */
static uint32_t yx_pi_memo_find(const yx_pikevm *vm, uint32_t ip, uint32_t count)
{
    uint64_t key = (uint64_t)ip << 32 | count;
    size_t mask, i;
    if (!vm->memo_slots) return 0;
    mask = vm->memo_slots - 1;
    for (i = (size_t)((key * 0x9E3779B97F4A7C15ull) >> 40) & mask;; i = (i + 1) & mask) {
        if (vm->memo_keys[i] == key) return vm->memo_values[i];
        if (vm->memo_keys[i] == UINT64_MAX) return 0;
    }
}

static bool yx_pi_memo_insert(yx_pikevm *vm, uint32_t ip, uint32_t count, uint32_t value)
{
    uint64_t key = (uint64_t)ip << 32 | count;
    size_t mask, i;
    if ((vm->memo_keyed + 1) * 2 > vm->memo_slots) {
        size_t slots = vm->memo_slots ? vm->memo_slots * 2 : 256;
        uint64_t *keys;
        uint32_t *values;
        if (slots > YX_PI_MEMO_SLOTS) return false;
        keys = malloc(slots * sizeof(*keys));
        values = malloc(slots * sizeof(*values));
        if (!keys || !values) { free(keys); free(values); return false; }
        memset(keys, 0xFF, slots * sizeof(*keys));
        for (size_t j = 0; j < vm->memo_slots; ++j) {
            uint64_t old = vm->memo_keys[j];
            if (old == UINT64_MAX) continue;
            for (i = (size_t)((old * 0x9E3779B97F4A7C15ull) >> 40) & (slots - 1); keys[i] != UINT64_MAX;
                 i = (i + 1) & (slots - 1)) {}
            keys[i] = old;
            values[i] = vm->memo_values[j];
        }
        free(vm->memo_keys);
        free(vm->memo_values);
        vm->memo_keys = keys;
        vm->memo_values = values;
        vm->memo_slots = slots;
    }
    mask = vm->memo_slots - 1;
    for (i = (size_t)((key * 0x9E3779B97F4A7C15ull) >> 40) & mask; vm->memo_keys[i] != UINT64_MAX; i = (i + 1) & mask) {}
    vm->memo_keys[i] = key;
    vm->memo_values[i] = value;
    ++vm->memo_keyed;
    return true;
}

/* Records the memo value of a count-dependent closure. */
static bool yx_pi_memo_store(yx_pikevm *vm, uint32_t start, uint32_t count, uint32_t value)
{
    uint32_t index = vm->memo_index[start];
    if (index < YX_PI_MEMO_KEYED) {
        index = YX_PI_MEMO_HASHED;
        if (vm->memo_blocks < YX_PI_MEMO_BLOCKS) {
            uint32_t *grown = realloc(vm->memo_direct,
                                      (vm->memo_blocks + 1) * YX_PI_MEMO_COUNTS * sizeof(*grown));
            if (grown) {
                memset(grown + vm->memo_blocks * YX_PI_MEMO_COUNTS, 0, YX_PI_MEMO_COUNTS * sizeof(*grown));
                vm->memo_direct = grown;
                index = YX_PI_MEMO_KEYED | (uint32_t)vm->memo_blocks++;
            }
        }
        vm->memo_index[start] = index;
    }
    if (index != YX_PI_MEMO_HASHED && count < YX_PI_MEMO_COUNTS) {
        vm->memo_direct[(index & ~YX_PI_MEMO_KEYED) * YX_PI_MEMO_COUNTS + count] = value;
        return true;
    }
    return yx_pi_memo_insert(vm, start, count, value);
}

/* Looks up the memo value of a count-dependent closure; 0 when unknown. */
YX_RX_INLINE uint32_t yx_pi_memo_lookup(const yx_pikevm *vm, uint32_t index, uint32_t ip, uint32_t count)
{
    if (index != YX_PI_MEMO_HASHED && count < YX_PI_MEMO_COUNTS)
        return vm->memo_direct[(index & ~YX_PI_MEMO_KEYED) * YX_PI_MEMO_COUNTS + count];
    return yx_pi_memo_find(vm, ip, count);
}

/* Memoises the scan VM's closure of (start, count) when no instruction it
 * reaches depends on the input bytes (assertions are not memoised): it is
 * then the sequence of consuming offsets, with their counts, that
 * yx_pi_closure tries to add, in yx_pi_closure's order. A closure that
 * reaches no repeat passes `count` to every thread and is stored once per
 * offset as offsets alone; one that reaches a repeat is stored per (start,
 * count) as (offset, count) pairs. The executed set and stack are cleared
 * and left as yx_pi_closure would; a later offset already reached in the
 * same closure is dropped, since adding it again could not change the list.
 * Returns the memo value of (start, count): 1 for yx_pi_closure. */
YX_RX_NOINLINE uint32_t yx_pi_memo_build(yx_pikevm *vm, uint32_t start, uint32_t count)
{
    size_t base, n = 0;
    uint32_t pops = 0, *items;
    bool keyed = false;
    if (!vm->memo_index) {
        vm->memo_index = calloc(vm->code_length, sizeof(*vm->memo_index));
        if (!vm->memo_index) return 1;
    }
    base = vm->memo_used;
    if (vm->memo_capacity - base < 2 + 2 * YX_PI_MEMO_IPS) {
        size_t capacity = vm->memo_capacity ? vm->memo_capacity * 2 : 1024;
        uint32_t *grown;
        if (capacity > YX_PI_MEMO_LIMIT) return vm->memo_index[start] = 1;
        grown = realloc(vm->memo_items, capacity * sizeof(*grown));
        if (!grown) return 1;
        vm->memo_items = grown;
        vm->memo_capacity = capacity;
    }
    items = vm->memo_items + base + 2;
    for (unsigned i = 0; i < vm->executed_used; ++i)
        vm->executed[vm->executed_words_used[i]] = 0;
    vm->executed_used = 0;
    vm->stack.used = 0;
    if (!yx_pi_push(&vm->stack, start, count)) return 1;
    while (vm->stack.used) {
        yx_pi_thread t = vm->stack.items[--vm->stack.used];
        yx_pi_op instr;
        const uint8_t *c;
        ++pops;
        if (t.ip >= vm->code_length) goto plain;
        instr = yx_pi_fetch(vm, t.ip);
        c = vm->code + t.ip;
        switch (instr.op) {
        case YX_PI_ANY_BYTE: case YX_PI_BYTE: case YX_PI_MASKED_BYTE:
        case YX_PI_NOCASE: case YX_PI_BITMAP: case YX_PI_RANGES: case YX_PI_MATCH: {
            size_t k = 0;
            while (k < n && items[2 * k] != t.ip) ++k;
            if (k < n) continue;
            if (n == YX_PI_MEMO_IPS) goto plain;
            items[2 * n] = t.ip;
            items[2 * n + 1] = t.count;
            ++n;
            continue;
        }
        case YX_PI_SPLIT_A: case YX_PI_SPLIT_B: case YX_PI_SPLIT_N: {
            unsigned id = (unsigned)yx_rx_u16(c + 2) & 8191u;
            uint64_t mask = (uint64_t)1 << (id & 63);
            if (vm->executed[id >> 6] & mask) continue;
            if (!vm->executed[id >> 6]) vm->executed_words_used[vm->executed_used++] = (uint8_t)(id >> 6);
            vm->executed[id >> 6] |= mask;
            if (instr.op == YX_PI_SPLIT_A) {
                if (!yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 4)), t.count) ||
                    !yx_pi_push(&vm->stack, t.ip + (uint32_t)instr.size, t.count)) goto plain;
            } else if (instr.op == YX_PI_SPLIT_B) {
                if (!yx_pi_push(&vm->stack, t.ip + (uint32_t)instr.size, t.count) ||
                    !yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 4)), t.count)) goto plain;
            } else {
                for (size_t k = c[4]; k-- > 0;)
                    if (!yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 5 + 4 * k)), t.count)) goto plain;
            }
            continue;
        }
        case YX_PI_REPEAT_GREEDY: case YX_PI_REPEAT_NON_GREEDY: {
            uint32_t min = yx_rx_u32(c + 6), max = yx_rx_u32(c + 10), next_count = t.count + 1;
            uint32_t loop = yx_pi_offset(t.ip, yx_rx_i32(c + 2)), next = t.ip + (uint32_t)instr.size;
            bool ok = true;
            keyed = true;
            if (instr.op == YX_PI_REPEAT_GREEDY) {
                if (next_count >= min) ok = yx_pi_push(&vm->stack, next, 0);
                if (ok && next_count < max) ok = yx_pi_push(&vm->stack, loop, next_count);
            } else {
                if (next_count < max) ok = yx_pi_push(&vm->stack, loop, next_count);
                if (ok && next_count >= min) ok = yx_pi_push(&vm->stack, next, 0);
            }
            if (!ok) goto plain;
            continue;
        }
        case YX_PI_JUMP:
            if (!yx_pi_push(&vm->stack, yx_pi_offset(t.ip, yx_rx_i32(c + 2)), t.count)) goto plain;
            continue;
        default:
            goto plain;
        }
    }
    items[-1] = pops;
    if (!keyed) {
        /* Every thread carries `count`: keep the offsets. */
        for (size_t k = 0; k < n; ++k) items[k] = items[2 * k];
        items[-2] = (uint32_t)n;
        vm->memo_used = base + 2 + n;
        return vm->memo_index[start] = (uint32_t)(base + 2);
    }
    items[-2] = (uint32_t)n | YX_PI_MEMO_PAIRS;
    if (!yx_pi_memo_store(vm, start, count, (uint32_t)(base + 2))) return vm->memo_index[start] = 1;
    vm->memo_used = base + 2 + 2 * n;
    return (uint32_t)(base + 2);
plain:
    /* Before any repeat the walk did not depend on count. */
    if (!keyed || !yx_pi_memo_store(vm, start, count, 1)) return vm->memo_index[start] = 1;
    return 1;
}

typedef bool (*yx_rx_length_callback)(size_t length, void *context); /* true: continue */

/* yx_pi_closure for one matched thread. A consuming instruction is its own
 * closure; the scan VM adds it directly, with the closure's single poll.
 * Memoised closures are added with the polls of their stack pops. */
YX_RX_INLINE void yx_pi_follow(yx_pikevm *vm, uint32_t ip, uint32_t count,
                               int curr, int prev, bool backwards, yx_pi_threads *list)
{
    if (!vm->unlimited && ip < vm->code_length) {
        yx_pi_op op = yx_pi_fetch(vm, ip);
        uint32_t memo;
        if (op.flags & YX_PF_CONSUMING) {
            if (yx_pi_poll(vm)) return;
            if (vm->marks[ip] == vm->mark_gen) return;
            vm->marks[ip] = vm->mark_gen;
            if (!yx_pi_push(list, ip, count)) vm->failed = true;
            return;
        }
        memo = vm->memo_index ? vm->memo_index[ip] : 0;
        if (memo >= YX_PI_MEMO_KEYED) memo = yx_pi_memo_lookup(vm, memo, ip, count);
        if (!memo) memo = yx_pi_memo_build(vm, ip, count);
        if (memo > 1) {
            const uint32_t *items = vm->memo_items + memo;
            uint32_t n = items[-2];
            if (vm->deadline) {
                unsigned before = vm->steps;
                vm->steps += items[-1];
                if ((before >> 10) != (vm->steps >> 10) && yx_scan_deadline_reached(vm->deadline)) {
                    vm->failed = true;
                    return;
                }
            }
            if (!(n & YX_PI_MEMO_PAIRS)) {
                for (uint32_t k = 0; k < n; ++k) {
                    uint32_t at = items[k];
                    if (vm->marks[at] == vm->mark_gen) continue;
                    vm->marks[at] = vm->mark_gen;
                    if (!yx_pi_push(list, at, count)) { vm->failed = true; return; }
                }
                return;
            }
            n &= ~YX_PI_MEMO_PAIRS;
            for (uint32_t k = 0; k < n; ++k) {
                uint32_t at = items[2 * k];
                if (vm->marks[at] == vm->mark_gen) continue;
                vm->marks[at] = vm->mark_gen;
                if (!yx_pi_push(list, at, items[2 * k + 1])) { vm->failed = true; return; }
            }
            return;
        }
    }
    yx_pi_closure(vm, ip, count, curr, prev, backwards, list);
}

/* PikeVM::try_match_impl. The callback returns false for Break. fwd reads
 * in the direction of the program (backwards), bck in the other one; both
 * have width `wide`. */
YX_RX_INLINE void yx_pi_run_impl(yx_pikevm *vm, uint32_t start, const bool backwards, const bool wide,
                                 yx_rx_iter *fwd, yx_rx_iter *bck,
                                 bool (*f)(size_t, void *), void *context)
{
    size_t current_pos = 0;
    int curr = yx_rx_iter_next(fwd, backwards, wide);
    yx_pi_threads *threads = &vm->threads, *next_threads = &vm->next;
    threads->used = next_threads->used = 0;
    if (vm->unlimited && !yx_pi_search_clear(vm)) return;
    yx_pi_new_list(vm);
    yx_pi_follow(vm, start, 0, curr, yx_rx_iter_next(bck, !backwards, wide), backwards, threads);
    while (threads->used && !vm->failed) {
        if (vm->unlimited && !yx_pi_search_clear(vm)) return;
        int next = yx_rx_iter_next(fwd, backwards, wide);
        bool runs = threads->used == 1;
        yx_pi_new_list(vm);
        for (size_t i = 0; i < threads->used; ++i) {
            if (yx_pi_poll(vm)) return;
            yx_pi_thread t = threads->items[i];
            yx_pi_op instr;
            unsigned op;
            size_t size;
            const uint8_t *c;
            bool is_match = false, stop = false;
            if (t.ip >= vm->code_length) { vm->failed = true; return; }
            instr = yx_pi_fetch(vm, t.ip);
            op = runs && (instr.flags & YX_PF_RUN) ? YX_PI_BYTES : instr.op;
            size = instr.size;
            c = vm->code + t.ip;
            switch (op) {
            case YX_PI_ANY_BYTE: is_match = curr >= 0; break;
            case YX_PI_BYTE: is_match = curr >= 0 && curr == c[0]; break;
            case YX_PI_BYTES: {
                /* LiteralBytesIter over the code at ip. */
                size_t offset = 0;
                int bytes[2];
                for (int k = 0; k < 2; ++k) {
                    if (t.ip + offset + 1 < vm->code_length && c[offset] == YX_RX_PREFIX && c[offset + 1] == YX_RX_PREFIX) {
                        bytes[k] = YX_RX_PREFIX; offset += 2;
                    } else if (c[offset] == YX_RX_PREFIX) bytes[k] = -1;
                    else { bytes[k] = c[offset]; offset += 1; }
                }
                is_match = false;
                if (bytes[0] >= 0 && curr == bytes[0]) {
                    if (bytes[1] < 0) is_match = true;
                    else if (next == bytes[1]) {
                        curr = next;
                        ++current_pos;
                        is_match = true;
                        for (;;) {
                            if (yx_pi_poll(vm)) return;
                            int expected;
                            if (t.ip + offset >= vm->code_length) break;
                            if (t.ip + offset + 1 < vm->code_length && c[offset] == YX_RX_PREFIX &&
                                c[offset + 1] == YX_RX_PREFIX) { expected = YX_RX_PREFIX; offset += 2; }
                            else if (c[offset] == YX_RX_PREFIX) break;
                            else { expected = c[offset]; offset += 1; }
                            curr = yx_rx_iter_next(fwd, backwards, wide);
                            if (curr < 0) { is_match = false; break; }
                            ++current_pos;
                            if (curr != expected) { is_match = false; break; }
                        }
                        if (is_match) next = yx_rx_iter_next(fwd, backwards, wide);
                    }
                }
                size = offset;
                break;
            }
            case YX_PI_MASKED_BYTE: is_match = curr >= 0 && ((unsigned)curr & c[3]) == c[2]; break;
            case YX_PI_NOCASE: {
                int lower = curr >= 'A' && curr <= 'Z' ? curr + 32 : curr;
                is_match = curr >= 0 && lower == c[2];
                break;
            }
            case YX_PI_BITMAP: is_match = curr >= 0 && (c[2 + (curr >> 3)] >> (curr & 7)) & 1; break;
            case YX_PI_RANGES:
                for (size_t k = 0; curr >= 0 && k < c[2]; ++k)
                    if (curr >= c[3 + 2 * k] && curr <= c[4 + 2 * k]) { is_match = true; break; }
                break;
            case YX_PI_MATCH:
                if (!f(current_pos, context)) stop = true;
                break;
            default:
                vm->failed = true;
                return;
            }
            if (stop) {
                if (vm->unlimited) {
                    threads->used = next_threads->used = 0;
                    return;
                }
                break;
            }
            if (is_match) {
                yx_pi_follow(vm, t.ip + (uint32_t)size, t.count, next, curr, backwards, next_threads);
                if (vm->failed) return;
            }
        }
        curr = next;
        ++current_pos;
        {
            yx_pi_threads *swap = threads; threads = next_threads; next_threads = swap;
        }
        next_threads->used = 0;
        if (current_pos >= YX_RX_SCAN_LIMIT && !vm->unlimited) {
            threads->used = 0;
            break;
        }
    }
    threads->used = next_threads->used = 0;
}

YX_RX_NOINLINE void yx_pi_run_fwd(yx_pikevm *vm, uint32_t start, yx_rx_iter *fwd, yx_rx_iter *bck,
                                  bool (*f)(size_t, void *), void *context)
{
    yx_pi_run_impl(vm, start, false, false, fwd, bck, f, context);
}

YX_RX_NOINLINE void yx_pi_run_bck(yx_pikevm *vm, uint32_t start, yx_rx_iter *fwd, yx_rx_iter *bck,
                                  bool (*f)(size_t, void *), void *context)
{
    yx_pi_run_impl(vm, start, true, false, fwd, bck, f, context);
}

YX_RX_NOINLINE void yx_pi_run_wide(yx_pikevm *vm, uint32_t start, bool backwards, yx_rx_iter *fwd,
                                   yx_rx_iter *bck, bool (*f)(size_t, void *), void *context)
{
    if (backwards) yx_pi_run_impl(vm, start, true, true, fwd, bck, f, context);
    else yx_pi_run_impl(vm, start, false, true, fwd, bck, f, context);
}

typedef struct {
    bool (*f)(size_t, void *);
    void *context;
    yx_rx_iter *fwd;
} yx_pi_wide_callback;

static bool yx_pi_wide_found(size_t length, void *context)
{
    yx_pi_wide_callback *w = context;
    if (w->fwd->has_error && w->fwd->error_pos < length) return false;
    return w->f(length * 2, w->context);
}

/* Per-call tables of the scan VM: op table and closure stamps. */
static bool yx_pi_tables(yx_pikevm *vm)
{
    size_t length = vm->code_length ? vm->code_length : 1;
    if (vm->tables) return true;
    if (length > SIZE_MAX / (sizeof(yx_pi_op) + sizeof(uint32_t))) return false;
    vm->tables = calloc(length, sizeof(yx_pi_op) + sizeof(uint32_t));
    if (!vm->tables) return false;
    vm->marks = vm->tables;
    vm->ops = (yx_pi_op *)(vm->marks + length);
    vm->mark_gen = 0;
    return true;
}

/* PikeVM::try_match: right is data[at..size], left is data[0..at]. */
static void yx_pikevm_try_match(yx_pikevm *vm, uint32_t start, bool backwards,
                                const uint8_t *data, size_t size, size_t at,
                                bool wide, bool (*f)(size_t, void *), void *context)
{
    yx_rx_iter fwd, bck;
    if (!vm->tables && !yx_pi_tables(vm)) { vm->failed = true; return; }
    if (!backwards) {
        yx_rx_iter_init(&fwd, data, at, size, false, wide, false);
        yx_rx_iter_init(&bck, data, 0, at, true, wide, true);
    } else {
        yx_rx_iter_init(&fwd, data, 0, at, true, wide, true);
        yx_rx_iter_init(&bck, data, at, size, false, wide, false);
    }
    if (!wide) {
        if (backwards) yx_pi_run_bck(vm, start, &fwd, &bck, f, context);
        else yx_pi_run_fwd(vm, start, &fwd, &bck, f, context);
        return;
    }
    yx_pi_wide_callback w = {f, context, &fwd};
    yx_pi_run_wide(vm, start, backwards, &fwd, &bck, yx_pi_wide_found, &w);
}

static bool yx_pi_search_found(size_t length, void *context)
{
    (void)length;
    *(bool *)context = true;
    return false;
}

int yx_rx_pike_search(const uint8_t *code, size_t code_length,
                      const uint8_t *data, size_t size, yx_scan_deadline *deadline)
{
    yx_pikevm vm;
    bool found = false;
    size_t words;
    if (!code || !code_length || code_length > UINT32_MAX || (!data && size) ||
        yx_scan_deadline_reached(deadline)) return -1;
    memset(&vm, 0, sizeof(vm));
    words = (code_length - 1) / 64 + 1;
    /* search_executed, then the op table; the sum must not wrap (32-bit). */
    if (code_length > SIZE_MAX / sizeof(yx_pi_op) ||
        words > (SIZE_MAX - code_length * sizeof(yx_pi_op)) / sizeof(*vm.search_executed)) return -1;
    vm.tables = calloc(1, words * sizeof(*vm.search_executed) + code_length * sizeof(yx_pi_op));
    if (!vm.tables) return -1;
    vm.search_executed = vm.tables;
    vm.ops = (yx_pi_op *)(vm.search_executed + words);
    vm.code = code;
    vm.code_length = code_length;
    vm.unlimited = true;
    vm.deadline = deadline;
    yx_pikevm_try_match(&vm, 0, false, data ? data : (const uint8_t *)"", size,
                        0, false, yx_pi_search_found, &found);
    yx_pikevm_free(&vm);
    if (vm.failed || yx_scan_deadline_reached(deadline)) return -1;
    return found ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* FastVM.                                                             */

typedef struct {
    size_t *items;
    size_t used, capacity;
    uint32_t *seen;
    size_t seen_size;
    uint32_t generation;
} yx_fv_set;

typedef struct yx_fastvm {
    const uint8_t *code;
    size_t code_length;
    yx_fv_set positions, next;
    bool failed;
} yx_fastvm;

static void yx_fv_set_clear(yx_fv_set *s)
{
    s->used = 0;
    if (++s->generation == 0) {
        if (s->seen) memset(s->seen, 0, s->seen_size * sizeof(*s->seen));
        s->generation = 1;
    }
}

static bool yx_fv_insert(yx_fv_set *s, size_t value)
{
    if (value >= s->seen_size) {
        size_t size = s->seen_size ? s->seen_size : 8192;
        while (size <= value) {
            if (size > SIZE_MAX / 2) return false;
            size *= 2;
        }
        uint32_t *seen = realloc(s->seen, size * sizeof(*seen));
        if (!seen) return false;
        memset(seen + s->seen_size, 0, (size - s->seen_size) * sizeof(*seen));
        s->seen = seen;
        s->seen_size = size;
    }
    if (s->seen[value] == s->generation) return true;
    s->seen[value] = s->generation;
    if (s->used == s->capacity) {
        size_t capacity = s->capacity ? s->capacity * 2 : 64;
        size_t *items = realloc(s->items, capacity * sizeof(*items));
        if (!items) return false;
        s->items = items;
        s->capacity = capacity;
    }
    s->items[s->used++] = value;
    return true;
}

enum { YX_FI_MATCH = 0, YX_FI_LITERAL = 1, YX_FI_MASKED = 2, YX_FI_JUMP_EXACT = 3, YX_FI_JUMP = 4,
       YX_FI_JUMP_EXACT_NO_NEWLINE = 5, YX_FI_JUMP_NO_NEWLINE = 6, YX_FI_ALTERNATION = 7 };

typedef struct {
    int op;
    size_t size;
    const uint8_t *literal, *mask;
    size_t length;          /* literal length, or alternation byte length */
    uint32_t min, max;
    bool unbounded;
} yx_fi_instr;

static bool yx_fi_decode(const uint8_t *code, size_t length, size_t ip, yx_fi_instr *out)
{
    const uint8_t *c = code + ip;
    size_t n = length - ip;
    memset(out, 0, sizeof(*out));
    if (ip >= length) return false;
    out->op = c[0];
    switch (c[0]) {
    case YX_FI_LITERAL: case YX_FI_MASKED: {
        size_t literal;
        if (n < 3) return false;
        literal = yx_rx_u16(c + 1);
        if (n - 3 < literal * (c[0] == YX_FI_MASKED ? 2 : 1)) return false;
        out->literal = c + 3;
        out->mask = c[0] == YX_FI_MASKED ? c + 3 + literal : NULL;
        out->length = literal;
        out->size = 3 + literal * (c[0] == YX_FI_MASKED ? 2 : 1);
        return true;
    }
    case YX_FI_ALTERNATION:
        if (n < 3 || n - 3 < yx_rx_u16(c + 1)) return false;
        out->length = yx_rx_u16(c + 1);
        out->literal = c + 3;
        out->size = 3 + out->length;
        return true;
    case YX_FI_JUMP_EXACT: case YX_FI_JUMP_EXACT_NO_NEWLINE:
        if (n < 5) return false;
        out->min = out->max = yx_rx_u32(c + 1);
        out->size = 5;
        return true;
    case YX_FI_JUMP: case YX_FI_JUMP_NO_NEWLINE:
        if (n < 9) return false;
        out->min = yx_rx_u32(c + 1);
        out->max = yx_rx_u32(c + 5);
        out->unbounded = out->max == 0;
        out->size = 9;
        return true;
    case YX_FI_MATCH:
        out->size = 1;
        return true;
    default:
        return false;
    }
}

/* input is the forward slice (data[0..length]), or for backward code the
 * slice that ends at the atom (data[0..length]) read from the end. */
static bool yx_fv_literal(const uint8_t *input, size_t length, size_t position, bool backwards,
                          const uint8_t *literal, const uint8_t *mask, size_t literal_length, bool wide)
{
    if (!backwards) {
        const uint8_t *in = input + position;
        size_t available = length - position;
        if (wide) {
            if (available < literal_length * 2) return false;
            if (!mask) {
                for (size_t i = 0; i < literal_length; ++i)
                    if (in[2 * i] != literal[i] || in[2 * i + 1]) return false;
                return true;
            }
            bool error = false;
            size_t error_pos = 0;
            for (size_t i = 0; i < literal_length; ++i) {
                if (in[2 * i + 1] && !error) { error = true; error_pos = i; }
                if ((in[2 * i] & mask[i]) != (literal[i] & mask[i])) return false;
            }
            return !(error && error_pos < literal_length);
        }
        if (available < literal_length) return false;
        if (!mask) return !memcmp(in, literal, literal_length);
        for (size_t i = 0; i < literal_length; ++i)
            if ((in[i] & mask[i]) != (literal[i] & mask[i])) return false;
        return true;
    }
    {
        size_t available = length - position;     /* input[..len - position] */
        const uint8_t *end = input + available;   /* exclusive */
        if (wide) {
            if (available < literal_length * 2) return false;
            if (!mask) {
                /* rchunks_exact(2): chunk[0] is the low byte, chunk[1] zero. */
                for (size_t i = 0; i < literal_length; ++i) {
                    const uint8_t *chunk = end - 2 * (i + 1);
                    if (chunk[0] != literal[literal_length - 1 - i] || chunk[1]) return false;
                }
                return true;
            }
            bool error = false;
            size_t error_pos = 0;
            /* WideIter::zero_first over the reversed slice. */
            for (size_t i = 0; i < literal_length; ++i) {
                uint8_t first = end[-1 - 2 * (long)i], second = end[-2 - 2 * (long)i];
                if (first && !error) { error = true; error_pos = i; }
                if ((second & mask[literal_length - 1 - i]) !=
                    (literal[literal_length - 1 - i] & mask[literal_length - 1 - i])) return false;
            }
            return !(error && error_pos < literal_length);
        }
        if (available < literal_length) return false;
        if (!mask) return !memcmp(end - literal_length, literal, literal_length);
        for (size_t i = 0; i < literal_length; ++i)
            if ((end[-1 - (long)i] & mask[literal_length - 1 - i]) !=
                (literal[literal_length - 1 - i] & mask[literal_length - 1 - i])) return false;
        return true;
    }
}

static const uint8_t *yx_fv_memchr2_or(const uint8_t *p, size_t n, int a, int b)
{
    for (size_t i = 0; i < n; ++i) if (p[i] == a || p[i] == b) return p + i;
    return NULL;
}

static bool yx_fv_jump_fwd(yx_fv_set *next, const uint8_t *input, size_t input_length,
                           int byte_after, bool accept_newlines, bool wide,
                           size_t min, size_t max, size_t position)
{
    size_t step = wide ? 2 : 1, n = min * step, m = max * step;
    size_t range_min = n, range_max = input_length < m + step ? input_length : m + step;
    if (range_min >= range_max) return true;
    if (!accept_newlines && memchr(input, 0x0A, range_min)) return true;
    const uint8_t *jmp = input + range_min;
    size_t jmp_length = range_max - range_min;
    if (byte_after >= 0 && !accept_newlines) {
        for (size_t offset = 0; offset < jmp_length;) {
            const uint8_t *hit = yx_fv_memchr2_or(jmp + offset, jmp_length - offset, byte_after, 0x0A);
            if (!hit) break;
            offset = (size_t)(hit - jmp);
            if (byte_after != 0x0A && jmp[offset] == 0x0A) return true;
            if (!yx_fv_insert(next, position + range_min + offset)) return false;
            ++offset;
        }
    } else if (byte_after >= 0) {
        for (size_t offset = 0; offset < jmp_length;) {
            const uint8_t *hit = memchr(jmp + offset, byte_after, jmp_length - offset);
            if (!hit) break;
            offset = (size_t)(hit - jmp);
            if (!yx_fv_insert(next, position + range_min + offset)) return false;
            ++offset;
        }
    } else {
        for (size_t offset = 0; offset < jmp_length; ++offset) {
            if (!accept_newlines && jmp[offset] == 0x0A) return true;
            if (!yx_fv_insert(next, position + range_min + offset)) return false;
        }
    }
    return true;
}

/* input is data[0..input_length] that ends where the atom starts. */
static bool yx_fv_jump_bck(yx_fv_set *next, const uint8_t *input, size_t input_length,
                           int expected, bool accept_newlines, bool wide,
                           size_t min, size_t max, size_t position)
{
    size_t step = wide ? 2 : 1, n = min * step, m = max * step;
    size_t range_min = input_length > m + step ? input_length - (m + step) : 0;
    size_t range_max = input_length > n ? input_length - n : 0;
    if (range_min >= range_max) return true;
    if (!accept_newlines && memchr(input + range_max, 0x0A, input_length - range_max)) return true;
    const uint8_t *jmp = input + range_min;
    size_t jmp_length = range_max - range_min;
/* on_match_found: jmp_range.len().checked_sub(offset + step); an offset in
 * the last byte of a wide jump range (odd alignment) is no position. */
#define YX_FV_BCK_FOUND(offset) \
    ((offset) + step > jmp_length || yx_fv_insert(next, position + n + jmp_length - (offset) - step))
    if (expected >= 0 && !accept_newlines) {
        for (size_t offset = jmp_length; offset-- > 0;) {
            if (jmp[offset] != expected && jmp[offset] != 0x0A) continue;
            if (expected != 0x0A && jmp[offset] == 0x0A) return true;
            if (!YX_FV_BCK_FOUND(offset)) return false;
        }
    } else if (expected >= 0) {
        for (size_t offset = jmp_length; offset-- > 0;) {
            if (jmp[offset] != expected) continue;
            if (!YX_FV_BCK_FOUND(offset)) return false;
        }
    } else {
        for (size_t offset = jmp_length; offset-- > 0;) {
            if (!accept_newlines && jmp[offset] == 0x0A) return true;
            if (!YX_FV_BCK_FOUND(offset)) return false;
        }
    }
#undef YX_FV_BCK_FOUND
    return true;
}

/* FastVM::try_match. Forward input is data[at..size]; backward input is
 * data[0..at]. Both are limited to the scan limit. */
static void yx_fastvm_try_match(yx_fastvm *vm, size_t ip, bool backwards,
                                const uint8_t *data, size_t size, size_t at, bool wide,
                                bool (*f)(size_t, void *), void *context)
{
    const uint8_t *input;
    size_t input_length, step = wide ? 2 : 1;
    if (backwards) {
        input_length = at < YX_RX_SCAN_LIMIT ? at : YX_RX_SCAN_LIMIT;
        input = data + at - input_length;
    } else {
        input = data + at;
        input_length = size - at < YX_RX_SCAN_LIMIT ? size - at : YX_RX_SCAN_LIMIT;
    }
    yx_fv_set_clear(&vm->positions);
    yx_fv_set_clear(&vm->next);
    if (!yx_fv_insert(&vm->positions, 0)) { vm->failed = true; return; }
    while (vm->positions.used) {
        yx_fi_instr instr;
        if (!yx_fi_decode(vm->code, vm->code_length, ip, &instr)) { vm->failed = true; return; }
        ip += instr.size;
        switch (instr.op) {
        case YX_FI_MATCH:
            for (size_t i = 0; i < vm->positions.used; ++i) {
                size_t position = vm->positions.items[i];
                if (wide) {
                    bool zeroes = true;
                    if (backwards) {
                        for (size_t k = 0; k < position && k < input_length; k += 2)
                            if (input[input_length - 1 - k]) { zeroes = false; break; }
                    } else {
                        for (size_t k = 1; k < position && k < input_length; k += 2)
                            if (input[k]) { zeroes = false; break; }
                    }
                    if (!zeroes) continue;
                }
                if (!f(position, context)) { vm->positions.used = 0; return; }
            }
            break;
        case YX_FI_LITERAL: case YX_FI_MASKED:
            for (size_t i = 0; i < vm->positions.used; ++i) {
                size_t position = vm->positions.items[i];
                if (position >= input_length) continue;
                if (yx_fv_literal(input, input_length, position, backwards, instr.literal, instr.mask,
                                  instr.length, wide) &&
                    !yx_fv_insert(&vm->next, position + step * instr.length)) { vm->failed = true; return; }
            }
            break;
        case YX_FI_ALTERNATION: {
            size_t alt = 0;
            while (alt < instr.length) {
                yx_fi_instr a;
                if (!yx_fi_decode(instr.literal, instr.length, alt, &a) ||
                    (a.op != YX_FI_LITERAL && a.op != YX_FI_MASKED)) { vm->failed = true; return; }
                alt += a.size;
                for (size_t i = 0; i < vm->positions.used; ++i) {
                    size_t position = vm->positions.items[i];
                    if (position >= input_length) continue;
                    if (yx_fv_literal(input, input_length, position, backwards, a.literal, a.mask,
                                      a.length, wide) &&
                        !yx_fv_insert(&vm->next, position + step * a.length)) { vm->failed = true; return; }
                }
            }
            break;
        }
        case YX_FI_JUMP_EXACT:
            for (size_t i = 0; i < vm->positions.used; ++i)
                if (!yx_fv_insert(&vm->next, vm->positions.items[i] + step * instr.min)) { vm->failed = true; return; }
            break;
        case YX_FI_JUMP_EXACT_NO_NEWLINE:
            for (size_t i = 0; i < vm->positions.used; ++i) {
                size_t position = vm->positions.items[i], width = step * instr.min;
                /* input.get(position..position + width) */
                if (position > input_length || width > input_length - position) continue;
                if (memchr(input + position, 0x0A, width)) continue;
                if (!yx_fv_insert(&vm->next, position + width)) { vm->failed = true; return; }
            }
            break;
        case YX_FI_JUMP: case YX_FI_JUMP_NO_NEWLINE: {
            bool accept_newlines = instr.op == YX_FI_JUMP;
            size_t min = instr.min, max = instr.unbounded ? YX_RX_SCAN_LIMIT : instr.max;
            yx_fi_instr following;
            int byte = -1;
            if (yx_fi_decode(vm->code, vm->code_length, ip, &following)) {
                if (following.op == YX_FI_LITERAL && following.length)
                    byte = backwards ? following.literal[following.length - 1] : following.literal[0];
                else if (following.op == YX_FI_MASKED && following.length) {
                    if (backwards && following.mask[following.length - 1] == 0xff)
                        byte = following.literal[following.length - 1];
                    else if (!backwards && following.mask[0] == 0xff)
                        byte = following.literal[0];
                }
            }
            for (size_t i = 0; i < vm->positions.used; ++i) {
                size_t position = vm->positions.items[i];
                bool ok;
                if (position >= input_length) continue;
                if (backwards)
                    ok = yx_fv_jump_bck(&vm->next, input, input_length - position, byte,
                                        accept_newlines, wide, min, max, position);
                else
                    ok = yx_fv_jump_fwd(&vm->next, input + position, input_length - position, byte,
                                        accept_newlines, wide, min, max, position);
                if (!ok) { vm->failed = true; return; }
            }
            break;
        }
        default:
            vm->failed = true;
            return;
        }
        {
            yx_fv_set swap = vm->positions; vm->positions = vm->next; vm->next = swap;
        }
        yx_fv_set_clear(&vm->next);
    }
}

/* ------------------------------------------------------------------ */
/* Verification.                                                       */

static bool yx_rx_alnum(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* verify_full_word without a XOR key. */
static bool yx_rx_full_word(const uint8_t *data, size_t size, size_t start, size_t end, unsigned flags)
{
    if (flags & YX_RX_WIDE) {
        if ((flags & YX_RX_FULLWORD_LEFT) && start >= 2 && data[start - 1] == 0 &&
            yx_rx_alnum(data[start - 2])) return false;
        if ((flags & YX_RX_FULLWORD_RIGHT) && end + 1 < size && data[end + 1] == 0 &&
            yx_rx_alnum(data[end])) return false;
    } else {
        if ((flags & YX_RX_FULLWORD_LEFT) && start >= 1 && yx_rx_alnum(data[start - 1])) return false;
        if ((flags & YX_RX_FULLWORD_RIGHT) && end < size && yx_rx_alnum(data[end])) return false;
    }
    return true;
}

/* MatchList::add. */
static bool yx_rx_add(yx_rx_match_list *list, size_t start, size_t end, bool replace_if_longer)
{
    if (list->limit && list->count >= list->limit) { list->limit_reached = true; return true; }
    if (list->count && start > list->items[list->count - 1].start) {
        /* push */
    } else if (list->count && start == list->items[list->count - 1].start) {
        if (replace_if_longer) list->items[list->count - 1].end = end;
        return true;
    } else if (list->count) {
        size_t low = 0, high = list->count;
        while (low < high) {
            size_t middle = low + (high - low) / 2;
            if (list->items[middle].start < start) low = middle + 1;
            else high = middle;
        }
        if (low < list->count && list->items[low].start == start) {
            if (replace_if_longer && list->items[low].end < end) list->items[low].end = end;
            return true;
        }
        if (list->count == list->capacity) {
            size_t capacity = list->capacity ? list->capacity * 2 : 16;
            yx_rx_match *items = realloc(list->items, capacity * sizeof(*items));
            if (!items) return false;
            list->items = items;
            list->capacity = capacity;
        }
        memmove(list->items + low + 1, list->items + low, (list->count - low) * sizeof(*list->items));
        list->items[low] = (yx_rx_match){start, end};
        ++list->count;
        return true;
    }
    if (list->count == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2 : 16;
        yx_rx_match *items = realloc(list->items, capacity * sizeof(*items));
        if (!items) return false;
        list->items = items;
        list->capacity = capacity;
    }
    list->items[list->count++] = (yx_rx_match){start, end};
    return true;
}

typedef struct {
    const yx_rx_sub *sub;
    const uint8_t *data;
    size_t size, match_start, fwd_length;
    bool have_fwd;
    yx_rx_match_list *list;
    bool failed;
} yx_rx_verify;

static bool yx_rx_fwd_found(size_t length, void *context)
{
    yx_rx_verify *v = context;
    v->fwd_length = length;
    v->have_fwd = true;
    return (v->sub->flags & YX_RX_FAST) && (v->sub->flags & YX_RX_GREEDY);
}

static bool yx_rx_bck_found(size_t length, void *context)
{
    yx_rx_verify *v = context;
    size_t start = v->match_start - length, end = v->match_start + v->fwd_length;
    if (yx_rx_full_word(v->data, v->size, start, end, v->sub->flags) &&
        !(v->list->each ? v->list->each(v->list->each_context, v->sub->flags, start, end) :
          yx_rx_add(v->list, start, end, (v->sub->flags & YX_RX_GREEDY) != 0))) v->failed = true;
    return true;
}

/* Input known to consist of a guard's run bytes: [from, end). */
typedef struct { size_t from, end; } yx_rx_run_span;

typedef struct {
    yx_pikevm pike;
    yx_fastvm fast;
    /* Per call, one span per program guard (yx_rx_guard_pass), or NULL. */
    yx_rx_run_span *spans;
    bool spans_failed;
} yx_rx_vms;

/* verify_regexp. */
static bool yx_rx_verify_regexp(yx_rx_vms *vms, const yx_rx_program *program, const yx_rx_sub *sub,
                                const yx_rx_atom *atom, const uint8_t *data, size_t size,
                                size_t match_start, yx_rx_match_list *list)
{
    yx_rx_verify v = {sub, data, size, match_start, 0, false, list, false};
    bool wide = (sub->flags & YX_RX_WIDE) != 0, fast = (sub->flags & YX_RX_FAST) != 0;
    if (atom->has_fwd) {
        if (fast) yx_fastvm_try_match(&vms->fast, atom->fwd, false, data, size, match_start, wide, yx_rx_fwd_found, &v);
        else yx_pikevm_try_match(&vms->pike, (uint32_t)atom->fwd, false, data, size, match_start, wide,
                                 yx_rx_fwd_found, &v);
        if (vms->fast.failed || vms->pike.failed) return false;
    } else {
        v.fwd_length = atom->length;
        v.have_fwd = true;
    }
    if (!v.have_fwd) return true;
    if (atom->has_bck) {
        if (fast) yx_fastvm_try_match(&vms->fast, atom->bck, true, data, size, match_start, wide, yx_rx_bck_found, &v);
        else yx_pikevm_try_match(&vms->pike, (uint32_t)atom->bck, true, data, size, match_start, wide,
                                 yx_rx_bck_found, &v);
        if (vms->fast.failed || vms->pike.failed) return false;
    } else {
        yx_rx_bck_found(0, &v);
    }
    (void)program;
    return !v.failed;
}

/* ------------------------------------------------------------------ */
/* Atom search in Aho-Corasick order.                                  */

typedef struct {
    size_t end, length, index;  /* index orders atoms by insertion */
    size_t position;            /* start offset of this occurrence */
    size_t bucket;              /* Teddy bucket; unused for Aho-Corasick */
    bool teddy;
    const yx_rx_sub *sub;
    const yx_rx_atom *atom;
} yx_rx_hit;

typedef struct { yx_rx_hit *items; size_t used, capacity; } yx_rx_heap;

/* Aho-Corasick (daachorse) reports by end offset, longest first; Teddy
 * reports by start offset, then bucket, then pattern order in the bucket. */
static bool yx_rx_hit_before(const yx_rx_hit *a, const yx_rx_hit *b)
{
    if (a->teddy) {
        if (a->position != b->position) return a->position < b->position;
        if (a->bucket != b->bucket) return a->bucket < b->bucket;
        return a->index < b->index;
    }
    if (a->end != b->end) return a->end < b->end;
    if (a->length != b->length) return a->length > b->length;
    return a->index < b->index;
}

static bool yx_rx_heap_push(yx_rx_heap *h, yx_rx_hit hit)
{
    if (h->used == h->capacity) {
        size_t capacity = h->capacity ? h->capacity * 2 : 64;
        yx_rx_hit *items = realloc(h->items, capacity * sizeof(*items));
        if (!items) return false;
        h->items = items;
        h->capacity = capacity;
    }
    size_t i = h->used++;
    h->items[i] = hit;
    while (i) {
        size_t parent = (i - 1) / 2;
        if (!yx_rx_hit_before(&h->items[i], &h->items[parent])) break;
        yx_rx_hit swap = h->items[i]; h->items[i] = h->items[parent]; h->items[parent] = swap;
        i = parent;
    }
    return true;
}

static yx_rx_hit yx_rx_heap_pop(yx_rx_heap *h)
{
    yx_rx_hit top = h->items[0];
    h->items[0] = h->items[--h->used];
    for (size_t i = 0;;) {
        size_t left = 2 * i + 1, right = left + 1, best = i;
        if (left < h->used && yx_rx_hit_before(&h->items[left], &h->items[best])) best = left;
        if (right < h->used && yx_rx_hit_before(&h->items[right], &h->items[best])) best = right;
        if (best == i) break;
        yx_rx_hit swap = h->items[i]; h->items[i] = h->items[best]; h->items[best] = swap;
        i = best;
    }
    return top;
}

/* Next occurrence of an atom starting at or after `from`. */
static bool yx_rx_find(const uint8_t *data, size_t size, const yx_rx_atom *atom, size_t from, size_t *position)
{
    if (!atom->length) {
        if (from > size) return false;
        *position = from;
        return true;
    }
    if (from > size || size - from < atom->length) return false;
    const uint8_t *hit = data + from;
    size_t remaining = size - from;
    while (remaining >= atom->length) {
        const uint8_t *first = memchr(hit, atom->bytes[0], remaining - atom->length + 1);
        if (!first) return false;
        if (!memcmp(first, atom->bytes, atom->length)) { *position = (size_t)(first - data); return true; }
        remaining -= (size_t)(first - hit) + 1;
        hit = first + 1;
    }
    return false;
}

struct yx_rx_index;
static void yx_rx_index_free(struct yx_rx_index *index);

/* The successors of the PikeVM instruction at ip: targets[0, *count), of
 * which the first *unmarked are followed by the epsilon closure without a
 * visited mark (jump, repeat, zero-width assertion). False when a target
 * or the fall-through is outside the code. A split has at most 255 targets. */
static bool yx_pv_successors(const uint8_t *code, size_t length, size_t ip, const yx_pi_instr *instr,
                             size_t targets[256], size_t *count, size_t *unmarked)
{
    const uint8_t *c = code + ip;
    size_t next = ip + instr->size, n = 0;
    int64_t target;
    *unmarked = 0;
#define YX_PV_TARGET(relative) \
    do { \
        target = (int64_t)ip + (relative); \
        if (target < 0 || (uint64_t)target >= length) return false; \
        targets[n++] = (size_t)target; \
    } while (0)
    switch (instr->op) {
    case YX_PI_MATCH:
        break;
    case YX_PI_JUMP:
        YX_PV_TARGET(yx_rx_i32(c + 2));
        *unmarked = n;
        break;
    case YX_PI_REPEAT_GREEDY: case YX_PI_REPEAT_NON_GREEDY:
        YX_PV_TARGET(yx_rx_i32(c + 2));
        if (next >= length) return false;
        targets[n++] = next;
        *unmarked = n;
        break;
    case YX_PI_SPLIT_A: case YX_PI_SPLIT_B:
        YX_PV_TARGET(yx_rx_i32(c + 4));
        if (next >= length) return false;
        targets[n++] = next;
        break;
    case YX_PI_SPLIT_N:
        for (size_t k = 0; k < c[4]; ++k) YX_PV_TARGET(yx_rx_i32(c + 5 + 4 * k));
        break;
    case YX_PI_ANY_BYTE: case YX_PI_BYTE: case YX_PI_MASKED_BYTE: case YX_PI_NOCASE:
    case YX_PI_BITMAP: case YX_PI_RANGES:
        if (next >= length) return false;
        targets[n++] = next;
        break;
    default: /* the zero-width assertions */
        if (next >= length) return false;
        targets[n++] = next;
        *unmarked = n;
        break;
    }
#undef YX_PV_TARGET
    *count = n;
    return true;
}

static bool yx_pv_code_valid(const uint8_t *code, size_t length, const size_t *entries, size_t entry_count)
{
    /* state: 0 not reached, 1 the start of a reached instruction, 2 inside
     * one. colour (cycle search over the unmarked edges): 0 new, 1 on the
     * path, 2 done. */
    uint8_t *state = calloc(length ? length : 1, 1), *colour = calloc(length ? length : 1, 1);
    uint32_t *stack = malloc((length ? length : 1) * sizeof(*stack));
    uint8_t *edge = malloc(length ? length : 1);
    size_t used = 0, targets[256], count, unmarked;
    yx_pi_instr instr;
    bool valid = false;
    if (!state || !colour || !stack || !edge || length > UINT32_MAX) goto done;
    /* Every instruction reachable from the entries; each offset is pushed
     * once, when it becomes a start. */
    for (size_t i = 0; i < entry_count; ++i) {
        if (entries[i] >= length || state[entries[i]] == 2) goto done;
        if (!state[entries[i]]) { state[entries[i]] = 1; stack[used++] = (uint32_t)entries[i]; }
    }
    while (used) {
        size_t ip = stack[--used];
        if (!yx_pi_decode(code, length, ip, false, &instr) || !instr.size || instr.size > length - ip) goto done;
        for (size_t k = 1; k < instr.size; ++k) {
            if (state[ip + k]) goto done;
            state[ip + k] = 2;
        }
        if (!yx_pv_successors(code, length, ip, &instr, targets, &count, &unmarked)) goto done;
        for (size_t k = 0; k < count; ++k) {
            if (state[targets[k]] == 2) goto done;
            if (!state[targets[k]]) { state[targets[k]] = 1; stack[used++] = (uint32_t)targets[k]; }
        }
    }
    /* No cycle of unmarked edges: a depth-first search from every reached
     * instruction, with the path kept in stack and the next edge in edge. */
    for (size_t root = 0; root < length; ++root) {
        if (state[root] != 1 || colour[root]) continue;
        used = 0;
        stack[used] = (uint32_t)root; edge[used++] = 0; colour[root] = 1;
        while (used) {
            size_t ip = stack[used - 1];
            if (!yx_pi_decode(code, length, ip, false, &instr) ||
                !yx_pv_successors(code, length, ip, &instr, targets, &count, &unmarked)) goto done;
            if (edge[used - 1] < unmarked) {
                size_t to = targets[edge[used - 1]++];
                if (colour[to] == 1) goto done;
                if (!colour[to]) { colour[to] = 1; stack[used] = (uint32_t)to; edge[used++] = 0; }
            } else {
                colour[ip] = 2;
                --used;
            }
        }
    }
    valid = true;
done:
    free(state); free(colour); free(stack); free(edge);
    return valid;
}

static bool yx_fv_code_valid(const uint8_t *code, size_t length, const size_t *entries, size_t entry_count)
{
    for (size_t i = 0; i < entry_count; ++i) {
        size_t ip = entries[i];
        uint64_t exact = 0;
        for (;;) {
            yx_fi_instr instr;
            if (!yx_fi_decode(code, length, ip, &instr) || !instr.size) return false;
            if (instr.op == YX_FI_MATCH) break;
            if (instr.op == YX_FI_ALTERNATION) {
                size_t alt = 0;
                while (alt < instr.length) {
                    yx_fi_instr a;
                    if (!yx_fi_decode(instr.literal, instr.length, alt, &a) || !a.size ||
                        (a.op != YX_FI_LITERAL && a.op != YX_FI_MASKED)) return false;
                    alt += a.size;
                }
            } else if (instr.op == YX_FI_JUMP_EXACT || instr.op == YX_FI_JUMP_EXACT_NO_NEWLINE) {
                exact += instr.min;
                if (exact > YX_RX_FAST_EXACT_JUMP_LIMIT) return false;
            }
            ip += instr.size;
        }
    }
    return true;
}

bool yx_rx_archived_code_valid(const uint8_t *code, size_t code_length, const size_t *entries,
                               size_t entry_count, bool fast)
{
    if (!entry_count) return true;
    if (!code || !entries) return false;
    return fast ? yx_fv_code_valid(code, code_length, entries, entry_count)
                : yx_pv_code_valid(code, code_length, entries, entry_count);
}

void yx_rx_program_free(yx_rx_program *program)
{
    if (!program) return;
    yx_rx_index_free(program->index);
    for (size_t i = 0; i < program->sub_count; ++i) free(program->subs[i].atoms);
    free(program->guards);
    free(program->windows);
    free(program->code);
    memset(program, 0, sizeof(*program));
}

void yx_rx_match_list_free(yx_rx_match_list *list)
{
    free(list->items);
    memset(list, 0, sizeof(*list));
}

/* Teddy bucket assignment (Teddy::new): atoms with the same low nybbles in
 * their first mask_len bytes share a bucket; a new group takes bucket
 * BUCKETS - 1 - id % BUCKETS. */
void yx_rx_teddy_buckets(const yx_rx_atom *const *atoms, size_t count, size_t *buckets,
                         size_t *minimum_len)
{
    size_t shortest = SIZE_MAX, mask_len, bucket_count = count > 32 ? 16 : 8;
    for (size_t i = 0; i < count; ++i) if (atoms[i]->length < shortest) shortest = atoms[i]->length;
    mask_len = shortest < 4 ? shortest : 4;
    for (size_t i = 0; i < count; ++i) {
        size_t j = 0;
        for (; j < i; ++j) {
            size_t k = 0;
            for (; k < mask_len; ++k)
                if ((atoms[i]->bytes[k] & 15) != (atoms[j]->bytes[k] & 15)) break;
            if (k == mask_len) break;
        }
        buckets[i] = j < i ? buckets[j] : bucket_count - 1 - i % bucket_count;
    }
    /* SlimAVX2 and SSSE3 take 16-byte chunks for short haystacks, and Fat
     * uses 16-byte halves, so the minimum length is 16 + mask_len - 1. */
    *minimum_len = 16 + mask_len - 1;
}

/* Programs with many atoms are searched in one pass over the input: an
 * index maps the first two bytes of each atom (one byte for one-byte
 * atoms) to the atoms that start with them. */
#define YX_RX_INDEXED_ATOMS 16

/* yx_rx_scan_indexed jumps between bytes of the index's first-byte set with
 * xx_byteset_find when the set has fewer than YX_RX_SKIP_MEMBERS members.
 * Where YX_RX_SKIP_SHORT_RUN jumps in a row each advance fewer than
 * YX_RX_SKIP_SHORT bytes, the members are dense enough that testing each
 * byte against the set's bitmap is cheaper (about 1 ns a byte against about
 * 7 ns a call), and that walk takes over up to the next YX_RX_SKIP_BLOCK
 * boundary. Measured (tests/test_rx_index_skip.c --bench) the jump is never
 * slower than visiting every position, except for sets of 160 members on
 * random bytes (0.8x-0.9x), which the member limit keeps on the per-position
 * loop.
 * None of these choices changes a result, only speed. */
#define YX_RX_SKIP_MEMBERS 128
#define YX_RX_SKIP_SHORT 8
#define YX_RX_SKIP_SHORT_RUN 8
#define YX_RX_SKIP_BLOCK ((size_t)4096)

typedef struct { uint32_t key, atom; } yx_rx_key;

struct yx_rx_index {
    uint64_t present2[65536 / 64], present1[256 / 64];
    yx_rx_key *keys2, *keys1;
    size_t count2, count1;
    uint32_t *empty;
    size_t empty_count;
    const yx_rx_sub **subs;
    const yx_rx_atom **atoms;
    size_t atom_count;
    /* The first byte of every 1- and 2-byte key: without empty atoms, no
     * atom occurs at a position whose byte is not in the set. */
    xx_byteset first;
    bool skip; /* no empty atoms and fewer than YX_RX_SKIP_MEMBERS first bytes */
};

static int yx_rx_key_cmp(const void *x, const void *y)
{
    const yx_rx_key *a = x, *b = y;
    if (a->key != b->key) return a->key < b->key ? -1 : 1;
    return a->atom < b->atom ? -1 : a->atom > b->atom;
}

static void yx_rx_index_free(struct yx_rx_index *index)
{
    if (!index) return;
    free(index->keys2); free(index->keys1); free(index->empty);
    free(index->subs); free(index->atoms); free(index);
}

/* ------------------------------------------------------------------ */
/* Windows: offsets at which every PikeVM match reads a byte of a set. */

/* The forward or backward PikeVM program from an atom is a graph of the
 * thread states (ip, repeat count) that yx_pi_closure and yx_pi_run_impl
 * create: a consuming instruction reads one byte and keeps the count, the
 * epsilon moves follow splits, jumps and repeats as the closure does, and an
 * assertion is passed through (assertions, the executed set, the closure
 * marks, repeat priority and the scan limit only remove paths). Every match
 * the VM reports reads its input along one path from the start state to a
 * Match state, one byte per consuming state. When every such path passes a
 * consuming instruction X, the byte X reads lies at an offset between the
 * fewest and the most bytes that paths read before reaching X: an occurrence
 * whose input holds no byte of X's set at those offsets cannot match. */
enum { YX_RW_NODES = 2048, YX_RW_STARTS = 16, YX_RW_CANDIDATES = 8, YX_RW_KEPT = 4, YX_RW_WIDTH = 256,
       YX_RW_POPCOUNT = 128 };
#define YX_RW_FAR UINT32_MAX

typedef struct {
    uint32_t ip, count;
    uint32_t first, edges; /* successors: edges[first .. first + edges) */
    uint32_t low, high;    /* fewest / most bytes read before the state; YX_RW_FAR: unbounded */
    uint8_t kind;          /* 0 consuming, 1 epsilon, 2 match */
} yx_rw_node;

typedef struct {
    const uint8_t *code;
    size_t length;
    yx_rw_node *nodes;
    size_t node_count, node_capacity;
    uint32_t *edges;
    size_t edge_count, edge_capacity;
    uint32_t *slots; /* (ip, count) -> node index + 1, open addressing */
    size_t slot_count;
} yx_rw_graph;

/* A consuming instruction with the offsets of its states, and the estimated
 * share of random inputs that pass its window. */
typedef struct {
    yx_rx_window window;
    double pass;
    uint32_t ip;
} yx_rw_found;

/* Per instruction: the fewest and most bytes read before any of its states. */
typedef struct {
    uint32_t ip_plus_one, low, high;
} yx_rw_span;

/* The kind and successors of thread state (ip, count), as the VM follows
 * them; -1 for code the VM fails on. */
static int yx_rw_step(const uint8_t *code, size_t length, uint32_t ip, uint32_t count,
                      uint32_t *next_ip, uint32_t *next_count, size_t *n)
{
    yx_pi_instr instr;
    const uint8_t *c = code + ip;
    *n = 0;
    if (ip >= length || !yx_pi_decode(code, length, ip, false, &instr)) return -1;
    switch (instr.op) {
    case YX_PI_MATCH:
        return 2;
    case YX_PI_ANY_BYTE: case YX_PI_BYTE: case YX_PI_MASKED_BYTE: case YX_PI_NOCASE:
    case YX_PI_BITMAP: case YX_PI_RANGES:
        next_ip[0] = ip + (uint32_t)instr.size;
        next_count[0] = count;
        *n = 1;
        return 0;
    case YX_PI_SPLIT_A: case YX_PI_SPLIT_B:
        next_ip[0] = yx_pi_offset(ip, yx_rx_i32(c + 4));
        next_ip[1] = ip + (uint32_t)instr.size;
        next_count[0] = next_count[1] = count;
        *n = 2;
        return 1;
    case YX_PI_SPLIT_N:
        for (size_t k = 0; k < c[4]; ++k) {
            next_ip[k] = yx_pi_offset(ip, yx_rx_i32(c + 5 + 4 * k));
            next_count[k] = count;
        }
        *n = c[4];
        return 1;
    case YX_PI_JUMP:
        next_ip[0] = yx_pi_offset(ip, yx_rx_i32(c + 2));
        next_count[0] = count;
        *n = 1;
        return 1;
    case YX_PI_REPEAT_GREEDY: case YX_PI_REPEAT_NON_GREEDY: {
        uint32_t min = yx_rx_u32(c + 6), max = yx_rx_u32(c + 10), counted = count + 1;
        if (counted >= min) {
            next_ip[*n] = ip + (uint32_t)instr.size;
            next_count[(*n)++] = 0;
        }
        if (counted < max) {
            next_ip[*n] = yx_pi_offset(ip, yx_rx_i32(c + 2));
            next_count[(*n)++] = counted;
        }
        return 1;
    }
    case YX_PI_START: case YX_PI_END: case YX_PI_WORD_BOUNDARY: case YX_PI_WORD_BOUNDARY_NEG:
    case YX_PI_WORD_START: case YX_PI_WORD_END: case YX_PI_LINE_START: case YX_PI_LINE_END:
    case YX_PI_SEARCH_START_LF: case YX_PI_SEARCH_END_LF:
    case YX_PI_SEARCH_START_CRLF: case YX_PI_SEARCH_END_CRLF:
    case YX_PI_SEARCH_WORD_START: case YX_PI_SEARCH_WORD_END:
    case YX_PI_SEARCH_WORD_START_HALF: case YX_PI_SEARCH_WORD_END_HALF:
        next_ip[0] = ip + (uint32_t)instr.size;
        next_count[0] = count;
        *n = 1;
        return 1;
    default:
        return -1;
    }
}

/* The bytes a consuming instruction accepts, as yx_pi_run_impl tests them. */
static void yx_rw_set(const uint8_t *code, size_t length, uint32_t ip, uint8_t set[32])
{
    yx_pi_instr instr;
    const uint8_t *c = code + ip;
    memset(set, 0, 32);
    if (!yx_pi_decode(code, length, ip, false, &instr)) return;
    switch (instr.op) {
    case YX_PI_ANY_BYTE: memset(set, 255, 32); break;
    case YX_PI_BYTE: set[c[0] >> 3] |= (uint8_t)(1u << (c[0] & 7)); break;
    case YX_PI_MASKED_BYTE:
        for (unsigned b = 0; b < 256; ++b)
            if ((b & c[3]) == c[2]) set[b >> 3] |= (uint8_t)(1u << (b & 7));
        break;
    case YX_PI_NOCASE:
        for (unsigned b = 0; b < 256; ++b)
            if ((b >= 'A' && b <= 'Z' ? b + 32 : b) == c[2]) set[b >> 3] |= (uint8_t)(1u << (b & 7));
        break;
    case YX_PI_BITMAP: memcpy(set, c + 2, 32); break;
    case YX_PI_RANGES:
        for (size_t k = 0; k < c[2]; ++k)
            for (unsigned b = c[3 + 2 * k]; b <= c[4 + 2 * k]; ++b) set[b >> 3] |= (uint8_t)(1u << (b & 7));
        break;
    default: break;
    }
}

static size_t yx_rw_hash(const yx_rw_graph *g, uint32_t ip, uint32_t count)
{
    return (size_t)(((uint64_t)ip * 2654435761u) ^ ((uint64_t)count * 40503u)) & (g->slot_count - 1);
}

/* Room for one more state: the node array doubles up to YX_RW_NODES and the
 * slot table stays at most half full. */
static bool yx_rw_reserve(yx_rw_graph *g)
{
    if (g->node_count == g->node_capacity) {
        size_t capacity = g->node_capacity * 2;
        yx_rw_node *nodes;
        if (g->node_capacity >= YX_RW_NODES) return false;
        nodes = realloc(g->nodes, capacity * sizeof(*nodes));
        if (!nodes) return false;
        g->nodes = nodes;
        g->node_capacity = capacity;
    }
    if (2 * (g->node_count + 1) > g->slot_count) {
        size_t count = g->slot_count * 2;
        uint32_t *slots = calloc(count, sizeof(*slots));
        if (!slots) return false;
        free(g->slots);
        g->slots = slots;
        g->slot_count = count;
        for (size_t i = 0; i < g->node_count; ++i) {
            size_t slot = yx_rw_hash(g, g->nodes[i].ip, g->nodes[i].count);
            while (g->slots[slot]) slot = (slot + 1) & (g->slot_count - 1);
            g->slots[slot] = (uint32_t)i + 1;
        }
    }
    return true;
}

/* The states reachable from (start, 0). False for too many states, code the
 * VM fails on, or no memory. */
static bool yx_rw_build(yx_rw_graph *g, uint32_t start)
{
    uint32_t next_ip[256], next_count[256];
    g->node_capacity = 64;
    g->slot_count = 256;
    g->nodes = malloc(g->node_capacity * sizeof(*g->nodes));
    g->slots = calloc(g->slot_count, sizeof(*g->slots));
    if (!g->nodes || !g->slots) return false;
    memset(&g->nodes[0], 0, sizeof(g->nodes[0]));
    g->nodes[0].ip = start;
    g->node_count = 1;
    g->slots[yx_rw_hash(g, start, 0)] = 1;
    for (size_t i = 0; i < g->node_count; ++i) {
        size_t n;
        int kind = yx_rw_step(g->code, g->length, g->nodes[i].ip, g->nodes[i].count, next_ip, next_count, &n);
        if (kind < 0) return false;
        g->nodes[i].kind = (uint8_t)kind;
        g->nodes[i].first = (uint32_t)g->edge_count;
        g->nodes[i].edges = (uint32_t)n;
        if (g->edge_count + n > g->edge_capacity) {
            size_t capacity = (g->edge_count + n) * 2;
            uint32_t *edges = realloc(g->edges, capacity * sizeof(*edges));
            if (!edges) return false;
            g->edges = edges;
            g->edge_capacity = capacity;
        }
        for (size_t k = 0; k < n; ++k) {
            size_t slot = yx_rw_hash(g, next_ip[k], next_count[k]);
            if (next_ip[k] >= g->length) return false;
            while (g->slots[slot] && (g->nodes[g->slots[slot] - 1].ip != next_ip[k] ||
                                      g->nodes[g->slots[slot] - 1].count != next_count[k]))
                slot = (slot + 1) & (g->slot_count - 1);
            if (!g->slots[slot]) {
                if (!yx_rw_reserve(g)) return false;
                /* A rehash moved the free slot. */
                slot = yx_rw_hash(g, next_ip[k], next_count[k]);
                while (g->slots[slot]) slot = (slot + 1) & (g->slot_count - 1);
                memset(&g->nodes[g->node_count], 0, sizeof(g->nodes[0]));
                g->nodes[g->node_count].ip = next_ip[k];
                g->nodes[g->node_count].count = next_count[k];
                g->slots[slot] = (uint32_t)++g->node_count;
            }
            g->edges[g->edge_count++] = g->slots[slot] - 1;
        }
    }
    return true;
}

/* low: 0-1 BFS (consuming states add one byte). high: longest path in
 * topological order; states on or behind a cycle stay unbounded. */
static bool yx_rw_distances(yx_rw_graph *g)
{
    size_t n = g->node_count, capacity = g->edge_count + 2, head = 0, used = 0, done_count = 0;
    uint32_t *queue = malloc(capacity * sizeof(*queue)), *order = malloc(n * sizeof(*order));
    uint32_t *degree = calloc(n, sizeof(*degree));
    uint8_t *done = calloc(n, 1);
    bool ok = queue && order && degree && done;
    for (size_t i = 0; ok && i < n; ++i) {
        g->nodes[i].low = YX_RW_FAR;
        g->nodes[i].high = 0;
    }
    if (ok) {
        g->nodes[0].low = 0;
        queue[0] = 0;
        used = 1;
    }
    while (ok && used) {
        uint32_t u = queue[head];
        head = (head + 1) % capacity;
        --used;
        if (done[u]) continue;
        done[u] = 1;
        uint32_t weight = g->nodes[u].kind == 0 ? 1u : 0u, distance = g->nodes[u].low + weight;
        for (uint32_t k = 0; k < g->nodes[u].edges; ++k) {
            uint32_t v = g->edges[g->nodes[u].first + k];
            if (done[v] || g->nodes[v].low <= distance) continue;
            g->nodes[v].low = distance;
            if (used == capacity) { ok = false; break; }
            if (weight) queue[(head + used) % capacity] = v;
            else {
                head = (head + capacity - 1) % capacity;
                queue[head] = v;
            }
            ++used;
        }
    }
    for (size_t i = 0; ok && i < g->edge_count; ++i) ++degree[g->edges[i]];
    if (ok && !degree[0]) order[done_count++] = 0;
    for (size_t at = 0; ok && at < done_count; ++at) {
        uint32_t u = order[at];
        uint32_t reach = g->nodes[u].high + (g->nodes[u].kind == 0 ? 1u : 0u);
        for (uint32_t k = 0; k < g->nodes[u].edges; ++k) {
            uint32_t v = g->edges[g->nodes[u].first + k];
            if (reach > g->nodes[v].high) g->nodes[v].high = reach;
            if (!--degree[v]) order[done_count++] = v;
        }
    }
    /* Kahn's order omits the states on or behind a cycle. */
    if (ok) {
        memset(done, 0, n);
        for (size_t at = 0; at < done_count; ++at) done[order[at]] = 1;
        for (size_t i = 0; i < n; ++i) if (!done[i]) g->nodes[i].high = YX_RW_FAR;
    }
    free(queue); free(order); free(degree); free(done);
    return ok;
}

/* Whether every path from the start state to a Match state passes a state
 * of instruction ip. */
static bool yx_rw_dominates(const yx_rw_graph *g, uint32_t ip, uint32_t *stack, uint8_t *seen)
{
    size_t used = 0;
    if (g->nodes[0].ip == ip) return true;
    memset(seen, 0, g->node_count);
    stack[used++] = 0;
    seen[0] = 1;
    while (used) {
        const yx_rw_node *node = &g->nodes[stack[--used]];
        if (node->kind == 2) return false;
        for (uint32_t k = 0; k < node->edges; ++k) {
            uint32_t v = g->edges[node->first + k];
            if (seen[v] || g->nodes[v].ip == ip) continue;
            seen[v] = 1;
            stack[used++] = v;
        }
    }
    return true;
}

static unsigned yx_rw_popcount(const uint8_t set[32])
{
    unsigned count = 0;
    for (size_t i = 0; i < 32; ++i)
        for (unsigned bits = set[i]; bits; bits &= bits - 1) ++count;
    return count;
}

/* The windows of the program at start, most selective first: consuming
 * instructions whose states all have bounded offsets, that dominate Match.
 * Returns their number (0 when the graph cannot be built). */
static size_t yx_rw_windows_at(const uint8_t *code, size_t length, uint32_t start, bool backward,
                               yx_rw_found *found)
{
    yx_rw_graph g;
    yx_rw_found candidates[YX_RW_CANDIDATES];
    size_t candidate_count = 0, kept = 0, span_slots = 16;
    uint32_t *stack = NULL;
    uint8_t *seen = NULL;
    yx_rw_span *spans = NULL;
    memset(&g, 0, sizeof(g));
    g.code = code;
    g.length = length;
    if (!yx_rw_build(&g, start) || !yx_rw_distances(&g)) goto done;
    while (span_slots < 2 * g.node_count) span_slots *= 2;
    stack = malloc(g.node_count * sizeof(*stack));
    seen = malloc(g.node_count);
    spans = calloc(span_slots, sizeof(*spans));
    if (!stack || !seen || !spans) goto done;
    /* The offsets of every consuming instruction over all its states. */
    for (size_t i = 0; i < g.node_count; ++i) {
        const yx_rw_node *node = &g.nodes[i];
        size_t slot;
        if (node->kind != 0) continue;
        slot = (size_t)(((uint64_t)node->ip * 2654435761u) & (span_slots - 1));
        while (spans[slot].ip_plus_one && spans[slot].ip_plus_one != node->ip + 1)
            slot = (slot + 1) & (span_slots - 1);
        if (!spans[slot].ip_plus_one) {
            spans[slot].ip_plus_one = node->ip + 1;
            spans[slot].low = node->low;
            spans[slot].high = node->high;
            continue;
        }
        if (node->low < spans[slot].low) spans[slot].low = node->low;
        if (node->high > spans[slot].high) spans[slot].high = node->high;
    }
    for (size_t s = 0; s < span_slots; ++s) {
        uint32_t low = spans[s].low, high = spans[s].high;
        if (!spans[s].ip_plus_one || low == YX_RW_FAR || high == YX_RW_FAR || high - low >= YX_RW_WIDTH) continue;
        yx_rw_found trial;
        memset(&trial, 0, sizeof(trial));
        trial.ip = spans[s].ip_plus_one - 1;
        yx_rw_set(code, length, trial.ip, trial.window.set);
        unsigned members = yx_rw_popcount(trial.window.set);
        if (!members || members > YX_RW_POPCOUNT) continue;
        double miss = 1.0, keep = 1.0 - members / 256.0;
        for (uint32_t d = low; d <= high; ++d) miss *= keep;
        trial.pass = 1.0 - miss;
        if (trial.pass > 0.75) continue;
        trial.window.low = low;
        trial.window.high = high;
        trial.window.backward = backward;
        trial.window.byte = -1;
        if (members == 1)
            for (unsigned b = 0; b < 256; ++b)
                if (trial.window.set[b >> 3] >> (b & 7) & 1) trial.window.byte = (int16_t)b;
        size_t at = candidate_count < YX_RW_CANDIDATES ? candidate_count++ : YX_RW_CANDIDATES;
        if (at == YX_RW_CANDIDATES) {
            if (trial.pass >= candidates[YX_RW_CANDIDATES - 1].pass) continue;
            at = YX_RW_CANDIDATES - 1;
        }
        for (; at && candidates[at - 1].pass > trial.pass; --at) candidates[at] = candidates[at - 1];
        candidates[at] = trial;
    }
    for (size_t c = 0; c < candidate_count && kept < YX_RW_KEPT; ++c)
        if (yx_rw_dominates(&g, candidates[c].ip, stack, seen)) found[kept++] = candidates[c];
done:
    free(g.nodes); free(g.slots); free(g.edges); free(stack); free(seen); free(spans);
    return kept;
}

/* Rule sets repeat patterns, and every copy of a program gets the first
 * copy's code (yx_ser_regexp_program_copy), so yx_rw_windows_at, a function
 * of (code, start, direction), is memoised per thread for small programs. */
enum { YX_RW_MEMO_SLOTS = 64, YX_RW_MEMO_CODE = 4096 };
typedef struct {
    uint8_t *code;
    size_t length, count;
    uint64_t hash;
    uint32_t start;
    bool backward;
    yx_rw_found found[YX_RW_KEPT];
} yx_rw_memo_entry;
typedef struct {
    yx_rw_memo_entry slots[YX_RW_MEMO_SLOTS];
} yx_rw_memo;
static yx_thread_storage yx_rw_memo_storage = YX_THREAD_STORAGE_INIT;
static _Thread_local yx_rw_memo *yx_rw_memo_thread;

static void yx_rw_memo_destroy(void *opaque)
{
    yx_rw_memo *memo = opaque;
    for (size_t i = 0; i < YX_RW_MEMO_SLOTS; ++i) free(memo->slots[i].code);
}

static uint64_t yx_rw_code_hash(const uint8_t *code, size_t length)
{
    uint64_t hash = 1469598103934665603ull ^ length;
    for (size_t i = 0; i < length; ++i) hash = (hash ^ code[i]) * 1099511628211ull;
    return hash;
}

static size_t yx_rw_windows_memo(const uint8_t *code, size_t length, uint64_t hash, uint32_t start,
                                 bool backward, yx_rw_found *found)
{
    yx_rw_memo_entry *entry = NULL;
    size_t count;
    if (length <= YX_RW_MEMO_CODE && !yx_rw_memo_thread)
        yx_rw_memo_thread = yx_thread_storage_get(&yx_rw_memo_storage, sizeof(*yx_rw_memo_thread),
                                                  yx_rw_memo_destroy);
    if (length <= YX_RW_MEMO_CODE && yx_rw_memo_thread) {
        entry = &yx_rw_memo_thread->slots[(hash ^ ((uint64_t)start * 0x9E3779B97F4A7C15ull) ^ backward) %
                                          YX_RW_MEMO_SLOTS];
        if (entry->code && entry->hash == hash && entry->length == length && entry->start == start &&
            entry->backward == backward && !memcmp(entry->code, code, length)) {
            memcpy(found, entry->found, entry->count * sizeof(*found));
            return entry->count;
        }
    }
    count = yx_rw_windows_at(code, length, start, backward, found);
    if (entry) {
        uint8_t *copy = malloc(length ? length : 1);
        if (copy) {
            memcpy(copy, code, length);
            free(entry->code);
            entry->code = copy;
            entry->length = length;
            entry->hash = hash;
            entry->start = start;
            entry->backward = backward;
            entry->count = count;
            memcpy(entry->found, found, count * sizeof(*found));
        }
    }
    return count;
}

/* A forward window tells nothing about an occurrence when the atom's own
 * bytes, which lie at offsets backtrack.. of the forward input, already put
 * a byte of its set at one of its offsets. */
static bool yx_rw_useful(const yx_rx_window *window, const yx_rx_atom *atom)
{
    if (window->backward) return true;
    for (size_t i = 0; i < atom->length; ++i) {
        size_t d = atom->backtrack + i;
        uint8_t b = atom->bytes[i];
        if (d >= window->low && d <= window->high && (window->set[b >> 3] >> (b & 7) & 1)) return false;
    }
    return true;
}

/* 1 + the index of window in windows, added when new; 0 when the table is
 * full. */
static uint16_t yx_rw_add(yx_rx_window *windows, size_t *count, const yx_rx_window *window)
{
    for (size_t i = 0; i < *count; ++i)
        if (windows[i].low == window->low && windows[i].high == window->high &&
            windows[i].backward == window->backward && !memcmp(windows[i].set, window->set, 32))
            return (uint16_t)(i + 1);
    if (*count >= UINT16_MAX) return 0;
    windows[*count] = *window;
    return (uint16_t)++*count;
}

/* The atoms' windows: for the inexact atoms of PikeVM sub-patterns that read
 * the input byte by byte (FastVM code and wide input are left alone), the
 * most selective window of each direction that the atom's own bytes do not
 * already satisfy. Without memory there are none, which changes nothing but
 * speed. */
static void yx_rx_windows_build(yx_rx_program *program)
{
    uint32_t starts[YX_RW_STARTS];
    bool backward[YX_RW_STARTS];
    size_t counts[YX_RW_STARTS], used = 0, total = 0, window_count = 0;
    uint64_t hash;
    /* Atoms take their windows from these lists: at most STARTS * KEPT. */
    yx_rw_found found[YX_RW_STARTS][YX_RW_KEPT];
    yx_rx_window windows[YX_RW_STARTS * YX_RW_KEPT];
    free(program->windows);
    program->windows = NULL;
    program->window_count = 0;
    for (size_t s = 0; s < program->sub_count; ++s)
        for (size_t a = 0; a < program->subs[s].atom_count; ++a) {
            program->subs[s].atoms[a].fwd_window = program->subs[s].atoms[a].bck_window = 0;
            ++total;
        }
    if (!total || !program->code || program->code_length > UINT32_MAX) return;
    for (size_t s = 0; s < program->sub_count; ++s) {
        if (program->subs[s].flags & (YX_RX_FAST | YX_RX_WIDE)) continue;
        for (size_t a = 0; a < program->subs[s].atom_count; ++a) {
            const yx_rx_atom *atom = &program->subs[s].atoms[a];
            for (int direction = 0; direction < 2 && !atom->exact; ++direction) {
                size_t ip = direction ? atom->bck : atom->fwd, k = 0;
                if (!(direction ? atom->has_bck : atom->has_fwd) || ip >= program->code_length) continue;
                while (k < used && (starts[k] != ip || backward[k] != (direction != 0))) ++k;
                if (k == used && used < YX_RW_STARTS) {
                    starts[used] = (uint32_t)ip;
                    backward[used++] = direction != 0;
                }
            }
        }
    }
    if (!used) return;
    hash = yx_rw_code_hash(program->code, program->code_length);
    for (size_t k = 0; k < used; ++k)
        counts[k] = yx_rw_windows_memo(program->code, program->code_length, hash, starts[k], backward[k], found[k]);
    for (size_t s = 0; s < program->sub_count; ++s) {
        if (program->subs[s].flags & (YX_RX_FAST | YX_RX_WIDE)) continue;
        for (size_t a = 0; a < program->subs[s].atom_count; ++a) {
            yx_rx_atom *atom = &program->subs[s].atoms[a];
            for (int direction = 0; direction < 2 && !atom->exact; ++direction) {
                size_t ip = direction ? atom->bck : atom->fwd, k = 0;
                uint16_t chosen = 0;
                if (!(direction ? atom->has_bck : atom->has_fwd)) continue;
                while (k < used && (starts[k] != ip || backward[k] != (direction != 0))) ++k;
                for (size_t i = 0; k < used && i < counts[k] && !chosen; ++i)
                    if (yx_rw_useful(&found[k][i].window, atom))
                        chosen = yx_rw_add(windows, &window_count, &found[k][i].window);
                if (direction) atom->bck_window = chosen;
                else atom->fwd_window = chosen;
            }
        }
    }
    if (!window_count) return;
    program->windows = malloc(window_count * sizeof(*program->windows));
    if (program->windows) {
        memcpy(program->windows, windows, window_count * sizeof(*program->windows));
        program->window_count = window_count;
        return;
    }
    for (size_t s = 0; s < program->sub_count; ++s)
        for (size_t a = 0; a < program->subs[s].atom_count; ++a)
            program->subs[s].atoms[a].fwd_window = program->subs[s].atoms[a].bck_window = 0;
}

bool yx_rx_program_prepare(yx_rx_program *program)
{
    size_t total = 0;
    yx_rx_windows_build(program);
    for (size_t s = 0; s < program->sub_count; ++s) total += program->subs[s].atom_count;
    if (total <= YX_RX_INDEXED_ATOMS || total > UINT32_MAX) return true;
    struct yx_rx_index *index = calloc(1, sizeof(*index));
    if (!index) return false;
    xx_byteset_clear(&index->first);
    index->subs = calloc(total, sizeof(*index->subs));
    index->atoms = calloc(total, sizeof(*index->atoms));
    index->keys2 = calloc(total, sizeof(*index->keys2));
    index->keys1 = calloc(total, sizeof(*index->keys1));
    index->empty = calloc(total, sizeof(*index->empty));
    if (!index->subs || !index->atoms || !index->keys2 || !index->keys1 || !index->empty) {
        yx_rx_index_free(index); return false;
    }
    for (size_t s = 0; s < program->sub_count; ++s)
        for (size_t a = 0; a < program->subs[s].atom_count; ++a) {
            const yx_rx_atom *atom = &program->subs[s].atoms[a];
            uint32_t id = (uint32_t)index->atom_count++;
            index->subs[id] = &program->subs[s];
            index->atoms[id] = atom;
            if (!atom->length) index->empty[index->empty_count++] = id;
            else if (atom->length == 1) {
                index->keys1[index->count1++] = (yx_rx_key){atom->bytes[0], id};
                index->present1[atom->bytes[0] / 64] |= (uint64_t)1 << (atom->bytes[0] % 64);
                xx_byteset_add(&index->first, atom->bytes[0]);
            } else {
                uint32_t key = atom->bytes[0] | (uint32_t)atom->bytes[1] << 8;
                index->keys2[index->count2++] = (yx_rx_key){key, id};
                index->present2[key / 64] |= (uint64_t)1 << (key % 64);
                xx_byteset_add(&index->first, atom->bytes[0]);
            }
        }
    /* Prepared here, on the CPU that scans: compiled rules carry no index
     * (serialization rebuilds it through this function). */
    xx_byteset_prepare(&index->first);
    index->skip = !index->empty_count && xx_byteset_count(&index->first) < YX_RX_SKIP_MEMBERS;
    qsort(index->keys2, index->count2, sizeof(*index->keys2), yx_rx_key_cmp);
    qsort(index->keys1, index->count1, sizeof(*index->keys1), yx_rx_key_cmp);
    program->index = index;
    return true;
}

bool yx_rx_program_set_index_skip(yx_rx_program *program, bool enable)
{
    struct yx_rx_index *index = program ? program->index : NULL;
    bool previous;
    if (!index) return false;
    previous = index->skip;
    index->skip = enable && !index->empty_count;
    return previous;
}

static size_t yx_rx_lower_bound(const yx_rx_key *keys, size_t count, uint32_t key)
{
    size_t low = 0, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (keys[middle].key < key) low = middle + 1; else high = middle;
    }
    return low;
}

/* yx_rx_guard: a forward match reads at most YX_RX_SCAN_LIMIT - 1 bytes
 * from at, so its stop byte or literal lies before at + YX_RX_SCAN_LIMIT - 1.
 * False when no forward match can exist.
 *
 * span (may be NULL) holds input this guard's run already covered. Bytes in
 * [span->from, span->end) are run bytes, so a start inside the span follows
 * the run on from span->end instead of from the start: occurrences inside one
 * long run (path segments, say) then cost the run once, not once each. */
static bool yx_rx_guard_pass(const yx_rx_guard *guard, const uint8_t *data, size_t size, size_t at,
                             yx_rx_run_span *span)
{
    size_t limit = size - at < YX_RX_SCAN_LIMIT - 1 ? size : at + YX_RX_SCAN_LIMIT - 1, end = at;
    bool inside = span && span->from <= at && at <= span->end;
    bool pass = false;
    if (inside) end = span->end;
    if (!guard->literal_length) {
        if (end > limit) end = limit;
        while (end < limit && (guard->run[data[end] >> 3] >> (data[end] & 7) & 1)) ++end;
        pass = end < limit && (guard->stop[data[end] >> 3] >> (data[end] & 7) & 1);
    } else {
        /* A literal that ends inside the window and starts where the run has
         * not ended yet (the run is only followed up to each start). */
        size_t n = guard->literal_length;
        if (limit - at < n) return false;
        const uint8_t *p = data + at, *last = data + (limit - n);
        while (p <= last && (p = memchr(p, guard->literal[0], (size_t)(last - p) + 1)) != NULL) {
            size_t start = (size_t)(p - data);
            while (end < start && (guard->run[data[end] >> 3] >> (data[end] & 7) & 1)) ++end;
            if (end < start) break;
            if (!memcmp(p + 1, guard->literal + 1, n - 1)) { pass = true; break; }
            ++p;
        }
    }
    /* [at, end) holds run bytes only; it extends a span that contains at. */
    if (span) {
        if (!inside) { span->from = at; span->end = end; }
        else if (end > span->end) span->end = end;
    }
    return pass;
}

/* Whether the input holds a byte of the window's set at one of its offsets
 * from atom position at. The VM reads at most YX_RX_SCAN_LIMIT bytes in
 * either direction and never past the input, so later offsets are absent. */
static bool yx_rx_window_pass(const yx_rx_window *w, const uint8_t *data, size_t size, size_t at)
{
    size_t available = w->backward ? at : size - at, last, first, count;
    if (available > YX_RX_SCAN_LIMIT) available = YX_RX_SCAN_LIMIT;
    if (w->low >= available) return false;
    last = w->high < available ? w->high : available - 1;
    /* Offsets low..last are one contiguous range of the input. */
    first = w->backward ? at - 1 - last : at + w->low;
    count = last - w->low + 1;
    if (w->byte >= 0) return memchr(data + first, w->byte, count) != NULL;
    for (size_t i = 0; i < count; ++i) {
        uint8_t b = data[first + i];
        if (w->set[b >> 3] >> (b & 7) & 1) return true;
    }
    return false;
}

/* False when an atom window rules out a match from atom position at. */
static bool yx_rx_windows_pass(const yx_rx_program *program, const yx_rx_atom *atom,
                               const uint8_t *data, size_t size, size_t at)
{
    if (atom->bck_window && atom->bck_window <= program->window_count &&
        !yx_rx_window_pass(&program->windows[atom->bck_window - 1], data, size, at)) return false;
    if (atom->fwd_window && atom->fwd_window <= program->window_count &&
        !yx_rx_window_pass(&program->windows[atom->fwd_window - 1], data, size, at)) return false;
    return true;
}

/* Verifies one atom occurrence. */
static bool yx_rx_process(yx_rx_vms *vms, const yx_rx_program *program, const yx_rx_hit *hit,
                          const uint8_t *data, size_t size, yx_rx_match_list *list)
{
    if (hit->position < hit->atom->backtrack) return true;
    size_t atom_pos = hit->position - hit->atom->backtrack;
    if (hit->atom->exact) {
        size_t end = atom_pos + hit->atom->length;
        if (!yx_rx_full_word(data, size, atom_pos, end, hit->sub->flags)) return true;
        if (list->each) return list->each(list->each_context, hit->sub->flags, atom_pos, end);
        return yx_rx_add(list, atom_pos, end, (hit->sub->flags & YX_RX_GREEDY) != 0);
    }
    if (hit->atom->guard) {
        const yx_rx_guard *guard = hit->atom->guard;
        yx_rx_run_span *span = NULL;
        if (!vms->spans && !vms->spans_failed && program->guard_count) {
            vms->spans = calloc(program->guard_count, sizeof(*vms->spans));
            vms->spans_failed = !vms->spans;
        }
        if (vms->spans && guard >= program->guards && guard < program->guards + program->guard_count)
            span = &vms->spans[guard - program->guards];
        if (!yx_rx_guard_pass(guard, data, size, atom_pos, span)) return true;
    }
    if ((hit->atom->fwd_window || hit->atom->bck_window) &&
        !yx_rx_windows_pass(program, hit->atom, data, size, atom_pos)) return true;
    return yx_rx_verify_regexp(vms, program, hit->sub, hit->atom, data, size, atom_pos, list);
}

static yx_rx_hit yx_rx_make_hit(const yx_rx_sub *sub, const yx_rx_atom *atom, size_t index, size_t position,
                                const yx_rx_order *order, bool teddy)
{
    return (yx_rx_hit){position + atom->length, atom->length, teddy ? order->ids[index] : index, position,
                       teddy ? order->buckets[index] : 0, teddy, sub, atom};
}

/* Pushes the hits of the 1- and 2-byte keys at position p < size, as the
 * per-position loop of yx_rx_scan_indexed does. */
YX_RX_INLINE bool yx_rx_index_push(const struct yx_rx_index *index, yx_rx_heap *heap, const uint8_t *data, size_t size,
                                   size_t p, const yx_rx_order *order, bool teddy)
{
    bool ok = true;
    if (index->present1[data[p] / 64] >> (data[p] % 64) & 1)
        for (size_t k = yx_rx_lower_bound(index->keys1, index->count1, data[p]);
             ok && k < index->count1 && index->keys1[k].key == data[p]; ++k) {
            uint32_t id = index->keys1[k].atom;
            ok = yx_rx_heap_push(heap, yx_rx_make_hit(index->subs[id], index->atoms[id], id, p, order, teddy));
        }
    if (p + 1 < size) {
        uint32_t key = data[p] | (uint32_t)data[p + 1] << 8;
        if (index->present2[key / 64] >> (key % 64) & 1)
            for (size_t k = yx_rx_lower_bound(index->keys2, index->count2, key);
                 ok && k < index->count2 && index->keys2[k].key == key; ++k) {
                uint32_t id = index->keys2[k].atom;
                const yx_rx_atom *atom = index->atoms[id];
                if (size - p < atom->length || memcmp(data + p + 2, atom->bytes + 2, atom->length - 2u)) continue;
                ok = yx_rx_heap_push(heap, yx_rx_make_hit(index->subs[id], atom, id, p, order, teddy));
            }
    }
    return ok;
}

/* yx_rx_scan_indexed's per-position loop, visiting only the positions that
 * can hold an atom: without empty atoms, those whose byte is in index->first.
 *
 * Exactness: the loop makes the same yx_rx_process calls, in the same order,
 * and the same deadline polls, at the same points between them, as the
 * per-position loop. At a position j whose byte is not in the set that loop
 * pushes nothing (no 1-byte key and no 2-byte key starts with data[j]); it
 * polls the deadline when j is a nonzero multiple of 4096 and then pops the
 * hits that end (Teddy: start) at or before j. Over skipped positions p..q-1
 * nothing is pushed, so its pops there take, in heap order, the hits whose
 * end (start) is below each position in turn, with the polls in between.
 * The loop below does exactly that before handling q: it pops the hits below
 * each multiple of 4096 up to q, polls there, and pops the hits below q.
 * Every hit pushed at q or later ends after q (starts at q or later), so it
 * comes after all of them in either loop. Position q is then handled as the
 * per-position loop handles it (a position whose byte is not in the set,
 * which the dense walk can stop at, pushes nothing). At position size that
 * loop pushes nothing and pops every hit left (all end at or before size),
 * which the final drain does. ok and limit_reached end both loops after the
 * same call.
 *
 * Speed: after YX_RX_SKIP_SHORT_RUN jumps in a row that each advance fewer
 * than YX_RX_SKIP_SHORT bytes, the bytes up to the next YX_RX_SKIP_BLOCK
 * boundary are tested one by one against the set's bitmap, which costs less
 * there than a call per member. */
static bool yx_rx_scan_indexed_skip(const yx_rx_program *program, yx_rx_vms *vms, const uint8_t *data,
                                    size_t size, yx_scan_deadline *deadline, yx_rx_match_list *list,
                                    const yx_rx_order *order, bool teddy)
{
    const struct yx_rx_index *index = program->index;
    const uint64_t *member = index->first.bits;
    yx_rx_heap heap = {0};
    bool ok = true;
    size_t p = 0, next_poll = 4096, dense_end = 0;
    unsigned short_jumps = 0;
    while (ok && !list->limit_reached) {
        size_t q; /* the next position that can hold an atom, or size */
        if (p >= size) {
            q = size;
        } else if (p < dense_end) {
            size_t stop = dense_end < size ? dense_end : size;
            for (q = p; q < stop && !(member[data[q] >> 6] >> (data[q] & 63) & 1); ++q) {
            }
        } else {
            q = xx_byteset_find(&index->first, data, size, p);
            if (q - p >= YX_RX_SKIP_SHORT) short_jumps = 0;
            else if (++short_jumps >= YX_RX_SKIP_SHORT_RUN) {
                short_jumps = 0;
                dense_end = (q / YX_RX_SKIP_BLOCK + 1) * YX_RX_SKIP_BLOCK;
            }
        }
        /* The per-position loop's work at p..q-1 and its poll at q. */
        if (heap.used || next_poll <= q) {
            for (;;) {
                size_t until = next_poll < q ? next_poll : q;
                while (ok && heap.used && !list->limit_reached &&
                       (teddy ? heap.items[0].position < until : heap.items[0].end < until)) {
                    yx_rx_hit hit = yx_rx_heap_pop(&heap);
                    ok = yx_rx_process(vms, program, &hit, data, size, list);
                }
                if (!ok || list->limit_reached || next_poll > q) break;
                if (yx_scan_deadline_poll(deadline)) ok = false;
                next_poll += 4096;
            }
            if (!ok || list->limit_reached) break;
        }
        if (q >= size) break;
        ok = yx_rx_index_push(index, &heap, data, size, q, order, teddy);
        /* Later hits start after q, so they end after q as well. */
        while (ok && heap.used && !list->limit_reached &&
               (teddy ? heap.items[0].position <= q : heap.items[0].end <= q)) {
            yx_rx_hit hit = yx_rx_heap_pop(&heap);
            ok = yx_rx_process(vms, program, &hit, data, size, list);
        }
        p = q + 1;
    }
    while (ok && heap.used && !list->limit_reached) {
        yx_rx_hit hit = yx_rx_heap_pop(&heap);
        ok = yx_rx_process(vms, program, &hit, data, size, list);
    }
    free(heap.items);
    return ok;
}

/* One pass over the input with the atom index. A hit is verified once no
 * later start offset can produce a hit ordered before it. */
static bool yx_rx_scan_indexed(const yx_rx_program *program, yx_rx_vms *vms, const uint8_t *data, size_t size,
                               yx_scan_deadline *deadline, yx_rx_match_list *list, const yx_rx_order *order,
                               bool teddy)
{
    const struct yx_rx_index *index = program->index;
    yx_rx_heap heap = {0};
    bool ok = true;
    if (index->skip) return yx_rx_scan_indexed_skip(program, vms, data, size, deadline, list, order, teddy);
    for (size_t p = 0; ok && p <= size && !list->limit_reached; ++p) {
        if (!(p & 4095) && p && yx_scan_deadline_poll(deadline)) { ok = false; break; }
        for (size_t i = 0; ok && i < index->empty_count; ++i) {
            uint32_t id = index->empty[i];
            ok = yx_rx_heap_push(&heap, yx_rx_make_hit(index->subs[id], index->atoms[id], id, p, order, teddy));
        }
        if (p < size && (index->present1[data[p] / 64] >> (data[p] % 64) & 1))
            for (size_t k = yx_rx_lower_bound(index->keys1, index->count1, data[p]);
                 ok && k < index->count1 && index->keys1[k].key == data[p]; ++k) {
                uint32_t id = index->keys1[k].atom;
                ok = yx_rx_heap_push(&heap, yx_rx_make_hit(index->subs[id], index->atoms[id], id, p, order, teddy));
            }
        if (p + 1 < size) {
            uint32_t key = data[p] | (uint32_t)data[p + 1] << 8;
            if (index->present2[key / 64] >> (key % 64) & 1)
                for (size_t k = yx_rx_lower_bound(index->keys2, index->count2, key);
                     ok && k < index->count2 && index->keys2[k].key == key; ++k) {
                    uint32_t id = index->keys2[k].atom;
                    const yx_rx_atom *atom = index->atoms[id];
                    if (size - p < atom->length || memcmp(data + p + 2, atom->bytes + 2, atom->length - 2u)) continue;
                    ok = yx_rx_heap_push(&heap, yx_rx_make_hit(index->subs[id], atom, id, p, order, teddy));
                }
        }
        /* Later hits start after p, so they end after p as well. */
        while (ok && heap.used && !list->limit_reached &&
               (teddy ? heap.items[0].position <= p : heap.items[0].end <= p)) {
            yx_rx_hit hit = yx_rx_heap_pop(&heap);
            ok = yx_rx_process(vms, program, &hit, data, size, list);
        }
    }
    while (ok && heap.used && !list->limit_reached) {
        yx_rx_hit hit = yx_rx_heap_pop(&heap);
        ok = yx_rx_process(vms, program, &hit, data, size, list);
    }
    free(heap.items);
    return ok;
}

bool yx_rx_scan_ordered(const yx_rx_program *program, const uint8_t *data, size_t size,
                        yx_scan_deadline *deadline, yx_rx_match_list *list,
                        const yx_rx_order *order)
{
    yx_rx_vms vms;
    yx_rx_heap heap = {0};
    bool ok = true, teddy = order && order->teddy && size >= order->minimum_len;
    size_t index = 0, steps = 0;
    memset(&vms, 0, sizeof(vms));
    vms.pike.code = vms.fast.code = program->code;
    vms.pike.code_length = vms.fast.code_length = program->code_length;
    if (program->index) {
        ok = yx_rx_scan_indexed(program, &vms, data, size, deadline, list, order, teddy);
        goto done;
    }
    for (size_t s = 0; ok && s < program->sub_count; ++s) {
        const yx_rx_sub *sub = &program->subs[s];
        for (size_t a = 0; ok && a < sub->atom_count; ++a, ++index) {
            const yx_rx_atom *atom = &sub->atoms[a];
            size_t position;
            if (yx_rx_find(data, size, atom, 0, &position))
                ok = yx_rx_heap_push(&heap, yx_rx_make_hit(sub, atom, index, position, order, teddy));
        }
    }
    while (ok && heap.used && !list->limit_reached) {
        yx_rx_hit hit = yx_rx_heap_pop(&heap);
        size_t position;
        if (!(++steps & 1023) && yx_scan_deadline_poll(deadline)) { ok = false; break; }
        ok = yx_rx_process(&vms, program, &hit, data, size, list);
        if (ok && yx_rx_find(data, size, hit.atom, hit.position + 1, &position)) {
            hit.position = position;
            hit.end = position + hit.atom->length;
            ok = yx_rx_heap_push(&heap, hit);
        }
    }
done:
    free(heap.items);
    yx_pikevm_free(&vms.pike);
    free(vms.fast.positions.items); free(vms.fast.positions.seen);
    free(vms.fast.next.items); free(vms.fast.next.seen);
    free(vms.spans);
    return ok;
}

bool yx_rx_scan(const yx_rx_program *program, const uint8_t *data, size_t size,
                yx_scan_deadline *deadline, yx_rx_match_list *list)
{
    return yx_rx_scan_ordered(program, data, size, deadline, list, NULL);
}

/* ------------------------------------------------------------------ */
/* Literal sub-patterns of an alternation of literals.                 */

void yx_rx_literals_free(yx_rx_literals *set)
{
    if (!set) return;
    for (size_t i = 0; i < set->count; ++i) {
        free(set->items[i].sub.atoms);
        free(set->items[i].bytes);
    }
    free(set->items);
    free(set);
}

/* verify_literal at start; *end is the end of the match. */
static bool yx_rx_literal_at(const yx_rx_literal *literal, const uint8_t *data, size_t size,
                             size_t start, size_t *end)
{
    if (start > size || literal->length > size - start) return false;
    *end = start + literal->length;
    if (!yx_rx_full_word(data, size, start, *end, literal->sub.flags)) return false;
    if (!(literal->sub.flags & YX_RX_NOCASE)) return memcmp(data + start, literal->bytes, literal->length) == 0;
    for (size_t i = 0; i < literal->length; ++i) {
        uint8_t a = data[start + i], b = literal->bytes[i];
        if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
        if (a != b) return false;
    }
    return true;
}

/* handle_atom_match for a Literal sub-pattern: an exact atom's occurrence
 * is the match; another atom's is verified against the whole literal. */
static bool yx_rx_literal_process(const yx_rx_hit *hit, const uint8_t *data, size_t size,
                                  yx_rx_match_list *list)
{
    const yx_rx_literal *literal = (const yx_rx_literal *)hit->sub;
    size_t start, end;
    if (hit->position < hit->atom->backtrack) return true;
    start = hit->position - hit->atom->backtrack;
    if (hit->atom->exact) {
        end = start + hit->atom->length;
        if (!yx_rx_full_word(data, size, start, end, literal->sub.flags)) return true;
    } else if (!yx_rx_literal_at(literal, data, size, start, &end)) return true;
    return yx_rx_add(list, start, end, false);
}

/* The hit of an atom occurrence. Atoms of one pattern have consecutive ids,
 * and two of them found at one offset share a Teddy bucket (the same first
 * bytes): the atom's index orders them as its id does. The anchored order
 * (the match's start, then the sub-pattern) uses the automaton's keys. */
static yx_rx_hit yx_rx_literal_hit(const yx_rx_sub *sub, const yx_rx_atom *atom, size_t index,
                                   size_t position, int order)
{
    if (order == YX_RX_LITERALS_ANCHORED)
        return (yx_rx_hit){position >= atom->backtrack ? position - atom->backtrack : 0, 0, index,
                           position, 0, false, sub, atom};
    return (yx_rx_hit){position + atom->length, atom->length, index, position, 0,
                       order == YX_RX_LITERALS_TEDDY, sub, atom};
}

/* The next of the listed offsets, from *cursor on, where the literal
 * matches (verify_literal); *cursor is left after it. */
static bool yx_rx_literal_next(const yx_rx_literal *literal, const uint8_t *data, size_t size,
                               const yx_rx_candidate *starts, size_t start_count, size_t *cursor,
                               size_t *start)
{
    while (*cursor < start_count) {
        size_t end;
        *start = starts[(*cursor)++].position;
        if (yx_rx_literal_at(literal, data, size, *start, &end)) return true;
    }
    return false;
}

/* yx_rx_scan_literals over listed offsets. A literal that matches at an
 * offset has one occurrence of its atom there, backtrack bytes on, and
 * without nocase one atom: the hits and their order are those of the atom
 * search. */
static bool yx_rx_scan_literal_starts(const yx_rx_literals *set, const uint8_t *data, size_t size,
                                      yx_scan_deadline *deadline, yx_rx_match_list *list, int order,
                                      const yx_rx_candidate *starts, size_t start_count)
{
    yx_rx_heap heap = {0};
    size_t *cursors = calloc(set->count ? set->count : 1, sizeof(*cursors));
    bool ok = cursors != NULL;
    size_t index = 0, steps = 0, start;
    for (size_t s = 0; ok && s < set->count; ++s) {
        const yx_rx_literal *literal = &set->items[s];
        if (literal->sub.atom_count &&
            yx_rx_literal_next(literal, data, size, starts, start_count, &cursors[s], &start))
            ok = yx_rx_heap_push(&heap, yx_rx_literal_hit(&literal->sub, literal->sub.atoms, index,
                                                          start + literal->sub.atoms->backtrack, order));
        index += literal->sub.atom_count;
    }
    while (ok && heap.used && !list->limit_reached) {
        yx_rx_hit hit = yx_rx_heap_pop(&heap);
        const yx_rx_literal *literal = (const yx_rx_literal *)hit.sub;
        if (!(++steps & 1023) && yx_scan_deadline_poll(deadline)) { ok = false; break; }
        start = hit.position - hit.atom->backtrack;
        ok = yx_rx_add(list, start, start + literal->length, false);
        if (ok && yx_rx_literal_next(literal, data, size, starts, start_count,
                                     &cursors[literal - set->items], &start))
            ok = yx_rx_heap_push(&heap, yx_rx_literal_hit(hit.sub, hit.atom, hit.index,
                                                          start + hit.atom->backtrack, order));
    }
    free(heap.items);
    free(cursors);
    return ok;
}

bool yx_rx_scan_literals(const yx_rx_literals *set, const uint8_t *data, size_t size,
                         yx_scan_deadline *deadline, yx_rx_match_list *list, int order,
                         const yx_rx_candidate *starts, size_t start_count)
{
    yx_rx_heap heap = {0};
    bool ok = true;
    size_t index = 0, steps = 0;
    if (starts) return yx_rx_scan_literal_starts(set, data, size, deadline, list, order, starts, start_count);
    for (size_t s = 0; ok && s < set->count; ++s) {
        const yx_rx_sub *sub = &set->items[s].sub;
        for (size_t a = 0; ok && a < sub->atom_count; ++a, ++index) {
            const yx_rx_atom *atom = &sub->atoms[a];
            size_t position;
            if (atom->length && yx_rx_find(data, size, atom, 0, &position))
                ok = yx_rx_heap_push(&heap, yx_rx_literal_hit(sub, atom, index, position, order));
        }
    }
    while (ok && heap.used && !list->limit_reached) {
        yx_rx_hit hit = yx_rx_heap_pop(&heap);
        size_t position;
        if (!(++steps & 1023) && yx_scan_deadline_poll(deadline)) { ok = false; break; }
        ok = yx_rx_literal_process(&hit, data, size, list);
        if (ok && yx_rx_find(data, size, hit.atom, hit.position + 1, &position))
            ok = yx_rx_heap_push(&heap, yx_rx_literal_hit(hit.sub, hit.atom, hit.index, position, order));
    }
    free(heap.items);
    return ok;
}

/* The shared scanner supplies occurrences; ordering and verification stay
 * identical to the per-program scan, including cap-dependent tie semantics. */

/* The sub-pattern and atom of a flattened atom index, or NULL. */
static const yx_rx_atom *yx_rx_flat_atom(const yx_rx_program *program, size_t index,
                                         const yx_rx_sub **sub)
{
    size_t sub_index = 0;
    while (sub_index < program->sub_count && index >= program->subs[sub_index].atom_count)
        index -= program->subs[sub_index++].atom_count;
    if (sub_index >= program->sub_count) return NULL;
    *sub = &program->subs[sub_index];
    return &program->subs[sub_index].atoms[index];
}

/* yx_rx_process's window test, ahead of the candidate list: an occurrence it
 * would skip there cannot add a match, so it need not be retained. */
bool yx_rx_atom_possible(const yx_rx_program *program, size_t index, const uint8_t *data,
                         size_t size, size_t position)
{
    const yx_rx_sub *sub;
    const yx_rx_atom *atom;
    if (!program || !program->window_count) return true;
    atom = yx_rx_flat_atom(program, index, &sub);
    if (!atom || atom->exact || (!atom->fwd_window && !atom->bck_window) ||
        position < atom->backtrack || position > size) return true;
    return yx_rx_windows_pass(program, atom, data, size, position - atom->backtrack);
}

typedef struct {
    const yx_rx_program *program;
    const yx_rx_order *order;
    bool teddy;
} yx_rx_candidate_order;

/* yx_rx_hit_before on the hits yx_rx_make_hit builds from two validated
 * candidates. Atom ids are unique per atom, so two candidates compare equal
 * only when they are the same occurrence; every sorting algorithm therefore
 * yields the one order in which hits are verified. */
static bool yx_rx_candidate_before(const yx_rx_candidate_order *o, const yx_rx_candidate *a,
                                   const yx_rx_candidate *b)
{
    if (o->teddy) {
        if (a->position != b->position) return a->position < b->position;
        if (o->order->buckets[a->index] != o->order->buckets[b->index])
            return o->order->buckets[a->index] < o->order->buckets[b->index];
        return o->order->ids[a->index] < o->order->ids[b->index];
    }
    const yx_rx_sub *sub;
    size_t la = yx_rx_flat_atom(o->program, a->index, &sub)->length;
    size_t lb = yx_rx_flat_atom(o->program, b->index, &sub)->length;
    if (a->position + la != b->position + lb) return a->position + la < b->position + lb;
    if (la != lb) return la > lb;
    return a->index < b->index;
}

/* Bottom-up merge sort for inputs far from sorted. False on allocation
 * failure. */
static bool yx_rx_merge_candidates(const yx_rx_candidate_order *o, yx_rx_candidate *items, size_t count)
{
    if (count > SIZE_MAX / sizeof(*items)) return false;
    yx_rx_candidate *buffer = malloc(count * sizeof(*items)), *from = items, *to = buffer;
    if (!buffer) return false;
    for (size_t width = 1; width < count; width = width > SIZE_MAX / 2 ? count : width * 2) {
        for (size_t low = 0; low < count; low += 2 * width) {
            size_t middle = count - low > width ? low + width : count;
            size_t high = count - middle > width ? middle + width : count;
            size_t i = low, j = middle, k = low;
            while (i < middle && j < high)
                to[k++] = yx_rx_candidate_before(o, &from[j], &from[i]) ? from[j++] : from[i++];
            while (i < middle) to[k++] = from[i++];
            while (j < high) to[k++] = from[j++];
            if (high == count) break;
        }
        yx_rx_candidate *swap = from; from = to; to = swap;
    }
    if (from != items) memcpy(items, from, count * sizeof(*items));
    free(buffer);
    return true;
}

/* The shared pass reports occurrences by start offset, so the verification
 * order is almost sorted already (Aho-Corasick order moves an occurrence only
 * past shorter atoms that end later). Insertion sort is linear then; a list
 * far from sorted falls back to the merge sort. */
static bool yx_rx_sort_candidates(const yx_rx_candidate_order *o, yx_rx_candidate *items, size_t count)
{
    size_t moves = 0, budget = count < SIZE_MAX / 16 ? 8 * count + 1024 : SIZE_MAX;
    for (size_t i = 1; i < count; ++i) {
        if (!yx_rx_candidate_before(o, &items[i], &items[i - 1])) continue;
        yx_rx_candidate item = items[i];
        size_t j = i;
        do {
            items[j] = items[j - 1];
            --j;
            ++moves;
        } while (j && yx_rx_candidate_before(o, &item, &items[j - 1]));
        items[j] = item;
        if (moves > budget) return yx_rx_merge_candidates(o, items, count);
    }
    return true;
}

bool yx_rx_scan_from_candidates(const yx_rx_program *program, const uint8_t *data, size_t size,
    yx_scan_deadline *deadline, yx_rx_match_list *list, const yx_rx_order *order,
    yx_rx_candidate *candidates, size_t count)
{
    yx_rx_vms vms;
    bool ok = true, teddy = order && order->teddy && size >= order->minimum_len;
    yx_rx_candidate_order sort_order = {program, order, teddy};
    /* Most programs have no occurrence in a given input. */
    if (!count) return !yx_scan_deadline_reached(deadline);
    memset(&vms, 0, sizeof(vms));
    vms.pike.code = vms.fast.code = program->code;
    vms.pike.code_length = vms.fast.code_length = program->code_length;
    for (size_t i = 0; i < count; ++i) {
        const yx_rx_sub *sub;
        const yx_rx_atom *atom = yx_rx_flat_atom(program, candidates[i].index, &sub);
        if (!atom || candidates[i].position > size || atom->length > size - candidates[i].position) {
            ok = false; goto done;
        }
    }
    if (count > 1 && !yx_rx_sort_candidates(&sort_order, candidates, count)) { ok = false; goto done; }
    for (size_t i = 0; ok && i < count && !list->limit_reached; ++i) {
        if (!(i & 1023) && yx_scan_deadline_reached(deadline)) { ok = false; break; }
        const yx_rx_sub *sub;
        const yx_rx_atom *atom = yx_rx_flat_atom(program, candidates[i].index, &sub);
        yx_rx_hit hit = yx_rx_make_hit(sub, atom, candidates[i].index, candidates[i].position, order, teddy);
        ok = yx_rx_process(&vms, program, &hit, data, size, list);
    }
done:
    yx_pikevm_free(&vms.pike);
    free(vms.fast.positions.items); free(vms.fast.positions.seen);
    free(vms.fast.next.items); free(vms.fast.next.seen);
    free(vms.spans);
    return ok && !yx_scan_deadline_reached(deadline);
}

/* ------------------------------------------------------------------ */
/* Owner prefilter over short atoms.                                   */

typedef struct { size_t owner; uint32_t tag; } yx_atom_entry;

struct yx_atom_set {
    xx_literal_set *finder;
    yx_atom_entry *entries;
    size_t count, capacity, owners;
};

yx_atom_set *yx_atom_set_new(void)
{
    yx_atom_set *set = calloc(1, sizeof(*set));
    if (!set) return NULL;
    set->finder = xx_literal_set_create();
    if (!set->finder) { free(set); return NULL; }
    return set;
}

void yx_atom_set_free(yx_atom_set *set)
{
    if (!set) return;
    xx_literal_set_free(set->finder);
    free(set->entries);
    free(set);
}

size_t yx_atom_set_owner_count(const yx_atom_set *set) { return set ? set->owners : 0; }

bool yx_atom_set_add_tagged(yx_atom_set *set, const uint8_t *bytes, size_t length,
                           size_t owner, uint32_t tag)
{
    if (!set || !bytes || !length || length > 8 || owner == SIZE_MAX) return false;
    if (set->count == set->capacity) {
        size_t next = set->capacity ? set->capacity * 2 : 64;
        if (next < set->capacity || next > SIZE_MAX / sizeof(*set->entries)) return false;
        yx_atom_entry *grown = realloc(set->entries, next * sizeof(*grown));
        if (!grown) return false;
        set->entries = grown; set->capacity = next;
    }
    if (!xx_literal_set_add(set->finder, bytes, length)) return false;
    set->entries[set->count++] = (yx_atom_entry){owner, tag};
    if (owner >= set->owners) set->owners = owner + 1;
    return true;
}

bool yx_atom_set_add(yx_atom_set *set, const uint8_t *bytes, size_t length, size_t owner)
{
    return yx_atom_set_add_tagged(set, bytes, length, owner, 0);
}

bool yx_atom_set_build(yx_atom_set *set)
{
    return set && xx_literal_set_finalize(set->finder);
}

typedef struct {
    const yx_atom_set *set;
    yx_scan_deadline *deadline;
    yx_atom_candidate_fn fn;
    void *ctx;
    bool *hit;
    size_t occurrences;
} yx_atom_scan_context;

static bool yx_atom_report(void *context, size_t index, size_t position)
{
    yx_atom_scan_context *scan = context;
    const yx_atom_entry *entry = &scan->set->entries[index];
    /* Also poll in dense-hit inputs, where advancing 256 KiB can take a
     * long time. A clock read every 1024 callbacks bounds that latency. */
    if (!(++scan->occurrences & 1023) && yx_scan_deadline_reached(scan->deadline)) return false;
    if (scan->hit) { scan->hit[entry->owner] = true; return true; }
    return scan->fn(scan->ctx, entry->owner, entry->tag, position);
}

static bool yx_atom_scan_ranges(const yx_atom_set *set, const uint8_t *data, size_t size,
                                yx_atom_scan_context *scan)
{
    if ((!data && size) || yx_scan_deadline_reached(scan->deadline)) return false;
    /* Starts are partitioned, but each range can read the whole buffer.
     * Atoms straddling a polling boundary are therefore reported once. */
    for (size_t begin = 0; begin < size;) {
        size_t count = size - begin < 0x40000u ? size - begin : 0x40000u;
        if (yx_scan_deadline_reached(scan->deadline)) return false;
        if (!xx_literal_set_scan(set->finder, data, size, begin, begin + count,
                                  yx_atom_report, scan)) return false;
        begin += count;
    }
    return !yx_scan_deadline_reached(scan->deadline);
}

bool yx_atom_set_scan_candidates(const yx_atom_set *set, const uint8_t *data, size_t size,
                                 yx_scan_deadline *deadline, yx_atom_candidate_fn fn, void *ctx)
{
    if (!set || !fn) return false;
    yx_atom_scan_context scan = {set, deadline, fn, ctx, NULL, 0};
    return yx_atom_scan_ranges(set, data, size, &scan);
}

bool yx_atom_set_scan(const yx_atom_set *set, const uint8_t *data, size_t size,
                      yx_scan_deadline *deadline, bool *hit)
{
    if (!set || (!hit && set->owners)) return false;
    if (set->owners) memset(hit, 0, set->owners * sizeof(*hit));
    yx_atom_scan_context scan = {set, deadline, NULL, NULL, hit, 0};
    return yx_atom_scan_ranges(set, data, size, &scan);
}
