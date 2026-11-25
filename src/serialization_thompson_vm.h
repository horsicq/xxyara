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
 * The instruction encoding, repetition lowering and atom selection follow
 * lib/src/re/thompson and lib/src/compiler/atoms in YARA-X v1.21.0.
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

/* Execute large Thompson programs using the pinned ordered-thread semantics.
 * Sharing compiler output avoids PCRE code-size and nested-counter differences. */
#ifndef XXYARA_SERIALIZATION_THOMPSON_VM_H
#define XXYARA_SERIALIZATION_THOMPSON_VM_H

#include "xxfclib/data/xx_data.h"

typedef struct {
    size_t ip;
    uint32_t count;
} yx_tv_thread;
typedef struct {
    yx_tv_thread *items;
    size_t used, capacity;
} yx_tv_threads;
typedef struct {
    yx_tv_threads current, next, stack;
    uint32_t *seen, generation;
    size_t seen_size;
    uint8_t splits[1024];
    yx_scan_deadline *deadline;
} yx_tv_state;

static bool yx_tv_push(yx_tv_threads *v, size_t ip, uint32_t count)
{
    if (v->used == v->capacity) {
        size_t capacity = v->capacity ? v->capacity * 2 : 32;
        if (capacity < v->capacity || capacity > SIZE_MAX / sizeof(*v->items)) return false;
        yx_tv_thread *items = realloc(v->items, capacity * sizeof(*items));
        if (!items) return false;
        v->items = items;
        v->capacity = capacity;
    }
    v->items[v->used++] = (yx_tv_thread){ip, count};
    return true;
}
static void yx_tv_clear(yx_tv_state *s)
{
    free(s->current.items);
    free(s->next.items);
    free(s->stack.items);
    free(s->seen);
    memset(s, 0, sizeof(*s));
}
static void yx_tv_generation(yx_tv_state *s)
{
    if (++s->generation == 0) {
        memset(s->seen, 0, s->seen_size * sizeof(*s->seen));
        s->generation = 1;
    }
}
static bool yx_tv_word(int byte)
{
    return byte == '_' || (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9');
}
static bool yx_tv_closure(yx_tv_state *s, const yx_writer *code, yx_tv_threads *out, size_t start, uint32_t count, int current, int previous, bool backwards)
{
    s->stack.used = 0;
    memset(s->splits, 0, sizeof(s->splits));
    if (!yx_tv_push(&s->stack, start, count)) return false;
    size_t steps = 0;
    while (s->stack.used) {
        if (!(++steps & 1023) && yx_scan_deadline_poll(s->deadline)) return false;
        yx_tv_thread t = s->stack.items[--s->stack.used];
        if (t.ip >= code->used) return false;
        const uint8_t *p = code->data + t.ip;
        size_t width = yx_tr_instruction_size(p, code->used - t.ip);
        if (!width) return false;
        unsigned op = p[0] == 0xaa ? p[1] : 0xff;
        if (op == 0xff || op == 0xaa || op == 0 || (op >= 5 && op <= 9)) {
            if (s->seen[t.ip] != s->generation) {
                s->seen[t.ip] = s->generation;
                if (!yx_tv_push(out, t.ip, t.count)) return false;
            }
        } else if (op >= 1 && op <= 3) {
            unsigned id = (unsigned)p[2] | ((unsigned)p[3] << 8);
            if (id >= 8192) return false;
            if (s->splits[id >> 3] & (1u << (id & 7))) continue;
            s->splits[id >> 3] |= (uint8_t)(1u << (id & 7));
            if (op == 3) {
                for (size_t n = p[4]; n-- > 0;)
                    if (!yx_tv_push(&s->stack, (size_t)((int64_t)t.ip + yx_tr_read_i32(p + 5 + 4 * n)), t.count)) return false;
            } else {
                size_t target = (size_t)((int64_t)t.ip + yx_tr_read_i32(p + 4));
                if (!yx_tv_push(&s->stack, op == 1 ? target : t.ip + width, t.count) || !yx_tv_push(&s->stack, op == 1 ? t.ip + width : target, t.count)) return false;
            }
        } else if (op == 4) {
            if (!yx_tv_push(&s->stack, (size_t)((int64_t)t.ip + yx_tr_read_i32(p + 2)), t.count)) return false;
        } else if (op == 16 || op == 17) {
            uint32_t min = (uint32_t)yx_tr_read_i32(p + 6), max = (uint32_t)yx_tr_read_i32(p + 10);
            size_t target = (size_t)((int64_t)t.ip + yx_tr_read_i32(p + 2));
            if (t.count == UINT32_MAX) return false;
            ++t.count;
            if (op == 16 && t.count >= min && !yx_tv_push(&s->stack, t.ip + width, 0)) return false;
            if (t.count < max && !yx_tv_push(&s->stack, target, t.count)) return false;
            if (op == 17 && t.count >= min && !yx_tv_push(&s->stack, t.ip + width, 0)) return false;
        } else {
            int left = backwards ? current : previous, right = backwards ? previous : current;
            bool accept = false;
            if (op == 10) accept = left < 0;
            else if (op == 11) accept = right < 0;
            else if (op == 12 || op == 13) accept = (yx_tv_word(left) != yx_tv_word(right)) == (op == 12);
            else if (op == 14) accept = !yx_tv_word(left) && yx_tv_word(right);
            else if (op == 15) accept = yx_tv_word(left) && !yx_tv_word(right);
            else if (op == 18) accept = left < 0 || (left == '\n' && right != '\r') || (left == '\r' && right != '\n');
            else if (op == 19) accept = right < 0 || (right == '\n' && left != '\r') || (right == '\r' && left != '\n');
            else return false;
            if (accept && !yx_tv_push(&s->stack, t.ip + width, t.count)) return false;
        }
    }
    return true;
}

static int yx_tv_byte(const uint8_t *data, size_t size, size_t origin, size_t index, bool backwards, bool wide)
{
    size_t width = wide ? 2 : 1;
    if (backwards) {
        if (index >= origin / width) return -1;
        size_t at = origin - (index + 1) * width;
        return data[at];
    }
    if (origin > size || index >= (size - origin) / width) return -1;
    size_t at = origin + index * width;
    return data[at];
}
typedef bool (*yx_tv_found)(size_t length, void *context);
static bool yx_tv_run(yx_tv_state *s, const yx_writer *code, size_t ip, const uint8_t *data, size_t size, size_t origin, bool backwards, bool wide, bool first,
                      yx_tv_found found, void *context)
{
    s->current.used = s->next.used = 0;
    yx_tv_generation(s);
    int current = yx_tv_byte(data, size, origin, 0, backwards, wide);
    int previous = yx_tv_byte(data, size, origin, 0, !backwards, wide);
    if (!yx_tv_closure(s, code, &s->current, ip, 0, current, previous, backwards)) return false;
    size_t position = 0;
    while (s->current.used) {
        if (yx_scan_deadline_poll(s->deadline)) return false;
        yx_tv_generation(s);
        s->next.used = 0;
        for (size_t i = 0; i < s->current.used; ++i) {
            yx_tv_thread t = s->current.items[i];
            const uint8_t *p = code->data + t.ip;
            size_t width = yx_tr_instruction_size(p, code->used - t.ip);
            unsigned op = p[0] == 0xaa ? p[1] : 0xff;
            if (op == 0) {
                bool valid = true;
                if (wide)
                    for (size_t n = 0; n < position; ++n) {
                        size_t at = backwards ? origin - (n + 1) * 2 : origin + n * 2;
                        if (data[at + 1]) {
                            valid = false;
                            break;
                        }
                    }
                if (valid && !found(position * (wide ? 2 : 1), context)) return false;
                if (first) break;
                continue;
            }
            bool accept = false;
            if (op == 0xff || op == 0xaa) {
                accept = current == p[0];
                if (accept && s->current.used == 1) {
                    /* The reference consumes a literal run in one VM turn;
                     * the scan bound is checked after the entire run. */
                    while (t.ip + width < code->used) {
                        const uint8_t *q = p + width;
                        if (q[0] == 0xaa && (t.ip + width + 1 >= code->used || q[1] != 0xaa)) break;
                        ++position;
                        current = yx_tv_byte(data, size, origin, position, backwards, wide);
                        width += q[0] == 0xaa ? 2 : 1;
                        if (current != q[0]) {
                            accept = false;
                            break;
                        }
                    }
                }
            } else if (current >= 0) {
                if (op == 5) accept = true;
                else if (op == 6) accept = ((unsigned)current & p[3]) == p[2];
                else if (op == 7) accept = (current >= 'A' && current <= 'Z' ? current + 32 : current) == p[2];
                else if (op == 8) accept = (p[2 + ((unsigned)current >> 3)] & (1u << (current & 7))) != 0;
                else if (op == 9)
                    for (unsigned n = 0; n < p[2]; ++n)
                        if (current >= p[3 + 2 * n] && current <= p[4 + 2 * n]) accept = true;
            }
            if (accept && !yx_tv_closure(s, code, &s->next, t.ip + width, t.count, yx_tv_byte(data, size, origin, position + 1, backwards, wide), current, backwards))
                return false;
        }
        ++position;
        current = yx_tv_byte(data, size, origin, position, backwards, wide);
        yx_tv_threads swap = s->current;
        s->current = s->next;
        s->next = swap;
        if (position >= 4096) break;
    }
    return true;
}

/* FastVM stores wildcard jump counts as u16 even when the source uses
 * a larger u32 bound. Preserve that measured behavior only after the full
 * Fast compiler accepts the expression; Thompson repetitions keep u32. */
/* FastVM bounds are u32 in v12. Keep them intact and route split chains
 * through the fragment matcher, whose gaps are measured in raw bytes. */
static bool yx_tv_literal_hex_chain(const YRX_PATTERN *pattern)
{
    size_t bytes = 0;
    bool gap = false;
    for (size_t i = 0; i < pattern->hex_atom_count; ++i) {
        const yx_hex_atom *atom = &pattern->hex_atoms[i];
        if (atom->kind == YX_HEX_BYTE) ++bytes;
        else if (atom->kind == YX_HEX_JUMP) {
            if (bytes < 2 || atom->maximum <= 200) return false;
            bytes = 0;
            gap = true;
        } else return false;
    }
    return gap && bytes >= 2;
}

static bool yx_ft_regex(yx_fast_program *p, const yx_tr_node *root, bool greedy);
/* Chains of pieces that are not all FastVM pieces (serialization_hir_chain.h). */
static bool yx_hc_is_chain(const YRX_PATTERN *pattern);
static int yx_hc_chain_status(const YRX_PATTERN *pattern);
static int yx_hc_scan(YRX_PATTERN *pattern, const uint8_t *data, size_t size, bool (*emit)(size_t, size_t, void *), void *context);
/* The FastVM pieces of a regexp pattern. The source lowering reads `(?s)`
 * flag groups only; other flag spellings ((?sm), (?si), (?sx), (?sU)) and
 * any-byte gaps written as (?s:.)+ or [\x00-\xff]+ come from the parsed
 * HIR, as Hir::split_at_large_gaps sees them. *program is left empty and
 * reusable when neither applies. */
static bool yx_tv_fast_pieces(yx_fast_program **program, const YRX_PATTERN *pattern)
{
    bool dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0, nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    if (yx_fast_regex(*program, pattern->regexp, dotall)) return true;
    yx_fast_program_destroy(*program);
    *program = calloc(1, sizeof(**program));
    if (!*program) return false;
    (*program)->nocase = nocase;
    yx_tr_parser parser = {.text = (const uint8_t *)pattern->regexp, .length = strlen(pattern->regexp), .dotall = dotall, .nocase = nocase};
    yx_tr_node *root = yx_tr_expression(&parser);
    bool parsed = root && !parser.failed && !parser.oom && parser.at == parser.length && yx_ft_regex(*program, root, parser.saw_greedy && !parser.saw_lazy);
    yx_tr_destroy(root);
    if (!parsed) {
        yx_fast_program_destroy(*program);
        *program = calloc(1, sizeof(**program));
        if (*program) (*program)->nocase = nocase;
    }
    return parsed;
}

/* Hir::is_alternation_literal (lib/src/re/hir.rs) of a regexp pattern: a
 * literal or an alternation of literals, optionally inside one capture
 * group: 1, 0 (also when the regexp does not parse), -1 on allocation
 * failure. */
static int yx_tv_alternation_literal(const YRX_PATTERN *pattern)
{
    yx_tr_parser parser = {.text = (const uint8_t *)pattern->regexp,
                           .length = strlen(pattern->regexp),
                           .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                           .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&parser);
    const yx_tr_node *node = root;
    bool literal = root && !parser.failed && !parser.oom && parser.at == parser.length;
    if (parser.oom) {
        yx_tr_destroy(root);
        return -1;
    }
    if (literal && node->kind == YX_TR_CAPTURE && node->count == 1) node = node->children[0];
    if (literal && node->kind != YX_TR_LITERAL) {
        literal = node->kind == YX_TR_ALT && !node->unicode_class && node->count;
        for (size_t i = 0; literal && i < node->count; ++i) literal = node->children[i]->kind == YX_TR_LITERAL;
    }
    yx_tr_destroy(root);
    return literal;
}

/* Hir::as_literal_bytes (lib/src/re/hir.rs) of a regexp pattern: 1 with the
 * bytes (free them), 0 when its HIR is not one literal, -1 on allocation
 * failure. in_capture also takes a literal inside one capture group, which
 * c_alternation_literal compiles as that literal. */
static int yx_tv_regexp_literal(const YRX_PATTERN *pattern, bool in_capture, uint8_t **bytes, size_t *length)
{
    *bytes = NULL;
    *length = 0;
    if (!pattern || pattern->kind != YX_PATTERN_REGEX || !pattern->regexp) return 0;
    yx_tr_parser parser = {.text = (const uint8_t *)pattern->regexp,
                           .length = strlen(pattern->regexp),
                           .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                           .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&parser);
    const yx_tr_node *node = root;
    int result = 0;
    if (in_capture && node && node->kind == YX_TR_CAPTURE && node->count == 1) node = node->children[0];
    if (parser.oom) result = -1;
    else if (root && !parser.failed && parser.at == parser.length && node->kind == YX_TR_LITERAL && node->length) {
        *bytes = malloc(node->length);
        if (!*bytes) result = -1;
        else {
            memcpy(*bytes, node->bytes, node->length);
            *length = node->length;
            result = 1;
        }
    }
    yx_tr_destroy(root);
    return result;
}

int yx_ser_regexp_literal(const YRX_PATTERN *pattern, uint8_t **bytes, size_t *length)
{
    return yx_tv_regexp_literal(pattern, false, bytes, length);
}

int yx_ser_lower_fast_regex(const YRX_PATTERN *pattern, char **lowered)
{
    *lowered = NULL;
    if (!pattern || (pattern->kind != YX_PATTERN_HEX && !pattern->regexp)) return -2;
    /* Variable-length alternative fragments can need several matches at
     * one offset. Keep those on the full hex walker; literal fragments
     * have exactly one endpoint per offset and can use the shared join. */
    if (pattern->kind == YX_PATTERN_HEX && !yx_tv_literal_hex_chain(pattern)) return -2;
    yx_fast_program *fast = calloc(1, sizeof(*fast));
    if (!fast) return -1;
    fast->nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool parsed = pattern->kind == YX_PATTERN_HEX ? yx_fast_hex_sequence(fast, pattern->hex_atoms, pattern->hex_atom_count) : yx_tv_fast_pieces(&fast, pattern);
    if (!fast) return -1;
    bool chain = parsed && yx_fast_requires_chain(fast);
    yx_fast_program_destroy(fast);
    /* Pieces with a look-around or a Unicode class: FastVM rejects them,
     * but split_at_large_gaps still makes the chain. */
    if (!parsed && pattern->kind == YX_PATTERN_REGEX) {
        int status = yx_hc_chain_status(pattern);
        if (status < 0) return -1;
        if (status) chain = true;
    }
    return chain ? 3 : -2;
}

static bool yx_tv_large(const yx_tr_node *n, bool repeated)
{
    if (n->kind == YX_TR_REPEAT && (n->minimum > 512 || (!yx_tr_unbounded(n) && n->maximum > 512))) return true;
    if (repeated && n->kind == YX_TR_LITERAL && n->length > 512) return true;
    for (size_t i = 0; i < n->count; ++i)
        if (yx_tv_large(n->children[i], repeated || n->kind == YX_TR_REPEAT)) return true;
    return false;
}
static bool yx_tv_nullable(const yx_tr_node *n)
{
    if (n->kind == YX_TR_LITERAL) return n->length == 0;
    if (n->kind == YX_TR_CLASS || n->kind == YX_TR_SCALAR_CLASS) return false;
    if (n->kind == YX_TR_REPEAT && !n->minimum) return true;
    if (n->kind == YX_TR_ALT) {
        for (size_t i = 0; i < n->count; ++i)
            if (yx_tv_nullable(n->children[i])) return true;
        return false;
    }
    for (size_t i = 0; i < n->count; ++i)
        if (!yx_tv_nullable(n->children[i])) return false;
    return true;
}
static int yx_tv_prepare(const YRX_PATTERN *pattern, yx_tr_program *program, bool *greedy_out)
{
    yx_tr_parser p = {.text = (const uint8_t *)pattern->regexp,
                      .length = strlen(pattern->regexp),
                      .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                      .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&p);
    bool eligible = root && !p.failed && !p.oom && p.at == p.length && yx_tv_large(root, false) && yx_tr_needs_thompson(root, false, false);
    bool nullable = eligible && yx_tv_nullable(root);
    yx_tr_destroy(root);
    if (!eligible) return -2;
    bool greedy;
    if (!yx_tr_compile(pattern->regexp, p.dotall, p.nocase, program, &greedy)) return -1;
    if (greedy_out) *greedy_out = greedy && pattern->kind != YX_PATTERN_HEX;
    return nullable ? 0 : 1;
}

int yx_ser_large_regex_validate(const YRX_PATTERN *pattern)
{
    yx_tr_program p = {0};
    int result = yx_tv_prepare(pattern, &p, NULL);
    yx_tr_program_free(&p);
    return result;
}
typedef struct {
    YRX_PATTERN *pattern;
    size_t origin, forward;
    bool wide;
    const uint8_t *data;
    size_t size;
    bool (*emit)(size_t, size_t, void *);
    void *context;
} yx_tv_output;
static bool yx_tv_forward(size_t length, void *context)
{
    ((yx_tv_output *)context)->forward = length;
    return true;
}
static bool yx_tv_backward(size_t length, void *context)
{
    yx_tv_output *o = context;
    size_t at = o->origin - length, span = o->forward + length, width = o->wide ? 2 : 1;
    if (o->pattern->modifiers & YX_MOD_FULLWORD) {
        int left = yx_tv_byte(o->data, o->size, at, 0, true, o->wide);
        int right = yx_tv_byte(o->data, o->size, at + span, 0, false, o->wide);
        if (o->wide) {
            if (at < 2 || o->data[at - 1]) left = -1;
            if (at + span >= o->size || o->size - (at + span) < 2 || o->data[at + span + 1]) right = -1;
        }
        bool lw = (left >= 'a' && left <= 'z') || (left >= 'A' && left <= 'Z') || (left >= '0' && left <= '9');
        bool rw = (right >= 'a' && right <= 'z') || (right >= 'A' && right <= 'Z') || (right >= '0' && right <= '9');
        if ((at >= width && lw) || rw) return true;
    }
    return o->emit(at, span, o->context);
}
/* Match each fragment on the original byte stream, then join its matches
 * by the raw byte distances stored in chain gaps. In wide mode the gap may
 * change alignment; only the fragments themselves require zero padding. */
int yx_ser_scan_large_fast_chain(YRX_PATTERN *pattern, const uint8_t *data, size_t size, bool (*emit)(size_t, size_t, void *), void *context)
{
    yx_fast_program *program = calloc(1, sizeof(*program)), *fragment = calloc(1, sizeof(*fragment));
    YRX_PATTERN *parts = NULL;
    size_t **finish = NULL, *starts = NULL, *ends = NULL, *gaps = NULL;
    size_t count = 0, start = 0, minimum = 0;
    int result = 0;
    if (!program || !fragment) goto done;
    program->nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool parsed = pattern->kind == YX_PATTERN_HEX ? yx_fast_hex_sequence(program, pattern->hex_atoms, pattern->hex_atom_count)
                                                  : pattern->regexp && yx_tv_fast_pieces(&program, pattern);
    if (program && !parsed && pattern->kind == YX_PATTERN_REGEX && yx_hc_is_chain(pattern)) {
        result = yx_hc_scan(pattern, data, size, emit, context);
        goto done;
    }
    if (!program || !parsed || !yx_fast_requires_chain(program)) goto done;
    if (program->count > SIZE_MAX / sizeof(*parts) || program->count > SIZE_MAX / sizeof(*starts)) goto done;
    parts = calloc(program->count, sizeof(*parts));
    finish = calloc(program->count, sizeof(*finish));
    starts = malloc(program->count * sizeof(*starts));
    ends = malloc(program->count * sizeof(*ends));
    gaps = malloc(program->count * sizeof(*gaps));
    if (!parts || !finish || !starts || !ends || !gaps) goto done;
    for (size_t i = 0; i < program->count; ++i) {
        const yx_fast_piece *piece = &program->pieces[i];
        if ((piece->kind == 3 || piece->kind == 4) && piece->newline && minimum >= 2 && piece->maximum > 200) {
            starts[count] = start;
            ends[count] = i;
            gaps[count++] = i;
            start = i + 1;
            minimum = 0;
            continue;
        }
        size_t width = piece->minimum;
        if (piece->alternative_count) {
            width = SIZE_MAX;
            for (size_t a = 0; a < piece->alternative_count; ++a)
                if (piece->alternatives[a].length < width) width = piece->alternatives[a].length;
        }
        if (minimum < 2) minimum += width;
    }
    if (minimum < 2 && count) --count;
    else starts[count] = start;
    ends[count++] = program->count;
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    for (unsigned variant = wide && !(pattern->modifiers & YX_MOD_ASCII) ? 1u : 0u; variant < (wide ? 2u : 1u); ++variant) {
        for (size_t i = 0; i < count; ++i) {
            free(parts[i].regexp);
            parts[i].regexp = NULL;
            free(finish[i]);
            finish[i] = NULL;
            fragment->count = ends[i] - starts[i];
            fragment->flags = program->flags;
            fragment->pieces = program->pieces + starts[i];
            yx_writer source = {0};
            bool dotall;
            if (!yx_fast_source(fragment, false, &source, &dotall) || !yx_put_u8(&source, 0)) {
                free(source.data);
                goto done;
            }
            parts[i].regexp = (char *)source.data;
            parts[i].kind = YX_PATTERN_REGEX;
            parts[i].modifiers = pattern->modifiers & ~(YX_MOD_FULLWORD | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_DOTALL);
            parts[i].modifiers |= variant ? YX_MOD_WIDE : YX_MOD_ASCII;
            if (dotall) parts[i].modifiers |= YX_MOD_DOTALL;
            parts[i].deadline = pattern->deadline;
            if (yx_scan_pattern(&parts[i], data, size, 0, false) != YRX_SUCCESS) goto done;
            finish[i] = malloc((parts[i].match_count ? parts[i].match_count : 1) * sizeof(**finish));
            if (!finish[i]) goto done;
        }
        bool greedy = (program->flags & 32) != 0;
        for (size_t i = count; i-- > 0;) {
            for (size_t m = 0; m < parts[i].match_count; ++m) {
                if (yx_scan_deadline_poll(pattern->deadline)) goto done;
                const YRX_MATCH *match = &parts[i].matches[m];
                size_t end = (size_t)match->offset + (size_t)match->length;
                size_t selected = SIZE_MAX;
                if (i + 1 == count) {
                    int right = yx_tv_byte(data, size, end, 0, false, variant != 0);
                    if (variant && (end >= size || size - end < 2 || data[end + 1])) right = -1;
                    bool word = (right >= 'a' && right <= 'z') || (right >= 'A' && right <= 'Z') || (right >= '0' && right <= '9');
                    if (!(pattern->modifiers & YX_MOD_FULLWORD) || !word) selected = end;
                } else {
                    const yx_fast_piece *gap = &program->pieces[gaps[i]];
                    for (size_t n = 0; n < parts[i + 1].match_count; ++n) {
                        if (!(n & 255u) && yx_scan_deadline_poll(pattern->deadline)) goto done;
                        if (finish[i + 1][n] == SIZE_MAX || parts[i + 1].matches[n].offset < end) continue;
                        size_t distance = (size_t)parts[i + 1].matches[n].offset - end;
                        if (distance < gap->minimum || (!gap->unbounded && distance > gap->maximum)) continue;
                        size_t candidate = finish[i + 1][n];
                        if (selected == SIZE_MAX || (greedy ? candidate > selected : candidate < selected)) selected = candidate;
                    }
                }
                finish[i][m] = selected;
            }
        }
        for (size_t m = 0; m < parts[0].match_count; ++m)
            if (finish[0][m] != SIZE_MAX) {
                size_t offset = (size_t)parts[0].matches[m].offset;
                yx_tv_output out = {pattern, offset, finish[0][m] - offset, variant != 0, data, size, emit, context};
                if (!yx_tv_backward(0, &out)) goto done;
            }
    }
    result = 1;
done:
    if (parts)
        for (size_t i = 0; i < count; ++i) {
            free(parts[i].regexp);
            free(parts[i].matches);
        }
    if (finish)
        for (size_t i = 0; i < count; ++i) free(finish[i]);
    free(parts);
    free(finish);
    free(starts);
    free(ends);
    free(gaps);
    free(fragment);
    if (program) yx_fast_program_destroy(program);
    return result;
}

int yx_ser_scan_large_regex(YRX_PATTERN *pattern, const uint8_t *data, size_t size, bool (*emit)(size_t, size_t, void *), void *context, bool *greedy)
{
    yx_tr_program p = {0};
    yx_tv_state state = {.deadline = pattern->deadline};
    int result = yx_tv_prepare(pattern, &p, greedy);
    if (result <= 0) {
        yx_tr_program_free(&p);
        return result == -2 ? -2 : 0;
    }
    state.seen_size = p.forward.used > p.backward.used ? p.forward.used : p.backward.used;
    state.seen = calloc(state.seen_size, sizeof(*state.seen));
    if (!state.seen) {
        result = 0;
        goto done;
    }
    bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    for (unsigned variant = 0; variant < (wide && (pattern->modifiers & YX_MOD_ASCII) ? 2u : 1u); ++variant) {
        bool use_wide = wide && !variant;
        for (size_t a = 0; a < p.atoms.count; ++a) {
            const yx_tr_atom_entry *atom = &p.atoms.items[a];
            uint8_t bytes[8] = {0};
            size_t length = atom->length * (use_wide ? 2 : 1);
            for (size_t i = 0; i < atom->length; ++i) bytes[i * (use_wide ? 2 : 1)] = atom->bytes[i];
            for (size_t start = 0; start <= size;) {
                if (yx_scan_deadline_poll(pattern->deadline)) {
                    result = 0;
                    goto done;
                }
                int64_t hit = length ? xx_data_find_bytes_buffer_optimize(data, size, start, bytes, length, NULL) : (int64_t)start;
                if (hit < 0) break;
                yx_tv_output out = {pattern, (size_t)hit, SIZE_MAX, use_wide, data, size, emit, context};
                if (!yx_tv_run(&state, &p.forward, atom->forward, data, size, (size_t)hit, false, use_wide, true, yx_tv_forward, &out) ||
                    (out.forward != SIZE_MAX && !yx_tv_run(&state, &p.backward, atom->backward, data, size, (size_t)hit, true, use_wide, false, yx_tv_backward, &out))) {
                    result = 0;
                    goto done;
                }
                if ((size_t)hit == size) break;
                start = (size_t)hit + 1;
            }
        }
    }
    result = 1;
done:
    yx_tv_clear(&state);
    yx_tr_program_free(&p);
    return result;
}
#endif
