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
 * The pattern-chain splitting, metadata and atom quality rules
 * follow lib/src/re/fast and lib/src/compiler/atoms in YARA-X v1.21.0.
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

#ifndef YX_SERIALIZATION_CHAIN_H
#define YX_SERIALIZATION_CHAIN_H

/* Semantic chained-pattern codec. Included after both verifier compilers. */
#define YX_CHAIN_MAX_ATOMS 16384

typedef struct yx_chain_frame {
    uint8_t variant;
    uint16_t flags;
    uint32_t minimum, maximum;
    bool finite_maximum;
    size_t previous, literal_index;
    const uint8_t *literal;
    size_t literal_length;
} yx_chain_frame;
typedef struct yx_chain_atom {
    yx_archive_regexp_atom atom;
    size_t frame;
} yx_chain_atom;
typedef struct yx_chain_archive {
    char *names[3];
    uint8_t kind;
    bool literal_only;
    yx_chain_frame *frames;
    size_t frame_count, frame_capacity;
    size_t heads[2], head_count;
    const uint8_t **pool;
    size_t *pool_lengths, pool_count, pool_capacity;
    yx_chain_atom *atoms;
    size_t atom_count;
    const uint8_t *code, *wasm;
    size_t code_length, wasm_length, archive_length;
} yx_chain_archive;
/* Frames and literal pools are vectors in the upstream format. Keep their
 * storage independent from names, which encoder views may borrow. */
static bool yx_chain_frames_reserve(yx_chain_archive *a, size_t count)
{
    if (count <= a->frame_capacity) return true;
    if (count > SIZE_MAX / sizeof(*a->frames)) return false;
    yx_chain_frame *frames = realloc(a->frames, count * sizeof(*frames));
    if (!frames) return false;
    memset(frames + a->frame_capacity, 0, (count - a->frame_capacity) * sizeof(*frames));
    a->frames = frames;
    a->frame_capacity = count;
    return true;
}
static bool yx_chain_pool_reserve(yx_chain_archive *a, size_t count)
{
    if (count <= a->pool_capacity) return true;
    if (count > SIZE_MAX / sizeof(*a->pool) || count > SIZE_MAX / sizeof(*a->pool_lengths)) return false;
    const uint8_t **pool = realloc(a->pool, count * sizeof(*pool));
    if (!pool) return false;
    a->pool = pool;
    size_t *lengths = realloc(a->pool_lengths, count * sizeof(*lengths));
    if (!lengths) return false;
    a->pool_lengths = lengths;
    a->pool_capacity = count;
    return true;
}
static void yx_chain_storage_destroy(yx_chain_archive *a)
{
    free(a->frames);
    free(a->pool);
    free(a->pool_lengths);
    free(a->atoms);
    a->frames = NULL;
    a->pool = NULL;
    a->pool_lengths = NULL;
    a->atoms = NULL;
    a->frame_capacity = a->pool_capacity = 0;
}
static void yx_chain_destroy(yx_chain_archive *a)
{
    for (size_t i = 0; i < 3; ++i) free(a->names[i]);
    yx_chain_storage_destroy(a);
    memset(a, 0, sizeof(*a));
}
static bool yx_chain_unbounded(const yx_chain_frame *frame)
{
    return frame->maximum == UINT32_MAX && !frame->finite_maximum;
}
static bool yx_chain_put_frame(yx_writer *w, const yx_chain_frame *f)
{
    if (!yx_put_uint(w, 0) || !yx_put_uint(w, f->variant)) return false;
    if ((f->variant == 0 || f->variant == 2 || f->variant == 3) && !yx_put_uint(w, f->literal_index)) return false;
    if (f->variant == 3 || f->variant == 6) {
        if (!yx_put_uint(w, f->previous) || !yx_put_uint(w, yx_chain_unbounded(f) ? 1 : 0) || !yx_put_uint(w, f->minimum) ||
            (!yx_chain_unbounded(f) && !yx_put_uint(w, f->maximum)))
            return false;
    }
    return (f->variant != 0 || yx_put_u8(w, 0)) && yx_put_uint(w, f->flags);
}
static yx_ser_result yx_chain_envelope(const yx_chain_archive *a, uint8_t **data, size_t *length)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    static const uint8_t globals[] = {0, 0, 1, 0}, suffix[] = {0, 0, 1, 1, 1, 0};
    yx_writer w = {0};
    uint8_t *ac = NULL;
    size_t ac_length = 0;
    const uint8_t **bytes = NULL;
    size_t *widths = NULL;
    if (!a->frame_count || !a->atom_count || a->atom_count > YX_CHAIN_MAX_ATOMS) return YX_SER_UNSUPPORTED;
    bytes = malloc(a->atom_count * sizeof(*bytes));
    widths = malloc(a->atom_count * sizeof(*widths));
    if (!bytes || !widths) goto memory;
    for (size_t i = 0; i < a->atom_count; ++i) {
        bytes[i] = a->atoms[i].atom.bytes;
        widths[i] = a->atoms[i].atom.length;
    }
    if (!yx_ser_build_atom_ac(bytes, widths, a->atom_count, &ac, &ac_length)) goto memory;
    if (!yx_put_bytes(&w, magic, sizeof(magic)) || !yx_put_uint(&w, 3)) goto memory;
    for (size_t i = 0; i < 3; ++i)
        if (!yx_put_string(&w, a->names[i])) goto memory;
    if (!yx_put_uint(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, a->pool_count)) goto memory;
    for (size_t i = 0; i < a->pool_count; ++i)
        if (!yx_put_uint(&w, a->pool_lengths[i]) || !yx_put_bytes(&w, a->pool[i], a->pool_lengths[i])) goto memory;
    static const uint8_t before_kind[] = {0, 0, 1, 0, 0, 2, 0, 0, 1, 0, 1}, after_kind[] = {0, 0, 0, 0, 1};
    if (!yx_put_uint(&w, a->wasm_length) || !yx_put_bytes(&w, a->wasm, a->wasm_length) || !yx_put_bytes(&w, before_kind, sizeof(before_kind)) ||
        !yx_put_uint(&w, a->kind) || !yx_put_bytes(&w, after_kind, sizeof(after_kind)) || !yx_put_uint(&w, a->frame_count))
        goto memory;
    for (size_t i = 0; i < a->frame_count; ++i)
        if (!yx_chain_put_frame(&w, &a->frames[i])) goto memory;
    if (!yx_put_uint(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, a->atom_count)) goto memory;
    for (size_t i = 0; i < a->atom_count; ++i) {
        const yx_archive_regexp_atom *b = &a->atoms[i].atom;
        if (!yx_put_uint(&w, a->atoms[i].frame) || !yx_put_uint(&w, b->length) || !yx_put_bytes(&w, b->bytes, b->length) || !yx_put_u8(&w, b->exact) ||
            !yx_put_uint(&w, b->backtrack) || !yx_put_u8(&w, b->has_forward) || (b->has_forward && !yx_put_uint(&w, b->forward + 1)) || !yx_put_u8(&w, b->has_backward) ||
            (b->has_backward && !yx_put_uint(&w, b->backward + 1)))
            goto memory;
    }
    if (!yx_put_uint(&w, a->code_length) || !yx_put_bytes(&w, a->code, a->code_length) || !yx_put_uint(&w, sizeof(globals)) ||
        !yx_put_bytes(&w, globals, sizeof(globals)) || !yx_put_uint(&w, ac_length) || !yx_put_bytes(&w, ac, ac_length) || !yx_put_bytes(&w, suffix, sizeof(suffix)))
        goto memory;
    free(ac);
    free(bytes);
    free(widths);
    *data = w.data;
    *length = w.used;
    return YX_SER_SUCCESS;
memory:
    free(ac);
    free(bytes);
    free(widths);
    free(w.data);
    return YX_SER_NO_MEMORY;
}
static uint64_t yx_chain_minimum(const yx_tr_node *n)
{
    if (n->kind == YX_TR_LITERAL) return n->length;
    if (n->kind == YX_TR_CLASS) return 1;
    /* ClassUnicode::minimum_len: the UTF-8 length of the first scalar. */
    if (n->kind == YX_TR_SCALAR_CLASS) {
        uint32_t first = n->length ? ((const yx_re_range *)n->bytes)[0].first : 0;
        return first < 0x80 ? 1 : first < 0x800 ? 2 : first < 0x10000 ? 3 : 4;
    }
    if (n->kind == YX_TR_CAPTURE) return yx_chain_minimum(n->children[0]);
    if (n->kind == YX_TR_REPEAT) {
        uint64_t v = yx_chain_minimum(n->children[0]);
        return v > UINT32_MAX / (n->minimum ? n->minimum : 1) ? UINT32_MAX : v * n->minimum;
    }
    uint64_t v = n->kind == YX_TR_ALT ? UINT32_MAX : 0;
    for (size_t i = 0; i < n->count; ++i) {
        uint64_t c = yx_chain_minimum(n->children[i]);
        if (n->kind == YX_TR_ALT) {
            if (c < v) v = c;
        } else {
            v += c;
            if (v > UINT32_MAX) return UINT32_MAX;
        }
    }
    return v;
}
static bool yx_chain_literal(const yx_tr_node *n, yx_writer *w)
{
    if (n->kind == YX_TR_LITERAL) return yx_put_bytes(w, n->bytes, n->length);
    if (n->kind == YX_TR_EMPTY) return true;
    if (n->kind != YX_TR_CONCAT) return false;
    for (size_t i = 0; i < n->count; ++i)
        if (!yx_chain_literal(n->children[i], w)) return false;
    return true;
}
static bool yx_chain_text(const yx_tr_node *n, yx_writer *w, size_t depth)
{
    if (depth > 250) return false;
    if (n->kind == YX_TR_EMPTY) return true;
    if (n->kind == YX_TR_LITERAL) {
        for (size_t i = 0; i < n->length; ++i)
            if (!yx_tr_hex_text(w, n->bytes[i])) return false;
        return true;
    }
    if (n->kind == YX_TR_CLASS) {
        bool all = true;
        for (size_t i = 0; i < 32; ++i)
            if (n->bitmap[i] != 255) all = false;
        if (all) return yx_tr_text(w, ".");
        if (!yx_tr_text(w, n->unicode_class ? "(" : "[")) return false;
        bool first = true;
        for (unsigned b = 0; b < 256; ++b)
            if (yx_tr_has(n->bitmap, b)) {
                if (n->unicode_class && !first && !yx_tr_text(w, "|")) return false;
                if (!yx_tr_hex_text(w, (uint8_t)b)) return false;
                first = false;
            }
        return !first && yx_tr_text(w, n->unicode_class ? ")" : "]");
    }
    if (n->kind == YX_TR_LOOK) {
        static const char *const looks[] = {"^", "$", "\\b", "\\B", "\\b", "\\B"};
        if (n->look == 0x12 || n->look == 0x13) return yx_tr_text(w, n->look == 0x12 ? "(?m:^)" : "(?m:$)");
        return n->look >= 10 && n->look <= 15 && yx_tr_text(w, looks[n->look - 10]);
    }
    if (n->kind == YX_TR_SCALAR_CLASS) {
        /* A Unicode class: its scalar ranges in a Unicode scope. */
        const yx_re_range *ranges = (const yx_re_range *)n->bytes;
        /* IntervalSet::negate's range \x{D7FF}-\x{E000} with an unmerged neighbour
         * ([^\x{D7FF}\x{E000}]): a positive class would merge them into one range
         * (any_byte). Written as the negated class it came from. */
        for (size_t q = 0; q + 1 < n->length; ++q) {
            if (!yx_u8_joins(n, ranges, n->length, q) || ranges[q].first != 0xd7ff || ranges[q + 1].last != 0xe000 ||
                !((q && ranges[q - 1].last == 0xd7fe) || (q + 2 < n->length && ranges[q + 2].first == 0xe001)))
                continue;
            if (!yx_tr_text(w, "(?u:[^")) return false;
            /* The ranges between the entries: an entry lo-hi ends one at
             * lo - 1 and starts the next at hi + 1; \x{D7FF}-\x{E000} ends one at
             * \x{D7FF} and starts the next at \x{E000}. */
            uint32_t from = 0;
            bool more = true;
            for (size_t i = 0; i < n->length; ++i) {
                char range[40];
                bool quirk = i == q;
                uint32_t low = ranges[i].first, high = quirk ? ranges[++i].last : ranges[i].last;
                if (quirk || low > from) {
                    snprintf(range, sizeof(range), "\\x{%x}-\\x{%x}", (unsigned)from, quirk ? 0xd7ffu : (unsigned)(low - 1));
                    if (!yx_tr_text(w, range)) return false;
                }
                if (!quirk && high == 0x10ffff) {
                    more = false;
                    break;
                }
                from = quirk ? 0xe000 : high + 1;
            }
            if (more) {
                char range[40];
                snprintf(range, sizeof(range), "\\x{%x}-\\x{10ffff}", (unsigned)from);
                if (!yx_tr_text(w, range)) return false;
            }
            return yx_tr_text(w, "])");
        }
        if (!n->length || !yx_tr_text(w, "(?u:[")) return false;
        for (size_t i = 0; i < n->length; ++i) {
            char range[40];
            uint32_t first = ranges[i].first;
            /* One range of chars across the surrogate gap. */
            if (yx_u8_joins(n, ranges, n->length, i)) ++i;
            snprintf(range, sizeof(range), "\\x{%x}-\\x{%x}", (unsigned)first, (unsigned)ranges[i].last);
            if (!yx_tr_text(w, range)) return false;
        }
        return yx_tr_text(w, "])");
    }
    if (n->kind == YX_TR_REPEAT) {
        char suffix[64];
        if (yx_tr_unbounded(n)) snprintf(suffix, sizeof(suffix), "{%u,}%s", n->minimum, n->greedy ? "" : "?");
        else snprintf(suffix, sizeof(suffix), "{%u,%u}%s", n->minimum, n->maximum, n->greedy ? "" : "?");
        uint64_t min, max;
        if (yx_tr_any_span(n->children[0], &min, &max) && min == 1 && max == 1) return yx_tr_text(w, ".") && yx_tr_text(w, suffix);
        return yx_tr_text(w, "(") && yx_chain_text(n->children[0], w, depth + 1) && yx_tr_text(w, ")") && yx_tr_text(w, suffix);
    }
    bool group = n->kind == YX_TR_ALT;
    if (group && !yx_tr_text(w, "(")) return false;
    for (size_t i = 0; i < n->count; ++i)
        if ((n->kind == YX_TR_ALT && i && !yx_tr_text(w, "|")) || !yx_chain_text(n->children[i], w, depth + 1)) return false;
    return !group || yx_tr_text(w, ")");
}
static bool yx_chain_add_atom(yx_chain_archive *a, size_t frame, const yx_archive_regexp_atom *atom)
{
    if (a->atom_count == YX_CHAIN_MAX_ATOMS) return false;
    a->atoms[a->atom_count++] = (yx_chain_atom){*atom, frame};
    return true;
}
static bool yx_literal_atom_variants(yx_chain_archive *a, size_t frame, yx_archive_regexp_atom *atom, size_t at, bool nocase);
/* Append what a failed FastVM compile of a piece leaves in the code vector
 * (re/fast/compiler.rs, Compiler::compile): the verifiers it emitted before
 * rejecting an atom shorter than two bytes, or, for a piece made of jumps
 * only (no atoms at all), the forward code of every piece and MATCH. */
static bool yx_chain_fast_residue(const yx_fast_program *fast, yx_writer *code)
{
    if (fast->code.used) return yx_put_bytes(code, fast->code.data, fast->code.used);
    for (size_t i = 0; i < fast->count; ++i)
        if (fast->pieces[i].alternative_count) return true;
    for (size_t i = 0; i < fast->count; ++i)
        if (!yx_fast_emit_piece(code, &fast->pieces[i])) return false;
    return yx_put_u8(code, 0);
}
/* MAX_ATOM_SEARCH_BYTES of atoms/quality.rs. */
enum {
    YX_CHAIN_ATOM_SEARCH_BYTES = 32768
};
static bool yx_chain_compile_frame(yx_chain_archive *a, size_t index, const yx_tr_node *n, uint16_t common, yx_writer *code, yx_writer *literal)
{
    yx_chain_frame *f = &a->frames[index];
    f->flags = (common & ~24u) | (index + 1 == a->frame_count ? 4 : 0);
    if ((common & 24u) && !index) f->flags |= 8;
    if ((common & 24u) && index + 1 == a->frame_count) f->flags |= 16;
    if (yx_chain_literal(n, literal) && literal->used) {
        f->variant = index ? 3 : 2;
        f->literal = literal->data;
        f->literal_length = literal->used;
        size_t pool = 0;
        while (pool < a->pool_count && (a->pool_lengths[pool] != literal->used || memcmp(a->pool[pool], literal->data, literal->used))) ++pool;
        if (pool == a->pool_count) {
            a->pool[pool] = literal->data;
            a->pool_lengths[pool] = literal->used;
            ++a->pool_count;
        }
        f->literal_index = pool;
        size_t searched = literal->used < YX_CHAIN_ATOM_SEARCH_BYTES ? literal->used : YX_CHAIN_ATOM_SEARCH_BYTES;
        uint8_t *mask = malloc(searched);
        if (!mask) return false;
        memset(mask, 255, searched);
        yx_fast_literal l = {literal->data, mask, searched, false};
        size_t offset, width;
        yx_fast_best_atom(&l, &offset, &width);
        free(mask);
        if (offset > UINT16_MAX) return false;
        yx_archive_regexp_atom atom = {0};
        atom.length = width;
        atom.backtrack = (uint16_t)offset;
        atom.exact = width == literal->used && !(f->flags & 24u);
        memcpy(atom.bytes, literal->data + offset, width);
        return yx_literal_atom_variants(a, index, &atom, 0, (f->flags & 2u) != 0);
    }
    free(literal->data);
    *literal = (yx_writer){0};
    yx_writer source = {0};
    if (!yx_chain_text(n, &source, 0) || !yx_put_u8(&source, 0)) {
        free(source.data);
        return false;
    }
    yx_fast_program *fast = calloc(1, sizeof(*fast));
    if (!fast) {
        free(source.data);
        return false;
    }
    bool ok = false;
    f->variant = index ? 6 : 5;
    /* FastVM's PatternSplitter walks the piece's HIR: an alternation of
     * single bytes is a class there (( DD | 11 ) is [\x11\xdd]), which
     * becomes an alternation of masked bytes. */
    bool parsed = yx_ft_regex(fast, n, false);
    if (parsed && yx_fast_compile_mode(fast, true)) {
        f->flags |= 64;
        for (size_t i = 0; i < fast->atom_count; ++i) {
            yx_archive_regexp_atom atom = fast->atoms[i];
            if (atom.has_forward) atom.forward += code->used;
            if (atom.has_backward) atom.backward += code->used;
            if (!yx_chain_add_atom(a, index, &atom)) goto done;
        }
        ok = yx_put_bytes(code, fast->code.data, fast->code.used);
    } else {
        /* Compiler::c_regexp runs the FastVM compiler on the shared code
         * vector first; when it fails with FastIncompatible after emitting
         * its verifier, Thompson's code follows those unreferenced bytes. */
        if (parsed && !yx_chain_fast_residue(fast, code)) goto done;
        yx_tr_program program = {0};
        bool greedy = false;
        if (!yx_tr_compile((char *)source.data, true, false, &program, &greedy)) {
            yx_tr_program_free(&program);
            goto done;
        }
        for (size_t i = 0; i < program.atoms.count; ++i) {
            const yx_tr_atom_entry *b = &program.atoms.items[i];
            yx_archive_regexp_atom atom = {0};
            memcpy(atom.bytes, b->bytes, b->length);
            atom.length = b->length;
            atom.exact = b->exact;
            atom.has_forward = atom.has_backward = true;
            atom.forward = code->used + b->forward;
            atom.backward = code->used + program.forward.used + b->backward;
            if (!yx_chain_add_atom(a, index, &atom)) {
                yx_tr_program_free(&program);
                goto done;
            }
        }
        ok = yx_put_bytes(code, program.forward.data, program.forward.used) && yx_put_bytes(code, program.backward.data, program.backward.used);
        yx_tr_program_free(&program);
    }
done:
    yx_fast_program_destroy(fast);
    free(source.data);
    return ok;
}
/* Literal and literal-alternative regular expressions retain their original
 * bytes in the pool. Case combinations affect atoms, never the pooled text. */
static bool yx_literal_atom_variants(yx_chain_archive *a, size_t frame, yx_archive_regexp_atom *atom, size_t at, bool nocase)
{
    if (at == atom->length) return yx_chain_add_atom(a, frame, atom);
    uint8_t byte = atom->bytes[at];
    if (nocase && byte < 128 && isalpha(byte)) {
        atom->bytes[at] = (uint8_t)tolower(byte);
        if (!yx_literal_atom_variants(a, frame, atom, at + 1, nocase)) return false;
        atom->bytes[at] = (uint8_t)toupper(byte);
        if (!yx_literal_atom_variants(a, frame, atom, at + 1, nocase)) return false;
        atom->bytes[at] = byte;
        return true;
    }
    return yx_literal_atom_variants(a, frame, atom, at + 1, nocase);
}
static bool yx_literal_frame_atoms(yx_chain_archive *a, size_t index)
{
    const yx_chain_frame *f = &a->frames[index];
    /* best_range_in_bytes (atoms/quality.rs) searches the first 32 KiB only
     * (MAX_ATOM_SEARCH_BYTES): the atom's u16 backtrack. A literal itself
     * has any length (SubPattern::Literal, c_alternation_literal). */
    size_t searched = f->literal_length < YX_CHAIN_ATOM_SEARCH_BYTES ? f->literal_length : YX_CHAIN_ATOM_SEARCH_BYTES;
    uint8_t *mask = malloc(searched ? searched : 1);
    if (!mask) return false;
    memset(mask, 255, searched);
    yx_fast_literal literal = {(uint8_t *)f->literal, mask, searched, false};
    size_t offset, width;
    yx_fast_best_atom(&literal, &offset, &width);
    free(mask);
    if (offset > UINT16_MAX || !width) return false;
    yx_archive_regexp_atom atom = {0};
    atom.length = width;
    atom.backtrack = (uint16_t)offset;
    atom.exact = width == f->literal_length;
    memcpy(atom.bytes, f->literal + offset, width);
    return yx_literal_atom_variants(a, index, &atom, 0, (f->flags & 2u) != 0);
}
static yx_ser_result yx_encode_literal_patterns(const YRX_RULES *rules, bool vba_order, uint8_t **data, size_t *length)
{
    if (!yx_fast_rule(rules)) return YX_SER_UNSUPPORTED;
    const YRX_RULE *r = &rules->rules[0];
    const YRX_PATTERN *p = &r->patterns[0];
    yx_writer hex = {0}, *literals = NULL;
    size_t literal_count = 0;
    const char *regexp = p->regexp;
    if (p->kind == YX_PATTERN_HEX) {
        if (!yx_tr_hex_regex(&hex, p->hex_atoms, p->hex_atom_count, 0) || !yx_put_u8(&hex, 0)) {
            free(hex.data);
            return YX_SER_UNSUPPORTED;
        }
        regexp = (char *)hex.data;
    }
    if (!regexp) {
        free(hex.data);
        return YX_SER_UNSUPPORTED;
    }
    yx_tr_parser parser = {
        .text = (const uint8_t *)regexp, .length = strlen(regexp), .dotall = (p->modifiers & YX_MOD_DOTALL) != 0, .nocase = (p->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&parser), *n = root;
    yx_chain_archive a = {0};
    yx_ser_result result = YX_SER_UNSUPPORTED;
    if (parser.oom) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    if (!root || parser.failed || parser.at != parser.length) goto done;
    if (n->kind == YX_TR_CAPTURE) n = n->children[0];
    /* A concatenation of alternatives is a verifier pattern, even when its
     * language is finite. The upstream literal classifier is equally narrow. */
    if (n->kind != YX_TR_LITERAL && n->kind != YX_TR_ALT) goto done;
    size_t alternatives = n->kind == YX_TR_ALT ? n->count : 1;
    bool wide = (p->modifiers & YX_MOD_WIDE) != 0, raw = !wide || (p->modifiers & YX_MOD_ASCII) != 0;
    size_t variants = raw && wide ? 2u : 1u;
    if (!alternatives || alternatives > SIZE_MAX / variants) goto done;
    literal_count = alternatives * variants;
    if (literal_count > SIZE_MAX / sizeof(*literals)) goto done;
    literals = calloc(literal_count, sizeof(*literals));
    if (!literals || !yx_chain_frames_reserve(&a, literal_count) || !yx_chain_pool_reserve(&a, literal_count)) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    a.names[0] = "default";
    a.names[1] = p->identifier;
    a.names[2] = r->identifier;
    a.kind = (uint8_t)p->kind;
    a.literal_only = true;
    a.atoms = calloc(YX_CHAIN_MAX_ATOMS, sizeof(*a.atoms));
    if (!a.atoms) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < alternatives; ++i) {
        const yx_tr_node *leaf = n->kind == YX_TR_ALT ? n->children[i] : n;
        if (leaf->kind != YX_TR_LITERAL || !leaf->length || leaf->length > SIZE_MAX / 2) goto done;
        for (unsigned variant = raw ? 0 : 1; variant < (wide ? 2u : 1u); ++variant) {
            size_t index = a.frame_count++;
            yx_writer *literal = &literals[index];
            for (size_t j = 0; j < leaf->length; ++j)
                if (!yx_put_u8(literal, leaf->bytes[j]) || (variant && !yx_put_u8(literal, 0))) goto done;
            yx_chain_frame *f = &a.frames[index];
            f->literal = literal->data;
            f->literal_length = literal->used;
            f->flags = (variant ? 1 : 0) | ((p->modifiers & YX_MOD_NOCASE) ? 2 : 0) | ((p->modifiers & YX_MOD_FULLWORD) ? 24 : 0);
            size_t pool = 0;
            while (pool < a.pool_count && (a.pool_lengths[pool] != literal->used || memcmp(a.pool[pool], literal->data, literal->used))) ++pool;
            if (pool == a.pool_count) {
                a.pool[pool] = literal->data;
                a.pool_lengths[pool] = literal->used;
                ++a.pool_count;
            }
            f->literal_index = pool;
            if (!yx_literal_frame_atoms(&a, index)) goto done;
        }
    }
    uint8_t wasm[sizeof(yx_single_text_pattern_wasm)];
    memcpy(wasm, yx_single_text_pattern_wasm, sizeof(wasm));
    if (vba_order && !yx_reorder_pattern_wasm(wasm, sizeof(wasm), true)) goto done;
    a.wasm = wasm;
    a.wasm_length = sizeof(wasm);
    result = yx_chain_envelope(&a, data, length);
done:
    if (literals)
        for (size_t i = 0; i < literal_count; ++i) free(literals[i].data);
    free(literals);
    yx_chain_storage_destroy(&a);
    free(hex.data);
    yx_tr_destroy(root);
    return result;
}
/* Wide chains have separate search paths. Literal heads are raw first;
 * verifier heads and all tails are wide first, as in the reference compiler. */
static bool yx_chain_expand_widths(yx_chain_archive *a, bool ascii_wide, yx_writer *storage)
{
    if (a->frame_count > SIZE_MAX / (ascii_wide ? 2u : 1u)) return false;
    size_t frame_count = a->frame_count * (ascii_wide ? 2u : 1u);
    yx_chain_archive *out = calloc(1, sizeof(*out));
    if (!out) return false;
    if (!yx_chain_frames_reserve(out, frame_count) || !yx_chain_pool_reserve(out, frame_count)) {
        yx_chain_storage_destroy(out);
        free(out);
        return false;
    }
    out->kind = a->kind;
    for (size_t i = 0; i < 3; ++i) out->names[i] = a->names[i];
    out->atoms = calloc(YX_CHAIN_MAX_ATOMS, sizeof(*out->atoms));
    if (!out->atoms) {
        yx_chain_storage_destroy(out);
        free(out);
        return false;
    }
    size_t previous[2] = {0, 0};
    bool ok = false;
    for (size_t i = 0; i < a->frame_count; ++i) {
        const yx_chain_frame *original = &a->frames[i];
        bool literal = original->variant == 2 || original->variant == 3;
        bool raw_first = ascii_wide && !i && literal;
        for (size_t v = 0; v < (ascii_wide ? 2u : 1u); ++v) {
            bool wide = raw_first ? v != 0 : v == 0;
            size_t index = out->frame_count++;
            yx_chain_frame *f = &out->frames[index];
            *f = *original;
            f->flags |= wide ? 1 : 0;
            if (i) f->previous = previous[wide ? 1 : 0];
            previous[wide ? 1 : 0] = index;
            if (literal) {
                if (wide) {
                    for (size_t j = 0; j < original->literal_length; ++j)
                        if (!yx_put_u8(&storage[index], original->literal[j]) || !yx_put_u8(&storage[index], 0)) goto done;
                    f->literal = storage[index].data;
                    f->literal_length = storage[index].used;
                }
                size_t pool = 0;
                while (pool < out->pool_count && (out->pool_lengths[pool] != f->literal_length || memcmp(out->pool[pool], f->literal, f->literal_length))) ++pool;
                if (pool == out->pool_count) {
                    out->pool[pool] = f->literal;
                    out->pool_lengths[pool] = f->literal_length;
                    ++out->pool_count;
                }
                f->literal_index = pool;
                size_t first = out->atom_count;
                if (!yx_literal_frame_atoms(out, index)) goto done;
                if (f->flags & 24u)
                    for (size_t j = first; j < out->atom_count; ++j) out->atoms[j].atom.exact = false;
            } else
                for (size_t j = 0; j < a->atom_count; ++j)
                    if (a->atoms[j].frame == i) {
                        yx_archive_regexp_atom atom = a->atoms[j].atom;
                        if (wide) {
                            if (atom.length > 4 || atom.backtrack > UINT16_MAX / 2) goto done;
                            for (size_t k = atom.length; k > 0; --k) {
                                atom.bytes[(k - 1) * 2] = atom.bytes[k - 1];
                                atom.bytes[(k - 1) * 2 + 1] = 0;
                            }
                            atom.length *= 2;
                            atom.backtrack *= 2;
                        }
                        if (!yx_chain_add_atom(out, index, &atom)) goto done;
                    }
        }
    }
    yx_chain_storage_destroy(a);
    *a = *out;
    out->frames = NULL;
    out->pool = NULL;
    out->pool_lengths = NULL;
    out->atoms = NULL;
    ok = true;
done:
    yx_chain_storage_destroy(out);
    free(out);
    return ok;
}
static yx_ser_result yx_encode_chained_pattern(const YRX_RULES *rules, bool vba_order, uint8_t **data, size_t *length)
{
    yx_ser_result literal_result = yx_encode_literal_patterns(rules, vba_order, data, length);
    if (literal_result != YX_SER_UNSUPPORTED) return literal_result;
    if (!yx_fast_rule(rules)) return YX_SER_UNSUPPORTED;
    const YRX_RULE *r = &rules->rules[0];
    const YRX_PATTERN *p = &r->patterns[0];
    if (p->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD)) return YX_SER_UNSUPPORTED;
    yx_writer hex = {0}, code = {0}, *literals = NULL, *wide_literals = NULL;
    size_t *starts = NULL, *ends = NULL, literal_count = 0, wide_literal_count = 0;
    const char *regexp = p->regexp;
    if (p->kind == YX_PATTERN_HEX) {
        if (!yx_tr_hex_regex(&hex, p->hex_atoms, p->hex_atom_count, 0) || !yx_put_u8(&hex, 0)) {
            free(hex.data);
            return YX_SER_UNSUPPORTED;
        }
        regexp = (char *)hex.data;
    }
    if (!regexp) {
        free(hex.data);
        return YX_SER_UNSUPPORTED;
    }
    yx_tr_parser parser = {
        .text = (const uint8_t *)regexp, .length = strlen(regexp), .dotall = (p->modifiers & YX_MOD_DOTALL) != 0, .nocase = (p->modifiers & YX_MOD_NOCASE) != 0};
    yx_tr_node *root = yx_tr_expression(&parser);
    yx_ser_result result = YX_SER_UNSUPPORTED;
    yx_chain_archive a = {0};
    if (parser.oom) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    if (!root || parser.failed || parser.at != parser.length || root->kind != YX_TR_CONCAT) goto done;
    literal_count = root->count;
    size_t variants = (p->modifiers & (YX_MOD_WIDE | YX_MOD_ASCII)) == (YX_MOD_WIDE | YX_MOD_ASCII) ? 2u : 1u;
    if (literal_count > SIZE_MAX / variants) goto done;
    wide_literal_count = literal_count * variants;
    if (wide_literal_count > SIZE_MAX / sizeof(*wide_literals) || literal_count > SIZE_MAX / sizeof(*starts)) goto done;
    literals = calloc(literal_count, sizeof(*literals));
    wide_literals = calloc(wide_literal_count, sizeof(*wide_literals));
    starts = malloc(literal_count * sizeof(*starts));
    ends = malloc(literal_count * sizeof(*ends));
    if (!literals || !wide_literals || !starts || !ends || !yx_chain_frames_reserve(&a, literal_count) || !yx_chain_pool_reserve(&a, literal_count)) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    size_t start = 0, count = 0;
    uint32_t minimum = 0, maximum = UINT32_MAX;
    bool finite_maximum = false;
    for (size_t i = 0; i < root->count; ++i) {
        const yx_tr_node *n = root->children[i];
        uint64_t low, high;
        if (i == start || n->kind != YX_TR_REPEAT || !yx_tr_any_span(n->children[0], &low, &high) || low != 1 || high != 1 || n->maximum <= 200) continue;
        yx_tr_node fragment = {.kind = YX_TR_CONCAT, .children = root->children + start, .count = i - start};
        if (yx_chain_minimum(&fragment) < 2) continue;
        starts[count] = start;
        ends[count] = i;
        a.frames[count].minimum = minimum;
        a.frames[count].maximum = maximum;
        a.frames[count].finite_maximum = finite_maximum;
        a.frames[count].previous = count ? count - 1 : 0;
        ++count;
        minimum = n->minimum;
        maximum = n->maximum;
        finite_maximum = n->finite_maximum;
        start = i + 1;
    }
    if (start < root->count) {
        yx_tr_node fragment = {.kind = YX_TR_CONCAT, .children = root->children + start, .count = root->count - start};
        if (count && yx_chain_minimum(&fragment) < 2) {
            ends[count - 1] = root->count;
        } else {
            starts[count] = start;
            ends[count] = root->count;
            a.frames[count].minimum = minimum;
            a.frames[count].maximum = maximum;
            a.frames[count].finite_maximum = finite_maximum;
            a.frames[count].previous = count ? count - 1 : 0;
            ++count;
        }
    }
    if (count < 2) goto done;
    a.frame_count = count;
    a.kind = (uint8_t)p->kind;
    a.names[0] = "default";
    a.names[1] = p->identifier;
    a.names[2] = r->identifier;
    a.atoms = calloc(YX_CHAIN_MAX_ATOMS, sizeof(*a.atoms));
    if (!a.atoms) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    uint16_t common =
        (p->kind == YX_PATTERN_REGEX && parser.saw_greedy ? 32 : 0) | ((p->modifiers & YX_MOD_NOCASE) ? 2 : 0) | ((p->modifiers & YX_MOD_FULLWORD) ? 24 : 0);
    for (size_t i = 0; i < count; ++i) {
        yx_tr_node fragment = {.kind = YX_TR_CONCAT, .children = root->children + starts[i], .count = ends[i] - starts[i]};
        if (!yx_chain_compile_frame(&a, i, &fragment, common, &code, &literals[i])) goto done;
    }
    if ((p->modifiers & YX_MOD_WIDE) && !yx_chain_expand_widths(&a, (p->modifiers & YX_MOD_ASCII) != 0, wide_literals)) goto done;
    uint8_t wasm[sizeof(yx_single_text_pattern_wasm)];
    memcpy(wasm, yx_single_text_pattern_wasm, sizeof(wasm));
    if (vba_order && !yx_reorder_pattern_wasm(wasm, sizeof(wasm), true)) goto done;
    a.wasm = wasm;
    a.wasm_length = sizeof(wasm);
    a.code = code.data;
    a.code_length = code.used;
    result = yx_chain_envelope(&a, data, length);
done:
    if (literals)
        for (size_t i = 0; i < literal_count; ++i) free(literals[i].data);
    if (wide_literals)
        for (size_t i = 0; i < wide_literal_count; ++i) free(wide_literals[i].data);
    free(literals);
    free(wide_literals);
    free(starts);
    free(ends);
    yx_chain_storage_destroy(&a);
    free(hex.data);
    free(code.data);
    yx_tr_destroy(root);
    return result;
}

static bool yx_chain_structure(yx_chain_archive *a)
{
    if (a->frame_count > SIZE_MAX / sizeof(size_t)) return false;
    size_t *children = malloc(a->frame_count * sizeof(*children));
    if (!children) return false;
    bool valid = false;
    for (size_t i = 0; i < a->frame_count; ++i) children[i] = SIZE_MAX;
    a->head_count = 0;
    for (size_t i = 0; i < a->frame_count; ++i) {
        const yx_chain_frame *f = &a->frames[i];
        bool head = f->variant == 2 || f->variant == 5;
        if (head) {
            if (a->head_count == 2 || i > 1) goto done;
            a->heads[a->head_count++] = i;
        } else {
            if (f->previous >= i || children[f->previous] != SIZE_MAX || (f->flags & 35u) != (a->frames[f->previous].flags & 35u)) goto done;
            children[f->previous] = i;
        }
        if ((f->flags & 8u) && !head) goto done;
    }
    if (!a->head_count) goto done;
    if (a->head_count == 2 && (a->frames[a->heads[0]].flags & 1u) == (a->frames[a->heads[1]].flags & 1u)) goto done;
    size_t visited = 0;
    for (size_t h = 0; h < a->head_count; ++h) {
        size_t at = a->heads[h], count = 0;
        bool fullword = (a->frames[at].flags & 8u) != 0;
        for (;;) {
            const yx_chain_frame *f = &a->frames[at];
            bool last = children[at] == SIZE_MAX;
            if (((f->flags & 4u) != 0) != last || ((f->flags & 16u) != 0) != (last && fullword)) goto done;
            ++visited;
            ++count;
            if (last) break;
            at = children[at];
        }
        if (count < 2) goto done;
    }
    valid = visited == a->frame_count;
done:
    free(children);
    return valid;
}
static bool yx_chain_read(const uint8_t *data, size_t length, yx_chain_archive *a)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    static const uint8_t before_kind[] = {0, 0, 1, 0, 0, 2, 0, 0, 1, 0, 1}, after_kind[] = {0, 0, 0, 0, 1};
    static const uint8_t globals[] = {0, 0, 1, 0}, suffix[] = {0, 0, 1, 1, 1, 0};
    yx_reader r = {data, length, 0, false, false};
    uint64_t n;
    uint8_t flag;
    memset(a, 0, sizeof(*a));
    if (!data || length < sizeof(magic) || memcmp(data, magic, sizeof(magic))) return false;
    r.at = sizeof(magic);
    if (!yx_expect_uint(&r, 3)) goto fail;
    for (size_t i = 0; i < 3; ++i)
        if (!yx_get_string(&r, &a->names[i])) goto fail;
    if (strcmp(a->names[0], "default") || !yx_valid_rule_name(a->names[2]) || !strcmp(a->names[2], "default") || a->names[1][0] != '$' ||
        !yx_valid_rule_name(a->names[1] + 1) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || n > length - r.at ||
        !yx_chain_pool_reserve(a, (size_t)n))
        goto fail;
    a->pool_count = (size_t)n;
    for (size_t i = 0; i < a->pool_count; ++i) {
        if (!yx_get_uint(&r, &n) || !n || n > length - r.at) goto fail;
        a->pool[i] = data + r.at;
        a->pool_lengths[i] = (size_t)n;
        r.at += (size_t)n;
    }
    if (!yx_get_uint(&r, &n) || n > length - r.at) goto fail;
    a->wasm = data + r.at;
    a->wasm_length = (size_t)n;
    r.at += (size_t)n;
    if (!yx_integer_wasm_bytes(&r, length, before_kind, sizeof(before_kind)) || !yx_get_uint(&r, &n) || n < 1 || n > 2) goto fail;
    a->kind = (uint8_t)n;
    if (!yx_integer_wasm_bytes(&r, length, after_kind, sizeof(after_kind)) || !yx_get_uint(&r, &n) || !n || n > (length - r.at) / 3 ||
        !yx_chain_frames_reserve(a, (size_t)n))
        goto fail;
    a->frame_count = (size_t)n;
    for (size_t i = 0; i < a->frame_count; ++i) {
        yx_chain_frame *f = &a->frames[i];
        if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n)) goto fail;
        if (!i) a->literal_only = n == 0;
        if (a->literal_only ? n != 0 : (n != 2 && n != 3 && n != 5 && n != 6)) goto fail;
        if (!a->literal_only && a->frame_count < 2) goto fail;
        f->variant = (uint8_t)n;
        if (f->variant == 0 || f->variant == 2 || f->variant == 3) {
            if (!yx_get_uint(&r, &n) || n >= a->pool_count) goto fail;
            f->literal_index = (size_t)n;
            f->literal = a->pool[n];
            f->literal_length = a->pool_lengths[n];
        }
        if (!a->literal_only && (f->variant == 3 || f->variant == 6)) {
            if (!yx_get_uint(&r, &n) || n >= i) goto fail;
            f->previous = (size_t)n;
            uint64_t kind;
            if (!yx_get_uint(&r, &kind) || kind > 1 || !yx_get_uint(&r, &n) || n > UINT32_MAX) goto fail;
            f->minimum = (uint32_t)n;
            if (kind) f->maximum = UINT32_MAX;
            else {
                if (!yx_get_uint(&r, &n) || n > UINT32_MAX) goto fail;
                f->maximum = (uint32_t)n;
                f->finite_maximum = n == UINT32_MAX;
            }
            if (f->maximum < f->minimum || f->maximum <= 200) goto fail;
        }
        if (a->literal_only && !yx_expect_uint(&r, 0)) goto fail;
        if (!yx_get_uint(&r, &n)) goto fail;
        if (a->literal_only) {
            if ((n & ~27u) || ((n & 24u) && (n & 24u) != 24u)) goto fail;
        } else if ((n & ~127u) || ((f->variant == 2 || f->variant == 3) && (n & 64u))) goto fail;
        f->flags = (uint16_t)n;
        if (a->kind == 1 && (n & 59u)) goto fail;
    }
    if (!a->literal_only && !yx_chain_structure(a)) goto fail;
    if (!yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || !n || n > YX_CHAIN_MAX_ATOMS || n > length - r.at)
        goto fail;
    a->atom_count = (size_t)n;
    a->atoms = calloc(a->atom_count, sizeof(*a->atoms));
    if (!a->atoms) goto fail;
    for (size_t i = 0; i < a->atom_count; ++i) {
        yx_archive_regexp_atom *b = &a->atoms[i].atom;
        if (!yx_get_uint(&r, &n) || n >= a->frame_count) goto fail;
        a->atoms[i].frame = (size_t)n;
        if (!yx_get_uint(&r, &n) || n > sizeof(b->bytes) || n > length - r.at) goto fail;
        b->length = (size_t)n;
        memcpy(b->bytes, data + r.at, b->length);
        r.at += b->length;
        if (!yx_get_u8(&r, &flag) || flag > 1) goto fail;
        b->exact = flag != 0;
        if (!yx_get_uint(&r, &n) || n > UINT16_MAX) goto fail;
        b->backtrack = (uint16_t)n;
        if (!yx_get_u8(&r, &flag) || flag > 1) goto fail;
        b->has_forward = flag != 0;
        if (flag) {
            if (!yx_get_uint(&r, &n) || !n || n > UINT32_MAX) goto fail;
            b->forward = (size_t)n - 1;
        }
        if (!yx_get_u8(&r, &flag) || flag > 1) goto fail;
        b->has_backward = flag != 0;
        if (flag) {
            if (!yx_get_uint(&r, &n) || !n || n > UINT32_MAX) goto fail;
            b->backward = (size_t)n - 1;
        }
    }
    if (!yx_get_uint(&r, &n) || n > length - r.at) goto fail;
    a->code = data + r.at;
    a->code_length = (size_t)n;
    r.at += (size_t)n;
    if (!yx_expect_uint(&r, sizeof(globals)) || !yx_integer_wasm_bytes(&r, length, globals, sizeof(globals)) || !yx_get_uint(&r, &n) || n > length - r.at) goto fail;
    r.at += (size_t)n;
    if (!yx_integer_wasm_bytes(&r, length, suffix, sizeof(suffix))) goto fail;
    a->archive_length = r.at;
    return true;
fail:
    yx_chain_destroy(a);
    return false;
}
static bool yx_chain_atom_equal(const yx_archive_regexp_atom *a, const yx_archive_regexp_atom *b, size_t base)
{
    return a->length == b->length && !memcmp(a->bytes, b->bytes, a->length) && a->exact == b->exact && a->backtrack == b->backtrack && a->has_forward == b->has_forward &&
           (!a->has_forward || a->forward == b->forward + base) && a->has_backward == b->has_backward && (!a->has_backward || a->backward == b->backward + base);
}
/* A bounded hex jump token "[a]" or "[a-b]" of length bytes. */
static bool yx_chain_hex_jump(const char *token, size_t length, unsigned long *min, unsigned long *max)
{
    char *end;
    if (length < 3 || token[0] != '[' || token[length - 1] != ']' || !isdigit((unsigned char)token[1])) return false;
    *min = strtoul(token + 1, &end, 10);
    if (*end == ']') {
        *max = *min;
        return end == token + length - 1;
    }
    if (*end != '-' || !isdigit((unsigned char)end[1])) return false;
    *max = strtoul(end + 1, &end, 10);
    return end == token + length - 1 && *max >= *min;
}
static bool yx_chain_hex_jump_text(yx_writer *w, unsigned long min, unsigned long max)
{
    char token[64];
    if (!max) return true;
    if (min == max) snprintf(token, sizeof(token), "[%lu] ", min);
    else snprintf(token, sizeof(token), "[%lu-%lu] ", min, max);
    return yx_tr_text(w, token);
}
/* One space-terminated token of yx_tr_hex_source text: the "(" that open
 * alternatives are glued to the token that follows them. */
typedef struct {
    const char *core;
    size_t open, length;
} yx_chain_hex_token;
static bool yx_chain_hex_token_at(const char *s, size_t n, size_t *at, yx_chain_hex_token *t)
{
    size_t start = *at;
    while (*at < n && s[*at] != ' ') ++*at;
    if (*at == n) return false;
    t->open = 0;
    while (start + t->open < *at && s[start + t->open] == '(') ++t->open;
    t->core = s + start + t->open;
    t->length = *at - start - t->open;
    ++*at;
    return true;
}
/* Thompson code does not tell `?? ??` from `[2]`, but hex source cannot
 * begin or end a pattern or an alternative with a jump, and a jump next to
 * a chain gap would merge into it. Such jumps are written back with ?? at
 * those edges. hex is token text as yx_tr_hex_source writes it. */
static bool yx_chain_hex_edges(const yx_writer *hex, yx_writer *text)
{
    const char *s = (const char *)hex->data;
    size_t n = hex->used, at = 0;
    yx_chain_hex_token previous = {NULL, 0, 0}, current, next;
    bool has_previous = false, has_next;
    if (!n || s[n - 1] != ' ') return yx_put_bytes(text, hex->data, n);
    if (!yx_chain_hex_token_at(s, n, &at, &current)) return false;
    for (;;) {
        size_t after = at;
        has_next = after < n && yx_chain_hex_token_at(s, n, &after, &next);
        unsigned long a, b;
        bool lead = !has_previous || current.open || (previous.length == 1 && previous.core[0] == '|');
        bool trail = !has_next || (!next.open && next.length == 1 && (next.core[0] == '|' || next.core[0] == ')'));
        for (size_t i = 0; i < current.open; ++i)
            if (!yx_put_u8(text, '(')) return false;
        if (yx_chain_hex_jump(current.core, current.length, &a, &b) && (lead || trail) && a >= (lead && trail ? 2u : 1u)) {
            unsigned long edges = lead && trail ? 2u : 1u;
            if ((lead && !yx_tr_text(text, "?? ")) || !yx_chain_hex_jump_text(text, a - edges, b - edges) || (trail && !yx_tr_text(text, "?? "))) return false;
        } else if (!yx_put_bytes(text, current.core, current.length) || !yx_put_u8(text, ' ')) return false;
        if (!has_next) return true;
        previous = current;
        has_previous = true;
        current = next;
        at = after;
    }
}
/* The Thompson forward and backward programs of a piece that start at
 * begin: text receives the forward one and end the end of the backward one.
 * Every atom of the piece points into them, and both hold the same literal
 * bytes (residue bytes misread as pattern bytes appear only forward). */
static bool yx_chain_thompson_programs(const yx_chain_archive *a, size_t first, size_t count, size_t begin, size_t *end, yx_writer *text)
{
    yx_writer forward = {0}, backward = {0};
    size_t forward_end = begin, at;
    bool ok = false;
    while (forward_end < a->code_length) {
        size_t width = yx_tr_instruction_size(a->code + forward_end, a->code_length - forward_end);
        if (!width) goto done;
        if (a->code[forward_end] == 0xaa && a->code[forward_end + 1] == 0) break;
        forward_end += width;
    }
    if (forward_end + 2 >= a->code_length || !yx_tr_decode_region(a->code, begin, forward_end, &forward, 0)) goto done;
    at = forward_end + 2;
    while (at < a->code_length) {
        size_t width = yx_tr_instruction_size(a->code + at, a->code_length - at);
        if (!width) goto done;
        if (a->code[at] == 0xaa && a->code[at + 1] == 0) break;
        at += width;
    }
    if (at + 2 > a->code_length || !yx_tr_decode_region(a->code, forward_end + 2, at, &backward, 0)) goto done;
    at += 2;
    for (size_t i = 0; i < count; ++i) {
        const yx_archive_regexp_atom *b = &a->atoms[first + i].atom;
        if (!b->has_forward || !b->has_backward || b->forward < begin || b->forward > forward_end || b->backward < forward_end + 2 || b->backward > at - 2) goto done;
    }
    if (!yx_put_u8(&forward, 0) || !yx_put_u8(&backward, 0) || !yx_tr_same_literals((const char *)forward.data, (const char *)backward.data)) goto done;
    --forward.used;
    *text = forward;
    forward = (yx_writer){0};
    *end = at;
    ok = true;
done:
    free(forward.data);
    free(backward.data);
    return ok;
}
/* Whether code[begin, end) is what a failed FastVM compile leaves for the
 * pieces it lists: one forward sequence, or a backward sequence (the pieces
 * before the atom piece, in reverse order) up to first_end and then a
 * forward one. Compiling those pieces again must fail with the same bytes. */
static bool yx_chain_residue_consistent(const yx_chain_archive *a, size_t begin, size_t first_end, size_t end)
{
    yx_fast_program *p = calloc(1, sizeof(*p));
    yx_writer residue = {0};
    size_t at = begin;
    bool ok = false;
    if (!p) return false;
    if (!yx_fast_read_sequence(p, a->code, a->code_length, &at) || at != first_end) goto done;
    if (end != first_end) {
        for (size_t i = 0; i < p->count / 2; ++i) {
            yx_fast_piece swap = p->pieces[i];
            p->pieces[i] = p->pieces[p->count - i - 1];
            p->pieces[p->count - i - 1] = swap;
        }
        if (!yx_fast_read_sequence(p, a->code, a->code_length, &at) || at != end) goto done;
    }
    ok = !yx_fast_compile_mode(p, true) && yx_chain_fast_residue(p, &residue) && residue.used == end - begin && !memcmp(residue.data, a->code + begin, residue.used);
done:
    free(residue.data);
    yx_fast_program_destroy(p);
    return ok;
}
/* The Thompson compiler unrolls e{n,} into n - 1 copies of e and e+, which
 * decodes as copies around (e)+; in a chain piece that turns `[218-]` into
 * 217 ?? and `[1-]`, a jump that splits the rebuilt pattern elsewhere.
 * rolled receives the forward program at start decoded with e{n,} rolled up
 * when it differs from the unrolled text and compiles back to exactly this
 * piece's code and atoms (Compiler::c_chain compiles every piece alone). */
static bool yx_chain_rolled_piece(const yx_chain_archive *a, size_t first, size_t count, size_t start, size_t end, const yx_writer *unrolled, yx_writer *rolled)
{
    size_t forward_end = start;
    yx_tr_program program = {0};
    bool greedy = false, same = false;
    while (forward_end < end) {
        size_t width = yx_tr_instruction_size(a->code + forward_end, end - forward_end);
        if (!width) return false;
        if (a->code[forward_end] == 0xaa && a->code[forward_end + 1] == 0) break;
        forward_end += width;
    }
    if (forward_end + 2 > end || !yx_tr_decode_region_mode(a->code, start, forward_end, rolled, 0, true) ||
        (rolled->used == unrolled->used && !memcmp(rolled->data, unrolled->data, rolled->used)) || !yx_put_u8(rolled, 0))
        return false;
    if (yx_tr_compile((const char *)rolled->data, true, false, &program, &greedy) && program.forward.used == forward_end + 2 - start &&
        program.backward.used == end - forward_end - 2 && program.atoms.count == count && !memcmp(program.forward.data, a->code + start, program.forward.used) &&
        !memcmp(program.backward.data, a->code + forward_end + 2, program.backward.used)) {
        same = true;
        for (size_t i = 0; i < count && same; ++i) {
            const yx_tr_atom_entry *b = &program.atoms.items[i];
            const yx_archive_regexp_atom *atom = &a->atoms[first + i].atom;
            same = atom->length == b->length && !memcmp(atom->bytes, b->bytes, b->length) && atom->exact == b->exact && atom->has_forward && atom->has_backward &&
                   atom->forward == start + b->forward && atom->backward == start + program.forward.used + b->backward;
        }
    }
    yx_tr_program_free(&program);
    --rolled->used;
    return same;
}
static bool yx_chain_decode_frame(const yx_chain_archive *a, size_t index, size_t *cursor, size_t *atom_at, yx_writer *text)
{
    const yx_chain_frame *f = &a->frames[index];
    size_t first = *atom_at;
    while (*atom_at < a->atom_count && a->atoms[*atom_at].frame == index) ++*atom_at;
    size_t count = *atom_at - first;
    if (!count) return false;
    if (f->variant == 2 || f->variant == 3) {
        if (count != 1) return false;
        const yx_archive_regexp_atom *atom = &a->atoms[first].atom;
        if (atom->has_forward || atom->has_backward || !atom->length || atom->length > 4 || atom->backtrack > f->literal_length ||
            atom->length > f->literal_length - atom->backtrack || memcmp(atom->bytes, f->literal + atom->backtrack, atom->length) ||
            atom->exact != (atom->length == f->literal_length && !(f->flags & 24u)))
            return false;
        uint8_t *masks = malloc(f->literal_length);
        if (!masks) return false;
        memset(masks, 255, f->literal_length);
        yx_fast_literal literal = {(uint8_t *)f->literal, masks, f->literal_length, false};
        size_t offset, width;
        yx_fast_best_atom(&literal, &offset, &width);
        bool ok = offset == atom->backtrack && width == atom->length && yx_fast_source_literal(text, &literal, a->kind == 1);
        free(masks);
        return ok;
    }
    size_t begin = *cursor, end = begin;
    yx_writer source = {0};
    bool ok = false;
    if (f->flags & 64u) {
        yx_fast_program *p = calloc(1, sizeof(*p));
        if (!p) return false;
        p->flags = f->flags & ~4u;
        const yx_archive_regexp_atom *atom = &a->atoms[first].atom;
        if (!atom->has_forward || atom->forward < begin || atom->forward >= a->code_length) goto fast_done;
        if (atom->has_backward) {
            if (atom->backward != begin || !yx_fast_read_sequence(p, a->code, a->code_length, &end) || end != atom->forward) goto fast_done;
            for (size_t i = 0; i < p->count / 2; ++i) {
                yx_fast_piece swap = p->pieces[i];
                p->pieces[i] = p->pieces[p->count - i - 1];
                p->pieces[p->count - i - 1] = swap;
            }
        } else if (atom->forward != begin) goto fast_done;
        bool dotall = false;
        if (!yx_fast_read_sequence(p, a->code, a->code_length, &end) || !yx_fast_compile_mode(p, true) || p->code.used != end - begin ||
            memcmp(p->code.data, a->code + begin, p->code.used) || p->atom_count != count || !yx_fast_source(p, a->kind == 1, &source, &dotall))
            goto fast_done;
        for (size_t i = 0; i < count; ++i)
            if (!yx_chain_atom_equal(&a->atoms[first + i].atom, &p->atoms[i], begin)) goto fast_done;
        if (a->kind == 2 && !dotall) {
            for (size_t i = 0; i < source.used; ++i) {
                if (source.data[i] == '.') {
                    if (!yx_tr_text(text, "[^\\x0a]")) goto fast_done;
                } else if (!yx_put_u8(text, source.data[i])) goto fast_done;
            }
        } else if (!yx_put_bytes(text, source.data, source.used)) goto fast_done;
        ok = true;
    fast_done:
        yx_fast_program_destroy(p);
    } else {
        /* A failed FastVM attempt may leave one or two unreferenced verifier
         * sequences (backward, then forward) in front of the Thompson code.
         * Longer residues are tried first; a residue must be exactly what
         * FastVM leaves when it rejects the pieces it describes. */
        size_t candidates[3] = {begin, 0, 0}, candidate_count = 1, at = begin;
        for (unsigned sequence = 0; sequence < 2; ++sequence) {
            if (at >= a->code_length || a->code[at] < 1 || a->code[at] > 7) break;
            yx_fast_program *probe = calloc(1, sizeof(*probe));
            if (!probe) goto done;
            bool parsed = yx_fast_read_sequence(probe, a->code, a->code_length, &at) && at < a->code_length;
            yx_fast_program_destroy(probe);
            bool unused = parsed;
            for (size_t i = 0; i < count && unused; ++i) {
                const yx_archive_regexp_atom *b = &a->atoms[first + i].atom;
                if (!b->has_forward || !b->has_backward || b->forward < at || b->backward < at) unused = false;
            }
            if (!unused) break;
            candidates[candidate_count++] = at;
        }
        bool decoded = false;
        size_t start = begin;
        for (size_t c = candidate_count; c-- > 0 && !decoded;) {
            free(source.data);
            source = (yx_writer){0};
            decoded =
                yx_chain_thompson_programs(a, first, count, candidates[c], &end, &source) && (!c || yx_chain_residue_consistent(a, begin, candidates[1], candidates[c]));
            start = candidates[c];
        }
        if (!decoded) goto done;
        yx_writer rolled = {0};
        if (yx_chain_rolled_piece(a, first, count, start, end, &source, &rolled)) {
            free(source.data);
            source = rolled;
        } else free(rolled.data);
        if (a->kind == 1) {
            if (!yx_put_u8(&source, 0)) goto done;
            yx_tr_parser parser = {.text = source.data, .length = source.used - 1, .literal_alternations = true};
            yx_tr_node *n = yx_tr_expression(&parser);
            yx_writer hex = {0};
            ok = n && !parser.failed && !parser.oom && parser.at == parser.length && yx_tr_hex_source(n, &hex) && yx_chain_hex_edges(&hex, text);
            free(hex.data);
            yx_tr_destroy(n);
        } else ok = yx_put_bytes(text, source.data, source.used);
    }
done:
    free(source.data);
    if (ok) *cursor = end;
    return ok;
}
static bool yx_chain_normalize_path(const yx_chain_archive *a, size_t head, yx_chain_archive *out, yx_writer *storage)
{
    memset(out, 0, sizeof(*out));
    out->kind = a->kind;
    out->code = a->code;
    out->code_length = a->code_length;
    if (!yx_chain_frames_reserve(out, a->frame_count)) return false;
    out->atoms = calloc(YX_CHAIN_MAX_ATOMS, sizeof(*out->atoms));
    if (!out->atoms) return false;
    for (size_t current = head;;) {
        const yx_chain_frame *original = &a->frames[current];
        bool wide = (original->flags & 1u) != 0;
        size_t index = out->frame_count++;
        yx_chain_frame *f = &out->frames[index];
        *f = *original;
        f->flags &= ~1u;
        f->previous = index ? index - 1 : 0;
        size_t first = 0;
        while (first < a->atom_count && a->atoms[first].frame < current) ++first;
        if (first == a->atom_count || a->atoms[first].frame != current) return false;
        bool literal = f->variant == 2 || f->variant == 3;
        if (literal) {
            size_t cursor = 0, atom_at = first;
            yx_writer ignored = {0};
            bool valid = yx_chain_decode_frame(a, current, &cursor, &atom_at, &ignored);
            free(ignored.data);
            if (!valid) return false;
            if (wide) {
                if (f->literal_length % 2) return false;
                for (size_t j = 0; j < f->literal_length; j += 2) {
                    if (f->literal[j + 1] || !yx_put_u8(&storage[index], f->literal[j])) return false;
                }
                f->literal = storage[index].data;
                f->literal_length = storage[index].used;
            }
            size_t start = out->atom_count;
            if (!yx_literal_frame_atoms(out, index)) return false;
            if (f->flags & 24u)
                for (size_t j = start; j < out->atom_count; ++j) out->atoms[j].atom.exact = false;
        } else
            for (size_t j = first; j < a->atom_count && a->atoms[j].frame == current; ++j) {
                yx_archive_regexp_atom atom = a->atoms[j].atom;
                if (wide) {
                    if (atom.length % 2 || atom.backtrack % 2) return false;
                    for (size_t k = 0; k < atom.length; k += 2) {
                        if (atom.bytes[k + 1]) return false;
                        atom.bytes[k / 2] = atom.bytes[k];
                    }
                    atom.length /= 2;
                    atom.backtrack /= 2;
                }
                if (!yx_chain_add_atom(out, index, &atom)) return false;
            }
        size_t next = SIZE_MAX;
        for (size_t j = current + 1; j < a->frame_count; ++j)
            if ((a->frames[j].variant == 3 || a->frames[j].variant == 6) && a->frames[j].previous == current) {
                next = j;
                break;
            }
        if (next == SIZE_MAX) break;
        current = next;
    }
    return true;
}
static bool yx_chain_same_paths(const yx_chain_archive *a, const yx_chain_archive *b)
{
    if (a->frame_count != b->frame_count || a->atom_count != b->atom_count) return false;
    for (size_t i = 0; i < a->frame_count; ++i) {
        const yx_chain_frame *x = &a->frames[i], *y = &b->frames[i];
        if (x->variant != y->variant || x->flags != y->flags || x->minimum != y->minimum || x->maximum != y->maximum || x->finite_maximum != y->finite_maximum ||
            x->literal_length != y->literal_length || (x->literal_length && memcmp(x->literal, y->literal, x->literal_length)))
            return false;
    }
    for (size_t i = 0; i < a->atom_count; ++i)
        if (a->atoms[i].frame != b->atoms[i].frame || !yx_chain_atom_equal(&a->atoms[i].atom, &b->atoms[i].atom, 0)) return false;
    return true;
}
static bool yx_literal_decode_source(const yx_chain_archive *a, yx_writer *source, bool *wide, bool *ascii_wide)
{
    if (a->code_length) return false;
    yx_chain_archive expected = *a;
    expected.atom_count = 0;
    expected.atoms = calloc(YX_CHAIN_MAX_ATOMS, sizeof(*expected.atoms));
    if (!expected.atoms) return false;
    bool valid = true;
    for (size_t i = 0; i < a->frame_count && valid; ++i) valid = yx_literal_frame_atoms(&expected, i);
    if (expected.atom_count != a->atom_count) valid = false;
    for (size_t i = 0; i < a->atom_count && valid; ++i)
        if (expected.atoms[i].frame != a->atoms[i].frame || !yx_chain_atom_equal(&a->atoms[i].atom, &expected.atoms[i].atom, 0)) valid = false;
    free(expected.atoms);
    if (!valid) return false;
    *wide = (a->frames[0].flags & 1u) != 0;
    *ascii_wide = false;
    for (size_t i = 1; i < a->frame_count; ++i)
        if ((a->frames[i].flags & 1u) != (*wide ? 1u : 0u)) *ascii_wide = true;
    if (*ascii_wide && (*wide || a->frame_count % 2)) return false;
    size_t stride = *ascii_wide ? 2 : 1, alternatives = a->frame_count / stride;
    if (a->kind == 1 && alternatives > 1 && !yx_tr_text(source, "(")) return false;
    for (size_t i = 0; i < a->frame_count; i += stride) {
        const yx_chain_frame *f = &a->frames[i];
        if ((f->flags & ~1u) != (a->frames[0].flags & ~1u) || (f->flags & 1u) != (*wide ? 1u : 0u)) return false;
        if (*ascii_wide) {
            const yx_chain_frame *w = &a->frames[i + 1];
            if (w->flags != (f->flags | 1u) || w->literal_length != f->literal_length * 2) return false;
            for (size_t j = 0; j < f->literal_length; ++j)
                if (w->literal[j * 2] != f->literal[j] || w->literal[j * 2 + 1]) return false;
        }
        if (i && !yx_tr_text(source, "|")) return false;
        if (*wide && f->literal_length % 2) return false;
        for (size_t j = 0; j < f->literal_length; j += *wide ? 2 : 1) {
            if (*wide && f->literal[j + 1]) return false;
            if (a->kind == 1) {
                char text[4];
                snprintf(text, sizeof(text), "%02X ", f->literal[j]);
                if (!yx_tr_text(source, text)) return false;
            } else if (f->literal[j] >= 32 && f->literal[j] < 127 && !strchr(".\\/[](){}?*+^$|", f->literal[j])) {
                if (!yx_put_u8(source, f->literal[j])) return false;
            } else if (!yx_tr_hex_text(source, f->literal[j])) return false;
        }
    }
    return a->kind != 1 || alternatives <= 1 || yx_tr_text(source, ")");
}
static yx_ser_result yx_decode_chained_pattern(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    yx_chain_archive a;
    yx_writer source = {0}, *normalized_literals[2] = {NULL, NULL};
    yx_chain_archive *normalized = NULL;
    const yx_chain_archive *view = &a;
    uint8_t *expected = NULL;
    size_t expected_length = 0;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    if (!yx_chain_read(data, length, &a)) return result;
    size_t cursor = 0, atom_at = 0;
    bool wide = false, ascii_wide = false;
    if (a.literal_only) {
        if (!yx_literal_decode_source(&a, &source, &wide, &ascii_wide)) goto done;
        atom_at = a.atom_count;
    } else if (a.head_count == 2 || (a.frames[a.heads[0]].flags & 1u)) {
        normalized = calloc(2, sizeof(*normalized));
        if (!normalized) {
            result = YX_SER_NO_MEMORY;
            goto done;
        }
        for (size_t h = 0; h < a.head_count; ++h) {
            if (a.frame_count > SIZE_MAX / sizeof(**normalized_literals)) goto done;
            normalized_literals[h] = calloc(a.frame_count, sizeof(**normalized_literals));
            if (!normalized_literals[h]) {
                result = YX_SER_NO_MEMORY;
                goto done;
            }
            if (!yx_chain_normalize_path(&a, a.heads[h], &normalized[h], normalized_literals[h])) goto done;
        }
        if (a.head_count == 2 && !yx_chain_same_paths(&normalized[0], &normalized[1])) goto done;
        view = &normalized[0];
        wide = true;
        ascii_wide = a.head_count == 2;
    }
    for (size_t i = 0; !a.literal_only && i < view->frame_count; ++i) {
        if (i) {
            char gap[96];
            const yx_chain_frame *f = &view->frames[i];
            if (a.kind == 1) {
                if (yx_chain_unbounded(f)) snprintf(gap, sizeof(gap), " [%u-] ", f->minimum);
                else snprintf(gap, sizeof(gap), " [%u-%u] ", f->minimum, f->maximum);
            } else {
                if (yx_chain_unbounded(f)) snprintf(gap, sizeof(gap), ".{%u,}%s", f->minimum, (f->flags & 32u) ? "" : "?");
                else snprintf(gap, sizeof(gap), ".{%u,%u}%s", f->minimum, f->maximum, (f->flags & 32u) ? "" : "?");
            }
            if (!yx_tr_text(&source, gap)) goto done;
        }
        if (!yx_chain_decode_frame(view, i, &cursor, &atom_at, &source)) goto done;
    }
    if (cursor != view->code_length || atom_at != view->atom_count) goto done;
    for (unsigned order = 0; order < 2; ++order) {
        uint8_t wasm[sizeof(yx_single_text_pattern_wasm)];
        memcpy(wasm, yx_single_text_pattern_wasm, sizeof(wasm));
        if (order && !yx_reorder_pattern_wasm(wasm, sizeof(wasm), true)) continue;
        a.wasm = wasm;
        a.wasm_length = sizeof(wasm);
        result = yx_chain_envelope(&a, &expected, &expected_length);
        if (result != YX_SER_SUCCESS) goto done;
        bool matches = expected_length == a.archive_length && !memcmp(data, expected, expected_length);
        free(expected);
        expected = NULL;
        if (!matches) {
            result = YX_SER_UNSUPPORTED;
            continue;
        }
        yx_ser_rule *r = calloc(1, sizeof(*r));
        if (!r) {
            result = YX_SER_NO_MEMORY;
            goto done;
        }
        r->namespace_name = a.names[0];
        a.names[0] = NULL;
        r->pattern_identifier = a.names[1];
        a.names[1] = NULL;
        r->identifier = a.names[2];
        a.names[2] = NULL;
        r->pattern_bytes = source.data;
        source.data = NULL;
        r->pattern_length = source.used;
        r->single_text_pattern = true;
        r->single_regex_fast = a.kind == 2;
        r->single_hex_fast = a.kind == 1;
        r->single_regex_dotall = a.kind == 2 && !a.literal_only;
        r->wide_single_pattern = wide || ascii_wide;
        r->ascii_wide_single_pattern = ascii_wide;
        r->nocase_single_pattern = (a.frames[0].flags & 2u) != 0;
        r->fullword_single_pattern = (a.frames[0].flags & (a.literal_only ? 24u : 8u)) != 0;
        r->preserve_serialized_prefix = true;
        r->truth = true;
        *rules = r;
        *rule_count = 1;
        result = YX_SER_SUCCESS;
        goto done;
    }
done:
    if (normalized) {
        yx_chain_storage_destroy(&normalized[0]);
        yx_chain_storage_destroy(&normalized[1]);
        free(normalized);
    }
    for (size_t h = 0; h < 2; ++h) {
        if (normalized_literals[h])
            for (size_t i = 0; i < a.frame_count; ++i) free(normalized_literals[h][i].data);
        free(normalized_literals[h]);
    }
    free(expected);
    free(source.data);
    yx_chain_destroy(&a);
    return result;
}
#endif
