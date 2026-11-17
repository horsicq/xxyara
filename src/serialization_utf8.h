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
 * The UTF-8 sequence code follows lib/src/re/thompson/compiler.rs
 * (visit_post_class, emit_utf8_seq, emit_utf8_range) and lib/src/re/hir.rs
 * (any_byte, any_byte_except_newline, class_to_masked_byte) in YARA-X v1.23.0.
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

/* Unicode classes (YX_TR_SCALAR_CLASS) in the Thompson compiler: regex-syntax's
 * Utf8Sequences and the PikeVM code YARA-X emits for them. Included by
 * serialization_thompson.h right before yx_tr_compile_node. */
#ifndef XXYARA_SERIALIZATION_UTF8_H
#define XXYARA_SERIALIZATION_UTF8_H

/* A class's ranges come from yx_re_class_ranges_gap, which splits them at
 * the surrogate gap. regex-syntax's ClassUnicodeRange is a range of chars: a
 * negated class or `.` holds one range across the gap (char increment skips
 * the surrogates). Range i ends where such a merged range ends. The class
 * [\x{0}-\x{D7FF}\x{E000}-\x{10FFFF}] has two ranges (gap_split): it is not
 * any_byte, so it does not match bytes that are not UTF-8. */
static bool yx_u8_joins(const yx_tr_node *node, const yx_re_range *ranges, size_t count, size_t i)
{
    return !node->gap_split && i + 1 < count && ranges[i].last == 0xd7ff && ranges[i + 1].first == 0xe000;
}

/* re::hir::any_byte for a Unicode class: its first range is \0-\u{10FFFF}. */
static bool yx_u8_any(const yx_tr_node *node)
{
    if (!node || node->kind != YX_TR_SCALAR_CLASS || !node->length) return false;
    const yx_re_range *r = (const yx_re_range *)node->bytes;
    size_t end = 0;
    while (yx_u8_joins(node, r, node->length, end)) ++end;
    return r[0].first == 0 && r[end].last == 0x10ffff;
}

/* re::hir::any_byte_except_newline for a Unicode class: exactly the ranges
 * \0-\x09 and \x0B-\u{10FFFF}. */
static bool yx_u8_any_except_newline(const yx_tr_node *node)
{
    if (!node || node->kind != YX_TR_SCALAR_CLASS || node->length < 2) return false;
    const yx_re_range *r = (const yx_re_range *)node->bytes;
    size_t end = 1;
    while (yx_u8_joins(node, r, node->length, end)) ++end;
    return r[0].first == 0 && r[0].last == 9 && r[1].first == 11 && r[end].last == 0x10ffff &&
           end + 1 == node->length;
}

/* The repetition gaps that the FastVM splitter and split_at_large_gaps read:
 * a byte class of every byte, or of every byte but \n, or a Unicode class
 * that any_byte or any_byte_except_newline accepts. *newline tells whether
 * the gap accepts \n. */
static bool yx_tr_gap_class(const yx_tr_node *node, bool *newline)
{
    bool any = false;
    if (!node) return false;
    if (node->kind == YX_TR_SCALAR_CLASS) {
        any = yx_u8_any(node);
        if (!any && !yx_u8_any_except_newline(node)) return false;
    } else {
        if (node->kind != YX_TR_CLASS || node->unicode_class) return false;
        for (unsigned b = 0; b < 256; ++b)
            if (b != 10 && !yx_tr_has(node->bitmap, b)) return false;
        any = yx_tr_has(node->bitmap, 10);
    }
    if (newline) *newline = any;
    return true;
}

/* One regex-syntax Utf8Sequence: a byte range per encoded byte. */
typedef struct { uint8_t first[4], last[4], length; } yx_u8_seq;
enum { YX_U8_MAX_SEQUENCES = 255 }; /* re::MAX_ALTERNATIVES */

static unsigned yx_u8_encode(uint32_t cp, uint8_t out[4])
{
    if (cp < 0x80) { out[0] = (uint8_t)cp; return 1; }
    if (cp < 0x800) {
        out[0] = (uint8_t)(0xc0 | (cp >> 6));
        out[1] = (uint8_t)(0x80 | (cp & 63)); return 2;
    }
    if (cp < 0x10000) {
        out[0] = (uint8_t)(0xe0 | (cp >> 12));
        out[1] = (uint8_t)(0x80 | ((cp >> 6) & 63));
        out[2] = (uint8_t)(0x80 | (cp & 63)); return 3;
    }
    out[0] = (uint8_t)(0xf0 | (cp >> 18));
    out[1] = (uint8_t)(0x80 | ((cp >> 12) & 63));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 63));
    out[3] = (uint8_t)(0x80 | (cp & 63)); return 4;
}

/* Utf8Sequences::next for one scalar range, in the iterator's order: every
 * split pushes its second half, so the first half is finished first.
 * Returns 0 when the class needs more than YX_U8_MAX_SEQUENCES. */
static int yx_u8_range(uint32_t first, uint32_t last, yx_u8_seq *out, size_t *count, unsigned depth)
{
    if (first > last || depth > 64) return first > last;
    if (first < 0xe000 && last > 0xd7ff)
        return yx_u8_range(first, 0xd7ff, out, count, depth + 1) &&
               yx_u8_range(0xe000, last, out, count, depth + 1);
    static const uint32_t maxima[] = {0x7f, 0x7ff, 0xffff};
    for (unsigned i = 0; i < 3; ++i)
        if (first <= maxima[i] && maxima[i] < last)
            return yx_u8_range(first, maxima[i], out, count, depth + 1) &&
                   yx_u8_range(maxima[i] + 1, last, out, count, depth + 1);
    if (last > 0x7f)
        for (unsigned i = 1; i < 4; ++i) {
            uint32_t m = (1u << (6 * i)) - 1;
            if ((first & ~m) == (last & ~m)) continue;
            if (first & m)
                return yx_u8_range(first, first | m, out, count, depth + 1) &&
                       yx_u8_range((first | m) + 1, last, out, count, depth + 1);
            if ((last & m) != m)
                return yx_u8_range(first, (last & ~m) - 1, out, count, depth + 1) &&
                       yx_u8_range(last & ~m, last, out, count, depth + 1);
        }
    if (*count == YX_U8_MAX_SEQUENCES) return 0;
    yx_u8_seq *seq = &out[(*count)++];
    seq->length = (uint8_t)yx_u8_encode(first, seq->first);
    (void)yx_u8_encode(last, seq->last);
    return 1;
}

/* The sequences of every range of the class, in class order. False when
 * there are more than YX_U8_MAX_SEQUENCES (YARA-X: Error::TooLarge). */
static bool yx_u8_sequences(const yx_re_range *ranges, size_t count, yx_u8_seq *out, size_t *n)
{
    *n = 0;
    for (size_t i = 0; i < count; ++i)
        if (!yx_u8_range(ranges[i].first, ranges[i].last, out, n, 0)) return false;
    return true;
}

/* emit_utf8_range: a single byte is a literal (0xAA doubled), a range that
 * class_to_masked_byte accepts is MASKED_BYTE, any other is CLASS_RANGES. */
static bool yx_u8_byte_range(yx_writer *w, uint8_t first, uint8_t last)
{
    if (first == last) return yx_put_u8(w, first) && (first != 0xaa || yx_put_u8(w, first));
    unsigned neg_mask = (unsigned)(first ^ last), bits = 0;
    bool masked = true;
    for (unsigned b = first; b <= last; ++b) if ((b & first) != first) { masked = false; break; }
    for (unsigned k = 0; k < 8; ++k) bits += (neg_mask >> k) & 1u;
    if (masked && (1u << bits) == (unsigned)(last - first) + 1u)
        return yx_tr_instr(w, 6, 0, 0) && yx_put_u8(w, first) && yx_put_u8(w, (uint8_t)~neg_mask);
    return yx_tr_instr(w, 9, 0, 0) && yx_put_u8(w, 1) && yx_put_u8(w, first) && yx_put_u8(w, last);
}

/* emit_utf8_seq: the byte ranges forward, and in reverse order backward. */
static bool yx_u8_seq_code(yx_tr_program *out, const yx_u8_seq *seq)
{
    for (unsigned i = 0; i < seq->length; ++i)
        if (!yx_u8_byte_range(&out->forward, seq->first[i], seq->last[i])) return false;
    for (unsigned i = seq->length; i-- > 0;)
        if (!yx_u8_byte_range(&out->backward, seq->first[i], seq->last[i])) return false;
    return true;
}

/* visit_post_class for a Class::Unicode (any_byte classes are ANY_BYTE, see
 * the caller): an ASCII class is emitted as its byte class (to_byte_class,
 * never a masked byte), one sequence directly, several as a SPLIT_N of the
 * sequences, each but the last followed by a JUMP to the end. */
static bool yx_u8_class_code(const yx_re_range *ranges, size_t count, yx_tr_program *out, unsigned *split)
{
    if (!count || ranges[count - 1].last < 0x80) {
        uint8_t bitmap[32] = {0};
        for (size_t i = 0; i < count; ++i)
            for (uint32_t b = ranges[i].first; b <= ranges[i].last; ++b) yx_tr_set(bitmap, (unsigned)b);
        return yx_tr_class_code(&out->forward, bitmap, true) && yx_tr_class_code(&out->backward, bitmap, true);
    }
    yx_u8_seq *seqs = malloc(YX_U8_MAX_SEQUENCES * sizeof(*seqs));
    /* Per branch: forward and backward start, forward and backward jump. */
    size_t (*at)[4] = malloc(YX_U8_MAX_SEQUENCES * sizeof(*at));
    size_t n = 0, f0 = out->forward.used, b0 = out->backward.used;
    bool ok = seqs && at && yx_u8_sequences(ranges, count, seqs, &n) && n;
    if (ok && n == 1) ok = yx_u8_seq_code(out, &seqs[0]);
    else if (ok) {
        ok = yx_tr_pair(out, 3, split, (unsigned)n);
        for (size_t i = 0; ok && i < n; ++i) {
            at[i][0] = out->forward.used; at[i][1] = out->backward.used;
            ok = yx_u8_seq_code(out, &seqs[i]);
            if (ok && i + 1 < n) {
                at[i][2] = out->forward.used; at[i][3] = out->backward.used;
                ok = yx_tr_pair(out, 4, split, 0);
            }
        }
        for (size_t i = 0; ok && i + 1 < n; ++i)
            ok = yx_tr_patch(&out->forward, at[i][2], 2, out->forward.used) &&
                 yx_tr_patch(&out->backward, at[i][3], 2, out->backward.used);
        for (size_t i = 0; ok && i < n; ++i)
            ok = yx_tr_patch(&out->forward, f0, 5 + 4 * i, at[i][0]) &&
                 yx_tr_patch(&out->backward, b0, 5 + 4 * i, at[i][1]);
    }
    free(seqs); free(at);
    return ok;
}
#endif
