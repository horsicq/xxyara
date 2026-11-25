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

#ifndef YX_SERIALIZATION_PATTERN_H
#define YX_SERIALIZATION_PATTERN_H

/* Shared single-regexp archive envelope. The caller supplies independently
 * generated Wasm, regexp verifier code and atoms; no archive templates are
 * accepted. Included after the serialization writer and AC primitives. */

typedef struct yx_archive_regexp_atom {
    uint8_t bytes[8]; /* A four-byte regexp atom can be widened to eight. */
    size_t length;
    uint16_t backtrack;
    bool exact, has_forward, has_backward;
    size_t forward, backward; /* zero-based verifier offsets, encoded as offset + 1 */
    size_t subpattern;
} yx_archive_regexp_atom;

typedef struct yx_archive_regexp_envelope {
    char *names[3];
    const uint8_t *wasm, *code;
    size_t wasm_length, code_length, archive_length;
    yx_archive_regexp_atom *atoms;
    size_t atom_count;
    uint8_t pattern_kind, variant;
    const uint8_t *literal, *mask;
    size_t literal_length;
    uint16_t flags;
    bool ascii_wide;
} yx_archive_regexp_envelope;

static void yx_regexp_envelope_destroy(yx_archive_regexp_envelope *e)
{
    for (size_t i = 0; i < 3; ++i) free(e->names[i]);
    free(e->atoms);
    memset(e, 0, sizeof(*e));
}

static yx_ser_result yx_pattern_variants_encode(const char *rule_name, const char *pattern_name, uint8_t pattern_kind, uint16_t flags, bool ascii_wide,
                                                const uint8_t *wasm, size_t wasm_length, const yx_archive_regexp_atom *atoms, size_t atom_count, const uint8_t *code,
                                                size_t code_length, const uint8_t *literal, const uint8_t *mask, size_t literal_length, uint8_t **data, size_t *length)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    static const uint8_t globals[] = {0, 0, 1, 0}, suffix[] = {0, 0, 1, 1, 1, 0};
    yx_writer w = {0};
    uint8_t *ac = NULL;
    size_t ac_length = 0;
    bool masked = literal != NULL, same_mask = masked && mask && !memcmp(literal, mask, literal_length);
    if ((masked && (!mask || !literal_length || code_length || ascii_wide)) || (ascii_wide && !(flags & 1u))) return YX_SER_UNSUPPORTED;
    const uint8_t **pointers = NULL;
    size_t *widths = NULL;
    if (!rule_name || !pattern_name || !yx_valid_rule_name(rule_name) || !strcmp(rule_name, "default") || pattern_name[0] != '$' ||
        !yx_valid_rule_name(pattern_name + 1) || pattern_kind < 1 || pattern_kind > 2 || !atoms || !atom_count || atom_count > 16384)
        return YX_SER_UNSUPPORTED;
    for (size_t i = 0; i < atom_count; ++i)
        if (atoms[i].subpattern > (ascii_wide ? 1u : 0u) || atoms[i].length > sizeof(atoms[i].bytes) ||
            (atoms[i].has_forward && (atoms[i].forward >= code_length || atoms[i].forward >= UINT32_MAX)) ||
            (atoms[i].has_backward && (atoms[i].backward >= code_length || atoms[i].backward >= UINT32_MAX)))
            return YX_SER_UNSUPPORTED;
    if (atom_count == 1 && atoms[0].length && atoms[0].length <= 4) {
        ac_length = atoms[0].length == 1 ? YX_PATTERN_AC_LENGTH : YX_PATTERN_AC_PREFILTER_LENGTH;
        ac = malloc(ac_length);
        if (!ac || !yx_make_short_pattern_ac(ac, atoms[0].bytes, atoms[0].length)) goto memory;
    } else {
        pointers = malloc(atom_count * sizeof(*pointers));
        widths = malloc(atom_count * sizeof(*widths));
        if (!pointers || !widths) goto memory;
        for (size_t i = 0; i < atom_count; ++i) {
            pointers[i] = atoms[i].bytes;
            widths[i] = atoms[i].length;
        }
        if (!yx_ser_build_atom_ac(pointers, widths, atom_count, &ac, &ac_length)) goto memory;
    }
    if (!yx_put_bytes(&w, magic, sizeof(magic)) || !yx_put_uint(&w, 3) || !yx_put_string(&w, "default") || !yx_put_string(&w, pattern_name) ||
        !yx_put_string(&w, rule_name) || !yx_put_uint(&w, 0) || !yx_put_u8(&w, 0) || !yx_put_uint(&w, masked ? (same_mask ? 1 : 2) : 0) ||
        (masked && (!yx_put_uint(&w, literal_length) || !yx_put_bytes(&w, literal, literal_length))) ||
        (masked && !same_mask && (!yx_put_uint(&w, literal_length) || !yx_put_bytes(&w, mask, literal_length))) || !yx_put_uint(&w, wasm_length) ||
        !yx_put_bytes(&w, wasm, wasm_length) || !yx_put_u8(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, 1) ||
        /* Rule namespace, identifier, tags, metadata, one pattern. */
        !yx_put_uint(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, 2) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, 1) || !yx_put_uint(&w, 0) ||
        !yx_put_uint(&w, 1) || !yx_put_uint(&w, pattern_kind) || !yx_put_u8(&w, 0) || !yx_put_uint(&w, 0) || !yx_put_u8(&w, 0) || !yx_put_u8(&w, 0) ||
        /* One pattern with wide first and optional ASCII second. */
        !yx_put_uint(&w, 1) || !yx_put_uint(&w, ascii_wide ? 2 : 1) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, masked ? 1 : 4) ||
        (masked && (!yx_put_uint(&w, 0) || !yx_put_uint(&w, same_mask ? 0 : 1))) || !yx_put_uint(&w, flags) ||
        (ascii_wide && (!yx_put_uint(&w, 0) || !yx_put_uint(&w, 4) || !yx_put_uint(&w, flags & ~1u))) || !yx_put_uint(&w, 0) || !yx_put_uint(&w, 0) ||
        !yx_put_uint(&w, 0) || !yx_put_uint(&w, atom_count))
        goto memory;
    for (size_t i = 0; i < atom_count; ++i) {
        const yx_archive_regexp_atom *a = &atoms[i];
        if (!yx_put_uint(&w, a->subpattern) || !yx_put_uint(&w, a->length) || !yx_put_bytes(&w, a->bytes, a->length) || !yx_put_u8(&w, a->exact) ||
            !yx_put_uint(&w, a->backtrack) || !yx_put_u8(&w, a->has_forward) || (a->has_forward && !yx_put_uint(&w, a->forward + 1)) || !yx_put_u8(&w, a->has_backward) ||
            (a->has_backward && !yx_put_uint(&w, a->backward + 1)))
            goto memory;
    }
    if (!yx_put_uint(&w, code_length) || !yx_put_bytes(&w, code, code_length) || !yx_put_uint(&w, sizeof(globals)) || !yx_put_bytes(&w, globals, sizeof(globals)) ||
        !yx_put_uint(&w, ac_length) || !yx_put_bytes(&w, ac, ac_length) || !yx_put_bytes(&w, suffix, sizeof(suffix)))
        goto memory;
    free(ac);
    free(pointers);
    free(widths);
    *data = w.data;
    *length = w.used;
    return YX_SER_SUCCESS;
memory:
    free(ac);
    free(pointers);
    free(widths);
    free(w.data);
    return YX_SER_NO_MEMORY;
}

static bool yx_pattern_envelope_read(const uint8_t *data, size_t length, yx_archive_regexp_envelope *e)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    static const uint8_t globals[] = {0, 0, 1, 0}, suffix[] = {0, 0, 1, 1, 1, 0};
    yx_reader r = {data, length, 0, false, false};
    uint64_t n;
    uint8_t flag;
    memset(e, 0, sizeof(*e));
    if (!data || length < sizeof(magic) || memcmp(data, magic, sizeof(magic))) return false;
    r.at = sizeof(magic);
    if (!yx_expect_uint(&r, 3)) goto fail;
    for (size_t i = 0; i < 3; ++i)
        if (!yx_get_string(&r, &e->names[i])) goto fail;
    if (strcmp(e->names[0], "default") || !yx_valid_rule_name(e->names[2]) || !strcmp(e->names[2], "default") || e->names[1][0] != '$' ||
        !yx_valid_rule_name(e->names[1] + 1) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || n > 2)
        goto fail;
    size_t pool_count = (size_t)n;
    const uint8_t *pool[2] = {NULL, NULL};
    size_t pool_length[2] = {0, 0};
    for (size_t i = 0; i < pool_count; ++i) {
        if (!yx_get_uint(&r, &n) || !n || n > length - r.at) goto fail;
        pool[i] = data + r.at;
        pool_length[i] = (size_t)n;
        r.at += (size_t)n;
    }
    if (!yx_get_uint(&r, &n) || n > length - r.at) goto fail;
    e->wasm = data + r.at;
    e->wasm_length = (size_t)n;
    r.at += (size_t)n;
    static const uint8_t before_kind[] = {0, 0, 1, 0, 0, 2, 0, 0, 1, 0, 1};
    if (!yx_integer_wasm_bytes(&r, length, before_kind, sizeof(before_kind)) || !yx_get_uint(&r, &n) || n < 1 || n > 2) goto fail;
    e->pattern_kind = (uint8_t)n;
    static const uint8_t before_variant[] = {0, 0, 0, 0, 1};
    if (!yx_integer_wasm_bytes(&r, length, before_variant, sizeof(before_variant)) || !yx_get_uint(&r, &n) || (n != 1 && n != 2)) goto fail;
    e->ascii_wide = n == 2;
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || (n != 1 && n != 4) || (e->ascii_wide && n != 4)) goto fail;
    e->variant = (uint8_t)n;
    if (e->variant == 1) {
        uint64_t pattern_index, mask_index;
        if (!yx_get_uint(&r, &pattern_index) || !yx_get_uint(&r, &mask_index) || pattern_index >= pool_count || mask_index >= pool_count ||
            pool_length[pattern_index] != pool_length[mask_index])
            goto fail;
        e->literal = pool[pattern_index];
        e->mask = pool[mask_index];
        e->literal_length = pool_length[pattern_index];
    } else if (pool_count) goto fail;
    if (!yx_get_uint(&r, &n) || n > UINT16_MAX) goto fail;
    e->flags = (uint16_t)n;
    if (e->ascii_wide && (!(e->flags & 1u) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 4) || !yx_expect_uint(&r, e->flags & ~1u))) goto fail;
    if (!yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || !n || n > 16384 || n > length - r.at) goto fail;
    e->atom_count = (size_t)n;
    e->atoms = calloc(e->atom_count, sizeof(*e->atoms));
    if (!e->atoms) goto fail;
    for (size_t i = 0; i < e->atom_count; ++i) {
        yx_archive_regexp_atom *a = &e->atoms[i];
        if (!yx_get_uint(&r, &n) || n > (e->ascii_wide ? 1u : 0u)) goto fail;
        a->subpattern = (size_t)n;
        if (!yx_get_uint(&r, &n) || n > sizeof(a->bytes) || n > length - r.at) goto fail;
        a->length = (size_t)n;
        memcpy(a->bytes, data + r.at, a->length);
        r.at += a->length;
        if (!yx_get_u8(&r, &flag) || flag > 1 || !yx_get_uint(&r, &n) || n > UINT16_MAX) goto fail;
        a->exact = flag != 0;
        a->backtrack = (uint16_t)n;
        if (!yx_get_u8(&r, &flag) || flag > 1) goto fail;
        a->has_forward = flag != 0;
        if (flag) {
            if (!yx_get_uint(&r, &n) || !n || n > UINT32_MAX) goto fail;
            a->forward = (size_t)n - 1;
        }
        if (!yx_get_u8(&r, &flag) || flag > 1) goto fail;
        a->has_backward = flag != 0;
        if (flag) {
            if (!yx_get_uint(&r, &n) || !n || n > UINT32_MAX) goto fail;
            a->backward = (size_t)n - 1;
        }
    }
    if (!yx_get_uint(&r, &n) || n > length - r.at) goto fail;
    e->code = data + r.at;
    e->code_length = (size_t)n;
    r.at += (size_t)n;
    if (!yx_expect_uint(&r, sizeof(globals)) || !yx_integer_wasm_bytes(&r, length, globals, sizeof(globals)) || !yx_get_uint(&r, &n) || n > length - r.at) goto fail;
    r.at += (size_t)n;
    if (!yx_integer_wasm_bytes(&r, length, suffix, sizeof(suffix))) goto fail;
    e->archive_length = r.at;
    return true;
fail:
    yx_regexp_envelope_destroy(e);
    return false;
}

static yx_ser_result yx_pattern_envelope_encode(const char *rule_name, const char *pattern_name, uint8_t pattern_kind, uint16_t flags, const uint8_t *wasm,
                                                size_t wasm_length, const yx_archive_regexp_atom *atoms, size_t atom_count, const uint8_t *code, size_t code_length,
                                                const uint8_t *literal, const uint8_t *mask, size_t literal_length, uint8_t **data, size_t *length)
{
    return yx_pattern_variants_encode(rule_name, pattern_name, pattern_kind, flags, false, wasm, wasm_length, atoms, atom_count, code, code_length, literal, mask,
                                      literal_length, data, length);
}
static yx_ser_result yx_regexp_variants_encode(const char *rule_name, const char *pattern_name, uint8_t pattern_kind, uint16_t flags, bool ascii_wide,
                                               const uint8_t *wasm, size_t wasm_length, const yx_archive_regexp_atom *atoms, size_t atom_count, const uint8_t *code,
                                               size_t code_length, uint8_t **data, size_t *length)
{
    return yx_pattern_variants_encode(rule_name, pattern_name, pattern_kind, flags, ascii_wide, wasm, wasm_length, atoms, atom_count, code, code_length, NULL, NULL, 0,
                                      data, length);
}

/* Compatibility wrappers keep the regexp-only contract narrow for verifier
 * decoders. Masked literals have a separate literal pool and no verifier. */
static inline yx_ser_result yx_regexp_envelope_encode(const char *rule_name, const char *pattern_name, uint8_t pattern_kind, uint16_t flags, const uint8_t *wasm,
                                                      size_t wasm_length, const yx_archive_regexp_atom *atoms, size_t atom_count, const uint8_t *code, size_t code_length,
                                                      uint8_t **data, size_t *length)
{
    return yx_pattern_envelope_encode(rule_name, pattern_name, pattern_kind, flags, wasm, wasm_length, atoms, atom_count, code, code_length, NULL, NULL, 0, data, length);
}
static bool yx_regexp_envelope_read(const uint8_t *data, size_t length, yx_archive_regexp_envelope *e)
{
    if (!yx_pattern_envelope_read(data, length, e)) return false;
    if (e->variant == 4) return true;
    yx_regexp_envelope_destroy(e);
    return false;
}

#endif
