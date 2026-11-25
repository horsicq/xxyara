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

#ifndef YX_SERIALIZATION_BASE64_H
#define YX_SERIALIZATION_BASE64_H
static yx_ser_result yx_encode_base64_pattern(const YRX_RULES *rules, uint8_t **data, size_t *length)
{
    if (!rules || rules->rule_count != 1 || rules->import_count || rules->global_count) return YX_SER_UNSUPPORTED;
    const YRX_RULE *r = &rules->rules[0];
    if (r->pattern_count != 1 || r->tag_count || r->metadata_count || r->is_global || !r->condition_text || (r->namespace_name && strcmp(r->namespace_name, "default")) ||
        /* The three names below are written without interning: a rule
         * named like the namespace shares its identifier in YARA-X. */
        !r->identifier || !strcmp(r->identifier, "default"))
        return YX_SER_UNSUPPORTED;
    const YRX_PATTERN *p = &r->patterns[0];
    if (p->kind != YX_PATTERN_TEXT || !p->bytes || p->length < 3 || p->length > SIZE_MAX / 2 || !(p->modifiers & (YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) ||
        (p->modifiers & ~(YX_MOD_BASE64 | YX_MOD_BASE64WIDE | YX_MOD_ASCII | YX_MOD_WIDE)))
        return YX_SER_UNSUPPORTED;
    yx_physical_archive *a = calloc(1, sizeof(*a));
    uint8_t *wide = NULL, *wasm = NULL;
    size_t wasm_length = 0;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    if (!a) return YX_SER_NO_MEMORY;
    if (!yx_physical_names_reserve(a, 3) || !yx_physical_patterns_reserve(a, 1) || !yx_physical_frames_reserve(a, 12)) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    a->name_count = 3;
    a->logical = a->physical = 1;
    a->name_ids[0] = 1;
    a->private_rule = r->is_private;
    a->names[0] = yx_copy_string("default");
    a->names[1] = yx_copy_string(p->identifier);
    a->names[2] = yx_copy_string(r->identifier);
    a->atoms = calloc(12, sizeof(*a->atoms));
    if (!a->names[0] || !a->names[1] || !a->names[2] || !a->atoms) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    status = yx_physical_single_condition_encode(rules, &wasm, &wasm_length, &a->limits[0]);
    if (status != YX_SER_SUCCESS) goto done;
    status = YX_SER_UNSUPPORTED;
    a->wasm = wasm;
    a->wasm_length = wasm_length;
    bool wide_input = (p->modifiers & YX_MOD_WIDE) != 0;
    size_t variants = wide_input && (p->modifiers & YX_MOD_ASCII) ? 2 : 1;
    if (wide_input) {
        wide = calloc(p->length, 2);
        if (!wide) {
            status = YX_SER_NO_MEMORY;
            goto done;
        }
        for (size_t i = 0; i < p->length; ++i) wide[2 * i] = p->bytes[i];
    }
    for (size_t v = 0; v < variants; ++v) {
        bool w = wide_input && v == 0;
        const uint8_t *bytes = w ? wide : p->bytes;
        size_t size = p->length * (w ? 2u : 1u);
        size_t pool = yx_physical_pool(a, (yx_literal){bytes, size});
        if (pool == SIZE_MAX) {
            status = YX_SER_NO_MEMORY;
            goto done;
        }
        for (unsigned output = 0; output < 2; ++output) {
            if (!(p->modifiers & (output ? YX_MOD_BASE64WIDE : YX_MOD_BASE64))) continue;
            const char *alphabet = output ? p->base64wide_alphabet : p->base64_alphabet;
            size_t alphabet_pool = 0;
            if (alphabet) {
                if (strlen(alphabet) != 64) goto done;
                alphabet_pool = yx_physical_pool(a, (yx_literal){(const uint8_t *)alphabet, 64});
                if (alphabet_pool == SIZE_MAX) {
                    status = YX_SER_NO_MEMORY;
                    goto done;
                }
            }
            uint8_t *phases[3] = {0};
            size_t widths[3], offsets[3], atom_widths[3];
            if (!yx_archive_base64_phases(bytes, size, output != 0, alphabet, phases, widths, offsets, atom_widths)) goto done;
            for (size_t phase = 0; phase < 3; ++phase) {
                size_t index = a->frame_count++;
                yx_physical_frame *f = &a->frames[index];
                f->frame.variant = (uint8_t)(8 + output + (alphabet ? 2 : 0));
                f->frame.literal_index = pool;
                f->mask = alphabet_pool;
                f->padding = (uint8_t)(2 - phase);
                yx_chain_atom *atom = &a->atoms[a->atom_count++];
                atom->frame = index;
                atom->atom.length = atom_widths[phase];
                atom->atom.backtrack = offsets[phase];
                memcpy(atom->atom.bytes, phases[phase] + offsets[phase], atom_widths[phase]);
                free(phases[phase]);
            }
        }
    }
    status = yx_physical_write(a, data, length);
done:
    yx_physical_destroy(a);
    free(a);
    free(wasm);
    free(wide);
    return status;
}

static yx_ser_result yx_decode_base64_pattern(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *count)
{
    yx_physical_archive *a = calloc(1, sizeof(*a));
    yx_ser_rule *decoded = NULL;
    yx_writer declaration = {0};
    uint8_t *canonical = NULL;
    size_t canonical_length = 0;
    size_t inputs[2] = {0}, input_count = 0, alphabets[2] = {SIZE_MAX, SIZE_MAX};
    unsigned outputs = 0;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    if (!a) return YX_SER_NO_MEMORY;
    if (!yx_physical_read(data, length, a) || a->logical != 1 || a->physical != 1 || a->kinds[0] != 0 || a->code_length || a->frame_count < 3 || a->frame_count > 12 ||
        a->frame_count % 3 || a->atom_count != a->frame_count)
        goto done;
    for (size_t i = 0; i < a->frame_count; i += 3) {
        const yx_physical_frame *first = &a->frames[i];
        unsigned variant = first->frame.variant;
        if (variant < 8 || variant > 11) goto done;
        unsigned output = (variant - 8) % 2;
        bool custom = variant >= 10;
        size_t input = first->frame.literal_index;
        if (!input_count || inputs[input_count - 1] != input) {
            if (input_count == 2) goto done;
            inputs[input_count++] = input;
        }
        size_t alphabet = custom ? first->mask : SIZE_MAX;
        if (custom && a->pool[alphabet].length != 64) goto done;
        if (input_count == 1) {
            if (outputs & (1u << output)) goto done;
            outputs |= 1u << output;
            alphabets[output] = alphabet;
        } else if (!(outputs & (1u << output)) || alphabets[output] != alphabet) goto done;
        uint8_t *phases[3] = {0};
        size_t widths[3], offsets[3], atom_widths[3];
        char alphabet_text[65];
        if (custom) {
            memcpy(alphabet_text, a->pool[alphabet].data, 64);
            alphabet_text[64] = 0;
        }
        const yx_literal *literal = &a->pool[input];
        if (!yx_archive_base64_phases(literal->data, literal->length, output != 0, custom ? alphabet_text : NULL, phases, widths, offsets, atom_widths)) goto done;
        bool valid = true;
        for (size_t phase = 0; phase < 3; ++phase) {
            const yx_physical_frame *f = &a->frames[i + phase];
            const yx_chain_atom *b = &a->atoms[i + phase];
            if (f->frame.variant != variant || f->frame.literal_index != input || f->padding != 2 - phase || (custom && f->mask != alphabet) || b->frame != i + phase ||
                b->atom.exact || b->atom.has_forward || b->atom.has_backward || b->atom.length != atom_widths[phase] || b->atom.backtrack != offsets[phase] ||
                memcmp(b->atom.bytes, phases[phase] + offsets[phase], atom_widths[phase]))
                valid = false;
            free(phases[phase]);
        }
        if (!valid) goto done;
    }
    if (a->frame_count != input_count * 3 * ((outputs & 1u) + ((outputs >> 1) & 1u))) goto done;
    const yx_literal *literal = &a->pool[inputs[input_count - 1]];
    unsigned modifiers = 0;
    if (input_count == 2) {
        const yx_literal *wide = &a->pool[inputs[0]];
        if (literal->length > SIZE_MAX / 2 || wide->length != literal->length * 2) goto done;
        for (size_t i = 0; i < literal->length; ++i)
            if (wide->data[2 * i] != literal->data[i] || wide->data[2 * i + 1]) goto done;
        modifiers = YX_MOD_ASCII | YX_MOD_WIDE;
    }
    status = yx_physical_write(a, &canonical, &canonical_length);
    if (status != YX_SER_SUCCESS) goto done;
    status = YX_SER_UNSUPPORTED;
    if (canonical_length != a->archive_length || memcmp(canonical, data, canonical_length)) goto done;
    decoded = calloc(1, sizeof(*decoded));
    if (!decoded) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    if (!yx_physical_single_condition_decode(a, decoded)) goto done;
    status = yx_physical_copy_rule_info(a, decoded);
    if (status != YX_SER_SUCCESS) goto done;
    status = YX_SER_UNSUPPORTED;
    YRX_PATTERN p = {0};
    p.kind = YX_PATTERN_TEXT;
    p.bytes = (uint8_t *)literal->data;
    p.length = literal->length;
    p.modifiers = modifiers;
    if (!yx_physical_declaration(&declaration, a->names[a->name_ids[0]], &p)) goto done;
    for (unsigned output = 0; output < 2; ++output)
        if (outputs & (1u << output)) {
            if (!yx_tr_text(&declaration, output ? "base64wide" : "base64")) goto done;
            if (alphabets[output] != SIZE_MAX) {
                if (!yx_tr_text(&declaration, "(\"")) goto done;
                for (size_t i = 0; i < 64; ++i) {
                    uint8_t byte = a->pool[alphabets[output]].data[i];
                    if (byte < ' ' || byte >= 127 || byte == '"' || byte == '\\' || !yx_put_u8(&declaration, byte)) goto done;
                }
                if (!yx_tr_text(&declaration, "\")")) goto done;
            }
            if (!yx_put_u8(&declaration, ' ')) goto done;
        }
    if ((a->pattern_private[0] && !yx_tr_text(&declaration, "private ")) || !yx_put_u8(&declaration, 0)) goto done;
    decoded->runtime_pattern_declarations = (char *)declaration.data;
    declaration.data = NULL;
    decoded->preserve_serialized_prefix = true;
    *rules = decoded;
    *count = 1;
    decoded = NULL;
    status = YX_SER_SUCCESS;
done:
    yx_physical_destroy(a);
    free(a);
    yx_ser_rules_destroy(decoded, decoded ? 1 : 0);
    free(canonical);
    free(declaration.data);
    return status;
}
#endif
