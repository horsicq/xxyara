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

/* XOR subpatterns retain the complete literal and select atoms before applying
 * the key range. Wide literals select their own four-byte windows. */
#ifndef YX_SERIALIZATION_XOR_H
#define YX_SERIALIZATION_XOR_H
static yx_ser_result yx_encode_xor_pattern(const YRX_RULES *rules,
                                         uint8_t **data, size_t *length)
{
    if (!rules || rules->rule_count != 1 || rules->import_count || rules->global_count)
        return YX_SER_UNSUPPORTED;
    const YRX_RULE *r = &rules->rules[0];
    if (r->pattern_count != 1 || r->tag_count || r->metadata_count || r->is_global ||
        !r->condition_text || (r->namespace_name && strcmp(r->namespace_name,"default")))
        return YX_SER_UNSUPPORTED;
    const YRX_PATTERN *p = &r->patterns[0];
    if (p->kind != YX_PATTERN_TEXT || !p->bytes || !p->length ||
        !(p->modifiers & YX_MOD_XOR) ||
        (p->modifiers & ~(YX_MOD_XOR|YX_MOD_ASCII|YX_MOD_WIDE|YX_MOD_FULLWORD)) ||
        p->xor_min > p->xor_max || p->length > SIZE_MAX / 2)
        return YX_SER_UNSUPPORTED;
    yx_physical_archive *a = calloc(1,sizeof(*a));
    uint8_t *wide = NULL, *wasm = NULL;
    size_t wasm_length = 0;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    if (!a || !yx_physical_names_reserve(a,3) ||
        !yx_physical_patterns_reserve(a,1) || !yx_physical_frames_reserve(a,2)) {
        status=YX_SER_NO_MEMORY; goto done;
    }
    a->name_count=3; a->logical=a->physical=1; a->name_ids[0]=1;
    a->names[0]=yx_copy_string("default"); a->names[1]=yx_copy_string(p->identifier);
    a->names[2]=yx_copy_string(r->identifier); a->private_rule=r->is_private;
    if (!a->names[0] || !a->names[1] || !a->names[2]) { status=YX_SER_NO_MEMORY; goto done; }
    status=yx_physical_single_condition_encode(rules,&wasm,&wasm_length,&a->limits[0]);
    if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED; a->wasm=wasm; a->wasm_length=wasm_length;
    size_t keys=(size_t)p->xor_max-p->xor_min+1;
    bool is_wide=(p->modifiers&YX_MOD_WIDE)!=0;
    bool ascii=!is_wide || (p->modifiers&YX_MOD_ASCII)!=0;
    size_t variants=(size_t)is_wide+(size_t)ascii;
    a->atoms=calloc(keys*variants,sizeof(*a->atoms));
    if (!a->atoms) { status=YX_SER_NO_MEMORY; goto done; }
    if (is_wide) {
        wide=calloc(p->length,2);
        if (!wide) { status=YX_SER_NO_MEMORY; goto done; }
        for (size_t i=0;i<p->length;++i) wide[2*i]=p->bytes[i];
    }
    for (size_t variant=0;variant<variants;++variant) {
        bool w=is_wide && variant==0;
        const uint8_t *bytes=w?wide:p->bytes;
        size_t size=w?p->length*2:p->length, offset, width;
        if (!yx_best_text_atom(bytes,size,&offset,&width)) goto done;
        yx_physical_frame *f=&a->frames[a->frame_count++];
        f->frame.variant=7; f->frame.flags=(w?1u:0u)|((p->modifiers&YX_MOD_FULLWORD)?24u:0u);
        f->frame.literal_index=yx_physical_pool(a,(yx_literal){bytes,size});
        if (f->frame.literal_index==SIZE_MAX) goto done;
        for (unsigned key=p->xor_min;key<=(unsigned)p->xor_max;++key) {
            yx_chain_atom *atom=&a->atoms[a->atom_count++];
            atom->frame=variant; atom->atom.length=width; atom->atom.backtrack=offset;
            for (size_t i=0;i<width;++i) atom->atom.bytes[i]=bytes[offset+i]^(uint8_t)key;
        }
    }
    status=yx_physical_write(a,data,length);
done:
    if (a) { yx_physical_destroy(a); free(a); }
    free(wasm); free(wide); return status;
}

static yx_ser_result yx_decode_xor_pattern(const uint8_t *data,size_t length,
                                         yx_ser_rule **rules,size_t *rule_count)
{
    yx_physical_archive *a=calloc(1,sizeof(*a));
    yx_ser_rule *decoded=NULL;
    yx_writer declaration={0}; uint8_t *canonical=NULL,*literal=NULL;
    size_t canonical_length=0, literal_length=0, cursor=0;
    unsigned minimum=0,maximum=0,modifiers=YX_MOD_XOR;
    yx_ser_result status=YX_SER_UNSUPPORTED;
    if (!a) return YX_SER_NO_MEMORY;
    if (!yx_physical_read(data,length,a) || a->logical!=1 || a->physical!=1 ||
        a->kinds[0]!=0 || a->frame_count<1 || a->frame_count>2 || a->code_length) goto done;
    for (size_t i=0;i<a->frame_count;++i) {
        const yx_chain_frame *f=&a->frames[i].frame;
        if (f->variant!=7 || (f->flags&~25u) ||
            ((f->flags&24u)!=0 && (f->flags&24u)!=24u)) goto done;
        const yx_literal *pool=&a->pool[f->literal_index];
        size_t offset,width;
        if (!yx_best_text_atom(pool->data,pool->length,&offset,&width) || cursor==a->atom_count) goto done;
        unsigned first=a->atoms[cursor].atom.bytes[0]^pool->data[offset],last=first;
        size_t begin=cursor;
        while (cursor<a->atom_count && a->atoms[cursor].frame==i) {
            const yx_archive_regexp_atom *atom=&a->atoms[cursor].atom;
            unsigned key=first+(unsigned)(cursor-begin);
            if (key>255 || atom->length!=width || atom->backtrack!=offset || atom->exact ||
                atom->has_forward || atom->has_backward) goto done;
            for (size_t j=0;j<width;++j) if (atom->bytes[j]!=(pool->data[offset+j]^(uint8_t)key)) goto done;
            last=key; ++cursor;
        }
        if (cursor==begin || (i && (minimum!=first || maximum!=last))) goto done;
        minimum=first; maximum=last;
        bool wide=(f->flags&1u)!=0;
        if (i==0) {
            if (wide && pool->length%2) goto done;
            literal_length=pool->length/(wide?2u:1u);
            literal=malloc(literal_length);
            if (!literal) { status=YX_SER_NO_MEMORY; goto done; }
            for (size_t j=0;j<literal_length;++j) {
                literal[j]=pool->data[j*(wide?2u:1u)];
                if (wide && pool->data[j*2+1]) goto done;
            }
            if (wide) modifiers|=YX_MOD_WIDE;
            if (f->flags&24u) modifiers|=YX_MOD_FULLWORD;
        } else {
            if (!(modifiers&YX_MOD_WIDE) || wide || pool->length!=literal_length ||
                memcmp(pool->data,literal,literal_length) ||
                (f->flags&24u)!=(a->frames[0].frame.flags&24u)) goto done;
            modifiers|=YX_MOD_ASCII;
        }
    }
    if (cursor!=a->atom_count) goto done;
    status=yx_physical_write(a,&canonical,&canonical_length);
    if (status!=YX_SER_SUCCESS) goto done;
    status=YX_SER_UNSUPPORTED;
    if (canonical_length!=a->archive_length || memcmp(canonical,data,canonical_length)) goto done;
    decoded=calloc(1,sizeof(*decoded));
    if (!decoded) { status=YX_SER_NO_MEMORY; goto done; }
    if (!yx_physical_single_condition_decode(a,decoded)) goto done;
    status=yx_physical_copy_rule_info(a,decoded);
    if (status!=YX_SER_SUCCESS) goto done;
    status=YX_SER_UNSUPPORTED;
    YRX_PATTERN pattern={0}; pattern.kind=YX_PATTERN_TEXT; pattern.bytes=literal;
    pattern.length=literal_length; pattern.modifiers=modifiers&~YX_MOD_XOR;
    char range[48]; snprintf(range,sizeof(range),"xor(%u-%u) ",minimum,maximum);
    if (!yx_physical_declaration(&declaration,a->names[a->name_ids[0]],&pattern) ||
        !yx_tr_text(&declaration,range) || (a->pattern_private[0] && !yx_tr_text(&declaration,"private ")) ||
        !yx_put_u8(&declaration,0)) { status=YX_SER_NO_MEMORY; goto done; }
    decoded->runtime_pattern_declarations=(char *)declaration.data; declaration.data=NULL;
    decoded->preserve_serialized_prefix=true;
    *rules=decoded; *rule_count=1; decoded=NULL; status=YX_SER_SUCCESS;
done:
    yx_physical_destroy(a); free(a); yx_ser_rules_destroy(decoded,decoded?1:0);
    free(canonical); free(literal); free(declaration.data); return status;
}
#endif
