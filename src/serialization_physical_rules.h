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


#ifndef YX_SERIALIZATION_PHYSICAL_RULES_H
#define YX_SERIALIZATION_PHYSICAL_RULES_H
typedef struct yx_physical_pattern_options {
    uint64_t limit,offset;
    bool anchored;
    yx_pattern_filesize_bounds bounds;
    yx_physical_header header;
} yx_physical_pattern_options;
typedef struct yx_physical_rules {
    yx_physical_archive *archive;
    yx_writer metadata,code;
    uint8_t **parts;size_t part_count;
    /* Optional, per rule: the literals its condition interns, in emission
     * order. Upstream compiles rules in turn, so they follow the rule's
     * metadata and pattern literals in the pool. Bytes are borrowed. */
    yx_literal **condition_literals;size_t *condition_literal_counts,condition_rule_count;
} yx_physical_rules;
static void yx_physical_rules_destroy(yx_physical_rules *a)
{
    if(a->archive){yx_physical_destroy(a->archive);free(a->archive);}
    for(size_t i=0;i<a->part_count;++i)free(a->parts[i]);
    free(a->parts);
    if(a->condition_literals)for(size_t i=0;i<a->condition_rule_count;++i)free(a->condition_literals[i]);
    free(a->condition_literals);free(a->condition_literal_counts);
    free(a->metadata.data);free(a->code.data);memset(a,0,sizeof(*a));
}
static bool yx_physical_rule_bounds_equal(const yx_pattern_filesize_bounds *a,const yx_pattern_filesize_bounds *b)
{
    return a->lower_kind==b->lower_kind&&a->upper_kind==b->upper_kind&&
        (a->lower_kind==2||a->lower==b->lower)&&(a->upper_kind==2||a->upper==b->upper);
}
static inline bool yx_physical_header_equal(const yx_physical_header *a,const yx_physical_header *b)
{
    return a->kind==b->kind&&(a->kind!=2||(a->length==b->length&&(!a->length||!memcmp(a->bytes,b->bytes,a->length))));
}
/* options are derived independently from each logical declaration's AST. */
static inline bool yx_physical_rules_options_equal(const yx_physical_archive *a,
    const yx_physical_pattern_options *options)
{
    for(size_t i=0;i<a->logical;++i) {
        size_t p=a->mapping[i];const yx_physical_pattern_options *o=&options[i];
        bool bounded=o->bounds.lower_kind!=2||o->bounds.upper_kind!=2;
        if(p>=a->physical||a->limits[p]!=o->limit||a->bounded[p]!=bounded||!yx_physical_header_equal(&a->headers[p],&o->header)||
           (bounded&&!yx_physical_rule_bounds_equal(&a->bounds[p],&o->bounds)))return false;
        for(size_t j=0;j<a->frame_count;++j)if(a->frames[j].pattern==p) {
            const yx_physical_frame *f=&a->frames[j];bool anchored=o->anchored&&f->frame.variant==0;
            if(f->anchored!=anchored||(anchored&&f->offset!=o->offset))return false;
        }
    }
    return true;
}
/* Offsets delimit the rule-metadata vector, after the shared Wasm program. */
static bool yx_multi_pattern_metadata_span(const uint8_t *data,size_t length,size_t *begin,size_t *end)
{
    yx_reader r={data,length,12,false,false};uint64_t n,width;
    if(length<12||!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i)if(!yx_get_uint(&r,&width)||width>length-r.at)return false;else r.at+=(size_t)width;
    /* The condition's regexp pool, then the relaxed-syntax flag. */
    if(!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i)if(!yx_get_uint(&r,&width)||width>length-r.at)return false;else r.at+=(size_t)width;
    if(!yx_expect_uint(&r,0)||!yx_get_uint(&r,&n))return false;
    for(uint64_t i=0;i<n;++i)if(!yx_get_uint(&r,&width)||width>length-r.at)return false;else r.at+=(size_t)width;
    if(!yx_get_uint(&r,&width)||width>length-r.at)return false;
    r.at+=(size_t)width;
    if(!yx_expect_uint(&r,0)||!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i)if(!yx_get_uint(&r,&width))return false;
    *begin=r.at;
    if(!yx_get_uint(&r,&n)||!n||n>(length-r.at)/9)return false;
    for(uint64_t i=0;i<n;++i) {
        uint64_t tags,metadata,patterns;uint8_t flag;
        if(!yx_get_uint(&r,&width)||!yx_get_uint(&r,&width)||!yx_get_uint(&r,&width)||!yx_get_uint(&r,&tags)||tags>length-r.at)return false;
        for(uint64_t j=0;j<tags;++j)if(!yx_get_uint(&r,&width))return false;
        if(!yx_get_uint(&r,&metadata)||metadata>(length-r.at)/3)return false;
        for(uint64_t j=0;j<metadata;++j) {
            if(!yx_get_uint(&r,&width)||!yx_get_uint(&r,&width)||width>4)return false;
            if(width==0){if(!yx_get_u8(&r,&flag)||flag>1)return false;}
            else if(width==1){int64_t v;if(!yx_get_signed(&r,&v))return false;}
            else if(width==2){double v;if(!yx_get_float(&r,&v))return false;}
            else if(!yx_get_uint(&r,&width))return false;
        }
        if(!yx_get_uint(&r,&patterns)||patterns>(length-r.at)/4)return false;
        for(uint64_t j=0;j<patterns;++j)if(!yx_get_uint(&r,&width)||!yx_get_uint(&r,&width)||
            !yx_get_uint(&r,&width)||!yx_get_u8(&r,&flag)||flag>1)return false;
        if(!yx_get_uint(&r,&width)||!yx_get_uint(&r,&width)||!yx_get_u8(&r,&flag))return false;
    }
    *end=r.at;return true;
}
static yx_ser_result yx_multi_pattern_replace_metadata(const uint8_t *data,size_t length,const yx_writer *metadata,uint8_t **out,size_t *out_length)
{
    size_t begin,end;yx_writer w={0};
    if(!yx_multi_pattern_metadata_span(data,length,&begin,&end))return YX_SER_UNSUPPORTED;
    if(!yx_put_bytes(&w,data,begin)||!yx_put_bytes(&w,metadata->data,metadata->used)||!yx_put_bytes(&w,data+end,length-end)) {
        free(w.data);return YX_SER_NO_MEMORY;
    }
    *out=w.data;*out_length=w.used;return YX_SER_SUCCESS;
}
/* Optional preseeded archive owns identifier strings and atom storage;
 * imported schema and literal bytes remain borrowed until write completes.
 * options are in declaration order; returned mapping is globally physical. */
static yx_ser_result yx_physical_rules_build(const YRX_RULES *rules,
    const yx_physical_pattern_options *options,yx_physical_rules *assembly)
{
    if(!rules||!rules->rule_count)return YX_SER_UNSUPPORTED;
    size_t count=rules->rule_count,logical=0;
    for(size_t i=0;i<count;++i) {
        const YRX_RULE *r=&rules->rules[i];
        if(!r->condition_text||r->pattern_count>SIZE_MAX-logical)return YX_SER_UNSUPPORTED;
        logical+=r->pattern_count;
    }
    yx_physical_archive *a=assembly->archive?assembly->archive:calloc(1,sizeof(*a)),*part=calloc(1,sizeof(*part));
    assembly->archive=NULL;
    yx_writer metadata={0},code={0},fields={0};
    uint8_t **parts=calloc(logical?logical:1,sizeof(*parts));
    size_t *widths=calloc(logical?logical:1,sizeof(*widths)),*pools=NULL;
    size_t bucket_count=64;while(bucket_count<logical*2)bucket_count*=2;
    size_t *heads=malloc(bucket_count*sizeof(*heads)),*tails=malloc(bucket_count*sizeof(*tails));
    size_t *chain=malloc((logical?logical:1)*sizeof(*chain));uint64_t *hashes=malloc((logical?logical:1)*sizeof(*hashes));
    if(heads&&tails)for(size_t b=0;b<bucket_count;++b)heads[b]=tails[b]=SIZE_MAX;
    yx_ser_result status=YX_SER_UNSUPPORTED;
    size_t atom_capacity=a?a->atom_count:0;
    yx_v12_memo memo={0},*previous_memo=yx_v12_memo_active;yx_v12_memo_active=&memo;
    if(!a||!part||!parts||!widths||!heads||!tails||!chain||!hashes||!yx_physical_patterns_reserve(a,logical)||
       !yx_physical_imports_reserve(a,rules->import_count)){status=YX_SER_NO_MEMORY;goto done;}
    /* Upstream's Pattern hashes order its bounds/header maps; without a
     * modeled hash for every pattern the writer keeps ascending order. */
    bool hashed=!a->physical&&!a->pattern_hashes;
    if(hashed&&!(a->pattern_hashes=malloc((logical?logical:1)*sizeof(*a->pattern_hashes)))){status=YX_SER_NO_MEMORY;goto done;}
    if(yx_physical_ident(a,"default")!=0||!yx_put_uint(&metadata,count))goto done;
    size_t next_import=0,next_namespace=0;
    for(size_t i=0;i<count;++i) {
        const YRX_RULE *r=&rules->rules[i];size_t first=a->logical,private_count=0;
        const char *ns=r->namespace_name?r->namespace_name:"default";
        fields.used=0;
        while(next_import<rules->import_count&&(!rules->import_rule_indices||rules->import_rule_indices[next_import]<=i)) {
            size_t ordinal=rules->import_namespace_indices?rules->import_namespace_indices[next_import]:r->namespace_index;
            while(next_namespace<rules->namespace_count&&next_namespace<=ordinal) {
                const char *name=rules->namespace_names[next_namespace++];
                if(name&&yx_physical_ident(a,name)==SIZE_MAX)goto done;
            }
            if(rules->import_namespaces&&yx_physical_ident(a,rules->import_namespaces[next_import])==SIZE_MAX)goto done;
            size_t import_id=yx_physical_ident(a,rules->imports[next_import++]);if(import_id==SIZE_MAX)goto done;
            bool duplicate=false;for(size_t m=0;m<a->import_count;++m)duplicate|=a->imports[m]==import_id;
            if(!duplicate)a->imports[a->import_count++]=import_id;
        }
        while(next_namespace<rules->namespace_count&&next_namespace<=r->namespace_index) {
            const char *name=rules->namespace_names[next_namespace++];
            if(name&&yx_physical_ident(a,name)==SIZE_MAX)goto done;
        }
        size_t namespace_id=yx_physical_ident(a,ns);
        if(namespace_id==SIZE_MAX||!yx_put_uint(&fields,r->tag_count))goto done;
        for(size_t j=0;j<r->tag_count;++j) {
            size_t tag=yx_physical_ident(a,r->tags[j]);if(tag==SIZE_MAX||!yx_put_uint(&fields,tag))goto done;
        }
        if(!yx_put_uint(&fields,r->metadata_count))goto done;
        for(size_t j=0;j<r->metadata_count;++j) {
            const YRX_METADATA *v=&r->metadata[j];size_t key=yx_physical_ident(a,v->identifier);
            unsigned kind=v->value_type==YRX_BOOLEAN?0:v->value_type==YRX_I64?1:v->value_type==YRX_F64?2:v->value_type==YRX_STRING?3:4;
            if(key==SIZE_MAX||!yx_put_uint(&fields,key)||!yx_put_uint(&fields,kind))goto done;
            if(kind==0){if(!yx_put_u8(&fields,v->value.boolean))goto done;}
            else if(kind==1){if(!yx_put_signed(&fields,v->value.i64))goto done;}
            else if(kind==2){if(!yx_put_float(&fields,v->value.f64))goto done;}
            else {
                yx_literal literal=kind==3?(yx_literal){(const uint8_t *)v->value.string,strlen(v->value.string)}:
                    (yx_literal){v->value.bytes.data,v->value.bytes.length};
                size_t pool=yx_physical_pool(a,literal);if(pool==SIZE_MAX||!yx_put_uint(&fields,pool))goto done;
            }
        }
        for(size_t j=0;j<r->pattern_count;++j) {
            const YRX_PATTERN *p=&r->patterns[j];size_t index=a->logical++;
            a->name_ids[index]=yx_physical_ident(a,p->identifier);if(a->name_ids[index]==SIZE_MAX)goto done;
            a->kinds[index]=(uint8_t)p->kind;
            a->pattern_private[index]=(p->modifiers&YX_MOD_PRIVATE)!=0;private_count+=a->pattern_private[index];
            YRX_PATTERN pattern=*p;YRX_RULE adapted=*r;YRX_RULES base=*rules;
            pattern.identifier="$a";pattern.modifiers&=~YX_MOD_PRIVATE;adapted.identifier="r";adapted.namespace_name="default";
            adapted.tags=NULL;adapted.tag_count=0;adapted.metadata=NULL;adapted.metadata_count=0;
            adapted.patterns=&pattern;adapted.pattern_count=1;adapted.condition_text="$a";adapted.is_private=false;adapted.is_global=false;adapted.namespace_index=0;
            adapted.is_global=false;adapted.namespace_index=0;
            base.rules=&adapted;base.rule_count=1;base.import_count=base.global_count=0;base.serialized_prefix=NULL;base.serialized_prefix_length=0;
            base.namespace_names=NULL;base.namespace_count=0;
            status=yx_ser_encode_part(&base,&parts[index],&widths[index]);if(status!=YX_SER_SUCCESS)goto done;
            status=YX_SER_UNSUPPORTED;size_t duplicate=index;
            /* The first equal earlier pattern, through a hash of the
             * compared fields; chains keep declaration order. */
            uint64_t hash=1469598103934665603ull;
            {
                uint64_t fields[]={options[index].limit,options[index].anchored,
                                   options[index].anchored?options[index].offset:0,a->pattern_private[index],widths[index]};
                for(size_t f=0;f<sizeof(fields)/sizeof(fields[0]);++f)hash=(hash^fields[f])*1099511628211ull;
                for(size_t b=0;b<widths[index];++b)hash=(hash^parts[index][b])*1099511628211ull;
                /* Upstream interns ir::Pattern values, whose HIR keeps capture groups: /a[0-9]{3}/ and
                 * /a([0-9]){3}/ compile to the same bytes but stay two patterns. */
                if(p->kind==YX_PATTERN_REGEX)hash=(hash^yx_pattern_hir_signature(p))*1099511628211ull;
            }
            size_t bucket=(size_t)hash&(bucket_count-1);
            for(size_t k=heads[bucket];k!=SIZE_MAX;k=chain[k])
                if(hashes[k]==hash&&options[k].limit==options[index].limit&&options[k].anchored==options[index].anchored&&(!options[index].anchored||options[k].offset==options[index].offset)&&yx_physical_rule_bounds_equal(&options[k].bounds,&options[index].bounds)&&yx_physical_header_equal(&options[k].header,&options[index].header)&&a->pattern_private[k]==a->pattern_private[index]&&widths[k]==widths[index]&&!memcmp(parts[k],parts[index],widths[index])){duplicate=k;break;}
            hashes[index]=hash;chain[index]=SIZE_MAX;
            if(heads[bucket]==SIZE_MAX)heads[bucket]=index;else chain[tails[bucket]]=index;
            tails[bucket]=index;
            if(duplicate<index)a->mapping[index]=a->mapping[duplicate];
            else {
                if(!yx_physical_read(parts[index],widths[index],part)||part->logical!=1||part->physical!=1)goto done;
                if(hashed) {
                    const yx_physical_pattern_options *o=&options[index];bool text=p->kind==YX_PATTERN_TEXT;
                    yx_pattern_hash_state state={o->anchored,!o->anchored,o->offset,
                        text?2:o->bounds.lower_kind,text?2:o->bounds.upper_kind,o->bounds.lower,o->bounds.upper,
                        text?0:o->header.kind,o->header.bytes,o->header.length,o->limit};
                    hashed=yx_pattern_fx_hash(p,&state,&a->pattern_hashes[a->physical]);
                }
                a->mapping[index]=a->physical++;
                a->limits[a->mapping[index]]=options[index].limit;
                a->bounds[a->mapping[index]]=options[index].bounds;
                a->headers[a->mapping[index]]=options[index].header;
                a->bounded[a->mapping[index]]=options[index].bounds.lower_kind!=2||options[index].bounds.upper_kind!=2;
                size_t frame_start=a->frame_count;
                free(pools);pools=calloc(part->pool_count?part->pool_count:1,sizeof(*pools));
                if(!pools){status=YX_SER_NO_MEMORY;goto done;}
                for(size_t k=0;k<part->pool_count;++k)if((pools[k]=yx_physical_pool(a,part->pool[k]))==SIZE_MAX)goto done;
                if(part->frame_count>SIZE_MAX-a->frame_count||part->atom_count>SIZE_MAX/sizeof(*a->atoms)-a->atom_count||
                   code.used>UINT32_MAX||part->code_length>UINT32_MAX-code.used)goto done;
                if(!yx_physical_frames_reserve(a,a->frame_count+part->frame_count)){status=YX_SER_NO_MEMORY;goto done;}
                for(size_t k=0;k<part->frame_count;++k) {
                    yx_physical_frame f=part->frames[k];f.pattern=a->mapping[index];
                    if(f.frame.variant<=3||f.frame.variant>=7)f.frame.literal_index=pools[f.frame.literal_index];
                    if(f.frame.variant==1||f.frame.variant>=10)f.mask=pools[f.mask];
                    if(f.frame.variant==3||f.frame.variant==6)f.frame.previous+=frame_start;
                    if(options[index].anchored&&f.frame.variant==0) {
                        f.anchored=true;f.offset=options[index].offset;a->anchored[a->anchored_count++]=a->frame_count;
                    }
                    a->frames[a->frame_count++]=f;
                }
                if(!yx_physical_atoms_reserve(a,&atom_capacity,a->atom_count+part->atom_count)){status=YX_SER_NO_MEMORY;goto done;}
                for(size_t k=0;k<part->atom_count;++k) {
                    yx_chain_atom atom=part->atoms[k];atom.frame+=frame_start;
                    if(a->frames[atom.frame].anchored)continue;
                    if(atom.atom.has_forward)atom.atom.forward+=(uint32_t)code.used;
                    if(atom.atom.has_backward)atom.atom.backward+=(uint32_t)code.used;
                    a->atoms[a->atom_count++]=atom;
                }
                if(!yx_put_bytes(&code,part->code,part->code_length)){status=YX_SER_NO_MEMORY;goto done;}
                yx_physical_destroy(part);
            }
        }
        if(assembly->condition_literals&&i<assembly->condition_rule_count)
            for(size_t k=0;k<assembly->condition_literal_counts[i];++k)
                if(yx_physical_pool(a,assembly->condition_literals[i][k])==SIZE_MAX)goto done;
        size_t rule_id=yx_physical_ident(a,r->identifier);if(rule_id==SIZE_MAX)goto done;
        if(!yx_put_uint(&metadata,r->namespace_index*2)||!yx_put_uint(&metadata,namespace_id)||!yx_put_uint(&metadata,rule_id)||
           !yx_put_bytes(&metadata,fields.data,fields.used)||!yx_put_uint(&metadata,r->pattern_count))goto done;
        for(size_t j=0;j<r->pattern_count;++j)if(!yx_put_uint(&metadata,a->mapping[first+j]*2)||
            !yx_put_uint(&metadata,a->name_ids[first+j])||!yx_put_uint(&metadata,a->kinds[first+j])||!yx_put_u8(&metadata,a->pattern_private[first+j]))goto done;
        if(!yx_put_uint(&metadata,private_count)||!yx_put_uint(&metadata,r->is_global)||!yx_put_u8(&metadata,r->is_private))goto done;

    }

    while(next_import<rules->import_count) {
        size_t ordinal=rules->import_namespace_indices?rules->import_namespace_indices[next_import]:rules->rules[count-1].namespace_index;
        while(next_namespace<rules->namespace_count&&next_namespace<=ordinal) {
            const char *name=rules->namespace_names[next_namespace++];
            if(name&&yx_physical_ident(a,name)==SIZE_MAX)goto done;
        }
        if(rules->import_namespaces&&yx_physical_ident(a,rules->import_namespaces[next_import])==SIZE_MAX)goto done;
        size_t id=yx_physical_ident(a,rules->imports[next_import++]);if(id==SIZE_MAX)goto done;
        bool duplicate=false;for(size_t i=0;i<a->import_count;++i)duplicate|=a->imports[i]==id;
        if(!duplicate)a->imports[a->import_count++]=id;
    }
    while(next_namespace<rules->namespace_count) {
        const char *name=rules->namespace_names[next_namespace++];
        if(name&&yx_physical_ident(a,name)==SIZE_MAX)goto done;
    }
    if(!hashed){free(a->pattern_hashes);a->pattern_hashes=NULL;}
    a->code=code.data;a->code_length=code.used;
    assembly->archive=a;a=NULL;assembly->metadata=metadata;metadata.data=NULL;assembly->code=code;code.data=NULL;
    assembly->parts=parts;assembly->part_count=logical;parts=NULL;status=YX_SER_SUCCESS;
done:
    yx_v12_memo_active=previous_memo;yx_v12_memo_free(&memo);
    if(parts)for(size_t i=0;i<logical;++i)free(parts[i]);
    free(parts);free(widths);free(pools);free(heads);free(tails);free(chain);free(hashes);
    if(a){yx_physical_destroy(a);free(a);}if(part){yx_physical_destroy(part);free(part);}
    free(metadata.data);free(fields.data);free(code.data);return status;
}
static yx_ser_result yx_physical_rules_write(yx_physical_rules *a,const uint8_t *wasm,size_t wasm_length,uint8_t **data,size_t *length)
{
    uint8_t *base=NULL;size_t base_length=0;
    a->archive->wasm=wasm;a->archive->wasm_length=wasm_length;
    yx_ser_result status=yx_physical_write(a->archive,&base,&base_length);
    if(status==YX_SER_SUCCESS)status=yx_multi_pattern_replace_metadata(base,base_length,&a->metadata,data,length);
    free(base);return status;
}
#endif
