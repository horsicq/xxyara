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

/* Physical pattern composition. Per-pattern codecs retain their own verifier
 * and atom rules; this layer relocates their pools and program offsets. */
#ifndef YX_SERIALIZATION_PHYSICAL_H
#define YX_SERIALIZATION_PHYSICAL_H
typedef struct yx_physical_frame {
    yx_chain_frame frame;
    size_t pattern, mask;
    uint8_t padding;
    bool anchored;
    uint64_t offset;
} yx_physical_frame;
typedef struct yx_physical_meta {
    size_t key, literal;
    uint8_t variant;
    int64_t integer;
    double floating;
    bool boolean;
} yx_physical_meta;
typedef struct yx_physical_header {
    uint8_t kind;
    const uint8_t *bytes;
    size_t length;
} yx_physical_header;
typedef struct yx_physical_archive {
    char **names; size_t name_capacity;
    size_t namespace_id, rule_name_id, *tags, tag_count, tag_capacity, metadata_count, metadata_capacity;
    yx_physical_meta *metadata;
    bool *pattern_private;
    size_t name_count, logical, physical, *mapping, *name_ids, pattern_capacity;
    uint8_t *kinds;
    bool private_rule;
    size_t *imports, import_count, import_capacity;
    const uint8_t *globals;
    size_t globals_length;
    yx_literal *pool; size_t pool_capacity;
    size_t pool_count;
    yx_physical_frame *frames; size_t frame_capacity;
    size_t frame_count;
    yx_chain_atom *atoms;
    size_t atom_count;
    const uint8_t *code, *wasm;
    size_t code_length, wasm_length, archive_length;
    uint64_t *limits;
    yx_physical_header *headers;
    yx_pattern_filesize_bounds *bounds;
    bool *bounded;
    size_t *anchored, anchored_count;
    /* Hash indexes over pool and names for yx_physical_pool/ident; entries
     * [0, *_indexed) are indexed. */
    size_t *pool_slots, pool_slot_count, pool_indexed;
    size_t *name_slots, name_slot_count, name_indexed;
    /* An empty rules vector instead of the single rule record. */
    bool no_rules;
    /* Key orders of the filesize-bounds and header-constraint maps as read
     * (rewriting a read archive keeps them) and, when the writer knows them,
     * the upstream FxHash of each physical pattern (pattern_hash.h). */
    size_t *bounds_order, bounds_order_count, *headers_order, headers_order_count;
    uint64_t *pattern_hashes;
    /* The condition's regexp pool (`matches`), as delimited source text. */
    yx_literal *regexps; size_t regexp_count;
} yx_physical_archive;
/* Capacity follows the decoded vector length or the requested construction
 * size. Every reserve preserves existing entries and zeroes new entries. */
static size_t yx_physical_grow(size_t capacity,size_t count)
{
    return count>capacity&&capacity<=SIZE_MAX/2&&count<capacity*2?capacity*2:count;
}
static bool yx_physical_buffer_reserve(void **buffer,size_t old_count,size_t count,size_t width)
{
    if(count<=old_count)return true;
    if(!width||count>SIZE_MAX/width)return false;
    void *next=realloc(*buffer,count*width);if(!next)return false;
    memset((uint8_t *)next+old_count*width,0,(count-old_count)*width);*buffer=next;return true;
}
static bool yx_physical_patterns_reserve(yx_physical_archive *a,size_t count)
{
    if(count<=a->pattern_capacity)return true;
    count=yx_physical_grow(a->pattern_capacity,count);
#define YX_RESERVE_PATTERN(field) if(!yx_physical_buffer_reserve((void **)&a->field,a->pattern_capacity,count,sizeof(*a->field)))return false
    YX_RESERVE_PATTERN(mapping);YX_RESERVE_PATTERN(name_ids);YX_RESERVE_PATTERN(kinds);
    YX_RESERVE_PATTERN(pattern_private);YX_RESERVE_PATTERN(limits);YX_RESERVE_PATTERN(headers);
    YX_RESERVE_PATTERN(bounds);YX_RESERVE_PATTERN(bounded);
#undef YX_RESERVE_PATTERN
    a->pattern_capacity=count;return true;
}
static bool yx_physical_frames_reserve(yx_physical_archive *a,size_t count)
{
    if(count<=a->frame_capacity)return true;
    count=yx_physical_grow(a->frame_capacity,count);
    if(!yx_physical_buffer_reserve((void **)&a->frames,a->frame_capacity,count,sizeof(*a->frames))||
       !yx_physical_buffer_reserve((void **)&a->anchored,a->frame_capacity,count,sizeof(*a->anchored)))return false;
    a->frame_capacity=count;return true;
}
#define YX_PHYSICAL_RESERVE(name,field,capacity) \
static bool yx_physical_##name##_reserve(yx_physical_archive *a,size_t count) \
{ \
    if(count<=a->capacity)return true; \
    count=yx_physical_grow(a->capacity,count); \
    if(!yx_physical_buffer_reserve((void **)&a->field,a->capacity,count,sizeof(*a->field)))return false; \
    a->capacity=count;return true; \
}
YX_PHYSICAL_RESERVE(names,names,name_capacity)
YX_PHYSICAL_RESERVE(pool,pool,pool_capacity)
YX_PHYSICAL_RESERVE(imports,imports,import_capacity)
YX_PHYSICAL_RESERVE(tags,tags,tag_capacity)
YX_PHYSICAL_RESERVE(metadata,metadata,metadata_capacity)
#undef YX_PHYSICAL_RESERVE
static void yx_physical_destroy(yx_physical_archive *a)
{
    for (size_t i = 0; i < a->name_count; ++i) free(a->names[i]);
    free(a->names);free(a->tags);free(a->metadata);free(a->imports);free(a->pool);
    free(a->mapping);free(a->name_ids);free(a->kinds);free(a->pattern_private);
    free(a->limits);free(a->headers);free(a->bounds);free(a->bounded);
    free(a->frames);free(a->anchored);free(a->atoms);
    free(a->pool_slots);free(a->name_slots);
    free(a->bounds_order);free(a->headers_order);free(a->pattern_hashes);free(a->regexps);
    memset(a, 0, sizeof(*a));
}
static bool yx_physical_read(const uint8_t *data, size_t length, yx_physical_archive *a)
{
    static const uint8_t magic[] = {'Y','A','R','A','-','X',0,0,12,0,0,0};
    yx_reader r = {data,length,12,false,false};
    uint64_t n, id; uint8_t flag;
    memset(a, 0, sizeof(*a));
    if (!data || length < 12 || memcmp(data,magic,12) ||
        !yx_get_uint(&r,&n) || n < 2 || n > length-r.at) return false;
    if(!yx_physical_names_reserve(a,(size_t)n))goto fail;
    a->name_count = (size_t)n;
    for (size_t i=0;i<a->name_count;++i)
        if (!yx_get_string(&r,&a->names[i])) goto fail;
    if (strcmp(a->names[0],"default") || !yx_get_uint(&r,&n) || n > length-r.at) goto fail;
    if (n) {
        a->regexps=calloc((size_t)n,sizeof(*a->regexps));
        if(!a->regexps)goto fail;
        a->regexp_count=(size_t)n;
        for(size_t i=0;i<a->regexp_count;++i) {
            if(!yx_get_uint(&r,&n)||n>length-r.at)goto fail;
            a->regexps[i]=(yx_literal){data+r.at,(size_t)n};r.at+=(size_t)n;
        }
    }
    if (!yx_expect_uint(&r,0) || !yx_get_uint(&r,&n) || n > length-r.at ||
        !yx_physical_pool_reserve(a,(size_t)n)) goto fail;
    a->pool_count=(size_t)n;
    for(size_t i=0;i<a->pool_count;++i) {
        if(!yx_get_uint(&r,&n)||n>length-r.at)goto fail;
        a->pool[i]=(yx_literal){data+r.at,(size_t)n};r.at+=(size_t)n;
    }
    if(!yx_get_uint(&r,&n)||n>length-r.at)goto fail;
    a->wasm=data+r.at;a->wasm_length=(size_t)n;r.at+=(size_t)n;
    if(!yx_expect_uint(&r,0)||!yx_get_uint(&r,&n)||n>length-r.at||!yx_physical_imports_reserve(a,(size_t)n))goto fail;
    a->import_count=(size_t)n;
    for(size_t i=0;i<a->import_count;++i) {
        if(!yx_get_uint(&r,&n)||n>=a->name_count||!yx_valid_rule_name(a->names[n]))goto fail;
        a->imports[i]=(size_t)n;
    }
    if(!yx_expect_uint(&r,1)||
       !yx_get_uint(&r,&id)||(id!=0&&id!=2)||!yx_get_uint(&r,&n)||n>=a->name_count||
       id!=(n?2u:0u))goto fail;
    a->namespace_id=(size_t)n;
    if(!yx_get_uint(&r,&n)||n>=a->name_count||!yx_valid_rule_name(a->names[n]))goto fail;
    a->rule_name_id=(size_t)n;
    if(!yx_get_uint(&r,&n)||n>length-r.at||!yx_physical_tags_reserve(a,(size_t)n))goto fail;
    a->tag_count=(size_t)n;
    for(size_t i=0;i<a->tag_count;++i) {
        if(!yx_get_uint(&r,&n)||n>=a->name_count||!yx_valid_rule_name(a->names[n]))goto fail;
        a->tags[i]=(size_t)n;
    }
    if(!yx_get_uint(&r,&n)||n>(length-r.at)/3||!yx_physical_metadata_reserve(a,(size_t)n))goto fail;
    a->metadata_count=(size_t)n;
    for(size_t i=0;i<a->metadata_count;++i) {
        yx_physical_meta *m=&a->metadata[i];
        if(!yx_get_uint(&r,&n)||n>=a->name_count||!yx_valid_rule_name(a->names[n]))goto fail;
        m->key=(size_t)n;
        if(!yx_get_uint(&r,&n)||n>4)goto fail;
        m->variant=(uint8_t)n;
        if(m->variant==0) {
            if(!yx_get_u8(&r,&flag)||flag>1)goto fail;
            m->boolean=flag!=0;
        } else if(m->variant==1) { if(!yx_get_signed(&r,&m->integer))goto fail; }
        else if(m->variant==2) { if(!yx_get_float(&r,&m->floating))goto fail; }
        else {
            if(!yx_get_uint(&r,&n)||n>=a->pool_count)goto fail;
            m->literal=(size_t)n;
        }
    }
    if(!yx_get_uint(&r,&n)||n>(length-r.at)/4||!yx_physical_patterns_reserve(a,(size_t)n))goto fail;
    a->logical=(size_t)n;
    for(size_t i=0;i<a->logical;++i) {
        if(!yx_get_uint(&r,&id)||(id&1u)||id/2>=a->logical)goto fail;
        a->mapping[i]=(size_t)(id/2);
        if(!yx_get_uint(&r,&id)||id>=a->name_count||a->names[id][0]!='$'||!yx_valid_rule_name(a->names[id]+1))goto fail;
        a->name_ids[i]=(size_t)id;
        if(!yx_get_uint(&r,&n)||n>2||!yx_get_u8(&r,&flag)||flag>1)goto fail;
        a->kinds[i]=(uint8_t)n;a->pattern_private[i]=flag!=0;
    }
    size_t private_count=0;
    for(size_t i=0;i<a->logical;++i)private_count+=a->pattern_private[i];
    if(!yx_expect_uint(&r,private_count)||!yx_expect_uint(&r,0)||!yx_get_u8(&r,&flag)||flag>1||
       !yx_get_uint(&r,&n)||n>a->logical||(!n!=!a->logical))goto fail;
    a->private_rule=flag!=0;a->physical=(size_t)n;
    for(size_t i=0;i<a->logical;++i)if(a->mapping[i]>=a->physical)goto fail;
    if(!yx_get_uint(&r,&n)||n>(length-r.at)/3||(!n!=!a->physical)||!yx_physical_frames_reserve(a,(size_t)n))goto fail;
    a->frame_count=(size_t)n;
    for(size_t i=0;i<a->frame_count;++i) {
        yx_physical_frame *p=&a->frames[i];yx_chain_frame *f=&p->frame;
        if(!yx_get_uint(&r,&id)||(id&1u)||id/2>=a->physical||!yx_get_uint(&r,&n)||n>11)goto fail;
        p->pattern=(size_t)(id/2);f->variant=(uint8_t)n;
        if((f->variant<=3||f->variant>=7)) {
            if(!yx_get_uint(&r,&n)||n>=a->pool_count)goto fail;
            f->literal_index=(size_t)n;f->literal=a->pool[n].data;f->literal_length=a->pool[n].length;
        }
        if(f->variant==1||f->variant>=10) {
            if(!yx_get_uint(&r,&n)||n>=a->pool_count||(f->variant==1&&a->pool[n].length!=f->literal_length))goto fail;
            p->mask=(size_t)n;
        }
        if(f->variant==0) {
            if(!yx_get_u8(&r,&flag)||flag>1)goto fail;
            p->anchored=flag!=0;
            if(p->anchored&&!yx_get_uint(&r,&p->offset))goto fail;
        }
        if(f->variant==3||f->variant==6) {
            if(!yx_get_uint(&r,&n)||n>=i)goto fail;
            f->previous=(size_t)n;
            if(a->frames[n].pattern!=p->pattern||!yx_get_uint(&r,&id)||id>1||
               !yx_get_uint(&r,&n)||n>UINT32_MAX)goto fail;
            f->minimum=(uint32_t)n;f->maximum=UINT32_MAX;
            if(!id) {
                if(!yx_get_uint(&r,&n)||n>UINT32_MAX||n<f->minimum)goto fail;
                f->maximum=(uint32_t)n;f->finite_maximum=n==UINT32_MAX;
            }
        }
        if(f->variant>=8) {
            if(!yx_get_u8(&r,&p->padding)||p->padding>2)goto fail;
        } else {
            if(!yx_get_uint(&r,&n)||n>127)goto fail;
            f->flags=(uint16_t)n;
        }
    }
    if(!yx_get_uint(&r,&n)||n>a->physical)goto fail;
    if(n&&!(a->bounds_order=malloc((size_t)n*sizeof(*a->bounds_order))))goto fail;
    a->bounds_order_count=(size_t)n;
    for(size_t i=0;i<(size_t)n;++i) {
        uint64_t pattern,kind;
        if(!yx_get_uint(&r,&pattern)||(pattern&1u)||pattern/2>=a->physical||a->bounded[pattern/2])goto fail;
        size_t p=(size_t)(pattern/2);a->bounded[p]=true;a->bounds_order[i]=p;
        if(!yx_get_uint(&r,&kind)||kind>2)goto fail;
        a->bounds[p].lower_kind=kind?(uint8_t)(kind-1):2;
        if(kind&&!yx_get_signed(&r,&a->bounds[p].lower))goto fail;
        if(!yx_get_uint(&r,&kind)||kind>2)goto fail;
        a->bounds[p].upper_kind=kind?(uint8_t)(kind-1):2;
        if(kind&&!yx_get_signed(&r,&a->bounds[p].upper))goto fail;
    }
    if(!yx_get_uint(&r,&n)||n>a->physical)goto fail;
    if(n&&!(a->headers_order=malloc((size_t)n*sizeof(*a->headers_order))))goto fail;
    a->headers_order_count=(size_t)n;
    for(size_t i=0;i<(size_t)n;++i) {
        uint64_t id,kind,width;
        if(!yx_get_uint(&r,&id)||(id&1u)||id/2>=a->physical||a->headers[id/2].kind||
           !yx_get_uint(&r,&kind)||kind<1||kind>2)goto fail;
        yx_physical_header *header=&a->headers[id/2];header->kind=(uint8_t)kind;a->headers_order[i]=(size_t)(id/2);
        if(kind==2) {
            if(!yx_get_uint(&r,&width)||width>length-r.at)goto fail;
            header->bytes=data+r.at;header->length=(size_t)width;r.at+=(size_t)width;
        }
    }
    if(!yx_get_uint(&r,&n)||n>a->frame_count)goto fail;
    a->anchored_count=(size_t)n;
    for(size_t i=0;i<a->anchored_count;++i) {
        if(!yx_get_uint(&r,&n)||n>=a->frame_count||a->frames[n].frame.variant!=0||!a->frames[n].anchored)goto fail;
        a->anchored[i]=(size_t)n;
    }
    if(!yx_get_uint(&r,&n)||n>(length-r.at)/7)goto fail;
    a->atom_count=(size_t)n;a->atoms=calloc(a->atom_count?a->atom_count:1,sizeof(*a->atoms));
    if(!a->atoms)goto fail;
    for(size_t i=0;i<a->atom_count;++i) {
        yx_chain_atom *atom=&a->atoms[i];yx_archive_regexp_atom *b=&atom->atom;
        if(!yx_get_uint(&r,&n)||n>=a->frame_count)goto fail;
        atom->frame=(size_t)n;
        if(!yx_get_uint(&r,&n)||n>sizeof(b->bytes)||n>length-r.at)goto fail;
        b->length=(size_t)n;memcpy(b->bytes,data+r.at,b->length);r.at+=b->length;
        if(!yx_get_u8(&r,&flag)||flag>1)goto fail;
        b->exact=flag!=0;
        if(!yx_get_uint(&r,&n)||n>SIZE_MAX)goto fail;
        b->backtrack=(size_t)n;
        if(!yx_get_u8(&r,&flag)||flag>1)goto fail;
        b->has_forward=flag!=0;
        if(b->has_forward) { if(!yx_get_uint(&r,&n)||!n||n>UINT32_MAX)goto fail;
        b->forward=(uint32_t)(n-1); }
        if(!yx_get_u8(&r,&flag)||flag>1)goto fail;
        b->has_backward=flag!=0;
        if(b->has_backward) { if(!yx_get_uint(&r,&n)||!n||n>UINT32_MAX)goto fail;
        b->backward=(uint32_t)(n-1); }
    }
    if(!yx_get_uint(&r,&n)||n>length-r.at)goto fail;
    a->code=data+r.at;a->code_length=(size_t)n;r.at+=(size_t)n;
    for(size_t i=0;i<a->atom_count;++i) {
        const yx_archive_regexp_atom *b=&a->atoms[i].atom;
        if((b->has_forward&&b->forward>=a->code_length)||(b->has_backward&&b->backward>=a->code_length))goto fail;
    }
    if(!yx_get_uint(&r,&n)||n>length-r.at)goto fail;
    a->globals=data+r.at;a->globals_length=(size_t)n;r.at+=(size_t)n;
    if(!yx_get_uint(&r,&n)||n>length-r.at)goto fail;
    r.at+=(size_t)n;
    /* Empty regex/literal sets; physical is the deduplicated PatternId count. */
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,a->physical))goto fail;
    for(size_t i=0;i<a->physical;++i) {
        if(!yx_get_u8(&r,&flag)||flag>1)goto fail;
        if(flag&&(!yx_get_uint(&r,&a->limits[i])||!a->limits[i]))goto fail;
    }
    if(!yx_expect_uint(&r,0))goto fail;
    a->archive_length=r.at;return true;
fail:yx_physical_destroy(a);return false;
}
/* Iteration order of the FxHashMap<PatternId, _> upstream serializes for
 * filesize bounds and header constraints: rustc-hash 2 FxHasher over a u32
 * and a SwissTable grown from empty, entries inserted by ascending id. The
 * order is exact while ids do not collide; upstream's insertion order
 * follows its pattern map, which only matters on collisions. */
static uint64_t yx_fx_hash_u32(uint32_t value)
{
    uint64_t hash=(uint64_t)value*UINT64_C(0xf1357aea2e62a9c5);
    return hash<<26|hash>>38;
}
static void yx_fx_place(size_t *slots,size_t buckets,size_t id)
{
    size_t pos=(size_t)yx_fx_hash_u32((uint32_t)id)&(buckets-1),stride=0;
    for(;;) {
        for(size_t i=0;i<(buckets<16?buckets:16);++i) {
            size_t at=(pos+i)&(buckets-1);
            if(slots[at]==SIZE_MAX){slots[at]=id;return;}
        }
        stride+=16;pos=(pos+stride)&(buckets-1);
    }
}
static size_t yx_fx_capacity(size_t buckets)
{
    return buckets<8?buckets-1:buckets/8*7;
}
static bool yx_fx_map_order(const bool *present,size_t count,size_t *order)
{
    size_t buckets=0,items=0,*slots=NULL,used=0;
    for(size_t id=0;id<count;++id) {
        if(!present[id])continue;
        if(items+1>(buckets?yx_fx_capacity(buckets):0)) {
            size_t wanted=items+1,next;size_t *grown;
            if(buckets&&yx_fx_capacity(buckets)+1>wanted)wanted=yx_fx_capacity(buckets)+1;
            if(wanted<4)next=4;else if(wanted<8)next=8;
            else{next=1;while(next<wanted*8/7)next<<=1;}
            grown=malloc(next*sizeof(*grown));
            if(!grown){free(slots);return false;}
            for(size_t i=0;i<next;++i)grown[i]=SIZE_MAX;
            for(size_t i=0;i<buckets;++i)if(slots[i]!=SIZE_MAX)yx_fx_place(grown,next,slots[i]);
            free(slots);slots=grown;buckets=next;
        }
        yx_fx_place(slots,buckets,id);++items;
    }
    for(size_t i=0;i<buckets;++i)if(slots[i]!=SIZE_MAX)order[used++]=slots[i];
    free(slots);return true;
}
/* The key order of a bounds/header map: as read when it still names exactly
 * the present keys; else the upstream insertion order (patterns-map order)
 * when the pattern hashes are known; else ascending insertion. */
static bool yx_physical_map_order(const yx_physical_archive *a,const bool *present,
                                  const size_t *read_order,size_t read_count,size_t *order)
{
    size_t count=0;
    for(size_t i=0;i<a->physical;++i)count+=present[i];
    if(read_order&&read_count==count) {
        bool *seen=calloc(a->physical?a->physical:1,sizeof(*seen)),valid=seen!=NULL;
        for(size_t k=0;valid&&k<count;++k)
            valid=read_order[k]<a->physical&&present[read_order[k]]&&!seen[read_order[k]]&&(seen[read_order[k]]=true);
        free(seen);
        if(valid){if(count)memcpy(order,read_order,count*sizeof(*order));return true;}
    }
    if(a->pattern_hashes&&count) {
        size_t *patterns=malloc(a->physical*sizeof(*patterns)),*inserted=malloc(count*sizeof(*inserted)),*placed=malloc(count*sizeof(*placed));
        uint64_t *hashes=malloc(count*sizeof(*hashes));size_t used=0;
        bool ok=patterns&&inserted&&placed&&hashes&&yx_fx_table_order(a->pattern_hashes,a->physical,patterns);
        for(size_t k=0;ok&&k<a->physical;++k)if(present[patterns[k]]){inserted[used]=patterns[k];hashes[used++]=yx_fx_hash_u32((uint32_t)patterns[k]);}
        ok=ok&&used==count&&yx_fx_table_order(hashes,count,placed);
        for(size_t k=0;ok&&k<count;++k)order[k]=inserted[placed[k]];
        free(patterns);free(inserted);free(placed);free(hashes);
        return ok;
    }
    return yx_fx_map_order(present,a->physical,order);
}
static yx_ser_result yx_physical_write(const yx_physical_archive *a,uint8_t **data,size_t *length)
{
    static const uint8_t magic[]={'Y','A','R','A','-','X',0,0,12,0,0,0},globals[]={0,0,1,0};
    yx_writer w={0};uint8_t *ac=NULL;size_t ac_length=0;
    const uint8_t **bytes=calloc(a->atom_count?a->atom_count:1,sizeof(*bytes));
    size_t *widths=calloc(a->atom_count?a->atom_count:1,sizeof(*widths));
    if(!bytes||!widths)goto fail;
    for(size_t i=0;i<a->atom_count;++i)bytes[i]=a->atoms[i].atom.bytes,widths[i]=a->atoms[i].atom.length;
    if(a->atom_count) {
        if(!yx_ser_build_atom_ac(bytes,widths,a->atom_count,&ac,&ac_length))goto fail;
    } else {
        ac_length=YX_AC_LENGTH;ac=malloc(ac_length);if(!ac)goto fail;yx_make_empty_ac(ac);
    }
    {
        /* An upper bound of the archive's size: a part's automaton image
         * (64 KiB of 2-gram filter alone) dominates, and growing the buffer
         * around it copied every part several times. */
        size_t estimate=64+ac_length+a->wasm_length+a->code_length+(a->globals?a->globals_length:sizeof(globals))+
            9*(a->name_count+a->pool_count+a->import_count+a->tag_count)+32*a->metadata_count+
            32*a->logical+48*a->frame_count+48*a->atom_count+32*a->physical+32*a->anchored_count;
        bool fits=true;
        for(size_t i=0;fits&&i<a->name_count;++i){size_t n=strlen(a->names[i]);fits=n<=SIZE_MAX-estimate;estimate+=n;}
        for(size_t i=0;fits&&i<a->pool_count;++i){fits=a->pool[i].length<=SIZE_MAX-estimate;estimate+=a->pool[i].length;}
        for(size_t i=0;fits&&i<a->physical;++i)if(a->headers[i].kind==2){fits=a->headers[i].length<=SIZE_MAX-estimate;estimate+=a->headers[i].length+9;}
        if(fits){uint8_t *reserved=malloc(estimate);if(reserved){w.data=reserved;w.capacity=estimate;}}
    }
    if(!yx_put_bytes(&w,magic,sizeof(magic))||!yx_put_uint(&w,a->name_count))goto fail;
    for(size_t i=0;i<a->name_count;++i)if(!yx_put_string(&w,a->names[i]))goto fail;
    if(!yx_put_uint(&w,a->regexp_count))goto fail;
    for(size_t i=0;i<a->regexp_count;++i)
        if(!yx_put_uint(&w,a->regexps[i].length)||!yx_put_bytes(&w,a->regexps[i].data,a->regexps[i].length))goto fail;
    if(!yx_put_uint(&w,0)||!yx_put_uint(&w,a->pool_count))goto fail;
    for(size_t i=0;i<a->pool_count;++i)
        if(!yx_put_uint(&w,a->pool[i].length)||!yx_put_bytes(&w,a->pool[i].data,a->pool[i].length))goto fail;
    if(!yx_put_uint(&w,a->wasm_length)||!yx_put_bytes(&w,a->wasm,a->wasm_length)||
       !yx_put_uint(&w,0)||!yx_put_uint(&w,a->import_count))goto fail;
    for(size_t i=0;i<a->import_count;++i)
        if(a->imports[i]>=a->name_count||!yx_put_uint(&w,a->imports[i]))goto fail;
    if(a->no_rules) {
        if(!yx_put_uint(&w,0))goto fail;
        goto rules_written;
    }
    if(!yx_put_uint(&w,1)||!yx_put_uint(&w,a->namespace_id?2:0)||
       !yx_put_uint(&w,a->namespace_id)||!yx_put_uint(&w,a->rule_name_id?a->rule_name_id:a->name_count-1)||
       !yx_put_uint(&w,a->tag_count))goto fail;
    for(size_t i=0;i<a->tag_count;++i)if(!yx_put_uint(&w,a->tags[i]))goto fail;
    if(!yx_put_uint(&w,a->metadata_count))goto fail;
    for(size_t i=0;i<a->metadata_count;++i) {
        const yx_physical_meta *m=&a->metadata[i];
        if(!yx_put_uint(&w,m->key)||!yx_put_uint(&w,m->variant))goto fail;
        if(m->variant==0?!yx_put_u8(&w,m->boolean):m->variant==1?!yx_put_signed(&w,m->integer):
           m->variant==2?!yx_put_float(&w,m->floating):!yx_put_uint(&w,m->literal))goto fail;
    }
    if(!yx_put_uint(&w,a->logical))goto fail;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_put_uint(&w,a->mapping[i]*2)||!yx_put_uint(&w,a->name_ids[i])||
           !yx_put_uint(&w,a->kinds[i])||!yx_put_u8(&w,a->pattern_private[i]))goto fail;
    size_t private_count=0;
    for(size_t i=0;i<a->logical;++i)private_count+=a->pattern_private[i];
    if(!yx_put_uint(&w,private_count)||!yx_put_uint(&w,0)||!yx_put_u8(&w,a->private_rule))goto fail;
rules_written:
    if(!yx_put_uint(&w,a->physical)||!yx_put_uint(&w,a->frame_count))goto fail;
    for(size_t i=0;i<a->frame_count;++i) {
        const yx_physical_frame *p=&a->frames[i];const yx_chain_frame *f=&p->frame;
        if(!yx_put_uint(&w,p->pattern*2)||!yx_put_uint(&w,f->variant)||
           ((f->variant<=3||f->variant>=7)&&!yx_put_uint(&w,f->literal_index))||
           ((f->variant==1||f->variant>=10)&&!yx_put_uint(&w,p->mask))||
           (f->variant==0&&(!yx_put_u8(&w,p->anchored)||(p->anchored&&!yx_put_uint(&w,p->offset)))))goto fail;
        if((f->variant==3||f->variant==6)&&
           (!yx_put_uint(&w,f->previous)||!yx_put_uint(&w,yx_chain_unbounded(f))||
            !yx_put_uint(&w,f->minimum)||(!yx_chain_unbounded(f)&&!yx_put_uint(&w,f->maximum))))goto fail;
        if(f->variant>=8?!yx_put_u8(&w,p->padding):!yx_put_uint(&w,f->flags))goto fail;
    }
    size_t bounded_count=0,*order=a->physical?malloc(a->physical*sizeof(*order)):NULL;
    bool *headed=a->physical?calloc(a->physical,sizeof(*headed)):NULL;
    if(a->physical&&(!order||!headed)){free(order);free(headed);goto fail;}
    for(size_t i=0;i<a->physical;++i)bounded_count+=a->bounded[i];
    if(!yx_put_uint(&w,bounded_count)||!yx_physical_map_order(a,a->bounded,a->bounds_order,a->bounds_order_count,order)){free(order);free(headed);goto fail;}
    for(size_t k=0;k<bounded_count;++k) {
        size_t i=order[k];const yx_pattern_filesize_bounds *b=&a->bounds[i];
        if(!yx_put_uint(&w,i*2)||!yx_put_uint(&w,b->lower_kind==2?0:b->lower_kind+1)||
           (b->lower_kind!=2&&!yx_put_signed(&w,b->lower))||!yx_put_uint(&w,b->upper_kind==2?0:b->upper_kind+1)||
           (b->upper_kind!=2&&!yx_put_signed(&w,b->upper))){free(order);free(headed);goto fail;}
    }
    size_t header_count=0;
    for(size_t i=0;i<a->physical;++i)header_count+=(headed[i]=a->headers[i].kind!=0);
    if(!yx_put_uint(&w,header_count)||!yx_physical_map_order(a,headed,a->headers_order,a->headers_order_count,order)){free(order);free(headed);goto fail;}
    for(size_t k=0;k<header_count;++k) {
        size_t i=order[k];const yx_physical_header *h=&a->headers[i];
        if(h->kind>2||!yx_put_uint(&w,i*2)||!yx_put_uint(&w,h->kind)||
           (h->kind==2&&(!yx_put_uint(&w,h->length)||!yx_put_bytes(&w,h->bytes,h->length)))){free(order);free(headed);goto fail;}
    }
    free(order);free(headed);
    if(!yx_put_uint(&w,a->anchored_count))goto fail;
    for(size_t i=0;i<a->anchored_count;++i)if(!yx_put_uint(&w,a->anchored[i]))goto fail;
    if(!yx_put_uint(&w,a->atom_count))goto fail;
    for(size_t i=0;i<a->atom_count;++i) {
        const yx_chain_atom *atom=&a->atoms[i];const yx_archive_regexp_atom *b=&atom->atom;
        if(!yx_put_uint(&w,atom->frame)||!yx_put_uint(&w,b->length)||!yx_put_bytes(&w,b->bytes,b->length)||
           !yx_put_u8(&w,b->exact)||!yx_put_uint(&w,b->backtrack)||!yx_put_u8(&w,b->has_forward)||
           (b->has_forward&&!yx_put_uint(&w,b->forward+1))||!yx_put_u8(&w,b->has_backward)||
           (b->has_backward&&!yx_put_uint(&w,b->backward+1)))goto fail;
    }
    /* Match limits are indexed by PatternId, not by subpattern frame. */
    if(!yx_put_uint(&w,a->code_length)||!yx_put_bytes(&w,a->code,a->code_length)||
       !yx_put_uint(&w,a->globals?a->globals_length:sizeof(globals))||
       !yx_put_bytes(&w,a->globals?a->globals:globals,a->globals?a->globals_length:sizeof(globals))||
       !yx_put_uint(&w,ac_length)||!yx_put_bytes(&w,ac,ac_length)||
       !yx_put_uint(&w,0)||!yx_put_uint(&w,0)||!yx_put_uint(&w,a->physical))goto fail;
    for(size_t i=0;i<a->physical;++i)
        if(!yx_put_u8(&w,a->limits[i]!=0)||(a->limits[i]&&!yx_put_uint(&w,a->limits[i])))goto fail;
    if(!yx_put_uint(&w,0))goto fail;
    free(ac);free(bytes);free(widths);*data=w.data;*length=w.used;return YX_SER_SUCCESS;
fail:free(w.data);free(ac);free(bytes);free(widths);return YX_SER_NO_MEMORY;
}
static uint64_t yx_physical_hash(const uint8_t *data,size_t length)
{
    uint64_t hash=1469598103934665603ull;
    for(size_t i=0;i<length;++i)hash=(hash^data[i])*1099511628211ull;
    return hash;
}
/* Open addressing over entry index + 1; the first equal entry is kept, so
 * lookups return the lowest index as the linear search did. */
static bool yx_physical_index(size_t **slots,size_t *slot_count,size_t *indexed,size_t count,
                              const uint8_t *(*key)(const yx_physical_archive *,size_t,size_t *),
                              const yx_physical_archive *a)
{
    if(*indexed>count){*indexed=0;if(*slots)memset(*slots,0,*slot_count*sizeof(**slots));}
    if(count*2>*slot_count) {
        size_t next=*slot_count?*slot_count:64;
        while(count*2>next){if(next>SIZE_MAX/2/sizeof(**slots))return false;next*=2;}
        size_t *grown=calloc(next,sizeof(*grown));if(!grown)return false;
        free(*slots);*slots=grown;*slot_count=next;*indexed=0;
    }
    for(;*indexed<count;++*indexed) {
        size_t length;const uint8_t *data=key(a,*indexed,&length);
        size_t at=(size_t)yx_physical_hash(data,length)&(*slot_count-1);
        bool duplicate=false;
        while((*slots)[at]) {
            size_t other_length;const uint8_t *other=key(a,(*slots)[at]-1,&other_length);
            if(other_length==length&&!memcmp(other,data,length)){duplicate=true;break;}
            at=(at+1)&(*slot_count-1);
        }
        if(!duplicate)(*slots)[at]=*indexed+1;
    }
    return true;
}
static size_t yx_physical_index_find(const size_t *slots,size_t slot_count,const uint8_t *data,size_t length,
                                     const uint8_t *(*key)(const yx_physical_archive *,size_t,size_t *),
                                     const yx_physical_archive *a)
{
    if(!slot_count)return SIZE_MAX;
    for(size_t at=(size_t)yx_physical_hash(data,length)&(slot_count-1);slots[at];at=(at+1)&(slot_count-1)) {
        size_t other_length;const uint8_t *other=key(a,slots[at]-1,&other_length);
        if(other_length==length&&!memcmp(other,data,length))return slots[at]-1;
    }
    return SIZE_MAX;
}
/* Call after entries were inserted, moved or replaced in place. */
static void yx_physical_index_reset(yx_physical_archive *a)
{
    if(a->pool_slots)memset(a->pool_slots,0,a->pool_slot_count*sizeof(*a->pool_slots));
    if(a->name_slots)memset(a->name_slots,0,a->name_slot_count*sizeof(*a->name_slots));
    a->pool_indexed=a->name_indexed=0;
}
static const uint8_t *yx_physical_pool_key(const yx_physical_archive *a,size_t i,size_t *length)
{*length=a->pool[i].length;return a->pool[i].data;}
static const uint8_t *yx_physical_name_key(const yx_physical_archive *a,size_t i,size_t *length)
{*length=strlen(a->names[i]);return (const uint8_t *)a->names[i];}
static size_t yx_physical_pool(yx_physical_archive *a,yx_literal literal)
{
    if(!yx_physical_index(&a->pool_slots,&a->pool_slot_count,&a->pool_indexed,a->pool_count,yx_physical_pool_key,a))
        return SIZE_MAX;
    size_t found=yx_physical_index_find(a->pool_slots,a->pool_slot_count,literal.data,literal.length,yx_physical_pool_key,a);
    if(found!=SIZE_MAX)return found;
    if(a->pool_count==SIZE_MAX||!yx_physical_pool_reserve(a,a->pool_count+1))return SIZE_MAX;
    a->pool[a->pool_count]=literal;return a->pool_count++;
}
static size_t yx_physical_ident(yx_physical_archive *a,const char *name)
{
    if(!yx_physical_index(&a->name_slots,&a->name_slot_count,&a->name_indexed,a->name_count,yx_physical_name_key,a))
        return SIZE_MAX;
    size_t found=yx_physical_index_find(a->name_slots,a->name_slot_count,(const uint8_t *)name,strlen(name),
                                        yx_physical_name_key,a);
    if(found!=SIZE_MAX)return found;
    if(a->name_count==SIZE_MAX||!yx_physical_names_reserve(a,a->name_count+1))return SIZE_MAX;
    char *copy=yx_copy_string(name);if(!copy)return SIZE_MAX;
    a->names[a->name_count]=copy;return a->name_count++;
}
/* kind: numeric, any, all, none, for-any. Set selection retains logical
 * duplicates, whereas an uninterrupted unique set uses the range import. */
static bool yx_physical_set_parse(const char *source,unsigned *kind,uint64_t *required)
{
    yx_bool_parser p={.at=(const unsigned char *)source};
    if(yx_bool_keyword(&p,"all"))*kind=2;
    else if(yx_bool_keyword(&p,"none"))*kind=3;
    else {
        bool for_any=false;
        if(!yx_pattern_set_parse(source,&for_any,required))return false;
        *kind=for_any?4:*required==UINT64_MAX?1:0;return true;
    }
    if(!yx_bool_keyword(&p,"of")||!yx_bool_keyword(&p,"them"))return false;
    yx_bool_skip_space(&p);return !*p.at;
}
static bool yx_physical_set_wasm(const yx_physical_archive *a,unsigned kind,uint64_t required,
    uint8_t profile,uint8_t **data,size_t *length)
{
    if(!a->logical)return false;
    if(kind==3)return yx_pattern_set_none_wasm(a->mapping,a->logical,profile,data,length);
    if(kind==4)return yx_pattern_set_wasm(a->mapping,a->logical,true,0,profile,data,length);
    if(kind==1)required=1;else if(kind==2)required=a->logical;
    bool consecutive=a->logical==a->physical;
    for(size_t i=0;i<a->logical;++i)if(a->mapping[i]!=i)consecutive=false;
    if(consecutive)return yx_pattern_set_range_wasm(a->physical-1,required,kind!=0,profile,data,length);
    if(kind==1||kind==2)return yx_pattern_set_keyword_wasm(a->mapping,a->logical,kind==2,profile,data,length);
    return kind==0&&yx_pattern_set_wasm(a->mapping,a->logical,false,required,profile,data,length);
}
static bool yx_physical_set_condition(const yx_physical_archive *a,char **source,uint8_t *profile)
{
    /* Fixed keyword forms are common and do not require guessing a numeric
     * threshold. Try them before the bounded numeric search. */
    /* `N of them` for 2 <= N < count differs only in N's constants: its
     * module's length is within a few bytes of `2 of them`'s. A profile whose
     * length is not is not tried for every N (the search is per pattern). */
    bool similar[4]={true,true,true,true};
    if(a->logical>3)for(uint8_t p=0;p<4;++p) {
        uint8_t *wasm=NULL;size_t length=0;
        if(yx_physical_set_wasm(a,0,2,p,&wasm,&length))
            similar[p]=length+32>=a->wasm_length&&a->wasm_length+32>=length;
        free(wasm);
    }
    for(unsigned choice=0;choice<5;++choice) {
        unsigned kind=choice<4?choice+1:0;
        uint64_t maximum=kind?0:a->logical;
        for(uint64_t required=0;required<=maximum;++required)for(uint8_t p=0;p<4;++p) {
            uint8_t *wasm=NULL;size_t length=0;
            if(!kind&&required>=2&&required<a->logical&&!similar[p])continue;
            bool exact=yx_physical_set_wasm(a,kind,required,p,&wasm,&length)&&
                length==a->wasm_length&&!memcmp(wasm,a->wasm,length);
            free(wasm);if(!exact)continue;
            char text[96];
            if(!kind)snprintf(text,sizeof(text),"%llu of them",(unsigned long long)required);
            else snprintf(text,sizeof(text),"%s",kind==1?"any of them":kind==2?"all of them":kind==3?"none of them":"for any of them : ( $ )");
            *source=yx_copy_string(text);if(!*source)return false;*profile=p;return true;
        }
    }
    return false;
}
/* IR::or and IR::and fold a condition with an absorbing constant
 * (`$a or true`) to that constant, after ast2ir.rs has marked the patterns
 * as used: the archive keeps the patterns and its module is that of the
 * constant alone. */
static bool yx_physical_folded(const yx_physical_archive *a,bool *truth)
{
    for(unsigned choice=0;choice<2;++choice) {
        uint8_t *wasm=NULL;size_t length=0;
        *truth=choice==0;
        bool exact=yx_make_constant_wasm(truth,NULL,1,&wasm,&length,NULL)&&
            length==a->wasm_length&&!memcmp(wasm,a->wasm,length);
        free(wasm);if(exact)return true;
    }
    return false;
}
/* The source that folds the same way names every pattern, in the
 * ` and (true or $a)` terms the composed rules use for a pattern without an
 * operand of its own. */
static bool yx_physical_folded_condition(const yx_physical_archive *a,char **source,uint8_t *profile)
{
    bool truth;yx_writer text={0};
    if(!yx_physical_folded(a,&truth))return false;
    bool ok=yx_tr_text(&text,truth?"true":"false");
    for(size_t i=0;ok&&i<a->logical;++i) {
        char anchor[32]="";
        for(size_t f=0;f<a->frame_count;++f)
            if(a->frames[f].pattern==a->mapping[i]&&a->frames[f].anchored) {
                snprintf(anchor,sizeof(anchor)," at %" PRIu64,a->frames[f].offset);break;
            }
        ok=yx_tr_text(&text," and (true or ")&&yx_tr_text(&text,a->names[a->name_ids[i]])&&yx_tr_text(&text,anchor)&&yx_put_u8(&text,')');
    }
    if(!ok||!yx_put_u8(&text,0)){free(text.data);return false;}
    *source=(char *)text.data;*profile=0;return true;
}
/* A part's Aho-Corasick automaton is built from its atoms, which precede it,
 * and is never read back: a composition builds its own from all atoms.
 * Parts are retained until write, so drop the automaton payload (leaving an
 * empty one) as soon as a part is encoded. Equal parts stay equal and the
 * literal pools they lend keep their bytes. A part that does not parse is
 * left whole for the caller to reject as before. */
static bool yx_physical_compact_part(uint8_t **data,size_t *length)
{
    yx_physical_archive probe;uint64_t n;
    if(!yx_physical_read(*data,*length,&probe))return true;
    size_t start=(size_t)(probe.globals-*data)+probe.globals_length;
    yx_physical_destroy(&probe);
    yx_reader r={*data,*length,start,false,false};
    if(!yx_get_uint(&r,&n)||n>*length-r.at||!n)return true;
    size_t end=r.at+(size_t)n,compact=start+1+(*length-end);
    uint8_t *copy=malloc(compact);if(!copy)return false;
    memcpy(copy,*data,start);copy[start]=0;memcpy(copy+start+1,*data+end,*length-end);
    free(*data);*data=copy;*length=compact;return true;
}
/* yx_ser_encode for a composition part, already compacted (serialization.c). */
static yx_ser_result yx_ser_encode_part(const YRX_RULES *rules,uint8_t **data,size_t *length);
/* Grows a composition's atom vector geometrically; *capacity starts at the
 * vector's length. Nothing to reserve never reallocates: realloc(p, 0) may
 * free p and return NULL (MSVC, glibc 2.33+) and is undefined in C23. */
static bool yx_physical_atoms_reserve(yx_physical_archive *a,size_t *capacity,size_t count)
{
    if(count<=*capacity)return true;
    size_t next=*capacity<=SIZE_MAX/2&&count<*capacity*2?*capacity*2:count;
    if(next>SIZE_MAX/sizeof(*a->atoms))return false;
    yx_chain_atom *atoms=realloc(a->atoms,next*sizeof(*atoms));
    if(!atoms)return false;
    a->atoms=atoms;*capacity=next;return true;
}
/* Composition encodes one single-pattern archive per pattern; lowering its
 * Wasm module in yx_v12_archive_wasm, a pure function of the module and the
 * profile, repeats for every pattern of the same shape. A composition
 * installs this memo on its thread so the lowering reuses its last result
 * for an equal module and profile. */
typedef struct yx_v12_memo {
    unsigned profile;
    uint8_t *input,*output;
    size_t input_length,output_length;
    bool valid;
} yx_v12_memo;
#ifdef _MSC_VER
static __declspec(thread) yx_v12_memo *yx_v12_memo_active;
#else
static _Thread_local yx_v12_memo *yx_v12_memo_active;
#endif
static void yx_v12_memo_free(yx_v12_memo *memo)
{
    free(memo->input);free(memo->output);memset(memo,0,sizeof(*memo));
}
/* First-of-value index over compacted parts: slots hold part index + 1 and
 * only a part without an equal earlier one is inserted, so a lookup finds
 * the first equal part as a scan in declaration order did. */
typedef struct yx_physical_part_index {
    size_t *slots;uint64_t *hashes;size_t slot_count,count;
} yx_physical_part_index;
static size_t yx_physical_part_find(const yx_physical_part_index *x,uint8_t *const *parts,const size_t *lengths,
                                    size_t index,uint64_t hash)
{
    if(!x->slot_count)return SIZE_MAX;
    for(size_t at=(size_t)hash&(x->slot_count-1);x->slots[at];at=(at+1)&(x->slot_count-1)) {
        size_t k=x->slots[at]-1;
        if(x->hashes[at]==hash&&lengths[k]==lengths[index]&&!memcmp(parts[k],parts[index],lengths[index]))return k;
    }
    return SIZE_MAX;
}
static bool yx_physical_part_insert(yx_physical_part_index *x,size_t index,uint64_t hash)
{
    size_t at;
    if((x->count+1)*2>x->slot_count) {
        size_t next=x->slot_count?x->slot_count*2:64;
        while((x->count+1)*2>next)next*=2;
        size_t *slots=calloc(next,sizeof(*slots));uint64_t *hashes=malloc(next*sizeof(*hashes));
        if(!slots||!hashes){free(slots);free(hashes);return false;}
        for(size_t i=0;i<x->slot_count;++i)if(x->slots[i]) {
            at=(size_t)x->hashes[i]&(next-1);
            while(slots[at])at=(at+1)&(next-1);
            slots[at]=x->slots[i];hashes[at]=x->hashes[i];
        }
        free(x->slots);free(x->hashes);x->slots=slots;x->hashes=hashes;x->slot_count=next;
    }
    at=(size_t)hash&(x->slot_count-1);
    while(x->slots[at])at=(at+1)&(x->slot_count-1);
    x->slots[at]=index+1;x->hashes[at]=hash;++x->count;return true;
}
static yx_ser_result yx_encode_physical_patterns(const YRX_RULES *rules,uint8_t **data,size_t *length)
{
    if(!rules||rules->rule_count!=1||rules->import_count||rules->global_count)return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule=&rules->rules[0];
    if(rule->pattern_count<2||rule->is_global||!rule->condition_text)return YX_SER_UNSUPPORTED;
    yx_physical_archive *a=calloc(1,sizeof(*a)),*part=calloc(1,sizeof(*part));
    yx_integer_expr *tree=calloc(1,sizeof(*tree));yx_pattern_expression_context context={0};
    uint8_t **parts=calloc(rule->pattern_count,sizeof(*parts)),*wasm=NULL;
    size_t *part_lengths=calloc(rule->pattern_count,sizeof(*part_lengths)),*pool=NULL,wasm_length=0,atom_capacity=0;
    yx_writer code={0};yx_ser_result status=YX_SER_UNSUPPORTED;
    yx_physical_part_index distinct={0};
    yx_v12_memo memo={0},*previous_memo=yx_v12_memo_active;yx_v12_memo_active=&memo;
    if(!a||!part||!tree||!parts||!part_lengths||
       !yx_physical_patterns_reserve(a,rule->pattern_count)||!yx_physical_tags_reserve(a,rule->tag_count)||
       !yx_physical_metadata_reserve(a,rule->metadata_count)||!yx_pattern_expression_reserve(&context,rule->pattern_count))
        {status=YX_SER_NO_MEMORY;goto done;}
    a->logical=rule->pattern_count;a->private_rule=rule->is_private;
    if(yx_physical_ident(a,"default")==SIZE_MAX||
       (a->namespace_id=yx_physical_ident(a,rule->namespace_name?rule->namespace_name:"default"))==SIZE_MAX)goto done;
    a->tag_count=rule->tag_count;a->metadata_count=rule->metadata_count;
    for(size_t i=0;i<a->tag_count;++i)
        if((a->tags[i]=yx_physical_ident(a,rule->tags[i]))==SIZE_MAX)goto done;
    for(size_t i=0;i<a->metadata_count;++i) {
        const YRX_METADATA *value=&rule->metadata[i];yx_physical_meta *m=&a->metadata[i];
        if((m->key=yx_physical_ident(a,value->identifier))==SIZE_MAX)goto done;
        m->variant=value->value_type==YRX_BOOLEAN?0:value->value_type==YRX_I64?1:value->value_type==YRX_F64?2:value->value_type==YRX_STRING?3:4;
        if(m->variant==0)m->boolean=value->value.boolean;
        else if(m->variant==1)m->integer=value->value.i64;
        else if(m->variant==2)m->floating=value->value.f64;
        else {
            yx_literal literal=m->variant==3?(yx_literal){(const uint8_t *)value->value.string,strlen(value->value.string)}:
                (yx_literal){value->value.bytes.data,value->value.bytes.length};
            if((m->literal=yx_physical_pool(a,literal))==SIZE_MAX)goto done;
        }
    }
    for(size_t i=0;i<rule->pattern_count;++i) {
        const YRX_PATTERN *p=&rule->patterns[i];
        if(p->modifiers&~(YX_MOD_ASCII|YX_MOD_WIDE|YX_MOD_NOCASE|YX_MOD_FULLWORD|YX_MOD_DOTALL|YX_MOD_XOR|YX_MOD_BASE64|YX_MOD_BASE64WIDE|YX_MOD_PRIVATE))goto done;
        a->name_ids[i]=yx_physical_ident(a,p->identifier);a->kinds[i]=(uint8_t)p->kind;
        a->pattern_private[i]=(p->modifiers&YX_MOD_PRIVATE)!=0;
        if(a->name_ids[i]==SIZE_MAX){status=YX_SER_NO_MEMORY;goto done;}
        YRX_PATTERN pattern=*p;YRX_RULE adapted=*rule;YRX_RULES base=*rules;
        pattern.identifier="$a";pattern.modifiers&=~YX_MOD_PRIVATE;adapted.identifier="r";adapted.namespace_name="default";
        adapted.tags=NULL;adapted.tag_count=0;adapted.metadata=NULL;adapted.metadata_count=0;adapted.patterns=&pattern;adapted.pattern_count=1;
        adapted.is_private=false;adapted.condition_text="$a";base.rules=&adapted;
        base.serialized_prefix=NULL;base.serialized_prefix_length=0;
        status=yx_ser_encode_part(&base,&parts[i],&part_lengths[i]);
        if(status!=YX_SER_SUCCESS)goto done;
        status=YX_SER_UNSUPPORTED;
        uint64_t part_hash=yx_physical_hash(parts[i],part_lengths[i]);
        size_t duplicate=yx_physical_part_find(&distinct,parts,part_lengths,i,part_hash);
        if(duplicate!=SIZE_MAX){a->mapping[i]=a->mapping[duplicate];continue;}
        if(!yx_physical_part_insert(&distinct,i,part_hash)){status=YX_SER_NO_MEMORY;goto done;}
        if(!yx_physical_read(parts[i],part_lengths[i],part)||part->logical!=1||part->physical!=1)goto done;
        a->mapping[i]=a->physical++;
        size_t frame_start=a->frame_count,atom_start=a->atom_count;
        free(pool);pool=calloc(part->pool_count?part->pool_count:1,sizeof(*pool));
        if(!pool){status=YX_SER_NO_MEMORY;goto done;}
        for(size_t j=0;j<part->pool_count;++j)
            if((pool[j]=yx_physical_pool(a,part->pool[j]))==SIZE_MAX)goto done;
        if(part->frame_count>SIZE_MAX-a->frame_count||part->atom_count>SIZE_MAX/sizeof(*a->atoms)-a->atom_count||
           code.used>UINT32_MAX||part->code_length>UINT32_MAX-code.used)goto done;
        if(!yx_physical_frames_reserve(a,a->frame_count+part->frame_count)){status=YX_SER_NO_MEMORY;goto done;}
        for(size_t j=0;j<part->frame_count;++j) {
            yx_physical_frame f=part->frames[j];f.pattern=a->mapping[i];
            if((f.frame.variant<=3||f.frame.variant>=7))f.frame.literal_index=pool[f.frame.literal_index];
            if(f.frame.variant==1||f.frame.variant>=10)f.mask=pool[f.mask];
            if(f.frame.variant==3||f.frame.variant==6)f.frame.previous+=frame_start;
            a->frames[a->frame_count++]=f;
        }
        if(!yx_physical_atoms_reserve(a,&atom_capacity,a->atom_count+part->atom_count)){status=YX_SER_NO_MEMORY;goto done;}
        for(size_t j=0;j<part->atom_count;++j) {
            a->atoms[atom_start+j]=part->atoms[j];yx_chain_atom *atom=&a->atoms[atom_start+j];
            atom->frame+=frame_start;
            if(atom->atom.has_forward)atom->atom.forward+=(uint32_t)code.used;
            if(atom->atom.has_backward)atom->atom.backward+=(uint32_t)code.used;
        }
        a->atom_count+=part->atom_count;
        if(!yx_put_bytes(&code,part->code,part->code_length)){status=YX_SER_NO_MEMORY;goto done;}
        yx_physical_destroy(part);
    }
    if((a->rule_name_id=yx_physical_ident(a,rule->identifier))==SIZE_MAX)goto done;
    context.name=rule->patterns[0].identifier;context.pattern_count=rule->pattern_count;
    for(size_t i=0;i<rule->pattern_count;++i)yx_pattern_names(&context)[i]=rule->patterns[i].identifier,yx_pattern_mapping(&context)[i]=a->mapping[i];
    yx_pattern_expression_setup(tree,&context);
    int root=yx_integer_expr_condition(tree,rule->condition_text);
    if(root<0) {
        unsigned kind;uint64_t required=0;
        if(!yx_physical_set_parse(rule->condition_text,&kind,&required)||
           !yx_physical_set_wasm(a,kind,required,yx_integer_import_profile(),&wasm,&wasm_length))goto done;
        for(size_t i=0;i<a->physical;++i)yx_pattern_limits(&context)[i]=1;
    } else if(!context.saw_pattern||!yx_pattern_expression_wasm(tree,root,&context,yx_integer_import_profile(),&wasm,&wasm_length))goto done;
    a->wasm=wasm;a->wasm_length=wasm_length;a->code=code.data;a->code_length=code.used;
    memcpy(a->limits,yx_pattern_limits(&context),a->physical*sizeof(*a->limits));
    status=yx_physical_write(a,data,length);
    if(status==YX_SER_SUCCESS&&root>=0) {
        yx_ser_result anchored=yx_constrain_pattern_anchors(data,length,tree,root,rule);
        if(anchored==YX_SER_NO_MEMORY){free(*data);*data=NULL;*length=0;status=anchored;}
    }
done:
    yx_v12_memo_active=previous_memo;yx_v12_memo_free(&memo);
    free(distinct.slots);free(distinct.hashes);
    if(parts)for(size_t i=0;i<rule->pattern_count;++i)free(parts[i]);
    free(parts);free(part_lengths);free(pool);yx_pattern_expression_destroy(&context);
    free(wasm);free(code.data);yx_integer_expr_free(tree);
    if(a){yx_physical_destroy(a);free(a);}if(part){yx_physical_destroy(part);free(part);}
    return status;
}
/* Rebuilds the name table and literal pool of a single-rule archive in the
 * writer's order with the given imports, tags and metadata (none to strip
 * them): names are `default`, imported modules, the namespace, tags,
 * metadata keys, pattern names and the rule name; metadata strings precede
 * pattern literals in the pool. The caller sets the module globals. */
static bool yx_physical_redecorate(yx_physical_archive *a,char *const *imports,size_t import_count,
    char *const *tags,size_t tag_count,const YRX_METADATA *metadata,size_t metadata_count)
{
    char **old_names=a->names;size_t old_name_count=a->name_count;
    yx_literal *old_pool=a->pool;size_t old_pool_count=a->pool_count;
    size_t namespace_id=a->namespace_id,rule_name_id=a->rule_name_id,*pool_map=NULL;
    bool ok=false,*used=NULL;
    if(namespace_id>=old_name_count||rule_name_id>=old_name_count)return false;
    for(size_t i=0;i<a->logical;++i)if(a->name_ids[i]>=old_name_count)return false;
    a->names=NULL;a->name_count=a->name_capacity=0;a->pool=NULL;a->pool_count=a->pool_capacity=0;
    yx_physical_index_reset(a);
    pool_map=calloc(old_pool_count?old_pool_count:1,sizeof(*pool_map));
    used=calloc(old_pool_count?old_pool_count:1,sizeof(*used));
    if(!pool_map||!used||yx_physical_ident(a,"default")!=0||!yx_physical_imports_reserve(a,import_count))goto done;
    a->import_count=0;
    for(size_t i=0;i<import_count;++i) {
        size_t id=yx_physical_ident(a,imports[i]),j=0;
        if(id==SIZE_MAX)goto done;
        while(j<a->import_count&&a->imports[j]!=id)++j;
        if(j==a->import_count)a->imports[a->import_count++]=id;
    }
    a->namespace_id=yx_physical_ident(a,old_names[namespace_id]);
    if(a->namespace_id==SIZE_MAX||!yx_physical_tags_reserve(a,tag_count)||
       !yx_physical_metadata_reserve(a,metadata_count))goto done;
    a->tag_count=tag_count;
    for(size_t i=0;i<tag_count;++i)if((a->tags[i]=yx_physical_ident(a,tags[i]))==SIZE_MAX)goto done;
    a->metadata_count=metadata_count;
    for(size_t i=0;i<metadata_count;++i) {
        const YRX_METADATA *value=&metadata[i];yx_physical_meta *m=&a->metadata[i];
        memset(m,0,sizeof(*m));
        if((m->key=yx_physical_ident(a,value->identifier))==SIZE_MAX)goto done;
        m->variant=value->value_type==YRX_BOOLEAN?0:value->value_type==YRX_I64?1:
                   value->value_type==YRX_F64?2:value->value_type==YRX_STRING?3:4;
        if(m->variant==0)m->boolean=value->value.boolean;
        else if(m->variant==1)m->integer=value->value.i64;
        else if(m->variant==2)m->floating=value->value.f64;
        else {
            yx_literal literal=m->variant==3?
                (yx_literal){(const uint8_t *)value->value.string,strlen(value->value.string)}:
                (yx_literal){value->value.bytes.data,value->value.bytes.length};
            if((m->literal=yx_physical_pool(a,literal))==SIZE_MAX)goto done;
        }
    }
    for(size_t i=0;i<a->logical;++i)
        if((a->name_ids[i]=yx_physical_ident(a,old_names[a->name_ids[i]]))==SIZE_MAX)goto done;
    if((a->rule_name_id=yx_physical_ident(a,old_names[rule_name_id]))==SIZE_MAX)goto done;
    /* Pattern literals keep their order; old metadata strings drop out. */
    for(size_t i=0;i<a->frame_count;++i) {
        const yx_physical_frame *f=&a->frames[i];
        if((f->frame.variant<=3||f->frame.variant>=7)&&f->frame.literal_index<old_pool_count)
            used[f->frame.literal_index]=true;
        if((f->frame.variant==1||f->frame.variant>=10)&&f->mask<old_pool_count)used[f->mask]=true;
    }
    for(size_t j=0;j<old_pool_count;++j)
        if(used[j]&&(pool_map[j]=yx_physical_pool(a,old_pool[j]))==SIZE_MAX)goto done;
    for(size_t i=0;i<a->frame_count;++i) {
        yx_physical_frame *f=&a->frames[i];
        if(f->frame.variant<=3||f->frame.variant>=7)f->frame.literal_index=pool_map[f->frame.literal_index];
        if(f->frame.variant==1||f->frame.variant>=10)f->mask=pool_map[f->mask];
    }
    ok=true;
done:
    for(size_t i=0;i<old_name_count;++i)free(old_names[i]);
    free(old_names);free(old_pool);free(pool_map);free(used);
    return ok;
}
static bool yx_unanchored_pattern_terms_archive(const yx_physical_archive *a,yx_integer_expr *tree,int *root);
static bool yx_physical_condition(const yx_physical_archive *a,char **condition,uint8_t *profile_out)
{
    yx_integer_expr *tree=calloc(1,sizeof(*tree));yx_pattern_expression_context c={0};
    yx_reader r={a->wasm,a->wasm_length,0,false,false};yx_writer source={0};
    uint8_t *canonical=NULL,marker;size_t canonical_length=0,body_end;
    uint64_t width,functions,locals;bool ok=false;
    if(!tree)return false;
    if(!yx_pattern_expression_reserve(&c,a->physical))goto done;
    yx_pattern_expression_setup(tree,&c);
    if(!yx_pattern_expression_read_header(&r,tree,&c)||!yx_rule_expression_byte(&r,10)||
       !yx_get_uleb(&r,&width)||width!=r.length-r.at||!yx_get_uleb(&r,&functions)||functions!=(c.presence?4u:3u)||
       !yx_get_uleb(&r,&width)||width>r.length-r.at)goto done;
    if(c.helper_first){r.at+=(size_t)width;if(!yx_get_uleb(&r,&width)||width>r.length-r.at)goto done;}
    body_end=r.at+(size_t)width;
    if(!yx_get_uleb(&r,&locals)||locals>1||(locals&&(!yx_get_uleb(&r,&width)||width<1||width>2||
       !yx_get_u8(&r,&marker)||marker!=0x7e))||!yx_rule_expression_byte(&r,2)||!yx_rule_expression_byte(&r,0x7f))goto done;
    int root=yx_integer_wasm_block(&r,body_end,tree,0,-1);
    if(root<0||!c.saw_pattern||c.pattern_count>a->physical)goto done;
    if(!yx_unanchored_pattern_terms_archive(a,tree,&root))goto done;
    if(!yx_pattern_expression_scope_fixup(tree,&root,&c))goto done;
    uint8_t profile=4;int original_root=root;
    /* Static inverses retain the private OR form without a final guard.
     * Writers use the new form; decode both only after full regeneration. */
    for(unsigned format=0;format<2&&profile==4;++format) {
        tree->legacy_boolean_or=format!=0;
        for(unsigned variant=0;variant<3&&profile==4;++variant) {
            root=variant?yx_integer_expr_node_new(tree,variant==1?0xd8:0xd9,original_root,original_root,0):original_root;
            if(root<0)goto done;
            for(profile=0;profile<4;++profile) {
                free(canonical);canonical=NULL;
                if(yx_pattern_expression_wasm(tree,root,&c,profile,&canonical,&canonical_length)&&
                   canonical_length==a->wasm_length&&!memcmp(canonical,a->wasm,a->wasm_length))break;
            }
        }
    }
    tree->legacy_boolean_or=false;
    if(profile==4)goto done;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_pattern_names(&c)[a->mapping[i]])yx_pattern_names(&c)[a->mapping[i]]=a->names[a->name_ids[i]];
    c.name=yx_pattern_names(&c)[0];
    if(!yx_put_u8(&source,'(')||!yx_integer_expr_print(tree,root,&source,0,false,0)||!yx_put_u8(&source,')'))goto done;
    /* A pattern whose operands IR::and / IR::or folded away has no operand
     * in the module: name it in a term that folds away again, with a range
     * when the archive tracks all its matches (disallow_fast_scan ran for
     * the folded operand). Sets name their patterns themselves. */
    for(size_t i=0;!c.of_set_count&&i<a->logical;++i) {
        bool read=false;
        for(size_t q=0;q<i;++q)read|=a->mapping[q]==a->mapping[i];
        for(size_t n=0;!read&&n<tree->count;++n) {
            const yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[n];
            read=node->op>=0xd1&&node->op<=0xd7&&node->value==(int64_t)a->mapping[i];
        }
        if(read)continue;
        if(!yx_tr_text(&source," and (true or ")||!yx_tr_text(&source,a->names[a->name_ids[i]])||
           !yx_tr_text(&source,a->limits[a->mapping[i]]?")":" in (0..1))"))goto done;
    }
    for(size_t i=0;i<a->logical;++i) {
        char anchor[32]="";
        if(!strcmp(yx_pattern_names(&c)[a->mapping[i]],a->names[a->name_ids[i]]))continue;
        /* An alias of an anchored pattern is used at the same offset. */
        for(size_t f=0;f<a->frame_count;++f)
            if(a->frames[f].pattern==a->mapping[i]&&a->frames[f].anchored) {
                snprintf(anchor,sizeof(anchor)," at %" PRIu64,a->frames[f].offset);break;
            }
        if(!yx_tr_text(&source," and (true or ")||!yx_tr_text(&source,a->names[a->name_ids[i]])||
           !yx_tr_text(&source,anchor)||!yx_put_u8(&source,')'))goto done;
    }
    if(!yx_put_u8(&source,0))goto done;
    *condition=(char *)source.data;source.data=NULL;*profile_out=profile;ok=true;
done:tree->legacy_boolean_or=false;yx_pattern_expression_destroy(&c);yx_integer_expr_free(tree);free(canonical);free(source.data);
    return ok||yx_physical_set_condition(a,condition,profile_out)||yx_physical_folded_condition(a,condition,profile_out);
}
static bool yx_physical_hex(yx_writer *w,const yx_hex_atom *atoms,size_t count,unsigned depth)
{
    static const char digits[]="0123456789abcdef";
    if(depth>256)return false;
    for(size_t i=0;i<count;++i) {
        const yx_hex_atom *a=&atoms[i];
        if(a->kind==YX_HEX_BYTE) {
            if(a->negated&&!yx_put_u8(w,'~'))return false;
            if(!yx_put_u8(w,(a->mask&0xf0)?digits[a->value>>4]:'?')||
               !yx_put_u8(w,(a->mask&15)?digits[a->value&15]:'?'))return false;
        } else if(a->kind==YX_HEX_JUMP) {
            char gap[64];
            if(a->maximum==UINT32_MAX&&!a->finite_maximum)snprintf(gap,sizeof(gap),"[%u-]",a->minimum);
            else snprintf(gap,sizeof(gap),"[%u-%u]",a->minimum,a->maximum);
            if(!yx_tr_text(w,gap))return false;
        } else if(a->kind==YX_HEX_ALTERNATIVE) {
            if(!yx_put_u8(w,'('))return false;
            for(size_t j=0;j<a->branch_count;++j)
                if((j&&!yx_tr_text(w," | "))||!yx_physical_hex(w,a->branches[j].atoms,a->branches[j].count,depth+1))return false;
            if(!yx_put_u8(w,')'))return false;
        } else return false;
        if(!yx_put_u8(w,' '))return false;
    }
    return true;
}
static bool yx_physical_declaration(yx_writer *w,const char *name,const YRX_PATTERN *p)
{
    if(!yx_tr_text(w,name)||!yx_tr_text(w," = "))return false;
    if(p->kind==YX_PATTERN_HEX) {
        if(!yx_tr_text(w,"{ ")||!yx_physical_hex(w,p->hex_atoms,p->hex_atom_count,0)||!yx_tr_text(w,"} "))return false;
    } else if(p->kind==YX_PATTERN_REGEX) {
        if(!yx_put_u8(w,'/')||!yx_tr_text(w,p->regexp)||!yx_put_u8(w,'/')||
           ((p->modifiers&YX_MOD_DOTALL)&&!yx_put_u8(w,'s')))return false;
    } else {
        if(!yx_put_u8(w,'"'))return false;
        for(size_t i=0;i<p->length;++i)if(!yx_tr_hex_text(w,p->bytes[i]))return false;
        if(!yx_put_u8(w,'"'))return false;
    }
    if(((p->modifiers&YX_MOD_ASCII)&&!yx_tr_text(w," ascii"))||
       ((p->modifiers&YX_MOD_WIDE)&&!yx_tr_text(w," wide"))||
       ((p->modifiers&YX_MOD_NOCASE)&&!yx_tr_text(w," nocase"))||
       ((p->modifiers&YX_MOD_FULLWORD)&&!yx_tr_text(w," fullword")))return false;
    if(p->modifiers&YX_MOD_XOR) {
        char modifier[48];
        snprintf(modifier,sizeof(modifier)," xor(%u-%u)",p->xor_min,p->xor_max);
        if(!yx_tr_text(w,modifier))return false;
    }
    for(unsigned output=0;output<2;++output) {
        if(!(p->modifiers&(output?YX_MOD_BASE64WIDE:YX_MOD_BASE64)))continue;
        const char *alphabet=output?p->base64wide_alphabet:p->base64_alphabet;
        if(!yx_tr_text(w,output?" base64wide":" base64"))return false;
        if(alphabet) {
            if(strlen(alphabet)!=64||!yx_tr_text(w,"(\""))return false;
            for(size_t i=0;i<64;++i) {
                uint8_t byte=(uint8_t)alphabet[i];
                if(byte<' '||byte>=127||byte=='"'||byte=='\\'||!yx_put_u8(w,byte))return false;
            }
            if(!yx_tr_text(w,"\")"))return false;
        }
    }
    return yx_put_u8(w,' ');
}
/* A single-pattern archive read back through the legacy readers can lose
 * the word-boundary flags (a literal regexp reads back as hex bytes), but
 * the physical frames keep them: FullwordLeft on the head frame and
 * FullwordRight on the last one. */
static bool yx_physical_pattern_declaration(yx_writer *w,const char *name,const YRX_PATTERN *p,
    const yx_physical_archive *a,size_t physical)
{
    YRX_PATTERN copy=*p;uint16_t flags=0;
    for(size_t i=0;i<a->frame_count;++i)
        if(a->frames[i].pattern==physical&&a->frames[i].frame.variant<8)flags|=a->frames[i].frame.flags;
    if((flags&24u)&&copy.kind!=YX_PATTERN_HEX)copy.modifiers|=YX_MOD_FULLWORD;
    return yx_physical_declaration(w,name,&copy);
}
/* The flags yx_physical_pattern_declaration collects, for every physical
 * pattern in one pass over the frames (one scan per declaration is
 * quadratic in large rule sets). NULL on allocation failure. */
static uint16_t *yx_physical_frame_flags(const yx_physical_archive *a)
{
    uint16_t *flags=calloc(a->physical?a->physical:1,sizeof(*flags));
    if(!flags)return NULL;
    for(size_t i=0;i<a->frame_count;++i)
        if(a->frames[i].pattern<a->physical&&a->frames[i].frame.variant<8)flags[a->frames[i].pattern]|=a->frames[i].frame.flags;
    return flags;
}
static bool yx_physical_flagged_declaration(yx_writer *w,const char *name,const YRX_PATTERN *p,
    const yx_physical_archive *a,const uint16_t *flags,size_t physical)
{
    YRX_PATTERN copy=*p;uint16_t pattern_flags=physical<a->physical?flags[physical]:0;
    if((pattern_flags&24u)&&copy.kind!=YX_PATTERN_HEX)copy.modifiers|=YX_MOD_FULLWORD;
    return yx_physical_declaration(w,name,&copy);
}
/* Atom entry points identify the final verifier segment of a physical
 * pattern. Walking that segment includes every instruction up to MATCH,
 * including code that follows the atom's selected verification position. */
static bool yx_physical_program_end(const yx_physical_archive *a,const size_t *atom_ids,size_t atom_n,size_t begin,size_t *end)
{
    bool found=false,fast=false;size_t maximum=0;
    for(size_t k=0;k<atom_n;++k) {
        const yx_chain_atom *atom=&a->atoms[atom_ids[k]];
        const yx_archive_regexp_atom *b=&atom->atom;
        if((b->has_forward&&b->forward<begin)||(b->has_backward&&b->backward<begin))return false;
        if(b->has_forward&&(!found||b->forward>=maximum))maximum=b->forward,found=true,fast=(a->frames[atom->frame].frame.flags&64u)!=0;
        if(b->has_backward&&(!found||b->backward>=maximum))maximum=b->backward,found=true,fast=(a->frames[atom->frame].frame.flags&64u)!=0;
    }
    if(!found){*end=begin;return true;}
    size_t at=maximum;
    if(fast) {
        yx_fast_program *program=calloc(1,sizeof(*program));
        if(!program)return false;
        bool ok=yx_fast_read_sequence(program,a->code,a->code_length,&at);
        yx_fast_program_destroy(program);
        if(!ok)return false;
    } else {
        for(;;) {
            size_t width=yx_tr_instruction_size(a->code+at,a->code_length-at);
            if(!width)return false;
            bool match=a->code[at]==0xaa&&width==2&&a->code[at+1]==0;
            at+=width;
            if(match)break;
        }
    }
    *end=at;return true;
}
/* Internal loads nested on this thread. The composed codec's relaxed last
 * resort loads its patterns through such loads, so it runs only outside one:
 * each nesting level costs the decoder's large stack frames. */
#ifdef _MSC_VER
static __declspec(thread) unsigned yx_physical_inspect_nesting;
#else
static _Thread_local unsigned yx_physical_inspect_nesting;
#endif
/* An internal load whose rules are read for their declarations and
 * conditions only (yx_inspect_begin). */
static YRX_RESULT yx_physical_inspect_load(const uint8_t *data,size_t length,YRX_RULES **loaded)
{
    yx_inspect_begin();++yx_physical_inspect_nesting;
    YRX_RESULT result=yrx_rules_deserialize(data,length,loaded);
    --yx_physical_inspect_nesting;yx_inspect_end();
    return result;
}
/* The reference keeps literal pools and search atoms independently. A
 * changed pool can still be read: exact atoms are authoritative, and partial
 * atoms trigger verification against the changed pool. */
static bool yx_physical_load_literal(const yx_physical_archive *a,YRX_RULES **loaded)
{
    if(a->logical!=1||a->physical!=1||a->frame_count!=1||a->code_length||!a->atom_count||a->kinds[0]!=0)return false;
    const yx_physical_frame *frame=&a->frames[0];const yx_chain_frame *f=&frame->frame;
    if(f->variant!=0||frame->anchored||!f->literal_length||
       (f->flags!=0&&f->flags!=2&&f->flags!=24&&f->flags!=26))return false;
    for(size_t i=0;i<a->atom_count;++i) {
        const yx_archive_regexp_atom *atom=&a->atoms[i].atom;
        if(a->atoms[i].frame||!atom->length||atom->length>4||atom->has_forward||atom->has_backward||
           atom->backtrack>f->literal_length||atom->length>f->literal_length-atom->backtrack||
           (atom->exact&&(atom->backtrack||atom->length!=f->literal_length)))return false;
    }
    YRX_PATTERN pattern={.kind=YX_PATTERN_TEXT,.bytes=(uint8_t *)f->literal,.length=f->literal_length,
        .modifiers=((f->flags&2)?YX_MOD_NOCASE:0)|((f->flags&24)?YX_MOD_FULLWORD:0)};
    yx_writer source={0};bool ok=false;
    if(!yx_tr_text(&source,"rule r { strings: ")||!yx_physical_declaration(&source,"$a",&pattern)||
       !yx_tr_text(&source," condition: $a }")||!yx_put_u8(&source,0))goto done;
    if(yx_compile_quiet((char *)source.data,loaded)!=YRX_SUCCESS||!(*loaded)||(*loaded)->rule_count!=1||
       (*loaded)->rules[0].pattern_count!=1)goto done;
    yx_archived_literal_prefilter *filter=&(*loaded)->rules[0].patterns[0].archived_literal_prefilter;
    filter->atoms=calloc(a->atom_count,sizeof(*filter->atoms));if(!filter->atoms)goto done;
    filter->count=a->atom_count;
    for(size_t i=0;i<a->atom_count;++i) {
        const yx_archive_regexp_atom *atom=&a->atoms[i].atom;
        filter->atoms[i]=(yx_archived_literal_atom){.length=atom->length,.backtrack=atom->backtrack,.exact=atom->exact};
        memcpy(filter->atoms[i].bytes,atom->bytes,atom->length);
    }
    ok=true;
done:
    if(!ok){yrx_rules_destroy(*loaded);*loaded=NULL;}
    free(source.data);return ok;
}
static bool yx_physical_copy_prefilter(yx_archived_literal_prefilter *to,const yx_archived_literal_prefilter *from)
{
    if(!from->atoms)return true;
    if(from->count>SIZE_MAX/sizeof(*to->atoms))return false;
    to->atoms=malloc(from->count*sizeof(*to->atoms));if(!to->atoms)return false;
    memcpy(to->atoms,from->atoms,from->count*sizeof(*to->atoms));to->count=from->count;return true;
}
/* A copy of an archived program (one allocation), or NULL without one. False
 * on allocation failure. */
static bool yx_physical_copy_regexp(yx_archived_regexp **to,const yx_archived_regexp *from)
{
    *to=NULL;
    if(!from)return true;
    *to=malloc(from->size);if(!*to)return false;
    memcpy(*to,from,from->size);return true;
}
/* regex_vm.h, which this file's includer reads later. */
bool yx_rx_archived_code_valid(const uint8_t *code, size_t code_length, const size_t *entries,
                               size_t entry_count, bool fast);
/* The archive's own program of a part (frames, atoms and code already those
 * of the part alone): every frame is a Regexp sub-pattern, at most two of
 * them. NULL for any other part, an atom outside the code or without
 * memory; the pattern then gets the program its declaration compiles to.
 * The archive's code is run as it is and need not come from a compiler:
 * code that yx_rx_archived_code_valid does not accept from the atoms' entry
 * offsets gives NULL as well. */
static yx_archived_regexp *yx_physical_part_regexp(const yx_physical_archive *one)
{
    size_t counts[2]={0,0},filled[2]={0,0},total;
    if(!one->frame_count||one->frame_count>2||one->code_length>UINT32_MAX)return NULL;
    for(size_t i=0;i<one->frame_count;++i)
        if(one->frames[i].frame.variant!=4||one->frames[i].anchored)return NULL;
    for(size_t i=0;i<one->atom_count;++i) {
        const yx_chain_atom *atom=&one->atoms[i];
        if(atom->frame>=one->frame_count||atom->atom.length>8||
           (atom->atom.has_forward&&atom->atom.forward>=one->code_length)||
           (atom->atom.has_backward&&atom->atom.backward>=one->code_length))return NULL;
        ++counts[atom->frame];
    }
    total=counts[0]+counts[1];
    if(total>(SIZE_MAX-sizeof(yx_archived_regexp)-one->code_length)/sizeof(yx_archived_regexp_atom))return NULL;
    {
        /* The entry offsets of the FastVM atoms, then of the PikeVM ones. */
        size_t *entries=malloc((total?total:1)*2*sizeof(*entries)),fast_count=0,pike_count=0;
        bool valid=entries!=NULL;
        for(unsigned fast=2;valid&&fast-->0;) {
            size_t n=0,*list=entries+(fast?0:fast_count);
            for(size_t i=0;i<one->atom_count;++i) {
                const yx_chain_atom *atom=&one->atoms[i];
                if(((one->frames[atom->frame].frame.flags&64u)!=0)!=(fast!=0))continue;
                if(atom->atom.has_forward)list[n++]=atom->atom.forward;
                if(atom->atom.has_backward)list[n++]=atom->atom.backward;
            }
            if(fast)fast_count=n;else pike_count=n;
            valid=yx_rx_archived_code_valid(one->code,one->code_length,list,n,fast!=0);
        }
        free(entries);
        (void)pike_count;
        if(!valid) {
#ifdef XXYARA_VERIFY_LOAD
            /* No official archive has such code: the verify runs prove it. */
            if(!getenv("XXYARA_VERIFY_LOAD_ALLOW_REJECTED_CODE")) {
                fprintf(stderr,"XXYARA_VERIFY_LOAD: archived regexp code rejected\n");
                abort();
            }
#endif
            return NULL;
        }
    }
    size_t size=sizeof(yx_archived_regexp)+total*sizeof(yx_archived_regexp_atom)+one->code_length;
    yx_archived_regexp *out=calloc(1,size);
    if(!out)return NULL;
    yx_archived_regexp_atom *atoms=(yx_archived_regexp_atom *)(out+1);
    out->size=size;out->code_length=one->code_length;out->sub_count=one->frame_count;
    for(size_t i=0;i<one->frame_count;++i)out->flags[i]=one->frames[i].frame.flags,out->atom_count[i]=counts[i];
    for(size_t i=0;i<one->atom_count;++i) {
        const yx_chain_atom *atom=&one->atoms[i];
        yx_archived_regexp_atom *to=&atoms[(atom->frame?counts[0]:0)+filled[atom->frame]++];
        memcpy(to->bytes,atom->atom.bytes,atom->atom.length);
        to->length=(uint8_t)atom->atom.length;to->exact=atom->atom.exact;
        to->has_fwd=atom->atom.has_forward;to->has_bck=atom->atom.has_backward;
        to->backtrack=atom->atom.backtrack;
        to->fwd=atom->atom.has_forward?(uint32_t)atom->atom.forward:0;
        to->bck=atom->atom.has_backward?(uint32_t)atom->atom.backward:0;
    }
    if(one->code_length)memcpy(atoms+total,one->code,one->code_length);
    return out;
}
/* Rule identity of a single-rule physical archive: namespace, name, tags,
 * metadata and the private flag. */
static yx_ser_result yx_physical_copy_rule_info(const yx_physical_archive *a,yx_ser_rule *decoded)
{
    decoded->namespace_name=yx_copy_string(a->names[a->namespace_id]);
    decoded->identifier=yx_copy_string(a->names[a->rule_name_id]);
    if(!decoded->namespace_name||!decoded->identifier)return YX_SER_NO_MEMORY;
    decoded->tags=calloc(a->tag_count?a->tag_count:1,sizeof(*decoded->tags));
    decoded->metadata=calloc(a->metadata_count?a->metadata_count:1,sizeof(*decoded->metadata));
    if(!decoded->tags||!decoded->metadata)return YX_SER_NO_MEMORY;
    decoded->tag_count=a->tag_count;decoded->metadata_count=a->metadata_count;
    for(size_t i=0;i<a->tag_count;++i)
        if(!(decoded->tags[i]=yx_copy_string(a->names[a->tags[i]])))return YX_SER_NO_MEMORY;
    for(size_t i=0;i<a->metadata_count;++i) {
        const yx_physical_meta *m=&a->metadata[i];YRX_METADATA *value=&decoded->metadata[i];
        if(!(value->identifier=yx_copy_string(a->names[m->key])))return YX_SER_NO_MEMORY;
        if(m->variant==0)value->value_type=YRX_BOOLEAN,value->value.boolean=m->boolean;
        else if(m->variant==1)value->value_type=YRX_I64,value->value.i64=m->integer;
        else if(m->variant==2)value->value_type=YRX_F64,value->value.f64=m->floating;
        else if(m->variant==3) {
            if(memchr(a->pool[m->literal].data,0,a->pool[m->literal].length)||
               !yx_valid_utf8(a->pool[m->literal].data,a->pool[m->literal].length))return YX_SER_UNSUPPORTED;
            value->value_type=YRX_STRING;value->value.string=(const char *)yx_copy_literal(&a->pool[m->literal],true);
            if(!value->value.string)return YX_SER_NO_MEMORY;
        } else {
            value->value_type=YRX_BYTES;value->value.bytes.data=yx_copy_literal(&a->pool[m->literal],false);
            value->value.bytes.length=a->pool[m->literal].length;
            if(!value->value.bytes.data)return YX_SER_NO_MEMORY;
        }
    }
    decoded->is_private=a->private_rule;
    return YX_SER_SUCCESS;
}
/* Direct part loads. The callers of the parts (yx_physical_reconstruct_direct,
 * yx_decode_physical_patterns) read only the declaration yx_physical_declaration
 * writes for a part's pattern and the pattern's archived literal prefilter.
 * For the shapes below the full load of a part (yx_physical_write, then
 * yrx_rules_deserialize: the decoder cascade and a compile of the decoded
 * rule) gives a TEXT pattern with the part's literal and modifiers and no
 * prefilter: the decoders that read these shapes leave none, and the decoders
 * before them in the cascade do not read them.
 * - xor: the archives yx_decode_xor_pattern reads, checked as it checks them
 *   (on the part itself: the write and its read give the part back);
 *   literals of up to four bytes are left to the full load
 *   (yx_decode_single_xor reads some of those).
 * - base64: yx_decode_base64_pattern's archives with one input that does not
 *   read as a wide literal (yx_decode_single_base64 reads the single-output
 *   ones to the same declaration).
 * - text: one literal frame whose atoms are those of the literal codec's
 *   encoder: the best four-byte window of the frame's literal, with its case
 *   variants for nocase.
 * Verify builds (-DXXYARA_VERIFY_LOAD) load each such part both ways and
 * abort on a difference. */
static bool yx_physical_part_rules(const uint8_t *bytes,size_t length,unsigned modifiers,unsigned xor_min,
    unsigned xor_max,const char *alphabet,const char *wide_alphabet,YRX_RULES **out)
{
    YRX_RULES *rules=calloc(1,sizeof(*rules));YRX_PATTERN *p;
    if(!rules)return false;
    if(!(rules->rules=calloc(1,sizeof(*rules->rules)))){free(rules);return false;}
    rules->rule_count=1;
    if(!(p=rules->rules[0].patterns=calloc(1,sizeof(*p)))){yrx_rules_destroy(rules);return false;}
    rules->rules[0].pattern_count=1;
    p->kind=YX_PATTERN_TEXT;p->modifiers=modifiers;p->length=length;
    p->xor_min=(uint8_t)xor_min;p->xor_max=(uint8_t)xor_max;
    p->identifier=yx_copy_string("$a");p->bytes=malloc(length?length:1);
    if(alphabet)p->base64_alphabet=yx_copy_string(alphabet);
    if(wide_alphabet)p->base64wide_alphabet=yx_copy_string(wide_alphabet);
    if(!p->identifier||!p->bytes||(alphabet&&!p->base64_alphabet)||(wide_alphabet&&!p->base64wide_alphabet)) {
        yrx_rules_destroy(rules);return false;
    }
    if(length)memcpy(p->bytes,bytes,length);
    *out=rules;return true;
}
static bool yx_physical_part_xor(const yx_physical_archive *a,YRX_RULES **out)
{
    uint8_t *literal=NULL;size_t literal_length=0,cursor=0;
    unsigned minimum=0,maximum=0,modifiers=YX_MOD_XOR;bool ok=false;
    if(a->logical!=1||a->physical!=1||a->kinds[0]!=0||a->frame_count<1||a->frame_count>2||a->code_length)return false;
    for(size_t i=0;i<a->frame_count;++i) {
        const yx_chain_frame *f=&a->frames[i].frame;
        if(f->variant!=7||(f->flags&~25u)||((f->flags&24u)!=0&&(f->flags&24u)!=24u)||f->literal_index>=a->pool_count)goto done;
        const yx_literal *pool=&a->pool[f->literal_index];
        size_t offset,width;
        if(pool->length<=4||!yx_best_text_atom(pool->data,pool->length,&offset,&width)||cursor==a->atom_count)goto done;
        unsigned first=a->atoms[cursor].atom.bytes[0]^pool->data[offset],last=first;
        size_t begin=cursor;
        while(cursor<a->atom_count&&a->atoms[cursor].frame==i) {
            const yx_archive_regexp_atom *atom=&a->atoms[cursor].atom;
            unsigned key=first+(unsigned)(cursor-begin);
            if(key>255||atom->length!=width||atom->backtrack!=offset||atom->exact||
               atom->has_forward||atom->has_backward)goto done;
            for(size_t j=0;j<width;++j)if(atom->bytes[j]!=(pool->data[offset+j]^(uint8_t)key))goto done;
            last=key;++cursor;
        }
        if(cursor==begin||(i&&(minimum!=first||maximum!=last)))goto done;
        minimum=first;maximum=last;
        bool wide=(f->flags&1u)!=0;
        if(i==0) {
            if(wide&&pool->length%2)goto done;
            literal_length=pool->length/(wide?2u:1u);
            if(!(literal=malloc(literal_length)))goto done;
            for(size_t j=0;j<literal_length;++j) {
                literal[j]=pool->data[j*(wide?2u:1u)];
                if(wide&&pool->data[j*2+1])goto done;
            }
            if(wide)modifiers|=YX_MOD_WIDE;
            if(f->flags&24u)modifiers|=YX_MOD_FULLWORD;
        } else {
            if(!(modifiers&YX_MOD_WIDE)||wide||pool->length!=literal_length||
               memcmp(pool->data,literal,literal_length)||
               (f->flags&24u)!=(a->frames[0].frame.flags&24u))goto done;
            modifiers|=YX_MOD_ASCII;
        }
    }
    if(cursor!=a->atom_count)goto done;
    ok=yx_physical_part_rules(literal,literal_length,modifiers,minimum,maximum,NULL,NULL,out);
done:
    free(literal);return ok;
}
static bool yx_physical_part_base64(const yx_physical_archive *a,YRX_RULES **out)
{
    size_t input=SIZE_MAX,alphabets[2]={SIZE_MAX,SIZE_MAX};unsigned outputs=0;
    char alphabet_text[2][65]={{0}};
    if(a->logical!=1||a->physical!=1||a->kinds[0]!=0||a->code_length||a->frame_count<3||a->frame_count>6||
       a->frame_count%3||a->atom_count!=a->frame_count)return false;
    for(size_t i=0;i<a->frame_count;i+=3) {
        const yx_physical_frame *first=&a->frames[i];
        unsigned variant=first->frame.variant;
        if(variant<8||variant>11)return false;
        unsigned output=(variant-8)%2;bool custom=variant>=10;
        if(first->frame.literal_index>=a->pool_count||(input!=SIZE_MAX&&first->frame.literal_index!=input)||
           (outputs&(1u<<output)))return false;
        input=first->frame.literal_index;
        size_t alphabet=custom?first->mask:SIZE_MAX;
        if(custom) {
            if(alphabet>=a->pool_count||a->pool[alphabet].length!=64)return false;
            /* Symbols both base64 decoders accept and write back. */
            bool seen[256]={false};
            for(size_t k=0;k<64;++k) {
                uint8_t symbol=a->pool[alphabet].data[k];
                if(symbol<32||symbol>126||symbol=='='||symbol=='"'||symbol=='\\'||seen[symbol])return false;
                seen[symbol]=true;
            }
            memcpy(alphabet_text[output],a->pool[alphabet].data,64);
        }
        outputs|=1u<<output;alphabets[output]=alphabet;
        uint8_t *phases[3]={0};size_t widths[3],offsets[3],atom_widths[3];
        const yx_literal *literal=&a->pool[input];
        if(!yx_archive_base64_phases(literal->data,literal->length,output!=0,
            custom?alphabet_text[output]:NULL,phases,widths,offsets,atom_widths))return false;
        bool valid=true;
        for(size_t phase=0;phase<3;++phase) {
            const yx_physical_frame *f=&a->frames[i+phase];const yx_chain_atom *b=&a->atoms[i+phase];
            if(f->frame.variant!=variant||f->frame.literal_index!=input||f->padding!=2-phase||
               (custom&&f->mask!=alphabet)||b->frame!=i+phase||b->atom.exact||b->atom.has_forward||
               b->atom.has_backward||b->atom.length!=atom_widths[phase]||b->atom.backtrack!=offsets[phase]||
               memcmp(b->atom.bytes,phases[phase]+offsets[phase],atom_widths[phase]))valid=false;
            free(phases[phase]);
        }
        if(!valid)return false;
    }
    const yx_literal *literal=&a->pool[input];
    /* yx_decode_single_base64 reads such a literal as a wide one. */
    bool wide_like=literal->length>=6&&!(literal->length&1);
    for(size_t k=1;wide_like&&k<literal->length;k+=2)wide_like=!literal->data[k];
    if(wide_like)return false;
    unsigned modifiers=((outputs&1u)?YX_MOD_BASE64:0)|((outputs&2u)?YX_MOD_BASE64WIDE:0);
    return yx_physical_part_rules(literal->data,literal->length,modifiers,0,0,
        alphabets[0]!=SIZE_MAX?alphabet_text[0]:NULL,alphabets[1]!=SIZE_MAX?alphabet_text[1]:NULL,out);
}
static bool yx_physical_part_text(const yx_physical_archive *a,YRX_RULES **out)
{
    uint8_t atoms[YX_NOCASE_MAX_ATOMS][4];const uint8_t *pointers[YX_NOCASE_MAX_ATOMS];
    size_t widths[YX_NOCASE_MAX_ATOMS],count=1,offset,width;
    if(a->logical!=1||a->physical!=1||a->kinds[0]!=YX_PATTERN_TEXT||a->frame_count!=1||a->code_length||!a->atom_count)return false;
    const yx_physical_frame *frame=&a->frames[0];const yx_chain_frame *f=&frame->frame;
    if(f->variant!=0||frame->anchored||(f->flags&~27u)||((f->flags&24u)&&(f->flags&24u)!=24u)||
       f->literal_index>=a->pool_count)return false;
    const yx_literal *pool=&a->pool[f->literal_index];
    bool wide=(f->flags&1u)!=0,nocase=(f->flags&2u)!=0;
    if(!pool->length||(wide&&pool->length%2))return false;
    for(size_t k=1;wide&&k<pool->length;k+=2)if(pool->data[k])return false;
    if(!yx_best_text_atom(pool->data,pool->length,&offset,&width))return false;
    if(nocase) {
        if(!yx_make_ascii_nocase_atoms(pool->data+offset,width,atoms,pointers,widths,&count))return false;
    } else memcpy(atoms[0],pool->data+offset,width);
    if(a->atom_count!=count)return false;
    for(size_t k=0;k<count;++k) {
        const yx_chain_atom *atom=&a->atoms[k];
        if(atom->frame||atom->atom.length!=width||atom->atom.backtrack!=offset||
           atom->atom.exact!=(width==pool->length)||atom->atom.has_forward||atom->atom.has_backward||
           memcmp(atom->atom.bytes,atoms[k],width))return false;
    }
    size_t length=pool->length/(wide?2u:1u);
    uint8_t *literal=malloc(length);
    if(!literal)return false;
    for(size_t k=0;k<length;++k)literal[k]=pool->data[k*(wide?2u:1u)];
    bool ok=yx_physical_part_rules(literal,length,(wide?YX_MOD_WIDE:0)|(nocase?YX_MOD_NOCASE:0)|
        ((f->flags&24u)?YX_MOD_FULLWORD:0),0,0,NULL,NULL,out);
    free(literal);return ok;
}
/* A part of a direct shape (above): *out holds its rules. */
static bool yx_physical_part_direct(const yx_physical_archive *one,YRX_RULES **out)
{
    *out=NULL;
    if(one->name_count!=3||one->tag_count||one->metadata_count||one->private_rule||one->pattern_private[0]||
       one->import_count||one->regexp_count||one->anchored_count||one->limits[0]!=1||one->bounded[0]||
       one->headers[0].kind||one->wasm!=yx_single_text_pattern_wasm)return false;
    return yx_physical_part_xor(one,out)||yx_physical_part_base64(one,out)||yx_physical_part_text(one,out);
}
#ifdef XXYARA_VERIFY_LOAD
/* Aborts unless the part's direct rules give the full load's declaration and
 * prefilter. */
static void yx_physical_part_verify(const YRX_RULES *direct,const YRX_RULES *full,yx_ser_result status)
{
    yx_writer x={0},y={0};
    bool same=status==YX_SER_SUCCESS&&full&&full->rule_count==1&&full->rules[0].pattern_count==1;
    if(same) {
        const YRX_PATTERN *p=&direct->rules[0].patterns[0],*q=&full->rules[0].patterns[0];
        const yx_archived_literal_prefilter *u=&p->archived_literal_prefilter,*v=&q->archived_literal_prefilter;
        same=yx_physical_declaration(&x,"$a",p)&&yx_physical_declaration(&y,"$a",q)&&x.used==y.used&&
            !memcmp(x.data,y.data,x.used)&&!u->atoms==!v->atoms&&u->count==v->count;
        for(size_t i=0;same&&u->atoms&&i<u->count;++i)
            same=u->atoms[i].length==v->atoms[i].length&&u->atoms[i].backtrack==v->atoms[i].backtrack&&
                u->atoms[i].exact==v->atoms[i].exact&&!memcmp(u->atoms[i].bytes,v->atoms[i].bytes,sizeof(u->atoms[i].bytes));
    }
    if(!same) {
        fprintf(stderr,"XXYARA_VERIFY_LOAD: direct part differs: status %d, direct `%.*s`, full `%.*s`\n",(int)status,
                (int)x.used,x.data?(const char *)x.data:"",(int)y.used,y.data?(const char *)y.data:"");
        abort();
    }
    free(x.data);free(y.data);
}
#endif
/* What the callers of the parts read of a loaded physical pattern: its
 * declaration after `<name> = ` (yx_physical_flagged_declaration), its
 * archived literal prefilter and its archived program. A part keeps only
 * these, so the loaded rules of a part are freed as soon as it loads. */
typedef struct yx_physical_part {
    char *declaration;
    yx_archived_literal_prefilter prefilter;
    yx_archived_regexp *regexp;
} yx_physical_part;
static void yx_physical_part_free(yx_physical_part *part)
{
    free(part->declaration);free(part->prefilter.atoms);free(part->regexp);
    memset(part,0,sizeof(*part));
}
/* Writes name and the part's declaration as yx_physical_flagged_declaration
 * writes the loaded pattern. */
static bool yx_physical_part_declaration(yx_writer *w,const char *name,const yx_physical_part *part)
{
    return part->declaration&&yx_tr_text(w,name)&&yx_tr_text(w," = ")&&yx_tr_text(w,part->declaration);
}
/* Loads every physical pattern of a through its own one-pattern archive
 * (names default, $a, r): out[p] holds what its callers read of the one
 * pattern loaded (a->physical entries), freed by yx_physical_destroy_parts. */
typedef struct yx_physical_parts_job {
    const yx_physical_archive *a;
    /* The frames and atoms of physical pattern p are frame_list/atom_list
     * [first[p], first[p + 1]); its code is [begins[p], ends[p]). */
    const size_t *frame_first,*atom_first,*frame_list,*atom_list,*logical_of,*begins,*ends;
    yx_physical_part *loaded;
    yx_ser_result *statuses;
} yx_physical_parts_job;
/* The position of frame id in ids[0, count), the frame ids of one pattern in
 * ascending order (yx_physical_load_parts lists them so), or SIZE_MAX: the
 * first position a search from the front finds, without making a pattern of
 * many frames quadratic. */
static size_t yx_physical_local_frame(const size_t *ids,size_t count,size_t id)
{
    size_t low=0,high=count;
    while(low<high) {
        size_t middle=low+(high-low)/2;
        if(ids[middle]<id)low=middle+1;else high=middle;
    }
    size_t found=low<count&&ids[low]==id?low:SIZE_MAX;
#ifdef XXYARA_VERIFY_LOAD
    {
        /* The search from the front must find the same position. */
        size_t expected=SIZE_MAX;
        for(size_t j=0;j<count;++j)if(ids[j]==id){expected=j;break;}
        if(expected!=found) {
            fprintf(stderr,"XXYARA_VERIFY_LOAD: frame %zu at %zu, expected %zu\n",id,found,expected);
            abort();
        }
    }
#endif
    return found;
}
/* The load of physical pattern p alone. It reads only a and the pattern's
 * own frames, atoms and code range, so the patterns load in any order. */
static yx_ser_result yx_physical_load_part(const yx_physical_parts_job *job,size_t p,YRX_RULES **out)
{
    const yx_physical_archive *a=job->a;
    yx_physical_archive *one=calloc(1,sizeof(*one));
    uint8_t *single=NULL;size_t single_length=0,cursor=job->begins[p],end=job->ends[p];
    size_t frames_here=job->frame_first[p+1]-job->frame_first[p],atoms_here=job->atom_first[p+1]-job->atom_first[p];
    const size_t *frame_ids_here=job->frame_list+job->frame_first[p],*atom_ids_here=job->atom_list+job->atom_first[p];
    yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!one)return YX_SER_NO_MEMORY;
    if(!yx_physical_names_reserve(one,3)||!yx_physical_patterns_reserve(one,1)||
       !yx_physical_frames_reserve(one,frames_here?frames_here:1)){status=YX_SER_NO_MEMORY;goto done;}
    one->name_count=3;one->logical=one->physical=1;one->name_ids[0]=1;one->limits[0]=1;
    one->names[0]=yx_copy_string("default");one->names[1]=yx_copy_string("$a");one->names[2]=yx_copy_string("r");
    if(!one->names[0]||!one->names[1]||!one->names[2]){status=YX_SER_NO_MEMORY;goto done;}
    size_t logical=job->logical_of[p]==SIZE_MAX?a->logical:job->logical_of[p];
    if(logical==a->logical)goto done;
    one->kinds[0]=a->kinds[logical];
    /* The k-th frame of this pattern becomes frame k of one. A reference to
     * a frame that is not copied before the referring one is invalid. */
    for(size_t k=0;k<frames_here;++k) {
        size_t i=frame_ids_here[k];
        yx_physical_frame f=a->frames[i];f.pattern=0;
        if((f.frame.variant<=3||f.frame.variant>=7)) {
            size_t pool=yx_physical_pool(one,a->pool[f.frame.literal_index]);
            if(pool==SIZE_MAX)goto done;
            f.frame.literal_index=pool;
        }
        if(f.frame.variant==1||f.frame.variant>=10) {
            size_t pool=yx_physical_pool(one,a->pool[f.mask]);
            if(pool==SIZE_MAX)goto done;
            f.mask=pool;
        }
        if(f.frame.variant==3||f.frame.variant==6) {
            f.frame.previous=yx_physical_local_frame(frame_ids_here,k,f.frame.previous);
            if(f.frame.previous==SIZE_MAX)goto done;
        }
        if(f.anchored)one->anchored[one->anchored_count++]=one->frame_count;
        one->frames[one->frame_count++]=f;
    }
    one->atoms=calloc(atoms_here?atoms_here:1,sizeof(*one->atoms));
    if(!one->atoms){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t k=0;k<atoms_here;++k) {
        yx_chain_atom atom=a->atoms[atom_ids_here[k]];
        atom.frame=yx_physical_local_frame(frame_ids_here,frames_here,atom.frame);
        if(atom.atom.has_forward)atom.atom.forward-=(uint32_t)cursor;
        if(atom.atom.has_backward)atom.atom.backward-=(uint32_t)cursor;
        one->atoms[one->atom_count++]=atom;
    }
    one->code=a->code+cursor;one->code_length=end-cursor;
    one->wasm=yx_single_text_pattern_wasm;one->wasm_length=sizeof(yx_single_text_pattern_wasm);
    if(one->anchored_count) {
        yx_chain_archive *literal=calloc(1,sizeof(*literal));
        if(!literal){status=YX_SER_NO_MEMORY;goto done;}
        if(!yx_chain_frames_reserve(literal,1)){free(literal);status=YX_SER_NO_MEMORY;goto done;}
        /* Room for every atom yx_literal_frame_atoms may add; it writes each
         * atom whole, so the block needs no zeroing (the pages it never
         * reaches stay untouched). */
        literal->atoms=malloc(YX_CHAIN_MAX_ATOMS*sizeof(*literal->atoms));
        if(!literal->atoms){yx_chain_storage_destroy(literal);free(literal);status=YX_SER_NO_MEMORY;goto done;}
        for(size_t i=0;i<one->frame_count;++i) {
            if(!one->frames[i].anchored)continue;
            literal->frames[0]=one->frames[i].frame;literal->atom_count=0;
            if(!yx_literal_frame_atoms(literal,0)||literal->atom_count>SIZE_MAX/sizeof(*one->atoms)-one->atom_count)
                {yx_chain_storage_destroy(literal);free(literal);goto done;}
            yx_chain_atom *atoms=realloc(one->atoms,(one->atom_count+literal->atom_count)*sizeof(*atoms));
            if(!atoms){yx_chain_storage_destroy(literal);free(literal);status=YX_SER_NO_MEMORY;goto done;}
            one->atoms=atoms;
            for(size_t j=0;j<literal->atom_count;++j) {
                yx_chain_atom atom=literal->atoms[j];atom.frame=i;one->atoms[one->atom_count++]=atom;
            }
            one->frames[i].anchored=false;one->frames[i].offset=0;
        }
        one->anchored_count=0;yx_chain_storage_destroy(literal);free(literal);
    }
    YRX_RULES *direct=NULL;bool truth;
    /* One pattern under a plain `$a` belongs to the earlier codecs, which
     * reach this one for a literal only; under a folded condition the part
     * (with the module of `$a`) is theirs to read. */
    bool inspect=a->logical!=1||yx_physical_folded(a,&truth);
    if(a->logical!=1&&yx_physical_part_direct(one,&direct)) {
#ifndef XXYARA_VERIFY_LOAD
        *out=direct;status=YX_SER_SUCCESS;goto done;
#endif
    }
    /* The part's archive is written and read back in one memo scope, as in
     * the outer load: the image built for it is found again by its reader. */
    yx_ser_ac_memo_begin();
    status=yx_physical_write(one,&single,&single_length);
    if(status==YX_SER_SUCCESS) {
        status=YX_SER_UNSUPPORTED;
        if(!inspect) {
            if(yx_physical_load_literal(one,out))status=YX_SER_SUCCESS;
        } else if(yx_physical_inspect_load(single,single_length,out)==YRX_SUCCESS||
                  yx_physical_load_literal(one,out))status=YX_SER_SUCCESS;
        if(status==YX_SER_SUCCESS&&(!*out||(*out)->rule_count!=1||(*out)->rules[0].pattern_count!=1))
            status=YX_SER_UNSUPPORTED;
    }
    yx_ser_ac_memo_end();
#ifdef XXYARA_VERIFY_LOAD
    if(direct){yx_physical_part_verify(direct,*out,status);yrx_rules_destroy(direct);}
#endif
done:
    if(status==YX_SER_SUCCESS&&*out&&(*out)->rule_count==1&&(*out)->rules[0].pattern_count==1) {
        YRX_PATTERN *pattern=&(*out)->rules[0].patterns[0];
        if((pattern->kind==YX_PATTERN_REGEX||pattern->kind==YX_PATTERN_HEX)&&!pattern->archived_regexp)
            pattern->archived_regexp=yx_physical_part_regexp(one);
    }
    yx_physical_destroy(one);free(one);free(single);
    return status;
}
static void yx_physical_load_part_task(size_t p,void *context)
{
    const yx_physical_parts_job *job=context;
    YRX_RULES *loaded=NULL;
    yx_ser_result status=yx_physical_load_part(job,p,&loaded);
    if(status==YX_SER_SUCCESS) {
        /* The declaration as yx_physical_flagged_declaration writes it, with
         * the frame flags of this pattern (its frames: frame_list). */
        const yx_physical_archive *a=job->a;yx_physical_part *part=&job->loaded[p];
        YRX_PATTERN copy=loaded->rules[0].patterns[0];uint16_t flags=0;yx_writer w={0};
        for(size_t k=job->frame_first[p];k<job->frame_first[p+1];++k) {
            const yx_physical_frame *f=&a->frames[job->frame_list[k]];
            if(f->frame.variant<8)flags|=f->frame.flags;
        }
        if((flags&24u)&&copy.kind!=YX_PATTERN_HEX)copy.modifiers|=YX_MOD_FULLWORD;
        if(!yx_physical_declaration(&w,"",&copy)||!yx_put_u8(&w,0)||w.used<4||
           !yx_physical_copy_prefilter(&part->prefilter,&loaded->rules[0].patterns[0].archived_literal_prefilter)||
           !yx_physical_copy_regexp(&part->regexp,loaded->rules[0].patterns[0].archived_regexp))status=YX_SER_NO_MEMORY;
        else if(!(part->declaration=malloc(w.used-3)))status=YX_SER_NO_MEMORY;
        else memcpy(part->declaration,w.data+3,w.used-3);
        free(w.data);
        if(status!=YX_SER_SUCCESS)yx_physical_part_free(part);
    }
    yrx_rules_destroy(loaded);
    job->statuses[p]=status;
}
/* Destroys count loaded parts. */
static void yx_physical_destroy_parts(yx_physical_part *parts,size_t count)
{
    if(parts)for(size_t p=0;p<count;++p)yx_physical_part_free(&parts[p]);
}
/* Physical patterns per thread below which the parts load on the calling
 * thread alone. */
enum { YX_PHYSICAL_PARTS_PER_THREAD = 8 };
static yx_ser_result yx_physical_load_parts(const yx_physical_archive *a,yx_physical_part **out)
{
    yx_physical_part *loaded=NULL;size_t loaded_count=0,cursor=0,limit=0;
    size_t *frame_first=NULL,*atom_first=NULL,*frame_list=NULL,*atom_list=NULL,*logical_of=NULL;
    size_t *begins=NULL,*ends=NULL;yx_ser_result *statuses=NULL;
    yx_ser_result status=YX_SER_UNSUPPORTED;
    *out=NULL;
    loaded_count=a->physical;loaded=calloc(loaded_count?loaded_count:1,sizeof(*loaded));
    if(!loaded){status=YX_SER_NO_MEMORY;goto done;}
    /* The frames, atoms and first logical pattern of every physical pattern,
     * found once; scanning the whole archive for each of them is quadratic. */
    frame_first=calloc(a->physical+1,sizeof(*frame_first));atom_first=calloc(a->physical+1,sizeof(*atom_first));
    frame_list=malloc((a->frame_count?a->frame_count:1)*sizeof(*frame_list));
    atom_list=malloc((a->atom_count?a->atom_count:1)*sizeof(*atom_list));
    logical_of=malloc((a->physical?a->physical:1)*sizeof(*logical_of));
    begins=malloc((a->physical?a->physical:1)*sizeof(*begins));ends=malloc((a->physical?a->physical:1)*sizeof(*ends));
    statuses=malloc((a->physical?a->physical:1)*sizeof(*statuses));
    if(!frame_first||!atom_first||!frame_list||!atom_list||!logical_of||!begins||!ends||!statuses){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<a->frame_count;++i)if(a->frames[i].pattern<a->physical)++frame_first[a->frames[i].pattern+1];
    for(size_t i=0;i<a->atom_count;++i) {
        if(a->atoms[i].frame>=a->frame_count)goto done;
        if(a->frames[a->atoms[i].frame].pattern<a->physical)++atom_first[a->frames[a->atoms[i].frame].pattern+1];
    }
    for(size_t i=0;i<a->physical;++i)frame_first[i+1]+=frame_first[i],atom_first[i+1]+=atom_first[i];
    {
        size_t *frame_fill=calloc(a->physical+1,sizeof(*frame_fill)),*atom_fill=calloc(a->physical+1,sizeof(*atom_fill));
        if(!frame_fill||!atom_fill){free(frame_fill);free(atom_fill);status=YX_SER_NO_MEMORY;goto done;}
        for(size_t i=0;i<a->frame_count;++i) {
            size_t q=a->frames[i].pattern;
            if(q<a->physical)frame_list[frame_first[q]+frame_fill[q]++]=i;
        }
        for(size_t i=0;i<a->atom_count;++i) {
            size_t q=a->frames[a->atoms[i].frame].pattern;
            if(q<a->physical)atom_list[atom_first[q]+atom_fill[q]++]=i;
        }
        free(frame_fill);free(atom_fill);
    }
    for(size_t i=0;i<a->physical;++i)logical_of[i]=SIZE_MAX;
    for(size_t i=a->logical;i-->0;)if(a->mapping[i]<a->physical)logical_of[a->mapping[i]]=i;
    /* Each pattern's code follows the previous pattern's. Loading the parts
     * one after the other stops at the first failure: a code range that
     * cannot be found ends the parts to load (limit), and the first failed
     * part in pattern order gives the result. */
    for(limit=0;limit<a->physical;++limit) {
        size_t end;
        if(!yx_physical_program_end(a,atom_list+atom_first[limit],atom_first[limit+1]-atom_first[limit],cursor,&end))break;
        begins[limit]=cursor;ends[limit]=end;cursor=end;
    }
    {
        yx_physical_parts_job job={a,frame_first,atom_first,frame_list,atom_list,logical_of,begins,ends,loaded,statuses};
        yx_parallel_run(limit,yx_parallel_threads(limit,YX_PHYSICAL_PARTS_PER_THREAD),yx_physical_load_part_task,&job);
    }
    for(size_t p=0;p<limit;++p)if(statuses[p]!=YX_SER_SUCCESS){status=statuses[p];goto done;}
    if(limit<a->physical||cursor!=a->code_length)goto done;
    *out=loaded;loaded=NULL;status=YX_SER_SUCCESS;
done:
    yx_physical_destroy_parts(loaded,loaded_count);
    free(loaded);free(begins);free(ends);free(statuses);
    free(frame_first);free(atom_first);free(frame_list);free(atom_list);free(logical_of);
    return status;
}
static yx_ser_result yx_decode_physical_patterns(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *rule_count)
{
    yx_physical_archive *a=calloc(1,sizeof(*a));
    yx_physical_part *loaded=NULL;size_t loaded_count=0;yx_ser_rule *decoded=NULL;
    uint8_t *canonical=NULL;size_t canonical_length=0;
    yx_writer declarations={0};yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!a){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_physical_read(data,length,a)||!a->logical||a->import_count||a->globals_length!=4||
       memcmp(a->globals,"\0\0\1\0",4))goto done;
    status=yx_physical_write(a,&canonical,&canonical_length);
    if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED;
    if(canonical_length!=a->archive_length||memcmp(canonical,data,canonical_length))goto done;
    decoded=calloc(1,sizeof(*decoded));
    if(!decoded){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_physical_condition(a,&decoded->runtime_integer_condition,&decoded->runtime_integer_import_profile))goto done;
    status=yx_physical_load_parts(a,&loaded);
    if(status!=YX_SER_SUCCESS)goto done;
    loaded_count=a->physical;status=YX_SER_UNSUPPORTED;
    decoded->runtime_literal_prefilters=calloc(a->logical,sizeof(*decoded->runtime_literal_prefilters));
    if(!decoded->runtime_literal_prefilters){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_literal_prefilter_count=a->logical;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_copy_prefilter(&decoded->runtime_literal_prefilters[i],
           &loaded[a->mapping[i]].prefilter)){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_regexp_programs=calloc(a->logical,sizeof(*decoded->runtime_regexp_programs));
    if(!decoded->runtime_regexp_programs){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_regexp_program_count=a->logical;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_copy_regexp(&decoded->runtime_regexp_programs[i],
           loaded[a->mapping[i]].regexp)){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_part_declaration(&declarations,a->names[a->name_ids[i]],&loaded[a->mapping[i]])||
           (a->pattern_private[i]&&!yx_tr_text(&declarations,"private ")))goto done;
    if(!yx_put_u8(&declarations,0)){status=YX_SER_NO_MEMORY;goto done;}
    decoded->namespace_name=yx_copy_string(a->names[a->namespace_id]);
    decoded->identifier=yx_copy_string(a->names[a->rule_name_id]);
    if(!decoded->namespace_name||!decoded->identifier){status=YX_SER_NO_MEMORY;goto done;}
    decoded->tags=calloc(a->tag_count?a->tag_count:1,sizeof(*decoded->tags));
    decoded->metadata=calloc(a->metadata_count?a->metadata_count:1,sizeof(*decoded->metadata));
    if(!decoded->tags||!decoded->metadata){status=YX_SER_NO_MEMORY;goto done;}
    decoded->tag_count=a->tag_count;decoded->metadata_count=a->metadata_count;
    for(size_t i=0;i<a->tag_count;++i)
        if(!(decoded->tags[i]=yx_copy_string(a->names[a->tags[i]]))){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<a->metadata_count;++i) {
        const yx_physical_meta *m=&a->metadata[i];YRX_METADATA *value=&decoded->metadata[i];
        if(!(value->identifier=yx_copy_string(a->names[m->key]))){status=YX_SER_NO_MEMORY;goto done;}
        if(m->variant==0)value->value_type=YRX_BOOLEAN,value->value.boolean=m->boolean;
        else if(m->variant==1)value->value_type=YRX_I64,value->value.i64=m->integer;
        else if(m->variant==2)value->value_type=YRX_F64,value->value.f64=m->floating;
        else if(m->variant==3) {
            if(memchr(a->pool[m->literal].data,0,a->pool[m->literal].length)||
               !yx_valid_utf8(a->pool[m->literal].data,a->pool[m->literal].length))goto done;
            value->value_type=YRX_STRING;value->value.string=(const char *)yx_copy_literal(&a->pool[m->literal],true);
            if(!value->value.string){status=YX_SER_NO_MEMORY;goto done;}
        } else {
            value->value_type=YRX_BYTES;value->value.bytes.data=yx_copy_literal(&a->pool[m->literal],false);
            value->value.bytes.length=a->pool[m->literal].length;
            if(!value->value.bytes.data){status=YX_SER_NO_MEMORY;goto done;}
        }
    }
    decoded->is_private=a->private_rule;decoded->runtime_pattern_declarations=(char *)declarations.data;
    declarations.data=NULL;decoded->preserve_serialized_prefix=true;decoded->truth=true;
    *rules=decoded;*rule_count=1;decoded=NULL;status=YX_SER_SUCCESS;
done:
    if(a){yx_physical_destroy(a);free(a);}
    yx_physical_destroy_parts(loaded,loaded_count);
    free(loaded);
    yx_ser_rules_destroy(decoded,decoded?1:0);free(canonical);free(declarations.data);return status;
}

/* Reconstruct verified pattern declarations without retaining the caller's
 * condition, module schema, metadata or ownership. The returned rules own
 * their source and patterns. A single logical pattern has one extra alias;
 * callers consume only the original a->logical entries. */
static int yx_physical_presence_union(yx_integer_expr *tree,const size_t *mapping,size_t count)
{
    if(count==1)return yx_integer_expr_node_new(tree,0xd1,-1,-1,(int64_t)mapping[0]);
    size_t middle=count/2;
    int left=yx_physical_presence_union(tree,mapping,middle);
    int right=yx_physical_presence_union(tree,mapping+middle,count-middle);
    return left<0||right<0?-1:yx_integer_expr_node_new(tree,0xa1,left,right,0);
}
/* Plain literal frames already contain the complete declaration. Avoid
 * compiling a synthetic OR over every pattern merely to recover these bytes,
 * which is disproportionately expensive for large one-pattern rule sets. */
static bool yx_physical_reconstruct_plain(const yx_physical_archive *a,YRX_RULES **loaded)
{
    size_t *frames=NULL;bool *covered=NULL;YRX_RULES *rules=NULL;bool ok=false;
    if(!a->logical||!a->physical||a->code_length||a->frame_count!=a->physical||
       a->physical>SIZE_MAX/sizeof(*frames))return false;
    frames=malloc(a->physical*sizeof(*frames));covered=calloc(a->physical,sizeof(*covered));
    if(!frames||!covered)goto done;
    for(size_t p=0;p<a->physical;++p)frames[p]=SIZE_MAX;
    for(size_t i=0;i<a->frame_count;++i) {
        const yx_physical_frame *f=&a->frames[i];
        if(f->pattern>=a->physical||frames[f->pattern]!=SIZE_MAX||f->anchored||
           f->frame.variant||f->frame.flags||!f->frame.literal_length)goto done;
        frames[f->pattern]=i;
    }
    for(size_t i=0;i<a->logical;++i)
        if(a->kinds[i]!=YX_PATTERN_TEXT||a->mapping[i]>=a->physical||
           frames[a->mapping[i]]==SIZE_MAX)goto done;
    for(size_t i=0;i<a->atom_count;++i) {
        if(a->atoms[i].frame>=a->frame_count)goto done;
        const yx_archive_regexp_atom *atom=&a->atoms[i].atom;
        const yx_chain_frame *f=&a->frames[a->atoms[i].frame].frame;
        if(atom->has_forward||atom->has_backward||!atom->length||atom->length>4||
           atom->backtrack>f->literal_length||atom->length>f->literal_length-atom->backtrack||
           (atom->exact&&(atom->backtrack||atom->length!=f->literal_length))||
           memcmp(atom->bytes,f->literal+atom->backtrack,atom->length))goto done;
        covered[a->frames[a->atoms[i].frame].pattern]=true;
    }
    for(size_t p=0;p<a->physical;++p)if(!covered[p])goto done;
    rules=calloc(1,sizeof(*rules));if(!rules)goto done;
    rules->rules=calloc(1,sizeof(*rules->rules));if(!rules->rules)goto done;
    rules->rule_count=1;
    rules->rules[0].patterns=calloc(a->logical,sizeof(*rules->rules[0].patterns));
    if(!rules->rules[0].patterns)goto done;
    for(size_t i=0;i<a->logical;++i) {
        YRX_PATTERN *pattern=&rules->rules[0].patterns[i];
        const yx_chain_frame *f=&a->frames[frames[a->mapping[i]]].frame;
        rules->rules[0].pattern_count=i+1;
        pattern->kind=YX_PATTERN_TEXT;pattern->length=f->literal_length;
        pattern->identifier=yx_copy_string("$a");pattern->bytes=malloc(f->literal_length);
        if(!pattern->identifier||!pattern->bytes)goto done;
        memcpy(pattern->bytes,f->literal,f->literal_length);
    }
    *loaded=rules;rules=NULL;ok=true;
done:
    yrx_rules_destroy(rules);free(frames);free(covered);return ok;
}

/* A combined archive (below) with this many patterns or more is read only
 * by yx_decode_physical_patterns: the fixed-shape readers before it in the
 * cascade hold at most ten patterns, the multi-rule readers need two rules
 * and the v12 restorers a v12 module. Its load is then exactly that
 * decoder's per-pattern loads and the rule it compiles from their
 * declarations, so it is done here directly, without writing, validating,
 * dispatching and decoding the combined archive and its union condition. */
enum { YX_PHYSICAL_DIRECT_MINIMUM = 32 };
/* The combined rule of many patterns is compiled in chunks of whole
 * declarations on several threads, each chunk as a rule of the same form.
 * A pattern is compiled from its own declaration; the rule adds its
 * `any of them` condition, whose code does not grow with the patterns, its
 * pattern count (at most 100,000, E035) and the source size limit, both
 * checked first. So when every chunk compiles, the whole rule compiles to the
 * chunks' patterns, at source offsets moved by their chunk's start; otherwise
 * the whole rule is compiled. Callers read the patterns only. Verify builds
 * (-DXXYARA_VERIFY_LOAD) compile the whole rule as well and compare them. */
enum {
    YX_COMBINED_CHUNK_PATTERNS = 128, YX_COMBINED_MINIMUM_PATTERNS = 256, YX_COMBINED_MAXIMUM_PATTERNS = 100000,
    /* The compile takes a few milliseconds: helpers start early. */
    YX_COMBINED_SERIAL_NS = 250000, YX_COMBINED_THREAD_NS = 1000000
};
static const char yx_combined_head[]="rule combined { strings: ",yx_combined_tail[]=" condition: any of them }";
typedef struct yx_combined_job {
    const char *source;
    /* Declaration i is source[starts[i], starts[i + 1]). */
    const size_t *starts;
    size_t count;
    YRX_RULES **rules;
    YRX_RESULT *results;
} yx_combined_job;
static void yx_combined_chunk_task(size_t index,void *context)
{
    yx_combined_job *job=context;
    size_t first=index*YX_COMBINED_CHUNK_PATTERNS;
    size_t last=job->count-first>YX_COMBINED_CHUNK_PATTERNS?first+YX_COMBINED_CHUNK_PATTERNS:job->count;
    size_t head=sizeof(yx_combined_head)-1,body=job->starts[last]-job->starts[first];
    char *text=malloc(head+body+sizeof(yx_combined_tail));
    job->results[index]=YRX_INVALID_ARGUMENT;
    if(!text)return;
    memcpy(text,yx_combined_head,head);memcpy(text+head,job->source+job->starts[first],body);
    memcpy(text+head+body,yx_combined_tail,sizeof(yx_combined_tail));
    job->results[index]=yx_compile_quiet(text,&job->rules[index]);
    free(text);
}
/* source: yx_combined_head, the count declarations and yx_combined_tail. */
static YRX_RESULT yx_physical_compile_combined(const char *source,size_t length,const size_t *starts,size_t count,
                                               YRX_RULES **out)
{
    size_t chunks=(count+YX_COMBINED_CHUNK_PATTERNS-1)/YX_COMBINED_CHUNK_PATTERNS;
    unsigned threads=yx_parallel_threads(count,YX_COMBINED_CHUNK_PATTERNS);
    YRX_RULES **parts=NULL;YRX_RESULT *results=NULL;bool joined=false;
    *out=NULL;
    /* More patterns than one rule may hold (E035): the archive's rules held
     * them, and the reconstruction compiles them in chunks only, on one
     * thread if need be; a chunk that does not compile fails the whole. */
    bool chunked_only=count>YX_COMBINED_MAXIMUM_PATTERNS;
    if(chunked_only&&threads<1)threads=1;
    if(!chunked_only&&(count<YX_COMBINED_MINIMUM_PATTERNS||threads<2||
       length>=yx_get_source_size_limit()))return yx_compile_quiet(source,out);
    parts=calloc(chunks,sizeof(*parts));results=calloc(chunks,sizeof(*results));
    if(parts&&results) {
        yx_combined_job job={source,starts,count,parts,results};
        yx_parallel_run_ex(chunks,threads,YX_COMBINED_SERIAL_NS,YX_COMBINED_THREAD_NS,yx_combined_chunk_task,&job);
        joined=true;
        for(size_t k=0;k<chunks;++k) {
            size_t first=k*YX_COMBINED_CHUNK_PATTERNS;
            size_t last=count-first>YX_COMBINED_CHUNK_PATTERNS?first+YX_COMBINED_CHUNK_PATTERNS:count;
            if(results[k]!=YRX_SUCCESS||!parts[k]||parts[k]->rule_count!=1||parts[k]->rules[0].pattern_count!=last-first)
                joined=false;
        }
        YRX_PATTERN *patterns=joined&&count<=SIZE_MAX/sizeof(*patterns)?
            realloc(parts[0]->rules[0].patterns,count*sizeof(*patterns)):NULL;
        if(!patterns)joined=false;
        else {
            YRX_RULE *rule=&parts[0]->rules[0];
            rule->patterns=patterns;
            for(size_t k=1;k<chunks;++k) {
                YRX_RULE *part=&parts[k]->rules[0];
                size_t moved=starts[k*YX_COMBINED_CHUNK_PATTERNS]-(sizeof(yx_combined_head)-1);
                for(size_t i=0;i<part->pattern_count;++i) {
                    YRX_PATTERN *pattern=&part->patterns[i];
                    pattern->declaration_start+=moved;pattern->declaration_end+=moved;
                    pattern->literal_start+=moved;pattern->literal_end+=moved;pattern->pattern_end+=moved;
                    patterns[rule->pattern_count++]=*pattern;
                }
                /* Its patterns moved: the part frees none of them. */
                part->pattern_count=0;
            }
            *out=parts[0];parts[0]=NULL;
        }
    }
    if(parts)for(size_t k=0;k<chunks;++k)yrx_rules_destroy(parts[k]);
    free(parts);free(results);
    if(!joined)return chunked_only?YRX_SYNTAX_ERROR:yx_compile_quiet(source,out);
#ifdef XXYARA_VERIFY_LOAD
    if(!chunked_only) {
        YRX_RULES *whole=NULL;
        bool same=yx_compile_quiet(source,&whole)==YRX_SUCCESS&&whole&&whole->rule_count==1&&
            whole->rules[0].pattern_count==count;
        for(size_t i=0;same&&i<count;++i)same=yx_verify_pattern(&(*out)->rules[0].patterns[i],&whole->rules[0].patterns[i]);
        if(!same) {
            fprintf(stderr,"XXYARA_VERIFY_LOAD: combined rule of %zu patterns differs from its chunks\n",count);
            abort();
        }
        yrx_rules_destroy(whole);
    }
#endif
    return YRX_SUCCESS;
}
/* The combined rule's condition only has to use every pattern: callers read
 * the declarations and the literal prefilters, which depend on neither. */
static bool yx_physical_reconstruct_direct(const yx_physical_archive *a,YRX_RULES **loaded)
{
    yx_physical_part *parts=NULL;YRX_RULES *rules=NULL;yx_writer source={0};bool ok=false;
    size_t *starts=malloc((a->logical+1)*sizeof(*starts));
    *loaded=NULL;
    if(!starts||yx_physical_load_parts(a,&parts)!=YX_SER_SUCCESS)goto done;
    if(!yx_tr_text(&source,yx_combined_head))goto done;
    for(size_t i=0;i<a->logical;++i) {
        starts[i]=source.used;
        if(a->mapping[i]>=a->physical||
           !yx_physical_part_declaration(&source,a->names[a->name_ids[i]],&parts[a->mapping[i]])||
           (a->pattern_private[i]&&!yx_tr_text(&source,"private ")))goto done;
    }
    starts[a->logical]=source.used;
    if(!yx_tr_text(&source,yx_combined_tail)||!yx_put_u8(&source,0))goto done;
    if(yx_physical_compile_combined((const char *)source.data,source.used-1,starts,a->logical,&rules)!=YRX_SUCCESS||
       !rules||rules->rule_count!=1||rules->rules[0].pattern_count!=a->logical)goto done;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_copy_prefilter(&rules->rules[0].patterns[i].archived_literal_prefilter,
                                       &parts[a->mapping[i]].prefilter))goto done;
    for(size_t i=0;i<a->logical;++i) {
        free(rules->rules[0].patterns[i].archived_regexp);
        if(!yx_physical_copy_regexp(&rules->rules[0].patterns[i].archived_regexp,
                                    parts[a->mapping[i]].regexp))goto done;
    }
    *loaded=rules;rules=NULL;ok=true;
done:
    yx_physical_destroy_parts(parts,a->physical);
    free(parts);free(source.data);free(starts);yrx_rules_destroy(rules);return ok;
}
static bool yx_physical_reconstruct_patterns(const yx_physical_archive *original,YRX_RULES **loaded)
{
    if(yx_physical_reconstruct_plain(original,loaded))return true;
    yx_physical_archive *a=calloc(1,sizeof(*a));yx_integer_expr *tree=calloc(1,sizeof(*tree));
    yx_pattern_expression_context c={0};uint8_t *wasm=NULL,*archive=NULL;
    size_t wasm_length=0,archive_length=0;bool ok=false;
    *loaded=NULL;
    if(!a||!tree||!original->logical)goto done;
    size_t reserve_count=original->logical<2?2:original->logical;
    if(reserve_count>SIZE_MAX/2||!yx_integer_expr_reserve(tree,reserve_count*2)||
       !yx_physical_patterns_reserve(a,reserve_count)||!yx_pattern_expression_reserve(&c,reserve_count))goto done;
    a->physical=original->physical;a->pool=original->pool;a->pool_count=original->pool_count;
    a->frames=original->frames;a->frame_count=original->frame_count;
    a->anchored=original->anchored;a->anchored_count=original->anchored_count;
    a->atoms=original->atoms;a->atom_count=original->atom_count;a->code=original->code;a->code_length=original->code_length;
    memcpy(a->mapping,original->mapping,original->logical*sizeof(*a->mapping));
    memcpy(a->kinds,original->kinds,original->logical*sizeof(*a->kinds));
    if(yx_physical_ident(a,"default")!=0)goto done;
    size_t count=original->logical<2?2:original->logical;
    a->logical=count;
    for(size_t i=0;i<count;++i) {
        char name[32];snprintf(name,sizeof(name),"$pattern%zu",i);
        a->name_ids[i]=yx_physical_ident(a,name);if(a->name_ids[i]==SIZE_MAX)goto done;
        if(i>=original->logical)a->mapping[i]=original->mapping[0],a->kinds[i]=original->kinds[0];
        a->pattern_private[i]=false;yx_pattern_names(&c)[i]=a->names[a->name_ids[i]];yx_pattern_mapping(&c)[i]=a->mapping[i];
    }
    a->rule_name_id=yx_physical_ident(a,"combined");if(a->rule_name_id==SIZE_MAX)goto done;
    if(count>=YX_PHYSICAL_DIRECT_MINIMUM) {
        ok=yx_physical_reconstruct_direct(a,loaded);
        goto done;
    }
    c.pattern_count=count;yx_pattern_expression_setup(tree,&c);
    int root=yx_physical_presence_union(tree,a->mapping,count);
    if(root<0)goto done;
    if(!yx_pattern_expression_wasm(tree,root,&c,0,&wasm,&wasm_length))goto done;
    a->wasm=wasm;a->wasm_length=wasm_length;
    for(size_t i=0;i<a->physical;++i)a->limits[i]=1;
    if(yx_physical_write(a,&archive,&archive_length)!=YX_SER_SUCCESS||
       yx_physical_inspect_load(archive,archive_length,loaded)!=YRX_SUCCESS||
       (*loaded)->rule_count!=1||(*loaded)->rules[0].pattern_count!=count)goto done;
    ok=true;
done:
    if(!ok){yrx_rules_destroy(*loaded);*loaded=NULL;}
    /* Frames, atom storage, code and literal bytes are borrowed from original. */
    if(a){a->pool=NULL;a->frames=NULL;a->anchored=NULL;a->atoms=NULL;yx_physical_destroy(a);}
    yx_pattern_expression_destroy(&c);free(a);yx_integer_expr_free(tree);free(wasm);free(archive);return ok;
}
#endif
