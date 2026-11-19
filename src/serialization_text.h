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

/* Plain text archive envelope with distinct logical declarations and
 * deduplicated physical patterns. The caller supplies compiled condition
 * code and match limits for the deduplicated PatternIds. */

/* `apart` (or NULL): declarations anchor_patterns never reached, which are
 * neither anchored nor NonAnchorable and so another Pattern than an equal
 * declaration it reached (PatternId identity, compiler/mod.rs). */
static size_t yx_text_pattern_mapping(const YRX_RULE *rule,size_t map[5],size_t unique[5],const bool *apart)
{
    size_t count=0;
    for(size_t i=0;i<rule->pattern_count;++i) {
        size_t j=0;
        for(;j<count;++j) {
            const YRX_PATTERN *a=&rule->patterns[i],*b=&rule->patterns[unique[j]];
            if(a->length==b->length&&!memcmp(a->bytes,b->bytes,a->length)&&
               (!apart||apart[i]==apart[unique[j]]))break;
        }
        if(j==count)unique[count++]=i;
        map[i]=j;
    }
    return count;
}

static yx_ser_result yx_text_envelope_encode(const YRX_RULE *rule,
    const uint8_t *wasm,size_t wasm_length,const uint64_t limits[5],
    bool anchored,uint64_t offset,const bool *apart,uint8_t **data,size_t *length)
{
    static const uint8_t magic[]={ 'Y','A','R','A','-','X',0,0,12,0,0,0 };
    static const uint8_t globals[]={0,0,1,0};
    const char **pool=NULL;size_t count=0,capacity=0,ns=0,ident=0;
    yx_literal *literals=NULL;size_t literal_count=0,literal_capacity=0;
    size_t names[5],literal_ids[5],mapping[5],unique[5],offsets[5],widths[5];
    size_t *tags=NULL,*keys=NULL,*values=NULL;
    const uint8_t *atoms[5];
    uint8_t *ac=NULL;size_t ac_length=0;yx_writer w={0};
    yx_ser_result status=YX_SER_NO_MEMORY;
    if(!rule||!rule->patterns||!rule->pattern_count||rule->pattern_count>5||rule->is_global)return YX_SER_UNSUPPORTED;
    for(size_t i=0;i<rule->pattern_count;++i)
        if(rule->patterns[i].kind!=YX_PATTERN_TEXT||!rule->patterns[i].length||
           (rule->patterns[i].modifiers&~YX_MOD_ASCII))return YX_SER_UNSUPPORTED;
    size_t physical=yx_text_pattern_mapping(rule,mapping,unique,apart);
    if(anchored&&physical!=1)return YX_SER_UNSUPPORTED;
    tags=calloc(rule->tag_count?rule->tag_count:1,sizeof(*tags));
    keys=calloc(rule->metadata_count?rule->metadata_count:1,sizeof(*keys));
    values=calloc(rule->metadata_count?rule->metadata_count:1,sizeof(*values));
    if(!tags||!keys||!values||!yx_intern_ident("default",&pool,&count,&capacity,&ns)||
       !yx_intern_ident(rule->namespace_name?rule->namespace_name:"default",&pool,&count,&capacity,&ns))goto done;
    for(size_t i=0;i<rule->tag_count;++i)
        if(!yx_intern_ident(rule->tags[i],&pool,&count,&capacity,&tags[i]))goto done;
    for(size_t i=0;i<rule->metadata_count;++i) {
        const YRX_METADATA *m=&rule->metadata[i];
        if(!yx_intern_ident(m->identifier,&pool,&count,&capacity,&keys[i]))goto done;
        if(m->value_type==YRX_STRING||m->value_type==YRX_BYTES) {
            const uint8_t *bytes=m->value_type==YRX_STRING?(const uint8_t *)m->value.string:m->value.bytes.data;
            size_t size=m->value_type==YRX_STRING?strlen(m->value.string):m->value.bytes.length;
            if(!yx_intern_literal(bytes,size,&literals,&literal_count,&literal_capacity,&values[i]))goto done;
        }
    }
    for(size_t i=0;i<rule->pattern_count;++i) {
        const YRX_PATTERN *p=&rule->patterns[i];
        if(!yx_intern_ident(p->identifier,&pool,&count,&capacity,&names[i])||
           !yx_intern_literal(p->bytes,p->length,&literals,&literal_count,&literal_capacity,&literal_ids[i]))goto done;
    }
    if(!yx_intern_ident(rule->identifier,&pool,&count,&capacity,&ident))goto done;
    for(size_t i=0;i<physical;++i) {
        const YRX_PATTERN *p=&rule->patterns[unique[i]];
        if(!yx_best_text_atom(p->bytes,p->length,&offsets[i],&widths[i])){status=YX_SER_UNSUPPORTED;goto done;}
        atoms[i]=p->bytes+offsets[i];
    }
    if(anchored) {
        ac_length=YX_AC_LENGTH;ac=malloc(ac_length);if(!ac)goto done;yx_make_empty_ac(ac);
    } else if(physical==1) {
        ac_length=widths[0]==1?YX_PATTERN_AC_LENGTH:YX_PATTERN_AC_PREFILTER_LENGTH;
        ac=malloc(ac_length);if(!ac||!yx_make_short_pattern_ac(ac,atoms[0],widths[0]))goto done;
    } else if(!yx_ser_build_atom_ac(atoms,widths,physical,&ac,&ac_length))goto done;
    if(!yx_put_bytes(&w,magic,sizeof(magic))||!yx_put_uint(&w,count))goto done;
    for(size_t i=0;i<count;++i)if(!yx_put_string(&w,pool[i]))goto done;
    if(!yx_put_u8(&w,0)||!yx_put_u8(&w,0)||!yx_put_uint(&w,literal_count))goto done;
    for(size_t i=0;i<literal_count;++i)if(!yx_put_uint(&w,literals[i].length)||!yx_put_bytes(&w,literals[i].data,literals[i].length))goto done;
    if(!yx_put_uint(&w,wasm_length)||!yx_put_bytes(&w,wasm,wasm_length)||
       !yx_put_u8(&w,0)||!yx_put_uint(&w,0)||!yx_put_uint(&w,1)||
       !yx_put_uint(&w,ns?2:0)||!yx_put_uint(&w,ns)||!yx_put_uint(&w,ident)||!yx_put_uint(&w,rule->tag_count))goto done;
    for(size_t i=0;i<rule->tag_count;++i)if(!yx_put_uint(&w,tags[i]))goto done;
    if(!yx_put_uint(&w,rule->metadata_count))goto done;
    for(size_t i=0;i<rule->metadata_count;++i) {
        const YRX_METADATA *m=&rule->metadata[i];
        unsigned variant=m->value_type==YRX_BOOLEAN?0:m->value_type==YRX_I64?1:m->value_type==YRX_F64?2:m->value_type==YRX_STRING?3:4;
        if(!yx_put_uint(&w,keys[i])||!yx_put_uint(&w,variant))goto done;
        if(variant==0?!yx_put_u8(&w,m->value.boolean):variant==1?!yx_put_signed(&w,m->value.i64):
           variant==2?!yx_put_float(&w,m->value.f64):!yx_put_uint(&w,values[i]))goto done;
    }
    if(!yx_put_uint(&w,rule->pattern_count))goto done;
    for(size_t i=0;i<rule->pattern_count;++i)
        if(!yx_put_uint(&w,mapping[i]*2)||!yx_put_uint(&w,names[i])||!yx_put_u8(&w,0)||!yx_put_u8(&w,0))goto done;
    if(!yx_put_u8(&w,0)||!yx_put_u8(&w,0)||!yx_put_u8(&w,rule->is_private)||
       !yx_put_uint(&w,physical)||!yx_put_uint(&w,physical))goto done;
    for(size_t i=0;i<physical;++i)
        if(!yx_put_uint(&w,i*2)||!yx_put_u8(&w,0)||!yx_put_uint(&w,literal_ids[unique[i]])||
           !yx_put_u8(&w,anchored)||(anchored&&!yx_put_uint(&w,offset))||!yx_put_u8(&w,0))goto done;
    if(!yx_put_u8(&w,0)||!yx_put_uint(&w,0)||!yx_put_u8(&w,anchored)||
       (anchored&&!yx_put_u8(&w,0))||!yx_put_uint(&w,anchored?0:physical))goto done;
    for(size_t i=0;!anchored&&i<physical;++i)
        if(!yx_put_uint(&w,i)||!yx_put_uint(&w,widths[i])||!yx_put_bytes(&w,atoms[i],widths[i])||
           !yx_put_u8(&w,widths[i]==rule->patterns[unique[i]].length)||!yx_put_uint(&w,offsets[i])||
           !yx_put_u8(&w,0)||!yx_put_u8(&w,0))goto done;
    if(!yx_put_u8(&w,0)||!yx_put_uint(&w,sizeof(globals))||!yx_put_bytes(&w,globals,sizeof(globals))||
       !yx_put_uint(&w,ac_length)||!yx_put_bytes(&w,ac,ac_length)||
       !yx_put_u8(&w,0)||!yx_put_u8(&w,0)||!yx_put_uint(&w,physical))goto done;
    for(size_t i=0;i<physical;++i)
        if(!yx_put_u8(&w,limits[i]!=0)||(limits[i]&&!yx_put_uint(&w,limits[i])))goto done;
    if(!yx_put_u8(&w,0))goto done;
    *data=w.data;*length=w.used;w.data=NULL;status=YX_SER_SUCCESS;
done:
    free(w.data);free(ac);free(pool);free(literals);free(tags);free(keys);free(values);return status;
}

static char *yx_copy_string(const char *string);
static uint8_t *yx_copy_literal(const yx_literal *literal,bool nul_term);

static bool yx_text_envelope_read(const uint8_t *data,size_t length,
    yx_ser_rule **out,size_t *logical_count,size_t mapping[5],
    const uint8_t **wasm,size_t *wasm_length)
{
    static const uint8_t magic[]={'Y','A','R','A','-','X',0,0,12,0,0,0};
    yx_reader r={data,length,12,false,false};
    char **pool=NULL;yx_literal *literals=NULL;yx_ser_rule *entry=NULL;
    size_t count=0,literal_count=0,patterns=0,physical=0;
    uint64_t n,id,variant,physical_literal[5],limits[5]={0},offset=0;
    uint8_t flag;bool anchored=false,ok=false;
    uint8_t *canonical=NULL;size_t canonical_length=0;
    if(!data||length<12||memcmp(data,magic,12)||!yx_get_uint(&r,&n)||n>length-r.at)goto done;
    count=(size_t)n;pool=calloc(count?count:1,sizeof(*pool));if(!pool)goto done;
    for(size_t i=0;i<count;++i)if(!yx_get_string(&r,&pool[i]))goto done;
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_get_uint(&r,&n)||n>length-r.at)goto done;
    literal_count=(size_t)n;literals=calloc(literal_count?literal_count:1,sizeof(*literals));if(!literals)goto done;
    for(size_t i=0;i<literal_count;++i) {
        if(!yx_get_uint(&r,&n)||n>length-r.at)goto done;
        literals[i]=(yx_literal){data+r.at,(size_t)n};r.at+=(size_t)n;
    }
    if(!yx_get_uint(&r,&n)||n>length-r.at)goto done;
    *wasm=data+r.at;*wasm_length=(size_t)n;r.at+=(size_t)n;
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,1)||
       !yx_get_uint(&r,&variant)||!yx_get_uint(&r,&id)||id>=count)goto done;
    entry=calloc(1,sizeof(*entry));if(!entry)goto done;
    entry->namespace_name=yx_copy_string(pool[id]);
    if(!entry->namespace_name||!yx_get_uint(&r,&id)||id>=count)goto done;
    entry->identifier=yx_copy_string(pool[id]);
    if(!entry->identifier||!yx_get_uint(&r,&n)||n>length-r.at)goto done;
    entry->tag_count=(size_t)n;entry->tags=calloc(entry->tag_count?entry->tag_count:1,sizeof(*entry->tags));if(!entry->tags)goto done;
    for(size_t i=0;i<entry->tag_count;++i)
        if(!yx_get_uint(&r,&id)||id>=count||!(entry->tags[i]=yx_copy_string(pool[id])))goto done;
    if(!yx_get_uint(&r,&n)||n>(length-r.at)/2)goto done;
    entry->metadata_count=(size_t)n;entry->metadata=calloc(entry->metadata_count?entry->metadata_count:1,sizeof(*entry->metadata));if(!entry->metadata)goto done;
    for(size_t i=0;i<entry->metadata_count;++i) {
        YRX_METADATA *m=&entry->metadata[i];
        if(!yx_get_uint(&r,&id)||id>=count||!yx_get_uint(&r,&variant)||variant>4||
           !(m->identifier=yx_copy_string(pool[id])))goto done;
        if(variant==0) {
            if(!yx_get_u8(&r,&flag)||flag>1)goto done;
            m->value_type=YRX_BOOLEAN;m->value.boolean=flag!=0;
        } else if(variant==1) {
            m->value_type=YRX_I64;if(!yx_get_signed(&r,&m->value.i64))goto done;
        } else if(variant==2) {
            m->value_type=YRX_F64;if(!yx_get_float(&r,&m->value.f64))goto done;
        } else {
            if(!yx_get_uint(&r,&id)||id>=literal_count)goto done;
            if(variant==3) {
                if(memchr(literals[id].data,0,literals[id].length))goto done;
                m->value_type=YRX_STRING;m->value.string=(const char *)yx_copy_literal(&literals[id],true);
                if(!m->value.string)goto done;
            } else {
                m->value_type=YRX_BYTES;m->value.bytes.data=yx_copy_literal(&literals[id],false);m->value.bytes.length=literals[id].length;
                if(!m->value.bytes.data)goto done;
            }
        }
    }
    if(!yx_get_uint(&r,&n)||n<1||n>5)goto done;
    patterns=(size_t)n;
    char **names[5]={&entry->pattern_identifier,&entry->second_pattern_identifier,&entry->third_pattern_identifier,
        &entry->fourth_pattern_identifier,&entry->fifth_pattern_identifier};
    uint8_t **bytes[5]={&entry->pattern_bytes,&entry->second_pattern_bytes,&entry->third_pattern_bytes,
        &entry->fourth_pattern_bytes,&entry->fifth_pattern_bytes};
    size_t *widths[5]={&entry->pattern_length,&entry->second_pattern_length,&entry->third_pattern_length,
        &entry->fourth_pattern_length,&entry->fifth_pattern_length};
    for(size_t i=0;i<patterns;++i) {
        if(!yx_get_uint(&r,&n)||n%2||n/2>=5||!yx_get_uint(&r,&id)||id>=count||
           !yx_expect_uint(&r,0)||!yx_expect_uint(&r,0))goto done;
        mapping[i]=(size_t)n/2;*names[i]=yx_copy_string(pool[id]);if(!*names[i])goto done;
    }
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_get_u8(&r,&flag)||flag>1||
       !yx_get_uint(&r,&n)||n<1||n>patterns)goto done;
    entry->is_private=flag!=0;physical=(size_t)n;
    if(!yx_expect_uint(&r,physical))goto done;
    for(size_t i=0;i<physical;++i) {
        if(!yx_expect_uint(&r,i*2)||!yx_expect_uint(&r,0)||!yx_get_uint(&r,&id)||id>=literal_count||
           !literals[id].length||!yx_get_u8(&r,&flag)||flag>1)goto done;
        physical_literal[i]=id;
        if(flag) {
            if(physical!=1||!yx_get_uint(&r,&offset))goto done;
            anchored=true;
        }
        if(!yx_expect_uint(&r,0))goto done;
    }
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,anchored)||
       (anchored&&!yx_expect_uint(&r,0))||!yx_get_uint(&r,&n)||n!=(anchored?0:physical))goto done;
    for(size_t i=0;!anchored&&i<physical;++i) {
        if(!yx_expect_uint(&r,i)||!yx_get_uint(&r,&n)||n>4||n>length-r.at)goto done;
        r.at+=(size_t)n;
        if(!yx_get_u8(&r,&flag)||flag>1||!yx_get_uint(&r,&n)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0))goto done;
    }
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,4)||r.at>length-4||memcmp(data+r.at,"\0\0\1\0",4))goto done;
    r.at+=4;if(!yx_get_uint(&r,&n)||n>length-r.at)goto done;r.at+=(size_t)n;
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,physical))goto done;
    for(size_t i=0;i<physical;++i) {
        if(!yx_get_u8(&r,&flag)||flag>1)goto done;
        if(flag&&(!yx_get_uint(&r,&limits[i])||!limits[i]||limits[i]>UINT32_MAX))goto done;
    }
    if(!yx_expect_uint(&r,0)||r.at!=length)goto done;
    YRX_PATTERN temporary[5]={{0}};
    for(size_t i=0;i<patterns;++i) {
        if(mapping[i]>=physical)goto done;
        const yx_literal *literal=&literals[physical_literal[mapping[i]]];
        *bytes[i]=yx_copy_literal(literal,false);*widths[i]=literal->length;if(!*bytes[i])goto done;
        temporary[i].kind=YX_PATTERN_TEXT;temporary[i].identifier=*names[i];temporary[i].bytes=*bytes[i];temporary[i].length=*widths[i];
    }
    YRX_RULE rule={0};rule.identifier=entry->identifier;rule.namespace_name=entry->namespace_name;rule.is_private=entry->is_private;
    rule.tags=entry->tags;rule.tag_count=entry->tag_count;rule.metadata=entry->metadata;rule.metadata_count=entry->metadata_count;
    rule.patterns=temporary;rule.pattern_count=patterns;
    if(yx_text_envelope_encode(&rule,*wasm,*wasm_length,limits,anchored,offset,NULL,&canonical,&canonical_length)!=YX_SER_SUCCESS||
       canonical_length!=length||memcmp(canonical,data,length))goto done;
    entry->single_text_pattern=patterns==1;entry->two_text_patterns=patterns==2;entry->three_text_patterns=patterns==3;
    entry->four_text_patterns=patterns==4;entry->five_text_patterns=patterns==5;
    *out=entry;entry=NULL;*logical_count=patterns;ok=true;
done:
    for(size_t i=0;i<count;++i)free(pool?pool[i]:NULL);
    free(pool);free(literals);free(canonical);yx_ser_rules_destroy(entry,entry?1:0);return ok;
}
