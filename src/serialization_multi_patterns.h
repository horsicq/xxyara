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


#ifndef YX_SERIALIZATION_MULTI_PATTERNS_H
#define YX_SERIALIZATION_MULTI_PATTERNS_H
/* Rule-local identifiers and global physical pattern IDs occupy independent
 * spaces. Both typed leaf domains share the same numeric/Boolean AST. */
typedef struct yx_multi_pattern_context {
    yx_pattern_expression_context pattern;
    yx_rule_expression_context rule;
} yx_multi_pattern_context;
static int yx_multi_pattern_primary(yx_integer_expr *t,unsigned depth,void *user)
{
    yx_multi_pattern_context *c=user;yx_bool_parser saved=t->parser;
    int n=yx_pattern_expression_primary(t,depth,&c->pattern);
    if(n>=0)return n;
    t->parser=saved;return yx_rule_expression_primary(t,depth,&c->rule);
}
static bool yx_multi_pattern_emit(const yx_integer_expr *t,int n,yx_writer *w,unsigned depth,int slot,bool boolean,void *user)
{
    yx_multi_pattern_context *c=user;
    return YX_INTEGER_NODES(t)[n].op==0xd0?yx_rule_expression_emit(t,n,w,depth,slot,boolean,&c->rule):
        yx_pattern_expression_emit(t,n,w,depth,slot,boolean,&c->pattern);
}
static bool yx_multi_pattern_resources(yx_integer_expr *t,int n,void *user)
{
    yx_multi_pattern_context *c=user;
    return YX_INTEGER_NODES(t)[n].op==0xd0?yx_rule_expression_resources(t,n,&c->rule):
        yx_pattern_expression_resources(t,n,&c->pattern);
}
static bool yx_multi_pattern_print(const yx_integer_expr *t,int n,yx_writer *w,void *user)
{
    yx_multi_pattern_context *c=user;
    return YX_INTEGER_NODES(t)[n].op==0xd0?yx_rule_expression_print(t,n,w,&c->rule):
        yx_pattern_expression_print(t,n,w,&c->pattern);
}
static int yx_multi_pattern_decode(yx_reader *r,size_t end,yx_integer_expr *t,void *user)
{
    yx_multi_pattern_context *c=user;int n=yx_pattern_expression_decode(r,end,t,&c->pattern);
    return n>=0?n:yx_rule_expression_decode(r,end,t,&c->rule);
}
static void yx_multi_pattern_scope(void *user,bool enter)
{ yx_multi_pattern_context *c=user;yx_pattern_expression_boolean_scope(&c->pattern,enter); }
static void yx_multi_pattern_setup(yx_integer_expr *t,yx_multi_pattern_context *c)
{
    t->extension=c;t->parse_primary=yx_multi_pattern_primary;t->emit_primary=yx_multi_pattern_emit;
    t->resource_primary=yx_multi_pattern_resources;t->print_primary=yx_multi_pattern_print;
    t->decode_primary=yx_multi_pattern_decode;t->boolean_scope=yx_multi_pattern_scope;
    t->decode_boolean_block=yx_pattern_expression_decode_block;
}
static int yx_multi_pattern_join(yx_integer_expr *tree,const int *roots,size_t count)
{
    if(!count)return -1;
    if(count==1)return roots[0];
    size_t middle=count/2;
    int left=yx_multi_pattern_join(tree,roots,middle),right=yx_multi_pattern_join(tree,roots+middle,count-middle);
    return left<0||right<0?-1:yx_integer_expr_node_new(tree,0xa0,left,right,0);
}
static bool yx_multi_pattern_emit_rule(yx_integer_expr *tree,int root,
    yx_pattern_expression_context *context,const yx_pattern_expression_context *all,
    const yx_integer_expr *combined,size_t helper,size_t rule,yx_writer *body)
{
    memcpy(context->ids,all->ids,sizeof(context->ids));context->search_global=all->search_global;
    context->helper_id=helper;context->search_emitted=false;context->scope_depth=0;
    tree->match_id=combined->match_id;tree->filesize_id=combined->filesize_id;
    memcpy(tree->read_ids,combined->read_ids,sizeof(combined->read_ids));
    return yx_rule_expression_emit_one(tree,root,rule,combined->match_id,body);
}
/* The import/type union is independent of local rule-function ordering.
 * Trees are read one at a time (yx_tree_list), so they can be parked. */
static bool yx_multi_pattern_wasm_list(yx_tree_list *trees,int *roots,yx_multi_pattern_context *contexts,
    size_t count,size_t physical,uint8_t profile,uint8_t **data,size_t *length,uint64_t *limits)
{
    yx_integer_expr *combined=calloc(1,sizeof(*combined));yx_pattern_expression_context all={0};
    yx_writer wasm={0},functions={0},exports={0},code={0};
    size_t chunks=0,capacity=count+3,total=0;
    size_t *indices=calloc(capacity,sizeof(*indices));int *combined_roots=calloc(count,sizeof(*combined_roots));
    yx_writer *bodies=calloc(capacity,sizeof(*bodies));yx_wasm_function *order=calloc(capacity,sizeof(*order));
    uint64_t *sizes=calloc(count,sizeof(*sizes));
    size_t *firsts=calloc(count,sizeof(*firsts)),*lasts=calloc(count,sizeof(*lasts));
    bool ok=false;int combined_root=-1;
    if(!combined||!count||!indices||!bodies||!order||!combined_roots||!sizes||!firsts||!lasts)goto done;
    for(size_t p=0;p<physical;++p)limits[p]=1;
    /* Each rule's limits pass writes physical pattern slots. One scratch of
     * that size is lent to the rule being analyzed; afterwards only the
     * slots its pattern leaves name are merged and reset. */
    size_t scratch_count=physical>5?physical:5;
    const char **scratch_names=calloc(scratch_count,sizeof(*scratch_names));
    size_t *scratch_mapping=calloc(scratch_count,sizeof(*scratch_mapping));
    uint64_t *scratch_limits=malloc(scratch_count*sizeof(*scratch_limits));
    if(!scratch_names||!scratch_mapping||!scratch_limits)goto scratch_failed;
    for(size_t p=0;p<scratch_count;++p)scratch_limits[p]=1;
    for(size_t i=0;i<count;++i) {
        yx_integer_expr *t=yx_tree_list_open(trees,i);yx_pattern_expression_context *c=&contexts[i].pattern;
        if(!t)goto scratch_failed;
        const char **own_names=c->extra_names;size_t *own_mapping=c->extra_mapping,own_capacity=c->capacity;
        uint64_t *own_limits=c->extra_limits;
        size_t used_slots=yx_pattern_capacity(c)<scratch_count?yx_pattern_capacity(c):scratch_count;
        memcpy(scratch_names,yx_pattern_names(c),used_slots*sizeof(*scratch_names));
        memcpy(scratch_mapping,yx_pattern_mapping(c),used_slots*sizeof(*scratch_mapping));
        c->extra_names=scratch_names;c->extra_mapping=scratch_mapping;c->extra_limits=scratch_limits;c->capacity=scratch_count;
        memset(c->used,0,sizeof(c->used));c->presence=c->unlimited=c->search_emitted=false;c->match_limit=1;c->scope_depth=0;
        t->has_filesize=t->has_shift=t->has_divisor=t->has_memory=t->has_loop=false;t->read_mask=0;
        bool analyzed=yx_integer_expr_resources(t,roots[i],0,0);
        for(size_t n=0;n<t->count;++n) {
            const yx_integer_expr_node *leaf=&YX_INTEGER_NODES(t)[n];
            if(leaf->op<0xd1||leaf->op>0xd7||leaf->value<0||(uint64_t)leaf->value>=physical)continue;
            size_t p=(size_t)leaf->value;
            if(!scratch_limits[p])limits[p]=0;
            else if(limits[p]&&scratch_limits[p]>limits[p])limits[p]=scratch_limits[p];
        }
        for(size_t n=0;n<t->count;++n) {
            const yx_integer_expr_node *leaf=&YX_INTEGER_NODES(t)[n];
            if(leaf->op>=0xd1&&leaf->op<=0xd7&&leaf->value>=0&&(uint64_t)leaf->value<scratch_count)
                scratch_limits[leaf->value]=1;
        }
        for(size_t p=0;p<5&&p<scratch_count;++p)scratch_limits[p]=1;
        c->extra_names=own_names;c->extra_mapping=own_mapping;c->extra_limits=own_limits;c->capacity=own_capacity;
        if(!analyzed||t->count>=SIZE_MAX-combined->count||
           !yx_integer_expr_reserve(combined,combined->count+t->count+1))goto scratch_failed;
        combined->has_filesize|=t->has_filesize;combined->has_memory|=t->has_memory;combined->read_mask|=t->read_mask;
        all.presence|=c->presence;
        for(size_t s=0;s<YX_PATTERN_EXPRESSION_SYMBOL_COUNT;++s)all.used[s]|=c->used[s];
        size_t base=combined->count;
        for(size_t n=0;n<t->count;++n) {
            yx_integer_expr_node node=YX_INTEGER_NODES(t)[n];
            if(node.left>=0)node.left+=(int)base;
            if(node.right>=0)node.right+=(int)base;
            if(node.extra>=0)node.extra+=(int)base;
            YX_INTEGER_NODES(combined)[combined->count++]=node;
        }
        combined_roots[i]=roots[i]+(int)base;
        if(!yx_tree_list_close(trees,i))goto scratch_failed;
    }
    free(scratch_names);free(scratch_mapping);free(scratch_limits);
    if(false) {
scratch_failed:
        free(scratch_names);free(scratch_mapping);free(scratch_limits);
        goto done;
    }
    if(count>SIZE_MAX-combined->count||!yx_integer_expr_reserve(combined,combined->count+count))goto done;
    combined_root=yx_multi_pattern_join(combined,combined_roots,count);
    if(combined_root<0||!all.used[1]||!yx_pattern_expression_header(combined,combined_root,&all,profile,&wasm))goto done;
    yx_reader header={wasm.data,wasm.used,8,false,false};
    for(unsigned i=0;i<2;++i) {
        uint8_t section;uint64_t width;
        if(!yx_get_u8(&header,&section)||section!=i+1||!yx_get_uleb(&header,&width)||width>header.length-header.at)goto done;
        header.at+=(size_t)width;
    }
    wasm.used=header.at;
    for(size_t i=0;i<count;++i) {
        yx_writer expression={0};yx_integer_expr *t=yx_tree_list_open(trees,i);
        bool measured=t&&yx_multi_pattern_emit_rule(t,roots[i],&contexts[i].pattern,
            &all,combined,combined->function_count,i,&expression)&&
            yx_rule_expression_rule_size(&expression,all.search_global,&sizes[i]);
        if(t&&!yx_tree_list_close(trees,i))measured=false;
        free(expression.data);if(!measured)goto done;
    }
    for(size_t first=0;first<count;) {
        size_t last=yx_rule_expression_chunk_end(sizes,first,count);if(last==first)goto done;
        firsts[chunks]=first;lasts[chunks++]=last;first=last;
    }
    total=chunks+2+all.presence;
    /* First emit with a placeholder helper index to determine function order;
     * instruction counts do not depend on index encoding widths. */
    for(unsigned pass=0;pass<2;++pass) {
        for(size_t chunk=0;chunk<chunks;++chunk) {
            yx_writer *body=&bodies[chunk];body->used=0;
            size_t first=firsts[chunk],last=lasts[chunk];
            bool locals=false,shift=false;
            for(size_t i=first;i<last;++i) {
                const yx_integer_expr *t=yx_tree_list_open(trees,i);
                if(!t)goto done;
                locals|=t->has_filesize||t->has_shift||t->has_divisor||t->has_loop;
                shift|=t->has_shift||t->has_loop;
                if(!yx_tree_list_close(trees,i))goto done;
            }
            if(!yx_put_u8(body,locals?1:0)||(locals&&(!yx_put_u8(body,shift?2:1)||!yx_put_u8(body,0x7e))))goto done;
            for(size_t i=first;i<last;++i) {
                yx_integer_expr *t=yx_tree_list_open(trees,i);
                bool emitted=t&&yx_multi_pattern_emit_rule(t,roots[i],&contexts[i].pattern,
                    &all,combined,pass?indices[chunks]:combined->function_count,i,body);
                if(t&&!yx_tree_list_close(trees,i))emitted=false;
                if(!emitted)goto done;
            }
            if(!yx_put_u8(body,0x41)||!yx_put_u8(body,0)||!yx_put_u8(body,0x0b)||
               !yx_rule_expression_instructions(body,&order[chunk].instructions))goto done;
            order[chunk].created=chunk;
        }
        size_t wrapper=chunks+all.presence,main=wrapper+1;
        if(all.presence)order[chunks]=(yx_wasm_function){chunks,15};
        order[wrapper]=(yx_wasm_function){wrapper,1+2*chunks};order[main]=(yx_wasm_function){main,2};
        qsort(order,total,sizeof(*order),yx_compare_wasm_functions);
        for(size_t i=0;i<total;++i)indices[order[i].created]=combined->function_count+i;
    }
    size_t wrapper=chunks+all.presence,main=wrapper+1;
    static const uint8_t helper[]={1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    if(all.presence&&!yx_put_bytes(&bodies[chunks],helper,sizeof(helper)))goto done;
    if(!yx_put_u8(&bodies[wrapper],0)||!yx_put_u8(&bodies[wrapper],2)||!yx_put_u8(&bodies[wrapper],0x40))goto done;
    for(size_t i=0;i<chunks;++i)if(!yx_put_u8(&bodies[wrapper],0x10)||!yx_put_uleb(&bodies[wrapper],indices[i])||
        !yx_put_u8(&bodies[wrapper],0x0d)||!yx_put_u8(&bodies[wrapper],0))goto done;
    if(!yx_put_u8(&bodies[wrapper],0x0b)||!yx_put_u8(&bodies[wrapper],0x0b)||
       !yx_put_u8(&bodies[main],0)||!yx_put_u8(&bodies[main],0x10)||!yx_put_uleb(&bodies[main],indices[wrapper])||
       !yx_put_u8(&bodies[main],0x41)||!yx_put_u8(&bodies[main],0)||!yx_put_u8(&bodies[main],0x0b)||
       !yx_put_uleb(&functions,total)||!yx_put_uleb(&code,total)||!yx_put_u8(&exports,1)||
       !yx_put_u8(&exports,4)||!yx_put_bytes(&exports,"main",4)||!yx_put_u8(&exports,0)||!yx_put_uleb(&exports,indices[main]))goto done;
    for(size_t i=0;i<total;++i) {
        size_t created=order[i].created;
        if(!yx_put_u8(&functions,created==wrapper?0:all.presence&&created==chunks?all.helper_type:1)||
           !yx_put_uleb(&code,bodies[created].used)||!yx_put_bytes(&code,bodies[created].data,bodies[created].used))goto done;
    }
    if(!yx_append_wasm_section(&wasm,3,&functions)||!yx_append_wasm_section(&wasm,7,&exports)||
       !yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:
    if(bodies)for(size_t i=0;i<capacity;++i)free(bodies[i].data);
    free(bodies);free(order);free(indices);free(combined_roots);free(sizes);free(firsts);free(lasts);
    yx_integer_expr_free(combined);free(wasm.data);free(functions.data);free(exports.data);free(code.data);return ok;
}
static bool yx_multi_pattern_wasm(yx_integer_expr *trees,int *roots,yx_multi_pattern_context *contexts,
    size_t count,size_t physical,uint8_t profile,uint8_t **data,size_t *length,uint64_t *limits)
{
    yx_tree_list list={trees,NULL};
    return yx_multi_pattern_wasm_list(&list,roots,contexts,count,physical,profile,data,length,limits);
}
static void yx_multi_pattern_bounds_merge(yx_pattern_filesize_bounds *a,const yx_pattern_filesize_bounds *b)
{
    if(b->lower_kind!=2&&(a->lower_kind==2||b->lower>a->lower||(b->lower==a->lower&&b->lower_kind==1)))
        a->lower=b->lower,a->lower_kind=b->lower_kind;
    if(b->upper_kind!=2&&(a->upper_kind==2||b->upper<a->upper||(b->upper==a->upper&&b->upper_kind==1)))
        a->upper=b->upper,a->upper_kind=b->upper_kind;
}
static void yx_multi_pattern_bounds_visit(const yx_integer_expr *t,int index,const yx_pattern_filesize_bounds *previous,
    yx_pattern_filesize_bounds *bounds,unsigned depth)
{
    if(index<0||depth>256)return;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(t)[index];
    if(n->op==0xd0){yx_multi_pattern_bounds_merge(bounds,&previous[n->value]);return;}
    if(n->op==0xa0||n->op==0xd8) {
        yx_multi_pattern_bounds_visit(t,n->left,previous,bounds,depth+1);
        if(n->right!=n->left)yx_multi_pattern_bounds_visit(t,n->right,previous,bounds,depth+1);
    } else yx_pattern_filesize_visit(t,index,bounds,depth);
}
/* Read rule metadata once to locate its pattern list and again after the
 * identifier/literal pools are available to create owned API values. */
static bool yx_multi_pattern_metadata_read(yx_reader *r,const yx_physical_archive *a,yx_ser_rule *out,size_t *namespace_id,size_t *rule_id)
{
    uint64_t n,kind;uint8_t flag;
    if(!yx_get_uint(r,&kind)||(kind&1u)||!yx_get_uint(r,&n)||n>=r->length)return false;
    *namespace_id=(size_t)n;
    if(!yx_get_uint(r,&n)||n>=r->length)return false;
    *rule_id=(size_t)n;
    if(out) {
        out->namespace_index=(size_t)(kind/2);
        if(*namespace_id>=a->name_count||*rule_id>=a->name_count||!yx_valid_rule_name(a->names[*rule_id]))return false;
        out->namespace_name=yx_copy_string(a->names[*namespace_id]);out->identifier=yx_copy_string(a->names[*rule_id]);
        if(!out->namespace_name||!out->identifier)return false;
    }
    if(!yx_get_uint(r,&n)||n>r->length-r->at)return false;
    size_t tags=(size_t)n;
    if(out&&tags) {
        out->tags=calloc(tags,sizeof(*out->tags));if(!out->tags)return false;out->tag_count=tags;
    }
    for(size_t i=0;i<tags;++i) {
        if(!yx_get_uint(r,&n)||n>=r->length)return false;
        if(out&&(n>=a->name_count||!yx_valid_rule_name(a->names[n])||!(out->tags[i]=yx_copy_string(a->names[n]))))return false;
    }
    if(!yx_get_uint(r,&n)||n>r->length-r->at)return false;
    size_t count=(size_t)n;
    if(out&&count) {
        out->metadata=calloc(count,sizeof(*out->metadata));if(!out->metadata)return false;out->metadata_count=count;
    }
    for(size_t i=0;i<count;++i) {
        if(!yx_get_uint(r,&n)||n>=r->length||!yx_get_uint(r,&kind)||kind>4)return false;
        YRX_METADATA *v=out?&out->metadata[i]:NULL;
        if(v&&(n>=a->name_count||!yx_valid_rule_name(a->names[n])||!(v->identifier=yx_copy_string(a->names[n]))))return false;
        if(kind==0) {if(!yx_get_u8(r,&flag)||flag>1)return false;if(v)v->value_type=YRX_BOOLEAN,v->value.boolean=flag!=0;}
        else if(kind==1) {int64_t x;if(!yx_get_signed(r,&x))return false;if(v)v->value_type=YRX_I64,v->value.i64=x;}
        else if(kind==2) {double x;if(!yx_get_float(r,&x))return false;if(v)v->value_type=YRX_F64,v->value.f64=x;}
        else {
            if(!yx_get_uint(r,&n)||n>=r->length)return false;
            if(v) {
                if(n>=a->pool_count)return false;
                const yx_literal *literal=&a->pool[n];
                if(kind==3) {
                    if(memchr(literal->data,0,literal->length)||!yx_valid_utf8(literal->data,literal->length))return false;
                    v->value_type=YRX_STRING;v->value.string=(const char *)yx_copy_literal(literal,true);if(!v->value.string)return false;
                } else {
                    v->value_type=YRX_BYTES;v->value.bytes.length=literal->length;v->value.bytes.data=yx_copy_literal(literal,false);if(!v->value.bytes.data)return false;
                }
            }
        }
    }
    return true;
}
static yx_ser_result yx_encode_multi_patterns(const YRX_RULES *rules,uint8_t **data,size_t *length)
{
    if(!rules||rules->rule_count<2||rules->global_count)return YX_SER_UNSUPPORTED;
    size_t count=rules->rule_count,logical=0,total_patterns=0;
    for(size_t i=0;i<count;++i){if(rules->rules[i].pattern_count>SIZE_MAX-total_patterns)return YX_SER_UNSUPPORTED;total_patterns+=rules->rules[i].pattern_count;}
    yx_integer_expr *trees=calloc(count,sizeof(*trees));yx_multi_pattern_context *contexts=calloc(count,sizeof(*contexts));
    yx_physical_rules assembly={0};yx_physical_pattern_options *options=calloc(total_patterns?total_patterns:1,sizeof(*options));
    const YRX_PATTERN **patterns=calloc(total_patterns?total_patterns:1,sizeof(*patterns));
    uint64_t *limits=calloc(total_patterns?total_patterns:1,sizeof(*limits));
    yx_pattern_filesize_bounds *bounds=calloc(count,sizeof(*bounds));int *roots=calloc(count,sizeof(*roots));
    yx_physical_header *headers=calloc(count,sizeof(*headers));yx_writer *header_storage=calloc(count,sizeof(*header_storage));
    uint8_t *wasm=NULL;size_t wasm_length=0;yx_ser_result status=YX_SER_UNSUPPORTED;
    yx_module_pattern_schema schema={0};
    if(!trees||!contexts||!bounds||!roots||!headers||!header_storage||!options||!patterns||!limits){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i) {
        const YRX_RULE *r=&rules->rules[i];yx_pattern_expression_context *c=&contexts[i].pattern;
        if(r->is_global||!r->condition_text)goto done;
        contexts[i].rule=(yx_rule_expression_context){rules->rules,NULL,count,i,false};c->pattern_count=r->pattern_count;
        if(!yx_pattern_expression_reserve(c,r->pattern_count)){status=YX_SER_NO_MEMORY;goto done;}
        for(size_t j=0;j<yx_pattern_capacity(c);++j)yx_pattern_limits(c)[j]=1;
        for(size_t j=0;j<r->pattern_count;++j)yx_pattern_names(c)[j]=r->patterns[j].identifier,yx_pattern_mapping(c)[j]=j;
        yx_multi_pattern_setup(&trees[i],&contexts[i]);roots[i]=yx_integer_expr_condition(&trees[i],r->condition_text);
        if(roots[i]<0||!yx_integer_expr_resources(&trees[i],roots[i],0,0))goto done;
        bounds[i]=(yx_pattern_filesize_bounds){2,2,0,0};yx_multi_pattern_bounds_visit(&trees[i],roots[i],bounds,&bounds[i],0);
        for(size_t j=0;j<r->pattern_count;++j)patterns[j]=&r->patterns[j];
        if(!yx_header_integer(&trees[i],roots[i],patterns,r->pattern_count,headers,i,&header_storage[i],&headers[i]))goto done;
        for(size_t j=0;j<r->pattern_count;++j) {
            yx_physical_pattern_options *option=&options[logical++];
            *option=(yx_physical_pattern_options){.limit=yx_pattern_limits(c)[j],.bounds=r->patterns[j].kind==YX_PATTERN_TEXT?(yx_pattern_filesize_bounds){2,2,0,0}:bounds[i]};
            if(r->patterns[j].kind!=YX_PATTERN_TEXT)option->header=headers[i];
            bool used=false,anchored=true;
            for(size_t n=0;n<trees[i].count;++n) {
                const yx_integer_expr_node *node=&YX_INTEGER_NODES(&trees[i])[n];
                if(node->op<0xd1||node->op>0xd7||node->value!=(int64_t)j)continue;
                if(node->op!=0xd5||node->left<0||!YX_INTEGER_NODES(&trees[i])[node->left].constant||YX_INTEGER_NODES(&trees[i])[node->left].value<0)anchored=false;
                else if(used&&option->offset!=(uint64_t)YX_INTEGER_NODES(&trees[i])[node->left].value)anchored=false;
                else option->offset=(uint64_t)YX_INTEGER_NODES(&trees[i])[node->left].value;
                used=true;
            }
            option->anchored=used&&anchored;
        }
    }
    status=yx_physical_rules_build(rules,options,&assembly);if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED;logical=0;
    for(size_t i=0;i<count;++i) {
        for(size_t n=0;n<trees[i].count;++n)if(YX_INTEGER_NODES(&trees[i])[n].op>=0xd1&&YX_INTEGER_NODES(&trees[i])[n].op<=0xd7) {
            size_t local=(size_t)YX_INTEGER_NODES(&trees[i])[n].value;
            if(local>=rules->rules[i].pattern_count)goto done;
            YX_INTEGER_NODES(&trees[i])[n].value=(int64_t)assembly.archive->mapping[logical+local];
        }
        /* Pattern sets take global ids too; ranges are recomputed and a form
         * that would need upstream's loop is unsupported. */
        for(size_t n=0;n<trees[i].count;++n)if(YX_INTEGER_NODES(&trees[i])[n].op==0xda) {
            yx_integer_expr_node *node=&YX_INTEGER_NODES(&trees[i])[n];
            yx_pattern_of_set *set=&contexts[i].pattern.of_sets[node->value>>4],remapped={0};
            unsigned kind=(unsigned)(node->value&3);size_t ids_count=0;uint32_t ids[256];
            for(uint8_t r=0;r<set->count;++r)for(uint32_t id=set->start[r];id<=set->end[r];++id) {
                if(id>=rules->rules[i].pattern_count||ids_count==256)goto done;
                ids[ids_count++]=(uint32_t)assembly.archive->mapping[logical+id];
            }
            for(size_t a=1;a<ids_count;++a)
                for(size_t b=a;b&&ids[b-1]>ids[b];--b){uint32_t t=ids[b];ids[b]=ids[b-1];ids[b-1]=t;}
            for(size_t a=0;a<ids_count;++a) {
                if(a&&ids[a]==ids[a-1])goto done;
                if(a&&ids[a]==ids[a-1]+1){remapped.end[remapped.count-1]=ids[a];continue;}
                if(remapped.count==YX_PATTERN_OF_RANGES)goto done;
                remapped.start[remapped.count]=remapped.end[remapped.count]=ids[a];++remapped.count;
            }
            if(kind==3&&remapped.count!=1)goto done;
            *set=remapped;
            node->value=yx_pattern_of_value(set,(uint8_t)(node->value>>4),kind);
        }
        for(size_t j=0;j<rules->rules[i].pattern_count;++j)yx_pattern_mapping(&contexts[i].pattern)[j]=assembly.archive->mapping[logical+j];
        logical+=rules->rules[i].pattern_count;
    }
    if(!yx_multi_pattern_wasm(trees,roots,contexts,count,assembly.archive->physical,yx_integer_import_profile(),&wasm,&wasm_length,limits))goto done;
    if(rules->import_count) {
        /* Imports unused by the conditions add the modules' globals. */
        char *unique[32];size_t unique_count=0;YRX_RULES modules={0};
        for(size_t i=0;i<rules->import_count;++i) {
            size_t j=0;
            while(j<unique_count&&strcmp(unique[j],rules->imports[i]))++j;
            if(j<unique_count)continue;
            if(unique_count==32)goto done;
            unique[unique_count++]=rules->imports[i];
        }
        modules.imports=unique;modules.import_count=unique_count;
        if(!yx_module_pattern_schema_build(&schema,&modules,yx_integer_import_profile()))goto done;
        assembly.archive->globals=schema.dynamic.globals.data;
        assembly.archive->globals_length=schema.dynamic.globals.used;
    }
    status=yx_physical_rules_write(&assembly,wasm,wasm_length,data,length);
done:
    yx_module_pattern_schema_free(&schema);
    if(header_storage)for(size_t i=0;i<count;++i)free(header_storage[i].data);
    free(header_storage);free(headers);free(bounds);free(roots);
    if(contexts)for(size_t i=0;i<count;++i)yx_pattern_expression_destroy(&contexts[i].pattern);
    free(options);free(patterns);free(limits);if(trees)for(size_t i=0;i<count;++i)yx_integer_expr_destroy(&trees[i]);
    free(trees);free(contexts);free(wasm);yx_physical_rules_destroy(&assembly);return status;
}

/* Whether data is the canonical encoding of a with the rules' own metadata:
 * the result is that of the archive writer, YX_SER_UNSUPPORTED when the
 * bytes differ. It reads a, the metadata and data only. */
typedef struct yx_multi_canonical_check {
    const yx_physical_archive *a;
    const yx_writer *metadata;
    const uint8_t *data;
    size_t length,original_length;
    yx_ser_result status;
} yx_multi_canonical_check;
static void yx_multi_canonical_run(void *context)
{
    yx_multi_canonical_check *check=context;
    uint8_t *canonical=NULL,*whole=NULL;size_t canonical_length=0,whole_length=0;
    yx_ser_result status=yx_physical_write(check->a,&canonical,&canonical_length);
    if(status==YX_SER_SUCCESS)
        status=yx_multi_pattern_replace_metadata(canonical,canonical_length,check->metadata,&whole,&whole_length);
    if(status==YX_SER_SUCCESS&&(whole_length!=check->original_length||whole_length>check->length||
       memcmp(whole,check->data,whole_length)))status=YX_SER_UNSUPPORTED;
    free(canonical);free(whole);
    check->status=status;
}
/* Archives with this many atoms check their canonical encoding (dominated
 * by the automaton image) on another thread while the rest is decoded. */
enum { YX_MULTI_ASYNC_CANONICAL_ATOMS = 4096 };
/* The pattern set of a (yx_physical_reconstruct_patterns), read from a only,
 * on another thread while the conditions are decoded and re-emitted. Its
 * part loads already run on helper threads of their own, so the thread it
 * runs on does not matter; it starts only outside internal loads. */
typedef struct yx_multi_reconstruct {
    const yx_physical_archive *a;
    YRX_RULES *loaded;
    bool ok;
} yx_multi_reconstruct;
static void yx_multi_reconstruct_run(void *context)
{
    yx_multi_reconstruct *job=context;
    job->ok=yx_physical_reconstruct_patterns(job->a,&job->loaded);
}
static yx_ser_result yx_decode_multi_patterns(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *rule_count)
{
    yx_multi_canonical_check check={0};yx_async *canonical_task=NULL;
    yx_multi_reconstruct reconstruct={0};yx_async *reconstruct_task=NULL;
    size_t begin,end,count=0,logical=0,*firsts=NULL,*counts=NULL;
    size_t *ids=NULL,*namespaces=NULL,*metadata_starts=NULL,*names=NULL,*mapping=NULL;
    size_t *body_starts=NULL,*body_ends=NULL;
    uint8_t *kinds=NULL;bool *private_patterns=NULL,*private_rules=NULL;
    const YRX_PATTERN **patterns=NULL;uint64_t *limits=NULL;
    const char **print_names=NULL;
    yx_physical_archive *a=calloc(1,sizeof(*a));yx_ser_rule *decoded=NULL;YRX_RULES *loaded=NULL;
    yx_tree_store store={0};yx_tree_list trees={NULL,&store};yx_multi_pattern_context *contexts=NULL;
    int *roots=NULL;yx_pattern_expression_context imports={0};yx_integer_expr import_tree={0};
    yx_pattern_filesize_bounds *bounds=NULL;
    uint8_t *base=NULL,*canonical=NULL;size_t base_length=0,canonical_length=0;
    yx_writer metadata={0},fake_metadata={0},*header_storage=NULL;
    yx_physical_header *headers=NULL;yx_ser_result status=YX_SER_UNSUPPORTED;
    uint16_t *frame_flags=NULL;size_t *frame_first=NULL,*frame_list=NULL;
    if(!a){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_multi_pattern_metadata_span(data,length,&begin,&end))goto done;
    yx_reader r={data,length,begin,false,false};uint64_t n,width;uint8_t flag;
    if(!yx_get_uint(&r,&n)||n<2||n>(end-r.at)/9)goto done;
    count=(size_t)n;
    size_t pattern_bound=(end-r.at)/4;
    names=calloc(pattern_bound?pattern_bound:1,sizeof(*names));mapping=calloc(pattern_bound?pattern_bound:1,sizeof(*mapping));
    kinds=calloc(pattern_bound?pattern_bound:1,sizeof(*kinds));private_patterns=calloc(pattern_bound?pattern_bound:1,sizeof(*private_patterns));
    firsts=calloc(count,sizeof(*firsts));counts=calloc(count,sizeof(*counts));
    ids=calloc(count,sizeof(*ids));namespaces=calloc(count,sizeof(*namespaces));metadata_starts=calloc(count,sizeof(*metadata_starts));
    private_rules=calloc(count,sizeof(*private_rules));roots=calloc(count,sizeof(*roots));bounds=calloc(count,sizeof(*bounds));
    headers=calloc(count,sizeof(*headers));header_storage=calloc(count,sizeof(*header_storage));
    if(!firsts||!counts||!ids||!namespaces||!metadata_starts||!private_rules||!roots||!bounds||!headers||!header_storage||!names||!mapping||!kinds||!private_patterns) {
        status=YX_SER_NO_MEMORY;goto done;
    }
    for(size_t i=0;i<count;++i) {
        metadata_starts[i]=r.at;
        if(!yx_multi_pattern_metadata_read(&r,NULL,NULL,&namespaces[i],&ids[i])||(i&&namespaces[i]!=namespaces[0])||
           !yx_get_uint(&r,&width)||width>pattern_bound-logical)goto done;
        firsts[i]=logical;counts[i]=(size_t)width;size_t private_count=0;
        for(size_t j=0;j<counts[i];++j) {
            if(!yx_get_uint(&r,&n)||(n&1u)||n/2>=pattern_bound)goto done;
            mapping[logical]=(size_t)(n/2);
            if(!yx_get_uint(&r,&n)||n>=r.length)goto done;
            names[logical]=(size_t)n;
            if(!yx_get_uint(&r,&n)||n>2||!yx_get_u8(&r,&flag)||flag>1)goto done;
            kinds[logical]=(uint8_t)n;private_patterns[logical]=flag!=0;private_count+=flag;++logical;
        }
        if(!yx_expect_uint(&r,private_count)||!yx_expect_uint(&r,0)||!yx_get_u8(&r,&flag)||flag>1)goto done;
        private_rules[i]=flag!=0;
    }
    if(!logical||r.at!=end)goto done;
    if(!yx_put_bytes(&metadata,data+begin,end-begin)||!yx_put_uint(&fake_metadata,1)||
       !yx_put_uint(&fake_metadata,0)||!yx_put_uint(&fake_metadata,0)||!yx_put_uint(&fake_metadata,ids[0])||
       !yx_put_uint(&fake_metadata,0)||!yx_put_uint(&fake_metadata,0)||!yx_put_uint(&fake_metadata,logical))goto done;
    size_t private_count=0;
    for(size_t j=0;j<logical;++j) {
        if(!yx_put_uint(&fake_metadata,mapping[j]*2)||!yx_put_uint(&fake_metadata,names[j])||
           !yx_put_uint(&fake_metadata,kinds[j])||!yx_put_u8(&fake_metadata,private_patterns[j]))goto done;
        private_count+=private_patterns[j];
    }
    if(!yx_put_uint(&fake_metadata,private_count)||!yx_put_uint(&fake_metadata,0)||!yx_put_u8(&fake_metadata,0))goto done;
    status=yx_multi_pattern_replace_metadata(data,length,&fake_metadata,&base,&base_length);
    if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED;
    if(!yx_physical_read(base,base_length,a))goto done;
    for(size_t i=0;i<count;++i)if(ids[i]>=a->name_count||!yx_valid_rule_name(a->names[ids[i]]))goto done;
    /* The canonical check comes first: when it fails, its result is the
     * decoder's. On another thread it runs while the steps below read the
     * same archive (none of them changes a); each exit waits for it and
     * then takes its result first, as when it ran before them. */
    check=(yx_multi_canonical_check){a,&metadata,data,length,a->archive_length+(end-begin)-fake_metadata.used,YX_SER_UNSUPPORTED};
    if(a->atom_count>=YX_MULTI_ASYNC_CANONICAL_ATOMS)canonical_task=yx_async_start(yx_multi_canonical_run,&check);
    else yx_multi_canonical_run(&check);
    if(!canonical_task&&check.status!=YX_SER_SUCCESS){status=check.status;goto done;}
    status=YX_SER_UNSUPPORTED;
    /* Started here, its result is taken where it was computed before. */
    bool reconstructing=!yx_physical_inspect_nesting;
    if(reconstructing){reconstruct.a=a;reconstruct_task=yx_async_start(yx_multi_reconstruct_run,&reconstruct);}
    contexts=calloc(count,sizeof(*contexts));decoded=calloc(count,sizeof(*decoded));
    if(!yx_tree_store_init(&store,count)||!contexts||!decoded){status=YX_SER_NO_MEMORY;goto done;}
    limits=calloc(a->physical?a->physical:1,sizeof(*limits));patterns=calloc(a->physical?a->physical:1,sizeof(*patterns));
    if(!limits||!patterns){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i)roots[i]=-1;
    yx_reader wr={a->wasm,a->wasm_length,0,false,false};uint64_t functions;
    if(!yx_pattern_expression_read_header(&wr,&import_tree,&imports)||!yx_rule_expression_byte(&wr,10)||
       !yx_get_uleb(&wr,&width)||width!=wr.length-wr.at||!yx_get_uleb(&wr,&functions)||
       functions<(count+9)/10+2+imports.presence||functions>count+2+imports.presence)goto done;
    if(functions>SIZE_MAX/sizeof(*body_starts))goto done;
    body_starts=calloc((size_t)functions,sizeof(*body_starts));body_ends=calloc((size_t)functions,sizeof(*body_ends));
    if(!body_starts||!body_ends){status=YX_SER_NO_MEMORY;goto done;}
    static const uint8_t helper[]={1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    bool found_helper=!imports.presence;
    for(size_t f=0;f<(size_t)functions;++f) {
        if(!yx_get_uleb(&wr,&width)||width>wr.length-wr.at)goto done;
        body_starts[f]=wr.at;body_ends[f]=wr.at+(size_t)width;
        if(width==sizeof(helper)&&!memcmp(wr.data+wr.at,helper,sizeof(helper))) {
            if(found_helper)goto done;
            imports.helper_id=import_tree.function_count+f;found_helper=true;
        }
        wr.at=body_ends[f];
    }
    if(!found_helper||wr.at!=wr.length)goto done;
    for(size_t f=0;f<(size_t)functions;++f) {
        wr.at=body_starts[f];size_t body_end=body_ends[f];uint64_t locals;
        if(!yx_get_uleb(&wr,&locals))goto done;
        if(locals>1)goto done;
        if(locals&&(!yx_get_uleb(&wr,&n)||n<1||n>2||!yx_get_u8(&wr,&flag)))goto done;
        if(locals&&flag!=0x7e)continue;
        while(wr.at+1<body_end&&wr.data[wr.at]==2&&wr.data[wr.at+1]==0x7f) {
            yx_integer_expr *t=yx_tree_store_copy(&store,&import_tree);yx_multi_pattern_context c={0};
            if(!t){status=YX_SER_NO_MEMORY;goto done;}
            c.pattern=imports;c.rule.current=c.rule.rule_count=count;
            /* The operand decoder needs an id bound, without owning an
             * array for every physical pattern in every rule. */
            c.pattern.capacity=a->physical;
            yx_multi_pattern_setup(t,&c);wr.at+=2;
            int root=yx_integer_wasm_block(&wr,body_end,t,0,-1);int64_t id;
            static const uint8_t suffix[]={0x45,4,0x40,5,0x41};
            bool valid=root>=0&&yx_integer_wasm_bytes(&wr,body_end,suffix,sizeof(suffix))&&
                yx_get_sleb_i64(&wr,&id)&&id>=0&&(uint64_t)id<count&&roots[id]<0&&
                yx_rule_expression_byte(&wr,0x10)&&yx_get_uleb(&wr,&n)&&n==import_tree.match_id&&yx_rule_expression_byte(&wr,0x0b);
            if(valid)for(size_t j=0;j<t->count;++j) {
                if(YX_INTEGER_NODES(t)[j].op==0xd0&&YX_INTEGER_NODES(t)[j].value>=id)valid=false;
                if(YX_INTEGER_NODES(t)[j].op>=0xd1&&YX_INTEGER_NODES(t)[j].op<=0xd7) {
                    bool owned=false;
                    for(size_t k=0;k<counts[id];++k)owned|=YX_INTEGER_NODES(t)[j].value==(int64_t)mapping[firsts[id]+k];
                    if(!owned)valid=false;
                }
            }
            if(!valid){yx_pattern_expression_destroy(&c.pattern);yx_integer_expr_destroy(t);goto done;}
            c.pattern.capacity=0;
            contexts[id]=c;roots[id]=root;yx_multi_pattern_setup(t,&contexts[id]);
            if(!yx_tree_store_park(&store,(size_t)id)){yx_integer_expr_destroy(t);status=YX_SER_NO_MEMORY;goto done;}
        }
    }
    for(size_t i=0;i<count;++i)if(roots[i]<0)goto done;
    uint8_t profile;
    for(profile=0;profile<4;++profile) {
        free(canonical);canonical=NULL;
        if(yx_multi_pattern_wasm_list(&trees,roots,contexts,count,a->physical,profile,&canonical,&canonical_length,limits)&&
           canonical_length==a->wasm_length&&!memcmp(canonical,a->wasm,a->wasm_length))break;
    }
    if(profile==4)goto done;
    if(reconstructing) {
        yx_async_wait(reconstruct_task);reconstruct_task=NULL;
        loaded=reconstruct.loaded;reconstruct.loaded=NULL;
        if(!reconstruct.ok)goto done;
    } else if(!yx_physical_reconstruct_patterns(a,&loaded))goto done;
    /* The bytecode and physical search restrictions must describe the same
     * condition. A canonical wire representation alone does not establish
     * that an arbitrary anchor, bound, or match limit is semantically valid. */
    for(size_t p=0;p<a->physical;++p)if(limits[p]!=a->limits[p])goto done;
    /* Each physical pattern's frames, found once (one scan of every frame
     * per logical pattern is quadratic). */
    frame_first=calloc(a->physical+1,sizeof(*frame_first));
    frame_list=malloc((a->frame_count?a->frame_count:1)*sizeof(*frame_list));
    if(!frame_first||!frame_list){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t n=0;n<a->frame_count;++n)if(a->frames[n].pattern<a->physical)++frame_first[a->frames[n].pattern+1];
    for(size_t p=0;p<a->physical;++p)frame_first[p+1]+=frame_first[p];
    {
        size_t *fill=malloc((a->physical?a->physical:1)*sizeof(*fill));
        if(!fill){status=YX_SER_NO_MEMORY;goto done;}
        if(a->physical)memcpy(fill,frame_first,a->physical*sizeof(*fill));
        for(size_t n=0;n<a->frame_count;++n)if(a->frames[n].pattern<a->physical)frame_list[fill[a->frames[n].pattern]++]=n;
        free(fill);
    }
    for(size_t i=0;i<count;++i) {
        yx_integer_expr *tree=yx_tree_list_open(&trees,i);
        if(!tree){status=YX_SER_NO_MEMORY;goto done;}
        bounds[i]=(yx_pattern_filesize_bounds){2,2,0,0};
        yx_multi_pattern_bounds_visit(tree,roots[i],bounds,&bounds[i],0);
        /* patterns holds only this rule's entries; the others stay NULL. */
        for(size_t j=0;j<counts[i];++j)patterns[mapping[firsts[i]+j]]=&loaded->rules[0].patterns[firsts[i]+j];
        if(!yx_header_integer(tree,roots[i],patterns,a->physical,headers,i,&header_storage[i],&headers[i]))goto done;
        /* A literal regexp with a group, such as /(abc)/, derives no header
         * upstream. When the archive has none, keep the bytes in a group. */
        for(size_t j=0;j<counts[i]&&headers[i].kind==2;++j) {
            size_t k=firsts[i]+j,p=mapping[k];
            YRX_PATTERN *pattern=&loaded->rules[0].patterns[k];
            if(kinds[k]==YX_PATTERN_TEXT||a->headers[p].kind!=0||!pattern->regexp||
               pattern->regexp[0]=='(')continue;
            size_t length=strlen(pattern->regexp);
            char *grouped=malloc(length+3);
            if(!grouped){status=YX_SER_NO_MEMORY;goto done;}
            grouped[0]='(';memcpy(grouped+1,pattern->regexp,length);
            grouped[length+1]=')';grouped[length+2]=0;
            free(pattern->regexp);pattern->regexp=grouped;
            header_storage[i].used=0;
            if(!yx_header_integer(tree,roots[i],patterns,a->physical,headers,i,&header_storage[i],&headers[i]))goto done;
        }
        for(size_t j=0;j<counts[i];++j) {
            size_t k=firsts[i]+j,p=mapping[k];
            yx_pattern_filesize_bounds expected=kinds[k]==YX_PATTERN_TEXT?
                (yx_pattern_filesize_bounds){2,2,0,0}:bounds[i];
            yx_physical_header header=kinds[k]==YX_PATTERN_TEXT?(yx_physical_header){0}:headers[i];
            if(!yx_physical_header_equal(&header,&a->headers[p]))goto done;
            bool bounded=expected.lower_kind!=2||expected.upper_kind!=2;
            if(a->bounded[p]!=bounded||(bounded&&!yx_physical_rule_bounds_equal(&expected,&a->bounds[p])))goto done;
            bool used=false,anchored=true;uint64_t offset=0;
            for(size_t n=0;n<tree->count;++n) {
                const yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[n];
                if(node->op<0xd1||node->op>0xd7||node->value!=(int64_t)p)continue;
                if(node->op!=0xd5||node->left<0||!YX_INTEGER_NODES(tree)[node->left].constant||YX_INTEGER_NODES(tree)[node->left].value<0)anchored=false;
                else if(used&&offset!=(uint64_t)YX_INTEGER_NODES(tree)[node->left].value)anchored=false;
                else offset=(uint64_t)YX_INTEGER_NODES(tree)[node->left].value;
                used=true;
            }
            for(size_t q=frame_first[p];q<frame_first[p+1];++q) {
                const yx_physical_frame *frame=&a->frames[frame_list[q]];
                bool required=used&&anchored&&frame->frame.variant==0;
                if(frame->anchored!=required||(required&&frame->offset!=offset))goto done;
            }
        }
        for(size_t j=0;j<counts[i];++j)patterns[mapping[firsts[i]+j]]=NULL;
        if(!yx_tree_list_close(&trees,i)){status=YX_SER_NO_MEMORY;goto done;}
    }
    for(size_t i=0;i<count;++i) {
        r.at=metadata_starts[i];
        if(!yx_multi_pattern_metadata_read(&r,a,&decoded[i],&namespaces[i],&ids[i]))goto done;
        decoded[i].is_private=private_rules[i];decoded[i].truth=true;decoded[i].preserve_serialized_prefix=true;
        if(!decoded[i].namespace_name||!decoded[i].identifier){status=YX_SER_NO_MEMORY;goto done;}
    }
    size_t print_capacity=a->physical>5?a->physical:5;
    print_names=calloc(print_capacity,sizeof(*print_names));
    if(!print_names){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i) {
        yx_writer text={0};yx_multi_pattern_context *c=&contexts[i];c->rule.decoded=decoded;c->rule.current=i;
        yx_integer_expr *tree=yx_tree_list_open(&trees,i);
        if(!tree){status=YX_SER_NO_MEMORY;goto done;}
        /* print_names is all NULL here: each rule clears the entries it sets. */
        c->pattern.extra_names=print_names;c->pattern.capacity=print_capacity;
        c->pattern.pattern_count=a->physical;
        for(size_t j=0;j<counts[i];++j) {
            size_t k=firsts[i]+j;if(!yx_pattern_names(&c->pattern)[mapping[k]])yx_pattern_names(&c->pattern)[mapping[k]]=a->names[names[k]];
        }
        bool valid=yx_put_u8(&text,'(')&&yx_integer_expr_print(tree,roots[i],&text,0,false,0)&&yx_put_u8(&text,')');
        for(size_t j=0;valid&&j<counts[i];++j) {
            size_t k=firsts[i]+j;
            bool used=false;
            for(size_t n=0;n<tree->count&&!used;++n) {
                const yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[n];
                if(node->op>=0xd1&&node->op<=0xd7&&node->value==(int64_t)mapping[k])used=true;
                if(node->op==0xda) {
                    const yx_pattern_of_set *set=&c->pattern.of_sets[node->value>>4];
                    for(uint8_t range=0;range<set->count;++range)
                        if(mapping[k]>=set->start[range]&&mapping[k]<=set->end[range])used=true;
                }
            }
            /* Constant folding can remove every operand for a declared
             * pattern. Retain a syntactic reference when recompiling the
             * recovered rule, just as for a duplicate logical identifier. */
            if(!used||strcmp(yx_pattern_names(&c->pattern)[mapping[k]],a->names[names[k]]))valid=yx_tr_text(&text," and (true or ")&&yx_tr_text(&text,a->names[names[k]])&&yx_put_u8(&text,')');
        }
        if(!valid||!yx_put_u8(&text,0)){free(text.data);goto done;}
        decoded[i].runtime_integer_condition=(char *)text.data;decoded[i].runtime_integer_import_profile=profile;
        for(size_t j=0;j<counts[i];++j)print_names[mapping[firsts[i]+j]]=NULL;
        c->pattern.extra_names=NULL;c->pattern.capacity=0;
        if(!yx_tree_list_close(&trees,i)){status=YX_SER_NO_MEMORY;goto done;}
    }
    frame_flags=yx_physical_frame_flags(a);
    if(!frame_flags){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i)if(counts[i]) {
        yx_writer declarations={0};bool valid=true;
        decoded[i].runtime_literal_prefilters=calloc(counts[i],sizeof(*decoded[i].runtime_literal_prefilters));
        if(!decoded[i].runtime_literal_prefilters){status=YX_SER_NO_MEMORY;goto done;}
        decoded[i].runtime_literal_prefilter_count=counts[i];
        for(size_t j=0;j<counts[i];++j)
            if(!yx_physical_copy_prefilter(&decoded[i].runtime_literal_prefilters[j],
               &loaded->rules[0].patterns[firsts[i]+j].archived_literal_prefilter)){status=YX_SER_NO_MEMORY;goto done;}
        for(size_t j=0;valid&&j<counts[i];++j) {
            size_t k=firsts[i]+j;valid=yx_physical_flagged_declaration(&declarations,a->names[names[k]],&loaded->rules[0].patterns[k],a,frame_flags,mapping[k]);
            if(valid&&private_patterns[k])valid=yx_tr_text(&declarations,"private ");
        }
        if(!valid||!yx_put_u8(&declarations,0)){free(declarations.data);goto done;}
        decoded[i].runtime_pattern_declarations=(char *)declarations.data;
    }
    yx_async_wait(canonical_task);canonical_task=NULL;
    if(check.status!=YX_SER_SUCCESS){status=check.status;goto done;}
    *rules=decoded;*rule_count=count;decoded=NULL;status=YX_SER_SUCCESS;
done:
    /* The pattern set reads a: it ends before a is freed. */
    if(reconstruct_task)yx_async_wait(reconstruct_task);
    yrx_rules_destroy(reconstruct.loaded);
    if(canonical_task){yx_async_wait(canonical_task);if(check.status!=YX_SER_SUCCESS)status=check.status;}
    if(a){yx_physical_destroy(a);free(a);}yx_ser_rules_destroy(decoded,decoded?count:0);yrx_rules_destroy(loaded);
    if(header_storage)for(size_t i=0;i<count;++i)free(header_storage[i].data);
    free(header_storage);free(headers);free(bounds);free(roots);
    free(firsts);free(counts);free(ids);free(namespaces);free(metadata_starts);free(private_rules);free(body_starts);free(body_ends);
    if(contexts)for(size_t i=0;i<count;++i) {
        if(contexts[i].pattern.extra_names==print_names)contexts[i].pattern.extra_names=NULL;
        yx_pattern_expression_destroy(&contexts[i].pattern);
    }
    free(print_names);
    free(names);free(mapping);free(kinds);free(private_patterns);free(patterns);free(limits);
    yx_tree_store_destroy(&store);free(frame_flags);free(frame_first);free(frame_list);
    free(contexts);free(base);free(canonical);free(metadata.data);free(fake_metadata.data);return status;
}
#endif
