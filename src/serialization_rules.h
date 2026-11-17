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

/* Generic prior-rule leaves composed with the numeric/Boolean archive AST.
 * The existing envelope codec supplies identifiers, tags and metadata; this
 * layer generates and validates code independently of rule names or values. */

typedef struct yx_rule_expression_context {
    const YRX_RULE *rules;
    const yx_ser_rule *decoded;
    size_t rule_count, current;
    bool saw_reference;
} yx_rule_expression_context;

static int yx_rule_expression_primary(yx_integer_expr *tree, unsigned depth, void *user)
{
    yx_rule_expression_context *context = user;
    const unsigned char *name;
    size_t length;
    (void)depth;
    if (!yx_with_identifier(&tree->parser, &name, &length)) return -1;
    for (size_t i = 0; i < context->current; ++i) {
        const char *expected = context->rules[i].identifier;
        if (strlen(expected) == length && !memcmp(name, expected, length)) {
            context->saw_reference = true;
            return yx_integer_expr_node_new(tree, 0xd0, -1, -1, (int64_t)i);
        }
    }
    return -1;
}

static bool yx_rule_expression_emit(const yx_integer_expr *tree, int index,
    yx_writer *writer, unsigned depth, int undefined_slot, bool boolean, void *user)
{
    const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[index];
    (void)depth; (void)undefined_slot; (void)user;
    if (node->op != 0xd0 || node->value < 0) return false;
    uint64_t rule = (uint64_t)node->value;
    return yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, (int64_t)(rule / 8)) &&
        yx_put_u8(writer, 0x2d) && yx_put_u8(writer, 0) &&
        yx_put_uleb(writer, 17664) &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, INT64_C(1) << (rule % 8)) &&
        yx_put_u8(writer, 0x71) && yx_put_u8(writer, 0x41) && yx_put_u8(writer, (uint8_t)(rule % 8)) &&
        yx_put_u8(writer, 0x76) && (boolean || yx_put_u8(writer, 0xad));
}

static bool yx_rule_expression_resources(yx_integer_expr *tree, int index, void *user)
{
    (void)user;
    if (YX_INTEGER_NODES(tree)[index].op != 0xd0) return false;
    tree->has_memory = true;
    return true;
}

static bool yx_rule_expression_print(const yx_integer_expr *tree, int index,
                                       yx_writer *out, void *user)
{
    yx_rule_expression_context *context = user;
    int64_t rule = YX_INTEGER_NODES(tree)[index].value;
    if (YX_INTEGER_NODES(tree)[index].op != 0xd0 || rule < 0 || (uint64_t)rule >= context->current) return false;
    const char *name = context->decoded[rule].identifier;
    return yx_put_bytes(out, name, strlen(name));
}

static bool yx_rule_expression_byte(yx_reader *reader, uint8_t expected)
{
    uint8_t value;
    return yx_get_u8(reader, &value) && value == expected;
}

static int yx_rule_expression_decode(yx_reader *reader, size_t end,
                                       yx_integer_expr *tree, void *user)
{
    yx_rule_expression_context *context = user;
    yx_reader saved = *reader;
    uint64_t offset;
    int64_t byte_index,mask,shift;
    if (!yx_rule_expression_byte(reader,0x41)||!yx_get_sleb_i64(reader,&byte_index)||byte_index<0||
        !yx_rule_expression_byte(reader,0x2d)||!yx_rule_expression_byte(reader,0)||
        !yx_get_uleb(reader,&offset)||offset!=17664||
        !yx_rule_expression_byte(reader,0x41)||!yx_get_sleb_i64(reader,&mask)||
        !yx_rule_expression_byte(reader,0x71)||!yx_rule_expression_byte(reader,0x41)||
        !yx_get_sleb_i64(reader,&shift)||shift<0||shift>7||
        mask!=(INT64_C(1)<<shift)||!yx_rule_expression_byte(reader,0x76)||reader->at>end) {
        *reader=saved;return -1;
    }
    uint64_t rule=(uint64_t)byte_index*8+(uint64_t)shift;
    if(rule>=context->current){*reader=saved;return -1;}
    context->saw_reference = true;
    return yx_integer_expr_node_new(tree,0xd0,-1,-1,(int64_t)rule);
}

static void yx_rule_expression_setup(yx_integer_expr *tree, yx_rule_expression_context *context)
{
    tree->extension = context;
    tree->parse_primary = yx_rule_expression_primary;
    tree->emit_primary = yx_rule_expression_emit;
    tree->resource_primary = yx_rule_expression_resources;
    tree->print_primary = yx_rule_expression_print;
    tree->decode_primary = yx_rule_expression_decode;
}

/* Walrus orders local functions by their instruction counts, excluding
 * structural end/else markers. Count emitted instructions, rather than
 * approximating the size from source expression shape. */
static bool yx_rule_expression_instructions(const yx_writer *body, uint64_t *count)
{
    yx_reader r={body->data,body->used,0,false,false};
    uint64_t groups, value; int64_t signed_value; uint8_t op;
    if(!yx_get_uleb(&r,&groups))return false;
    for(uint64_t i=0;i<groups;++i)
        if(!yx_get_uleb(&r,&value)||!yx_get_u8(&r,&op))return false;
    *count=0;
    while(r.at<r.length) {
        if(!yx_get_u8(&r,&op))return false;
        if(op!=0x0b&&op!=0x05)++*count;
        if(op==0x02||op==0x03||op==0x04) {
            if(!yx_get_u8(&r,&op))return false;
        } else if(op==0x41||op==0x42) {
            if(!yx_get_sleb_i64(&r,&signed_value))return false;
        } else if(op==0x44) {
            if(r.length-r.at<8)return false;
            r.at+=8;
        } else if(op==0x0c||op==0x0d||op==0x10||(op>=0x20&&op<=0x24)) {
            if(!yx_get_uleb(&r,&value))return false;
        } else if(op>=0x28&&op<=0x3e) {
            if(!yx_get_uleb(&r,&value)||!yx_get_uleb(&r,&value))return false;
        }
    }
    return true;
}

/* The final v12 lowering removes unreferenced value blocks and adds the
 * lazy-search eqz. Measure that form before choosing rule-function bounds. */
static bool yx_v12_rule_size(const uint8_t *data,size_t length,
                             size_t search_global,uint64_t *count);
enum { YX_ARCHIVE_RULES_PER_FUNCTION=10, YX_ARCHIVE_MAX_FUNCTION_INSTRUCTIONS=100000 };
static bool yx_rule_expression_rule_size(const yx_writer *expression,
                                         size_t search_global,uint64_t *count)
{
    yx_writer body={0};
    bool ok=yx_put_u8(&body,0)&&yx_put_bytes(&body,expression->data,expression->used)&&
        yx_put_u8(&body,0x0b)&&yx_v12_rule_size(body.data,body.used,search_global,count);
    free(body.data);return ok&&*count<=YX_ARCHIVE_MAX_FUNCTION_INSTRUCTIONS;
}
static size_t yx_rule_expression_chunk_end(const uint64_t *sizes,size_t first,size_t last)
{
    uint64_t instructions=0;size_t end=first;
    while(end<last&&end-first<YX_ARCHIVE_RULES_PER_FUNCTION) {
        if(sizes[end]>YX_ARCHIVE_MAX_FUNCTION_INSTRUCTIONS)return first;
        if(instructions>YX_ARCHIVE_MAX_FUNCTION_INSTRUCTIONS-sizes[end])break;
        instructions+=sizes[end++];
    }
    return end;
}
static bool yx_rule_expression_function_total(const uint8_t *wasm,size_t length,
                                               size_t minimum,size_t maximum,size_t *total)
{
    yx_reader r={wasm,length,8,false,false};uint64_t n;uint8_t section;
    if(length<8||memcmp(wasm,"\0asm\1\0\0\0",8))return false;
    while(r.at<r.length) {
        if(!yx_get_u8(&r,&section)||!yx_get_uleb(&r,&n)||n>r.length-r.at)return false;
        if(section==3) {
            size_t end=r.at+(size_t)n;
            if(!yx_get_uleb(&r,&n)||r.at>end||n<minimum||n>maximum)return false;
            *total=(size_t)n;return true;
        }
        r.at+=(size_t)n;
    }
    return false;
}
static bool yx_rule_expression_emit_one(yx_integer_expr *tree,int root,
                                        size_t rule_id,uint8_t match_id,yx_writer *body)
{
    static const uint8_t suffix[]={0x0b,0x45,0x04,0x40,0x05,0x41};
    return yx_put_u8(body,2)&&yx_put_u8(body,0x7f)&&yx_integer_boolean_emit(tree,root,body,0)&&
        yx_put_bytes(body,suffix,sizeof(suffix))&&yx_put_sleb_i64(body,(int64_t)rule_id)&&
        yx_put_u8(body,0x10)&&yx_put_uleb(body,match_id)&&yx_put_u8(body,0x0b);
}

static bool yx_rule_expressions_wasm(yx_integer_expr *trees, const int *roots,
    size_t count, uint8_t profile, uint8_t **data, size_t *length)
{
    yx_integer_expr imports={0};yx_writer wasm={0},code={0},functions={0},exports={0};
    size_t chunks=0,total=0,capacity=count+2;
    yx_writer *bodies=calloc(capacity,sizeof(*bodies));
    yx_wasm_function *order=calloc(capacity,sizeof(*order));
    size_t *indices=calloc(capacity,sizeof(*indices));
    uint64_t *sizes=calloc(count,sizeof(*sizes));
    size_t *firsts=calloc(count,sizeof(*firsts)),*lasts=calloc(count,sizeof(*lasts));
    bool ok=false;
    if(!bodies||!order||!indices||!sizes||!firsts||!lasts)goto done;
    for(size_t i=0;i<count;++i) {
        yx_integer_expr *tree=&trees[i];
        tree->has_filesize=tree->has_shift=tree->has_divisor=tree->has_memory=tree->has_loop=false;
        tree->read_mask=0;
        if(!yx_integer_expr_resources(tree,roots[i],0,0))goto done;
        imports.has_filesize|=tree->has_filesize;imports.has_memory|=tree->has_memory;
        imports.read_mask|=tree->read_mask;
    }
    if(!yx_integer_module_header(&imports,profile,&wasm))goto done;
    /* Keep the independently generated types/imports; rebuild the function
     * and export sections after ordering all rule chunks. */
    yx_reader header={wasm.data,wasm.used,8,false,false};
    for(unsigned i=0;i<2;++i) {
        uint8_t section;uint64_t width;
        if(!yx_get_u8(&header,&section)||section!=i+1||!yx_get_uleb(&header,&width)||width>header.length-header.at)goto done;
        header.at+=(size_t)width;
    }
    wasm.used=header.at;
    for(size_t i=0;i<count;++i) {
        yx_writer expression={0};
        trees[i].match_id=imports.match_id;memcpy(trees[i].read_ids,imports.read_ids,sizeof(imports.read_ids));
        bool measured=yx_rule_expression_emit_one(&trees[i],roots[i],i,imports.match_id,&expression)&&
            yx_rule_expression_rule_size(&expression,SIZE_MAX,&sizes[i]);
        free(expression.data);if(!measured)goto done;
    }
    for(size_t first=0;first<count;) {
        size_t last=yx_rule_expression_chunk_end(sizes,first,count);if(last==first)goto done;
        firsts[chunks]=first;lasts[chunks++]=last;first=last;
    }
    total=chunks+2;
    for(size_t chunk=0;chunk<chunks;++chunk) {
        yx_writer *body=&bodies[chunk];size_t first=firsts[chunk],last=lasts[chunk];
        bool locals=false,shift=false;
        for(size_t i=first;i<last;++i) {
            locals|=trees[i].has_filesize||trees[i].has_shift||trees[i].has_divisor||trees[i].has_loop;
            shift|=trees[i].has_shift||trees[i].has_loop;
        }
        if(!yx_put_u8(body,locals?1:0)||(locals&&(!yx_put_u8(body,shift?2:1)||!yx_put_u8(body,0x7e))))goto done;
        for(size_t i=first;i<last;++i) {
            trees[i].match_id=imports.match_id;memcpy(trees[i].read_ids,imports.read_ids,sizeof(imports.read_ids));
            if(!yx_rule_expression_emit_one(&trees[i],roots[i],i,imports.match_id,body))goto done;
        }
        if(!yx_put_u8(body,0x41)||!yx_put_u8(body,0)||!yx_put_u8(body,0x0b)||
           !yx_rule_expression_instructions(body,&order[chunk].instructions))goto done;
        order[chunk].created=chunk;
    }
    order[chunks]=(yx_wasm_function){chunks,1+2*chunks};
    order[chunks+1]=(yx_wasm_function){chunks+1,2};
    qsort(order,total,sizeof(*order),yx_compare_wasm_functions);
    for(size_t i=0;i<total;++i)indices[order[i].created]=imports.function_count+i;
    yx_writer *wrapper=&bodies[chunks],*main=&bodies[chunks+1];
    if(!yx_put_u8(wrapper,0)||!yx_put_u8(wrapper,2)||!yx_put_u8(wrapper,0x40))goto done;
    for(size_t i=0;i<chunks;++i)
        if(!yx_put_u8(wrapper,0x10)||!yx_put_uleb(wrapper,indices[i])||!yx_put_u8(wrapper,0x0d)||!yx_put_u8(wrapper,0))goto done;
    if(!yx_put_u8(wrapper,0x0b)||!yx_put_u8(wrapper,0x0b)||
       !yx_put_u8(main,0)||!yx_put_u8(main,0x10)||!yx_put_uleb(main,indices[chunks])||
       !yx_put_u8(main,0x41)||!yx_put_u8(main,0)||!yx_put_u8(main,0x0b)||
       !yx_put_uleb(&functions,total)||!yx_put_uleb(&code,total)||
       !yx_put_u8(&exports,1)||!yx_put_u8(&exports,4)||!yx_put_bytes(&exports,"main",4)||
       !yx_put_u8(&exports,0)||!yx_put_uleb(&exports,indices[chunks+1]))goto done;
    for(size_t i=0;i<total;++i) {
        size_t created=order[i].created;
        if(!yx_put_u8(&functions,created==chunks?0:1)||!yx_put_uleb(&code,bodies[created].used)||
           !yx_put_bytes(&code,bodies[created].data,bodies[created].used))goto done;
    }
    if(!yx_append_wasm_section(&wasm,3,&functions)||!yx_append_wasm_section(&wasm,7,&exports)||
       !yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:
    if(bodies)for(size_t i=0;i<capacity;++i)free(bodies[i].data);
    free(bodies);free(order);free(indices);free(sizes);free(firsts);free(lasts);
    free(wasm.data);free(code.data);free(functions.data);free(exports.data);return ok;
}

/* Return both the length-prefix and byte span, preserving arbitrary metadata
 * literals. The expression domains here have no regular-expression pool. */
static bool yx_rule_expression_wasm_span(const uint8_t *data,size_t length,
    size_t *prefix,size_t *start,size_t *size,size_t *count)
{
    yx_reader reader={data,length,12,false,false};uint64_t n,width;
    if(length<12||memcmp(data,"YARA-X\0\0\14\0\0\0",12)||!yx_get_uint(&reader,&n))return false;
    for(uint64_t i=0;i<n;i++) {
        if(!yx_get_uint(&reader,&width)||width>length-reader.at)return false;
        reader.at+=(size_t)width;
    }
    if(!yx_expect_uint(&reader,0)||!yx_expect_uint(&reader,0)||!yx_get_uint(&reader,&n))return false;
    for(uint64_t i=0;i<n;i++) {
        if(!yx_get_uint(&reader,&width)||width>length-reader.at)return false;
        reader.at+=(size_t)width;
    }
    *prefix=reader.at;
    if(!yx_get_uint(&reader,&width)||width>length-reader.at)return false;
    *start=reader.at;*size=(size_t)width;reader.at+=(size_t)width;
    if(!yx_expect_uint(&reader,0)||!yx_expect_uint(&reader,0)||!yx_get_uint(&reader,&n)||n>SIZE_MAX)return false;
    *count=(size_t)n;return true;
}

static bool yx_rule_expression_replace_wasm(const uint8_t *data,size_t length,
    const uint8_t *wasm,size_t wasm_length,uint8_t **out,size_t *out_length)
{
    size_t prefix,start,size,count;yx_writer writer={0};
    if(!yx_rule_expression_wasm_span(data,length,&prefix,&start,&size,&count))return false;
    if(!yx_put_bytes(&writer,data,prefix)||!yx_put_uint(&writer,wasm_length)||
       !yx_put_bytes(&writer,wasm,wasm_length)||
       !yx_put_bytes(&writer,data+start+size,length-start-size)) {free(writer.data);return false;}
    *out=writer.data;*out_length=writer.used;return true;
}

static yx_ser_result yx_encode_rule_expressions(const YRX_RULES *rules,uint8_t **data,size_t *length)
{
    if(!rules||!rules->rule_count||rules->rule_count>INT32_MAX||rules->import_count||rules->global_count)return YX_SER_UNSUPPORTED;
    size_t count=rules->rule_count;
    for(size_t i=0;i<count;i++)
        if(rules->rules[i].pattern_count||rules->rules[i].is_global||!rules->rules[i].condition_text||
           strcmp(rules->rules[i].namespace_name?rules->rules[i].namespace_name:"default",
                  rules->rules[0].namespace_name?rules->rules[0].namespace_name:"default"))return YX_SER_UNSUPPORTED;
    yx_integer_expr *trees=calloc(count,sizeof(*trees));int *roots=calloc(count,sizeof(*roots));
    bool *truths=calloc(count,sizeof(*truths));uint8_t *wasm=NULL,*envelope=NULL;
    size_t wasm_length=0,envelope_length=0;yx_ser_result status=YX_SER_UNSUPPORTED;
    yx_rule_expression_context context={rules->rules,NULL,count,0,false};
    if(!trees||!roots||!truths){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;i++) {
        context.current=i;yx_rule_expression_setup(&trees[i],&context);
        roots[i]=yx_integer_expr_condition(&trees[i],rules->rules[i].condition_text);
        if(roots[i]<0)goto done;
        for(size_t n=0;n<trees[i].count;++n) {
            yx_integer_expr_node *node=&YX_INTEGER_NODES(&trees[i])[n];
            if(node->op!=0x51)continue;
            int boolean=-1,number=-1;
            if(yx_integer_expr_boolean(YX_INTEGER_NODES(&trees[i])[node->left].op)&&YX_INTEGER_NODES(&trees[i])[node->right].op==0x42)
                boolean=node->left,number=node->right;
            else if(yx_integer_expr_boolean(YX_INTEGER_NODES(&trees[i])[node->right].op)&&YX_INTEGER_NODES(&trees[i])[node->left].op==0x42)
                boolean=node->right,number=node->left;
            if(boolean>=0&&(YX_INTEGER_NODES(&trees[i])[number].value==0||YX_INTEGER_NODES(&trees[i])[number].value==1)) {
                if(YX_INTEGER_NODES(&trees[i])[number].value)*node=YX_INTEGER_NODES(&trees[i])[boolean];
                else {node->op=0xa2;node->left=node->right=boolean;}
            }
        }
    }
    if(!context.saw_reference&&count==1)goto done;
    if(!yx_rule_expressions_wasm(trees,roots,count,yx_integer_import_profile(),&wasm,&wasm_length))goto done;
    status=yx_encode_fields(rules->rules,count,truths,NULL,false,false,false,false,false,false,false,false,false,false,false,
                           YX_PATTERN_STAT_DEFAULT,false,false,false,false,&envelope,&envelope_length);
    if(status==YX_SER_SUCCESS&&!yx_rule_expression_replace_wasm(envelope,envelope_length,wasm,wasm_length,data,length))status=YX_SER_NO_MEMORY;
done:
    if(trees)for(size_t i=0;i<count;++i)yx_integer_expr_destroy(&trees[i]);
    free(trees);free(roots);free(truths);free(wasm);free(envelope);return status;
}

/* Decode typed expression leaves, then validate every instruction by emitting
 * the independent canonical builder. The existing envelope parser continues
 * to own rule identifiers, metadata, flags and archive structure validation. */
static yx_ser_result yx_decode_rule_expressions(const uint8_t *data, size_t length,
                                                 yx_ser_rule **rules, size_t *rule_count)
{
    size_t prefix, start, size, count, body_end;
    uint64_t width, functions, local_groups, locals;
    uint8_t marker, *canonical=NULL, *constant=NULL, *base=NULL;
    size_t canonical_length=0, constant_length=0, base_length=0, decoded_count=0;
    yx_integer_expr imports={0}, *trees=NULL;
    int *roots=NULL;
    bool *truths=NULL;
    yx_ser_rule *decoded=NULL;
    yx_ser_result status=YX_SER_UNSUPPORTED;
    yx_rule_expression_context context={0};
    if(!yx_rule_expression_wasm_span(data,length,&prefix,&start,&size,&count)||!count||count>INT32_MAX||count>size||count>SIZE_MAX/sizeof(*trees)) return status;
    yx_reader reader={data+start,size,0,false,false};
    if(!yx_integer_wasm_header(&reader,&imports)||
       !yx_rule_expression_byte(&reader,10)||!yx_get_uleb(&reader,&width)||width!=size-reader.at||
       !yx_get_uleb(&reader,&functions)||functions<(count+9)/10+2||functions>count+2||
       !yx_get_uleb(&reader,&width)||width>size-reader.at) return status;
    /* The first body length was read above. Rule chunks may be reordered
     * by instruction count; match callbacks carry their stable rule IDs. */
    size_t body_start=reader.at;uint64_t first_width=width;
    trees=calloc(count,sizeof(*trees));roots=malloc(count*sizeof(*roots));truths=calloc(count,sizeof(*truths));
    if(!trees||!roots||!truths){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i)roots[i]=-1;
    context.rule_count=context.current=count;
    for(uint64_t function=0;function<functions;++function) {
        if(function==0){reader.at=body_start;width=first_width;}
        else if(!yx_get_uleb(&reader,&width)||width>size-reader.at)goto done;
        body_end=reader.at+(size_t)width;
        if(!yx_get_uleb(&reader,&local_groups)||local_groups>1||
           (local_groups&&(!yx_get_uleb(&reader,&locals)||locals<1||locals>2||
            !yx_get_u8(&reader,&marker)||marker!=0x7e)))goto done;
        while(reader.at+1<body_end&&reader.data[reader.at]==2&&reader.data[reader.at+1]==0x7f) {
            yx_integer_expr *tree=calloc(1,sizeof(*tree));
            if(!tree){status=YX_SER_NO_MEMORY;goto done;}
            *tree=imports;yx_rule_expression_setup(tree,&context);reader.at+=2;
            int root=yx_integer_wasm_block(&reader,body_end,tree,0,-1);
            static const uint8_t suffix[]={0x45,0x04,0x40,0x05,0x41};int64_t rule_id;
            bool valid=root>=0&&yx_integer_wasm_bytes(&reader,body_end,suffix,sizeof(suffix))&&
                yx_get_sleb_i64(&reader,&rule_id)&&rule_id>=0&&(uint64_t)rule_id<count&&roots[rule_id]<0&&
                yx_rule_expression_byte(&reader,0x10)&&yx_get_uleb(&reader,&width)&&width==imports.match_id&&
                yx_rule_expression_byte(&reader,0x0b);
            if(valid)for(size_t n=0;n<tree->count;++n)
                if(YX_INTEGER_NODES(tree)[n].op==0xd0&&YX_INTEGER_NODES(tree)[n].value>=rule_id)valid=false;
            if(!valid){yx_integer_expr_free(tree);goto done;}
            trees[rule_id]=*tree;tree->extra_nodes=NULL;tree->loop_failures=NULL;roots[rule_id]=root;yx_integer_expr_free(tree);
        }
        reader.at=body_end;
    }
    for(size_t i=0;i<count;++i)if(roots[i]<0)goto done;
    bool dynamic=false;
    for(size_t i=0;i<count;++i)dynamic|=!YX_INTEGER_NODES(&trees[i])[roots[i]].constant;
    if(!dynamic&&!context.saw_reference)goto done;
    uint8_t profile;
    for(profile=0;profile<4;++profile) {
        free(canonical);canonical=NULL;
        if(yx_rule_expressions_wasm(trees,roots,count,profile,&canonical,&canonical_length)&&
           canonical_length==size&&!memcmp(canonical,data+start,size))break;
    }
    if(profile==4)goto done;
    if(!yx_make_constant_wasm(truths,NULL,count,&constant,&constant_length,NULL)||
       !yx_rule_expression_replace_wasm(data,length,constant,constant_length,&base,&base_length)) {
        status=YX_SER_NO_MEMORY;goto done;
    }
    status=yx_ser_decode_many(base,base_length,&decoded,&decoded_count);
    if(status!=YX_SER_SUCCESS)goto done;
    if(decoded_count!=count){status=YX_SER_UNSUPPORTED;goto done;}
    context.decoded=decoded;
    for(size_t i=0;i<count;i++) {
        yx_writer source={0};context.current=i;
        if(!yx_integer_expr_print(&trees[i],roots[i],&source,0,false,0)||!yx_put_u8(&source,0)) {
            free(source.data);status=YX_SER_NO_MEMORY;goto done;
        }
        decoded[i].runtime_integer_condition=(char *)source.data;
        decoded[i].runtime_integer_import_profile=profile;
    }
    *rules=decoded;*rule_count=count;decoded=NULL;status=YX_SER_SUCCESS;
done:
    if(trees)for(size_t i=0;i<count;++i)yx_integer_expr_destroy(&trees[i]);
    free(trees);free(roots);free(truths);free(canonical);free(constant);free(base);
    yx_ser_rules_destroy(decoded,decoded_count);return status;
}
