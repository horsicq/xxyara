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

/* Shared module/global/pattern expressions use ten-rule chunks. The joined
 * expression collects the import and type union; each rule still gets its own
 * search guard and undefined-value scope. */
static int yx_composed_join_roots(yx_module_program *p,const int *roots,size_t count)
{
    if(count==1)return roots[0];
    size_t left_count=count/2;int left=yx_composed_join_roots(p,roots,left_count),right=yx_composed_join_roots(p,roots+left_count,count-left_count);
    if(left<0||right<0)return -1;
    int node=yx_module_node_new(p,YX_ME_AND,1);if(node>=0){p->nodes[node].args[0]=left;p->nodes[node].args[1]=right;}return node;
}
static bool yx_composed_rule_emit(yx_module_program *p,yx_module_patterns *context,
    int root,size_t rule,size_t match,size_t no_match,yx_writer *expression)
{
    static const uint8_t suffix[]={0x0b,0x45,4,0x40};
    context->searched=false;context->scope_depth=0;p->undefined_slot=-1;
    if(!yx_put_u8(expression,2)||!yx_put_u8(expression,0x7f)||
       !yx_module_root_boolean(p,root,expression)||!yx_put_bytes(expression,suffix,sizeof(suffix)))return false;
    if(context->prior.rules[rule].is_global&&
       (no_match==SIZE_MAX||!yx_put_u8(expression,0x41)||!yx_put_sleb_i64(expression,(int64_t)rule)||
        !yx_put_u8(expression,0x10)||!yx_put_uleb(expression,p->imports[no_match].id)||
        !yx_put_u8(expression,0x41)||!yx_put_u8(expression,1)||!yx_put_u8(expression,0x0f)))return false;
    return yx_put_u8(expression,5)&&yx_put_u8(expression,0x41)&&
        yx_put_sleb_i64(expression,(int64_t)rule)&&yx_put_u8(expression,0x10)&&
        yx_put_uleb(expression,p->imports[match].id)&&yx_put_u8(expression,0x0b);
}
static bool yx_composed_module_wasm(yx_module_program *p, const int *roots,
                                    size_t count, uint8_t **data, size_t *length)
{
    yx_module_patterns *context=p?p->extension:NULL;
    size_t original_count=p?p->count:0,chunks=0,namespaces=0,total=0,capacity=0;
    uint8_t *initial=NULL;size_t initial_length=0;
    yx_writer wasm={0},functions={0},exports={0},code={0};
    yx_writer *bodies=NULL;yx_wasm_function *order=NULL;
    size_t *indices=NULL,*firsts=NULL,*lasts=NULL,*chunk_ns=NULL,*helper_counts=NULL;
    uint64_t *sizes=NULL;
    size_t **helper_offsets=NULL;
    bool ok=false;
    if(!p||!context||!roots||!count||count>SIZE_MAX/sizeof(size_t)-16||context->prior.count!=count||!context->prior.rules)goto done;
    size_t last_namespace=context->prior.rules[count-1].namespace_index;
    if(context->namespace_count&&context->namespace_count-1>last_namespace)
        last_namespace=context->namespace_count-1;
    size_t wrappers=last_namespace?last_namespace/20+(last_namespace%20!=0):1;
    if(wrappers>SIZE_MAX-count-2)goto done;
    capacity=count+wrappers+2;
    bodies=calloc(capacity,sizeof(*bodies));order=calloc(capacity,sizeof(*order));indices=calloc(capacity,sizeof(*indices));
    firsts=calloc(count,sizeof(*firsts));lasts=calloc(count,sizeof(*lasts));chunk_ns=calloc(count,sizeof(*chunk_ns));
    helper_counts=calloc(capacity,sizeof(*helper_counts));helper_offsets=calloc(capacity,sizeof(*helper_offsets));
    sizes=calloc(count,sizeof(*sizes));
    if(!bodies||!order||!indices||!firsts||!lasts||!chunk_ns||!helper_counts||!helper_offsets||!sizes)goto done;
    for (size_t i = 0; i < count; ++i)
        if (roots[i] < 0 || (size_t)roots[i] >= p->count) goto done;
    if(!yx_module_nodes_reserve(p,count))goto done;
    int joined=yx_composed_join_roots(p,roots,count);
    if(joined<0)goto done;
    p->no_match=false;
    for(size_t i=0;i<count;++i)p->no_match|=context->prior.rules[i].is_global;
    if(context->archive&&context->archive->logical) {
        if(!yx_module_pattern_wasm(p,joined,&initial,&initial_length))goto done;
    } else {
        context->presence=false;p->import_count=0;p->call_count=0;
        p->memory=false;p->filesize=false;p->divisor=false;p->filesize_global=0;
        if(!yx_module_wasm(p,joined,&initial,&initial_length))goto done;
    }
    /* Helper calls are relocated using canonical unsigned LEB128, including
     * function indices beyond the first 128 entries. */
    if(p->import_count>SIZE_MAX-capacity)goto done;
    yx_reader header = {initial, initial_length, 8, false, false};
    for (unsigned i = 0; i < 2; ++i) {
        uint8_t section;
        uint64_t width;
        if (!yx_get_u8(&header, &section) || section != i + 1 ||
            !yx_get_uleb(&header, &width) || width > header.length - header.at) goto done;
        header.at += (size_t)width;
    }
    if (!yx_put_bytes(&wasm, initial, header.at)) goto done;
    size_t match = SIZE_MAX, no_match=SIZE_MAX, import_count = p->import_count;
    for (size_t i = 0; i < import_count; ++i) {
        if (!strcmp(p->imports[i].name,"rule_match@rule_id:i@"))match=i;
        if (!strcmp(p->imports[i].name,"rule_no_match@rule_id:i@"))no_match=i;
    }
    if (match == SIZE_MAX) goto done;
    for(size_t i=0;i<count;++i) {
        yx_writer expression={0};p->filesize=p->divisor=p->i32_local=p->two_locals=false;p->call_count=0;context->helper_call_count=0;
        bool measured=yx_composed_rule_emit(p,context,roots[i],i,match,no_match,&expression)&&
            p->import_count==import_count&&
            yx_rule_expression_rule_size(&expression,context->search_global,&sizes[i]);
        free(expression.data);if(!measured)goto done;
    }
    for(size_t first=0;first<count;) {
        size_t ns=context->prior.rules[first].namespace_index,last=first+1;
        while(last<count&&ns==context->prior.rules[last].namespace_index)++last;
        for(size_t i=first;i<last;) {
            size_t end=yx_rule_expression_chunk_end(sizes,i,last);if(end==i)goto done;
            firsts[chunks]=i;lasts[chunks]=end;chunk_ns[chunks++]=namespaces;i=end;
        }
        ++namespaces;first=last;
    }
    total=chunks+wrappers+1+context->presence;
    for (size_t chunk = 0; chunk < chunks; ++chunk) {
        yx_writer expression = {0};
        size_t first=firsts[chunk],last=lasts[chunk];
        p->filesize = p->divisor = p->i32_local = p->two_locals = false;
        p->call_count = 0;
        context->helper_call_count = 0;
        bool emitted = true;
        for (size_t i = first; emitted && i < last; ++i) {
            emitted=yx_composed_rule_emit(p,context,roots[i],i,match,no_match,&expression);
        }
        if (p->import_count != import_count) emitted = false;
        for (size_t i = 0; emitted && i < p->call_count; ++i) {
            size_t at = p->calls[i];
            if (at >= expression.used || expression.data[at] >= import_count) emitted = false;
            else expression.data[at] = p->imports[expression.data[at]].id;
        }
        yx_writer *body = &bodies[chunk];
        bool locals = p->filesize || p->divisor || p->two_locals;
        /* walrus numbers the i32 temporary before the i64 ones, which the
         * writer numbers from 0. Range bounds and signed division use
         * i64_tmp_b as well. */
        if (emitted && p->i32_local && locals)
            emitted = yx_module_shift_wide_locals(expression.data, expression.used, 1);
        emitted = emitted && yx_put_u8(body, (locals ? 1 : 0) + p->i32_local) &&
            (!p->i32_local || (yx_put_u8(body, 1) && yx_put_u8(body, 0x7f))) &&
            (!locals || (yx_put_u8(body, p->two_locals ? 2 : 1) && yx_put_u8(body, 0x7e)));
        helper_counts[chunk] = context->helper_call_count;
        helper_offsets[chunk]=calloc(context->helper_call_count?context->helper_call_count:1,sizeof(*helper_offsets[chunk]));
        if(!helper_offsets[chunk])emitted=false;
        for (size_t i = 0; emitted && i < context->helper_call_count; ++i) {
            if (context->helper_calls[i] >= expression.used) emitted = false;
            else helper_offsets[chunk][i] = body->used + context->helper_calls[i];
        }
        emitted = emitted && yx_put_bytes(body, expression.data, expression.used) &&
            yx_put_u8(body, 0x41) && yx_put_u8(body, 0) && yx_put_u8(body, 0x0b);
        free(expression.data);
        /* Sort by the public program's instruction count. Lowering can make
         * a rule chunk tie a namespace wrapper; the original creation order
         * must decide that tie before the v12 pass sees the private order. */
        if (!emitted || !yx_v12_rule_size(body->data, body->used,
                context->search_global, &order[chunk].instructions)) goto done;
        order[chunk].created = chunk;
    }
    size_t wrapper=chunks+context->presence,main=wrapper+wrappers;
    if(context->presence)order[chunks]=(yx_wasm_function){chunks,15};
    for(size_t w=0;w<wrappers;++w) {
        uint64_t instructions=0;
        for(size_t ns=0;ns<namespaces;++ns) {
            size_t ordinal=context->prior.rules[firsts[0]].namespace_index;
            for(size_t ch=0;ch<chunks;++ch)if(chunk_ns[ch]==ns){ordinal=context->prior.rules[firsts[ch]].namespace_index;break;}
            if((ordinal?(ordinal-1)/20:0)!=w)continue;
            ++instructions;
            for(size_t ch=0;ch<chunks;++ch)if(chunk_ns[ch]==ns)instructions+=2;
        }
        order[wrapper+w]=(yx_wasm_function){wrapper+w,instructions};
    }
    order[main]=(yx_wasm_function){main,wrappers+1};
    qsort(order,total,sizeof(*order),yx_compare_wasm_functions);
    for(size_t i=0;i<total;++i)indices[order[i].created]=import_count+i;
    if(context->presence) {
        static const uint8_t helper[]={1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
        context->helper_id=indices[chunks];if(!yx_put_bytes(&bodies[chunks],helper,sizeof(helper)))goto done;
        for(size_t ch=0;ch<chunks;++ch)if(!yx_module_pattern_relocate_helper(&bodies[ch],helper_offsets[ch],helper_counts[ch],context->helper_id))goto done;
    }
    for(size_t w=0;w<wrappers;++w) {
        yx_writer *body=&bodies[wrapper+w];if(!yx_put_u8(body,0))goto done;
        for(size_t ns=0;ns<namespaces;++ns) {
            size_t ordinal=context->prior.rules[firsts[0]].namespace_index;
            for(size_t ch=0;ch<chunks;++ch)if(chunk_ns[ch]==ns){ordinal=context->prior.rules[firsts[ch]].namespace_index;break;}
            if((ordinal?(ordinal-1)/20:0)!=w)continue;
            if(!yx_put_u8(body,2)||!yx_put_u8(body,0x40))goto done;
            for(size_t ch=0;ch<chunks;++ch)if(chunk_ns[ch]==ns)
                if(!yx_put_u8(body,0x10)||!yx_put_uleb(body,indices[ch])||!yx_put_u8(body,0x0d)||!yx_put_u8(body,0))goto done;
            if(!yx_put_u8(body,0x0b))goto done;
        }
        if(!yx_put_u8(body,0x0b))goto done;
    }
    if(!yx_put_u8(&bodies[main],0))goto done;
    for(size_t w=0;w<wrappers;++w)if(!yx_put_u8(&bodies[main],0x10)||!yx_put_uleb(&bodies[main],indices[wrapper+w]))goto done;
    if(!yx_put_u8(&bodies[main],0x41)||!yx_put_u8(&bodies[main],0)||!yx_put_u8(&bodies[main],0x0b)||
       !yx_put_uleb(&functions,total)||!yx_put_uleb(&code,total)||!yx_put_u8(&exports,1)||
       !yx_module_wasm_string(&exports,"main")||!yx_put_u8(&exports,0)||!yx_put_uleb(&exports,indices[main]))goto done;
    for (size_t i = 0; i < total; ++i) {
        size_t created = order[i].created;
        uint8_t type = created >= wrapper && created < main ? 0 :
            context->presence && created == chunks ? context->helper_type : 1;
        if (!yx_put_u8(&functions, type) || !yx_put_uleb(&code, bodies[created].used) ||
            !yx_put_bytes(&code, bodies[created].data, bodies[created].used)) goto done;
    }
    if (!yx_append_wasm_section(&wasm, 3, &functions) ||
        !yx_append_wasm_section(&wasm, 7, &exports) ||
        !yx_append_wasm_section(&wasm, 10, &code)) goto done;
    *data = wasm.data;
    *length = wasm.used;
    wasm.data = NULL;
    ok = true;
done:
    if (p) p->count = original_count;
    if(bodies)for(size_t i=0;i<capacity;++i)free(bodies[i].data);
    if(helper_offsets)for(size_t i=0;i<capacity;++i)free(helper_offsets[i]);
    free(bodies);free(order);free(indices);free(firsts);free(lasts);free(chunk_ns);free(helper_counts);free(helper_offsets);free(sizes);
    free(initial);
    free(wasm.data);
    free(functions.data);
    free(exports.data);
    free(code.data);
    return ok;
}
