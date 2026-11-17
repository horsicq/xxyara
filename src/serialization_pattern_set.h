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

/* Pattern set lowering preserves logical duplicates while sharing physical
 * match storage. The selection table follows the source set's ordering. */
static bool yx_pattern_set_variable(yx_writer *w,unsigned slot)
{
    /* The loop initializes every counter and the current pattern id before
     * reading them. Upstream omits undefined flags for these local values. */
    return yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,slot*8)&&
        yx_put_bytes(w,"\x29\x03\x80\x02",4);
}
static bool yx_pattern_set_store(yx_writer *w)
{ return yx_put_bytes(w,"\x37\x03\x80\x02",4); }
static bool yx_pattern_set_constant(yx_writer *w, unsigned slot, uint64_t value)
{
    return yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,slot*8)&&yx_put_u8(w,0x42)&&
        yx_put_sleb_i64(w,(int64_t)value)&&yx_pattern_set_store(w);
}
static bool yx_pattern_set_increment(yx_writer *w,unsigned slot,int depth)
{
    (void)depth;
    return yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,slot*8)&&
        yx_pattern_set_variable(w,slot)&&yx_put_u8(w,0x42)&&
        yx_put_u8(w,1)&&yx_put_u8(w,0x7c)&&yx_pattern_set_store(w);
}
static bool yx_pattern_set_search(yx_writer *w,const yx_pattern_expression_context *c)
{
    const uint8_t bytes[]={0x23,c->search_global,4,0x40,5,0x10,c->ids[1],0x0b};
    return yx_put_bytes(w,bytes,sizeof(bytes));
}
static bool yx_pattern_set_select(yx_writer *w,const size_t *mapping,size_t count)
{
    if(!yx_put_u8(w,2)||!yx_put_u8(w,0x7e))return false;
    for(size_t i=0;i<=count;++i)if(!yx_put_u8(w,2)||!yx_put_u8(w,0x40))return false;
    if(!yx_put_u8(w,0x20)||!yx_put_u8(w,0)||!yx_put_u8(w,0x0e)||!yx_put_uleb(w,count))return false;
    for(size_t i=0;i<count;++i)if(!yx_put_uleb(w,i+1))return false;
    if(!yx_put_u8(w,0)||!yx_put_u8(w,0x0b)||!yx_put_u8(w,0))return false;
    for(size_t i=0;i<count;++i) {
        if(!yx_put_u8(w,0x0b)||!yx_put_u8(w,2)||!yx_put_u8(w,0x7e)||
           !yx_put_u8(w,0x42)||!yx_put_sleb_i64(w,(int64_t)mapping[i])||!yx_put_u8(w,0x0b))return false;
        if(i+1<count&&(!yx_put_u8(w,0x0c)||!yx_put_uleb(w,count-i-1)))return false;
    }
    return yx_put_u8(w,0x0b);
}
static bool yx_pattern_set_body(yx_writer *w,const yx_pattern_expression_context *c,
                                const size_t *mapping,size_t count,bool for_any,bool none,uint64_t required)
{
    const uint8_t start[]={1,1,0x7f,2,0x7f};
    if(!yx_put_bytes(w,start,sizeof(start))||(!for_any&&!yx_pattern_set_search(w,c))||
       !yx_put_u8(w,2)||!yx_put_u8(w,0x7f))return false;
    if(for_any) {
        if(!yx_pattern_set_constant(w,0,count)||!yx_pattern_set_constant(w,1,0))return false;
    } else if(none) {
        if(!yx_pattern_set_constant(w,1,count)||!yx_pattern_set_constant(w,2,0))return false;
    } else if(!yx_pattern_set_constant(w,1,count)||!yx_pattern_set_constant(w,2,0)||
              !yx_pattern_set_constant(w,3,required)||!yx_pattern_set_constant(w,4,0))return false;
    unsigned current=for_any?4:0,index=for_any?1:2;
    if(!yx_put_u8(w,3)||!yx_put_u8(w,0x40)||!yx_put_u8(w,0x41)||!yx_put_u8(w,current*8)||
       !yx_pattern_set_variable(w,index)||!yx_put_u8(w,0xa7)||!yx_put_u8(w,0x21)||!yx_put_u8(w,0)||
       !yx_pattern_set_select(w,mapping,count)||!yx_pattern_set_store(w)||
       !yx_put_u8(w,2)||!yx_put_u8(w,0x7f)||(for_any&&!yx_pattern_set_search(w,c))||
       !yx_pattern_set_variable(w,current)||!yx_put_u8(w,0xa7)||
       !yx_put_u8(w,0x10)||!yx_put_u8(w,c->helper_id)||!yx_put_u8(w,0x0b))return false;
    if(for_any||none) {
        const uint8_t found[]={4,0x40,0x41,(uint8_t)!none,0x0c,2,5,0x0b};
        const uint8_t end[]={0x53,0x0d,0,0x0b,0x41,(uint8_t)none};
        if(!yx_put_bytes(w,found,sizeof(found))||!yx_pattern_set_increment(w,index,-5)||
           !yx_pattern_set_variable(w,index)||!yx_pattern_set_variable(w,for_any?0:1)||
           !yx_put_bytes(w,end,sizeof(end)))return false;
    } else {
        const uint8_t reached[]={0x5a,4,0x40};
        const uint8_t accept[]={0x42,0,0x52,0x0c,3,5,0x0b,5,0x0b};
        const uint8_t again[]={0x53,0x0d,0,0x0b};
        if(!yx_put_u8(w,4)||!yx_put_u8(w,0x40)||!yx_pattern_set_increment(w,4,-5)||
           !yx_pattern_set_variable(w,4)||!yx_pattern_set_variable(w,3)||
           !yx_put_bytes(w,reached,sizeof(reached))||!yx_pattern_set_variable(w,3)||
           !yx_put_bytes(w,accept,sizeof(accept))||!yx_pattern_set_increment(w,2,-4)||
           !yx_pattern_set_variable(w,2)||!yx_pattern_set_variable(w,1)||
           !yx_put_bytes(w,again,sizeof(again))||!yx_pattern_set_variable(w,3)||!yx_put_u8(w,0x50))return false;
    }
    const uint8_t suffix[]={0x0b,0x0b,0x45,4,0x40,5,0x41,0,0x10,c->ids[0],0x0b,0x41,0,0x0b};
    return yx_put_bytes(w,suffix,sizeof(suffix));
}
static bool yx_pattern_set_keyword_wasm(const size_t *mapping,size_t count,bool all,uint8_t profile,
                                    uint8_t **data,size_t *length)
{
    size_t groups=0;
    if(!count||count>SIZE_MAX/sizeof(size_t))return false;
    size_t *sorted=calloc(count,sizeof(*sorted)),*begins=calloc(count,sizeof(*begins)),*ends=calloc(count,sizeof(*ends));
    if(!sorted||!begins||!ends){free(sorted);free(begins);free(ends);return false;}
    for(size_t i=0;i<count;++i) {
        size_t j=i;while(j&&sorted[j-1]>mapping[i]){sorted[j]=sorted[j-1];--j;}
        sorted[j]=mapping[i];
    }
    for(size_t i=0;i<count;++i) {
        if(groups&&sorted[i]==ends[groups-1]+1)ends[groups-1]=sorted[i];
        else begins[groups]=ends[groups]=sorted[i],++groups;
    }
    bool singles=false,ranges=false;
    for(size_t i=0;i<groups;++i)if(begins[i]==ends[i])singles=true;else ranges=true;
    /* Single uninterrupted sets already use the compact existing encoder. */
    if(groups<2){free(sorted);free(begins);free(ends);return false;}
    yx_writer types={0},imports={0},functions={0},exports={0},body={0},code={0},wasm={0};bool ok=false;
    static const uint8_t order[4][3]={{0,2,1},{0,2,1},{1,0,2},{1,2,0}};
    uint8_t ids[3]={0},n=0;
    for(unsigned i=0;i<3;++i)if(order[profile][i]!=2||ranges)ids[order[profile][i]]=n++;
    const uint8_t basics[]={0x60,0,0,0x60,0,1,0x7f,0x60,1,0x7f,0};
    const uint8_t single_type[]={0x60,1,0x7f,1,0x7f},range_type[]={0x60,3,0x7f,0x7f,0x7e,1,0x7f};
    if(!yx_put_u8(&types,3+singles+ranges)||!yx_put_bytes(&types,basics,sizeof(basics))||
       (singles&&!yx_put_bytes(&types,single_type,sizeof(single_type)))||
       (ranges&&!yx_put_bytes(&types,range_type,sizeof(range_type)))||!yx_put_u8(&imports,n+1+singles*2))goto done;
    for(unsigned i=0;i<3;++i) {
        unsigned symbol=order[profile][i];if(symbol==2&&!ranges)continue;
        const char *name=symbol==2?"pat_range_match@pattern_id_start:i,pattern_id_end:i,required:i@b":yx_pattern_expression_symbols[symbol];
        if(!yx_put_integer_read_import(&imports,name,symbol==0?2:symbol==1?0:3+singles))goto done;
    }
    const char *globals[]={"matching_patterns_bitmap_base","pattern_search_done"};
    for(unsigned i=singles?0:1;i<2;++i)if(!yx_put_u8(&imports,6)||!yx_put_bytes(&imports,"yara_x",6)||
        !yx_put_uleb(&imports,strlen(globals[i]))||!yx_put_bytes(&imports,globals[i],strlen(globals[i]))||
        !yx_put_u8(&imports,3)||!yx_put_u8(&imports,0x7f)||!yx_put_u8(&imports,i))goto done;
    if(singles&&(!yx_put_u8(&imports,6)||!yx_put_bytes(&imports,"yara_x",6)||!yx_put_u8(&imports,11)||
       !yx_put_bytes(&imports,"main_memory",11)||!yx_put_u8(&imports,2)||!yx_put_u8(&imports,0)||!yx_put_u8(&imports,1)))goto done;
    if(!yx_put_u8(&functions,3+singles)||!yx_put_u8(&functions,1)||(singles&&!yx_put_u8(&functions,3))||
       !yx_put_u8(&functions,0)||!yx_put_u8(&functions,1)||!yx_put_u8(&exports,1)||!yx_put_u8(&exports,4)||
       !yx_put_bytes(&exports,"main",4)||!yx_put_u8(&exports,0)||!yx_put_u8(&exports,n+2+singles))goto done;
    const uint8_t start[]={0,2,0x7f,0x23,(uint8_t)singles,4,0x40,5,0x10,ids[1],0x0b,2,0x7f};
    if(!yx_put_bytes(&body,start,sizeof(start)))goto done;
    for(size_t i=0;i<groups;++i) {
        if(!yx_put_u8(&body,0x41)||!yx_put_sleb_i64(&body,(int64_t)begins[i]))goto done;
        if(begins[i]!=ends[i]&&(!yx_put_u8(&body,0x41)||!yx_put_sleb_i64(&body,(int64_t)ends[i])||
           !yx_put_u8(&body,0x42)||!yx_put_sleb_i64(&body,all?(int64_t)(ends[i]-begins[i]+1):1)))goto done;
        if(!yx_put_u8(&body,0x10)||!yx_put_u8(&body,begins[i]==ends[i]?n+1:ids[2]))goto done;
        const uint8_t any_shortcut[]={4,0x40,0x41,1,0x0c,1,5,0x0b};
        const uint8_t all_shortcut[]={4,0x40,5,0x41,0,0x0c,1,0x0b};
        if(i+1<groups&&!yx_put_bytes(&body,all?all_shortcut:any_shortcut,sizeof(any_shortcut)))goto done;
    }
    const uint8_t suffix[]={0x0b,0x0b,0x45,4,0x40,5,0x41,0,0x10,ids[0],0x0b,0x41,0,0x0b};
    static const uint8_t helper[]={29,1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    uint8_t tail[]={9,0,2,0x40,0x10,n,0x0d,0,0x0b,0x0b,6,0,0x10,(uint8_t)(n+1+singles),0x41,0,0x0b};
    if(!yx_put_bytes(&body,suffix,sizeof(suffix))||!yx_put_u8(&code,3+singles)||!yx_put_uleb(&code,body.used)||
       !yx_put_bytes(&code,body.data,body.used)||(singles&&!yx_put_bytes(&code,helper,sizeof(helper)))||
       !yx_put_bytes(&code,tail,sizeof(tail))||!yx_put_bytes(&wasm,yx_constant_wasm,8)||
       !yx_append_wasm_section(&wasm,1,&types)||!yx_append_wasm_section(&wasm,2,&imports)||
       !yx_append_wasm_section(&wasm,3,&functions)||!yx_append_wasm_section(&wasm,7,&exports)||
       !yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:free(sorted);free(begins);free(ends);free(types.data);free(imports.data);free(functions.data);free(exports.data);free(body.data);free(code.data);free(wasm.data);return ok;
}
static bool yx_pattern_set_wasm(const size_t *mapping,size_t count,bool for_any,uint64_t required,
                                uint8_t profile,uint8_t **data,size_t *length)
{
    if(!for_any&&required==UINT64_MAX)return yx_pattern_set_keyword_wasm(mapping,count,false,profile,data,length);
    yx_integer_expr *tree=calloc(1,sizeof(*tree));yx_pattern_expression_context c={0};
    yx_writer wasm={0},body={0},code={0};bool ok=false;
    if(!tree)return false;
    int root=yx_integer_expr_node_new(tree,0xd1,-1,-1,0);
    c.presence=true;c.used[1]=true;tree->has_memory=true;
    if(root<0||!yx_pattern_expression_header(tree,root,&c,profile,&wasm)||
       !yx_pattern_set_body(&body,&c,mapping,count,for_any,false,required))goto done;
    static const uint8_t helper[]={29,1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    uint8_t tail[]={9,0,2,0x40,0x10,tree->function_count,0x0d,0,0x0b,0x0b,6,0,0x10,(uint8_t)(tree->function_count+2),0x41,0,0x0b};
    if(!yx_put_u8(&code,4)||!yx_put_uleb(&code,body.used)||!yx_put_bytes(&code,body.data,body.used)||
       !yx_put_bytes(&code,helper,sizeof(helper))||!yx_put_bytes(&code,tail,sizeof(tail))||
       !yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:yx_integer_expr_free(tree);free(wasm.data);free(body.data);free(code.data);return ok;
}
/* Continuous physical sets use the range import; keyword quantifiers retain
 * their result block while numeric quantifiers call it directly. */
static bool yx_pattern_set_range_wasm(size_t last,uint64_t required,bool keyword,
    uint8_t profile,uint8_t **data,size_t *length)
{
    yx_writer types={0},imports={0},functions={0},exports={0},body={0},code={0},wasm={0};bool ok=false;
    static const uint8_t order[4][3]={{0,2,1},{0,2,1},{1,0,2},{1,2,0}};
    uint8_t ids[3];for(unsigned i=0;i<3;++i)ids[order[profile][i]]=(uint8_t)i;
    static const uint8_t signatures[]={4,0x60,0,0,0x60,0,1,0x7f,0x60,1,0x7f,0,0x60,3,0x7f,0x7f,0x7e,1,0x7f};
    if(!yx_put_bytes(&types,signatures,sizeof(signatures))||!yx_put_u8(&imports,4))goto done;
    for(unsigned i=0;i<3;++i) {
        unsigned symbol=order[profile][i];
        const char *name=symbol==2?"pat_range_match@pattern_id_start:i,pattern_id_end:i,required:i@b":yx_pattern_expression_symbols[symbol];
        if(!yx_put_integer_read_import(&imports,name,symbol==0?2:symbol==1?0:3))goto done;
    }
    static const uint8_t funcs[]={3,1,0,1},export_main[]={1,4,'m','a','i','n',0,5};
    if(!yx_put_u8(&imports,6)||!yx_put_bytes(&imports,"yara_x",6)||!yx_put_u8(&imports,19)||
       !yx_put_bytes(&imports,"pattern_search_done",19)||!yx_put_u8(&imports,3)||!yx_put_u8(&imports,0x7f)||!yx_put_u8(&imports,1)||
       !yx_put_bytes(&functions,funcs,sizeof(funcs))||!yx_put_bytes(&exports,export_main,sizeof(export_main)))goto done;
    const uint8_t prefix[]={0,2,0x7f,0x23,0,4,0x40,5,0x10,ids[1],0x0b};
    const uint8_t suffix[]={0x0b,0x45,4,0x40,5,0x41,0,0x10,ids[0],0x0b,0x41,0,0x0b};
    static const uint8_t tail[]={9,0,2,0x40,0x10,3,0x0d,0,0x0b,0x0b,6,0,0x10,4,0x41,0,0x0b};
    if(!yx_put_bytes(&body,prefix,sizeof(prefix))||(keyword&&(!yx_put_u8(&body,2)||!yx_put_u8(&body,0x7f)))||
       !yx_put_u8(&body,0x41)||!yx_put_u8(&body,0)||!yx_put_u8(&body,0x41)||!yx_put_sleb_i64(&body,(int64_t)last)||
       !yx_put_u8(&body,0x42)||!yx_put_sleb_i64(&body,(int64_t)required)||!yx_put_u8(&body,0x10)||!yx_put_u8(&body,ids[2])||
       (keyword&&!yx_put_u8(&body,0x0b))||!yx_put_bytes(&body,suffix,sizeof(suffix))||!yx_put_u8(&code,3)||
       !yx_put_uleb(&code,body.used)||!yx_put_bytes(&code,body.data,body.used)||!yx_put_bytes(&code,tail,sizeof(tail))||
       !yx_put_bytes(&wasm,yx_constant_wasm,8)||!yx_append_wasm_section(&wasm,1,&types)||
       !yx_append_wasm_section(&wasm,2,&imports)||!yx_append_wasm_section(&wasm,3,&functions)||
       !yx_append_wasm_section(&wasm,7,&exports)||!yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:free(types.data);free(imports.data);free(functions.data);free(exports.data);free(body.data);free(code.data);free(wasm.data);return ok;
}
static bool yx_pattern_set_none_wasm(const size_t *mapping,size_t count,uint8_t profile,uint8_t **data,size_t *length)
{
    yx_integer_expr *tree=calloc(1,sizeof(*tree));yx_pattern_expression_context c={0};
    yx_writer wasm={0},body={0},code={0};bool ok=false;
    if(!tree)return false;
    int root=yx_integer_expr_node_new(tree,0xd1,-1,-1,0);
    c.presence=true;c.used[1]=true;tree->has_memory=true;
    if(root<0||!yx_pattern_expression_header(tree,root,&c,profile,&wasm)||
       !yx_pattern_set_body(&body,&c,mapping,count,false,true,0))goto done;
    static const uint8_t helper[]={29,1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    uint8_t tail[]={9,0,2,0x40,0x10,tree->function_count,0x0d,0,0x0b,0x0b,6,0,0x10,(uint8_t)(tree->function_count+2),0x41,0,0x0b};
    if(!yx_put_u8(&code,4)||!yx_put_uleb(&code,body.used)||!yx_put_bytes(&code,body.data,body.used)||
       !yx_put_bytes(&code,helper,sizeof(helper))||!yx_put_bytes(&code,tail,sizeof(tail))||!yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:yx_integer_expr_free(tree);free(wasm.data);free(body.data);free(code.data);return ok;
}
/* `for all of ... : ( $ )` counts the matching patterns inside the found
 * branch and leaves the loop with 0 at the first pattern without a match. */
static bool yx_pattern_set_all_body(yx_writer *w,const yx_pattern_expression_context *c,
                                    const size_t *mapping,size_t count)
{
    const uint8_t start[]={1,1,0x7f,2,0x7f};
    if(!yx_put_bytes(w,start,sizeof(start))||!yx_put_u8(w,2)||!yx_put_u8(w,0x7f)||
       !yx_pattern_set_constant(w,0,count)||!yx_pattern_set_constant(w,1,0))return false;
    if(!yx_put_u8(w,3)||!yx_put_u8(w,0x40)||!yx_put_u8(w,0x41)||!yx_put_u8(w,4*8)||
       !yx_pattern_set_variable(w,1)||!yx_put_u8(w,0xa7)||!yx_put_u8(w,0x21)||!yx_put_u8(w,0)||
       !yx_pattern_set_select(w,mapping,count)||!yx_pattern_set_store(w)||
       !yx_put_u8(w,2)||!yx_put_u8(w,0x7f)||!yx_pattern_set_search(w,c)||
       !yx_pattern_set_variable(w,4)||!yx_put_u8(w,0xa7)||
       !yx_put_u8(w,0x10)||!yx_put_u8(w,c->helper_id)||!yx_put_u8(w,0x0b))return false;
    const uint8_t next[]={0x53,0x0d,1,0x41,1,0x0c,2,5,0x0b,0x41,0,0x0c,1,0x0b,0x41,1};
    if(!yx_put_u8(w,4)||!yx_put_u8(w,0x40)||!yx_pattern_set_increment(w,1,-5)||
       !yx_pattern_set_variable(w,1)||!yx_pattern_set_variable(w,0)||
       !yx_put_bytes(w,next,sizeof(next)))return false;
    const uint8_t suffix[]={0x0b,0x0b,0x45,4,0x40,5,0x41,0,0x10,c->ids[0],0x0b,0x41,0,0x0b};
    return yx_put_bytes(w,suffix,sizeof(suffix));
}
/* `for any|none|all of <set> : ( $ )`: loop 0, 1 or 2. `for none` keeps the
 * `for any` loop with both results swapped. */
static bool yx_pattern_set_loop_wasm(const size_t *mapping,size_t count,unsigned loop,
                                     uint8_t profile,uint8_t **data,size_t *length)
{
    if(loop==0)return yx_pattern_set_wasm(mapping,count,true,0,profile,data,length);
    yx_integer_expr *tree=calloc(1,sizeof(*tree));yx_pattern_expression_context c={0};
    yx_writer wasm={0},body={0},code={0};bool ok=false;
    if(!tree)return false;
    int root=yx_integer_expr_node_new(tree,0xd1,-1,-1,0);
    c.presence=true;c.used[1]=true;tree->has_memory=true;
    if(root<0||!yx_pattern_expression_header(tree,root,&c,profile,&wasm)||
       !(loop==1?yx_pattern_set_body(&body,&c,mapping,count,true,true,0):
                 yx_pattern_set_all_body(&body,&c,mapping,count)))goto done;
    static const uint8_t helper[]={29,1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    uint8_t tail[]={9,0,2,0x40,0x10,tree->function_count,0x0d,0,0x0b,0x0b,6,0,0x10,(uint8_t)(tree->function_count+2),0x41,0,0x0b};
    if(!yx_put_u8(&code,4)||!yx_put_uleb(&code,body.used)||!yx_put_bytes(&code,body.data,body.used)||
       !yx_put_bytes(&code,helper,sizeof(helper))||!yx_put_bytes(&code,tail,sizeof(tail))||
       !yx_append_wasm_section(&wasm,10,&code))goto done;
    *data=wasm.data;*length=wasm.used;wasm.data=NULL;ok=true;
done:yx_integer_expr_free(tree);free(wasm.data);free(body.data);free(code.data);return ok;
}
/* A set naming every pattern once in declaration order is `them`. */
static bool yx_pattern_set_loop_set(yx_bool_parser *p,const YRX_RULE *r)
{
    size_t next=0;
    if(yx_bool_keyword(p,"them"))return true;
    if(!yx_pattern_expression_symbol_token(p,'('))return false;
    for(;;) {
        yx_bool_skip_space(p);
        if(*p->at!='$')return false;
        const unsigned char *name=p->at++;
        while(isalnum(*p->at)||*p->at=='_')++p->at;
        size_t length=(size_t)(p->at-name);
        bool wildcard=*p->at=='*';
        if(wildcard)++p->at;
        size_t matched=0;
        for(size_t i=next;i<r->pattern_count;++i) {
            const char *id=r->patterns[i].identifier;
            if(!id||(wildcard?strncmp(id,(const char *)name,length):
                     (strlen(id)!=length||memcmp(id,name,length))))break;
            ++matched;
            if(!wildcard)break;
        }
        if(!matched)return false;
        next+=matched;
        yx_bool_skip_space(p);
        if(*p->at==','){++p->at;continue;}
        return yx_pattern_expression_symbol_token(p,')')&&next==r->pattern_count;
    }
}
static bool yx_pattern_set_loop_parse(const YRX_RULE *r,unsigned *loop)
{
    if(!r||!r->condition_text)return false;
    yx_bool_parser p={.at=(const unsigned char *)r->condition_text};
    if(!yx_bool_keyword(&p,"for"))return false;
    if(yx_bool_keyword(&p,"any"))*loop=0;
    else if(yx_bool_keyword(&p,"none"))*loop=1;
    else if(yx_bool_keyword(&p,"all"))*loop=2;
    else return false;
    if(!yx_bool_keyword(&p,"of")||!yx_pattern_set_loop_set(&p,r)||
       !yx_pattern_expression_symbol_token(&p,':')||!yx_pattern_expression_symbol_token(&p,'(')||
       !yx_pattern_expression_symbol_token(&p,'$')||!yx_pattern_expression_symbol_token(&p,')'))return false;
    yx_bool_skip_space(&p);return !*p.at;
}
static bool yx_pattern_set_parse(const char *source,bool *for_any,uint64_t *required)
{
    yx_bool_parser p={.at=(const unsigned char *)source};
    *for_any=yx_bool_keyword(&p,"for");
    if(*for_any) {
        if(!yx_bool_keyword(&p,"any"))return false;
    } else if(yx_bool_keyword(&p,"any")) {
        *required=UINT64_MAX;
    } else {
        yx_bool_skip_space(&p);*required=0;
        if(!isdigit(*p.at))return false;
        while(isdigit(*p.at)) {
            if(*required>UINT32_MAX/10)return false;
            *required=*required*10+(*p.at++-'0');
        }
    }
    if(!yx_bool_keyword(&p,"of")||!yx_bool_keyword(&p,"them"))return false;
    if(*for_any&&(!yx_pattern_expression_symbol_token(&p,':')||
       !yx_pattern_expression_symbol_token(&p,'(')||!yx_pattern_expression_symbol_token(&p,'$')||
       !yx_pattern_expression_symbol_token(&p,')')))return false;
    yx_bool_skip_space(&p);return !*p.at;
}
static yx_ser_result yx_encode_pattern_set(const YRX_RULES *rules,uint8_t **data,size_t *length)
{
    if(!rules||rules->rule_count!=1||rules->import_count||rules->global_count||rules->rules[0].is_global||
       !rules->rules[0].condition_text)return YX_SER_UNSUPPORTED;
    const YRX_RULE *r=&rules->rules[0];bool for_any;uint64_t required=0;unsigned loop=0;bool loop_form=false;
    if(!r->pattern_count||r->pattern_count>5)return YX_SER_UNSUPPORTED;
    if(!yx_pattern_set_parse(r->condition_text,&for_any,&required)) {
        if(!yx_pattern_set_loop_parse(r,&loop))return YX_SER_UNSUPPORTED;
        loop_form=true;
    }
    for(size_t i=0;i<r->pattern_count;++i)if(r->patterns[i].kind!=YX_PATTERN_TEXT||
        (r->patterns[i].modifiers&~YX_MOD_ASCII))return YX_SER_UNSUPPORTED;
    size_t mapping[5],unique[5];yx_text_pattern_mapping(r,mapping,unique);
    uint8_t *wasm=NULL;size_t wasm_length=0;uint64_t limits[5]={1,1,1,1,1};
    if(!(loop_form?yx_pattern_set_loop_wasm(mapping,r->pattern_count,loop,yx_integer_import_profile(),&wasm,&wasm_length):
         yx_pattern_set_wasm(mapping,r->pattern_count,for_any,required,yx_integer_import_profile(),&wasm,&wasm_length)))
        return YX_SER_NO_MEMORY;
    yx_ser_result result=yx_text_envelope_encode(r,wasm,wasm_length,limits,false,0,data,length);
    free(wasm);return result;
}
static yx_ser_result yx_decode_pattern_set(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *count)
{
    yx_ser_rule *decoded=NULL;size_t logical=0,mapping[5];const uint8_t *wasm;size_t wasm_length;
    if(!yx_text_envelope_read(data,length,&decoded,&logical,mapping,&wasm,&wasm_length))return YX_SER_UNSUPPORTED;
    for(unsigned kind=0;kind<6;++kind)for(uint64_t required=0;required<=(kind?0:logical);++required)
        for(uint8_t profile=0;profile<4;++profile) {
            uint8_t *canonical=NULL;size_t canonical_length=0;
            bool built=kind>=4?yx_pattern_set_loop_wasm(mapping,logical,kind-3,profile,&canonical,&canonical_length):
                kind==3?yx_pattern_set_none_wasm(mapping,logical,profile,&canonical,&canonical_length):
                yx_pattern_set_wasm(mapping,logical,kind==1,kind==2?UINT64_MAX:required,profile,&canonical,&canonical_length);
            bool valid=built&&
                canonical_length==wasm_length&&!memcmp(canonical,wasm,wasm_length);
            free(canonical);
            if(valid) {
                char source[96];
                if(kind==5)snprintf(source,sizeof(source),"for all of them : ( $ )");
                else if(kind==4)snprintf(source,sizeof(source),"for none of them : ( $ )");
                else if(kind==3)snprintf(source,sizeof(source),"none of them");
                else if(kind==2)snprintf(source,sizeof(source),"any of them");
                else if(kind==1)snprintf(source,sizeof(source),"for any of them : ( $ )");
                else snprintf(source,sizeof(source),"%llu of them",(unsigned long long)required);
                decoded->runtime_integer_condition=yx_copy_string(source);
                if(!decoded->runtime_integer_condition){yx_ser_rules_destroy(decoded,1);return YX_SER_NO_MEMORY;}
                decoded->runtime_integer_import_profile=profile;decoded->preserve_serialized_prefix=true;
                *rules=decoded;*count=1;return YX_SER_SUCCESS;
            }
        }
    yx_ser_rules_destroy(decoded,1);return YX_SER_UNSUPPORTED;
}
