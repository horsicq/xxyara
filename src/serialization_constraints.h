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

typedef struct yx_pattern_filesize_bounds {
    uint8_t lower_kind,upper_kind; int64_t lower,upper;
} yx_pattern_filesize_bounds;
static void yx_pattern_filesize_visit(const yx_integer_expr *tree,int index,
                                     yx_pattern_filesize_bounds *bounds,unsigned depth)
{
    if(index<0||depth>256)return;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->op==0xa0||n->op==0xd8) {
        yx_pattern_filesize_visit(tree,n->left,bounds,depth+1);
        if(n->right!=n->left)yx_pattern_filesize_visit(tree,n->right,bounds,depth+1);
        return;
    }
    if(n->op!=0x53&&n->op!=0x55&&n->op!=0x57&&n->op!=0x59)return;
    const yx_integer_expr_node *a=&YX_INTEGER_NODES(tree)[n->left],*b=&YX_INTEGER_NODES(tree)[n->right];
    bool reversed=b->op==0x23;const yx_integer_expr_node *constant=reversed?a:b;
    if((reversed?a:b)->constant==false||(reversed?b:a)->op!=0x23)return;
    bool lower=n->op==0x55||n->op==0x59;
    if(reversed)lower=!lower;
    bool inclusive=n->op==0x57||n->op==0x59;
    int64_t value=constant->value;
    if(constant->floating) {
        double rounded=lower?floor(constant->real):ceil(constant->real);
        if(!isfinite(rounded))return;
        inclusive=inclusive&&rounded==constant->real;
        value=rounded>=(double)INT64_MAX?INT64_MAX:rounded<=(double)INT64_MIN?INT64_MIN:(int64_t)rounded;
    }
    uint8_t kind=inclusive?0:1;
    uint8_t *old_kind=lower?&bounds->lower_kind:&bounds->upper_kind;
    int64_t *old=lower?&bounds->lower:&bounds->upper;
    if(*old_kind==2||(lower?value>*old:value<*old)||(value==*old&&kind==1)) {*old_kind=kind;*old=value;}
}
static bool yx_pattern_filesize_span(const uint8_t *data,size_t length,size_t *start,size_t *end,size_t *physical,unsigned *regex_mask)
{
    size_t prefix,wasm_start,wasm_size,rules;uint64_t n,id,kind;uint8_t flag;
    if(!yx_rule_expression_wasm_span(data,length,&prefix,&wasm_start,&wasm_size,&rules)||rules!=1)return false;
    yx_reader r={data,length,wasm_start+wasm_size,false,false};
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,1))return false;
    for(unsigned i=0;i<3;++i)if(!yx_get_uint(&r,&n))return false;
    if(!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i)if(!yx_get_uint(&r,&id))return false;
    if(!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i) {
        if(!yx_get_uint(&r,&id)||!yx_get_uint(&r,&kind)||kind>4)return false;
        if(kind==2){if(length-r.at<8)return false;r.at+=8;}
        else if(!yx_get_uint(&r,&id))return false;
    }
    if(!yx_get_uint(&r,&n)||!n||n>length-r.at)return false;
    *regex_mask=0;
    for(uint64_t i=0;i<n;++i) {
        uint64_t pattern_id;
        if(!yx_get_uint(&r,&pattern_id)||pattern_id%2||pattern_id/2>=5||
           !yx_get_uint(&r,&id)||!yx_get_uint(&r,&kind)||kind>2||!yx_get_uint(&r,&id))return false;
        if(kind)*regex_mask|=1u<<(pattern_id/2);
    }
    for(unsigned i=0;i<3;++i)if(!yx_get_uint(&r,&id))return false;
    if(!yx_get_uint(&r,&n)||!n||n>5)return false;
    *physical=(size_t)n;
    if(!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i) {
        if(!yx_get_uint(&r,&id)||!yx_get_uint(&r,&kind)||kind>11)return false;
        if(kind==0) {
            if(!yx_get_uint(&r,&id)||!yx_get_u8(&r,&flag)||flag>1||(flag&&!yx_get_uint(&r,&id)))return false;
        } else if(kind==1||kind==10||kind==11) {
            if(!yx_get_uint(&r,&id)||!yx_get_uint(&r,&id))return false;
        } else if(kind==2||kind==3||kind==7||kind==8||kind==9) {
            if(!yx_get_uint(&r,&id))return false;
        }
        if(kind==3||kind==6) {
            uint64_t gap;
            if(!yx_get_uint(&r,&id)||!yx_get_uint(&r,&gap)||gap>1||!yx_get_uint(&r,&id)||
               (gap==0&&!yx_get_uint(&r,&id)))return false;
        }
        if(!yx_get_uint(&r,&id))return false;
    }
    *start=r.at;
    if(!yx_get_uint(&r,&n)||n>*physical)return false;
    for(uint64_t i=0;i<n;++i) {
        if(!yx_get_uint(&r,&id)||id%2||id/2>=*physical)return false;
        for(unsigned j=0;j<2;++j)if(!yx_get_uint(&r,&kind)||kind>2||(kind!=0&&!yx_get_uint(&r,&id)))return false;
    }
    *end=r.at;return true;
}
static bool yx_pattern_filesize_rewrite(const yx_integer_expr *tree,int root,
    const uint8_t *data,size_t length,bool strip,uint8_t **out,size_t *out_length)
{
    size_t start,end,physical;unsigned regex_mask;yx_writer expected={0},w={0};bool ok=false;
    yx_pattern_filesize_bounds bounds={2,2,0,0};
    yx_pattern_filesize_visit(tree,root,&bounds,0);
    if(!yx_pattern_filesize_span(data,length,&start,&end,&physical,&regex_mask))return false;
    bool bounded=bounds.lower_kind!=2||bounds.upper_kind!=2;
    size_t entries=0;
    for(size_t i=0;i<physical;++i)if(regex_mask&(1u<<i))++entries;
    if(!yx_put_uint(&expected,bounded?entries:0))goto done;
    for(size_t i=0;bounded&&i<physical;++i) {
        if(!(regex_mask&(1u<<i)))continue;
        if(!yx_put_uint(&expected,i*2)||!yx_put_uint(&expected,bounds.lower_kind==2?0:bounds.lower_kind+1)||
           (bounds.lower_kind!=2&&!yx_put_signed(&expected,bounds.lower))||
           !yx_put_uint(&expected,bounds.upper_kind==2?0:bounds.upper_kind+1)||
           (bounds.upper_kind!=2&&!yx_put_signed(&expected,bounds.upper)))goto done;
    }
    if(strip) {
        if(expected.used!=end-start||memcmp(expected.data,data+start,expected.used))goto done;
    } else if(end-start!=1||data[start])goto done;
    if(!yx_put_bytes(&w,data,start)||(strip?!yx_put_u8(&w,0):!yx_put_bytes(&w,expected.data,expected.used))||
       !yx_put_bytes(&w,data+end,length-end))goto done;
    *out=w.data;*out_length=w.used;w.data=NULL;ok=true;
done:free(expected.data);free(w.data);return ok;
}

/* Locate the serialized match-limit vector by walking the bounded archive
 * fields. Rewriting this vector preserves the selected physical atoms and
 * verifier program for non-text patterns. */
static bool yx_pattern_limits_rewrite(const uint8_t *data,size_t length,
    const uint64_t limits[5],bool strip,uint8_t **out,size_t *out_length)
{
    size_t start,end,physical;unsigned regex_mask;uint64_t n,id;uint8_t flag;
    if(!yx_pattern_filesize_span(data,length,&start,&end,&physical,&regex_mask))return false;
    yx_reader r={data,length,end,false,false};
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_get_uint(&r,&n)||n>length-r.at)return false;
    for(uint64_t i=0;i<n;++i) {
        if(!yx_get_uint(&r,&id)||!yx_get_uint(&r,&id)||id>length-r.at)return false;
        r.at+=(size_t)id;
        if(!yx_get_u8(&r,&flag)||flag>1||!yx_get_uint(&r,&id))return false;
        for(unsigned j=0;j<2;++j)if(!yx_get_u8(&r,&flag)||flag>1||(flag&&!yx_get_uint(&r,&id)))return false;
    }
    for(unsigned i=0;i<3;++i) {
        if(!yx_get_uint(&r,&n)||n>length-r.at)return false;
        r.at+=(size_t)n;
    }
    if(!yx_expect_uint(&r,0)||!yx_expect_uint(&r,0)||!yx_expect_uint(&r,physical))return false;
    start=r.at;
    for(size_t i=0;i<physical;++i) {
        if(!yx_get_u8(&r,&flag)||flag>1)return false;
        uint64_t actual=0;
        if(flag&&(!yx_get_uint(&r,&actual)||!actual))return false;
        if(actual!=(strip?limits[i]:1))return false;
    }
    end=r.at;
    if(!yx_expect_uint(&r,0)||r.at!=length)return false;
    yx_writer w={0};
    if(!yx_put_bytes(&w,data,start))goto fail;
    for(size_t i=0;i<physical;++i) {
        uint64_t value=strip?1:limits[i];
        if(!yx_put_u8(&w,value!=0)||(value&&!yx_put_uint(&w,value)))goto fail;
    }
    if(!yx_put_bytes(&w,data+end,length-end))goto fail;
    *out=w.data;*out_length=w.used;return true;
fail:free(w.data);return false;
}
