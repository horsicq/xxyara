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


#ifndef YX_SERIALIZATION_HEADERS_H
#define YX_SERIALIZATION_HEADERS_H
/* Sparse byte constraints preserve conflicts beyond the contiguous prefix. */
typedef struct yx_header_piece {
    uint64_t offset;
    uint8_t *bytes;
    size_t length;
} yx_header_piece;
typedef struct yx_header_collection {
    yx_header_piece *pieces;
    size_t count;
    bool impossible;
} yx_header_collection;
static inline void yx_header_collection_destroy(yx_header_collection *c)
{
    for(size_t i=0;i<c->count;++i)free(c->pieces[i].bytes);
    free(c->pieces);memset(c,0,sizeof(*c));
}
static inline bool yx_header_add(yx_header_collection *c,uint64_t offset,const uint8_t *bytes,size_t length)
{
    if(c->impossible||!length)return true;
    if(length>UINT64_MAX-offset)return false;
    for(size_t i=0;i<c->count;++i) {
        const yx_header_piece *p=&c->pieces[i];
        uint64_t start=offset>p->offset?offset:p->offset;
        uint64_t end=offset+length<p->offset+p->length?offset+length:p->offset+p->length;
        if(start<end&&memcmp(bytes+(size_t)(start-offset),p->bytes+(size_t)(start-p->offset),(size_t)(end-start))) {
            c->impossible=true;return true;
        }
    }
    if(c->count==SIZE_MAX/sizeof(*c->pieces))return false;
    yx_header_piece *grown=realloc(c->pieces,(c->count+1)*sizeof(*grown));
    if(!grown)return false;
    c->pieces=grown;uint8_t *copy=malloc(length);
    if(!copy)return false;
    memcpy(copy,bytes,length);c->pieces[c->count++]=(yx_header_piece){offset,copy,length};return true;
}
static int yx_header_order(const void *left,const void *right)
{
    const yx_header_piece *a=left,*b=right;
    return a->offset<b->offset?-1:a->offset>b->offset?1:0;
}
static inline bool yx_header_finish(yx_header_collection *c,yx_writer *storage,yx_physical_header *header)
{
    *header=(yx_physical_header){0};
    if(c->impossible){header->kind=1;return true;}
    if(c->count>1)qsort(c->pieces,c->count,sizeof(*c->pieces),yx_header_order);
    for(size_t i=0;i<c->count;++i) {
        const yx_header_piece *p=&c->pieces[i];
        if(p->offset>storage->used)break;
        size_t skip=storage->used-(size_t)p->offset;
        if(skip<p->length&&!yx_put_bytes(storage,p->bytes+skip,p->length-skip))return false;
    }
    if(storage->used)*header=(yx_physical_header){2,storage->data,storage->used};
    return true;
}
static inline bool yx_header_pattern_bytes(const YRX_PATTERN *pattern,yx_writer *bytes)
{
    if(!pattern||(pattern->modifiers&(YX_MOD_WIDE|YX_MOD_NOCASE|YX_MOD_XOR|YX_MOD_BASE64|YX_MOD_BASE64WIDE)))return true;
    if(pattern->kind==YX_PATTERN_TEXT)return yx_put_bytes(bytes,pattern->bytes,pattern->length);
    if(pattern->kind==YX_PATTERN_HEX) {
        if(pattern->hex_has_jump||!pattern->mask)return true;
        for(size_t i=0;i<pattern->length;++i)if(pattern->mask[i]!=255)return true;
        return yx_put_bytes(bytes,pattern->bytes,pattern->length);
    }
    if(!pattern->regexp)return true;
    yx_tr_parser parser={.text=(const uint8_t *)pattern->regexp,.length=strlen(pattern->regexp)};
    yx_tr_node *root=yx_tr_expression(&parser),*node=root;bool ok=!parser.oom;
    if(node&&!parser.failed&&parser.at==parser.length&&node->kind==YX_TR_LITERAL)
        ok=yx_put_bytes(bytes,node->bytes,node->length);
    yx_tr_destroy(root);return ok;
}
static inline bool yx_header_integer_visit(const yx_integer_expr *tree,int index,
    const YRX_PATTERN *const *patterns,size_t pattern_count,
    const yx_physical_header *previous,size_t previous_count,yx_header_collection *c,unsigned depth)
{
    if(index<0||depth>256)return true;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->op==0xa0||n->op==0xd8)
        return yx_header_integer_visit(tree,n->left,patterns,pattern_count,previous,previous_count,c,depth+1)&&
            (n->right==n->left||yx_header_integer_visit(tree,n->right,patterns,pattern_count,previous,previous_count,c,depth+1));
    if(n->op==0xd0) {
        if(n->value<0||(uint64_t)n->value>=previous_count)return false;
        const yx_physical_header *h=&previous[n->value];
        if(h->kind==1)c->impossible=true;
        return h->kind!=2||yx_header_add(c,0,h->bytes,h->length);
    }
    if(n->op==0xd5&&n->value>=0&&(uint64_t)n->value<pattern_count&&n->left>=0&&
       YX_INTEGER_NODES(tree)[n->left].constant&&!YX_INTEGER_NODES(tree)[n->left].floating&&!YX_INTEGER_NODES(tree)[n->left].value) {
        yx_writer bytes={0};bool ok=yx_header_pattern_bytes(patterns[n->value],&bytes)&&yx_header_add(c,0,bytes.data,bytes.used);
        free(bytes.data);return ok;
    }
    if(n->op!=0x51||n->left<0||n->right<0)return true;
    const yx_integer_expr_node *a=&YX_INTEGER_NODES(tree)[n->left],*b=&YX_INTEGER_NODES(tree)[n->right];
    if(a->constant){const yx_integer_expr_node *swap=a;a=b;b=swap;}
    if(a->op<0xb0||a->op>0xb5||a->left<0||!b->constant||b->floating)return true;
    const yx_integer_expr_node *offset=&YX_INTEGER_NODES(tree)[a->left];
    if(!offset->constant||offset->floating||offset->value<0)return true;
    size_t width=(size_t)1<<((a->op-0xb0)%3);uint8_t bytes[4];uint64_t value=(uint64_t)b->value;
    for(size_t i=0;i<width;++i)bytes[i]=(uint8_t)(value>>(8*i));
    return yx_header_add(c,(uint64_t)offset->value,bytes,width);
}
/* Upstream anchoring (`anchor_patterns`): a pattern is anchored at K when
 * every use is `$a at K` with a constant K. An unanchored `$a` is ignored
 * when `$a at K` is also required through top-level `and`s; any other use
 * (`#a`, `@a`, `!a`, `in`, a non-constant offset, two offsets) prevents it. */
static void yx_anchor_top_level(const yx_integer_expr *tree,int index,int64_t pattern,
    int64_t *offset,unsigned depth)
{
    if(index<0||depth>4096)return;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    /* find_top_level_anchors (ir/mod.rs) descends `and` and the body of a
     * `with`; a folded operator is a constant and has no operands. */
    while(n->op==0xc0&&!n->constant) {
        if(n->right<0||++depth>4096)return;
        n=&YX_INTEGER_NODES(tree)[n->right];
    }
    if(n->constant)return;
    if(n->op==0xa0||n->op==0xd8) {
        yx_anchor_top_level(tree,n->left,pattern,offset,depth+1);
        if(n->right!=n->left)yx_anchor_top_level(tree,n->right,pattern,offset,depth+1);
    } else if(n->op==0xd5&&n->value==pattern&&n->left>=0&&
              YX_INTEGER_NODES(tree)[n->left].constant&&!YX_INTEGER_NODES(tree)[n->left].floating&&
              YX_INTEGER_NODES(tree)[n->left].value>=0)
        *offset=YX_INTEGER_NODES(tree)[n->left].value;
}
/* anchor_patterns: an unanchored `<quantifier> of <set>` makes each pattern
 * of the set without a top-level anchor non-anchorable. The trees that hold
 * set nodes (0xda) are pattern-expression trees, whose extension starts with
 * the yx_pattern_expression_context (yx_multi_pattern_context too). */
static const yx_pattern_of_set *yx_anchor_of_set(const yx_integer_expr *tree,const yx_integer_expr_node *n)
{
    const yx_pattern_expression_context *c=tree->extension;
    if(n->op!=0xda||!c||n->value<0||(uint64_t)(n->value>>4)>=c->of_set_count)return NULL;
    return &c->of_sets[n->value>>4];
}
static bool yx_anchor_uses(const yx_integer_expr *tree,int index,int64_t pattern,bool top,
    int64_t *anchor,bool *blocked,unsigned depth)
{
    if(index<0)return true;
    if(depth>4096)return false;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    /* anchor_patterns walks the folded IR: a folded `and` / `or` uses no
     * pattern. */
    if(n->constant&&(n->op==0xa0||n->op==0xa1||n->op==0xa2))return true;
    if(n->op>=0xd1&&n->op<=0xd7&&n->value==pattern) {
        if(n->op==0xd5) {
            const yx_integer_expr_node *at=n->left>=0?&YX_INTEGER_NODES(tree)[n->left]:NULL;
            if(!at||!at->constant||at->floating||at->value<0)*blocked=true;
            else if(*anchor>=0&&*anchor!=at->value)*blocked=true;
            else *anchor=at->value;
        } else if(n->op!=0xd1||!top)*blocked=true;
    }
    if(n->op==0xda&&!top) {
        const yx_pattern_of_set *set=yx_anchor_of_set(tree,n);
        for(uint8_t i=0;set&&i<set->count;++i)
            if(pattern>=0&&(uint64_t)pattern>=set->start[i]&&(uint64_t)pattern<=set->end[i])*blocked=true;
    }
    if(!yx_anchor_uses(tree,n->left,pattern,top,anchor,blocked,depth+1))return false;
    if(n->right!=n->left&&!yx_anchor_uses(tree,n->right,pattern,top,anchor,blocked,depth+1))return false;
    return n->extra<0||n->extra==n->left||n->extra==n->right||
           yx_anchor_uses(tree,n->extra,pattern,top,anchor,blocked,depth+1);
}
/* anchor_patterns (ast2ir.rs) walks the folded IR: a pattern whose every
 * use sits under a folded `and` / `or` / `not` is neither anchored nor
 * NonAnchorable. marks[p] (p < count): 1 when the tree names the pattern,
 * 2 more when the walk reaches it. One pass over the nodes, one walk with
 * an explicit stack (left-nested chains are long). */
static bool yx_pattern_ir_marks(const yx_integer_expr *tree,int root,uint8_t *marks,size_t count)
{
    size_t used=0;int *stack;uint8_t *seen;
    memset(marks,0,count);
    for(size_t n=0;n<tree->count;++n) {
        const yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[n];
        if(node->op>=0xd1&&node->op<=0xd7&&node->value>=0&&(uint64_t)node->value<count)marks[node->value]|=1;
    }
    if(root<0||(size_t)root>=tree->count)return true;
    stack=malloc(tree->count*sizeof(*stack));seen=calloc(tree->count,1);
    if(!stack||!seen){free(stack);free(seen);return false;}
    stack[used++]=root;seen[root]=1;
    while(used) {
        const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[stack[--used]];
        int next[3];
        if(n->constant&&(n->op==0xa0||n->op==0xa1||n->op==0xa2))continue;
        if(n->op>=0xd1&&n->op<=0xd7&&n->value>=0&&(uint64_t)n->value<count)marks[n->value]|=2;
        next[0]=n->left;next[1]=n->right;next[2]=n->extra;
        for(int k=0;k<3;++k)
            if(next[k]>=0&&(size_t)next[k]<tree->count&&!seen[next[k]]){seen[next[k]]=1;stack[used++]=next[k];}
    }
    free(stack);free(seen);return true;
}
/* Every pattern of a rule, pattern sets, counts, offsets and anchors
 * included: the condition's own anchor_patterns port (condition.c) leaves a
 * pattern neither anchored nor NonAnchorable exactly when the walk does not
 * reach it. Asked only when the tree has a folded `and` / `or` / `not` with
 * operands or does not reach some pattern directly (a set, or an operand a
 * one-operand root dropped); unmarked[] is all false otherwise. A condition
 * that does not compile or fold here is YX_SER_UNSUPPORTED (the archive
 * would be a guess), a failed allocation YX_SER_NO_MEMORY. */
static yx_ser_result yx_rule_unmarked_patterns(const YRX_RULES *rules,const YRX_RULE *r,const yx_integer_expr *tree,
    const uint8_t *marks,bool *unmarked)
{
    bool folded=false;yx_condition *condition;const char **names;yx_ser_result status=YX_SER_SUCCESS;
    for(size_t j=0;j<r->pattern_count;++j)unmarked[j]=false;
    for(size_t n=0;!folded&&n<tree->count;++n) {
        const yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[n];
        folded=node->constant&&(node->op==0xa0||node->op==0xa1||node->op==0xa2)&&node->left>=0;
    }
    for(size_t j=0;!folded&&j<r->pattern_count;++j)folded=!(marks[j]&2);
    if(!folded||!r->pattern_count)return YX_SER_SUCCESS;
    if(!r->condition_text||!(condition=yx_condition_compile(r->condition_text,NULL,0)))return YX_SER_UNSUPPORTED;
    names=malloc(r->pattern_count*sizeof(*names));
    if(!names)status=YX_SER_NO_MEMORY;
    else {
        for(size_t j=0;j<r->pattern_count;++j)names[j]=r->patterns[j].identifier;
        yx_condition_bind_pattern_sets(condition,names,r->pattern_count);
        if(!yx_condition_fold_modules(condition,(const char *const *)rules->imports,rules->import_count,
                                      rules->globals,rules->global_count,NULL,0))status=YX_SER_UNSUPPORTED;
        else for(size_t j=0;j<r->pattern_count;++j) {
            size_t at=0;
            unmarked[j]=!yx_condition_pattern_fixed_at(condition,names[j],&at)&&
                !yx_condition_pattern_nonanchorable(condition,names[j],false);
        }
        free((void *)names);
    }
    yx_condition_destroy(condition);
    if(status!=YX_SER_SUCCESS)for(size_t j=0;j<r->pattern_count;++j)unmarked[j]=false;
    return status;
}
/* anchor_patterns for every pattern p < count at once: yx_anchor_top_level
 * and yx_anchor_uses with per-pattern state, one walk each. anchored[p] and
 * offset[p] are what yx_pattern_anchor_offset gives for p; false only when
 * out of memory (a tree deeper than the walks anchors nothing, as there). */
static void yx_anchor_top_level_all(const yx_integer_expr *tree,int index,size_t count,int64_t *top,unsigned depth)
{
    if(index<0||depth>4096)return;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    while(n->op==0xc0&&!n->constant) {
        if(n->right<0||++depth>4096)return;
        n=&YX_INTEGER_NODES(tree)[n->right];
    }
    if(n->constant)return;
    if(n->op==0xa0||n->op==0xd8) {
        yx_anchor_top_level_all(tree,n->left,count,top,depth+1);
        if(n->right!=n->left)yx_anchor_top_level_all(tree,n->right,count,top,depth+1);
    } else if(n->op==0xd5&&n->value>=0&&(uint64_t)n->value<count&&n->left>=0&&
              YX_INTEGER_NODES(tree)[n->left].constant&&!YX_INTEGER_NODES(tree)[n->left].floating&&
              YX_INTEGER_NODES(tree)[n->left].value>=0)
        top[n->value]=YX_INTEGER_NODES(tree)[n->left].value;
}
static bool yx_anchor_uses_all(const yx_integer_expr *tree,int index,size_t count,const int64_t *top,
    int64_t *anchor,bool *blocked,size_t *cover,unsigned depth)
{
    if(index<0)return true;
    if(depth>4096)return false;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->constant&&(n->op==0xa0||n->op==0xa1||n->op==0xa2))return true;
    if(n->op>=0xd1&&n->op<=0xd7&&n->value>=0&&(uint64_t)n->value<count) {
        size_t p=(size_t)n->value;
        if(n->op==0xd5) {
            const yx_integer_expr_node *at=n->left>=0?&YX_INTEGER_NODES(tree)[n->left]:NULL;
            if(!at||!at->constant||at->floating||at->value<0)blocked[p]=true;
            else if(anchor[p]>=0&&anchor[p]!=at->value)blocked[p]=true;
            else anchor[p]=at->value;
        } else if(n->op!=0xd1||top[p]<0)blocked[p]=true;
    }
    /* A set's ranges go to a difference array (cover[count + 1]) that the
     * caller resolves once: not one pass over the set per set expression. */
    if(n->op==0xda) {
        const yx_pattern_of_set *set=yx_anchor_of_set(tree,n);
        for(uint8_t i=0;set&&i<set->count;++i)
            if(set->start[i]<count&&set->start[i]<=set->end[i]) {
                ++cover[set->start[i]];
                --cover[set->end[i]<count?set->end[i]+1:count];
            }
    }
    if(!yx_anchor_uses_all(tree,n->left,count,top,anchor,blocked,cover,depth+1))return false;
    if(n->right!=n->left&&!yx_anchor_uses_all(tree,n->right,count,top,anchor,blocked,cover,depth+1))return false;
    return n->extra<0||n->extra==n->left||n->extra==n->right||
           yx_anchor_uses_all(tree,n->extra,count,top,anchor,blocked,cover,depth+1);
}
static bool yx_pattern_anchor_offsets(const yx_integer_expr *tree,int root,size_t count,bool *anchored,uint64_t *offset)
{
    int64_t *top=malloc((count?count:1)*sizeof(*top)),*anchor=malloc((count?count:1)*sizeof(*anchor));
    bool *blocked=calloc(count?count:1,sizeof(*blocked)),walked;
    size_t *cover=calloc(count+1,sizeof(*cover)),covered=0;
    if(!top||!anchor||!blocked||!cover){free(top);free(anchor);free(blocked);free(cover);return false;}
    for(size_t p=0;p<count;++p){top[p]=-1;anchor[p]=-1;anchored[p]=false;offset[p]=0;}
    yx_anchor_top_level_all(tree,root,count,top,0);
    walked=yx_anchor_uses_all(tree,root,count,top,anchor,blocked,cover,0);
    /* Unsigned wrap-around sums the +1/-1 entries exactly. */
    for(size_t p=0;p<count;++p){covered+=cover[p];if(covered&&top[p]<0)blocked[p]=true;}
    for(size_t p=0;walked&&p<count;++p)
        if(!blocked[p]&&anchor[p]>=0){anchored[p]=true;offset[p]=(uint64_t)anchor[p];}
    free(top);free(anchor);free(blocked);free(cover);return true;
}
static bool yx_pattern_anchor_offset(const yx_integer_expr *tree,int root,int64_t pattern,
    uint64_t *offset)
{
    int64_t top=-1,anchor=-1;bool blocked=false;
    yx_anchor_top_level(tree,root,pattern,&top,0);
    if(!yx_anchor_uses(tree,root,pattern,top>=0,&anchor,&blocked,0)||blocked||anchor<0)return false;
    *offset=(uint64_t)anchor;return true;
}
static inline bool yx_header_integer(const yx_integer_expr *tree,int root,
    const YRX_PATTERN *const *patterns,size_t pattern_count,
    const yx_physical_header *previous,size_t previous_count,yx_writer *storage,yx_physical_header *header)
{
    yx_header_collection c={0};bool ok=yx_header_integer_visit(tree,root,patterns,pattern_count,previous,previous_count,&c,0)&&
        yx_header_finish(&c,storage,header);
    yx_header_collection_destroy(&c);return ok;
}
/* Writer: adds what upstream derives from a single rule's condition for its
 * lone regexp/hex pattern: the header constraint and, when every frame is a
 * plain literal, the anchor (anchored frames have no atoms). Text patterns
 * use their own envelope codec. Returns YX_SER_UNSUPPORTED when nothing
 * applies, leaving the archive unchanged. */
static yx_ser_result yx_constrain_single_pattern_archive(uint8_t **data,size_t *length,
    const YRX_PATTERN *pattern,const yx_integer_expr *tree,int root)
{
    uint64_t offset=0;yx_writer storage={0};yx_physical_header header={0};
    const YRX_PATTERN *patterns[1]={pattern};yx_physical_archive a;
    uint8_t *out=NULL;size_t out_length=0;yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!pattern||root<0)return YX_SER_UNSUPPORTED;
    bool anchored=yx_pattern_anchor_offset(tree,root,0,&offset);
    /* Upstream assigns header constraints to regexp and hex patterns only. */
    if(pattern->kind!=YX_PATTERN_TEXT&&
       !yx_header_integer(tree,root,patterns,1,NULL,0,&storage,&header)){free(storage.data);return YX_SER_NO_MEMORY;}
    if(!yx_physical_read(*data,*length,&a)){free(storage.data);return YX_SER_UNSUPPORTED;}
    if(a.logical!=1||a.physical!=1||!a.frame_count||a.anchored_count||a.headers[0].kind)goto done;
    /* c_literal_pattern never anchors a nocase text pattern; a nocase
     * regexp literal (c_alternation_literal) is anchored. */
    for(size_t i=0;anchored&&i<a.frame_count;++i)
        if(a.frames[i].frame.variant!=0||((a.frames[i].frame.flags&2)&&pattern->kind==YX_PATTERN_TEXT))anchored=false;
    if(!anchored&&!header.kind)goto done;
    if(anchored) {
        for(size_t i=0;i<a.frame_count;++i) {
            a.frames[i].anchored=true;a.frames[i].offset=offset;a.anchored[i]=i;
        }
        a.anchored_count=a.frame_count;a.atom_count=0;
    }
    a.headers[0]=header;
    status=yx_physical_write(&a,&out,&out_length);
    if(status==YX_SER_SUCCESS){free(*data);*data=out;*length=out_length;out=NULL;}
done:
    free(out);free(storage.data);yx_physical_destroy(&a);return status;
}
/* Writer: upstream anchoring for a rule with several patterns. Each
 * pattern whose every use is `at K` with a constant K, and whose frames are
 * plain literals, is anchored at K; anchored frames have no atoms, so the
 * Aho-Corasick automaton covers only the others. `tree` refers to physical
 * pattern indexes; `rule` gives the declared pattern kinds. Returns
 * YX_SER_UNSUPPORTED when nothing changes, leaving the archive unchanged. */
static yx_ser_result yx_constrain_pattern_anchors(uint8_t **data,size_t *length,
    const yx_integer_expr *tree,int root,const YRX_RULE *rule)
{
    yx_physical_archive a;uint8_t *out=NULL;size_t out_length=0,anchored=0,kept=0;
    yx_ser_result status=YX_SER_UNSUPPORTED;yx_writer storage={0};
    YRX_PATTERN *literals=NULL;const YRX_PATTERN **patterns=NULL;
    /* Per pattern: its frame count, last frame, and whether all its frames
     * are plain (one pass over the frames, not one per pattern). */
    size_t *frame_counts=NULL,*last_frames=NULL,*first_frames=NULL,*next_frames=NULL;bool *not_plain=NULL,*text_patterns=NULL;
    /* Every pattern's anchor from one walk (yx_pattern_anchor_offsets). */
    bool *anchors=NULL;uint64_t *offsets=NULL;
    if(root<0||!yx_physical_read(*data,*length,&a))return YX_SER_UNSUPPORTED;
    if(a.anchored_count||a.logical<2)goto done;
    /* Upstream assigns the rule's header constraint to its regexp and hex
     * patterns; a lone plain literal frame contributes its bytes. */
    literals=calloc(a.physical,sizeof(*literals));patterns=calloc(a.physical,sizeof(*patterns));
    frame_counts=calloc(a.physical,sizeof(*frame_counts));last_frames=calloc(a.physical,sizeof(*last_frames));
    not_plain=calloc(a.physical,sizeof(*not_plain));
    /* Each pattern's frames as a list in frame order (index + 1, 0 ends). */
    first_frames=calloc(a.physical,sizeof(*first_frames));
    next_frames=calloc(a.frame_count?a.frame_count:1,sizeof(*next_frames));
    if(!literals||!patterns||!frame_counts||!last_frames||!not_plain||!first_frames||!next_frames)
        {status=YX_SER_NO_MEMORY;goto done;}
    /* c_literal_pattern never anchors a nocase text pattern; a nocase
     * regexp literal (c_alternation_literal) is anchored. */
    text_patterns=calloc(a.physical?a.physical:1,sizeof(*text_patterns));
    if(!text_patterns){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<a.logical;++i)if(a.mapping[i]<a.physical&&a.kinds[i]==YX_PATTERN_TEXT)text_patterns[a.mapping[i]]=true;
    for(size_t i=0;i<a.frame_count;++i) {
        size_t p=a.frames[i].pattern;
        if(p>=a.physical)continue;
        if(frame_counts[p])next_frames[last_frames[p]]=i+1;else first_frames[p]=i+1;
        ++frame_counts[p];last_frames[p]=i;
        if(a.frames[i].frame.variant!=0||((a.frames[i].frame.flags&2)&&text_patterns[p]))not_plain[p]=true;
    }
    for(size_t p=0;p<a.physical;++p) {
        size_t frames=frame_counts[p],last=last_frames[p];
        if(frames==1&&a.frames[last].frame.variant==0&&!(a.frames[last].frame.flags&3)) {
            literals[p].kind=YX_PATTERN_TEXT;literals[p].bytes=(uint8_t *)a.frames[last].frame.literal;
            literals[p].length=a.frames[last].frame.literal_length;patterns[p]=&literals[p];
        }
        if(a.headers[p].kind)goto done;
    }
    {
        yx_physical_header header={0};
        if(!yx_header_integer(tree,root,patterns,a.physical,NULL,0,&storage,&header)){status=YX_SER_NO_MEMORY;goto done;}
        /* The declared kind decides; literal regexps encoded as text are
         * marked in yx_literal_regex_mask. */
        if(header.kind&&rule&&rule->pattern_count==a.logical)
            for(size_t i=0;i<a.logical;++i)
                if(rule->patterns[i].kind!=YX_PATTERN_TEXT||(i<8&&(yx_literal_regex_mask>>i&1u))) {
                    a.headers[a.mapping[i]]=header;++anchored;
                }
    }
    anchors=malloc((a.physical?a.physical:1)*sizeof(*anchors));
    offsets=malloc((a.physical?a.physical:1)*sizeof(*offsets));
    if(!anchors||!offsets||!yx_pattern_anchor_offsets(tree,root,a.physical,anchors,offsets))
        {status=YX_SER_NO_MEMORY;goto done;}
    for(size_t p=0;p<a.physical;++p) {
        uint64_t offset=offsets[p];bool plain=!not_plain[p],any=frame_counts[p]!=0;
        if(!anchors[p])continue;
        if(!any||!plain)continue;
        for(size_t i=first_frames[p];i;i=next_frames[i-1])
            {a.frames[i-1].anchored=true;a.frames[i-1].offset=offset;}
        ++anchored;
    }
    if(!anchored)goto done;
    for(size_t i=0;i<a.frame_count;++i)
        if(a.frames[i].anchored)a.anchored[a.anchored_count++]=i;
    for(size_t i=0;i<a.atom_count;++i)
        if(!a.frames[a.atoms[i].frame].anchored)a.atoms[kept++]=a.atoms[i];
    a.atom_count=kept;
    status=yx_physical_write(&a,&out,&out_length);
    if(status==YX_SER_SUCCESS){free(*data);*data=out;*length=out_length;out=NULL;}
done:
    free(out);free(storage.data);free(literals);free(patterns);
    free(frame_counts);free(last_frames);free(first_frames);free(next_frames);free(not_plain);free(text_patterns);
    free(anchors);free(offsets);yx_physical_destroy(&a);return status;
}
/* Reader: validates the anchor and header against the condition, then
 * restores the plain form (best literal atom per frame, no header) that the
 * base codec decodes. The header is an optimization of the same condition;
 * when a frame is a literal it may contribute its bytes at offset 0. */
static yx_ser_result yx_unconstrain_single_pattern_archive(const uint8_t *data,size_t length,
    const yx_integer_expr *tree,int root,uint8_t **out,size_t *out_length)
{
    yx_physical_archive a;yx_ser_result status=YX_SER_UNSUPPORTED;uint64_t offset=0;
    if(root<0||!yx_physical_read(data,length,&a))return YX_SER_UNSUPPORTED;
    if(a.logical!=1||a.physical!=1||!a.frame_count||
       (!a.anchored_count&&!a.headers[0].kind))goto done;
    /* Plain `$a at N` text archives belong to the text envelope codec. */
    if(a.kinds[0]==YX_PATTERN_TEXT&&a.frame_count==1&&!a.frames[0].frame.flags&&
       YX_INTEGER_NODES(tree)[root].op==0xd5)goto done;
    if(a.anchored_count) {
        if(a.anchored_count!=a.frame_count||a.atom_count||
           !yx_pattern_anchor_offset(tree,root,0,&offset))goto done;
        for(size_t i=0;i<a.frame_count;++i)
            if(a.frames[i].frame.variant!=0||!a.frames[i].anchored||a.frames[i].offset!=offset||
               ((a.frames[i].frame.flags&2)&&a.kinds[0]==YX_PATTERN_TEXT)||!a.frames[i].frame.literal_length)goto done;
    }
    if(a.headers[0].kind) {
        yx_writer plain={0},literal={0};yx_physical_header without={0},with={0};bool ok;
        YRX_PATTERN bytes={0};const YRX_PATTERN *none[1]={NULL},*lit[1]={&bytes};
        ok=yx_header_integer(tree,root,none,1,NULL,0,&plain,&without);
        if(ok&&a.frame_count==1&&a.frames[0].frame.variant==0) {
            bytes.kind=YX_PATTERN_TEXT;bytes.bytes=(uint8_t *)a.frames[0].frame.literal;
            bytes.length=a.frames[0].frame.literal_length;
            ok=yx_header_integer(tree,root,lit,1,NULL,0,&literal,&with);
        }
        bool match=ok&&(yx_physical_header_equal(&without,&a.headers[0])||
                        (with.kind&&yx_physical_header_equal(&with,&a.headers[0])));
        free(plain.data);free(literal.data);
        if(!ok){status=YX_SER_NO_MEMORY;goto done;}
        if(!match)goto done;
    }
    if(a.anchored_count) {
        free(a.atoms);a.atoms=calloc(a.frame_count,sizeof(*a.atoms));
        if(!a.atoms){status=YX_SER_NO_MEMORY;goto done;}
        for(size_t i=0;i<a.frame_count;++i) {
            const yx_chain_frame *f=&a.frames[i].frame;size_t at=0,width=0;
            if(!yx_best_text_atom(f->literal,f->literal_length,&at,&width)||
               width>sizeof(a.atoms[i].atom.bytes))goto done;
            a.atoms[i].frame=i;memcpy(a.atoms[i].atom.bytes,f->literal+at,width);
            a.atoms[i].atom.length=width;a.atoms[i].atom.exact=width==f->literal_length;
            a.atoms[i].atom.backtrack=(uint16_t)at;
            a.frames[i].anchored=false;a.frames[i].offset=0;
        }
        a.atom_count=a.frame_count;a.anchored_count=0;
    }
    a.headers[0]=(yx_physical_header){0};
    status=yx_physical_write(&a,out,out_length);
done:
    yx_physical_destroy(&a);return status;
}
/* Wraps each `$p at K` (constant K) that find_top_level_anchors reaches
 * (`and`, a one-operand `and`, the body of a `with`) in a one-operand `or`. */
static bool yx_unanchor_top_level_terms(yx_integer_expr *tree,int index,int parent,int64_t pattern,int *root,
    unsigned depth)
{
    const yx_integer_expr_node *n;
    if(index<0||depth>4096)return index<0;
    n=&YX_INTEGER_NODES(tree)[index];
    while(n->op==0xc0&&!n->constant) {
        if(n->right<0||++depth>4096)return n->right<0;
        parent=index;index=n->right;n=&YX_INTEGER_NODES(tree)[index];
    }
    if(n->constant)return true;
    if(n->op==0xa0||n->op==0xd8) {
        int left=n->left,right=n->right;
        return yx_unanchor_top_level_terms(tree,left,index,pattern,root,depth+1)&&
            (right==left||yx_unanchor_top_level_terms(tree,right,index,pattern,root,depth+1));
    }
    if(n->op==0xd5&&n->value==pattern&&n->left>=0&&YX_INTEGER_NODES(tree)[n->left].constant&&
       !YX_INTEGER_NODES(tree)[n->left].floating&&YX_INTEGER_NODES(tree)[n->left].value>=0) {
        int wrapper=yx_integer_expr_node_new(tree,0xd9,index,index,0);
        if(wrapper<0)return false;
        if(parent<0)*root=wrapper;
        else {
            yx_integer_expr_node *p=&YX_INTEGER_NODES(tree)[parent];
            if(p->left==index)p->left=wrapper;
            if(p->right==index)p->right=wrapper;
            if(p->extra==index)p->extra=wrapper;
        }
    }
    return true;
}
/* Reader: IR::or keeps a one-operand `or` (`false or $a at 5`), and
 * find_top_level_anchors does not descend into it; when its operand raises
 * no `undefined` the module has no block for it, only a lazy-search scope
 * that a one-operand `and` (which it does descend into) explains as well.
 * The archive tells them apart: a pattern whose frames are all plain
 * literals and that the decoded tree would anchor (yx_pattern_anchor_offset)
 * but the archive leaves unanchored had its top-level `at` term under a
 * one-operand `or`. The caller's scope fixup and canonical code comparison
 * verify the tree. Returns false only when the tree cannot grow. */
static bool yx_unanchored_pattern_terms_archive(const yx_physical_archive *a,yx_integer_expr *tree,int *root)
{
    /* Only a pattern with an `at` term can be anchored: one pass over the
     * frames and one anchor analysis of the tree for all patterns. */
    bool ok=true,any=false,*anchored=NULL;uint8_t *state;uint64_t *offset=NULL;
    if(*root<0)return true;
    for(size_t n=0;!any&&n<tree->count;++n)any=YX_INTEGER_NODES(tree)[n].op==0xd5;
    if(!any||!a->physical)return true;
    state=calloc(a->physical,1);anchored=calloc(a->physical,sizeof(*anchored));offset=calloc(a->physical,sizeof(*offset));
    if(!state||!anchored||!offset||!yx_pattern_anchor_offsets(tree,*root,a->physical,anchored,offset)) {
        free(state);free(anchored);free(offset);return false;
    }
    /* 1: has frames, 2: a frame is not a plain literal, 4: anchored */
    for(size_t i=0;i<a->frame_count;++i) {
        size_t p=a->frames[i].pattern;
        if(p>=a->physical)continue;
        state[p]|=1;
        if(a->frames[i].frame.variant!=0||(a->frames[i].frame.flags&2))state[p]|=2;
        if(a->frames[i].anchored)state[p]|=4;
    }
    /* Wrapping one pattern's `at` terms leaves the other patterns' analysis
     * as it was: those terms name that pattern alone (a constant offset). */
    for(size_t p=0;ok&&p<a->physical;++p)
        if(state[p]==1&&anchored[p])ok=yx_unanchor_top_level_terms(tree,*root,-1,(int64_t)p,root,0);
    free(state);free(anchored);free(offset);return ok;
}
static bool yx_unanchored_pattern_terms(const uint8_t *data,size_t length,yx_integer_expr *tree,int *root)
{
    yx_physical_archive a;bool ok;
    if(*root<0||!yx_physical_read(data,length,&a))return true;
    ok=yx_unanchored_pattern_terms_archive(&a,tree,root);
    yx_physical_destroy(&a);return ok;
}
#endif
