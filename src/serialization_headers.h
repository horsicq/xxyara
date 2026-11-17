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
    if(index<0||depth>256)return;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->op==0xa0||n->op==0xd8) {
        yx_anchor_top_level(tree,n->left,pattern,offset,depth+1);
        if(n->right!=n->left)yx_anchor_top_level(tree,n->right,pattern,offset,depth+1);
    } else if(n->op==0xd5&&n->value==pattern&&n->left>=0&&
              YX_INTEGER_NODES(tree)[n->left].constant&&!YX_INTEGER_NODES(tree)[n->left].floating&&
              YX_INTEGER_NODES(tree)[n->left].value>=0)
        *offset=YX_INTEGER_NODES(tree)[n->left].value;
}
static bool yx_anchor_uses(const yx_integer_expr *tree,int index,int64_t pattern,bool top,
    int64_t *anchor,bool *blocked,unsigned depth)
{
    if(index<0)return true;
    if(depth>4096)return false;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->op>=0xd1&&n->op<=0xd7&&n->value==pattern) {
        if(n->op==0xd5) {
            const yx_integer_expr_node *at=n->left>=0?&YX_INTEGER_NODES(tree)[n->left]:NULL;
            if(!at||!at->constant||at->floating||at->value<0)*blocked=true;
            else if(*anchor>=0&&*anchor!=at->value)*blocked=true;
            else *anchor=at->value;
        } else if(n->op!=0xd1||!top)*blocked=true;
    }
    if(!yx_anchor_uses(tree,n->left,pattern,top,anchor,blocked,depth+1))return false;
    if(n->right!=n->left&&!yx_anchor_uses(tree,n->right,pattern,top,anchor,blocked,depth+1))return false;
    return n->extra<0||n->extra==n->left||n->extra==n->right||
           yx_anchor_uses(tree,n->extra,pattern,top,anchor,blocked,depth+1);
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
    for(size_t i=0;anchored&&i<a.frame_count;++i)
        if(a.frames[i].frame.variant!=0||(a.frames[i].frame.flags&2))anchored=false;
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
    if(root<0||!yx_physical_read(*data,*length,&a))return YX_SER_UNSUPPORTED;
    if(a.anchored_count||a.logical<2)goto done;
    /* Upstream assigns the rule's header constraint to its regexp and hex
     * patterns; a lone plain literal frame contributes its bytes. */
    literals=calloc(a.physical,sizeof(*literals));patterns=calloc(a.physical,sizeof(*patterns));
    if(!literals||!patterns){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t p=0;p<a.physical;++p) {
        size_t frames=0,last=0;
        for(size_t i=0;i<a.frame_count;++i)if(a.frames[i].pattern==p)++frames,last=i;
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
    for(size_t p=0;p<a.physical;++p) {
        uint64_t offset=0;bool plain=true,any=false;
        if(!yx_pattern_anchor_offset(tree,root,(int64_t)p,&offset))continue;
        for(size_t i=0;i<a.frame_count;++i) {
            if(a.frames[i].pattern!=p)continue;
            any=true;
            if(a.frames[i].frame.variant!=0||(a.frames[i].frame.flags&2))plain=false;
        }
        if(!any||!plain)continue;
        for(size_t i=0;i<a.frame_count;++i)
            if(a.frames[i].pattern==p){a.frames[i].anchored=true;a.frames[i].offset=offset;}
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
    free(out);free(storage.data);free(literals);free(patterns);yx_physical_destroy(&a);return status;
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
               (a.frames[i].frame.flags&2)||!a.frames[i].frame.literal_length)goto done;
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
#endif
