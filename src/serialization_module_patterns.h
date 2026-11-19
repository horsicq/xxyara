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

/* Module and pattern operands share one typed expression and physical archive. */
/* Pattern operands of a `for .. of` body (`$`, `#`, `@`, `!`) keep
 * -(1 + the YX_MP_FOR_OF node) in integer instead of a PatternId.
 * YX_MP_ITEM is the decoder's transient operand for the loop's item.
 * YX_MP_RANGE is `for .. in (a..b)`; YX_MP_REGEX a `matches` operand.
 * YX_MP_TUPLE is `for .. in (e1, e2, ..)` and YX_MP_TUPLE_OF `.. of (b1, b2, ..)`:
 * their bytes hold the elements' node indexes (int). */
enum { YX_MP_PRESENT=32, YX_MP_COUNT, YX_MP_OFFSET, YX_MP_LENGTH,
       YX_MP_AT, YX_MP_IN, YX_MP_COUNT_IN, YX_MP_OF, YX_MP_FOR_OF, YX_MP_ITEM,
       YX_MP_RANGE, YX_MP_REGEX, YX_MP_TUPLE, YX_MP_TUPLE_OF };
static const char yx_module_pattern_range_name[]="pat_range_match@pattern_id_start:i,pattern_id_end:i,required:i@b";
typedef struct yx_module_patterns {
    yx_physical_archive *archive;
    bool presence, searched, helper_first, rule_scope, pattern_search;
    bool scopes[129]; unsigned scope_depth;
    uint8_t search_global, helper_type;size_t helper_id;
    size_t logical_start, logical_count, namespace_count;
    yx_global_rules_context prior;
    size_t *helper_calls, helper_call_count, helper_call_capacity;
    int for_of; /* the enclosing YX_MP_FOR_OF node, -1 outside a body */
    /* The condition roots yx_module_pattern_limits looks at (a `#a` that is
     * a whole condition needs one match), or NULL. */
    const int *limit_roots; size_t limit_root_count;
    unsigned quantity; /* nesting of quantifier parses: no loops or `of` there */
    /* The archive's regexp pool (RegexpId order), interned while emitting. */
    yx_literal *regexes; size_t regex_count, regex_capacity;
    /* Decoding: the name the printed conditions give each logical pattern
     * (the reconstructed patterns have placeholder identifiers), or NULL. */
    const char *const *anchor_names;
    /* yx_module_pattern_wasm_sized: the helper goes first whatever the
     * rule's size. */
    bool helper_tie;
} yx_module_patterns;
static bool yx_module_pattern_relocate_helper(yx_writer *body,const size_t *offsets,size_t count,size_t id)
{
    if(!count)return true;
    yx_writer rewritten={0};size_t previous=0;
    for(size_t i=0;i<count;++i) {
        size_t at=offsets[i];
        if(at<previous||at>=body->used||!yx_put_bytes(&rewritten,body->data+previous,at-previous)||!yx_put_uleb(&rewritten,id)){free(rewritten.data);return false;}
        previous=at+1;
    }
    if(!yx_put_bytes(&rewritten,body->data+previous,body->used-previous)){free(rewritten.data);return false;}
    free(body->data);*body=rewritten;return true;
}
/* Sorted copy of an `of` node's PatternIds (its bytes keep declaration
 * order) and the number of contiguous ranges; NULL on allocation failure. */
static uint32_t *yx_module_pattern_of_sorted(const yx_module_node *n,size_t *ranges)
{
    uint32_t *ids=malloc((n->length?n->length:1)*sizeof(*ids));
    if(!ids)return NULL;
    if(n->length)memcpy(ids,n->bytes,n->length*sizeof(*ids));
    for(size_t i=1;i<n->length;++i)
        for(size_t j=i;j&&ids[j-1]>ids[j];--j){uint32_t t=ids[j];ids[j]=ids[j-1];ids[j-1]=t;}
    *ranges=0;
    for(size_t i=0;i<n->length;++i)if(!i||ids[i]!=ids[i-1]+1)++*ranges;
    return ids;
}
/* Whether upstream evaluates the set with emit_of_pattern_set_with_loop:
 * `none`, a percentage, an anchor or `N` over several ranges. The low bits
 * of comparison are the quantifier (yx_module_pattern_quantifier), bits 4-5
 * the anchor (1 `at`, 2 `in`). */
static bool yx_module_pattern_of_loop(const yx_module_node *n)
{
    size_t ranges=0;uint32_t *ids;
    if(n->comparison==2||n->comparison==4||(n->comparison>>4))return true;
    if(n->comparison!=3)return false;
    ids=yx_module_pattern_of_sorted(n,&ranges);free(ids);
    return ranges>1;
}
/* `them` or `($a, $b*, ...)`: the member PatternIds of the rule in
 * declaration order (pattern_set_from_ast). NULL when not modeled. */
static uint32_t *yx_module_pattern_set(yx_module_program *p,size_t *count)
{
    yx_module_patterns *c=p->extension;
    const unsigned char *items[64];size_t lengths[64],item_count=0;bool wildcards[64];
    *count=0;
    if(!yx_bool_keyword(&p->parser,"them")) {
        if(!yx_module_take(p,'('))return NULL;
        do {
            const unsigned char *name;size_t length;
            yx_bool_skip_space(&p->parser);
            if(*p->parser.at!='$'||item_count==64)return NULL;
            ++p->parser.at;
            if(!yx_with_identifier(&p->parser,&name,&length))length=0,name=p->parser.at;
            items[item_count]=name;lengths[item_count]=length;
            wildcards[item_count]=*p->parser.at=='*';
            if(wildcards[item_count])++p->parser.at;
            else if(!length)return NULL;
            ++item_count;
        } while(yx_module_take(p,','));
        if(!yx_module_take(p,')'))return NULL;
    }
    size_t finish=c->rule_scope?c->logical_start+c->logical_count:c->archive->logical;
    uint32_t *ids=malloc((finish>c->logical_start?finish-c->logical_start:1)*sizeof(*ids));
    if(!ids)return NULL;
    for(size_t index=c->logical_start;index<finish;++index) {
        const char *name=c->archive->names[c->archive->name_ids[index]];size_t length=strlen(name+1);bool member=!item_count;
        for(size_t j=0;j<item_count&&!member;++j)
            member=wildcards[j]?length>=lengths[j]&&!memcmp(name+1,items[j],lengths[j]):
                   length==lengths[j]&&!memcmp(name+1,items[j],lengths[j]);
        if(member)ids[(*count)++]=(uint32_t)c->archive->mapping[index];
    }
    if(!*count){free(ids);return NULL;}
    return ids;
}
/* Whether the quantifier at `at` ends in the keyword `of`: a short balanced
 * run of operands and arithmetic operators followed by `of`. */
static bool yx_module_pattern_of_ahead(const unsigned char *at)
{
    static const char *const stops[]={"and","or","not","at","in","for","with","defined","matches","contains",
        "icontains","startswith","istartswith","endswith","iendswith","iequals","them","true","false"};
    const unsigned char *start=at;size_t level=0;bool operand=false;
    while(*at&&at-start<512) {
        unsigned char ch=*at;
        if(ch=='"')return false;
        if(ch=='('||ch=='['){++level;++at;continue;}
        if(ch==')'||ch==']'){if(!level)return false;--level;++at;operand=true;continue;}
        if(level||ch==' '||ch=='\t'||ch=='\r'||ch=='\n'){++at;continue;}
        if(isalpha(ch)||ch=='_') {
            const unsigned char *word=at;
            while(isalnum(*at)||*at=='_')++at;
            size_t length=(size_t)(at-word);
            if(length==2&&!memcmp(word,"of",2))return operand;
            for(size_t i=0;i<sizeof(stops)/sizeof(stops[0]);++i)
                if(strlen(stops[i])==length&&!memcmp(word,stops[i],length))return false;
            operand=true;continue;
        }
        if(isdigit(ch)||ch=='.'||ch=='$'||ch=='#'||ch=='@'){++at;operand=true;continue;}
        if(ch=='!'&&at[1]=='=')return false;
        if((ch=='<'||ch=='>')&&at[1]!=ch)return false;
        if(ch=='<'||ch=='>'){at+=2;continue;}
        if(strchr("!%+-*\\&|^~",ch)){++at;continue;}
        return false;
    }
    return false;
}
/* emit_for's quantifier (quantifier_from_ast): 0 any, 1 all, 2 none, 3 an
 * expression (Quantifier::Expr) and 4 a term followed by `%`
 * (Quantifier::Percentage); *quantity is the expression of 3 and 4. */
static bool yx_module_pattern_quantifier(yx_module_program *p,unsigned depth,uint8_t *kind,int *quantity)
{
    yx_module_patterns *c=p->extension;
    *quantity=-1;
    if(yx_bool_keyword(&p->parser,"any")){*kind=0;return true;}
    if(yx_bool_keyword(&p->parser,"all")){*kind=1;return true;}
    if(yx_bool_keyword(&p->parser,"none")){*kind=2;return true;}
    const unsigned char *start=p->parser.at;size_t saved_count=p->count;
    ++c->quantity;
    int term=yx_module_primary(p,depth+1);
    if(term>=0&&yx_module_take(p,'%')){*kind=4;*quantity=term;}
    else if(!p->failed) {
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;p->parser.at=start;
        *kind=3;*quantity=yx_module_parse(p,4,depth+1);
    }
    --c->quantity;
    if(*quantity<0||p->nodes[*quantity].type!=3)return false;
    const unsigned char *after=p->parser.at;
    if(*kind==3&&yx_module_take(p,'%'))return false;
    p->parser.at=after;return true;
}
/* `<quantifier> of them|(<set>)|(<b1>, <b2>, ..)`, with `at <e>` or
 * `in (<a>..<b>)` after a set (emit_of_pattern_set, emit_of_expr_tuple).
 * The frame (OF_FRAME_SIZE) is reserved before the quantifier and the items.
 * A set's node keeps its PatternIds, in declaration order, as uint32 values in
 * its bytes; a tuple is a YX_MP_TUPLE_OF node. comparison holds the
 * quantifier and, for a set, the anchor (yx_module_pattern_of_loop); args
 * hold the quantity of 3 and 4, then the anchor's operands; integer is the
 * loop frame. */
static int yx_module_pattern_of(yx_module_program *p,unsigned depth)
{
    yx_module_patterns *c=p->extension;
    const unsigned char *start=p->parser.at;size_t id_count=0,ranges=0,saved_count=p->count,base=p->binding_count;
    uint8_t kind,anchor=0;uint32_t *ids=NULL;int quantity=-1,args[3],argc=0,n=-1;
    const unsigned char *word=p->parser.at;
    bool keyword=yx_bool_keyword(&p->parser,"any")||yx_bool_keyword(&p->parser,"all")||yx_bool_keyword(&p->parser,"none");
    p->parser.at=word;
    if(c->quantity||(!keyword&&!yx_module_pattern_of_ahead(word)))return -1;
    if(base>YX_ARCHIVE_MAX_VARS-5||!yx_archive_bindings_reserve(&p->bindings,&p->binding_capacity,base+5)){p->failed=true;return -1;}
    if(!yx_module_pattern_quantifier(p,depth,&kind,&quantity)||!yx_bool_keyword(&p->parser,"of")) {
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;p->parser.at=start;return -1;
    }
    if(quantity>=0)args[argc++]=quantity;
    const unsigned char *items=p->parser.at;
    if(!(ids=yx_module_pattern_set(p,&id_count))) {
        /* `(<b1>, <b2>, ..)`: Boolean expressions, after the frame. */
        p->parser.at=items;
        if(p->failed||!yx_module_take(p,'('))goto unsupported;
        yx_writer elements={0};bool ok=true;
        memset(p->bindings+base,0,5*sizeof(*p->bindings));p->binding_count=base+5;
        do {
            int item=yx_module_parse(p,1,depth+1);
            ok=item>=0&&p->nodes[item].type>=1&&p->nodes[item].type<=4&&yx_put_bytes(&elements,&item,sizeof(item));
        } while(ok&&yx_module_take(p,','));
        p->binding_count=base;
        if(!ok||!yx_module_take(p,')')||(n=yx_module_node_new(p,YX_MP_TUPLE_OF,1))<0){free(elements.data);goto unsupported;}
        p->nodes[n].comparison=kind;p->nodes[n].bytes=elements.data;p->nodes[n].length=elements.used/sizeof(int);
        p->nodes[n].integer=(int64_t)base;p->nodes[n].argc=(uint8_t)argc;memcpy(p->nodes[n].args,args,(size_t)argc*sizeof(int));
        return n;
    }
    {
        const unsigned char *after=p->parser.at;
        if(yx_bool_keyword(&p->parser,"at")) {
            anchor=1;args[argc]=yx_module_parse(p,4,depth+1);
            if(args[argc++]<0)goto unsupported;
        } else if(yx_bool_keyword(&p->parser,"in")) {
            anchor=2;
            if(!yx_module_take(p,'(')||(args[argc++]=yx_module_parse(p,1,depth+1))<0)goto unsupported;
            yx_bool_skip_space(&p->parser);
            if(p->parser.at[0]!='.'||p->parser.at[1]!='.')goto unsupported;
            p->parser.at+=2;
            if((args[argc++]=yx_module_parse(p,1,depth+1))<0||!yx_module_take(p,')'))goto unsupported;
        } else p->parser.at=after;
        for(int i=quantity>=0;i<argc;++i)if(p->nodes[args[i]].type!=3)goto unsupported;
    }
    {
        yx_module_node probe={0};probe.bytes=(uint8_t *)ids;probe.length=id_count;
        uint32_t *sorted=yx_module_pattern_of_sorted(&probe,&ranges);
        free(sorted);
        if(!sorted)goto unsupported;
    }
    n=yx_module_node_new(p,YX_MP_OF,1);
    if(n<0)goto unsupported;
    p->nodes[n].comparison=(uint8_t)(kind|anchor<<4);p->nodes[n].bytes=(uint8_t *)ids;p->nodes[n].length=id_count;
    p->nodes[n].integer=(int64_t)base;
    p->nodes[n].argc=(uint8_t)argc;memcpy(p->nodes[n].args,args,(size_t)argc*sizeof(int));
    return n;
unsupported:
    free(ids);p->binding_count=base;p->failed=true;return -1;
}
/* `for <quantifier> <ident> in (<lower>..<upper>) : (<body>)`
 * (for_in_expr_from_ast): the FOR_IN frame is reserved before the
 * quantifier and the range; the variable is the frame's item (base + 5).
 * args: lower, upper, body and the quantity of 3 and 4. A tuple
 * `(<e1>, <e2>, ..)` is a YX_MP_TUPLE node (args: body and the quantity).
 * -1 with the parser restored when the iterable is neither. */
static int yx_module_pattern_range(yx_module_program *p,unsigned depth,const unsigned char *start,uint8_t kind,int quantity,
                                   size_t saved_count)
{
    const unsigned char *name;size_t length;
    if(!yx_with_identifier(&p->parser,&name,&length)||!yx_bool_keyword(&p->parser,"in")||!yx_module_take(p,'(')) {
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;p->parser.at=start;return -1;
    }
    size_t base=p->binding_count;
    if(base>YX_ARCHIVE_MAX_VARS-7||!yx_archive_bindings_reserve(&p->bindings,&p->binding_capacity,base+7)){p->failed=true;return -1;}
    memset(p->bindings+base,0,7*sizeof(*p->bindings));p->binding_count=base+7;
    int lower=-1,upper=-1,body=-1;
    lower=yx_module_parse(p,1,depth+1);
    yx_bool_skip_space(&p->parser);
    if(lower>=0&&(p->parser.at[0]==','||p->parser.at[0]==')')) {
        /* emit_for_in_expr_tuple: elements of one type; integers make an
         * unsigned variable when one of them is unsigned. */
        yx_writer elements={0};uint8_t type=p->nodes[lower].type;bool is_unsigned=false,ok=type>=1&&type<=4;
        for(int item=lower;ok;) {
            ok=p->nodes[item].type==type&&yx_put_bytes(&elements,&item,sizeof(item));
            is_unsigned|=p->nodes[item].unsigned_value;
            if(!ok||!yx_module_take(p,','))break;
            ok=(item=yx_module_parse(p,1,depth+1))>=0;
        }
        ok=ok&&yx_module_take(p,')')&&yx_module_take(p,':')&&yx_module_take(p,'(');
        int variable=ok?yx_module_node_new(p,YX_ME_VARIABLE,type):-1;
        if(variable>=0) {
            p->nodes[variable].integer=(int64_t)base+5;p->nodes[variable].unsigned_value=is_unsigned&&type==3;
            p->bindings[base+5].name=name;p->bindings[base+5].length=length;p->bindings[base+5].value=variable;
            body=yx_module_parse(p,1,depth+1);
        }
        p->binding_count=base;
        int node=-1;
        if(body>=0&&p->nodes[body].type>=1&&p->nodes[body].type<=4&&yx_module_take(p,')'))
            node=yx_module_node_new(p,YX_MP_TUPLE,1);
        if(node<0){free(elements.data);return -1;}
        yx_module_node *n=&p->nodes[node];
        n->comparison=kind;n->integer=(int64_t)base;n->bytes=elements.data;n->length=elements.used/sizeof(int);
        n->args[0]=body;n->argc=1;
        if(quantity>=0){n->args[1]=quantity;n->argc=2;}
        return node;
    }
    if(lower<0||p->parser.at[0]!='.'||p->parser.at[1]!='.') {
        /* Not a range: the array form belongs to the typed parser. */
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;p->binding_count=base;
        if(p->failed)return -1;
        p->parser.at=start;return -1;
    }
    p->parser.at+=2;upper=yx_module_parse(p,1,depth+1);
    if(upper<0||p->nodes[lower].type!=3||p->nodes[upper].type!=3||!yx_module_take(p,')')||
       !yx_module_take(p,':')||!yx_module_take(p,'(')){p->binding_count=base;return -1;}
    int variable=yx_module_node_new(p,YX_ME_VARIABLE,3);
    if(variable<0){p->binding_count=base;return -1;}
    p->nodes[variable].integer=(int64_t)base+5;
    p->bindings[base+5].name=name;p->bindings[base+5].length=length;p->bindings[base+5].value=variable;
    body=yx_module_parse(p,1,depth+1);
    p->binding_count=base;
    if(body<0||p->nodes[body].type<1||p->nodes[body].type>3||!yx_module_take(p,')'))return -1;
    int node=yx_module_node_new(p,YX_MP_RANGE,1);
    if(node<0)return -1;
    yx_module_node *n=&p->nodes[node];
    n->comparison=kind;n->integer=(int64_t)base;n->args[0]=lower;n->args[1]=upper;n->args[2]=body;n->argc=3;
    if(quantity>=0){n->args[3]=quantity;n->argc=4;}
    return node;
}
/* `for <quantifier> of <set> : (<body>)` (for_of_expr_from_ast). The
 * frame (VarStack::FOR_OF_FRAME_SIZE: n, i, max_count, count, item) is
 * reserved before the quantifier and the body; integer holds its base,
 * bytes the set's PatternIds, args[0] the body and args[1] the quantity of
 * 3 and 4. */
static int yx_module_pattern_for_of(yx_module_program *p,unsigned depth)
{
    yx_module_patterns *c=p->extension;
    const unsigned char *start=p->parser.at;uint8_t kind;int quantity;size_t id_count=0,saved_count=p->count;
    if(c->quantity||!yx_bool_keyword(&p->parser,"for"))return -1;
    if(!yx_module_pattern_quantifier(p,depth,&kind,&quantity)) {
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;p->parser.at=start;return -1;
    }
    if(!yx_bool_keyword(&p->parser,"of"))return yx_module_pattern_range(p,depth,start,kind,quantity,saved_count);
    size_t base=p->binding_count;
    if(base>YX_ARCHIVE_MAX_VARS-5||!yx_archive_bindings_reserve(&p->bindings,&p->binding_capacity,base+5)){p->failed=true;return -1;}
    uint32_t *ids=yx_module_pattern_set(p,&id_count);
    if(!ids)return -1;
    int node=yx_module_node_new(p,YX_MP_FOR_OF,1);
    if(node<0){free(ids);return -1;}
    p->nodes[node].comparison=kind;p->nodes[node].bytes=(uint8_t *)ids;p->nodes[node].length=id_count;
    p->nodes[node].integer=(int64_t)base;
    if(!yx_module_take(p,':')||!yx_module_take(p,'('))return -1;
    memset(p->bindings+base,0,5*sizeof(*p->bindings));p->binding_count=base+5;
    int saved=c->for_of;c->for_of=node;
    int body=yx_module_parse(p,1,depth+1);
    c->for_of=saved;p->binding_count=base;
    if(body<0||p->nodes[body].type<1||p->nodes[body].type>3||!yx_module_take(p,')'))return -1;
    p->nodes[node].args[0]=body;p->nodes[node].argc=1;
    if(quantity>=0){p->nodes[node].args[1]=quantity;p->nodes[node].argc=2;}
    return node;
}
/* `/regexp/flags` (YX_MP_REGEX, type 5): bytes hold the delimited text as
 * upstream's regexp pool interns it, followed by the literal the regexp
 * reduces to (integer: its length, or -1; comparison: 1 when `i`), as
 * matches_expr_from_ast then emits `contains` / `icontains` instead. */
static int yx_module_pattern_regex(yx_module_program *p)
{
    const unsigned char *start=p->parser.at,*at=start+1;
    bool escaped=false,in_class=false,closed=false,nocase=false;
    while(*at&&!closed) {
        unsigned char ch=*at++;
        if(escaped){escaped=false;continue;}
        if(ch=='\\')escaped=true;
        else if(ch=='[')in_class=true;
        else if(ch==']')in_class=false;
        else if(ch=='/'&&!in_class)closed=true;
    }
    if(!closed||at==start+2)return -1;
    const unsigned char *finish=at-1;
    while(*at=='i'||*at=='s'){nocase|=*at=='i';++at;}
    if(isalnum(*at)||*at=='_')return -1;
    size_t size=(size_t)(at-start);
    yx_writer bytes={0};bool literal=false;
    if(!yx_put_bytes(&bytes,start,size)){p->failed=true;return -1;}
    /* The condition compiler's own rewrite decides the literal, with the
     * scalar escapes (`\x{e9}` is U+00E9) groups and repetitions it knows. */
    {
        size_t body_length=(size_t)(finish-start-1);
        char *body=malloc(body_length+1),*text=NULL;size_t text_length=0;
        int found=body?0:-1;
        if(body) {
            memcpy(body,start+1,body_length);body[body_length]=0;
            found=yx_condition_regex_literal_bytes(body,&text,&text_length);
            free(body);
        }
        if(found<0||(found>0&&!yx_put_bytes(&bytes,text,text_length))) {
            free(text);free(bytes.data);p->failed=true;return -1;
        }
        /* An empty literal is Hir::empty, which as_literal_bytes rejects. */
        free(text);literal=found>0&&text_length>0;
    }
    int node=yx_module_node_new(p,YX_MP_REGEX,5);
    if(node<0){free(bytes.data);return -1;}
    p->nodes[node].bytes=bytes.data;p->nodes[node].length=size;
    p->nodes[node].integer=literal?(int64_t)(bytes.used-size):-1;p->nodes[node].comparison=nocase;
    p->parser.at=at;return node;
}
static int yx_module_pattern_primary(yx_module_program *p,unsigned depth)
{
    yx_module_patterns *c=p->extension;
    {
        int loop=yx_module_pattern_for_of(p,depth);
        if(loop>=0||p->failed)return loop;
        int of=yx_module_pattern_of(p,depth);
        if(of>=0||p->failed)return of;
    }
    if(*p->parser.at=='/')return yx_module_pattern_regex(p);
    uint8_t marker=*p->parser.at;
    if(marker!='$'&&marker!='#'&&marker!='@'&&marker!='!') {
        p->extension=&c->prior;int n=yx_global_rule_primary(p,depth);p->extension=c;return n;
    }
    ++p->parser.at;
    const unsigned char *name;size_t length;
    size_t index=0,finish=c->rule_scope?c->logical_start+c->logical_count:c->archive->logical;
    /* The anonymous operand of a `for .. of` body: no identifier follows. */
    bool anonymous=c->for_of>=0&&!isalnum(*p->parser.at)&&*p->parser.at!='_';
    if(!anonymous) {
        if(!yx_with_identifier(&p->parser,&name,&length))return -1;
        for(index=c->logical_start;index<finish;++index) {
            const char *id=c->archive->names[c->archive->name_ids[index]];
            if(strlen(id+1)==length&&!memcmp(id+1,name,length))break;
        }
        if(index==finish)return -1;
    }
    uint8_t op=marker=='$'?YX_MP_PRESENT:marker=='#'?YX_MP_COUNT:marker=='@'?YX_MP_OFFSET:YX_MP_LENGTH;
    int args[2]={-1,-1};size_t argc=0;
    if(marker=='@'||marker=='!') {
        if(yx_module_take(p,'[')) {
            args[0]=yx_module_parse(p,1,depth+1);
            if(args[0]<0||!yx_module_take(p,']'))return -1;
        } else {args[0]=yx_module_node_new(p,YX_ME_INT,3);if(args[0]>=0)p->nodes[args[0]].integer=1;}
        argc=1;
    } else if(marker=='$'&&yx_bool_keyword(&p->parser,"at")) {
        op=YX_MP_AT;args[0]=yx_module_parse(p,4,depth+1);argc=1;
    } else if(yx_bool_keyword(&p->parser,"in")) {
        op=marker=='$'?YX_MP_IN:YX_MP_COUNT_IN;
        if(!yx_module_take(p,'('))return -1;
        args[0]=yx_module_parse(p,1,depth+1);yx_bool_skip_space(&p->parser);
        if(p->parser.at[0]!='.'||p->parser.at[1]!='.')return -1;
        p->parser.at+=2;args[1]=yx_module_parse(p,1,depth+1);argc=2;
        if(!yx_module_take(p,')'))return -1;
    }
    for(size_t i=0;i<argc;++i)if(args[i]<0||p->nodes[args[i]].type!=3)return -1;
    int n=yx_module_node_new(p,op,op==YX_MP_PRESENT||op==YX_MP_AT||op==YX_MP_IN?1:3);
    if(n>=0){p->nodes[n].integer=anonymous?-1-(int64_t)c->for_of:(int64_t)c->archive->mapping[index];p->nodes[n].argc=(uint8_t)argc;memcpy(p->nodes[n].args,args,argc*sizeof(int));}
    return n;
}
/* The enclosing YX_MP_FOR_OF node of an anonymous operand, or NULL. */
static const yx_module_node *yx_module_pattern_owner(const yx_module_program *p,const yx_module_node *n)
{
    if(n->integer>=0||n->integer<-(int64_t)p->count)return NULL;
    const yx_module_node *loop=&p->nodes[-1-n->integer];
    return loop->op==YX_MP_FOR_OF?loop:NULL;
}
/* Push a pattern operand's PatternId: a constant, or the `for .. of` item
 * wrapped to i32 (emit_pattern_match on PatternMatchVar). */
static bool yx_module_pattern_id(yx_module_program *p,const yx_module_node *n,yx_writer *w)
{
    if(n->integer>=0)return yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,n->integer);
    const yx_module_node *loop=yx_module_pattern_owner(p,n);
    if(!loop)return false;
    p->memory=true;
    return yx_module_load_variable(w,loop->integer+4,3)&&yx_put_u8(w,0xa7);
}
static void yx_module_pattern_scope(yx_module_program *p,bool enter)
{
    yx_module_patterns *c=p->extension;
    if(enter){if(c->scope_depth<129)c->scopes[c->scope_depth++]=c->searched;c->searched=false;}
    else if(c->scope_depth)c->searched=c->scopes[--c->scope_depth];
}
/* Call the pattern check helper; its index is relocated once known. */
static bool yx_module_pattern_helper_call(yx_module_patterns *c,yx_writer *w)
{
    if(c->helper_call_count==c->helper_call_capacity) {
        size_t capacity=c->helper_call_capacity?c->helper_call_capacity*2:32;
        if(capacity<c->helper_call_capacity||capacity>SIZE_MAX/sizeof(*c->helper_calls))return false;
        size_t *grown=realloc(c->helper_calls,capacity*sizeof(*grown));if(!grown)return false;
        c->helper_calls=grown;c->helper_call_capacity=capacity;
    }
    if(!yx_put_u8(w,0x10))return false;
    c->helper_calls[c->helper_call_count++]=w->used;
    return yx_put_u8(w,0);
}
static bool yx_module_pattern_search(yx_module_program *p,yx_writer *w)
{
    yx_module_patterns *c=p->extension;
    if(c->searched)return true;
    if(!yx_put_u8(w,0x23)||!yx_put_u8(w,c->search_global)||!yx_put_u8(w,4)||!yx_put_u8(w,0x40)||
       !yx_put_u8(w,5)||!yx_module_call(p,w,"yara_x::wasm","search_for_patterns@@",NULL,0,0,false)||!yx_put_u8(w,0x0b))return false;
    c->searched=true;return true;
}
/* emit_of_pattern_set: one range calls pat_range_match (or the check helper
 * for a single `any`/`all` id) directly. Several ranges form the AND/OR
 * short-circuit block; an `any` set wraps every range but the last in a
 * result block, so it lowers like an OR whose last result stays on the stack. */
/* set_var/load_var/incr_var (emit.rs) of an integer loop variable. */
static bool yx_module_var_store(yx_writer *w){return yx_put_bytes(w,"\x37\x03\x80\x02",4);}
static bool yx_module_var_set(yx_writer *w,int64_t slot,int64_t value)
{
    return yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,slot*8)&&yx_put_u8(w,0x42)&&
        yx_put_sleb_i64(w,value)&&yx_module_var_store(w);
}
static bool yx_module_var_incr(yx_writer *w,int64_t slot)
{
    return yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,slot*8)&&yx_module_load_variable(w,slot,3)&&
        yx_put_bytes(w,"\x42\x01\x7c",3)&&yx_module_var_store(w);
}
/* emit_for's incr_i_and_repeat: i += 1, repeat while i < n. */
static bool yx_module_loop_next(yx_writer *w,int64_t i,int64_t n)
{
    return yx_module_var_incr(w,i)&&yx_module_load_variable(w,i,3)&&yx_module_load_variable(w,n,3)&&
        yx_put_bytes(w,"\x53\x0d\x00",3);
}
/* emit_switch over constant i64 branches; the i64 selector is on the stack.
 * The selector goes through the function's i32 temporary (local 0). */
static bool yx_module_switch_ids(yx_module_program *p,yx_writer *w,const uint32_t *ids,size_t k)
{
    if(!k||k>UINT32_MAX)return false;
    p->i32_local=true;
    if(!yx_put_bytes(w,"\xa7\x21\x00\x02\x7e",5))return false;
    for(size_t j=1;j<k;++j)if(!yx_put_bytes(w,"\x02\x40",2))return false;
    if(!yx_put_bytes(w,"\x02\x40\x02\x40\x20\x00\x0e",7)||!yx_put_uleb(w,k))return false;
    for(size_t j=0;j<k;++j)if(!yx_put_uleb(w,j+1))return false;
    if(!yx_put_bytes(w,"\x00\x0b\x00\x0b",4))return false;
    for(size_t j=0;j+1<k;++j)
        if(!yx_put_u8(w,0x42)||!yx_put_sleb_i64(w,ids[j])||!yx_put_u8(w,0x0c)||
           !yx_put_uleb(w,k-1-j)||!yx_put_u8(w,0x0b))return false;
    return yx_put_u8(w,0x42)&&yx_put_sleb_i64(w,ids[k-1])&&yx_put_u8(w,0x0b);
}
/* emit_for's incr_i_and_repeat with the loop `depth` labels away; `after`
 * is the item emit_for_in_range advances first (after_cond), or -1. */
static bool yx_module_loop_next_at(yx_writer *w,int64_t after,int64_t i,int64_t n,unsigned depth)
{
    return (after<0||yx_module_var_incr(w,after))&&yx_module_var_incr(w,i)&&yx_module_load_variable(w,i,3)&&
        yx_module_load_variable(w,n,3)&&yx_put_bytes(w,"\x53\x0d",2)&&yx_put_uleb(w,depth);
}
/* emit_for's quantifier branches after the body and the loop's end. The
 * writer keeps the body in its void catch block; walrus drops that block
 * when nothing branches to it, and so does the v12 lowering (`catch`). */
static bool yx_module_for_tail(uint8_t kind,bool catch_block,yx_writer *w,int64_t n,int64_t i,
                               int64_t max_count,int64_t count,int64_t after)
{
    uint8_t d=catch_block?1:0;
    if(!yx_put_bytes(w,"\x04\x40",2))return false;
    if(kind==0||kind==2) {
        if(!yx_put_u8(w,0x41)||!yx_put_u8(w,kind==0)||!yx_put_u8(w,0x0c)||!yx_put_u8(w,(uint8_t)(2+d))||
           !yx_put_bytes(w,"\x05\x0b",2)||(catch_block&&!yx_put_u8(w,0x0b))||!yx_module_loop_next_at(w,after,i,n,0))return false;
    } else if(kind==1) {
        if(!yx_module_loop_next_at(w,after,i,n,1u+d)||!yx_put_bytes(w,"\x41\x01\x0c",3)||!yx_put_u8(w,(uint8_t)(2+d))||
           !yx_put_bytes(w,"\x05\x0b",2)||(catch_block&&!yx_put_u8(w,0x0b))||!yx_put_bytes(w,"\x41\x00\x0c\x01",4))return false;
    } else if(kind==3||kind==4) {
        if(!yx_module_var_incr(w,count)||!yx_module_load_variable(w,count,3)||!yx_module_load_variable(w,max_count,3)||
           !yx_put_bytes(w,"\x5a\x04\x40",3)||!yx_module_load_variable(w,max_count,3)||
           !yx_put_bytes(w,"\x42\x00\x52\x0c",4)||!yx_put_u8(w,(uint8_t)(3+d))||!yx_put_bytes(w,"\x05\x0b\x05\x0b",4)||
           (catch_block&&!yx_put_u8(w,0x0b))||!yx_module_loop_next_at(w,after,i,n,0))return false;
    } else return false;
    if(!yx_put_u8(w,0x0b))return false;
    if(kind>=3)return yx_module_load_variable(w,max_count,3)&&yx_put_bytes(w,"\x50\x0b",2);
    return yx_put_u8(w,0x41)&&yx_put_u8(w,kind!=0)&&yx_put_u8(w,0x0b);
}
/* emit_for's set_var(max_count) and set_var(count, 0) for an expression or
 * a percentage quantifier (`kind` 3, 4): n * quantity / 100 rounded up and
 * saturated, a negative runtime percentage replaced by i64::MAX. The
 * quantity's undefined values reach the handler outside the loop's block. */
static bool yx_module_quantity_emit(yx_module_program *p,yx_writer *w,uint8_t kind,int quantity,
                                    int64_t n,int64_t max_count,int64_t count,unsigned depth)
{
    if(quantity<0||(size_t)quantity>=p->count)return false;
    const yx_module_node *q=&p->nodes[quantity];
    bool percentage=kind==4,select=percentage&&!yx_module_non_negative(q),is_unsigned=q->unsigned_value;
    int saved=p->undefined_slot;
    p->undefined_slot=yx_integer_undefined_shift(saved,1);
    bool ok=yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,max_count*8)&&
        (!percentage||(yx_module_load_variable(w,n,3)&&yx_put_u8(w,0xb9)))&&
        yx_module_emit(p,quantity,w,depth+1);
    p->undefined_slot=saved;
    if(ok&&select) {
        p->divisor=true;
        ok=yx_put_bytes(w,"\x22\x00\x42",3)&&yx_put_sleb_i64(w,INT64_MAX)&&yx_put_bytes(w,"\x20\x00\x42\x00\x59\x1b",6);
    }
    if(ok&&percentage)
        ok=yx_put_u8(w,is_unsigned?0xba:0xb9)&&yx_put_u8(w,0xa2)&&yx_put_u8(w,0x44)&&yx_put_float(w,100.0)&&
            yx_put_bytes(w,"\xa3\x9b\xfc\x06",4);
    return ok&&yx_module_var_store(w)&&yx_module_var_set(w,count,0);
}
/* emit_switch: the i64 selector on the stack picks one of `k` branches,
 * whose results have Wasm type `type`. The selector goes through the
 * function's i32 temporary (local 0); branch j ends with
 * yx_module_switch_close. */
static bool yx_module_switch_open(yx_module_program *p,yx_writer *w,uint8_t type,size_t k)
{
    if(!k)return false;
    p->i32_local=true;
    if(!yx_put_bytes(w,"\xa7\x21\x00\x02",4)||!yx_put_u8(w,type))return false;
    for(size_t j=1;j<k;++j)if(!yx_put_bytes(w,"\x02\x40",2))return false;
    if(!yx_put_bytes(w,"\x02\x40\x02\x40\x20\x00\x0e",7)||!yx_put_uleb(w,k))return false;
    for(size_t j=0;j<k;++j)if(!yx_put_uleb(w,j+1))return false;
    return yx_put_bytes(w,"\x00\x0b\x00\x0b",4);
}
static bool yx_module_switch_close(yx_writer *w,size_t j,size_t k)
{
    return j+1<k?yx_put_u8(w,0x0c)&&yx_put_uleb(w,k-1-j)&&yx_put_u8(w,0x0b):yx_put_u8(w,0x0b);
}
/* catch_undef's block exists only when something branches to it: drop the
 * `block` opener written at `at`, moving the call sites recorded since. */
static void yx_module_drop_block(yx_module_program *p,yx_writer *w,size_t at,size_t calls,size_t helpers)
{
    yx_module_patterns *c=p->extension;
    memmove(w->data+at,w->data+at+2,w->used-at-2);w->used-=2;
    for(size_t i=calls;i<p->call_count;++i)if(p->calls[i]>=at+2)p->calls[i]-=2;
    for(size_t i=helpers;i<c->helper_call_count;++i)if(c->helper_calls[i]>=at+2)c->helper_calls[i]-=2;
}
/* A loop body inside emit_for's void catch block: an undefined value leaves
 * that block (`br 1`). `used` tells whether the block was kept; the caller
 * closes it with the quantifier branches. */
static bool yx_module_catch_body(yx_module_program *p,int body,yx_writer *w,unsigned depth,bool *used)
{
    yx_module_patterns *c=p->extension;
    size_t at=w->used,calls=p->call_count,helpers=c->helper_call_count;
    int saved=p->undefined_slot;p->undefined_slot=-34;
    bool ok=yx_put_bytes(w,"\x02\x40",2)&&yx_module_boolean(p,body,w,depth+1);
    p->undefined_slot=saved;
    if(!ok||!yx_module_body_escapes(w->data+at+2,w->used-at-2,used))return false;
    if(!*used)yx_module_drop_block(p,w,at,calls,helpers);
    return true;
}
/* emit_of_pattern_set_with_loop. Frame (VarStack::OF_FRAME_SIZE): item, n,
 * i, max_count, count. The body checks the item's PatternId: the check
 * helper, or is_pat_match_at/_in with the anchor's operands, inside the
 * quantifier's catch block when an operand can be undefined. */
static bool yx_module_pattern_of_loop_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    int64_t item=n->integer,count=n->integer+1,i=n->integer+2,max_count=n->integer+3,matched=n->integer+4;
    uint8_t kind=n->comparison&15,anchor=n->comparison>>4;int first=kind>=3?1:0;
    if(n->integer<0||n->integer>YX_ARCHIVE_MAX_VARS-5||kind>4||anchor>2||n->argc!=first+anchor)return false;
    p->memory=true;
    if(!yx_put_bytes(w,"\x02\x7f",2)||!yx_module_var_set(w,count,(int64_t)n->length)||!yx_module_var_set(w,i,0))return false;
    if(kind>=3&&!yx_module_quantity_emit(p,w,kind,n->args[0],count,max_count,matched,depth))return false;
    if(!yx_put_bytes(w,"\x03\x40",2)||!yx_put_u8(w,0x41)||!yx_put_sleb_i64(w,item*8)||
       !yx_module_load_variable(w,i,3)||!yx_module_switch_ids(p,w,(const uint32_t *)n->bytes,n->length)||
       !yx_module_var_store(w))return false;
    size_t at=w->used,calls=p->call_count,helpers=c->helper_call_count;bool used=false,ok;
    int saved=p->undefined_slot;p->undefined_slot=-34;
    ok=yx_put_bytes(w,"\x02\x40",2)&&yx_module_load_variable(w,item,3)&&yx_put_u8(w,0xa7);
    if(ok&&!anchor)ok=yx_module_pattern_helper_call(c,w);
    else if(ok) {
        static const uint8_t args[]={0x7f,0x7e,0x7e};
        for(int k=0;ok&&k<anchor;++k)ok=yx_module_emit(p,n->args[first+k],w,depth+1);
        ok=ok&&yx_module_call(p,w,"yara_x::wasm",yx_pattern_expression_symbols[yx_pattern_expression_symbol(anchor==1?0xd5:0xd6)],
                              args,(size_t)anchor+1,0x7f,false);
    }
    p->undefined_slot=saved;
    if(!ok||!yx_module_body_escapes(w->data+at+2,w->used-at-2,&used))return false;
    if(!used)yx_module_drop_block(p,w,at,calls,helpers);
    return yx_module_for_tail(kind,used,w,count,i,max_count,matched,-1);
}
/* emit_for_in_expr_tuple (FOR_IN_FRAME_SIZE: n, i, max_count, count, -,
 * item): n is the number of elements. Before each iteration the i-th
 * element (emit_switch) is stored in the item inside a catch_undef whose
 * handler flags the item undefined; that block, the flag operations and the
 * body's checks of the flag exist only when an element can be undefined. */
static bool yx_module_pattern_tuple_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    int64_t base=n->integer;uint8_t kind=n->comparison;size_t k=n->length;const int *items=(const int *)n->bytes;
    if(base<0||base>YX_ARCHIVE_MAX_VARS-7||!items||!k||kind>4||n->argc!=(kind>=3?2:1))return false;
    uint8_t type=p->nodes[items[0]].type;
    p->memory=true;
    if(!yx_put_bytes(w,"\x02\x7f",2)||!yx_module_var_set(w,base,(int64_t)k)||!yx_module_var_set(w,base+1,0)||
       (kind>=3&&!yx_module_quantity_emit(p,w,kind,n->args[1],base,base+2,base+3,depth))||!yx_put_bytes(w,"\x03\x40",2))return false;
    size_t at=w->used,calls=p->call_count,helpers=c->helper_call_count;bool used=false;
    bool ok=yx_put_bytes(w,"\x02\x40",2)&&yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,(base+5)*8)&&
        yx_module_load_variable(w,base+1,3)&&yx_module_switch_open(p,w,yx_module_wasm_type(type),k);
    int saved=p->undefined_slot;
    for(size_t j=0;ok&&j<k;++j) {
        p->undefined_slot=yx_integer_undefined_shift((int)(base+5),(unsigned)(k-j));
        ok=yx_module_emit(p,items[j],w,depth+1)&&yx_module_switch_close(w,j,k);
    }
    p->undefined_slot=saved;
    if(!ok||!yx_module_store_value(w,type)||!yx_module_body_escapes(w->data+at+2,w->used-at-2,&used))return false;
    if(used){if(!yx_integer_clear_variable(w,base+5)||!yx_put_u8(w,0x0b))return false;}
    else yx_module_drop_block(p,w,at,calls,helpers);
    bool defined=p->slot_defined[base+5],caught=false;
    p->slot_defined[base+5]=!used;
    ok=yx_module_catch_body(p,n->args[0],w,depth,&caught);
    p->slot_defined[base+5]=defined;
    return ok&&yx_module_for_tail(kind,caught,w,base,base+1,base+2,base+3,-1);
}
/* emit_of_expr_tuple (OF_FRAME_SIZE: item, n, i, max_count, count): the
 * i-th Boolean (emit_switch) is stored in the item, which is the body.
 * Undefined values of an element reach the handler outside the loop. */
static bool yx_module_pattern_tuple_of_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    const yx_module_node *n=&p->nodes[index];
    int64_t base=n->integer;uint8_t kind=n->comparison;size_t k=n->length;const int *items=(const int *)n->bytes;
    if(base<0||base>YX_ARCHIVE_MAX_VARS-5||!items||!k||kind>4||n->argc!=(kind>=3?1:0))return false;
    p->memory=true;
    bool ok=yx_put_bytes(w,"\x02\x7f",2)&&yx_module_var_set(w,base+1,(int64_t)k)&&yx_module_var_set(w,base+2,0)&&
        (kind<3||yx_module_quantity_emit(p,w,kind,n->args[0],base+1,base+3,base+4,depth))&&
        yx_put_bytes(w,"\x03\x40",2)&&yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,base*8)&&
        yx_module_load_variable(w,base+2,3)&&yx_module_switch_open(p,w,0x7f,k);
    int saved=p->undefined_slot;
    for(size_t j=0;ok&&j<k;++j) {
        p->undefined_slot=yx_integer_undefined_shift(saved,(unsigned)(k-j+2));
        ok=yx_module_boolean(p,items[j],w,depth+1)&&yx_module_switch_close(w,j,k);
    }
    p->undefined_slot=saved;
    return ok&&yx_module_store_value(w,1)&&yx_module_load_variable(w,base,1)&&
        yx_module_for_tail(kind,false,w,base+1,base+2,base+3,base+4,-1);
}
/* emit_for_in_range (FOR_IN_FRAME_SIZE: n, i, max_count, count, -, item):
 * undefined bounds exit the loop with false from their own catch block. */
static bool yx_module_pattern_range_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    int64_t base=n->integer;uint8_t kind=n->comparison;
    if(base<0||base>YX_ARCHIVE_MAX_VARS-7||kind>4||n->argc!=(kind>=3?4:3))return false;
    bool lower_unsigned=p->nodes[n->args[0]].unsigned_value,upper_unsigned=p->nodes[n->args[1]].unsigned_value;
    p->memory=true;p->two_locals=true;
    size_t at=w->used+2,calls=p->call_count,helpers=c->helper_call_count;bool used=false;
    int saved=p->undefined_slot;p->undefined_slot=-33;
    bool ok=yx_put_bytes(w,"\x02\x7f\x02\x40",4)&&yx_module_emit(p,n->args[1],w,depth+1)&&
        yx_module_emit(p,n->args[0],w,depth+1)&&yx_put_bytes(w,"\x21\x00\x21\x01",4);
    p->undefined_slot=saved;
    if(!ok||!yx_module_body_escapes(w->data+at+2,w->used-at-2,&used))return false;
    if(!used)yx_module_drop_block(p,w,at,calls,helpers);
    else if(!yx_put_u8(w,0x0b))return false;
    ok=yx_put_bytes(w,"\x20\x01\x20\x00\x53",5)&&
        (!lower_unsigned||yx_put_bytes(w,"\x20\x00\x42\x00\x53\x72",6))&&
        (!upper_unsigned||yx_put_bytes(w,"\x20\x01\x42\x00\x53\x72",6))&&
        yx_put_bytes(w,"\x04\x40\x41\x00\x0c\x01\x05\x0b",8)&&
        yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,base*8)&&yx_put_u8(w,0x42)&&yx_put_sleb_i64(w,INT64_MAX)&&
        yx_put_bytes(w,"\x20\x01\x20\x00\x7d\x42\x01\x7c\x20\x01\x20\x00\x7d\x42",14)&&
        yx_put_sleb_i64(w,INT64_MAX)&&yx_put_bytes(w,"\x5a\x1b",2)&&yx_module_var_store(w)&&
        yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,(base+5)*8)&&yx_put_bytes(w,"\x20\x00",2)&&yx_module_var_store(w)&&
        yx_module_var_set(w,base+1,0);
    if(ok&&kind>=3)ok=yx_module_quantity_emit(p,w,kind,n->args[3],base,base+2,base+3,depth);
    if(!ok||!yx_put_bytes(w,"\x03\x40",2))return false;
    bool defined=p->slot_defined[base+5];p->slot_defined[base+5]=true;
    ok=yx_module_catch_body(p,n->args[2],w,depth,&used);
    p->slot_defined[base+5]=defined;
    return ok&&yx_module_for_tail(kind,used,w,base,base+1,base+2,base+3,base+5);
}
/* emit_for_of_pattern_set: the item is the i-th PatternId of the set. */
static bool yx_module_pattern_for_of_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    const yx_module_node *n=&p->nodes[index];
    int64_t base=n->integer;uint8_t kind=n->comparison;
    if(base<0||base>YX_ARCHIVE_MAX_VARS-5||!n->bytes||!n->length||kind>4||n->argc!=(kind>=3?2:1))return false;
    p->memory=true;
    if(!yx_put_bytes(w,"\x02\x7f",2)||!yx_module_var_set(w,base,(int64_t)n->length)||!yx_module_var_set(w,base+1,0))return false;
    if(kind>=3&&!yx_module_quantity_emit(p,w,kind,n->args[1],base,base+2,base+3,depth))return false;
    if(!yx_put_bytes(w,"\x03\x40",2)||!yx_put_u8(w,0x41)||!yx_put_sleb_i64(w,(base+4)*8)||
       !yx_module_load_variable(w,base+1,3)||!yx_module_switch_ids(p,w,(const uint32_t *)n->bytes,n->length)||
       !yx_module_var_store(w))return false;
    bool used=false;
    return yx_module_catch_body(p,n->args[0],w,depth,&used)&&yx_module_for_tail(kind,used,w,base,base+1,base+2,base+3,-1);
}
static bool yx_module_pattern_of_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    static const uint8_t range_args[]={0x7f,0x7f,0x7e};
    size_t count=n->length,ranges=0;
    if(!n->bytes||!count||!yx_module_pattern_search(p,w))return false;
    if(yx_module_pattern_of_loop(n))return yx_module_pattern_of_loop_emit(p,index,w,depth);
    uint32_t *ids=yx_module_pattern_of_sorted(n,&ranges);
    if(!ids)return false;
    bool ok=true;
    if(n->comparison==3) {
        ok=ranges==1&&yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,ids[0])&&yx_put_u8(w,0x41)&&
            yx_put_sleb_i64(w,ids[count-1])&&yx_module_emit(p,n->args[0],w,depth+1)&&
            yx_module_call(p,w,"yara_x::wasm",yx_module_pattern_range_name,range_args,3,0x7f,false);
        free(ids);return ok;
    }
    bool all=n->comparison==1;
    if(ranges>1&&!yx_put_bytes(w,"\x02\x7f",2))ok=false;
    for(size_t i=0;ok&&i<count;) {
        size_t j=i;
        while(j+1<count&&ids[j+1]==ids[j]+1)++j;
        bool last=j+1==count,wrap=ranges>1&&!all&&!last;
        if(wrap&&!yx_put_bytes(w,"\x02\x7f",2))ok=false;
        if(ok&&(!yx_put_u8(w,0x41)||!yx_put_sleb_i64(w,ids[i])))ok=false;
        if(ok&&i==j) {
            if(!yx_module_pattern_helper_call(c,w))ok=false;
        } else if(ok&&(!yx_put_u8(w,0x41)||!yx_put_sleb_i64(w,ids[j])||!yx_put_u8(w,0x42)||
                  !yx_put_sleb_i64(w,all?(int64_t)(j-i+1):1)||
                  !yx_module_call(p,w,"yara_x::wasm",yx_module_pattern_range_name,range_args,3,0x7f,false)))ok=false;
        if(ok&&wrap&&!yx_put_u8(w,0x0b))ok=false;
        if(ok&&!last&&!yx_put_bytes(w,all?yx_integer_and_guard:yx_integer_or_guard,sizeof(yx_integer_or_guard)))ok=false;
        i=j+1;
    }
    free(ids);
    return ok&&(ranges<=1||yx_put_u8(w,0x0b));
}
/* `<string> matches <regexp>`: a literal regexp is `contains`/`icontains`
 * of that literal; otherwise str_matches takes the RegexpId. */
static bool yx_module_pattern_matches_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    static const uint8_t strings[]={0x7e,0x7e},regexp[]={0x7e,0x7f};
    const yx_module_node *re=&p->nodes[n->args[1]];size_t id;
    if(re->op!=YX_MP_REGEX||!re->bytes||p->nodes[n->args[0]].type!=4||!yx_module_emit(p,n->args[0],w,depth+1))return false;
    if(re->integer>=0)
        return yx_intern_literal(re->bytes+re->length,(size_t)re->integer,&p->literals,&p->literal_count,&p->literal_capacity,&id)&&
            id<=INT64_MAX/4&&yx_put_u8(w,0x42)&&yx_put_sleb_i64(w,(int64_t)(id*4))&&
            yx_module_call(p,w,"yara_x::wasm",yx_module_comparison_names[re->comparison?7:6],strings,2,0x7f,false);
    return yx_intern_literal(re->bytes,re->length,&c->regexes,&c->regex_count,&c->regex_capacity,&id)&&id<=INT32_MAX&&
        yx_put_u8(w,0x41)&&yx_put_sleb_i64(w,(int64_t)id)&&
        yx_module_call(p,w,"yara_x::wasm","str_matches@lhs:s,rhs:r@b",regexp,2,0x7f,false);
}
static bool yx_module_pattern_emit(yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    if(n->op==YX_ME_COMPARE&&n->comparison==13)return yx_module_pattern_matches_emit(p,index,w,depth);
    if(n->op==YX_GLOBAL_RULE_REFERENCE)return yx_global_rule_emit(p,index,w,depth);
    if(n->op==YX_MP_OF)return yx_module_pattern_of_emit(p,index,w,depth);
    if(n->op==YX_MP_FOR_OF)return yx_module_pattern_for_of_emit(p,index,w,depth);
    if(n->op==YX_MP_RANGE)return yx_module_pattern_range_emit(p,index,w,depth);
    if(n->op==YX_MP_TUPLE)return yx_module_pattern_tuple_emit(p,index,w,depth);
    if(n->op==YX_MP_TUPLE_OF)return yx_module_pattern_tuple_of_emit(p,index,w,depth);
    if(n->op<YX_MP_PRESENT||n->op>YX_MP_COUNT_IN)return false;
    if(!yx_module_pattern_search(p,w))return false;
    if(!yx_module_pattern_id(p,n,w))return false;
    for(size_t i=0;i<n->argc;++i)if(!yx_module_emit(p,n->args[i],w,depth+1))return false;
    if(n->op==YX_MP_PRESENT)return yx_module_pattern_helper_call(c,w);
    static const uint8_t args[]={0x7f,0x7e,0x7e};
    unsigned symbol=yx_pattern_expression_symbol((uint8_t)(n->op-YX_MP_PRESENT+0xd1));
    return yx_module_call(p,w,"yara_x::wasm",yx_pattern_expression_symbols[symbol],args,n->argc+1,
             n->type==1?0x7f:0x7e,n->op==YX_MP_OFFSET||n->op==YX_MP_LENGTH)&&
        ((n->op!=YX_MP_OFFSET&&n->op!=YX_MP_LENGTH)||yx_module_guard(p,w));
}
/* `(<names>)` of a pattern set's PatternIds: each id names the next unused
 * declared pattern with that id. */
static bool yx_module_pattern_print_set(const yx_module_program *p,const yx_module_node *n,yx_writer *w)
{
    const yx_module_patterns *c=p->extension;const uint32_t *ids=(const uint32_t *)n->bytes;
    size_t finish=c->rule_scope?c->logical_start+c->logical_count:c->archive->logical;
    bool *taken=ids&&n->length?calloc(finish>c->logical_start?finish-c->logical_start:1,sizeof(*taken)):NULL;
    bool ok=taken&&yx_put_u8(w,'(');
    for(size_t k=0;ok&&k<n->length;++k) {
        const char *name=NULL;
        for(size_t i=c->logical_start;i<finish;++i)
            if(!taken[i-c->logical_start]&&c->archive->mapping[i]==ids[k]){taken[i-c->logical_start]=true;name=c->archive->names[c->archive->name_ids[i]];break;}
        ok=name&&(!k||yx_put_bytes(w,", ",2))&&yx_put_bytes(w,name,strlen(name));
    }
    free(taken);
    return ok&&yx_put_u8(w,')');
}
/* A quantifier as source: a constant quantity as is, another one in
 * parentheses, a percentage followed by `%`. */
static bool yx_module_pattern_print_quantifier(const yx_module_program *p,uint8_t kind,int quantity,yx_writer *w,unsigned depth)
{
    if(kind<3)return kind==2?yx_put_bytes(w,"none",4):yx_put_bytes(w,kind?"all":"any",3);
    bool plain=p->nodes[quantity].op==YX_ME_INT;
    return (plain||yx_put_u8(w,'('))&&yx_module_print(p,quantity,w,depth+1)&&(plain||yx_put_u8(w,')'))&&
        (kind!=4||yx_put_u8(w,'%'));
}
/* `(<e1>, <e2>, ..)` of a tuple node. */
static bool yx_module_pattern_print_tuple(const yx_module_program *p,const yx_module_node *n,yx_writer *w,unsigned depth)
{
    bool ok=yx_put_u8(w,'(');
    for(size_t i=0;ok&&i<n->length;++i)
        ok=(!i||yx_put_bytes(w,", ",2))&&yx_module_print(p,((const int *)n->bytes)[i],w,depth+1);
    return ok&&yx_put_u8(w,')');
}
static bool yx_module_pattern_print(const yx_module_program *p,int index,yx_writer *w,unsigned depth)
{
    const yx_module_patterns *c=p->extension;const yx_module_node *n=&p->nodes[index];
    if(n->op==YX_GLOBAL_RULE_REFERENCE) {
        if(n->integer<0||(uint64_t)n->integer>=c->prior.current)return false;
        const char *id=c->prior.rules[n->integer].identifier;return yx_put_bytes(w,id,strlen(id));
    }
    if(n->op==YX_ME_COMPARE&&n->comparison==13)
        return yx_put_u8(w,'(')&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_bytes(w," matches ",9)&&
            yx_module_print(p,n->args[1],w,depth+1)&&yx_put_u8(w,')');
    if(n->op==YX_MP_REGEX)return n->bytes&&yx_put_bytes(w,n->bytes,n->length);
    if(n->op==YX_MP_RANGE) {
        char variable[48];
        snprintf(variable,sizeof(variable)," v%" PRId64 " in (",n->integer+5);
        return yx_put_bytes(w,"for ",4)&&yx_module_pattern_print_quantifier(p,n->comparison,n->args[3],w,depth)&&
            yx_put_bytes(w,variable,strlen(variable))&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_bytes(w,"..",2)&&
            yx_module_print(p,n->args[1],w,depth+1)&&yx_put_bytes(w,") : (",5)&&yx_module_print(p,n->args[2],w,depth+1)&&yx_put_u8(w,')');
    }
    if(n->op==YX_MP_TUPLE) {
        char variable[48];
        snprintf(variable,sizeof(variable)," v%" PRId64 " in ",n->integer+5);
        return yx_put_bytes(w,"for ",4)&&yx_module_pattern_print_quantifier(p,n->comparison,n->args[1],w,depth)&&
            yx_put_bytes(w,variable,strlen(variable))&&yx_module_pattern_print_tuple(p,n,w,depth)&&
            yx_put_bytes(w," : (",4)&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_u8(w,')');
    }
    if(n->op==YX_MP_TUPLE_OF)
        return yx_module_pattern_print_quantifier(p,n->comparison,n->args[0],w,depth)&&yx_put_bytes(w," of ",4)&&
            yx_module_pattern_print_tuple(p,n,w,depth);
    if(n->op==YX_MP_OF||n->op==YX_MP_FOR_OF) {
        bool loop=n->op==YX_MP_FOR_OF;uint8_t kind=n->comparison&15,anchor=n->comparison>>4;
        int first=kind>=3?1:0;
        bool ok=(!loop||yx_put_bytes(w,"for ",4))&&yx_module_pattern_print_quantifier(p,kind,n->args[loop?1:0],w,depth)&&
            yx_put_bytes(w," of ",4)&&yx_module_pattern_print_set(p,n,w);
        if(ok&&anchor==1)ok=yx_put_bytes(w," at (",5)&&yx_module_print(p,n->args[first],w,depth+1)&&yx_put_u8(w,')');
        if(ok&&anchor==2)ok=yx_put_bytes(w," in ((",6)&&yx_module_print(p,n->args[first],w,depth+1)&&yx_put_bytes(w,")..(",4)&&
            yx_module_print(p,n->args[first+1],w,depth+1)&&yx_put_bytes(w,"))",2);
        return ok&&(!loop||(yx_put_bytes(w," : (",4)&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_u8(w,')')));
    }
    if(n->op<YX_MP_PRESENT||n->op>YX_MP_COUNT_IN)return false;
    const char *name=NULL;
    size_t finish=c->rule_scope?c->logical_start+c->logical_count:c->archive->logical;
    if(n->integer<0)name=yx_module_pattern_owner(p,n)?"$":NULL;
    else for(size_t i=c->logical_start;i<finish;++i)if(c->archive->mapping[i]==(size_t)n->integer){name=c->archive->names[c->archive->name_ids[i]];break;}
    char marker=n->op==YX_MP_COUNT||n->op==YX_MP_COUNT_IN?'#':n->op==YX_MP_OFFSET?'@':n->op==YX_MP_LENGTH?'!':'$';
    if(!name||!yx_put_u8(w,(uint8_t)marker)||!yx_put_bytes(w,name+1,strlen(name+1)))return false;
    if(n->op==YX_MP_OFFSET||n->op==YX_MP_LENGTH)return yx_put_u8(w,'[')&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_u8(w,']');
    if(n->op==YX_MP_AT)return yx_put_bytes(w," at (",5)&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_u8(w,')');
    if(n->op==YX_MP_IN||n->op==YX_MP_COUNT_IN)return yx_put_bytes(w," in (",5)&&yx_module_print(p,n->args[0],w,depth+1)&&yx_put_bytes(w,"..",2)&&yx_module_print(p,n->args[1],w,depth+1)&&yx_put_u8(w,')');
    return true;
}
static bool yx_module_expect(yx_reader *r,size_t end,const char *bytes,size_t length)
{
    if(length>end-r->at||memcmp(r->data+r->at,bytes,length))return false;
    r->at+=length;return true;
}
static bool yx_module_expect_store(yx_reader *r,size_t end,int64_t slot,int64_t *value)
{
    int64_t address;
    return yx_module_expect(r,end,"\x41",1)&&yx_get_sleb_i64(r,&address)&&address==slot*8&&
        yx_module_expect(r,end,"\x42",1)&&yx_get_sleb_i64(r,value)&&yx_module_expect(r,end,"\x37\x03\x80\x02",4);
}
/* yx_module_switch_ids over k PatternIds, after the i64 selector. */
static uint32_t *yx_module_switch_decode(yx_reader *q,size_t end,int64_t k,size_t physical)
{
    uint64_t targets,target;int64_t value;
    if(k<1||k>(int64_t)(end-q->at)||!yx_module_expect(q,end,"\xa7\x21\x00\x02\x7e",5))return NULL;
    for(int64_t j=1;j<k;++j)if(!yx_module_expect(q,end,"\x02\x40",2))return NULL;
    if(!yx_module_expect(q,end,"\x02\x40\x02\x40\x20\x00\x0e",7)||!yx_get_uleb(q,&targets)||targets!=(uint64_t)k)return NULL;
    for(int64_t j=0;j<k;++j)if(!yx_get_uleb(q,&target)||target!=(uint64_t)j+1)return NULL;
    if(!yx_module_expect(q,end,"\x00\x0b\x00\x0b",4))return NULL;
    uint32_t *ids=malloc((size_t)k*sizeof(*ids));
    if(!ids)return NULL;
    for(int64_t j=0;j<k;++j) {
        uint64_t depth_back;
        if(!yx_module_expect(q,end,"\x42",1)||!yx_get_sleb_i64(q,&value)||value<0||(uint64_t)value>=physical||
           (j+1<k&&(!yx_module_expect(q,end,"\x0c",1)||!yx_get_uleb(q,&depth_back)||depth_back!=(uint64_t)(k-1-j)))||
           !yx_module_expect(q,end,"\x0b",1)){free(ids);return NULL;}
        ids[j]=(uint32_t)value;
    }
    return ids;
}
static size_t yx_module_block_tail(const uint8_t *data,size_t at,size_t end,const uint8_t *tail,size_t tail_length);
/* The instructions [at, stop) of `data` as one block, with `suffix` (0 for
 * none) appended before its end: a node, or -1 with its nodes released. */
static int yx_module_slice_decode(const uint8_t *data,size_t at,size_t stop,uint8_t suffix,yx_module_program *p,
                                  unsigned depth,int undefined_slot)
{
    yx_writer slice={0};size_t saved_count=p->count;
    if(stop<at||!yx_put_bytes(&slice,data+at,stop-at)||(suffix&&!yx_put_u8(&slice,suffix))||!yx_put_u8(&slice,0x0b)) {
        free(slice.data);p->failed=true;return -1;
    }
    yx_reader inner={slice.data,slice.used,0,false,false};
    int saved=p->undefined_slot;p->undefined_slot=undefined_slot;
    int node=yx_module_decode_block(&inner,inner.length,p,depth+1);
    p->undefined_slot=saved;
    bool whole=node>=0&&inner.at==inner.length;
    free(slice.data);
    if(whole)return node;
    for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
    p->count=saved_count;return -1;
}
/* yx_module_quantity_emit's initialization at `q`: true with *kind 3 or 4,
 * the quantity's node and `q` after it; false (`q` unchanged) when absent.
 * The quantity's code ends at max_count's store, after a percentage's select
 * of a negative quantity and its conversion. */
static bool yx_module_quantity_decode(yx_reader *q,size_t end,yx_module_program *p,unsigned depth,
                                      int64_t n,int64_t max_count,int64_t count,uint8_t *kind,int *quantity)
{
    yx_reader r=*q;int64_t address;bool found=false;size_t saved_count=p->count;
    if(!yx_module_expect(&r,end,"\x41",1)||!yx_get_sleb_i64(&r,&address)||address!=max_count*8)return false;
    yx_writer prefix={0},tail={0},select={0};
    bool ok=yx_module_load_variable(&prefix,n,3)&&yx_put_u8(&prefix,0xb9)&&yx_put_bytes(&select,"\x22\x00\x42",3)&&
        yx_put_sleb_i64(&select,INT64_MAX)&&yx_put_bytes(&select,"\x20\x00\x42\x00\x59\x1b",6);
    for(unsigned percentage=0;ok&&!found&&percentage<2;++percentage) {
        yx_reader v=r;tail.used=0;
        if(percentage&&!yx_module_expect(&v,end,(const char *)prefix.data,prefix.used))continue;
        if(percentage&&(!yx_put_u8(&tail,0xa2)||!yx_put_u8(&tail,0x44)||!yx_put_float(&tail,100.0)||
                        !yx_put_bytes(&tail,"\xa3\x9b\xfc\x06",4))){ok=false;break;}
        if(!yx_module_var_store(&tail)||!yx_module_var_set(&tail,count,0)){ok=false;break;}
        size_t finish=yx_module_block_tail(v.data,v.at,end,tail.data,tail.used),stop=finish;
        if(finish==SIZE_MAX||finish==v.at)continue;
        bool selected=false;uint8_t conversion=0;
        if(percentage) {
            conversion=v.data[--stop];
            if(stop==v.at||(conversion!=0xb9&&conversion!=0xba))continue;
            selected=stop-v.at>select.used&&!memcmp(v.data+stop-select.used,select.data,select.used);
            if(selected)stop-=select.used;
        }
        int node=yx_module_slice_decode(v.data,v.at,stop,0,p,depth,yx_integer_undefined_shift(p->undefined_slot,1));
        if(node<0){if(p->failed)break;continue;}
        const yx_module_node *value=&p->nodes[node];
        if(value->type!=3||(percentage&&(selected==yx_module_non_negative(value)||
                                         conversion!=(value->unsigned_value?0xba:0xb9)))) {
            for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
            p->count=saved_count;continue;
        }
        *kind=percentage?4:3;*quantity=node;q->at=finish+tail.used;found=true;
    }
    free(prefix.data);free(tail.data);free(select.data);
    if(!ok)p->failed=true;
    return found;
}
/* The body of an emit_for loop at `q` (inside its `loop`), with or without
 * its catch block: it ends at the earliest quantifier tail of the frame at
 * `base` (a nested loop has a higher frame). `owner` is the `for .. of`
 * node that anonymous operands refer to, or -1. */
static int yx_module_loop_body_decode(yx_reader *q,size_t end,yx_module_program *p,unsigned depth,bool counted,
                                      int64_t base,int64_t after,int owner,uint8_t *kind,size_t *finish)
{
    yx_module_patterns *c=p->extension;size_t saved_count=p->count;
    for(int with_catch=1;with_catch>=0;--with_catch) {
        yx_reader b=*q;
        if(with_catch&&!yx_module_expect(&b,end,"\x02\x40",2))continue;
        size_t body_start=b.at,best=SIZE_MAX,best_length=0;uint8_t best_kind=0;
        for(uint8_t candidate=counted?3:0;candidate<=(counted?3:2);++candidate) {
            yx_writer tail={0};
            if(!yx_module_for_tail(candidate,with_catch!=0,&tail,base,base+1,base+2,base+3,after)){free(tail.data);p->failed=true;return -1;}
            for(size_t s=body_start;s<best&&tail.used<=end-s;++s)
                if(!memcmp(b.data+s,tail.data,tail.used)){best=s;best_length=tail.used;best_kind=candidate;break;}
            free(tail.data);
        }
        if(best==SIZE_MAX||best==body_start)continue;
        yx_writer slice={0};
        if(!yx_put_bytes(&slice,b.data+body_start,best-body_start)||!yx_put_u8(&slice,0x0b)){free(slice.data);p->failed=true;return -1;}
        yx_reader inner={slice.data,slice.used,0,false,false};
        int saved=c->for_of,saved_slot=p->undefined_slot;
        if(owner>=0)c->for_of=owner;
        p->undefined_slot=with_catch?-34:-1;
        int body=yx_module_decode_block(&inner,inner.length,p,depth+1);
        c->for_of=saved;p->undefined_slot=saved_slot;
        free(slice.data);
        if(body>=0&&inner.at==inner.length&&p->nodes[body].type>=1&&p->nodes[body].type<=3) {
            *kind=best_kind;*finish=best+best_length;return body;
        }
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;
        if(p->failed)return -1;
    }
    return -1;
}
/* A `for .. of` loop: its frame, quantifier and set prefix the body, and the
 * body ends at the earliest quantifier tail of that frame (a nested loop
 * has a higher frame). The body decodes with the loop as the item owner. */
static int yx_module_pattern_for_of_decode(yx_reader *r,size_t end,yx_module_program *p,unsigned depth)
{
    yx_module_patterns *c=p->extension;yx_reader q=*r;int64_t address,k,value;
    if(end-q.at<6||memcmp(q.data+q.at,"\x02\x7f\x41",3))return -1;
    q.at+=3;
    if(!yx_get_sleb_i64(&q,&address)||address<0||address%8||address/8>YX_ARCHIVE_MAX_VARS-5)return -1;
    int64_t base=address/8;q.at=r->at+2;
    if(!yx_module_expect_store(&q,end,base,&k)||k<1||k>(int64_t)(end-q.at)||
       !yx_module_expect_store(&q,end,base+1,&value)||value)return -1;
    size_t quantity_count=p->count;uint8_t quantity_kind=0;int quantity=-1;
    bool counted=yx_module_quantity_decode(&q,end,p,depth,base,base+2,base+3,&quantity_kind,&quantity);
    if(p->failed)return -1;
    yx_writer prefix={0};
    bool ok=yx_put_bytes(&prefix,"\x03\x40",2)&&yx_put_u8(&prefix,0x41)&&yx_put_sleb_i64(&prefix,(base+4)*8)&&
        yx_module_load_variable(&prefix,base+1,3);
    ok=ok&&yx_module_expect(&q,end,(const char *)prefix.data,prefix.used);free(prefix.data);
    uint32_t *ids=ok?yx_module_switch_decode(&q,end,k,c->archive->physical):NULL;
    if(!ids||!yx_module_expect(&q,end,"\x37\x03\x80\x02",4)) {
        free(ids);for(size_t i=quantity_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=quantity_count;return -1;
    }
    size_t saved_count=quantity_count,finish;uint8_t kind;
    int node=-1,body=-1;
    node=yx_module_node_new(p,YX_MP_FOR_OF,1);
    if(node>=0) {
        p->nodes[node].integer=base;
        body=yx_module_loop_body_decode(&q,end,p,depth,counted,base,-1,node,&kind,&finish);
    }
    if(body<0) {
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;free(ids);return -1;
    }
    p->nodes[node].comparison=counted?quantity_kind:kind;p->nodes[node].bytes=(uint8_t *)ids;p->nodes[node].length=(size_t)k;
    p->nodes[node].args[0]=body;p->nodes[node].argc=1;
    if(quantity>=0){p->nodes[node].args[1]=quantity;p->nodes[node].argc=2;}
    r->at=finish;return node;
}
/* Skip one instruction of a function body (the immediates of
 * yx_wasm_patch_body); `op` receives its opcode. */
static bool yx_module_wasm_next(yx_reader *r,uint8_t *op)
{
    uint64_t v,n;uint8_t o,b;
    if(!yx_get_u8(r,op))return false;
    o=*op;
    if(o==2||o==3||o==4||o==0x0c||o==0x0d||o==0x10||o==0x12||o==0xd2||(o>=0x20&&o<=0x26)||
       o==0x3f||o==0x40||o==0xd0)return yx_get_uleb(r,&v);
    if(o==0x0e) {
        if(!yx_get_uleb(r,&n)||n>r->length-r->at)return false;
        for(uint64_t k=0;k<=n;++k)if(!yx_get_uleb(r,&v))return false;
        return true;
    }
    if(o==0x11||o==0x13||(o>=0x28&&o<=0x3e))return yx_get_uleb(r,&v)&&yx_get_uleb(r,&v);
    if(o==0x1c) {
        if(!yx_get_uleb(r,&n)||n>r->length-r->at)return false;
        r->at+=(size_t)n;return true;
    }
    if(o==0x41||o==0x42) {
        do{if(!yx_get_u8(r,&b))return false;}while(b&0x80);
        return true;
    }
    if(o==0x43||o==0x44) {
        size_t width=o==0x43?4:8;
        if(width>r->length-r->at)return false;
        r->at+=width;return true;
    }
    if(o==0xfc) {
        if(!yx_get_uleb(r,&v))return false;
        if(v<=7)return true;
        if(v==8||v==10||v==12||v==14)return yx_get_uleb(r,&n)&&yx_get_uleb(r,&n);
        return (v==9||v==11||v==13||(v>=15&&v<=17))&&yx_get_uleb(r,&n);
    }
    return o<=1||o==5||o==0x0b||o==0x0f||o==0x1a||o==0x1b||o==0xd1||(o>=0x45&&o<=0xc4);
}
/* The first instruction boundary in [at, end), at the nesting level of
 * `at`, where `tail` starts; SIZE_MAX when the enclosing block ends first. */
static size_t yx_module_block_tail(const uint8_t *data,size_t at,size_t end,const uint8_t *tail,size_t tail_length)
{
    yx_reader r={data,end,at,false,false};size_t depth=0;uint8_t op;
    while(r.at<end) {
        if(!depth&&tail_length<=end-r.at&&!memcmp(data+r.at,tail,tail_length))return r.at;
        if(!yx_module_wasm_next(&r,&op))return SIZE_MAX;
        if(op==2||op==3||op==4)++depth;
        else if(op==0x0b){if(!depth)return SIZE_MAX;--depth;}
    }
    return SIZE_MAX;
}
/* A `for .. in (a..b)` loop (yx_module_pattern_range_emit). The bounds end
 * at the store into the two i64 temporaries; they decode as one comparison
 * of the two values (an appended `i64.eq`). */
static int yx_module_pattern_range_decode(yx_reader *r,size_t end,yx_module_program *p,unsigned depth)
{
    static const uint8_t caught[]={0x21,0,0x21,1,0x0b,0x20,1,0x20,0,0x53},plain[]={0x21,0,0x21,1,0x20,1,0x20,0,0x53};
    if(end-r->at<8||r->data[r->at]!=0x02||r->data[r->at+1]!=0x7f)return -1;
    size_t saved_count=p->count;
    for(int bounds_catch=1;bounds_catch>=0;--bounds_catch) {
        yx_reader q=*r;q.at+=2;
        if(bounds_catch&&!yx_module_expect(&q,end,"\x02\x40",2))continue;
        const uint8_t *tail=bounds_catch?caught:plain;size_t tail_length=bounds_catch?sizeof(caught):sizeof(plain);
        /* Every result block is offered here: the bounds' tail lies at the
         * block's own level, so a block costs a walk over its own
         * instructions, whatever the length of its bounds. */
        size_t bounds=q.at,s=yx_module_block_tail(q.data,bounds,end,tail,tail_length);
        if(s==SIZE_MAX||s==bounds)continue;
        yx_writer slice={0};
        if(!yx_put_bytes(&slice,q.data+bounds,s-bounds)||!yx_put_bytes(&slice,"\x51\x0b",2)){free(slice.data);p->failed=true;return -1;}
        yx_reader inner={slice.data,slice.used,0,false,false};
        int saved_slot=p->undefined_slot;p->undefined_slot=bounds_catch?-33:-1;
        int pair=yx_module_decode_block(&inner,inner.length,p,depth+1);
        p->undefined_slot=saved_slot;free(slice.data);
        int upper=-1,lower=-1,quantity=-1,body=-1,node=-1;
        int64_t address,base=0;bool counted=false,ok=false;uint8_t quantity_kind=0;
        if(pair>=0&&inner.at==inner.length&&p->nodes[pair].op==YX_ME_COMPARE) {
            upper=p->nodes[pair].args[0];lower=p->nodes[pair].args[1];
            /* The comparison only joined the bounds: it must not look like a
             * parent of `#a` (yx_module_pattern_limits). */
            p->nodes[pair].op=YX_ME_BOOL;p->nodes[pair].constant=true;
            q.at=s+tail_length;
            bool lower_unsigned=yx_module_expect(&q,end,"\x20\x00\x42\x00\x53\x72",6);
            bool upper_unsigned=yx_module_expect(&q,end,"\x20\x01\x42\x00\x53\x72",6);
            ok=p->nodes[lower].type==3&&p->nodes[upper].type==3&&
                lower_unsigned==p->nodes[lower].unsigned_value&&upper_unsigned==p->nodes[upper].unsigned_value&&
                yx_module_expect(&q,end,"\x04\x40\x41\x00\x0c\x01\x05\x0b\x41",9)&&yx_get_sleb_i64(&q,&address)&&
                address>=0&&!(address%8)&&address/8<=YX_ARCHIVE_MAX_VARS-7;
        }
        if(ok) {
            base=address/8;
            yx_writer expected={0};
            ok=yx_put_u8(&expected,0x42)&&yx_put_sleb_i64(&expected,INT64_MAX)&&
                yx_put_bytes(&expected,"\x20\x01\x20\x00\x7d\x42\x01\x7c\x20\x01\x20\x00\x7d\x42",14)&&
                yx_put_sleb_i64(&expected,INT64_MAX)&&yx_put_bytes(&expected,"\x5a\x1b",2)&&yx_module_var_store(&expected)&&
                yx_put_u8(&expected,0x41)&&yx_put_sleb_i64(&expected,(base+5)*8)&&yx_put_bytes(&expected,"\x20\x00",2)&&
                yx_module_var_store(&expected)&&yx_module_var_set(&expected,base+1,0)&&
                yx_module_expect(&q,end,(const char *)expected.data,expected.used);
            free(expected.data);
        }
        if(ok) {
            counted=yx_module_quantity_decode(&q,end,p,depth,base,base+2,base+3,&quantity_kind,&quantity);
            ok=!p->failed&&yx_module_expect(&q,end,"\x03\x40",2);
        }
        size_t finish=0;uint8_t kind=0;
        if(ok&&(!counted||quantity>=0)) {
            int64_t slot=base+5;uint8_t type=p->slot_types[slot];
            bool defined=p->slot_defined[slot],is_unsigned=p->slot_unsigned[slot];
            const yx_archive_module_field *field=p->slot_fields[slot];
            p->slot_types[slot]=3;p->slot_defined[slot]=true;p->slot_unsigned[slot]=false;p->slot_fields[slot]=NULL;
            body=yx_module_loop_body_decode(&q,end,p,depth,counted,base,base+5,-1,&kind,&finish);
            p->slot_types[slot]=type;p->slot_defined[slot]=defined;p->slot_unsigned[slot]=is_unsigned;p->slot_fields[slot]=field;
        }
        if(body>=0&&(node=yx_module_node_new(p,YX_MP_RANGE,1))>=0) {
            yx_module_node *n=&p->nodes[node];
            n->comparison=counted?quantity_kind:kind;n->integer=base;n->args[0]=lower;n->args[1]=upper;n->args[2]=body;n->argc=3;
            if(quantity>=0){n->args[3]=quantity;n->argc=4;}
            r->at=finish;return node;
        }
        for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
        p->count=saved_count;
        if(p->failed)return -1;
    }
    return -1;
}
/* The tail of an emit_for loop at `q` for a quantifier that is not counted
 * (0 any, 1 all, 2 none) or counted (3); *kind receives it. */
static bool yx_module_tail_decode(yx_reader *q,size_t end,bool counted,bool caught,int64_t n,int64_t i,
                                  int64_t max_count,int64_t count,uint8_t *kind)
{
    for(uint8_t candidate=counted?3:0;candidate<=(counted?3:2);++candidate) {
        yx_writer tail={0};
        bool matched=yx_module_for_tail(candidate,caught,&tail,n,i,max_count,count,-1)&&
            yx_module_expect(q,end,(const char *)tail.data,tail.used);
        free(tail.data);
        if(matched){*kind=candidate;return true;}
    }
    return false;
}
/* emit_switch's header at `q` for `k` branches of Wasm type `type`. */
static bool yx_module_switch_open_decode(yx_reader *q,size_t end,yx_module_program *p,uint8_t type,int64_t k)
{
    yx_writer expected={0};bool i32_local=p->i32_local;
    bool ok=k>=1&&(uint64_t)k<=end-q->at&&yx_module_switch_open(p,&expected,type,(size_t)k)&&
        yx_module_expect(q,end,(const char *)expected.data,expected.used);
    p->i32_local=i32_local;free(expected.data);return ok;
}
/* The `k` branches of an emit_switch at `q`, each one node decoded with the
 * undefined slot that `slot_of` gives for its position; the nodes go to
 * `items`. */
static bool yx_module_switch_branches_decode(yx_reader *q,size_t end,yx_module_program *p,unsigned depth,int64_t k,
                                             int first_slot,bool loop_item,int *items)
{
    for(int64_t j=0;j<k;++j) {
        yx_writer close={0};
        if(!yx_module_switch_close(&close,(size_t)j,(size_t)k)){free(close.data);p->failed=true;return false;}
        size_t stop=yx_module_block_tail(q->data,q->at,end,close.data,close.used);
        int slot=loop_item?yx_integer_undefined_shift(first_slot,(unsigned)(k-j)):
                           yx_integer_undefined_shift(first_slot,(unsigned)(k-j+2));
        int node=stop==SIZE_MAX||stop==q->at?-1:yx_module_slice_decode(q->data,q->at,stop,0,p,depth,slot);
        if(node>=0)q->at=stop;
        bool ok=node>=0&&yx_module_expect(q,end,(const char *)close.data,close.used);
        free(close.data);
        if(!ok)return false;
        items[j]=node;
    }
    return true;
}
/* The loop form of an `of` (emit_of_pattern_set_with_loop: a set whose body
 * checks the item with the helper or an anchor; emit_of_expr_tuple: Boolean
 * elements whose item is the body). -1 when absent. */
static int yx_module_pattern_of_loop_decode(yx_reader *r,size_t end,yx_module_program *p,unsigned depth)
{
    yx_module_patterns *c=p->extension;yx_reader q=*r;int64_t address,k,value;
    if(end-q.at<6||memcmp(q.data+q.at,"\x02\x7f\x41",3))return -1;
    q.at+=3;
    if(!yx_get_sleb_i64(&q,&address)||address<8||address%8||address/8-1>YX_ARCHIVE_MAX_VARS-5)return -1;
    int64_t base=address/8-1;q.at=r->at+2;
    if(!yx_module_expect_store(&q,end,base+1,&k)||k<1||k>(int64_t)(end-q.at)||
       !yx_module_expect_store(&q,end,base+2,&value)||value)return -1;
    size_t saved_count=p->count;uint8_t kind=0,quantity_kind=0;int quantity=-1,node=-1;uint32_t *ids=NULL;int *items=NULL;
    bool counted=yx_module_quantity_decode(&q,end,p,depth,base+1,base+3,base+4,&quantity_kind,&quantity);
    yx_writer prefix={0};
    bool ok=!p->failed&&yx_put_bytes(&prefix,"\x03\x40",2)&&yx_put_u8(&prefix,0x41)&&yx_put_sleb_i64(&prefix,base*8)&&
        yx_module_load_variable(&prefix,base+2,3)&&yx_module_expect(&q,end,(const char *)prefix.data,prefix.used);
    free(prefix.data);
    if(ok&&end-q.at>5&&!memcmp(q.data+q.at,"\xa7\x21\x00\x02\x7f",5)) {
        /* Boolean elements, then the item as the body. */
        items=malloc((size_t)k*sizeof(*items));
        ok=items&&yx_module_switch_open_decode(&q,end,p,0x7f,k)&&
            yx_module_switch_branches_decode(&q,end,p,depth,k,p->undefined_slot,false,items);
        for(int64_t j=0;ok&&j<k;++j)ok=p->nodes[items[j]].type>=1&&p->nodes[items[j]].type<=4;
        yx_writer item={0};
        ok=ok&&yx_module_store_value(&item,1)&&yx_module_load_variable(&item,base,1)&&
            yx_module_expect(&q,end,(const char *)item.data,item.used)&&
            yx_module_tail_decode(&q,end,counted,false,base+1,base+2,base+3,base+4,&kind);
        free(item.data);
        if(ok&&(node=yx_module_node_new(p,YX_MP_TUPLE_OF,1))>=0) {
            yx_module_node *n=&p->nodes[node];
            n->comparison=counted?quantity_kind:kind;n->integer=base;n->bytes=(uint8_t *)items;n->length=(size_t)k;items=NULL;
            if(quantity>=0){n->args[0]=quantity;n->argc=1;}
            r->at=q.at;return node;
        }
        goto fail;
    }
    ids=ok?yx_module_switch_decode(&q,end,k,c->archive->physical):NULL;
    yx_writer item={0};
    bool caught=false;
    ok=ids&&yx_module_expect(&q,end,"\x37\x03\x80\x02",4);
    if(ok){caught=yx_module_expect(&q,end,"\x02\x40",2);ok=yx_module_load_variable(&item,base,3)&&yx_put_u8(&item,0xa7)&&
        yx_module_expect(&q,end,(const char *)item.data,item.used);}
    free(item.data);
    uint8_t anchor=0;int args[3],argc=0;
    if(quantity>=0)args[argc++]=quantity;
    if(ok&&!(c->presence&&end-q.at>=2&&q.data[q.at]==0x10&&q.data[q.at+1]==c->helper_id)) {
        /* An anchor's operands and is_pat_match_at/_in. */
        size_t at_id=SIZE_MAX,in_id=SIZE_MAX,stop=SIZE_MAX;
        for(size_t i=0;i<p->import_count;++i) {
            if(!strcmp(p->imports[i].name,yx_pattern_expression_symbols[yx_pattern_expression_symbol(0xd5)]))at_id=i;
            if(!strcmp(p->imports[i].name,yx_pattern_expression_symbols[yx_pattern_expression_symbol(0xd6)]))in_id=i;
        }
        yx_reader walk=q;uint8_t op;size_t level=0;
        while(walk.at<end&&stop==SIZE_MAX) {
            size_t at=walk.at;uint64_t id;
            if(!level&&walk.data[at]==0x10) {
                yx_reader call=walk;++call.at;
                if(yx_get_uleb(&call,&id)&&(id==at_id||id==in_id)){stop=at;anchor=id==at_id?1:2;break;}
            }
            if(!yx_module_wasm_next(&walk,&op))break;
            if(op==2||op==3||op==4)++level;
            else if(op==0x0b){if(!level)break;--level;}
        }
        int operand=stop==SIZE_MAX?-1:yx_module_slice_decode(q.data,q.at,stop,anchor==2?0x51:0,p,depth,-34);
        if(operand<0)ok=false;
        else if(anchor==1)args[argc++]=operand;
        else if(p->nodes[operand].op==YX_ME_COMPARE) {
            args[argc++]=p->nodes[operand].args[0];args[argc++]=p->nodes[operand].args[1];
            p->nodes[operand].op=YX_ME_BOOL;p->nodes[operand].constant=true;
        }
        else ok=false;
        if(ok){q.at=stop;ok=yx_module_expect(&q,end,"\x10",1)&&yx_get_uleb(&q,&(uint64_t){0});}
    } else if(ok) q.at+=2;
    ok=ok&&yx_module_tail_decode(&q,end,counted,caught,base+1,base+2,base+3,base+4,&kind);
    if(ok&&(node=yx_module_node_new(p,YX_MP_OF,1))>=0) {
        yx_module_node *n=&p->nodes[node];
        n->comparison=(uint8_t)((counted?quantity_kind:kind)|anchor<<4);n->bytes=(uint8_t *)ids;n->length=(size_t)k;ids=NULL;
        n->integer=base;n->argc=(uint8_t)argc;memcpy(n->args,args,(size_t)argc*sizeof(int));
        /* Regenerate with the module's helper index and compare. */
        yx_writer expected={0};size_t calls=c->helper_call_count;bool searched=c->searched,i32_local=p->i32_local;
        c->searched=true;
        ok=yx_module_pattern_of_loop(n)&&yx_module_pattern_of_loop_emit(p,node,&expected,depth+1)&&
            yx_module_pattern_relocate_helper(&expected,c->helper_calls+calls,c->helper_call_count-calls,c->helper_id);
        c->helper_call_count=calls;c->searched=searched;p->i32_local=i32_local;
        ok=ok&&expected.used==q.at-r->at&&!memcmp(r->data+r->at,expected.data,expected.used);
        free(expected.data);
        if(ok){r->at=q.at;return node;}
    }
fail:
    free(ids);free(items);
    for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
    p->count=saved_count;return -1;
}
/* A `for .. in (<e1>, <e2>, ..)` loop (yx_module_pattern_tuple_emit). The
 * switch's type tells integers (or strings) from floats and Booleans; the
 * literal ids of string constants decode as integers until the body
 * rejects that type. */
static int yx_module_pattern_tuple_decode(yx_reader *r,size_t end,yx_module_program *p,unsigned depth)
{
    yx_reader q=*r;int64_t address,k,value;
    if(end-q.at<6||memcmp(q.data+q.at,"\x02\x7f\x41",3))return -1;
    q.at+=3;
    if(!yx_get_sleb_i64(&q,&address)||address<0||address%8||address/8>YX_ARCHIVE_MAX_VARS-7)return -1;
    int64_t base=address/8;q.at=r->at+2;
    if(!yx_module_expect_store(&q,end,base,&k)||k<1||k>(int64_t)(end-q.at)||
       !yx_module_expect_store(&q,end,base+1,&value)||value)return -1;
    size_t saved_count=p->count;uint8_t quantity_kind=0,kind=0;int quantity=-1,node=-1;int *items=NULL;
    bool counted=yx_module_quantity_decode(&q,end,p,depth,base,base+2,base+3,&quantity_kind,&quantity);
    bool ok=!p->failed&&yx_module_expect(&q,end,"\x03\x40",2),caught=ok&&yx_module_expect(&q,end,"\x02\x40",2);
    yx_writer prefix={0};
    ok=ok&&yx_put_u8(&prefix,0x41)&&yx_put_sleb_i64(&prefix,(base+5)*8)&&yx_module_load_variable(&prefix,base+1,3)&&
        yx_module_expect(&q,end,(const char *)prefix.data,prefix.used)&&end-q.at>5;
    free(prefix.data);
    uint8_t wasm_type=ok?q.data[q.at+4]:0;
    items=malloc((size_t)k*sizeof(*items));
    ok=ok&&items&&(wasm_type==0x7e||wasm_type==0x7c||wasm_type==0x7f)&&yx_module_switch_open_decode(&q,end,p,wasm_type,k)&&
        yx_module_switch_branches_decode(&q,end,p,depth,k,(int)(base+5),true,items);
    uint8_t type=wasm_type==0x7c?2:wasm_type==0x7f?1:3;bool strings=false,literals=true,is_unsigned=false;
    for(int64_t j=0;ok&&j<k;++j) {
        const yx_module_node *item=&p->nodes[items[j]];
        if(item->type==4)strings=true;
        literals&=item->type==4||(item->op==YX_ME_INT&&item->integer>=0&&!(item->integer%4)&&(uint64_t)item->integer/4<p->literal_count);
        is_unsigned|=item->unsigned_value;
        ok=item->type==type||(type==3&&item->type==4)||(type==3&&item->type==3);
    }
    if(ok&&strings){ok=literals;type=4;for(int64_t j=0;ok&&j<k;++j)ok=yx_module_decode_string(p,items[j]);}
    yx_writer store={0};
    ok=ok&&yx_module_store_value(&store,type)&&(!caught||(yx_integer_clear_variable(&store,base+5)&&yx_put_u8(&store,0x0b)))&&
        yx_module_expect(&q,end,(const char *)store.data,store.used);
    free(store.data);
    int body=-1;size_t finish=0,body_count=p->count;
    for(unsigned attempt=0;ok&&body<0&&attempt<2;++attempt) {
        if(attempt) {
            /* String constants: their literal ids decoded as integers. */
            if(type!=3||!literals)break;
            for(size_t i=body_count;i<p->count;++i)free(p->nodes[i].bytes);
            p->count=body_count;type=4;
            for(int64_t j=0;ok&&j<k;++j)ok=yx_module_decode_string(p,items[j]);
            if(!ok)break;
        }
        int64_t slot=base+5;uint8_t old_type=p->slot_types[slot];
        bool defined=p->slot_defined[slot],old_unsigned=p->slot_unsigned[slot];
        const yx_archive_module_field *field=p->slot_fields[slot];
        p->slot_types[slot]=type;p->slot_defined[slot]=!caught;p->slot_unsigned[slot]=is_unsigned&&type==3;p->slot_fields[slot]=NULL;
        body=yx_module_loop_body_decode(&q,end,p,depth,counted,base,-1,-1,&kind,&finish);
        p->slot_types[slot]=old_type;p->slot_defined[slot]=defined;p->slot_unsigned[slot]=old_unsigned;p->slot_fields[slot]=field;
        if(p->failed)break;
    }
    if(body>=0&&(node=yx_module_node_new(p,YX_MP_TUPLE,1))>=0) {
        yx_module_node *n=&p->nodes[node];
        n->comparison=counted?quantity_kind:kind;n->integer=base;n->bytes=(uint8_t *)items;n->length=(size_t)k;items=NULL;
        n->args[0]=body;n->argc=1;
        if(quantity>=0){n->args[1]=quantity;n->argc=2;}
        r->at=finish;return node;
    }
    free(items);
    for(size_t i=saved_count;i<p->count;++i)free(p->nodes[i].bytes);
    p->count=saved_count;return -1;
}
/* The `for .. of` item as a PatternId operand (yx_module_pattern_id). */
static int yx_module_pattern_item_decode(yx_reader *r,size_t end,yx_module_program *p)
{
    yx_module_patterns *c=p->extension;
    if(c->for_of<0||(size_t)c->for_of>=p->count)return -1;
    yx_writer item={0};
    bool match=yx_module_load_variable(&item,p->nodes[c->for_of].integer+4,3)&&yx_put_u8(&item,0xa7)&&
        item.used<=end-r->at&&!memcmp(r->data+r->at,item.data,item.used);
    if(match)r->at+=item.used;
    free(item.data);
    if(!match)return -1;
    int node=yx_module_node_new(p,YX_MP_ITEM,3);
    if(node>=0)p->nodes[node].integer=-1-(int64_t)c->for_of;
    return node;
}
static int yx_module_pattern_decode_primary(yx_reader *r,size_t end,yx_module_program *p,unsigned depth)
{
    (void)depth;yx_module_patterns *c=p->extension;
    {int of=yx_module_pattern_of_loop_decode(r,end,p,depth);if(of>=0)return of;}
    {int loop=yx_module_pattern_for_of_decode(r,end,p,depth);if(loop>=0)return loop;}
    {int loop=yx_module_pattern_range_decode(r,end,p,depth);if(loop>=0)return loop;}
    {int loop=yx_module_pattern_tuple_decode(r,end,p,depth);if(loop>=0)return loop;}
    {int item=yx_module_pattern_item_decode(r,end,p);if(item>=0)return item;}
    for(size_t i=0;i<p->import_count;++i)if(!strcmp(p->imports[i].name,"search_for_patterns@@")) {
        uint8_t guard[]={0x23,c->search_global,4,0x40,5,0x10,(uint8_t)i,0x0b};
        if(sizeof(guard)<=end-r->at&&!memcmp(r->data+r->at,guard,sizeof(guard))){r->at+=sizeof(guard);++p->decoded_guards;return -2;}
    }
    p->extension=&c->prior;int n=yx_global_rule_decode(r,end,p,depth);p->extension=c;return n;
}
static int yx_module_pattern_decode_call(yx_reader *r,size_t end,yx_module_program *p,uint64_t id,int *stack,size_t *used)
{
    yx_module_patterns *c=p->extension;unsigned op=0,argc=0;
    if(id<p->import_count&&!strcmp(p->imports[id].module,"yara_x::wasm")&&
       !strcmp(p->imports[id].name,"str_matches@lhs:s,rhs:r@b")) {
        if(*used<2)return -1;
        const yx_module_node *value=&p->nodes[stack[*used-1]];
        if((value->op!=YX_ME_BOOL&&value->op!=YX_ME_INT)||value->integer<0||(uint64_t)value->integer>=c->regex_count||
           !yx_module_decode_string(p,stack[*used-2]))return -1;
        const yx_literal *text=&c->regexes[value->integer];
        int regex=yx_module_node_new(p,YX_MP_REGEX,5),node=regex<0?-1:yx_module_node_new(p,YX_ME_COMPARE,1);
        if(node<0)return -1;
        if(!(p->nodes[regex].bytes=malloc(text->length?text->length:1))){p->failed=true;return -1;}
        if(text->length)memcpy(p->nodes[regex].bytes,text->data,text->length);
        p->nodes[regex].length=text->length;p->nodes[regex].integer=-1;
        p->nodes[node].comparison=13;p->nodes[node].args[0]=stack[*used-2];p->nodes[node].args[1]=regex;
        *used-=2;return node;
    }
    if(id<p->import_count&&!strcmp(p->imports[id].module,"yara_x::wasm")&&
       !strcmp(p->imports[id].name,yx_module_pattern_range_name)) {
        if(*used<3)return -1;
        const yx_module_node *first=&p->nodes[stack[*used-3]],*last=&p->nodes[stack[*used-2]];
        int required=stack[*used-1];
        if((first->op!=YX_ME_BOOL&&first->op!=YX_ME_INT)||(last->op!=YX_ME_BOOL&&last->op!=YX_ME_INT)||
           first->integer<0||last->integer<first->integer||(uint64_t)last->integer>=c->archive->physical||
           p->nodes[required].type!=3)return -1;
        size_t count=(size_t)(last->integer-first->integer)+1;
        uint32_t *ids=malloc(count*sizeof(*ids));if(!ids)return -1;
        for(size_t i=0;i<count;++i)ids[i]=(uint32_t)(first->integer+(int64_t)i);
        const yx_module_node *k=&p->nodes[required];
        uint8_t kind=count==1||k->op!=YX_ME_INT?3:k->integer==1?0:k->integer==(int64_t)count?1:3;
        int node=yx_module_node_new(p,YX_MP_OF,1);
        if(node<0){free(ids);return -1;}
        p->nodes[node].comparison=kind;p->nodes[node].bytes=(uint8_t *)ids;p->nodes[node].length=count;
        if(kind==3){p->nodes[node].argc=1;p->nodes[node].args[0]=required;}
        *used-=3;return node;
    }
    if(c->presence&&id==c->helper_id)op=YX_MP_PRESENT;
    else if(id<p->import_count&&!strcmp(p->imports[id].module,"yara_x::wasm")) {
        for(unsigned i=2;i<=7;++i)if(!strcmp(p->imports[id].name,yx_pattern_expression_symbols[i])){op=YX_MP_PRESENT+i-1;break;}
    }
    if(!op)return -1;
    argc=op==YX_MP_PRESENT||op==YX_MP_COUNT?0:op==YX_MP_IN||op==YX_MP_COUNT_IN?2:1;
    if(*used<argc+1)return -1;
    const yx_module_node *pattern=&p->nodes[stack[*used-argc-1]];
    if(pattern->op==YX_MP_ITEM){if(!yx_module_pattern_owner(p,pattern))return -1;}
    else if((pattern->op!=YX_ME_INT&&pattern->op!=YX_ME_BOOL)||pattern->integer<0||(uint64_t)pattern->integer>=c->archive->physical)return -1;
    if((op==YX_MP_OFFSET||op==YX_MP_LENGTH)&&!yx_integer_wasm_guard(r,end,0x10,p->undefined_slot))return -1;
    int node=yx_module_node_new(p,(uint8_t)op,op==YX_MP_PRESENT||op==YX_MP_AT||op==YX_MP_IN?1:3);
    if(node>=0){p->nodes[node].integer=pattern->integer;p->nodes[node].argc=(uint8_t)argc;memcpy(p->nodes[node].args,stack+*used-argc,argc*sizeof(int));*used-=argc+1;}
    return node;
}
/* An AND/OR chain of pattern checks without a search guard of its own is
 * an `all`/`any` set of several ranges: the set's guard precedes its block
 * and an `any` set leaves its last range without a result block. */
static int yx_module_pattern_decode_set(yx_module_program *p,uint8_t op,int joined,int last,bool bare,bool guarded)
{
    if(guarded||(op!=YX_ME_AND&&op!=YX_ME_OR)||(op==YX_ME_OR&&!bare))return -1;
    size_t count=0,total=0;int *items=yx_module_left_chain(p,joined,op,&count);
    if(!items)return -1;
    uint8_t kind=op==YX_ME_AND?1:0;bool valid=true;
    for(size_t i=0;valid&&i<=count;++i) {
        const yx_module_node *n=&p->nodes[i<count?items[i]:last];
        if(n->op==YX_MP_PRESENT&&n->integer>=0)++total;
        else if(n->op==YX_MP_OF&&n->comparison==kind&&n->length>1)total+=n->length;
        else valid=false;
    }
    uint32_t *ids=valid?malloc(total*sizeof(*ids)):NULL;size_t used=0;
    for(size_t i=0;ids&&i<=count;++i) {
        const yx_module_node *n=&p->nodes[i<count?items[i]:last];
        uint32_t first=n->op==YX_MP_PRESENT?(uint32_t)n->integer:((const uint32_t *)n->bytes)[0];
        /* consecutive_ranges: the next range repeats the last PatternId or
         * starts after a gap. */
        if(used&&(first<ids[used-1]||first==ids[used-1]+1)){free(ids);ids=NULL;break;}
        if(n->op==YX_MP_PRESENT)ids[used++]=first;
        else{memcpy(ids+used,n->bytes,n->length*sizeof(*ids));used+=n->length;}
    }
    free(items);
    if(!ids)return -1;
    int node=yx_module_node_new(p,YX_MP_OF,1);
    if(node<0){free(ids);return -1;}
    p->nodes[node].comparison=kind;p->nodes[node].bytes=(uint8_t *)ids;p->nodes[node].length=used;
    return node;
}
/* Whether a pattern operand or loop cannot throw an undefined value: offsets
 * and lengths can, a quantity and a tuple's Boolean elements reach the
 * handler outside their loop, everything else is caught or defined. */
static bool yx_module_pattern_definite(const yx_module_program *p,int index,unsigned depth)
{
    const yx_module_node *n=&p->nodes[index];
    uint8_t kind=n->comparison&15;
    if(depth>128)return false;
    switch(n->op) {
    case YX_MP_PRESENT:case YX_MP_COUNT:case YX_MP_AT:case YX_MP_IN:case YX_MP_COUNT_IN:
        for(size_t i=0;i<n->argc;++i)if(!yx_module_definite_value(p,n->args[i],depth+1))return false;
        return true;
    case YX_MP_OF:case YX_MP_TUPLE_OF:
        if(kind>=3&&!yx_module_definite_value(p,n->args[0],depth+1))return false;
        if(n->op==YX_MP_TUPLE_OF)
            for(size_t i=0;i<n->length;++i)if(!yx_module_definite_value(p,((const int *)n->bytes)[i],depth+1))return false;
        return true;
    case YX_MP_FOR_OF:case YX_MP_TUPLE:return kind<3||yx_module_definite_value(p,n->args[1],depth+1);
    case YX_MP_RANGE:return kind<3||yx_module_definite_value(p,n->args[3],depth+1);
    case YX_MP_REGEX:case YX_MP_ITEM:case YX_GLOBAL_RULE_REFERENCE:return true;
    default:return false;
    }
}
static void yx_module_pattern_setup(yx_module_program *p,yx_module_patterns *c)
{
    p->extension=c;p->parse_primary=yx_module_pattern_primary;p->emit_primary=yx_module_pattern_emit;
    p->print_primary=yx_module_pattern_print;p->decode_primary=yx_module_pattern_decode_primary;
    p->decode_call=yx_module_pattern_decode_call;p->boolean_scope=yx_module_pattern_scope;
    p->decode_set=yx_module_pattern_decode_set;p->definite_primary=yx_module_pattern_definite;c->for_of=-1;
    /* Regexp arguments of module functions share the pool of `matches`. */
    p->regexes=&c->regexes;p->regex_count=&c->regex_count;p->regex_capacity=&c->regex_capacity;
}

static bool yx_module_pattern_live_globals(yx_module_program *p,int root)
{
    yx_module_patterns *c=p->extension;
    if(root<0||(size_t)root>=p->count)return false;
    if(p->count>SIZE_MAX/sizeof(size_t))return false;
    bool *live=calloc(p->count,sizeof(*live));
    size_t *pending=malloc(p->count*sizeof(*pending)),used=0;
    if(!live||!pending){free(live);free(pending);return false;}
    live[root]=true;pending[used++]=(size_t)root;
    c->presence=c->pattern_search=false;p->filesize=false;
    bool ok=true;
    /* Prefix operators are allocated before their operands by the parser.
     * Follow reachable edges rather than assuming a node allocation order. */
    while(used&&ok) {
        size_t i=pending[--used];
        const yx_module_node *n=&p->nodes[i];size_t children=0;
        c->presence|=n->op==YX_MP_PRESENT;p->filesize|=n->op==YX_ME_FILESIZE;
        c->pattern_search|=n->op>=YX_MP_PRESENT&&n->op<=YX_MP_OF;
        if(n->op==YX_MP_OF&&n->bytes) {
            size_t ranges=0;uint32_t *ids=yx_module_pattern_of_loop(n)?NULL:n->comparison!=3?yx_module_pattern_of_sorted(n,&ranges):NULL;
            if(yx_module_pattern_of_loop(n)&&!(n->comparison>>4))c->presence=true;
            for(size_t k=0;ids&&k<n->length;++k)
                if((!k||ids[k]!=ids[k-1]+1)&&(k+1==n->length||ids[k+1]!=ids[k]+1))c->presence=true;
            free(ids);
        }
        switch(n->op) {
        case YX_ME_MEMBER:case YX_ME_NOT:case YX_ME_LENGTH:case YX_ME_GROUP:case YX_ME_READ:case YX_ME_DEFINED:children=1;break;
        case YX_ME_LOOP:case YX_ME_BIND:case YX_ME_COMPARE:case YX_ME_AND:case YX_ME_OR:case YX_ME_ARITH:case YX_ME_INDEX:children=2;break;
        case YX_ME_CALL:children=n->argc;break;
        default:if(n->op>=YX_MP_PRESENT&&n->op<=YX_MP_TUPLE_OF)children=n->argc;break;
        }
        size_t elements=n->op==YX_MP_TUPLE||n->op==YX_MP_TUPLE_OF?n->length:0;
        for(size_t j=0;j<children+elements;++j) {
            int child=j<children?n->args[j]:((const int *)n->bytes)[j-children];
            if(child<0||(size_t)child>=p->count){ok=false;break;}
            if(!live[child]){live[child]=true;pending[used++]=(size_t)child;}
        }
    }
    free(pending);free(live);return ok;
}
static bool yx_module_pattern_wasm(yx_module_program *p, int root, uint8_t **data, size_t *length)
{
    yx_module_patterns *c=p->extension;
    c->searched=false;c->scope_depth=0;c->helper_call_count=0;
    p->import_count=0;p->call_count=0;p->i32_local=false;p->two_locals=false;p->shift=false;p->shifts=true;
    if(!yx_module_pattern_live_globals(p,root))return false;
    p->filesize_global=c->presence?1:0;c->search_global=(uint8_t)(c->presence+p->filesize);p->memory|=c->presence;
    yx_writer expression = {0}, types = {0}, imports = {0}, body = {0}, code = {0}, wasm = {0}, wrapper={0}, main_body={0}, exports={0};
    yx_module_import unique[YX_MODULE_IMPORTS + 3];
    size_t type_count = 3;
    uint8_t order[YX_MODULE_IMPORTS];
    static const uint8_t magic[] = {0,0x61,0x73,0x6d,1,0,0,0};
    yx_writer functions={0};
    const uint8_t match_arg = 0x7f;
    memset(unique, 0, sizeof(unique));
    p->undefined_slot = -1;
    bool ok = yx_module_root_boolean(p, root, &expression);
    int match = ok ? yx_module_import_add(p, "yara_x::wasm", "rule_match@rule_id:i@", &match_arg, 1, 0, false) : -1;
    bool global_rule=false;
    for(size_t i=0;i<c->prior.count;++i)global_rule|=c->prior.rules[i].is_global;
    if(global_rule&&yx_module_import_add(p,"yara_x::wasm","rule_no_match@rule_id:i@",&match_arg,1,0,false)<0)ok=false;
    if (!ok || match < 0 || p->import_count > YX_MODULE_IMPORTS) { ok = false; goto done; }
    unique[1].resultc = 1; unique[1].results[0] = 0x7f;
    unique[2].argc = 1; unique[2].args[0] = 0x7f;
    if(c->presence){unique[3].argc=1;unique[3].args[0]=0x7f;unique[3].resultc=1;unique[3].results[0]=0x7f;type_count=4;}
    for (size_t i = 0; i < p->import_count; ++i) {
        size_t type;
        for (type = 0; type < type_count; ++type)
            if (yx_module_type_equal(&p->imports[i], &unique[type])) break;
        if (type == type_count) unique[type_count++] = p->imports[i];
        order[i] = (uint8_t)i;
    }
    for (size_t i = 1; i < type_count; ++i) {
        yx_module_import item = unique[i]; size_t j = i;
        while (j && yx_module_type_compare(&unique[j - 1], &item) > 0) { unique[j] = unique[j - 1]; --j; }
        unique[j] = item;
    }
    for (size_t i = 0; i < p->import_count; ++i)
        for (size_t type = 0; type < type_count; ++type)
            if (yx_module_type_equal(&p->imports[i], &unique[type])) { p->imports[i].type = (uint8_t)type; break; }
    for (size_t i = 1; i < p->import_count; ++i) {
        uint8_t item = order[i]; size_t j = i;
        while (j && p->imports[order[j - 1]].rank > p->imports[item].rank) { order[j] = order[j - 1]; --j; }
        order[j] = item;
    }
    for (size_t i = 0; i < p->import_count; ++i) p->imports[order[i]].id = (uint8_t)i;
    for (size_t i = 0; i < p->call_count; ++i) {
        size_t at = p->calls[i];
        if (at >= expression.used || expression.data[at] >= p->import_count) { ok = false; goto done; }
        expression.data[at] = p->imports[expression.data[at]].id;
    }
    uint8_t helper_type=0;
    for(size_t i=0;i<type_count;++i)if(unique[i].argc==1&&unique[i].args[0]==0x7f&&unique[i].resultc==1&&unique[i].results[0]==0x7f)helper_type=(uint8_t)i;
    c->helper_type=helper_type;
    c->helper_id=p->import_count+(c->helper_first?0:1);
    if(!yx_module_pattern_relocate_helper(&expression,c->helper_calls,c->helper_call_count,c->helper_id)){ok=false;goto done;}
    ok = yx_put_uleb(&types, type_count);
    for (size_t i = 0; ok && i < type_count; ++i)
        ok = yx_put_u8(&types, 0x60) && yx_put_uleb(&types, unique[i].argc) &&
            yx_put_bytes(&types, unique[i].args, unique[i].argc) &&
            yx_put_uleb(&types, unique[i].resultc) && yx_put_bytes(&types, unique[i].results, unique[i].resultc);
    ok = ok && yx_put_uleb(&imports, p->import_count + c->presence + (p->filesize ? 1 : 0) + c->pattern_search + (p->memory ? 1 : 0));
    for (size_t i = 0; ok && i < p->import_count; ++i) {
        const yx_module_import *entry = &p->imports[order[i]];
        ok = yx_module_wasm_string(&imports, entry->module) && yx_module_wasm_string(&imports, entry->name) &&
            yx_put_u8(&imports, 0) && yx_put_uleb(&imports, entry->type);
    }
    if(ok&&c->presence)ok=yx_module_wasm_string(&imports,"yara_x")&&yx_module_wasm_string(&imports,"matching_patterns_bitmap_base")&&yx_put_u8(&imports,3)&&yx_put_u8(&imports,0x7f)&&yx_put_u8(&imports,0);
    if (ok && p->filesize)
        ok = yx_module_wasm_string(&imports, "yara_x") && yx_module_wasm_string(&imports, "filesize") &&
            yx_put_u8(&imports, 3) && yx_put_u8(&imports, 0x7e) && yx_put_u8(&imports, 1);
    if(ok&&c->pattern_search)ok=yx_module_wasm_string(&imports,"yara_x")&&yx_module_wasm_string(&imports,"pattern_search_done")&&yx_put_u8(&imports,3)&&yx_put_u8(&imports,0x7f)&&yx_put_u8(&imports,1);
    if (ok && p->memory)
        ok = yx_module_wasm_string(&imports, "yara_x") && yx_module_wasm_string(&imports, "main_memory") &&
            yx_put_u8(&imports, 2) && yx_put_u8(&imports, 0) && yx_put_u8(&imports, 1);
    if (ok) {
        static const uint8_t suffix[] = {0x0b,0x45,0x04,0x40,0x05,0x41,0x00,0x10};
        static const uint8_t tail[] = {0x0b,0x41,0x00,0x0b};
        /* i64_tmp_a and, for range bounds and signed division, i64_tmp_b,
         * numbered after emit_switch's i32 temporary. */
        bool wide=p->filesize||p->divisor||p->two_locals;
        /* A shift wrote i64_tmp_b as local 1: it is the only i64 local
         * unless something uses i64_tmp_a (yx_module_wasm). */
        if(p->shift) {
            if(wide)p->two_locals=true;
            else ok=yx_module_shift_wide_locals(expression.data,expression.used,-1);
            wide=true;
        }
        ok = ok && (!(p->i32_local && wide) || yx_module_shift_wide_locals(expression.data, expression.used, 1)) &&
            yx_put_u8(&body, (wide ? 1 : 0) + p->i32_local) &&
            (!p->i32_local || (yx_put_u8(&body, 1) && yx_put_u8(&body, 0x7f))) &&
            (!wide || (yx_put_u8(&body, p->two_locals ? 2 : 1) && yx_put_u8(&body, 0x7e))) &&
            yx_put_u8(&body, 2) && yx_put_u8(&body, 0x7f) &&
            yx_put_bytes(&body, expression.data, expression.used) && yx_put_bytes(&body, suffix, sizeof(suffix)) &&
            yx_put_uleb(&body, p->imports[match].id) && yx_put_bytes(&body, tail, sizeof(tail)) &&
            true;
        uint64_t instructions=0;
        if(ok)ok=yx_rule_expression_instructions(&body,&instructions);
        bool first=c->presence&&(instructions<15||c->helper_tie);
        if(ok&&first!=c->helper_first){c->helper_first=first;free(expression.data);free(types.data);free(imports.data);free(body.data);free(code.data);free(wasm.data);return yx_module_pattern_wasm(p,root,data,length);}
        static const uint8_t helper[]={29,1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
        ok=ok&&yx_put_u8(&code,c->presence?4:3)&&( !c->helper_first||yx_put_bytes(&code,helper,sizeof(helper)))&&yx_put_uleb(&code,body.used)&&yx_put_bytes(&code,body.data,body.used)&&(!c->presence||c->helper_first||yx_put_bytes(&code,helper,sizeof(helper)));
        ok=ok&&yx_put_u8(&wrapper,0)&&yx_put_u8(&wrapper,2)&&yx_put_u8(&wrapper,0x40)&&
            yx_put_u8(&wrapper,0x10)&&yx_put_uleb(&wrapper,p->import_count+c->helper_first)&&yx_put_u8(&wrapper,0x0d)&&
            yx_put_u8(&wrapper,0)&&yx_put_u8(&wrapper,0x0b)&&yx_put_u8(&wrapper,0x0b)&&
            yx_put_u8(&main_body,0)&&yx_put_u8(&main_body,0x10)&&yx_put_uleb(&main_body,p->import_count+1+c->presence)&&
            yx_put_u8(&main_body,0x41)&&yx_put_u8(&main_body,0)&&yx_put_u8(&main_body,0x0b)&&
            yx_put_u8(&exports,1)&&yx_module_wasm_string(&exports,"main")&&yx_put_u8(&exports,0)&&yx_put_uleb(&exports,p->import_count+2+c->presence);
        ok=ok&&yx_put_u8(&functions,c->presence?4:3)&&yx_put_u8(&functions,c->helper_first?helper_type:1)&&(!c->presence||yx_put_u8(&functions,c->helper_first?1:helper_type))&&yx_put_u8(&functions,0)&&yx_put_u8(&functions,1);
        ok = ok && yx_put_uleb(&code,wrapper.used)&&yx_put_bytes(&code,wrapper.data,wrapper.used)&&
            yx_put_uleb(&code,main_body.used)&&yx_put_bytes(&code,main_body.data,main_body.used)&& yx_put_bytes(&wasm, magic, sizeof(magic)) &&
            yx_put_u8(&wasm, 1) && yx_put_uleb(&wasm, types.used) && yx_put_bytes(&wasm, types.data, types.used) &&
            yx_put_u8(&wasm, 2) && yx_put_uleb(&wasm, imports.used) && yx_put_bytes(&wasm, imports.data, imports.used) &&
            yx_append_wasm_section(&wasm,3,&functions) &&
            yx_append_wasm_section(&wasm,7,&exports) &&
            yx_put_u8(&wasm, 10) && yx_put_uleb(&wasm, code.used) && yx_put_bytes(&wasm, code.data, code.used);
    }
done:
    free(wrapper.data);free(main_body.data);free(exports.data);
    free(functions.data); free(expression.data); free(types.data); free(imports.data); free(body.data); free(code.data);
    if (!ok) { free(wasm.data); return false; }
    *data = wasm.data; *length = wasm.used; return true;
}
static bool yx_v12_wasm(const uint8_t *data,size_t length,unsigned profile,yx_writer *out);
/* walrus defines the pattern-match helper before the rule function and
 * sorts the functions by size, keeping that order for equal sizes. The
 * lowering (yx_v12_wasm) sorts the same way, stably: the two orders of the
 * module lower differently exactly when the sizes are equal, and then the
 * helper goes first. */
static bool yx_module_pattern_wasm_sized(yx_module_program *p,int root,uint8_t **data,size_t *length)
{
    yx_module_patterns *c=p->extension;uint8_t *tie=NULL;size_t tie_length=0;bool differ=false;
    if(!yx_module_pattern_wasm(p,root,data,length))return false;
    if(!c->presence||c->helper_first)return true;
    c->helper_tie=true;
    if(yx_module_pattern_wasm(p,root,&tie,&tie_length)) {
        yx_writer mine={0},other={0};
        differ=yx_v12_wasm(*data,*length,0,&mine)&&yx_v12_wasm(tie,tie_length,0,&other)&&
            (mine.used!=other.used||memcmp(mine.data,other.data,mine.used));
        free(mine.data);free(other.data);
    }
    c->helper_tie=false;
    if(differ){free(*data);*data=tie;*length=tie_length;return true;}
    free(tie);free(*data);*data=NULL;
    return yx_module_pattern_wasm(p,root,data,length);
}

static void yx_module_pattern_bounds(const yx_module_program *p,int root,yx_pattern_filesize_bounds *bounds,unsigned depth)
{
    if(root<0||depth>128)return;
    const yx_module_node *n=&p->nodes[root];
    if(n->op==YX_ME_GROUP){yx_module_pattern_bounds(p,n->args[0],bounds,depth+1);return;}
    if(n->op==YX_ME_AND){yx_module_pattern_bounds(p,n->args[0],bounds,depth+1);yx_module_pattern_bounds(p,n->args[1],bounds,depth+1);return;}
    if(n->op!=YX_ME_COMPARE||n->comparison<2||n->comparison>5)return;
    const yx_module_node *a=&p->nodes[n->args[0]],*b=&p->nodes[n->args[1]];
    bool reversed=b->op==YX_ME_FILESIZE;
    const yx_module_node *constant=reversed?a:b;
    if((reversed?b:a)->op!=YX_ME_FILESIZE||(constant->op!=YX_ME_INT&&constant->op!=YX_ME_FLOAT))return;
    bool lower=n->comparison==3||n->comparison==5;if(reversed)lower=!lower;
    bool inclusive=n->comparison==4||n->comparison==5;
    int64_t value=constant->integer;
    if(constant->op==YX_ME_FLOAT){double rounded=lower?floor(constant->real):ceil(constant->real);if(!isfinite(rounded))return;inclusive=inclusive&&rounded==constant->real;value=rounded>=(double)INT64_MAX?INT64_MAX:rounded<=(double)INT64_MIN?INT64_MIN:(int64_t)rounded;}
    uint8_t kind=inclusive?0:1,*old_kind=lower?&bounds->lower_kind:&bounds->upper_kind;
    int64_t *old=lower?&bounds->lower:&bounds->upper;
    if(*old_kind==2||(lower?value>*old:value<*old)||(value==*old&&kind==1)){*old_kind=kind;*old=value;}
}
static void yx_module_pattern_apply_bounds(yx_module_program *p,int root)
{
    yx_module_patterns *c=p->extension;yx_pattern_filesize_bounds bounds={2,2,0,0};
    yx_module_pattern_bounds(p,root,&bounds,0);memset(c->archive->bounded,0,c->archive->physical*sizeof(*c->archive->bounded));
    if(bounds.lower_kind==2&&bounds.upper_kind==2)return;
    for(size_t i=0;i<c->archive->logical;++i)if(c->archive->kinds[i]){size_t physical=c->archive->mapping[i];c->archive->bounded[physical]=true;c->archive->bounds[physical]=bounds;}
}
/* The parents yx_module_pattern_limits asks about for each `#a`, indexed in
 * one pass over the nodes instead of one pass per `#a` (quadratic in a large
 * composed program): the first GROUP over a node, the first comparison of it
 * with another node, whether a Boolean context holds it and whether it is a
 * limit root. -1 / false when there is none. */
typedef struct { int *group,*compare; bool *boolean,*root; } yx_module_limit_index;
static void yx_module_limit_index_free(yx_module_limit_index *x){free(x->group);free(x->compare);free(x->boolean);free(x->root);memset(x,0,sizeof(*x));}
static bool yx_module_limit_index_build(const yx_module_program *p,const yx_module_patterns *c,yx_module_limit_index *x)
{
    size_t count=p->count?p->count:1;
    memset(x,0,sizeof(*x));
    x->group=malloc(count*sizeof(*x->group));x->compare=malloc(count*sizeof(*x->compare));
    x->boolean=calloc(count,sizeof(*x->boolean));x->root=calloc(count,sizeof(*x->root));
    if(!x->group||!x->compare||!x->boolean||!x->root){yx_module_limit_index_free(x);return false;}
    for(size_t i=0;i<p->count;++i){x->group[i]=-1;x->compare[i]=-1;}
    for(size_t j=p->count;j-->0;) {
        const yx_module_node *parent=&p->nodes[j];
        int a=parent->args[0],b=parent->args[1];
        if(parent->op==YX_ME_GROUP&&a>=0&&(size_t)a<p->count&&(int)j!=a)x->group[a]=(int)j;
        if(parent->op==YX_ME_COMPARE&&a!=b&&parent->comparison<=5) {
            if(a>=0&&(size_t)a<p->count)x->compare[a]=(int)j;
            if(b>=0&&(size_t)b<p->count)x->compare[b]=(int)j;
        }
        if(parent->op==YX_ME_AND||parent->op==YX_ME_OR) {
            if(a>=0&&(size_t)a<p->count&&(int)j!=a)x->boolean[a]=true;
            if(b>=0&&(size_t)b<p->count&&(int)j!=b)x->boolean[b]=true;
        }
        if(parent->op==YX_ME_NOT&&a>=0&&(size_t)a<p->count&&(int)j!=a)x->boolean[a]=true;
        if((parent->op==YX_ME_BIND||parent->op==YX_ME_LOOP)&&b!=a&&b>=0&&(size_t)b<p->count&&(int)j!=b)x->boolean[b]=true;
    }
    for(size_t j=0;j<c->limit_root_count;++j) {
        int root=c->limit_roots[j];
        if(root>=0&&(size_t)root<p->count)x->root[root]=true;
    }
    return true;
}
static bool yx_module_pattern_limits(yx_module_program *p)
{
    yx_module_patterns *c=p->extension;
    yx_module_limit_index index={0};
    bool indexed=false,has_count=false;
    for(size_t i=0;i<p->count&&!has_count;++i)has_count=p->nodes[i].op==YX_MP_COUNT;
    if(has_count)indexed=yx_module_limit_index_build(p,c,&index);
    for(size_t i=0;i<c->archive->physical;++i)c->archive->limits[i]=1;
    for(size_t i=0;i<p->count;++i) {
        const yx_module_node *n=&p->nodes[i];
        /* of_expr_from_ast: disallow_fast_scan for an anchored set. */
        if(n->op==YX_MP_OF&&(n->comparison>>4))
            for(size_t k=0;k<n->length;++k) {
                uint32_t id=((const uint32_t *)n->bytes)[k];
                if(id>=c->archive->physical){yx_module_limit_index_free(&index);return false;}
                c->archive->limits[id]=0;
            }
        if(n->op<YX_MP_COUNT||n->op>YX_MP_COUNT_IN)continue;
        /* required_matches_for_count (rule_condition_from_ast) visits the
         * folded IR only; disallow_fast_scan above and below ran before. */
        if(n->op==YX_MP_COUNT&&n->folded_away)continue;
        uint64_t limit=0;
        /* IR::required_matches_for_count: the root and the Boolean contexts
         * (`and`, `or`, `not`, the body of a `with` or a `for .. in`) need
         * one match. Parentheses are not IR nodes. */
        if(n->op==YX_MP_COUNT&&indexed) {
            int operand=(int)i;
            while(index.group[operand]>=0)operand=index.group[operand];
            limit=index.root[operand]||index.boolean[operand];
        } else if(n->op==YX_MP_COUNT) {
            int operand=(int)i;
            for(bool climbed=true;climbed;) {
                climbed=false;
                for(size_t j=0;j<p->count&&!climbed;++j)
                    if(p->nodes[j].op==YX_ME_GROUP&&p->nodes[j].args[0]==operand&&(int)j!=operand){operand=(int)j;climbed=true;}
            }
            for(size_t j=0;j<c->limit_root_count&&!limit;++j)if(c->limit_roots[j]==operand)limit=1;
            for(size_t j=0;j<p->count&&!limit;++j) {
                const yx_module_node *parent=&p->nodes[j];
                if((int)j==operand)continue;
                if(((parent->op==YX_ME_AND||parent->op==YX_ME_OR)&&(parent->args[0]==operand||parent->args[1]==operand))||
                   (parent->op==YX_ME_NOT&&parent->args[0]==operand)||
                   ((parent->op==YX_ME_BIND||parent->op==YX_ME_LOOP)&&parent->args[1]==operand&&parent->args[0]!=operand))limit=1;
            }
        }
        if(n->op==YX_MP_COUNT&&!limit)for(size_t j=indexed?(index.compare[i]<0?p->count:(size_t)index.compare[i]):0;j<p->count;++j) {
            const yx_module_node *parent=&p->nodes[j];
            static const uint8_t ops[]={0x51,0x52,0x53,0x55,0x57,0x59};
            if(parent->op!=YX_ME_COMPARE||(parent->args[0]!=(int)i&&parent->args[1]!=(int)i)||
               parent->args[0]==parent->args[1]||parent->comparison>5)continue;
            bool count_first=parent->args[0]==(int)i;
            const yx_module_node *bound=&p->nodes[parent->args[count_first?1:0]];
            /* IR::required_matches_for_count: any constant integer, on either side. */
            if(!bound->constant||bound->type!=3||
               !yx_count_required_matches(bound->integer,bound->unsigned_value,ops[parent->comparison],count_first,&limit))
                limit=0;
            break;
        }
        /* An anonymous operand limits every pattern of its `for .. of` set. */
        const yx_module_node *loop=yx_module_pattern_owner(p,n);
        const uint32_t *ids=loop?(const uint32_t *)loop->bytes:NULL;
        size_t count=loop?loop->length:1;
        if(!loop&&(n->integer<0||(uint64_t)n->integer>=c->archive->physical)){yx_module_limit_index_free(&index);return false;}
        for(size_t k=0;k<count;++k) {
            uint64_t id=ids?ids[k]:(uint64_t)n->integer;
            if(id>=c->archive->physical){yx_module_limit_index_free(&index);return false;}
            uint64_t *old=&c->archive->limits[id];
            if(!limit)*old=0;else if(*old&&limit>*old)*old=limit;
        }
    }
    yx_module_limit_index_free(&index);
    return true;
}
/* Derive the same contiguous prefix constraints from the typed condition AST
 * as the integer codec, while retaining contradictions at sparse offsets. */
static bool yx_module_header_visit(const yx_module_program *p,int root,const YRX_RULES *rules,
    const int *roots,size_t current,yx_header_collection *out,unsigned depth)
{
    if(root<0||depth>256)return true;
    const yx_module_node *n=&p->nodes[root];
    if(n->op==YX_ME_GROUP)return yx_module_header_visit(p,n->args[0],rules,roots,current,out,depth+1);
    if(n->op==YX_ME_AND)return yx_module_header_visit(p,n->args[0],rules,roots,current,out,depth+1)&&
        yx_module_header_visit(p,n->args[1],rules,roots,current,out,depth+1);
    if(n->op==YX_GLOBAL_RULE_REFERENCE&&n->integer>=0&&(uint64_t)n->integer<current)
        return yx_module_header_visit(p,roots[n->integer],rules,roots,(size_t)n->integer,out,depth+1);
    if(n->op==YX_MP_AT&&n->args[0]>=0&&p->nodes[n->args[0]].op==YX_ME_INT&&!p->nodes[n->args[0]].integer) {
        const yx_module_patterns *context=p->extension;size_t logical=0;
        for(size_t i=0;i<rules->rule_count;++i)for(size_t j=0;j<rules->rules[i].pattern_count;++j,++logical)
            if(context->archive->mapping[logical]==(size_t)n->integer) {
                yx_writer bytes={0};bool ok=yx_header_pattern_bytes(&rules->rules[i].patterns[j],&bytes)&&yx_header_add(out,0,bytes.data,bytes.used);
                free(bytes.data);return ok;
            }
        return false;
    }
    if(n->op!=YX_ME_COMPARE||n->comparison!=0)return true;
    const yx_module_node *a=&p->nodes[n->args[0]],*b=&p->nodes[n->args[1]];
    if(a->constant){const yx_module_node *swap=a;a=b;b=swap;}
    if(a->op!=YX_ME_READ||a->integer<0||a->integer>5||!b->constant||b->type!=3)return true;
    const yx_module_node *offset=&p->nodes[a->args[0]];
    if(!offset->constant||offset->type!=3||offset->integer<0)return true;
    size_t width=(size_t)1<<(a->integer%3);uint8_t bytes[4];
    for(size_t i=0;i<width;++i)bytes[i]=(uint8_t)((uint64_t)b->integer>>(8*i));
    return yx_header_add(out,(uint64_t)offset->integer,bytes,width);
}
static bool yx_module_header(const yx_module_program *p,int root,const YRX_RULES *rules,
    const int *roots,size_t current,yx_writer *storage,yx_physical_header *header)
{
    yx_header_collection pieces={0};bool ok=yx_module_header_visit(p,root,rules,roots,current,&pieces,0);
    for(size_t g=0;ok&&g<=current;++g)if(rules->rules[g].is_global&&rules->rules[g].namespace_index==rules->rules[current].namespace_index)
        ok=yx_module_header_visit(p,roots[g],rules,roots,g,&pieces,0);
    ok=ok&&yx_header_finish(&pieces,storage,header);
    yx_header_collection_destroy(&pieces);return ok;
}
typedef struct yx_module_pattern_schema {
    yx_archive_globals_schema dynamic;
    yx_archive_module_signature *signatures;
} yx_module_pattern_schema;
static void yx_module_pattern_schema_free(yx_module_pattern_schema *schema)
{
    yx_archive_globals_schema_free(&schema->dynamic);free(schema->signatures);memset(schema,0,sizeof(*schema));
}
static bool yx_module_pattern_schema_build(yx_module_pattern_schema *out,const YRX_RULES *rules,uint8_t profile)
{
    yx_archive_globals_schema *d=&out->dynamic;
    if(profile>3||rules->import_count>UINT16_MAX-rules->global_count||
       !yx_put_uint(&d->globals,rules->global_count+rules->import_count))return false;
    for(size_t i=0;i<rules->global_count;++i) {
        const yx_global *global=&rules->globals[i];yx_global_scalar_value value=yx_archive_global_value(global);uint16_t index=(uint16_t)i;
        if(!yx_put_string(&d->globals,global->name)||!yx_put_uint(&d->globals,0)||
           !yx_archive_global_write_value(&d->globals,global->type,value,0)||
           !yx_archive_global_add_field(d,global->name,global->type,value,&index,1))return false;
    }
    size_t signature_count=0;
    for(size_t m=0;m<rules->import_count;++m) {
        const yx_archive_module_schema *module=yx_archive_schema(rules->imports[m]);
        if(!module||module->signature_count>SIZE_MAX-signature_count)return false;
        signature_count+=module->signature_count;
    }
    out->signatures=calloc(signature_count?signature_count:1,sizeof(*out->signatures));if(!out->signatures)return false;
    for(size_t m=0;m<rules->import_count;++m) {
        const yx_archive_module_schema *module=yx_archive_schema(rules->imports[m]);
        const uint8_t *bytes=module->globals[profile];size_t length=module->globals_length[profile];
        if(length<4||bytes[0]!=1||memcmp(bytes+length-3,"\0\1\0",3)||!yx_put_bytes(&d->globals,bytes+1,length-4))return false;
        /* The module's fields, then the members of its struct-array elements. */
        const yx_archive_module_field *elements=NULL;size_t element_count=0;
        for(size_t e=0;e<sizeof(yx_archive_module_elements)/sizeof(yx_archive_module_elements[0]);++e)
            if(!strcmp(yx_archive_module_elements[e].module,rules->imports[m])){elements=yx_archive_module_elements[e].fields;element_count=yx_archive_module_elements[e].count;}
        for(size_t f=0;f<module->field_count+element_count;++f) {
            const yx_archive_module_field *field=f<module->field_count?&module->fields[f]:&elements[f-module->field_count];
            uint16_t indexes[16];memcpy(indexes,field->indexes,sizeof(indexes));
            if(!field->depth||indexes[0]>UINT16_MAX-rules->global_count-m)return false;
            indexes[0]+=(uint16_t)(rules->global_count+m);
            yx_global_type type=field->kind==1?YX_GLOBAL_BOOL:field->kind==2?YX_GLOBAL_FLOAT:field->kind==3?YX_GLOBAL_INT:YX_GLOBAL_STR;
            yx_global_scalar_value empty={0};
            if(!yx_archive_global_add_field(d,field->path,type,empty,indexes,field->depth))return false;
            yx_archive_module_field *copy=&d->fields[d->schema.field_count-1];const char *path=copy->path;
            *copy=*field;copy->path=path;memcpy(copy->indexes,indexes,sizeof(indexes));
        }
        memcpy(out->signatures+d->schema.signature_count,module->signatures,module->signature_count*sizeof(*module->signatures));
        d->schema.signature_count+=module->signature_count;
    }
    if(!yx_put_uint(&d->globals,0)||!yx_put_u8(&d->globals,1)||!yx_put_u8(&d->globals,0))return false;
    d->schema.name="";d->schema.signatures=out->signatures;
    for(size_t i=0;i<4;++i){d->schema.globals[i]=d->globals.data;d->schema.globals_length[i]=d->globals.used;}
    return true;
}
static bool yx_global_rules_schema_build(yx_archive_globals_schema *out,
                                          const YRX_RULES *rules, uint8_t profile)
{
    yx_module_pattern_schema merged = {0};
    if (!yx_module_pattern_schema_build(&merged, rules, profile)) {
        yx_module_pattern_schema_free(&merged);
        return false;
    }
    *out = merged.dynamic;
    out->owned_signatures = merged.signatures;
    return true;
}

static yx_ser_result yx_encode_module_patterns_profile(const YRX_RULES *rules,uint8_t profile,uint8_t **data,size_t *length)
{
    if(!rules||rules->rule_count!=1||rules->import_count>32||(!rules->import_count&&!rules->global_count)||(rules->import_count&&!rules->imports)||profile>3)return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule=&rules->rules[0];
    if(rule->namespace_name&&strcmp(rule->namespace_name,"default"))return YX_SER_UNSUPPORTED;
    for(size_t i=0;i<rules->import_count;++i)for(size_t j=0;j<i;++j)if(!strcmp(rules->imports[i],rules->imports[j]))return YX_SER_UNSUPPORTED;
    if(!rule->pattern_count||rule->is_global||!rule->condition_text)return YX_SER_UNSUPPORTED;
    yx_module_pattern_schema dynamic={0};
    if(!yx_module_pattern_schema_build(&dynamic,rules,profile)){yx_module_pattern_schema_free(&dynamic);return YX_SER_UNSUPPORTED;}
    const yx_archive_module_schema *schema=&dynamic.dynamic.schema;
    yx_physical_archive *a=calloc(1,sizeof(*a));yx_module_program *p=calloc(1,sizeof(*p));
    yx_module_patterns c={0};yx_writer neutral={0},header_storage={0};uint8_t *base=NULL,*wasm=NULL;
    size_t base_length=0,wasm_length=0;yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!a||!p){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<rule->pattern_count;++i)
        if((i&&!yx_put_bytes(&neutral," or ",4))||!yx_put_bytes(&neutral,rule->patterns[i].identifier,strlen(rule->patterns[i].identifier)))goto memory;
    if(!yx_put_u8(&neutral,0))goto memory;
    YRX_RULE r=*rule;YRX_RULES rs=*rules;r.condition_text=(char *)neutral.data;rs.rules=&r;rs.import_count=0;rs.imports=NULL;rs.global_count=0;rs.globals=NULL;
    status=yx_ser_encode(&rs,&base,&base_length);
    if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED;
    if(!yx_physical_read(base,base_length,a)||!yx_physical_imports_reserve(a,rules->import_count))goto done;
    /* Imports are interned before rule-local names and namespaces. */
    for(size_t m=0;m<rules->import_count;++m) {
        if(!yx_physical_names_reserve(a,a->name_count+1))goto done;
        char *module_name=yx_copy_string(rules->imports[m]);if(!module_name)goto memory;
        size_t position=1+m;
        memmove(a->names+position+1,a->names+position,(a->name_count-position)*sizeof(*a->names));
        a->names[position]=module_name;++a->name_count;
        if(a->namespace_id>=position)++a->namespace_id;
        if(a->rule_name_id>=position)++a->rule_name_id;
        for(size_t i=0;i<a->logical;++i)if(a->name_ids[i]>=position)++a->name_ids[i];
        for(size_t i=0;i<a->tag_count;++i)if(a->tags[i]>=position)++a->tags[i];
        for(size_t i=0;i<a->metadata_count;++i)if(a->metadata[i].key>=position)++a->metadata[i].key;
        a->imports[m]=position;
    }
    yx_physical_index_reset(a);
    a->import_count=rules->import_count;
    a->globals=schema->globals[profile];a->globals_length=schema->globals_length[profile];
    p->schema=schema;p->profile=profile;p->capi_import_order=!rules->archive_cli&&profile==0;p->parser.at=(const unsigned char *)rule->condition_text;
    c.archive=a;yx_module_pattern_setup(p,&c);
    for(size_t i=0;i<a->pool_count;++i) {
        size_t id;
        if(!yx_intern_literal(a->pool[i].data,a->pool[i].length,&p->literals,&p->literal_count,&p->literal_capacity,&id)||id!=i)goto done;
    }
    int root=yx_module_parse(p,1,0);yx_bool_skip_space(&p->parser);
    c.limit_roots=&root;c.limit_root_count=1;
    if(root<0||*p->parser.at||p->failed||!yx_module_pattern_limits(p)||
       !yx_module_pattern_wasm_sized(p,root,&wasm,&wasm_length)||!yx_physical_pool_reserve(a,p->literal_count))goto done;
    for(size_t i=0;i<p->count;++i)if(p->nodes[i].op==YX_MP_AT||(p->nodes[i].op==YX_MP_OF&&(p->nodes[i].comparison>>4)))goto done;
    yx_module_pattern_apply_bounds(p,root);
    yx_physical_header header={0};if(!yx_module_header(p,root,rules,&root,0,&header_storage,&header))goto done;
    for(size_t i=0;i<a->logical;++i)if(a->kinds[i])a->headers[a->mapping[i]]=header;
    a->pool_count=p->literal_count;if(p->literal_count)memcpy(a->pool,p->literals,p->literal_count*sizeof(*p->literals));
    if(c.regex_count) {
        free(a->regexps);if(!(a->regexps=malloc(c.regex_count*sizeof(*c.regexes))))goto memory;
        memcpy(a->regexps,c.regexes,c.regex_count*sizeof(*c.regexes));a->regexp_count=c.regex_count;
    }
    yx_physical_index_reset(a);
    a->wasm=wasm;a->wasm_length=wasm_length;
    status=yx_physical_write(a,data,length);goto done;
memory:status=YX_SER_NO_MEMORY;
done:free(c.helper_calls);free(c.regexes);free(header_storage.data);free(neutral.data);free(base);free(wasm);if(a)yx_physical_destroy(a);free(a);yx_module_program_free(p);yx_module_pattern_schema_free(&dynamic);return status;
}
static bool yx_module_pattern_decode_header_mode(yx_reader *r, yx_module_program *p, size_t *body_end, bool multi)
{
    yx_module_patterns *c=p->extension;
    static const uint8_t sections[] = {1,2,3,7,10};
    if (r->length < 8 || memcmp(r->data, yx_constant_wasm, 8)) return false;
    r->at = 8;
    for (size_t section = 0; section < sizeof(sections); ++section) {
        uint8_t id; uint64_t length;
        if (!yx_get_u8(r, &id) || id != sections[section] || !yx_get_uleb(r, &length) || length > r->length - r->at) return false;
        size_t end = r->at + (size_t)length;
        if (id == 2) {
            uint64_t count;
            if (!yx_get_uleb(r, &count) || r->at > end || count > YX_MODULE_IMPORTS + 4) return false;
            for (uint64_t i = 0; i < count; ++i) {
                const uint8_t *module, *name; size_t module_length, name_length;
                uint8_t kind; uint64_t value;
                if (!yx_integer_wasm_name(r, end, &module, &module_length) ||
                    !yx_integer_wasm_name(r, end, &name, &name_length) || !yx_get_u8(r, &kind)) return false;
                if (kind == 0) {
                    if (p->import_count == YX_MODULE_IMPORTS || module_length >= 80 || name_length >= 160 ||
                        !yx_get_uleb(r, &value)) return false;
                    yx_module_import *entry = &p->imports[p->import_count++];
                    memcpy(entry->module, module, module_length); entry->module[module_length] = 0;
                    memcpy(entry->name, name, name_length); entry->name[name_length] = 0;
                } else if(kind==3&&module_length==6&&!memcmp(module,"yara_x",6)&&
                    ((name_length==29&&!memcmp(name,"matching_patterns_bitmap_base",29))||
                     (name_length==19&&!memcmp(name,"pattern_search_done",19)))) {
                    uint8_t type,mutable;bool bitmap=name_length==29;
                    if(!yx_get_u8(r,&type)||type!=0x7f||!yx_get_u8(r,&mutable)||mutable!=(bitmap?0:1))return false;
                    if(bitmap)c->presence=true;else c->pattern_search=true;
                } else if (kind == 3 && module_length == 6 && !memcmp(module, "yara_x", 6) &&
                           name_length == 8 && !memcmp(name, "filesize", 8)) {
                    uint8_t type, mutable;
                    if (p->filesize || !yx_get_u8(r, &type) || type != 0x7e || !yx_get_u8(r, &mutable) || mutable != 1) return false;
                    p->filesize = true;
                } else if (kind == 2 && module_length == 6 && !memcmp(module, "yara_x", 6) &&
                           name_length == 11 && !memcmp(name, "main_memory", 11)) {
                    uint8_t flags, minimum;
                    if (p->memory || !yx_get_u8(r, &flags) || flags || !yx_get_u8(r, &minimum) || minimum != 1) return false;
                    p->memory = true;
                } else return false;
            }
            if (r->at != end) return false;
        } else if (id == 10) {
            p->filesize_global=c->presence?1:0;c->search_global=(uint8_t)(c->presence+p->filesize);
            if(multi){*body_end=end;return true;}
            uint64_t count, size, locals, local_count; uint8_t type;
            if (!yx_get_uleb(r, &count) || count != (c->presence?4u:3u) || !yx_get_uleb(r, &size) || r->at > end || size > end - r->at) return false;
            if(c->presence&&size==29&&end-r->at>=3&&!memcmp(r->data+r->at,"\1\1\x7f",3)) {
                c->helper_first=true;r->at+=(size_t)size;
                if(!yx_get_uleb(r,&size)||size>end-r->at)return false;
            }
            c->helper_id=p->import_count+(c->helper_first?0:1);
            p->filesize_global=c->presence?1:0;c->search_global=(uint8_t)(c->presence+p->filesize);
            *body_end = r->at + (size_t)size;
            if (!yx_get_uleb(r, &locals) || r->at > *body_end || locals > 1) return false;
            if (locals && (!yx_get_uleb(r, &local_count) || local_count < 1 || local_count > 2 || !yx_get_u8(r, &type) ||
                           (type != 0x7e && (type != 0x7f || local_count != 1)))) return false;
            return yx_get_u8(r, &type) && type == 2 && yx_get_u8(r, &type) && type == 0x7f && r->at <= *body_end;
        }
        r->at = end;
    }
    return false;
}
static yx_ser_result yx_decode_module_patterns(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *rule_count)
{
    yx_physical_archive *a=calloc(1,sizeof(*a));yx_module_program *p=calloc(1,sizeof(*p));
    yx_module_pattern_schema dynamic={0};yx_global *globals=NULL;size_t global_count=0;
    YRX_RULES source_rules={0};char *module_names[32]={0};
    uint64_t *limits=NULL;bool *bounded=NULL;yx_pattern_filesize_bounds *bounds=NULL;
    yx_module_patterns c={0};yx_ser_rule *decoded=NULL;YRX_RULES *loaded=NULL;
    yx_writer source={0},declarations={0},header_storage={0};uint8_t *canonical=NULL,*wasm=NULL;
    size_t canonical_length=0,wasm_length=0;yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!a||!p){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_physical_read(data,length,a)||a->archive_length!=length||a->import_count>32)goto done;
    status=yx_physical_write(a,&canonical,&canonical_length);
    if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED;
    if(canonical_length!=length||memcmp(canonical,data,length))goto done;
    for(size_t i=0;i<a->import_count;++i) {
        module_names[i]=a->names[a->imports[i]];
        if(!yx_archive_schema(module_names[i]))goto done;
    }
    source_rules.import_count=a->import_count;source_rules.imports=module_names;
    yx_reader gr={a->globals,a->globals_length,0,false,false};uint64_t fields;
    if(!yx_get_uint(&gr,&fields)||!fields||fields<a->import_count||fields-a->import_count>UINT16_MAX)goto done;
    global_count=(size_t)(fields-a->import_count);
    if(global_count) {
        globals=calloc(global_count,sizeof(*globals));if(!globals){global_count=0;status=YX_SER_NO_MEMORY;goto done;}
        for(size_t i=0;i<global_count;++i) {
            yx_global_scalar_value value={0};
            if(!yx_get_string(&gr,&globals[i].name)||!yx_expect_uint(&gr,0))goto done;
            bool ok=yx_archive_global_read_value(&gr,&globals[i].type,&value,0);memcpy(&globals[i].value,&value,sizeof(value));
            if(!ok)goto done;
        }
        source_rules.globals=globals;source_rules.global_count=global_count;
    }
    if(!yx_module_pattern_schema_build(&dynamic,&source_rules,0))goto done;
    p->schema=&dynamic.dynamic.schema;
    c.archive=a;yx_module_pattern_setup(p,&c);p->undefined_slot=-1;
    if(a->regexp_count) {
        if(!(c.regexes=malloc(a->regexp_count*sizeof(*c.regexes)))){status=YX_SER_NO_MEMORY;goto done;}
        memcpy(c.regexes,a->regexps,a->regexp_count*sizeof(*c.regexes));c.regex_count=c.regex_capacity=a->regexp_count;
    }
    p->literal_count=p->literal_capacity=a->pool_count;
    p->literals=calloc(a->pool_count?a->pool_count:1,sizeof(*p->literals));
    if(!p->literals){status=YX_SER_NO_MEMORY;goto done;}
    if(a->pool_count)memcpy(p->literals,a->pool,a->pool_count*sizeof(*p->literals));
    yx_reader wr={a->wasm,a->wasm_length,0,false,false};size_t body_end;
    if(!yx_module_pattern_decode_header_mode(&wr,p,&body_end,false))goto done;
    int root=yx_module_decode_block(&wr,body_end,p,0);
    /* The terms below go inside the body of a `with` condition: a `with`
     * whose body is constant has a constant type value, and IR::and / IR::or
     * would fold it away with its declarations (their calls run). */
    int with_body=root;bool with_root=root>=0&&p->nodes[root].op==YX_ME_BIND;
    if(with_root) {
        for(bool first=true;p->nodes[with_body].op==YX_ME_BIND;first=false) {
            const yx_module_node *bind=&p->nodes[with_body];char number[48];
            snprintf(number,sizeof(number),first?"with v%" PRId64 "=":", v%" PRId64 "=",bind->integer);
            if(bind->args[1]<0||(size_t)bind->args[1]>=p->count||!yx_tr_text(&source,number)||
               !yx_module_print(p,bind->args[0],&source,1))goto done;
            with_body=bind->args[1];
        }
        if(!yx_tr_text(&source,": (("))goto done;
    }
    if(root<0||!yx_module_print(p,with_body,&source,0)||(with_root&&!yx_put_u8(&source,')')))goto done;
    /* Folding can remove every pattern operand while its private physical
     * patterns remain in the archive. Retain syntactic references when the
     * runtime compiler reconstructs the source, without evaluating them. */
    if(!c.pattern_search) {
        bool opened=false;
        for(size_t i=0;i<a->logical;++i)if(a->pattern_private[i]) {
            if(!opened&&!yx_tr_text(&source," or (false"))goto done;
            opened=true;
            if(!yx_tr_text(&source," and ")||!yx_tr_text(&source,a->names[a->name_ids[i]]))goto done;
        }
        if(opened&&!yx_put_u8(&source,')'))goto done;
    }
    /* Identical declarations share one PatternId, which prints as the first
     * name: reference the others without evaluating them, as the composed
     * decoder does. */
    for(size_t i=0;i<a->logical;++i) {
        bool duplicate=false;
        for(size_t q=0;q<i&&!duplicate;++q)duplicate=a->mapping[q]==a->mapping[i];
        /* So does a pattern whose operands IR::and / IR::or folded away. */
        bool read=duplicate||(a->pattern_private[i]&&!c.pattern_search);
        for(size_t n=0;!read&&n<p->count;++n) {
            const yx_module_node *node=&p->nodes[n];
            if(node->op>=YX_MP_PRESENT&&node->op<=YX_MP_COUNT_IN)read=node->integer<0||node->integer==(int64_t)a->mapping[i];
            if(node->op==YX_MP_OF||node->op==YX_MP_FOR_OF)for(size_t m=0;m<node->length;++m)
                read|=((const uint32_t *)node->bytes)[m]==a->mapping[i];
        }
        if((duplicate||!read)&&(!yx_tr_text(&source," and (true or ")||!yx_tr_text(&source,a->names[a->name_ids[i]])||
                       !yx_put_u8(&source,')')))goto done;
    }
    if((with_root&&!yx_put_u8(&source,')'))||!yx_put_u8(&source,0))goto done;
    uint8_t profile=4;bool found=false;
    for(unsigned frontend=0;frontend<2&&!found;++frontend)for(profile=0;profile<4;++profile) {
        p->profile=profile;p->capi_import_order=frontend==0&&profile==0;free(wasm);wasm=NULL;
        yx_module_pattern_schema expected={0};
        if(!yx_module_pattern_schema_build(&expected,&source_rules,profile)){yx_module_pattern_schema_free(&expected);goto done;}
        bool same=a->globals_length==expected.dynamic.globals.used&&!memcmp(a->globals,expected.dynamic.globals.data,a->globals_length);
        yx_module_pattern_schema_free(&expected);
        if(same&&yx_module_pattern_wasm_sized(p,root,&wasm,&wasm_length)&&wasm_length==a->wasm_length&&
           !memcmp(wasm,a->wasm,wasm_length)&&c.regex_count==a->regexp_count){found=true;break;}
    }
    /* The restored module can order the rule function and the pattern
     * helper either way when both lower to the archive's module (the
     * lowering sorts functions by size, as walrus does): compare the
     * lowered modules. */
    for(unsigned frontend=0;frontend<2&&!found;++frontend)for(profile=0;profile<4&&!found;++profile) {
        p->profile=profile;p->capi_import_order=frontend==0&&profile==0;free(wasm);wasm=NULL;
        yx_module_pattern_schema expected={0};
        if(!yx_module_pattern_schema_build(&expected,&source_rules,profile)){yx_module_pattern_schema_free(&expected);goto done;}
        bool same=a->globals_length==expected.dynamic.globals.used&&!memcmp(a->globals,expected.dynamic.globals.data,a->globals_length);
        yx_module_pattern_schema_free(&expected);
        if(!same||!yx_module_pattern_wasm(p,root,&wasm,&wasm_length)||c.regex_count!=a->regexp_count)continue;
        for(unsigned lowering=0;lowering<4&&!found;++lowering) {
            yx_writer mine={0},archived={0};unsigned flags=(lowering&1?4u:0u)|(lowering&2?256u:0u);
            found=yx_v12_wasm(wasm,wasm_length,flags,&mine)&&yx_v12_wasm(a->wasm,a->wasm_length,flags,&archived)&&
                mine.used==archived.used&&!memcmp(mine.data,archived.data,mine.used);
            free(mine.data);free(archived.data);
        }
        if(found)break;
    }
    if(!found)goto done;
    for(size_t i=0;i<p->count;++i)if(p->nodes[i].op==YX_MP_AT||(p->nodes[i].op==YX_MP_OF&&(p->nodes[i].comparison>>4)))goto done;
    limits=calloc(a->physical?a->physical:1,sizeof(*limits));bounded=calloc(a->physical?a->physical:1,sizeof(*bounded));bounds=calloc(a->physical?a->physical:1,sizeof(*bounds));
    if(!limits||!bounded||!bounds){status=YX_SER_NO_MEMORY;goto done;}
    if(a->physical)memcpy(limits,a->limits,a->physical*sizeof(*limits));
    c.limit_roots=&root;c.limit_root_count=1;
    if(!yx_module_pattern_limits(p)||memcmp(limits,a->limits,a->physical*sizeof(*limits)))goto done;
    memcpy(bounded,a->bounded,a->physical*sizeof(*bounded));memcpy(bounds,a->bounds,a->physical*sizeof(*bounds));
    yx_module_pattern_apply_bounds(p,root);
    for(size_t i=0;i<a->physical;++i)if(a->bounded[i]!=bounded[i]||(bounded[i]&&
        (a->bounds[i].lower_kind!=bounds[i].lower_kind||a->bounds[i].upper_kind!=bounds[i].upper_kind||
         (bounds[i].lower_kind!=2&&a->bounds[i].lower!=bounds[i].lower)||(bounds[i].upper_kind!=2&&a->bounds[i].upper!=bounds[i].upper))))goto done;
    if(!yx_physical_reconstruct_patterns(a,&loaded)||!loaded||loaded->rule_count!=1||
       loaded->rules[0].pattern_count<a->logical)goto done;
    yx_physical_header header={0};
    if(!yx_module_header(p,root,loaded,&root,0,&header_storage,&header))goto done;
    for(size_t i=0;i<a->logical;++i) {
        yx_physical_header expected=a->kinds[i]?header:(yx_physical_header){0};
        if(!yx_physical_header_equal(&expected,&a->headers[a->mapping[i]]))goto done;
    }
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_pattern_declaration(&declarations,a->names[a->name_ids[i]],&loaded->rules[0].patterns[i],a,a->mapping[i])||
           (a->pattern_private[i]&&!yx_tr_text(&declarations,"private ")))goto done;
    if(!yx_put_u8(&declarations,0)){status=YX_SER_NO_MEMORY;goto done;}
    decoded=calloc(1,sizeof(*decoded));if(!decoded){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_literal_prefilters=calloc(a->logical,sizeof(*decoded->runtime_literal_prefilters));
    if(!decoded->runtime_literal_prefilters){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_literal_prefilter_count=a->logical;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_copy_prefilter(&decoded->runtime_literal_prefilters[i],
            &loaded->rules[0].patterns[i].archived_literal_prefilter)){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_regexp_programs=calloc(a->logical,sizeof(*decoded->runtime_regexp_programs));
    if(!decoded->runtime_regexp_programs){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_regexp_program_count=a->logical;
    for(size_t i=0;i<a->logical;++i)
        if(!yx_physical_copy_regexp(&decoded->runtime_regexp_programs[i],
            loaded->rules[0].patterns[i].archived_regexp)){status=YX_SER_NO_MEMORY;goto done;}
    decoded->namespace_name=yx_copy_string(a->names[a->namespace_id]);decoded->identifier=yx_copy_string(a->names[a->rule_name_id]);
    if(!decoded->namespace_name||!decoded->identifier){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_module_names=calloc(a->import_count?a->import_count:1,sizeof(*decoded->runtime_module_names));
    if(!decoded->runtime_module_names){status=YX_SER_NO_MEMORY;goto done;}
    decoded->runtime_module_count=a->import_count;
    for(size_t i=0;i<a->import_count;++i)if(!(decoded->runtime_module_names[i]=yx_copy_string(module_names[i]))){status=YX_SER_NO_MEMORY;goto done;}
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
            if(memchr(a->pool[m->literal].data,0,a->pool[m->literal].length)||!yx_valid_utf8(a->pool[m->literal].data,a->pool[m->literal].length))goto done;
            value->value_type=YRX_STRING;value->value.string=(const char *)yx_copy_literal(&a->pool[m->literal],true);
            if(!value->value.string){status=YX_SER_NO_MEMORY;goto done;}
        } else {
            value->value_type=YRX_BYTES;value->value.bytes.data=yx_copy_literal(&a->pool[m->literal],false);value->value.bytes.length=a->pool[m->literal].length;
            if(!value->value.bytes.data){status=YX_SER_NO_MEMORY;goto done;}
        }
    }
    decoded->is_private=a->private_rule;decoded->runtime_pattern_declarations=(char *)declarations.data;declarations.data=NULL;
    decoded->runtime_integer_condition=(char *)source.data;source.data=NULL;decoded->runtime_integer_import_profile=profile;
    decoded->runtime_globals=globals;decoded->runtime_global_count=global_count;globals=NULL;global_count=0;
    decoded->preserve_serialized_prefix=true;decoded->truth=true;
    *rules=decoded;*rule_count=1;decoded=NULL;status=YX_SER_SUCCESS;
done:free(canonical);free(wasm);free(source.data);free(declarations.data);yrx_rules_destroy(loaded);
    if(a)yx_physical_destroy(a);
    free(c.helper_calls);free(c.regexes);free(header_storage.data);free(limits);free(bounded);free(bounds);free(a);yx_module_program_free(p);yx_module_pattern_schema_free(&dynamic);yx_archive_globals_destroy(globals,global_count);yx_ser_rules_destroy(decoded,decoded?1:0);return status;
}
