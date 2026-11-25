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

/* Typed module/global/prior-rule expressions over the shared physical archive. */
static bool yx_composed_empty_namespaces(const YRX_RULES *rules)
{
    if(!rules||!rules->rule_count||rules->namespace_count<=1)return false;
    size_t previous=0;
    for(size_t i=0;i<rules->rule_count;++i) {
        size_t current=rules->rules[i].namespace_index;
        if(current>previous&&current-previous>1)return true;
        previous=current;
    }
    return rules->namespace_count-1>previous;
}
/* Interning the pool into an empty literal list, in order, gives every
 * literal its own index exactly when no two are equal: check that once with
 * a hash table (not one search per literal) and copy the pool. 1 adopted, 0 two
 * literals are equal (interning would give a different index), -1 not
 * decided here (the list is not empty, or no memory). */
static int yx_composed_adopt_pool(yx_module_program *p,const yx_literal *pool,size_t count)
{
    size_t *slots,mask=15;yx_literal *copy;int result=1;
    if(p->literal_count||!count)return -1;
    while(mask<count*2&&mask<=SIZE_MAX/4)mask=mask*2+1;
    if(mask>=SIZE_MAX/sizeof(*slots)||count>SIZE_MAX/sizeof(*copy)||!(slots=calloc(mask+1,sizeof(*slots))))return -1;
    for(size_t i=0;i<count&&result;++i) {
        uint64_t hash=UINT64_C(1469598103934665603)^(uint64_t)pool[i].length;
        for(size_t k=0;k<pool[i].length;++k)hash=(hash^pool[i].data[k])*UINT64_C(1099511628211);
        size_t slot=(size_t)(hash^(hash>>29))&mask;
        for(;slots[slot];slot=(slot+1)&mask) {
            const yx_literal *x=&pool[slots[slot]-1];
            if(x->length==pool[i].length&&(!x->length||memcmp(x->data,pool[i].data,x->length)==0)){result=0;break;}
        }
        if(result)slots[slot]=i+1;
    }
    free(slots);
    if(!result)return 0;
    if(!(copy=realloc(p->literals,count*sizeof(*copy))))return -1;
    memcpy(copy,pool,count*sizeof(*copy));
    p->literals=copy;p->literal_count=count;p->literal_capacity=count;
    return 1;
}
static bool yx_composed_parse_rules(yx_module_program *p,yx_module_patterns *c,const YRX_RULES *rules,int *roots)
{
    c->prior=(yx_global_rules_context){rules->rules,rules->rule_count,0};c->rule_scope=true;c->logical_start=0;
    c->namespace_count=rules->namespace_count;
    yx_global_rules_index(&c->prior);
    for(size_t i=0;i<rules->rule_count;++i) {
        c->prior.current=i;c->logical_count=rules->rules[i].pattern_count;
        p->parser.at=(const unsigned char *)rules->rules[i].condition_text;
        roots[i]=yx_module_parse(p,1,0);yx_bool_skip_space(&p->parser);
        if(roots[i]<0||*p->parser.at||p->failed){yx_global_rules_index_free(&c->prior);return false;}
        c->logical_start+=c->logical_count;
    }
    yx_global_rules_index_free(&c->prior);
    return true;
}
static void yx_composed_bounds(const yx_module_program *p,int root,const int *roots,size_t current,yx_pattern_filesize_bounds *bounds,unsigned depth);
typedef struct { const yx_module_program *p; int root; const int *roots; size_t current; yx_pattern_filesize_bounds *bounds; unsigned depth; } yx_composed_bounds_job;
static void yx_composed_bounds_thunk(void *data)
{ yx_composed_bounds_job *j = data; yx_composed_bounds(j->p, j->root, j->roots, j->current, j->bounds, j->depth); }
static void yx_composed_bounds(const yx_module_program *p,int root,const int *roots,size_t current,yx_pattern_filesize_bounds *bounds,unsigned depth)
{
    if(root<0||depth>YX_MODULE_DEPTH)return;
    if(YX_MODULE_DEEP(depth)) {
        yx_composed_bounds_job job={p,root,roots,current,bounds,depth};
        (void)yx_module_deep_walk(YX_MODULE_DEPTH,yx_composed_bounds_thunk,&job);return;
    }
    const yx_module_node *n=&p->nodes[root];
    if(n->op==YX_ME_GROUP){yx_composed_bounds(p,n->args[0],roots,current,bounds,depth+1);}
    else if(n->op==YX_ME_AND) {
        /* A flat chain is one level (yx_module_pattern_bounds). */
        size_t count=0;int *items=yx_module_left_chain(p,root,YX_ME_AND,&count);
        if(!items){yx_walk_no_memory=true;return;}
        for(size_t i=0;i<count;++i)yx_composed_bounds(p,items[i],roots,current,bounds,depth+1);
        free(items);
    }
    else if(n->op==YX_GLOBAL_RULE_REFERENCE&&n->integer>=0&&(uint64_t)n->integer<current) {
        const yx_module_patterns *context=p->extension;
        if(context&&context->rule_bounds&&(uint64_t)n->integer<context->rule_constraint_count)
            yx_multi_pattern_bounds_merge(bounds,&context->rule_bounds[n->integer]);
        else yx_composed_bounds(p,roots[n->integer],roots,(size_t)n->integer,bounds,depth+1);
    }
    else yx_module_pattern_bounds(p,root,bounds,depth);
}
/* HeaderConstraint::merge (compiler/rules.rs): the intersection of two
 * finished header constraints (kind 0 none, 1 unsatisfiable, 2 a prefix):
 * prefixes that agree give the longer one. *result's bytes are written to
 * storage (a copy). */
static bool yx_header_constraint_merge_into(const yx_physical_header *a,const yx_physical_header *b,
    yx_physical_header *result,yx_writer *storage)
{
    const yx_physical_header *pick=a;
    *result=(yx_physical_header){0};
    if(a->kind==1||b->kind==1){result->kind=1;return true;}
    if(a->kind==0)pick=b;
    else if(b->kind==2) {
        size_t common=a->length<b->length?a->length:b->length;
        if(common&&memcmp(a->bytes,b->bytes,common)){result->kind=1;return true;}
        if(b->length>a->length)pick=b;
    }
    if(pick->kind!=2)return true;
    if(!yx_put_bytes(storage,pick->bytes,pick->length))return false;
    *result=(yx_physical_header){2,storage->data,storage->used};return true;
}
/* A namespace's global constraints take `other` in (merged into *global,
 * whose bytes live in *storage; `merged` receives the new bytes). */
static bool yx_header_constraint_merge(yx_physical_header *global,const yx_writer *storage,
    const yx_physical_header *other,yx_writer *merged)
{
    yx_physical_header result={0};
    (void)storage;
    if(!yx_header_constraint_merge_into(global,other,&result,merged))return false;
    *global=result;return true;
}
/* anchor_patterns (ast2ir.rs) per rule: the condition's own analysis
 * (yx_condition_pattern_fixed_at) is the port of it. Rules are independent:
 * each task compiles one rule's condition and writes only its patterns'
 * answers (state 0: no answer, the node scan decides; 1: anchored at
 * offset; 2: not anchored, with `unmarked`). */
typedef struct {
    const YRX_RULES *rules;const char *const *anchor_names;const size_t *starts;
    uint8_t *state;uint64_t *offset;bool *unmarked;bool *failed;
} yx_composed_anchor_job;
static void yx_composed_anchor_task(size_t i,void *context)
{
    const yx_composed_anchor_job *job=context;const YRX_RULE *rule=&job->rules->rules[i];
    yx_condition *anchors;const char **names;size_t first=job->starts[i];char error[64]="";
    if(!rule->pattern_count||!rule->condition_text)return;
    /* A condition the parser does not read leaves the node scan to decide;
     * one it could not read for want of memory fails the encoding. */
    if(!(anchors=yx_condition_compile(rule->condition_text,error,sizeof(error)))) {
        if(strstr(error,"out of memory"))job->failed[i]=true;
        return;
    }
    names=malloc(rule->pattern_count*sizeof(*names));
    if(!names){yx_condition_destroy(anchors);job->failed[i]=true;return;}
    for(size_t j=0;j<rule->pattern_count;++j)
        names[j]=job->anchor_names?job->anchor_names[first+j]:rule->patterns[j].identifier;
    yx_condition_bind_pattern_sets(anchors,names,rule->pattern_count);
    (void)yx_condition_fold_modules(anchors,(const char *const *)job->rules->imports,job->rules->import_count,
        job->rules->globals,job->rules->global_count,NULL,0);
    for(size_t j=0;j<rule->pattern_count;++j) {
        size_t at=0;
        if(!names[j])continue;
        if(yx_condition_pattern_fixed_at(anchors,names[j],&at)){job->state[first+j]=1;job->offset[first+j]=at;}
        else {job->state[first+j]=2;job->unmarked[first+j]=!yx_condition_pattern_nonanchorable(anchors,names[j],false);}
    }
    free((void *)names);yx_condition_destroy(anchors);
}
static bool yx_composed_options(yx_module_program *p,const YRX_RULES *rules,const int *roots,yx_physical_pattern_options *options,yx_writer *header_storage)
{
    yx_module_patterns *c=p->extension;size_t logical=0,physical=c->archive->physical;
    c->limit_roots=roots;c->limit_root_count=rules->rule_count;
    if(!yx_module_pattern_limits(p))return false;
    /* Uses of each PatternId, in node order (one pass, not one per logical
     * pattern): whether a node uses it and whether every use is `at` the
     * same constant offset. */
    bool *used=calloc(physical?physical:1,sizeof(*used)),*anchor=malloc((physical?physical:1)*sizeof(*anchor));
    uint64_t *offset=calloc(physical?physical:1,sizeof(*offset));
    bool ok=used&&anchor&&offset;
    /* Out of memory is p->no_memory: the caller fails the encoding, it does
     * not try another codec (no archive depends on an allocation). */
    if(!ok)p->no_memory=true;
    for(size_t id=0;ok&&id<physical;++id)anchor[id]=true;
    for(size_t n=0;ok&&n<p->count;++n) {
        const yx_module_node *node=&p->nodes[n];
        /* anchor_patterns (ast2ir.rs) walks the folded IR. */
        if(node->folded_away)continue;
        /* Patterns of a `for .. of` set cannot be anchored. */
        if(node->op==YX_MP_FOR_OF)for(size_t m=0;m<node->length;++m) {
            uint32_t id=((const uint32_t *)node->bytes)[m];
            if(id<physical)used[id]=true,anchor[id]=false;
        }
        /* `<quantifier> of <set> at <constant>` anchors every pattern of the
         * set, like `$a at <constant>`; another anchor does not. */
        if(node->op==YX_MP_OF&&(node->comparison>>4))for(size_t m=0;m<node->length;++m) {
            uint32_t id=((const uint32_t *)node->bytes)[m];
            const yx_module_node *at=(node->comparison>>4)==1?&p->nodes[node->args[(node->comparison&15)>=3?1:0]]:NULL;
            if(id>=physical)continue;
            if(!at||at->op!=YX_ME_INT||at->integer<0)anchor[id]=false;
            else if(used[id]&&offset[id]!=(uint64_t)at->integer)anchor[id]=false;
            else offset[id]=(uint64_t)at->integer;
            used[id]=true;
        }
        if(node->op<YX_MP_PRESENT||node->op>YX_MP_COUNT_IN||node->integer<0||(uint64_t)node->integer>=physical)continue;
        size_t id=(size_t)node->integer;
        if(node->op!=YX_MP_AT||node->args[0]<0||p->nodes[node->args[0]].op!=YX_ME_INT||p->nodes[node->args[0]].integer<0)anchor[id]=false;
        else if(used[id]&&offset[id]!=(uint64_t)p->nodes[node->args[0]].integer)anchor[id]=false;
        else offset[id]=(uint64_t)p->nodes[node->args[0]].integer;
        used[id]=true;
    }
    /* anchor_patterns (ast2ir.rs) decides per rule (yx_composed_anchor_task,
     * every rule at once). The node scan above remains for a text the
     * condition parser does not read. */
    size_t total=0,*starts=malloc((rules->rule_count?rules->rule_count:1)*sizeof(*starts));
    for(size_t i=0;starts&&i<rules->rule_count;++i){starts[i]=total;total+=rules->rules[i].pattern_count;}
    uint8_t *states=calloc(total?total:1,1);uint64_t *offsets=calloc(total?total:1,sizeof(*offsets));
    bool *unmarked=calloc(total?total:1,sizeof(*unmarked)),*failed=calloc(rules->rule_count?rules->rule_count:1,sizeof(*failed));
    if(!(starts&&states&&offsets&&unmarked&&failed)){ok=false;p->no_memory=true;}
    if(ok) {
        yx_composed_anchor_job job={rules,c->anchor_names,starts,states,offsets,unmarked,failed};
        yx_parallel_run(rules->rule_count,yx_parallel_threads(rules->rule_count,16),yx_composed_anchor_task,&job);
        for(size_t i=0;i<rules->rule_count;++i)if(failed[i]){ok=false;p->no_memory=true;}
    }
    /* Each rule's constraints once, in definition order, as upstream keeps
     * them (compiler/mod.rs rule_constraints): the condition's own (a rule
     * reference merges the referenced rule's finished constraints, ir/mod.rs
     * filesize_bounds / header_constraints), then the namespace's global
     * rules' (a global rule adds its own to them and takes the result). */
    size_t namespaces=1;
    for(size_t i=0;i<rules->rule_count;++i)if(rules->rules[i].namespace_index>=namespaces)namespaces=rules->rules[i].namespace_index+1;
    yx_pattern_filesize_bounds *rule_bounds=calloc(rules->rule_count?rules->rule_count:1,sizeof(*rule_bounds));
    yx_header_collection *rule_headers=calloc(rules->rule_count?rules->rule_count:1,sizeof(*rule_headers));
    yx_pattern_filesize_bounds *global_bounds=calloc(namespaces,sizeof(*global_bounds));
    yx_physical_header *global_headers=calloc(namespaces,sizeof(*global_headers));
    yx_writer *global_storage=calloc(namespaces,sizeof(*global_storage));
    if(!rule_bounds||!rule_headers||!global_bounds||!global_headers||!global_storage){ok=false;p->no_memory=true;}
    for(size_t n=0;global_bounds&&n<namespaces;++n)global_bounds[n]=(yx_pattern_filesize_bounds){2,2,0,0};
    c->rule_bounds=rule_bounds;c->rule_headers=rule_headers;c->rule_constraint_count=0;
    for(size_t i=0;ok&&i<rules->rule_count;++i) {
        size_t ns=rules->rules[i].namespace_index;
        yx_pattern_filesize_bounds bounds={2,2,0,0};yx_composed_bounds(p,roots[i],roots,i,&bounds,0);
        yx_header_collection pieces={0};yx_physical_header header={0};yx_writer own={0};
        /* A header walk that fails refuses this codec, as before; what
         * fails after it is an allocation. */
        if(!yx_module_header_visit(p,roots[i],rules,roots,i,&pieces,0)) {
            yx_header_collection_destroy(&pieces);ok=false;break;
        }
        ok=yx_header_finish(&pieces,&own,&header);
        yx_header_collection_destroy(&pieces);
        if(ok&&rules->rules[i].is_global) {
            yx_multi_pattern_bounds_merge(&global_bounds[ns],&bounds);bounds=global_bounds[ns];
            yx_writer merged={0};
            ok=yx_header_constraint_merge(&global_headers[ns],&global_storage[ns],&header,&merged);
            if(ok){free(global_storage[ns].data);global_storage[ns]=merged;global_headers[ns].bytes=merged.data;}
            else free(merged.data);
            header=global_headers[ns];
        } else if(ok) {
            yx_multi_pattern_bounds_merge(&bounds,&global_bounds[ns]);
            yx_writer merged={0};yx_physical_header result={0};
            ok=yx_header_constraint_merge_into(&header,&global_headers[ns],&result,&merged);
            if(ok){header=result;free(own.data);own=merged;header.bytes=own.data;}
            else free(merged.data);
        }
        /* The rule's finished constraints: what a reference to it merges,
         * and what its patterns get. */
        header_storage[i].used=0;
        if(ok&&header.kind==2&&!yx_put_bytes(&header_storage[i],header.bytes,header.length))ok=false;
        free(own.data);
        if(!ok){p->no_memory=true;break;}
        if(header.kind==2)header.bytes=header_storage[i].data;
        rule_bounds[i]=bounds;
        if(header.kind==1)rule_headers[i].impossible=true;
        else if(header.kind==2&&!yx_header_add(&rule_headers[i],0,header.bytes,header.length)){ok=false;p->no_memory=true;break;}
        c->rule_constraint_count=i+1;
        for(size_t j=0;j<rules->rules[i].pattern_count;++j,++logical) {
            yx_physical_pattern_options *o=&options[logical];size_t id=c->archive->mapping[logical];
            *o=(yx_physical_pattern_options){.limit=c->archive->limits[id],.bounds=rules->rules[i].patterns[j].kind==YX_PATTERN_TEXT?(yx_pattern_filesize_bounds){2,2,0,0}:bounds};
            if(rules->rules[i].patterns[j].kind!=YX_PATTERN_TEXT)o->header=header;
            if(id<physical){o->offset=offset[id];o->anchored=used[id]&&anchor[id];}
            if(states[logical]==1){o->anchored=true;o->offset=offsets[logical];}
            else if(states[logical]==2){o->anchored=false;o->unmarked=unmarked[logical];}
        }
    }
    free(starts);free(states);free(offsets);free(unmarked);free(failed);
    free(used);free(anchor);free(offset);
    for(size_t i=0;rule_headers&&i<rules->rule_count;++i)yx_header_collection_destroy(&rule_headers[i]);
    for(size_t n=0;global_storage&&n<namespaces;++n)free(global_storage[n].data);
    free(rule_bounds);free(rule_headers);free(global_bounds);free(global_headers);free(global_storage);
    c->rule_bounds=NULL;c->rule_headers=NULL;c->rule_constraint_count=0;
    return ok;
}
/* The literals each rule's condition interns, in emission order: a dry
 * emission of every root with a literal pool of its own. The bytes stay
 * owned by `p`'s nodes. */
static bool yx_composed_condition_literals(yx_module_program *p,yx_module_patterns *c,const int *roots,size_t count,
                                           yx_physical_rules *assembly)
{
    assembly->condition_literals=calloc(count,sizeof(*assembly->condition_literals));
    assembly->condition_literal_counts=calloc(count,sizeof(*assembly->condition_literal_counts));
    if(!assembly->condition_literals||!assembly->condition_literal_counts)return false;
    assembly->condition_rule_count=count;p->shifts=true;
    bool ok=true;
    for(size_t i=0;ok&&i<count;++i) {
        yx_writer scratch={0};
        p->literal_count=0;c->searched=false;c->scope_depth=0;p->undefined_slot=-1;
        /* Call offsets refer to the scratch writer: a loop's catch rewrite
         * moves those after its start, so earlier rules' must not remain. */
        p->call_count=0;c->helper_call_count=0;
        ok=yx_module_boolean(p,roots[i],&scratch,0);
        free(scratch.data);
        if(ok&&p->literal_count) {
            if(!(assembly->condition_literals[i]=malloc(p->literal_count*sizeof(*p->literals))))ok=false;
            else {
                memcpy(assembly->condition_literals[i],p->literals,p->literal_count*sizeof(*p->literals));
                assembly->condition_literal_counts[i]=p->literal_count;
            }
        }
    }
    p->literal_count=0;
    return ok;
}
/* `relaxed` also accepts plain rule sets (one namespace, no imports or
 * globals): the last resort after the specialized codecs. */
static yx_ser_result yx_encode_composed_rules_mode(const YRX_RULES *rules,uint8_t profile,uint8_t **data,size_t *length,bool relaxed)
{
    if(!rules||rules->rule_count<1||rules->rule_count>SIZE_MAX/sizeof(int)||
       rules->import_count>32||profile>3)return YX_SER_UNSUPPORTED;
    YRX_RULES unique=*rules;char *unique_imports[32],*unique_namespaces[32];size_t unique_positions[32],unique_ordinals[32];
    unique.import_count=0;
    for(size_t i=0;i<rules->import_count;++i) {
        bool duplicate=false;for(size_t j=0;j<unique.import_count;++j)duplicate|=!strcmp(unique_imports[j],rules->imports[i]);
        if(!duplicate){size_t j=unique.import_count++;unique_imports[j]=rules->imports[i];unique_namespaces[j]=rules->import_namespaces?rules->import_namespaces[i]:NULL;unique_positions[j]=rules->import_rule_indices?rules->import_rule_indices[i]:0;unique_ordinals[j]=rules->import_namespace_indices?rules->import_namespace_indices[i]:0;}
    }
    unique.imports=unique_imports;unique.import_rule_indices=unique_positions;unique.import_namespaces=rules->import_namespaces?unique_namespaces:NULL;unique.import_namespace_indices=rules->import_namespace_indices?unique_ordinals:NULL;rules=&unique;
    size_t logical=0;bool special=rules->global_count||rules->import_count||rules->namespace_count>1;
    const char *first_ns=rules->rules[0].namespace_name?rules->rules[0].namespace_name:"default";
    for(size_t i=0;i<rules->rule_count;++i) {
        special|=rules->rules[i].is_global||rules->rules[i].namespace_index!=rules->rules[0].namespace_index||strcmp(first_ns,rules->rules[i].namespace_name?rules->rules[i].namespace_name:"default");
        if(!rules->rules[i].condition_text||rules->rules[i].pattern_count>SIZE_MAX-logical)return YX_SER_UNSUPPORTED;
        logical+=rules->rules[i].pattern_count;
    }
    if(!special&&!relaxed)return YX_SER_UNSUPPORTED;
    yx_module_pattern_schema schema={0};yx_physical_rules assembly={0};
    yx_physical_archive *provisional=calloc(1,sizeof(*provisional));yx_module_program *p=calloc(1,sizeof(*p)),*dry=NULL;
    yx_module_patterns c={0};yx_physical_pattern_options *options=calloc(logical?logical:1,sizeof(*options));int *roots=calloc(rules->rule_count,sizeof(*roots));
    yx_writer *header_storage=calloc(rules->rule_count,sizeof(*header_storage));
    uint8_t *wasm=NULL;size_t wasm_length=0;yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!provisional||!p||!roots||!options||!header_storage){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_physical_patterns_reserve(provisional,logical)){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_module_pattern_schema_build(&schema,rules,profile))goto done;
    for(size_t i=0,k=0;i<rules->rule_count;++i)for(size_t j=0;j<rules->rules[i].pattern_count;++j,++k) {
        provisional->name_ids[k]=yx_physical_ident(provisional,rules->rules[i].patterns[j].identifier);
        if(provisional->name_ids[k]==SIZE_MAX){status=YX_SER_NO_MEMORY;goto done;}
        provisional->mapping[k]=k;provisional->kinds[k]=(uint8_t)rules->rules[i].patterns[j].kind;
    }
    provisional->physical=provisional->logical=logical;c.archive=provisional;yx_module_pattern_setup(p,&c);
    p->schema=&schema.dynamic.schema;p->profile=profile;p->capi_import_order=!rules->archive_cli&&profile==0;
    if(!yx_composed_parse_rules(p,&c,rules,roots)||!yx_composed_options(p,rules,roots,options,header_storage)||
       !yx_composed_condition_literals(p,&c,roots,rules->rule_count,&assembly)){if(p->no_memory)status=YX_SER_NO_MEMORY;goto done;}
    assembly.archive=calloc(1,sizeof(*assembly.archive));if(!assembly.archive){status=YX_SER_NO_MEMORY;goto done;}
    if(yx_physical_ident(assembly.archive,"default")!=0){status=YX_SER_NO_MEMORY;goto done;}
    assembly.archive->globals=schema.dynamic.globals.data;assembly.archive->globals_length=schema.dynamic.globals.used;
    status=yx_physical_rules_build(rules,options,&assembly);if(status!=YX_SER_SUCCESS)goto done;
    /* The condition literals stay borrowed from the first program's nodes. */
    status=YX_SER_UNSUPPORTED;dry=p;p=calloc(1,sizeof(*p));if(!p){status=YX_SER_NO_MEMORY;goto done;}
    free(c.helper_calls);free(c.regexes);c=(yx_module_patterns){.archive=assembly.archive};yx_module_pattern_setup(p,&c);
    p->schema=&schema.dynamic.schema;p->profile=profile;p->capi_import_order=!rules->archive_cli&&profile==0;
    switch(yx_composed_adopt_pool(p,assembly.archive->pool,assembly.archive->pool_count)) {
    case 0: goto done;
    case 1: break;
    default:
    for(size_t i=0;i<assembly.archive->pool_count;++i) {
        size_t id;
        if(!yx_intern_literal(assembly.archive->pool[i].data,assembly.archive->pool[i].length,&p->literals,&p->literal_count,&p->literal_capacity,&id)||id!=i)goto done;
    }
    }
    if(!yx_composed_parse_rules(p,&c,rules,roots)||!yx_composed_module_wasm(p,roots,rules->rule_count,&wasm,&wasm_length))goto done;
    if(!yx_physical_pool_reserve(assembly.archive,p->literal_count)){status=YX_SER_NO_MEMORY;goto done;}
    assembly.archive->pool_count=p->literal_count;if(p->literal_count)memcpy(assembly.archive->pool,p->literals,p->literal_count*sizeof(*p->literals));
    if(c.regex_count) {
        if(!(assembly.archive->regexps=malloc(c.regex_count*sizeof(*c.regexes)))){status=YX_SER_NO_MEMORY;goto done;}
        memcpy(assembly.archive->regexps,c.regexes,c.regex_count*sizeof(*c.regexes));assembly.archive->regexp_count=c.regex_count;
    }
    yx_physical_index_reset(assembly.archive);
    status=yx_physical_rules_write(&assembly,wasm,wasm_length,data,length);
done:
    if(header_storage)for(size_t i=0;i<rules->rule_count;++i)free(header_storage[i].data);
    free(c.helper_calls);free(c.regexes);free(header_storage);free(options);free(roots);free(wasm);yx_module_program_free(p);if(provisional){yx_physical_destroy(provisional);free(provisional);}
    yx_physical_rules_destroy(&assembly);yx_module_program_free(dry);yx_module_pattern_schema_free(&schema);return status;
}
static yx_ser_result yx_encode_composed_rules_profile(const YRX_RULES *rules,uint8_t profile,uint8_t **data,size_t *length)
{
    return yx_encode_composed_rules_mode(rules,profile,data,length,false);
}
static yx_ser_result yx_decode_composed_rules_mode(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *rule_count,bool relaxed)
{
    size_t begin,end,count=0,logical=0,*firsts=NULL,*counts=NULL,*ids=NULL,*namespaces=NULL,*metadata_starts=NULL;
    size_t *names=NULL,*mapping=NULL,*body_starts=NULL,*body_ends=NULL;
    uint8_t *kinds=NULL;bool *private_patterns=NULL,*private_rules=NULL,*global_rules=NULL,*referenced=NULL,*tracked=NULL;
    yx_physical_pattern_options *options=NULL;uint64_t *limits=NULL;yx_writer *header_storage=NULL;uint16_t *frame_flags=NULL;
    yx_physical_archive *a=calloc(1,sizeof(*a));yx_ser_rule *decoded=NULL;YRX_RULES *loaded=NULL;
    yx_module_program *p=calloc(1,sizeof(*p));yx_module_pattern_schema schema={0};yx_module_patterns c={0};
    YRX_RULE *source_rules=NULL;YRX_RULES source={0};char *module_names[32]={0};
    yx_global *globals=NULL;size_t global_count=0;int *roots=NULL;
    uint8_t *base=NULL,*canonical=NULL,*wasm=NULL,*shifted=NULL;size_t base_length=0,canonical_length=0,wasm_length=0;
    yx_writer metadata={0},fake_metadata={0};yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!a||!p){status=YX_SER_NO_MEMORY;goto done;}
    if(!yx_multi_pattern_metadata_span(data,length,&begin,&end))goto done;
    size_t logical_capacity=(end-begin)/4;
    if(logical_capacity>SIZE_MAX/sizeof(*names))goto done;
    names=calloc(logical_capacity?logical_capacity:1,sizeof(*names));mapping=calloc(logical_capacity?logical_capacity:1,sizeof(*mapping));
    kinds=calloc(logical_capacity?logical_capacity:1,sizeof(*kinds));private_patterns=calloc(logical_capacity?logical_capacity:1,sizeof(*private_patterns));
    referenced=calloc(logical_capacity?logical_capacity:1,sizeof(*referenced));tracked=calloc(logical_capacity?logical_capacity:1,sizeof(*tracked));
    if(!names||!mapping||!kinds||!private_patterns||!referenced||!tracked){status=YX_SER_NO_MEMORY;goto done;}
    yx_reader r={data,length,begin,false,false};uint64_t n,width;uint8_t flag;
    if(!yx_get_uint(&r,&n)||!n||n>length/8||n>SIZE_MAX/sizeof(YRX_RULE))goto done;
    count=(size_t)n;
    firsts=calloc(count,sizeof(*firsts));counts=calloc(count,sizeof(*counts));ids=calloc(count,sizeof(*ids));namespaces=calloc(count,sizeof(*namespaces));metadata_starts=calloc(count,sizeof(*metadata_starts));
    private_rules=calloc(count,sizeof(*private_rules));global_rules=calloc(count,sizeof(*global_rules));source_rules=calloc(count,sizeof(*source_rules));roots=calloc(count,sizeof(*roots));
    if(!firsts||!counts||!ids||!namespaces||!metadata_starts||!private_rules||!global_rules||!source_rules||!roots){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i) {
        metadata_starts[i]=r.at;roots[i]=-1;
        size_t saved_at=r.at;uint64_t namespace_ordinal;
        if(!yx_get_uint(&r,&namespace_ordinal)||(namespace_ordinal&1u)||namespace_ordinal/2>SIZE_MAX)goto done;
        source_rules[i].namespace_index=(size_t)(namespace_ordinal/2);r.at=saved_at;
        if(!yx_multi_pattern_metadata_read(&r,NULL,NULL,&namespaces[i],&ids[i])||
           !yx_get_uint(&r,&width)||width>logical_capacity-logical)goto done;
        firsts[i]=logical;counts[i]=(size_t)width;size_t private_count=0;
        for(size_t j=0;j<counts[i];++j) {
            if(!yx_get_uint(&r,&n)||(n&1u)||n/2>=logical_capacity)goto done;
            mapping[logical]=(size_t)(n/2);
            if(!yx_get_uint(&r,&n)||n>=length)goto done;
            names[logical]=(size_t)n;
            if(!yx_get_uint(&r,&n)||n>2||!yx_get_u8(&r,&flag)||flag>1)goto done;
            kinds[logical]=(uint8_t)n;private_patterns[logical]=flag!=0;private_count+=flag;++logical;
        }
        if(!yx_expect_uint(&r,private_count)||!yx_get_uint(&r,&n)||n>1||!yx_get_u8(&r,&flag)||flag>1)goto done;
        private_rules[i]=flag!=0;global_rules[i]=n!=0;
    }
    if(r.at!=end)goto done;
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
    if(!yx_physical_read(base,base_length,a)||a->import_count>32)goto done;
    yx_reader gr={a->globals,a->globals_length,0,false,false};uint64_t fields;
    if(!yx_get_uint(&gr,&fields)||fields<a->import_count||fields-a->import_count>UINT16_MAX)goto done;
    if(!fields) {
        bool special=false;for(size_t i=0;i<count;++i)special|=global_rules[i]||namespaces[i]!=namespaces[0]||source_rules[i].namespace_index!=0;
        if(!special&&!relaxed)goto done;
    }
    for(size_t i=0;i<count;++i) {
        if(ids[i]>=a->name_count||namespaces[i]>=a->name_count||!yx_valid_rule_name(a->names[ids[i]]))goto done;
        source_rules[i].identifier=a->names[ids[i]];source_rules[i].namespace_name=a->names[namespaces[i]];source_rules[i].is_global=global_rules[i];
    }
    status=yx_physical_write(a,&canonical,&canonical_length);if(status!=YX_SER_SUCCESS)goto done;
    uint8_t *whole=NULL;size_t whole_length=0;
    status=yx_multi_pattern_replace_metadata(canonical,canonical_length,&metadata,&whole,&whole_length);
    free(canonical);canonical=whole;canonical_length=whole_length;
    if(status!=YX_SER_SUCCESS)goto done;
    status=YX_SER_UNSUPPORTED;
    if(canonical_length!=length||memcmp(canonical,data,length))goto done;
    for(size_t i=0;i<a->import_count;++i) {
        module_names[i]=a->names[a->imports[i]];if(!yx_archive_schema(module_names[i]))goto done;
    }
    source.rules=source_rules;source.rule_count=count;source.import_count=a->import_count;source.imports=module_names;
    global_count=(size_t)(fields-a->import_count);
    if(global_count) {
        globals=calloc(global_count,sizeof(*globals));if(!globals){global_count=0;status=YX_SER_NO_MEMORY;goto done;}
        for(size_t i=0;i<global_count;++i) {
            yx_global_scalar_value value={0};
            if(!yx_get_string(&gr,&globals[i].name)||!yx_expect_uint(&gr,0))goto done;
            bool ok=yx_archive_global_read_value(&gr,&globals[i].type,&value,0);memcpy(&globals[i].value,&value,sizeof(value));if(!ok)goto done;
        }
        source.globals=globals;source.global_count=global_count;
    }
    if(!yx_module_pattern_schema_build(&schema,&source,0))goto done;
    p->schema=&schema.dynamic.schema;c.archive=a;c.prior=(yx_global_rules_context){source_rules,count,count};yx_module_pattern_setup(p,&c);
    if(a->regexp_count) {
        if(!(c.regexes=malloc(a->regexp_count*sizeof(*c.regexes)))){status=YX_SER_NO_MEMORY;goto done;}
        memcpy(c.regexes,a->regexps,a->regexp_count*sizeof(*c.regexes));c.regex_count=c.regex_capacity=a->regexp_count;
    }
    p->literal_count=p->literal_capacity=a->pool_count;p->literals=calloc(a->pool_count?a->pool_count:1,sizeof(*p->literals));
    if(!p->literals){status=YX_SER_NO_MEMORY;goto done;}if(a->pool_count)memcpy(p->literals,a->pool,a->pool_count*sizeof(*p->literals));
    yx_reader wr={a->wasm,a->wasm_length,0,false,false};size_t code_end;uint64_t functions;
    if(!yx_module_pattern_decode_header_mode(&wr,p,&code_end,true)||code_end!=wr.length||!yx_get_uleb(&wr,&functions)||
       functions>wr.length/2)goto done;
    size_t chunk_count=0;
    for(size_t first=0;first<count;) {
        size_t last=first+1;while(last<count&&source_rules[last].namespace_index==source_rules[first].namespace_index)++last;
        chunk_count+=(last-first+9)/10;first=last;
    }
    size_t last_namespace=source_rules[count-1].namespace_index;
    size_t wrapper_count=last_namespace?last_namespace/20+(last_namespace%20!=0):1;
    if(wrapper_count>SIZE_MAX-chunk_count-1-c.presence||
       functions<chunk_count+wrapper_count+1+c.presence)goto done;
    body_starts=calloc((size_t)functions,sizeof(*body_starts));body_ends=calloc((size_t)functions,sizeof(*body_ends));
    if(!body_starts||!body_ends){status=YX_SER_NO_MEMORY;goto done;}
    static const uint8_t helper[]={1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
    bool found_helper=!c.presence;size_t match_id=SIZE_MAX,no_match_id=SIZE_MAX;
    for(size_t i=0;i<p->import_count;++i) {
        if(!strcmp(p->imports[i].name,"rule_match@rule_id:i@"))match_id=i;
        if(!strcmp(p->imports[i].name,"rule_no_match@rule_id:i@"))no_match_id=i;
    }
    if(match_id==SIZE_MAX)goto done;
    for(size_t f=0;f<(size_t)functions;++f) {
        if(!yx_get_uleb(&wr,&width)||width>wr.length-wr.at)goto done;
        body_starts[f]=wr.at;body_ends[f]=wr.at+(size_t)width;
        if(width==sizeof(helper)&&!memcmp(wr.data+wr.at,helper,sizeof(helper))) {
            if(found_helper)goto done;
            c.helper_id=p->import_count+f;found_helper=true;
        }
        wr.at=body_ends[f];
    }
    if(!found_helper||wr.at!=wr.length)goto done;
    size_t actual_chunks=0;
    for(size_t f=0;f<(size_t)functions;++f) {
        wr.at=body_starts[f];size_t body_end=body_ends[f];uint64_t locals;
        if(c.presence&&p->import_count+f==c.helper_id)continue;
        /* Rule chunks declare emit_switch's i32 temporary, one or two i64
         * ones (range bounds), or both: then the i64 ones are numbered after
         * the i32 one, and the writer's numbering is restored in a copy. */
        if(!yx_get_uleb(&wr,&locals)||locals>2)goto done;
        bool narrow=false,wide=false;
        for(uint64_t g=0;g<locals;++g) {
            if(!yx_get_uleb(&wr,&n)||!yx_get_u8(&wr,&flag))goto done;
            if(flag==0x7f&&n==1&&!g&&!narrow)narrow=true;
            else if(flag==0x7e&&n>=1&&n<=2&&!wide)wide=true;
            else goto done;
        }
        if(narrow&&wide) {
            if(!shifted) {
                if(!(shifted=malloc(wr.length))){status=YX_SER_NO_MEMORY;goto done;}
                memcpy(shifted,wr.data,wr.length);wr.data=shifted;
            }
            if(!yx_module_shift_wide_locals(shifted+wr.at,body_end-wr.at-1,-1))goto done;
        }
        p->undefined_slot=-1;
        if(wr.at+1<body_end&&wr.data[wr.at]==2&&wr.data[wr.at+1]==0x7f)++actual_chunks;
        while(wr.at+1<body_end&&wr.data[wr.at]==2&&wr.data[wr.at+1]==0x7f) {
            wr.at+=2;size_t start=p->count;int root=yx_module_decode_block(&wr,body_end,p,0);int64_t id;
            static const uint8_t suffix[]={0x45,4,0x40};int64_t failed_id=-1;
            if(root<0||!yx_integer_wasm_bytes(&wr,body_end,suffix,sizeof(suffix)))goto done;
            if(wr.at<body_end&&wr.data[wr.at]==0x41) {
                ++wr.at;
                if(!yx_get_sleb_i64(&wr,&failed_id)||failed_id<0||!yx_rule_expression_byte(&wr,0x10)||!yx_get_uleb(&wr,&n)||n!=no_match_id||
                   !yx_rule_expression_byte(&wr,0x41)||!yx_rule_expression_byte(&wr,1)||!yx_rule_expression_byte(&wr,0x0f))goto done;
            }
            if(!yx_rule_expression_byte(&wr,5)||!yx_rule_expression_byte(&wr,0x41)||!yx_get_sleb_i64(&wr,&id)||id<0||
               (uint64_t)id>=count||roots[id]>=0||global_rules[id]!=(failed_id>=0)||(failed_id>=0&&failed_id!=id)||!yx_rule_expression_byte(&wr,0x10)||!yx_get_uleb(&wr,&n)||n!=match_id||!yx_rule_expression_byte(&wr,0x0b))goto done;
            for(size_t j=start;j<p->count;++j) {
                const yx_module_node *node=&p->nodes[j];
                if(node->op==YX_GLOBAL_RULE_REFERENCE&&(node->integer>=id||node->integer<0||source_rules[node->integer].namespace_index!=source_rules[id].namespace_index))goto done;
                if(node->op>=YX_MP_PRESENT&&node->op<=YX_MP_COUNT_IN&&node->integer<0) {
                    const yx_module_node *loop=yx_module_pattern_owner(p,node);
                    if(!loop||loop<p->nodes+start)goto done;
                } else if(node->op>=YX_MP_PRESENT&&node->op<=YX_MP_COUNT_IN) {
                    bool owned=false;for(size_t k=0;k<counts[id];++k)if(node->integer==(int64_t)mapping[firsts[id]+k])owned=referenced[firsts[id]+k]=true;if(!owned)goto done;
                }
                if(node->op==YX_MP_OF||node->op==YX_MP_FOR_OF)for(size_t m=0;m<node->length;++m) {
                    bool owned=false;uint32_t pattern=((const uint32_t *)node->bytes)[m];
                    for(size_t k=0;k<counts[id];++k)if(pattern==mapping[firsts[id]+k])owned=referenced[firsts[id]+k]=true;if(!owned)goto done;
                }
            }
            roots[id]=root;
        }
    }
    for(size_t i=0;i<count;++i)if(roots[i]<0)goto done;
    /* Budget-limited chunks can contain fewer than ten rules. Count actual
     * rule bodies before separating them from empty namespace wrappers. */
    if(actual_chunks<chunk_count||actual_chunks>count||
       wrapper_count>SIZE_MAX-actual_chunks-1-c.presence||
       functions<actual_chunks+wrapper_count+1+c.presence)goto done;
    wrapper_count=(size_t)functions-actual_chunks-1-c.presence;
    if(wrapper_count>(SIZE_MAX-1)/20)goto done;
    c.namespace_count=wrapper_count*20+1;
    uint8_t profile=4;bool found=false;
    for(unsigned frontend=0;frontend<2&&!found;++frontend)for(profile=0;profile<4;++profile) {
        p->profile=profile;p->capi_import_order=frontend==0&&profile==0;free(wasm);wasm=NULL;
        yx_module_pattern_schema expected={0};
        if(!yx_module_pattern_schema_build(&expected,&source,profile)){yx_module_pattern_schema_free(&expected);goto done;}
        bool same=a->globals_length==expected.dynamic.globals.used&&!memcmp(a->globals,expected.dynamic.globals.data,a->globals_length);yx_module_pattern_schema_free(&expected);
        if(same&&yx_composed_module_wasm(p,roots,count,&wasm,&wasm_length)&&wasm_length==a->wasm_length&&
           !memcmp(wasm,a->wasm,wasm_length)&&c.regex_count==a->regexp_count){found=true;break;}
    }
    if(!found)goto done;
    decoded=calloc(count,sizeof(*decoded));if(!decoded){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i) {
        r.at=metadata_starts[i];if(!yx_multi_pattern_metadata_read(&r,a,&decoded[i],&namespaces[i],&ids[i]))goto done;
        source_rules[i].identifier=decoded[i].identifier;source_rules[i].namespace_name=decoded[i].namespace_name;
        decoded[i].namespace_index=source_rules[i].namespace_index;decoded[i].is_private=private_rules[i];decoded[i].is_global=global_rules[i];decoded[i].truth=true;decoded[i].preserve_serialized_prefix=true;
    }
    for(size_t i=0;i<count;++i) {
        yx_writer text={0};c.prior.current=i;c.rule_scope=true;c.logical_start=firsts[i];c.logical_count=counts[i];
        bool valid=yx_module_print(p,roots[i],&text,0);
        for(size_t j=0;valid&&j<counts[i];++j) {
            size_t k=firsts[i]+j;bool duplicate=false;for(size_t q=firsts[i];q<k;++q)duplicate|=mapping[q]==mapping[k];
            /* A pattern whose operands IR::and / IR::or folded away is still
             * a pattern of the rule: name it where it folds away again. */
            if(duplicate||!referenced[k])valid=yx_tr_text(&text," and (true or ")&&yx_tr_text(&text,a->names[names[k]])&&yx_put_u8(&text,')');
        }
        if(!valid||!yx_put_u8(&text,0)){free(text.data);goto done;}
        decoded[i].runtime_integer_condition=(char *)text.data;decoded[i].runtime_integer_import_profile=profile;
    }
    if(logical&&!yx_physical_reconstruct_patterns(a,&loaded))goto done;
    for(size_t i=0;i<count;++i){source_rules[i].patterns=logical?loaded->rules[0].patterns+firsts[i]:NULL;source_rules[i].pattern_count=counts[i];}
    header_storage=calloc(count,sizeof(*header_storage));
    options=calloc(logical?logical:1,sizeof(*options));limits=calloc(a->physical?a->physical:1,sizeof(*limits));
    if(!options||!limits||!header_storage){status=YX_SER_NO_MEMORY;goto done;}
    if(a->physical)memcpy(limits,a->limits,a->physical*sizeof(*limits));
    /* The anchors are those of the decoded conditions, which name the
     * patterns as the archive does. */
    const char **anchor_names=malloc((logical?logical:1)*sizeof(*anchor_names));
    if(!anchor_names){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t k=0;k<logical;++k)anchor_names[k]=a->names[names[k]];
    c.anchor_names=anchor_names;
    for(size_t i=0;i<count;++i)if(!source_rules[i].condition_text)source_rules[i].condition_text=decoded[i].runtime_integer_condition;
    bool options_ok=yx_composed_options(p,&source,roots,options,header_storage);if(a->physical)memcpy(a->limits,limits,a->physical*sizeof(*limits));
    for(size_t i=0;i<count;++i)if(source_rules[i].condition_text==decoded[i].runtime_integer_condition)source_rules[i].condition_text=NULL;
    c.anchor_names=NULL;free((void *)anchor_names);
    /* disallow_fast_scan (ast2ir.rs) also runs for an operand that is folded
     * away afterwards (`($a at 0 and false) or $b`): the archive then tracks
     * every match of a pattern that the remaining operands would limit.
     * The decoded condition says so in a term that folds away again. */
    for(size_t k=0;options_ok&&k<logical;++k)
        if(mapping[k]<a->physical&&!a->limits[mapping[k]]&&options[k].limit){tracked[k]=true;options[k].limit=0;}
    if(!options_ok||!yx_physical_rules_options_equal(a,options))goto done;
    for(size_t i=0;i<count;++i) {
        yx_writer text={0};bool any=false,valid=true;
        for(size_t j=0;j<counts[i];++j)any|=tracked[firsts[i]+j];
        if(!any)continue;
        valid=yx_tr_text(&text,decoded[i].runtime_integer_condition);
        for(size_t j=0;valid&&j<counts[i];++j)if(tracked[firsts[i]+j])
            valid=yx_tr_text(&text," and (true or ")&&yx_tr_text(&text,a->names[names[firsts[i]+j]])&&yx_tr_text(&text," in (0..1))");
        if(!valid||!yx_put_u8(&text,0)){free(text.data);status=YX_SER_NO_MEMORY;goto done;}
        free(decoded[i].runtime_integer_condition);decoded[i].runtime_integer_condition=(char *)text.data;
    }
    /* The frame flags of every physical pattern in one pass: a scan of
     * every frame per declaration is quadratic in large rule sets. */
    frame_flags=yx_physical_frame_flags(a);
    if(!frame_flags){status=YX_SER_NO_MEMORY;goto done;}
    for(size_t i=0;i<count;++i)if(counts[i]) {
        yx_writer declarations={0};bool valid=true;
        decoded[i].runtime_literal_prefilters=calloc(counts[i],sizeof(*decoded[i].runtime_literal_prefilters));
        if(!decoded[i].runtime_literal_prefilters){status=YX_SER_NO_MEMORY;goto done;}
        decoded[i].runtime_literal_prefilter_count=counts[i];
        decoded[i].runtime_regexp_programs=calloc(counts[i],sizeof(*decoded[i].runtime_regexp_programs));
        if(!decoded[i].runtime_regexp_programs){status=YX_SER_NO_MEMORY;goto done;}
        decoded[i].runtime_regexp_program_count=counts[i];
        for(size_t j=0;valid&&j<counts[i];++j) {
            size_t k=firsts[i]+j;valid=yx_physical_flagged_declaration(&declarations,a->names[names[k]],&loaded->rules[0].patterns[k],a,frame_flags,mapping[k]);
            if(valid&&private_patterns[k])valid=yx_tr_text(&declarations,"private ");
            if(valid)valid=yx_physical_copy_prefilter(&decoded[i].runtime_literal_prefilters[j],
                &loaded->rules[0].patterns[k].archived_literal_prefilter);
            if(valid)valid=yx_physical_copy_regexp(&decoded[i].runtime_regexp_programs[j],
                loaded->rules[0].patterns[k].archived_regexp);
        }
        if(!valid||!yx_put_u8(&declarations,0)){free(declarations.data);goto done;}decoded[i].runtime_pattern_declarations=(char *)declarations.data;
    }
    decoded[0].runtime_module_names=calloc(a->import_count?a->import_count:1,sizeof(*decoded[0].runtime_module_names));
    if(!decoded[0].runtime_module_names){status=YX_SER_NO_MEMORY;goto done;}decoded[0].runtime_module_count=a->import_count;
    for(size_t i=0;i<a->import_count;++i)if(!(decoded[0].runtime_module_names[i]=yx_copy_string(module_names[i]))){status=YX_SER_NO_MEMORY;goto done;}
    decoded[0].runtime_globals=globals;decoded[0].runtime_global_count=global_count;globals=NULL;global_count=0;
    *rules=decoded;*rule_count=count;decoded=NULL;status=YX_SER_SUCCESS;
done:
    if(a){yx_physical_destroy(a);free(a);}yx_ser_rules_destroy(decoded,decoded?count:0);yrx_rules_destroy(loaded);yx_module_program_free(p);yx_module_pattern_schema_free(&schema);yx_archive_globals_destroy(globals,global_count);
    if(header_storage)for(size_t i=0;i<count;++i)free(header_storage[i].data);
    free(c.helper_calls);free(c.regexes);free(header_storage);
    free(names);free(mapping);free(kinds);free(private_patterns);free(referenced);free(tracked);free(options);free(limits);
    free(firsts);free(counts);free(ids);free(namespaces);free(metadata_starts);free(private_rules);free(global_rules);free(source_rules);free(roots);free(body_starts);free(body_ends);
    free(base);free(canonical);free(wasm);free(shifted);free(metadata.data);free(fake_metadata.data);free(frame_flags);return status;
}
static yx_ser_result yx_decode_composed_rules(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *rule_count)
{
    return yx_decode_composed_rules_mode(data,length,rules,rule_count,false);
}
/* The relaxed decoder loads its physical patterns through one-pattern
 * archives; those never fall back to it again (no unbounded recursion). */
#ifdef _MSC_VER
static __declspec(thread) unsigned yx_composed_relaxed_depth;
#else
static _Thread_local unsigned yx_composed_relaxed_depth;
#endif
static yx_ser_result yx_decode_composed_rules_relaxed(const uint8_t *data,size_t length,yx_ser_rule **rules,size_t *rule_count)
{
    if(yx_composed_relaxed_depth||yx_physical_inspect_nesting)return YX_SER_UNSUPPORTED;
    ++yx_composed_relaxed_depth;
    yx_ser_result status=yx_decode_composed_rules_mode(data,length,rules,rule_count,true);
    --yx_composed_relaxed_depth;
    return status;
}
/* The relaxed writer encodes each pattern as a one-pattern rule set, which
 * must not reach it again (no unbounded recursion either). */
static yx_ser_result yx_encode_composed_rules_relaxed(const YRX_RULES *rules,uint8_t profile,uint8_t **data,size_t *length)
{
    if(yx_composed_relaxed_depth)return YX_SER_UNSUPPORTED;
    ++yx_composed_relaxed_depth;
    yx_ser_result status=yx_encode_composed_rules_mode(rules,profile,data,length,true);
    --yx_composed_relaxed_depth;
    return status;
}
