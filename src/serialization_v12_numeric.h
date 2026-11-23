/* Numeric rule chunks are decoded from their bounded operands, then the
 * complete legacy module is independently rebuilt and lowered for validation.
 * Rule-match immediates identify rules after instruction-count sorting. */
static int yx_v12_numeric_rule(const uint8_t *body,yx_v12_instruction *ins,size_t count,
    size_t first,size_t finish,const yx_integer_expr *imports,
    yx_rule_expression_context *context,yx_integer_expr *decoded)
{
    yx_integer_expr tree=*imports;yx_writer expression={0};int root=-1;tree.loop_failures=NULL;tree.loop_failure_count=tree.loop_failure_capacity=0;
    yx_rule_expression_setup(&tree,context);
    if(first>=finish||finish>count)goto done;
    /* The rules of one function are decoded in order on the same `ins`:
     * the blocks before `first` were marked by the earlier calls. */
    size_t marked=first;
    bool range=false;
    for(size_t i=first+1;i<finish;++i)
        if(ins[i].op==3&&ins[i].parent==first){range=true;break;}
    if(!range&&ins[first].op==2&&ins[first].argument==0x7f&&ins[first].mate+1==finish) {
        ++first;--finish;
    }
    for(size_t i=marked;i<finish;++i) {
        if(ins[i].op!=2||ins[i].argument!=0x7f||i+1>=count)continue;
        size_t inner=i+1,end=ins[inner].mate;
        if(ins[inner].op!=2||ins[inner].argument!=0x40||end==SIZE_MAX||
           end+2!=ins[i].mate||end<inner+2||ins[end+1].op!=0x41||
           ins[end+1].end-ins[end+1].start!=2||body[ins[end+1].start+1]>1||
           ins[end-1].op!=0x0c||ins[end-1].argument!=1)continue;
        ins[inner].boolean_block=true;ins[inner].short_value=body[ins[end+1].start+1];
        ins[inner].remove=ins[end-1].remove=ins[end].remove=ins[end+1].remove=true;
        if(ins[inner].short_value&&end>=inner+4&&ins[end-3].op==0x0d&&
           !ins[end-3].argument&&ins[end-2].op==0x41&&
           ins[end-2].end-ins[end-2].start==2&&!body[ins[end-2].start+1])
            ins[end-3].remove=ins[end-2].remove=true;
    }
    /* A numeric OR operand catches undefined values in a void block. Undo
     * that local catch separately from the OR's enclosing success block. */
    for(size_t i=first;i<finish;++i) {
        yx_v12_instruction *p=&ins[i];size_t parent=p->parent,end=p->mate;
        if(p->op!=2||p->argument!=0x40||parent==SIZE_MAX||
           !ins[parent].boolean_block||!ins[parent].short_value||
           end==SIZE_MAX||end<=i+1||ins[end-1].op!=0x0d||ins[end-1].argument!=1)continue;
        p->or_operand=true;ins[end-1].remove=true;
        p->or_last=end+3==ins[parent].mate&&ins[end+1].op==0x41&&
            ins[end+1].end-ins[end+1].start==2&&!body[ins[end+1].start+1];
        if(p->or_last)ins[end+1].remove=true;
    }
    for(size_t i=first;i<finish;++i) {
        if(ins[i].op!=0x0c&&ins[i].op!=0x0d)continue;
        size_t target=ins[i].parent;
        for(uint64_t d=0;d<ins[i].argument&&target!=SIZE_MAX;++d)target=ins[target].parent;
        if(ins[i].remove||target==SIZE_MAX)continue;
        if(ins[target].or_operand&&ins[i].op==0x0c) {
            ins[i].catch_undef=true;continue;
        }
        if(!ins[target].boolean_block)continue;
        if(ins[i].op==0x0d) {
            if(ins[i].parent!=target)goto done;
            ins[i].short_circuit=true;ins[i].short_value=ins[target].short_value;
            if(!ins[i].short_value) {
                if(!i||ins[i-1].op!=0x45)goto done;ins[i-1].remove=true;
            }
        } else {
            if(ins[target].short_value)goto done;ins[i].catch_undef=true;
        }
    }
    for(size_t i=first;i<finish;++i) {
        if(ins[i].op>=0x28&&ins[i].op<=0x3e)tree.has_memory=true;
        if(ins[i].op==0x23) {
            if(ins[i].argument!=1)goto done;tree.has_filesize=true;
        }
        if(i&&(ins[i-1].op==0x53||ins[i-1].op==0x50)&&
           ins[i].op==4&&ins[i].argument==0x40&&ins[i].alternative!=SIZE_MAX&&
           ins[i].mate==ins[i].alternative+1&&ins[i].mate+1<finish&&
           ins[ins[i].mate+1].op==0x20) {
            ins[i].move_value=true;ins[ins[i].mate+1].remove=true;
        }
    }
    for(size_t i=first;i<finish;++i) {
        yx_v12_instruction *p=&ins[i];
        if(p->remove)continue;
        if(p->or_operand) {
            if(!yx_put_u8(&expression,2)||!yx_put_u8(&expression,0x7f))goto done;
        } else if(p->op==0x0b&&p->mate!=SIZE_MAX&&ins[p->mate].or_operand) {
            if(!yx_put_u8(&expression,0x0b)||(!ins[p->mate].or_last&&
               !yx_put_bytes(&expression,yx_integer_or_guard,sizeof(yx_integer_or_guard))))goto done;
        } else if(p->short_circuit) {
            const uint8_t *guard=p->short_value?yx_integer_or_guard:yx_integer_and_guard;
            size_t width=p->short_value?sizeof(yx_integer_or_guard):sizeof(yx_integer_and_guard);
            if(!yx_put_bytes(&expression,guard,width))goto done;
        } else if(p->op==0x0c||p->op==0x0d) {
            size_t parent=p->parent;uint64_t adjusted=p->argument;
            for(uint64_t d=0;d<p->argument&&parent!=SIZE_MAX;++d) {
                if(ins[parent].boolean_block)--adjusted;
                parent=ins[parent].parent;
            }
            if(p->catch_undef&&(!yx_put_u8(&expression,0x41)||!yx_put_u8(&expression,0)))goto done;
            if(!yx_put_u8(&expression,p->op)||!yx_put_uleb(&expression,adjusted))goto done;
        } else if(p->op==0x23) {
            if(!yx_put_u8(&expression,0x23)||!yx_put_u8(&expression,0))goto done;
        } else if(p->op==4&&p->move_value) {
            if(!yx_put_u8(&expression,4)||!yx_put_u8(&expression,0x7e))goto done;
        } else {
            if(!yx_put_bytes(&expression,body+p->start,p->end-p->start))goto done;
            if(p->op==5&&p->parent!=SIZE_MAX&&ins[p->parent].move_value) {
                yx_v12_instruction *value=&ins[ins[p->parent].mate+1];
                if(!yx_put_bytes(&expression,body+value->start,value->end-value->start))goto done;
            }
        }
    }
    if(!yx_put_u8(&expression,0x0b))goto done;
    yx_reader reader={expression.data,expression.used,0,false,false};
    root=yx_integer_wasm_block(&reader,reader.length,&tree,0,-1);
    if(root<0||reader.at!=reader.length){root=-1;goto done;}
    *decoded=tree;tree.extra_nodes=NULL;tree.bindings=NULL;tree.loop_failures=NULL;
done:
    free(expression.data);yx_integer_expr_destroy(&tree);return root;
}

static bool yx_v12_restore_numeric_rules(const uint8_t *data,size_t length,
    size_t rule_count,yx_writer *restored)
{
    const uint8_t *parts[13];size_t sizes[13];yx_integer_expr imports={0};
    yx_tree_store store={0};yx_tree_list trees={NULL,&store};
    int *roots=NULL;uint8_t *seed=NULL;size_t seed_length=0;bool ok=false;uint64_t n;
    yx_rule_expression_context context={0};
    if(!rule_count||rule_count>INT32_MAX||rule_count>length||
       rule_count>SIZE_MAX/sizeof(int)||!yx_v12_sections(data,length,parts,sizes)||
       !parts[2]||!parts[3]||!parts[10])return false;
    yx_reader r={parts[2],sizes[2],0,false,false};imports.match_id=255;
    if(!yx_get_uleb(&r,&n)||n>YX_INTEGER_READ_COUNT+1)goto done;
    for(size_t i=0;i<n;++i) {
        char module[64],name[256],expected[256];uint8_t kind;uint64_t type;
        if(!yx_v12_read_name(&r,module,sizeof(module))||strcmp(module,"yara_x::wasm")||
           !yx_v12_read_name(&r,name,sizeof(name))||!yx_get_u8(&r,&kind)||kind||
           !yx_get_uleb(&r,&type))goto done;
        if(!strcmp(name,"rule_match@rule_id:i64@")) {
            if(imports.match_id!=255||type!=2)goto done;imports.match_id=(uint8_t)i;
        } else {
            unsigned reader;
            for(reader=0;reader<YX_INTEGER_READ_COUNT;++reader)
                if(yx_v12_mangle(yx_integer_codec_read_import_name((uint8_t)reader),expected,sizeof(expected))&&
                   !strcmp(name,expected))break;
            if(reader==YX_INTEGER_READ_COUNT||type!=3||(imports.read_mask&(1u<<reader)))goto done;
            imports.read_mask|=(uint16_t)(1u<<reader);imports.read_ids[reader]=(uint8_t)i;
        }
        ++imports.function_count;
    }
    if(r.at!=r.length||imports.match_id==255)goto done;
    /* One tree per rule, parked in a store (see serialization_tree_store.h). */
    roots=malloc(rule_count*sizeof(*roots));
    if(!yx_tree_store_init(&store,rule_count)||!roots)goto done;
    for(size_t i=0;i<rule_count;++i)roots[i]=-1;
    context.rule_count=rule_count;
    r=(yx_reader){parts[10],sizes[10],0,false,false};uint64_t functions;
    if(!yx_get_uleb(&r,&functions)||functions<3||functions>rule_count+2)goto done;
    for(uint64_t function=0;function<functions;++function) {
        if(!yx_get_uleb(&r,&n)||n>r.length-r.at)goto done;
        const uint8_t *body=r.data+r.at;yx_v12_instruction *ins=NULL;
        size_t count=0,locals=0,first=0;bool valid=true;
        if(!yx_v12_instructions(body,(size_t)n,&ins,&count,&locals))goto done;
        for(size_t i=4;valid&&i<count;++i) {
            if(ins[i].op!=0x10||ins[i].argument!=imports.match_id)continue;
            int64_t id;yx_reader immediate={body,ins[i-1].end,ins[i-1].start+1,false,false};
            if(ins[i-1].op!=0x41||ins[i-2].op!=5||ins[i-3].op!=4||
               ins[i-3].argument!=0x40||ins[i-3].mate!=i+1||ins[i-4].op!=0x45||
               !yx_get_sleb_i64(&immediate,&id)||immediate.at!=immediate.length||
               id<0||(uint64_t)id>=rule_count||roots[id]>=0) {valid=false;break;}
            context.current=(size_t)id;
            yx_integer_expr *tree=yx_tree_store_fresh(&store);
            roots[id]=yx_v12_numeric_rule(body,ins,count,first,i-4,&imports,&context,tree);
            if(!yx_tree_store_park(&store,(size_t)id)){yx_integer_expr_destroy(tree);roots[id]=-1;}
            if(roots[id]<0){valid=false;break;}
            first=i+2;
        }
        free(ins);if(!valid)goto done;r.at+=(size_t)n;
    }
    if(r.at!=r.length)goto done;
    for(size_t i=0;i<rule_count;++i)if(roots[i]<0)goto done;
    for(unsigned profile=0;!ok&&profile<4;++profile) {
        yx_writer expected={0};free(seed);seed=NULL;seed_length=0;
        ok=yx_rule_expressions_wasm_list(&trees,roots,rule_count,0,&seed,&seed_length)&&
            yx_v12_wasm(seed,seed_length,(profile&1?4:0)|(profile&2?256:0),&expected)&&
            expected.used==length&&!memcmp(expected.data,data,length);
        free(expected.data);
    }
    if(ok)ok=yx_put_bytes(restored,seed,seed_length);
done:
    yx_tree_store_destroy(&store);
    free(roots);free(seed);return ok;
}
