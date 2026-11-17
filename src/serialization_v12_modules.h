/* Reverse the shared v12 control-flow reduction for module expressions.
 * This operates on bounded instructions, then requires whole-module lowering
 * equality before handing the private representation to a schema decoder. */
static bool yx_module_loop_catch_rewrite(yx_module_program *p,yx_writer *out,size_t start)
{
    yx_writer input={0},body={0};yx_v12_instruction *ins=NULL;size_t count=0,locals=0;
    bool ok=false;
    if(start>out->used||!yx_put_u8(&input,0)||!yx_put_bytes(&input,out->data+start,out->used-start)||
       !yx_put_u8(&input,0x0b)||!yx_v12_instructions(input.data,input.used,&ins,&count,&locals)||
       count<2||ins[0].op!=2||ins[0].argument!=0x40||ins[0].mate==SIZE_MAX)goto done;
    size_t finish=ins[0].mate;
    size_t call=0;
    while(call<p->call_count&&p->calls[call]<start)++call;
    for(size_t i=0;i<finish;++i) {
        if(ins[i].op==0x41&&i+1<finish&&ins[i+1].op==0x0c&&
           ins[i].end-ins[i].start==2&&!input.data[ins[i].start+1]) {
            size_t target=ins[i+1].parent;
            for(uint64_t depth=0;depth<ins[i+1].argument&&target!=SIZE_MAX;++depth)target=ins[target].parent;
            if(!target)continue;
        }
        size_t original=start+ins[i].start-1;
        while(call<p->call_count&&p->calls[call]<start+ins[i].end-1) {
            if(p->calls[call]<original)goto done;
            p->calls[call]=start+body.used+(p->calls[call]-original);++call;
        }
        if(!yx_put_bytes(&body,input.data+ins[i].start,ins[i].end-ins[i].start))goto done;
    }
    out->used=start;ok=yx_put_bytes(out,body.data,body.used);
done:
    free(ins);free(input.data);free(body.data);return ok;
}
static int yx_module_loop_catch_decode(yx_reader *r,size_t end,yx_module_program *p,unsigned depth)
{
    /* The catch block that the loop prefix opened (its last two bytes), on
     * its own, also inside a decoded slice; stand-in blocks around it keep
     * the branches to the handlers outside it valid. */
    enum { WRAP=16 };
    size_t start=r->at>=2?r->at-2:0,block_end=SIZE_MAX,level=0,root=WRAP;
    yx_v12_instruction *ins=NULL;size_t count=0,locals=0;
    yx_writer expression={0},buffer={0};int result=-1;
    yx_reader walk={r->data,end,start,false,false};uint8_t op;
    while(walk.at<end&&yx_module_wasm_next(&walk,&op)) {
        if(op==2||op==3||op==4)++level;
        else if(op==0x0b){if(!level)break;if(!--level){block_end=walk.at;break;}}
    }
    if(block_end==SIZE_MAX||!yx_put_u8(&buffer,0))goto done;
    for(unsigned i=0;i<WRAP;++i)if(!yx_put_bytes(&buffer,"\x02\x40",2))goto done;
    if(!yx_put_bytes(&buffer,r->data+start,block_end-start))goto done;
    for(unsigned i=0;i<=WRAP;++i)if(!yx_put_u8(&buffer,0x0b))goto done;
    if(!yx_v12_instructions(buffer.data,buffer.used,&ins,&count,&locals)||count<=root)goto done;
    if(ins[root].op!=2||ins[root].argument!=0x40||ins[root].mate==SIZE_MAX)goto done;
    size_t finish=ins[root].mate;
    if(finish<=root+1||ins[finish-1].op!=0x0b||ins[finish-1].mate==SIZE_MAX)goto done;
    size_t tail=ins[finish-1].mate;
    if(tail<=root||ins[tail].op!=4||ins[tail].argument!=0x40||ins[tail].parent!=root)goto done;
    for(size_t i=root+1;i<tail;++i) {
        if(ins[i].op==0x0c) {
            size_t target=ins[i].parent;
            for(uint64_t d=0;d<ins[i].argument&&target!=SIZE_MAX;++d)target=ins[target].parent;
            if(target==root&&!yx_put_bytes(&expression,"\x41\0",2))goto done;
        }
        if(!yx_put_bytes(&expression,buffer.data+ins[i].start,ins[i].end-ins[i].start))goto done;
    }
    if(!yx_put_u8(&expression,0x0b))goto done;
    yx_reader body={expression.data,expression.used,0,false,false};
    result=yx_module_decode_block(&body,body.length,p,depth+1);
    if(result<0||body.at!=body.length){result=-1;goto done;}
    r->at=start+ins[tail].start-(1+2*WRAP);
done:
    free(ins);free(expression.data);free(buffer.data);return result;
}
/* Whether a branch of the balanced instruction sequence `body` targets a
 * label that encloses it (catch_undef's handler.used). */
static bool yx_module_body_escapes(const uint8_t *body,size_t length,bool *escapes)
{
    /* Enclosing labels are stand-in blocks, so that branches beyond the
     * sequence still validate; a guard leaves at most a few labels. */
    enum { WRAP=8 };
    yx_writer buffer={0};yx_v12_instruction *ins=NULL;size_t count=0,locals=0;bool ok=false;
    *escapes=false;
    if(!yx_put_u8(&buffer,0))goto done;
    for(unsigned i=0;i<WRAP;++i)if(!yx_put_bytes(&buffer,"\x02\x40",2))goto done;
    if(!yx_put_bytes(&buffer,body,length))goto done;
    for(unsigned i=0;i<=WRAP;++i)if(!yx_put_u8(&buffer,0x0b))goto done;
    if(!yx_v12_instructions(buffer.data,buffer.used,&ins,&count,&locals))goto done;
    for(size_t i=WRAP;i+WRAP+1<count;++i) {
        uint64_t depth=0;
        for(size_t parent=ins[i].parent;parent!=SIZE_MAX;parent=ins[parent].parent)++depth;
        if(depth<WRAP)goto done;
        depth-=WRAP;
        if(ins[i].op==0x0c||ins[i].op==0x0d) {
            if(ins[i].argument>=depth)*escapes=true;
        } else if(ins[i].op==0x0e) {
            yx_reader r={buffer.data,ins[i].end,ins[i].start+1,false,false};uint64_t n,target;
            if(!yx_get_uleb(&r,&n))goto done;
            for(uint64_t j=0;j<=n;++j) {
                if(!yx_get_uleb(&r,&target))goto done;
                if(target>=depth)*escapes=true;
            }
        }
    }
    ok=true;
done:
    free(ins);free(buffer.data);return ok;
}
/* walrus numbers emit_switch's i32 temporary before i64_tmp_a/_b. The
 * writer numbers the i64 ones from 0; add `delta` to every local index but
 * the switch's (`i32.wrap_i64; local.set`, `local.get; br_table`) in the
 * balanced sequence `body`, in place (indices stay one byte). */
static bool yx_module_shift_wide_locals(uint8_t *body,size_t length,int delta)
{
    yx_writer buffer={0};yx_v12_instruction *ins=NULL;size_t count=0,locals=0;bool ok=false;
    if(!yx_put_u8(&buffer,0)||!yx_put_bytes(&buffer,body,length)||!yx_put_u8(&buffer,0x0b)||
       !yx_v12_instructions(buffer.data,buffer.used,&ins,&count,&locals))goto done;
    for(size_t i=0;i+1<count;++i) {
        uint8_t op=ins[i].op;
        if(op<0x20||op>0x22)continue;
        if((op==0x21&&i&&ins[i-1].op==0xa7)||(op==0x20&&ins[i+1].op==0x0e))continue;
        if(ins[i].end-ins[i].start!=2)goto done;
        int index=(int)ins[i].argument+delta;
        if(index<0||index>127)goto done;
        body[ins[i].start]=(uint8_t)index;
    }
    ok=true;
done:
    free(ins);free(buffer.data);return ok;
}
/* `or_marker`: the module writer's plain OR keeps its last test as an OR
 * guard plus `i32.const 0`, and a pattern-set `any` (no such tail) keeps its
 * last range without a result block. */
static bool yx_v12_module_expression(const uint8_t *body,yx_v12_instruction *ins,size_t count,
                                      size_t first,size_t finish,const size_t globals[3],size_t search,
                                      size_t imports,const size_t mapping[4],size_t defined,yx_writer *out,
                                      bool or_marker)
{
    yx_writer expression={0};bool ok=false;
    bool *or_open=calloc(count?count:1,sizeof(*or_open)),*or_close=calloc(count?count:1,sizeof(*or_close));
    if(!or_open||!or_close||first>=finish||finish>count)goto done;
    /* The codec adds an untargeted result block around every condition.
     * A reduced AND/OR result block has its own void catch and must survive. */
    bool range=false;
    for(size_t i=first+1;i<finish;++i)
        if(ins[i].op==3&&ins[i].parent==first){range=true;break;}
    if(!range&&ins[first].op==2&&ins[first].argument==0x7f&&ins[first].mate+1==finish&&
       !(first+1<finish&&ins[first+1].op==2&&ins[first+1].argument==0x40&&
         ins[first+1].mate!=SIZE_MAX&&ins[first+1].mate+2==ins[first].mate&&
         ins[ins[first+1].mate+1].op==0x41)) {
        ++first;--finish;
    }
    for(size_t i=0;i<finish;++i) {
        if(ins[i].op!=2||ins[i].argument!=0x7f||i+1>=count||yx_v12_switch_result_block(ins,count,i))continue;
        size_t inner=i+1,end=ins[inner].mate;
        if(ins[inner].op!=2||ins[inner].argument!=0x40||end==SIZE_MAX||
           end+2!=ins[i].mate||end<inner+2||ins[end+1].op!=0x41||
           ins[end+1].end-ins[end+1].start!=2||body[ins[end+1].start+1]>1||
           ins[end-1].op!=0x0c||ins[end-1].argument!=1)continue;
        ins[inner].boolean_block=true;ins[inner].short_value=body[ins[end+1].start+1];
        ins[inner].remove=ins[end-1].remove=ins[end].remove=ins[end+1].remove=true;
        if(ins[inner].short_value&&end>=inner+4&&ins[end-3].op==0x0d&&
           !ins[end-3].argument&&ins[end-2].op==0x41&&
           ins[end-2].end-ins[end-2].start==2&&!body[ins[end-2].start+1]) {
            ins[inner].or_last=true;
            if(!or_marker)ins[end-3].remove=ins[end-2].remove=true;
        }
    }
    /* A numeric OR operand catches undefined values in a void block. Undo
     * that local catch separately from the OR's enclosing success block. */
    for(size_t i=first;i<finish;++i) {
        yx_v12_instruction *p=&ins[i];size_t parent=p->parent,end=p->mate;
        if(p->op!=2||p->argument!=0x40||parent==SIZE_MAX||
           !ins[parent].boolean_block||!ins[parent].short_value||
           end==SIZE_MAX||end<=i+1||ins[end-1].op!=0x0d||ins[end-1].argument!=1)continue;
        p->or_operand=true;ins[end-1].remove=true;
        p->or_last=!or_marker&&end+3==ins[parent].mate&&ins[end+1].op==0x41&&
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
        if(ins[i].op==0x23) {
            if(ins[i].argument>=3||globals[ins[i].argument]==SIZE_MAX)goto done;
            /* emit_lazy_call_to_search_for_patterns uses an inverted guard
             * and an empty else arm in v12 (upstream compiler/emit.rs). */
            if(ins[i].argument==2&&i+5<finish&&ins[i+1].op==0x45&&
               ins[i+2].op==4&&ins[i+2].argument==0x40&&
               ins[i+3].op==0x10&&ins[i+3].argument==search&&
               ins[i+4].op==5&&ins[i+2].mate==i+5) {
                ins[i].guard=true;
                for(size_t j=1;j<=5;++j)ins[i+j].remove=true;
            }
        }
        if(i&&(ins[i-1].op==0x53||ins[i-1].op==0x50)&&
           ins[i].op==4&&ins[i].argument==0x40&&ins[i].alternative!=SIZE_MAX&&
           ins[i].mate==ins[i].alternative+1&&ins[i].mate+1<finish&&
           ins[ins[i].mate+1].op==0x20) {
            ins[i].move_value=true;ins[ins[i].mate+1].remove=true;
        }
    }
    /* Defined OR operands lose their untargeted local result block during
     * reduction. Restore those blocks too: the typed decoder deliberately
     * recognizes the same operand boundaries as the private writer. */
    for(size_t block=first;block<finish;++block) {
        if(!ins[block].boolean_block||!ins[block].short_value)continue;
        size_t end=ins[block].mate,start=block+1;
        if(end==SIZE_MAX||end>finish)goto done;
        for(size_t i=start;i<end;++i) {
            if(ins[i].parent!=block)continue;
            if(ins[i].or_operand) {start=ins[i].mate+1;i=ins[i].mate;continue;}
            if(!ins[i].remove&&ins[i].short_circuit&&ins[i].short_value) {
                or_open[start]=true;or_close[i]=true;start=i+1;
            }
        }
        size_t last=end-1;
        if(end>=3&&ins[end-3].op==0x0d&&ins[end-3].remove&&
           ins[end-2].op==0x41&&ins[end-2].remove)last=end-3;
        bool remaining=false;
        for(size_t i=start;i<last;++i)remaining|=!ins[i].remove;
        if(remaining&&!or_marker){or_open[start]=true;or_close[last]=true;}
    }
    /* The primitive-array loop writer catches an undefined body in a
     * result block. Walrus removes that block when the body is defined. Its
     * element store and the tail branch back to the enclosing loop identify
     * the missing boundary independently of expression operands. */
    for(size_t loop=first;loop<finish;++loop) {
        if(ins[loop].op!=3||ins[loop].argument!=0x40||ins[loop].mate==SIZE_MAX)continue;
        size_t store=SIZE_MAX,tail=SIZE_MAX,loop_end=ins[loop].mate;
        if(loop_end>=finish)continue;
        for(size_t i=loop+1;i<loop_end;++i) {
            if(ins[i].parent!=loop||(ins[i].op!=0x36&&ins[i].op!=0x37&&ins[i].op!=0x39))continue;
            /* A map loop (emit_for_in_map) stores the value and then the key
             * of map_lookup_by_index through i64_tmp_a (set_vars). */
            if(i>=4&&ins[i-1].op==0x20&&ins[i-2].op==0x41&&ins[i-3].op==0x21&&ins[i-4].op==0x10&&
               i+4<loop_end&&ins[i+1].op==0x21&&ins[i+2].op==0x41&&ins[i+3].op==0x20&&
               ins[i+4].op==0x37&&ins[i+4].parent==loop){store=i+4;break;}
            if(!i||ins[i-1].op!=0x0b||ins[i-1].mate==SIZE_MAX)break;
            size_t guard=ins[i-1].mate;
            if(ins[guard].op==4&&ins[guard].argument==0x40&&guard&&ins[guard-1].op==0x10)store=i;
            break;
        }
        if(store==SIZE_MAX||store+1>=loop_end)continue;
        /* emit_for's body never keeps a result block: one after the store
         * (`defined`, an AND/OR, an `of` loop) belongs to the body. */
        size_t start=store+1;
        for(size_t i=start;i<loop_end&&tail==SIZE_MAX;++i) {
            if(ins[i].parent!=loop||ins[i].op!=4||ins[i].argument!=0x40||ins[i].mate==SIZE_MAX)continue;
            for(size_t j=i+1;j<ins[i].mate;++j) {
                if(ins[j].op!=0x0c)continue;
                size_t target=ins[j].parent;
                for(uint64_t d=0;d<ins[j].argument&&target!=SIZE_MAX;++d)target=ins[target].parent;
                if(target==ins[loop].parent){tail=i;break;}
            }
        }
        if(tail!=SIZE_MAX){or_open[start]=true;or_close[tail]=true;}
    }
    for(size_t i=first;i<finish;++i) {
        yx_v12_instruction *p=&ins[i];
        if(or_close[i]&&!yx_put_u8(&expression,0x0b))goto done;
        if(or_open[i]&&(!yx_put_u8(&expression,2)||!yx_put_u8(&expression,0x7f)))goto done;
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
            if(!yx_put_u8(&expression,0x23)||!yx_put_uleb(&expression,globals[p->argument]))goto done;
            if(p->guard&&(!yx_put_u8(&expression,4)||!yx_put_u8(&expression,0x40)||
               !yx_put_u8(&expression,5)||!yx_put_u8(&expression,0x10)||
               !yx_put_uleb(&expression,search)||!yx_put_u8(&expression,0x0b)))goto done;
        } else if(p->op==0x10) {
            uint64_t id=p->argument;
            if(id>=imports){if(id-imports>=defined)goto done;id=imports+mapping[id-imports];}
            if(!yx_put_u8(&expression,0x10)||!yx_put_uleb(&expression,id))goto done;
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
    ok=yx_put_bytes(out,expression.data,expression.used);
done:
    free(or_open);free(or_close);free(expression.data);return ok;
}

static bool yx_v12_module_legacy_name(const char *module,const char *wire,char *name,size_t capacity)
{
    for(size_t i=0;i<sizeof(yx_archive_symbol_aliases)/sizeof(yx_archive_symbol_aliases[0]);++i) {
        if(strcmp(module,yx_archive_symbol_aliases[i].module)||strcmp(wire,yx_archive_symbol_aliases[i].wire_name))continue;
        size_t n=strlen(yx_archive_symbol_aliases[i].name);
        if(n>=capacity)return false;
        memcpy(name,yx_archive_symbol_aliases[i].name,n+1);return true;
    }
    return false;
}

static bool yx_v12_module_relocate(const uint8_t *body,size_t length,
                                    size_t imports,const size_t mapping[4],size_t defined,yx_writer *out)
{
    yx_v12_instruction *ins=NULL;size_t count=0,locals=0;bool ok=false;
    if(!yx_v12_instructions(body,length,&ins,&count,&locals)||!yx_put_bytes(out,body,locals))goto done;
    for(size_t i=0;i<count;++i) {
        if(ins[i].op==0x10) {
            uint64_t id=ins[i].argument;
            if(id>=imports){if(id-imports>=defined)goto done;id=imports+mapping[id-imports];}
            if(!yx_put_u8(out,0x10)||!yx_put_uleb(out,id))goto done;
        } else if(!yx_put_bytes(out,body+ins[i].start,ins[i].end-ins[i].start))goto done;
    }
    ok=true;
done:
    free(ins);return ok;
}

/* Recover a single typed expression, including pattern leaves. The private
 * representation imports globals lazily, while v12 exports a fixed runtime
 * layout. Function order is also recovered before checking the entire lowered
 * module, so no recovered instruction stream bypasses canonical validation. */
/* External/module rules can occupy several independent rule chunks. Recover
 * each chunk, then restore the private writer's instruction-count ordering.
 * Whole-module lowering equality remains the acceptance boundary. */
static bool yx_v12_restore_module_chunks(const uint8_t *data,size_t length,
    const uint8_t *const parts[13],const size_t sizes[13],const yx_writer *legacy_imports,
    size_t import_count,size_t match,size_t search,yx_writer *restored)
{
    const uint8_t **bodies=NULL;size_t *body_sizes=NULL,*mapping=NULL,*creation=NULL,*first_rule=NULL;
    uint64_t *type_ids=NULL;yx_writer *decoded=NULL;yx_wasm_function *order=NULL;
    yx_writer imports={0},functions={0},exports={0},code={0},module={0};
    size_t defined=0,main=SIZE_MAX,helper=SIZE_MAX,chunks=0,wrappers=0;uint64_t n;
    bool filesize=false,memory=false,patterns=search!=SIZE_MAX,ok=false;
    yx_reader r={parts[3],sizes[3],0,false,false};
    if(!yx_get_uleb(&r,&n)||n<4||n>r.length-r.at||n>SIZE_MAX/sizeof(*decoded))goto done;
    defined=(size_t)n;
    bodies=calloc(defined,sizeof(*bodies));body_sizes=calloc(defined,sizeof(*body_sizes));
    mapping=calloc(defined,sizeof(*mapping));creation=calloc(defined,sizeof(*creation));
    first_rule=malloc(defined*sizeof(*first_rule));type_ids=calloc(defined,sizeof(*type_ids));
    decoded=calloc(defined,sizeof(*decoded));order=calloc(defined,sizeof(*order));
    if(!bodies||!body_sizes||!mapping||!creation||!first_rule||!type_ids||!decoded||!order)goto done;
    for(size_t i=0;i<defined;++i) {
        mapping[i]=i;first_rule[i]=SIZE_MAX;
        if(!yx_get_uleb(&r,&type_ids[i]))goto done;
    }
    if(r.at!=r.length)goto done;
    r=(yx_reader){parts[7],sizes[7],0,false,false};
    if(!yx_get_uleb(&r,&n)||n>r.length-r.at)goto done;
    for(uint64_t i=0;i<n;++i) {
        char name[80];uint8_t kind;uint64_t id;
        if(!yx_v12_read_name(&r,name,sizeof(name))||!yx_get_u8(&r,&kind)||!yx_get_uleb(&r,&id))goto done;
        if(!strcmp(name,"main")) {
            if(kind||id<import_count||id-import_count>=defined||main!=SIZE_MAX)goto done;
            main=(size_t)(id-import_count);
        }
    }
    if(r.at!=r.length||main==SIZE_MAX)goto done;
    r=(yx_reader){parts[10],sizes[10],0,false,false};
    if(!yx_get_uleb(&r,&n)||n!=defined)goto done;
    for(size_t f=0;f<defined;++f) {
        yx_v12_instruction *ins=NULL;size_t count=0,locals=0;bool valid=true;
        if(!yx_get_uleb(&r,&n)||n>r.length-r.at)goto done;
        bodies[f]=r.data+r.at;body_sizes[f]=(size_t)n;r.at+=(size_t)n;
        if(!yx_v12_instructions(bodies[f],body_sizes[f],&ins,&count,&locals))goto done;
        for(size_t i=0;i<count;++i) {
            if(ins[i].op>=0x28&&ins[i].op<=0x3e)memory=true;
            if(ins[i].op==0x23) {
                if(ins[i].argument==1)filesize=true;
                else if(ins[i].argument==0) {
                    static const uint8_t bitmap[]={1,1,0x7f,0x20,0,0x41,3,0x76,0x23,0,0x6a,
                        0x2d,0,0,0x41,1,0x20,0,0x41,8,0x70,0x22,1,0x74,0x71,0x20,1,0x76,0x0b};
                    if(!patterns||body_sizes[f]!=sizeof(bitmap)||memcmp(bodies[f],bitmap,sizeof(bitmap))||
                       (helper!=SIZE_MAX&&helper!=f))valid=false;
                    else helper=f;
                } else if(ins[i].argument!=2||!patterns)valid=false;
            }
            if(ins[i].op==0x24)valid=false;
            if(ins[i].op==0x10&&ins[i].argument==match&&first_rule[f]==SIZE_MAX) {
                if(!i){valid=false;break;}
                int64_t id;yx_reader immediate={bodies[f],ins[i-1].end,ins[i-1].start+1,false,false};
                if(ins[i-1].op!=0x41||!yx_get_sleb_i64(&immediate,&id)||id<0)valid=false;
                else first_rule[f]=(size_t)id;
            }
        }
        free(ins);if(!valid)goto done;
    }
    if(r.at!=r.length||first_rule[main]!=SIZE_MAX)goto done;
    for(size_t f=0;f<defined;++f)
        if(first_rule[f]!=SIZE_MAX) {
            if(f==helper)goto done;
            creation[chunks++]=f;
        }
    if(!chunks||helper==main)goto done;
    for(size_t i=1;i<chunks;++i) {
        size_t item=creation[i],j=i;
        while(j&&first_rule[creation[j-1]]>first_rule[item]){creation[j]=creation[j-1];--j;}
        creation[j]=item;
    }
    /* main calls namespace wrappers in creation order, including empty
     * wrappers. Recover that order structurally instead of guessing it from
     * equal instruction counts or the sorted function positions. */
    size_t created=chunks;
    if(helper!=SIZE_MAX)creation[created++]=helper;
    {
        yx_v12_instruction *ins=NULL;size_t count=0,locals=0;bool valid=true;
        if(!yx_v12_instructions(bodies[main],body_sizes[main],&ins,&count,&locals))goto done;
        if(locals!=1||bodies[main][0]||count<3||ins[count-2].op!=0x41||
           ins[count-2].end-ins[count-2].start!=2||bodies[main][ins[count-2].start+1]||
           ins[count-1].op!=0x0b)valid=false;
        for(size_t i=0;valid&&i+2<count;++i) {
            uint64_t id=ins[i].argument;
            if(ins[i].op!=0x10||id<import_count||id-import_count>=defined) {valid=false;break;}
            size_t f=(size_t)(id-import_count);
            if(f==main||f==helper||first_rule[f]!=SIZE_MAX||created>=defined-1) {valid=false;break;}
            for(size_t j=chunks;j<created;++j)if(creation[j]==f)valid=false;
            if(valid){creation[created++]=f;++wrappers;}
        }
        free(ins);
        if(!valid||!wrappers||created+1!=defined)goto done;
    }
    creation[created]=main;
    for(size_t f=0;f<defined;++f) {
        if(first_rule[f]==SIZE_MAX)continue;
        yx_v12_instruction *ins=NULL;size_t count=0,locals=0,first=0;bool valid=true;
        if(!yx_v12_instructions(bodies[f],body_sizes[f],&ins,&count,&locals))goto done;
        if(!yx_put_bytes(&decoded[f],bodies[f],locals)){free(ins);goto done;}
        size_t globals[3]={helper!=SIZE_MAX?0:SIZE_MAX,
            filesize?(size_t)(helper!=SIZE_MAX):SIZE_MAX,
            patterns?(size_t)(helper!=SIZE_MAX)+filesize:SIZE_MAX};
        for(size_t i=4;valid&&i<count;++i) {
            if(ins[i].op!=0x10||ins[i].argument!=match)continue;
            size_t branch=ins[i].parent;
            if(ins[i-1].op!=0x41||ins[i-2].op!=5||branch==SIZE_MAX||!branch||
               ins[i-2].parent!=branch||ins[branch].op!=4||ins[branch].argument!=0x40||
               ins[branch].mate!=i+1||ins[branch-1].op!=0x45||
               branch-1<=first||i+1>=count){valid=false;break;}
            size_t condition_end=branch-1;
            valid=yx_put_bytes(&decoded[f],"\2\x7f",2)&&
                yx_v12_module_expression(bodies[f],ins,count,first,condition_end,globals,search,
                    import_count,mapping,defined,&decoded[f],true)&&yx_put_u8(&decoded[f],0x0b)&&
                yx_put_bytes(&decoded[f],bodies[f]+ins[condition_end].start,ins[i+1].end-ins[condition_end].start);
            first=i+2;
        }
        valid=valid&&first&&first<count&&yx_put_bytes(&decoded[f],bodies[f]+ins[first].start,body_sizes[f]-ins[first].start);
        free(ins);if(!valid)goto done;
    }
    for(size_t i=0;i<defined;++i) {
        size_t f=creation[i];yx_writer view=decoded[f];
        if(!view.data)view=(yx_writer){(uint8_t *)bodies[f],body_sizes[f],body_sizes[f]};
        order[i].created=i;
        if(!yx_v12_rule_size(view.data,view.used,
            patterns?(size_t)(helper!=SIZE_MAX)+filesize:SIZE_MAX,&order[i].instructions))goto done;
    }
    qsort(order,defined,sizeof(*order),yx_compare_wasm_functions);
    for(size_t i=0;i<defined;++i)mapping[creation[order[i].created]]=i;
    if(!yx_put_uleb(&imports,import_count+(helper!=SIZE_MAX)+filesize+patterns+memory)||
       !yx_put_bytes(&imports,legacy_imports->data,legacy_imports->used))goto done;
    if(helper!=SIZE_MAX&&(!yx_v12_name(&imports,"yara_x")||!yx_v12_name(&imports,"matching_patterns_bitmap_base")||
       !yx_put_bytes(&imports,"\3\x7f\0",3)))goto done;
    if(filesize&&(!yx_v12_name(&imports,"yara_x")||!yx_v12_name(&imports,"filesize")||!yx_put_bytes(&imports,"\3\x7e\1",3)))goto done;
    if(patterns&&(!yx_v12_name(&imports,"yara_x")||!yx_v12_name(&imports,"pattern_search_done")||
       !yx_put_bytes(&imports,"\3\x7f\1",3)))goto done;
    if(memory&&(!yx_v12_name(&imports,"yara_x")||!yx_v12_name(&imports,"main_memory")||!yx_put_bytes(&imports,"\2\0\1",3)))goto done;
    if(!yx_put_uleb(&functions,defined)||!yx_put_uleb(&exports,1)||!yx_v12_name(&exports,"main")||
       !yx_put_u8(&exports,0)||!yx_put_uleb(&exports,import_count+mapping[main])||!yx_put_uleb(&code,defined))goto done;
    for(size_t i=0;i<defined;++i) {
        size_t f=creation[order[i].created];yx_writer body={0};
        const uint8_t *source=decoded[f].data?decoded[f].data:bodies[f];
        size_t width=decoded[f].data?decoded[f].used:body_sizes[f];
        bool valid=yx_v12_module_relocate(source,width,import_count,mapping,defined,&body)&&
            yx_put_uleb(&functions,type_ids[f])&&yx_put_uleb(&code,body.used)&&yx_put_bytes(&code,body.data,body.used);
        free(body.data);if(!valid)goto done;
    }
    yx_writer types={(uint8_t *)parts[1],sizes[1],sizes[1]};
    if(!yx_put_bytes(&module,data,8)||!yx_v12_section(&module,1,&types)||!yx_v12_section(&module,2,&imports)||
       !yx_v12_section(&module,3,&functions)||!yx_v12_section(&module,7,&exports)||!yx_v12_section(&module,10,&code))goto done;
    for(unsigned profile=0;!ok&&profile<4;++profile) {
        yx_writer expected={0};
        ok=yx_v12_wasm(module.data,module.used,(profile&1?4:0)|(profile&2?256:0),&expected)&&
            expected.used==length&&!memcmp(expected.data,data,length);free(expected.data);
    }
    if(ok)ok=yx_put_bytes(restored,module.data,module.used);
done:
    if(decoded)for(size_t i=0;i<defined;++i)free(decoded[i].data);
    free(bodies);free(body_sizes);free(mapping);free(creation);free(first_rule);free(type_ids);free(decoded);free(order);
    free(imports.data);free(functions.data);free(exports.data);free(code.data);free(module.data);return ok;
}
static bool yx_v12_restore_module_expression(const uint8_t *data,size_t length,yx_writer *restored)
{
    const uint8_t *parts[13],*bodies[4]={0};size_t sizes[13],body_sizes[4]={0},mapping[4]={0};
    yx_writer imports={0},functions={0},exports={0},code={0},module={0},rule_body={0};
    yx_v12_instruction *ins=NULL;size_t count=0,locals=0,rule=SIZE_MAX,main=SIZE_MAX,wrapper=SIZE_MAX,helper=SIZE_MAX;
    uint64_t type_ids[4],n,import_count=0,match=UINT64_MAX,search=UINT64_MAX;
    size_t defined=0;bool filesize=false,memory=false,patterns=false,ok=false;
    if(!yx_v12_sections(data,length,parts,sizes)||!parts[1]||!parts[2]||!parts[3]||!parts[7]||!parts[10])return false;
    yx_reader r={parts[2],sizes[2],0,false,false};
    if(!yx_get_uleb(&r,&import_count)||!import_count||import_count>YX_MODULE_IMPORTS)goto done;
    for(size_t i=0;i<(size_t)import_count;++i) {
        char owner[80],wire[256],name[256];uint8_t kind;uint64_t type;
        if(!yx_v12_read_name(&r,owner,sizeof(owner))||!yx_v12_read_name(&r,wire,sizeof(wire))||
           !yx_get_u8(&r,&kind)||kind||!yx_get_uleb(&r,&type)||
           !yx_v12_module_legacy_name(owner,wire,name,sizeof(name)))goto done;
        if(!strcmp(name,"rule_match@rule_id:i@"))match=i;
        if(!strcmp(name,"search_for_patterns@@"))search=i;
        if(!yx_v12_name(&imports,owner)||!yx_v12_name(&imports,name)||!yx_put_u8(&imports,0)||!yx_put_uleb(&imports,type))goto done;
    }
    if(r.at!=r.length||match==UINT64_MAX)goto done;
    r=(yx_reader){parts[3],sizes[3],0,false,false};
    if(!yx_get_uleb(&r,&n))goto done;
    if(n>4||(n>=4&&search==UINT64_MAX)) {
        ok=yx_v12_restore_module_chunks(data,length,parts,sizes,&imports,(size_t)import_count,(size_t)match,(size_t)search,restored);
        goto done;
    }
    if(n!=3&&n!=4)goto done;
    defined=(size_t)n;patterns=search!=UINT64_MAX;
    if(defined==4&&!patterns)goto done;
    for(size_t i=0;i<defined;++i)if(!yx_get_uleb(&r,&type_ids[i]))goto done;
    if(r.at!=r.length)goto done;
    r=(yx_reader){parts[7],sizes[7],0,false,false};
    if(!yx_get_uleb(&r,&n)||n>sizes[7])goto done;
    for(uint64_t i=0;i<n;++i) {
        char name[80];uint8_t kind;uint64_t id;
        if(!yx_v12_read_name(&r,name,sizeof(name))||!yx_get_u8(&r,&kind)||!yx_get_uleb(&r,&id))goto done;
        if(!strcmp(name,"main")) {
            if(kind||id<import_count||id-import_count>=defined||main!=SIZE_MAX)goto done;
            main=(size_t)(id-import_count);
        }
    }
    if(r.at!=r.length||main==SIZE_MAX)goto done;
    r=(yx_reader){parts[10],sizes[10],0,false,false};
    if(!yx_get_uleb(&r,&n)||n!=defined)goto done;
    for(size_t function=0;function<defined;++function) {
        if(!yx_get_uleb(&r,&n)||n>r.length-r.at)goto done;
        bodies[function]=r.data+r.at;body_sizes[function]=(size_t)n;r.at+=(size_t)n;
        yx_v12_instruction *walk=NULL;size_t used=0,local_bytes=0;
        if(!yx_v12_instructions(bodies[function],body_sizes[function],&walk,&used,&local_bytes))goto done;
        bool is_rule=false,is_helper=false,valid=true;
        for(size_t i=0;i<used;++i) {
            if(walk[i].op==0x10&&walk[i].argument==match)is_rule=true;
            if(walk[i].op>=0x28&&walk[i].op<=0x3e)memory=true;
            if(walk[i].op==0x23) {
                if(walk[i].argument==1)filesize=true;
                else if(!walk[i].argument&&defined==4)is_helper=true;
                else if(walk[i].argument!=2||!patterns)valid=false;
            }
            if(walk[i].op==0x24)valid=false;
        }
        if(is_rule) {
            if(rule!=SIZE_MAX||function==main||is_helper)valid=false;
            else {rule=function;ins=walk;count=used;locals=local_bytes;walk=NULL;}
        } else if(is_helper) {
            if(helper!=SIZE_MAX||function==main)valid=false;else helper=function;
        }
        free(walk);if(!valid)goto done;
    }
    if(r.at!=r.length||rule==SIZE_MAX||(defined==4&&helper==SIZE_MAX))goto done;
    for(size_t i=0;i<defined;++i)if(i!=main&&i!=rule&&i!=helper) {
        if(wrapper!=SIZE_MAX)goto done;wrapper=i;
    }
    if(wrapper==SIZE_MAX)goto done;
    size_t finish=SIZE_MAX;
    for(size_t i=4;i<count;++i) {
        size_t branch=ins[i].parent;
        if(ins[i].op==0x10&&ins[i].argument==match&&ins[i-1].op==0x41&&
           ins[i-2].op==5&&branch!=SIZE_MAX&&branch>0&&branch<count&&
           ins[i-2].parent==branch&&ins[branch].op==4&&ins[branch].argument==0x40&&
           ins[branch].mate==i+1&&ins[branch-1].op==0x45){finish=branch-1;break;}
    }
    if(finish==SIZE_MAX)goto done;
    for(unsigned helper_first=0;!ok&&helper_first<(defined==4?2u:1u);++helper_first) {
        free(functions.data);functions=(yx_writer){0};free(exports.data);exports=(yx_writer){0};
        free(code.data);code=(yx_writer){0};free(module.data);module=(yx_writer){0};
        free(rule_body.data);rule_body=(yx_writer){0};
        mapping[rule]=helper_first;mapping[wrapper]=defined-2;mapping[main]=defined-1;
        if(helper!=SIZE_MAX)mapping[helper]=helper_first?0:1;
        size_t globals[3]={helper!=SIZE_MAX?0:SIZE_MAX,filesize?(helper!=SIZE_MAX?1u:0u):SIZE_MAX,
                           patterns?(size_t)(helper!=SIZE_MAX)+filesize:SIZE_MAX};
        if(!yx_put_bytes(&rule_body,bodies[rule],locals))goto done;
        size_t first=0;
        for(size_t i=4;i<count;++i) {
            if(ins[i].op!=0x10||ins[i].argument!=match)continue;
            /* A global rule's failure arm calls rule_no_match and returns.
             * Its success call still belongs to the enclosing if/else; find
             * that parent rather than assuming the failure arm is empty. */
            size_t branch=ins[i].parent;
            if(ins[i-1].op!=0x41||ins[i-2].op!=5||branch==SIZE_MAX||!branch||
               branch>=count||ins[i-2].parent!=branch||ins[branch].op!=4||
               ins[branch].argument!=0x40||ins[branch].mate!=i+1||
               ins[branch-1].op!=0x45||branch-1<=first||i+1>=count)goto done;
            size_t condition_end=branch-1;
            if(!yx_put_u8(&rule_body,2)||!yx_put_u8(&rule_body,0x7f)||
               !yx_v12_module_expression(bodies[rule],ins,count,first,condition_end,globals,(size_t)search,
                                         (size_t)import_count,mapping,defined,&rule_body,true)||
               !yx_put_u8(&rule_body,0x0b)||!yx_put_bytes(&rule_body,bodies[rule]+ins[condition_end].start,
                   ins[i+1].end-ins[condition_end].start))goto done;
            first=i+2;
        }
        if(!first||first>=count||!yx_put_bytes(&rule_body,bodies[rule]+ins[first].start,
            body_sizes[rule]-ins[first].start))goto done;
        yx_writer import_section={0};
        bool built=yx_put_uleb(&import_section,import_count+(helper!=SIZE_MAX)+filesize+patterns+memory)&&
            yx_put_bytes(&import_section,imports.data,imports.used);
        if(built&&helper!=SIZE_MAX)built=yx_v12_name(&import_section,"yara_x")&&yx_v12_name(&import_section,"matching_patterns_bitmap_base")&&
            yx_put_u8(&import_section,3)&&yx_put_u8(&import_section,0x7f)&&yx_put_u8(&import_section,0);
        if(built&&filesize)built=yx_v12_name(&import_section,"yara_x")&&yx_v12_name(&import_section,"filesize")&&
            yx_put_u8(&import_section,3)&&yx_put_u8(&import_section,0x7e)&&yx_put_u8(&import_section,1);
        if(built&&patterns)built=yx_v12_name(&import_section,"yara_x")&&yx_v12_name(&import_section,"pattern_search_done")&&
            yx_put_u8(&import_section,3)&&yx_put_u8(&import_section,0x7f)&&yx_put_u8(&import_section,1);
        if(built&&memory)built=yx_v12_name(&import_section,"yara_x")&&yx_v12_name(&import_section,"main_memory")&&
            yx_put_u8(&import_section,2)&&yx_put_u8(&import_section,0)&&yx_put_u8(&import_section,1);
        size_t order[4]={rule,wrapper,main,0};
        if(defined==4){order[0]=helper_first?helper:rule;order[1]=helper_first?rule:helper;order[2]=wrapper;order[3]=main;}
        built=built&&yx_put_uleb(&functions,defined)&&yx_put_uleb(&exports,1)&&yx_v12_name(&exports,"main")&&
            yx_put_u8(&exports,0)&&yx_put_uleb(&exports,import_count+defined-1)&&yx_put_uleb(&code,defined);
        for(size_t i=0;built&&i<defined;++i) {
            size_t function=order[i];yx_writer body={0};
            built=yx_put_uleb(&functions,type_ids[function]);
            if(function==rule)built=built&&yx_put_bytes(&body,rule_body.data,rule_body.used);
            else built=built&&yx_v12_module_relocate(bodies[function],body_sizes[function],(size_t)import_count,mapping,defined,&body);
            built=built&&yx_put_uleb(&code,body.used)&&yx_put_bytes(&code,body.data,body.used);free(body.data);
        }
        yx_writer types={(uint8_t *)parts[1],sizes[1],sizes[1]};
        built=built&&yx_put_bytes(&module,data,8)&&yx_v12_section(&module,1,&types)&&
            yx_v12_section(&module,2,&import_section)&&yx_v12_section(&module,3,&functions)&&
            yx_v12_section(&module,7,&exports)&&yx_v12_section(&module,10,&code);
        free(import_section.data);if(!built)goto done;
        for(unsigned profile=0;!ok&&profile<4;++profile) {
            yx_writer expected={0};
            ok=yx_v12_wasm(module.data,module.used,(profile&1?4:0)|(profile&2?256:0),&expected)&&
                expected.used==length&&!memcmp(expected.data,data,length);free(expected.data);
        }
    }
    if(ok)ok=yx_put_bytes(restored,module.data,module.used);
done:
    free(ins);free(imports.data);free(functions.data);free(exports.data);free(code.data);free(module.data);free(rule_body.data);
    return ok;
}
