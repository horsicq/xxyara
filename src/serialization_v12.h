/* Archive-only lowering from the codec's template IR to YARA-X 1.23 WASM.
 * Keeping this at the archive boundary also covers the specialized emitters.
 * No scanner or condition-evaluator instructions are changed here. */

typedef struct yx_v12_instruction {
    size_t start, end, parent, mate, alternative, catch_target, constant;
    uint64_t argument;
    uint8_t op;
    bool targeted, remove, guard, move_value, switch_result;
    bool boolean_block, short_circuit;
    bool catch_undef, or_operand, or_last;
    uint8_t short_value;
} yx_v12_instruction;

/* Each lowered constant retains its source ordinal. A zero origin marks a
 * control-flow constant introduced by lowering and must match exactly. */
typedef struct yx_v12_origins {
    size_t *items, count, capacity;
} yx_v12_origins;

static bool yx_v12_origin(yx_v12_origins *origins, size_t source)
{
    if (!origins) return true;
    if (origins->count == origins->capacity) {
        size_t capacity = origins->capacity ? origins->capacity * 2 : 16;
        if (capacity < origins->capacity || capacity > SIZE_MAX / sizeof(*origins->items)) return false;
        size_t *items = realloc(origins->items, capacity * sizeof(*items));
        if (!items) return false;
        origins->items = items; origins->capacity = capacity;
    }
    origins->items[origins->count++] = source;
    return true;
}

static bool yx_v12_section(yx_writer *w, uint8_t id, const yx_writer *s)
{
    return yx_put_u8(w,id) && yx_put_uleb(w,s->used) &&
           yx_put_bytes(w,s->data,s->used);
}

static bool yx_v12_name(yx_writer *w, const char *s)
{
    size_t n=strlen(s);
    return yx_put_uleb(w,n) && yx_put_bytes(w,s,n);
}

/* Integer widths in names describe the YARA type. The WASM ABI still passes
 * pattern/rule IDs as i32, and undefined values still have a second result. */
static bool yx_v12_mangle(const char *name, char *out, size_t capacity)
{
    const char *special=NULL;
    if(!strncmp(name,"lookup_",7)) {
        if(!strcmp(name,"lookup_bool@structure:iu,num_lookup_indexes:i@bu"))
            special="lookup_bool@structure:i64u,num_lookup_indexes:i32@bu";
        else if(!strcmp(name,"lookup_integer@structure:iu,num_lookup_indexes:i@iu"))
            special="lookup_integer@structure:i64u,num_lookup_indexes:i32@i64u";
        else if(!strcmp(name,"lookup_float@structure:iu,num_lookup_indexes:i@fu"))
            special="lookup_float@structure:i64u,num_lookup_indexes:i32@fu";
        else if(!strcmp(name,"lookup_string@structure:iu,num_lookup_indexes:i@su"))
            special="lookup_string@structure:i64u,num_lookup_indexes:i32@su";
    }
    if(special) {
        if(strlen(special)>=capacity)return false;
        strcpy(out,special);return true;
    }
    /* Reader return values no longer use signed range constraints. */
    if(!strncmp(name,"uint",4)||!strncmp(name,"int",3)) {
        const char *at=strchr(name,'@');
        if(at&&strstr(at,"offset:i@")) {
            size_t n=(size_t)(at-name);
            char stem[32];
            if(n>=sizeof(stem))return false;
            memcpy(stem,name,n);stem[n]=0;
            const char *bits=stem+(stem[0]=='u'?4:3);
            unsigned width=(unsigned)strtoul(bits,NULL,10);
            if(width==8||width==16||width==32||width==64) {
                int written=snprintf(out,capacity,"%s@offset:i64@%c%uu",stem,
                                     stem[0]=='u'?'u':'i',width);
                return written>=0&&(size_t)written<capacity;
            }
        }
    }
    size_t used=0;
    for(size_t i=0;name[i];++i) {
        if(used+1>=capacity)return false;
        out[used++]=name[i];
        if(name[i]=='i'&&i&& (name[i-1]==':'||name[i-1]=='@')&&
           (!name[i+1]||name[i+1]=='u'||name[i+1]==','||name[i+1]=='@'||name[i+1]==':')) {
            if(used+2>=capacity)return false;
            out[used++]='6';out[used++]='4';
        }
    }
    out[used]=0;return true;
}

/* The same bounded instruction walker used for import relocation, extended
 * with structured-control bookkeeping. Every branch target is retained. */
static bool yx_v12_instructions(const uint8_t *data, size_t length,
                                yx_v12_instruction **instructions,
                                size_t *count, size_t *locals)
{
    yx_reader r={data,length,0,false,false};
    uint64_t groups,v;
    size_t used=0,depth=0,constants=0;
    yx_v12_instruction *ins=NULL;
    size_t *stack=NULL;
    bool ok=false;
    if(!yx_get_uleb(&r,&groups)||groups>length)return false;
    for(uint64_t i=0;i<groups;++i) {
        uint8_t type;
        if(!yx_get_uleb(&r,&v)||!yx_get_u8(&r,&type))return false;
    }
    *locals=r.at;
    if(length>SIZE_MAX/sizeof(*ins)||length>SIZE_MAX/sizeof(*stack))return false;
    ins=calloc(length?length:1,sizeof(*ins));stack=malloc((length?length:1)*sizeof(*stack));
    if(!ins||!stack)goto done;
    while(r.at<length) {
        size_t index=used++;
        yx_v12_instruction *p=&ins[index];
        p->start=r.at;p->parent=depth?stack[depth-1]:SIZE_MAX;
        p->mate=p->alternative=p->catch_target=SIZE_MAX;
        if(!yx_get_u8(&r,&p->op))goto done;
        uint8_t op=p->op;
        if(op==2||op==3||op==4) {
            if(!yx_get_uleb(&r,&p->argument))goto done;
            stack[depth++]=index;
        } else if(op==5) {
            if(!depth||ins[stack[depth-1]].op!=4)goto done;
            ins[stack[depth-1]].alternative=index;
        } else if(op==0x0b) {
            if(depth) {p->mate=stack[--depth];ins[p->mate].mate=index;}
            else if(r.at!=length)goto done;
        } else if(op==0x0c||op==0x0d) {
            if(!yx_get_uleb(&r,&p->argument)||p->argument>depth)goto done;
            if(p->argument<depth)ins[stack[depth-1-(size_t)p->argument]].targeted=true;
        } else if(op==0x0e) {
            uint64_t n;
            if(!yx_get_uleb(&r,&n)||n>length-r.at)goto done;
            for(uint64_t j=0;j<=n;++j) {
                if(!yx_get_uleb(&r,&v)||v>depth)goto done;
                if(v<depth)ins[stack[depth-1-(size_t)v]].targeted=true;
            }
        } else if(op==0x10||op==0x12||op==0xd2||(op>=0x20&&op<=0x26)) {
            if(!yx_get_uleb(&r,&p->argument))goto done;
        } else if(op==0x11||op==0x13) {
            if(!yx_get_uleb(&r,&v)||!yx_get_uleb(&r,&v))goto done;
        } else if(op==0x1c) {
            if(!yx_get_uleb(&r,&v)||v>length-r.at)goto done;
            r.at+=(size_t)v;
        } else if(op>=0x28&&op<=0x3e) {
            if(!yx_wasm_skip_memarg(&r))goto done;
        } else if(op==0x3f||op==0x40||op==0xd0) {
            if(!yx_get_uleb(&r,&v))goto done;
        } else if(op==0x41||op==0x42) {
            do {uint8_t b;if(!yx_get_u8(&r,&b))goto done;if(!(b&128))break;}while(true);
        } else if(op==0x43||op==0x44) {
            size_t n=op==0x43?4:8;
            if(n>length-r.at)goto done;r.at+=n;
        } else if(op==0xfc) {
            if(!yx_get_uleb(&r,&v))goto done;
            if(v>=8) {
                if(v==8||v==10||v==12||v==14) {
                    if(!yx_get_uleb(&r,&v)||!yx_get_uleb(&r,&v))goto done;
                } else if(v==9||v==11||v==13||(v>=15&&v<=17)) {
                    if(!yx_get_uleb(&r,&v))goto done;
                } else goto done;
            }
        } else if(!(op<=1||op==0x0f||op==0x1a||op==0x1b||op==0xd1||
                    (op>=0x45&&op<=0xc4)))goto done;
        if(op>=0x41&&op<=0x44)p->constant=++constants;
        p->end=r.at;
    }
    if(depth)goto done;
    *instructions=ins;*count=used;ins=NULL;ok=true;
done:
    free(ins);free(stack);return ok;
}

/* emit_and/emit_or use a void short-circuit block in v12. Recognize only
 * the old exact constant/branch stubs; nested expression branches retain
 * their target when the additional label is inserted. */
static void yx_v12_boolean_blocks(const uint8_t *data,yx_v12_instruction *ins,size_t count)
{
    for(size_t block=0;block<count;++block) {
        if(ins[block].op!=2||ins[block].argument!=0x7f||!ins[block].targeted)continue;
        int kind=-1;bool mixed=false;size_t stubs=0;
        for(size_t i=block+1;i<ins[block].mate;++i) {
            if(ins[i].parent!=block||ins[i].op!=4||ins[i].argument!=0x40||ins[i].mate!=i+4)continue;
            int value=-1;
            if(ins[i+1].op==0x41&&ins[i+1].end-ins[i+1].start==2&&data[ins[i+1].start+1]==1&&
               ins[i+2].op==0x0c&&ins[i+2].argument==1&&ins[i+3].op==5)value=1;
            if(ins[i+1].op==5&&ins[i+2].op==0x41&&ins[i+2].end-ins[i+2].start==2&&
               data[ins[i+2].start+1]==0&&ins[i+3].op==0x0c&&ins[i+3].argument==1)value=0;
            if(value<0)continue;
            if(kind>=0&&kind!=value){mixed=true;break;}
            kind=value;++stubs;
        }
        if(!stubs||mixed)continue;
        ins[block].boolean_block=true;ins[block].short_value=(uint8_t)kind;
        for(size_t i=block+1;i<ins[block].mate;++i) {
            if(ins[i].parent!=block||ins[i].op!=4||ins[i].argument!=0x40||ins[i].mate!=i+4)continue;
            bool match=kind?ins[i+1].op==0x41&&ins[i+1].end-ins[i+1].start==2&&data[ins[i+1].start+1]==1&&
                            ins[i+2].op==0x0c&&ins[i+2].argument==1&&ins[i+3].op==5:
                            ins[i+1].op==5&&ins[i+2].op==0x41&&ins[i+2].end-ins[i+2].start==2&&
                            data[ins[i+2].start+1]==0&&ins[i+3].op==0x0c&&ins[i+3].argument==1;
            if(!match)continue;
            ins[i].short_circuit=true;ins[i].short_value=(uint8_t)kind;
            for(size_t j=i+1;j<=i+4;++j)ins[j].remove=true;
        }
    }
    /* Undefined operands of AND exit the void catch block, whose fallback
     * already pushes false; no result operand belongs on that branch. */
    for(size_t i=1;i<count;++i) {
        if(ins[i].op!=0x0c||ins[i].remove||ins[i-1].remove||
           ins[i-1].op!=0x41||ins[i-1].end-ins[i-1].start!=2||
           data[ins[i-1].start+1]!=0||ins[i-1].parent!=ins[i].parent)continue;
        size_t target=ins[i].parent;
        for(uint64_t d=0;d<ins[i].argument&&target!=SIZE_MAX;++d)target=ins[target].parent;
        if(target!=SIZE_MAX&&ins[target].boolean_block&&!ins[target].short_value) {
            ins[i].catch_undef=true;ins[i].catch_target=target;ins[i-1].remove=true;
        }
    }
}

/* emit_switch keeps its enclosing result block (i64, f64 or i32) even for
 * one branch, when that block is not itself a branch target. The inner
 * constant's result block is still reduced by the ordinary untargeted-block
 * pass. */
static void yx_v12_switch_blocks(yx_v12_instruction *ins,size_t count)
{
    for(size_t i=0;i<count;++i)if(ins[i].op==0x0e) {
        size_t parent=ins[i].parent;
        while(parent!=SIZE_MAX&&ins[parent].op==2&&ins[parent].argument==0x40)
            parent=ins[parent].parent;
        if(parent!=SIZE_MAX&&ins[parent].op==2&&ins[parent].argument!=0x40)
            ins[parent].switch_result=true;
    }
}
/* Whether `block` is emit_switch's result block: void blocks open down to
 * the selector's `local.get` and `br_table`. */
static bool yx_v12_switch_result_block(const yx_v12_instruction *ins,size_t count,size_t block)
{
    size_t i=block+1;
    while(i<count&&ins[i].op==2&&ins[i].argument==0x40)++i;
    return i>block+1&&i+1<count&&ins[i].op==0x20&&ins[i+1].op==0x0e;
}

static bool yx_v12_body(const uint8_t *data,size_t length,const size_t *functions,
                        size_t function_count,const size_t *globals,size_t global_count,
                        size_t search,bool explicit_or,yx_writer *out,size_t *instruction_count,
                        const yx_v12_origins *input_origins,yx_v12_origins *output_origins)
{
    yx_v12_instruction *ins=NULL;
    size_t count=0,locals=0;
    bool ok=false;
    if(!yx_v12_instructions(data,length,&ins,&count,&locals))return false;
    yx_v12_boolean_blocks(data,ins,count);
    yx_v12_switch_blocks(ins,count);
    /* Undefined OR operands have their own catch. Upstream gives that catch
     * no result and branches to the OR's success label before leaving it.
     * The old IR catches false in a value block and branches afterwards. */
    for(size_t i=0;i<count;++i) {
        yx_v12_instruction *p=&ins[i];size_t parent=p->parent,end=p->mate;
        if(p->op!=2||p->argument!=0x7f||!p->targeted||parent==SIZE_MAX||
           !ins[parent].boolean_block||!ins[parent].short_value||end==SIZE_MAX)continue;
        bool next=end+1<count&&ins[end+1].short_circuit&&ins[end+1].short_value;
        bool last=explicit_or&&end+1==ins[parent].mate;
        if(!next&&!last)continue;
        p->or_operand=true;p->or_last=last;
        if(next)ins[end+1].remove=true;
    }
    for(size_t i=1;i<count;++i) {
        if(ins[i].op!=0x0c||ins[i].remove||ins[i-1].remove||
           ins[i-1].op!=0x41||ins[i-1].end-ins[i-1].start!=2||
           data[ins[i-1].start+1]!=0||ins[i-1].parent!=ins[i].parent)continue;
        size_t target=ins[i].parent;
        for(uint64_t d=0;d<ins[i].argument&&target!=SIZE_MAX;++d)target=ins[target].parent;
        if(target!=SIZE_MAX&&ins[target].or_operand) {
            ins[i].catch_undef=true;ins[i].catch_target=target;ins[i-1].remove=true;
        }
    }
    for(size_t i=0;i<count;++i) {
        yx_v12_instruction *p=&ins[i];
        if(p->op==2&&!p->targeted&&!p->switch_result) {p->remove=true;ins[p->mate].remove=true;}
        /* Lazy search: invert the guard and keep an explicit empty else. */
        if(i+4<count&&p->op==0x23&&p->argument<global_count&&globals[p->argument]==2&&
           ins[i+1].op==4&&ins[i+1].argument==0x40&&ins[i+2].op==5&&
           ins[i+3].op==0x10&&ins[i+3].argument==search&&ins[i+1].mate==i+4) {
            p->guard=true;ins[i+2].remove=true;ins[i+3].guard=true;
        }
        /* A defined value on the else arm can be read after the guard. */
        if(p->op==4&&p->argument!=0x40&&p->alternative!=SIZE_MAX&&
           p->mate==p->alternative+2&&ins[p->alternative+1].op==0x20&&
           p->alternative>i+1&&
           (ins[p->alternative-1].op==0x0c||ins[p->alternative-1].op==0x0f)) {
            p->move_value=true;ins[p->alternative+1].remove=true;
            ins[p->mate].move_value=true;
        }
    }
    if(!yx_put_bytes(out,data,locals))goto done;
    *instruction_count=0;
    for(size_t i=0;i<count;++i) {
        yx_v12_instruction *p=&ins[i];
        if(p->remove)continue;
        if(p->op!=5&&p->op!=0x0b)++*instruction_count;
        if(p->short_circuit) {
            if(!p->short_value){if(!yx_put_u8(out,0x45))goto done;++*instruction_count;}
            if(!yx_put_u8(out,0x0d)||!yx_put_u8(out,0))goto done;
        } else if(p->or_operand) {
            if(!yx_put_u8(out,2)||!yx_put_u8(out,0x40))goto done;
        } else if(p->op==0x0b&&p->mate!=SIZE_MAX&&ins[p->mate].or_operand) {
            static const uint8_t branch[]={0x0d,1,0x0b};
            if(!yx_put_bytes(out,branch,sizeof(branch)))goto done;++*instruction_count;
            if(ins[p->mate].or_last) {
                if(!yx_put_u8(out,0x41)||!yx_put_u8(out,0)||!yx_v12_origin(output_origins,0))goto done;
                ++*instruction_count;
            }
        } else if(p->boolean_block) {
            static const uint8_t nested[]={2,0x7f,2,0x40};
            if(!yx_put_bytes(out,nested,sizeof(nested)))goto done;++*instruction_count;
        } else if(p->op==0x0b&&p->mate!=SIZE_MAX&&ins[p->mate].boolean_block) {
            /* Plain `or` evaluates the last operand through br_if as well.
             * Pattern-set `any` leaves the last Boolean on the stack. The
             * v7 templates share that suffix, so source provenance selects
             * the v12 spelling when it is unambiguous. */
            bool last_default=i&&((ins[i-1].op==0x41&&ins[i-1].end-ins[i-1].start==2&&
                data[ins[i-1].start+1]==0&&i>1&&ins[i-2].remove)||
                (ins[i-1].op==0x0b&&ins[i-1].mate!=SIZE_MAX&&ins[ins[i-1].mate].or_last));
            if(explicit_or&&ins[p->mate].short_value&&!last_default) {
                static const uint8_t last[]={0x0d,0,0x41,0};
                if(!yx_put_bytes(out,last,sizeof(last))||!yx_v12_origin(output_origins,0))goto done;*instruction_count+=2;
            }
            uint8_t tail[]={0x0c,1,0x0b,0x41,ins[p->mate].short_value,0x0b};
            if(!yx_put_bytes(out,tail,sizeof(tail))||!yx_v12_origin(output_origins,0))goto done;*instruction_count+=2;
        } else if(p->op==0x10||p->op==0x12||p->op==0xd2) {
            if(p->argument>=function_count||!yx_put_u8(out,p->op)||
               !yx_put_uleb(out,functions[p->argument]))goto done;
            if(p->guard&&!yx_put_u8(out,5))goto done;
        } else if(p->op==0x23||p->op==0x24) {
            if(p->argument>=global_count||!yx_put_u8(out,p->op)||
               !yx_put_uleb(out,globals[p->argument]))goto done;
            if(p->guard) {if(!yx_put_u8(out,0x45))goto done;++*instruction_count;}
        } else if(p->op==0x0c||p->op==0x0d) {
            size_t parent=p->parent;uint64_t depth=p->argument,adjusted=depth;
            for(uint64_t d=0;d<depth&&parent!=SIZE_MAX;++d) {
                if(ins[parent].remove)--adjusted;
                if(ins[parent].boolean_block&&parent!=p->catch_target)++adjusted;
                parent=ins[parent].parent;
            }
            if(parent!=SIZE_MAX&&ins[parent].boolean_block&&parent!=p->catch_target)++adjusted;
            if(!yx_put_u8(out,p->op)||!yx_put_uleb(out,adjusted))goto done;
        } else if(p->op==0x0e) {
            yx_reader r={data,p->end,p->start+1,false,false};uint64_t n,d;
            if(!yx_get_uleb(&r,&n)||!yx_put_u8(out,0x0e)||!yx_put_uleb(out,n))goto done;
            for(uint64_t j=0;j<=n;++j) {
                if(!yx_get_uleb(&r,&d))goto done;
                size_t parent=p->parent;uint64_t adjusted=d;
                for(uint64_t k=0;k<d&&parent!=SIZE_MAX;++k) {
                    if(ins[parent].remove)--adjusted;
                    if(ins[parent].boolean_block)++adjusted;
                    parent=ins[parent].parent;
                }
                if(parent!=SIZE_MAX&&ins[parent].boolean_block)++adjusted;
                if(!yx_put_uleb(out,adjusted))goto done;
            }
        } else if(p->op==4&&p->move_value) {
            if(!yx_put_u8(out,4)||!yx_put_u8(out,0x40))goto done;
        } else {
            if(!yx_put_bytes(out,data+p->start,p->end-p->start))goto done;
            if(p->constant) {
                if(input_origins&&p->constant>input_origins->count)goto done;
                size_t source=input_origins?input_origins->items[p->constant-1]:p->constant;
                if(!yx_v12_origin(output_origins,source))goto done;
            }
            if(p->op==0x0b&&p->move_value) {
                yx_v12_instruction *value=&ins[ins[p->mate].alternative+1];
                if(!yx_put_bytes(out,data+value->start,value->end-value->start))goto done;
                ++*instruction_count;
            }
        }
    }
    ok=true;
done:
    free(ins);return ok;
}

typedef struct yx_v12_import {
    char module[128],name[256],wire_name[384];
    uint64_t type;
    size_t original;
    uint32_t rank;
} yx_v12_import;

static bool yx_v12_read_name(yx_reader *r,char *out,size_t capacity)
{
    uint64_t n;
    if(!yx_get_uleb(r,&n)||n>=capacity||n>r->length-r->at)return false;
    memcpy(out,r->data+r->at,(size_t)n);out[n]=0;r->at+=(size_t)n;return true;
}

static uint32_t yx_v12_rank(const yx_v12_import *p,unsigned profile)
{
    const char *name=p->name;
    for(size_t i=0;i<sizeof(yx_archive_symbol_aliases)/sizeof(yx_archive_symbol_aliases[0]);++i)
        if(!strcmp(p->module,yx_archive_symbol_aliases[i].module)&&
           !strcmp(name,yx_archive_symbol_aliases[i].wire_name)) {
            name=yx_archive_symbol_aliases[i].name;break;
        }
    if(profile==4) {
        for(size_t i=0;i<sizeof(yx_archive_capi_symbol_orders)/sizeof(yx_archive_capi_symbol_orders[0]);++i)
            if(!strcmp(p->module,yx_archive_capi_symbol_orders[i].module)&&
               !strcmp(name,yx_archive_capi_symbol_orders[i].name))return yx_archive_capi_symbol_orders[i].rank;
    } else {
        for(size_t i=0;i<sizeof(yx_archive_symbol_orders)/sizeof(yx_archive_symbol_orders[0]);++i)
            if(!strcmp(p->module,yx_archive_symbol_orders[i].module)&&
               !strcmp(name,yx_archive_symbol_orders[i].name))return yx_archive_symbol_orders[i].ranks[profile];
    }
    return UINT32_MAX;
}

static bool yx_v12_wasm_impl(const uint8_t *data,size_t length,unsigned profile,
                        yx_writer *out,size_t *definition_map,size_t map_capacity,
                        yx_v12_origins **constant_origins,size_t *origin_function_count)
{
    const uint8_t *sections[13]={0};size_t sizes[13]={0};
    yx_reader r={data,length,8,false,false};
    yx_v12_import imports[64];size_t import_count=0,global_count=0,globals[3]={0};
    size_t search=SIZE_MAX,defined=0,main=SIZE_MAX;
    uint64_t *types=NULL;size_t *map=NULL,*order=NULL,*counts=NULL;
    yx_writer *bodies=NULL;yx_v12_origins *origins=NULL;
    yx_writer imp={0},fun={0},exp={0},code={0};bool ok=false;
    if(length<8||memcmp(data,"\0asm\1\0\0\0",8))return false;
    while(r.at<length) {
        uint8_t id;uint64_t n;
        if(!yx_get_u8(&r,&id)||id>12||!id||!yx_get_uleb(&r,&n)||n>length-r.at||sections[id])goto done;
        sections[id]=data+r.at;sizes[id]=(size_t)n;r.at+=(size_t)n;
    }
    /* Already lowered by a nested encode call. */
    if(sections[5]&&sections[6])return yx_put_bytes(out,data,length);
    if(!sections[1]||!sections[3]||!sections[7]||!sections[10]||sections[8]||sections[9])goto done;
    r=(yx_reader){sections[2],sizes[2],0,false,false};uint64_t n=0;
    if(sections[2]&&(!yx_get_uleb(&r,&n)||n>68))goto done;
    for(uint64_t i=0;i<n;++i) {
        yx_v12_import p={0};uint8_t kind;
        if(!yx_v12_read_name(&r,p.module,sizeof(p.module))||!yx_v12_read_name(&r,p.name,sizeof(p.name))||!yx_get_u8(&r,&kind))goto done;
        if(kind==0) {
            if(import_count==64||!yx_get_uleb(&r,&p.type)||!yx_v12_mangle(p.name,p.wire_name,sizeof(p.wire_name)))goto done;
            for(size_t alias=0;alias<sizeof(yx_archive_symbol_aliases)/sizeof(yx_archive_symbol_aliases[0]);++alias)
                if(!strcmp(p.module,yx_archive_symbol_aliases[alias].module)&&
                   !strcmp(p.name,yx_archive_symbol_aliases[alias].name)) {
                    const char *wire=yx_archive_symbol_aliases[alias].wire_name;
                    if(strlen(wire)>=sizeof(p.wire_name))goto done;
                    strcpy(p.wire_name,wire);break;
                }
            p.original=import_count;p.rank=yx_v12_rank(&p,profile&255);
            if(!strcmp(p.name,"search_for_patterns@@"))search=import_count;
            imports[import_count++]=p;
        } else if(kind==3) {
            uint8_t type,mut;
            if(global_count==3||strcmp(p.module,"yara_x")||!yx_get_u8(&r,&type)||!yx_get_u8(&r,&mut))goto done;
            if(!strcmp(p.name,"matching_patterns_bitmap_base"))globals[global_count++]=0;
            else if(!strcmp(p.name,"filesize"))globals[global_count++]=1;
            else if(!strcmp(p.name,"pattern_search_done"))globals[global_count++]=2;
            else goto done;
        } else if(kind==2) {
            uint64_t flags,min;
            if(strcmp(p.module,"yara_x")||strcmp(p.name,"main_memory")||!yx_get_uleb(&r,&flags)||flags||!yx_get_uleb(&r,&min)||min!=1)goto done;
        } else goto done;
    }
    if(r.at!=r.length)goto done;
    r=(yx_reader){sections[3],sizes[3],0,false,false};
    if(!yx_get_uleb(&r,&n)||n>length||n>SIZE_MAX/sizeof(*types))goto done;
    defined=(size_t)n;
    types=calloc(defined?defined:1,sizeof(*types));counts=calloc(defined?defined:1,sizeof(*counts));
    order=calloc(defined?defined:1,sizeof(*order));map=calloc(import_count+defined?import_count+defined:1,sizeof(*map));
    bodies=calloc(defined?defined:1,sizeof(*bodies));
    if(constant_origins)origins=calloc(defined?defined:1,sizeof(*origins));
    if(!types||!counts||!order||!map||!bodies||(constant_origins&&!origins))goto done;
    for(size_t i=0;i<defined;++i)if(!yx_get_uleb(&r,&types[i]))goto done;
    if(r.at!=r.length)goto done;
    /* Stable sort imports by the official release's link order. */
    for(size_t i=1;i<import_count;++i) {
        yx_v12_import p=imports[i];size_t j=i;
        while(j&&imports[j-1].rank>p.rank){imports[j]=imports[j-1];--j;}imports[j]=p;
    }
    for(size_t i=0;i<import_count;++i)map[imports[i].original]=i;
    for(size_t i=0;i<defined;++i){map[import_count+i]=import_count+i;order[i]=i;}
    r=(yx_reader){sections[10],sizes[10],0,false,false};
    if(!yx_get_uleb(&r,&n)||n!=defined)goto done;
    /* First pass counts the reduced functions, then sorts like walrus. */
    for(size_t i=0;i<defined;++i) {
        if(!yx_get_uleb(&r,&n)||n>r.length-r.at||!yx_v12_body(r.data+r.at,(size_t)n,map,import_count+defined,globals,global_count,search,(profile&256)!=0,&bodies[i],&counts[i],NULL,origins?&origins[i]:NULL))goto done;
        /* emit_rule measures before finish_rule_func appends its final
         * i32.const 0. Check the lowered spelling too: single-rule module
         * builders and explicit OR can add instructions after chunk sizing. */
        if(counts[i]>YX_ARCHIVE_MAX_FUNCTION_INSTRUCTIONS+1u)goto done;
        r.at+=(size_t)n;
    }
    if(r.at!=r.length)goto done;
    for(size_t i=1;i<defined;++i) {
        size_t p=order[i],j=i;
        while(j&&counts[order[j-1]]<counts[p]){order[j]=order[j-1];--j;}order[j]=p;
    }
    for(size_t i=0;i<defined;++i)map[import_count+order[i]]=import_count+i;
    if(definition_map) {
        if(defined>map_capacity)goto done;
        for(size_t i=0;i<defined;++i)definition_map[i]=map[import_count+i]-import_count;
    }
    /* Relocate reduced bodies; globals are already in their final indices. */
    size_t identity_globals[3]={0,1,2};
    size_t *identity_imports=calloc(import_count+defined?import_count+defined:1,sizeof(size_t));
    if(!identity_imports)goto done;
    for(size_t i=0;i<import_count;++i)identity_imports[i]=i;
    for(size_t i=0;i<defined;++i)identity_imports[import_count+i]=map[import_count+i];
    bool relocated=true;
    for(size_t i=0;relocated&&i<defined;++i) {
        yx_writer body={0};size_t ignored;yx_v12_origins relocated_origins={0};
        relocated=yx_v12_body(bodies[i].data,bodies[i].used,identity_imports,import_count+defined,identity_globals,3,SIZE_MAX,false,&body,&ignored,origins?&origins[i]:NULL,origins?&relocated_origins:NULL);
        if(relocated){
            free(bodies[i].data);bodies[i]=body;
            if(origins){free(origins[i].items);origins[i]=relocated_origins;}
        }else {free(body.data);free(relocated_origins.items);}
    }
    free(identity_imports);if(!relocated)goto done;
    r=(yx_reader){sections[7],sizes[7],0,false,false};
    if(!yx_get_uleb(&r,&n)||n!=1)goto done;
    {char name[64];uint8_t kind;uint64_t index;
        if(!yx_v12_read_name(&r,name,sizeof(name))||strcmp(name,"main")||!yx_get_u8(&r,&kind)||kind||!yx_get_uleb(&r,&index)||index>=import_count+defined)goto done;
        main=map[index];}
    if(!yx_put_uleb(&imp,import_count)||!yx_put_uleb(&fun,defined)||!yx_put_uleb(&code,defined)||!yx_put_uleb(&exp,5))goto done;
    for(size_t i=0;i<import_count;++i)
        if(!yx_v12_name(&imp,imports[i].module)||!yx_v12_name(&imp,imports[i].wire_name)||!yx_put_u8(&imp,0)||!yx_put_uleb(&imp,imports[i].type))goto done;
    for(size_t i=0;i<defined;++i) {
        size_t p=order[i];
        if(!yx_put_uleb(&fun,types[p])||!yx_put_uleb(&code,bodies[p].used)||!yx_put_bytes(&code,bodies[p].data,bodies[p].used))goto done;
    }
    {static const char *names[]={"matching_patterns_bitmap_base","filesize","pattern_search_done","main_memory","main"};
        for(size_t i=0;i<5;++i)
            if(!yx_v12_name(&exp,names[i])||!yx_put_u8(&exp,i<3?3:i==3?2:0)||!yx_put_uleb(&exp,i<3?i:i==3?0:main))goto done;}
    {static const uint8_t memory[]={1,0,1};
        static const uint8_t global[]={3,0x7f,1,0x41,0,0x0b,0x7e,1,0x42,0x7f,0x0b,0x7f,1,0x41,0,0x0b};
        yx_writer t={(uint8_t*)sections[1],sizes[1],sizes[1]},m={(uint8_t*)memory,sizeof(memory),sizeof(memory)},g={(uint8_t*)global,sizeof(global),sizeof(global)};
        ok=yx_put_bytes(out,data,8)&&yx_v12_section(out,1,&t)&&(!import_count||yx_v12_section(out,2,&imp))&&yx_v12_section(out,3,&fun)&&
           yx_v12_section(out,5,&m)&&yx_v12_section(out,6,&g)&&yx_v12_section(out,7,&exp)&&yx_v12_section(out,10,&code);}
    if(ok&&constant_origins) {
        yx_v12_origins *sorted=calloc(defined?defined:1,sizeof(*sorted));
        if(!sorted)ok=false;
        else {
            for(size_t i=0;i<defined;++i){sorted[i]=origins[order[i]];origins[order[i]].items=NULL;}
            *constant_origins=sorted;*origin_function_count=defined;
        }
    }
done:
    if(origins)for(size_t i=0;i<defined;++i)free(origins[i].items);
    free(origins);
    if(bodies)for(size_t i=0;i<defined;++i)free(bodies[i].data);
    free(types);free(map);free(order);free(counts);free(bodies);
    free(imp.data);free(fun.data);free(exp.data);free(code.data);return ok;
}

static bool yx_v12_wasm(const uint8_t *data,size_t length,unsigned profile,
                        yx_writer *out)
{
    return yx_v12_wasm_impl(data,length,profile,out,NULL,0,NULL,NULL);
}

static bool yx_v12_rule_size(const uint8_t *data,size_t length,
                             size_t search_global,uint64_t *count)
{
    yx_v12_instruction *ins=NULL;size_t n=0,locals=0;uint64_t result=0;
    if(!yx_v12_instructions(data,length,&ins,&n,&locals))return false;
    yx_v12_boolean_blocks(data,ins,n);
    yx_v12_switch_blocks(ins,n);
    for(size_t i=0;i<n;++i) {
        if(!ins[i].remove&&ins[i].op!=5&&ins[i].op!=0x0b&&
           !(ins[i].op==2&&!ins[i].targeted&&!ins[i].switch_result))++result;
        if(ins[i].boolean_block)result+=3;
        if(ins[i].short_circuit&&!ins[i].short_value)++result;
        if(i+4<n&&ins[i].op==0x23&&ins[i].argument==search_global&&
           ins[i+1].op==4&&ins[i+2].op==5&&ins[i+3].op==0x10&&
           ins[i+1].mate==i+4)++result;
    }
    free(ins);*count=result;return true;
}

static bool yx_v12_archive_wasm(uint8_t **data,size_t *length,unsigned profile)
{
    size_t start,size;
    yx_writer w={0},wasm={0};
    if(!yx_archive_wasm_locate(*data,*length,&start,&size))return false;
    /* Locate the bincode length separately; its width can change. */
    yx_reader r={*data,*length,12,false,false};uint64_t n;
    for(unsigned pool=0;pool<2;++pool) {
        if(!yx_get_uint(&r,&n))return false;
        for(uint64_t i=0;i<n;++i)if(!yx_skip_bincode_bytes(&r))return false;
    }
    uint8_t flag;
    if(!yx_get_u8(&r,&flag)||!yx_get_uint(&r,&n))return false;
    for(uint64_t i=0;i<n;++i)if(!yx_skip_bincode_bytes(&r))return false;
    size_t prefix=r.at;
    /* The rewritten archive is about as long as the original. */
    if(*length<=SIZE_MAX-64&&(w.data=malloc(*length+64)))w.capacity=*length+64;
    yx_v12_memo *memo=yx_v12_memo_active;bool lowered;
    if(memo&&memo->valid&&memo->profile==profile&&memo->input_length==size&&!memcmp(memo->input,*data+start,size))
        lowered=yx_put_bytes(&wasm,memo->output,memo->output_length);
    else if((lowered=yx_v12_wasm(*data+start,size,profile,&wasm))&&memo) {
        uint8_t *input=malloc(size?size:1),*output=malloc(wasm.used?wasm.used:1);
        if(input&&output) {
            memcpy(input,*data+start,size);if(wasm.used)memcpy(output,wasm.data,wasm.used);
            yx_v12_memo_free(memo);
            *memo=(yx_v12_memo){profile,input,output,size,wasm.used,true};
        } else {free(input);free(output);}
    }
    bool ok=lowered&&
        yx_put_bytes(&w,*data,prefix)&&yx_put_uint(&w,wasm.used)&&
        yx_put_bytes(&w,wasm.data,wasm.used)&&
        yx_put_bytes(&w,*data+start+size,*length-start-size);
    free(wasm.data);
    if(!ok){free(w.data);return false;}
    free(*data);*data=w.data;*length=w.used;return true;
}

static bool yx_v12_sections(const uint8_t *data,size_t length,
                            const uint8_t **parts,size_t *sizes)
{
    yx_reader r={data,length,8,false,false};
    if(length<8||memcmp(data,"\0asm\1\0\0\0",8))return false;
    memset(parts,0,13*sizeof(*parts));memset(sizes,0,13*sizeof(*sizes));
    while(r.at<length) {
        uint8_t id;uint64_t n;
        if(!yx_get_u8(&r,&id)||!id||id>12||parts[id]||!yx_get_uleb(&r,&n)||n>length-r.at)return false;
        parts[id]=data+r.at;sizes[id]=(size_t)n;r.at+=(size_t)n;
    }
    return true;
}

/* Match the existing template grammar, allowing its integer/float immediates
 * to vary. Nonconstant instructions, signatures and indices must match. This
 * is deliberately narrower than accepting arbitrary executable WASM. */
static bool yx_v12_body_constants(const uint8_t *expected,size_t expected_length,
                                  const uint8_t *actual,size_t actual_length,
                                  yx_literal **values,size_t *value_count,const yx_v12_origins *origins)
{
    yx_v12_instruction *a=NULL,*b=NULL;
    size_t na=0,nb=0,la=0,lb=0,n=0;yx_literal *v=NULL;bool ok=false;
    if(!yx_v12_instructions(expected,expected_length,&a,&na,&la)||
       !yx_v12_instructions(actual,actual_length,&b,&nb,&lb)||na!=nb||la!=lb||memcmp(expected,actual,la))goto done;
    v=calloc(na?na:1,sizeof(*v));if(!v)goto done;
    for(size_t i=0;i<na;++i) {
        if(a[i].op!=b[i].op)goto done;
        if(a[i].op>=0x41&&a[i].op<=0x44) {
            if(!origins||n>=origins->count)goto done;
            if(!origins->items[n]&&(a[i].end-a[i].start!=b[i].end-b[i].start||
                memcmp(expected+a[i].start,actual+b[i].start,a[i].end-a[i].start)))goto done;
            v[n].data=actual+b[i].start+1;v[n++].length=b[i].end-b[i].start-1;
        } else if(a[i].end-a[i].start!=b[i].end-b[i].start||
                  memcmp(expected+a[i].start,actual+b[i].start,a[i].end-a[i].start))goto done;
    }
    if(n!=origins->count)goto done;
    *values=v;*value_count=n;v=NULL;ok=true;
done:
    free(a);free(b);free(v);return ok;
}

static bool yx_v12_restore_template(const uint8_t *actual,size_t actual_length,
                                    const uint8_t *template_data,size_t template_length,
                                    unsigned profile,yx_writer *restored)
{
    const uint8_t *a[13],*e[13],*t[13];size_t az[13],ez[13],tz[13],mapping[64];
    yx_writer expected={0},code={0};yx_literal **constants=NULL;size_t *counts=NULL;
    yx_v12_origins *origins=NULL;size_t origin_count=0;
    size_t defined=0;bool ok=false;
    if(!yx_v12_wasm_impl(template_data,template_length,profile,&expected,mapping,64,&origins,&origin_count)||
       !yx_v12_sections(actual,actual_length,a,az)||
       !yx_v12_sections(expected.data,expected.used,e,ez)||
       !yx_v12_sections(template_data,template_length,t,tz))goto done;
    if(expected.used==actual_length&&!memcmp(expected.data,actual,actual_length)) {
        ok=yx_put_bytes(restored,template_data,template_length);goto done;
    }
    for(unsigned i=1;i<13;++i)
        if(i!=10&&(az[i]!=ez[i]||(az[i]&&memcmp(a[i],e[i],az[i]))))goto done;
    yx_reader ar={a[10],az[10],0,false,false},er={e[10],ez[10],0,false,false};uint64_t n,m;
    if(!yx_get_uleb(&ar,&n)||!yx_get_uleb(&er,&m)||n!=m||n>64)goto done;
    defined=(size_t)n;constants=calloc(defined?defined:1,sizeof(*constants));counts=calloc(defined?defined:1,sizeof(*counts));
    if(!constants||!counts)goto done;
    for(size_t i=0;i<defined;++i) {
        if(!yx_get_uleb(&ar,&n)||n>ar.length-ar.at||!yx_get_uleb(&er,&m)||m>er.length-er.at||
           !yx_v12_body_constants(er.data+er.at,(size_t)m,ar.data+ar.at,(size_t)n,&constants[i],&counts[i],&origins[i]))goto done;
        ar.at+=(size_t)n;er.at+=(size_t)m;
    }
    if(ar.at!=ar.length||er.at!=er.length)goto done;
    yx_reader tr={t[10],tz[10],0,false,false};
    if(!yx_get_uleb(&tr,&n)||n!=defined||!yx_put_uleb(&code,defined))goto done;
    for(size_t i=0;i<defined;++i) {
        if(!yx_get_uleb(&tr,&n)||n>tr.length-tr.at)goto done;
        const uint8_t *body=tr.data+tr.at;
        yx_v12_instruction *ins=NULL;size_t ni=0,locals=0;
        yx_literal *source_values=NULL;yx_writer rewritten={0};
        bool written=yx_v12_instructions(body,(size_t)n,&ins,&ni,&locals)&&yx_put_bytes(&rewritten,body,locals);
        if(written)source_values=calloc(ni?ni:1,sizeof(*source_values));
        written=written&&source_values;
        size_t f=mapping[i];
        for(size_t k=0;written&&k<origins[f].count;++k) {
            size_t source=origins[f].items[k];
            if(source>ni)written=false;
            else if(source)source_values[source-1]=constants[f][k];
        }
        for(size_t j=0;written&&j<ni;++j) {
            yx_literal value={0};
            if(ins[j].constant)value=source_values[ins[j].constant-1];
            if(value.data)
                written=yx_put_u8(&rewritten,ins[j].op)&&yx_put_bytes(&rewritten,value.data,value.length);
            else written=yx_put_bytes(&rewritten,body+ins[j].start,ins[j].end-ins[j].start);
        }
        written=written&&yx_put_uleb(&code,rewritten.used)&&yx_put_bytes(&code,rewritten.data,rewritten.used);
        free(ins);free(source_values);free(rewritten.data);if(!written)goto done;
        tr.at+=(size_t)n;
    }
    if(!yx_put_bytes(restored,template_data,8))goto done;
    for(unsigned i=1;i<13;++i)if(t[i]) {
        yx_writer part={(uint8_t*)t[i],tz[i],tz[i]};
        if(!yx_v12_section(restored,(uint8_t)i,i==10?&code:&part))goto done;
    }
    ok=true;
done:
    if(constants)for(size_t i=0;i<defined;++i)free(constants[i]);
    if(origins)for(size_t i=0;i<origin_count;++i)free(origins[i].items);
    free(origins);
    free(constants);free(counts);free(expected.data);free(code.data);return ok;
}

/* Recover a numeric expression directly from its operands. Only the small
 * guard changes made above are reversed; re-emitting the expression must
 * reproduce the complete input module before this representation is used. */
static bool yx_v12_restore_numeric(const uint8_t *data,size_t length,yx_writer *restored)
{
    const uint8_t *parts[13];size_t sizes[13];yx_integer_expr tree={0};
    yx_v12_instruction *ins=NULL;size_t count=0,locals=0;yx_writer expression={0},source={0};
    uint8_t *seed=NULL;size_t seed_length=0;bool ok=false;uint64_t n;
    if(!yx_v12_sections(data,length,parts,sizes)||!parts[2]||!parts[10])return false;
    yx_reader r={parts[2],sizes[2],0,false,false};tree.match_id=255;
    if(!yx_get_uleb(&r,&n)||n>YX_INTEGER_READ_COUNT+1)goto done;
    for(size_t i=0;i<n;++i) {
        char module[64],name[256],expected[256];uint8_t kind;uint64_t type;
        if(!yx_v12_read_name(&r,module,sizeof(module))||strcmp(module,"yara_x::wasm")||
           !yx_v12_read_name(&r,name,sizeof(name))||!yx_get_u8(&r,&kind)||kind||
           !yx_get_uleb(&r,&type))goto done;
        if(!strcmp(name,"rule_match@rule_id:i64@")) {
            if(tree.match_id!=255||type!=2)goto done;tree.match_id=(uint8_t)i;
        } else {
            unsigned reader;
            for(reader=0;reader<YX_INTEGER_READ_COUNT;++reader)
                if(yx_v12_mangle(yx_integer_codec_read_import_name((uint8_t)reader),expected,sizeof(expected))&&
                   !strcmp(name,expected))break;
            if(reader==YX_INTEGER_READ_COUNT||type!=3||(tree.read_mask&(1u<<reader)))goto done;
            tree.read_mask|=(uint16_t)(1u<<reader);tree.read_ids[reader]=(uint8_t)i;
        }
        ++tree.function_count;
    }
    if(r.at!=r.length||tree.match_id==255)goto done;
    r=(yx_reader){parts[10],sizes[10],0,false,false};
    if(!yx_get_uleb(&r,&n)||n!=3||!yx_get_uleb(&r,&n)||n>r.length-r.at||
       !yx_v12_instructions(r.data+r.at,(size_t)n,&ins,&count,&locals))goto done;
    const uint8_t *body=r.data+r.at;size_t finish=SIZE_MAX;
    for(size_t i=4;i<count;++i)
        if(ins[i].op==0x10&&ins[i].argument==tree.match_id&&
           ins[i-1].op==0x41&&ins[i-2].op==5&&ins[i-3].op==4&&
           ins[i-3].argument==0x40&&ins[i-4].op==0x45){finish=i-4;break;}
    if(finish==SIZE_MAX)goto done;
    size_t first=0;
    if(count&&ins[0].op==2&&ins[0].argument==0x7f&&ins[0].mate+1==finish) {
        first=1;--finish;
    }
    for(size_t i=0;i<finish;++i) {
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
    r=(yx_reader){expression.data,expression.used,0,false,false};
    int root=yx_integer_wasm_block(&r,r.length,&tree,0,-1);
    if(root<0||r.at!=r.length||!yx_integer_expr_print(&tree,root,&source,0,false,0)||!yx_put_u8(&source,0))goto done;
    for(unsigned profile=0;!ok&&profile<2;++profile) {
        yx_writer expected={0};free(seed);seed=NULL;seed_length=0;
        ok=yx_make_runtime_integer_wasm((const char*)source.data,0,&seed,&seed_length)&&
            yx_v12_wasm(seed,seed_length,(profile?4:0)|256,&expected)&&
            expected.used==length&&!memcmp(expected.data,data,length);
        free(expected.data);
    }
    if(ok)ok=yx_put_bytes(restored,seed,seed_length);
done:
    free(ins);free(expression.data);free(source.data);free(seed);yx_integer_expr_destroy(&tree);return ok;
}

#include "serialization_v12_numeric.h"
#include "serialization_v12_patterns.h"

#include "serialization_v12_modules.h"
#include "serialization_v12_multi.h"

/* The existing codec recognizes these instruction grammars, with numeric
 * immediates filled from the archive. Keep the serialized v12 module intact
 * outside this bounded private decode representation. `module_only` restores
 * just the module-expression form, for the composed decoder when another
 * restorer's form was not decodable. */
static bool yx_v12_decode_archive_mode(const uint8_t *data,size_t length,
                                       uint8_t **normalized,size_t *normalized_length,bool module_only);
static bool yx_v12_decode_archive(const uint8_t *data,size_t length,
                                  uint8_t **normalized,size_t *normalized_length)
{
    return yx_v12_decode_archive_mode(data,length,normalized,normalized_length,false);
}
static bool yx_v12_decode_archive_mode(const uint8_t *data,size_t length,
                                       uint8_t **normalized,size_t *normalized_length,bool module_only)
{
    static const struct {const uint8_t *data;size_t length;} templates[]={
        {yx_constant_wasm,sizeof(yx_constant_wasm)},
        {yx_with_eq_wasm,sizeof(yx_with_eq_wasm)},
        {yx_with_ref_and_eq_wasm,sizeof(yx_with_ref_and_eq_wasm)},
        {yx_with_two_integer_wasm,sizeof(yx_with_two_integer_wasm)},
        {yx_integer_global_gt_zero_wasm,sizeof(yx_integer_global_gt_zero_wasm)},
        {yx_boolean_global_wasm,sizeof(yx_boolean_global_wasm)},
        {yx_float_global_gt_zero_wasm,sizeof(yx_float_global_gt_zero_wasm)},
        {yx_string_global_eq_wasm,sizeof(yx_string_global_eq_wasm)},
        {yx_single_text_pattern_wasm,sizeof(yx_single_text_pattern_wasm)},
        {yx_time_now_wasm,sizeof(yx_time_now_wasm)},
        {yx_time_now_magic_wasm,sizeof(yx_time_now_magic_wasm)},
        {yx_math_max_eq_wasm,sizeof(yx_math_max_eq_wasm)},
        {yx_console_pe_log_wasm,sizeof(yx_console_pe_log_wasm)},
        {yx_single_text_range_offset_wasm,sizeof(yx_single_text_range_offset_wasm)},
        {yx_single_text_range_offset_magic_wasm,sizeof(yx_single_text_range_offset_magic_wasm)},
        {yx_single_text_match_in_range_wasm,sizeof(yx_single_text_match_in_range_wasm)},
        {yx_single_text_direct_length_wasm,sizeof(yx_single_text_direct_length_wasm)},
        {yx_single_text_direct_offset_wasm,sizeof(yx_single_text_direct_offset_wasm)},
        {yx_single_text_presence_offset_ten_wasm,sizeof(yx_single_text_presence_offset_ten_wasm)},
        {yx_single_text_all_stats_wasm,sizeof(yx_single_text_all_stats_wasm)},
        {yx_single_text_presence_offset_ten_true_magic_wasm,sizeof(yx_single_text_presence_offset_ten_true_magic_wasm)},
        {yx_single_text_presence_offset_ten_dual_wasm,sizeof(yx_single_text_presence_offset_ten_dual_wasm)},
        {yx_single_text_all_stats_true_magic_wasm,sizeof(yx_single_text_all_stats_true_magic_wasm)},
        {yx_single_text_all_stats_dual_wasm,sizeof(yx_single_text_all_stats_dual_wasm)},
        {yx_single_text_all_stats_vba_wasm,sizeof(yx_single_text_all_stats_vba_wasm)},
        {yx_single_text_range_offset_true_magic_wasm,sizeof(yx_single_text_range_offset_true_magic_wasm)},
        {yx_single_text_range_offset_dual_wasm,sizeof(yx_single_text_range_offset_dual_wasm)},
        {yx_single_text_at_zero_wasm,sizeof(yx_single_text_at_zero_wasm)},
        {yx_single_text_count_gt_zero_wasm,sizeof(yx_single_text_count_gt_zero_wasm)},
        {yx_single_pattern_one_wasm,sizeof(yx_single_pattern_one_wasm)},
        {yx_pattern_true_wasm,sizeof(yx_pattern_true_wasm)},
        {yx_true_pattern_wasm,sizeof(yx_true_pattern_wasm)},
        {yx_two_rules_single_text_wasm,sizeof(yx_two_rules_single_text_wasm)},
        {yx_two_pattern_reference_ref_wasm,sizeof(yx_two_pattern_reference_ref_wasm)},
        {yx_two_pattern_reference_magic_wasm,sizeof(yx_two_pattern_reference_magic_wasm)},
        {yx_one_pattern_reference_wasm,sizeof(yx_one_pattern_reference_wasm)},
        {yx_two_text_or_wasm,sizeof(yx_two_text_or_wasm)},
        {yx_two_text_all_wasm,sizeof(yx_two_text_all_wasm)},
        {yx_numeric_of_wasm,sizeof(yx_numeric_of_wasm)},
        {yx_for_any_one_wasm,sizeof(yx_for_any_one_wasm)},
        {yx_for_any_two_wasm,sizeof(yx_for_any_two_wasm)},
        {yx_for_any_three_wasm,sizeof(yx_for_any_three_wasm)},
        {yx_for_any_four_wasm,sizeof(yx_for_any_four_wasm)},
        {yx_two_text_any_wasm,sizeof(yx_two_text_any_wasm)},
        {yx_two_text_and_wasm,sizeof(yx_two_text_and_wasm)},
        {yx_three_text_any_wasm,sizeof(yx_three_text_any_wasm)},
        {yx_three_text_or_wasm,sizeof(yx_three_text_or_wasm)},
        {yx_three_text_and_wasm,sizeof(yx_three_text_and_wasm)},
        {yx_four_text_any_wasm,sizeof(yx_four_text_any_wasm)},
        {yx_four_text_or_wasm,sizeof(yx_four_text_or_wasm)},
        {yx_four_text_and_wasm,sizeof(yx_four_text_and_wasm)},
        {yx_five_text_or_wasm,sizeof(yx_five_text_or_wasm)},
        {yx_five_text_and_wasm,sizeof(yx_five_text_and_wasm)},
        {yx_pe_is_pe_wasm,sizeof(yx_pe_is_pe_wasm)},
        {yx_pe_number_of_sections_wasm,sizeof(yx_pe_number_of_sections_wasm)},
        {yx_pe_sections_len_wasm,sizeof(yx_pe_sections_len_wasm)},
        {yx_pe_version_with_any_wasm,sizeof(yx_pe_version_with_any_wasm)},
        {yx_pe_version_with_any_magic_wasm,sizeof(yx_pe_version_with_any_magic_wasm)},
        {yx_pe_version_any_wasm,sizeof(yx_pe_version_any_wasm)},
        {yx_pe_version_any_two_wasm,sizeof(yx_pe_version_any_two_wasm)},
        {yx_pe_version_any_magic_wasm,sizeof(yx_pe_version_any_magic_wasm)},
        {yx_pe_version_any_two_magic_wasm,sizeof(yx_pe_version_any_two_magic_wasm)},
        {yx_pe_version_any_true_magic_wasm,sizeof(yx_pe_version_any_true_magic_wasm)},
        {yx_pe_version_any_dual_wasm,sizeof(yx_pe_version_any_dual_wasm)},
        {yx_pe_version_any_two_true_magic_wasm,sizeof(yx_pe_version_any_two_true_magic_wasm)},
        {yx_pe_version_any_two_dual_wasm,sizeof(yx_pe_version_any_two_dual_wasm)},
        {yx_pe_version_with_any_true_magic_wasm,sizeof(yx_pe_version_with_any_true_magic_wasm)},
        {yx_pe_version_with_any_dual_wasm,sizeof(yx_pe_version_with_any_dual_wasm)},
        {yx_pe_is_pe_filesize_wasm,sizeof(yx_pe_is_pe_filesize_wasm)},
        {yx_empty_rules_wasm,sizeof(yx_empty_rules_wasm)},
    };
    size_t start,size;
    if(!yx_archive_wasm_locate(data,length,&start,&size))return false;
    const uint8_t *parts[13];size_t sizes[13];
    if(!yx_v12_sections(data+start,size,parts,sizes)||!parts[5]||!parts[6])return false;
    yx_writer restored={0},archive={0};bool found=false;
    if(module_only) {
        found=yx_v12_restore_module_expression(data+start,size,&restored);
        goto restored_ready;
    }
    for(size_t i=0;!found&&i<sizeof(templates)/sizeof(templates[0]);++i)
        for(unsigned p=0;!found&&p<4;++p) {
            restored.used=0;
            found=yx_v12_restore_template(data+start,size,templates[i].data,templates[i].length,(p&1?4:0)|(p&2?256:0),&restored);
        }
    if(!found) {
        restored.used=0;
        found=yx_v12_restore_numeric(data+start,size,&restored);
    }
    if(!found) {
        size_t prefix,numeric_start,numeric_size,numeric_count;
        if(yx_rule_expression_wasm_span(data,length,&prefix,&numeric_start,&numeric_size,&numeric_count)&&numeric_count>0) {
            restored.used=0;
            found=yx_v12_restore_numeric_rules(data+start,size,numeric_count,&restored);
        }
    }
    if(!found)found=yx_v12_restore_pattern_sets(data,length,data+start,size,&restored);
    /* Typed pattern operands must retain their writer's Boolean grammar.
     * A raw module inverse can lower identically while reconstructing an
     * older private OR form which the typed archive reader cannot accept. */
    if(!found)found=yx_v12_restore_multi_expressions(data,length,data+start,size,&restored);
    if(!found)found=yx_v12_restore_module_expression(data+start,size,&restored);
    if(!found)found=yx_v12_restore_pattern_expressions(data+start,size,&restored);
    if(!found)found=yx_v12_restore_pattern_rules(data,length,data+start,size,&restored);
    /* Runtime integer emitters construct these grammars rather than storing
     * static modules. Numeric immediates are recovered by the same matcher. */
    for(unsigned shape=0;!found&&shape<1+YX_INTEGER_READ_COUNT;++shape)
        for(unsigned comparison=0;!found&&comparison<6;++comparison) {
            static const char *const operators[]={"==","!=","<",">","<=",">="};
            char condition[96];yx_ser_rule rule={0};uint8_t *seed=NULL;size_t seed_length=0;
            if(shape==0) {
                snprintf(condition,sizeof(condition),"filesize %s 100",operators[comparison]);
                if(!yx_condition_filesize(condition,&rule)||!yx_make_filesize_wasm(&rule,&seed,&seed_length))continue;
            } else {
                snprintf(condition,sizeof(condition),"%s(0) %s 1",yx_integer_codec_read_name((uint8_t)(shape-1)),operators[comparison]);
                if(shape<=6) {
                    if(!yx_condition_integer_read(condition,&rule)||!yx_make_integer_read_wasm(&rule,false,&seed,&seed_length))continue;
                } else if(!yx_make_runtime_integer_wasm(condition,0,&seed,&seed_length))continue;
            }
            for(unsigned p=0;!found&&p<2;++p) {
                restored.used=0;
                found=yx_v12_restore_template(data+start,size,seed,seed_length,p?4:0,&restored);
            }
            free(seed);
        }
    /* Range-loop immediates include control-flow constants which lowering
     * removes. Their source ordinals, rather than their positions in the
     * reduced body, identify the corresponding bounds and comparison value. */
    static const char *const quantifiers[]={"any","all","none"};
    static const char *const comparisons[]={"==","!=","<",">","<=",">="};
    for(unsigned quantifier=0;!found&&quantifier<3;++quantifier)
        for(unsigned body=0;!found&&body<7;++body) {
            char condition[128];uint8_t *seed=NULL;size_t seed_length=0;
            if(body==6)snprintf(condition,sizeof(condition),"for %s i in (0..3) : (true)",quantifiers[quantifier]);
            else snprintf(condition,sizeof(condition),"for %s i in (0..3) : (i %s 1)",quantifiers[quantifier],comparisons[body]);
            if(!yx_make_runtime_integer_wasm(condition,0,&seed,&seed_length))continue;
            for(unsigned p=0;!found&&p<2;++p) {
                restored.used=0;
                found=yx_v12_restore_template(data+start,size,seed,seed_length,p?4:0,&restored);
            }
            free(seed);
        }
    /* Constant and prior-rule grammars have a variable number of rule
     * records. The envelope gives that number independently of WASM. */
    size_t prefix,wasm_start,wasm_size,rule_count;
    if(!found&&yx_rule_expression_wasm_span(data,length,&prefix,&wasm_start,&wasm_size,&rule_count)&&
       rule_count>1&&rule_count<=256) {
        bool *truths=calloc(rule_count,sizeof(*truths));uint8_t *seed=NULL;size_t seed_length=0;
        if(truths) {
            if(yx_make_constant_wasm(truths,NULL,rule_count,&seed,&seed_length,NULL)) {
                for(unsigned p=0;!found&&p<2;++p) {
                    restored.used=0;
                    found=yx_v12_restore_template(data+start,size,seed,seed_length,p?4:0,&restored);
                }
            }
            free(seed);free(truths);
        }
        if(!found) {
            yx_integer_expr *trees=calloc(rule_count,sizeof(*trees));
            int *roots=calloc(rule_count,sizeof(*roots));
            YRX_RULE *rules=calloc(rule_count,sizeof(*rules));
            yx_rule_expression_context context={0};bool valid=trees&&roots&&rules;
            context.rules=rules;context.rule_count=rule_count;
            for(size_t i=0;valid&&i<rule_count;++i) {
                rules[i].identifier=(char*)"a";context.current=i;
                yx_rule_expression_setup(&trees[i],&context);
                roots[i]=yx_integer_expr_condition(&trees[i],i?"a":"true");
                valid=roots[i]>=0;
            }
            seed=NULL;seed_length=0;
            if(valid&&yx_rule_expressions_wasm(trees,roots,rule_count,0,&seed,&seed_length)) {
                for(unsigned p=0;!found&&p<2;++p) {
                    restored.used=0;
                    found=yx_v12_restore_template(data+start,size,seed,seed_length,p?4:0,&restored);
                }
            }
            if(trees)for(size_t i=0;i<rule_count;++i)yx_integer_expr_destroy(&trees[i]);
            free(seed);free(trees);free(roots);free(rules);
        }
    }
restored_ready:
    if(!found){free(restored.data);return false;}
    yx_reader r={data,length,12,false,false};uint64_t n;
    bool ok=true;
    for(unsigned pool=0;ok&&pool<2;++pool) {
        ok=yx_get_uint(&r,&n);
        for(uint64_t i=0;ok&&i<n;++i)ok=yx_skip_bincode_bytes(&r);
    }
    uint8_t flag;
    ok=ok&&yx_get_u8(&r,&flag)&&yx_get_uint(&r,&n);
    for(uint64_t i=0;ok&&i<n;++i)ok=yx_skip_bincode_bytes(&r);
    ok=ok&&yx_put_bytes(&archive,data,r.at)&&yx_put_uint(&archive,restored.used)&&
        yx_put_bytes(&archive,restored.data,restored.used)&&
        yx_put_bytes(&archive,data+start+size,length-start-size);
    free(restored.data);
    if(!ok){free(archive.data);return false;}
    *normalized=archive.data;*normalized_length=archive.used;return true;
}
