/* Recover the codec's pattern expression grammars at the v12 boundary.
 * Every recovered module is checked against the complete lowered template;
 * archive immediates are copied only after instruction and origin checks. */
static bool yx_v12_restore_pattern_expressions(const uint8_t *actual,size_t actual_length,
                                               yx_writer *restored)
{
    static const char *const conditions[]={
        "$a at 0", "$a at 0 and filesize > 2", "filesize > 2 and $a at 0",
        "$a at 0 and uint8(1) == 98", "$a and $a at 0",
        "$a at 0 or filesize > 2", "#a == 1 and $a at 0",
        "$a at 0 and $a at 3", "uint8(0) == 97 and $a",
        "uint16(0) == 25185 and $a", "$a at 0 and uint8(0) == 98",
        "$a in (0..2)"
    };
    for(size_t i=0;i<sizeof(conditions)/sizeof(conditions[0]);++i) {
        yx_integer_expr tree={0};yx_pattern_expression_context context={0};
        uint8_t *seed=NULL;size_t seed_length=0;bool found=false;
        context.name="$a";context.names[0]="$a";context.pattern_count=1;
        yx_pattern_expression_setup(&tree,&context);
        int root=yx_integer_expr_condition(&tree,conditions[i]);
        if(root>=0&&yx_pattern_expression_wasm(&tree,root,&context,0,&seed,&seed_length))
            for(unsigned p=0;!found&&p<4;++p) {
                restored->used=0;
                found=yx_v12_restore_template(actual,actual_length,seed,seed_length,(p&1?4:0)|(p&2?256:0),restored);
            }
        free(seed);yx_integer_expr_destroy(&tree);yx_pattern_expression_destroy(&context);
        if(found)return true;
    }
    return false;
}

/* Pattern sets retain logical duplicates, while their entries refer to
 * deduplicated physical ids. Derive the seed's selection table from the
 * metadata rather than assuming that logical and physical counts agree. */
static bool yx_v12_restore_pattern_sets(const uint8_t *archive,size_t archive_length,
                                        const uint8_t *actual,size_t actual_length,
                                        yx_writer *restored)
{
    size_t begin,end,namespace_id,ident_id;uint64_t n,width;uint8_t flag;
    size_t *mapping=NULL;bool found=false;
    if(!yx_multi_pattern_metadata_span(archive,archive_length,&begin,&end))return false;
    yx_reader r={archive,archive_length,begin,false,false};
    if(!yx_get_uint(&r,&n)||n!=1||
       !yx_multi_pattern_metadata_read(&r,NULL,NULL,&namespace_id,&ident_id)||
       !yx_get_uint(&r,&width)||!width||width>(end-r.at)/4||
       width>SIZE_MAX/sizeof(*mapping))return false;
    size_t count=(size_t)width;
    mapping=calloc(count,sizeof(*mapping));if(!mapping)return false;
    size_t private_count=0;
    for(size_t i=0;i<count;++i) {
        if(!yx_get_uint(&r,&n)||(n&1)||n/2>=count)goto done;
        mapping[i]=(size_t)(n/2);
        if(!yx_get_uint(&r,&n)||!yx_get_uint(&r,&n)||n>2||
           !yx_get_u8(&r,&flag)||flag>1)goto done;
        private_count+=flag;
    }
    if(!yx_expect_uint(&r,private_count)||!yx_expect_uint(&r,0)||
       !yx_get_u8(&r,&flag)||flag>1||r.at!=end)goto done;
    for(unsigned shape=0;!found&&shape<7;++shape)
        for(unsigned profile=0;!found&&profile<4;++profile) {
            uint8_t *seed=NULL;size_t seed_length=0;bool valid;
            if(shape<2)valid=yx_pattern_set_wasm(mapping,count,shape==0,1,profile,&seed,&seed_length);
            else if(shape==2)valid=yx_pattern_set_none_wasm(mapping,count,profile,&seed,&seed_length);
            else if(shape==3)valid=yx_pattern_set_keyword_wasm(mapping,count,false,profile,&seed,&seed_length);
            else if(shape<6)valid=yx_pattern_set_range_wasm(count-1,1,shape==4,profile,&seed,&seed_length);
            /* `for all of ... : ( $ )` has its own loop. */
            else valid=yx_pattern_set_loop_wasm(mapping,count,2,profile,&seed,&seed_length);
            if(valid)for(unsigned p=0;!found&&p<4;++p) {
                restored->used=0;
                found=yx_v12_restore_template(actual,actual_length,seed,seed_length,
                    (p&1?4:0)|(p&2?256:0),restored);
            }
            free(seed);
        }
done:
    free(mapping);return found;
}

/* Consecutive rules with one independent pattern each share five common
 * presence/prior-reference grammars. This bounded enumeration handles their
 * composition without assuming anything about pattern bytes or rule names. */
static bool yx_v12_restore_pattern_rules(const uint8_t *archive,size_t archive_length,
                                         const uint8_t *actual,size_t actual_length,
                                         yx_writer *restored)
{
    size_t begin,end;uint64_t n,width;uint8_t flag;
    if(!yx_multi_pattern_metadata_span(archive,archive_length,&begin,&end))return false;
    yx_reader r={archive,archive_length,begin,false,false};
    if(!yx_get_uint(&r,&n)||n<2||n>YX_MULTI_SINGLE_MAX)return false;
    size_t count=(size_t)n;
    for(size_t i=0;i<count;++i) {
        size_t namespace_id,ident_id;
        if(!yx_multi_pattern_metadata_read(&r,NULL,NULL,&namespace_id,&ident_id)||
           !yx_get_uint(&r,&width)||width!=1)return false;
        for(unsigned j=0;j<3;++j)if(!yx_get_uint(&r,&width))return false;
        if(!yx_get_u8(&r,&flag)||flag>1||!yx_get_uint(&r,&width)||
           !yx_get_uint(&r,&width)||width||!yx_get_u8(&r,&flag)||flag)return false;
    }
    if(r.at!=end)return false;
    /* Independent one-pattern rules share a generated grammar through the
     * ten-rule chunk boundary. Recover it before enumerating prior-rule
     * combinations; the latter deliberately has a much smaller bound. */
    uint8_t *plain=NULL;size_t plain_length=0;bool matched=false;
    if(yx_make_single_rule_set_wasm(count,false,&plain,&plain_length))
        for(unsigned p=0;!matched&&p<4;++p) {
            restored->used=0;
            matched=yx_v12_restore_template(actual,actual_length,plain,plain_length,
                (p&1?4:0)|(p&2?256:0),restored);
        }
    free(plain);
    if(matched)return true;
    if(count>4)return false;
    size_t variants=1;
    for(size_t i=1;i<count;++i)variants*=5;
    for(size_t variant=0;variant<variants;++variant) {
        yx_integer_expr trees[4]={{0}};yx_multi_pattern_context contexts[4]={{0}};
        YRX_RULE rules[4]={{0}};char names[4][16];int roots[4];uint64_t limits[4]={0};
        uint8_t *seed=NULL;size_t seed_length=0,spelling=variant;bool valid=true,found=false;
        for(size_t i=0;i<count;++i) {
            snprintf(names[i],sizeof(names[i]),"rule%zu",i);rules[i].identifier=names[i];
        }
        for(size_t i=0;i<count&&valid;++i) {
            yx_pattern_expression_context *context=&contexts[i].pattern;
            context->name="$a";context->names[0]="$a";context->pattern_count=1;
            context->mapping[0]=i;context->limits[0]=1;
            contexts[i].rule=(yx_rule_expression_context){rules,NULL,count,i,false};
            yx_multi_pattern_setup(&trees[i],&contexts[i]);
            char condition[80];unsigned choice=i?(unsigned)(spelling%5):0;
            if(i)spelling/=5;
            if(!i||!choice)snprintf(condition,sizeof(condition),"$a");
            else if(choice==1)snprintf(condition,sizeof(condition),"$a or %s",names[i-1]);
            else if(choice==2)snprintf(condition,sizeof(condition),"%s and $a",names[i-1]);
            else if(choice==3)snprintf(condition,sizeof(condition),"$a and %s",names[i-1]);
            else snprintf(condition,sizeof(condition),"%s or $a",names[i-1]);
            roots[i]=yx_integer_expr_condition(&trees[i],condition);
            valid=roots[i]>=0&&yx_integer_expr_resources(&trees[i],roots[i],0,0);
        }
        if(valid&&yx_multi_pattern_wasm(trees,roots,contexts,count,count,0,&seed,&seed_length,limits))
            for(unsigned p=0;!found&&p<4;++p) {
                restored->used=0;
                found=yx_v12_restore_template(actual,actual_length,seed,seed_length,(p&1?4:0)|(p&2?256:0),restored);
            }
        free(seed);
        for(size_t i=0;i<count;++i){yx_integer_expr_destroy(&trees[i]);yx_pattern_expression_destroy(&contexts[i].pattern);}
        if(found)return true;
    }
    return false;
}
