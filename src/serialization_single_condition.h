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

#ifndef YX_SERIALIZATION_SINGLE_CONDITION_H
#define YX_SERIALIZATION_SINGLE_CONDITION_H
/* Every single physical pattern has the same condition address space. */
static yx_ser_result yx_physical_single_condition_encode(const YRX_RULES *rules,
    uint8_t **data,size_t *length,uint64_t *limit)
{
    const YRX_RULE *r=&rules->rules[0]; const YRX_PATTERN *p=&r->patterns[0];
    yx_integer_expr *tree=calloc(1,sizeof(*tree));
    yx_pattern_expression_context context={0};
    uint8_t *wasm=NULL;size_t wasm_length=0;
    yx_ser_result status=YX_SER_UNSUPPORTED;
    if(!tree)return YX_SER_NO_MEMORY;
    context.name=p->identifier; context.pattern_count=1; context.names[0]=p->identifier;
    yx_pattern_expression_setup(tree,&context);
    int root=yx_integer_expr_condition(tree,r->condition_text);
    if (root>=0) for (size_t i=0;i<tree->count;++i) {
        yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[i];
        if ((node->op==0xa0 || node->op==0xa1) && !node->constant) {
            bool identity=node->op==0xa0;
            int child=YX_INTEGER_NODES(tree)[node->left].constant && !!YX_INTEGER_NODES(tree)[node->left].value==identity ? node->right :
                YX_INTEGER_NODES(tree)[node->right].constant && !!YX_INTEGER_NODES(tree)[node->right].value==identity ? node->left : -1;
            if (child>=0) { node->op=identity?0xd8:0xd9; node->left=node->right=child; }
        }
    }
    if (root<0) {
        /* Set quantifiers share the ordinary literal's condition program. */
        YRX_PATTERN plain=*p; YRX_RULE adapted=*r; YRX_RULES base=*rules;
        uint8_t *archive=NULL; size_t archive_length=0,prefix,start,count;
        plain.modifiers=0; adapted.patterns=&plain; base.rules=&adapted;
        base.serialized_prefix=NULL; base.serialized_prefix_length=0;
        yx_ser_result result=yx_ser_encode(&base,&archive,&archive_length);
        bool valid=result==YX_SER_SUCCESS &&
            yx_rule_expression_wasm_span(archive,archive_length,&prefix,&start,&wasm_length,&count) && count==1;
        if (valid) {
            wasm=malloc(wasm_length);
            if (wasm) memcpy(wasm,archive+start,wasm_length);
            else status=YX_SER_NO_MEMORY;
        }
        free(archive);
        if (!valid || !wasm) goto done;
        context.limits[0]=1;
    } else if (!context.saw_pattern ||
               !yx_pattern_expression_wasm(tree,root,&context,yx_integer_import_profile(),&wasm,&wasm_length)) goto done;
    *data=wasm; *length=wasm_length; *limit=context.limits[0]; wasm=NULL; status=YX_SER_SUCCESS;
done:
    yx_integer_expr_free(tree); free(wasm); return status;
}
static bool yx_physical_single_condition_decode(const yx_physical_archive *a,yx_ser_rule *decoded)
{
    if (!yx_physical_condition(a,&decoded->runtime_integer_condition,
                               &decoded->runtime_integer_import_profile)) {
        /* Decode set programs through the same literal condition reader. The
         * temporary physical pattern changes no condition or pattern IDs. */
        YRX_PATTERN plain={0}; YRX_RULE r={0}; YRX_RULES *loaded=NULL;
        uint8_t *archive=NULL; size_t archive_length=0;
        plain.kind=YX_PATTERN_TEXT; plain.identifier=a->names[a->name_ids[0]];
        plain.bytes=(uint8_t *)"a"; plain.length=1;
        r.identifier=a->names[2]; r.namespace_name=a->names[0]; r.patterns=&plain; r.pattern_count=1;
        bool valid=yx_text_envelope_encode(&r,a->wasm,a->wasm_length,a->limits,false,0,
                                           &archive,&archive_length)==YX_SER_SUCCESS &&
            yx_physical_inspect_load(archive,archive_length,&loaded)==YRX_SUCCESS &&
            loaded && loaded->rule_count==1;
        if (valid) decoded->runtime_integer_condition=yx_copy_string(loaded->rules[0].condition_text);
        free(archive); yrx_rules_destroy(loaded);
        if (!valid || !decoded->runtime_integer_condition) return false;
    }
    return true;
}
#endif
