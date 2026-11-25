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

/* External values and prior-rule references share a typed module program.
 * Chunking and function ordering follow the ordinary rule-expression codec. */
#define YX_GLOBAL_RULE_REFERENCE 63

/* The module registry adapter is defined after its schema merger. */
static bool yx_global_rules_schema_build(yx_archive_globals_schema *out, const YRX_RULES *rules, uint8_t profile);

typedef struct {
    const YRX_RULE *rules;
    size_t count, current;
    /* Optional: the first rule of each (namespace, identifier), as index + 1
     * in an open-addressed table of name_mask + 1 slots (NULL: search the
     * rules one by one). */
    size_t *names, name_mask;
} yx_global_rules_context;

static size_t yx_global_rule_hash(size_t namespace_index, const unsigned char *name, size_t length)
{
    uint64_t hash = UINT64_C(1469598103934665603) ^ (uint64_t)namespace_index;
    for (size_t i = 0; i < length; ++i) hash = (hash ^ name[i]) * UINT64_C(1099511628211);
    return (size_t)(hash ^ (hash >> 29));
}
static void yx_global_rules_index_free(yx_global_rules_context *c)
{
    free(c->names);
    c->names = NULL;
    c->name_mask = 0;
}
/* Builds the name table of c->rules; without memory the search stays linear. */
static void yx_global_rules_index(yx_global_rules_context *c)
{
    size_t slots = 16;
    c->names = NULL;
    c->name_mask = 0;
    for (size_t i = 0; i < c->count; ++i)
        if (!c->rules[i].identifier) return;
    while (slots < c->count * 2 && slots <= SIZE_MAX / 4) slots *= 2;
    if (slots > SIZE_MAX / sizeof(*c->names)) return;
    c->names = calloc(slots, sizeof(*c->names));
    if (!c->names) return;
    c->name_mask = slots - 1;
    for (size_t i = 0; i < c->count; ++i) {
        const char *name = c->rules[i].identifier;
        size_t length = strlen(name), slot = yx_global_rule_hash(c->rules[i].namespace_index, (const unsigned char *)name, length) & c->name_mask;
        for (; c->names[slot]; slot = (slot + 1) & c->name_mask) {
            const YRX_RULE *seen = &c->rules[c->names[slot] - 1];
            if (seen->namespace_index == c->rules[i].namespace_index && strcmp(seen->identifier, name) == 0) break;
        }
        if (!c->names[slot]) c->names[slot] = i + 1;
    }
}

static int yx_global_rule_primary(yx_module_program *p, unsigned depth)
{
    yx_global_rules_context *c = p->extension;
    const unsigned char *save = p->parser.at, *name;
    size_t length;
    (void)depth;
    if (!yx_with_identifier(&p->parser, &name, &length)) return -1;
    /* A `with` or loop variable hides a rule of the same name. */
    for (size_t i = p->binding_count; i > 0; --i)
        if (p->bindings[i - 1].length == length && !memcmp(p->bindings[i - 1].name, name, length)) {
            p->parser.at = save;
            return -1;
        }
    /* The first rule of that namespace and name, when it precedes this one. */
    if (c->names && c->current < c->count) {
        size_t space = c->rules[c->current].namespace_index;
        size_t slot = yx_global_rule_hash(space, name, length) & c->name_mask;
        for (; c->names[slot]; slot = (slot + 1) & c->name_mask) {
            size_t i = c->names[slot] - 1;
            if (c->rules[i].namespace_index != space || strlen(c->rules[i].identifier) != length || memcmp(name, c->rules[i].identifier, length)) continue;
            if (i >= c->current) break;
            int n = yx_module_node_new(p, YX_GLOBAL_RULE_REFERENCE, 1);
            if (n >= 0) p->nodes[n].integer = (int64_t)i;
            return n;
        }
        p->parser.at = save;
        return -1;
    }
    for (size_t i = 0; i < c->current; ++i)
        if (c->current < c->count && c->rules[i].namespace_index == c->rules[c->current].namespace_index && strlen(c->rules[i].identifier) == length &&
            !memcmp(name, c->rules[i].identifier, length)) {
            int n = yx_module_node_new(p, YX_GLOBAL_RULE_REFERENCE, 1);
            if (n >= 0) p->nodes[n].integer = (int64_t)i;
            return n;
        }
    p->parser.at = save;
    return -1;
}
static bool yx_global_rule_emit(yx_module_program *p, int index, yx_writer *out, unsigned depth)
{
    const yx_module_node *n = &p->nodes[index];
    (void)depth;
    if (n->op != YX_GLOBAL_RULE_REFERENCE || n->integer < 0) return false;
    p->memory = true;
    uint64_t rule = (uint64_t)n->integer;
    return yx_put_u8(out, 0x41) && yx_put_sleb_i64(out, (int64_t)(rule / 8)) && yx_put_u8(out, 0x2d) && yx_put_u8(out, 0) && yx_put_uleb(out, 17664) &&
           yx_put_u8(out, 0x41) && yx_put_sleb_i64(out, INT64_C(1) << (rule % 8)) && yx_put_u8(out, 0x71) && yx_put_u8(out, 0x41) &&
           yx_put_u8(out, (uint8_t)(rule % 8)) && yx_put_u8(out, 0x76);
}
static bool yx_global_rule_print(const yx_module_program *p, int index, yx_writer *out, unsigned depth)
{
    const yx_module_node *n = &p->nodes[index];
    const yx_global_rules_context *c = p->extension;
    (void)depth;
    if (n->op != YX_GLOBAL_RULE_REFERENCE || n->integer < 0 || (uint64_t)n->integer >= c->current) return false;
    const char *name = c->rules[n->integer].identifier;
    return yx_put_bytes(out, name, strlen(name));
}
static int yx_global_rule_decode(yx_reader *r, size_t end, yx_module_program *p, unsigned depth)
{
    yx_global_rules_context *c = p->extension;
    yx_reader saved = *r;
    uint64_t offset;
    int64_t byte, mask, shift;
    (void)depth;
    if (!yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &byte) || byte < 0 || !yx_rule_expression_byte(r, 0x2d) || !yx_rule_expression_byte(r, 0) ||
        !yx_get_uleb(r, &offset) || offset != 17664 || !yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &mask) || !yx_rule_expression_byte(r, 0x71) ||
        !yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &shift) || shift < 0 || shift > 7 || mask != (INT64_C(1) << shift) ||
        !yx_rule_expression_byte(r, 0x76) || r->at > end || (uint64_t)byte > UINT64_MAX / 8 || (uint64_t)byte * 8 + (uint64_t)shift >= c->current) {
        *r = saved;
        return -1;
    }
    int n = yx_module_node_new(p, YX_GLOBAL_RULE_REFERENCE, 1);
    if (n >= 0) p->nodes[n].integer = byte * 8 + shift;
    return n;
}
static void yx_global_rules_setup(yx_module_program *p, yx_global_rules_context *context)
{
    p->extension = context;
    p->parse_primary = yx_global_rule_primary;
    p->emit_primary = yx_global_rule_emit;
    p->print_primary = yx_global_rule_print;
    p->decode_primary = yx_global_rule_decode;
}
static int yx_global_rules_join(yx_module_program *p, const int *roots, size_t count)
{
    if (count == 1) return roots[0];
    size_t middle = count / 2;
    int left = yx_global_rules_join(p, roots, middle);
    int right = yx_global_rules_join(p, roots + middle, count - middle);
    if (left < 0 || right < 0) return -1;
    int node = yx_module_node_new(p, YX_ME_AND, 1);
    if (node >= 0) {
        p->nodes[node].args[0] = left;
        p->nodes[node].args[1] = right;
    }
    return node;
}
static bool yx_global_rules_emit_one(yx_module_program *p, int root, size_t rule, size_t match, yx_writer *expression)
{
    static const uint8_t suffix[] = {0x0b, 0x45, 4, 0x40, 5, 0x41};
    p->undefined_slot = -1;
    return yx_put_u8(expression, 2) && yx_put_u8(expression, 0x7f) && yx_module_root_boolean(p, root, expression) && yx_put_bytes(expression, suffix, sizeof(suffix)) &&
           yx_put_sleb_i64(expression, (int64_t)rule) && yx_put_u8(expression, 0x10) && yx_put_uleb(expression, p->imports[match].id) && yx_put_u8(expression, 0x0b);
}
static bool yx_global_rules_wasm(yx_module_program *p, const int *roots, size_t count, uint8_t **data, size_t *length)
{
    uint8_t *initial = NULL;
    size_t initial_length = 0;
    yx_writer wasm = {0}, functions = {0}, exports = {0}, code = {0};
    yx_writer *bodies = NULL;
    yx_wasm_function *order = NULL;
    size_t *indices = NULL, *firsts = NULL, *lasts = NULL;
    uint64_t *sizes = NULL;
    size_t chunks = 0, total = 0, capacity = count + 2;
    size_t original_count = p ? p->count : 0;
    bool ok = false;
    if (!p || !roots || !count || count > SIZE_MAX - 2 || capacity > SIZE_MAX / sizeof(*bodies) || capacity > SIZE_MAX / sizeof(*order) ||
        capacity > SIZE_MAX / sizeof(*indices))
        goto done;
    bodies = calloc(capacity, sizeof(*bodies));
    order = malloc(capacity * sizeof(*order));
    indices = malloc(capacity * sizeof(*indices));
    sizes = calloc(count, sizeof(*sizes));
    firsts = calloc(count, sizeof(*firsts));
    lasts = calloc(count, sizeof(*lasts));
    if (!bodies || !order || !indices || !sizes || !firsts || !lasts) goto done;
    if (!yx_module_nodes_reserve(p, count)) goto done;
    int joined = yx_global_rules_join(p, roots, count);
    if (joined < 0) goto done;
    p->shifts = true;
    if (!yx_module_wasm(p, joined, &initial, &initial_length)) goto done;
    yx_reader header = {initial, initial_length, 8, false, false};
    for (unsigned i = 0; i < 2; ++i) {
        uint8_t section;
        uint64_t width;
        if (!yx_get_u8(&header, &section) || section != i + 1 || !yx_get_uleb(&header, &width) || width > header.length - header.at) goto done;
        header.at += (size_t)width;
    }
    if (!yx_put_bytes(&wasm, initial, header.at)) goto done;
    int match = -1;
    for (size_t i = 0; i < p->import_count; ++i)
        if (!strcmp(p->imports[i].name, "rule_match@rule_id:i@")) match = (int)i;
    if (match < 0) goto done;
    for (size_t i = 0; i < count; ++i) {
        yx_writer expression = {0};
        p->filesize = p->divisor = p->two_locals = p->shift = false;
        p->call_count = 0;
        bool measured = yx_global_rules_emit_one(p, roots[i], i, (size_t)match, &expression) && yx_rule_expression_rule_size(&expression, SIZE_MAX, &sizes[i]);
        free(expression.data);
        if (!measured) goto done;
    }
    for (size_t first = 0; first < count;) {
        size_t last = yx_rule_expression_chunk_end(sizes, first, count);
        if (last == first) goto done;
        firsts[chunks] = first;
        lasts[chunks++] = last;
        first = last;
    }
    total = chunks + 2;
    for (size_t chunk = 0; chunk < chunks; ++chunk) {
        yx_writer expression = {0};
        size_t first = firsts[chunk], last = lasts[chunk];
        p->filesize = p->divisor = p->two_locals = p->shift = false;
        p->call_count = 0;
        p->undefined_slot = -1;
        for (size_t i = first; i < last; ++i) {
            if (!yx_global_rules_emit_one(p, roots[i], i, (size_t)match, &expression)) {
                free(expression.data);
                goto done;
            }
        }
        for (size_t i = 0; i < p->call_count; ++i) {
            size_t at = p->calls[i];
            if (at >= expression.used || expression.data[at] >= p->import_count) {
                free(expression.data);
                goto done;
            }
            expression.data[at] = p->imports[expression.data[at]].id;
        }
        yx_writer *body = &bodies[chunk];
        bool locals = p->filesize || p->divisor || p->two_locals;
        bool emitted = true;
        /* A shift wrote i64_tmp_b as local 1: it is the function's only
         * local unless something uses i64_tmp_a (yx_module_wasm). */
        if (p->shift) {
            if (locals) p->two_locals = true;
            else emitted = yx_module_shift_wide_locals(expression.data, expression.used, -1);
            locals = true;
        }
        emitted = emitted && yx_put_u8(body, locals ? 1 : 0) && (!locals || (yx_put_u8(body, p->two_locals ? 2 : 1) && yx_put_u8(body, 0x7e))) &&
                  yx_put_bytes(body, expression.data, expression.used) && yx_put_u8(body, 0x41) && yx_put_u8(body, 0) && yx_put_u8(body, 0x0b);
        free(expression.data);
        if (!emitted || !yx_rule_expression_instructions(body, &order[chunk].instructions)) goto done;
        order[chunk].created = chunk;
    }
    order[chunks] = (yx_wasm_function){chunks, 1 + 2 * chunks};
    order[chunks + 1] = (yx_wasm_function){chunks + 1, 2};
    qsort(order, total, sizeof(*order), yx_compare_wasm_functions);
    for (size_t i = 0; i < total; ++i) indices[order[i].created] = p->import_count + i;
    yx_writer *wrapper = &bodies[chunks], *main = &bodies[chunks + 1];
    if (!yx_put_u8(wrapper, 0) || !yx_put_u8(wrapper, 2) || !yx_put_u8(wrapper, 0x40)) goto done;
    for (size_t i = 0; i < chunks; ++i)
        if (!yx_put_u8(wrapper, 0x10) || !yx_put_uleb(wrapper, indices[i]) || !yx_put_u8(wrapper, 0x0d) || !yx_put_u8(wrapper, 0)) goto done;
    if (!yx_put_u8(wrapper, 0x0b) || !yx_put_u8(wrapper, 0x0b) || !yx_put_u8(main, 0) || !yx_put_u8(main, 0x10) || !yx_put_uleb(main, indices[chunks]) ||
        !yx_put_u8(main, 0x41) || !yx_put_u8(main, 0) || !yx_put_u8(main, 0x0b) || !yx_put_uleb(&functions, total) || !yx_put_uleb(&code, total) ||
        !yx_put_u8(&exports, 1) || !yx_module_wasm_string(&exports, "main") || !yx_put_u8(&exports, 0) || !yx_put_uleb(&exports, indices[chunks + 1]))
        goto done;
    for (size_t i = 0; i < total; ++i) {
        size_t created = order[i].created;
        if (!yx_put_u8(&functions, created == chunks ? 0 : 1) || !yx_put_uleb(&code, bodies[created].used) ||
            !yx_put_bytes(&code, bodies[created].data, bodies[created].used))
            goto done;
    }
    if (!yx_append_wasm_section(&wasm, 3, &functions) || !yx_append_wasm_section(&wasm, 7, &exports) || !yx_append_wasm_section(&wasm, 10, &code)) goto done;
    *data = wasm.data;
    *length = wasm.used;
    wasm.data = NULL;
    ok = true;
done:
    if (p) p->count = original_count;
    if (bodies)
        for (size_t i = 0; i < capacity; ++i) free(bodies[i].data);
    free(bodies);
    free(order);
    free(indices);
    free(sizes);
    free(firsts);
    free(lasts);
    free(initial);
    free(wasm.data);
    free(functions.data);
    free(exports.data);
    free(code.data);
    return ok;
}

static yx_ser_result yx_encode_global_rules_profile(const YRX_RULES *rules, uint8_t profile, uint8_t **data, size_t *length)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    if (!rules || rules->rule_count < 2 || rules->rule_count > SIZE_MAX / sizeof(size_t) || rules->rule_count > SIZE_MAX / sizeof(int) || !rules->rules ||
        (!rules->global_count && !rules->import_count) || rules->import_count > 32 || (rules->import_count && !rules->imports) || profile > 3)
        return YX_SER_UNSUPPORTED;
    for (size_t i = 0; i < rules->import_count; ++i) {
        if (rules->import_rule_indices && rules->import_rule_indices[i]) return YX_SER_UNSUPPORTED;
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(rules->imports[i], rules->imports[j])) return YX_SER_UNSUPPORTED;
    }
    for (size_t i = 0; i < rules->rule_count; ++i)
        if (rules->rules[i].namespace_index || (rules->rules[i].namespace_name && strcmp(rules->rules[i].namespace_name, "default")) || rules->rules[i].pattern_count ||
            rules->rules[i].is_global || rules->rules[i].tag_count || rules->rules[i].metadata_count || !rules->rules[i].condition_text ||
            !yx_valid_rule_name(rules->rules[i].identifier))
            return YX_SER_UNSUPPORTED;
    yx_archive_globals_schema dynamic = {0};
    yx_module_program *p = calloc(1, sizeof(*p));
    yx_writer out = {0};
    uint8_t *wasm = NULL;
    size_t wasm_length = 0;
    const char **pool = NULL;
    size_t count = 0, capacity = 0, ignored = 0;
    size_t *namespaces = NULL, *names = NULL;
    size_t modules[32];
    int *roots = NULL;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    if (!p) return YX_SER_NO_MEMORY;
    namespaces = malloc(rules->rule_count * sizeof(*namespaces));
    names = malloc(rules->rule_count * sizeof(*names));
    roots = malloc(rules->rule_count * sizeof(*roots));
    if (!namespaces || !names || !roots) goto memory;
    if (!yx_global_rules_schema_build(&dynamic, rules, profile)) goto done;
    p->schema = &dynamic.schema;
    p->profile = profile;
    p->capi_import_order = !rules->archive_cli && profile == 0;
    yx_global_rules_context context = {rules->rules, rules->rule_count, 0};
    yx_global_rules_setup(p, &context);
    if (!yx_intern_ident("default", &pool, &count, &capacity, &ignored)) goto memory;
    for (size_t i = 0; i < rules->import_count; ++i)
        if (!yx_intern_ident(rules->imports[i], &pool, &count, &capacity, &modules[i])) goto memory;
    for (size_t i = 0; i < rules->rule_count; ++i) {
        context.current = i;
        p->parser.at = (const unsigned char *)rules->rules[i].condition_text;
        roots[i] = yx_module_parse(p, 1, 0);
        yx_bool_skip_space(&p->parser);
        if (roots[i] < 0 || *p->parser.at || p->failed) goto done;
        if (!yx_intern_ident(rules->rules[i].namespace_name ? rules->rules[i].namespace_name : "default", &pool, &count, &capacity, &namespaces[i]) ||
            !yx_intern_ident(rules->rules[i].identifier, &pool, &count, &capacity, &names[i]))
            goto memory;
    }
    if (!yx_global_rules_wasm(p, roots, rules->rule_count, &wasm, &wasm_length)) goto done;
    if (!yx_put_bytes(&out, magic, sizeof(magic)) || !yx_put_uint(&out, count)) goto memory;
    for (size_t i = 0; i < count; ++i)
        if (!yx_put_string(&out, pool[i])) goto memory;
    if (!yx_put_uint(&out, 0) || !yx_put_uint(&out, 0) || !yx_put_uint(&out, p->literal_count)) goto memory;
    for (size_t i = 0; i < p->literal_count; ++i)
        if (!yx_put_uint(&out, p->literals[i].length) || !yx_put_bytes(&out, p->literals[i].data, p->literals[i].length)) goto memory;
    if (!yx_put_uint(&out, wasm_length) || !yx_put_bytes(&out, wasm, wasm_length) || !yx_put_uint(&out, 0) || !yx_put_uint(&out, rules->import_count)) goto memory;
    for (size_t i = 0; i < rules->import_count; ++i)
        if (!yx_put_uint(&out, modules[i])) goto memory;
    if (!yx_put_uint(&out, rules->rule_count)) goto memory;
    for (size_t i = 0; i < rules->rule_count; ++i) {
        if (!yx_put_uint(&out, namespaces[i] ? 2 : 0) || !yx_put_uint(&out, namespaces[i]) || !yx_put_uint(&out, names[i])) goto memory;
        for (unsigned j = 0; j < 5; ++j)
            if (!yx_put_u8(&out, 0)) goto memory;
        if (!yx_put_u8(&out, rules->rules[i].is_private ? 1 : 0)) goto memory;
    }
    for (unsigned j = 0; j < 7; ++j)
        if (!yx_put_u8(&out, 0)) goto memory;
    uint8_t ac[YX_AC_LENGTH];
    yx_make_empty_ac(ac);
    if (!yx_put_uint(&out, dynamic.globals.used) || !yx_put_bytes(&out, dynamic.globals.data, dynamic.globals.used) || !yx_put_uint(&out, sizeof(ac)) ||
        !yx_put_bytes(&out, ac, sizeof(ac)) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0))
        goto memory;
    *data = out.data;
    *length = out.used;
    out.data = NULL;
    result = YX_SER_SUCCESS;
    goto done;
memory:
    result = YX_SER_NO_MEMORY;
done:
    free(namespaces);
    free(names);
    free(roots);
    free(out.data);
    free(wasm);
    free(pool);
    yx_module_program_free(p);
    yx_archive_globals_schema_free(&dynamic);
    return result;
}

static yx_ser_result yx_decode_global_rules(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    yx_reader r = {data, length, 0, false, false};
    char **pool = NULL;
    size_t pool_count = 0, count = 0;
    YRX_RULE *source_rules = NULL;
    YRX_RULES source = {0};
    char *module_names[32];
    size_t module_count = 0;
    yx_module_program *p = NULL;
    yx_ser_rule *decoded = NULL;
    yx_archive_globals_schema dynamic = {0};
    yx_global *globals = NULL;
    size_t global_count = 0;
    uint8_t *canonical = NULL;
    size_t canonical_length = 0;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    uint64_t n, size;
    const uint8_t *wasm;
    size_t wasm_length;
    int *roots = NULL;
    if (length < sizeof(magic) || memcmp(data, magic, sizeof(magic))) return result;
    r.at = sizeof(magic);
    if (!yx_get_uint(&r, &n) || !n || n > SIZE_MAX / sizeof(*pool) || n > length - r.at) goto done;
    pool_count = (size_t)n;
    pool = calloc(pool_count, sizeof(*pool));
    p = calloc(1, sizeof(*p));
    if (!pool || !p) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < pool_count; ++i)
        if (!yx_get_string(&r, &pool[i])) goto done;
    if (!yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || n > length - r.at) goto done;
    p->literal_count = (size_t)n;
    p->literals = calloc(n ? (size_t)n : 1, sizeof(*p->literals));
    if (!p->literals) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < p->literal_count; ++i) {
        if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
        p->literals[i] = (yx_literal){data + r.at, (size_t)size};
        r.at += (size_t)size;
    }
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    wasm = data + r.at;
    wasm_length = (size_t)size;
    r.at += (size_t)size;
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &n) || n > 32) goto done;
    module_count = (size_t)n;
    for (size_t i = 0; i < module_count; ++i) {
        if (!yx_get_uint(&r, &n) || n >= pool_count || !yx_archive_schema(pool[n])) goto done;
        module_names[i] = pool[n];
    }
    if (!yx_get_uint(&r, &n) || n < 2 || n > (length - r.at) / 8 || n > SIZE_MAX / sizeof(*source_rules) || n > SIZE_MAX / sizeof(*roots)) goto done;
    count = (size_t)n;
    source_rules = calloc(count, sizeof(*source_rules));
    roots = malloc(count * sizeof(*roots));
    if (!source_rules || !roots) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < count; ++i) roots[i] = -1;
    for (size_t i = 0; i < count; ++i) {
        uint64_t variant, ns, name;
        uint8_t flags;
        if (!yx_get_uint(&r, &variant) || !yx_get_uint(&r, &ns) || ns >= pool_count || (variant != 0 && variant != 2) || (variant == 0 && ns) ||
            !yx_get_uint(&r, &name) || name >= pool_count)
            goto done;
        for (unsigned j = 0; j < 5; ++j)
            if (!yx_expect_uint(&r, 0)) goto done;
        if (!yx_get_u8(&r, &flags) || flags > 1) goto done;
        source_rules[i].identifier = pool[name];
        source_rules[i].namespace_name = pool[ns];
        source_rules[i].is_private = flags != 0;
    }
    for (unsigned j = 0; j < 7; ++j)
        if (!yx_expect_uint(&r, 0)) goto done;
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    yx_reader gr = {data + r.at, (size_t)size, 0, false, false};
    if (!yx_get_uint(&gr, &n) || !n || n < module_count || n > UINT16_MAX || n > gr.length - gr.at) goto done;
    global_count = (size_t)n - module_count;
    globals = calloc(global_count ? global_count : 1, sizeof(*globals));
    if (!globals) {
        global_count = 0;
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < global_count; ++i) {
        yx_global_scalar_value value = {0};
        if (!yx_get_string(&gr, &globals[i].name) || !yx_expect_uint(&gr, 0)) goto done;
        bool ok = yx_archive_global_read_value(&gr, &globals[i].type, &value, 0);
        memcpy(&globals[i].value, &value, sizeof(value));
        if (!ok) goto done;
    }
    if (!module_count && (!yx_expect_uint(&gr, 0) || !yx_expect_uint(&gr, 1) || !yx_expect_uint(&gr, 0) || gr.at != gr.length)) goto done;
    source.rules = source_rules;
    source.rule_count = count;
    source.globals = globals;
    source.global_count = global_count;
    source.imports = module_names;
    source.import_count = module_count;
    if (!yx_global_rules_schema_build(&dynamic, &source, 0)) goto done;
    p->schema = &dynamic.schema;
    if (!yx_rule_expression_function_total(wasm, wasm_length, count / 10 + (count % 10 != 0) + 2, count + 2, &p->expected_functions)) goto done;
    yx_global_rules_context context = {source_rules, count, count};
    yx_global_rules_setup(p, &context);
    yx_reader wr = {wasm, wasm_length, 0, false, false};
    size_t first_end;
    if (!yx_module_decode_header(&wr, p, &first_end)) goto done;
    wr.at = 8;
    while (wr.at < wr.length) {
        uint8_t section;
        uint64_t width;
        if (!yx_get_u8(&wr, &section) || !yx_get_uleb(&wr, &width) || width > wr.length - wr.at) goto done;
        if (section == 10) break;
        wr.at += (size_t)width;
    }
    uint64_t functions;
    if (!yx_get_uleb(&wr, &functions) || functions != p->expected_functions) goto done;
    size_t match = SIZE_MAX;
    for (size_t i = 0; i < p->import_count; ++i)
        if (!strcmp(p->imports[i].name, "rule_match@rule_id:i@")) match = i;
    if (match == SIZE_MAX) goto done;
    for (uint64_t function = 0; function < functions; ++function) {
        uint64_t width, groups, locals;
        uint8_t type;
        if (!yx_get_uleb(&wr, &width) || width > wr.length - wr.at) goto done;
        size_t end = wr.at + (size_t)width;
        if (!yx_get_uleb(&wr, &groups) || groups > 1 || (groups && (!yx_get_uleb(&wr, &locals) || locals != 1 || !yx_get_u8(&wr, &type) || type != 0x7e))) goto done;
        while (end - wr.at >= 2 && wr.data[wr.at] == 2 && wr.data[wr.at + 1] == 0x7f) {
            wr.at += 2;
            p->undefined_slot = -1;
            memset(p->slot_types, 0, sizeof(p->slot_types));
            memset((void *)p->slot_fields, 0, sizeof(p->slot_fields));
            size_t node_start = p->count;
            int root = yx_module_decode_block(&wr, end, p, 0);
            static const uint8_t suffix[] = {0x45, 4, 0x40, 5, 0x41};
            int64_t rule;
            uint64_t call;
            if (root < 0 || !yx_integer_wasm_bytes(&wr, end, suffix, sizeof(suffix)) || !yx_get_sleb_i64(&wr, &rule) || rule < 0 || (uint64_t)rule >= count ||
                roots[rule] >= 0 || !yx_rule_expression_byte(&wr, 0x10) || !yx_get_uleb(&wr, &call) || call != match || !yx_rule_expression_byte(&wr, 0x0b))
                goto done;
            for (size_t j = node_start; j < p->count; ++j)
                if (p->nodes[j].op == YX_GLOBAL_RULE_REFERENCE && p->nodes[j].integer >= rule) goto done;
            roots[rule] = root;
        }
        wr.at = end;
    }
    for (size_t i = 0; i < count; ++i) {
        yx_writer text = {0};
        context.current = i;
        if (roots[i] < 0 || !yx_module_print(p, roots[i], &text, 0) || !yx_put_u8(&text, 0)) {
            free(text.data);
            goto done;
        }
        source_rules[i].condition_text = (char *)text.data;
    }
    bool exact = false;
    uint8_t profile = 0;
    for (unsigned frontend = 0; frontend < 2 && !exact; ++frontend) {
        source.archive_cli = frontend != 0;
        for (profile = 0; profile < 4; ++profile) {
            free(canonical);
            canonical = NULL;
            if (yx_encode_global_rules_profile(&source, profile, &canonical, &canonical_length) == YX_SER_SUCCESS && canonical_length <= length &&
                !memcmp(canonical, data, canonical_length)) {
                exact = true;
                break;
            }
        }
    }
    if (!exact) goto done;
    decoded = calloc(count, sizeof(*decoded));
    if (!decoded) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < count; ++i) {
        decoded[i].identifier = malloc(strlen(source_rules[i].identifier) + 1);
        decoded[i].namespace_name = malloc(strlen(source_rules[i].namespace_name) + 1);
        if (!decoded[i].identifier || !decoded[i].namespace_name) {
            result = YX_SER_NO_MEMORY;
            goto done;
        }
        strcpy(decoded[i].identifier, source_rules[i].identifier);
        strcpy(decoded[i].namespace_name, source_rules[i].namespace_name);
        decoded[i].is_private = source_rules[i].is_private;
        decoded[i].runtime_integer_condition = source_rules[i].condition_text;
        source_rules[i].condition_text = NULL;
        decoded[i].runtime_integer_import_profile = profile;
        decoded[i].preserve_serialized_prefix = true;
    }
    if (module_count) {
        decoded[0].runtime_module_names = calloc(module_count, sizeof(*decoded[0].runtime_module_names));
        if (!decoded[0].runtime_module_names) {
            result = YX_SER_NO_MEMORY;
            goto done;
        }
        decoded[0].runtime_module_count = module_count;
        for (size_t i = 0; i < module_count; ++i) {
            decoded[0].runtime_module_names[i] = malloc(strlen(module_names[i]) + 1);
            if (!decoded[0].runtime_module_names[i]) {
                result = YX_SER_NO_MEMORY;
                goto done;
            }
            strcpy(decoded[0].runtime_module_names[i], module_names[i]);
        }
    }
    decoded[0].runtime_globals = globals;
    decoded[0].runtime_global_count = global_count;
    globals = NULL;
    global_count = 0;
    *rules = decoded;
    *rule_count = count;
    decoded = NULL;
    result = YX_SER_SUCCESS;
done:
    if (source_rules)
        for (size_t i = 0; i < count; ++i) free(source_rules[i].condition_text);
    free(source_rules);
    free(roots);
    if (pool)
        for (size_t i = 0; i < pool_count; ++i) free(pool[i]);
    free(pool);
    free(canonical);
    yx_ser_rules_destroy(decoded, count);
    yx_module_program_free(p);
    yx_archive_globals_destroy(globals, global_count);
    yx_archive_globals_schema_free(&dynamic);
    return result;
}
