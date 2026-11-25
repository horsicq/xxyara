/* Literal-set lowering for scalar string disjunctions in archive version 12.
 * The expression codec keeps its semantic kinds and import spelling; the
 * archive boundary supplies the v12 WASM structure and exact wire names. */

#define YX_LITERAL_SET_NODE 64
#define YX_REGEX_VALUE_NODE 65
#define YX_REGEX_MATCH_NODE 66

typedef struct yx_string_set {
    size_t *members, count;
    int lhs;
    uint8_t comparison;
    bool regex;
} yx_string_set;
typedef struct yx_string_sets {
    yx_string_set *sets;
    size_t count, literal_count, regex_count, source_size;
    yx_literal *regexes;
    size_t regex_pool_count, regex_pool_capacity;
} yx_string_sets;

static void yx_string_sets_free(yx_string_sets *sets)
{
    for (size_t i = 0; i < sets->count; ++i) free(sets->sets[i].members);
    free(sets->sets);
    free(sets->regexes);
}

static const char *const yx_string_set_names[] = {"str_eq_many@lhs:s,literal_set:i@b",
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  "str_contains_many@lhs:s,literal_set:i@b",
                                                  "str_icontains_many@lhs:s,literal_set:i@b",
                                                  "str_startswith_many@lhs:s,literal_set:i@b",
                                                  "str_istartswith_many@lhs:s,literal_set:i@b",
                                                  "str_endswith_many@lhs:s,literal_set:i@b",
                                                  "str_iendswith_many@lhs:s,literal_set:i@b",
                                                  "str_iequals_many@lhs:s,literal_set:i@b",
                                                  "str_matches_regex_set@lhs:s,regex_set:i@b"};

/* The typed parser delegates regexp leaves here, keeping regexp delimiters and
 * flags in exactly the spelling stored by upstream's regex string pool. */
static int yx_string_set_regex_primary(yx_module_program *p, unsigned depth)
{
    (void)depth;
    const unsigned char *start = p->parser.at;
    if (*start != '/') return -1;
    const unsigned char *at = start + 1;
    bool escaped = false, in_class = false;
    while (*at) {
        unsigned char c = *at++;
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '[') in_class = true;
        else if (c == ']') in_class = false;
        else if (c == '/' && !in_class) break;
    }
    if (at == start + 1 || at[-1] != '/') {
        p->parser.at = at;
        return -1;
    }
    while (*at == 'i' || *at == 's') ++at;
    int node = yx_module_node_new(p, YX_REGEX_VALUE_NODE, 5);
    if (node < 0) return -1;
    size_t size = (size_t)(at - start);
    p->nodes[node].bytes = malloc(size);
    if (!p->nodes[node].bytes) {
        p->failed = true;
        yx_walk_no_memory = true;
        return -1;
    }
    memcpy(p->nodes[node].bytes, start, size);
    p->nodes[node].length = size;
    p->parser.at = at;
    return node;
}

static bool yx_literal_set_emit(yx_module_program *p, int index, yx_writer *out, unsigned depth)
{
    const uint8_t args[] = {0x7e, 0x7f};
    const yx_module_node *n = &p->nodes[index];
    if (n->op == YX_REGEX_MATCH_NODE) {
        return yx_module_emit(p, n->args[0], out, depth + 1) && yx_put_u8(out, 0x41) && yx_put_sleb_i64(out, n->integer) &&
               yx_module_call(p, out, "yara_x::wasm", "str_matches@lhs:s,rhs:r@b", args, 2, 0x7f, false);
    }
    return n->op == YX_LITERAL_SET_NODE && n->comparison < sizeof(yx_string_set_names) / sizeof(yx_string_set_names[0]) && yx_string_set_names[n->comparison] &&
           yx_module_emit(p, n->args[0], out, depth + 1) && yx_put_u8(out, 0x41) && yx_put_sleb_i64(out, n->integer) &&
           yx_module_call(p, out, "yara_x::wasm", yx_string_set_names[n->comparison], args, 2, 0x7f, false);
}

static int yx_literal_set_ungroup(const yx_module_program *p, int index)
{
    while (p->nodes[index].op == YX_ME_GROUP) index = p->nodes[index].args[0];
    return index;
}

static bool yx_literal_set_same_lhs(const yx_module_program *p, int a, int b)
{
    a = yx_literal_set_ungroup(p, a);
    b = yx_literal_set_ungroup(p, b);
    const yx_module_node *x = &p->nodes[a], *y = &p->nodes[b];
    if (x->op != y->op || x->type != 4 || y->type != 4) return false;
    if (x->op == YX_ME_STRING) return x->length == y->length && (!x->length || !memcmp(x->bytes, y->bytes, x->length));
    return x->op == YX_ME_LOOKUP && x->field && y->field && !strcmp(x->field->path, y->field->path);
}

static bool yx_literal_set_operands(const yx_module_program *p, int index, int *items, size_t *count, unsigned depth)
{
    if (depth > 128 || *count >= p->count) return false;
    index = yx_literal_set_ungroup(p, index);
    const yx_module_node *n = &p->nodes[index];
    if (n->op == YX_ME_OR) return yx_literal_set_operands(p, n->args[0], items, count, depth + 1) && yx_literal_set_operands(p, n->args[1], items, count, depth + 1);
    items[(*count)++] = index;
    return true;
}

/* Upstream turns a regexp whose HIR is one literal into contains. Cover
 * the unescaped spelling here; complex regexp syntax retains its regex id. */
static bool yx_string_set_literal_regex(yx_module_node *node, uint8_t *comparison)
{
    if (node->op != YX_REGEX_VALUE_NODE || node->length < 2) return true;
    size_t end = node->length;
    bool nocase = false;
    while (end > 1 && (node->bytes[end - 1] == 'i' || node->bytes[end - 1] == 's')) {
        if (node->bytes[end - 1] == 'i') nocase = true;
        --end;
    }
    if (end < 2 || node->bytes[end - 1] != '/') return true;
    for (size_t i = 1; i + 1 < end; ++i)
        if (strchr(".^$[](){}|*+?\\", node->bytes[i])) return true;
    size_t count = end - 2;
    uint8_t *bytes = malloc(count ? count : 1);
    if (!bytes) return false;
    if (count) memcpy(bytes, node->bytes + 1, count);
    free(node->bytes);
    node->bytes = bytes;
    node->length = count;
    node->type = 4;
    node->op = YX_ME_STRING;
    *comparison = nocase ? 7 : 6;
    return true;
}

/* OR operands are grouped in first-occurrence order, then all uncollapsed
 * operands follow. This is upstream collapse_or_operands' ordering. */
static int yx_string_sets_lower(yx_module_program *p, int root, yx_string_sets *sets)
{
    size_t count = 0;
    int *items = malloc(p->count * sizeof(*items)), *final = malloc(p->count * sizeof(*final));
    bool *consumed = calloc(p->count, sizeof(*consumed));
    if (!items || !final || !consumed) {
        free(items);
        free(final);
        free(consumed);
        p->failed = true;
        return -1;
    }
    if (!yx_literal_set_operands(p, root, items, &count, 0) || count < 2) goto fail;
    sets->sets = calloc(count, sizeof(*sets->sets));
    if (!sets->sets) {
        p->failed = true;
        goto fail;
    }
    size_t final_count = 0;
    for (size_t i = 0; i < count; ++i) {
        yx_module_node *n = &p->nodes[items[i]];
        if (n->op != YX_ME_COMPARE || n->comparison > 13 || p->nodes[n->args[0]].type != 4) goto fail;
        int lhs = n->args[0], rhs = n->args[1];
        if (n->comparison == 13 && !yx_string_set_literal_regex(&p->nodes[rhs], &n->comparison)) {
            p->failed = true;
            goto fail;
        }
        /* Equality accepts the constant on either side. */
        if ((n->comparison == 0 || n->comparison == 12) && p->nodes[rhs].op != YX_ME_STRING && p->nodes[lhs].op == YX_ME_STRING) {
            n->args[0] = rhs;
            n->args[1] = lhs;
            lhs = rhs;
            rhs = n->args[1];
        }
        if ((p->nodes[lhs].op != YX_ME_STRING && p->nodes[lhs].op != YX_ME_LOOKUP) || p->nodes[rhs].op != (n->comparison == 13 ? YX_REGEX_VALUE_NODE : YX_ME_STRING))
            goto fail;
        size_t left_size = p->nodes[lhs].op == YX_ME_STRING ? p->nodes[lhs].length : strlen(p->nodes[lhs].field->path);
        size_t right_size = p->nodes[rhs].length;
        if (left_size > (SIZE_MAX - 64) / 4 || right_size > (SIZE_MAX - 64) / 4 || left_size * 4 > SIZE_MAX - 64 - right_size * 4 ||
            sets->source_size > SIZE_MAX - 64 - left_size * 4 - right_size * 4)
            goto fail;
        sets->source_size += left_size * 4 + right_size * 4 + 64;
    }
    for (size_t i = 0; i < count; ++i) {
        if (consumed[i]) continue;
        yx_module_node first = p->nodes[items[i]];
        if (first.comparison > 0 && first.comparison < 6) continue;
        size_t members_count = 0;
        for (size_t j = i; j < count; ++j)
            if (!consumed[j] && p->nodes[items[j]].comparison == first.comparison && yx_literal_set_same_lhs(p, first.args[0], p->nodes[items[j]].args[0]))
                ++members_count;
        if (members_count < 2) continue;
        yx_string_set *set = &sets->sets[sets->count++];
        set->members = calloc(members_count, sizeof(*set->members));
        if (!set->members) {
            p->failed = true;
            goto fail;
        }
        set->lhs = first.args[0];
        set->comparison = first.comparison;
        set->regex = first.comparison == 13;
        for (size_t j = i; j < count; ++j)
            if (!consumed[j] && p->nodes[items[j]].comparison == first.comparison && yx_literal_set_same_lhs(p, first.args[0], p->nodes[items[j]].args[0])) {
                const yx_module_node *value = &p->nodes[p->nodes[items[j]].args[1]];
                size_t member;
                bool interned = set->regex ? yx_intern_literal(value->bytes, value->length, &sets->regexes, &sets->regex_pool_count, &sets->regex_pool_capacity, &member)
                                           : yx_intern_literal(value->bytes, value->length, &p->literals, &p->literal_count, &p->literal_capacity, &member);
                if (!interned) {
                    p->failed = true;
                    goto fail;
                }
                set->members[set->count++] = member;
                consumed[j] = true;
            }
        int node = yx_module_node_new(p, YX_LITERAL_SET_NODE, 1);
        if (node < 0) goto fail;
        p->nodes[node].args[0] = set->lhs;
        p->nodes[node].comparison = set->comparison;
        p->nodes[node].integer = (int64_t)(set->regex ? sets->regex_count++ : sets->literal_count++);
        final[final_count++] = node;
    }
    if (!sets->count) goto fail;
    for (size_t i = 0; i < count; ++i)
        if (!consumed[i]) {
            int index = items[i];
            yx_module_node *n = &p->nodes[index];
            if (n->comparison == 13) {
                const yx_module_node *value = &p->nodes[n->args[1]];
                size_t id;
                if (!yx_intern_literal(value->bytes, value->length, &sets->regexes, &sets->regex_pool_count, &sets->regex_pool_capacity, &id)) {
                    p->failed = true;
                    goto fail;
                }
                n->op = YX_REGEX_MATCH_NODE;
                n->integer = (int64_t)id;
            }
            final[final_count++] = index;
        }
    root = final[0];
    for (size_t i = 1; i < final_count; ++i) {
        int node = yx_module_node_new(p, YX_ME_OR, 1);
        if (node < 0) goto fail;
        p->nodes[node].args[0] = root;
        p->nodes[node].args[1] = final[i];
        root = node;
    }
    free(items);
    free(final);
    free(consumed);
    return root;
fail:
    free(items);
    free(final);
    free(consumed);
    return -1;
}

static bool yx_string_sets_write(yx_writer *out, const yx_string_sets *sets, bool regex)
{
    size_t count = regex ? sets->regex_count : sets->literal_count;
    bool *present = calloc(count ? count : 1, sizeof(*present));
    size_t *order = malloc((count ? count : 1) * sizeof(*order));
    if (!present || !order) {
        free(present);
        free(order);
        return false;
    }
    for (size_t i = 0; i < count; ++i) present[i] = true;
    bool ok = yx_fx_map_order(present, count, order) && yx_put_uint(out, count);
    for (size_t i = 0; ok && i < count; ++i) {
        const yx_string_set *set = NULL;
        size_t index = 0;
        for (size_t j = 0; j < sets->count; ++j)
            if (sets->sets[j].regex == regex && index++ == order[i]) {
                set = &sets->sets[j];
                break;
            }
        ok = set && yx_put_signed(out, (int64_t)order[i]) && yx_put_uint(out, set->count);
        for (size_t j = 0; ok && j < set->count; ++j) ok = regex ? yx_put_signed(out, (int64_t)set->members[j]) : yx_put_uint(out, set->members[j]);
    }
    free(present);
    free(order);
    return ok;
}

static yx_ser_result yx_encode_literal_sets(const YRX_RULES *rules, uint8_t **data, size_t *length)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    static const uint8_t empty_globals[] = {0, 0, 1, 0};
    if (!rules || rules->rule_count != 1 || !rules->rules || rules->import_count > 1) return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule = &rules->rules[0];
    if (rule->pattern_count || rule->is_global || rule->tag_count || rule->metadata_count || !rule->condition_text || !yx_valid_rule_name(rule->identifier))
        return YX_SER_UNSUPPORTED;
    const char *module = rules->import_count && rules->imports ? rules->imports[0] : NULL;
    const yx_archive_module_schema *schema = yx_archive_schema(module);
    if (rules->import_count && !schema) return YX_SER_UNSUPPORTED;
    uint8_t profile = yx_integer_import_profile();
    yx_archive_globals_schema dynamic = {0};
    yx_module_program *p = calloc(1, sizeof(*p));
    yx_writer out = {0};
    uint8_t *wasm = NULL;
    size_t wasm_length = 0;
    const char **pool = NULL;
    yx_string_sets sets = {0};
    size_t count = 0, capacity = 0, ignored = 0, namespace_id = 0, module_id = 0, rule_id = 0;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    if (!p) return YX_SER_NO_MEMORY;
    if (rules->global_count) {
        if (!yx_archive_globals_schema_build(&dynamic, rules, schema, profile)) goto done;
        schema = &dynamic.schema;
    }
    p->schema = schema;
    p->profile = profile;
    p->capi_import_order = !rules->archive_cli && profile == 0;
    p->parse_primary = yx_string_set_regex_primary;
    p->parser.at = (const unsigned char *)rule->condition_text;
    int root = yx_module_parse(p, 1, 0);
    yx_bool_skip_space(&p->parser);
    if (root < 0 || *p->parser.at || p->failed) goto done;
    root = yx_literal_set_ungroup(p, root);
    if (p->nodes[root].op != YX_ME_OR) goto done;
    root = yx_string_sets_lower(p, root, &sets);
    if (root < 0) {
        if (p->failed) result = YX_SER_NO_MEMORY;
        goto done;
    }
    p->emit_primary = yx_literal_set_emit;
    if (!yx_module_wasm(p, root, &wasm, &wasm_length)) goto done;
    const char *namespace_name = rule->namespace_name ? rule->namespace_name : "default";
    if (!yx_intern_ident("default", &pool, &count, &capacity, &ignored) || !yx_intern_ident(namespace_name, &pool, &count, &capacity, &namespace_id) ||
        (module && !yx_intern_ident(module, &pool, &count, &capacity, &module_id)) || !yx_intern_ident(rule->identifier, &pool, &count, &capacity, &rule_id))
        goto memory;
    if (!yx_put_bytes(&out, magic, sizeof(magic)) || !yx_put_uint(&out, count)) goto memory;
    for (size_t i = 0; i < count; ++i)
        if (!yx_put_string(&out, pool[i])) goto memory;
    if (!yx_put_uint(&out, sets.regex_pool_count)) goto memory;
    for (size_t i = 0; i < sets.regex_pool_count; ++i)
        if (!yx_put_uint(&out, sets.regexes[i].length) || !yx_put_bytes(&out, sets.regexes[i].data, sets.regexes[i].length)) goto memory;
    if (!yx_put_u8(&out, 0) || !yx_put_uint(&out, p->literal_count)) goto memory;
    for (size_t i = 0; i < p->literal_count; ++i)
        if (!yx_put_uint(&out, p->literals[i].length) || !yx_put_bytes(&out, p->literals[i].data, p->literals[i].length)) goto memory;
    if (!yx_put_uint(&out, wasm_length) || !yx_put_bytes(&out, wasm, wasm_length) || !yx_put_u8(&out, 0) || !yx_put_uint(&out, module ? 1 : 0) ||
        (module && !yx_put_uint(&out, module_id)) || !yx_put_uint(&out, 1) || !yx_put_uint(&out, namespace_id ? 2 : 0) || !yx_put_uint(&out, namespace_id) ||
        !yx_put_uint(&out, rule_id) || !yx_put_uint(&out, 0) || !yx_put_uint(&out, 0) || !yx_put_uint(&out, 0) || !yx_put_uint(&out, 0) || !yx_put_u8(&out, 0) ||
        !yx_put_u8(&out, rule->is_private ? 1 : 0))
        goto memory;
    for (size_t i = 0; i < 7; ++i)
        if (!yx_put_uint(&out, 0)) goto memory;
    const uint8_t *globals = schema ? schema->globals[profile] : empty_globals;
    size_t globals_length = schema ? schema->globals_length[profile] : sizeof(empty_globals);
    uint8_t ac[YX_AC_LENGTH];
    yx_make_empty_ac(ac);
    if (!yx_put_uint(&out, globals_length) || !yx_put_bytes(&out, globals, globals_length) || !yx_put_uint(&out, sizeof(ac)) || !yx_put_bytes(&out, ac, sizeof(ac)) ||
        !yx_string_sets_write(&out, &sets, true) || !yx_string_sets_write(&out, &sets, false))
        goto memory;
    if (!yx_put_uint(&out, 0) || !yx_put_u8(&out, 0)) goto memory;
    /* Bound semantic source expansion on load by a fixed multiple of wire
     * length. This also prevents a hostile repeated-lhs set from causing
     * quadratic allocation while reconstructing the runtime condition. */
    if (out.used <= SIZE_MAX / 64 && sets.source_size > out.used * 64) goto done;
    *data = out.data;
    *length = out.used;
    out.data = NULL;
    result = YX_SER_SUCCESS;
    goto done;
memory:
    result = YX_SER_NO_MEMORY;
done:
    free(out.data);
    free(wasm);
    free(pool);
    yx_string_sets_free(&sets);
    yx_module_program_free(p);
    yx_archive_globals_schema_free(&dynamic);
    return result;
}

/* Candidate reconstruction is accepted only after re-emission matches every
 * byte, including the module schema, atom image and executable instructions. */
static bool yx_literal_set_string(yx_writer *out, const yx_literal *literal)
{
    yx_module_node node = {0};
    yx_module_program p = {0};
    node.op = YX_ME_STRING;
    node.type = 4;
    node.bytes = (uint8_t *)literal->data;
    node.length = literal->length;
    p.nodes = &node;
    p.count = 1;
    return yx_module_print(&p, 0, out, 0);
}

typedef struct yx_string_set_import {
    uint8_t comparison;
    bool recognized, many, lookup;
} yx_string_set_import;

static bool yx_string_sets_read(yx_reader *r, yx_string_sets *sets, bool regex, size_t pool_count)
{
    uint64_t count, members, member;
    int64_t id;
    if (!yx_get_uint(r, &count) || count > r->length - r->at || count > INT32_MAX || count > SIZE_MAX / sizeof(*sets->sets) - sets->count) return false;
    size_t first = sets->count, n = (size_t)count;
    yx_string_set *grown = realloc(sets->sets, (first + n ? first + n : 1) * sizeof(*grown));
    if (!grown) return false;
    sets->sets = grown;
    memset(grown + first, 0, n * sizeof(*grown));
    sets->count += n;
    if (regex) sets->regex_count = n;
    else sets->literal_count = n;
    for (size_t i = 0; i < n; ++i) {
        if (!yx_get_signed(r, &id) || id < 0 || (uint64_t)id >= count || !yx_get_uint(r, &members) || members < 2 || members > r->length - r->at ||
            members > SIZE_MAX / sizeof(size_t))
            return false;
        yx_string_set *set = &sets->sets[first + (size_t)id];
        if (set->members) return false;
        set->members = malloc((size_t)members * sizeof(*set->members));
        if (!set->members) return false;
        set->count = (size_t)members;
        set->regex = regex;
        for (size_t j = 0; j < set->count; ++j) {
            if (regex) {
                if (!yx_get_signed(r, &id) || id < 0) return false;
                member = (uint64_t)id;
            } else if (!yx_get_uint(r, &member)) return false;
            if (member >= pool_count) return false;
            set->members[j] = (size_t)member;
        }
    }
    return true;
}

static bool yx_string_set_immediate(const uint8_t *body, const yx_v12_instruction *n, int64_t *value)
{
    if (n->op != 0x41 && n->op != 0x42) return false;
    yx_reader r = {body, n->end, n->start + 1, false, false};
    return yx_get_sleb_i64(&r, value) && r.at == r.length;
}

/* Decode the string operand itself: either a tagged LiteralId or a lookup's
 * bounded field-index vector. No candidate-pool search or trial compilation
 * is needed to identify the operand. */
static bool yx_string_set_lhs(yx_writer *source, const uint8_t *body, const yx_v12_instruction *ins, size_t before, const yx_string_set_import *imports,
                              size_t import_count, const yx_literal *literals, size_t literal_count, const yx_archive_module_schema *schema)
{
    int64_t value;
    if (before && ins[before - 1].op == 0x42 && yx_string_set_immediate(body, &ins[before - 1], &value) && value >= 0 && !(value & 3) &&
        (uint64_t)value / 4 < literal_count)
        return yx_literal_set_string(source, &literals[(size_t)value / 4]);
    /* A string lookup has a small undefined guard after its call. */
    size_t lookup = before;
    for (size_t step = 0; lookup && step < 20; ++step) {
        --lookup;
        if (ins[lookup].op == 0x10) break;
    }
    if (lookup >= before || ins[lookup].op != 0x10 || ins[lookup].argument >= import_count || !imports[ins[lookup].argument].lookup || !lookup ||
        !yx_string_set_immediate(body, &ins[lookup - 1], &value) || value < 1 || value > 16 || !schema)
        return false;
    size_t depth = (size_t)value;
    if (lookup < depth * 3 + 2) return false;
    size_t at = lookup - depth * 3 - 2;
    if (ins[at].op != 0x42 || !yx_string_set_immediate(body, &ins[at], &value) || value != -1) return false;
    uint16_t indexes[16];
    for (size_t i = 0; i < depth; ++i) {
        const yx_v12_instruction *offset = &ins[at + 1 + i * 3], *index = &ins[at + 2 + i * 3], *store = &ins[at + 3 + i * 3];
        if (offset->op != 0x41 || !yx_string_set_immediate(body, offset, &value) || value != (int64_t)i * 4 || index->op != 0x41 ||
            !yx_string_set_immediate(body, index, &value) || value < 0 || value > UINT16_MAX || store->op != 0x36)
            return false;
        indexes[i] = (uint16_t)value;
    }
    for (size_t i = 0; i < schema->field_count; ++i) {
        const yx_archive_module_field *field = &schema->fields[i];
        if (field->kind == 4 && field->depth == depth && !memcmp(field->indexes, indexes, depth * sizeof(*indexes)))
            return yx_put_bytes(source, field->path, strlen(field->path));
    }
    return false;
}

static bool yx_string_sets_source(const uint8_t *wasm, size_t length, const yx_literal *literals, size_t literal_count, const yx_literal *regexes, size_t regex_count,
                                  const yx_string_sets *sets, const yx_archive_module_schema *schema, size_t wire_length, yx_writer *source)
{
    const uint8_t *parts[13];
    size_t sizes[13];
    yx_string_set_import imports[YX_MODULE_IMPORTS] = {0};
    if (!yx_v12_sections(wasm, length, parts, sizes) || !parts[2] || !parts[10]) return false;
    yx_reader r = {parts[2], sizes[2], 0, false, false};
    uint64_t import_count, type;
    if (!yx_get_uleb(&r, &import_count) || import_count > YX_MODULE_IMPORTS) return false;
    for (size_t i = 0; i < (size_t)import_count; ++i) {
        char module[128], name[256], mangled[256];
        uint8_t kind;
        if (!yx_v12_read_name(&r, module, sizeof(module)) || !yx_v12_read_name(&r, name, sizeof(name)) || !yx_get_u8(&r, &kind) || kind || !yx_get_uleb(&r, &type))
            return false;
        if (strcmp(module, "yara_x::wasm")) continue;
        imports[i].lookup = !strcmp(name, "lookup_string@structure:i64u,num_lookup_indexes:i32@su");
        for (size_t c = 0; c < 14; ++c)
            if (yx_string_set_names[c] && yx_v12_mangle(yx_string_set_names[c], mangled, sizeof(mangled))) {
                /* Sets use i32 ids, represented explicitly in the measured alias table. */
                const char *alias = NULL;
                for (size_t k = 0; k < sizeof(yx_archive_symbol_aliases) / sizeof(yx_archive_symbol_aliases[0]); ++k)
                    if (!strcmp(yx_archive_symbol_aliases[k].name, yx_string_set_names[c])) {
                        alias = yx_archive_symbol_aliases[k].wire_name;
                        break;
                    }
                if (!strcmp(name, alias ? alias : mangled)) {
                    imports[i].comparison = (uint8_t)c;
                    imports[i].recognized = true;
                    imports[i].many = true;
                }
            }
        for (size_t c = 0; c < 13; ++c)
            if (!strcmp(name, yx_module_comparison_names[c])) {
                imports[i].comparison = (uint8_t)c;
                imports[i].recognized = true;
            }
        if (!strcmp(name, "str_matches@lhs:s,rhs:r@b")) {
            imports[i].comparison = 13;
            imports[i].recognized = true;
        }
    }
    if (r.at != r.length) return false;
    r = (yx_reader){parts[10], sizes[10], 0, false, false};
    uint64_t functions, size;
    size_t leaves = 0;
    if (!yx_get_uleb(&r, &functions) || functions > r.length - r.at) return false;
    for (uint64_t f = 0; f < functions; ++f) {
        if (!yx_get_uleb(&r, &size) || size > r.length - r.at) return false;
        const uint8_t *body = r.data + r.at;
        r.at += (size_t)size;
        yx_v12_instruction *ins = NULL;
        size_t count = 0, locals = 0;
        if (!yx_v12_instructions(body, (size_t)size, &ins, &count, &locals)) return false;
        bool valid = true;
        for (size_t i = 0; valid && i < count; ++i) {
            if (ins[i].op != 0x10 || ins[i].argument >= import_count || !imports[ins[i].argument].recognized) continue;
            const yx_string_set_import *entry = &imports[ins[i].argument];
            int64_t value;
            if (!i || !yx_string_set_immediate(body, &ins[i - 1], &value) || value < 0) {
                valid = false;
                break;
            }
            const size_t *members = NULL;
            size_t one, count_members = 1;
            const yx_literal *pool = entry->comparison == 13 ? regexes : literals;
            size_t pool_count = entry->comparison == 13 ? regex_count : literal_count;
            if (entry->many) {
                size_t n = entry->comparison == 13 ? sets->regex_count : sets->literal_count;
                size_t base = entry->comparison == 13 ? 0 : sets->regex_count;
                if (ins[i - 1].op != 0x41 || (uint64_t)value >= n) {
                    valid = false;
                    break;
                }
                const yx_string_set *set = &sets->sets[base + (size_t)value];
                members = set->members;
                count_members = set->count;
            } else {
                if (entry->comparison != 13) {
                    if (ins[i - 1].op != 0x42 || (value & 3)) {
                        valid = false;
                        break;
                    }
                    value /= 4;
                } else if (ins[i - 1].op != 0x41) {
                    valid = false;
                    break;
                }
                if ((uint64_t)value >= pool_count) {
                    valid = false;
                    break;
                }
                one = (size_t)value;
                members = &one;
            }
            for (size_t m = 0; valid && m < count_members; ++m) {
                if (wire_length <= SIZE_MAX / 64 && source->used > wire_length * 64) {
                    valid = false;
                    break;
                }
                const char *op = entry->comparison == 13 ? " matches " : yx_module_comparison_text[entry->comparison];
                valid = (!leaves || yx_put_bytes(source, " or ", 4)) &&
                        yx_string_set_lhs(source, body, ins, i - 1, imports, (size_t)import_count, literals, literal_count, schema) &&
                        yx_put_bytes(source, op, strlen(op));
                const yx_literal *value_literal = &pool[members[m]];
                valid =
                    valid && (entry->comparison == 13 ? yx_put_bytes(source, value_literal->data, value_literal->length) : yx_literal_set_string(source, value_literal));
                if (wire_length <= SIZE_MAX / 64 && source->used > wire_length * 64) valid = false;
                ++leaves;
            }
        }
        free(ins);
        if (!valid) return false;
    }
    return r.at == r.length && leaves && yx_put_u8(source, 0);
}

static yx_ser_result yx_decode_literal_sets(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    yx_reader r = {data, length, 12, false, false};
    char **pool = NULL;
    size_t pool_count = 0, literal_count = 0, regex_count = 0, global_count = 0;
    yx_literal *literals = NULL, *regexes = NULL;
    yx_global *globals = NULL;
    yx_string_sets sets = {0};
    yx_archive_globals_schema dynamic = {0};
    yx_writer source = {0};
    yx_ser_rule *decoded = NULL;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    uint64_t count, size, imports, module_id = 0, namespace_variant, namespace_id, rule_id;
    uint8_t private_rule;
    const uint8_t *wasm;
    size_t wasm_length;
    const yx_archive_module_schema *module = NULL, *schema = NULL;
    if (length < 12 || memcmp(data, magic, 12)) return YX_SER_UNSUPPORTED;
    if (!yx_get_uint(&r, &count) || count < 1 || count > length - r.at || count > SIZE_MAX / sizeof(*pool)) goto done;
    pool_count = (size_t)count;
    pool = calloc(pool_count, sizeof(*pool));
    if (!pool) goto memory;
    for (size_t i = 0; i < pool_count; ++i)
        if (!yx_get_string(&r, &pool[i])) goto done;
    if (!yx_get_uint(&r, &count) || count > length - r.at || count > SIZE_MAX / sizeof(*regexes)) goto done;
    regex_count = (size_t)count;
    regexes = calloc(regex_count ? regex_count : 1, sizeof(*regexes));
    if (!regexes) goto memory;
    for (size_t i = 0; i < regex_count; ++i) {
        if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
        regexes[i] = (yx_literal){data + r.at, (size_t)size};
        r.at += (size_t)size;
    }
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &count) || count > length - r.at || count > SIZE_MAX / sizeof(*literals)) goto done;
    literal_count = (size_t)count;
    literals = calloc(literal_count ? literal_count : 1, sizeof(*literals));
    if (!literals) goto memory;
    for (size_t i = 0; i < literal_count; ++i) {
        if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
        literals[i] = (yx_literal){data + r.at, (size_t)size};
        r.at += (size_t)size;
    }
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    wasm = data + r.at;
    wasm_length = (size_t)size;
    r.at += (size_t)size;
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &imports) || imports > 1) goto done;
    if (imports && (!yx_get_uint(&r, &module_id) || module_id >= pool_count || !(module = yx_archive_schema(pool[module_id])))) goto done;
    if (!yx_expect_uint(&r, 1) || !yx_get_uint(&r, &namespace_variant) || !yx_get_uint(&r, &namespace_id) || namespace_id >= pool_count || !yx_get_uint(&r, &rule_id) ||
        rule_id >= pool_count || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) ||
        !yx_get_u8(&r, &private_rule) || private_rule > 1 || (namespace_variant != 0 && namespace_variant != 2) || (namespace_variant == 0 && namespace_id))
        goto done;
    for (size_t i = 0; i < 7; ++i)
        if (!yx_expect_uint(&r, 0)) goto done;
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    yx_reader gr = {data + r.at, (size_t)size, 0, false, false};
    r.at += (size_t)size;
    if (!yx_get_uint(&gr, &count) || count < imports || count - imports > UINT16_MAX || count > gr.length - gr.at) goto done;
    global_count = (size_t)(count - imports);
    if (global_count) {
        globals = calloc(global_count, sizeof(*globals));
        if (!globals) {
            global_count = 0;
            goto memory;
        }
        for (size_t i = 0; i < global_count; ++i) {
            yx_global_scalar_value value = {0};
            if (!yx_get_string(&gr, &globals[i].name) || !yx_expect_uint(&gr, 0)) goto done;
            bool valid = yx_archive_global_read_value(&gr, &globals[i].type, &value, 0);
            memcpy(&globals[i].value, &value, sizeof(value));
            if (!valid) goto done;
        }
    }
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    r.at += (size_t)size;
    if (!yx_string_sets_read(&r, &sets, true, regex_count) || !yx_string_sets_read(&r, &sets, false, literal_count) || !sets.count || !yx_expect_uint(&r, 0) ||
        !yx_expect_uint(&r, 0) || r.at != length)
        goto done;
    YRX_RULE candidate = {0};
    YRX_RULES candidate_rules = {0};
    candidate.identifier = pool[rule_id];
    candidate.namespace_name = pool[namespace_id];
    candidate.is_private = private_rule != 0;
    candidate_rules.rules = &candidate;
    candidate_rules.rule_count = 1;
    candidate_rules.import_count = (size_t)imports;
    char *module_name = imports ? pool[module_id] : NULL;
    candidate_rules.imports = &module_name;
    candidate_rules.globals = globals;
    candidate_rules.global_count = global_count;
    schema = module;
    if (global_count) {
        if (!yx_archive_globals_schema_build(&dynamic, &candidate_rules, module, 0)) goto done;
        schema = &dynamic.schema;
    }
    if (!yx_string_sets_source(wasm, wasm_length, literals, literal_count, regexes, regex_count, &sets, schema, length, &source)) goto done;
    candidate.condition_text = (char *)source.data;
    bool matched = false;
    for (unsigned frontend = 0; !matched && frontend < 2; ++frontend) {
        uint8_t *canonical = NULL;
        size_t canonical_length = 0;
        candidate_rules.archive_cli = frontend != 0;
        yx_ser_result encoded = yx_encode_literal_sets(&candidate_rules, &canonical, &canonical_length);
        if (encoded == YX_SER_NO_MEMORY) {
            free(canonical);
            goto memory;
        }
        if (encoded == YX_SER_SUCCESS && yx_v12_archive_wasm(&canonical, &canonical_length, (frontend ? 0 : 4) | 256) && canonical_length == length &&
            !memcmp(canonical, data, length))
            matched = true;
        free(canonical);
    }
    if (!matched) goto done;
    decoded = calloc(1, sizeof(*decoded));
    if (!decoded) goto memory;
    decoded->namespace_name = malloc(strlen(pool[namespace_id]) + 1);
    if (!decoded->namespace_name) goto memory;
    strcpy(decoded->namespace_name, pool[namespace_id]);
    if (module_name) {
        decoded->runtime_module_name = malloc(strlen(module_name) + 1);
        if (!decoded->runtime_module_name) goto memory;
        strcpy(decoded->runtime_module_name, module_name);
    }
    decoded->identifier = pool[rule_id];
    pool[rule_id] = NULL;
    decoded->runtime_integer_condition = (char *)source.data;
    source.data = NULL;
    decoded->runtime_globals = globals;
    decoded->runtime_global_count = global_count;
    globals = NULL;
    global_count = 0;
    decoded->runtime_integer_import_profile = 0;
    decoded->is_private = private_rule != 0;
    decoded->preserve_serialized_prefix = true;
    *rules = decoded;
    *rule_count = 1;
    decoded = NULL;
    result = YX_SER_SUCCESS;
    goto done;
memory:
    result = YX_SER_NO_MEMORY;
done:
    if (decoded) yx_ser_rules_destroy(decoded, 1);
    if (pool)
        for (size_t i = 0; i < pool_count; ++i) free(pool[i]);
    free(pool);
    free(literals);
    free(regexes);
    free(source.data);
    yx_string_sets_free(&sets);
    yx_archive_globals_destroy(globals, global_count);
    yx_archive_globals_schema_free(&dynamic);
    return result;
}
