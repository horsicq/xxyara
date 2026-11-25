/* Decode typed pattern/rule operands before regenerating the complete module.
 * This avoids enumerating combinations of independent rule conditions. The
 * regenerated v12 module must still equal every byte of the input module. */
static bool yx_v12_restore_multi_expressions(const uint8_t *archive, size_t archive_length, const uint8_t *data, size_t length, yx_writer *restored)
{
    const uint8_t *parts[13];
    size_t sizes[13], begin, end, rule_count = 0, physical = 0;
    yx_integer_expr imports = {0};
    yx_multi_pattern_context base = {0}, *contexts = NULL;
    yx_tree_store store = {0};
    yx_tree_list trees = {NULL, &store};
    int *roots = NULL;
    size_t *mapping = NULL;
    uint64_t *limits = NULL;
    uint8_t *seed = NULL;
    size_t seed_length = 0;
    uint64_t n, functions, import_count = 0;
    bool ok = false;
    if (!yx_multi_pattern_metadata_span(archive, archive_length, &begin, &end) || !yx_v12_sections(data, length, parts, sizes) || !parts[2] || !parts[10]) return false;
    yx_reader r = {archive, archive_length, begin, false, false};
    if (!yx_get_uint(&r, &n) || !n || n > (end - r.at) / 9 || n > SIZE_MAX / sizeof(yx_integer_expr)) goto done;
    rule_count = (size_t)n;
    for (size_t i = 0; i < rule_count; ++i) {
        size_t namespace_id, ident_id;
        uint64_t count;
        uint8_t flag;
        if (!yx_multi_pattern_metadata_read(&r, NULL, NULL, &namespace_id, &ident_id) || !yx_get_uint(&r, &count) || count > (end - r.at) / 4) goto done;
        size_t private_count = 0;
        for (uint64_t p = 0; p < count; ++p) {
            if (!yx_get_uint(&r, &n) || (n & 1) || n / 2 >= archive_length) goto done;
            if (n / 2 >= physical) physical = (size_t)(n / 2) + 1;
            if (!yx_get_uint(&r, &n) || !yx_get_uint(&r, &n) || n > 2 || !yx_get_u8(&r, &flag) || flag > 1) goto done;
            private_count += flag;
        }
        if (!yx_expect_uint(&r, private_count) || !yx_expect_uint(&r, 0) || !yx_get_u8(&r, &flag) || flag > 1) goto done;
    }
    if (r.at != end || !physical) goto done;
    r = (yx_reader){parts[2], sizes[2], 0, false, false};
    if (!yx_get_uleb(&r, &import_count) || import_count > YX_PATTERN_EXPRESSION_SYMBOL_COUNT) goto done;
    memset(base.pattern.ids, 255, sizeof(base.pattern.ids));
    imports.match_id = 255;
    for (size_t i = 0; i < (size_t)import_count; ++i) {
        char owner[64], wire[256], expected[256];
        uint8_t kind;
        uint64_t type;
        unsigned symbol;
        if (!yx_v12_read_name(&r, owner, sizeof(owner)) || strcmp(owner, "yara_x::wasm") || !yx_v12_read_name(&r, wire, sizeof(wire)) || !yx_get_u8(&r, &kind) || kind ||
            !yx_get_uleb(&r, &type))
            goto done;
        for (symbol = 0; symbol < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++symbol)
            if (yx_v12_mangle(yx_pattern_expression_symbols[symbol], expected, sizeof(expected)) && !strcmp(expected, wire)) break;
        if (symbol == YX_PATTERN_EXPRESSION_SYMBOL_COUNT || base.pattern.used[symbol]) goto done;
        base.pattern.used[symbol] = true;
        base.pattern.ids[symbol] = (uint8_t)i;
        if (!symbol) imports.match_id = (uint8_t)i;
        if ((symbol >= 8 && symbol < 14) || symbol >= 15) {
            unsigned reader = symbol < 14 ? symbol - 8 : symbol - 9;
            imports.read_ids[reader] = (uint8_t)i;
            imports.read_mask |= (uint16_t)(1u << reader);
        }
    }
    if (r.at != r.length || imports.match_id == 255 || !base.pattern.used[1]) goto done;
    imports.function_count = (uint8_t)import_count;
    imports.filesize_id = 1;
    /* v12 defines the shared memory even when no imported memory appears in
     * this module. Bindings and range loops must be available to the inverse. */
    imports.has_memory = true;
    base.pattern.search_global = 2;
    r = (yx_reader){parts[10], sizes[10], 0, false, false};
    if (!yx_get_uleb(&r, &functions) || functions < 3 || functions > rule_count + 3 || functions > SIZE_MAX / sizeof(*mapping)) goto done;
    mapping = calloc((size_t)functions, sizeof(*mapping));
    contexts = calloc(rule_count, sizeof(*contexts));
    roots = malloc(rule_count * sizeof(*roots));
    limits = calloc(physical, sizeof(*limits));
    if (!mapping || !yx_tree_store_init(&store, rule_count) || !contexts || !roots || !limits) goto done;
    for (size_t i = 0; i < (size_t)functions; ++i) mapping[i] = i;
    for (size_t i = 0; i < rule_count; ++i) roots[i] = -1;
    /* The bitmap helper is independent of rule conditions and has no calls. */
    static const uint8_t helper[] = {1, 1,    0x7f, 0x20, 0, 0x41, 3,    0x76, 0x23, 0,    0x6a, 0x2d, 0,    0,   0x41,
                                     1, 0x20, 0,    0x41, 8, 0x70, 0x22, 1,    0x74, 0x71, 0x20, 1,    0x76, 0x0b};
    size_t bodies_start = r.at;
    for (size_t f = 0; f < (size_t)functions; ++f) {
        if (!yx_get_uleb(&r, &n) || n > r.length - r.at) goto done;
        if (n == sizeof(helper) && !memcmp(r.data + r.at, helper, sizeof(helper))) {
            if (base.pattern.presence) goto done;
            base.pattern.presence = true;
            base.pattern.helper_id = (size_t)import_count + f;
        }
        r.at += (size_t)n;
    }
    if (r.at != r.length) goto done;
    r.at = bodies_start;
    for (size_t f = 0; f < (size_t)functions; ++f) {
        if (!yx_get_uleb(&r, &n) || n > r.length - r.at) goto done;
        const uint8_t *body = r.data + r.at;
        yx_v12_instruction *ins = NULL;
        size_t count = 0, locals = 0, first = 0;
        bool valid = true;
        if (!yx_v12_instructions(body, (size_t)n, &ins, &count, &locals)) goto done;
        for (size_t i = 4; valid && i < count; ++i) {
            if (ins[i].op != 0x10 || ins[i].argument != imports.match_id) continue;
            int64_t id;
            yx_reader immediate = {body, ins[i - 1].end, ins[i - 1].start + 1, false, false};
            if (ins[i - 1].op != 0x41 || ins[i - 2].op != 5 || ins[i - 3].op != 4 || ins[i - 3].argument != 0x40 || ins[i - 3].mate != i + 1 || ins[i - 4].op != 0x45 ||
                !yx_get_sleb_i64(&immediate, &id) || immediate.at != immediate.length || id < 0 || (uint64_t)id >= rule_count || roots[id] >= 0) {
                valid = false;
                break;
            }
            yx_writer expression = {0};
            size_t globals[3] = {0, 1, 2};
            contexts[id] = base;
            contexts[id].rule.rule_count = rule_count;
            contexts[id].rule.current = (size_t)id;
            yx_integer_expr *tree = yx_tree_store_copy(&store, &imports);
            if (!tree) {
                free(ins);
                goto done;
            }
            yx_multi_pattern_setup(tree, &contexts[id]);
            /* Operand decoding only bounds physical ids; it does not access
             * the name/mapping arrays. Avoid a physical-sized allocation for
             * every rule in large archives. The emitter lends its own scratch. */
            contexts[id].pattern.capacity = physical;
            valid = yx_v12_module_expression(body, ins, count, first, i - 4, globals, base.pattern.ids[1], (size_t)import_count, mapping, (size_t)functions, &expression,
                                             false) &&
                    yx_put_u8(&expression, 0x0b);
            if (valid) {
                yx_reader operand = {expression.data, expression.used, 0, false, false};
                roots[id] = yx_integer_wasm_block(&operand, operand.length, tree, 0, -1);
                valid = roots[id] >= 0 && operand.at == operand.length;
            }
            contexts[id].pattern.capacity = 0;
            /* The entry keeps the tree, decoded or not, until the store goes. */
            if (!yx_tree_store_park(&store, (size_t)id)) {
                yx_integer_expr_destroy(tree);
                valid = false;
            }
            free(expression.data);
            first = i + 2;
        }
        free(ins);
        if (!valid) goto done;
        r.at += (size_t)n;
    }
    for (size_t i = 0; i < rule_count; ++i)
        if (roots[i] < 0) goto done;
    for (unsigned profile = 0; !ok && profile < 8; ++profile) {
        yx_writer expected = {0};
        free(seed);
        seed = NULL;
        seed_length = 0;
        for (size_t i = 0; i < rule_count; ++i) contexts[i].pattern.capi_import_order = (profile & 4) != 0;
        ok = yx_multi_pattern_wasm_list(&trees, roots, contexts, rule_count, physical, profile & 3, &seed, &seed_length, limits) &&
             yx_v12_wasm(seed, seed_length, (profile & 4 ? 4 : 0) | 256, &expected) && expected.used == length && !memcmp(expected.data, data, length);
        free(expected.data);
    }
    if (ok) ok = yx_put_bytes(restored, seed, seed_length);
done:
    yx_tree_store_destroy(&store);
    if (contexts)
        for (size_t i = 0; i < rule_count; ++i) yx_pattern_expression_destroy(&contexts[i].pattern);
    free(contexts);
    free(roots);
    free(mapping);
    free(limits);
    free(seed);
    return ok;
}
