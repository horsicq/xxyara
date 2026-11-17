/* Resolve immutable AST names once per condition evaluation. Synthetic alias
 * nodes deliberately miss this table and retain the ordinary name lookup. */
typedef enum {
    YX_CALL_OTHER, YX_CALL_MATH, YX_CALL_HASH, YX_CALL_STRING, YX_CALL_TIME
} yx_call_family;

typedef enum {
    YX_MATH_OTHER, YX_MATH_ENTROPY, YX_MATH_COUNT, YX_MATH_PERCENTAGE,
    YX_MATH_TO_STRING, YX_MATH_TO_NUMBER, YX_MATH_SERIAL_CORRELATION,
    YX_MATH_MONTE_CARLO_PI, YX_MATH_MODE, YX_MATH_MEAN, YX_MATH_DEVIATION,
    YX_MATH_IN_RANGE, YX_MATH_ABS, YX_MATH_MIN, YX_MATH_MAX
} yx_math_function;

typedef struct yx_resolved_name {
    const yx_node *node;
    size_t pattern_index;
    size_t cache_index;
    yx_call_family family;
    yx_math_function math;
} yx_resolved_name;

static yx_math_function yx_resolve_math_function(const char *name)
{
    static const char *const names[] = {
        "", "entropy", "count", "percentage", "to_string", "to_number",
        "serial_correlation", "monte_carlo_pi", "mode", "mean", "deviation",
        "in_range", "abs", "min", "max"
    };
    if (!name || strncmp(name, "math.", 5)) return YX_MATH_OTHER;
    for (size_t i = 1; i < sizeof(names) / sizeof(names[0]); ++i)
        if (!strcmp(name + 5, names[i])) return (yx_math_function)i;
    return YX_MATH_OTHER;
}

static size_t yx_resolve_function_cache(const char *name)
{
    static const char *const names[YX_MO_FUNCTION_CACHE_COUNT] = {
        "pe.imphash", "pe.calculate_checksum", "macho.dylib_hash",
        "macho.entitlement_hash", "macho.export_hash", "macho.import_hash",
        "macho.symhash", "elf.import_md5", "elf.telfhash"
    };
    if (name)
        for (size_t i = 0; i < YX_MO_FUNCTION_CACHE_COUNT; ++i)
            if (!strcmp(name, names[i])) return i;
    return YX_MO_FUNCTION_CACHE_COUNT;
}

static size_t yx_name_slot(const yx_node *node, size_t capacity)
{
    return (size_t)(((uintptr_t)node >> 4) * UINT64_C(0x9e3779b97f4a7c15)) &
           (capacity - 1);
}

static const yx_resolved_name *yx_eval_resolved_name(const yx_eval_context *ctx,
                                                     const yx_node *node)
{
    const yx_eval_string_arena *arena = ctx->string_arena;
    const yx_resolved_name *names;
    size_t slot;
    if (!arena || !arena->resolved_names || !arena->resolved_name_capacity || !node)
        return NULL;
    names = arena->resolved_names;
    slot = yx_name_slot(node, arena->resolved_name_capacity);
    while (names[slot].node) {
        if (names[slot].node == node) return &names[slot];
        slot = (slot + 1) & (arena->resolved_name_capacity - 1);
    }
    return NULL;
}

typedef struct {
    const char *name;
    size_t index;
} yx_pattern_name_slot;

static size_t yx_pattern_name_hash(const char *name, size_t capacity)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    return (size_t)hash & (capacity - 1);
}

/* Build once, rather than linearly searching P pattern names for each of N
 * AST references. Canonicalization and first-duplicate wins match
 * yx_name_matches/yx_find_pattern for explicit names exactly. */
static bool yx_pattern_name_map(const yx_eval_context *ctx,
    yx_pattern_name_slot **out_slots, size_t *out_capacity)
{
    yx_pattern_name_slot *slots;
    size_t capacity = 16;
    *out_slots = NULL;
    *out_capacity = 0;
    if (!ctx->pattern_count) return true;
    if (ctx->pattern_count > SIZE_MAX / 2) return false;
    while (capacity < ctx->pattern_count * 2) {
        if (capacity > SIZE_MAX / 2) return false;
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*slots)) return false;
    if (capacity > ctx->string_arena->pattern_name_capacity) {
        slots = realloc(ctx->string_arena->pattern_name_map, capacity * sizeof(*slots));
        if (!slots) return false;
        ctx->string_arena->pattern_name_map = slots;
        ctx->string_arena->pattern_name_capacity = capacity;
    }
    slots = ctx->string_arena->pattern_name_map;
    memset(slots, 0, capacity * sizeof(*slots));
    for (size_t i = 0; i < ctx->pattern_count; ++i) {
        const char *name = ctx->pattern_names[i];
        size_t slot;
        if (ctx->deadline && ctx->deadline->enabled &&
            yx_scan_deadline_poll(ctx->deadline)) return false;
        if (!name) continue;
        if (name[0] == '$') ++name;
        slot = yx_pattern_name_hash(name, capacity);
        while (slots[slot].name && strcmp(slots[slot].name, name))
            slot = (slot + 1) & (capacity - 1);
        if (!slots[slot].name)
            slots[slot] = (yx_pattern_name_slot){name, i};
    }
    *out_slots = slots;
    *out_capacity = capacity;
    return true;
}

static size_t yx_pattern_name_index(const yx_pattern_name_slot *slots,
    size_t capacity, const char *name)
{
    size_t slot;
    if (!slots) return SIZE_MAX;
    slot = yx_pattern_name_hash(name, capacity);
    while (slots[slot].name) {
        if (!strcmp(slots[slot].name, name)) return slots[slot].index;
        slot = (slot + 1) & (capacity - 1);
    }
    return SIZE_MAX;
}

/* The nodes yx_eval_prepare_names visits: the compile-time list of the kinds
 * it resolves when there is one (yx_condition_record_name_nodes, same order),
 * otherwise every allocated node. */
static const yx_node *yx_name_node_first(const yx_condition *condition, size_t *at)
{
    *at = 0;
    if (!condition->name_nodes_ready) return condition->allocated;
    return condition->name_node_count ? condition->name_nodes[(*at)++] : NULL;
}

static const yx_node *yx_name_node_next(const yx_condition *condition, const yx_node *node,
                                        size_t *at)
{
    if (!condition->name_nodes_ready) return node->next_allocated;
    return *at < condition->name_node_count ? condition->name_nodes[(*at)++] : NULL;
}

static void yx_eval_prepare_names(const yx_condition *condition,
                                   const yx_eval_context *ctx)
{
    size_t count = 0, capacity = 16, at;
    size_t pattern_capacity = 0;
    yx_resolved_name *names;
    yx_pattern_name_slot *patterns = NULL;
    bool need_patterns = false;
    yx_eval_string_arena *arena = ctx->string_arena;
    arena->resolved_name_capacity = 0;
    for (const yx_node *node = yx_name_node_first(condition, &at); node;
         node = yx_name_node_next(condition, node, &at)) {
        if (ctx->deadline && ctx->deadline->enabled &&
            yx_scan_deadline_poll(ctx->deadline)) return;
        if (node->kind == N_CALL || node->kind == N_PATTERN || node->kind == N_COUNT ||
            node->kind == N_OFFSET || node->kind == N_LENGTH) {
            ++count;
            if (node->kind != N_CALL && node->name && node->name[0] &&
                !strchr(node->name, '*')) need_patterns = true;
        }
    }
    if (!count || count > SIZE_MAX / 2) return;
    while (capacity < count * 2) {
        if (capacity > SIZE_MAX / 2) return;
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*names)) return;
    if (capacity > arena->resolved_name_storage_capacity) {
        names = realloc(arena->resolved_names, capacity * sizeof(*names));
        if (!names) return;
        arena->resolved_names = names;
        arena->resolved_name_storage_capacity = capacity;
    }
    names = arena->resolved_names;
    memset(names, 0, capacity * sizeof(*names));
    if (need_patterns && !yx_pattern_name_map(ctx, &patterns, &pattern_capacity))
        return;
    for (const yx_node *node = yx_name_node_first(condition, &at); node;
         node = yx_name_node_next(condition, node, &at)) {
        if (ctx->deadline && ctx->deadline->enabled &&
            yx_scan_deadline_poll(ctx->deadline)) {
            return;
        }
        yx_resolved_name entry = {node, SIZE_MAX, YX_MO_FUNCTION_CACHE_COUNT,
                                  YX_CALL_OTHER, YX_MATH_OTHER};
        size_t slot;
        if (node->kind == N_CALL) {
            entry.cache_index = yx_resolve_function_cache(node->name);
            if (node->name && !strncmp(node->name, "math.", 5)) {
                entry.family = YX_CALL_MATH;
                entry.math = yx_resolve_math_function(node->name);
            } else if (node->name && !strncmp(node->name, "hash.", 5))
                entry.family = YX_CALL_HASH;
            else if (node->name && !strncmp(node->name, "string.", 7))
                entry.family = YX_CALL_STRING;
            else if (node->name && !strcmp(node->name, "time.now"))
                entry.family = YX_CALL_TIME;
        } else if (node->kind == N_PATTERN || node->kind == N_COUNT ||
                   node->kind == N_OFFSET || node->kind == N_LENGTH) {
            if (node->name && node->name[0] && !strchr(node->name, '*'))
                entry.pattern_index = yx_pattern_name_index(patterns, pattern_capacity,
                                                             node->name);
        } else continue;
        slot = yx_name_slot(node, capacity);
        while (names[slot].node) slot = (slot + 1) & (capacity - 1);
        names[slot] = entry;
    }
    arena->resolved_name_capacity = capacity;
}

static size_t yx_eval_pattern_index(const yx_node *node,
    const yx_eval_context *ctx, size_t current_pattern)
{
    const yx_resolved_name *name = yx_eval_resolved_name(ctx, node);
    if (name && node->name && node->name[0] && !strchr(node->name, '*'))
        return name->pattern_index;
    return yx_find_pattern(ctx, node->name, current_pattern);
}
