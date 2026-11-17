/* A scanner-owned, lazily prepared typed loop program. Include after the scalar evaluator
 * helpers and before yx_eval_for_in. The arena owns the cache, so scans of the
 * same immutable condition never modify a shared node or prepared program. */
enum { YX_LOOP_MAX_DEPTH = 192 };

typedef struct {
    union {
        uint64_t value;
        double floating;
        const yx_node *string_node;
    };
    bool defined;
    bool is_unsigned;
    yx_value_type type;
} yx_loop_value;

typedef enum {
    YX_LOOP_CONST, YX_LOOP_ITER, YX_LOOP_BINDING, YX_LOOP_FILESIZE,
    YX_LOOP_READ_GUARD, YX_LOOP_READ, YX_LOOP_UNARY, YX_LOOP_BINARY,
    YX_LOOP_AND, YX_LOOP_OR, YX_LOOP_BOOL,
    YX_LOOP_PATTERN, YX_LOOP_PATTERN_AT,
    YX_LOOP_CALL_BEGIN, YX_LOOP_ARG1, YX_LOOP_ARG2, YX_LOOP_IN_RANGE,
    YX_LOOP_FLOAT, YX_LOOP_STRING, YX_LOOP_CAST_FLOAT, YX_LOOP_MATH,
    YX_LOOP_COUNT, YX_LOOP_OFFSET, YX_LOOP_LENGTH, YX_LOOP_NESTED,
    YX_LOOP_PATTERN_IN, YX_LOOP_COUNT_IN
} yx_loop_opcode;

typedef struct {
    yx_loop_opcode code;
    yx_token_kind operation;
    const yx_node *node;
    size_t target;
} yx_loop_instruction;

typedef struct yx_loop_program {
    struct yx_loop_program *next;
    struct yx_loop_program *hash_next;
    const yx_node *loop;
    yx_loop_instruction *code;
    size_t count;
    yx_loop_value *values;
    /* Common two-operand predicates bypass the instruction dispatcher. */
    const yx_node *hot_read;
    yx_loop_value hot_constant;
    yx_loop_value hot_upper;
    yx_token_kind hot_operation;
    size_t hot_pattern;
    size_t hot_binding_depth;
    unsigned hot; /* 1 literal, 2 iterator compare, 3 read compare, 4 pattern, 5 in_range */
    unsigned hot_polls;
    bool hot_constant_left;
    bool hot_negated;
    bool hot_outer_binding;
    bool math_safe;
    bool valid;
} yx_loop_program;

typedef struct {
    yx_loop_instruction *code;
    size_t count, capacity, nodes;
    const char *iterator;
    const yx_eval_context *context;
    const yx_binding *bindings;
    bool math_safe;
} yx_loop_builder;

static yx_loop_value yx_loop_integer(uint64_t value, bool is_unsigned)
{
    yx_loop_value result = {value, true, is_unsigned};
    return result;
}

static bool yx_loop_truth(yx_loop_value value)
{
    return value.defined && (value.type == V_FLOAT ? value.floating != 0.0 :
        value.type == V_STRING ? value.string_node->string_length != 0 : value.value != 0);
}

static yx_loop_value yx_loop_float(double number)
{
    yx_loop_value result = {0};
    result.type = V_FLOAT;
    result.defined = true;
    result.floating = number;
    return result;
}

static double yx_loop_double(yx_loop_value value)
{
    return value.type == V_FLOAT ? value.floating : value.is_unsigned ?
        (double)value.value : (double)(int64_t)value.value;
}

/* Keep integer wrap and IEEE floating operations identical to the AST path. */
static yx_loop_value yx_loop_binary(yx_token_kind operation,
                                    yx_loop_value left, yx_loop_value right)
{
    const yx_loop_value undefined = {0, false, false};
    uint64_t a = left.value, b = right.value;
    bool is_unsigned = left.is_unsigned || right.is_unsigned;
    int order;
    if (!left.defined || !right.defined) return undefined;
    if (left.type == V_STRING || right.type == V_STRING) {
        yx_value a, b, result;
        if (left.type != V_STRING || right.type != V_STRING) return undefined;
        a = yx_defined_string(left.string_node->name, left.string_node->string_length);
        b = yx_defined_string(right.string_node->name, right.string_node->string_length);
        result = yx_eval_string_binary(operation, a, b);
        return result.defined ? yx_loop_integer(result.value, false) : undefined;
    }
    if (left.type == V_FLOAT || right.type == V_FLOAT) {
        double x = yx_loop_double(left), y = yx_loop_double(right);
        switch (operation) {
        case TK_PLUS: return yx_loop_float(x + y);
        case TK_MINUS: return yx_loop_float(x - y);
        case TK_STAR: return yx_loop_float(x * y);
        case TK_DIV: return yx_loop_float(x / y);
        case TK_EQ: return yx_loop_integer(x == y, false);
        case TK_NE: return yx_loop_integer(x != y, false);
        case TK_LT: return yx_loop_integer(x < y, false);
        case TK_LE: return yx_loop_integer(x <= y, false);
        case TK_GT: return yx_loop_integer(x > y, false);
        case TK_GE: return yx_loop_integer(x >= y, false);
        default: return undefined;
        }
    }
    if (!left.is_unsigned && (int64_t)a < 0 && right.is_unsigned) order = -1;
    else if (left.is_unsigned && !right.is_unsigned && (int64_t)b < 0) order = 1;
    else if (is_unsigned) order = (a > b) - (a < b);
    else order = ((int64_t)a > (int64_t)b) - ((int64_t)a < (int64_t)b);
    switch (operation) {
    case TK_PLUS: return yx_loop_integer(a + b, is_unsigned);
    case TK_MINUS: return yx_loop_integer(a - b, is_unsigned);
    case TK_STAR: return yx_loop_integer(a * b, is_unsigned);
    case TK_DIV:
        if (!b || (!is_unsigned && a == (uint64_t)INT64_MIN && b == UINT64_MAX))
            return undefined;
        return is_unsigned ? yx_loop_integer(a / b, true) :
            yx_loop_integer((uint64_t)((int64_t)a / (int64_t)b), false);
    case TK_PERCENT:
        if (!b) return undefined;
        if (is_unsigned) return yx_loop_integer(a % b, true);
        if (a == (uint64_t)INT64_MIN && b == UINT64_MAX)
            return yx_loop_integer(0, false);
        return yx_loop_integer((uint64_t)((int64_t)a % (int64_t)b), false);
    case TK_SHL:
        return yx_loop_integer((right.is_unsigned ? b >= 64 : (int64_t)b >= 64) ?
                               0 : a << (b & 63), left.is_unsigned);
    case TK_SHR:
        if (right.is_unsigned ? b >= 64 : (int64_t)b >= 64)
            return yx_loop_integer(0, left.is_unsigned);
        b &= 63;
        if (!b) return yx_loop_integer(a, left.is_unsigned);
        return yx_loop_integer((a >> b) | (!left.is_unsigned && (int64_t)a < 0 ?
                               UINT64_MAX << (64 - b) : 0), left.is_unsigned);
    case TK_AMP: return yx_loop_integer(a & b, is_unsigned);
    case TK_CARET: return yx_loop_integer(a ^ b, is_unsigned);
    case TK_PIPE: return yx_loop_integer(a | b, is_unsigned);
    case TK_EQ: return yx_loop_integer(order == 0, false);
    case TK_NE: return yx_loop_integer(order != 0, false);
    case TK_LT: return yx_loop_integer(order < 0, false);
    case TK_LE: return yx_loop_integer(order <= 0, false);
    case TK_GT: return yx_loop_integer(order > 0, false);
    case TK_GE: return yx_loop_integer(order >= 0, false);
    default: return undefined;
    }
}

static bool yx_loop_emit(yx_loop_builder *builder, yx_loop_opcode code,
                          const yx_node *node)
{
    if (builder->count == builder->capacity) {
        size_t next = builder->capacity ? builder->capacity * 2 : 64;
        yx_loop_instruction *grown;
        if (next < builder->capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(builder->code, next * sizeof(*grown));
        if (!grown) return false;
        builder->code = grown;
        builder->capacity = next;
    }
    builder->code[builder->count++] =
        (yx_loop_instruction){code, node->operation, node, 0};
    return true;
}

static bool yx_loop_compile(yx_loop_builder *builder, const yx_node *node,
                             unsigned depth);

/* The generic evaluator promotes an entire homogeneous arithmetic chain.
 * Detect floats in its operands before emitting any arithmetic. */
static bool yx_loop_has_float(const yx_node *node, unsigned depth)
{
    if (!node || depth >= YX_LOOP_MAX_DEPTH) return false;
    if (node->kind == N_FLOAT || (node->kind == N_READ && node->floating_read)) return true;
    if (node->kind == N_UNARY && (node->operation == TK_PLUS || node->operation == TK_MINUS))
        return yx_loop_has_float(node->a, depth + 1);
    if (node->kind == N_BINARY && (node->operation == TK_PLUS ||
        node->operation == TK_MINUS || node->operation == TK_STAR || node->operation == TK_DIV))
        return yx_loop_has_float(node->a, depth + 1) || yx_loop_has_float(node->b, depth + 1);
    return false;
}

static bool yx_loop_compile_chain(yx_loop_builder *builder, const yx_node *node,
    yx_token_kind operation, bool floating, unsigned depth)
{
    if (depth >= YX_LOOP_MAX_DEPTH) return false;
    if (node->kind == N_BINARY && node->operation == operation) {
        return yx_loop_compile_chain(builder, node->a, operation, floating, depth + 1) &&
            yx_loop_compile(builder, node->b, depth + 1) &&
            (!floating || yx_loop_emit(builder, YX_LOOP_CAST_FLOAT, node)) &&
            yx_loop_emit(builder, YX_LOOP_BINARY, node);
    }
    return yx_loop_compile(builder, node, depth + 1) &&
        (!floating || yx_loop_emit(builder, YX_LOOP_CAST_FLOAT, node));
}

/* Flatten Boolean spines iteratively; chain length is independent of depth. */
static bool yx_loop_compile_boolean(yx_loop_builder *builder, const yx_node *node,
    unsigned depth)
{
    const yx_node **items = NULL;
    size_t used = 0, capacity = 0, first_jump = SIZE_MAX;
    yx_token_kind operation = node->operation;
    bool ok = false;
    capacity = 32;
    items = malloc(capacity * sizeof(*items));
    if (!items) return false;
    items[used++] = node;
    while (used) {
        node = items[--used];
        if (node->kind == N_BINARY && node->operation == operation) {
            if (used + 2 > capacity) {
                size_t next = capacity * 2;
                const yx_node **grown;
                if (next < capacity || next > SIZE_MAX / sizeof(*grown)) goto done;
                grown = realloc(items, next * sizeof(*grown));
                if (!grown) goto done;
                items = grown; capacity = next;
            }
            items[used++] = node->b;
            items[used++] = node->a;
            continue;
        }
        if (!yx_loop_compile(builder, node, depth + 1)) goto done;
        if (used) {
            size_t jump = builder->count;
            if (!yx_loop_emit(builder, operation == TK_AND ? YX_LOOP_AND : YX_LOOP_OR, node)) goto done;
            builder->code[jump].target = first_jump;
            first_jump = jump;
        }
    }
    if (!yx_loop_emit(builder, YX_LOOP_BOOL, node)) goto done;
    while (first_jump != SIZE_MAX) {
        size_t next = builder->code[first_jump].target;
        builder->code[first_jump].target = builder->count;
        first_jump = next;
    }
    ok = true;
done:
    free(items);
    return ok;
}

static bool yx_loop_compile(yx_loop_builder *builder, const yx_node *node,
                             unsigned depth)
{
    size_t jump;
    if (!node || depth >= YX_LOOP_MAX_DEPTH) return false;
    ++builder->nodes;
    switch (node->kind) {
    case N_INTEGER: return yx_loop_emit(builder, YX_LOOP_CONST, node);
    case N_FLOAT: return yx_loop_emit(builder, YX_LOOP_FLOAT, node);
    case N_STRING: return yx_loop_emit(builder, YX_LOOP_STRING, node);
    case N_FOR_IN:
        return node->range_loop && yx_loop_emit(builder, YX_LOOP_NESTED, node);
    case N_FILESIZE: return yx_loop_emit(builder, YX_LOOP_FILESIZE, node);
    case N_RULE:
        if (!node->name) return false;
        if (!strcmp(node->name, builder->iterator))
            return yx_loop_emit(builder, YX_LOOP_ITER, node);
        {
            size_t binding_depth = 0;
            for (const yx_binding *at = builder->bindings; at;
                 at = at->parent, ++binding_depth) {
                if (strcmp(at->name, node->name)) continue;
                if (!at->range_integer) return false;
                jump = builder->count;
                if (!yx_loop_emit(builder, YX_LOOP_BINDING, node)) return false;
                builder->code[jump].target = binding_depth;
                return true;
            }
        }
        return false;
    case N_PATTERN: case N_COUNT: case N_OFFSET: case N_LENGTH: {
        size_t index;
        const yx_eval_match_list *list;
        if (!node->name || !node->name[0] || strchr(node->name, '*') ||
            (node->filter != FILTER_NONE && node->filter != FILTER_AT &&
             node->filter != FILTER_IN)) return false;
        index = yx_eval_pattern_index(node, builder->context, SIZE_MAX);
        list = yx_matches(builder->context, index);
        if (!list || (!list->matches && list->count)) return false;
        if ((node->kind == N_OFFSET || node->kind == N_LENGTH) && node->a &&
            !yx_loop_compile(builder, node->a, depth + 1)) return false;
        if (node->filter != FILTER_NONE &&
            (!yx_loop_compile(builder, node->b, depth + 1) ||
             (node->filter == FILTER_IN && !yx_loop_compile(builder, node->c, depth + 1)))) return false;
        jump = builder->count;
        if (!yx_loop_emit(builder, node->kind == N_OFFSET ? YX_LOOP_OFFSET :
                node->kind == N_LENGTH ? YX_LOOP_LENGTH : node->filter == FILTER_IN ?
                (node->kind == N_COUNT ? YX_LOOP_COUNT_IN : YX_LOOP_PATTERN_IN) :
                node->kind == N_COUNT ? YX_LOOP_COUNT : node->filter == FILTER_AT ? YX_LOOP_PATTERN_AT :
                YX_LOOP_PATTERN, node)) return false;
        builder->code[jump].target = index;
        return true;
    }
    case N_CALL: {
        size_t guards[3], count = node->item_count;
        yx_math_function function = yx_resolve_math_function(node->name);
        if (!builder->math_safe ||
            !((function == YX_MATH_IN_RANGE && count == 3) ||
              ((function == YX_MATH_ABS || function == YX_MATH_TO_NUMBER) && count == 1) ||
              ((function == YX_MATH_MIN || function == YX_MATH_MAX) && count == 2)))
            return false;
        if (!yx_loop_emit(builder, YX_LOOP_CALL_BEGIN, node)) return false;
        for (size_t i = 0; i < count; ++i) {
            if (!yx_loop_compile(builder, node->items[i], depth + 1)) return false;
            guards[i] = builder->count;
            if (!yx_loop_emit(builder, YX_LOOP_ARG1, node)) return false;
            builder->code[guards[i]].operation = (yx_token_kind)i;
        }
        jump = builder->count;
        if (!yx_loop_emit(builder, YX_LOOP_MATH, node)) return false;
        builder->code[jump].target = (size_t)function;
        for (size_t i = 0; i < count; ++i) builder->code[guards[i]].target = builder->count;
        return true;
    }
    case N_READ:
        if (node->width != 1 && node->width != 2 &&
            node->width != 4 && node->width != 8) return false;
        jump = builder->count;
        if (!yx_loop_emit(builder, YX_LOOP_READ_GUARD, node) ||
            !yx_loop_compile(builder, node->a, depth + 1) ||
            !yx_loop_emit(builder, YX_LOOP_READ, node)) return false;
        builder->code[jump].target = builder->count;
        return true;
    case N_UNARY:
        if (node->operation != TK_DEFINED && node->operation != TK_NOT &&
            node->operation != TK_MINUS && node->operation != TK_PLUS &&
            node->operation != TK_TILDE) return false;
        return yx_loop_compile(builder, node->a, depth + 1) &&
               yx_loop_emit(builder, YX_LOOP_UNARY, node);
    case N_BINARY:
        switch (node->operation) {
        case TK_AND: case TK_OR:
            return yx_loop_compile_boolean(builder, node, depth);
        case TK_PLUS: case TK_MINUS: case TK_STAR: case TK_DIV:
        case TK_PERCENT: case TK_SHL: case TK_SHR: case TK_AMP:
        case TK_CARET: case TK_PIPE: case TK_EQ: case TK_NE:
        case TK_CONTAINS: case TK_ICONTAINS: case TK_STARTSWITH: case TK_ISTARTSWITH:
        case TK_ENDSWITH: case TK_IENDSWITH: case TK_IEQUALS:
        case TK_LT: case TK_LE: case TK_GT: case TK_GE:
            if (node->operation == TK_PLUS || node->operation == TK_MINUS ||
                node->operation == TK_STAR)
                return yx_loop_compile_chain(builder, node, node->operation,
                    yx_loop_has_float(node, 0), depth);
            return yx_loop_compile(builder, node->a, depth + 1) &&
                   yx_loop_compile(builder, node->b, depth + 1) &&
                   yx_loop_emit(builder, YX_LOOP_BINARY, node);
        default: return false;
        }
    default: return false;
    }
}

static bool yx_loop_compare_operation(yx_token_kind operation)
{
    return operation == TK_EQ || operation == TK_NE || operation == TK_LT ||
           operation == TK_LE || operation == TK_GT || operation == TK_GE;
}

static bool yx_loop_hot_offset(yx_loop_program *program,
    const yx_node *node, const yx_node *loop, const yx_binding *bindings)
{
    size_t depth = 0;
    if (!node || node->kind != N_RULE || !node->name) return false;
    if (!strcmp(node->name, loop->name)) return true;
    for (const yx_binding *at = bindings; at; at = at->parent, ++depth) {
        if (strcmp(node->name, at->name)) continue;
        if (!at->range_integer) return false;
        program->hot_outer_binding = true;
        program->hot_binding_depth = depth;
        return true;
    }
    return false;
}

static size_t yx_loop_program_slot(const yx_node *loop, size_t capacity)
{
    uint64_t hash = (uint64_t)(uintptr_t)loop >> 4;
    hash ^= hash >> 33;
    hash *= UINT64_C(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    return (size_t)hash & (capacity - 1);
}

static bool yx_loop_program_cache_reserve(yx_eval_string_arena *arena)
{
    size_t capacity = arena->loop_program_bucket_capacity;
    yx_loop_program **buckets;
    if (capacity && arena->loop_program_count < capacity - capacity / 4)
        return true;
    if (capacity > SIZE_MAX / 2) return false;
    capacity = capacity ? capacity * 2 : 16;
    if (capacity > SIZE_MAX / sizeof(*buckets)) return false;
    buckets = calloc(capacity, sizeof(*buckets));
    if (!buckets) return false;
    for (yx_loop_program *program = arena->loop_programs; program; program = program->next) {
        size_t slot = yx_loop_program_slot(program->loop, capacity);
        program->hash_next = buckets[slot];
        buckets[slot] = program;
    }
    free(arena->loop_program_buckets);
    arena->loop_program_buckets = buckets;
    arena->loop_program_bucket_capacity = capacity;
    return true;
}

static const yx_loop_program *yx_loop_program_get(const yx_node *loop,
    const yx_eval_context *ctx, size_t current_pattern, const yx_binding *bindings)
{
    yx_loop_program *program;
    yx_loop_program **buckets;
    yx_loop_builder *builder;
    const yx_node *body = loop->body, *operand, *constant;
    size_t slot;
    (void)current_pattern;
    if (!ctx->string_arena || !loop->range_loop) return NULL;
    buckets = ctx->string_arena->loop_program_buckets;
    slot = buckets ? yx_loop_program_slot(loop,
        ctx->string_arena->loop_program_bucket_capacity) : 0;
    for (program = buckets ? buckets[slot] : NULL; program; program = program->hash_next)
        if (program->loop == loop) {
            if (yx_eval_module_output(ctx, "math.in_range")) return NULL;
            return program->valid ? program : NULL;
        }
    /* Keep lookup chains bounded even when growing the cache runs out of
     * memory. An uncached loop can always use the ordinary evaluator. */
    if (!yx_loop_program_cache_reserve(ctx->string_arena)) return NULL;
    program = calloc(1, sizeof(*program));
    if (!program) return NULL;
    program->loop = loop;
    buckets = ctx->string_arena->loop_program_buckets;
    slot = yx_loop_program_slot(loop, ctx->string_arena->loop_program_bucket_capacity);
    program->hash_next = buckets[slot];
    buckets[slot] = program;
    ++ctx->string_arena->loop_program_count;
    program->next = ctx->string_arena->loop_programs;
    ctx->string_arena->loop_programs = program;
    builder = calloc(1, sizeof(*builder));
    if (!builder) return NULL;
    builder->iterator = loop->name;
    builder->context = ctx;
    builder->bindings = bindings;
    builder->math_safe = strcmp(loop->name, "math") != 0 &&
                         !yx_eval_module_output(ctx, "math.in_range");
    for (const yx_binding *at = bindings; builder->math_safe && at; at = at->parent)
        if (!strcmp(at->name, "math")) builder->math_safe = false;
    for (size_t i = 0; builder->math_safe && ctx->globals && i < ctx->global_count; ++i)
        if (ctx->globals[i].name && !strcmp(ctx->globals[i].name, "math"))
            builder->math_safe = false;
    if (!yx_loop_compile(builder, body, 0)) { free(builder->code); free(builder); return NULL; }
    program->values = calloc(builder->count + 1, sizeof(*program->values));
    if (!program->values) { free(builder->code); free(builder); return NULL; }
    program->math_safe = builder->math_safe;
    program->code = builder->code;
    program->count = builder->count;
    free(builder);
    program->valid = true;
    if (body->kind == N_INTEGER) {
        program->hot = 1;
        program->hot_polls = 1;
        program->hot_constant = yx_loop_integer(body->number, body->is_unsigned);
        return program;
    }
    operand = body;
    if (operand->kind == N_UNARY && operand->operation == TK_NOT) {
        program->hot_negated = true;
        operand = operand->a;
    }
    if (operand->kind == N_PATTERN && operand->filter == FILTER_AT &&
        operand->b && operand->b->kind == N_RULE &&
        !strcmp(operand->b->name, loop->name)) {
        program->hot = 4;
        program->hot_pattern = yx_eval_pattern_index(operand, ctx, SIZE_MAX);
        program->hot_polls = program->hot_negated ? 3 : 2;
        return program;
    }
    if (body->kind == N_CALL && !strcmp(body->name, "math.in_range") &&
        body->item_count == 3 && body->items[0]->kind == N_READ &&
        !body->items[0]->floating_read &&
        body->items[1]->kind == N_INTEGER && body->items[2]->kind == N_INTEGER &&
        yx_loop_hot_offset(program, body->items[0]->a, loop, bindings)) {
        program->hot = 5;
        program->hot_polls = 5;
        program->hot_read = body->items[0];
        program->hot_constant = yx_loop_integer(body->items[1]->number,
                                                body->items[1]->is_unsigned);
        program->hot_upper = yx_loop_integer(body->items[2]->number,
                                             body->items[2]->is_unsigned);
        return program;
    }
    if (body->kind != N_BINARY || !yx_loop_compare_operation(body->operation))
        return program;
    operand = body->a; constant = body->b;
    if (operand->kind == N_INTEGER) {
        operand = body->b; constant = body->a;
        program->hot_constant_left = true;
    }
    if (constant->kind != N_INTEGER) return program;
    program->hot_constant = yx_loop_integer(constant->number, constant->is_unsigned);
    program->hot_operation = body->operation;
    if (operand->kind == N_RULE && !strcmp(operand->name, loop->name)) {
        program->hot = 2;
        program->hot_polls = 5;
    }
    else if (operand->kind == N_READ && !operand->floating_read &&
             yx_loop_hot_offset(program, operand->a, loop, bindings)) {
        program->hot = 3;
        program->hot_polls = 6;
        program->hot_read = operand;
    }
    return program;
}

static void yx_loop_programs_destroy(void *head)
{
    yx_loop_program *program = head;
    while (program) {
        yx_loop_program *next = program->next;
        free(program->values);
        free(program->code);
        free(program);
        program = next;
    }
}

static yx_loop_value yx_loop_read(const yx_node *node,
    const yx_eval_context *ctx, yx_loop_value offset)
{
    const yx_loop_value undefined = {0, false, false};
    uint64_t result;
    unsigned bits = node->width * 8;
    if (ctx->block_mode || !offset.defined || offset.type != V_INTEGER ||
        (int64_t)offset.value < 0 ||
        offset.value > SIZE_MAX || !ctx->data || node->width > ctx->size ||
        (size_t)offset.value > ctx->size - node->width) return undefined;
    result = yx_load_integer_bits(ctx->data + (size_t)offset.value,
                                  node->width, node->big_endian);
    if (node->floating_read) {
        if (node->width == 4) {
            uint32_t raw = (uint32_t)result;
            float number;
            memcpy(&number, &raw, sizeof(number));
            return yx_loop_float(number);
        }
        if (node->width == 8) {
            double number;
            memcpy(&number, &result, sizeof(number));
            return yx_loop_float(number);
        }
        return undefined;
    }
    if (node->signed_read && bits < 64 &&
        (result & (UINT64_C(1) << (bits - 1)))) result |= UINT64_MAX << bits;
    return yx_loop_integer(result, !node->signed_read && node->width == 8);
}

static bool yx_loop_hot_poll(const yx_eval_context *ctx, unsigned count)
{
    if (!ctx->deadline || !ctx->deadline->enabled) return false;
    while (count--)
        if (yx_scan_deadline_poll(ctx->deadline)) return true;
    return false;
}

static bool yx_loop_program_interpret(const yx_loop_program *program,
    const yx_eval_context *ctx, uint64_t iteration, const yx_binding *bindings,
    size_t current_pattern)
{
    yx_loop_value *values = program->values;
    size_t used = 0;
    bool timed = ctx->deadline && ctx->deadline->enabled;
    for (size_t ip = 0; ip < program->count; ++ip) {
        const yx_loop_instruction *instruction = &program->code[ip];
        const yx_node *node = instruction->node;
        yx_loop_value *value;
        /* READ_GUARD owns the read node's poll; READ and BOOL are its
         * continuations. Every actually visited source node still polls. */
        if (timed && instruction->code != YX_LOOP_READ && instruction->code != YX_LOOP_BOOL &&
            instruction->code != YX_LOOP_ARG1 && instruction->code != YX_LOOP_ARG2 &&
            instruction->code != YX_LOOP_IN_RANGE && instruction->code != YX_LOOP_CAST_FLOAT &&
            instruction->code != YX_LOOP_MATH && instruction->code != YX_LOOP_NESTED &&
            yx_scan_deadline_poll(ctx->deadline)) return false;
        switch (instruction->code) {
        case YX_LOOP_CONST:
            values[used++] = yx_loop_integer(node->number, node->is_unsigned);
            break;
        case YX_LOOP_FLOAT:
            values[used++] = yx_loop_float(node->floating);
            break;
        case YX_LOOP_STRING: {
            yx_loop_value string = {0};
            string.defined = node->name != NULL;
            string.type = V_STRING;
            string.string_node = node;
            values[used++] = string;
            break;
        }
        case YX_LOOP_CAST_FLOAT:
            if (values[used - 1].defined) {
                if (values[used - 1].type == V_INTEGER || values[used - 1].type == V_FLOAT)
                    values[used - 1] = yx_loop_float(yx_loop_double(values[used - 1]));
                else values[used - 1] = (yx_loop_value){0};
            }
            break;
        case YX_LOOP_NESTED: {
            yx_binding binding = {program->loop->name, {0}, bindings};
            yx_value result;
            binding.value = yx_defined(iteration);
            binding.range_integer = true;
            result = yx_eval(node, ctx, current_pattern, &binding);
            values[used++] = (yx_loop_value){result.value, result.defined, result.is_unsigned};
            break;
        }
        case YX_LOOP_ITER:
            values[used++] = yx_loop_integer(iteration, false);
            break;
        case YX_LOOP_BINDING: {
            const yx_binding *binding = bindings;
            for (size_t depth = 0; depth < instruction->target; ++depth)
                binding = binding->parent;
            values[used++] = (yx_loop_value){binding->value.value,
                                             binding->value.defined,
                                             binding->value.is_unsigned};
            break;
        }
        case YX_LOOP_FILESIZE:
            values[used++] = (yx_loop_value){(uint64_t)ctx->size,
                                             !ctx->block_mode, false};
            break;
        case YX_LOOP_PATTERN: {
            const yx_eval_match_list *list = yx_matches(ctx, instruction->target);
            values[used++] = yx_loop_integer(list->present, false);
            break;
        }
        case YX_LOOP_OFFSET: case YX_LOOP_LENGTH: {
            const yx_eval_match_list *list = yx_matches(ctx, instruction->target);
            yx_loop_value at = node->a ? values[used - 1] : yx_loop_integer(1, false);
            if (!node->a) ++used;
            if (!at.defined || at.type != V_INTEGER || !at.value || at.value > list->count)
                values[used - 1] = (yx_loop_value){0};
            else values[used - 1] = yx_loop_integer(instruction->code == YX_LOOP_OFFSET ?
                list->matches[at.value - 1].offset : list->matches[at.value - 1].length, false);
            break;
        }
        case YX_LOOP_PATTERN_IN: case YX_LOOP_COUNT_IN: {
            const yx_eval_match_list *list = yx_matches(ctx, instruction->target);
            yx_loop_value low = values[used - 2], high = values[used - 1];
            yx_loop_value result = {0};
            if (low.defined && high.defined) {
                size_t first = list->count, end = list->count;
                if (low.type == V_INTEGER && high.type == V_INTEGER) {
                    yx_value lower = yx_defined_integer(low.value, low.is_unsigned);
                    yx_value upper = yx_defined_integer(high.value, high.is_unsigned);
                    first = yx_match_range_start(list, lower);
                    if (first < list->count && yx_offset_in_range(list->matches[first].offset, FILTER_IN, lower, upper)) {
                        size_t at = first;
                        while (at < end) {
                            size_t middle = at + (end - at) / 2;
                            if (list->matches[middle].offset <= (size_t)high.value) at = middle + 1;
                            else end = middle;
                        }
                    } else end = first;
                }
                result = yx_loop_integer(instruction->code == YX_LOOP_COUNT_IN ?
                    end - first : end > first, false);
            }
            values[used - 2] = result;
            --used;
            break;
        }
        case YX_LOOP_COUNT:
            if (node->filter == FILTER_NONE) {
                values[used++] = yx_loop_integer(yx_matches(ctx, instruction->target)->count, false);
                break;
            }
            /* AT has the same zero/one result as a pattern presence test. */
        case YX_LOOP_PATTERN_AT: {
            yx_loop_value offset = values[used - 1];
            if (offset.defined) {
                const yx_eval_match_list *list = yx_matches(ctx, instruction->target);
                bool present = false;
                if ((offset.is_unsigned || (int64_t)offset.value >= 0) &&
                    offset.value <= SIZE_MAX) {
                    size_t at = yx_match_lower_bound(list->matches, list->count,
                                                     (size_t)offset.value);
                    present = at < list->count &&
                              list->matches[at].offset == (size_t)offset.value;
                }
                values[used - 1] = yx_loop_integer(present, false);
            }
            break;
        }
        case YX_LOOP_CALL_BEGIN: break;
        case YX_LOOP_ARG1: case YX_LOOP_ARG2:
            if (!values[used - 1].defined) {
                used -= (size_t)instruction->operation;
                values[used - 1] = (yx_loop_value){0, false, false};
                ip = instruction->target - 1;
            }
            break;
        case YX_LOOP_MATH: {
            size_t count = node->item_count;
            yx_loop_value *args = &values[used - count];
            yx_loop_value result = {0};
            bool integers = true;
            for (size_t i = 0; i < count; ++i) integers &= args[i].defined && args[i].type == V_INTEGER;
            if (instruction->target == YX_MATH_IN_RANGE && args[0].type == V_FLOAT &&
                args[1].type == V_FLOAT && args[2].type == V_FLOAT)
                result = yx_loop_integer(args[1].floating <= args[0].floating &&
                    args[0].floating <= args[2].floating, false);
            else if (integers) {
                int64_t x = (int64_t)args[0].value;
                switch ((yx_math_function)instruction->target) {
                case YX_MATH_IN_RANGE:
                    result = yx_loop_integer((int64_t)args[1].value <= x && x <= (int64_t)args[2].value, false); break;
                case YX_MATH_ABS:
                    if (x != INT64_MIN) result = yx_loop_integer(x < 0 ? 0 - args[0].value : args[0].value, false); break;
                case YX_MATH_TO_NUMBER: result = yx_loop_integer(x != 0, false); break;
                case YX_MATH_MIN: result = yx_loop_integer(x < (int64_t)args[1].value ? args[0].value : args[1].value, false); break;
                case YX_MATH_MAX: result = yx_loop_integer(x > (int64_t)args[1].value ? args[0].value : args[1].value, false); break;
                default: break;
                }
            }
            values[used - count] = result;
            used -= count - 1;
            break;
        }
        case YX_LOOP_IN_RANGE: {
            yx_loop_value x = values[used - 3], low = values[used - 2], high = values[used - 1];
            values[used - 3] = !high.defined ? (yx_loop_value){0, false, false} :
                yx_loop_integer((int64_t)low.value <= (int64_t)x.value &&
                                (int64_t)x.value <= (int64_t)high.value, false);
            used -= 2;
            break;
        }
        case YX_LOOP_READ_GUARD:
            if (ctx->block_mode) {
                values[used++] = (yx_loop_value){0, false, false};
                ip = instruction->target - 1;
            }
            break;
        case YX_LOOP_READ:
            values[used - 1] = yx_loop_read(node, ctx, values[used - 1]);
            break;
        case YX_LOOP_UNARY:
            value = &values[used - 1];
            if (instruction->operation == TK_DEFINED)
                *value = yx_loop_integer(value->defined, false);
            else if (value->defined) {
                switch (instruction->operation) {
                case TK_NOT: *value = yx_loop_integer(!yx_loop_truth(*value), false); break;
                case TK_MINUS: *value = value->type == V_FLOAT ? yx_loop_float(-value->floating) :
                    value->type == V_INTEGER ? yx_loop_integer(0 - value->value, false) : (yx_loop_value){0}; break;
                case TK_TILDE: if (value->type == V_INTEGER) value->value = ~value->value;
                    else *value = (yx_loop_value){0}; break;
                default: break;
                }
            }
            break;
        case YX_LOOP_BINARY:
            values[used - 2] = yx_loop_binary(instruction->operation,
                                                values[used - 2], values[used - 1]);
            --used;
            break;
        case YX_LOOP_AND: case YX_LOOP_OR:
            if (yx_loop_truth(values[used - 1]) ==
                (instruction->code == YX_LOOP_OR)) {
                values[used - 1] = yx_loop_integer(instruction->code == YX_LOOP_OR, false);
                ip = instruction->target - 1;
            } else --used;
            break;
        case YX_LOOP_BOOL:
            values[used - 1] = yx_loop_integer(yx_loop_truth(values[used - 1]), false);
            break;
        }
    }
    return used == 1 && yx_loop_truth(values[0]);
}

static bool yx_loop_program_truth(const yx_loop_program *program,
    const yx_eval_context *ctx, uint64_t iteration, const yx_binding *bindings,
    size_t current_pattern)
{
    yx_loop_value value;
    if (!program->hot) return yx_loop_program_interpret(program, ctx, iteration, bindings, current_pattern);
    if (yx_loop_hot_poll(ctx, program->hot_polls)) return false;
    if (program->hot == 1) return yx_loop_truth(program->hot_constant);
    if (program->hot == 4) {
        const yx_eval_match_list *list = yx_matches(ctx, program->hot_pattern);
        bool present = false;
        if ((int64_t)iteration >= 0 && iteration <= SIZE_MAX) {
            size_t at = yx_match_lower_bound(list->matches, list->count, (size_t)iteration);
            present = at < list->count && list->matches[at].offset == (size_t)iteration;
        }
        return present != program->hot_negated;
    }
    value = yx_loop_integer(iteration, false);
    if (program->hot_outer_binding) {
        const yx_binding *binding = bindings;
        for (size_t depth = 0; depth < program->hot_binding_depth; ++depth)
            binding = binding->parent;
        value = (yx_loop_value){binding->value.value, binding->value.defined,
                                 binding->value.is_unsigned};
    }
    if (program->hot == 3 || program->hot == 5)
        value = yx_loop_read(program->hot_read, ctx, value);
    if (program->hot == 5)
        return value.defined &&
            (int64_t)program->hot_constant.value <= (int64_t)value.value &&
            (int64_t)value.value <= (int64_t)program->hot_upper.value;
    return yx_loop_truth(program->hot_constant_left ?
        yx_loop_binary(program->hot_operation, program->hot_constant, value) :
        yx_loop_binary(program->hot_operation, value, program->hot_constant));
}

/* Conservative loop-invariant range analysis. It proves only defined numeric
 * values, with no signed overflow or non-finite floating endpoints. A failed
 * proof leaves execution to the typed program. Byte bounds are measured once
 * for small buffers; every read offset must independently be proved in-bounds.
 * Deadline-enabled scans retain the ordinary program and its polling work. */
typedef struct {
    int64_t low, high;
    double f_low, f_high;
    bool valid, floating;
} yx_loop_bounds;

typedef struct yx_loop_bounds_scope {
    const char *name;
    yx_loop_bounds value;
    const struct yx_loop_bounds_scope *parent;
} yx_loop_bounds_scope;

static yx_loop_bounds yx_loop_bounds_integer(int64_t low, int64_t high)
{
    yx_loop_bounds value = {low, high, 0, 0, true, false};
    return value;
}

static yx_loop_bounds yx_loop_bounds_float(double low, double high)
{
    yx_loop_bounds value = {0, 0, low, high, isfinite(low) && isfinite(high), true};
    return value;
}

static yx_loop_bounds yx_loop_bounds_cast(yx_loop_bounds value)
{
    if (value.valid && !value.floating)
        return yx_loop_bounds_float((double)value.low, (double)value.high);
    return value;
}

static bool yx_loop_bounds_truth(yx_loop_bounds value, bool *truth)
{
    if (!value.valid) return false;
    if (value.floating) {
        if (value.f_low == 0 && value.f_high == 0) { *truth = false; return true; }
        if (value.f_low > 0 || value.f_high < 0) { *truth = true; return true; }
    } else {
        if (!value.low && !value.high) { *truth = false; return true; }
        if (value.low > 0 || value.high < 0) { *truth = true; return true; }
    }
    return false;
}

static bool yx_loop_add_checked(int64_t a, int64_t b, int64_t *out)
{
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) return false;
    *out = a + b;
    return true;
}

static bool yx_loop_sub_checked(int64_t a, int64_t b, int64_t *out)
{
    if ((b < 0 && a > INT64_MAX + b) || (b > 0 && a < INT64_MIN + b)) return false;
    *out = a - b;
    return true;
}

static bool yx_loop_mul_checked(int64_t a, int64_t b, int64_t *out)
{
    if (a > 0 ? (b > 0 ? a > INT64_MAX / b : b < INT64_MIN / a) :
        (a < 0 ? (b > 0 ? a < INT64_MIN / b : b < 0 && a < INT64_MAX / b) : false))
        return false;
    *out = a * b;
    return true;
}

static yx_loop_bounds yx_loop_bounds_binary(yx_token_kind operation,
    yx_loop_bounds left, yx_loop_bounds right)
{
    yx_loop_bounds unknown = {0};
    int64_t low, high;
    if (!left.valid || !right.valid) return unknown;
    if (left.floating || right.floating) {
        double a, b, c, d;
        left = yx_loop_bounds_cast(left); right = yx_loop_bounds_cast(right);
        a = left.f_low; b = left.f_high; c = right.f_low; d = right.f_high;
        switch (operation) {
        case TK_PLUS: return yx_loop_bounds_float(a + c, b + d);
        case TK_MINUS: return yx_loop_bounds_float(a - d, b - c);
        case TK_STAR: {
            double products[] = {a*c, a*d, b*c, b*d};
            double lo = products[0], hi = lo;
            for (unsigned i = 0; i < 4; ++i) {
                if (!isfinite(products[i])) return unknown;
                if (products[i] < lo) lo = products[i];
                if (products[i] > hi) hi = products[i];
            }
            return yx_loop_bounds_float(lo, hi);
        }
        case TK_EQ: case TK_NE:
            if (a == b && c == d && a == c) return yx_loop_bounds_integer(operation == TK_EQ, operation == TK_EQ);
            if (b < c || d < a) return yx_loop_bounds_integer(operation == TK_NE, operation == TK_NE);
            return unknown;
        case TK_LT: if (b < c) return yx_loop_bounds_integer(1,1); if (a >= d) return yx_loop_bounds_integer(0,0); break;
        case TK_LE: if (b <= c) return yx_loop_bounds_integer(1,1); if (a > d) return yx_loop_bounds_integer(0,0); break;
        case TK_GT: return yx_loop_bounds_binary(TK_LT, right, left);
        case TK_GE: return yx_loop_bounds_binary(TK_LE, right, left);
        default: break;
        }
        return unknown;
    }
    switch (operation) {
    case TK_PLUS:
        if (yx_loop_add_checked(left.low, right.low, &low) &&
            yx_loop_add_checked(left.high, right.high, &high)) return yx_loop_bounds_integer(low, high);
        break;
    case TK_MINUS:
        if (yx_loop_sub_checked(left.low, right.high, &low) &&
            yx_loop_sub_checked(left.high, right.low, &high)) return yx_loop_bounds_integer(low, high);
        break;
    case TK_STAR: {
        int64_t products[4];
        if (!yx_loop_mul_checked(left.low, right.low, &products[0]) ||
            !yx_loop_mul_checked(left.low, right.high, &products[1]) ||
            !yx_loop_mul_checked(left.high, right.low, &products[2]) ||
            !yx_loop_mul_checked(left.high, right.high, &products[3])) break;
        low = high = products[0];
        for (unsigned i = 1; i < 4; ++i) {
            if (products[i] < low) low = products[i];
            if (products[i] > high) high = products[i];
        }
        return yx_loop_bounds_integer(low, high);
    }
    case TK_PERCENT:
        if (right.low == right.high && right.low > 0) {
            int64_t extent = right.low - 1;
            return yx_loop_bounds_integer(left.low < 0 ? -extent : 0,
                left.high > 0 ? extent : 0);
        }
        break;
    case TK_DIV:
        if (right.low == right.high && right.low > 0)
            return yx_loop_bounds_integer(left.low / right.low, left.high / right.low);
        break;
    case TK_EQ: case TK_NE:
        if (left.low == left.high && right.low == right.high && left.low == right.low)
            return yx_loop_bounds_integer(operation == TK_EQ, operation == TK_EQ);
        if (left.high < right.low || right.high < left.low)
            return yx_loop_bounds_integer(operation == TK_NE, operation == TK_NE);
        break;
    case TK_LT:
        if (left.high < right.low) return yx_loop_bounds_integer(1,1);
        if (left.low >= right.high) return yx_loop_bounds_integer(0,0);
        break;
    case TK_LE:
        if (left.high <= right.low) return yx_loop_bounds_integer(1,1);
        if (left.low > right.high) return yx_loop_bounds_integer(0,0);
        break;
    case TK_GT: return yx_loop_bounds_binary(TK_LT, right, left);
    case TK_GE: return yx_loop_bounds_binary(TK_LE, right, left);
    default: break;
    }
    return unknown;
}

static yx_loop_bounds yx_loop_bounds_node(const yx_node *node,
    const yx_loop_program *program, const yx_eval_context *ctx,
    const yx_binding *bindings, const yx_loop_bounds_scope *scope, unsigned depth);

static yx_loop_bounds yx_loop_bounds_chain(const yx_node *node,
    yx_token_kind operation, bool floating, const yx_loop_program *program,
    const yx_eval_context *ctx, const yx_binding *bindings,
    const yx_loop_bounds_scope *scope, unsigned depth)
{
    yx_loop_bounds value = {0}, right;
    if (depth >= YX_LOOP_MAX_DEPTH) return value;
    if (node->kind == N_BINARY && node->operation == operation) {
        value = yx_loop_bounds_chain(node->a, operation, floating, program, ctx, bindings, scope, depth + 1);
        right = yx_loop_bounds_node(node->b, program, ctx, bindings, scope, depth + 1);
        if (floating) right = yx_loop_bounds_cast(right);
        return yx_loop_bounds_binary(operation, value, right);
    }
    value = yx_loop_bounds_node(node, program, ctx, bindings, scope, depth + 1);
    return floating ? yx_loop_bounds_cast(value) : value;
}

static yx_loop_bounds yx_loop_bounds_node(const yx_node *node,
    const yx_loop_program *program, const yx_eval_context *ctx,
    const yx_binding *bindings, const yx_loop_bounds_scope *scope, unsigned depth)
{
    yx_loop_bounds unknown = {0}, left, right;
    bool truth;
    if (!node || depth >= YX_LOOP_MAX_DEPTH) return unknown;
    switch (node->kind) {
    case N_INTEGER:
        return node->is_unsigned ? unknown : yx_loop_bounds_integer((int64_t)node->number, (int64_t)node->number);
    case N_FLOAT: return yx_loop_bounds_float(node->floating, node->floating);
    case N_FILESIZE:
        return ctx->block_mode || ctx->size > INT64_MAX ? unknown :
            yx_loop_bounds_integer((int64_t)ctx->size, (int64_t)ctx->size);
    case N_RULE:
        for (const yx_loop_bounds_scope *at = scope; at; at = at->parent)
            if (!strcmp(at->name, node->name)) return at->value;
        for (const yx_binding *at = bindings; at; at = at->parent)
            if (!strcmp(at->name, node->name))
                return at->range_integer && at->value.defined && !at->value.is_unsigned ?
                    yx_loop_bounds_integer((int64_t)at->value.value, (int64_t)at->value.value) : unknown;
        return unknown;
    case N_READ:
        left = yx_loop_bounds_node(node->a, program, ctx, bindings, scope, depth + 1);
        if (!left.valid || left.floating || ctx->block_mode || !ctx->data ||
            left.low < 0 || node->width > ctx->size ||
            (uint64_t)left.high > ctx->size - node->width || node->floating_read) return unknown;
        if (node->width == 1 && !node->signed_read && ctx->size <= ((size_t)16 << 20)) {
            yx_eval_string_arena *arena = ctx->string_arena;
            if (!arena->byte_bounds_ready || arena->byte_bounds_data != ctx->data ||
                arena->byte_bounds_size != ctx->size) {
                uint8_t lo = UINT8_MAX, hi = 0;
                for (size_t i = 0; i < ctx->size; ++i) {
                    if (ctx->data[i] < lo) lo = ctx->data[i];
                    if (ctx->data[i] > hi) hi = ctx->data[i];
                }
                arena->byte_minimum = lo; arena->byte_maximum = hi;
                arena->byte_bounds_data = ctx->data;
                arena->byte_bounds_size = ctx->size;
                arena->byte_bounds_ready = true;
            }
            return yx_loop_bounds_integer(arena->byte_minimum, arena->byte_maximum);
        }
        if (node->width == 1 || node->width == 2 || node->width == 4) {
            unsigned bits = node->width * 8;
            return node->signed_read ?
                yx_loop_bounds_integer(-((int64_t)1 << (bits-1)), ((int64_t)1 << (bits-1))-1) :
                yx_loop_bounds_integer(0, ((int64_t)1 << bits)-1);
        }
        return unknown;
    case N_OFFSET: case N_LENGTH: case N_COUNT: {
        const yx_eval_match_list *list;
        if (!node->name || !node->name[0] || strchr(node->name, '*')) return unknown;
        size_t index = yx_eval_pattern_index(node, ctx, SIZE_MAX);
        list = yx_matches(ctx, index);
        if (!list || (!list->matches && list->count)) return unknown;
        if (node->kind == N_COUNT) return node->filter == FILTER_NONE && list->count <= INT64_MAX ?
            yx_loop_bounds_integer((int64_t)list->count, (int64_t)list->count) : unknown;
        left = node->a ? yx_loop_bounds_node(node->a, program, ctx, bindings, scope, depth + 1) : yx_loop_bounds_integer(1,1);
        if (!left.valid || left.floating || left.low != left.high || left.low < 1 || (uint64_t)left.low > list->count) return unknown;
        size_t value = node->kind == N_OFFSET ? list->matches[left.low-1].offset : list->matches[left.low-1].length;
        return value <= INT64_MAX ? yx_loop_bounds_integer((int64_t)value, (int64_t)value) : unknown;
    }
    case N_UNARY:
        left = yx_loop_bounds_node(node->a, program, ctx, bindings, scope, depth + 1);
        if (!left.valid) return unknown;
        if (node->operation == TK_DEFINED) return yx_loop_bounds_integer(1,1);
        if (node->operation == TK_PLUS) return left;
        if (node->operation == TK_NOT && yx_loop_bounds_truth(left, &truth)) return yx_loop_bounds_integer(!truth,!truth);
        if (node->operation == TK_MINUS) {
            if (left.floating) return yx_loop_bounds_float(-left.f_high, -left.f_low);
            if (left.low != INT64_MIN) return yx_loop_bounds_integer(-left.high, -left.low);
        }
        return unknown;
    case N_BINARY:
        if (node->operation == TK_PLUS || node->operation == TK_MINUS || node->operation == TK_STAR)
            return yx_loop_bounds_chain(node, node->operation, yx_loop_has_float(node, 0), program, ctx, bindings, scope, depth + 1);
        left = yx_loop_bounds_node(node->a, program, ctx, bindings, scope, depth + 1);
        if (node->operation == TK_AND || node->operation == TK_OR) {
            if (!yx_loop_bounds_truth(left, &truth)) return unknown;
            if (truth == (node->operation == TK_OR)) return yx_loop_bounds_integer(truth,truth);
            right = yx_loop_bounds_node(node->b, program, ctx, bindings, scope, depth + 1);
            return yx_loop_bounds_truth(right, &truth) ? yx_loop_bounds_integer(truth,truth) : unknown;
        }
        right = yx_loop_bounds_node(node->b, program, ctx, bindings, scope, depth + 1);
        return yx_loop_bounds_binary(node->operation, left, right);
    case N_CALL:
        for (const yx_loop_bounds_scope *at = scope; at; at = at->parent)
            if (!strcmp(at->name, "math")) return unknown;
        if (!program->math_safe || !node->name || node->item_count != 1 || strcmp(node->name, "math.abs")) return unknown;
        left = yx_loop_bounds_node(node->items[0], program, ctx, bindings, scope, depth + 1);
        if (!left.valid || left.floating || left.low == INT64_MIN) return unknown;
        return yx_loop_bounds_integer(left.low <= 0 && left.high >= 0 ? 0 :
            (left.low > 0 ? left.low : -left.high),
            left.low > 0 ? left.high : left.high < 0 ? -left.low :
            (-left.low > left.high ? -left.low : left.high));
    case N_FOR_IN: {
        yx_loop_bounds_scope nested = {node->name, {0}, scope};
        uint64_t total, minimum;
        if (!node->range_loop) return unknown;
        left = yx_loop_bounds_node(node->b, program, ctx, bindings, scope, depth + 1);
        right = yx_loop_bounds_node(node->c, program, ctx, bindings, scope, depth + 1);
        if (!left.valid || !right.valid || left.floating || right.floating ||
            left.low != left.high || right.low != right.high) return unknown;
        if (left.low > right.low) return yx_loop_bounds_integer(0,0);
        total = (uint64_t)right.low - (uint64_t)left.low;
        total = total >= (uint64_t)INT64_MAX ? INT64_MAX : total + 1;
        nested.value = yx_loop_bounds_integer(left.low, right.low);
        switch (node->quantifier) {
        case Q_ANY: minimum = 1; break;
        case Q_ALL: minimum = total; break;
        case Q_NONE: minimum = 0; break;
        case Q_NUMBER: case Q_PERCENT:
            left = yx_loop_bounds_node(node->a, program, ctx, bindings, scope, depth + 1);
            if (!left.valid || left.floating || left.low != left.high || left.low < 0) return unknown;
            minimum = (uint64_t)left.low;
            if (node->quantifier == Q_PERCENT) {
                if (minimum > 100) return yx_loop_bounds_integer(0,0);
                minimum = minimum * (total/100) + (minimum*(total%100)+99)/100;
            }
            break;
        default: return unknown;
        }
        if (minimum > total) return yx_loop_bounds_integer(0,0);
        left = yx_loop_bounds_node(node->body, program, ctx, bindings, &nested, depth + 1);
        if (!yx_loop_bounds_truth(left, &truth)) return unknown;
        truth = truth ? minimum != 0 : minimum == 0;
        return yx_loop_bounds_integer(truth,truth);
    }
    default: return unknown;
    }
}

static bool yx_loop_prove_range(const yx_node *node, const yx_loop_program *program,
    const yx_eval_context *ctx, const yx_binding *bindings,
    uint64_t first, uint64_t total, bool *truth)
{
    yx_loop_bounds_scope scope = {node->name, {0}, NULL};
    yx_loop_bounds value;
    if (!program || total < 1024 || (ctx->deadline && ctx->deadline->enabled) ||
        (int64_t)first > (int64_t)(first + total - 1)) return false;
    scope.value = yx_loop_bounds_integer((int64_t)first, (int64_t)(first + total - 1));
    value = yx_loop_bounds_node(node->body, program, ctx, bindings, &scope, 0);
    return yx_loop_bounds_truth(value, truth);
}
