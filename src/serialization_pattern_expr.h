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

/* Typed pattern leaves composed with the numeric/Boolean archive AST. */
enum {
    YX_PATTERN_EXPRESSION_SYMBOL_COUNT = 25
};
static const char *const yx_pattern_expression_symbols[YX_PATTERN_EXPRESSION_SYMBOL_COUNT] = {
    "rule_match@rule_id:i@",
    "search_for_patterns@@",
    "pat_matches@pattern_id:i@i",
    "pat_offset@pattern_id:i,index:i@iu",
    "pat_length@pattern_id:i,index:i@iu",
    "is_pat_match_at@pattern_id:i,offset:i@b",
    "is_pat_match_in@pattern_id:i,lower_bound:i,upper_bound:i@b",
    "pat_matches_in@pattern_id:i,lower_bound:i,upper_bound:i@i",
    "uint8@offset:i@i:R0:255u",
    "uint16@offset:i@i:R0:65535u",
    "uint32@offset:i@i:R0:4294967295u",
    "int8@offset:i@i:R-128:127u",
    "int16@offset:i@i:R-32768:32767u",
    "int32@offset:i@i:R-2147483648:2147483647u",
    "pat_range_match@pattern_id_start:i,pattern_id_end:i,required:i@b",
    "uint64@offset:i64@u64u",
    "int64@offset:i64@i64u",
    "uint8be@offset:i64@u8u",
    "uint16be@offset:i64@u16u",
    "uint32be@offset:i64@u32u",
    "uint64be@offset:i64@u64u",
    "int8be@offset:i64@i8u",
    "int16be@offset:i64@i16u",
    "int32be@offset:i64@i32u",
    "int64be@offset:i64@i64u",
};
static unsigned yx_pattern_expression_read_symbol(unsigned type)
{
    return type < 6 ? 8 + type : 9 + type;
}
/* Generated profile/C API ranks are shared with the module codec. New
 * reader wire names resolve through the same aliases as the v12 post-pass. */
static uint32_t yx_pattern_expression_rank(unsigned symbol, unsigned profile, bool capi)
{
    const char *name = yx_pattern_expression_symbols[symbol];
    for (size_t i = 0; i < sizeof(yx_archive_symbol_aliases) / sizeof(yx_archive_symbol_aliases[0]); ++i)
        if (!strcmp(yx_archive_symbol_aliases[i].module, "yara_x::wasm") && !strcmp(name, yx_archive_symbol_aliases[i].wire_name)) {
            name = yx_archive_symbol_aliases[i].name;
            break;
        }
    if (capi) {
        for (size_t i = 0; i < sizeof(yx_archive_capi_symbol_orders) / sizeof(yx_archive_capi_symbol_orders[0]); ++i)
            if (!strcmp(yx_archive_capi_symbol_orders[i].module, "yara_x::wasm") && !strcmp(name, yx_archive_capi_symbol_orders[i].name))
                return yx_archive_capi_symbol_orders[i].rank;
    } else if (profile < 4) {
        for (size_t i = 0; i < sizeof(yx_archive_symbol_orders) / sizeof(yx_archive_symbol_orders[0]); ++i)
            if (!strcmp(yx_archive_symbol_orders[i].module, "yara_x::wasm") && !strcmp(name, yx_archive_symbol_orders[i].name))
                return yx_archive_symbol_orders[i].ranks[profile];
    }
    return UINT32_MAX;
}
/* `<quantifier> of <pattern set>`: the set as sorted ranges of pattern ids. */
#define YX_PATTERN_OF_RANGES 8
#define YX_PATTERN_OF_SETS 16
typedef struct yx_pattern_of_set {
    uint32_t start[YX_PATTERN_OF_RANGES], end[YX_PATTERN_OF_RANGES];
    uint8_t count;
} yx_pattern_of_set;

typedef struct yx_pattern_expression_context {
    bool capi_import_order;
    const char *name;
    const char *names[5];
    size_t pattern_count;
    size_t mapping[5];
    const char **extra_names;
    size_t *extra_mapping, capacity;
    uint64_t *extra_limits;
    uint8_t ids[YX_PATTERN_EXPRESSION_SYMBOL_COUNT], types[YX_PATTERN_EXPRESSION_SYMBOL_COUNT], signatures[12], signature_count;
    uint8_t helper_type, search_global;
    size_t helper_id;
    bool used[YX_PATTERN_EXPRESSION_SYMBOL_COUNT], presence, unlimited, saw_pattern, helper_first, search_emitted;
    yx_pattern_of_set of_sets[YX_PATTERN_OF_SETS];
    uint8_t of_set_count;
    uint64_t match_limit, limits[5];
    bool search_scopes[257];
    unsigned scope_depth;
    /* Decoding (yx_pattern_expression_scope_fixup): the pattern nodes whose
     * lazy-search call the scopes of the decoded tree do not explain. */
    bool fixup;
    int *fixups;
    size_t fixup_count, fixup_capacity;
} yx_pattern_expression_context;

/* Small single-pattern adapters keep inline storage. Composition reserves
 * independent owned arrays, so the public pattern count has no inline cap. */
static const char **yx_pattern_names(yx_pattern_expression_context *c)
{
    return c->extra_names ? c->extra_names : c->names;
}
static size_t *yx_pattern_mapping(yx_pattern_expression_context *c)
{
    return c->extra_mapping ? c->extra_mapping : c->mapping;
}
static uint64_t *yx_pattern_limits(yx_pattern_expression_context *c)
{
    return c->extra_limits ? c->extra_limits : c->limits;
}
static size_t yx_pattern_capacity(const yx_pattern_expression_context *c)
{
    return c->capacity > 5 ? c->capacity : 5;
}
static bool yx_pattern_expression_reserve(yx_pattern_expression_context *c, size_t count)
{
    size_t old = yx_pattern_capacity(c);
    if (count <= old) return true;
    if (count > SIZE_MAX / sizeof(uint64_t) || count > SIZE_MAX / sizeof(size_t) || count > SIZE_MAX / sizeof(char *)) return false;
    const char **names = calloc(count, sizeof(*names));
    size_t *mapping = calloc(count, sizeof(*mapping));
    uint64_t *limits = calloc(count, sizeof(*limits));
    if (!names || !mapping || !limits) {
        free(names);
        free(mapping);
        free(limits);
        return false;
    }
    memcpy(names, yx_pattern_names(c), old * sizeof(*names));
    memcpy(mapping, yx_pattern_mapping(c), old * sizeof(*mapping));
    memcpy(limits, yx_pattern_limits(c), old * sizeof(*limits));
    for (size_t i = old; i < count; ++i) limits[i] = 1;
    free(c->extra_names);
    free(c->extra_mapping);
    free(c->extra_limits);
    c->extra_names = names;
    c->extra_mapping = mapping;
    c->extra_limits = limits;
    c->capacity = count;
    return true;
}
static void yx_pattern_expression_destroy(yx_pattern_expression_context *c)
{
    free(c->extra_names);
    free(c->extra_mapping);
    free(c->extra_limits);
    c->extra_names = NULL;
    c->extra_mapping = NULL;
    c->extra_limits = NULL;
    c->capacity = 0;
}
static bool yx_pattern_expression_symbol_token(yx_bool_parser *parser, unsigned char symbol)
{
    yx_bool_skip_space(parser);
    if (*parser->at != symbol) return false;
    ++parser->at;
    return true;
}

/* `any|all|N of them|(<set>)` in the forms upstream emits without a loop:
 * any or all of the set's id ranges, or N of a single contiguous range.
 * The node value holds the set index (bits 4+), whether pat_range_match
 * (bit 2) and the pattern check helper (bit 3) are called, and the
 * quantifier (bits 0-1: 0 any, 1 all, 3 N); `left` is N. The bits let a
 * tree merged from several rules be analyzed without their sets. */
static int64_t yx_pattern_of_value(const yx_pattern_of_set *set, uint8_t index, unsigned kind)
{
    int64_t value = (int64_t)index << 4 | kind;
    for (uint8_t i = 0; i < set->count; ++i) value |= set->start[i] == set->end[i] && kind != 3 ? 8 : 4;
    return value;
}
/* The selectors of a pattern tuple `($a, $b*, ...)`: wildcard prefixes in
 * order and exact names in a hash table, so that finding the members of n
 * patterns is linear in n and the tuple's length. */
typedef struct yx_pattern_tuple {
    const unsigned char **names;
    size_t *lengths;
    bool *wildcards;
    size_t count, capacity;
    /* table: selector indexes by (name, wildcard); prefixes: the distinct
     * lengths of the wildcard prefixes. */
    size_t *table, table_size, *prefixes, prefix_count;
} yx_pattern_tuple;
static uint64_t yx_pattern_tuple_hash(const unsigned char *name, size_t length)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < length; ++i) hash = (hash ^ name[i]) * UINT64_C(1099511628211);
    return hash;
}
static bool yx_pattern_tuple_add(yx_pattern_tuple *t, const unsigned char *name, size_t length, bool wildcard)
{
    if (t->count == t->capacity) {
        size_t capacity = t->capacity ? t->capacity * 2 : 16;
        if (capacity > SIZE_MAX / sizeof(*t->lengths)) return false;
        const unsigned char **names = realloc((void *)t->names, capacity * sizeof(*names));
        if (!names) return false;
        t->names = names;
        size_t *lengths = realloc(t->lengths, capacity * sizeof(*lengths));
        if (!lengths) return false;
        t->lengths = lengths;
        bool *wildcards = realloc(t->wildcards, capacity * sizeof(*wildcards));
        if (!wildcards) return false;
        t->wildcards = wildcards;
        t->capacity = capacity;
    }
    t->names[t->count] = name;
    t->lengths[t->count] = length;
    t->wildcards[t->count] = wildcard;
    ++t->count;
    return true;
}
/* The slot of selector (name, wildcard) in the table: its entry, or the
 * empty slot where it goes. `hash` is yx_pattern_tuple_hash of the name. */
static size_t yx_pattern_tuple_slot_hashed(const yx_pattern_tuple *t, uint64_t hash, const unsigned char *name, size_t length, bool wildcard)
{
    size_t mask = t->table_size - 1;
    size_t at = (size_t)(hash ^ (wildcard ? UINT64_C(0x9e3779b97f4a7c15) : 0)) & mask;
    for (; t->table[at] != SIZE_MAX; at = (at + 1) & mask) {
        size_t item = t->table[at];
        if (t->wildcards[item] == wildcard && t->lengths[item] == length && !memcmp(name, t->names[item], length)) break;
    }
    return at;
}
static size_t yx_pattern_tuple_slot(const yx_pattern_tuple *t, const unsigned char *name, size_t length, bool wildcard)
{
    return yx_pattern_tuple_slot_hashed(t, yx_pattern_tuple_hash(name, length), name, length, wildcard);
}
static int yx_pattern_tuple_length_compare(const void *a, const void *b)
{
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}
/* Repeated selectors are entered once (a tuple naming `$a` n times costs n
 * probes); wildcard prefixes are looked up by their distinct lengths, so a
 * pattern costs one probe per such length instead of one per wildcard. */
static bool yx_pattern_tuple_finish(yx_pattern_tuple *t)
{
    size_t size = 16;
    while (size < t->count * 2) {
        if (size > SIZE_MAX / 4 / sizeof(size_t)) return false;
        size *= 2;
    }
    t->table = malloc(size * sizeof(*t->table));
    t->prefixes = malloc((t->count ? t->count : 1) * sizeof(*t->prefixes));
    if (!t->table || !t->prefixes) return false;
    t->table_size = size;
    t->prefix_count = 0;
    for (size_t i = 0; i < size; ++i) t->table[i] = SIZE_MAX;
    for (size_t i = 0; i < t->count; ++i) {
        size_t at = yx_pattern_tuple_slot(t, t->names[i], t->lengths[i], t->wildcards[i]);
        if (t->table[at] != SIZE_MAX) continue;
        t->table[at] = i;
        if (t->wildcards[i]) {
            size_t k = 0;
            while (k < t->prefix_count && t->prefixes[k] != t->lengths[i]) ++k;
            if (k == t->prefix_count) t->prefixes[t->prefix_count++] = t->lengths[i];
        }
    }
    qsort(t->prefixes, t->prefix_count, sizeof(*t->prefixes), yx_pattern_tuple_length_compare);
    return true;
}
/* Whether a pattern name (without `$`) is selected by the tuple. */
static bool yx_pattern_tuple_match(const yx_pattern_tuple *t, const char *name, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)name;
    /* One pass over the name: its hash is read at each prefix length
     * (ascending), as yx_pattern_tuple_hash extends it byte by byte. */
    uint64_t hash = yx_pattern_tuple_hash(bytes, 0);
    size_t hashed = 0;
    for (size_t i = 0; i < t->prefix_count && t->prefixes[i] <= length; ++i) {
        for (; hashed < t->prefixes[i]; ++hashed) hash = (hash ^ bytes[hashed]) * UINT64_C(1099511628211);
        if (t->table[yx_pattern_tuple_slot_hashed(t, hash, bytes, t->prefixes[i], true)] != SIZE_MAX) return true;
    }
    return t->table[yx_pattern_tuple_slot(t, bytes, length, false)] != SIZE_MAX;
}
static void yx_pattern_tuple_free(yx_pattern_tuple *t)
{
    free((void *)t->names);
    free(t->lengths);
    free(t->wildcards);
    free(t->table);
    free(t->prefixes);
    memset(t, 0, sizeof(*t));
}
static int yx_pattern_tuple_id_compare(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}
static int yx_pattern_expression_of(yx_integer_expr *tree, unsigned depth, yx_pattern_expression_context *c)
{
    const unsigned char *start = tree->parser.at;
    yx_pattern_tuple tuple = {0};
    size_t item_count = 0, count = c->pattern_count ? c->pattern_count : 1, id_count = 0;
    uint32_t *ids = NULL;
    int quantity = -1;
    uint8_t kind;
    yx_pattern_of_set set = {0};
    (void)depth;
    yx_bool_skip_space(&tree->parser);
    if (yx_bool_keyword(&tree->parser, "any")) kind = 0;
    else if (yx_bool_keyword(&tree->parser, "all")) kind = 1;
    else if (*tree->parser.at >= '0' && *tree->parser.at <= '9') {
        uint64_t value = 0;
        const unsigned char *at = tree->parser.at;
        if (at[0] == '0' && (at[1] == 'x' || at[1] == 'o')) return -1;
        for (; *at >= '0' && *at <= '9'; ++at) {
            if (value > (UINT64_C(1) << 62)) return -1;
            value = value * 10 + (unsigned)(*at - '0');
        }
        if (*at == '%' || *at == '_' || (*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z')) return -1;
        tree->parser.at = at;
        kind = 3;
        quantity = yx_integer_expr_node_new(tree, 0x42, -1, -1, (int64_t)value);
        if (quantity < 0) return -1;
    } else return -1;
    if (!yx_bool_keyword(&tree->parser, "of")) {
        tree->parser.at = start;
        return -1;
    }
    yx_bool_skip_space(&tree->parser);
    if (!yx_bool_keyword(&tree->parser, "them")) {
        if (!yx_pattern_expression_symbol_token(&tree->parser, '(')) goto unsupported;
        do {
            const unsigned char *name;
            size_t length;
            yx_bool_skip_space(&tree->parser);
            bool wildcard;
            if (*tree->parser.at != '$') goto unsupported;
            ++tree->parser.at;
            if (!yx_with_identifier(&tree->parser, &name, &length)) length = 0, name = tree->parser.at;
            wildcard = *tree->parser.at == '*';
            if (wildcard) ++tree->parser.at;
            else if (!length) goto unsupported;
            /* Any number of items (yx_pattern_tuple). */
            if (!yx_pattern_tuple_add(&tuple, name, length, wildcard)) goto unsupported;
            ++item_count;
        } while (yx_pattern_expression_symbol_token(&tree->parser, ','));
        if (!yx_pattern_expression_symbol_token(&tree->parser, ')') || !yx_pattern_tuple_finish(&tuple)) goto unsupported;
    }
    {
        /* `at` and `in` anchors use a loop. */
        const unsigned char *after = tree->parser.at;
        if (yx_bool_keyword(&tree->parser, "at") || yx_bool_keyword(&tree->parser, "in")) goto unsupported;
        tree->parser.at = after;
    }
    ids = malloc(count * sizeof(*ids));
    if (!ids) goto unsupported;
    for (size_t i = 0; i < count; ++i) {
        const char *name = c->pattern_count ? yx_pattern_names(c)[i] : c->name;
        bool member = !item_count || (name && yx_pattern_tuple_match(&tuple, name + 1, strlen(name + 1)));
        if (member) ids[id_count++] = (uint32_t)(c->pattern_count ? yx_pattern_mapping(c)[i] : 0);
    }
    if (!id_count) goto unsupported;
    qsort(ids, id_count, sizeof(*ids), yx_pattern_tuple_id_compare);
    for (size_t i = 0; i < id_count; ++i) {
        if (i && ids[i] == ids[i - 1]) goto unsupported;
        if (i && ids[i] == ids[i - 1] + 1) {
            set.end[set.count - 1] = ids[i];
            continue;
        }
        if (set.count == YX_PATTERN_OF_RANGES) goto unsupported;
        set.start[set.count] = set.end[set.count] = ids[i];
        ++set.count;
    }
    if ((kind == 3 && set.count != 1) || c->of_set_count == YX_PATTERN_OF_SETS) goto unsupported;
    free(ids);
    yx_pattern_tuple_free(&tuple);
    c->of_sets[c->of_set_count] = set;
    c->saw_pattern = true;
    return yx_integer_expr_node_new(tree, 0xda, quantity, -1, yx_pattern_of_value(&set, c->of_set_count++, kind));
unsupported:
    free(ids);
    yx_pattern_tuple_free(&tuple);
    tree->failed = true;
    return -1;
}

static int yx_pattern_expression_primary(yx_integer_expr *tree, unsigned depth, void *user)
{
    yx_pattern_expression_context *c = user;
    yx_bool_skip_space(&tree->parser);
    {
        int of = yx_pattern_expression_of(tree, depth, c);
        if (of >= 0 || tree->failed) return of;
    }
    uint8_t marker = *tree->parser.at;
    if (marker != '$' && marker != '#' && marker != '@' && marker != '!') return -1;
    ++tree->parser.at;
    const unsigned char *name;
    size_t length;
    if (!yx_with_identifier(&tree->parser, &name, &length)) return -1;
    size_t pattern = 0;
    if (c->pattern_count) {
        for (; pattern < c->pattern_count; ++pattern)
            if (strlen(yx_pattern_names(c)[pattern] + 1) == length && !memcmp(yx_pattern_names(c)[pattern] + 1, name, length)) break;
        if (pattern == c->pattern_count) return -1;
    } else if (!c->name || strlen(c->name + 1) != length || memcmp(c->name + 1, name, length)) return -1;
    c->saw_pattern = true;
    int left = -1, right = -1;
    uint8_t op = marker == '$' ? 0xd1 : marker == '#' ? 0xd2 : marker == '@' ? 0xd3 : 0xd4;
    if (marker == '@' || marker == '!') {
        if (yx_pattern_expression_symbol_token(&tree->parser, '[')) {
            left = yx_integer_expr_parse(tree, 1, depth + 1);
            if (left < 0 || !yx_pattern_expression_symbol_token(&tree->parser, ']')) return -1;
        } else left = yx_integer_expr_node_new(tree, 0x42, -1, -1, 1);
        right = left;
    } else if (marker == '$' && yx_bool_keyword(&tree->parser, "at")) {
        op = 0xd5;
        left = yx_integer_expr_parse(tree, 1, depth + 1);
        right = left;
    } else if (yx_bool_keyword(&tree->parser, "in")) {
        op = marker == '$' ? 0xd6 : 0xd7;
        if (!yx_pattern_expression_symbol_token(&tree->parser, '(')) return -1;
        left = yx_integer_expr_parse(tree, 1, depth + 1);
        yx_bool_skip_space(&tree->parser);
        if (tree->parser.at[0] != '.' || tree->parser.at[1] != '.') return -1;
        tree->parser.at += 2;
        right = yx_integer_expr_parse(tree, 1, depth + 1);
        if (left < 0 || right < 0 || !yx_pattern_expression_symbol_token(&tree->parser, ')')) return -1;
    }
    return yx_integer_expr_node_new(tree, op, left, right, (int64_t)yx_pattern_mapping(c)[pattern]);
}

static unsigned yx_pattern_expression_symbol(uint8_t op)
{
    return op == 0xd2 ? 2 : op == 0xd3 ? 3 : op == 0xd4 ? 4 : op == 0xd5 ? 5 : op == 0xd6 ? 6 : 7;
}

static bool yx_pattern_expression_resources(yx_integer_expr *tree, int index, void *user)
{
    yx_pattern_expression_context *c = user;
    uint8_t op = YX_INTEGER_NODES(tree)[index].op;
    if (op == 0xd8 || op == 0xd9) return true;
    if (op == 0xda) {
        int64_t value = YX_INTEGER_NODES(tree)[index].value;
        c->used[1] = true;
        if (value & 8) c->presence = true, tree->has_memory = true;
        if (value & 4) c->used[14] = true;
        return true;
    }
    if (op < 0xd1 || op > 0xd7) return false;
    c->used[1] = true;
    if (op == 0xd1) c->presence = true, tree->has_memory = true;
    else {
        c->used[yx_pattern_expression_symbol(op)] = true;
        bool bounded = false;
        uint64_t pattern_limit = 1;
        /* IR::required_matches_for_count (ir/mod.rs): the count on either
         * side of a comparison with a constant integer. */
        /* The root, and the Boolean contexts (`and`, `or`, `not`, the body
         * of a `with` or of a `for .. in`): one match tells `#a != 0`. */
        if (op == 0xd2 && index >= 0 && (size_t)index + 1 == tree->count) {
            pattern_limit = 1;
            bounded = true;
        }
        if (op == 0xd2 && !bounded)
            for (size_t n = 0; n < tree->count; ++n) {
                const yx_integer_expr_node *parent = &YX_INTEGER_NODES(tree)[n];
                if (((parent->op >= 0xa0 && parent->op <= 0xa2) && (parent->left == index || parent->right == index)) ||
                    ((parent->op == 0xd8 || parent->op == 0xd9) && parent->left == index) || (parent->op == 0xc0 && parent->right == index && parent->left != index) ||
                    (parent->op >= 0xc4 && parent->op <= 0xc6 && parent->extra == index)) {
                    pattern_limit = 1;
                    bounded = true;
                    break;
                }
                if ((parent->left != index && parent->right != index) || parent->op < 0x51 || parent->op > 0x59 || parent->left < 0 || parent->right < 0 ||
                    parent->left == parent->right)
                    continue;
                bool count_first = parent->left == index;
                const yx_integer_expr_node *bound = &YX_INTEGER_NODES(tree)[count_first ? parent->right : parent->left];
                uint64_t limit;
                if (!bound->constant || bound->floating || !yx_count_required_matches(bound->value, bound->unsigned_value, parent->op, count_first, &limit)) break;
                if (limit > c->match_limit) c->match_limit = limit;
                pattern_limit = limit;
                bounded = true;
                break;
            }
        size_t physical = (size_t)YX_INTEGER_NODES(tree)[index].value;
        if (physical >= yx_pattern_capacity(c)) return false;
        if (!bounded) c->unlimited = true, yx_pattern_limits(c)[physical] = 0;
        else if (yx_pattern_limits(c)[physical] && pattern_limit > yx_pattern_limits(c)[physical]) yx_pattern_limits(c)[physical] = pattern_limit;
    }
    return true;
}

static void yx_pattern_expression_boolean_scope(void *user, bool enter);
static bool yx_pattern_expression_emit(const yx_integer_expr *tree, int index, yx_writer *w, unsigned depth, int slot, bool boolean, void *user)
{
    yx_pattern_expression_context *c = user;
    const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[index];
    if (node->op == 0xd8 || node->op == 0xd9) {
        /* A one-operand And / Or (IR::and, IR::or keep it): emit_expr pushes
         * a lazy-search scope for it like for any other (emit.rs). */
        bool ok;
        yx_pattern_expression_boolean_scope(c, true);
        ok = yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && (node->op != 0xd9 || (yx_put_u8(w, 2) && yx_put_u8(w, 0x7f))) &&
             yx_integer_boolean_emit(tree, node->left, w, depth + 1) && yx_put_u8(w, 0x0b) && (node->op != 0xd9 || yx_put_u8(w, 0x0b));
        yx_pattern_expression_boolean_scope(c, false);
        return ok;
    }
    if (node->op == 0xda) {
        const yx_pattern_of_set *set = &c->of_sets[node->value >> 4];
        unsigned kind = (unsigned)(node->value & 3);
        if (!c->search_emitted) {
            if (!yx_put_u8(w, 0x23) || !yx_put_u8(w, c->search_global) || !yx_put_u8(w, 4) || !yx_put_u8(w, 0x40) || !yx_put_u8(w, 5) || !yx_put_u8(w, 0x10) ||
                !yx_put_uleb(w, c->ids[1]) || !yx_put_u8(w, 0x0b))
                return false;
            c->search_emitted = true;
        } else if (c->fixup && node->guarded && c->fixup_count < c->fixup_capacity) c->fixups[c->fixup_count++] = index;
        if (kind == 3) {
            if (!yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, set->start[0]) || !yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, set->end[0]) ||
                !yx_integer_expr_emit(tree, node->left, w, 0, depth + 1, slot, false) || !yx_put_u8(w, 0x10) || !yx_put_uleb(w, c->ids[14]))
                return false;
        } else {
            static const uint8_t any_guard[] = {4, 0x40, 0x41, 1, 0x0c, 1, 5, 0x0b}, all_guard[] = {4, 0x40, 5, 0x41, 0, 0x0c, 1, 0x0b};
            if (!yx_put_u8(w, 2) || !yx_put_u8(w, 0x7f)) return false;
            for (uint8_t i = 0; i < set->count; ++i) {
                if (set->start[i] == set->end[i]) {
                    if (!yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, set->start[i]) || !yx_put_u8(w, 0x10) || !yx_put_uleb(w, c->helper_id)) return false;
                } else if (!yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, set->start[i]) || !yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, set->end[i]) || !yx_put_u8(w, 0x42) ||
                           !yx_put_sleb_i64(w, kind ? (int64_t)(set->end[i] - set->start[i] + 1) : 1) || !yx_put_u8(w, 0x10) || !yx_put_uleb(w, c->ids[14]))
                    return false;
                if (i + 1 < set->count && !yx_put_bytes(w, kind ? all_guard : any_guard, 8)) return false;
            }
            if (!yx_put_u8(w, 0x0b)) return false;
        }
        return boolean || yx_put_u8(w, 0xad);
    }
    if (node->op < 0xd1 || node->op > 0xd7) return false;
    if (!c->search_emitted) {
        if (!yx_put_u8(w, 0x23) || !yx_put_u8(w, c->search_global) || !yx_put_u8(w, 4) || !yx_put_u8(w, 0x40) || !yx_put_u8(w, 5) || !yx_put_u8(w, 0x10) ||
            !yx_put_uleb(w, c->ids[1]) || !yx_put_u8(w, 0x0b))
            return false;
        c->search_emitted = true;
    } else if (c->fixup && node->guarded && c->fixup_count < c->fixup_capacity) c->fixups[c->fixup_count++] = index;
    if (!yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, node->value)) return false;
    if (node->left >= 0 && !yx_integer_expr_emit(tree, node->left, w, 0, depth + 1, slot, false)) return false;
    if ((node->op == 0xd6 || node->op == 0xd7) && !yx_integer_expr_emit(tree, node->right, w, 0, depth + 1, slot, false)) return false;
    unsigned function = node->op == 0xd1 ? c->helper_id : c->ids[yx_pattern_expression_symbol(node->op)];
    if (!yx_put_u8(w, 0x10) || !yx_put_uleb(w, function)) return false;
    if ((node->op == 0xd3 || node->op == 0xd4) && !yx_integer_emit_guard(w, 0x10, slot)) return false;
    bool is_bool = node->op == 0xd1 || node->op == 0xd5 || node->op == 0xd6;
    return is_bool ? (boolean || yx_put_u8(w, 0xad)) : (!boolean || (yx_put_u8(w, 0x42) && yx_put_u8(w, 0) && yx_put_u8(w, 0x52)));
}

static bool yx_pattern_expression_print(const yx_integer_expr *tree, int index, yx_writer *w, void *user)
{
    yx_pattern_expression_context *c = user;
    const yx_integer_expr_node *n = &YX_INTEGER_NODES(tree)[index];
    /* The constant first: a one-operand node inside another stays apart
     * (a left-nested chain is one operation). */
    if (n->op == 0xd8 || n->op == 0xd9)
        return yx_put_bytes(w, n->op == 0xd8 ? "(true and " : "(false or ", 10) && yx_integer_expr_print(tree, n->left, w, 0, false, 0) && yx_put_u8(w, ')');
    if (n->op == 0xda) {
        const yx_pattern_of_set *set = &c->of_sets[n->value >> 4];
        unsigned kind = (unsigned)(n->value & 3);
        bool first = true;
        if (kind == 3 ? !yx_integer_expr_print(tree, n->left, w, 0, false, 0) : !yx_put_bytes(w, kind ? "all" : "any", 3)) return false;
        if (!yx_put_bytes(w, " of (", 5)) return false;
        for (uint8_t i = 0; i < set->count; ++i)
            for (uint32_t id = set->start[i]; id <= set->end[i]; ++id) {
                const char *name = c->pattern_count && id < c->pattern_count ? yx_pattern_names(c)[id] : id == 0 ? c->name : NULL;
                if (!name || (!first && !yx_put_bytes(w, ", ", 2)) || !yx_put_bytes(w, name, strlen(name))) return false;
                first = false;
            }
        return yx_put_u8(w, ')');
    }
    const char *name = c->pattern_count && n->value >= 0 && (uint64_t)n->value < c->pattern_count ? yx_pattern_names(c)[n->value] : c->name;
    if (n->op < 0xd1 || n->op > 0xd7 || !name) return false;
    char marker = n->op == 0xd2 || n->op == 0xd7 ? '#' : n->op == 0xd3 ? '@' : n->op == 0xd4 ? '!' : '$';
    if (!yx_put_u8(w, (uint8_t)marker) || !yx_put_bytes(w, name + 1, strlen(name + 1))) return false;
    if (n->op == 0xd3 || n->op == 0xd4) return yx_put_u8(w, '[') && yx_integer_expr_print(tree, n->left, w, 0, false, 0) && yx_put_u8(w, ']');
    if (n->op == 0xd5) return yx_put_bytes(w, " at (", 5) && yx_integer_expr_print(tree, n->left, w, 0, false, 0) && yx_put_u8(w, ')');
    if (n->op == 0xd6 || n->op == 0xd7)
        return yx_put_bytes(w, " in (", 5) && yx_integer_expr_print(tree, n->left, w, 0, false, 0) && yx_put_bytes(w, "..", 2) &&
               yx_integer_expr_print(tree, n->right, w, 0, false, 0) && yx_put_u8(w, ')');
    return true;
}

/* The `of` forms written by yx_pattern_expression_emit. */
static int yx_pattern_expression_decode_of(yx_reader *r, size_t end, yx_integer_expr *tree, yx_pattern_expression_context *c)
{
    yx_pattern_of_set set = {0};
    int64_t start, last, required;
    uint64_t function;
    int quantity = -1;
    unsigned kind = 0;
    bool block = r->at + 1 < end && r->data[r->at] == 2 && r->data[r->at + 1] == 0x7f;
    if (c->of_set_count == YX_PATTERN_OF_SETS) return -1;
    if (!block) {
        if (!c->used[14] || !yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &start) || !yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &last) ||
            !yx_rule_expression_byte(r, 0x42) || !yx_get_sleb_i64(r, &required) || !yx_rule_expression_byte(r, 0x10) || !yx_get_uleb(r, &function) ||
            function != c->ids[14] || start < 0 || last < start || last > UINT32_MAX || required < 0)
            return -1;
        set.start[0] = (uint32_t)start;
        set.end[0] = (uint32_t)last;
        set.count = 1;
        kind = 3;
        quantity = yx_integer_expr_node_new(tree, 0x42, -1, -1, required);
        if (quantity < 0) return -1;
    } else {
        static const uint8_t any_guard[] = {4, 0x40, 0x41, 1, 0x0c, 1, 5, 0x0b}, all_guard[] = {4, 0x40, 5, 0x41, 0, 0x0c, 1, 0x0b};
        int guard = -1, required_kind = -1;
        r->at += 2;
        for (;;) {
            if (set.count == YX_PATTERN_OF_RANGES || !yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &start) || start < 0 || start > UINT32_MAX) return -1;
            if (r->at < end && r->data[r->at] == 0x10) {
                if (!c->presence || !yx_rule_expression_byte(r, 0x10) || !yx_get_uleb(r, &function) || function != c->helper_id) return -1;
                last = start;
            } else {
                if (!c->used[14] || !yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &last) || last <= start || last > UINT32_MAX ||
                    !yx_rule_expression_byte(r, 0x42) || !yx_get_sleb_i64(r, &required) || !yx_rule_expression_byte(r, 0x10) || !yx_get_uleb(r, &function) ||
                    function != c->ids[14])
                    return -1;
                int range_kind = required == 1 ? 0 : required == last - start + 1 ? 1 : -1;
                if (range_kind < 0 || (required_kind >= 0 && required_kind != range_kind)) return -1;
                required_kind = range_kind;
            }
            if (set.count && set.start[set.count - 1] <= (uint32_t)start && set.end[set.count - 1] + 1 >= (uint32_t)start) return -1;
            if (set.count && set.end[set.count - 1] >= (uint32_t)start) return -1;
            set.start[set.count] = (uint32_t)start;
            set.end[set.count] = (uint32_t)last;
            ++set.count;
            if (r->at < end && r->data[r->at] == 0x0b) {
                ++r->at;
                break;
            }
            if (end - r->at >= 8 && !memcmp(r->data + r->at, any_guard, 8)) {
                if (guard == 1) return -1;
                guard = 0;
                r->at += 8;
            } else if (end - r->at >= 8 && !memcmp(r->data + r->at, all_guard, 8)) {
                if (guard == 0) return -1;
                guard = 1;
                r->at += 8;
            } else return -1;
        }
        if (guard >= 0 && required_kind >= 0 && guard != required_kind) return -1;
        /* A block around one pattern check is an or-operand, not a set. */
        if (set.count == 1 && set.start[0] == set.end[0]) return -1;
        kind = guard >= 0 ? (unsigned)guard : required_kind >= 0 ? (unsigned)required_kind : 0;
    }
    c->of_sets[c->of_set_count] = set;
    c->saw_pattern = true;
    for (uint8_t i = 0; i < set.count; ++i)
        if (set.end[i] >= c->pattern_count) c->pattern_count = set.end[i] + 1;
    return yx_integer_expr_node_new(tree, 0xda, quantity, -1, yx_pattern_of_value(&set, c->of_set_count++, kind));
}

static int yx_pattern_expression_decode_node(yx_reader *r, size_t end, yx_integer_expr *tree, void *user);
static int yx_pattern_expression_decode(yx_reader *r, size_t end, yx_integer_expr *tree, void *user)
{
    yx_pattern_expression_context *c = user;
    uint8_t guard[] = {0x23, c->search_global, 4, 0x40, 5, 0x10, c->ids[1], 0x0b};
    bool guarded = r->at <= end && end - r->at >= sizeof(guard) && end <= r->length && !memcmp(r->data + r->at, guard, sizeof(guard));
    int node = yx_pattern_expression_decode_node(r, end, tree, user);
    if (node >= 0 && guarded) YX_INTEGER_NODES(tree)[node].guarded = true;
    return node;
}

/* A one-operand `and` / `or` whose operand raises no `undefined` leaves no
 * block in the module, only its lazy-search scope: the search call before a
 * pattern that an enclosing scope already searched for. Emitting the decoded
 * tree finds those patterns; each one's Boolean term gets the one-operand
 * node (0xd8) that explains its call. */
static bool yx_pattern_expression_scope_fixup(yx_integer_expr *tree, int *root, yx_pattern_expression_context *c)
{
    size_t count = tree->count;
    yx_writer scratch = {0};
    int *parents = NULL;
    bool ok = true;
    if (*root < 0 || !count) return true;
    c->fixups = malloc(count * sizeof(*c->fixups));
    if (!c->fixups) return false;
    c->fixup_capacity = count;
    c->fixup_count = 0;
    c->fixup = true;
    c->search_emitted = false;
    c->scope_depth = 0;
    (void)yx_integer_boolean_emit(tree, *root, &scratch, 0);
    c->fixup = false;
    c->search_emitted = false;
    c->scope_depth = 0;
    free(scratch.data);
    if (c->fixup_count) {
        parents = malloc(count * sizeof(*parents));
        if (!parents) ok = false;
        for (size_t n = 0; ok && n < count; ++n) parents[n] = -1;
        for (size_t n = 0; ok && n < count; ++n) {
            const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[n];
            if (node->constant) continue;
            if (node->left >= 0 && (size_t)node->left < count && (size_t)node->left != n) parents[node->left] = (int)n;
            if (node->right >= 0 && (size_t)node->right < count && (size_t)node->right != n) parents[node->right] = (int)n;
            if (node->extra >= 0 && (size_t)node->extra < count && (size_t)node->extra != n) parents[node->extra] = (int)n;
        }
    }
    for (size_t f = 0; ok && f < c->fixup_count; ++f) {
        int term = c->fixups[f], wrapper;
        /* Up to the Boolean term: an operand of `and`, `or`, `not`, the body
         * of a loop or of a `with`, or the condition itself. */
        for (unsigned depth = 0; depth < 4096; ++depth) {
            int parent = parents[term];
            uint8_t op;
            if (parent < 0) break;
            op = YX_INTEGER_NODES(tree)[parent].op;
            if (op == 0xa0 || op == 0xa1 || op == 0xa2 || op == 0xd8 || op == 0xd9 || ((op >= 0xc4 && op <= 0xc6) && YX_INTEGER_NODES(tree)[parent].extra == term) ||
                (op == 0xc0 && YX_INTEGER_NODES(tree)[parent].right == term))
                break;
            term = parent;
        }
        if (YX_INTEGER_NODES(tree)[term].op == 0xd8) continue;
        wrapper = yx_integer_expr_node_new(tree, 0xd8, term, term, 0);
        if (wrapper < 0) {
            ok = false;
            break;
        }
        if (parents[term] >= 0) {
            yx_integer_expr_node *parent = &YX_INTEGER_NODES(tree)[parents[term]];
            if (parent->left == term) parent->left = wrapper;
            if (parent->right == term) parent->right = wrapper;
            if (parent->extra == term) parent->extra = wrapper;
        } else if (*root == term) *root = wrapper;
    }
    free(parents);
    free(c->fixups);
    c->fixups = NULL;
    c->fixup_count = c->fixup_capacity = 0;
    return ok;
}

static int yx_pattern_expression_decode_node(yx_reader *r, size_t end, yx_integer_expr *tree, void *user)
{
    yx_pattern_expression_context *c = user;
    yx_reader saved = *r;
    size_t count = tree->count;
    uint8_t guard[] = {0x23, c->search_global, 4, 0x40, 5, 0x10, c->ids[1], 0x0b};
    (void)yx_integer_wasm_bytes(r, end, guard, sizeof(guard));
    {
        yx_reader before = *r;
        uint8_t sets = c->of_set_count;
        int of = yx_pattern_expression_decode_of(r, end, tree, c);
        if (of >= 0) return of;
        *r = before;
        tree->count = count;
        tree->failed = false;
        c->of_set_count = sets;
    }
    int64_t pattern;
    if (!yx_rule_expression_byte(r, 0x41) || !yx_get_sleb_i64(r, &pattern) || pattern < 0 || (uint64_t)pattern >= yx_pattern_capacity(c)) {
        *r = saved;
        return -1;
    }
    size_t prefix = r->at - saved.at;
    for (unsigned op = 0xd1; op <= 0xd7; ++op) {
        unsigned function = op == 0xd1 ? c->helper_id : c->ids[yx_pattern_expression_symbol((uint8_t)op)];
        if ((op == 0xd1 && !c->presence) || (op != 0xd1 && !c->used[yx_pattern_expression_symbol((uint8_t)op)])) continue;
        r->at = saved.at + prefix;
        tree->count = count;
        tree->failed = false;
        int left = -1, right = -1;
        if (op >= 0xd3) {
            bool active = tree->stop_call_active;
            unsigned stop = tree->stop_call;
            int second = tree->second_argument;
            tree->stop_call_active = true;
            tree->stop_call = function;
            left = yx_integer_wasm_block(r, end, tree, 0, -1);
            right = tree->second_argument;
            tree->stop_call_active = active;
            tree->stop_call = stop;
            tree->second_argument = second;
            if (left < 0 || ((op == 0xd6 || op == 0xd7) ? right < 0 : right >= 0)) continue;
            if (right < 0) right = left;
            if ((op == 0xd3 || op == 0xd4) && YX_INTEGER_NODES(tree)[left].constant && YX_INTEGER_NODES(tree)[left].value <= 0) continue;
            if ((op == 0xd6 || op == 0xd7) && YX_INTEGER_NODES(tree)[left].constant && YX_INTEGER_NODES(tree)[right].constant &&
                (YX_INTEGER_NODES(tree)[left].value < 0 || YX_INTEGER_NODES(tree)[right].value < YX_INTEGER_NODES(tree)[left].value))
                continue;
        }
        uint64_t actual;
        if (!yx_rule_expression_byte(r, 0x10) || !yx_get_uleb(r, &actual) || actual != function) continue;
        if ((op == 0xd3 || op == 0xd4) && !yx_integer_wasm_guard(r, end, 0x10, -1)) continue;
        c->saw_pattern = true;
        if ((size_t)pattern >= c->pattern_count) c->pattern_count = (size_t)pattern + 1;
        return yx_integer_expr_node_new(tree, (uint8_t)op, left, right, pattern);
    }
    *r = saved;
    tree->count = count;
    tree->failed = false;
    return -1;
}

static void yx_pattern_expression_boolean_scope(void *user, bool enter)
{
    yx_pattern_expression_context *c = user;
    if (enter) {
        if (c->scope_depth < 257) c->search_scopes[c->scope_depth++] = c->search_emitted;
        c->search_emitted = false;
    } else if (c->scope_depth) c->search_emitted = c->search_scopes[--c->scope_depth];
}

static int yx_pattern_expression_decode_block(yx_integer_expr *tree, int node, void *user)
{
    (void)user;
    uint8_t op = YX_INTEGER_NODES(tree)[node].op;
    /* Boolean conjunction/disjunction already retain their result block.
       A result block around a leaf survives an eliminated identity term. */
    if (op == 0xa0 || op == 0xa1 || op == 0xc0 || (op >= 0xc4 && op <= 0xc6)) return node;
    return yx_integer_expr_node_new(tree, 0xd8, node, node, 0);
}

static void yx_pattern_expression_setup(yx_integer_expr *tree, yx_pattern_expression_context *c)
{
    tree->extension = c;
    tree->parse_primary = yx_pattern_expression_primary;
    tree->emit_primary = yx_pattern_expression_emit;
    tree->resource_primary = yx_pattern_expression_resources;
    tree->print_primary = yx_pattern_expression_print;
    tree->decode_primary = yx_pattern_expression_decode;
    tree->boolean_scope = yx_pattern_expression_boolean_scope;
    tree->decode_boolean_block = yx_pattern_expression_decode_block;
}

/* Signature numbers identify Wasm types, independent of imported names. */
static uint8_t yx_pattern_expression_type(yx_pattern_expression_context *c, uint8_t signature)
{
    for (uint8_t i = 0; i < c->signature_count; ++i)
        if (c->signatures[i] == signature) return i;
    if (c->signature_count == 12) return 255;
    c->signatures[c->signature_count] = signature;
    return c->signature_count++;
}
static bool yx_pattern_expression_types(yx_integer_expr *tree, int index, yx_pattern_expression_context *c, unsigned depth)
{
    if (depth > 256 || !tree->count || tree->count > SIZE_MAX / sizeof(int)) return false;
    int *stack = malloc(tree->count * sizeof(*stack));
    size_t used = 0;
    bool ok = false;
    if (!stack) return false;
    stack[used++] = index;
    while (used) {
        int current = stack[--used];
        if (current < 0 || (size_t)current >= tree->count) goto types_done;
        const yx_integer_expr_node *n = &YX_INTEGER_NODES(tree)[current];
        if (n->constant) continue;
        if (n->op >= 0xb0 && n->op < 0xc0) c->types[yx_pattern_expression_read_symbol(n->op - 0xb0)] = yx_pattern_expression_type(c, 8);
        if (n->op == 0xd1) c->helper_type = yx_pattern_expression_type(c, 3);
        else if (n->op == 0xda) {
            if (n->value & 8) c->helper_type = yx_pattern_expression_type(c, 3);
            if (n->value & 4) c->types[14] = yx_pattern_expression_type(c, 10);
        } else if (n->op >= 0xd2 && n->op <= 0xd7) {
            unsigned symbol = yx_pattern_expression_symbol(n->op);
            c->types[symbol] = yx_pattern_expression_type(c, n->op == 0xd2 ? 4 : n->op == 0xd3 || n->op == 0xd4 ? 5 : n->op == 0xd5 ? 6 : n->op == 0xd6 ? 7 : 9);
        }
        int children[3] = {n->extra, n->right == n->left ? -1 : n->right, n->left};
        for (size_t child = 0; child < 3; ++child)
            if (children[child] >= 0) {
                if (used == tree->count) goto types_done;
                stack[used++] = children[child];
            }
    }
    ok = true;
types_done:
    free(stack);
    return ok;
}
static bool yx_pattern_expression_header(yx_integer_expr *tree, int root, yx_pattern_expression_context *c, uint8_t profile, yx_writer *wasm)
{
    static const uint8_t signatures[11][8] = {{0x60, 0, 0},
                                              {0x60, 0, 1, 0x7f},
                                              {0x60, 1, 0x7f, 0},
                                              {0x60, 1, 0x7f, 1, 0x7f},
                                              {0x60, 1, 0x7f, 1, 0x7e},
                                              {0x60, 2, 0x7f, 0x7e, 2, 0x7e, 0x7f},
                                              {0x60, 2, 0x7f, 0x7e, 1, 0x7f},
                                              {0x60, 3, 0x7f, 0x7e, 0x7e, 1, 0x7f},
                                              {0x60, 1, 0x7e, 2, 0x7e, 0x7f},
                                              {0x60, 3, 0x7f, 0x7e, 0x7e, 1, 0x7e},
                                              {0x60, 3, 0x7f, 0x7f, 0x7e, 1, 0x7f}};
    static const uint8_t widths[] = {3, 4, 4, 5, 5, 7, 6, 7, 6, 7, 7};
    yx_writer types = {0}, imports = {0}, functions = {0}, exports = {0};
    bool ok = false;
    c->signature_count = 0;
    c->used[0] = true;
    c->types[0] = 2;
    c->types[1] = 0;
    for (unsigned i = 0; i < 3; ++i) yx_pattern_expression_type(c, (uint8_t)i);
    if (c->presence) c->helper_type = yx_pattern_expression_type(c, 3);
    if (!yx_pattern_expression_types(tree, root, c, 0)) goto done;
    for (unsigned i = 0; i < YX_INTEGER_READ_COUNT; ++i) c->used[yx_pattern_expression_read_symbol(i)] = !!(tree->read_mask & (1u << i));
    /* Wasm types are canonicalized by parameter and result value types,
       independently of the order in which expressions reference them. */
    {
        static const uint8_t order[] = {0, 1, 2, 3, 4, 10, 6, 5, 7, 9, 8};
        uint8_t old[12], remap[12];
        unsigned count = c->signature_count, next = 0;
        memcpy(old, c->signatures, count);
        for (unsigned i = 0; i < sizeof(order); ++i)
            for (unsigned j = 0; j < count; ++j)
                if (old[j] == order[i]) {
                    remap[j] = (uint8_t)next;
                    c->signatures[next++] = order[i];
                }
        if (next != count) goto done;
        for (unsigned i = 0; i < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++i)
            if (c->used[i]) c->types[i] = remap[c->types[i]];
        if (c->presence) c->helper_type = remap[c->helper_type];
    }
    uint8_t symbol_order[YX_PATTERN_EXPRESSION_SYMBOL_COUNT];
    uint32_t ranks[YX_PATTERN_EXPRESSION_SYMBOL_COUNT];
    for (unsigned i = 0; i < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++i) {
        ranks[i] = yx_pattern_expression_rank(i, profile, c->capi_import_order);
        if (c->used[i] && ranks[i] == UINT32_MAX) goto done;
        symbol_order[i] = (uint8_t)i;
    }
    for (unsigned i = 1; i < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++i) {
        uint8_t symbol = symbol_order[i];
        unsigned j = i;
        while (j && ranks[symbol_order[j - 1]] > ranks[symbol]) {
            symbol_order[j] = symbol_order[j - 1];
            --j;
        }
        symbol_order[j] = symbol;
    }
    tree->function_count = 0;
    for (unsigned i = 0; i < YX_INTEGER_READ_COUNT; ++i) c->used[yx_pattern_expression_read_symbol(i)] = !!(tree->read_mask & (1u << i));
    for (unsigned i = 0; i < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++i)
        if (c->used[symbol_order[i]]) c->ids[symbol_order[i]] = tree->function_count++;
    tree->match_id = c->ids[0];
    for (unsigned i = 0; i < YX_INTEGER_READ_COUNT; ++i) tree->read_ids[i] = c->ids[yx_pattern_expression_read_symbol(i)];
    tree->filesize_id = c->presence ? 1 : 0;
    c->search_global = (uint8_t)((c->presence ? 1 : 0) + (tree->has_filesize ? 1 : 0));
    c->helper_id = tree->function_count + (c->helper_first ? 0u : 1u);
    if (!yx_put_u8(&types, c->signature_count)) goto done;
    for (unsigned i = 0; i < c->signature_count; ++i)
        if (!yx_put_bytes(&types, signatures[c->signatures[i]], widths[c->signatures[i]])) goto done;
    if (!yx_put_u8(&imports, (uint8_t)(tree->function_count + c->presence + tree->has_filesize + 1 + tree->has_memory))) goto done;
    for (unsigned i = 0; i < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++i) {
        unsigned symbol = symbol_order[i];
        if (c->used[symbol] && !yx_put_integer_read_import(&imports, yx_pattern_expression_symbols[symbol], c->types[symbol])) goto done;
    }
    const char *globals[] = {"matching_patterns_bitmap_base", "filesize", "pattern_search_done"};
    for (unsigned i = 0; i < 3; ++i)
        if (i == 2 || (i == 0 ? c->presence : tree->has_filesize)) {
            if (!yx_put_u8(&imports, 6) || !yx_put_bytes(&imports, "yara_x", 6) || !yx_put_uleb(&imports, strlen(globals[i])) ||
                !yx_put_bytes(&imports, globals[i], strlen(globals[i])) || !yx_put_u8(&imports, 3) || !yx_put_u8(&imports, i == 1 ? 0x7e : 0x7f) ||
                !yx_put_u8(&imports, i != 0))
                goto done;
        }
    if (tree->has_memory && (!yx_put_u8(&imports, 6) || !yx_put_bytes(&imports, "yara_x", 6) || !yx_put_u8(&imports, 11) || !yx_put_bytes(&imports, "main_memory", 11) ||
                             !yx_put_u8(&imports, 2) || !yx_put_u8(&imports, 0) || !yx_put_u8(&imports, 1)))
        goto done;
    if (!yx_put_u8(&functions, c->presence ? 4 : 3) || !yx_put_u8(&functions, c->helper_first ? c->helper_type : 1) ||
        (c->presence && !yx_put_u8(&functions, c->helper_first ? 1 : c->helper_type)) || !yx_put_u8(&functions, 0) || !yx_put_u8(&functions, 1) ||
        !yx_put_u8(&exports, 1) || !yx_put_u8(&exports, 4) || !yx_put_bytes(&exports, "main", 4) || !yx_put_u8(&exports, 0) ||
        !yx_put_uleb(&exports, tree->function_count + (c->presence ? 3 : 2)) || !yx_put_bytes(wasm, yx_constant_wasm, 8) || !yx_append_wasm_section(wasm, 1, &types) ||
        !yx_append_wasm_section(wasm, 2, &imports) || !yx_append_wasm_section(wasm, 3, &functions) || !yx_append_wasm_section(wasm, 7, &exports))
        goto done;
    ok = true;
done:
    free(types.data);
    free(imports.data);
    free(functions.data);
    free(exports.data);
    return ok;
}

static bool yx_pattern_expression_wasm(yx_integer_expr *tree, int root, yx_pattern_expression_context *c, uint8_t profile, uint8_t **data, size_t *length)
{
    yx_writer wasm = {0}, body = {0}, code = {0};
    bool ok = false;
    memset(c->used, 0, sizeof(c->used));
    c->presence = c->unlimited = c->search_emitted = false;
    c->match_limit = 1;
    c->scope_depth = 0;
    for (size_t i = 0; i < yx_pattern_capacity(c); ++i) yx_pattern_limits(c)[i] = 1;
    tree->has_filesize = tree->has_shift = tree->has_divisor = tree->has_memory = tree->has_loop = false;
    tree->read_mask = 0;
    tree->small_shift = true;
    if (!yx_integer_expr_resources(tree, root, 0, 0) || !c->used[1] || !yx_pattern_expression_header(tree, root, c, profile, &wasm)) goto done;
    /* disallow_fast_scan (ast2ir.rs) runs for every offset, length, anchored
     * match and ranged count the condition names, also in an operand that
     * IR::and / IR::or fold away afterwards and the walk above skips. */
    for (size_t n = 0; n < tree->count; ++n) {
        const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[n];
        if (node->op >= 0xd3 && node->op <= 0xd7 && node->value >= 0 && (uint64_t)node->value < yx_pattern_capacity(c))
            yx_pattern_limits(c)[node->value] = 0, c->unlimited = true;
    }
    bool locals = tree->has_filesize || tree->has_shift || tree->has_divisor || tree->has_loop;
    if (!yx_put_u8(&body, locals ? 1 : 0) ||
        (locals && (!yx_put_u8(&body, tree->has_loop || (tree->has_shift && (!tree->small_shift || tree->has_filesize || tree->has_divisor)) ? 2 : 1) ||
                    !yx_put_u8(&body, 0x7e))) ||
        !yx_put_u8(&body, 2) || !yx_put_u8(&body, 0x7f) || !yx_integer_boolean_emit(tree, root, &body, 0))
        goto done;
    uint8_t suffix[] = {0x0b, 0x45, 4, 0x40, 5, 0x41, 0, 0x10, tree->match_id, 0x0b, 0x41, 0, 0x0b};
    if (!yx_put_bytes(&body, suffix, sizeof(suffix))) goto done;
    uint64_t instructions;
    if (!yx_rule_expression_instructions(&body, &instructions)) goto done;
    bool helper_first = c->presence && instructions < 15;
    if (helper_first != c->helper_first) {
        c->helper_first = helper_first;
        free(wasm.data);
        free(body.data);
        free(code.data);
        return yx_pattern_expression_wasm(tree, root, c, profile, data, length);
    }
    static const uint8_t helper[] = {29,   1, 1,    0x7f, 0x20, 0, 0x41, 3,    0x76, 0x23, 0,    0x6a, 0x2d, 0,    0,
                                     0x41, 1, 0x20, 0,    0x41, 8, 0x70, 0x22, 1,    0x74, 0x71, 0x20, 1,    0x76, 0x0b};
    if (!yx_put_u8(&code, c->presence ? 4 : 3) || (c->helper_first && !yx_put_bytes(&code, helper, sizeof(helper))) || !yx_put_uleb(&code, body.used) ||
        !yx_put_bytes(&code, body.data, body.used) || (c->presence && !c->helper_first && !yx_put_bytes(&code, helper, sizeof(helper))))
        goto done;
    uint8_t others[] = {9,    0,    2, 0x40, 0x10, (uint8_t)(tree->function_count + (c->helper_first ? 1 : 0)), 0x0d, 0,
                        0x0b, 0x0b, 6, 0,    0x10, (uint8_t)(tree->function_count + (c->presence ? 2 : 1)),     0x41, 0,
                        0x0b};
    if (!yx_put_bytes(&code, others, sizeof(others)) || !yx_append_wasm_section(&wasm, 10, &code)) goto done;
    *data = wasm.data;
    *length = wasm.used;
    wasm.data = NULL;
    ok = true;
done:
    free(wasm.data);
    free(body.data);
    free(code.data);
    return ok;
}

static yx_ser_result yx_constrain_single_pattern_archive(uint8_t **data, size_t *length, const YRX_PATTERN *pattern, const yx_integer_expr *tree, int root);
static yx_ser_result yx_unconstrain_single_pattern_archive(const uint8_t *data, size_t length, const yx_integer_expr *tree, int root, uint8_t **out, size_t *out_length);
static yx_ser_result yx_constrain_pattern_anchors(uint8_t **data, size_t *length, const yx_integer_expr *tree, int root, const YRX_RULE *rule);
static bool yx_unanchored_pattern_terms(const uint8_t *data, size_t length, yx_integer_expr *tree, int *root);
static bool yx_pattern_ir_marks(const yx_integer_expr *tree, int root, uint8_t *marks, size_t count);
static yx_ser_result yx_rule_unmarked_patterns(const YRX_RULES *rules, const YRX_RULE *r, const yx_integer_expr *tree, const uint8_t *marks, bool *unmarked);
static yx_ser_result yx_encode_pattern_expression(const YRX_RULES *rules, uint8_t **data, size_t *length)
{
    if (!rules || rules->rule_count != 1 || rules->import_count || rules->global_count || rules->rules[0].is_global || !rules->rules[0].pattern_count ||
        rules->rules[0].pattern_count > 5 || !rules->rules[0].condition_text)
        return YX_SER_UNSUPPORTED;
    const YRX_PATTERN *pattern = &rules->rules[0].patterns[0];
    size_t pattern_count = rules->rules[0].pattern_count;
    bool non_text = pattern->kind != YX_PATTERN_TEXT;
    for (size_t i = 0; i < pattern_count; ++i)
        if (pattern_count > 1 && (pattern[i].kind != YX_PATTERN_TEXT || (pattern[i].modifiers & ~YX_MOD_ASCII))) return YX_SER_UNSUPPORTED;
    if ((non_text && pattern->kind != YX_PATTERN_HEX && pattern->kind != YX_PATTERN_REGEX) ||
        (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD | YX_MOD_DOTALL)))
        return YX_SER_UNSUPPORTED;
    /* A direct unsupported pattern must not recurse into this adapter. */
    if (non_text && yx_regex_direct_condition(rules->rules[0].condition_text, pattern->identifier)) return YX_SER_UNSUPPORTED;
    yx_integer_expr *tree = calloc(1, sizeof(*tree));
    yx_pattern_expression_context c = {0};
    uint8_t *wasm = NULL, *base = NULL;
    size_t wasm_length = 0, base_length = 0;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    bool anchor_single = false;
    if (!tree) return YX_SER_NO_MEMORY;
    c.name = pattern->identifier;
    c.pattern_count = pattern_count;
    c.capi_import_order = !rules->archive_cli && yx_integer_import_profile() == 0;
    for (size_t i = 0; i < pattern_count; ++i) c.names[i] = pattern[i].identifier;
    size_t unique[5];
    yx_text_pattern_mapping(&rules->rules[0], c.mapping, unique, NULL);
    yx_pattern_expression_setup(tree, &c);
    int root = yx_integer_expr_condition(tree, rules->rules[0].condition_text);
    /* Equal declarations that anchor_patterns marks differently are two
     * Patterns: map them apart and parse again. */
    bool apart[5] = {false};
    if (root >= 0 && pattern_count > 1) {
        size_t split[5], split_unique[5];
        uint8_t marks[5];
        if (!yx_pattern_ir_marks(tree, root, marks, pattern_count)) {
            status = YX_SER_NO_MEMORY;
            goto done;
        }
        if ((status = yx_rule_unmarked_patterns(rules, &rules->rules[0], tree, marks, apart)) != YX_SER_SUCCESS) goto done;
        status = YX_SER_UNSUPPORTED;
        yx_text_pattern_mapping(&rules->rules[0], split, split_unique, apart);
        if (memcmp(split, c.mapping, pattern_count * sizeof(*split))) {
            yx_integer_expr_free(tree);
            if (!(tree = calloc(1, sizeof(*tree)))) {
                status = YX_SER_NO_MEMORY;
                goto done;
            }
            memcpy(c.mapping, split, sizeof(split));
            c.saw_pattern = false;
            yx_pattern_expression_setup(tree, &c);
            root = yx_integer_expr_condition(tree, rules->rules[0].condition_text);
        }
    }
    if (root < 0 || !c.saw_pattern || !yx_pattern_expression_wasm(tree, root, &c, yx_integer_import_profile(), &wasm, &wasm_length)) goto done;
    if (non_text) {
        YRX_RULE adapted = rules->rules[0];
        YRX_RULES base_rules = *rules;
        adapted.condition_text = pattern->identifier;
        base_rules.rules = &adapted;
        status = yx_ser_encode(&base_rules, &base, &base_length);
        if (status == YX_SER_SUCCESS) {
            uint8_t *limited = NULL;
            size_t limited_length = 0;
            if (!yx_pattern_limits_rewrite(base, base_length, c.limits, false, &limited, &limited_length)) status = YX_SER_UNSUPPORTED;
            else {
                free(base);
                base = limited;
                base_length = limited_length;
            }
        }
        if (status == YX_SER_SUCCESS && !yx_rule_expression_replace_wasm(base, base_length, wasm, wasm_length, data, length)) status = YX_SER_NO_MEMORY;
        anchor_single = status == YX_SER_SUCCESS && pattern_count == 1;
        goto done;
    }
    if (pattern_count > 1 || (YX_INTEGER_NODES(tree)[root].op == 0xd5 && YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[root].left].constant)) {
        bool anchored = YX_INTEGER_NODES(tree)[root].op == 0xd5 && YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[root].left].constant;
        uint64_t first_limit = c.limits[0];
        if (anchored) c.limits[0] = 0;
        status = yx_text_envelope_encode(&rules->rules[0], wasm, wasm_length, c.limits, anchored,
                                         anchored ? (uint64_t)YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[root].left].value : 0, apart, data, length);
        /* The plain envelope takes only unmodified text; other single
         * patterns use the field codec below plus the anchoring pass. */
        if (status != YX_SER_UNSUPPORTED || pattern_count > 1) goto done;
        c.limits[0] = first_limit;
    }
    yx_ser_rule shape = {0};
    bool truth = true;
    shape.single_text_pattern = true;
    shape.pattern_bytes = pattern->bytes;
    shape.pattern_length = pattern->length;
    shape.nocase_single_pattern = !!(pattern->modifiers & YX_MOD_NOCASE);
    shape.fullword_single_pattern = !!(pattern->modifiers & YX_MOD_FULLWORD);
    shape.wide_single_pattern = (pattern->modifiers & YX_MOD_WIDE) && !(pattern->modifiers & YX_MOD_ASCII);
    shape.ascii_wide_single_pattern = (pattern->modifiers & (YX_MOD_WIDE | YX_MOD_ASCII)) == (YX_MOD_WIDE | YX_MOD_ASCII);
    if (c.unlimited || c.match_limit > 1) shape.count_operator = YX_SER_COUNT_GT, shape.count_value = c.unlimited ? UINT32_MAX : (uint32_t)(c.match_limit - 1);
    YRX_RULE adapted = rules->rules[0];
    if (pattern_count > 1) {
        if (c.unlimited || c.match_limit > 1) goto done;
        shape.single_text_pattern = false;
        shape.two_text_patterns = pattern_count == 2;
        shape.two_text_any = pattern_count == 2;
        shape.three_text_patterns = pattern_count == 3;
        shape.three_text_any = pattern_count == 3;
        shape.four_text_patterns = pattern_count == 4;
        shape.four_text_any = pattern_count == 4;
        shape.five_text_patterns = pattern_count == 5;
        shape.five_text_any = pattern_count == 5;
        shape.second_pattern_bytes = pattern[1].bytes;
        shape.second_pattern_length = pattern[1].length;
        if (pattern_count > 2) shape.third_pattern_bytes = pattern[2].bytes, shape.third_pattern_length = pattern[2].length;
        if (pattern_count > 3) shape.fourth_pattern_bytes = pattern[3].bytes, shape.fourth_pattern_length = pattern[3].length;
        if (pattern_count > 4) shape.fifth_pattern_bytes = pattern[4].bytes, shape.fifth_pattern_length = pattern[4].length;
        adapted.condition_text = "any of them";
    }
    status = yx_encode_fields(&adapted, 1, &truth, &shape, false, false, false, false, false, false, false, false, false, false, false, YX_PATTERN_STAT_DEFAULT, false,
                              false, false, false, &base, &base_length);
    if (status == YX_SER_SUCCESS && !yx_rule_expression_replace_wasm(base, base_length, wasm, wasm_length, data, length)) status = YX_SER_NO_MEMORY;
    anchor_single = status == YX_SER_SUCCESS && pattern_count == 1;
done:
    if (status == YX_SER_SUCCESS) {
        uint8_t *bounded = NULL;
        size_t bounded_length = 0;
        if (yx_pattern_filesize_rewrite(tree, root, *data, *length, false, &bounded, &bounded_length)) {
            free(*data);
            *data = bounded;
            *length = bounded_length;
        } else {
            free(*data);
            *data = NULL;
            *length = 0;
            status = YX_SER_UNSUPPORTED;
        }
    }
    if (status == YX_SER_SUCCESS && anchor_single) {
        yx_ser_result anchored = yx_constrain_single_pattern_archive(data, length, pattern, tree, root);
        if (anchored == YX_SER_NO_MEMORY) {
            free(*data);
            *data = NULL;
            *length = 0;
            status = anchored;
        }
    } else if (status == YX_SER_SUCCESS && pattern_count > 1) {
        yx_ser_result anchored = yx_constrain_pattern_anchors(data, length, tree, root, &rules->rules[0]);
        if (anchored == YX_SER_NO_MEMORY) {
            free(*data);
            *data = NULL;
            *length = 0;
            status = anchored;
        }
    }
    yx_integer_expr_free(tree);
    free(wasm);
    free(base);
    return status;
}

static bool yx_pattern_expression_read_header(yx_reader *r, yx_integer_expr *tree, yx_pattern_expression_context *c)
{
    static const uint8_t sections[] = {1, 2, 3, 7, 10};
    if (r->length < 8 || memcmp(r->data, yx_constant_wasm, 8)) return false;
    r->at = 8;
    memset(c->ids, 255, sizeof(c->ids));
    for (unsigned section = 0; section < sizeof(sections); ++section) {
        uint8_t id;
        uint64_t width;
        if (!yx_get_u8(r, &id) || id != sections[section]) return false;
        if (id == 10) {
            --r->at;
            c->helper_id = tree->function_count + (c->helper_first ? 0u : 1u);
            return c->used[0] && c->used[1];
        }
        if (!yx_get_uleb(r, &width) || width > r->length - r->at) return false;
        size_t end = r->at + (size_t)width;
        if (id == 3) {
            uint64_t functions, type;
            if (!yx_get_uleb(r, &functions) || !yx_get_uleb(r, &type)) return false;
            c->helper_first = c->presence && type != 1;
        }
        if (id == 2) {
            uint64_t imports;
            unsigned global = 0;
            if (!yx_get_uleb(r, &imports) || imports > YX_PATTERN_EXPRESSION_SYMBOL_COUNT + 4) return false;
            for (uint64_t i = 0; i < imports; ++i) {
                const uint8_t *module, *name;
                size_t module_length, name_length;
                uint8_t kind;
                if (!yx_integer_wasm_name(r, end, &module, &module_length) || !yx_integer_wasm_name(r, end, &name, &name_length) || !yx_get_u8(r, &kind)) return false;
                if (kind == 0 && module_length == 12 && !memcmp(module, "yara_x::wasm", 12)) {
                    uint64_t type;
                    unsigned symbol;
                    if (!yx_get_uleb(r, &type)) return false;
                    for (symbol = 0; symbol < YX_PATTERN_EXPRESSION_SYMBOL_COUNT; ++symbol)
                        if (name_length == strlen(yx_pattern_expression_symbols[symbol]) && !memcmp(name, yx_pattern_expression_symbols[symbol], name_length)) break;
                    if (symbol == YX_PATTERN_EXPRESSION_SYMBOL_COUNT || c->used[symbol]) return false;
                    c->used[symbol] = true;
                    c->ids[symbol] = tree->function_count++;
                    if (symbol == 0) tree->match_id = c->ids[symbol];
                    if ((symbol >= 8 && symbol < 14) || symbol >= 15) {
                        unsigned type = symbol < 14 ? symbol - 8 : symbol - 9;
                        tree->read_mask |= (uint16_t)(1u << type);
                        tree->read_ids[type] = c->ids[symbol];
                    }
                } else if (module_length == 6 && !memcmp(module, "yara_x", 6) && kind == 3) {
                    uint8_t type, mutable;
                    if (!yx_get_u8(r, &type) || !yx_get_u8(r, &mutable)) return false;
                    if (name_length == 29 && !memcmp(name, "matching_patterns_bitmap_base", 29) && type == 0x7f && !mutable) c->presence = true;
                    else if (name_length == 8 && !memcmp(name, "filesize", 8) && type == 0x7e && mutable == 1)
                        tree->has_filesize = true, tree->filesize_id = (uint8_t)global;
                    else if (name_length == 19 && !memcmp(name, "pattern_search_done", 19) && type == 0x7f && mutable == 1) c->search_global = (uint8_t)global;
                    else return false;
                    ++global;
                } else if (module_length == 6 && !memcmp(module, "yara_x", 6) && kind == 2 && name_length == 11 && !memcmp(name, "main_memory", 11)) {
                    if (!yx_rule_expression_byte(r, 0) || !yx_rule_expression_byte(r, 1)) return false;
                    tree->has_memory = true;
                } else return false;
            }
            if (r->at != end) return false;
        }
        r->at = end;
    }
    return false;
}

static yx_ser_result yx_decode_pattern_expression(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    size_t prefix, start, size, count, body_end;
    uint64_t width, functions, locals;
    uint8_t marker;
    yx_integer_expr *tree = calloc(1, sizeof(*tree));
    yx_pattern_expression_context c = {0};
    uint8_t *canonical = NULL, *base_wasm = NULL, *base = NULL, *normalized = NULL;
    size_t canonical_length = 0, base_wasm_length = 0, base_length = 0;
    yx_ser_rule *decoded = NULL;
    size_t decoded_count = 0;
    yx_ser_result status = YX_SER_UNSUPPORTED;
    yx_writer source = {0};
    if (!tree) return YX_SER_NO_MEMORY;
    if (!yx_rule_expression_wasm_span(data, length, &prefix, &start, &size, &count) || count != 1) goto done;
    yx_reader r = {data + start, size, 0, false, false};
    yx_pattern_expression_setup(tree, &c);
    if (!yx_pattern_expression_read_header(&r, tree, &c) || !yx_rule_expression_byte(&r, 10) || !yx_get_uleb(&r, &width) || width != size - r.at ||
        !yx_get_uleb(&r, &functions) || functions != (c.presence ? 4u : 3u) || !yx_get_uleb(&r, &width) || width > size - r.at)
        goto done;
    if (c.helper_first) {
        r.at += (size_t)width;
        if (!yx_get_uleb(&r, &width) || width > size - r.at) goto done;
    }
    body_end = r.at + (size_t)width;
    if (!yx_get_uleb(&r, &locals) || locals > 1 || (locals && (!yx_get_uleb(&r, &width) || width < 1 || width > 2 || !yx_get_u8(&r, &marker) || marker != 0x7e)) ||
        !yx_rule_expression_byte(&r, 2) || !yx_rule_expression_byte(&r, 0x7f))
        goto done;
    int root = yx_integer_wasm_block(&r, body_end, tree, 0, -1);
    if (root < 0 || !c.saw_pattern) goto done;
    if (!yx_unanchored_pattern_terms(data, length, tree, &root)) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    if (!yx_pattern_expression_scope_fixup(tree, &root, &c)) goto done;
    uint8_t profile = 4;
    int original_root = root;
    for (unsigned variant = 0; variant < 3 && profile == 4; ++variant) {
        root = variant ? yx_integer_expr_node_new(tree, variant == 1 ? 0xd8 : 0xd9, original_root, original_root, 0) : original_root;
        if (root < 0) goto done;
        for (profile = 0; profile < 5; ++profile) {
            free(canonical);
            canonical = NULL;
            c.capi_import_order = profile == 4;
            if (yx_pattern_expression_wasm(tree, root, &c, profile == 4 ? 0 : profile, &canonical, &canonical_length) && canonical_length == size &&
                !memcmp(canonical, data + start, size))
                break;
        }
        if (profile == 4) profile = 0;
        else if (profile == 5) profile = 4;
    }
    if (profile == 4) goto done;
    /* Anchored Literal sub-patterns: the base `$a` archive is unanchored and
     * the decoded condition restores the anchor. */
    uint8_t *plain = NULL;
    size_t plain_length = 0;
    if (c.pattern_count == 1) {
        yx_ser_result unanchored = yx_unconstrain_single_pattern_archive(data, length, tree, root, &plain, &plain_length);
        if (unanchored == YX_SER_NO_MEMORY) {
            status = unanchored;
            goto done;
        }
        if (unanchored == YX_SER_SUCCESS) {
            data = plain;
            length = plain_length;
        }
    }
    {
        size_t normalized_length;
        bool rewritten = yx_pattern_filesize_rewrite(tree, root, data, length, true, &normalized, &normalized_length);
        free(plain);
        if (!rewritten) goto done;
        data = normalized;
        length = normalized_length;
    }
    {
        size_t logical = 0, mapping[5] = {0};
        const uint8_t *raw_wasm;
        size_t raw_size;
        if (yx_text_envelope_read(data, length, &decoded, &logical, mapping, &raw_wasm, &raw_size)) {
            const char *names[5] = {decoded->pattern_identifier, decoded->second_pattern_identifier, decoded->third_pattern_identifier,
                                    decoded->fourth_pattern_identifier, decoded->fifth_pattern_identifier};
            decoded_count = 1;
            for (size_t i = 0; i < logical; ++i)
                if (!c.names[mapping[i]]) c.names[mapping[i]] = names[i];
            c.name = c.names[0];
            if (!yx_put_u8(&source, '(') || !yx_integer_expr_print(tree, root, &source, 0, false, 0) || !yx_put_u8(&source, ')')) goto done;
            for (size_t i = 0; i < logical; ++i)
                if (strcmp(c.names[mapping[i]], names[i]))
                    if (!yx_put_bytes(&source, " and (true or ", 14) || !yx_put_bytes(&source, names[i], strlen(names[i])) || !yx_put_u8(&source, ')')) goto done;
            if (!yx_put_u8(&source, 0)) goto done;
            decoded[0].runtime_integer_condition = (char *)source.data;
            source.data = NULL;
            decoded[0].runtime_integer_import_profile = profile;
            decoded[0].preserve_serialized_prefix = true;
            *rules = decoded;
            *rule_count = 1;
            decoded = NULL;
            status = YX_SER_SUCCESS;
            goto done;
        }
    }
    bool non_text = false;
    {
        size_t field_start, field_end, physical;
        unsigned regex_mask;
        if (!yx_pattern_filesize_span(data, length, &field_start, &field_end, &physical, &regex_mask)) goto done;
        non_text = regex_mask != 0;
        if (non_text) {
            uint8_t *limited = NULL;
            size_t limited_length = 0;
            if (!yx_pattern_limits_rewrite(data, length, c.limits, true, &limited, &limited_length)) goto done;
            free(normalized);
            normalized = limited;
            data = normalized;
            length = limited_length;
        }
    }
    if (c.pattern_count > 1) {
        const uint8_t *base_bytes = c.pattern_count == 2   ? yx_two_text_or_wasm
                                    : c.pattern_count == 3 ? yx_three_text_or_wasm
                                    : c.pattern_count == 4 ? yx_four_text_or_wasm
                                                           : yx_five_text_or_wasm;
        base_wasm_length = c.pattern_count == 2   ? sizeof(yx_two_text_or_wasm)
                           : c.pattern_count == 3 ? sizeof(yx_three_text_or_wasm)
                           : c.pattern_count == 4 ? sizeof(yx_four_text_or_wasm)
                                                  : sizeof(yx_five_text_or_wasm);
        base_wasm = malloc(base_wasm_length);
        if (!base_wasm) {
            status = YX_SER_NO_MEMORY;
            goto done;
        }
        memcpy(base_wasm, base_bytes, base_wasm_length);
    } else if (!non_text && (c.unlimited || c.match_limit > 1)) {
        yx_integer_expr *base_tree = calloc(1, sizeof(*base_tree));
        yx_pattern_expression_context base_context = {0};
        if (!base_tree) {
            status = YX_SER_NO_MEMORY;
            goto done;
        }
        base_context.name = "$a";
        yx_pattern_expression_setup(base_tree, &base_context);
        char base_condition[64];
        snprintf(base_condition, sizeof(base_condition), "#a > %" PRIu64, c.unlimited ? (uint64_t)UINT32_MAX : c.match_limit - 1);
        int base_root = yx_integer_expr_condition(base_tree, base_condition);
        bool ok = base_root >= 0 && yx_pattern_expression_wasm(base_tree, base_root, &base_context, 0, &base_wasm, &base_wasm_length);
        yx_integer_expr_free(base_tree);
        if (!ok) goto done;
    } else {
        base_wasm_length = sizeof(yx_single_text_pattern_wasm);
        base_wasm = malloc(base_wasm_length);
        if (!base_wasm) {
            status = YX_SER_NO_MEMORY;
            goto done;
        }
        memcpy(base_wasm, yx_single_text_pattern_wasm, base_wasm_length);
    }
    if (base_wasm_length == size && !memcmp(base_wasm, data + start, size)) goto done;
    if (!yx_rule_expression_replace_wasm(data, length, base_wasm, base_wasm_length, &base, &base_length)) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    status = yx_ser_decode_many(base, base_length, &decoded, &decoded_count);
    if (status != YX_SER_SUCCESS) goto done;
    if (decoded_count != 1) {
        status = YX_SER_UNSUPPORTED;
        goto done;
    }
    size_t decoded_patterns = decoded[0].five_text_patterns    ? 5
                              : decoded[0].four_text_patterns  ? 4
                              : decoded[0].three_text_patterns ? 3
                              : decoded[0].two_text_patterns   ? 2
                              : decoded[0].single_text_pattern ? 1
                                                               : 0;
    if (decoded_patterns != c.pattern_count) {
        status = YX_SER_UNSUPPORTED;
        goto done;
    }
    c.name = decoded[0].pattern_identifier;
    c.names[0] = decoded[0].pattern_identifier;
    c.names[1] = decoded[0].second_pattern_identifier;
    c.names[2] = decoded[0].third_pattern_identifier;
    c.names[3] = decoded[0].fourth_pattern_identifier;
    c.names[4] = decoded[0].fifth_pattern_identifier;
    if (!yx_integer_expr_print(tree, root, &source, 0, false, 0) || !yx_put_u8(&source, 0)) {
        status = YX_SER_NO_MEMORY;
        goto done;
    }
    decoded[0].runtime_integer_condition = (char *)source.data;
    source.data = NULL;
    decoded[0].runtime_integer_import_profile = profile;
    decoded[0].preserve_serialized_prefix = true;
    *rules = decoded;
    *rule_count = 1;
    decoded = NULL;
    status = YX_SER_SUCCESS;
done:
    yx_integer_expr_free(tree);
    free(canonical);
    free(base_wasm);
    free(base);
    free(normalized);
    free(source.data);
    yx_ser_rules_destroy(decoded, decoded_count);
    return status;
}
