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

/* Private numeric-expression codec, included by serialization.c after its
 * LEB128 and writer primitives. The expression tree preserves operator
 * precedence and reference constant-folding boundaries; emitted Wasm is
 * validated again byte for byte when reading an archive. */

#define YX_INTEGER_EXPR_LIMIT 1024
#define YX_ARCHIVE_MAX_VARS 2048
typedef struct yx_archive_binding {
    const unsigned char *name;
    size_t length;
    int value;
} yx_archive_binding;

static bool yx_archive_bindings_reserve(yx_archive_binding **bindings,
    size_t *capacity, size_t count)
{
    if (count <= *capacity) return true;
    if (count > YX_ARCHIVE_MAX_VARS) return false;
    size_t next = *capacity ? *capacity * 2 : 32;
    if (next < count) next = count;
    if (next > YX_ARCHIVE_MAX_VARS) next = YX_ARCHIVE_MAX_VARS;
    yx_archive_binding *grown = realloc(*bindings, next * sizeof(*grown));
    if (!grown) return false;
    *bindings = grown; *capacity = next;
    return true;
}
enum { YX_INTEGER_READ_COUNT=16 };
static const char *yx_integer_codec_read_name(uint8_t type)
{
    static const char *const names[YX_INTEGER_READ_COUNT]={
        "uint8","uint16","uint32","int8","int16","int32","uint64","int64",
        "uint8be","uint16be","uint32be","uint64be","int8be","int16be","int32be","int64be"
    };
    return type<YX_INTEGER_READ_COUNT?names[type]:NULL;
}
static const char *yx_integer_codec_read_import_name(uint8_t type)
{
    static const char *const names[YX_INTEGER_READ_COUNT-6]={
        "uint64@offset:i64@u64u","int64@offset:i64@i64u",
        "uint8be@offset:i64@u8u","uint16be@offset:i64@u16u",
        "uint32be@offset:i64@u32u","uint64be@offset:i64@u64u",
        "int8be@offset:i64@i8u","int16be@offset:i64@i16u",
        "int32be@offset:i64@i32u","int64be@offset:i64@i64u"
    };
    return type<6?yx_integer_read_import_name(type):
        type<YX_INTEGER_READ_COUNT?names[type-6]:NULL;
}

typedef struct yx_integer_expr_node {
    int left, right, extra;
    uint8_t op;
    bool constant, floating, unsigned_value;
    int64_t value;
    double real;
} yx_integer_expr_node;

typedef struct yx_integer_expr {
    yx_bool_parser parser;
    yx_integer_expr_node nodes[YX_INTEGER_EXPR_LIMIT];
    yx_integer_expr_node *extra_nodes;size_t node_capacity;
    size_t count;
    bool failed, has_filesize, has_shift, has_divisor, has_memory, has_loop, small_shift;
    /* Used only when matching an older private physical condition stream. */
    bool legacy_boolean_or;
    uint16_t read_mask;
    uint8_t read_ids[YX_INTEGER_READ_COUNT], match_id, function_count, filesize_id;
    bool stop_call_active;
    unsigned stop_call;
    int second_argument;
    bool stop_loop_bounds,stop_loop_body;
    int stop_loop_slot;
    uint64_t defined_variables[YX_ARCHIVE_MAX_VARS / 64];
    uint64_t unsigned_variables[YX_ARCHIVE_MAX_VARS / 64];
    yx_archive_binding *bindings;
    size_t binding_count, binding_capacity;
    /* Loop-shaped decodes of a block that already failed (see below). */
    struct yx_loop_failure *loop_failures;
    size_t loop_failure_count, loop_failure_capacity;
    /* Optional typed leaves supplied by other archive expression domains. */
    void *extension;
    void (*boolean_scope)(void *, bool);
    int (*parse_primary)(struct yx_integer_expr *, unsigned, void *);
    bool (*emit_primary)(const struct yx_integer_expr *, int, yx_writer *, unsigned, int, bool, void *);
    bool (*resource_primary)(struct yx_integer_expr *, int, void *);
    bool (*print_primary)(const struct yx_integer_expr *, int, yx_writer *, void *);
    int (*decode_primary)(yx_reader *, size_t, struct yx_integer_expr *, void *);
    int (*decode_boolean_block)(struct yx_integer_expr *, int, void *);
} yx_integer_expr;

/* Reserve before recursive parsing/decoding so node pointers remain stable
 * throughout a walk. Small trees use the inline storage without allocation. */
#define YX_INTEGER_NODES(tree) ((tree)->extra_nodes?(tree)->extra_nodes:(tree)->nodes)
static bool yx_integer_expr_reserve(yx_integer_expr *tree,size_t count)
{
    size_t capacity=tree->extra_nodes?tree->node_capacity:YX_INTEGER_EXPR_LIMIT;
    if(count<=capacity)return true;
    if(count>INT_MAX||count>SIZE_MAX/sizeof(*tree->extra_nodes))return false;
    /* Grow geometrically: composition reserves once per joined rule. */
    if(tree->extra_nodes&&count<capacity*2&&capacity*2<=INT_MAX)count=capacity*2;
    yx_integer_expr_node *nodes=calloc(count,sizeof(*nodes));if(!nodes)return false;
    memcpy(nodes,YX_INTEGER_NODES(tree),tree->count*sizeof(*nodes));
    free(tree->extra_nodes);tree->extra_nodes=nodes;tree->node_capacity=count;return true;
}
static void yx_integer_expr_destroy(yx_integer_expr *tree)
{ if(tree){free(tree->extra_nodes);tree->extra_nodes=NULL;tree->node_capacity=0;
    free(tree->bindings);tree->bindings=NULL;tree->binding_capacity=0;
    free(tree->loop_failures);tree->loop_failures=NULL;tree->loop_failure_count=tree->loop_failure_capacity=0;} }
static void yx_integer_expr_free(yx_integer_expr *tree)
{ yx_integer_expr_destroy(tree);free(tree); }
static bool yx_integer_expr_boolean(uint8_t op)
{
    return op == 0x41 || (op >= 0x51 && op <= 0x59) ||
           (op >= 0xa0 && op <= 0xa2) || op == 0xc0 || (op >= 0xc4 && op <= 0xc6) || op == 0xd0 || op == 0xd1 || op == 0xd5 || op == 0xd6 || op == 0xda;
}

/* Only Uint64 keeps unsigned arithmetic in the upstream IR. Narrow unsigned
 * readers promote to signed i64, but remain known non-negative comparisons. */
static bool yx_integer_expr_non_negative(const yx_integer_expr_node *node)
{
    return node->unsigned_value || (node->constant && node->value >= 0) ||
        node->op == 0xb0 || node->op == 0xb1 || node->op == 0xb2 ||
        node->op == 0xb8 || node->op == 0xb9 || node->op == 0xba;
}

static bool yx_integer_comparison_mixed(bool left_unsigned, bool right_unsigned,
                                        bool left_non_negative, bool right_non_negative)
{
    return left_unsigned != right_unsigned &&
        !(left_unsigned ? right_non_negative : left_non_negative);
}

static bool yx_integer_comparison_emit(yx_writer *writer, uint8_t op,
    bool left_unsigned, bool right_unsigned, bool left_non_negative, bool right_non_negative)
{
    if (!left_unsigned && !right_unsigned) return yx_put_u8(writer, op);
    uint8_t unsigned_op = op >= 0x53 ? (uint8_t)(op + 1) : op;
    if (!yx_integer_comparison_mixed(left_unsigned, right_unsigned,
            left_non_negative, right_non_negative)) return yx_put_u8(writer, unsigned_op);
    bool negative_result = op == 0x52 ||
        ((op == 0x53 || op == 0x57) && !left_unsigned) ||
        ((op == 0x55 || op == 0x59) && !right_unsigned);
    static const uint8_t save[] = {0x21,1,0x22,0,0x20,1};
    return yx_put_bytes(writer, save, sizeof(save)) && yx_put_u8(writer, unsigned_op) &&
        yx_put_u8(writer, 0x20) && yx_put_u8(writer, left_unsigned ? 1 : 0) &&
        yx_put_u8(writer, 0x42) && yx_put_u8(writer, 0) &&
        yx_put_u8(writer, negative_result ? 0x53 : 0x59) &&
        yx_put_u8(writer, negative_result ? 0x72 : 0x71);
}

/* Parse all u64 literal bits without narrowing through a signed magnitude. */
static bool yx_integer_archive_literal(yx_bool_parser *parser, int64_t *value, bool *is_unsigned)
{
    const unsigned char *start = parser->at;
    uint64_t bits = 0; unsigned base = 10; bool digits = false;
    if (yx_integer_literal(parser, value)) { *is_unsigned = false; return true; }
    parser->at = start; yx_bool_skip_space(parser);
    if (parser->at[0] == '0' && (parser->at[1] == 'x' || parser->at[1] == 'X')) {
        parser->at += 2; base = 16;
    } else if (parser->at[0] == '0' && (parser->at[1] == 'o' || parser->at[1] == 'O')) {
        parser->at += 2; base = 8;
    }
    for (;;) {
        unsigned char c = *parser->at;
        unsigned digit = c >= '0' && c <= '9' ? c - '0' :
            base == 16 && c >= 'a' && c <= 'f' ? c - 'a' + 10 :
            base == 16 && c >= 'A' && c <= 'F' ? c - 'A' + 10 : 255;
        if (digit >= base) break;
        if (bits > (UINT64_MAX - digit) / base) { parser->at = start; return false; }
        bits = bits * base + digit; digits = true; ++parser->at;
    }
    if (!digits || bits <= INT64_MAX) { parser->at = start; return false; }
    *value = yx_integer_signed_bits(bits); *is_unsigned = true; return true;
}

/* IR::add/sub/mul/div/minus fold Float constants without a range check (ir/mod.rs fold_arithmetic, fold_div), so
 * a folded constant may be an infinity or the default NaN of either sign. The archive source text spells those
 * four values as the divisions that produce them. */
static const char *yx_float_special_source(double value)
{
    uint64_t bits; memcpy(&bits, &value, sizeof(bits));
    if (bits == UINT64_C(0x7ff0000000000000)) return "(1.0\\0.0)";
    if (bits == UINT64_C(0xfff0000000000000)) return "(-1.0\\0.0)";
    if (bits == UINT64_C(0xfff8000000000000)) return "(0.0\\0.0)";
    if (bits == UINT64_C(0x7ff8000000000000)) return "(-(0.0\\0.0))";
    return NULL;
}
static bool yx_float_representable(double value)
{ return isfinite(value) || yx_float_special_source(value) != NULL; }

static int yx_integer_expr_node_new(yx_integer_expr *tree, uint8_t op,
                                     int left, int right, int64_t value)
{
    yx_integer_expr_node *node;
    int index;
    if (tree->failed || tree->count == (tree->extra_nodes?tree->node_capacity:YX_INTEGER_EXPR_LIMIT) ||
        (op != 0x41 && op != 0x42 && op != 0x44 && op != 0x23 && op != 0xc2 && op != 0xc3 && op < 0xd0 && (left < 0 || right < 0))) {
        tree->failed = true;
        return -1;
    }
    index = (int)tree->count++;
    node = &YX_INTEGER_NODES(tree)[index];
    node->op = op; node->left = left; node->right = right; node->extra = -1;
    node->constant = op == 0x41 || op == 0x42 || op == 0x44; node->value = value;
    node->floating = op == 0x44 || (left >= 0 && right >= 0 &&
        !yx_integer_expr_boolean(op) && (YX_INTEGER_NODES(tree)[left].floating || YX_INTEGER_NODES(tree)[right].floating));
    node->unsigned_value = op == 0xb6 || op == 0xbb ||
        (!node->floating && !yx_integer_expr_boolean(op) && left >= 0 && right >= 0 &&
         (YX_INTEGER_NODES(tree)[left].unsigned_value ||
          ((op != 0x86 && op != 0x87) && YX_INTEGER_NODES(tree)[right].unsigned_value)));
    if (node->floating && op != 0x44 && op != 0xc1 &&
        op != 0x7c && op != 0x7d && op != 0x7e && op != 0x7f) goto unsupported;
    if (node->floating && op != 0x44 &&
        YX_INTEGER_NODES(tree)[left].constant && YX_INTEGER_NODES(tree)[right].constant) {
        double a = YX_INTEGER_NODES(tree)[left].floating ? YX_INTEGER_NODES(tree)[left].real : (YX_INTEGER_NODES(tree)[left].unsigned_value ? (double)(uint64_t)YX_INTEGER_NODES(tree)[left].value : (double)YX_INTEGER_NODES(tree)[left].value);
        double b = YX_INTEGER_NODES(tree)[right].floating ? YX_INTEGER_NODES(tree)[right].real : (YX_INTEGER_NODES(tree)[right].unsigned_value ? (double)(uint64_t)YX_INTEGER_NODES(tree)[right].value : (double)YX_INTEGER_NODES(tree)[right].value);
        node->real = op == 0x7c ? a + b : op == 0x7d ? a - b : op == 0x7e ? a * b : op == 0x7f ? a / b : -a;
        if (!yx_float_representable(node->real)) goto unsupported;
        node->constant = true;
    }
    if (op == 0x23) tree->has_filesize = true;
    if (op == 0xc0 || op == 0xc2 || op == 0xc3) tree->has_memory = true;
    if ((op == 0x7f || op == 0x81) && !node->floating) tree->has_divisor = true;
    if (op >= 0xb0 && op < 0xc0) tree->read_mask |= (uint16_t)(1u << (op - 0xb0));
    if (op == 0xa0 || op == 0xa1) {
        const yx_integer_expr_node *a = &YX_INTEGER_NODES(tree)[left], *b = &YX_INTEGER_NODES(tree)[right];
        bool absorbing = op == 0xa1;
        if ((a->constant && yx_integer_expr_boolean(a->op) && !!a->value == absorbing) ||
            (b->constant && yx_integer_expr_boolean(b->op) && !!b->value == absorbing)) {
            node->constant = true; node->value = absorbing;
        }
    }
    if (op < 0xd0 && op != 0x41 && op != 0x42 && op != 0x44 && op != 0x23 && op != 0xc0 && op != 0xc2 && op != 0xc3 &&
        !YX_INTEGER_NODES(tree)[left].floating && !YX_INTEGER_NODES(tree)[right].floating &&
        YX_INTEGER_NODES(tree)[left].constant && YX_INTEGER_NODES(tree)[right].constant) {
        int64_t a = YX_INTEGER_NODES(tree)[left].value, b = YX_INTEGER_NODES(tree)[right].value;
        if (node->unsigned_value) {
            uint64_t x = (uint64_t)a, y = (uint64_t)b, bits;
            switch (op) {
            case 0x7c: bits = x + y; break;
            case 0x7d: bits = x - y; break;
            case 0x7e: bits = x * y; break;
            case 0x7f: if (!y) return index; bits = x / y; break;
            case 0x81: if (!y) return index; bits = x % y; break;
            case 0x83: bits = x & y; break;
            case 0x84: bits = x | y; break;
            case 0x85: bits = x ^ y; break;
            case 0x86: bits = y >= 64 ? 0 : x << (unsigned)y; break;
            case 0x87: bits = y >= 64 ? 0 : x >> (unsigned)y; break;
            default: return index;
            }
            node->constant = true; node->value = yx_integer_signed_bits(bits);
            return index;
        }
        switch (op) {
        case 0xa0: value = a && b; break;
        case 0xa1: value = a || b; break;
        case 0xa2: value = !a; break;
        case 0x7c:
            if ((b > 0 && a > INT64_MAX - b) ||
                (b < 0 && a < INT64_MIN - b)) goto unsupported;
            value = a + b; break;
        case 0x7d:
            if ((b < 0 && a > INT64_MAX + b) ||
                (b > 0 && a < INT64_MIN + b)) goto unsupported;
            value = a - b; break;
        case 0x7e:
            if ((a > 0 && b > 0 && a > INT64_MAX / b) ||
                (a > 0 && b < 0 && b < INT64_MIN / a) ||
                (a < 0 && b > 0 && a < INT64_MIN / b) ||
                (a < 0 && b < 0 && a < INT64_MAX / b)) goto unsupported;
            value = a * b; break;
        case 0x7f:
            if (!b || (a == INT64_MIN && b == -1)) return index;
            value = a / b; break;
        case 0x81:
            if (!b) return index;
            value = a == INT64_MIN && b == -1 ? 0 : a % b; break;
        case 0x83: value = a & b; break;
        case 0x84: value = a | b; break;
        case 0x85: value = a ^ b; break;
        case 0x86: case 0x87: {
            uint64_t bits = (uint64_t)a;
            if (b < 0) goto unsupported;
            if (b >= 64) bits = 0;
            else if (op == 0x86) bits <<= (unsigned)b;
            else if (b) {
                bits >>= (unsigned)b;
                if (a < 0) bits |= UINT64_MAX << (64u - (unsigned)b);
            }
            value = yx_integer_signed_bits(bits);
            break;
        }
        default: return index;
        }
        node->constant = true; node->value = value;
    }
    if ((op == 0x86 || op == 0x87) && !node->constant) tree->has_shift = true;
    return index;
unsupported:
    tree->failed = true;
    return -1;
}

static int yx_integer_expr_real(yx_integer_expr *tree, double value)
{
    int node;
    if (!yx_float_representable(value)) return -1;
    node = yx_integer_expr_node_new(tree, 0x44, -1, -1, 0);
    if (node >= 0) YX_INTEGER_NODES(tree)[node].real = value;
    return node;
}

static unsigned yx_integer_expr_precedence(uint8_t op)
{
    switch (op) {
    case 0x84: return 1;
    case 0x85: return 2;
    case 0x83: return 3;
    case 0x86: case 0x87: return 4;
    case 0x7c: case 0x7d: return 5;
    case 0x7e: case 0x7f: case 0x81: return 6;
    default: return 0;
    }
}

static int yx_integer_expr_parse(yx_integer_expr *tree, unsigned minimum,
                                  unsigned depth);

static int yx_integer_expr_primary(yx_integer_expr *tree, unsigned depth)
{
    const unsigned char *start;
    int64_t value;
    int node, operand, constant;
    unsigned char token;
    if (depth > 256) { tree->failed = true; return -1; }
    yx_bool_skip_space(&tree->parser);
    if (yx_bool_keyword(&tree->parser, "filesize"))
        return yx_integer_expr_node_new(tree, 0x23, -1, -1, 0);
    for (uint8_t type = 0; type < YX_INTEGER_READ_COUNT; ++type) {
        if (!yx_bool_keyword(&tree->parser, yx_integer_codec_read_name(type))) continue;
        yx_bool_skip_space(&tree->parser);
        if (*tree->parser.at != '(') return -1;
        ++tree->parser.at;
        operand = yx_integer_expr_parse(tree, 1, depth + 1);
        yx_bool_skip_space(&tree->parser);
        if (operand < 0 || *tree->parser.at != ')') return -1;
        ++tree->parser.at;
        return yx_integer_expr_node_new(tree, (uint8_t)(0xb0 + type), operand, operand, 0);
    }
    start = tree->parser.at;
    {
        const unsigned char *name;
        size_t length;
        if (yx_with_identifier(&tree->parser, &name, &length)) {
            for (size_t i = tree->binding_count; i > 0; --i)
                if (tree->bindings[i - 1].length == length &&
                    !memcmp(tree->bindings[i - 1].name, name, length))
                    return tree->bindings[i - 1].value;
        }
        tree->parser.at = start;
    }
    if (tree->parse_primary) {
        start = tree->parser.at;
        node = tree->parse_primary(tree, depth, tree->extension);
        if (node >= 0) return node;
        tree->parser.at = start;
        if (tree->failed) return -1;
    }
    start = tree->parser.at;
    if ((*start >= '0' && *start <= '9') || *start == '-' || *start == '+') {
        char *end;
        double real = strtod((const char *)start, &end);
        const unsigned char *digits = (*start == '-' || *start == '+') ? start + 1 : start;
        bool is_real = false;
        for (const char *at = (const char *)start; at < end; ++at)
            if ((*at == '.' && at[1] != '.' && (at == (const char *)start || at[-1] != '.')) || *at == 'e' || *at == 'E') is_real = true;
        if (is_real && !(digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X'))) {
            tree->parser.at = (const unsigned char *)end;
            return yx_integer_expr_real(tree, real);
        }
    }
    bool is_unsigned;
    if (yx_integer_archive_literal(&tree->parser, &value, &is_unsigned)) {
        node = yx_integer_expr_node_new(tree, 0x42, -1, -1, value);
        if (node >= 0) YX_INTEGER_NODES(tree)[node].unsigned_value = is_unsigned;
        return node;
    }
    tree->parser.at = start;
    token = *start;
    if (token == '(') {
        ++tree->parser.at;
        node = yx_integer_expr_parse(tree, 1, depth + 1);
        yx_bool_skip_space(&tree->parser);
        if (node < 0 || *tree->parser.at != ')') return -1;
        ++tree->parser.at;
        return node;
    }
    if (token != '-' && token != '+' && token != '~') return -1;
    ++tree->parser.at;
    operand = yx_integer_expr_primary(tree, depth + 1);
    if (operand < 0 || token == '+') return operand;
    if (token == '-' && YX_INTEGER_NODES(tree)[operand].floating)
        return yx_integer_expr_node_new(tree, 0xc1, operand, operand, 0);
    constant = yx_integer_expr_node_new(tree, 0x42, -1, -1,
                                        token == '-' ? 0 : -1);
    return token == '-'
        ? yx_integer_expr_node_new(tree, 0x7d, constant, operand, 0)
        : yx_integer_expr_node_new(tree, 0x85, operand, constant, 0);
}

static int yx_integer_expr_parse(yx_integer_expr *tree, unsigned minimum,
                                  unsigned depth)
{
    int left = yx_integer_expr_primary(tree, depth);
    while (left >= 0) {
        uint8_t op = 0;
        unsigned width = 1, precedence;
        int right;
        yx_bool_skip_space(&tree->parser);
        switch (*tree->parser.at) {
        case '|': op = 0x84; break;
        case '^': op = 0x85; break;
        case '&': op = 0x83; break;
        case '+': op = 0x7c; break;
        case '-': op = 0x7d; break;
        case '*': op = 0x7e; break;
        case '\\': op = 0x7f; break;
        case '%': op = 0x81; break;
        case '<': case '>':
            if (tree->parser.at[0] == tree->parser.at[1]) {
                op = *tree->parser.at == '<' ? 0x86 : 0x87;
                width = 2;
            }
            break;
        }
        precedence = yx_integer_expr_precedence(op);
        if (precedence < minimum) break;
        tree->parser.at += width;
        right = yx_integer_expr_parse(tree, precedence + 1, depth + 1);
        left = yx_integer_expr_node_new(tree, op, left, right, 0);
    }
    return left;
}

static int yx_integer_expr_boolean_parse(yx_integer_expr *tree, unsigned level,
                                          unsigned depth);

/* Upstream only allocates an undefinedness bit for a with declaration when
 * its initializer can throw. Counts, presence checks and prior-rule values
 * are defined, while offsets, readers and filesize can be undefined. */
static bool yx_integer_expr_defined(const yx_integer_expr *tree,int index,unsigned depth)
{
    if(index<0||depth>256)return false;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->constant)return true;
    if(n->op==0x23||n->op==0xc0||n->op==0xc2||n->op==0xd3||n->op==0xd4||
       (n->op>=0xb0&&n->op<0xc0)||n->op==0x7f||n->op==0x81)return false;
    if(n->op==0xa0||n->op==0xa1||n->op==0xa2)return true;
    return (n->left<0||yx_integer_expr_defined(tree,n->left,depth+1))&&
        (n->right<0||n->right==n->left||yx_integer_expr_defined(tree,n->right,depth+1))&&
        (n->extra<0||yx_integer_expr_defined(tree,n->extra,depth+1));
}

static int yx_integer_expr_with(yx_integer_expr *tree, unsigned depth)
{
    size_t first = tree->binding_count, count = 0;
    int *values = malloc(YX_ARCHIVE_MAX_VARS * sizeof(*values));
    int body = -1;
    if (!values) return -1;
    for (;;) {
        const unsigned char *name;
        size_t length;
        if (!yx_archive_bindings_reserve(&tree->bindings, &tree->binding_capacity,
                tree->binding_count + 1) ||
            !yx_with_identifier(&tree->parser, &name, &length)) goto done;
        yx_bool_skip_space(&tree->parser);
        if (*tree->parser.at++ != '=') goto done;
        int left = yx_integer_expr_parse(tree, 1, depth + 1);
        if (left < 0 || yx_integer_expr_boolean(YX_INTEGER_NODES(tree)[left].op)) goto done;
        values[count++] = left;
        tree->bindings[tree->binding_count].name = name;
        tree->bindings[tree->binding_count].length = length;
        if (YX_INTEGER_NODES(tree)[left].constant) tree->bindings[tree->binding_count].value = left;
        else {
            int variable = yx_integer_expr_node_new(tree,
                yx_integer_expr_defined(tree,left,0)?0xc3:0xc2, -1, -1, (int64_t)tree->binding_count);
            if (variable < 0) goto done;
            YX_INTEGER_NODES(tree)[variable].floating = YX_INTEGER_NODES(tree)[left].floating;
            YX_INTEGER_NODES(tree)[variable].unsigned_value = YX_INTEGER_NODES(tree)[left].unsigned_value;
            tree->bindings[tree->binding_count].value = variable;
        }
        ++tree->binding_count;
        yx_bool_skip_space(&tree->parser);
        if (*tree->parser.at != ',') break;
        ++tree->parser.at;
    }
    if (*tree->parser.at++ != ':') goto done;
    yx_bool_skip_space(&tree->parser);
    if (*tree->parser.at++ != '(') goto done;
    body = yx_integer_expr_boolean_parse(tree, 0, depth + 1);
    yx_bool_skip_space(&tree->parser);
    if (body < 0 || *tree->parser.at++ != ')') { body = -1; goto done; }
    for (size_t i = count; i > 0; --i)
        body = yx_integer_expr_node_new(tree, 0xc0, values[i - 1], body,
                                         (int64_t)(first + i - 1));
done:
    tree->binding_count = first;
    free(values);
    return body;
}

static int yx_integer_expr_boolean_primary(yx_integer_expr *tree, unsigned depth)
{
    const unsigned char *start;
    size_t saved_count;
    int left, right;
    uint8_t op;
    unsigned width;
    if (depth > 256) return -1;
    yx_bool_skip_space(&tree->parser);
    if (yx_bool_keyword(&tree->parser, "for")) {
        const unsigned char *name;
        size_t length, first = tree->binding_count;
        int lower, upper, body, variable, loop;
        uint8_t quantifier;
        if (yx_bool_keyword(&tree->parser, "any")) quantifier = 0xc4;
        else if (yx_bool_keyword(&tree->parser, "all")) quantifier = 0xc5;
        else if (yx_bool_keyword(&tree->parser, "none")) quantifier = 0xc6;
        else return -1;
        if (!yx_archive_bindings_reserve(&tree->bindings, &tree->binding_capacity, first + 7) ||
            !yx_with_identifier(&tree->parser, &name, &length) ||
            !yx_bool_keyword(&tree->parser, "in")) return -1;
        yx_bool_skip_space(&tree->parser);
        if (*tree->parser.at++ != '(') return -1;
        lower = yx_integer_expr_parse(tree, 1, depth + 1);
        yx_bool_skip_space(&tree->parser);
        if (lower < 0 || YX_INTEGER_NODES(tree)[lower].floating || tree->parser.at[0] != '.' || tree->parser.at[1] != '.') return -1;
        tree->parser.at += 2;
        upper = yx_integer_expr_parse(tree, 1, depth + 1);
        yx_bool_skip_space(&tree->parser);
        if (upper < 0 || YX_INTEGER_NODES(tree)[upper].floating || *tree->parser.at++ != ')') return -1;
        if (YX_INTEGER_NODES(tree)[lower].constant && YX_INTEGER_NODES(tree)[upper].constant &&
            YX_INTEGER_NODES(tree)[lower].value > YX_INTEGER_NODES(tree)[upper].value) return -1;
        yx_bool_skip_space(&tree->parser);
        if (*tree->parser.at++ != ':') return -1;
        yx_bool_skip_space(&tree->parser);
        if (*tree->parser.at++ != '(') return -1;
        memset(tree->bindings + first, 0, 7 * sizeof(tree->bindings[0]));
        variable = yx_integer_expr_node_new(tree, 0xc3, -1, -1, (int64_t)first + 5);
        if (variable < 0) return -1;
        tree->binding_count = first + 7;
        tree->bindings[first + 5].name = name;
        tree->bindings[first + 5].length = length;
        tree->bindings[first + 5].value = variable;
        body = yx_integer_expr_boolean_parse(tree, 0, depth + 1);
        yx_bool_skip_space(&tree->parser);
        tree->binding_count = first;
        if (body < 0 || *tree->parser.at++ != ')') return -1;
        loop = yx_integer_expr_node_new(tree, quantifier, lower, upper, (int64_t)first);
        if (loop >= 0) YX_INTEGER_NODES(tree)[loop].extra = body;
        return loop;
    }
    if (yx_bool_keyword(&tree->parser, "with")) {
        return yx_integer_expr_with(tree, depth);
    }
    if (yx_bool_keyword(&tree->parser, "not")) {
        left = yx_integer_expr_boolean_primary(tree, depth + 1);
        return yx_integer_expr_node_new(tree, 0xa2, left, left, 0);
    }
    if (yx_bool_keyword(&tree->parser, "true"))
        return yx_integer_expr_node_new(tree, 0x41, -1, -1, 1);
    if (yx_bool_keyword(&tree->parser, "false"))
        return yx_integer_expr_node_new(tree, 0x41, -1, -1, 0);
    start = tree->parser.at; saved_count = tree->count;
    left = yx_integer_expr_parse(tree, 1, depth + 1);
    if (left < 0) {
        tree->parser.at = start; tree->count = saved_count; tree->failed = false;
        if (*tree->parser.at != '(') return -1;
        ++tree->parser.at;
        left = yx_integer_expr_boolean_parse(tree, 0, depth + 1);
        yx_bool_skip_space(&tree->parser);
        if (left < 0 || *tree->parser.at != ')') return -1;
        ++tree->parser.at;
        return left;
    }
    yx_bool_skip_space(&tree->parser);
    width = 1;
    if (tree->parser.at[0] == '=' && tree->parser.at[1] == '=') { op = 0x51; width = 2; }
    else if (tree->parser.at[0] == '!' && tree->parser.at[1] == '=') { op = 0x52; width = 2; }
    else if (tree->parser.at[0] == '<' && tree->parser.at[1] == '=') { op = 0x57; width = 2; }
    else if (tree->parser.at[0] == '>' && tree->parser.at[1] == '=') { op = 0x59; width = 2; }
    else if (tree->parser.at[0] == '<') op = 0x53;
    else if (tree->parser.at[0] == '>') op = 0x55;
    else return left;
    tree->parser.at += width;
    right = yx_integer_expr_parse(tree, 1, depth + 1);
    return yx_integer_expr_node_new(tree, op, left, right, 0);
}

static int yx_integer_expr_boolean_parse(yx_integer_expr *tree, unsigned level,
                                          unsigned depth)
{
    int left, right;
    if (depth > 256) return -1;
    if (level == 2) return yx_integer_expr_boolean_primary(tree, depth + 1);
    left = yx_integer_expr_boolean_parse(tree, level + 1, depth + 1);
    while (left >= 0 && yx_bool_keyword(&tree->parser, level ? "and" : "or")) {
        right = yx_integer_expr_boolean_parse(tree, level + 1, depth + 1);
        left = yx_integer_expr_node_new(tree, level ? 0xa0 : 0xa1, left, right, 0);
    }
    return left;
}

static int yx_integer_expr_condition(yx_integer_expr *tree, const char *condition)
{
    int root;size_t length=strlen(condition);
    if(length>(SIZE_MAX-tree->count)/2||!yx_integer_expr_reserve(tree,tree->count+length*2))return -1;
    tree->parser.at = (const unsigned char *)condition;
    root = yx_integer_expr_boolean_parse(tree, 0, 0);
    yx_bool_skip_space(&tree->parser);
    return root >= 0 && !tree->failed && !*tree->parser.at ? root : -1;
}

static const uint8_t yx_integer_divisor_guard[] = {
    0x22, 0x00, 0x50, 0x04, 0x7e, 0x41, 0x00, 0x0c,
    0x01, 0x05, 0x20, 0x00, 0x0b
};

static const uint8_t yx_integer_filesize_read[] = {
    0x23,0x00,0x22,0x00,0x42,0x00,0x53,0x04,0x7e,
    0x41,0x00,0x0c,0x01,0x05,0x20,0x00,0x0b
};

static const uint8_t yx_integer_shift_prefix[] = {
    0x21,0x01,0x21,0x00,0x20,0x01,0x42,0xc0,0x00,0x53,
    0x04,0x7e,0x20,0x00,0x20,0x01
};
static const uint8_t yx_integer_shift_suffix[] = {0x05,0x42,0x00,0x0b};
static const uint8_t yx_integer_read_guard[] = {0x04,0x40,0x41,0x00,0x0c,0x01,0x05,0x0b};

/* A handler `extra` blocks further out than the guard's usual position (an
 * emit_switch branch, emit_for's loop block): the slot that
 * yx_integer_undefined_shift(slot, extra) returns writes the catch code of
 * `slot` with every branch depth raised by `extra` (INT_MIN when it cannot). */
#define YX_UNDEFINED_SHIFT_BASE 0x10000000
static int yx_integer_undefined_shift(int slot, unsigned extra)
{
    if (slot <= -YX_UNDEFINED_SHIFT_BASE) {
        unsigned packed = (unsigned)(-(slot + YX_UNDEFINED_SHIFT_BASE));
        extra += packed >> 16;
        slot = (int)(packed & 0xffff) - 64;
    }
    if (!extra) return slot;
    if (extra > 0xfff || slot < -64 || slot >= 0xffff - 64) return INT_MIN;
    return -YX_UNDEFINED_SHIFT_BASE - (int)(extra << 16) - (slot + 64);
}
static bool yx_integer_emit_undefined(yx_writer *writer, int slot)
{
    if (slot <= -YX_UNDEFINED_SHIFT_BASE) {
        unsigned packed = (unsigned)(-(slot + YX_UNDEFINED_SHIFT_BASE)), extra = packed >> 16;
        int base = (int)(packed & 0xffff) - 64;
        if (slot == INT_MIN) return false;
        if (base == -34) return yx_put_u8(writer, 0x0c) && yx_put_uleb(writer, 1 + extra);
        if (base == -33)
            return yx_put_bytes(writer, "\x41\x00\x0c", 3) && yx_put_uleb(writer, 2 + extra) &&
                yx_put_u8(writer, 0x0c) && yx_put_uleb(writer, 1 + extra);
        if (base < 0)
            return yx_put_u8(writer, base == -2 ? 0x42 : 0x41) && yx_put_u8(writer, 0) &&
                yx_put_u8(writer, 0x0c) && yx_put_uleb(writer, (base < -2 ? (unsigned)(-base - 1) : 1u) + extra);
        return base < YX_ARCHIVE_MAX_VARS &&
            yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, base / 8) &&
            yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, base / 8) &&
            yx_put_bytes(writer, "\x2d\x00\x00\x41", 4) &&
            yx_put_sleb_i64(writer, INT64_C(1) << (base % 8)) &&
            yx_put_bytes(writer, "\x72\x3a\x00\x00\x0c", 5) && yx_put_uleb(writer, 1 + extra);
    }
    if(slot==-34)return yx_put_bytes(writer,"\x0c\x01",2);
    if(slot==-33)return yx_put_bytes(writer,"\x41\x00\x0c\x02\x0c\x01",6);
    if (slot < 0) return yx_put_u8(writer, slot == -2 ? 0x42 : 0x41) && yx_put_u8(writer, 0) &&
        yx_put_u8(writer, 0x0c) && yx_put_u8(writer, slot < -2 ? (uint8_t)(-slot - 1) : 1);
    return slot < YX_ARCHIVE_MAX_VARS &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, slot / 8) &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, slot / 8) &&
        yx_put_bytes(writer, "\x2d\x00\x00\x41", 4) &&
        yx_put_sleb_i64(writer, INT64_C(1) << (slot % 8)) &&
        yx_put_bytes(writer, "\x72\x3a\x00\x00\x0c\x01", 6);
}

static bool yx_integer_clear_variable(yx_writer *writer, int64_t slot)
{
    return slot >= 0 && slot < YX_ARCHIVE_MAX_VARS &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, slot / 8) &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, slot / 8) &&
        yx_put_bytes(writer, "\x2d\x00\x00\x41", 4) &&
        yx_put_sleb_i64(writer, ~(INT64_C(1) << (slot % 8))) &&
        yx_put_bytes(writer, "\x71\x3a\x00\x00", 4);
}

static bool yx_integer_emit_guard(yx_writer *writer, uint8_t kind, int slot)
{
    const uint8_t *bytes = kind == 0x23 ? yx_integer_filesize_read :
        kind == 0x22 ? yx_integer_divisor_guard : yx_integer_read_guard;
    size_t length = kind == 0x23 ? sizeof(yx_integer_filesize_read) :
        kind == 0x22 ? sizeof(yx_integer_divisor_guard) : sizeof(yx_integer_read_guard);
    size_t prefix = kind == 0x23 ? 9 : kind == 0x22 ? 5 : 2;
    return yx_put_bytes(writer, bytes, prefix) && yx_integer_emit_undefined(writer, slot) &&
        yx_put_bytes(writer, bytes + prefix + 4, length - prefix - 4);
}

static bool yx_integer_signed_division_emit(yx_writer *writer,int slot)
{
    static const uint8_t start[]={0x21,1,0x21,0,0x20,1,0x50,0x20,0,0x42};
    static const uint8_t check[]={0x51,0x20,1,0x42,0x7f,0x51,0x71,0x72,4,0x40};
    static const uint8_t tail[]={5,0x0b,0x20,0,0x20,1,0x7f};
    return yx_put_bytes(writer,start,sizeof(start))&&yx_put_sleb_i64(writer,INT64_MIN)&&
        yx_put_bytes(writer,check,sizeof(check))&&yx_integer_emit_undefined(writer,slot)&&
        yx_put_bytes(writer,tail,sizeof(tail));
}

static bool yx_integer_shift_v12_emit(yx_writer *writer,uint8_t op,bool left_unsigned,
                                       bool right_unsigned,uint8_t local)
{
    return yx_put_u8(writer,0x22)&&yx_put_u8(writer,local)&&
        yx_put_u8(writer,op==0x87&&left_unsigned?0x88:op)&&
        yx_put_u8(writer,0x42)&&yx_put_u8(writer,0)&&yx_put_u8(writer,0x20)&&
        yx_put_u8(writer,local)&&yx_put_u8(writer,0x42)&&yx_put_sleb_i64(writer,64)&&
        yx_put_u8(writer,right_unsigned?0x54:0x53)&&yx_put_u8(writer,0x1b);
}

static bool yx_integer_emit_variable(yx_writer *writer, int64_t variable,
                                       bool floating, int slot)
{
    return variable >= 0 && variable < YX_ARCHIVE_MAX_VARS &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, variable / 8) &&
        yx_put_bytes(writer, "\x2d\x00\x00\x41", 4) &&
        yx_put_sleb_i64(writer, INT64_C(1) << (variable % 8)) &&
        yx_put_bytes(writer, "\x71\x04\x40", 3) && yx_integer_emit_undefined(writer, slot) &&
        yx_put_bytes(writer, "\x05\x0b\x41", 3) && yx_put_sleb_i64(writer, variable * 8) &&
        yx_put_u8(writer, floating ? 0x2b : 0x29) && yx_put_u8(writer, 3) && yx_put_uleb(writer, 256);
}

static bool yx_integer_expr_emit(const yx_integer_expr *tree, int index,
                                   yx_writer *writer, uint8_t parent,
                                   unsigned depth, int undefined_slot, bool float_chain)
{
    const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[index];
    /* The upstream AST flattens a left child with the same arithmetic
     * operator, including an explicitly parenthesized left child. */
    bool chain = node->op == parent &&
        (parent == 0x7c || parent == 0x7d || parent == 0x7e || parent == 0x7f || parent == 0x81);
    if (depth > 256) return false;
    if (node->constant && !chain)
        return node->floating
            ? yx_put_u8(writer, 0x44) && yx_put_float(writer, node->real)
            : yx_put_u8(writer, 0x42) && yx_put_sleb_i64(writer, node->value);
    if (node->op >= 0xd0)
        return tree->emit_primary && tree->emit_primary(tree, index, writer, depth,
            undefined_slot, false, tree->extension);
    if (node->op == 0x23) {
        size_t start=writer->used;
        if(!yx_integer_emit_guard(writer,0x23,undefined_slot))return false;
        writer->data[start+1]=tree->filesize_id;
        return true;
    }
    if (node->op == 0xc2)
        return yx_integer_emit_variable(writer, node->value, node->floating, undefined_slot);
    if (node->op == 0xc3)
        return node->value>=0&&node->value<YX_ARCHIVE_MAX_VARS&&yx_put_u8(writer,0x41)&&
            yx_put_sleb_i64(writer,node->value*8)&&yx_put_u8(writer,node->floating?0x2b:0x29)&&
            yx_put_u8(writer,3)&&yx_put_uleb(writer,256);
    if (node->op >= 0xb0 && node->op < 0xc0)
        return yx_integer_expr_emit(tree, node->left, writer, 0, depth + 1, undefined_slot, false) &&
               yx_put_u8(writer, 0x10) && yx_put_u8(writer, tree->read_ids[node->op - 0xb0]) &&
               yx_integer_emit_guard(writer, 0x10, undefined_slot);
    if (node->op == 0xc1)
        return yx_integer_expr_emit(tree, node->left, writer, 0, depth + 1, undefined_slot, false) && yx_put_u8(writer, 0x9a);
    /* Iterative postorder along the left spine keeps flat source expressions
     * independent of the nesting limit, while preserving operand promotions
     * and the constant-folding boundary of each operator. */
    typedef struct { int index; bool floating, left_chain; } yx_integer_emit_frame;
    yx_integer_emit_frame *frames = NULL;
    size_t used = 0, capacity = 0;
    int current = index;
    bool ok = false;
    uint8_t current_parent = parent;
    bool current_float = float_chain;
    for (;;) {
        const yx_integer_expr_node *part = &YX_INTEGER_NODES(tree)[current];
        bool part_chain = part->op == current_parent &&
            (current_parent == 0x7c || current_parent == 0x7d || current_parent == 0x7e || current_parent == 0x7f || current_parent == 0x81);
        if ((part->constant && !part_chain) || !yx_integer_expr_precedence(part->op)) break;
        if (part->left < 0 || part->right < 0 || (size_t)part->left >= tree->count ||
            (size_t)part->right >= tree->count || used >= tree->count) goto emit_done;
        if (used == capacity) {
            size_t next = capacity ? capacity * 2 : 16;
            if (next < capacity || next > SIZE_MAX / sizeof(*frames)) goto emit_done;
            yx_integer_emit_frame *grown = realloc(frames, next * sizeof(*frames));
            if (!grown) goto emit_done;
            frames = grown; capacity = next;
        }
        bool floating = part->floating || (part_chain && current_float);
        bool left_chain = YX_INTEGER_NODES(tree)[part->left].op == part->op &&
            (part->op == 0x7c || part->op == 0x7d || part->op == 0x7e);
        frames[used++] = (yx_integer_emit_frame){current, floating, left_chain};
        current_parent = part->op;
        current_float = floating && left_chain;
        current = part->left;
    }
    if (!used || !yx_integer_expr_emit(tree, current, writer, current_parent,
            depth + 1, undefined_slot, current_float)) goto emit_done;
    while (used) {
        yx_integer_emit_frame frame = frames[--used];
        const yx_integer_expr_node *part = &YX_INTEGER_NODES(tree)[frame.index];
        if (frame.floating) {
            uint8_t op = part->op == 0x7c ? 0xa0 : part->op == 0x7d ? 0xa1 : part->op == 0x7e ? 0xa2 : 0xa3;
            if ((!YX_INTEGER_NODES(tree)[part->left].floating && !frame.left_chain &&
                    !yx_put_u8(writer, YX_INTEGER_NODES(tree)[part->left].unsigned_value ? 0xba : 0xb9)) ||
                !yx_integer_expr_emit(tree, part->right, writer, 0, depth + 1, undefined_slot, false) ||
                (!YX_INTEGER_NODES(tree)[part->right].floating &&
                    !yx_put_u8(writer, YX_INTEGER_NODES(tree)[part->right].unsigned_value ? 0xba : 0xb9)) ||
                !yx_put_u8(writer, op)) goto emit_done;
        } else {
            if (!yx_integer_expr_emit(tree, part->right, writer, 0, depth + 1, undefined_slot, false)) goto emit_done;
            if(part->op==0x7f&&!part->unsigned_value) {
                if(!yx_integer_signed_division_emit(writer,undefined_slot))goto emit_done;
                continue;
            }
            if ((part->op == 0x7f || part->op == 0x81) && !yx_integer_emit_guard(writer, 0x22, undefined_slot)) goto emit_done;
            if (part->op == 0x86 || part->op == 0x87) {
                uint8_t local=tree->small_shift&&!tree->has_filesize&&!tree->has_divisor&&!tree->has_loop?0:1;
                if(!yx_integer_shift_v12_emit(writer,part->op,YX_INTEGER_NODES(tree)[part->left].unsigned_value,
                        YX_INTEGER_NODES(tree)[part->right].unsigned_value,local))goto emit_done;
            } else if (!yx_put_u8(writer, part->unsigned_value &&
                    (part->op == 0x7f || part->op == 0x81) ? (uint8_t)(part->op + 1) : part->op)) goto emit_done;
        }
    }
    ok = true;
emit_done:
    free(frames);
    return ok;
}

static const uint8_t yx_integer_and_guard[] =
    {0x04,0x40,0x05,0x41,0x00,0x0c,0x01,0x0b};
static const uint8_t yx_integer_or_guard[] =
    {0x04,0x40,0x41,0x01,0x0c,0x01,0x05,0x0b};

static bool yx_integer_boolean_emit(const yx_integer_expr *tree, int index,
                                      yx_writer *writer, unsigned depth);
static bool yx_integer_boolean_emit_inner(const yx_integer_expr *tree,int index,
    yx_writer *writer,unsigned depth,int undefined_slot);

static bool yx_integer_loop_store(yx_writer *writer, int64_t slot)
{
    return slot >= 0 && slot < YX_ARCHIVE_MAX_VARS &&
        yx_put_bytes(writer, "\x37\x03\x80\x02", 4) &&
        yx_integer_clear_variable(writer, slot);
}

static bool yx_integer_loop_init_tail(yx_writer *writer, int64_t slot)
{
    static const uint8_t check[] = {0x42,0x00,0x57,0x04,0x40,0x41,0x00,0x0c,0x01,0x05,0x0b,0x41};
    return yx_integer_loop_store(writer, slot) &&
        yx_integer_emit_variable(writer, slot, false, -3) &&
        yx_put_bytes(writer, check, sizeof(check)) && yx_put_sleb_i64(writer, (slot + 5) * 8) &&
        yx_put_u8(writer, 0x20) && yx_put_u8(writer, 0) && yx_integer_loop_store(writer, slot + 5) &&
        yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, (slot + 1) * 8) &&
        yx_put_u8(writer, 0x42) && yx_put_u8(writer, 0) && yx_integer_loop_store(writer, slot + 1) &&
        yx_put_u8(writer, 0x03) && yx_put_u8(writer, 0x7f) &&
        yx_put_u8(writer, 0x02) && yx_put_u8(writer, 0x7f);
}

static bool yx_integer_loop_increment(yx_writer *writer, int64_t slot)
{
    return yx_put_u8(writer, 0x41) && yx_put_sleb_i64(writer, slot * 8) &&
        yx_integer_emit_variable(writer, slot, false, -5) && yx_put_u8(writer, 0x42) &&
        yx_put_u8(writer, 1) && yx_put_u8(writer, 0x7c) && yx_integer_loop_store(writer, slot);
}

static bool yx_integer_loop_exit(yx_writer *writer, bool value)
{
    return yx_put_u8(writer, 0x41) && yx_put_u8(writer, value ? 1 : 0) &&
        yx_put_u8(writer, 0x0c) && yx_put_u8(writer, 2);
}

static bool yx_integer_loop_tail(yx_writer *writer, int64_t slot, uint8_t op)
{
    bool all = op == 0xc5, any = op == 0xc4;
    if (!yx_put_u8(writer, 0x04) || !yx_put_u8(writer, 0x7f)) return false;
    if (!all && (!yx_integer_loop_exit(writer, any) || !yx_put_u8(writer, 0x05))) return false;
    if (!yx_integer_loop_increment(writer, slot + 5) || !yx_integer_loop_increment(writer, slot + 1) ||
        !yx_integer_emit_variable(writer, slot + 1, false, -5) ||
        !yx_integer_emit_variable(writer, slot, false, -5) ||
        !yx_put_u8(writer, 0x53) || !yx_put_u8(writer, 0x0d) || !yx_put_u8(writer, 1) ||
        !yx_integer_loop_exit(writer, !any)) return false;
    if (all && (!yx_put_u8(writer, 0x05) || !yx_integer_loop_exit(writer, false))) return false;
    return yx_put_u8(writer, 0x0b) && yx_put_u8(writer, 0x0b) && yx_put_u8(writer, 0x0b);
}

static bool yx_integer_loop_v12_load(yx_writer *writer,int64_t slot)
{
    return slot>=0&&slot<YX_ARCHIVE_MAX_VARS&&yx_put_u8(writer,0x41)&&yx_put_sleb_i64(writer,slot*8)&&
        yx_put_u8(writer,0x29)&&yx_put_u8(writer,3)&&yx_put_uleb(writer,256);
}
static bool yx_integer_loop_v12_store(yx_writer *writer)
{ return yx_put_u8(writer,0x37)&&yx_put_u8(writer,3)&&yx_put_uleb(writer,256); }
static bool yx_integer_loop_v12_init_bounds(yx_writer *writer,int64_t slot,
                                             bool lower_unsigned,bool upper_unsigned)
{
    static const uint8_t bounds[]={0x21,0,0x21,1,0x20,1,0x20,0,0x53};
    static const uint8_t empty[]={4,0x40,0x41,0,0x0c,1,5,0x0b};
    static const uint8_t diff_plus_one[]={0x20,1,0x20,0,0x7d,0x42,1,0x7c,0x20,1,0x20,0,0x7d,0x42};
    return slot>=0&&slot<=YX_ARCHIVE_MAX_VARS-7&&yx_put_bytes(writer,bounds,sizeof(bounds))&&
        (!lower_unsigned||yx_put_bytes(writer,"\x20\x00\x42\x00\x53\x72",6))&&
        (!upper_unsigned||yx_put_bytes(writer,"\x20\x01\x42\x00\x53\x72",6))&&
        yx_put_bytes(writer,empty,sizeof(empty))&&
        yx_put_u8(writer,0x41)&&yx_put_sleb_i64(writer,slot*8)&&yx_put_u8(writer,0x42)&&
        yx_put_sleb_i64(writer,INT64_MAX)&&yx_put_bytes(writer,diff_plus_one,sizeof(diff_plus_one))&&
        yx_put_sleb_i64(writer,INT64_MAX)&&yx_put_u8(writer,0x5a)&&yx_put_u8(writer,0x1b)&&
        yx_integer_loop_v12_store(writer)&&yx_put_u8(writer,0x41)&&yx_put_sleb_i64(writer,(slot+5)*8)&&
        yx_put_u8(writer,0x20)&&yx_put_u8(writer,0)&&yx_integer_loop_v12_store(writer)&&
        yx_put_u8(writer,0x41)&&yx_put_sleb_i64(writer,(slot+1)*8)&&yx_put_u8(writer,0x42)&&
        yx_put_u8(writer,0)&&yx_integer_loop_v12_store(writer)&&yx_put_u8(writer,3)&&yx_put_u8(writer,0x40);
}
static bool yx_integer_loop_v12_init(yx_writer *writer,int64_t slot)
{ return yx_integer_loop_v12_init_bounds(writer,slot,false,false); }
static bool yx_integer_loop_v12_init_guarded(yx_writer *writer,int64_t slot,
    bool lower_unsigned,bool upper_unsigned,bool guarded)
{
    yx_writer bytes={0};
    bool ok=yx_integer_loop_v12_init_bounds(&bytes,slot,lower_unsigned,upper_unsigned)&&
        yx_put_bytes(writer,bytes.data,4)&&(!guarded||yx_put_u8(writer,0x0b))&&
        yx_put_bytes(writer,bytes.data+4,bytes.used-4);
    free(bytes.data);return ok;
}
static bool yx_integer_loop_v12_increment(yx_writer *writer,int64_t slot)
{
    return yx_put_u8(writer,0x41)&&yx_put_sleb_i64(writer,slot*8)&&
        yx_integer_loop_v12_load(writer,slot)&&yx_put_u8(writer,0x42)&&yx_put_u8(writer,1)&&
        yx_put_u8(writer,0x7c)&&yx_integer_loop_v12_store(writer);
}
static bool yx_integer_loop_v12_repeat(yx_writer *writer,int64_t slot,unsigned depth)
{
    return yx_integer_loop_v12_increment(writer,slot+5)&&yx_integer_loop_v12_increment(writer,slot+1)&&
        yx_integer_loop_v12_load(writer,slot+1)&&yx_integer_loop_v12_load(writer,slot)&&
        yx_put_u8(writer,0x53)&&yx_put_u8(writer,0x0d)&&yx_put_u8(writer,(uint8_t)depth);
}
static bool yx_integer_loop_v12_tail(yx_writer *writer,int64_t slot,uint8_t op)
{
    bool all=op==0xc5,any=op==0xc4;
    if(!yx_put_u8(writer,4)||!yx_put_u8(writer,0x40))return false;
    if(all) {
        if(!yx_integer_loop_v12_repeat(writer,slot,1)||!yx_integer_loop_exit(writer,true))return false;
    } else if(!yx_integer_loop_exit(writer,any))return false;
    if(!yx_put_u8(writer,5)||!yx_put_u8(writer,0x0b))return false;
    if(all) {
        if(!yx_put_u8(writer,0x41)||!yx_put_u8(writer,0)||!yx_put_u8(writer,0x0c)||!yx_put_u8(writer,1))return false;
    } else if(!yx_integer_loop_v12_repeat(writer,slot,0))return false;
    return yx_put_u8(writer,0x0b)&&yx_put_u8(writer,0x41)&&yx_put_u8(writer,any?0:1)&&yx_put_u8(writer,0x0b);
}
static bool yx_integer_loop_v12_guarded_tail(yx_writer *writer,int64_t slot,uint8_t op)
{
    bool all=op==0xc5,any=op==0xc4;
    if(!yx_put_u8(writer,4)||!yx_put_u8(writer,0x40))return false;
    if(all&&!yx_integer_loop_v12_repeat(writer,slot,2))return false;
    if(!yx_put_u8(writer,0x41)||!yx_put_u8(writer,all||any?1:0)||
       !yx_put_u8(writer,0x0c)||!yx_put_u8(writer,3)||
       !yx_put_bytes(writer,"\x05\x0b\x0b",3))return false;
    if(all) {
        if(!yx_put_bytes(writer,"\x41\x00\x0c\x01",4))return false;
    } else if(!yx_integer_loop_v12_repeat(writer,slot,0))return false;
    return yx_put_bytes(writer,"\x0b\x41",2)&&yx_put_u8(writer,any?0:1)&&yx_put_u8(writer,0x0b);
}
static bool yx_integer_loop_signed_bound(const yx_integer_expr *tree,int index,unsigned depth)
{
    if(index<0||depth>256)return false;
    const yx_integer_expr_node *n=&YX_INTEGER_NODES(tree)[index];
    if(n->op>=0xd0)return false;
    return (n->left<0||yx_integer_loop_signed_bound(tree,n->left,depth+1))&&
        (n->right<0||n->right==n->left||yx_integer_loop_signed_bound(tree,n->right,depth+1));
}
static bool yx_integer_loop_defined_body(const yx_integer_expr *tree,int index,unsigned depth)
{
    return yx_integer_expr_defined(tree,index,depth);
}
static bool yx_integer_loop_emit(const yx_integer_expr *tree,int index,yx_writer *writer,unsigned depth)
{
    const yx_integer_expr_node *node=&YX_INTEGER_NODES(tree)[index];
    bool defined=yx_integer_loop_defined_body(tree,node->extra,0);
    return node->value>=0&&node->value<=YX_ARCHIVE_MAX_VARS-7&&node->extra>=0&&
        yx_integer_loop_signed_bound(tree,node->left,0)&&yx_integer_loop_signed_bound(tree,node->right,0)&&
        yx_put_u8(writer,2)&&yx_put_u8(writer,0x7f)&&
        yx_put_u8(writer,2)&&yx_put_u8(writer,0x40)&&
        yx_integer_expr_emit(tree,node->right,writer,0,depth+1,-33,false)&&
        yx_integer_expr_emit(tree,node->left,writer,0,depth+1,-33,false)&&
        yx_integer_loop_v12_init_guarded(writer,node->value,
            YX_INTEGER_NODES(tree)[node->left].unsigned_value,
            YX_INTEGER_NODES(tree)[node->right].unsigned_value,true)&&
        (defined||yx_put_bytes(writer,"\x02\x40",2))&&
        yx_integer_boolean_emit_inner(tree,node->extra,writer,depth+1,defined?-1:-34)&&
        (defined?yx_integer_loop_v12_tail(writer,node->value,node->op):
            yx_integer_loop_v12_guarded_tail(writer,node->value,node->op));
}

static bool yx_integer_boolean_operands(const yx_integer_expr *tree, int index,
                                          uint8_t op, yx_writer *writer,
                                          bool flatten, bool last, unsigned depth)
{
    const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[index];
    if (depth > 256) return false;
    if (flatten && node->op == op && !node->constant) {
        if (tree->count > SIZE_MAX / sizeof(int)) return false;
        int *operands = malloc(tree->count * sizeof(*operands));
        size_t used = 0;
        bool ok = false;
        if (!operands) return false;
        while (node->op == op && !node->constant) {
            if (node->left < 0 || node->right < 0 || (size_t)node->left >= tree->count ||
                (size_t)node->right >= tree->count || used >= tree->count) goto operands_done;
            operands[used++] = node->right;
            index = node->left; node = &YX_INTEGER_NODES(tree)[index];
        }
        if (!yx_integer_boolean_operands(tree, index, op, writer, false, false, depth)) goto operands_done;
        while (used) {
            int operand = operands[--used];
            if (!yx_integer_boolean_operands(tree, operand, op, writer, false, used ? false : last, depth)) goto operands_done;
        }
        ok = true;
operands_done:
        free(operands);
        return ok;
    }
    if (op == 0xa1 && (!yx_put_u8(writer, 0x02) || !yx_put_u8(writer, 0x7f))) return false;
    if (!yx_integer_boolean_emit(tree, index, writer, depth + 1)) return false;
    if (op == 0xa1 && !yx_put_u8(writer, 0x0b)) return false;
    if (last) return true;
    return op == 0xa1
        ? yx_put_bytes(writer, yx_integer_or_guard, sizeof(yx_integer_or_guard))
        : yx_put_bytes(writer, yx_integer_and_guard, sizeof(yx_integer_and_guard));
}

static bool yx_integer_boolean_emit(const yx_integer_expr *tree, int index,
                                      yx_writer *writer, unsigned depth)
{ return yx_integer_boolean_emit_inner(tree,index,writer,depth,-1); }

static bool yx_integer_boolean_emit_inner(const yx_integer_expr *tree, int index,
                                      yx_writer *writer, unsigned depth,int undefined_slot)
{
    const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[index];
    if (depth > 256) return false;
    if (node->op >= 0xd0)
        return tree->emit_primary && tree->emit_primary(tree, index, writer, depth,
            undefined_slot, true, tree->extension);
    if (node->op >= 0xc4 && node->op <= 0xc6)
        return yx_integer_loop_emit(tree, index, writer, depth + 1);
    if (node->op == 0xc0) {
        static const uint8_t set_start[] = {0x02,0x40,0x41};
        bool defined=yx_integer_expr_defined(tree,node->left,0);
        if (node->value < 0 || node->value >= YX_ARCHIVE_MAX_VARS) return false;
        return
            yx_put_bytes(writer, set_start+(defined?2:0), sizeof(set_start)-(defined?2:0)) &&
            yx_put_sleb_i64(writer, node->value * 8) &&
            yx_integer_expr_emit(tree, node->left, writer, 0, depth + 1, (int)node->value, false) &&
            yx_put_u8(writer, YX_INTEGER_NODES(tree)[node->left].floating ? 0x39 : 0x37) && yx_put_u8(writer, 0x03) &&
            yx_put_uleb(writer, 256) &&
            (defined||(yx_integer_clear_variable(writer,node->value)&&yx_put_u8(writer,0x0b))) &&
            yx_integer_boolean_emit_inner(tree,node->right,writer,depth+1,undefined_slot);
    }
    if (yx_integer_expr_boolean(node->op) && node->constant)
        return yx_put_u8(writer, 0x41) && yx_put_u8(writer, node->value ? 1 : 0);
    if (node->op == 0xa0 || node->op == 0xa1) {
        if(tree->boolean_scope)tree->boolean_scope(tree->extension,true);
        bool ok = yx_put_u8(writer, 0x02) && yx_put_u8(writer, 0x7f);
        if (!ok) return false;
        /* Flatten only the left chain. A right grouped expression retains
         * its own block, as in the reference AST. */
        if (!yx_integer_boolean_operands(tree, node->left, node->op, writer, true, false, depth + 1)) return false;
        if (node->op == 0xa1 && (!yx_put_u8(writer, 0x02) || !yx_put_u8(writer, 0x7f))) return false;
        if (!yx_integer_boolean_emit(tree, node->right, writer, depth + 1)) return false;
        if (node->op == 0xa1 && !yx_put_u8(writer, 0x0b)) return false;
        /* Plain OR tests its last operand too (emit.rs::emit_or). Pattern-set
         * ANY leaves that operand on the stack. Keep the distinction in this
         * intermediate stream even when both forms occur in one condition. */
        if (node->op == 0xa1 && !tree->legacy_boolean_or &&
            (!yx_put_bytes(writer, yx_integer_or_guard, sizeof(yx_integer_or_guard)) ||
             !yx_put_u8(writer, 0x41) || !yx_put_u8(writer, 0))) return false;
        if(tree->boolean_scope)tree->boolean_scope(tree->extension,false);
        return yx_put_u8(writer, 0x0b);
    }
    if (node->op == 0xa2)
        return yx_integer_boolean_emit(tree, node->left, writer, depth + 1) &&
               yx_put_u8(writer, 0x45);
    if (node->op >= 0x51 && node->op <= 0x59) {
        if (YX_INTEGER_NODES(tree)[node->left].floating || YX_INTEGER_NODES(tree)[node->right].floating) {
            uint8_t op = node->op == 0x51 ? 0x61 : node->op == 0x52 ? 0x62 :
                         node->op == 0x53 ? 0x63 : node->op == 0x55 ? 0x64 : node->op == 0x57 ? 0x65 : 0x66;
            return yx_integer_expr_emit(tree, node->left, writer, 0, depth + 1, undefined_slot, false) &&
                (YX_INTEGER_NODES(tree)[node->left].floating ||
                    yx_put_u8(writer, YX_INTEGER_NODES(tree)[node->left].unsigned_value ? 0xba : 0xb9)) &&
                yx_integer_expr_emit(tree, node->right, writer, 0, depth + 1, undefined_slot, false) &&
                (YX_INTEGER_NODES(tree)[node->right].floating ||
                    yx_put_u8(writer, YX_INTEGER_NODES(tree)[node->right].unsigned_value ? 0xba : 0xb9)) && yx_put_u8(writer, op);
        }
        return yx_integer_expr_emit(tree, node->left, writer, 0, depth + 1, undefined_slot, false) &&
               yx_integer_expr_emit(tree, node->right, writer, 0, depth + 1, undefined_slot, false) &&
               yx_integer_comparison_emit(writer, node->op,
                   YX_INTEGER_NODES(tree)[node->left].unsigned_value,
                   YX_INTEGER_NODES(tree)[node->right].unsigned_value,
                   yx_integer_expr_non_negative(&YX_INTEGER_NODES(tree)[node->left]),
                   yx_integer_expr_non_negative(&YX_INTEGER_NODES(tree)[node->right]));
    }
    if (node->floating)
        return yx_integer_expr_emit(tree, index, writer, 0, depth + 1, undefined_slot, false) &&
            yx_put_u8(writer, 0x44) && yx_put_float(writer, 0.0) && yx_put_u8(writer, 0x62);
    return yx_integer_expr_emit(tree, index, writer, 0, depth + 1, undefined_slot, false) &&
           yx_put_u8(writer, 0x42) && yx_put_u8(writer, 0) && yx_put_u8(writer, 0x52);
}

/* Only emitted operands contribute imports and locals. Constant Boolean
 * branches can discard reads while with declarations still have stores. */
static bool yx_integer_expr_resources(yx_integer_expr *tree, int index,
                                        uint8_t parent, unsigned depth)
{
    typedef struct { int index; uint8_t parent, context; bool real_context; } yx_integer_resource_frame;
    yx_integer_resource_frame *stack;
    size_t used = 0;
    bool ok = false;
    if (depth > 256 || !tree->count || tree->count > SIZE_MAX / sizeof(*stack)) return false;
    stack = malloc(tree->count * sizeof(*stack));
    if (!stack) return false;
    stack[used++] = (yx_integer_resource_frame){index, parent, 0, false};
    while (used) {
        yx_integer_resource_frame frame = stack[--used];
        if (frame.index < 0 || (size_t)frame.index >= tree->count) goto resources_done;
        const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[frame.index];
        if (node->op >= 0x51 && node->op <= 0x59 && node->left >= 0 && node->right >= 0 &&
            yx_integer_comparison_mixed(YX_INTEGER_NODES(tree)[node->left].unsigned_value,
                YX_INTEGER_NODES(tree)[node->right].unsigned_value,
                yx_integer_expr_non_negative(&YX_INTEGER_NODES(tree)[node->left]),
                yx_integer_expr_non_negative(&YX_INTEGER_NODES(tree)[node->right]))) {
            tree->has_shift = true;tree->small_shift=false;
        }
        bool chain = node->op == frame.parent &&
            (frame.parent == 0x7c || frame.parent == 0x7d || frame.parent == 0x7e || frame.parent == 0x7f || frame.parent == 0x81);
        if (node->constant && !chain) continue;
        if (node->op >= 0xd0 && (!tree->resource_primary ||
            !tree->resource_primary(tree, frame.index, tree->extension))) goto resources_done;
        if (node->op == 0x23) tree->has_filesize = true;
        if (node->op == 0xc0 || node->op == 0xc2 || node->op == 0xc3) tree->has_memory = true;
        if (node->op >= 0xc4 && node->op <= 0xc6) {tree->has_memory = tree->has_loop = true;tree->small_shift=false;}
        if ((node->op == 0x7f || node->op == 0x81) && !node->floating) tree->has_divisor = true;
        if(node->op==0x7f&&!node->floating&&!node->unsigned_value) {tree->has_shift=true;tree->small_shift=false;}
        if (node->op == 0x86 || node->op == 0x87) {
            tree->has_shift = true;
        }
        if (node->op >= 0xb0 && node->op < 0xc0) tree->read_mask |= (uint16_t)(1u << (node->op - 0xb0));
        bool real_context = node->floating;
        if (node->op == 0x51 || node->op == 0x52) {
            if ((node->left >= 0 && (size_t)node->left >= tree->count) ||
                (node->right >= 0 && (size_t)node->right >= tree->count)) goto resources_done;
            if (node->left >= 0 && YX_INTEGER_NODES(tree)[node->left].floating) real_context = true;
            if (node->right >= 0 && YX_INTEGER_NODES(tree)[node->right].floating) real_context = true;
        }
        int children[3] = {node->extra, node->right == node->left ? -1 : node->right, node->left};
        for (size_t child = 0; child < 3; ++child) if (children[child] >= 0) {
            if (used == tree->count) goto resources_done;
            stack[used++] = (yx_integer_resource_frame){children[child], child == 2 ? node->op : 0, node->op, real_context};
        }
    }
    ok = true;
resources_done:
    free(stack);
    return ok;
}

static uint8_t yx_integer_import_profile(void)
{
#if defined(XXYARA_ENABLE_MAGIC) && defined(XXYARA_ENABLE_VBA)
    return 3;
#elif defined(XXYARA_ENABLE_MAGIC)
    return 1;
#elif defined(XXYARA_ENABLE_VBA)
    return 2;
#else
    return 0;
#endif
}

static bool yx_integer_module_header(yx_integer_expr *tree, uint8_t profile,
                                       yx_writer *wasm)
{
    /* Registry iteration order in the pinned 1.21.0 build, restricted to
     * used imports. 16 denotes rule_match; the six original reads retain
     * their internal ordering. The final v12 pass orders all release symbols.
     * These are symbol-order data, independent of expression shape. */
    static const uint8_t orders[4][YX_INTEGER_READ_COUNT+1] = {
        {16,2,1,0,5,4,3,6,7,8,9,10,11,12,13,14,15},
        {3,4,16,5,0,1,2,6,7,8,9,10,11,12,13,14,15},
        {16,1,5,3,2,0,4,6,7,8,9,10,11,12,13,14,15},
        {0,1,2,5,4,3,16,6,7,8,9,10,11,12,13,14,15}
    };
    static const uint8_t read_types[] = {
        0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
        0x01,0x12,0x04,0x60,0x00,0x00,0x60,0x00,
        0x01,0x7f,0x60,0x01,0x7f,0x00,0x60,0x01,
        0x7e,0x02,0x7e,0x7f
    };
    static const uint8_t functions_export[] = {
        0x03,0x04,0x03,0x01,0x00,0x01,0x07,0x08,0x01,0x04,'m','a','i','n',0x00
    };
    yx_writer imports = {0};
    bool ok;
    if (profile > 3) return false;
    tree->function_count = 0;
    for (size_t i = 0; i < YX_INTEGER_READ_COUNT+1; ++i) {
        uint8_t type = orders[profile][i];
        if (type == YX_INTEGER_READ_COUNT) tree->match_id = tree->function_count++;
        else if (tree->read_mask & (1u << type)) tree->read_ids[type] = tree->function_count++;
    }
    ok = yx_put_u8(&imports, (uint8_t)(tree->function_count +
        (tree->has_filesize ? 1 : 0) + (tree->has_memory ? 1 : 0)));
    for (size_t i = 0; ok && i < YX_INTEGER_READ_COUNT+1; ++i) {
        uint8_t type = orders[profile][i];
        if (type == YX_INTEGER_READ_COUNT)
            ok = yx_put_integer_read_import(&imports, "rule_match@rule_id:i@", 2);
        else if (tree->read_mask & (1u << type))
            ok = yx_put_integer_read_import(&imports, yx_integer_codec_read_import_name(type), 3);
    }
    if (ok && tree->has_filesize)
        ok = yx_put_u8(&imports, 6) && yx_put_bytes(&imports, "yara_x", 6) &&
             yx_put_u8(&imports, 8) && yx_put_bytes(&imports, "filesize", 8) &&
             yx_put_u8(&imports, 3) && yx_put_u8(&imports, 0x7e) && yx_put_u8(&imports, 1);
    if (ok && tree->has_memory)
        ok = yx_put_u8(&imports, 6) && yx_put_bytes(&imports, "yara_x", 6) &&
             yx_put_u8(&imports, 11) && yx_put_bytes(&imports, "main_memory", 11) &&
             yx_put_u8(&imports, 2) && yx_put_u8(&imports, 0) && yx_put_u8(&imports, 1);
    if (ok)
        ok = (tree->read_mask ? yx_put_bytes(wasm, read_types, sizeof(read_types))
                             : yx_put_bytes(wasm, yx_constant_wasm, 22)) &&
             yx_put_u8(wasm, 2) && yx_put_uleb(wasm, imports.used) &&
             yx_put_bytes(wasm, imports.data, imports.used) &&
             yx_put_bytes(wasm, functions_export, sizeof(functions_export)) &&
             yx_put_u8(wasm, (uint8_t)(tree->function_count + 2));
    free(imports.data);
    return ok;
}

static bool yx_make_runtime_integer_wasm(const char *condition, uint8_t profile,
                                          uint8_t **data, size_t *length)
{
    uint8_t prefix[] = {0x01, 0x01, 0x7e, 0x02, 0x7f};
    uint8_t suffix[] = {
        0x0b, 0x45, 0x04, 0x40, 0x05, 0x41, 0x00, 0x10,
        0x00, 0x0b, 0x41, 0x00, 0x0b
    };
    uint8_t others[] = {
        0x09, 0x00, 0x02, 0x40, 0x10, 0x01, 0x0d, 0x00,
        0x0b, 0x0b, 0x06, 0x00, 0x10, 0x02, 0x41, 0x00, 0x0b
    };
    yx_integer_expr *tree = calloc(1, sizeof(*tree));
    yx_writer body = {0}, code = {0}, wasm = {0};
    int root = tree && condition ? yx_integer_expr_condition(tree, condition) : -1;
    bool ok = root >= 0 && (!YX_INTEGER_NODES(tree)[root].constant || YX_INTEGER_NODES(tree)[root].floating);
    if (ok) {
        tree->has_filesize = tree->has_shift = tree->has_divisor = tree->has_memory = tree->has_loop = false;
        tree->small_shift=true;
        tree->read_mask = 0;
        ok = yx_integer_expr_resources(tree, root, 0, 0) && yx_integer_module_header(tree, profile, &wasm);
    }
    if (ok) {
        bool locals = tree->has_filesize || tree->has_shift || tree->has_divisor || tree->has_loop;
        suffix[8] = tree->match_id;
        others[5] = tree->function_count;
        others[13] = (uint8_t)(tree->function_count + 1);
        prefix[1] = tree->has_loop||(tree->has_shift&&(!tree->small_shift||tree->has_filesize||tree->has_divisor)) ? 2 : 1;
        ok = (locals ? yx_put_bytes(&body, prefix, sizeof(prefix))
                     : (yx_put_u8(&body, 0) && yx_put_u8(&body, 0x02) && yx_put_u8(&body, 0x7f))) &&
             yx_integer_boolean_emit(tree, root, &body, 0) &&
             yx_put_bytes(&body, suffix, sizeof(suffix)) &&
             yx_put_u8(&code, 3) && yx_put_uleb(&code, body.used) &&
             yx_put_bytes(&code, body.data, body.used) &&
             yx_put_bytes(&code, others, sizeof(others)) &&
             yx_put_u8(&wasm, 0x0a) && yx_put_uleb(&wasm, code.used) &&
             yx_put_bytes(&wasm, code.data, code.used);
    }
    yx_integer_expr_free(tree); free(body.data); free(code.data);
    if (!ok) { free(wasm.data); return false; }
    *data = wasm.data; *length = wasm.used;
    return true;
}

static bool yx_condition_runtime_integer(const char *condition,
                                          yx_ser_rule *rule)
{
    uint8_t *wasm = NULL;
    size_t length = 0;
    uint8_t profile = yx_integer_import_profile();
    if (!yx_make_runtime_integer_wasm(condition, profile, &wasm, &length)) return false;
    free(wasm);
    rule->runtime_integer_condition = (char *)condition; /* borrowed on encode */
    rule->runtime_integer_import_profile = profile;
    return true;
}

static const char *yx_integer_expr_operator(uint8_t op)
{
    switch (op) {
    case 0x7c: return " + "; case 0x7d: return " - ";
    case 0x7e: return " * "; case 0x7f: return " \\ ";
    case 0x81: return " % "; case 0x83: return " & ";
    case 0x84: return " | "; case 0x85: return " ^ ";
    case 0x86: return " << "; case 0x87: return " >> ";
    case 0x51: return " == "; case 0x52: return " != ";
    case 0x53: return " < "; case 0x55: return " > ";
    case 0x57: return " <= "; case 0x59: return " >= ";
    case 0xa0: return " and "; case 0xa1: return " or ";
    default: return NULL;
    }
}

static bool yx_integer_expr_print(const yx_integer_expr *tree, int index,
                                    yx_writer *writer, unsigned parent,
                                    bool right, unsigned depth)
{
    const yx_integer_expr_node *node = &YX_INTEGER_NODES(tree)[index];
    unsigned precedence = node->op == 0xa1 ? 1 : node->op == 0xa0 ? 2 :
        yx_integer_expr_boolean(node->op) ? 3 :
        yx_integer_expr_precedence(node->op) + 3;
    const char *op;
    bool grouped;
    if (depth > 256) return false;
    if (node->op >= 0xd0)
        return tree->print_primary && tree->print_primary(tree, index, writer, tree->extension);
    if (node->op == 0x41)
        return yx_put_bytes(writer, node->value ? "true" : "false", node->value ? 4 : 5);
    if (node->op >= 0xc4 && node->op <= 0xc6) {
        char prefix[48];
        int length = snprintf(prefix, sizeof(prefix), "for %s v%u in (",
            node->op == 0xc4 ? "any" : node->op == 0xc5 ? "all" : "none", (unsigned)node->value + 5);
        return length > 0 && (size_t)length < sizeof(prefix) &&
            yx_put_bytes(writer, prefix, (size_t)length) &&
            yx_integer_expr_print(tree, node->left, writer, 0, false, depth + 1) &&
            yx_put_bytes(writer, "..", 2) &&
            yx_integer_expr_print(tree, node->right, writer, 0, false, depth + 1) &&
            yx_put_bytes(writer, "): (", 4) &&
            yx_integer_expr_print(tree, node->extra, writer, 0, false, depth + 1) && yx_put_u8(writer, ')');
    }
    if (node->op == 0xc0) {
        char declaration[40];
        int length = snprintf(declaration, sizeof(declaration), "with v%u = ", (unsigned)node->value);
        return length > 0 && (size_t)length < sizeof(declaration) &&
            yx_put_bytes(writer, declaration, (size_t)length) &&
            yx_integer_expr_print(tree, node->left, writer, 0, false, depth + 1) &&
            yx_put_bytes(writer, ": (", 3) &&
            yx_integer_expr_print(tree, node->right, writer, 0, false, depth + 1) &&
            yx_put_u8(writer, ')');
    }
    if (node->op == 0xa2)
        return yx_put_bytes(writer, "not (", 5) &&
            yx_integer_expr_print(tree, node->left, writer, 0, false, depth + 1) &&
            yx_put_u8(writer, ')');
    if (node->op == 0x23) return yx_put_bytes(writer, "filesize", 8);
    if (node->op >= 0xb0 && node->op < 0xc0) {
        const char *name = yx_integer_codec_read_name((uint8_t)(node->op - 0xb0));
        return yx_put_bytes(writer, name, strlen(name)) && yx_put_u8(writer, '(') &&
            yx_integer_expr_print(tree, node->left, writer, 0, false, depth + 1) &&
            yx_put_u8(writer, ')');
    }
    if (node->op == 0xc2 || node->op == 0xc3) {
        char name[16];
        int length = snprintf(name, sizeof(name), "v%u", (unsigned)node->value);
        return length > 0 && (size_t)length < sizeof(name) && yx_put_bytes(writer, name, (size_t)length);
    }
    if (node->op == 0xc1)
        return yx_put_bytes(writer, "-(", 2) &&
            yx_integer_expr_print(tree, node->left, writer, 0, false, depth + 1) && yx_put_u8(writer, ')');
    if (node->op == 0x44) {
        char text[40];
        const char *special = yx_float_special_source(node->real);
        if (special) return yx_put_bytes(writer, special, strlen(special));
        int size = snprintf(text, sizeof(text), "%.17g", node->real);
        return size > 0 && (size_t)size < sizeof(text) && yx_put_bytes(writer, text, (size_t)size) &&
            (strchr(text, '.') || strchr(text, 'e') || strchr(text, 'E') || yx_put_bytes(writer, ".0", 2));
    }
    if (node->op == 0x42) {
        char text[40];
        int size;
        if (node->unsigned_value) {
            size = snprintf(text, sizeof(text), "%" PRIu64, (uint64_t)node->value);
            return size > 0 && (size_t)size < sizeof(text) && yx_put_bytes(writer, text, (size_t)size);
        }
        if (node->value == INT64_MIN)
            return yx_put_bytes(writer, "(-9223372036854775807 - 1)", 26);
        size = snprintf(text, sizeof(text), "%" PRId64, node->value);
        return size > 0 && (size_t)size < sizeof(text) &&
               yx_put_bytes(writer, text, (size_t)size);
    }
    op = yx_integer_expr_operator(node->op);
    if (!op) return false;
    typedef struct { int index; unsigned precedence; bool grouped; } yx_integer_print_frame;
    if (tree->count > SIZE_MAX / sizeof(yx_integer_print_frame)) return false;
    yx_integer_print_frame *frames = malloc(tree->count * sizeof(*frames));
    size_t used = 0;
    bool ok = false;
    if (!frames) return false;
    for (;;) {
        grouped = precedence < parent || (right && precedence == parent);
        if (used >= tree->count || node->left < 0 || node->right < 0 ||
            (size_t)node->left >= tree->count || (size_t)node->right >= tree->count ||
            (grouped && !yx_put_u8(writer, '('))) goto print_done;
        frames[used++] = (yx_integer_print_frame){index, precedence, grouped};
        index = node->left; node = &YX_INTEGER_NODES(tree)[index];
        parent = precedence; right = false;
        op = yx_integer_expr_operator(node->op);
        if (!op) break;
        precedence = node->op == 0xa1 ? 1 : node->op == 0xa0 ? 2 :
            yx_integer_expr_boolean(node->op) ? 3 : yx_integer_expr_precedence(node->op) + 3;
    }
    if (!yx_integer_expr_print(tree, index, writer, parent, false, depth + 1)) goto print_done;
    while (used) {
        yx_integer_print_frame frame = frames[--used];
        node = &YX_INTEGER_NODES(tree)[frame.index];
        op = yx_integer_expr_operator(node->op);
        if (!yx_put_bytes(writer, op, strlen(op)) ||
            !yx_integer_expr_print(tree, node->right, writer, frame.precedence, true, depth + 1) ||
            (frame.grouped && !yx_put_u8(writer, ')'))) goto print_done;
    }
    ok = true;
print_done:
    free(frames);
    return ok;
}

static bool yx_integer_wasm_bytes(yx_reader *reader, size_t end,
                                    const uint8_t *bytes, size_t length)
{
    if (reader->at > end || length > end - reader->at ||
        memcmp(reader->data + reader->at, bytes, length)) return false;
    reader->at += length;
    return true;
}

static bool yx_integer_wasm_guard(yx_reader *reader, size_t end, uint8_t kind, int slot)
{
    yx_writer bytes = {0};
    bool ok = yx_integer_emit_guard(&bytes, kind, slot) &&
        yx_integer_wasm_bytes(reader, end, bytes.data, bytes.used);
    free(bytes.data);
    return ok;
}

static int yx_integer_wasm_block(yx_reader *reader, size_t end,
                                   yx_integer_expr *tree, unsigned depth, int binding_slot);

/* A `block` that is not a v12 loop is first decoded as one: its bounds are
 * parsed up to the end of the block before the attempt is rejected, and the
 * parse of every nested block repeats the attempt in turn. A balanced OR of
 * N patterns therefore cost about N^2.3 steps. A rejected attempt is a pure
 * function of where it starts and of the decoder state below, so it is
 * remembered; a deeper retry can only fail again (the nesting limit). */
typedef struct yx_loop_failure {
    const uint8_t *data;
    size_t at, end;
    unsigned depth, stop_call;
    int stop_loop_slot;
    uint8_t flags;
    uint16_t read_mask;
    uint64_t defined[YX_ARCHIVE_MAX_VARS / 64], unsigned_defined[YX_ARCHIVE_MAX_VARS / 64];
} yx_loop_failure;
static void yx_loop_failure_key(yx_loop_failure *key,const yx_reader *reader,size_t at,size_t end,
    const yx_integer_expr *tree,unsigned depth)
{
    key->data=reader->data;key->at=at;key->end=end;key->depth=depth;key->stop_call=tree->stop_call;
    key->stop_loop_slot=tree->stop_loop_slot;key->read_mask=tree->read_mask;
    key->flags=(uint8_t)((tree->stop_call_active?1u:0u)|(tree->stop_loop_bounds?2u:0u)|
        (tree->stop_loop_body?4u:0u)|(tree->legacy_boolean_or?8u:0u)|(tree->has_filesize?16u:0u));
    memcpy(key->defined,tree->defined_variables,sizeof(key->defined));
    memcpy(key->unsigned_defined,tree->unsigned_variables,sizeof(key->unsigned_defined));
}
static bool yx_loop_failure_same(const yx_loop_failure *a,const yx_loop_failure *b)
{
    return a->data==b->data&&a->at==b->at&&a->end==b->end&&a->stop_call==b->stop_call&&
        a->stop_loop_slot==b->stop_loop_slot&&a->flags==b->flags&&a->read_mask==b->read_mask&&
        !memcmp(a->defined,b->defined,sizeof(a->defined))&&
        !memcmp(a->unsigned_defined,b->unsigned_defined,sizeof(a->unsigned_defined));
}
static size_t yx_loop_failure_hash(const yx_loop_failure *key)
{
    uint64_t hash=key->at*0x9e3779b97f4a7c15ull^(key->end+key->flags)*0xc2b2ae3d27d4eb4full^key->stop_call;
    for(size_t i=0;i<sizeof(key->defined)/sizeof(key->defined[0]);++i)hash=(hash^key->defined[i])*1099511628211ull;
    return (size_t)(hash^(hash>>31));
}
/* The table of failures is open-addressed in loop_failures; index 0 of
 * loop_failure_capacity slots holds the entry number plus one. */
static bool yx_loop_failure_known(const yx_integer_expr *tree,const yx_reader *reader,size_t end,unsigned depth)
{
    yx_loop_failure key;
    if(!tree->loop_failure_count)return false;
    yx_loop_failure_key(&key,reader,reader->at,end,tree,depth);
    const size_t *slots=(const size_t *)(tree->loop_failures+tree->loop_failure_capacity);
    for(size_t slot=yx_loop_failure_hash(&key)&(tree->loop_failure_capacity*2-1);slots[slot];
        slot=(slot+1)&(tree->loop_failure_capacity*2-1)) {
        const yx_loop_failure *known=&tree->loop_failures[slots[slot]-1];
        if(yx_loop_failure_same(known,&key))return known->depth<=depth;
    }
    return false;
}
static bool yx_loop_failure_grow(yx_integer_expr *tree)
{
    size_t next=tree->loop_failure_capacity?tree->loop_failure_capacity*2:64;
    yx_loop_failure *grown=malloc(next*sizeof(*grown)+next*2*sizeof(size_t));
    if(!grown)return false;
    size_t *slots=(size_t *)(grown+next);
    memset(slots,0,next*2*sizeof(size_t));
    if(tree->loop_failure_count)memcpy(grown,tree->loop_failures,tree->loop_failure_count*sizeof(*grown));
    for(size_t i=0;i<tree->loop_failure_count;++i) {
        size_t slot=yx_loop_failure_hash(&grown[i])&(next*2-1);
        while(slots[slot])slot=(slot+1)&(next*2-1);
        slots[slot]=i+1;
    }
    free(tree->loop_failures);tree->loop_failures=grown;tree->loop_failure_capacity=next;
    return true;
}
static void yx_loop_failure_note(yx_integer_expr *tree,const yx_reader *reader,size_t at,size_t end,unsigned depth)
{
    yx_loop_failure key;
    yx_loop_failure_key(&key,reader,at,end,tree,depth);
    if(tree->loop_failure_count==tree->loop_failure_capacity&&!yx_loop_failure_grow(tree))return;
    size_t *slots=(size_t *)(tree->loop_failures+tree->loop_failure_capacity);
    size_t mask=tree->loop_failure_capacity*2-1,slot=yx_loop_failure_hash(&key)&mask;
    for(;slots[slot];slot=(slot+1)&mask) {
        yx_loop_failure *known=&tree->loop_failures[slots[slot]-1];
        if(yx_loop_failure_same(known,&key)){if(depth<known->depth)known->depth=depth;return;}
    }
    tree->loop_failures[tree->loop_failure_count]=key;
    slots[slot]=++tree->loop_failure_count;
}
static int yx_integer_wasm_loop_v12(yx_reader *reader,size_t end,yx_integer_expr *tree,unsigned depth)
{
    int upper,lower,body,slot=-1;bool old_bounds=tree->stop_loop_bounds;
    int old_second=tree->second_argument;
    if(depth>256||!tree->has_memory)return -1;
    bool guarded=reader->at+2<=end&&reader->data[reader->at]==2&&reader->data[reader->at+1]==0x40;
    if(guarded)reader->at+=2;
    tree->stop_loop_bounds=true;tree->second_argument=-1;
    upper=yx_integer_wasm_block(reader,end,tree,depth+1,guarded?-33:-1);lower=tree->second_argument;
    tree->stop_loop_bounds=old_bounds;tree->second_argument=old_second;
    if(upper<0||lower<0)return -1;
    for(int candidate=0;candidate<=YX_ARCHIVE_MAX_VARS-7;++candidate) {
        yx_writer expected={0};
        bool matched=yx_integer_loop_v12_init_guarded(&expected,candidate,
            YX_INTEGER_NODES(tree)[lower].unsigned_value,YX_INTEGER_NODES(tree)[upper].unsigned_value,guarded)&&
            yx_integer_wasm_bytes(reader,end,expected.data,expected.used);
        free(expected.data);if(matched){slot=candidate;break;}
    }
    if(slot<0)return -1;
    bool body_guarded=reader->at+2<=end&&reader->data[reader->at]==2&&reader->data[reader->at+1]==0x40;
    if(body_guarded)reader->at+=2;
    bool old_body=tree->stop_loop_body;int old_slot=tree->stop_loop_slot;
    uint64_t old_defined[YX_ARCHIVE_MAX_VARS / 64];
    memcpy(old_defined, tree->defined_variables, sizeof(old_defined));
    tree->stop_loop_body=true;tree->stop_loop_slot=slot;
    tree->defined_variables[slot / 64] |= UINT64_C(1) << (slot % 64);
    tree->defined_variables[(slot + 1) / 64] |= UINT64_C(1) << ((slot + 1) % 64);
    tree->defined_variables[(slot + 5) / 64] |= UINT64_C(1) << ((slot + 5) % 64);
    body=yx_integer_wasm_block(reader,end,tree,depth+1,body_guarded?-34:-1);
    tree->stop_loop_body=old_body;tree->stop_loop_slot=old_slot;
    memcpy(tree->defined_variables, old_defined, sizeof(old_defined));
    if(body<0)return -1;
    for(uint8_t op=0xc4;op<=0xc6;++op) {
        yx_writer expected={0};
        bool matched=(body_guarded?yx_integer_loop_v12_guarded_tail(&expected,slot,op):
            yx_integer_loop_v12_tail(&expected,slot,op))&&
            yx_integer_wasm_bytes(reader,end,expected.data,expected.used);
        free(expected.data);
        if(matched) {
            int node=yx_integer_expr_node_new(tree,op,lower,upper,slot);
            if(node>=0)YX_INTEGER_NODES(tree)[node].extra=body;
            return node;
        }
    }
    return -1;
}
static int yx_integer_wasm_loop(yx_reader *reader, size_t end,
                                   yx_integer_expr *tree, unsigned depth)
{
    int range, body, lower, upper;
    int64_t address, slot;
    uint8_t marker;
    yx_writer expected = {0};
    bool matched;
    if (depth > 256 || !tree->has_memory || !yx_get_u8(reader, &marker) || marker != 0x41 ||
        !yx_get_sleb_i64(reader, &address) || address < 0 || address > (YX_ARCHIVE_MAX_VARS - 7) * 8 || address % 8 ||
        !yx_get_u8(reader, &marker) || marker != 0x02 ||
        !yx_get_u8(reader, &marker) || marker != 0x7e) return -1;
    slot = address / 8;
    range = yx_integer_wasm_block(reader, end, tree, depth + 1, -2);
    if (range < 0 || YX_INTEGER_NODES(tree)[range].op != 0x7c ||
        YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[range].right].op != 0x42 ||
        YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[range].right].value != 1 ||
        YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[range].left].op != 0x7d) return -1;
    upper = YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[range].left].left;
    lower = YX_INTEGER_NODES(tree)[YX_INTEGER_NODES(tree)[range].left].right;
    matched = yx_integer_loop_init_tail(&expected, slot) &&
        yx_integer_wasm_bytes(reader, end, expected.data, expected.used);
    free(expected.data);
    if (!matched) return -1;
    body = yx_integer_wasm_block(reader, end, tree, depth + 1, -1);
    if (body < 0) return -1;
    for (uint8_t op = 0xc4; op <= 0xc6; ++op) {
        size_t start = reader->at;
        expected = (yx_writer){0};
        matched = yx_integer_loop_tail(&expected, slot, op) &&
            yx_integer_wasm_bytes(reader, end, expected.data, expected.used);
        free(expected.data);
        if (matched) {
            int node = yx_integer_expr_node_new(tree, op, lower, upper, slot);
            if (node >= 0) YX_INTEGER_NODES(tree)[node].extra = body;
            return node;
        }
        reader->at = start;
    }
    return -1;
}

static int yx_integer_wasm_binding(yx_reader *reader, size_t end,
                                    yx_integer_expr *tree, int *slot, unsigned depth)
{
    uint64_t offset;
    int64_t address;
    uint8_t marker, store, alignment;
    int node;
    if (!tree->has_memory || !yx_get_u8(reader, &marker) || marker != 0x41 ||
        !yx_get_sleb_i64(reader, &address) || address < 0 || address >= YX_ARCHIVE_MAX_VARS * 8 || address % 8) return -1;
    *slot = (int)(address / 8);
    node = yx_integer_wasm_block(reader, end, tree, depth + 1, *slot);
    if (node < 0) return -1;
    store = YX_INTEGER_NODES(tree)[node].floating ? 0x39 : 0x37;
    if (node < 0 || !yx_get_u8(reader, &marker) || marker != store ||
        !yx_get_u8(reader, &alignment) || alignment != 3 ||
        !yx_get_uleb(reader, &offset) || offset != 256) return -1;
    yx_writer clear = {0};
    bool valid = yx_integer_clear_variable(&clear, *slot) && yx_put_u8(&clear, 0x0b) &&
        yx_integer_wasm_bytes(reader, end, clear.data, clear.used);
    free(clear.data);
    if (!valid) return -1;
    uint64_t bit = UINT64_C(1) << (*slot % 64);
    tree->defined_variables[*slot / 64] &= ~bit;
    if (YX_INTEGER_NODES(tree)[node].unsigned_value) tree->unsigned_variables[*slot / 64] |= bit;
    else tree->unsigned_variables[*slot / 64] &= ~bit;
    return node;
}

static int yx_integer_wasm_variable_slot(const yx_reader *reader, size_t start)
{
    yx_reader r = *reader;
    int64_t address, mask;
    uint8_t marker;
    uint64_t alignment, offset;
    r.at = start;
    if (!yx_get_u8(&r, &marker) || marker != 0x41 ||
        !yx_get_sleb_i64(&r, &address) || address < 0 || address >= YX_ARCHIVE_MAX_VARS / 8 ||
        !yx_get_u8(&r, &marker) || marker != 0x2d ||
        !yx_get_uleb(&r, &alignment) || alignment || !yx_get_uleb(&r, &offset) || offset ||
        !yx_get_u8(&r, &marker) || marker != 0x41 || !yx_get_sleb_i64(&r, &mask)) return -1;
    for (unsigned bit = 0; bit < 8; ++bit)
        if (mask == (INT64_C(1) << bit)) return (int)(address * 8 + bit);
    return -1;
}

static int yx_integer_wasm_block_inner(yx_reader *reader, size_t end,
                                   yx_integer_expr *tree, unsigned depth, int binding_slot,int *stack,size_t stack_capacity,
                                   int *bindings, int *slots, size_t binding_capacity)
{
    int joined = -1;
    size_t binding_count = 0;
    size_t used = 0;
    uint8_t marker, join_op = 0;
    if (depth > 256) return -1;
    while (reader->at < end && yx_get_u8(reader, &marker)) {
        int node;
        bool floating_opcode = false, mixed_comparison = false;
        size_t start = reader->at - 1;
        if(marker==0x21&&tree->stop_loop_bounds&&used==2&&!binding_count&&joined<0) {
            reader->at=start;tree->second_argument=stack[1];return stack[0];
        }
        /* A loop body may end in a `with` whose bindings are still pending:
         * 1.23.0 stores defined bindings without clearing them afterwards. */
        if(marker==4&&tree->stop_loop_body&&used==1&&joined<0) {
            for(uint8_t op=0xc4;op<=0xc6;++op) {
                yx_writer expected={0};
                bool matched=(binding_slot==-34?yx_integer_loop_v12_guarded_tail(&expected,tree->stop_loop_slot,op):
                    yx_integer_loop_v12_tail(&expected,tree->stop_loop_slot,op))&&
                    expected.used<=end-start&&!memcmp(reader->data+start,expected.data,expected.used);
                free(expected.data);
                if(matched) {
                    while(binding_count) {
                        --binding_count;
                        stack[0]=yx_integer_expr_node_new(tree,0xc0,bindings[binding_count],stack[0],slots[binding_count]);
                        if(stack[0]<0)return -1;
                    }
                    reader->at=start;return stack[0];
                }
            }
        }
        if (binding_slot >= 0 && (marker == 0x37 || marker == 0x39)) {
            --reader->at;
            return used == 1 && joined < 0 && !binding_count ? stack[0] : -1;
        }
        if(marker==0x10&&tree->stop_call_active) {
            yx_reader probe=*reader;uint64_t function;
            if(yx_get_uleb(&probe,&function)&&function==tree->stop_call&&used>=1&&used<=2&&!binding_count&&joined<0) {
                reader->at=start;tree->second_argument=used==2?stack[1]:-1;return stack[0];
            }
        }
        if (marker == 0x0b) {
            if (used != 1) return -1;
            node = stack[0];
            /* The plain-OR writer tests every operand, then leaves a false
             * fallback. It belongs to the control flow, not to the operand
             * list; adding it to the AST would emit another final guard. */
            if (!binding_count && joined >= 0 && join_op == 0xa1 &&
                YX_INTEGER_NODES(tree)[node].op == 0x41 &&
                !YX_INTEGER_NODES(tree)[node].value) return joined;
            while (binding_count) {
                --binding_count;
                node = yx_integer_expr_node_new(tree, 0xc0, bindings[binding_count], node, slots[binding_count]);
            }
            return node < 0 ? -1 : joined < 0 ? node :
                yx_integer_expr_node_new(tree, join_op, joined, node, 0);
        }
        int special = -1;
        int variable_slot = marker == 0x41 ? yx_integer_wasm_variable_slot(reader, start) : -1;
        if (tree->decode_primary) {
            reader->at = start;
            special = tree->decode_primary(reader, end, tree, tree->extension);
            if (special < 0) reader->at = start + 1;
        }
        if (special >= 0) {
            node = special;
        } else if (variable_slot >= 0 && tree->has_memory) {
            unsigned slot = (unsigned)variable_slot;
            bool matched = false;
            for (unsigned floating = 0; floating < 2; ++floating) {
                yx_writer bytes = {0};
                reader->at = start;
                matched = yx_integer_emit_variable(&bytes, slot, floating != 0, binding_slot) &&
                    yx_integer_wasm_bytes(reader, end, bytes.data, bytes.used);
                free(bytes.data);
                if (matched) {
                    node = yx_integer_expr_node_new(tree, 0xc2, -1, -1, slot);
                    if (node >= 0) {
                        YX_INTEGER_NODES(tree)[node].floating = floating != 0;
                        YX_INTEGER_NODES(tree)[node].unsigned_value = !!(tree->unsigned_variables[slot / 64] & (UINT64_C(1) << (slot % 64)));
                    }
                    break;
                }
            }
            if (!matched) return -1;
        } else if (marker == 0x44) {
            double value;
            if (end - reader->at < 8 || !yx_get_float(reader, &value)) return -1;
            node = yx_integer_expr_real(tree, value);
        } else if (marker == 0xb9 || marker == 0xba) {
            if (!used || YX_INTEGER_NODES(tree)[stack[used - 1]].floating) return -1;
            /* Promotion is inferred again from the enclosing floating operation. */
            if (marker == 0xba) YX_INTEGER_NODES(tree)[stack[used - 1]].unsigned_value = true;
            continue;
        } else if (marker == 0x9a) {
            if (!used || !YX_INTEGER_NODES(tree)[stack[used - 1]].floating) return -1;
            node = yx_integer_expr_node_new(tree, 0xc1, stack[used - 1], stack[used - 1], 0);
            --used;
        } else if(marker==0x41) {
            yx_reader probe=*reader;int64_t address;uint64_t alignment,offset;uint8_t opcode;
            if(tree->has_memory&&!used&&binding_slot<0&&binding_count<binding_capacity&&
               yx_get_sleb_i64(&probe,&address)&&address>=0&&address<YX_ARCHIVE_MAX_VARS*8&&!(address%8)&&
               probe.at<end&&(probe.data[probe.at]==0x41||probe.data[probe.at]==0x42||
                   probe.data[probe.at]==0x44||probe.data[probe.at]==0x23)) {
                size_t saved_count=tree->count;yx_reader saved=*reader;bool saved_failed=tree->failed;
                uint64_t saved_defined[YX_ARCHIVE_MAX_VARS/64],saved_unsigned[YX_ARCHIVE_MAX_VARS/64];
                memcpy(saved_defined,tree->defined_variables,sizeof(saved_defined));
                memcpy(saved_unsigned,tree->unsigned_variables,sizeof(saved_unsigned));
                *reader=probe;int value=yx_integer_wasm_block(reader,end,tree,depth+1,(int)(address/8));
                if(value>=0&&yx_integer_expr_defined(tree,value,0)&&
                   yx_get_u8(reader,&opcode)&&opcode==(YX_INTEGER_NODES(tree)[value].floating?0x39:0x37)&&
                   yx_get_uleb(reader,&alignment)&&alignment==3&&yx_get_uleb(reader,&offset)&&offset==256) {
                    int slot=(int)(address/8);uint64_t bit=UINT64_C(1)<<(slot%64);
                    tree->defined_variables[slot/64]|=bit;
                    if(YX_INTEGER_NODES(tree)[value].unsigned_value)tree->unsigned_variables[slot/64]|=bit;
                    else tree->unsigned_variables[slot/64]&=~bit;
                    bindings[binding_count]=value;slots[binding_count++]=slot;continue;
                }
                *reader=saved;tree->count=saved_count;tree->failed=saved_failed;
                memcpy(tree->defined_variables,saved_defined,sizeof(saved_defined));
                memcpy(tree->unsigned_variables,saved_unsigned,sizeof(saved_unsigned));
            }
            probe=*reader;
            if(yx_get_sleb_i64(&probe,&address)&&address>=0&&address<YX_ARCHIVE_MAX_VARS*8&&!(address%8)&&
               (tree->defined_variables[address/8/64]&(UINT64_C(1)<<(address/8%64)))&&
               yx_get_u8(&probe,&opcode)&&(opcode==0x29||opcode==0x2b)&&yx_get_uleb(&probe,&alignment)&&alignment==3&&
               yx_get_uleb(&probe,&offset)&&offset==256&&probe.at<=end) {
                *reader=probe;node=yx_integer_expr_node_new(tree,0xc3,-1,-1,address/8);
                if(node>=0) {
                    YX_INTEGER_NODES(tree)[node].floating=opcode==0x2b;
                    YX_INTEGER_NODES(tree)[node].unsigned_value=!!(tree->unsigned_variables[address/8/64]&(UINT64_C(1)<<(address/8%64)));
                }
            } else {
                int64_t value;if(!yx_get_sleb_i64(reader,&value)||(value!=0&&value!=1))return -1;
                node=yx_integer_expr_node_new(tree,0x41,-1,-1,value);
            }
        } else if (marker == 0x41 || marker == 0x42) {
            int64_t value;
            if (!yx_get_sleb_i64(reader, &value) ||
                (marker == 0x41 && value != 0 && value != 1)) return -1;
            node = yx_integer_expr_node_new(tree, marker, -1, -1, value);
        } else if (marker == 0x02) {
            if (!yx_get_u8(reader, &marker)) return -1;
            if (marker == 0x40) {
                if (binding_count == binding_capacity) return -1;
                node = yx_integer_wasm_binding(reader, end, tree, &slots[binding_count], depth + 1);
                if (node < 0) return -1;
                bindings[binding_count++] = node;
                continue;
            }
            if (marker != 0x7f) return -1;
            size_t saved_at=reader->at,saved_count=tree->count;
            bool loop_known=tree->has_memory&&yx_loop_failure_known(tree,reader,end,depth+1);
            bool clean_start=!tree->failed&&tree->has_memory;
            node=loop_known?-1:yx_integer_wasm_loop_v12(reader,end,tree,depth+1);
            /* Only a structural mismatch is remembered, not one caused by the
             * node table filling up or by an earlier failure of the tree. */
            if(node<0&&!loop_known&&clean_start&&!tree->failed)yx_loop_failure_note(tree,reader,saved_at,end,depth+1);
            if(node<0) {
                reader->at=saved_at;tree->count=saved_count;tree->failed=false;
                node=yx_integer_wasm_loop(reader,end,tree,depth+1);
            }
            if(node<0) {
                reader->at=saved_at;tree->count=saved_count;tree->failed=false;
                node=yx_integer_wasm_block(reader,end,tree,depth+1,-1);
            }
            if (node >= 0 && tree->decode_boolean_block && join_op != 0xa1 &&
                !(sizeof(yx_integer_or_guard) <= end - reader->at &&
                  !memcmp(reader->data + reader->at, yx_integer_or_guard,
                          sizeof(yx_integer_or_guard))))
                node = tree->decode_boolean_block(tree, node, tree->extension);
        } else if (marker == 0x45) {
            if (!used) return -1;
            node = yx_integer_expr_node_new(tree, 0xa2, stack[used - 1], stack[used - 1], 0);
            --used;
        } else if (marker == 0x04) {
            uint8_t op;
            const uint8_t *guard;
            size_t guard_length;
            if (used != 1) return -1;
            while (binding_count) {
                --binding_count;
                stack[0] = yx_integer_expr_node_new(tree, 0xc0, bindings[binding_count], stack[0], slots[binding_count]);
                if (stack[0] < 0) return -1;
            }
            if (sizeof(yx_integer_and_guard) <= end - start &&
                !memcmp(reader->data + start, yx_integer_and_guard, sizeof(yx_integer_and_guard))) {
                op = 0xa0; guard = yx_integer_and_guard; guard_length = sizeof(yx_integer_and_guard);
            } else {
                op = 0xa1; guard = yx_integer_or_guard; guard_length = sizeof(yx_integer_or_guard);
            }
            if ((join_op && join_op != op) || guard_length > end - start ||
                memcmp(reader->data + start, guard, guard_length)) return -1;
            reader->at = start + guard_length;
            joined = joined < 0 ? stack[0] : yx_integer_expr_node_new(tree, op, joined, stack[0], 0);
            if (joined < 0) return -1;
            join_op = op; used = 0;
            continue;
        } else if (marker == 0x23) {
            reader->at = start;
            yx_writer bytes={0};
            bool ok=yx_integer_emit_guard(&bytes,0x23,binding_slot);
            if(ok)bytes.data[1]=tree->filesize_id;
            ok=ok&&yx_integer_wasm_bytes(reader,end,bytes.data,bytes.used);
            free(bytes.data);if(!ok)return -1;
            node = yx_integer_expr_node_new(tree, marker, -1, -1, 0);
        } else if (marker == 0x10) {
            uint64_t function;
            uint8_t type;
            if (!used || !yx_get_uleb(reader, &function) ||
                !yx_integer_wasm_guard(reader, end, 0x10, binding_slot)) return -1;
            for (type = 0; type < YX_INTEGER_READ_COUNT; ++type)
                if ((tree->read_mask & (1u << type)) && tree->read_ids[type] == function) break;
            if (type == YX_INTEGER_READ_COUNT) return -1;
            node = yx_integer_expr_node_new(tree, (uint8_t)(0xb0 + type),
                                            stack[used - 1], stack[used - 1], 0);
            --used;        } else {
            if (marker == 0x22) {
                bool shifted=false;
                if(used>=2) {
                    const yx_integer_expr_node *left=&YX_INTEGER_NODES(tree)[stack[used-2]],
                        *right=&YX_INTEGER_NODES(tree)[stack[used-1]];
                    for(uint8_t local=0;local<2&&!shifted;++local)for(uint8_t op=0x86;op<=0x87&&!shifted;++op) {
                        yx_writer expected={0};reader->at=start;
                        shifted=yx_integer_shift_v12_emit(&expected,op,left->unsigned_value,right->unsigned_value,local)&&
                            yx_integer_wasm_bytes(reader,end,expected.data,expected.used);
                        free(expected.data);if(shifted)marker=op;
                    }
                }
                if(shifted) {
                    node=yx_integer_expr_node_new(tree,marker,stack[used-2],stack[used-1],0);
                    used-=2;
                    if(node<0||used==stack_capacity)return -1;
                    stack[used++]=node;continue;
                }
                reader->at=start+1;
                if (binding_slot == -2 && reader->at < end && reader->data[reader->at] == 0 &&
                    reader->at + 1 < end && reader->data[reader->at + 1] == 0x7d) {
                    ++reader->at;
                    continue;
                }
                reader->at = start;
                if (!yx_integer_wasm_guard(reader, end, 0x22, binding_slot)) return -1;
                if (!yx_get_u8(reader, &marker) ||
                    (marker != 0x7f && marker != 0x80 && marker != 0x81 && marker != 0x82)) return -1;
                if(marker==0x80||marker==0x82) {
                    if(used<2)return -1;
                    yx_integer_expr_node *left=&YX_INTEGER_NODES(tree)[stack[used-2]],
                        *right=&YX_INTEGER_NODES(tree)[stack[used-1]];
                    /* i64.const stores only bits. The unsigned opcode restores
                     * the type of a high-bit literal before folding its prefix. */
                    if(!left->unsigned_value&&!right->unsigned_value) {
                        if(left->op==0x42&&left->value<0)left->unsigned_value=true;
                        else if(right->op==0x42&&right->value<0)right->unsigned_value=true;
                    }
                    --marker;
                }
            } else if(marker==0x21&&used>=2&&end-start>=4&&
                      !memcmp(reader->data+start,"\x21\x01\x21\x00",4)) {
                yx_writer expected={0};reader->at=start;
                bool matched=yx_integer_signed_division_emit(&expected,binding_slot)&&
                    yx_integer_wasm_bytes(reader,end,expected.data,expected.used);
                free(expected.data);if(!matched)return -1;marker=0x7f;
            } else if (marker == 0x21 && used >= 2 && end-start >= 6 &&
                       !memcmp(reader->data+start,"\x21\x01\x22\x00\x20\x01",6)) {
                const yx_integer_expr_node *left=&YX_INTEGER_NODES(tree)[stack[used-2]],
                    *right=&YX_INTEGER_NODES(tree)[stack[used-1]];
                bool matched=false;
                for(uint8_t comparison=0x51;comparison<=0x59;++comparison) {
                    if(comparison>0x52&&!(comparison&1))continue;
                    yx_writer expected={0};reader->at=start;
                    matched=yx_integer_comparison_emit(&expected,comparison,left->unsigned_value,right->unsigned_value,
                        yx_integer_expr_non_negative(left),yx_integer_expr_non_negative(right))&&
                        yx_integer_wasm_bytes(reader,end,expected.data,expected.used);
                    free(expected.data);if(matched){marker=comparison;break;}
                }
                if(!matched)return -1;
                mixed_comparison=true;
            } else if (marker == 0x21) {
                if (sizeof(yx_integer_shift_prefix) + 1 + sizeof(yx_integer_shift_suffix) > end - start ||
                    memcmp(reader->data + start, yx_integer_shift_prefix,
                           sizeof(yx_integer_shift_prefix))) return -1;
                reader->at = start + sizeof(yx_integer_shift_prefix);
                if (!yx_get_u8(reader, &marker) || (marker != 0x86 && marker != 0x87 && marker != 0x88) ||
                    memcmp(reader->data + reader->at, yx_integer_shift_suffix,
                           sizeof(yx_integer_shift_suffix))) return -1;
                reader->at += sizeof(yx_integer_shift_suffix);
                if(marker==0x88)marker=0x87;
            } else if (marker == 0x7f || marker == 0x81 || marker == 0x86 || marker == 0x87) return -1;
            if (marker >= 0xa0 && marker <= 0xa3) {
                static const uint8_t ops[] = {0x7c,0x7d,0x7e,0x7f};
                floating_opcode = true;
                marker = ops[marker - 0xa0];
            } else if (marker >= 0x61 && marker <= 0x66) {
                static const uint8_t ops[] = {0x51,0x52,0x53,0x55,0x57,0x59};
                marker = ops[marker - 0x61];
            }
            if(marker>=0x54&&marker<=0x5a&&!(marker&1))--marker;
            if (!yx_integer_expr_operator(marker) || marker >= 0xa0 || used < 2) return -1;
            if(marker>=0x51&&marker<=0x59&&!mixed_comparison) {
                yx_integer_expr_node *left=&YX_INTEGER_NODES(tree)[stack[used-2]],
                    *right=&YX_INTEGER_NODES(tree)[stack[used-1]];
                if(left->unsigned_value&&right->op==0x42&&right->value<0)right->unsigned_value=true;
                if(right->unsigned_value&&left->op==0x42&&left->value<0)left->unsigned_value=true;
            }
            node = yx_integer_expr_node_new(tree, marker, stack[used - 2], stack[used - 1], 0);
            if (node >= 0 && floating_opcode && !YX_INTEGER_NODES(tree)[node].floating) {
                yx_integer_expr_node *value = &YX_INTEGER_NODES(tree)[node];
                double left = (double)YX_INTEGER_NODES(tree)[value->left].value;
                double right = (double)YX_INTEGER_NODES(tree)[value->right].value;
                value->floating = true;
                value->real = marker == 0x7c ? left + right : marker == 0x7d ? left - right : marker == 0x7e ? left * right : left / right;
            }
            used -= 2;
        }
        if (node < 0 || used == stack_capacity) return -1;
        stack[used++] = node;
    }
    return -1;
}

/* Every block needs a value stack as long as the bytes it may still read.
 * A combined archive condition has thousands of blocks, so the large stacks
 * are recycled through a few per-thread buffers instead of being obtained
 * from (and returned to) the heap each time. */
enum { YX_WASM_SCRATCH_SLOTS = 8 };
typedef struct { int *buffers[YX_WASM_SCRATCH_SLOTS]; size_t ints[YX_WASM_SCRATCH_SLOTS]; } yx_integer_wasm_scratch;
static yx_thread_storage yx_integer_wasm_scratch_storage = YX_THREAD_STORAGE_INIT;
static void yx_integer_wasm_scratch_destroy(void *opaque)
{
    yx_integer_wasm_scratch *pool = opaque;
    for (size_t i = 0; i < YX_WASM_SCRATCH_SLOTS; ++i) free(pool->buffers[i]);
}
/* *ints is the required length on entry and the length of the returned
 * buffer on exit, which release must be given back. */
static _Thread_local yx_integer_wasm_scratch *yx_integer_wasm_scratch_pool;
static yx_integer_wasm_scratch *yx_integer_wasm_scratch_get(void)
{
    if (!yx_integer_wasm_scratch_pool)
        yx_integer_wasm_scratch_pool = yx_thread_storage_get(
            &yx_integer_wasm_scratch_storage, sizeof(*yx_integer_wasm_scratch_pool),
            yx_integer_wasm_scratch_destroy);
    return yx_integer_wasm_scratch_pool;
}
static int *yx_integer_wasm_scratch_acquire(size_t *ints)
{
    yx_integer_wasm_scratch *pool = yx_integer_wasm_scratch_get();
    size_t need = *ints, rounded = 1024;
    if (pool)
        for (size_t i = 0; i < YX_WASM_SCRATCH_SLOTS; ++i)
            if (pool->buffers[i] && pool->ints[i] >= need) {
                int *buffer = pool->buffers[i];
                *ints = pool->ints[i];
                pool->buffers[i] = NULL;
                pool->ints[i] = 0;
                return buffer;
            }
    while (rounded < need && rounded <= SIZE_MAX / 2 / sizeof(int)) rounded *= 2;
    if (rounded < need) rounded = need;
    if (rounded > SIZE_MAX / sizeof(int)) return NULL;
    *ints = rounded;
    return malloc(rounded * sizeof(int));
}
static void yx_integer_wasm_scratch_release(int *buffer, size_t ints)
{
    yx_integer_wasm_scratch *pool = yx_integer_wasm_scratch_get();
    size_t smallest = 0;
    if (!pool) { free(buffer); return; }
    for (size_t i = 0; i < YX_WASM_SCRATCH_SLOTS; ++i) {
        if (!pool->buffers[i]) { smallest = i; break; }
        if (pool->ints[i] < pool->ints[smallest]) smallest = i;
    }
    if (pool->buffers[smallest] && pool->ints[smallest] >= ints) { free(buffer); return; }
    free(pool->buffers[smallest]);
    pool->buffers[smallest] = buffer;
    pool->ints[smallest] = ints;
}

static int yx_integer_wasm_block(yx_reader *reader,size_t end,
    yx_integer_expr *tree,unsigned depth,int binding_slot)
{
    if(end<reader->at||end>reader->length)return -1;
    size_t capacity=end-reader->at+1;
    size_t bindings = capacity < YX_ARCHIVE_MAX_VARS ? capacity : YX_ARCHIVE_MAX_VARS;
    if(capacity>SIZE_MAX/sizeof(int)-bindings*2)return -1;
    if(!tree->count&&(capacity>SIZE_MAX/2||!yx_integer_expr_reserve(tree,capacity*2)))return -1;
    int local[192],*stack=local;
    size_t scratch_ints=capacity+bindings*2;
    if(capacity>64) {
        stack=yx_integer_wasm_scratch_acquire(&scratch_ints);
        if(!stack)return -1;
    }
    int result=yx_integer_wasm_block_inner(reader,end,tree,depth,binding_slot,stack,capacity,
        stack+capacity,stack+capacity+bindings,bindings);
    if(stack!=local)yx_integer_wasm_scratch_release(stack,scratch_ints);
    return result;
}

static bool yx_integer_wasm_name(yx_reader *reader, size_t end,
                                   const uint8_t **name, size_t *length)
{
    uint64_t size;
    if (!yx_get_uleb(reader, &size) || reader->at > end || size > end - reader->at)
        return false;
    *name = reader->data + reader->at; *length = (size_t)size;
    reader->at += (size_t)size;
    return true;
}

static bool yx_integer_wasm_header(yx_reader *reader, yx_integer_expr *tree)
{
    static const uint8_t sections[] = {1,2,3,7,10};
    if (reader->length < 8 || memcmp(reader->data, yx_constant_wasm, 8)) return false;
    reader->at = 8; tree->match_id = 255;
    for (size_t section = 0; section < sizeof(sections); ++section) {
        uint8_t id;
        uint64_t length;
        size_t end;
        if (!yx_get_u8(reader, &id) || id != sections[section]) return false;
        if (id == 10) { --reader->at; return tree->match_id != 255; }
        if (!yx_get_uleb(reader, &length) || length > reader->length - reader->at) return false;
        end = reader->at + (size_t)length;
        if (id == 2) {
            uint64_t count;
            if (!yx_get_uleb(reader, &count) || count > YX_INTEGER_READ_COUNT+3) return false;
            for (uint64_t i = 0; i < count; ++i) {
                const uint8_t *module, *name;
                size_t module_length, name_length;
                uint8_t kind;
                uint64_t type_index;
                if (!yx_integer_wasm_name(reader, end, &module, &module_length) ||
                    !yx_integer_wasm_name(reader, end, &name, &name_length) ||
                    !yx_get_u8(reader, &kind)) return false;
                if (kind == 0 && module_length == 12 && !memcmp(module, "yara_x::wasm", 12)) {
                    uint8_t type;
                    if (!yx_get_uleb(reader, &type_index)) return false;
                    if (name_length == 21 && !memcmp(name, "rule_match@rule_id:i@", 21)) {
                        if (tree->match_id != 255 || type_index != 2) return false;
                        tree->match_id = tree->function_count++;
                    } else {
                        for (type = 0; type < YX_INTEGER_READ_COUNT; ++type) {
                            const char *expected = yx_integer_codec_read_import_name(type);
                            if (name_length == strlen(expected) && !memcmp(name, expected, name_length)) break;
                        }
                        if (type == YX_INTEGER_READ_COUNT || type_index != 3 || (tree->read_mask & (1u << type))) return false;
                        tree->read_mask |= (uint16_t)(1u << type);
                        tree->read_ids[type] = tree->function_count++;
                    }
                } else if (kind == 3 && module_length == 6 && !memcmp(module, "yara_x", 6) &&
                           name_length == 8 && !memcmp(name, "filesize", 8)) {
                    uint8_t value_type, mutable;
                    if (tree->has_filesize || !yx_get_u8(reader, &value_type) || value_type != 0x7e ||
                        !yx_get_u8(reader, &mutable) || mutable != 1) return false;
                    tree->has_filesize = true;
                } else if (kind == 2 && module_length == 6 && !memcmp(module, "yara_x", 6) &&
                           name_length == 11 && !memcmp(name, "main_memory", 11)) {
                    uint8_t flags, minimum;
                    if (tree->has_memory || !yx_get_u8(reader, &flags) || flags != 0 ||
                        !yx_get_u8(reader, &minimum) || minimum != 1) return false;
                    tree->has_memory = true;
                } else return false;
            }
            if (reader->at != end) return false;
        }
        reader->at = end;
    }
    return false;
}

static yx_ser_result yx_wasm_runtime_integer(const uint8_t *wasm, size_t length,
                                              yx_ser_rule *rule)
{
    uint8_t prefix[] = {0x01, 0x01, 0x7e, 0x02, 0x7f};
    yx_reader reader = {wasm, length, 78, false, false};
    yx_integer_expr *tree = NULL;
    yx_writer source = {0};
    int root;
    size_t body_end, prefix_length;
    uint64_t section_length, body_length;
    uint8_t marker;
    uint8_t *canonical = NULL;
    size_t canonical_length = 0;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    uint8_t profile;
    tree = calloc(1, sizeof(*tree));
    if (!tree) return YX_SER_NO_MEMORY;
    if (!yx_integer_wasm_header(&reader, tree)) goto done;
    if (!yx_get_u8(&reader, &marker) || marker != 0x0a ||
        !yx_get_uleb(&reader, &section_length) || section_length != length - reader.at ||
        !yx_get_u8(&reader, &marker) || marker != 3 ||
        !yx_get_uleb(&reader, &body_length) || body_length > length - reader.at ||
        body_length < sizeof(prefix)) goto done;
    body_end = reader.at + (size_t)body_length;
    if (wasm[reader.at] == 0) {
        if (wasm[reader.at + 1] != 0x02 || wasm[reader.at + 2] != 0x7f) goto done;
        prefix_length = 3;
    } else {
        if (wasm[reader.at + 1] == 2) prefix[1] = 2;
        if (memcmp(wasm + reader.at, prefix, sizeof(prefix))) goto done;
        prefix_length = sizeof(prefix);
    }
    reader.at += prefix_length;
    root = yx_integer_wasm_block(&reader, body_end, tree, 0, -1);
    if (root < 0 || !yx_integer_expr_print(tree, root, &source, 0, false, 0) ||
        !yx_put_u8(&source, 0)) goto done;
    for (profile = 0; profile < 4; ++profile) {
        free(canonical); canonical = NULL;
        if (yx_make_runtime_integer_wasm((const char *)source.data, profile,
                                           &canonical, &canonical_length) &&
            canonical_length == length && !memcmp(canonical, wasm, length)) break;
    }
    if (profile == 4) goto done;
    rule->runtime_integer_condition = (char *)source.data;
    rule->runtime_integer_import_profile = profile;
    source.data = NULL;
    result = YX_SER_SUCCESS;
done:
    free(canonical); free(source.data); yx_integer_expr_free(tree);
    return result;
}
