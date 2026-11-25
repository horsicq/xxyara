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

/* Typed scalar module-expression codec. Module schema data is generated
 * separately from rule code; imports and Wasm function types are collected
 * from the expression tree and ordered for the pinned reference profile. */

typedef struct yx_archive_module_field {
    const char *path;
    uint16_t indexes[16];
    uint8_t depth, kind, state, element;
    int64_t integer;
    double real;
} yx_archive_module_field;
typedef struct yx_archive_module_signature {
    const char *path, *name;
    uint8_t args[8], argc, result, undefined;
} yx_archive_module_signature;
typedef struct yx_archive_module_schema {
    const char *name;
    const uint8_t *globals[4];
    size_t globals_length[4];
    const yx_archive_module_field *fields;
    size_t field_count;
    const yx_archive_module_signature *signatures;
    size_t signature_count;
} yx_archive_module_schema;
typedef struct yx_archive_symbol_order {
    const char *module, *name;
    uint16_t ranks[4];
} yx_archive_symbol_order;
#include "serialization_modules_data.h"
#include "serialization_modules_maps.h"
#include "serialization_modules_elements.h"
#include "serialization_capi_order.h"

#define YX_MODULE_IMPORTS 128
/* How deep the module-expression walks recurse. Upstream's IR has no such
 * limit (a condition nests as deep as its 2048 variables allow); the levels
 * past YX_MODULE_SWITCH_DEPTH run on a deep stack. */
#define YX_MODULE_DEPTH 1024
/* A walk that gets YX_MODULE_SWITCH_DEPTH levels deep goes on on a deep
 * stack (yx_run_deep_walk) unless it already runs on one: the caller's
 * thread (a library caller's, 1 MiB or less) holds only those first levels. */
#define YX_MODULE_SWITCH_DEPTH 48
#define YX_MODULE_DEEP(depth) ((depth) >= YX_MODULE_SWITCH_DEPTH && !yx_deep_stack_ready(YX_MODULE_DEPTH))
/* Set when a walk could not get its deep stack (no thread): its answer is
 * then not the walk's, and yx_ser_encode / yx_ser_decode_many fail with
 * YX_SER_NO_MEMORY instead of using it. */
static _Thread_local bool yx_module_deep_failed;
/* Set when an and/with walk (yx_and_leaves) or a rule-constraint walk ran
 * out of memory: its answer is incomplete, and the same entry points fail
 * with YX_SER_NO_MEMORY. */
static _Thread_local bool yx_walk_no_memory;
/* The walk on the deep stack runs on another thread: its failure flags are
 * that thread's, and come back here with the job. */
typedef struct {
    void (*call)(void *);
    void *data;
    bool walk_no_memory, deep_failed;
} yx_module_deep_job;
static void yx_module_deep_thunk(void *data)
{
    yx_module_deep_job *job = data;
    bool walk = yx_walk_no_memory, deep = yx_module_deep_failed;
    yx_walk_no_memory = false;
    yx_module_deep_failed = false;
    job->call(job->data);
    job->walk_no_memory = yx_walk_no_memory;
    job->deep_failed = yx_module_deep_failed;
    yx_walk_no_memory = walk || job->walk_no_memory;
    yx_module_deep_failed = deep || job->deep_failed;
}
static bool yx_module_deep_walk(size_t depth, void (*call)(void *), void *data)
{
    yx_module_deep_job job = {call, data, false, false};
    bool ran = yx_run_deep_walk(depth, yx_module_deep_thunk, &job);
    if (job.walk_no_memory) yx_walk_no_memory = true;
    if (job.deep_failed || !ran) yx_module_deep_failed = true;
    return ran;
}

static bool yx_expect_uint(yx_reader *r, uint64_t expected);

enum yx_module_op {
    YX_ME_INT,
    YX_ME_FLOAT,
    YX_ME_STRING,
    YX_ME_BOOL,
    YX_ME_FILESIZE,
    YX_ME_LOOKUP,
    YX_ME_INDEX,
    YX_ME_CALL,
    YX_ME_COMPARE,
    YX_ME_NOT,
    YX_ME_AND,
    YX_ME_OR,
    YX_ME_ARITH,
    YX_ME_READ,
    YX_ME_BIND,
    YX_ME_VARIABLE,
    YX_ME_LOOP,
    YX_ME_LENGTH,
    YX_ME_MEMBER,
    YX_ME_GROUP,
    YX_ME_DEFINED,
    /* Expr::Minus of a float (args[0]); a `/regexp/` argument of a module
     * function (type 5; bytes hold the delimited text with its flags). */
    YX_ME_NEGATE,
    YX_ME_REGEX
};
typedef struct yx_module_node {
    uint8_t op, type, argc, comparison;
    bool constant, unsigned_value;
    /* The TypeValue variant of a module field's integer (3..10: Int8..Int64,
     * Uint8..Uint64; yx_archive_field_integer_kind), 0 for any other node. */
    uint8_t integer_kind;
    /* An operand of an `and` / `or` that IR::and / IR::or folded to a
     * constant: it is not in the IR that anchors patterns and limits `#a`. */
    bool folded_away;
    int args[8];
    int64_t integer;
    double real;
    uint8_t *bytes;
    size_t length;
    const yx_archive_module_field *field;
    const yx_archive_module_signature *signature;
} yx_module_node;
typedef struct yx_module_import {
    char module[80], name[160];
    uint8_t args[8], argc, results[2], resultc, type, id;
    uint16_t rank;
} yx_module_import;
typedef struct yx_module_program {
    yx_bool_parser parser;
    const yx_archive_module_schema *schema;
    yx_module_node *nodes;
    size_t count, node_capacity;
    yx_module_import imports[YX_MODULE_IMPORTS];
    size_t import_count;
    size_t *calls, call_count, call_capacity;
    bool memory, filesize, divisor, failed, no_match, two_locals;
    /* An allocation of the composed codec failed (yx_composed_options). */
    bool no_memory;
    yx_literal *literals;
    size_t literal_count, literal_capacity;
    /* The archive's regexp pool (RegexpId order) that regexp arguments are
     * interned in: the codec's own, or NULL when it has none. */
    yx_literal **regexes;
    size_t *regex_count, *regex_capacity;
    /* `shifts`: the codec's function builder numbers a shift's i64_tmp_b
     * (local 1, or the only local when nothing uses i64_tmp_a: yx_module_wasm);
     * `shift`: the expression has one. */
    bool shifts, shift;
    /* The quantity of the `for <expr>` / `for <expr>%` loop whose prefix
     * is being written (kind 3 or 4, else 0), and where it goes. */
    uint8_t loop_kind;
    int loop_quantity;
    size_t loop_split;
    yx_archive_binding *bindings;
    size_t binding_count, binding_capacity;
    uint8_t slot_types[YX_ARCHIVE_MAX_VARS];
    bool slot_unsigned[YX_ARCHIVE_MAX_VARS];
    uint8_t slot_integer_kinds[YX_ARCHIVE_MAX_VARS];
    /* Decoding: 1 + the node bound to each `with` slot (0: none). */
    int slot_values[YX_ARCHIVE_MAX_VARS];
    /* The variable nodes decoded for each slot since its binding (saturating). */
    uint8_t slot_uses[YX_ARCHIVE_MAX_VARS];
    /* Decoding: the slot's `with` statement is in scope (its body is being
     * decoded). */
    bool slot_open[YX_ARCHIVE_MAX_VARS];
    bool slot_defined[YX_ARCHIVE_MAX_VARS];
    const yx_archive_module_field *slot_fields[YX_ARCHIVE_MAX_VARS];
    int undefined_slot;
    uint8_t profile;
    bool capi_import_order;
    uint8_t filesize_global;
    size_t expected_functions;
    /* Optional typed leaves share the parser, guards, and Boolean emitter. */
    void *extension;
    int (*parse_primary)(struct yx_module_program *, unsigned);
    bool (*emit_primary)(struct yx_module_program *, int, yx_writer *, unsigned);
    bool (*print_primary)(const struct yx_module_program *, int, yx_writer *, unsigned);
    int (*decode_primary)(yx_reader *, size_t, struct yx_module_program *, unsigned);
    int (*decode_call)(yx_reader *, size_t, struct yx_module_program *, uint64_t, int *, size_t *);
    void (*boolean_scope)(struct yx_module_program *, bool);
    /* A decoded AND/OR chain the extension may fold into one node (pattern
     * sets); `bare` when the last operand had no result block, `guarded`
     * when a search guard was decoded inside the chain. -1 keeps the chain. */
    int (*decode_set)(struct yx_module_program *, uint8_t, int, int, bool, bool);
    size_t decoded_guards;
    int set_node;   /* 1 + the last node decode_set folded; its block is its own */
    bool i32_local; /* emit_switch's i32 temporary (local 0 of the function) */
    /* Whether an extension's node cannot throw an undefined value. */
    bool (*definite_primary)(const struct yx_module_program *, int, unsigned);
} yx_module_program;

static const yx_archive_module_schema *yx_archive_schema(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof(yx_archive_module_schemas) / sizeof(yx_archive_module_schemas[0]); ++i)
        if (!strcmp(name, yx_archive_module_schemas[i].name)) return &yx_archive_module_schemas[i];
    return NULL;
}
/* The module schemas record every field as "integer". The width and the
 * signedness that emit.rs asks for (TypeValue::is_unsigned, is_non_negative)
 * are in the module's serialized root structure (types/mod.rs TypeValue:
 * 3..6 Int8..Int64, 7..10 Uint8..Uint64), which this walks by field name. */
static bool yx_schema_skip_type(yx_reader *r, unsigned depth);
static bool yx_schema_skip_blob(yx_reader *r)
{
    uint64_t n;
    if (!yx_get_uint(r, &n) || n > r->length - r->at) return false;
    r->at += (size_t)n;
    return true;
}
static bool yx_schema_skip_optional_blob(yx_reader *r)
{
    uint8_t present;
    return yx_get_u8(r, &present) && present <= 1 && (!present || yx_schema_skip_blob(r));
}
/* A Struct: its fields up to the one called `name` (the reader is left at
 * that field's type and *found is set), or the whole structure. */
static bool yx_schema_struct(yx_reader *r, const char *name, size_t name_length, bool *found, unsigned depth)
{
    uint64_t count, length, number;
    uint8_t flag;
    if (depth > 64 || !yx_get_uint(r, &count)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        if (!yx_get_uint(r, &length) || length > r->length - r->at) return false;
        bool match = name && length == name_length && !memcmp(r->data + r->at, name, name_length);
        r->at += (size_t)length;
        if (!yx_get_uint(r, &number)) return false;
        if (match) {
            *found = true;
            return true;
        }
        if (!yx_schema_skip_type(r, depth + 1)) return false;
    }
    return yx_schema_skip_optional_blob(r) && yx_get_u8(r, &flag) && yx_get_u8(r, &flag);
}
static bool yx_schema_skip_type(yx_reader *r, unsigned depth)
{
    uint64_t kind, state, count, value;
    uint8_t byte;
    bool found = false;
    if (depth > 64 || !yx_get_uint(r, &kind)) return false;
    if (kind >= 1 && kind <= 11) {
        if (!yx_get_uint(r, &state) || state > 2) return false;
        if (state != 2) {
            if (kind == 1 || kind == 3 || kind == 7) {
                if (!yx_get_u8(r, &byte)) return false;
            } else if (kind == 2) {
                if (r->length - r->at < 8) return false;
                r->at += 8;
            } else if (kind == 11) {
                if (!yx_schema_skip_blob(r)) return false;
            } else if (!yx_get_uint(r, &value)) return false;
        }
        if (kind == 11) {
            if (!yx_get_u8(r, &byte) || byte > 1) return false;
            if (byte) {
                if (!yx_get_uint(r, &count)) return false;
                for (uint64_t i = 0; i < count; ++i)
                    if (!yx_get_uint(r, &value) || value > 2 || (value == 2 && !yx_get_uint(r, &value))) return false;
            }
        }
        return true;
    }
    if (kind == 0) return true;
    if (kind == 12) return yx_schema_skip_optional_blob(r);
    if (kind == 13) return yx_schema_struct(r, NULL, 0, &found, depth + 1);
    if (kind == 14) {
        if (!yx_get_uint(r, &state) || state > 4 || !yx_get_uint(r, &count)) return false;
        for (uint64_t i = 0; i < count; ++i) {
            if (state == 0) {
                if (!yx_get_uint(r, &value)) return false;
            } else if (state == 1) {
                if (r->length - r->at < 8) return false;
                r->at += 8;
            } else if (state == 2) {
                if (!yx_get_u8(r, &byte)) return false;
            } else if (state == 3) {
                if (!yx_schema_skip_blob(r)) return false;
            } else if (!yx_schema_struct(r, NULL, 0, &found, depth + 1)) return false;
        }
        return true;
    }
    if (kind == 15) {
        if (!yx_get_uint(r, &state) || state > 1 || !yx_get_u8(r, &byte) || byte > 1 || (byte && !yx_schema_skip_type(r, depth + 1)) || !yx_get_uint(r, &count))
            return false;
        for (uint64_t i = 0; i < count; ++i)
            if ((state ? !yx_schema_skip_blob(r) : !yx_get_uint(r, &value)) || !yx_schema_skip_type(r, depth + 1)) return false;
        return true;
    }
    if (kind == 16) {
        if (!yx_get_uint(r, &count)) return false;
        for (uint64_t i = 0; i < count; ++i) {
            if (!yx_schema_skip_blob(r) || !yx_get_uint(r, &value)) return false;
            for (uint64_t j = 0; j < value; ++j)
                if (!yx_schema_skip_blob(r) || !yx_schema_skip_type(r, depth + 1)) return false;
            if (!yx_schema_skip_type(r, depth + 1) || !yx_schema_skip_optional_blob(r)) return false;
        }
        return yx_schema_skip_optional_blob(r);
    }
    return false;
}
/* The TypeValue variant of the field `path` ("pe.sections.raw_data_size":
 * members of array elements and of map values are reached through the
 * array's first structure and the map's deputy), 0 when it is not found. */
static uint8_t yx_archive_field_integer_kind(const char *path)
{
    char module[32];
    const char *dot = path ? strchr(path, '.') : NULL;
    if (!dot || (size_t)(dot - path) >= sizeof(module)) return 0;
    memcpy(module, path, (size_t)(dot - path));
    module[dot - path] = 0;
    const yx_archive_module_schema *schema = yx_archive_schema(module);
    if (!schema || !schema->globals[0]) return 0;
    yx_reader r = {schema->globals[0], schema->globals_length[0], 0, false, false};
    const char *name = path;
    for (unsigned depth = 0; depth < 32; ++depth) {
        const char *end = strchr(name, '.');
        size_t length = end ? (size_t)(end - name) : strlen(name);
        bool found = false;
        uint64_t kind, variant, count;
        uint8_t present;
        if (!yx_schema_struct(&r, name, length, &found, 0) || !found) return 0;
        size_t type_at = r.at;
        if (!yx_get_uint(&r, &kind)) return 0;
        if (!end) return kind <= 16 ? (uint8_t)kind : 0;
        name = end + 1;
        if (kind == 14) {
            if (!yx_get_uint(&r, &variant) || variant != 4 || !yx_get_uint(&r, &count) || !count) return 0;
        } else if (kind == 15) {
            if (!yx_get_uint(&r, &variant) || !yx_get_u8(&r, &present) || present != 1 || !yx_get_uint(&r, &kind) || kind != 13) return 0;
        } else if (kind != 13) return 0;
        (void)type_at;
    }
    return 0;
}
/* An enum value of the vt module (`vt.NetError.NET_ERROR_TIMED_OUT`): the
 * schema's integer constants, as upstream builds them from vt.proto. Enum
 * and message names start with a capital letter, fields do not. */
bool yx_ser_vt_enum_constant(const char *name, uint64_t *value)
{
    if (!name || strncmp(name, "vt.", 3) || name[3] < 'A' || name[3] > 'Z') return false;
    for (size_t i = 0; i < sizeof(yx_archive_fields_vt) / sizeof(yx_archive_fields_vt[0]); ++i) {
        const yx_archive_module_field *field = &yx_archive_fields_vt[i];
        if (field->kind == 3 && field->state == 0 && !strcmp(name, field->path)) {
            if (value) *value = (uint64_t)field->integer;
            return true;
        }
    }
    return false;
}
/* Whether the first `length` bytes of `path` name an enum or a message of
 * the vt module that enum values hang from (`vt.Domain.Permutation`). */
bool yx_ser_vt_enum_scope(const char *path, size_t length)
{
    if (!path || length < 4 || strncmp(path, "vt.", 3) || path[3] < 'A' || path[3] > 'Z') return false;
    for (size_t i = 0; i < sizeof(yx_archive_fields_vt) / sizeof(yx_archive_fields_vt[0]); ++i) {
        const yx_archive_module_field *field = &yx_archive_fields_vt[i];
        if (field->kind == 6 && strlen(field->path) == length && !memcmp(path, field->path, length)) return true;
    }
    return false;
}
/* The key and value types of a map field (serialization_modules_maps.h). */
static const yx_archive_module_map *yx_module_map_types(const yx_archive_module_field *field)
{
    if (!field || field->kind != 8) return NULL;
    for (size_t i = 0; i < sizeof(yx_archive_module_maps) / sizeof(yx_archive_module_maps[0]); ++i)
        if (!strcmp(field->path, yx_archive_module_maps[i].path)) return &yx_archive_module_maps[i];
    return NULL;
}
static const char *yx_module_map_lookup_name(const yx_archive_module_map *map);
/* emit_map_lookup_by_index: the (key, value) pair of a map entry. Only maps
 * whose keys and values are i64 values (integers and strings) are modelled:
 * set_vars stores both through i64_tmp_a. */
static const char *yx_module_map_by_index_name(const yx_archive_module_map *map)
{
    if (!map || (map->key != 3 && map->key != 4) || (map->value != 3 && map->value != 4)) return NULL;
    if (map->key == 4) return map->value == 4 ? "map_lookup_by_index_string_string@map:i,index:i@ii" : "map_lookup_by_index_string_integer@map:i,index:i@ii";
    return map->value == 4 ? "map_lookup_by_index_integer_string@map:i,index:i@ii" : "map_lookup_by_index_integer_integer@map:i,index:i@ii";
}
static void yx_module_program_free(yx_module_program *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->count; ++i) free(p->nodes[i].bytes);
    free(p->nodes);
    free(p->calls);
    free(p->literals);
    free(p->bindings);
    free(p);
}
/* Reserve at parser/decoder entry, before recursive code borrows node pointers.
 * A source byte or Wasm byte contributes at most two typed nodes; the extra
 * slots also cover synthetic binding/group nodes. Joining rule roots reserves
 * its own additional nodes before emission. */
static bool yx_module_nodes_reserve(yx_module_program *p, size_t additional)
{
    if (!p || p->count > INT_MAX || additional > (size_t)INT_MAX - p->count) return false;
    size_t needed = p->count + additional;
    if (needed <= p->node_capacity) return true;
    size_t capacity = p->node_capacity ? p->node_capacity : 64;
    while (capacity < needed) {
        if (capacity > (size_t)INT_MAX / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*p->nodes)) return false;
    yx_module_node *grown = realloc(p->nodes, capacity * sizeof(*grown));
    if (!grown) {
        yx_walk_no_memory = true;
        return false;
    }
    p->nodes = grown;
    p->node_capacity = capacity;
    return true;
}
static bool yx_module_nodes_for_input(yx_module_program *p, size_t length)
{
    if (length > ((size_t)INT_MAX - 16) / 2 || !yx_module_nodes_reserve(p, length * 2 + 16)) {
        p->failed = true;
        return false;
    }
    return true;
}
static int yx_module_node_new(yx_module_program *p, uint8_t op, uint8_t type)
{
    if (p->count == p->node_capacity) {
        p->failed = true;
        return -1;
    }
    int n = (int)p->count++;
    memset(&p->nodes[n], 0, sizeof(p->nodes[n]));
    p->nodes[n].op = op;
    p->nodes[n].type = type;
    p->nodes[n].constant = op == YX_ME_INT || op == YX_ME_FLOAT || op == YX_ME_BOOL || op == YX_ME_STRING;
    return n;
}
/* Types a node that reads the scalar integer field `p->nodes[n].field`. */
static void yx_module_field_typing(yx_module_program *p, int n)
{
    yx_module_node *node;
    if (n < 0) return;
    node = &p->nodes[n];
    if (node->type != 3 || !node->field || node->field->kind != 3) return;
    node->integer_kind = yx_archive_field_integer_kind(node->field->path);
    if (node->integer_kind < 3 || node->integer_kind > 10) node->integer_kind = 0;
    node->unsigned_value = node->integer_kind == 10;
}
static int yx_module_arithmetic_node(yx_module_program *p, uint8_t operation, int left, int right)
{
    const yx_module_node *a = &p->nodes[left], *b = &p->nodes[right];
    if (a->type < 2 || a->type > 3 || b->type < 2 || b->type > 3) return -1;
    bool real = a->type == 2 || b->type == 2;
    if (real && operation != 0x7c && operation != 0x7d && operation != 0x7e && operation != 0x7f) return -1;
    int index = yx_module_node_new(p, YX_ME_ARITH, real ? 2 : 3);
    if (index < 0) return -1;
    yx_module_node *n = &p->nodes[index];
    n->args[0] = left;
    n->args[1] = right;
    n->comparison = operation;
    n->unsigned_value = !real && (a->unsigned_value || b->unsigned_value);
    if (operation == 0x86 || operation == 0x87) {
        /* IR::shl and IR::shr (ir/mod.rs): the result has the signedness of
         * the left operand; constants fold unless the amount is negative. */
        n->unsigned_value = a->unsigned_value;
        if (!a->constant || !b->constant || (!b->unsigned_value && b->integer < 0)) return index;
        n->constant = true;
        /* The amount is not negative here: as an i128 it is 64 or more
         * exactly when its bits are, whatever its signedness. */
        if ((uint64_t)b->integer >= 64) n->integer = 0;
        else if (operation == 0x86) n->integer = yx_integer_signed_bits((uint64_t)a->integer << b->integer);
        else if (a->unsigned_value) n->integer = yx_integer_signed_bits((uint64_t)a->integer >> b->integer);
        else n->integer = a->integer < 0 ? ~(~a->integer >> b->integer) : a->integer >> b->integer;
        return index;
    }
    if (!a->constant || !b->constant) return index;
    n->constant = true;
    if (real) {
        double x = a->type == 2 ? a->real : a->unsigned_value ? (double)(uint64_t)a->integer : (double)a->integer;
        double y = b->type == 2 ? b->real : b->unsigned_value ? (double)(uint64_t)b->integer : (double)b->integer;
        n->real = operation == 0x7c ? x + y : operation == 0x7d ? x - y : operation == 0x7e ? x * y : x / y;
        return yx_float_representable(n->real) ? index : -1;
    }
    int64_t x = a->integer, y = b->integer;
    if (n->unsigned_value) {
        uint64_t u = (uint64_t)x, v = (uint64_t)y, bits;
        if (operation == 0x7c) bits = u + v;
        else if (operation == 0x7d) bits = u - v;
        else if (operation == 0x7e) bits = u * v;
        else if (operation == 0x7f || operation == 0x81) {
            if (!v) {
                n->constant = false;
                return index;
            }
            bits = operation == 0x7f ? u / v : u % v;
        } else if (operation == 0x83) bits = u & v;
        else if (operation == 0x84) bits = u | v;
        else if (operation == 0x85) bits = u ^ v;
        else return -1;
        n->integer = yx_integer_signed_bits(bits);
        return index;
    }
    if (operation == 0x7c) {
        if ((y > 0 && x > INT64_MAX - y) || (y < 0 && x < INT64_MIN - y)) return -1;
        n->integer = x + y;
    } else if (operation == 0x7d) {
        if ((y < 0 && x > INT64_MAX + y) || (y > 0 && x < INT64_MIN + y)) return -1;
        n->integer = x - y;
    } else if (operation == 0x7e) {
        if ((x > 0 && y > 0 && x > INT64_MAX / y) || (x > 0 && y < 0 && y < INT64_MIN / x) || (x < 0 && y > 0 && x < INT64_MIN / y) ||
            (x < 0 && y < 0 && x < INT64_MAX / y))
            return -1;
        n->integer = x * y;
    } else if (operation == 0x7f || operation == 0x81) {
        if (!y || (x == INT64_MIN && y == -1)) {
            n->constant = false;
            return index;
        }
        n->integer = operation == 0x7f ? x / y : x % y;
    } else if (operation == 0x83) n->integer = x & y;
    else if (operation == 0x84) n->integer = x | y;
    else if (operation == 0x85) n->integer = x ^ y;
    else return -1;
    return index;
}
static uint8_t yx_module_wasm_type(uint8_t type)
{
    return type == 1 || type == 5 ? 0x7f : type == 2 ? 0x7c : 0x7e;
}
/* TypeValue::cast_to_bool of a constant operand (IR::and/or folding): 1 or 0,
 * -1 when the operand is not a constant. */
static int yx_module_constant_truth(const yx_module_node *n)
{
    if (!n->constant) return -1;
    if (n->type == 1 || n->type == 3) return n->integer != 0;
    if (n->type == 2) return n->real != 0;
    if (n->type == 4) return n->length != 0;
    return -1;
}
/* The same for an operand of IR::and / IR::or: a `with` has the type value
 * of its body (Expr::With), so a constant body makes it a constant operand
 * whose declarations never run. */
static int yx_module_operand_truth(const yx_module_program *p, int index)
{
    for (size_t steps = 0; index >= 0 && (size_t)index < p->count && p->nodes[index].op == YX_ME_BIND && steps < p->count; ++steps) index = p->nodes[index].args[1];
    return index < 0 || (size_t)index >= p->count ? -1 : yx_module_constant_truth(&p->nodes[index]);
}
static bool yx_module_take(yx_module_program *p, unsigned char c)
{
    yx_bool_skip_space(&p->parser);
    if (*p->parser.at != c) return false;
    ++p->parser.at;
    return true;
}
static int yx_module_parse(yx_module_program *, unsigned, unsigned);
static const char *const yx_module_comparison_names[] = {
    "str_eq@lhs:s,rhs:s@b",       "str_ne@lhs:s,rhs:s@b",        "str_lt@lhs:s,rhs:s@b",        "str_gt@lhs:s,rhs:s@b",         "str_le@lhs:s,rhs:s@b",
    "str_ge@lhs:s,rhs:s@b",       "str_contains@lhs:s,rhs:s@b",  "str_icontains@lhs:s,rhs:s@b", "str_startswith@lhs:s,rhs:s@b", "str_istartswith@lhs:s,rhs:s@b",
    "str_endswith@lhs:s,rhs:s@b", "str_iendswith@lhs:s,rhs:s@b", "str_iequals@lhs:s,rhs:s@b"};
static const char *const yx_module_comparison_text[] = {" == ",        " != ",         " < ",           " > ",        " <= ",        " >= ",     " contains ",
                                                        " icontains ", " startswith ", " istartswith ", " endswith ", " iendswith ", " iequals "};
static int yx_module_parse_with(yx_module_program *p, unsigned depth)
{
    size_t first = p->binding_count, count = 0;
    int *values = malloc(YX_ARCHIVE_MAX_VARS * sizeof(*values));
    int body = -1;
    if (!values) {
        yx_walk_no_memory = true;
        return -1;
    }
    do {
        const unsigned char *name;
        size_t length;
        if (!yx_archive_bindings_reserve(&p->bindings, &p->binding_capacity, p->binding_count + 1)) goto done;
        /* A `?` item (yx_condition_alias_free_text): a slot of the
         * statement's frame that holds no variable. Such items follow the
         * declared variables. */
        if (yx_module_take(p, '?')) {
            memset(&p->bindings[p->binding_count], 0, sizeof(p->bindings[0]));
            ++p->binding_count;
            continue;
        }
        if (!yx_with_identifier(&p->parser, &name, &length) || !yx_module_take(p, '=')) goto done;
        int value = yx_module_parse(p, 1, depth + 1);
        /* Scalars, structures, arrays and maps (indexed, measured by
         * `.len()` or iterated by `for .. in <name>`). */
        if (value < 0 || p->nodes[value].type < 1 || (p->nodes[value].type > 4 && (p->nodes[value].type < 6 || p->nodes[value].type > 8))) goto done;
        values[count++] = value;
        p->bindings[p->binding_count].name = name;
        p->bindings[p->binding_count].length = length;
        int variable = value;
        if (!p->nodes[value].constant) {
            variable = yx_module_node_new(p, YX_ME_VARIABLE, p->nodes[value].type);
            if (variable < 0) goto done;
            p->nodes[variable].integer = (int64_t)p->binding_count;
            p->nodes[variable].field = p->nodes[value].field;
            p->nodes[variable].unsigned_value = p->nodes[value].unsigned_value;
            p->nodes[variable].integer_kind = p->nodes[value].integer_kind;
        }
        p->bindings[p->binding_count++].value = variable;
    } while (yx_module_take(p, ','));
    if (!yx_module_take(p, ':') || !yx_module_take(p, '(')) goto done;
    body = yx_module_parse(p, 1, depth + 1);
    if (body < 0 || !yx_module_take(p, ')')) {
        body = -1;
        goto done;
    }
    p->binding_count = first;
    for (size_t i = count; i > 0; --i) {
        int bind = yx_module_node_new(p, YX_ME_BIND, p->nodes[body].type);
        if (bind < 0) {
            body = -1;
            goto done;
        }
        p->nodes[bind].args[0] = values[i - 1];
        p->nodes[bind].args[1] = body;
        p->nodes[bind].integer = (int64_t)(first + i - 1);
        body = bind;
    }
done:
    p->binding_count = first;
    free(values);
    return body;
}
static int yx_module_primary(yx_module_program *, unsigned);
static int yx_module_parse_operators(yx_module_program *, size_t, int, unsigned, unsigned);
/* quantifier_from_ast for `for <quantifier> x in <array or map>`: 0xc4 any,
 * 0xc5 all, 0xc6 none, 0xc7 an integer expression (Quantifier::Expr) and
 * 0xc8 a term followed by `%` (Quantifier::Percentage), whose node is
 * *quantity. 0 when there is no quantifier. */
static uint8_t yx_module_for_quantifier(yx_module_program *p, unsigned depth, int *quantity)
{
    uint8_t kind = 0xc8;
    int term;
    size_t first = p->count;
    *quantity = -1;
    if (yx_bool_keyword(&p->parser, "any")) return 0xc4;
    if (yx_bool_keyword(&p->parser, "all")) return 0xc5;
    if (yx_bool_keyword(&p->parser, "none")) return 0xc6;
    term = yx_module_primary(p, depth + 1);
    if (term < 0) return 0;
    /* A term and `%`, or the expression that the term starts. */
    if (!yx_module_take(p, '%')) {
        kind = 0xc7;
        term = yx_module_parse_operators(p, first, term, 4, depth + 1);
    }
    if (term < 0 || p->nodes[term].type != 3) return 0;
    *quantity = term;
    return kind;
}
/* `/regexp/flags` as the argument of a module function (YX_ME_REGEX): the
 * delimited text with its flags is what upstream's regexp pool interns
 * (emit.rs: TypeValue::Regexp). */
static int yx_module_regex(yx_module_program *p)
{
    const unsigned char *start = p->parser.at, *at = start + 1;
    bool escaped = false, in_class = false, closed = false;
    size_t size;
    int n;
    while (*at && !closed) {
        unsigned char ch = *at++;
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch == '\\') escaped = true;
        else if (ch == '[') in_class = true;
        else if (ch == ']') in_class = false;
        else if (ch == '/' && !in_class) closed = true;
    }
    if (!closed || at == start + 2) return -1;
    while (*at == 'i' || *at == 's') ++at;
    if (isalnum(*at) || *at == '_') return -1;
    size = (size_t)(at - start);
    n = yx_module_node_new(p, YX_ME_REGEX, 5);
    if (n < 0) return -1;
    if (!(p->nodes[n].bytes = malloc(size))) {
        p->failed = true;
        yx_walk_no_memory = true;
        return -1;
    }
    memcpy(p->nodes[n].bytes, start, size);
    p->nodes[n].length = size;
    p->parser.at = at;
    return n;
}
/* The readers a module expression calls: the integer readers, then
 * float32, float64, float32be and float64be (YX_ME_READ of a float). */
enum {
    YX_MODULE_READ_COUNT = YX_INTEGER_READ_COUNT + 4
};
static const char *yx_module_read_name(uint8_t type)
{
    static const char *const floats[YX_MODULE_READ_COUNT - YX_INTEGER_READ_COUNT] = {"float32", "float64", "float32be", "float64be"};
    return type < YX_INTEGER_READ_COUNT ? yx_integer_codec_read_name(type) : type < YX_MODULE_READ_COUNT ? floats[type - YX_INTEGER_READ_COUNT] : NULL;
}
static int yx_module_primary(yx_module_program *p, unsigned depth);
typedef struct {
    yx_module_program *p;
    unsigned depth;
    int result;
} yx_module_primary_job;
static void yx_module_primary_thunk(void *data)
{
    yx_module_primary_job *j = data;
    j->result = yx_module_primary(j->p, j->depth);
}
static int yx_module_primary(yx_module_program *p, unsigned depth)
{
    const unsigned char *start;
    int n;
    if (depth > YX_MODULE_DEPTH) return -1;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_primary_job job = {p, depth, -1};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_primary_thunk, &job) ? job.result : -1;
    }
    yx_bool_skip_space(&p->parser);
    if (p->parse_primary) {
        const unsigned char *saved = p->parser.at;
        int extension = p->parse_primary(p, depth);
        if (extension >= 0 || p->parser.at != saved) return extension;
    }
    if (yx_bool_keyword(&p->parser, "for")) {
        int quantity = -1;
        uint8_t quantifier = yx_module_for_quantifier(p, depth, &quantity);
        const unsigned char *name, *value_name = NULL;
        size_t length, value_length = 0, first = p->binding_count;
        if (!quantifier || !yx_archive_bindings_reserve(&p->bindings, &p->binding_capacity, first + 7) || !yx_with_identifier(&p->parser, &name, &length)) return -1;
        /* `for <q> k, v in <map>` (emit_for_in_map): the key and the value. */
        if (yx_module_take(p, ',') && !yx_with_identifier(&p->parser, &value_name, &value_length)) return -1;
        if (!yx_bool_keyword(&p->parser, "in")) return -1;
        int array = yx_module_parse(p, 1, depth + 1);
        static const uint8_t types[] = {3, 2, 1, 4, 6};
        const yx_archive_module_map *map = NULL;
        if (array < 0) return -1;
        if (value_name) {
            if (p->nodes[array].op == YX_ME_LOOKUP || p->nodes[array].op == YX_ME_VARIABLE || p->nodes[array].op == YX_ME_MEMBER)
                map = yx_module_map_types(p->nodes[array].field);
            if (!yx_module_map_by_index_name(map)) return -1;
        } else if ((p->nodes[array].op != YX_ME_LOOKUP && p->nodes[array].op != YX_ME_MEMBER) || !p->nodes[array].field || p->nodes[array].type != 7 ||
                   p->nodes[array].field->element > 4)
            return -1;
        if (!yx_module_take(p, ':') || !yx_module_take(p, '(')) return -1;
        int variable = yx_module_node_new(p, YX_ME_VARIABLE, map ? map->key : types[p->nodes[array].field->element]);
        if (variable < 0) return -1;
        p->nodes[variable].integer = (int64_t)first + 5;
        p->nodes[variable].field = p->nodes[array].field;
        memset(p->bindings + first, 0, 7 * sizeof(p->bindings[0]));
        p->bindings[first + 5].name = name;
        p->bindings[first + 5].length = length;
        p->bindings[first + 5].value = variable;
        if (map) {
            int value = yx_module_node_new(p, YX_ME_VARIABLE, map->value);
            if (value < 0) return -1;
            p->nodes[value].integer = (int64_t)first + 6;
            p->nodes[value].field = p->nodes[array].field;
            p->bindings[first + 6].name = value_name;
            p->bindings[first + 6].length = value_length;
            p->bindings[first + 6].value = value;
        }
        p->binding_count += 7;
        int body = yx_module_parse(p, 1, depth + 1);
        p->binding_count = first;
        if (body < 0 || !yx_module_take(p, ')')) return -1;
        int loop = yx_module_node_new(p, YX_ME_LOOP, 1);
        if (loop >= 0) {
            p->nodes[loop].integer = (int64_t)first;
            p->nodes[loop].comparison = quantifier;
            p->nodes[loop].args[0] = array;
            p->nodes[loop].args[1] = body;
            p->nodes[loop].args[2] = quantity;
        }
        return loop;
    }
    if (yx_bool_keyword(&p->parser, "with")) return yx_module_parse_with(p, depth);
    if (yx_bool_keyword(&p->parser, "defined")) {
        n = yx_module_node_new(p, YX_ME_DEFINED, 1);
        if (n < 0 || (p->nodes[n].args[0] = yx_module_parse(p, 3, depth + 1)) < 0) return -1;
        return n;
    }
    if (yx_bool_keyword(&p->parser, "not")) {
        n = yx_module_node_new(p, YX_ME_NOT, 1);
        if (n < 0 || (p->nodes[n].args[0] = yx_module_parse(p, 3, depth + 1)) < 0) return -1;
        return n;
    }
    if (yx_bool_keyword(&p->parser, "true")) {
        n = yx_module_node_new(p, YX_ME_BOOL, 1);
        if (n >= 0) p->nodes[n].integer = 1;
        return n;
    }
    if (yx_bool_keyword(&p->parser, "false")) return yx_module_node_new(p, YX_ME_BOOL, 1);
    if (yx_bool_keyword(&p->parser, "filesize")) return yx_module_node_new(p, YX_ME_FILESIZE, 3);
    if (yx_module_take(p, '(')) {
        n = yx_module_parse(p, 1, depth + 1);
        return n >= 0 && yx_module_take(p, ')') ? n : -1;
    }
    if (*p->parser.at == '"') {
        yx_writer bytes = {0};
        ++p->parser.at;
        while (*p->parser.at && *p->parser.at != '"') {
            unsigned char c = *p->parser.at++;
            if (c == '\\') {
                c = *p->parser.at++;
                if (!c) {
                    free(bytes.data);
                    return -1;
                }
                if (c == 'n') c = '\n';
                else if (c == 'r') c = '\r';
                else if (c == 't') c = '\t';
                else if (c == '0') c = 0;
                else if (c == 'x') {
                    unsigned v = 0;
                    for (unsigned i = 0; i < 2; ++i) {
                        c = *p->parser.at++;
                        if (c >= '0' && c <= '9') v = v * 16 + c - '0';
                        else if (c >= 'a' && c <= 'f') v = v * 16 + c - 'a' + 10;
                        else if (c >= 'A' && c <= 'F') v = v * 16 + c - 'A' + 10;
                        else {
                            free(bytes.data);
                            return -1;
                        }
                    }
                    c = (unsigned char)v;
                } else if (c != '\\' && c != '"') {
                    free(bytes.data);
                    return -1;
                }
            }
            if (!yx_put_u8(&bytes, c)) {
                free(bytes.data);
                return -1;
            }
        }
        if (*p->parser.at != '"') {
            free(bytes.data);
            return -1;
        }
        ++p->parser.at;
        n = yx_module_node_new(p, YX_ME_STRING, 4);
        if (n < 0) {
            free(bytes.data);
            return -1;
        }
        p->nodes[n].bytes = bytes.data;
        p->nodes[n].length = bytes.used;
        return n;
    }
    if (*p->parser.at == '/') return yx_module_regex(p);
    start = p->parser.at;
    if (*start == '~' || (*start == '-' && !(start[1] >= '0' && start[1] <= '9'))) {
        /* IR::minus and IR::bitwise_not (ir/mod.rs) fold a constant operand. Otherwise Expr::Minus of an
         * integer is `i64.const 0; operand; i64.sub` and Expr::BitwiseNot is `operand; i64.const -1; i64.xor`
         * (emit.rs:504, :516): the bytes of `0 - x` and `x ^ -1`. A float Expr::Minus is the operand
         * and `f64.neg` (YX_ME_NEGATE). */
        bool invert = *start == '~';
        ++p->parser.at;
        int operand = yx_module_primary(p, depth + 1);
        if (operand < 0) return -1;
        const yx_module_node *value = &p->nodes[operand];
        if (value->constant && value->type == 2 && !invert) {
            double real = -value->real;
            n = yx_module_node_new(p, YX_ME_FLOAT, 2);
            if (n >= 0) p->nodes[n].real = real;
            return n;
        }
        if (value->type == 2 && !invert) {
            n = yx_module_node_new(p, YX_ME_NEGATE, 2);
            if (n >= 0) p->nodes[n].args[0] = operand;
            return n;
        }
        if (value->type != 3) return -1;
        if (value->constant) {
            bool is_unsigned = value->unsigned_value;
            if (!invert && (is_unsigned || value->integer == INT64_MIN)) return -1;
            int64_t folded = invert ? ~value->integer : -value->integer;
            n = yx_module_node_new(p, YX_ME_INT, 3);
            if (n >= 0) {
                p->nodes[n].integer = folded;
                p->nodes[n].unsigned_value = invert && is_unsigned;
            }
            return n;
        }
        int constant = yx_module_node_new(p, YX_ME_INT, 3);
        if (constant < 0) return -1;
        p->nodes[constant].integer = invert ? -1 : 0;
        n = invert ? yx_module_arithmetic_node(p, 0x85, operand, constant) : yx_module_arithmetic_node(p, 0x7d, constant, operand);
        if (n >= 0 && !invert) p->nodes[n].unsigned_value = false;
        return n;
    }
    if ((*start >= '0' && *start <= '9') || *start == '-') {
        char *end = NULL;
        double real = strtod((const char *)start, &end);
        bool floating = false;
        for (const unsigned char *s = start; s < (const unsigned char *)end; ++s)
            if (*s == '.' || *s == 'e' || *s == 'E') floating = true;
        if (end > (const char *)start && end[-1] == '.' && *end == '.') floating = false;
        const unsigned char *magnitude = *start == '-' ? start + 1 : start;
        if (magnitude[0] == '0' && (magnitude[1] == 'x' || magnitude[1] == 'X')) floating = false;
        if (floating && end != (const char *)start && isfinite(real)) {
            n = yx_module_node_new(p, YX_ME_FLOAT, 2);
            if (n >= 0) {
                p->nodes[n].real = real;
                p->parser.at = (const unsigned char *)end;
            }
            return n;
        }
        int64_t integer;
        bool is_unsigned;
        if (!yx_integer_archive_literal(&p->parser, &integer, &is_unsigned)) return -1;
        n = yx_module_node_new(p, YX_ME_INT, 3);
        if (n >= 0) {
            p->nodes[n].integer = integer;
            p->nodes[n].unsigned_value = is_unsigned;
        }
        return n;
    }
    while ((*p->parser.at >= 'a' && *p->parser.at <= 'z') || (*p->parser.at >= 'A' && *p->parser.at <= 'Z') || (*p->parser.at >= '0' && *p->parser.at <= '9') ||
           *p->parser.at == '_' || (*p->parser.at == '.' && p->parser.at[1] != '.'))
        ++p->parser.at;
    size_t length = (size_t)(p->parser.at - start);
    if (!length || length >= 160) return -1;
    char path[160];
    memcpy(path, start, length);
    path[length] = 0;
    int bound = -1;
    for (size_t i = p->binding_count; i > 0; --i)
        if (p->bindings[i - 1].length == length && !memcmp(p->bindings[i - 1].name, path, length)) {
            /* A `with` variable declared as an array or a map is indexed
             * like the field it holds. */
            const yx_module_node *value = &p->nodes[p->bindings[i - 1].value];
            const unsigned char *next = p->parser.at;
            while (*next == ' ' || *next == '\t' || *next == '\r' || *next == '\n') ++next;
            if (*next != '[' || value->op != YX_ME_VARIABLE || (value->type != 7 && value->type != 8) || !value->field || value->field->kind != value->type)
                return p->bindings[i - 1].value;
            bound = p->bindings[i - 1].value;
            break;
        }
    /* `<variable>.len()` of such a variable (Array::len, Map::len). */
    const unsigned char *call_end = p->parser.at;
    while (*call_end == ' ' || *call_end == '\t' || *call_end == '\r' || *call_end == '\n') ++call_end;
    if (*call_end == '(') {
        ++call_end;
        while (*call_end == ' ' || *call_end == '\t' || *call_end == '\r' || *call_end == '\n') ++call_end;
        call_end = *call_end == ')' ? call_end + 1 : NULL;
    } else call_end = NULL;
    if (bound < 0 && length > 4 && !memcmp(path + length - 4, ".len", 4) && call_end)
        for (size_t i = p->binding_count; i > 0; --i)
            if (p->bindings[i - 1].length == length - 4 && !memcmp(p->bindings[i - 1].name, path, length - 4)) {
                const yx_module_node *value = &p->nodes[p->bindings[i - 1].value];
                /* A variable bound to a string literal is that literal
                 * (RuntimeString::Literal): len() takes it directly. */
                if ((value->op != YX_ME_VARIABLE && value->op != YX_ME_STRING) || (value->type != 4 && value->type != 7 && value->type != 8)) break;
                p->parser.at = call_end;
                n = yx_module_node_new(p, YX_ME_LENGTH, 3);
                if (n >= 0) p->nodes[n].args[0] = p->bindings[i - 1].value;
                return n;
            }
    int base = -1;
    for (size_t i = p->binding_count; i > 0; --i) {
        size_t prefix = p->bindings[i - 1].length;
        const yx_module_node *binding = &p->nodes[p->bindings[i - 1].value];
        if (prefix < length && path[prefix] == '.' && !memcmp(p->bindings[i - 1].name, path, prefix) && binding->type == 6 && binding->field) {
            char expanded[160];
            int needed = snprintf(expanded, sizeof(expanded), "%s%s", binding->field->path, path + prefix);
            if (needed < 0 || (size_t)needed >= sizeof(expanded)) return -1;
            strcpy(path, expanded);
            base = p->bindings[i - 1].value;
            break;
        }
    }
    if (yx_module_take(p, '(')) {
        /* Only when the loop above did not expand the path: a variable named
         * like the first component of its own value (`with pe =
         * pe.rich_signature`) would be expanded twice. */
        for (size_t i = base < 0 ? p->binding_count : 0; i > 0; --i) {
            size_t prefix = p->bindings[i - 1].length;
            const yx_module_node *binding = &p->nodes[p->bindings[i - 1].value];
            if (prefix < length && path[prefix] == '.' && !memcmp(p->bindings[i - 1].name, path, prefix) && binding->type == 6 && binding->field) {
                char expanded[160];
                int needed = snprintf(expanded, sizeof(expanded), "%s%s", binding->field->path, path + prefix);
                if (needed < 0 || (size_t)needed >= sizeof(expanded)) return -1;
                strcpy(path, expanded);
                break;
            }
        }
        int args[8];
        size_t count = 0;
        if (!yx_module_take(p, ')')) {
            do {
                if (count == 8 || (args[count] = yx_module_parse(p, 1, depth + 1)) < 0) return -1;
                ++count;
            } while (yx_module_take(p, ','));
            if (!yx_module_take(p, ')')) return -1;
        }
        for (uint8_t type = 0; type < YX_INTEGER_READ_COUNT; ++type)
            if (!strcmp(path, yx_integer_codec_read_name(type)) && count == 1 && p->nodes[args[0]].type == 3) {
                n = yx_module_node_new(p, YX_ME_READ, 3);
                if (n >= 0) {
                    p->nodes[n].args[0] = args[0];
                    p->nodes[n].integer = type;
                    p->nodes[n].unsigned_value = type == 6 || type == 11;
                }
                return n;
            }
        for (uint8_t type = YX_INTEGER_READ_COUNT; type < YX_MODULE_READ_COUNT; ++type)
            if (!strcmp(path, yx_module_read_name(type)) && count == 1 && p->nodes[args[0]].type == 3) {
                n = yx_module_node_new(p, YX_ME_READ, 2);
                if (n >= 0) {
                    p->nodes[n].args[0] = args[0];
                    p->nodes[n].integer = type;
                }
                return n;
            }
        if (!p->schema) return -1;
        size_t path_length = strlen(path);
        if (!count && path_length > 4 && !strcmp(path + path_length - 4, ".len")) {
            path[path_length - 4] = 0;
            for (size_t i = 0; i < p->schema->field_count; ++i) {
                const yx_archive_module_field *field = &p->schema->fields[i];
                if ((field->kind != 4 && field->kind != 7 && field->kind != 8) || strcmp(path, field->path)) continue;
                int array = yx_module_node_new(p, base < 0 ? YX_ME_LOOKUP : YX_ME_MEMBER, field->kind);
                if (array < 0) return -1;
                p->nodes[array].field = field;
                p->nodes[array].args[0] = base;
                n = yx_module_node_new(p, YX_ME_LENGTH, 3);
                if (n >= 0) p->nodes[n].args[0] = array;
                return n;
            }
            return -1;
        }
        for (unsigned promote = 0; promote < 2; ++promote)
            for (size_t i = 0; i < p->schema->signature_count; ++i) {
                const yx_archive_module_signature *sig = &p->schema->signatures[i];
                if (strcmp(path, sig->path) || count != sig->argc) continue;
                bool match = true;
                for (size_t j = 0; j < count; ++j)
                    if (sig->args[j] != p->nodes[args[j]].type && !(promote && sig->args[j] == 2 && p->nodes[args[j]].type == 3)) match = false;
                if (!match) continue;
                n = yx_module_node_new(p, YX_ME_CALL, sig->result);
                if (n >= 0) {
                    p->nodes[n].signature = sig;
                    p->nodes[n].argc = (uint8_t)count;
                    memcpy(p->nodes[n].args, args, count * sizeof(*args));
                }
                return n;
            }
        return -1;
    }
    if (!p->schema) return -1;
    const yx_archive_module_field *field = NULL;
    if (bound >= 0) field = p->nodes[bound].field;
    else
        for (size_t i = 0; i < p->schema->field_count; ++i)
            if (!strcmp(path, p->schema->fields[i].path)) {
                field = &p->schema->fields[i];
                break;
            }
    if (!field) return -1;
    if (bound >= 0) n = bound;
    else if (field->state == 0 && field->kind >= 1 && field->kind <= 3) {
        n = yx_module_node_new(p, field->kind == 1 ? YX_ME_BOOL : field->kind == 2 ? YX_ME_FLOAT : YX_ME_INT, field->kind);
        if (n >= 0) {
            p->nodes[n].integer = field->integer;
            p->nodes[n].real = field->real;
        }
    } else {
        n = yx_module_node_new(p, base < 0 ? YX_ME_LOOKUP : YX_ME_MEMBER, field->kind);
        if (n >= 0) {
            p->nodes[n].field = field;
            p->nodes[n].args[0] = base;
            yx_module_field_typing(p, n);
        }
    }
    if (n < 0) return -1;
    if (yx_module_take(p, '[')) {
        static const uint8_t element_types[] = {3, 2, 1, 4, 6};
        if (field->kind == 8) {
            /* Expr::Lookup on a map (emit_map_lookup): the map object, the
             * key, then map_lookup_<key>_<value> with an undefined result. */
            const yx_archive_module_map *map = yx_module_map_types(field);
            if (!yx_module_map_lookup_name(map)) return -1;
            int key = yx_module_parse(p, 1, depth + 1);
            if (key < 0 || p->nodes[key].type != map->key || !yx_module_take(p, ']')) return -1;
            int index = yx_module_node_new(p, YX_ME_INDEX, map->value);
            if (index < 0) return -1;
            p->nodes[index].args[0] = n;
            p->nodes[index].args[1] = key;
            p->nodes[index].field = field;
            return index;
        }
        /* A member array of an element is indexed in turn, or its length
         * taken (`pe.import_details[0].functions[1].name`, `...functions.len()`). */
        for (;;) {
            if (field->kind != 7 || field->element > 4) return -1;
            int offset = yx_module_parse(p, 1, depth + 1);
            if (offset < 0 || p->nodes[offset].type != 3 || !yx_module_take(p, ']')) return -1;
            int index = yx_module_node_new(p, YX_ME_INDEX, element_types[field->element]);
            if (index < 0) return -1;
            p->nodes[index].args[0] = n;
            p->nodes[index].args[1] = offset;
            p->nodes[index].field = field;
            if (field->element != 4 || !yx_module_take(p, '.')) return index;
            const unsigned char *member = p->parser.at;
            /* A range's `..` ends the member (`pe.sections[0].virtual_size..10`). */
            while (isalnum(*p->parser.at) || *p->parser.at == '_' || (*p->parser.at == '.' && p->parser.at[1] != '.')) ++p->parser.at;
            size_t member_length = (size_t)(p->parser.at - member);
            bool length_call = member_length > 4 && !memcmp(p->parser.at - 4, ".len", 4) && p->parser.at[0] == '(' && p->parser.at[1] == ')';
            if (length_call) {
                member_length -= 4;
                p->parser.at += 2;
            }
            char expanded[160];
            int needed = snprintf(expanded, sizeof(expanded), "%s.%.*s", field->path, (int)member_length, member);
            if (!member_length || needed < 0 || (size_t)needed >= sizeof(expanded)) return -1;
            const yx_archive_module_field *member_field = NULL;
            for (size_t i = 0; i < p->schema->field_count && !member_field; ++i)
                if (!strcmp(expanded, p->schema->fields[i].path)) member_field = &p->schema->fields[i];
            if (!member_field || (length_call && member_field->kind != 4 && member_field->kind != 7 && member_field->kind != 8)) return -1;
            n = yx_module_node_new(p, YX_ME_MEMBER, member_field->kind);
            if (n < 0) return -1;
            p->nodes[n].args[0] = index;
            p->nodes[n].field = member_field;
            yx_module_field_typing(p, n);
            if (length_call) {
                int length = yx_module_node_new(p, YX_ME_LENGTH, 3);
                if (length >= 0) p->nodes[length].args[0] = n;
                return length;
            }
            if (member_field->kind != 7 || !yx_module_take(p, '[')) return n;
            field = member_field;
        }
    }
    return n;
}
static int yx_module_parse(yx_module_program *p, unsigned minimum, unsigned depth)
{
    if (!depth && !yx_module_nodes_for_input(p, strlen((const char *)p->parser.at))) return -1;
    size_t first = p->count;
    int left = yx_module_primary(p, depth + 1);
    if (left < 0) return -1;
    return yx_module_parse_operators(p, first, left, minimum, depth);
}
/* The operators that follow the operand `left`, by precedence; `first` is the
 * index of the first node made for that operand. */
static int yx_module_parse_operators(yx_module_program *p, size_t first, int left, unsigned minimum, unsigned depth)
{
    for (;;) {
        const unsigned char *save = p->parser.at;
        unsigned precedence = 0;
        uint8_t op = YX_ME_COMPARE, comparison = 0;
        yx_bool_skip_space(&p->parser);
        if (yx_bool_keyword(&p->parser, "or")) {
            precedence = 1;
            op = YX_ME_OR;
        } else if (yx_bool_keyword(&p->parser, "and")) {
            precedence = 2;
            op = YX_ME_AND;
        } else if (p->parse_primary && yx_bool_keyword(&p->parser, "matches")) {
            precedence = 3;
            comparison = 13;
        } else if (!strncmp((const char *)p->parser.at, "==", 2)) {
            precedence = 3;
            comparison = 0;
            p->parser.at += 2;
        } else if (!strncmp((const char *)p->parser.at, "!=", 2)) {
            precedence = 3;
            comparison = 1;
            p->parser.at += 2;
        } else if (!strncmp((const char *)p->parser.at, "<=", 2)) {
            precedence = 3;
            comparison = 4;
            p->parser.at += 2;
        } else if (!strncmp((const char *)p->parser.at, ">=", 2)) {
            precedence = 3;
            comparison = 5;
            p->parser.at += 2;
        } else if (!strncmp((const char *)p->parser.at, "<<", 2) || !strncmp((const char *)p->parser.at, ">>", 2)) {
            op = YX_ME_ARITH;
            comparison = *p->parser.at == '<' ? 0x86 : 0x87;
            p->parser.at += 2;
            precedence = yx_integer_expr_precedence(comparison) + 3;
        } else if (*p->parser.at == '<') {
            precedence = 3;
            comparison = 2;
            ++p->parser.at;
        } else if (*p->parser.at == '>') {
            precedence = 3;
            comparison = 3;
            ++p->parser.at;
        } else if (*p->parser.at == '+' || *p->parser.at == '-' || *p->parser.at == '*' || *p->parser.at == '&' || *p->parser.at == '|' || *p->parser.at == '^' ||
                   *p->parser.at == '%' || *p->parser.at == '\\') {
            unsigned char token = *p->parser.at++;
            op = YX_ME_ARITH;
            comparison = token == '+'   ? 0x7c
                         : token == '-' ? 0x7d
                         : token == '*' ? 0x7e
                         : token == '&' ? 0x83
                         : token == '|' ? 0x84
                         : token == '^' ? 0x85
                         : token == '%' ? 0x81
                                        : 0x7f;
            precedence = yx_integer_expr_precedence(comparison) + 3;
        } else {
            static const char *const words[] = {"contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals"};
            for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
                if (yx_bool_keyword(&p->parser, words[i])) {
                    precedence = 3;
                    comparison = (uint8_t)(i + 6);
                    break;
                }
        }
        if (!precedence || precedence < minimum) {
            p->parser.at = save;
            break;
        }
        int right = yx_module_parse(p, precedence + 1, depth + 1);
        if (right < 0) return -1;
        if (op == YX_ME_ARITH) {
            /* IR::fold_div / IR::fold_rem fold a `\` / `%` chain (one n-ary
             * operation, groups included) only when every operand is
             * constant: a constant prefix of `20 \ 2 \ filesize` divides at
             * run time. */
            if ((comparison == 0x7f || comparison == 0x81) && !p->nodes[right].constant)
                for (int link = left; link >= 0 && p->nodes[link].op == YX_ME_ARITH && p->nodes[link].comparison == comparison && p->nodes[link].constant;
                     link = p->nodes[link].args[0])
                    p->nodes[link].constant = false;
            left = yx_module_arithmetic_node(p, comparison, left, right);
            if (left < 0) return -1;
            continue;
        }
        /* IR::and/or folds an absorbing constant before imports and literals
         * are collected, including calls with side effects. Physical pattern
         * metadata remains independent of the surviving expression. */
        if (op == YX_ME_AND || op == YX_ME_OR) {
            int absorbing = op == YX_ME_OR;
            int t_left = yx_module_operand_truth(p, left);
            int t_right = yx_module_operand_truth(p, right);
            int folded = t_left == absorbing ? left : t_right == absorbing ? right : -1;
            if (folded >= 0) {
                /* Every node made for the operands so far, in order. */
                for (size_t dead = first; dead < p->count; ++dead) p->nodes[dead].folded_away = dead != (size_t)folded;
                /* The folded result is a Boolean constant. */
                if (p->nodes[folded].op != YX_ME_BOOL) {
                    int n = yx_module_node_new(p, YX_ME_BOOL, 1);
                    if (n < 0) return -1;
                    p->nodes[n].integer = absorbing;
                    p->nodes[n].constant = true;
                    folded = n;
                }
                left = folded;
                continue;
            }
            if (t_left >= 0 && t_right >= 0) {
                int n = yx_module_node_new(p, YX_ME_BOOL, 1);
                if (n < 0) return -1;
                p->nodes[n].integer = (op == YX_ME_AND) ? (t_left && t_right) : (t_left || t_right);
                p->nodes[n].constant = true;
                left = n;
                continue;
            }
        }
        int n = yx_module_node_new(p, op, 1);
        if (n < 0) return -1;
        p->nodes[n].args[0] = left;
        p->nodes[n].args[1] = right;
        p->nodes[n].comparison = comparison;
        left = n;
    }
    return left;
}

static int yx_module_import_add(yx_module_program *p, const char *module, const char *name, const uint8_t *args, size_t argc, uint8_t result, bool undefined)
{
    for (size_t i = 0; i < p->import_count; ++i)
        if (!strcmp(module, p->imports[i].module) && !strcmp(name, p->imports[i].name)) return (int)i;
    if (p->import_count == YX_MODULE_IMPORTS || argc > 8 || strlen(module) >= 80 || strlen(name) >= 160) return -1;
    const yx_archive_symbol_order *order = NULL;
    for (size_t i = 0; i < sizeof(yx_archive_symbol_orders) / sizeof(yx_archive_symbol_orders[0]); ++i)
        if (!strcmp(module, yx_archive_symbol_orders[i].module) && !strcmp(name, yx_archive_symbol_orders[i].name)) {
            order = &yx_archive_symbol_orders[i];
            break;
        }
    uint16_t rank = order ? order->ranks[p->profile] : UINT16_MAX;
    if (p->capi_import_order) {
        rank = UINT16_MAX;
        for (size_t i = 0; i < sizeof(yx_archive_capi_symbol_orders) / sizeof(yx_archive_capi_symbol_orders[0]); ++i)
            if (!strcmp(module, yx_archive_capi_symbol_orders[i].module) && !strcmp(name, yx_archive_capi_symbol_orders[i].name)) {
                rank = yx_archive_capi_symbol_orders[i].rank;
                break;
            }
    }
    if (rank == UINT16_MAX) return -1;
    int n = (int)p->import_count++;
    yx_module_import *entry = &p->imports[n];
    strcpy(entry->module, module);
    strcpy(entry->name, name);
    entry->rank = rank;
    entry->argc = (uint8_t)argc;
    if (argc) memcpy(entry->args, args, argc);
    entry->resultc = result ? (undefined ? 2 : 1) : 0;
    entry->results[0] = result;
    entry->results[1] = 0x7f;
    return n;
}
static bool yx_module_call(yx_module_program *p, yx_writer *body, const char *module, const char *name, const uint8_t *args, size_t argc, uint8_t result, bool undefined)
{
    int id = yx_module_import_add(p, module, name, args, argc, result, undefined);
    if (id < 0) return false;
    if (p->call_count == p->call_capacity) {
        size_t capacity = p->call_capacity ? p->call_capacity * 2 : 64;
        if (capacity < p->call_capacity || capacity > SIZE_MAX / sizeof(*p->calls)) return false;
        size_t *grown = realloc(p->calls, capacity * sizeof(*grown));
        if (!grown) {
            yx_walk_no_memory = true;
            return false;
        }
        p->calls = grown;
        p->call_capacity = capacity;
    }
    if (!yx_put_u8(body, 0x10)) return false;
    p->calls[p->call_count++] = body->used;
    return yx_put_u8(body, (uint8_t)id);
}
static bool yx_module_guard(yx_module_program *p, yx_writer *w)
{
    return yx_integer_emit_guard(w, 0x10, p->undefined_slot);
}
static bool yx_module_filesize_guard(yx_module_program *p, yx_writer *w)
{
    size_t start = w->used;
    if (!yx_integer_emit_guard(w, 0x23, p->undefined_slot)) return false;
    w->data[start + 1] = p->filesize_global;
    return true;
}
static bool yx_module_load_variable(yx_writer *w, int64_t slot, uint8_t type)
{
    return slot >= 0 && slot < YX_ARCHIVE_MAX_VARS && type >= 1 && type <= 8 && yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, slot * 8) &&
           yx_put_u8(w, type == 1   ? 0x28
                        : type == 2 ? 0x2b
                                    : 0x29) &&
           yx_put_u8(w, type == 1 ? 2 : 3) && yx_put_uleb(w, 256);
}
static bool yx_module_variable(yx_writer *w, int64_t slot, uint8_t type, int undefined_slot)
{
    return slot >= 0 && slot < YX_ARCHIVE_MAX_VARS && type >= 1 && type <= 8 && yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, slot / 8) &&
           yx_put_bytes(w, "\x2d\x00\x00\x41", 4) && yx_put_sleb_i64(w, INT64_C(1) << (slot % 8)) && yx_put_bytes(w, "\x71\x04\x40", 3) &&
           yx_integer_emit_undefined(w, undefined_slot) && yx_put_bytes(w, "\x05\x0b", 2) && yx_module_load_variable(w, slot, type);
}
/* emit_with records an undefined bitmap only when its initializer can throw.
 * A defined scalar call and its defined arguments use the same direct store
 * and load path as an object lookup. */
static bool yx_module_definite_value(const yx_module_program *p, int index, unsigned depth);
typedef struct {
    const yx_module_program *p;
    int index;
    unsigned depth;
    bool result;
} yx_module_definite_job;
static void yx_module_definite_thunk(void *data)
{
    yx_module_definite_job *j = data;
    j->result = yx_module_definite_value(j->p, j->index, j->depth);
}
static bool yx_module_definite_value(const yx_module_program *p, int index, unsigned depth)
{
    if (depth > YX_MODULE_DEPTH || index < 0 || (size_t)index >= p->count) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_definite_job job = {p, index, depth, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_definite_thunk, &job) && job.result;
    }
    const yx_module_node *n = &p->nodes[index];
    if (n->constant) return true;
    if (n->op >= 32) return p->definite_primary && p->definite_primary(p, index, depth);
    if (n->op == YX_ME_VARIABLE) return n->integer >= 0 && n->integer < YX_ARCHIVE_MAX_VARS && p->slot_defined[n->integer];
    if (n->op == YX_ME_LOOKUP) return n->type > 4;
    if (n->op == YX_ME_MEMBER) return n->type > 4 && yx_module_definite_value(p, n->args[0], depth + 1);
    if (n->op == YX_ME_CALL) {
        if (!n->signature || n->signature->undefined) return false;
        for (size_t i = 0; i < n->argc; ++i)
            if (n->signature->args[i] != 5 && !yx_module_definite_value(p, n->args[i], depth + 1)) return false;
        return true;
    }
    if (n->op == YX_ME_LENGTH || n->op == YX_ME_NOT || n->op == YX_ME_GROUP || n->op == YX_ME_NEGATE) return yx_module_definite_value(p, n->args[0], depth + 1);
    if (n->op == YX_ME_AND || n->op == YX_ME_OR || n->op == YX_ME_DEFINED) return true;
    if (n->op == YX_ME_COMPARE || n->op == YX_ME_ARITH) {
        if (n->op == YX_ME_ARITH && (n->comparison == 0x7f || n->comparison == 0x81)) return false;
        return yx_module_definite_value(p, n->args[0], depth + 1) && yx_module_definite_value(p, n->args[1], depth + 1);
    }
    return false;
}
static bool yx_module_emit(yx_module_program *, int, yx_writer *, unsigned);
static bool yx_module_boolean(yx_module_program *, int, yx_writer *, unsigned);
/* The integer readers' template names, which the symbol orders list and the
 * v12 lowering renames (yx_archive_symbol_aliases); 64-bit and big-endian
 * readers too. */
static const char *yx_module_read_import_name(uint8_t type)
{
    static const char *const names[YX_INTEGER_READ_COUNT - 6] = {"uint64@offset:i@iu",
                                                                 "int64@offset:i@iu",
                                                                 "uint8be@offset:i@i:R0:255u",
                                                                 "uint16be@offset:i@i:R0:65535u",
                                                                 "uint32be@offset:i@i:R0:4294967295u",
                                                                 "uint64be@offset:i@iu",
                                                                 "int8be@offset:i@i:R-128:127u",
                                                                 "int16be@offset:i@i:R-32768:32767u",
                                                                 "int32be@offset:i@i:R-2147483648:2147483647u",
                                                                 "int64be@offset:i@iu"};
    /* float32/float64 and their big-endian forms (wasm/builtins.rs). */
    static const char *const floats[YX_MODULE_READ_COUNT - YX_INTEGER_READ_COUNT] = {"float32@offset:i@fu", "float64@offset:i@fu", "float32be@offset:i@fu",
                                                                                     "float64be@offset:i@fu"};
    return type < 6                       ? yx_integer_read_import_name(type)
           : type < YX_INTEGER_READ_COUNT ? names[type - 6]
           : type < YX_MODULE_READ_COUNT  ? floats[type - YX_INTEGER_READ_COUNT]
                                          : NULL;
}
static const char *yx_module_index_name(uint8_t type)
{
    return type == 1   ? "array_indexing_bool@array:i,index:i@bu"
           : type == 2 ? "array_indexing_float@array:i,index:i@fu"
           : type == 3 ? "array_indexing_integer@array:i,index:i@iu"
           : type == 6 ? "array_indexing_struct@array:i,index:i@iu"
                       : "array_indexing_string@array:i,index:i@iu";
}
/* emit_map_lookup: map_lookup_<key>_<value> for a map of scalar values. */
static const char *yx_module_map_lookup_name(const yx_archive_module_map *map)
{
    static const char *const string_keys[] = {"map_lookup_string_bool@map:i,key:s@bu", "map_lookup_string_float@map:i,key:s@fu",
                                              "map_lookup_string_integer@map:i,key:s@iu", "map_lookup_string_string@map:i,key:s@iu"};
    static const char *const integer_keys[] = {"map_lookup_integer_bool@map:i,key:i@bu", "map_lookup_integer_float@map:i,key:i@fu",
                                               "map_lookup_integer_integer@map:i,key:i@iu", "map_lookup_integer_string@map:i,key:i@iu"};
    if (!map || map->value < 1 || map->value > 4 || (map->key != 3 && map->key != 4)) return NULL;
    return (map->key == 4 ? string_keys : integer_keys)[map->value - 1];
}
static bool yx_module_store_tail(yx_writer *w, int64_t slot, uint8_t type)
{
    return slot >= 0 && slot < YX_ARCHIVE_MAX_VARS &&
           yx_put_u8(w, type == 1   ? 0x36
                        : type == 2 ? 0x39
                                    : 0x37) &&
           yx_put_u8(w, type == 1 ? 2 : 3) && yx_put_uleb(w, 256) && yx_integer_clear_variable(w, slot);
}
static bool yx_module_store_value(yx_writer *w, uint8_t type)
{
    return yx_put_u8(w, type == 1 ? 0x36 : type == 2 ? 0x39 : 0x37) && yx_put_u8(w, type == 1 ? 2 : 3) && yx_put_uleb(w, 256);
}
static bool yx_module_loop_repeat(yx_writer *w, int64_t slot, unsigned depth)
{
    return yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, (slot + 1) * 8) && yx_module_load_variable(w, slot + 1, 3) && yx_put_bytes(w, "\x42\x01\x7c", 3) &&
           yx_module_store_value(w, 3) && yx_module_load_variable(w, slot + 1, 3) && yx_module_load_variable(w, slot, 3) && yx_put_u8(w, 0x53) && yx_put_u8(w, 0x0d) &&
           yx_put_uleb(w, depth);
}
static bool yx_module_loop_tail(yx_writer *w, int64_t slot, uint8_t quantifier)
{
    bool all = quantifier == 0xc5, any = quantifier == 0xc4;
    if (!yx_put_bytes(w, "\x04\x40", 2)) return false;
    if (all) {
        if (!yx_module_loop_repeat(w, slot, 1) || !yx_integer_loop_exit(w, true)) return false;
    } else if (!yx_integer_loop_exit(w, any)) return false;
    if (!yx_put_bytes(w, "\x05\x0b", 2)) return false;
    if (all) {
        if (!yx_put_bytes(w, "\x41\x00\x0c\x01", 4)) return false;
    } else if (!yx_module_loop_repeat(w, slot, 0)) return false;
    return yx_put_bytes(w, "\x0b\x41", 2) && yx_put_u8(w, any ? 0 : 1) && yx_put_u8(w, 0x0b);
}
static bool yx_module_loop_catch_tail(yx_writer *w, int64_t slot, uint8_t quantifier)
{
    bool all = quantifier == 0xc5, any = quantifier == 0xc4;
    if (!yx_put_bytes(w, "\4\x40", 2)) return false;
    if (all && !yx_module_loop_repeat(w, slot, 2)) return false;
    if (!yx_put_u8(w, 0x41) || !yx_put_u8(w, all || any ? 1 : 0) || !yx_put_bytes(w, "\x0c\3\5\x0b\x0b", 5)) return false;
    if (all) {
        if (!yx_put_bytes(w, "\x41\0\x0c\1", 4)) return false;
    } else if (!yx_module_loop_repeat(w, slot, 0)) return false;
    return yx_put_bytes(w, "\x0b\x41", 2) && yx_put_u8(w, any ? 0 : 1) && yx_put_u8(w, 0x0b);
}
static bool yx_module_loop_catch_rewrite(yx_module_program *, yx_writer *, size_t);
static int yx_module_loop_catch_decode(yx_reader *, size_t, yx_module_program *, unsigned);
static bool yx_module_body_escapes(const uint8_t *, size_t, bool *);
static bool yx_module_shift_wide_locals(uint8_t *, size_t, int);
/* emit_for's quantifier code, shared with `for .. in (a..b)`
 * (serialization_module_patterns.h). */
static bool yx_module_for_tail(uint8_t, bool, yx_writer *, int64_t, int64_t, int64_t, int64_t, int64_t);
static bool yx_module_quantity_emit(yx_module_program *, yx_writer *, uint8_t, int, int64_t, int64_t, int64_t, unsigned);
static bool yx_module_quantity_decode(yx_reader *, size_t, yx_module_program *, unsigned, int64_t, int64_t, int64_t, uint8_t *, int *);
/* emit_for: set_var(max_count) and set_var(count, 0) of an expression or
 * percentage quantifier follow `i = 0`, before the loop (frame: n, i,
 * max_count, count at `slot`). Nothing for `any`, `all` and `none`. */
static bool yx_module_loop_quantity(yx_module_program *p, yx_writer *w, int64_t slot)
{
    uint8_t kind = p->loop_kind;
    int quantity = p->loop_quantity;
    p->loop_kind = 0;
    p->loop_split = w->used;
    return !kind || yx_module_quantity_emit(p, w, kind, quantity, slot, slot + 2, slot + 3, 0);
}
/* `catching`: the body's block is the loop's void catch_undef (structure
 * elements whose body can be undefined) instead of a result block. */
static bool yx_module_loop_prefix(yx_module_program *p, yx_writer *w, int64_t slot, uint8_t type, bool catching)
{
    const uint8_t arg = 0x7e, pair[] = {0x7e, 0x7e};
    static const uint8_t empty[] = {0x42, 0, 0x57, 0x04, 0x40, 0x41, 0, 0x0c, 1, 0x05, 0x0b, 0x41};
    return yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, slot * 8) && yx_module_load_variable(w, slot + 4, 3) &&
           yx_module_call(p, w, "yara_x::wasm", "Array::len@array:i@i", &arg, 1, 0x7e, false) && yx_module_store_value(w, 3) && yx_module_load_variable(w, slot, 3) &&
           yx_put_bytes(w, empty, sizeof(empty)) && yx_put_sleb_i64(w, (slot + 1) * 8) && yx_put_u8(w, 0x42) && yx_put_u8(w, 0) && yx_module_store_value(w, 3) &&
           yx_module_loop_quantity(p, w, slot) && yx_put_u8(w, 3) && yx_put_u8(w, 0x40) && yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, (slot + 5) * 8) &&
           yx_module_load_variable(w, slot + 4, 3) && yx_module_load_variable(w, slot + 1, 3) &&
           yx_module_call(p, w, "yara_x::wasm", yx_module_index_name(type), pair, 2, yx_module_wasm_type(type), true) &&
           /* An element's undefined value reaches the handler outside the loop
            * and its block (before_cond is outside the body's catch). */
           yx_integer_emit_guard(w, 0x10, yx_integer_undefined_shift(p->undefined_slot, 2)) && yx_module_store_value(w, type) && yx_put_u8(w, 2) &&
           yx_put_u8(w, catching ? 0x40 : 0x7f);
}
/* map_lookup_by_index_<key>_<value> returns two i64 values, not a value and
 * an undefined flag. */
static bool yx_module_call_pair(yx_module_program *p, yx_writer *w, const char *name)
{
    static const uint8_t pair[] = {0x7e, 0x7e};
    if (!yx_module_call(p, w, "yara_x::wasm", name, pair, 2, 0x7e, true)) return false;
    int id = yx_module_import_add(p, "yara_x::wasm", name, pair, 2, 0x7e, true);
    if (id < 0) return false;
    p->imports[id].results[1] = 0x7e;
    return true;
}
/* emit_for_in_map: as yx_module_loop_prefix, with Map::len and, before each
 * iteration, set_vars([key, value], map_lookup_by_index(item, i)) through
 * i64_tmp_a (local 0): the value at slot + 6 first, then the key at slot + 5.
 * The body's block is the loop's void catch_undef when the body can be
 * undefined (`catching`), as for structure elements. */
static bool yx_module_map_loop_prefix(yx_module_program *p, yx_writer *w, int64_t slot, const yx_archive_module_map *map, bool catching)
{
    const uint8_t arg = 0x7e;
    static const uint8_t empty[] = {0x42, 0, 0x57, 0x04, 0x40, 0x41, 0, 0x0c, 1, 0x05, 0x0b, 0x41};
    const char *name = yx_module_map_by_index_name(map);
    return name && yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, slot * 8) && yx_module_load_variable(w, slot + 4, 3) &&
           yx_module_call(p, w, "yara_x::wasm", "Map::len@map:i@i", &arg, 1, 0x7e, false) && yx_module_store_value(w, 3) && yx_module_load_variable(w, slot, 3) &&
           yx_put_bytes(w, empty, sizeof(empty)) && yx_put_sleb_i64(w, (slot + 1) * 8) && yx_put_u8(w, 0x42) && yx_put_u8(w, 0) && yx_module_store_value(w, 3) &&
           yx_module_loop_quantity(p, w, slot) && yx_put_u8(w, 3) && yx_put_u8(w, 0x40) && yx_module_load_variable(w, slot + 4, 3) &&
           yx_module_load_variable(w, slot + 1, 3) && yx_module_call_pair(p, w, name) && yx_put_bytes(w, "\x21\x00\x41", 3) && yx_put_sleb_i64(w, (slot + 6) * 8) &&
           yx_put_bytes(w, "\x20\x00", 2) && yx_module_store_value(w, map->value) && yx_put_bytes(w, "\x21\x00\x41", 3) && yx_put_sleb_i64(w, (slot + 5) * 8) &&
           yx_put_bytes(w, "\x20\x00", 2) && yx_module_store_value(w, map->key) && yx_put_u8(w, 2) && yx_put_u8(w, catching ? 0x40 : 0x7f);
}
static bool yx_module_arithmetic(yx_module_program *p, int index, yx_writer *w, uint8_t parent, unsigned depth, bool float_chain);
typedef struct {
    yx_module_program *p;
    int index;
    yx_writer *w;
    uint8_t parent;
    unsigned depth;
    bool float_chain, result;
} yx_module_arithmetic_job;
static void yx_module_arithmetic_thunk(void *data)
{
    yx_module_arithmetic_job *j = data;
    j->result = yx_module_arithmetic(j->p, j->index, j->w, j->parent, j->depth, j->float_chain);
}
static bool yx_module_arithmetic(yx_module_program *p, int index, yx_writer *w, uint8_t parent, unsigned depth, bool float_chain)
{
    const yx_module_node *n = &p->nodes[index];
    if (depth > YX_MODULE_DEPTH) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_arithmetic_job job = {p, index, w, parent, depth, float_chain, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_arithmetic_thunk, &job) && job.result;
    }
    if (n->op != YX_ME_ARITH) return yx_module_emit(p, index, w, depth + 1);
    bool chain = n->comparison == parent && (parent == 0x7c || parent == 0x7d || parent == 0x7e);
    if (n->constant && !chain) return n->type == 2 ? yx_put_u8(w, 0x44) && yx_put_float(w, n->real) : yx_put_u8(w, 0x42) && yx_put_sleb_i64(w, n->integer);
    const yx_module_node *a = &p->nodes[n->args[0]], *b = &p->nodes[n->args[1]];
    if (n->comparison == 0x86 || n->comparison == 0x87) {
        /* emit_shift_op (emit.rs:146): the amount goes through i64_tmp_b,
         * and an amount of 64 or more gives 0. */
        if (!p->shifts) return false;
        p->shift = true;
        return yx_module_arithmetic(p, n->args[0], w, 0, depth + 1, false) && yx_module_arithmetic(p, n->args[1], w, 0, depth + 1, false) &&
               yx_integer_shift_v12_emit(w, n->comparison, a->unsigned_value, b->unsigned_value, 1);
    }
    bool real = n->type == 2 || (chain && float_chain);
    bool left_chain = a->op == YX_ME_ARITH && a->comparison == n->comparison && (n->comparison == 0x7c || n->comparison == 0x7d || n->comparison == 0x7e);
    uint8_t operation = real ? (uint8_t)(n->comparison - 0x7c + 0xa0) : n->comparison;
    if (!real && (n->comparison == 0x7f || n->comparison == 0x81)) p->divisor = true;
    if (!real && n->comparison == 0x7f && !n->unsigned_value) p->two_locals = true;
    return yx_module_arithmetic(p, n->args[0], w, n->comparison, depth + 1, real && left_chain) &&
           (!real || a->type == 2 || left_chain || yx_put_u8(w, a->unsigned_value ? 0xba : 0xb9)) && yx_module_arithmetic(p, n->args[1], w, 0, depth + 1, false) &&
           (!real || b->type == 2 || yx_put_u8(w, b->unsigned_value ? 0xba : 0xb9)) &&
           ((!real && operation == 0x7f && !n->unsigned_value)
                ? yx_integer_signed_division_emit(w, p->undefined_slot)
                : ((real || (operation != 0x7f && operation != 0x81) || yx_integer_emit_guard(w, 0x22, p->undefined_slot)) &&
                   yx_put_u8(w, !real && n->unsigned_value && (operation == 0x7f || operation == 0x81) ? (uint8_t)(operation + 1) : operation)));
}
static bool yx_module_boolean(yx_module_program *p, int index, yx_writer *w, unsigned depth)
{
    const yx_module_node *n = &p->nodes[index];
    if (!yx_module_emit(p, index, w, depth + 1)) return false;
    if (n->type == 1) return true;
    if (n->type == 3) return yx_put_u8(w, 0x42) && yx_put_u8(w, 0) && yx_put_u8(w, 0x52);
    if (n->type == 2) return yx_put_u8(w, 0x44) && yx_put_float(w, 0) && yx_put_u8(w, 0x62);
    /* emit_bool_expr: a string is true when it is not empty. */
    if (n->type == 4) {
        const uint8_t arg = 0x7e;
        return yx_module_call(p, w, "yara_x::wasm", "str_len@s:s@i", &arg, 1, 0x7e, false) && yx_put_u8(w, 0x42) && yx_put_u8(w, 0) && yx_put_u8(w, 0x52);
    }
    return false;
}
/* emit_defined: catch_undef(I32) around the operand as a Boolean, whose value
 * is dropped for `i32.const 1`; an undefined operand gives 0. The block exists
 * only when an undefined value can reach it (not for a definite operand).
 * Writes the block's content. */
static bool yx_module_defined_body(yx_module_program *p, int index, yx_writer *w, unsigned depth);
typedef struct {
    yx_module_program *p;
    int index;
    yx_writer *w;
    unsigned depth;
    bool result;
} yx_module_defined_job;
static void yx_module_defined_thunk(void *data)
{
    yx_module_defined_job *j = data;
    j->result = yx_module_defined_body(j->p, j->index, j->w, j->depth);
}
static bool yx_module_defined_body(yx_module_program *p, int index, yx_writer *w, unsigned depth)
{
    const yx_module_node *n = &p->nodes[index];
    if (depth > YX_MODULE_DEPTH) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_defined_job job = {p, index, w, depth, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_defined_thunk, &job) && job.result;
    }
    int saved = p->undefined_slot;
    p->undefined_slot = -1;
    /* Only `and` and `or` open a lazy search scope (emit_expr): the first
     * pattern operand of the operand shares the enclosing scope's search. */
    bool ok = yx_module_boolean(p, n->args[0], w, depth + 1) && yx_put_u8(w, 0x1a) && yx_put_u8(w, 0x41) && yx_put_u8(w, 1);
    p->undefined_slot = saved;
    return ok;
}
/* emit_rule_condition's catch_undef has a block only when an undefined value
 * reaches it. A root `defined` catches every undefined value of its operand
 * itself, so its block is the rule's leading block (the v12 restoration
 * strips the untargeted outer block only around a single block). Writes the
 * leading block's content. */
static bool yx_module_root_boolean(yx_module_program *p, int root, yx_writer *w)
{
    if (root >= 0 && (size_t)root < p->count && p->nodes[root].op == YX_ME_DEFINED && !yx_module_definite_value(p, p->nodes[root].args[0], 0))
        return yx_module_defined_body(p, root, w, 0);
    return yx_module_boolean(p, root, w, 0);
}
/* A flat source chain is a left-associated tree. Its length is not expression
 * nesting, so walk that spine without growing the C stack or nesting budget. */
static int *yx_module_left_chain(const yx_module_program *p, int index, uint8_t op, size_t *count)
{
    size_t length = 1;
    int at = index;
    while (p->nodes[at].op == op) {
        if (length >= p->count) return NULL;
        ++length;
        at = p->nodes[at].args[0];
        if (at < 0 || (size_t)at >= p->count) return NULL;
    }
    if (length > SIZE_MAX / sizeof(int)) return NULL;
    int *items = malloc(length * sizeof(*items));
    if (!items) {
        yx_walk_no_memory = true;
        return NULL;
    }
    *count = length;
    at = index;
    while (p->nodes[at].op == op) {
        items[--length] = p->nodes[at].args[1];
        at = p->nodes[at].args[0];
    }
    items[0] = at;
    return items;
}
static bool yx_module_boolean_operands(yx_module_program *p, int index, uint8_t op, yx_writer *w, bool flatten, unsigned depth);
typedef struct {
    yx_module_program *p;
    int index;
    uint8_t op;
    yx_writer *w;
    bool flatten;
    unsigned depth;
    bool result;
} yx_module_operands_job;
static void yx_module_operands_thunk(void *data)
{
    yx_module_operands_job *j = data;
    j->result = yx_module_boolean_operands(j->p, j->index, j->op, j->w, j->flatten, j->depth);
}
static bool yx_module_boolean_operands(yx_module_program *p, int index, uint8_t op, yx_writer *w, bool flatten, unsigned depth)
{
    const yx_module_node *n = &p->nodes[index];
    if (depth > YX_MODULE_DEPTH) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_operands_job job = {p, index, op, w, flatten, depth, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_operands_thunk, &job) && job.result;
    }
    /* IR::and/or drop neutral constants; the plain module codec has no
     * one-operand form and leaves such conditions to the composed codec. */
    if (yx_module_operand_truth(p, index) == (op == YX_ME_AND ? 1 : 0)) return p->boolean_scope != NULL;
    if (flatten && n->op == op) {
        size_t count;
        int *items = yx_module_left_chain(p, index, op, &count);
        if (!items) return false;
        bool ok = true;
        for (size_t i = 0; ok && i < count; ++i) ok = yx_module_boolean_operands(p, items[i], op, w, false, depth);
        free(items);
        return ok;
    }
    if (op == YX_ME_OR && (!yx_put_u8(w, 2) || !yx_put_u8(w, 0x7f))) return false;
    if (!yx_module_boolean(p, index, w, depth + 1)) return false;
    if (op == YX_ME_OR && !yx_put_u8(w, 0x0b)) return false;
    return op == YX_ME_OR ? yx_put_bytes(w, yx_integer_or_guard, sizeof(yx_integer_or_guard)) : yx_put_bytes(w, yx_integer_and_guard, sizeof(yx_integer_and_guard));
}
static bool yx_module_non_negative(const yx_module_node *node)
{
    return node->unsigned_value || (node->constant && node->integer >= 0) || (node->integer_kind >= 7 && node->integer_kind <= 10) ||
           (node->op == YX_ME_READ && (node->integer <= 2 || (node->integer >= 8 && node->integer <= 10)));
}
static bool yx_module_emit(yx_module_program *p, int index, yx_writer *w, unsigned depth);
typedef struct {
    yx_module_program *p;
    int index;
    yx_writer *w;
    unsigned depth;
    bool result;
} yx_module_emit_job;
static void yx_module_emit_thunk(void *data)
{
    yx_module_emit_job *j = data;
    j->result = yx_module_emit(j->p, j->index, j->w, j->depth);
}
static bool yx_module_emit(yx_module_program *p, int index, yx_writer *w, unsigned depth)
{
    if (depth > YX_MODULE_DEPTH || index < 0 || (size_t)index >= p->count) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_emit_job job = {p, index, w, depth, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_emit_thunk, &job) && job.result;
    }
    const yx_module_node *n = &p->nodes[index];
    if (n->op >= 32) return p->emit_primary && p->emit_primary(p, index, w, depth);
    static const uint8_t pair64[] = {0x7e, 0x7e}, lookup_args[] = {0x7e, 0x7f};
    if (n->op == YX_ME_ARITH) return yx_module_arithmetic(p, index, w, 0, depth + 1, false);
    /* Expr::Minus of a float (emit.rs:504): the operand and `f64.neg`. */
    if (n->op == YX_ME_NEGATE) return yx_module_emit(p, n->args[0], w, depth + 1) && yx_put_u8(w, 0x9a);
    if (n->op == YX_ME_INT) return yx_put_u8(w, 0x42) && yx_put_sleb_i64(w, n->integer);
    if (n->op == YX_ME_FLOAT) return yx_put_u8(w, 0x44) && yx_put_float(w, n->real);
    if (n->op == YX_ME_BOOL) return yx_put_u8(w, 0x41) && yx_put_u8(w, n->integer != 0);
    if (n->op == YX_ME_STRING) {
        size_t id;
        return yx_intern_literal(n->bytes, n->length, &p->literals, &p->literal_count, &p->literal_capacity, &id) && id <= INT64_MAX / 4 && yx_put_u8(w, 0x42) &&
               yx_put_sleb_i64(w, (int64_t)(id * 4));
    }
    if (n->op == YX_ME_FILESIZE) {
        p->filesize = true;
        return yx_module_filesize_guard(p, w);
    }
    if (n->op == YX_ME_VARIABLE) {
        p->memory = true;
        return n->integer >= 0 && n->integer < YX_ARCHIVE_MAX_VARS &&
               (p->slot_defined[n->integer] ? yx_module_load_variable(w, n->integer, n->type) : yx_module_variable(w, n->integer, n->type, p->undefined_slot));
    }
    if (n->op == YX_ME_LOOP) {
        static const uint8_t types[] = {3, 2, 1, 4, 6};
        const yx_archive_module_field *field = p->nodes[n->args[0]].field;
        /* Quantifier::Expr and ::Percentage count the true iterations
         * (emit_for): kinds 3 and 4 of yx_module_for_tail. */
        uint8_t counted = n->comparison == 0xc7 ? 3 : n->comparison == 0xc8 ? 4 : 0;
        /* A percentage that can be negative is replaced at run time
         * (emit.rs:2460, TypeValue::is_non_negative). The width of a module
         * field comes from the module's serialized structure
         * (yx_archive_field_integer_kind); the result types of module
         * functions and of map values are not carried, so a percentage is a
         * constant, `filesize`, an integer read or a module field here. */
        if (counted == 4 && !p->nodes[n->args[2]].constant && p->nodes[n->args[2]].op != YX_ME_FILESIZE && p->nodes[n->args[2]].op != YX_ME_READ &&
            !p->nodes[n->args[2]].integer_kind)
            return false;
        if (field && field->kind == 8) {
            const yx_archive_module_map *map = yx_module_map_types(field);
            if (!yx_module_map_by_index_name(map) || n->integer < 0 || n->integer > YX_ARCHIVE_MAX_VARS - 7) return false;
            /* set_vars uses i64_tmp_a, the local that divisions use. */
            p->memory = true;
            p->divisor = true;
            bool saved_key = p->slot_defined[n->integer + 5], saved_value = p->slot_defined[n->integer + 6];
            p->slot_defined[n->integer + 5] = p->slot_defined[n->integer + 6] = true;
            bool escapes = false;
            bool ok = yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, (n->integer + 4) * 8) && yx_module_emit(p, n->args[0], w, depth + 1) && yx_module_store_value(w, 3) &&
                      (p->loop_kind = counted, p->loop_quantity = n->args[2], true) && yx_module_map_loop_prefix(p, w, n->integer, map, false);
            size_t body_start = w->used >= 2 ? w->used - 2 : 0;
            int saved = p->undefined_slot;
            p->undefined_slot = -1;
            ok = ok && yx_module_boolean(p, n->args[1], w, depth + 1);
            p->slot_defined[n->integer + 5] = saved_key;
            p->slot_defined[n->integer + 6] = saved_value;
            p->undefined_slot = saved;
            /* catch_undef keeps the loop's void block only when the body can
             * leave it; the body's code does not depend on that block. */
            if (!ok || !yx_module_body_escapes(w->data + body_start + 2, w->used - body_start - 2, &escapes) || !yx_put_u8(w, 0x0b)) return false;
            if (escapes) {
                w->data[body_start + 1] = 0x40;
                return yx_module_loop_catch_rewrite(p, w, body_start) &&
                       (counted ? yx_module_for_tail(counted, true, w, n->integer, n->integer + 1, n->integer + 2, n->integer + 3, -1)
                                : yx_module_loop_catch_tail(w, n->integer, n->comparison));
            }
            return counted ? yx_module_for_tail(counted, false, w, n->integer, n->integer + 1, n->integer + 2, n->integer + 3, -1)
                           : yx_module_loop_tail(w, n->integer, n->comparison);
        }
        if (!field || field->element > 4 || n->integer < 0 || n->integer > YX_ARCHIVE_MAX_VARS - 7) return false;
        p->memory = true;
        uint8_t element = types[field->element];
        bool ok = yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, (n->integer + 4) * 8) && yx_module_emit(p, n->args[0], w, depth + 1) && yx_module_store_value(w, 3) &&
                  (p->loop_kind = counted, p->loop_quantity = n->args[2], true) && yx_module_loop_prefix(p, w, n->integer, element, element == 6);
        int saved = p->undefined_slot;
        p->undefined_slot = -1;
        bool saved_defined = p->slot_defined[n->integer + 5];
        p->slot_defined[n->integer + 5] = true;
        size_t body_start = w->used >= 2 ? w->used - 2 : 0;
        ok = ok && yx_module_boolean(p, n->args[1], w, depth + 1);
        p->slot_defined[n->integer + 5] = saved_defined;
        p->undefined_slot = saved;
        /* The loop's catch_undef block stays only when the body can leave it
         * (emit_for: catch_undef's handler.used), whatever the element type
         * (a nested loop's array_indexing leaves it); otherwise the body is
         * a result block. */
        bool escapes = false;
        if (!ok || !yx_module_body_escapes(w->data + body_start + 2, w->used - body_start - 2, &escapes) || !yx_put_u8(w, 0x0b)) return false;
        if (escapes) {
            w->data[body_start + 1] = 0x40;
            return yx_module_loop_catch_rewrite(p, w, body_start) &&
                   (counted ? yx_module_for_tail(counted, true, w, n->integer, n->integer + 1, n->integer + 2, n->integer + 3, -1)
                            : yx_module_loop_catch_tail(w, n->integer, n->comparison));
        }
        w->data[body_start + 1] = 0x7f;
        return counted ? yx_module_for_tail(counted, false, w, n->integer, n->integer + 1, n->integer + 2, n->integer + 3, -1)
                       : yx_module_loop_tail(w, n->integer, n->comparison);
    }
    if (n->op == YX_ME_BIND) {
        /* The declarations of a `with` are a chain of nodes, as long as the
         * variables YARA-X allows (2048): walked here, not by recursion. */
        bool *saved_defined = NULL;
        size_t chain = 0, capacity = 0;
        bool ok = true;
        int body = index;
        while (ok && p->nodes[body].op == YX_ME_BIND) {
            n = &p->nodes[body];
            if (n->integer < 0 || n->integer >= YX_ARCHIVE_MAX_VARS || n->args[1] < 0 || (size_t)n->args[1] >= p->count || chain >= YX_ARCHIVE_MAX_VARS) {
                ok = false;
                break;
            }
            if (chain == capacity) {
                size_t next = capacity ? capacity * 2 : 16;
                bool *grown = realloc(saved_defined, next * sizeof(*grown));
                if (!grown) {
                    yx_walk_no_memory = true;
                    ok = false;
                    break;
                }
                saved_defined = grown;
                capacity = next;
            }
            uint8_t type = p->nodes[n->args[0]].type;
            bool direct = yx_module_definite_value(p, n->args[0], 0);
            saved_defined[chain++] = p->slot_defined[n->integer];
            int saved = p->undefined_slot;
            p->undefined_slot = direct ? saved : (int)n->integer;
            p->memory = true;
            ok = (direct || (yx_put_u8(w, 2) && yx_put_u8(w, 0x40))) && yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, n->integer * 8) &&
                 yx_module_emit(p, n->args[0], w, depth + 1) && yx_module_store_value(w, type) &&
                 (direct || (yx_integer_clear_variable(w, n->integer) && yx_put_u8(w, 0x0b)));
            p->undefined_slot = saved;
            p->slot_defined[n->integer] = direct;
            body = n->args[1];
        }
        ok = ok && yx_module_emit(p, body, w, depth + 1);
        /* Each declaration's slot gets back the state it had, innermost first. */
        if (chain) {
            int *links = malloc(chain * sizeof(*links));
            if (!links) {
                yx_walk_no_memory = true;
                ok = false;
            } else {
                int at = index;
                for (size_t i = 0; i < chain; ++i) {
                    links[i] = at;
                    at = p->nodes[at].args[1];
                }
                for (size_t i = chain; i-- > 0;) p->slot_defined[p->nodes[links[i]].integer] = saved_defined[i];
                free(links);
            }
        }
        free(saved_defined);
        return ok;
    }
    if (n->op == YX_ME_LENGTH) {
        const uint8_t arg = 0x7e;
        return yx_module_emit(p, n->args[0], w, depth + 1) && yx_module_call(p, w, "yara_x::wasm",
                                                                             p->nodes[n->args[0]].type == 8   ? "Map::len@map:i@i"
                                                                             : p->nodes[n->args[0]].type == 4 ? "RuntimeString::len@string:s@i"
                                                                                                              : "Array::len@array:i@i",
                                                                             &arg, 1, 0x7e, false);
    }
    if (n->op == YX_ME_LOOKUP || n->op == YX_ME_MEMBER) {
        const yx_archive_module_field *field = n->field;
        const char *name = n->type == 1   ? "lookup_bool@structure:iu,num_lookup_indexes:i@bu"
                           : n->type == 2 ? "lookup_float@structure:iu,num_lookup_indexes:i@fu"
                           : n->type == 3 ? "lookup_integer@structure:iu,num_lookup_indexes:i@iu"
                           : n->type == 4 ? "lookup_string@structure:iu,num_lookup_indexes:i@su"
                                          : "lookup_object@structure:iu,num_lookup_indexes:i@i";
        p->memory = true;
        size_t first = 0;
        if (!field) return false;
        if (n->op == YX_ME_MEMBER) {
            const yx_module_node *base = &p->nodes[n->args[0]];
            if (!base->field || base->field->depth >= field->depth || !yx_module_emit(p, n->args[0], w, depth + 1)) return false;
            first = base->field->depth;
        } else if (!yx_put_u8(w, 0x42) || !yx_put_sleb_i64(w, -1)) return false;
        for (size_t i = first; i < field->depth; ++i)
            if (!yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, (int64_t)((i - first) * 4)) || !yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, field->indexes[i]) ||
                !yx_put_u8(w, 0x36) || !yx_put_u8(w, 2) || !yx_put_uleb(w, 16640))
                return false;
        return yx_put_u8(w, 0x41) && yx_put_sleb_i64(w, (int64_t)(field->depth - first)) &&
               yx_module_call(p, w, "yara_x::wasm", name, lookup_args, 2, yx_module_wasm_type(n->type), n->type <= 4) && (n->type > 4 || yx_module_guard(p, w));
    }
    if (n->op == YX_ME_INDEX) {
        const char *name = n->field && n->field->kind == 8 ? yx_module_map_lookup_name(yx_module_map_types(n->field)) : yx_module_index_name(n->type);
        return name && yx_module_emit(p, n->args[0], w, depth + 1) && yx_module_emit(p, n->args[1], w, depth + 1) &&
               yx_module_call(p, w, "yara_x::wasm", name, pair64, 2, yx_module_wasm_type(n->type), true) && yx_module_guard(p, w);
    }
    if (n->op == YX_ME_CALL) {
        const yx_archive_module_signature *sig = n->signature;
        char module[80];
        uint8_t args[8];
        if (!p->schema || !sig) return false;
        const char *separator = strchr(sig->path, '.');
        if (!separator || separator == sig->path || separator - sig->path > 48) return false;
        snprintf(module, sizeof(module), "yara_x::modules::%.*s", (int)(separator - sig->path), sig->path);
        for (size_t i = 0; i < sig->argc; ++i) {
            args[i] = yx_module_wasm_type(sig->args[i]);
            if (sig->args[i] == 5) {
                /* TypeValue::Regexp (emit.rs:345): the RegexpId in the regexp pool. */
                const yx_module_node *re = &p->nodes[n->args[i]];
                size_t id;
                if (re->type != 5 || !re->bytes || !p->regexes || !yx_intern_literal(re->bytes, re->length, p->regexes, p->regex_count, p->regex_capacity, &id) ||
                    id > INT32_MAX || !yx_put_u8(w, 0x41) || !yx_put_sleb_i64(w, (int64_t)id))
                    return false;
                continue;
            }
            if (!yx_module_emit(p, n->args[i], w, depth + 1) ||
                (sig->args[i] == 2 && p->nodes[n->args[i]].type == 3 && !yx_put_u8(w, p->nodes[n->args[i]].unsigned_value ? 0xba : 0xb9)))
                return false;
        }
        return yx_module_call(p, w, module, sig->name, args, sig->argc, yx_module_wasm_type(sig->result), sig->undefined != 0) &&
               (!sig->undefined || yx_module_guard(p, w));
    }
    if (n->op == YX_ME_READ) {
        const uint8_t arg = 0x7e;
        return yx_module_emit(p, n->args[0], w, depth + 1) &&
               yx_module_call(p, w, "yara_x::wasm", yx_module_read_import_name((uint8_t)n->integer), &arg, 1, n->integer >= YX_INTEGER_READ_COUNT ? 0x7c : 0x7e, true) &&
               yx_integer_emit_guard(w, 0x10, p->undefined_slot);
    }
    if (n->op == YX_ME_NOT) return yx_module_boolean(p, n->args[0], w, depth + 1) && yx_put_u8(w, 0x45);
    if (n->op == YX_ME_DEFINED) {
        if (yx_module_definite_value(p, n->args[0], 0)) return yx_module_defined_body(p, index, w, depth + 1);
        return yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && yx_module_defined_body(p, index, w, depth + 1) && yx_put_u8(w, 0x0b);
    }
    /* A result block catches its operands' undefined values (`i32.const 0;
     * br 1`), whatever catch encloses the block itself. */
    if (n->op == YX_ME_GROUP) {
        int saved = p->undefined_slot;
        p->undefined_slot = -1;
        if (p->boolean_scope) p->boolean_scope(p, true);
        bool ok = yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && yx_module_boolean(p, n->args[0], w, depth + 1) && yx_put_u8(w, 0x0b);
        if (p->boolean_scope) p->boolean_scope(p, false);
        p->undefined_slot = saved;
        return ok;
    }
    if (n->op == YX_ME_AND || n->op == YX_ME_OR) {
        int saved = p->undefined_slot;
        p->undefined_slot = -1;
        {
            const yx_module_node *left = &p->nodes[n->args[0]], *right = &p->nodes[n->args[1]];
            int neutral = n->op == YX_ME_AND ? 1 : 0, child = -1;
            if (yx_module_operand_truth(p, n->args[0]) == neutral) child = n->args[1];
            else if (yx_module_operand_truth(p, n->args[1]) == neutral) child = n->args[0];
            if (child >= 0 && !p->boolean_scope) {
                p->undefined_slot = saved;
                return false;
            }
            if (child >= 0) {
                p->boolean_scope(p, true);
                bool ok = yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && yx_module_boolean(p, child, w, depth + 1) && yx_put_u8(w, 0x0b);
                p->boolean_scope(p, false);
                p->undefined_slot = saved;
                return ok;
            }
        }
        if (p->boolean_scope) p->boolean_scope(p, true);
        /* Plain OR tests its last operand too (emit.rs::emit_or), unlike a
         * pattern-set `any`: mark it as the integer codec does, so the v12
         * lowering does not depend on the other conditions of the module. */
        bool ok =
            yx_put_u8(w, 2) && yx_put_u8(w, 0x7f) && yx_module_boolean_operands(p, n->args[0], n->op, w, true, depth + 1) &&
            (n->op != YX_ME_OR || (yx_put_u8(w, 2) && yx_put_u8(w, 0x7f))) && yx_module_boolean(p, n->args[1], w, depth + 1) &&
            (n->op != YX_ME_OR || (yx_put_u8(w, 0x0b) && yx_put_bytes(w, yx_integer_or_guard, sizeof(yx_integer_or_guard)) && yx_put_u8(w, 0x41) && yx_put_u8(w, 0))) &&
            yx_put_u8(w, 0x0b);
        if (p->boolean_scope) p->boolean_scope(p, false);
        p->undefined_slot = saved;
        return ok;
    }
    if (n->op == YX_ME_COMPARE) {
        const yx_module_node *a = &p->nodes[n->args[0]], *b = &p->nodes[n->args[1]];
        /* `matches` takes a regexp, which only an extension parses. */
        if (n->comparison == 13) return p->emit_primary && p->emit_primary(p, index, w, depth);
        if (a->type == 1 && b->type == 1) {
            if (n->comparison > 1) return false;
            return yx_module_boolean(p, n->args[0], w, depth + 1) && yx_put_u8(w, 0xad) && yx_module_boolean(p, n->args[1], w, depth + 1) && yx_put_u8(w, 0xad) &&
                   yx_put_u8(w, n->comparison ? 0x52 : 0x51);
        }
        if (a->type == 1 || b->type == 1) {
            const yx_module_node *constant = a->type == 1 ? b : a;
            int expression = a->type == 1 ? n->args[0] : n->args[1];
            if (n->comparison == 0 && constant->type == 3 && !(constant->constant && (constant->integer == 0 || constant->integer == 1))) {
                /* Only `==` takes a Boolean; 0 and 1 rewrite it (ast2ir.rs:585). Otherwise emit_operands
                 * promotes the Boolean (i64.extend_i32_u), which emit_int_comparison takes as non-negative. */
                return yx_module_emit(p, n->args[0], w, depth + 1) && (a->type != 1 || yx_put_u8(w, 0xad)) && yx_module_emit(p, n->args[1], w, depth + 1) &&
                       (b->type != 1 || yx_put_u8(w, 0xad)) &&
                       yx_integer_comparison_emit(w, 0x51, a->unsigned_value, b->unsigned_value, a->type == 1 || yx_module_non_negative(a),
                                                  b->type == 1 || yx_module_non_negative(b));
            }
            if (n->comparison > 1 || !constant->constant || constant->type != 3 || (constant->integer != 0 && constant->integer != 1)) return false;
            return yx_module_boolean(p, expression, w, depth + 1) && ((constant->integer != 0) != (n->comparison != 0) || yx_put_u8(w, 0x45));
        }
        if (a->type == 4 || b->type == 4) {
            if (a->type != 4 || b->type != 4 || n->comparison >= sizeof(yx_module_comparison_names) / sizeof(yx_module_comparison_names[0])) return false;
            return yx_module_emit(p, n->args[0], w, depth + 1) && yx_module_emit(p, n->args[1], w, depth + 1) &&
                   yx_module_call(p, w, "yara_x::wasm", yx_module_comparison_names[n->comparison], pair64, 2, 0x7f, false);
        }
        if (n->comparison > 5) return false;
        bool real = a->type == 2 || b->type == 2;
        static const uint8_t integer_ops[] = {0x51, 0x52, 0x53, 0x55, 0x57, 0x59};
        static const uint8_t float_ops[] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66};
        if (!real && yx_integer_comparison_mixed(a->unsigned_value, b->unsigned_value, yx_module_non_negative(a), yx_module_non_negative(b))) p->two_locals = true;
        return a->type >= 2 && a->type <= 3 && b->type >= 2 && b->type <= 3 && yx_module_emit(p, n->args[0], w, depth + 1) &&
               (!real || a->type == 2 || yx_put_u8(w, a->unsigned_value ? 0xba : 0xb9)) && yx_module_emit(p, n->args[1], w, depth + 1) &&
               (!real || b->type == 2 || yx_put_u8(w, b->unsigned_value ? 0xba : 0xb9)) &&
               (real ? yx_put_u8(w, float_ops[n->comparison])
                     : yx_integer_comparison_emit(w, integer_ops[n->comparison], a->unsigned_value, b->unsigned_value, yx_module_non_negative(a),
                                                  yx_module_non_negative(b)));
    }
    return false;
}

static bool yx_module_wasm_string(yx_writer *w, const char *text)
{
    size_t n = strlen(text);
    return yx_put_uleb(w, n) && yx_put_bytes(w, text, n);
}
static bool yx_module_type_equal(const yx_module_import *a, const yx_module_import *b)
{
    return a->argc == b->argc && a->resultc == b->resultc && !memcmp(a->args, b->args, a->argc) && !memcmp(a->results, b->results, a->resultc);
}
static int yx_module_type_compare(const yx_module_import *a, const yx_module_import *b)
{
    /* Wasmtime orders signatures lexically by its value-type variants,
     * I32, I64, F32, F64; result types follow the argument vector. */
    for (size_t i = 0; i < a->argc && i < b->argc; ++i)
        if (a->args[i] != b->args[i]) return a->args[i] > b->args[i] ? -1 : 1;
    if (a->argc != b->argc) return a->argc < b->argc ? -1 : 1;
    for (size_t i = 0; i < a->resultc && i < b->resultc; ++i)
        if (a->results[i] != b->results[i]) return a->results[i] > b->results[i] ? -1 : 1;
    return a->resultc < b->resultc ? -1 : a->resultc > b->resultc ? 1 : 0;
}
static bool yx_module_wasm(yx_module_program *p, int root, uint8_t **data, size_t *length)
{
    yx_writer expression = {0}, types = {0}, imports = {0}, body = {0}, code = {0}, wasm = {0}, wrapper = {0}, main_body = {0}, exports = {0};
    yx_module_import unique[YX_MODULE_IMPORTS + 3];
    size_t type_count = 3;
    uint8_t order[YX_MODULE_IMPORTS];
    static const uint8_t magic[] = {0, 0x61, 0x73, 0x6d, 1, 0, 0, 0};
    static const uint8_t functions[] = {3, 4, 3, 1, 0, 1};
    const uint8_t match_arg = 0x7f;
    memset(unique, 0, sizeof(unique));
    p->undefined_slot = -1;
    bool ok = yx_module_root_boolean(p, root, &expression);
    /* A shift wrote i64_tmp_b as local 1. walrus keeps the used locals only:
     * it is the only local unless something uses i64_tmp_a. */
    if (ok && p->shift) {
        if (p->filesize || p->divisor || p->two_locals) p->two_locals = true;
        else ok = yx_module_shift_wide_locals(expression.data, expression.used, -1);
    }
    int match = ok ? yx_module_import_add(p, "yara_x::wasm", "rule_match@rule_id:i@", &match_arg, 1, 0, false) : -1;
    if (p->no_match && yx_module_import_add(p, "yara_x::wasm", "rule_no_match@rule_id:i@", &match_arg, 1, 0, false) < 0) ok = false;
    if (!ok || match < 0 || p->import_count > YX_MODULE_IMPORTS) {
        ok = false;
        goto done;
    }
    unique[1].resultc = 1;
    unique[1].results[0] = 0x7f;
    unique[2].argc = 1;
    unique[2].args[0] = 0x7f;
    for (size_t i = 0; i < p->import_count; ++i) {
        size_t type;
        for (type = 0; type < type_count; ++type)
            if (yx_module_type_equal(&p->imports[i], &unique[type])) break;
        if (type == type_count) unique[type_count++] = p->imports[i];
        order[i] = (uint8_t)i;
    }
    for (size_t i = 1; i < type_count; ++i) {
        yx_module_import item = unique[i];
        size_t j = i;
        while (j && yx_module_type_compare(&unique[j - 1], &item) > 0) {
            unique[j] = unique[j - 1];
            --j;
        }
        unique[j] = item;
    }
    for (size_t i = 0; i < p->import_count; ++i)
        for (size_t type = 0; type < type_count; ++type)
            if (yx_module_type_equal(&p->imports[i], &unique[type])) {
                p->imports[i].type = (uint8_t)type;
                break;
            }
    for (size_t i = 1; i < p->import_count; ++i) {
        uint8_t item = order[i];
        size_t j = i;
        while (j && p->imports[order[j - 1]].rank > p->imports[item].rank) {
            order[j] = order[j - 1];
            --j;
        }
        order[j] = item;
    }
    for (size_t i = 0; i < p->import_count; ++i) p->imports[order[i]].id = (uint8_t)i;
    for (size_t i = 0; i < p->call_count; ++i) {
        size_t at = p->calls[i];
        if (at >= expression.used || expression.data[at] >= p->import_count) {
            ok = false;
            goto done;
        }
        expression.data[at] = p->imports[expression.data[at]].id;
    }
    ok = yx_put_uleb(&types, type_count);
    for (size_t i = 0; ok && i < type_count; ++i)
        ok = yx_put_u8(&types, 0x60) && yx_put_uleb(&types, unique[i].argc) && yx_put_bytes(&types, unique[i].args, unique[i].argc) &&
             yx_put_uleb(&types, unique[i].resultc) && yx_put_bytes(&types, unique[i].results, unique[i].resultc);
    ok = ok && yx_put_uleb(&imports, p->import_count + (p->filesize ? 1 : 0) + (p->memory ? 1 : 0));
    for (size_t i = 0; ok && i < p->import_count; ++i) {
        const yx_module_import *entry = &p->imports[order[i]];
        ok = yx_module_wasm_string(&imports, entry->module) && yx_module_wasm_string(&imports, entry->name) && yx_put_u8(&imports, 0) &&
             yx_put_uleb(&imports, entry->type);
    }
    if (ok && p->filesize)
        ok = yx_module_wasm_string(&imports, "yara_x") && yx_module_wasm_string(&imports, "filesize") && yx_put_u8(&imports, 3) && yx_put_u8(&imports, 0x7e) &&
             yx_put_u8(&imports, 1);
    if (ok && p->memory)
        ok = yx_module_wasm_string(&imports, "yara_x") && yx_module_wasm_string(&imports, "main_memory") && yx_put_u8(&imports, 2) && yx_put_u8(&imports, 0) &&
             yx_put_u8(&imports, 1);
    if (ok) {
        static const uint8_t suffix[] = {0x0b, 0x45, 0x04, 0x40, 0x05, 0x41, 0x00, 0x10};
        static const uint8_t tail[] = {0x0b, 0x41, 0x00, 0x0b};
        ok = yx_put_u8(&body, p->filesize || p->divisor || p->two_locals || p->shift ? 1 : 0) &&
             (!(p->filesize || p->divisor || p->two_locals || p->shift) || (yx_put_u8(&body, p->two_locals ? 2 : 1) && yx_put_u8(&body, 0x7e))) && yx_put_u8(&body, 2) &&
             yx_put_u8(&body, 0x7f) && yx_put_bytes(&body, expression.data, expression.used) && yx_put_bytes(&body, suffix, sizeof(suffix)) &&
             yx_put_uleb(&body, p->imports[match].id) && yx_put_bytes(&body, tail, sizeof(tail)) && yx_put_u8(&code, 3) && yx_put_uleb(&code, body.used) &&
             yx_put_bytes(&code, body.data, body.used);
        ok = ok && yx_put_u8(&wrapper, 0) && yx_put_u8(&wrapper, 2) && yx_put_u8(&wrapper, 0x40) && yx_put_u8(&wrapper, 0x10) && yx_put_uleb(&wrapper, p->import_count) &&
             yx_put_u8(&wrapper, 0x0d) && yx_put_u8(&wrapper, 0) && yx_put_u8(&wrapper, 0x0b) && yx_put_u8(&wrapper, 0x0b) && yx_put_u8(&main_body, 0) &&
             yx_put_u8(&main_body, 0x10) && yx_put_uleb(&main_body, p->import_count + 1) && yx_put_u8(&main_body, 0x41) && yx_put_u8(&main_body, 0) &&
             yx_put_u8(&main_body, 0x0b) && yx_put_u8(&exports, 1) && yx_module_wasm_string(&exports, "main") && yx_put_u8(&exports, 0) &&
             yx_put_uleb(&exports, p->import_count + 2);
        ok = ok && yx_put_uleb(&code, wrapper.used) && yx_put_bytes(&code, wrapper.data, wrapper.used) && yx_put_uleb(&code, main_body.used) &&
             yx_put_bytes(&code, main_body.data, main_body.used) && yx_put_bytes(&wasm, magic, sizeof(magic)) && yx_put_u8(&wasm, 1) && yx_put_uleb(&wasm, types.used) &&
             yx_put_bytes(&wasm, types.data, types.used) && yx_put_u8(&wasm, 2) && yx_put_uleb(&wasm, imports.used) && yx_put_bytes(&wasm, imports.data, imports.used) &&
             yx_put_bytes(&wasm, functions, sizeof(functions)) && yx_append_wasm_section(&wasm, 7, &exports) && yx_put_u8(&wasm, 10) && yx_put_uleb(&wasm, code.used) &&
             yx_put_bytes(&wasm, code.data, code.used);
    }
done:
    free(wrapper.data);
    free(main_body.data);
    free(exports.data);
    free(expression.data);
    free(types.data);
    free(imports.data);
    free(body.data);
    free(code.data);
    if (!ok) {
        free(wasm.data);
        return false;
    }
    *data = wasm.data;
    *length = wasm.used;
    return true;
}

static yx_ser_result yx_encode_module_expression_profile(const YRX_RULES *rules, uint8_t profile, uint8_t **data, size_t *length)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    static const uint8_t empty_globals[] = {0, 0, 1, 0};
    if (!rules || rules->rule_count != 1 || !rules->rules || rules->global_count || rules->import_count > 1 || profile > 3) return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule = &rules->rules[0];
    const char *module = rules->import_count && rules->imports ? rules->imports[0] : NULL;
    if (rule->pattern_count || rule->is_global || rule->tag_count || rule->metadata_count || !rule->condition_text || !yx_valid_rule_name(rule->identifier))
        return YX_SER_UNSUPPORTED;
    const yx_archive_module_schema *schema = yx_archive_schema(module);
    if (rules->import_count && !schema) return YX_SER_UNSUPPORTED;
    yx_module_program *p = calloc(1, sizeof(*p));
    yx_writer out = {0};
    uint8_t *wasm = NULL;
    size_t wasm_length = 0, count = 0, capacity = 0, ignored = 0, namespace_id = 0, module_id = 0, rule_id = 0;
    const char **pool = NULL;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    if (!p) return YX_SER_NO_MEMORY;
    p->schema = schema;
    p->profile = profile;
    p->parser.at = (const unsigned char *)rule->condition_text;
    p->capi_import_order = !rules->archive_cli && profile == 0;
    yx_literal *regexes = NULL;
    size_t regex_count = 0, regex_capacity = 0;
    p->regexes = &regexes;
    p->regex_count = &regex_count;
    p->regex_capacity = &regex_capacity;
    p->shifts = true;
    int root = yx_module_parse(p, 1, 0);
    yx_bool_skip_space(&p->parser);
    if (root < 0 || *p->parser.at || p->failed) goto done;
    bool uses_module_or_string = false;
    for (size_t i = 0; i < p->count; ++i)
        if (p->nodes[i].op == YX_ME_LOOKUP || p->nodes[i].op == YX_ME_CALL || p->nodes[i].op == YX_ME_STRING) uses_module_or_string = true;
    if (!uses_module_or_string || !yx_module_wasm(p, root, &wasm, &wasm_length)) goto done;
    const char *namespace_name = rule->namespace_name ? rule->namespace_name : "default";
    if (!yx_intern_ident("default", &pool, &count, &capacity, &ignored) || !yx_intern_ident(namespace_name, &pool, &count, &capacity, &namespace_id) ||
        (module && !yx_intern_ident(module, &pool, &count, &capacity, &module_id)) || !yx_intern_ident(rule->identifier, &pool, &count, &capacity, &rule_id))
        goto memory;
    if (!yx_put_bytes(&out, magic, sizeof(magic)) || !yx_put_uint(&out, count)) goto memory;
    for (size_t i = 0; i < count; ++i)
        if (!yx_put_string(&out, pool[i])) goto memory;
    if (!yx_put_uint(&out, regex_count)) goto memory;
    for (size_t i = 0; i < regex_count; ++i)
        if (!yx_put_uint(&out, regexes[i].length) || !yx_put_bytes(&out, regexes[i].data, regexes[i].length)) goto memory;
    if (!yx_put_u8(&out, 0) || !yx_put_uint(&out, p->literal_count)) goto memory;
    for (size_t i = 0; i < p->literal_count; ++i)
        if (!yx_put_uint(&out, p->literals[i].length) || !yx_put_bytes(&out, p->literals[i].data, p->literals[i].length)) goto memory;
    if (!yx_put_uint(&out, wasm_length) || !yx_put_bytes(&out, wasm, wasm_length) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, module ? 1 : 0) ||
        (module && !yx_put_uint(&out, module_id)) || !yx_put_u8(&out, 1) || !yx_put_u8(&out, namespace_id ? 2 : 0) || !yx_put_uint(&out, namespace_id) ||
        !yx_put_uint(&out, rule_id) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) ||
        !yx_put_u8(&out, rule->is_private ? 1 : 0))
        goto memory;
    for (size_t i = 0; i < 7; ++i)
        if (!yx_put_u8(&out, 0)) goto memory;
    const uint8_t *globals = schema ? schema->globals[profile] : empty_globals;
    size_t globals_length = schema ? schema->globals_length[profile] : sizeof(empty_globals);
    uint8_t ac[YX_AC_LENGTH];
    yx_make_empty_ac(ac);
    if (!yx_put_uint(&out, globals_length) || !yx_put_bytes(&out, globals, globals_length) || !yx_put_uint(&out, sizeof(ac)) || !yx_put_bytes(&out, ac, sizeof(ac)) ||
        !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0))
        goto memory;
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
    free(regexes);
    yx_module_program_free(p);
    return result;
}

static bool yx_module_decode_string(yx_module_program *p, int node)
{
    yx_module_node *n = &p->nodes[node];
    if (n->type == 4) return true;
    if (n->op != YX_ME_INT || n->integer < 0 || n->integer % 4 || (uint64_t)n->integer / 4 >= p->literal_count) return false;
    const yx_literal *literal = &p->literals[(uint64_t)n->integer / 4];
    n->bytes = malloc(literal->length ? literal->length : 1);
    if (!n->bytes) {
        yx_walk_no_memory = true;
        return false;
    }
    if (literal->length) memcpy(n->bytes, literal->data, literal->length);
    n->length = literal->length;
    n->op = YX_ME_STRING;
    n->type = 4;
    return true;
}
/* A regexp argument: the RegexpId (`i32.const`) becomes the pool's text. */
static bool yx_module_decode_regex(yx_module_program *p, int node)
{
    yx_module_node *n = &p->nodes[node];
    if (n->op != YX_ME_BOOL || n->bytes || !p->regexes || n->integer < 0 || (uint64_t)n->integer >= *p->regex_count) return false;
    const yx_literal *text = &(*p->regexes)[n->integer];
    n->bytes = malloc(text->length ? text->length : 1);
    if (!n->bytes) {
        p->failed = true;
        yx_walk_no_memory = true;
        return false;
    }
    if (text->length) memcpy(n->bytes, text->data, text->length);
    n->length = text->length;
    n->op = YX_ME_REGEX;
    n->type = 5;
    n->constant = false;
    n->integer = 0;
    return true;
}
static bool yx_module_decode_header(yx_reader *r, yx_module_program *p, size_t *body_end)
{
    static const uint8_t sections[] = {1, 2, 3, 7, 10};
    if (r->length < 8 || memcmp(r->data, yx_constant_wasm, 8)) return false;
    r->at = 8;
    for (size_t section = 0; section < sizeof(sections); ++section) {
        uint8_t id;
        uint64_t length;
        if (!yx_get_u8(r, &id) || id != sections[section] || !yx_get_uleb(r, &length) || length > r->length - r->at) return false;
        size_t end = r->at + (size_t)length;
        if (id == 2) {
            uint64_t count;
            if (!yx_get_uleb(r, &count) || r->at > end || count > YX_MODULE_IMPORTS + 2) return false;
            for (uint64_t i = 0; i < count; ++i) {
                const uint8_t *module, *name;
                size_t module_length, name_length;
                uint8_t kind;
                uint64_t value;
                if (!yx_integer_wasm_name(r, end, &module, &module_length) || !yx_integer_wasm_name(r, end, &name, &name_length) || !yx_get_u8(r, &kind)) return false;
                if (kind == 0) {
                    if (p->import_count == YX_MODULE_IMPORTS || module_length >= 80 || name_length >= 160 || !yx_get_uleb(r, &value)) return false;
                    yx_module_import *entry = &p->imports[p->import_count++];
                    memcpy(entry->module, module, module_length);
                    entry->module[module_length] = 0;
                    memcpy(entry->name, name, name_length);
                    entry->name[name_length] = 0;
                } else if (kind == 3 && module_length == 6 && !memcmp(module, "yara_x", 6) && name_length == 8 && !memcmp(name, "filesize", 8)) {
                    uint8_t type, mutable;
                    if (p->filesize || !yx_get_u8(r, &type) || type != 0x7e || !yx_get_u8(r, &mutable) || mutable != 1) return false;
                    p->filesize = true;
                } else if (kind == 2 && module_length == 6 && !memcmp(module, "yara_x", 6) && name_length == 11 && !memcmp(name, "main_memory", 11)) {
                    uint8_t flags, minimum;
                    if (p->memory || !yx_get_u8(r, &flags) || flags || !yx_get_u8(r, &minimum) || minimum != 1) return false;
                    p->memory = true;
                } else return false;
            }
            if (r->at != end) return false;
        } else if (id == 10) {
            uint64_t count, size, locals, local_count;
            uint8_t type;
            if (!yx_get_uleb(r, &count) || count != (p->expected_functions ? p->expected_functions : 3) || !yx_get_uleb(r, &size) || r->at > end || size > end - r->at)
                return false;
            *body_end = r->at + (size_t)size;
            if (!yx_get_uleb(r, &locals) || r->at > *body_end || locals > 1) return false;
            if (locals && (!yx_get_uleb(r, &local_count) || local_count < 1 || local_count > 2 || !yx_get_u8(r, &type) || type != 0x7e)) return false;
            return yx_get_u8(r, &type) && type == 2 && yx_get_u8(r, &type) && type == 0x7f && r->at <= *body_end;
        }
        r->at = end;
    }
    return false;
}
static int yx_module_decode_lookup(yx_reader *r, size_t end, yx_module_program *p, int base)
{
    uint16_t indexes[16];
    size_t count = 0, first = 0;
    if (base >= 0) {
        const yx_archive_module_field *field = p->nodes[base].field;
        if (!field || field->depth >= 16) return -1;
        first = count = field->depth;
        memcpy(indexes, field->indexes, count * sizeof(*indexes));
    }
    while (r->at < end && r->data[r->at] == 0x41) {
        size_t start = r->at;
        uint8_t marker;
        int64_t position, value;
        uint64_t alignment, offset;
        ++r->at;
        if (!yx_get_sleb_i64(r, &position) || !yx_get_u8(r, &marker)) return -1;
        if (marker == 0x10) {
            uint64_t function;
            if (position != (int64_t)(count - first) || count == first || !yx_get_uleb(r, &function) || function >= p->import_count) return -1;
            const char *name = p->imports[function].name;
            if (strcmp(p->imports[function].module, "yara_x::wasm") || strncmp(name, "lookup_", 7)) return -1;
            const yx_archive_module_field *field = NULL;
            if (!p->schema) return -1;
            for (size_t i = 0; i < p->schema->field_count; ++i)
                if (p->schema->fields[i].depth == count && !memcmp(p->schema->fields[i].indexes, indexes, count * sizeof(*indexes))) {
                    field = &p->schema->fields[i];
                    break;
                }
            if (!field) return -1;
            if (field->kind <= 4 && !yx_integer_wasm_guard(r, end, 0x10, p->undefined_slot)) return -1;
            int node = yx_module_node_new(p, base < 0 ? YX_ME_LOOKUP : YX_ME_MEMBER, field->kind);
            if (node >= 0) {
                p->nodes[node].field = field;
                p->nodes[node].args[0] = base;
                yx_module_field_typing(p, node);
            }
            return node;
        }
        if (marker != 0x41 || count == 16 || position != (int64_t)((count - first) * 4) || !yx_get_sleb_i64(r, &value) || value < 0 || value > UINT16_MAX ||
            !yx_get_u8(r, &marker) || marker != 0x36 || !yx_get_uleb(r, &alignment) || alignment != 2 || !yx_get_uleb(r, &offset) || offset != 16640 || r->at > end ||
            r->at <= start)
            return -1;
        indexes[count++] = (uint16_t)value;
    }
    return -1;
}
static int yx_module_decode_block(yx_reader *r, size_t end, yx_module_program *p, unsigned depth);
static int yx_module_decode_loop(yx_reader *r, size_t end, yx_module_program *p, unsigned depth)
{
    int64_t address;
    if (!p->memory || !yx_get_sleb_i64(r, &address) || address < 32 || address > (YX_ARCHIVE_MAX_VARS - 3) * 8 || address % 8) return -1;
    int64_t slot = address / 8 - 4;
    size_t saved_count = p->count, saved_guards = p->decoded_guards;
    int array = yx_module_decode_block(r, end, p, depth + 1);
    const yx_archive_module_map *map = NULL;
    if (array >= 0 && (p->nodes[array].op == YX_ME_LOOKUP || p->nodes[array].op == YX_ME_VARIABLE || p->nodes[array].op == YX_ME_MEMBER) && p->nodes[array].type == 8) {
        map = yx_module_map_types(p->nodes[array].field);
        if (!yx_module_map_by_index_name(map)) goto fail;
    } else if (array < 0 || (p->nodes[array].op != YX_ME_LOOKUP && p->nodes[array].op != YX_ME_MEMBER) || p->nodes[array].type != 7 || !p->nodes[array].field ||
               p->nodes[array].field->element > 4)
        goto fail;
    static const uint8_t types[] = {3, 2, 1, 4, 6};
    uint8_t type = map ? map->value : types[p->nodes[array].field->element];
    /* A body has a void catch block or a result block, depending on whether
     * it can be undefined. */
    bool forms = true, catching = false, matched = false;
    size_t prefix_start = r->at, prefix_count = p->count;
    /* The quantity of an expression or percentage quantifier, where
     * yx_module_loop_quantity writes it. */
    uint8_t counted = 0;
    int quantity = -1;
    for (unsigned form = 0; form < (forms ? 2u : 1u) && !matched; ++form) {
        yx_writer expected = {0};
        r->at = prefix_start;
        catching = form != 0;
        p->loop_kind = 0;
        counted = 0;
        quantity = -1;
        matched = yx_module_store_value(&expected, 3) &&
                  (map ? yx_module_map_loop_prefix(p, &expected, slot, map, catching) : yx_module_loop_prefix(p, &expected, slot, type, catching)) &&
                  p->loop_split <= expected.used && yx_integer_wasm_bytes(r, end, expected.data, p->loop_split);
        if (matched) {
            size_t split = p->loop_split;
            if (!yx_module_quantity_decode(r, end, p, depth, slot, slot + 2, slot + 3, &counted, &quantity)) counted = 0;
            matched = !p->failed && yx_integer_wasm_bytes(r, end, expected.data + split, expected.used - split);
        }
        free(expected.data);
        if (!matched) {
            for (size_t i = prefix_count; i < p->count; ++i) free(p->nodes[i].bytes);
            p->count = prefix_count;
            if (p->failed) goto fail;
        }
    }
    if (!matched) goto fail;
    p->slot_types[slot + 5] = map ? map->key : type;
    p->slot_defined[slot + 5] = true;
    p->slot_fields[slot + 5] = p->nodes[array].field;
    if (map) {
        p->slot_types[slot + 6] = type;
        p->slot_defined[slot + 6] = true;
        p->slot_fields[slot + 6] = p->nodes[array].field;
    }
    int saved = p->undefined_slot;
    p->undefined_slot = -1;
    int body = catching ? yx_module_loop_catch_decode(r, end, p, depth + 1) : yx_module_decode_block(r, end, p, depth + 1);
    p->undefined_slot = saved;
    if (body < 0) goto fail;
    for (uint8_t quantifier = counted ? 0xc7 : 0xc4; quantifier <= (counted ? 0xc7 : 0xc6); ++quantifier) {
        size_t start = r->at;
        yx_writer expected = {0};
        matched = (counted    ? yx_module_for_tail(counted, catching, &expected, slot, slot + 1, slot + 2, slot + 3, -1)
                   : catching ? yx_module_loop_catch_tail(&expected, slot, quantifier)
                              : yx_module_loop_tail(&expected, slot, quantifier)) &&
                  yx_integer_wasm_bytes(r, end, expected.data, expected.used);
        free(expected.data);
        if (matched) {
            int node = yx_module_node_new(p, YX_ME_LOOP, 1);
            if (node < 0) goto fail;
            p->nodes[node].integer = slot;
            p->nodes[node].comparison = counted == 4 ? 0xc8 : quantifier;
            p->nodes[node].args[0] = array;
            p->nodes[node].args[1] = body;
            p->nodes[node].args[2] = quantity;
            return node;
        }
        r->at = start;
    }
fail:
    for (size_t i = saved_count; i < p->count; ++i) free(p->nodes[i].bytes);
    p->count = saved_count;
    p->decoded_guards = saved_guards;
    return -1;
}
static int yx_module_decode_binding(yx_reader *r, size_t end, yx_module_program *p, int *slot, unsigned depth)
{
    uint8_t marker, alignment;
    uint64_t offset;
    int64_t address;
    if (!p->memory || !yx_get_u8(r, &marker) || marker != 0x41 || !yx_get_sleb_i64(r, &address) || address < 0 || address >= YX_ARCHIVE_MAX_VARS * 8 || address % 8)
        return -1;
    *slot = (int)(address / 8);
    int saved = p->undefined_slot;
    p->undefined_slot = *slot;
    int value = yx_module_decode_block(r, end, p, depth + 1);
    p->undefined_slot = saved;
    if (value < 0) return -1;
    uint8_t type = p->nodes[value].type;
    if (!yx_get_u8(r, &marker) ||
        marker != (type == 1   ? 0x36
                   : type == 2 ? 0x39
                               : 0x37) ||
        !yx_get_u8(r, &alignment) || alignment != (type == 1 ? 2 : 3) || !yx_get_uleb(r, &offset) || offset != 256)
        return -1;
    yx_writer clear = {0};
    bool valid = yx_integer_clear_variable(&clear, *slot) && yx_put_u8(&clear, 0x0b) && yx_integer_wasm_bytes(r, end, clear.data, clear.used);
    free(clear.data);
    if (!valid) return -1;
    p->slot_types[*slot] = type;
    p->slot_unsigned[*slot] = p->nodes[value].unsigned_value;
    p->slot_integer_kinds[*slot] = p->nodes[value].integer_kind;
    p->slot_values[*slot] = value + 1;
    p->slot_uses[*slot] = 0;
    p->slot_open[*slot] = true;
    p->slot_fields[*slot] = p->nodes[value].field;
    return value;
}
/* The innermost `with` slot in scope whose value is the literal with this
 * RuntimeString (still an integer when decoded, or already a string), and
 * that the body never loads: a string variable's uses are its literal. */
static int yx_module_literal_slot(const yx_module_program *p, int64_t runtime_string)
{
    for (int slot = YX_ARCHIVE_MAX_VARS; slot-- > 0;) {
        const yx_module_node *value;
        if (!p->slot_open[slot] || !p->slot_values[slot] || p->slot_uses[slot] || (size_t)p->slot_values[slot] > p->count) continue;
        value = &p->nodes[p->slot_values[slot] - 1];
        if ((value->op == YX_ME_INT && !value->unsigned_value) || value->op == YX_ME_STRING)
            if (value->integer == runtime_string) return slot;
    }
    return -1;
}
static int yx_module_bind_nodes(yx_module_program *p, int body, const int *values, const int *slots, size_t count)
{
    /* The statement's scope ends here. */
    for (size_t i = 0; i < count; ++i)
        if (slots[i] >= 0 && slots[i] < YX_ARCHIVE_MAX_VARS) p->slot_open[slots[i]] = false;
    while (count) {
        --count;
        int bind = yx_module_node_new(p, YX_ME_BIND, p->nodes[body].type);
        if (bind < 0) return -1;
        p->nodes[bind].args[0] = values[count];
        p->nodes[bind].args[1] = body;
        p->nodes[bind].integer = slots[count];
        body = bind;
    }
    return body;
}
static int yx_module_decode_block_inner(yx_reader *r, size_t end, yx_module_program *p, unsigned depth, int *stack, size_t stack_capacity, int *bindings, int *slots,
                                        size_t binding_capacity);
static int yx_module_decode_block(yx_reader *r, size_t end, yx_module_program *p, unsigned depth);
typedef struct {
    yx_reader *r;
    size_t end;
    yx_module_program *p;
    unsigned depth;
    int result;
} yx_module_decode_job;
static void yx_module_decode_thunk(void *data)
{
    yx_module_decode_job *j = data;
    j->result = yx_module_decode_block(j->r, j->end, j->p, j->depth);
}
static int yx_module_decode_block(yx_reader *r, size_t end, yx_module_program *p, unsigned depth)
{
    if (depth > YX_MODULE_DEPTH || end < r->at || end > r->length || end - r->at >= SIZE_MAX / sizeof(int)) return -1;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_decode_job job = {r, end, p, depth, -1};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_decode_thunk, &job) ? job.result : -1;
    }
    size_t capacity = end - r->at + 1;
    size_t bindings = capacity < YX_ARCHIVE_MAX_VARS ? capacity : YX_ARCHIVE_MAX_VARS;
    if (capacity > SIZE_MAX / sizeof(int) - bindings * 2) return -1;
    if (!depth && !yx_module_nodes_for_input(p, end - r->at)) return -1;
    int *stack = malloc((capacity + bindings * 2) * sizeof(*stack));
    if (!stack) {
        yx_walk_no_memory = true;
        return -1;
    }
    int result = yx_module_decode_block_inner(r, end, p, depth, stack, capacity, stack + capacity, stack + capacity + bindings, bindings);
    free(stack);
    return result;
}
/* The module-expression form of yx_integer_force_unsigned: marks the literal
 * that gives `index` the unsigned type an unsigned opcode asks for. */
static bool yx_module_force_unsigned(yx_module_program *p, int index, bool strict, unsigned depth);
typedef struct {
    yx_module_program *p;
    int index;
    bool strict;
    unsigned depth;
    bool result;
} yx_module_unsigned_job;
static void yx_module_unsigned_thunk(void *data)
{
    yx_module_unsigned_job *j = data;
    j->result = yx_module_force_unsigned(j->p, j->index, j->strict, j->depth);
}
static bool yx_module_force_unsigned(yx_module_program *p, int index, bool strict, unsigned depth)
{
    yx_module_node *n;
    if (index < 0 || (size_t)index >= p->count || depth > YX_MODULE_DEPTH) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_unsigned_job job = {p, index, strict, depth, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_unsigned_thunk, &job) && job.result;
    }
    n = &p->nodes[index];
    if (n->type != 3) return false;
    if (n->unsigned_value) return true;
    if (n->op == YX_ME_INT) {
        if (strict && n->integer >= 0) return false;
        n->unsigned_value = true;
        return true;
    }
    if (n->op == YX_ME_VARIABLE) {
        int64_t slot = n->integer;
        /* See yx_integer_force_unsigned: a literal above INT64_MAX in the
         * declaration, from the variable's first use only. */
        if (!strict || slot < 0 || slot >= YX_ARCHIVE_MAX_VARS || !p->slot_values[slot] || p->slot_uses[slot] != 1 || (size_t)p->slot_values[slot] > p->count ||
            p->slot_types[slot] != 3 || !yx_module_force_unsigned(p, p->slot_values[slot] - 1, strict, depth + 1))
            return false;
        p->slot_unsigned[slot] = true;
        n->unsigned_value = true;
        return true;
    }
    if (n->constant || n->op != YX_ME_ARITH) return false;
    switch (n->comparison) {
        case 0x7c:
        case 0x7d:
        case 0x7e:
        case 0x83:
        case 0x84:
        case 0x85:
            if (!yx_module_force_unsigned(p, n->args[0], strict, depth + 1) && !yx_module_force_unsigned(p, n->args[1], strict, depth + 1)) return false;
            break;
        case 0x86:
            if (!yx_module_force_unsigned(p, n->args[0], strict, depth + 1)) return false;
            break;
        default: return false;
    }
    n->unsigned_value = true;
    return true;
}
static bool yx_module_make_unsigned(yx_module_program *p, int index)
{
    return yx_module_force_unsigned(p, index, true, 0) || yx_module_force_unsigned(p, index, false, 0);
}
static bool yx_module_make_either_unsigned(yx_module_program *p, int first, int second)
{
    if (p->nodes[first].unsigned_value || p->nodes[second].unsigned_value || yx_module_force_unsigned(p, first, true, 0) || yx_module_force_unsigned(p, second, true, 0))
        return true;
    /* Then an operand that is itself a literal, then a literal inside one. */
    if (p->nodes[first].op == YX_ME_INT) return yx_module_force_unsigned(p, first, false, 0);
    if (p->nodes[second].op == YX_ME_INT) return yx_module_force_unsigned(p, second, false, 0);
    return yx_module_force_unsigned(p, first, false, 0) || yx_module_force_unsigned(p, second, false, 0);
}
static bool yx_module_non_negative(const yx_module_node *node);
static int yx_module_decode_block_inner(yx_reader *r, size_t end, yx_module_program *p, unsigned depth, int *stack, size_t stack_capacity, int *bindings, int *slots,
                                        size_t binding_capacity)
{
    int joined = -1;
    size_t used = 0;
    uint8_t join_op = 0;
    size_t binding_count = 0, guards = p->decoded_guards;
    bool wrapped = false;
    if (depth > YX_MODULE_DEPTH) return -1;
    while (r->at < end) {
        size_t start = r->at;
        uint8_t marker;
        int node = -1;
        bool block_operand = false;
        if (p->decode_primary) {
            node = p->decode_primary(r, end, p, depth);
            if (node == -2) continue;
            if (node >= 0) {
                if (used == stack_capacity) return -1;
                wrapped = false;
                stack[used++] = node;
                continue;
            }
            if (r->at != start) return -1;
        }
        if (!yx_get_u8(r, &marker)) return -1;
        if (marker == 0x36 || marker == 0x37 || marker == 0x39) {
            r->at = start;
            return used == 1 && joined < 0 && !binding_count ? stack[0] : -1;
        }
        if (marker == 0x0b) {
            if (used != 1) return -1;
            int value = yx_module_bind_nodes(p, stack[0], bindings, slots, binding_count);
            if (value < 0 || joined < 0) return value;
            /* The plain-OR marker the writer appends after the last operand. */
            if (join_op == YX_ME_OR && !wrapped && !binding_count && p->nodes[joined].op == YX_ME_OR && p->nodes[value].op == YX_ME_BOOL && !p->nodes[value].integer)
                return joined;
            if (p->decode_set && !binding_count) {
                node = p->decode_set(p, join_op, joined, value, !wrapped, p->decoded_guards != guards);
                if (node >= 0) p->set_node = node + 1;
                if (node >= 0 || p->failed) return node;
            }
            node = yx_module_node_new(p, join_op, 1);
            if (node >= 0) {
                p->nodes[node].args[0] = joined;
                p->nodes[node].args[1] = value;
            }
            return node;
        }
        /* Defined initializers are stored directly, without a catch or bitmap
         * operation. The following typed store disambiguates a binding address
         * from an ordinary i32 operand. */
        if (marker == 0x41 && binding_count < binding_capacity && !used) {
            yx_reader probe = *r;
            int64_t address;
            if (yx_get_sleb_i64(&probe, &address) && address >= 0 && address < YX_ARCHIVE_MAX_VARS * 8 && !(address % 8) && probe.at < end) {
                uint8_t first = probe.data[probe.at];
                /* A pattern operand starts with the lazy search guard. */
                if (first == 0x41 || first == 0x42 || first == 0x44 || first == 0x23 || first == 0x10) {
                    size_t saved_count = p->count, saved_guards = p->decoded_guards;
                    int value_node = yx_module_decode_block(&probe, end, p, depth + 1);
                    yx_writer store = {0};
                    bool direct = value_node >= 0 && (p->nodes[value_node].type <= 4 || (p->nodes[value_node].type >= 6 && p->nodes[value_node].type <= 8)) &&
                                  yx_module_definite_value(p, value_node, 0) && yx_module_store_value(&store, p->nodes[value_node].type) &&
                                  yx_integer_wasm_bytes(&probe, end, store.data, store.used);
                    free(store.data);
                    if (direct && (p->nodes[value_node].type == 7 || p->nodes[value_node].type == 8)) {
                        /* A map or an array stored in a loop frame's item slot is followed
                         * by the loop's prefix (yx_module_map_loop_prefix),
                         * not by the body of a `with`. */
                        yx_writer prefix = {0};
                        bool loop = address >= 32 && yx_put_u8(&prefix, 2) && yx_put_u8(&prefix, 0x7f) && yx_put_u8(&prefix, 0x41) &&
                                    yx_put_sleb_i64(&prefix, address - 32) && yx_module_load_variable(&prefix, address / 8, 3) && prefix.used <= end - probe.at &&
                                    !memcmp(probe.data + probe.at, prefix.data, prefix.used);
                        free(prefix.data);
                        if (loop) direct = false;
                    }
                    if (direct) {
                        int slot = (int)(address / 8);
                        p->slot_types[slot] = p->nodes[value_node].type;
                        p->slot_defined[slot] = true;
                        p->slot_fields[slot] = p->nodes[value_node].field;
                        p->slot_unsigned[slot] = p->nodes[value_node].unsigned_value;
                        p->slot_integer_kinds[slot] = p->nodes[value_node].integer_kind;
                        p->slot_values[slot] = value_node + 1;
                        p->slot_uses[slot] = 0;
                        p->slot_open[slot] = true;
                        slots[binding_count] = slot;
                        bindings[binding_count++] = value_node;
                        *r = probe;
                        continue;
                    }
                    for (size_t i = saved_count; i < p->count; ++i) free(p->nodes[i].bytes);
                    p->count = saved_count;
                    p->decoded_guards = saved_guards;
                    if (p->failed) return -1;
                }
            }
        }
        int variable_slot = marker == 0x41 ? yx_integer_wasm_variable_slot(r, start) : -1;
        int defined_slot = -1;
        if (marker == 0x41 && variable_slot < 0) {
            yx_reader probe = *r;
            int64_t address;
            if (yx_get_sleb_i64(&probe, &address) && address >= 0 && address < YX_ARCHIVE_MAX_VARS * 8 && !(address % 8) && p->slot_types[address / 8] &&
                p->slot_defined[address / 8] && probe.at < end &&
                probe.data[probe.at] == (p->slot_types[address / 8] == 1   ? 0x28
                                         : p->slot_types[address / 8] == 2 ? 0x2b
                                                                           : 0x29))
                defined_slot = (int)(address / 8);
        }
        if (variable_slot >= 0 || defined_slot >= 0) {
            bool matched = false;
            int expected_slot = variable_slot >= 0 ? variable_slot : defined_slot;
            for (int slot = expected_slot; slot == expected_slot && slot < YX_ARCHIVE_MAX_VARS; ++slot) {
                if (!p->slot_types[slot]) continue;
                yx_writer expected = {0};
                r->at = start;
                matched = (defined_slot >= 0 ? yx_module_load_variable(&expected, slot, p->slot_types[slot])
                                             : yx_module_variable(&expected, slot, p->slot_types[slot], p->undefined_slot)) &&
                          yx_integer_wasm_bytes(r, end, expected.data, expected.used);
                free(expected.data);
                if (!matched) continue;
                node = yx_module_node_new(p, YX_ME_VARIABLE, p->slot_types[slot]);
                if (node >= 0) {
                    p->nodes[node].integer = slot;
                    p->nodes[node].field = p->slot_fields[slot];
                    p->nodes[node].unsigned_value = p->slot_unsigned[slot];
                    p->nodes[node].integer_kind = p->slot_values[slot] ? p->slot_integer_kinds[slot] : 0;
                    if (p->slot_uses[slot] < UINT8_MAX) ++p->slot_uses[slot];
                }
                break;
            }
            if (!matched) return -1;
        } else if (marker == 0x41 && used && p->nodes[stack[used - 1]].type == 6) {
            r->at = start;
            node = yx_module_decode_lookup(r, end, p, stack[--used]);
        } else if (marker == 0x41 && r->at < end && ((!p->decode_call && r->data[r->at] != 0 && r->data[r->at] != 1) || (p->decode_call && r->data[r->at] >= 32)) &&
                   (node = yx_module_decode_loop(r, end, p, depth + 1)) >= 0) {
            /* A loop prefix. In calls, an argument such as a pattern id of
             * 32 or more starts the same way; it is read as a constant. */
        } else if (marker == 0x41 && p->decode_call && (r->at = start + 1, true) && r->at < end && r->data[r->at] >= 32 && !p->failed) {
            int64_t value;
            if (!yx_get_sleb_i64(r, &value)) return -1;
            node = yx_module_node_new(p, YX_ME_BOOL, 1);
            if (node >= 0) p->nodes[node].integer = value;
        } else if (marker == 0x41 || marker == 0x42) {
            int64_t value;
            /* An attempted loop prefix moved the reader. A larger `i32.const` is
             * the RegexpId of a function's argument (yx_module_decode_regex). */
            r->at = start + 1;
            if (!yx_get_sleb_i64(r, &value) ||
                (marker == 0x41 && !p->decode_call && value != 0 && value != 1 && !(p->regexes && value > 0 && (uint64_t)value < *p->regex_count)))
                return -1;
            if (marker == 0x42 && value == -1 && p->schema && p->memory && r->at < end && r->data[r->at] == 0x41) node = yx_module_decode_lookup(r, end, p, -1);
            else {
                node = yx_module_node_new(p, marker == 0x41 ? YX_ME_BOOL : YX_ME_INT, marker == 0x41 ? 1 : 3);
                if (node >= 0) p->nodes[node].integer = value;
            }
        } else if (marker == 0x44) {
            double value;
            if (!yx_get_float(r, &value) || !yx_float_representable(value)) return -1;
            node = yx_module_node_new(p, YX_ME_FLOAT, 2);
            if (node >= 0) p->nodes[node].real = value;
        } else if (marker == 0x23) {
            r->at = start;
            yx_writer guard = {0};
            bool valid = p->filesize && yx_module_filesize_guard(p, &guard) && yx_integer_wasm_bytes(r, end, guard.data, guard.used);
            free(guard.data);
            if (!valid) return -1;
            node = yx_module_node_new(p, YX_ME_FILESIZE, 3);
        } else if (marker == 0xb9 || marker == 0xba) {
            if (!used || p->nodes[stack[used - 1]].type != 3) return -1;
            if (marker == 0xba && !yx_module_make_unsigned(p, stack[used - 1])) return -1;
            continue;
        } else if (marker == 0xad) {
            if (!used || p->nodes[stack[used - 1]].type != 1) return -1;
            continue;
        } else if (marker == 0x02) {
            if (!yx_get_u8(r, &marker)) return -1;
            if (marker == 0x40) {
                if (binding_count == binding_capacity || used) return -1;
                node = yx_module_decode_binding(r, end, p, &slots[binding_count], depth + 1);
                if (node < 0) return -1;
                bindings[binding_count++] = node;
                continue;
            }
            if (marker != 0x7f) return -1;
            {
                int saved = p->undefined_slot;
                p->undefined_slot = -1;
                node = yx_module_decode_block(r, end, p, depth + 1);
                p->undefined_slot = saved;
            }
            block_operand = true;
            if (node >= 0 && node + 1 != p->set_node && p->boolean_scope && join_op != YX_ME_OR && p->nodes[node].op != YX_ME_AND && p->nodes[node].op != YX_ME_OR &&
                p->nodes[node].op != YX_ME_DEFINED &&
                !(sizeof(yx_integer_or_guard) <= end - r->at && !memcmp(r->data + r->at, yx_integer_or_guard, sizeof(yx_integer_or_guard)))) {
                int group = yx_module_node_new(p, YX_ME_GROUP, 1);
                if (group < 0) return -1;
                p->nodes[group].args[0] = node;
                node = group;
            }
        } else if (marker == 0x04) {
            uint8_t op;
            const uint8_t *guard;
            size_t length;
            if (used != 1) return -1;
            stack[0] = yx_module_bind_nodes(p, stack[0], bindings, slots, binding_count);
            if (stack[0] < 0) return -1;
            binding_count = 0;
            if (sizeof(yx_integer_and_guard) <= end - start && !memcmp(r->data + start, yx_integer_and_guard, sizeof(yx_integer_and_guard))) {
                op = YX_ME_AND;
                guard = yx_integer_and_guard;
                length = sizeof(yx_integer_and_guard);
            } else {
                op = YX_ME_OR;
                guard = yx_integer_or_guard;
                length = sizeof(yx_integer_or_guard);
            }
            r->at = start;
            if ((join_op && join_op != op) || !yx_integer_wasm_bytes(r, end, guard, length)) return -1;
            /* A first operand that is a block of the same operator is an
             * operand of its own: the AST's n-ary operation had a constant
             * before it that IR::and / IR::or dropped. Restore it, as the
             * source `true and (A and B) and C` parses. */
            if (joined < 0 && p->nodes[stack[0]].op == op) {
                int neutral = yx_module_node_new(p, YX_ME_BOOL, 1);
                if (neutral < 0) return -1;
                p->nodes[neutral].integer = op == YX_ME_AND;
                p->nodes[neutral].constant = true;
                node = yx_module_node_new(p, op, 1);
                if (node < 0) return -1;
                p->nodes[node].args[0] = neutral;
                p->nodes[node].args[1] = stack[0];
                stack[0] = node;
            }
            if (joined < 0) joined = stack[0];
            else {
                node = yx_module_node_new(p, op, 1);
                if (node < 0) return -1;
                p->nodes[node].args[0] = joined;
                p->nodes[node].args[1] = stack[0];
                joined = node;
            }
            join_op = op;
            used = 0;
            continue;
        } else if (marker == 0x45) {
            if (!used) return -1;
            node = yx_module_node_new(p, YX_ME_NOT, 1);
            if (node >= 0) p->nodes[node].args[0] = stack[--used];
        } else if (marker == 0x1a) {
            /* emit_defined: the operand's value is dropped for `i32.const 1`,
             * which ends the block that catches the operand's undefined (if
             * it can be undefined at all). */
            uint8_t constant, value;
            if (!used || !yx_get_u8(r, &constant) || constant != 0x41 || !yx_get_u8(r, &value) || value != 1) return -1;
            node = yx_module_node_new(p, YX_ME_DEFINED, 1);
            if (node >= 0) p->nodes[node].args[0] = stack[--used];
        } else if (marker == 0x21 && used >= 2 && end - start >= 4 && !memcmp(r->data + start, "\x21\x01\x21\x00", 4)) {
            yx_writer expected = {0};
            r->at = start;
            bool matched = yx_integer_signed_division_emit(&expected, p->undefined_slot) && yx_integer_wasm_bytes(r, end, expected.data, expected.used);
            free(expected.data);
            if (!matched) return -1;
            int right = stack[--used], left = stack[--used];
            node = yx_module_arithmetic_node(p, 0x7f, left, right);
        } else if (marker == 0x21 && used >= 2 && end - start >= 6 && !memcmp(r->data + start, "\x21\x01\x22\x00\x20\x01", 6)) {
            static const uint8_t ops[] = {0x51, 0x52, 0x53, 0x55, 0x57, 0x59};
            yx_module_node *left = &p->nodes[stack[used - 2]], *right = &p->nodes[stack[used - 1]];
            bool matched = false;
            uint8_t comparison = 0;
            int m;
            for (m = 0; m < 2 && !matched; ++m) {
                bool l_uns = (m == 0), r_uns = (m == 1);
                if ((l_uns && right->unsigned_value) || (r_uns && left->unsigned_value)) continue;
                for (comparison = 0; comparison < 6; ++comparison) {
                    yx_writer expected = {0};
                    r->at = start;
                    matched = yx_integer_comparison_emit(&expected, ops[comparison], l_uns, r_uns, l_uns || yx_module_non_negative(left),
                                                         r_uns || yx_module_non_negative(right)) &&
                              yx_integer_wasm_bytes(r, end, expected.data, expected.used);
                    free(expected.data);
                    if (matched) {
                        if (!yx_module_make_unsigned(p, l_uns ? stack[used - 2] : stack[used - 1])) return -1;
                        break;
                    }
                }
            }
            if (!matched) return -1;
            node = yx_module_node_new(p, YX_ME_COMPARE, 1);
            if (node >= 0) {
                p->nodes[node].args[1] = stack[--used];
                p->nodes[node].args[0] = stack[--used];
                p->nodes[node].comparison = comparison;
            }
        } else if (marker == 0x9a) {
            if (!used || p->nodes[stack[used - 1]].type != 2) return -1;
            node = yx_module_node_new(p, YX_ME_NEGATE, 2);
            if (node >= 0) p->nodes[node].args[0] = stack[--used];
        } else if (marker == 0x22 && used >= 2 && end - start >= 3 && r->data[start + 1] <= 1 && r->data[start + 2] >= 0x86 && r->data[start + 2] <= 0x88) {
            /* emit_shift_op, through either number of i64_tmp_b. */
            yx_module_node *left = &p->nodes[stack[used - 2]], *right = &p->nodes[stack[used - 1]];
            uint8_t operation = r->data[start + 2] == 0x86 ? 0x86 : 0x87;
            /* `i64.shr_u` and the amount's `i64.lt_u` tell that a literal is unsigned. */
            if (r->data[start + 2] == 0x88 && !yx_module_make_unsigned(p, stack[used - 2])) return -1;
            if (end - start >= 11 && r->data[start + 10] == 0x54 && !yx_module_make_unsigned(p, stack[used - 1])) return -1;
            yx_writer expected = {0};
            r->at = start;
            bool matched = yx_integer_shift_v12_emit(&expected, operation, left->unsigned_value, right->unsigned_value, r->data[start + 1]) &&
                           yx_integer_wasm_bytes(r, end, expected.data, expected.used);
            free(expected.data);
            if (!matched) return -1;
            int shift = stack[--used], value = stack[--used];
            node = yx_module_arithmetic_node(p, operation, value, shift);
        } else if (marker == 0x22) {
            r->at = start;
            if (used < 2 || !yx_integer_wasm_guard(r, end, 0x22, p->undefined_slot) || !yx_get_u8(r, &marker) ||
                (marker != 0x7f && marker != 0x80 && marker != 0x81 && marker != 0x82))
                return -1;
            if (marker == 0x80 || marker == 0x82) {
                /* emit_div / emit_mod: the unsigned opcode when an operand is unsigned. */
                if (!yx_module_make_either_unsigned(p, stack[used - 2], stack[used - 1])) return -1;
                --marker;
            }
            int right = stack[--used], left = stack[--used];
            node = yx_module_arithmetic_node(p, marker, left, right);
        } else if ((marker >= 0x7c && marker <= 0x7e) || (marker >= 0x83 && marker <= 0x85) || (marker >= 0xa0 && marker <= 0xa3)) {
            if (used < 2) return -1;
            uint8_t operation = marker >= 0xa0 ? (uint8_t)(marker - 0xa0 + 0x7c) : marker;
            int right = stack[--used], left = stack[--used];
            node = yx_module_arithmetic_node(p, operation, left, right);
        } else if (marker == 0x46 || marker == 0x47 || (marker >= 0x51 && marker <= 0x5a) || (marker >= 0x61 && marker <= 0x66)) {
            static const uint8_t integer_ops[] = {0x51, 0x52, 0x53, 0x55, 0x57, 0x59};
            static const uint8_t float_ops[] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66};
            uint8_t comparison;
            if (marker >= 0x54 && marker <= 0x5a && !(marker & 1)) {
                /* emit_int_comparison's plain unsigned opcode: both operands
                 * unsigned, or one unsigned and the other one not negative. */
                if (used < 2) return -1;
                for (unsigned side = 0; side < 2; ++side) {
                    int operand = stack[used - 2 + side];
                    if (!p->nodes[operand].unsigned_value && !yx_module_non_negative(&p->nodes[operand]) && !yx_module_make_unsigned(p, operand)) return -1;
                }
                if (!yx_module_make_either_unsigned(p, stack[used - 1], stack[used - 2])) return -1;
                --marker;
            }
            for (comparison = 0; comparison < 6; ++comparison)
                if (integer_ops[comparison] == marker || float_ops[comparison] == marker) break;
            if (marker == 0x46 || marker == 0x47) comparison = (uint8_t)(marker - 0x46);
            if (used < 2 || comparison == 6) return -1;
            yx_module_node *left = &p->nodes[stack[used - 2]], *right = &p->nodes[stack[used - 1]];
            if (left->unsigned_value && right->op == YX_ME_INT && right->integer < 0) right->unsigned_value = true;
            if (right->unsigned_value && left->op == YX_ME_INT && left->integer < 0) left->unsigned_value = true;
            node = yx_module_node_new(p, YX_ME_COMPARE, 1);
            if (node >= 0) {
                p->nodes[node].args[1] = stack[--used];
                p->nodes[node].args[0] = stack[--used];
                p->nodes[node].comparison = comparison;
            }
        } else if (marker == 0x10) {
            uint64_t id;
            if (!yx_get_uleb(r, &id)) return -1;
            if (p->decode_call) {
                node = p->decode_call(r, end, p, id, stack, &used);
                if (node >= 0) {
                    if (used == stack_capacity) return -1;
                    wrapped = false;
                    stack[used++] = node;
                    continue;
                }
            }
            if (id >= p->import_count) return -1;
            const yx_module_import *entry = &p->imports[id];
            if (!strcmp(entry->module, "yara_x::wasm") && !strcmp(entry->name, "str_len@s:s@i")) {
                /* emit_bool_expr of a string: str_len(s) != 0. */
                if (!used || !yx_module_decode_string(p, stack[used - 1]) || end - r->at < 3 || memcmp(r->data + r->at, "\x42\x00\x52", 3)) return -1;
                r->at += 3;
                continue;
            }
            size_t comparison;
            for (comparison = 0; comparison < sizeof(yx_module_comparison_names) / sizeof(yx_module_comparison_names[0]); ++comparison)
                if (!strcmp(entry->name, yx_module_comparison_names[comparison])) break;
            if (!strcmp(entry->module, "yara_x::wasm") && comparison < sizeof(yx_module_comparison_names) / sizeof(yx_module_comparison_names[0])) {
                if (used < 2 || !yx_module_decode_string(p, stack[used - 1]) || !yx_module_decode_string(p, stack[used - 2])) return -1;
                node = yx_module_node_new(p, YX_ME_COMPARE, 1);
                if (node >= 0) {
                    p->nodes[node].args[1] = stack[--used];
                    p->nodes[node].args[0] = stack[--used];
                    p->nodes[node].comparison = (uint8_t)comparison;
                }
            } else if (!strcmp(entry->module, "yara_x::wasm") && (!strcmp(entry->name, "Array::len@array:i@i") || !strcmp(entry->name, "Map::len@map:i@i") ||
                                                                  !strcmp(entry->name, "RuntimeString::len@string:s@i"))) {
                /* RuntimeString::len of a literal: its RuntimeString as an
                 * i64 constant, the value of the `with` variable in scope
                 * that holds it (yx_module_literal_slot). */
                int literal_slot = -1;
                if (used && entry->name[0] == 'R' && p->nodes[stack[used - 1]].op == YX_ME_INT) {
                    literal_slot = yx_module_literal_slot(p, p->nodes[stack[used - 1]].integer);
                    if (literal_slot < 0 || !yx_module_decode_string(p, stack[used - 1]) || !yx_module_decode_string(p, p->slot_values[literal_slot] - 1)) return -1;
                }
                if (!used || p->nodes[stack[used - 1]].type != (entry->name[0] == 'A' ? 7 : entry->name[0] == 'M' ? 8 : 4)) return -1;
                node = yx_module_node_new(p, YX_ME_LENGTH, 3);
                if (node >= 0) {
                    p->nodes[node].args[0] = stack[--used];
                    p->nodes[node].integer = literal_slot + 1;
                }
            } else if (!strcmp(entry->module, "yara_x::wasm") && !strncmp(entry->name, "map_lookup_", 11) && strncmp(entry->name, "map_lookup_by_index_", 20)) {
                /* map_lookup_<key>_<value>(map, key): a lookup by key. */
                if (used < 2) return -1;
                int map = stack[used - 2];
                const yx_archive_module_field *field = p->nodes[map].field;
                const yx_archive_module_map *types = yx_module_map_types(field);
                const char *name = yx_module_map_lookup_name(types);
                if ((p->nodes[map].op != YX_ME_LOOKUP && p->nodes[map].op != YX_ME_MEMBER && p->nodes[map].op != YX_ME_VARIABLE) || !name || strcmp(entry->name, name) ||
                    (types->key == 4 ? !yx_module_decode_string(p, stack[used - 1]) : p->nodes[stack[used - 1]].type != 3) ||
                    !yx_integer_wasm_guard(r, end, 0x10, p->undefined_slot))
                    return -1;
                node = yx_module_node_new(p, YX_ME_INDEX, types->value);
                if (node >= 0) {
                    p->nodes[node].args[1] = stack[--used];
                    p->nodes[node].args[0] = stack[--used];
                    p->nodes[node].field = field;
                }
            } else if (!strcmp(entry->module, "yara_x::wasm") && !strncmp(entry->name, "array_indexing_", 15)) {
                if (used < 2) return -1;
                int array = stack[used - 2];
                const yx_archive_module_field *field = p->nodes[array].field;
                static const uint8_t types[] = {3, 2, 1, 4, 6};
                if ((p->nodes[array].op != YX_ME_LOOKUP && p->nodes[array].op != YX_ME_MEMBER && p->nodes[array].op != YX_ME_VARIABLE) || !field || field->kind != 7 ||
                    field->element > 4 || !yx_integer_wasm_guard(r, end, 0x10, p->undefined_slot))
                    return -1;
                node = yx_module_node_new(p, YX_ME_INDEX, types[field->element]);
                if (node >= 0) {
                    p->nodes[node].args[1] = stack[--used];
                    p->nodes[node].args[0] = stack[--used];
                    p->nodes[node].field = field;
                }
            } else {
                const yx_archive_module_signature *sig = NULL;
                if (p->schema)
                    for (size_t i = 0; i < p->schema->signature_count; ++i)
                        if (!strcmp(entry->name, p->schema->signatures[i].name)) {
                            sig = &p->schema->signatures[i];
                            break;
                        }
                if (sig) {
                    if (used < sig->argc || (sig->undefined && !yx_integer_wasm_guard(r, end, 0x10, p->undefined_slot))) return -1;
                    for (size_t i = 0; i < sig->argc; ++i)
                        if ((sig->args[i] == 4 && !yx_module_decode_string(p, stack[used - sig->argc + i])) ||
                            (sig->args[i] == 5 && !yx_module_decode_regex(p, stack[used - sig->argc + i])))
                            return -1;
                    node = yx_module_node_new(p, YX_ME_CALL, sig->result);
                    if (node >= 0) {
                        p->nodes[node].signature = sig;
                        p->nodes[node].argc = sig->argc;
                        used -= sig->argc;
                        memcpy(p->nodes[node].args, stack + used, sig->argc * sizeof(*stack));
                    }
                } else {
                    uint8_t type;
                    for (type = 0; type < YX_MODULE_READ_COUNT; ++type)
                        if (!strcmp(entry->name, yx_module_read_import_name(type))) break;
                    if (type == YX_MODULE_READ_COUNT || !used || strcmp(entry->module, "yara_x::wasm") || !yx_integer_wasm_guard(r, end, 0x10, p->undefined_slot))
                        return -1;
                    node = yx_module_node_new(p, YX_ME_READ, type >= YX_INTEGER_READ_COUNT ? 2 : 3);
                    if (node >= 0) {
                        p->nodes[node].integer = type;
                        p->nodes[node].args[0] = stack[--used];
                        p->nodes[node].unsigned_value = type == 6 || type == 11;
                    }
                }
            }
        } else return -1;
        if (node < 0 || used == stack_capacity || r->at > end) return -1;
        wrapped = block_operand;
        stack[used++] = node;
    }
    return -1;
}
static bool yx_module_print(const yx_module_program *p, int index, yx_writer *out, unsigned depth);
typedef struct {
    const yx_module_program *p;
    int index;
    yx_writer *out;
    unsigned depth;
    bool result;
} yx_module_print_job;
static void yx_module_print_thunk(void *data)
{
    yx_module_print_job *j = data;
    j->result = yx_module_print(j->p, j->index, j->out, j->depth);
}
static bool yx_module_print(const yx_module_program *p, int index, yx_writer *out, unsigned depth)
{
    if (depth > YX_MODULE_DEPTH || index < 0 || (size_t)index >= p->count) return false;
    if (YX_MODULE_DEEP(depth)) {
        yx_module_print_job job = {p, index, out, depth, false};
        return yx_module_deep_walk(YX_MODULE_DEPTH, yx_module_print_thunk, &job) && job.result;
    }
    const yx_module_node *n = &p->nodes[index];
    if (n->op >= 32) return p->print_primary && p->print_primary(p, index, out, depth);
    char number[80];
    const char *text = NULL;
    if (n->op == YX_ME_INT) {
        /* An unsigned constant that fits i64 has no literal of its own: the
         * conjunction folds to it and keeps the type. */
        if (n->unsigned_value) {
            snprintf(number, sizeof(number), n->integer < 0 ? "%" PRIu64 : "(18446744073709551615 & %" PRIu64 ")", (uint64_t)n->integer);
            text = number;
        } else if (n->integer == INT64_MIN) text = "(-9223372036854775807 - 1)";
        else {
            snprintf(number, sizeof(number), "%" PRId64, n->integer);
            text = number;
        }
    } else if (n->op == YX_ME_FLOAT) {
        char real[YX_FLOAT_SOURCE_TEXT];
        return yx_float_source_text(n->real, real) && yx_put_bytes(out, real, strlen(real));
    } else if (n->op == YX_ME_BOOL) text = n->integer ? "true" : "false";
    else if (n->op == YX_ME_VARIABLE) {
        snprintf(number, sizeof(number), "v%" PRId64, n->integer);
        text = number;
    } else if (n->op == YX_ME_FILESIZE) text = "filesize";
    else if (n->op == YX_ME_LOOKUP) text = n->field->path;
    if (text) return yx_put_bytes(out, text, strlen(text));
    if (n->op == YX_ME_BIND) {
        /* A chain of declarations prints as one `with`: the same variables
         * in the same slots, without nesting as deep as the chain. */
        int body = index;
        for (bool first = true; p->nodes[body].op == YX_ME_BIND; first = false) {
            n = &p->nodes[body];
            snprintf(number, sizeof(number), first ? "with v%" PRId64 "=" : ", v%" PRId64 "=", n->integer);
            if (n->args[1] < 0 || (size_t)n->args[1] >= p->count || !yx_put_bytes(out, number, strlen(number)) || !yx_module_print(p, n->args[0], out, depth + 1))
                return false;
            body = n->args[1];
        }
        return yx_put_bytes(out, ": (", 3) && yx_module_print(p, body, out, depth + 1) && yx_put_u8(out, ')');
    }
    if (n->op == YX_ME_LOOP) {
        const yx_archive_module_field *field = p->nodes[n->args[0]].field;
        bool counted = n->comparison == 0xc7 || n->comparison == 0xc8;
        if (counted) {
            bool plain = p->nodes[n->args[2]].op == YX_ME_INT;
            if (!yx_put_bytes(out, "for ", 4) || (!plain && !yx_put_u8(out, '(')) || !yx_module_print(p, n->args[2], out, depth + 1) ||
                (!plain && !yx_put_u8(out, ')')) || (n->comparison == 0xc8 && !yx_put_u8(out, '%')))
                return false;
        }
        if (field && field->kind == 8)
            snprintf(number, sizeof(number), "%s v%" PRId64 ", v%" PRId64 " in ",
                     counted                 ? ""
                     : n->comparison == 0xc4 ? "for any"
                     : n->comparison == 0xc5 ? "for all"
                                             : "for none",
                     n->integer + 5, n->integer + 6);
        else
            snprintf(number, sizeof(number), "%s v%" PRId64 " in ",
                     counted                 ? ""
                     : n->comparison == 0xc4 ? "for any"
                     : n->comparison == 0xc5 ? "for all"
                                             : "for none",
                     n->integer + 5);
        return yx_put_bytes(out, number, strlen(number)) && yx_module_print(p, n->args[0], out, depth + 1) && yx_put_bytes(out, ": (", 3) &&
               yx_module_print(p, n->args[1], out, depth + 1) && yx_put_u8(out, ')');
    }
    if (n->op == YX_ME_STRING) {
        static const char hex[] = "0123456789abcdef";
        if (!yx_put_u8(out, '"')) return false;
        for (size_t i = 0; i < n->length; ++i) {
            uint8_t c = n->bytes[i];
            if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
                if (!yx_put_u8(out, c)) return false;
            } else {
                char escape[] = {'\\', 'x', hex[c >> 4], hex[c & 15]};
                if (!yx_put_bytes(out, escape, sizeof(escape))) return false;
            }
        }
        return yx_put_u8(out, '"');
    }
    if (n->op == YX_ME_LENGTH) {
        /* len() of a string literal: the source names a `with` variable
         * bound to that literal (a literal has no methods). The text is
         * compiled again and compared, so a binding out of scope refuses. */
        if (n->args[0] < 0 || (size_t)n->args[0] >= p->count) return false;
        if (p->nodes[n->args[0]].op == YX_ME_STRING) {
            /* `integer`: 1 + the slot of the binding the decoder found in
             * scope (yx_module_literal_slot); none, no source. */
            if (n->integer <= 0 || n->integer > YX_ARCHIVE_MAX_VARS) return false;
            snprintf(number, sizeof(number), "v%" PRId64 ".len()", n->integer - 1);
            return yx_put_bytes(out, number, strlen(number));
        }
        return yx_module_print(p, n->args[0], out, depth + 1) && yx_put_bytes(out, ".len()", 6);
    }
    if (n->op == YX_ME_NEGATE) return yx_put_bytes(out, "-(", 2) && yx_module_print(p, n->args[0], out, depth + 1) && yx_put_u8(out, ')');
    if (n->op == YX_ME_REGEX) return n->bytes && yx_put_bytes(out, n->bytes, n->length);
    if (n->op == YX_ME_MEMBER) {
        const yx_module_node *base = &p->nodes[n->args[0]];
        if (!base->field || !n->field) return false;
        const char *member = n->field->path + strlen(base->field->path);
        return yx_module_print(p, n->args[0], out, depth + 1) && yx_put_bytes(out, member, strlen(member));
    }
    if (n->op == YX_ME_INDEX)
        return yx_module_print(p, n->args[0], out, depth + 1) && yx_put_u8(out, '[') && yx_module_print(p, n->args[1], out, depth + 1) && yx_put_u8(out, ']');
    if (n->op == YX_ME_CALL || n->op == YX_ME_READ) {
        const char *name = n->op == YX_ME_CALL ? n->signature->path : yx_module_read_name((uint8_t)n->integer);
        size_t argc = n->op == YX_ME_CALL ? n->argc : 1;
        if (!yx_put_bytes(out, name, strlen(name)) || !yx_put_u8(out, '(')) return false;
        for (size_t i = 0; i < argc; ++i)
            if ((i && !yx_put_u8(out, ',')) || !yx_module_print(p, n->args[i], out, depth + 1)) return false;
        return yx_put_u8(out, ')');
    }
    if (n->op == YX_ME_NOT) return yx_put_bytes(out, "not (", 5) && yx_module_print(p, n->args[0], out, depth + 1) && yx_put_u8(out, ')');
    if (n->op == YX_ME_DEFINED) return yx_put_bytes(out, "defined (", 9) && yx_module_print(p, n->args[0], out, depth + 1) && yx_put_u8(out, ')');
    if (n->op == YX_ME_GROUP) return yx_put_u8(out, '(') && yx_module_print(p, n->args[0], out, depth + 1) && yx_put_bytes(out, " and true)", 10);
    if (n->op == YX_ME_AND || n->op == YX_ME_OR) {
        size_t count;
        int *items = yx_module_left_chain(p, index, n->op, &count);
        if (!items) return false;
        const char *join = n->op == YX_ME_AND ? " and " : " or ";
        bool ok = yx_put_u8(out, '(');
        for (size_t i = 0; ok && i < count; ++i) ok = (!i || yx_put_bytes(out, join, strlen(join))) && yx_module_print(p, items[i], out, depth + 1);
        ok = ok && yx_put_u8(out, ')');
        free(items);
        return ok;
    }
    const char *op = n->op == YX_ME_AND ? " and " : n->op == YX_ME_OR ? " or " : NULL;
    if (n->op == YX_ME_ARITH) op = yx_integer_expr_operator(n->comparison);
    if (n->op == YX_ME_COMPARE) {
        if (n->comparison == 13) return p->print_primary && p->print_primary(p, index, out, depth);
        if (n->comparison >= sizeof(yx_module_comparison_text) / sizeof(yx_module_comparison_text[0])) return false;
        op = yx_module_comparison_text[n->comparison];
    }
    return op && yx_put_u8(out, '(') && yx_module_print(p, n->args[0], out, depth + 1) && yx_put_bytes(out, op, strlen(op)) &&
           yx_module_print(p, n->args[1], out, depth + 1) && yx_put_u8(out, ')');
}

static yx_ser_result yx_decode_module_expression(const uint8_t *data, size_t length, yx_ser_rule **rules, size_t *rule_count)
{
    static const uint8_t magic[] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0, 12, 0, 0, 0};
    yx_reader r = {data, length, 0, false, false};
    char **pool = NULL;
    yx_module_program *p = NULL;
    size_t pool_count = 0;
    yx_writer source = {0};
    uint8_t *canonical = NULL;
    size_t canonical_length = 0;
    yx_ser_rule *decoded = NULL;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    uint64_t count, size, imports, module_id = 0, namespace_variant, namespace_id, rule_id;
    const uint8_t *wasm;
    size_t wasm_length;
    uint8_t private_rule;
    yx_literal *regexes = NULL;
    size_t regex_count = 0;
    if (length < sizeof(magic) || memcmp(data, magic, sizeof(magic))) return YX_SER_UNSUPPORTED;
    r.at = sizeof(magic);
    if (!yx_get_uint(&r, &count) || count < 1 || count > 4 || count > length - r.at) goto done;
    pool_count = (size_t)count;
    pool = calloc(pool_count, sizeof(*pool));
    p = calloc(1, sizeof(*p));
    if (!pool || !p) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < pool_count; ++i)
        if (!yx_get_string(&r, &pool[i])) {
            if (r.no_memory) result = YX_SER_NO_MEMORY;
            goto done;
        }
    if (!yx_get_uint(&r, &count) || count > length - r.at) goto done;
    regex_count = (size_t)count;
    regexes = calloc(regex_count ? regex_count : 1, sizeof(*regexes));
    if (!regexes) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < regex_count; ++i) {
        if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
        regexes[i] = (yx_literal){data + r.at, (size_t)size};
        r.at += (size_t)size;
    }
    p->regexes = &regexes;
    p->regex_count = &regex_count;
    p->regex_capacity = &regex_count;
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &count) || count > length - r.at) goto done;
    p->literal_count = (size_t)count;
    p->literals = calloc(p->literal_count ? p->literal_count : 1, sizeof(*p->literals));
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
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &imports) || imports > 1) goto done;
    if (imports && (!yx_get_uint(&r, &module_id) || module_id >= pool_count || !(p->schema = yx_archive_schema(pool[module_id])))) goto done;
    if (!yx_expect_uint(&r, 1) || !yx_get_uint(&r, &namespace_variant) || !yx_get_uint(&r, &namespace_id) || namespace_id >= pool_count || !yx_get_uint(&r, &rule_id) ||
        rule_id >= pool_count || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) ||
        !yx_get_u8(&r, &private_rule) || private_rule > 1)
        goto done;
    if ((namespace_variant != 0 && namespace_variant != 2) || (namespace_variant == 0 && namespace_id != 0)) goto done;
    yx_reader wr = {wasm, wasm_length, 0, false, false};
    size_t body_end;
    if (!yx_module_decode_header(&wr, p, &body_end)) goto done;
    p->undefined_slot = -1;
    int root = yx_module_decode_block(&wr, body_end, p, 0);
    if (root < 0 || !yx_module_print(p, root, &source, 0)) goto done;
    if (!yx_put_u8(&source, 0)) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    YRX_RULE source_rule = {0};
    YRX_RULES source_rules = {0};
    source_rule.identifier = pool[rule_id];
    source_rule.namespace_name = pool[namespace_id];
    source_rule.condition_text = (char *)source.data;
    source_rule.is_private = private_rule != 0;
    source_rules.rules = &source_rule;
    source_rules.rule_count = 1;
    source_rules.import_count = (size_t)imports;
    char *module = imports ? pool[module_id] : NULL;
    source_rules.imports = &module;
    uint8_t profile;
    for (profile = 0; profile < 4; ++profile) {
        free(canonical);
        canonical = NULL;
        canonical_length = 0;
        if (yx_encode_module_expression_profile(&source_rules, profile, &canonical, &canonical_length) == YX_SER_SUCCESS && canonical_length <= length &&
            !memcmp(canonical, data, canonical_length))
            break;
    }
    if (profile == 4) goto done;
    decoded = calloc(1, sizeof(*decoded));
    if (!decoded) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    decoded->identifier = pool[rule_id];
    pool[rule_id] = NULL;
    decoded->namespace_name = malloc(strlen(source_rule.namespace_name) + 1);
    if (!decoded->namespace_name) {
        result = YX_SER_NO_MEMORY;
        goto done;
    }
    strcpy(decoded->namespace_name, source_rule.namespace_name);
    if (module) {
        decoded->runtime_module_name = malloc(strlen(module) + 1);
        if (!decoded->runtime_module_name) {
            result = YX_SER_NO_MEMORY;
            goto done;
        }
        strcpy(decoded->runtime_module_name, module);
    }
    decoded->runtime_integer_condition = (char *)source.data;
    source.data = NULL;
    decoded->runtime_integer_import_profile = profile;
    decoded->is_private = private_rule != 0;
    *rules = decoded;
    *rule_count = 1;
    decoded = NULL;
    result = YX_SER_SUCCESS;
done:
    if (decoded) yx_ser_rules_destroy(decoded, 1);
    if (pool)
        for (size_t i = 0; i < pool_count; ++i) free(pool[i]);
    free(pool);
    free(source.data);
    free(canonical);
    free(regexes);
    yx_module_program_free(p);
    return result;
}
