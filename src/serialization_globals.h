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

/* External values use the same bincode TypeValue/Struct representation as
 * native module globals. Build their schema from the declared values instead
 * of embedding whole-rule templates. */
typedef struct {
    yx_archive_module_schema schema;
    yx_archive_module_field *fields;
    yx_archive_module_signature *owned_signatures;
    size_t capacity;
    yx_writer globals;
} yx_archive_globals_schema;

static uint8_t yx_archive_global_kind(yx_global_type type)
{
    /* Expression nodes use the codec's compact semantic kinds. Wire kinds
     * below follow the v12 TypeValue enum independently. */
    static const uint8_t kinds[] = {1,3,2,4,7,6};
    return type <= YX_GLOBAL_STRUCT ? kinds[type] : 0;
}
static uint8_t yx_archive_global_wire_kind(yx_global_type type)
{
    static const uint8_t kinds[] = {1,6,2,11,14,13};
    return type <= YX_GLOBAL_STRUCT ? kinds[type] : 0;
}
static uint8_t yx_archive_global_element(yx_global_type type)
{
    static const uint8_t kinds[] = {2,0,1,3,255,4};
    return type <= YX_GLOBAL_STRUCT ? kinds[type] : 255;
}
static yx_global_scalar_value yx_archive_global_value(const yx_global *global)
{
    yx_global_scalar_value value = {0};
    switch (global->type) {
    case YX_GLOBAL_BOOL: value.boolean = global->value.boolean; break;
    case YX_GLOBAL_INT: value.integer = global->value.integer; break;
    case YX_GLOBAL_FLOAT: value.floating = global->value.floating; break;
    case YX_GLOBAL_STR: value.string = global->value.string; break;
    case YX_GLOBAL_ARRAY: value.array = global->value.array; break;
    case YX_GLOBAL_STRUCT: value.object = global->value.object; break;
    }
    return value;
}
static bool yx_archive_global_write_value(yx_writer *out, yx_global_type type,
                                          yx_global_scalar_value value, unsigned depth);
static bool yx_archive_global_write_object(yx_writer *out, const yx_global_object *object,
                                           unsigned depth)
{
    if (!object || depth > 16 || !yx_put_uint(out, object->count)) return false;
    for (size_t i = 0; i < object->count; ++i) {
        const yx_global_field *field = &object->fields[i];
        if (!yx_put_string(out, field->name) || !yx_put_uint(out, 0) ||
            !yx_archive_global_write_value(out, field->type, field->value, depth + 1)) return false;
    }
    return yx_put_uint(out, 0) && yx_put_u8(out, 0) && yx_put_u8(out, 0);
}
static bool yx_archive_global_write_scalar(yx_writer *out, yx_global_type type,
                                           yx_global_scalar_value value, unsigned depth)
{
    switch (type) {
    case YX_GLOBAL_BOOL: return yx_put_u8(out, value.boolean);
    case YX_GLOBAL_INT: return yx_put_signed(out, value.integer);
    case YX_GLOBAL_FLOAT: return yx_put_float(out, value.floating);
    case YX_GLOBAL_STR: return yx_put_uint(out, value.string.length) &&
        yx_put_bytes(out, value.string.data, value.string.length);
    case YX_GLOBAL_STRUCT: return yx_archive_global_write_object(out, value.object, depth + 1);
    default: return false;
    }
}
static bool yx_archive_global_write_value(yx_writer *out, yx_global_type type,
                                          yx_global_scalar_value value, unsigned depth)
{
    if (depth > 16 || !yx_put_uint(out, yx_archive_global_wire_kind(type))) return false;
    if (type == YX_GLOBAL_STRUCT) return yx_archive_global_write_object(out, value.object, depth + 1);
    if (type == YX_GLOBAL_ARRAY) {
        const yx_global_array *array = value.array;
        if (!array || yx_archive_global_element(array->element_type) == 255 ||
            !yx_put_uint(out, yx_archive_global_element(array->element_type)) ||
            !yx_put_uint(out, array->count)) return false;
        for (size_t i = 0; i < array->count; ++i)
            if (!yx_archive_global_write_scalar(out, array->element_type, array->items[i], depth + 1)) return false;
        return true;
    }
    return yx_put_uint(out, 1) && /* Value::Var */
        yx_archive_global_write_scalar(out, type, value, depth + 1) &&
        (type != YX_GLOBAL_STR || yx_put_uint(out, 0));
}
static bool yx_archive_global_add_field(yx_archive_globals_schema *out, const char *path,
                                        yx_global_type type, yx_global_scalar_value value,
                                        const uint16_t *indexes, size_t depth)
{
    if (!depth || depth > 16) return false;
    if (out->schema.field_count == out->capacity) {
        size_t capacity = out->capacity ? out->capacity * 2 : 16;
        if (capacity < out->capacity || capacity > SIZE_MAX / sizeof(*out->fields)) return false;
        yx_archive_module_field *fields = realloc(out->fields, capacity * sizeof(*fields));
        if (!fields) return false;
        out->fields = fields; out->capacity = capacity; out->schema.fields = fields;
    }
    char *copy = malloc(strlen(path) + 1);
    if (!copy) return false;
    strcpy(copy, path);
    yx_archive_module_field *field = &out->fields[out->schema.field_count++];
    memset(field, 0, sizeof(*field));
    field->path = copy; field->kind = yx_archive_global_kind(type); field->state = 1;
    field->depth = (uint8_t)depth; memcpy(field->indexes, indexes, depth * sizeof(*indexes));
    if (type == YX_GLOBAL_ARRAY) {
        if (!value.array) return false;
        field->element = yx_archive_global_element(value.array->element_type);
    }
    const yx_global_object *object = type == YX_GLOBAL_STRUCT ? value.object :
        type == YX_GLOBAL_ARRAY && value.array && value.array->element_type == YX_GLOBAL_STRUCT &&
        value.array->count ? value.array->items[0].object : NULL;
    if (object) {
        if (object->count > UINT16_MAX) return false;
        for (size_t i = 0; i < object->count; ++i) {
            const yx_global_field *member = &object->fields[i];
            size_t a = strlen(path), b = strlen(member->name);
            if (a > SIZE_MAX - b - 2 || depth == 16) return false;
            char *child = malloc(a + b + 2);
            if (!child) return false;
            memcpy(child, path, a); child[a] = '.'; memcpy(child + a + 1, member->name, b + 1);
            uint16_t nested[16]; memcpy(nested, indexes, depth * sizeof(*indexes)); nested[depth] = (uint16_t)i;
            bool ok = yx_archive_global_add_field(out, child, member->type, member->value, nested, depth + 1);
            free(child); if (!ok) return false;
        }
    }
    return true;
}
static void yx_archive_globals_schema_free(yx_archive_globals_schema *schema)
{
    for (size_t i = 0; i < schema->schema.field_count; ++i) free((char *)schema->fields[i].path);
    free(schema->fields); free(schema->owned_signatures);
    free(schema->globals.data); memset(schema, 0, sizeof(*schema));
}
static bool yx_archive_globals_schema_build(yx_archive_globals_schema *out, const YRX_RULES *rules,
                                            const yx_archive_module_schema *module, uint8_t profile)
{
    if (!rules->globals || rules->global_count > UINT16_MAX || profile > 3 ||
        !yx_put_uint(&out->globals, rules->global_count + (module ? 1 : 0))) return false;
    out->schema.name = module ? module->name : "";
    out->schema.signatures = module ? module->signatures : NULL;
    out->schema.signature_count = module ? module->signature_count : 0;
    for (size_t i = 0; i < rules->global_count; ++i) {
        const yx_global *global = &rules->globals[i];
        yx_global_scalar_value value = yx_archive_global_value(global);
        uint16_t index = (uint16_t)i;
        if (!yx_put_string(&out->globals, global->name) || !yx_put_uint(&out->globals, 0) ||
            !yx_archive_global_write_value(&out->globals, global->type, value, 0) ||
            !yx_archive_global_add_field(out, global->name, global->type, value, &index, 1)) return false;
    }
    if (module) {
        const uint8_t *bytes = module->globals[profile]; size_t size = module->globals_length[profile];
        if (size < 4 || bytes[0] != 1 || memcmp(bytes + size - 3, "\0\1\0", 3) ||
            !yx_put_bytes(&out->globals, bytes + 1, size - 4)) return false;
        for (size_t i = 0; i < module->field_count; ++i) {
            const yx_archive_module_field *field = &module->fields[i];
            uint16_t indexes[16]; memcpy(indexes, field->indexes, sizeof(indexes));
            if (!field->depth || indexes[0] > UINT16_MAX - rules->global_count) return false;
            indexes[0] += (uint16_t)rules->global_count;
            yx_global_type type = field->kind == 1 ? YX_GLOBAL_BOOL : field->kind == 2 ? YX_GLOBAL_FLOAT :
                field->kind == 3 ? YX_GLOBAL_INT : YX_GLOBAL_STR;
            yx_global_scalar_value empty = {0};
            if (!yx_archive_global_add_field(out, field->path, type, empty, indexes, field->depth)) return false;
            yx_archive_module_field *copy = &out->fields[out->schema.field_count - 1];
            const char *path = copy->path; *copy = *field; copy->path = path;
            memcpy(copy->indexes, indexes, sizeof(indexes));
        }
    }
    if (!yx_put_uint(&out->globals, 0) || !yx_put_u8(&out->globals, 1) || !yx_put_u8(&out->globals, 0)) return false;
    for (size_t i = 0; i < 4; ++i) {
        out->schema.globals[i] = out->globals.data;
        out->schema.globals_length[i] = out->globals.used;
    }
    return true;
}

static yx_ser_result yx_encode_global_expression_profile(const YRX_RULES *rules, uint8_t profile,
                                                           uint8_t **data, size_t *length)
{
    static const uint8_t magic[] = {'Y','A','R','A','-','X',0,0,12,0,0,0};
    static const uint8_t empty_globals[] = {0,0,1,0};
    if (!rules || rules->rule_count != 1 || !rules->rules || !rules->global_count || rules->import_count > 1 || profile > 3)
        return YX_SER_UNSUPPORTED;
    const YRX_RULE *rule = &rules->rules[0];
    const char *module = rules->import_count && rules->imports ? rules->imports[0] : NULL;
    if (rule->pattern_count || rule->is_global || rule->tag_count || rule->metadata_count || !rule->condition_text ||
        !yx_valid_rule_name(rule->identifier)) return YX_SER_UNSUPPORTED;
    const yx_archive_module_schema *module_schema = yx_archive_schema(module);
    if (rules->import_count && !module_schema) return YX_SER_UNSUPPORTED;
    yx_archive_globals_schema dynamic = {0};
    if (!yx_archive_globals_schema_build(&dynamic, rules, module_schema, profile)) {
        yx_archive_globals_schema_free(&dynamic); return YX_SER_UNSUPPORTED;
    }
    const yx_archive_module_schema *schema = &dynamic.schema;
    yx_module_program *p = calloc(1, sizeof(*p));
    yx_writer out = {0}; uint8_t *wasm = NULL;
    size_t wasm_length = 0, count = 0, capacity = 0, ignored = 0, namespace_id = 0, module_id = 0, rule_id = 0;
    const char **pool = NULL;
    yx_ser_result result = YX_SER_UNSUPPORTED;
    if (!p) { yx_archive_globals_schema_free(&dynamic); return YX_SER_NO_MEMORY; }
    p->schema = schema; p->profile = profile; p->parser.at = (const unsigned char *)rule->condition_text;
    p->capi_import_order = !rules->archive_cli && profile == 0;
    int root = yx_module_parse(p, 1, 0);
    yx_bool_skip_space(&p->parser);
    if (root < 0 || *p->parser.at || p->failed) goto done;
    if (!yx_module_wasm(p, root, &wasm, &wasm_length)) goto done;
    const char *namespace_name = rule->namespace_name ? rule->namespace_name : "default";
    if (!yx_intern_ident("default", &pool, &count, &capacity, &ignored) ||
        !yx_intern_ident(namespace_name, &pool, &count, &capacity, &namespace_id) ||
        (module && !yx_intern_ident(module, &pool, &count, &capacity, &module_id)) ||
        !yx_intern_ident(rule->identifier, &pool, &count, &capacity, &rule_id)) goto memory;
    if (!yx_put_bytes(&out, magic, sizeof(magic)) || !yx_put_uint(&out, count)) goto memory;
    for (size_t i = 0; i < count; ++i) if (!yx_put_string(&out, pool[i])) goto memory;
    if (!yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_uint(&out, p->literal_count)) goto memory;
    for (size_t i = 0; i < p->literal_count; ++i)
        if (!yx_put_uint(&out, p->literals[i].length) || !yx_put_bytes(&out, p->literals[i].data, p->literals[i].length)) goto memory;
    if (!yx_put_uint(&out, wasm_length) || !yx_put_bytes(&out, wasm, wasm_length) ||
        !yx_put_u8(&out, 0) || !yx_put_u8(&out, module ? 1 : 0) || (module && !yx_put_uint(&out, module_id)) ||
        !yx_put_u8(&out, 1) || !yx_put_u8(&out, namespace_id ? 2 : 0) || !yx_put_uint(&out, namespace_id) ||
        !yx_put_uint(&out, rule_id) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) ||
        !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, rule->is_private ? 1 : 0)) goto memory;
    for (size_t i = 0; i < 7; ++i) if (!yx_put_u8(&out, 0)) goto memory;
    const uint8_t *globals = schema ? schema->globals[profile] : empty_globals;
    size_t globals_length = schema ? schema->globals_length[profile] : sizeof(empty_globals);
    uint8_t ac[YX_AC_LENGTH]; yx_make_empty_ac(ac);
    if (!yx_put_uint(&out, globals_length) || !yx_put_bytes(&out, globals, globals_length) ||
        !yx_put_uint(&out, sizeof(ac)) || !yx_put_bytes(&out, ac, sizeof(ac)) ||
        !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0) || !yx_put_u8(&out, 0)) goto memory;
    *data = out.data; *length = out.used; out.data = NULL; result = YX_SER_SUCCESS; goto done;
memory:
    result = YX_SER_NO_MEMORY;
done:
    free(out.data); free(wasm); free(pool); yx_module_program_free(p);
    yx_archive_globals_schema_free(&dynamic);
    return result;
}

static void yx_archive_global_destroy_value(yx_global_type type, yx_global_scalar_value value)
{
    if (type == YX_GLOBAL_STR) free(value.string.data);
    else if (type == YX_GLOBAL_ARRAY && value.array) {
        for (size_t i = 0; i < value.array->count; ++i)
            yx_archive_global_destroy_value(value.array->element_type, value.array->items[i]);
        free(value.array->items); free(value.array);
    } else if (type == YX_GLOBAL_STRUCT && value.object) {
        for (size_t i = 0; i < value.object->count; ++i) {
            free(value.object->fields[i].name);
            yx_archive_global_destroy_value(value.object->fields[i].type, value.object->fields[i].value);
        }
        free(value.object->fields); free(value.object);
    }
}
static void yx_archive_globals_destroy(yx_global *globals, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        free(globals[i].name);
        yx_archive_global_destroy_value(globals[i].type, yx_archive_global_value(&globals[i]));
    }
    free(globals);
}
static bool yx_archive_global_read_value(yx_reader *r, yx_global_type *type,
                                         yx_global_scalar_value *value, unsigned depth);
static bool yx_archive_global_read_object(yx_reader *r, yx_global_object **out, unsigned depth)
{
    uint64_t count;
    if (depth > 16 || !yx_get_uint(r, &count) || count > r->length - r->at ||
        count > SIZE_MAX / sizeof(yx_global_field)) return false;
    yx_global_object *object = calloc(1, sizeof(*object));
    if (!object) return false;
    *out = object; object->count = (size_t)count;
    object->fields = calloc(count ? (size_t)count : 1, sizeof(*object->fields));
    if (!object->fields) { object->count = 0; return false; }
    for (size_t i = 0; i < object->count; ++i) {
        yx_global_field *field = &object->fields[i];
        if (!yx_get_string(r, &field->name) || !yx_expect_uint(r, 0) ||
            !yx_archive_global_read_value(r, &field->type, &field->value, depth + 1)) return false;
    }
    return yx_expect_uint(r, 0) && yx_expect_uint(r, 0) && yx_expect_uint(r, 0);
}
static bool yx_archive_global_read_scalar(yx_reader *r, yx_global_type type,
                                          yx_global_scalar_value *value, unsigned depth)
{
    uint64_t length; uint8_t boolean;
    switch (type) {
    case YX_GLOBAL_BOOL:
        if (!yx_get_u8(r, &boolean) || boolean > 1) return false;
        value->boolean = boolean != 0; return true;
    case YX_GLOBAL_INT: return yx_get_signed(r, &value->integer);
    case YX_GLOBAL_FLOAT: return yx_get_float(r, &value->floating);
    case YX_GLOBAL_STR:
        if (!yx_get_uint(r, &length) || length > r->length - r->at || length == SIZE_MAX) return false;
        value->string.data = malloc((size_t)length + 1);
        if (!value->string.data) return false;
        memcpy(value->string.data, r->data + r->at, (size_t)length);
        value->string.data[length] = 0; value->string.length = (size_t)length; r->at += (size_t)length;
        return true;
    case YX_GLOBAL_STRUCT: return yx_archive_global_read_object(r, &value->object, depth + 1);
    default: return false;
    }
}
static bool yx_archive_global_read_value(yx_reader *r, yx_global_type *type,
                                         yx_global_scalar_value *value, unsigned depth)
{
    uint64_t kind, element, count;
    if (depth > 16 || !yx_get_uint(r, &kind)) return false;
    switch (kind) {
    case 1: *type = YX_GLOBAL_BOOL; break;
    case 2: *type = YX_GLOBAL_FLOAT; break;
    case 6: *type = YX_GLOBAL_INT; break;
    case 11: *type = YX_GLOBAL_STR; break;
    case 13: *type = YX_GLOBAL_STRUCT; return yx_archive_global_read_object(r, &value->object, depth + 1);
    case 14: {
        static const yx_global_type types[] = {YX_GLOBAL_INT,YX_GLOBAL_FLOAT,YX_GLOBAL_BOOL,YX_GLOBAL_STR,YX_GLOBAL_STRUCT};
        *type = YX_GLOBAL_ARRAY;
        if (!yx_get_uint(r, &element) || element > 4 || !yx_get_uint(r, &count) || !count ||
            count > r->length - r->at || count > SIZE_MAX / sizeof(yx_global_scalar_value)) return false;
        yx_global_array *array = calloc(1, sizeof(*array));
        if (!array) return false;
        value->array = array; array->element_type = types[element]; array->count = (size_t)count;
        array->items = calloc(count ? (size_t)count : 1, sizeof(*array->items));
        if (!array->items) { array->count = 0; return false; }
        for (size_t i = 0; i < array->count; ++i)
            if (!yx_archive_global_read_scalar(r, array->element_type, &array->items[i], depth + 1)) return false;
        return true;
    }
    default: return false;
    }
    return yx_expect_uint(r, 1) && yx_archive_global_read_scalar(r, *type, value, depth + 1) &&
        (*type != YX_GLOBAL_STR || yx_expect_uint(r, 0));
}

static yx_ser_result yx_decode_global_expression(const uint8_t *data, size_t length,
                                                  yx_ser_rule **rules, size_t *rule_count)
{
    static const uint8_t magic[] = {'Y','A','R','A','-','X',0,0,12,0,0,0};
    yx_reader r = {data,length,0,false,false};
    char **pool = NULL; yx_module_program *p = NULL;
    size_t pool_count = 0; yx_writer source = {0};
    uint8_t *canonical = NULL; size_t canonical_length = 0;
    yx_ser_rule *decoded = NULL;
    yx_global *globals = NULL; size_t global_count = 0;
    yx_archive_globals_schema dynamic = {0};
    yx_ser_result result = YX_SER_UNSUPPORTED;
    uint64_t count, size, imports, module_id = 0, namespace_variant, namespace_id, rule_id;
    const uint8_t *wasm; size_t wasm_length;
    uint8_t private_rule;
    if (length < sizeof(magic) || memcmp(data, magic, sizeof(magic))) return YX_SER_UNSUPPORTED;
    r.at = sizeof(magic);
    if (!yx_get_uint(&r, &count) || count < 1 || count > 4 || count > length - r.at) goto done;
    pool_count = (size_t)count; pool = calloc(pool_count, sizeof(*pool)); p = calloc(1, sizeof(*p));
    if (!pool || !p) { result = YX_SER_NO_MEMORY; goto done; }
    for (size_t i = 0; i < pool_count; ++i) if (!yx_get_string(&r, &pool[i])) goto done;
    if (!yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_uint(&r, &count) || count > length - r.at) goto done;
    p->literal_count = (size_t)count;
    p->literals = calloc(p->literal_count ? p->literal_count : 1, sizeof(*p->literals));
    if (!p->literals) { result = YX_SER_NO_MEMORY; goto done; }
    for (size_t i = 0; i < p->literal_count; ++i) {
        if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
        p->literals[i] = (yx_literal){data + r.at,(size_t)size}; r.at += (size_t)size;
    }
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    wasm = data + r.at; wasm_length = (size_t)size; r.at += (size_t)size;
    if (!yx_expect_uint(&r, 0) || !yx_get_uint(&r, &imports) || imports > 1) goto done;
    const yx_archive_module_schema *module = NULL;
    if (imports && (!yx_get_uint(&r, &module_id) || module_id >= pool_count || !(module = yx_archive_schema(pool[module_id])))) goto done;
    if (!yx_expect_uint(&r, 1) || !yx_get_uint(&r, &namespace_variant) || !yx_get_uint(&r, &namespace_id) || namespace_id >= pool_count ||
        !yx_get_uint(&r, &rule_id) || rule_id >= pool_count || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) ||
        !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_expect_uint(&r, 0) || !yx_get_u8(&r, &private_rule) || private_rule > 1) goto done;
    if ((namespace_variant != 0 && namespace_variant != 2) || (namespace_variant == 0 && namespace_id != 0)) goto done;
    for (size_t i = 0; i < 7; ++i) if (!yx_expect_uint(&r, 0)) goto done;
    if (!yx_get_uint(&r, &size) || size > length - r.at) goto done;
    yx_reader gr = {data + r.at, (size_t)size, 0, false, false};
    if (!yx_get_uint(&gr, &count) || count <= imports || count - imports > UINT16_MAX || count > gr.length - gr.at) goto done;
    global_count = (size_t)(count - imports); globals = calloc(global_count, sizeof(*globals));
    if (!globals) { global_count = 0; result = YX_SER_NO_MEMORY; goto done; }
    for (size_t i = 0; i < global_count; ++i) {
        yx_global_scalar_value value = {0};
        if (!yx_get_string(&gr, &globals[i].name) || !yx_expect_uint(&gr, 0)) goto done;
        bool ok = yx_archive_global_read_value(&gr, &globals[i].type, &value, 0);
        memcpy(&globals[i].value, &value, sizeof(value));
        if (!ok) goto done;
    }
    if (!imports && (!yx_expect_uint(&gr, 0) || !yx_expect_uint(&gr, 1) || !yx_expect_uint(&gr, 0) || gr.at != gr.length)) goto done;
    YRX_RULE source_rule = {0}; YRX_RULES source_rules = {0};
    source_rule.identifier = pool[rule_id]; source_rule.namespace_name = pool[namespace_id]; source_rule.is_private = private_rule != 0;
    source_rules.rules = &source_rule; source_rules.rule_count = 1; source_rules.import_count = (size_t)imports;
    char *module_name = imports ? pool[module_id] : NULL; source_rules.imports = &module_name;
    source_rules.globals = globals; source_rules.global_count = global_count;
    if (!yx_archive_globals_schema_build(&dynamic, &source_rules, module, 0)) goto done;
    p->schema = &dynamic.schema;
    yx_reader wr = {wasm,wasm_length,0,false,false}; size_t body_end;
    if (!yx_module_decode_header(&wr, p, &body_end)) goto done;
    p->undefined_slot = -1;
    int root = yx_module_decode_block(&wr, body_end, p, 0);
    if (root < 0 || !yx_module_print(p, root, &source, 0) || !yx_put_u8(&source, 0)) goto done;
    source_rule.condition_text = (char *)source.data;
    uint8_t profile = 0;
    bool canonical_match = false;
    for (unsigned frontend = 0; frontend < 2 && !canonical_match; ++frontend) {
        source_rules.archive_cli = frontend != 0;
        for (profile = 0; profile < 4; ++profile) {
            free(canonical); canonical = NULL; canonical_length = 0;
            if (yx_encode_global_expression_profile(&source_rules, profile, &canonical, &canonical_length) == YX_SER_SUCCESS &&
                canonical_length <= length && !memcmp(canonical, data, canonical_length)) {
                canonical_match = true; break;
            }
        }
    }
    if (!canonical_match) goto done;
    decoded = calloc(1, sizeof(*decoded));
    if (!decoded) { result = YX_SER_NO_MEMORY; goto done; }
    decoded->identifier = pool[rule_id]; pool[rule_id] = NULL;
    decoded->namespace_name = malloc(strlen(source_rule.namespace_name) + 1);
    if (!decoded->namespace_name) { result = YX_SER_NO_MEMORY; goto done; }
    strcpy(decoded->namespace_name, source_rule.namespace_name);
    if (module_name) {
        decoded->runtime_module_name = malloc(strlen(module_name) + 1);
        if (!decoded->runtime_module_name) { result = YX_SER_NO_MEMORY; goto done; }
        strcpy(decoded->runtime_module_name, module_name);
    }
    decoded->runtime_globals = globals; decoded->runtime_global_count = global_count; globals = NULL; global_count = 0;
    decoded->runtime_integer_condition = (char *)source.data; source.data = NULL;
    decoded->runtime_integer_import_profile = profile; decoded->is_private = private_rule != 0;
    decoded->preserve_serialized_prefix = true;
    *rules = decoded; *rule_count = 1; decoded = NULL; result = YX_SER_SUCCESS;
done:
    if (decoded) yx_ser_rules_destroy(decoded, 1);
    if (pool) for (size_t i = 0; i < pool_count; ++i) free(pool[i]);
    free(pool); free(source.data); free(canonical); yx_module_program_free(p);
    yx_archive_globals_destroy(globals, global_count); yx_archive_globals_schema_free(&dynamic);
    return result;
}
