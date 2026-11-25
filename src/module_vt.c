/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "module_vt.h"
#include <xxfclib/algo/protobuf/xx_protobuf_wire.h>
#include <xxfclib/net/xx_domain_yx.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    YX_VTW_INT32,
    YX_VTW_UINT32,
    YX_VTW_SINT32,
    YX_VTW_FIXED32,
    YX_VTW_SFIXED32,
    YX_VTW_INT64,
    YX_VTW_UINT64,
    YX_VTW_SINT64,
    YX_VTW_FIXED64,
    YX_VTW_SFIXED64,
    YX_VTW_BOOL,
    YX_VTW_FLOAT,
    YX_VTW_DOUBLE,
    YX_VTW_STRING,
    YX_VTW_MESSAGE
} yx_vt_wire_type;
typedef struct {
    const char *name;
    unsigned number;
    yx_vt_wire_type type;
    unsigned child;
    unsigned flags;
} yx_vt_wire_field;
typedef struct {
    const char *name;
    const yx_vt_wire_field *fields;
    size_t count;
} yx_vt_wire_message;
#include "vt_wire_schema.h"
struct yx_vt_value {
    uint64_t number;
    double floating;
    char *string;
    size_t length;
    yx_vt_record *record;
    struct yx_vt_value *items;
    size_t count;
};
struct yx_vt_record {
    unsigned schema;
    yx_vt_value *fields;
};
typedef struct {
    char *error;
    size_t capacity;
} yx_vt_decode;

static bool yx_vt_error(yx_vt_decode *ctx, const char *message)
{
    if (ctx->error && ctx->capacity) snprintf(ctx->error, ctx->capacity, "%s", message);
    return false;
}
static bool yx_vt_varint(const uint8_t *data, size_t size, size_t *at, uint64_t *value)
{
    return xx_protobuf_wire_varint(data, size, at, value);
}
static bool yx_vt_utf8(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        unsigned c = s[i++], extra, code, minimum;
        if (c < 128) continue;
        if (c >= 0xc2 && c <= 0xdf) {
            extra = 1;
            code = c & 31;
            minimum = 128;
        } else if (c >= 0xe0 && c <= 0xef) {
            extra = 2;
            code = c & 15;
            minimum = 2048;
        } else if (c >= 0xf0 && c <= 0xf4) {
            extra = 3;
            code = c & 7;
            minimum = 65536;
        } else return false;
        if (extra > n - i) return false;
        while (extra--) {
            c = s[i++];
            if ((c & 0xc0) != 0x80) return false;
            code = (code << 6) | (c & 63);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
    }
    return true;
}
static void yx_vt_value_destroy(yx_vt_value *value)
{
    free(value->string);
    yx_vt_output_destroy(value->record);
    for (size_t i = 0; i < value->count; ++i) yx_vt_value_destroy(&value->items[i]);
    free(value->items);
}
void yx_vt_output_destroy(yx_vt_record *record)
{
    if (!record) return;
    for (size_t i = 0; i < yx_vt_wire_messages[record->schema].count; ++i) yx_vt_value_destroy(&record->fields[i]);
    free(record->fields);
    free(record);
}
static yx_vt_record *yx_vt_record_new(unsigned schema)
{
    yx_vt_record *record = calloc(1, sizeof(*record));
    if (!record) return NULL;
    record->schema = schema;
    size_t count = yx_vt_wire_messages[schema].count;
    record->fields = calloc(count ? count : 1, sizeof(*record->fields));
    if (!record->fields) {
        free(record);
        return NULL;
    }
    return record;
}
static bool yx_vt_skip(const uint8_t *data, size_t size, size_t *at, unsigned wire, unsigned depth)
{
    return xx_protobuf_wire_skip_field_vt(data, size, at, wire, depth);
}
static bool yx_vt_decode_record(yx_vt_record *, const uint8_t *, size_t, yx_vt_decode *, unsigned);
static unsigned yx_vt_wire(yx_vt_wire_type type)
{
    if (type == YX_VTW_MESSAGE || type == YX_VTW_STRING) return 2;
    if (type == YX_VTW_DOUBLE || type == YX_VTW_FIXED64 || type == YX_VTW_SFIXED64) return 1;
    if (type == YX_VTW_FLOAT || type == YX_VTW_FIXED32 || type == YX_VTW_SFIXED32) return 5;
    return 0;
}
static bool yx_vt_decode_scalar(yx_vt_value *value, const yx_vt_wire_field *field, const uint8_t *data, size_t size, size_t *at, yx_vt_decode *ctx, unsigned depth)
{
    uint64_t number = 0;
    unsigned wire = yx_vt_wire(field->type);
    if (wire == 0) {
        if (!yx_vt_varint(data, size, at, &number)) return yx_vt_error(ctx, "Incorrect varint");
        if (field->type == YX_VTW_INT32 && number > INT32_MAX && number < UINT64_MAX - INT32_MAX) {
            if (ctx->error && ctx->capacity) snprintf(ctx->error, ctx->capacity, "Value too large for i32: %" PRId64, (int64_t)number);
            return false;
        }
        if (field->type == YX_VTW_UINT32) number = (uint32_t)number;
        if (field->type == YX_VTW_BOOL) number = number != 0;
        if (field->type == YX_VTW_SINT32) number = (uint64_t)(int64_t)(int32_t)(((uint32_t)number >> 1) ^ -(int32_t)(number & 1));
        if (field->type == YX_VTW_SINT64) number = (number >> 1) ^ (uint64_t)-(int64_t)(number & 1);
        value->number = number;
        return true;
    }
    if (wire == 1 || wire == 5) {
        size_t bytes = wire == 1 ? 8 : 4;
        if (bytes > size - *at) return yx_vt_error(ctx, "Unexpected EOF");
        for (size_t i = 0; i < bytes; ++i) number |= (uint64_t)data[(*at)++] << (8 * i);
        if (field->type == YX_VTW_DOUBLE) memcpy(&value->floating, &number, 8);
        else if (field->type == YX_VTW_FLOAT) {
            uint32_t n = (uint32_t)number;
            float f;
            memcpy(&f, &n, 4);
            value->floating = f;
        } else value->number = field->type == YX_VTW_SFIXED32 ? (uint64_t)(int64_t)(int32_t)number : number;
        return true;
    }
    if (!yx_vt_varint(data, size, at, &number)) return yx_vt_error(ctx, "Incorrect varint");
    if (number > size - *at) return yx_vt_error(ctx, "Truncated message");
    size_t length = (size_t)number;
    const uint8_t *bytes = data + *at;
    *at += length;
    if (field->type == YX_VTW_MESSAGE) {
        /* The upstream output setter replaces singular message occurrences. */
        yx_vt_output_destroy(value->record);
        value->record = yx_vt_record_new(field->child);
        if (!value->record) return yx_vt_error(ctx, "out of memory");
        return yx_vt_decode_record(value->record, bytes, length, ctx, depth + 1);
    }
    if (!(field->flags & 4) && !yx_vt_utf8(bytes, length)) return yx_vt_error(ctx, "Invalid UTF-8 sequence");
    char *copy = malloc(length + 1);
    if (!copy) return yx_vt_error(ctx, "out of memory");
    if (length) memcpy(copy, bytes, length);
    copy[length] = 0;
    free(value->string);
    value->string = copy;
    value->length = length;
    return true;
}
static bool yx_vt_append_value(yx_vt_value *list, yx_vt_value *item, yx_vt_decode *ctx)
{
    if (list->count == SIZE_MAX / sizeof(*list->items)) return yx_vt_error(ctx, "out of memory");
    yx_vt_value *grown = realloc(list->items, (list->count + 1) * sizeof(*grown));
    if (!grown) return yx_vt_error(ctx, "out of memory");
    list->items = grown;
    list->items[list->count++] = *item;
    memset(item, 0, sizeof(*item));
    return true;
}
static bool yx_vt_decode_record(yx_vt_record *record, const uint8_t *data, size_t size, yx_vt_decode *ctx, unsigned depth)
{
    const yx_vt_wire_message *schema = &yx_vt_wire_messages[record->schema];
    size_t at = 0;
    if (depth > 64) return yx_vt_error(ctx, "Recursion limit exceeded");
    while (at < size) {
        uint64_t tag;
        size_t tag_start = at;
        if (!yx_vt_varint(data, size, &at, &tag)) return yx_vt_error(ctx, at == size && at - tag_start < 10 ? "Unexpected EOF" : "Incorrect varint");
        if (!(tag >> 3) || tag >> 3 > 0x1fffffff) return yx_vt_error(ctx, "Incorrect tag");
        unsigned wire = (unsigned)(tag & 7);
        size_t f = 0;
        for (; f < schema->count; ++f)
            if (schema->fields[f].number == (tag >> 3)) break;
        if (f == schema->count ||
            (wire != yx_vt_wire(schema->fields[f].type) && !(wire == 2 && (schema->fields[f].flags & 1) && yx_vt_wire(schema->fields[f].type) != 2))) {
            if (wire == 3 && at == size && strcmp(schema->name, "vt.MapEntry") == 0) continue;
            if (!yx_vt_skip(data, size, &at, wire, depth)) return yx_vt_error(ctx, "Unexpected EOF");
            continue;
        }
        const yx_vt_wire_field *field = &schema->fields[f];
        yx_vt_value *target = &record->fields[f];
        if (!(field->flags & 1)) {
            if (!yx_vt_decode_scalar(target, field, data, size, &at, ctx, depth)) return false;
            continue;
        }
        size_t stop = at;
        bool packed = wire == 2 && yx_vt_wire(field->type) != 2;
        if (packed) {
            uint64_t n;
            if (!yx_vt_varint(data, size, &at, &n) || n > size - at) return yx_vt_error(ctx, "Unexpected EOF");
            stop = at + (size_t)n;
        }
        do {
            yx_vt_value item = {0};
            if (packed && at == stop) break;
            if (!yx_vt_decode_scalar(&item, field, data, packed ? stop : size, &at, ctx, depth)) {
                yx_vt_value_destroy(&item);
                return false;
            }
            if (field->flags & 2) {
                const yx_vt_value *key = &item.record->fields[0];
                bool replaced = false;
                for (size_t j = 0; j < target->count; ++j) {
                    const yx_vt_value *old = &target->items[j].record->fields[0];
                    if (old->length == key->length && (!key->length || memcmp(old->string, key->string, key->length) == 0)) {
                        yx_vt_value_destroy(&target->items[j]);
                        target->items[j] = item;
                        memset(&item, 0, sizeof(item));
                        replaced = true;
                        break;
                    }
                }
                if (replaced) continue;
            }
            if (!yx_vt_append_value(target, &item, ctx)) {
                yx_vt_value_destroy(&item);
                return false;
            }
        } while (packed && at < stop);
    }
    return true;
}
bool yx_vt_parse_output(const uint8_t *data, size_t size, yx_vt_record **out, char *error, size_t capacity)
{
    yx_vt_decode ctx = {error, capacity};
    *out = NULL;
    yx_vt_record *record = yx_vt_record_new(YX_VT_ROOT_MESSAGE);
    if (!record) return yx_vt_error(&ctx, "out of memory");
    if (!yx_vt_decode_record(record, data, size, &ctx, 0)) {
        yx_vt_output_destroy(record);
        return false;
    }
    *out = record;
    return true;
}
static void yx_vt_data_scalar(const yx_vt_wire_field *field, const yx_vt_value *value, yx_vt_data *out)
{
    if (field->type == YX_VTW_STRING) {
        out->type = YX_VT_DATA_STRING;
        out->string = value && value->string ? value->string : "";
        out->length = value ? value->length : 0;
    } else if (field->type == YX_VTW_FLOAT || field->type == YX_VTW_DOUBLE) {
        out->type = YX_VT_DATA_FLOAT;
        out->floating = value ? value->floating : 0;
    } else if (field->type == YX_VTW_MESSAGE) out->type = YX_VT_DATA_STRUCT;
    else {
        out->type = YX_VT_DATA_INTEGER;
        out->number = value ? value->number : 0;
        out->is_unsigned = !(field->flags & 1) && (field->type == YX_VTW_UINT64 || field->type == YX_VTW_FIXED64);
    }
}
bool yx_vt_output_get(const yx_vt_record *record, const char *path, const yx_vt_key *keys, size_t key_count, bool element, yx_vt_data *out)
{
    unsigned schema = YX_VT_ROOT_MESSAGE;
    size_t key = 0;
    memset(out, 0, sizeof(*out));
    if (strncmp(path, "vt.", 3) != 0) return false;
    path += 3;
    while (*path) {
        size_t length = strcspn(path, ".");
        const yx_vt_wire_message *message = &yx_vt_wire_messages[schema];
        size_t f = 0;
        for (; f < message->count; ++f)
            if (strlen(message->fields[f].name) == length && !memcmp(message->fields[f].name, path, length)) break;
        if (f == message->count) return false;
        const yx_vt_wire_field *field = &message->fields[f];
        const yx_vt_value *value = record ? &record->fields[f] : NULL;
        path += length;
        if (*path == '.') ++path;
        if (field->flags & 1) {
            if (!*path || !strcmp(path, "len")) {
                out->type = (field->flags & 2) ? YX_VT_DATA_MAP : YX_VT_DATA_ARRAY;
                out->number = value ? value->count : 0;
                out->collection = value;
                return key == key_count;
            }
            if (key >= key_count) return false;
            size_t index = SIZE_MAX;
            if (field->flags & 2) {
                if (!keys[key].is_string) return false;
                for (size_t j = 0; value && j < value->count; ++j) {
                    const yx_vt_value *k = &value->items[j].record->fields[0];
                    if (k->length == keys[key].length && (!k->length || !memcmp(k->string, keys[key].string, k->length))) {
                        index = j;
                        break;
                    }
                }
            } else if (!keys[key].is_string && keys[key].number <= SIZE_MAX) index = (size_t)keys[key].number;
            ++key;
            if (!value || index >= value->count) return false;
            value = &value->items[index];
            if (field->flags & 2) {
                if (strcmp(path, "value")) return false;
                yx_vt_data_scalar(&yx_vt_wire_messages[field->child].fields[1], &value->record->fields[1], out);
                return key == key_count;
            }
            if (!strcmp(path, "value") && (field->type != YX_VTW_MESSAGE || element)) {
                yx_vt_data_scalar(field, value, out);
                return key == key_count;
            }
        }
        if (!*path) {
            yx_vt_data_scalar(field, value, out);
            return key == key_count;
        }
        if (field->type != YX_VTW_MESSAGE) return false;
        schema = field->child;
        record = value ? value->record : NULL;
    }
    return false;
}
bool yx_vt_map_item(const yx_vt_value *map, size_t index, const char **key, size_t *key_length, const char **value, size_t *value_length)
{
    if (!map || index >= map->count) return false;
    const yx_vt_record *entry = map->items[index].record;
    *key = entry->fields[0].string ? entry->fields[0].string : "";
    *key_length = entry->fields[0].length;
    *value = entry->fields[1].string ? entry->fields[1].string : "";
    *value_length = entry->fields[1].length;
    return true;
}

/* The EnrichedIP/in_range, public-suffix and domain-permutation helpers
 * moved to xxfclib (xxfclib/net/xx_domain_yx.h; _yx because they encode the
 * vt module's YARA-X choices); these adapters keep the yx_vt_* module API
 * unchanged for condition.c and the tests. */
bool yx_vt_ip_in_range(const char *ip, size_t ip_length, const char *cidr, size_t cidr_length)
{
    return xx_domain_yx_ip_in_range(ip, ip_length, cidr, cidr_length);
}
size_t yx_vt_public_suffix_length(const char *name, size_t length)
{
    return xx_domain_yx_public_suffix_length(name, length);
}
bool yx_vt_parse_domain(const char *name, size_t length, yx_vt_domain_parts *parts)
{
    return xx_domain_yx_parse_domain(name, length, parts);
}
bool yx_vt_domain_permutation_of(const char *domain, size_t domain_length, const char *target, size_t target_length, int64_t kinds)
{
    return xx_domain_yx_permutation_of(domain, domain_length, target, target_length, kinds);
}
