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

#include "module_output.h"
#include <xxfclib/algo/protobuf/xx_protobuf_wire.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  YX_MOW_INT32,
  YX_MOW_UINT32,
  YX_MOW_SINT32,
  YX_MOW_FIXED32,
  YX_MOW_SFIXED32,
  YX_MOW_INT64,
  YX_MOW_UINT64,
  YX_MOW_SINT64,
  YX_MOW_FIXED64,
  YX_MOW_SFIXED64,
  YX_MOW_BOOL,
  YX_MOW_FLOAT,
  YX_MOW_DOUBLE,
  YX_MOW_STRING,
  YX_MOW_MESSAGE
} yx_mo_wire_type;
typedef struct {
  const char *name;
  unsigned number;
  yx_mo_wire_type type;
  unsigned child;
  unsigned flags;
} yx_mo_wire_field;
typedef struct {
  const char *name;
  const yx_mo_wire_field *fields;
  size_t count;
} yx_mo_wire_message;
typedef struct {
  const char *name;
  const char *root_name;
  unsigned root;
} yx_mo_module;
#include "module_output_schema.h"
struct yx_mo_value {
  bool present;
  uint64_t number;
  double floating;
  char *string;
  size_t length;
  yx_mo_record *record;
  struct yx_mo_value *items;
  size_t count;
};
struct yx_mo_record {
  unsigned schema;
  yx_mo_value *fields;
  bool descriptor_only;
};
typedef struct {
  char *error;
  size_t capacity;
  bool nested_failure;
} yx_mo_decode;

static bool yx_mo_error(yx_mo_decode *ctx, const char *message) {
  if (ctx->error && ctx->capacity)
    snprintf(ctx->error, ctx->capacity, "%s", message);
  return false;
}
static bool yx_mo_varint(const uint8_t *data, size_t size, size_t *at,
                         uint64_t *value) {
  return xx_protobuf_wire_varint(data, size, at, value);
}
static bool yx_mo_utf8(const uint8_t *s, size_t n) {
  for (size_t i = 0; i < n;) {
    unsigned c = s[i++], extra, code, minimum;
    if (c < 128)
      continue;
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
    } else
      return false;
    if (extra > n - i)
      return false;
    while (extra--) {
      c = s[i++];
      if ((c & 0xc0) != 0x80)
        return false;
      code = (code << 6) | (c & 63);
    }
    if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
      return false;
  }
  return true;
}
static void yx_mo_value_destroy(yx_mo_value *value) {
  free(value->string);
  yx_mo_output_destroy(value->record);
  for (size_t i = 0; i < value->count; ++i)
    yx_mo_value_destroy(&value->items[i]);
  free(value->items);
}
void yx_mo_output_destroy(yx_mo_record *record) {
  if (!record)
    return;
  for (size_t i = 0; i < yx_mo_wire_messages[record->schema].count; ++i)
    yx_mo_value_destroy(&record->fields[i]);
  free(record->fields);
  free(record);
}
static yx_mo_record *yx_mo_record_new(unsigned schema) {
  yx_mo_record *record = calloc(1, sizeof(*record));
  if (!record)
    return NULL;
  record->schema = schema;
  size_t count = yx_mo_wire_messages[schema].count;
  record->fields = calloc(count ? count : 1, sizeof(*record->fields));
  if (!record->fields) {
    free(record);
    return NULL;
  }
  return record;
}
static bool yx_mo_skip(const uint8_t *data, size_t size, size_t *at,
                       unsigned wire, unsigned depth, yx_mo_decode *ctx,
                       uint64_t logical_size) {
  switch (xx_protobuf_wire_skip_field_checked(data, size, at, wire, depth,
                                              logical_size)) {
  case XX_PROTOBUF_WIRE_SKIP_OK:
    return true;
  case XX_PROTOBUF_WIRE_SKIP_UNEXPECTED_EOF:
    return yx_mo_error(ctx, "Unexpected EOF");
  case XX_PROTOBUF_WIRE_SKIP_INCORRECT_VARINT:
    return yx_mo_error(ctx, "Incorrect varint");
  case XX_PROTOBUF_WIRE_SKIP_TRUNCATED_MESSAGE:
    return yx_mo_error(ctx, "Truncated message");
  case XX_PROTOBUF_WIRE_SKIP_RECURSION_LIMIT:
    return yx_mo_error(ctx, "Recursion limit exceeded");
  case XX_PROTOBUF_WIRE_SKIP_UNEXPECTED_WIRE:
    return yx_mo_error(ctx, "Unexpected wire type");
  default:
    return yx_mo_error(ctx, "Incorrect tag");
  }
}
static bool yx_mo_decode_record(yx_mo_record *, const uint8_t *, size_t,
                                yx_mo_decode *, unsigned, bool, uint64_t);
static unsigned yx_mo_wire(yx_mo_wire_type type) {
  if (type == YX_MOW_MESSAGE || type == YX_MOW_STRING)
    return 2;
  if (type == YX_MOW_DOUBLE || type == YX_MOW_FIXED64 ||
      type == YX_MOW_SFIXED64)
    return 1;
  if (type == YX_MOW_FLOAT || type == YX_MOW_FIXED32 || type == YX_MOW_SFIXED32)
    return 5;
  return 0;
}
static bool yx_mo_decode_scalar(yx_mo_value *value,
                                const yx_mo_wire_field *field,
                                const uint8_t *data, size_t size, size_t *at,
                                yx_mo_decode *ctx, unsigned depth, uint64_t logical_size) {
  uint64_t number = 0;
  unsigned wire = yx_mo_wire(field->type);
  if (wire == 0) {
    size_t start = *at;
    if (!yx_mo_varint(data, size, at, &number))
      return yx_mo_error(ctx, *at == size && *at - start < 10 ?
                              "Unexpected EOF" : "Incorrect varint");
    if (field->type == YX_MOW_INT32 && number > INT32_MAX &&
        number < UINT64_MAX - INT32_MAX) {
      if (ctx->error && ctx->capacity)
        snprintf(ctx->error, ctx->capacity, "Value too large for i32: %" PRId64,
                 (int64_t)number);
      return false;
    }
    if (field->type == YX_MOW_UINT32)
      number = (uint32_t)number;
    if (field->type == YX_MOW_BOOL)
      number = number != 0;
    if (field->type == YX_MOW_SINT32)
      number = (uint64_t)(int64_t)(int32_t)(((uint32_t)number >> 1) ^
                                            -(int32_t)(number & 1));
    if (field->type == YX_MOW_SINT64)
      number = (number >> 1) ^ (uint64_t)-(int64_t)(number & 1);
    value->number = number;
    value->present = true;
    return true;
  }
  if (wire == 1 || wire == 5) {
    size_t bytes = wire == 1 ? 8 : 4;
    if (bytes > size - *at)
      return yx_mo_error(ctx, "Unexpected EOF");
    for (size_t i = 0; i < bytes; ++i)
      number |= (uint64_t)data[(*at)++] << (8 * i);
    if (field->type == YX_MOW_DOUBLE)
      memcpy(&value->floating, &number, 8);
    else if (field->type == YX_MOW_FLOAT) {
      uint32_t n = (uint32_t)number;
      float f;
      memcpy(&f, &n, 4);
      value->floating = f;
    } else
      value->number = field->type == YX_MOW_SFIXED32
                          ? (uint64_t)(int64_t)(int32_t)number
                          : number;
    value->present = true;
    return true;
  }
  size_t length_start = *at;
  if (!yx_mo_varint(data, size, at, &number))
    return yx_mo_error(ctx, *at == size && *at - length_start < 10 ?
                            "Unexpected EOF" : "Incorrect varint");
  if (field->type == YX_MOW_MESSAGE && number > logical_size - *at)
    return yx_mo_error(ctx, "New limit must not be greater than current limit");
  if (number > size - *at && field->type != YX_MOW_MESSAGE)
    return yx_mo_error(ctx, "Unexpected EOF");
  size_t length = number > size - *at ? size - *at : (size_t)number;
  const uint8_t *bytes = data + *at;
  *at += length;
  if (field->type == YX_MOW_MESSAGE) {
    /* The upstream output setter replaces singular message occurrences. */
    yx_mo_output_destroy(value->record);
    value->record = yx_mo_record_new(field->child);
    if (!value->record)
      return yx_mo_error(ctx, "out of memory");
    value->present = true;
    bool success = yx_mo_decode_record(value->record, bytes, length, ctx, depth + 1, (field->flags & 1) != 0, number);
    if (!success) ctx->nested_failure = true;
    return success;
  }
  if (!(field->flags & 4) && !yx_mo_utf8(bytes, length))
    return yx_mo_error(ctx, "Invalid UTF-8 sequence");
  char *copy = malloc(length + 1);
  if (!copy)
    return yx_mo_error(ctx, "out of memory");
  if (length)
    memcpy(copy, bytes, length);
  copy[length] = 0;
  free(value->string);
  value->string = copy;
  value->length = length;
  value->present = true;
  return true;
}
static bool yx_mo_append_value(yx_mo_value *list, yx_mo_value *item,
                               yx_mo_decode *ctx) {
  if (list->count == SIZE_MAX / sizeof(*list->items))
    return yx_mo_error(ctx, "out of memory");
  yx_mo_value *grown = realloc(list->items, (list->count + 1) * sizeof(*grown));
  if (!grown)
    return yx_mo_error(ctx, "out of memory");
  list->items = grown;
  list->items[list->count++] = *item;
  memset(item, 0, sizeof(*item));
  return true;
}
static bool yx_mo_initialized(const yx_mo_record *record) {
  const yx_mo_wire_message *schema = &yx_mo_wire_messages[record->schema];
  for (size_t i = 0; i < schema->count; ++i) {
    const yx_mo_value *value = &record->fields[i];
    if ((schema->fields[i].flags & 16) && !value->present) return false;
    if (value->record && !yx_mo_initialized(value->record)) return false;
    for (size_t j = 0; j < value->count; ++j)
      if (value->items[j].record && !yx_mo_initialized(value->items[j].record)) return false;
  }
  return true;
}
static bool yx_mo_decode_record(yx_mo_record *record, const uint8_t *data,
                                size_t size, yx_mo_decode *ctx,
                                unsigned depth, bool verify, uint64_t logical_size) {
  const yx_mo_wire_message *schema = &yx_mo_wire_messages[record->schema];
  size_t at = 0;
  if (depth > 500)
    return yx_mo_error(ctx, "Recursion limit exceeded");
  while (at < size) {
    uint64_t tag;
    size_t tag_start = at;
    if (!yx_mo_varint(data, size, &at, &tag))
      return yx_mo_error(ctx, at == size && at - tag_start < 10 ?
                                 "Unexpected EOF" : "Incorrect varint");
    if (!(tag >> 3) || tag >> 3 > 0x1fffffff || (tag & 7) > 5)
      return yx_mo_error(ctx, "Incorrect tag");
    unsigned wire = (unsigned)(tag & 7);
    size_t f = 0;
    for (; f < schema->count; ++f)
      if (schema->fields[f].number == (tag >> 3))
        break;
    if (f == schema->count || (wire != yx_mo_wire(schema->fields[f].type) &&
                               !(wire == 2 && (schema->fields[f].flags & 1) &&
                                 yx_mo_wire(schema->fields[f].type) != 2))) {
      if (wire == 3 && at == size && strcmp(schema->name, "vt.MapEntry") == 0)
        continue;
      if (!yx_mo_skip(data, size, &at, wire, depth, ctx, logical_size))
        return false;
      continue;
    }
    const yx_mo_wire_field *field = &schema->fields[f];
    yx_mo_value *target = &record->fields[f];
    if (!(field->flags & 1)) {
      if (!yx_mo_decode_scalar(target, field, data, size, &at, ctx, depth, logical_size))
        return false;
      continue;
    }
    size_t stop = at;
    bool packed = wire == 2 && yx_mo_wire(field->type) != 2;
    if (packed) {
      uint64_t n;
      if (!yx_mo_varint(data, size, &at, &n) || n > size - at)
        return yx_mo_error(ctx, "Unexpected EOF");
      stop = at + (size_t)n;
    }
    do {
      yx_mo_value item = {0};
      if (packed && at == stop)
        break;
      if (!yx_mo_decode_scalar(&item, field, data, packed ? stop : size, &at,
                               ctx, depth, packed ? stop : logical_size)) {
        yx_mo_value_destroy(&item);
        return false;
      }
      if (field->flags & 2) {
        const yx_mo_value *key = &item.record->fields[0];
        bool replaced = false;
        for (size_t j = 0; j < target->count; ++j) {
          const yx_mo_value *old = &target->items[j].record->fields[0];
          bool string_key = yx_mo_wire_messages[field->child].fields[0].type == YX_MOW_STRING;
          if (string_key ? (old->length == key->length &&
              (!key->length || !memcmp(old->string, key->string, key->length))) :
              old->number == key->number) {
            yx_mo_value_destroy(&target->items[j]);
            target->items[j] = item;
            memset(&item, 0, sizeof(item));
            replaced = true;
            break;
          }
        }
        if (replaced)
          continue;
      }
      if (!yx_mo_append_value(target, &item, ctx)) {
        yx_mo_value_destroy(&item);
        return false;
      }
    } while (packed && at < stop);
  }
  if (verify && !yx_mo_initialized(record)) {
    if (ctx->error && ctx->capacity)
      snprintf(ctx->error, ctx->capacity, "Message `%s` is missing required fields",
               strrchr(schema->name, '.') ? strrchr(schema->name, '.') + 1 : schema->name);
    return false;
  }
  return true;
}
int yx_mo_module_index(const char *name) {
  if (!name) return -1;
#ifndef XXYARA_ENABLE_OLECF
  if (!strcmp(name, "olecf") || !strcmp(name, "olecf.Olecf")) return -1;
#endif
#ifndef XXYARA_ENABLE_MSI
  if (!strcmp(name, "msi") || !strcmp(name, "msi.Msi")) return -1;
#endif
#ifndef XXYARA_ENABLE_VBA
  if (!strcmp(name, "vba") || !strcmp(name, "vba.Vba")) return -1;
#endif
  for (size_t i = 0; i < YX_MO_MODULE_COUNT; ++i)
    if (!strcmp(name, yx_mo_modules[i].name) || !strcmp(name, yx_mo_modules[i].root_name))
      return (int)i;
  return -1;
}
yx_mo_record *yx_mo_empty_output(const char *module) {
  int index = yx_mo_module_index(module);
  yx_mo_record *record = index < 0 ? NULL : yx_mo_record_new(yx_mo_modules[index].root);
  if (record) record->descriptor_only = true;
  return record;
}
bool yx_mo_parse_output(const char *module, const uint8_t *data, size_t size, yx_mo_record **out,
                        char *error, size_t capacity, bool *nested_failure) {
  yx_mo_decode ctx = {error, capacity, false};
  if (nested_failure) *nested_failure = false;
  *out = NULL;
  int index = yx_mo_module_index(module);
  if (index < 0) return yx_mo_error(&ctx, "unknown module");
  yx_mo_record *record = yx_mo_record_new(yx_mo_modules[index].root);
  if (!record)
    return yx_mo_error(&ctx, "out of memory");
  if (!yx_mo_decode_record(record, data, size, &ctx, 0, true, UINT64_MAX)) {
    if (nested_failure) *nested_failure = ctx.nested_failure;
    yx_mo_output_destroy(record);
    return false;
  }
  *out = record;
  return true;
}
static void yx_mo_data_scalar(const yx_mo_wire_field *field,
                              const yx_mo_value *value, yx_mo_data *out) {
  if ((field->flags & 8) && field->type != YX_MOW_MESSAGE &&
      (!value || !value->present)) {
    out->type = YX_MO_DATA_UNDEFINED;
    return;
  }
  if (field->type == YX_MOW_STRING) {
    out->type = YX_MO_DATA_STRING;
    out->string = value && value->string ? value->string : "";
    out->length = value ? value->length : 0;
  } else if (field->type == YX_MOW_FLOAT || field->type == YX_MOW_DOUBLE) {
    out->type = YX_MO_DATA_FLOAT;
    out->floating = value ? value->floating : 0;
  } else if (field->type == YX_MOW_MESSAGE)
    out->type = YX_MO_DATA_STRUCT;
  else {
    out->type = YX_MO_DATA_INTEGER;
    out->number = value ? value->number : 0;
    out->is_unsigned = !(field->flags & 1) &&
        (field->type == YX_MOW_UINT64 || field->type == YX_MOW_FIXED64);
  }
}
bool yx_mo_output_get(const yx_mo_record *record, const char *path,
                      const yx_mo_key *keys, size_t key_count, bool element,
                      yx_mo_data *out) {
  if (!record || !path || !out) return false;
  unsigned schema = record->schema;
  size_t key = 0;
  bool unavailable = false;
  bool descriptor_only = record->descriptor_only;
  memset(out, 0, sizeof(*out));
  path = strchr(path, '.');
  if (!path) return false;
  ++path;
  while (*path) {
    size_t length = strcspn(path, ".");
    const yx_mo_wire_message *message = &yx_mo_wire_messages[schema];
    size_t f = 0;
    for (; f < message->count; ++f)
      if (!(message->fields[f].flags & 32) && strlen(message->fields[f].name) == length &&
          !memcmp(message->fields[f].name, path, length)) break;
    if (f == message->count) return false;
    const yx_mo_wire_field *field = &message->fields[f];
    const yx_mo_value *value = record ? &record->fields[f] : NULL;
    path += length;
    if (*path == '.') ++path;
    if (field->flags & 1) {
      /* A descriptor without a message carries one unknown record as the
       * element schema; primitive arrays and maps instead start empty. */
      bool deputy = descriptor_only && field->type == YX_MOW_MESSAGE && !(field->flags & 2);
      size_t count = deputy ? 1 : value ? value->count : 0;
      if (!*path || !strcmp(path, "len")) {
        if (unavailable) return true;
        out->type = (field->flags & 2) ? YX_MO_DATA_MAP : YX_MO_DATA_ARRAY;
        out->number = count;
        out->collection = value;
        return key == key_count;
      }
      if (key >= key_count) return false;
      size_t index = SIZE_MAX;
      if (field->flags & 2) {
        bool string_key = yx_mo_wire_messages[field->child].fields[0].type == YX_MOW_STRING;
        if (keys[key].is_string != string_key) return false;
        for (size_t j = 0; value && j < value->count; ++j) {
          const yx_mo_value *k = &value->items[j].record->fields[0];
          if (string_key ? (k->length == keys[key].length &&
              (!k->length || !memcmp(k->string, keys[key].string, k->length))) :
              k->number == keys[key].number) { index = j; break; }
        }
      } else if (!keys[key].is_string && keys[key].number <= SIZE_MAX)
        index = (size_t)keys[key].number;
      ++key;
      if (index >= count) { unavailable = true; value = NULL; }
      else value = deputy ? NULL : &value->items[index];
      if (field->flags & 2) {
        const yx_mo_wire_message *entry = &yx_mo_wire_messages[field->child];
        field = &entry->fields[1];
        value = value && value->record ? &value->record->fields[1] : NULL;
      }
      if (!strcmp(path, "value") &&
          (field->type != YX_MOW_MESSAGE || element)) {
        if (!unavailable) yx_mo_data_scalar(field, value, out);
        return key == key_count;
      }
    }
    if (!*path) {
      if (!unavailable) yx_mo_data_scalar(field, value, out);
      return key == key_count;
    }
    if (field->type != YX_MOW_MESSAGE) return false;
    schema = field->child;
    record = value ? value->record : NULL;
    descriptor_only = !record || record->descriptor_only;
  }
  return false;
}
bool yx_mo_map_item(const yx_mo_value *map, size_t index,
                    yx_mo_data *key, yx_mo_data *value) {
  if (!map || index >= map->count || !map->items[index].record) return false;
  const yx_mo_record *entry = map->items[index].record;
  const yx_mo_wire_message *schema = &yx_mo_wire_messages[entry->schema];
  memset(key, 0, sizeof(*key)); memset(value, 0, sizeof(*value));
  yx_mo_data_scalar(&schema->fields[0], &entry->fields[0], key);
  yx_mo_data_scalar(&schema->fields[1], &entry->fields[1], value);
  return true;
}
/* With `indexed`, a collection followed by a member is read through its
 * items, as after `pe.sections[0]`. */
static yx_mo_data_type yx_mo_schema_path_type_bool(const char *path,
                                                   bool indexed,
                                                   bool *boolean,
                                                   bool *module_known) {
  char module[32];
  size_t length;
  unsigned schema;
  int index;
  if (boolean) *boolean = false;
  if (module_known) *module_known = false;
  if (!path) return YX_MO_DATA_UNDEFINED;
  length = strcspn(path, ".");
  if (!path[length] || length >= sizeof(module)) return YX_MO_DATA_UNDEFINED;
  memcpy(module, path, length);
  module[length] = '\0';
  index = yx_mo_module_index(module);
  if (index < 0) return YX_MO_DATA_UNDEFINED;
  if (module_known) *module_known = true;
  schema = yx_mo_modules[index].root;
  path += length + 1;
  while (*path) {
    const yx_mo_wire_message *message = &yx_mo_wire_messages[schema];
    const yx_mo_wire_field *field = NULL;
    length = strcspn(path, ".");
    for (size_t f = 0; f < message->count; ++f)
      if (!(message->fields[f].flags & 32) && strlen(message->fields[f].name) == length &&
          !memcmp(message->fields[f].name, path, length)) {
        field = &message->fields[f];
        break;
      }
    if (!field) return YX_MO_DATA_UNDEFINED;
    path += length;
    /* A collection needs an index before any member. */
    if ((field->flags & 1) && indexed && *path) {
      if (field->flags & 2) field = &yx_mo_wire_messages[field->child].fields[1];
      if (field->type != YX_MOW_MESSAGE) return YX_MO_DATA_UNDEFINED;
      schema = field->child;
      ++path;
      continue;
    }
    if (field->flags & 1)
      return *path ? YX_MO_DATA_UNDEFINED :
             (field->flags & 2) ? YX_MO_DATA_MAP : YX_MO_DATA_ARRAY;
    if (!*path) {
      if (field->type == YX_MOW_MESSAGE) return YX_MO_DATA_STRUCT;
      if (field->type == YX_MOW_STRING) return YX_MO_DATA_STRING;
      if (field->type == YX_MOW_FLOAT || field->type == YX_MOW_DOUBLE)
        return YX_MO_DATA_FLOAT;
      if (boolean) *boolean = field->type == YX_MOW_BOOL;
      return YX_MO_DATA_INTEGER;
    }
    if (field->type != YX_MOW_MESSAGE) return YX_MO_DATA_UNDEFINED;
    schema = field->child;
    ++path;
  }
  return YX_MO_DATA_UNDEFINED;
}
yx_mo_data_type yx_mo_schema_path_type(const char *path) {
  return yx_mo_schema_path_type_bool(path, false, NULL, NULL);
}
static const char *yx_mo_wire_type_name(const yx_mo_wire_field *field) {
  if (field->type == YX_MOW_MESSAGE) return "struct";
  if (field->type == YX_MOW_STRING) return "string";
  if (field->type == YX_MOW_FLOAT || field->type == YX_MOW_DOUBLE) return "float";
  return field->type == YX_MOW_BOOL ? "boolean" : "integer";
}
bool yx_mo_schema_collection_types(const char *path, const char **key,
                                   const char **item) {
  char module[32];
  size_t length;
  unsigned schema;
  int index;
  *key = *item = NULL;
  if (!path) return false;
  length = strcspn(path, ".");
  if (!path[length] || length >= sizeof(module)) return false;
  memcpy(module, path, length);
  module[length] = '\0';
  index = yx_mo_module_index(module);
  if (index < 0) return false;
  schema = yx_mo_modules[index].root;
  path += length + 1;
  while (*path) {
    const yx_mo_wire_message *message = &yx_mo_wire_messages[schema];
    const yx_mo_wire_field *field = NULL;
    length = strcspn(path, ".");
    for (size_t f = 0; f < message->count; ++f)
      if (!(message->fields[f].flags & 32) && strlen(message->fields[f].name) == length &&
          !memcmp(message->fields[f].name, path, length)) {
        field = &message->fields[f];
        break;
      }
    if (!field) return false;
    path += length;
    if (!*path) {
      if (!(field->flags & 1)) return false;
      if (field->flags & 2) {
        *key = yx_mo_wire_type_name(&yx_mo_wire_messages[field->child].fields[0]);
        field = &yx_mo_wire_messages[field->child].fields[1];
      }
      *item = yx_mo_wire_type_name(field);
      return true;
    }
    /* A collection before a member is read through its items. */
    if ((field->flags & 1) && (field->flags & 2))
      field = &yx_mo_wire_messages[field->child].fields[1];
    if (field->type != YX_MOW_MESSAGE) return false;
    schema = field->child;
    ++path;
  }
  return false;
}
const char *yx_mo_schema_element_type_name(const char *path) {
  const char *key, *item;
  return yx_mo_schema_collection_types(path, &key, &item) ? item : NULL;
}
bool yx_mo_schema_integer_range(const char *path, bool item, int64_t *minimum,
                                uint64_t *maximum) {
  char module[32];
  const char *full = path;
  size_t length;
  unsigned schema;
  int index;
  if (!path) return false;
  length = strcspn(path, ".");
  if (!path[length] || length >= sizeof(module)) return false;
  memcpy(module, path, length);
  module[length] = '\0';
  index = yx_mo_module_index(module);
  if (index < 0) return false;
  schema = yx_mo_modules[index].root;
  path += length + 1;
  while (*path) {
    const yx_mo_wire_message *message = &yx_mo_wire_messages[schema];
    const yx_mo_wire_field *field = NULL;
    length = strcspn(path, ".");
    for (size_t f = 0; f < message->count; ++f)
      if (!(message->fields[f].flags & 32) && strlen(message->fields[f].name) == length &&
          !memcmp(message->fields[f].name, path, length)) {
        field = &message->fields[f];
        break;
      }
    if (!field) return false;
    path += length;
    if (!*path) {
      if (item != ((field->flags & 1) != 0)) return false;
      if (item && (field->flags & 2)) field = &yx_mo_wire_messages[field->child].fields[1];
      switch (field->type) {
      case YX_MOW_UINT32: case YX_MOW_FIXED32:
        *minimum = 0; *maximum = UINT32_MAX; return true;
      case YX_MOW_SINT32: case YX_MOW_SFIXED32:
        *minimum = INT32_MIN; *maximum = INT32_MAX; return true;
      case YX_MOW_INT32:
        /* The schema stores enumerations as int32; YARA-X reads them as
         * int64. vba.module_count is the one int32 field of the modules. */
        if (strcmp(full, "vba.module_count") == 0) {
          *minimum = INT32_MIN; *maximum = INT32_MAX;
        } else {
          *minimum = INT64_MIN; *maximum = INT64_MAX;
        }
        return true;
      case YX_MOW_INT64: case YX_MOW_SINT64: case YX_MOW_SFIXED64:
        *minimum = INT64_MIN; *maximum = INT64_MAX; return true;
      case YX_MOW_UINT64: case YX_MOW_FIXED64:
        *minimum = 0; *maximum = UINT64_MAX; return true;
      default:
        return false;
      }
    }
    /* A collection before a member is read through its items. */
    if ((field->flags & 1) && (field->flags & 2))
      field = &yx_mo_wire_messages[field->child].fields[1];
    if (field->type != YX_MOW_MESSAGE) return false;
    schema = field->child;
    ++path;
  }
  return false;
}
const char *yx_mo_schema_path_type_name(const char *path, bool indexed,
                                        bool *module_known) {
  bool boolean;
  switch (yx_mo_schema_path_type_bool(path, indexed, &boolean, module_known)) {
  case YX_MO_DATA_INTEGER: return boolean ? "boolean" : "integer";
  case YX_MO_DATA_FLOAT: return "float";
  case YX_MO_DATA_STRING: return "string";
  case YX_MO_DATA_ARRAY: return "array";
  case YX_MO_DATA_MAP: return "map";
  case YX_MO_DATA_STRUCT: return "struct";
  default: return NULL;
  }
}
