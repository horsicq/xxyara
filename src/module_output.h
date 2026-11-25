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

#ifndef XXYARA_MODULE_OUTPUT_H
#define XXYARA_MODULE_OUTPUT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct yx_mo_record yx_mo_record;
typedef struct yx_mo_value yx_mo_value;
typedef struct {
    const char *string;
    size_t length;
    uint64_t number;
    bool is_string;
} yx_mo_key;
typedef enum {
    YX_MO_DATA_UNDEFINED,
    YX_MO_DATA_INTEGER,
    YX_MO_DATA_FLOAT,
    YX_MO_DATA_STRING,
    YX_MO_DATA_ARRAY,
    YX_MO_DATA_MAP,
    YX_MO_DATA_STRUCT
} yx_mo_data_type;
typedef struct {
    yx_mo_data_type type;
    uint64_t number;
    bool is_unsigned;
    double floating;
    const char *string;
    size_t length;
    const yx_mo_value *collection;
} yx_mo_data;
enum {
    YX_MO_MODULE_COUNT = 13,
    YX_MO_FUNCTION_CACHE_COUNT = 9
};
typedef struct {
    bool defined;
    bool string;
    uint64_t number;
    size_t length;
    char bytes[72];
} yx_mo_function_cache;
int yx_mo_module_index(const char *name);
yx_mo_record *yx_mo_empty_output(const char *module);
bool yx_mo_parse_output(const char *module, const uint8_t *data, size_t size, yx_mo_record **out, char *error, size_t error_capacity, bool *nested_failure);
void yx_mo_output_destroy(yx_mo_record *output);
bool yx_mo_output_get(const yx_mo_record *output, const char *path, const yx_mo_key *keys, size_t key_count, bool element, yx_mo_data *out);
bool yx_mo_map_item(const yx_mo_value *map, size_t index, yx_mo_data *key, yx_mo_data *value);
/* The schema type of an unindexed module path such as `pe.overlay`
 * (YX_MO_DATA_STRUCT, _ARRAY, _MAP, _INTEGER, _FLOAT or _STRING);
 * YX_MO_DATA_UNDEFINED when the path is not a field. */
yx_mo_data_type yx_mo_schema_path_type(const char *path);
/* The YARA-X type name of a schema path ("integer", "boolean", "struct"...),
 * or NULL when the schema lacks it. With `indexed`, a collection followed by
 * a member is read through its items. *module_known (optional) tells whether
 * the path's module has a schema. */
const char *yx_mo_schema_path_type_name(const char *path, bool indexed, bool *module_known);
/* The YARA-X type name of the items of the array or map (its values) at a
 * schema path, NULL when the path is no collection in a module schema.
 * Collections before the path's last member are read through their items. */
const char *yx_mo_schema_element_type_name(const char *path);
/* The type names of the keys (NULL for an array) and the items of the
 * collection at a schema path, read like yx_mo_schema_element_type_name.
 * False when the path is no collection. */
bool yx_mo_schema_collection_types(const char *path, const char **key, const char **item);
/* The range of the integer field at a schema path as YARA-X types it
 * (TypeValue::integer_range): uint32 [0, 2^32-1], int32 [-2^31, 2^31-1],
 * uint64 [0, 2^64-1], int64 and enumerations the int64 range. With `item`
 * the path is a collection and the range is its items'. False when the
 * path is no integer field. */
bool yx_mo_schema_integer_range(const char *path, bool item, int64_t *minimum, uint64_t *maximum);
#endif
