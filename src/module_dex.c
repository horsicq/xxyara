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

#include "module_dex.h"

/* The YARA-X-exact DEX parsing moved to xxfclib (xx_dex_yx.h); this file
 * keeps the yx_dex_* module API as thin adapters. */

yx_dex_result *yx_dex_parse(const uint8_t *data, size_t size)
{
    return xx_dex_yx_parse(data, size);
}

void yx_dex_destroy(yx_dex_result *result)
{
    xx_dex_yx_destroy(result);
}

bool yx_dex_numeric_field_supported(const char *path)
{
    return xx_dex_yx_numeric_field_supported(path);
}

bool yx_dex_numeric_field(const yx_dex_result *result, const char *path, uint64_t *value)
{
    return xx_dex_yx_numeric_field(result, path, value);
}

bool yx_dex_string_field_supported(const char *path)
{
    return xx_dex_yx_string_field_supported(path);
}

bool yx_dex_string_field(const yx_dex_result *result, const char *path, const uint8_t **bytes, size_t *length)
{
    return xx_dex_yx_string_field(result, path, bytes, length);
}

bool yx_dex_constant(const char *name, uint64_t *value)
{
    return xx_dex_yx_constant(name, value);
}

bool yx_dex_collection_supported(const char *collection)
{
    return xx_dex_yx_collection_supported(collection);
}

bool yx_dex_collection_count(const yx_dex_result *result, const char *collection, uint64_t *count)
{
    return xx_dex_yx_collection_count(result, collection, count);
}

bool yx_dex_indexed_numeric_field_supported(const char *collection, const char *member)
{
    return xx_dex_yx_indexed_numeric_field_supported(collection, member);
}

bool yx_dex_indexed_numeric_field(const yx_dex_result *result, const char *collection, uint64_t index, const char *member, uint64_t *value)
{
    return xx_dex_yx_indexed_numeric_field(result, collection, index, member, value);
}

bool yx_dex_indexed_string_field_supported(const char *collection, const char *member)
{
    return xx_dex_yx_indexed_string_field_supported(collection, member);
}

bool yx_dex_indexed_string_field(const yx_dex_result *result, const char *collection, uint64_t index, const char *member, const uint8_t **bytes, size_t *length)
{
    return xx_dex_yx_indexed_string_field(result, collection, index, member, bytes, length);
}

bool yx_dex_nested_collection_count(const yx_dex_result *result, const char *collection, uint64_t index, const char *nested, uint64_t *count)
{
    return xx_dex_yx_nested_collection_count(result, collection, index, nested, count);
}

bool yx_dex_nested_indexed_string(const yx_dex_result *result, const char *collection, uint64_t index, const char *nested, uint64_t nested_index, const uint8_t **bytes,
                                  size_t *length)
{
    return xx_dex_yx_nested_indexed_string(result, collection, index, nested, nested_index, bytes, length);
}

bool yx_dex_contains_string(const yx_dex_result *result, const uint8_t *bytes, size_t length, bool *found)
{
    return xx_dex_yx_contains_string(result, bytes, length, found);
}

bool yx_dex_contains_method(const yx_dex_result *result, const uint8_t *bytes, size_t length, bool *found)
{
    return xx_dex_yx_contains_method(result, bytes, length, found);
}

bool yx_dex_contains_class(const yx_dex_result *result, const uint8_t *bytes, size_t length, bool *found)
{
    return xx_dex_yx_contains_class(result, bytes, length, found);
}

bool yx_dex_checksum(const yx_dex_result *result, uint64_t *value)
{
    return xx_dex_yx_checksum(result, value);
}

bool yx_dex_signature(const yx_dex_result *result, char out[41])
{
    return xx_dex_yx_signature(result, out);
}
