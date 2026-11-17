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

#ifndef XXYARA_MODULE_DEX_H
#define XXYARA_MODULE_DEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/executable/dex/xx_dex_yx.h>

/* The YARA-X-exact DEX parsing moved to xxfclib (xx_dex_yx.h,
 * src/formats/executable/dex/xx_dex_yx.c). The opaque result type and the
 * functions below keep the yx_dex_* module API as thin adapters; the private
 * parsing copy (header validation, lazy collection tables, MUTF-8 decoder,
 * map_list handling, contains_* predicates) was removed from module_dex.c. */

typedef xx_dex_yx_result yx_dex_result;

/* Returns a result for both DEX and non-DEX data; NULL means an invalid
   argument or allocation failure. data must outlive the result: strings,
   types, protos, fields, methods and class_defs are parsed on first access
   and valid UTF-8 strings point into data. Borrowed string pointers stay
   valid until yx_dex_destroy. The caller can parse once per scan and share
   the result across condition evaluations of that scan; the accessors fill
   the lazy collections, so one result must not be used by two threads at
   once. A collection whose lazy parse fails to allocate reads as
   undefined. */
yx_dex_result *yx_dex_parse(const uint8_t *data, size_t size);
void yx_dex_destroy(yx_dex_result *result);

/* Names are relative to the `dex.` module prefix. Optional values return
   false when absent, while `is_dex` and repeated-field lengths are defined
   even for arbitrary non-DEX input. */
bool yx_dex_numeric_field_supported(const char *path);
bool yx_dex_numeric_field(const yx_dex_result *result, const char *path,
                          uint64_t *value);
bool yx_dex_string_field_supported(const char *path);
bool yx_dex_string_field(const yx_dex_result *result, const char *path,
                         const uint8_t **bytes, size_t *length);
bool yx_dex_constant(const char *name, uint64_t *value);

/* Collection names: strings, types, protos, fields, methods, class_defs,
   and map_list.items. Scalar strings/types use the synthetic member `value`
   for integration with the condition evaluator's indexed-field model.
   YARA-X exposes map_list.items.len() == 1 when map_list is absent, although
   all fields of that placeholder item are undefined. */
bool yx_dex_collection_supported(const char *collection);
bool yx_dex_collection_count(const yx_dex_result *result,
                              const char *collection, uint64_t *count);
bool yx_dex_indexed_numeric_field_supported(const char *collection,
                                              const char *member);
bool yx_dex_indexed_numeric_field(const yx_dex_result *result,
                                   const char *collection, uint64_t index,
                                   const char *member, uint64_t *value);
bool yx_dex_indexed_string_field_supported(const char *collection,
                                             const char *member);
bool yx_dex_indexed_string_field(const yx_dex_result *result,
                                  const char *collection, uint64_t index,
                                  const char *member,
                                  const uint8_t **bytes, size_t *length);

/* Nested arrays are `protos[i].parameters[j]` and
   `methods[i].proto.parameters[j]`. The nested member is `parameters` or
   `proto.parameters`, respectively. */
bool yx_dex_nested_collection_count(const yx_dex_result *result,
                                      const char *collection, uint64_t index,
                                      const char *nested, uint64_t *count);
bool yx_dex_nested_indexed_string(const yx_dex_result *result,
                                    const char *collection, uint64_t index,
                                    const char *nested, uint64_t nested_index,
                                    const uint8_t **bytes, size_t *length);

/* Exported module functions. Predicates are defined as false for non-DEX
   input. checksum/signature are undefined on non-DEX input. The SHA-1 digest
   and header signature are lowercase hexadecimal strings. */
bool yx_dex_contains_string(const yx_dex_result *result,
                             const uint8_t *bytes, size_t length,
                             bool *found);
bool yx_dex_contains_method(const yx_dex_result *result,
                             const uint8_t *bytes, size_t length,
                             bool *found);
bool yx_dex_contains_class(const yx_dex_result *result,
                            const uint8_t *bytes, size_t length,
                            bool *found);
bool yx_dex_checksum(const yx_dex_result *result, uint64_t *value);
bool yx_dex_signature(const yx_dex_result *result, char out[41]);

#endif
