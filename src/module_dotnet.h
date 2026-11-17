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

#ifndef XXYARA_MODULE_DOTNET_H
#define XXYARA_MODULE_DOTNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/executable/dotnet/xx_dotnet_yx.h>

/* The YARA-X-exact .NET parsing moved to xxfclib (xx_dotnet_yx.h); this
 * header keeps the yx_dotnet_* module API as typedef aliases and thin adapter
 * declarations so condition.c, cli_dump.c and the tests do not change. */
typedef xx_dotnet_yx_stream yx_dotnet_stream;
typedef xx_dotnet_yx_version yx_dotnet_version;
typedef xx_dotnet_yx_assembly yx_dotnet_assembly;
typedef xx_dotnet_yx_assembly_ref yx_dotnet_assembly_ref;
typedef xx_dotnet_yx_resource yx_dotnet_resource;
typedef xx_dotnet_yx_class yx_dotnet_class;
typedef xx_dotnet_yx_method yx_dotnet_method;
typedef xx_dotnet_yx_method_parameter yx_dotnet_method_parameter;
typedef xx_dotnet_yx_result yx_dotnet_result;

bool yx_dotnet_parse(const uint8_t *data, size_t size,
                     yx_dotnet_result *result);
bool yx_dotnet_guid_at(const uint8_t *data, size_t size,
                       const yx_dotnet_result *result, size_t index,
                       char text[37]);
bool yx_dotnet_user_string_at(const uint8_t *data, size_t size,
                              const yx_dotnet_result *result, size_t index,
                              const uint8_t **bytes, size_t *length);
bool yx_dotnet_assembly_ref_at(const yx_dotnet_result *result, size_t index,
                               yx_dotnet_assembly_ref *out);
bool yx_dotnet_module_ref_at(const yx_dotnet_result *result, size_t index,
                             const uint8_t **name, size_t *length);
bool yx_dotnet_constant_at(const yx_dotnet_result *result, size_t index,
                           const uint8_t **bytes, size_t *length);
bool yx_dotnet_field_offset_at(const uint8_t *data, size_t size,
                               const yx_dotnet_result *result, size_t index,
                               uint32_t *offset);
bool yx_dotnet_resource_at(const yx_dotnet_result *result, size_t index,
                           yx_dotnet_resource *out);
bool yx_dotnet_class_at(const yx_dotnet_result *result, size_t index,
                        char *fullname_buffer, size_t buffer_capacity,
                        yx_dotnet_class *out);
bool yx_dotnet_class_raw_index(const yx_dotnet_result *result,
                               size_t class_index, size_t *raw_index);
bool yx_dotnet_type_def_or_ref_fullname(
    const yx_dotnet_result *result, uint16_t coded, char *buffer,
    size_t capacity, size_t *required, size_t *length);
bool yx_dotnet_class_generic_parameter_at(
    const yx_dotnet_result *result, size_t class_index,
    size_t parameter_index, const uint8_t **name, size_t *length);
bool yx_dotnet_class_base_type_at(const yx_dotnet_result *result,
                                  size_t class_index, size_t base_index,
                                  char *buffer, size_t buffer_capacity,
                                  size_t *required_capacity, size_t *length);

size_t yx_dotnet_class_method_count(const yx_dotnet_result *result,
                                    size_t class_index);
bool yx_dotnet_class_method_at(const yx_dotnet_result *result,
                               size_t class_index, size_t method_index,
                               char *return_type_buffer,
                               size_t buffer_capacity, yx_dotnet_method *out);
bool yx_dotnet_method_parameter_at(const yx_dotnet_result *result,
                                   const yx_dotnet_method *method,
                                   size_t parameter_index, char *type_buffer,
                                   size_t buffer_capacity,
                                   yx_dotnet_method_parameter *out);
bool yx_dotnet_method_generic_parameter_at(
    const yx_dotnet_result *result, const yx_dotnet_method *method,
    size_t parameter_index, const uint8_t **name, size_t *length);
bool yx_dotnet_type_spec_fullname(const yx_dotnet_result *result,
                                  size_t raw_type_spec_index,
                                  size_t class_index, char *buffer,
                                  size_t buffer_capacity,
                                  size_t *required_capacity, size_t *length);

#endif
