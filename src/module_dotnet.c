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

#include "module_dotnet.h"

/* The YARA-X-exact .NET parsing moved to xxfclib (xx_dotnet_yx.h); this file
 * keeps the yx_dotnet_* module API as thin adapters, including the method
 * signature helpers that used to live in module_dotnet_method.c. */

bool yx_dotnet_parse(const uint8_t *data, size_t size,
                     yx_dotnet_result *result)
{
    return xx_dotnet_yx_parse(data, size, result);
}

bool yx_dotnet_guid_at(const uint8_t *data, size_t size,
                       const yx_dotnet_result *result, size_t index,
                       char text[37])
{
    return xx_dotnet_yx_guid_at(data, size, result, index, text);
}

bool yx_dotnet_user_string_at(const uint8_t *data, size_t size,
                              const yx_dotnet_result *result, size_t index,
                              const uint8_t **bytes, size_t *length)
{
    return xx_dotnet_yx_user_string_at(data, size, result, index, bytes,
                                       length);
}

bool yx_dotnet_assembly_ref_at(const yx_dotnet_result *result, size_t index,
                               yx_dotnet_assembly_ref *out)
{
    return xx_dotnet_yx_assembly_ref_at(result, index, out);
}

bool yx_dotnet_module_ref_at(const yx_dotnet_result *result, size_t index,
                             const uint8_t **name, size_t *length)
{
    return xx_dotnet_yx_module_ref_at(result, index, name, length);
}

bool yx_dotnet_constant_at(const yx_dotnet_result *result, size_t index,
                           const uint8_t **bytes, size_t *length)
{
    return xx_dotnet_yx_constant_at(result, index, bytes, length);
}

bool yx_dotnet_field_offset_at(const uint8_t *data, size_t size,
                               const yx_dotnet_result *result, size_t index,
                               uint32_t *offset)
{
    return xx_dotnet_yx_field_offset_at(data, size, result, index, offset);
}

bool yx_dotnet_resource_at(const yx_dotnet_result *result, size_t index,
                           yx_dotnet_resource *out)
{
    return xx_dotnet_yx_resource_at(result, index, out);
}

bool yx_dotnet_class_at(const yx_dotnet_result *result, size_t index,
                        char *fullname_buffer, size_t buffer_capacity,
                        yx_dotnet_class *out)
{
    return xx_dotnet_yx_class_at(result, index, fullname_buffer,
                                 buffer_capacity, out);
}

bool yx_dotnet_class_raw_index(const yx_dotnet_result *result,
                               size_t class_index, size_t *raw_index)
{
    return xx_dotnet_yx_class_raw_index(result, class_index, raw_index);
}

bool yx_dotnet_type_def_or_ref_fullname(
    const yx_dotnet_result *result, uint16_t coded, char *buffer,
    size_t capacity, size_t *required, size_t *length)
{
    return xx_dotnet_yx_type_def_or_ref_fullname(result, coded, buffer,
                                                 capacity, required, length);
}

bool yx_dotnet_class_generic_parameter_at(
    const yx_dotnet_result *result, size_t class_index,
    size_t parameter_index, const uint8_t **name, size_t *length)
{
    return xx_dotnet_yx_class_generic_parameter_at(result, class_index,
                                                   parameter_index, name,
                                                   length);
}

bool yx_dotnet_class_base_type_at(const yx_dotnet_result *result,
                                  size_t class_index, size_t base_index,
                                  char *buffer, size_t buffer_capacity,
                                  size_t *required_capacity, size_t *length)
{
    return xx_dotnet_yx_class_base_type_at(result, class_index, base_index,
                                           buffer, buffer_capacity,
                                           required_capacity, length);
}

size_t yx_dotnet_class_method_count(const yx_dotnet_result *result,
                                    size_t class_index)
{
    return xx_dotnet_yx_class_method_count(result, class_index);
}

bool yx_dotnet_class_method_at(const yx_dotnet_result *result,
                               size_t class_index, size_t method_index,
                               char *return_type_buffer,
                               size_t buffer_capacity, yx_dotnet_method *out)
{
    return xx_dotnet_yx_class_method_at(result, class_index, method_index,
                                        return_type_buffer, buffer_capacity,
                                        out);
}

bool yx_dotnet_method_parameter_at(const yx_dotnet_result *result,
                                   const yx_dotnet_method *method,
                                   size_t parameter_index, char *type_buffer,
                                   size_t buffer_capacity,
                                   yx_dotnet_method_parameter *out)
{
    return xx_dotnet_yx_method_parameter_at(result, method, parameter_index,
                                            type_buffer, buffer_capacity, out);
}

bool yx_dotnet_method_generic_parameter_at(
    const yx_dotnet_result *result, const yx_dotnet_method *method,
    size_t parameter_index, const uint8_t **name, size_t *length)
{
    return xx_dotnet_yx_method_generic_parameter_at(result, method,
                                                    parameter_index, name,
                                                    length);
}

bool yx_dotnet_type_spec_fullname(const yx_dotnet_result *result,
                                  size_t raw_type_spec_index,
                                  size_t class_index, char *buffer,
                                  size_t buffer_capacity,
                                  size_t *required_capacity, size_t *length)
{
    return xx_dotnet_yx_type_spec_fullname(result, raw_type_spec_index,
                                           class_index, buffer,
                                           buffer_capacity, required_capacity,
                                           length);
}
