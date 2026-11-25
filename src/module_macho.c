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

#include "module_macho.h"

/* The YARA-X-exact Mach-O parsing moved to xxfclib (xx_macho_yx.h); the
 * private parsing copy (fat flattening, load commands, entry point, version
 * formatters, code-signature extras, symhash collector) was removed from
 * this file. */

bool yx_macho_field_supported(const char *member)
{
    return xx_macho_yx_field_supported(member);
}

bool yx_macho_field(const uint8_t *data, size_t size, const char *member, uint64_t *value)
{
    return xx_macho_yx_field(data, size, member, value);
}

bool yx_macho_top_file_span(const uint8_t *data, size_t size, const uint8_t **bytes, size_t *length)
{
    return xx_macho_yx_top_file_span(data, size, bytes, length);
}

bool yx_macho_file_span(const uint8_t *data, size_t size, uint64_t index, const uint8_t **bytes, size_t *length)
{
    return xx_macho_yx_file_span(data, size, index, bytes, length);
}

bool yx_macho_string_field_supported(const char *member)
{
    return xx_macho_yx_string_field_supported(member);
}

bool yx_macho_string_field(const uint8_t *data, size_t size, const char *member, const uint8_t **bytes, size_t *length)
{
    return xx_macho_yx_string_field(data, size, member, bytes, length);
}

bool yx_macho_source_version(const uint8_t *data, size_t size, char *buffer, size_t capacity, size_t *length)
{
    return xx_macho_yx_source_version(data, size, buffer, capacity, length);
}

bool yx_macho_file_source_version(const uint8_t *data, size_t size, uint64_t index, char *buffer, size_t capacity, size_t *length)
{
    return xx_macho_yx_file_source_version(data, size, index, buffer, capacity, length);
}

bool yx_macho_uuid(const uint8_t *data, size_t size, char *buffer, size_t capacity, size_t *length)
{
    return xx_macho_yx_uuid(data, size, buffer, capacity, length);
}

bool yx_macho_file_uuid(const uint8_t *data, size_t size, uint64_t index, char *buffer, size_t capacity, size_t *length)
{
    return xx_macho_yx_file_uuid(data, size, index, buffer, capacity, length);
}

bool yx_macho_text_field_supported(const char *member)
{
    return xx_macho_yx_text_field_supported(member);
}

bool yx_macho_text_field(const uint8_t *data, size_t size, const char *member, char *buffer, size_t capacity, size_t *length)
{
    return xx_macho_yx_text_field(data, size, member, buffer, capacity, length);
}

bool yx_macho_indexed_text_field_supported(const char *collection, const char *member)
{
    return xx_macho_yx_indexed_text_field_supported(collection, member);
}

bool yx_macho_indexed_text_field(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, char *buffer, size_t capacity,
                                 size_t *length)
{
    return xx_macho_yx_indexed_text_field(data, size, collection, index, member, buffer, capacity, length);
}

bool yx_macho_file_dylib_version(const uint8_t *data, size_t size, uint64_t file_index, uint64_t dylib_index, const char *member, char *buffer, size_t capacity,
                                 size_t *length)
{
    return xx_macho_yx_file_dylib_version(data, size, file_index, dylib_index, member, buffer, capacity, length);
}

bool yx_macho_file_dylib_name(const uint8_t *data, size_t size, uint64_t file_index, uint64_t dylib_index, const uint8_t **bytes, size_t *length)
{
    return xx_macho_yx_file_dylib_name(data, size, file_index, dylib_index, bytes, length);
}

bool yx_macho_file_build_tool_field(const uint8_t *data, size_t size, uint64_t file_index, uint64_t tool_index, const char *member, uint64_t *value)
{
    return xx_macho_yx_file_build_tool_field(data, size, file_index, tool_index, member, value);
}

bool yx_macho_file_build_tool_version(const uint8_t *data, size_t size, uint64_t file_index, uint64_t tool_index, char *buffer, size_t capacity, size_t *length)
{
    return xx_macho_yx_file_build_tool_version(data, size, file_index, tool_index, buffer, capacity, length);
}

bool yx_macho_constant(const char *member, uint64_t *value)
{
    return xx_macho_yx_constant(member, value);
}

bool yx_macho_collection_supported(const char *member)
{
    return xx_macho_yx_collection_supported(member);
}

bool yx_macho_collection_count(const uint8_t *data, size_t size, const char *member, uint64_t *count)
{
    return xx_macho_yx_collection_count(data, size, member, count);
}

bool yx_macho_fat_arch_field_supported(const char *member)
{
    return xx_macho_yx_fat_arch_field_supported(member);
}

bool yx_macho_fat_arch_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value)
{
    return xx_macho_yx_fat_arch_field(data, size, index, member, value);
}

bool yx_macho_indexed_field_supported(const char *collection, const char *member)
{
    return xx_macho_yx_indexed_field_supported(collection, member);
}

bool yx_macho_indexed_field(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, uint64_t *value)
{
    return xx_macho_yx_indexed_field(data, size, collection, index, member, value);
}

bool yx_macho_indexed_string_field_supported(const char *collection, const char *member)
{
    return xx_macho_yx_indexed_string_field_supported(collection, member);
}

bool yx_macho_indexed_string_field(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, const uint8_t **bytes, size_t *length)
{
    return xx_macho_yx_indexed_string_field(data, size, collection, index, member, bytes, length);
}

bool yx_macho_nested_collection_count(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, uint64_t *count)
{
    return xx_macho_yx_nested_collection_count(data, size, collection, index, member, count);
}

bool yx_macho_section_field_supported(const char *member)
{
    return xx_macho_yx_section_field_supported(member);
}

bool yx_macho_section_field(const uint8_t *data, size_t size, uint64_t segment_index, uint64_t section_index, const char *member, uint64_t *value)
{
    return xx_macho_yx_section_field(data, size, segment_index, section_index, member, value);
}

bool yx_macho_section_string_field_supported(const char *member)
{
    return xx_macho_yx_section_string_field_supported(member);
}

bool yx_macho_section_string_field(const uint8_t *data, size_t size, uint64_t segment_index, uint64_t section_index, const char *member, const uint8_t **bytes,
                                   size_t *length)
{
    return xx_macho_yx_section_string_field(data, size, segment_index, section_index, member, bytes, length);
}

bool yx_macho_file_index_for_arch(const uint8_t *data, size_t size, uint64_t cputype, bool has_subtype, uint64_t cpusubtype, uint64_t *index)
{
    return xx_macho_yx_file_index_for_arch(data, size, cputype, has_subtype, cpusubtype, index);
}

bool yx_macho_has_dylib(const uint8_t *data, size_t size, const uint8_t *name, size_t name_length, bool *found)
{
    return xx_macho_yx_has_dylib(data, size, name, name_length, found);
}

bool yx_macho_has_rpath(const uint8_t *data, size_t size, const uint8_t *name, size_t name_length, bool *found)
{
    return xx_macho_yx_has_rpath(data, size, name, name_length, found);
}

bool yx_macho_entry_point_for_arch(const uint8_t *data, size_t size, uint64_t cputype, bool has_subtype, uint64_t cpusubtype, uint64_t *offset)
{
    return xx_macho_yx_entry_point_for_arch(data, size, cputype, has_subtype, cpusubtype, offset);
}

bool yx_macho_extras_parse(const uint8_t *data, size_t size, yx_macho_extras *result)
{
    return xx_macho_yx_extras_parse(data, size, result);
}

bool yx_macho_file_extras_parse(const uint8_t *data, size_t size, uint64_t index, yx_macho_extras *result)
{
    return xx_macho_yx_file_extras_parse(data, size, index, result);
}

void yx_macho_extras_free(yx_macho_extras *result)
{
    xx_macho_yx_extras_free(result);
}

bool yx_macho_symhash_input(const uint8_t *data, size_t size, uint8_t **bytes, size_t *length)
{
    return xx_macho_yx_symhash_input(data, size, bytes, length);
}
