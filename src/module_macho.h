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

#ifndef XXYARA_MODULE_MACHO_H
#define XXYARA_MODULE_MACHO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/executable/macho/xx_macho_yx.h>

/* The YARA-X-exact Mach-O parsing moved to xxfclib (xx_macho_yx.h,
 * src/formats/executable/macho/xx_macho_yx.c). The extras types keep their
 * yx_macho_ names as aliases so existing consumers are unchanged; the
 * function declarations below are the yx_macho_* module API, implemented as
 * thin adapters in module_macho.c. */

typedef xx_macho_yx_certificate yx_macho_certificate;
typedef xx_macho_yx_extras yx_macho_extras;

/* Public numeric fields from YARA-X 1.21's macho.Macho schema. A recognized
 * field is undefined (returns false) when the input is not a Mach-O file or
 * when the corresponding optional value was not present. */
bool yx_macho_field_supported(const char *member);
bool yx_macho_field(const uint8_t *data, size_t size, const char *member, uint64_t *value);

/* Byte range of the top-level Mach-O file. A fat archive exposes one child
 * at the top level when exactly one architecture parses successfully. The
 * returned range borrows the scanned buffer and is undefined otherwise. */
bool yx_macho_top_file_span(const uint8_t *data, size_t size, const uint8_t **bytes, size_t *length);
/* Exposed file[index] child span, for recursively applying ordinary accessors.
 * Undefined for thin files or a fat binary flattened to a single child. */
bool yx_macho_file_span(const uint8_t *data, size_t size, uint64_t index, const uint8_t **bytes, size_t *length);

/* Byte strings refer to the scanned input and remain valid for its lifetime. */
bool yx_macho_string_field_supported(const char *member);
bool yx_macho_string_field(const uint8_t *data, size_t size, const char *member, const uint8_t **bytes, size_t *length);

/* LC_SOURCE_VERSION is decoded to A.B.C.D.E in the caller's buffer. The
 * buffer must hold the terminating NUL; 32 bytes suffice for every value.
 * A missing command, hidden top-level file, or undersized buffer returns
 * false without modifying the buffer or length. */
bool yx_macho_source_version(const uint8_t *data, size_t size, char *buffer, size_t capacity, size_t *length);
bool yx_macho_file_source_version(const uint8_t *data, size_t size, uint64_t index, char *buffer, size_t capacity, size_t *length);

/* LC_UUID is formatted as uppercase hex with dashes. Its source bytes are
 * trimmed of trailing NULs by YARA-X; 37 bytes suffice for every value. */
bool yx_macho_uuid(const uint8_t *data, size_t size, char *buffer, size_t capacity, size_t *length);
bool yx_macho_file_uuid(const uint8_t *data, size_t size, uint64_t index, char *buffer, size_t capacity, size_t *length);

/* Generated text fields, including build/minimum OS versions and dylib
 * versions. The caller owns the NUL-terminated output; 37 bytes suffice for
 * all fields. On an undefined field or undersized buffer, outputs are
 * unchanged. Top-level names use a dotted path such as
 * "build_version.minos". Indexed names use collection "file" with a
 * top-level name, or "dylibs" with "current_version" or
 * "compatibility_version". */
bool yx_macho_text_field_supported(const char *member);
bool yx_macho_text_field(const uint8_t *data, size_t size, const char *member, char *buffer, size_t capacity, size_t *length);
bool yx_macho_indexed_text_field_supported(const char *collection, const char *member);
bool yx_macho_indexed_text_field(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, char *buffer, size_t capacity,
                                 size_t *length);
/* Nested dylib version strings under an indexed fat Mach-O file. */
bool yx_macho_file_dylib_version(const uint8_t *data, size_t size, uint64_t file_index, uint64_t dylib_index, const char *member, char *buffer, size_t capacity,
                                 size_t *length);
bool yx_macho_file_dylib_name(const uint8_t *data, size_t size, uint64_t file_index, uint64_t dylib_index, const uint8_t **bytes, size_t *length);

/* Build-tool fields: build_version.tools.len(), tools[i].tool, and
 * tools[i].version, including those under file[i] in fat binaries.
 * The indexed generic APIs use collection "build_version" and member
 * "tools.tool" or "tools.version". The nested file APIs take both indices.
 * Version output is caller-owned and NUL terminated; 16 bytes suffice. */
bool yx_macho_file_build_tool_field(const uint8_t *data, size_t size, uint64_t file_index, uint64_t tool_index, const char *member, uint64_t *value);
bool yx_macho_file_build_tool_version(const uint8_t *data, size_t size, uint64_t file_index, uint64_t tool_index, char *buffer, size_t capacity, size_t *length);

/* Inline enum values from the public macho.proto. These are defined as soon
 * as the module is imported, independently of the scanned input. */
bool yx_macho_constant(const char *member, uint64_t *value);

/* Top-level repeated fields have a defined length, including zero for
 * non-Mach-O data. The nested build_version.tools.len() and symtab.nlists.len()
 * evaluate to one when their containing object is absent in YARA-X 1.21;
 * symtab.entries.len() is zero in that case. Fat archives with exactly
 * one successfully parsed child expose that child's collections at the top
 * level. */
bool yx_macho_collection_supported(const char *member);
bool yx_macho_collection_count(const uint8_t *data, size_t size, const char *member, uint64_t *count);

/* Public fat_arch descriptors are present only for fat archives whose
 * successfully parsed child count differs from one. The index is zero based. */
bool yx_macho_fat_arch_field_supported(const char *member);
bool yx_macho_fat_arch_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value);

/* One-index fields of segments, dylibs, build_version.tools, symtab, fat_arch, and
 * file. The latter is exposed only for fat archives with zero or multiple
 * parsed children. For symtab use numeric members "nlists.n_strx", "nlists.n_type",
 * "nlists.n_sect", "nlists.n_desc", "nlists.n_value" and string member
 * "entries.value"; both arrays enumerate retained nonempty symbol names. */
bool yx_macho_indexed_field_supported(const char *collection, const char *member);
bool yx_macho_indexed_field(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, uint64_t *value);
bool yx_macho_indexed_string_field_supported(const char *collection, const char *member);
bool yx_macho_indexed_string_field(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, const uint8_t **bytes, size_t *length);

/* Nested collection lengths and section fields under a top-level segment. */
bool yx_macho_nested_collection_count(const uint8_t *data, size_t size, const char *collection, uint64_t index, const char *member, uint64_t *count);
bool yx_macho_section_field_supported(const char *member);
bool yx_macho_section_field(const uint8_t *data, size_t size, uint64_t segment_index, uint64_t section_index, const char *member, uint64_t *value);
bool yx_macho_section_string_field_supported(const char *member);
bool yx_macho_section_string_field(const uint8_t *data, size_t size, uint64_t segment_index, uint64_t section_index, const char *member, const uint8_t **bytes,
                                   size_t *length);

/* Return the fat_arch index for a CPU type, optionally constrained by CPU
 * subtype. Undefined if the input has no exposed fat_arch array or no match. */
bool yx_macho_file_index_for_arch(const uint8_t *data, size_t size, uint64_t cputype, bool has_subtype, uint64_t cpusubtype, uint64_t *index);

/* These predicates are defined on all inputs and compare ASCII without
 * case, matching YARA-X's BStr comparison. */
bool yx_macho_has_dylib(const uint8_t *data, size_t size, const uint8_t *name, size_t name_length, bool *found);
bool yx_macho_has_rpath(const uint8_t *data, size_t size, const uint8_t *name, size_t name_length, bool *found);

/* Fat-archive entry offset plus a matching child's entry point. */
bool yx_macho_entry_point_for_arch(const uint8_t *data, size_t size, uint64_t cputype, bool has_subtype, uint64_t cpusubtype, uint64_t *offset);

/* Parsed code-signature, import, and export strings. All strings and arrays are
 * owned by the result, which must be released with yx_macho_extras_free.
 * A valid Mach-O with no such data returns an empty result. For a fat file
 * with multiple children, the top-level result is empty and the indexed
 * function accesses file[index]. An invalid input returns false and leaves
 * the result empty and free-safe. */

bool yx_macho_extras_parse(const uint8_t *data, size_t size, yx_macho_extras *result);
bool yx_macho_file_extras_parse(const uint8_t *data, size_t size, uint64_t index, yx_macho_extras *result);
void yx_macho_extras_free(yx_macho_extras *result);

/* The sorted, deduplicated, display-decoded symbol bytes used by macho.symhash().
 * Returns false (undefined) if no symbol-table entry was parsed. A table
 * with entries but no eligible undefined external symbol yields an empty
 * allocated buffer. The caller frees *bytes. */
bool yx_macho_symhash_input(const uint8_t *data, size_t size, uint8_t **bytes, size_t *length);

#endif
