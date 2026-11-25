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

#ifndef XXYARA_MODULE_PE_H
#define XXYARA_MODULE_PE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "xxfclib/formats/executable/pe/xx_pe_yx.h"

/* Returns the value of YARA-X v1.21.0's `pe.is_pe` for a scanned byte buffer. */
bool yx_pe_is_pe(const uint8_t *data, size_t size);

/* Scalar PE module members. A recognized field is defined only when the
 * reference PE module would expose a value for this input. Constants are
 * always defined once the module has been imported. */
bool yx_pe_field_supported(const char *member);
bool yx_pe_field(const uint8_t *data, size_t size, const char *member, uint64_t *value);
bool yx_pe_constant(const char *member, uint64_t *value);

/* Public data-directory entries, capped at the reference's 16 entries.
 * A truncated directory is exposed as an empty collection. */
bool yx_pe_data_directory_count(const uint8_t *data, size_t size, uint64_t *count);
bool yx_pe_data_directory_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value);

/* Rich raw bytes borrow the input. Clear bytes are allocated for the caller.
 * Absent rich_signature.tools.len() is one in the pinned reference; indexed
 * tools themselves remain undefined. */
bool yx_pe_rich_tool_count(const uint8_t *data, size_t size, uint64_t *count);
bool yx_pe_rich_tool_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value);
bool yx_pe_rich_clear_data(const uint8_t *data, size_t size, uint8_t **bytes, size_t *length);

/* The returned bytes point into `data` and remain valid for its lifetime.
 * `dll_name` is a UTF-8 string; `pdb_path` is an arbitrary byte string. */
bool yx_pe_string_field_supported(const char *member);
bool yx_pe_string_field(const uint8_t *data, size_t size, const char *member, const uint8_t **bytes, size_t *length);

/* A valid PE always has an overlay object. Both members are zero if no
 * trailing content follows the parsed sections. */
bool yx_pe_overlay(const uint8_t *data, size_t size, uint64_t *offset, uint64_t *length);

/* `sections` is a repeated field: its length is defined as zero on non-PE
 * data. Indexed members are undefined when the index is out of range.
 * String members point into `data` and may contain arbitrary bytes. */
bool yx_pe_section_count(const uint8_t *data, size_t size, uint64_t *count);
bool yx_pe_section_field_supported(const char *member);
bool yx_pe_section_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value);
bool yx_pe_section_string_field_supported(const char *member);
bool yx_pe_section_string_field(const uint8_t *data, size_t size, uint64_t index, const char *member, const uint8_t **bytes, size_t *length);

bool yx_pe_function_supported(const char *member);
bool yx_pe_function(const uint8_t *data, size_t size, const char *member, uint64_t *value);
bool yx_pe_rva_to_offset(const uint8_t *data, size_t size, uint64_t rva, uint64_t *value);
bool yx_pe_offset_to_rva(const uint8_t *data, size_t size, uint64_t offset, uint64_t *value);
bool yx_pe_section_index_name(const uint8_t *data, size_t size, const char *name, size_t name_length, uint64_t *value);
bool yx_pe_section_index_offset(const uint8_t *data, size_t size, uint64_t offset, uint64_t *value);
bool yx_pe_calculate_checksum(const uint8_t *data, size_t size, uint64_t *value);
bool yx_pe_exports(const uint8_t *data, size_t size, const char *name, size_t name_length, bool by_ordinal, uint64_t ordinal, bool *found, uint64_t *index);

typedef struct {
    const uint8_t *name;
    size_t name_length;
    uint32_t ordinal;
    uint32_t rva;
    bool has_offset;
    uint32_t offset;
    const uint8_t *forward_name;
    size_t forward_name_length;
} yx_pe_export;

typedef void (*yx_pe_export_visitor)(void *opaque, const yx_pe_export *entry);
bool yx_pe_visit_exports(const uint8_t *data, size_t size, yx_pe_export_visitor visitor, void *opaque);

/* The PE resource tree is traversed in the same breadth-first order as
 * YARA-X. Named identifiers are UTF-16LE bytes pointing into `data`.
 * The structs live in xxfclib (xx_pe_yx.h) and are aliased here. */
typedef xx_pe_yx_resource_id_kind yx_pe_resource_id_kind;
typedef xx_pe_yx_resource_id yx_pe_resource_id;
typedef xx_pe_yx_resource yx_pe_resource;
typedef xx_pe_yx_resource_directory yx_pe_resource_directory;
typedef xx_pe_yx_resource_visitor yx_pe_resource_visitor;
/* Enum constants keep their historical YX_PE_RESOURCE_* spellings. */
#define YX_PE_RESOURCE_UNKNOWN XX_PE_YX_RESOURCE_UNKNOWN
#define YX_PE_RESOURCE_NUMERIC XX_PE_YX_RESOURCE_NUMERIC
#define YX_PE_RESOURCE_NAMED XX_PE_YX_RESOURCE_NAMED
bool yx_pe_visit_resources(const uint8_t *data, size_t size, yx_pe_resource_directory *directory, yx_pe_resource_visitor visitor, void *opaque);

/* Version attributes are decoded as UTF-8. The pointers are valid only
 * during the callback. Duplicate keys are retained in file order. */
typedef xx_pe_yx_version_visitor yx_pe_version_visitor;
bool yx_pe_visit_version_info(const uint8_t *data, size_t size, yx_pe_version_visitor visitor, void *opaque);

typedef struct yx_pe_scan_cache yx_pe_scan_cache;
struct yx_scan_deadline;

typedef struct {
    char *key;
    size_t key_length;
    char *value;
    size_t value_length;
} yx_pe_version_entry;

/* Lazy scan-local indexes. Export/resource strings borrow the scan input;
 * version strings are copied from the parser's temporary callback buffers.
 * Changing the input replaces the cache. Destroy it before releasing input. */
const yx_pe_export *yx_pe_scan_cache_export(yx_pe_scan_cache **cache, const uint8_t *data, size_t size, uint64_t index, struct yx_scan_deadline *deadline);
const yx_pe_resource *yx_pe_scan_cache_resource(yx_pe_scan_cache **cache, const uint8_t *data, size_t size, uint64_t index, struct yx_scan_deadline *deadline);
const yx_pe_version_entry *yx_pe_scan_cache_version(yx_pe_scan_cache **cache, const uint8_t *data, size_t size, uint64_t index, const char *key, size_t key_length,
                                                    struct yx_scan_deadline *deadline);
bool yx_pe_scan_cache_count(yx_pe_scan_cache **cache, const uint8_t *data, size_t size, const char *member, uint64_t *value, struct yx_scan_deadline *deadline);
bool yx_pe_scan_cache_visit_versions(yx_pe_scan_cache **cache, const uint8_t *data, size_t size, yx_pe_version_visitor visitor, void *opaque,
                                     struct yx_scan_deadline *deadline);
void yx_pe_scan_cache_destroy(yx_pe_scan_cache *cache);

/* Signature result structs live in xxfclib (xx_pe_yx.h) and are aliased
 * here so existing consumers (condition.c, module_msi.c, cli_dump.c) keep
 * their types. All strings and arrays in a result are owned and released by
 * yx_pe_signature_result_destroy. */
typedef xx_pe_yx_certificate yx_pe_certificate;
typedef xx_pe_yx_countersignature yx_pe_countersignature;
typedef xx_pe_yx_signature yx_pe_signature;
typedef xx_pe_yx_signature_result yx_pe_signature_result;

/* Parses Authenticode PKCS#7 signatures from the PE security directory.
 * All strings and arrays in `result` are owned and released by destroy. */
bool yx_pe_parse_signatures(const uint8_t *data, size_t size, yx_pe_signature_result *result);
void yx_pe_signature_result_destroy(yx_pe_signature_result *result);

/* YARA-X's AuthenticodeHasher for inputs other than PE files (the msi
 * module's MsiHasher): the hasher feeds the signed bytes to `update`, which
 * hashes them with the signature's digest algorithm. */
typedef xx_pe_yx_authenticode_update_fn yx_authenticode_update_fn;
typedef xx_pe_yx_authenticode_hasher_fn yx_authenticode_hasher_fn;

/* Parses the Authenticode signatures of one DER PKCS#7 SignedData blob, such
 * as an MSI DigitalSignature stream, like AuthenticodeParser::parse; each
 * file_digest is computed with `hasher` instead of the PE byte ranges. A
 * blob that is not a valid signature leaves `result` empty. Returns false
 * only for invalid arguments or allocation failure (`result` destroyed). */
bool yx_authenticode_parse_blob(const uint8_t *blob, size_t blob_size, yx_authenticode_hasher_fn hasher, void *hasher_opaque, yx_pe_signature_result *result);

typedef struct {
    uint64_t standard_libraries;
    uint64_t standard_functions;
    uint64_t delayed_libraries;
    uint64_t delayed_functions;
} yx_pe_import_stats;

typedef struct {
    unsigned flags; /* bit 0: standard; bit 1: delayed */
    const char *dll_name;
    size_t dll_name_length;
    /* NULL with by_ordinal false counts every function from the DLL. */
    const char *function_name;
    size_t function_name_length;
    bool by_ordinal;
    uint64_t ordinal;
} yx_pe_import_query;

typedef void (*yx_pe_import_visitor)(void *opaque, const uint8_t *dll, size_t dll_length, const uint8_t *function, size_t function_length, bool by_ordinal,
                                     uint16_t ordinal, uint32_t rva);

/* The descriptor index preserves separate import library records even when
 * adjacent descriptors have identical DLL names. */
typedef void (*yx_pe_import_descriptor_visitor)(void *opaque, size_t descriptor_index, const uint8_t *dll, size_t dll_length, const uint8_t *function,
                                                size_t function_length, bool by_ordinal, uint16_t ordinal, uint32_t rva);

/* Stats and imphash are undefined on non-PE data (return false).
 * imports() is defined on all data and returns a zero count for non-PE data.
 * An import RVA is defined only when a matching function exists. */
bool yx_pe_get_import_stats(const uint8_t *data, size_t size, yx_pe_import_stats *out);
bool yx_pe_import_count(const uint8_t *data, size_t size, const yx_pe_import_query *query, uint64_t *count);
bool yx_pe_import_rva(const uint8_t *data, size_t size, bool delayed, const yx_pe_import_query *query, uint64_t *rva);
bool yx_pe_imphash(const uint8_t *data, size_t size, char out[33]);
/* Visit successfully parsed functions in file order. Useful for regex
 * import predicates, which apply case-sensitive expressions to both names. */
void yx_pe_visit_imports(const uint8_t *data, size_t size, unsigned flags, yx_pe_import_visitor visitor, void *opaque);
void yx_pe_visit_import_descriptors(const uint8_t *data, size_t size, unsigned flags, yx_pe_import_descriptor_visitor visitor, void *opaque);

/* Indexed public import_details/delayed_import_details. Library names borrow
 * the input. Function names are copied (ordinal fallback names are temporary
 * in the parser); the caller frees name. Indices enumerate retained records. */
bool yx_pe_import_detail(const uint8_t *data, size_t size, bool delayed, uint64_t index, const uint8_t **library, size_t *library_length, uint64_t *function_count);
typedef struct {
    char *name;
    size_t name_length;
    bool has_ordinal;
    uint16_t ordinal;
    uint32_t rva;
} yx_pe_import_function;
bool yx_pe_import_function_detail(const uint8_t *data, size_t size, bool delayed, uint64_t library_index, uint64_t function_index, yx_pe_import_function *function);

#endif
