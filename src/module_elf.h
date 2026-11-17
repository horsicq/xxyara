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

#ifndef XXYARA_MODULE_ELF_H
#define XXYARA_MODULE_ELF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Scalar fields of the YARA-X 1.21 ELF module. A false result from
 * yx_elf_field means that the field is undefined for the scanned bytes. */
bool yx_elf_field_supported(const char *member);
bool yx_elf_field(const uint8_t *data, size_t size, const char *member,
                  uint64_t *value);

/* Constants from the public ELF module schema; independent of file data. */
bool yx_elf_constant(const char *member, uint64_t *value);

/* Counts for repeated fields: sections, segments, symtab, dynsym, dynamic.
 * They are defined as zero even if the file is not ELF. */
bool yx_elf_collection_count(const uint8_t *data, size_t size,
                              const char *member, uint64_t *count);

/* Indexed fields for the section and segment collections. The string field
 * points into `data`; malformed or out-of-range items are undefined. */
bool yx_elf_indexed_field_supported(const char *collection,
                                     const char *member);
bool yx_elf_indexed_field(const uint8_t *data, size_t size,
                           const char *collection, uint64_t index,
                           const char *member, uint64_t *value);
bool yx_elf_indexed_string_field_supported(const char *collection,
                                            const char *member);
bool yx_elf_indexed_string_field(const uint8_t *data, size_t size,
                                  const char *collection, uint64_t index,
                                  const char *member,
                                  const uint8_t **bytes, size_t *length);

/* Convert a parsed ELF name as Rust's String::from_utf8_lossy does. With
 * out == NULL, returns the required byte length in written. Otherwise out
 * must have at least that many bytes; the caller owns its storage. */
bool yx_elf_utf8_lossy(const uint8_t *bytes, size_t length, char *out,
                        size_t capacity, size_t *written);

/* Computes import_md5() with YARA-X's lossy UTF-8 decoding and Unicode
 * lowercase conversion. Empty or malformed files hash the empty string.
 * Returns false for invalid C arguments or allocation failure. `out`
 * receives 32 lowercase hex digits plus NUL. */
bool yx_elf_import_md5(const uint8_t *data, size_t size, char out[33]);

/* Computes the YARA-X ELF telfhash() string when the selected global
 * function symbols provide enough bytes for a valid TLSH digest. */
bool yx_elf_telfhash(const uint8_t *data, size_t size, char out[73]);

#endif
