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

#ifndef XXYARA_MODULE_OLECF_H
#define XXYARA_MODULE_OLECF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/document/cfbf/xx_olecf_yx.h>

/* The YARA-X-exact OLECF reader moved to xxfclib (xx_olecf_yx.h,
 * src/formats/document/cfbf/xx_olecf_yx.c). The types keep their yx_olecf_
 * names as aliases so existing consumers (the msi and vba modules) are
 * unchanged; the functions below keep the yx_olecf_* module API as thin
 * adapters. */

typedef xx_olecf_yx_stream yx_olecf_stream;
typedef xx_olecf_yx_document yx_olecf_document;

/* Public YARA-X olecf module fields. The module is experimental and must be
 * enabled explicitly in YARA-X v1.21.0; these helpers implement its exposed
 * is_olecf flag and streams collection. */

/* Nested enum constants: StreamType.UNKNOWN/STORAGE/STREAM/ROOT. */
bool yx_olecf_constant(const char *member, uint64_t *value);

/* Always defined: false for non-OLECF or malformed input. */
bool yx_olecf_is_olecf(const uint8_t *data, size_t size);

/* Always defined for valid arguments, including count zero on non-OLECF.
 * Returns false only for invalid arguments or allocation failure. */
bool yx_olecf_stream_count(const uint8_t *data, size_t size,
                            uint64_t *count);

/* The zero-based stream index follows the order in YARA-X's IndexMap.
 * Returns false when index is out of range or the file is invalid. */
bool yx_olecf_stream_get(const uint8_t *data, size_t size,
                          uint64_t index, yx_olecf_stream *stream);

/* A compound file parsed once, for readers of stream contents (the msi
 * module). It mirrors YARA-X's Olecf (lib/src/modules/olecf/parser.rs). */

/* NULL for non-OLECF input (or allocation failure). */
yx_olecf_document *yx_olecf_open(const uint8_t *data, size_t size);
void yx_olecf_close(yx_olecf_document *document);
size_t yx_olecf_sector_size(const yx_olecf_document *document);
size_t yx_olecf_entry_count(const yx_olecf_document *document);
/* Directory entries in IndexMap order (Olecf::streams). */
const yx_olecf_stream *yx_olecf_entry(const yx_olecf_document *document,
                                      size_t index);

/* Contents of entry `index`, like Olecf::get_stream_data: entries smaller
 * than 4096 bytes other than the root storage are read through the MiniFAT
 * from the root mini stream, the others through the FAT. A sequential chain
 * borrows from the scanned data (*owner is NULL); any other chain is
 * gathered into *owner, which the caller frees, and *bytes points into it.
 * Fails for a broken, cyclic or truncated chain or a stream above 256 MiB. */
bool yx_olecf_entry_data(const yx_olecf_document *document, size_t index,
                         const uint8_t **bytes, size_t *size,
                         uint8_t **owner);

#endif
