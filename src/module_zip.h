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

#ifndef XXYARA_MODULE_ZIP_H
#define XXYARA_MODULE_ZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/archive/zip/xx_zip_yx.h>

/* The YARA-X-exact ZIP parsing moved to xxfclib (xx_zip_yx.h,
 * src/formats/archive/zip/xx_zip_yx.c). The result types keep their yx_
 * names as aliases so existing consumers (condition evaluator, CLI dump)
 * are unchanged, and the functions below keep the yx_zip_* module API as
 * thin adapters. */

typedef xx_zip_yx_entry yx_zip_entry;
typedef xx_zip_yx_result yx_zip_result;

/* Parses the scanned byte buffer. Non-ZIP and malformed input produce a
 * defined is_zip=false value. A malformed central entry may leave a prefix
 * of valid entries, just as the upstream forward iterator does. Returns
 * false only for invalid API arguments or an allocation failure. */
bool yx_zip_parse(const uint8_t *data, size_t size, yx_zip_result *result);
/* Decode the validated zip.Zip protobuf supplied by the scanner output API.
 * Optional fields remain absent when their protobuf field is absent. */
bool yx_zip_parse_output(const uint8_t *data, size_t size, yx_zip_result *result);
void yx_zip_result_free(yx_zip_result *result);

/* Inline zip.Compression enum constants, e.g. "DEFLATED" and "UNKNOWN". */
bool yx_zip_constant(const char *member, uint64_t *value);

#endif
