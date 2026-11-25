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

#ifndef XXYARA_MODULE_VBA_H
#define XXYARA_MODULE_VBA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/document/vba/xx_vba_yx.h>

/* The YARA-X-exact VBA project parsing moved to xxfclib (xx_vba_yx.h,
 * src/formats/document/vba/xx_vba_yx.c). The result types keep their yx_vba_
 * names as aliases so existing consumers are unchanged, and the functions
 * below keep the yx_vba_* module API as thin adapters. */

typedef xx_vba_yx_module yx_vba_module;
typedef xx_vba_yx_result yx_vba_result;

enum {
    YX_VBA_MODULE_STANDARD = XX_VBA_YX_MODULE_STANDARD,
    YX_VBA_MODULE_CLASS = XX_VBA_YX_MODULE_CLASS,
    YX_VBA_MODULE_UNKNOWN = XX_VBA_YX_MODULE_UNKNOWN
};

/* Parse a VBA project from a scanned OLE compound file or ZIP-packaged Office
 * document. A valid call
 * always produces a defined has_macros value. False indicates bad API
 * arguments; malformed input produces has_macros=false. */
bool yx_vba_parse(const uint8_t *data, size_t size, yx_vba_result *result);
void yx_vba_result_free(yx_vba_result *result);

/* Decode an MS-OVBA compressed stream. Exposed for focused conformance tests.
 * Caller owns *output and must free it. False means invalid or truncated data,
 * or a resource limit was reached. */
bool yx_vba_decompress(const uint8_t *data, size_t size, uint8_t **output, size_t *output_size);

#endif
