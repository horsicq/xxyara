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

#ifndef YX_MODULE_CRX_H
#define YX_MODULE_CRX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/installer/crx/xx_crx_yx.h>

/* The YARA-X-exact CRX parsing moved to xxfclib (xx_crx_yx.h,
 * src/formats/installer/crx/xx_crx_yx.c). The result types keep their yx_crx_
 * names as aliases so existing consumers are unchanged, and the functions
 * below keep the yx_crx_* module API as thin adapters. */

typedef xx_crx_yx_string_list yx_crx_string_list;
typedef xx_crx_yx_signature yx_crx_signature;
typedef xx_crx_yx_result yx_crx_result;

/* Returns false only for invalid arguments or allocation failure. For an
 * unrecognized or malformed CRX, returns true with is_crx == false. Initialize
 * the result to zero before its first use and free it after each parse. */
bool yx_crx_parse(const uint8_t *data, size_t size, yx_crx_result *result);
/* Decode a validated crx.Crx protobuf provided by the scanner output API. */
bool yx_crx_parse_output(const uint8_t *data, size_t size, yx_crx_result *result);
/* Normalize an overlong terminal CrxSignature length when the bytes at EOF
 * form a complete nested message. The caller owns the returned buffer. */
uint8_t *yx_crx_complete_terminal_signature(const uint8_t *data, size_t size, size_t *adjusted_size);
void yx_crx_result_free(yx_crx_result *result);

/* SHA-256 of the concatenated required runtime permissions, in array order.
 * Returns false for non-CRX inputs or invalid arguments. */
bool yx_crx_permhash(const yx_crx_result *result, char hex[65]);
/* The YARA-X module caches permhash per thread until native CRX main runs. */
bool yx_crx_permhash_cached(const yx_crx_result *result, char hex[65]);
void yx_crx_permhash_cache_reset(void);

#endif
