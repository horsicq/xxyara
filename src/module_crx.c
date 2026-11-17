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

#include "module_crx.h"

/* The YARA-X-exact CRX parsing moved to xxfclib (xx_crx_yx.h); the private
 * parsing copy (Cr24 header, protobuf proofs, nested ZIP access, manifest
 * and locale JSON, signature verification, permhash) was removed from this
 * file. */

bool yx_crx_parse(const uint8_t *data, size_t size, yx_crx_result *result)
{
    return xx_crx_yx_parse(data, size, result);
}

bool yx_crx_parse_output(const uint8_t *data, size_t size,
                          yx_crx_result *result)
{
    return xx_crx_yx_parse_output(data, size, result);
}

uint8_t *yx_crx_complete_terminal_signature(const uint8_t *data, size_t size,
                                              size_t *adjusted_size)
{
    return xx_crx_yx_complete_terminal_signature(data, size, adjusted_size);
}

void yx_crx_result_free(yx_crx_result *result)
{
    xx_crx_yx_result_free(result);
}

bool yx_crx_permhash(const yx_crx_result *result, char hex[65])
{
    return xx_crx_yx_permhash(result, hex);
}

bool yx_crx_permhash_cached(const yx_crx_result *result, char hex[65])
{
    return xx_crx_yx_permhash_cached(result, hex);
}

void yx_crx_permhash_cache_reset(void)
{
    xx_crx_yx_permhash_cache_reset();
}
