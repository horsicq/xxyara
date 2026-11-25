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

#include "module_vba.h"

/* The YARA-X-exact VBA project parsing moved to xxfclib (xx_vba_yx.h); the
 * private parsing copy (OLE compound reader, ZIP-packaged Office container,
 * _VBA_PROJECT / dir / PROJECT streams, MS-OVBA decompression, codepage
 * tables) was removed from this file. */

bool yx_vba_parse(const uint8_t *data, size_t size, yx_vba_result *result)
{
    return xx_vba_yx_parse(data, size, result);
}

void yx_vba_result_free(yx_vba_result *result)
{
    xx_vba_yx_result_free(result);
}

bool yx_vba_decompress(const uint8_t *data, size_t size, uint8_t **output, size_t *output_size)
{
    return xx_vba_yx_decompress(data, size, output, output_size);
}
