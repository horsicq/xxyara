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

#include "module_zip.h"

/* The YARA-X-exact ZIP parsing moved to xxfclib (xx_zip_yx.h); the private
 * parsing copy (EOCD scan, ZIP64 recovery, central directory iterator,
 * lossy UTF-8 path decoding, protobuf output decoder) was removed from this
 * file. */

bool yx_zip_parse(const uint8_t *data, size_t size, yx_zip_result *result)
{
    return xx_zip_yx_parse(data, size, result);
}

bool yx_zip_parse_output(const uint8_t *data, size_t size, yx_zip_result *result)
{
    return xx_zip_yx_parse_output(data, size, result);
}

void yx_zip_result_free(yx_zip_result *result)
{
    xx_zip_yx_result_free(result);
}

bool yx_zip_constant(const char *member, uint64_t *value)
{
    return xx_zip_yx_constant(member, value);
}
