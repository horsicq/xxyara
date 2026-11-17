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

#include "module_lnk.h"

/* The YARA-X-exact LNK parsing moved to xxfclib (xx_lnk_yx.h); the private
 * parsing copy (ShellLinkHeader, LinkTargetIDList, LinkInfo, StringData,
 * TrackerData, ExtraData overlay) was removed from this file. */

bool yx_lnk_parse(const uint8_t *data, size_t size, yx_lnk_result *result)
{
    return xx_lnk_yx_parse(data, size, result);
}

void yx_lnk_result_free(yx_lnk_result *result)
{
    xx_lnk_yx_result_free(result);
}

bool yx_lnk_constant(const char *name, uint64_t *value)
{
    return xx_lnk_yx_constant(name, value);
}
