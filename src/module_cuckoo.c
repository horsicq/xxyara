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

#include "module_cuckoo.h"

/* The YARA-X-exact Cuckoo report parsing moved to xxfclib (xx_cuckoo_yx.h);
 * this file keeps the yx_cuckoo_* module API as thin adapters. The
 * yx_cuckoo_report tag is only a local spelling (condition.h forward-
 * declares it), so the pointers cross over void *. */

bool yx_cuckoo_report_parse(const uint8_t *json, size_t size,
                            yx_cuckoo_report **out)
{
    return xx_cuckoo_yx_report_parse(json, size,
                                     (xx_cuckoo_yx_report **)(void *)out);
}

bool yx_cuckoo_report_parse_ex(const uint8_t *json, size_t size,
    yx_cuckoo_report **out, char *error, size_t error_capacity)
{
    return xx_cuckoo_yx_report_parse_ex(json, size,
                                        (xx_cuckoo_yx_report **)(void *)out,
                                        error, error_capacity);
}

void yx_cuckoo_report_free(yx_cuckoo_report *report)
{
    xx_cuckoo_yx_report_free((xx_cuckoo_yx_report *)(void *)report);
}

bool yx_cuckoo_query(const yx_cuckoo_report *report,
                     const char *function, yx_cuckoo_match_fn matches,
                     void *opaque, bool has_port, int64_t port,
                     uint64_t *count)
{
    return xx_cuckoo_yx_query((const xx_cuckoo_yx_report *)(const void *)report,
                              function,
                              (xx_cuckoo_yx_match_fn)(void *)matches, opaque,
                              has_port, port, count);
}
