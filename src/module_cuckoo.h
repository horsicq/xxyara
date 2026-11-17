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

#ifndef XXYARA_MODULE_CUCKOO_H
#define XXYARA_MODULE_CUCKOO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/other/cuckoo/xx_cuckoo_yx.h>

/* The Cuckoo report parser moved to xxfclib
 * (xxfclib/formats/other/cuckoo/xx_cuckoo_yx.h); this header keeps the
 * yx_cuckoo_* module API unchanged. condition.h forward-declares this tag,
 * so yx_cuckoo_report stays a struct tag of its own: the module_cuckoo.c
 * adapters bridge the two spellings over void *, and every yx_cuckoo_report
 * object is in fact an xxfclib xx_cuckoo_yx_report. */

/* Cuckoo is an input-only YARA-X module. The report is scanner module data,
 * not the bytes of the scanned file. An absent/empty report is valid and
 * yields zero for every function. Invalid JSON or wrong field types fail. */
typedef struct yx_cuckoo_report yx_cuckoo_report;

typedef bool (*yx_cuckoo_match_fn)(const uint8_t *bytes, size_t length,
                                    void *opaque);

bool yx_cuckoo_report_parse(const uint8_t *json, size_t size,
                             yx_cuckoo_report **out);
bool yx_cuckoo_report_parse_ex(const uint8_t *json, size_t size,
    yx_cuckoo_report **out, char *error, size_t error_capacity);
void yx_cuckoo_report_free(yx_cuckoo_report *report);

/* `function` is one of the exported names after `cuckoo.`. TCP and UDP
 * require a port argument; other functions require has_port=false. The
 * regex callback receives decoded UTF-8 bytes. Counts follow YARA-X's
 * integer-valued exports, including zero when a field is absent. */
bool yx_cuckoo_query(const yx_cuckoo_report *report,
                      const char *function, yx_cuckoo_match_fn matches,
                      void *opaque, bool has_port, int64_t port,
                      uint64_t *count);

#endif
