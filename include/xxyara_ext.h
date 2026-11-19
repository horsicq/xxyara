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

/* xxyara-only extensions of the YARA-X C API. include/yara_x.h stays
 * identical to upstream; the functions declared here have no YARA-X
 * counterpart. */

#ifndef XXYARA_EXT_H
#define XXYARA_EXT_H

#include "yara_x.h"

#ifdef __cplusplus
extern "C" {
#endif

// Controls whether the scanner keeps its own copy of the data of the last
// normal scan.
//
// When `retain` is true (the default), every [`yrx_scanner_scan`] whose
// rules import a native module whose fields are read lazily from the scanned
// data (pe, elf, macho, dex and the like) copies that data into the scanner,
// so that a later multi-block scan ([`yrx_scanner_scan_block`] and
// [`yrx_scanner_finish`]) on the same scanner can still evaluate those
// module fields after the caller released the buffer, as YARA-X does.
//
// Passing false frees any data already retained and stops the copying. A
// later [`yrx_scanner_scan_block`]/[`yrx_scanner_finish`] on that scanner
// then no longer sees the previous normal scan's lazy native-module fields
// (this differs from YARA-X). Callers that never use the multi-block API get
// results identical to the default, without one copy of every scanned
// buffer.
enum YRX_RESULT xxyara_scanner_retain_scan_data(struct YRX_SCANNER *scanner,
                                                bool retain);

// Calls `callback` for every rule, private ones included, that did not match
// in the last scan, in rule declaration order (YARA-X's
// `ScanResults::non_matching_rules`). The rules passed to the callback belong
// to that scan: their patterns report the matches found, as for the rules
// passed to the callback set with [`yrx_scanner_on_matching_rule`]. They are
// valid until the next scan or the scanner's destruction.
enum YRX_RESULT xxyara_scanner_iter_non_matching_rules(
    struct YRX_SCANNER *scanner, YRX_RULE_CALLBACK callback, void *user_data);

#ifdef __cplusplus
}
#endif

#endif  /* XXYARA_EXT_H */
