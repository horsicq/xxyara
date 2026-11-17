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

#ifndef YX_MODULE_LNK_H
#define YX_MODULE_LNK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <xxfclib/formats/other/windows_shell_link/xx_lnk_yx.h>

/* The YARA-X-exact LNK parsing moved to xxfclib (xx_lnk_yx.h,
 * src/formats/other/windows_shell_link/xx_lnk_yx.c). The result types keep
 * their yx_lnk_ names as aliases so existing consumers are unchanged, and
 * the functions below keep the yx_lnk_* module API as thin adapters. */

typedef xx_lnk_yx_uint yx_lnk_uint;
typedef xx_lnk_yx_string yx_lnk_string;
typedef xx_lnk_yx_bytes yx_lnk_bytes;
typedef xx_lnk_yx_shell_item yx_lnk_shell_item;
typedef xx_lnk_yx_tracker yx_lnk_tracker;
typedef xx_lnk_yx_result yx_lnk_result;

/* Returns false only for an invalid argument or allocation failure. A non-LNK
 * input succeeds with result->is_lnk == false and all optional fields absent.
 * Initialize result to zero before first use; free it after every parse. */
bool yx_lnk_parse(const uint8_t *data, size_t size, yx_lnk_result *result);
void yx_lnk_result_free(yx_lnk_result *result);

/* Names include inline FileAttributes constants and qualified enum members,
 * such as "FILE_ATTRIBUTE_READONLY" and "ShowCommand.NORMAL". */
bool yx_lnk_constant(const char *name, uint64_t *value);

#endif
