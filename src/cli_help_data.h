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

/* YARA-X v1.23.0 CLI help text; see LICENSE.YARA-X. */
#ifndef XXYARA_CLI_HELP_DATA_H
#define XXYARA_CLI_HELP_DATA_H

#include <stddef.h>
#include <stdio.h>

/* The upstream `yr` release whose output this command line reproduces: the
 * `--version` line, the help banner and the JSON "version" field. The C API
 * version in yara_x.h follows the library ABI separately. */
#define YX_CLI_VERSION "1.23.0"

/* Help and usage text names the program "yr". clap names it after the file
 * name of argv[0] instead ("yr.exe" for F:\bin\yr.exe), so these writers,
 * implemented in cli.c, replace the name at the start of every usage line
 * ("Usage: yr ..." and the indented "  yr ..." help line). */
void yx_cli_usage_write(const char *text, size_t length, FILE *stream);
void yx_cli_usage_fputs(const char *text, FILE *stream);
void yx_cli_usage_fprintf(FILE *stream, const char *format, ...);

extern const char yx_cli_help_top_short[];
extern const char yx_cli_help_top_long[];
extern const char yx_cli_help_scan_short[];
extern const char yx_cli_help_scan_long[];
extern const char yx_cli_help_scan_long_tail[];
extern const char yx_cli_help_compile_short[];
extern const char yx_cli_help_compile_long[];
extern const char yx_cli_help_dump_short[];
extern const char yx_cli_help_dump_long[];

#endif
