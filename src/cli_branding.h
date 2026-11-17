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

/* The identity of the command line. The same sources build two programs:
 * - yr (XXYARA_CLI_BRANDED unset): prints exactly what YARA-X's yr prints,
 *   banner and version line included, because every parity gate compares it
 *   with the official yr;
 * - xxyara (XXYARA_CLI_BRANDED defined): the same commands, options and output,
 *   with its own banner, version line and program name. */
#ifndef XXYARA_CLI_BRANDING_H
#define XXYARA_CLI_BRANDING_H

#include "cli_help_data.h"

#ifdef XXYARA_CLI_BRANDED

/* The xxyara version; CMake passes PROJECT_VERSION. */
#ifndef XXYARA_CLI_VERSION
#define XXYARA_CLI_VERSION "0.1.0"
#endif

/* The program name: the fallback for usage lines when argv[0] names no file,
 * and the command that the shell completion scripts complete. */
#define YX_CLI_PROGRAM_NAME "xxyara"
#define YX_CLI_PACKAGE_NAME "xxyara"

/* The first lines of `xxyara help`, up to the blank line before "Usage:". */
#define YX_CLI_BANNER \
    "xxyara " XXYARA_CLI_VERSION ", the pattern matching swiss army knife " \
    "(YARA-X " YX_CLI_VERSION " compatible).\n" \
    "\n" \
    "Copyright (c) 2026 hors\n" \
    "Based on the original YARA-X by Victor M. Alvarez <vmalvarez@virustotal.com>\n" \
    "https://github.com/horsicq/xxyara\n"

/* `xxyara --version`. */
#define YX_CLI_VERSION_LINE "xxyara " XXYARA_CLI_VERSION " (YARA-X " YX_CLI_VERSION ")\n"

#else

#define YX_CLI_PROGRAM_NAME "yr"
#define YX_CLI_PACKAGE_NAME "yara-x-cli"
#define YX_CLI_BANNER \
    "YARA-X " YX_CLI_VERSION ", the pattern matching swiss army knife.\n" \
    "\n" \
    "Victor M. Alvarez <vmalvarez@virustotal.com>\n"
#define YX_CLI_VERSION_LINE "yara-x-cli " YX_CLI_VERSION "\n"

#endif

#endif
