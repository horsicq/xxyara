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

#ifndef XXYARA_TOML_H
#define XXYARA_TOML_H

/* The TOML 1.0 document parser moved to xxfclib (xxfclib/toml/xx_toml.h);
 * this header keeps the yx_toml_* API as typedef aliases and macros so
 * cli.c, cli_config_tree.h and the tests stay unchanged. */

#include <xxfclib/toml/xx_toml.h>

typedef xx_toml_kind yx_toml_kind;
typedef xx_toml_value yx_toml_value;
typedef xx_toml_error yx_toml_error;

#define YX_TOML_TABLE XX_TOML_TABLE
#define YX_TOML_ARRAY XX_TOML_ARRAY
#define YX_TOML_STRING XX_TOML_STRING
#define YX_TOML_INTEGER XX_TOML_INTEGER
#define YX_TOML_FLOAT XX_TOML_FLOAT
#define YX_TOML_BOOLEAN XX_TOML_BOOLEAN
#define YX_TOML_DATETIME XX_TOML_DATETIME

#define yx_toml_parse xx_toml_parse
#define yx_toml_error_clear xx_toml_error_clear
#define yx_toml_free xx_toml_free
#define yx_toml_get xx_toml_get

#endif
