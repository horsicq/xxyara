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

/* YARA-X compatible module dump command, backed by the pure C modules. */
#include "cli_dump.h"
#include "cli_config.h"
#include "cli_help_data.h"
#include "module_crx.h"
#include "module_dex.h"
#include "module_dotnet.h"
#include "module_dotnet_method.h"
#include "module_elf.h"
#include "module_lnk.h"
#include "module_macho.h"
#include "module_pe.h"
#include "module_zip.h"
#ifdef XXYARA_ENABLE_OLECF
#include "module_olecf.h"
#endif
#ifdef XXYARA_ENABLE_VBA
#include "module_vba.h"
#endif

#include "xxfclib/io/xx_io.h"
#include "xxfclib/terminal/xx_terminal.h"
#include "xxfclib/algo/base64/xx_base64.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include "os_error.h"

typedef enum {
    YX_DUMP_OBJECT, YX_DUMP_ARRAY, YX_DUMP_BOOL, YX_DUMP_INTEGER,
    YX_DUMP_STRING, YX_DUMP_BYTES, YX_DUMP_ENUM
} yx_dump_kind;

typedef enum {
    YX_DUMP_DECIMAL, YX_DUMP_HEX, YX_DUMP_TIMESTAMP, YX_DUMP_FLAGS
} yx_dump_format;

typedef struct yx_dump_node {
    struct yx_dump_node *allocation_next;
    struct yx_dump_node *first;
    struct yx_dump_node *last;
    struct yx_dump_node *next;
    const char *key;
    char *owned;
    char *owned_key;
    const char *enum_name;
    const char *comment;
    size_t length;
    uint64_t number;
    yx_dump_kind kind;
    yx_dump_format format;
    bool wide_integer;
    bool quoted_keys;
    bool block_string;
} yx_dump_node;

typedef struct {
    yx_dump_node *allocations;
    bool oom;
} yx_dump_doc;

static yx_dump_node *yx_dump_add(yx_dump_doc *doc, yx_dump_node *parent,
                                  const char *key, yx_dump_kind kind)
{
    yx_dump_node *node = (yx_dump_node *)calloc(1, sizeof(*node));
    if (!node) { doc->oom = true; return NULL; }
    node->kind = kind;
    node->key = key;
    node->allocation_next = doc->allocations;
    doc->allocations = node;
    if (parent) {
        if (parent->last) parent->last->next = node;
        else parent->first = node;
        parent->last = node;
    }
    return node;
}

static yx_dump_node *yx_dump_number(yx_dump_doc *doc, yx_dump_node *parent,
                                     const char *key, uint64_t value,
                                     bool wide, yx_dump_format format)
{
    yx_dump_node *node = yx_dump_add(doc, parent, key, YX_DUMP_INTEGER);
    if (node) {
        node->number = value;
        node->wide_integer = wide;
        node->format = format;
    }
    return node;
}

static yx_dump_node *yx_dump_boolean(yx_dump_doc *doc, yx_dump_node *parent,
                                      const char *key, bool value)
{
    yx_dump_node *node = yx_dump_add(doc, parent, key, YX_DUMP_BOOL);
    if (node) node->number = value;
    return node;
}

static yx_dump_node *yx_dump_text(yx_dump_doc *doc, yx_dump_node *parent,
                                   const char *key, const void *bytes,
                                   size_t length, bool byte_string)
{
    yx_dump_node *node = yx_dump_add(doc, parent, key,
                                      byte_string ? YX_DUMP_BYTES :
                                                    YX_DUMP_STRING);
    if (!node || length > SIZE_MAX - 1) { doc->oom = true; return node; }
    node->owned = (char *)malloc(length + 1);
    if (!node->owned) { doc->oom = true; return node; }
    if (length) memcpy(node->owned, bytes, length);
    node->owned[length] = '\0';
    node->length = length;
    return node;
}

/* Protobuf text fields replace each malformed UTF-8 subsequence the same
 * way as Rust's String::from_utf8_lossy. */
static size_t yx_dump_utf8_piece(const uint8_t *bytes, size_t length,
                                  bool *valid)
{
    uint8_t lead = bytes[0];
    unsigned width;
    if (lead < 0x80) { *valid = true; return 1; }
    if (lead >= 0xc2 && lead <= 0xdf) width = 2;
    else if (lead >= 0xe0 && lead <= 0xef) width = 3;
    else if (lead >= 0xf0 && lead <= 0xf4) width = 4;
    else { *valid = false; return 1; }
    for (unsigned i = 1; i < width; ++i) {
        if (i >= length || bytes[i] < 0x80 || bytes[i] > 0xbf ||
            (i == 1 && ((lead == 0xe0 && bytes[i] < 0xa0) ||
                        (lead == 0xed && bytes[i] > 0x9f) ||
                        (lead == 0xf0 && bytes[i] < 0x90) ||
                        (lead == 0xf4 && bytes[i] > 0x8f)))) {
            *valid = false;
            return i;
        }
    }
    *valid = true;
    return width;
}

static void yx_dump_lossy_text(yx_dump_doc *doc, yx_dump_node *parent,
                                const char *key, const uint8_t *bytes,
                                size_t length)
{
    static const char replacement[] = "\xef\xbf\xbd";
    char *converted;
    size_t used = 0;
    if (length > (SIZE_MAX - 1) / 3) { doc->oom = true; return; }
    converted = (char *)malloc(length * 3 + 1);
    if (!converted) { doc->oom = true; return; }
    for (size_t i = 0; i < length;) {
        bool valid;
        size_t piece = yx_dump_utf8_piece(bytes + i, length - i, &valid);
        if (valid) {
            memcpy(converted + used, bytes + i, piece);
            used += piece;
        } else {
            memcpy(converted + used, replacement, 3);
            used += 3;
        }
        i += piece;
    }
    yx_dump_text(doc, parent, key, converted, used, false);
    free(converted);
}

static yx_dump_node *yx_dump_enum(yx_dump_doc *doc, yx_dump_node *parent,
                                   const char *key, uint64_t number,
                                   const char *name)
{
    yx_dump_node *node = yx_dump_add(doc, parent, key, YX_DUMP_ENUM);
    if (node) { node->number = number; node->enum_name = name; }
    return node;
}

static void yx_dump_free(yx_dump_doc *doc)
{
    yx_dump_node *node = doc->allocations;
    while (node) {
        yx_dump_node *next = node->allocation_next;
        free(node->owned);
        free(node->owned_key);
        free(node);
        node = next;
    }
}

static void yx_dump_indent(FILE *out, unsigned level)
{
    for (unsigned i = 0; i < level; ++i) fputc(' ', out);
}

static void yx_dump_json_string(FILE *out, const char *s, size_t length)
{
    fputc('"', out);
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { fputc('\\', out); fputc(c, out); }
        else if (c == '\n') fputs("\\n", out);
        else if (c == '\r') fputs("\\r", out);
        else if (c == '\t') fputs("\\t", out);
        else if (c < 0x20 || c == 0x7f) fprintf(out, "\\u%04x", c);
        else fputc(c, out);
    }
    fputc('"', out);
}

static void yx_dump_base64(FILE *out, const uint8_t *data, size_t length)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t encoded_size = xx_base64_encoded_size(length, true);
    char *encoded = (char *)malloc(encoded_size ? encoded_size : 1);
    if (!encoded) return;
    if (xx_base64_encode_buffer(data, length, alphabet, true,
                                encoded, encoded_size, NULL))
        fwrite(encoded, 1, encoded_size, out);
    free(encoded);
}

static void yx_dump_json(FILE *out, const yx_dump_node *node, unsigned level)
{
    const yx_dump_node *item;
    switch (node->kind) {
    case YX_DUMP_OBJECT:
    case YX_DUMP_ARRAY:
        fputc(node->kind == YX_DUMP_OBJECT ? '{' : '[', out);
        fputc('\n', out);
        yx_dump_indent(out, level + 4);
        for (item = node->first; item; item = item->next) {
            if (node->kind == YX_DUMP_OBJECT) {
                yx_dump_json_string(out, item->key, strlen(item->key));
                fputs(": ", out);
            }
            yx_dump_json(out, item, level + 4);
            if (item->next) { fputs(",\n", out); yx_dump_indent(out, level + 4); }
        }
        fputc('\n', out);
        yx_dump_indent(out, level);
        fputc(node->kind == YX_DUMP_OBJECT ? '}' : ']', out);
        break;
    case YX_DUMP_BOOL:
        fputs(node->number ? "true" : "false", out);
        break;
    case YX_DUMP_INTEGER:
        if (node->format == YX_DUMP_TIMESTAMP) {
            if (node->wide_integer)
                fprintf(out,
                        "{ \"encoding\": \"timestamp\", \"value\": %" PRId64
                        " }",
                        (int64_t)node->number);
            else
                fprintf(out,
                        "{ \"encoding\": \"timestamp\", \"value\": %" PRIu64
                        " }",
                        node->number);
        }
        else if (node->wide_integer)
            fprintf(out, "%" PRId64, (int64_t)node->number);
        else fprintf(out, "%" PRIu64, node->number);
        break;
    case YX_DUMP_STRING:
        yx_dump_json_string(out, node->owned, node->length);
        break;
    case YX_DUMP_BYTES:
        fputs("{ \"encoding\": \"base64\", \"value\": \"", out);
        yx_dump_base64(out, (const uint8_t *)node->owned, node->length);
        fputs("\"}", out);
        break;
    case YX_DUMP_ENUM:
        if (node->enum_name)
            yx_dump_json_string(out, node->enum_name, strlen(node->enum_name));
        else fprintf(out, "%" PRId32, (int32_t)node->number);
        break;
    }
}

/* YAML colors, as yr writes them: keys and list dashes "\x1b[33m", strings
 * "\x1b[32m", comments "\x1b[38;2;222;184;135m". */
#define YX_DUMP_KEY_COLOR UINT32_C(0xffff00)
#define YX_DUMP_TEXT_COLOR UINT32_C(0x00ff00)
#define YX_DUMP_COMMENT_COLOR UINT32_C(0xdeb887)

/* YAML output. Without a terminal it goes to `file`. With one, plain text
 * collects in `pending` and every colored span is written in one piece by
 * xx_terminal_write_color_ex(): writing character by character let the
 * console render a span in parts (ConPTY split "hello.txt" into two colored
 * runs). With neither, the object is a memory buffer for building spans. */
typedef struct yx_dump_out {
    FILE *file;
    const xx_terminal_state *terminal;
    char *pending;
    size_t length;
    size_t capacity;
    bool failed;
} yx_dump_out;

static void yx_out_write(yx_dump_out *out, const char *data, size_t size)
{
    if (!size || out->failed) return;
    if (out->file) {
        if (fwrite(data, 1, size, out->file) != size) out->failed = true;
        return;
    }
    if (size > out->capacity - out->length) {
        size_t capacity = out->capacity ? out->capacity : 256;
        char *grown;
        while (size > capacity - out->length) {
            if (capacity > SIZE_MAX / 2) { out->failed = true; return; }
            capacity *= 2;
        }
        grown = (char *)realloc(out->pending, capacity);
        if (!grown) { out->failed = true; return; }
        out->pending = grown;
        out->capacity = capacity;
    }
    memcpy(out->pending + out->length, data, size);
    out->length += size;
}

static void yx_out_puts(yx_dump_out *out, const char *text)
{
    yx_out_write(out, text, strlen(text));
}

static void yx_out_putc(yx_dump_out *out, char c)
{
    yx_out_write(out, &c, 1);
}

static void yx_out_printf(yx_dump_out *out, const char *format, ...)
{
    char stack_text[128];
    va_list args, copy;
    int needed;
    va_start(args, format);
    va_copy(copy, args);
    needed = vsnprintf(stack_text, sizeof(stack_text), format, copy);
    va_end(copy);
    if (needed < 0) {
        out->failed = true;
    } else if ((size_t)needed < sizeof(stack_text)) {
        yx_out_write(out, stack_text, (size_t)needed);
    } else {
        char *large = (char *)malloc((size_t)needed + 1);
        if (!large) out->failed = true;
        else {
            vsnprintf(large, (size_t)needed + 1, format, args);
            yx_out_write(out, large, (size_t)needed);
            free(large);
        }
    }
    va_end(args);
}

static void yx_out_indent(yx_dump_out *out, unsigned level)
{
    for (unsigned i = 0; i < level; ++i) yx_out_putc(out, ' ');
}

static void yx_out_flush(yx_dump_out *out)
{
    if (out->terminal && out->length && !out->failed &&
        xx_terminal_write(out->terminal, out->pending, out->length) != XXFC_OK)
        out->failed = true;
    if (out->terminal) out->length = 0;
}

/* One colored span; plain text where colors are off. */
static void yx_out_color(yx_dump_out *out, const char *data, size_t size,
                         uint32_t color)
{
    if (!out->terminal) {
        yx_out_write(out, data, size);
        return;
    }
    yx_out_flush(out);
    if (!out->failed &&
        xx_terminal_write_color_ex(out->terminal, data, size, color,
                                   UINT32_MAX, XX_TERMINAL_COLOR_EXACT) !=
        XXFC_OK)
        out->failed = true;
}

/* Move a span built in `span` to `out` as one colored write. */
static void yx_out_color_span(yx_dump_out *out, yx_dump_out *span,
                              uint32_t color)
{
    if (span->failed) out->failed = true;
    else yx_out_color(out, span->pending, span->length, color);
    span->length = 0;
}

static void yx_dump_yaml_string(yx_dump_out *out, const char *s, size_t length,
                                  bool byte_string, uint32_t color)
{
    yx_dump_out text = {0};
    yx_out_putc(out, '"');
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!byte_string && c == 0xc2 && i + 1 < length &&
            (unsigned char)s[i + 1] >= 0x80 &&
            (unsigned char)s[i + 1] <= 0x9f &&
            (unsigned char)s[i + 1] != 0x85) {
            yx_out_printf(&text, "\\x%02x", (unsigned char)s[++i]);
        } else if (c == '"' || c == '\'' || c == '\\') {
            yx_out_putc(&text, '\\'); yx_out_putc(&text, (char)c);
        } else if (c == '\n') yx_out_puts(&text, "\\n");
        else if (c == '\r') yx_out_puts(&text, "\\r");
        else if (c == '\t') yx_out_puts(&text, "\\t");
        else if ((byte_string && (c < 0x20 || c > 0x7e)) ||
                 (!byte_string && (c < 0x20 || c == 0x7f)))
            yx_out_printf(&text, "\\x%02x", c);
        else yx_out_putc(&text, (char)c);
    }
    yx_out_color_span(out, &text, color);
    free(text.pending);
    yx_out_putc(out, '"');
}

static bool yx_dump_yaml_block_text(const yx_dump_node *node)
{
    if (node->kind != YX_DUMP_STRING) return false;
    if (node->block_string) return true;
    if (!memchr(node->owned, '\n', node->length)) return false;
    for (size_t i = 0; i < node->length; ++i) {
        unsigned char c = (unsigned char)node->owned[i];
        if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') ||
            c == 0x7f) return false;
        if (c == 0xc2 && i + 1 < node->length &&
            (unsigned char)node->owned[i + 1] >= 0x80 &&
            (unsigned char)node->owned[i + 1] <= 0x9f &&
            (unsigned char)node->owned[i + 1] != 0x85) return false;
    }
    return true;
}

static void yx_dump_yaml_block(yx_dump_out *out, const yx_dump_node *node,
                                unsigned content_level)
{
    yx_dump_out line = {0};
    yx_out_color(out, "|", 1, YX_DUMP_TEXT_COLOR);
    yx_out_putc(out, '\n');
    /* Each line is one colored span; the newline after it is plain. */
    for (size_t i = 0; i < node->length; ++i) {
        if (i == 0 || node->owned[i - 1] == '\n')
            yx_out_indent(out, content_level);
        if (node->owned[i] == '\r' && i + 1 < node->length &&
            node->owned[i + 1] == '\n')
            continue;
        if (!node->block_string && node->owned[i] == '\r' &&
            i + 1 == node->length)
            continue;
        if (node->owned[i] == '\n') {
            yx_out_color_span(out, &line, YX_DUMP_TEXT_COLOR);
            yx_out_putc(out, '\n');
            continue;
        }
        yx_out_putc(&line, node->owned[i]);
    }
    if (node->length && node->owned[node->length - 1] != '\n')
        yx_out_color_span(out, &line, YX_DUMP_TEXT_COLOR);
    if (node->length && node->owned[node->length - 1] == '\n')
        yx_out_indent(out, content_level);
    free(line.pending);
}

static void yx_dump_yaml(yx_dump_out *out, const yx_dump_node *node,
                          unsigned level)
{
    const yx_dump_node *item;
    if (node->kind == YX_DUMP_OBJECT) {
        for (item = node->first; item; item = item->next) {
            if (node->quoted_keys)
                yx_dump_yaml_string(out, item->key, strlen(item->key), false,
                                    YX_DUMP_KEY_COLOR);
            else
                yx_out_color(out, item->key, strlen(item->key),
                             YX_DUMP_KEY_COLOR);
            yx_out_putc(out, ':');
            if (item->kind == YX_DUMP_OBJECT) {
                yx_out_putc(out, '\n');
                yx_out_indent(out, level + 4);
                yx_dump_yaml(out, item, level + 4);
            } else if (item->kind == YX_DUMP_ARRAY) {
                yx_out_putc(out, '\n');
                for (const yx_dump_node *element = item->first;
                     element; element = element->next) {
                    yx_out_indent(out, level + 2);
                    yx_out_color(out, "-", 1, YX_DUMP_KEY_COLOR);
                    yx_out_putc(out, ' ');
                    if (yx_dump_yaml_block_text(element))
                        yx_dump_yaml_block(out, element, level + 4);
                    else
                        yx_dump_yaml(out, element, level + 4);
                    if (element->next) yx_out_putc(out, '\n');
                }
            } else if (yx_dump_yaml_block_text(item)) {
                yx_out_putc(out, ' ');
                yx_dump_yaml_block(out, item, level + 4);
            } else {
                yx_out_putc(out, ' ');
                yx_dump_yaml(out, item, level + 4);
            }
            if (item->next) { yx_out_putc(out, '\n'); yx_out_indent(out, level); }
        }
        return;
    }
    switch (node->kind) {
    case YX_DUMP_BOOL: yx_out_puts(out, node->number ? "true" : "false"); break;
    case YX_DUMP_INTEGER:
        if (node->format == YX_DUMP_HEX || node->format == YX_DUMP_FLAGS)
            yx_out_printf(out, "0x%" PRIx64, node->number);
        else if (node->wide_integer)
            yx_out_printf(out, "%" PRId64, (int64_t)node->number);
        else yx_out_printf(out, "%" PRIu64, node->number);
        if (node->comment) {
            yx_dump_out comment = {0};
            yx_out_printf(&comment, "  # %s", node->comment);
            yx_out_color_span(out, &comment, YX_DUMP_COMMENT_COLOR);
            free(comment.pending);
        }
        break;
    case YX_DUMP_STRING:
    case YX_DUMP_BYTES:
        yx_dump_yaml_string(out, node->owned, node->length,
                            node->kind == YX_DUMP_BYTES, YX_DUMP_TEXT_COLOR);
        break;
    case YX_DUMP_ENUM:
        if (node->enum_name) yx_out_puts(out, node->enum_name);
        else if (node->format == YX_DUMP_HEX)
            yx_out_printf(out, "0x%" PRIx64, node->number);
        else yx_out_printf(out, "%" PRId32, (int32_t)node->number);
        break;
    case YX_DUMP_OBJECT: case YX_DUMP_ARRAY: break;
    }
}

/* The YAML document on stdout, colored when stdout is a terminal. */
static bool yx_dump_yaml_document(const yx_dump_node *root, bool colors)
{
    yx_dump_out out = {stdout, NULL, NULL, 0, 0, false};
    xx_terminal_state terminal;
    bool styled = false;
    if (colors) {
        /* xx_terminal writes to the handle itself: drain stdio first. */
        fflush(stdout);
        terminal = xx_terminal_init(XX_TERMINAL_STDOUT);
        styled = terminal.valid && terminal.type != XX_TERMINAL_TYPE_NONE;
        if (styled) {
            out.file = NULL;
            out.terminal = &terminal;
        } else {
            xx_terminal_finish(&terminal);
        }
    }
    yx_dump_yaml(&out, root, 0);
    yx_out_flush(&out);
    if (styled) xx_terminal_finish(&terminal);
    free(out.pending);
    return !out.failed;
}

static bool yx_dump_read(const char *path, uint8_t **bytes, size_t *length)
{
    xx_io_device *device = NULL;
    size_t used = 0, capacity = 0;
    uint8_t *buffer = NULL;
    *bytes = NULL;
    *length = 0;
    if (path) {
        device = xx_io_file_open(path, "rb");
        if (!device) return false;
    }
    for (;;) {
        ssize_t n;
        if (used == capacity) {
            size_t next = capacity ? capacity * 2 : 65536;
            uint8_t *grown;
            if (next <= capacity || next == SIZE_MAX) goto failure;
            grown = (uint8_t *)realloc(buffer, next + 1);
            if (!grown) goto failure;
            buffer = grown;
            capacity = next;
        }
        if (device) n = xx_io_read(device, buffer + used, capacity - used);
        else n = (ssize_t)fread(buffer + used, 1, capacity - used, stdin);
        if (n < 0 || (size_t)n > capacity - used ||
            (!device && ferror(stdin))) goto failure;
        if (n == 0) break;
        used += (size_t)n;
    }
    if (device && xx_io_close(device) != 0) { free(buffer); return false; }
    buffer[used] = 0;
    *bytes = buffer;
    *length = used;
    return true;
failure:
    {
#ifdef _WIN32
    DWORD error = GetLastError();
#endif
    if (device) xx_io_close(device);
    free(buffer);
#ifdef _WIN32
    SetLastError(error);
#endif
    return false;
    }
}

static const char *yx_dump_lnk_show_command(uint64_t value)
{
    switch (value) {
    case 1: return "NORMAL";
    case 3: return "MAXIMIZED";
    case 7: return "MIN_NO_ACTIVE";
    default: return NULL;
    }
}

static const char *yx_dump_lnk_drive_type(uint64_t value)
{
    static const char *const names[] = {
        "UNKNOWN", "NO_ROOT_DIR", "REMOVABLE", "FIXED", "REMOTE",
        "CDROM", "RAMDISK"
    };
    return value < sizeof(names) / sizeof(names[0]) ? names[value] : NULL;
}

static const char *yx_dump_lnk_item_type(uint64_t value)
{
    switch (value) {
    case 0x00: return "CONTROL_PANEL_CPL";
    case 0x01: return "CONTROL_PANEL_CATEGORY";
    case 0x1f: return "ROOT_FOLDER";
    case 0x20: return "VOLUME";
    case 0x30: return "FILE_ENTRY";
    case 0x40: return "NETWORK_LOCATION";
    case 0x52: return "COMPRESSED_FOLDER";
    case 0x61: return "URI";
    case 0x71: return "CONTROL_PANEL";
    case 0x72: return "PRINTERS";
    case 0x73: return "COMMON_PLACES_FOLDER";
    case 0x74: return "USERS_FILES_FOLDER";
    default: return NULL;
    }
}

static void yx_dump_optional_uint(yx_dump_doc *doc, yx_dump_node *parent,
                                    const char *key, yx_lnk_uint field)
{
    if (field.defined)
        yx_dump_number(doc, parent, key, field.value, true,
                        YX_DUMP_DECIMAL);
}

static void yx_dump_optional_string(yx_dump_doc *doc, yx_dump_node *parent,
                                      const char *key, yx_lnk_string field)
{
    if (field.defined)
        yx_dump_text(doc, parent, key, field.data, field.length, false);
}

static void yx_dump_lnk(yx_dump_doc *doc, yx_dump_node *parent,
                          const uint8_t *data, size_t size)
{
    yx_lnk_result result = {0};
    yx_dump_node *module;
    if (!yx_lnk_parse(data, size, &result)) { doc->oom = true; return; }
    module = yx_dump_add(doc, parent, "lnk", YX_DUMP_OBJECT);
    if (!module) goto done;
    yx_dump_boolean(doc, module, "is_lnk", result.is_lnk);
    yx_dump_optional_string(doc, module, "name", result.name);
    yx_dump_optional_uint(doc, module, "creation_time", result.creation_time);
    yx_dump_optional_uint(doc, module, "access_time", result.access_time);
    yx_dump_optional_uint(doc, module, "write_time", result.write_time);
    yx_dump_optional_uint(doc, module, "file_size", result.file_size);
    yx_dump_optional_uint(doc, module, "file_attributes", result.file_attributes);
    yx_dump_optional_string(doc, module, "icon_location", result.icon_location);
    yx_dump_optional_uint(doc, module, "icon_index", result.icon_index);
    if (result.show_command.defined)
        yx_dump_enum(doc, module, "show_command", result.show_command.value,
                     yx_dump_lnk_show_command(result.show_command.value));
    if (result.drive_type.defined)
        yx_dump_enum(doc, module, "drive_type", result.drive_type.value,
                     yx_dump_lnk_drive_type(result.drive_type.value));
    yx_dump_optional_uint(doc, module, "drive_serial_number", result.drive_serial_number);
    yx_dump_optional_string(doc, module, "volume_label", result.volume_label);
    yx_dump_optional_string(doc, module, "local_base_path", result.local_base_path);
    yx_dump_optional_string(doc, module, "common_path_suffix", result.common_path_suffix);
    yx_dump_optional_string(doc, module, "relative_path", result.relative_path);
    yx_dump_optional_string(doc, module, "working_dir", result.working_dir);
    yx_dump_optional_string(doc, module, "cmd_line_args", result.cmd_line_args);
    yx_dump_optional_uint(doc, module, "overlay_size", result.overlay_size);
    yx_dump_optional_uint(doc, module, "overlay_offset", result.overlay_offset);
    if (result.tracker_data.defined) {
        yx_dump_node *tracker = yx_dump_add(doc, module, "tracker_data",
                                             YX_DUMP_OBJECT);
        if (tracker) {
            yx_dump_optional_uint(doc, tracker, "version", result.tracker_data.version);
            yx_dump_optional_string(doc, tracker, "machine_id", result.tracker_data.machine_id);
            yx_dump_optional_string(doc, tracker, "droid_volume_id", result.tracker_data.droid_volume_id);
            yx_dump_optional_string(doc, tracker, "droid_file_id", result.tracker_data.droid_file_id);
            yx_dump_optional_string(doc, tracker, "droid_birth_volume_id", result.tracker_data.droid_birth_volume_id);
            yx_dump_optional_string(doc, tracker, "droid_birth_file_id", result.tracker_data.droid_birth_file_id);
        }
    }
    if (result.target_id_list_count) {
        yx_dump_node *array = yx_dump_add(doc, module, "target_id_list",
                                           YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < result.target_id_list_count; ++i) {
            const yx_lnk_shell_item *source = &result.target_id_list[i];
            yx_dump_node *item = yx_dump_add(doc, array, NULL,
                                              YX_DUMP_OBJECT);
            if (!item) break;
            if (source->item_type.defined) {
                yx_dump_node *type = yx_dump_enum(
                    doc, item, "item_type", source->item_type.value,
                    yx_dump_lnk_item_type(source->item_type.value));
                if (type) type->format = YX_DUMP_HEX;
            }
            if (source->data.defined)
                yx_dump_text(doc, item, "data", source->data.data,
                              source->data.length, true);
            yx_dump_optional_string(doc, item, "cpl_file_path", source->cpl_file_path);
            yx_dump_optional_string(doc, item, "root_folder_id", source->root_folder_id);
            yx_dump_optional_string(doc, item, "volume_name", source->volume_name);
            yx_dump_optional_string(doc, item, "volume_id", source->volume_id);
            yx_dump_optional_string(doc, item, "file_entry_name", source->file_entry_name);
            yx_dump_optional_string(doc, item, "network_location", source->network_location);
        }
    }
done:
    yx_lnk_result_free(&result);
}

static void yx_dump_crx_string(yx_dump_doc *doc, yx_dump_node *module,
                                const char *key, const char *value,
                                size_t length)
{
    if (value) yx_dump_text(doc, module, key, value, length, false);
}

static void yx_dump_crx_list(yx_dump_doc *doc, yx_dump_node *module,
                              const char *key, const yx_crx_string_list *list)
{
    if (list->count) {
        yx_dump_node *array = yx_dump_add(doc, module, key, YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < list->count; ++i)
            yx_dump_text(doc, array, NULL, list->items[i],
                          list->lengths[i], false);
    }
}

static void yx_dump_crx(yx_dump_doc *doc, yx_dump_node *parent,
                          const uint8_t *data, size_t size)
{
    yx_crx_result result = {0};
    yx_dump_node *module;
    if (!yx_crx_parse(data, size, &result)) { doc->oom = true; return; }
    module = yx_dump_add(doc, parent, "crx", YX_DUMP_OBJECT);
    if (!module) goto done;
    yx_dump_boolean(doc, module, "is_crx", result.is_crx);
    if (result.is_crx) {
        yx_dump_number(doc, module, "crx_version", result.crx_version,
                        false, YX_DUMP_DECIMAL);
        yx_dump_number(doc, module, "header_size", result.header_size,
                        false, YX_DUMP_DECIMAL);
    }
    yx_dump_crx_string(doc, module, "id", result.id, result.id_length);
    yx_dump_crx_string(doc, module, "version", result.version,
                        result.version_length);
    yx_dump_crx_string(doc, module, "name", result.name, result.name_length);
    yx_dump_crx_string(doc, module, "description", result.description,
                        result.description_length);
    yx_dump_crx_string(doc, module, "raw_name", result.raw_name,
                        result.raw_name_length);
    yx_dump_crx_string(doc, module, "raw_description", result.raw_description,
                        result.raw_description_length);
    yx_dump_crx_string(doc, module, "minimum_chrome_version",
                        result.minimum_chrome_version,
                        result.minimum_chrome_version_length);
    yx_dump_crx_string(doc, module, "homepage_url", result.homepage_url,
                        result.homepage_url_length);
    yx_dump_crx_list(doc, module, "permissions", &result.permissions);
    yx_dump_crx_list(doc, module, "host_permissions", &result.host_permissions);
    yx_dump_crx_list(doc, module, "optional_permissions",
                      &result.optional_permissions);
    yx_dump_crx_list(doc, module, "optional_host_permissions",
                      &result.optional_host_permissions);
    if (result.signature_count) {
        yx_dump_node *array = yx_dump_add(doc, module, "signatures",
                                           YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < result.signature_count; ++i) {
            yx_dump_node *item = yx_dump_add(doc, array, NULL,
                                              YX_DUMP_OBJECT);
            if (!item) break;
            yx_dump_text(doc, item, "key", result.signatures[i].key,
                          strlen(result.signatures[i].key), false);
            yx_dump_boolean(doc, item, "verified",
                             result.signatures[i].verified);
        }
    }
done:
    yx_crx_result_free(&result);
}

#ifdef XXYARA_ENABLE_OLECF
static void yx_dump_olecf(yx_dump_doc *doc, yx_dump_node *parent,
                            const uint8_t *data, size_t size)
{
    bool is_olecf = yx_olecf_is_olecf(data, size);
    uint64_t count = 0;
    yx_dump_node *module = yx_dump_add(doc, parent, "olecf",
                                        YX_DUMP_OBJECT);
    if (!module) return;
    yx_dump_boolean(doc, module, "is_olecf", is_olecf);
    if (!yx_olecf_stream_count(data, size, &count)) { doc->oom = true; return; }
    if (count) {
        yx_dump_node *array = yx_dump_add(doc, module, "streams",
                                           YX_DUMP_ARRAY);
        for (uint64_t i = 0; array && i < count; ++i) {
            yx_olecf_stream source;
            yx_dump_node *item;
            const char *type_name;
            if (!yx_olecf_stream_get(data, size, i, &source)) break;
            item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
            if (!item) break;
            yx_dump_text(doc, item, "name", source.name,
                          source.name_length, false);
            switch (source.type) {
            case 0: type_name = "UNKNOWN"; break;
            case 1: type_name = "STORAGE"; break;
            case 2: type_name = "STREAM"; break;
            case 5: type_name = "ROOT"; break;
            default: type_name = NULL; break;
            }
            yx_dump_enum(doc, item, "type", source.type, type_name);
            yx_dump_number(doc, item, "size", source.size, true,
                            YX_DUMP_DECIMAL);
        }
    }
}
#endif

static const char *yx_dump_elf_enum(const char *kind, uint64_t value)
{
    static const char *const types[] = {
        "ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE",
        "ET_LOPROC", "ET_HIPROC"
    };
    static const char *const machines[] = {
        "EM_NONE", "EM_M32", "EM_SPARC", "EM_386", "EM_68K", "EM_88K",
        "EM_IAMCU", "EM_860", "EM_MIPS", "EM_S370", "EM_MIPS_RS3_LE",
        "EM_PARISC", "EM_SPARC32PLUS", "EM_PPC", "EM_PPC64", "EM_S390",
        "EM_MCORE", "EM_ARM", "EM_SH", "EM_SPARCV9", "EM_X86_64",
        "EM_ARC_COMPACT", "EM_AARCH64", "EM_BPF", "EM_LOONGARCH"
    };
    static const char *const osabi[] = {
        "OSABI_NONE", "OSABI_HPUX", "OSABI_NETBSD", "OSABI_LINUX",
        "OSABI_GNU_HURD", "OSABI_SOLARIS", "OSABI_AIX", "OSABI_IRIX",
        "OSABI_FREE_BSD", "OSABI_TRU64", "OSABI_MODESTO",
        "OSABI_OPENBSD", "OSABI_OPENVMS", "OSABI_NSK", "OSABI_AROS",
        "OSABI_FENIXOS", "OSABI_CLOUDABI", "OSABI_OPENVOS",
        "OSABI_ARM_AEABI", "OSABI_ARM",
        "OSABI_STANDALONE"
    };
    static const char *const sections[] = {
        "SHT_NULL", "SHT_PROGBITS", "SHT_SYMTAB", "SHT_STRTAB",
        "SHT_RELA", "SHT_HASH", "SHT_DYNAMIC", "SHT_NOTE", "SHT_NOBITS",
        "SHT_REL", "SHT_SHLIB", "SHT_DYNSYM", "SHT_INIT_ARRAY",
        "SHT_FINI_ARRAY", "SHT_PREINIT_ARRAY", "SHT_GROUP",
        "SHT_SYMTAB_SHNDX"
    };
    static const char *const segments[] = {
        "PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE",
        "PT_SHLIB", "PT_PHDR", "PT_TLS", "PT_GNU_EH_FRAME",
        "PT_GNU_STACK", "PT_GNU_RELRO", "PT_GNU_PROPERTY"
    };
    static const char *const sym_types[] = {
        "STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE",
        "STT_COMMON", "STT_TLS"
    };
    static const char *const sym_binds[] = {
        "STB_LOCAL", "STB_GLOBAL", "STB_WEAK"
    };
    static const char *const sym_visibilities[] = {
        "STV_DEFAULT", "STV_INTERNAL", "STV_HIDDEN", "STV_PROTECTED"
    };
    static const char *const dyn_types[] = {
        "DT_NULL", "DT_NEEDED", "DT_PLTRELSZ", "DT_PLTGOT", "DT_HASH",
        "DT_STRTAB", "DT_SYMTAB", "DT_RELA", "DT_RELASZ", "DT_RELAENT",
        "DT_STRSZ", "DT_SYMENT", "DT_INIT", "DT_FINI", "DT_SONAME",
        "DT_RPATH", "DT_SYMBOLIC", "DT_REL", "DT_RELSZ", "DT_RELENT",
        "DT_PLTREL", "DT_DEBUG", "DT_TEXTREL", "DT_JMPREL", "DT_BIND_NOW",
        "DT_INIT_ARRAY", "DT_FINI_ARRAY", "DT_INIT_ARRAYSZ",
        "DT_FINI_ARRAYSZ", "DT_RUNPATH", "DT_FLAGS", "DT_ENCODING",
        "DT_LOOS", "DT_HIOS", "DT_VALRNGLO", "DT_VALRNGHI",
        "DT_ADDRRNGLO", "DT_ADDRRNGHI", "DT_VERSYM", "DT_RELACOUNT",
        "DT_RELCOUNT", "DT_FLAGS_1", "DT_VERDEF", "DT_VERDEFNUM",
        "DT_VERNEED", "DT_VERNEEDNUM", "DT_LOPROC", "DT_HIPROC"
    };
    const char *const *names;
    size_t count;
    if (strcmp(kind, "type") == 0) {
        names = types; count = sizeof(types) / sizeof(types[0]);
    } else if (strcmp(kind, "machine") == 0) {
        names = machines; count = sizeof(machines) / sizeof(machines[0]);
    } else if (strcmp(kind, "osabi") == 0) {
        names = osabi; count = sizeof(osabi) / sizeof(osabi[0]);
    } else if (strcmp(kind, "section_type") == 0) {
        names = sections; count = sizeof(sections) / sizeof(sections[0]);
    } else if (strcmp(kind, "segment_type") == 0) {
        names = segments; count = sizeof(segments) / sizeof(segments[0]);
    } else if (strcmp(kind, "sym_type") == 0) {
        names = sym_types; count = sizeof(sym_types) / sizeof(sym_types[0]);
    } else if (strcmp(kind, "sym_bind") == 0) {
        names = sym_binds; count = sizeof(sym_binds) / sizeof(sym_binds[0]);
    } else if (strcmp(kind, "sym_visibility") == 0) {
        names = sym_visibilities;
        count = sizeof(sym_visibilities) / sizeof(sym_visibilities[0]);
    } else {
        names = dyn_types; count = sizeof(dyn_types) / sizeof(dyn_types[0]);
    }
    for (size_t i = 0; i < count; ++i) {
        uint64_t constant;
        if (yx_elf_constant(names[i], &constant) && constant == value)
            return names[i];
    }
    return NULL;
}

static void yx_dump_elf(yx_dump_doc *doc, yx_dump_node *parent,
                          const uint8_t *data, size_t size)
{
    static const char *const scalars[] = {
        "type", "machine", "osabi", "entry_point", "sh_offset",
        "sh_entry_size", "ph_offset", "ph_entry_size",
        "number_of_sections", "number_of_segments", "symtab_entries",
        "dynsym_entries", "dynamic_section_entries"
    };
    static const char *const section_fields[] = {
        "type", "flags", "address", "size", "offset"
    };
    static const char *const segment_fields[] = {
        "type", "flags", "offset", "virtual_address", "physical_address",
        "file_size", "memory_size", "alignment"
    };
    yx_dump_node *module = yx_dump_add(doc, parent, "elf", YX_DUMP_OBJECT);
    if (!module) return;
    for (size_t i = 0; i < sizeof(scalars) / sizeof(scalars[0]); ++i) {
        uint64_t value;
        if (!yx_elf_field(data, size, scalars[i], &value)) continue;
        if (i < 3)
            yx_dump_enum(doc, module, scalars[i], value,
                          yx_dump_elf_enum(scalars[i], value));
        else yx_dump_number(doc, module, scalars[i], value,
                             i != 5 && i != 7, YX_DUMP_DECIMAL);
    }
    for (unsigned c = 0; c < 2; ++c) {
        const char *collection = c == 0 ? "sections" : "segments";
        const char *const *fields = c == 0 ? section_fields : segment_fields;
        size_t field_count = c == 0 ?
            sizeof(section_fields) / sizeof(section_fields[0]) :
            sizeof(segment_fields) / sizeof(segment_fields[0]);
        uint64_t count = 0;
        if (!yx_elf_collection_count(data, size, collection, &count) ||
            !count) continue;
        yx_dump_node *array = yx_dump_add(doc, module, collection,
                                           YX_DUMP_ARRAY);
        for (uint64_t j = 0; array && j < count; ++j) {
            yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
            if (!item) break;
            for (size_t k = 0; k < field_count; ++k) {
                uint64_t value;
                if (!yx_elf_indexed_field(data, size, collection, j,
                                           fields[k], &value)) continue;
                if (k == 0)
                    yx_dump_enum(doc, item, fields[k], value,
                        yx_dump_elf_enum(c == 0 ? "section_type" :
                                         "segment_type", value));
                else {
                    yx_dump_node *field = yx_dump_number(doc, item,
                        fields[k], value, c == 0 || k >= 2,
                        c == 1 && k == 1 ? YX_DUMP_FLAGS :
                                             YX_DUMP_DECIMAL);
                    if (field && c == 1 && k == 1) {
                        switch (value) {
                        case 1: field->comment = "PF_X"; break;
                        case 2: field->comment = "PF_W"; break;
                        case 4: field->comment = "PF_R"; break;
                        case 5: field->comment = "PF_X | PF_R"; break;
                        case 6: field->comment = "PF_W | PF_R"; break;
                        case 7: field->comment = "PF_X | PF_W | PF_R"; break;
                        }
                    }
                }
            }
            if (c == 0) {
                const uint8_t *name;
                size_t length;
                if (yx_elf_indexed_string_field(data, size, collection,
                                                 j, "name", &name, &length))
                    yx_dump_lossy_text(doc, item, "name", name, length);
            }
        }
    }
    for (unsigned c = 0; c < 3; ++c) {
        const char *collection = c == 0 ? "symtab" :
                                 c == 1 ? "dynsym" : "dynamic";
        uint64_t count = 0;
        if (!yx_elf_collection_count(data, size, collection, &count) ||
            !count) continue;
        yx_dump_node *array = yx_dump_add(doc, module, collection,
                                           YX_DUMP_ARRAY);
        for (uint64_t j = 0; array && j < count; ++j) {
            yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
            uint64_t value;
            if (!item) break;
            if (c < 2) {
                const uint8_t *name;
                size_t length;
                if (yx_elf_indexed_string_field(data, size, collection, j,
                                                 "name", &name, &length))
                    yx_dump_lossy_text(doc, item, "name", name, length);
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "value", &value))
                    yx_dump_number(doc, item, "value", value, true,
                                    YX_DUMP_DECIMAL);
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "size", &value))
                    yx_dump_number(doc, item, "size", value, true,
                                    YX_DUMP_DECIMAL);
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "type", &value))
                    yx_dump_enum(doc, item, "type", value,
                                  yx_dump_elf_enum("sym_type", value));
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "bind", &value))
                    yx_dump_enum(doc, item, "bind", value,
                                  yx_dump_elf_enum("sym_bind", value));
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "shndx", &value))
                    yx_dump_number(doc, item, "shndx", value, false,
                                    YX_DUMP_DECIMAL);
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "visibility", &value))
                    yx_dump_enum(doc, item, "visibility", value,
                                  yx_dump_elf_enum("sym_visibility", value));
            } else {
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "type", &value))
                    yx_dump_enum(doc, item, "type", value,
                                  yx_dump_elf_enum("dyn_type", value));
                if (yx_elf_indexed_field(data, size, collection, j,
                                          "val", &value))
                    yx_dump_number(doc, item, "val", value, true,
                                    YX_DUMP_DECIMAL);
            }
        }
    }
}

static void yx_dump_macho_number(yx_dump_doc *doc, yx_dump_node *parent,
                                  const uint8_t *data, size_t size,
                                  const char *name, bool wide,
                                  yx_dump_format format)
{
    uint64_t value;
    if (yx_macho_field(data, size, name, &value))
        yx_dump_number(doc, parent, name, value, wide, format);
}

static void yx_dump_pe_timestamp(yx_dump_doc *doc, yx_dump_node *node);

static void yx_dump_macho_flags(yx_dump_doc *doc, yx_dump_node *node,
                                 bool segment)
{
    static const char *const file_names[] = {
        "MH_NOUNDEFS", "MH_INCRLINK", "MH_DYLDLINK", "MH_BINDATLOAD",
        "MH_PREBOUND", "MH_SPLIT_SEGS", "MH_LAZY_INIT", "MH_TWOLEVEL",
        "MH_FORCE_FLAT", "MH_NOMULTIDEFS", "MH_NOFIXPREBINDING",
        "MH_PREBINDABLE", "MH_ALLMODSBOUND",
        "MH_SUBSECTIONS_VIA_SYMBOLS", "MH_CANONICAL", "MH_WEAK_DEFINES",
        "MH_BINDS_TO_WEAK", "MH_ALLOW_STACK_EXECUTION", "MH_ROOT_SAFE",
        "MH_SETUID_SAFE", "MH_NO_REEXPORTED_DYLIBS", "MH_PIE",
        "MH_DEAD_STRIPPABLE_DYLIB", "MH_HAS_TLV_DESCRIPTORS",
        "MH_NO_HEAP_EXECUTION", "MH_APP_EXTENSION_SAFE"
    };
    static const char *const segment_names[] = {
        "SG_HIGHVM", "SG_FVMLIB", "SG_NORELOC", "SG_PROTECTED_VERSION_1"
    };
    const char *const *names = segment ? segment_names : file_names;
    size_t count = segment ? sizeof(segment_names) / sizeof(segment_names[0]) :
                             sizeof(file_names) / sizeof(file_names[0]);
    char comment[768] = {0};
    size_t used = 0;
    if (!node) return;
    for (size_t i = 0; i < count; ++i) {
        if (!(node->number & (UINT64_C(1) << i))) continue;
        int n = snprintf(comment + used, sizeof(comment) - used, "%s%s",
                         used ? " | " : "", names[i]);
        if (n < 0 || (size_t)n >= sizeof(comment) - used) return;
        used += (size_t)n;
    }
    if (!used) return;
    node->owned = (char *)malloc(used + 1);
    if (!node->owned) { doc->oom = true; return; }
    memcpy(node->owned, comment, used + 1);
    node->comment = node->owned;
}

static uint64_t yx_dump_macho_read(const uint8_t *bytes, unsigned width,
                                    bool little)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < width; ++i) {
        unsigned at = little ? width - 1 - i : i;
        result = (result << 8) | bytes[at];
    }
    return result;
}

static void yx_dump_macho_symtab_content(yx_dump_doc *doc,
                                          yx_dump_node *object,
                                          const uint8_t *data, size_t size)
{
    uint64_t magic, symoff, nsyms, stroff, strsize;
    if (!yx_macho_field(data, size, "magic", &magic) ||
        !yx_macho_field(data, size, "symtab.symoff", &symoff) ||
        !yx_macho_field(data, size, "symtab.nsyms", &nsyms) ||
        !yx_macho_field(data, size, "symtab.stroff", &stroff) ||
        !yx_macho_field(data, size, "symtab.strsize", &strsize) ||
        stroff > size || strsize > size - stroff || symoff > size) return;
    bool little = magic == UINT32_C(0xcefaedfe) ||
                  magic == UINT32_C(0xcffaedfe);
    bool is64 = magic == UINT32_C(0xfeedfacf) ||
                magic == UINT32_C(0xcffaedfe);
    size_t width = is64 ? 16u : 12u;
    yx_dump_node *entries = NULL, *nlists = NULL;
    for (uint64_t i = 0; i < nsyms && i < (size - symoff) / width; ++i) {
        const uint8_t *record = data + (size_t)symoff + (size_t)i * width;
        uint64_t strx = yx_dump_macho_read(record, 4, little);
        if (strx >= strsize) continue;
        const uint8_t *name = data + (size_t)stroff + (size_t)strx;
        const uint8_t *end = memchr(name, 0, (size_t)(strsize - strx));
        if (!end) break;
        if (name == end) continue;
        if (!entries) entries = yx_dump_add(doc, object, "entries",
                                            YX_DUMP_ARRAY);
        if (!nlists) nlists = yx_dump_add(doc, object, "nlists",
                                          YX_DUMP_ARRAY);
        if (entries) yx_dump_text(doc, entries, NULL, name,
                                   (size_t)(end - name), true);
        yx_dump_node *item = yx_dump_add(doc, nlists, NULL, YX_DUMP_OBJECT);
        if (!item) break;
        yx_dump_number(doc, item, "n_strx", strx, false, YX_DUMP_DECIMAL);
        yx_dump_number(doc, item, "n_type", record[4], false,
                        YX_DUMP_DECIMAL);
        yx_dump_number(doc, item, "n_sect", record[5], false,
                        YX_DUMP_DECIMAL);
        yx_dump_number(doc, item, "n_desc",
                        yx_dump_macho_read(record + 6, 2, little), false,
                        YX_DUMP_DECIMAL);
        yx_dump_number(doc, item, "n_value",
                        yx_dump_macho_read(record + 8, is64 ? 8 : 4, little),
                        true, YX_DUMP_DECIMAL);
    }
}

static yx_dump_node *yx_dump_macho_object(yx_dump_doc *doc, yx_dump_node *parent,
                                  const uint8_t *data, size_t size,
                                  const char *name,
                                  const char *const *fields, size_t count)
{
    yx_dump_node *object = NULL;
    for (size_t i = 0; i < count; ++i) {
        char path[80];
        uint64_t value;
        snprintf(path, sizeof(path), "%s.%s", name, fields[i]);
        if (!yx_macho_field(data, size, path, &value)) continue;
        if (!object) object = yx_dump_add(doc, parent, name, YX_DUMP_OBJECT);
        if (object) yx_dump_number(doc, object, fields[i], value, false,
                                   YX_DUMP_DECIMAL);
    }
    if (object && strcmp(name, "symtab") == 0)
        yx_dump_macho_symtab_content(doc, object, data, size);
    return object;
}

static const yx_dump_node *yx_dump_child(const yx_dump_node *parent,
                                          const char *key)
{
    if (!parent) return NULL;
    for (const yx_dump_node *item = parent->first; item; item = item->next)
        if (item->key && strcmp(item->key, key) == 0) return item;
    return NULL;
}

static void yx_dump_macho_symbol_names(yx_dump_doc *doc,
                                        yx_dump_node *parent,
                                        const yx_dump_node *symtab,
                                        bool exports, bool imports)
{
    const yx_dump_node *entries = yx_dump_child(symtab, "entries");
    const yx_dump_node *nlists = yx_dump_child(symtab, "nlists");
    yx_dump_node *export_array = NULL, *import_array = NULL;
    for (unsigned pass = 0; pass < 2; ++pass) {
        const yx_dump_node *name = entries ? entries->first : NULL;
        const yx_dump_node *nlist = nlists ? nlists->first : NULL;
        while (name && nlist) {
            const yx_dump_node *type = yx_dump_child(nlist, "n_type");
            if (type) {
                uint64_t kind = type->number & 0x0e;
                if (pass == 0 && exports && (type->number & 1) &&
                    !(type->number & 0xe0) &&
                    (kind == 0x0e || kind == 0x02 || kind == 0x0a)) {
                    if (!export_array) export_array = yx_dump_add(doc, parent,
                        "exports", YX_DUMP_ARRAY);
                    if (export_array) yx_dump_lossy_text(doc, export_array,
                        NULL, (const uint8_t *)name->owned, name->length);
                }
                if (pass == 1 && imports && !(type->number & 0xe0) &&
                    kind == 0) {
                    if (!import_array) import_array = yx_dump_add(doc, parent,
                        "imports", YX_DUMP_ARRAY);
                    if (import_array) yx_dump_lossy_text(doc, import_array,
                        NULL, (const uint8_t *)name->owned, name->length);
                }
            }
            name = name->next;
            nlist = nlist->next;
        }
    }
}

static void yx_dump_macho_entitlements(yx_dump_doc *doc,
                                        yx_dump_node *parent,
                                        const yx_macho_extras *extras)
{
    if (extras->entitlement_count) {
        yx_dump_node *array = yx_dump_add(doc, parent, "entitlements",
                                           YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < extras->entitlement_count; ++i)
            yx_dump_text(doc, array, NULL, extras->entitlements[i],
                           strlen(extras->entitlements[i]), false);
    }
}

static void yx_dump_macho_certificates(yx_dump_doc *doc,
                                        yx_dump_node *parent,
                                        const yx_macho_extras *extras)
{
    if (extras->certificate_count) {
        yx_dump_node *array = yx_dump_add(doc, parent, "certificates",
                                           YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < extras->certificate_count; ++i) {
            const yx_macho_certificate *cert = &extras->certificates[i];
            yx_dump_node *item = yx_dump_add(doc, array, NULL,
                                               YX_DUMP_OBJECT);
            if (!item) break;
            if (cert->issuer)
                yx_dump_text(doc, item, "issuer", cert->issuer,
                               cert->issuer_length, false);
            if (cert->subject)
                yx_dump_text(doc, item, "subject", cert->subject,
                               cert->subject_length, false);
            yx_dump_boolean(doc, item, "is_self_signed", cert->is_self_signed);
        }
    }
}

static bool yx_dump_macho_imports(yx_dump_doc *doc,
                                   yx_dump_node *parent,
                                   const yx_macho_extras *extras)
{
    if (extras->import_count) {
        yx_dump_node *array = yx_dump_add(doc, parent, "imports",
                                           YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < extras->import_count; ++i)
            yx_dump_text(doc, array, NULL, extras->imports[i],
                           strlen(extras->imports[i]), false);
    }
    return extras->import_count != 0;
}

static void yx_dump_macho_segments(yx_dump_doc *doc, yx_dump_node *parent,
                                    const uint8_t *data, size_t size)
{
    static const char *const fields[] = {
        "vmaddr", "vmsize", "fileoff", "filesize", "maxprot",
        "initprot", "nsects", "flags"
    };
    static const char *const section_fields[] = {
        "addr", "size", "offset", "align", "reloff", "nreloc",
        "flags", "reserved1", "reserved2", "reserved3"
    };
    uint64_t count = 0;
    if (!yx_macho_collection_count(data, size, "segments", &count) || !count)
        return;
    yx_dump_node *array = yx_dump_add(doc, parent, "segments", YX_DUMP_ARRAY);
    for (uint64_t i = 0; array && i < count; ++i) {
        yx_dump_node *segment = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
        const uint8_t *bytes;
        size_t length;
        uint64_t value;
        if (!segment) break;
        if (yx_macho_indexed_string_field(data, size, "segments", i,
                                           "segname", &bytes, &length))
            yx_dump_text(doc, segment, "segname", bytes, length, true);
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); ++j) {
            if (!yx_macho_indexed_field(data, size, "segments", i,
                                         fields[j], &value)) continue;
            yx_dump_node *field = yx_dump_number(doc, segment, fields[j], value,
                            j <= 3, j == 0 || j == 1 || j == 4 || j == 5 ?
                            YX_DUMP_HEX : j == 7 ? YX_DUMP_FLAGS :
                            YX_DUMP_DECIMAL);
            if (j == 7) yx_dump_macho_flags(doc, field, true);
        }
        uint64_t nsections = 0;
        if (!yx_macho_nested_collection_count(data, size, "segments", i,
                                                "sections", &nsections) ||
            !nsections) continue;
        yx_dump_node *sections = yx_dump_add(doc, segment, "sections",
                                               YX_DUMP_ARRAY);
        for (uint64_t k = 0; sections && k < nsections; ++k) {
            yx_dump_node *section = yx_dump_add(doc, sections, NULL,
                                                 YX_DUMP_OBJECT);
            if (!section) break;
            static const char *const names[] = {"segname", "sectname"};
            for (size_t m = 0; m < 2; ++m)
                if (yx_macho_section_string_field(data, size, i, k,
                    names[m], &bytes, &length))
                    yx_dump_text(doc, section, names[m], bytes, length, true);
            for (size_t m = 0; m < sizeof(section_fields) /
                                     sizeof(section_fields[0]); ++m)
                if (yx_macho_section_field(data, size, i, k,
                    section_fields[m], &value))
                    yx_dump_number(doc, section, section_fields[m], value,
                                    m <= 1, m <= 1 || m == 6 ? YX_DUMP_HEX :
                                    YX_DUMP_DECIMAL);
        }
    }
}

static void yx_dump_macho_collections(yx_dump_doc *doc,
                                       yx_dump_node *parent,
                                       const uint8_t *data, size_t size)
{
    uint64_t count = 0;
    yx_dump_macho_segments(doc, parent, data, size);
    if (yx_macho_collection_count(data, size, "dylibs", &count) && count) {
        yx_dump_node *array = yx_dump_add(doc, parent, "dylibs", YX_DUMP_ARRAY);
        uint64_t magic = 0;
        yx_macho_field(data, size, "magic", &magic);
        bool little = magic == UINT32_C(0xcefaedfe) ||
                      magic == UINT32_C(0xcffaedfe);
        for (uint64_t i = 0; array && i < count; ++i) {
            yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
            const uint8_t *bytes = NULL;
            size_t length;
            uint64_t value;
            if (!item) break;
            if (yx_macho_indexed_string_field(data, size, "dylibs", i,
                                               "name", &bytes, &length))
                yx_dump_text(doc, item, "name", bytes, length, true);
            if (yx_macho_indexed_field(data, size, "dylibs", i,
                                        "timestamp", &value)) {
                yx_dump_node *timestamp = yx_dump_number(doc, item,
                    "timestamp", value, false, YX_DUMP_TIMESTAMP);
                if (timestamp) yx_dump_pe_timestamp(doc, timestamp);
            }
            if (bytes && size >= 16 && bytes >= data + 16 &&
                bytes <= data + size) {
                static const char *const names[] = {
                    "compatibility_version", "current_version"
                };
                for (size_t j = 0; j < 2; ++j) {
                    uint64_t encoded = yx_dump_macho_read(bytes - (j ? 8 : 4),
                                                              4, little);
                    char version[32];
                    int n = snprintf(version, sizeof(version), "%" PRIu64
                        ".%" PRIu64 ".%" PRIu64,
                        encoded >> 16, (encoded >> 8) & 0xff,
                        encoded & 0xff);
                    if (n > 0 && (size_t)n < sizeof(version))
                        yx_dump_text(doc, item, names[j], version,
                                      (size_t)n, false);
                }
            }
        }
    }
}

static void yx_dump_macho_byte_array(yx_dump_doc *doc, yx_dump_node *parent,
                                      const uint8_t *data, size_t size,
                                      const char *name)
{
    uint64_t count = 0;
    if (!yx_macho_collection_count(data, size, name, &count) || !count) return;
    yx_dump_node *array = yx_dump_add(doc, parent, name, YX_DUMP_ARRAY);
    for (uint64_t i = 0; array && i < count; ++i) {
        const uint8_t *bytes;
        size_t length;
        if (yx_macho_indexed_string_field(data, size, name, i, "value",
                                           &bytes, &length))
            yx_dump_text(doc, array, NULL, bytes, length, true);
    }
}

static bool yx_dump_macho_command(const uint8_t *data, size_t size,
                                   uint32_t wanted, const uint8_t **payload,
                                   size_t *length, bool *little)
{
    uint64_t magic, count;
    if (!yx_macho_field(data, size, "magic", &magic) ||
        !yx_macho_field(data, size, "ncmds", &count)) return false;
    *little = magic == UINT32_C(0xcefaedfe) ||
              magic == UINT32_C(0xcffaedfe);
    size_t position = magic == UINT32_C(0xfeedfacf) ||
                      magic == UINT32_C(0xcffaedfe) ? 32u : 28u;
    bool found = false;
    for (uint64_t i = 0; i < count && position <= size &&
                         size - position >= 8; ++i) {
        uint64_t command = yx_dump_macho_read(data + position, 4, *little);
        uint64_t command_size = yx_dump_macho_read(data + position + 4, 4,
                                                    *little);
        /* Upstream (macho/parser.rs command(): take(command_size.saturating_sub(8)))
         * never breaks the walk for an undersized command - its data is
         * simply empty (0 bytes, not negative), and the cursor still
         * advances by at least the 8-byte command+command_size header.
         * Only a command_size that overruns the remaining buffer is a hard
         * stop (the `take()` itself would fail there). */
        uint64_t advance = command_size < 8 ? 8 : command_size;
        if (advance > size - position) break;
        if (command_size >= 8 && command == wanted) {
            *payload = data + position + 8;
            *length = (size_t)command_size - 8;
            found = true;
        }
        position += (size_t)advance;
    }
    return found;
}

typedef struct {
    size_t offset;
    char *prefix;
} yx_dump_macho_export_node;

static bool yx_dump_macho_uleb(const uint8_t *data, size_t size,
                                size_t *position, uint64_t *value)
{
    uint64_t result = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 10 && *position < size; ++i) {
        uint8_t byte = data[(*position)++];
        if (shift == 63 && (byte & 0x7e)) return false;
        result |= (uint64_t)(byte & 0x7f) << shift;
        if (!(byte & 0x80)) { *value = result; return true; }
        shift += 7;
    }
    return false;
}

static bool yx_dump_macho_valid_utf8(const uint8_t *data, size_t size)
{
    size_t i = 0;
    while (i < size) {
        uint8_t first = data[i];
        unsigned extra;
        uint32_t code;
        if (first < 0x80) { ++i; continue; }
        if (first >= 0xc2 && first <= 0xdf) {
            extra = 1; code = first & 0x1fu;
        } else if (first >= 0xe0 && first <= 0xef) {
            extra = 2; code = first & 0x0fu;
        } else if (first >= 0xf0 && first <= 0xf4) {
            extra = 3; code = first & 0x07u;
        } else return false;
        if (extra > size - i - 1) return false;
        for (unsigned j = 1; j <= extra; ++j) {
            uint8_t next = data[i + j];
            if ((next & 0xc0u) != 0x80u) return false;
            code = (code << 6) | (next & 0x3fu);
        }
        if ((extra == 2 && (code < 0x800u ||
                            (code >= 0xd800u && code <= 0xdfffu))) ||
            (extra == 3 && (code < 0x10000u || code > 0x10ffffu)))
            return false;
        i += extra + 1;
    }
    return true;
}

/* The export trie is visited with a LIFO stack, like YARA-X's Mach-O parser.
 * The reversed edge order is visible in the public exports array. */
static void yx_dump_macho_export_trie(yx_dump_doc *doc,
                                       yx_dump_node *parent,
                                       const uint8_t *data, size_t size,
                                       size_t offset, size_t length)
{
    yx_dump_macho_export_node *stack = NULL;
    uint8_t *visited = NULL;
    size_t count = 0, capacity = 0;
    yx_dump_node *array = NULL;
    if (offset > size || length > size - offset || !length) return;
    data += offset;
    size = length;
    visited = calloc(size, 1);
    stack = malloc(sizeof(*stack));
    if (!visited || !stack) goto done;
    stack[0].offset = 0;
    stack[0].prefix = malloc(1);
    if (!stack[0].prefix) goto done;
    stack[0].prefix[0] = '\0';
    count = capacity = 1;
    while (count) {
        yx_dump_macho_export_node node = stack[--count];
        size_t at = node.offset;
        uint64_t terminal_length, flags, ignored;
        bool terminal;
        if (at >= size || visited[at]) { free(node.prefix); continue; }
        visited[at] = 1;
        if (!yx_dump_macho_uleb(data, size, &at, &terminal_length)) {
            free(node.prefix); break;
        }
        terminal = terminal_length != 0;
        if (terminal) {
            if (!yx_dump_macho_uleb(data, size, &at, &flags)) {
                free(node.prefix); break;
            }
            if (flags == 0x10) {
                if (!yx_dump_macho_uleb(data, size, &at, &ignored) ||
                    !yx_dump_macho_uleb(data, size, &at, &ignored)) {
                    free(node.prefix); break;
                }
            } else if (flags == 0x08) {
                if (!yx_dump_macho_uleb(data, size, &at, &ignored) ||
                    at >= size) { free(node.prefix); break; }
                const uint8_t *end = memchr(data + at, 0, size - at);
                if (!end) { free(node.prefix); break; }
                at = (size_t)(end - data) + 1;
            } else if (!yx_dump_macho_uleb(data, size, &at, &ignored)) {
                free(node.prefix); break;
            }
        }
        if (at >= size) { free(node.prefix); break; }
        unsigned edges = data[at++];
        bool valid_edges = true;
        for (unsigned i = 0; i < edges; ++i) {
            const uint8_t *end;
            uint64_t child_offset;
            size_t prefix_length, edge_length;
            char *prefix;
            if (at >= size || !(end = memchr(data + at, 0, size - at))) {
                valid_edges = false;
                break;
            }
            edge_length = (size_t)(end - (data + at));
            prefix_length = strlen(node.prefix);
            if (edge_length > SIZE_MAX - prefix_length - 1) {
                valid_edges = false;
                break;
            }
            prefix = malloc(prefix_length + edge_length + 1);
            if (!prefix) { doc->oom = true; valid_edges = false; break; }
            memcpy(prefix, node.prefix, prefix_length);
            memcpy(prefix + prefix_length, data + at, edge_length);
            prefix[prefix_length + edge_length] = '\0';
            at = (size_t)(end - data) + 1;
            if (!yx_dump_macho_uleb(data, size, &at, &child_offset)) {
                free(prefix); valid_edges = false; break;
            }
            if (child_offset >= size ||
                !yx_dump_macho_valid_utf8(end - edge_length, edge_length)) {
                free(prefix);
                continue;
            }
            if (count == capacity) {
                size_t grown_capacity = capacity <= SIZE_MAX / 2 ?
                                        capacity * 2 : SIZE_MAX;
                yx_dump_macho_export_node *grown;
                if (grown_capacity <= capacity ||
                    grown_capacity > SIZE_MAX / sizeof(*stack)) {
                    free(prefix); doc->oom = true; valid_edges = false;
                    break;
                }
                grown = realloc(stack, grown_capacity * sizeof(*stack));
                if (!grown) {
                    free(prefix); doc->oom = true; valid_edges = false;
                    break;
                }
                stack = grown;
                capacity = grown_capacity;
            }
            stack[count++] = (yx_dump_macho_export_node){
                (size_t)child_offset, prefix
            };
        }
        if (!valid_edges) { free(node.prefix); break; }
        if (terminal) {
            if (!array) array = yx_dump_add(doc, parent, "exports",
                                            YX_DUMP_ARRAY);
            if (array) yx_dump_text(doc, array, NULL, node.prefix,
                                    strlen(node.prefix), false);
        }
        free(node.prefix);
    }
done:
    for (size_t i = 0; i < count; ++i) free(stack[i].prefix);
    free(stack);
    free(visited);
}

/* A load command is sufficient to suppress symbol-table fallback, even when
 * its export data is malformed or empty. */
static bool yx_dump_macho_trie(yx_dump_doc *doc, yx_dump_node *parent,
                                const uint8_t *data, size_t size)
{
    const uint8_t *payload;
    size_t length;
    bool little;
    if (!yx_dump_macho_command(data, size, UINT32_C(0x80000033),
                                &payload, &length, &little))
        return false;
    if (length >= 8)
        yx_dump_macho_export_trie(doc, parent, data, size,
            (size_t)yx_dump_macho_read(payload, 4, little),
            (size_t)yx_dump_macho_read(payload + 4, 4, little));
    return true;
}

static size_t yx_dump_macho_version(char text[32], uint64_t encoded,
                                     bool build_tool)
{
    int n;
    if (build_tool)
        n = snprintf(text, 32, "%" PRIu64 ".%" PRIu64,
                     encoded >> 16, (encoded >> 8) & 0xff);
    else n = snprintf(text, 32, "%" PRIu64 ".%" PRIu64 ".%" PRIu64,
                      encoded >> 16, (encoded >> 8) & 0xff, encoded & 0xff);
    return n > 0 && n < 32 ? (size_t)n : 0;
}

static void yx_dump_macho_build_version(yx_dump_doc *doc,
                                         yx_dump_node *parent,
                                         const uint8_t *data, size_t size)
{
    const uint8_t *payload = NULL;
    size_t length = 0;
    bool little;
    if (!yx_dump_macho_command(data, size, 0x32, &payload, &length, &little) ||
        length < 16) return;
    uint64_t ntools = yx_dump_macho_read(payload + 12, 4, little);
    if (ntools > (length - 16) / 8) return;
    yx_dump_node *object = yx_dump_add(doc, parent, "build_version",
                                        YX_DUMP_OBJECT);
    if (!object) return;
    yx_dump_number(doc, object, "platform",
                    yx_dump_macho_read(payload, 4, little), false,
                    YX_DUMP_DECIMAL);
    static const char *const names[] = {"minos", "sdk"};
    for (size_t i = 0; i < 2; ++i) {
        char version[32];
        size_t n = yx_dump_macho_version(version,
            yx_dump_macho_read(payload + 4 + i * 4, 4, little), false);
        if (n) yx_dump_text(doc, object, names[i], version, n, false);
    }
    yx_dump_number(doc, object, "ntools", ntools, false, YX_DUMP_DECIMAL);
    if (ntools) {
        yx_dump_node *array = yx_dump_add(doc, object, "tools", YX_DUMP_ARRAY);
        for (uint64_t i = 0; array && i < ntools; ++i) {
            const uint8_t *tool = payload + 16 + (size_t)i * 8;
            yx_dump_node *item = yx_dump_add(doc, array, NULL,
                                              YX_DUMP_OBJECT);
            if (!item) break;
            yx_dump_number(doc, item, "tool",
                            yx_dump_macho_read(tool, 4, little), false,
                            YX_DUMP_DECIMAL);
            char version[32];
            size_t n = yx_dump_macho_version(version,
                yx_dump_macho_read(tool + 4, 4, little), true);
            if (n) yx_dump_text(doc, item, "version", version, n, false);
        }
    }
}

static void yx_dump_macho_min_version(yx_dump_doc *doc,
                                       yx_dump_node *parent,
                                       const uint8_t *data, size_t size)
{
    static const struct { uint32_t command; const char *name; } devices[] = {
        {0x24, "MACOSX"}, {0x25, "IPHONEOS"}, {0x2f, "TVOS"},
        {0x30, "WATCHOS"}
    };
    const uint8_t *payload = NULL, *last = NULL;
    size_t length = 0, last_length = 0;
    bool little = false, last_little = false;
    size_t device = 0;
    for (size_t i = 0; i < 4; ++i) {
        if (yx_dump_macho_command(data, size, devices[i].command,
                                   &payload, &length, &little) && length >= 8) {
            last = payload; last_length = length; last_little = little;
            device = i;
        }
    }
    if (!last || last_length < 8) return;
    yx_dump_node *object = yx_dump_add(doc, parent, "min_version",
                                        YX_DUMP_OBJECT);
    if (!object) return;
    yx_dump_enum(doc, object, "device", devices[device].command,
                  devices[device].name);
    static const char *const names[] = {"version", "sdk"};
    for (size_t i = 0; i < 2; ++i) {
        char version[32];
        size_t n = yx_dump_macho_version(version,
            yx_dump_macho_read(last + i * 4, 4, last_little), false);
        if (n) yx_dump_text(doc, object, names[i], version, n, false);
    }
}

static void yx_dump_macho_file_order(yx_dump_doc *doc, yx_dump_node *file)
{
    static const char *const order[] = {
        "magic", "cputype", "cpusubtype", "filetype", "ncmds",
        "sizeofcmds", "flags", "reserved", "number_of_segments",
        "dynamic_linker", "entry_point", "stack_size", "source_version",
        "segments", "dylibs", "rpaths", "entitlements", "symtab",
        "dysymtab", "dyld_info", "code_signature_data", "certificates",
        "uuid", "build_version", "min_version", "exports", "imports",
        "linker_options"
    };
    yx_dump_node *first = NULL, *last = NULL;
    if (!file) return;
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); ++i) {
        yx_dump_node *previous = NULL;
        yx_dump_node *item = file->first;
        while (item && (!item->key || strcmp(item->key, order[i]) != 0)) {
            previous = item;
            item = item->next;
        }
        if (!item) continue;
        if (previous) previous->next = item->next;
        else file->first = item->next;
        item->next = NULL;
        if (last) last->next = item;
        else first = item;
        last = item;
    }
    if (last) last->next = file->first;
    else first = file->first;
    if (!last) last = first;
    while (last && last->next) last = last->next;
    file->first = first;
    file->last = last;
    for (yx_dump_node *item = file->first; item; item = item->next)
        if (item->key && strcmp(item->key, "flags") == 0) {
            item->format = YX_DUMP_FLAGS;
            yx_dump_macho_flags(doc, item, false);
            break;
        }
}

static void yx_dump_macho(yx_dump_doc *doc, yx_dump_node *parent,
                            const uint8_t *data, size_t size)
{
    static const char *const header[] = {
        "magic", "cputype", "cpusubtype", "filetype", "ncmds",
        "sizeofcmds", "flags", "reserved", "number_of_segments"
    };
    static const char *const symtab[] = {
        "symoff", "nsyms", "stroff", "strsize"
    };
    static const char *const dysymtab[] = {
        "ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym",
        "iundefsym", "nundefsym", "tocoff", "ntoc", "modtaboff",
        "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff",
        "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel"
    };
    static const char *const signature[] = {"dataoff", "datasize"};
    static const char *const dyld_info[] = {
        "rebase_off", "rebase_size", "bind_off", "bind_size",
        "weak_bind_off", "weak_bind_size", "lazy_bind_off",
        "lazy_bind_size", "export_off", "export_size"
    };
    const uint8_t *file_data = data;
    size_t file_size = size;
    (void)yx_macho_top_file_span(data, size, &file_data, &file_size);
    yx_dump_node *module = yx_dump_add(doc, parent, "macho", YX_DUMP_OBJECT);
    if (!module) return;
    yx_macho_extras extras = {0};
    (void)yx_macho_extras_parse(data, size, &extras);
    for (size_t i = 0; i < sizeof(header) / sizeof(header[0]); ++i) {
        uint64_t value;
        if (!yx_macho_field(data, size, header[i], &value)) continue;
        yx_dump_number(doc, module, header[i], value,
            i == 8, i == 0 || i == 1 || i == 2 || i == 6 ?
            YX_DUMP_HEX : YX_DUMP_DECIMAL);
    }
    {
        const uint8_t *bytes;
        size_t length;
        if (yx_macho_string_field(data, size, "dynamic_linker",
                                   &bytes, &length))
            yx_dump_text(doc, module, "dynamic_linker", bytes, length, true);
    }
    yx_dump_macho_number(doc, module, data, size, "entry_point", true,
                          YX_DUMP_DECIMAL);
    yx_dump_macho_number(doc, module, data, size, "stack_size", true,
                          YX_DUMP_DECIMAL);
    {
        char version[32];
        size_t length;
        if (yx_macho_source_version(data, size, version, sizeof(version),
                                     &length))
            yx_dump_text(doc, module, "source_version", version, length,
                          false);
    }
    yx_dump_node *symbols = yx_dump_macho_object(doc, module,
        file_data, file_size,
        "symtab", symtab, sizeof(symtab) / sizeof(symtab[0]));
    yx_dump_macho_object(doc, module, data, size, "dysymtab", dysymtab,
                          sizeof(dysymtab) / sizeof(dysymtab[0]));
    yx_dump_macho_object(doc, module, data, size, "code_signature_data",
                          signature, sizeof(signature) / sizeof(signature[0]));
    yx_dump_macho_collections(doc, module, data, size);
    yx_dump_macho_object(doc, module, data, size, "dyld_info", dyld_info,
                          sizeof(dyld_info) / sizeof(dyld_info[0]));
    yx_dump_macho_byte_array(doc, module, data, size, "rpaths");
    yx_dump_macho_entitlements(doc, module, &extras);
    yx_dump_macho_certificates(doc, module, &extras);
    {
        char uuid[37];
        size_t length;
        if (yx_macho_uuid(data, size, uuid, sizeof(uuid), &length))
            yx_dump_text(doc, module, "uuid", uuid, length, false);
    }
    yx_dump_macho_build_version(doc, module, file_data, file_size);
    yx_dump_macho_min_version(doc, module, file_data, file_size);
    {
        bool trie = yx_dump_macho_trie(doc, module, file_data, file_size);
        /* Whether LC_DYLD_INFO or LC_DYLD_INFO_ONLY is present, checked
         * directly against the load commands (same technique as the
         * chained-fixups check below) rather than inferred from whether a
         * "dyld_info" node happened to get added to the dump tree: a
         * present-but-all-zero-fields dyld_info command must still count
         * as present, or the imports/exports symtab fallback fires twice
         * (once from the real data, once from the fallback) and the JSON
         * output gets a duplicate key. */
        const uint8_t *dyld_payload;
        size_t dyld_length;
        bool dyld_little;
        bool dyld_info_present =
            yx_dump_macho_command(file_data, file_size, 0x22, &dyld_payload,
                                    &dyld_length, &dyld_little) ||
            yx_dump_macho_command(file_data, file_size, UINT32_C(0x80000022),
                                    &dyld_payload, &dyld_length,
                                    &dyld_little);
        if (yx_dump_child(module, "dyld_info") != NULL) {
            uint64_t offset, length;
            if (yx_macho_field(data, size, "dyld_info.export_off",
                                &offset) &&
                yx_macho_field(data, size, "dyld_info.export_size",
                                &length) &&
                offset <= file_size && length <= file_size - offset)
                yx_dump_macho_export_trie(doc, module, file_data, file_size,
                                            (size_t)offset, (size_t)length);
        }
        if (!dyld_info_present && !trie)
            yx_dump_macho_symbol_names(doc, module, symbols, true, false);
        /* Upstream falls back to symtab imports only when both
         * LC_DYLD_CHAINED_FIXUPS and LC_DYLD_INFO (LC_DYLD_INFO_ONLY) are
         * absent (macho/parser.rs ~2244), not merely when the
         * chained-fixups/bind-opcode parse happened to yield zero import
         * names (a present-but-empty table must not trigger the symtab
         * fallback). extras->import_count is also checked directly (belt
         * and suspenders): real imports and the symtab fallback must never
         * both be added, or the dump gets two "imports" keys. */
        {
            bool has_imports = yx_dump_macho_imports(doc, module, &extras);
            const uint8_t *chained_payload;
            size_t chained_length;
            bool chained_little;
            bool chained_fixups = yx_dump_macho_command(
                file_data, file_size, UINT32_C(0x80000034), &chained_payload,
                &chained_length, &chained_little);
            if (!has_imports && !dyld_info_present && !chained_fixups)
                yx_dump_macho_symbol_names(doc, module, symbols, false, true);
        }
    }
    yx_dump_macho_byte_array(doc, module, data, size, "linker_options");
    yx_dump_macho_number(doc, module, data, size, "fat_magic", false,
                          YX_DUMP_HEX);
    yx_dump_macho_number(doc, module, data, size, "nfat_arch", false,
                          YX_DUMP_DECIMAL);
    {
        static const char *const fields[] = {
            "cputype", "cpusubtype", "offset", "size", "align", "reserved"
        };
        uint64_t count = 0;
        if (yx_macho_collection_count(data, size, "fat_arch", &count) && count) {
            yx_dump_node *array = yx_dump_add(doc, module, "fat_arch",
                                               YX_DUMP_ARRAY);
            for (uint64_t i = 0; array && i < count; ++i) {
                yx_dump_node *item = yx_dump_add(doc, array, NULL,
                                                  YX_DUMP_OBJECT);
                if (!item) break;
                for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); ++j) {
                    uint64_t value;
                    if (yx_macho_fat_arch_field(data, size, i, fields[j],
                                                &value))
                        yx_dump_number(doc, item, fields[j], value, j < 4,
                                        j < 2 ? YX_DUMP_HEX : YX_DUMP_DECIMAL);
                }
            }
        }
    }
    {
        uint64_t count = 0, arch_count = 0, emitted = 0;
        yx_dump_node *array = NULL;
        if (yx_macho_collection_count(data, size, "file", &count) && count &&
            yx_macho_field(data, size, "nfat_arch", &arch_count)) {
            array = yx_dump_add(doc, module, "file", YX_DUMP_ARRAY);
            for (uint64_t i = 0; array && i < arch_count && emitted < count;
                 ++i) {
                uint64_t offset, length, child_magic;
                if (!yx_macho_fat_arch_field(data, size, i, "offset",
                                               &offset) ||
                    !yx_macho_fat_arch_field(data, size, i, "size",
                                               &length) ||
                    offset > size || length > size - offset ||
                    !yx_macho_field(data + (size_t)offset, (size_t)length,
                                     "magic", &child_magic)) continue;
                yx_dump_macho(doc, array, data + (size_t)offset,
                               (size_t)length);
                yx_dump_node *file = array->last;
                if (file) {
                    file->key = NULL;
                    yx_dump_macho_file_order(doc, file);
                    ++emitted;
                }
            }
        }
    }
    yx_macho_extras_free(&extras);
}

static const char *yx_dump_dex_type_name(uint64_t value)
{
    static const struct { uint64_t value; const char *name; } names[] = {
        {0x0000, "TYPE_HEADER_ITEM"}, {0x0001, "TYPE_STRING_ID_ITEM"},
        {0x0002, "TYPE_TYPE_ID_ITEM"}, {0x0003, "TYPE_PROTO_ID_ITEM"},
        {0x0004, "TYPE_FIELD_ID_ITEM"}, {0x0005, "TYPE_METHOD_ID_ITEM"},
        {0x0006, "TYPE_CLASS_DEF_ITEM"}, {0x0007, "TYPE_CALL_SITE_ID_ITEM"},
        {0x0008, "TYPE_METHOD_HANDLE_ITEM"}, {0x1000, "TYPE_MAP_LIST"},
        {0x1001, "TYPE_TYPE_LIST"},
        {0x1002, "TYPE_ANNOTATION_SET_REF_LIST"},
        {0x1003, "TYPE_ANNOTATION_SET_ITEM"},
        {0x2000, "TYPE_CLASS_DATA_ITEM"}, {0x2001, "TYPE_CODE_ITEM"},
        {0x2002, "TYPE_STRING_DATA_ITEM"},
        {0x2003, "TYPE_DEBUG_INFO_ITEM"},
        {0x2004, "TYPE_ANNOTATION_ITEM"},
        {0x2005, "TYPE_ENCODED_ARRAY_ITEM"},
        {0x2006, "TYPE_ANNOTATIONS_DIRECTORY_ITEM"},
        {0xf000, "TYPE_HIDDENAPI_CLASS_DATA_ITEM"}
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (names[i].value == value) return names[i].name;
    return NULL;
}

static void yx_dump_dex_flags(yx_dump_doc *doc, yx_dump_node *node)
{
    static const struct { uint32_t bit; const char *name; } flags[] = {
        {1, "ACC_PUBLIC"}, {2, "ACC_PRIVATE"}, {4, "ACC_PROTECTED"},
        {8, "ACC_STATIC"}, {16, "ACC_FINAL"},
        {32, "ACC_SYNCHRONIZED"}, {64, "ACC_BRIDGE"},
        {128, "ACC_VARARGS"}, {256, "ACC_NATIVE"},
        {512, "ACC_INTERFACE"}, {1024, "ACC_ABSTRACT"},
        {2048, "ACC_STRICT"}, {4096, "ACC_SYNTHETIC"},
        {8192, "ACC_ANNOTATION"}, {16384, "ACC_ENUM"},
        {65536, "ACC_CONSTRUCTOR"},
        {131072, "ACC_DECLARED_SYNCHRONIZED"}
    };
    char text[512] = {0};
    size_t used = 0;
    if (!node) return;
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        if (!(node->number & flags[i].bit)) continue;
        int n = snprintf(text + used, sizeof(text) - used, "%s%s",
                         used ? " | " : "", flags[i].name);
        if (n < 0 || (size_t)n >= sizeof(text) - used) return;
        used += (size_t)n;
    }
    if (!used) return;
    node->owned = (char *)malloc(used + 1);
    if (!node->owned) { doc->oom = true; return; }
    memcpy(node->owned, text, used + 1);
    node->comment = node->owned;
}

static void yx_dump_dex_string(yx_dump_doc *doc, yx_dump_node *parent,
                                const yx_dex_result *result,
                                const char *collection, uint64_t index,
                                const char *member, const char *key)
{
    const uint8_t *bytes;
    size_t length;
    if (yx_dex_indexed_string_field(result, collection, index, member,
                                     &bytes, &length))
        yx_dump_text(doc, parent, key, bytes, length, false);
}

static void yx_dump_dex_parameters(yx_dump_doc *doc, yx_dump_node *parent,
                                    const yx_dex_result *result,
                                    const char *collection, uint64_t index,
                                    const char *nested)
{
    uint64_t count;
    if (!yx_dex_nested_collection_count(result, collection, index,
                                          nested, &count) || !count) return;
    yx_dump_node *array = yx_dump_add(doc, parent, "parameters", YX_DUMP_ARRAY);
    for (uint64_t j = 0; array && j < count; ++j) {
        const uint8_t *bytes;
        size_t length;
        if (yx_dex_nested_indexed_string(result, collection, index,
                                          nested, j, &bytes, &length))
            yx_dump_text(doc, array, NULL, bytes, length, false);
    }
}

static void yx_dump_dex_proto(yx_dump_doc *doc, yx_dump_node *parent,
                               const yx_dex_result *result,
                               const char *collection, uint64_t index,
                               bool nested)
{
    const char *prefix = nested ? "proto." : "";
    char member[40];
    uint64_t value;
    const char *const strings[] = {"shorty", "return_type"};
    for (size_t i = 0; i < 2; ++i) {
        snprintf(member, sizeof(member), "%s%s", prefix, strings[i]);
        yx_dump_dex_string(doc, parent, result, collection, index,
                            member, strings[i]);
    }
    snprintf(member, sizeof(member), "%sparameters_count", prefix);
    if (yx_dex_indexed_numeric_field(result, collection, index,
                                      member, &value))
        yx_dump_number(doc, parent, "parameters_count", value, false,
                        YX_DUMP_DECIMAL);
    yx_dump_dex_parameters(doc, parent, result, collection, index,
                            nested ? "proto.parameters" : "parameters");
}

static void yx_dump_dex(yx_dump_doc *doc, yx_dump_node *parent,
                         const uint8_t *data, size_t size)
{
    static const char *const header[] = {
        "magic", "version", "checksum", "file_size", "header_size",
        "endian_tag", "link_size", "link_off", "data_size", "data_off",
        "container_size", "header_offset"
    };
    static const char *const collection_names[] = {
        "strings", "types", "protos", "fields", "methods", "class_defs"
    };
    yx_dex_result *result = yx_dex_parse(data, size);
    yx_dump_node *module = yx_dump_add(doc, parent, "dex", YX_DUMP_OBJECT);
    uint64_t valid = 0;
    if (!result || !module) { doc->oom = true; yx_dex_destroy(result); return; }
    yx_dex_numeric_field(result, "is_dex", &valid);
    yx_dump_boolean(doc, module, "is_dex", valid != 0);
    if (!valid) { yx_dex_destroy(result); return; }
    yx_dump_node *object = yx_dump_add(doc, module, "header", YX_DUMP_OBJECT);
    for (size_t i = 0; object && i < sizeof(header) / sizeof(header[0]); ++i) {
        char path[40];
        uint64_t value;
        snprintf(path, sizeof(path), "header.%s", header[i]);
        if (yx_dex_numeric_field(result, path, &value))
            yx_dump_number(doc, object, header[i], value, false,
                            i == 0 || i == 2 || i == 4 || i == 5 ||
                            i == 7 || i == 9 || i == 11 ? YX_DUMP_HEX :
                            YX_DUMP_DECIMAL);
        if (i == 2) {
            const uint8_t *bytes;
            size_t length;
            if (yx_dex_string_field(result, "header.signature", &bytes,
                                      &length))
                yx_dump_text(doc, object, "signature", bytes, length, false);
        }
    }
    for (size_t c = 0; c < 6; ++c) {
        uint64_t count = 0;
        const char *collection = collection_names[c];
        if (!yx_dex_collection_count(result, collection, &count) || !count)
            continue;
        yx_dump_node *array = yx_dump_add(doc, module, collection,
                                           YX_DUMP_ARRAY);
        for (uint64_t i = 0; array && i < count; ++i) {
            if (c <= 1) {
                yx_dump_dex_string(doc, array, result, collection, i,
                                    "value", NULL);
                continue;
            }
            yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
            uint64_t value;
            if (!item) break;
            if (c == 2) yx_dump_dex_proto(doc, item, result, collection,
                                           i, false);
            if (c == 3) {
                static const char *const names[] = {"class", "type", "name"};
                for (size_t j = 0; j < 3; ++j)
                    yx_dump_dex_string(doc, item, result, collection, i,
                                        names[j], names[j]);
            }
            if (c == 4) {
                yx_dump_dex_string(doc, item, result, collection, i,
                                    "class", "class");
                yx_dump_node *proto = yx_dump_add(doc, item, "proto",
                                                    YX_DUMP_OBJECT);
                if (proto) yx_dump_dex_proto(doc, proto, result, collection,
                                              i, true);
                yx_dump_dex_string(doc, item, result, collection, i,
                                    "name", "name");
            }
            if (c == 5) {
                yx_dump_dex_string(doc, item, result, collection, i,
                                    "class", "class");
                if (yx_dex_indexed_numeric_field(result, collection, i,
                                                   "access_flags", &value)) {
                    yx_dump_node *field = yx_dump_number(doc, item,
                        "access_flags", value, false, YX_DUMP_FLAGS);
                    yx_dump_dex_flags(doc, field);
                }
                yx_dump_dex_string(doc, item, result, collection, i,
                                    "superclass", "superclass");
                yx_dump_dex_string(doc, item, result, collection, i,
                                    "source_file", "source_file");
            }
        }
    }
    {
        uint64_t value;
        if (yx_dex_numeric_field(result, "map_list.size", &value)) {
            yx_dump_node *map = yx_dump_add(doc, module, "map_list",
                                             YX_DUMP_OBJECT);
            if (map) yx_dump_number(doc, map, "size", value, false,
                                     YX_DUMP_DECIMAL);
            uint64_t count = 0;
            if (map && yx_dex_collection_count(result, "map_list.items",
                                                 &count) && count) {
                yx_dump_node *array = yx_dump_add(doc, map, "items",
                                                   YX_DUMP_ARRAY);
                static const char *const fields[] = {
                    "type", "unused", "size", "offset"
                };
                for (uint64_t i = 0; array && i < count; ++i) {
                    yx_dump_node *item = yx_dump_add(doc, array, NULL,
                                                      YX_DUMP_OBJECT);
                    for (size_t j = 0; item && j < 4; ++j) {
                        if (!yx_dex_indexed_numeric_field(result,
                            "map_list.items", i, fields[j], &value)) continue;
                        if (j == 0) yx_dump_enum(doc, item, fields[j], value,
                                                  yx_dump_dex_type_name(value));
                        else yx_dump_number(doc, item, fields[j], value,
                                             false, j == 3 ? YX_DUMP_HEX :
                                             YX_DUMP_DECIMAL);
                    }
                }
            }
        }
    }
    yx_dex_destroy(result);
}

static uint64_t yx_dump_le(const uint8_t *data, size_t at, unsigned width)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i)
        value |= (uint64_t)data[at + i] << (8 * i);
    return value;
}

static const char *yx_dump_pe_enum_name(const char *kind, uint64_t value)
{
    static const char *const machines[] = {
        "MACHINE_UNKNOWN", "MACHINE_ALPHA", "MACHINE_ALPHA64",
        "MACHINE_AM33", "MACHINE_AMD64", "MACHINE_ARM", "MACHINE_ARM64",
        "MACHINE_ARM64EC", "MACHINE_ARM64X", "MACHINE_ARMNT",
        "MACHINE_EBC", "MACHINE_I386", "MACHINE_IA64",
        "MACHINE_LOONGARCH32", "MACHINE_LOONGARCH64", "MACHINE_M32R",
        "MACHINE_MIPS16", "MACHINE_MIPSFPU", "MACHINE_MIPSFPU16",
        "MACHINE_POWERPC", "MACHINE_POWERPCFP", "MACHINE_R3000BE",
        "MACHINE_R3000", "MACHINE_R4000", "MACHINE_R10000",
        "MACHINE_RISCV32", "MACHINE_RISCV64", "MACHINE_RISCV128",
        "MACHINE_SH3", "MACHINE_SH3DSP", "MACHINE_SH4", "MACHINE_SH5",
        "MACHINE_THUMB", "MACHINE_WCEMIPSV2"
    };
    static const char *const subsystems[] = {
        "SUBSYSTEM_UNKNOWN", "SUBSYSTEM_NATIVE", "SUBSYSTEM_WINDOWS_GUI",
        "SUBSYSTEM_WINDOWS_CUI", "SUBSYSTEM_OS2_CUI",
        "SUBSYSTEM_POSIX_CUI", "SUBSYSTEM_NATIVE_WINDOWS",
        "SUBSYSTEM_WINDOWS_CE_GUI", "SUBSYSTEM_EFI_APPLICATION",
        "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
        "SUBSYSTEM_EFI_RUNTIME_DRIVER", "SUBSYSTEM_EFI_ROM_IMAGE",
        "SUBSYSTEM_XBOX", "SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
    };
    static const char *const magics[] = {
        "IMAGE_NT_OPTIONAL_HDR32_MAGIC", "IMAGE_NT_OPTIONAL_HDR64_MAGIC",
        "IMAGE_ROM_OPTIONAL_HDR_MAGIC"
    };
    const char *const *names;
    size_t count;
    if (strcmp(kind, "machine") == 0) {
        names = machines; count = sizeof(machines) / sizeof(machines[0]);
    } else if (strcmp(kind, "subsystem") == 0) {
        names = subsystems; count = sizeof(subsystems) / sizeof(subsystems[0]);
    } else {
        names = magics; count = sizeof(magics) / sizeof(magics[0]);
    }
    for (size_t i = 0; i < count; ++i) {
        uint64_t constant;
        if (yx_pe_constant(names[i], &constant) && constant == value)
            return names[i];
    }
    return NULL;
}

static void yx_dump_pe_flags(yx_dump_doc *doc, yx_dump_node *node,
                              const char *kind)
{
    static const char *const characteristics[] = {
        "RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "LINE_NUMS_STRIPPED",
        "LOCAL_SYMS_STRIPPED", "AGGRESIVE_WS_TRIM", "LARGE_ADDRESS_AWARE",
        "BYTES_REVERSED_LO", "MACHINE_32BIT", "DEBUG_STRIPPED",
        "REMOVABLE_RUN_FROM_SWAP", "NET_RUN_FROM_SWAP", "SYSTEM", "DLL",
        "UP_SYSTEM_ONLY", "BYTES_REVERSED_HI"
    };
    static const char *const dll[] = {
        "HIGH_ENTROPY_VA", "DYNAMIC_BASE", "FORCE_INTEGRITY",
        "NX_COMPAT", "NO_ISOLATION", "NO_SEH", "NO_BIND",
        "APPCONTAINER", "WDM_DRIVER", "GUARD_CF",
        "TERMINAL_SERVER_AWARE"
    };
    const char *const *names = strcmp(kind, "characteristics") == 0 ?
                               characteristics : dll;
    size_t count = strcmp(kind, "characteristics") == 0 ?
                   sizeof(characteristics) / sizeof(characteristics[0]) :
                   sizeof(dll) / sizeof(dll[0]);
    char comment[512] = {0};
    for (size_t i = 0; i < count; ++i) {
        uint64_t constant;
        if (!yx_pe_constant(names[i], &constant) ||
            !(node->number & constant)) continue;
        size_t current = strlen(comment);
        int written = snprintf(comment + current, sizeof(comment) - current,
                               "%s%s", current ? " | " : "", names[i]);
        if (written < 0 || (size_t)written >= sizeof(comment) - current)
            break;
    }
    if (*comment) {
        size_t length = strlen(comment);
        node->owned = (char *)malloc(length + 1);
        if (!node->owned) { doc->oom = true; return; }
        memcpy(node->owned, comment, length + 1);
        node->comment = node->owned;
    }
}

static void yx_dump_pe_timestamp(yx_dump_doc *doc, yx_dump_node *node)
{
    time_t stamp = (time_t)node->number;
    struct tm *utc = gmtime(&stamp);
    char text[64];
    size_t length;
    if (!utc || !(length = strftime(text, sizeof(text),
                                    "%Y-%m-%d %H:%M:%S UTC", utc))) return;
    node->owned = (char *)malloc(length + 1);
    if (!node->owned) { doc->oom = true; return; }
    memcpy(node->owned, text, length + 1);
    node->comment = node->owned;
}

static void yx_dump_pe_number(yx_dump_doc *doc, yx_dump_node *module,
                               const uint8_t *data, size_t size,
                               const char *name)
{
    uint64_t value;
    yx_dump_format format = YX_DUMP_DECIMAL;
    yx_dump_node *node;
    if (!yx_pe_field(data, size, name, &value)) return;
    if (strcmp(name, "machine") == 0 ||
        strcmp(name, "subsystem") == 0 ||
        strcmp(name, "opthdr_magic") == 0) {
        yx_dump_enum(doc, module, name, value,
                      yx_dump_pe_enum_name(name, value));
        return;
    }
    if (strcmp(name, "timestamp") == 0 ||
        strcmp(name, "export_timestamp") == 0)
        format = YX_DUMP_TIMESTAMP;
    else if (strcmp(name, "characteristics") == 0 ||
             strcmp(name, "dll_characteristics") == 0)
        format = YX_DUMP_FLAGS;
    else if (strcmp(name, "image_base") == 0 ||
             strcmp(name, "base_of_code") == 0 ||
             strcmp(name, "base_of_data") == 0 ||
             strcmp(name, "entry_point") == 0 ||
             strcmp(name, "entry_point_raw") == 0 ||
             strcmp(name, "section_alignment") == 0 ||
             strcmp(name, "file_alignment") == 0 ||
             strcmp(name, "loader_flags") == 0 ||
             strncmp(name, "size_of_", 8) == 0 ||
             strcmp(name, "pointer_to_symbol_table") == 0)
        format = YX_DUMP_HEX;
    node = yx_dump_number(doc, module, name, value,
                           strcmp(name, "image_base") == 0 ||
                           strstr(name, "stack_") || strstr(name, "heap_"),
                           format);
    if (!node) return;
    if (format == YX_DUMP_FLAGS) yx_dump_pe_flags(doc, node, name);
    if (format == YX_DUMP_TIMESTAMP) yx_dump_pe_timestamp(doc, node);
}

static void yx_dump_pe_version(yx_dump_doc *doc, yx_dump_node *module,
                                const char *name, const uint8_t *data,
                                size_t size, size_t offset,
                                unsigned width, bool optional_valid)
{
    if (optional_valid && (offset > size || 2 * width > size - offset))
        return;
    yx_dump_node *version = yx_dump_add(doc, module, name, YX_DUMP_OBJECT);
    if (!version) return;
    yx_dump_number(doc, version, "major",
                    optional_valid ? yx_dump_le(data, offset, width) : 0,
                    false, YX_DUMP_DECIMAL);
    yx_dump_number(doc, version, "minor",
                    optional_valid ? yx_dump_le(data, offset + width, width) : 0,
                    false,
                    YX_DUMP_DECIMAL);
}

static void yx_dump_pe_section_flags(yx_dump_doc *doc, yx_dump_node *node)
{
    static const char *const names[] = {
        "SECTION_NO_PAD", "SECTION_CNT_CODE",
        "SECTION_CNT_INITIALIZED_DATA", "SECTION_CNT_UNINITIALIZED_DATA",
        "SECTION_LNK_OTHER", "SECTION_LNK_INFO", "SECTION_LNK_REMOVE",
        "SECTION_LNK_COMDAT", "SECTION_NO_DEFER_SPEC_EXC", "SECTION_GPREL",
        "SECTION_ALIGN_1BYTES", "SECTION_ALIGN_2BYTES",
        "SECTION_ALIGN_4BYTES", "SECTION_ALIGN_8BYTES",
        "SECTION_ALIGN_16BYTES", "SECTION_ALIGN_32BYTES",
        "SECTION_ALIGN_64BYTES", "SECTION_ALIGN_128BYTES",
        "SECTION_ALIGN_256BYTES", "SECTION_ALIGN_512BYTES",
        "SECTION_ALIGN_1024BYTES", "SECTION_ALIGN_2048BYTES",
        "SECTION_ALIGN_4096BYTES", "SECTION_ALIGN_8192BYTES",
        "SECTION_ALIGN_MASK", "SECTION_LNK_NRELOC_OVFL",
        "SECTION_MEM_DISCARDABLE", "SECTION_MEM_NOT_CACHED",
        "SECTION_MEM_NOT_PAGED", "SECTION_MEM_SHARED",
        "SECTION_MEM_EXECUTE", "SECTION_MEM_READ", "SECTION_MEM_WRITE",
        "SECTION_SCALE_INDEX"
    };
    char comment[1024] = {0};
    size_t used = 0;
    if (!node) return;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (!(node->number & (i + 1))) continue;
        int n = snprintf(comment + used, sizeof(comment) - used, "%s%s",
                         used ? " | " : "", names[i]);
        if (n < 0 || (size_t)n >= sizeof(comment) - used) return;
        used += (size_t)n;
    }
    if (!used) return;
    node->owned = (char *)malloc(used + 1);
    if (!node->owned) { doc->oom = true; return; }
    memcpy(node->owned, comment, used + 1);
    node->comment = node->owned;
}

static void yx_dump_pe_sections(yx_dump_doc *doc, yx_dump_node *module,
                                  const uint8_t *data, size_t size)
{
    static const char *const fields[] = {
        "characteristics", "raw_data_size", "raw_data_offset",
        "virtual_address", "virtual_size", "pointer_to_relocations",
        "pointer_to_line_numbers", "number_of_relocations",
        "number_of_line_numbers"
    };
    uint64_t count = 0;
    if (!yx_pe_section_count(data, size, &count) || !count) return;
    yx_dump_node *array = yx_dump_add(doc, module, "sections", YX_DUMP_ARRAY);
    for (uint64_t i = 0; array && i < count; ++i) {
        yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
        if (!item) break;
        static const char *const names[] = {"name", "full_name"};
        for (size_t j = 0; j < 2; ++j) {
            const uint8_t *bytes;
            size_t length;
            if (yx_pe_section_string_field(data, size, i, names[j],
                                            &bytes, &length))
                yx_dump_text(doc, item, names[j], bytes, length, true);
        }
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); ++j) {
            uint64_t value;
            if (!yx_pe_section_field(data, size, i, fields[j], &value))
                continue;
            yx_dump_node *field = yx_dump_number(doc, item, fields[j], value,
                false, j <= 6 ? YX_DUMP_HEX : YX_DUMP_DECIMAL);
            if (j == 0) yx_dump_pe_section_flags(doc, field);
        }
    }
}

static void yx_dump_pe_directories(yx_dump_doc *doc, yx_dump_node *module,
                                    const uint8_t *data, size_t size)
{
    uint64_t count, pe_offset;
    if (!yx_pe_field(data, size, "number_of_rva_and_sizes", &count) ||
        size < 64) return;
    pe_offset = yx_dump_le(data, 60, 4);
    if (pe_offset > size || size - pe_offset < 26) return;
    size_t opt = (size_t)pe_offset + 24;
    uint64_t magic = yx_dump_le(data, opt, 2);
    size_t header_size = magic == 0x20b ? 112u : 96u;
    size_t first = opt + header_size;
    /* The reference reads directories present in the file even when the
       COFF header declares a shorter optional header. */
    if (first > size) return;
    uint64_t available = (size - first) / 8;
    if (count > 16) count = 16;
    /* The parser reads the requested entries as one array. An incomplete
     * directory table produces no entries, even if some records fit. */
    if (!count || count > available) return;
    yx_dump_node *array = yx_dump_add(doc, module, "data_directories",
                                       YX_DUMP_ARRAY);
    for (uint64_t i = 0; array && i < count; ++i) {
        size_t at = first + (size_t)i * 8;
        yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
        if (!item) break;
        yx_dump_number(doc, item, "virtual_address",
                        yx_dump_le(data, at, 4), false, YX_DUMP_HEX);
        yx_dump_number(doc, item, "size", yx_dump_le(data, at + 4, 4),
                        false, YX_DUMP_HEX);
    }
}

static void yx_dump_pe_rich_signature(yx_dump_doc *doc,
                                       yx_dump_node *module,
                                       const uint8_t *data, size_t size)
{
    if (size < 64) return;
    uint64_t pe_offset = yx_dump_le(data, 60, 4);
    if (pe_offset > size || pe_offset < 8) return;
    size_t rich = SIZE_MAX;
    for (size_t i = (size_t)pe_offset - 8;; --i) {
        if (memcmp(data + i, "Rich", 4) == 0) { rich = i; break; }
        if (i == 0) break;
    }
    /* "DanS" precedes "Rich" by at least one 4-byte word. */
    if (rich == SIZE_MAX || rich < 4) return;
    uint32_t key = (uint32_t)yx_dump_le(data, rich + 4, 4);
    uint32_t dans = key ^ UINT32_C(0x536e6144);
    size_t start = SIZE_MAX;
    for (size_t i = rich - 4;; --i) {
        if (yx_dump_le(data, i, 4) == dans) { start = i; break; }
        if (i == 0) break;
    }
    if (start == SIZE_MAX) return;
    size_t length = rich - start;
    uint8_t *clear = (uint8_t *)malloc(length ? length : 1);
    if (!clear) { doc->oom = true; return; }
    for (size_t i = 0; i < length; ++i)
        clear[i] = data[start + i] ^ (uint8_t)(key >> ((i & 3u) * 8u));
    yx_dump_node *object = yx_dump_add(doc, module, "rich_signature",
                                        YX_DUMP_OBJECT);
    if (object) {
        yx_dump_number(doc, object, "offset", start, false, YX_DUMP_HEX);
        yx_dump_number(doc, object, "length", length, false, YX_DUMP_HEX);
        yx_dump_number(doc, object, "key", key, false, YX_DUMP_DECIMAL);
        yx_dump_text(doc, object, "raw_data", data + start, length, true);
        yx_dump_text(doc, object, "clear_data", clear, length, true);
        if (length >= 24) {
            yx_dump_node *tools = yx_dump_add(doc, object, "tools",
                                                YX_DUMP_ARRAY);
            for (size_t i = 16; tools && i + 8 <= length; i += 8) {
                yx_dump_node *tool = yx_dump_add(doc, tools, NULL,
                                                  YX_DUMP_OBJECT);
                if (!tool) break;
                yx_dump_number(doc, tool, "toolid",
                                yx_dump_le(clear, i + 2, 2), false,
                                YX_DUMP_DECIMAL);
                yx_dump_number(doc, tool, "version",
                                yx_dump_le(clear, i, 2), false,
                                YX_DUMP_DECIMAL);
                yx_dump_number(doc, tool, "times",
                                yx_dump_le(clear, i + 4, 4), false,
                                YX_DUMP_DECIMAL);
            }
        }
    }
    free(clear);
}

typedef struct {
    yx_dump_doc *doc;
    yx_dump_node *module;
    yx_dump_node *array;
    yx_dump_node *functions;
    yx_dump_node *count;
    size_t last_descriptor;
    bool has_descriptor;
    const char *key;
} yx_dump_pe_import_context;

static void yx_dump_pe_import_visit(void *opaque, size_t descriptor_index,
                                     const uint8_t *dll,
                                     size_t dll_length,
                                     const uint8_t *function,
                                     size_t function_length,
                                     bool by_ordinal, uint16_t ordinal,
                                     uint32_t rva)
{
    yx_dump_pe_import_context *context = opaque;
    yx_dump_doc *doc = context->doc;
    if (!context->has_descriptor ||
        context->last_descriptor != descriptor_index) {
        if (!context->array)
            context->array = yx_dump_add(doc, context->module,
                                          context->key, YX_DUMP_ARRAY);
        if (!context->array) return;
        yx_dump_node *library = yx_dump_add(doc, context->array, NULL,
                                             YX_DUMP_OBJECT);
        if (!library) return;
        yx_dump_text(doc, library, "library_name", dll, dll_length, false);
        context->count = yx_dump_number(doc, library,
            "number_of_functions", 0, true, YX_DUMP_DECIMAL);
        context->functions = yx_dump_add(doc, library, "functions",
                                          YX_DUMP_ARRAY);
        context->last_descriptor = descriptor_index;
        context->has_descriptor = true;
    }
    if (!context->functions || !context->count) return;
    yx_dump_node *item = yx_dump_add(doc, context->functions, NULL,
                                      YX_DUMP_OBJECT);
    if (!item) return;
    if (function)
        yx_dump_text(doc, item, "name", function, function_length, false);
    if (by_ordinal)
        yx_dump_number(doc, item, "ordinal", ordinal, false,
                        YX_DUMP_DECIMAL);
    yx_dump_number(doc, item, "rva", rva, false, YX_DUMP_HEX);
    ++context->count->number;
}

static void yx_dump_pe_imports(yx_dump_doc *doc, yx_dump_node *module,
                                const uint8_t *data, size_t size,
                                bool delayed)
{
    yx_dump_pe_import_context context = {0};
    context.doc = doc;
    context.module = module;
    context.key = delayed ? "delayed_import_details" : "import_details";
    yx_pe_visit_import_descriptors(data, size, delayed ? 2u : 1u,
                                    yx_dump_pe_import_visit, &context);
}

typedef struct {
    yx_dump_doc *doc;
    yx_dump_node *module;
    yx_dump_node *array;
} yx_dump_pe_export_context;

static void yx_dump_pe_export_visit(void *opaque,
                                     const yx_pe_export *entry)
{
    yx_dump_pe_export_context *context = opaque;
    if (!context->array)
        context->array = yx_dump_add(context->doc, context->module,
                                      "export_details", YX_DUMP_ARRAY);
    if (!context->array) return;
    yx_dump_node *item = yx_dump_add(context->doc, context->array, NULL,
                                      YX_DUMP_OBJECT);
    if (!item) return;
    if (entry->name)
        yx_dump_text(context->doc, item, "name", entry->name,
                      entry->name_length, false);
    yx_dump_number(context->doc, item, "ordinal", entry->ordinal, false,
                    YX_DUMP_DECIMAL);
    yx_dump_number(context->doc, item, "rva", entry->rva, false,
                    YX_DUMP_HEX);
    if (entry->has_offset)
        yx_dump_number(context->doc, item, "offset", entry->offset, false,
                        YX_DUMP_HEX);
    if (entry->forward_name)
        yx_dump_text(context->doc, item, "forward_name",
                      entry->forward_name, entry->forward_name_length, false);
}

static void yx_dump_pe_exports(yx_dump_doc *doc, yx_dump_node *module,
                                const uint8_t *data, size_t size)
{
    yx_dump_pe_export_context context = {doc, module, NULL};
    (void)yx_pe_visit_exports(data, size, yx_dump_pe_export_visit,
                               &context);
}

static const char *yx_dump_pe_resource_type(uint32_t value)
{
    static const struct { uint32_t value; const char *name; } names[] = {
        {1, "RESOURCE_TYPE_CURSOR"}, {2, "RESOURCE_TYPE_BITMAP"},
        {3, "RESOURCE_TYPE_ICON"}, {4, "RESOURCE_TYPE_MENU"},
        {5, "RESOURCE_TYPE_DIALOG"}, {6, "RESOURCE_TYPE_STRING"},
        {7, "RESOURCE_TYPE_FONTDIR"}, {8, "RESOURCE_TYPE_FONT"},
        {9, "RESOURCE_TYPE_ACCELERATOR"}, {10, "RESOURCE_TYPE_RCDATA"},
        {11, "RESOURCE_TYPE_MESSAGETABLE"},
        {12, "RESOURCE_TYPE_GROUP_CURSOR"},
        {14, "RESOURCE_TYPE_GROUP_ICON"},
        {16, "RESOURCE_TYPE_VERSION"},
        {17, "RESOURCE_TYPE_DLGINCLUDE"},
        {19, "RESOURCE_TYPE_PLUGPLAY"}, {20, "RESOURCE_TYPE_VXD"},
        {21, "RESOURCE_TYPE_ANICURSOR"},
        {22, "RESOURCE_TYPE_ANIICON"}, {23, "RESOURCE_TYPE_HTML"},
        {24, "RESOURCE_TYPE_MANIFEST"}
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (names[i].value == value) return names[i].name;
    return NULL;
}

typedef struct {
    yx_dump_doc *doc;
    yx_dump_node *array;
} yx_dump_pe_resource_context;

static void yx_dump_pe_resource_visit(void *opaque,
                                       const yx_pe_resource *resource)
{
    yx_dump_pe_resource_context *context = opaque;
    yx_dump_doc *doc = context->doc;
    yx_dump_node *item = yx_dump_add(doc, context->array, NULL,
                                      YX_DUMP_OBJECT);
    if (!item) return;
    yx_dump_number(doc, item, "length", resource->length, false,
                    YX_DUMP_HEX);
    yx_dump_number(doc, item, "rva", resource->rva, false, YX_DUMP_HEX);
    if (resource->has_offset)
        yx_dump_number(doc, item, "offset", resource->offset, false,
                        YX_DUMP_HEX);
    if (resource->type.kind == YX_PE_RESOURCE_NUMERIC)
        yx_dump_enum(doc, item, "type", resource->type.value,
                      yx_dump_pe_resource_type(resource->type.value));
    if (resource->id.kind == YX_PE_RESOURCE_NUMERIC)
        yx_dump_number(doc, item, "id", resource->id.value, false,
                        YX_DUMP_DECIMAL);
    if (resource->language.kind == YX_PE_RESOURCE_NUMERIC)
        yx_dump_number(doc, item, "language", resource->language.value,
                        false, YX_DUMP_DECIMAL);
    if (resource->type.kind == YX_PE_RESOURCE_NAMED)
        yx_dump_text(doc, item, "type_string", resource->type.name,
                      resource->type.name_length, true);
    if (resource->id.kind == YX_PE_RESOURCE_NAMED)
        yx_dump_text(doc, item, "name_string", resource->id.name,
                      resource->id.name_length, true);
    if (resource->language.kind == YX_PE_RESOURCE_NAMED)
        yx_dump_text(doc, item, "language_string", resource->language.name,
                      resource->language.name_length, true);
}

static void yx_dump_pe_resources(yx_dump_doc *doc, yx_dump_node *module,
                                  const uint8_t *data, size_t size)
{
    yx_pe_resource_directory directory;
    if (!yx_pe_visit_resources(data, size, &directory, NULL, NULL) ||
        !directory.present) return;
    yx_dump_node *timestamp = yx_dump_number(doc, module,
        "resource_timestamp", directory.timestamp, true, YX_DUMP_TIMESTAMP);
    if (timestamp) yx_dump_pe_timestamp(doc, timestamp);
    yx_dump_node *version = yx_dump_add(doc, module, "resource_version",
                                        YX_DUMP_OBJECT);
    if (version) {
        yx_dump_number(doc, version, "major", directory.major_version,
                        false, YX_DUMP_DECIMAL);
        yx_dump_number(doc, version, "minor", directory.minor_version,
                        false, YX_DUMP_DECIMAL);
    }
    yx_dump_pe_resource_context context = {doc,
        yx_dump_add(doc, module, "resources", YX_DUMP_ARRAY)};
    if (context.array)
        (void)yx_pe_visit_resources(data, size, &directory,
                                     yx_dump_pe_resource_visit, &context);
}

typedef struct {
    yx_dump_doc *doc;
    yx_dump_node *module;
    yx_dump_node *map;
    yx_dump_node *list;
} yx_dump_pe_version_context;

static void yx_dump_pe_version_visit(void *opaque,
                                      const char *key, size_t key_length,
                                      const char *value, size_t value_length)
{
    yx_dump_pe_version_context *context = opaque;
    yx_dump_doc *doc = context->doc;
    yx_dump_node *member;
    if (!context->map) {
        context->map = yx_dump_add(doc, context->module, "version_info",
                                    YX_DUMP_OBJECT);
        if (context->map) context->map->quoted_keys = true;
        context->list = yx_dump_add(doc, context->module,
                                     "version_info_list", YX_DUMP_ARRAY);
    }
    if (!context->map || !context->list) return;
    for (member = context->map->first; member; member = member->next)
        if (strlen(member->key) == key_length &&
            memcmp(member->key, key, key_length) == 0) break;
    if (member) {
        char *replacement = (char *)malloc(value_length + 1);
        if (!replacement) doc->oom = true;
        else {
            if (value_length) memcpy(replacement, value, value_length);
            replacement[value_length] = 0;
            free(member->owned);
            member->owned = replacement;
            member->length = value_length;
        }
    } else {
        member = yx_dump_text(doc, context->map, NULL, value,
                               value_length, false);
        if (member) {
            member->owned_key = (char *)malloc(key_length + 1);
            if (!member->owned_key) {
                /* the member stays in the map: its key must not be NULL */
                doc->oom = true;
                member->key = "";
            } else {
                if (key_length) memcpy(member->owned_key, key, key_length);
                member->owned_key[key_length] = 0;
                member->key = member->owned_key;
            }
        }
    }
    yx_dump_node *pair = yx_dump_add(doc, context->list, NULL,
                                      YX_DUMP_OBJECT);
    if (pair) {
        yx_dump_text(doc, pair, "key", key, key_length, false);
        yx_dump_text(doc, pair, "value", value, value_length, false);
    }
}

static void yx_dump_pe_version_info(yx_dump_doc *doc, yx_dump_node *module,
                                     const uint8_t *data, size_t size)
{
    yx_dump_pe_version_context context = {doc, module, NULL, NULL};
    (void)yx_pe_visit_version_info(data, size,
                                    yx_dump_pe_version_visit, &context);
    if (context.map) {
        yx_dump_node *sorted = NULL;
        yx_dump_node *current = context.map->first;
        while (current) {
            yx_dump_node *next = current->next;
            yx_dump_node **position = &sorted;
            while (*position && strcmp((*position)->key, current->key) < 0)
                position = &(*position)->next;
            current->next = *position;
            *position = current;
            current = next;
        }
        context.map->first = sorted;
        context.map->last = sorted;
        while (context.map->last && context.map->last->next)
            context.map->last = context.map->last->next;
    }
}

static void yx_dump_pe_certificate(yx_dump_doc *doc, yx_dump_node *array,
                                    const yx_pe_certificate *cert)
{
    yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
    if (!item) return;
    if (cert->issuer)
        yx_dump_text(doc, item, "issuer", cert->issuer,
                      cert->issuer_length, false);
    if (cert->subject)
        yx_dump_text(doc, item, "subject", cert->subject,
                      cert->subject_length, false);
    if (cert->thumbprint)
        yx_dump_text(doc, item, "thumbprint", cert->thumbprint,
                      strlen(cert->thumbprint), false);
    yx_dump_number(doc, item, "version", (uint64_t)cert->version, true,
                    YX_DUMP_DECIMAL);
    if (cert->algorithm)
        yx_dump_text(doc, item, "algorithm", cert->algorithm,
                      strlen(cert->algorithm), false);
    if (cert->algorithm_oid)
        yx_dump_text(doc, item, "algorithm_oid", cert->algorithm_oid,
                      strlen(cert->algorithm_oid), false);
    if (cert->serial)
        yx_dump_text(doc, item, "serial", cert->serial,
                      strlen(cert->serial), false);
    yx_dump_node *before = yx_dump_number(doc, item, "not_before",
        (uint64_t)cert->not_before, true, YX_DUMP_TIMESTAMP);
    if (before) yx_dump_pe_timestamp(doc, before);
    yx_dump_node *after = yx_dump_number(doc, item, "not_after",
        (uint64_t)cert->not_after, true, YX_DUMP_TIMESTAMP);
    if (after) yx_dump_pe_timestamp(doc, after);
}

static void yx_dump_pe_signature(yx_dump_doc *doc, yx_dump_node *array,
                                  const yx_pe_signature *signature)
{
    yx_dump_node *item = yx_dump_add(doc, array, NULL, YX_DUMP_OBJECT);
    if (!item) return;
    if (signature->signer_chain_count && signature->signer_chain_indices[0] <
        signature->certificate_count) {
        const yx_pe_certificate *cert = &signature->certificates[
            signature->signer_chain_indices[0]];
        if (cert->subject)
            yx_dump_text(doc, item, "subject", cert->subject,
                          cert->subject_length, false);
        if (cert->issuer)
            yx_dump_text(doc, item, "issuer", cert->issuer,
                          cert->issuer_length, false);
        if (cert->thumbprint)
            yx_dump_text(doc, item, "thumbprint", cert->thumbprint,
                          strlen(cert->thumbprint), false);
        yx_dump_number(doc, item, "version", (uint64_t)cert->version,
                        true, YX_DUMP_DECIMAL);
        if (cert->algorithm)
            yx_dump_text(doc, item, "algorithm", cert->algorithm,
                          strlen(cert->algorithm), false);
        if (cert->algorithm_oid)
            yx_dump_text(doc, item, "algorithm_oid", cert->algorithm_oid,
                          strlen(cert->algorithm_oid), false);
        if (cert->serial)
            yx_dump_text(doc, item, "serial", cert->serial,
                          strlen(cert->serial), false);
        yx_dump_node *before = yx_dump_number(doc, item, "not_before",
            (uint64_t)cert->not_before, true, YX_DUMP_TIMESTAMP);
        if (before) yx_dump_pe_timestamp(doc, before);
        yx_dump_node *after = yx_dump_number(doc, item, "not_after",
            (uint64_t)cert->not_after, true, YX_DUMP_TIMESTAMP);
        if (after) yx_dump_pe_timestamp(doc, after);
    }
    yx_dump_boolean(doc, item, "verified", signature->verified);
    if (signature->digest_alg)
        yx_dump_text(doc, item, "digest_alg", signature->digest_alg,
                      strlen(signature->digest_alg), false);
    if (signature->digest)
        yx_dump_text(doc, item, "digest", signature->digest,
                      strlen(signature->digest), false);
    if (signature->file_digest)
        yx_dump_text(doc, item, "file_digest", signature->file_digest,
                      strlen(signature->file_digest), false);
    yx_dump_number(doc, item, "number_of_certificates",
                    signature->certificate_count, true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, item, "number_of_countersignatures",
                    signature->countersignature_count, true,
                    YX_DUMP_DECIMAL);
    yx_dump_node *signer = yx_dump_add(doc, item, "signer_info",
                                       YX_DUMP_OBJECT);
    if (signer) {
        if (signature->program_name)
            yx_dump_text(doc, signer, "program_name", signature->program_name,
                          strlen(signature->program_name), false);
        if (signature->more_info)
            yx_dump_text(doc, signer, "more_info", signature->more_info,
                          strlen(signature->more_info), false);
        if (signature->signer_digest)
            yx_dump_text(doc, signer, "digest", signature->signer_digest,
                          strlen(signature->signer_digest), false);
        if (signature->signer_digest_alg)
            yx_dump_text(doc, signer, "digest_alg",
                          signature->signer_digest_alg,
                          strlen(signature->signer_digest_alg), false);
        if (signature->signer_chain_count) {
            yx_dump_node *chain = yx_dump_add(doc, signer, "chain",
                                               YX_DUMP_ARRAY);
            for (size_t i = 0; chain && i < signature->signer_chain_count;
                 ++i) {
                size_t index = signature->signer_chain_indices[i];
                if (index < signature->certificate_count)
                    yx_dump_pe_certificate(doc, chain,
                        &signature->certificates[index]);
            }
        }
    }
    if (signature->certificate_count) {
        yx_dump_node *certificates = yx_dump_add(doc, item, "certificates",
                                                 YX_DUMP_ARRAY);
        for (size_t i = 0; certificates && i < signature->certificate_count;
             ++i)
            yx_dump_pe_certificate(doc, certificates,
                                    &signature->certificates[i]);
    }
    if (signature->countersignature_count) {
        yx_dump_node *counters = yx_dump_add(doc, item,
            "countersignatures", YX_DUMP_ARRAY);
        for (size_t i = 0; counters && i < signature->countersignature_count;
             ++i) {
            const yx_pe_countersignature *counter =
                &signature->countersignatures[i];
            yx_dump_node *c = yx_dump_add(doc, counters, NULL,
                                           YX_DUMP_OBJECT);
            if (!c) break;
            yx_dump_boolean(doc, c, "verified", counter->verified);
            if (counter->has_sign_time) {
                yx_dump_node *stamp = yx_dump_number(doc, c, "sign_time",
                    (uint64_t)counter->sign_time, true,
                    YX_DUMP_TIMESTAMP);
                if (stamp) yx_dump_pe_timestamp(doc, stamp);
            }
            if (counter->digest)
                yx_dump_text(doc, c, "digest", counter->digest,
                              strlen(counter->digest), false);
            if (counter->digest_alg)
                yx_dump_text(doc, c, "digest_alg", counter->digest_alg,
                              strlen(counter->digest_alg), false);
            if (counter->chain_count) {
                yx_dump_node *chain = yx_dump_add(doc, c, "chain",
                                                   YX_DUMP_ARRAY);
                for (size_t j = 0; chain && j < counter->chain_count; ++j) {
                    size_t index = counter->chain_indices[j];
                    if (index < signature->certificate_count)
                        yx_dump_pe_certificate(doc, chain,
                            &signature->certificates[index]);
                }
            }
        }
    }
}

static void yx_dump_pe_signatures(yx_dump_doc *doc, yx_dump_node *module,
                                   const yx_pe_signature_result *result)
{
    if (result->count) {
        yx_dump_node *array = yx_dump_add(doc, module, "signatures",
                                           YX_DUMP_ARRAY);
        for (size_t i = 0; array && i < result->count; ++i)
            yx_dump_pe_signature(doc, array, &result->items[i]);
    }
}

static void yx_dump_pe(yx_dump_doc *doc, yx_dump_node *parent,
                         const uint8_t *data, size_t size)
{
    static const char *const fields[] = {
        "characteristics", "dll_characteristics", "timestamp",
        "image_base", "checksum",
        "base_of_code", "base_of_data", "entry_point", "entry_point_raw",
        "section_alignment", "file_alignment", "loader_flags",
        "size_of_optional_header", "size_of_code",
        "size_of_initialized_data", "size_of_uninitialized_data",
        "size_of_image", "size_of_headers", "size_of_stack_reserve",
        "size_of_stack_commit", "size_of_heap_reserve",
        "size_of_heap_commit", "pointer_to_symbol_table",
        "win32_version_value", "number_of_symbols",
        "number_of_rva_and_sizes", "number_of_sections",
        "number_of_imported_functions", "number_of_delayed_imported_functions"
    };
    bool is_pe = yx_pe_is_pe(data, size);
    yx_pe_signature_result signatures = {0};
    yx_dump_node *module = yx_dump_add(doc, parent, "pe", YX_DUMP_OBJECT);
    if (!module) return;
    yx_dump_boolean(doc, module, "is_pe", is_pe);
    if (!is_pe) return;
    yx_dump_pe_number(doc, module, data, size, "machine");
    yx_dump_pe_number(doc, module, data, size, "subsystem");
    if (size >= 64) {
        uint64_t pe_offset = yx_dump_le(data, 60, 4);
        if (pe_offset <= size && pe_offset + 24 <= size) {
            size_t opt = (size_t)pe_offset + 24;
            uint16_t magic = size - opt >= 2 ?
                (uint16_t)yx_dump_le(data, opt, 2) : 0;
            bool optional_valid = size - opt >=
                (magic == 0x20b ? 112u : 96u);
            /* The parser publishes all four version objects as zero when
             * the fixed optional-header prefix is incomplete. */
            yx_dump_pe_version(doc, module, "os_version", data, size,
                                opt + 40, 2, optional_valid);
            yx_dump_pe_version(doc, module, "subsystem_version", data,
                                size, opt + 48, 2, optional_valid);
            yx_dump_pe_version(doc, module, "image_version", data, size,
                                opt + 44, 2, optional_valid);
            yx_dump_pe_version(doc, module, "linker_version", data, size,
                                opt + 2, 1, optional_valid);
        }
    }
    yx_dump_pe_number(doc, module, data, size, "opthdr_magic");
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        if (strcmp(fields[i], "section_alignment") == 0) {
            const uint8_t *bytes;
            size_t length;
            if (yx_pe_string_field(data, size, "dll_name", &bytes, &length))
                yx_dump_text(doc, module, "dll_name", bytes, length, false);
            yx_dump_pe_number(doc, module, data, size, "export_timestamp");
        }
        yx_dump_pe_number(doc, module, data, size, fields[i]);
    }
    yx_dump_pe_number(doc, module, data, size, "number_of_resources");
    yx_dump_pe_number(doc, module, data, size, "number_of_version_infos");
    yx_dump_pe_number(doc, module, data, size, "number_of_imports");
    yx_dump_pe_number(doc, module, data, size, "number_of_delayed_imports");
    yx_dump_pe_number(doc, module, data, size, "number_of_exports");
    (void)yx_pe_parse_signatures(data, size, &signatures);
    yx_dump_number(doc, module, "number_of_signatures", signatures.count, true,
                    YX_DUMP_DECIMAL);
    yx_dump_pe_version_info(doc, module, data, size);
    yx_dump_pe_rich_signature(doc, module, data, size);
    {
        const uint8_t *bytes;
        size_t length;
        if (yx_pe_string_field(data, size, "pdb_path", &bytes, &length))
            yx_dump_text(doc, module, "pdb_path", bytes, length, true);
    }
    yx_dump_pe_sections(doc, module, data, size);
    yx_dump_pe_directories(doc, module, data, size);
    yx_dump_pe_resources(doc, module, data, size);
    yx_dump_pe_imports(doc, module, data, size, false);
    yx_dump_pe_imports(doc, module, data, size, true);
    yx_dump_pe_exports(doc, module, data, size);
    bool is_signed = false;
    for (size_t i = 0; i < signatures.count; ++i)
        if (signatures.items[i].verified) { is_signed = true; break; }
    yx_dump_boolean(doc, module, "is_signed", is_signed);
    yx_dump_pe_signatures(doc, module, &signatures);
    {
        uint64_t offset, length;
        if (yx_pe_overlay(data, size, &offset, &length)) {
            yx_dump_node *overlay = yx_dump_add(doc, module, "overlay",
                                                 YX_DUMP_OBJECT);
            if (overlay) {
                yx_dump_number(doc, overlay, "offset", offset, false,
                                YX_DUMP_HEX);
                yx_dump_number(doc, overlay, "size", length, false,
                                YX_DUMP_HEX);
            }
        }
    }
    yx_pe_signature_result_destroy(&signatures);
}

static void yx_dump_dotnet_version(yx_dump_doc *doc, yx_dump_node *parent,
                                     const yx_dotnet_version *version)
{
    yx_dump_node *item = yx_dump_add(doc, parent, "version", YX_DUMP_OBJECT);
    if (!item) return;
    yx_dump_number(doc, item, "major", version->major, false,
                    YX_DUMP_DECIMAL);
    yx_dump_number(doc, item, "minor", version->minor, false,
                    YX_DUMP_DECIMAL);
    yx_dump_number(doc, item, "build_number", version->build_number, false,
                    YX_DUMP_DECIMAL);
    yx_dump_number(doc, item, "revision_number", version->revision_number,
                    false, YX_DUMP_DECIMAL);
}

static void yx_dump_dotnet_method(yx_dump_doc *doc, yx_dump_node *methods,
                                    const yx_dotnet_result *dotnet,
                                    size_t class_index, size_t method_index)
{
    yx_dotnet_method method;
    yx_dump_node *item;
    char *return_type = NULL;
    if (!yx_dotnet_class_method_at(dotnet, class_index, method_index,
                                    NULL, 0, &method)) return;
    if (method.has_return_type) {
        if (method.return_type_length == SIZE_MAX) {
            doc->oom = true;
            return;
        }
        return_type = malloc(method.return_type_length + 1);
        if (!return_type) { doc->oom = true; return; }
        if (!yx_dotnet_class_method_at(dotnet, class_index, method_index,
                                        return_type,
                                        method.return_type_length + 1,
                                        &method)) {
            free(return_type);
            return;
        }
    }
    item = yx_dump_add(doc, methods, NULL, YX_DUMP_OBJECT);
    if (!item) { free(return_type); return; }
    yx_dump_text(doc, item, "name", method.name, method.name_length, false);
    yx_dump_text(doc, item, "visibility", method.visibility,
                   strlen(method.visibility), false);
    yx_dump_boolean(doc, item, "abstract", method.is_abstract);
    yx_dump_boolean(doc, item, "static", method.is_static);
    yx_dump_boolean(doc, item, "virtual", method.is_virtual);
    yx_dump_boolean(doc, item, "final", method.is_final);
    if (method.has_return_type)
        yx_dump_text(doc, item, "return_type", return_type,
                       method.return_type_length, false);
    free(return_type);
    yx_dump_number(doc, item, "number_of_generic_parameters",
                    method.number_of_generic_parameters, true,
                    YX_DUMP_DECIMAL);
    yx_dump_number(doc, item, "number_of_parameters",
                    method.number_of_parameters, true, YX_DUMP_DECIMAL);
    if (method.number_of_generic_parameters) {
        yx_dump_node *generics = yx_dump_add(doc, item,
                                               "generic_parameters",
                                               YX_DUMP_ARRAY);
        for (size_t j = 0; generics &&
                           j < method.number_of_generic_parameters; ++j) {
            const uint8_t *name;
            size_t length;
            if (yx_dotnet_method_generic_parameter_at(dotnet, &method, j,
                                                        &name, &length))
                yx_dump_text(doc, generics, NULL, name, length, false);
        }
    }
    if (method.number_of_parameters) {
        yx_dump_node *parameters = yx_dump_add(doc, item, "parameters",
                                                 YX_DUMP_ARRAY);
        for (size_t j = 0; parameters && j < method.number_of_parameters;
             ++j) {
            yx_dotnet_method_parameter parameter;
            yx_dump_node *param_item;
            char fallback[32];
            char *type;
            int fallback_length;
            if (!yx_dotnet_method_parameter_at(dotnet, &method, j, NULL, 0,
                                                 &parameter)) continue;
            if (parameter.type_length == SIZE_MAX) {
                doc->oom = true;
                return;
            }
            type = malloc(parameter.type_length + 1);
            if (!type) { doc->oom = true; return; }
            if (!yx_dotnet_method_parameter_at(dotnet, &method, j, type,
                                                 parameter.type_length + 1,
                                                 &parameter)) {
                free(type);
                continue;
            }
            param_item = yx_dump_add(doc, parameters, NULL, YX_DUMP_OBJECT);
            if (!param_item) { free(type); return; }
            if (parameter.name) {
                yx_dump_text(doc, param_item, "name", parameter.name,
                               parameter.name_length, false);
            } else {
                fallback_length = snprintf(fallback, sizeof(fallback),
                                            "P_%zu",
                                            parameter.generated_name_index);
                if (fallback_length < 0 ||
                    (size_t)fallback_length >= sizeof(fallback)) {
                    free(type);
                    doc->oom = true;
                    return;
                }
                yx_dump_text(doc, param_item, "name", fallback,
                               (size_t)fallback_length, false);
            }
            yx_dump_text(doc, param_item, "type", type,
                           parameter.type_length, false);
            free(type);
        }
    }
}

static void yx_dump_dotnet(yx_dump_doc *doc, yx_dump_node *root,
                            const uint8_t *data, size_t size,
                            const yx_dotnet_result *dotnet)
{
    yx_dump_node *module = yx_dump_add(doc, root, "dotnet", YX_DUMP_OBJECT);
    if (!module) return;
    yx_dump_boolean(doc, module, "is_dotnet", dotnet->is_dotnet);
    if (!dotnet->is_dotnet) return;
    if (dotnet->module_name)
        yx_dump_text(doc, module, "module_name", dotnet->module_name,
                       dotnet->module_name_length, false);
    if (dotnet->version)
        yx_dump_text(doc, module, "version", dotnet->version,
                       dotnet->version_length, false);
    yx_dump_number(doc, module, "number_of_streams", dotnet->stream_count,
                    true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_guids", dotnet->guid_count,
                    true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_resources",
                    dotnet->resource_count, true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_classes", dotnet->class_count,
                    true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_assembly_refs",
                    dotnet->assembly_ref_count, true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_modulerefs",
                    dotnet->module_ref_count, true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_user_strings",
                    dotnet->user_string_count, true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_constants",
                    dotnet->constant_count, true, YX_DUMP_DECIMAL);
    yx_dump_number(doc, module, "number_of_field_offsets",
                    dotnet->field_offset_count, true, YX_DUMP_DECIMAL);
    if (dotnet->typelib)
        yx_dump_text(doc, module, "typelib", dotnet->typelib,
                       dotnet->typelib_length, false);
    if (dotnet->stream_count) {
        yx_dump_node *streams = yx_dump_add(doc, module, "streams",
                                             YX_DUMP_ARRAY);
        for (size_t i = 0; streams && i < dotnet->stream_count; ++i) {
            const yx_dotnet_stream *stream = &dotnet->streams[i];
            yx_dump_node *item = yx_dump_add(doc, streams, NULL,
                                               YX_DUMP_OBJECT);
            if (!item) break;
            if (stream->name)
                yx_dump_text(doc, item, "name", stream->name,
                               stream->name_length, false);
            yx_dump_number(doc, item, "offset", stream->offset, false,
                            YX_DUMP_HEX);
            yx_dump_number(doc, item, "size", stream->size, false,
                            YX_DUMP_HEX);
        }
    }
    if (dotnet->guid_count) {
        yx_dump_node *guids = yx_dump_add(doc, module, "guids",
                                            YX_DUMP_ARRAY);
        for (size_t i = 0; guids && i < dotnet->guid_count; ++i) {
            char guid[37];
            if (yx_dotnet_guid_at(data, size, dotnet, i, guid))
                yx_dump_text(doc, guids, NULL, guid, 36, false);
        }
    }
    if (dotnet->constant_count) {
        yx_dump_node *constants = yx_dump_add(doc, module, "constants",
                                                YX_DUMP_ARRAY);
        for (size_t i = 0; constants && i < dotnet->constant_count; ++i) {
            const uint8_t *bytes;
            size_t length;
            if (yx_dotnet_constant_at(dotnet, i, &bytes, &length))
                yx_dump_text(doc, constants, NULL, bytes, length, true);
        }
    }
    if (dotnet->assembly.present) {
        yx_dump_node *assembly = yx_dump_add(doc, module, "assembly",
                                                YX_DUMP_OBJECT);
        if (assembly) {
            if (dotnet->assembly.name)
                yx_dump_text(doc, assembly, "name", dotnet->assembly.name,
                               dotnet->assembly.name_length, false);
            if (dotnet->assembly.culture)
                yx_dump_text(doc, assembly, "culture",
                               dotnet->assembly.culture,
                               dotnet->assembly.culture_length, false);
            yx_dump_dotnet_version(doc, assembly,
                                    &dotnet->assembly.version);
        }
    }
    if (dotnet->assembly_ref_count) {
        yx_dump_node *references = yx_dump_add(doc, module,
                                                  "assembly_refs",
                                                  YX_DUMP_ARRAY);
        for (size_t i = 0; references && i < dotnet->assembly_ref_count;
             ++i) {
            yx_dotnet_assembly_ref reference;
            yx_dump_node *item;
            if (!yx_dotnet_assembly_ref_at(dotnet, i, &reference)) continue;
            item = yx_dump_add(doc, references, NULL, YX_DUMP_OBJECT);
            if (!item) break;
            if (reference.name)
                yx_dump_text(doc, item, "name", reference.name,
                               reference.name_length, false);
            if (reference.public_key_or_token)
                yx_dump_text(doc, item, "public_key_or_token",
                               reference.public_key_or_token,
                               reference.public_key_or_token_length, true);
            yx_dump_dotnet_version(doc, item, &reference.version);
        }
    }
    if (dotnet->resource_count) {
        yx_dump_node *resources = yx_dump_add(doc, module, "resources",
                                                 YX_DUMP_ARRAY);
        for (size_t i = 0; resources && i < dotnet->resource_count; ++i) {
            yx_dotnet_resource resource;
            yx_dump_node *item;
            if (!yx_dotnet_resource_at(dotnet, i, &resource)) continue;
            item = yx_dump_add(doc, resources, NULL, YX_DUMP_OBJECT);
            if (!item) break;
            if (resource.has_offset)
                yx_dump_number(doc, item, "offset", resource.offset, false,
                                YX_DUMP_HEX);
            if (resource.has_length)
                yx_dump_number(doc, item, "length", resource.length, false,
                                YX_DUMP_HEX);
            if (resource.name)
                yx_dump_text(doc, item, "name", resource.name,
                               resource.name_length, false);
        }
    }
    if (dotnet->class_count) {
        yx_dump_node *classes = yx_dump_add(doc, module, "classes",
                                               YX_DUMP_ARRAY);
        for (size_t i = 0; classes && i < dotnet->class_count; ++i) {
            yx_dotnet_class class_info;
            yx_dump_node *item;
            char *fullname = NULL;
            if (!yx_dotnet_class_at(dotnet, i, NULL, 0, &class_info))
                continue;
            if (class_info.required_fullname_capacity) {
                fullname = malloc(class_info.required_fullname_capacity);
                if (!fullname) { doc->oom = true; break; }
                if (!yx_dotnet_class_at(dotnet, i, fullname,
                                         class_info.required_fullname_capacity,
                                         &class_info)) {
                    free(fullname);
                    continue;
                }
            }
            item = yx_dump_add(doc, classes, NULL, YX_DUMP_OBJECT);
            if (!item) { free(fullname); break; }
            if (class_info.fullname)
                yx_dump_text(doc, item, "fullname", class_info.fullname,
                               class_info.fullname_length, false);
            if (class_info.name)
                yx_dump_text(doc, item, "name", class_info.name,
                               class_info.name_length, false);
            if (class_info.namespace_name)
                yx_dump_text(doc, item, "namespace",
                               class_info.namespace_name,
                               class_info.namespace_length, false);
            if (class_info.visibility)
                yx_dump_text(doc, item, "visibility", class_info.visibility,
                               strlen(class_info.visibility), false);
            if (class_info.type)
                yx_dump_text(doc, item, "type", class_info.type,
                               strlen(class_info.type), false);
            yx_dump_boolean(doc, item, "abstract", class_info.is_abstract);
            yx_dump_boolean(doc, item, "sealed", class_info.is_sealed);
            yx_dump_number(doc, item, "number_of_base_types",
                            class_info.number_of_base_types, true,
                            YX_DUMP_DECIMAL);
            yx_dump_number(doc, item, "number_of_generic_parameters",
                            class_info.number_of_generic_parameters, true,
                            YX_DUMP_DECIMAL);
            size_t method_count = yx_dotnet_class_method_count(dotnet, i);
            yx_dump_number(doc, item, "number_of_methods", method_count,
                            true, YX_DUMP_DECIMAL);
            if (class_info.number_of_base_types) {
                yx_dump_node *bases = yx_dump_add(doc, item, "base_types",
                                                    YX_DUMP_ARRAY);
                for (size_t j = 0; bases &&
                                   j < class_info.number_of_base_types;
                     ++j) {
                    size_t required = 0, length = 0;
                    char *base;
                    if (!yx_dotnet_class_base_type_at(dotnet, i, j, NULL, 0,
                                                       &required, &length) ||
                        !required) continue;
                    base = malloc(required);
                    if (!base) { doc->oom = true; break; }
                    if (yx_dotnet_class_base_type_at(dotnet, i, j, base,
                                                       required, NULL, NULL))
                        yx_dump_text(doc, bases, NULL, base, length, false);
                    free(base);
                }
            }
            if (class_info.number_of_generic_parameters) {
                yx_dump_node *generics = yx_dump_add(doc, item,
                                                       "generic_parameters",
                                                       YX_DUMP_ARRAY);
                for (size_t j = 0; generics &&
                                   j < class_info.number_of_generic_parameters;
                     ++j) {
                    const uint8_t *name;
                    size_t length;
                    if (yx_dotnet_class_generic_parameter_at(dotnet, i, j,
                                                               &name, &length))
                        yx_dump_text(doc, generics, NULL, name, length,
                                       false);
                }
            }
            if (method_count) {
                yx_dump_node *methods = yx_dump_add(doc, item, "methods",
                                                      YX_DUMP_ARRAY);
                for (size_t j = 0; methods && j < method_count; ++j)
                    yx_dump_dotnet_method(doc, methods, dotnet, i, j);
            }
            free(fullname);
        }
    }
    if (dotnet->field_offset_count) {
        yx_dump_node *offsets = yx_dump_add(doc, module,
                                               "field_offsets",
                                               YX_DUMP_ARRAY);
        for (size_t i = 0; offsets && i < dotnet->field_offset_count;
             ++i) {
            uint32_t offset;
            if (yx_dotnet_field_offset_at(data, size, dotnet, i, &offset))
                yx_dump_number(doc, offsets, NULL, offset, false,
                                YX_DUMP_DECIMAL);
        }
    }
    if (dotnet->user_string_count) {
        yx_dump_node *strings = yx_dump_add(doc, module, "user_strings",
                                              YX_DUMP_ARRAY);
        for (size_t i = 0; strings && i < dotnet->user_string_count; ++i) {
            const uint8_t *bytes;
            size_t length;
            if (yx_dotnet_user_string_at(data, size, dotnet, i,
                                          &bytes, &length))
                yx_dump_text(doc, strings, NULL, bytes, length, true);
        }
    }
    if (dotnet->module_ref_count) {
        yx_dump_node *references = yx_dump_add(doc, module, "modulerefs",
                                                  YX_DUMP_ARRAY);
        for (size_t i = 0; references && i < dotnet->module_ref_count;
             ++i) {
            const uint8_t *name;
            size_t length;
            if (yx_dotnet_module_ref_at(dotnet, i, &name, &length))
                yx_dump_text(doc, references, NULL, name, length, false);
        }
    }
}

#ifdef XXYARA_ENABLE_VBA
static void yx_dump_vba(yx_dump_doc *doc, yx_dump_node *parent,
                         const yx_vba_result *parsed)
{
    yx_dump_node *module = yx_dump_add(doc, parent, "vba", YX_DUMP_OBJECT);
    if (!module) return;
    yx_dump_boolean(doc, module, "has_macros", parsed->has_macros);
    if (parsed->module_count) {
        yx_dump_node *modules = yx_dump_add(doc, module, "modules",
                                              YX_DUMP_ARRAY);
        for (size_t i = 0; modules && i < parsed->module_count; ++i) {
            const yx_vba_module *source = &parsed->modules[i];
            const char *type_name = NULL;
            yx_dump_node *item = yx_dump_add(doc, modules, NULL,
                                               YX_DUMP_OBJECT);
            yx_dump_node *code;
            if (!item) break;
            if (source->name)
                yx_dump_text(doc, item, "name", source->name,
                               source->name_length, false);
            switch (source->type) {
            case YX_VBA_MODULE_STANDARD:
                type_name = "MODULE_TYPE_STANDARD"; break;
            case YX_VBA_MODULE_CLASS:
                type_name = "MODULE_TYPE_CLASS"; break;
            case YX_VBA_MODULE_UNKNOWN:
                type_name = "MODULE_TYPE_UNKNOWN"; break;
            default: break;
            }
            yx_dump_enum(doc, item, "type", source->type, type_name);
            code = yx_dump_text(doc, item, "code", source->code,
                                  source->code_length, false);
            if (code) code->block_string = true;
        }
    }
    if (parsed->has_project_info) {
        yx_dump_node *project = yx_dump_add(doc, module, "project_info",
                                              YX_DUMP_OBJECT);
        if (!project) return;
        if (parsed->project_name)
            yx_dump_text(doc, project, "name", parsed->project_name,
                           parsed->project_name_length, false);
        if (parsed->project_version)
            yx_dump_text(doc, project, "version", parsed->project_version,
                           parsed->project_version_length, false);
        if (parsed->reference_count) {
            yx_dump_node *references = yx_dump_add(doc, project,
                                                      "references",
                                                      YX_DUMP_ARRAY);
            for (size_t i = 0; references &&
                               i < parsed->reference_count; ++i)
                yx_dump_text(doc, references, NULL, parsed->references[i],
                               strlen(parsed->references[i]), false);
        }
        yx_dump_number(doc, project, "module_count",
                         (uint64_t)(int64_t)parsed->declared_module_count,
                         true, YX_DUMP_DECIMAL);
    }
}
#endif

static void yx_dump_zip(yx_dump_doc *doc, yx_dump_node *parent,
                        const yx_zip_result *parsed)
{
    static const struct {
        uint32_t value;
        const char *name;
    } compression[] = {
        {0, "STORED"}, {1, "SHRUNK"}, {2, "REDUCED_1"},
        {3, "REDUCED_2"}, {4, "REDUCED_3"}, {5, "REDUCED_4"},
        {6, "IMPLODED"}, {8, "DEFLATED"}, {9, "DEFLATE64"},
        {10, "PKWARE_IMPLODING"}, {12, "BZIP2"}, {14, "LZMA"},
        {93, "ZSTD"}, {95, "XZ"}, {255, "UNKNOWN"}
    };
    yx_dump_node *module = yx_dump_add(doc, parent, "zip", YX_DUMP_OBJECT);
    if (!module) return;
    if (parsed->is_zip_present)
        yx_dump_boolean(doc, module, "is_zip", parsed->is_zip);
    if (parsed->entry_count) {
        yx_dump_node *entries = yx_dump_add(doc, module, "entries", YX_DUMP_ARRAY);
        for (size_t i = 0; entries && i < parsed->entry_count; ++i) {
            const yx_zip_entry *source = &parsed->entries[i];
            yx_dump_node *item = yx_dump_add(doc, entries, NULL, YX_DUMP_OBJECT);
            if (!item) break;
            if (source->file_path_present)
                yx_dump_text(doc, item, "file_path", source->file_path,
                               source->file_path_length, false);
            if (source->compression_present) {
                const char *name = NULL;
                for (size_t j = 0; j < sizeof(compression) /
                                       sizeof(compression[0]); ++j) {
                    if (compression[j].value == source->compression) {
                        name = compression[j].name;
                        break;
                    }
                }
                yx_dump_enum(doc, item, "compression", source->compression, name);
            }
            if (source->uncompressed_size_present)
                yx_dump_number(doc, item, "uncompressed_size",
                                 source->uncompressed_size, true, YX_DUMP_DECIMAL);
            if (source->compressed_size_present)
                yx_dump_number(doc, item, "compressed_size",
                                 source->compressed_size, true, YX_DUMP_DECIMAL);
        }
    }
}

static const char *const yx_dump_module_names[] = {
    "pe", "elf", "dotnet", "macho", "lnk", "olecf", "vba", "crx", "dex", "zip"
};

static int yx_dump_module_index(const char *name, size_t length)
{
    for (size_t i = 0; i < sizeof(yx_dump_module_names) /
                            sizeof(yx_dump_module_names[0]); ++i)
        if (strlen(yx_dump_module_names[i]) == length &&
            memcmp(yx_dump_module_names[i], name, length) == 0)
            return (int)i;
    return -1;
}

static int yx_dump_arg_error(const char *message)
{
    fprintf(stderr, "%s\n\nFor more information, try '--help'.\n", message);
    return 2;
}

static const char *yx_dump_suggest_value(const char *unknown,
                                         size_t unknown_len,
                                         const char *const *values,
                                         size_t value_count);

static int yx_dump_parse_module(bool selected[10], const char *value)
{
    static const char *const possible[] = {
        "lnk", "macho", "elf", "pe", "dotnet", "olecf", "vba", "crx", "dex", "zip"
    };
    const char *start = value;
    for (;;) {
        const char *end = strchr(start, ',');
        size_t length = end ? (size_t)(end - start) : strlen(start);
        int index = yx_dump_module_index(start, length);
        if (index < 0) {
            if (length == 0)
                return yx_dump_arg_error(
                    "error: a value is required for '--module <module>' but none was supplied\n"
                    "  [possible values: lnk, macho, elf, pe, dotnet, olecf, vba, crx, dex, zip]");
            const char *suggestion = yx_dump_suggest_value(
                start, length, possible, sizeof(possible) / sizeof(possible[0]));
            fprintf(stderr,
                    "error: invalid value '%.*s' for '--module <module>'\n"
                    "  [possible values: lnk, macho, elf, pe, dotnet, olecf, vba, crx, dex, zip]\n\n",
                    (int)length, start);
            if (suggestion)
                fprintf(stderr, "  tip: a similar value exists: '%s'\n\n",
                        suggestion);
            fputs("For more information, try '--help'.\n", stderr);
            return 2;
        }
        selected[index] = true;
        if (!end) break;
        start = end + 1;
    }
    return 0;
}

static void yx_dump_build(yx_dump_doc *doc, yx_dump_node *root,
                           const bool selected[10], bool explicit_modules,
                           const uint8_t *data, size_t size)
{
    yx_lnk_result lnk = {0};
    yx_crx_result crx = {0};
    yx_dotnet_result dotnet = {0};
    yx_zip_result zip = {0};
#ifdef XXYARA_ENABLE_VBA
    yx_vba_result vba = {0};
#endif
    uint64_t value;
    bool valid_lnk = yx_lnk_parse(data, size, &lnk);
    bool valid_crx = yx_crx_parse(data, size, &crx);
    bool valid_dotnet = yx_dotnet_parse(data, size, &dotnet);
    bool valid_zip = yx_zip_parse(data, size, &zip);
#ifdef XXYARA_ENABLE_VBA
    bool valid_vba = yx_vba_parse(data, size, &vba);
#endif
    if (!valid_lnk || !valid_crx || !valid_dotnet || !valid_zip) doc->oom = true;
#ifdef XXYARA_ENABLE_VBA
    if (!valid_vba) doc->oom = true;
#endif
    if ((explicit_modules && selected[0]) ||
        (!explicit_modules && yx_pe_is_pe(data, size)))
        yx_dump_pe(doc, root, data, size);
    if ((explicit_modules && selected[1]) ||
        (!explicit_modules && yx_elf_field(data, size, "type", &value)))
        yx_dump_elf(doc, root, data, size);
    if ((explicit_modules && selected[2]) ||
        (!explicit_modules && dotnet.is_dotnet))
        yx_dump_dotnet(doc, root, data, size, &dotnet);
    if ((explicit_modules && selected[3]) ||
        (!explicit_modules &&
         (yx_macho_field(data, size, "magic", &value) ||
          yx_macho_field(data, size, "fat_magic", &value))))
        yx_dump_macho(doc, root, data, size);
    if ((explicit_modules && selected[4]) ||
        (!explicit_modules && valid_lnk && lnk.is_lnk))
        yx_dump_lnk(doc, root, data, size);
#ifdef XXYARA_ENABLE_OLECF
    if ((explicit_modules && selected[5]) ||
        (!explicit_modules && yx_olecf_is_olecf(data, size)))
        yx_dump_olecf(doc, root, data, size);
#endif
#ifdef XXYARA_ENABLE_VBA
    if ((explicit_modules && selected[6]) ||
        (!explicit_modules && valid_vba && vba.has_macros))
        yx_dump_vba(doc, root, &vba);
#endif
    if ((explicit_modules && selected[7]) ||
        (!explicit_modules && valid_crx && crx.is_crx))
        yx_dump_crx(doc, root, data, size);
    if ((explicit_modules && selected[8]) ||
        (!explicit_modules && size >= 4 && memcmp(data, "dex\n", 4) == 0))
        yx_dump_dex(doc, root, data, size);
    if ((explicit_modules && selected[9]) ||
        (!explicit_modules && valid_zip && zip.is_zip))
        yx_dump_zip(doc, root, &zip);
    yx_lnk_result_free(&lnk);
    yx_crx_result_free(&crx);
    yx_zip_result_free(&zip);
#ifdef XXYARA_ENABLE_VBA
    yx_vba_result_free(&vba);
#endif
}

typedef struct yx_dump_option_suggestion {
    const char *name;
    const char *usage;
} yx_dump_option_suggestion;

static double yx_dump_jaro_option(const char *unknown, size_t unknown_len,
                                  const char *candidate)
{
    size_t candidate_len = strlen(candidate), search_range, matches = 0;
    size_t transpositions = 0, next_candidate = 0;
    bool unknown_matches[256] = {false};
    bool candidate_matches[256] = {false};
    if (!unknown_len || !candidate_len || unknown_len > 256 ||
        candidate_len > 256) return 0.0;
    search_range = (unknown_len > candidate_len ? unknown_len :
                    candidate_len) / 2;
    if (search_range) --search_range;
    for (size_t i = 0; i < unknown_len; ++i) {
        size_t first = i > search_range ? i - search_range : 0;
        size_t last = i + search_range + 1;
        if (last > candidate_len) last = candidate_len;
        for (size_t j = first; j < last; ++j) {
            if (unknown[i] == candidate[j] && !candidate_matches[j]) {
                unknown_matches[i] = true;
                candidate_matches[j] = true;
                ++matches;
                break;
            }
        }
    }
    if (!matches) return 0.0;
    for (size_t i = 0; i < unknown_len; ++i) {
        if (!unknown_matches[i]) continue;
        while (!candidate_matches[next_candidate]) ++next_candidate;
        if (unknown[i] != candidate[next_candidate]) ++transpositions;
        ++next_candidate;
    }
    transpositions /= 2;
    return ((double)matches / (double)unknown_len +
            (double)matches / (double)candidate_len +
            (double)(matches - transpositions) / (double)matches) / 3.0;
}

static const char *yx_dump_suggest_value(const char *unknown,
                                         size_t unknown_len,
                                         const char *const *values,
                                         size_t value_count)
{
    const char *best = NULL;
    double best_score = 0.7;
    for (size_t i = 0; i < value_count; ++i) {
        double score = yx_dump_jaro_option(unknown, unknown_len, values[i]);
        if (score > best_score || (best && score == best_score)) {
            best = values[i];
            best_score = score;
        }
    }
    return best;
}

static const yx_dump_option_suggestion *yx_dump_suggest_option(
    const char *unknown, size_t unknown_len)
{
    static const yx_dump_option_suggestion options[] = {
        {"module", "--module <module>"},
        {"no-colors", "--no-colors"},
        {"output-format", "--output-format <FORMAT>"},
        {"help", "--help"},
    };
    const yx_dump_option_suggestion *best = NULL;
    double best_score = 0.7;
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        double score = yx_dump_jaro_option(unknown, unknown_len,
                                           options[i].name);
        if (score > best_score || (best && score == best_score)) {
            best = &options[i];
            best_score = score;
        }
    }
    return best;
}

static const char *yx_dump_usage_part(const char *arg)
{
    if (strcmp(arg, "-m") == 0 || strcmp(arg, "--module") == 0 ||
        strncmp(arg, "--module=", 9) == 0 ||
        (arg[0] == '-' && arg[1] == 'm' && arg[2]))
        return "--module <module>";
    if (strcmp(arg, "--no-colors") == 0) return "--no-colors";
    if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output-format") == 0 ||
        strncmp(arg, "--output-format=", 16) == 0 ||
        (arg[0] == '-' && arg[1] == 'o' && arg[2]))
        return "--output-format <FORMAT>";
    return NULL;
}

static void yx_dump_usage(char **argv, int stop, int skip_index,
                          const char *suggested_usage,
                          bool show_options_when_empty)
{
    const char *parts[4];
    size_t count = 0;
    yx_cli_usage_fputs("\nUsage: yr dump", stderr);
    for (int i = 2; i < stop; ++i) {
        const char *part;
        bool seen = false;
        if (i == skip_index) continue;
        if (strcmp(argv[i], "--") == 0) break;
        part = yx_dump_usage_part(argv[i]);
        if (!part) continue;
        for (size_t j = 0; j < count; ++j)
            if (strcmp(parts[j], part) == 0) seen = true;
        if (!seen) {
            parts[count++] = part;
            fprintf(stderr, " %s", part);
        }
    }
    if (suggested_usage) {
        bool seen = false;
        for (size_t j = 0; j < count; ++j)
            if (strcmp(parts[j], suggested_usage) == 0) seen = true;
        if (!seen) {
            parts[count++] = suggested_usage;
            fprintf(stderr, " %s", suggested_usage);
        }
    }
    if (!count && show_options_when_empty) fputs(" [OPTIONS]", stderr);
    fputs(" <FILE>\n\nFor more information, try '--help'.\n", stderr);
}

static int yx_dump_unexpected_option(char **argv, int index, bool has_path,
                                     int skip_index)
{
    const char *arg = argv[index];
    const char *equal = NULL;
    size_t argument_length = strlen(arg);
    bool long_option = arg[1] == '-' && arg[2] != '\0';
    const yx_dump_option_suggestion *suggestion = NULL;
    if (long_option) {
        equal = strchr(arg, '=');
        if (equal) argument_length = (size_t)(equal - arg);
        if (argument_length > 2)
            suggestion = yx_dump_suggest_option(arg + 2,
                                                 argument_length - 2);
    } else if (argument_length > 2) {
        argument_length = 2;
    }
    if (equal && suggestion &&
        strlen(suggestion->name) == argument_length - 2 &&
        memcmp(arg + 2, suggestion->name, argument_length - 2) == 0) {
        fprintf(stderr,
                "error: unexpected value '%s' for '--%s' found; "
                "no more were expected\n",
                equal + 1, suggestion->name);
        yx_dump_usage(argv, index, skip_index, suggestion->usage, false);
        return 2;
    }
    if (suggestion) {
        fprintf(stderr,
                "error: unexpected argument '%.*s' found\n\n"
                "  tip: a similar argument exists: '--%s'\n",
                (int)argument_length, arg, suggestion->name);
    } else {
        fprintf(stderr,
                "error: unexpected argument '%.*s' found\n\n"
                "  tip: to pass '%.*s' as a value, use '-- %.*s'\n",
                (int)argument_length, arg,
                (int)argument_length, arg,
                (int)argument_length, arg);
    }
    if (long_option) {
        yx_dump_usage(argv, index, skip_index,
                      suggestion ? suggestion->usage : NULL, !has_path);
    } else {
        yx_cli_usage_fputs("\nUsage: yr dump [OPTIONS] <FILE>\n\n"
              "For more information, try '--help'.\n", stderr);
    }
    return 2;
}

static bool yx_dump_starts_option(const char *arg)
{
    return strcmp(arg, "--") == 0 || strcmp(arg, "-h") == 0 ||
           strcmp(arg, "--help") == 0 || yx_dump_usage_part(arg) != NULL;
}

static int yx_dump_invalid_format(const char *value)
{
    static const char *const possible[] = {"json", "yaml"};
    const char *suggestion = yx_dump_suggest_value(
        value, strlen(value), possible, sizeof(possible) / sizeof(possible[0]));
    fprintf(stderr,
            "error: invalid value '%s' for '--output-format <FORMAT>'\n"
            "  [possible values: json, yaml]\n\n", value);
    if (suggestion)
        fprintf(stderr, "  tip: a similar value exists: '%s'\n\n",
                suggestion);
    fputs("For more information, try '--help'.\n", stderr);
    return 2;
}

int yx_cli_dump_command(int argc, char **argv)
{
    bool selected[10] = {false};
    bool explicit_modules = false;
    bool json = false;
    bool no_colors_seen = false;
    bool output_format_seen = false;
    const char *path = NULL;
    const char *pending_module = NULL;
    const char *pending_format = NULL;
    uint8_t *data = NULL;
    size_t size = 0;
    yx_dump_doc doc = {0};
    yx_dump_node *root;
    for (int i = 2; i < argc; ++i) {
        const char *arg = argv[i];
        const char *value = NULL;
        bool separated_value = false;
        if (path && !*path && strcmp(arg, "--") != 0 &&
            (yx_dump_starts_option(arg) ||
             (arg[0] == '-' && arg[1] == 'h' && arg[2])))
            return yx_dump_arg_error(
                "error: a value is required for '<FILE>' but none was supplied");
        bool immediate_error =
            (arg[0] == '-' && strcmp(arg, "-") != 0 &&
             !yx_dump_starts_option(arg) &&
             !(arg[1] == 'h' && arg[2])) ||
            (path && (arg[0] != '-' || strcmp(arg, "-") == 0 ||
                      (strcmp(arg, "--") == 0 && i + 1 < argc)));
        if (!immediate_error) {
            if (pending_module) {
                int status = yx_dump_parse_module(selected, pending_module);
                if (status) return status;
                pending_module = NULL;
            }
            if (pending_format) {
                if (strcmp(pending_format, "json") == 0) json = true;
                else if (strcmp(pending_format, "yaml") == 0) json = false;
                else return yx_dump_invalid_format(pending_format);
                pending_format = NULL;
            }
        }
        if (strcmp(arg, "--") == 0) {
            for (++i; i < argc; ++i) {
                if (path) {
                    yx_cli_usage_fprintf(stderr,
                            "error: unexpected argument '%s' found\n\n"
                            "Usage: yr dump [OPTIONS] <FILE>\n\n"
                            "For more information, try '--help'.\n",
                            argv[i]);
                    return 2;
                }
                path = argv[i];
            }
            break;
        }
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0 ||
            (arg[0] == '-' && arg[1] == 'h' && arg[2])) {
            yx_cli_usage_fputs(strcmp(arg, "--help") == 0 ?
                               yx_cli_help_dump_long :
                               yx_cli_help_dump_short, stdout);
            return 0;
        }
        if (strcmp(arg, "-m") == 0 || strcmp(arg, "--module") == 0) {
            if (path && i + 2 < argc &&
                strcmp(argv[i + 1], "--") == 0) {
                yx_cli_usage_fprintf(stderr,
                        "error: unexpected argument '%s' found\n\n"
                        "Usage: yr dump [OPTIONS] <FILE>\n\n"
                        "For more information, try '--help'.\n",
                        argv[i + 2]);
                return 2;
            }
            if (i + 1 >= argc ||
                yx_dump_starts_option(argv[i + 1]))
                return yx_dump_arg_error(
                    "error: a value is required for '--module <module>' but none was supplied\n"
                    "  [possible values: lnk, macho, elf, pe, dotnet, olecf, vba, crx, dex, zip]");
            if (argv[i + 1][0] == '-' && argv[i + 1][1])
                return yx_dump_unexpected_option(argv, i + 1,
                                                 path != NULL, i);
            value = argv[++i];
            separated_value = true;
        } else if (strncmp(arg, "--module=", 9) == 0) value = arg + 9;
        else if (strncmp(arg, "-m", 2) == 0 && arg[2])
            value = arg[2] == '=' ? arg + 3 : arg + 2;
        if (value) {
            if (!*value)
                return yx_dump_arg_error(
                    "error: a value is required for '--module <module>' but none was supplied\n"
                    "  [possible values: lnk, macho, elf, pe, dotnet, olecf, vba, crx, dex, zip]");
            if (separated_value) pending_module = value;
            else {
                int status = yx_dump_parse_module(selected, value);
                if (status) return status;
            }
            explicit_modules = true;
            continue;
        }
        if (strcmp(arg, "-o") == 0 ||
            strcmp(arg, "--output-format") == 0) {
            if (path && i + 2 < argc &&
                strcmp(argv[i + 1], "--") == 0) {
                yx_cli_usage_fprintf(stderr,
                        "error: unexpected argument '%s' found\n\n"
                        "Usage: yr dump [OPTIONS] <FILE>\n\n"
                        "For more information, try '--help'.\n",
                        argv[i + 2]);
                return 2;
            }
            if (i + 1 >= argc ||
                yx_dump_starts_option(argv[i + 1]))
                return yx_dump_arg_error(
                    "error: a value is required for '--output-format <FORMAT>' but none was supplied\n"
                    "  [possible values: json, yaml]");
            if (argv[i + 1][0] == '-' && argv[i + 1][1])
                return yx_dump_unexpected_option(argv, i + 1,
                                                 path != NULL, i);
            value = argv[++i];
            separated_value = true;
        } else if (strncmp(arg, "--output-format=", 16) == 0)
            value = arg + 16;
        else if (strncmp(arg, "-o", 2) == 0 && arg[2])
            value = arg[2] == '=' ? arg + 3 : arg + 2;
        if (value) {
            if (output_format_seen) {
                yx_cli_usage_fputs("error: the argument '--output-format <FORMAT>' "
                      "cannot be used multiple times\n\n"
                      "Usage: yr dump [OPTIONS] <FILE>\n\n"
                      "For more information, try '--help'.\n", stderr);
                return 2;
            }
            if (!*value)
                return yx_dump_arg_error(
                    "error: a value is required for '--output-format <FORMAT>' but none was supplied\n"
                    "  [possible values: json, yaml]");
            if (separated_value) pending_format = value;
            else {
                if (strcmp(value, "json") == 0) json = true;
                else if (strcmp(value, "yaml") == 0) json = false;
                else return yx_dump_invalid_format(value);
            }
            output_format_seen = true;
            continue;
        }
        if (strcmp(arg, "--no-colors") == 0) {
            if (no_colors_seen) {
                yx_cli_usage_fputs("error: the argument '--no-colors' cannot be used "
                      "multiple times\n\n"
                      "Usage: yr dump [OPTIONS] <FILE>\n\n"
                      "For more information, try '--help'.\n", stderr);
                return 2;
            }
            no_colors_seen = true;
            continue;
        }
        if (strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0) {
            return yx_dump_unexpected_option(argv, i, path != NULL, -1);
        }
        if (arg[0] == '-' && strcmp(arg, "-") != 0) {
            int skip_index = -1;
            if ((pending_module || pending_format) && i >= 2 &&
                (strncmp(arg, "--help=", 7) == 0 ||
                 strncmp(arg, "--no-colors=", 12) == 0))
                skip_index = i - 2;
            return yx_dump_unexpected_option(argv, i, path != NULL,
                                             skip_index);
        }
        if (path) {
            yx_cli_usage_fprintf(stderr,
                    "error: unexpected argument '%s' found\n\n"
                    "Usage: yr dump [OPTIONS] <FILE>\n\n"
                    "For more information, try '--help'.\n", arg);
            return 2;
        }
        path = arg;
    }
    if (pending_module) {
        int status = yx_dump_parse_module(selected, pending_module);
        if (status) return status;
    }
    if (pending_format) {
        if (strcmp(pending_format, "json") == 0) json = true;
        else if (strcmp(pending_format, "yaml") == 0) json = false;
        else return yx_dump_invalid_format(pending_format);
    }
    if (!path) {
        fputs("error: the following required arguments were not provided:\n"
              "  <FILE>\n", stderr);
        yx_dump_usage(argv, argc, -1, NULL, false);
        return 2;
    }
    if (!*path)
        return yx_dump_arg_error(
            "error: a value is required for '<FILE>' but none was supplied");
    if (!yx_cli_validate_command_config()) return 1;
    if (!yx_dump_read(path, &data, &size)) {
        fprintf(stderr, "error: %s\n", yx_os_error_text(yx_os_error_last()));
        return 1;
    }
    root = yx_dump_add(&doc, NULL, NULL, YX_DUMP_OBJECT);
    if (root) yx_dump_build(&doc, root, selected, explicit_modules, data, size);
    if (doc.oom) {
        fputs("error: out of memory\n", stderr);
        yx_dump_free(&doc);
        free(data);
        return 1;
    }
    bool written = true;
    if (json) yx_dump_json(stdout, root, 0);
    else written = yx_dump_yaml_document(root, !no_colors_seen);
    fputc('\n', stdout);
    yx_dump_free(&doc);
    free(data);
    return ferror(stdout) || !written ? 1 : 0;
}
