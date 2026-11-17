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

#include "module_elf.h"

#include <xxfclib/formats/executable/elf/xx_elf_yx.h>
#include <xxfclib/strings/xx_string_casefold.h>

/* The YARA-X-exact ELF parsing moved to xxfclib (xx_elf_yx.h,
 * src/formats/executable/elf/xx_elf_yx.c). The functions below keep the
 * yx_elf_* module API used by the scanner, the condition evaluator and the
 * CLI dump as thin adapters; the private parsing copies (header parser,
 * entry-point resolution, dynamic walker, Unicode casefold tables, MD5 and
 * TLSH collectors) were removed from this file. */

bool yx_elf_field_supported(const char *member)
{
    return xx_elf_yx_field_supported(member);
}

bool yx_elf_field(const uint8_t *data, size_t size, const char *member,
                  uint64_t *value)
{
    return xx_elf_yx_field(data, size, member, value);
}

bool yx_elf_constant(const char *member, uint64_t *value)
{
    return xx_elf_yx_constant(member, value);
}

bool yx_elf_collection_count(const uint8_t *data, size_t size,
                              const char *member, uint64_t *count)
{
    return xx_elf_yx_collection_count(data, size, member, count);
}

bool yx_elf_indexed_field_supported(const char *collection,
                                     const char *member)
{
    return xx_elf_yx_indexed_field_supported(collection, member);
}

bool yx_elf_indexed_field(const uint8_t *data, size_t size,
                           const char *collection, uint64_t index,
                           const char *member, uint64_t *value)
{
    return xx_elf_yx_indexed_field(data, size, collection, index, member,
                                   value);
}

bool yx_elf_indexed_string_field_supported(const char *collection,
                                            const char *member)
{
    return xx_elf_yx_indexed_string_field_supported(collection, member);
}

bool yx_elf_indexed_string_field(const uint8_t *data, size_t size,
                                  const char *collection, uint64_t index,
                                  const char *member,
                                  const uint8_t **bytes, size_t *length)
{
    return xx_elf_yx_indexed_string_field(data, size, collection, index,
                                          member, bytes, length);
}

bool yx_elf_utf8_lossy(const uint8_t *bytes, size_t length, char *out,
                        size_t capacity, size_t *written)
{
    return xx_string_utf8_lossy(bytes, length, out, capacity, written);
}

bool yx_elf_import_md5(const uint8_t *data, size_t size, char out[33])
{
    return xx_elf_yx_import_md5(data, size, out);
}

bool yx_elf_telfhash(const uint8_t *data, size_t size, char out[73])
{
    return xx_elf_yx_telfhash(data, size, out);
}
