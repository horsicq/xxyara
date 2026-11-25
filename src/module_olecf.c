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

#include "module_olecf.h"

/* The YARA-X-exact OLECF reader moved to xxfclib (xx_olecf_yx.h); the
 * private parsing copy (DIFAT/FAT/MiniFAT, IndexMap directory entries, mini
 * stream reassembly) was removed from this file. */

bool yx_olecf_constant(const char *member, uint64_t *value)
{
    return xx_olecf_yx_constant(member, value);
}

bool yx_olecf_is_olecf(const uint8_t *data, size_t size)
{
    return xx_olecf_yx_is_olecf(data, size);
}

bool yx_olecf_stream_count(const uint8_t *data, size_t size, uint64_t *count)
{
    return xx_olecf_yx_stream_count(data, size, count);
}

bool yx_olecf_stream_get(const uint8_t *data, size_t size, uint64_t index, yx_olecf_stream *stream)
{
    return xx_olecf_yx_stream_get(data, size, index, stream);
}

yx_olecf_document *yx_olecf_open(const uint8_t *data, size_t size)
{
    return xx_olecf_yx_open(data, size);
}

void yx_olecf_close(yx_olecf_document *document)
{
    xx_olecf_yx_close(document);
}

size_t yx_olecf_sector_size(const yx_olecf_document *document)
{
    return xx_olecf_yx_sector_size(document);
}

size_t yx_olecf_entry_count(const yx_olecf_document *document)
{
    return xx_olecf_yx_entry_count(document);
}

const yx_olecf_stream *yx_olecf_entry(const yx_olecf_document *document, size_t index)
{
    return xx_olecf_yx_entry(document, index);
}

bool yx_olecf_entry_data(const yx_olecf_document *document, size_t index, const uint8_t **bytes, size_t *size, uint8_t **owner)
{
    return xx_olecf_yx_entry_data(document, index, bytes, size, owner);
}
