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

#include "module_msi.h"
#include "module_olecf.h"

#include <xxfclib/formats/installer/msi/xx_msi_yx.h>

#include <stdlib.h>
#include <string.h>

/* The OLECF container and the MsiHasher hash-input moved to xxfclib
 * (xx_olecf_yx.h / xx_msi_yx.h). What remains here is the module glue: the
 * DigitalSignature stream lookup and the Authenticode PKCS#7 parsing, which
 * produces the pe.Signature values shared with the pe module. */

typedef struct {
    const uint8_t *data;
    size_t size;
} yx_msi_context;

static void yx_msi_hasher(void *opaque, yx_authenticode_update_fn update,
                          void *state)
{
    const yx_msi_context *context = (const yx_msi_context *)opaque;
    (void)xx_msi_yx_hash_input(context->data, context->size, update, state);
}

bool yx_msi_hash_input(const uint8_t *data, size_t size,
                       yx_authenticode_update_fn update, void *state)
{
    if (!update) return false;
    return xx_msi_yx_hash_input(data, size, update, state);
}

bool yx_msi_signatures(const uint8_t *data, size_t size,
                       yx_pe_signature_result *result)
{
    yx_olecf_document *document;
    size_t count, index;
    bool ok = true;
    if (!result) return false;
    memset(result, 0, sizeof(*result));
    if (!data && size) return false;
    /* CachedOlecf::NotOlecf: unsigned. */
    document = yx_olecf_open(data, size);
    if (!document) return true;
    /* Msi::parse: the first entry named DigitalSignature, after cleaning. */
    count = yx_olecf_entry_count(document);
    for (index = 0; index < count; ++index)
        if (xx_msi_yx_name_is(yx_olecf_entry(document, index),
                              "DigitalSignature")) break;
    if (index < count) {
        const uint8_t *bytes;
        size_t length;
        uint8_t *owner;
        /* A signature stream that cannot be read means unsigned. */
        if (yx_olecf_entry_data(document, index, &bytes, &length, &owner)) {
            yx_msi_context context;
            context.data = data;
            context.size = size;
            ok = yx_authenticode_parse_blob(bytes, length, yx_msi_hasher,
                                            &context, result);
            free(owner);
        }
    }
    yx_olecf_close(document);
    return ok;
}
