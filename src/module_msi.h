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

#ifndef XXYARA_MODULE_MSI_H
#define XXYARA_MODULE_MSI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "module_pe.h"

/* The experimental YARA-X v1.23.0 msi module (feature `msi-module`,
 * lib/src/modules/msi). It exposes `is_signed` and `signatures`, a repeated
 * pe.Signature, so the result reuses yx_pe_signature_result and the
 * pe.signatures field walkers.
 *
 * Non-OLECF input, a missing DigitalSignature stream and an unparsable
 * signature all leave result->count at zero: msi.is_signed is then false
 * and msi.signatures empty, never undefined (msi/mod.rs). False is returned
 * only for invalid arguments or allocation failure. */
bool yx_msi_signatures(const uint8_t *data, size_t size, yx_pe_signature_result *result);

/* The MSI Authenticode hash input (MsiHasher, msi/parser.rs) of an OLECF
 * file, fed to `update`; exposed for tests. False for non-OLECF input. */
bool yx_msi_hash_input(const uint8_t *data, size_t size, yx_authenticode_update_fn update, void *state);

#endif
