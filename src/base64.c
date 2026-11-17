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

#include "internal.h"

#include <xxfclib/data/xx_data.h>
#include <xxfclib/algo/base64/xx_base64.h>

#include <stdlib.h>
#include <string.h>

static const char yx_standard_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static bool yx_encoded_length(size_t length, size_t *out)
{
    size_t groups = length / 3;
    size_t remainder = length % 3;
    if (groups > (SIZE_MAX - 3) / 4) return false;
    *out = groups * 4 + (remainder ? remainder + 1 : 0);
    return true;
}

static bool yx_encode_base64(const uint8_t *input, size_t length,
                             const char *alphabet, uint8_t **out,
                             size_t *out_length)
{
    uint8_t *encoded;
    size_t capacity;
    if (!yx_encoded_length(length, &capacity)) return false;
    encoded = (uint8_t *) malloc(capacity ? capacity : 1);
    if (!encoded) return false;
    /* xxfclib's buffer primitive, unpadded form (identical output). */
    if (!xx_base64_encode_buffer(input, length, alphabet, false,
                                 (char *)encoded, capacity, out_length)) {
        free(encoded);
        return false;
    }
    *out = encoded;
    return true;
}

/* Mirrors YARA-X 1.21's verification ranges for each base64 phase. The
 * candidate found by byte search excludes unstable edge characters. The
 * surrounding characters are decoded and compared with the original text. */
static int yx_verify_base64(const uint8_t *plain, size_t plain_length,
                            const uint8_t *data, size_t size,
                            size_t padding, size_t candidate_start,
                            const char *alphabet, bool wide,
                            size_t *match_length)
{
    size_t encoded_length, decode_delta, decode_length, reported_length;
    size_t decode_start, decode_end, ascii_length = 0, decoded_length = 0;
    uint8_t *ascii = NULL, *decoded = NULL;
    int verdict = 0;
    if (!yx_encoded_length(plain_length, &encoded_length)) return false;
    if (encoded_length > SIZE_MAX - 5) return false;
    switch (padding) {
    case 0:
        if (encoded_length % 4 == 0) {
            decode_delta = 0; decode_length = encoded_length;
            reported_length = encoded_length;
        } else if (encoded_length % 4 == 2) {
            decode_delta = 0; decode_length = encoded_length + 2;
            reported_length = encoded_length - 1;
        } else {
            decode_delta = 0; decode_length = encoded_length + 1;
            reported_length = encoded_length - 1;
        }
        break;
    case 1:
        decode_delta = 2;
        if (encoded_length % 4 == 0) {
            decode_length = encoded_length + 4;
            reported_length = encoded_length - 1;
        } else if (encoded_length % 4 == 2) {
            decode_length = encoded_length + 2;
            reported_length = encoded_length - 2;
        } else {
            decode_length = encoded_length + 1;
            reported_length = encoded_length - 1;
        }
        break;
    case 2:
        decode_delta = 3;
        if (encoded_length % 4 == 0) {
            decode_length = encoded_length + 4;
            reported_length = encoded_length - 1;
        } else if (encoded_length % 4 == 2) {
            decode_length = encoded_length + 2;
            reported_length = encoded_length - 1;
        } else {
            decode_length = encoded_length + 5;
            reported_length = encoded_length - 1;
        }
        break;
    default: return false;
    }
    if (wide) {
        if (decode_delta > SIZE_MAX / 2 ||
            decode_length > SIZE_MAX / 2 ||
            reported_length > SIZE_MAX / 2) return false;
        decode_delta *= 2;
        decode_length *= 2;
        reported_length *= 2;
    }
    if (candidate_start < decode_delta ||
        candidate_start > size || reported_length > size - candidate_start)
        return false;
    decode_start = candidate_start - decode_delta;
    decode_end = decode_length > size - decode_start ? size :
                 decode_start + decode_length;
    ascii = (uint8_t *) malloc(decode_end - decode_start + 1);
    if (!ascii) return -1;
    if (wide) {
        for (size_t i = decode_start; i < decode_end; ++i) {
            if ((i - decode_start) % 2 == 0) {
                if (data[i] != '=') ascii[ascii_length++] = data[i];
            } else if (data[i] != 0) goto done;
        }
    } else {
        ascii_length = decode_end - decode_start;
        memcpy(ascii, data + decode_start, ascii_length);
        if (ascii_length && ascii[ascii_length - 1] == '=') {
            --ascii_length;
            if (ascii_length && ascii[ascii_length - 1] == '=') --ascii_length;
        }
    }
    if (ascii_length == SIZE_MAX) goto done;
    decoded = (uint8_t *) malloc(ascii_length + 1);
    if (!decoded) {
        verdict = -1;
        goto done;
    }
    /* xxfclib's decoder: zero-valued tail bits, no padding, length != 1 mod 4.
     * decoded holds ascii_length + 1 bytes, more than any decoded size. */
    if (!xx_base64_decode_buffer((const char *) ascii, ascii_length, alphabet,
                                 decoded, ascii_length + 1, &decoded_length) ||
        padding > decoded_length || plain_length > decoded_length - padding)
        goto done;
    verdict = memcmp(decoded + padding, plain, plain_length) == 0;
    if (verdict) *match_length = reported_length;
done:
    free(ascii);
    free(decoded);
    return verdict;
}

static bool yx_append_base64_match(YRX_PATTERN *pattern, size_t offset,
                                   size_t length, bool first_only)
{
    YRX_MATCH *grown;
    size_t next;
    if (first_only && pattern->match_count) {
        YRX_MATCH *current = &pattern->matches[0];
        if (offset < current->offset ||
            (offset == current->offset && length < current->length))
            *current = (YRX_MATCH){offset, length, -1};
        return true;
    }
    if (pattern->match_count == pattern->match_capacity) {
        next = pattern->match_capacity ? pattern->match_capacity * 2 : 8;
        if (next <= pattern->match_capacity ||
            next > SIZE_MAX / sizeof(*grown)) return false;
        grown = (YRX_MATCH *) realloc(pattern->matches, next * sizeof(*grown));
        if (!grown) return false;
        pattern->matches = grown;
        pattern->match_capacity = next;
    }
    pattern->matches[pattern->match_count++] = (YRX_MATCH){offset, length, -1};
    return true;
}

static int yx_base64_match_compare(const void *left, const void *right)
{
    const YRX_MATCH *a = (const YRX_MATCH *) left;
    const YRX_MATCH *b = (const YRX_MATCH *) right;
    if (a->offset < b->offset) return -1;
    if (a->offset > b->offset) return 1;
    if (a->length < b->length) return -1;
    if (a->length > b->length) return 1;
    return 0;
}

static bool yx_scan_encoded_variant(YRX_PATTERN *pattern,
                                     const uint8_t *plain, size_t plain_length,
                                     const uint8_t *data, size_t size,
                                     const char *alphabet, bool wide,
                                     bool first_only)
{
    for (size_t padding = 2; padding <= 2; --padding) {
        uint8_t *padded = NULL, *encoded = NULL, *needle = NULL;
        size_t encoded_length, left_trim, right_trim, candidate_length;
        size_t needle_length, start;
        if (plain_length > SIZE_MAX - padding) return false;
        padded = (uint8_t *) malloc(plain_length + padding);
        if (!padded) return false;
        memset(padded, 'X', padding);
        memcpy(padded + padding, plain, plain_length);
        if (!yx_encode_base64(padded, plain_length + padding, alphabet,
                              &encoded, &encoded_length)) {
            free(padded);
            return false;
        }
        free(padded);
        left_trim = padding == 2 ? 3 : padding == 1 ? 2 : 0;
        right_trim = (plain_length + padding) % 3 != 0;
        if (encoded_length < left_trim + right_trim) {
            free(encoded);
            return false;
        }
        candidate_length = encoded_length - left_trim - right_trim;
        if (!candidate_length || (wide && candidate_length > SIZE_MAX / 2)) {
            free(encoded);
            return false;
        }
        needle_length = candidate_length * (wide ? 2 : 1);
        needle = (uint8_t *) malloc(needle_length);
        if (!needle) {
            free(encoded);
            return false;
        }
        for (size_t i = 0; i < candidate_length; ++i) {
            needle[i * (wide ? 2 : 1)] = encoded[left_trim + i];
            if (wide) needle[i * 2 + 1] = 0;
        }
        free(encoded);
        start = 0;
        while (start <= size && needle_length <= size - start) {
            int64_t found = xx_data_find_bytes_buffer_optimize(
                data, size, start, needle, needle_length, NULL);
            size_t matched_length = 0;
            int verified;
            if (found < 0) break;
            verified = yx_verify_base64(plain, plain_length, data, size,
                                        padding, (size_t) found, alphabet,
                                        wide, &matched_length);
            if (verified < 0 || (verified > 0 &&
                !yx_append_base64_match(pattern, (size_t) found,
                                        matched_length, first_only))) {
                free(needle);
                return false;
            }
            start = (size_t) found + 1;
        }
        free(needle);
        if (padding == 0) break;
    }
    return true;
}

/* An archive can retain its original three search atoms after the literal
 * pool changes. Keep their phase and backtrack positions for candidate
 * discovery, then verify each candidate with the changed literal. */
static bool yx_scan_archived_base64_atoms(YRX_PATTERN *pattern,
                                          const uint8_t *data, size_t size,
                                          bool first_only)
{
    const yx_base64_archived_prefilter *prefilter =
        &pattern->base64_archived_prefilter;
    for (size_t phase = 0; phase < 3; ++phase) {
        size_t width = prefilter->widths[phase];
        size_t backtrack = prefilter->offsets[phase];
        size_t start = 0;
        if (width == 0 || width > sizeof(prefilter->atoms[phase]))
            return false;
        while (start <= size && width <= size - start) {
            int64_t found = xx_data_find_bytes_buffer_optimize(
                data, size, start, prefilter->atoms[phase], width, NULL);
            size_t matched_length = 0;
            int verified;
            if (found < 0) break;
            if ((size_t) found >= backtrack) {
                size_t candidate_start = (size_t) found - backtrack;
                verified = yx_verify_base64(
                    pattern->bytes, pattern->length, data, size,
                    2 - phase, candidate_start, yx_standard_alphabet,
                    false, &matched_length);
                if (verified < 0 ||
                    (verified > 0 &&
                     !yx_append_base64_match(pattern, candidate_start,
                                             matched_length, first_only)))
                    return false;
            }
            start = (size_t) found + 1;
        }
    }
    return true;
}

int yx_scan_base64(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                   size_t limit, bool first_only)
{
    bool plain_ascii, plain_wide;
    if (!pattern || !pattern->bytes || pattern->length < 3) return 0;
    if (pattern->base64_archived_prefilter.present) {
        if ((pattern->modifiers & ~YX_MOD_ASCII) != YX_MOD_BASE64 ||
            pattern->base64_alphabet || pattern->base64wide_alphabet ||
            !yx_scan_archived_base64_atoms(pattern, data, size, first_only))
            return 0;
    } else {
        plain_ascii = (pattern->modifiers & YX_MOD_ASCII) ||
                      !(pattern->modifiers & YX_MOD_WIDE);
        plain_wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
        for (int plain_variant = 0; plain_variant < 2; ++plain_variant) {
            const uint8_t *plain = pattern->bytes;
            uint8_t *owned_plain = NULL;
            size_t plain_length = pattern->length;
            if (plain_variant == 0 && !plain_ascii) continue;
            if (plain_variant == 1 && !plain_wide) continue;
            if (plain_variant == 1) {
                if (plain_length > SIZE_MAX / 2) return 0;
                plain_length *= 2;
                owned_plain = (uint8_t *) malloc(plain_length);
                if (!owned_plain) return 0;
                for (size_t i = 0; i < pattern->length; ++i) {
                    owned_plain[2 * i] = pattern->bytes[i];
                    owned_plain[2 * i + 1] = 0;
                }
                plain = owned_plain;
            }
            for (int encoded_variant = 0; encoded_variant < 2;
                 ++encoded_variant) {
                unsigned modifier = encoded_variant ?
                    YX_MOD_BASE64WIDE : YX_MOD_BASE64;
                const char *alphabet = encoded_variant ?
                    pattern->base64wide_alphabet : pattern->base64_alphabet;
                if (!(pattern->modifiers & modifier)) continue;
                if (!alphabet) alphabet = yx_standard_alphabet;
                if (!yx_scan_encoded_variant(pattern, plain, plain_length,
                                             data, size, alphabet,
                                             encoded_variant != 0,
                                             first_only)) {
                    free(owned_plain);
                    return 0;
                }
            }
            free(owned_plain);
        }
    }
    if (pattern->match_count > 1)
        qsort(pattern->matches, pattern->match_count, sizeof(YRX_MATCH),
              yx_base64_match_compare);
    size_t unique = 0;
    for (size_t i = 0; i < pattern->match_count; ++i) {
        if (unique && pattern->matches[unique - 1].offset ==
                      pattern->matches[i].offset) continue;
        pattern->matches[unique++] = pattern->matches[i];
    }
    pattern->match_count = unique;
    if (limit && pattern->match_count > limit)
        pattern->match_count = limit;
    return 1;
}
#include "scan_candidates.h"

yx_base64_candidate *yx_base64_candidates_build(const YRX_PATTERN *pattern,
                                                size_t *count)
{
    yx_base64_candidate *variants;
    bool ascii, wide;
    *count = 0;
    if (!pattern || !pattern->bytes || pattern->length < 3 ||
        pattern->base64_archived_prefilter.present) return NULL;
    variants = calloc(12, sizeof(*variants));
    if (!variants) return NULL;
    ascii = (pattern->modifiers & YX_MOD_ASCII) ||
            !(pattern->modifiers & YX_MOD_WIDE);
    wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    for (unsigned plain_variant = 0; plain_variant < 2; ++plain_variant) {
        if ((!plain_variant && !ascii) || (plain_variant && !wide)) continue;
        if (plain_variant && pattern->length > SIZE_MAX / 2) goto fail;
        size_t plain_length = pattern->length * (plain_variant ? 2 : 1);
        for (unsigned encoding = 0; encoding < 2; ++encoding) {
            unsigned modifier = encoding ? YX_MOD_BASE64WIDE : YX_MOD_BASE64;
            if (!(pattern->modifiers & modifier)) continue;
            const char *alphabet = encoding ? pattern->base64wide_alphabet :
                                             pattern->base64_alphabet;
            if (!alphabet) alphabet = yx_standard_alphabet;
            for (size_t padding = 2; padding <= 2; --padding) {
                yx_base64_candidate *variant = &variants[(*count)++];
                uint8_t *padded = NULL, *encoded = NULL;
                size_t encoded_length, trim, candidate_length;
                variant->plain_length = plain_length;
                variant->padding = padding;
                variant->alphabet = alphabet;
                variant->wide = encoding != 0;
                variant->plain = malloc(plain_length);
                if (!variant->plain || plain_length > SIZE_MAX - padding)
                    goto fail;
                for (size_t i = 0; i < pattern->length; ++i) {
                    variant->plain[i * (plain_variant ? 2 : 1)] = pattern->bytes[i];
                    if (plain_variant) variant->plain[i * 2 + 1] = 0;
                }
                padded = malloc(plain_length + padding);
                if (!padded) goto fail;
                memset(padded, 'X', padding);
                memcpy(padded + padding, variant->plain, plain_length);
                bool encoded_ok = yx_encode_base64(padded, plain_length + padding,
                                                    alphabet, &encoded,
                                                    &encoded_length);
                free(padded);
                if (!encoded_ok) goto fail;
                trim = padding == 2 ? 3 : padding == 1 ? 2 : 0;
                if (encoded_length < trim + ((plain_length + padding) % 3 != 0)) {
                    free(encoded); goto fail;
                }
                candidate_length = encoded_length - trim -
                                   ((plain_length + padding) % 3 != 0);
                if (!candidate_length || (encoding && candidate_length > SIZE_MAX / 2)) {
                    free(encoded); goto fail;
                }
                variant->length = candidate_length * (encoding ? 2 : 1);
                variant->needle = malloc(variant->length);
                if (!variant->needle) { free(encoded); goto fail; }
                for (size_t i = 0; i < candidate_length; ++i) {
                    variant->needle[i * (encoding ? 2 : 1)] = encoded[trim + i];
                    if (encoding) variant->needle[i * 2 + 1] = 0;
                }
                free(encoded);
                if (padding == 0) break;
            }
        }
    }
    if (*count) return variants;
fail:
    yx_base64_candidates_destroy(variants, *count);
    *count = 0;
    return NULL;
}

void yx_base64_candidates_destroy(yx_base64_candidate *variants, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        free(variants[i].needle);
        free(variants[i].plain);
    }
    free(variants);
}

int yx_base64_candidate_verify(const yx_base64_candidate *variant,
    const uint8_t *data, size_t size, size_t start, size_t *length)
{
    if (start > size || variant->length > size - start ||
        memcmp(data + start, variant->needle, variant->length) != 0) return 0;
    return yx_verify_base64(variant->plain, variant->plain_length, data, size,
        variant->padding, start, variant->alphabet, variant->wide, length);
}
