/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef XXYARA_MODULE_VT_H
#define XXYARA_MODULE_VT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <xxfclib/net/xx_domain_yx.h>
typedef struct yx_vt_record yx_vt_record;
typedef struct yx_vt_value yx_vt_value;
typedef struct {
    const char *string;
    size_t length;
    uint64_t number;
    bool is_string;
} yx_vt_key;
typedef enum {
    YX_VT_DATA_INTEGER,
    YX_VT_DATA_FLOAT,
    YX_VT_DATA_STRING,
    YX_VT_DATA_ARRAY,
    YX_VT_DATA_MAP,
    YX_VT_DATA_STRUCT
} yx_vt_data_type;
typedef struct {
    yx_vt_data_type type;
    uint64_t number;
    bool is_unsigned;
    double floating;
    const char *string;
    size_t length;
    const yx_vt_value *collection;
} yx_vt_data;
bool yx_vt_parse_output(const uint8_t *data, size_t size, yx_vt_record **out, char *error, size_t error_capacity);
void yx_vt_output_destroy(yx_vt_record *output);
bool yx_vt_output_get(const yx_vt_record *output, const char *path, const yx_vt_key *keys, size_t key_count, bool element, yx_vt_data *out);
bool yx_vt_map_item(const yx_vt_value *map, size_t index, const char **key, size_t *key_length, const char **value, size_t *value_length);

/* vt.net.EnrichedIP.in_range(cidr) (YARA-X lib/src/modules/vt/mod.rs):
 * `ip` is the struct's `raw` field, parsed like Rust's IpAddr, and `cidr`
 * is parsed like ipnet's IpNet. Unparsable input yields false. */
bool yx_vt_ip_in_range(const char *ip, size_t ip_length, const char *cidr, size_t cidr_length);

/* vt.net.EnrichedDomain.permutation_of(target[, kinds]): `domain` is the
 * struct's `raw` field; `kinds` is a vt.Domain.Permutation bit set
 * (permutation_of(target) uses ALL = 0x1F). */
bool yx_vt_domain_permutation_of(const char *domain, size_t domain_length, const char *target, size_t target_length, int64_t kinds);

/* The parts of a domain name split at its public suffix (parse_domain in
 * vt/mod.rs); absent parts have NULL pointers. Exposed for tests. The
 * implementation lives in xxfclib (xx_domain_yx_parts). */
typedef xx_domain_yx_parts yx_vt_domain_parts;
bool yx_vt_parse_domain(const char *name, size_t length, yx_vt_domain_parts *parts);
/* Length of psl::suffix(name), 0 for None. Exposed for tests. */
size_t yx_vt_public_suffix_length(const char *name, size_t length);
#endif
