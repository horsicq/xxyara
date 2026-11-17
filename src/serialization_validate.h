/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef YX_SERIALIZATION_VALIDATE_H
#define YX_SERIALIZATION_VALIDATE_H

static _Thread_local const char *yx_wire_decode_detail;
static _Thread_local char yx_wire_decode_message[192];

typedef struct yx_wire_minimal {
    const uint8_t *data;
    yx_writer bytes;
    size_t copied;
    bool no_memory;
} yx_wire_minimal;
static _Thread_local yx_wire_minimal *yx_wire_minimizing;
static _Thread_local bool yx_wire_nonminimal;

/* Bincode permits a wider marker within the destination integer's width.
 * Canonical reconstruction uses the same value with its shortest marker. */
static bool yx_wire_minimal_integer(yx_reader *r, size_t start, uint64_t value)
{
    size_t width = value < 251 ? 1 : value <= UINT16_MAX ? 3 :
        value <= UINT32_MAX ? 5 : 9;
    if (r->at - start == width) return true;
    yx_wire_nonminimal = true;
    yx_wire_minimal *minimal = yx_wire_minimizing;
    if (!minimal || minimal->data != r->data) return true;
    if (start < minimal->copied) return false;
    if (!yx_put_bytes(&minimal->bytes, r->data + minimal->copied,
            start - minimal->copied) || !yx_put_uint(&minimal->bytes, value)) {
        minimal->no_memory = true;
        return false;
    }
    minimal->copied = r->at;
    return true;
}

const char *yx_ser_v12_decode_error_detail(void)
{
    return yx_wire_decode_detail;
}

static bool yx_wire_missing(uint64_t additional)
{
    snprintf(yx_wire_decode_message, sizeof(yx_wire_decode_message),
        "UnexpectedEnd { additional: %" PRIu64 " }", additional);
    yx_wire_decode_detail = yx_wire_decode_message;
    return false;
}

/* Bincode validates the marker before reading its payload. A larger integer
 * marker is invalid even if the encoded value would fit the destination. */
static bool yx_wire_integer(yx_reader *r, uint64_t *value,
    unsigned bits, const char *expected, bool signed_type)
{
    if (!r->data || r->at >= r->length) return yx_wire_missing(1);
    uint8_t marker = r->data[r->at];
    if (marker >= (bits == 16 ? 252 : bits == 32 ? 253 : 254)) {
        const char *found = marker == 255 ? "Reserved" :
            marker == 252 ? (signed_type ? "I32" : "U32") :
            marker == 253 ? (signed_type ? "I64" : "U64") :
                            (signed_type ? "I128" : "U128");
        snprintf(yx_wire_decode_message, sizeof(yx_wire_decode_message),
            "InvalidIntegerType { expected: %s, found: %s }", expected, found);
        yx_wire_decode_detail = yx_wire_decode_message;
        return false;
    }
    size_t width = marker == 251 ? 2 : marker == 252 ? 4 : marker == 253 ? 8 : 0;
    size_t remaining = r->length - r->at - 1;
    if (width > remaining) return yx_wire_missing(width - remaining);
    size_t start = r->at;
    return yx_get_uint(r, value) && yx_wire_minimal_integer(r, start, *value);
}

static bool yx_wire_uint(yx_reader *r, uint64_t *value, unsigned bits)
{
    return yx_wire_integer(r, value, bits,
        bits == 16 ? "U16" : bits == 32 ? "U32" : "U64", false);
}

static bool yx_wire_size(yx_reader *r, uint64_t *value)
{
    return yx_wire_integer(r, value, 64, "Usize", false);
}

static bool yx_wire_i32(yx_reader *r, uint64_t *value)
{
    return yx_wire_integer(r, value, 32, "I32", true);
}

/* Walk the wire container independently of condition reconstruction. Bounds
 * failures must have upstream's InvalidFormat classification even when the
 * condition is not one of the canonical codecs supported below. No allocation
 * depends on a count in the input. */
static bool yx_wire_count(yx_reader *r, uint64_t *count, size_t minimum)
{
    /* Each element walk consumes at least one byte and stops at the first
     * error. Let that read identify the missing field, as bincode does. */
    (void)minimum;
    return yx_wire_size(r, count);
}

static bool yx_wire_bytes(yx_reader *r)
{
    uint64_t count;
    if (!yx_wire_size(r, &count)) return false;
    if (count > r->length - r->at) return yx_wire_missing(count - (r->length - r->at));
    r->at += (size_t) count;
    return true;
}

/* A plain Vec<u8> is a serde sequence: bincode reads its elements one at a
 * time, so a truncated vector always misses exactly one more byte. */
static bool yx_wire_sequence_bytes(yx_reader *r)
{
    uint64_t count;
    if (!yx_wire_size(r, &count)) return false;
    if (count > r->length - r->at) return yx_wire_missing(1);
    r->at += (size_t) count;
    return true;
}

/* AhoCorasick is deserialized from its byte slice while bincode walks the
 * fields, before Rules checks its cross-references. Even an empty state
 * vector needs its four-byte length. */
static bool yx_wire_automaton(yx_reader *r)
{
    uint64_t count;
    if (!yx_wire_size(r, &count)) return false;
    if (count > r->length - r->at)
        return yx_wire_missing(count - (r->length - r->at));
    if (count < 4) {
        yx_wire_decode_detail = "OtherString(\"InvalidAutomatonError: invalid serialized automaton\")";
        return false;
    }
    r->at += (size_t)count;
    return true;
}

static bool yx_wire_utf8_error(size_t offset, unsigned error_length)
{
    char error[32];
    if (error_length) snprintf(error, sizeof(error), "Some(%u)", error_length);
    else snprintf(error, sizeof(error), "None");
    snprintf(yx_wire_decode_message, sizeof(yx_wire_decode_message),
        "Utf8 { inner: Utf8Error { valid_up_to: %zu, error_len: %s } }", offset, error);
    yx_wire_decode_detail = yx_wire_decode_message;
    return false;
}

static bool yx_wire_string(yx_reader *r)
{
    uint64_t count;
    if (!yx_wire_size(r, &count)) return false;
    if (count > r->length - r->at) return yx_wire_missing(count - (r->length - r->at));
    const uint8_t *bytes = r->data + r->at;
    size_t length = (size_t)count;
    for (size_t i = 0; i < length;) {
        uint8_t first = bytes[i], low = 0x80, high = 0xbf;
        unsigned width;
        if (first < 0x80) { ++i; continue; }
        if (first >= 0xc2 && first <= 0xdf) width = 2;
        else if (first >= 0xe0 && first <= 0xef) {
            width = 3;
            if (first == 0xe0) low = 0xa0;
            if (first == 0xed) high = 0x9f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            width = 4;
            if (first == 0xf0) low = 0x90;
            if (first == 0xf4) high = 0x8f;
        } else return yx_wire_utf8_error(i, 1);
        for (unsigned j = 1; j < width; ++j) {
            if (j >= length - i) return yx_wire_utf8_error(i, 0);
            uint8_t byte = bytes[i + j];
            if (byte < (j == 1 ? low : 0x80) || byte > (j == 1 ? high : 0xbf))
                return yx_wire_utf8_error(i, j);
        }
        i += width;
    }
    r->at += length;
    return true;
}

static bool yx_wire_bool(yx_reader *r, uint8_t *value)
{
    if (!yx_get_u8(r, value)) return yx_wire_missing(1);
    if (*value <= 1) return true;
    snprintf(yx_wire_decode_message, sizeof(yx_wire_decode_message),
        "InvalidBooleanValue(%u)", (unsigned)*value);
    yx_wire_decode_detail = yx_wire_decode_message;
    return false;
}

static bool yx_wire_option_tag(yx_reader *r, uint8_t *value)
{
    if (!yx_get_u8(r, value)) return yx_wire_missing(1);
    if (*value <= 1) return true;
    snprintf(yx_wire_decode_message, sizeof(yx_wire_decode_message),
        "UnexpectedVariant { type_name: \"Option<T>\", allowed: Range { min: 0, max: 1 }, found: %u }",
        (unsigned)*value);
    yx_wire_decode_detail = yx_wire_decode_message;
    return false;
}

static bool yx_wire_option(yx_reader *r, uint64_t *value)
{
    uint8_t present;
    *value = 0;
    return yx_wire_option_tag(r, &present) &&
        (!present || (yx_wire_uint(r, value, 32) && *value));
}

static bool yx_wire_ids(yx_reader *r)
{
    uint64_t count, value;
    if (!yx_wire_count(r, &count, 1)) return false;
    for (uint64_t i = 0; i < count; ++i)
        if (!yx_wire_uint(r, &value, 32)) return false;
    return true;
}

static bool yx_wire_wasm_name(yx_reader *r)
{
    uint64_t size;
    if (!yx_get_uleb(r, &size) || size > r->length - r->at ||
        !yx_valid_utf8(r->data + r->at, (size_t)size)) return false;
    r->at += (size_t)size;
    return true;
}

static bool yx_wire_wasm_names(yx_reader *r, bool imports)
{
    uint64_t count, index;
    if (!yx_get_uleb(r, &count) || count > r->length - r->at) return false;
    for (uint64_t i = 0; i < count; ++i) {
        uint8_t kind;
        if (!yx_wire_wasm_name(r) || (imports && !yx_wire_wasm_name(r)) ||
            !yx_get_u8(r, &kind)) return false;
        /* The release's v12 imports are functions. Legacy templates also
         * import memories/globals; leave their descriptors to their codecs. */
        if (imports && kind) return true;
        if (!yx_get_uleb(r, &index)) return false;
    }
    return r->at == r->length;
}

static bool yx_wire_wasm_code(yx_reader *r)
{
    uint64_t count;
    if (!yx_get_uleb(r, &count) || count > r->length - r->at) return false;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t length, groups, locals;
        if (!yx_get_uleb(r, &length) || !length || length > r->length - r->at) return false;
        yx_reader body = {r->data + r->at, (size_t)length, 0, false, false};
        if (!yx_get_uleb(&body, &groups) || groups > body.length - body.at) return false;
        for (uint64_t group = 0; group < groups; ++group) {
            uint8_t type;
            if (!yx_get_uleb(&body, &locals) || !yx_get_u8(&body, &type)) return false;
            if (type == 0x63 || type == 0x64) {
                int64_t heap_type;
                if (!yx_get_sleb_i64(&body, &heap_type)) return false;
            } else if (type < 0x68 || type > 0x7f || (type > 0x75 && type < 0x7b)) return false;
        }
        if (body.at >= body.length || body.data[body.length - 1] != 0x0b ||
            body.data[body.at] == 0xf5 || body.data[body.at] == 0xff) return false;
        r->at += (size_t)length;
    }
    return r->at == r->length;
}

static bool yx_wire_wasm(const uint8_t *data, size_t length)
{
    yx_reader r = {data, length, 8, false, false};
    unsigned sections = 0;
    if (length < 8 || memcmp(data, "\0asm\1\0\0\0", 8)) return false;
    while (r.at < r.length) {
        uint8_t id;
        uint64_t size;
        if (!yx_get_u8(&r, &id) || id > 12 ||
            !yx_get_uleb(&r, &size) || size > r.length - r.at)
            return false;
        if (id) {
            if (sections & (1u << id)) return false;
            sections |= 1u << id;
        }
        yx_reader section = {data + r.at, (size_t)size, 0, false, false};
        if ((id == 2 && !yx_wire_wasm_names(&section, true)) ||
            (id == 7 && !yx_wire_wasm_names(&section, false)) ||
            (id == 10 && !yx_wire_wasm_code(&section))) return false;
        r.at += (size_t) size;
    }
    return true;
}

static int yx_ser_validate_v12_uncached(const uint8_t *data, size_t length, size_t *consumed);

/* A load validates its archive several times (the load itself, the decoder
 * cascade, the serialized prefix). The validation is a pure function of the
 * bytes; a valid archive leaves no error detail, only the nonminimal flag.
 * Within yx_ser_validate_memo_begin/end the archive's valid result is kept
 * and returned, with those side effects, for the same bytes. */
static _Thread_local yx_wire_known *yx_wire_known_active;
void yx_ser_validate_memo_begin(yx_wire_known *known, const uint8_t *data, size_t length)
{
    *known = (yx_wire_known){data, length, 0, false, false, yx_wire_known_active};
    yx_wire_known_active = known;
}
void yx_ser_validate_memo_end(yx_wire_known *known)
{
    yx_wire_known_active = known->outer;
}

int yx_ser_validate_v12(const uint8_t *data, size_t length, size_t *consumed)
{
    yx_wire_known *known = yx_wire_known_active;
    if (!known || known->data != data || known->length != length || yx_wire_minimizing)
        return yx_ser_validate_v12_uncached(data, length, consumed);
    if (known->valid) {
        yx_wire_decode_detail = NULL;
        yx_wire_nonminimal = known->nonminimal;
        if (consumed) *consumed = known->consumed;
        return YX_SER_WIRE_VALID;
    }
    size_t end = 0;
    int status = yx_ser_validate_v12_uncached(data, length, &end);
    if (consumed) *consumed = end;
    if (status == YX_SER_WIRE_VALID) {
        known->valid = true;
        known->consumed = end;
        known->nonminimal = yx_wire_nonminimal;
    }
    return status;
}

static int yx_ser_validate_v12_uncached(const uint8_t *data, size_t length, size_t *consumed)
{
    yx_reader r = {data, length, 12, false, false};
    uint64_t count, value, patterns, sub_patterns, max_code = 0;
    size_t wasm_at, wasm_length;
    uint8_t flag;
    bool valid = true, has_code = false;
    yx_wire_decode_detail = NULL;
    yx_wire_nonminimal = false;
    if (consumed) *consumed = 0;
    if (!data || length < 12) return YX_SER_WIRE_DECODE;
    /* Identifier and regexp pools, relaxed syntax, literal pool. */
    for (unsigned pool = 0; pool < 2; ++pool) {
        if (!yx_wire_count(&r, &count, 1)) return YX_SER_WIRE_DECODE;
        for (uint64_t i = 0; i < count; ++i)
            if (!yx_wire_string(&r)) return YX_SER_WIRE_DECODE;
    }
    if (!yx_wire_bool(&r, &flag) || !yx_wire_count(&r, &count, 1))
        return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i)
        if (!yx_wire_bytes(&r)) return YX_SER_WIRE_DECODE;
    if (!yx_wire_size(&r, &value)) return YX_SER_WIRE_DECODE;
    if (value > r.length - r.at) {
        yx_wire_missing(1); return YX_SER_WIRE_DECODE;
    }
    wasm_at = r.at; wasm_length = (size_t) value; r.at += wasm_length;
    if (!yx_wire_option_tag(&r, &flag)) return YX_SER_WIRE_DECODE;
    /* Native-code serialization is not emitted by the pinned release. */
    if (flag) return YX_SER_WIRE_UNKNOWN;
    if (!yx_wire_ids(&r) || !yx_wire_count(&r, &count, 9))
        return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t metadata, rule_patterns;
        for (unsigned j = 0; j < 3; ++j)
            if (!(j ? yx_wire_uint(&r, &value, 32) : yx_wire_i32(&r, &value)))
                return YX_SER_WIRE_DECODE;
        if (!yx_wire_ids(&r) || !yx_wire_count(&r, &metadata, 3))
            return YX_SER_WIRE_DECODE;
        for (uint64_t j = 0; j < metadata; ++j) {
            if (!yx_wire_uint(&r, &value, 32) ||
                !yx_wire_uint(&r, &value, 32) || value > 4)
                return YX_SER_WIRE_DECODE;
            if (value == 0) {
                if (!yx_wire_bool(&r, &flag)) return YX_SER_WIRE_DECODE;
            } else if (value == 2) {
                if (r.length - r.at < 8) {
                    yx_wire_missing(8 - (r.length - r.at)); return YX_SER_WIRE_DECODE;
                }
                r.at += 8;
            } else if (!yx_wire_integer(&r, &value, value == 1 ? 64 : 32,
                    value == 1 ? "I64" : "U32", value == 1)) return YX_SER_WIRE_DECODE;
        }
        if (!yx_wire_count(&r, &rule_patterns, 4)) return YX_SER_WIRE_DECODE;
        for (uint64_t j = 0; j < rule_patterns; ++j) {
            if (!yx_wire_i32(&r, &value) ||
                !yx_wire_uint(&r, &value, 32) ||
                !yx_wire_uint(&r, &value, 32) || value > 2 ||
                !yx_wire_bool(&r, &flag)) return YX_SER_WIRE_DECODE;
        }
        if (!yx_wire_size(&r, &value) || !yx_wire_bool(&r, &flag) ||
            !yx_wire_bool(&r, &flag)) return YX_SER_WIRE_DECODE;
    }
    if (!yx_wire_size(&r, &patterns) || !yx_wire_count(&r, &sub_patterns, 3))
        return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < sub_patterns; ++i) {
        uint64_t kind, id, gap;
        if (!yx_wire_i32(&r, &id) ||
            !yx_wire_uint(&r, &kind, 32) || kind > 11) return YX_SER_WIRE_DECODE;
        valid = valid && !(id & 1) && id / 2 < patterns;
        if ((kind <= 3 || kind >= 7) && !yx_wire_uint(&r, &value, 32))
            return YX_SER_WIRE_DECODE;
        if ((kind == 1 || kind >= 10) && !yx_wire_uint(&r, &value, 32))
            return YX_SER_WIRE_DECODE;
        if (kind == 0) {
            if (!yx_wire_option_tag(&r, &flag) ||
                (flag && !yx_wire_size(&r, &value))) return YX_SER_WIRE_DECODE;
        }
        if (kind == 3 || kind == 6) {
            if (!yx_wire_uint(&r, &value, 32))
                return YX_SER_WIRE_DECODE;
            valid = valid && value < sub_patterns;
            if (!yx_wire_uint(&r, &gap, 32) || gap > 1 ||
                !yx_wire_uint(&r, &value, 32) ||
                (!gap && !yx_wire_uint(&r, &value, 32)))
                return YX_SER_WIRE_DECODE;
        }
        if (kind >= 8) {
            if (!yx_get_u8(&r, &flag)) return YX_SER_WIRE_DECODE;
        } else if (!yx_wire_uint(&r, &value, 16)) return YX_SER_WIRE_DECODE;
    }
    /* Filesize bounds and header constraints. */
    if (!yx_wire_count(&r, &count, 3)) return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i) {
        if (!yx_wire_i32(&r, &value)) return YX_SER_WIRE_DECODE;
        for (unsigned j = 0; j < 2; ++j) {
            if (!yx_wire_uint(&r, &value, 32) || value > 2 ||
                (value && !yx_wire_size(&r, &value))) return YX_SER_WIRE_DECODE;
        }
    }
    if (!yx_wire_count(&r, &count, 2)) return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i) {
        if (!yx_wire_i32(&r, &value) || !yx_wire_uint(&r, &value, 32) ||
            value > 2 || (value == 2 && !yx_wire_sequence_bytes(&r)))
            return YX_SER_WIRE_DECODE;
    }
    if (!yx_wire_count(&r, &count, 1)) return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i) {
        if (!yx_wire_uint(&r, &value, 32))
            return YX_SER_WIRE_DECODE;
        valid = valid && value < sub_patterns;
    }
    if (!yx_wire_count(&r, &count, 6)) return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i) {
        if (!yx_wire_uint(&r, &value, 32))
            return YX_SER_WIRE_DECODE;
        valid = valid && value < sub_patterns;
        if (!yx_wire_sequence_bytes(&r) || !yx_wire_bool(&r, &flag) ||
            !yx_wire_uint(&r, &value, 16))
            return YX_SER_WIRE_DECODE;
        for (unsigned j = 0; j < 2; ++j) {
            if (!yx_wire_option(&r, &value)) return YX_SER_WIRE_DECODE;
            if (value) {
                has_code = true;
                if (value - 1 > max_code) max_code = value - 1;
            }
        }
    }
    if (!yx_wire_size(&r, &value)) return YX_SER_WIRE_DECODE;
    if (value > r.length - r.at) {
        yx_wire_missing(1); return YX_SER_WIRE_DECODE;
    }
    valid = valid && (!has_code || max_code < value);
    r.at += (size_t) value;
    if (!yx_wire_sequence_bytes(&r) || !yx_wire_automaton(&r)) return YX_SER_WIRE_DECODE;
    for (unsigned sets = 0; sets < 2; ++sets) {
        if (!yx_wire_count(&r, &count, 2)) return YX_SER_WIRE_DECODE;
        for (uint64_t i = 0; i < count; ++i)
            if (!yx_wire_i32(&r, &value) || !yx_wire_ids(&r))
                return YX_SER_WIRE_DECODE;
    }
    if (!yx_wire_count(&r, &count, 1)) return YX_SER_WIRE_DECODE;
    for (uint64_t i = 0; i < count; ++i)
        if (!yx_wire_option(&r, &value)) return YX_SER_WIRE_DECODE;
    if (!yx_wire_bool(&r, &flag)) return YX_SER_WIRE_DECODE;
    if (consumed) *consumed = r.at;
    if (flag) return YX_SER_WIRE_WASM;
    if (!yx_wire_wasm(data + wasm_at, wasm_length))
        return YX_SER_WIRE_WASM;
    return valid ? YX_SER_WIRE_VALID : YX_SER_WIRE_BOUNDS;
}
/* Run the typed container walker before replacing legal nonminimal integer
 * markers. Payloads such as WASM, literals and the automaton stay untouched. */
static yx_ser_result yx_wire_normalize_v12(const uint8_t *data,
    size_t length, uint8_t **out, size_t *out_length)
{
    *out = NULL; *out_length = 0;
    if (!yx_wire_nonminimal) return YX_SER_UNSUPPORTED;
    yx_wire_minimal minimal = {.data = data};
    yx_wire_minimal *previous = yx_wire_minimizing;
    yx_wire_minimizing = &minimal;
    int status = yx_ser_validate_v12(data, length, NULL);
    yx_wire_minimizing = previous;
    if (minimal.no_memory) {
        free(minimal.bytes.data);
        return YX_SER_NO_MEMORY;
    }
    if (status != YX_SER_WIRE_VALID || !minimal.copied) {
        free(minimal.bytes.data);
        return YX_SER_UNSUPPORTED;
    }
    if (!yx_put_bytes(&minimal.bytes, data + minimal.copied,
            length - minimal.copied)) {
        free(minimal.bytes.data);
        return YX_SER_NO_MEMORY;
    }
    *out = minimal.bytes.data; *out_length = minimal.bytes.used;
    return YX_SER_SUCCESS;
}
#endif
