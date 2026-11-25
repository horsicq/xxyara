/* JSON syntax diagnostics used by the C API before argument validation.
 * The grammar and byte positions follow serde_json's string deserializer.
 * Semantic conversion remains in the existing global-variable parser. */
#ifndef YX_CAPI_JSON_H
#define YX_CAPI_JSON_H

typedef struct {
    const unsigned char *text;
    size_t length;
    size_t at;
    size_t error_at;
    unsigned int depth;
    const char *error;
} yx_capi_json;

static bool yx_capi_json_fail(yx_capi_json *json, const char *error, bool peek)
{
    json->error = error;
    json->error_at = json->at + (peek && json->at < json->length ? 1 : 0);
    return false;
}

static void yx_capi_json_space(yx_capi_json *json)
{
    while (json->at < json->length) {
        unsigned char c = json->text[json->at];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++json->at;
    }
}

static bool yx_capi_json_hex(yx_capi_json *json, uint16_t *value)
{
    uint16_t result = 0;
    bool valid = true;
    if (json->length - json->at < 4) {
        json->at = json->length;
        return yx_capi_json_fail(json, "EOF while parsing a string", false);
    }
    for (size_t i = 0; i < 4; ++i) {
        unsigned char c = json->text[json->at++];
        unsigned int digit = 0;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else valid = false;
        result = (uint16_t)((result << 4) | digit);
    }
    if (!valid) return yx_capi_json_fail(json, "invalid escape", false);
    *value = result;
    return true;
}

static bool yx_capi_json_string(yx_capi_json *json)
{
    ++json->at;
    while (json->at < json->length) {
        unsigned char c = json->text[json->at++];
        if (c == '"') return true;
        if (c < 0x20) return yx_capi_json_fail(json, "control character (\\u0000-\\u001F) found while parsing a string", false);
        if (c != '\\') continue;
        if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a string", false);
        c = json->text[json->at++];
        if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' || c == 'n' || c == 'r' || c == 't') continue;
        if (c != 'u') return yx_capi_json_fail(json, "invalid escape", false);
        uint16_t value;
        if (!yx_capi_json_hex(json, &value)) return false;
        if (value >= 0xdc00 && value <= 0xdfff) return yx_capi_json_fail(json, "lone leading surrogate in hex escape", false);
        if (value >= 0xd800 && value <= 0xdbff) {
            for (unsigned int i = 0; i < 2; ++i) {
                if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a string", false);
                c = json->text[json->at++];
                if (c != (i == 0 ? '\\' : 'u')) return yx_capi_json_fail(json, "unexpected end of hex escape", false);
            }
            if (!yx_capi_json_hex(json, &value)) return false;
            if (value < 0xdc00 || value > 0xdfff) return yx_capi_json_fail(json, "lone leading surrogate in hex escape", false);
        }
    }
    return yx_capi_json_fail(json, "EOF while parsing a string", false);
}

/* serde_json keeps a u64 significand, discards overflowing digits, and
 * multiplies its rounded f64 by a power of ten. strtod alone differs at the
 * upper f64 boundary, including 1.7976931348623158e308. */
static bool yx_capi_json_number_finite(const unsigned char *text, size_t length)
{
    size_t at = text[0] == '-' ? 1 : 0;
    uint64_t significand = 0;
    int64_t scale = 0;
    bool overflow = false;
    while (at < length && text[at] >= '0' && text[at] <= '9') {
        uint64_t digit = (uint64_t)(text[at++] - '0');
        if (!overflow && significand <= (UINT64_MAX - digit) / 10) significand = significand * 10 + digit;
        else {
            overflow = true;
            ++scale;
        }
    }
    if (at < length && text[at] == '.') {
        ++at;
        overflow = false;
        while (at < length && text[at] >= '0' && text[at] <= '9') {
            uint64_t digit = (uint64_t)(text[at++] - '0');
            if (!overflow && significand <= (UINT64_MAX - digit) / 10) {
                significand = significand * 10 + digit;
                --scale;
            } else overflow = true;
        }
    }
    if (at < length) {
        ++at;
        bool positive = at == length || text[at] != '-';
        if (at < length && (text[at] == '+' || text[at] == '-')) ++at;
        uint32_t exponent = 0;
        while (at < length) {
            uint32_t digit = (uint32_t)(text[at++] - '0');
            if (exponent > ((uint32_t)INT32_MAX - digit) / 10) return !positive || significand == 0;
            exponent = exponent * 10 + digit;
        }
        scale += positive ? (int64_t)exponent : -(int64_t)exponent;
    }
    if (scale <= 0 || significand == 0) return true;
    if (scale > 308) return false;
    char power[32];
    snprintf(power, sizeof(power), "1e%lld", (long long)scale);
    double value = (double)significand * strtod(power, NULL);
    return isfinite(value);
}

static bool yx_capi_json_number(yx_capi_json *json)
{
    size_t start = json->at;
    if (json->text[json->at] == '-') ++json->at;
    if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a value", false);
    unsigned char c = json->text[json->at++];
    if (c < '0' || c > '9') return yx_capi_json_fail(json, "invalid number", false);
    if (c == '0' && json->at < json->length && json->text[json->at] >= '0' && json->text[json->at] <= '9') return yx_capi_json_fail(json, "invalid number", true);
    while (json->at < json->length && json->text[json->at] >= '0' && json->text[json->at] <= '9') ++json->at;
    if (json->at < json->length && json->text[json->at] == '.') {
        ++json->at;
        size_t first = json->at;
        while (json->at < json->length && json->text[json->at] >= '0' && json->text[json->at] <= '9') ++json->at;
        if (first == json->at) return yx_capi_json_fail(json, json->at == json->length ? "EOF while parsing a value" : "invalid number", true);
    }
    if (json->at < json->length && (json->text[json->at] == 'e' || json->text[json->at] == 'E')) {
        bool nonzero = false;
        for (size_t i = start; i < json->at; ++i)
            if (json->text[i] >= '1' && json->text[i] <= '9') nonzero = true;
        ++json->at;
        bool positive = json->at == json->length || json->text[json->at] != '-';
        if (json->at < json->length && (json->text[json->at] == '+' || json->text[json->at] == '-')) ++json->at;
        if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a value", false);
        c = json->text[json->at++];
        if (c < '0' || c > '9') return yx_capi_json_fail(json, "invalid number", false);
        uint32_t exponent = (uint32_t)(c - '0');
        while (json->at < json->length && json->text[json->at] >= '0' && json->text[json->at] <= '9') {
            uint32_t digit = (uint32_t)(json->text[json->at++] - '0');
            if (exponent > ((uint32_t)INT32_MAX - digit) / 10) {
                if (positive && nonzero) return yx_capi_json_fail(json, "number out of range", false);
                while (json->at < json->length && json->text[json->at] >= '0' && json->text[json->at] <= '9') ++json->at;
                break;
            }
            exponent = exponent * 10 + digit;
        }
    }
    if (!yx_capi_json_number_finite(json->text + start, json->at - start)) return yx_capi_json_fail(json, "number out of range", false);
    return true;
}

static bool yx_capi_json_value(yx_capi_json *json);

static bool yx_capi_json_container(yx_capi_json *json, bool object)
{
    unsigned char end = object ? '}' : ']';
    ++json->at;
    if (++json->depth >= 128) return yx_capi_json_fail(json, "recursion limit exceeded", false);
    yx_capi_json_space(json);
    if (json->at < json->length && json->text[json->at] == end) {
        ++json->at;
        --json->depth;
        return true;
    }
    if (json->at == json->length) return yx_capi_json_fail(json, object ? "EOF while parsing an object" : "EOF while parsing a list", false);
    for (;;) {
        if (object) {
            if (json->text[json->at] != '"') return yx_capi_json_fail(json, "key must be a string", true);
            if (!yx_capi_json_string(json)) return false;
            yx_capi_json_space(json);
            if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing an object", false);
            if (json->text[json->at] != ':') return yx_capi_json_fail(json, "expected `:`", true);
            ++json->at;
        }
        if (!yx_capi_json_value(json)) return false;
        yx_capi_json_space(json);
        if (json->at == json->length) return yx_capi_json_fail(json, object ? "EOF while parsing an object" : "EOF while parsing a list", false);
        if (json->text[json->at] == end) {
            ++json->at;
            --json->depth;
            return true;
        }
        if (json->text[json->at] != ',') return yx_capi_json_fail(json, object ? "expected `,` or `}`" : "expected `,` or `]`", true);
        ++json->at;
        yx_capi_json_space(json);
        if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a value", false);
        if (json->text[json->at] == end) return yx_capi_json_fail(json, "trailing comma", true);
    }
}

static bool yx_capi_json_value(yx_capi_json *json)
{
    yx_capi_json_space(json);
    if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a value", false);
    unsigned char c = json->text[json->at];
    if (c == '"') return yx_capi_json_string(json);
    if (c == '{' || c == '[') return yx_capi_json_container(json, c == '{');
    if (c == '-' || (c >= '0' && c <= '9')) return yx_capi_json_number(json);
    const char *literal = c == 'n' ? "null" : c == 't' ? "true" : c == 'f' ? "false" : NULL;
    if (!literal) return yx_capi_json_fail(json, "expected value", true);
    for (size_t i = 0; literal[i]; ++i) {
        if (json->at == json->length) return yx_capi_json_fail(json, "EOF while parsing a value", false);
        if (json->text[json->at++] != (unsigned char)literal[i]) return yx_capi_json_fail(json, "expected ident", false);
    }
    return true;
}

/* The caller already checked the pointer and UTF-8 validity. */
static bool yx_capi_json_validate(const char *text)
{
    yx_capi_json json = {0};
    json.text = (const unsigned char *)text;
    json.length = strlen(text);
    bool valid = yx_capi_json_value(&json);
    if (valid) {
        yx_capi_json_space(&json);
        if (json.at < json.length) valid = yx_capi_json_fail(&json, "trailing characters", true);
    }
    if (valid) return true;
    size_t line = 1, column = 0;
    for (size_t i = 0; i < json.error_at; ++i) {
        if (json.text[i] == '\n') {
            ++line;
            column = 0;
        } else ++column;
    }
    yx_fail_format(YRX_INVALID_ARGUMENT, "%s at line %zu column %zu", json.error, line, column);
    return false;
}

#endif
