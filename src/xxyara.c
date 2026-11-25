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

#ifndef _WIN32
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "internal.h"
#include "xxyara_ext.h"
#include "regex_vm.h"
#include "scan_candidates.h"
#include "warning_suppression.h"
#include "condition.h"
#include "serialization.h"
#include "native_regex.h"
#include "module_cuckoo.h"
#include "module_pe.h"

#include <xxfclib/io/xx_io.h>
#include <xxfclib/json/xx_json.h>
#include <xxfclib/memory/xx_memory.h>
#include <xxfclib/strings/xx_string.h>
#include <xxfclib/threads/xx_parallel.h>
#include <xxfclib/strings/xx_string_casefold.h>
#include <xxfclib/strings/xx_string_uppercase.h>
#include <xxfclib/strings/xx_string_width.h>
#include <xxfclib/algo/protobuf/xx_protobuf_wire.h>

#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "os_error.h"
#if defined(XXYARA_VERIFY_LOAD) && defined(_MSC_VER)
#include <intrin.h>
#endif
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define PCRE2_CODE_UNIT_WIDTH 8
#include "native_regex.h"

/* The public API reports the last error separately for each calling thread. */
static _Thread_local char *yx_last_error_message;
#ifdef _WIN32
/* Use an OS-thread detach callback: fiber-local destructors are unsuitable
 * for the thread-local error slot when a host switches Windows fibers. */
static void NTAPI yx_last_error_thread_destroy(PVOID module, DWORD reason, PVOID reserved)
{
    (void)module;
    (void)reserved;
    if (reason == DLL_THREAD_DETACH || reason == DLL_PROCESS_DETACH) {
        free(yx_last_error_message);
        yx_last_error_message = NULL;
    }
}
#ifdef _MSC_VER
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK yx_last_error_tls_callback = yx_last_error_thread_destroy;
#ifdef _WIN64
#pragma comment(linker, "/include:yx_last_error_tls_callback")
#else
#pragma comment(linker, "/include:_yx_last_error_tls_callback")
#endif
#else
PIMAGE_TLS_CALLBACK yx_last_error_tls_callback __attribute__((section(".CRT$XLB"), used)) = yx_last_error_thread_destroy;
#endif
#else
static pthread_once_t yx_last_error_once = PTHREAD_ONCE_INIT;
static pthread_key_t yx_last_error_slot;
static bool yx_last_error_slot_valid;

static void yx_last_error_initialize(void)
{
    yx_last_error_slot_valid = pthread_key_create(&yx_last_error_slot, free) == 0;
}
#endif

static void yx_set_last_error_message(char *message)
{
    if (!message && !yx_last_error_message) return;
#ifndef _WIN32
    pthread_once(&yx_last_error_once, yx_last_error_initialize);
    if (yx_last_error_slot_valid) pthread_setspecific(yx_last_error_slot, message);
#endif
    free(yx_last_error_message);
    yx_last_error_message = message;
}
/* Native module function caches belong to the calling thread and survive
 * scanner destruction. Only that module's native execution resets them. */
static _Thread_local yx_mo_function_cache yx_module_function_cache[YX_MO_FUNCTION_CACHE_COUNT];
/* The public C API distinguishes its implicit `line` origin from an explicit
 * caller-supplied origin with the same spelling. */
static _Thread_local bool yx_explicit_line_origin;

static YRX_RESULT yx_ok(void)
{
    yx_set_last_error_message(NULL);
    return YRX_SUCCESS;
}

static YRX_RESULT yx_fail(YRX_RESULT result, const char *message)
{
    const char *text = message ? message : "xxyara operation failed";
    size_t length = strlen(text);
    char *copy = (char *)malloc(length + 1);
    if (copy) memcpy(copy, text, length + 1);
    yx_set_last_error_message(copy);
    return result;
}

static YRX_RESULT yx_fail_format(YRX_RESULT result, const char *format, ...)
{
    va_list args, copy;
    int length;
    char *message;
    va_start(args, format);
    va_copy(copy, args);
    length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    message = length >= 0 ? (char *)malloc((size_t)length + 1) : NULL;
    if (message) vsnprintf(message, (size_t)length + 1, format, args);
    va_end(args);
    result = yx_fail(result, message ? message : "out of memory");
    free(message);
    return result;
}

static YRX_RESULT yx_null_argument(const char *name)
{
    return yx_fail_format(YRX_INVALID_ARGUMENT, "`%s` pointer cannot be null", name);
}

#include "capi_json.h"

/* Titles and labels that quote an identifier, a pattern or a module name:
 * room for names up to 4095 bytes (YARA-X has no length limit). */
#define YX_DIAG_NAME_TEXT_SIZE 4352

static YRX_RESULT yx_unsupported(const char *feature)
{
    return yx_fail_format(YRX_NOT_SUPPORTED, "%s is not implemented", feature);
}

static uint64_t yx_monotonic_now_ns(void)
{
#ifdef _WIN32
    return GetTickCount64() * UINT64_C(1000000);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
#endif
}

static void yx_scan_deadline_start(YRX_SCANNER *scanner)
{
    yx_scan_deadline *deadline = &scanner->deadline;
    uint64_t now = yx_monotonic_now_ns();
    uint64_t seconds = scanner->timeout_seconds;
    yx_pe_scan_cache_destroy(deadline->pe_cache);
    *deadline = (yx_scan_deadline){0};
    deadline->enabled = scanner->timeout_configured;
    /* The reference caps very large timeout values at 315360000 seconds. */
    if (seconds > UINT64_C(315360000)) seconds = UINT64_C(315360000);
    uint64_t duration = seconds * UINT64_C(1000000000);
    deadline->expires_ns = duration > UINT64_MAX - now ? UINT64_MAX : now + duration;
}

bool yx_scan_deadline_reached(yx_scan_deadline *deadline)
{
    if (!deadline || !deadline->enabled) return false;
    if (!deadline->expired) deadline->expired = yx_monotonic_now_ns() >= deadline->expires_ns;
    return deadline->expired;
}

bool yx_scan_deadline_poll_clock(yx_scan_deadline *deadline)
{
    deadline->polls = 0;
    return yx_scan_deadline_reached(deadline);
}

#ifdef XXYARA_ENABLE_PROFILING
/* Profiling measures elapsed time and must ignore wall-clock adjustments. */
static uint64_t yx_profile_now_ns(void)
{
#ifdef _WIN32
    /* YARA-X times rules with std::time::Instant, QueryPerformanceCounter on
     * Windows; GetTickCount64's ~16 ms steps would read most pattern
     * matching as zero. */
    LARGE_INTEGER frequency, counter;
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0 && QueryPerformanceCounter(&counter) && counter.QuadPart >= 0) {
        uint64_t ticks = (uint64_t)counter.QuadPart;
        uint64_t rate = (uint64_t)frequency.QuadPart;
        return ticks / rate * UINT64_C(1000000000) + ticks % rate * UINT64_C(1000000000) / rate;
    }
#endif
    return yx_monotonic_now_ns();
}

static void yx_profile_add_elapsed(uint64_t *total, uint64_t started)
{
    uint64_t finished;
    uint64_t elapsed;
    if (!started) return;
    finished = yx_profile_now_ns();
    if (finished <= started) return;
    elapsed = finished - started;
    *total = elapsed > UINT64_MAX - *total ? UINT64_MAX : *total + elapsed;
}

/* Candidate verifications are often shorter than one QueryPerformanceCounter
 * tick; YARA-X's nanosecond clock never reads them as zero. */
static void yx_profile_add_verification(uint64_t *total, uint64_t started)
{
    uint64_t finished = yx_profile_now_ns();
    uint64_t elapsed = finished > started ? finished - started : 1;
    *total = elapsed > UINT64_MAX - *total ? UINT64_MAX : *total + elapsed;
}

static uint64_t yx_profile_total_ns(const yx_rule_profile *profile)
{
    if (profile->pattern_nanoseconds > UINT64_MAX - profile->condition_nanoseconds) return UINT64_MAX;
    return profile->pattern_nanoseconds + profile->condition_nanoseconds;
}
#endif

static YRX_RESULT yx_buffer_from_text(const char *text, size_t length, YRX_BUFFER **out)
{
    YRX_BUFFER *buffer;
    uint8_t *data;
    if (length == SIZE_MAX) return yx_fail(YRX_SERIALIZATION_ERROR, "JSON output is too large");
    buffer = (YRX_BUFFER *)malloc(sizeof(*buffer));
    data = (uint8_t *)malloc(length + 1);
    if (!buffer || !data) {
        free(buffer);
        free(data);
        return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory building JSON");
    }
    memcpy(data, text, length);
    data[length] = '\0';
    buffer->data = data;
    buffer->length = length;
    *out = buffer;
    return yx_ok();
}

/* yx_buffer_from_text for a malloc'd text of `length` bytes (NUL at
 * `length`) that the buffer takes: freed here on failure. */
static YRX_RESULT yx_buffer_adopt_text(char *text, size_t length, YRX_BUFFER **out)
{
    YRX_BUFFER *buffer = (YRX_BUFFER *)malloc(sizeof(*buffer));
    if (!buffer) {
        free(text);
        return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory building JSON");
    }
    buffer->data = (uint8_t *)text;
    buffer->length = length;
    *out = buffer;
    return yx_ok();
}

static YRX_RESULT yx_error_json(const char *message, YRX_BUFFER **out)
{
    static const char prefix[] = "[{\"type\":\"SyntaxError\",\"code\":\"E001\",\"title\":\"syntax error\",\"labels\":[],\"text\":\"";
    static const char suffix[] = "\"}]";
    static const char hex[] = "0123456789abcdef";
    size_t message_length, capacity, used;
    char *json;
    const unsigned char *cursor;
    YRX_RESULT result;
    if (!message || !*message) return yx_buffer_from_text("[]", 2, out);
    message_length = strlen(message);
    if (message_length > (SIZE_MAX - sizeof(prefix) - sizeof(suffix)) / 6) return yx_fail(YRX_SERIALIZATION_ERROR, "JSON output is too large");
    capacity = sizeof(prefix) + sizeof(suffix) + message_length * 6;
    json = (char *)malloc(capacity);
    if (!json) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory building JSON");
    used = sizeof(prefix) - 1;
    memcpy(json, prefix, used);
    for (cursor = (const unsigned char *)message; *cursor; ++cursor) {
        unsigned char byte = *cursor;
        if (byte == '"' || byte == '\\') {
            json[used++] = '\\';
            json[used++] = (char)byte;
        } else if (byte < 0x20) {
            json[used++] = '\\';
            json[used++] = 'u';
            json[used++] = '0';
            json[used++] = '0';
            json[used++] = hex[byte >> 4];
            json[used++] = hex[byte & 15];
        } else {
            json[used++] = (char)byte;
        }
    }
    memcpy(json + used, suffix, sizeof(suffix));
    used += sizeof(suffix) - 1;
    result = yx_buffer_from_text(json, used, out);
    free(json);
    return result;
}

static char *yx_strdup(const char *source)
{
    size_t length;
    char *copy;
    if (!source) return NULL;
    length = strlen(source);
    if (length == SIZE_MAX) return NULL;
    copy = (char *)malloc(length + 1);
    if (copy) memcpy(copy, source, length + 1);
    return copy;
}

static char *yx_copy_string_bytes(const char *source, size_t length)
{
    char *copy;
    if (!source || length == SIZE_MAX) return NULL;
    copy = (char *)malloc(length + 1);
    if (!copy) return NULL;
    memcpy(copy, source, length);
    copy[length] = '\0';
    return copy;
}

static bool yx_valid_utf8_bytes(const char *text, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)text;
    size_t at = 0;
    if (!text) return false;
    while (at < length) {
        unsigned char first = bytes[at];
        size_t continuation;
        if (first < 0x80) {
            ++at;
            continue;
        }
        if (first >= 0xc2 && first <= 0xdf) continuation = 1;
        else if (first >= 0xe0 && first <= 0xef) continuation = 2;
        else if (first >= 0xf0 && first <= 0xf4) continuation = 3;
        else return false;
        if (continuation > length - at - 1) return false;
        for (size_t i = 1; i <= continuation; ++i) {
            if ((bytes[at + i] & 0xc0) != 0x80) return false;
        }
        if ((first == 0xe0 && bytes[at + 1] < 0xa0) || (first == 0xed && bytes[at + 1] >= 0xa0) || (first == 0xf0 && bytes[at + 1] < 0x90) ||
            (first == 0xf4 && bytes[at + 1] >= 0x90))
            return false;
        at += continuation + 1;
    }
    return true;
}

static bool yx_valid_utf8(const char *text)
{
    return text && yx_valid_utf8_bytes(text, strlen(text));
}

/* Match the byte-oriented UTF-8 failure text returned by scanner setters. */
static YRX_RESULT yx_invalid_utf8(const char *text, size_t length, YRX_RESULT result)
{
    const unsigned char *bytes = (const unsigned char *)text;
    size_t at = 0;
    while (at < length) {
        unsigned char lead = bytes[at];
        size_t width, valid = 1;
        char message[128];
        if (lead < 0x80) {
            ++at;
            continue;
        }
        if (lead >= 0xc2 && lead <= 0xdf) width = 2;
        else if (lead >= 0xe0 && lead <= 0xef) width = 3;
        else if (lead >= 0xf0 && lead <= 0xf4) width = 4;
        else width = 0;
        if (!width) {
            snprintf(message, sizeof(message), "invalid utf-8 sequence of 1 bytes from index %zu", at);
            return yx_fail(result, message);
        }
        for (size_t i = 1; i < width; ++i) {
            unsigned char next;
            if (at + i >= length) {
                snprintf(message, sizeof(message), "incomplete utf-8 byte sequence from index %zu", at);
                return yx_fail(result, message);
            }
            next = bytes[at + i];
            if ((next & 0xc0) != 0x80 ||
                (i == 1 && ((lead == 0xe0 && next < 0xa0) || (lead == 0xed && next >= 0xa0) || (lead == 0xf0 && next < 0x90) || (lead == 0xf4 && next >= 0x90)))) {
                snprintf(message, sizeof(message), "invalid utf-8 sequence of %zu bytes from index %zu", valid, at);
                return yx_fail(result, message);
            }
            ++valid;
        }
        at += width;
    }
    return yx_ok();
}

static YRX_RESULT yx_scanner_invalid_utf8(const char *text, size_t length)
{
    return yx_invalid_utf8(text, length, YRX_INVALID_UTF8);
}

static YRX_RESULT yx_compiler_invalid_utf8(const char *text)
{
    return yx_invalid_utf8(text, strlen(text), YRX_INVALID_ARGUMENT);
}

static bool yx_valid_global_name(const char *name)
{
    const unsigned char *at = (const unsigned char *)name;
    if (!((*at >= 'a' && *at <= 'z') || (*at >= 'A' && *at <= 'Z') || *at == '_')) return false;
    for (++at; *at; ++at)
        if (!((*at >= 'a' && *at <= 'z') || (*at >= 'A' && *at <= 'Z') || (*at >= '0' && *at <= '9') || *at == '_')) return false;
    return true;
}

/* JSON object keys become struct fields. YARA-X accepts Unicode Alphabetic
 * code points initially and Unicode Alphabetic/Numeric code points after the
 * first. The public rule tokenizer currently accepts fewer of these names;
 * validating a JSON key and parsing a field reference are separate steps. */
static bool yx_valid_json_field_name(const char *name)
{
    static const char pattern[] = "\\A(?:_|\\p{Alphabetic})(?:_|\\p{Alphabetic}|\\p{N})*\\z";
    const unsigned char *at;
    pcre2_code *compiled;
    pcre2_match_data *matches;
    PCRE2_SIZE error_offset = 0;
    int error_code = 0;
    int matched;
    if (!name || !yx_valid_utf8(name)) return false;
    for (at = (const unsigned char *)name; *at; ++at)
        if (*at >= 0x80) break;
    if (!*at) return yx_valid_global_name(name);
    compiled = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, PCRE2_UTF | PCRE2_UCP, &error_code, &error_offset, NULL);
    if (!compiled) return false;
    matches = pcre2_match_data_create_from_pattern(compiled, NULL);
    if (!matches) {
        pcre2_code_free(compiled);
        return false;
    }
    matched = pcre2_match(compiled, (PCRE2_SPTR)name, strlen(name), 0, 0, matches, NULL);
    pcre2_match_data_free(matches);
    pcre2_code_free(compiled);
    return matched >= 0;
}

static char *yx_json_quoted(const char *value)
{
    static const char hex[] = "0123456789abcdef";
    size_t length, used = 0;
    char *quoted;
    const unsigned char *at;
    if (!value) return NULL;
    length = strlen(value);
    if (length > (SIZE_MAX - 3) / 6) return NULL;
    quoted = (char *)malloc(length * 6 + 3);
    if (!quoted) return NULL;
    quoted[used++] = '"';
    for (at = (const unsigned char *)value; *at; ++at) {
        if (*at == '"' || *at == '\\') {
            quoted[used++] = '\\';
            quoted[used++] = (char)*at;
        } else if (*at == '\n' || *at == '\r' || *at == '\t' || *at == '\b' || *at == '\f') {
            quoted[used++] = '\\';
            quoted[used++] = *at == '\n' ? 'n' : *at == '\r' ? 'r' : *at == '\t' ? 't' : *at == '\b' ? 'b' : 'f';
        } else if (*at < 0x20) {
            quoted[used++] = '\\';
            quoted[used++] = 'u';
            quoted[used++] = '0';
            quoted[used++] = '0';
            quoted[used++] = hex[*at >> 4];
            quoted[used++] = hex[*at & 15];
        } else {
            quoted[used++] = (char)*at;
        }
    }
    quoted[used++] = '"';
    quoted[used] = '\0';
    return quoted;
}

static char *yx_json_quoted_code_origin(const char *origin)
{
    if (!origin || (strcmp(origin, "line") == 0 && !yx_explicit_line_origin)) return yx_strdup("null");
    return yx_json_quoted(origin);
}

static bool yx_diagnostic_append(char **buffer, size_t *used, size_t *capacity, const char *format, ...)
{
    va_list args;
    int needed;
    char *grown;
    size_t target;
    va_start(args, format);
    needed = vsnprintf(NULL, 0, format, args);
    va_end(args);
    if (needed < 0 || (size_t)needed > SIZE_MAX - *used - 1) return false;
    target = *used + (size_t)needed + 1;
    if (target > *capacity) {
        size_t next = *capacity ? *capacity : 256;
        while (next < target) {
            if (next > SIZE_MAX / 2) {
                next = target;
                break;
            }
            next *= 2;
        }
        grown = (char *)realloc(*buffer, next);
        if (!grown) return false;
        *buffer = grown;
        *capacity = next;
    }
    va_start(args, format);
    vsnprintf(*buffer + *used, *capacity - *used, format, args);
    va_end(args);
    *used += (size_t)needed;
    return true;
}

/* A CR immediately before LF belongs to the line ending and is not drawn in
 * a source excerpt. A bare CR at EOF remains part of the source line. */
static const char *yx_diagnostic_display_line_end(const char *start, const char *end)
{
    return end > start && *end == '\n' && end[-1] == '\r' ? end - 1 : end;
}

static char *yx_diagnostic_visible_cr(const char *source, size_t length)
{
    char *rendered;
    size_t used = 0;
    if (length > (SIZE_MAX - 1) / 3) return NULL;
    rendered = (char *)malloc(length * 3 + 1);
    if (!rendered) return NULL;
    for (size_t at = 0; at < length; ++at) {
        if (source[at] == '\r') {
            memcpy(rendered + used, "\xe2\x90\x8d", 3);
            used += 3;
        } else {
            rendered[used++] = source[at];
        }
    }
    rendered[used] = '\0';
    return rendered;
}

static bool yx_diagnostic_normalize_visible_cr(char **text)
{
    char *rendered;
    if (!text || !*text) return false;
    if (!strchr(*text, '\r')) return true;
    rendered = yx_diagnostic_visible_cr(*text, strlen(*text));
    if (!rendered) return false;
    free(*text);
    *text = rendered;
    return true;
}

static char *yx_diagnostic_snippet_one(const char *level, const char *code, const char *title, const char *source, const char *origin, size_t start, size_t end,
                                       const char *label, bool primary, size_t line, size_t column);

/* A label spanning lines, drawn by the shared snippet renderer. A bare CR
 * shows as a control picture; the note follows the snippet. */
static char *yx_diagnostic_multiline(const char *level, const char *code, const char *title, const char *label, const char *source, const char *origin, size_t start,
                                     size_t end, size_t first_line, size_t column, const char *first_line_start, const char *note)
{
    size_t last_line = first_line, digits = 1, used, capacity;
    /* An error's label is its primary annotation (`^`); a warning's is
     * secondary (`-`). */
    char *result = yx_diagnostic_snippet_one(level, code, title, source, origin, start, end, label, strcmp(level, "error") == 0, first_line, column);
    (void)first_line_start;
    if (!result) return NULL;
    if (strchr(result, '\r')) {
        char *visible = yx_diagnostic_visible_cr(result, strlen(result));
        free(result);
        if (!visible) return NULL;
        result = visible;
    }
    if (!note) return result;
    /* A span ending just after a line break ends on that break's line. */
    for (const char *cursor = source + start; cursor + 1 < source + end; ++cursor)
        if (*cursor == '\n') ++last_line;
    for (size_t n = last_line; n >= 10; n /= 10) ++digits;
    used = strlen(result);
    capacity = used + 1;
    if (!yx_diagnostic_append(&result, &used, &capacity, "\n%*s|\n%*s= note: %s", (int)digits + 1, "", (int)digits + 1, "", note)) {
        free(result);
        return NULL;
    }
    return result;
}

/* Eight bytes from `at` (any alignment). */
static uint64_t yx_diagnostic_word(const unsigned char *at)
{
    uint64_t word;
    memcpy(&word, at, sizeof(word));
    return word;
}

/* Whether all eight bytes of a word are printable ASCII (0x20..0x7e), which
 * take one column and one display cell each. */
static bool yx_diagnostic_printable_word(uint64_t word)
{
    const uint64_t ones = 0x0101010101010101ull, highs = 0x8080808080808080ull;
    uint64_t del = word ^ (ones * 0x7f);
    return !(word & highs) &&                         /* no byte >= 0x80 */
           !((word - ones * 0x20) & ~word & highs) && /* no byte < 0x20 */
           !((del - ones) & ~del & highs);            /* no 0x7f */
}

static size_t yx_diagnostic_columns(const char *start, const char *end)
{
    size_t columns = 0;
    const unsigned char *at = (const unsigned char *)start;
    const unsigned char *limit = (const unsigned char *)end;
    /* Long lines of ASCII (one rule on one line) eight bytes at a time. */
    while (limit - at >= 8 && !(yx_diagnostic_word(at) & 0x8080808080808080ull)) {
        columns += 8;
        at += 8;
    }
    for (; at < limit; ++at)
        if ((*at & 0xc0) != 0x80) ++columns;
    return columns;
}

static unsigned yx_diagnostic_scalar_width(uint32_t scalar)
{
    /* The diagnostic renderer substitutes a visible replacement character
       for bidirectional controls before measuring their terminal width. */
    if ((scalar >= 0x202a && scalar <= 0x202e) || (scalar >= 0x2066 && scalar <= 0x2069)) return 1;
    return xx_string_scalar_display_width(scalar);
}

/* Diagnostic JSON columns count Unicode scalars. The rendered underline and
 * its indentation use terminal cells, including zero- and two-cell scalars. */
static size_t yx_diagnostic_display_width(const char *start, const char *end)
{
    const unsigned char *at = (const unsigned char *)start;
    const unsigned char *limit = (const unsigned char *)end;
    size_t cells = 0;
    while (at < limit) {
        uint32_t scalar = *at;
        size_t length = 1;
        /* Printable ASCII takes one cell, eight bytes at a time. */
        if (limit - at >= 8 && yx_diagnostic_printable_word(yx_diagnostic_word(at))) {
            cells += 8;
            at += 8;
            continue;
        }
        if (scalar >= 0x20 && scalar < 0x7f) {
            ++cells;
            ++at;
            continue;
        }
        if (scalar >= 0xc2 && scalar <= 0xdf && limit - at >= 2 && (at[1] & 0xc0) == 0x80) {
            scalar = ((scalar & 0x1f) << 6) | (at[1] & 0x3f);
            length = 2;
        } else if (scalar >= 0xe0 && scalar <= 0xef && limit - at >= 3 && (at[1] & 0xc0) == 0x80 && (at[2] & 0xc0) == 0x80) {
            scalar = ((scalar & 0x0f) << 12) | ((at[1] & 0x3f) << 6) | (at[2] & 0x3f);
            length = 3;
        } else if (scalar >= 0xf0 && scalar <= 0xf4 && limit - at >= 4 && (at[1] & 0xc0) == 0x80 && (at[2] & 0xc0) == 0x80 && (at[3] & 0xc0) == 0x80) {
            scalar = ((scalar & 0x07) << 18) | ((at[1] & 0x3f) << 12) | ((at[2] & 0x3f) << 6) | (at[3] & 0x3f);
            length = 4;
        }
        cells += yx_diagnostic_scalar_width(scalar);
        at += length;
    }
    return cells;
}

/* Match annotate-snippets' visible control pictures, invisible joiner and
 * bidi replacements in rendered headers and source excerpts. Diagnostic
 * labels and JSON titles retain the original source text. The replacement
 * mapping is used under its MIT terms in LICENSE.ANNOTATE-SNIPPETS. */
static char *yx_diagnostic_render_fragment(const char *source, size_t length)
{
    char *result;
    size_t used = 0;
    if (length > (SIZE_MAX - 1) / 4) return NULL;
    result = (char *)malloc(length * 4 + 1);
    if (!result) return NULL;
    for (size_t at = 0; at < length;) {
        const unsigned char *bytes = (const unsigned char *)source + at;
        if (bytes[0] == '\t') {
            memcpy(result + used, "    ", 4);
            used += 4;
            ++at;
            continue;
        }
        if ((bytes[0] < 0x20 && bytes[0] != '\n' && bytes[0] != '\t') || bytes[0] == 0x7f) {
            result[used++] = (char)0xe2;
            result[used++] = (char)0x90;
            result[used++] = (char)(bytes[0] == 0x7f ? 0xa1 : 0x80 + bytes[0]);
            ++at;
            continue;
        }
        if (length - at >= 3 && bytes[0] == 0xe2 && bytes[1] == 0x80 && bytes[2] == 0x8d) {
            at += 3;
            continue;
        }
        if (length - at >= 3 && bytes[0] == 0xe2 &&
            ((bytes[1] == 0x80 && bytes[2] >= 0xaa && bytes[2] <= 0xae) || (bytes[1] == 0x81 && bytes[2] >= 0xa6 && bytes[2] <= 0xa9))) {
            memcpy(result + used, "\xef\xbf\xbd", 3);
            used += 3;
            at += 3;
            continue;
        }
        result[used++] = source[at++];
    }
    result[used] = '\0';
    return result;
}

static void yx_note_patch(YRX_COMPILER *compiler, const char *text, size_t column, size_t removed, size_t added);

/* The byte length of the UTF-8 scalar at `at` (1 for an invalid byte), as
 * yx_diagnostic_display_width decodes it. */
static size_t yx_diagnostic_scalar_length(const char *at, const char *limit)
{
    const unsigned char *s = (const unsigned char *)at;
    size_t available = (size_t)(limit - at);
    if (s[0] >= 0xc2 && s[0] <= 0xdf && available >= 2 && (s[1] & 0xc0) == 0x80) return 2;
    if (s[0] >= 0xe0 && s[0] <= 0xef && available >= 3 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80) return 3;
    if (s[0] >= 0xf0 && s[0] <= 0xf4 && available >= 4 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80 && (s[3] & 0xc0) == 0x80) return 4;
    return 1;
}

/* Moves forward from `at` over at least `cells` display cells. */
static const char *yx_diagnostic_skip_cells(const char *at, const char *limit, size_t cells)
{
    size_t taken = 0;
    while (at < limit && taken < cells) {
        size_t length = yx_diagnostic_scalar_length(at, limit);
        taken += yx_diagnostic_display_width(at, at + length);
        at += length;
    }
    return at;
}

/* Moves backward from `at` over at least `cells` display cells. */
static const char *yx_diagnostic_back_cells(const char *base, const char *at, size_t cells)
{
    size_t taken = 0;
    while (at > base && taken < cells) {
        const char *previous = at - 1;
        while (previous > base && ((unsigned char)*previous & 0xc0) == 0x80 && at - previous < 4) --previous;
        if (previous + yx_diagnostic_scalar_length(previous, at) != at) previous = at - 1;
        taken += yx_diagnostic_display_width(previous, at);
        at = previous;
    }
    return at;
}

/* annotate-snippets elides the middle of an annotation wider than 272
 * cells: the excerpt keeps six cells on each side of the span (the outer
 * three become "..." where the line continues) and 45 cells at each end of
 * the span, joined by "...". The markers below are drawn the same way.
 * Returns the excerpt and the span's 1-based display column in it. */
static char *yx_diagnostic_elide_span(const char *line, size_t line_length, size_t span_start, size_t span_end, size_t *marker_column)
{
    const char *limit = line + line_length, *start = line + span_start;
    const char *end = line + span_end, *left, *head, *tail, *right;
    const char *right_stop;
    size_t used = 0, size;
    bool left_cut, right_cut;
    char *excerpt;
    left = yx_diagnostic_back_cells(line, start, 6);
    left_cut = left > line;
    if (left_cut) left = yx_diagnostic_skip_cells(left, start, 3);
    head = yx_diagnostic_skip_cells(start, end, 45);
    tail = yx_diagnostic_back_cells(head, end, 45);
    right = yx_diagnostic_skip_cells(end, limit, 6);
    right_cut = right < limit;
    right_stop = right_cut ? yx_diagnostic_back_cells(end, right, 3) : limit;
    size = (size_t)(start - left) + (size_t)(head - start) + (size_t)(end - tail) + (size_t)(right_stop - end) + 10;
    excerpt = (char *)malloc(size);
    if (!excerpt) return NULL;
    if (left_cut) {
        memcpy(excerpt, "...", 3);
        used = 3;
    }
    memcpy(excerpt + used, left, (size_t)(start - left));
    used += (size_t)(start - left);
    *marker_column = (left_cut ? 3 : 0) + yx_diagnostic_display_width(left, start) + 1;
    memcpy(excerpt + used, start, (size_t)(head - start));
    used += (size_t)(head - start);
    memcpy(excerpt + used, "...", 3);
    used += 3;
    memcpy(excerpt + used, tail, (size_t)(end - tail));
    used += (size_t)(end - tail);
    memcpy(excerpt + used, end, (size_t)(right_stop - end));
    used += (size_t)(right_stop - end);
    if (right_cut) {
        memcpy(excerpt + used, "...", 3);
        used += 3;
    }
    excerpt[used] = '\0';
    return excerpt;
}

/* Sources added through the bytes API or read from include files have their
 * NUL bytes escaped before parsing, because the parser works on C strings:
 * a bare NUL and a backslash-NUL inside a regexp become the text "\x00", and
 * a backslash-NUL inside a quoted string becomes "\" plus U+2400. Each escape
 * is recorded so diagnostics keep the reference engine's coordinates. The
 * rendered text uses a display copy where every NUL is one U+2400 scalar,
 * and JSON spans count the original bytes.
 *
 * The registry belongs to the compiler: each source being parsed links one
 * entry, owned by the function that parses it, in front of the entries of
 * the sources that include it. Compilers on different threads never share
 * it, and include nesting has no limit. */
enum {
    YX_NUL_BARE,          /* NUL -> "\x00"; display U+2400 */
    YX_NUL_REGEXP_ESCAPE, /* backslash NUL -> "\x00"; display "\" U+2400 */
    YX_NUL_STRING_ESCAPE  /* backslash NUL -> "\" U+2400; display the same */
};

enum {
    YX_NUL_SPACE_ESCAPED,
    YX_NUL_SPACE_DISPLAY,
    YX_NUL_SPACE_ORIGINAL
};

typedef struct {
    size_t offset; /* of the escape in the escaped source */
    unsigned char kind;
} yx_nul_escape;

struct yx_nul_escape_entry {
    const char *source; /* the escaped source being parsed */
    yx_nul_escape *escapes;
    size_t count;
    char *display; /* display copy, built on first use */
    yx_nul_escape_entry *parent;
};

/* Byte length of each escape kind in the escaped, display and original
 * coordinate spaces. Every escape is 4 bytes in the escaped source; the
 * backslash of a backslash-NUL is the same byte in every space. */
static const unsigned char yx_nul_escape_lengths[3][3] = {{4, 3, 1}, {4, 4, 2}, {4, 4, 2}};

static void yx_nul_escape_register(YRX_COMPILER *compiler, yx_nul_escape_entry *entry, const char *source, yx_nul_escape *escapes, size_t count)
{
    entry->source = source;
    entry->escapes = escapes;
    entry->count = count;
    entry->display = NULL;
    entry->parent = compiler->nul_escapes;
    compiler->nul_escapes = entry;
}

static void yx_nul_escape_unregister(YRX_COMPILER *compiler, yx_nul_escape_entry *entry)
{
    compiler->nul_escapes = entry->parent;
    free(entry->escapes);
    free(entry->display);
}

static yx_nul_escape_entry *yx_nul_escape_find(const YRX_COMPILER *compiler, const char *source)
{
    yx_nul_escape_entry *entry = compiler ? compiler->nul_escapes : NULL;
    if (!source) return NULL;
    for (; entry; entry = entry->parent)
        if (entry->source == source) return entry->count ? entry : NULL;
    return NULL;
}

/* Maps a byte offset between coordinate spaces. A position inside the NUL
 * of an escape snaps to the NUL's start (end positions: to its end). */
static size_t yx_nul_escape_map(const yx_nul_escape_entry *entry, size_t pos, int from, int to, bool snap_end)
{
    size_t from_shift = 0, to_shift = 0;
    for (size_t k = 0; k < entry->count; ++k) {
        const yx_nul_escape *escape = &entry->escapes[k];
        size_t from_length = yx_nul_escape_lengths[escape->kind][from];
        size_t to_length = yx_nul_escape_lengths[escape->kind][to];
        size_t prefix = escape->kind != YX_NUL_BARE;
        size_t from_at = escape->offset - from_shift;
        size_t to_at = escape->offset - to_shift;
        if (pos < from_at + from_length) {
            if (pos <= from_at) break;
            pos -= from_at;
            if (pos <= prefix) return to_at + pos;
            return snap_end ? to_at + to_length : to_at + prefix;
        }
        from_shift += 4 - from_length;
        to_shift += 4 - to_length;
    }
    return pos + from_shift - to_shift;
}

/* The display copy of the source: each escaped NUL is U+2400, after its
 * backslash when it had one. Built once per source, on first use. */
static const char *yx_nul_escape_display(yx_nul_escape_entry *entry)
{
    size_t length, used = 0, at = 0, k = 0;
    char *copy;
    if (entry->display) return entry->display;
    length = strlen(entry->source);
    copy = (char *)malloc(length + 1);
    if (!copy) return NULL;
    while (at < length) {
        if (k < entry->count && at == entry->escapes[k].offset) {
            if (entry->escapes[k].kind != YX_NUL_BARE) copy[used++] = '\\';
            memcpy(copy + used, "\xe2\x90\x80", 3);
            used += 3;
            at += 4;
            ++k;
        } else {
            copy[used++] = entry->source[at++];
        }
    }
    copy[used] = '\0';
    entry->display = copy;
    return copy;
}

static size_t yx_nul_escape_json_number(const char **at)
{
    size_t value = 0;
    while (**at >= '0' && **at <= '9') value = value * 10 + (size_t)(*(*at)++ - '0');
    return value;
}

/* Rewrites one diagnostic JSON object built in `space` coordinates into
 * YARA-X's: spans count the original bytes and columns count characters,
 * each NUL being one. Labels are rewritten in place; the report's own line
 * and column follow the label they were taken from. For
 * YX_NUL_SPACE_ORIGINAL, spans only move back by `shift` bytes. */
static char *yx_nul_escape_rewrite_json(const yx_nul_escape_entry *entry, char *json, int space, size_t shift)
{
    static const char line_key[] = "\"line\":";
    size_t old_columns[32], new_columns[32], lines[32], labels = 0;
    const char *at;
    char *out, *write;
    if (!json) return json;
    /* First pass: each label's column before and after. */
    for (at = strstr(json, line_key); at; at = strstr(at, line_key)) {
        const char *cursor = at + strlen(line_key);
        size_t line = yx_nul_escape_json_number(&cursor), column, start;
        size_t removed = 0, line_start;
        if (strncmp(cursor, ",\"column\":", 10) != 0) {
            ++at;
            continue;
        }
        cursor += 10;
        column = yx_nul_escape_json_number(&cursor);
        at = cursor;
        if (strncmp(cursor, ",\"span\":{\"start\":", 17) != 0) continue;
        cursor += 17;
        start = yx_nul_escape_json_number(&cursor);
        if (labels == sizeof(lines) / sizeof(*lines)) break;
        if (space == YX_NUL_SPACE_ESCAPED) {
            /* Characters the escapes before the label add on its line:
             * "\x00" is 4 for 1 (bare NUL) or 2 (regexp backslash-NUL). */
            line_start = start;
            while (line_start > 0 && entry->source[line_start - 1] != '\n') --line_start;
            for (size_t k = 0; k < entry->count; ++k) {
                const yx_nul_escape *escape = &entry->escapes[k];
                if (escape->offset + 4 > start) break;
                if (escape->offset < line_start) continue;
                if (escape->kind == YX_NUL_BARE) removed += 3;
                else if (escape->kind == YX_NUL_REGEXP_ESCAPE) removed += 2;
            }
        }
        lines[labels] = line;
        old_columns[labels] = column;
        new_columns[labels] = column > removed ? column - removed : 1;
        ++labels;
    }
    /* Numbers only shrink, so the copy fits in the original's size. */
    out = (char *)malloc(strlen(json) + 1);
    if (!out) return json;
    write = out;
    for (at = json; *at;) {
        const char *cursor;
        size_t line, column, start, end;
        if (strncmp(at, line_key, strlen(line_key)) != 0) {
            *write++ = *at++;
            continue;
        }
        cursor = at + strlen(line_key);
        line = yx_nul_escape_json_number(&cursor);
        if (strncmp(cursor, ",\"column\":", 10) != 0) {
            *write++ = *at++;
            continue;
        }
        cursor += 10;
        column = yx_nul_escape_json_number(&cursor);
        for (size_t n = 0; n < labels; ++n)
            if (lines[n] == line && old_columns[n] == column) {
                column = new_columns[n];
                break;
            }
        write += sprintf(write, "\"line\":%zu,\"column\":%zu", line, column);
        at = cursor;
        if (strncmp(cursor, ",\"span\":{\"start\":", 17) != 0) continue;
        cursor += 17;
        start = yx_nul_escape_json_number(&cursor);
        if (strncmp(cursor, ",\"end\":", 7) != 0) continue;
        cursor += 7;
        end = yx_nul_escape_json_number(&cursor);
        if (space == YX_NUL_SPACE_ORIGINAL) {
            start = start > shift ? start - shift : 0;
            end = end > shift ? end - shift : 0;
        } else {
            start = yx_nul_escape_map(entry, start, space, YX_NUL_SPACE_ORIGINAL, false);
            end = yx_nul_escape_map(entry, end, space, YX_NUL_SPACE_ORIGINAL, true);
        }
        write += sprintf(write, ",\"span\":{\"start\":%zu,\"end\":%zu", start, end < start ? start : end);
        at = cursor;
    }
    *write = '\0';
    free(json);
    return out;
}

/* Diagnostic JSON is built in the escaped source's coordinates, or in the
 * display copy's under compiler->nul_json_space, because the compiler reads
 * spans back while it parses (yx_compiler_json_span). A diagnostic of a
 * source with escaped NULs is rewritten into YARA-X's coordinates when it
 * is stored. */
static char *yx_nul_escape_public_json(const YRX_COMPILER *compiler, char *json)
{
    const yx_nul_escape_entry *entry = compiler->nul_escapes;
    if (!entry || !entry->count || compiler->nul_json_space == YX_NUL_SPACE_ORIGINAL) return json;
    return yx_nul_escape_rewrite_json(entry, json, compiler->nul_json_space, 0);
}

/* Reads a stored diagnostic's span back in the coordinates of the source
 * being parsed. `end` may be NULL. */
bool yx_compiler_json_span(const YRX_COMPILER *compiler, const char *span, size_t *start, size_t *end)
{
    const yx_nul_escape_entry *entry = compiler ? compiler->nul_escapes : NULL;
    size_t ignored;
    if (!end) end = &ignored;
    if (!span || sscanf(span, "\"span\":{\"start\":%zu,\"end\":%zu", start, end) != 2) return false;
    if (entry && entry->count) {
        *start = yx_nul_escape_map(entry, *start, YX_NUL_SPACE_ORIGINAL, YX_NUL_SPACE_ESCAPED, false);
        *end = yx_nul_escape_map(entry, *end, YX_NUL_SPACE_ORIGINAL, YX_NUL_SPACE_ESCAPED, true);
    }
    return true;
}

static char *yx_diagnostic_text_source(const char *level, const char *code, const char *title, const char *label, const char *source, const char *origin, size_t start,
                                       size_t end, const char *note);

/* Diagnostics for a source with escaped NULs are rendered from its display
 * copy, matching the reference engine's columns, spans and excerpts. */
static char *yx_compiler_diagnostic_text(const YRX_COMPILER *compiler, const char *level, const char *code, const char *title, const char *label, const char *source,
                                         const char *origin, size_t start, size_t end, const char *note)
{
    yx_nul_escape_entry *entry = yx_nul_escape_find(compiler, source);
    const char *display = entry ? yx_nul_escape_display(entry) : NULL;
    if (display) {
        start = yx_nul_escape_map(entry, start, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, false);
        end = yx_nul_escape_map(entry, end, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, true);
        if (end < start) end = start;
        source = display;
    }
    return yx_diagnostic_text_source(level, code, title, label, source, origin, start, end, note);
}

static size_t yx_snippet_columns(const char *start, const char *end);
static size_t yx_snippet_whitespace(const char *at, const char *end);

/* True for a line with a character the renderer draws as a control picture,
 * removes or replaces (yx_diagnostic_render_fragment). */
static bool yx_diagnostic_line_has_pictures(const char *start, const char *end)
{
    for (const char *at = start; at < end; ++at) {
        unsigned char byte = (unsigned char)*at;
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f) return true;
        /* U+200D and the bidirectional controls U+202A..U+202E and
         * U+2066..U+2069. */
        if (byte == 0xe2 && end - at >= 3 &&
            (((unsigned char)at[1] == 0x80 && ((unsigned char)at[2] == 0x8d || ((unsigned char)at[2] >= 0xaa && (unsigned char)at[2] <= 0xae))) ||
             ((unsigned char)at[1] == 0x81 && (unsigned char)at[2] >= 0xa6 && (unsigned char)at[2] <= 0xa9)))
            return true;
    }
    return false;
}

/* True for a line with characters outside printable ASCII that the
 * renderer's margin cuts: wider than the terminal allows, or indented by
 * more than 26 columns. */
static bool yx_diagnostic_wide_line_is_cut(const char *start, const char *end)
{
    const char *text = start;
    size_t leading = 0;
    bool wide = false;
    /* What the byte-indexed crop of printable ASCII cannot cut: other
     * scalars and the characters drawn as control pictures (a bare CR is
     * cut there). */
    for (const char *at = start; at < end; ++at)
        if ((unsigned char)*at >= 0x7f || ((unsigned char)*at < 0x20 && *at != '\t' && *at != '\r')) wide = true;
    if (!wide) return false;
    while (text < end) {
        size_t bytes = yx_snippet_whitespace(text, end);
        if (!bytes) break;
        text += bytes;
        ++leading;
    }
    return (text < end && leading > 26) || yx_snippet_columns(start, end) > 126;
}

/* Every caller is a compiler method; the registry is the compiler's. */
#define yx_diagnostic_text(...) yx_compiler_diagnostic_text(compiler, __VA_ARGS__)

static char *yx_diagnostic_text_source(const char *level, const char *code, const char *title, const char *label, const char *source, const char *origin, size_t start,
                                       size_t end, const char *note)
{
    const char *line_start = source;
    const char *line_end;
    size_t line = 1, column, marker_column, gutter_digits = 1;
    size_t source_length = yx_source_text_length(source);
    size_t width, line_length, note_length;
    char *marks, *text, *cropped_line = NULL;
    char *rendered_title, *rendered_line;
    bool cropped_marker_middle = false;
    bool regexp_span = strcmp(code, "E014") == 0 || strcmp(code, "slow_pattern") == 0;
    bool bare_cr_crop;
    char note_lead[64] = {0};
    int needed;
    if (start > source_length) start = source_length;
    if (end > source_length) end = source_length;
    line = yx_source_line_of(source, start, &line_start);
    line_end = strchr(line_start, '\n');
    if (!line_end) line_end = source + source_length;
    /* The reference treats CRLF as one line ending in rendered excerpts.
     * A bare CR remains visible as a control picture. */
    if (*line_end == '\n' && line_end > line_start && line_end[-1] == '\r') --line_end;
    column = yx_diagnostic_columns(line_start, source + start) + 1;
    /* A final line break ending the span does not make it multi-line. */
    if (end > start + 1 && memchr(source + start, '\n', end - start - 1))
        return yx_diagnostic_multiline(level, code, title, label, source, origin, start, end, line, column, line_start, note);
    /* The byte-indexed crop below handles printable ASCII. A longer line
     * with other characters is cut by the general snippet renderer, which
     * works in display cells. */
    if (end > start && source + end <= line_end && yx_diagnostic_wide_line_is_cut(line_start, line_end))
        return yx_diagnostic_multiline(level, code, title, label, source, origin, start, end, line, column, line_start, note);
    for (size_t n = line; n >= 10; n /= 10) ++gutter_digits;
    line_length = (size_t)(line_end - line_start);
    bare_cr_crop = line_length > 140 - (3 + gutter_digits) && memchr(line_start, '\r', line_length) != NULL;
    /* A span can include the CR byte of CRLF even though that byte is
     * omitted from the rendered excerpt. Keep the JSON source span intact,
     * but stop its visible underline at the displayed end of the line. */
    const char *marker_end = source + end;
    if (marker_end > line_end) marker_end = line_end;
    width = marker_end > source + start ? yx_diagnostic_display_width(source + start, marker_end) : 1;
    /* An invalid zero-cell scalar still gets a visible one-cell marker. */
    if (width == 0) width = 1;
    /* Keep the full span while computing the reference renderer's margin.
     * A bare CR does not divide a source line, so formerly multiline spans
     * can now occupy most of one physical line and need middle elision. */
    /* The 272-cell middle-elision block below predates main's rename of this
     * flag to `regexp_span` (E014 or slow_pattern); it keeps D1's exact
     * exemption for the E014 "regex is too large" span, which the
     * 45-column crop below then handles. There is no 256-column clamp:
     * spans up to 272 columns keep their full marker. */
    bool oversized_regexp = strcmp(code, "E014") == 0 && (strcmp(label, "regex is too large") == 0 || strcmp(label, "regexp is too large") == 0);
    if (line_length > INT_MAX || column > INT_MAX || width > INT_MAX) return NULL;
    marker_column = yx_diagnostic_display_width(line_start, source + start) + 1;
    /* Any other annotation wider than 272 cells loses its middle. */
    if (!oversized_regexp && !bare_cr_crop && width > 272 && !(strcmp(code, "E014") == 0 && strcmp(label, "too many alternatives in alternation (max: 255)") == 0)) {
        cropped_line = yx_diagnostic_elide_span(line_start, line_length, (size_t)(source + start - line_start), (size_t)(marker_end - line_start), &marker_column);
        if (!cropped_line) return NULL;
        line_start = cropped_line;
        line_length = strlen(cropped_line);
        width = 93;
        cropped_marker_middle = true;
    }
    /* The same source-margin renderer is used for warnings and errors. */
    if (end >= start && (end - start == width || (bare_cr_crop && end == start))) {
        size_t available, whitespace = 0;
        size_t margin_white, margin_start, margin_end, margin_label;
        size_t left, right, span_start = column - 1;
        bool plain_ascii = true;
        for (size_t i = 0; i < line_length; ++i) {
            unsigned char byte = (unsigned char)line_start[i];
            /* Bare CR is drawn as a one-cell control picture. It can use
             * the same byte-indexed crop as printable ASCII. */
            if ((byte < 0x20 && byte != '\r' && byte != '\t') || byte >= 0x7f) {
                plain_ascii = false;
                break;
            }
        }
        if (plain_ascii) {
            available = 140 - (3 + gutter_digits);
            while (whitespace < line_length && line_start[whitespace] == ' ') ++whitespace;
            margin_white = whitespace > 6 ? whitespace - 6 : 0;
            margin_start = span_start > 6 ? span_start - 6 : 0;
            margin_end = span_start + width + 6;
            margin_label = span_start + width + strlen(label) + 7;
            left = margin_white > 20 ? margin_white - 16 : 0;
            right = line_length > left ? line_length : left;
            if (right - left > available) {
                if (margin_label >= margin_white && margin_label - margin_white <= available) {
                    left = margin_white;
                    right = left + available;
                } else if (margin_label >= margin_start && margin_label - margin_start <= available) {
                    size_t pad = (available - (margin_label - margin_start)) / 2;
                    left = margin_start > pad ? margin_start - pad : 0;
                    right = left + available;
                } else if (margin_end >= margin_start && margin_end - margin_start <= available) {
                    size_t pad = (available - (margin_end - margin_start)) / 5 * 2;
                    left = margin_start > pad ? margin_start - pad : 0;
                    right = left + available;
                } else {
                    left = margin_start;
                    right = margin_end;
                }
            }
            if (left > line_length) left = line_length;
            if (line_length - left <= available) right = line_length;
            else if (right > line_length) right = line_length;
            if ((left || right < line_length) && span_start >= left && (span_start + width <= right || (bare_cr_crop && end == start && span_start == right)) &&
                right - left >= 3) {
                cropped_line = (char *)malloc(right - left + 1);
                if (!cropped_line) return NULL;
                memcpy(cropped_line, line_start + left, right - left);
                if (left) memcpy(cropped_line, "...", 3);
                if (right < line_length) memcpy(cropped_line + right - left - 3, "...", 3);
                cropped_line[right - left] = '\0';
                line_start = cropped_line;
                line_length = right - left;
                marker_column = column - left;
            }
        }
    }
    /* The reference keeps 45 marked columns at each edge once this regex
     * span exceeds 272 columns, preserving text after the right marker. */
    if ((regexp_span || bare_cr_crop) && width > 272 && cropped_line) {
        size_t span_start = marker_column - 1;
        size_t trailing, prefix, suffix;
        char *crop;
        if (span_start > line_length || width > line_length - span_start) {
            free(cropped_line);
            return NULL;
        }
        trailing = line_length - span_start - width;
        if (trailing > SIZE_MAX - 45 - 3 - span_start - 45 - 1) {
            free(cropped_line);
            return NULL;
        }
        prefix = span_start + 45;
        suffix = trailing + 45;
        crop = (char *)malloc(prefix + 3 + suffix + 1);
        if (!crop) {
            free(cropped_line);
            return NULL;
        }
        memcpy(crop, line_start, prefix);
        memcpy(crop + prefix, "...", 3);
        memcpy(crop + prefix + 3, line_start + line_length - suffix, suffix);
        crop[prefix + 3 + suffix] = '\0';
        free(cropped_line);
        cropped_line = crop;
        line_start = crop;
        line_length = prefix + 3 + suffix;
        width = 93;
        cropped_marker_middle = true;
    }
    /* Spans of 257-272 cells keep their full marker (wider ones were
     * elided above); YARA-X has no 256-cell cap. */
    /* The reference diagnostic renderer displays each tab as one space while
     * keeping source byte offsets for columns and spans. */
    if (memchr(line_start, '\t', line_length)) {
        if (!cropped_line) {
            cropped_line = (char *)malloc(line_length + 1);
            if (!cropped_line) return NULL;
            memcpy(cropped_line, line_start, line_length);
            cropped_line[line_length] = '\0';
            line_start = cropped_line;
        }
        for (size_t i = 0; i < line_length; ++i)
            if (cropped_line[i] == '\t') cropped_line[i] = ' ';
    }
    rendered_title = yx_diagnostic_render_fragment(title, strlen(title));
    rendered_line = yx_diagnostic_render_fragment(line_start, line_length);
    if (!rendered_title || !rendered_line) {
        free(rendered_title);
        free(rendered_line);
        free(cropped_line);
        return NULL;
    }
    line_start = rendered_line;
    line_length = strlen(rendered_line);
    marks = (char *)malloc(width + 1);
    if (!marks) {
        free(rendered_title);
        free(rendered_line);
        free(cropped_line);
        return NULL;
    }
    memset(marks, strcmp(level, "warning") == 0 ? '-' : '^', width);
    if (cropped_marker_middle) memcpy(marks + 45, "...", 3);
    marks[width] = '\0';
    note_length = note ? strlen(note) : 0;
    if (note && snprintf(note_lead, sizeof(note_lead), "\n%*s|\n%*s= note: ", (int)gutter_digits + 1, "", (int)gutter_digits + 1, "") >= (int)sizeof(note_lead)) {
        free(marks);
        free(rendered_title);
        free(rendered_line);
        free(cropped_line);
        return NULL;
    }
    needed = snprintf(NULL, 0, "%s[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n%*zu |%s%.*s\n%*s| %*s%s %s%s%s", level, code, rendered_title, (int)gutter_digits, "",
                      origin ? origin : "line", line, column, (int)gutter_digits + 1, "", (int)gutter_digits, line, line_length ? " " : "", (int)line_length, line_start,
                      (int)gutter_digits + 1, "", (int)(marker_column - 1), "", marks, label, note_lead, note ? note : "");
    if (needed < 0 || (size_t)needed > SIZE_MAX - 1 - note_length) {
        free(marks);
        free(rendered_title);
        free(rendered_line);
        free(cropped_line);
        return NULL;
    }
    text = (char *)malloc((size_t)needed + 1);
    if (text)
        snprintf(text, (size_t)needed + 1, "%s[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n%*zu |%s%.*s\n%*s| %*s%s %s%s%s", level, code, rendered_title, (int)gutter_digits, "",
                 origin ? origin : "line", line, column, (int)gutter_digits + 1, "", (int)gutter_digits, line, line_length ? " " : "", (int)line_length, line_start,
                 (int)gutter_digits + 1, "", (int)(marker_column - 1), "", marks, label, note_lead, note ? note : "");
    free(marks);
    free(rendered_title);
    free(rendered_line);
    free(cropped_line);
    return text;
}

static char *yx_diagnostic_json(const char *type, const char *code, const char *title, const char *label, const char *text, const char *source, const char *origin,
                                size_t start, size_t end, const char *note, const char *level)
{
    char *quoted_type = yx_json_quoted(type);
    char *quoted_code = yx_json_quoted(code);
    char *quoted_title = yx_json_quoted(title);
    char *quoted_label = yx_json_quoted(label);
    char *visible_text = text && strchr(text, '\r') ? yx_diagnostic_visible_cr(text, strlen(text)) : NULL;
    char *quoted_text = yx_json_quoted(visible_text ? visible_text : text);
    char *quoted_origin = yx_json_quoted_code_origin(origin);
    char *quoted_note = note ? yx_json_quoted(note) : NULL;
    char *quoted_level = yx_json_quoted(level);
    const char *line_start = source;
    size_t line = 1, column, source_length = yx_source_text_length(source);
    const char *footer = note ? "[{\"level\":\"note\",\"text\":%s}]" : "[]";
    char *footer_json = NULL;
    char *json = NULL;
    int needed;
    if (start > source_length) start = source_length;
    line = yx_source_line_of(source, start, &line_start);
    column = yx_diagnostic_columns(line_start, source + start) + 1;
    if (text && strchr(text, '\r') && !visible_text) goto done;
    if (!quoted_type || !quoted_code || !quoted_title || !quoted_label || !quoted_text || !quoted_origin || !quoted_level || (note && !quoted_note)) goto done;
    needed = snprintf(NULL, 0, footer, quoted_note);
    if (needed < 0) goto done;
    footer_json = (char *)malloc((size_t)needed + 1);
    if (!footer_json) goto done;
    snprintf(footer_json, (size_t)needed + 1, footer, quoted_note);
    needed =
        snprintf(NULL, 0,
                 "{\"type\":%s,\"code\":%s,\"title\":%s,\"line\":%zu,\"column\":%zu,\"labels\":[{\"level\":%s,\"code_origin\":%s,\"line\":%zu,\"column\":%zu,\"span\":{"
                 "\"start\":%zu,\"end\":%zu},\"text\":%s}],\"footers\":%s,\"text\":%s}",
                 quoted_type, quoted_code, quoted_title, line, column, quoted_level, quoted_origin, line, column, start, end, quoted_label, footer_json, quoted_text);
    if (needed < 0) goto done;
    json = (char *)malloc((size_t)needed + 1);
    if (json)
        snprintf(json, (size_t)needed + 1,
                 "{\"type\":%s,\"code\":%s,\"title\":%s,\"line\":%zu,\"column\":%zu,\"labels\":[{\"level\":%s,\"code_origin\":%s,\"line\":%zu,\"column\":%zu,\"span\":{"
                 "\"start\":%zu,\"end\":%zu},\"text\":%s}],\"footers\":%s,\"text\":%s}",
                 quoted_type, quoted_code, quoted_title, line, column, quoted_level, quoted_origin, line, column, start, end, quoted_label, footer_json, quoted_text);
done:
    free(visible_text);
    free(quoted_type);
    free(quoted_code);
    free(quoted_title);
    free(quoted_label);
    free(quoted_text);
    free(quoted_origin);
    free(quoted_note);
    free(quoted_level);
    free(footer_json);
    return json;
}

/* Compact storage of warning JSON. A report's text is JSON-escaped and its
 * rows are separated by the escape `\n`; a row of YX_WARNING_ROW_MIN bytes or
 * more (a source line a patch shows in full) is kept once in
 * compiler->warning_rows and the stored warning refers to it. A stored
 * warning that refers to rows starts with YX_WARNING_COMPACT; a reference is
 * YX_WARNING_ROW_REF id ',' offset ',' n YX_WARNING_ROW_REF for n bytes of
 * row id from offset (a patch's `+` row is its `-` row with the gutter sign
 * and the replaced span changed). JSON never holds these raw control
 * bytes (a warning that does is stored as it is), and expanding a stored
 * warning gives back exactly the bytes it was built with. */
#define YX_WARNING_COMPACT '\x02'
#define YX_WARNING_ROW_REF '\x01'
enum {
    YX_WARNING_ROW_MIN = 256
};

typedef struct yx_warning_bytes {
    char *data;
    size_t used, capacity;
} yx_warning_bytes;

static bool yx_warning_bytes_put(yx_warning_bytes *bytes, const char *data, size_t length)
{
    if (length > SIZE_MAX - bytes->used - 1) return false;
    if (bytes->used + length + 1 > bytes->capacity) {
        size_t next = bytes->capacity ? bytes->capacity : 256;
        char *grown;
        while (next < bytes->used + length + 1) {
            if (next > SIZE_MAX / 2) {
                next = bytes->used + length + 1;
                break;
            }
            next *= 2;
        }
        grown = (char *)realloc(bytes->data, next);
        if (!grown) return false;
        bytes->data = grown;
        bytes->capacity = next;
    }
    if (length) memcpy(bytes->data + bytes->used, data, length);
    bytes->used += length;
    bytes->data[bytes->used] = '\0';
    return true;
}

static bool yx_warning_bytes_ref(yx_warning_bytes *bytes, size_t id, size_t offset, size_t length)
{
    char token[96];
    int written = snprintf(token, sizeof(token), "%c%zu,%zu,%zu%c", YX_WARNING_ROW_REF, id, offset, length, YX_WARNING_ROW_REF);
    return written > 0 && (size_t)written < sizeof(token) && yx_warning_bytes_put(bytes, token, (size_t)written);
}

static uint64_t yx_warning_row_hash(const char *data, size_t length)
{
    uint64_t hash = 0x9e3779b97f4a7c15ull ^ (uint64_t)length;
    size_t i = 0;
    for (; i + 8 <= length; i += 8) {
        uint64_t word;
        memcpy(&word, data + i, 8);
        hash = (hash ^ word) * 0xff51afd7ed558ccdull;
        hash ^= hash >> 29;
    }
    for (; i < length; ++i) hash = (hash ^ (unsigned char)data[i]) * 0x100000001b3ull;
    return hash ^ (hash >> 32);
}

/* The id of the stored row equal to data[0, length), or SIZE_MAX. */
static size_t yx_warning_row_find(const yx_warning_rows *rows, const char *data, size_t length, uint64_t hash)
{
    size_t mask = rows->slot_capacity - 1;
    if (!rows->slot_capacity) return SIZE_MAX;
    for (size_t at = (size_t)hash & mask;; at = (at + 1) & mask) {
        size_t id = rows->slots[at];
        if (!id) return SIZE_MAX;
        --id;
        if (rows->hashes[id] == hash && rows->lengths[id] == length && memcmp(rows->items[id], data, length) == 0) return id;
    }
}

static void yx_warning_row_slot(yx_warning_rows *rows, size_t id)
{
    size_t mask = rows->slot_capacity - 1;
    size_t at = (size_t)rows->hashes[id] & mask;
    while (rows->slots[at]) at = (at + 1) & mask;
    rows->slots[at] = id + 1;
}

static bool yx_warning_row_add(yx_warning_rows *rows, const char *data, size_t length, uint64_t hash, size_t *id)
{
    char *copy;
    if (rows->count == rows->capacity) {
        size_t next = rows->capacity ? rows->capacity * 2 : 16;
        char **items;
        size_t *lengths;
        uint64_t *hashes;
        if (rows->capacity > SIZE_MAX / 2 / sizeof(uint64_t)) return false;
        items = (char **)realloc(rows->items, next * sizeof(*items));
        if (!items) return false;
        rows->items = items;
        lengths = (size_t *)realloc(rows->lengths, next * sizeof(*lengths));
        if (!lengths) return false;
        rows->lengths = lengths;
        hashes = (uint64_t *)realloc(rows->hashes, next * sizeof(*hashes));
        if (!hashes) return false;
        rows->hashes = hashes;
        rows->capacity = next;
    }
    if (rows->count >= rows->slot_capacity / 2) {
        size_t next = rows->slot_capacity ? rows->slot_capacity * 2 : 64;
        size_t *slots;
        if (rows->slot_capacity > SIZE_MAX / 2 / sizeof(*slots)) return false;
        slots = (size_t *)calloc(next, sizeof(*slots));
        if (!slots) return false;
        free(rows->slots);
        rows->slots = slots;
        rows->slot_capacity = next;
        for (size_t i = 0; i < rows->count; ++i) yx_warning_row_slot(rows, i);
    }
    if (length == SIZE_MAX || !(copy = (char *)malloc(length + 1))) return false;
    memcpy(copy, data, length);
    copy[length] = '\0';
    rows->items[rows->count] = copy;
    rows->lengths[rows->count] = length;
    rows->hashes[rows->count] = hash;
    yx_warning_row_slot(rows, rows->count);
    *id = rows->count++;
    return true;
}

static void yx_warning_rows_free(yx_warning_rows *rows)
{
    for (size_t i = 0; i < rows->count; ++i) free(rows->items[i]);
    free(rows->items);
    free(rows->lengths);
    free(rows->hashes);
    free(rows->slots);
    memset(rows, 0, sizeof(*rows));
}

static void yx_warning_row_recent(yx_warning_rows *rows, size_t id)
{
    for (size_t i = 0; i < rows->recent_count; ++i)
        if (rows->recent[i] == id) return;
    if (rows->recent_count < YX_WARNING_RECENT_ROWS) rows->recent[rows->recent_count++] = id;
    else {
        rows->recent[rows->recent_next] = id;
        rows->recent_next = (rows->recent_next + 1) % YX_WARNING_RECENT_ROWS;
    }
}

/* Writes the public JSON of a stored warning into `out` (NULL: measures
 * it). Returns its length; SIZE_MAX for a reference that names no row. */
static size_t yx_warning_expand_into(const yx_warning_rows *rows, const char *stored, char *out)
{
    const char *at = stored;
    size_t used = 0;
    if (*at != YX_WARNING_COMPACT) {
        size_t length = strlen(at);
        if (out) memcpy(out, at, length);
        return length;
    }
    ++at;
    while (*at) {
        const char *ref = strchr(at, YX_WARNING_ROW_REF);
        size_t literal = ref ? (size_t)(ref - at) : strlen(at);
        size_t fields[3] = {0, 0, 0};
        if (literal >= SIZE_MAX - used) return SIZE_MAX;
        if (out) memcpy(out + used, at, literal);
        used += literal;
        if (!ref) break;
        at = ref + 1;
        for (size_t k = 0; k < 3; ++k) {
            if (*at < '0' || *at > '9') return SIZE_MAX;
            for (; *at >= '0' && *at <= '9'; ++at) {
                if (fields[k] > (SIZE_MAX - 9) / 10) return SIZE_MAX;
                fields[k] = fields[k] * 10 + (size_t)(*at - '0');
            }
            if (*at++ != (k < 2 ? ',' : YX_WARNING_ROW_REF)) return SIZE_MAX;
        }
        /* fields: row id, offset, length */
        if (fields[0] >= rows->count || fields[1] > rows->lengths[fields[0]] || fields[2] > rows->lengths[fields[0]] - fields[1] || fields[2] >= SIZE_MAX - used)
            return SIZE_MAX;
        if (out) memcpy(out + used, rows->items[fields[0]] + fields[1], fields[2]);
        used += fields[2];
    }
    return used;
}

/* The public JSON of a stored warning; NULL: out of memory. */
static char *yx_warning_expand(const YRX_COMPILER *compiler, const char *stored, size_t *length)
{
    size_t needed = yx_warning_expand_into(&compiler->warning_rows, stored, NULL);
    char *out;
    if (needed == SIZE_MAX || !(out = (char *)malloc(needed + 1))) return NULL;
    yx_warning_expand_into(&compiler->warning_rows, stored, out);
    out[needed] = '\0';
    if (length) *length = needed;
    return out;
}

enum {
    YX_WARNING_RUN_MIN = 16,
    YX_WARNING_MISS_MAX = 64
};

/* Compares segment with row id at equal offsets over [0, limit). *matched:
 * the bytes in equal runs of YX_WARNING_RUN_MIN or more; *stop: the end of
 * the last such run (the walk ends after YX_WARNING_MISS_MAX bytes without
 * one). With `out`, writes segment[0, *stop) as references to the runs and
 * literal bytes between them. False: out of memory. */
static bool yx_warning_row_walk(const char *row, const char *segment, size_t limit, size_t id, yx_warning_bytes *out, size_t *matched, size_t *stop)
{
    size_t at = 0, done = 0;
    *matched = 0;
    while (at < limit) {
        size_t run = at;
        while (run < limit && row[run] == segment[run]) ++run;
        if (run - at >= YX_WARNING_RUN_MIN) {
            if (out && ((at > done && !yx_warning_bytes_put(out, segment + done, at - done)) || !yx_warning_bytes_ref(out, id, at, run - at))) return false;
            *matched += run - at;
            done = at = run;
            continue;
        }
        if (run >= limit) break;
        at = run + 1;
        if (at - done > YX_WARNING_MISS_MAX) break;
    }
    *stop = done;
    return true;
}

/* Writes a row of YX_WARNING_ROW_MIN bytes or more as references to kept
 * rows. `shown` (YX_WARNING_RECENT_ROWS entries) holds the rows the same
 * report showed before. False: out of memory. */
static bool yx_warning_put_row(yx_warning_rows *rows, yx_warning_bytes *out, const char *segment, size_t size, size_t *shown, size_t *shown_count)
{
    size_t prefix_id = SIZE_MAX, suffix_id = SIZE_MAX, id = SIZE_MAX;
    size_t best_matched = 0, best_suffix = 0;
    uint64_t hash = 0;
    /* An exact copy of a kept row wins: a recent one (compared first, no
     * hash), else any. */
    for (size_t i = 0; i < rows->recent_count && id == SIZE_MAX; ++i) {
        size_t candidate = rows->recent[i];
        if (rows->lengths[candidate] == size && memcmp(rows->items[candidate], segment, size) == 0) id = candidate;
    }
    if (id == SIZE_MAX) {
        hash = yx_warning_row_hash(segment, size);
        id = yx_warning_row_find(rows, segment, size, hash);
    }
    /* Otherwise a patched copy of a row this report showed before it (a
     * `+` row after its `-` rows): the prefix at equal offsets from one of
     * them, the suffix from one of them. Any other new row is kept, so a
     * source line is stored once. */
    for (size_t i = 0; id == SIZE_MAX && i < *shown_count; ++i) {
        size_t candidate = shown[i], suffix = 0;
        size_t row_length = rows->lengths[candidate];
        size_t limit = row_length < size ? row_length : size;
        const char *row = rows->items[candidate];
        while (suffix < limit && row[row_length - 1 - suffix] == segment[size - 1 - suffix]) ++suffix;
        if (suffix > best_suffix) {
            best_suffix = suffix;
            suffix_id = candidate;
        }
    }
    for (size_t i = 0; id == SIZE_MAX && i < *shown_count; ++i) {
        size_t candidate = shown[i], matched, stop;
        size_t row_length = rows->lengths[candidate];
        size_t limit = row_length < size - best_suffix ? row_length : size - best_suffix;
        yx_warning_row_walk(rows->items[candidate], segment, limit, candidate, NULL, &matched, &stop);
        if (matched > best_matched) {
            best_matched = matched;
            prefix_id = candidate;
        }
    }
    if (id == SIZE_MAX && best_matched + best_suffix >= YX_WARNING_ROW_MIN && best_matched + best_suffix >= size / 2) {
        size_t stop = 0, matched;
        if (prefix_id != SIZE_MAX) {
            size_t row_length = rows->lengths[prefix_id];
            size_t limit = row_length < size - best_suffix ? row_length : size - best_suffix;
            if (!yx_warning_row_walk(rows->items[prefix_id], segment, limit, prefix_id, out, &matched, &stop)) return false;
        }
        return yx_warning_bytes_put(out, segment + stop, size - best_suffix - stop) &&
               (!best_suffix || yx_warning_bytes_ref(out, suffix_id, rows->lengths[suffix_id] - best_suffix, best_suffix));
    }
    if (id == SIZE_MAX && !yx_warning_row_add(rows, segment, size, hash, &id)) return false;
    yx_warning_row_recent(rows, id);
    if (*shown_count < YX_WARNING_RECENT_ROWS) shown[(*shown_count)++] = id;
    return yx_warning_bytes_ref(out, id, 0, size);
}

/* Plain text (rows separated by newlines) in the stored form: long rows
 * refer to kept rows, a text with raw reference bytes is kept as it is.
 * NULL: out of memory. */
static char *yx_warning_compact_text(yx_warning_rows *rows, const char *text, size_t length)
{
    yx_warning_bytes out = {0};
    size_t shown[YX_WARNING_RECENT_ROWS], shown_count = 0;
    const char *segment = text, *end = text + length;
    if (memchr(text, YX_WARNING_ROW_REF, length) || memchr(text, YX_WARNING_COMPACT, length)) {
        if (!yx_warning_bytes_put(&out, text, length)) goto failure;
        return out.data;
    }
    if (!yx_warning_bytes_put(&out, "\x02", 1)) goto failure;
    for (;;) {
        const char *line_end = memchr(segment, '\n', (size_t)(end - segment));
        size_t size = (size_t)((line_end ? line_end : end) - segment);
        if (size < YX_WARNING_ROW_MIN) {
            if (!yx_warning_bytes_put(&out, segment, size)) goto failure;
        } else if (!yx_warning_put_row(rows, &out, segment, size, shown, &shown_count)) {
            goto failure;
        }
        if (!line_end) break;
        if (!yx_warning_bytes_put(&out, "\n", 1)) goto failure;
        segment = line_end + 1;
    }
    return out.data;
failure:
    free(out.data);
    return NULL;
}

/* Takes a warning's JSON about to be stored (or stored and rewritten) and
 * returns the form to store, which may be `json` itself; NULL (and `json`
 * freed) when out of memory. */
static char *yx_warning_compact(YRX_COMPILER *compiler, char *json)
{
    yx_warning_rows *rows = &compiler->warning_rows;
    yx_warning_bytes out = {0};
    const char *field = NULL, *value, *end, *at, *segment;
    size_t length, shown[YX_WARNING_RECENT_ROWS], shown_count = 0;
    bool compacted = false;
    if (!json) return NULL;
    if (json[0] == YX_WARNING_COMPACT) {
        char *expanded = yx_warning_expand(compiler, json, NULL);
        free(json);
        if (!expanded) return NULL;
        json = expanded;
    }
    if (strchr(json, YX_WARNING_ROW_REF) || strchr(json, YX_WARNING_COMPACT)) return json;
    length = strlen(json);
    if (length < YX_WARNING_ROW_MIN || json[length - 1] != '}' || json[length - 2] != '"') return json;
    /* The report's own text is the last field and closes the object. */
    for (at = json; (at = strstr(at, "\"text\":\"")) != NULL; ++at) field = at;
    if (!field) return json;
    value = field + 8;
    end = json + length - 2;
    if (end < value) return json;
    for (at = value; at < end; ++at) {
        if (*at == '"') return json;
        if (*at == '\\' && ++at >= end) return json;
    }
    if (!yx_warning_bytes_put(&out, "\x02", 1) || !yx_warning_bytes_put(&out, json, (size_t)(value - json))) goto failure;
    for (segment = at = value;;) {
        bool stop = at >= end;
        size_t size;
        if (!stop && !(at[0] == '\\' && at[1] == 'n')) {
            at += at[0] == '\\' ? 2 : 1;
            continue;
        }
        size = (size_t)(at - segment);
        if (size < YX_WARNING_ROW_MIN) {
            if (!yx_warning_bytes_put(&out, segment, size)) goto failure;
        } else {
            if (!yx_warning_put_row(rows, &out, segment, size, shown, &shown_count)) goto failure;
            compacted = true;
        }
        if (stop) break;
        if (!yx_warning_bytes_put(&out, "\\n", 2)) goto failure;
        at += 2;
        segment = at;
    }
    if (!compacted) {
        free(out.data);
        return json;
    }
    if (!yx_warning_bytes_put(&out, "\"}", 2)) goto failure;
    free(json);
    return out.data;
failure:
    free(out.data);
    free(json);
    return NULL;
}

/* A warning the caller will not show (yr's --disable-warnings, set on the
 * compiler by the CLI): it is not rendered or recorded, as the reference
 * compiler's switch_warning(code, false) does not generate it. */
bool yx_compiler_warning_skipped(const YRX_COMPILER *compiler, const char *code)
{
    if (!compiler || !code) return false;
    if (compiler->warnings_all_disabled) return true;
    for (size_t i = 0; i < compiler->warnings_disabled_count; ++i)
        if (compiler->warnings_disabled[i] && strcmp(compiler->warnings_disabled[i], code) == 0) return true;
    return false;
}

static bool yx_compiler_warning(YRX_COMPILER *compiler, const char *type, const char *code, const char *title, const char *label, const char *source, const char *origin,
                                size_t start, size_t end, const char *note)
{
    char *text, *json, **grown;
    if (yx_compiler_warning_skipped(compiler, code)) return true;
    if (compiler->warning_count >= compiler->max_warnings) return true;
    if (source && yx_warning_suppressed_span((const uint8_t *)source, yx_source_text_length(source), code, start, end)) return true;
    if (compiler->warning_count >= compiler->max_warnings) return true;
    text = yx_diagnostic_text("warning", code, title, label, source, origin, start, end, note);
    if (!text) return false;
    json = yx_diagnostic_json(type, code, title, label, text, source, origin, start, end, note, "warning");
    free(text);
    if (!json || compiler->warning_count >= SIZE_MAX / sizeof(*grown)) {
        free(json);
        return false;
    }
    grown = (char **)realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) {
        free(json);
        return false;
    }
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) return false;
    compiler->warnings[compiler->warning_count++] = json;
    return true;
}

static bool yx_compiler_append_error_diagnostic(YRX_COMPILER *compiler, char *diagnostic);

/* A slow diagnostic becomes a compilation error under the corresponding
 * public compiler flag. Return 2 so callers can stop the current rule, while
 * 0 continues to mean allocation failure and 1 means an ordinary warning. */
static int yx_compiler_slow_error(YRX_COMPILER *compiler, const char *type, const char *code, const char *title, const char *label, const char *source,
                                  const char *origin, size_t start, size_t end, const char *note)
{
    char *text = yx_diagnostic_text("error", code, title, label, source, origin, start, end, note);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json(type, code, title, label, text, source, origin, start, end, note, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 2;
}

int yx_compiler_potentially_slow_loop_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    if (compiler->flags & YRX_ERROR_ON_SLOW_LOOP)
        return yx_compiler_slow_error(compiler, "PotentiallySlowLoop", "E034", "potentially slow loop", "this range can be very large", source, origin, start, end, NULL);
    return yx_compiler_warning(compiler, "PotentiallySlowLoop", "potentially_slow_loop", "potentially slow loop", "this range can be very large", source, origin, start,
                               end, NULL);
}

int yx_compiler_unused_identifier_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    return yx_compiler_warning(compiler, "UnusedIdentifier", "unused_identifier", "unused identifier", "this identifier declared but not used", source, origin, start,
                               end, NULL);
}

int yx_compiler_too_many_iterations_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, uint64_t iterations)
{
    char label[96];
    snprintf(label, sizeof(label), "this loop iterates %llu times, which may be slow", (unsigned long long)iterations);
    return yx_compiler_warning(compiler, "TooManyIterations", "too_many_iterations", "loop has too many iterations", label, source, origin, start, end, NULL);
}

/* A snippet renderer for reports whose labels may span several lines, as
 * annotate-snippets (rustc's emitter) draws them: a multi-line label opens
 * with `__-` under its first character, keeps a `|` in a left margin (one
 * column per nesting depth) and closes with `|__-` and its text under its
 * last character; labels on one line stack below each other when they would
 * collide. Columns are display cells; tabs show as one space. */
typedef struct {
    size_t start, end;
    const char *text;
    bool primary;
} yx_snippet_label;

typedef enum {
    YX_SNIPPET_SINGLE,
    YX_SNIPPET_START,
    YX_SNIPPET_END,
    YX_SNIPPET_LINE
} yx_snippet_kind;

typedef struct {
    yx_snippet_kind kind;
    size_t depth, start_col, end_col;
    const char *text;
    bool primary;
} yx_snippet_annotation;

typedef struct {
    size_t number;
    const char *start, *end;
    yx_snippet_annotation items[8];
    size_t count;
} yx_snippet_line;

/* Rows lose their trailing spaces, but a source row keeps its text. */
typedef struct {
    char **rows;
    size_t *lengths, *kept;
    size_t count, capacity;
    /* Allocated bytes of each row (0 before its first write). */
    size_t *allocated;
} yx_snippet_buffer;

static bool yx_snippet_row(yx_snippet_buffer *buffer, size_t row)
{
    while (buffer->count <= row) {
        if (buffer->count == buffer->capacity) {
            size_t next = buffer->capacity ? buffer->capacity * 2 : 16;
            char **rows = realloc(buffer->rows, next * sizeof(*rows));
            size_t *lengths, *kept;
            if (!rows) return false;
            buffer->rows = rows;
            lengths = realloc(buffer->lengths, next * sizeof(*lengths));
            if (!lengths) return false;
            buffer->lengths = lengths;
            kept = realloc(buffer->kept, next * sizeof(*kept));
            if (!kept) return false;
            buffer->kept = kept;
            kept = realloc(buffer->allocated, next * sizeof(*kept));
            if (!kept) return false;
            buffer->allocated = kept;
            buffer->capacity = next;
        }
        buffer->rows[buffer->count] = NULL;
        buffer->allocated[buffer->count] = 0;
        buffer->kept[buffer->count] = 0;
        buffer->lengths[buffer->count++] = 0;
    }
    return true;
}

static bool yx_snippet_put(yx_snippet_buffer *buffer, size_t row, size_t column, const char *text, size_t length)
{
    char *grown;
    if (!yx_snippet_row(buffer, row)) return false;
    if (buffer->lengths[row] < column + length) {
        size_t needed = column + length + 1;
        if (needed > buffer->allocated[row]) {
            size_t size = buffer->allocated[row] * 2;
            if (size < needed) size = needed;
            grown = realloc(buffer->rows[row], size);
            if (!grown) return false;
            buffer->allocated[row] = size;
        } else grown = buffer->rows[row];
        memset(grown + buffer->lengths[row], ' ', column + length - buffer->lengths[row]);
        buffer->rows[row] = grown;
        buffer->lengths[row] = column + length;
        grown[column + length] = '\0';
    }
    memcpy(buffer->rows[row] + column, text, length);
    return true;
}

static bool yx_snippet_putc(yx_snippet_buffer *buffer, size_t row, size_t column, char character)
{
    return yx_snippet_put(buffer, row, column, &character, 1);
}

static size_t yx_snippet_columns(const char *start, const char *end)
{
    size_t cells = 0;
    while (start < end) {
        size_t length;
        if (end - start >= 8 && yx_diagnostic_printable_word(yx_diagnostic_word((const unsigned char *)start))) {
            cells += 8;
            start += 8;
            continue;
        }
        if ((unsigned char)*start >= 0x20 && (unsigned char)*start < 0x7f) {
            ++cells;
            ++start;
            continue;
        }
        length = yx_diagnostic_scalar_length(start, end);
        cells += *start == '\t' ? 1 : yx_diagnostic_display_width(start, start + length);
        start += length;
    }
    return cells;
}

/* annotate-snippets' Margin: the window of display columns of the source
 * lines that fits the terminal. */
typedef struct {
    size_t whitespace_left, span_left, span_right, label_right;
    size_t computed_left, computed_right, column_width;
} yx_snippet_margin;

static void yx_snippet_margin_compute(yx_snippet_margin *m, size_t max_line_len)
{
    m->whitespace_left = m->whitespace_left > 6 ? m->whitespace_left - 6 : 0;
    m->span_left = m->span_left > 6 ? m->span_left - 6 : 0;
    m->span_right += 6;
    m->label_right += 6;
    /* A lot of leading whitespace (> 20) is trimmed, keeping some padding. */
    m->computed_left = m->whitespace_left > 20 ? m->whitespace_left - 16 : 0;
    m->computed_right = max_line_len > m->computed_left ? max_line_len : m->computed_left;
    if (m->computed_right - m->computed_left <= m->column_width) return;
    if (m->label_right >= m->whitespace_left && m->label_right - m->whitespace_left <= m->column_width) {
        /* The window fits when only whitespace is trimmed. */
        m->computed_left = m->whitespace_left;
        m->computed_right = m->computed_left + m->column_width;
    } else if (m->label_right >= m->span_left && m->label_right - m->span_left <= m->column_width) {
        /* The spans and their labels fit. */
        size_t padding = (m->column_width - (m->label_right - m->span_left)) / 2;
        m->computed_left = m->span_left > padding ? m->span_left - padding : 0;
        m->computed_right = m->computed_left + m->column_width;
    } else if (m->span_right >= m->span_left && m->span_right - m->span_left <= m->column_width) {
        /* The spans fit. */
        size_t padding = (m->column_width - (m->span_right - m->span_left)) / 5 * 2;
        m->computed_left = m->span_left > padding ? m->span_left - padding : 0;
        m->computed_right = m->computed_left + m->column_width;
    } else {
        /* Mostly give up, but still do not show the full line. */
        m->computed_left = m->span_left;
        m->computed_right = m->span_right;
    }
}

/* Whether yx_snippet_columns(start, end) exceeds `limit`, without
 * measuring a long line past that point. */
static bool yx_snippet_columns_exceed(const char *start, const char *end, size_t limit)
{
    size_t cells = 0;
    while (start < end) {
        size_t length;
        if (end - start >= 8 && yx_diagnostic_printable_word(yx_diagnostic_word((const unsigned char *)start))) {
            cells += 8;
            start += 8;
        } else if ((unsigned char)*start >= 0x20 && (unsigned char)*start < 0x7f) {
            ++cells;
            ++start;
        } else {
            length = yx_diagnostic_scalar_length(start, end);
            cells += *start == '\t' ? 1 : yx_diagnostic_display_width(start, start + length);
            start += length;
        }
        if (cells > limit) return true;
    }
    return false;
}

static size_t yx_snippet_scalar_cells(const char *at, size_t length)
{
    return *at == '\t' ? 1 : yx_diagnostic_display_width(at, at + length);
}

typedef struct {
    const char *text;
    size_t length;
} yx_snippet_slot;

/* The styled buffer holds one scalar per cell whatever its width. */
static void yx_snippet_slots_put(yx_snippet_slot *slots, size_t *count, size_t at, const char *text, const char *end)
{
    static const char space[] = " ";
    while (*count < at) {
        slots[*count].text = space;
        slots[(*count)++].length = 1;
    }
    while (text < end) {
        size_t bytes = yx_diagnostic_scalar_length(text, end);
        slots[at].text = text;
        slots[at].length = bytes;
        if (++at > *count) *count = at;
        text += bytes;
    }
}

/* annotate-snippets draws control characters as pictures, drops the zero
 * width joiner and replaces the bidirectional controls in the source text
 * it shows: the same for the text of row `row` from `from` on. */
static bool yx_snippet_row_pictures(yx_snippet_buffer *buffer, size_t row, size_t from)
{
    char *rendered, *grown;
    size_t length;
    if (row >= buffer->count || buffer->lengths[row] <= from || !yx_diagnostic_line_has_pictures(buffer->rows[row] + from, buffer->rows[row] + buffer->lengths[row]))
        return true;
    rendered = yx_diagnostic_render_fragment(buffer->rows[row] + from, buffer->lengths[row] - from);
    if (!rendered) return false;
    length = strlen(rendered);
    grown = (char *)realloc(buffer->rows[row], from + length + 1);
    if (!grown) {
        free(rendered);
        return false;
    }
    memcpy(grown + from, rendered, length + 1);
    free(rendered);
    buffer->allocated[row] = from + length + 1;
    buffer->rows[row] = grown;
    buffer->lengths[row] = from + length;
    if (buffer->kept[row]) buffer->kept[row] = from + length;
    return true;
}

/* Draws a source line: its number, the separator and the text (tabs as one
 * space) at `code_offset`, cut to the margin's window with "..." where text
 * was removed (annotate-snippets' draw_line). *left_out receives the number
 * of display columns removed on the left. */
static bool yx_snippet_source_row(yx_snippet_buffer *buffer, size_t row, size_t number, size_t digits, size_t width_offset, size_t code_offset, const char *start,
                                  const char *end, const yx_snippet_margin *margin, size_t *left_out)
{
    static const char placeholder[] = "...";
    char prefix[32];
    int length = snprintf(prefix, sizeof(prefix), "%*zu", (int)digits, number);
    size_t line_len = yx_snippet_columns(start, end);
    size_t left = margin->computed_left < line_len ? margin->computed_left : line_len;
    size_t right = (line_len > margin->computed_left ? line_len - margin->computed_left : 0) <= margin->column_width || line_len < margin->computed_right
                       ? line_len
                       : margin->computed_right;
    size_t skipped = 0, taken = 0, window = right > left ? right - left : 0;
    size_t width_taken = 0, scalars = 0, count = 0, column = code_offset;
    const char *code = start, *code_end, *text;
    yx_snippet_slot *slots;
    bool ok = true;
    if (length < 0 || !yx_snippet_put(buffer, row, 0, prefix, (size_t)length) || !yx_snippet_putc(buffer, row, width_offset - 2, '|')) return false;
    /* A scalar that straddles the left edge is skipped whole. */
    while (code < end && skipped < left) {
        size_t bytes = yx_diagnostic_scalar_length(code, end);
        skipped += yx_snippet_scalar_cells(code, bytes);
        code += bytes;
    }
    code_end = code;
    while (code_end < end) {
        size_t bytes = yx_diagnostic_scalar_length(code_end, end);
        taken += yx_snippet_scalar_cells(code_end, bytes);
        if (taken > window) break;
        code_end += bytes;
        ++scalars;
    }
    if (skipped > left) left = skipped;
    if (left_out) *left_out = left;
    if (margin->computed_left == 0 && line_len <= right) {
        if (code_end > code) {
            if (!yx_snippet_put(buffer, row, code_offset, code, (size_t)(code_end - code))) return false;
            buffer->kept[row] = code_offset + (size_t)(code_end - code);
        }
        for (size_t at = code_offset; at < buffer->lengths[row]; ++at)
            if (buffer->rows[row][at] == '\t') buffer->rows[row][at] = ' ';
        return yx_snippet_row_pictures(buffer, row, code_offset);
    }
    slots = (yx_snippet_slot *)malloc((scalars + 16) * sizeof(*slots));
    if (!slots) return false;
    text = code;
    if (margin->computed_left > 0) {
        /* "..." stands for the first scalars covering at least three cells. */
        while (text < code_end) {
            size_t bytes = yx_diagnostic_scalar_length(text, code_end);
            width_taken += yx_snippet_scalar_cells(text, bytes);
            text += bytes;
            --scalars;
            if (width_taken >= 3) break;
        }
        yx_snippet_slots_put(slots, &count, 0, placeholder, placeholder + 3);
    }
    yx_snippet_slots_put(slots, &count, width_taken, text, code_end);
    if (line_len > right) {
        /* "..." overwrites the last scalars covering at least three cells. */
        const char *cut = code_end;
        size_t cells = 0, removed = 0, at;
        while (cut > code && cells < 3) {
            const char *previous = cut - 1;
            while (previous > code && ((unsigned char)*previous & 0xc0) == 0x80 && cut - previous < 4) --previous;
            if (previous + yx_diagnostic_scalar_length(previous, cut) != cut) previous = cut - 1;
            cells += yx_snippet_scalar_cells(previous, (size_t)(cut - previous));
            cut = previous;
            ++removed;
        }
        at = width_taken + scalars > removed ? width_taken + scalars - removed : 0;
        yx_snippet_slots_put(slots, &count, at, placeholder, placeholder + 3);
    }
    for (size_t i = 0; ok && i < count; ++i) {
        ok = yx_snippet_put(buffer, row, column, slots[i].text, slots[i].length);
        column += slots[i].length;
    }
    free(slots);
    if (!ok) return false;
    for (size_t at = code_offset; at < buffer->lengths[row]; ++at)
        if (buffer->rows[row][at] == '\t') buffer->rows[row][at] = ' ';
    if (count) buffer->kept[row] = column;
    return yx_snippet_row_pictures(buffer, row, code_offset);
}

/* The byte length of the Unicode whitespace scalar at `at`, 0 for others. */
static size_t yx_snippet_whitespace(const char *at, const char *end)
{
    const unsigned char *s = (const unsigned char *)at;
    size_t available = (size_t)(end - at);
    if (*s == ' ' || (*s >= 9 && *s <= 13)) return 1;
    if (available >= 2 && s[0] == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0)) return 2;
    if (available >= 3) {
        if (s[0] == 0xe1 && s[1] == 0x9a && s[2] == 0x80) return 3;
        if (s[0] == 0xe2 && s[1] == 0x80 && ((s[2] >= 0x80 && s[2] <= 0x8a) || s[2] == 0xa8 || s[2] == 0xa9 || s[2] == 0xaf)) return 3;
        if (s[0] == 0xe2 && s[1] == 0x81 && s[2] == 0x9f) return 3;
        if (s[0] == 0xe3 && s[1] == 0x80 && s[2] == 0x80) return 3;
    }
    return 0;
}

/* The buffer column of display column `column` of a line cut by `left`. */
static size_t yx_snippet_x(size_t code_offset, size_t column, size_t left)
{
    return code_offset + column > left ? code_offset + column - left : 0;
}

static bool yx_snippet_overlaps(const yx_snippet_annotation *a, const yx_snippet_annotation *b, size_t padding)
{
    return (b->start_col <= a->start_col && a->start_col < b->end_col + padding) || (a->start_col <= b->start_col && b->start_col < a->end_col + padding);
}

static bool yx_snippet_has_text(const yx_snippet_annotation *a)
{
    return a->text && *a->text;
}

static bool yx_snippet_takes_space(const yx_snippet_annotation *a)
{
    return a->kind == YX_SNIPPET_START || a->kind == YX_SNIPPET_END;
}

/* render_source_line: the source row and its annotation rows. *depths
 * receives the depths of the multi-line labels opening or closing here. */
/* StyledBuffer::replace: "..." takes the place of positions [from, to) of
 * a row. A source row has one position per scalar, an annotation row one
 * per byte. A row that does not reach `to` is left alone. */
static bool yx_snippet_replace(yx_snippet_buffer *buffer, size_t row, size_t from, size_t to, bool scalars)
{
    size_t length, begin = SIZE_MAX, end = SIZE_MAX, position = 0, at = 0;
    char *text;
    if (row >= buffer->count || from >= to) return true;
    length = buffer->lengths[row];
    text = buffer->rows[row];
    while (at <= length) {
        if (position == from) begin = at;
        if (position == to) {
            end = at;
            break;
        }
        if (at == length) break;
        at += scalars ? yx_diagnostic_scalar_length(text + at, text + length) : 1;
        ++position;
    }
    if (begin == SIZE_MAX || end == SIZE_MAX) return true;
    if (end - begin < 3) {
        char *grown = (char *)realloc(text, length + 3 - (end - begin) + 1);
        if (!grown) return false;
        buffer->rows[row] = text = grown;
        buffer->allocated[row] = length + 3 - (end - begin) + 1;
    }
    memmove(text + begin + 3, text + end, length - end);
    memcpy(text + begin, "...", 3);
    buffer->lengths[row] = length - (end - begin) + 3;
    text[buffer->lengths[row]] = '\0';
    if (buffer->kept[row] >= end) buffer->kept[row] = buffer->kept[row] - (end - begin) + 3;
    else if (buffer->kept[row] > begin) buffer->kept[row] = begin + 3;
    return true;
}

static bool yx_snippet_render_line(yx_snippet_buffer *buffer, const yx_snippet_line *line, size_t digits, size_t width_offset, size_t code_offset,
                                   const yx_snippet_margin *margin, size_t *depths, size_t *depth_count)
{
    yx_snippet_annotation items[8];
    size_t positions[8], count = line->count, line_len = 0, p = 0;
    size_t row = buffer->count, left = 0;
    bool short_start = true, all_lines = true, all_starts = true;
    *depth_count = 0;
    if (!yx_snippet_source_row(buffer, row, line->number, digits, width_offset, code_offset, line->start, line->end, margin, &left)) return false;
    /* Sort by start column, rightmost first (stable). */
    for (size_t i = 0; i < count; ++i) {
        size_t j = i;
        while (j > 0 && items[j - 1].start_col < line->items[i].start_col) {
            items[j] = items[j - 1];
            --j;
        }
        items[j] = line->items[i];
    }
    for (size_t i = 0; i < count; ++i) {
        if (items[i].kind == YX_SNIPPET_START) {
            const char *at = line->start;
            size_t cells = 0;
            while (at < line->end && cells < items[i].start_col) {
                size_t length = yx_diagnostic_scalar_length(at, line->end);
                if (!isspace((unsigned char)*at)) break;
                cells += yx_snippet_columns(at, at + length);
                at += length;
            }
            if (cells < items[i].start_col) {
                short_start = false;
                break;
            }
        } else if (items[i].kind != YX_SNIPPET_LINE) {
            short_start = false;
            break;
        }
    }
    if (short_start) {
        for (size_t i = 0; i < count; ++i)
            if (items[i].kind == YX_SNIPPET_START) {
                if (!yx_snippet_putc(buffer, row, width_offset + items[i].depth - 1, '/')) return false;
                depths[(*depth_count)++] = items[i].depth;
            }
        return true;
    }
    for (size_t i = 0; i < count; ++i)
        if (items[i].kind != YX_SNIPPET_LINE) all_lines = false;
    if (all_lines) return true;
    for (size_t i = 0; i < count; ++i) {
        const yx_snippet_annotation *annotation = &items[i];
        for (size_t j = i + 1; j < count; ++j) {
            const yx_snippet_annotation *next = &items[j];
            if (yx_snippet_overlaps(next, annotation, 0) && yx_snippet_has_text(annotation) && p == 0) {
                if (next->start_col == annotation->start_col && next->end_col == annotation->end_col && !yx_snippet_has_text(next)) continue;
                ++p;
                break;
            }
        }
        positions[i] = p;
        for (size_t j = i + 1; j < count; ++j) {
            const yx_snippet_annotation *next = &items[j];
            size_t padding = yx_snippet_has_text(next) ? strlen(next->text) + 2 : 0;
            if ((yx_snippet_overlaps(next, annotation, padding) && yx_snippet_has_text(annotation) && yx_snippet_has_text(next)) ||
                (yx_snippet_takes_space(annotation) && yx_snippet_has_text(next)) || (yx_snippet_has_text(annotation) && yx_snippet_takes_space(next)) ||
                (yx_snippet_takes_space(annotation) && yx_snippet_takes_space(next)) ||
                (yx_snippet_overlaps(next, annotation, padding) && next->end_col <= annotation->end_col && yx_snippet_has_text(next) && p == 0)) {
                ++p;
                break;
            }
        }
        if (p > line_len) line_len = p;
    }
    if (line_len) ++line_len;
    for (size_t i = 0; i < count; ++i)
        if (items[i].kind != YX_SNIPPET_START) all_starts = false;
    if (all_starts && count) {
        size_t maximum = 0;
        for (size_t i = 0; i < count; ++i)
            if (positions[i] > maximum) maximum = positions[i];
        for (size_t i = 0; i < count; ++i) positions[i] = maximum - positions[i];
        if (line_len) --line_len;
    }
    for (size_t pos = 0; pos <= line_len; ++pos)
        if (!yx_snippet_putc(buffer, row + pos + 1, width_offset - 2, '|')) return false;
    /* Horizontal and vertical lines of multi-line labels and connectors. */
    for (size_t i = 0; i < count; ++i) {
        const yx_snippet_annotation *annotation = &items[i];
        size_t pos = positions[i] + 1;
        size_t column = yx_snippet_x(code_offset, annotation->start_col, left);
        if (pos > 1 && (yx_snippet_has_text(annotation) || yx_snippet_takes_space(annotation))) {
            for (size_t r = row + 1; r <= row + pos; ++r)
                if (!yx_snippet_putc(buffer, r, column, '|')) return false;
        }
        if (annotation->kind == YX_SNIPPET_START) {
            if (!yx_snippet_putc(buffer, row + pos, width_offset + annotation->depth - 1, ' ')) return false;
            for (size_t x = width_offset + annotation->depth; x < column; ++x)
                if (!yx_snippet_putc(buffer, row + pos, x, '_')) return false;
        } else if (annotation->kind == YX_SNIPPET_END) {
            for (size_t r = row; r <= row + pos; ++r)
                if (!yx_snippet_putc(buffer, r, width_offset + annotation->depth - 1, '|')) return false;
            for (size_t x = width_offset + annotation->depth; x < column; ++x)
                if (!yx_snippet_putc(buffer, row + pos, x, '_')) return false;
        }
    }
    for (size_t i = 0; i < count; ++i) {
        const yx_snippet_annotation *annotation = &items[i];
        size_t r, column;
        if (!yx_snippet_has_text(annotation)) continue;
        if (!positions[i]) {
            r = row + 1;
            column = annotation->end_col + (annotation->end_col ? 1 : 2);
        } else {
            r = row + positions[i] + 2;
            column = annotation->start_col;
        }
        column = column > left ? column - left : 0;
        if (!yx_snippet_put(buffer, r, code_offset + column, annotation->text, strlen(annotation->text))) return false;
    }
    for (size_t i = 0; i < count; ++i) {
        const yx_snippet_annotation *annotation = &items[i];
        char mark = annotation->primary ? '^' : '-';
        for (size_t x = annotation->start_col; x < annotation->end_col; ++x)
            if (!yx_snippet_putc(buffer, row + 1, yx_snippet_x(code_offset, x, left), mark)) return false;
        if (yx_snippet_takes_space(annotation) || (positions[i] && yx_snippet_has_text(annotation)))
            if (!yx_snippet_putc(buffer, row + 1, yx_snippet_x(code_offset, annotation->start_col, left), mark)) return false;
    }
    /* An underline wider than twice the width left for the code loses its
     * middle: "..." replaces what lies between its first and last third of
     * that width, on the underline's row and, at the same positions, on
     * the source row (annotate-snippets' renderer; rightmost first). */
    for (size_t i = 0; i < count; ++i) {
        const yx_snippet_annotation *annotation = &items[i];
        size_t width = annotation->end_col - annotation->start_col;
        size_t pad = margin->column_width / 3 > 5 ? margin->column_width / 3 : 5;
        size_t from, to;
        if (width <= margin->column_width * 2 || width <= 10) continue;
        from = yx_snippet_x(code_offset, annotation->start_col, left) + pad;
        to = yx_snippet_x(code_offset, annotation->end_col, left);
        to = to > pad ? to - pad : 0;
        if (!yx_snippet_replace(buffer, row, from, to, true) || !yx_snippet_replace(buffer, row + 1, from, to, false)) return false;
    }
    /* A label opening here keeps its margin bar on the rows below its
     * horizontal line. */
    for (size_t i = 0; i < count; ++i) {
        if (items[i].kind != YX_SNIPPET_START) continue;
        for (size_t r = row + positions[i] + 2; r <= row + line_len + 1; ++r)
            if (!yx_snippet_putc(buffer, r, width_offset + items[i].depth - 1, '|')) return false;
    }
    for (size_t i = 0; i < count; ++i)
        if (yx_snippet_takes_space(&items[i])) depths[(*depth_count)++] = items[i].depth;
    return true;
}

/* rustc's filter for the lines kept inside a multi-line label: blank lines,
 * comments and lone delimiters are not worth showing. */
static bool yx_snippet_worth_showing(const char *start, const char *end)
{
    while (start < end && isspace((unsigned char)*start)) ++start;
    while (end > start && isspace((unsigned char)end[-1])) --end;
    if (end - start >= 2 && start[0] == '/' && start[1] == '/') return end - start >= 3 && (start[2] == '/' || start[2] == '!');
    return !(end == start || (end - start == 1 && strchr("{}()[]", *start)));
}

static bool yx_snippet_add(yx_snippet_line *lines, size_t *count, size_t capacity, const char *source, size_t number, const yx_snippet_annotation *annotation)
{
    size_t i = 0;
    const char *start = source, *end;
    while (i < *count && lines[i].number < number) ++i;
    if (i == *count || lines[i].number != number) {
        if (*count == capacity) return false;
        memmove(lines + i + 1, lines + i, (*count - i) * sizeof(*lines));
        ++*count;
        memset(&lines[i], 0, sizeof(lines[i]));
        lines[i].number = number;
        for (size_t n = 1; n < number; ++n) {
            start = strchr(start, '\n');
            if (!start) return false;
            ++start;
        }
        end = strchr(start, '\n');
        if (!end) end = start + strlen(start);
        lines[i].start = start;
        lines[i].end = yx_diagnostic_display_line_end(start, end);
    }
    if (lines[i].count == sizeof(lines[i].items) / sizeof(lines[i].items[0])) return false;
    lines[i].items[lines[i].count++] = *annotation;
    return true;
}

static size_t yx_snippet_line_of(const char *source, size_t offset, const char **line_start)
{
    return yx_source_line_of(source, offset, line_start);
}

/* The report text of `labels` (at most 4): title, location and snippet.
 * For a report over several sources each one is a section: `source` then
 * holds lines `line_base + 1` onwards, the gutter is at least `min_digits`
 * wide and a `continuation` section starts with its `:::` location. */
static char *yx_diagnostic_snippet_section(const char *level, const char *code, const char *title, const char *source, const char *origin, const yx_snippet_label *labels,
                                           size_t label_count, size_t header_line, size_t header_column, size_t line_base, size_t min_digits, bool continuation)
{
    yx_snippet_line lines[64];
    size_t line_count = 0, depth[4] = {0}, max_depth = 0, digits = 1;
    size_t start_line[4], end_line[4], width_offset, code_offset;
    const char *start_of[4], *end_of[4];
    yx_snippet_buffer buffer = {0};
    yx_snippet_margin margin = {0};
    bool open[6] = {0};
    char *text = NULL;
    size_t used = 0, capacity = 0;
    if (label_count > 4) return NULL;
    for (size_t i = 0; i < label_count; ++i) {
        start_line[i] = yx_snippet_line_of(source, labels[i].start, &start_of[i]);
        end_line[i] = yx_snippet_line_of(source, labels[i].end - 1, &end_of[i]);
    }
    /* Overlapping multi-line labels nest: the one opening first (the outer
     * one when they open together) is drawn leftmost. */
    for (size_t i = 0; i < label_count; ++i) {
        if (start_line[i] == end_line[i]) continue;
        depth[i] = 1;
        for (size_t j = 0; j < label_count; ++j) {
            bool before;
            if (j == i || start_line[j] == end_line[j]) continue;
            before = start_line[j] < start_line[i] || (start_line[j] == start_line[i] && (end_line[j] > end_line[i] || (end_line[j] == end_line[i] && j < i)));
            if (before && start_line[j] <= end_line[i] && start_line[i] <= end_line[j] && depth[i] <= depth[j]) depth[i] = depth[j] + 1;
        }
        if (depth[i] > max_depth) max_depth = depth[i];
    }
    for (size_t i = 0; i < label_count; ++i) {
        yx_snippet_annotation annotation = {0};
        const char *start = source + labels[i].start;
        const char *last = source + labels[i].end - 1;
        annotation.primary = labels[i].primary;
        if (start_line[i] == end_line[i]) {
            annotation.kind = YX_SNIPPET_SINGLE;
            annotation.start_col = yx_snippet_columns(start_of[i], start);
            annotation.end_col = annotation.start_col + yx_snippet_columns(start, source + labels[i].end);
            if (annotation.end_col == annotation.start_col) ++annotation.end_col;
            annotation.text = labels[i].text;
            if (!yx_snippet_add(lines, &line_count, 64, source, start_line[i], &annotation)) goto done;
            continue;
        }
        annotation.depth = depth[i];
        annotation.kind = YX_SNIPPET_START;
        annotation.start_col = yx_snippet_columns(start_of[i], start);
        annotation.end_col = annotation.start_col + 1;
        if (!yx_snippet_add(lines, &line_count, 64, source, start_line[i], &annotation)) goto done;
        annotation.kind = YX_SNIPPET_END;
        annotation.start_col = yx_snippet_columns(end_of[i], last);
        annotation.end_col = annotation.start_col + 1;
        annotation.text = labels[i].text;
        if (!yx_snippet_add(lines, &line_count, 64, source, end_line[i], &annotation)) goto done;
        /* The lines shown inside: up to three after the first, through the
         * last one worth showing, and the line before the last. */
        {
            size_t middle = start_line[i] + 4 < end_line[i] ? start_line[i] + 4 : end_line[i];
            size_t until = start_line[i];
            const char *at = start_of[i];
            annotation.kind = YX_SNIPPET_LINE;
            annotation.start_col = annotation.end_col = 0;
            annotation.text = NULL;
            for (size_t n = start_line[i]; n < middle && at; ++n) {
                const char *end = strchr(at, '\n');
                if (!end) end = at + strlen(at);
                if (yx_snippet_worth_showing(at, end)) until = n + 1;
                at = *end ? end + 1 : NULL;
            }
            for (size_t n = start_line[i] + 1; n < until; ++n)
                if (!yx_snippet_add(lines, &line_count, 64, source, n, &annotation)) goto done;
            if (middle < end_line[i] - 1) {
                const char *line_start = source, *line_end;
                for (size_t n = 1; n < end_line[i] - 1 && line_start; ++n) {
                    line_start = strchr(line_start, '\n');
                    if (line_start) ++line_start;
                }
                if (line_start) {
                    line_end = strchr(line_start, '\n');
                    if (!line_end) line_end = line_start + strlen(line_start);
                    if (yx_snippet_worth_showing(line_start, line_end) && !yx_snippet_add(lines, &line_count, 64, source, end_line[i] - 1, &annotation)) goto done;
                }
            }
        }
    }
    if (!line_count) goto done;
    for (size_t i = 0; i < line_count; ++i) lines[i].number += line_base;
    for (size_t n = lines[line_count - 1].number; n >= 10; n /= 10) ++digits;
    if (digits < min_digits) digits = min_digits;
    width_offset = digits + 3;
    code_offset = width_offset + (max_depth ? max_depth + 1 : 0);
    /* The margin: the leading whitespace shared by the annotated lines, the
     * leftmost and rightmost annotated columns, the rightmost label end and
     * the widest annotated line. */
    {
        size_t whitespace = SIZE_MAX, max_line_len = 0;
        margin.span_left = SIZE_MAX;
        for (size_t i = 0; i < line_count; ++i) {
            const char *at = lines[i].start;
            size_t leading = 0, cells = yx_snippet_columns(lines[i].start, lines[i].end);
            while (at < lines[i].end) {
                size_t bytes = yx_snippet_whitespace(at, lines[i].end);
                if (!bytes) break;
                at += bytes;
                ++leading;
            }
            if (at < lines[i].end && leading < whitespace) whitespace = leading;
            if (cells > max_line_len) max_line_len = cells;
            for (size_t k = 0; k < lines[i].count; ++k) {
                const yx_snippet_annotation *a = &lines[i].items[k];
                size_t label = a->end_col + (yx_snippet_has_text(a) ? yx_diagnostic_display_width(a->text, a->text + strlen(a->text)) + 1 : 0);
                if (a->start_col < margin.span_left) margin.span_left = a->start_col;
                if (a->end_col < margin.span_left) margin.span_left = a->end_col;
                if (a->start_col > margin.span_right) margin.span_right = a->start_col;
                if (a->end_col > margin.span_right) margin.span_right = a->end_col;
                if (label > margin.label_right) margin.label_right = label;
            }
        }
        margin.whitespace_left = whitespace == SIZE_MAX ? 0 : whitespace;
        if (margin.span_left == SIZE_MAX) margin.span_left = 0;
        margin.column_width = 140 > code_offset ? 140 - code_offset : 0;
        yx_snippet_margin_compute(&margin, max_line_len);
    }
    for (size_t i = 0; i < line_count; ++i) {
        size_t first_row = buffer.count, depths[8], depth_count;
        bool closing[6] = {0}, opening[6] = {0};
        if (!yx_snippet_render_line(&buffer, &lines[i], digits, width_offset, code_offset, &margin, depths, &depth_count)) goto done;
        for (size_t d = 0; d < depth_count; ++d) {
            if (depths[d] >= 6) goto done;
            if (open[depths[d]]) closing[depths[d]] = true;
            else opening[depths[d]] = true;
        }
        for (size_t d = 1; d < 6; ++d) {
            if (closing[d]) open[d] = false;
            if (!open[d]) continue;
            for (size_t r = first_row; r < buffer.count; ++r)
                if (!yx_snippet_putc(&buffer, r, width_offset + d - 1, '|')) goto done;
        }
        if (i + 1 < line_count) {
            size_t delta = lines[i + 1].number - lines[i].number;
            size_t row = buffer.count;
            if (delta > 2) {
                if (!yx_snippet_put(&buffer, row, 0, "...", 3)) goto done;
            } else if (delta == 2) {
                const char *start = lines[i].end, *end;
                while (*start && *start != '\n') ++start;
                if (*start) ++start;
                end = strchr(start, '\n');
                if (!end) end = start + strlen(start);
                end = yx_diagnostic_display_line_end(start, end);
                if (!yx_snippet_source_row(&buffer, row, lines[i].number + 1, digits, width_offset, code_offset, start, end, &margin, NULL)) goto done;
            }
            if (delta >= 2)
                for (size_t d = 1; d < 6; ++d)
                    if ((open[d] || opening[d]) && !yx_snippet_putc(&buffer, row, width_offset + d - 1, '|')) goto done;
        }
        for (size_t d = 1; d < 6; ++d)
            if (opening[d]) open[d] = true;
    }
    if (continuation) {
        if (!yx_diagnostic_append(&text, &used, &capacity, "%*s::: %s:%zu:%zu\n%*s|", (int)digits, "", origin ? origin : "line", header_line, header_column,
                                  (int)digits + 1, ""))
            goto done;
    } else {
        char *rendered_title = yx_diagnostic_render_fragment(title, strlen(title));
        bool appended = rendered_title && yx_diagnostic_append(&text, &used, &capacity, "%s[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|", level, code, rendered_title, (int)digits,
                                                               "", origin ? origin : "line", header_line, header_column, (int)digits + 1, "");
        free(rendered_title);
        if (!appended) goto done;
    }
    for (size_t r = 0; r < buffer.count; ++r) {
        size_t length = buffer.lengths[r];
        while (length > buffer.kept[r] && buffer.rows[r][length - 1] == ' ') --length;
        if (!yx_diagnostic_append(&text, &used, &capacity, "\n%.*s", (int)length, buffer.rows[r] ? buffer.rows[r] : "")) {
            free(text);
            text = NULL;
            goto done;
        }
    }
done:
    for (size_t r = 0; r < buffer.count; ++r) free(buffer.rows[r]);
    free(buffer.rows);
    free(buffer.lengths);
    free(buffer.kept);
    free(buffer.allocated);
    return text;
}

static char *yx_diagnostic_snippet(const char *level, const char *code, const char *title, const char *source, const char *origin, const yx_snippet_label *labels,
                                   size_t label_count, size_t header_line, size_t header_column)
{
    return yx_diagnostic_snippet_section(level, code, title, source, origin, labels, label_count, header_line, header_column, 0, 1, false);
}

/* The start of 1-based line `number` of `source`, NULL when it has fewer. */
static const char *yx_snippet_line_start(const char *source, size_t number)
{
    for (size_t n = 1; n < number && source; ++n) {
        source = strchr(source, '\n');
        if (source) ++source;
    }
    return source;
}

/* True when a line holding one of `offsets` is long enough, or indented
 * enough, for the renderer's margin to cut it, or holds characters whose
 * width is not one cell: such a report is drawn by yx_diagnostic_snippet. */
static bool yx_snippet_margin_applies(const char *source, const size_t *offsets, size_t count)
{
    size_t length = yx_source_text_length(source);
    for (size_t i = 0; i < count; ++i) {
        size_t at = offsets[i] < length ? offsets[i] : length;
        const char *start = source + at, *end, *text;
        size_t leading = 0;
        while (start > source && start[-1] != '\n') --start;
        end = strchr(source + at, '\n');
        if (!end) end = source + length;
        end = yx_diagnostic_display_line_end(start, end);
        for (text = start; text < end; ++leading) {
            size_t bytes = yx_snippet_whitespace(text, end);
            if (!bytes) break;
            text += bytes;
        }
        /* The answer is known at the first line that applies: a long
         * line is not measured past its 127th cell. */
        if (text < end && leading > 26) return true;
        if (yx_snippet_columns_exceed(start, end, 126)) return true;
        /* Columns are display cells, which the generic renderer counts. */
        for (text = start; text < end; ++text)
            if ((unsigned char)*text >= 0x80) return true;
    }
    return false;
}

static char *yx_diagnostic_snippet_one(const char *level, const char *code, const char *title, const char *source, const char *origin, size_t start, size_t end,
                                       const char *label, bool primary, size_t line, size_t column)
{
    yx_snippet_label item = {start, end, label, primary};
    if (end <= start) return NULL;
    return yx_diagnostic_snippet(level, code, title, source, origin, &item, 1, line, column);
}

/* Pair warnings on a source with escaped NULs render from its display copy
 * like every other diagnostic. */
static bool yx_compiler_pair_warning_source(YRX_COMPILER *compiler, const char *type, const char *code, const char *title, const char *source, const char *origin,
                                            size_t a_start, size_t a_end, const char *a_label, size_t b_start, size_t b_end, const char *b_label, bool b_note);

static bool yx_compiler_pair_warning(YRX_COMPILER *compiler, const char *type, const char *code, const char *title, const char *source, const char *origin,
                                     size_t a_start, size_t a_end, const char *a_label, size_t b_start, size_t b_end, const char *b_label, bool b_note)
{
    yx_nul_escape_entry *entry;
    const char *display = NULL;
    unsigned char space;
    bool ok;
    if (yx_compiler_warning_skipped(compiler, code)) return true;
    entry = yx_nul_escape_find(compiler, source);
    /* Past the warning limit the plain call returns without rendering. */
    if (entry && compiler->warning_count < compiler->max_warnings) display = yx_nul_escape_display(entry);
    if (!display) return yx_compiler_pair_warning_source(compiler, type, code, title, source, origin, a_start, a_end, a_label, b_start, b_end, b_label, b_note);
    space = compiler->nul_json_space;
    compiler->nul_json_space = YX_NUL_SPACE_DISPLAY;
    ok = yx_compiler_pair_warning_source(compiler, type, code, title, display, origin,
                                         yx_nul_escape_map(entry, a_start, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, false),
                                         yx_nul_escape_map(entry, a_end, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, true), a_label,
                                         yx_nul_escape_map(entry, b_start, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, false),
                                         yx_nul_escape_map(entry, b_end, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, true), b_label, b_note);
    compiler->nul_json_space = space;
    return ok;
}

/* Related spans are rendered in source order, while the JSON labels retain
 * the semantic order supplied by the caller. Adjacent lines are supported. */
static bool yx_compiler_pair_warning_source(YRX_COMPILER *compiler, const char *type, const char *code, const char *title, const char *source, const char *origin,
                                            size_t a_start, size_t a_end, const char *a_label, size_t b_start, size_t b_end, const char *b_label, bool b_note)
{
    const char *line_start, *line_end, *display_end;
    const char *right_line_start = NULL, *right_line_end = NULL;
    const char *right_display_end = NULL;
    const char *left_label, *right_label;
    size_t source_length, left_start, left_end, right_start, right_end;
    size_t line = 1, right_line, a_line, b_line;
    size_t top_column, a_column, b_column, digits = 1;
    size_t left_cell, right_cell, left_width, right_width, gap;
    size_t crop_left = 0, crop_right;
    size_t text_used = 0, text_capacity = 0;
    size_t json_used = 0, json_capacity = 0;
    size_t middle_used = 0, middle_capacity = 0;
    char *display = NULL, *right_display = NULL;
    char *left_marks = NULL, *right_marks = NULL;
    char *text = NULL, *json = NULL, *quoted_text = NULL, *middle = NULL;
    char *quoted_type = NULL, *quoted_code = NULL, *quoted_title = NULL;
    char *quoted_a = NULL, *quoted_b = NULL, *quoted_origin = NULL;
    char **grown;
    bool ok = false;
    if (!compiler || !source || !a_label || !b_label) return false;
    if (yx_compiler_warning_skipped(compiler, code)) return true;
    source_length = yx_source_text_length(source);
    if (a_start >= a_end || b_start >= b_end || a_end > source_length || b_end > source_length) return false;
    if (a_start < b_start) {
        left_start = a_start;
        left_end = a_end;
        left_label = a_label;
        right_start = b_start;
        right_end = b_end;
        right_label = b_label;
    } else {
        left_start = b_start;
        left_end = b_end;
        left_label = b_label;
        right_start = a_start;
        right_end = a_end;
        right_label = a_label;
    }
    if (left_end > right_start) return false;
    line_start = source + left_start;
    while (line_start > source && line_start[-1] != '\n') --line_start;
    line_end = strchr(line_start, '\n');
    if (!line_end) line_end = source + source_length;
    if (memchr(source + left_start, '\n', left_end - left_start) || memchr(source + right_start, '\n', right_end - right_start) ||
        yx_snippet_margin_applies(source, (const size_t[]){left_start, right_start}, 2)) {
        /* A label spanning lines, or a line the margin cuts: the general
         * snippet renderer. */
        yx_snippet_label labels[2] = {{left_start, left_end, left_label, false}, {right_start, right_end, right_label, false}};
        const char *a_line_start, *b_line_start;
        if (yx_warning_suppressed_span((const uint8_t *)source, source_length, code, left_start, left_end) ||
            yx_warning_suppressed_span((const uint8_t *)source, source_length, code, right_start, right_end))
            return true;
        if (compiler->warning_count >= compiler->max_warnings) return true;
        line = yx_snippet_line_of(source, left_start, &a_line_start);
        top_column = yx_diagnostic_columns(line_start, source + left_start) + 1;
        text = yx_diagnostic_snippet("warning", code, title, source, origin, labels, 2, line, top_column);
        if (!text) goto done;
        a_line = yx_snippet_line_of(source, a_start, &a_line_start);
        b_line = yx_snippet_line_of(source, b_start, &b_line_start);
        a_column = yx_diagnostic_columns(a_line_start, source + a_start) + 1;
        b_column = yx_diagnostic_columns(b_line_start, source + b_start) + 1;
        goto json;
    }
    if (source + left_end > line_end) return true;
    if (source + right_start > line_end) {
        if (line_end == source + source_length) return true;
        right_line_start = line_end + 1;
        right_line_end = strchr(right_line_start, '\n');
        if (!right_line_end) right_line_end = source + source_length;
        while (source + right_start > right_line_end) {
            if (right_line_end == source + source_length) return true;
            right_line_start = right_line_end + 1;
            right_line_end = strchr(right_line_start, '\n');
            if (!right_line_end) right_line_end = source + source_length;
        }
        if (source + right_start < right_line_start || source + right_end > right_line_end) return true;
    }
    display_end = yx_diagnostic_display_line_end(line_start, line_end);
    if (right_line_start) right_display_end = yx_diagnostic_display_line_end(right_line_start, right_line_end);
    if (compiler->warning_count >= compiler->max_warnings) return true;
    if (yx_warning_suppressed_span((const uint8_t *)source, source_length, code, left_start, left_end) ||
        yx_warning_suppressed_span((const uint8_t *)source, source_length, code, right_start, right_end))
        return true;
    {
        const char *ignored_line_start;
        line = yx_source_line_of(source, (size_t)(line_start - source), &ignored_line_start);
    }
    right_line = line;
    if (right_line_start)
        for (const char *at = line_start; at < right_line_start; ++at)
            if (*at == '\n') ++right_line;
    a_line = a_start == left_start ? line : right_line;
    b_line = b_start == left_start ? line : right_line;
    for (size_t n = right_line; n >= 10; n /= 10) ++digits;
    top_column = yx_diagnostic_columns(line_start, source + left_start) + 1;
    a_column = yx_diagnostic_columns(a_line == line ? line_start : right_line_start, source + a_start) + 1;
    b_column = yx_diagnostic_columns(b_line == line ? line_start : right_line_start, source + b_start) + 1;
    left_cell = yx_diagnostic_display_width(line_start, source + left_start) + 1;
    right_cell = yx_diagnostic_display_width(right_line_start ? right_line_start : line_start, source + right_start) + 1;
    left_width = yx_diagnostic_display_width(source + left_start, source + left_end);
    right_width = yx_diagnostic_display_width(source + right_start, source + right_end);
    if (!left_width || !right_width || (!right_line_start && right_cell < left_cell + left_width)) goto done;
    gap = right_line_start ? 0 : right_cell - left_cell - left_width;
    if (digits > INT_MAX - 1 || left_cell > INT_MAX || right_cell > INT_MAX || left_width > INT_MAX || right_width > INT_MAX || gap > INT_MAX ||
        display_end - line_start > INT_MAX || (right_line_start && right_display_end - right_line_start > INT_MAX))
        goto done;
    crop_right = (size_t)(display_end - line_start);
    if (!right_line_start && crop_right > 140 - (3 + digits)) {
        size_t white = 0, margin_white, margin_start, margin_end;
        size_t margin_label, label_left, label_right, available;
        bool simple = true;
        for (size_t at = 0; at < crop_right; ++at) {
            unsigned char byte = (unsigned char)line_start[at];
            if ((byte < 0x20 && byte != '\r') || byte >= 0x7f) {
                simple = false;
                break;
            }
        }
        if (simple) {
            available = 140 - (3 + digits);
            while (white < crop_right && line_start[white] == ' ') ++white;
            margin_white = white > 6 ? white - 6 : 0;
            margin_start = left_cell > 7 ? left_cell - 7 : 0;
            margin_end = right_cell - 1 + right_width + 6;
            label_left = left_cell - 1 + left_width + strlen(left_label) + 1;
            label_right = right_cell - 1 + right_width + strlen(right_label) + 1;
            margin_label = (label_left > label_right ? label_left : label_right) + 6;
            crop_left = margin_white > 20 ? margin_white - 16 : 0;
            if (crop_right - crop_left > available) {
                if (margin_label >= margin_white && margin_label - margin_white <= available) {
                    crop_left = margin_white;
                    crop_right = crop_left + available;
                } else if (margin_label >= margin_start && margin_label - margin_start <= available) {
                    size_t pad = (available - (margin_label - margin_start)) / 2;
                    crop_left = margin_start > pad ? margin_start - pad : 0;
                    crop_right = crop_left + available;
                } else if (margin_end >= margin_start && margin_end - margin_start <= available) {
                    size_t pad = (available - (margin_end - margin_start)) / 5 * 2;
                    crop_left = margin_start > pad ? margin_start - pad : 0;
                    crop_right = crop_left + available;
                } else {
                    crop_left = margin_start;
                    crop_right = margin_end;
                }
            }
            size_t line_length = (size_t)(display_end - line_start);
            if (crop_left > line_length) crop_left = line_length;
            if (line_length - crop_left <= available) crop_right = line_length;
            else if (crop_right > line_length) crop_right = line_length;
            if (crop_right <= crop_left || crop_right - crop_left < 3 || left_cell <= crop_left || right_cell <= crop_left) {
                crop_left = 0;
                crop_right = line_length;
            } else {
                left_cell -= crop_left;
                right_cell -= crop_left;
            }
        }
    }
    display = malloc(crop_right - crop_left + 1);
    if (right_line_start) right_display = malloc((size_t)(right_display_end - right_line_start) + 1);
    left_marks = malloc(left_width + 1);
    right_marks = malloc(right_width + 1);
    if (!display || (right_line_start && !right_display) || !left_marks || !right_marks) goto done;
    memcpy(display, line_start + crop_left, crop_right - crop_left);
    if (crop_left) memcpy(display, "...", 3);
    if (crop_right < (size_t)(display_end - line_start)) memcpy(display + crop_right - crop_left - 3, "...", 3);
    display[crop_right - crop_left] = '\0';
    for (char *at = display; *at; ++at)
        if (*at == '\t') *at = ' ';
    if (right_display) {
        memcpy(right_display, right_line_start, (size_t)(right_display_end - right_line_start));
        right_display[right_display_end - right_line_start] = '\0';
        for (char *at = right_display; *at; ++at)
            if (*at == '\t') *at = ' ';
    }
    memset(left_marks, '-', left_width);
    left_marks[left_width] = '\0';
    memset(right_marks, '-', right_width);
    right_marks[right_width] = '\0';
    if (right_line_start) {
        if (right_line > line + 2) {
            if (!yx_diagnostic_append(&middle, &middle_used, &middle_capacity, "...\n")) goto done;
        } else if (right_line == line + 2) {
            const char *between = line_end + 1;
            const char *between_end = strchr(between, '\n');
            size_t length;
            char *shown;
            if (!between_end) goto done;
            length = (size_t)(yx_diagnostic_display_line_end(between, between_end) - between);
            if (length > INT_MAX) goto done;
            shown = malloc(length + 1);
            if (!shown) goto done;
            memcpy(shown, between, length);
            shown[length] = '\0';
            for (size_t i = 0; i < length; ++i)
                if (shown[i] == '\t') shown[i] = ' ';
            bool middle_ok = yx_diagnostic_append(&middle, &middle_used, &middle_capacity, "%*zu |%s%s\n", (int)digits, line + 1, length ? " " : "", shown);
            free(shown);
            if (!middle_ok) goto done;
        }
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                                  "warning[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                  "%*zu | %s\n%*s| %*s%s %s\n"
                                  "%s%*zu | %s\n%*s| %*s%s %s",
                                  code, title, (int)digits, "", origin ? origin : "line", line, top_column, (int)digits + 1, "", (int)digits, line, display,
                                  (int)digits + 1, "", (int)left_cell - 1, "", left_marks, left_label, middle ? middle : "", (int)digits, right_line, right_display,
                                  (int)digits + 1, "", (int)right_cell - 1, "", right_marks, right_label))
            goto done;
    } else if (gap >= strlen(left_label) && gap - strlen(left_label) >= 2) {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                                  "warning[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                  "%*zu | %s\n%*s| %*s%s %s%*s%s %s",
                                  code, title, (int)digits, "", origin ? origin : "line", line, top_column, (int)digits + 1, "", (int)digits, line, display,
                                  (int)digits + 1, "", (int)left_cell - 1, "", left_marks, left_label, (int)(gap - strlen(left_label) - 1), "", right_marks, right_label))
            goto done;
    } else if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                                     "warning[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                     "%*zu | %s\n%*s| %*s%s%*s%s %s\n%*s| %*s|\n"
                                     "%*s| %*s%s",
                                     code, title, (int)digits, "", origin ? origin : "line", line, top_column, (int)digits + 1, "", (int)digits, line, display,
                                     (int)digits + 1, "", (int)left_cell - 1, "", left_marks, (int)gap, "", right_marks, right_label, (int)digits + 1, "",
                                     (int)left_cell - 1, "", (int)digits + 1, "", (int)left_cell - 1, "", left_label))
        goto done;
json:
    if (!yx_diagnostic_normalize_visible_cr(&text)) goto done;
    quoted_type = yx_json_quoted(type);
    quoted_code = yx_json_quoted(code);
    quoted_title = yx_json_quoted(title);
    quoted_a = yx_json_quoted(a_label);
    quoted_b = yx_json_quoted(b_label);
    quoted_text = yx_json_quoted(text);
    quoted_origin = yx_json_quoted_code_origin(origin);
    if (!quoted_type || !quoted_code || !quoted_title || !quoted_a || !quoted_b || !quoted_text || !quoted_origin) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity,
                              "{\"type\":%s,\"code\":%s,\"title\":%s,"
                              "\"line\":%zu,\"column\":%zu,\"labels\":["
                              "{\"level\":\"warning\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":%s},"
                              "{\"level\":\"%s\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":%s}],"
                              "\"footers\":[],\"text\":%s}",
                              quoted_type, quoted_code, quoted_title, a_line, a_column, quoted_origin, a_line, a_column, a_start, a_end, quoted_a,
                              b_note ? "note" : "warning", quoted_origin, b_line, b_column, b_start, b_end, quoted_b, quoted_text))
        goto done;
    if (compiler->warning_count >= SIZE_MAX / sizeof(*grown)) goto done;
    grown = realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) goto done;
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) goto done;
    compiler->warnings[compiler->warning_count++] = json;
    json = NULL;
    ok = true;
done:
    free(display);
    free(right_display);
    free(left_marks);
    free(right_marks);
    free(middle);
    free(text);
    free(json);
    free(quoted_text);
    free(quoted_type);
    free(quoted_code);
    free(quoted_title);
    free(quoted_a);
    free(quoted_b);
    free(quoted_origin);
    return ok;
}

int yx_compiler_unsatisfiable_pattern_at_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t quantifier_start, size_t quantifier_end,
                                                 size_t at_start, size_t at_end)
{
    return yx_compiler_pair_warning(compiler, "PotentiallyUnsatisfiableExpression", "unsatisfiable_expr", "potentially unsatisfiable expression", source, origin,
                                    quantifier_start, quantifier_end, "this implies that multiple patterns must match", at_start, at_end,
                                    "but they must match at the same offset", false);
}

int yx_compiler_unsatisfiable_pair_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t first_start, size_t first_end, const char *first_label,
                                           size_t second_start, size_t second_end, const char *second_label)
{
    return yx_compiler_pair_warning(compiler, "UnsatisfiableExpression", "unsatisfiable_expr", "unsatisfiable expression", source, origin, first_start, first_end,
                                    first_label, second_start, second_end, second_label, false);
}

int yx_compiler_duplicate_pattern_value_warning(YRX_COMPILER *compiler, const char *identifier, const char *source, const char *origin, size_t duplicate_start,
                                                size_t duplicate_end, size_t existing_start, size_t existing_end)
{
    char *duplicate_label = NULL, *existing_label = NULL;
    size_t duplicate_used = 0, duplicate_capacity = 0;
    size_t existing_used = 0, existing_capacity = 0;
    bool ok = false;
    if (!compiler || !identifier || !source) return false;
    if (yx_compiler_warning_skipped(compiler, "duplicate_pattern_value")) return true;
    if (compiler->warning_count >= compiler->max_warnings) return true;
    if (yx_warning_suppressed_span((const uint8_t *)source, yx_source_text_length(source), "duplicate_pattern_value", duplicate_start, duplicate_end) ||
        yx_warning_suppressed_span((const uint8_t *)source, yx_source_text_length(source), "duplicate_pattern_value", existing_start, existing_end))
        return true;
    if (!yx_diagnostic_append(&duplicate_label, &duplicate_used, &duplicate_capacity, "duplicate of pattern `%s`", identifier) ||
        !yx_diagnostic_append(&existing_label, &existing_used, &existing_capacity, "pattern `%s` defined here first", identifier))
        goto done;
    ok = yx_compiler_pair_warning(compiler, "DuplicatePatternValue", "duplicate_pattern_value", "duplicate pattern value", source, origin, duplicate_start, duplicate_end,
                                  duplicate_label, existing_start, existing_end, existing_label, true);
done:
    free(duplicate_label);
    free(existing_label);
    return ok;
}

/* The `duplicate_import` warning of Compiler::c_items: the later import of a
 * module already imported by the same source, its previous import as a
 * note, and a patch deleting the later one. */
int yx_compiler_duplicate_import_warning(YRX_COMPILER *compiler, const char *module, const char *source, const char *origin, size_t first_start, size_t first_end,
                                         size_t duplicate_start, size_t duplicate_end)
{
    char *first_label = NULL, *patch = NULL, *rebuilt = NULL;
    char *quoted = NULL, *json, *text_field, *text_end;
    size_t label_used = 0, label_capacity = 0, patch_used = 0;
    size_t patch_capacity = 0, count_before, line = 1, digits = 1;
    size_t rest_length;
    const char *line_start, *line_end, *display_end;
    bool ok = false, whitespace_only = true;
    if (!compiler || !module || !source) return false;
    count_before = compiler->warning_count;
    if (!yx_diagnostic_append(&first_label, &label_used, &label_capacity, "`%s` imported here for the first time", module)) goto done;
    if (!yx_compiler_pair_warning(compiler, "DuplicateImport", "duplicate_import", "duplicate import statement", source, origin, duplicate_start, duplicate_end,
                                  "duplicate import", first_start, first_end, first_label, true))
        goto done;
    /* Suppressed, over the warning limit or not rendered. */
    if (compiler->warning_count != count_before + 1) {
        ok = true;
        goto done;
    }
    /* help: the duplicate's line without it; a line left blank is shown
     * as removed only. */
    line_start = source + duplicate_start;
    while (line_start > source && line_start[-1] != '\n') --line_start;
    line_end = strchr(source + duplicate_start, '\n');
    if (!line_end) line_end = source + yx_source_text_length(source);
    display_end = yx_diagnostic_display_line_end(line_start, line_end);
    if (source + duplicate_end > display_end) {
        ok = true;
        goto done;
    }
    {
        const char *ignored_line_start;
        line = yx_source_line_of(source, (size_t)(line_start - source), &ignored_line_start);
    }
    for (size_t n = line; n >= 10; n /= 10) ++digits;
    rest_length = (size_t)(display_end - line_start) - (duplicate_end - duplicate_start);
    for (const char *at = line_start; at < display_end; ++at) {
        if (at == source + duplicate_start) {
            at = source + duplicate_end - 1;
            continue;
        }
        if (*at != ' ' && *at != '\t') whitespace_only = false;
    }
    if (!yx_diagnostic_append(&patch, &patch_used, &patch_capacity,
                              "\n%*s|\nhelp: consider the following change"
                              "\n%*s|\n%*zu - %.*s",
                              (int)digits + 1, "", (int)digits + 1, "", (int)digits, line, (int)(display_end - line_start), line_start))
        goto done;
    if (rest_length && !whitespace_only &&
        !yx_diagnostic_append(&patch, &patch_used, &patch_capacity, "\n%*zu + %.*s%.*s", (int)digits, line, (int)(duplicate_start - (size_t)(line_start - source)),
                              line_start, (int)(display_end - (source + duplicate_end)), source + duplicate_end))
        goto done;
    if (!yx_diagnostic_append(&patch, &patch_used, &patch_capacity, "\n%*s|", (int)digits + 1, "")) goto done;
    for (char *at = patch; *at; ++at)
        if (*at == '\t') *at = ' ';
    /* Append the section to the report's rendered text, the last field. */
    json = compiler->warnings[count_before];
    text_field = strstr(json, ",\"text\":\"");
    text_end = json + strlen(json);
    if (!text_field || text_end - json < 2 || text_end[-1] != '}' || text_end[-2] != '"') goto done;
    quoted = yx_json_quoted(patch);
    if (!quoted) goto done;
    {
        size_t head = (size_t)(text_end - 2 - json), added = strlen(quoted) - 2;
        rebuilt = malloc(head + added + 3);
        if (!rebuilt) goto done;
        memcpy(rebuilt, json, head);
        memcpy(rebuilt + head, quoted + 1, added);
        memcpy(rebuilt + head + added, "\"}", 3);
    }
    rebuilt = yx_warning_compact(compiler, rebuilt);
    if (!rebuilt) goto done;
    free(json);
    compiler->warnings[count_before] = rebuilt;
    rebuilt = NULL;
    ok = true;
done:
    free(first_label);
    free(patch);
    free(rebuilt);
    free(quoted);
    return ok;
}

int yx_compiler_ambiguous_expr_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t quantifier_end, size_t end)
{
    const char *line_start, *line_end;
    size_t source_length, line = 1, digits = 1, used = 0, capacity = 0;
    size_t replaced;
    char *base = NULL, *display = NULL, *replacement = NULL;
    char *text = NULL, *json = NULL, **grown;
    bool ok = false;
    if (!compiler || !source) return false;
    source_length = yx_source_text_length(source);
    if (start >= source_length || end > source_length || quantifier_end <= start || quantifier_end > end) return false;
    if (compiler->warning_count >= compiler->max_warnings) return true;
    if (yx_warning_suppressed_span((const uint8_t *)source, source_length, "ambiguous_expr", start, end)) return true;
    line_start = source + start;
    while (line_start > source && line_start[-1] != '\n') --line_start;
    line_end = strchr(line_start, '\n');
    if (!line_end) line_end = source + source_length;
    line_end = yx_diagnostic_display_line_end(line_start, line_end);
    {
        const char *ignored_line_start;
        line = yx_source_line_of(source, (size_t)(line_start - source), &ignored_line_start);
    }
    for (size_t n = line; n >= 10; n /= 10) ++digits;
    if (digits > INT_MAX - 1 || line_end - line_start > INT_MAX) goto done;
    /* The help replaces the quantifier's text (`0`, `0x0`, `1-1`). */
    if (source + quantifier_end > line_end) goto done;
    replaced = quantifier_end - start;
    display = malloc((size_t)(line_end - line_start) + 1);
    replacement = malloc((size_t)(line_end - line_start) + 4);
    if (!display || !replacement) goto done;
    memcpy(display, line_start, (size_t)(line_end - line_start));
    display[line_end - line_start] = '\0';
    for (char *at = display; *at; ++at)
        if (*at == '\t') *at = ' ';
    {
        size_t before = (size_t)(source + start - line_start);
        size_t after = (size_t)(line_end - source - quantifier_end);
        memcpy(replacement, display, before);
        memcpy(replacement + before, "none", 4);
        memcpy(replacement + before + 4, display + before + replaced, after);
        replacement[before + 4 + after] = '\0';
    }
    base = yx_diagnostic_text("warning", "ambiguous_expr", "ambiguous expression", "this expression is ambiguous", source, origin, start, end, NULL);
    if (!base || !yx_diagnostic_append(&text, &used, &capacity,
                                       "%s\n%*s|\nhelp: consider using `none` instead of `0`\n"
                                       "%*s|\n%zu - %s\n%zu + %s\n%*s|",
                                       base, (int)digits + 1, "", (int)digits + 1, "", line, display, line, replacement, (int)digits + 1, ""))
        goto done;
    yx_note_patch(compiler, text, (size_t)(source + start - line_start), replaced, 4);
    json = yx_diagnostic_json("AmbiguousExpression", "ambiguous_expr", "ambiguous expression", "this expression is ambiguous", text, source, origin, start, end, NULL,
                              "warning");
    if (!json || compiler->warning_count >= SIZE_MAX / sizeof(*grown)) goto done;
    grown = realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) goto done;
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) goto done;
    compiler->warnings[compiler->warning_count++] = json;
    json = NULL;
    ok = true;
done:
    free(base);
    free(display);
    free(replacement);
    free(text);
    free(json);
    return ok;
}

/* A function value used as an `and`/`or` operand: no note. */
int yx_compiler_nonbool_function_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    return yx_compiler_warning(compiler, "NonBooleanAsBoolean", "non_bool_expr", "non-boolean expression used as boolean",
                               "this expression is `function` but is being used as `bool`", source, origin, start, end, NULL);
}

int yx_compiler_nonbool_integer_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    return yx_compiler_warning(compiler, "NonBooleanAsBoolean", "non_bool_expr", "non-boolean expression used as boolean",
                               "this expression is `integer` but is being used as `bool`", source, origin, start, end,
                               "non-zero integers are considered `true`, while zero is `false`");
}

int yx_compiler_unintended_pattern_in_set_warning(YRX_COMPILER *compiler, const char *source, const char *origin, const char *pattern_name, const char *set_name,
                                                  size_t set_name_length, const char *first_name, size_t first_name_length, bool first_wildcard, size_t first_start,
                                                  size_t first_end, const char *second_name, size_t second_name_length, bool second_wildcard, size_t second_start,
                                                  size_t second_end)
{
    char *title = NULL, *first_label = NULL, *second_label = NULL;
    size_t title_used = 0, title_capacity = 0;
    size_t first_used = 0, first_capacity = 0;
    size_t second_used = 0, second_capacity = 0;
    bool ok = false;
    if (!pattern_name || !set_name || !first_name || !second_name || set_name_length > INT_MAX || first_name_length > INT_MAX || second_name_length > INT_MAX)
        return false;
    if (!yx_diagnostic_append(&title, &title_used, &title_capacity,
                              "pattern `%s` may be unintendedly or redundantly included "
                              "in pattern set `%.*s*`",
                              pattern_name, (int)set_name_length, set_name) ||
        !yx_diagnostic_append(&first_label, &first_used, &first_capacity, first_wildcard ? "`%s` is included in `%.*s*`" : "`%s` is used here", pattern_name,
                              (int)first_name_length, first_name) ||
        !yx_diagnostic_append(&second_label, &second_used, &second_capacity, second_wildcard ? "`%s` is also included in `%.*s*`" : "`%s` is also used here",
                              pattern_name, (int)second_name_length, second_name))
        goto done;
    ok = yx_compiler_pair_warning(compiler, "UnintendedPatternInSet", "unintended_pattern_in_set", title, source, origin, first_start, first_end, first_label,
                                  second_start, second_end, second_label, false);
done:
    free(title);
    free(first_label);
    free(second_label);
    return ok;
}

static bool yx_slow_filler_bytes(const uint8_t *bytes, size_t length)
{
    if (length < 2 || !bytes || (bytes[0] != 0x00 && bytes[0] != 0x90 && bytes[0] != 0xff)) return false;
    for (size_t i = 1; i < length; ++i)
        if (bytes[i] != bytes[0]) return false;
    return true;
}

static bool yx_same_slow_hex_atoms(const yx_hex_atom *first, const yx_hex_atom *second, size_t count, unsigned depth)
{
    if (depth > 32) return false;
    for (size_t i = 0; i < count; ++i) {
        if (first[i].kind != second[i].kind || first[i].value != second[i].value || first[i].mask != second[i].mask || first[i].negated != second[i].negated ||
            first[i].minimum != second[i].minimum || first[i].maximum != second[i].maximum || first[i].branch_count != second[i].branch_count)
            return false;
        for (size_t branch = 0; branch < first[i].branch_count; ++branch) {
            const yx_hex_sequence *a = &first[i].branches[branch];
            const yx_hex_sequence *b = &second[i].branches[branch];
            if (a->count != b->count || !yx_same_slow_hex_atoms(a->atoms, b->atoms, a->count, depth + 1)) return false;
        }
    }
    return true;
}

/* Two declarations of the same regexp or hex pattern: equal kind,
 * modifiers and source (hex patterns compare their parsed atoms). */
static bool yx_same_slow_pattern(const YRX_PATTERN *first, const YRX_PATTERN *second)
{
    unsigned first_modifiers = first->modifiers;
    unsigned second_modifiers = second->modifiers;
    if (first->kind != second->kind || first->kind == YX_PATTERN_TEXT) return false;
    if (!(first_modifiers & (YX_MOD_ASCII | YX_MOD_WIDE))) first_modifiers |= YX_MOD_ASCII;
    if (!(second_modifiers & (YX_MOD_ASCII | YX_MOD_WIDE))) second_modifiers |= YX_MOD_ASCII;
    if (first_modifiers != second_modifiers) return false;
    if (first->kind == YX_PATTERN_REGEX) return first->regexp && second->regexp && strcmp(first->regexp, second->regexp) == 0;
    return first->hex_atom_count == second->hex_atom_count && yx_same_slow_hex_atoms(first->hex_atoms, second->hex_atoms, first->hex_atom_count, 0);
}

/* The patterns of the compiler's rules by a hash that equal patterns
 * (yx_same_slow_pattern) share, extended as rules are appended: a slow
 * pattern looks at its candidates instead of at every earlier pattern. */
typedef struct yx_slow_pattern_entry {
    uint64_t hash;
    size_t rule, pattern, next; /* next: entry index + 1, 0 ends */
} yx_slow_pattern_entry;
typedef struct yx_slow_pattern_table {
    yx_slow_pattern_entry *entries;
    size_t count, capacity;
    size_t *heads, head_count; /* entry index + 1 per bucket */
} yx_slow_pattern_table;
struct yx_slow_pattern_cache {
    const YRX_RULES *rules;
    size_t scanned;
    const YRX_PATTERN *last; /* patterns of rules[scanned - 1] */
    yx_slow_pattern_table table;
    /* The rule being compiled: its first `current_indexed` patterns, valid
     * while `current_patterns` is set (cleared at each rule's first
     * pattern by yx_compiler_slow_pattern_warning). */
    const YRX_PATTERN *current_patterns;
    size_t current_count, current_indexed;
    yx_slow_pattern_table current;
};

static void yx_slow_pattern_table_free(yx_slow_pattern_table *table)
{
    free(table->entries);
    free(table->heads);
    memset(table, 0, sizeof(*table));
}

static void yx_slow_pattern_table_clear(yx_slow_pattern_table *table)
{
    table->count = 0;
    if (table->heads) memset(table->heads, 0, table->head_count * sizeof(*table->heads));
}

static void yx_slow_pattern_cache_free(struct yx_slow_pattern_cache *cache)
{
    if (!cache) return;
    yx_slow_pattern_table_free(&cache->table);
    yx_slow_pattern_table_free(&cache->current);
    free(cache);
}

static uint64_t yx_slow_hash_mix(uint64_t hash, uint64_t value)
{
    hash ^= value + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6) + (hash >> 2);
    return hash * UINT64_C(0xff51afd7ed558ccd);
}

static uint64_t yx_slow_hex_hash(const yx_hex_atom *atoms, size_t count, unsigned depth, uint64_t hash)
{
    if (depth > 32) return hash;
    for (size_t i = 0; i < count; ++i) {
        hash = yx_slow_hash_mix(hash, (uint64_t)atoms[i].kind);
        hash = yx_slow_hash_mix(hash, atoms[i].value | ((uint64_t)atoms[i].mask << 8) | ((uint64_t)atoms[i].negated << 16));
        hash = yx_slow_hash_mix(hash, atoms[i].minimum | ((uint64_t)atoms[i].maximum << 32));
        hash = yx_slow_hash_mix(hash, (uint64_t)atoms[i].branch_count);
        for (size_t branch = 0; branch < atoms[i].branch_count; ++branch) {
            const yx_hex_sequence *sequence = &atoms[i].branches[branch];
            hash = yx_slow_hash_mix(hash, (uint64_t)sequence->count);
            hash = yx_slow_hex_hash(sequence->atoms, sequence->count, depth + 1, hash);
        }
    }
    return hash;
}

/* False for a pattern that yx_same_slow_pattern finds equal to none. */
static bool yx_slow_pattern_hash(const YRX_PATTERN *pattern, uint64_t *hash)
{
    unsigned modifiers = pattern->modifiers;
    if (pattern->kind == YX_PATTERN_TEXT) return false;
    if (pattern->kind == YX_PATTERN_REGEX && !pattern->regexp) return false;
    if (!(modifiers & (YX_MOD_ASCII | YX_MOD_WIDE))) modifiers |= YX_MOD_ASCII;
    *hash = yx_slow_hash_mix(yx_slow_hash_mix(0, (uint64_t)pattern->kind), (uint64_t)modifiers);
    if (pattern->kind == YX_PATTERN_REGEX) {
        for (const unsigned char *at = (const unsigned char *)pattern->regexp; *at; ++at) *hash = (*hash ^ *at) * UINT64_C(1099511628211);
        return true;
    }
    *hash = yx_slow_hash_mix(*hash, (uint64_t)pattern->hex_atom_count);
    *hash = yx_slow_hex_hash(pattern->hex_atoms, pattern->hex_atom_count, 0, *hash);
    return true;
}

static bool yx_slow_pattern_table_rehash(yx_slow_pattern_table *table, size_t head_count)
{
    size_t *heads;
    if (head_count > SIZE_MAX / sizeof(*heads)) return false;
    heads = (size_t *)calloc(head_count, sizeof(*heads));
    if (!heads) return false;
    for (size_t i = 0; i < table->count; ++i) {
        size_t bucket = (size_t)table->entries[i].hash & (head_count - 1);
        table->entries[i].next = heads[bucket];
        heads[bucket] = i + 1;
    }
    free(table->heads);
    table->heads = heads;
    table->head_count = head_count;
    return true;
}

static bool yx_slow_pattern_table_add(yx_slow_pattern_table *table, uint64_t hash, size_t rule, size_t pattern)
{
    size_t bucket;
    if (table->count == table->capacity) {
        size_t capacity = table->capacity ? table->capacity * 2 : 256;
        yx_slow_pattern_entry *grown;
        if (capacity <= table->capacity || capacity > SIZE_MAX / sizeof(*grown)) return false;
        grown = (yx_slow_pattern_entry *)realloc(table->entries, capacity * sizeof(*grown));
        if (!grown) return false;
        table->entries = grown;
        table->capacity = capacity;
    }
    if ((table->count + 1) * 2 > table->head_count && !yx_slow_pattern_table_rehash(table, table->head_count ? table->head_count * 2 : 512)) return false;
    bucket = (size_t)hash & (table->head_count - 1);
    table->entries[table->count] = (yx_slow_pattern_entry){hash, rule, pattern, table->heads[bucket]};
    table->heads[bucket] = ++table->count;
    return true;
}

/* Brings the cache up to the compiler's rules, starting over when the
 * rule list no longer extends what was scanned. */
static bool yx_slow_pattern_cache_update(struct yx_slow_pattern_cache *cache, const YRX_RULES *rules)
{
    if (cache->rules != rules || rules->rule_count < cache->scanned || (cache->scanned && rules->rules[cache->scanned - 1].patterns != cache->last)) {
        cache->rules = rules;
        cache->scanned = 0;
        cache->last = NULL;
        yx_slow_pattern_table_clear(&cache->table);
    }
    for (; cache->scanned < rules->rule_count; ++cache->scanned) {
        const YRX_RULE *rule = &rules->rules[cache->scanned];
        for (size_t j = 0; j < rule->pattern_count; ++j) {
            uint64_t hash;
            if (!yx_slow_pattern_hash(&rule->patterns[j], &hash)) continue;
            if (!yx_slow_pattern_table_add(&cache->table, hash, cache->scanned, j)) return false;
        }
        cache->last = rule->patterns;
    }
    return true;
}

/* Brings the current-rule table up to the patterns of `rule` before
 * index `limit`, starting over for another rule. */
static bool yx_slow_pattern_cache_current(struct yx_slow_pattern_cache *cache, const YRX_RULE *rule, size_t limit)
{
    if (cache->current_patterns != rule->patterns || cache->current_count != rule->pattern_count) {
        cache->current_patterns = rule->patterns;
        cache->current_count = rule->pattern_count;
        cache->current_indexed = 0;
        yx_slow_pattern_table_clear(&cache->current);
    }
    for (; cache->current_indexed < limit; ++cache->current_indexed) {
        uint64_t hash;
        if (!yx_slow_pattern_hash(&rule->patterns[cache->current_indexed], &hash)) continue;
        if (!yx_slow_pattern_table_add(&cache->current, hash, 0, cache->current_indexed)) {
            cache->current_patterns = NULL;
            return false;
        }
    }
    return true;
}

/* Whether an earlier declaration `earlier->patterns[j]` equal to `pattern`
 * has the same anchor offset and match limit. */
static bool yx_slow_pattern_same_use(const YRX_RULE *earlier, size_t j, const YRX_PATTERN *pattern, bool current_fixed, size_t current_offset, bool current_all,
                                     bool current_counted, size_t current_count)
{
    size_t earlier_offset = SIZE_MAX, earlier_count = 0;
    bool earlier_fixed, earlier_all, earlier_counted;
    if (!yx_same_slow_pattern(&earlier->patterns[j], pattern)) return false;
    earlier_fixed = yx_condition_pattern_fixed_at(earlier->condition, earlier->patterns[j].identifier, &earlier_offset);
    earlier_all = yx_condition_pattern_requires_all_matches(earlier->condition, earlier->patterns[j].identifier);
    earlier_counted = yx_condition_pattern_fast_count(earlier->condition, earlier->patterns[j].identifier, &earlier_count);
    if (earlier_counted && earlier_count <= 1) earlier_counted = earlier_all = false;
    return current_fixed == earlier_fixed && (!current_fixed || current_offset == earlier_offset) && current_all == earlier_all && current_counted == earlier_counted &&
           (!current_counted || current_count == earlier_count);
}

/* Compiler::c_rule reuses the PatternId of an equal pattern declared
 * earlier in the rule or in a rule added before, and only a new PatternId
 * reaches c_regexp. Equality includes the anchor offset and the fast-scan
 * match limit the condition imposes. */
static bool yx_previously_compiled_slow_pattern(const YRX_COMPILER *compiler, const YRX_RULE *rule, const YRX_PATTERN *pattern)
{
    size_t current_offset = SIZE_MAX, current_count = 0;
    bool current_fixed = yx_condition_pattern_fixed_at(rule->condition, pattern->identifier, &current_offset);
    bool current_all = yx_condition_pattern_requires_all_matches(rule->condition, pattern->identifier);
    bool current_counted = yx_condition_pattern_fast_count(rule->condition, pattern->identifier, &current_count);
    struct yx_slow_pattern_cache *cache = NULL;
    uint64_t hash = 0;
    bool hashed;
    /* A one-match limit is the default limit of a bare `$a`. */
    if (current_counted && current_count <= 1) current_counted = current_all = false;
    hashed = yx_slow_pattern_hash(pattern, &hash);
    if (!hashed) return false;
    if (compiler->rules) {
        YRX_COMPILER *owner = (YRX_COMPILER *)compiler;
        if (!owner->slow_pattern_cache) owner->slow_pattern_cache = (struct yx_slow_pattern_cache *)calloc(1, sizeof(*owner->slow_pattern_cache));
        cache = owner->slow_pattern_cache;
        if (cache && !yx_slow_pattern_cache_update(cache, compiler->rules)) {
            /* Without memory: drop the index, search every rule. */
            yx_slow_pattern_cache_free(cache);
            owner->slow_pattern_cache = cache = NULL;
        }
    }
    /* The rules' candidates in the index (a declaration at or after
     * `pattern` in its own pattern list does not count), then the earlier
     * patterns of `rule` itself; the order does not change the answer. */
    for (size_t at = cache && cache->table.head_count ? cache->table.heads[(size_t)hash & (cache->table.head_count - 1)] : 0; at;
         at = cache->table.entries[at - 1].next) {
        const yx_slow_pattern_entry *entry = &cache->table.entries[at - 1];
        const YRX_RULE *earlier;
        size_t j = entry->pattern, earlier_offset = SIZE_MAX, earlier_count = 0;
        bool earlier_fixed, earlier_all, earlier_counted;
        if (entry->hash != hash || entry->rule >= compiler->rules->rule_count) continue;
        earlier = &compiler->rules->rules[entry->rule];
        if (j >= earlier->pattern_count) continue;
        if ((uintptr_t)pattern >= (uintptr_t)earlier->patterns && (uintptr_t)pattern < (uintptr_t)(earlier->patterns + earlier->pattern_count) &&
            j >= (size_t)(pattern - earlier->patterns))
            continue;
        if (!yx_same_slow_pattern(&earlier->patterns[j], pattern)) continue;
        earlier_fixed = yx_condition_pattern_fixed_at(earlier->condition, earlier->patterns[j].identifier, &earlier_offset);
        earlier_all = yx_condition_pattern_requires_all_matches(earlier->condition, earlier->patterns[j].identifier);
        earlier_counted = yx_condition_pattern_fast_count(earlier->condition, earlier->patterns[j].identifier, &earlier_count);
        if (earlier_counted && earlier_count <= 1) earlier_counted = earlier_all = false;
        if (current_fixed == earlier_fixed && (!current_fixed || current_offset == earlier_offset) && current_all == earlier_all && current_counted == earlier_counted &&
            (!current_counted || current_count == earlier_count))
            return true;
    }
    /* The earlier patterns of `rule` itself: those before `pattern` when it
     * is one of them, else all. */
    if (cache) {
        size_t limit = rule->pattern_count;
        if ((uintptr_t)pattern >= (uintptr_t)rule->patterns && (uintptr_t)pattern < (uintptr_t)(rule->patterns + rule->pattern_count))
            limit = (size_t)(pattern - rule->patterns);
        if (yx_slow_pattern_cache_current(cache, rule, limit)) {
            for (size_t at = cache->current.head_count ? cache->current.heads[(size_t)hash & (cache->current.head_count - 1)] : 0; at;
                 at = cache->current.entries[at - 1].next) {
                const yx_slow_pattern_entry *entry = &cache->current.entries[at - 1];
                if (entry->hash != hash || entry->pattern >= limit) continue;
                if (yx_slow_pattern_same_use(rule, entry->pattern, pattern, current_fixed, current_offset, current_all, current_counted, current_count)) return true;
            }
            return false;
        }
    }
    for (size_t r = cache ? compiler->rules->rule_count : 0; r <= (compiler->rules ? compiler->rules->rule_count : 0); ++r) {
        const YRX_RULE *earlier = compiler->rules && r < compiler->rules->rule_count ? &compiler->rules->rules[r] : rule;
        for (size_t j = 0; j < earlier->pattern_count; ++j) {
            size_t earlier_offset = SIZE_MAX, earlier_count = 0;
            bool earlier_fixed, earlier_all, earlier_counted;
            if (&earlier->patterns[j] == pattern) break;
            if (!yx_same_slow_pattern(&earlier->patterns[j], pattern)) continue;
            earlier_fixed = yx_condition_pattern_fixed_at(earlier->condition, earlier->patterns[j].identifier, &earlier_offset);
            earlier_all = yx_condition_pattern_requires_all_matches(earlier->condition, earlier->patterns[j].identifier);
            earlier_counted = yx_condition_pattern_fast_count(earlier->condition, earlier->patterns[j].identifier, &earlier_count);
            if (earlier_counted && earlier_count <= 1) earlier_counted = earlier_all = false;
            if (current_fixed == earlier_fixed && (!current_fixed || current_offset == earlier_offset) && current_all == earlier_all &&
                current_counted == earlier_counted && (!current_counted || current_count == earlier_count))
                return true;
        }
    }
    return false;
}

int yx_compiler_slow_pattern_warning(YRX_COMPILER *compiler, const YRX_RULE *rule, const YRX_PATTERN *pattern, const char *source, const char *origin, bool compiled)
{
    static const char *extreme_note = "this is an exceptionally extreme case that may severely degrade scanning throughput";
    size_t start, end, anchored_offset = SIZE_MAX, call_count = 0;
    uint8_t *calls = NULL;
    bool literal_slow = false;
    int result = 1;
    /* Each rule's patterns are checked from its first one: the current-rule
     * index of yx_previously_compiled_slow_pattern starts over there. */
    if (compiler && compiler->slow_pattern_cache && rule && pattern && pattern == rule->patterns) compiler->slow_pattern_cache->current_patterns = NULL;
    if (!rule->condition || !source || !pattern || pattern->literal_end <= pattern->literal_start) return 1;
    /* Rules rebuilt from a compiled archive discard their warnings
     * (max_warnings is 0): skip the atom analysis that only feeds them. */
    if ((compiler->warning_count >= compiler->max_warnings || yx_compiler_warning_skipped(compiler, "slow_pattern")) && !(compiler->flags & YRX_ERROR_ON_SLOW_PATTERN))
        return 1;
    start = pattern->kind == YX_PATTERN_HEX ? pattern->literal_start : pattern->declaration_start;
    end = pattern->kind == YX_PATTERN_HEX ? pattern->literal_end : pattern->pattern_end;
    if (pattern->kind == YX_PATTERN_TEXT) {
        if (compiled) return 1;
        literal_slow = pattern->length == 1 || yx_slow_filler_bytes(pattern->bytes, pattern->length);
    } else {
        /* A pattern outside the model's grammar is not reported. */
        int model = yx_ser_slow_pattern(pattern, &literal_slow, &calls, &call_count);
        if (model < 0) return 0;
    }
    if (!compiled) {
        /* The literal check skips anchored patterns and the modifiers that
         * make a common byte sequence uncommon. */
        free(calls);
        if (!literal_slow || (pattern->modifiers & (YX_MOD_FULLWORD | YX_MOD_XOR | YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) ||
            yx_condition_pattern_fixed_at(rule->condition, pattern->identifier, &anchored_offset))
            return 1;
        if (compiler->flags & YRX_ERROR_ON_SLOW_PATTERN)
            return yx_compiler_slow_error(compiler, "SlowPattern", "E018", "slow pattern", "this pattern may slow down the scan", source, origin, start, end, NULL);
        return yx_compiler_warning(compiler, "SlowPattern", "slow_pattern", "slow pattern", "this pattern may slow down the scan", source, origin, start, end, NULL) ? 1
                                                                                                                                                                     : 0;
    }
    /* c_regexp runs once per new PatternId, anchored or not. The scan for
     * an earlier equal pattern only matters when some call is slow. */
    bool any_slow = false;
    for (size_t i = 0; i < call_count; ++i) any_slow |= calls[i] != 0;
    if (any_slow && !yx_previously_compiled_slow_pattern(compiler, rule, pattern)) {
        for (size_t i = 0; i < call_count && result == 1; ++i) {
            if (!calls[i]) continue;
            if (compiler->flags & YRX_ERROR_ON_SLOW_PATTERN)
                result = yx_compiler_slow_error(compiler, "SlowPattern", "E018", "slow pattern", "this pattern may slow down the scan", source, origin, start, end,
                                                calls[i] == 2 ? extreme_note : NULL);
            else if (!yx_compiler_warning(compiler, "SlowPattern", "slow_pattern", "slow pattern", "this pattern may slow down the scan", source, origin, start, end,
                                          calls[i] == 2 ? extreme_note : NULL))
                result = 0;
        }
    }
    free(calls);
    return result;
}

static int yx_compiler_redundant_case_modifier_warning_source(YRX_COMPILER *compiler, const char *source, const char *origin, size_t suffix_start, size_t nocase_start,
                                                              size_t nocase_end);

/* A source with escaped NULs renders from its display copy, built once per
 * source and only when the warning can still be recorded. */
int yx_compiler_redundant_case_modifier_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t suffix_start, size_t nocase_start,
                                                size_t nocase_end)
{
    yx_nul_escape_entry *entry = yx_nul_escape_find(compiler, source);
    const char *display = NULL;
    unsigned char space;
    int ok;
    /* Past the warning limit the plain call returns without rendering. */
    if (entry && compiler->warning_count < compiler->max_warnings) display = yx_nul_escape_display(entry);
    if (!display) return yx_compiler_redundant_case_modifier_warning_source(compiler, source, origin, suffix_start, nocase_start, nocase_end);
    space = compiler->nul_json_space;
    compiler->nul_json_space = YX_NUL_SPACE_DISPLAY;
    ok = yx_compiler_redundant_case_modifier_warning_source(compiler, display, origin,
                                                            yx_nul_escape_map(entry, suffix_start, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, false),
                                                            yx_nul_escape_map(entry, nocase_start, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, false),
                                                            yx_nul_escape_map(entry, nocase_end, YX_NUL_SPACE_ESCAPED, YX_NUL_SPACE_DISPLAY, true));
    compiler->nul_json_space = space;
    return ok;
}

static int yx_compiler_redundant_case_modifier_warning_source(YRX_COMPILER *compiler, const char *source, const char *origin, size_t suffix_start, size_t nocase_start,
                                                              size_t nocase_end)
{
    static const char *title = "redundant case-insensitive modifier";
    static const char *suffix_label = "the `i` suffix indicates that the pattern is case-insensitive";
    static const char *nocase_label = "the `nocase` modifier does the same";
    size_t source_length, first_line = 1, last_line = 1;
    size_t first_column, last_column, digits = 1;
    size_t used = 0, capacity = 0, json_used = 0, json_capacity = 0;
    const char *first_start = source, *last_start = source;
    char *text = NULL, *json = NULL, *quoted_text = NULL;
    char *quoted_origin = NULL, **grown;
    if (!compiler || !source) return 0;
    source_length = yx_source_text_length(source);
    if (suffix_start >= source_length || nocase_start > nocase_end || nocase_end > source_length || suffix_start >= nocase_start || source[suffix_start] != 'i' ||
        nocase_end - nocase_start != 6 || memcmp(source + nocase_start, "nocase", 6) != 0)
        return 0;
    if (compiler->warning_count >= compiler->max_warnings) return 1;
    if (yx_warning_suppressed_span((const uint8_t *)source, source_length, "redundant_modifier", suffix_start, suffix_start + 1) ||
        yx_warning_suppressed_span((const uint8_t *)source, source_length, "redundant_modifier", nocase_start, nocase_end))
        return 1;
    first_line = yx_source_line_of(source, suffix_start, &first_start);
    last_line = first_line;
    last_start = first_start;
    for (size_t i = suffix_start; i < nocase_start; ++i)
        if (source[i] == '\n') {
            ++last_line;
            last_start = source + i + 1;
        }
    first_column = yx_diagnostic_columns(first_start, source + suffix_start) + 1;
    last_column = yx_diagnostic_columns(last_start, source + nocase_start) + 1;
    if (last_line == first_line && last_column <= first_column) return 0;
    /* Lines the renderer's margin cuts (long, deeply indented or not plain
     * ASCII) are drawn by the general snippet renderer too. */
    if (last_line > first_line + 1 || yx_snippet_margin_applies(source, (const size_t[]){suffix_start, nocase_start}, 2)) {
        /* The line between the labels, or `...` for several. */
        yx_snippet_label labels[2] = {{suffix_start, suffix_start + 1, suffix_label, false}, {nocase_start, nocase_end, nocase_label, false}};
        if (compiler->warning_count >= compiler->max_warnings) return 1;
        text = yx_diagnostic_snippet("warning", "redundant_modifier", title, source, origin, labels, 2, first_line, first_column);
        if (!text) goto failure;
        used = strlen(text);
        goto json;
    }
    for (size_t n = last_line; n >= 10; n /= 10) ++digits;
    if (digits > INT_MAX - 1 || first_column > INT_MAX || last_column > INT_MAX || nocase_end - nocase_start > INT_MAX) return 0;
    if (!yx_diagnostic_append(&text, &used, &capacity, "warning[redundant_modifier]: %s\n%*s--> %s:%zu:%zu\n%*s|\n", title, (int)digits, "", origin ? origin : "line",
                              first_line, first_column, (int)digits + 1, ""))
        goto failure;
    const char *line_start = first_start;
    for (size_t line = first_line; line <= last_line; ++line) {
        const char *line_end = strchr(line_start, '\n');
        size_t line_length;
        char *display;
        if (!line_end) line_end = source + source_length;
        line_length = (size_t)(line_end - line_start);
        if (line_length && line_start[line_length - 1] == '\r') --line_length;
        if (line_length > INT_MAX) goto failure;
        display = (char *)malloc(line_length + 1);
        if (!display) goto failure;
        memcpy(display, line_start, line_length);
        display[line_length] = '\0';
        for (size_t i = 0; i < line_length; ++i)
            if (display[i] == '\t') display[i] = ' ';
        if (!yx_diagnostic_append(&text, &used, &capacity, "%*zu |%s%.*s\n", (int)digits, line, line_length ? " " : "", (int)line_length, display)) {
            free(display);
            goto failure;
        }
        free(display);
        if (line == first_line && line == last_line) {
            size_t between = last_column - first_column - 1;
            if (between > INT_MAX || !yx_diagnostic_append(&text, &used, &capacity, "%*s| %*s-%*s%.*s %s\n%*s| %*s|\n%*s| %*s%s", (int)digits + 1, "",
                                                           (int)first_column - 1, "", (int)between, "", (int)(nocase_end - nocase_start), "------", nocase_label,
                                                           (int)digits + 1, "", (int)first_column - 1, "", (int)digits + 1, "", (int)first_column - 1, "", suffix_label))
                goto failure;
        } else if (line == first_line) {
            if (!yx_diagnostic_append(&text, &used, &capacity, "%*s| %*s- %s\n", (int)digits + 1, "", (int)first_column - 1, "", suffix_label)) goto failure;
        } else if (line == last_line) {
            if (!yx_diagnostic_append(&text, &used, &capacity, "%*s| %*s%.*s %s", (int)digits + 1, "", (int)last_column - 1, "", (int)(nocase_end - nocase_start),
                                      "------", nocase_label))
                goto failure;
        }
        line_start = line_end + (*line_end == '\n');
    }
json:
    if (!yx_diagnostic_normalize_visible_cr(&text)) goto failure;
    quoted_text = yx_json_quoted(text);
    quoted_origin = yx_json_quoted_code_origin(origin);
    if (!quoted_text || !quoted_origin ||
        !yx_diagnostic_append(&json, &json_used, &json_capacity,
                              "{\"type\":\"RedundantCaseModifier\","
                              "\"code\":\"redundant_modifier\",\"title\":\"%s\","
                              "\"line\":%zu,\"column\":%zu,\"labels\":["
                              "{\"level\":\"warning\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":\"%s\"},"
                              "{\"level\":\"warning\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":\"%s\"}],"
                              "\"footers\":[],\"text\":%s}",
                              title, first_line, first_column, quoted_origin, first_line, first_column, suffix_start, suffix_start + 1, suffix_label, quoted_origin,
                              last_line, last_column, nocase_start, nocase_end, nocase_label, quoted_text))
        goto failure;
    if (compiler->warning_count >= SIZE_MAX / sizeof(*grown)) goto failure;
    grown = (char **)realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) goto failure;
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) goto failure;
    compiler->warnings[compiler->warning_count++] = json;
    free(text);
    free(quoted_text);
    free(quoted_origin);
    return 1;
failure:
    free(text);
    free(json);
    free(quoted_text);
    free(quoted_origin);
    return 0;
}

typedef enum {
    YX_DEPRECATED_ROOT,
    YX_DEPRECATED_MACHO_FILE,
    YX_DEPRECATED_DOTNET_CLASS,
    YX_DEPRECATED_DOTNET_METHOD,
    YX_DEPRECATED_OTHER
} yx_deprecated_scope;

typedef struct {
    const char *module;
    yx_deprecated_scope scope;
    const char *field;
    const char *replacement;
    const char *help;
} yx_deprecated_field;

/* Keep this list aligned with deprecation_notice in the public module
 * schemas. A warning is emitted only after the whole rule has passed semantic
 * validation, so a similarly named user symbol does not produce one. */
static const yx_deprecated_field yx_deprecated_fields[] = {
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_streams", "streams.len()", "use `dotnet.streams.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_guids", "guids.len()", "use `dotnet.guids.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_resources", "resources.len()", "use `dotnet.resources.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_classes", "classes.len()", "use `dotnet.classes.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_assembly_refs", "assembly_refs.len()", "use `dotnet.assembly_refs.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_modulerefs", "modulerefs.len()", "use `dotnet.modulerefs.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_user_strings", "user_strings.len()", "use `dotnet.user_strings.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_constants", "constants.len()", "use `dotnet.constants.len()` instead"},
    {"dotnet", YX_DEPRECATED_ROOT, "number_of_field_offsets", "field_offsets.len()", "use `dotnet.field_offsets.len()` instead"},
    {"elf", YX_DEPRECATED_ROOT, "number_of_sections", "sections.len()", "use `elf.sections.len()` instead"},
    {"elf", YX_DEPRECATED_ROOT, "number_of_segments", "segments.len()", "use `elf.segments.len()` instead"},
    {"pe", YX_DEPRECATED_ROOT, "number_of_sections", "sections.len()", "use `pe.sections.len()` instead"},
    {"pe", YX_DEPRECATED_ROOT, "number_of_resources", "resources.len()", "use `pe.resources.len()` instead"},
    {"pe", YX_DEPRECATED_ROOT, "number_of_signatures", "signatures.len()", "use `pe.signatures.len()` instead"},
    {"macho", YX_DEPRECATED_ROOT, "number_of_segments", "segments.len()", "use `macho.segments.len()` instead"},
    {"macho", YX_DEPRECATED_MACHO_FILE, "number_of_segments", "segments.len()", "use `segments.len()` instead"},
    {"dotnet", YX_DEPRECATED_DOTNET_CLASS, "number_of_base_types", "base_types.len()", "use `base_types.len()` instead"},
    {"dotnet", YX_DEPRECATED_DOTNET_CLASS, "number_of_generic_parameters", "generic_parameters.len()", "use `generic_parameters.len()` instead"},
    {"dotnet", YX_DEPRECATED_DOTNET_CLASS, "number_of_methods", "methods.len()", "use `methods.len()` instead"},
    {"dotnet", YX_DEPRECATED_DOTNET_METHOD, "number_of_generic_parameters", "generic_parameters.len()", "use `generic_parameters.len()` instead"},
    {"dotnet", YX_DEPRECATED_DOTNET_METHOD, "number_of_parameters", "parameters.len()", "use `parameters.len()` instead"}};

static bool yx_warning_identifier_is(const char *start, size_t length, const char *name)
{
    return strlen(name) == length && memcmp(start, name, length) == 0;
}

static bool yx_warning_module_imported(const YRX_COMPILER *compiler, const char *module)
{
    for (size_t i = 0; i < compiler->rules->import_count; ++i)
        if (strcmp(compiler->rules->imports[i], module) == 0) return true;
    return false;
}

static bool yx_compiler_deprecated_field_warning(YRX_COMPILER *compiler, const yx_deprecated_field *field, const char *source, const char *origin, size_t start,
                                                 size_t end)
{
    const char *line_start = source, *line_end;
    size_t line = 1, digits = 1, used, capacity;
    size_t prefix_length, suffix_length, line_length;
    char title[160];
    const char *label = strcmp(field->module, "test_proto2") == 0 ? "don't use" : "this field is deprecated";
    char *text, *json, **grown, *rendered_line = NULL;
    if (yx_compiler_warning_skipped(compiler, "deprecated_field")) return true;
    if (compiler->warning_count >= compiler->max_warnings) return true;
    if (yx_warning_suppressed_span((const uint8_t *)source, yx_source_text_length(source), "deprecated_field", start, end)) return true;
    line = yx_source_line_of(source, start, &line_start);
    for (size_t n = line; n >= 10; n /= 10) ++digits;
    line_end = strchr(line_start, '\n');
    if (!line_end) line_end = source + yx_source_text_length(source);
    /* The patch lines end before a CRLF's CR, as the snippet does. */
    if (line_end > source + end && line_end[-1] == '\r') --line_end;
    if (source + end > line_end) return false;
    prefix_length = (size_t)((source + start) - line_start);
    suffix_length = (size_t)(line_end - (source + end));
    line_length = (size_t)(line_end - line_start);
    if (line_length > INT_MAX || prefix_length > INT_MAX || suffix_length > INT_MAX || digits > INT_MAX - 1) return false;
    if (memchr(line_start, '\t', line_length)) {
        rendered_line = (char *)malloc(line_length + 1);
        if (!rendered_line) return false;
        memcpy(rendered_line, line_start, line_length);
        rendered_line[line_length] = '\0';
        for (size_t i = 0; i < line_length; ++i)
            if (rendered_line[i] == '\t') rendered_line[i] = ' ';
        line_start = rendered_line;
    }
    snprintf(title, sizeof(title), "field `%s` is deprecated", field->field);
    text = yx_diagnostic_text("warning", "deprecated_field", title, label, source, origin, start, end, NULL);
    if (!text) {
        free(rendered_line);
        return false;
    }
    used = strlen(text);
    capacity = used + 1;
    if (!yx_diagnostic_append(&text, &used, &capacity, "\n%*s|\nhelp: %s\n%*s|\n%zu - %.*s\n%zu + %.*s%s%.*s\n%*s|", (int)digits + 1, "", field->help, (int)digits + 1,
                              "", line, (int)line_length, line_start, line, (int)prefix_length, line_start, field->replacement, (int)suffix_length,
                              line_start + prefix_length + (end - start), (int)digits + 1, "")) {
        free(text);
        free(rendered_line);
        return false;
    }
    yx_note_patch(compiler, text, prefix_length, end - start, strlen(field->replacement));
    free(rendered_line);
    json = yx_diagnostic_json("DeprecatedField", "deprecated_field", title, label, text, source, origin, start, end, NULL, "warning");
    free(text);
    if (!json || compiler->warning_count >= SIZE_MAX / sizeof(*grown)) {
        free(json);
        return false;
    }
    grown = (char **)realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) {
        free(json);
        return false;
    }
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) return false;
    compiler->warnings[compiler->warning_count++] = json;
    return true;
}

/* Add a source replacement to the last generated warning. Patches appear in
 * the rendered report; the public JSON keeps its labels and note footers. */
static bool yx_compiler_warning_patch(YRX_COMPILER *compiler, const char *source, size_t start, size_t end, const char *replacement, const char *note)
{
    char *stored = compiler->warnings[compiler->warning_count - 1];
    /* The stored form may refer to kept rows; the patch reads its text. */
    char *old = stored[0] == YX_WARNING_COMPACT ? yx_warning_expand(compiler, stored, NULL) : stored;
    const char *tail = old ? strstr(old, "\"footers\":[],\"text\":") : NULL;
    const char *line_start = source + start, *line_end = source + end;
    size_t line = 1, end_line, digits = 1, used, capacity, json_used = 0;
    size_t json_capacity = 0;
    char *text = NULL, *shown = NULL, *patched = NULL, *quoted = NULL;
    char *quoted_note = NULL, *json = NULL;
    xx_json parser;
    bool ok = false;
    if (!tail) {
        if (old != stored) free(old);
        return false;
    }
    while (line_start > source && line_start[-1] != '\n') --line_start;
    while (*line_end && *line_end != '\n') ++line_end;
    {
        const char *ignored_line_start;
        line = yx_source_line_of(source, (size_t)(line_start - source), &ignored_line_start);
    }
    end_line = line;
    for (const char *at = line_start; at < line_end; ++at)
        if (*at == '\n') ++end_line;
    for (size_t value = end_line; value >= 10; value /= 10) ++digits;
    const char *encoded = tail + strlen("\"footers\":[],\"text\":");
    xx_json_init(&parser, encoded, strlen(encoded));
    if (!xx_json_string(&parser, &text)) goto done;
    used = strlen(text);
    capacity = used + 1;
    if (note && !yx_diagnostic_append(&text, &used, &capacity, "\n%*s|\n%*s= note: %s", (int)digits + 1, "", (int)digits + 1, "", note)) goto done;
    if (!note && !yx_diagnostic_append(&text, &used, &capacity, "\n%*s|", (int)digits + 1, "")) goto done;
    if (!yx_diagnostic_append(&text, &used, &capacity, "\nhelp: consider the following change\n%*s|", (int)digits + 1, "")) goto done;
    size_t old_length = (size_t)(line_end - line_start);
    size_t prefix_length = (size_t)((source + start) - line_start);
    size_t suffix_length = (size_t)(line_end - (source + end));
    size_t replacement_length = strlen(replacement);
    if (prefix_length > SIZE_MAX - replacement_length - suffix_length - 1) goto done;
    shown = malloc(old_length + 1);
    patched = malloc(prefix_length + replacement_length + suffix_length + 1);
    if (!shown || !patched) goto done;
    memcpy(shown, line_start, old_length);
    shown[old_length] = '\0';
    memcpy(patched, line_start, prefix_length);
    memcpy(patched + prefix_length, replacement, replacement_length);
    memcpy(patched + prefix_length + replacement_length, source + end, suffix_length);
    patched[prefix_length + replacement_length + suffix_length] = '\0';
    for (char *at = shown; *at; ++at)
        if (*at == '\t') *at = ' ';
    for (char *at = patched; *at; ++at)
        if (*at == '\t') *at = ' ';
    const char *groups[] = {shown, patched};
    bool split_line = !strchr(shown, '\n') && strchr(patched, '\n') != NULL;
    for (size_t group = split_line ? 1 : 0; group < 2; ++group) {
        const char *at = groups[group];
        size_t number = line;
        do {
            const char *next = strchr(at, '\n');
            size_t length = next ? (size_t)(next - at) : strlen(at);
            if (length > INT_MAX || !yx_diagnostic_append(&text, &used, &capacity, "\n%*zu %c %.*s", (int)digits, number++,
                                                          split_line && at == patched ? '~'
                                                          : group                     ? '+'
                                                                                      : '-',
                                                          (int)length, at))
                goto done;
            at = next ? next + 1 : NULL;
        } while (at);
    }
    if (!yx_diagnostic_append(&text, &used, &capacity, "\n%*s|", (int)digits + 1, "")) goto done;
    yx_note_patch(compiler, text, prefix_length, end - start, replacement_length);
    quoted = yx_json_quoted(text);
    quoted_note = note ? yx_json_quoted(note) : NULL;
    if (!quoted || (note && !quoted_note) || (size_t)(tail - old) > INT_MAX) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity, "%.*s\"footers\":[", (int)(tail - old), old)) goto done;
    if (note && !yx_diagnostic_append(&json, &json_used, &json_capacity, "{\"level\":\"note\",\"text\":%s}", quoted_note)) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity, "],\"text\":%s}", quoted)) goto done;
    json = yx_warning_compact(compiler, json);
    if (!json) goto done;
    compiler->warnings[compiler->warning_count - 1] = json;
    json = NULL;
    free(stored);
    ok = true;
done:
    if (old != stored) free(old);
    free(text);
    free(shown);
    free(patched);
    free(quoted);
    free(quoted_note);
    free(json);
    return ok;
}

static bool yx_warning_string_case_replacement(const char *source, size_t start, size_t end, bool upper, char **replacement, bool *changed)
{
    if (end - start < 2 || source[start] != '"' || source[end - 1] != '"') return false;
    char *decoded = malloc(end - start + 3), *mapped = NULL;
    size_t length = 0, mapped_length = 0;
    if (!decoded) return false;
    for (size_t i = start + 1; i + 1 < end; ++i) {
        unsigned char ch = (unsigned char)source[i];
        if (ch == '\\' && i + 2 < end) {
            ch = (unsigned char)source[++i];
            if (ch == 'n') ch = '\n';
            else if (ch == 'r') ch = '\r';
            else if (ch == 't') ch = '\t';
            else if (ch == '0') ch = 0;
            else if (ch == 'x' && i + 3 < end) {
                unsigned value = 0;
                for (unsigned digit = 0; digit < 2; ++digit) {
                    unsigned char h = (unsigned char)source[++i];
                    value = value * 16 + (h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10 : h - 'A' + 10);
                }
                ch = (unsigned char)value;
            }
        }
        decoded[length++] = (char)ch;
    }
    decoded[length] = '\0';
    *changed = xx_string_has_case_property((const uint8_t *)decoded, length, !upper);
    char *lossy = NULL;
    size_t lossy_length = 0;
    bool ok = xx_string_utf8_lossy((const uint8_t *)decoded, length, NULL, 0, &lossy_length) && (lossy = malloc(lossy_length + 1)) != NULL &&
              xx_string_utf8_lossy((const uint8_t *)decoded, length, lossy, lossy_length + 1, &lossy_length);
    free(decoded);
    if (!ok) {
        free(lossy);
        return false;
    }
    ok = upper ? xx_string_to_upper_alloc((const uint8_t *)lossy, lossy_length, &mapped, &mapped_length)
               : xx_string_to_lower_alloc((const uint8_t *)lossy, lossy_length, &mapped, &mapped_length);
    free(lossy);
    if (!ok) return false;
    char *visible = yx_diagnostic_render_fragment(mapped, mapped_length);
    free(mapped);
    if (!visible) return false;
    size_t visible_length = strlen(visible);
    *replacement = malloc(visible_length + 3);
    if (!*replacement) {
        free(visible);
        return false;
    }
    (*replacement)[0] = '"';
    memcpy(*replacement + 1, visible, visible_length);
    (*replacement)[visible_length + 1] = '"';
    (*replacement)[visible_length + 2] = '\0';
    free(visible);
    return true;
}

/* Remembers where YARA-X raises the warning just added (see
 * warning_point_keys in internal.h). */
static bool yx_compiler_note_warning_point(YRX_COMPILER *compiler, size_t count, size_t point)
{
    if (compiler->warning_count != count + 1) return true;
    if (compiler->warning_point_count == compiler->warning_point_capacity) {
        size_t grown = compiler->warning_point_capacity ? compiler->warning_point_capacity * 2 : 16;
        const char **keys = (const char **)realloc((void *)compiler->warning_point_keys, grown * sizeof(*keys));
        size_t *values;
        if (!keys) return false;
        compiler->warning_point_keys = keys;
        values = (size_t *)realloc(compiler->warning_point_values, grown * sizeof(*values));
        if (!values) return false;
        compiler->warning_point_values = values;
        compiler->warning_point_capacity = grown;
    }
    compiler->warning_point_keys[compiler->warning_point_count] = compiler->warnings[count];
    compiler->warning_point_values[compiler->warning_point_count++] = point;
    return true;
}

bool yx_compiler_warning_raised_at(YRX_COMPILER *compiler, size_t count, size_t raised)
{
    return yx_compiler_note_warning_point(compiler, count, raised);
}

int yx_compiler_excess_quantifier_warning(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, size_t raised, int64_t required,
                                          size_t available)
{
    size_t count = compiler->warning_count, length = yx_source_text_length(source);
    char note[160];
    if (start >= end || end > length) return 0;
    snprintf(note, sizeof(note), "the expression requires %" PRId64 " matching patterns out of %zu", required, available);
    if (!yx_compiler_warning(compiler, "InvariantBooleanExpression", "invariant_expr", "invariant boolean expression", "this expression is always false", source, origin,
                             start, end, note))
        return 0;
    return yx_compiler_note_warning_point(compiler, count, raised);
}

int yx_compiler_type_warning(YRX_COMPILER *compiler, const char *source, const char *origin, const char *kind, size_t start, size_t end, size_t other_start,
                             size_t other_end, const char *type)
{
    size_t count = compiler->warning_count, length = yx_source_text_length(source);
    bool ok;
    if (start >= end || end > length || other_end > length) return 0;
    if (strcmp(kind, "non_bool_expr") == 0 || strcmp(kind, "unused_identifier") == 0 || strcmp(kind, "potentially_slow_loop") == 0) {
        /* other_end is where YARA-X raises it: after the whole `and`/`or`
         * chain, the body, the `with` statement or the loop's range. */
        int added = yx_compiler_type_warning(compiler, source, origin,
                                             strcmp(kind, "non_bool_expr") == 0       ? "non_bool_expr:point"
                                             : strcmp(kind, "unused_identifier") == 0 ? "unused_identifier:point"
                                                                                      : "potentially_slow_loop:point",
                                             start, end, 0, 0, type);
        if (added && other_end && !yx_compiler_note_warning_point(compiler, count, other_end)) return 0;
        return added;
    }
    if (strncmp(kind, "unsigned_unary_op:", 18) == 0) {
        char title[80];
        char operation = kind[18];
        const char *note = operation == '-' ? "the result is a signed integer, which wraps around if the unsigned value is greater than 0x7FFFFFFFFFFFFFFF"
                                            : "the result is an unsigned integer with all its 64 bits inverted";
        snprintf(title, sizeof(title), "`%c` applied to an unsigned integer", operation);
        return yx_compiler_warning(compiler, "UnsignedUnaryOperation", "unsigned_unary_op", title, "this is an unsigned integer", source, origin, start, end, note);
    }
    if (strncmp(kind, "sign_conversion:", 16) == 0) {
        const char *converted = kind + 16;
        const char *separator = strchr(converted, ':');
        char label[96];
        if (!separator || separator - converted > 21) return 0;
        snprintf(label, sizeof(label), "this is converted to %.*s", (int)(separator - converted), converted);
        return yx_compiler_warning(compiler, "SignConversion", "sign_conversion", "implicit conversion changes signedness", label, source, origin, start, end,
                                   strcmp(separator + 1, "unsigned") == 0 ? "signed integers are converted to unsigned when mixed with unsigned integers"
                                                                          : "the function expects a signed integer");
    }
    if (strcmp(kind, "deprecated") == 0) {
        const yx_deprecated_field field = {"test_proto2", YX_DEPRECATED_ROOT, "deprecated", "foo", "use `foo` instead"};
        return yx_compiler_deprecated_field_warning(compiler, &field, source, origin, start, end);
    }
    if (strcmp(kind, "non_bool_expr:point") == 0) {
        /* warn_if_not_bool (ast2ir.rs): the note only for the types that
         * convert to a Boolean. */
        char label[96];
        const char *note = strcmp(type, "integer") == 0  ? "non-zero integers are considered `true`, while zero is `false`"
                           : strcmp(type, "float") == 0  ? "non-zero floats are considered `true`, while zero is `false`"
                           : strcmp(type, "string") == 0 ? "non-empty strings are considered `true`, while the empty string (\"\") is `false`"
                                                         : NULL;
        snprintf(label, sizeof(label), "this expression is `%s` but is being used as `bool`", type);
        return yx_compiler_warning(compiler, "NonBooleanAsBoolean", "non_bool_expr", "non-boolean expression used as boolean", label, source, origin, start, end, note);
    }
    if (strcmp(kind, "unused_identifier:point") == 0) return yx_compiler_unused_identifier_warning(compiler, source, origin, start, end);
    if (strcmp(kind, "potentially_slow_loop:point") == 0) return yx_compiler_potentially_slow_loop_warning(compiler, source, origin, start, end);
    if (other_start >= other_end) return 0;
    if (strcmp(kind, "bool_int_comparison") == 0) {
        ok = yx_compiler_warning(compiler, "BooleanIntegerComparison", "bool_int_comparison", "comparison between boolean and integer",
                                 "this is comparing an integer and a boolean", source, origin, start, end, NULL);
        if (!ok || count == compiler->warning_count) return ok;
        size_t prefix = strcmp(type, "0") == 0 ? 4 : 0;
        char *replacement = malloc(prefix + other_end - other_start + 1);
        if (!replacement) return 0;
        if (prefix) memcpy(replacement, "not ", prefix);
        memcpy(replacement + prefix, source + other_start, other_end - other_start);
        replacement[prefix + other_end - other_start] = '\0';
        ok = yx_compiler_warning_patch(compiler, source, start, end, replacement, NULL);
        free(replacement);
        return ok;
    }
    if (strcmp(kind, "integer_range") == 0) {
        /* eq_check's check_integer_range: `type` is "minimum,maximum". */
        int64_t minimum;
        uint64_t maximum;
        char ranged_label[96], constant_label[96];
        if (sscanf(type, "%" SCNd64 ",%" SCNu64, &minimum, &maximum) != 2) return 0;
        snprintf(ranged_label, sizeof(ranged_label), "this expression is an integer in the range [%" PRId64 ",%" PRIu64 "]", minimum, maximum);
        snprintf(constant_label, sizeof(constant_label), "this integer is outside the range [%" PRId64 ",%" PRIu64 "]", minimum, maximum);
        if (!yx_compiler_unsatisfiable_pair_warning(compiler, source, origin, start, end, ranged_label, other_start, other_end, constant_label)) return 0;
        /* Raised once both operands are compiled: at the comparison's end. */
        return yx_compiler_note_warning_point(compiler, count, end > other_end ? end : other_end) ? 1 : 0;
    }
    if (strcmp(kind, "string_length") == 0) {
        size_t expected = 0, actual = 0;
        if (sscanf(type, "%zu", &expected) != 1 || other_end - other_start < 2 || source[other_start] != '"' || source[other_end - 1] != '"') return 0;
        for (size_t at = other_start + 1; at + 1 < other_end; ++at) {
            if (source[at] == '\\' && at + 2 < other_end) {
                ++at;
                if (source[at] == 'x' && at + 3 < other_end) at += 2;
            }
            ++actual;
        }
        if (actual == expected) return 1;
        char expected_label[96], actual_label[96];
        snprintf(expected_label, sizeof(expected_label), "the length of this string is %zu", expected);
        snprintf(actual_label, sizeof(actual_label), "the length of this string is %zu", actual);
        return yx_compiler_unsatisfiable_pair_warning(compiler, source, origin, start, end, expected_label, other_start, other_end, actual_label);
    }
    if (strcmp(kind, "string_case") == 0) {
        bool upper = strcmp(type, "uppercase") == 0;
        bool opposite = false;
        char *replacement = NULL;
        if (!yx_warning_string_case_replacement(source, other_start, other_end, upper, &replacement, &opposite)) return 0;
        if (!opposite) {
            free(replacement);
            return 1;
        }
        const char *note = upper ? "an uppercase string can't be equal to a string containing lowercase characters"
                                 : "a lowercase string can't be equal to a string containing uppercase characters";
        ok = yx_compiler_pair_warning(compiler, "UnsatisfiableExpression", "unsatisfiable_expr", "unsatisfiable expression", source, origin, start, end,
                                      upper ? "this is an uppercase string" : "this is a lowercase string", other_start, other_end,
                                      upper ? "this contains lowercase characters" : "this contains uppercase characters", false);
        if (!ok || count == compiler->warning_count) {
            free(replacement);
            return ok;
        }
        ok = yx_compiler_warning_patch(compiler, source, other_start, other_end, replacement, note);
        free(replacement);
        return ok;
    }
    return 1;
}

static const char *yx_warning_skip_index(const char *at)
{
    unsigned depth = 0;
    if (*at != '[') return at;
    do {
        if (*at == '"') {
            ++at;
            while (*at && *at != '"') {
                if (*at == '\\' && at[1]) ++at;
                ++at;
            }
            if (*at) ++at;
            continue;
        }
        if (*at == '[') ++depth;
        else if (*at == ']') --depth;
        ++at;
    } while (*at && depth);
    return at;
}

/* White space and comments between the tokens of a member chain. */
static const char *yx_deprecated_skip_blank(const char *at)
{
    for (;;) {
        while (isspace((unsigned char)*at)) ++at;
        if (at[0] == '/' && at[1] == '/') {
            while (*at && *at != '\n') ++at;
        } else if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
        } else return at;
    }
}

/* Walks the member chain after a module (or a name bound to one of its
 * structures, starting at `scope`), warning about deprecated fields when
 * `emit` is set. *final_scope and *end receive the scope reached and the
 * position after the chain. */
static bool yx_compiler_warn_deprecated_chain(YRX_COMPILER *compiler, const char *module, yx_deprecated_scope scope, const char *after_module, const char *condition,
                                              const char *source, const char *origin, size_t condition_offset, bool emit, yx_deprecated_scope *final_scope,
                                              const char **end)
{
    const char *at = after_module;
    *end = at;
    while (*at) {
        const char *field_start, *field_end;
        size_t length;
        bool called;
        *end = at;
        at = yx_deprecated_skip_blank(at);
        if (*at++ != '.') break;
        at = yx_deprecated_skip_blank(at);
        field_start = at;
        if (!isalpha((unsigned char)*at) && *at != '_') break;
        do {
            ++at;
        } while (isalnum((unsigned char)*at) || *at == '_');
        field_end = at;
        length = (size_t)(field_end - field_start);
        /* A called name is looked up as a function (func_call_from_ast),
         * not as a field: it raises no deprecation notice. */
        at = yx_deprecated_skip_blank(at);
        called = *at == '(';
        at = field_end;
        for (size_t i = 0; emit && !called && i < sizeof(yx_deprecated_fields) / sizeof(yx_deprecated_fields[0]); ++i) {
            const yx_deprecated_field *field = &yx_deprecated_fields[i];
            if (scope != field->scope || strcmp(module, field->module) != 0 || !yx_warning_identifier_is(field_start, length, field->field)) continue;
            if (!yx_compiler_deprecated_field_warning(compiler, field, source, origin, condition_offset + (size_t)(field_start - condition),
                                                      condition_offset + (size_t)(field_end - condition)))
                return false;
            break;
        }
        if (scope == YX_DEPRECATED_ROOT && strcmp(module, "macho") == 0 && yx_warning_identifier_is(field_start, length, "file")) scope = YX_DEPRECATED_MACHO_FILE;
        else if (scope == YX_DEPRECATED_ROOT && strcmp(module, "dotnet") == 0 && yx_warning_identifier_is(field_start, length, "classes"))
            scope = YX_DEPRECATED_DOTNET_CLASS;
        else if (scope == YX_DEPRECATED_DOTNET_CLASS && yx_warning_identifier_is(field_start, length, "methods")) scope = YX_DEPRECATED_DOTNET_METHOD;
        else scope = YX_DEPRECATED_OTHER;
        *end = at;
        while (isspace((unsigned char)*at)) ++at;
        while (*at == '[') {
            at = yx_warning_skip_index(at);
            *end = at;
            while (isspace((unsigned char)*at)) ++at;
        }
    }
    *final_scope = scope;
    return true;
}

/* A name declared by `with`, visible from the end of its value to the end
 * of the body. A value that is a module structure makes reads through the
 * name reads of that structure; any other value (module NULL) hides an
 * outer binding of the same name. */
typedef struct {
    const char *name;
    size_t length;
    const char *module;
    yx_deprecated_scope scope;
    const char *from, *to;
} yx_deprecated_alias;

/* Scans from `at` over strings, comments, regexps and nested groups. With
 * `separators`, stops at the first `,` or `:` outside groups (NULL at a
 * `for` or `with` there, whose own `:` would be ambiguous); otherwise at the
 * `)` that closes the group `at` is in. NULL at the end of the text. */
static const char *yx_deprecated_scan(const char *at, bool separators)
{
    unsigned depth = 0;
    bool next_regex = false;
    while (*at) {
        if (at[0] == '/' && at[1] == '/') {
            while (*at && *at != '\n') ++at;
            continue;
        }
        if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
            continue;
        }
        if (*at == '"' || (*at == '/' && next_regex)) {
            char terminator = *at++;
            while (*at && *at != terminator) {
                if (*at == '\\' && at[1]) ++at;
                ++at;
            }
            if (*at) ++at;
            next_regex = false;
            continue;
        }
        if (isalpha((unsigned char)*at) || *at == '_') {
            const char *word = at;
            while (isalnum((unsigned char)*at) || *at == '_') ++at;
            if (separators && !depth && (yx_warning_identifier_is(word, (size_t)(at - word), "for") || yx_warning_identifier_is(word, (size_t)(at - word), "with")))
                return NULL;
            next_regex = yx_warning_identifier_is(word, (size_t)(at - word), "matches");
            continue;
        }
        if (*at == '(' || *at == '[') ++depth;
        else if (*at == ')' || *at == ']') {
            if (!depth) return separators || *at != ')' ? NULL : at;
            --depth;
        } else if (separators && !depth && (*at == ',' || *at == ':')) return at;
        if (!isspace((unsigned char)*at)) next_regex = false;
        ++at;
    }
    return NULL;
}

static const yx_deprecated_alias *yx_deprecated_alias_at(const yx_deprecated_alias *aliases, size_t count, const char *name, size_t length)
{
    /* `to` is NULL while the declarations of its `with` are read. */
    for (size_t i = count; i-- > 0;)
        if (aliases[i].length == length && memcmp(aliases[i].name, name, length) == 0 && name >= aliases[i].from && (!aliases[i].to || name < aliases[i].to))
            return &aliases[i];
    return NULL;
}

static const char *yx_deprecated_module(const YRX_COMPILER *compiler, const char *start, size_t length)
{
    const char *module = NULL;
    if (yx_warning_identifier_is(start, length, "dotnet")) module = "dotnet";
    else if (yx_warning_identifier_is(start, length, "elf")) module = "elf";
    else if (yx_warning_identifier_is(start, length, "pe")) module = "pe";
    else if (yx_warning_identifier_is(start, length, "macho")) module = "macho";
    return module && yx_warning_module_imported(compiler, module) ? module : NULL;
}

/* Records the declarations of the `with` whose keyword ends at `at`. */
static bool yx_deprecated_with(const YRX_COMPILER *compiler, const char *at, yx_deprecated_alias **aliases, size_t *count, size_t *capacity)
{
    size_t first = *count;
    const char *cursor = at, *body_end = NULL;
    for (;;) {
        const char *name, *value, *value_end, *word, *chain_end = NULL;
        const yx_deprecated_alias *bound;
        yx_deprecated_alias alias = {0};
        while (isspace((unsigned char)*cursor)) ++cursor;
        name = cursor;
        if (!isalpha((unsigned char)*cursor) && *cursor != '_') break;
        while (isalnum((unsigned char)*cursor) || *cursor == '_') ++cursor;
        alias.name = name;
        alias.length = (size_t)(cursor - name);
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor != '=' || cursor[1] == '=') break;
        value = ++cursor;
        value_end = yx_deprecated_scan(value, true);
        if (!value_end) break;
        while (isspace((unsigned char)*value)) ++value;
        word = value;
        while (isalnum((unsigned char)*value) || *value == '_') ++value;
        if (value > word && !isdigit((unsigned char)*word)) {
            bound = yx_deprecated_alias_at(*aliases, *count, word, (size_t)(value - word));
            if (bound) {
                alias.module = bound->module;
                alias.scope = bound->scope;
            } else {
                alias.module = yx_deprecated_module(compiler, word, (size_t)(value - word));
                alias.scope = YX_DEPRECATED_ROOT;
            }
            if (alias.module && !yx_compiler_warn_deprecated_chain(NULL, alias.module, alias.scope, value, NULL, NULL, NULL, 0, false, &alias.scope, &chain_end))
                return false;
            while (chain_end && isspace((unsigned char)*chain_end)) ++chain_end;
            if (chain_end != value_end) alias.module = NULL;
        }
        alias.from = value_end;
        if (*count == *capacity) {
            size_t next = *capacity ? *capacity * 2 : 8;
            yx_deprecated_alias *grown = realloc(*aliases, next * sizeof(*grown));
            if (!grown) return false;
            *aliases = grown;
            *capacity = next;
        }
        (*aliases)[(*count)++] = alias;
        cursor = value_end + 1;
        if (*value_end == ',') continue;
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor == '(') body_end = yx_deprecated_scan(cursor + 1, false);
        break;
    }
    for (size_t i = first; i < *count; ++i) (*aliases)[i].to = body_end ? body_end : (*aliases)[i].from;
    return true;
}

static bool yx_compiler_warn_deprecated_fields(YRX_COMPILER *compiler, const char *condition, const char *source, const char *origin, size_t condition_offset)
{
    const char *at = condition;
    bool next_regex = false;
    yx_deprecated_alias *aliases = NULL;
    size_t alias_count = 0, alias_capacity = 0;
    bool ok = false;
    while (*at) {
        const char *start;
        size_t length;
        const char *module = NULL;
        if (at[0] == '/' && at[1] == '/') {
            at += 2;
            while (*at && *at != '\n') ++at;
            continue;
        }
        if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
            continue;
        }
        if (*at == '"' || (*at == '/' && next_regex)) {
            char terminator = *at++;
            while (*at && *at != terminator) {
                if (*at == '\\' && at[1]) ++at;
                ++at;
            }
            if (*at) ++at;
            next_regex = false;
            continue;
        }
        if (!isalpha((unsigned char)*at) && *at != '_') {
            if (!isspace((unsigned char)*at)) next_regex = false;
            ++at;
            continue;
        }
        start = at++;
        while (isalnum((unsigned char)*at) || *at == '_') ++at;
        length = (size_t)(at - start);
        if (yx_warning_identifier_is(start, length, "matches")) next_regex = true;
        else next_regex = false;
        /* A '.' before the name is a member access, but `..` is the range
         * operator: `(0..pe.number_of_signatures)` uses the module. */
        if (start > condition && (isalnum((unsigned char)start[-1]) || start[-1] == '_' || (start[-1] == '.' && !(start - 1 > condition && start[-2] == '.')) ||
                                  start[-1] == '$' || start[-1] == '#' || start[-1] == '@' || start[-1] == '!'))
            continue;
        if (yx_warning_identifier_is(start, length, "with")) {
            if (!yx_deprecated_with(compiler, at, &aliases, &alias_count, &alias_capacity)) goto done;
            continue;
        }
        /* A field read through a name bound to a module structure. */
        const yx_deprecated_alias *alias = yx_deprecated_alias_at(aliases, alias_count, start, length);
        yx_deprecated_scope scope = YX_DEPRECATED_ROOT;
        const char *chain_end;
        if (alias) {
            module = alias->module;
            scope = alias->scope;
        } else module = yx_deprecated_module(compiler, start, length);
        if (module && !yx_compiler_warn_deprecated_chain(compiler, module, scope, at, condition, source, origin, condition_offset, true, &scope, &chain_end)) goto done;
    }
    ok = true;
done:
    free(aliases);
    return ok;
}

static void yx_compiler_move_before_later(YRX_COMPILER *compiler, size_t first_type_warning, size_t index, size_t position);
static bool yx_compiler_warn_global_rule_references(YRX_COMPILER *compiler, const char *condition, const char *source, const char *origin, size_t condition_offset);

/* YARA-X checks field accesses while compiling a condition, so the
 * deprecations it meets before a semantic error stay reported for the
 * failing rule: those starting before the error's end. So do the
 * references to a global rule (global_rule_misuse, raised where ast2ir
 * looks the identifier up), after them as in a rule that compiles.
 * Warnings from `first_type_warning` on are the typed ones kept for it. */
int yx_compiler_warn_deprecated_before(YRX_COMPILER *compiler, const char *condition, const char *source, const char *origin, size_t condition_offset, size_t limit,
                                       size_t first_type_warning)
{
    size_t length = strlen(condition), first_deprecated;
    char *prefix;
    bool ok;
    if (limit <= condition_offset) return 1;
    if (limit - condition_offset < length) {
        /* Keep the `(` of a call that the error's label ends before: the
         * called name is no field read. */
        size_t next = (size_t)(yx_deprecated_skip_blank(condition + (limit - condition_offset)) - condition);
        length = next < length && condition[next] == '(' ? next + 1 : limit - condition_offset;
    }
    if (!(prefix = malloc(length + 1))) return 0;
    memcpy(prefix, condition, length);
    prefix[length] = '\0';
    first_deprecated = compiler->warning_count;
    ok = yx_compiler_warn_deprecated_fields(compiler, prefix, source, origin, condition_offset);
    /* Merged into the typed warnings kept for the rule as the full
     * condition's are: a field is read when its operand is converted. */
    for (size_t i = first_deprecated; ok && i < compiler->warning_count; ++i) {
        const char *span = strstr(compiler->warnings[i], "\"span\":{\"start\":");
        size_t position;
        if (!yx_compiler_json_span(compiler, span, &position, NULL)) continue;
        yx_compiler_move_before_later(compiler, first_type_warning, i, position);
    }
    first_deprecated = compiler->warning_count;
    ok = ok && yx_compiler_warn_global_rule_references(compiler, prefix, source, origin, condition_offset);
    free(prefix);
    if (ok) yx_compiler_order_raised_warnings(compiler, first_type_warning, first_deprecated);
    return ok;
}

/* Warnings from `first_new` on that YARA-X raises while it converts the
 * expression at their label (a loop's iterations, a global rule's name)
 * move before the typed warnings it raises later (yx_compiler_move_before_
 * later), as deprecations do. */
void yx_compiler_order_raised_warnings(YRX_COMPILER *compiler, size_t first_type_warning, size_t first_new)
{
    for (size_t i = first_new; i < compiler->warning_count; ++i) {
        const char *span = strstr(compiler->warnings[i], "\"span\":{\"start\":");
        size_t position;
        if (!span || !yx_compiler_json_span(compiler, span, &position, NULL)) continue;
        yx_compiler_move_before_later(compiler, first_type_warning, i, position);
    }
}

/* The primary span of the errors added after `mark`, unless the first is
 * a syntax or literal error, which stop before field checks. */
bool yx_compiler_semantic_error_span(const YRX_COMPILER *compiler, size_t mark, size_t *start, size_t *end)
{
    const char *json = compiler->error_diagnostic_json, *code, *span;
    if (!json || strlen(json) <= mark) return false;
    json += mark;
    if (!(code = strstr(json, "\"code\":\""))) return false;
    code += 8;
    if (!strncmp(code, "E001\"", 5) || !strncmp(code, "E027\"", 5) || !strncmp(code, "E028\"", 5) || !strncmp(code, "E029\"", 5) || !strncmp(code, "E030\"", 5) ||
        !strncmp(code, "E031\"", 5))
        return false;
    if (!(span = strstr(json, "\"span\":{\"start\":"))) return false;
    return yx_compiler_json_span(compiler, span, start, end);
}

bool yx_compiler_semantic_error_end(const YRX_COMPILER *compiler, size_t mark, size_t *end)
{
    size_t start;
    return yx_compiler_semantic_error_span(compiler, mark, &start, end);
}

/* YARA-X warns about an expression after checking its operands, so a
 * semantic error inside it leaves no warning for it: warnings for the
 * expressions enclosing the error are dropped, those for operands remain.
 * Nor did it convert what follows the error and the operands converted
 * before it (`converted_end`, 0 when unknown): warnings there are dropped
 * too. */
void yx_compiler_drop_warnings_after(YRX_COMPILER *compiler, size_t first, size_t error_mark, size_t error_start, size_t error_end, size_t converted_end)
{
    size_t kept = first, moment = error_start;
    const char *json = compiler->error_diagnostic_json;
    /* An `and`/`or` operand of the wrong type (E002) fails after YARA-X
     * warned about every operand of its chain: the error happens at the
     * point of that operand's own non_bool_expr warning. Another E002 at
     * the operand (a member of a call's result) is met while converting it,
     * before that warning. */
    if (json && strlen(json) > error_mark && strstr(json + error_mark, "\"code\":\"E002\"") &&
        (strstr(json + error_mark, "expression should be `bool`") || strstr(json + error_mark, "expression should be `boolean`, `float`, `integer`, or `string`"))) {
        for (size_t point = 0; point < compiler->warning_point_count; ++point) {
            const char *key = compiler->warning_point_keys[point], *span;
            size_t start, end;
            bool listed = false;
            /* Keys of warnings removed since are never dereferenced. */
            for (size_t i = first; i < compiler->warning_count; ++i)
                if (compiler->warnings[i] == key) listed = true;
            if (!listed) continue;
            span = strstr(key, "\"span\":{\"start\":");
            if (span && strstr(key, "\"code\":\"non_bool_expr\"") && yx_compiler_json_span(compiler, span, &start, &end) && start == error_start && end == error_end &&
                compiler->warning_point_values[point] > moment)
                moment = compiler->warning_point_values[point];
        }
    }
    for (size_t i = first; i < compiler->warning_count; ++i) {
        const char *span = strstr(compiler->warnings[i], "\"span\":{\"start\":");
        size_t start, end, point;
        bool has_point = false, drop;
        /* A warning raised after a later source position (the end of its
         * `and`/`or` chain, `with` statement or loop range) was never raised
         * when the error lies before that position. */
        for (point = 0; point < compiler->warning_point_count; ++point)
            if (compiler->warning_point_keys[point] == compiler->warnings[i]) {
                has_point = true;
                break;
            }
        if (has_point) drop = compiler->warning_point_values[point] > moment;
        else
            drop = span && yx_compiler_json_span(compiler, span, &start, &end) &&
                   ((start <= error_start && end >= error_end && (start < error_start || end > error_end)) ||
                    (converted_end && start >= (converted_end > error_end ? converted_end : error_end)));
        if (drop) {
            free(compiler->warnings[i]);
            continue;
        }
        compiler->warnings[kept++] = compiler->warnings[i];
    }
    compiler->warning_count = kept;
}

/* References to a global rule are redundant because that rule is already a
 * prerequisite for every match. Inspect identifiers after semantic
 * validation, so text in strings, comments, and regular expressions cannot
 * be mistaken for a rule reference. */
static bool yx_compiler_warn_global_rule_references(YRX_COMPILER *compiler, const char *condition, const char *source, const char *origin, size_t condition_offset)
{
    const char *at = condition;
    bool next_regex = false;
    /* Only a global rule draws this warning, and most rule sets have none:
     * count them incrementally instead of scanning every earlier rule for
     * each identifier of every condition (quadratic in the rule count). */
    if (compiler->global_rules_scanned > compiler->rules->rule_count) compiler->global_rules_scanned = compiler->global_rule_count = 0;
    for (; compiler->global_rules_scanned < compiler->rules->rule_count; ++compiler->global_rules_scanned)
        if (compiler->rules->rules[compiler->global_rules_scanned].is_global) ++compiler->global_rule_count;
    if (!compiler->global_rule_count) return true;
    while (*at) {
        const char *start;
        size_t length;
        if (at[0] == '/' && at[1] == '/') {
            at += 2;
            while (*at && *at != '\n') ++at;
            continue;
        }
        if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
            continue;
        }
        if (*at == '"' || (*at == '/' && next_regex)) {
            char terminator = *at++;
            while (*at && *at != terminator) {
                if (*at == '\\' && at[1]) ++at;
                ++at;
            }
            if (*at) ++at;
            next_regex = false;
            continue;
        }
        if (!isalpha((unsigned char)*at) && *at != '_') {
            if (!isspace((unsigned char)*at)) next_regex = false;
            ++at;
            continue;
        }
        start = at++;
        while (isalnum((unsigned char)*at) || *at == '_') ++at;
        length = (size_t)(at - start);
        next_regex = yx_warning_identifier_is(start, length, "matches");
        if (start > condition &&
            (isalnum((unsigned char)start[-1]) || start[-1] == '_' || start[-1] == '.' || start[-1] == '$' || start[-1] == '#' || start[-1] == '@' || start[-1] == '!'))
            continue;
        for (size_t i = 0; i < compiler->rules->rule_count; ++i) {
            const YRX_RULE *rule = &compiler->rules->rules[i];
            size_t offset;
            if (!rule->is_global || strlen(rule->identifier) != length || memcmp(rule->identifier, start, length) != 0 ||
                rule->namespace_index != compiler->current_namespace_index)
                continue;
            offset = condition_offset + (size_t)(start - condition);
            if (!yx_compiler_warning(compiler, "GlobalRuleMisuse", "global_rule_misuse", "global rule used in condition",
                                     "a global rule is being used as part of an condition", source, origin, offset, offset + length,
                                     "referencing a global rule in a condition is redundant, "
                                     "and may result in an unsatisfiable condition"))
                return false;
            break;
        }
    }
    return true;
}

static void yx_free_compiler_policies(YRX_COMPILER *compiler)
{
    for (size_t i = 0; i < compiler->enabled_feature_count; ++i) free(compiler->enabled_features[i]);
    free(compiler->enabled_features);
    compiler->enabled_features = NULL;
    compiler->enabled_feature_count = 0;
    for (size_t i = 0; i < compiler->module_policy_count; ++i) {
        free(compiler->module_policies[i].name);
        free(compiler->module_policies[i].ban_title);
        free(compiler->module_policies[i].ban_message);
    }
    free(compiler->module_policies);
    compiler->module_policies = NULL;
    compiler->module_policy_count = 0;
    for (size_t i = 0; i < compiler->ignored_import_count; ++i) {
        free(compiler->ignored_imports[i].module);
        free(compiler->ignored_imports[i].namespace_name);
    }
    free(compiler->ignored_imports);
    compiler->ignored_imports = NULL;
    compiler->ignored_import_count = 0;
    for (size_t i = 0; i < compiler->ignored_rule_count; ++i) {
        free(compiler->ignored_rules[i].name);
        free(compiler->ignored_rules[i].namespace_name);
        free(compiler->ignored_rules[i].module);
        free(compiler->ignored_rules[i].parent);
    }
    free(compiler->ignored_rules);
    compiler->ignored_rules = NULL;
    compiler->ignored_rule_count = 0;
    for (size_t i = 0; i < compiler->warning_count; ++i) free(compiler->warnings[i]);
    free(compiler->warnings);
    compiler->warnings = NULL;
    compiler->warning_count = 0;
}

static yx_module_policy *yx_find_module_policy(YRX_COMPILER *compiler, const char *module)
{
    for (size_t i = 0; i < compiler->module_policy_count; ++i)
        if (strcmp(compiler->module_policies[i].name, module) == 0) return &compiler->module_policies[i];
    return NULL;
}

static yx_module_policy *yx_get_module_policy(YRX_COMPILER *compiler, const char *module)
{
    yx_module_policy *policy = yx_find_module_policy(compiler, module);
    yx_module_policy *grown;
    char *name;
    if (policy) return policy;
    if (compiler->module_policy_count >= SIZE_MAX / sizeof(*grown)) return NULL;
    name = yx_strdup(module);
    if (!name) return NULL;
    grown = (yx_module_policy *)realloc(compiler->module_policies, (compiler->module_policy_count + 1) * sizeof(*grown));
    if (!grown) {
        free(name);
        return NULL;
    }
    compiler->module_policies = grown;
    policy = &compiler->module_policies[compiler->module_policy_count++];
    memset(policy, 0, sizeof(*policy));
    policy->name = name;
    return policy;
}

/* condition.c is built once for every library variant; this tells it
 * whether the test-only modules are registered (condition.h). */
#ifdef XXYARA_ENABLE_TEST_PROTO
const bool yx_test_proto_modules_enabled = true;
#else
const bool yx_test_proto_modules_enabled = false;
#endif

static bool yx_known_module(const char *name)
{
#ifdef XXYARA_ENABLE_OLECF
    if (strcmp(name, "olecf") == 0) return true;
#endif
#ifdef XXYARA_ENABLE_MAGIC
    if (strcmp(name, "magic") == 0) return true;
#endif
#ifdef XXYARA_ENABLE_VBA
    if (strcmp(name, "vba") == 0) return true;
#endif
#ifdef XXYARA_ENABLE_MSI
    if (strcmp(name, "msi") == 0) return true;
#endif
#ifdef XXYARA_ENABLE_TEST_PROTO
    if (strcmp(name, "test_proto2") == 0 || strcmp(name, "test_proto3") == 0) return true;
#endif
    static const char *const known[] = {"console", "crx", "cuckoo", "dex", "dotnet", "elf", "hash", "lnk", "macho", "math", "pe", "string", "time", "vt", "zip"};
    for (size_t i = 0; i < sizeof(known) / sizeof(*known); ++i)
        if (strcmp(name, known[i]) == 0) return true;
    return false;
}

static bool yx_record_ignored_import(YRX_COMPILER *compiler, const char *module)
{
    yx_ignored_import *grown;
    char *name, *namespace_name;
    if (compiler->ignored_import_count >= SIZE_MAX / sizeof(*grown)) return false;
    name = yx_strdup(module);
    namespace_name = yx_strdup(compiler->current_namespace);
    if (!name || !namespace_name) {
        free(name);
        free(namespace_name);
        return false;
    }
    grown = (yx_ignored_import *)realloc(compiler->ignored_imports, (compiler->ignored_import_count + 1) * sizeof(*grown));
    if (!grown) {
        free(name);
        free(namespace_name);
        return false;
    }
    compiler->ignored_imports = grown;
    compiler->ignored_imports[compiler->ignored_import_count].module = name;
    compiler->ignored_imports[compiler->ignored_import_count].namespace_name = namespace_name;
    compiler->ignored_imports[compiler->ignored_import_count].namespace_index = compiler->current_namespace_index;
    ++compiler->ignored_import_count;
    return true;
}

/* A diagnostic object for an error reported only as text, shaped like the
 * structured ones: the line comes from an `origin:N:` prefix when there is
 * one. */
static char *yx_fallback_error_diagnostic(const char *message, const char *origin)
{
    static const char hex[] = "0123456789abcdef";
    size_t line = 0, length = strlen(message), origin_length = origin ? strlen(origin) : 0;
    if (origin && !strncmp(message, origin, origin_length) && message[origin_length] == ':') {
        const char *digits = message + origin_length + 1;
        char *stop = NULL;
        unsigned long long value = strtoull(digits, &stop, 10);
        if (stop != digits && *stop == ':') line = (size_t)value;
    }
    if (length > (SIZE_MAX - 256) / 6) return NULL;
    char *json = (char *)malloc(length * 6 + 256);
    if (!json) return NULL;
    size_t used = (size_t)(line ? sprintf(json,
                                          "{\"type\":\"SyntaxError\",\"code\":\"E001\",\"title\":\"syntax error\","
                                          "\"line\":%zu,\"column\":1,\"labels\":[],\"footers\":[],\"text\":\"",
                                          line)
                                : sprintf(json,
                                          "{\"type\":\"SyntaxError\",\"code\":\"E001\",\"title\":\"syntax error\","
                                          "\"labels\":[],\"footers\":[],\"text\":\""));
    for (const unsigned char *at = (const unsigned char *)message; *at; ++at) {
        if (*at == '"' || *at == '\\') {
            json[used++] = '\\';
            json[used++] = (char)*at;
        } else if (*at < 0x20) {
            json[used++] = '\\';
            json[used++] = 'u';
            json[used++] = '0';
            json[used++] = '0';
            json[used++] = hex[*at >> 4];
            json[used++] = hex[*at & 15];
        } else json[used++] = (char)*at;
    }
    memcpy(json + used, "\"}", 3);
    return json;
}

static bool yx_compiler_join_error_diagnostic(YRX_COMPILER *compiler, char *diagnostic);

static bool yx_compiler_append_error_diagnostic(YRX_COMPILER *compiler, char *diagnostic)
{
    return yx_compiler_join_error_diagnostic(compiler, yx_nul_escape_public_json(compiler, diagnostic));
}

/* Appends diagnostics already in their final coordinates. */
static bool yx_compiler_join_error_diagnostic(YRX_COMPILER *compiler, char *diagnostic)
{
    char *joined;
    size_t previous, additional;
    if (!diagnostic) return false;
    if (!compiler->error_diagnostic_json) {
        compiler->error_diagnostic_json = diagnostic;
        return true;
    }
    previous = strlen(compiler->error_diagnostic_json);
    additional = strlen(diagnostic);
    if (previous > SIZE_MAX - additional - 2) {
        free(diagnostic);
        return false;
    }
    joined = (char *)realloc(compiler->error_diagnostic_json, previous + additional + 2);
    if (!joined) {
        free(diagnostic);
        return false;
    }
    joined[previous] = ',';
    memcpy(joined + previous + 1, diagnostic, additional + 1);
    compiler->error_diagnostic_json = joined;
    free(diagnostic);
    return true;
}

/* YRX_COLORIZE_ERRORS: YARA-X styles each character of a report and emits a
 * run whenever the style changes: the level header and primary (`^`)
 * annotations in the level's color, line numbers, gutters, arrows and
 * secondary (`-`) annotations in bold bright blue, bold titles and footer
 * kinds, and patches in red (removed) and green (added). The plain report
 * fixes every character; this pass recovers the styles from its layout. */
enum {
    YX_STYLE_NONE,
    YX_STYLE_LEVEL,
    YX_STYLE_BOLD,
    YX_STYLE_BLUE,
    YX_STYLE_HELP,
    YX_STYLE_ADDITION,
    YX_STYLE_REMOVAL
};

static bool yx_color_put(char **out, size_t *used, size_t *capacity, const char *data, size_t length)
{
    if (length > SIZE_MAX - *used - 1) return false;
    if (*used + length + 1 > *capacity) {
        size_t next = !*capacity ? 256 : *capacity <= SIZE_MAX / 2 ? *capacity * 2 : *used + length + 1;
        char *grown;
        while (next < *used + length + 1) next = next <= SIZE_MAX / 2 ? next * 2 : *used + length + 1;
        if (!(grown = realloc(*out, next))) return false;
        *out = grown;
        *capacity = next;
    }
    memcpy(*out + *used, data, length);
    *used += length;
    (*out)[*used] = '\0';
    return true;
}

static void yx_note_patch(YRX_COMPILER *compiler, const char *text, size_t column, size_t removed, size_t added)
{
    const char *help = NULL, *rows, *at, *last;
    yx_patch_note note, *grown;
    bool first_removal = true, addition_marked = false;
    if (!compiler || !text || (!(compiler->flags & YRX_COLORIZE_ERRORS) && !compiler->record_patch_notes)) return;
    for (at = strstr(text, "\nhelp: "); at; at = strstr(at + 1, "\nhelp: ")) help = at;
    if (!help || !(rows = strchr(help + 1, '\n')) || !(rows = strchr(rows + 1, '\n'))) return;
    memset(&note, 0, sizeof(note));
    last = ++rows;
    for (size_t row = 0; *(at = last == rows ? rows : last + 1) && row < 64; ++row) {
        const char *line_end = strchr(at, '\n');
        size_t length = line_end ? (size_t)(line_end - at) : strlen(at);
        size_t sign = 0, content, content_length;
        while (sign < length && at[sign] == ' ') ++sign;
        if (sign == length || !isdigit((unsigned char)at[sign])) break;
        while (sign < length && isdigit((unsigned char)at[sign])) ++sign;
        if (sign + 2 > length || at[sign] != ' ' || !strchr("-+~", at[sign + 1]) || !at[sign + 1] || (sign + 2 < length && at[sign + 2] != ' ')) break;
        content = sign + 3;
        content_length = length > content ? length - content : 0;
        if (at[sign + 1] == '-') {
            size_t from = first_removal ? column : 0, take;
            first_removal = false;
            if (removed && from <= content_length) {
                take = content_length - from < removed ? content_length - from : removed;
                if (take && note.mark_count < 16) {
                    note.marks[note.mark_count][0] = row;
                    note.marks[note.mark_count][1] = content + from;
                    note.marks[note.mark_count++][2] = content + from + take;
                }
                removed -= take;
                if (removed) --removed;
            }
        } else if (!addition_marked) {
            size_t to = column + added > content_length ? content_length : column + added;
            addition_marked = true;
            if (to > column && note.mark_count < 16) {
                note.marks[note.mark_count][0] = row;
                note.marks[note.mark_count][1] = content + column;
                note.marks[note.mark_count++][2] = content + to;
            }
        }
        last = at + length;
        if (!line_end) break;
    }
    if (last == rows) return;
    /* Kept in the stored form: a long line shown by many notes is kept
     * once (compiler->warning_rows), so the notes stay linear in size. */
    note.length = (size_t)(last - rows);
    note.hash = yx_warning_row_hash(rows, note.length);
    /* Only the first note for the same rows is ever used: an equal one is
     * not kept again (one per rows, so a lookup stops at its match). */
    if (compiler->patch_note_slot_capacity) {
        size_t mask = compiler->patch_note_slot_capacity - 1;
        for (size_t at = (size_t)note.hash & mask; compiler->patch_note_slots[at]; at = (at + 1) & mask) {
            const yx_patch_note *kept = &compiler->patch_notes[compiler->patch_note_slots[at] - 1];
            char *expanded;
            bool same;
            if (kept->hash != note.hash || kept->length != note.length) continue;
            expanded = yx_warning_expand(compiler, kept->rows, NULL);
            if (!expanded) return;
            same = memcmp(expanded, rows, note.length) == 0;
            free(expanded);
            if (same) return;
        }
    }
    note.rows = yx_warning_compact_text(&compiler->warning_rows, rows, note.length);
    if (!note.rows) return;
    if (compiler->patch_note_count == compiler->patch_note_capacity) {
        size_t next = compiler->patch_note_capacity ? compiler->patch_note_capacity * 2 : 16;
        if (compiler->patch_note_capacity > SIZE_MAX / 2 / sizeof(*grown)) {
            free(note.rows);
            return;
        }
        grown = realloc(compiler->patch_notes, next * sizeof(*grown));
        if (!grown) {
            free(note.rows);
            return;
        }
        compiler->patch_notes = grown;
        compiler->patch_note_capacity = next;
    }
    if (compiler->patch_note_count >= compiler->patch_note_slot_capacity / 2) {
        size_t next = compiler->patch_note_slot_capacity ? compiler->patch_note_slot_capacity * 2 : 64;
        size_t *slots;
        if (compiler->patch_note_slot_capacity > SIZE_MAX / 2 / sizeof(*slots) || !(slots = calloc(next, sizeof(*slots)))) {
            free(note.rows);
            return;
        }
        free(compiler->patch_note_slots);
        compiler->patch_note_slots = slots;
        compiler->patch_note_slot_capacity = next;
        for (size_t i = 0; i < compiler->patch_note_count; ++i) {
            size_t at = (size_t)compiler->patch_notes[i].hash & (next - 1);
            while (slots[at]) at = (at + 1) & (next - 1);
            slots[at] = i + 1;
        }
    }
    {
        size_t mask = compiler->patch_note_slot_capacity - 1;
        size_t at = (size_t)note.hash & mask;
        while (compiler->patch_note_slots[at]) at = (at + 1) & mask;
        compiler->patch_note_slots[at] = compiler->patch_note_count + 1;
    }
    compiler->patch_notes[compiler->patch_note_count++] = note;
}

static size_t yx_patch_row_sign(const char *line, size_t length)
{
    size_t at = 0;
    while (at < length && line[at] == ' ') ++at;
    if (at == length || !isdigit((unsigned char)line[at])) return 0;
    while (at < length && isdigit((unsigned char)line[at])) ++at;
    if (at + 2 > length || line[at] != ' ' || !strchr("-+~", line[at + 1]) || (at + 2 < length && line[at + 2] != ' ')) return 0;
    return at + 1;
}

/* Styles a run of `help:` patch rows: the recorded spans, a whole line for
 * an insertion, or else the part between the common prefix and suffix. */
static void yx_color_patch(const YRX_COMPILER *compiler, const char **lines, const size_t *lengths, unsigned char **styles, size_t first, size_t count)
{
    const yx_patch_note *note = NULL;
    size_t group_length = 0;
    bool has_removal = false;
    for (size_t i = first; i < first + count; ++i) {
        size_t sign = yx_patch_row_sign(lines[i], lengths[i]);
        for (size_t at = 0; at < sign - 1; ++at) styles[i][at] = YX_STYLE_BLUE;
        styles[i][sign] = lines[i][sign] == '-' ? YX_STYLE_REMOVAL : YX_STYLE_ADDITION;
        if (sign + 1 < lengths[i]) styles[i][sign + 1] = styles[i][sign];
        if (lines[i][sign] == '-') has_removal = true;
        group_length += lengths[i] + 1;
    }
    /* The first note for these rows (the rows are one run of the report's
     * text): found by hash, then compared in full. */
    if (compiler && compiler->patch_note_slot_capacity && group_length) {
        size_t length = group_length - 1, best = SIZE_MAX;
        size_t mask = compiler->patch_note_slot_capacity - 1;
        uint64_t hash = yx_warning_row_hash(lines[first], length);
        for (size_t at = (size_t)hash & mask; compiler->patch_note_slots[at]; at = (at + 1) & mask) {
            size_t n = compiler->patch_note_slots[at] - 1;
            const yx_patch_note *candidate = &compiler->patch_notes[n];
            char *rows;
            if (n >= best || candidate->hash != hash || candidate->length != length) continue;
            rows = yx_warning_expand(compiler, candidate->rows, NULL);
            if (rows && memcmp(rows, lines[first], length) == 0) best = n;
            free(rows);
            if (best != SIZE_MAX) break;
        }
        if (best != SIZE_MAX) note = &compiler->patch_notes[best];
    }
    if (note) {
        for (size_t m = 0; m < note->mark_count; ++m) {
            size_t i = first + note->marks[m][0];
            if (i >= first + count) continue;
            for (size_t at = note->marks[m][1]; at < note->marks[m][2] && at < lengths[i]; ++at)
                styles[i][at] = lines[i][yx_patch_row_sign(lines[i], lengths[i])] == '-' ? YX_STYLE_REMOVAL : YX_STYLE_ADDITION;
        }
        return;
    }
    if (!has_removal) {
        for (size_t i = first; i < first + count; ++i)
            for (size_t at = yx_patch_row_sign(lines[i], lengths[i]) + 2; at < lengths[i]; ++at) styles[i][at] = YX_STYLE_ADDITION;
        return;
    }
    {
        /* Removed and added rows as two texts, compared end to end. */
        size_t sides[2][64][2], side_count[2] = {0, 0}, total[2] = {0, 0};
        size_t prefix = 0, suffix = 0;
        for (size_t i = first; i < first + count; ++i) {
            size_t sign = yx_patch_row_sign(lines[i], lengths[i]);
            int side = lines[i][sign] == '-' ? 0 : 1;
            if (side_count[side] == 64) return;
            sides[side][side_count[side]][0] = i;
            sides[side][side_count[side]++][1] = sign + 2;
            total[side] += (lengths[i] > sign + 2 ? lengths[i] - sign - 2 : 0) + 1;
        }
#define YX_PATCH_CHAR(side, offset, out)                                     \
    do {                                                                     \
        size_t rest_ = (offset);                                             \
        (out) = '\n';                                                        \
        for (size_t r_ = 0; r_ < side_count[side]; ++r_) {                   \
            size_t row_ = sides[side][r_][0], from_ = sides[side][r_][1];    \
            size_t len_ = lengths[row_] > from_ ? lengths[row_] - from_ : 0; \
            if (rest_ < len_) {                                              \
                (out) = lines[row_][from_ + rest_];                          \
                break;                                                       \
            }                                                                \
            if (rest_ == len_) {                                             \
                (out) = '\n';                                                \
                break;                                                       \
            }                                                                \
            rest_ -= len_ + 1;                                               \
        }                                                                    \
    } while (0)
        for (;;) {
            char a, b;
            if (prefix + 1 >= total[0] || prefix + 1 >= total[1]) break;
            YX_PATCH_CHAR(0, prefix, a);
            YX_PATCH_CHAR(1, prefix, b);
            if (a != b) break;
            ++prefix;
        }
        for (;;) {
            char a, b;
            if (prefix + suffix + 1 >= total[0] || prefix + suffix + 1 >= total[1]) break;
            YX_PATCH_CHAR(0, total[0] - 2 - suffix, a);
            YX_PATCH_CHAR(1, total[1] - 2 - suffix, b);
            if (a != b) break;
            ++suffix;
        }
#undef YX_PATCH_CHAR
        for (int side = 0; side < 2; ++side) {
            size_t offset = 0;
            for (size_t r = 0; r < side_count[side]; ++r) {
                size_t row = sides[side][r][0], from = sides[side][r][1];
                size_t len = lengths[row] > from ? lengths[row] - from : 0;
                for (size_t c = 0; c < len; ++c)
                    if (offset + c >= prefix && offset + c < total[side] - 1 - suffix) styles[row][from + c] = side ? YX_STYLE_ADDITION : YX_STYLE_REMOVAL;
                offset += len + 1;
            }
        }
    }
}

/* The byte offset in `line` (from `from`) where display column `column`
 * starts, or SIZE_MAX. */
static size_t yx_color_column_offset(const char *line, size_t length, size_t from, size_t column)
{
    size_t at = from, cells = 0;
    while (at < length && cells < column) {
        size_t width = yx_diagnostic_scalar_length(line + at, line + length);
        cells += yx_diagnostic_display_width(line + at, line + at + width);
        at += width;
    }
    return cells == column ? at : SIZE_MAX;
}

static char *yx_colorize_diagnostic(const YRX_COMPILER *compiler, const char *text)
{
    const char *level_code;
    const char **lines = NULL;
    size_t *lengths = NULL, line_count = 0, widest = 0;
    unsigned char **styles = NULL, *columns = NULL;
    size_t vertical = SIZE_MAX, multiline_end = 0;
    unsigned char vertical_style = YX_STYLE_BLUE;
    char *out = NULL;
    size_t used = 0, capacity = 0;
    bool ok = true;
    /* The diagnostic code links to its documentation (OSC 8), except for
     * custom errors (E100). */
    const char *link_kind = NULL;
    size_t code_start = 0, code_end = 0;
    if (!strncmp(text, "error[", 6) || !strncmp(text, "error:", 6)) {
        level_code = "\x1b[1m\x1b[91m";
        if (text[5] == '[') {
            link_kind = "errors";
            code_start = 6;
        }
    } else if (!strncmp(text, "warning[", 8) || !strncmp(text, "warning:", 8)) {
        level_code = "\x1b[1m\x1b[93m";
        if (text[7] == '[') {
            link_kind = "warnings";
            code_start = 8;
        }
    } else return NULL;
    if (link_kind) {
        const char *close = strchr(text + code_start, ']');
        const char *newline = strchr(text, '\n');
        if (!close || (newline && close > newline) || (size_t)(close - text) == code_start ||
            ((size_t)(close - text) - code_start == 4 && !memcmp(text + code_start, "E100", 4)))
            link_kind = NULL;
        else code_end = (size_t)(close - text);
    }
    for (const char *at = text;; ++line_count) {
        const char *end = strchr(at, '\n');
        if (!end) {
            ++line_count;
            break;
        }
        at = end + 1;
    }
    lines = calloc(line_count, sizeof(*lines));
    lengths = calloc(line_count, sizeof(*lengths));
    styles = calloc(line_count, sizeof(*styles));
    if (!lines || !lengths || !styles) goto done;
    {
        const char *at = text;
        for (size_t i = 0; i < line_count; ++i) {
            const char *end = strchr(at, '\n');
            lines[i] = at;
            lengths[i] = end ? (size_t)(end - at) : strlen(at);
            if (lengths[i] > widest) widest = lengths[i];
            if (!(styles[i] = calloc(lengths[i] + 1, 1))) goto done;
            at = end ? end + 1 : at + lengths[i];
        }
    }
    if (!(columns = calloc(widest + 1, 1))) goto done;
    /* A multi-line annotation ends on `|___^` beside the gutter. */
    for (size_t i = 1; i < line_count && vertical == SIZE_MAX; ++i) {
        const char *line = lines[i];
        size_t gutter = 0, at;
        while (gutter < lengths[i] && line[gutter] == ' ') ++gutter;
        if (gutter + 4 > lengths[i] || line[gutter] != '|' || line[gutter + 1] != ' ' || line[gutter + 2] != '|' || !strchr("_^-", line[gutter + 3])) continue;
        at = gutter + 3;
        while (at < lengths[i] && line[at] == '_') ++at;
        if (at == lengths[i] || (line[at] != '^' && line[at] != '-')) continue;
        vertical = gutter + 2;
        vertical_style = line[at] == '^' ? YX_STYLE_LEVEL : YX_STYLE_BLUE;
        multiline_end = i;
    }
    for (size_t i = 0; i < line_count; ++i) {
        const char *line = lines[i];
        unsigned char *style = styles[i];
        size_t length = lengths[i], indent = 0;
        bool in_multiline = vertical != SIZE_MAX && i <= multiline_end;
        while (indent < length && line[indent] == ' ') ++indent;
        if (i == 0) {
            const char *colon = memchr(line, ':', length);
            size_t split = colon ? (size_t)(colon - line) : length;
            for (size_t at = 0; at < length; ++at) style[at] = at < split ? YX_STYLE_LEVEL : YX_STYLE_BOLD;
        } else if (indent + 4 <= length && !memcmp(line + indent, "--> ", 4)) {
            memset(style + indent, YX_STYLE_BLUE, 4);
        } else if (indent == 0 && length >= 5 && !memcmp(line, "help:", 5)) {
            memset(style, YX_STYLE_HELP, 4);
        } else if (indent + 2 <= length && line[indent] == '=' && line[indent + 1] == ' ') {
            static const char help_lead[] = "help: you probably meant ";
            const char *colon = memchr(line + indent + 2, ':', length - indent - 2);
            size_t lead = indent + 2 + sizeof(help_lead) - 1;
            memset(style + indent, YX_STYLE_BLUE, 2);
            if (colon) memset(style + indent + 2, YX_STYLE_BOLD, (size_t)(colon - line) - indent - 2);
            /* E002's help names the call in green. */
            if (length > lead && !memcmp(line + indent + 2, help_lead, sizeof(help_lead) - 1)) memset(style + lead, YX_STYLE_ADDITION, length - lead);
        } else if (yx_patch_row_sign(line, length)) {
            size_t count = 1;
            while (i + count < line_count && yx_patch_row_sign(lines[i + count], lengths[i + count])) ++count;
            yx_color_patch(compiler, lines, lengths, styles, i, count);
            i += count - 1;
        } else if (indent < length && isdigit((unsigned char)line[indent])) {
            size_t digits = indent, content;
            while (digits < length && isdigit((unsigned char)line[digits])) ++digits;
            if (digits + 1 < length && line[digits] == ' ' && line[digits + 1] == '|') {
                memset(style, YX_STYLE_BLUE, digits);
                style[digits + 1] = YX_STYLE_BLUE;
                content = digits + 3;
                if (in_multiline && vertical < length && (line[vertical] == '|' || line[vertical] == '/')) {
                    style[vertical] = vertical_style;
                }
                if (in_multiline) content = vertical + 2;
                if (content + 3 <= length && !memcmp(line + content, "...", 3)) memset(style + content, YX_STYLE_BLUE, 3);
                if (length >= content + 6 && !memcmp(line + length - 3, "...", 3)) memset(style + length - 3, YX_STYLE_BLUE, 3);
                /* An annotation elided in the middle: the excerpt's "..."
                 * sits above the one between the markers. */
                if (!in_multiline && i + 1 < line_count) {
                    const char *marks = lines[i + 1];
                    size_t marks_length = lengths[i + 1], pipe = 0;
                    while (pipe < marks_length && marks[pipe] == ' ') ++pipe;
                    if (pipe < marks_length && marks[pipe] == '|' && pipe == digits + 1) {
                        for (size_t m = pipe + 3; m + 4 <= marks_length; ++m) {
                            size_t offset;
                            if (memcmp(marks + m, "...", 3) || (marks[m - 1] != '-' && marks[m - 1] != '^') || (marks[m + 3] != '-' && marks[m + 3] != '^')) continue;
                            offset = yx_color_column_offset(line, length, content, m - (pipe + 2));
                            if (offset != SIZE_MAX && offset + 3 <= length && !memcmp(line + offset, "...", 3)) memset(style + offset, YX_STYLE_BLUE, 3);
                            break;
                        }
                    }
                }
            }
        } else if (indent < length && line[indent] == '|') {
            unsigned char last = YX_STYLE_NONE;
            size_t at = indent + 1;
            style[indent] = YX_STYLE_BLUE;
            while (at < length) {
                char c = line[at];
                bool vertical_here = in_multiline && at == vertical;
                if (c == ' ' && !(vertical_here && at + 1 < length && line[at + 1] == '_')) {
                    ++at;
                    continue;
                }
                if (c == '^' || c == '-' || c == '_' || (c == '|' && vertical_here) || c == ' ') {
                    size_t run = at, stop = (c == '|' || c == ' ') ? at + 1 : at;
                    unsigned char color;
                    while (stop < length && line[stop] == '_') ++stop;
                    if (stop < length && (line[stop] == '^' || line[stop] == '-')) {
                        char mark = line[stop];
                        while (stop < length && line[stop] == mark) ++stop;
                        /* The markers of an annotation elided in the middle
                         * are one run. */
                        if (stop + 4 <= length && !memcmp(line + stop, "...", 3) && line[stop + 3] == mark) {
                            stop += 3;
                            while (stop < length && line[stop] == mark) ++stop;
                        }
                        color = mark == '^' ? YX_STYLE_LEVEL : YX_STYLE_BLUE;
                    } else {
                        color = vertical_style;
                    }
                    memset(style + run, color, stop - run);
                    if (!columns[run]) columns[run] = color;
                    last = color;
                    at = stop;
                    continue;
                }
                if (c == '|') {
                    style[at] = columns[at] ? columns[at] : YX_STYLE_BLUE;
                    ++at;
                    continue;
                }
                {
                    /* A label's text, up to the next annotation on the
                     * row: spaces then a run of markers. The spaces
                     * between them keep no style. */
                    unsigned char color = last ? last : columns[at];
                    size_t label_end = length, next = length;
                    for (size_t k = at; k + 1 < length; ++k) {
                        size_t j = k;
                        if (line[k] != ' ' || line[k + 1] != ' ') continue;
                        while (j < length && line[j] == ' ') ++j;
                        if (j < length && (line[j] == '^' || line[j] == '-')) {
                            label_end = k;
                            next = j;
                            break;
                        }
                        k = j;
                    }
                    if (color) memset(style + at, color, label_end - at);
                    if (next == length) break;
                    at = next;
                    continue;
                }
            }
        } else if (length == indent + 3 && !memcmp(line + indent, "...", 3)) {
            memset(style + indent, YX_STYLE_BLUE, 3);
        }
    }
    for (size_t i = 0; ok && i < line_count; ++i) {
        const char *current = "";
        for (size_t at = 0; ok && at < lengths[i]; ++at) {
            const char *code;
            /* annotate-snippets' styles: titles and footer labels are
             * bright white, the gutter and secondary annotations bright
             * cyan. */
            switch (styles[i][at]) {
                case YX_STYLE_LEVEL: code = level_code; break;
                case YX_STYLE_BOLD: code = "\x1b[1m\x1b[97m"; break;
                case YX_STYLE_BLUE: code = "\x1b[1m\x1b[96m"; break;
                case YX_STYLE_HELP: code = "\x1b[1m\x1b[96m"; break;
                case YX_STYLE_ADDITION: code = "\x1b[92m"; break;
                case YX_STYLE_REMOVAL: code = "\x1b[91m"; break;
                default: code = ""; break;
            }
            if (code != current) {
                if (*current) ok = yx_color_put(&out, &used, &capacity, "\x1b[0m", 4);
                current = code;
                if (ok && *code) ok = yx_color_put(&out, &used, &capacity, code, strlen(code));
            }
            if (ok && i == 0 && link_kind && at == code_end) {
                static const char close_link[] = "\x1b]8;;\x1b\\";
                ok = yx_color_put(&out, &used, &capacity, close_link, sizeof(close_link) - 1);
            }
            if (ok) ok = yx_color_put(&out, &used, &capacity, lines[i] + at, 1);
            if (ok && i == 0 && link_kind && at + 1 == code_start) {
                char open_link[160];
                int written = snprintf(open_link, sizeof(open_link), "\x1b]8;;https://virustotal.github.io/yara-x/docs/%s/#%.*s\x1b\\", link_kind,
                                       (int)(code_end - code_start), lines[0] + code_start);
                ok = written > 0 && (size_t)written < sizeof(open_link) && yx_color_put(&out, &used, &capacity, open_link, (size_t)written);
            }
        }
        if (ok && *current) ok = yx_color_put(&out, &used, &capacity, "\x1b[0m", 4);
        if (ok && i + 1 < line_count) ok = yx_color_put(&out, &used, &capacity, "\n", 1);
    }
    if (ok && !out) out = calloc(1, 1);
    if (!ok) {
        free(out);
        out = NULL;
    }
done:
    for (size_t i = 0; styles && i < line_count; ++i) free(styles[i]);
    free(styles);
    free(lines);
    free(lengths);
    free(columns);
    return out;
}

/* One plain report text as YRX_COLORIZE_ERRORS renders it (compiler may be
 * NULL: no patch notes). NULL: not a report, or out of memory. */
char *yx_compiler_colorize_report(const YRX_COMPILER *compiler, const char *text)
{
    return text ? yx_colorize_diagnostic(compiler, text) : NULL;
}

/* A report array with each "text" value colorized. */
static char *yx_colorize_reports(const YRX_COMPILER *compiler, const char *json)
{
    size_t length = strlen(json), used = 0, capacity = 0;
    char *out = NULL;
    const char *at = json;
    while (*at) {
        const char *field = strstr(at, "\"text\":\"");
        const char *value, *end;
        char *plain, *colored, *escaped;
        size_t plain_used = 0;
        bool top = false;
        if (!field) break;
        value = field + 8;
        end = value;
        while (*end && *end != '"') {
            if (*end == '\\' && end[1]) ++end;
            ++end;
        }
        /* Only a report's own text, the field closing the object. */
        top = end[0] == '"' && end[1] == '}' && (end[2] == ',' || end[2] == ']' || end[2] == '\0');
        if (!yx_color_put(&out, &used, &capacity, at, (size_t)(value - at))) goto failure;
        at = value;
        if (!top) {
            /* E002's help footer is built with the call in green. */
            static const char lead[] = "you probably meant ";
            size_t lead_length = sizeof(lead) - 1;
            if ((size_t)(end - value) > lead_length && !memcmp(value, lead, lead_length)) {
                if (!yx_color_put(&out, &used, &capacity, value, lead_length) || !yx_color_put(&out, &used, &capacity, "\\u001b[92m", 10) ||
                    !yx_color_put(&out, &used, &capacity, value + lead_length, (size_t)(end - value) - lead_length) ||
                    !yx_color_put(&out, &used, &capacity, "\\u001b[0m", 9))
                    goto failure;
                at = end;
            }
            continue;
        }
        plain = malloc((size_t)(end - value) + 1);
        if (!plain) goto failure;
        for (const char *p = value; p < end; ++p) {
            char c = *p;
            if (c == '\\' && p + 1 < end) {
                char e = *++p;
                if (e == 'n') c = '\n';
                else if (e == 't') c = '\t';
                else if (e == 'r') c = '\r';
                else if (e == 'u' && end - p >= 5) {
                    unsigned v = (unsigned)strtoul((char[5]){p[1], p[2], p[3], p[4], 0}, NULL, 16);
                    p += 4;
                    if (v < 0x80) c = (char)v;
                    else if (v < 0x800) {
                        plain[plain_used++] = (char)(0xc0 | v >> 6);
                        c = (char)(0x80 | (v & 0x3f));
                    } else {
                        plain[plain_used++] = (char)(0xe0 | v >> 12);
                        plain[plain_used++] = (char)(0x80 | ((v >> 6) & 0x3f));
                        c = (char)(0x80 | (v & 0x3f));
                    }
                } else c = e;
            }
            plain[plain_used++] = c;
        }
        plain[plain_used] = '\0';
        colored = yx_colorize_diagnostic(compiler, plain);
        free(plain);
        if (!colored) {
            if (!yx_color_put(&out, &used, &capacity, value, (size_t)(end - value))) goto failure;
            at = end;
            continue;
        }
        escaped = yx_json_quoted(colored);
        free(colored);
        if (!escaped) goto failure;
        /* yx_json_quoted adds the quotes. */
        if (!yx_color_put(&out, &used, &capacity, escaped + 1, strlen(escaped) - 2)) {
            free(escaped);
            goto failure;
        }
        free(escaped);
        at = end;
    }
    if (!yx_color_put(&out, &used, &capacity, at, strlen(at))) goto failure;
    (void)length;
    return out;
failure:
    free(out);
    return NULL;
}

/* yrx_last_error after a failed add_source is the first error it added:
 * the text of the first diagnostic past `start`. */
void yx_compiler_first_source_error(YRX_COMPILER *compiler, size_t start)
{
    const char *json = compiler->error_diagnostic_json, *at, *item;
    size_t used = 0;
    if (!json || strlen(json) <= start) return;
    item = json + start;
    if (*item == ',') ++item;
    /* The item's own "text" is its last field. */
    {
        const char *next = strstr(item + 1, ",{\"type\":");
        const char *end = next ? next : item + strlen(item);
        const char *field = NULL;
        for (const char *p = item; (p = strstr(p, "\"text\":\"")) && p < end; ++p) field = p;
        if (!field) return;
        at = field + 8;
        while (at < end && *at != '"' && used + 4 < sizeof(compiler->error)) {
            char c = *at++;
            if (c == '\\' && at < end) {
                char e = *at++;
                if (e == 'n') c = '\n';
                else if (e == 't') c = '\t';
                else if (e == 'r') c = '\r';
                else if (e == 'u' && end - at >= 4) {
                    unsigned value = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = *at++;
                        value = value * 16 + (unsigned)(h >= 'a' ? h - 'a' + 10 : h >= 'A' ? h - 'A' + 10 : h - '0');
                    }
                    if (value < 0x80) c = (char)value;
                    else if (value < 0x800) {
                        compiler->error[used++] = (char)(0xc0 | value >> 6);
                        c = (char)(0x80 | (value & 0x3f));
                    } else {
                        compiler->error[used++] = (char)(0xe0 | value >> 12);
                        compiler->error[used++] = (char)(0x80 | ((value >> 6) & 0x3f));
                        c = (char)(0x80 | (value & 0x3f));
                    }
                } else c = e;
            }
            compiler->error[used++] = c;
        }
        compiler->error[used] = '\0';
    }
}

/* YARA-X reports a source's compile errors, in item order, before the
 * errors its parser recorded: syntax errors, invalid integers, floats and
 * escape sequences, and invalid regexp modifiers. Errors from an included
 * source were ordered when it ended and stay where the include is. */
void yx_compiler_order_source_diagnostics(YRX_COMPILER *compiler, size_t start, const char *origin)
{
    static const char *const parse_codes[] = {"E001", "E027", "E028", "E029", "E030", "E031"};
    char *json = compiler->error_diagnostic_json, *quoted;
    char *semantic = NULL, *parsed = NULL, *out;
    size_t length, quoted_length, semantic_used = 0, parsed_used = 0;
    const char *at;
    if (!json) return;
    length = strlen(json);
    if (start >= length) return;
    quoted = yx_json_quoted_code_origin(origin);
    if (!quoted) return;
    quoted_length = strlen(quoted);
    semantic = (char *)malloc(length - start + 1);
    parsed = (char *)malloc(length - start + 1);
    if (!semantic || !parsed) goto done;
    at = json + start;
    if (*at == ',') ++at;
    while (*at) {
        /* A raw `{"type":` cannot occur inside a JSON string. */
        const char *next = strstr(at + 1, ",{\"type\":");
        const char *end = next ? next : json + length;
        const char *code = strstr(at, "\"code\":\"");
        const char *field = strstr(at, "\"code_origin\":");
        bool parse_phase = false;
        char *target;
        size_t *used;
        for (size_t i = 0; code && code < end && i < sizeof(parse_codes) / sizeof(*parse_codes); ++i)
            if (strncmp(code + 8, parse_codes[i], 4) == 0 && code[12] == '"') parse_phase = true;
        if (parse_phase &&
            (!field || field >= end || strncmp(field + 14, quoted, quoted_length) != 0 || (field[14 + quoted_length] != ',' && field[14 + quoted_length] != '}')))
            parse_phase = false;
        target = parse_phase ? parsed : semantic;
        used = parse_phase ? &parsed_used : &semantic_used;
        if (*used) target[(*used)++] = ',';
        memcpy(target + *used, at, (size_t)(end - at));
        *used += (size_t)(end - at);
        at = next ? next + 1 : end;
    }
    if (!parsed_used || !semantic_used) goto done;
    out = json + start;
    if (*out == ',') ++out;
    memcpy(out, semantic, semantic_used);
    out += semantic_used;
    *out++ = ',';
    memcpy(out, parsed, parsed_used);
    out[parsed_used] = '\0';
done:
    free(semantic);
    free(parsed);
    free(quoted);
}

/* Semantic errors are reported before recovered escaped imports and, for
 * unknown identifiers, before syntax recovery errors. Keep earlier include
 * diagnostics in place when returning to the parent source. */
static bool yx_compiler_insert_semantic_diagnostic(YRX_COMPILER *compiler, char *diagnostic, const char *origin, bool before_syntax)
{
    const char *syntax = NULL, *candidate, *next;
    char *joined;
    char *quoted_origin;
    size_t previous, additional, prefix;
    diagnostic = yx_nul_escape_public_json(compiler, diagnostic);
    if (!diagnostic) return false;
    if (!compiler->error_diagnostic_json) return yx_compiler_join_error_diagnostic(compiler, diagnostic);
    quoted_origin = yx_json_quoted_code_origin(origin);
    if (!quoted_origin) {
        free(diagnostic);
        return false;
    }
    for (candidate = strstr(compiler->error_diagnostic_json, "{\"type\":"); candidate; candidate = next) {
        const char *field, *value;
        size_t quoted_length = strlen(quoted_origin);
        bool recovered_escape =
            strncmp(candidate, "{\"type\":\"UnexpectedEscapeSequence\",\"code\":\"E031\"", strlen("{\"type\":\"UnexpectedEscapeSequence\",\"code\":\"E031\"")) == 0;
        bool recovered_syntax =
            before_syntax && strncmp(candidate, "{\"type\":\"SyntaxError\",\"code\":\"E001\"", strlen("{\"type\":\"SyntaxError\",\"code\":\"E001\"")) == 0;
        next = strstr(candidate + 1, "{\"type\":");
        if (!recovered_escape && !recovered_syntax) continue;
        if (compiler->include_depth != 0) {
            syntax = candidate;
            break;
        }
        field = strstr(candidate, "\"code_origin\":");
        if (!field || (next && field >= next)) continue;
        value = field + strlen("\"code_origin\":");
        if ((!next || (size_t)(next - value) > quoted_length) && strncmp(value, quoted_origin, quoted_length) == 0 && value[quoted_length] == ',') {
            syntax = candidate;
            break;
        }
    }
    free(quoted_origin);
    if (!syntax) return yx_compiler_join_error_diagnostic(compiler, diagnostic);
    previous = strlen(compiler->error_diagnostic_json);
    additional = strlen(diagnostic);
    prefix = (size_t)(syntax - compiler->error_diagnostic_json);
    if (previous > SIZE_MAX - additional - 2) {
        free(diagnostic);
        return false;
    }
    joined = (char *)realloc(compiler->error_diagnostic_json, previous + additional + 2);
    if (!joined) {
        free(diagnostic);
        return false;
    }
    memmove(joined + prefix + additional + 1, joined + prefix, previous - prefix + 1);
    memcpy(joined + prefix, diagnostic, additional);
    joined[prefix + additional] = ',';
    compiler->error_diagnostic_json = joined;
    free(diagnostic);
    return true;
}

static char *yx_rule_diagnostic_line(const char *line)
{
    char *copy = yx_strdup(line);
    char *rendered;
    if (!copy) return NULL;
    for (char *at = copy; *at; ++at)
        if (*at == '\t') *at = ' ';
    rendered = yx_diagnostic_render_fragment(copy, strlen(copy));
    free(copy);
    return rendered;
}

static char *yx_rule_diagnostic_middle_line(const char *source, size_t line)
{
    const char *start = source;
    const char *end;
    for (size_t n = 1; n < line; ++n) {
        start = strchr(start, '\n');
        if (!start) return NULL;
        ++start;
    }
    end = strchr(start, '\n');
    if (!end) end = start + strlen(start);
    else if (end > start && end[-1] == '\r') --end;
    size_t length = (size_t)(end - start);
    char *copy = (char *)malloc(length + 1);
    char *rendered;
    if (!copy) return NULL;
    memcpy(copy, start, length);
    copy[length] = '\0';
    rendered = yx_rule_diagnostic_line(copy);
    free(copy);
    return rendered;
}

static char *yx_rule_diagnostic_marker(size_t column, size_t length, char marker)
{
    char *text;
    size_t width;
    if (!column || !length || column - 1 > SIZE_MAX - length) return NULL;
    width = column - 1 + length;
    if (width == SIZE_MAX) return NULL;
    text = (char *)malloc(width + 1);
    if (!text) return NULL;
    memset(text, ' ', column - 1);
    memset(text + column - 1, marker, length);
    text[width] = '\0';
    return text;
}

/* The report of a rule declared in two sources, when the plain form does
 * not fit: a declaration line the renderer's margin cuts, or line numbers
 * of different widths (both sections share the gutter of the wider one).
 * Each section is drawn by the general snippet renderer from the
 * declaration's line. False when the plain form applies; otherwise *text
 * is the report, NULL on failure. */
static bool yx_duplicate_rule_sections(const YRX_RULE *duplicate, const YRX_RULE *existing, const char *title, const char *duplicate_label, const char *existing_label,
                                       const char *duplicate_origin, const char *existing_origin, size_t duplicate_column, size_t existing_column,
                                       size_t identifier_length, char **text)
{
    const YRX_RULE *rules[2] = {duplicate, existing};
    yx_snippet_label labels[2];
    size_t digits[2] = {1, 1}, widest;
    char *first, *second;
    size_t used = 0, capacity = 0;
    bool cut = false;
    *text = NULL;
    for (size_t i = 0; i < 2; ++i) {
        const char *line = rules[i]->declaration_line;
        if (!line || !rules[i]->declaration_column || !rules[i]->declaration_line_number || strchr(line, '\n') ||
            strlen(line) < rules[i]->declaration_column - 1 + identifier_length)
            return false;
        labels[i].start = rules[i]->declaration_column - 1;
        labels[i].end = labels[i].start + identifier_length;
        labels[i].text = i ? existing_label : duplicate_label;
        labels[i].primary = i == 0;
        for (size_t n = rules[i]->declaration_line_number; n >= 10; n /= 10) ++digits[i];
        if (yx_snippet_margin_applies(line, &labels[i].start, 1)) cut = true;
    }
    if (!cut && digits[0] == digits[1]) return false;
    widest = digits[0] > digits[1] ? digits[0] : digits[1];
    first = yx_diagnostic_snippet_section("error", "E012", title, duplicate->declaration_line, duplicate_origin, &labels[0], 1, duplicate->declaration_line_number,
                                          duplicate_column, duplicate->declaration_line_number - 1, widest, false);
    second = yx_diagnostic_snippet_section("error", "E012", title, existing->declaration_line, existing_origin, &labels[1], 1, existing->declaration_line_number,
                                           existing_column, existing->declaration_line_number - 1, widest, true);
    if (first && second && !yx_diagnostic_append(text, &used, &capacity, "%s\n%*s|\n%s", first, (int)widest + 1, "", second)) {
        free(*text);
        *text = NULL;
    }
    free(first);
    free(second);
    return true;
}

int yx_compiler_duplicate_rule_error(YRX_COMPILER *compiler, const YRX_RULE *duplicate, const YRX_RULE *existing, const char *source)
{
    const char *name = duplicate->identifier;
    const char *duplicate_origin = duplicate->declaration_origin;
    const char *existing_origin = existing->declaration_origin;
    const size_t duplicate_line = duplicate->declaration_line_number;
    const size_t existing_line = existing->declaration_line_number;
    /* declaration_column counts bytes: the header and JSON count Unicode
     * scalars, the markers terminal cells (yx_diagnostic_text). */
    size_t duplicate_column = duplicate->declaration_column;
    size_t existing_column = existing->declaration_column;
    size_t duplicate_cell = duplicate_column, existing_cell = existing_column;
    const size_t identifier_length = strlen(name);
    const bool same_source = duplicate->declaration_source_serial == existing->declaration_source_serial;
    char *title = NULL, *duplicate_label = NULL, *existing_label = NULL;
    char *duplicate_text_line = NULL, *existing_text_line = NULL;
    char *duplicate_marker = NULL, *existing_marker = NULL;
    char *text = NULL, *json = NULL, *middle = NULL;
    char *quoted_title = NULL, *quoted_duplicate_label = NULL;
    char *quoted_existing_label = NULL, *quoted_duplicate_origin = NULL;
    char *quoted_existing_origin = NULL, *quoted_text = NULL;
    char *sections = NULL;
    size_t text_used = 0, text_capacity = 0;
    size_t json_used = 0, json_capacity = 0;
    size_t digits = 1;
    bool ok = false;
    int needed;

    for (size_t n = duplicate_line; n >= 10; n /= 10) ++digits;
    if (duplicate->declaration_line && duplicate_column && strlen(duplicate->declaration_line) >= duplicate_column - 1) {
        const char *line = duplicate->declaration_line;
        duplicate_cell = yx_diagnostic_display_width(line, line + duplicate_column - 1) + 1;
        duplicate_column = yx_diagnostic_columns(line, line + duplicate_column - 1) + 1;
    }
    if (existing->declaration_line && existing_column && strlen(existing->declaration_line) >= existing_column - 1) {
        const char *line = existing->declaration_line;
        existing_cell = yx_diagnostic_display_width(line, line + existing_column - 1) + 1;
        existing_column = yx_diagnostic_columns(line, line + existing_column - 1) + 1;
    }
    if (digits > INT_MAX - 1 || duplicate_cell > INT_MAX || existing_cell > INT_MAX || identifier_length > INT_MAX) goto done;
    needed = snprintf(NULL, 0, "duplicate rule `%s`", name);
    if (needed < 0) goto done;
    title = (char *)malloc((size_t)needed + 1);
    if (!title) goto done;
    snprintf(title, (size_t)needed + 1, "duplicate rule `%s`", name);
    needed = snprintf(NULL, 0, "duplicate declaration of `%s`", name);
    if (needed < 0) goto done;
    duplicate_label = (char *)malloc((size_t)needed + 1);
    if (!duplicate_label) goto done;
    snprintf(duplicate_label, (size_t)needed + 1, "duplicate declaration of `%s`", name);
    needed = snprintf(NULL, 0, "`%s` declared here for the first time", name);
    if (needed < 0) goto done;
    existing_label = (char *)malloc((size_t)needed + 1);
    if (!existing_label) goto done;
    snprintf(existing_label, (size_t)needed + 1, "`%s` declared here for the first time", name);
    duplicate_text_line = yx_rule_diagnostic_line(duplicate->declaration_line);
    existing_text_line = yx_rule_diagnostic_line(existing->declaration_line);
    duplicate_marker = yx_rule_diagnostic_marker(duplicate_cell, identifier_length, '^');
    existing_marker = yx_rule_diagnostic_marker(existing_cell, identifier_length, '-');
    if (!duplicate_text_line || !existing_text_line || !duplicate_marker || !existing_marker) goto done;

    /* Lines the renderer's margin cuts are drawn by the general snippet
     * renderer, from the declarations' offsets in the source. */
    if (same_source && source && existing_line <= duplicate_line) {
        const char *existing_start = yx_snippet_line_start(source, existing_line);
        const char *duplicate_start = yx_snippet_line_start(source, duplicate_line);
        if (existing_start && duplicate_start && existing->declaration_column && duplicate->declaration_column &&
            strlen(existing_start) >= existing->declaration_column - 1 + identifier_length &&
            strlen(duplicate_start) >= duplicate->declaration_column - 1 + identifier_length &&
            !memcmp(existing_start + existing->declaration_column - 1, name, identifier_length) &&
            !memcmp(duplicate_start + duplicate->declaration_column - 1, name, identifier_length)) {
            yx_snippet_label labels[2];
            labels[0].start = (size_t)(existing_start - source) + existing->declaration_column - 1;
            labels[0].end = labels[0].start + identifier_length;
            labels[0].text = existing_label;
            labels[0].primary = false;
            labels[1].start = (size_t)(duplicate_start - source) + duplicate->declaration_column - 1;
            labels[1].end = labels[1].start + identifier_length;
            labels[1].text = duplicate_label;
            labels[1].primary = true;
            if (labels[0].end <= labels[1].start && yx_snippet_margin_applies(source, (const size_t[]){labels[0].start, labels[1].start}, 2))
                text = yx_diagnostic_snippet("error", "E012", title, source, duplicate_origin, labels, 2, duplicate_line, duplicate_column);
        }
    }
    if (text) {
        /* Drawn above. */
    } else if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "error[E012]: %s\n%*s--> %s:%zu:%zu\n%*s|\n", title, (int)digits, "", duplicate_origin,
                                     duplicate_line, duplicate_column, (int)digits + 1, ""))
        goto done;
    else if (same_source && existing_line == duplicate_line && existing_cell + identifier_length <= duplicate_cell) {
        size_t marks_length = duplicate_cell - 1 + identifier_length;
        char *marks = (char *)malloc(marks_length + 1);
        if (!marks) goto done;
        memset(marks, ' ', marks_length);
        memset(marks + existing_cell - 1, '-', identifier_length);
        memset(marks + duplicate_cell - 1, '^', identifier_length);
        marks[marks_length] = '\0';
        ok = yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s\n%*s| %*s|\n%*s| %*s%s", (int)digits, duplicate_line, duplicate_text_line,
                                  (int)digits + 1, "", marks, duplicate_label, (int)digits + 1, "", (int)existing_cell - 1, "", (int)digits + 1, "",
                                  (int)existing_cell - 1, "", existing_label);
        free(marks);
        if (!ok) goto done;
    } else if (same_source) {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s\n", (int)digits, existing_line, existing_text_line, (int)digits + 1, "",
                                  existing_marker, existing_label))
            goto done;
        if (duplicate_line == existing_line + 2) {
            middle = yx_rule_diagnostic_middle_line(source, existing_line + 1);
            if (!middle || !yx_diagnostic_append(&text, &text_used, &text_capacity, *middle ? "%*zu | %s\n" : "%*zu |%s\n", (int)digits, existing_line + 1, middle))
                goto done;
        } else if (duplicate_line > existing_line + 2 && !yx_diagnostic_append(&text, &text_used, &text_capacity, "...\n")) goto done;
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s", (int)digits, duplicate_line, duplicate_text_line, (int)digits + 1, "",
                                  duplicate_marker, duplicate_label))
            goto done;
    } else if (yx_duplicate_rule_sections(duplicate, existing, title, duplicate_label, existing_label, duplicate_origin, existing_origin, duplicate_column,
                                          existing_column, identifier_length, &sections)) {
        /* A line the margin cuts, or line numbers of different widths. */
        if (!sections) goto done;
        free(text);
        text = sections;
    } else {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s\n%*s|\n%*s::: %s:%zu:%zu\n%*s|\n%*zu | %s\n%*s| %s %s", (int)digits,
                                  duplicate_line, duplicate_text_line, (int)digits + 1, "", duplicate_marker, duplicate_label, (int)digits + 1, "", (int)digits, "",
                                  existing_origin, existing_line, existing_column, (int)digits + 1, "", (int)digits, existing_line, existing_text_line, (int)digits + 1,
                                  "", existing_marker, existing_label))
            goto done;
    }

    quoted_title = yx_json_quoted(title);
    quoted_duplicate_label = yx_json_quoted(duplicate_label);
    quoted_existing_label = yx_json_quoted(existing_label);
    quoted_duplicate_origin = strcmp(duplicate_origin, "line") == 0 && !duplicate->declaration_origin_explicit ? yx_strdup("null") : yx_json_quoted(duplicate_origin);
    quoted_existing_origin = strcmp(existing_origin, "line") == 0 && !existing->declaration_origin_explicit ? yx_strdup("null") : yx_json_quoted(existing_origin);
    quoted_text = yx_json_quoted(text);
    if (!quoted_title || !quoted_duplicate_label || !quoted_existing_label || !quoted_duplicate_origin || !quoted_existing_origin || !quoted_text) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity,
                              "{\"type\":\"DuplicateRule\",\"code\":\"E012\","
                              "\"title\":%s,\"line\":%zu,\"column\":%zu,"
                              "\"labels\":[{\"level\":\"error\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,\"span\":{\"start\":%zu,"
                              "\"end\":%zu},\"text\":%s},{\"level\":\"note\","
                              "\"code_origin\":%s,\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":%s}],"
                              "\"footers\":[],\"text\":%s}",
                              quoted_title, duplicate_line, duplicate_column, quoted_duplicate_origin, duplicate_line, duplicate_column, duplicate->declaration_start,
                              duplicate->declaration_end, quoted_duplicate_label, quoted_existing_origin, existing_line, existing_column, existing->declaration_start,
                              existing->declaration_end, quoted_existing_label, quoted_text))
        goto done;
    if (!yx_compiler_append_error_diagnostic(compiler, json)) {
        json = NULL;
        goto done;
    }
    json = NULL;
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    ok = true;
done:
    free(title);
    free(duplicate_label);
    free(existing_label);
    free(duplicate_text_line);
    free(existing_text_line);
    free(duplicate_marker);
    free(existing_marker);
    free(middle);
    free(text);
    free(json);
    free(quoted_title);
    free(quoted_duplicate_label);
    free(quoted_existing_label);
    free(quoted_duplicate_origin);
    free(quoted_existing_origin);
    free(quoted_text);
    return ok ? 1 : 0;
}

int yx_compiler_duplicate_pattern_error(YRX_COMPILER *compiler, const char *identifier, const char *source, const char *origin, size_t duplicate_start,
                                        size_t duplicate_end, size_t existing_start, size_t existing_end)
{
    size_t duplicate_line = 1, existing_line = 1;
    size_t duplicate_column, existing_column, digits = 1;
    size_t duplicate_width, existing_width;
    size_t text_used = 0, text_capacity = 0;
    size_t json_used = 0, json_capacity = 0;
    const char *duplicate_line_start = source;
    const char *existing_line_start = source;
    char *title = NULL, *duplicate_label = NULL, *existing_label = NULL;
    char *duplicate_text_line = NULL, *existing_text_line = NULL;
    char *duplicate_marker = NULL, *existing_marker = NULL, *middle = NULL;
    char *text = NULL, *json = NULL;
    char *quoted_title = NULL, *quoted_duplicate_label = NULL;
    char *quoted_existing_label = NULL, *quoted_origin = NULL;
    char *quoted_text = NULL;
    bool ok = false;
    int needed;
    size_t source_length = yx_source_text_length(source);
    if (existing_start >= duplicate_start || existing_end > source_length || duplicate_end > source_length || existing_start >= existing_end ||
        duplicate_start >= duplicate_end)
        return 0;
    existing_line = yx_source_line_of(source, existing_start, &existing_line_start);
    duplicate_line = yx_source_line_of(source, duplicate_start, &duplicate_line_start);
    existing_column = yx_diagnostic_columns(existing_line_start, source + existing_start) + 1;
    duplicate_column = yx_diagnostic_columns(duplicate_line_start, source + duplicate_start) + 1;
    existing_width = yx_diagnostic_columns(source + existing_start, source + existing_end);
    duplicate_width = yx_diagnostic_columns(source + duplicate_start, source + duplicate_end);
    for (size_t n = duplicate_line; n >= 10; n /= 10) ++digits;
    if (digits > INT_MAX - 1 || existing_column > INT_MAX || duplicate_column > INT_MAX || existing_width > INT_MAX || duplicate_width > INT_MAX) goto done;
    needed = snprintf(NULL, 0, "duplicate pattern `%s`", identifier);
    if (needed < 0) goto done;
    title = malloc((size_t)needed + 1);
    if (!title) goto done;
    snprintf(title, (size_t)needed + 1, "duplicate pattern `%s`", identifier);
    needed = snprintf(NULL, 0, "duplicate declaration of `%s`", identifier);
    if (needed < 0) goto done;
    duplicate_label = malloc((size_t)needed + 1);
    if (!duplicate_label) goto done;
    snprintf(duplicate_label, (size_t)needed + 1, "duplicate declaration of `%s`", identifier);
    needed = snprintf(NULL, 0, "`%s` declared here for the first time", identifier);
    if (needed < 0) goto done;
    existing_label = malloc((size_t)needed + 1);
    if (!existing_label) goto done;
    snprintf(existing_label, (size_t)needed + 1, "`%s` declared here for the first time", identifier);
    duplicate_text_line = yx_rule_diagnostic_middle_line(source, duplicate_line);
    existing_text_line = yx_rule_diagnostic_middle_line(source, existing_line);
    duplicate_marker = yx_rule_diagnostic_marker(duplicate_column, duplicate_width, '^');
    existing_marker = yx_rule_diagnostic_marker(existing_column, existing_width, '-');
    if (!duplicate_text_line || !existing_text_line || !duplicate_marker || !existing_marker) goto done;
    if (existing_end <= duplicate_start && yx_snippet_margin_applies(source, (const size_t[]){existing_start, duplicate_start}, 2)) {
        yx_snippet_label labels[2] = {{existing_start, existing_end, existing_label, false}, {duplicate_start, duplicate_end, duplicate_label, true}};
        text = yx_diagnostic_snippet("error", "E023", title, source, origin, labels, 2, duplicate_line, duplicate_column);
    }
    if (text) {
        /* Drawn by the general snippet renderer. */
    } else if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "error[E023]: %s\n%*s--> %s:%zu:%zu\n%*s|\n", title, (int)digits, "", origin ? origin : "line",
                                     duplicate_line, duplicate_column, (int)digits + 1, ""))
        goto done;
    else if (existing_line == duplicate_line) {
        size_t marker_length = duplicate_column - 1 + duplicate_width;
        char *combined = malloc(marker_length + 1);
        if (!combined) goto done;
        memset(combined, ' ', marker_length);
        memset(combined + existing_column - 1, '-', existing_width);
        memset(combined + duplicate_column - 1, '^', duplicate_width);
        combined[marker_length] = '\0';
        ok = yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s\n%*s| %*s|\n%*s| %*s%s", (int)digits, duplicate_line, duplicate_text_line,
                                  (int)digits + 1, "", combined, duplicate_label, (int)digits + 1, "", (int)existing_column - 1, "", (int)digits + 1, "",
                                  (int)existing_column - 1, "", existing_label);
        free(combined);
        if (!ok) goto done;
    } else {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s\n", (int)digits, existing_line, existing_text_line, (int)digits + 1, "",
                                  existing_marker, existing_label))
            goto done;
        if (duplicate_line == existing_line + 2) {
            middle = yx_rule_diagnostic_middle_line(source, existing_line + 1);
            if (!middle || !yx_diagnostic_append(&text, &text_used, &text_capacity, *middle ? "%*zu | %s\n" : "%*zu |%s\n", (int)digits, existing_line + 1, middle))
                goto done;
        } else if (duplicate_line > existing_line + 2 && !yx_diagnostic_append(&text, &text_used, &text_capacity, "...\n")) goto done;
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "%*zu | %s\n%*s| %s %s", (int)digits, duplicate_line, duplicate_text_line, (int)digits + 1, "",
                                  duplicate_marker, duplicate_label))
            goto done;
    }
    quoted_title = yx_json_quoted(title);
    quoted_duplicate_label = yx_json_quoted(duplicate_label);
    quoted_existing_label = yx_json_quoted(existing_label);
    quoted_origin = yx_json_quoted_code_origin(origin);
    quoted_text = yx_json_quoted(text);
    if (!quoted_title || !quoted_duplicate_label || !quoted_existing_label || !quoted_origin || !quoted_text) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity,
                              "{\"type\":\"DuplicatePattern\",\"code\":\"E023\","
                              "\"title\":%s,\"line\":%zu,\"column\":%zu,"
                              "\"labels\":[{\"level\":\"error\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,\"span\":{\"start\":%zu,"
                              "\"end\":%zu},\"text\":%s},{\"level\":\"note\","
                              "\"code_origin\":%s,\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":%s}],"
                              "\"footers\":[],\"text\":%s}",
                              quoted_title, duplicate_line, duplicate_column, quoted_origin, duplicate_line, duplicate_column, duplicate_start, duplicate_end,
                              quoted_duplicate_label, quoted_origin, existing_line, existing_column, existing_start, existing_end, quoted_existing_label, quoted_text))
        goto done;
    ok = yx_compiler_append_error_diagnostic(compiler, json);
    json = NULL;
    if (ok) snprintf(compiler->error, sizeof(compiler->error), "%s", text);
done:
    free(title);
    free(duplicate_label);
    free(existing_label);
    free(duplicate_text_line);
    free(existing_text_line);
    free(duplicate_marker);
    free(existing_marker);
    free(middle);
    free(text);
    free(json);
    free(quoted_title);
    free(quoted_duplicate_label);
    free(quoted_existing_label);
    free(quoted_origin);
    free(quoted_text);
    return ok;
}

int yx_compiler_unknown_identifier_error(YRX_COMPILER *compiler, const char *identifier, const char *source, const char *origin, size_t start, size_t end)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    const char *label = "this identifier has not been declared";
    char note_buffer[256];
    const char *note = NULL;
    char *text, *diagnostic;
    if (yx_known_module(identifier)) {
        snprintf(note_buffer, sizeof(note_buffer), "there is a module named `%s`, but the `import \"%s\"` statement is missing", identifier, identifier);
        note = note_buffer;
    }
    snprintf(title, sizeof(title), "unknown identifier `%s`", identifier);
    text = yx_diagnostic_text("error", "E009", title, label, source, origin, start, end, note);
    if (!text) return 0;
    if (note) {
        char help[160];
        size_t line = 1, digits = 1;
        int help_length;
        /* The help's gutter is as wide as the diagnostic's. */
        {
            const char *ignored_line_start;
            size_t known = yx_source_text_length(source);
            line = yx_source_line_of(source, start < known ? start : known, &ignored_line_start);
        }
        for (size_t n = line; n >= 10; n /= 10) ++digits;
        if (digits > 32) digits = 32;
        help_length = snprintf(help, sizeof(help),
                               "\nhelp: consider the following change\n"
                               "%*s|\n%*d + import \"%s\"\n%*s|",
                               (int)digits + 1, "", (int)digits, 1, identifier, (int)digits + 1, "");
        size_t length = strlen(text);
        char *extended;
        if (help_length < 0 || (size_t)help_length >= sizeof(help) || length > SIZE_MAX - (size_t)help_length - 1) {
            free(text);
            return 0;
        }
        extended = realloc(text, length + (size_t)help_length + 1);
        if (!extended) {
            free(text);
            return 0;
        }
        text = extended;
        memcpy(text + length, help, (size_t)help_length + 1);
    }
    diagnostic = yx_diagnostic_json("UnknownIdentifier", "E009", title, label, text, source, origin, start, end, note, "error");
    if (!yx_compiler_insert_semantic_diagnostic(compiler, diagnostic, origin, true)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_conflicting_rule_error(YRX_COMPILER *compiler, const char *identifier, const char *source, const char *origin, size_t start, size_t end)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    const char *label = "identifier already in use by a module or global variable";
    char *text, *diagnostic;
    snprintf(title, sizeof(title), "rule `%s` conflicts with an existing identifier", identifier);
    text = yx_diagnostic_text("error", "E013", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("ConflictingRuleIdentifier", "E013", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_unknown_module_field_error(YRX_COMPILER *compiler, const char *field, const char *source, const char *origin, size_t start, size_t end)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    const char *label = "this field or method doesn't exist";
    char *text, *diagnostic;
    snprintf(title, sizeof(title), "unknown field or method `%s`", field);
    text = yx_diagnostic_text("error", "E008", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("UnknownField", "E008", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_custom_error(YRX_COMPILER *compiler, const char *title, const char *label, const char *source, const char *origin, size_t start, size_t end)
{
    char *text = yx_diagnostic_text("error", "E100", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("CustomError", "E100", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_vt_acl_error(YRX_COMPILER *compiler, const char *field, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = strcmp(field, "net") == 0        ? "vt.net is not supported in rulesets matching against files"
                        : strcmp(field, "metadata") == 0 ? "vt.metadata is supported only in rulesets matching against files"
                                                         : "vt.behaviour is supported only in rulesets matching against files";
    const char *label = strcmp(field, "net") == 0 ? "this field is not supported for files, consider using `vt.metadata.itw`" : "this field is supported for files only";
    return yx_compiler_custom_error(compiler, title, label, source, origin, start, end);
}

int yx_compiler_entrypoint_unsupported_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    static const char title[] = "`entrypoint` is unsupported";
    static const char label[] = "the `entrypoint` keyword is not supported anymore";
    static const char replacement[] = "pe.entry_point";
    const char *line_start = source + start;
    char *base = NULL, *original = NULL, *changed = NULL;
    char *text = NULL, *json = NULL;
    size_t line = 1, digits = 1, offset, line_length;
    size_t text_used = 0, text_capacity = 0;
    bool ok = false;
    if (end - start != sizeof("entrypoint") - 1) return 0;
    while (line_start > source && line_start[-1] != '\n') --line_start;
    {
        const char *ignored_line_start;
        line = yx_source_line_of(source, (size_t)(line_start - source), &ignored_line_start);
    }
    for (size_t n = line; n >= 10; n /= 10) ++digits;
    if (digits > INT_MAX - 1) return 0;
    original = yx_rule_diagnostic_middle_line(source, line);
    base = yx_diagnostic_text("error", "E017", title, label, source, origin, start, end, NULL);
    if (!original || !base) goto done;
    offset = (size_t)(source + start - line_start);
    /* Source offsets are bytes, while the patch excerpt already renders a
     * bare CR as the three UTF-8 bytes for its one-cell control picture. */
    for (const char *at = line_start; at < source + start; ++at)
        if (*at == '\r') {
            if (offset > SIZE_MAX - 2) goto done;
            offset += 2;
        }
    line_length = strlen(original);
    if (offset + end - start > line_length) goto done;
    changed = malloc(line_length - (end - start) + sizeof(replacement));
    if (!changed) goto done;
    memcpy(changed, original, offset);
    memcpy(changed + offset, replacement, sizeof(replacement) - 1);
    memcpy(changed + offset + sizeof(replacement) - 1, original + offset + end - start, line_length - offset - (end - start) + 1);
    if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                              "%s\n%*s|\nhelp: use `pe.entry_point`, elf.entry_point` or "
                              "`macho.entry_point`\n%*s|\n%zu - %s\n%zu + %s\n%*s|",
                              base, (int)digits + 1, "", (int)digits + 1, "", line, original, line, changed, (int)digits + 1, ""))
        goto done;
    /* Colored, the patch marks the whole replaced span and replacement. */
    yx_note_patch(compiler, text, offset, end - start, sizeof(replacement) - 1);
    json = yx_diagnostic_json("EntrypointUnsupported", "E017", title, label, text, source, origin, start, end, NULL, "error");
    if (!json) goto done;
    ok = yx_compiler_append_error_diagnostic(compiler, json);
    json = NULL;
    if (ok) snprintf(compiler->error, sizeof(compiler->error), "%s", text);
done:
    free(base);
    free(original);
    free(changed);
    free(text);
    free(json);
    return ok;
}

int yx_compiler_duplicate_tag_error(YRX_COMPILER *compiler, const char *tag, const char *source, const char *origin, size_t start, size_t end)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    const char *label = "duplicate tag";
    char *text, *diagnostic;
    snprintf(title, sizeof(title), "duplicate tag `%s`", tag);
    text = yx_diagnostic_text("error", "E021", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("DuplicateTag", "E021", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_unknown_pattern_error(YRX_COMPILER *compiler, const char *pattern, const char *source, const char *origin, size_t start, size_t end)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    const char *label = "this pattern is not declared in the `strings` section";
    char *text, *diagnostic;
    snprintf(title, sizeof(title), "unknown pattern `%s`", pattern);
    text = yx_diagnostic_text("error", "E025", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("UnknownPattern", "E025", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_unused_pattern_error(YRX_COMPILER *compiler, const char *pattern, const char *source, const char *origin, size_t start, size_t end)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    const char *label = "this pattern was not used in the condition";
    char *text, *diagnostic;
    snprintf(title, sizeof(title), "unused pattern `%s`", pattern);
    text = yx_diagnostic_text("error", "E022", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("UnusedPattern", "E022", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_insert_semantic_diagnostic(compiler, diagnostic, origin, false)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_empty_pattern_set_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *note)
{
    const char *title = "no matching patterns";
    const char *label = "there's no pattern in this set";
    char *text = yx_diagnostic_text("error", "E016", title, label, source, origin, start, end, note);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("EmptyPatternSet", "E016", title, label, text, source, origin, start, end, note, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_unexpected_negative_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "unexpected negative number";
    const char *label = "this number can not be negative";
    char *text = yx_diagnostic_text("error", "E006", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("UnexpectedNegativeNumber", "E006", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_invalid_escape_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, bool hexadecimal)
{
    const char *title = "invalid escape sequence";
    const char *hex_label = "expecting two hex digits after `\\x`";
    char *dynamic_label = NULL;
    const char *label;
    size_t used = 0, capacity = 0;
    size_t display_end = end > start + 2 ? start + 2 : end;
    char *text, *diagnostic;
    if (hexadecimal) {
        label = hex_label;
    } else {
        if (end < start || end - start > INT_MAX ||
            !yx_diagnostic_append(&dynamic_label, &used, &capacity, "invalid escape sequence `%.*s`", (int)(end - start), source + start))
            return 0;
        label = dynamic_label;
    }
    text = yx_diagnostic_text("error", "E029", title, label, source, origin, start, display_end, NULL);
    if (!text) {
        free(dynamic_label);
        return 0;
    }
    diagnostic = yx_diagnostic_json("InvalidEscapeSequence", "E029", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(dynamic_label);
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(dynamic_label);
    free(text);
    return 1;
}

int yx_compiler_invalid_regexp_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *label, const char *note)
{
    const char *title = "invalid regular expression";
    char *text = yx_diagnostic_text("error", "E014", title, label, source, origin, start, end, note);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("InvalidRegexp", "E014", title, label, text, source, origin, start, end, note, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_arbitrary_regexp_prefix_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "arbitrary regular expression prefix";
    const char *label = "this prefix can be arbitrarily long and matches all bytes";
    char *text = yx_diagnostic_text("error", "E045", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("ArbitraryRegexpPrefix", "E045", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_invalid_pattern_error(YRX_COMPILER *compiler, const char *identifier, const char *source, const char *origin, size_t start, size_t end, const char *label,
                                      const char *note)
{
    char title[YX_DIAG_NAME_TEXT_SIZE];
    char *text, *diagnostic;
    snprintf(title, sizeof(title), "invalid pattern `%s`", identifier);
    text = yx_diagnostic_text("error", "E024", title, label, source, origin, start, end, note);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("InvalidPattern", "E024", title, label, text, source, origin, start, end, note, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_invalid_integer_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *range)
{
    const char *title = "invalid integer";
    char label[160];
    char *text, *diagnostic;
    snprintf(label, sizeof(label), "this number is out of the valid range: %s", range);
    text = yx_diagnostic_text("error", "E027", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("InvalidInteger", "E027", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_number_out_of_range_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *range)
{
    const char *title = "number out of range";
    char label[160];
    char *text, *diagnostic;
    snprintf(label, sizeof(label), "this number is out of the allowed range %s", range);
    text = yx_diagnostic_text("error", "E007", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("NumberOutOfRange", "E007", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_invalid_range_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, int64_t lower, int64_t upper)
{
    const char *title = "invalid range";
    char label[160];
    char *text, *diagnostic;
    snprintf(label, sizeof(label), "lower bound (%" PRId64 ") is greater than upper bound (%" PRId64 ")", lower, upper);
    text = yx_diagnostic_text("error", "E011", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("InvalidRange", "E011", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_unexpected_escape_sequence_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "unexpected escape sequence";
    const char *label = "escape sequences are not allowed in this string";
    char *text = yx_diagnostic_text("error", "E031", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("UnexpectedEscapeSequence", "E031", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_invalid_base64_alphabet_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *label)
{
    const char *title = "invalid base64 alphabet";
    char *text = yx_diagnostic_text("error", "E026", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("InvalidBase64Alphabet", "E026", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

static int yx_compiler_simple_modifier_error(YRX_COMPILER *compiler, const char *source, const char *origin, const char *type, const char *code, const char *title,
                                             const char *label, size_t start, size_t end)
{
    char *text = yx_diagnostic_text("error", code, title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json(type, code, title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_duplicate_modifier_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    return yx_compiler_simple_modifier_error(compiler, source, origin, "DuplicateModifier", "E020", "duplicate pattern modifier", "duplicate modifier", start, end);
}

int yx_compiler_invalid_modifier_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *label)
{
    return yx_compiler_simple_modifier_error(compiler, source, origin, "InvalidModifier", "E033", "invalid pattern modifier", label, start, end);
}

int yx_compiler_invalid_regexp_modifier_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    char title[80];
    snprintf(title, sizeof(title), "invalid regexp modifier `%c`", source[start]);
    return yx_compiler_simple_modifier_error(compiler, source, origin, "InvalidRegexpModifier", "E030", title, "invalid modifier", start, end);
}

int yx_compiler_invalid_modifier_combination_error(YRX_COMPILER *compiler, const char *source, const char *origin, const char *first, size_t first_start,
                                                   size_t first_end, const char *second, size_t second_start, size_t second_end)
{
    const char *line_start = source;
    const char *line_end;
    const char *left_line_start, *left_line_end;
    const char *right_line_start, *right_line_end;
    const char *left_name, *right_name;
    size_t left_start, left_end, right_start, right_end;
    size_t line = 1, first_line = 1, second_line = 1;
    size_t right_line;
    size_t first_column, second_column, left_column, right_column;
    size_t left_width, right_width, gap, digits = 1;
    size_t text_used = 0, text_capacity = 0, json_used = 0, json_capacity = 0;
    char title[128], first_label[64], second_label[64];
    char *left_marks = NULL, *right_marks = NULL;
    char *quoted_title = NULL, *quoted_first = NULL, *quoted_second = NULL;
    char *quoted_origin = NULL, *quoted_text = NULL;
    char *text = NULL, *json = NULL;
    bool ok = false;

    first_line = yx_source_line_of(source, first_start, &line_start);
    first_column = yx_diagnostic_columns(line_start, source + first_start) + 1;
    line_start = source;
    second_line = yx_source_line_of(source, second_start, &line_start);
    second_column = yx_diagnostic_columns(line_start, source + second_start) + 1;
    line = first_line < second_line ? first_line : second_line;
    line_end = strchr(line_start, '\n');
    if (!line_end) line_end = source + yx_source_text_length(source);
    for (size_t n = line; n >= 10; n /= 10) ++digits;
    if (first_start <= second_start) {
        left_name = first;
        left_start = first_start;
        left_end = first_end;
        right_name = second;
        right_start = second_start;
        right_end = second_end;
        left_column = first_column;
        right_column = second_column;
        right_line = second_line;
    } else {
        left_name = second;
        left_start = second_start;
        left_end = second_end;
        right_name = first;
        right_start = first_start;
        right_end = first_end;
        left_column = second_column;
        right_column = first_column;
        right_line = first_line;
    }
    left_width = yx_diagnostic_columns(source + left_start, source + left_end);
    right_width = yx_diagnostic_columns(source + right_start, source + right_end);
    left_line_start = source + left_start;
    while (left_line_start > source && left_line_start[-1] != '\n') --left_line_start;
    right_line_start = source + right_start;
    while (right_line_start > source && right_line_start[-1] != '\n') --right_line_start;
    left_line_end = strchr(left_line_start, '\n');
    right_line_end = strchr(right_line_start, '\n');
    if (!left_line_end) left_line_end = source + yx_source_text_length(source);
    if (!right_line_end) right_line_end = source + yx_source_text_length(source);
    line_end = yx_diagnostic_display_line_end(line_start, line_end);
    left_line_end = yx_diagnostic_display_line_end(left_line_start, left_line_end);
    right_line_end = yx_diagnostic_display_line_end(right_line_start, right_line_end);
    if (!left_width || !right_width || (first_line == second_line && right_column < left_column + left_width) || right_column > INT_MAX || left_column > INT_MAX ||
        left_width > INT_MAX || right_width > INT_MAX || digits > INT_MAX - 1 || left_line_end - left_line_start > INT_MAX || right_line_end - right_line_start > INT_MAX)
        goto done;
    gap = first_line == second_line ? right_column - left_column - left_width : 0;
    if (gap > INT_MAX) goto done;
    left_marks = malloc(left_width + 1);
    right_marks = malloc(right_width + 1);
    if (!left_marks || !right_marks) goto done;
    memset(left_marks, '^', left_width);
    left_marks[left_width] = 0;
    memset(right_marks, '^', right_width);
    right_marks[right_width] = 0;
    snprintf(title, sizeof(title), "invalid modifier combination: `%s` `%s`", first, second);
    snprintf(first_label, sizeof(first_label), "`%s` modifier used here", first);
    snprintf(second_label, sizeof(second_label), "`%s` modifier used here", second);
    /* Lines the renderer's margin cuts are drawn by the general snippet
     * renderer. */
    if (left_end <= right_start && yx_snippet_margin_applies(source, (const size_t[]){left_start, right_start}, 2)) {
        yx_snippet_label labels[2];
        size_t last_line = first_line > second_line ? first_line : second_line;
        size_t note_digits = 1;
        for (size_t n = last_line; n >= 10; n /= 10) ++note_digits;
        labels[0].start = left_start;
        labels[0].end = left_end;
        labels[0].text = left_start == first_start ? first_label : second_label;
        labels[0].primary = true;
        labels[1].start = right_start;
        labels[1].end = right_end;
        labels[1].text = left_start == first_start ? second_label : first_label;
        labels[1].primary = true;
        text = yx_diagnostic_snippet("error", "E019", title, source, origin, labels, 2, line, left_column);
        if (text) {
            text_used = strlen(text);
            text_capacity = text_used + 1;
            if (!yx_diagnostic_append(&text, &text_used, &text_capacity, "\n%*s|\n%*s= note: these two modifiers can't be used together", (int)note_digits + 1, "",
                                      (int)note_digits + 1, ""))
                goto done;
        }
    }
    if (!text && first_line == second_line &&
        !yx_diagnostic_append(&text, &text_used, &text_capacity,
                              "error[E019]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                              "%*zu | %.*s\n%*s| %*s%s%*s%s `%s` modifier used here\n"
                              "%*s| %*s|\n%*s| %*s`%s` modifier used here\n"
                              "%*s|\n%*s= note: these two modifiers can't be used together",
                              title, (int)digits, "", origin ? origin : "line", line, left_column, (int)digits + 1, "", (int)digits, line, (int)(line_end - line_start),
                              line_start, (int)digits + 1, "", (int)left_column - 1, "", left_marks, (int)gap, "", right_marks, right_name, (int)digits + 1, "",
                              (int)left_column - 1, "", (int)digits + 1, "", (int)left_column - 1, "", left_name, (int)digits + 1, "", (int)digits + 1, ""))
        goto done;
    if (!text_used && first_line != second_line &&
        !yx_diagnostic_append(&text, &text_used, &text_capacity,
                              "error[E019]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                              "%*zu | %.*s\n%*s| %*s%s `%s` modifier used here\n"
                              "%*zu | %.*s\n%*s| %*s%s `%s` modifier used here\n"
                              "%*s|\n%*s= note: these two modifiers can't be used together",
                              title, (int)digits, "", origin ? origin : "line", line, left_column, (int)digits + 1, "", (int)digits, line,
                              (int)(left_line_end - left_line_start), left_line_start, (int)digits + 1, "", (int)left_column - 1, "", left_marks, left_name, (int)digits,
                              right_line, (int)(right_line_end - right_line_start), right_line_start, (int)digits + 1, "", (int)right_column - 1, "", right_marks,
                              right_name, (int)digits + 1, "", (int)digits + 1, ""))
        goto done;
    if (!yx_diagnostic_normalize_visible_cr(&text)) goto done;
    quoted_title = yx_json_quoted(title);
    quoted_first = yx_json_quoted(first_label);
    quoted_second = yx_json_quoted(second_label);
    quoted_origin = yx_json_quoted_code_origin(origin);
    quoted_text = yx_json_quoted(text);
    if (!quoted_title || !quoted_first || !quoted_second || !quoted_origin || !quoted_text) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity,
                              "{\"type\":\"InvalidModifierCombination\",\"code\":\"E019\","
                              "\"title\":%s,\"line\":%zu,\"column\":%zu,\"labels\":["
                              "{\"level\":\"error\",\"code_origin\":%s,\"line\":%zu,"
                              "\"column\":%zu,\"span\":{\"start\":%zu,\"end\":%zu},"
                              "\"text\":%s},{\"level\":\"error\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,\"span\":{\"start\":%zu,"
                              "\"end\":%zu},\"text\":%s}],\"footers\":[{\"level\":\"note\","
                              "\"text\":\"these two modifiers can't be used together\"}],\"text\":%s}",
                              quoted_title, first_line, first_column, quoted_origin, first_line, first_column, first_start, first_end, quoted_first, quoted_origin,
                              second_line, second_column, second_start, second_end, quoted_second, quoted_text))
        goto done;
    ok = yx_compiler_append_error_diagnostic(compiler, json);
    json = NULL;
    if (ok) snprintf(compiler->error, sizeof(compiler->error), "%s", text);
done:
    free(left_marks);
    free(right_marks);
    free(quoted_title);
    free(quoted_first);
    free(quoted_second);
    free(quoted_origin);
    free(quoted_text);
    free(text);
    free(json);
    return ok;
}

int yx_compiler_wrong_type_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *expected, const char *actual)
{
    const char *title = "wrong type";
    char label[192];
    char *text, *diagnostic;
    /* bool_expr_from_ast describes kinds with an article ("a struct",
     * "an array"); other checks quote a type name. */
    if (strncmp(actual, "a ", 2) == 0 || strncmp(actual, "an ", 3) == 0) snprintf(label, sizeof(label), "expression should be %s, but it is %s", expected, actual);
    else snprintf(label, sizeof(label), "expression should be %s, but it is `%s`", expected, actual);
    text = yx_diagnostic_text("error", "E002", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("WrongType", "E002", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_insert_semantic_diagnostic(compiler, diagnostic, origin, true)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

/* E002 with a `help` footer (bool_expr_from_ast: "you probably meant
 * f()" for a function value that can be called without arguments or
 * returns a bool). */
int yx_compiler_wrong_type_help_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *expected, const char *actual,
                                      const char *help)
{
    static const char meant[] = "you probably meant ";
    const char *title = "wrong type";
    const char *json_help = help;
    char label[192];
    char *text, *diagnostic, *footer, *painted = NULL;
    snprintf(label, sizeof(label), "expression should be %s, but it is %s", expected, actual);
    text = yx_diagnostic_text("error", "E002", title, label, source, origin, start, end, help);
    if (!text) return 0;
    /* The footer is a help, not a note. */
    footer = strstr(text, "= note: ");
    if (footer) memcpy(footer + 2, "help", 4);
    /* With colours the footer's own text paints the call green
     * (ReportBuilder::green_style). */
    if (help && (compiler->flags & YRX_COLORIZE_ERRORS) && strncmp(help, meant, sizeof(meant) - 1) == 0) {
        size_t length = strlen(help) + 10;
        painted = (char *)malloc(length);
        if (!painted) {
            free(text);
            return 0;
        }
        snprintf(painted, length, "%s\x1b[92m%s\x1b[0m", meant, help + sizeof(meant) - 1);
        json_help = painted;
    }
    diagnostic = yx_diagnostic_json("WrongType", "E002", title, label, text, source, origin, start, end, json_help, "error");
    free(painted);
    if (diagnostic) {
        footer = strstr(diagnostic, "\"footers\":[{\"level\":\"note\"");
        if (footer) memcpy(footer + strlen("\"footers\":[{\"level\":\""), "help", 4);
    }
    if (!yx_compiler_insert_semantic_diagnostic(compiler, diagnostic, origin, true)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_wrong_arguments_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *note)
{
    const char *title = "wrong arguments";
    const char *label = "wrong arguments in this call";
    size_t line = 1, digits = 1, indent, note_length, breaks = 0;
    char *rendered_note, *text, *diagnostic;
    {
        const char *ignored_line_start;
        size_t known = yx_source_text_length(source);
        line = yx_source_line_of(source, start < known ? start : known, &ignored_line_start);
    }
    for (size_t value = line; value >= 10; value /= 10) ++digits;
    indent = digits + 9;
    note_length = strlen(note);
    for (size_t i = 0; i < note_length; ++i)
        if (note[i] == '\n') ++breaks;
    if (breaks && indent > (SIZE_MAX - note_length - 1) / breaks) return 0;
    rendered_note = malloc(note_length + breaks * indent + 1);
    if (!rendered_note) return 0;
    char *out = rendered_note;
    for (size_t i = 0; i < note_length; ++i) {
        *out++ = note[i];
        if (note[i] == '\n') {
            memset(out, ' ', indent);
            out += indent;
        }
    }
    *out = '\0';
    text = yx_diagnostic_text("error", "E004", title, label, source, origin, start, end, rendered_note);
    free(rendered_note);
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("WrongArguments", "E004", title, label, text, source, origin, start, end, note, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

static int yx_compiler_two_label_error(YRX_COMPILER *compiler, const char *source, const char *origin, const char *type, const char *code, const char *title,
                                       size_t first_start, size_t first_end, const char *first_label, size_t second_start, size_t second_end, const char *second_label,
                                       bool later_first_json)
{
    const char *first_line_start = source, *second_line_start = source;
    size_t first_line = 1, second_line = 1, first_column, second_column;
    size_t first_width, second_width, digits = 1;
    size_t text_used = 0, text_capacity = 0;
    size_t json_used = 0, json_capacity = 0;
    char *first_source_line = NULL, *second_source_line = NULL;
    char *first_marker = NULL, *second_marker = NULL, *vertical_marker = NULL;
    char *quoted_first = NULL, *quoted_second = NULL;
    char *quoted_origin = NULL, *quoted_text = NULL;
    char *quoted_type = NULL, *quoted_code = NULL, *quoted_title = NULL;
    char *text = NULL, *json = NULL;
    bool ok = false;
    bool stacked = strcmp(type, "MixedGreediness") == 0 && first_start == second_start;
    /* A repetition inside another (`(a+?)+`): both labels hang below the
     * union of the spans, the inner one first. */
    bool nested = strcmp(type, "MixedGreediness") == 0 && first_start < second_start && second_start < first_end &&
                  !memchr(source + first_start, '\n', (first_end > second_end ? first_end : second_end) - first_start);
    size_t source_length = yx_source_text_length(source);
    if (first_start > first_end || second_start > second_end || first_end > source_length || second_end > source_length || (first_start >= second_start && !stacked))
        return 0;
    first_line = yx_source_line_of(source, first_start, &first_line_start);
    second_line = yx_source_line_of(source, second_start, &second_line_start);
    first_column = yx_diagnostic_columns(first_line_start, source + first_start) + 1;
    second_column = yx_diagnostic_columns(second_line_start, source + second_start) + 1;
    first_width = yx_diagnostic_columns(source + first_start, source + first_end);
    second_width = yx_diagnostic_columns(source + second_start, source + second_end);
    /* Labels more than a line apart show the line between them, or `...`
     * for several: the general snippet renderer draws that. */
    if (memchr(source + first_start, '\n', first_end - first_start) || memchr(source + second_start, '\n', second_end - second_start) || second_line > first_line + 1 ||
        yx_snippet_margin_applies(source, (const size_t[]){first_start, second_start}, 2)) {
        yx_snippet_label labels[2];
        labels[0].start = first_start;
        labels[0].end = first_end;
        labels[0].text = first_label;
        labels[0].primary = true;
        labels[1].start = second_start;
        labels[1].end = second_end;
        labels[1].text = second_label;
        labels[1].primary = true;
        text = yx_diagnostic_snippet("error", code, title, source, origin, labels, 2, first_line, first_column);
        if (!text) goto done;
        goto json;
    }
    if (!first_width || !second_width || first_column > INT_MAX || second_column > INT_MAX || first_width > INT_MAX || second_width > INT_MAX ||
        (!stacked && !nested && first_line == second_line && first_column + first_width > second_column))
        return 0;
    for (size_t n = second_line; n >= 10; n /= 10) ++digits;
    if (digits > INT_MAX - 1) return 0;
    first_source_line = yx_rule_diagnostic_middle_line(source, first_line);
    second_source_line = first_line == second_line ? NULL : yx_rule_diagnostic_middle_line(source, second_line);
    first_marker = yx_rule_diagnostic_marker(first_column, first_width, '^');
    second_marker = yx_rule_diagnostic_marker(second_column, stacked && first_width > second_width ? first_width : second_width, '^');
    vertical_marker = yx_rule_diagnostic_marker(first_column, 1, '|');
    if (!first_source_line || !first_marker || !second_marker || !vertical_marker || (first_line != second_line && !second_source_line)) goto done;
    /* A nested pair draws the union of its spans instead: the outer span
     * can end past the inner marker's buffer. */
    if (first_line == second_line && !nested) memset(second_marker + first_column - 1, '^', first_width);
    if (nested) {
        size_t union_width = first_column + first_width > second_column + second_width ? first_width : second_column + second_width - first_column;
        char *union_marker = yx_rule_diagnostic_marker(first_column, union_width, '^');
        if (!union_marker ||
            !yx_diagnostic_append(&text, &text_used, &text_capacity,
                                  "error[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                  "%*zu | %s\n%*s| %s\n%*s| %*s|%*s|\n%*s| %*s|%*s%s\n%*s| %*s%s",
                                  code, title, (int)digits, "", origin ? origin : "line", first_line, first_column, (int)digits + 1, "", (int)digits, first_line,
                                  first_source_line, (int)digits + 1, "", union_marker, (int)digits + 1, "", (int)first_column - 1, "",
                                  (int)(second_column - first_column - 1), "", (int)digits + 1, "", (int)first_column - 1, "", (int)(second_column - first_column - 1),
                                  "", second_label, (int)digits + 1, "", (int)first_column - 1, "", first_label)) {
            free(union_marker);
            goto done;
        }
        free(union_marker);
    } else if (stacked) {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                                  "error[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                  "%*zu | %s\n%*s| %s\n%*s| %s\n%*s| %*s%s\n%*s| %*s%s",
                                  code, title, (int)digits, "", origin ? origin : "line", first_line, first_column, (int)digits + 1, "", (int)digits, first_line,
                                  first_source_line, (int)digits + 1, "", second_marker, (int)digits + 1, "", vertical_marker, (int)digits + 1, "", (int)first_column - 1,
                                  "", first_label, (int)digits + 1, "", (int)second_column - 1, "", second_label))
            goto done;
    } else if (first_line == second_line) {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                                  "error[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                  "%*zu | %s\n%*s| %s %s\n%*s| %s\n%*s| %*s%s",
                                  code, title, (int)digits, "", origin ? origin : "line", first_line, first_column, (int)digits + 1, "", (int)digits, first_line,
                                  first_source_line, (int)digits + 1, "", second_marker, second_label, (int)digits + 1, "", vertical_marker, (int)digits + 1, "",
                                  (int)first_column - 1, "", first_label))
            goto done;
    } else {
        if (!yx_diagnostic_append(&text, &text_used, &text_capacity,
                                  "error[%s]: %s\n%*s--> %s:%zu:%zu\n%*s|\n"
                                  "%*zu | %s\n%*s| %s %s\n%*zu | %s\n%*s| %s %s",
                                  code, title, (int)digits, "", origin ? origin : "line", first_line, first_column, (int)digits + 1, "", (int)digits, first_line,
                                  first_source_line, (int)digits + 1, "", first_marker, first_label, (int)digits, second_line, second_source_line, (int)digits + 1, "",
                                  second_marker, second_label))
            goto done;
    }
json:
    quoted_first = yx_json_quoted(first_label);
    quoted_second = yx_json_quoted(second_label);
    quoted_type = yx_json_quoted(type);
    quoted_code = yx_json_quoted(code);
    quoted_title = yx_json_quoted(title);
    quoted_origin = yx_json_quoted_code_origin(origin);
    quoted_text = yx_json_quoted(text);
    if (!quoted_first || !quoted_second || !quoted_type || !quoted_code || !quoted_title || !quoted_origin || !quoted_text) goto done;
    if (!yx_diagnostic_append(&json, &json_used, &json_capacity,
                              "{\"type\":%s,\"code\":%s,"
                              "\"title\":%s,\"line\":%zu,\"column\":%zu,"
                              "\"labels\":[{\"level\":\"error\",\"code_origin\":%s,"
                              "\"line\":%zu,\"column\":%zu,\"span\":{\"start\":%zu,"
                              "\"end\":%zu},\"text\":%s},{\"level\":\"error\","
                              "\"code_origin\":%s,\"line\":%zu,\"column\":%zu,"
                              "\"span\":{\"start\":%zu,\"end\":%zu},\"text\":%s}],"
                              "\"footers\":[],\"text\":%s}",
                              quoted_type, quoted_code, quoted_title, later_first_json ? second_line : first_line, later_first_json ? second_column : first_column,
                              quoted_origin, later_first_json ? second_line : first_line, later_first_json ? second_column : first_column,
                              later_first_json ? second_start : first_start, later_first_json ? second_end : first_end, later_first_json ? quoted_second : quoted_first,
                              quoted_origin, later_first_json ? first_line : second_line, later_first_json ? first_column : second_column,
                              later_first_json ? first_start : second_start, later_first_json ? first_end : second_end, later_first_json ? quoted_first : quoted_second,
                              quoted_text))
        goto done;
    ok = yx_compiler_append_error_diagnostic(compiler, json);
    json = NULL;
    if (ok) snprintf(compiler->error, sizeof(compiler->error), "%s", text);
done:
    free(first_source_line);
    free(second_source_line);
    free(first_marker);
    free(second_marker);
    free(vertical_marker);
    free(quoted_first);
    free(quoted_second);
    free(quoted_type);
    free(quoted_code);
    free(quoted_title);
    free(quoted_origin);
    free(quoted_text);
    free(text);
    free(json);
    return ok;
}

int yx_compiler_mismatching_types_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t first_start, size_t first_end, const char *first_type,
                                        size_t second_start, size_t second_end, const char *second_type)
{
    char first_label[80], second_label[80];
    snprintf(first_label, sizeof(first_label), "this expression is `%s`", first_type);
    snprintf(second_label, sizeof(second_label), "this expression is `%s`", second_type);
    return yx_compiler_two_label_error(compiler, source, origin, "MismatchingTypes", "E003", "mismatching types", first_start, first_end, first_label, second_start,
                                       second_end, second_label, false);
}

int yx_compiler_assignment_mismatch_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t binding_start, size_t binding_end, size_t binding_count,
                                          size_t iterable_start, size_t iterable_end, size_t iterable_count)
{
    char binding_label[80], iterable_label[80];
    snprintf(binding_label, sizeof(binding_label), "this expects %zu value(s)", binding_count);
    snprintf(iterable_label, sizeof(iterable_label), "this produces %zu value(s)", iterable_count);
    return yx_compiler_two_label_error(compiler, source, origin, "AssignmentMismatch", "E005", "assignment mismatch", binding_start, binding_end, binding_label,
                                       iterable_start, iterable_end, iterable_label, false);
}

int yx_compiler_method_binding_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "method not allowed in `with` statement";
    const char *label = "this method is not allowed here";
    char *text = yx_diagnostic_text("error", "E036", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("MethodNotAllowedInWith", "E036", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_mixed_greediness_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t greedy_start, size_t greedy_end, size_t lazy_start,
                                       size_t lazy_end)
{
    static const char title[] = "mixing greedy and non-greedy quantifiers in regular expression";
    if (greedy_start < lazy_start || (greedy_start == lazy_start && greedy_end < lazy_end))
        return yx_compiler_two_label_error(compiler, source, origin, "MixedGreediness", "E015", title, greedy_start, greedy_end, "this is greedy", lazy_start, lazy_end,
                                           "this is non-greedy", true);
    return yx_compiler_two_label_error(compiler, source, origin, "MixedGreediness", "E015", title, lazy_start, lazy_end, "this is non-greedy", greedy_start, greedy_end,
                                       "this is greedy", true);
}

int yx_compiler_syntax_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *label)
{
    const char *title = "syntax error";
    char *text = yx_diagnostic_text("error", "E001", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("SyntaxError", "E001", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

/* Source diagnostics use the UTF-8 text after replacement characters have
 * been inserted. Record the first malformed sequence in those byte offsets.
 * Escaped NULs become the one-column control picture U+2400, after their
 * backslash when they had one, so the recorded offsets and the rendered text
 * stay in the copy's coordinates; `escapes_before` counts the escapes before
 * the first malformed sequence. */
static char *yx_lossy_source_utf8(const char *source, size_t *first_invalid, bool *truncated_at_end, const yx_nul_escape_entry *nul_escape, size_t *escapes_before)
{
    static const char replacement[] = "\xef\xbf\xbd";
    size_t length = yx_source_text_length(source), used = 0, escape_at = 0;
    const unsigned char *bytes = (const unsigned char *)source;
    char *result;
    if (length > (SIZE_MAX - 1) / 3) return NULL;
    result = (char *)malloc(length * 3 + 1);
    if (!result) return NULL;
    *first_invalid = SIZE_MAX;
    *truncated_at_end = false;
    *escapes_before = 0;
    for (size_t at = 0; at < length;) {
        unsigned char lead = bytes[at];
        size_t width = 0, valid_prefix = 1;
        bool valid = false, incomplete = false;
        if (nul_escape && escape_at < nul_escape->count && at == nul_escape->escapes[escape_at].offset) {
            if (nul_escape->escapes[escape_at].kind != YX_NUL_BARE) result[used++] = '\\';
            memcpy(result + used, "\xe2\x90\x80", 3);
            used += 3;
            at += 4;
            ++escape_at;
            continue;
        }
        if (lead < 0x80) width = 1;
        else if (lead >= 0xc2 && lead <= 0xdf) width = 2;
        else if (lead >= 0xe0 && lead <= 0xef) width = 3;
        else if (lead >= 0xf0 && lead <= 0xf4) width = 4;
        if (width == 1) {
            valid = true;
        } else if (width > 1) {
            for (; valid_prefix < width; ++valid_prefix) {
                unsigned char next;
                if (at + valid_prefix >= length) {
                    incomplete = true;
                    break;
                }
                next = bytes[at + valid_prefix];
                if ((next & 0xc0) != 0x80 || (valid_prefix == 1 && ((lead == 0xe0 && next < 0xa0) || (lead == 0xed && next >= 0xa0) || (lead == 0xf0 && next < 0x90) ||
                                                                    (lead == 0xf4 && next >= 0x90))))
                    break;
            }
            valid = valid_prefix == width;
        }
        if (valid) {
            memcpy(result + used, source + at, width);
            used += width;
            at += width;
        } else {
            if (*first_invalid == SIZE_MAX) {
                *first_invalid = used;
                *truncated_at_end = incomplete;
                *escapes_before = escape_at;
            }
            memcpy(result + used, replacement, sizeof(replacement) - 1);
            used += sizeof(replacement) - 1;
            at += valid_prefix;
        }
    }
    result[used] = '\0';
    return result;
}

static int yx_compiler_invalid_utf8_error(YRX_COMPILER *compiler, const char *source, const char *origin)
{
    static const char title[] = "invalid UTF-8";
    static const char label[] = "invalid UTF-8 character";
    size_t start, end, escapes;
    bool truncated_at_end, appended;
    const yx_nul_escape_entry *nul_escape = yx_nul_escape_find(compiler, source);
    char *display = yx_lossy_source_utf8(source, &start, &truncated_at_end, nul_escape, &escapes);
    char *text, *diagnostic;
    unsigned char space;
    if (!display || start == SIZE_MAX) {
        free(display);
        return 0;
    }
    end = truncated_at_end ? start : start + 3;
    text = yx_diagnostic_text("error", "E032", title, label, display, origin, start, end, NULL);
    diagnostic = text ? yx_diagnostic_json("InvalidUTF8", "E032", title, label, text, display, origin, start, end, NULL, "error") : NULL;
    free(display);
    /* Each escape before the malformed sequence is 2 bytes longer in the
     * copy than in the original source (U+2400 for NUL). */
    if (nul_escape) diagnostic = yx_nul_escape_rewrite_json(nul_escape, diagnostic, YX_NUL_SPACE_ORIGINAL, 2 * escapes);
    space = compiler->nul_json_space;
    compiler->nul_json_space = YX_NUL_SPACE_ORIGINAL;
    appended = diagnostic && yx_compiler_append_error_diagnostic(compiler, diagnostic);
    compiler->nul_json_space = space;
    if (!appended) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

int yx_compiler_too_many_variables_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "too many variables";
    const char *label = "too many local variables";
    char *text = yx_diagnostic_text("error", "E047", title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json("TooManyVariables", "E047", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

/* A single-label error without footers. */
static int yx_compiler_simple_error(YRX_COMPILER *compiler, const char *type, const char *code, const char *title, const char *label, const char *source,
                                    const char *origin, size_t start, size_t end)
{
    char *text = yx_diagnostic_text("error", code, title, label, source, origin, start, end, NULL);
    char *diagnostic;
    if (!text) return 0;
    diagnostic = yx_diagnostic_json(type, code, title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return 0;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return 1;
}

/* E035: a rule gets at most 100,000 patterns (MAX_PATTERNS_PER_RULE),
 * reported at the rule's identifier. */
int yx_compiler_too_many_patterns_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    return yx_compiler_simple_error(compiler, "TooManyPatterns", "E035", "too many patterns in a rule", "this rule has more than 100000 patterns", source, origin, start,
                                    end);
}

/* E048: the rule's WebAssembly code exceeds 100,000 instructions
 * (MAX_FUNC_INSTRS, wasm/builder.rs), reported at the rule's identifier. */
int yx_compiler_condition_too_large_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    return yx_compiler_simple_error(compiler, "ConditionTooLarge", "E048", "condition is too large", "the condition of this rule is too large", source, origin, start,
                                    end);
}

/* E042: reading an included file failed for another reason than the file
 * not existing; `error` is the operating system's message. */
int yx_compiler_include_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end, const char *error)
{
    char label[1100];
    snprintf(label, sizeof(label), "failed with error: %s", error);
    return yx_compiler_simple_error(compiler, "IncludeError", "E042", "error including file", label, source, origin, start, end);
}

/* Patch excerpts use one display cell for tabs and omit CR in CRLF lines. */
static char *yx_text_as_hex_patch_line(const char *start, size_t *length)
{
    char *display;
    if (*length && start[*length - 1] == '\r') --*length;
    if (*length == SIZE_MAX) return NULL;
    display = (char *)malloc(*length + 1);
    if (!display) return NULL;
    for (size_t i = 0; i < *length; ++i) display[i] = start[i] == '\t' ? ' ' : start[i];
    display[*length] = 0;
    return display;
}

/* regex-syntax folds a one-branch hex group, and folds identical one-byte
 * alternatives to one literal byte. Multi-byte alternatives remain an
 * alternation even when their branches happen to contain equal bytes. */
static bool yx_hex_literal_atoms(const yx_hex_atom *atoms, size_t count, uint8_t *output, size_t capacity, size_t *used)
{
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_atom *atom = &atoms[i];
        if (atom->kind == YX_HEX_BYTE) {
            if (atom->negated || atom->mask != 0xff || *used == SIZE_MAX || (output && *used >= capacity)) return false;
            if (output) output[*used] = atom->value;
            ++*used;
        } else if (atom->kind == YX_HEX_ALTERNATIVE && atom->branch_count != 0) {
            if (atom->branch_count == 1) {
                if (!yx_hex_literal_atoms(atom->branches[0].atoms, atom->branches[0].count, output, capacity, used)) return false;
            } else {
                uint8_t common = 0;
                for (size_t branch = 0; branch < atom->branch_count; ++branch) {
                    uint8_t byte = 0;
                    size_t branch_length = 0;
                    if (!yx_hex_literal_atoms(atom->branches[branch].atoms, atom->branches[branch].count, &byte, 1, &branch_length) || branch_length != 1 ||
                        (branch && byte != common))
                        return false;
                    common = byte;
                }
                if (*used == SIZE_MAX || (output && *used >= capacity)) return false;
                if (output) output[*used] = common;
                ++*used;
            }
        } else {
            return false;
        }
    }
    return true;
}

int yx_compiler_text_as_hex_warning(YRX_COMPILER *compiler, const YRX_PATTERN *pattern, const char *source, const char *origin, size_t start, size_t end)
{
    static const char title[] = "hex pattern could be written as text literal";
    static const char label[] = "this pattern can be written as a text literal";
    size_t source_length, first_line = 1, last_line;
    size_t gutter_digits = 1, used, capacity;
    const char *first_line_start = source, *last_line_start;
    const char *line_start, *line_end;
    char *replacement = NULL, *text = NULL, *json = NULL, **grown;
    char *first_display = NULL, *last_display = NULL;
    uint8_t *owned_literal = NULL;
    const uint8_t *literal;
    size_t first_display_length, last_display_length;
    size_t replacement_used = 0, replacement_capacity = 0;

    if (!pattern || pattern->kind != YX_PATTERN_HEX || !pattern->length || start >= end) return 1;
    /* Measuring the whole source for every hex pattern is quadratic in the
     * rule set; it is needed only for a warning that will be recorded (no
     * span check below reads the source before that). */
    if (compiler->warning_count >= compiler->max_warnings || yx_compiler_warning_skipped(compiler, "text_as_hex")) return 1;
    source_length = yx_source_text_length(source);
    if (end > source_length) return 1;
    literal = pattern->bytes;
    if (pattern->hex_has_jump) {
        size_t literal_length = 0;
        if (!pattern->hex_atoms || !yx_hex_literal_atoms(pattern->hex_atoms, pattern->hex_atom_count, NULL, 0, &literal_length) || literal_length != pattern->length)
            return 1;
        owned_literal = (uint8_t *)malloc(literal_length);
        if (!owned_literal) return 0;
        literal_length = 0;
        if (!yx_hex_literal_atoms(pattern->hex_atoms, pattern->hex_atom_count, owned_literal, pattern->length, &literal_length) || literal_length != pattern->length)
            goto failure;
        literal = owned_literal;
    } else if (!pattern->bytes || !pattern->mask) {
        return 1;
    }
    for (size_t i = 0; i < pattern->length; ++i) {
        uint8_t byte = literal[i];
        if ((!pattern->hex_has_jump && pattern->mask[i] != 0xff) || (byte != '\t' && byte != '\n' && byte != '\r' && (byte < 0x20 || byte > 0x7e))) goto not_text;
    }
    if (compiler->warning_count >= compiler->max_warnings || yx_warning_suppressed_span((const uint8_t *)source, source_length, "text_as_hex", start, end)) {
        free(owned_literal);
        return 1;
    }

    if (!yx_diagnostic_append(&replacement, &replacement_used, &replacement_capacity, "\"")) goto failure;
    for (size_t i = 0; i < pattern->length; ++i) {
        const char *escaped = NULL;
        switch (literal[i]) {
            case '\t': escaped = "\\t"; break;
            case '\n': escaped = "\\n"; break;
            case '\r': escaped = "\\r"; break;
            case '\\': escaped = "\\\\"; break;
            case '"': escaped = "\\\""; break;
            default: break;
        }
        if (escaped) {
            if (!yx_diagnostic_append(&replacement, &replacement_used, &replacement_capacity, "%s", escaped)) goto failure;
        } else if (!yx_diagnostic_append(&replacement, &replacement_used, &replacement_capacity, "%c", literal[i])) {
            goto failure;
        }
    }
    if (!yx_diagnostic_append(&replacement, &replacement_used, &replacement_capacity, "\"")) goto failure;

    text = yx_diagnostic_text("warning", "text_as_hex", title, label, source, origin, start, end, NULL);
    if (!text) goto failure;
    used = strlen(text);
    capacity = used + 1;
    first_line = yx_source_line_of(source, start, &first_line_start);
    last_line = first_line;
    last_line_start = first_line_start;
    for (size_t i = start; i < end; ++i)
        if (source[i] == '\n') {
            ++last_line;
            last_line_start = source + i + 1;
        }
    for (size_t n = last_line; n >= 10; n /= 10) ++gutter_digits;
    if (gutter_digits > INT_MAX - 1 || start - (size_t)(first_line_start - source) > INT_MAX || replacement_used > INT_MAX) goto failure;
    line_end = strchr(first_line_start, '\n');
    if (!line_end) line_end = source + source_length;
    first_display_length = (size_t)(line_end - first_line_start);
    first_display = yx_text_as_hex_patch_line(first_line_start, &first_display_length);
    line_end = strchr(last_line_start, '\n');
    if (!line_end) line_end = source + source_length;
    last_display_length = (size_t)(line_end - last_line_start);
    last_display = yx_text_as_hex_patch_line(last_line_start, &last_display_length);
    if (!first_display || !last_display || (size_t)(source + end - last_line_start) > last_display_length) goto failure;
    if (!yx_diagnostic_append(&text, &used, &capacity, "\n%*s|\nhelp: consider the following change\n%*s|\n", (int)gutter_digits + 1, "", (int)gutter_digits + 1, ""))
        goto failure;
    line_start = first_line_start;
    for (size_t line = first_line; line <= last_line; ++line) {
        char *display;
        size_t display_length;
        line_end = strchr(line_start, '\n');
        if (!line_end) line_end = source + source_length;
        display_length = (size_t)(line_end - line_start);
        display = yx_text_as_hex_patch_line(line_start, &display_length);
        if (!display) goto failure;
        bool appended =
            display_length <= INT_MAX && yx_diagnostic_append(&text, &used, &capacity, "%*zu - %.*s\n", (int)gutter_digits, line, (int)display_length, display);
        free(display);
        if (!appended) goto failure;
        if (line == last_line) break;
        line_start = line_end + 1;
    }
    if (last_display_length - (size_t)(source + end - last_line_start) > INT_MAX ||
        !yx_diagnostic_append(&text, &used, &capacity, "%*zu + %.*s%s%.*s\n%*s|", (int)gutter_digits, first_line, (int)(source + start - first_line_start), first_display,
                              replacement, (int)(last_display_length - (size_t)(source + end - last_line_start)), last_display + (source + end - last_line_start),
                              (int)gutter_digits + 1, ""))
        goto failure;
    yx_note_patch(compiler, text, (size_t)(source + start - first_line_start), end - start, strlen(replacement));

    json = yx_diagnostic_json("TextPatternAsHex", "text_as_hex", title, label, text, source, origin, start, end, NULL, "warning");
    if (!json || compiler->warning_count >= SIZE_MAX / sizeof(*grown)) goto failure;
    grown = (char **)realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) goto failure;
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) goto failure;
    compiler->warnings[compiler->warning_count++] = json;
    free(owned_literal);
    free(first_display);
    free(last_display);
    free(replacement);
    free(text);
    return 1;
not_text:
    free(owned_literal);
    return 1;
failure:
    free(json);
    free(owned_literal);
    free(first_display);
    free(last_display);
    free(replacement);
    free(text);
    return 0;
}

int yx_compiler_consecutive_jumps_warning(YRX_COMPILER *compiler, const char *identifier, const char *source, const char *origin, size_t start, size_t end,
                                          uint64_t lower, uint64_t upper, bool has_lower, bool has_upper)
{
    const char *line_start = source, *line_end, *last_start, *last_end, *at;
    size_t line = 1, last_line, digits = 1, used, capacity, prefix, suffix;
    size_t rows;
    char title[512], label[160], replacement[96];
    char *text, *json, **grown;
    if (compiler->warning_count >= compiler->max_warnings) return 1;
    if (yx_warning_suppressed_span((const uint8_t *)source, yx_source_text_length(source), "consecutive_jumps", start, end)) return 1;
    line = yx_source_line_of(source, start, &line_start);
    /* Jumps may continue on later lines; the patch shows each of them. */
    last_line = line;
    last_start = line_start;
    for (size_t i = start; i < end; ++i)
        if (source[i] == '\n') {
            ++last_line;
            last_start = source + i + 1;
        }
    for (size_t n = last_line; n >= 10; n /= 10) ++digits;
    last_end = strchr(last_start, '\n');
    if (!last_end) last_end = source + yx_source_text_length(source);
    last_end = yx_diagnostic_display_line_end(last_start, last_end);
    if (source + end > last_end) return 0;
    prefix = (size_t)((source + start) - line_start);
    suffix = (size_t)(last_end - (source + end));
    if (prefix > INT_MAX || suffix > INT_MAX || digits > INT_MAX - 1) return 0;
    snprintf(title, sizeof(title), "consecutive jumps in hex pattern `%s`", identifier);
    /* Like HexJump's Display, an absent bound stays absent. */
    if (has_lower && has_upper) snprintf(replacement, sizeof(replacement), "[%llu-%llu]", (unsigned long long)lower, (unsigned long long)upper);
    else if (has_lower) snprintf(replacement, sizeof(replacement), "[%llu-]", (unsigned long long)lower);
    else if (has_upper) snprintf(replacement, sizeof(replacement), "[-%llu]", (unsigned long long)upper);
    else snprintf(replacement, sizeof(replacement), "[-]");
    snprintf(label, sizeof(label), "these consecutive jumps will be treated as %s", replacement);
    text = yx_diagnostic_text("warning", "consecutive_jumps", title, label, source, origin, start, end, NULL);
    if (!text) return 0;
    used = strlen(text);
    capacity = used + 1;
    if (!yx_diagnostic_append(&text, &used, &capacity, "\n%*s|\nhelp: consider the following change\n%*s|", (int)digits + 1, "", (int)digits + 1, "")) {
        free(text);
        return 0;
    }
    rows = used;
    at = line_start;
    for (size_t number = line; number <= last_line; ++number) {
        line_end = strchr(at, '\n');
        if (!line_end) line_end = source + yx_source_text_length(source);
        line_end = yx_diagnostic_display_line_end(at, line_end);
        if ((size_t)(line_end - at) > INT_MAX || !yx_diagnostic_append(&text, &used, &capacity, "\n%*zu - %.*s", (int)digits, number, (int)(line_end - at), at)) {
            free(text);
            return 0;
        }
        at = strchr(at, '\n');
        if (!at) break;
        ++at;
    }
    if (!yx_diagnostic_append(&text, &used, &capacity, "\n%*zu + %.*s%s%.*s\n%*s|", (int)digits, line, (int)prefix, line_start, replacement, (int)suffix, source + end,
                              (int)digits + 1, "")) {
        free(text);
        return 0;
    }
    for (size_t i = rows; i < used; ++i)
        if (text[i] == '\t') text[i] = ' ';
    yx_note_patch(compiler, text, prefix, end - start, strlen(replacement));
    json = yx_diagnostic_json("ConsecutiveJumps", "consecutive_jumps", title, label, text, source, origin, start, end, NULL, "warning");
    free(text);
    if (!json || compiler->warning_count >= SIZE_MAX / sizeof(*grown)) {
        free(json);
        return 0;
    }
    grown = (char **)realloc(compiler->warnings, (compiler->warning_count + 1) * sizeof(*grown));
    if (!grown) {
        free(json);
        return 0;
    }
    compiler->warnings = grown;
    json = yx_warning_compact(compiler, yx_nul_escape_public_json(compiler, json));
    if (!json) return 0;
    compiler->warnings[compiler->warning_count++] = json;
    return 1;
}

int yx_compiler_check_import(YRX_COMPILER *compiler, const char *module, const char *source, const char *origin, size_t start, size_t end)
{
    yx_module_policy *policy = yx_find_module_policy(compiler, module);
    char title[YX_DIAG_NAME_TEXT_SIZE], label[YX_DIAG_NAME_TEXT_SIZE];
    char *text;
    /* YARA-X ae8ff837: an ignored module is treated as if it did not exist,
     * even when YARA-X implements it, so its import is skipped with the
     * unsupported_module warning and the dependent rules are ignored. */
    if (!yx_known_module(module) || (policy && policy->ignored)) {
        if (policy && policy->ignored) {
            snprintf(title, sizeof(title), "module `%s` is not supported", module);
            snprintf(label, sizeof(label), "module `%s` used here", module);
            if (!yx_record_ignored_import(compiler, module) ||
                !yx_compiler_warning(compiler, "IgnoredModule", "unsupported_module", title, label, source, origin, start, end, NULL)) {
                snprintf(compiler->error, sizeof(compiler->error), "out of memory recording ignored module");
                return 0;
            }
            return 2;
        }
        snprintf(title, sizeof(title), "unknown module `%s`", module);
        snprintf(label, sizeof(label), "module `%s` not found", module);
        text = yx_diagnostic_text("error", "E010", title, label, source, origin, start, end, NULL);
        if (!text || !yx_compiler_insert_semantic_diagnostic(
                         compiler, yx_diagnostic_json("UnknownModule", "E010", title, label, text, source, origin, start, end, NULL, "error"), origin, false)) {
            free(text);
            snprintf(compiler->error, sizeof(compiler->error), "out of memory recording unknown module");
            return 0;
        }
        snprintf(compiler->error, sizeof(compiler->error), "%s", text);
        free(text);
        return 3;
    }
    if (policy && policy->ban_title) {
        /* YARA-X reports the banned import and still imports the module:
         * the rules compile and are built. */
        text = yx_diagnostic_text("error", "E100", policy->ban_title, policy->ban_message, source, origin, start, end, NULL);
        if (!text || !yx_compiler_append_error_diagnostic(
                         compiler, yx_diagnostic_json("CustomError", "E100", policy->ban_title, policy->ban_message, text, source, origin, start, end, NULL, "error"))) {
            free(text);
            snprintf(compiler->error, sizeof(compiler->error), "out of memory recording banned module");
            return 0;
        }
        snprintf(compiler->error, sizeof(compiler->error), "%s", text);
        free(text);
        return 4;
    }
    return 1;
}

static const char *yx_ignored_import_module(YRX_COMPILER *compiler, const char *name, const char *namespace_name)
{
    for (size_t i = 0; i < compiler->ignored_import_count; ++i)
        if (strcmp(compiler->ignored_imports[i].module, name) == 0 && strcmp(compiler->ignored_imports[i].namespace_name, namespace_name) == 0 &&
            compiler->ignored_imports[i].namespace_index == compiler->current_namespace_index)
            return compiler->ignored_imports[i].module;
    return NULL;
}

static const char *yx_ignored_dependency_module(YRX_COMPILER *compiler, const char *name, const char *namespace_name)
{
    for (size_t i = 0; i < compiler->ignored_rule_count; ++i)
        if (strcmp(compiler->ignored_rules[i].name, name) == 0 && strcmp(compiler->ignored_rules[i].namespace_name, namespace_name) == 0 &&
            compiler->ignored_rules[i].namespace_index == compiler->current_namespace_index)
            return compiler->ignored_rules[i].module;
    return NULL;
}

static bool yx_record_ignored_rule(YRX_COMPILER *compiler, const char *rule_name, const char *namespace_name, const char *module, const char *parent_rule)
{
    yx_ignored_rule *grown;
    char *name, *space, *mod, *parent = NULL;
    if (compiler->ignored_rule_count >= SIZE_MAX / sizeof(*grown)) return false;
    name = yx_strdup(rule_name);
    space = yx_strdup(namespace_name);
    mod = yx_strdup(module);
    if (parent_rule) parent = yx_strdup(parent_rule);
    if (!name || !space || !mod || (parent_rule && !parent)) {
        free(name);
        free(space);
        free(mod);
        free(parent);
        return false;
    }
    grown = (yx_ignored_rule *)realloc(compiler->ignored_rules, (compiler->ignored_rule_count + 1) * sizeof(*grown));
    if (!grown) {
        free(name);
        free(space);
        free(mod);
        free(parent);
        return false;
    }
    compiler->ignored_rules = grown;
    compiler->ignored_rules[compiler->ignored_rule_count].name = name;
    compiler->ignored_rules[compiler->ignored_rule_count].namespace_name = space;
    compiler->ignored_rules[compiler->ignored_rule_count].namespace_index = compiler->current_namespace_index;
    compiler->ignored_rules[compiler->ignored_rule_count].module = mod;
    compiler->ignored_rules[compiler->ignored_rule_count].parent = parent;
    ++compiler->ignored_rule_count;
    return true;
}

int yx_compiler_skip_ignored_rule(YRX_COMPILER *compiler, const char *condition, const char *rule_name, const char *namespace_name, const char *source,
                                  const char *origin, size_t condition_offset)
{
    const char *at = condition;
    bool next_regex = false;
    while (*at) {
        const char *start, *module = NULL;
        bool indirect = false;
        char *name;
        size_t length, span_start, span_end;
        char title[512], label[512], note[512];
        if (at[0] == '/' && at[1] == '/') {
            at += 2;
            while (*at && *at != '\n') ++at;
            continue;
        }
        if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
            continue;
        }
        if (*at == '"' || (*at == '/' && next_regex)) {
            char terminator = *at++;
            while (*at && *at != terminator) {
                if (*at == '\\' && at[1]) ++at;
                ++at;
            }
            if (*at) ++at;
            next_regex = false;
            continue;
        }
        if (!(isalpha((unsigned char)*at) || *at == '_') || (at > condition && (at[-1] == '$' || at[-1] == '#' || at[-1] == '@' || at[-1] == '!'))) {
            if (!isspace((unsigned char)*at)) next_regex = false;
            ++at;
            continue;
        }
        start = at++;
        while (isalnum((unsigned char)*at) || *at == '_') ++at;
        length = (size_t)(at - start);
        name = (char *)malloc(length + 1);
        if (!name) goto memory_failure;
        memcpy(name, start, length);
        name[length] = '\0';
        if (strcmp(name, "matches") == 0) next_regex = true;
        else {
            module = yx_ignored_import_module(compiler, name, namespace_name);
            if (!module && (at[0] == '.' || at[0] == '(' || at[0] == '[') && (start == condition || start[-1] != '.')) {
                /* An ignored module used without its import. */
                yx_module_policy *policy = yx_find_module_policy(compiler, name);
                bool imported = false, declared = false;
                for (size_t i = 0; i < compiler->rules->import_count; ++i)
                    if (!strcmp(compiler->rules->imports[i], name) &&
                        (!compiler->rules->import_namespace_indices || compiler->rules->import_namespace_indices[i] == compiler->current_namespace_index))
                        imported = true;
                /* Only an ignored module asks whether a rule or global has
                 * the name (a search of every rule per call otherwise). */
                if (policy && policy->ignored && !imported) {
                    for (size_t i = 0; i < compiler->rules->rule_count && !declared; ++i) declared = !strcmp(compiler->rules->rules[i].identifier, name);
                    for (size_t i = 0; i < compiler->rules->global_count && !declared; ++i) declared = !strcmp(compiler->rules->globals[i].name, name);
                }
                if (policy && policy->ignored && !imported && !declared) module = policy->name;
            }
            if (!module) {
                module = yx_ignored_dependency_module(compiler, name, namespace_name);
                indirect = module != NULL;
            }
            next_regex = false;
        }
        if (!module) {
            free(name);
            continue;
        }
        span_start = condition_offset + (size_t)(start - condition);
        span_end = span_start + length;
        if (indirect) {
            snprintf(title, sizeof(title), "rule `%s` will be ignored due to an indirect dependency on module `%s`", rule_name, module);
            snprintf(label, sizeof(label), "this other rule depends on module `%s`, which is unsupported", module);
            note[0] = '\0';
        } else {
            snprintf(title, sizeof(title), "module `%s` is not supported", module);
            snprintf(label, sizeof(label), "module `%s` used here", module);
            snprintf(note, sizeof(note), "the whole rule `%s` will be ignored", rule_name);
        }
        if (!yx_record_ignored_rule(compiler, rule_name, namespace_name, module, indirect ? name : NULL) ||
            !yx_compiler_warning(compiler, indirect ? "IgnoredRule" : "IgnoredModule", indirect ? "ignored_rule" : "unsupported_module", title, label, source, origin,
                                 span_start, span_end, indirect ? NULL : note)) {
            free(name);
            goto memory_failure;
        }
        free(name);
        return 1;
    }
    return 0;
memory_failure:
    snprintf(compiler->error, sizeof(compiler->error), "out of memory recording ignored rule");
    return -1;
}

typedef enum {
    YX_INV_END,
    YX_INV_TRUE,
    YX_INV_FALSE,
    YX_INV_NOT,
    YX_INV_AND,
    YX_INV_OR,
    YX_INV_LPAREN,
    YX_INV_RPAREN,
    YX_INV_OTHER
} yx_inv_token;

typedef enum {
    YX_INV_NONBOOL_NONE,
    YX_INV_NONBOOL_INTEGER,
    YX_INV_NONBOOL_FLOAT,
    YX_INV_NONBOOL_STRING
} yx_inv_nonbool_type;

typedef struct {
    size_t start;
    size_t end;
    yx_inv_nonbool_type type;
} yx_inv_nonbool;

typedef struct {
    const char *source;
    const char *at;
    yx_inv_token token;
    size_t start;
    size_t end;
    yx_inv_nonbool *nonbool;
    size_t nonbool_count;
    size_t nonbool_capacity;
    bool out_of_memory;
    const YRX_COMPILER *compiler;
} yx_inv_parser;

typedef struct {
    bool valid;
    int value; /* -1 is dynamic, 0 is false, 1 is true. */
    yx_inv_nonbool_type nonbool_type;
    /* A non-boolean global alone: 1 false, 2 true, 0 otherwise. */
    int bare_global;
    size_t start;
    size_t end;
    yx_inv_token pending_operator;
    yx_inv_nonbool *pending;
    size_t pending_count;
    size_t pending_capacity;
} yx_inv_expr;

static void yx_inv_next(yx_inv_parser *parser)
{
    const char *at = parser->at;
    size_t length;
    for (;;) {
        while (isspace((unsigned char)*at)) ++at;
        if (at[0] == '/' && at[1] == '/') {
            at += 2;
            while (*at && *at != '\n') ++at;
        } else if (at[0] == '/' && at[1] == '*') {
            at += 2;
            while (*at && !(at[0] == '*' && at[1] == '/')) ++at;
            if (*at) at += 2;
        } else {
            break;
        }
    }
    parser->start = (size_t)(at - parser->source);
    parser->token = YX_INV_OTHER;
    if (!*at) {
        parser->token = YX_INV_END;
    } else if (*at == '(') {
        parser->token = YX_INV_LPAREN;
        ++at;
    } else if (*at == ')') {
        parser->token = YX_INV_RPAREN;
        ++at;
    } else if (*at == '"') {
        ++at;
        while (*at && *at != '"') {
            if (*at == '\\' && at[1]) ++at;
            ++at;
        }
        if (*at) ++at;
    } else if ((*at == '$' || *at == '#' || *at == '@' || *at == '!') && (isalpha((unsigned char)at[1]) || at[1] == '_')) {
        ++at;
        while (isalnum((unsigned char)*at) || *at == '_') ++at;
    } else if (*at == '/') {
        const char *cursor = at + 1;
        bool in_class = false;
        while (*cursor) {
            if (*cursor == '\\' && cursor[1]) {
                cursor += 2;
                continue;
            }
            if (*cursor == '[') in_class = true;
            else if (*cursor == ']') in_class = false;
            else if (*cursor == '/' && !in_class) break;
            ++cursor;
        }
        at = *cursor == '/' ? cursor + 1 : at + 1;
    } else if (isalnum((unsigned char)*at) || *at == '_') {
        const char *word = at;
        while (isalnum((unsigned char)*at) || *at == '_') ++at;
        length = (size_t)(at - word);
        if (length == 4 && memcmp(word, "true", 4) == 0) parser->token = YX_INV_TRUE;
        else if (length == 5 && memcmp(word, "false", 5) == 0) parser->token = YX_INV_FALSE;
        else if (length == 3 && memcmp(word, "not", 3) == 0) parser->token = YX_INV_NOT;
        else if (length == 3 && memcmp(word, "and", 3) == 0) parser->token = YX_INV_AND;
        else if (length == 2 && memcmp(word, "or", 2) == 0) parser->token = YX_INV_OR;
    } else {
        ++at;
    }
    parser->end = (size_t)(at - parser->source);
    parser->at = at;
}

/* Recursion bounds of the invariant analysis. The syntax check limits
 * conditions to YARA-X's nesting depth (1000 CST levels), which takes at
 * most two Boolean levels and eight arithmetic levels per CST level here,
 * so every accepted condition is analysed completely. */
#define YX_INV_DEPTH_LIMIT 4096
#define YX_INV_ARITHMETIC_DEPTH_LIMIT 16384

static yx_inv_expr yx_inv_parse_or(yx_inv_parser *parser, unsigned depth);

typedef struct {
    bool valid;
    bool known;
    bool is_unsigned;
    yx_inv_nonbool_type type;
    uint64_t integer;
    double floating;
    /* A same-operator integer chain may later promote every operand to f64. */
    double chain_floating;
    char chain_operation;
} yx_inv_number;

typedef struct {
    const char *at;
    const char *end;
} yx_inv_arithmetic;

static void yx_inv_arithmetic_skip(yx_inv_arithmetic *parser)
{
    for (;;) {
        while (parser->at < parser->end && isspace((unsigned char)*parser->at)) ++parser->at;
        if (parser->end - parser->at >= 2 && parser->at[0] == '/' && parser->at[1] == '*') {
            parser->at += 2;
            while (parser->end - parser->at >= 2 && !(parser->at[0] == '*' && parser->at[1] == '/')) ++parser->at;
            if (parser->end - parser->at >= 2) parser->at += 2;
            else parser->at = parser->end;
        } else if (parser->end - parser->at >= 2 && parser->at[0] == '/' && parser->at[1] == '/') {
            parser->at += 2;
            while (parser->at < parser->end && *parser->at != '\n') ++parser->at;
        } else break;
    }
}

static yx_inv_number yx_inv_arithmetic_or(yx_inv_arithmetic *parser, unsigned depth);

/* The compiler whose rule is analysed (yx_compiler_warn_invariant_condition):
 * a path is a module constant only when its root is an imported module that
 * no global hides, as CompileContext::lookup resolves it. */
static _Thread_local const YRX_COMPILER *yx_inv_scope_compiler;

static bool yx_inv_module_imported(const char *path)
{
    const YRX_COMPILER *compiler = yx_inv_scope_compiler;
    size_t root = strcspn(path, ".");
    bool imported = false;
    if (!compiler || !compiler->rules) return false;
    for (size_t i = 0; i < compiler->rules->import_count && !imported; ++i)
        imported = compiler->rules->imports[i] && strlen(compiler->rules->imports[i]) == root && memcmp(compiler->rules->imports[i], path, root) == 0;
    for (size_t i = 0; imported && i < compiler->rules->global_count; ++i) {
        const char *name = compiler->rules->globals[i].name;
        if (name && strncmp(name, path, root) == 0 && (!name[root] || name[root] == '.')) imported = false;
    }
    return imported;
}

static yx_inv_number yx_inv_arithmetic_primary(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number result = {0};
    const char *begin;
    uint64_t integer = 0;
    int base = 10;
    bool decimal = false;
    double floating, factor;
    if (depth > YX_INV_ARITHMETIC_DEPTH_LIMIT) return result;
    yx_inv_arithmetic_skip(parser);
    if (parser->at >= parser->end) return result;
    if (*parser->at == '(') {
        ++parser->at;
        result = yx_inv_arithmetic_or(parser, depth + 1);
        yx_inv_arithmetic_skip(parser);
        if (parser->at >= parser->end || *parser->at != ')') result.valid = false;
        else ++parser->at;
        return result;
    }
    if (parser->end - parser->at >= 8 && memcmp(parser->at, "filesize", 8) == 0 &&
        (parser->end - parser->at == 8 || !(isalnum((unsigned char)parser->at[8]) || parser->at[8] == '_'))) {
        parser->at += 8;
        result.valid = true;
        result.type = YX_INV_NONBOOL_INTEGER;
        return result;
    }
    if ((*parser->at == '@' || *parser->at == '!' || *parser->at == '#') && parser->at + 1 < parser->end &&
        (isalpha((unsigned char)parser->at[1]) || parser->at[1] == '_')) {
        const char *cursor = parser->at + 2;
        while (cursor < parser->end && (isalnum((unsigned char)*cursor) || *cursor == '_')) ++cursor;
        if (*parser->at == '@' || *parser->at == '!') {
            yx_inv_arithmetic suffix = {cursor, parser->end};
            yx_inv_arithmetic_skip(&suffix);
            if (suffix.at < parser->end && *suffix.at == '[') cursor = suffix.at;
        }
        if (cursor < parser->end && *cursor == '[') {
            unsigned brackets = 1;
            ++cursor;
            while (cursor < parser->end && brackets) {
                if (*cursor == '[') ++brackets;
                else if (*cursor == ']') --brackets;
                ++cursor;
            }
            if (brackets) return result;
        }
        if (*parser->at == '#') {
            yx_inv_arithmetic suffix = {cursor, parser->end};
            yx_inv_arithmetic_skip(&suffix);
            if (suffix.end - suffix.at >= 2 && memcmp(suffix.at, "in", 2) == 0) {
                suffix.at += 2;
                yx_inv_arithmetic_skip(&suffix);
                if (suffix.at < suffix.end && *suffix.at == '(') {
                    unsigned parentheses = 1;
                    cursor = suffix.at + 1;
                    while (cursor < parser->end && parentheses) {
                        if (*cursor == '(') ++parentheses;
                        else if (*cursor == ')') --parentheses;
                        ++cursor;
                    }
                    if (parentheses) return result;
                }
            }
        }
        parser->at = cursor;
        result.valid = true;
        result.type = YX_INV_NONBOOL_INTEGER;
        return result;
    }
    begin = parser->at;
    if (isalpha((unsigned char)*parser->at) || *parser->at == '_') {
        /* A module constant (`pe.MACHINE_I386`, `math.MEAN_BYTES`): a
         * dotted path that is neither called nor indexed. */
        char path[128];
        const char *cursor = parser->at;
        size_t length = 0;
        bool dotted = false, floating_constant = false;
        uint64_t constant = 0;
        double number = 0.0;
        for (;;) {
            const char *word = cursor;
            while (cursor < parser->end && (isalnum((unsigned char)*cursor) || *cursor == '_')) ++cursor;
            if (cursor == word || length + (size_t)(cursor - word) + 2 > sizeof(path)) return result;
            memcpy(path + length, word, (size_t)(cursor - word));
            length += (size_t)(cursor - word);
            {
                yx_inv_arithmetic after = {cursor, parser->end};
                yx_inv_arithmetic_skip(&after);
                if (after.at >= after.end || *after.at != '.') {
                    if (after.at < after.end && (*after.at == '(' || *after.at == '[')) return result;
                    break;
                }
                after.at++;
                yx_inv_arithmetic_skip(&after);
                cursor = after.at;
            }
            path[length++] = '.';
            dotted = true;
        }
        path[length] = '\0';
        if (!dotted || !yx_inv_module_imported(path) || !yx_condition_module_constant_value(path, &floating_constant, &constant, &number)) return result;
        parser->at = cursor;
        result.valid = true;
        result.known = true;
        result.type = floating_constant ? YX_INV_NONBOOL_FLOAT : YX_INV_NONBOOL_INTEGER;
        result.integer = constant;
        result.floating = floating_constant ? number : (double)(int64_t)constant;
        return result;
    }
    if (parser->end - parser->at >= 2 && parser->at[0] == '0' && (parser->at[1] == 'x' || parser->at[1] == 'X' || parser->at[1] == 'o' || parser->at[1] == 'O')) {
        base = parser->at[1] == 'o' || parser->at[1] == 'O' ? 8 : 16;
        parser->at += 2;
    }
    if (parser->at >= parser->end || !(base == 16 ? isxdigit((unsigned char)*parser->at) : isdigit((unsigned char)*parser->at))) return result;
    while (parser->at < parser->end) {
        if (*parser->at == '_') {
            ++parser->at;
            continue;
        }
        if (!(base == 16 ? isxdigit((unsigned char)*parser->at) : isdigit((unsigned char)*parser->at))) break;
        unsigned char ch = (unsigned char)*parser->at++;
        unsigned digit = ch <= '9' ? (unsigned)(ch - '0') : (unsigned)(tolower(ch) - 'a' + 10);
        if (digit >= (unsigned)base) return result;
        integer = integer * (unsigned)base + digit;
    }
    floating = (double)integer;
    if (base == 10 && parser->at < parser->end && *parser->at == '.') {
        decimal = true;
        ++parser->at;
        if (parser->at >= parser->end || !isdigit((unsigned char)*parser->at)) return result;
        factor = 0.1;
        while (parser->at < parser->end && (isdigit((unsigned char)*parser->at) || *parser->at == '_')) {
            if (*parser->at == '_') {
                ++parser->at;
                continue;
            }
            floating += (double)(*parser->at++ - '0') * factor;
            factor *= 0.1;
        }
    }
    if (!decimal && base == 10 && parser->end - parser->at >= 2 && (parser->at[0] == 'K' || parser->at[0] == 'M') && parser->at[1] == 'B') {
        integer *= parser->at[0] == 'K' ? UINT64_C(1024) : UINT64_C(1048576);
        parser->at += 2;
        floating = (double)integer;
    }
    if (parser->at == begin) return result;
    result.valid = true;
    result.known = true;
    result.type = decimal ? YX_INV_NONBOOL_FLOAT : YX_INV_NONBOOL_INTEGER;
    result.integer = integer;
    result.floating = floating;
    result.is_unsigned = !decimal && integer > INT64_MAX;
    return result;
}

static yx_inv_number yx_inv_arithmetic_unary(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number result;
    char op;
    if (depth > YX_INV_ARITHMETIC_DEPTH_LIMIT) {
        yx_inv_number invalid = {0};
        return invalid;
    }
    yx_inv_arithmetic_skip(parser);
    if (parser->at >= parser->end || (*parser->at != '-' && *parser->at != '~')) return yx_inv_arithmetic_primary(parser, depth + 1);
    op = *parser->at++;
    result = yx_inv_arithmetic_unary(parser, depth + 1);
    if (!result.valid || (op == '~' && result.type != YX_INV_NONBOOL_INTEGER)) {
        result.valid = false;
        return result;
    }
    if (result.known) {
        if (op == '~') result.integer = ~result.integer;
        else if (result.type == YX_INV_NONBOOL_INTEGER) result.integer = UINT64_C(0) - result.integer;
        else result.floating = -result.floating;
    }
    if (op == '-') result.is_unsigned = false;
    result.chain_operation = 0;
    return result;
}

static int64_t yx_inv_integer_signed(uint64_t bits)
{
    return bits <= INT64_MAX ? (int64_t)bits : -1 - (int64_t)(UINT64_MAX - bits);
}

static double yx_inv_arithmetic_float(yx_inv_number value)
{
    return value.type == YX_INV_NONBOOL_FLOAT ? value.floating : value.is_unsigned ? (double)value.integer : (double)yx_inv_integer_signed(value.integer);
}

static yx_inv_number yx_inv_arithmetic_multiply(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number left = yx_inv_arithmetic_unary(parser, depth + 1);
    if (!left.valid) return left;
    for (;;) {
        yx_inv_number right;
        char op;
        double chain_value;
        yx_inv_arithmetic_skip(parser);
        if (parser->at >= parser->end || (*parser->at != '*' && *parser->at != '%' && *parser->at != '\\')) break;
        op = *parser->at++;
        right = yx_inv_arithmetic_unary(parser, depth + 1);
        if (!right.valid || (op == '%' && (left.type != YX_INV_NONBOOL_INTEGER || right.type != YX_INV_NONBOOL_INTEGER))) {
            left.valid = false;
            return left;
        }
        chain_value = op == '*' && left.chain_operation == '*' ? left.chain_floating : yx_inv_arithmetic_float(left);
        if (op == '*') chain_value *= yx_inv_arithmetic_float(right);
        if (left.known && right.known) {
            if (left.type == YX_INV_NONBOOL_FLOAT || right.type == YX_INV_NONBOOL_FLOAT) {
                /* IR::fold_div: a float division folds, by zero too
                 * (an infinity or NaN, true as a Boolean). */
                double divisor = yx_inv_arithmetic_float(right);
                double dividend = yx_inv_arithmetic_float(left);
                /* fold_div (ir/mod.rs) divides floats as IEEE 754 does: a
                 * zero divisor gives a NaN for a zero or NaN dividend and
                 * otherwise an infinity with the product of the signs. The
                 * result is built here, without dividing by zero. */
                if (op == '*') left.floating = chain_value;
                else if (divisor != 0.0) left.floating = dividend / divisor;
                else if (isnan(dividend) || dividend == 0.0) left.floating = NAN;
                else left.floating = (signbit(dividend) != 0) != (signbit(divisor) != 0) ? -INFINITY : INFINITY;
            } else if (op == '*') left.integer *= right.integer;
            else if (right.integer == 0) left.known = false;
            else if (left.is_unsigned || right.is_unsigned) {
                left.integer = op == '%' ? left.integer % right.integer : left.integer / right.integer;
            } else {
                int64_t lhs = yx_inv_integer_signed(left.integer);
                int64_t rhs = yx_inv_integer_signed(right.integer);
                if (lhs == INT64_MIN && rhs == -1) {
                    if (op == '%') left.integer = 0;
                    else left.known = false;
                } else left.integer = (uint64_t)(op == '%' ? lhs % rhs : lhs / rhs);
            }
        } else left.known = false;
        left.is_unsigned = left.is_unsigned || right.is_unsigned;
        left.chain_operation = op == '*' ? '*' : 0;
        left.chain_floating = chain_value;
        if (right.type == YX_INV_NONBOOL_FLOAT) left.type = YX_INV_NONBOOL_FLOAT;
    }
    return left;
}

static yx_inv_number yx_inv_arithmetic_add(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number left = yx_inv_arithmetic_multiply(parser, depth + 1);
    if (!left.valid) return left;
    for (;;) {
        yx_inv_number right;
        char op;
        double chain_value;
        yx_inv_arithmetic_skip(parser);
        if (parser->at >= parser->end || (*parser->at != '+' && *parser->at != '-')) break;
        op = *parser->at++;
        right = yx_inv_arithmetic_multiply(parser, depth + 1);
        if (!right.valid) {
            left.valid = false;
            return left;
        }
        chain_value = left.chain_operation == op ? left.chain_floating : yx_inv_arithmetic_float(left);
        chain_value = op == '+' ? chain_value + yx_inv_arithmetic_float(right) : chain_value - yx_inv_arithmetic_float(right);
        if (left.known && right.known) {
            if (left.type == YX_INV_NONBOOL_FLOAT || right.type == YX_INV_NONBOOL_FLOAT) left.floating = chain_value;
            else left.integer = op == '+' ? left.integer + right.integer : left.integer - right.integer;
        } else left.known = false;
        left.is_unsigned = left.is_unsigned || right.is_unsigned;
        left.chain_operation = op;
        left.chain_floating = chain_value;
        if (right.type == YX_INV_NONBOOL_FLOAT) left.type = YX_INV_NONBOOL_FLOAT;
    }
    return left;
}

static yx_inv_number yx_inv_arithmetic_shift(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number left = yx_inv_arithmetic_add(parser, depth + 1);
    if (!left.valid) return left;
    for (;;) {
        yx_inv_number right;
        char op;
        yx_inv_arithmetic_skip(parser);
        if (parser->end - parser->at < 2 || !((parser->at[0] == '<' && parser->at[1] == '<') || (parser->at[0] == '>' && parser->at[1] == '>'))) break;
        op = *parser->at;
        parser->at += 2;
        right = yx_inv_arithmetic_add(parser, depth + 1);
        if (!right.valid || left.type != YX_INV_NONBOOL_INTEGER || right.type != YX_INV_NONBOOL_INTEGER) {
            left.valid = false;
            return left;
        }
        if (left.known && right.known) {
            if (right.integer >= 64) left.integer = 0;
            else if (op == '<') left.integer <<= right.integer;
            else {
                bool negative = !left.is_unsigned && (left.integer & (UINT64_C(1) << 63)) != 0;
                left.integer >>= right.integer;
                if (negative && right.integer != 0) left.integer |= UINT64_MAX << (64 - right.integer);
            }
        } else left.known = false;
        left.chain_operation = 0;
    }
    return left;
}

static yx_inv_number yx_inv_arithmetic_bitwise(yx_inv_arithmetic *parser, unsigned depth, char op);

static yx_inv_number yx_inv_arithmetic_and(yx_inv_arithmetic *parser, unsigned depth)
{
    return yx_inv_arithmetic_bitwise(parser, depth, '&');
}

static yx_inv_number yx_inv_arithmetic_xor(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number left = yx_inv_arithmetic_and(parser, depth + 1);
    if (!left.valid) return left;
    for (;;) {
        yx_inv_number right;
        yx_inv_arithmetic_skip(parser);
        if (parser->at >= parser->end || *parser->at != '^') break;
        ++parser->at;
        right = yx_inv_arithmetic_and(parser, depth + 1);
        if (!right.valid || left.type != YX_INV_NONBOOL_INTEGER || right.type != YX_INV_NONBOOL_INTEGER) {
            left.valid = false;
            return left;
        }
        if (left.known && right.known) left.integer ^= right.integer;
        else left.known = false;
        left.is_unsigned = left.is_unsigned || right.is_unsigned;
        left.chain_operation = 0;
    }
    return left;
}

static yx_inv_number yx_inv_arithmetic_or(yx_inv_arithmetic *parser, unsigned depth)
{
    yx_inv_number left = yx_inv_arithmetic_xor(parser, depth + 1);
    if (!left.valid) return left;
    for (;;) {
        yx_inv_number right;
        yx_inv_arithmetic_skip(parser);
        if (parser->at >= parser->end || *parser->at != '|') break;
        ++parser->at;
        right = yx_inv_arithmetic_xor(parser, depth + 1);
        if (!right.valid || left.type != YX_INV_NONBOOL_INTEGER || right.type != YX_INV_NONBOOL_INTEGER) {
            left.valid = false;
            return left;
        }
        if (left.known && right.known) left.integer |= right.integer;
        else left.known = false;
        left.is_unsigned = left.is_unsigned || right.is_unsigned;
        left.chain_operation = 0;
    }
    return left;
}

static yx_inv_number yx_inv_arithmetic_bitwise(yx_inv_arithmetic *parser, unsigned depth, char op)
{
    yx_inv_number left = yx_inv_arithmetic_shift(parser, depth + 1);
    if (!left.valid) return left;
    for (;;) {
        yx_inv_number right;
        yx_inv_arithmetic_skip(parser);
        if (parser->at >= parser->end || *parser->at != op) break;
        ++parser->at;
        right = yx_inv_arithmetic_shift(parser, depth + 1);
        if (!right.valid || left.type != YX_INV_NONBOOL_INTEGER || right.type != YX_INV_NONBOOL_INTEGER) {
            left.valid = false;
            return left;
        }
        if (left.known && right.known) left.integer &= right.integer;
        else left.known = false;
        left.is_unsigned = left.is_unsigned || right.is_unsigned;
        left.chain_operation = 0;
    }
    return left;
}

static bool yx_inv_typed_atom(const char *start, size_t length, yx_inv_nonbool_type *type, int *value)
{
    yx_inv_arithmetic parser = {start, start + length};
    yx_inv_number number;
    if (length >= 2 && start[0] == '"' && start[length - 1] == '"') {
        size_t i = 1;
        while (i < length - 1) {
            if (start[i] == '\\' && i + 1 < length - 1) ++i;
            else if (start[i] == '"') return false;
            ++i;
        }
        *type = YX_INV_NONBOOL_STRING;
        *value = length == 2 ? 0 : 1;
        return true;
    }
    number = yx_inv_arithmetic_or(&parser, 0);
    yx_inv_arithmetic_skip(&parser);
    if (!number.valid || parser.at != parser.end) return false;
    *type = number.type;
    *value = !number.known ? -1 : (number.type == YX_INV_NONBOOL_FLOAT ? number.floating != 0.0 : number.integer != 0);
    return true;
}

static bool yx_inv_call_name_is(const char *name, size_t length, const char *expected)
{
    size_t expected_length = strlen(expected);
    return length == expected_length && memcmp(name, expected, expected_length) == 0;
}

/* The condition has already passed semantic validation. Identify calls whose
 * return type is known here so the warning pass can report an implicit
 * conversion to bool. The compiler highlights the final method and its
 * arguments, omitting the module and any containing object path. */
static bool yx_inv_typed_module_call(const char *start, size_t length, yx_inv_nonbool_type *type, size_t *method_start)
{
    const char *open = memchr(start, '(', length);
    size_t name_length, last_dot = 0;
    if (!open || !length || start[length - 1] != ')') return false;
    /* A module call must own the entire expression. A comparison such as
     * hash.md5(...) == hash.md5(...) also ends in ')' and must not inherit
     * the return type of its first call. Honor nested calls and quoted
     * string arguments while locating the first call's closing paren. */
    {
        size_t depth = 1;
        bool quoted = false, escaped = false;
        for (size_t i = (size_t)(open - start) + 1; i < length; ++i) {
            char ch = start[i];
            if (quoted) {
                if (escaped) escaped = false;
                else if (ch == '\\') escaped = true;
                else if (ch == '"') quoted = false;
            } else if (ch == '"') {
                quoted = true;
            } else if (ch == '(') {
                ++depth;
            } else if (ch == ')' && --depth == 0) {
                if (i != length - 1) return false;
            }
        }
        if (quoted || depth) return false;
    }
    name_length = (size_t)(open - start);
    while (name_length && isspace((unsigned char)start[name_length - 1])) --name_length;
    for (size_t i = 0; i < name_length; ++i) {
        unsigned char ch = (unsigned char)start[i];
        if (ch == '.') last_dot = i + 1;
        else if (!isalnum(ch) && ch != '_') return false;
    }
    if (!last_dot || last_dot == name_length) return false;
    *method_start = last_dot;

    if ((name_length > 7 && memcmp(start, "cuckoo.", 7) == 0) || (name_length > 4 && memcmp(start + name_length - 4, ".len", 4) == 0) ||
        yx_inv_call_name_is(start, name_length, "hash.crc32") || yx_inv_call_name_is(start, name_length, "hash.checksum32") ||
        yx_inv_call_name_is(start, name_length, "string.length") || yx_inv_call_name_is(start, name_length, "string.to_int") ||
        yx_inv_call_name_is(start, name_length, "time.now") || yx_inv_call_name_is(start, name_length, "math.max") ||
        yx_inv_call_name_is(start, name_length, "pe.calculate_checksum") || yx_inv_call_name_is(start, name_length, "pe.section_index") ||
        yx_inv_call_name_is(start, name_length, "pe.rva_to_offset") || yx_inv_call_name_is(start, name_length, "pe.offset_to_rva") ||
        yx_inv_call_name_is(start, name_length, "pe.exports_index") || yx_inv_call_name_is(start, name_length, "pe.import_rva") ||
        yx_inv_call_name_is(start, name_length, "pe.delayed_import_rva") || yx_inv_call_name_is(start, name_length, "macho.file_index_for_arch") ||
        yx_inv_call_name_is(start, name_length, "macho.entry_point_for_arch")) {
        *type = YX_INV_NONBOOL_INTEGER;
        return true;
    }
    if (yx_inv_call_name_is(start, name_length, "math.entropy") || yx_inv_call_name_is(start, name_length, "math.percentage") ||
        yx_inv_call_name_is(start, name_length, "math.mean") || yx_inv_call_name_is(start, name_length, "math.deviation") ||
        yx_inv_call_name_is(start, name_length, "math.serial_correlation") || yx_inv_call_name_is(start, name_length, "math.monte_carlo_pi")) {
        *type = YX_INV_NONBOOL_FLOAT;
        return true;
    }
    if (yx_inv_call_name_is(start, name_length, "hash.md5") || yx_inv_call_name_is(start, name_length, "hash.sha1") ||
        yx_inv_call_name_is(start, name_length, "hash.sha256") || yx_inv_call_name_is(start, name_length, "math.to_string") ||
        yx_inv_call_name_is(start, name_length, "pe.imphash") || yx_inv_call_name_is(start, name_length, "elf.import_md5") ||
        yx_inv_call_name_is(start, name_length, "crx.permhash") || yx_inv_call_name_is(start, name_length, "dex.signature")
#ifdef XXYARA_ENABLE_MAGIC
        || yx_inv_call_name_is(start, name_length, "magic.type") || yx_inv_call_name_is(start, name_length, "magic.mime_type")
#endif
    ) {
        *type = YX_INV_NONBOOL_STRING;
        return true;
    }
    return false;
}

static bool yx_inv_record_nonbool(yx_inv_parser *parser, size_t start, size_t end, yx_inv_nonbool_type type)
{
    yx_inv_nonbool *grown;
    size_t capacity;
    if (parser->nonbool_count == parser->nonbool_capacity) {
        capacity = parser->nonbool_capacity ? parser->nonbool_capacity * 2 : 8;
        if (capacity < parser->nonbool_capacity || capacity > SIZE_MAX / sizeof(*grown)) {
            parser->out_of_memory = true;
            return false;
        }
        grown = (yx_inv_nonbool *)realloc(parser->nonbool, capacity * sizeof(*grown));
        if (!grown) {
            parser->out_of_memory = true;
            return false;
        }
        parser->nonbool = grown;
        parser->nonbool_capacity = capacity;
    }
    parser->nonbool[parser->nonbool_count].start = start;
    parser->nonbool[parser->nonbool_count].end = end;
    parser->nonbool[parser->nonbool_count].type = type;
    ++parser->nonbool_count;
    return true;
}

static bool yx_inv_save_direct(yx_inv_parser *parser, yx_inv_nonbool **items, size_t *count, size_t *capacity, yx_inv_expr expr)
{
    yx_inv_nonbool *grown;
    size_t next;
    if (expr.nonbool_type == YX_INV_NONBOOL_NONE) return true;
    if (*count == *capacity) {
        next = *capacity ? *capacity * 2 : 4;
        if (next < *capacity || next > SIZE_MAX / sizeof(*grown)) {
            parser->out_of_memory = true;
            return false;
        }
        grown = (yx_inv_nonbool *)realloc(*items, next * sizeof(*grown));
        if (!grown) {
            parser->out_of_memory = true;
            return false;
        }
        *items = grown;
        *capacity = next;
    }
    (*items)[*count].start = expr.start;
    (*items)[*count].end = expr.end;
    (*items)[*count].type = expr.nonbool_type;
    ++*count;
    return true;
}

static bool yx_inv_commit_pending(yx_inv_parser *parser, yx_inv_expr *expr)
{
    bool good = true;
    for (size_t i = 0; i < expr->pending_count; ++i) {
        if (!yx_inv_record_nonbool(parser, expr->pending[i].start, expr->pending[i].end, expr->pending[i].type)) {
            good = false;
            break;
        }
    }
    free(expr->pending);
    expr->pending = NULL;
    expr->pending_count = 0;
    expr->pending_capacity = 0;
    expr->pending_operator = YX_INV_END;
    return good;
}

static bool yx_inv_save_operand(yx_inv_parser *parser, yx_inv_expr *group, yx_inv_expr operand)
{
    return yx_inv_save_direct(parser, &group->pending, &group->pending_count, &group->pending_capacity, operand);
}

static yx_inv_expr yx_inv_parse_dynamic(yx_inv_parser *parser, size_t start)
{
    yx_inv_expr expr = {0};
    unsigned parentheses = 0;
    expr.valid = true;
    expr.value = -1;
    expr.start = start;
    expr.end = start;
    while (parser->token != YX_INV_END) {
        if (parentheses == 0 && (parser->token == YX_INV_AND || parser->token == YX_INV_OR || parser->token == YX_INV_RPAREN)) break;
        if (parser->token == YX_INV_LPAREN) ++parentheses;
        else if (parser->token == YX_INV_RPAREN) --parentheses;
        expr.end = parser->end;
        yx_inv_next(parser);
    }
    if (expr.end == start) {
        expr.valid = false;
        return expr;
    }
    if (yx_inv_typed_atom(parser->source + start, expr.end - start, &expr.nonbool_type, &expr.value) && expr.nonbool_type != YX_INV_NONBOOL_STRING) {
        /* The reference expression span omits closing parentheses when
         * they are the final tokens of an arithmetic expression. */
        while (expr.end > start && parser->source[expr.end - 1] == ')') {
            size_t open = expr.end - 1;
            unsigned depth = 1;
            while (open > start && depth) {
                --open;
                if (parser->source[open] == ')') ++depth;
                else if (parser->source[open] == '(') --depth;
            }
            size_t before = open;
            while (before > start && isspace((unsigned char)parser->source[before - 1])) --before;
            if (!depth && before >= start + 2 && memcmp(parser->source + before - 2, "in", 2) == 0) break;
            --expr.end;
            while (expr.end > start && isspace((unsigned char)parser->source[expr.end - 1])) --expr.end;
        }
    } else if (expr.nonbool_type == YX_INV_NONBOOL_NONE) {
        size_t method_start;
        if (yx_inv_typed_module_call(parser->source + start, expr.end - start, &expr.nonbool_type, &method_start)) expr.start += method_start;
    }
    return expr;
}

/* A global the compiler defines as an integer, float or string, used as a
 * whole Boolean operand: a non-boolean expression whose value stays dynamic
 * unless it is the entire condition. */
static bool yx_inv_parse_global(yx_inv_parser *parser, yx_inv_expr *expr)
{
    const char *name = parser->source + parser->start;
    size_t length = parser->end - parser->start;
    yx_inv_parser next;
    if (!parser->compiler || !parser->compiler->rules || !length || !(isalpha((unsigned char)name[0]) || name[0] == '_')) return false;
    for (size_t i = 1; i < length; ++i)
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_')) return false;
    next = *parser;
    yx_inv_next(&next);
    if (next.token != YX_INV_AND && next.token != YX_INV_OR && next.token != YX_INV_RPAREN && next.token != YX_INV_END) return false;
    for (size_t i = 0; i < parser->compiler->rules->global_count; ++i) {
        const yx_global *global = &parser->compiler->rules->globals[i];
        bool truth;
        if (strlen(global->name) != length || memcmp(global->name, name, length)) continue;
        if (global->type == YX_GLOBAL_INT) {
            expr->nonbool_type = YX_INV_NONBOOL_INTEGER;
            truth = global->value.integer != 0;
        } else if (global->type == YX_GLOBAL_FLOAT) {
            expr->nonbool_type = YX_INV_NONBOOL_FLOAT;
            truth = global->value.floating != 0.0;
        } else if (global->type == YX_GLOBAL_STR) {
            expr->nonbool_type = YX_INV_NONBOOL_STRING;
            truth = global->value.string.length != 0;
        } else {
            return false;
        }
        expr->valid = true;
        expr->value = -1;
        expr->bare_global = truth ? 2 : 1;
        expr->start = parser->start;
        expr->end = parser->end;
        *parser = next;
        return true;
    }
    return false;
}

static yx_inv_expr yx_inv_parse_primary(yx_inv_parser *parser, unsigned depth)
{
    yx_inv_expr expr = {0};
    if (depth > YX_INV_DEPTH_LIMIT) return expr;
    if (parser->token == YX_INV_OTHER && parser->end - parser->start == 4 && memcmp(parser->source + parser->start, "with", 4) == 0) {
        yx_inv_parser cursor = *parser;
        size_t opening = parser->start;
        unsigned nesting = 0, nested_scopes = 0;
        yx_inv_next(&cursor);
        while (cursor.token != YX_INV_END) {
            char symbol = cursor.source[cursor.start];
            if (cursor.token == YX_INV_LPAREN || symbol == '[') ++nesting;
            else if (cursor.token == YX_INV_RPAREN || symbol == ']') {
                if (!nesting) break;
                --nesting;
            } else if (!nesting && cursor.token == YX_INV_OTHER) {
                size_t token_length = cursor.end - cursor.start;
                if ((token_length == 4 && memcmp(cursor.source + cursor.start, "with", 4) == 0) ||
                    (token_length == 3 && memcmp(cursor.source + cursor.start, "for", 3) == 0))
                    ++nested_scopes;
                else if (symbol == ':') {
                    if (!nested_scopes) break;
                    --nested_scopes;
                }
            }
            yx_inv_next(&cursor);
        }
        if (cursor.token == YX_INV_OTHER && cursor.source[cursor.start] == ':') {
            yx_inv_next(&cursor);
            if (cursor.token == YX_INV_LPAREN) {
                *parser = cursor;
                yx_inv_next(parser);
                expr = yx_inv_parse_or(parser, depth + 1);
                if (parser->token != YX_INV_RPAREN) expr.valid = false;
                else {
                    expr.start = opening;
                    expr.end = parser->end;
                    yx_inv_next(parser);
                }
                return expr;
            }
        }
        return yx_inv_parse_dynamic(parser, opening);
    } else if (parser->token == YX_INV_TRUE || parser->token == YX_INV_FALSE) {
        expr.valid = true;
        expr.value = parser->token == YX_INV_TRUE ? 1 : 0;
        expr.start = parser->start;
        expr.end = parser->end;
        yx_inv_next(parser);
    } else if (parser->token == YX_INV_LPAREN) {
        size_t opening = parser->start;
        yx_inv_next(parser);
        expr = yx_inv_parse_or(parser, depth + 1);
        if (parser->token != YX_INV_RPAREN) expr.valid = false;
        else yx_inv_next(parser);
        if (expr.valid && parser->token == YX_INV_OTHER) {
            size_t display_start = expr.start;
            if (!yx_inv_commit_pending(parser, &expr)) expr.valid = false;
            else {
                expr = yx_inv_parse_dynamic(parser, opening);
                expr.start = display_start;
            }
        }
    } else if (parser->token == YX_INV_OTHER && yx_inv_parse_global(parser, &expr)) {
        /* A non-boolean global operand. */
    } else if (parser->token != YX_INV_END && parser->token != YX_INV_AND && parser->token != YX_INV_OR && parser->token != YX_INV_RPAREN) {
        expr = yx_inv_parse_dynamic(parser, parser->start);
    }
    return expr;
}

static yx_inv_expr yx_inv_parse_not(yx_inv_parser *parser, unsigned depth)
{
    yx_inv_expr expr = {0};
    size_t start;
    if (depth > YX_INV_DEPTH_LIMIT) return expr;
    if (parser->token != YX_INV_NOT) return yx_inv_parse_primary(parser, depth + 1);
    start = parser->start;
    yx_inv_next(parser);
    expr = yx_inv_parse_not(parser, depth + 1);
    if (expr.valid) {
        if (!yx_inv_commit_pending(parser, &expr)) {
            expr.valid = false;
            return expr;
        }
        if (expr.nonbool_type != YX_INV_NONBOOL_NONE && !yx_inv_record_nonbool(parser, expr.start, expr.end, expr.nonbool_type)) expr.valid = false;
        expr.value = expr.nonbool_type != YX_INV_NONBOOL_NONE || expr.value < 0 ? -1 : !expr.value;
        expr.nonbool_type = YX_INV_NONBOOL_NONE;
        expr.bare_global = 0;
        expr.start = start;
    }
    return expr;
}

static yx_inv_expr yx_inv_parse_and(yx_inv_parser *parser, unsigned depth)
{
    yx_inv_expr expr = yx_inv_parse_not(parser, depth + 1);
    if (!expr.valid || parser->token != YX_INV_AND) return expr;
    if (expr.pending_operator != YX_INV_AND && !yx_inv_commit_pending(parser, &expr)) goto failure;
    expr.pending_operator = YX_INV_AND;
    if (!yx_inv_save_operand(parser, &expr, expr)) goto failure;
    while (expr.valid && parser->token == YX_INV_AND) {
        yx_inv_expr rhs;
        yx_inv_next(parser);
        rhs = yx_inv_parse_not(parser, depth + 1);
        if (!rhs.valid || !yx_inv_commit_pending(parser, &rhs) || !yx_inv_save_operand(parser, &expr, rhs)) {
            free(rhs.pending);
            expr.valid = false;
            goto failure;
        }
        expr.value = expr.value == 0 || rhs.value == 0 ? 0 : (expr.value == 1 && rhs.value == 1 ? 1 : -1);
        expr.nonbool_type = YX_INV_NONBOOL_NONE;
        expr.bare_global = 0;
        expr.end = rhs.end;
    }
    return expr;
failure:
    free(expr.pending);
    expr.pending = NULL;
    expr.valid = false;
    return expr;
}

static yx_inv_expr yx_inv_parse_or(yx_inv_parser *parser, unsigned depth)
{
    yx_inv_expr expr = {0};
    if (depth > YX_INV_DEPTH_LIMIT) return expr;
    expr = yx_inv_parse_and(parser, depth + 1);
    if (!expr.valid || parser->token != YX_INV_OR) return expr;
    if (expr.pending_operator != YX_INV_OR && !yx_inv_commit_pending(parser, &expr)) goto failure;
    expr.pending_operator = YX_INV_OR;
    if (!yx_inv_save_operand(parser, &expr, expr)) goto failure;
    while (expr.valid && parser->token == YX_INV_OR) {
        yx_inv_expr rhs;
        yx_inv_next(parser);
        rhs = yx_inv_parse_and(parser, depth + 1);
        if (!rhs.valid || !yx_inv_commit_pending(parser, &rhs) || !yx_inv_save_operand(parser, &expr, rhs)) {
            free(rhs.pending);
            expr.valid = false;
            goto failure;
        }
        expr.value = expr.value == 1 || rhs.value == 1 ? 1 : (expr.value == 0 && rhs.value == 0 ? 0 : -1);
        expr.nonbool_type = YX_INV_NONBOOL_NONE;
        expr.bare_global = 0;
        expr.end = rhs.end;
    }
    return expr;
failure:
    free(expr.pending);
    expr.pending = NULL;
    expr.valid = false;
    return expr;
}

/* An external bool used alone is reported as invariant by YARA-X. Its value
 * remains dynamic inside a larger expression, including `not foo`. The
 * parser keeps the innermost span for parenthesized expressions, so checking
 * the final span also covers `(foo)` without folding composite conditions. */
static void yx_inv_resolve_bare_global(const YRX_COMPILER *compiler, const char *condition, yx_inv_expr *expr)
{
    const char *name;
    size_t length;
    if (expr->value >= 0 || expr->nonbool_type != YX_INV_NONBOOL_NONE || expr->end <= expr->start || !compiler->rules) return;
    name = condition + expr->start;
    length = expr->end - expr->start;
    if (!(isalpha((unsigned char)name[0]) || name[0] == '_')) return;
    for (size_t i = 1; i < length; ++i)
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_')) return;
    for (size_t i = 0; i < compiler->rules->global_count; ++i) {
        const yx_global *global = &compiler->rules->globals[i];
        if (global->type == YX_GLOBAL_BOOL && strlen(global->name) == length && memcmp(global->name, name, length) == 0) {
            expr->value = global->value.boolean ? 1 : 0;
            return;
        }
    }
}

/* YARA-X folds through `with` identifiers: a declared identifier carries
 * its declaration's type value, constant folding reads type values, and
 * Expr::With takes its body's value (ir/mod.rs). So the invariant analysis
 * reads each `with` body with every use of a declared identifier replaced
 * by its parenthesised declaration; headers are kept, so positions before
 * the first replacement and after the last one are unchanged. */
typedef struct {
    const char *name;
    size_t length;
    char *value;
} yx_inv_binding;

typedef struct {
    const char *source;
    char *text;
    size_t used;
    size_t capacity;
    yx_inv_binding *bindings;
    size_t binding_count;
    size_t binding_capacity;
    bool expanded;
} yx_inv_with_state;

#define YX_INV_WITH_DEPTH_LIMIT 64
#define YX_INV_WITH_TEXT_LIMIT ((size_t)1 << 20)

/* Returns the end of the comment, string or regexp at `at`, or `at`.
 * Division is `\` in YARA, so any other `/` starts a regexp. */
static const char *yx_inv_skip_literal(const char *at, const char *end)
{
    if (at >= end) return at;
    if (end - at >= 2 && at[0] == '/' && at[1] == '/') {
        at += 2;
        while (at < end && *at != '\n') ++at;
        return at;
    }
    if (end - at >= 2 && at[0] == '/' && at[1] == '*') {
        at += 2;
        while (end - at >= 2 && !(at[0] == '*' && at[1] == '/')) ++at;
        return end - at >= 2 ? at + 2 : end;
    }
    if (*at == '"') {
        ++at;
        while (at < end && *at != '"') {
            if (*at == '\\' && end - at >= 2) ++at;
            ++at;
        }
        return at < end ? at + 1 : end;
    }
    if (*at == '/') {
        bool in_class = false;
        ++at;
        while (at < end) {
            if (*at == '\\' && end - at >= 2) {
                at += 2;
                continue;
            }
            if (*at == '[') in_class = true;
            else if (*at == ']') in_class = false;
            else if (*at == '/' && !in_class) break;
            ++at;
        }
        if (at < end) ++at;
        while (at < end && isalpha((unsigned char)*at)) ++at;
        return at;
    }
    return at;
}

static const char *yx_inv_skip_space(const char *at, const char *end)
{
    for (;;) {
        while (at < end && isspace((unsigned char)*at)) ++at;
        if (end - at >= 2 && at[0] == '/' && (at[1] == '/' || at[1] == '*')) {
            at = yx_inv_skip_literal(at, end);
            continue;
        }
        return at;
    }
}

static bool yx_inv_word_char(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

/* The `,` or `:` that ends the declaration at `at`, or NULL. */
static const char *yx_inv_declaration_end(const char *at, const char *end)
{
    size_t depth = 0;
    while (at < end) {
        const char *skipped = yx_inv_skip_literal(at, end);
        if (skipped != at) {
            at = skipped;
            continue;
        }
        if (*at == '(' || *at == '[') ++depth;
        else if (*at == ')' || *at == ']') {
            if (!depth) return NULL;
            --depth;
        } else if (!depth && (*at == ',' || *at == ':')) return at;
        ++at;
    }
    return NULL;
}

static const char *yx_inv_closing_paren(const char *open, const char *end)
{
    size_t depth = 0;
    const char *at = open;
    while (at < end) {
        const char *skipped = yx_inv_skip_literal(at, end);
        if (skipped != at) {
            at = skipped;
            continue;
        }
        if (*at == '(') ++depth;
        else if (*at == ')' && depth && --depth == 0) return at;
        ++at;
    }
    return NULL;
}

static bool yx_inv_with_append(yx_inv_with_state *state, const char *text, size_t length)
{
    if (state->used > YX_INV_WITH_TEXT_LIMIT || length > YX_INV_WITH_TEXT_LIMIT) return false;
    /* The copy yx_diagnostic_append("%.*s") makes, without formatting each
     * token of the condition (the text holds no NUL byte). */
    if (state->used + length + 1 > state->capacity) {
        size_t next = state->capacity ? state->capacity : 256;
        char *grown;
        while (next < state->used + length + 1) next *= 2;
        grown = (char *)realloc(state->text, next);
        if (!grown) return false;
        state->text = grown;
        state->capacity = next;
    }
    memcpy(state->text + state->used, text, length);
    state->used += length;
    state->text[state->used] = '\0';
    return true;
}

/* Appends source[at..end) with the bound identifiers replaced. A
 * declaration drops its comments. Returns false when the text is beyond
 * this analysis: a `for` (its variables may shadow) or a `with` inside a
 * declaration, or a malformed `with`. */
static bool yx_inv_expand_with(yx_inv_with_state *state, const char *at, const char *end, unsigned depth, bool declaration)
{
    if (depth > YX_INV_WITH_DEPTH_LIMIT) return false;
    while (at < end) {
        const char *skipped = yx_inv_skip_literal(at, end);
        if (skipped != at) {
            bool comment = *at == '/' && end - at >= 2 && (at[1] == '/' || at[1] == '*');
            if (declaration && comment) {
                if (!yx_inv_with_append(state, " ", 1)) return false;
            } else if (!yx_inv_with_append(state, at, (size_t)(skipped - at))) return false;
            at = skipped;
            continue;
        }
        if ((*at == '$' || *at == '#' || *at == '@' || *at == '!' || isdigit((unsigned char)*at))) {
            const char *token = at++;
            while (at < end && (yx_inv_word_char(*at) || (isdigit((unsigned char)*token) && *at == '.' && end - at >= 2 && isdigit((unsigned char)at[1])) ||
                                (*token == '$' && *at == '*')))
                ++at;
            if (!yx_inv_with_append(state, token, (size_t)(at - token))) return false;
            continue;
        }
        if (isalpha((unsigned char)*at) || *at == '_') {
            const char *word = at, *back = at;
            size_t length;
            bool member;
            while (at < end && yx_inv_word_char(*at)) ++at;
            length = (size_t)(at - word);
            while (back > state->source && isspace((unsigned char)back[-1])) --back;
            member = back > state->source && back[-1] == '.' && !(back - 1 > state->source && back[-2] == '.');
            if (member) {
                if (!yx_inv_with_append(state, word, length)) return false;
                continue;
            }
            if (length == 3 && memcmp(word, "for", 3) == 0 && (declaration || state->binding_count)) return false;
            if (length == 4 && memcmp(word, "with", 4) == 0) {
                const char *cursor = at, *open, *close;
                size_t mark = state->binding_count;
                bool ok = true;
                if (declaration) return false;
                for (;;) {
                    const char *name, *declaration_end;
                    size_t value_start;
                    yx_inv_binding *binding;
                    cursor = yx_inv_skip_space(cursor, end);
                    if (cursor >= end || !(isalpha((unsigned char)*cursor) || *cursor == '_')) {
                        ok = false;
                        break;
                    }
                    name = cursor;
                    while (cursor < end && yx_inv_word_char(*cursor)) ++cursor;
                    if (state->binding_count == state->binding_capacity) {
                        size_t grown = state->binding_capacity ? state->binding_capacity * 2 : 8;
                        yx_inv_binding *bindings = (yx_inv_binding *)realloc(state->bindings, grown * sizeof(*bindings));
                        if (!bindings) {
                            ok = false;
                            break;
                        }
                        state->bindings = bindings;
                        state->binding_capacity = grown;
                    }
                    binding = &state->bindings[state->binding_count];
                    binding->name = name;
                    binding->length = (size_t)(cursor - name);
                    binding->value = NULL;
                    cursor = yx_inv_skip_space(cursor, end);
                    if (cursor >= end || *cursor != '=' || (end - cursor >= 2 && cursor[1] == '=')) {
                        ok = false;
                        break;
                    }
                    ++cursor;
                    declaration_end = yx_inv_declaration_end(cursor, end);
                    if (!declaration_end) {
                        ok = false;
                        break;
                    }
                    /* Expand the declaration at the end of the text, then
                     * move it into the binding. */
                    value_start = state->used;
                    if (!yx_inv_with_append(state, "(", 1) || !yx_inv_expand_with(state, cursor, declaration_end, depth + 1, true) ||
                        !yx_inv_with_append(state, ")", 1)) {
                        ok = false;
                        break;
                    }
                    binding->value = (char *)malloc(state->used - value_start + 1);
                    if (!binding->value) {
                        ok = false;
                        break;
                    }
                    memcpy(binding->value, state->text + value_start, state->used - value_start);
                    binding->value[state->used - value_start] = '\0';
                    state->used = value_start;
                    state->text[state->used] = '\0';
                    /* Later declarations see this one. */
                    ++state->binding_count;
                    cursor = declaration_end + 1;
                    if (*declaration_end == ':') break;
                }
                open = ok ? yx_inv_skip_space(cursor, end) : NULL;
                close = open && open < end && *open == '(' ? yx_inv_closing_paren(open, end) : NULL;
                ok = ok && close && yx_inv_with_append(state, word, (size_t)(open + 1 - word)) && yx_inv_expand_with(state, open + 1, close, depth + 1, false) &&
                     yx_inv_with_append(state, ")", 1);
                while (state->binding_count > mark) free(state->bindings[--state->binding_count].value);
                if (!ok) return false;
                state->expanded = true;
                at = close + 1;
                continue;
            }
            for (size_t i = state->binding_count; i-- > 0;) {
                if (state->bindings[i].length == length && memcmp(state->bindings[i].name, word, length) == 0) {
                    if (!yx_inv_with_append(state, state->bindings[i].value, strlen(state->bindings[i].value))) return false;
                    length = 0;
                    break;
                }
            }
            if (length && !yx_inv_with_append(state, word, length)) return false;
            continue;
        }
        if (!yx_inv_with_append(state, at, 1)) return false;
        ++at;
    }
    return true;
}

/* The condition with `with` identifiers replaced, or NULL to analyse the
 * condition as written. */
static char *yx_inv_expand_condition(const char *condition)
{
    yx_inv_with_state state;
    bool ok;
    memset(&state, 0, sizeof(state));
    state.source = condition;
    ok = yx_inv_expand_with(&state, condition, condition + strlen(condition), 0, false);
    while (state.binding_count) free(state.bindings[--state.binding_count].value);
    free(state.bindings);
    if (!ok || !state.expanded || !state.text) {
        free(state.text);
        return NULL;
    }
    return state.text;
}

/* Moves warning `index` before the first warning from `first_type_warning`
 * on that YARA-X raises after source position `position`. non_bool_expr,
 * unused_identifier and potentially_slow_loop are raised at their recorded
 * point (after their expression); the other typed kinds at their label. */
static void yx_compiler_move_before_later(YRX_COMPILER *compiler, size_t first_type_warning, size_t index, size_t position)
{
    for (size_t j = first_type_warning; j < index; ++j) {
        const char *warning = compiler->warnings[j];
        size_t other_position = 0, point;
        bool raised_after = false;
        for (point = 0; point < compiler->warning_point_count; ++point)
            if (compiler->warning_point_keys[point] == warning) {
                other_position = compiler->warning_point_values[point];
                raised_after = true;
                break;
            }
        if (!raised_after) {
            const char *other;
            if (!strstr(warning, "\"type\":\"UnsatisfiableExpression\"") && !strstr(warning, "\"type\":\"BooleanIntegerComparison\"") &&
                !strstr(warning, "\"type\":\"NonBooleanAsBoolean\"") && !strstr(warning, "\"type\":\"DeprecatedField\""))
                continue;
            other = strstr(warning, "\"span\":{\"start\":");
            if (!other || !yx_compiler_json_span(compiler, other, &other_position, NULL)) continue;
        }
        if (other_position > position) {
            char *saved = compiler->warnings[index];
            memmove(compiler->warnings + j + 1, compiler->warnings + j, (index - j) * sizeof(*compiler->warnings));
            compiler->warnings[j] = saved;
            return;
        }
    }
}

static int yx_compiler_warn_invariant_condition_impl(YRX_COMPILER *compiler, const char *condition, const YRX_RULE *rule, const char *source, const char *origin,
                                                     size_t condition_offset, size_t first_type_warning);

int yx_compiler_warn_invariant_condition(YRX_COMPILER *compiler, const char *condition, const YRX_RULE *rule, const char *source, const char *origin,
                                         size_t condition_offset, size_t first_type_warning)
{
    int result;
    yx_inv_scope_compiler = compiler;
    result = yx_compiler_warn_invariant_condition_impl(compiler, condition, rule, source, origin, condition_offset, first_type_warning);
    yx_inv_scope_compiler = NULL;
    return result;
}

static int yx_compiler_warn_invariant_condition_impl(YRX_COMPILER *compiler, const char *condition, const YRX_RULE *rule, const char *source, const char *origin,
                                                     size_t condition_offset, size_t first_type_warning)
{
    yx_inv_parser parser = {0};
    yx_inv_expr expr;
    const char *value;
    char label[128], *note;
    char *expanded = NULL;
    parser.source = condition;
    parser.compiler = compiler;
    parser.at = condition;
    size_t first_deprecated = compiler->warning_count;
    if (!yx_compiler_warn_deprecated_fields(compiler, condition, source, origin, condition_offset)) goto memory_failure;
    /* The typed visitor and legacy schema deprecations are separate passes.
     * Merge deprecations into those local type warnings in source order,
     * retaining the order of every other warning category. */
    for (size_t i = first_deprecated; i < compiler->warning_count; ++i) {
        const char *span = strstr(compiler->warnings[i], "\"span\":{\"start\":");
        size_t position;
        if (!yx_compiler_json_span(compiler, span, &position, NULL)) continue;
        /* A deprecated field read before a typed warning's point (in an
         * operand, the body) comes first. */
        yx_compiler_move_before_later(compiler, first_type_warning, i, position);
    }
    if (!yx_compiler_warn_global_rule_references(compiler, condition, source, origin, condition_offset)) goto memory_failure;
    expanded = yx_inv_expand_condition(condition);
    if (expanded) {
        parser.source = expanded;
        parser.at = expanded;
    }
    yx_inv_next(&parser);
    expr = yx_inv_parse_or(&parser, 0);
    if (parser.out_of_memory) {
        free(expr.pending);
        goto memory_failure;
    }
    if (!expr.valid || parser.token != YX_INV_END) {
        free(expr.pending);
        free(parser.nonbool);
        free(expanded);
        return 1;
    }
    if (!yx_inv_commit_pending(&parser, &expr)) goto memory_failure;
    /* non_bool_expr comes from the typed condition walk (condition.c,
     * yx_warn_non_bool), in YARA-X's order; this parser only decides the
     * invariant value. */
    free(parser.nonbool);
    parser.nonbool = NULL;
    yx_inv_resolve_bare_global(compiler, parser.source, &expr);
    if (expanded) {
        /* Only `with` bodies differ, and the expression ends after them. */
        size_t expanded_length = strlen(expanded), length = strlen(condition);
        if (expr.end + length < expanded_length) expr.value = -1;
        else expr.end = expr.end + length - expanded_length;
        free(expanded);
        expanded = NULL;
    }
    if (expr.bare_global) expr.value = expr.bare_global - 1;
    if (expr.value < 0) return 1;
    /* A function call spans its identifier and arguments, not the object
     * it is called on (parser ast/mod.rs, `impl WithSpan for FuncCall`), and
     * an operation starts where its first operand does. */
    {
        const char *at = condition + expr.start, *name = at, *last = NULL;
        for (;;) {
            if (!(isalpha((unsigned char)*at) || *at == '_')) break;
            name = at;
            while (isalnum((unsigned char)*at) || *at == '_') ++at;
            while (isspace((unsigned char)*at)) ++at;
            if (*at == '(') {
                last = name;
                break;
            }
            if (*at != '.') break;
            ++at;
            while (isspace((unsigned char)*at)) ++at;
        }
        if (last && last > condition + expr.start && (size_t)(last - condition) < expr.end) expr.start = (size_t)(last - condition);
    }
    value = expr.value == 1 ? "true" : "false";
    snprintf(label, sizeof(label), "this expression is always %s", value);
    /* The note holds the whole rule identifier, however long. */
    note = malloc(strlen(rule->identifier) + 32);
    if (note) sprintf(note, "rule `%s` is always `%s`", rule->identifier, value);
    if (!note || !yx_compiler_warning(compiler, "InvariantBooleanExpression", "invariant_expr", "invariant boolean expression", label, source, origin,
                                      condition_offset + expr.start, condition_offset + expr.end, note)) {
        free(note);
        snprintf(compiler->error, sizeof(compiler->error), "out of memory recording invariant expression warning");
        return 0;
    }
    free(note);
    return 1;
memory_failure:
    free(parser.nonbool);
    free(expanded);
    snprintf(compiler->error, sizeof(compiler->error), "out of memory recording condition warning");
    return 0;
}

static bool yx_append_source(YRX_RULES *rules, const char *source)
{
    size_t existing = rules->source ? strlen(rules->source) : 0;
    size_t added = strlen(source);
    char *combined;
    size_t separator = existing ? 1 : 0;
    if (existing > SIZE_MAX - separator - 1 || added > SIZE_MAX - existing - separator - 1) return false;
    combined = (char *)realloc(rules->source, existing + added + separator + 1);
    if (!combined) return false;
    if (separator) combined[existing++] = '\n';
    memcpy(combined + existing, source, added + 1);
    rules->source = combined;
    return true;
}

static void yx_free_include_state(YRX_COMPILER *compiler)
{
    size_t i;
    for (i = 0; i < compiler->include_dir_count; ++i) free(compiler->include_dirs[i]);
    free(compiler->include_dirs);
    compiler->include_dirs = NULL;
    compiler->include_dir_count = 0;
    for (i = 0; i < compiler->include_depth; ++i) free(compiler->include_stack[i]);
    free(compiler->include_stack);
    compiler->include_stack = NULL;
    compiler->include_depth = 0;
}

static bool yx_absolute_path(const char *path)
{
    return path[0] == '/' || path[0] == '\\' || ((((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':'));
}

static char *yx_join_include_path(const char *directory, const char *filename)
{
    size_t dir_length, file_length, separator;
    char *path;
    if (yx_absolute_path(filename) || !directory || !*directory || strcmp(directory, ".") == 0) return yx_strdup(filename);
    dir_length = strlen(directory);
    file_length = strlen(filename);
    separator = directory[dir_length - 1] != '/' && directory[dir_length - 1] != '\\';
    if (dir_length > SIZE_MAX - file_length - separator - 1) return NULL;
    path = (char *)malloc(dir_length + file_length + separator + 1);
    if (!path) return NULL;
    memcpy(path, directory, dir_length);
    if (separator) path[dir_length++] = '/';
    memcpy(path + dir_length, filename, file_length + 1);
    return path;
}

static char *yx_include_parent(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    size_t length;
    char *directory;
    if (backslash && (!slash || backslash > slash)) slash = backslash;
    if (!slash) return yx_strdup(".");
    length = slash == path ? 1 : (size_t)(slash - path);
    directory = (char *)malloc(length + 1);
    if (!directory) return NULL;
    memcpy(directory, path, length);
    directory[length] = '\0';
    return directory;
}

static char *yx_include_canonical_path(const char *path)
{
    char *absolute, *cwd = NULL, *canonical_cwd = NULL, *relative;
    size_t capacity = 256, absolute_length, cwd_length, offset;
#ifdef _WIN32
    absolute = _fullpath(NULL, path, 0);
#else
    absolute = realpath(path, NULL);
#endif
    if (!absolute) return NULL;
    for (;;) {
        char *grown = (char *)realloc(cwd, capacity);
        if (!grown) {
            free(cwd);
            return absolute;
        }
        cwd = grown;
#ifdef _WIN32
        if (_getcwd(cwd, (int)capacity)) break;
#else
        if (getcwd(cwd, capacity)) break;
#endif
        if (errno != ERANGE || capacity > INT_MAX / 2) {
            free(cwd);
            return absolute;
        }
        capacity *= 2;
    }
#ifdef _WIN32
    canonical_cwd = _fullpath(NULL, cwd, 0);
#else
    canonical_cwd = realpath(cwd, NULL);
#endif
    free(cwd);
    if (!canonical_cwd) return absolute;
    absolute_length = strlen(absolute);
    cwd_length = strlen(canonical_cwd);
    if (absolute_length <= cwd_length) {
        free(canonical_cwd);
        return absolute;
    }
    offset = cwd_length;
    if (cwd_length && canonical_cwd[cwd_length - 1] != '/' && canonical_cwd[cwd_length - 1] != '\\') {
        if (absolute[offset] != '/' && absolute[offset] != '\\') {
            free(canonical_cwd);
            return absolute;
        }
        ++offset;
    }
#ifdef _WIN32
    if (_strnicmp(absolute, canonical_cwd, cwd_length) != 0)
#else
    if (strncmp(absolute, canonical_cwd, cwd_length) != 0)
#endif
    {
        free(canonical_cwd);
        return absolute;
    }
    free(canonical_cwd);
    if (!absolute[offset]) return absolute;
    relative = yx_strdup(absolute + offset);
    if (!relative) return absolute;
    free(absolute);
    return relative;
}

/* The public C API takes a NUL-terminated source. File literals also allow
 * NUL bytes. Keep escapes inside regexps and invalid quoted-string escapes
 * distinct when making those bytes safe for the NUL-terminated parser.
 * `escape_offsets`/`escape_count` (optional) receive the position and kind
 * of every escape written for a NUL, for the diagnostic NUL registry. */
static char *yx_escape_source_nuls(const uint8_t *source, size_t length, yx_nul_escape **escape_offsets, size_t *escape_count)
{
    size_t nuls = 0, used = 0, escapes = 0;
    bool quoted = false, regexp = false, regexp_class = false;
    bool line_comment = false, block_comment = false;
    char *escaped;
    yx_nul_escape *offsets = NULL;
    for (size_t i = 0; i < length; ++i)
        if (!source[i]) ++nuls;
    if (length == SIZE_MAX || nuls > (SIZE_MAX - length - 1) / 3) return NULL;
    escaped = (char *)malloc(length + nuls * 3 + 1);
    if (!escaped) return NULL;
    if (escape_offsets) {
        *escape_offsets = NULL;
        *escape_count = 0;
        if (nuls) {
            offsets = (yx_nul_escape *)malloc(nuls * sizeof(*offsets));
            if (!offsets) {
                free(escaped);
                return NULL;
            }
        }
    }
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = source[i];
        if (line_comment) {
            if (byte == '\n') line_comment = false;
        } else if (block_comment) {
            if (byte == '*' && i + 1 < length && source[i + 1] == '/') {
                escaped[used++] = (char)byte;
                escaped[used++] = (char)source[++i];
                block_comment = false;
                continue;
            }
        } else if (quoted || regexp) {
            if (byte == '\\' && i + 1 < length) {
                if (!source[i + 1]) {
                    if (quoted) {
                        /* This is an invalid escape, not a literal NUL.
                         * A control picture keeps it invalid and visible. */
                        if (offsets) {
                            offsets[escapes].offset = used;
                            offsets[escapes++].kind = YX_NUL_STRING_ESCAPE;
                        }
                        escaped[used++] = '\\';
                        memcpy(escaped + used, "\xe2\x90\x80", 3);
                        used += 3;
                    } else {
                        /* Escaping NUL is permitted by the regexp parser. */
                        if (offsets) {
                            offsets[escapes].offset = used;
                            offsets[escapes++].kind = YX_NUL_REGEXP_ESCAPE;
                        }
                        memcpy(escaped + used, "\\x00", 4);
                        used += 4;
                    }
                    ++i;
                    continue;
                }
                escaped[used++] = (char)byte;
                escaped[used++] = (char)source[++i];
                continue;
            }
            if (quoted && byte == '"') quoted = false;
            else if (regexp) {
                if (byte == '[') regexp_class = true;
                else if (byte == ']') regexp_class = false;
                else if (byte == '/' && !regexp_class) regexp = false;
            }
        } else if (byte == '"') {
            quoted = true;
        } else if (byte == '/' && i + 1 < length) {
            if (source[i + 1] == '/' || source[i + 1] == '*') {
                line_comment = source[i + 1] == '/';
                block_comment = !line_comment;
                escaped[used++] = (char)byte;
                escaped[used++] = (char)source[++i];
                continue;
            }
            regexp = true;
            regexp_class = false;
        }
        if (!byte) {
            if (offsets) {
                offsets[escapes].offset = used;
                offsets[escapes++].kind = YX_NUL_BARE;
            }
            memcpy(escaped + used, "\\x00", 4);
            used += 4;
        } else {
            escaped[used++] = (char)byte;
        }
    }
    escaped[used] = '\0';
    if (escape_offsets) {
        *escape_offsets = offsets;
        *escape_count = escapes;
    } else {
        free(offsets);
    }
    return escaped;
}

YRX_RESULT yx_compiler_add_source_bytes(YRX_COMPILER *compiler, const uint8_t *source, size_t length, const char *origin)
{
    char *escaped;
    yx_nul_escape *offsets;
    size_t offset_count;
    yx_nul_escape_entry entry;
    YRX_RESULT result;
    if (!source) return yx_null_argument("src");
    if (!compiler) return yx_null_argument("compiler");
    escaped = yx_escape_source_nuls(source, length, &offsets, &offset_count);
    if (!escaped) return yx_fail(YRX_SYNTAX_ERROR, "out of memory");
    yx_nul_escape_register(compiler, &entry, escaped, offsets, offset_count);
    result = yrx_compiler_add_source_with_origin(compiler, escaped, origin);
    yx_nul_escape_unregister(compiler, &entry);
    free(escaped);
    return result;
}

static bool yx_read_include(const char *path, char **source, yx_nul_escape **escape_offsets, size_t *escape_count)
{
    xx_io_device *file = xx_io_file_open(path, "rb");
    char *bytes = NULL;
    size_t used = 0, capacity = 0;
    bool success = false;
    *source = NULL;
    if (escape_offsets) {
        *escape_offsets = NULL;
        *escape_count = 0;
    }
    if (!file) return false;
    for (;;) {
        ssize_t count;
        if (used == capacity) {
            size_t next = capacity ? capacity * 2 : 4096;
            char *grown;
            if (next <= capacity || next == SIZE_MAX) break;
            grown = (char *)realloc(bytes, next + 1);
            if (!grown) break;
            bytes = grown;
            capacity = next;
        }
        count = xx_io_read(file, bytes + used, capacity - used);
        if (count < 0 || (size_t)count > capacity - used) break;
        if (!count) {
            bytes[used] = '\0';
            success = true;
            break;
        }
        used += (size_t)count;
    }
    if (xx_io_close(file) != 0) success = false;
    if (!success) {
        free(bytes);
        return false;
    }
    *source = yx_escape_source_nuls((const uint8_t *)bytes, used, escape_offsets, escape_count);
    free(bytes);
    if (!*source) return false;
    return true;
}

/* Why Rust's fs::read of path.canonicalize() fails for `path`, as
 * Compiler::read_included_file sees it: 0 when the file can be opened,
 * else the operating system's error code. ERROR_FILE_NOT_FOUND and
 * ERROR_PATH_NOT_FOUND (ENOENT elsewhere) are ErrorKind::NotFound. */
static unsigned long yx_include_open_error(const char *path)
{
#ifdef _WIN32
    int length = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    unsigned long error = 0;
    wchar_t *wide;
    HANDLE handle;
    if (length <= 0) return ERROR_INVALID_NAME;
    wide = (wchar_t *)malloc((size_t)length * sizeof(*wide));
    if (!wide) return ERROR_NOT_ENOUGH_MEMORY;
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, length);
    /* canonicalize() opens the path itself, directories included. */
    handle = CreateFileW(wide, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
    } else {
        CloseHandle(handle);
        /* fs::read() opens it for reading, which a directory refuses. */
        handle = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (handle == INVALID_HANDLE_VALUE) error = GetLastError();
        else CloseHandle(handle);
    }
    free(wide);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return 0;
    return error;
#else
    char *resolved = realpath(path, NULL);
    int descriptor;
    unsigned long error = 0;
    if (!resolved) return errno == ENOENT ? 0 : (unsigned long)errno;
    descriptor = open(resolved, O_RDONLY);
    if (descriptor < 0) {
        error = errno == ENOENT ? 0 : (unsigned long)errno;
    } else {
        char byte;
        if (read(descriptor, &byte, 1) < 0) error = (unsigned long)errno;
        close(descriptor);
    }
    free(resolved);
    return error;
#endif
}

static YRX_RESULT yx_include_error(YRX_COMPILER *compiler, const char *origin, size_t line, const char *message, const char *filename)
{
    snprintf(compiler->error, sizeof(compiler->error), "%s:%zu: %s: %s", origin ? origin : "line", line, message, filename);
    return YRX_SYNTAX_ERROR;
}

static YRX_RESULT yx_include_not_found_error(YRX_COMPILER *compiler, const char *filename, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "include file not found";
    const char *suffix = "` not found in any of the include directories";
    size_t filename_size = strlen(filename);
    size_t suffix_size = strlen(suffix);
    char *label, *text, *diagnostic;
    if (filename_size > SIZE_MAX - suffix_size - 2) return YRX_SYNTAX_ERROR;
    label = (char *)malloc(filename_size + suffix_size + 2);
    if (!label) return YRX_SYNTAX_ERROR;
    snprintf(label, filename_size + suffix_size + 2, "`%s%s", filename, suffix);
    text = yx_diagnostic_text("error", "E043", title, label, source, origin, start, end, NULL);
    if (!text) {
        free(label);
        return YRX_SYNTAX_ERROR;
    }
    diagnostic = yx_diagnostic_json("IncludeNotFound", "E043", title, label, text, source, origin, start, end, NULL, "error");
    free(label);
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return YRX_SYNTAX_ERROR;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return YRX_SYNTAX_ERROR;
}

/* YRX_DISABLE_INCLUDES: E044 at the include statement. */
static YRX_RESULT yx_include_not_allowed_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "include statements not allowed";
    const char *label = "includes are disabled for this compilation";
    char *text = yx_diagnostic_text("error", "E044", title, label, source, origin, start, end, NULL), *diagnostic;
    if (!text) return YRX_SYNTAX_ERROR;
    diagnostic = yx_diagnostic_json("IncludeNotAllowed", "E044", title, label, text, source, origin, start, end, NULL, "error");
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return YRX_SYNTAX_ERROR;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return YRX_SYNTAX_ERROR;
}

static YRX_RESULT yx_include_circular_error(YRX_COMPILER *compiler, const char *source, const char *origin, size_t start, size_t end)
{
    const char *title = "circular include dependencies";
    const char *label = "include statement has circular dependencies";
    const char *heading = "include dependencies:\n";
    char *note, *raw_note, *text, *diagnostic;
    size_t capacity = strlen(heading) + 1, used, raw_used;
    size_t line = 1, gutter_digits = 1, indent;
    /* YARA-X stores each dependency indented by two spaces per level; the
     * renderer aligns the continuation lines with the text after
     * `= note: `, whose column depends on the line-number gutter. */
    {
        const char *ignored_line_start;
        size_t known = yx_source_text_length(source);
        line = yx_source_line_of(source, start < known ? start : known, &ignored_line_start);
    }
    for (size_t n = line; n >= 10; n /= 10) ++gutter_digits;
    indent = gutter_digits + 9;
    for (size_t i = 0; i < compiler->include_depth; ++i) {
        size_t path_length = strlen(compiler->include_stack[i]);
        size_t extra = indent + i * 2 + sizeof("↳ ") - 1 + path_length + 1;
        if (extra > SIZE_MAX - capacity) return YRX_SYNTAX_ERROR;
        capacity += extra;
    }
    note = (char *)malloc(capacity);
    raw_note = (char *)malloc(capacity);
    if (!note || !raw_note) {
        free(note);
        free(raw_note);
        return YRX_SYNTAX_ERROR;
    }
    used = (size_t)snprintf(note, capacity, "%s", heading);
    raw_used = (size_t)snprintf(raw_note, capacity, "%s", heading);
    for (size_t i = 0; i < compiler->include_depth; ++i) {
        int count =
            snprintf(note + used, capacity - used, "%*s↳ %s%s", (int)(indent + i * 2), "", compiler->include_stack[i], i + 1 < compiler->include_depth ? "\n" : "");
        int raw_count =
            snprintf(raw_note + raw_used, capacity - raw_used, "%*s↳ %s%s", (int)(i * 2), "", compiler->include_stack[i], i + 1 < compiler->include_depth ? "\n" : "");
        if (count < 0 || (size_t)count >= capacity - used || raw_count < 0 || (size_t)raw_count >= capacity - raw_used) {
            free(note);
            free(raw_note);
            return YRX_SYNTAX_ERROR;
        }
        used += (size_t)count;
        raw_used += (size_t)raw_count;
    }
    text = yx_diagnostic_text("error", "E046", title, label, source, origin, start, end, note);
    free(note);
    if (!text) {
        free(raw_note);
        return YRX_SYNTAX_ERROR;
    }
    diagnostic = yx_diagnostic_json("CircularIncludes", "E046", title, label, text, source, origin, start, end, raw_note, "error");
    free(raw_note);
    if (!yx_compiler_append_error_diagnostic(compiler, diagnostic)) {
        free(text);
        return YRX_SYNTAX_ERROR;
    }
    snprintf(compiler->error, sizeof(compiler->error), "%s", text);
    free(text);
    return YRX_SYNTAX_ERROR;
}

YRX_RESULT yx_include_source(YRX_COMPILER *compiler, const char *filename, size_t filename_length, const char *original_source, const char *origin, size_t include_line,
                             size_t include_start, size_t include_end)
{
    char *path = NULL, *source = NULL;
    yx_nul_escape *escape_offsets = NULL;
    size_t escape_count = 0;
    yx_nul_escape_entry escape_entry;
    char **grown;
    size_t i;
    YRX_RESULT result;
    if (!compiler || !filename) return YRX_INVALID_ARGUMENT;
    if (compiler->flags & YRX_DISABLE_INCLUDES) return yx_include_not_allowed_error(compiler, original_source, origin, include_start, include_end);
    if (memchr(filename, '\0', filename_length) || !yx_valid_utf8(filename))
        return yx_include_error(compiler, origin, include_line, "invalid include filename", filename);
    /* YARA-X has no include nesting limit; the stack grows below. */

    if (compiler->include_depth && !yx_absolute_path(filename)) {
        char *directory = yx_include_parent(compiler->include_stack[compiler->include_depth - 1]);
        if (!directory) return yx_include_error(compiler, origin, include_line, "out of memory resolving include", filename);
        path = yx_join_include_path(directory, filename);
        free(directory);
        if (!path) return yx_include_error(compiler, origin, include_line, "out of memory resolving include", filename);
        if (!yx_read_include(path, &source, &escape_offsets, &escape_count)) {
            free(path);
            path = NULL;
        }
    }
    if (!source && compiler->include_dir_count) {
        for (i = 0; i < compiler->include_dir_count; ++i) {
            path = yx_join_include_path(compiler->include_dirs[i], filename);
            if (!path) return yx_include_error(compiler, origin, include_line, "out of memory resolving include", filename);
            if (yx_read_include(path, &source, &escape_offsets, &escape_count)) break;
            free(path);
            path = NULL;
        }
    }
    if (!source && !compiler->include_dir_count) {
        path = yx_strdup(filename);
        if (!path) return yx_include_error(compiler, origin, include_line, "out of memory resolving include", filename);
        if (!yx_read_include(path, &source, &escape_offsets, &escape_count)) {
            /* Without include directories, a file that exists but cannot
             * be read is E042 with the system's message; only a missing
             * one is E043. */
            unsigned long error = yx_include_open_error(path);
            free(path);
            path = NULL;
            if (error) {
                if (!yx_compiler_include_error(compiler, original_source, origin, include_start, include_end, yx_os_error_text(error)))
                    snprintf(compiler->error, sizeof(compiler->error), "out of memory recording include error");
                return YRX_SYNTAX_ERROR;
            }
        }
    }
    if (!source) return yx_include_not_found_error(compiler, filename, original_source, origin, include_start, include_end);
    {
        char *canonical = yx_include_canonical_path(path);
        if (canonical) {
            free(path);
            path = canonical;
        }
    }
    for (i = 0; i < compiler->include_depth; ++i) {
        if (strcmp(compiler->include_stack[i], path) == 0) {
            free(source);
            free(escape_offsets);
            free(path);
            return yx_include_circular_error(compiler, original_source, origin, include_start, include_end);
        }
    }
    if (compiler->include_depth >= SIZE_MAX / sizeof(*grown)) {
        free(source);
        free(escape_offsets);
        free(path);
        return yx_include_error(compiler, origin, include_line, "include nesting limit exceeded", filename);
    }
    grown = (char **)realloc(compiler->include_stack, (compiler->include_depth + 1) * sizeof(*grown));
    if (!grown) {
        free(source);
        free(escape_offsets);
        free(path);
        return yx_include_error(compiler, origin, include_line, "out of memory resolving include", filename);
    }
    compiler->include_stack = grown;
    compiler->include_stack[compiler->include_depth++] = path;
    {
        /* YARA-X reports an included file under its path with every
         * backslash turned into a slash; the include stack (resolution and
         * the circular-include note) keeps the native spelling. */
        char *origin_path = yx_strdup(path);
        if (origin_path)
            for (char *at = origin_path; *at; ++at)
                if (*at == '\\') *at = '/';
        yx_nul_escape_register(compiler, &escape_entry, source, escape_offsets, escape_count);
        escape_offsets = NULL;
        {
            /* One scan for the suppression comments of this source. */
            yx_suppression_scope suppressions;
            yx_suppression_scope_begin(&suppressions, (const uint8_t *)source, yx_source_text_length(source));
            result = yx_parse_source(compiler, source, origin_path ? origin_path : path);
            yx_suppression_scope_end(&suppressions);
        }
        yx_nul_escape_unregister(compiler, &escape_entry);
        free(origin_path);
    }
    --compiler->include_depth;
    free(compiler->include_stack[compiler->include_depth]);
    compiler->include_stack[compiler->include_depth] = NULL;
    free(source);
    return result;
}

static void yx_free_global_object(yx_global_object *object);
static yx_global_object *yx_copy_global_object(const yx_global_object *source);
static bool yx_global_objects_same_type(const yx_global_object *a, const yx_global_object *b);

static void yx_free_global_array(yx_global_array *array)
{
    if (!array) return;
    if (array->element_type == YX_GLOBAL_STR)
        for (size_t i = 0; i < array->count; ++i) free(array->items[i].string.data);
    if (array->element_type == YX_GLOBAL_STRUCT)
        for (size_t i = 0; i < array->count; ++i) yx_free_global_object(array->items[i].object);
    free(array->items);
    free(array);
}

static yx_global_array *yx_copy_global_array(const yx_global_array *source)
{
    yx_global_array *copy;
    if (!source || source->count > SIZE_MAX / sizeof(*source->items)) return NULL;
    copy = (yx_global_array *)calloc(1, sizeof(*copy));
    if (!copy) return NULL;
    copy->element_type = source->element_type;
    if (source->count) {
        copy->items = (yx_global_scalar_value *)calloc(source->count, sizeof(*copy->items));
        if (!copy->items) {
            free(copy);
            return NULL;
        }
    }
    copy->count = source->count;
    for (size_t i = 0; i < source->count; ++i) {
        if (source->element_type == YX_GLOBAL_STR) {
            copy->items[i].string.length = source->items[i].string.length;
            copy->items[i].string.data = yx_copy_string_bytes(source->items[i].string.data, source->items[i].string.length);
            if (!copy->items[i].string.data) {
                yx_free_global_array(copy);
                return NULL;
            }
        } else if (source->element_type == YX_GLOBAL_STRUCT) {
            copy->items[i].object = yx_copy_global_object(source->items[i].object);
            if (!copy->items[i].object) {
                yx_free_global_array(copy);
                return NULL;
            }
        } else {
            copy->items[i] = source->items[i];
        }
    }
    return copy;
}

static void yx_free_global_object(yx_global_object *object)
{
    if (!object) return;
    for (size_t i = 0; i < object->count; ++i) {
        free(object->fields[i].name);
        if (object->fields[i].type == YX_GLOBAL_STR) free(object->fields[i].value.string.data);
        else if (object->fields[i].type == YX_GLOBAL_ARRAY) yx_free_global_array(object->fields[i].value.array);
        else if (object->fields[i].type == YX_GLOBAL_STRUCT) yx_free_global_object(object->fields[i].value.object);
    }
    free(object->fields);
    free(object);
}

static yx_global_object *yx_copy_global_object(const yx_global_object *source)
{
    yx_global_object *copy;
    if (!source || source->count > SIZE_MAX / sizeof(*source->fields)) return NULL;
    copy = (yx_global_object *)calloc(1, sizeof(*copy));
    if (!copy) return NULL;
    if (source->count) {
        copy->fields = (yx_global_field *)calloc(source->count, sizeof(*copy->fields));
        if (!copy->fields) {
            free(copy);
            return NULL;
        }
    }
    copy->count = source->count;
    for (size_t i = 0; i < source->count; ++i) {
        copy->fields[i].name = yx_strdup(source->fields[i].name);
        copy->fields[i].type = source->fields[i].type;
        if (!copy->fields[i].name) {
            yx_free_global_object(copy);
            return NULL;
        }
        if (source->fields[i].type == YX_GLOBAL_STR) {
            copy->fields[i].value.string.length = source->fields[i].value.string.length;
            copy->fields[i].value.string.data = yx_copy_string_bytes(source->fields[i].value.string.data, source->fields[i].value.string.length);
            if (!copy->fields[i].value.string.data) {
                yx_free_global_object(copy);
                return NULL;
            }
        } else if (source->fields[i].type == YX_GLOBAL_ARRAY) {
            copy->fields[i].value.array = yx_copy_global_array(source->fields[i].value.array);
            if (!copy->fields[i].value.array) {
                yx_free_global_object(copy);
                return NULL;
            }
        } else if (source->fields[i].type == YX_GLOBAL_STRUCT && source->fields[i].value.object) {
            copy->fields[i].value.object = yx_copy_global_object(source->fields[i].value.object);
            if (!copy->fields[i].value.object) {
                yx_free_global_object(copy);
                return NULL;
            }
        } else {
            copy->fields[i].value = source->fields[i].value;
        }
    }
    return copy;
}

static bool yx_global_objects_same_type(const yx_global_object *a, const yx_global_object *b)
{
    if (!a || !b || a->count != b->count) return false;
    for (size_t i = 0; i < a->count; ++i)
        if (a->fields[i].type != b->fields[i].type || strcmp(a->fields[i].name, b->fields[i].name) != 0 ||
            (a->fields[i].type == YX_GLOBAL_STRUCT && !yx_global_objects_same_type(a->fields[i].value.object, b->fields[i].value.object)) ||
            (a->fields[i].type == YX_GLOBAL_ARRAY &&
             (a->fields[i].value.array->element_type != b->fields[i].value.array->element_type ||
              (a->fields[i].value.array->element_type == YX_GLOBAL_STRUCT &&
               ((!a->fields[i].value.array->count || !b->fields[i].value.array->count)
                    ? a->fields[i].value.array->count != b->fields[i].value.array->count
                    : !yx_global_objects_same_type(a->fields[i].value.array->items[0].object, b->fields[i].value.array->items[0].object))))))
            return false;
    return true;
}

static void yx_clear_global(yx_global *global)
{
    free(global->name);
    if (global->type == YX_GLOBAL_STR) free(global->value.string.data);
    else if (global->type == YX_GLOBAL_ARRAY) yx_free_global_array(global->value.array);
    else if (global->type == YX_GLOBAL_STRUCT) yx_free_global_object(global->value.object);
}

static void yx_free_globals(yx_global *globals, size_t count)
{
    size_t i;
    if (!globals) return;
    for (i = 0; i < count; ++i) yx_clear_global(&globals[i]);
    free(globals);
}

static bool yx_copy_globals(const yx_global *source, size_t count, yx_global **out)
{
    yx_global *copy;
    size_t i;
    *out = NULL;
    if (!count) return true;
    copy = (yx_global *)calloc(count, sizeof(*copy));
    if (!copy) return false;
    for (i = 0; i < count; ++i) {
        copy[i].type = source[i].type;
        if (source[i].type != YX_GLOBAL_STR && source[i].type != YX_GLOBAL_ARRAY && source[i].type != YX_GLOBAL_STRUCT) copy[i].value = source[i].value;
        copy[i].name = yx_strdup(source[i].name);
        if (!copy[i].name) {
            yx_free_globals(copy, count);
            return false;
        }
        if (copy[i].type == YX_GLOBAL_STR) {
            copy[i].value.string.length = source[i].value.string.length;
            copy[i].value.string.data = yx_copy_string_bytes(source[i].value.string.data, source[i].value.string.length);
            if (!copy[i].value.string.data) {
                yx_free_globals(copy, count);
                return false;
            }
        } else if (copy[i].type == YX_GLOBAL_ARRAY) {
            copy[i].value.array = yx_copy_global_array(source[i].value.array);
            if (!copy[i].value.array) {
                yx_free_globals(copy, count);
                return false;
            }
        } else if (copy[i].type == YX_GLOBAL_STRUCT) {
            copy[i].value.object = yx_copy_global_object(source[i].value.object);
            if (!copy[i].value.object) {
                yx_free_globals(copy, count);
                return false;
            }
        }
    }
    *out = copy;
    return true;
}

static yx_global *yx_find_global(yx_global *globals, size_t count, const char *name)
{
    size_t i;
    for (i = 0; i < count; ++i)
        if (strcmp(globals[i].name, name) == 0) return &globals[i];
    return NULL;
}

static YRX_RESULT yx_define_global(YRX_COMPILER *compiler, const char *name, yx_global_type type, const void *value)
{
    YRX_RULES *rules;
    yx_global global = {0}, *grown, *existing;
    if (!compiler) return yx_null_argument("compiler");
    if (!name) return yx_null_argument("ident");
    if (!value) return yx_null_argument("value");
    if (!yx_valid_utf8(name)) return yx_compiler_invalid_utf8(name);
    if (!yx_valid_json_field_name(name)) {
        char message[512];
        return yx_fail_format(YRX_VARIABLE_ERROR, "invalid identifier `%s`", name);
    }
    rules = compiler->rules;
    existing = yx_find_global(rules->globals, rules->global_count, name);
    global.name = yx_strdup(name);
    if (!global.name) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    global.type = type;
    switch (type) {
        case YX_GLOBAL_BOOL: global.value.boolean = *(const bool *)value; break;
        case YX_GLOBAL_INT: global.value.integer = *(const int64_t *)value; break;
        case YX_GLOBAL_FLOAT: global.value.floating = *(const double *)value; break;
        case YX_GLOBAL_STR:
            global.value.string.length = ((const yx_global_string *)value)->length;
            global.value.string.data = yx_copy_string_bytes(((const yx_global_string *)value)->data, global.value.string.length);
            if (!global.value.string.data) {
                free(global.name);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            break;
        case YX_GLOBAL_ARRAY:
            global.value.array = yx_copy_global_array((const yx_global_array *)value);
            if (!global.value.array) {
                free(global.name);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            break;
        case YX_GLOBAL_STRUCT:
            global.value.object = yx_copy_global_object((const yx_global_object *)value);
            if (!global.value.object) {
                free(global.name);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            break;
    }
    if (existing) {
        char message[512];
        /* YARA-X updates the runtime field before reporting AlreadyExists,
         * while its compiler symbol still contains the first declaration. */
        if (!yx_find_global(compiler->redefined_global_symbols, compiler->redefined_global_symbol_count, name)) {
            yx_global *saved = NULL;
            size_t count = compiler->redefined_global_symbol_count;
            if (count == SIZE_MAX / sizeof(*grown) || !yx_copy_globals(existing, 1, &saved)) {
                yx_clear_global(&global);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            grown = (yx_global *)realloc(compiler->redefined_global_symbols, (count + 1) * sizeof(*grown));
            if (!grown) {
                yx_free_globals(saved, 1);
                yx_clear_global(&global);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            compiler->redefined_global_symbols = grown;
            grown[count] = saved[0];
            compiler->redefined_global_symbol_count = count + 1;
            free(saved);
        }
        yx_clear_global(existing);
        *existing = global;
        return yx_fail_format(YRX_VARIABLE_ERROR, "variable `%s` already exists", name);
    }
    if (rules->global_count == SIZE_MAX / sizeof(*grown)) {
        free(global.name);
        if (type == YX_GLOBAL_STR) free(global.value.string.data);
        else if (type == YX_GLOBAL_ARRAY) yx_free_global_array(global.value.array);
        else if (type == YX_GLOBAL_STRUCT) yx_free_global_object(global.value.object);
        return yx_fail(YRX_VARIABLE_ERROR, "too many global variables");
    }
    grown = (yx_global *)realloc(rules->globals, (rules->global_count + 1) * sizeof(*grown));
    if (!grown) {
        free(global.name);
        if (type == YX_GLOBAL_STR) free(global.value.string.data);
        else if (type == YX_GLOBAL_ARRAY) yx_free_global_array(global.value.array);
        else if (type == YX_GLOBAL_STRUCT) yx_free_global_object(global.value.object);
        return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    }
    rules->globals = grown;
    rules->globals[rules->global_count++] = global;
    return yx_ok();
}

static const char *yx_global_type_label(yx_global_type type)
{
    switch (type) {
        case YX_GLOBAL_BOOL: return "boolean";
        case YX_GLOBAL_INT: return "integer";
        case YX_GLOBAL_FLOAT: return "float";
        case YX_GLOBAL_STR: return "string";
        case YX_GLOBAL_ARRAY: return "array";
        case YX_GLOBAL_STRUCT: return "struct";
    }
    return "unknown";
}

static YRX_RESULT yx_global_type_mismatch(const char *name, yx_global_type expected, yx_global_type actual)
{
    return yx_fail_format(YRX_VARIABLE_ERROR, "invalid type for `%s`, expecting `%s`, got `%s", name, yx_global_type_label(expected), yx_global_type_label(actual));
}

static YRX_RESULT yx_set_global(YRX_SCANNER *scanner, const char *name, yx_global_type type, const void *value)
{
    yx_global *global;
    if (!scanner) return yx_null_argument("scanner");
    if (!name || !value) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(name)) return yx_scanner_invalid_utf8(name, strlen(name));
    if (type == YX_GLOBAL_STR && !yx_valid_utf8_bytes(((const yx_global_string *)value)->data, ((const yx_global_string *)value)->length))
        return yx_scanner_invalid_utf8(((const yx_global_string *)value)->data, ((const yx_global_string *)value)->length);
    global = yx_find_global(scanner->globals, scanner->global_count, name);
    if (!global) {
        char message[512];
        return yx_fail_format(YRX_VARIABLE_ERROR, "variable `%s` not defined", name);
    }
    if (global->type != type) return yx_global_type_mismatch(name, global->type, type);
    if (type == YX_GLOBAL_ARRAY && global->value.array->element_type != ((const yx_global_array *)value)->element_type)
        return yx_global_type_mismatch(name, global->type, type);
    if (type == YX_GLOBAL_ARRAY && global->value.array->element_type == YX_GLOBAL_STRUCT &&
        ((!global->value.array->count || !((const yx_global_array *)value)->count)
             ? global->value.array->count != ((const yx_global_array *)value)->count
             : !yx_global_objects_same_type(global->value.array->items[0].object, ((const yx_global_array *)value)->items[0].object)))
        return yx_global_type_mismatch(name, global->type, type);
    if (type == YX_GLOBAL_STRUCT && !yx_global_objects_same_type(global->value.object, (const yx_global_object *)value)) {
        return yx_fail_format(YRX_VARIABLE_ERROR, "invalid type for `%s`, expecting `struct`, got `struct", name);
    }
    switch (type) {
        case YX_GLOBAL_BOOL: global->value.boolean = *(const bool *)value; break;
        case YX_GLOBAL_INT: global->value.integer = *(const int64_t *)value; break;
        case YX_GLOBAL_FLOAT: global->value.floating = *(const double *)value; break;
        case YX_GLOBAL_STR: {
            const yx_global_string *input = (const yx_global_string *)value;
            char *copy = yx_copy_string_bytes(input->data, input->length);
            if (!copy) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            free(global->value.string.data);
            global->value.string.data = copy;
            global->value.string.length = input->length;
            break;
        }
        case YX_GLOBAL_ARRAY: {
            yx_global_array *copy = yx_copy_global_array((const yx_global_array *)value);
            if (!copy) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            yx_free_global_array(global->value.array);
            global->value.array = copy;
            break;
        }
        case YX_GLOBAL_STRUCT: {
            yx_global_object *copy = yx_copy_global_object((const yx_global_object *)value);
            if (!copy) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            yx_free_global_object(global->value.object);
            global->value.object = copy;
            break;
        }
    }
    return yx_ok();
}

typedef struct yx_json_scalar {
    yx_global_type type;
    union {
        bool boolean;
        int64_t integer;
        double floating;
        yx_global_string string;
    } value;
} yx_json_scalar;

static bool yx_json_at_end(const xx_json *json)
{
    size_t position = json->position;
    while (position < json->size && (json->data[position] == ' ' || json->data[position] == '\t' || json->data[position] == '\n' || json->data[position] == '\r'))
        ++position;
    return position == json->size;
}

/* Object keys are C identifiers, so an embedded NUL is invalid there. */
static bool yx_json_string_has_nul(const char *text, size_t size)
{
    size_t i;
    for (i = 1; i < size; ++i) {
        if (text[i] == '"') break;
        if (text[i] != '\\' || ++i >= size) continue;
        if (text[i] == 'u' && i + 4 < size && text[i + 1] == '0' && text[i + 2] == '0' && text[i + 3] == '0' && text[i + 4] == '0') return true;
    }
    return false;
}

/* xxfclib decodes JSON strings but exposes only a NUL-terminated buffer.
 * Derive the decoded byte count from the already validated source token. */
static size_t yx_json_decoded_string_length(const uint8_t *text, size_t start, size_t end)
{
    size_t length = 0;
    for (size_t i = start + 1; i + 1 < end;) {
        if (text[i] != '\\') {
            ++i;
            ++length;
        } else {
            ++i;
            if (text[i] != 'u') {
                ++i;
                ++length;
            } else {
                unsigned code = 0;
                ++i;
                for (unsigned digit = 0; digit < 4; ++digit) {
                    unsigned ch = text[i++];
                    code = (code << 4) | (ch <= '9' ? ch - '0' : (ch <= 'F' ? ch - 'A' + 10 : ch - 'a' + 10));
                }
                if (code >= 0xd800 && code <= 0xdbff) {
                    i += 6; /* Validated low surrogate. */
                    length += 4;
                } else {
                    length += code < 0x80 ? 1 : code < 0x800 ? 2 : 3;
                }
            }
        }
    }
    return length;
}

typedef enum yx_json_semantic_kind {
    YX_JSON_BOOL,
    YX_JSON_INT,
    YX_JSON_FLOAT,
    YX_JSON_STRING,
    YX_JSON_OBJECT,
    YX_JSON_ARRAY,
    YX_JSON_NULL_ERROR,
    YX_JSON_ARRAY_ERROR,
    YX_JSON_IDENTIFIER_ERROR,
    YX_JSON_RANGE_ERROR,
    YX_JSON_SYNTAX_ERROR
} yx_json_semantic_kind;

/* The reference C API accepts 127 nested JSON object levels and rejects the
 * 128th with YRX_INVALID_ARGUMENT. xxfclib's parser allows more, so enforce
 * the reference limit during the semantic pass. */
enum {
    YX_JSON_COMPAT_MAX_DEPTH = 128
};

static bool yx_json_key_maybe_valid(const char *name)
{
    return yx_valid_json_field_name(name);
}

static yx_json_semantic_kind yx_json_number_kind(xx_json *json)
{
    const char *start, *cursor, *end;
    bool floating = false;
    char *parsed_end;
    unsigned long long unsigned_value;
    long long signed_value;
    xx_json_peek(json);
    start = (const char *)json->data + json->position;
    cursor = start;
    if (*cursor == '-') ++cursor;
    if (*cursor == '0') {
        ++cursor;
        if (*cursor >= '0' && *cursor <= '9') return YX_JSON_SYNTAX_ERROR;
    } else if (*cursor >= '1' && *cursor <= '9') {
        do {
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
    } else {
        return YX_JSON_SYNTAX_ERROR;
    }
    if (*cursor == '.') {
        floating = true;
        ++cursor;
        if (*cursor < '0' || *cursor > '9') return YX_JSON_SYNTAX_ERROR;
        do {
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
    }
    if (*cursor == 'e' || *cursor == 'E') {
        floating = true;
        ++cursor;
        if (*cursor == '+' || *cursor == '-') ++cursor;
        if (*cursor < '0' || *cursor > '9') return YX_JSON_SYNTAX_ERROR;
        do {
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
    }
    end = cursor;
    if (!xx_json_skip(json) || (const char *)json->data + json->position != end) return YX_JSON_SYNTAX_ERROR;
    if (floating) {
        double value = strtod(start, &parsed_end);
        return parsed_end == end && isfinite(value) ? YX_JSON_FLOAT : YX_JSON_SYNTAX_ERROR;
    }
    errno = 0;
    if (*start == '-') {
        signed_value = strtoll(start, &parsed_end, 10);
        (void)signed_value;
        if (parsed_end != end) return YX_JSON_SYNTAX_ERROR;
        if (errno == ERANGE) {
            double value = strtod(start, &parsed_end);
            return parsed_end == end && isfinite(value) ? YX_JSON_FLOAT : YX_JSON_SYNTAX_ERROR;
        }
        return YX_JSON_INT;
    }
    unsigned_value = strtoull(start, &parsed_end, 10);
    if (parsed_end != end) return YX_JSON_SYNTAX_ERROR;
    if (errno == ERANGE) {
        double value = strtod(start, &parsed_end);
        return parsed_end == end && isfinite(value) ? YX_JSON_FLOAT : YX_JSON_SYNTAX_ERROR;
    }
    return unsigned_value > INT64_MAX ? YX_JSON_RANGE_ERROR : YX_JSON_INT;
}

static yx_json_semantic_kind yx_json_container_kind(xx_json *json, unsigned depth, char **invalid_key, bool allow_arbitrary_keys)
{
    xx_json_type_t type = xx_json_peek(json);
    if (depth >= YX_JSON_COMPAT_MAX_DEPTH) return YX_JSON_SYNTAX_ERROR;
    if (type == XX_JSON_TYPE_BOOL) {
        return xx_json_bool(json, NULL) ? YX_JSON_BOOL : YX_JSON_SYNTAX_ERROR;
    }
    if (type == XX_JSON_TYPE_STRING) {
        return xx_json_skip(json) ? YX_JSON_STRING : YX_JSON_SYNTAX_ERROR;
    }
    if (type == XX_JSON_TYPE_NUMBER) return yx_json_number_kind(json);
    if (type == XX_JSON_TYPE_NULL) {
        return xx_json_null(json) ? YX_JSON_NULL_ERROR : YX_JSON_SYNTAX_ERROR;
    }
    if (type == XX_JSON_TYPE_OBJECT) {
        if (!xx_json_object_begin(json)) return YX_JSON_SYNTAX_ERROR;
        if (!xx_json_object_empty(json)) {
            for (;;) {
                char *key = NULL;
                yx_json_semantic_kind member;
                size_t key_start;
                xx_json_peek(json);
                key_start = json->position;
                if (!xx_json_object_key(json, &key)) return YX_JSON_SYNTAX_ERROR;
                if (!allow_arbitrary_keys &&
                    (yx_json_string_has_nul((const char *)json->data + key_start, json->position - key_start) || !yx_json_key_maybe_valid(key))) {
                    if (invalid_key) {
                        size_t length = yx_json_decoded_string_length(json->data, key_start, json->position);
                        size_t used = 0;
                        /* Rust removes interior NULs from last_error without
                         * dropping the rest of the invalid identifier. */
                        for (size_t i = 0; i < length; ++i)
                            if (key[i]) key[used++] = key[i];
                        key[used] = '\0';
                        *invalid_key = key;
                    } else xx_str_free(key);
                    return YX_JSON_IDENTIFIER_ERROR;
                }
                xx_str_free(key);
                member = yx_json_container_kind(json, depth + 1, invalid_key, false);
                if (member >= YX_JSON_NULL_ERROR) return member;
                if (!xx_json_more(json)) break;
            }
        }
        return xx_json_object_end(json) ? YX_JSON_OBJECT : YX_JSON_SYNTAX_ERROR;
    }
    if (type == XX_JSON_TYPE_ARRAY) {
        yx_json_semantic_kind array_kind = YX_JSON_NULL_ERROR;
        if (!xx_json_array_begin(json)) return YX_JSON_SYNTAX_ERROR;
        if (xx_json_array_empty(json)) return YX_JSON_ARRAY_ERROR;
        for (;;) {
            xx_json_type_t item_type = xx_json_peek(json);
            if (item_type == XX_JSON_TYPE_ARRAY) return YX_JSON_ARRAY_ERROR;
            if (array_kind != YX_JSON_NULL_ERROR && item_type == XX_JSON_TYPE_OBJECT && array_kind != YX_JSON_OBJECT) return YX_JSON_ARRAY_ERROR;
            yx_json_semantic_kind item = yx_json_container_kind(json, depth + 1, invalid_key, item_type == XX_JSON_TYPE_OBJECT);
            if (item == YX_JSON_SYNTAX_ERROR) return item;
            if (item == YX_JSON_IDENTIFIER_ERROR) return item;
            if (item == YX_JSON_NULL_ERROR && item_type != XX_JSON_TYPE_NULL) return item;
            if (item == YX_JSON_RANGE_ERROR || item == YX_JSON_NULL_ERROR || item == YX_JSON_ARRAY_ERROR || item == YX_JSON_ARRAY) return YX_JSON_ARRAY_ERROR;
            if (array_kind == YX_JSON_NULL_ERROR) array_kind = item;
            else if (item != array_kind && !(array_kind == YX_JSON_FLOAT && item == YX_JSON_INT)) return YX_JSON_ARRAY_ERROR;
            if (!xx_json_more(json)) break;
        }
        return xx_json_array_end(json) ? YX_JSON_ARRAY : YX_JSON_SYNTAX_ERROR;
    }
    return YX_JSON_SYNTAX_ERROR;
}

/* serde_json checks the complete input before converting JSON to typed
 * globals. Enforce its container depth before semantic array/key failures. */
static bool yx_json_depth_compatible(const char *text)
{
    unsigned depth = 0;
    for (const char *at = text; *at; ++at) {
        if (*at == '"') {
            while (*++at && *at != '"')
                if (*at == '\\' && at[1]) ++at;
            if (!*at) break;
        } else if (*at == '{' || *at == '[') {
            if (++depth >= YX_JSON_COMPAT_MAX_DEPTH) return false;
        } else if ((*at == '}' || *at == ']') && depth) --depth;
    }
    return true;
}

/* serde_json syntax failures return INVALID_ARGUMENT without changing the
 * C API's last-error slot. Semantic failures below set their own message. */
static YRX_RESULT yx_parse_json_scalar(const char *text, yx_json_scalar *out)
{
    xx_json json;
    xx_json_type_t type;
    const char *cursor;
    const char *end;
    bool floating = false;

    if (!yx_valid_utf8(text)) return YRX_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    xx_json_init(&json, text, strlen(text));
    type = xx_json_peek(&json);
    if (type == XX_JSON_TYPE_STRING) {
        size_t start = json.position;
        if (!xx_json_string(&json, &out->value.string.data) || !yx_json_at_end(&json)) {
            xx_str_free(out->value.string.data);
            out->value.string.data = NULL;
            return YRX_INVALID_ARGUMENT;
        }
        out->value.string.length = yx_json_decoded_string_length(json.data, start, json.position);
        out->type = YX_GLOBAL_STR;
        return yx_ok();
    }
    if (type == XX_JSON_TYPE_BOOL) {
        if (!xx_json_bool(&json, &out->value.boolean) || !yx_json_at_end(&json)) return YRX_INVALID_ARGUMENT;
        out->type = YX_GLOBAL_BOOL;
        return yx_ok();
    }
    if (type == XX_JSON_TYPE_NULL) {
        if (!xx_json_null(&json) || !yx_json_at_end(&json)) return YRX_INVALID_ARGUMENT;
        return yx_fail(YRX_VARIABLE_ERROR, "null values are not accepted");
    }
    if (type == XX_JSON_TYPE_OBJECT || type == XX_JSON_TYPE_ARRAY) {
        yx_json_semantic_kind semantic;
        char *invalid_key = NULL;
        if (!xx_json_skip(&json) || !yx_json_at_end(&json) || !yx_json_depth_compatible(text)) return YRX_INVALID_ARGUMENT;
        xx_json_init(&json, text, strlen(text));
        semantic = yx_json_container_kind(&json, 0, &invalid_key, false);
        if (semantic == YX_JSON_NULL_ERROR) return yx_fail(YRX_VARIABLE_ERROR, "null values are not accepted");
        if (semantic == YX_JSON_ARRAY_ERROR) return yx_fail(YRX_VARIABLE_ERROR, "arrays can't be empty and all items must be non-null and the same type");
        if (semantic == YX_JSON_IDENTIFIER_ERROR) {
            if (invalid_key) {
                YRX_RESULT result = yx_fail_format(YRX_VARIABLE_ERROR, "invalid identifier `%s`", invalid_key);
                xx_str_free(invalid_key);
                return result;
            }
            return yx_fail(YRX_VARIABLE_ERROR, "invalid identifier in JSON object");
        }
        if (semantic == YX_JSON_RANGE_ERROR) return yx_fail(YRX_VARIABLE_ERROR, "integer value is out of range");
        if (semantic == YX_JSON_SYNTAX_ERROR || !yx_json_at_end(&json)) return YRX_INVALID_ARGUMENT;
        return yx_unsupported("JSON object and array globals");
    }
    if (type != XX_JSON_TYPE_NUMBER) return YRX_INVALID_ARGUMENT;

    cursor = text + json.position;
    if (*cursor == '-') ++cursor;
    if (*cursor == '0') {
        ++cursor;
        if (*cursor >= '0' && *cursor <= '9') return YRX_INVALID_ARGUMENT;
    } else if (*cursor >= '1' && *cursor <= '9') {
        do {
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
    } else {
        return YRX_INVALID_ARGUMENT;
    }
    if (*cursor == '.') {
        floating = true;
        ++cursor;
        if (*cursor < '0' || *cursor > '9') return YRX_INVALID_ARGUMENT;
        do {
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
    }
    if (*cursor == 'e' || *cursor == 'E') {
        floating = true;
        ++cursor;
        if (*cursor == '+' || *cursor == '-') ++cursor;
        if (*cursor < '0' || *cursor > '9') return YRX_INVALID_ARGUMENT;
        do {
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
    }
    end = cursor;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r') ++cursor;
    if (*cursor != '\0') return YRX_INVALID_ARGUMENT;
    errno = 0;
    if (floating) {
        char *parsed_end;
        out->value.floating = strtod(text + json.position, &parsed_end);
        if (parsed_end != end || !isfinite(out->value.floating)) return YRX_INVALID_ARGUMENT;
        out->type = YX_GLOBAL_FLOAT;
    } else {
        char *parsed_end;
        long long number = strtoll(text + json.position, &parsed_end, 10);
        if (parsed_end != end) return YRX_INVALID_ARGUMENT;
        if (errno == ERANGE) {
            const char *number_start = text + json.position;
            if (*number_start != '-') {
                char *unsigned_end;
                errno = 0;
                (void)strtoull(number_start, &unsigned_end, 10);
                if (unsigned_end != end) return YRX_INVALID_ARGUMENT;
                if (errno != ERANGE) return yx_fail(YRX_VARIABLE_ERROR, "integer value is out of range");
            }
            out->value.floating = strtod(number_start, &parsed_end);
            if (parsed_end != end || !isfinite(out->value.floating)) return YRX_INVALID_ARGUMENT;
            out->type = YX_GLOBAL_FLOAT;
            return yx_ok();
        }
        out->value.integer = (int64_t)number;
        out->type = YX_GLOBAL_INT;
    }
    return yx_ok();
}

static const void *yx_json_scalar_value(const yx_json_scalar *scalar)
{
    switch (scalar->type) {
        case YX_GLOBAL_BOOL: return &scalar->value.boolean;
        case YX_GLOBAL_INT: return &scalar->value.integer;
        case YX_GLOBAL_FLOAT: return &scalar->value.floating;
        case YX_GLOBAL_STR: return &scalar->value.string;
        case YX_GLOBAL_ARRAY: return NULL;
        case YX_GLOBAL_STRUCT: return NULL;
    }
    return NULL;
}

/* The semantic pass above rejects empty, mixed, nested and null arrays.
 * For object arrays, the first item's fields define the static schema.
 * Subsequent object items retain their own fields, as in the reference. */
static YRX_RESULT yx_parse_json_object_depth(const char *text, yx_global_object **out, unsigned depth, bool allow_arbitrary_keys);

static YRX_RESULT yx_parse_json_array_depth(const char *text, yx_global_array **out, unsigned depth)
{
    xx_json json;
    yx_global_array *array;
    size_t capacity = 0;
    *out = NULL;
    xx_json_init(&json, text, strlen(text));
    if (!xx_json_array_begin(&json) || xx_json_array_empty(&json)) return yx_unsupported("JSON array globals");
    array = (yx_global_array *)calloc(1, sizeof(*array));
    if (!array) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    for (;;) {
        size_t start, length;
        char *item_text;
        yx_json_scalar item = {0};
        yx_global_object *item_object = NULL;
        yx_global_type item_type;
        yx_global_scalar_value *grown;
        YRX_RESULT result;
        xx_json_peek(&json);
        start = json.position;
        if (!xx_json_skip(&json)) {
            yx_free_global_array(array);
            return YRX_INVALID_ARGUMENT;
        }
        length = json.position - start;
        item_text = (char *)malloc(length + 1);
        if (!item_text) {
            yx_free_global_array(array);
            return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
        }
        memcpy(item_text, text + start, length);
        item_text[length] = '\0';
        if (item_text[0] == '{') {
            result = yx_parse_json_object_depth(item_text, &item_object, depth + 1, true);
            item_type = YX_GLOBAL_STRUCT;
        } else {
            result = yx_parse_json_scalar(item_text, &item);
            item_type = item.type;
        }
        free(item_text);
        if (result != YRX_SUCCESS) {
            yx_free_global_object(item_object);
            yx_free_global_array(array);
            return result;
        }
        if (!array->count) array->element_type = item_type;
        if (item_type != array->element_type && !(array->element_type == YX_GLOBAL_FLOAT && item_type == YX_GLOBAL_INT)) {
            if (item.type == YX_GLOBAL_STR) xx_str_free(item.value.string.data);
            yx_free_global_object(item_object);
            yx_free_global_array(array);
            return yx_fail(YRX_VARIABLE_ERROR, "arrays can't be empty and all items must be non-null and the same type");
        }
        if (array->count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            if (next_capacity < capacity || next_capacity > SIZE_MAX / sizeof(*grown)) {
                if (item.type == YX_GLOBAL_STR) xx_str_free(item.value.string.data);
                yx_free_global_object(item_object);
                yx_free_global_array(array);
                return yx_fail(YRX_VARIABLE_ERROR, "too many array items");
            }
            grown = (yx_global_scalar_value *)realloc(array->items, next_capacity * sizeof(*grown));
            if (!grown) {
                if (item.type == YX_GLOBAL_STR) xx_str_free(item.value.string.data);
                yx_free_global_object(item_object);
                yx_free_global_array(array);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            array->items = grown;
            capacity = next_capacity;
        }
        if (array->element_type == YX_GLOBAL_BOOL) array->items[array->count].boolean = item.value.boolean;
        else if (array->element_type == YX_GLOBAL_INT) array->items[array->count].integer = item.value.integer;
        else if (array->element_type == YX_GLOBAL_FLOAT)
            array->items[array->count].floating = item.type == YX_GLOBAL_INT ? (double)item.value.integer : item.value.floating;
        else if (array->element_type == YX_GLOBAL_STRUCT) {
            array->items[array->count].object = item_object;
        } else {
            array->items[array->count].string.length = item.value.string.length;
            array->items[array->count].string.data = yx_copy_string_bytes(item.value.string.data, item.value.string.length);
            xx_str_free(item.value.string.data);
            if (!array->items[array->count].string.data) {
                yx_free_global_array(array);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
        }
        ++array->count;
        if (!xx_json_more(&json)) break;
    }
    if (!xx_json_array_end(&json) || !yx_json_at_end(&json)) {
        yx_free_global_array(array);
        return YRX_INVALID_ARGUMENT;
    }
    *out = array;
    return yx_ok();
}

static YRX_RESULT yx_parse_json_array(const char *text, yx_global_array **out)
{
    return yx_parse_json_array_depth(text, out, 0);
}

/* serde_json keeps the final value of a duplicate object key at that key's
 * original position. Replacing a key discards its earlier owned value. */
static size_t yx_object_remove_path(yx_global_object *object, const char *name)
{
    size_t length = strlen(name);
    size_t insertion = object->count, kept = 0;
    for (size_t i = 0; i < object->count; ++i) {
        yx_global_field *field = &object->fields[i];
        bool matches = strncmp(field->name, name, length) == 0 && (field->name[length] == '\0' || field->name[length] == '.');
        if (matches) {
            if (insertion == object->count) insertion = kept;
            free(field->name);
            if (field->type == YX_GLOBAL_STR) free(field->value.string.data);
            else if (field->type == YX_GLOBAL_ARRAY) yx_free_global_array(field->value.array);
            else if (field->type == YX_GLOBAL_STRUCT) yx_free_global_object(field->value.object);
        } else {
            if (kept != i) object->fields[kept] = *field;
            ++kept;
        }
    }
    object->count = kept;
    return insertion == object->count ? kept : insertion;
}

static YRX_RESULT yx_object_put_scalar(yx_global_object *object, size_t *capacity, const char *name, yx_global_type type, yx_global_scalar_value value)
{
    yx_global_string string_copy = {0};
    yx_global_array *array_copy = NULL;
    yx_global_object *object_copy = NULL;
    size_t index;
    if (type == YX_GLOBAL_STR) {
        string_copy.length = value.string.length;
        string_copy.data = yx_copy_string_bytes(value.string.data, value.string.length);
        if (!string_copy.data) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    } else if (type == YX_GLOBAL_ARRAY) {
        array_copy = yx_copy_global_array(value.array);
        if (!array_copy) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    }
    if (type == YX_GLOBAL_STRUCT && value.object) {
        object_copy = yx_copy_global_object(value.object);
        if (!object_copy) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    }
    for (index = 0; index < object->count; ++index)
        if (strcmp(object->fields[index].name, name) == 0) break;
    if (index == object->count) {
        char *name_copy = yx_strdup(name);
        if (!name_copy) {
            free(string_copy.data);
            yx_free_global_array(array_copy);
            yx_free_global_object(object_copy);
            return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
        }
        if (object->count == *capacity) {
            size_t next_capacity = *capacity ? *capacity * 2 : 8;
            yx_global_field *grown;
            if (next_capacity < *capacity || next_capacity > SIZE_MAX / sizeof(*grown)) {
                free(name_copy);
                free(string_copy.data);
                yx_free_global_array(array_copy);
                yx_free_global_object(object_copy);
                return yx_fail(YRX_VARIABLE_ERROR, "too many object fields");
            }
            grown = (yx_global_field *)realloc(object->fields, next_capacity * sizeof(*grown));
            if (!grown) {
                free(name_copy);
                free(string_copy.data);
                yx_free_global_array(array_copy);
                yx_free_global_object(object_copy);
                return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
            }
            object->fields = grown;
            *capacity = next_capacity;
        }
        memset(&object->fields[index], 0, sizeof(object->fields[index]));
        object->fields[index].name = name_copy;
        ++object->count;
    } else if (object->fields[index].type == YX_GLOBAL_STR) {
        free(object->fields[index].value.string.data);
    } else if (object->fields[index].type == YX_GLOBAL_ARRAY) {
        yx_free_global_array(object->fields[index].value.array);
    } else if (object->fields[index].type == YX_GLOBAL_STRUCT) {
        yx_free_global_object(object->fields[index].value.object);
    }
    object->fields[index].type = type;
    if (type == YX_GLOBAL_STR) object->fields[index].value.string = string_copy;
    else if (type == YX_GLOBAL_ARRAY) object->fields[index].value.array = array_copy;
    else if (type == YX_GLOBAL_STRUCT) object->fields[index].value.object = object_copy;
    else object->fields[index].value = value;
    return yx_ok();
}

static YRX_RESULT yx_parse_json_object_depth(const char *text, yx_global_object **out, unsigned depth, bool allow_arbitrary_keys)
{
    xx_json json;
    yx_global_object *object;
    size_t capacity = 0;
    *out = NULL;
    if (depth >= YX_JSON_COMPAT_MAX_DEPTH - 1) return YRX_INVALID_ARGUMENT;
    xx_json_init(&json, text, strlen(text));
    if (!xx_json_object_begin(&json)) return YRX_INVALID_ARGUMENT;
    object = (yx_global_object *)calloc(1, sizeof(*object));
    if (!object) return yx_fail(YRX_VARIABLE_ERROR, "out of memory");
    if (!xx_json_object_empty(&json)) {
        for (;;) {
            char *key = NULL, *item_text = NULL;
            yx_global_object *child = NULL;
            yx_global_array *array = NULL;
            yx_json_scalar item = {0};
            yx_global_scalar_value scalar = {0};
            const char *item_start;
            size_t start, length, key_start;
            size_t insertion, prior_count;
            bool have_scalar = false;
            YRX_RESULT result = YRX_SUCCESS;
            xx_json_peek(&json);
            key_start = json.position;
            if (!xx_json_object_key(&json, &key)) {
                result = YRX_INVALID_ARGUMENT;
                goto item_error;
            }
            if (allow_arbitrary_keys) {
                size_t key_end = key_start + 1;
                size_t decoded_length;
                while (key_end < json.size) {
                    if (json.data[key_end] == '\\') {
                        key_end += 2;
                    } else if (json.data[key_end++] == '"') {
                        break;
                    }
                }
                decoded_length = yx_json_decoded_string_length(json.data, key_start, key_end);
                if (memchr(key, '\0', decoded_length)) {
                    static const char hex[] = "0123456789abcdef";
                    char *encoded;
                    if (decoded_length > (SIZE_MAX - 2) / 2) {
                        result = yx_fail(YRX_VARIABLE_ERROR, "object field name is too long");
                        goto item_error;
                    }
                    /* An invalid UTF-8 prefix keeps this private key distinct
                     * from every valid JSON string, including one with NUL. */
                    encoded = (char *)xx_mem_alloc(decoded_length * 2 + 2);
                    if (!encoded) {
                        result = yx_fail(YRX_VARIABLE_ERROR, "out of memory");
                        goto item_error;
                    }
                    encoded[0] = (char)0xff;
                    for (size_t i = 0; i < decoded_length; ++i) {
                        unsigned byte = (unsigned char)key[i];
                        encoded[1 + i * 2] = hex[byte >> 4];
                        encoded[2 + i * 2] = hex[byte & 15];
                    }
                    encoded[1 + decoded_length * 2] = '\0';
                    xx_str_free(key);
                    key = encoded;
                }
            }
            if (!allow_arbitrary_keys && !yx_valid_json_field_name(key)) {
                result = yx_fail(YRX_VARIABLE_ERROR, "invalid identifier in JSON object");
                goto item_error;
            }
            insertion = yx_object_remove_path(object, key);
            prior_count = object->count;
            xx_json_peek(&json);
            start = json.position;
            if (!xx_json_skip(&json)) {
                result = YRX_INVALID_ARGUMENT;
                goto item_error;
            }
            length = json.position - start;
            item_text = (char *)malloc(length + 1);
            if (!item_text) {
                result = yx_fail(YRX_VARIABLE_ERROR, "out of memory");
                goto item_error;
            }
            memcpy(item_text, text + start, length);
            item_text[length] = '\0';
            item_start = item_text;
            while (*item_start == ' ' || *item_start == '\t' || *item_start == '\r' || *item_start == '\n') ++item_start;
            if (*item_start == '{') {
                result = yx_parse_json_object_depth(item_text, &child, depth + 1, false);
                if (result != YRX_SUCCESS) goto item_error;
                scalar.object = child;
                result = yx_object_put_scalar(object, &capacity, key, YX_GLOBAL_STRUCT, scalar);
                if (result != YRX_SUCCESS) goto item_error;
            } else if (*item_start == '[') {
                result = yx_parse_json_array_depth(item_text, &array, depth + 1);
                if (result != YRX_SUCCESS) goto item_error;
                scalar.array = array;
                result = yx_object_put_scalar(object, &capacity, key, YX_GLOBAL_ARRAY, scalar);
                if (result != YRX_SUCCESS) goto item_error;
            } else {
                result = yx_parse_json_scalar(item_text, &item);
                if (result != YRX_SUCCESS) goto item_error;
                have_scalar = true;
                if (item.type == YX_GLOBAL_BOOL) scalar.boolean = item.value.boolean;
                else if (item.type == YX_GLOBAL_INT) scalar.integer = item.value.integer;
                else if (item.type == YX_GLOBAL_FLOAT) scalar.floating = item.value.floating;
                else scalar.string = item.value.string;
                result = yx_object_put_scalar(object, &capacity, key, item.type, scalar);
                if (result != YRX_SUCCESS) goto item_error;
            }
            for (size_t i = prior_count; i < object->count; ++i) {
                yx_global_field moved = object->fields[i];
                memmove(object->fields + insertion + 1, object->fields + insertion, (i - insertion) * sizeof(*object->fields));
                object->fields[insertion++] = moved;
            }
            if (have_scalar && item.type == YX_GLOBAL_STR) xx_str_free(item.value.string.data);
            yx_free_global_object(child);
            yx_free_global_array(array);
            free(item_text);
            xx_str_free(key);
            if (!xx_json_more(&json)) break;
            continue;
        item_error:
            if (have_scalar && item.type == YX_GLOBAL_STR) xx_str_free(item.value.string.data);
            yx_free_global_object(child);
            yx_free_global_array(array);
            free(item_text);
            if (key) xx_str_free(key);
            yx_free_global_object(object);
            return result;
        }
    }
    if (!xx_json_object_end(&json) || !yx_json_at_end(&json)) {
        yx_free_global_object(object);
        return YRX_INVALID_ARGUMENT;
    }
    *out = object;
    return yx_ok();
}

static YRX_RESULT yx_parse_json_object(const char *text, yx_global_object **out)
{
    return yx_parse_json_object_depth(text, out, 0, false);
}

static void yx_clear_views(YRX_SCANNER *scanner)
{
    size_t i, j;
    if (!scanner || !scanner->views) return;
    for (i = 0; i < scanner->rules->rule_count; ++i) {
        YRX_RULE *view = &scanner->views[i];
        if (!view->patterns) continue;
        for (j = 0; j < view->pattern_count; ++j) {
            if (!view->patterns[j].matches_borrowed) free(view->patterns[j].matches);
            view->patterns[j].matches_borrowed = false;
            view->patterns[j].matches = NULL;
            free(view->patterns[j].candidate_hits);
            view->patterns[j].candidate_hits = NULL;
            view->patterns[j].candidate_hit_count = view->patterns[j].candidate_hit_capacity = 0;
            view->patterns[j].candidate_hits_overflow = false;
            view->patterns[j].match_count = 0;
            view->patterns[j].match_capacity = 0;
            view->patterns[j].zero_limit_present = false;
        }
        view->matched = false;
    }
}

static void yx_destroy_views(YRX_SCANNER *scanner)
{
    size_t i;
    if (!scanner || !scanner->views) return;
    yx_clear_views(scanner);
    for (i = 0; i < scanner->rules->rule_count; ++i) {
        for (size_t j = 0; scanner->views[i].patterns && j < scanner->views[i].pattern_count; ++j) {
            free(scanner->views[i].patterns[j].rx_order_ids);
            free(scanner->views[i].patterns[j].rx_order_buckets);
        }
        free(scanner->views[i].patterns);
    }
    free(scanner->views);
    scanner->views = NULL;
    yx_atom_set_free(scanner->text_prefilter);
    scanner->text_prefilter = NULL;
    free(scanner->text_prefilter_hit);
    scanner->text_prefilter_hit = NULL;
    free(scanner->candidate_patterns);
    scanner->candidate_patterns = NULL;
    scanner->candidate_pattern_count = 0;
#ifdef XXYARA_ENABLE_PROFILING
    free(scanner->candidate_rule_index);
    scanner->candidate_rule_index = NULL;
#endif
}

/* All supported variants share one atom pass. A missing plan leaves the
 * existing full scanner in charge of that pattern. */
static void yx_build_text_prefilter(YRX_SCANNER *scanner)
{
    size_t count = 0;
    for (size_t i = 0; i < scanner->rules->rule_count; ++i) count += scanner->views[i].pattern_count;
    if (!count || count > SIZE_MAX / sizeof(YRX_PATTERN *)) return;
    YRX_PATTERN **patterns = calloc(count, sizeof(*patterns));
    size_t *literal_owners = malloc(count * sizeof(*literal_owners));
#ifdef XXYARA_ENABLE_PROFILING
    size_t *rule_index = malloc(count * sizeof(*rule_index));
    if (!rule_index) {
        free(patterns);
        free(literal_owners);
        return;
    }
#endif
    if (literal_owners)
        for (size_t i = 0; i < count; ++i) literal_owners[i] = SIZE_MAX;
    yx_atom_set *set = yx_atom_set_new();
    if (!patterns || !set || !literal_owners) {
        free(patterns);
        free(literal_owners);
        yx_atom_set_free(set);
#ifdef XXYARA_ENABLE_PROFILING
        free(rule_index);
#endif
        return;
    }
    size_t owners = 0;
    for (size_t i = 0; i < scanner->rules->rule_count; ++i)
        for (size_t j = 0; j < scanner->views[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &scanner->views[i].patterns[j];
            const yx_candidate_plan *plan = pattern->candidate_plan;
            size_t atoms = yx_candidate_plan_atom_count(plan);
            if (!atoms) continue;
            if (pattern->scan_duplicate && pattern->scan_duplicate->prefilter_owner != SIZE_MAX) {
                pattern->prefilter_owner = pattern->scan_duplicate->prefilter_owner;
                continue;
            }
            if (pattern->kind == YX_PATTERN_TEXT && pattern->compat_pattern_id < count && literal_owners[pattern->compat_pattern_id] != SIZE_MAX) {
                pattern->prefilter_owner = literal_owners[pattern->compat_pattern_id];
                continue;
            }
            if (pattern->kind == YX_PATTERN_TEXT && pattern->compat_pattern_id < count) literal_owners[pattern->compat_pattern_id] = owners;
            for (size_t a = 0; a < atoms; ++a) {
                const yx_candidate_atom *atom = yx_candidate_plan_atom(plan, a);
                if (!yx_atom_set_add_tagged(set, atom->bytes, atom->length, owners, atom->tag)) goto failed;
            }
            patterns[owners] = pattern;
#ifdef XXYARA_ENABLE_PROFILING
            rule_index[owners] = i;
#endif
            pattern->prefilter_owner = owners++;
        }
    if (!owners || !yx_atom_set_build(set)) goto failed;
    bool *hit = calloc(owners, sizeof(*hit));
    if (!hit) goto failed;
    scanner->text_prefilter = set;
    scanner->text_prefilter_hit = hit;
    scanner->candidate_patterns = patterns;
    scanner->candidate_pattern_count = owners;
#ifdef XXYARA_ENABLE_PROFILING
    scanner->candidate_rule_index = rule_index;
#endif
    free(literal_owners);
    return;
failed:
#ifdef XXYARA_ENABLE_PROFILING
    free(rule_index);
#endif
    for (size_t i = 0; i < scanner->rules->rule_count; ++i)
        for (size_t j = 0; j < scanner->views[i].pattern_count; ++j) scanner->views[i].patterns[j].prefilter_owner = SIZE_MAX;
    yx_atom_set_free(set);
    free(patterns);
    free(literal_owners);
}

static bool yx_any_of_them_condition(const YRX_RULE *rule)
{
    static const char condition[] = "any of them";
    const char *text = rule->condition_text;
    if (!text) return false;
    while (isspace((unsigned char)*text)) ++text;
    if (strncmp(text, condition, sizeof(condition) - 1) != 0) return false;
    text += sizeof(condition) - 1;
    while (isspace((unsigned char)*text)) ++text;
    return *text == '\0';
}

static void yx_add_known_atom(uint8_t atoms[65][4], size_t lengths[65], size_t *count, const uint8_t *bytes, size_t length, size_t *shortest)
{
    if (length < *shortest) *shortest = length;
    /* The reference automaton keeps a separate entry for every extracted
       atom, including byte-identical atoms from different subpatterns. */
    if (*count == 65) return;
    memcpy(atoms[*count], bytes, length);
    lengths[*count] = length;
    ++*count;
}

/* Count atoms guaranteed by a simple mandatory character-class repeat.
 * The literal extractor expands the Cartesian product of the first few
 * positions, so two class positions can cross Teddy's 16-atom limit even
 * when the class itself is small. Unknown regexp forms remain uncounted. */
static bool yx_add_class_repeat_atoms(const char *regexp, unsigned modifiers, uint8_t atoms[65][4], size_t lengths[65], size_t *count, size_t *shortest)
{
    const char *at = regexp;
    uint8_t values[256], atom[4];
    bool seen[256] = {false};
    size_t value_count = 0, prefix_length = 0, prefix_variants = 1;
    uint8_t prefix_byte = 0;
    size_t repeat = 1, positions, combinations = 1;
    if (*at == '^') ++at;
    if (isalnum((unsigned char)*at) && (at[1] == '[' || (at[1] == '+' && at[2] == '['))) {
        if (at[1] == '[') {
            prefix_byte = (uint8_t)*at;
            prefix_length = 1;
            if ((modifiers & YX_MOD_NOCASE) && isalpha((unsigned char)*at)) prefix_variants = 2;
            ++at;
        } else {
            at += 2;
        }
    }
    if (*at++ != '[') return false;
    while (*at && *at != ']') {
        unsigned char first = (unsigned char)*at;
        unsigned char last = first;
        if (!isalnum(first)) return false;
        if (at[1] == '-' && at[2] && at[2] != ']') {
            last = (unsigned char)at[2];
            if (!isalnum(last) || last < first) return false;
            at += 3;
        } else {
            ++at;
        }
        for (unsigned ch = first; ch <= last; ++ch) {
            if (!seen[ch]) {
                seen[ch] = true;
                values[value_count++] = (uint8_t)ch;
            }
            if (modifiers & YX_MOD_NOCASE) {
                unsigned other = ch;
                if (ch >= 'a' && ch <= 'z') other = ch - ('a' - 'A');
                else if (ch >= 'A' && ch <= 'Z') other = ch + ('a' - 'A');
                if (!seen[other]) {
                    seen[other] = true;
                    values[value_count++] = (uint8_t)other;
                }
            }
        }
    }
    if (!value_count || *at++ != ']') return false;
    if (*at == '+') {
        ++at;
    } else if (*at == '{') {
        ++at;
        if (*at < '1' || *at > '4') return false;
        repeat = (size_t)(*at++ - '0');
        if (*at == ',') {
            ++at;
            if (*at < '1' || *at > '9' || (size_t)(*at - '0') < repeat) return false;
            ++at;
        }
        if (*at++ != '}') return false;
    }
    if (*at != '\0') return false;
    positions = repeat;
    if (positions > sizeof(atom) - prefix_length) positions = sizeof(atom) - prefix_length;
    for (size_t i = 0; i < positions; ++i) {
        if (combinations > 65 / value_count) {
            combinations = 65;
            break;
        }
        combinations *= value_count;
    }
    if (combinations > 65 / prefix_variants) combinations = 65;
    else combinations *= prefix_variants;
    if (combinations > 65) combinations = 65;
    for (size_t variant = 0; variant < combinations; ++variant) {
        size_t index = variant / prefix_variants;
        if (prefix_length) {
            atom[0] = prefix_byte;
            if (prefix_variants == 2 && variant % prefix_variants) {
                if (prefix_byte >= 'a' && prefix_byte <= 'z') atom[0] = (uint8_t)(prefix_byte - ('a' - 'A'));
                else atom[0] = (uint8_t)(prefix_byte + ('a' - 'A'));
            }
        }
        for (size_t pos = positions; pos > 0; --pos) {
            atom[prefix_length + pos - 1] = values[index % value_count];
            index /= value_count;
        }
        yx_add_known_atom(atoms, lengths, count, atom, prefix_length + positions, shortest);
    }
    return true;
}

/* The short-first lazy pair `([xy]|x[yz]){1,2}?` contributes these six
 * extracted atoms. Counting them lets the scan choose the same verifier
 * when other patterns push the shared one-byte atom set past 16 entries. */
static bool yx_add_lazy_class_pair_atoms(const char *regexp, uint8_t atoms[65][4], size_t lengths[65], size_t *count, size_t *shortest)
{
    if (!regexp || strlen(regexp) != 18 || regexp[0] != '(' || regexp[1] != '[' || regexp[4] != ']' || regexp[5] != '|' || regexp[7] != '[' || regexp[10] != ']' ||
        regexp[11] != ')' || memcmp(regexp + 12, "{1,2}?", 6) != 0)
        return false;
    uint8_t x = (uint8_t)regexp[2];
    uint8_t y = (uint8_t)regexp[3];
    uint8_t z = (uint8_t)regexp[9];
    if (!((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9')) || !((y >= 'a' && y <= 'z') || (y >= 'A' && y <= 'Z') || (y >= '0' && y <= '9')) ||
        !((z >= 'a' && z <= 'z') || (z >= 'A' && z <= 'Z') || (z >= '0' && z <= '9')) || regexp[6] != (char)x || regexp[8] != (char)y || x >= y || y >= z)
        return false;

    uint8_t wide_x[2] = {x, 0};
    uint8_t wide_xz[4] = {x, 0, z, 0};
    uint8_t wide_y[2] = {y, 0};
    uint8_t ascii_xz[2] = {x, z};
    yx_add_known_atom(atoms, lengths, count, wide_x, 2, shortest);
    yx_add_known_atom(atoms, lengths, count, wide_xz, 4, shortest);
    yx_add_known_atom(atoms, lengths, count, wide_y, 2, shortest);
    yx_add_known_atom(atoms, lengths, count, &x, 1, shortest);
    yx_add_known_atom(atoms, lengths, count, ascii_xz, 2, shortest);
    yx_add_known_atom(atoms, lengths, count, &y, 1, shortest);
    return true;
}

/* This is the compiler's atom quality score, including masked-byte costs. */
static int yx_literal_atom_quality(const uint8_t *bytes, const uint8_t *masks, size_t length)
{
    unsigned unique = 0;
    int quality = 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = bytes[i], mask = masks ? masks[i] : 0xff;
        if (mask != 0xff) {
            unsigned bits = 0;
            for (unsigned k = 0; k < 8; ++k) bits += (mask >> k) & 1u;
            quality += bits ? (int)(3 * bits) - 8 : -13;
        } else {
            quality += byte == 0                                                      ? 6
                       : byte == 0x20 || byte == 0x90 || byte == 0xcc || byte == 0xff ? 12
                       : (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ? 18
                                                                                      : 20;
            bool seen = false;
            for (size_t j = 0; j < i; ++j)
                if ((!masks || masks[j] == 0xff) && bytes[j] == byte) seen = true;
            if (!seen) ++unique;
        }
    }
    if (unique == 1) quality += bytes[0] == 0 || bytes[0] == 0x20 || bytes[0] == 0x90 || bytes[0] == 0xcc || bytes[0] == 0xff ? -5 : 2;
    else quality += (int)(2 * unique);
    return quality;
}

/* Choose the unmasked four-byte window before nocase/XOR expansion, as the
   compiler does. Common padding bytes and repeated bytes lower its quality. */
static size_t yx_text_best_atom_bytes(const YRX_PATTERN *pattern, bool wide, uint8_t selected[4])
{
    if (wide && pattern->length > SIZE_MAX / 2) return 0;
    size_t length = pattern->length * (wide ? 2 : 1);
    size_t width = length < 4 ? length : 4;
    int best = INT_MIN;
    if (!width) return 0;
    for (size_t at = 0; at <= length - width; ++at) {
        uint8_t bytes[4];
        for (size_t i = 0; i < width; ++i) {
            size_t index = at + i;
            bytes[i] = wide && index % 2 ? 0 : pattern->bytes[index / (wide ? 2 : 1)];
        }
        int quality = yx_literal_atom_quality(bytes, NULL, width);
        if (quality > best) {
            best = quality;
            memcpy(selected, bytes, width);
        }
    }
    return width;
}

/* An ordinary regexp with literal fragments separated by greedy dot stars
 * searches the best mandatory fragment. It adds one shared-search atom. */
static bool yx_add_gap_literal_atom(const YRX_PATTERN *pattern, uint8_t atoms[65][4], size_t lengths[65], size_t *count, size_t *shortest)
{
    if (!pattern->regexp || (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_PRIVATE))) return false;
    const char *at = pattern->regexp;
    uint8_t selected[4];
    size_t width = 0;
    int best = INT_MIN;
    bool gap = false;
    for (;;) {
        const char *start = at;
        while ((*at >= 'a' && *at <= 'z') || (*at >= 'A' && *at <= 'Z') || (*at >= '0' && *at <= '9')) ++at;
        if (at == start) return false;
        YRX_PATTERN literal = *pattern;
        literal.bytes = (uint8_t *)start;
        literal.length = (size_t)(at - start);
        uint8_t bytes[4];
        size_t length = yx_text_best_atom_bytes(&literal, false, bytes);
        int quality = yx_literal_atom_quality(bytes, NULL, length);
        if (quality > best) {
            best = quality;
            width = length;
            memcpy(selected, bytes, length);
        }
        if (!*at) break;
        if (at[0] != '.' || at[1] != '*') return false;
        at += 2;
        gap = true;
    }
    if (!gap) return false;
    yx_add_known_atom(atoms, lengths, count, selected, width, shortest);
    return true;
}

/* A masked HEX literal can still select one entirely fixed atom. Account
 * for that atom only when it wins against every masked window as upstream. */
static bool yx_add_masked_hex_atom(const YRX_PATTERN *pattern, uint8_t atoms[65][4], size_t lengths[65], size_t *count, size_t *shortest)
{
    size_t length = pattern->hex_atom_count, width = 0;
    uint8_t selected[4];
    int best = INT_MIN;
    bool fixed = false;
    if (!pattern->hex_atoms || !length || (pattern->modifiers & ~YX_MOD_PRIVATE)) return false;
    for (size_t i = 0; i < length; ++i)
        if (pattern->hex_atoms[i].kind != YX_HEX_BYTE || pattern->hex_atoms[i].negated) return false;
    size_t limit = length < 4 ? length : 4;
    for (size_t n = 1; n <= limit; ++n) {
        for (size_t at = 0; at <= length - n; ++at) {
            uint8_t bytes[4], masks[4];
            bool unmasked = true;
            for (size_t i = 0; i < n; ++i) {
                bytes[i] = pattern->hex_atoms[at + i].value;
                masks[i] = pattern->hex_atoms[at + i].mask;
                if (masks[i] != 0xff) unmasked = false;
            }
            int quality = yx_literal_atom_quality(bytes, masks, n);
            if (quality > best) {
                best = quality;
                fixed = unmasked;
                width = n;
                memcpy(selected, bytes, n);
            }
        }
    }
    if (!fixed) return false;
    yx_add_known_atom(atoms, lengths, count, selected, width, shortest);
    return true;
}

static bool yx_compat_same_pattern(const YRX_PATTERN *a, const YRX_PATTERN *b, bool same_rule);
static uint64_t yx_compat_pattern_hash(const YRX_PATTERN *p);

/* Teddy accepts 16 atoms when any atom is one byte, or 64 wider atoms.
   Count atoms whose bytes are certain. Other regexps can add atoms, but
   cannot remove these from the shared atom set. */
static size_t yx_known_global_atom_count(const YRX_RULES *rules, size_t *minimum_width_hint, bool text_variants)
{
    uint8_t atoms[65][4];
    size_t lengths[65];
    size_t count = 0;
    const YRX_PATTERN *counted_regex[17];
    size_t counted_regex_count = 0;
    const YRX_PATTERN *counted_text[65];
    /* Equal literals hash equally (yx_compat_pattern_hash covers a subset
     * of the fields yx_compat_same_pattern compares for them). */
    uint64_t counted_text_hash[65];
    size_t counted_text_count = 0;
    size_t shortest = SIZE_MAX;
    bool has_short_regex = false;
    bool width_complete = true;
    for (size_t i = 0; i < rules->rule_count; ++i) {
        const YRX_RULE *rule = &rules->rules[i];
        bool all_patterns = yx_any_of_them_condition(rule);
        if (!rule->pattern_count) continue;
        for (size_t j = 0; j < rule->pattern_count; ++j) {
            const YRX_PATTERN *pattern = &rule->patterns[j];
            /* A dot repetition supplies every one-byte atom. These atoms
               disable the small Teddy path for every pattern in the rules. */
            if (yx_regex_many_single_byte_atoms(pattern)) {
                for (unsigned byte = 0; byte < 256; ++byte) {
                    if (byte == '\n' && !(pattern->modifiers & YX_MOD_DOTALL)) continue;
                    uint8_t atom = (uint8_t)byte;
                    yx_add_known_atom(atoms, lengths, &count, &atom, 1, &shortest);
                }
                has_short_regex = true;
                continue;
            }
            if (pattern->kind == YX_PATTERN_REGEX && rule->pattern_count == 1 && !all_patterns) {
                bool duplicate = false;
                /* The reference compiler reuses one PatternId for exact
                   copies of a pattern in separate rules. Those copies do
                   not add a second set of automaton atoms. Limit this to
                   the direct-pattern conditions whose scan cap agrees. */
                for (size_t k = 0; k < counted_regex_count; ++k) {
                    const YRX_PATTERN *earlier = counted_regex[k];
                    if (pattern->modifiers == earlier->modifiers && pattern->regexp && earlier->regexp && strcmp(pattern->regexp, earlier->regexp) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;
            }
            if (text_variants && pattern->kind == YX_PATTERN_TEXT && pattern->bytes && pattern->length >= 1) {
                if (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD | YX_MOD_XOR)) {
                    width_complete = false;
                    continue;
                }
                bool duplicate = false;
                uint64_t text_hash = yx_compat_pattern_hash(pattern);
                for (size_t k = 0; k < counted_text_count; ++k)
                    if (counted_text_hash[k] == text_hash && yx_compat_same_pattern(pattern, counted_text[k], false)) {
                        duplicate = true;
                        break;
                    }
                if (duplicate) continue;
                if (counted_text_count < 65) {
                    counted_text_hash[counted_text_count] = text_hash;
                    counted_text[counted_text_count++] = pattern;
                }
                has_short_regex = true;
                bool ascii = (pattern->modifiers & YX_MOD_ASCII) || !(pattern->modifiers & YX_MOD_WIDE);
                bool wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
                bool nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
                unsigned first = (pattern->modifiers & YX_MOD_XOR) ? pattern->xor_min : 0;
                unsigned last = (pattern->modifiers & YX_MOD_XOR) ? pattern->xor_max : 0;
                for (unsigned variant = 0; variant < 2; ++variant) {
                    if ((!variant && !ascii) || (variant && !wide)) continue;
                    uint8_t selected[4];
                    size_t length = yx_text_best_atom_bytes(pattern, variant != 0, selected);
                    if (!length) {
                        width_complete = false;
                        continue;
                    }
                    unsigned letter_count = 0;
                    if (nocase) {
                        for (size_t k = 0; k < length; ++k) {
                            uint8_t byte = selected[k];
                            if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) ++letter_count;
                        }
                    }
                    for (unsigned bits = 0; bits < (1u << letter_count); ++bits) {
                        uint8_t bytes[4] = {0};
                        unsigned letter_index = 0;
                        for (size_t k = 0; k < length; ++k) {
                            uint8_t byte = selected[k];
                            if (nocase && byte >= 'A' && byte <= 'Z') byte = (uint8_t)(byte + ('a' - 'A'));
                            if (nocase && byte >= 'a' && byte <= 'z') {
                                if (bits & (1u << letter_index)) byte = (uint8_t)(byte - ('a' - 'A'));
                                ++letter_index;
                            }
                            bytes[k] = byte;
                        }
                        for (unsigned key = first; key <= last; ++key) {
                            uint8_t encoded[4];
                            for (size_t k = 0; k < length; ++k) encoded[k] = (uint8_t)(bytes[k] ^ key);
                            yx_add_known_atom(atoms, lengths, &count, encoded, length, &shortest);
                        }
                    }
                }
            } else if (pattern->kind == YX_PATTERN_TEXT && pattern->bytes && pattern->length >= 1 && pattern->length <= 4) {
                if (pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_NOCASE)) {
                    yx_rx_atom *literal_atoms = NULL;
                    size_t literal_count = 0;
                    if (yx_ser_pattern_reference_atoms(pattern, &literal_atoms, &literal_count)) {
                        for (size_t a = 0; a < literal_count; ++a) yx_add_known_atom(atoms, lengths, &count, literal_atoms[a].bytes, literal_atoms[a].length, &shortest);
                        if (shortest == 1) has_short_regex = true;
                    } else width_complete = false;
                    free(literal_atoms);
                    continue;
                }
                if (pattern->modifiers & YX_MOD_NOCASE) {
                    unsigned letter_count = 0;
                    for (size_t k = 0; k < pattern->length; ++k) {
                        uint8_t byte = pattern->bytes[k];
                        if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) ++letter_count;
                    }
                    for (unsigned bits = 0; bits < (1u << letter_count); ++bits) {
                        uint8_t variant[4];
                        unsigned letter_index = 0;
                        for (size_t k = 0; k < pattern->length; ++k) {
                            uint8_t byte = pattern->bytes[k];
                            if (byte >= 'A' && byte <= 'Z') byte = (uint8_t)(byte + ('a' - 'A'));
                            if (byte >= 'a' && byte <= 'z') {
                                if (bits & (1u << letter_index)) byte = (uint8_t)(byte - ('a' - 'A'));
                                ++letter_index;
                            }
                            variant[k] = byte;
                        }
                        yx_add_known_atom(atoms, lengths, &count, variant, pattern->length, &shortest);
                    }
                } else {
                    yx_add_known_atom(atoms, lengths, &count, pattern->bytes, pattern->length, &shortest);
                }
            } else if (text_variants && pattern->kind == YX_PATTERN_HEX) {
                bool fixed = pattern->hex_atoms && pattern->hex_atom_count && !(pattern->modifiers & ~YX_MOD_PRIVATE);
                uint8_t *bytes = fixed ? malloc(pattern->hex_atom_count) : NULL;
                if (!bytes) fixed = false;
                for (size_t k = 0; fixed && k < pattern->hex_atom_count; ++k) {
                    const yx_hex_atom *atom = &pattern->hex_atoms[k];
                    if (atom->kind != YX_HEX_BYTE || atom->mask != 0xff || atom->negated) fixed = false;
                    else bytes[k] = atom->value;
                }
                if (fixed) {
                    YRX_PATTERN literal = *pattern;
                    literal.bytes = bytes;
                    literal.length = pattern->hex_atom_count;
                    uint8_t selected[4];
                    size_t width = yx_text_best_atom_bytes(&literal, false, selected);
                    yx_add_known_atom(atoms, lengths, &count, selected, width, &shortest);
                    has_short_regex = true;
                } else if (yx_add_masked_hex_atom(pattern, atoms, lengths, &count, &shortest)) {
                    has_short_regex = true;
                } else width_complete = false;
                free(bytes);
            } else if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp &&
                       (pattern->modifiers == (YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE) || pattern->modifiers == (YX_MOD_WIDE | YX_MOD_NOCASE))) {
                /* A two-branch case-insensitive prefix pair contributes
                   eight certain atoms: two one-byte and two wide variants
                   of the prefix, plus four two-byte ASCII variants. Once
                   these and other literal atoms exceed Teddy's capacity,
                   YARA-X verifies the ASCII hit before its wide twin. */
                const char *regexp = pattern->regexp;
                const char *bar = strchr(regexp, '|');
                bool width_known = false;
                if (bar && !strchr(bar + 1, '|')) {
                    size_t left = (size_t)(bar - regexp);
                    size_t right = strlen(bar + 1);
                    const char *shorter = left == 1 && right == 2 ? regexp : left == 2 && right == 1 ? bar + 1 : NULL;
                    const char *longer = shorter == regexp ? bar + 1 : regexp;
                    if (shorter) {
                        unsigned char first = (unsigned char)shorter[0];
                        unsigned char lead = (unsigned char)longer[0];
                        unsigned char tail = (unsigned char)longer[1];
                        if (first >= 'A' && first <= 'Z') first += 'a' - 'A';
                        if (lead >= 'A' && lead <= 'Z') lead += 'a' - 'A';
                        if (tail >= 'A' && tail <= 'Z') tail += 'a' - 'A';
                        if (first >= '0' && first <= '9' && lead == first && tail >= '0' && tail <= '9') {
                            uint8_t prefix = first;
                            uint8_t pair[2] = {first, tail};
                            uint8_t wide_prefix[2] = {first, 0};
                            uint8_t wide_pair[4] = {first, 0, tail, 0};
                            has_short_regex = true;
                            width_known = true;
                            if (pattern->modifiers & YX_MOD_ASCII) {
                                yx_add_known_atom(atoms, lengths, &count, &prefix, 1, &shortest);
                                yx_add_known_atom(atoms, lengths, &count, pair, 2, &shortest);
                            }
                            yx_add_known_atom(atoms, lengths, &count, wide_prefix, 2, &shortest);
                            yx_add_known_atom(atoms, lengths, &count, wide_pair, 4, &shortest);
                        } else if (pattern->modifiers & YX_MOD_ASCII && first >= 'a' && first <= 'z' && lead == first && tail >= 'a' && tail <= 'z') {
                            has_short_regex = true;
                            width_known = true;
                            for (unsigned a = 0; a < 2; ++a) {
                                uint8_t prefix = (uint8_t)(first - (a ? 'a' - 'A' : 0));
                                uint8_t wide_prefix[2] = {prefix, 0};
                                yx_add_known_atom(atoms, lengths, &count, &prefix, 1, &shortest);
                                yx_add_known_atom(atoms, lengths, &count, wide_prefix, 2, &shortest);
                                for (unsigned b = 0; b < 2; ++b) {
                                    uint8_t pair[2] = {prefix, (uint8_t)(tail - (b ? 'a' - 'A' : 0))};
                                    yx_add_known_atom(atoms, lengths, &count, pair, 2, &shortest);
                                }
                            }
                        }
                    }
                }
                if (!width_known) width_complete = false;
                else if (rule->pattern_count == 1 && !all_patterns && counted_regex_count < 17) counted_regex[counted_regex_count++] = pattern;
            } else if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp && !(pattern->modifiers & ~(YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE))) {
                const char *regexp = pattern->regexp;
                const char *branch = regexp;
                bool valid = true, alternation = false;
                if (pattern->modifiers == (YX_MOD_ASCII | YX_MOD_WIDE) && yx_add_lazy_class_pair_atoms(regexp, atoms, lengths, &count, &shortest)) {
                    has_short_regex = true;
                    if (rule->pattern_count == 1 && !all_patterns && counted_regex_count < 17) counted_regex[counted_regex_count++] = pattern;
                    continue;
                }
                if (!(pattern->modifiers & YX_MOD_WIDE) && yx_add_class_repeat_atoms(regexp, pattern->modifiers, atoms, lengths, &count, &shortest)) {
                    has_short_regex = true;
                    if (rule->pattern_count == 1 && !all_patterns && counted_regex_count < 17) counted_regex[counted_regex_count++] = pattern;
                    continue;
                }
                if (pattern->modifiers & YX_MOD_NOCASE) {
                    width_complete = false;
                    continue;
                }
                for (const char *p = regexp;; ++p) {
                    unsigned char ch = (unsigned char)*p;
                    if (ch != '|' && ch != '\0') {
                        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) || (!text_variants && (size_t)(p - branch) >= 4)) {
                            valid = false;
                            break;
                        }
                        continue;
                    }
                    if (p == branch) {
                        valid = false;
                        break;
                    }
                    if (ch == '\0') break;
                    alternation = true;
                    branch = p + 1;
                }
                if (!valid || (!text_variants && !alternation)) {
                    if (text_variants && yx_add_gap_literal_atom(pattern, atoms, lengths, &count, &shortest)) {
                        has_short_regex = true;
                        if (rule->pattern_count == 1 && !all_patterns && counted_regex_count < 17) counted_regex[counted_regex_count++] = pattern;
                    } else width_complete = false;
                    continue;
                }
                has_short_regex = true;
                branch = regexp;
                for (const char *p = regexp;; ++p) {
                    if (*p != '|' && *p != '\0') continue;
                    size_t length = (size_t)(p - branch);
                    if (text_variants) {
                        YRX_PATTERN literal = *pattern;
                        literal.bytes = (uint8_t *)branch;
                        literal.length = length;
                        for (unsigned variant = 0; variant < 2; ++variant) {
                            bool wide = variant != 0;
                            if (wide ? !(pattern->modifiers & YX_MOD_WIDE) : ((pattern->modifiers & YX_MOD_WIDE) && !(pattern->modifiers & YX_MOD_ASCII))) continue;
                            uint8_t selected[4];
                            size_t width = yx_text_best_atom_bytes(&literal, wide, selected);
                            yx_add_known_atom(atoms, lengths, &count, selected, width, &shortest);
                        }
                        if (*p == '\0') break;
                        branch = p + 1;
                        continue;
                    }
                    if (!(pattern->modifiers & YX_MOD_WIDE) || (pattern->modifiers & YX_MOD_ASCII))
                        yx_add_known_atom(atoms, lengths, &count, (const uint8_t *)branch, length, &shortest);
                    /* The complete UTF-16LE literal is the atom when it is
                       no longer than the four-byte atom size. */
                    if ((pattern->modifiers & YX_MOD_WIDE) && length <= 4) {
                        uint8_t wide[4] = {0};
                        size_t atom_characters = length < 2 ? length : 2;
                        for (size_t k = 0; k < atom_characters; ++k) wide[2 * k] = (uint8_t)branch[k];
                        yx_add_known_atom(atoms, lengths, &count, wide, 2 * atom_characters, &shortest);
                    }
                    if (*p == '\0') break;
                    branch = p + 1;
                }
                if (rule->pattern_count == 1 && !all_patterns && counted_regex_count < 17) counted_regex[counted_regex_count++] = pattern;
            } else width_complete = false;
        }
    }
    /* A complete set of known atoms with no one-byte member cannot enter
       the 16-byte Teddy path. Zero leaves the normal conservative behavior. */
    if (text_variants) *minimum_width_hint = shortest != SIZE_MAX && (shortest == 1 || width_complete) ? shortest : 0;
    else *minimum_width_hint = width_complete && shortest != SIZE_MAX && shortest >= 2 ? 2 : 0;
    /* Wider atoms allow up to 64 Teddy entries. Keep the legacy regexp
       hint saturated at 17 while text ties distinguish that second limit. */
    /* An unmodeled pattern can contribute enough atoms to force fallback.
       Preserve the old ASCII tie in that case rather than assume capacity. */
    if (text_variants && (!width_complete || count > 64)) return 65;
    if (has_short_regex && shortest == 1) {
        /* The ordinary regexp hint retains its existing 16-entry boundary. */
        return !text_variants && count > 16 ? 17 : count;
    }
    return 0;
}

static bool yx_pattern_uses_fixed_at_atom(const YRX_PATTERN *pattern)
{
    /* An alternation of literals: c_alternation_literal anchors each, with
     * nocase too. */
    if (pattern->rx_literals) return true;
    if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp && (pattern->modifiers & YX_MOD_NOCASE) &&
        !(pattern->modifiers & (YX_MOD_XOR | YX_MOD_BASE64 | YX_MOD_BASE64WIDE)))
        return yx_ser_regexp_literal_caseless(pattern->regexp);
    if (pattern->modifiers & (YX_MOD_NOCASE | YX_MOD_XOR | YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) return false;
    if (pattern->kind == YX_PATTERN_TEXT) return true;
    if (pattern->kind == YX_PATTERN_HEX) {
        if (pattern->hex_has_jump || !pattern->mask) return false;
        for (size_t i = 0; i < pattern->length; ++i)
            if (pattern->mask[i] != 0xff) return false;
        return true;
    }
    if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp) return yx_ser_regexp_literal_atoms(pattern->regexp);
    return false;
}

static bool yx_compat_optional_string_equal(const char *a, const char *b)
{
    return a && b ? strcmp(a, b) == 0 : a == b;
}

/* Pattern IDs are shared by equal pattern IR across the complete ruleset.
 * Only the source-independent parts of a pattern participate in this test. */
static bool yx_compat_same_pattern(const YRX_PATTERN *a, const YRX_PATTERN *b, bool same_rule)
{
    if (a->kind != b->kind || a->modifiers != b->modifiers || a->compat_nonanchorable != b->compat_nonanchorable || a->fixed_at_enabled != b->fixed_at_enabled ||
        (a->fixed_at_enabled && a->fixed_at_offset != b->fixed_at_offset) || a->fast_scan_needs_all != b->fast_scan_needs_all ||
        a->fast_count_enabled != b->fast_count_enabled || (a->fast_count_enabled && a->fast_count_threshold != b->fast_count_threshold))
        return false;
    if (a->kind == YX_PATTERN_TEXT) {
        const yx_archived_literal_prefilter *left = &a->archived_literal_prefilter, *right = &b->archived_literal_prefilter;
        if (left->count != right->count || (!left->atoms != !right->atoms)) return false;
        for (size_t i = 0; i < left->count; ++i) {
            const yx_archived_literal_atom *x = &left->atoms[i], *y = &right->atoms[i];
            if (x->length != y->length || x->backtrack != y->backtrack || x->exact != y->exact || memcmp(x->bytes, y->bytes, x->length)) return false;
        }
        return a->length == b->length && (!a->length || (a->bytes && b->bytes && memcmp(a->bytes, b->bytes, a->length) == 0)) && a->xor_min == b->xor_min &&
               a->xor_max == b->xor_max && yx_compat_optional_string_equal(a->base64_alphabet, b->base64_alphabet) &&
               yx_compat_optional_string_equal(a->base64wide_alphabet, b->base64wide_alphabet);
    }
    /* Regex and hex IR can acquire rule-specific filesize/header bounds.
     * Reuse their IDs within a rule, where those constraints are shared. */
    if (!same_rule) return false;
    if (a->kind == YX_PATTERN_REGEX) return yx_compat_optional_string_equal(a->regexp, b->regexp);
    if (a->kind == YX_PATTERN_HEX && !a->hex_has_jump && !b->hex_has_jump && a->length == b->length && a->bytes && b->bytes && a->mask && b->mask)
        return memcmp(a->bytes, b->bytes, a->length) == 0 && memcmp(a->mask, b->mask, a->length) == 0;
    return false;
}

/* The reference searches all atoms of a compiled rule set with one Teddy
 * searcher when there are at most 64 atoms (16 for one-byte atoms) and no
 * empty atom, and with Aho-Corasick otherwise. Teddy reports matches by
 * start, bucket and atom id, which decides ties between sub-patterns of a
 * pattern. Atoms of patterns shared by several rules are counted once, and
 * a literal anchored at an offset (`$a at 10`) is verified there and has no
 * atom (Compiler::add_sub_pattern). A pattern whose atoms are not modeled
 * leaves the search unknown, unless the atoms of the others already rule
 * Teddy out: atoms are only ever added.
 * False when out of memory: without the order, chains would report other
 * matches. */

/* Whether two rules give their regexp and hex patterns the same filesize
 * bounds and header constraints (yx_view_constraints_build, on first use):
 * 1 equal, 0 different, 2 not known, -1 out of memory. */
typedef struct yx_view_sharing yx_view_sharing;
static yx_view_sharing *yx_view_sharing_new(const YRX_RULES *rules);
static int yx_view_sharing_rules(yx_view_sharing *sharing, size_t rule, size_t other);
static void yx_view_sharing_free(yx_view_sharing *sharing);
static bool yx_hex_atoms_equal(const yx_hex_atom *x, size_t x_count, const yx_hex_atom *y, size_t y_count, unsigned depth);

/* Equal regexp or hex patterns but for their rules' constraints: with those
 * equal too, Compiler::c_rule gives both one PatternId. */
static bool yx_view_same_regexp_pattern(const YRX_PATTERN *a, const YRX_PATTERN *b)
{
    if (a->kind != b->kind || a->modifiers != b->modifiers || a->compat_nonanchorable != b->compat_nonanchorable || a->fixed_at_enabled != b->fixed_at_enabled ||
        (a->fixed_at_enabled && a->fixed_at_offset != b->fixed_at_offset) || a->fast_scan_needs_all != b->fast_scan_needs_all ||
        a->fast_count_enabled != b->fast_count_enabled || (a->fast_count_enabled && a->fast_count_threshold != b->fast_count_threshold))
        return false;
    if (a->kind == YX_PATTERN_HEX) return a->hex_atoms && b->hex_atoms && yx_hex_atoms_equal(a->hex_atoms, a->hex_atom_count, b->hex_atoms, b->hex_atom_count, 0);
    return a->kind == YX_PATTERN_REGEX && a->regexp && b->regexp && !strcmp(a->regexp, b->regexp);
}

/* Regexp and hex patterns whose atoms were counted, to find their copies in
 * later rules. Past this many, a copy counts as a pattern of its own. */
#define YX_VIEW_COUNTED_PATTERNS 512

static bool yx_view_atom_order(YRX_SCANNER *scanner)
{
    yx_rx_atom *all = NULL, *atoms = NULL;
    size_t all_count = 0, all_capacity = 0, count = 0;
    /* Atoms of copies that share the earlier pattern's atoms or do not,
     * depending on rule constraints that are not known. */
    size_t unsure_count = 0;
    yx_view_sharing *sharing = NULL;
    struct {
        const YRX_PATTERN *pattern;
        size_t rule, index;
    } *counted = NULL;
    size_t counted_count = 0;
    size_t *first = NULL, *buckets = NULL, total_patterns = 0, minimum_len = 0;
    const yx_rx_atom **pointers = NULL;
    bool known = true, empty = false, oom = false, one_byte = false;
    for (size_t i = 0; i < scanner->rules->rule_count; ++i) total_patterns += scanner->views[i].pattern_count;
    first = calloc(total_patterns ? total_patterns : 1, sizeof(*first));
    size_t *first_with_id = malloc((total_patterns ? total_patterns : 1) * sizeof(*first_with_id));
    /* Atoms per pattern: hex chains have no program to count them from. */
    size_t *counts = calloc(total_patterns ? total_patterns : 1, sizeof(*counts));
    counted = malloc(YX_VIEW_COUNTED_PATTERNS * sizeof(*counted));
    if (!first || !first_with_id || !counts || !counted) {
        free(first);
        free(first_with_id);
        free(counts);
        free(counted);
        return false;
    }
    for (size_t k = 0; k < total_patterns; ++k) first_with_id[k] = SIZE_MAX;
    size_t index = 0;
    /* Only a set of at most 64 atoms is used, and the count never shrinks:
     * the atoms of later patterns are not needed once it has more. */
    for (size_t i = 0; !oom && all_count - unsure_count <= 64 && i < scanner->rules->rule_count; ++i) {
        YRX_RULE *view = &scanner->views[i];
        for (size_t j = 0; !oom && all_count - unsure_count <= 64 && j < view->pattern_count; ++j, ++index) {
            YRX_PATTERN *pattern = &view->patterns[j];
            bool unsure = false;
            first[index] = SIZE_MAX;
            /* An earlier identical pattern supplies the atoms. */
            size_t id = pattern->compat_pattern_id;
            if (id < total_patterns && first_with_id[id] != SIZE_MAX) {
                first[index] = first[first_with_id[id]];
                counts[index] = counts[first_with_id[id]];
                continue;
            }
            /* So does an equal regexp or hex pattern of an earlier rule
             * with the same constraints. */
            if (pattern->kind != YX_PATTERN_TEXT) {
                size_t k = 0;
                int same = 0;
                for (; k < counted_count; ++k) {
                    if (counted[k].rule == i || !yx_view_same_regexp_pattern(counted[k].pattern, pattern)) continue;
                    if (!sharing) sharing = yx_view_sharing_new(scanner->rules);
                    same = sharing ? yx_view_sharing_rules(sharing, i, counted[k].rule) : -1;
                    if (same == 1 || same < 0) break;
                    if (same == 2) unsure = true;
                }
                if (same < 0) {
                    oom = true;
                    break;
                }
                if (same == 1) {
                    first[index] = first[counted[k].index];
                    counts[index] = counts[counted[k].index];
                    if (id < total_patterns) first_with_id[id] = counted[k].index;
                    continue;
                }
                if (counted_count < YX_VIEW_COUNTED_PATTERNS) {
                    counted[counted_count].pattern = pattern;
                    counted[counted_count].rule = i;
                    counted[counted_count++].index = index;
                } else unsure = true;
            }
            if (id < total_patterns) first_with_id[id] = index;
            if (pattern->fixed_at_enabled && !pattern->rx_program) {
                first[index] = all_count;
                continue;
            }
            int modeled = yx_ser_search_atoms_status(pattern, &atoms, &count);
            if (modeled != 1) {
                known = false;
                oom = modeled < 0;
                if (id < total_patterns) first_with_id[id] = SIZE_MAX;
                if (oom) break;
                continue;
            }
            first[index] = all_count;
            counts[index] = count;
            if (all_count + count > all_capacity) {
                size_t next = (all_count + count) * 2;
                yx_rx_atom *grown = realloc(all, next * sizeof(*grown));
                if (!grown) {
                    known = false;
                    oom = true;
                    free(atoms);
                    break;
                }
                all = grown;
                all_capacity = next;
            }
            for (size_t a = 0; a < count; ++a) {
                if (!atoms[a].length) empty = true;
                if (atoms[a].length == 1) one_byte = true;
                all[all_count++] = atoms[a];
            }
            if (unsure) unsure_count += count;
            free(atoms);
            atoms = NULL;
        }
    }
    /* Aho-Corasick for certain, also with atoms that are not modeled. A
     * copy that may share its atoms has the atoms of the pattern it copies:
     * Teddy with them is Teddy without them. */
    size_t least = all_count - unsure_count;
    bool automaton = !oom && (least > 64 || empty || (one_byte && least > 16) || (known && !all_count));
    bool teddy = false;
    if (!oom && known && all_count && all_count <= 64 && !empty) {
        pointers = calloc(all_count, sizeof(*pointers));
        buckets = calloc(all_count, sizeof(*buckets));
        if (!pointers || !buckets) oom = true;
        if (pointers && buckets) {
            for (size_t a = 0; a < all_count; ++a) pointers[a] = &all[a];
            yx_rx_teddy_buckets(pointers, all_count, buckets, &minimum_len);
            if (!(minimum_len == 16 && all_count > 16)) {
                teddy = true;
                index = 0;
                for (size_t i = 0; i < scanner->rules->rule_count; ++i)
                    for (size_t j = 0; j < scanner->views[i].pattern_count; ++j, ++index) {
                        YRX_PATTERN *pattern = &scanner->views[i].patterns[j];
                        const yx_rx_program *program = pattern->rx_program;
                        size_t n = 0;
                        /* A chain of sub-patterns orders its pieces' matches
                         * with these (yx_hc_join_scan). */
                        if (first[index] == SIZE_MAX) continue;
                        if (!program) {
                            int chain = pattern->kind == YX_PATTERN_HEX ? yx_ser_hex_chain_status(pattern) : yx_ser_regex_chain_status(pattern);
                            if (chain < 0) oom = true;
                            if (chain <= 0) continue;
                        }
                        if (!program) n = counts[index];
                        for (size_t s = 0; program && s < program->sub_count; ++s) n += program->subs[s].atom_count;
                        pattern->rx_order_ids = calloc(n ? n : 1, sizeof(size_t));
                        pattern->rx_order_buckets = calloc(n ? n : 1, sizeof(size_t));
                        if (!pattern->rx_order_ids || !pattern->rx_order_buckets) {
                            free(pattern->rx_order_ids);
                            free(pattern->rx_order_buckets);
                            pattern->rx_order_ids = pattern->rx_order_buckets = NULL;
                            oom = true;
                            continue;
                        }
                        for (size_t a = 0; a < n; ++a) {
                            pattern->rx_order_ids[a] = first[index] + a;
                            pattern->rx_order_buckets[a] = buckets[first[index] + a];
                        }
                        pattern->rx_teddy = true;
                        pattern->rx_teddy_minimum = minimum_len;
                    }
            }
        }
    }
    if (!oom && (teddy || automaton))
        for (size_t i = 0; i < scanner->rules->rule_count; ++i)
            for (size_t j = 0; j < scanner->views[i].pattern_count; ++j) {
                YRX_PATTERN *pattern = &scanner->views[i].patterns[j];
                pattern->atom_search_known = true;
                pattern->atom_search_teddy = teddy;
                pattern->atom_search_minimum = teddy ? minimum_len : 0;
            }
    free(pointers);
    free(buckets);
    free(all);
    free(first);
    free(first_with_id);
    free(counts);
    free(counted);
    yx_view_sharing_free(sharing);
    return !oom;
}

/* Hash of the fields yx_compat_same_pattern compares for literals. */
static uint64_t yx_compat_pattern_hash(const YRX_PATTERN *p)
{
    uint64_t hash = 1469598103934665603ull;
    uint64_t fields[] = {(uint64_t)p->kind,
                         p->modifiers,
                         p->compat_nonanchorable,
                         p->fixed_at_enabled,
                         p->fixed_at_enabled ? p->fixed_at_offset : 0,
                         p->fast_scan_needs_all,
                         p->fast_count_enabled,
                         p->fast_count_enabled ? p->fast_count_threshold : 0,
                         p->length,
                         p->xor_min,
                         p->xor_max};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) hash = (hash ^ fields[i]) * 1099511628211ull;
    for (size_t i = 0; p->bytes && i < p->length; ++i) hash = (hash ^ p->bytes[i]) * 1099511628211ull;
    return hash;
}

/* Repeated regexp programs are common in generated rule sets. Share only
 * identical verifier inputs, including the view's cap and atom-order hints. */
static bool yx_same_scan_program(const YRX_PATTERN *a, const YRX_PATTERN *b)
{
    if (a->kind != b->kind || a->modifiers != b->modifiers || a->compat_nonanchorable != b->compat_nonanchorable || a->fixed_at_enabled != b->fixed_at_enabled ||
        (a->fixed_at_enabled && a->fixed_at_offset != b->fixed_at_offset) || a->fast_scan_needs_all != b->fast_scan_needs_all ||
        a->fast_count_enabled != b->fast_count_enabled || (a->fast_count_enabled && a->fast_count_threshold != b->fast_count_threshold) ||
        a->global_atom_count_hint != b->global_atom_count_hint || !yx_compat_optional_string_equal(a->regexp, b->regexp) ||
        !yx_compat_optional_string_equal(a->gap_head_regexp, b->gap_head_regexp) || !a->rx_program != !b->rx_program)
        return false;
    /* A regexp chain orders its matches with its own atom ids. */
    if (!a->rx_program)
        return a->kind == YX_PATTERN_REGEX && a->rx_teddy == b->rx_teddy && !a->rx_order_ids == !b->rx_order_ids &&
               (!a->rx_order_ids || a->rx_order_ids[0] == b->rx_order_ids[0]);
    const yx_rx_program *left = a->rx_program, *right = b->rx_program;
    if (left->code_length != right->code_length || left->sub_count != right->sub_count || memcmp(left->code, right->code, left->code_length) ||
        a->rx_teddy != b->rx_teddy || (a->rx_teddy && a->rx_teddy_minimum != b->rx_teddy_minimum))
        return false;
    size_t index = 0;
    for (size_t sub = 0; sub < left->sub_count; ++sub) {
        const yx_rx_sub *x = &left->subs[sub], *y = &right->subs[sub];
        if (x->flags != y->flags || x->atom_count != y->atom_count) return false;
        for (size_t i = 0; i < x->atom_count; ++i, ++index) {
            const yx_rx_atom *m = &x->atoms[i], *n = &y->atoms[i];
            if (m->length != n->length || m->exact != n->exact || m->backtrack != n->backtrack || m->has_fwd != n->has_fwd || m->has_bck != n->has_bck ||
                m->fwd != n->fwd || m->bck != n->bck || memcmp(m->bytes, n->bytes, m->length))
                return false;
            if (a->rx_teddy && ((!a->rx_order_ids != !b->rx_order_ids) ||
                                (a->rx_order_ids && (a->rx_order_ids[index] != b->rx_order_ids[index] || a->rx_order_buckets[index] != b->rx_order_buckets[index]))))
                return false;
        }
    }
    return true;
}

static void yx_build_scan_aliases(YRX_SCANNER *scanner, size_t count)
{
    size_t buckets = 64, used = 0;
    while (buckets < count && buckets <= SIZE_MAX / 2) buckets *= 2;
    size_t *heads = malloc(buckets * sizeof(*heads));
    size_t *chain = malloc((count ? count : 1) * sizeof(*chain));
    uint64_t *hashes = malloc((count ? count : 1) * sizeof(*hashes));
    YRX_PATTERN **patterns = malloc((count ? count : 1) * sizeof(*patterns));
    if (!heads || !chain || !hashes || !patterns) goto done;
    for (size_t i = 0; i < buckets; ++i) heads[i] = SIZE_MAX;
    for (size_t i = 0; i < scanner->rules->rule_count; ++i)
        for (size_t j = 0; j < scanner->views[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &scanner->views[i].patterns[j];
            if (pattern->kind == YX_PATTERN_TEXT || (!pattern->rx_program && pattern->kind != YX_PATTERN_REGEX)) continue;
            uint64_t hash = yx_compat_pattern_hash(pattern);
            const uint8_t *key = pattern->rx_program ? pattern->rx_program->code : (const uint8_t *)pattern->regexp;
            size_t length = pattern->rx_program ? pattern->rx_program->code_length : pattern->regexp ? strlen(pattern->regexp) : 0;
            for (size_t k = 0; k < length; ++k) hash = (hash ^ key[k]) * 1099511628211ull;
            size_t bucket = (size_t)hash & (buckets - 1);
            for (size_t at = heads[bucket]; at != SIZE_MAX; at = chain[at])
                if (hashes[at] == hash && yx_same_scan_program(pattern, patterns[at])) {
                    pattern->scan_duplicate = patterns[at];
                    break;
                }
            if (pattern->scan_duplicate) continue;
            patterns[used] = pattern;
            hashes[used] = hash;
            chain[used] = heads[bucket];
            heads[bucket] = used++;
        }
done:
    free(heads);
    free(chain);
    free(hashes);
    free(patterns);
}

static uint64_t yx_hex_atoms_hash(const yx_hex_atom *atoms, size_t count, uint64_t hash, unsigned depth);
static bool yx_hex_atoms_equal(const yx_hex_atom *x, size_t x_count, const yx_hex_atom *y, size_t y_count, unsigned depth);

/* Whether YARA-X's condition analysis (Compiler::c_rule: filesize_bounds,
 * header_constraints) provably gives a rule's regexp and hex patterns no
 * filesize bounds and no header constraints: its condition has no filesize,
 * no ==, no `at` and no reference to a rule, and its namespace has no global
 * rule. False when unsure. */
static bool yx_view_rule_unconstrained(const YRX_RULES *rules, size_t index)
{
    const YRX_RULE *rule = &rules->rules[index];
    const char *text = rule->condition_text;
    if (!text || strstr(text, "==")) return false;
    for (size_t k = 0; k < rules->rule_count; ++k)
        if (rules->rules[k].is_global && rules->rules[k].namespace_index == rule->namespace_index) return false;
    for (const char *at = text; *at;) {
        if (!isalpha((unsigned char)*at) && *at != '_') {
            ++at;
            continue;
        }
        const char *word = at;
        while (isalnum((unsigned char)*at) || *at == '_') ++at;
        size_t length = (size_t)(at - word);
        if (word > text && (word[-1] == '$' || word[-1] == '#' || word[-1] == '@' || word[-1] == '!' || word[-1] == '.')) continue;
        if ((length == 8 && !strncmp(word, "filesize", 8)) || (length == 2 && !strncmp(word, "at", 2))) return false;
        for (size_t k = 0; k < rules->rule_count; ++k) {
            const char *name = rules->rules[k].identifier;
            if (name && strlen(name) == length && !strncmp(name, word, length)) return false;
        }
    }
    return true;
}

/* The constraints Compiler::c_rule gives each rule's regexp and hex patterns:
 * the condition's filesize bounds and header constraints, with those of the
 * rules it requires and of the namespace's global rules so far. */
typedef struct {
    const YRX_RULES *rules;
    yx_rule_constraints *constraints; /* one per rule */
    signed char *known;               /* 1 when constraints[i] is exact */
    size_t *names, name_buckets;      /* (namespace, identifier) -> rule */
    size_t current;
    uint8_t *literal; /* the last regexp literal handed out */
    bool oom;
    bool unknown_rule; /* the current rule requires one whose constraints are not known */
} yx_view_constraints;

static uint64_t yx_view_rule_name_hash(size_t namespace_index, const char *name)
{
    uint64_t hash = 1469598103934665603ull ^ (uint64_t)namespace_index;
    hash *= 1099511628211ull;
    for (const unsigned char *at = (const unsigned char *)name; *at; ++at) hash = (hash ^ *at) * 1099511628211ull;
    return hash;
}

static const yx_rule_constraints *yx_view_constraints_rule(void *user, const char *name)
{
    yx_view_constraints *c = user;
    const YRX_RULE *rule = &c->rules->rules[c->current];
    /* A global variable hides a rule of the same name. */
    for (size_t g = 0; g < c->rules->global_count; ++g)
        if (c->rules->globals[g].name && !strcmp(c->rules->globals[g].name, name)) return NULL;
    for (size_t at = (size_t)yx_view_rule_name_hash(rule->namespace_index, name) & (c->name_buckets - 1); c->names[at] != SIZE_MAX;
         at = (at + 1) & (c->name_buckets - 1)) {
        const YRX_RULE *other = &c->rules->rules[c->names[at]];
        if (other->namespace_index == rule->namespace_index && !strcmp(other->identifier, name)) {
            if (c->known[c->names[at]] <= 0) c->unknown_rule = true;
            return c->known[c->names[at]] > 0 ? &c->constraints[c->names[at]] : NULL;
        }
    }
    return NULL;
}

/* The bytes `$name at 0` requires at the start of the data: a text literal,
 * or a hex pattern or regexp that is one literal (Hir::as_literal_bytes),
 * without xor, nocase, wide or base64 modifiers. */
static bool yx_view_constraints_pattern(void *user, const char *name, const uint8_t **bytes, size_t *length)
{
    yx_view_constraints *c = user;
    const YRX_RULE *rule = &c->rules->rules[c->current];
    for (size_t j = 0; j < rule->pattern_count; ++j) {
        const YRX_PATTERN *pattern = &rule->patterns[j];
        const char *identifier = pattern->identifier;
        if (!identifier) continue;
        if (*identifier == '$') ++identifier;
        if (strcmp(identifier, name)) continue;
        if (pattern->modifiers & (YX_MOD_XOR | YX_MOD_NOCASE | YX_MOD_WIDE | YX_MOD_BASE64 | YX_MOD_BASE64WIDE)) return false;
        if (pattern->kind == YX_PATTERN_TEXT) {
            *bytes = pattern->bytes;
            *length = pattern->bytes ? pattern->length : 0;
            return true;
        }
        if (pattern->kind == YX_PATTERN_HEX) {
            if (pattern->hex_has_jump || !pattern->bytes || !pattern->mask) return false;
            for (size_t k = 0; k < pattern->length; ++k)
                if (pattern->mask[k] != 0xff) return false;
            *bytes = pattern->bytes;
            *length = pattern->length;
            return true;
        }
        if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp) {
            free(c->literal);
            c->literal = NULL;
            int literal = yx_ser_regexp_literal(pattern, &c->literal, length);
            if (literal < 0) c->oom = true;
            if (literal != 1) return false;
            *bytes = c->literal;
            return true;
        }
        return false;
    }
    return false;
}

static void yx_view_constraints_free(yx_view_constraints *c, size_t rule_count)
{
    for (size_t i = 0; c->constraints && i < rule_count; ++i) free(c->constraints[i].header);
    free(c->constraints);
    free(c->known);
    free(c->names);
    free(c->literal);
    memset(c, 0, sizeof(*c));
}

static bool yx_view_rule_unconstrained(const YRX_RULES *rules, size_t index);

/* Fills c for every rule, in declaration order. False when out of memory. */
static bool yx_view_constraints_build(yx_view_constraints *c, const YRX_RULES *rules)
{
    size_t count = rules->rule_count, namespaces = 1;
    yx_rule_constraints *globals = NULL;
    signed char *globals_known = NULL;
    bool ok = false;
    memset(c, 0, sizeof(*c));
    c->rules = rules;
    c->name_buckets = 64;
    while (c->name_buckets < count * 2) c->name_buckets *= 2;
    for (size_t i = 0; i < count; ++i)
        if (rules->rules[i].namespace_index >= namespaces) namespaces = rules->rules[i].namespace_index + 1;
    c->constraints = calloc(count ? count : 1, sizeof(*c->constraints));
    c->known = calloc(count ? count : 1, 1);
    c->names = malloc(c->name_buckets * sizeof(*c->names));
    globals = calloc(namespaces, sizeof(*globals));
    globals_known = malloc(namespaces);
    if (!c->constraints || !c->known || !c->names || !globals || !globals_known) goto done;
    for (size_t b = 0; b < c->name_buckets; ++b) c->names[b] = SIZE_MAX;
    memset(globals_known, 1, namespaces);
    for (size_t i = 0; i < count; ++i) {
        const YRX_RULE *rule = &rules->rules[i];
        yx_rule_constraints *own = &c->constraints[i], *global = &globals[rule->namespace_index];
        c->current = i;
        c->unknown_rule = false;
        if (rule->condition) {
            if (!yx_condition_rule_constraints(rule->condition, yx_view_constraints_rule, yx_view_constraints_pattern, c, own) || c->oom) goto done;
            c->known[i] = c->unknown_rule ? -1 : 1;
        } else {
            /* No parsed condition: exact only when its text provably
             * imposes nothing. */
            c->known[i] = yx_view_rule_unconstrained(rules, i) ? 1 : -1;
        }
        if (rule->is_global) {
            if (c->known[i] < 0) globals_known[rule->namespace_index] = 0;
            else if (!yx_rule_constraints_merge(global, own)) goto done;
            free(own->header);
            memset(own, 0, sizeof(*own));
            if (!yx_rule_constraints_merge(own, global)) goto done;
        } else if (!yx_rule_constraints_merge(own, global)) goto done;
        if (!globals_known[rule->namespace_index]) c->known[i] = -1;
        if (rule->identifier) {
            size_t at = (size_t)yx_view_rule_name_hash(rule->namespace_index, rule->identifier) & (c->name_buckets - 1);
            while (c->names[at] != SIZE_MAX) at = (at + 1) & (c->name_buckets - 1);
            c->names[at] = i;
        }
    }
    ok = true;
done:
    for (size_t n = 0; globals && n < namespaces; ++n) free(globals[n].header);
    free(globals);
    free(globals_known);
    if (!ok) yx_view_constraints_free(c, count);
    return ok;
}

struct yx_view_sharing {
    const YRX_RULES *rules;
    yx_view_constraints constraints;
    bool built, failed;
};

static yx_view_sharing *yx_view_sharing_new(const YRX_RULES *rules)
{
    yx_view_sharing *sharing = calloc(1, sizeof(*sharing));
    if (sharing) sharing->rules = rules;
    return sharing;
}

static int yx_view_sharing_rules(yx_view_sharing *sharing, size_t rule, size_t other)
{
    if (!sharing->built && !sharing->failed) sharing->failed = !(sharing->built = yx_view_constraints_build(&sharing->constraints, sharing->rules));
    if (!sharing->built) return -1;
    if (sharing->constraints.known[rule] <= 0 || sharing->constraints.known[other] <= 0) return 2;
    return yx_rule_constraints_equal(&sharing->constraints.constraints[rule], &sharing->constraints.constraints[other]) ? 1 : 0;
}

static void yx_view_sharing_free(yx_view_sharing *sharing)
{
    if (!sharing) return;
    if (sharing->built) yx_view_constraints_free(&sharing->constraints, sharing->rules->rule_count);
    free(sharing);
}

/* YARA-X gives equal patterns of the whole rule set one PatternId
 * (Compiler::c_rule, lib/src/compiler/mod.rs), so their atoms enter the
 * automaton once; a regexp or hex pattern's equality includes the filesize
 * bounds and header constraints of its rule. Equal chain patterns of one
 * rule, or of two rules with equal constraints, share the earlier pattern's
 * id. False when out of memory. */
static bool yx_view_share_chains(YRX_SCANNER *scanner)
{
    size_t total = 0, used = 0;
    size_t rule_count = scanner->rules->rule_count;
    yx_view_constraints constraints = {0};
    bool built = false, ok = false;
    for (size_t i = 0; i < rule_count; ++i) total += scanner->views[i].pattern_count;
    YRX_PATTERN **items = malloc((total ? total : 1) * sizeof(*items));
    size_t *rule_of = malloc((total ? total : 1) * sizeof(*rule_of));
    uint64_t *hashes = malloc((total ? total : 1) * sizeof(*hashes));
    size_t buckets = 64;
    while (buckets < total * 2) buckets *= 2;
    size_t *heads = malloc(buckets * sizeof(*heads)), *next = malloc((total ? total : 1) * sizeof(*next));
    if (!items || !rule_of || !hashes || !heads || !next) goto done;
    for (size_t b = 0; b < buckets; ++b) heads[b] = SIZE_MAX;
    for (size_t i = 0; i < rule_count; ++i) {
        YRX_RULE *view = &scanner->views[i];
        for (size_t j = 0; j < view->pattern_count; ++j) {
            YRX_PATTERN *pattern = &view->patterns[j];
            if (pattern->kind == YX_PATTERN_TEXT) continue;
            int chain = pattern->kind == YX_PATTERN_HEX ? yx_ser_hex_chain_status(pattern) : yx_ser_regex_chain_status(pattern);
            if (chain < 0) goto done;
            if (!chain) continue;
            uint64_t hash = 1469598103934665603ull ^ pattern->modifiers ^ ((uint64_t)pattern->kind << 32);
            if (pattern->kind == YX_PATTERN_HEX) hash = yx_hex_atoms_hash(pattern->hex_atoms, pattern->hex_atom_count, hash, 0);
            else
                for (const unsigned char *at = (const unsigned char *)pattern->regexp; *at; ++at) hash = (hash ^ *at) * 1099511628211ull;
            /* Equal chains with other constraints go to other buckets. */
            if (!built) {
                if (!yx_view_constraints_build(&constraints, scanner->rules)) goto done;
                built = true;
            }
            if (constraints.known[i] > 0) {
                const yx_rule_constraints *own = &constraints.constraints[i];
                uint64_t fields[] = {own->lower_kind, own->lower_kind ? (uint64_t)own->lower : 0, own->upper_kind, own->upper_kind ? (uint64_t)own->upper : 0,
                                     own->header_kind};
                for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); ++f) hash = (hash ^ fields[f]) * 1099511628211ull;
                for (size_t f = 0; own->header_kind == 2 && f < own->header_length; ++f) hash = (hash ^ own->header[f]) * 1099511628211ull;
            } else hash = (hash ^ (uint64_t)i ^ 0x9e3779b97f4a7c15ull) * 1099511628211ull;
            bool shared = false;
            for (size_t k = heads[hash & (buckets - 1)]; k != SIZE_MAX; k = next[k]) {
                const YRX_PATTERN *other = items[k];
                if (hashes[k] != hash || other->kind != pattern->kind || other->modifiers != pattern->modifiers ||
                    other->compat_nonanchorable != pattern->compat_nonanchorable || other->fixed_at_enabled != pattern->fixed_at_enabled ||
                    (other->fixed_at_enabled && other->fixed_at_offset != pattern->fixed_at_offset) || other->fast_scan_needs_all != pattern->fast_scan_needs_all ||
                    other->fast_count_enabled != pattern->fast_count_enabled ||
                    (other->fast_count_enabled && other->fast_count_threshold != pattern->fast_count_threshold) ||
                    (pattern->kind == YX_PATTERN_HEX ? !yx_hex_atoms_equal(other->hex_atoms, other->hex_atom_count, pattern->hex_atoms, pattern->hex_atom_count, 0)
                                                     : strcmp(other->regexp, pattern->regexp)))
                    continue;
                if (rule_of[k] != i) {
                    if (constraints.known[i] <= 0 || constraints.known[rule_of[k]] <= 0 ||
                        !yx_rule_constraints_equal(&constraints.constraints[i], &constraints.constraints[rule_of[k]]))
                        continue;
                }
                pattern->compat_pattern_id = other->compat_pattern_id;
                shared = true;
                break;
            }
            /* Equality is transitive: only the first of each class is kept. */
            if (shared) continue;
            items[used] = pattern;
            rule_of[used] = i;
            hashes[used] = hash;
            next[used] = heads[hash & (buckets - 1)];
            heads[hash & (buckets - 1)] = used++;
        }
    }
    ok = true;
done:
    if (built) yx_view_constraints_free(&constraints, rule_count);
    free(items);
    free(rule_of);
    free(hashes);
    free(heads);
    free(next);
    return ok;
}

/* The pattern views of one rule and the condition queries that set their
 * scan strategy (yx_make_views). The queries are answered for all patterns
 * of the rule at once (yx_condition_pattern_queries); the per-pattern
 * functions are the reference and the fallback when that runs out of
 * memory. Built with YX_CONDITION_QUERY_CHECK, every answer is compared
 * with them. */
typedef struct {
    const YRX_RULE *source;
    YRX_RULE *view;
} yx_view_query_job;
static void yx_view_query_one(const YRX_RULE *source, size_t j, YRX_PATTERN *pattern)
{
    pattern->fast_scan_needs_all = yx_condition_pattern_requires_all_matches(source->condition, source->patterns[j].identifier);
    pattern->fixed_at_enabled = yx_pattern_uses_fixed_at_atom(&source->patterns[j]) &&
                                yx_condition_pattern_fixed_at(source->condition, source->patterns[j].identifier, &pattern->fixed_at_offset);
    pattern->fast_count_enabled = yx_condition_pattern_fast_count(source->condition, source->patterns[j].identifier, &pattern->fast_count_threshold);
    pattern->compat_nonanchorable = yx_condition_pattern_nonanchorable(source->condition, source->patterns[j].identifier, pattern->fixed_at_enabled);
}
static void yx_view_query_patterns(void *data)
{
    yx_view_query_job *job = data;
    const YRX_RULE *source = job->source;
    YRX_RULE *view = job->view;
    size_t count = source->pattern_count;
    const char **names = malloc(count * sizeof(*names));
    yx_condition_pattern_answers *answers = malloc(count * sizeof(*answers));
    bool batched = names && answers;
    for (size_t j = 0; batched && j < count; ++j) names[j] = source->patterns[j].identifier;
    if (batched) batched = yx_condition_pattern_queries(source->condition, names, count, answers);
    for (size_t j = 0; j < count; ++j) {
        YRX_PATTERN *pattern = &view->patterns[j];
        *pattern = source->patterns[j];
        pattern->matches = NULL;
        pattern->match_count = 0;
        pattern->match_capacity = 0;
        if (!batched) {
            yx_view_query_one(source, j, pattern);
        } else {
            pattern->fast_scan_needs_all = answers[j].requires_all;
            pattern->fixed_at_enabled = yx_pattern_uses_fixed_at_atom(&source->patterns[j]) && answers[j].fixed_at;
            if (pattern->fixed_at_enabled) pattern->fixed_at_offset = answers[j].fixed_at_offset;
            pattern->fast_count_enabled = answers[j].fast_count;
            if (answers[j].fast_count) pattern->fast_count_threshold = answers[j].fast_count_threshold;
            pattern->compat_nonanchorable = answers[j].nonanchorable;
#ifdef YX_CONDITION_QUERY_CHECK
            {
                YRX_PATTERN reference = source->patterns[j];
                yx_view_query_one(source, j, &reference);
                if (reference.fast_scan_needs_all != pattern->fast_scan_needs_all || reference.fixed_at_enabled != pattern->fixed_at_enabled ||
                    (reference.fixed_at_enabled && reference.fixed_at_offset != pattern->fixed_at_offset) ||
                    reference.fast_count_enabled != pattern->fast_count_enabled ||
                    (reference.fast_count_enabled && reference.fast_count_threshold != pattern->fast_count_threshold) ||
                    reference.compat_nonanchorable != pattern->compat_nonanchorable) {
                    fprintf(stderr,
                            "YX_CONDITION_QUERY_CHECK mismatch: rule %s pattern %s "
                            "all %d/%d fixed %d/%d@%zu/%zu count %d/%d@%zu/%zu nonanch %d/%d\n",
                            source->identifier, source->patterns[j].identifier, reference.fast_scan_needs_all, pattern->fast_scan_needs_all, reference.fixed_at_enabled,
                            pattern->fixed_at_enabled, reference.fixed_at_offset, pattern->fixed_at_offset, reference.fast_count_enabled, pattern->fast_count_enabled,
                            reference.fast_count_threshold, pattern->fast_count_threshold, reference.compat_nonanchorable, pattern->compat_nonanchorable);
                    abort();
                }
            }
#endif
        }
        /* A one-match limit (`#a` used as a Boolean) is YARA-X's
         * default fast-scan limit: the pattern is that of a bare `$a`. */
        if (pattern->fast_count_enabled && pattern->fast_count_threshold <= 1) {
            pattern->fast_count_enabled = false;
            pattern->fast_scan_needs_all = false;
        }
    }
    free(names);
    free(answers);
}
static bool yx_make_views(YRX_SCANNER *scanner)
{
    size_t i, j, next_pattern_id = 0;
    size_t rule_count = scanner->rules->rule_count, total_patterns = 0;
    for (i = 0; i < rule_count; ++i) total_patterns += scanner->rules->rules[i].pattern_count;
    size_t buckets = 64;
    while (buckets < total_patterns * 2) buckets *= 2;
    size_t *heads = malloc(buckets * sizeof(*heads)), *tails = malloc(buckets * sizeof(*tails));
    size_t *chain = malloc((total_patterns ? total_patterns : 1) * sizeof(*chain)), item_count = 0;
    uint64_t *hashes = malloc((total_patterns ? total_patterns : 1) * sizeof(*hashes));
    const YRX_PATTERN **items = malloc((total_patterns ? total_patterns : 1) * sizeof(*items));
    scanner->views = (YRX_RULE *)calloc(rule_count ? rule_count : 1, sizeof(YRX_RULE));
    if (!scanner->views || !heads || !tails || !chain || !hashes || !items) {
        free(scanner->views);
        scanner->views = NULL;
        free(heads);
        free(tails);
        free(chain);
        free(hashes);
        free(items);
        return false;
    }
    for (size_t b = 0; b < buckets; ++b) heads[b] = tails[b] = SIZE_MAX;
    for (i = 0; i < rule_count; ++i) {
        const YRX_RULE *source = &scanner->rules->rules[i];
        YRX_RULE *view = &scanner->views[i];
        *view = *source;
        view->patterns = NULL;
        view->matched = false;
        if (!source->pattern_count) continue;
        view->patterns = (YRX_PATTERN *)calloc(source->pattern_count, sizeof(YRX_PATTERN));
        if (!view->patterns) {
            yx_destroy_views(scanner);
            free(heads);
            free(tails);
            free(chain);
            free(hashes);
            free(items);
            return false;
        }
        {
            /* The condition queries of every pattern, on one deep stack for
             * a deep condition (the queries then run in place). */
            yx_view_query_job job = {source, view};
            if (!yx_condition_run_deep(source->condition, yx_view_query_patterns, &job)) yx_view_query_patterns(&job);
        }
        for (j = 0; j < source->pattern_count; ++j) {
            view->patterns[j].prefilter_owner = SIZE_MAX;
            view->patterns[j].compat_pattern_id = next_pattern_id;
            if (view->patterns[j].kind == YX_PATTERN_TEXT) {
                /* Literal identity spans rules: the earliest equal
                 * literal, found through its hash bucket. */
                uint64_t hash = yx_compat_pattern_hash(&view->patterns[j]);
                size_t bucket = (size_t)hash & (buckets - 1);
                for (size_t at = heads[bucket]; at != SIZE_MAX; at = chain[at])
                    if (hashes[at] == hash && yx_compat_same_pattern(&view->patterns[j], items[at], false)) {
                        view->patterns[j].compat_pattern_id = items[at]->compat_pattern_id;
                        break;
                    }
                if (view->patterns[j].compat_pattern_id == next_pattern_id) {
                    items[item_count] = &view->patterns[j];
                    hashes[item_count] = hash;
                    chain[item_count] = SIZE_MAX;
                    if (heads[bucket] == SIZE_MAX) heads[bucket] = item_count;
                    else chain[tails[bucket]] = item_count;
                    tails[bucket] = item_count++;
                }
            } else {
                /* Regex and hex identity is only shared within a rule. */
                for (size_t prev_pattern = 0; prev_pattern < j; ++prev_pattern)
                    if (yx_compat_same_pattern(&view->patterns[j], &view->patterns[prev_pattern], true)) {
                        view->patterns[j].compat_pattern_id = view->patterns[prev_pattern].compat_pattern_id;
                        break;
                    }
            }
            if (view->patterns[j].compat_pattern_id == next_pattern_id) ++next_pattern_id;
        }
    }
    free(heads);
    free(tails);
    free(chain);
    free(hashes);
    free(items);
    if (!yx_view_share_chains(scanner)) {
        yx_destroy_views(scanner);
        return false;
    }
    if (!yx_view_atom_order(scanner)) {
        yx_destroy_views(scanner);
        return false;
    }
    size_t minimum_width_hint = 0;
    size_t atom_count = yx_known_global_atom_count(scanner->rules, &minimum_width_hint, false);
    if (atom_count > 16 || minimum_width_hint) {
        for (i = 0; i < rule_count; ++i) {
            YRX_RULE *view = &scanner->views[i];
            for (j = 0; j < view->pattern_count; ++j)
                if (view->patterns[j].kind == YX_PATTERN_REGEX || view->patterns[j].kind == YX_PATTERN_TEXT)
                    view->patterns[j].global_atom_count_hint = atom_count > 16 ? atom_count : minimum_width_hint;
        }
    }
    /* Keep the existing regexp hints independent from the literal encoding
       expansion. Text ties also need nocase and XOR atoms from both encodings. */
    size_t text_minimum_width = 0;
    size_t text_atom_count = yx_known_global_atom_count(scanner->rules, &text_minimum_width, true);
    if (text_atom_count > 16 || text_minimum_width) {
        for (i = 0; i < rule_count; ++i) {
            YRX_RULE *view = &scanner->views[i];
            for (j = 0; j < view->pattern_count; ++j)
                if (view->patterns[j].kind == YX_PATTERN_TEXT) view->patterns[j].global_atom_count_hint = text_atom_count > 16 ? text_atom_count : text_minimum_width;
        }
    }
    yx_build_scan_aliases(scanner, total_patterns);
    yx_build_text_prefilter(scanner);
    return true;
}

static bool yx_append_match(YRX_PATTERN *pattern, YRX_MATCH match)
{
    size_t i;
    YRX_MATCH *grown;
    size_t capacity;
    for (i = 0; i < pattern->match_count; ++i)
        if (pattern->matches[i].offset == match.offset) {
            if (match.length > pattern->matches[i].length) pattern->matches[i].length = match.length;
            return true;
        }
    if (pattern->match_count < pattern->match_capacity) {
        pattern->matches[pattern->match_count++] = match;
        return true;
    }
    capacity = pattern->match_capacity ? pattern->match_capacity * 2 : 8;
    if (capacity <= pattern->match_capacity || capacity > SIZE_MAX / sizeof(*grown)) return false;
    grown = (YRX_MATCH *)realloc(pattern->matches, capacity * sizeof(*grown));
    if (!grown) return false;
    pattern->matches = grown;
    pattern->match_capacity = capacity;
    pattern->matches[pattern->match_count++] = match;
    return true;
}

static int yx_compare_matches(const void *left, const void *right)
{
    const YRX_MATCH *a = (const YRX_MATCH *)left;
    const YRX_MATCH *b = (const YRX_MATCH *)right;
    if (a->offset < b->offset) return -1;
    if (a->offset > b->offset) return 1;
    if (a->length < b->length) return -1;
    if (a->length > b->length) return 1;
    return 0;
}

/* YARA-X records each namespace when one of its rules first matches and
 * keeps that order for the scanner's lifetime (matching_rules_per_ns is an
 * IndexMap whose reset only drains the rule lists). Rules are evaluated in
 * declaration order; a false global rule ends its namespace's evaluation.
 * Called with the conditions' results, before global suppression. */
static bool yx_scanner_track_namespaces(YRX_SCANNER *scanner, size_t count)
{
    size_t namespaces = 0;
    bool *failed;
    for (size_t i = 0; i < count; ++i)
        if (scanner->views[i].namespace_index >= namespaces) namespaces = scanner->views[i].namespace_index + 1;
    if (namespaces > scanner->namespace_capacity) {
        bool *seen = (bool *)realloc(scanner->namespace_seen, namespaces * sizeof(*seen));
        size_t *order;
        if (!seen) return false;
        scanner->namespace_seen = seen;
        memset(seen + scanner->namespace_capacity, 0, (namespaces - scanner->namespace_capacity) * sizeof(*seen));
        order = (size_t *)realloc(scanner->namespace_order, namespaces * sizeof(*order));
        if (!order) return false;
        scanner->namespace_order = order;
        scanner->namespace_capacity = namespaces;
    }
    failed = (bool *)calloc(namespaces ? namespaces : 1, sizeof(*failed));
    if (!failed) return false;
    for (size_t i = 0; i < count; ++i) {
        const YRX_RULE *rule = &scanner->views[i];
        size_t ns = rule->namespace_index;
        if (failed[ns]) continue;
        if (!rule->matched) {
            if (rule->is_global) failed[ns] = true;
            continue;
        }
        if (!scanner->namespace_seen[ns]) {
            scanner->namespace_seen[ns] = true;
            scanner->namespace_order[scanner->namespace_order_count++] = ns;
        }
    }
    free(failed);
    return true;
}

/* Reports the matching public rules grouped by namespace in the scanner's
 * namespace order, each group in declaration order. */
static bool yx_scanner_report_matches(YRX_SCANNER *scanner, size_t count)
{
    size_t namespaces = scanner->namespace_capacity, *rank, *start, *sorted;
    size_t total;
    if (!scanner->callback) return true;
    rank = (size_t *)calloc(namespaces ? namespaces : 1, sizeof(*rank));
    start = (size_t *)calloc(scanner->namespace_order_count + 1, sizeof(*start));
    sorted = (size_t *)malloc((count ? count : 1) * sizeof(*sorted));
    if (!rank || !start || !sorted) {
        free(rank);
        free(start);
        free(sorted);
        return false;
    }
    for (size_t k = 0; k < scanner->namespace_order_count; ++k) rank[scanner->namespace_order[k]] = k;
    for (size_t i = 0; i < count; ++i) {
        const YRX_RULE *rule = &scanner->views[i];
        if (rule->matched && !rule->is_private && rule->namespace_index < namespaces && scanner->namespace_seen[rule->namespace_index])
            ++start[rank[rule->namespace_index] + 1];
    }
    for (size_t k = 0; k < scanner->namespace_order_count; ++k) start[k + 1] += start[k];
    total = start[scanner->namespace_order_count];
    for (size_t i = 0; i < count; ++i) {
        const YRX_RULE *rule = &scanner->views[i];
        if (rule->matched && !rule->is_private && rule->namespace_index < namespaces && scanner->namespace_seen[rule->namespace_index])
            sorted[start[rank[rule->namespace_index]]++] = i;
    }
    for (size_t k = 0; k < total; ++k) scanner->callback(&scanner->views[sorted[k]], scanner->callback_data);
    free(rank);
    free(start);
    free(sorted);
    return true;
}

typedef struct yx_scanner_eval_scratch {
    yx_eval_string_arena *condition;
    const char **rule_names;
    bool *rule_values;
    yx_eval_global *globals;
    const char **pattern_names;
    yx_eval_match_list *match_lists;
    size_t *pattern_ids;
} yx_scanner_eval_scratch;

static bool yx_scanner_create_eval_scratch(YRX_SCANNER *scanner)
{
    size_t pattern_count = 0;
    size_t rule_count = scanner->rules->rule_count;
    yx_scanner_eval_scratch *scratch = calloc(1, sizeof(*scratch));
    if (!scratch) return false;
    scanner->eval_scratch = scratch;
    scratch->condition = yx_condition_scratch_create();
    if (!scratch->condition) return false;
    for (size_t i = 0; i < rule_count; ++i)
        if (scanner->views[i].pattern_count > pattern_count) pattern_count = scanner->views[i].pattern_count;
    if (rule_count) {
        scratch->rule_names = calloc(rule_count, sizeof(*scratch->rule_names));
        scratch->rule_values = calloc(rule_count, sizeof(*scratch->rule_values));
        if (!scratch->rule_names || !scratch->rule_values) return false;
    }
    if (scanner->global_count) {
        scratch->globals = calloc(scanner->global_count, sizeof(*scratch->globals));
        if (!scratch->globals) return false;
    }
    if (pattern_count) {
        scratch->pattern_names = calloc(pattern_count, sizeof(*scratch->pattern_names));
        scratch->match_lists = calloc(pattern_count, sizeof(*scratch->match_lists));
        scratch->pattern_ids = calloc(pattern_count, sizeof(*scratch->pattern_ids));
        if (!scratch->pattern_names || !scratch->match_lists || !scratch->pattern_ids) return false;
    }
    return true;
}

static void yx_scanner_destroy_eval_scratch(YRX_SCANNER *scanner)
{
    yx_scanner_eval_scratch *scratch = scanner->eval_scratch;
    if (!scratch) return;
    yx_condition_scratch_destroy(scratch->condition);
    free(scratch->rule_names);
    free(scratch->rule_values);
    free(scratch->globals);
    free(scratch->pattern_names);
    free(scratch->match_lists);
    free(scratch->pattern_ids);
    free(scratch);
    scanner->eval_scratch = NULL;
}

/* All patterns are collected before evaluating conditions. The condition
 * evaluator therefore sees match counts and offsets for every pattern. */
static YRX_RESULT yx_evaluate_views(YRX_SCANNER *scanner, const uint8_t *data, size_t size)
{
    size_t i, j, count = scanner->rules->rule_count;
    yx_scanner_eval_scratch *scratch = scanner->eval_scratch;
    const char **rule_names = scratch->rule_names;
    bool *rule_values = scratch->rule_values;
    yx_eval_global *globals = scratch->globals;
    yx_cuckoo_report *cuckoo_report = NULL;
    YRX_RESULT result = YRX_SUCCESS;

    if (yx_scan_deadline_reached(&scanner->deadline)) return yx_fail(YRX_SCAN_TIMEOUT, "timeout");
    yx_condition_scratch_new_scan(scratch->condition);

    if (!scanner->block_mode) {
        bool retain_native_data = false;
        for (i = 0; scanner->retain_scan_data && i < scanner->rules->import_count; ++i) {
            const char *module = scanner->rules->imports[i];
            int index = yx_mo_module_index(module);
            if (index >= 0 && !scanner->module_outputs[index] && strcmp(module, "lnk") && strcmp(module, "crx") && strcmp(module, "zip")) retain_native_data = true;
        }
        /* The remaining native field providers read their structures lazily.
         * Own the last input until replacement/destruction so later block
         * evaluation can retain those fields without borrowing caller memory.
         * A scanner opted out with xxyara_scanner_retain_scan_data() keeps
         * nothing: only block evaluation reads the copy. */
        uint8_t *retained_data = retain_native_data ? malloc(size ? size : 1) : NULL;
        if (retain_native_data && !retained_data) return yx_fail(YRX_SCAN_ERROR, "out of memory");
        if (retain_native_data && size) memcpy(retained_data, data, size);
        free(scanner->native_module_scan_data);
        scanner->native_module_scan_data = retained_data;
        scanner->native_module_scan_size = retain_native_data ? size : 0;
        yx_lnk_result_free(&scanner->native_lnk_output);
        yx_crx_result_free(&scanner->native_crx_output);
        yx_zip_result_free(&scanner->native_zip_output);
        scanner->native_lnk_output_present = false;
        scanner->native_crx_output_present = false;
        scanner->native_zip_output_present = false;
        for (i = 0; i < scanner->rules->import_count; ++i) {
            const char *module = scanner->rules->imports[i];
            int index = yx_mo_module_index(module);
            if (index >= 0 && scanner->module_outputs[index]) continue;
            bool parsed = true;
            if (!strcmp(module, "lnk")) {
                if (scanner->native_lnk_output_present) continue;
                parsed = yx_lnk_parse(data, size, &scanner->native_lnk_output);
                scanner->native_lnk_output_present = parsed;
            } else if (!strcmp(module, "crx")) {
                if (scanner->native_crx_output_present) continue;
                parsed = yx_crx_parse(data, size, &scanner->native_crx_output);
                scanner->native_crx_output_present = parsed;
            } else if (!strcmp(module, "zip")) {
                if (scanner->native_zip_output_present) continue;
                parsed = yx_zip_parse(data, size, &scanner->native_zip_output);
                scanner->native_zip_output_present = parsed;
            }
            if (!parsed) return yx_fail(YRX_SCAN_ERROR, "out of memory");
        }
    }

    if (!scanner->block_mode && !scanner->crx_output_present && !scanner->module_outputs[yx_mo_module_index("crx")])
        for (i = 0; i < scanner->rules->import_count; ++i)
            if (strcmp(scanner->rules->imports[i], "crx") == 0) {
                yx_crx_permhash_cache_reset();
                break;
            }

    for (i = 0; i < scanner->rules->import_count; ++i)
        if (strcmp(scanner->rules->imports[i], "cuckoo") == 0) {
            const uint8_t *metadata = NULL;
            size_t metadata_size = 0;
            for (j = 0; j < scanner->module_data_count; ++j)
                if (strcmp(scanner->module_data[j].name, "cuckoo") == 0) {
                    metadata = scanner->module_data[j].data;
                    metadata_size = scanner->module_data[j].size;
                    break;
                }
            char metadata_error[1024];
            if (!yx_cuckoo_report_parse_ex(metadata, metadata_size, &cuckoo_report, metadata_error, sizeof(metadata_error))) {
                static const char prefix[] = "error in module `cuckoo`: invalid metadata";
                char *error_text = metadata_error;
                size_t text_length = strlen(metadata_error);
                /* serde prints the whole offending value, which renders in
                 * at most six bytes per report byte ("\u{7f}"). A message
                 * that filled the buffer is rebuilt at full size; without
                 * memory for that it stays cut, the error unchanged. */
                if (text_length == sizeof(metadata_error) - 1 && metadata_size <= (SIZE_MAX - 1024) / 6) {
                    size_t error_capacity = metadata_size * 6 + 1024;
                    char *full = (char *)malloc(error_capacity);
                    if (full) {
                        yx_cuckoo_report *ignored = NULL;
                        if (!yx_cuckoo_report_parse_ex(metadata, metadata_size, &ignored, full, error_capacity)) {
                            error_text = full;
                            text_length = strlen(full);
                        } else {
                            yx_cuckoo_report_free(ignored);
                            free(full);
                        }
                    }
                }
                char *message = (char *)malloc(sizeof(prefix) + 2 + text_length);
                if (message) {
                    memcpy(message, prefix, sizeof(prefix) - 1);
                    if (text_length) {
                        memcpy(message + sizeof(prefix) - 1, ": ", 2);
                        memcpy(message + sizeof(prefix) + 1, error_text, text_length + 1);
                    } else message[sizeof(prefix) - 1] = 0;
                    result = yx_fail(YRX_SCAN_ERROR, message);
                    free(message);
                } else {
                    char cut[1152];
                    snprintf(cut, sizeof(cut), "%s%s%s", prefix, text_length ? ": " : "", metadata_error);
                    result = yx_fail(YRX_SCAN_ERROR, cut);
                }
                if (error_text != metadata_error) free(error_text);
                goto done;
            }
            break;
        }

    if (scanner->global_count) {
        for (i = 0; i < scanner->global_count; ++i) {
            const yx_global *source = &scanner->globals[i];
            globals[i].name = source->name;
            switch (source->type) {
                case YX_GLOBAL_BOOL:
                    globals[i].type = YX_EVAL_GLOBAL_BOOL;
                    globals[i].value.boolean = source->value.boolean;
                    break;
                case YX_GLOBAL_INT:
                    globals[i].type = YX_EVAL_GLOBAL_INT;
                    globals[i].value.integer = source->value.integer;
                    break;
                case YX_GLOBAL_FLOAT:
                    globals[i].type = YX_EVAL_GLOBAL_FLOAT;
                    globals[i].value.floating = source->value.floating;
                    break;
                case YX_GLOBAL_STR:
                    globals[i].type = YX_EVAL_GLOBAL_STRING;
                    globals[i].value.string.data = source->value.string.data;
                    globals[i].value.string.length = source->value.string.length;
                    break;
                case YX_GLOBAL_ARRAY:
                    globals[i].type = YX_EVAL_GLOBAL_ARRAY;
                    globals[i].value.array.element_type = source->value.array->element_type;
                    globals[i].value.array.items = source->value.array->items;
                    globals[i].value.array.count = source->value.array->count;
                    break;
                case YX_GLOBAL_STRUCT:
                    globals[i].type = YX_EVAL_GLOBAL_STRUCT;
                    globals[i].value.object = source->value.object;
                    break;
            }
        }
    }
    /* Earlier rules of the current rule's namespace, extended as rules are
     * evaluated: their results are final once evaluated. */
    size_t visible_count = 0, visible_upto = 0, visible_namespace = SIZE_MAX;
    size_t skipped_namespace = SIZE_MAX;
    bool pattern_search = false;
    /* The scan's part of every rule's context; the loop below only sets the
     * rule's patterns and visible rules. Nothing the loop runs changes the
     * scanner fields read here. */
    yx_eval_context context;
    memset(&context, 0, sizeof(context));
    context.data = data;
    context.size = size;
    if (scanner->block_mode && scanner->native_module_scan_data) {
        context.data = scanner->native_module_scan_data;
        context.size = scanner->native_module_scan_size;
    }
    context.block_mode = scanner->block_mode;
    context.pattern_names = scratch->pattern_names;
    context.patterns = scratch->match_lists;
    context.pattern_ids = scratch->pattern_ids;
    context.rule_names = rule_names;
    context.rule_values = rule_values;
    context.globals = globals;
    context.global_count = scanner->global_count;
    context.console_callback = scanner->console_callback;
    context.console_c_string = scanner->console_c_string;
    context.deadline = &scanner->deadline;
    context.string_arena = scratch->condition;
    context.cuckoo_report = cuckoo_report;
    context.pe_output_present = scanner->pe_output_present;
    context.pe_output_is_pe = scanner->pe_output_is_pe;
    context.pe_output_languages = scanner->pe_output_languages;
    context.pe_output_language_count = scanner->pe_output_language_count;
    context.lnk_output_present = scanner->lnk_output_present;
    context.lnk_output_is_lnk = scanner->lnk_output_is_lnk;
    context.crx_output_present = scanner->crx_output_present;
    context.crx_output = scanner->crx_output_present ? &scanner->crx_output : NULL;
    context.zip_output_present = scanner->zip_output_present;
    context.zip_output = scanner->zip_output_present ? &scanner->zip_output : NULL;
    if (scanner->native_lnk_output_present) context.lnk_output = &scanner->native_lnk_output;
    if (scanner->native_crx_output_present) context.crx_output = &scanner->native_crx_output;
    if (scanner->native_zip_output_present) {
        context.zip_output_present = true;
        context.zip_output = &scanner->native_zip_output;
    }
    context.vt_output = scanner->vt_output;
    context.module_function_cache = yx_module_function_cache;
    for (size_t module = 0; module < YX_MO_MODULE_COUNT; ++module)
        context.module_outputs[module] = scanner->block_mode ? scanner->last_module_outputs[module] : scanner->module_outputs[module];
    context.test_proto2_metadata = NULL;
    context.test_proto2_metadata_length = 0;
    context.test_proto2_metadata_present = false;
    for (size_t module = 0; module < scanner->module_data_count; ++module)
        if (strcmp(scanner->module_data[module].name, "test_proto2") == 0) {
            context.test_proto2_metadata = (const char *)scanner->module_data[module].data;
            context.test_proto2_metadata_length = scanner->module_data[module].size;
            context.test_proto2_metadata_present = true;
            break;
        }
    context.dex_output_present = scanner->dex_output_present;
    context.dex_output_is_dex = scanner->dex_output_is_dex;
    memcpy(context.dex_output_header_present, scanner->dex_output_header_present, sizeof(context.dex_output_header_present));
    memcpy(context.dex_output_header_values, scanner->dex_output_header_values, sizeof(context.dex_output_header_values));
    context.dex_output_map_size_present = scanner->dex_output_map_size_present;
    context.dex_output_map_size = scanner->dex_output_map_size;
    memcpy(context.dex_output_collection_counts, scanner->dex_output_collection_counts, sizeof(context.dex_output_collection_counts));
    context.dex_output_map_list_present = scanner->dex_output_map_list_present;
    context.dex_output_header_signature = scanner->dex_output_header_signature;
    context.dex_output_header_signature_length = scanner->dex_output_header_signature_length;
    context.dex_output_header_signature_present = scanner->dex_output_header_signature_present;
    context.dex_output_data = scanner->dex_output_data;
    context.dex_output_data_size = scanner->dex_output_data_size;
    for (i = 0; i < count; ++i) {
        YRX_RULE *rule = &scanner->views[i];
        const char **pattern_names = scratch->pattern_names;
        yx_eval_match_list *match_lists = scratch->match_lists;
        size_t *pattern_ids = scratch->pattern_ids;
        bool matched = false;

        context.pattern_search = &pattern_search;
        if (!rule->condition) {
            result = yx_fail(YRX_SCAN_ERROR, "rule has no compiled condition");
            goto done;
        }
        for (j = 0; j < rule->pattern_count; ++j) {
            const char *identifier = rule->patterns[j].identifier;
            pattern_names[j] = identifier && identifier[0] == '$' ? identifier + 1 : identifier;
            pattern_ids[j] = rule->patterns[j].compat_pattern_id;
            match_lists[j].matches = rule->patterns[j].matches;
            match_lists[j].count = rule->patterns[j].match_count;
            match_lists[j].present = match_lists[j].count != 0 || rule->patterns[j].zero_limit_present;
        }
        if (visible_namespace != rule->namespace_index) {
            visible_namespace = rule->namespace_index;
            visible_count = visible_upto = 0;
        }
        for (j = visible_upto; j < i; ++j) {
            const YRX_RULE *earlier = &scanner->views[j];
            if (earlier->namespace_index != rule->namespace_index) continue;
            rule_names[visible_count] = earlier->identifier;
            rule_values[visible_count] = earlier->matched;
            ++visible_count;
        }
        visible_upto = i;
        context.pattern_names = pattern_names;
        context.patterns = match_lists;
        context.pattern_ids = pattern_ids;
        context.pattern_count = rule->pattern_count;
        context.rule_count = visible_count;
#ifdef XXYARA_ENABLE_PROFILING
        uint64_t condition_started = yx_profile_now_ns();
#endif
        /* A false global rule ends its namespace (wasm/builder.rs,
         * emit_rule_into_current_func returns from the rules function and the
         * namespace block): the rules declared after it are not evaluated. */
        if (skipped_namespace == rule->namespace_index) {
            rule->matched = false;
            continue;
        }
        bool evaluated = yx_condition_evaluate(rule->condition, &context, &matched);
        if (evaluated && rule->is_global && !matched) skipped_namespace = rule->namespace_index;
#ifdef XXYARA_ENABLE_PROFILING
        yx_profile_add_elapsed(&scanner->rule_profiles[i].condition_nanoseconds, condition_started);
#endif
        if (!evaluated) {
            result = scanner->deadline.expired ? yx_fail(YRX_SCAN_TIMEOUT, "timeout") : yx_fail(YRX_SCAN_ERROR, "condition evaluation failed");
            goto done;
        }
        rule->matched = matched;
    }

    if (!yx_scanner_track_namespaces(scanner, count)) {
        result = yx_fail(YRX_SCAN_ERROR, "out of memory");
        goto done;
    }
    /* A false global rule suppresses matches in its namespace. */
    for (i = 0; i < count; ++i) {
        const YRX_RULE *global = &scanner->views[i];
        if (!global->is_global || global->matched) continue;
        for (j = 0; j < count; ++j) {
            YRX_RULE *rule = &scanner->views[j];
            if (global->namespace_index == rule->namespace_index) rule->matched = false;
        }
    }
    /* The generated code searches for the patterns before the first
     * pattern operand it evaluates (emit.rs,
     * emit_lazy_call_to_search_for_patterns): when no condition read one,
     * no pattern has matches. */
    for (i = 0; !pattern_search && i < count; ++i)
        for (j = 0; j < scanner->views[i].pattern_count; ++j) scanner->views[i].patterns[j].match_count = 0;
    if (!yx_scanner_report_matches(scanner, count)) result = yx_fail(YRX_SCAN_ERROR, "out of memory");
done:
    yx_cuckoo_report_free(cuckoo_report);
    return result;
}

const char *yrx_last_error(void)
{
    return yx_last_error_message;
}

void yrx_buffer_destroy(YRX_BUFFER *buffer)
{
    if (!buffer) return;
    free(buffer->data);
    free(buffer);
}

static YRX_RULES *yx_new_compiler_rules(void)
{
    YRX_RULES *rules = calloc(1, sizeof(*rules));
    if (!rules) return NULL;
    rules->namespace_names = calloc(1, sizeof(*rules->namespace_names));
    if (rules->namespace_names) rules->namespace_names[0] = yx_strdup("default");
    if (!rules->namespace_names || !rules->namespace_names[0]) {
        free(rules->namespace_names);
        free(rules);
        return NULL;
    }
    rules->namespace_count = 1;
    return rules;
}

YRX_RESULT yrx_compiler_create(uint32_t flags, YRX_COMPILER **out)
{
    YRX_COMPILER *compiler;
    if (!out) return yx_fail(YRX_INVALID_ARGUMENT, "`compiler` pointer cannot be null");
    *out = NULL;
    /* Like YARA-X, preserve even unknown flag bits across compiler reuse. */
    compiler = (YRX_COMPILER *)calloc(1, sizeof(*compiler));
    if (!compiler) return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    compiler->rules = yx_new_compiler_rules();
    compiler->current_namespace = yx_strdup("default");
    if (!compiler->rules || !compiler->current_namespace) {
        yx_free_rules(compiler->rules);
        free(compiler->current_namespace);
        free(compiler);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    compiler->flags = flags;
    compiler->max_warnings = SIZE_MAX;
    *out = compiler;
    return yx_ok();
}

void yrx_compiler_destroy(YRX_COMPILER *compiler)
{
    if (!compiler) return;
    yx_free_include_state(compiler);
    yx_free_compiler_policies(compiler);
    yx_warning_rows_free(&compiler->warning_rows);
    free(compiler->error_diagnostic_json);
    for (size_t i = 0; i < compiler->patch_note_count; ++i) free(compiler->patch_notes[i].rows);
    free(compiler->patch_notes);
    free(compiler->patch_note_slots);
    free((void *)compiler->warning_point_keys);
    free(compiler->warning_point_values);
    yx_free_globals(compiler->redefined_global_symbols, compiler->redefined_global_symbol_count);
    yx_free_rules(compiler->rules);
    yx_rule_name_cache_free(compiler->rule_name_cache);
    yx_slow_pattern_cache_free(compiler->slow_pattern_cache);
    free(compiler->current_namespace);
    free(compiler);
}

/* The diagnostic JSON owns the complete rendered text; compiler->error is
 * only the parser's bounded fallback. Decode the first new report's text. */
static char *yx_first_diagnostic_text(const char *diagnostic)
{
    const char *end, *field = NULL, *at;
    xx_json json;
    char *text = NULL;
    if (!diagnostic) return NULL;
    end = strstr(diagnostic + 1, ",{\"type\":");
    if (!end) end = diagnostic + strlen(diagnostic);
    for (at = diagnostic; (at = strstr(at, "\"text\":\"")) && at < end; ++at) field = at;
    if (!field) return NULL;
    field += 7;
    xx_json_init(&json, field, (size_t)(end - field));
    if (!xx_json_string(&json, &text)) return NULL;
    return text;
}

YRX_RESULT yrx_compiler_add_source_with_origin(YRX_COMPILER *compiler, const char *source, const char *origin)
{
    YRX_RESULT result;
    char prior_error[sizeof(compiler->error)];
    char *prior_diagnostic;
    yx_global *runtime_globals = NULL, *symbol_globals = NULL;
    bool prior_origin_explicit, prior_explicit_line_origin;
    if (!compiler) return yx_null_argument("compiler");
    if (!source) return yx_null_argument("src");
    if (origin && !yx_valid_utf8(origin)) return yx_compiler_invalid_utf8(origin);
    if (compiler->redefined_global_symbol_count) {
        size_t count = compiler->rules->global_count;
        symbol_globals = (yx_global *)malloc(count * sizeof(*symbol_globals));
        if (!symbol_globals) return yx_fail(YRX_SYNTAX_ERROR, "out of memory");
        runtime_globals = compiler->rules->globals;
        memcpy(symbol_globals, runtime_globals, count * sizeof(*symbol_globals));
        for (size_t i = 0; i < count; ++i) {
            yx_global *saved = yx_find_global(compiler->redefined_global_symbols, compiler->redefined_global_symbol_count, symbol_globals[i].name);
            if (saved) symbol_globals[i] = *saved;
        }
        compiler->rules->globals = symbol_globals;
    }
    memcpy(prior_error, compiler->error, sizeof(prior_error));
    prior_diagnostic = compiler->error_diagnostic_json;
    compiler->error_diagnostic_json = NULL;
    prior_origin_explicit = compiler->current_origin_explicit;
    prior_explicit_line_origin = yx_explicit_line_origin;
    compiler->current_origin_explicit = origin != NULL;
    yx_explicit_line_origin = origin && strcmp(origin, "line") == 0;
    if (!yx_valid_utf8(source)) {
        if (!yx_compiler_invalid_utf8_error(compiler, source, origin ? origin : "line"))
            snprintf(compiler->error, sizeof(compiler->error), "out of memory recording invalid UTF-8");
        result = YRX_SYNTAX_ERROR;
    } else {
        /* One scan for the suppression comments of this source. */
        yx_suppression_scope suppressions;
        yx_suppression_scope_begin(&suppressions, (const uint8_t *)source, yx_source_text_length(source));
        result = yx_parse_source(compiler, source, origin ? origin : "line");
        yx_suppression_scope_end(&suppressions);
    }
    if (symbol_globals) {
        compiler->rules->globals = runtime_globals;
        free(symbol_globals);
    }
    compiler->current_origin_explicit = prior_origin_explicit;
    yx_explicit_line_origin = prior_explicit_line_origin;
    if (result != YRX_SUCCESS) {
        char latest_error[sizeof(compiler->error)];
        char *latest_diagnostic = compiler->error_diagnostic_json;
        char *full_error = yx_first_diagnostic_text(latest_diagnostic);
        memcpy(latest_error, compiler->error, sizeof(latest_error));
        compiler->error_diagnostic_json = prior_diagnostic;
        /* Every failed source contributes to errors_json, including one
         * that only produced a text error. */
        if (!latest_diagnostic && latest_error[0]) latest_diagnostic = yx_fallback_error_diagnostic(latest_error, origin ? origin : "line");
        if (latest_diagnostic) (void)yx_compiler_join_error_diagnostic(compiler, latest_diagnostic);
        if (prior_error[0]) {
            memcpy(compiler->error, prior_error, sizeof(prior_error));
        }
        const char *error_text = full_error ? full_error : (latest_error[0] ? latest_error : "compilation failed");
        if (compiler->flags & YRX_COLORIZE_ERRORS && *error_text) {
            char *colored = yx_colorize_diagnostic(compiler, error_text);
            if (colored) {
                result = yx_fail(result, colored);
                free(colored);
                xx_str_free(full_error);
                return result;
            }
        }
        result = yx_fail(result, error_text);
        xx_str_free(full_error);
        return result;
    }
    if (!yx_append_source(compiler->rules, source)) {
        snprintf(compiler->error, sizeof(compiler->error), "out of memory saving source");
        free(prior_diagnostic);
        return yx_fail(YRX_SYNTAX_ERROR, compiler->error);
    }
    free(compiler->error_diagnostic_json);
    compiler->error_diagnostic_json = prior_diagnostic;
    if (prior_error[0]) memcpy(compiler->error, prior_error, sizeof(prior_error));
    return yx_ok();
}

YRX_RESULT yrx_compiler_add_source(YRX_COMPILER *compiler, const char *source)
{
    return yrx_compiler_add_source_with_origin(compiler, source, NULL);
}

/* A later copy of a regexp pattern (same modifiers and regexp, no gap head
 * set before this pass) takes the first copy's gap head and a copy of its
 * program, or no program when the first had none: both are functions of
 * the kind, regexp and modifiers (yx_ser_gap_head_regexp,
 * yx_ser_regexp_program). After an allocation failure it builds its own. */
static bool yx_copy_regexp_program(YRX_PATTERN *pattern, const YRX_PATTERN *first, int result)
{
    yx_rx_program *program = NULL;
    char *head = first->gap_head_regexp ? yx_strdup(first->gap_head_regexp) : NULL;
    char *source = result == 1 ? yx_strdup(pattern->regexp) : NULL;
    if (result == 1) program = calloc(1, sizeof(*program));
    if ((first->gap_head_regexp && !head) || (result == 1 && (!source || !program || yx_ser_regexp_program_copy(first->rx_program, program) != 1))) {
        free(head);
        free(source);
        free(program);
        return false;
    }
    pattern->gap_head_regexp = head;
    if (result == 1) {
        pattern->rx_program = program;
        pattern->rx_program_regexp = source;
        pattern->rx_program_modifiers = pattern->modifiers;
    }
    return true;
}

/* A hex pattern's program is a function of its hex atoms and modifiers
 * (yx_ser_regexp_program reads nothing else of it), so equal atom trees
 * build equal programs. */
static uint64_t yx_hex_atoms_hash(const yx_hex_atom *atoms, size_t count, uint64_t hash, unsigned depth)
{
    hash = (hash ^ count) * 1099511628211ull;
    for (size_t i = 0; i < count && depth <= 64; ++i) {
        const yx_hex_atom *a = &atoms[i];
        uint64_t fields[8] = {a->kind, a->value, a->mask, a->negated, a->minimum, a->maximum, a->finite_maximum, a->branch_count};
        for (size_t f = 0; f < 8; ++f) hash = (hash ^ fields[f]) * 1099511628211ull;
        for (size_t b = 0; b < a->branch_count; ++b) hash = yx_hex_atoms_hash(a->branches[b].atoms, a->branches[b].count, hash, depth + 1);
    }
    return hash;
}

static bool yx_hex_atoms_equal(const yx_hex_atom *x, size_t x_count, const yx_hex_atom *y, size_t y_count, unsigned depth)
{
    if (x_count != y_count || depth > 64) return false;
    for (size_t i = 0; i < x_count; ++i) {
        const yx_hex_atom *a = &x[i], *b = &y[i];
        if (a->kind != b->kind || a->value != b->value || a->mask != b->mask || a->negated != b->negated || a->minimum != b->minimum || a->maximum != b->maximum ||
            a->finite_maximum != b->finite_maximum || a->branch_count != b->branch_count)
            return false;
        for (size_t k = 0; k < a->branch_count; ++k)
            if (!yx_hex_atoms_equal(a->branches[k].atoms, a->branches[k].count, b->branches[k].atoms, b->branches[k].count, depth + 1)) return false;
    }
    return true;
}

/* A later copy of a hex pattern takes a copy of the first copy's program, or
 * no program when the first had none. False after an allocation failure. */
static bool yx_copy_hex_program(YRX_PATTERN *pattern, const YRX_PATTERN *first, int result)
{
    if (result != 1) return true;
    yx_rx_program *program = calloc(1, sizeof(*program));
    if (!program || yx_ser_regexp_program_copy(first->rx_program, program) != 1) {
        free(program);
        return false;
    }
    pattern->rx_program = program;
    return true;
}

/* Builds one pattern's program as the loop below does: its gap head, then
 * the program. The yx_ser_regexp_program result, or INT_MIN when no program
 * could be allocated. Reads and writes that pattern only. */
static int yx_build_pattern_program(YRX_PATTERN *pattern)
{
    yx_rx_program *program;
    int result;
    if (!pattern->gap_head_regexp) pattern->gap_head_regexp = yx_ser_gap_head_regexp(pattern);
    program = calloc(1, sizeof(*program));
    if (!program) return INT_MIN;
    result = yx_ser_regexp_program(pattern, program);
    if (result == 1) {
        pattern->rx_program = program;
        if (pattern->kind == YX_PATTERN_REGEX && pattern->regexp) {
            pattern->rx_program_regexp = yx_strdup(pattern->regexp);
            pattern->rx_program_modifiers = pattern->modifiers;
        }
    } else free(program);
    return result;
}

/* A pattern loaded from an archive runs the archive's own program
 * (archived_regexp) instead of the one its declaration compiles to; the
 * gap head and the program's provenance are set as yx_build_pattern_program
 * sets them. Without memory the pattern is left for that function. Verify
 * builds (-DXXYARA_VERIFY_LOAD) build both and abort when the code, a
 * sub-pattern's flags or an atom differ. */
static void yx_build_archived_program(YRX_PATTERN *pattern)
{
    yx_rx_program *program = calloc(1, sizeof(*program));
    char *source = pattern->kind == YX_PATTERN_REGEX && pattern->regexp ? yx_strdup(pattern->regexp) : NULL;
    if (!program || (pattern->kind == YX_PATTERN_REGEX && pattern->regexp && !source) || yx_ser_archived_regexp_program(pattern->archived_regexp, program) != 1) {
        free(program);
        free(source);
        return;
    }
    if (!pattern->gap_head_regexp) pattern->gap_head_regexp = yx_ser_gap_head_regexp(pattern);
#ifdef XXYARA_VERIFY_LOAD
    {
        /* The program the declaration compiles to, compared with the
         * archive's. A difference is reported with its class: the code, the
         * GREEDY flag alone, other flags, the atoms, or no program at all.
         * XXYARA_VERIFY_LOAD_LOG appends one line per difference to a file;
         * XXYARA_VERIFY_LOAD_STRICT aborts on any difference. */
        yx_rx_program built;
        int result = yx_ser_regexp_program(pattern, &built);
        const char *what = NULL;
        if (result != 1) what = "no rebuilt program";
        else if (built.code_length != program->code_length || built.sub_count != program->sub_count ||
                 (built.code_length && memcmp(built.code, program->code, built.code_length)))
            what = "code";
        for (size_t s = 0; !what && s < built.sub_count; ++s) {
            const yx_rx_sub *p = &built.subs[s], *q = &program->subs[s];
            if (p->atom_count != q->atom_count) {
                what = "atom count";
                break;
            }
            for (size_t i = 0; !what && i < p->atom_count; ++i) {
                const yx_rx_atom *m = &p->atoms[i], *n = &q->atoms[i];
                if (m->length != n->length || m->exact != n->exact || m->backtrack != n->backtrack || m->has_fwd != n->has_fwd || m->has_bck != n->has_bck ||
                    (m->has_fwd && m->fwd != n->fwd) || (m->has_bck && m->bck != n->bck) || memcmp(m->bytes, n->bytes, m->length) != 0)
                    what = "atom";
            }
        }
        for (size_t s = 0; !what && s < built.sub_count; ++s)
            if (built.subs[s].flags != program->subs[s].flags)
                what = (built.subs[s].flags ^ program->subs[s].flags) == YX_RX_GREEDY
                           ? (program->subs[s].flags & YX_RX_GREEDY ? "greedy flag set in archive only" : "greedy flag set in rebuilt only")
                           : "flags";
        if (what) {
            static volatile long lock;
            const char *path = getenv("XXYARA_VERIFY_LOAD_LOG");
            if (path) {
                FILE *log;
#ifdef _MSC_VER
                while (_InterlockedExchange(&lock, 1));
#endif
                log = fopen(path, "ab");
                if (log) {
                    fprintf(log, "%s\tkind %d\tmodifiers %#x\tflags %#x/%#x\t%s\n", what, (int)pattern->kind, (unsigned)pattern->modifiers,
                            result == 1 ? built.subs[0].flags : 0u, program->subs[0].flags, pattern->regexp ? pattern->regexp : "");
                    fclose(log);
                }
#ifdef _MSC_VER
                _InterlockedExchange(&lock, 0);
#endif
            }
            if (getenv("XXYARA_VERIFY_LOAD_STRICT")) {
                fprintf(stderr, "XXYARA_VERIFY_LOAD: archived program differs (%s): kind %d modifiers %#x `%s`\n", what, (int)pattern->kind, (unsigned)pattern->modifiers,
                        pattern->regexp ? pattern->regexp : "");
                abort();
            }
        }
        if (result == 1) yx_rx_program_free(&built);
    }
#endif
    pattern->rx_program = program;
    if (source) {
        pattern->rx_program_regexp = source;
        pattern->rx_program_modifiers = pattern->modifiers;
    }
}

/* Patterns with the same archived program (the same bytes: flags, atoms
 * and code) get the same program. The first of them builds it; a later one
 * takes a copy (yx_ser_regexp_program_copy, as later copies of one regexp or
 * hex form do), with its own gap head and provenance, or builds its own
 * when the first has none or the copy cannot be allocated. */
typedef struct {
    YRX_PATTERN **patterns;
    /* The first pattern with the same archived program, or the pattern's
     * own index. */
    size_t *first;
    /* The patterns one pass handles: the firsts, then the others. */
    size_t *order;
} yx_archived_program_tasks;

static void yx_build_archived_program_task(size_t index, void *context)
{
    const yx_archived_program_tasks *tasks = context;
    yx_build_archived_program(tasks->patterns[tasks->order[index]]);
}

static void yx_copy_archived_program_task(size_t index, void *context)
{
    const yx_archived_program_tasks *tasks = context;
    size_t i = tasks->order[index];
    YRX_PATTERN *pattern = tasks->patterns[i];
    const YRX_PATTERN *first = tasks->patterns[tasks->first[i]];
    yx_rx_program *program = first->rx_program ? calloc(1, sizeof(*program)) : NULL;
    char *source = pattern->kind == YX_PATTERN_REGEX && pattern->regexp ? yx_strdup(pattern->regexp) : NULL;
    if (!program || (pattern->kind == YX_PATTERN_REGEX && pattern->regexp && !source) || yx_ser_regexp_program_copy(first->rx_program, program) != 1) {
        free(program);
        free(source);
        yx_build_archived_program(pattern);
        return;
    }
    if (!pattern->gap_head_regexp) pattern->gap_head_regexp = yx_ser_gap_head_regexp(pattern);
    pattern->rx_program = program;
    if (source) {
        pattern->rx_program_regexp = source;
        pattern->rx_program_modifiers = pattern->modifiers;
    }
}

/* The archive's programs, built on several threads: each build or copy
 * writes its own pattern only, and the copies run after every first is
 * built. */
static void yx_build_archived_programs(YRX_RULES *rules)
{
    size_t count = 0, used = 0, buckets = 64, firsts = 0, others = 0;
    yx_archived_program_tasks tasks = {NULL, NULL, NULL};
    size_t *heads = NULL, *chain = NULL;
    uint64_t *hashes = NULL;
    for (size_t i = 0; rules && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j)
            if (rules->rules[i].patterns[j].archived_regexp && !rules->rules[i].patterns[j].rx_program) ++count;
    if (!count) return;
    while (buckets < count * 2 && buckets <= SIZE_MAX / 4) buckets *= 2;
    tasks.patterns = malloc(count * sizeof(*tasks.patterns));
    tasks.first = malloc(count * sizeof(*tasks.first));
    tasks.order = malloc(count * sizeof(*tasks.order));
    heads = malloc(buckets * sizeof(*heads));
    chain = malloc(count * sizeof(*chain));
    hashes = malloc(count * sizeof(*hashes));
    if (!tasks.patterns || !tasks.first || !tasks.order || !heads || !chain || !hashes) goto done;
    for (size_t i = 0; i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            if (pattern->archived_regexp && !pattern->rx_program) tasks.patterns[used++] = pattern;
        }
    for (size_t i = 0; i < buckets; ++i) heads[i] = SIZE_MAX;
    for (size_t i = 0; i < used; ++i) {
        const yx_archived_regexp *archived = tasks.patterns[i]->archived_regexp;
        const unsigned char *bytes = (const unsigned char *)archived;
        uint64_t hash = 1469598103934665603ull;
        size_t bucket, at;
        for (size_t k = 0; k < archived->size; ++k) hash = (hash ^ bytes[k]) * 1099511628211ull;
        bucket = (size_t)hash & (buckets - 1);
        for (at = heads[bucket]; at != SIZE_MAX; at = chain[at])
            if (hashes[at] == hash && tasks.patterns[at]->archived_regexp->size == archived->size &&
                !memcmp(tasks.patterns[at]->archived_regexp, archived, archived->size))
                break;
        hashes[i] = hash;
        if (at != SIZE_MAX) {
            tasks.first[i] = at;
            chain[i] = SIZE_MAX;
            continue;
        }
        tasks.first[i] = i;
        chain[i] = heads[bucket];
        heads[bucket] = i;
    }
    for (size_t i = 0; i < used; ++i)
        if (tasks.first[i] == i) tasks.order[firsts++] = i;
    yx_parallel_run(firsts, yx_parallel_threads(firsts, 16), yx_build_archived_program_task, &tasks);
    for (size_t i = 0; i < used; ++i)
        if (tasks.first[i] != i) tasks.order[others++] = i;
    yx_parallel_run(others, yx_parallel_threads(others, 16), yx_copy_archived_program_task, &tasks);
done:
    free(tasks.patterns);
    free(tasks.first);
    free(tasks.order);
    free(heads);
    free(chain);
    free(hashes);
}

typedef struct {
    YRX_PATTERN **patterns;
    int *results;
} yx_program_tasks;

static void yx_build_program_task(size_t index, void *context)
{
    yx_program_tasks *tasks = context;
    tasks->results[index] = yx_build_pattern_program(tasks->patterns[index]);
}

/* Regexp sub-pattern programs for the scanner. A pattern that is not a
 * regexp sub-pattern, or that cannot be built, keeps the generic path. */
static void yx_build_regexp_programs(YRX_RULES *rules)
{
    size_t count = 0, buckets = 64, used = 0, task_count = 0, flat = 0;
    for (size_t i = 0; rules && i < rules->rule_count; ++i) count += rules->rules[i].pattern_count;
    while (buckets < count * 2 && buckets <= SIZE_MAX / 4) buckets *= 2;
    size_t *heads = count ? malloc(buckets * sizeof(*heads)) : NULL;
    size_t *hex_heads = count ? malloc(buckets * sizeof(*hex_heads)) : NULL;
    size_t *chain = count ? malloc(count * sizeof(*chain)) : NULL;
    uint64_t *hashes = count ? malloc(count * sizeof(*hashes)) : NULL;
    int *results = count ? malloc(count * sizeof(*results)) : NULL;
    const YRX_PATTERN **firsts = count ? malloc(count * sizeof(*firsts)) : NULL;
    bool shared = heads && hex_heads && chain && hashes && results && firsts;
    /* The loop below builds a program at a pattern it cannot share and at
     * the first copy of each shareable regexp or hex form (no earlier copy is
     * registered then). Those patterns are found first, without building
     * anything, and built on several threads: a build reads and writes its
     * own pattern only. At such a pattern the loop then only registers the
     * result, exactly as after building it there. The loop builds any other
     * pattern itself, which happens only after an allocation failure. */
    YRX_PATTERN **task_patterns = count ? malloc(count * sizeof(*task_patterns)) : NULL;
    int *task_results = count ? malloc(count * sizeof(*task_results)) : NULL;
    uint64_t *task_hashes = count ? malloc(count * sizeof(*task_hashes)) : NULL;
    uint8_t *task_kinds = count ? malloc(count * sizeof(*task_kinds)) : NULL;
    size_t *task_of = count ? malloc(count * sizeof(*task_of)) : NULL;
    if (!task_patterns || !task_results || !task_hashes || !task_kinds || !task_of) {
        free(task_of);
        task_of = NULL;
    }
    for (size_t i = 0; shared && i < buckets; ++i) heads[i] = hex_heads[i] = SIZE_MAX;
    for (size_t i = 0; task_of && rules && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            uint64_t hash = 0;
            size_t bucket, at = SIZE_MAX, k = flat++;
            uint8_t kind = 0;
            task_of[k] = SIZE_MAX;
            if (pattern->rx_program || (pattern->kind != YX_PATTERN_REGEX && pattern->kind != YX_PATTERN_HEX)) continue;
            if (shared && pattern->kind == YX_PATTERN_HEX && pattern->hex_atoms && !pattern->gap_head_regexp) {
                hash = yx_hex_atoms_hash(pattern->hex_atoms, pattern->hex_atom_count, 1469598103934665603ull ^ pattern->modifiers, 0);
                bucket = (size_t)hash & (buckets - 1);
                for (at = hex_heads[bucket]; at != SIZE_MAX; at = chain[at])
                    if (hashes[at] == hash && firsts[at]->modifiers == pattern->modifiers &&
                        yx_hex_atoms_equal(firsts[at]->hex_atoms, firsts[at]->hex_atom_count, pattern->hex_atoms, pattern->hex_atom_count, 0))
                        break;
                if (at != SIZE_MAX) continue;
                firsts[used] = pattern;
                hashes[used] = hash;
                chain[used] = hex_heads[bucket];
                hex_heads[bucket] = used++;
                kind = 2;
            } else if (shared && pattern->kind == YX_PATTERN_REGEX && pattern->regexp && !pattern->gap_head_regexp) {
                hash = 1469598103934665603ull ^ pattern->modifiers;
                for (const unsigned char *c = (const unsigned char *)pattern->regexp; *c; ++c) hash = (hash ^ *c) * 1099511628211ull;
                bucket = (size_t)hash & (buckets - 1);
                for (at = heads[bucket]; at != SIZE_MAX; at = chain[at])
                    if (hashes[at] == hash && firsts[at]->modifiers == pattern->modifiers && strcmp(firsts[at]->regexp, pattern->regexp) == 0) break;
                if (at != SIZE_MAX) continue;
                firsts[used] = pattern;
                hashes[used] = hash;
                chain[used] = heads[bucket];
                heads[bucket] = used++;
                kind = 1;
            }
            task_of[k] = task_count;
            task_hashes[task_count] = hash;
            task_kinds[task_count] = kind;
            task_patterns[task_count++] = pattern;
        }
    if (task_of) {
        yx_program_tasks tasks = {task_patterns, task_results};
        yx_parallel_run(task_count, yx_parallel_threads(task_count, 4), yx_build_program_task, &tasks);
    }
    used = flat = 0;
    for (size_t i = 0; shared && i < buckets; ++i) heads[i] = hex_heads[i] = SIZE_MAX;
    for (size_t i = 0; rules && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            uint64_t hash = 0;
            size_t bucket = 0, at = SIZE_MAX, k = flat++;
            int result;
            bool shareable, hex_shareable;
            if (task_of && task_of[k] != SIZE_MAX) {
                size_t t = task_of[k];
                result = task_results[t];
                if (result == INT_MIN) continue;
                shareable = task_kinds[t] == 1;
                hex_shareable = task_kinds[t] == 2;
                hash = task_hashes[t];
                bucket = (size_t)hash & (buckets - 1);
                goto built;
            }
            if (pattern->rx_program || (pattern->kind != YX_PATTERN_REGEX && pattern->kind != YX_PATTERN_HEX)) continue;
            shareable = shared && pattern->kind == YX_PATTERN_REGEX && pattern->regexp && !pattern->gap_head_regexp;
            hex_shareable = shared && pattern->kind == YX_PATTERN_HEX && pattern->hex_atoms && !pattern->gap_head_regexp;
            if (hex_shareable) {
                hash = yx_hex_atoms_hash(pattern->hex_atoms, pattern->hex_atom_count, 1469598103934665603ull ^ pattern->modifiers, 0);
                bucket = (size_t)hash & (buckets - 1);
                for (at = hex_heads[bucket]; at != SIZE_MAX; at = chain[at])
                    if (hashes[at] == hash && firsts[at]->modifiers == pattern->modifiers &&
                        yx_hex_atoms_equal(firsts[at]->hex_atoms, firsts[at]->hex_atom_count, pattern->hex_atoms, pattern->hex_atom_count, 0))
                        break;
                if (at != SIZE_MAX && results[at] >= 0 && yx_copy_hex_program(pattern, firsts[at], results[at])) continue;
            }
            if (shareable) {
                hash = 1469598103934665603ull ^ pattern->modifiers;
                for (const unsigned char *c = (const unsigned char *)pattern->regexp; *c; ++c) hash = (hash ^ *c) * 1099511628211ull;
                bucket = (size_t)hash & (buckets - 1);
                for (at = heads[bucket]; at != SIZE_MAX; at = chain[at])
                    if (hashes[at] == hash && firsts[at]->modifiers == pattern->modifiers && strcmp(firsts[at]->regexp, pattern->regexp) == 0) break;
                if (at != SIZE_MAX && results[at] >= 0 && yx_copy_regexp_program(pattern, firsts[at], results[at])) continue;
            }
            result = yx_build_pattern_program(pattern);
            if (result == INT_MIN) continue;
        built:
            /* Only a complete first copy is shared. */
            if (shareable && at == SIZE_MAX && result >= 0 && (result != 1 || pattern->rx_program_regexp)) {
                firsts[used] = pattern;
                results[used] = result;
                hashes[used] = hash;
                chain[used] = heads[bucket];
                heads[bucket] = used++;
            } else if (hex_shareable && at == SIZE_MAX && result >= 0 && (result != 1 || pattern->rx_program)) {
                firsts[used] = pattern;
                results[used] = result;
                hashes[used] = hash;
                chain[used] = hex_heads[bucket];
                hex_heads[bucket] = used++;
            }
        }
    free(heads);
    free(hex_heads);
    free(chain);
    free(hashes);
    free(results);
    free(firsts);
    free(task_patterns);
    free(task_results);
    free(task_hashes);
    free(task_kinds);
    free(task_of);
}

/* The inputs yx_candidate_plan_build reads from a regexp pattern: kind,
 * modifiers, regexp, gap_head_regexp, deadline, the archived prefilters
 * (none), the program's provenance and its code, sub-pattern flags and
 * atoms. Equal inputs build equal plans, except that regex_source points
 * at each pattern's own regexp. */
static bool yx_same_plan_inputs(const YRX_PATTERN *a, const YRX_PATTERN *b)
{
    if (a->kind != YX_PATTERN_REGEX || b->kind != YX_PATTERN_REGEX || a->modifiers != b->modifiers || !a->regexp || !b->regexp || strcmp(a->regexp, b->regexp) != 0 ||
        !yx_compat_optional_string_equal(a->gap_head_regexp, b->gap_head_regexp) || a->deadline != b->deadline || a->archived_literal_prefilter.atoms ||
        b->archived_literal_prefilter.atoms || a->base64_archived_prefilter.present || b->base64_archived_prefilter.present ||
        !yx_compat_optional_string_equal(a->rx_program_regexp, b->rx_program_regexp) || a->rx_program_modifiers != b->rx_program_modifiers ||
        !a->rx_program != !b->rx_program)
        return false;
    if (!a->rx_program) return true;
    const yx_rx_program *x = a->rx_program, *y = b->rx_program;
    if (x->code_length != y->code_length || x->sub_count != y->sub_count || (x->code_length && memcmp(x->code, y->code, x->code_length) != 0)) return false;
    for (size_t s = 0; s < x->sub_count; ++s) {
        const yx_rx_sub *p = &x->subs[s], *q = &y->subs[s];
        if (p->flags != q->flags || p->atom_count != q->atom_count) return false;
        for (size_t i = 0; i < p->atom_count; ++i) {
            const yx_rx_atom *m = &p->atoms[i], *n = &q->atoms[i];
            if (m->length != n->length || m->exact != n->exact || m->backtrack != n->backtrack || m->has_fwd != n->has_fwd || m->has_bck != n->has_bck ||
                m->fwd != n->fwd || m->bck != n->bck || memcmp(m->bytes, n->bytes, m->length) != 0)
                return false;
        }
    }
    return true;
}

static uint64_t yx_plan_inputs_hash(const YRX_PATTERN *pattern)
{
    uint64_t hash = 1469598103934665603ull ^ pattern->modifiers;
    for (const unsigned char *at = (const unsigned char *)pattern->regexp; *at; ++at) hash = (hash ^ *at) * 1099511628211ull;
    if (pattern->gap_head_regexp)
        for (const unsigned char *at = (const unsigned char *)pattern->gap_head_regexp; *at; ++at) hash = (hash ^ *at) * 1099511628211ull;
    return hash;
}

/* Chains of sub-patterns: their pieces' programs, once per rule set. */
static void yx_build_chains(YRX_RULES *rules)
{
    for (size_t i = 0; rules && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            if (!pattern->rx_program && !pattern->rx_chain && (pattern->kind == YX_PATTERN_HEX || pattern->kind == YX_PATTERN_REGEX))
                pattern->rx_chain = yx_ser_chain_new(pattern);
        }
}

/* Alternations of literals: their Literal sub-patterns, once per rule set. */
static void yx_build_literal_sets(YRX_RULES *rules)
{
    for (size_t i = 0; rules && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            if (!pattern->rx_program && !pattern->rx_chain && !pattern->rx_literals && !pattern->archived_regexp &&
                (pattern->kind == YX_PATTERN_HEX || pattern->kind == YX_PATTERN_REGEX))
                pattern->rx_literals = yx_ser_literal_set(pattern);
        }
}

static void yx_plan_build_task(size_t index, void *context)
{
    YRX_PATTERN **patterns = context;
    YRX_PATTERN *pattern = patterns[index];
    yx_candidate_plan_free(pattern->candidate_plan);
    pattern->candidate_plan = yx_candidate_plan_build(pattern);
}

/* Rule sets repeat regexp patterns across rules and namespaces (APKiD's
 * tracker files hold 1,100 regexps three times): the first copy builds its
 * plan and later copies with the same inputs clone it. A copy whose first
 * plan is NULL, or that the clone does not cover, builds its own. */
static void yx_build_candidate_plans(YRX_RULES *rules)
{
    size_t count = 0, buckets = 64, used = 0, task_count = 0, flat = 0;
    for (size_t i = 0; i < rules->rule_count; ++i) count += rules->rules[i].pattern_count;
    while (buckets < count * 2 && buckets <= SIZE_MAX / 4) buckets *= 2;
    size_t *heads = count ? malloc(buckets * sizeof(*heads)) : NULL;
    size_t *chain = count ? malloc(count * sizeof(*chain)) : NULL;
    uint64_t *hashes = count ? malloc(count * sizeof(*hashes)) : NULL;
    YRX_PATTERN **firsts = count ? malloc(count * sizeof(*firsts)) : NULL;
    bool shared = heads && chain && hashes && firsts;
    /* The loop below builds a plan at a pattern it does not share and at the
     * first copy of each plan input (which nothing earlier matches). Those
     * patterns are found first and built on several threads (a build reads
     * its own pattern and sets its own plan); the loop then leaves them as
     * they are. The table of first copies does not depend on the plans. */
    YRX_PATTERN **tasks = count ? malloc(count * sizeof(*tasks)) : NULL;
    bool *built = count ? calloc(count, sizeof(*built)) : NULL;
    if (!tasks || !built) {
        free(built);
        built = NULL;
    }
    for (size_t i = 0; shared && i < buckets; ++i) heads[i] = SIZE_MAX;
    for (size_t i = 0; built && i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            size_t k = flat++;
            if (shared && pattern->kind == YX_PATTERN_REGEX && pattern->regexp) {
                uint64_t hash = yx_plan_inputs_hash(pattern);
                size_t bucket = (size_t)hash & (buckets - 1), at;
                for (at = heads[bucket]; at != SIZE_MAX; at = chain[at])
                    if (hashes[at] == hash && yx_same_plan_inputs(pattern, firsts[at])) break;
                if (at != SIZE_MAX) continue;
                firsts[used] = pattern;
                hashes[used] = hash;
                chain[used] = heads[bucket];
                heads[bucket] = used++;
            }
            built[k] = true;
            tasks[task_count++] = pattern;
        }
    if (built) yx_parallel_run(task_count, yx_parallel_threads(task_count, 16), yx_plan_build_task, tasks);
    used = flat = 0;
    for (size_t i = 0; shared && i < buckets; ++i) heads[i] = SIZE_MAX;
    for (size_t i = 0; i < rules->rule_count; ++i)
        for (size_t j = 0; j < rules->rules[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &rules->rules[i].patterns[j];
            bool done = built && built[flat++];
            if (!done) {
                yx_candidate_plan_free(pattern->candidate_plan);
                pattern->candidate_plan = NULL;
            }
            if (!shared || pattern->kind != YX_PATTERN_REGEX || !pattern->regexp) {
                if (!done) pattern->candidate_plan = yx_candidate_plan_build(pattern);
                continue;
            }
            uint64_t hash = yx_plan_inputs_hash(pattern);
            size_t bucket = (size_t)hash & (buckets - 1), at;
            for (at = heads[bucket]; at != SIZE_MAX; at = chain[at])
                if (hashes[at] == hash && yx_same_plan_inputs(pattern, firsts[at])) break;
            if (!done) {
                if (at != SIZE_MAX && firsts[at]->candidate_plan) pattern->candidate_plan = yx_candidate_plan_clone(firsts[at]->candidate_plan, pattern);
                if (!pattern->candidate_plan) pattern->candidate_plan = yx_candidate_plan_build(pattern);
            }
            if (at == SIZE_MAX) {
                firsts[used] = pattern;
                hashes[used] = hash;
                chain[used] = heads[bucket];
                heads[bucket] = used++;
            }
        }
    free(heads);
    free(chain);
    free(hashes);
    free(firsts);
    free(tasks);
    free(built);
}

/* Rules built while the loader inspects an internal load (yx_inspect_begin)
 * never scan: their callers read pattern declarations and conditions. */
static _Thread_local unsigned yx_inspect_depth;
void yx_inspect_begin(void)
{
    ++yx_inspect_depth;
}
/* The decoded rules of the archive being loaded on this thread, while its
 * rules are built: the build gives each pattern its archived program
 * before the programs are built. */
static _Thread_local yx_ser_rule *yx_attach_decoded;
static _Thread_local size_t yx_attach_decoded_count;
static void yx_attach_archived_regexps(YRX_RULES *rules)
{
    yx_ser_rule *decoded = yx_attach_decoded;
    if (!decoded || !rules || rules->rule_count != yx_attach_decoded_count) return;
    for (size_t i = 0; i < rules->rule_count; ++i) {
        YRX_RULE *rule = &rules->rules[i];
        if (!decoded[i].runtime_regexp_programs || rule->pattern_count != decoded[i].runtime_regexp_program_count) continue;
        for (size_t p = 0; p < rule->pattern_count; ++p) {
            YRX_PATTERN *pattern = &rule->patterns[p];
            /* yx_ser_regexp_program's own conditions for a program. */
            if (!decoded[i].runtime_regexp_programs[p] || pattern->archived_regexp || (pattern->kind != YX_PATTERN_REGEX && pattern->kind != YX_PATTERN_HEX) ||
                (pattern->kind == YX_PATTERN_REGEX && !pattern->regexp) || (pattern->kind == YX_PATTERN_HEX && !pattern->hex_atoms) ||
                (pattern->modifiers & ~(YX_MOD_DOTALL | YX_MOD_ASCII | YX_MOD_WIDE | YX_MOD_NOCASE | YX_MOD_FULLWORD | YX_MOD_PRIVATE)))
                continue;
            pattern->archived_regexp = decoded[i].runtime_regexp_programs[p];
            decoded[i].runtime_regexp_programs[p] = NULL;
        }
    }
}
void yx_inspect_end(void)
{
    if (yx_inspect_depth) --yx_inspect_depth;
}

/* Set on every thread while it runs a parallel loop's calls (the calling
 * thread for the whole loop), so a nested loop runs on its own thread. */
static _Thread_local unsigned yx_parallel_depth;

unsigned yx_parallel_threads(size_t count, size_t per_thread)
{
    uint32_t threads;
    const char *limit;
    if (yx_parallel_depth || !per_thread || count / per_thread < 2) return 1;
    threads = xx_thread_cpu_count();
    /* YARA-X loads on rayon's pool, which RAYON_NUM_THREADS sizes when it is
     * a positive number; other values keep the default. */
    limit = getenv("RAYON_NUM_THREADS");
    if (limit && *limit >= '0' && *limit <= '9') {
        unsigned long value = 0;
        const char *at = limit;
        while (*at >= '0' && *at <= '9' && value <= 100000) value = value * 10 + (unsigned long)(*at++ - '0');
        if (!*at && value) threads = value > 256 ? 256 : (uint32_t)value;
    }
    if (threads > count / per_thread) threads = (uint32_t)(count / per_thread);
    return threads ? threads : 1;
}

typedef struct {
    void (*fn)(size_t index, void *context);
    void *context;
    /* Calls before first ran on the calling thread. */
    size_t first;
    /* The memos each helper hands over before it ends. */
    struct yx_compile_memos **memos;
    volatile long memo_count;
    long memo_capacity;
} yx_parallel_call;

static void yx_parallel_call_one(size_t index, void *arg)
{
    const yx_parallel_call *call = arg;
    ++yx_parallel_depth;
    call->fn(call->first + index, call->context);
    --yx_parallel_depth;
}

static void yx_parallel_helper_done(void *arg)
{
    yx_parallel_call *call = arg;
    long slot = xx_atomic_add(&call->memo_count, 1);
    if (slot < call->memo_capacity) call->memos[slot] = yx_compile_memos_take();
}

/* Regexp compilations left by a loop's helpers below which they are freed
 * on the calling thread alone. */
enum {
    YX_PARALLEL_RELEASE_MINIMUM = 128
};
static void yx_parallel_release_one(size_t index, void *arg)
{
    struct yx_compile_memos **memos = arg;
    yx_compile_memos_release(memos[index]);
}

static uint64_t yx_parallel_now_ns(void)
{
#ifdef _WIN32
    LARGE_INTEGER frequency, counter;
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0 && QueryPerformanceCounter(&counter))
        return (uint64_t)counter.QuadPart / (uint64_t)frequency.QuadPart * UINT64_C(1000000000) +
               (uint64_t)counter.QuadPart % (uint64_t)frequency.QuadPart * UINT64_C(1000000000) / (uint64_t)frequency.QuadPart;
#endif
    return yx_monotonic_now_ns();
}

/* A loop starts on the calling thread. Only the calls left after
 * YX_PARALLEL_SERIAL_NS go to helpers, as many as there is measured work for
 * (YX_PARALLEL_THREAD_NS per thread): starting threads, their caches and a
 * shared heap cost more than a short loop. Every call writes its own result,
 * so the thread count changes nothing else. */
enum {
    YX_PARALLEL_SERIAL_NS = 1000000,
    YX_PARALLEL_THREAD_NS = 5000000
};

void yx_parallel_run(size_t count, unsigned threads, void (*fn)(size_t index, void *context), void *context)
{
    yx_parallel_run_ex(count, threads, YX_PARALLEL_SERIAL_NS, YX_PARALLEL_THREAD_NS, fn, context);
}

void yx_parallel_run_ex(size_t count, unsigned threads, uint64_t serial_ns, uint64_t thread_ns, void (*fn)(size_t index, void *context), void *context)
{
    yx_parallel_call call = {fn, context, 0, NULL, 0, 0};
    ++yx_parallel_depth;
    if (threads > 1 && count > 1) {
        uint64_t started = yx_parallel_now_ns(), elapsed = 0;
        while (call.first < count && elapsed < serial_ns) {
            fn(call.first++, context);
            elapsed = yx_parallel_now_ns() - started;
        }
        if (call.first < count) {
            double left = (double)elapsed / (double)call.first * (double)(count - call.first);
            double wanted = left / (double)thread_ns + 1.0;
            if (wanted < (double)threads) threads = (unsigned)wanted;
        }
    }
    if (threads > 1 && count - call.first > 1) {
        call.memos = calloc(threads, sizeof(*call.memos));
        if (call.memos) call.memo_capacity = (long)threads;
    }
    /* Helper threads reserve the stack of the yr executable's main thread. */
    (void)xx_parallel_for_ex(count - call.first, threads, (size_t)8 << 20, yx_parallel_call_one, call.memos ? yx_parallel_helper_done : NULL, &call);
    --yx_parallel_depth;
    /* The pure compile-time results the helpers memoized stay with this
     * thread, which would have made them itself on one thread. */
    {
        /* Adopted in the helpers' order, as a merge of each in turn adopts
         * them. The compilations this thread does not keep are then only
         * freed: many of them, on as many threads as there were helpers. */
        long merged = call.memo_count < call.memo_capacity ? call.memo_count : call.memo_capacity;
        size_t leftover = 0;
        for (long i = 0; i < merged; ++i) {
            yx_compile_memos_adopt(call.memos[i]);
            leftover += yx_compile_memos_leftover(call.memos[i]);
        }
        if (merged > 1 && leftover >= YX_PARALLEL_RELEASE_MINIMUM)
            (void)xx_parallel_for_ex((size_t)merged, (uint32_t)merged, 0, yx_parallel_release_one, NULL, call.memos);
        else
            for (long i = 0; i < merged; ++i) yx_compile_memos_release(call.memos[i]);
    }
    free(call.memos);
}

struct yx_async {
    xx_thread_t *thread;
    void (*fn)(void *context);
    void *context;
    struct yx_compile_memos *memos;
};

static int yx_async_main(void *arg)
{
    struct yx_async *task = arg;
    task->fn(task->context);
    task->memos = yx_compile_memos_take();
    return 0;
}

yx_async *yx_async_start(void (*fn)(void *context), void *context)
{
    struct yx_async *task = yx_parallel_threads(2, 1) > 1 ? calloc(1, sizeof(*task)) : NULL;
    if (task) {
        task->fn = fn;
        task->context = context;
        task->thread = xx_thread_create_ex(yx_async_main, task, (size_t)8 << 20);
        if (task->thread) return task;
        free(task);
    }
    fn(context);
    return NULL;
}

void yx_async_wait(yx_async *task)
{
    if (!task) return;
    (void)xx_thread_join(task->thread, NULL);
    yx_compile_memos_merge(task->memos);
    free(task);
}

static YRX_RULES *yx_compiler_build_impl(YRX_COMPILER *compiler, bool prepare_candidates)
{
    YRX_RULES *rules, *replacement;
    char *default_namespace;
    if (!compiler || !compiler->rules) return NULL;
    replacement = yx_new_compiler_rules();
    default_namespace = yx_strdup("default");
    if (!replacement || !default_namespace) {
        yx_free_rules(replacement);
        free(default_namespace);
        yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
        return NULL;
    }
    rules = compiler->rules;
    rules->relaxed_re_syntax = (compiler->flags & YRX_RELAXED_RE_SYNTAX) != 0;
    compiler->rules = replacement;
    compiler->global_rules_scanned = compiler->global_rule_count = 0;
    yx_rule_name_cache_free(compiler->rule_name_cache);
    compiler->rule_name_cache = NULL;
    yx_slow_pattern_cache_free(compiler->slow_pattern_cache);
    compiler->slow_pattern_cache = NULL;
    yx_attach_archived_regexps(rules);
    if (!yx_inspect_depth) yx_build_archived_programs(rules);
    if (!yx_inspect_depth) yx_build_regexp_programs(rules);
    if (!yx_inspect_depth) yx_build_chains(rules);
    if (!yx_inspect_depth) yx_build_literal_sets(rules);
    if (prepare_candidates && !yx_inspect_depth) yx_build_candidate_plans(rules);
    yx_free_globals(compiler->redefined_global_symbols, compiler->redefined_global_symbol_count);
    compiler->redefined_global_symbols = NULL;
    compiler->redefined_global_symbol_count = 0;
    yx_free_include_state(compiler);
    yx_free_compiler_policies(compiler);
    free(compiler->error_diagnostic_json);
    compiler->error_diagnostic_json = NULL;
    compiler->max_warnings = SIZE_MAX;
    free(compiler->current_namespace);
    compiler->current_namespace = default_namespace;
    compiler->current_namespace_index = 0;
    compiler->error[0] = '\0';
    return rules;
}

YRX_RULES *yrx_compiler_build(YRX_COMPILER *compiler)
{
    return yx_compiler_build_impl(compiler, true);
}

YRX_RESULT yx_compile_quiet(const char *source, YRX_RULES **out)
{
    YRX_COMPILER *compiler = NULL;
    YRX_RESULT result;
    if (!out) return yx_null_argument("rules");
    *out = NULL;
    if (!source) return yx_null_argument("src");
    result = yrx_compiler_create(0, &compiler);
    if (result != YRX_SUCCESS) return result;
    /* Callers only inspect the compiled rules; no warning is reported. */
    compiler->max_warnings = 0;
    result = yrx_compiler_add_source(compiler, source);
    if (result != YRX_SUCCESS) {
        yrx_compiler_destroy(compiler);
        return result;
    }
    yx_inspect_begin();
    *out = yrx_compiler_build(compiler);
    yx_inspect_end();
    if (!*out) {
        yrx_compiler_destroy(compiler);
        return YRX_SYNTAX_ERROR;
    }
    yrx_compiler_destroy(compiler);
    return yx_ok();
}

YRX_RESULT yrx_compile(const char *source, YRX_RULES **out)
{
    YRX_COMPILER *compiler = NULL;
    YRX_RESULT result;
    if (!out) return yx_null_argument("rules");
    *out = NULL;
    if (!source) return yx_null_argument("src");
    result = yrx_compiler_create(0, &compiler);
    if (result != YRX_SUCCESS) return result;
    result = yrx_compiler_add_source(compiler, source);
    if (result != YRX_SUCCESS) {
        yrx_compiler_destroy(compiler);
        return result;
    }
    *out = yrx_compiler_build(compiler);
    if (!*out) {
        yrx_compiler_destroy(compiler);
        return YRX_SYNTAX_ERROR;
    }
    yrx_compiler_destroy(compiler);
    return yx_ok();
}

void yrx_finalize(void)
{
}

YRX_RESULT yrx_compiler_new_namespace(YRX_COMPILER *compiler, const char *name)
{
    char *copy, *generation;
    if (!compiler) return yx_null_argument("compiler");
    if (!name) return yx_null_argument("namespace");
    if (!yx_valid_utf8(name)) return yx_compiler_invalid_utf8(name);
    if (!strcmp(compiler->current_namespace, name)) return yx_ok();
    if (compiler->current_namespace_index >= SIZE_MAX / sizeof(char *) - 1) return yx_fail(YRX_INVALID_ARGUMENT, "too many namespaces");
    copy = yx_strdup(name);
    generation = yx_strdup(name);
    if (!copy || !generation) {
        free(copy);
        free(generation);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    size_t index = compiler->current_namespace_index + 1;
    YRX_RULES *rules = compiler->rules;
    if (index >= rules->namespace_count) {
        char **grown = realloc(rules->namespace_names, (index + 1) * sizeof(*grown));
        if (!grown) {
            free(copy);
            free(generation);
            return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
        }
        rules->namespace_names = grown;
        memset(grown + rules->namespace_count, 0, (index + 1 - rules->namespace_count) * sizeof(*grown));
        rules->namespace_count = index + 1;
    }
    free(rules->namespace_names[index]);
    rules->namespace_names[index] = generation;
    free(compiler->current_namespace);
    compiler->current_namespace = copy;
    ++compiler->current_namespace_index;
    return yx_ok();
}

int yrx_rules_count(YRX_RULES *rules)
{
    if (!rules) {
        yx_null_argument("rules");
        return -1;
    }
    yx_ok();
    return (int)rules->rule_count;
}

void yrx_rules_destroy(YRX_RULES *rules)
{
    if (!rules) return;
    free(rules->serialized_prefix);
    yx_free_rules(rules);
}

YRX_RESULT yrx_rules_iter(const YRX_RULES *rules, YRX_RULE_CALLBACK callback, void *user_data)
{
    size_t i;
    if (!rules) return yx_null_argument("rules");
    if (!callback) return yx_null_argument("callback");
    for (i = 0; i < rules->rule_count; ++i) callback(&rules->rules[i], user_data);
    return yx_ok();
}

YRX_RESULT yrx_rules_iter_imports(const YRX_RULES *rules, YRX_IMPORT_CALLBACK callback, void *user_data)
{
    size_t i, j;
    if (!rules) return yx_null_argument("rules");
    if (!callback) return yx_null_argument("callback");
    for (i = 0; i < rules->import_count; ++i) {
        for (j = 0; j < i; ++j)
            if (strcmp(rules->imports[j], rules->imports[i]) == 0) break;
        if (j == i) callback(rules->imports[i], user_data);
    }
    return yx_ok();
}

YRX_RESULT yrx_scanner_create(const YRX_RULES *rules, YRX_SCANNER **out)
{
    YRX_SCANNER *scanner;
    if (!out) return yx_null_argument("scanner");
    *out = NULL;
    if (!rules) return yx_null_argument("rules");
    if (rules->unknown_wasm_import) return yx_fail(YRX_SCAN_ERROR, "compiled rules contain an unknown WebAssembly import");
    scanner = (YRX_SCANNER *)calloc(1, sizeof(*scanner));
    if (!scanner) return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    scanner->rules = rules;
    scanner->max_matches_per_pattern = 1000000;
    scanner->retain_scan_data = true;
    scanner->global_count = rules->global_count;
    if (!yx_copy_globals(rules->globals, rules->global_count, &scanner->globals) || !yx_make_views(scanner)) {
        yx_free_globals(scanner->globals, scanner->global_count);
        free(scanner);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
#ifdef XXYARA_ENABLE_PROFILING
    scanner->rule_profiles = (yx_rule_profile *)calloc(rules->rule_count ? rules->rule_count : 1, sizeof(*scanner->rule_profiles));
    if (!scanner->rule_profiles) {
        yx_destroy_views(scanner);
        yx_free_globals(scanner->globals, scanner->global_count);
        free(scanner);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
#endif
    if (!yx_scanner_create_eval_scratch(scanner)) {
        yrx_scanner_destroy(scanner);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    /* Before the first normal scan, block scanning sees descriptor defaults,
     * including absent proto2 scalars and default-valued proto3 scalars. */
    for (size_t i = 0; i < rules->import_count; ++i) {
        int module = yx_mo_module_index(rules->imports[i]);
        if (module < 0 || scanner->last_module_outputs[module]) continue;
        scanner->last_module_outputs[module] = yx_mo_empty_output(rules->imports[i]);
        if (!scanner->last_module_outputs[module]) {
            yrx_scanner_destroy(scanner);
            return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
        }
    }
    *out = scanner;
    return yx_ok();
}

static void yx_scanner_clear_module_data(YRX_SCANNER *scanner)
{
    if (!scanner) return;
    free(scanner->module_data);
    scanner->module_data = NULL;
    scanner->module_data_count = 0;
}

void yrx_scanner_destroy(YRX_SCANNER *scanner)
{
    if (!scanner) return;
    yx_scanner_destroy_eval_scratch(scanner);
    yx_destroy_views(scanner);
    yx_free_globals(scanner->globals, scanner->global_count);
    yx_scanner_clear_module_data(scanner);
    yx_zip_result_free(&scanner->zip_output);
    yx_crx_result_free(&scanner->crx_output);
    yx_vt_output_destroy(scanner->vt_output);
    yx_lnk_result_free(&scanner->native_lnk_output);
    yx_crx_result_free(&scanner->native_crx_output);
    yx_zip_result_free(&scanner->native_zip_output);
    free(scanner->native_module_scan_data);
    for (size_t module = 0; module < YX_MO_MODULE_COUNT; ++module) {
        yx_mo_output_destroy(scanner->module_outputs[module]);
        yx_mo_output_destroy(scanner->last_module_outputs[module]);
        scanner->module_outputs[module] = NULL;
    }
    free(scanner->pe_output_languages);
    free(scanner->dex_output_header_signature);
    yx_pe_scan_cache_destroy(scanner->deadline.pe_cache);
    free(scanner->dex_output_data);
#ifdef XXYARA_ENABLE_PROFILING
    free(scanner->rule_profiles);
#endif
    free(scanner->namespace_seen);
    free(scanner->namespace_order);
    free(scanner->block_data);
    free(scanner);
}

YRX_RESULT yrx_scanner_on_matching_rule(YRX_SCANNER *scanner, YRX_RULE_CALLBACK callback, void *user_data)
{
    if (!scanner) return yx_null_argument("scanner");
    scanner->callback = callback;
    scanner->callback_data = user_data;
    return yx_ok();
}

YRX_RESULT yrx_scanner_fast_scan(YRX_SCANNER *scanner, bool enabled)
{
    if (!scanner) return yx_null_argument("scanner");
    scanner->fast_scan = enabled;
    return yx_ok();
}

/* scanner/mod.rs NonMatchingRules: the zero bits of the matching-rules
 * bitmap in rule-ID order, each rule bound to the scan context, so its
 * patterns yield the matches the (lazy) pattern search recorded. */
YRX_RESULT xxyara_scanner_iter_non_matching_rules(YRX_SCANNER *scanner, YRX_RULE_CALLBACK callback, void *user_data)
{
    if (!scanner) return yx_null_argument("scanner");
    if (!callback) return yx_null_argument("callback");
    for (size_t i = 0; i < scanner->rules->rule_count; ++i) {
        const YRX_RULE *rule = scanner->views ? &scanner->views[i] : &scanner->rules->rules[i];
        if (!scanner->views || !rule->matched) callback(rule, user_data);
    }
    return yx_ok();
}

YRX_RESULT xxyara_scanner_retain_scan_data(YRX_SCANNER *scanner, bool retain)
{
    if (!scanner) return yx_null_argument("scanner");
    scanner->retain_scan_data = retain;
    if (!retain) {
        free(scanner->native_module_scan_data);
        scanner->native_module_scan_data = NULL;
        scanner->native_module_scan_size = 0;
    }
    return yx_ok();
}

YRX_RESULT yrx_scanner_max_matches_per_pattern(YRX_SCANNER *scanner, size_t limit)
{
    if (!scanner) return yx_null_argument("scanner");
    scanner->max_matches_per_pattern = limit;
    return yx_ok();
}

static YRX_RESULT yx_scan_pattern_fixed_at(YRX_PATTERN *pattern, const uint8_t *data, size_t size, size_t limit, bool fast_scan)
{
    if (pattern->fixed_at_enabled) {
        if (pattern->fixed_at_offset >= size) {
            free(pattern->matches);
            pattern->matches = NULL;
            pattern->match_count = 0;
            pattern->match_capacity = 0;
            return YRX_SUCCESS;
        }
        /* Earlier offsets must not exhaust the reporting cap before the
         * fixed position has been checked. */
        if (limit && limit <= pattern->fixed_at_offset) limit = pattern->fixed_at_offset + 1;
    }
    YRX_RESULT result = yx_scan_pattern(pattern, data, size, limit, fast_scan);
    if (result != YRX_SUCCESS || !pattern->fixed_at_enabled) return result;
    size_t kept = 0;
    for (size_t i = 0; i < pattern->match_count; ++i)
        if (pattern->matches[i].offset == pattern->fixed_at_offset) {
            pattern->matches[kept++] = pattern->matches[i];
            break;
        }
    pattern->match_count = kept;
    return YRX_SUCCESS;
}

typedef struct yx_candidate_scan {
    YRX_SCANNER *scanner;
    const uint8_t *data;
    size_t size, limit;
    YRX_PATTERN *shadows;
    YRX_RESULT result;
} yx_candidate_scan;

static bool yx_scan_candidate(void *opaque, size_t owner, uint32_t tag, size_t position)
{
    yx_candidate_scan *scan = opaque;
    YRX_PATTERN *pattern = scan->shadows ? &scan->shadows[owner] : scan->scanner->candidate_patterns[owner];
#ifdef XXYARA_ENABLE_PROFILING
    uint64_t started = yx_profile_now_ns();
#endif
    scan->result = yx_candidate_verify(pattern, pattern->candidate_plan, tag, position, scan->data, scan->size, scan->limit, scan->scanner->fast_scan);
#ifdef XXYARA_ENABLE_PROFILING
    yx_profile_add_verification(&scan->scanner->rule_profiles[scan->scanner->candidate_rule_index[owner]].pattern_nanoseconds, started);
#endif
    return scan->result == YRX_SUCCESS;
}

static YRX_RESULT yx_scan_candidates(YRX_SCANNER *scanner, const uint8_t *data, size_t size)
{
    yx_candidate_scan scan = {scanner, data, size, scanner->max_matches_per_pattern ? scanner->max_matches_per_pattern : 1, NULL, YRX_SUCCESS};
    size_t count = scanner->candidate_pattern_count;
    if (!scanner->text_prefilter) return YRX_SUCCESS;
    if (!scanner->max_matches_per_pattern) {
        scan.shadows = calloc(count, sizeof(*scan.shadows));
        if (!scan.shadows) return YRX_SCAN_ERROR;
    }
    for (size_t i = 0; i < count; ++i) {
        YRX_PATTERN *pattern = scanner->candidate_patterns[i];
        pattern->deadline = &scanner->deadline;
        if (scan.shadows) {
            scan.shadows[i] = *pattern;
            scan.shadows[i].matches = NULL;
            scan.shadows[i].match_count = scan.shadows[i].match_capacity = 0;
        }
    }
    if (!yx_atom_set_scan_candidates(scanner->text_prefilter, data, size, &scanner->deadline, yx_scan_candidate, &scan) && scan.result == YRX_SUCCESS)
        scan.result = scanner->deadline.expired ? YRX_SCAN_TIMEOUT : YRX_SCAN_ERROR;
    for (size_t i = 0; i < count; ++i) {
        YRX_PATTERN *pattern = scanner->candidate_patterns[i];
        YRX_PATTERN *found = scan.shadows ? &scan.shadows[i] : pattern;
        if (scan.result == YRX_SUCCESS) {
#ifdef XXYARA_ENABLE_PROFILING
            uint64_t started = yx_profile_now_ns();
#endif
            scan.result = yx_candidate_finalize(found, found->candidate_plan, data, size, scan.limit, scanner->fast_scan);
#ifdef XXYARA_ENABLE_PROFILING
            if (found->match_count) yx_profile_add_verification(&scanner->rule_profiles[scanner->candidate_rule_index[i]].pattern_nanoseconds, started);
#endif
        }
        if (scan.shadows) {
            if (pattern->ever_matched) {
                pattern->zero_limit_present = found->match_count != 0;
                free(found->matches);
            } else {
                pattern->matches = found->matches;
                pattern->match_count = found->match_count;
                pattern->match_capacity = found->match_capacity;
            }
        }
        if (scan.shadows) free(found->candidate_hits);
        if (pattern->match_count) pattern->ever_matched = true;
    }
    for (size_t i = 0; i < scanner->rules->rule_count; ++i)
        for (size_t j = 0; j < scanner->views[i].pattern_count; ++j) {
            YRX_PATTERN *pattern = &scanner->views[i].patterns[j];
            if (pattern->prefilter_owner == SIZE_MAX) continue;
            YRX_PATTERN *owner = scanner->candidate_patterns[pattern->prefilter_owner];
            if (owner == pattern) continue;
            if (!scanner->max_matches_per_pattern && pattern->ever_matched) {
                pattern->zero_limit_present = owner->match_count != 0 || owner->zero_limit_present;
                continue;
            }
            pattern->matches = owner->matches;
            pattern->match_count = owner->match_count;
            pattern->match_capacity = owner->match_capacity;
            pattern->matches_borrowed = true;
            if (pattern->match_count) pattern->ever_matched = true;
        }
    free(scan.shadows);
    return scan.result;
}

YRX_RESULT yrx_scanner_scan(YRX_SCANNER *scanner, const uint8_t *data, size_t size)
{
    size_t i, j;
    YRX_RESULT scan_result = YRX_SUCCESS;
    yx_ok();
    if (!scanner) return yx_null_argument("scanner");
    if (!data && size) return yx_fail(YRX_INVALID_ARGUMENT, "`data` pointer cannot be null when `len` is greater than 0");
    if (scanner->block_mode) {
        yx_scanner_clear_module_data(scanner);
        return yx_fail(YRX_INVALID_STATE, "cannot use `yrx_scanner_scan` on a scanner in multi-block mode");
    }
    yx_clear_views(scanner);
    /* Native module execution clears its function caches. Injecting an output
     * bypasses that execution, so cached hashes survive until a native scan. */
    static const char *const cache_modules[YX_MO_FUNCTION_CACHE_COUNT] = {"pe", "pe", "macho", "macho", "macho", "macho", "macho", "elf", "elf"};
    for (size_t cache = 0; cache < YX_MO_FUNCTION_CACHE_COUNT; ++cache) {
        int module = yx_mo_module_index(cache_modules[cache]);
        bool imported = false;
        for (size_t i = 0; i < scanner->rules->import_count; ++i)
            if (!strcmp(scanner->rules->imports[i], cache_modules[cache])) {
                imported = true;
                break;
            }
        if (imported && module >= 0 && !scanner->module_outputs[module]) memset(&yx_module_function_cache[cache], 0, sizeof(yx_module_function_cache[cache]));
    }
    static const char *const empty_cache_modules[] = {"hash", "math", "magic"};
    for (size_t cache = 0; cache < 3; ++cache) {
        if (scanner->empty_module_outputs[cache]) continue;
        for (size_t import = 0; import < scanner->rules->import_count; ++import)
            if (!strcmp(scanner->rules->imports[import], empty_cache_modules[cache])) {
                yx_condition_module_cache_reset(empty_cache_modules[cache]);
                break;
            }
    }
    yx_scan_deadline_start(scanner);
    if (yx_scan_deadline_reached(&scanner->deadline)) {
        scan_result = yx_fail(YRX_SCAN_TIMEOUT, "timeout");
        goto done;
    }
    scan_result = yx_scan_candidates(scanner, data, size);
    if (scan_result != YRX_SUCCESS) {
        scan_result = yx_fail(scan_result, scan_result == YRX_SCAN_TIMEOUT ? "timeout" : "pattern scan failed");
        goto done;
    }
    for (i = 0; i < scanner->rules->rule_count; ++i) {
        YRX_RULE *rule = &scanner->views[i];
#ifdef XXYARA_ENABLE_PROFILING
        uint64_t pattern_started = rule->pattern_count ? yx_profile_now_ns() : 0;
#endif
        for (j = 0; j < rule->pattern_count; ++j) {
            YRX_PATTERN *pattern = &rule->patterns[j];
            YRX_RESULT result;
            pattern->deadline = &scanner->deadline;
            if (scanner->text_prefilter && pattern->prefilter_owner != SIZE_MAX) continue;
            if (scanner->max_matches_per_pattern && pattern->scan_duplicate) {
                const YRX_PATTERN *owner = pattern->scan_duplicate;
                pattern->matches = owner->matches;
                pattern->match_count = owner->match_count;
                pattern->match_capacity = owner->match_capacity;
                pattern->matches_borrowed = true;
                if (pattern->match_count) pattern->ever_matched = true;
                continue;
            }
            if (yx_scan_deadline_reached(&scanner->deadline)) {
#ifdef XXYARA_ENABLE_PROFILING
                yx_profile_add_elapsed(&scanner->rule_profiles[i].pattern_nanoseconds, pattern_started);
#endif
                scan_result = yx_fail(YRX_SCAN_TIMEOUT, "timeout");
                goto done;
            }
            if (!scanner->max_matches_per_pattern && pattern->ever_matched) {
                YRX_PATTERN temporary = *pattern;
                temporary.matches = NULL;
                temporary.match_count = 0;
                temporary.match_capacity = 0;
                result = yx_scan_pattern_fixed_at(&temporary, data, size, 1, scanner->fast_scan);
                if (result == YRX_SUCCESS) pattern->zero_limit_present = temporary.match_count != 0;
                free(temporary.matches);
            } else {
                result = yx_scan_pattern_fixed_at(pattern, data, size, scanner->max_matches_per_pattern ? scanner->max_matches_per_pattern : 1, scanner->fast_scan);
                if (result == YRX_SUCCESS && pattern->match_count) pattern->ever_matched = true;
            }
            if (result != YRX_SUCCESS) {
#ifdef XXYARA_ENABLE_PROFILING
                yx_profile_add_elapsed(&scanner->rule_profiles[i].pattern_nanoseconds, pattern_started);
#endif
                scan_result = yx_fail(result, result == YRX_SCAN_TIMEOUT ? "timeout" : "pattern scan failed");
                goto done;
            }
        }
#ifdef XXYARA_ENABLE_PROFILING
        yx_profile_add_elapsed(&scanner->rule_profiles[i].pattern_nanoseconds, pattern_started);
#endif
    }
    {
        YRX_RESULT result = yx_evaluate_views(scanner, data, size);
        if (result != YRX_SUCCESS) {
            scan_result = result;
            goto done;
        }
    }
    scan_result = yx_ok();
done:
    memset(scanner->empty_module_outputs, 0, sizeof(scanner->empty_module_outputs));
    yx_scanner_clear_module_data(scanner);
    yx_zip_result_free(&scanner->zip_output);
    yx_crx_result_free(&scanner->crx_output);
    yx_vt_output_destroy(scanner->vt_output);
    for (size_t module = 0; module < YX_MO_MODULE_COUNT; ++module) {
        /* Block scans retain the fields established by the last normal scan.
         * Pending injected outputs are consumed only by a normal scan. */
        yx_mo_output_destroy(scanner->last_module_outputs[module]);
        scanner->last_module_outputs[module] = scanner->module_outputs[module];
        scanner->module_outputs[module] = NULL;
    }
    scanner->vt_output = NULL;
    yx_pe_scan_cache_destroy(scanner->deadline.pe_cache);
    scanner->deadline.pe_cache = NULL;
    free(scanner->pe_output_languages);
    scanner->pe_output_languages = NULL;
    scanner->pe_output_language_count = 0;
    free(scanner->dex_output_header_signature);
    scanner->dex_output_header_signature = NULL;
    scanner->dex_output_header_signature_present = false;
    free(scanner->dex_output_data);
    scanner->dex_output_data = NULL;
    scanner->pe_output_present = false;
    scanner->lnk_output_present = false;
    scanner->crx_output_present = false;
    scanner->zip_output_present = false;
    scanner->dex_output_present = false;
    return scan_result;
}

static YRX_RESULT yx_scan_file_os_error(const char *path, unsigned long error)
{
    return yx_fail_format(YRX_SCAN_ERROR, "can not open `%s`: %s", path, yx_os_error_text(error));
}

YRX_RESULT yrx_scanner_scan_file(YRX_SCANNER *scanner, const char *path)
{
    xx_io_device *file;
    uint8_t *data = NULL;
    size_t size = 0, capacity = 0, scan_limit = SIZE_MAX;
    int64_t reported_size;
    YRX_RESULT result;
    yx_ok();
    if (!scanner) return yx_null_argument("scanner");
    if (!path) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(path)) return yx_scanner_invalid_utf8(path, strlen(path));
    if (scanner->block_mode) {
        yx_scanner_clear_module_data(scanner);
        return yx_fail(YRX_INVALID_STATE, "cannot use `yrx_scanner_scan_file` on a scanner in multi-block mode");
    }
    file = xx_io_file_open(path, "rb");
    if (!file) {
        unsigned long error = yx_os_error_last();
        yx_scanner_clear_module_data(scanner);
        return yx_scan_file_os_error(path, error);
    }
    reported_size = xx_io_size(file);
#ifndef _WIN32
    {
        struct stat metadata;
        if (stat(path, &metadata) == 0) {
            if (S_ISDIR(metadata.st_mode)) {
                xx_io_close(file);
                yx_scanner_clear_module_data(scanner);
                return yx_scan_file_os_error(path, EISDIR);
            }
            if (metadata.st_size >= 0 && (uint64_t)metadata.st_size <= SIZE_MAX) reported_size = (int64_t)metadata.st_size;
        }
    }
#endif
    /* YARA-X reads no more than the initial metadata length. This includes
     * pseudo files that can produce bytes despite reporting a zero length. */
    if (reported_size >= 0 && (uint64_t)reported_size <= SIZE_MAX) scan_limit = (size_t)reported_size;
    if (scan_limit == 0) {
        xx_io_close(file);
        return yrx_scanner_scan(scanner, NULL, 0);
    }
    while (size < scan_limit) {
        ssize_t count;
        if (size == capacity) {
            size_t next = capacity ? capacity * 2 : 65536;
            uint8_t *larger;
            if (next <= capacity) {
                xx_io_close(file);
                free(data);
                yx_scanner_clear_module_data(scanner);
                return yx_fail(YRX_SCAN_ERROR, "scan file is too large");
            }
            if (next > scan_limit) next = scan_limit;
            larger = (uint8_t *)realloc(data, next);
            if (!larger) {
                xx_io_close(file);
                free(data);
                yx_scanner_clear_module_data(scanner);
                return yx_fail(YRX_SCAN_ERROR, "out of memory reading scan file");
            }
            data = larger;
            capacity = next;
        }
        count = xx_io_read(file, data + size, capacity - size);
        if (count < 0) {
            unsigned long error = yx_os_error_last();
            xx_io_close(file);
            free(data);
            yx_scanner_clear_module_data(scanner);
            return yx_scan_file_os_error(path, error);
        }
        if (count == 0) break;
        size += (size_t)count;
    }
    xx_io_close(file);
    result = yrx_scanner_scan(scanner, data, size);
    free(data);
    return result;
}

YRX_RESULT yrx_rule_identifier(const YRX_RULE *rule, const uint8_t **out, size_t *length)
{
    if (!out || !length) return yx_fail(YRX_INVALID_ARGUMENT, "`ident` and `len` pointers cannot be null");
    if (!rule) {
        *out = NULL;
        *length = 0;
        return yx_null_argument("rule");
    }
    *out = (const uint8_t *)rule->identifier;
    *length = rule->identifier ? strlen(rule->identifier) : 0;
    return yx_ok();
}

YRX_RESULT yrx_rule_namespace(const YRX_RULE *rule, const uint8_t **out, size_t *length)
{
    if (!out || !length) return yx_fail(YRX_INVALID_ARGUMENT, "`ns` and `len` pointers cannot be null");
    if (!rule) {
        *out = NULL;
        *length = 0;
        return yx_null_argument("rule");
    }
    *out = (const uint8_t *)rule->namespace_name;
    *length = rule->namespace_name_length ? rule->namespace_name_length : rule->namespace_name ? strlen(rule->namespace_name) : 0;
    return yx_ok();
}

YRX_RESULT yrx_rule_iter_metadata(const YRX_RULE *rule, YRX_METADATA_CALLBACK callback, void *user_data)
{
    size_t i;
    if (!rule) return yx_null_argument("rule");
    if (!callback) return yx_null_argument("callback");
    for (i = 0; i < rule->metadata_count; ++i) callback(&rule->metadata[i], user_data);
    return yx_ok();
}

YRX_RESULT yrx_rule_iter_patterns(const YRX_RULE *rule, YRX_PATTERN_CALLBACK callback, void *user_data)
{
    size_t i;
    if (!rule) return yx_null_argument("rule");
    if (!callback) return yx_null_argument("callback");
    for (i = 0; i < rule->pattern_count; ++i)
        if (!(rule->patterns[i].modifiers & YX_MOD_PRIVATE)) callback(&rule->patterns[i], user_data);
    return yx_ok();
}

YRX_RESULT yrx_rule_iter_tags(const YRX_RULE *rule, YRX_TAG_CALLBACK callback, void *user_data)
{
    size_t i;
    if (!rule) return yx_null_argument("rule");
    if (!callback) return yx_null_argument("callback");
    for (i = 0; i < rule->tag_count; ++i) callback(rule->tags[i], user_data);
    return yx_ok();
}

YRX_RESULT yrx_pattern_identifier(const YRX_PATTERN *pattern, const uint8_t **out, size_t *length)
{
    if (!out || !length) return yx_fail(YRX_INVALID_ARGUMENT, "`ident` and `len` pointers cannot be null");
    if (!pattern) {
        *out = NULL;
        *length = 0;
        return yx_null_argument("pattern");
    }
    *out = (const uint8_t *)pattern->identifier;
    *length = pattern->identifier ? strlen(pattern->identifier) : 0;
    return yx_ok();
}

YRX_RESULT yrx_pattern_iter_matches(const YRX_PATTERN *pattern, YRX_MATCH_CALLBACK callback, void *user_data)
{
    size_t i;
    if (!pattern) return yx_null_argument("pattern");
    if (!callback) return yx_null_argument("callback");
    for (i = 0; i < pattern->match_count; ++i) callback(&pattern->matches[i], user_data);
    return yx_ok();
}

/* The remaining entry points are declared for ABI compatibility and fail
 * explicitly until their semantics are implemented. */
YRX_RESULT yrx_compiler_add_include_dir(YRX_COMPILER *compiler, const char *dir)
{
    char **grown;
    char *copy;
    if (!compiler) return yx_null_argument("compiler");
    if (!dir) return yx_null_argument("dir");
    if (!yx_valid_utf8(dir)) return yx_compiler_invalid_utf8(dir);
    if (compiler->include_dir_count >= SIZE_MAX / sizeof(*grown)) return yx_fail(YRX_INVALID_ARGUMENT, "too many include directories");
    copy = yx_strdup(dir);
    if (!copy) return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    grown = (char **)realloc(compiler->include_dirs, (compiler->include_dir_count + 1) * sizeof(*grown));
    if (!grown) {
        free(copy);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    compiler->include_dirs = grown;
    compiler->include_dirs[compiler->include_dir_count++] = copy;
    return yx_ok();
}
YRX_RESULT yrx_compiler_ignore_module(YRX_COMPILER *compiler, const char *module)
{
    yx_module_policy *policy;
    if (!compiler) return yx_null_argument("compiler");
    if (!module) return yx_null_argument("module");
    if (!yx_valid_utf8(module)) return yx_compiler_invalid_utf8(module);
    policy = yx_get_module_policy(compiler, module);
    if (!policy) return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    policy->ignored = true;
    return yx_ok();
}
YRX_RESULT yrx_compiler_max_warnings(YRX_COMPILER *compiler, size_t n)
{
    if (!compiler) return yx_null_argument("compiler");
    compiler->max_warnings = n;
    return yx_ok();
}
YRX_RESULT yrx_compiler_enable_feature(YRX_COMPILER *compiler, const char *feature)
{
    char *copy;
    char **grown;
    if (!compiler) return yx_null_argument("compiler");
    if (!feature) return yx_null_argument("feature");
    if (!yx_valid_utf8(feature)) return yx_compiler_invalid_utf8(feature);
    for (size_t i = 0; i < compiler->enabled_feature_count; ++i)
        if (strcmp(compiler->enabled_features[i], feature) == 0) return yx_ok();
    if (compiler->enabled_feature_count >= SIZE_MAX / sizeof(*grown)) return yx_fail(YRX_INVALID_ARGUMENT, "too many enabled features");
    copy = yx_strdup(feature);
    if (!copy) return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    grown = realloc(compiler->enabled_features, (compiler->enabled_feature_count + 1) * sizeof(*grown));
    if (!grown) {
        free(copy);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    compiler->enabled_features = grown;
    compiler->enabled_features[compiler->enabled_feature_count++] = copy;
    return yx_ok();
}
YRX_RESULT yrx_compiler_ban_module(YRX_COMPILER *compiler, const char *module, const char *title, const char *message)
{
    yx_module_policy *policy;
    char *new_title, *new_message;
    if (!compiler) return yx_null_argument("compiler");
    if (!module || !title || !message) return yx_fail(YRX_INVALID_ARGUMENT, "`module`, `error_title`, and `error_msg` pointers cannot be null");
    if (!yx_valid_utf8(module)) return yx_compiler_invalid_utf8(module);
    if (!yx_valid_utf8(title)) return yx_compiler_invalid_utf8(title);
    if (!yx_valid_utf8(message)) return yx_compiler_invalid_utf8(message);
    new_title = yx_strdup(title);
    new_message = yx_strdup(message);
    if (!new_title || !new_message) {
        free(new_title);
        free(new_message);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    policy = yx_get_module_policy(compiler, module);
    if (!policy) {
        free(new_title);
        free(new_message);
        return yx_fail(YRX_INVALID_ARGUMENT, "out of memory");
    }
    free(policy->ban_title);
    free(policy->ban_message);
    policy->ban_title = new_title;
    policy->ban_message = new_message;
    return yx_ok();
}
YRX_RESULT yrx_compiler_define_global_str(YRX_COMPILER *compiler, const char *name, const char *value)
{
    if (!value) return yx_null_argument("value");
    if (!yx_valid_utf8(value)) return yx_compiler_invalid_utf8(value);
    yx_global_string string = {(char *)value, value ? strlen(value) : 0};
    return yx_define_global(compiler, name, YX_GLOBAL_STR, value ? &string : NULL);
}
YRX_RESULT yrx_compiler_define_global_bool(YRX_COMPILER *compiler, const char *name, bool value)
{
    return yx_define_global(compiler, name, YX_GLOBAL_BOOL, &value);
}
YRX_RESULT yrx_compiler_define_global_int(YRX_COMPILER *compiler, const char *name, int64_t value)
{
    return yx_define_global(compiler, name, YX_GLOBAL_INT, &value);
}
YRX_RESULT yrx_compiler_define_global_float(YRX_COMPILER *compiler, const char *name, double value)
{
    return yx_define_global(compiler, name, YX_GLOBAL_FLOAT, &value);
}
YRX_RESULT yrx_compiler_define_global_json(YRX_COMPILER *compiler, const char *name, const char *value)
{
    yx_json_scalar scalar;
    yx_global_array *array = NULL;
    yx_global_object *object = NULL;
    YRX_RESULT result;
    if (!value) return yx_null_argument("value");
    if (!yx_valid_utf8(value)) return yx_compiler_invalid_utf8(value);
    if (!yx_capi_json_validate(value)) return YRX_INVALID_ARGUMENT;
    if (!compiler) return yx_null_argument("compiler");
    if (!name) return yx_null_argument("ident");
    if (!yx_valid_utf8(name)) return yx_compiler_invalid_utf8(name);
    result = yx_parse_json_scalar(value, &scalar);
    if (result == YRX_NOT_SUPPORTED || result == YRX_VARIABLE_ERROR) {
        if (!yx_valid_json_field_name(name)) {
            char message[512];
            return yx_fail_format(YRX_VARIABLE_ERROR, "invalid identifier `%s`", name);
        }
    }
    if (result == YRX_NOT_SUPPORTED) {
        const char *at = value;
        while (*at == ' ' || *at == '\t' || *at == '\n' || *at == '\r') ++at;
        if (*at == '[') {
            result = yx_parse_json_array(value, &array);
            if (result != YRX_SUCCESS) return result;
            result = yx_define_global(compiler, name, YX_GLOBAL_ARRAY, array);
            yx_free_global_array(array);
            return result;
        }
        if (*at == '{') {
            result = yx_parse_json_object(value, &object);
            if (result != YRX_SUCCESS) return result;
            result = yx_define_global(compiler, name, YX_GLOBAL_STRUCT, object);
            yx_free_global_object(object);
            return result;
        }
    }
    if (result != YRX_SUCCESS) return result;
    result = yx_define_global(compiler, name, scalar.type, yx_json_scalar_value(&scalar));
    if (scalar.type == YX_GLOBAL_STR) xx_str_free(scalar.value.string.data);
    return result;
}
YRX_RESULT yrx_compiler_errors_json(YRX_COMPILER *compiler, YRX_BUFFER **buffer)
{
    size_t length;
    char *json;
    YRX_RESULT result;
    if (!buffer) return yx_null_argument("buf");
    *buffer = NULL;
    if (!compiler) return yx_null_argument("compiler");
    if (compiler->error_diagnostic_json) {
        length = strlen(compiler->error_diagnostic_json);
        if (length > SIZE_MAX - 3) return yx_fail(YRX_SERIALIZATION_ERROR, "error JSON too large");
        json = (char *)malloc(length + 3);
        if (!json) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory");
        json[0] = '[';
        memcpy(json + 1, compiler->error_diagnostic_json, length);
        json[length + 1] = ']';
        json[length + 2] = '\0';
        if (compiler->flags & YRX_COLORIZE_ERRORS) {
            char *colored = yx_colorize_reports(compiler, json);
            if (colored) {
                free(json);
                json = colored;
                length = strlen(json) - 2;
            }
        }
        result = yx_buffer_from_text(json, length + 2, buffer);
        free(json);
        return result;
    }
    return yx_error_json(compiler->error, buffer);
}
YRX_RESULT yrx_compiler_warnings_json(YRX_COMPILER *compiler, YRX_BUFFER **buffer)
{
    size_t size = 2, used = 0;
    char *json;
    YRX_RESULT result;
    if (!buffer) return yx_null_argument("buf");
    *buffer = NULL;
    if (!compiler) return yx_null_argument("compiler");
    if (compiler->flags & YRX_COLORIZE_ERRORS) {
        /* Each element colored on its own, as the array would be (a
         * report's text closes its element): one element at a time beside
         * the result. */
        yx_warning_bytes out = {0};
        bool ok = yx_warning_bytes_put(&out, "[", 1);
        for (size_t i = 0; ok && i < compiler->warning_count; ++i) {
            char *element = yx_compiler_warning_json(compiler, i);
            ok = element && (!i || yx_warning_bytes_put(&out, ",", 1)) && yx_warning_bytes_put(&out, element, strlen(element));
            free(element);
        }
        if (!ok || !yx_warning_bytes_put(&out, "]", 1)) {
            free(out.data);
            return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory");
        }
        json = out.data;
        used = out.used;
    } else {
        for (size_t i = 0; i < compiler->warning_count; ++i) {
            size_t length = yx_warning_expand_into(&compiler->warning_rows, compiler->warnings[i], NULL);
            /* size + length + separator + the terminator must fit. */
            if (length == SIZE_MAX || size >= SIZE_MAX - 3 || length > SIZE_MAX - 2 - size - (i != 0)) return yx_fail(YRX_SERIALIZATION_ERROR, "warning JSON too large");
            size += length + (i != 0);
        }
        json = (char *)malloc(size + 1);
        if (!json) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory");
        json[used++] = '[';
        for (size_t i = 0; i < compiler->warning_count; ++i) {
            if (i) json[used++] = ',';
            used += yx_warning_expand_into(&compiler->warning_rows, compiler->warnings[i], json + used);
        }
        json[used++] = ']';
        json[used] = '\0';
    }
    /* The buffer takes the text: no second copy of what can be large. */
    result = yx_buffer_adopt_text(json, used, buffer);
    return result;
}
char *yx_compiler_warning_json(const YRX_COMPILER *compiler, size_t index)
{
    char *json;
    if (!compiler || index >= compiler->warning_count) return NULL;
    json = yx_warning_expand(compiler, compiler->warnings[index], NULL);
    if (json && (compiler->flags & YRX_COLORIZE_ERRORS)) {
        /* As in the array: the element's report text closes it. */
        char *colored = yx_colorize_reports(compiler, json);
        free(json);
        json = colored; /* NULL: out of memory, an error, never uncolored */
    }
    return json;
}
bool yx_compiler_warnings_contain(const YRX_COMPILER *compiler, const char *needle)
{
    if (!compiler || !needle) return false;
    for (size_t i = 0; i < compiler->warning_count; ++i)
        if (strstr(compiler->warnings[i], needle)) return true;
    return false;
}
YRX_RESULT yrx_rules_serialize(const YRX_RULES *rules, YRX_BUFFER **buffer)
{
    yx_ser_result status;
    uint8_t *data = NULL;
    size_t length = 0;
    YRX_BUFFER *result;
    if (!buffer) return yx_null_argument("buf");
    *buffer = NULL;
    if (!rules) return yx_null_argument("rules");
    if (rules->serialized_prefix) {
        length = rules->serialized_prefix_length;
        data = malloc(length ? length : 1);
        if (!data) return yx_fail(YRX_SERIALIZATION_ERROR, "cannot encode YARA-X rules");
        memcpy(data, rules->serialized_prefix, length);
        status = YX_SER_SUCCESS;
    } else {
        status = yx_ser_encode(rules, &data, &length);
    }
    if (status == YX_SER_UNSUPPORTED) return yx_unsupported("compiled-rule serialization for this rule shape");
    if (status != YX_SER_SUCCESS) return yx_fail(YRX_SERIALIZATION_ERROR, "cannot encode YARA-X rules");
    result = malloc(sizeof(*result));
    if (!result) {
        free(data);
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot encode YARA-X rules");
    }
    result->data = data;
    result->length = length;
    *buffer = result;
    return yx_ok();
}

/* Emit a decimal YARA literal that round-trips an f64 without exponent
 * syntax, which the rule language does not accept. */
static bool yx_float_source_literal(double value, char *out, size_t capacity)
{
    char compact[64], digits[32];
    const char *exponent;
    size_t digit_count = 0, point = SIZE_MAX, sign = 0, length;
    long scale;
    int decimal_position;
    char *end;
    if (!isfinite(value) || !out || capacity == 0) return false;
    if (snprintf(compact, sizeof(compact), "%.17g", value) < 0) return false;
    exponent = strchr(compact, 'e');
    if (!exponent) exponent = strchr(compact, 'E');
    if (!exponent) {
        length = strlen(compact);
        if (length + (strchr(compact, '.') ? 0 : 2) >= capacity) return false;
        memcpy(out, compact, length + 1);
        if (!strchr(compact, '.')) strcat(out, ".0");
        return true;
    }
    scale = strtol(exponent + 1, &end, 10);
    if (*end != '\0' || scale < -400 || scale > 400) return false;
    sign = compact[0] == '-' ? 1 : 0;
    for (const char *p = compact + sign; p < exponent; ++p) {
        if (*p == '.') {
            point = digit_count;
        } else if (*p >= '0' && *p <= '9' && digit_count + 1 < sizeof(digits)) {
            digits[digit_count++] = *p;
        } else {
            return false;
        }
    }
    if (point == SIZE_MAX) point = digit_count;
    decimal_position = (int)point + (int)scale;
    if (decimal_position <= 0) length = sign + 2 + (size_t)-decimal_position + digit_count;
    else if ((size_t)decimal_position >= digit_count) length = sign + (size_t)decimal_position + 2;
    else length = sign + digit_count + 1;
    if (length >= capacity) return false;
    {
        char *p = out;
        if (sign) *p++ = '-';
        if (decimal_position <= 0) {
            *p++ = '0';
            *p++ = '.';
            memset(p, '0', (size_t)-decimal_position);
            p += (size_t)-decimal_position;
            memcpy(p, digits, digit_count);
            p += digit_count;
        } else if ((size_t)decimal_position >= digit_count) {
            memcpy(p, digits, digit_count);
            p += digit_count;
            memset(p, '0', (size_t)decimal_position - digit_count);
            p += (size_t)decimal_position - digit_count;
            *p++ = '.';
            *p++ = '0';
        } else {
            memcpy(p, digits, (size_t)decimal_position);
            p += (size_t)decimal_position;
            *p++ = '.';
            memcpy(p, digits + decimal_position, digit_count - (size_t)decimal_position);
            p += digit_count - (size_t)decimal_position;
        }
        *p = '\0';
    }
    return true;
}

static const char *yx_vt_permutation_variant(int64_t value)
{
    switch (value) {
        case 31: return "ALL";
        case 1: return "TYPO";
        case 2: return "HOMOGLYPH";
        case 4: return "HYPHENATION";
        case 8: return "SUBDOMAIN";
        case 16: return "BITSQUATTING";
        default: return NULL;
    }
}

static yx_ser_result yx_deserialized_prefix_length(const uint8_t *data, size_t size, size_t *prefix_length)
{
    if (yx_ser_validate_v12(data, size, prefix_length) == YX_SER_WIRE_VALID) return YX_SER_SUCCESS;
    size_t low = 12, high = size;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        yx_ser_rule *probe = NULL;
        size_t probe_count = 0;
        yx_ser_result status = yx_ser_decode_many(data, middle, &probe, &probe_count);
        yx_ser_rules_destroy(probe, probe_count);
        if (status == YX_SER_NO_MEMORY) return status;
        if (status == YX_SER_SUCCESS) high = middle;
        else low = middle + 1;
    }
    *prefix_length = low;
    return YX_SER_SUCCESS;
}

/* Bincode decodes the fast-scan Option<NonZeroU32> before the final rules
 * profiling flag. A malformed option or zero value is a decode error; a
 * valid option change can instead make the following 1 the profiling flag,
 * which YARA-X rejects after decoding the archive. Repair exactly one footer
 * byte and require a fully supported, exact-length archive before assigning
 * either official error. */
static const char *yx_classify_serialized_fast_scan_footer(const uint8_t *data, size_t size)
{
    static const uint8_t canonical[6] = {0, 0, 1, 1, 1, 0};
    static const char decode_error[] = "cannot decode YARA-X rules";
    static const char u32_u128_error[] = "cannot decode YARA-X rules: InvalidIntegerType { expected: U32, found: U128 }";
    static const char profiling_error[] = "invalid YARA-X compiled rules file";
    const char *message = NULL;
    size_t changed_at = SIZE_MAX, prefix_length = 0;
    uint8_t *repaired;
    yx_ser_rule *probe = NULL;
    size_t probe_count = 0;
    yx_ser_result status;
    if (size < sizeof(canonical)) return NULL;
    for (size_t i = 0; i < sizeof(canonical); ++i) {
        if (data[size - sizeof(canonical) + i] == canonical[i]) continue;
        if (changed_at != SIZE_MAX) return NULL;
        changed_at = i;
    }
    if (changed_at == SIZE_MAX || changed_at < 3) return NULL;
    switch (changed_at) {
        case 3: /* Option<NonZeroU32>: None moves the next 1 to the bool. */
            if (data[size - 3] != 0 && data[size - 3] != 255) return NULL;
            message = data[size - 3] == 0 ? profiling_error : decode_error;
            break;
        case 4: /* A zero NonZeroU32 or invalid integer marker. */
            if (data[size - 2] == 254) message = u32_u128_error;
            else if (data[size - 2] == 0 || data[size - 2] == 255) message = decode_error;
            else return NULL;
            break;
        case 5: /* The profiling flag is a bincode bool. */ message = data[size - 1] == 1 ? profiling_error : decode_error; break;
        default: return NULL;
    }
    repaired = malloc(size);
    if (!repaired) return NULL;
    memcpy(repaired, data, size);
    repaired[size - sizeof(canonical) + changed_at] = canonical[changed_at];
    status = yx_ser_decode_many(repaired, size, &probe, &probe_count);
    yx_ser_rules_destroy(probe, probe_count);
    if (status == YX_SER_SUCCESS) status = yx_deserialized_prefix_length(repaired, size, &prefix_length);
    free(repaired);
    return status == YX_SER_SUCCESS && prefix_length == size && probe_count == 1 ? message : NULL;
}

/* The supported single-rule archives end in either a zeroed footer or the
 * fast-scan footer above. If appending its final zero byte yields one fully
 * decoded archive with no trailing data, bincode's next read requests just
 * that byte. This keeps other truncated and malformed shapes unclassified. */
static bool yx_is_missing_final_archive_zero(const uint8_t *data, size_t size)
{
    static const uint8_t zero_footer_prefix[5] = {0, 0, 0, 0, 0};
    static const uint8_t fast_footer_prefix[5] = {0, 0, 1, 1, 1};
    yx_ser_rule *probe = NULL;
    size_t probe_count = 0, prefix_length = 0;
    yx_ser_result status;
    uint8_t *repaired;
    if (!data || size < 16 || size == SIZE_MAX || (memcmp(data + size - 5, zero_footer_prefix, 5) != 0 && memcmp(data + size - 5, fast_footer_prefix, 5) != 0))
        return false;
    repaired = malloc(size + 1);
    if (!repaired) return false;
    memcpy(repaired, data, size);
    repaired[size] = 0;
    status = yx_ser_decode_many(repaired, size + 1, &probe, &probe_count);
    yx_ser_rules_destroy(probe, probe_count);
    if (status == YX_SER_SUCCESS) status = yx_deserialized_prefix_length(repaired, size + 1, &prefix_length);
    free(repaired);
    return status == YX_SER_SUCCESS && probe_count == 1 && prefix_length == size + 1;
}

static bool yx_archive_source_append(char *source, size_t capacity, size_t *used, const char *format, ...)
{
    va_list args;
    int written;
    if (*used >= capacity) return false;
    va_start(args, format);
    written = vsnprintf(source + *used, capacity - *used, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= capacity - *used) return false;
    *used += (size_t)written;
    return true;
}

/* The batch source of a loaded archive's rules, compiled in chunks of whole
 * rules on several threads. Each chunk is compiled by a compiler of its own,
 * set up as the batch compiler (flags, namespace; batches with imports,
 * globals or global rules are compiled whole), and its rules are appended to
 * the batch compiler in order. A rule is compiled from its own text, the
 * compiler's setup and the earlier rules of that compiler only: those decide
 * whether its name is a duplicate and what its condition can refer to. So
 * when every chunk compiles without an error and no rule name occurs in two
 * chunks, the batch compiles without an error too, every reference resolved
 * in its chunk exactly as in the batch, and each rule is the batch's rule
 * except for its offsets into the source, line number and source serial,
 * which are then set to the batch's. Otherwise the batch is compiled whole. */
enum {
    YX_BATCH_RULES_PER_CHUNK = 32,
    YX_BATCH_MINIMUM_RULES = 256
};

typedef struct {
    const char *source;
    /* starts[i]: offset of rule i's text in source; starts[count]: length. */
    const size_t *starts;
    size_t count;
    uint32_t flags;
    const char *namespace_name;
    size_t namespace_index;
    YRX_COMPILER **compilers;
    YRX_RESULT *results;
} yx_batch_job;

static void yx_batch_chunk_task(size_t index, void *context)
{
    yx_batch_job *job = context;
    size_t first = index * YX_BATCH_RULES_PER_CHUNK;
    size_t last = job->count - first > YX_BATCH_RULES_PER_CHUNK ? first + YX_BATCH_RULES_PER_CHUNK : job->count;
    size_t begin = job->starts[first], length = job->starts[last] - begin;
    YRX_COMPILER *compiler = NULL;
    char *text = malloc(length + 1);
    YRX_RESULT result = text ? yrx_compiler_create(job->flags, &compiler) : YRX_INVALID_ARGUMENT;
    if (result == YRX_SUCCESS) {
        compiler->max_warnings = 0;
        result = yrx_compiler_new_namespace(compiler, job->namespace_name);
    }
    if (result == YRX_SUCCESS) {
        compiler->current_namespace_index = job->namespace_index;
        memcpy(text, job->source + begin, length);
        text[length] = 0;
        result = yrx_compiler_add_source(compiler, text);
    }
    free(text);
    job->compilers[index] = compiler;
    job->results[index] = result;
}

/* Whether a rule name occurs twice in the chunks' rules (one namespace). */
static bool yx_batch_duplicate_names(YRX_COMPILER *const *compilers, size_t chunks, size_t total, bool *duplicate)
{
    size_t slots = 64;
    while (slots < total * 2 && slots <= SIZE_MAX / 4) slots *= 2;
    const char **table = calloc(slots, sizeof(*table));
    if (!table) return false;
    *duplicate = false;
    for (size_t k = 0; k < chunks && !*duplicate; ++k) {
        const YRX_RULES *part = compilers[k]->rules;
        for (size_t i = 0; i < part->rule_count && !*duplicate; ++i) {
            const char *name = part->rules[i].identifier;
            uint64_t hash = 1469598103934665603ull;
            for (const unsigned char *at = (const unsigned char *)name; *at; ++at) hash = (hash ^ *at) * 1099511628211ull;
            size_t slot = (size_t)(hash ^ (hash >> 32)) & (slots - 1);
            while (table[slot] && strcmp(table[slot], name)) slot = (slot + 1) & (slots - 1);
            if (table[slot]) *duplicate = true;
            else table[slot] = name;
        }
    }
    free(table);
    return true;
}

#ifdef XXYARA_VERIFY_LOAD
static void yx_verify_batch(const YRX_COMPILER *compiler, const char *source, size_t first_rule);
#endif

static YRX_RESULT yx_compile_batch(YRX_COMPILER *compiler, const char *source, size_t length, const size_t *starts, size_t count, bool any_global)
{
    YRX_RULES *rules = compiler->rules;
    size_t chunks = count / YX_BATCH_RULES_PER_CHUNK + (count % YX_BATCH_RULES_PER_CHUNK != 0);
    unsigned threads = yx_parallel_threads(count, YX_BATCH_RULES_PER_CHUNK);
    YRX_COMPILER **compilers = NULL;
    YRX_RESULT *results = NULL;
    bool joined = false;
    if (!starts || threads < 2 || count < YX_BATCH_MINIMUM_RULES || any_global || length >= yx_get_source_size_limit() || rules->rule_count || rules->import_count ||
        rules->global_count || compiler->redefined_global_symbol_count || compiler->module_policy_count || compiler->ignored_import_count ||
        compiler->ignored_rule_count || compiler->include_dir_count || compiler->include_depth || compiler->enabled_feature_count || compiler->warning_count ||
        compiler->max_warnings || compiler->error_diagnostic_json)
        return yrx_compiler_add_source(compiler, source);
    compilers = calloc(chunks, sizeof(*compilers));
    results = calloc(chunks, sizeof(*results));
    if (compilers && results) {
        yx_batch_job job = {source, starts, count, compiler->flags, compiler->current_namespace, compiler->current_namespace_index, compilers, results};
        size_t total = 0, capacity = rules->rule_capacity, have = rules->rule_count;
        bool allocated = rules->rules != NULL, duplicate = true;
        yx_parallel_run(chunks, threads, yx_batch_chunk_task, &job);
        joined = true;
        for (size_t k = 0; k < chunks; ++k) {
            if (results[k] != YRX_SUCCESS || !compilers[k]) joined = false;
            else total += compilers[k]->rules->rule_count;
        }
        if (joined && (!yx_batch_duplicate_names(compilers, chunks, total, &duplicate) || duplicate)) joined = false;
        /* The rule array grows as yx_append_rule grows it. */
        for (size_t i = 0; joined && i < total; ++i, ++have)
            if (!allocated || have >= capacity) {
                capacity = have < 8 ? 8 : have <= SIZE_MAX / 2 ? have * 2 : SIZE_MAX;
                allocated = true;
            }
        if (joined && total) {
            YRX_RULE *grown = capacity > SIZE_MAX / sizeof(*grown) ? NULL : realloc(rules->rules, capacity * sizeof(*grown));
            if (!grown) joined = false;
            else {
                rules->rules = grown;
                rules->rule_capacity = capacity;
            }
        }
        if (joined) {
            size_t serial = ++compiler->next_source_serial, lines = 0, scanned = 0, first_rule = rules->rule_count;
            for (size_t k = 0; k < chunks; ++k) {
                YRX_RULES *part = compilers[k]->rules;
                size_t begin = starts[k * YX_BATCH_RULES_PER_CHUNK];
                for (; scanned < begin; ++scanned) lines += source[scanned] == '\n';
                for (size_t i = 0; i < part->rule_count; ++i) {
                    YRX_RULE *rule = &part->rules[i];
                    rule->declaration_start += begin;
                    rule->declaration_end += begin;
                    rule->declaration_line_number += lines;
                    rule->declaration_source_serial = serial;
                    for (size_t p = 0; p < rule->pattern_count; ++p) {
                        YRX_PATTERN *pattern = &rule->patterns[p];
                        pattern->declaration_start += begin;
                        pattern->declaration_end += begin;
                        pattern->literal_start += begin;
                        pattern->literal_end += begin;
                        pattern->pattern_end += begin;
                    }
                    rules->rules[rules->rule_count++] = *rule;
                }
                part->rule_count = 0;
            }
#ifdef XXYARA_VERIFY_LOAD
            yx_verify_batch(compiler, source, first_rule);
#else
            (void)first_rule;
#endif
        }
    }
    for (size_t k = 0; compilers && k < chunks; ++k) yrx_compiler_destroy(compilers[k]);
    free(compilers);
    free(results);
    if (!joined) return yrx_compiler_add_source(compiler, source);
    if (!yx_append_source(rules, source)) {
        snprintf(compiler->error, sizeof(compiler->error), "out of memory saving source");
        return yx_fail(YRX_SYNTAX_ERROR, compiler->error);
    }
    return yx_ok();
}

#ifdef XXYARA_VERIFY_LOAD
/* Verify builds (-DXXYARA_VERIFY_LOAD) compile every joined batch whole as
 * well and abort when a rule differs in any field the parser sets. */
static bool yx_verify_string(const char *a, const char *b)
{
    return (!a && !b) || (a && b && !strcmp(a, b));
}

static bool yx_verify_bytes(const void *a, const void *b, size_t length)
{
    return (!a && !b) || (a && b && (!length || !memcmp(a, b, length)));
}

bool yx_verify_pattern(const YRX_PATTERN *a, const YRX_PATTERN *b)
{
    return yx_verify_string(a->identifier, b->identifier) && a->declaration_start == b->declaration_start && a->declaration_end == b->declaration_end &&
           a->literal_start == b->literal_start && a->literal_end == b->literal_end && a->pattern_end == b->pattern_end && a->kind == b->kind &&
           a->modifiers == b->modifiers && a->length == b->length && yx_verify_bytes(a->bytes, b->bytes, a->length) && yx_verify_bytes(a->mask, b->mask, a->length) &&
           a->hex_atom_count == b->hex_atom_count && yx_hex_atoms_equal(a->hex_atoms, a->hex_atom_count, b->hex_atoms, b->hex_atom_count, 0) &&
           a->hex_has_jump == b->hex_has_jump && yx_verify_string(a->regexp, b->regexp) && yx_verify_string(a->gap_head_regexp, b->gap_head_regexp) &&
           yx_verify_string(a->base64_alphabet, b->base64_alphabet) && yx_verify_string(a->base64wide_alphabet, b->base64wide_alphabet) &&
           !memcmp(&a->base64_archived_prefilter, &b->base64_archived_prefilter, sizeof(a->base64_archived_prefilter)) &&
           a->archived_literal_prefilter.count == b->archived_literal_prefilter.count &&
           yx_verify_bytes(a->archived_literal_prefilter.atoms, b->archived_literal_prefilter.atoms,
                           a->archived_literal_prefilter.count * sizeof(*a->archived_literal_prefilter.atoms)) &&
           a->xor_min == b->xor_min && a->xor_max == b->xor_max && a->match_count == b->match_count && !a->matches == !b->matches && a->ever_matched == b->ever_matched &&
           a->fast_scan_needs_all == b->fast_scan_needs_all && a->fixed_at_enabled == b->fixed_at_enabled && a->fixed_at_offset == b->fixed_at_offset &&
           a->fast_count_enabled == b->fast_count_enabled && a->fast_count_threshold == b->fast_count_threshold &&
           a->global_atom_count_hint == b->global_atom_count_hint && a->compat_pattern_id == b->compat_pattern_id && a->compat_nonanchorable == b->compat_nonanchorable &&
           !a->deadline == !b->deadline && !a->rx_program == !b->rx_program && yx_verify_string(a->rx_program_regexp, b->rx_program_regexp) &&
           a->rx_program_modifiers == b->rx_program_modifiers && !a->candidate_plan == !b->candidate_plan && a->prefilter_owner == b->prefilter_owner;
}

static bool yx_verify_metadata(const YRX_METADATA *a, const YRX_METADATA *b)
{
    if (!yx_verify_string(a->identifier, b->identifier) || a->value_type != b->value_type) return false;
    switch (a->value_type) {
        case YRX_STRING: return yx_verify_string(a->value.string, b->value.string);
        case YRX_BYTES: return a->value.bytes.length == b->value.bytes.length && yx_verify_bytes(a->value.bytes.data, b->value.bytes.data, a->value.bytes.length);
        default: return !memcmp(&a->value, &b->value, sizeof(a->value));
    }
}

static bool yx_verify_rule(const YRX_RULE *a, const YRX_RULE *b)
{
    if (!yx_verify_string(a->identifier, b->identifier) || !yx_verify_string(a->namespace_name, b->namespace_name) ||
        a->namespace_name_length != b->namespace_name_length || a->namespace_index != b->namespace_index || !yx_verify_string(a->declaration_line, b->declaration_line) ||
        !yx_verify_string(a->declaration_origin, b->declaration_origin) || a->declaration_origin_explicit != b->declaration_origin_explicit ||
        a->declaration_line_number != b->declaration_line_number || a->declaration_column != b->declaration_column || a->declaration_start != b->declaration_start ||
        a->declaration_end != b->declaration_end || a->declaration_source_serial != b->declaration_source_serial || a->is_private != b->is_private ||
        a->is_global != b->is_global || a->tag_count != b->tag_count || a->metadata_count != b->metadata_count || a->pattern_count != b->pattern_count ||
        !yx_verify_string(a->condition_text, b->condition_text) || a->matched != b->matched || !yx_condition_equal(a->condition, b->condition))
        return false;
    for (size_t i = 0; i < a->tag_count; ++i)
        if (!yx_verify_string(a->tags[i], b->tags[i])) return false;
    for (size_t i = 0; i < a->metadata_count; ++i)
        if (!yx_verify_metadata(&a->metadata[i], &b->metadata[i])) return false;
    for (size_t i = 0; i < a->pattern_count; ++i)
        if (!yx_verify_pattern(&a->patterns[i], &b->patterns[i])) return false;
    return true;
}

static void yx_verify_batch(const YRX_COMPILER *compiler, const char *source, size_t first_rule)
{
    YRX_COMPILER *whole = NULL;
    const YRX_RULES *joined = compiler->rules;
    YRX_RESULT result = yrx_compiler_create(compiler->flags, &whole);
    if (result == YRX_SUCCESS) {
        whole->max_warnings = 0;
        result = yrx_compiler_new_namespace(whole, compiler->current_namespace);
    }
    if (result == YRX_SUCCESS) {
        whole->current_namespace_index = compiler->current_namespace_index;
        whole->next_source_serial = compiler->next_source_serial - 1;
        result = yrx_compiler_add_source(whole, source);
    }
    if (result != YRX_SUCCESS || whole->rules->rule_count != joined->rule_count - first_rule || whole->rules->rule_capacity != joined->rule_capacity) {
        fprintf(stderr, "XXYARA_VERIFY_LOAD: joined batch differs: result %d, %zu rules (whole %zu)\n", (int)result, joined->rule_count - first_rule,
                whole ? whole->rules->rule_count : 0);
        abort();
    }
    for (size_t i = 0; i < whole->rules->rule_count; ++i)
        if (!yx_verify_rule(&joined->rules[first_rule + i], &whole->rules->rules[i])) {
            fprintf(stderr, "XXYARA_VERIFY_LOAD: joined batch rule %zu (%s) differs\n", i, whole->rules->rules[i].identifier);
            abort();
        }
    yrx_compiler_destroy(whole);
}
#endif

/* yr prints a decode error with its bincode detail; the C API reports only
 * the error itself. */
_Thread_local bool yx_deserialize_error_detail;

static YRX_RESULT yx_rules_deserialize(const uint8_t *data, size_t size, YRX_RULES **rules, bool relaxed);

YRX_RESULT yrx_rules_deserialize(const uint8_t *data, size_t size, YRX_RULES **rules)
{
    static const char decode[] = "cannot decode YARA-X rules: ";
    static const char invalid[] = "invalid YARA-X compiled rules file: ";
    YRX_RESULT result;
    if (!rules) return yx_null_argument("rules");
    *rules = NULL;
    if (!data) return yx_null_argument("data");
    size_t syntax_at;
    bool relaxed = yx_ser_archive_relaxed_syntax(data, size, &syntax_at);
    uint8_t *normalized = NULL;
    if (relaxed) {
        normalized = malloc(size);
        if (!normalized) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory decoding YARA-X rules");
        memcpy(normalized, data, size);
        normalized[syntax_at] = 0;
    }
    yx_wire_known wire_known;
    yx_ser_validate_memo_begin(&wire_known, normalized ? normalized : data, size);
    yx_ser_ac_memo_begin();
    result = yx_rules_deserialize(normalized ? normalized : data, size, rules, relaxed);
    yx_ser_ac_memo_end();
    yx_ser_validate_memo_end(&wire_known);
    free(normalized);
    if (result != YRX_SUCCESS) *rules = NULL;
    const char *error = yrx_last_error();
    /* Serializing loaded rules keeps the archive's runtime import order, as
     * YARA-X keeps the loaded module. */
    if (result == YRX_SUCCESS && *rules) {
        if (!yx_inspect_depth) yx_build_candidate_plans(*rules);
        /* An inspected load is never serialized again. */
        (*rules)->archive_cli = !yx_inspect_depth && !yx_ser_archive_capi_ordered(data, size);
        (*rules)->relaxed_re_syntax = relaxed;
        if (relaxed && (*rules)->serialized_prefix && syntax_at < (*rules)->serialized_prefix_length) (*rules)->serialized_prefix[syntax_at] = 1;
    }
    if (result == YRX_SERIALIZATION_ERROR && !yx_deserialize_error_detail && error && strncmp(error, decode, sizeof(decode) - 1) == 0)
        return yx_fail(result, "cannot decode YARA-X rules");
    if (result == YRX_SERIALIZATION_ERROR && !yx_deserialize_error_detail && error && strncmp(error, invalid, sizeof(invalid) - 1) == 0)
        return yx_fail(result, "invalid YARA-X compiled rules file");
    return result;
}

static YRX_RESULT yx_rules_deserialize(const uint8_t *data, size_t size, YRX_RULES **rules, bool relaxed)
{
    static const uint8_t magic[8] = {'Y', 'A', 'R', 'A', '-', 'X', 0, 0};
    static const uint8_t default_namespace[7] = {'d', 'e', 'f', 'a', 'u', 'l', 't'};
    uint32_t version;
    char message[128];
    yx_ser_rule *decoded = NULL;
    size_t decoded_count = 0;
    yx_ser_result status;
    YRX_COMPILER *compiler = NULL;
    YRX_RULES *deserialized = NULL;
    YRX_RESULT result;
    char *source;
    uint8_t *normalized = NULL;
    size_t embedded_nul_at = SIZE_MAX;
    size_t prefix_length = 0;
    bool normalized_empty_ac = false;
    bool normalized_bitmap_shift = false;
    bool normalized_import_name = false;
    bool noncanonical_ac = false;
    bool noncanonical_literal_pool = false;
    bool preserve_serialized_prefix = false;
    if (!data || !rules) return YRX_INVALID_ARGUMENT;
    if (size < 12 || memcmp(data, magic, sizeof(magic)) != 0) return yx_fail(YRX_SERIALIZATION_ERROR, "not a YARA-X compiled rules file");
    version = (uint32_t)data[8] | ((uint32_t)data[9] << 8) | ((uint32_t)data[10] << 16) | ((uint32_t)data[11] << 24);
    if (version != 12) {
        snprintf(message, sizeof(message), "incompatible version, expected 12 got %u", version);
        return yx_fail(YRX_SERIALIZATION_ERROR, message);
    }
    if (size == 12) return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules: UnexpectedEnd { additional: 1 }");
    int wire_status = yx_ser_validate_v12(data, size, NULL);
    if (wire_status == YX_SER_WIRE_DECODE && yx_ser_v12_decode_error_detail()) {
        snprintf(message, sizeof(message), "cannot decode YARA-X rules: %s", yx_ser_v12_decode_error_detail());
        return yx_fail(YRX_SERIALIZATION_ERROR, message);
    }
    if (wire_status == YX_SER_WIRE_BOUNDS) return yx_fail(YRX_SERIALIZATION_ERROR, "not a YARA-X compiled rules file");
    if (wire_status == YX_SER_WIRE_DECODE || wire_status == YX_SER_WIRE_WASM) {
        status = wire_status == YX_SER_WIRE_DECODE ? YX_SER_MALFORMED : YX_SER_UNSUPPORTED;
        goto classify_serialized_archive;
    }
    /* A rule set without rules: an empty compiler's rules, with the
     * archive's imports. */
    const char **empty_imports = NULL;
    size_t empty_import_count = 0;
    if (yx_ser_is_empty_rules_archive(data, size, &empty_imports, &empty_import_count)) {
        result = yrx_compiler_create(relaxed ? YRX_RELAXED_RE_SYNTAX : 0, &compiler);
        if (result != YRX_SUCCESS) return result;
        for (size_t i = 0; result == YRX_SUCCESS && i < empty_import_count; ++i) {
            char module_source[96];
            snprintf(module_source, sizeof(module_source), "import \"%s\"", empty_imports[i]);
            result = yrx_compiler_add_source(compiler, module_source);
        }
        if (result != YRX_SUCCESS) {
            yrx_compiler_destroy(compiler);
            return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
        }
        deserialized = yx_compiler_build_impl(compiler, false);
        yrx_compiler_destroy(compiler);
        if (!deserialized) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory decoding YARA-X rules");
        *rules = deserialized;
        return yx_ok();
    }
    if (size >= 21 && (data[12] == 2 || data[12] == 3) && data[13] == sizeof(default_namespace)) {
        bool possible = true;
        for (size_t i = 0; i < sizeof(default_namespace); ++i) {
            if (data[14 + i] == 0) {
                if (embedded_nul_at != SIZE_MAX) possible = false;
                embedded_nul_at = 14 + i;
            } else if (data[14 + i] != default_namespace[i]) {
                possible = false;
            }
        }
        if (!possible) embedded_nul_at = SIZE_MAX;
    }
    if (embedded_nul_at != SIZE_MAX) {
        normalized = malloc(size);
        if (!normalized) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory decoding YARA-X rules");
        memcpy(normalized, data, size);
        normalized[embedded_nul_at] = default_namespace[embedded_nul_at - 14];
    }
    status = yx_ser_decode_many(normalized ? normalized : data, size, &decoded, &decoded_count);
    if (status == YX_SER_UNSUPPORTED) {
        uint8_t *ac_normalized = NULL;
        yx_ser_result ac_status = yx_ser_normalize_empty_ac(normalized ? normalized : data, size, &ac_normalized);
        if (ac_status == YX_SER_SUCCESS) {
            free(normalized);
            normalized = ac_normalized;
            normalized_empty_ac = true;
            status = yx_ser_decode_many(normalized, size, &decoded, &decoded_count);
        } else if (ac_status == YX_SER_NO_MEMORY) {
            status = ac_status;
        }
    }
    if (status == YX_SER_UNSUPPORTED && !normalized) {
        uint8_t *shift_normalized = NULL;
        yx_ser_result shift_status = yx_ser_normalize_single_pattern_bitmap_shift(data, size, &shift_normalized);
        if (shift_status == YX_SER_SUCCESS) {
            normalized = shift_normalized;
            normalized_bitmap_shift = true;
            status = yx_ser_decode_many(normalized, size, &decoded, &decoded_count);
        } else if (shift_status == YX_SER_NO_MEMORY) {
            status = shift_status;
        }
    }
    if (status == YX_SER_UNSUPPORTED) {
        uint8_t *import_normalized = NULL;
        yx_ser_result import_status = yx_ser_normalize_unknown_wasm_import_name(normalized ? normalized : data, size, &import_normalized);
        if (import_status == YX_SER_SUCCESS) {
            free(normalized);
            normalized = import_normalized;
            normalized_import_name = true;
            status = yx_ser_decode_many(normalized, size, &decoded, &decoded_count);
        } else if (import_status == YX_SER_NO_MEMORY) {
            status = import_status;
        }
    }
    /* Another build's import order: the decoded rules keep the original
     * archive bytes for serialization. */
    if (status == YX_SER_UNSUPPORTED && !normalized) {
        status = yx_ser_decode_reordered_imports(data, size, &decoded, &decoded_count);
        if (status == YX_SER_SUCCESS)
            for (size_t i = 0; i < decoded_count; ++i) decoded[i].preserve_serialized_prefix = true;
    }
    if (status == YX_SER_SUCCESS && decoded_count) {
        preserve_serialized_prefix = decoded[0].preserve_serialized_prefix;
        if (decoded_count != 1 && preserve_serialized_prefix) status = yx_deserialized_prefix_length(data, size, &prefix_length);
    }
    if (status == YX_SER_SUCCESS && decoded_count == 1) {
        noncanonical_ac = decoded[0].noncanonical_ac;
        noncanonical_literal_pool = decoded[0].noncanonical_literal_pool;
        preserve_serialized_prefix = decoded[0].preserve_serialized_prefix || decoded[0].string_global_condition;
        if (normalized || noncanonical_ac || noncanonical_literal_pool || preserve_serialized_prefix)
            status = yx_deserialized_prefix_length(normalized ? normalized : data, size, &prefix_length);
    }
    free(normalized);
    if (status == YX_SER_SUCCESS &&
        (embedded_nul_at != SIZE_MAX || normalized_empty_ac || normalized_bitmap_shift || normalized_import_name || noncanonical_ac || noncanonical_literal_pool) &&
        decoded_count != 1) {
        yx_ser_rules_destroy(decoded, decoded_count);
        return yx_unsupported("compiled-rule deserialization for this rule shape");
    }
    if (status != YX_SER_SUCCESS) {
        yx_ser_rules_destroy(decoded, decoded_count);
        decoded = NULL;
        decoded_count = 0;
    }
classify_serialized_archive:
    if (status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) {
        size_t valid_up_to;
        if (yx_ser_ascii_pool_utf8_error(data, size, &valid_up_to)) {
            snprintf(message, sizeof(message), "cannot decode YARA-X rules: Utf8 { inner: Utf8Error { valid_up_to: %zu, error_len: Some(1) } }", valid_up_to);
            return yx_fail(YRX_SERIALIZATION_ERROR, message);
        }
        if (yx_ser_prefix_pool_utf8_error_detail(data, size, &valid_up_to)) {
            snprintf(message, sizeof(message), "cannot decode YARA-X rules: Utf8 { inner: Utf8Error { valid_up_to: %zu, error_len: Some(1) } }", valid_up_to);
            return yx_fail(YRX_SERIALIZATION_ERROR, message);
        }
    }
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_is_missing_final_archive_zero(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules: UnexpectedEnd { additional: 1 }");
    if (status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) {
        size_t additional;
        if (yx_ser_short_prefix_truncation(data, size, &additional)) {
            snprintf(message, sizeof(message), "cannot decode YARA-X rules: UnexpectedEnd { additional: %zu }", additional);
            return yx_fail(YRX_SERIALIZATION_ERROR, message);
        }
    }
    if (status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) {
        size_t additional;
        if (yx_ser_base64_ac_truncation(data, size, &additional)) {
            snprintf(message, sizeof(message), "cannot decode YARA-X rules: UnexpectedEnd { additional: %zu }", additional);
            return yx_fail(YRX_SERIALIZATION_ERROR, message);
        }
    }
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_zero_length_final_identifier(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_ac_structure(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_three_atom_ac_node(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR,
                       "cannot decode YARA-X rules: "
                       "OtherString(\"InvalidAutomatonError: "
                       "invalid serialized automaton\")");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_empty_subpattern_count(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_wasm_header(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR,
                       "invalid YARA-X compiled rules file: "
                       "failed to parse WebAssembly module");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_wasm_type_prefix(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR,
                       "invalid YARA-X compiled rules file: "
                       "failed to parse WebAssembly module");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_wasm_import_section_length(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR, "invalid YARA-X compiled rules file");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_wasm_import_name(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR,
                       "invalid YARA-X compiled rules file: "
                       "failed to parse WebAssembly module");
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && yx_ser_has_invalid_wasm_code_byte(data, size))
        return yx_fail(YRX_SERIALIZATION_ERROR, "invalid YARA-X compiled rules file");
    if (status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) {
        yx_ser_base64_wasm_error wasm_error = yx_ser_classify_base64_wasm_error(data, size);
        if (wasm_error == YX_SER_BASE64_WASM_PARSE)
            return yx_fail(YRX_SERIALIZATION_ERROR,
                           "invalid YARA-X compiled rules file: "
                           "failed to parse WebAssembly module");
        if (wasm_error == YX_SER_BASE64_WASM_COMPILE)
            return yx_fail(YRX_SERIALIZATION_ERROR,
                           "invalid YARA-X compiled rules file: "
                           "failed to compile: wasm[0]::function[3]");
    }
    if ((status == YX_SER_UNSUPPORTED || status == YX_SER_MALFORMED) && size >= 5 && data[size - 2] == 254) {
        const char *malformed = yx_classify_serialized_fast_scan_footer(data, size);
        if (malformed) return yx_fail(YRX_SERIALIZATION_ERROR, malformed);
    }
    if (status == YX_SER_UNSUPPORTED) {
        const char *malformed = yx_classify_serialized_fast_scan_footer(data, size);
        if (malformed) return yx_fail(YRX_SERIALIZATION_ERROR, malformed);
        if (wire_status == YX_SER_WIRE_DECODE) return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
        if (wire_status == YX_SER_WIRE_WASM) return yx_fail(YRX_SERIALIZATION_ERROR, "invalid YARA-X compiled rules file");
        return yx_unsupported("compiled-rule deserialization for this rule shape");
    }
    if (status == YX_SER_MALFORMED) return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
    if (status == YX_SER_NO_MEMORY) return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory decoding YARA-X rules");
    if (decoded_count == 0 || !decoded) {
        yx_ser_rules_destroy(decoded, decoded_count);
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
    }
    result = yrx_compiler_create(relaxed ? YRX_RELAXED_RE_SYNTAX : 0, &compiler);
    /* The rebuilt rules never report warnings. A zero limit keeps the
     * warning analyses (and their scans of the whole source) out of the load. */
    if (result == YRX_SUCCESS) compiler->max_warnings = 0;
    if (result == YRX_SUCCESS) result = yrx_compiler_new_namespace(compiler, decoded[0].namespace_name);
    /* Older single-namespace codecs leave the ordinal unset. A nondefault
     * initial namespace still has the ordinal assigned by new_namespace. */
    if (result == YRX_SUCCESS && (decoded[0].namespace_index || !strcmp(decoded[0].namespace_name, "default")))
        compiler->current_namespace_index = decoded[0].namespace_index;
    if (result == YRX_SUCCESS && decoded[0].runtime_global_count) {
        if (!yx_copy_globals(decoded[0].runtime_globals, decoded[0].runtime_global_count, &compiler->rules->globals))
            result = yx_fail(YRX_SERIALIZATION_ERROR, "out of memory restoring globals");
        else compiler->rules->global_count = decoded[0].runtime_global_count;
    }
    if (result == YRX_SUCCESS && decoded[0].integer_global_condition) result = yrx_compiler_define_global_int(compiler, decoded[0].global_name, decoded[0].global_value);
    if (result == YRX_SUCCESS && decoded[0].float_global_condition)
        result = yrx_compiler_define_global_float(compiler, decoded[0].global_name, decoded[0].global_float_value);
    if (result == YRX_SUCCESS && decoded[0].boolean_global_condition)
        result = yrx_compiler_define_global_bool(compiler, decoded[0].global_name, decoded[0].global_boolean_value);
    if (result == YRX_SUCCESS && decoded[0].string_global_condition)
        result = yrx_compiler_define_global_str(compiler, decoded[0].global_name, decoded[0].global_string_value);
    if (result == YRX_SUCCESS && decoded[0].runtime_module_name) {
        char module_source[80];
        snprintf(module_source, sizeof(module_source), "import \"%s\"", decoded[0].runtime_module_name);
        result = yrx_compiler_add_source(compiler, module_source);
    }
    for (size_t i = 0; result == YRX_SUCCESS && i < decoded[0].runtime_module_count; ++i) {
        char module_source[80];
        int n = snprintf(module_source, sizeof(module_source), "import \"%s\"", decoded[0].runtime_module_names[i]);
        if (n < 0 || (size_t)n >= sizeof(module_source)) result = YRX_INVALID_ARGUMENT;
        else result = yrx_compiler_add_source(compiler, module_source);
    }
    if (result == YRX_SUCCESS && decoded[0].pe_imported) result = yrx_compiler_add_source(compiler, "import \"pe\"");
    if (result == YRX_SUCCESS && decoded[0].cuckoo_imported) result = yrx_compiler_add_source(compiler, "import \"cuckoo\"");
    if (result == YRX_SUCCESS && decoded[0].vt_imported) result = yrx_compiler_add_source(compiler, "import \"vt\"");
    if (result == YRX_SUCCESS && decoded[0].time_now) result = yrx_compiler_add_source(compiler, "import \"time\"");
    if (result == YRX_SUCCESS && decoded[0].math_max_eq) result = yrx_compiler_add_source(compiler, "import \"math\"");
    if (result == YRX_SUCCESS && decoded[0].console_pe_log) result = yrx_compiler_add_source(compiler, "import \"console\"\nimport \"pe\"");
    /* Re-validating the complete compiler after each recovered rule is
     * quadratic. A namespace's recovered rules can be compiled together. */
    bool batch_rules = decoded_count > 10;
    for (size_t i = 1; batch_rules && i < decoded_count; ++i)
        if (decoded[i].namespace_index != decoded[0].namespace_index || strcmp(decoded[i].namespace_name, decoded[0].namespace_name)) batch_rules = false;
    char *batch_source = NULL;
    size_t batch_length = 0, batch_capacity = 0;
    /* Where each rule's text starts in the batch, for yx_compile_batch. */
    size_t *batch_starts = batch_rules ? malloc((decoded_count + 1) * sizeof(*batch_starts)) : NULL;
    bool batch_global = false;
    for (size_t i = 0; result == YRX_SUCCESS && i < decoded_count; ++i) {
        size_t name_length = strlen(decoded[i].identifier);
        size_t source_capacity;
        if (name_length > SIZE_MAX - 192) {
            result = YRX_SERIALIZATION_ERROR;
            break;
        }
        source_capacity = name_length + 192;
        if (decoded[i].runtime_pattern_declarations) {
            size_t declarations_length = strlen(decoded[i].runtime_pattern_declarations);
            if (declarations_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += declarations_length;
        }
        if (decoded[i].runtime_integer_condition) {
            size_t condition_length = strlen(decoded[i].runtime_integer_condition);
            if (condition_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += condition_length;
        }
        if (decoded[i].cuckoo_imported) {
            size_t condition_length = strlen(decoded[i].cuckoo_condition);
            if (condition_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += condition_length;
        }
        if (decoded[i].console_pe_log) {
            if (decoded[i].console_log_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += decoded[i].console_log_length;
        }
        if (decoded[i].reference_first_rule || decoded[i].with_first_rule_and_integer_eq) {
            size_t referenced_length = strlen(decoded[0].identifier);
            if (i == 0 || referenced_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += referenced_length;
        }
        if (decoded[i].integer_global_condition || decoded[i].float_global_condition || decoded[i].boolean_global_condition || decoded[i].string_global_condition) {
            size_t global_length = strlen(decoded[i].global_name);
            if (global_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += global_length;
        }
        if (decoded[i].string_global_condition) {
            if (decoded[i].string_compare_length > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += decoded[i].string_compare_length;
        }
        if (decoded[i].pe_version_any) {
            if (decoded[i].pe_version_key_length > SIZE_MAX - source_capacity ||
                decoded[i].pe_version_value_length > SIZE_MAX - source_capacity - decoded[i].pe_version_key_length) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += decoded[i].pe_version_key_length + decoded[i].pe_version_value_length;
        }
        if (decoded[i].float_global_condition) {
            if (source_capacity > SIZE_MAX - 384) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += 384;
        }
        if (decoded[i].filesize_negations || decoded[i].filesize_identity_blocks) {
            size_t extra = (size_t)decoded[i].filesize_negations * 4 + 16;
            if (extra > SIZE_MAX - source_capacity) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += extra;
        }
        if (decoded[i].filesize_double_and || decoded[i].filesize_double_or || decoded[i].filesize_triple_and || decoded[i].filesize_triple_or ||
            decoded[i].filesize_mixed_or_and || decoded[i].filesize_mixed_and_or || decoded[i].filesize_mixed_and_or_left || decoded[i].filesize_mixed_or_and_left ||
            decoded[i].filesize_quad_and || decoded[i].filesize_quad_or || decoded[i].filesize_five_and || decoded[i].filesize_five_or || decoded[i].filesize_six_and ||
            decoded[i].filesize_six_or || decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and ||
            decoded[i].filesize_eight_or) {
            if (source_capacity > SIZE_MAX - 416) {
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            source_capacity += 416;
        }
        if (decoded[i].single_hex_pattern || decoded[i].single_text_pattern || decoded[i].two_text_patterns || decoded[i].two_hex_patterns ||
            decoded[i].two_mixed_hex_first || decoded[i].two_mixed_hex_last || decoded[i].three_hex_patterns || decoded[i].three_text_patterns ||
            decoded[i].four_text_patterns || decoded[i].five_text_patterns || decoded[i].six_text_patterns || decoded[i].seven_text_patterns ||
            decoded[i].eight_text_patterns) {
            const char *names[8] = {decoded[i].pattern_identifier,         decoded[i].second_pattern_identifier, decoded[i].third_pattern_identifier,
                                    decoded[i].fourth_pattern_identifier,  decoded[i].fifth_pattern_identifier,  decoded[i].sixth_pattern_identifier,
                                    decoded[i].seventh_pattern_identifier, decoded[i].eighth_pattern_identifier};
            size_t lengths[8] = {decoded[i].pattern_length,       decoded[i].second_pattern_length, decoded[i].third_pattern_length,   decoded[i].fourth_pattern_length,
                                 decoded[i].fifth_pattern_length, decoded[i].sixth_pattern_length,  decoded[i].seventh_pattern_length, decoded[i].eighth_pattern_length};
            size_t count = decoded[i].eight_text_patterns                                                                                                     ? 8
                           : decoded[i].seven_text_patterns                                                                                                   ? 7
                           : decoded[i].six_text_patterns                                                                                                     ? 6
                           : decoded[i].five_text_patterns                                                                                                    ? 5
                           : decoded[i].four_text_patterns                                                                                                    ? 4
                           : (decoded[i].three_text_patterns || decoded[i].three_hex_patterns)                                                                ? 3
                           : (decoded[i].two_text_patterns || decoded[i].two_hex_patterns || decoded[i].two_mixed_hex_first || decoded[i].two_mixed_hex_last) ? 2
                                                                                                                                                              : 1;
            for (size_t j = 0; j < count; ++j) {
                size_t name_length = strlen(names[j]);
                size_t name_copies = decoded[i].all_positive_single_text_statistics ? 5
                                     : decoded[i].text_presence_count_range_offset  ? 4
                                     : decoded[i].text_presence_offset_equal        ? 3
                                                                                    : 2;
                if (name_length > (SIZE_MAX - source_capacity) / name_copies) {
                    result = YRX_SERIALIZATION_ERROR;
                    break;
                }
                source_capacity += name_length * name_copies;
                if (source_capacity == SIZE_MAX || lengths[j] > (SIZE_MAX - source_capacity - 1) / 4) {
                    result = YRX_SERIALIZATION_ERROR;
                    break;
                }
                source_capacity += lengths[j] * 4 + 1;
            }
            if (result != YRX_SUCCESS) break;
        }
        source = malloc(source_capacity);
        if (!source) {
            result = YRX_SERIALIZATION_ERROR;
            break;
        }
        if (decoded[i].runtime_pattern_declarations && decoded[i].runtime_integer_condition) {
            int written =
                snprintf(source, source_capacity, "%s%srule %s { strings: %s condition: %s }", decoded[i].is_global ? "global " : "",
                         decoded[i].is_private ? "private " : "", decoded[i].identifier, decoded[i].runtime_pattern_declarations, decoded[i].runtime_integer_condition);
            if (written < 0 || (size_t)written >= source_capacity) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
        } else if (decoded[i].single_hex_pattern || decoded[i].single_text_pattern || decoded[i].two_text_patterns || decoded[i].two_hex_patterns ||
                   decoded[i].two_mixed_hex_first || decoded[i].two_mixed_hex_last || decoded[i].three_hex_patterns || decoded[i].three_text_patterns ||
                   decoded[i].four_text_patterns || decoded[i].five_text_patterns || decoded[i].six_text_patterns || decoded[i].seven_text_patterns ||
                   decoded[i].eight_text_patterns) {
            static const char hex[] = "0123456789abcdef";
            const char *names[8] = {decoded[i].pattern_identifier,         decoded[i].second_pattern_identifier, decoded[i].third_pattern_identifier,
                                    decoded[i].fourth_pattern_identifier,  decoded[i].fifth_pattern_identifier,  decoded[i].sixth_pattern_identifier,
                                    decoded[i].seventh_pattern_identifier, decoded[i].eighth_pattern_identifier};
            const uint8_t *bytes[8] = {decoded[i].pattern_bytes,         decoded[i].second_pattern_bytes, decoded[i].third_pattern_bytes,
                                       decoded[i].fourth_pattern_bytes,  decoded[i].fifth_pattern_bytes,  decoded[i].sixth_pattern_bytes,
                                       decoded[i].seventh_pattern_bytes, decoded[i].eighth_pattern_bytes};
            size_t lengths[8] = {decoded[i].pattern_length,       decoded[i].second_pattern_length, decoded[i].third_pattern_length,   decoded[i].fourth_pattern_length,
                                 decoded[i].fifth_pattern_length, decoded[i].sixth_pattern_length,  decoded[i].seventh_pattern_length, decoded[i].eighth_pattern_length};
            size_t count = decoded[i].eight_text_patterns                                                                                                     ? 8
                           : decoded[i].seven_text_patterns                                                                                                   ? 7
                           : decoded[i].six_text_patterns                                                                                                     ? 6
                           : decoded[i].five_text_patterns                                                                                                    ? 5
                           : decoded[i].four_text_patterns                                                                                                    ? 4
                           : (decoded[i].three_text_patterns || decoded[i].three_hex_patterns)                                                                ? 3
                           : (decoded[i].two_text_patterns || decoded[i].two_hex_patterns || decoded[i].two_mixed_hex_first || decoded[i].two_mixed_hex_last) ? 2
                                                                                                                                                              : 1;
            char *escaped_storage = malloc(source_capacity);
            char *escaped[8] = {NULL};
            size_t at = 0;
            int written;
            if (!escaped_storage) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            for (size_t j = 0; j < count; ++j) {
                bool mixed_masked = (decoded[i].two_mixed_masked_first && j == 0) || (decoded[i].two_mixed_masked_last && j == 1);
                bool mixed_double_nibble = (decoded[i].two_mixed_double_nibble_first && j == 0) || (decoded[i].two_mixed_double_nibble_last && j == 1);
                bool mixed_interior_wildcard = (decoded[i].two_mixed_interior_wildcard_first && j == 0) || (decoded[i].two_mixed_interior_wildcard_last && j == 1);
                bool three_mixed_hex = decoded[i].three_mixed_hex_last && j == 2;
                bool mixed_wildcard = (decoded[i].two_mixed_wildcard_first && j == 0) || (decoded[i].two_mixed_wildcard_last && j == 1);
                escaped[j] = escaped_storage + at;
                if (decoded[i].single_hex_pattern || decoded[i].two_hex_patterns || decoded[i].three_hex_patterns || three_mixed_hex ||
                    (decoded[i].two_mixed_hex_first && j == 0 && !decoded[i].two_regex_dotall_first) ||
                    (decoded[i].two_mixed_hex_last && j == 1 && !decoded[i].two_regex_dotall_last)) {
                    size_t pos = 0;
                    for (size_t k = 0; k < lengths[j]; ++k) {
                        uint8_t byte = bytes[j][k];
                        if (k) escaped[j][pos++] = ' ';
                        if ((decoded[i].single_hex_wildcard_first && k == 0) || (decoded[i].single_hex_wildcard_last && k == lengths[j] - 1) ||
                            (decoded[i].single_hex_wildcard_interior_one && k == 1) || (decoded[i].single_hex_wildcard_interior_masked_one && k == 1) ||
                            (decoded[i].single_hex_wildcard_interior_one_two && k == 1) || (decoded[i].single_hex_wildcard_interior_two_one && k == 2) ||
                            (decoded[i].single_hex_wildcard_interior_masked_one_two && k == 1) || (decoded[i].single_hex_wildcard_interior_masked_two_one && k == 2) ||
                            (decoded[i].single_hex_wildcard_interior_two && k == 2) || (decoded[i].single_hex_wildcard_interior_three && k == 3) ||
                            (decoded[i].single_hex_wildcard_interior_four && k == 4) || (decoded[i].single_hex_nibble_wildcard_first && k == 0) ||
                            (decoded[i].single_hex_nibble_wildcard_last && k == 1) || ((mixed_interior_wildcard || three_mixed_hex) && k == 2) ||
                            (mixed_wildcard &&
                             (k == ((j == 1 ? decoded[i].two_mixed_wildcard_second_edge_first : decoded[i].two_mixed_wildcard_edge_first) ? 0u : lengths[j] - 1)))) {
                            escaped[j][pos++] = '?';
                            escaped[j][pos++] = '?';
                        } else if ((decoded[i].single_hex_nibble_first && k == 0) || (decoded[i].single_hex_nibble_last && k == 1) ||
                                   (decoded[i].single_hex_nibble_only && k == 0) || (decoded[i].single_hex_nibble_wildcard_first && k == 1) ||
                                   (decoded[i].single_hex_nibble_wildcard_last && k == 0) || (decoded[i].single_hex_combined_masked_suffix && k == 4) ||
                                   ((mixed_interior_wildcard || three_mixed_hex) && k == 4 && lengths[j] > 4) || (mixed_double_nibble && k < 2) ||
                                   (mixed_masked && k == 0)) {
                            uint8_t mask = mixed_masked                                   ? decoded[i].two_mixed_masked_mask
                                           : mixed_double_nibble                          ? decoded[i].two_mixed_double_nibble_mask[k]
                                           : (mixed_interior_wildcard || three_mixed_hex) ? decoded[i].two_mixed_interior_suffix_mask
                                                                                          : decoded[i].single_hex_nibble_mask;
                            if (decoded[i].single_hex_nibble_first && decoded[i].single_hex_nibble_last)
                                mask = (decoded[i].single_hex_nibble_mask & (k ? 2u : 1u)) ? 0xf0 : 0x0f;
                            escaped[j][pos++] = mask == 0x0f ? '?' : hex[byte >> 4];
                            escaped[j][pos++] = mask == 0xf0 ? '?' : hex[byte & 15];
                        } else {
                            escaped[j][pos++] = hex[byte >> 4];
                            escaped[j][pos++] = hex[byte & 15];
                        }
                    }
                    escaped[j][pos] = 0;
                } else if (decoded[i].single_regex_literal || decoded[i].single_regex_dot || decoded[i].single_regex_digit_plus || decoded[i].single_regex_fast ||
                           decoded[i].single_hex_fast || decoded[i].single_regex_thompson || decoded[i].single_hex_thompson ||
                           (decoded[i].two_regex_dotall_first && j == 0) || (decoded[i].two_regex_dotall_last && j == 1) ||
                           (decoded[i].multi_literal_regex_mask & (1u << j))) {
                    memcpy(escaped[j], bytes[j], lengths[j]);
                    escaped[j][lengths[j]] = 0;
                } else {
                    for (size_t k = 0; k < lengths[j]; ++k) {
                        uint8_t byte = bytes[j][k];
                        escaped[j][k * 4] = '\\';
                        escaped[j][k * 4 + 1] = 'x';
                        escaped[j][k * 4 + 2] = hex[byte >> 4];
                        escaped[j][k * 4 + 3] = hex[byte & 15];
                    }
                    escaped[j][lengths[j] * 4] = 0;
                }
                at += lengths[j] * 4 + 1;
            }
            if (count > 1 && decoded[i].runtime_integer_condition) {
                size_t used = 0;
                bool ok =
                    yx_archive_source_append(source, source_capacity, &used, "%srule %s { strings: ", decoded[i].is_private ? "private " : "", decoded[i].identifier);
                for (size_t j = 0; ok && j < count; ++j) ok = yx_archive_source_append(source, source_capacity, &used, "%s = \"%s\" ", names[j], escaped[j]);
                if (ok) ok = yx_archive_source_append(source, source_capacity, &used, "condition: %s }", decoded[i].runtime_integer_condition);
                written = ok && used <= INT_MAX ? (int)used : -1;
            } else if (decoded[i].multi_literal_regex_mask) {
                size_t used = 0;
                size_t order[8] = {0, 1, 2, 3, 4, 5, 6, 7};
                bool any = count == 2   ? decoded[i].two_text_any
                           : count == 3 ? decoded[i].three_text_any
                           : count == 4 ? decoded[i].four_text_any
                           : count == 5 ? decoded[i].five_text_any
                                        : false;
                bool all = count == 2 && decoded[i].two_text_all;
                bool and_condition = count == 2   ? decoded[i].two_text_and
                                     : count == 3 ? decoded[i].three_text_and
                                     : count == 4 ? decoded[i].four_text_and
                                     : count == 5 ? decoded[i].five_text_and
                                     : count == 6 ? decoded[i].six_text_and
                                     : count == 7 ? decoded[i].seven_text_and
                                                  : decoded[i].eight_text_and;
                bool ok =
                    yx_archive_source_append(source, source_capacity, &used, "%srule %s { strings: ", decoded[i].is_private ? "private " : "", decoded[i].identifier);
                if (count == 2 && decoded[i].two_text_reverse) {
                    order[0] = 1;
                    order[1] = 0;
                } else if (count == 3) {
                    for (size_t j = 0; j < count; ++j) order[j] = decoded[i].three_text_order[j];
                } else if (count == 4) {
                    for (size_t j = 0; j < count; ++j) order[j] = decoded[i].four_text_order[j];
                } else if (count == 5) {
                    for (size_t j = 0; j < count; ++j) order[j] = decoded[i].five_text_order[j];
                } else if (count == 6) {
                    for (size_t j = 0; j < count; ++j) order[j] = decoded[i].six_text_order[j];
                } else if (count == 7) {
                    for (size_t j = 0; j < count; ++j) order[j] = decoded[i].seven_text_order[j];
                } else if (count == 8) {
                    for (size_t j = 0; j < count; ++j) order[j] = decoded[i].eight_text_order[j];
                }
                for (size_t j = 0; ok && j < count; ++j) {
                    bool is_regex = (decoded[i].multi_literal_regex_mask & (1u << j)) != 0;
                    bool three_mixed_hex = count >= 3 && decoded[i].three_mixed_hex_last && j == 2;
                    const char *open = is_regex ? "/" : three_mixed_hex ? "{ " : "\"";
                    const char *close = is_regex ? "/" : three_mixed_hex ? " }" : "\"";
                    const char *dotall = (count == 2 || decoded[i].three_mixed_hex_last) && decoded[i].two_regex_dotall_last && j == 1 ? "s" : "";
                    const char *nocase = "", *ascii = "", *wide = "";
                    const char *xor_modifier = "";
                    const char *base64_modifier = "";
                    const char *fullword = "";
                    /* A literal regexp keeps the modifiers recovered for
                     * its literal frame, including fullword. */
                    if (count == 2) {
                        bool second = j == 1;
                        nocase = (second ? decoded[i].two_text_second_nocase : decoded[i].two_text_first_nocase) ? " nocase" : "";
                        ascii = (second ? decoded[i].two_text_second_ascii_wide : decoded[i].two_text_first_ascii_wide) ? " ascii" : "";
                        wide = (second ? decoded[i].two_text_second_wide : decoded[i].two_text_first_wide) ? " wide" : "";
                        fullword = (second ? decoded[i].two_text_second_fullword : decoded[i].two_text_first_fullword) ? " fullword" : "";
                    }
                    if (count >= 4 && decoded[i].four_mixed_wide_last && j == 3) wide = " wide";
                    if (count >= 5 && decoded[i].five_mixed_nocase_last && j == 4) nocase = " nocase";
                    if (count >= 6 && decoded[i].six_mixed_ascii_wide_last && j == 5) {
                        ascii = " ascii";
                        wide = " wide";
                    }
                    if (count >= 7 && decoded[i].seven_mixed_xor_last && j == 6) xor_modifier = " xor";
                    if (count == 8 && decoded[i].eight_mixed_base64_last && j == 7) base64_modifier = " base64";
                    ok = yx_archive_source_append(source, source_capacity, &used, "%s = %s%s%s%s%s%s%s%s%s%s ", names[j], open, escaped[j], close, dotall, nocase, ascii,
                                                  wide, fullword, xor_modifier, base64_modifier);
                }
                if (ok) {
                    if (any || all) {
                        ok = yx_archive_source_append(source, source_capacity, &used, "condition: %s of them }", any ? "any" : "all");
                    } else {
                        ok = yx_archive_source_append(source, source_capacity, &used, "condition: ");
                        for (size_t j = 0; ok && j < count; ++j)
                            ok = yx_archive_source_append(source, source_capacity, &used, "%s%s", names[order[j]],
                                                          j + 1 == count  ? ""
                                                          : and_condition ? " and "
                                                                          : " or ");
                        if (ok) ok = yx_archive_source_append(source, source_capacity, &used, " }");
                    }
                }
                written = ok && used <= INT_MAX ? (int)used : -1;
            } else if (decoded[i].text_for_any || decoded[i].text_for_none_one || decoded[i].text_for_all_one) {
                size_t used = 0;
                bool ok =
                    yx_archive_source_append(source, source_capacity, &used, "%srule %s { strings: ", decoded[i].is_private ? "private " : "", decoded[i].identifier);
                for (size_t j = 0; ok && j < count; ++j) ok = yx_archive_source_append(source, source_capacity, &used, "%s = \"%s\" ", names[j], escaped[j]);
                if (ok)
                    ok = yx_archive_source_append(source, source_capacity, &used, "condition: for %s of them : ( $ ) }",
                                                  decoded[i].text_for_all_one    ? "all"
                                                  : decoded[i].text_for_none_one ? "none"
                                                                                 : "any");
                written = ok && used <= INT_MAX ? (int)used : -1;
            } else if (decoded[i].text_of_required) {
                size_t used = 0;
                bool ok =
                    yx_archive_source_append(source, source_capacity, &used, "%srule %s { strings: ", decoded[i].is_private ? "private " : "", decoded[i].identifier);
                for (size_t j = 0; ok && j < count; ++j) ok = yx_archive_source_append(source, source_capacity, &used, "%s = \"%s\" ", names[j], escaped[j]);
                if (ok) ok = yx_archive_source_append(source, source_capacity, &used, "condition: %u of them }", (unsigned)decoded[i].text_of_required);
                written = ok && used <= INT_MAX ? (int)used : -1;
            } else if (count == 5 && decoded[i].five_text_any) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "%s = \"%s\" %s = \"%s\" %s = \"%s\" "
                                   "%s = \"%s\" condition: any of them }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2],
                                   names[3], escaped[3], names[4], escaped[4]);
            } else if (count == 5) {
                const char *op = decoded[i].five_text_and ? "and" : "or";
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "%s = \"%s\" %s = \"%s\" %s = \"%s\" "
                                   "%s = \"%s\" "
                                   "condition: %s %s %s %s %s %s %s %s %s }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2],
                                   names[3], escaped[3], names[4], escaped[4], names[decoded[i].five_text_order[0]], op, names[decoded[i].five_text_order[1]], op,
                                   names[decoded[i].five_text_order[2]], op, names[decoded[i].five_text_order[3]], op, names[decoded[i].five_text_order[4]]);
            } else if (count == 4 && decoded[i].four_text_any) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "%s = \"%s\" %s = \"%s\" %s = \"%s\" "
                                   "condition: any of them }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2],
                                   names[3], escaped[3]);
            } else if (count == 4) {
                const char *op = decoded[i].four_text_and ? "and" : "or";
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "%s = \"%s\" %s = \"%s\" %s = \"%s\" "
                                   "condition: %s %s %s %s %s %s %s }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2],
                                   names[3], escaped[3], names[decoded[i].four_text_order[0]], op, names[decoded[i].four_text_order[1]], op,
                                   names[decoded[i].four_text_order[2]], op, names[decoded[i].four_text_order[3]]);
            } else if (count == 3 && decoded[i].three_hex_patterns && decoded[i].three_text_any) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = { %s } "
                                   "%s = { %s } %s = { %s } "
                                   "condition: any of them }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2]);
            } else if (count == 3 && decoded[i].three_hex_patterns) {
                const char *op = decoded[i].three_text_and ? "and" : "or";
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = { %s } "
                                   "%s = { %s } %s = { %s } "
                                   "condition: %s %s %s %s %s }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2],
                                   names[decoded[i].three_text_order[0]], op, names[decoded[i].three_text_order[1]], op, names[decoded[i].three_text_order[2]]);
            } else if (count == 3 && decoded[i].three_text_any) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "%s = \"%s\" %s = \"%s\" "
                                   "condition: any of them }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2]);
            } else if (count == 3) {
                const char *op = decoded[i].three_text_and ? "and" : "or";
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "%s = \"%s\" %s = \"%s\" "
                                   "condition: %s %s %s %s %s }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[1], escaped[1], names[2], escaped[2],
                                   names[decoded[i].three_text_order[0]], op, names[decoded[i].three_text_order[1]], op, names[decoded[i].three_text_order[2]]);
            } else if (decoded[i].two_hex_patterns || decoded[i].two_mixed_hex_first || decoded[i].two_mixed_hex_last) {
                const char *open0 = decoded[i].two_regex_dotall_first ? "/" : decoded[i].two_mixed_hex_last ? "\"" : "{ ";
                const char *close0 = decoded[i].two_regex_dotall_first ? "/s" : decoded[i].two_mixed_hex_last ? "\"" : " }";
                const char *open1 = decoded[i].two_regex_dotall_last ? "/" : decoded[i].two_mixed_hex_first ? "\"" : "{ ";
                const char *close1 = decoded[i].two_regex_dotall_last ? "/s" : decoded[i].two_mixed_hex_first ? "\"" : " }";
                if (decoded[i].two_text_any) {
                    written = snprintf(source, source_capacity,
                                       "%srule %s { strings: %s = %s%s%s%s "
                                       "%s = %s%s%s%s condition: any of them }",
                                       decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], open0, escaped[0], close0,
                                       decoded[i].two_text_first_wide ? (decoded[i].two_text_first_ascii_wide ? " ascii wide" : " wide") : "", names[1], open1,
                                       escaped[1], close1, decoded[i].two_text_second_wide ? (decoded[i].two_text_second_ascii_wide ? " ascii wide" : " wide") : "");
                } else {
                    const char *lhs = decoded[i].two_text_reverse ? names[1] : names[0];
                    const char *rhs = decoded[i].two_text_reverse ? names[0] : names[1];
                    written = snprintf(source, source_capacity,
                                       "%srule %s { strings: %s = %s%s%s%s "
                                       "%s = %s%s%s%s condition: %s %s %s }",
                                       decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], open0, escaped[0], close0,
                                       decoded[i].two_text_first_wide ? (decoded[i].two_text_first_ascii_wide ? " ascii wide" : " wide") : "", names[1], open1,
                                       escaped[1], close1, decoded[i].two_text_second_wide ? (decoded[i].two_text_second_ascii_wide ? " ascii wide" : " wide") : "", lhs,
                                       decoded[i].two_text_and ? "and" : "or", rhs);
                }
            } else if (decoded[i].two_text_any || decoded[i].two_text_all) {
                written =
                    snprintf(source, source_capacity,
                             "%srule %s { strings: %s = \"%s\" %s%s%s%s"
                             "%s = \"%s\" %s%s%s%scondition: %s of them }",
                             decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], decoded[i].two_text_first_nocase ? "nocase " : "",
                             decoded[i].two_text_first_ascii_wide ? "ascii " : "", decoded[i].two_text_first_wide ? "wide " : "",
                             decoded[i].two_text_first_fullword ? "fullword " : "", names[1], escaped[1], decoded[i].two_text_second_nocase ? "nocase " : "",
                             decoded[i].two_text_second_ascii_wide ? "ascii " : "", decoded[i].two_text_second_wide ? "wide " : "",
                             decoded[i].two_text_second_fullword ? "fullword " : "", decoded[i].two_text_all ? "all" : "any");
            } else if (count == 2) {
                const char *lhs = decoded[i].two_text_reverse ? names[1] : names[0];
                const char *rhs = decoded[i].two_text_reverse ? names[0] : names[1];
                written =
                    snprintf(source, source_capacity,
                             "%srule %s { strings: %s = \"%s\" %s%s%s%s"
                             "%s = \"%s\" %s%s%s%scondition: %s %s %s }",
                             decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], decoded[i].two_text_first_nocase ? "nocase " : "",
                             decoded[i].two_text_first_ascii_wide ? "ascii " : "", decoded[i].two_text_first_wide ? "wide " : "",
                             decoded[i].two_text_first_fullword ? "fullword " : "", names[1], escaped[1], decoded[i].two_text_second_nocase ? "nocase " : "",
                             decoded[i].two_text_second_ascii_wide ? "ascii " : "", decoded[i].two_text_second_wide ? "wide " : "",
                             decoded[i].two_text_second_fullword ? "fullword " : "", lhs, decoded[i].two_text_and ? "and" : "or", rhs);
            } else if (decoded[i].runtime_integer_condition && (decoded[i].single_hex_pattern || decoded[i].single_hex_fast || decoded[i].single_hex_thompson)) {
                written = snprintf(source, source_capacity, "%srule %s { strings: %s = { %s } condition: %s }", decoded[i].is_private ? "private " : "",
                                   decoded[i].identifier, names[0], escaped[0], decoded[i].runtime_integer_condition);
            } else if (decoded[i].runtime_integer_condition && (decoded[i].single_regex_literal || decoded[i].single_regex_dot || decoded[i].single_regex_digit_plus ||
                                                                decoded[i].single_regex_fast || decoded[i].single_regex_thompson)) {
                written =
                    snprintf(source, source_capacity, "%srule %s { strings: %s = /%s/%s %s%s%s%s condition: %s }", decoded[i].is_private ? "private " : "",
                             decoded[i].identifier, names[0], escaped[0], decoded[i].single_regex_dotall ? "s" : "", decoded[i].ascii_wide_single_pattern ? "ascii " : "",
                             decoded[i].wide_single_pattern || decoded[i].ascii_wide_single_pattern ? "wide " : "", decoded[i].nocase_single_pattern ? "nocase " : "",
                             decoded[i].fullword_single_pattern ? "fullword " : "", decoded[i].runtime_integer_condition);
            } else if (decoded[i].runtime_integer_condition) {
                written =
                    snprintf(source, source_capacity, "%srule %s { strings: %s = \"%s\" %s%s%s%s condition: %s }", decoded[i].is_private ? "private " : "",
                             decoded[i].identifier, names[0], escaped[0], decoded[i].ascii_wide_single_pattern ? "ascii " : "",
                             decoded[i].wide_single_pattern || decoded[i].ascii_wide_single_pattern ? "wide " : "", decoded[i].nocase_single_pattern ? "nocase " : "",
                             decoded[i].fullword_single_pattern ? "fullword " : "", decoded[i].runtime_integer_condition);
            } else if (decoded[i].single_regex_literal || decoded[i].single_regex_dot || decoded[i].single_regex_digit_plus || decoded[i].single_regex_fast ||
                       decoded[i].single_regex_thompson) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = /%s/%s%s%s%s%s "
                                   "condition: %s }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], decoded[i].single_regex_dotall ? "s" : "",
                                   decoded[i].fullword_single_pattern ? " fullword" : "", decoded[i].wide_single_pattern ? " wide" : "",
                                   decoded[i].ascii_wide_single_pattern ? " ascii" : "", decoded[i].nocase_single_pattern ? " nocase" : "",
                                   decoded[i].single_pattern_quantifier == 1   ? "any of them"
                                   : decoded[i].single_pattern_quantifier == 2 ? "1 of them"
                                                                               : names[0]);
            } else if (decoded[i].single_hex_fast || decoded[i].single_hex_thompson) {
                written = snprintf(source, source_capacity, "rule %s { strings: %s = { %s } condition: %s }", decoded[i].identifier, names[0], escaped[0], names[0]);
            } else if (decoded[i].single_hex_pattern) {
                const char *count_operator = decoded[i].count_operator == YX_SER_COUNT_GT   ? ">"
                                             : decoded[i].count_operator == YX_SER_COUNT_GE ? ">="
                                             : decoded[i].count_operator == YX_SER_COUNT_EQ ? "=="
                                             : decoded[i].count_operator == YX_SER_COUNT_LT ? "<"
                                             : decoded[i].count_operator == YX_SER_COUNT_LE ? "<="
                                             : decoded[i].count_operator == YX_SER_COUNT_NE ? "!="
                                                                                            : NULL;
                char count_comparison[16] = "";
                char at_position[16] = "";
                const char *quantified_condition = decoded[i].single_pattern_quantifier == 1   ? "any of them"
                                                   : decoded[i].single_pattern_quantifier == 2 ? "1 of them"
                                                                                               : NULL;
                if (count_operator) (void)snprintf(count_comparison, sizeof(count_comparison), " %s %u", count_operator, (unsigned)decoded[i].count_value);
                if (decoded[i].at_single_text_pattern) (void)snprintf(at_position, sizeof(at_position), " at %u", (unsigned)decoded[i].at_offset);
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = { %s } "
                                   "condition: %s%s%s }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0],
                                   quantified_condition                     ? ""
                                   : count_operator                         ? "#"
                                   : decoded[i].negated_single_text_pattern ? "not "
                                                                            : "",
                                   quantified_condition ? quantified_condition
                                   : count_operator     ? names[0] + 1
                                                        : names[0],
                                   quantified_condition                ? ""
                                   : decoded[i].at_single_text_pattern ? at_position
                                                                       : count_comparison);
            } else if (decoded[i].text_presence_count_range_offset) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "condition: %s and #%s in (%u..%u) "
                                   "and @%s == %u }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[0], names[0] + 1,
                                   (unsigned)decoded[i].text_count_range_lower, (unsigned)decoded[i].text_count_range_upper, names[0] + 1,
                                   (unsigned)decoded[i].text_count_range_offset);
            } else if (decoded[i].text_presence_offset_equal) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "condition: %s and @%s == %d }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[0], names[0] + 1,
                                   (int)decoded[i].text_offset_equal_value);
            } else if (decoded[i].text_match_in_range) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "condition: %s in (%u..%u) }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[0],
                                   (unsigned)decoded[i].text_match_range_lower, (unsigned)decoded[i].text_match_range_upper);
            } else if (decoded[i].text_direct_offset_compare) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "condition: @%s[%u] %s %d }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[0] + 1,
                                   (unsigned)decoded[i].text_direct_offset_index,
                                   decoded[i].text_direct_offset_not_equal ? "!=" : "==", (int)decoded[i].text_direct_offset_value);
            } else if (decoded[i].text_direct_length_compare) {
                written = snprintf(source, source_capacity,
                                   "%srule %s { strings: %s = \"%s\" "
                                   "condition: !%s[%u] %s %d }",
                                   decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[0] + 1,
                                   (unsigned)decoded[i].text_direct_length_index,
                                   decoded[i].text_direct_length_not_equal ? "!=" : "==", (int)decoded[i].text_direct_length_value);
            } else if (decoded[i].all_positive_single_text_statistics) {
                written =
                    snprintf(source, source_capacity,
                             "%srule %s { strings: %s = \"%s\" "
                             "condition: %s and @%s and !%s and #%s }",
                             decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0], names[0], names[0] + 1, names[0] + 1, names[0] + 1);
            } else {
                const char *count_operator = decoded[i].count_operator == YX_SER_COUNT_GT   ? ">"
                                             : decoded[i].count_operator == YX_SER_COUNT_GE ? ">="
                                             : decoded[i].count_operator == YX_SER_COUNT_EQ ? "=="
                                             : decoded[i].count_operator == YX_SER_COUNT_LT ? "<"
                                             : decoded[i].count_operator == YX_SER_COUNT_LE ? "<="
                                             : decoded[i].count_operator == YX_SER_COUNT_NE ? "!="
                                                                                            : NULL;
                char count_comparison[16] = "";
                char at_position[16] = "";
                char base64_modifier[160] = "";
                const char *quantified_condition = decoded[i].single_pattern_quantifier == 1   ? "any of them"
                                                   : decoded[i].single_pattern_quantifier == 2 ? "1 of them"
                                                                                               : NULL;
                if (count_operator) (void)snprintf(count_comparison, sizeof(count_comparison), " %s %u", count_operator, (unsigned)decoded[i].count_value);
                if (decoded[i].at_single_text_pattern) (void)snprintf(at_position, sizeof(at_position), " at %u", (unsigned)decoded[i].at_offset);
                if (decoded[i].single_base64_pattern || decoded[i].single_base64wide_pattern) {
                    const char *input_modifier = decoded[i].single_base64_input_ascii_wide ? "ascii wide " : decoded[i].single_base64_input_wide ? "wide " : "";
                    const char *encoding_modifier = decoded[i].single_base64wide_pattern ? "base64wide" : "base64";
                    const char *alphabet = decoded[i].single_base64_alphabet;
                    (void)snprintf(base64_modifier, sizeof(base64_modifier), "%s%s%s%s%s ", input_modifier, encoding_modifier, alphabet ? "(\"" : "",
                                   alphabet ? alphabet : "", alphabet ? "\")" : "");
                }
                written = snprintf(
                    source, source_capacity,
                    "%srule %s { strings: %s = \"%s\" "
                    "%scondition: %s%s%s }",
                    decoded[i].is_private ? "private " : "", decoded[i].identifier, names[0], escaped[0],
                    (decoded[i].ascii_wide_single_pattern && decoded[i].nocase_single_pattern && decoded[i].fullword_single_pattern)    ? "ascii wide nocase fullword "
                    : (decoded[i].wide_single_pattern && decoded[i].nocase_single_pattern && decoded[i].fullword_single_pattern)        ? "wide nocase fullword "
                    : (decoded[i].ascii_wide_single_pattern && decoded[i].nocase_single_pattern && !decoded[i].fullword_single_pattern) ? "ascii wide nocase "
                    : (decoded[i].wide_single_pattern && decoded[i].nocase_single_pattern && !decoded[i].fullword_single_pattern)       ? "wide nocase "
                    : (decoded[i].ascii_wide_single_pattern && decoded[i].fullword_single_pattern)                                      ? "ascii wide fullword "
                    : (decoded[i].wide_single_pattern && decoded[i].fullword_single_pattern)                                            ? "wide fullword "
                    : decoded[i].ascii_wide_single_pattern                                                                              ? "ascii wide "
                    : decoded[i].wide_single_pattern                                                                                    ? "wide "
                    : (decoded[i].nocase_single_pattern && decoded[i].fullword_single_pattern)                                          ? "nocase fullword "
                    : decoded[i].fullword_single_pattern                                                                                ? "fullword "
                    : decoded[i].nocase_single_pattern                                                                                  ? "nocase "
                    : decoded[i].single_xor_pattern                                                                                     ? "xor "
                                                                                                                                        : base64_modifier,
                    quantified_condition                     ? ""
                    : count_operator                         ? "#"
                    : decoded[i].negated_single_text_pattern ? "not "
                                                             : "",
                    quantified_condition ? quantified_condition
                    : count_operator     ? names[0] + 1
                                         : names[0],
                    quantified_condition                ? ""
                    : decoded[i].at_single_text_pattern ? at_position
                                                        : count_comparison);
            }
            free(escaped_storage);
            if (written < 0 || (size_t)written >= source_capacity) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
        } else if (decoded[i].integer_global_condition) {
            const char *op;
            switch (decoded[i].global_compare_opcode) {
                case 0x51: op = "=="; break;
                case 0x52: op = "!="; break;
                case 0x53: op = "<"; break;
                case 0x55: op = ">"; break;
                case 0x57: op = "<="; break;
                case 0x59: op = ">="; break;
                default: op = NULL; break;
            }
            if (!op) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            char literal[64];
            if (decoded[i].global_compare_value == INT64_MIN) strcpy(literal, "(-9223372036854775807 - 1)");
            else snprintf(literal, sizeof(literal), "%" PRId64, decoded[i].global_compare_value);
            if (decoded[i].global_compare_literal_first)
                snprintf(source, source_capacity, "%srule %s { condition: %s %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier, literal, op,
                         decoded[i].global_name);
            else
                snprintf(source, source_capacity, "%srule %s { condition: %s %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                         decoded[i].global_name, op, literal);
        } else if (decoded[i].float_global_condition) {
            const char *op;
            char literal[384];
            switch (decoded[i].float_compare_opcode) {
                case 0x61: op = "=="; break;
                case 0x62: op = "!="; break;
                case 0x63: op = "<"; break;
                case 0x64: op = ">"; break;
                case 0x65: op = "<="; break;
                case 0x66: op = ">="; break;
                default: op = NULL; break;
            }
            if (!op || !yx_float_source_literal(decoded[i].float_compare_value, literal, sizeof(literal))) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            if (decoded[i].float_compare_literal_first)
                snprintf(source, source_capacity, "%srule %s { condition: %s %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier, literal, op,
                         decoded[i].global_name);
            else
                snprintf(source, source_capacity, "%srule %s { condition: %s %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                         decoded[i].global_name, op, literal);
        } else if (decoded[i].boolean_global_condition) {
            const char *suffix;
            const char *prefix;
            bool grouped;
            if (decoded[i].boolean_global_blocks > 2 || decoded[i].boolean_global_negations > 2) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            if (decoded[i].boolean_global_constant) suffix = decoded[i].boolean_global_constant_value ? " or true" : " and false";
            else suffix = decoded[i].boolean_global_blocks == 1 ? " and true" : decoded[i].boolean_global_blocks == 2 ? " or false" : "";
            prefix = decoded[i].boolean_global_negations == 2 ? "not not " : decoded[i].boolean_global_negations == 1 ? "not " : "";
            grouped = decoded[i].boolean_global_negations != 0;
            snprintf(source, source_capacity, "%srule %s { condition: %s%s%s%s%s }", decoded[i].is_private ? "private " : "", decoded[i].identifier, prefix,
                     grouped ? "(" : "", decoded[i].global_name, suffix, grouped ? ")" : "");
        } else if (decoded[i].string_global_condition) {
            if (decoded[i].string_compare_literal_first)
                snprintf(source, source_capacity, "%srule %s { condition: \"%s\" %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                         decoded[i].string_compare_literal, decoded[i].string_compare_not_equal ? "!=" : "==", decoded[i].global_name);
            else
                snprintf(source, source_capacity, "%srule %s { condition: %s %s \"%s\" }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                         decoded[i].global_name, decoded[i].string_compare_not_equal ? "!=" : "==", decoded[i].string_compare_literal);
        } else if (decoded[i].time_now) {
            snprintf(source, source_capacity, "rule %s { condition: time.now() }", decoded[i].identifier);
        } else if (decoded[i].math_max_eq) {
            snprintf(source, source_capacity, "rule %s { condition: math.max(%d, %d) %s %d }", decoded[i].identifier, (int)decoded[i].math_max_first,
                     (int)decoded[i].math_max_second, decoded[i].math_max_not_equal ? "!=" : "==", (int)decoded[i].math_max_compared);
        } else if (decoded[i].console_pe_log) {
            snprintf(source, source_capacity, "rule %s { condition: console.log(\"%s\") }", decoded[i].identifier, decoded[i].console_log_text);
        } else if (decoded[i].cuckoo_imported) {
            snprintf(source, source_capacity, "rule %s { condition: %s }", decoded[i].identifier, decoded[i].cuckoo_condition);
        } else if (decoded[i].vt_imported) {
            const char *variant = yx_vt_permutation_variant(decoded[i].integer_left);
            bool enum_first = variant != NULL;
            const char *op;
            if (!enum_first) variant = yx_vt_permutation_variant(decoded[i].integer_right);
            switch (decoded[i].integer_opcode) {
                case 0x51: op = "=="; break;
                case 0x52: op = "!="; break;
                case 0x53: op = "<"; break;
                case 0x55: op = ">"; break;
                case 0x57: op = "<="; break;
                case 0x59: op = ">="; break;
                default: op = NULL; break;
            }
            if (!variant || !op) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            if (enum_first)
                snprintf(source, source_capacity,
                         "%srule %s { condition: "
                         "vt.Domain.Permutation.%s %s %" PRId64 " }",
                         decoded[i].is_private ? "private " : "", decoded[i].identifier, variant, op, decoded[i].integer_right);
            else
                snprintf(source, source_capacity,
                         "%srule %s { condition: %" PRId64
                         " %s "
                         "vt.Domain.Permutation.%s }",
                         decoded[i].is_private ? "private " : "", decoded[i].identifier, decoded[i].integer_left, op, variant);
        } else if (decoded[i].pe_version_any) {
            if (decoded[i].pe_version_with_any)
                snprintf(source, source_capacity,
                         "%srule %s { condition: with v = pe.version_info: "
                         "(for any k, v in v: "
                         "(k == \"%s\" and v == \"%s\")) }",
                         decoded[i].is_private ? "private " : "", decoded[i].identifier, decoded[i].pe_version_key, decoded[i].pe_version_value);
            else
                snprintf(source, source_capacity,
                         "%srule %s { condition: for any k, v in "
                         "pe.version_info: "
                         "(k == \"%s\" and v == \"%s\") }",
                         decoded[i].is_private ? "private " : "", decoded[i].identifier, decoded[i].pe_version_key, decoded[i].pe_version_value);
        } else if (decoded[i].pe_is_pe) {
            snprintf(source, source_capacity, "%srule %s { condition: pe.is_pe }", decoded[i].is_private ? "private " : "", decoded[i].identifier);
        } else if (decoded[i].pe_is_pe_filesize) {
            snprintf(source, source_capacity, "%srule %s { condition: %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                     decoded[i].pe_filesize_first && decoded[i].pe_filesize_or ? "filesize > 0 or pe.is_pe"
                     : decoded[i].pe_filesize_first                            ? "filesize > 0 and pe.is_pe"
                     : decoded[i].pe_filesize_or                               ? "pe.is_pe or filesize > 0"
                     : decoded[i].pe_filesize_equals_one                       ? "pe.is_pe and filesize == 1"
                     : decoded[i].pe_filesize_ge_one                           ? "pe.is_pe and filesize >= 1"
                                                                               : "pe.is_pe and filesize > 0");
        } else if (decoded[i].pe_number_of_sections) {
            snprintf(source, source_capacity, "%srule %s { condition: pe.number_of_sections %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                     decoded[i].pe_equals_one ? "== 1" : "> 0");
        } else if (decoded[i].pe_sections_len) {
            snprintf(source, source_capacity, "%srule %s { condition: pe.sections.len() %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                     decoded[i].pe_equals_one ? "== 1" : "> 0");
        } else if (decoded[i].runtime_integer_condition) {
            snprintf(source, source_capacity, "%s%srule %s { condition: %s }", decoded[i].is_global ? "global " : "", decoded[i].is_private ? "private " : "",
                     decoded[i].identifier, decoded[i].runtime_integer_condition);
        } else if (decoded[i].integer_read_comparison || decoded[i].integer_comparison || decoded[i].filesize_comparison) {
            const char *op;
            char left_integer[40], right_integer[40], read_offset[40];
            /* The grammar parses the magnitude before unary minus and
             * rejects a direct INT64_MIN literal. Archives can contain
             * that value after constant folding, so reconstruct it using
             * two representable literals. */
            if (decoded[i].integer_left == INT64_MIN) strcpy(left_integer, "(-9223372036854775807 - 1)");
            else snprintf(left_integer, sizeof(left_integer), "%" PRId64, decoded[i].integer_left);
            if (decoded[i].integer_right == INT64_MIN) strcpy(right_integer, "(-9223372036854775807 - 1)");
            else snprintf(right_integer, sizeof(right_integer), "%" PRId64, decoded[i].integer_right);
            if (decoded[i].integer_read_offset == INT64_MIN) strcpy(read_offset, "(-9223372036854775807 - 1)");
            else snprintf(read_offset, sizeof(read_offset), "%" PRId64, decoded[i].integer_read_offset);
            switch (decoded[i].integer_opcode) {
                case 0x51: op = "=="; break;
                case 0x52: op = "!="; break;
                case 0x53: op = "<"; break;
                case 0x55: op = ">"; break;
                case 0x57: op = "<="; break;
                case 0x59: op = ">="; break;
                default: op = NULL; break;
            }
            if (!op) {
                free(source);
                result = YRX_SERIALIZATION_ERROR;
                break;
            }
            if (decoded[i].integer_read_comparison) {
                static const char *const read_names[] = {"uint8", "uint16", "uint32", "int8", "int16", "int32"};
                if (decoded[i].integer_read_type >= sizeof(read_names) / sizeof(read_names[0])) {
                    free(source);
                    result = YRX_SERIALIZATION_ERROR;
                    break;
                }
                snprintf(source, source_capacity, "%srule %s { condition: %s(%s) %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                         read_names[decoded[i].integer_read_type], read_offset, op, right_integer);
            } else if (decoded[i].filesize_comparison) {
                char negation_prefix[8 * 4 + 2] = "";
                const char *open_group = "";
                const char *close_group = "";
                if (decoded[i].filesize_negations > 8 || decoded[i].filesize_identity_blocks > 2 ||
                    (decoded[i].filesize_negations && decoded[i].filesize_identity_blocks)) {
                    free(source);
                    result = YRX_SERIALIZATION_ERROR;
                    break;
                }
                for (uint8_t n = 0; n < decoded[i].filesize_negations; ++n) strcat(negation_prefix, "not ");
                if (decoded[i].filesize_negations) {
                    open_group = "(";
                    close_group = ")";
                } else if (decoded[i].filesize_identity_blocks) {
                    open_group = "(";
                    close_group = decoded[i].filesize_identity_blocks == 1 ? ") and true" : ") or false";
                }
                if (decoded[i].filesize_double_and || decoded[i].filesize_double_or || decoded[i].filesize_triple_and || decoded[i].filesize_triple_or ||
                    decoded[i].filesize_mixed_or_and || decoded[i].filesize_mixed_and_or || decoded[i].filesize_mixed_and_or_left ||
                    decoded[i].filesize_mixed_or_and_left || decoded[i].filesize_quad_and || decoded[i].filesize_quad_or || decoded[i].filesize_five_and ||
                    decoded[i].filesize_five_or || decoded[i].filesize_six_and || decoded[i].filesize_six_or || decoded[i].filesize_seven_and ||
                    decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                    const char *second_op;
                    const char *third_op = NULL;
                    const char *fourth_op = NULL;
                    const char *fifth_op = NULL;
                    const char *sixth_op = NULL;
                    const char *seventh_op = NULL;
                    const char *eighth_op = NULL;
                    switch (decoded[i].filesize_second_opcode) {
                        case 0x51: second_op = "=="; break;
                        case 0x52: second_op = "!="; break;
                        case 0x53: second_op = "<"; break;
                        case 0x55: second_op = ">"; break;
                        case 0x57: second_op = "<="; break;
                        case 0x59: second_op = ">="; break;
                        default: second_op = NULL; break;
                    }
                    if (decoded[i].filesize_triple_and || decoded[i].filesize_triple_or || decoded[i].filesize_mixed_or_and || decoded[i].filesize_mixed_and_or ||
                        decoded[i].filesize_mixed_and_or_left || decoded[i].filesize_mixed_or_and_left || decoded[i].filesize_quad_and || decoded[i].filesize_quad_or ||
                        decoded[i].filesize_five_and || decoded[i].filesize_five_or || decoded[i].filesize_six_and || decoded[i].filesize_six_or ||
                        decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                        switch (decoded[i].filesize_third_opcode) {
                            case 0x51: third_op = "=="; break;
                            case 0x52: third_op = "!="; break;
                            case 0x53: third_op = "<"; break;
                            case 0x55: third_op = ">"; break;
                            case 0x57: third_op = "<="; break;
                            case 0x59: third_op = ">="; break;
                            default: break;
                        }
                    }
                    if (decoded[i].filesize_quad_and || decoded[i].filesize_quad_or || decoded[i].filesize_five_and || decoded[i].filesize_five_or ||
                        decoded[i].filesize_six_and || decoded[i].filesize_six_or || decoded[i].filesize_seven_and || decoded[i].filesize_seven_or ||
                        decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                        switch (decoded[i].filesize_fourth_opcode) {
                            case 0x51: fourth_op = "=="; break;
                            case 0x52: fourth_op = "!="; break;
                            case 0x53: fourth_op = "<"; break;
                            case 0x55: fourth_op = ">"; break;
                            case 0x57: fourth_op = "<="; break;
                            case 0x59: fourth_op = ">="; break;
                            default: break;
                        }
                    }
                    if (decoded[i].filesize_five_and || decoded[i].filesize_five_or || decoded[i].filesize_six_and || decoded[i].filesize_six_or ||
                        decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                        switch (decoded[i].filesize_fifth_opcode) {
                            case 0x51: fifth_op = "=="; break;
                            case 0x52: fifth_op = "!="; break;
                            case 0x53: fifth_op = "<"; break;
                            case 0x55: fifth_op = ">"; break;
                            case 0x57: fifth_op = "<="; break;
                            case 0x59: fifth_op = ">="; break;
                            default: break;
                        }
                    }
                    if (decoded[i].filesize_six_and || decoded[i].filesize_six_or || decoded[i].filesize_seven_and || decoded[i].filesize_seven_or ||
                        decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                        switch (decoded[i].filesize_sixth_opcode) {
                            case 0x51: sixth_op = "=="; break;
                            case 0x52: sixth_op = "!="; break;
                            case 0x53: sixth_op = "<"; break;
                            case 0x55: sixth_op = ">"; break;
                            case 0x57: sixth_op = "<="; break;
                            case 0x59: sixth_op = ">="; break;
                            default: break;
                        }
                    }
                    if (decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                        switch (decoded[i].filesize_seventh_opcode) {
                            case 0x51: seventh_op = "=="; break;
                            case 0x52: seventh_op = "!="; break;
                            case 0x53: seventh_op = "<"; break;
                            case 0x55: seventh_op = ">"; break;
                            case 0x57: seventh_op = "<="; break;
                            case 0x59: seventh_op = ">="; break;
                            default: break;
                        }
                    }
                    if (decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) {
                        switch (decoded[i].filesize_eighth_opcode) {
                            case 0x51: eighth_op = "=="; break;
                            case 0x52: eighth_op = "!="; break;
                            case 0x53: eighth_op = "<"; break;
                            case 0x55: eighth_op = ">"; break;
                            case 0x57: eighth_op = "<="; break;
                            case 0x59: eighth_op = ">="; break;
                            default: break;
                        }
                    }
                    if (!second_op ||
                        ((decoded[i].filesize_triple_and || decoded[i].filesize_triple_or || decoded[i].filesize_mixed_or_and || decoded[i].filesize_mixed_and_or ||
                          decoded[i].filesize_mixed_and_or_left || decoded[i].filesize_mixed_or_and_left || decoded[i].filesize_quad_and || decoded[i].filesize_quad_or ||
                          decoded[i].filesize_five_and || decoded[i].filesize_five_or || decoded[i].filesize_six_and || decoded[i].filesize_six_or ||
                          decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) &&
                         !third_op) ||
                        ((decoded[i].filesize_quad_and || decoded[i].filesize_quad_or || decoded[i].filesize_five_and || decoded[i].filesize_five_or ||
                          decoded[i].filesize_six_and || decoded[i].filesize_six_or || decoded[i].filesize_seven_and || decoded[i].filesize_seven_or ||
                          decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) &&
                         !fourth_op) ||
                        ((decoded[i].filesize_five_and || decoded[i].filesize_five_or || decoded[i].filesize_six_and || decoded[i].filesize_six_or ||
                          decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) &&
                         !fifth_op) ||
                        ((decoded[i].filesize_six_and || decoded[i].filesize_six_or || decoded[i].filesize_seven_and || decoded[i].filesize_seven_or ||
                          decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) &&
                         !sixth_op) ||
                        ((decoded[i].filesize_seven_and || decoded[i].filesize_seven_or || decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) &&
                         !seventh_op) ||
                        ((decoded[i].filesize_eight_and || decoded[i].filesize_eight_or) && !eighth_op) ||
                        (decoded[i].filesize_triple_or_right_grouped && !decoded[i].filesize_triple_or) ||
                        (decoded[i].filesize_triple_and_right_grouped && !decoded[i].filesize_triple_and) ||
                        (unsigned)decoded[i].filesize_double_and + (unsigned)decoded[i].filesize_double_or + (unsigned)decoded[i].filesize_triple_and +
                                (unsigned)decoded[i].filesize_triple_or + (unsigned)decoded[i].filesize_mixed_or_and + (unsigned)decoded[i].filesize_mixed_and_or +
                                (unsigned)decoded[i].filesize_mixed_and_or_left + (unsigned)decoded[i].filesize_mixed_or_and_left +
                                (unsigned)decoded[i].filesize_quad_and + (unsigned)decoded[i].filesize_quad_or + (unsigned)decoded[i].filesize_five_and +
                                (unsigned)decoded[i].filesize_five_or + (unsigned)decoded[i].filesize_six_and + (unsigned)decoded[i].filesize_six_or +
                                (unsigned)decoded[i].filesize_seven_and + (unsigned)decoded[i].filesize_seven_or + (unsigned)decoded[i].filesize_eight_and +
                                (unsigned)decoded[i].filesize_eight_or !=
                            1 ||
                        decoded[i].filesize_arithmetic || decoded[i].filesize_literal_first || decoded[i].filesize_negations || decoded[i].filesize_identity_blocks) {
                        free(source);
                        result = YRX_SERIALIZATION_ERROR;
                        break;
                    }
                    if (decoded[i].filesize_eight_and || decoded[i].filesize_eight_or)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64
                                 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right,
                                 decoded[i].filesize_eight_or ? "or" : "and", second_op, decoded[i].filesize_second_literal, decoded[i].filesize_eight_or ? "or" : "and",
                                 third_op, decoded[i].filesize_third_literal, decoded[i].filesize_eight_or ? "or" : "and", fourth_op, decoded[i].filesize_fourth_literal,
                                 decoded[i].filesize_eight_or ? "or" : "and", fifth_op, decoded[i].filesize_fifth_literal, decoded[i].filesize_eight_or ? "or" : "and",
                                 sixth_op, decoded[i].filesize_sixth_literal, decoded[i].filesize_eight_or ? "or" : "and", seventh_op,
                                 decoded[i].filesize_seventh_literal, decoded[i].filesize_eight_or ? "or" : "and", eighth_op, decoded[i].filesize_eighth_literal);
                    else if (decoded[i].filesize_seven_and || decoded[i].filesize_seven_or)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64
                                 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right,
                                 decoded[i].filesize_seven_or ? "or" : "and", second_op, decoded[i].filesize_second_literal, decoded[i].filesize_seven_or ? "or" : "and",
                                 third_op, decoded[i].filesize_third_literal, decoded[i].filesize_seven_or ? "or" : "and", fourth_op, decoded[i].filesize_fourth_literal,
                                 decoded[i].filesize_seven_or ? "or" : "and", fifth_op, decoded[i].filesize_fifth_literal, decoded[i].filesize_seven_or ? "or" : "and",
                                 sixth_op, decoded[i].filesize_sixth_literal, decoded[i].filesize_seven_or ? "or" : "and", seventh_op,
                                 decoded[i].filesize_seventh_literal);
                    else if (decoded[i].filesize_six_and || decoded[i].filesize_six_or)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64
                                 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, decoded[i].filesize_six_or ? "or" : "and",
                                 second_op, decoded[i].filesize_second_literal, decoded[i].filesize_six_or ? "or" : "and", third_op, decoded[i].filesize_third_literal,
                                 decoded[i].filesize_six_or ? "or" : "and", fourth_op, decoded[i].filesize_fourth_literal, decoded[i].filesize_six_or ? "or" : "and",
                                 fifth_op, decoded[i].filesize_fifth_literal, decoded[i].filesize_six_or ? "or" : "and", sixth_op, decoded[i].filesize_sixth_literal);
                    else if (decoded[i].filesize_five_and || decoded[i].filesize_five_or)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64
                                 ") %s (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, decoded[i].filesize_five_or ? "or" : "and",
                                 second_op, decoded[i].filesize_second_literal, decoded[i].filesize_five_or ? "or" : "and", third_op, decoded[i].filesize_third_literal,
                                 decoded[i].filesize_five_or ? "or" : "and", fourth_op, decoded[i].filesize_fourth_literal, decoded[i].filesize_five_or ? "or" : "and",
                                 fifth_op, decoded[i].filesize_fifth_literal);
                    else if (decoded[i].filesize_quad_and || decoded[i].filesize_quad_or)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64
                                 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, decoded[i].filesize_quad_or ? "or" : "and",
                                 second_op, decoded[i].filesize_second_literal, decoded[i].filesize_quad_or ? "or" : "and", third_op, decoded[i].filesize_third_literal,
                                 decoded[i].filesize_quad_or ? "or" : "and", fourth_op, decoded[i].filesize_fourth_literal);
                    else if (decoded[i].filesize_mixed_or_and_left)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: ((filesize %s %" PRId64 ") or (filesize %s %" PRId64 ")) and (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, second_op,
                                 decoded[i].filesize_second_literal, third_op, decoded[i].filesize_third_literal);
                    else if (decoded[i].filesize_mixed_and_or_left)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: ((filesize %s %" PRId64 ") and (filesize %s %" PRId64 ")) or (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, second_op,
                                 decoded[i].filesize_second_literal, third_op, decoded[i].filesize_third_literal);
                    else if (decoded[i].filesize_mixed_and_or)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") and ((filesize %s %" PRId64 ") or (filesize %s %" PRId64 ")) }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, second_op,
                                 decoded[i].filesize_second_literal, third_op, decoded[i].filesize_third_literal);
                    else if (decoded[i].filesize_mixed_or_and)
                        snprintf(source, source_capacity,
                                 "%srule %s { condition: (filesize %s %" PRId64 ") or ((filesize %s %" PRId64 ") and (filesize %s %" PRId64 ")) }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, second_op,
                                 decoded[i].filesize_second_literal, third_op, decoded[i].filesize_third_literal);
                    else if (decoded[i].filesize_triple_or_right_grouped || decoded[i].filesize_triple_and_right_grouped)
                        snprintf(
                            source, source_capacity, "%srule %s { condition: (filesize %s %" PRId64 ") %s ((filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ")) }",
                            decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, decoded[i].filesize_triple_or ? "or" : "and",
                            second_op, decoded[i].filesize_second_literal, decoded[i].filesize_triple_or ? "or" : "and", third_op, decoded[i].filesize_third_literal);
                    else if (decoded[i].filesize_triple_and || decoded[i].filesize_triple_or)
                        snprintf(source, source_capacity, "%srule %s { condition: (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") %s (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right,
                                 decoded[i].filesize_triple_or ? "or" : "and", second_op, decoded[i].filesize_second_literal,
                                 decoded[i].filesize_triple_or ? "or" : "and", third_op, decoded[i].filesize_third_literal);
                    else if (decoded[i].filesize_double_or)
                        snprintf(source, source_capacity, "%srule %s { condition: (filesize %s %" PRId64 ") or (filesize %s %" PRId64 ") }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, second_op,
                                 decoded[i].filesize_second_literal);
                    else
                        snprintf(source, source_capacity, "%srule %s { condition: filesize %s %" PRId64 " and filesize %s %" PRId64 " }",
                                 decoded[i].is_private ? "private " : "", decoded[i].identifier, op, decoded[i].integer_right, second_op,
                                 decoded[i].filesize_second_literal);
                } else if (decoded[i].filesize_arithmetic) {
                    char arithmetic_op = decoded[i].filesize_arith_opcode == 0x7c ? '+' : decoded[i].filesize_arith_opcode == 0x7d ? '-' : '\0';
                    if (!arithmetic_op) {
                        free(source);
                        result = YRX_SERIALIZATION_ERROR;
                        break;
                    }
                    snprintf(source, source_capacity, "%srule %s { condition: %s%sfilesize %c (%" PRId64 ") %s %" PRId64 "%s }", decoded[i].is_private ? "private " : "",
                             decoded[i].identifier, negation_prefix, open_group, arithmetic_op, decoded[i].filesize_arith_operand, op, decoded[i].integer_right,
                             close_group);
                } else if (decoded[i].filesize_literal_first) {
                    snprintf(source, source_capacity, "%srule %s { condition: %s%s%s %s filesize%s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                             negation_prefix, open_group, right_integer, op, close_group);
                } else {
                    snprintf(source, source_capacity, "%srule %s { condition: %s%sfilesize %s %s%s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                             negation_prefix, open_group, op, right_integer, close_group);
                }
            } else {
                snprintf(source, source_capacity, "%srule %s { condition: %s %s %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier, left_integer, op,
                         right_integer);
            }
        } else if (decoded[i].with_two_integer_test) {
            snprintf(source, source_capacity,
                     "rule %s { condition: with a = %d, b = %d: "
                     "(a == %d and (a == b or b > %d)) }",
                     decoded[i].identifier, (int)decoded[i].with_first_value, (int)decoded[i].with_second_value, (int)decoded[i].with_first_compare,
                     (int)decoded[i].with_second_threshold);
        } else if (decoded[i].with_integer_eq || decoded[i].with_first_rule_and_integer_eq) {
            if (decoded[i].with_first_rule_and_integer_eq)
                snprintf(source, source_capacity,
                         "rule %s { condition: %s and with v = %d: "
                         "(v == %d) }",
                         decoded[i].identifier, decoded[0].identifier, (int)decoded[i].with_bound_value, (int)decoded[i].with_compared_value);
            else
                snprintf(source, source_capacity,
                         "rule %s { condition: with v = %d: "
                         "(v == %d) }",
                         decoded[i].identifier, (int)decoded[i].with_bound_value, (int)decoded[i].with_compared_value);
        } else if (decoded[i].reference_first_rule) {
            snprintf(source, source_capacity, "rule %s { condition: %s }", decoded[i].identifier, decoded[0].identifier);
        } else {
            snprintf(source, source_capacity, "%srule %s { condition: %s }", decoded[i].is_private ? "private " : "", decoded[i].identifier,
                     decoded[i].truth ? "true" : "false");
        }
        if (i && (strcmp(decoded[i].namespace_name, decoded[i - 1].namespace_name) || decoded[i].namespace_index != decoded[i - 1].namespace_index)) {
            result = yrx_compiler_new_namespace(compiler, decoded[i].namespace_name);
            if (decoded[i].namespace_index || !strcmp(decoded[i].namespace_name, "default")) compiler->current_namespace_index = decoded[i].namespace_index;
            for (size_t m = 0; result == YRX_SUCCESS && m < decoded[0].runtime_module_count; ++m) {
                char module_source[256];
                int n = snprintf(module_source, sizeof(module_source), "import \"%s\"", decoded[0].runtime_module_names[m]);
                if (n < 0 || (size_t)n >= sizeof(module_source)) result = YRX_SERIALIZATION_ERROR;
                else result = yrx_compiler_add_source(compiler, module_source);
            }
        }
        if (result == YRX_SUCCESS && batch_rules) {
            size_t added = strlen(source);
            if (batch_length > SIZE_MAX - 2 || added > SIZE_MAX - batch_length - 2) result = YRX_SERIALIZATION_ERROR;
            else {
                size_t needed = batch_length + added + 2;
                if (needed > batch_capacity) {
                    size_t capacity = batch_capacity && batch_capacity <= SIZE_MAX / 2 ? batch_capacity * 2 : needed;
                    if (capacity < needed) capacity = needed;
                    char *grown = realloc(batch_source, capacity);
                    if (!grown) result = YRX_SERIALIZATION_ERROR;
                    else {
                        batch_source = grown;
                        batch_capacity = capacity;
                    }
                }
                if (result == YRX_SUCCESS) {
                    if (batch_starts) batch_starts[i] = batch_length;
                    batch_global |= decoded[i].is_global;
                    memcpy(batch_source + batch_length, source, added);
                    batch_length += added;
                    batch_source[batch_length++] = '\n';
                    batch_source[batch_length] = 0;
                }
            }
        } else if (result == YRX_SUCCESS) result = yrx_compiler_add_source(compiler, source);
        free(source);
    }
    if (result == YRX_SUCCESS && batch_rules) {
        if (batch_starts) batch_starts[decoded_count] = batch_length;
        result = yx_compile_batch(compiler, batch_source, batch_length, batch_starts, decoded_count, batch_global);
    }
    free(batch_starts);
    free(batch_source);
    if (result == YRX_SUCCESS) {
        yx_ser_rule *outer_decoded = yx_attach_decoded;
        size_t outer_count = yx_attach_decoded_count;
        yx_attach_decoded = decoded;
        yx_attach_decoded_count = decoded_count;
        deserialized = yx_compiler_build_impl(compiler, false);
        yx_attach_decoded = outer_decoded;
        yx_attach_decoded_count = outer_count;
    }
    if (result == YRX_SUCCESS && deserialized && deserialized->rule_count == decoded_count) {
        for (size_t i = 0; i < decoded_count; ++i) {
            YRX_RULE *rule = &deserialized->rules[i];
            if (decoded[i].base64_archived_prefilter.present) {
                if (rule->pattern_count != 1 || rule->patterns[0].kind != YX_PATTERN_TEXT || !(rule->patterns[0].modifiers & YX_MOD_BASE64) ||
                    (rule->patterns[0].modifiers & (YX_MOD_WIDE | YX_MOD_BASE64WIDE))) {
                    result = YRX_SERIALIZATION_ERROR;
                    break;
                }
                rule->patterns[0].base64_archived_prefilter = decoded[i].base64_archived_prefilter;
            }
            if (decoded[i].runtime_literal_prefilters) {
                if (rule->pattern_count != decoded[i].runtime_literal_prefilter_count) {
                    result = YRX_SERIALIZATION_ERROR;
                    break;
                }
                for (size_t p = 0; p < rule->pattern_count; ++p) {
                    rule->patterns[p].archived_literal_prefilter = decoded[i].runtime_literal_prefilters[p];
                    decoded[i].runtime_literal_prefilters[p].atoms = NULL;
                }
            }
            rule->tags = decoded[i].tags;
            rule->tag_count = decoded[i].tag_count;
            rule->metadata = decoded[i].metadata;
            rule->metadata_count = decoded[i].metadata_count;
            decoded[i].tags = NULL;
            decoded[i].tag_count = 0;
            decoded[i].metadata = NULL;
            decoded[i].metadata_count = 0;
        }
    }
    yx_ser_rules_destroy(decoded, decoded_count);
    yrx_compiler_destroy(compiler);
    if (result != YRX_SUCCESS || !deserialized || deserialized->rule_count != decoded_count) {
        if (deserialized) yrx_rules_destroy(deserialized);
        return yx_fail(YRX_SERIALIZATION_ERROR, "cannot decode YARA-X rules");
    }
    if (embedded_nul_at != SIZE_MAX || normalized_empty_ac || normalized_bitmap_shift || normalized_import_name || noncanonical_ac || noncanonical_literal_pool ||
        preserve_serialized_prefix) {
        YRX_RULE *rule = &deserialized->rules[0];
        char *namespace_name = NULL;
        uint8_t *serialized_prefix = malloc(prefix_length);
        if (embedded_nul_at != SIZE_MAX) {
            if (prefix_length <= embedded_nul_at || !rule->namespace_name || strcmp(rule->namespace_name, "default") != 0) {
                free(serialized_prefix);
                yrx_rules_destroy(deserialized);
                return yx_unsupported("compiled-rule deserialization for this rule shape");
            }
            namespace_name = malloc(sizeof(default_namespace) + 1);
        }
        if (!serialized_prefix || (embedded_nul_at != SIZE_MAX && !namespace_name)) {
            free(namespace_name);
            free(serialized_prefix);
            yrx_rules_destroy(deserialized);
            return yx_fail(YRX_SERIALIZATION_ERROR, "out of memory decoding YARA-X rules");
        }
        memcpy(serialized_prefix, data, prefix_length);
        if (embedded_nul_at != SIZE_MAX) {
            memcpy(namespace_name, data + 14, sizeof(default_namespace));
            namespace_name[sizeof(default_namespace)] = 0;
            free(rule->namespace_name);
            rule->namespace_name = namespace_name;
            rule->namespace_name_length = sizeof(default_namespace);
        }
        deserialized->serialized_prefix = serialized_prefix;
        deserialized->serialized_prefix_length = prefix_length;
        deserialized->unknown_wasm_import = normalized_import_name;
    }
    *rules = deserialized;
    return yx_ok();
}
YRX_RESULT yrx_scanner_set_timeout(YRX_SCANNER *scanner, uint64_t seconds)
{
    if (!scanner) return yx_null_argument("scanner");
    scanner->timeout_seconds = seconds;
    scanner->timeout_configured = true;
    return yx_ok();
}
YRX_RESULT yrx_scanner_on_console_log(YRX_SCANNER *scanner, YRX_CONSOLE_CALLBACK callback)
{
    if (!scanner) return yx_null_argument("scanner");
    if (!callback) return yx_null_argument("callback");
    scanner->console_callback = callback;
    scanner->console_c_string = true;
    return yx_ok();
}

YRX_RESULT yx_scanner_on_console_log_raw(YRX_SCANNER *scanner, YRX_CONSOLE_CALLBACK callback)
{
    if (!scanner) return yx_null_argument("scanner");
    scanner->console_callback = callback;
    scanner->console_c_string = false;
    return yx_ok();
}

/* These modules have protobuf root messages with no declared fields. Any
 * well-formed fields in their wire payload are unknown and ignored by YARA-X.
 * Supplying an output also skips native module execution, including its
 * per-thread function-cache reset. */
static bool yx_function_only_module_output(const char *name)
{
    static const struct {
        const char *module;
        const char *descriptor;
    } modules[] = {{"console", "console.Console"}, {"hash", "hash.Hash"}, {"math", "math.Math"},
#ifdef XXYARA_ENABLE_MAGIC
                   {"magic", "magic.Magic"},
#endif
                   {"string", "string.String"},    {"time", "time.Time"}};
    for (size_t i = 0; i < sizeof(modules) / sizeof(*modules); ++i)
        if (strcmp(name, modules[i].module) == 0 || strcmp(name, modules[i].descriptor) == 0) return true;
    return false;
}

static const char *yx_module_output_import_name(const char *name)
{
    if (strcmp(name, "crx.Crx") == 0) return "crx";
    if (strcmp(name, "cuckoo.Cuckoo") == 0) return "cuckoo";
    if (strcmp(name, "dex.Dex") == 0) return "dex";
    if (strcmp(name, "dotnet.Dotnet") == 0) return "dotnet";
    if (strcmp(name, "elf.ELF") == 0) return "elf";
    if (strcmp(name, "macho.Macho") == 0) return "macho";
    if (strcmp(name, "lnk.Lnk") == 0) return "lnk";
#ifdef XXYARA_ENABLE_OLECF
    if (strcmp(name, "olecf.Olecf") == 0) return "olecf";
#endif
#ifdef XXYARA_ENABLE_VBA
    if (strcmp(name, "vba.Vba") == 0) return "vba";
#endif
#ifdef XXYARA_ENABLE_MSI
    if (strcmp(name, "msi.Msi") == 0) return "msi";
#endif
    if (strcmp(name, "pe.PE") == 0) return "pe";
    if (strcmp(name, "vt.titan.LiveHuntData") == 0) return "vt";
    if (strcmp(name, "zip.Zip") == 0) return "zip";
#ifdef XXYARA_ENABLE_TEST_PROTO
    if (strcmp(name, "test_proto2.TestProto2") == 0) return "test_proto2";
    if (strcmp(name, "test_proto3.TestProto3") == 0) return "test_proto3";
#endif
    return yx_known_module(name) ? name : NULL;
}

static bool yx_unused_module_output(const YRX_SCANNER *scanner, const char *module)
{
    static const char *const accepted[] = {"crx", "cuckoo", "dex", "dotnet", "elf", "lnk", "macho", "pe", "test_proto3", "vt", "zip"};
    bool empty_message_allowed = false;
    for (size_t i = 0; i < sizeof(accepted) / sizeof(*accepted); ++i)
        if (strcmp(module, accepted[i]) == 0) {
            empty_message_allowed = true;
            break;
        }
    if (!empty_message_allowed) return false;
    for (size_t i = 0; i < scanner->rules->import_count; ++i)
        if (strcmp(module, scanner->rules->imports[i]) == 0) {
            for (size_t j = 0; j < scanner->rules->rule_count; ++j)
                if (yx_condition_uses_module(scanner->rules->rules[j].condition, module)) return false;
            return true;
        }
    return true;
}

typedef enum yx_protobuf_error {
    YX_PROTOBUF_OK,
    YX_PROTOBUF_EOF,
    YX_PROTOBUF_TAG,
    YX_PROTOBUF_WIRE,
    YX_PROTOBUF_TRUNCATED,
    YX_PROTOBUF_VARINT,
    YX_PROTOBUF_LIMIT_INCREASE
} yx_protobuf_error;

static const char *yx_protobuf_error_text(yx_protobuf_error error)
{
    if (error == YX_PROTOBUF_EOF) return "Unexpected EOF";
    if (error == YX_PROTOBUF_WIRE) return "Unexpected wire type";
    if (error == YX_PROTOBUF_TRUNCATED) return "Truncated message";
    if (error == YX_PROTOBUF_VARINT) return "Incorrect varint";
    if (error == YX_PROTOBUF_LIMIT_INCREASE) return "New limit must not be greater than current limit";
    return "Incorrect tag";
}

static yx_protobuf_error yx_protobuf_varint(const uint8_t *data, size_t size, size_t *offset, uint64_t *value)
{
    size_t start = *offset;
    if (xx_protobuf_wire_varint(data, size, offset, value)) return YX_PROTOBUF_OK;
    return *offset == size && *offset - start < 10 ? YX_PROTOBUF_EOF : YX_PROTOBUF_VARINT;
}

static yx_protobuf_error yx_protobuf_length_varint(const uint8_t *data, size_t size, size_t *offset, uint64_t *value)
{
    size_t start = *offset;
    if (xx_protobuf_wire_varint32(data, size, offset, value)) return YX_PROTOBUF_OK;
    return *offset == size && *offset - start < 5 ? YX_PROTOBUF_EOF : YX_PROTOBUF_VARINT;
}

static yx_protobuf_error yx_protobuf_message(const uint8_t *data, size_t size, size_t *offset, uint32_t end_group, unsigned depth, bool nested_limit)
{
    /* YARA-X raises protobuf's recursion limit to 500 for module outputs. */
    if (depth > 500) return YX_PROTOBUF_TAG;
    while (*offset < size) {
        uint64_t key, length;
        uint32_t field;
        unsigned wire;
        size_t key_start = *offset;
        yx_protobuf_error result = yx_protobuf_varint(data, size, offset, &key);
        if (result == YX_PROTOBUF_EOF && *offset - key_start >= 5) result = YX_PROTOBUF_VARINT;
        if (result != YX_PROTOBUF_OK) return result;
        wire = (unsigned)(key & 7);
        if ((key >> 3) == 0) return YX_PROTOBUF_TAG;
        if (key >> 3 > 0x1fffffff) return YX_PROTOBUF_VARINT;
        field = (uint32_t)(key >> 3);
        if (wire == 4) return end_group != 0 ? YX_PROTOBUF_OK : YX_PROTOBUF_WIRE;
        switch (wire) {
            case 0:
                result = yx_protobuf_varint(data, size, offset, &length);
                if (result != YX_PROTOBUF_OK) return result;
                break;
            case 1:
                if (size - *offset < 8) return YX_PROTOBUF_EOF;
                *offset += 8;
                break;
            case 2:
                result = yx_protobuf_varint(data, size, offset, &length);
                if (result != YX_PROTOBUF_OK) return result;
                if (length > size - *offset) return nested_limit ? YX_PROTOBUF_TRUNCATED : YX_PROTOBUF_EOF;
                *offset += (size_t)length;
                break;
            case 3:
                result = yx_protobuf_message(data, size, offset, field, depth + 1, nested_limit);
                if (result != YX_PROTOBUF_OK) return result;
                break;
            case 5:
                if (size - *offset < 4) return YX_PROTOBUF_EOF;
                *offset += 4;
                break;
            default: return YX_PROTOBUF_TAG;
        }
    }
    return end_group == 0 ? YX_PROTOBUF_OK : YX_PROTOBUF_EOF;
}

static yx_protobuf_error yx_protobuf_validate(const uint8_t *data, size_t size)
{
    size_t offset = 0;
    return yx_protobuf_message(data, size, &offset, 0, 0, false);
}

static yx_protobuf_error yx_protobuf_validate_nested(const uint8_t *data, size_t size)
{
    size_t offset = 0;
    return yx_protobuf_message(data, size, &offset, 0, 0, true);
}

/* In the v1.21.0 root descriptors, fields numbered 100000 and above are
 * unknown. PE and LNK require a bool in field 1. Their validated root
 * subsets also support unimported outputs and narrow imported boolean
 * conditions. */
typedef enum yx_protobuf_root_failure {
    YX_ROOT_FAILURE_NONE,
    YX_ROOT_FAILURE_I32,
    YX_ROOT_FAILURE_NESTED,
    YX_ROOT_FAILURE_VARINT,
    YX_ROOT_FAILURE_UTF8,
    YX_ROOT_FAILURE_KEY_VALUE_MISSING,
    YX_ROOT_FAILURE_SECTION_MISSING,
    YX_ROOT_FAILURE_DIR_ENTRY_MISSING,
    YX_ROOT_FAILURE_RESOURCE_MISSING,
    YX_ROOT_FAILURE_IMPORT_MISSING,
    YX_ROOT_FAILURE_EXPORT_MISSING,
    YX_ROOT_FAILURE_FUNCTION_MISSING,
    YX_ROOT_FAILURE_RICH_TOOL_MISSING,
    YX_ROOT_FAILURE_CRX_SIGNATURE_MISSING
} yx_protobuf_root_failure;

typedef struct yx_protobuf_root_state {
    bool required_present;
    bool required_value;
    int64_t i32_overflow_value;
    bool nested_missing;
    bool overlay_present;
    bool overlay_complete;
    bool rich_present;
    bool rich_complete;
    bool version_present[5];
    bool version_complete[5];
    bool dex_header_present[27];
    uint32_t dex_header_values[27];
    bool dex_map_size_present;
    uint32_t dex_map_size;
    size_t dex_collection_counts[10];
    bool dex_map_list_present;
    const uint8_t *dex_header_signature;
    size_t dex_header_signature_length;
    bool dex_header_signature_present;
    yx_protobuf_error nested_error;
    yx_protobuf_root_failure first_failure;
} yx_protobuf_root_state;

static bool yx_pe_version_fields(const uint8_t *data, size_t size, unsigned version_index, yx_protobuf_root_state *state)
{
    size_t at = 0;
    bool major = false, minor = false;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        unsigned wire;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        wire = (unsigned)(key & 7);
        switch (wire) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (field == 1 || field == 2) {
                    if (field == 1) major = true;
                    else minor = true;
                    if (value > UINT32_MAX && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_VARINT;
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                at += (size_t)value;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    state->version_present[version_index] = true;
    state->version_complete[version_index] = major && minor;
    return true;
}

static bool yx_pe_key_value_fields(const uint8_t *data, size_t size, bool required, yx_protobuf_root_state *state)
{
    size_t at = 0;
    bool key_present = false, value_present = false;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, length;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &length) != YX_PROTOBUF_OK) return false;
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &length) != YX_PROTOBUF_OK || length > size - at) return false;
                if (field == 1 || field == 2) {
                    if (field == 1) key_present = true;
                    else value_present = true;
                    if (!yx_valid_utf8_bytes((const char *)(data + at), (size_t)length) && state->first_failure == YX_ROOT_FAILURE_NONE)
                        state->first_failure = YX_ROOT_FAILURE_UTF8;
                }
                at += (size_t)length;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    if (required && (!key_present || !value_present) && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_KEY_VALUE_MISSING;
    return true;
}

static yx_protobuf_error yx_crx_signature_message(const uint8_t *data, size_t size, uint64_t logical_size, size_t *at, uint32_t end_group, unsigned depth)
{
    if (depth > 500) return YX_PROTOBUF_TAG;
    while (*at < size) {
        uint64_t key, length;
        size_t key_at = *at;
        yx_protobuf_error error = yx_protobuf_varint(data, size, at, &key);
        if (error == YX_PROTOBUF_EOF && *at - key_at >= 5) error = YX_PROTOBUF_VARINT;
        if (error != YX_PROTOBUF_OK) return error;
        if ((key >> 3) == 0) return YX_PROTOBUF_TAG;
        if ((key >> 3) > 0x1fffffff) return YX_PROTOBUF_VARINT;
        if ((key & 7) == 4) return end_group ? YX_PROTOBUF_OK : YX_PROTOBUF_WIRE;
        switch (key & 7) {
            case 0:
                error = yx_protobuf_varint(data, size, at, &length);
                if (error != YX_PROTOBUF_OK) return error;
                break;
            case 1:
                if (size - *at < 8) return YX_PROTOBUF_EOF;
                *at += 8;
                break;
            case 2:
                error = yx_protobuf_length_varint(data, size, at, &length);
                if (error != YX_PROTOBUF_OK) return error;
                if (length > logical_size - *at) return YX_PROTOBUF_TRUNCATED;
                if (length > size - *at) return YX_PROTOBUF_EOF;
                *at += (size_t)length;
                break;
            case 3:
                error = yx_crx_signature_message(data, size, logical_size, at, (uint32_t)(key >> 3), depth + 1);
                if (error != YX_PROTOBUF_OK) return error;
                break;
            case 5:
                if (size - *at < 4) return YX_PROTOBUF_EOF;
                *at += 4;
                break;
            default: return YX_PROTOBUF_TAG;
        }
    }
    return end_group ? YX_PROTOBUF_EOF : YX_PROTOBUF_OK;
}

static bool yx_crx_signature_fields(const uint8_t *data, size_t size, uint64_t logical_size, yx_protobuf_root_state *state)
{
    size_t at = 0;
    unsigned present = 0;
    size_t validated = 0;
    yx_protobuf_error error = yx_crx_signature_message(data, size, logical_size, &validated, 0, 0);
    if (error != YX_PROTOBUF_OK) {
        /* The generated decoder checks each string as it reaches it, before
         * a malformed field later in the same signature. */
        size_t scan = 0;
        while (scan < size && state->first_failure == YX_ROOT_FAILURE_NONE) {
            uint64_t key, length;
            if (yx_protobuf_varint(data, size, &scan, &key) != YX_PROTOBUF_OK || (key >> 3) == 0 || (key >> 3) > 0x1fffffff) break;
            switch (key & 7) {
                case 0:
                    if (yx_protobuf_varint(data, size, &scan, &length) != YX_PROTOBUF_OK) scan = size;
                    break;
                case 1:
                    if (size - scan < 8) scan = size;
                    else scan += 8;
                    break;
                case 2:
                    if (yx_protobuf_length_varint(data, size, &scan, &length) != YX_PROTOBUF_OK || length > size - scan) {
                        scan = size;
                        break;
                    }
                    if ((key >> 3) == 1 && !yx_valid_utf8_bytes((const char *)(data + scan), (size_t)length)) state->first_failure = YX_ROOT_FAILURE_UTF8;
                    scan += (size_t)length;
                    break;
                case 3:
                    if (yx_protobuf_message(data, size, &scan, (uint32_t)(key >> 3), 1, true) != YX_PROTOBUF_OK) scan = size;
                    break;
                case 5:
                    if (size - scan < 4) scan = size;
                    else scan += 4;
                    break;
                default: scan = size; break;
            }
        }
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (field == 2) present |= 2u;
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (field == 1) {
                    present |= 1u;
                    if (!yx_valid_utf8_bytes((const char *)(data + at), (size_t)value) && state->first_failure == YX_ROOT_FAILURE_NONE)
                        state->first_failure = YX_ROOT_FAILURE_UTF8;
                }
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    if (present != 3u && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_CRX_SIGNATURE_MISSING;
    return true;
}

static bool yx_zip_entry_fields(const uint8_t *data, size_t size, yx_protobuf_root_state *state)
{
    size_t at = 0;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (field == 2 && state->first_failure == YX_ROOT_FAILURE_NONE) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        state->first_failure = YX_ROOT_FAILURE_I32;
                        state->i32_overflow_value = signed_value;
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (field == 1 && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value) && state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_UTF8;
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return true;
}

typedef enum yx_dex_field_type {
    YX_DEX_UNKNOWN,
    YX_DEX_BOOL,
    YX_DEX_U32,
    YX_DEX_I32,
    YX_DEX_STRING,
    YX_DEX_MESSAGE
} yx_dex_field_type;

/* Message kinds: Dex, DexHeader, ProtoItem, FieldItem, MethodItem,
 * ClassItem, MapList, and MapItem. */
static yx_dex_field_type yx_dex_record_field_type(unsigned kind, uint64_t field, unsigned *child_kind)
{
    switch (kind) {
        case 0:
            if (field == 1) return YX_DEX_BOOL;
            if (field == 3 || field == 4) return YX_DEX_STRING;
            if (field == 2 || (field >= 5 && field <= 9)) {
                *child_kind = field == 2 ? 1u : field == 5 ? 2u : field == 6 ? 3u : field == 7 ? 4u : field == 8 ? 5u : 6u;
                return YX_DEX_MESSAGE;
            }
            break;
        case 1:
            if (field == 4) return YX_DEX_STRING;
            if ((field >= 1 && field <= 9) || (field >= 23 && field <= 26)) return YX_DEX_U32;
            break;
        case 2:
            if (field == 1 || field == 2 || field == 4) return YX_DEX_STRING;
            if (field == 3) return YX_DEX_U32;
            break;
        case 3:
            if (field >= 1 && field <= 3) return YX_DEX_STRING;
            break;
        case 4:
            if (field == 1 || field == 3) return YX_DEX_STRING;
            if (field == 2) {
                *child_kind = 2u;
                return YX_DEX_MESSAGE;
            }
            break;
        case 5:
            if (field == 1 || field == 3 || field == 4) return YX_DEX_STRING;
            if (field == 2) return YX_DEX_U32;
            break;
        case 6:
            if (field == 1) return YX_DEX_U32;
            if (field == 2) {
                *child_kind = 7u;
                return YX_DEX_MESSAGE;
            }
            break;
        case 7:
            if (field == 1) return YX_DEX_I32;
            if (field >= 2 && field <= 4) return YX_DEX_U32;
            break;
    }
    return YX_DEX_UNKNOWN;
}

static yx_protobuf_error yx_dex_group_fields(const uint8_t *data, size_t size, size_t *offset, uint32_t end_group, unsigned depth, uint64_t logical_size)
{
    if (depth > 500) return YX_PROTOBUF_TAG;
    while (*offset < size) {
        uint64_t key, length;
        uint32_t field;
        unsigned wire;
        size_t key_start = *offset;
        yx_protobuf_error error = yx_protobuf_varint(data, size, offset, &key);
        if (error == YX_PROTOBUF_EOF && *offset - key_start >= 5) error = YX_PROTOBUF_VARINT;
        if (error != YX_PROTOBUF_OK) return error;
        field = (uint32_t)(key >> 3);
        wire = (unsigned)(key & 7);
        if (field == 0) return YX_PROTOBUF_TAG;
        if (key >> 3 > 0x1fffffff) return YX_PROTOBUF_VARINT;
        if (wire == 4) return end_group != 0 ? YX_PROTOBUF_OK : YX_PROTOBUF_WIRE;
        switch (wire) {
            case 0:
                error = yx_protobuf_varint(data, size, offset, &length);
                if (error != YX_PROTOBUF_OK) return error;
                break;
            case 1:
                if (size - *offset < 8) return YX_PROTOBUF_EOF;
                *offset += 8;
                break;
            case 2:
                error = yx_protobuf_length_varint(data, size, offset, &length);
                if (error != YX_PROTOBUF_OK) return error;
                if (length > logical_size - *offset) return YX_PROTOBUF_TRUNCATED;
                if (length > size - *offset) return YX_PROTOBUF_EOF;
                *offset += (size_t)length;
                break;
            case 3:
                error = yx_dex_group_fields(data, size, offset, field, depth + 1, logical_size);
                if (error != YX_PROTOBUF_OK) return error;
                break;
            case 5:
                if (size - *offset < 4) return YX_PROTOBUF_EOF;
                *offset += 4;
                break;
            default: return YX_PROTOBUF_TAG;
        }
    }
    return YX_PROTOBUF_EOF;
}

static bool yx_dex_record_fields(const uint8_t *data, size_t size, uint64_t logical_size, unsigned kind, yx_protobuf_root_state *state)
{
    size_t at = 0;
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        unsigned child_kind = 0;
        yx_dex_field_type type;
        {
            size_t key_start = at;
            yx_protobuf_error error = yx_protobuf_varint(data, size, &at, &key);
            if (error == YX_PROTOBUF_EOF && at - key_start >= 5) error = YX_PROTOBUF_VARINT;
            if (error != YX_PROTOBUF_OK) {
                if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                    state->first_failure = YX_ROOT_FAILURE_NESTED;
                    state->nested_error = error;
                }
                return false;
            }
        }
        field = key >> 3;
        if (field == 0 || field > 0x1fffffff) {
            if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                state->first_failure = YX_ROOT_FAILURE_NESTED;
                state->nested_error = field == 0 ? YX_PROTOBUF_TAG : YX_PROTOBUF_VARINT;
            }
            return false;
        }
        type = yx_dex_record_field_type(kind, field, &child_kind);
        switch (key & 7) {
            case 0: {
                yx_protobuf_error error = yx_protobuf_varint(data, size, &at, &value);
                if (error != YX_PROTOBUF_OK) {
                    if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = error;
                    }
                    return false;
                }
            }
                if (kind == 0 && field == 1) {
                    state->required_present = true;
                    state->required_value = value != 0;
                }
                if (kind == 1 && field < 27 && type == YX_DEX_U32 && value <= UINT32_MAX) {
                    state->dex_header_present[field] = true;
                    state->dex_header_values[field] = (uint32_t)value;
                }
                if (kind == 6 && field == 1 && value <= UINT32_MAX) {
                    state->dex_map_size_present = true;
                    state->dex_map_size = (uint32_t)value;
                }
                if (type == YX_DEX_U32 && value > UINT32_MAX && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_VARINT;
                if (type == YX_DEX_I32 && state->first_failure == YX_ROOT_FAILURE_NONE) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        state->first_failure = YX_ROOT_FAILURE_I32;
                        state->i32_overflow_value = signed_value;
                    }
                }
                break;
            case 1:
                if (size - at < 8) {
                    if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = YX_PROTOBUF_EOF;
                    }
                    return false;
                }
                at += 8;
                break;
            case 2: {
                yx_protobuf_error error = type == YX_DEX_MESSAGE ? yx_protobuf_varint(data, size, &at, &value) : yx_protobuf_length_varint(data, size, &at, &value);
                if (error != YX_PROTOBUF_OK) {
                    if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = error;
                    }
                    return false;
                }
            }
                if (type == YX_DEX_MESSAGE && value > logical_size - at) {
                    if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = YX_PROTOBUF_LIMIT_INCREASE;
                    }
                    return true;
                }
                uint64_t declared_length = value;
                if (value > size - at) {
                    if (type == YX_DEX_MESSAGE) {
                        value = size - at;
                    } else {
                        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                            state->first_failure = YX_ROOT_FAILURE_NESTED;
                            /* Protobuf streams large byte fields in chunks. */
                            state->nested_error = value > logical_size - at || value >= 10000000u ? YX_PROTOBUF_TRUNCATED : YX_PROTOBUF_EOF;
                        }
                        return true;
                    }
                }
                if (kind == 0 && field >= 3 && field <= 8 && type != YX_DEX_UNKNOWN) ++state->dex_collection_counts[field];
                if (kind == 0 && field == 9 && type == YX_DEX_MESSAGE) state->dex_map_list_present = true;
                if (kind == 6 && field == 2 && type == YX_DEX_MESSAGE) ++state->dex_collection_counts[9];
                if (kind == 0 && field == 2 && type == YX_DEX_MESSAGE) {
                    memset(state->dex_header_present, 0, sizeof(state->dex_header_present));
                    memset(state->dex_header_values, 0, sizeof(state->dex_header_values));
                    state->dex_header_signature = NULL;
                    state->dex_header_signature_length = 0;
                    state->dex_header_signature_present = false;
                }
                if (kind == 0 && field == 9 && type == YX_DEX_MESSAGE) {
                    state->dex_map_size_present = false;
                    state->dex_map_size = 0;
                    state->dex_collection_counts[9] = 0;
                }
                if (kind == 1 && field == 4 && type == YX_DEX_STRING) {
                    state->dex_header_signature = data + at;
                    state->dex_header_signature_length = (size_t)value;
                    state->dex_header_signature_present = true;
                }
                if (type == YX_DEX_STRING && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value) && state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_UTF8;
                if (type == YX_DEX_MESSAGE) {
                    if (!yx_dex_record_fields(data + at, (size_t)value, declared_length, child_kind, state)) {
                        return false;
                    }
                }
                at += (size_t)value;
                break;
            case 3: {
                yx_protobuf_error group_error = yx_dex_group_fields(data, size, &at, (uint32_t)field, 1, logical_size);
                if (group_error != YX_PROTOBUF_OK) {
                    if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = group_error;
                    }
                    return true;
                }
            } break;
            case 5:
                if (size - at < 4) {
                    if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = YX_PROTOBUF_EOF;
                    }
                    return false;
                }
                at += 4;
                break;
            default:
                if (state->first_failure == YX_ROOT_FAILURE_NONE) {
                    state->first_failure = YX_ROOT_FAILURE_NESTED;
                    state->nested_error = (key & 7) == 4 ? YX_PROTOBUF_WIRE : YX_PROTOBUF_TAG;
                }
                return false;
        }
    }
    return true;
}

bool yx_dex_output_root_string_at(const uint8_t *data, size_t size, unsigned field, uint64_t index, const uint8_t **bytes, size_t *length)
{
    size_t at = 0;
    bool found = false;
    if (!data || !bytes || !length) return false;
    while (at < size) {
        uint64_t key, value;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (value > size - at) value = size - at;
                if (key >> 3 == field) {
                    bool last = index == UINT64_MAX;
                    if (last || index-- == 0) {
                        *bytes = data + at;
                        *length = (size_t)value;
                        if (!last) return true;
                        found = true;
                    }
                }
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)(key >> 3), 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return found;
}

bool yx_dex_output_record_string_at(const uint8_t *data, size_t size, unsigned root_field, uint64_t index, unsigned record_field, const uint8_t **bytes, size_t *length)
{
    const uint8_t *record;
    size_t record_length;
    return yx_dex_output_root_string_at(data, size, root_field, index, &record, &record_length) &&
           yx_dex_output_root_string_at(record, record_length, record_field, UINT64_MAX, bytes, length);
}

bool yx_dex_output_record_numeric_at(const uint8_t *data, size_t size, unsigned root_field, uint64_t index, unsigned record_field, bool signed_enum, uint64_t *value)
{
    const uint8_t *record;
    size_t record_length, at = 0;
    bool found = false;
    if (!value || !yx_dex_output_root_string_at(data, size, root_field, index, &record, &record_length)) return false;
    while (at < record_length) {
        uint64_t key, number;
        if (yx_protobuf_varint(record, record_length, &at, &key) != YX_PROTOBUF_OK) return false;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(record, record_length, &at, &number) != YX_PROTOBUF_OK) return false;
                if (key >> 3 == record_field) {
                    if (signed_enum) {
                        int64_t signed_value = number <= INT64_MAX ? (int64_t)number : -(int64_t)(UINT64_MAX - number) - 1;
                        if (signed_value >= INT32_MIN && signed_value <= INT32_MAX) {
                            *value = (uint64_t)signed_value;
                            found = true;
                        }
                    } else if (number <= UINT32_MAX) {
                        *value = number;
                        found = true;
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(record, record_length, &at, &number) != YX_PROTOBUF_OK) return false;
                if (number > record_length - at) number = record_length - at;
                at += (size_t)number;
                break;
            case 3:
                if (yx_protobuf_message(record, record_length, &at, (uint32_t)(key >> 3), 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return found;
}

bool yx_dex_output_map_item_numeric_at(const uint8_t *data, size_t size, uint64_t index, unsigned item_field, bool signed_enum, uint64_t *value)
{
    const uint8_t *map;
    size_t map_length;
    return yx_dex_output_root_string_at(data, size, 9, UINT64_MAX, &map, &map_length) &&
           yx_dex_output_record_numeric_at(map, map_length, 2, index, item_field, signed_enum, value);
}

static bool yx_pe_required_record_fields(const uint8_t *data, size_t size, unsigned record_kind, yx_protobuf_root_state *state)
{
    size_t at = 0;
    uint32_t present = 0;
    uint32_t required = record_kind == 1 ? 0x7ffu : 0x3u;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if ((record_kind != 1 && field >= 1 && field <= 2) || (record_kind == 1 && field >= 3 && field <= 11) ||
                    (record_kind == 2 && (field == 3 || field == 5 || field == 6))) {
                    if ((record_kind != 2 || field <= 2) && field <= 11) present |= 1u << (field - 1);
                    if (value > UINT32_MAX && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_VARINT;
                }
                if (record_kind == 2 && field == 4 && state->first_failure == YX_ROOT_FAILURE_NONE) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        state->first_failure = YX_ROOT_FAILURE_I32;
                        state->i32_overflow_value = signed_value;
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (record_kind == 1 && field >= 1 && field <= 2) present |= 1u << (field - 1);
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    if ((present & required) != required && state->first_failure == YX_ROOT_FAILURE_NONE)
        state->first_failure = record_kind == 1   ? YX_ROOT_FAILURE_SECTION_MISSING
                               : record_kind == 2 ? YX_ROOT_FAILURE_RESOURCE_MISSING
                                                  : YX_ROOT_FAILURE_DIR_ENTRY_MISSING;
    return true;
}

/* Import and Export each contain a small nested record. A decoded Function
 * has its own required RVA, so validate it before accepting the Import. */
static bool yx_pe_symbol_record_fields(const uint8_t *data, size_t size, unsigned record_kind, yx_protobuf_root_state *state)
{
    size_t at = 0;
    unsigned present = 0;
    unsigned required = record_kind == 0 ? 0x3u : record_kind == 1 ? 0x6u : 0x4u;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if ((record_kind == 0 && field == 2) || (record_kind == 1 && (field == 2 || field == 3)) || (record_kind == 2 && field == 3))
                    present |= 1u << (field - 1);
                if (((record_kind == 1 && field >= 2 && field <= 4) || (record_kind == 2 && (field == 2 || field == 3))) && value > UINT32_MAX &&
                    state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_VARINT;
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if ((record_kind == 0 && field == 1) || (record_kind == 1 && (field == 1 || field == 5)) || (record_kind == 2 && field == 1)) {
                    if (record_kind == 0 && field == 1) present |= 1u;
                    if (!yx_valid_utf8_bytes((const char *)(data + at), (size_t)value) && state->first_failure == YX_ROOT_FAILURE_NONE)
                        state->first_failure = YX_ROOT_FAILURE_UTF8;
                }
                if (record_kind == 0 && field == 3 && !yx_pe_symbol_record_fields(data + at, (size_t)value, 2u, state)) return false;
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    if ((present & required) != required && state->first_failure == YX_ROOT_FAILURE_NONE)
        state->first_failure = record_kind == 0 ? YX_ROOT_FAILURE_IMPORT_MISSING : record_kind == 1 ? YX_ROOT_FAILURE_EXPORT_MISSING : YX_ROOT_FAILURE_FUNCTION_MISSING;
    return true;
}

static bool yx_pe_rich_fields(const uint8_t *data, size_t size, bool tool, yx_protobuf_root_state *state)
{
    size_t at = 0;
    unsigned present = 0;
    unsigned required = tool ? 0x7u : 0x1fu;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (field >= 1 && field <= 3) {
                    present |= 1u << (field - 1);
                    if (value > UINT32_MAX && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_VARINT;
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (!tool && (field == 4 || field == 5)) present |= 1u << (field - 1);
                if (!tool && field == 6 && !yx_pe_rich_fields(data + at, (size_t)value, true, state)) return false;
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    if (tool) {
        if ((present & required) != required && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_RICH_TOOL_MISSING;
    } else {
        state->rich_present = true;
        state->rich_complete = (present & required) == required;
    }
    return true;
}

/* Signature, SignerInfo, Certificate, and CounterSignature have no required
 * fields, but their string fields still need protobuf UTF-8 validation. */
static bool yx_pe_signature_fields(const uint8_t *data, size_t size, unsigned record_kind, yx_protobuf_root_state *state)
{
    size_t at = 0;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                break;
            case 1: at += 8; break;
            case 2: {
                bool string_field = record_kind == 0   ? (field >= 1 && field <= 3) || (field >= 5 && field <= 7) || (field >= 11 && field <= 13)
                                    : record_kind == 1 ? field >= 1 && field <= 4
                                    : record_kind == 2 ? (field >= 1 && field <= 3) || (field >= 5 && field <= 7)
                                                       : field == 3 || field == 12;
                unsigned child_kind = 0;
                bool nested_field = false;
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (string_field && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value) && state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_UTF8;
                if (record_kind == 0) {
                    nested_field = field >= 16 && field <= 18;
                    child_kind = field == 16 ? 1u : field == 17 ? 2u : 3u;
                } else if (record_kind == 1 && field == 5) {
                    nested_field = true;
                    child_kind = 2u;
                } else if (record_kind == 3 && field == 4) {
                    nested_field = true;
                    child_kind = 2u;
                }
                if (nested_field && !yx_pe_signature_fields(data + at, (size_t)value, child_kind, state)) return false;
                at += (size_t)value;
                break;
            }
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return true;
}

static bool yx_pe_overlay_fields(const uint8_t *data, size_t size, yx_protobuf_root_state *state)
{
    size_t at = 0;
    unsigned present = 0;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (field == 1 || field == 2) present |= 1u << (field - 1);
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    state->overlay_present = true;
    state->overlay_complete = present == 3;
    return true;
}

static bool yx_pe_root_i32(uint64_t field)
{
    return field == 2 || field == 3 || field == 8;
}

static bool yx_pe_root_u32(uint64_t field)
{
    return field == 9 || field == 10 || field == 11 || (field >= 13 && field <= 17) || (field >= 19 && field <= 28) || (field >= 33 && field <= 37);
}

static bool yx_crx_root_u32(uint64_t field)
{
    return field == 2 || field == 3;
}

static bool yx_crx_root_string(uint64_t field)
{
    return field == 4 || (field >= 5 && field <= 14) || field == 16;
}

static bool yx_lnk_root_i32(uint64_t field)
{
    return field == 10 || field == 11;
}

static bool yx_lnk_root_u32(uint64_t field)
{
    return field == 6 || field == 7 || field == 9 || field == 12;
}

static bool yx_lnk_root_string(uint64_t field)
{
    return field == 2 || field == 8 || (field >= 13 && field <= 18);
}

static bool yx_lnk_nested_fields(const uint8_t *data, size_t size, bool shell_item, yx_protobuf_root_state *state)
{
    size_t at = 0;
    yx_protobuf_error error = yx_protobuf_validate_nested(data, size);
    if (error != YX_PROTOBUF_OK) {
        if (state->first_failure == YX_ROOT_FAILURE_NONE) {
            state->first_failure = YX_ROOT_FAILURE_NESTED;
            state->nested_error = error;
        }
        return true;
    }
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (field == 1 && state->first_failure == YX_ROOT_FAILURE_NONE) {
                    if (!shell_item && value > UINT32_MAX) state->first_failure = YX_ROOT_FAILURE_VARINT;
                    if (shell_item) {
                        int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                        if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                            state->first_failure = YX_ROOT_FAILURE_I32;
                            state->i32_overflow_value = signed_value;
                        }
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (((!shell_item && field >= 2 && field <= 6) || (shell_item && field >= 4 && field <= 9)) &&
                    !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value) && state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_UTF8;
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return true;
}

/* Look for the first oversized length varint inside an unknown CRX group.
 * Other malformed fields stop the probe and keep the generic error. */
static int yx_crx_group_length_error(const uint8_t *data, size_t size, size_t *at, unsigned depth)
{
    if (depth > 500) return -1;
    while (*at < size) {
        uint64_t key, value;
        yx_protobuf_error error = yx_protobuf_varint(data, size, at, &key);
        if (error != YX_PROTOBUF_OK || (key >> 3) == 0 || (key >> 3) > 0x1fffffff) return -1;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, at, &value) != YX_PROTOBUF_OK) return -1;
                break;
            case 1:
                if (size - *at < 8) return -1;
                *at += 8;
                break;
            case 2:
                error = yx_protobuf_length_varint(data, size, at, &value);
                if (error == YX_PROTOBUF_VARINT) return 1;
                if (error != YX_PROTOBUF_OK || value > size - *at) return -1;
                *at += (size_t)value;
                break;
            case 3: {
                int nested = yx_crx_group_length_error(data, size, at, depth + 1);
                if (nested != 0) return nested;
                break;
            }
            case 4: return 0;
            case 5:
                if (size - *at < 4) return -1;
                *at += 4;
                break;
            default: return -1;
        }
    }
    return -1;
}

static bool yx_protobuf_simple_root_fields(const uint8_t *data, size_t size, unsigned root_kind, yx_protobuf_root_state *state)
{
    size_t at = 0;
    if (state) memset(state, 0, sizeof(*state));
    while (at < size) {
        uint64_t key, length;
        uint64_t field;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK || (root_kind == 0 && (key >> 3) < 100000) || (root_kind == 5 && (key >> 3) < 64)) return false;
        field = key >> 3;
        if (root_kind == 3 && (field == 0 || field > 0x1fffffff)) return false;
        if (root_kind && field == 1 && (key & 7) == 0 && state) state->required_present = true;
        switch (key & 7) {
            case 0: {
                size_t value_at = at;
                yx_protobuf_error value_error = yx_protobuf_varint(data, size, &at, &length);
                if (value_error != YX_PROTOBUF_OK) {
                    if (root_kind == 3 && yx_crx_root_u32(field) && state && state->first_failure == YX_ROOT_FAILURE_NONE &&
                        (value_error == YX_PROTOBUF_VARINT || (value_error == YX_PROTOBUF_EOF && at - value_at >= 5)))
                        state->first_failure = YX_ROOT_FAILURE_VARINT;
                    return false;
                }
                if (root_kind && field == 1 && state) state->required_value = length != 0;
                if (((root_kind == 1 && yx_pe_root_i32(field)) || (root_kind == 2 && yx_lnk_root_i32(field))) && state) {
                    int64_t signed_value = length <= INT64_MAX ? (int64_t)length : -(int64_t)(UINT64_MAX - length) - 1;
                    if ((signed_value < INT32_MIN || signed_value > INT32_MAX) && state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_I32;
                        state->i32_overflow_value = signed_value;
                    }
                }
                if (((root_kind == 1 && yx_pe_root_u32(field)) || (root_kind == 2 && yx_lnk_root_u32(field)) || (root_kind == 3 && yx_crx_root_u32(field))) && state &&
                    length > UINT32_MAX && state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_VARINT;
                break;
            }
            case 1:
                if (size - at < 8) return false;
                at += 8;
                break;
            case 2:
                if (root_kind == 3) {
                    yx_protobuf_error length_error = yx_protobuf_length_varint(data, size, &at, &length);
                    if (length_error != YX_PROTOBUF_OK) {
                        if (length_error == YX_PROTOBUF_VARINT && state && state->first_failure == YX_ROOT_FAILURE_NONE) state->first_failure = YX_ROOT_FAILURE_VARINT;
                        return false;
                    }
                } else if (yx_protobuf_varint(data, size, &at, &length) != YX_PROTOBUF_OK) {
                    return false;
                }
                if (length > size - at) {
                    if (root_kind == 3 && field == 15 && state) (void)yx_crx_signature_fields(data + at, size - at, length, state);
                    else if (root_kind == 3 && length >= UINT64_C(10000000) && state && state->first_failure == YX_ROOT_FAILURE_NONE) {
                        state->first_failure = YX_ROOT_FAILURE_NESTED;
                        state->nested_error = YX_PROTOBUF_TRUNCATED;
                    }
                    return false;
                }
                if (root_kind == 1 && ((field >= 4 && field <= 7) || field == 53) && state &&
                    !yx_pe_version_fields(data + at, (size_t)length, field == 53 ? 4u : (unsigned)(field - 4), state))
                    return false;
                if (root_kind == 1 && (field == 46 || field == 47) && state && !yx_pe_key_value_fields(data + at, (size_t)length, field == 47, state)) return false;
                if (root_kind == 1 && field == 48 && state && !yx_pe_rich_fields(data + at, (size_t)length, false, state)) return false;
                if (root_kind == 1 && (field == 50 || field == 51 || field == 54) && state &&
                    !yx_pe_required_record_fields(data + at, (size_t)length,
                                                  field == 50   ? 1u
                                                  : field == 54 ? 2u
                                                                : 0u,
                                                  state))
                    return false;
                if (root_kind == 1 && (field == 55 || field == 56 || field == 57) && state &&
                    !yx_pe_symbol_record_fields(data + at, (size_t)length, field == 57 ? 1u : 0u, state))
                    return false;
                if (root_kind == 1 && field == 59 && state && !yx_pe_signature_fields(data + at, (size_t)length, 0u, state)) return false;
                if (root_kind == 1 && field == 60 && state && !yx_pe_overlay_fields(data + at, (size_t)length, state)) return false;
                if (root_kind == 2 && (field == 21 || field == 22) && state && !yx_lnk_nested_fields(data + at, (size_t)length, field == 22, state)) return false;
                if (root_kind == 3 && field == 15 && state && !yx_crx_signature_fields(data + at, (size_t)length, length, state)) return false;
                if (root_kind == 4 && field == 2 && state && !yx_zip_entry_fields(data + at, (size_t)length, state)) return false;
                if (((root_kind == 1 && field == 18) || (root_kind == 2 && yx_lnk_root_string(field)) || (root_kind == 3 && yx_crx_root_string(field))) && state &&
                    !yx_valid_utf8_bytes((const char *)(data + at), (size_t)length) && state->first_failure == YX_ROOT_FAILURE_NONE)
                    state->first_failure = YX_ROOT_FAILURE_UTF8;
                at += (size_t)length;
                break;
            case 3:
                if (root_kind == 3 && state && state->first_failure == YX_ROOT_FAILURE_NONE) {
                    size_t probe = at;
                    if (yx_crx_group_length_error(data, size, &probe, 1) == 1) state->first_failure = YX_ROOT_FAILURE_VARINT;
                }
                if (yx_protobuf_message(data, size, &at, (uint32_t)field, 1, false) != YX_PROTOBUF_OK) return false;
                break;
            case 5:
                if (size - at < 4) return false;
                at += 4;
                break;
            default: return false;
        }
    }
    if (root_kind == 1 && state)
        for (size_t i = 0; i < 5; ++i)
            if (state->version_present[i] && !state->version_complete[i]) state->nested_missing = true;
    if (root_kind == 1 && state && state->overlay_present && !state->overlay_complete) state->nested_missing = true;
    if (root_kind == 1 && state && state->rich_present && !state->rich_complete) state->nested_missing = true;
    return true;
}

typedef enum yx_scalar_root_type {
    YX_ROOT_NONE,
    YX_ROOT_BOOL,
    YX_ROOT_U32,
    YX_ROOT_U64,
    YX_ROOT_I32,
    YX_ROOT_SINT32,
    YX_ROOT_STRING,
    YX_ROOT_MESSAGE,
    YX_ROOT_MESSAGE_GUARDED,
    YX_ROOT_UNKNOWN
} yx_scalar_root_type;

typedef enum yx_scalar_root_error {
    YX_ROOT_ERROR_NONE,
    YX_ROOT_ERROR_VARINT,
    YX_ROOT_ERROR_I32,
    YX_ROOT_ERROR_UTF8,
    YX_ROOT_ERROR_EOF,
    YX_ROOT_ERROR_TAG,
    YX_ROOT_ERROR_NESTED,
    YX_ROOT_ERROR_MISSING
} yx_scalar_root_error;

typedef struct yx_scalar_root_result {
    yx_scalar_root_error error;
    int64_t overflow_value;
    yx_protobuf_error nested_error;
    const char *missing_message;
} yx_scalar_root_result;

/* Field numbers from YARA-X 1.21.0's LiveHuntData children. Protobuf skips a
 * known field with the wrong wire type just as it skips an unknown field. Keep
 * correctly typed nested records guarded until their schemas are checked. */
static bool yx_vt_nested_field_wire(uint64_t parent, uint64_t field, unsigned *wire)
{
    if (parent == 1) { /* FileMetadata */
        if ((field >= 1 && field <= 7) || field == 12 || field == 13 || field == 15 || field == 18 || field == 19 || field == 20 || field == 25 || field == 26 ||
            field == 27 || field == 28 || field == 30 || field == 31 || field == 32 || field == 36) {
            *wire = 2;
            return true;
        }
        if (field == 8 || field == 9 || field == 10 || field == 11 || field == 16 || field == 17 || field == 22) {
            *wire = 0;
            return true;
        }
    } else if (parent == 2) { /* BehaviourSummary */
        if ((field >= 1 && field <= 7) || (field >= 9 && field <= 52) || field == 55 || field == 56 || (field >= 57 && field <= 60) || field == 64 || field == 65 ||
            (field >= 68 && field <= 72) || field == 74 || field == 75 || field == 84) {
            *wire = 2;
            return true;
        }
        if (field == 61) {
            *wire = 0;
            return true;
        }
    } else if (parent == 3 && field >= 1 && field <= 3) {
        *wire = 2; /* EnrichedNetloc */
        return true;
    }
    return false;
}

static bool yx_vt_nested_string_field(uint64_t parent, uint64_t field)
{
    if (parent == 1) /* FileMetadata */
        return (field >= 1 && field <= 7) || field == 12 || field == 19 || field == 20 || field == 27 || field == 30 || field == 31;
    if (parent == 2) /* BehaviourSummary */
        return (field >= 1 && field <= 3) || field == 5 || field == 7 || (field >= 9 && field <= 21) || (field >= 23 && field <= 36) || field == 38 || field == 40 ||
               field == 41 || field == 43 || field == 45 || field == 47 || field == 55 || field == 56 || (field >= 57 && field <= 60) || field == 65;
    return false;
}

static bool yx_vt_netloc_string_field(uint64_t kind, uint64_t field)
{
    if (kind == 1) /* EnrichedURL */
        return field == 9 || field == 10 || field == 11 || field == 24 || field == 34 || (field >= 26 && field <= 28) || field == 49 || field == 51;
    if (kind == 2) /* EnrichedIP */
        return field == 5 || field == 6 || field == 8 || field == 17 || field == 18 || field == 22 || field == 26;
    if (kind == 3) /* EnrichedDomain */
        return field == 5 || field == 17 || field == 18 || field == 26 || field == 27;
    return false;
}

static bool yx_vt_netloc_message_field(uint64_t kind, uint64_t field)
{
    if (kind == 1) /* EnrichedURL */
        return field == 4 || field == 5 || field == 7 || field == 8 || field == 12 || field == 18 || field == 20 || field == 21 || field == 25 ||
               (field >= 29 && field <= 31) || field == 35 || field == 39 || field == 40 || (field >= 45 && field <= 48) || field == 50;
    if (kind == 2) /* EnrichedIP */
        return field == 3 || field == 4 || field == 13 || field == 14 || field == 19 || field == 20 || field == 30;
    if (kind == 3) /* EnrichedDomain */
        return field == 3 || field == 4 || field == 6 || field == 7 || field == 12 || field == 13 || field == 19 || field == 20 || field == 28 || field == 30 ||
               field == 32 || field == 37;
    return false;
}

/* In VT string-map entries, protobuf accepts a final unknown start-group
 * marker with no explicit end marker. Keep this exception within map entries
 * and require all preceding fields to have valid wire structure. */
static bool yx_vt_map_terminal_group(const uint8_t *data, size_t size)
{
    size_t at = 0;
    while (at < size) {
        uint64_t key, value;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK || (key >> 3) == 0 || (key >> 3) > 0x1fffffff) return false;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                break;
            case 1:
                if (size - at < 8) return false;
                at += 8;
                break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                at += (size_t)value;
                break;
            case 3: return at == size;
            case 5:
                if (size - at < 4) return false;
                at += 4;
                break;
            default: return false;
        }
    }
    return false;
}

/* These VT leaves have small proto3 schemas and no required fields. The
 * caller first validates the protobuf wire structure. Unknown fields and
 * known fields using another wire type are skipped by protobuf. */
static bool yx_vt_known_leaf_output(uint64_t parent, uint64_t field, const uint8_t *data, size_t size, yx_scalar_root_result *result)
{
    bool stats = parent == 1 && field == 18;
    bool string_map = parent == 1 && (field == 13 || field == 25);
    bool string_pair = parent == 2 && (field == 22 || field == 39 || field == 42 || field == 44 || field == 46);
    bool signature_match = parent == 2 && field == 72;
    bool main_icon = parent == 1 && field == 26;
    bool submitter = parent == 1 && field == 15;
    bool nested_netloc = parent == 1 && field == 32;
    bool gti_score = parent == 1 && field == 36;
    bool gti_value = parent == 36 && field >= 1 && field <= 3;
    bool file_copy = parent == 2 && field == 4;
    bool dropped_file = parent == 2 && field == 6;
    bool ip_traffic = parent == 2 && field == 50;
    bool netloc = parent == 3 && field >= 1 && field <= 3;
    size_t at = 0;
    if (!stats && !string_map && !string_pair && !signature_match && !main_icon && !submitter && !nested_netloc && !gti_score && !gti_value && !file_copy &&
        !dropped_file && !ip_traffic && !netloc)
        return false;
    while (at < size) {
        uint64_t key, value, number;
        unsigned wire;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        number = key >> 3;
        wire = (unsigned)(key & 7);
        switch (wire) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if ((stats && number >= 1 && number <= 6) || (signature_match && (number == 2 || number == 9)) || (gti_value && number == 1) ||
                    (dropped_file && number == 3) || (ip_traffic && (number == 2 || number == 3))) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        result->error = YX_ROOT_ERROR_I32;
                        result->overflow_value = signed_value;
                        return true;
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if ((((string_map || string_pair || main_icon) && (number == 1 || number == 2)) || (signature_match && (number == 1 || (number >= 3 && number <= 8))) ||
                     (submitter && (number == 6 || number == 8)) || (file_copy && (number == 1 || number == 2)) ||
                     (dropped_file && (number == 1 || number == 2 || (number >= 5 && number <= 7))) || (ip_traffic && number == 1) ||
                     (netloc && yx_vt_netloc_string_field(field, number))) &&
                    !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value)) {
                    result->error = YX_ROOT_ERROR_UTF8;
                    return true;
                }
                if (nested_netloc && number >= 1 && number <= 3 && value != 0) {
                    yx_protobuf_error nested = yx_protobuf_validate_nested(data + at, (size_t)value);
                    if (nested != YX_PROTOBUF_OK) {
                        result->error = YX_ROOT_ERROR_NESTED;
                        result->nested_error = nested;
                        return true;
                    }
                    if (!yx_vt_known_leaf_output(3, number, data + at, (size_t)value, result)) return false;
                    if (result->error != YX_ROOT_ERROR_NONE) return true;
                }
                if (gti_score && number >= 1 && number <= 3 && value != 0) {
                    yx_protobuf_error nested = yx_protobuf_validate_nested(data + at, (size_t)value);
                    if (nested != YX_PROTOBUF_OK) {
                        result->error = YX_ROOT_ERROR_NESTED;
                        result->nested_error = nested;
                        return true;
                    }
                    if (!yx_vt_known_leaf_output(36, number, data + at, (size_t)value, result)) return false;
                    if (result->error != YX_ROOT_ERROR_NONE) return true;
                }
                if (netloc && value != 0 && yx_vt_netloc_message_field(field, number)) return false;
                at += (size_t)value;
                break;
            case 3:
                if (string_map && at == size) break;
                if (yx_protobuf_message(data, size, &at, (uint32_t)number, 1, true) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return true;
}

/* Nlist, BuildTool, Dysymtab, DyldInfo, and MinVersion have scalar optional
 * fields. */
static bool yx_macho_known_leaf_output(uint64_t parent, uint64_t field, const uint8_t *data, size_t size, yx_scalar_root_result *result)
{
    bool nlist = parent == 14 && field == 6;
    bool build_tool = parent == 24 && field == 5;
    bool dysymtab = parent == 32 && field == 19;
    bool dyld_info = parent == 32 && field == 20;
    bool min_version = parent == 32 && field == 25;
    size_t at = 0;
    if (!nlist && !build_tool && !dysymtab && !dyld_info && !min_version) return false;
    while (at < size) {
        uint64_t key, value, number;
        unsigned wire;
        bool known_u32, known_i32, known_string;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        number = key >> 3;
        wire = (unsigned)(key & 7);
        known_u32 = (nlist && number >= 1 && number <= 4) || (build_tool && number == 1) || (dysymtab && number >= 3 && number <= 20) ||
                    (dyld_info && number >= 1 && number <= 10);
        known_i32 = min_version && number == 1;
        known_string = (build_tool && number == 2) || (min_version && (number == 2 || number == 3));
        switch (wire) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (known_u32 && value > UINT32_MAX) {
                    result->error = YX_ROOT_ERROR_VARINT;
                    return true;
                }
                if (known_i32) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        result->error = YX_ROOT_ERROR_I32;
                        result->overflow_value = signed_value;
                        return true;
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (known_string && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value)) {
                    result->error = YX_ROOT_ERROR_UTF8;
                    return true;
                }
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)number, 1, true) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    return true;
}

/* Assembly and AssemblyRef own a required Version, and Class methods own
 * required Method fields. Check only their scalar subset; populated Param
 * records remain guarded until their required name is checked. */
static bool yx_dotnet_required_child_output(uint64_t parent, uint64_t field, const uint8_t *data, size_t size, yx_scalar_root_result *result)
{
    bool version = (parent == 20 || parent == 21) && field == 3;
    bool method = parent == 23 && field == 13;
    uint64_t present = 0;
    size_t at = 0;
    if (!version && !method) return false;
    while (at < size) {
        uint64_t key, value, number;
        unsigned wire;
        bool known_string;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        number = key >> 3;
        wire = (unsigned)(key & 7);
        known_string = method && (number == 1 || number == 2 || number == 7 || number == 10);
        if (wire == 0 && number < 64 && ((version && number >= 1 && number <= 4) || (method && ((number >= 3 && number <= 6) || number == 8 || number == 9))))
            present |= UINT64_C(1) << number;
        switch (wire) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (version && number >= 1 && number <= 4 && value > UINT32_MAX) {
                    result->error = YX_ROOT_ERROR_VARINT;
                    return true;
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (known_string && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value)) {
                    result->error = YX_ROOT_ERROR_UTF8;
                    return true;
                }
                if (method && number == 11) return false;
                at += (size_t)value;
                break;
            case 3:
                if (yx_protobuf_message(data, size, &at, (uint32_t)number, 1, true) != YX_PROTOBUF_OK) return false;
                break;
            case 5: at += 4; break;
            default: return false;
        }
    }
    if ((version && (present & UINT64_C(0x1e)) != UINT64_C(0x1e)) || (method && (present & UINT64_C(0x378)) != UINT64_C(0x378))) {
        result->error = YX_ROOT_ERROR_MISSING;
        result->missing_message = version ? (parent == 20 ? "Dotnet" : "AssemblyRef") : "Method";
    }
    return true;
}

static bool yx_vt_nested_failure(bool vt_nested, yx_scalar_root_result *result, yx_protobuf_error error)
{
    if (!vt_nested) return false;
    result->error = YX_ROOT_ERROR_NESTED;
    result->nested_error = error;
    return true;
}

/* A module output that no condition reads still has to deserialize exactly as
 * the module's protobuf type. Check the required fields of the small nested
 * records here. For optional records, accept only empty payloads and the
 * shallow field subsets validated below. Other valid records remain guarded
 * rather than silently treating an invalid known field as unknown. */
static bool yx_unused_nested_output(const char *module, uint64_t parent, const uint8_t *data, size_t size, yx_scalar_root_result *result)
{
    const char *missing = NULL;
    uint64_t required = 0, present = 0;
    bool shallow = false, segment_unknown = false;
    bool optional_macho = false, vt_nested = false;
    size_t at = 0;

    if (strcmp(module, "elf") == 0) {
        if (parent == 13) missing = "Section", required = 0x3e;
        else if (parent == 14) missing = "Segment", required = 0x1fe;
        else if (parent == 15 || parent == 16) missing = "Sym", required = 0xfc;
        else if (parent == 17) shallow = true; /* Dyn */
        else return false;
    } else if (strcmp(module, "dotnet") == 0) {
        if (parent == 17) missing = "Stream", required = 0x0c;
        else if (parent == 20) missing = "Dotnet", required = 0x08;
        else if (parent == 21) missing = "AssemblyRef", required = 0x08;
        else if (parent == 22) shallow = true; /* Resource */
        else if (parent == 23) missing = "Class", required = 0x7c0;
        else return false;
    } else if (strcmp(module, "macho") == 0) {
        if (parent == 18) missing = "Dylib", required = 0x1e;
        else if (parent == 22) missing = "Certificate", required = 0x0e;
        else if (parent == 17) segment_unknown = true;
        else if (parent == 14 || parent == 15 || parent == 16 || parent == 19 || parent == 24 || parent == 25 || parent == 31 || parent == 32) optional_macho = true;
        else return false;
    } else if (strcmp(module, "vt") == 0) {
        if (parent >= 1 && parent <= 3) vt_nested = true;
        else return false;
    } else return false;

    while (at < size) {
        uint64_t key, value, field;
        unsigned wire, expected = 0xff;
        bool known_string = false, known_nested = false;
        bool vt_packed_enum = false;
        bool known_u32 = false, known_i32 = false;
        size_t key_start = at;
        yx_protobuf_error parse_error = yx_protobuf_varint(data, size, &at, &key);
        if (parse_error != YX_PROTOBUF_OK) {
            if (parse_error == YX_PROTOBUF_EOF && at - key_start >= 5) parse_error = YX_PROTOBUF_VARINT;
            return yx_vt_nested_failure(vt_nested, result, parse_error);
        }
        field = key >> 3;
        wire = (unsigned)(key & 7);
        if (field == 0) return yx_vt_nested_failure(vt_nested, result, YX_PROTOBUF_TAG);
        if (missing) {
            if (strcmp(module, "elf") == 0) {
                if (parent == 13) {
                    if (field >= 1 && field <= 5) expected = 0;
                    if (field == 1) known_i32 = true;
                    if (field == 6) expected = 2, known_string = true;
                } else if (parent == 14) {
                    if (field >= 1 && field <= 8) expected = 0;
                    if (field == 1) known_i32 = true;
                    if (field == 2) known_u32 = true;
                } else if (parent == 15 || parent == 16) {
                    if (field == 1) expected = 2, known_string = true;
                    if (field >= 2 && field <= 7) expected = 0;
                    if (field == 4 || field == 5 || field == 7) known_i32 = true;
                    if (field == 6) known_u32 = true;
                }
            } else if (strcmp(module, "dotnet") == 0) {
                if (parent == 17) {
                    if (field == 1) expected = 2, known_string = true;
                    if (field == 2 || field == 3) expected = 0, known_u32 = true;
                } else if (parent == 20 || parent == 21) {
                    if (field == 1) expected = 2, known_string = true;
                    if (parent == 20 && field == 2) expected = 2, known_string = true;
                    if (parent == 21 && field == 2) expected = 2;
                    if (field == 3) expected = 2, known_nested = true;
                } else if (parent == 23) {
                    if (field >= 1 && field <= 5) expected = 2, known_string = true;
                    if (field >= 6 && field <= 10) expected = 0;
                    if (field == 11 || field == 12) expected = 2, known_string = true;
                    if (field == 13) expected = 2, known_nested = true;
                }
            } else if (parent == 18) {
                if (field == 1 || field == 3 || field == 4) expected = 2;
                if (field == 3 || field == 4) known_string = true;
                if (field == 2) expected = 0;
            } else if (parent == 22) {
                if (field == 1 || field == 2) expected = 2, known_string = true;
                if (field == 3) expected = 0;
            }
            if (field < 64 && wire == expected) present |= UINT64_C(1) << field;
        }
        if (shallow) {
            if (strcmp(module, "elf") == 0) {
                if (field == 1 || field == 2) expected = 0;
            } else if (field == 1 || field == 2) expected = 0;
            else if (field == 3) expected = 2, known_string = true;
        }
        if (segment_unknown) {
            if (field == 3) expected = 2; /* bytes segname */
            if (field >= 4 && field <= 11) expected = 0;
            if (field >= 8 && field <= 11) known_u32 = true;
            if (field == 12) expected = 2, known_nested = true;
        }
        if (optional_macho) {
            if (parent == 14) { /* Symtab */
                if (field >= 1 && field <= 4) known_u32 = true;
                if (field == 5) expected = 2; /* bytes entries */
                if (field == 6) expected = 2, known_nested = true;
            } else if (parent == 15) { /* Dysymtab: 1 and 2 are absent. */
                if (field >= 3 && field <= 20) known_u32 = true;
            } else if (parent == 16) { /* LinkedItData */
                if (field == 1 || field == 2) known_u32 = true;
            } else if (parent == 19) { /* DyldInfo */
                if (field >= 1 && field <= 10) known_u32 = true;
            } else if (parent == 24) { /* BuildVersion */
                if (field == 1 || field == 4) known_u32 = true;
                if (field == 2 || field == 3) expected = 2, known_string = true;
                if (field == 5) expected = 2, known_nested = true;
            } else if (parent == 25) { /* MinVersion */
                if (field == 1) known_i32 = true;
                if (field == 2 || field == 3) expected = 2, known_string = true;
            } else if (parent == 31) { /* FatArch */
                if (field == 1 || field == 2 || field == 5 || field == 6) known_u32 = true;
                if (field == 3 || field == 4) expected = 0;
            } else if (parent == 32) { /* File */
                if (field >= 1 && field <= 8) known_u32 = true;
                if (field == 9 || field == 11 || field == 12) expected = 0;
                if (field == 10 || field == 16) expected = 2;
                if (field == 13 || field == 17) expected = 2, known_string = true;
                if (field == 23 || field == 26 || field == 27) expected = 2, known_string = true;
                if (field == 28) expected = 2;
                if (field == 14 || field == 15 || field == 18 || field == 19 || field == 20 || field == 21 || field == 22 || field == 24 || field == 25)
                    expected = 2, known_nested = true;
            }
        }
        if (vt_nested) {
            unsigned vt_wire;
            if (parent == 2 && field == 37 && wire == 0) {
                expected = 0, known_i32 = true;
            } else if (parent == 2 && field == 37 && wire == 2) {
                expected = 2, vt_packed_enum = true;
            } else if (field < 100000 && yx_vt_nested_field_wire(parent, field, &vt_wire) && wire == vt_wire) {
                if (yx_vt_nested_string_field(parent, field)) expected = 2, known_string = true;
                else if (vt_wire == 0) {
                    expected = 0;
                    if ((parent == 1 && (field == 8 || field == 10 || field == 17)) || (parent == 2 && field == 61)) known_i32 = true;
                } else expected = 2, known_nested = true;
            }
        }
        if (known_u32 || known_i32) expected = 0;
        switch (wire) {
            case 0:
                parse_error = yx_protobuf_varint(data, size, &at, &value);
                if (parse_error != YX_PROTOBUF_OK) return yx_vt_nested_failure(vt_nested, result, parse_error);
                if ((optional_macho || segment_unknown || missing) && wire == expected && known_u32 && value > UINT32_MAX) {
                    result->error = YX_ROOT_ERROR_VARINT;
                    return true;
                }
                if ((optional_macho || segment_unknown || vt_nested || missing) && wire == expected && known_i32) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        result->error = YX_ROOT_ERROR_I32;
                        result->overflow_value = signed_value;
                        return true;
                    }
                }
                if (shallow && wire == expected && strcmp(module, "elf") == 0 && field == 1) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        result->error = YX_ROOT_ERROR_I32;
                        result->overflow_value = signed_value;
                        return true;
                    }
                }
                if (shallow && wire == expected && strcmp(module, "dotnet") == 0 && value > UINT32_MAX) {
                    result->error = YX_ROOT_ERROR_VARINT;
                    return true;
                }
                break;
            case 1:
                if (size - at < 8) return yx_vt_nested_failure(vt_nested, result, YX_PROTOBUF_EOF);
                at += 8;
                break;
            case 2:
                parse_error = yx_protobuf_varint(data, size, &at, &value);
                if (parse_error != YX_PROTOBUF_OK) return yx_vt_nested_failure(vt_nested, result, parse_error);
                if (value > size - at)
                    return yx_vt_nested_failure(vt_nested, result, known_nested && wire == expected ? YX_PROTOBUF_LIMIT_INCREASE : YX_PROTOBUF_TRUNCATED);
                if (vt_packed_enum) {
                    size_t packed_at = at, packed_end = at + (size_t)value;
                    while (packed_at < packed_end) {
                        uint64_t element;
                        yx_protobuf_error packed_error = yx_protobuf_varint(data, packed_end, &packed_at, &element);
                        if (packed_error != YX_PROTOBUF_OK) {
                            result->error = YX_ROOT_ERROR_NESTED;
                            result->nested_error = packed_error;
                            return true;
                        }
                        int64_t signed_value = element <= INT64_MAX ? (int64_t)element : -(int64_t)(UINT64_MAX - element) - 1;
                        if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                            result->error = YX_ROOT_ERROR_I32;
                            result->overflow_value = signed_value;
                            return true;
                        }
                    }
                }
                if (known_string && wire == expected && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value)) {
                    result->error = YX_ROOT_ERROR_UTF8;
                    return true;
                }
                if (known_nested && wire == expected) {
                    yx_protobuf_error nested = yx_protobuf_validate_nested(data + at, (size_t)value);
                    if (nested == YX_PROTOBUF_EOF && vt_nested && parent == 1 && (field == 13 || field == 25) && yx_vt_map_terminal_group(data + at, (size_t)value))
                        nested = YX_PROTOBUF_OK;
                    if (nested != YX_PROTOBUF_OK) {
                        result->error = YX_ROOT_ERROR_NESTED;
                        result->nested_error = nested;
                        return true;
                    }
                    /* A valid VT child may be empty. Populated children are
                     * admitted only when their leaf schema is checked. */
                    if (vt_nested && value != 0) {
                        if (!yx_vt_known_leaf_output(parent, field, data + at, (size_t)value, result)) return false;
                        if (result->error != YX_ROOT_ERROR_NONE) return true;
                    } else if (optional_macho) {
                        if (parent == 32 && (field == 14 || field == 15 || field == 18 || field == 22)) {
                            uint64_t child = field == 14 ? 17 : field == 15 ? 18 : field == 18 ? 14 : 22;
                            if (!yx_unused_nested_output(module, child, data + at, (size_t)value, result)) return false;
                        } else if (!yx_macho_known_leaf_output(parent, field, data + at, (size_t)value, result)) return false;
                        if (result->error != YX_ROOT_ERROR_NONE) return true;
                    } else if (strcmp(module, "dotnet") == 0) {
                        if (parent == 20 && field == 3) {
                            yx_scalar_root_result version_result = {0};
                            if (!yx_dotnet_required_child_output(parent, field, data + at, (size_t)value, &version_result)) return false;
                            /* Assembly.version is singular: a later recognized
                             * occurrence replaces the earlier Version. Missing
                             * fields are checked after the enclosing message. */
                            *result = version_result;
                            if (result->error != YX_ROOT_ERROR_NONE && result->error != YX_ROOT_ERROR_MISSING) return true;
                        } else {
                            if (!yx_dotnet_required_child_output(parent, field, data + at, (size_t)value, result)) return false;
                            if (result->error != YX_ROOT_ERROR_NONE) return true;
                        }
                    } else if (!vt_nested) return false;
                }
                at += (size_t)value;
                break;
            case 3:
                parse_error = yx_protobuf_message(data, size, &at, (uint32_t)field, 1, vt_nested);
                if (parse_error != YX_PROTOBUF_OK) return yx_vt_nested_failure(vt_nested, result, parse_error);
                break;
            case 5:
                if (size - at < 4) return yx_vt_nested_failure(vt_nested, result, YX_PROTOBUF_EOF);
                at += 4;
                break;
            default: return yx_vt_nested_failure(vt_nested, result, wire == 4 ? YX_PROTOBUF_WIRE : YX_PROTOBUF_TAG);
        }
        if (shallow && expected != 0xff && wire != expected) continue;
        if (shallow && expected == 0xff && ((strcmp(module, "elf") == 0 && field <= 2) || (strcmp(module, "dotnet") == 0 && field <= 3))) return false;
    }
    if (missing && (present & required) != required) {
        result->error = YX_ROOT_ERROR_MISSING;
        result->missing_message = missing;
        return true;
    }
    /* A complete singular Assembly can be represented by this descriptor
     * subset. Its last Version result has already been checked above. */
    return !missing || (strcmp(module, "dotnet") == 0 && parent == 20);
}

/* Root descriptor subset for module outputs unused by every rule condition.
 * Nested records with required fields remain guarded until their complete
 * schema can be checked. */
static yx_scalar_root_type yx_module_scalar_field(const char *module, uint64_t field)
{
    static const yx_scalar_root_type crx[] = {YX_ROOT_BOOL, YX_ROOT_U32, YX_ROOT_U32, YX_ROOT_STRING, YX_ROOT_STRING};
    static const yx_scalar_root_type dex[] = {YX_ROOT_BOOL, YX_ROOT_MESSAGE, YX_ROOT_STRING, YX_ROOT_STRING, YX_ROOT_MESSAGE};
    static const yx_scalar_root_type dotnet[] = {YX_ROOT_BOOL, YX_ROOT_STRING, YX_ROOT_STRING, YX_ROOT_U64, YX_ROOT_U64};
    static const yx_scalar_root_type elf[] = {YX_ROOT_I32, YX_ROOT_I32, YX_ROOT_U64, YX_ROOT_U64, YX_ROOT_U32};
    static const yx_scalar_root_type macho[] = {YX_ROOT_U32, YX_ROOT_U32, YX_ROOT_U32, YX_ROOT_U32, YX_ROOT_U32};
    static const yx_scalar_root_type zip[] = {YX_ROOT_BOOL, YX_ROOT_MESSAGE, YX_ROOT_UNKNOWN, YX_ROOT_UNKNOWN, YX_ROOT_UNKNOWN};
    static const yx_scalar_root_type vt[] = {YX_ROOT_MESSAGE, YX_ROOT_MESSAGE, YX_ROOT_MESSAGE, YX_ROOT_UNKNOWN, YX_ROOT_UNKNOWN};
    static const yx_scalar_root_type proto3[] = {YX_ROOT_I32, YX_ROOT_U64, YX_ROOT_SINT32, YX_ROOT_U64, YX_ROOT_U32};
    const yx_scalar_root_type *types = NULL;
    if (field < 1) return YX_ROOT_NONE;
    if (field > 5) {
        if (strcmp(module, "elf") == 0) {
            if (field == 7) return YX_ROOT_U32;
            if (field == 6 || (field >= 8 && field <= 12)) return YX_ROOT_U64;
            if (field >= 13 && field <= 17) return YX_ROOT_MESSAGE_GUARDED;
            if (field == 18) return YX_ROOT_I32;
            return YX_ROOT_UNKNOWN;
        }
        if (strcmp(module, "macho") == 0) {
            if ((field >= 6 && field <= 8) || field == 29 || field == 30) return YX_ROOT_U32;
            if (field == 9 || field == 11 || field == 12) return YX_ROOT_U64;
            if (field == 13 || field == 21 || field == 23 || field == 26 || field == 27) return YX_ROOT_STRING;
            if ((field >= 14 && field <= 19) || field == 22 || field == 24 || field == 25 || field == 31 || field == 32) return YX_ROOT_MESSAGE_GUARDED;
            return YX_ROOT_UNKNOWN;
        }
        if (strcmp(module, "dotnet") == 0) {
            if (field == 6 || field == 7 || (field >= 10 && field <= 15)) return YX_ROOT_U64;
            if (field == 16 || field == 18 || field == 26) return YX_ROOT_STRING;
            if (field == 17 || (field >= 20 && field <= 23)) return YX_ROOT_MESSAGE_GUARDED;
            if (field == 24) return YX_ROOT_U32;
            return YX_ROOT_UNKNOWN;
        }
        if (strcmp(module, "vt") == 0) return YX_ROOT_UNKNOWN;
        return YX_ROOT_NONE;
    }
    if (strcmp(module, "crx") == 0) types = crx;
    else if (strcmp(module, "dex") == 0) types = dex;
    else if (strcmp(module, "dotnet") == 0) types = dotnet;
    else if (strcmp(module, "elf") == 0) types = elf;
    else if (strcmp(module, "macho") == 0) types = macho;
    else if (strcmp(module, "zip") == 0) types = zip;
    else if (strcmp(module, "vt") == 0) types = vt;
    else if (strcmp(module, "test_proto3") == 0) types = proto3;
    return types ? types[field - 1] : YX_ROOT_NONE;
}

static bool yx_protobuf_scalar_root_fields(const uint8_t *data, size_t size, const char *module, yx_scalar_root_result *result)
{
    size_t at = 0;
    bool dotnet_assembly_missing = false;
    memset(result, 0, sizeof(*result));
    while (at < size) {
        uint64_t key, value;
        uint64_t field;
        yx_scalar_root_type type;
        unsigned wire;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        field = key >> 3;
        wire = (unsigned)(key & 7);
        type = field >= 100000 ? YX_ROOT_NONE : yx_module_scalar_field(module, field);
        if (field < 100000 && type == YX_ROOT_NONE) return false;
        switch (wire) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (result->error == YX_ROOT_ERROR_NONE && (type == YX_ROOT_U32 || type == YX_ROOT_SINT32) && value > UINT32_MAX) result->error = YX_ROOT_ERROR_VARINT;
                if (result->error == YX_ROOT_ERROR_NONE && type == YX_ROOT_I32) {
                    int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
                    if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                        result->error = YX_ROOT_ERROR_I32;
                        result->overflow_value = signed_value;
                    }
                }
                break;
            case 1: at += 8; break;
            case 2:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > size - at) return false;
                if (strcmp(module, "dotnet") == 0 && field == 24) {
                    size_t packed_at = at;
                    size_t packed_end = at + (size_t)value;
                    while (packed_at < packed_end) {
                        uint64_t element;
                        yx_protobuf_error packed_error = yx_protobuf_varint(data, packed_end, &packed_at, &element);
                        if (packed_error != YX_PROTOBUF_OK) {
                            result->error = YX_ROOT_ERROR_NESTED;
                            result->nested_error = packed_error;
                            break;
                        }
                        if (element > UINT32_MAX) {
                            result->error = YX_ROOT_ERROR_VARINT;
                            break;
                        }
                    }
                }
                if (result->error == YX_ROOT_ERROR_NONE && type == YX_ROOT_STRING && !yx_valid_utf8_bytes((const char *)(data + at), (size_t)value))
                    result->error = YX_ROOT_ERROR_UTF8;
                if (type == YX_ROOT_MESSAGE || type == YX_ROOT_MESSAGE_GUARDED) {
                    yx_protobuf_error nested = type == YX_ROOT_MESSAGE_GUARDED || strcmp(module, "vt") == 0 ? yx_protobuf_validate_nested(data + at, (size_t)value)
                                                                                                            : yx_protobuf_validate(data + at, (size_t)value);
                    if (type == YX_ROOT_MESSAGE && strcmp(module, "vt") == 0) {
                        /* VT child schemas determine whether an inner parse
                         * failure is an invalid string, varint, or length. */
                        if (!yx_unused_nested_output(module, field, data + at, (size_t)value, result) && nested == YX_PROTOBUF_OK) return false;
                        if (result->error == YX_ROOT_ERROR_NONE && nested != YX_PROTOBUF_OK) {
                            result->error = YX_ROOT_ERROR_NESTED;
                            result->nested_error = nested;
                        }
                    } else {
                        if ((result->error == YX_ROOT_ERROR_NONE || (strcmp(module, "dotnet") == 0 && field == 20 && result->error == YX_ROOT_ERROR_MISSING)) &&
                            nested != YX_PROTOBUF_OK) {
                            if (type == YX_ROOT_MESSAGE_GUARDED) {
                                yx_scalar_root_result typed = {0};
                                /* A decoded string or bounded integer can fail
                                 * before malformed bytes later in this child. */
                                (void)yx_unused_nested_output(module, field, data + at, (size_t)value, &typed);
                                if (typed.error == YX_ROOT_ERROR_UTF8 || typed.error == YX_ROOT_ERROR_I32 || typed.error == YX_ROOT_ERROR_VARINT ||
                                    typed.error == YX_ROOT_ERROR_NESTED ||
                                    (typed.error == YX_ROOT_ERROR_MISSING && ((strcmp(module, "dotnet") == 0 && strcmp(typed.missing_message, "Method") == 0) ||
                                                                              (strcmp(module, "macho") == 0 && (strcmp(typed.missing_message, "Dylib") == 0 ||
                                                                                                                strcmp(typed.missing_message, "Certificate") == 0)))))
                                    *result = typed;
                                else {
                                    result->error = YX_ROOT_ERROR_NESTED;
                                    result->nested_error = nested;
                                }
                            } else {
                                result->error = nested == YX_PROTOBUF_EOF ? YX_ROOT_ERROR_EOF : YX_ROOT_ERROR_TAG;
                            }
                        }
                        if (nested == YX_PROTOBUF_OK && type == YX_ROOT_MESSAGE_GUARDED) {
                            if (strcmp(module, "dotnet") == 0 && field == 20) {
                                yx_scalar_root_result assembly_result = {0};
                                if (!yx_unused_nested_output(module, field, data + at, (size_t)value, &assembly_result)) return false;
                                /* The optional Assembly field is singular too.
                                 * Defer its missing check so later root fields
                                 * can still report an eager decode error. */
                                dotnet_assembly_missing = assembly_result.error == YX_ROOT_ERROR_MISSING;
                                if (!dotnet_assembly_missing) *result = assembly_result;
                            } else if (!yx_unused_nested_output(module, field, data + at, (size_t)value, result)) return false;
                        }
                        if (nested == YX_PROTOBUF_OK && type == YX_ROOT_MESSAGE && !yx_protobuf_simple_root_fields(data + at, (size_t)value, 0, NULL)) return false;
                    }
                }
                at += (size_t)value;
                break;
            case 5: at += 4; break;
            default: return false;
        }
        /* Required records in repeated fields fail at the first element.
         * The optional Dotnet assembly and VT messages can have later
         * occurrences, so keep inspecting those. */
        if (result->error != YX_ROOT_ERROR_NONE &&
            (result->error == YX_ROOT_ERROR_NESTED || strcmp(module, "vt") != 0 || result->error == YX_ROOT_ERROR_UTF8 || result->error == YX_ROOT_ERROR_I32) &&
            !(strcmp(module, "dotnet") == 0 && field == 20 && result->error == YX_ROOT_ERROR_MISSING))
            return true;
    }
    if (dotnet_assembly_missing && result->error == YX_ROOT_ERROR_NONE) {
        result->error = YX_ROOT_ERROR_MISSING;
        result->missing_message = "Dotnet";
    }
    return true;
}

/* This narrow override can represent only one scalar field. Inspect the
 * parsed condition so literal strings and regexes cannot look like fields. */
static bool yx_rules_use_only_module_field(const YRX_RULES *rules, const char *module, const char *field)
{
    for (size_t i = 0; i < rules->rule_count; ++i) {
        if (!yx_condition_uses_only_module_field(rules->rules[i].condition, module, field)) return false;
    }
    return true;
}

static bool yx_rules_use_only_pe_locale_fields(const YRX_RULES *rules)
{
    for (size_t i = 0; i < rules->rule_count; ++i)
        if (!yx_condition_uses_only_pe_locale_fields(rules->rules[i].condition)) return false;
    return true;
}

static bool yx_rules_use_only_dex_scalar_fields(const YRX_RULES *rules)
{
    for (size_t i = 0; i < rules->rule_count; ++i)
        if (!yx_condition_uses_only_dex_scalar_fields(rules->rules[i].condition)) return false;
    return true;
}

static bool yx_zip_nested_length_reaches_physical_eof(const uint8_t *data, size_t size, uint64_t entry_length)
{
    size_t at = 0;
    while (at < size) {
        uint64_t key, value;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK || (key >> 3) == 0) return false;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                break;
            case 1:
                if (size - at < 8) return false;
                at += 8;
                break;
            case 2:
                if (yx_protobuf_length_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return false;
                if (value > size - at) return entry_length >= at && value <= entry_length - at;
                at += (size_t)value;
                break;
            case 5:
                if (size - at < 4) return false;
                at += 4;
                break;
            default: return false;
        }
    }
    return false;
}

/* protobuf's ZIP entry parser accepts an entry whose advertised length runs
 * past physical EOF, treating the remaining bytes as the whole entry. Keep
 * that behavior local to ZIP and validate the adjusted message normally. */
static uint8_t *yx_zip_complete_terminal_entry(const uint8_t *data, size_t size, size_t *adjusted_size, bool *nested_eof)
{
    size_t at = 0;
    *nested_eof = false;
    if (!data) return NULL;
    while (at < size) {
        uint64_t key, value;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK || (key >> 3) == 0) return NULL;
        switch (key & 7) {
            case 0:
                if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return NULL;
                break;
            case 1:
                if (size - at < 8) return NULL;
                at += 8;
                break;
            case 2: {
                size_t length_at = at;
                if (yx_protobuf_length_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return NULL;
                if (value <= size - at) {
                    at += (size_t)value;
                    break;
                }
                if ((key >> 3) != 2 || size - at > UINT32_MAX || size > SIZE_MAX - 5) return NULL;
                *nested_eof = yx_zip_nested_length_reaches_physical_eof(data + at, size - at, value);
                uint32_t available = (uint32_t)(size - at);
                uint8_t length_bytes[5];
                size_t length_size = 0;
                do {
                    uint8_t byte = (uint8_t)(available & 0x7f);
                    available >>= 7;
                    length_bytes[length_size++] = available ? (uint8_t)(byte | 0x80) : byte;
                } while (available);
                size_t new_size = length_at + length_size + (size - at);
                uint8_t *adjusted = (uint8_t *)malloc(new_size);
                if (!adjusted) return NULL;
                memcpy(adjusted, data, length_at);
                memcpy(adjusted + length_at, length_bytes, length_size);
                memcpy(adjusted + length_at + length_size, data + at, size - at);
                *adjusted_size = new_size;
                return adjusted;
            }
            case 5:
                if (size - at < 4) return NULL;
                at += 4;
                break;
            default: return NULL;
        }
    }
    return NULL;
}

static bool yx_zip_skip_output_field(const uint8_t *data, size_t size, size_t *at, unsigned wire)
{
    uint64_t value;
    switch (wire) {
        case 0: return yx_protobuf_varint(data, size, at, &value) == YX_PROTOBUF_OK;
        case 1:
            if (size - *at < 8) return false;
            *at += 8;
            return true;
        case 2:
            if (yx_protobuf_length_varint(data, size, at, &value) != YX_PROTOBUF_OK || value > size - *at) return false;
            *at += (size_t)value;
            return true;
        case 5:
            if (size - *at < 4) return false;
            *at += 4;
            return true;
        default: return false;
    }
}

/* Report a bad Compression enum as soon as it is decoded. The protobuf
 * decoder gives this error precedence over malformed fields that follow it. */
static int yx_zip_entry_compression_overflow(const uint8_t *data, size_t size, int64_t *overflow)
{
    size_t at = 0;
    while (at < size) {
        uint64_t key, value;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK || (key >> 3) == 0) return -1;
        if ((key >> 3) == 2 && (key & 7) == 0) {
            if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK) return -1;
            int64_t signed_value = value <= INT64_MAX ? (int64_t)value : -(int64_t)(UINT64_MAX - value) - 1;
            if (signed_value < INT32_MIN || signed_value > INT32_MAX) {
                *overflow = signed_value;
                return 1;
            }
        } else if (!yx_zip_skip_output_field(data, size, &at, (unsigned)(key & 7))) {
            return -1;
        }
    }
    return 0;
}

static bool yx_zip_output_compression_overflow(const uint8_t *data, size_t size, int64_t *overflow)
{
    size_t at = 0;
    if (!data) return false;
    while (at < size) {
        uint64_t key, length;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK || (key >> 3) == 0) return false;
        if ((key >> 3) == 2 && (key & 7) == 2) {
            if (yx_protobuf_length_varint(data, size, &at, &length) != YX_PROTOBUF_OK) return false;
            size_t available = size - at;
            size_t entry_size = length <= available ? (size_t)length : available;
            int status = yx_zip_entry_compression_overflow(data + at, entry_size, overflow);
            if (status != 0) return status > 0;
            at += entry_size;
        } else if (!yx_zip_skip_output_field(data, size, &at, (unsigned)(key & 7))) {
            return false;
        }
    }
    return false;
}

static bool yx_pe_output_skip_field(const uint8_t *data, size_t size, size_t *at, uint64_t key)
{
    uint64_t value;
    switch (key & 7u) {
        case 0: return yx_protobuf_varint(data, size, at, &value) == YX_PROTOBUF_OK;
        case 1:
            if (size - *at < 8) return false;
            *at += 8;
            return true;
        case 2:
            if (yx_protobuf_varint(data, size, at, &value) != YX_PROTOBUF_OK || value > size - *at) return false;
            *at += (size_t)value;
            return true;
        case 3: return yx_protobuf_message(data, size, at, (uint32_t)(key >> 3), 1, false) == YX_PROTOBUF_OK;
        case 5:
            if (size - *at < 4) return false;
            *at += 4;
            return true;
        default: return false;
    }
}

static bool yx_pe_output_resource_language(const uint8_t *data, size_t size, uint32_t *language, bool *present)
{
    size_t at = 0;
    *present = false;
    while (at < size) {
        uint64_t key, value;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) return false;
        if ((key >> 3) == 6 && (key & 7u) == 0) {
            if (yx_protobuf_varint(data, size, &at, &value) != YX_PROTOBUF_OK || value > UINT32_MAX) return false;
            *language = (uint32_t)value;
            *present = true;
        } else if (!yx_pe_output_skip_field(data, size, &at, key)) {
            return false;
        }
    }
    return true;
}

static bool yx_pe_output_languages(const uint8_t *data, size_t size, uint32_t **languages, size_t *count)
{
    size_t at = 0, length = 0, capacity = 0;
    uint32_t *values = NULL;
    *languages = NULL;
    *count = 0;
    while (at < size) {
        uint64_t key, record_length;
        uint32_t language = 0;
        bool present;
        if (yx_protobuf_varint(data, size, &at, &key) != YX_PROTOBUF_OK) goto failed;
        if ((key >> 3) != 54 || (key & 7u) != 2) {
            if (!yx_pe_output_skip_field(data, size, &at, key)) goto failed;
            continue;
        }
        if (yx_protobuf_varint(data, size, &at, &record_length) != YX_PROTOBUF_OK || record_length > size - at ||
            !yx_pe_output_resource_language(data + at, (size_t)record_length, &language, &present))
            goto failed;
        at += (size_t)record_length;
        if (!present) continue;
        if (length == capacity) {
            size_t next = capacity ? capacity * 2 : 8;
            uint32_t *grown;
            if (next < capacity || next > SIZE_MAX / sizeof(*values)) goto failed;
            grown = realloc(values, next * sizeof(*values));
            if (!grown) goto failed;
            values = grown;
            capacity = next;
        }
        values[length++] = language;
    }
    *languages = values;
    *count = length;
    return true;
failed:
    free(values);
    return false;
}

static YRX_RESULT yx_scanner_set_schema_output(YRX_SCANNER *scanner, const char *name, int index, const uint8_t *data, size_t size)
{
    yx_mo_record *decoded = NULL;
    char detail[256], message[512];
    if (!yx_mo_parse_output(name, data, size, &decoded, detail, sizeof(detail), NULL)) {
        snprintf(message, sizeof(message), "can not deserialize protobuf message for YARA module `%s`: %s", name, detail);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    yx_mo_output_destroy(scanner->module_outputs[index]);
    scanner->module_outputs[index] = decoded;
    return yx_ok();
}

YRX_RESULT yrx_scanner_set_module_output(YRX_SCANNER *scanner, const char *name, const uint8_t *data, size_t size)
{
    char message[512];
    yx_protobuf_error protobuf_error;
    const char *module;
    bool unknown_root_fields;
    bool required_bool_shape = false;
    yx_protobuf_root_state root_state;
    yx_scalar_root_result scalar_root_result;
    bool scalar_root_shape = false;
    if (!scanner) return yx_null_argument("scanner");
    if (!name) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(name)) return yx_scanner_invalid_utf8(name, strlen(name));
    if (!data && size) return yx_fail(YRX_INVALID_ARGUMENT, "`data` pointer cannot be null when `len` is greater than 0");
    if (scanner->block_mode) return yx_fail(YRX_INVALID_STATE, "cannot use `yrx_scanner_set_module_output` on a scanner in multi-block mode");
    module = yx_module_output_import_name(name);
    if (!module && !yx_function_only_module_output(name)) {
        return yx_fail_format(YRX_SCAN_ERROR, "unknown module `%s`", name);
    }
    /* These optional descriptors use the schema decoder directly; unlike
     * legacy output modules they have no preceding specialized wire checks. */
    if (module && (!strcmp(module, "olecf") || !strcmp(module, "vba") || !strcmp(module, "msi")))
        return yx_scanner_set_schema_output(scanner, name, yx_mo_module_index(module), data, size);
    if (module && strcmp(module, "crx") == 0 && !yx_unused_module_output(scanner, module)) {
        size_t adjusted_size = 0;
        uint8_t *adjusted = yx_crx_complete_terminal_signature(data, size, &adjusted_size);
        if (adjusted) {
            YRX_RESULT outcome = yrx_scanner_set_module_output(scanner, name, adjusted, adjusted_size);
            free(adjusted);
            return outcome;
        }
    }
    if (module && strcmp(module, "zip") == 0 && !yx_unused_module_output(scanner, module)) {
        int64_t overflow;
        if (yx_zip_output_compression_overflow(data, size, &overflow)) {
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA module "
                     "`%s`: Value too large for i32: %" PRId64,
                     name, overflow);
            return yx_fail(YRX_SCAN_ERROR, message);
        }
        size_t adjusted_size = 0;
        bool nested_eof = false;
        uint8_t *adjusted = yx_zip_complete_terminal_entry(data, size, &adjusted_size, &nested_eof);
        if (adjusted) {
            YRX_RESULT outcome = yrx_scanner_set_module_output(scanner, name, adjusted, adjusted_size);
            free(adjusted);
            if (outcome == YRX_SCAN_ERROR && nested_eof) {
                snprintf(message, sizeof(message),
                         "can not deserialize protobuf message for YARA "
                         "module `%s`: Truncated message",
                         name);
                if (yx_last_error_message && strcmp(yx_last_error_message, message) == 0) {
                    snprintf(message, sizeof(message),
                             "can not deserialize protobuf message for "
                             "YARA module `%s`: Unexpected EOF",
                             name);
                    return yx_fail(YRX_SCAN_ERROR, message);
                }
            }
            return outcome;
        }
    }
    protobuf_error = yx_protobuf_validate(data, size);
    if (protobuf_error != YX_PROTOBUF_OK && module && strcmp(module, "crx") == 0 && !yx_unused_module_output(scanner, module)) {
        yx_protobuf_root_state early = {0};
        (void)yx_protobuf_simple_root_fields(data, size, 3u, &early);
        if (early.first_failure == YX_ROOT_FAILURE_VARINT || early.first_failure == YX_ROOT_FAILURE_UTF8 ||
            early.first_failure == YX_ROOT_FAILURE_CRX_SIGNATURE_MISSING || early.first_failure == YX_ROOT_FAILURE_NESTED) {
            const char *cause = early.first_failure == YX_ROOT_FAILURE_VARINT   ? "Incorrect varint"
                                : early.first_failure == YX_ROOT_FAILURE_UTF8   ? "Invalid UTF-8 sequence"
                                : early.first_failure == YX_ROOT_FAILURE_NESTED ? yx_protobuf_error_text(early.nested_error)
                                                                                : "Message `CrxSignature` is missing required fields";
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA module "
                     "`%s`: %s",
                     name, cause);
            return yx_fail(YRX_SCAN_ERROR, message);
        }
    }
    if ((protobuf_error == YX_PROTOBUF_EOF || protobuf_error == YX_PROTOBUF_TAG) && module && yx_mo_module_index(module) >= 0) {
        yx_mo_record *decoded = NULL;
        char detail[256];
        /* A message can end at physical EOF before its declared logical
         * boundary. The schema decoder distinguishes that from a truncated
         * scalar or string, which the wire-only validator cannot do. */
        bool nested_failure = false;
        bool parsed = yx_mo_parse_output(name, data, size, &decoded, detail, sizeof(detail), &nested_failure);
        if (parsed && protobuf_error == YX_PROTOBUF_EOF) {
            int output_index = yx_mo_module_index(module);
            yx_mo_output_destroy(scanner->module_outputs[output_index]);
            scanner->module_outputs[output_index] = decoded;
            return yx_ok();
        }
        yx_mo_output_destroy(decoded);
        if (!parsed && nested_failure && protobuf_error == YX_PROTOBUF_TAG && !strcmp(detail, "Unexpected EOF")) {
            snprintf(message, sizeof(message), "can not deserialize protobuf message for YARA module `%s`: %s", name, detail);
            return yx_fail(YRX_SCAN_ERROR, message);
        }
    }
    if (protobuf_error != YX_PROTOBUF_OK && !(module && strcmp(module, "dex") == 0)) {
        snprintf(message, sizeof(message), "can not deserialize protobuf message for YARA module `%s`: %s", name, yx_protobuf_error_text(protobuf_error));
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    unknown_root_fields = yx_protobuf_simple_root_fields(data, size, 0, NULL);
    if (module && (strcmp(module, "pe") == 0 || strcmp(module, "lnk") == 0 || strcmp(module, "crx") == 0 || strcmp(module, "zip") == 0))
        required_bool_shape = yx_protobuf_simple_root_fields(data, size,
                                                             strcmp(module, "lnk") == 0   ? 2u
                                                             : strcmp(module, "crx") == 0 ? 3u
                                                             : strcmp(module, "zip") == 0 ? 4u
                                                                                          : 1u,
                                                             &root_state);
    if (module && strcmp(module, "dex") == 0) {
        memset(&root_state, 0, sizeof(root_state));
        required_bool_shape = yx_dex_record_fields(data, size, UINT64_MAX, 0u, &root_state);
        if (!required_bool_shape) {
            if (root_state.first_failure == YX_ROOT_FAILURE_NONE) {
                root_state.first_failure = YX_ROOT_FAILURE_NESTED;
                root_state.nested_error = yx_protobuf_validate_nested(data, size);
                if (root_state.nested_error == YX_PROTOBUF_OK) root_state.nested_error = YX_PROTOBUF_EOF;
            }
            required_bool_shape = true;
        }
    }
    if (protobuf_error != YX_PROTOBUF_OK && !required_bool_shape) {
        snprintf(message, sizeof(message), "can not deserialize protobuf message for YARA module `%s`: %s", name, yx_protobuf_error_text(protobuf_error));
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (module && strcmp(module, "dex") != 0 && yx_unused_module_output(scanner, module))
        scalar_root_shape = yx_protobuf_scalar_root_fields(data, size, module, &scalar_root_result);
    if (scalar_root_shape && scalar_root_result.error != YX_ROOT_ERROR_NONE) {
        if (scalar_root_result.error == YX_ROOT_ERROR_I32)
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA module "
                     "`%s`: Value too large for i32: %" PRId64,
                     name, scalar_root_result.overflow_value);
        else if (scalar_root_result.error == YX_ROOT_ERROR_MISSING)
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA module "
                     "`%s`: Message `%s` is missing required fields",
                     name, scalar_root_result.missing_message);
        else if (scalar_root_result.error == YX_ROOT_ERROR_NESTED)
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA module "
                     "`%s`: %s",
                     name, yx_protobuf_error_text(scalar_root_result.nested_error));
        else
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA module "
                     "`%s`: %s",
                     name,
                     scalar_root_result.error == YX_ROOT_ERROR_UTF8  ? "Invalid UTF-8 sequence"
                     : scalar_root_result.error == YX_ROOT_ERROR_EOF ? "Unexpected EOF"
                     : scalar_root_result.error == YX_ROOT_ERROR_TAG ? "Incorrect tag"
                                                                     : "Incorrect varint");
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && root_state.first_failure == YX_ROOT_FAILURE_I32) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Value too large for i32: %" PRId64,
                 name, root_state.i32_overflow_value);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && root_state.first_failure == YX_ROOT_FAILURE_NESTED) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "%s",
                 name, yx_protobuf_error_text(root_state.nested_error));
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && root_state.first_failure == YX_ROOT_FAILURE_VARINT) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Incorrect varint",
                 name);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && root_state.first_failure == YX_ROOT_FAILURE_UTF8) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Invalid UTF-8 sequence",
                 name);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && root_state.first_failure == YX_ROOT_FAILURE_KEY_VALUE_MISSING) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Message `KeyValue` is missing required fields",
                 name);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && (root_state.first_failure == YX_ROOT_FAILURE_SECTION_MISSING || root_state.first_failure == YX_ROOT_FAILURE_DIR_ENTRY_MISSING ||
                                root_state.first_failure == YX_ROOT_FAILURE_RESOURCE_MISSING || root_state.first_failure == YX_ROOT_FAILURE_IMPORT_MISSING ||
                                root_state.first_failure == YX_ROOT_FAILURE_EXPORT_MISSING || root_state.first_failure == YX_ROOT_FAILURE_FUNCTION_MISSING ||
                                root_state.first_failure == YX_ROOT_FAILURE_RICH_TOOL_MISSING || root_state.first_failure == YX_ROOT_FAILURE_CRX_SIGNATURE_MISSING)) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Message `%s` is missing required fields",
                 name,
                 root_state.first_failure == YX_ROOT_FAILURE_SECTION_MISSING         ? "Section"
                 : root_state.first_failure == YX_ROOT_FAILURE_RESOURCE_MISSING      ? "Resource"
                 : root_state.first_failure == YX_ROOT_FAILURE_IMPORT_MISSING        ? "Import"
                 : root_state.first_failure == YX_ROOT_FAILURE_EXPORT_MISSING        ? "Export"
                 : root_state.first_failure == YX_ROOT_FAILURE_FUNCTION_MISSING      ? "Function"
                 : root_state.first_failure == YX_ROOT_FAILURE_RICH_TOOL_MISSING     ? "RichTool"
                 : root_state.first_failure == YX_ROOT_FAILURE_CRX_SIGNATURE_MISSING ? "CrxSignature"
                                                                                     : "DirEntry");
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && (!root_state.required_present || root_state.nested_missing) && module && strcmp(module, "pe") == 0) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Message `PE` is missing required fields",
                 name);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (required_bool_shape && !root_state.required_present && module && strcmp(module, "lnk") == 0) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Message `Lnk` is missing required fields",
                 name);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    if (unknown_root_fields && (strcmp(name, "test_proto2") == 0 || strcmp(name, "test_proto2.TestProto2") == 0)) {
        snprintf(message, sizeof(message),
                 "can not deserialize protobuf message for YARA module `%s`: "
                 "Message `TestProto2` is missing required fields",
                 name);
        return yx_fail(YRX_SCAN_ERROR, message);
    }
    int output_index = yx_mo_module_index(name);
    if (output_index >= 0) return yx_scanner_set_schema_output(scanner, name, output_index, data, size);
    if (yx_function_only_module_output(name)) {
        static const char *const modules[] = {"hash", "math", "magic"};
        static const char *const descriptors[] = {"hash.Hash", "math.Math", "magic.Magic"};
        for (size_t i = 0; i < 3; ++i)
            if (!strcmp(name, modules[i]) || !strcmp(name, descriptors[i])) scanner->empty_module_outputs[i] = true;
        return yx_ok();
    }
    if (module && strcmp(module, "pe") == 0 && !yx_unused_module_output(scanner, module) && required_bool_shape && root_state.required_present &&
        yx_rules_use_only_pe_locale_fields(scanner->rules)) {
        uint32_t *languages;
        size_t language_count;
        if (!yx_pe_output_languages(data, size, &languages, &language_count)) return yx_fail(YRX_SCAN_ERROR, "can not store PE module output languages");
        free(scanner->pe_output_languages);
        scanner->pe_output_languages = languages;
        scanner->pe_output_language_count = language_count;
        scanner->pe_output_present = true;
        scanner->pe_output_is_pe = root_state.required_value;
        return yx_ok();
    }
    if (module && strcmp(module, "lnk") == 0 && !yx_unused_module_output(scanner, module) && required_bool_shape && root_state.required_present &&
        yx_rules_use_only_module_field(scanner->rules, "lnk", "is_lnk")) {
        scanner->lnk_output_present = true;
        scanner->lnk_output_is_lnk = root_state.required_value;
        return yx_ok();
    }
    if (module && strcmp(module, "crx") == 0 && !yx_unused_module_output(scanner, module)) {
        yx_crx_result decoded = {0};
        if (!yx_crx_parse_output(data, size, &decoded))
            return yx_fail(YRX_SCAN_ERROR,
                           "can not deserialize protobuf message for YARA "
                           "module `crx`");
        yx_crx_result_free(&scanner->crx_output);
        scanner->crx_output = decoded;
        scanner->crx_output_present = true;
        return yx_ok();
    }
    if (module && strcmp(module, "zip") == 0 && !yx_unused_module_output(scanner, module)) {
        yx_zip_result decoded = {0};
        if (!yx_zip_parse_output(data, size, &decoded))
            return yx_fail(YRX_SCAN_ERROR,
                           "can not deserialize protobuf message for YARA "
                           "module `zip`");
        yx_zip_result_free(&scanner->zip_output);
        scanner->zip_output = decoded;
        scanner->zip_output_present = true;
        return yx_ok();
    }
    if (module && strcmp(module, "dex") == 0 && !yx_unused_module_output(scanner, module) && required_bool_shape && yx_rules_use_only_dex_scalar_fields(scanner->rules)) {
        uint8_t *payload = (uint8_t *)malloc(size ? size : 1);
        uint8_t *signature = NULL;
        if (!payload) return yx_fail(YRX_SCAN_ERROR, "out of memory storing module output");
        if (size) memcpy(payload, data, size);
        if (root_state.dex_header_signature_present) {
            signature = (uint8_t *)malloc(root_state.dex_header_signature_length ? root_state.dex_header_signature_length : 1);
            if (!signature) {
                free(payload);
                return yx_fail(YRX_SCAN_ERROR, "out of memory storing module output");
            }
            if (root_state.dex_header_signature_length) memcpy(signature, root_state.dex_header_signature, root_state.dex_header_signature_length);
        }
        free(scanner->dex_output_header_signature);
        free(scanner->dex_output_data);
        scanner->dex_output_data = payload;
        scanner->dex_output_data_size = size;
        scanner->dex_output_header_signature = signature;
        scanner->dex_output_header_signature_length = root_state.dex_header_signature_length;
        scanner->dex_output_header_signature_present = root_state.dex_header_signature_present;
        scanner->dex_output_present = true;
        scanner->dex_output_is_dex = root_state.required_value;
        memcpy(scanner->dex_output_header_present, root_state.dex_header_present, sizeof(scanner->dex_output_header_present));
        memcpy(scanner->dex_output_header_values, root_state.dex_header_values, sizeof(scanner->dex_output_header_values));
        scanner->dex_output_map_size_present = root_state.dex_map_size_present;
        scanner->dex_output_map_size = root_state.dex_map_size;
        memcpy(scanner->dex_output_collection_counts, root_state.dex_collection_counts, sizeof(scanner->dex_output_collection_counts));
        scanner->dex_output_map_list_present = root_state.dex_map_list_present;
        return yx_ok();
    }
    if (module && strcmp(module, "vt") == 0 && !yx_unused_module_output(scanner, module)) {
        yx_vt_record *decoded = NULL;
        char detail[256];
        if (!yx_vt_parse_output(data, size, &decoded, detail, sizeof(detail))) {
            snprintf(message, sizeof(message),
                     "can not deserialize protobuf message for YARA "
                     "module `%s`: %s",
                     name, detail);
            return yx_fail(YRX_SCAN_ERROR, message);
        }
        yx_vt_output_destroy(scanner->vt_output);
        scanner->vt_output = decoded;
        return yx_ok();
    }
    /* Cuckoo's root protobuf is an empty message. Every valid field is
     * unknown to that descriptor, regardless of its field number. */
    if (module && strcmp(module, "cuckoo") == 0) return yx_ok();
    if (scalar_root_shape && module && yx_unused_module_output(scanner, module)) return yx_ok();
    if (required_bool_shape && module && yx_unused_module_output(scanner, module) &&
        (root_state.required_present || strcmp(module, "crx") == 0 || strcmp(module, "zip") == 0 || strcmp(module, "dex") == 0))
        return yx_ok();
    if (unknown_root_fields && module && yx_unused_module_output(scanner, module)) return yx_ok();
    /* These descriptors have no root fields numbered 64 or above in
     * YARA-X 1.21.0. Keep well-formed unknown fields when the imported
     * module does not participate in any rule condition. */
    if (module && yx_unused_module_output(scanner, module) &&
        (strcmp(module, "elf") == 0 || strcmp(module, "macho") == 0 || strcmp(module, "dotnet") == 0 || strcmp(module, "vt") == 0) &&
        yx_protobuf_simple_root_fields(data, size, 5u, NULL))
        return yx_ok();
    return yx_unsupported("module output");
}
YRX_RESULT yrx_scanner_set_module_data(YRX_SCANNER *scanner, const char *name, const uint8_t *data, size_t size)
{
    size_t index;
    if (!scanner) return yx_null_argument("scanner");
    if (!name) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(name)) return yx_scanner_invalid_utf8(name, strlen(name));
    if (!data && size) return yx_fail(YRX_INVALID_ARGUMENT, "`data` pointer cannot be null when `len` is greater than 0");
    if (scanner->block_mode) return yx_fail(YRX_INVALID_STATE, "cannot use `yrx_scanner_set_module_data` on a scanner in multi-block mode");
    for (index = 0; index < scanner->module_data_count; ++index)
        if (strcmp(scanner->module_data[index].name, name) == 0) break;
    if (index == scanner->module_data_count) {
        yx_scanner_module_data *grown;
        if (index == SIZE_MAX / sizeof(*grown)) return yx_fail(YRX_SCAN_ERROR, "too many module data entries");
        grown = realloc(scanner->module_data, (index + 1) * sizeof(*grown));
        if (!grown) return yx_fail(YRX_SCAN_ERROR, "out of memory storing module data");
        scanner->module_data = grown;
        scanner->module_data_count = index + 1;
        scanner->module_data[index].name = name;
    }
    scanner->module_data[index].data = data;
    scanner->module_data[index].size = size;
    /* The upstream setter borrows both inputs until the next scan. */
    return yx_ok();
}
YRX_RESULT yrx_scanner_set_global_str(YRX_SCANNER *scanner, const char *name, const char *value)
{
    if (!value) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(value)) return yx_scanner_invalid_utf8(value, strlen(value));
    yx_global_string string = {(char *)value, value ? strlen(value) : 0};
    return yx_set_global(scanner, name, YX_GLOBAL_STR, value ? &string : NULL);
}
YRX_RESULT yrx_scanner_set_global_bool(YRX_SCANNER *scanner, const char *name, bool value)
{
    return yx_set_global(scanner, name, YX_GLOBAL_BOOL, &value);
}
YRX_RESULT yrx_scanner_set_global_int(YRX_SCANNER *scanner, const char *name, int64_t value)
{
    return yx_set_global(scanner, name, YX_GLOBAL_INT, &value);
}
YRX_RESULT yrx_scanner_set_global_float(YRX_SCANNER *scanner, const char *name, double value)
{
    return yx_set_global(scanner, name, YX_GLOBAL_FLOAT, &value);
}
YRX_RESULT yrx_scanner_set_global_json(YRX_SCANNER *scanner, const char *name, const char *value)
{
    yx_json_scalar scalar;
    yx_global_array *array = NULL;
    yx_global_object *object = NULL;
    YRX_RESULT result;
    if (!value) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(value)) return yx_scanner_invalid_utf8(value, strlen(value));
    if (!yx_capi_json_validate(value)) return YRX_INVALID_ARGUMENT;
    if (!scanner) return yx_null_argument("scanner");
    if (!name) return yx_fail(YRX_INVALID_ARGUMENT, "string pointer cannot be null");
    if (!yx_valid_utf8(name)) return yx_scanner_invalid_utf8(name, strlen(name));
    result = yx_parse_json_scalar(value, &scalar);
    if (result == YRX_VARIABLE_ERROR) {
        char message[512];
        if (!yx_valid_utf8(name)) return yx_scanner_invalid_utf8(name, strlen(name));
        if (!yx_find_global(scanner->globals, scanner->global_count, name)) {
            return yx_fail_format(YRX_VARIABLE_ERROR, "variable `%s` not defined", name);
        }
    }
    if (result == YRX_NOT_SUPPORTED) {
        const char *at = value;
        while (*at == ' ' || *at == '\t' || *at == '\n' || *at == '\r') ++at;
        if (*at == '[' || *at == '{') {
            yx_global *global;
            const char *expected;
            char message[512];
            if (!yx_valid_utf8(name)) return yx_scanner_invalid_utf8(name, strlen(name));
            global = yx_find_global(scanner->globals, scanner->global_count, name);
            if (!global) {
                return yx_fail_format(YRX_VARIABLE_ERROR, "variable `%s` not defined", name);
            }
            switch (global->type) {
                case YX_GLOBAL_BOOL: expected = "boolean"; break;
                case YX_GLOBAL_INT: expected = "integer"; break;
                case YX_GLOBAL_FLOAT: expected = "float"; break;
                case YX_GLOBAL_STR: expected = "string"; break;
                case YX_GLOBAL_ARRAY: expected = "array"; break;
                case YX_GLOBAL_STRUCT: expected = "struct"; break;
                default: expected = "unknown"; break;
            }
            if (*at == '[' && global->type == YX_GLOBAL_ARRAY) {
                result = yx_parse_json_array(value, &array);
                if (result != YRX_SUCCESS) return result;
                result = yx_set_global(scanner, name, YX_GLOBAL_ARRAY, array);
                yx_free_global_array(array);
                return result;
            }
            if (*at == '{' && global->type == YX_GLOBAL_STRUCT) {
                result = yx_parse_json_object(value, &object);
                if (result != YRX_SUCCESS) return result;
                result = yx_set_global(scanner, name, YX_GLOBAL_STRUCT, object);
                yx_free_global_object(object);
                return result;
            }
            return yx_fail_format(YRX_VARIABLE_ERROR, "invalid type for `%s`, expecting `%s`, got `%s", name, expected, *at == '[' ? "array" : "struct");
        }
    }
    if (result != YRX_SUCCESS) return result;
    result = yx_set_global(scanner, name, scalar.type, yx_json_scalar_value(&scalar));
    if (scalar.type == YX_GLOBAL_STR) xx_str_free(scalar.value.string.data);
    return result;
}
#ifdef XXYARA_ENABLE_PROFILING
typedef struct yx_profile_entry {
    const YRX_RULE *rule;
    yx_rule_profile times;
    uint64_t total_nanoseconds;
    size_t ordinal;
} yx_profile_entry;

static int yx_compare_profile_entries(const void *left, const void *right)
{
    const yx_profile_entry *a = (const yx_profile_entry *)left;
    const yx_profile_entry *b = (const yx_profile_entry *)right;
    if (a->total_nanoseconds > b->total_nanoseconds) return -1;
    if (a->total_nanoseconds < b->total_nanoseconds) return 1;
    return a->ordinal < b->ordinal ? -1 : a->ordinal > b->ordinal;
}
#endif

YRX_RESULT yrx_scanner_iter_slowest_rules(YRX_SCANNER *scanner, size_t n, YRX_SLOWEST_RULES_CALLBACK callback, void *user_data)
{
#ifndef XXYARA_ENABLE_PROFILING
    (void)scanner;
    (void)n;
    (void)callback;
    (void)user_data;
    return yx_fail(YRX_NOT_SUPPORTED, "`rules-profiling` feature is not enabled");
#else
    yx_profile_entry *entries;
    size_t count = 0;
    size_t limit;
    if (!scanner) return yx_null_argument("scanner");
    if (!callback) return yx_null_argument("callback");
    if (n == 0 || scanner->rules->rule_count == 0) return yx_ok();
    if (scanner->rules->rule_count > SIZE_MAX / sizeof(*entries)) return yx_fail(YRX_SCAN_ERROR, "too many rules for profiling output");
    entries = (yx_profile_entry *)malloc(scanner->rules->rule_count * sizeof(*entries));
    if (!entries) return yx_fail(YRX_SCAN_ERROR, "out of memory building profiling output");
    for (size_t i = 0; i < scanner->rules->rule_count; ++i) {
        uint64_t total = yx_profile_total_ns(&scanner->rule_profiles[i]);
        /* YARA-X suppresses rules with no more than 100 ms of total time. */
        if (total <= UINT64_C(100000000)) continue;
        entries[count].rule = &scanner->rules->rules[i];
        entries[count].times = scanner->rule_profiles[i];
        entries[count].total_nanoseconds = total;
        entries[count].ordinal = i;
        ++count;
    }
    qsort(entries, count, sizeof(*entries), yx_compare_profile_entries);
    limit = n < count ? n : count;
    if (limit && !callback) {
        free(entries);
        return yx_fail(YRX_INVALID_ARGUMENT, "profiling callback is null");
    }
    for (size_t i = 0; i < limit; ++i) {
        const YRX_RULE *rule = entries[i].rule;
        callback(rule->namespace_name ? rule->namespace_name : "default", rule->identifier, (double)entries[i].times.pattern_nanoseconds / 1e9,
                 (double)entries[i].times.condition_nanoseconds / 1e9, user_data);
    }
    free(entries);
    return yx_ok();
#endif
}

YRX_RESULT yrx_scanner_clear_profiling_data(YRX_SCANNER *scanner)
{
#ifndef XXYARA_ENABLE_PROFILING
    (void)scanner;
    return yx_fail(YRX_NOT_SUPPORTED, "`rules-profiling` feature is not enabled");
#else
    if (!scanner) return yx_null_argument("scanner");
    memset(scanner->rule_profiles, 0, scanner->rules->rule_count * sizeof(*scanner->rule_profiles));
    return yx_ok();
#endif
}

YRX_RESULT yrx_scanner_scan_block(YRX_SCANNER *scanner, size_t base, const uint8_t *data, size_t size)
{
    size_t i, j;
    yx_ok();
    if (!scanner) return yx_null_argument("scanner");
    if (!data && size) return yx_fail(YRX_INVALID_ARGUMENT, "`data` pointer cannot be null when `len` is greater than 0");
    scanner->block_mode = true;
    if (!scanner->block_size) {
        yx_clear_views(scanner);
        yx_scan_deadline_start(scanner);
        scanner->block_size = 1; /* Marks an active block scan. */
    }
    if (scanner->timeout_seconds && yx_scan_deadline_reached(&scanner->deadline)) return yx_fail(YRX_SCAN_TIMEOUT, "timeout");
    if (scanner->text_prefilter &&
        !yx_atom_set_scan(scanner->text_prefilter, data, size, scanner->timeout_seconds ? &scanner->deadline : NULL, scanner->text_prefilter_hit))
        return yx_fail(YRX_SCAN_TIMEOUT, "timeout");
    for (i = 0; i < scanner->rules->rule_count; ++i) {
        YRX_RULE *rule = &scanner->views[i];
#ifdef XXYARA_ENABLE_PROFILING
        uint64_t pattern_started = rule->pattern_count ? yx_profile_now_ns() : 0;
#endif
        for (j = 0; j < rule->pattern_count; ++j) {
            YRX_PATTERN *pattern = &rule->patterns[j];
            YRX_PATTERN temporary = *pattern;
            /* Zero-timeout block scans defer failure until a match or
             * finish, matching the block scanner's observed contract. */
            temporary.deadline = scanner->timeout_seconds ? &scanner->deadline : NULL;
            size_t limit = scanner->max_matches_per_pattern ? scanner->max_matches_per_pattern : 1;
            size_t scan_limit = limit;
            size_t fixed_at_local = 0;
            size_t k;
            YRX_RESULT result;
            bool presence_only = !scanner->max_matches_per_pattern && pattern->ever_matched;
            if (scanner->fast_scan && pattern->fast_count_enabled && pattern->fast_count_threshold < limit) limit = pattern->fast_count_threshold;
            scan_limit = limit;
            if (!presence_only && pattern->match_count >= limit) continue;
            if (!presence_only && scanner->fast_scan && !pattern->fast_scan_needs_all && pattern->match_count) continue;
            if (pattern->fixed_at_enabled) {
                if (pattern->fixed_at_offset < base || pattern->fixed_at_offset - base >= size) continue;
                fixed_at_local = pattern->fixed_at_offset - base;
                /* A fixed `at` condition needs the match at that exact
                 * position even when earlier hits fill the reporting cap. */
                scan_limit = fixed_at_local + 1;
            }
            if (scanner->text_prefilter && pattern->prefilter_owner != SIZE_MAX && !scanner->text_prefilter_hit[pattern->prefilter_owner]) {
                if (yx_scan_deadline_reached(temporary.deadline)) return yx_fail(YRX_SCAN_TIMEOUT, "timeout");
                continue;
            }
            temporary.matches = NULL;
            temporary.match_count = 0;
            temporary.match_capacity = 0;
            /* A block may repeat matches already found in an overlapping
             * block. Give the block the full limit so those duplicates don't
             * consume the slots still available for new offsets. */
            result = yx_scan_pattern(&temporary, data, size, scan_limit, scanner->fast_scan);
            if (result != YRX_SUCCESS) {
                free(temporary.matches);
#ifdef XXYARA_ENABLE_PROFILING
                yx_profile_add_elapsed(&scanner->rule_profiles[i].pattern_nanoseconds, pattern_started);
#endif
                return yx_fail(result, result == YRX_SCAN_TIMEOUT ? "timeout" : "pattern block scan failed");
            }
            if (scanner->timeout_configured && scanner->timeout_seconds == 0 && temporary.match_count) {
                free(temporary.matches);
                return yx_fail(YRX_SCAN_TIMEOUT, "timeout");
            }
            if (presence_only) {
                if (temporary.match_count) pattern->zero_limit_present = true;
                free(temporary.matches);
                continue;
            }
            for (k = 0; k < temporary.match_count; ++k) {
                YRX_MATCH match = temporary.matches[k];
                size_t end;
                if (pattern->fixed_at_enabled && match.offset != fixed_at_local) continue;
                /* A block's virtual base is unrelated to its data pointer.
                 * Rebase both ends in unsigned arithmetic, as YARA-X does.
                 * An end that wraps below the start has a reported length
                 * of zero (the length of that empty absolute range). */
                end = base + match.offset + match.length;
                match.offset += base;
                match.length = end >= match.offset ? end - match.offset : 0;
                if (!yx_append_match(pattern, match)) {
                    free(temporary.matches);
#ifdef XXYARA_ENABLE_PROFILING
                    yx_profile_add_elapsed(&scanner->rule_profiles[i].pattern_nanoseconds, pattern_started);
#endif
                    return yx_fail(YRX_SCAN_ERROR, "out of memory storing block match");
                }
                pattern->ever_matched = true;
                if (pattern->match_count >= limit) break;
            }
            free(temporary.matches);
        }
#ifdef XXYARA_ENABLE_PROFILING
        yx_profile_add_elapsed(&scanner->rule_profiles[i].pattern_nanoseconds, pattern_started);
#endif
    }
    return yx_ok();
}
YRX_RESULT yrx_scanner_finish(YRX_SCANNER *scanner)
{
    size_t i, j;
    YRX_RESULT result;
    yx_ok();
    if (!scanner) return yx_null_argument("scanner");
    scanner->block_mode = true;
    if (!scanner->block_size) {
        yx_clear_views(scanner);
        yx_scan_deadline_start(scanner);
    }
    for (i = 0; i < scanner->rules->rule_count; ++i) {
        YRX_RULE *rule = &scanner->views[i];
        for (j = 0; j < rule->pattern_count; ++j)
            if (rule->patterns[j].match_count > 1) qsort(rule->patterns[j].matches, rule->patterns[j].match_count, sizeof(YRX_MATCH), yx_compare_matches);
    }
    if (yx_scan_deadline_reached(&scanner->deadline)) {
        scanner->block_size = 0;
        return yx_fail(YRX_SCAN_TIMEOUT, "timeout");
    }
    result = yx_evaluate_views(scanner, NULL, 0);
    yx_pe_scan_cache_destroy(scanner->deadline.pe_cache);
    scanner->deadline.pe_cache = NULL;
    scanner->block_size = 0;
    if (result != YRX_SUCCESS) return result;
    return yx_ok();
}
