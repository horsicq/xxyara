/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* Scanner adapter to xxfclib's native regular expression engine. The private
 * compatibility names retain the scanner's existing normalization code; this
 * header does not include or link PCRE2. */
#ifndef XXYARA_NATIVE_REGEX_H
#define XXYARA_NATIVE_REGEX_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
typedef size_t PCRE2_SIZE;
typedef const unsigned char *PCRE2_SPTR;
typedef struct yx_native_regex pcre2_code;
typedef struct { int unused; } pcre2_compile_context;
typedef struct { size_t current_position, start_match; } pcre2_callout_block;
typedef struct {
    int (*callout)(pcre2_callout_block *, void *);
    void *user;
} pcre2_match_context;
typedef struct { size_t *offsets; int32_t *captures; size_t count; } pcre2_match_data;
typedef struct { uint32_t first, last; } yx_re_range;
struct yx_scan_deadline;
#define PCRE2_ZERO_TERMINATED SIZE_MAX
#define PCRE2_CASELESS 1u
#define PCRE2_DOTALL 2u
#define PCRE2_UTF 4u
#define PCRE2_UCP 8u
#define PCRE2_ANCHORED 16u
#define PCRE2_ENDANCHORED 32u
#define PCRE2_NOTBOL 64u
#define PCRE2_NOTEOL 128u
#define PCRE2_AUTO_CALLOUT 256u
#define PCRE2_DOLLAR_ENDONLY 512u
#define PCRE2_MATCH_INVALID_UTF 1024u
#define PCRE2_EXTENDED 2048u
/* Rule source scalar escapes differ from already lowered PCRE byte input
 * (used by the CLI regex translator) for braced hex values below 256. */
#define YX_RE_YARA_ESCAPES 4096u
#define PCRE2_NEWLINE_LF 1u
#define PCRE2_ERROR_NOMATCH (-1)
#define PCRE2_ERROR_NOMEMORY (-2)
#define PCRE2_ERROR_CALLOUT (-3)
#define PCRE2_ERROR_MATCHLIMIT (-4)
#define PCRE2_ERROR_DEPTHLIMIT (-5)
#define PCRE2_ERROR_HEAPLIMIT (-6)
#define PCRE2_ERROR_DFA_WSSIZE (-7)
#define PCRE2_ERROR_BADDATA (-8)
#define PCRE2_ERROR_QUANTIFIER_TOO_BIG 105
#define PCRE2_ERROR_PATTERN_TOO_LARGE 120
#define PCRE2_ERROR_HEAP_FAILED 121
/* Parse one literal, class or class escape for the compiler's size model.
 * The returned sorted scalar ranges belong to the caller (free()). */
int yx_re_class_ranges(const unsigned char *, size_t, size_t *, uint32_t,
                       yx_re_range **, size_t *);
/* The same for a Unicode class (PCRE2_UTF), as regex-syntax's ranges of
 * chars: *gap_split is set when the range ending at U+D7FF and the range
 * starting at U+E000 are two ranges of the class, not one across the
 * surrogate gap. A negated outermost class keeps its ranges unmerged. */
int yx_re_class_ranges_gap(const unsigned char *, size_t, size_t *, uint32_t,
                           yx_re_range **, size_t *, bool *gap_split);
/* UTF-8 byte expression for scalar ranges; caller frees the returned text. */
char *yx_re_ranges_pattern(const yx_re_range *, size_t);
/* Validate and register a capture name: 1 valid, 0 invalid/duplicate, -1 OOM.
 * The NUL-separated registry belongs to the caller and is released with free. */
int yx_re_capture_name_append(char **, size_t *, size_t *,
                               const unsigned char *, size_t);
/* Compile once from the original YARA regexp, then search without captures.
 * Search returns 1/0 for match/miss, -1 for allocation failure or deadline. */
int yx_re_code_set_source(pcre2_code *, const char *, size_t, bool, bool);
pcre2_code *yx_re_compile_search(const char *, size_t, bool, bool, int *);
int yx_re_code_search(const pcre2_code *, const unsigned char *, size_t,
                       struct yx_scan_deadline *);
/* Shared regex-syntax property resolver; ranges are owned by the caller. */
int yx_re_property_ranges(const char *, size_t, int, yx_re_range **, size_t *);
const char *yx_re_property_error(const char *, size_t);
pcre2_compile_context *yx_re_compile_context_create(void *);
void yx_re_compile_context_free(pcre2_compile_context *);
int yx_re_set_newline(pcre2_compile_context *, unsigned);
pcre2_code *yx_re_compile(PCRE2_SPTR, size_t, uint32_t, int *, size_t *, pcre2_compile_context *);
void yx_re_code_free(pcre2_code *);
pcre2_code *yx_re_code_copy(const pcre2_code *);
pcre2_match_data *yx_re_match_data_create_from_pattern(const pcre2_code *, void *);
void yx_re_match_data_free(pcre2_match_data *);
size_t *yx_re_get_ovector_pointer(pcre2_match_data *);
pcre2_match_context *yx_re_match_context_create(void *);
void yx_re_match_context_free(pcre2_match_context *);
int yx_re_set_callout(pcre2_match_context *, int (*)(pcre2_callout_block *, void *), void *);
int yx_re_match(const pcre2_code *, PCRE2_SPTR, size_t, size_t, uint32_t, pcre2_match_data *, pcre2_match_context *);
int yx_re_dfa_match(const pcre2_code *, PCRE2_SPTR, size_t, size_t, uint32_t, pcre2_match_data *, pcre2_match_context *, int *, size_t);
#define pcre2_compile_context_create yx_re_compile_context_create
#define pcre2_compile_context_free yx_re_compile_context_free
#define pcre2_set_newline yx_re_set_newline
#define pcre2_compile yx_re_compile
#define pcre2_code_free yx_re_code_free
#define pcre2_code_copy yx_re_code_copy
#define pcre2_match_data_create_from_pattern yx_re_match_data_create_from_pattern
#define pcre2_match_data_free yx_re_match_data_free
#define pcre2_get_ovector_pointer yx_re_get_ovector_pointer
#define pcre2_match_context_create yx_re_match_context_create
#define pcre2_match_context_free yx_re_match_context_free
#define pcre2_set_callout yx_re_set_callout
#define pcre2_match yx_re_match
#define pcre2_dfa_match yx_re_dfa_match
#endif
