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

#ifndef XXYARA_SERIALIZATION_H
#define XXYARA_SERIALIZATION_H

#include "internal.h"

/* -2 means the pattern belongs to the normal scanner. */
int yx_ser_large_regex_validate(const YRX_PATTERN *pattern);
struct yx_rx_program;
/* 1: a regexp sub-pattern program; 0: another sub-pattern kind; -1: OOM. */
/* The head YARA-X compiles when it drops a trailing large any-byte gap. */
char *yx_ser_gap_head_regexp(const YRX_PATTERN *pattern);
int yx_ser_regexp_program(const YRX_PATTERN *pattern, struct yx_rx_program *out);
/* The program of an archive's own code and atoms (yx_archived_regexp), with
 * the guards, index and windows yx_ser_regexp_program derives: 1, or -1. */
int yx_ser_archived_regexp_program(const yx_archived_regexp *archived, struct yx_rx_program *out);
/* A copy of such a program for a pattern with the same inputs: 1, or -1. */
int yx_ser_regexp_program_copy(const struct yx_rx_program *from, struct yx_rx_program *out);
int yx_ser_literal_branches(const YRX_PATTERN *pattern, uint8_t **bytes, size_t **offsets);
/* Boolean condition regexp, compiled once: 1 success, 0 unsupported/too large,
 * -1 allocation failure. The caller owns the unanchored PikeVM program. */
int yx_ser_search_program(const char *regexp, size_t length, bool dotall,
                           bool nocase, uint8_t **code, size_t *code_length);
/* Compiler::c_rule's slow_pattern decisions for a regexp or hex pattern:
 * the literal check and one entry per c_regexp call (0 not slow, 1 slow,
 * 2 slow and exceptionally extreme). 1 when modeled, 0 when not, -1 on
 * allocation failure; the caller frees *calls. */
int yx_ser_slow_pattern(const YRX_PATTERN *pattern, bool *literal_slow,
                        uint8_t **calls, size_t *call_count);
struct yx_rx_atom;
/* The reference's automaton atoms for a pattern; false when not modeled. */
bool yx_ser_pattern_reference_atoms(const YRX_PATTERN *pattern, struct yx_rx_atom **atoms, size_t *count);
/* The same: 1 with the atoms, 0 when not modeled, -1 on allocation failure. */
int yx_ser_pattern_reference_atoms_status(const YRX_PATTERN *pattern, struct yx_rx_atom **atoms, size_t *count);
/* -2: ordinary path, -1: allocation error, 0: empty verifier, 1: owned source, 3: chain. */
int yx_ser_lower_fast_regex(const YRX_PATTERN *pattern, char **lowered);
int yx_ser_scan_large_fast_chain(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    bool (*emit)(size_t offset, size_t length, void *context), void *context);
/* Chains of sub-patterns (Hir::split_at_large_gaps): hex patterns, also
 * literal-only ones, and regexps, joined as verify_chain_of_matches joins
 * them. The scans return 1, 0 on failure, -2 when the pattern is not such a
 * chain or a piece cannot be built. */
bool yx_ser_hex_chain(const YRX_PATTERN *pattern);
bool yx_ser_regex_chain(const YRX_PATTERN *pattern);
/* Hir::as_literal_bytes of a regexp pattern: 1 with the bytes (the caller
 * frees them), 0 when it is not one literal, -1 on allocation failure. */
int yx_ser_regexp_literal(const YRX_PATTERN *pattern, uint8_t **bytes, size_t *length);
/* The same tests: 1 a chain, 0 not one, -1 when memory ran out first. */
int yx_ser_hex_chain_status(const YRX_PATTERN *pattern);
int yx_ser_regex_chain_status(const YRX_PATTERN *pattern);
/* The gate of such a chain (hex or regexp): the literal head, or the raw
 * atoms of the head sub-pattern. Branch k is (*bytes)[(*offsets)[k] .. (*offsets)[k+1]).
 * Returns the branch count, 0 when there is none, -1 on allocation failure. */
int yx_ser_hex_chain_gate(const YRX_PATTERN *pattern, uint8_t **bytes, size_t **offsets);
int yx_ser_scan_hex_chain(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    bool (*emit)(size_t offset, size_t length, void *context), void *context);
int yx_ser_scan_regex_chain(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    bool (*emit)(size_t offset, size_t length, void *context), void *context);
/* The chain the scans above build for a pattern, built ahead (NULL when the
 * pattern is not a chain, a piece cannot be built or memory runs out; the
 * scans then build their own). */
struct yx_hc_chain *yx_ser_chain_new(const YRX_PATTERN *pattern);
void yx_ser_chain_free(struct yx_hc_chain *chain);
/* `greedy` reports whether a longer match replaces a shorter one that starts
 * at the same offset, as for the reference's greedy regexp sub-patterns. */
int yx_ser_scan_large_regex(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
    bool (*emit)(size_t offset, size_t length, void *context), void *context,
    bool *greedy);

/* YARA-X v1.23.0 / archive version 12 codec. Typed numeric, pattern,
 * module and external-global expressions share structural readers/writers.
 * Physical pattern composition relocates literal pools, subpatterns, atoms
 * and verifier programs across rules and namespace generations. Per-pattern
 * codecs implement literal, Fast/Thompson regex, chain, XOR and base64 payloads.
 * Legacy canonical codecs remain as fast paths and compatibility controls.
 *
 * Successful decoding validates the supported wire representation and
 * reconstructs owned scanner state. Where reconstruction changes optimization
 * layout, the original validated archive is retained for serialization.
 * Search atoms and literal verification remain separate for accepted changed
 * pools. Generic collection counts use checked dynamic storage; recursion guards apply to actual
 * expression nesting. Other unsupported wire/condition forms fail explicitly.
 * See private_docs/ARCHIVE_FORMAT.md for schema and ownership details. */
typedef enum yx_ser_result {
    YX_SER_NO_MEMORY = -2,
    YX_SER_MALFORMED = -1,
    YX_SER_UNSUPPORTED = 0,
    YX_SER_SUCCESS = 1
} yx_ser_result;

enum {
    YX_SER_WIRE_UNKNOWN = 0,
    YX_SER_WIRE_VALID = 1,
    YX_SER_WIRE_DECODE = -1,
    YX_SER_WIRE_BOUNDS = -2,
    YX_SER_WIRE_WASM = -3
};
int yx_ser_validate_v12(const uint8_t *data, size_t length,
                         size_t *consumed);
/* Between begin and end (nested per thread), a valid result of
 * yx_ser_validate_v12 for exactly these bytes is computed once. */
typedef struct yx_wire_known {
    const uint8_t *data;
    size_t length, consumed;
    bool valid, nonminimal;
    struct yx_wire_known *outer;
} yx_wire_known;
void yx_ser_validate_memo_begin(yx_wire_known *known, const uint8_t *data, size_t length);
void yx_ser_validate_memo_end(yx_wire_known *known);
const char *yx_ser_v12_decode_error_detail(void);

/* Locate one orphan UTF-8 continuation byte in an otherwise ASCII
 * identifier-pool string. The returned offset is relative to that string. */
bool yx_ser_ascii_pool_utf8_error(const uint8_t *data, size_t length,
                                  size_t *valid_up_to);
/* Classify one changed identifier-pool count or namespace width byte only
 * when repairing it restores a canonical complete archive. */
bool yx_ser_prefix_pool_utf8_error_detail(const uint8_t *data,
                                           size_t length,
                                           size_t *valid_up_to);

/* For an exact canonical base64 archive prefix cut inside its AC image,
 * report the bytes needed to complete that image. */
bool yx_ser_base64_ac_truncation(const uint8_t *data, size_t length,
                                 size_t *additional);

/* Diagnose a truncated, structurally valid small archive prefix through
 * its identifier and literal pools or its embedded WASM byte vector. */
bool yx_ser_archive_capi_ordered(const uint8_t *data, size_t length);
bool yx_ser_cli_import_order_copy(const uint8_t *data, size_t length,
                                  uint8_t **out);
bool yx_ser_short_prefix_truncation(const uint8_t *data, size_t length,
                                    size_t *additional);

/* Build the YARA-X Aho-Corasick image for a caller-owned sequence of atoms.
 * The returned buffer belongs to the caller and must be freed with free().
 * This internal entry point also supports atom sets larger than the archive
 * codec's currently supported rule shapes. */
bool yx_ser_build_atom_ac(const uint8_t *const *atoms, const size_t *lengths,
                          size_t atom_count, uint8_t **out,
                          size_t *out_length);
/* Between begin and end (nested, per thread), built images are memoized by
 * their atom sequence; the outermost end frees them. */
void yx_ser_ac_memo_begin(void);
void yx_ser_ac_memo_end(void);

typedef enum yx_ser_count_op {
    YX_SER_COUNT_NONE = 0,
    YX_SER_COUNT_GT,
    YX_SER_COUNT_GE,
    YX_SER_COUNT_EQ,
    YX_SER_COUNT_LT,
    YX_SER_COUNT_LE,
    YX_SER_COUNT_NE
} yx_ser_count_op;

typedef struct yx_ser_rule {
    char *namespace_name;
    size_t namespace_index;
    char *identifier;
    bool truth;
    /* A later pattern-free rule can use the first constant rule directly. */
    bool reference_first_rule;
    /* A two-rule program may bind one small integer in its second rule. */
    bool with_integer_eq;
    bool with_first_rule_and_integer_eq;
    int8_t with_bound_value;
    int8_t with_compared_value;
    /* One rule with two scoped integer bindings and a fixed boolean shape. */
    bool with_two_integer_test;
    int8_t with_first_value;
    int8_t with_second_value;
    int8_t with_first_compare;
    int8_t with_second_threshold;
    /* A loaded archive can retain a semantically equivalent AC image. */
    bool noncanonical_ac;
    /* An exact atom can retain a different, unused literal-pool payload. */
    bool noncanonical_literal_pool;
    /* Bytecode can reconstruct an equivalent expression with a different
     * optimization layout. Retain the validated original archive on reload. */
    bool preserve_serialized_prefix;
    bool integer_comparison;
    char *runtime_integer_condition; /* borrowed on encode, owned on decode */
    char *runtime_pattern_declarations; /* owned source declarations on decode */
    yx_archived_literal_prefilter *runtime_literal_prefilters; /* owned per pattern */
    size_t runtime_literal_prefilter_count;
    yx_archived_regexp **runtime_regexp_programs; /* owned per pattern, entries may be NULL */
    size_t runtime_regexp_program_count;
    char *runtime_module_name; /* owned on decode; NULL for expressions without imports */
    char **runtime_module_names; /* owned ordered imports for composed expressions */
    size_t runtime_module_count;
    yx_global *runtime_globals; /* owned external values reconstructed from archive */
    size_t runtime_global_count;
    uint8_t runtime_integer_import_profile;
    /* One fixed-offset integer read compared with an integer literal. */
    bool integer_read_comparison;
    uint8_t integer_read_type; /* uint8/16/32, int8/16/32 */
    int64_t integer_read_offset;
    bool filesize_comparison;
    bool filesize_arithmetic;
    bool filesize_literal_first;
    uint8_t filesize_negations;
    uint8_t filesize_identity_blocks; /* 1: and true, 2: or false */
    bool filesize_double_and;
    bool filesize_double_or;
    int64_t filesize_second_literal;
    uint8_t filesize_second_opcode;
    bool filesize_triple_and;
    bool filesize_triple_and_right_grouped;
    bool filesize_triple_or;
    bool filesize_triple_or_right_grouped;
    bool filesize_mixed_or_and;
    bool filesize_mixed_and_or;
    bool filesize_mixed_and_or_left;
    bool filesize_mixed_or_and_left;
    int64_t filesize_third_literal;
    uint8_t filesize_third_opcode;
    bool filesize_quad_and;
    bool filesize_quad_or;
    int64_t filesize_fourth_literal;
    uint8_t filesize_fourth_opcode;
    bool filesize_five_and;
    bool filesize_five_or;
    int64_t filesize_fifth_literal;
    uint8_t filesize_fifth_opcode;
    bool filesize_six_and;
    bool filesize_six_or;
    int64_t filesize_sixth_literal;
    uint8_t filesize_sixth_opcode;
    bool filesize_seven_and;
    bool filesize_seven_or;
    int64_t filesize_seventh_literal;
    uint8_t filesize_seventh_opcode;
    bool filesize_eight_and;
    bool filesize_eight_or;
    int64_t filesize_eighth_literal;
    uint8_t filesize_eighth_opcode;
    bool pe_imported;
    /* Reconstructed direct cuckoo module-call condition. */
    bool cuckoo_imported;
    char *cuckoo_condition;
    bool vt_imported;
    bool time_now;
    bool math_max_eq;
    bool math_max_not_equal;
    int8_t math_max_first;
    int8_t math_max_second;
    int8_t math_max_compared;
    bool console_pe_log;
    char *console_log_text;
    size_t console_log_length;
    bool pe_is_pe;
    bool pe_is_pe_filesize;
    bool pe_filesize_or;
    bool pe_filesize_first;
    bool pe_filesize_equals_one;
    bool pe_filesize_ge_one;
    bool pe_number_of_sections;
    bool pe_sections_len;
    bool pe_equals_one;
    /* A direct `for any key, value in pe.version_info` string pair. */
    bool pe_version_any;
    bool pe_version_with_any;
    char *pe_version_key;
    size_t pe_version_key_length;
    char *pe_version_value;
    size_t pe_version_value_length;
    bool integer_global_condition;
    bool boolean_global_condition;
    uint8_t boolean_global_blocks; /* 0: direct, 1: and true, 2: or false */
    uint8_t boolean_global_negations; /* outer `not` operators, at most two */
    bool boolean_global_constant;
    bool boolean_global_constant_value;
    bool string_global_condition;
    bool float_global_condition;
    char *global_name;
    int64_t global_value;
    uint8_t global_compare_opcode;
    int64_t global_compare_value;
    bool global_compare_literal_first;
    bool global_boolean_value;
    char *global_string_value;
    size_t global_string_length;
    char *string_compare_literal;
    size_t string_compare_length;
    bool string_compare_literal_first;
    bool string_compare_not_equal;
    double global_float_value;
    double float_compare_value;
    uint8_t float_compare_opcode;
    bool float_compare_literal_first;
    /* One text or fixed-byte hex pattern. Fixed-byte hex additionally
     * supports negation, count comparison, and at offsets.
     * Encoding borrows the bytes; decoding owns a copy. */
    bool single_text_pattern;
    /* 1: `any/all of them`, 2: `1 of them`; each has its own WASM body. */
    uint8_t single_pattern_quantifier;
    bool single_xor_pattern;
    bool single_base64_pattern;
    bool single_base64wide_pattern;
    bool single_base64_input_wide;
    bool single_base64_input_ascii_wide;
    char *single_base64_alphabet;
    yx_base64_archived_prefilter base64_archived_prefilter;
    bool single_regex_literal;
    bool single_regex_dot;
    bool single_regex_dotall;
    bool single_regex_digit_plus;
    bool single_regex_fast;
    bool single_hex_fast;
    bool single_regex_thompson;
    bool single_hex_thompson;
    bool single_hex_pattern;
    /* Two to five hex bytes, one full-byte wildcard at an edge. */
    bool single_hex_wildcard_first;
    bool single_hex_wildcard_last;
    /* Equal fixed runs of one to four bytes around one full wildcard. */
    bool single_hex_wildcard_interior_one;
    bool single_hex_wildcard_interior_masked_one;
    /* Four-byte hex with unequal fixed runs and a selected fixed pair. */
    bool single_hex_wildcard_interior_one_two;
    bool single_hex_wildcard_interior_two_one;
    /* The same shapes with all 256 concrete four-byte atoms selected. */
    bool single_hex_wildcard_interior_masked_one_two;
    bool single_hex_wildcard_interior_masked_two_one;
    /* A selected four-byte masked wildcard atom followed by one nibble
     * byte and optionally one fixed byte. */
    bool single_hex_combined_masked_suffix;
    bool single_hex_wildcard_interior_two;
    bool single_hex_wildcard_interior_three;
    bool single_hex_wildcard_interior_four;
    /* Exactly two hex bytes: one fixed, one nibble-masked (0x0f/0xf0). */
    bool single_hex_nibble_first;
    bool single_hex_nibble_last;
    uint8_t single_hex_nibble_mask;
    /* One nibble byte, optionally next to one full-byte wildcard. */
    bool single_hex_nibble_only;
    bool single_hex_nibble_wildcard_first;
    bool single_hex_nibble_wildcard_last;
    bool negated_single_text_pattern;
    bool at_single_text_pattern;
    bool all_positive_single_text_statistics;
    bool text_presence_offset_equal;
    int8_t text_offset_equal_value;
    bool text_direct_offset_compare;
    uint8_t text_direct_offset_index;
    int8_t text_direct_offset_value;
    bool text_direct_offset_not_equal;
    bool text_direct_length_compare;
    uint8_t text_direct_length_index;
    int8_t text_direct_length_value;
    bool text_direct_length_not_equal;
    bool text_match_in_range;
    uint8_t text_match_range_lower;
    uint8_t text_match_range_upper;
    bool text_presence_count_range_offset;
    uint8_t text_count_range_lower;
    uint8_t text_count_range_upper;
    uint8_t text_count_range_offset;
    uint32_t at_offset;
    yx_ser_count_op count_operator;
    uint32_t count_value;
    bool nocase_single_pattern;
    bool fullword_single_pattern;
    bool wide_single_pattern;
    bool ascii_wide_single_pattern;
    bool two_text_patterns;
    bool two_text_first_nocase;
    bool two_text_second_nocase;
    bool two_text_first_wide;
    bool two_text_second_wide;
    bool two_text_first_ascii_wide;
    bool two_text_second_ascii_wide;
    bool two_text_first_fullword;
    bool two_text_second_fullword;
    /* Both patterns are HEX: fixed, one fixed plus one edge wildcard, or
     * two edge wildcards in the same orientation. */
    bool two_hex_patterns;
    /* Exactly one of the two patterns is HEX. */
    bool two_mixed_hex_first;
    bool two_mixed_hex_last;
    /* One of the two mixed patterns is a single nibble-masked HEX byte. */
    bool two_mixed_masked_first;
    bool two_mixed_masked_last;
    uint8_t two_mixed_masked_mask;
    bool two_mixed_double_nibble_first;
    bool two_mixed_double_nibble_last;
    uint8_t two_mixed_double_nibble_mask[2];
    bool two_mixed_interior_wildcard_first;
    bool two_mixed_interior_wildcard_last;
    uint8_t two_mixed_interior_suffix_mask;
    /* Mixed TEXT/HEX with one edge wildcard and one to four fixed bytes. */
    bool two_mixed_wildcard_first;
    bool two_mixed_wildcard_last;
    bool two_mixed_wildcard_edge_first;
    /* The second HEX pattern can place its wildcard at the other edge. */
    bool two_mixed_wildcard_second_edge_first;
    bool two_regex_dotall_first;
    bool two_regex_dotall_last;
    bool two_text_any;
    bool two_text_and;
    bool two_text_all;
    /* Direct `N of them` over two to four distinct text patterns. */
    uint8_t text_of_required;
    /* Direct `for any of them : ( $ )` over distinct text patterns. */
    bool text_for_any;
    /* Imported one-pattern `for none of them : ( $ )` source shape. */
    bool text_for_none_one;
    /* Imported one-pattern `for all of them : ( $ )` source shape. */
    bool text_for_all_one;
    bool two_text_reverse;
    bool three_text_patterns;
    bool three_mixed_hex_last;
    /* All three patterns are fixed-byte HEX. */
    bool three_hex_patterns;
    bool three_text_any;
    bool three_text_and;
    uint8_t three_text_order[3];
    bool four_text_patterns;
    bool four_mixed_wide_last;
    bool four_text_any;
    bool four_text_and;
    uint8_t four_text_order[4];
    bool five_text_patterns;
    bool five_mixed_nocase_last;
    bool five_text_any;
    bool five_text_and;
    uint8_t five_text_order[5];
    bool six_text_patterns;
    bool six_mixed_ascii_wide_last;
    bool six_text_and;
    uint8_t six_text_order[6];
    bool seven_text_patterns;
    bool seven_mixed_xor_last;
    bool seven_text_and;
    uint8_t seven_text_order[7];
    bool eight_text_patterns;
    bool eight_mixed_base64_last;
    bool eight_text_and;
    uint8_t eight_text_order[8];
    uint8_t multi_literal_regex_mask; /* one bit for each regex among 2..8 */
    char *pattern_identifier;
    uint8_t *pattern_bytes;
    size_t pattern_length;
    char *second_pattern_identifier;
    uint8_t *second_pattern_bytes;
    size_t second_pattern_length;
    char *third_pattern_identifier;
    uint8_t *third_pattern_bytes;
    size_t third_pattern_length;
    char *fourth_pattern_identifier;
    uint8_t *fourth_pattern_bytes;
    size_t fourth_pattern_length;
    char *fifth_pattern_identifier;
    uint8_t *fifth_pattern_bytes;
    size_t fifth_pattern_length;
    char *sixth_pattern_identifier;
    uint8_t *sixth_pattern_bytes;
    size_t sixth_pattern_length;
    char *seventh_pattern_identifier;
    uint8_t *seventh_pattern_bytes;
    size_t seventh_pattern_length;
    char *eighth_pattern_identifier;
    uint8_t *eighth_pattern_bytes;
    size_t eighth_pattern_length;
    int64_t filesize_arith_operand;
    uint8_t filesize_arith_opcode;
    int64_t integer_left;
    int64_t integer_right;
    uint8_t integer_opcode;
    bool is_private;
    bool is_global;
    char **tags;
    size_t tag_count;
    YRX_METADATA *metadata;
    size_t metadata_count;
} yx_ser_rule;

/* True for the literal-only HIR shapes eligible for anchored scanning. */
bool yx_ser_regexp_literal_atoms(const char *regexp);

/* The value of an enum constant of the vt module, by its full path. */
bool yx_ser_vt_enum_constant(const char *name, uint64_t *value);
/* Whether the first `length` bytes of `path` name an enum or a message of
 * the vt module that enum values hang from. */
bool yx_ser_vt_enum_scope(const char *path, size_t length);

yx_ser_result yx_ser_encode(const YRX_RULES *rules, uint8_t **data,
                            size_t *length);
yx_ser_result yx_ser_decode_many(const uint8_t *data, size_t length,
                                  yx_ser_rule **rules, size_t *rule_count);
/* Copy an archive with one structurally valid, noncanonical empty AC image
 * replaced by the canonical image so the strict decoder can verify it. */
yx_ser_result yx_ser_normalize_empty_ac(const uint8_t *data, size_t length,
                                        uint8_t **normalized);
/* True only when repairing one WASM magic/version byte makes the complete
 * archive a supported compiled rule. */
bool yx_ser_has_invalid_wasm_header(const uint8_t *data, size_t length);
/* A single changed byte in the known WASM type-section prefix is malformed
 * only when repairing it makes the complete archive decode canonically. */
bool yx_ser_has_invalid_wasm_type_prefix(const uint8_t *data, size_t length);
/* Recognize a changed one-byte import-section length in the one-pattern WASM
 * only when repairing that byte yields a strictly supported archive. */
bool yx_ser_has_invalid_wasm_import_section_length(const uint8_t *data,
                                                     size_t length);
/* Recognize a zero-length final identifier-pool item only when changing its
 * length to one yields an otherwise canonical one-rule archive. */
bool yx_ser_has_zero_length_final_identifier(const uint8_t *data,
                                              size_t length);
/* Recognize an AC state-count or state-index violation only when repairing
 * one byte yields a strictly supported canonical archive. */
bool yx_ser_has_invalid_ac_structure(const uint8_t *data, size_t length);
/* A single damaged high byte in the 256-state, three-output AC image is
 * classified only when its repair restores a canonical complete archive. */
bool yx_ser_has_invalid_three_atom_ac_node(const uint8_t *data,
                                             size_t length);
/* Classify a nonzero sub-pattern count in a canonical pattern-free rule
 * only after exact one-byte repair and re-encoding. */
bool yx_ser_has_invalid_empty_subpattern_count(const uint8_t *data,
                                                size_t length);
/* True only when one invalid UTF-8 byte in a known length-prefixed WASM name
 * can be repaired to a fully supported canonical archive. */
bool yx_ser_has_invalid_wasm_import_name(const uint8_t *data, size_t length);
/* Normalize one valid UTF-8 byte change in a known WASM import name only
 * when repairing it yields a fully supported canonical archive. The caller
 * retains the original bytes for serialization. */
yx_ser_result yx_ser_normalize_unknown_wasm_import_name(
    const uint8_t *data, size_t length, uint8_t **normalized);
/* Decode an archive whose WASM function imports follow another build's link
 * order: imports are permuted into recorded rank orders (and, for at most six
 * imports, any order) with all function references renumbered, until a
 * canonical decoder accepts it. The caller keeps the original bytes. */
yx_ser_result yx_ser_decode_reordered_imports(const uint8_t *data, size_t length,
                                              yx_ser_rule **rules, size_t *count);
/* Recognize a single malformed WASM local declaration or bitmap shift byte
 * only after strict repair to a supported canonical archive. */
bool yx_ser_has_invalid_wasm_code_byte(const uint8_t *data, size_t length);
typedef enum yx_ser_base64_wasm_error {
    YX_SER_BASE64_WASM_OK = 0,
    YX_SER_BASE64_WASM_PARSE,
    YX_SER_BASE64_WASM_COMPILE
} yx_ser_base64_wasm_error;
/* Classify only the two measured single-byte WASM mutations in a direct,
 * standard-alphabet base64 archive after full canonical repaired decoding. */
yx_ser_base64_wasm_error yx_ser_classify_base64_wasm_error(
    const uint8_t *data, size_t length);
/* Normalize a single-pattern bitmap-index instruction with a semantically
 * equivalent shift immediate; the caller retains the original archive. */
yx_ser_result yx_ser_normalize_single_pattern_bitmap_shift(
    const uint8_t *data, size_t length, uint8_t **normalized);
void yx_ser_rules_destroy(yx_ser_rule *rules, size_t rule_count);
/* Compatibility wrapper for the current single-rule public decoder. */
/* Whether the archive is exactly the one of an empty rule set. */
bool yx_ser_is_empty_rules_archive(const uint8_t *data, size_t length,
                                   const char ***imports, size_t *import_count);
/* Locate the regex-pool policy bit independently of the condition codec. */
bool yx_ser_archive_relaxed_syntax(const uint8_t *data, size_t length, size_t *offset);
yx_ser_result yx_ser_decode(const uint8_t *data, size_t length,
                            yx_ser_rule *rule);
void yx_ser_rule_destroy(yx_ser_rule *rule);

#endif
