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

#ifndef XXYARA_INTERNAL_H
#define XXYARA_INTERNAL_H

#include "yara_x.h"
#include "module_crx.h"
#include "module_lnk.h"
#include "module_zip.h"
#include "module_vt.h"
#include "module_output.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct yx_condition yx_condition;

/* Shared by matching and condition evaluation for one scan (or block series). */
typedef struct yx_scan_deadline {
    uint64_t expires_ns;
    unsigned polls;
    bool enabled;
    bool expired;
    /* Lazy PE indexes share the scanner's per-scan lifetime. */
    struct yx_pe_scan_cache *pe_cache;
} yx_scan_deadline;
bool yx_scan_deadline_reached(yx_scan_deadline *deadline);
/* The clock-reading half of yx_scan_deadline_poll. */
bool yx_scan_deadline_poll_clock(yx_scan_deadline *deadline);
/* Amortize clock reads in tight expression and matcher loops: one clock
 * read per 1024 polls. Inline, because hex and regex matchers poll once per
 * input position or walk step and the call itself dominated those loops. */
static inline bool yx_scan_deadline_poll(yx_scan_deadline *deadline)
{
    if (!deadline || !deadline->enabled) return false;
    if (deadline->expired) return true;
    if (++deadline->polls < 1024) return false;
    return yx_scan_deadline_poll_clock(deadline);
}

typedef enum yx_pattern_kind {
    YX_PATTERN_TEXT,
    YX_PATTERN_HEX,
    YX_PATTERN_REGEX
} yx_pattern_kind;

typedef enum yx_hex_atom_kind {
    YX_HEX_BYTE,
    YX_HEX_JUMP,
    YX_HEX_ALTERNATIVE
} yx_hex_atom_kind;

typedef struct yx_hex_atom yx_hex_atom;

typedef struct yx_hex_sequence {
    yx_hex_atom *atoms;
    size_t count;
} yx_hex_sequence;

struct yx_hex_atom {
    yx_hex_atom_kind kind;
    uint8_t value;
    uint8_t mask;
    bool negated;
    uint32_t minimum;
    uint32_t maximum;
    bool finite_maximum;
    yx_hex_sequence *branches;
    size_t branch_count;
};

typedef enum yx_global_type {
    YX_GLOBAL_BOOL,
    YX_GLOBAL_INT,
    YX_GLOBAL_FLOAT,
    YX_GLOBAL_STR,
    YX_GLOBAL_ARRAY,
    YX_GLOBAL_STRUCT
} yx_global_type;

typedef struct yx_global_array yx_global_array;
typedef struct yx_global_object yx_global_object;

typedef struct yx_global_string {
    char *data;
    size_t length;
} yx_global_string;

/* The three original search atoms in a loaded direct base64 archive whose
 * literal pool was changed after compilation. Offsets are relative to each
 * phase's stable encoded candidate; verification uses the changed literal. */
typedef struct yx_base64_archived_prefilter {
    bool present;
    uint8_t atoms[3][4];
    uint8_t widths[3];
    uint8_t offsets[3];
} yx_base64_archived_prefilter;

/* Owned atom prefilter retained by decoded literals. Exact atoms bypass
 * literal verification; other atoms verify against the stored literal. */
typedef struct yx_archived_literal_atom {
    uint8_t bytes[4];
    size_t length, backtrack;
    bool exact;
} yx_archived_literal_atom;
typedef struct yx_archived_literal_prefilter {
    yx_archived_literal_atom *atoms;
    size_t count;
} yx_archived_literal_prefilter;

/* A regexp sub-pattern program read from a compiled-rules archive: one
 * allocation of `size` bytes holding this header, the atoms of the
 * sub-patterns in order and then the code. Offsets count from the code's
 * first byte. */
typedef struct yx_archived_regexp_atom {
    uint8_t bytes[8];
    uint8_t length;
    bool exact, has_fwd, has_bck;
    uint32_t backtrack, fwd, bck;
} yx_archived_regexp_atom;
typedef struct yx_archived_regexp {
    size_t size, code_length, sub_count;
    unsigned flags[2];
    size_t atom_count[2];
} yx_archived_regexp;

typedef union yx_global_scalar_value {
    bool boolean;
    int64_t integer;
    double floating;
    yx_global_string string;
    yx_global_array *array;
    yx_global_object *object;
} yx_global_scalar_value;

struct yx_global_array {
    yx_global_type element_type;
    yx_global_scalar_value *items;
    size_t count;
};

typedef struct yx_global_field {
    char *name;
    yx_global_type type;
    yx_global_scalar_value value;
} yx_global_field;

struct yx_global_object {
    yx_global_field *fields;
    size_t count;
};

typedef struct yx_global {
    char *name;
    yx_global_type type;
    union {
        bool boolean;
        int64_t integer;
        double floating;
        yx_global_string string;
        yx_global_array *array;
        yx_global_object *object;
    } value;
} yx_global;

enum {
    YX_MOD_ASCII = 1u << 0,
    YX_MOD_WIDE = 1u << 1,
    YX_MOD_NOCASE = 1u << 2,
    YX_MOD_FULLWORD = 1u << 3,
    YX_MOD_XOR = 1u << 4,
    YX_MOD_BASE64 = 1u << 5,
    YX_MOD_BASE64WIDE = 1u << 6,
    YX_MOD_DOTALL = 1u << 7,
    YX_MOD_PRIVATE = 1u << 8
};

struct YRX_PATTERN {
    char *identifier;
    /* Compiler-only source span for diagnostics at the declaration. */
    size_t declaration_start;
    size_t declaration_end;
    /* Source spans retained until rule validation for slow-pattern warnings. */
    size_t literal_start;
    size_t literal_end;
    size_t pattern_end;
    yx_pattern_kind kind;
    unsigned modifiers;
    uint8_t *bytes;
    size_t length;
    /* A hex byte matches when (input & mask) == (bytes & mask). */
    uint8_t *mask;
    yx_hex_atom *hex_atoms;
    size_t hex_atom_count;
    /* Jump, negation, or alternative needs the recursive hex matcher. */
    bool hex_has_jump;
    char *regexp;
    /* Scan-only regexp when YARA-X drops a trailing large any-byte gap. */
    char *gap_head_regexp;
    char *base64_alphabet;
    char *base64wide_alphabet;
    yx_base64_archived_prefilter base64_archived_prefilter;
    yx_archived_literal_prefilter archived_literal_prefilter;
    /* The archive's own program for this pattern, or NULL (owned). */
    yx_archived_regexp *archived_regexp;
    uint8_t xor_min;
    uint8_t xor_max;
    YRX_MATCH *matches;
    size_t match_count;
    size_t match_capacity;
    /* Scanner view aliases may borrow an identical candidate result. */
    bool matches_borrowed;
    struct YRX_PATTERN *scan_duplicate;
    /* YARA-X retains an empty match list across resets for cap-zero scans. */
    bool ever_matched;
    /* Current normal scan found this pattern but cap zero hid its matches. */
    bool zero_limit_present;
    bool fast_scan_needs_all;
    bool fixed_at_enabled;
    size_t fixed_at_offset;
    bool fast_count_enabled;
    size_t fast_count_threshold;
    /* Set only when the complete ruleset has a known literal atom set. */
    size_t global_atom_count_hint;
    /* YARA-X assigns one ID per distinct compiled pattern across rules. */
    size_t compat_pattern_id;
    bool compat_nonanchorable;
    yx_scan_deadline *deadline;
    /* Regexp sub-patterns executed by regex_vm, owned by the compiled rules;
     * scanner views share the pointer read-only. */
    struct yx_rx_program *rx_program;
    /* Exact source provenance for this immutable program. Scanner views
     * borrow the snapshot owned by the compiled rules. */
    char *rx_program_regexp;
    unsigned rx_program_modifiers;
    /* A chain of sub-patterns (serialization_hir_chain.h) built once with the
     * programs, owned by the compiled rules; views share it read-only. */
    struct yx_hc_chain *rx_chain;
    /* Read-only prepared candidate variants, owned by the compiled rules. */
    struct yx_candidate_plan *candidate_plan;
    /* Scanner-owned occurrences for the shared regexp verifier. */
    struct yx_rx_candidate *candidate_hits;
    size_t candidate_hit_count, candidate_hit_capacity;
    bool candidate_hits_overflow;
    /* Gate plans: candidate_hits lists every verified branch start unless
     * candidate_gate_dropped (an occurrence was not kept; the full scanner
     * then searches the whole input). candidate_gate_starts is set only
     * while that full scan runs from the sorted list. */
    bool candidate_gate_dropped;
    bool candidate_gate_starts;
    /* Scanner views only: the reference's atom order for rx_program's atoms
     * (global atom ids and Teddy buckets), owned by the view. */
    size_t *rx_order_ids, *rx_order_buckets;
    bool rx_teddy;
    size_t rx_teddy_minimum;
    /* Scanner views only: owner index in the scanner's text prefilter, or
     * SIZE_MAX when the pattern is always scanned. */
    size_t prefilter_owner;
};
/* Releases a pattern's rx_chain (serialization_hir_chain.h). */
void yx_ser_chain_free(struct yx_hc_chain *chain);

struct YRX_RULE {
    char *identifier;
    char *namespace_name;
    size_t namespace_name_length;
    /* A name can recur after another namespace; each transition is a new scope. */
    size_t namespace_index;
    /* Compiler-only provenance for duplicate-rule diagnostics. */
    char *declaration_line;
    char *declaration_origin;
    bool declaration_origin_explicit;
    size_t declaration_line_number;
    size_t declaration_column;
    size_t declaration_start;
    size_t declaration_end;
    size_t declaration_source_serial;
    bool is_private;
    bool is_global;
    char **tags;
    size_t tag_count;
    YRX_METADATA *metadata;
    size_t metadata_count;
    YRX_PATTERN *patterns;
    size_t pattern_count;
    yx_condition *condition;
    char *condition_text;
    bool matched;
};

struct YRX_RULES {
    YRX_RULE *rules;
    size_t rule_count;
    /* Allocated length of rules while a compiler appends to it; any other
     * owner leaves it zero or smaller than rule_count. */
    size_t rule_capacity;
    char **imports;
    size_t import_count;
    /* Preserve declaration position for canonical namespace/import interning. */
    size_t *import_rule_indices;
    size_t *import_namespace_indices;
    char **import_namespaces;
    /* Owned names for every namespace generation, including empty scopes. */
    char **namespace_names;
    size_t namespace_count;
    char *source;
    uint8_t *serialized_prefix;
    size_t serialized_prefix_length;
    bool unknown_wasm_import;
    yx_global *globals;
    size_t global_count;
    /* CLI and C API reference builds register runtime imports differently. */
    bool archive_cli;
    bool relaxed_re_syntax;
};

typedef struct yx_module_policy {
    char *name;
    char *ban_title;
    char *ban_message;
    bool ignored;
} yx_module_policy;

typedef struct yx_ignored_import {
    char *module;
    char *namespace_name;
    size_t namespace_index;
} yx_ignored_import;

typedef struct yx_ignored_rule {
    char *name;
    char *namespace_name;
    char *module;
    /* The ignored rule it depends on (IgnoredRuleReason::IgnoredRule), or
     * NULL when it uses the ignored module directly (IgnoredModule). */
    char *parent;
    size_t namespace_index;
} yx_ignored_rule;

/* The spans a rendered `help:` patch replaces, for YRX_COLORIZE_ERRORS. */
typedef struct yx_patch_note {
    char *rows;
    size_t mark_count;
    size_t marks[16][3];
} yx_patch_note;

/* A source being parsed whose NUL bytes were escaped; see xxyara.c. */
typedef struct yx_nul_escape_entry yx_nul_escape_entry;

struct YRX_COMPILER {
    uint32_t flags;
    YRX_RULES *rules;
    /* Earlier rule names for type warnings; see yx_rule_name_cache. */
    struct yx_rule_name_cache *rule_name_cache;
    /* A duplicate definition replaces runtime values but not compiler symbols. */
    yx_global *redefined_global_symbols;
    size_t redefined_global_symbol_count;
    char **enabled_features;
    size_t enabled_feature_count;
    char *current_namespace;
    size_t current_namespace_index;
    size_t next_source_serial;
    bool current_origin_explicit;
    char **include_dirs;
    size_t include_dir_count;
    char **include_stack;
    size_t include_depth;
    yx_module_policy *module_policies;
    size_t module_policy_count;
    yx_ignored_import *ignored_imports;
    size_t ignored_import_count;
    yx_ignored_rule *ignored_rules;
    size_t ignored_rule_count;
    char **warnings;
    size_t warning_count;
    size_t max_warnings;
    /* For the current rule's typed warnings raised after their operands
     * (non_bool_expr, unused_identifier): the source offset at which
     * YARA-X raises each one, keyed by the warning's text. The text-based
     * deprecated_field pass merges its warnings by these points. */
    const char **warning_point_keys;
    size_t *warning_point_values;
    size_t warning_point_count;
    size_t warning_point_capacity;
    char *error_diagnostic_json;
    /* NUL escapes of the sources being parsed, innermost include first,
     * and the coordinates of the diagnostic JSON being built. */
    yx_nul_escape_entry *nul_escapes;
    unsigned char nul_json_space;
    yx_patch_note *patch_notes;
    size_t patch_note_count;
    /* Global rules among rules->rules[0 .. global_rules_scanned): the rules
     * only grow until build replaces them, which resets both counts. */
    size_t global_rules_scanned, global_rule_count;
    char error[1024];
};

/* Borrowed until the next scan, matching yrx_scanner_set_module_data. */
typedef struct yx_scanner_module_data {
    const char *name;
    const uint8_t *data;
    size_t size;
} yx_scanner_module_data;

#ifdef XXYARA_ENABLE_PROFILING
typedef struct yx_rule_profile {
    uint64_t pattern_nanoseconds;
    uint64_t condition_nanoseconds;
} yx_rule_profile;
#endif

struct YRX_SCANNER {
    const YRX_RULES *rules;
    YRX_RULE *views;
    /* Reused condition context arrays; owned by this scanner. */
    struct yx_scanner_eval_scratch *eval_scratch;
    /* One-pass atom prefilter over literal text patterns; a pattern whose
     * atoms do not occur cannot match and is not scanned. */
    struct yx_atom_set *text_prefilter;
    bool *text_prefilter_hit;
    YRX_PATTERN **candidate_patterns;
    size_t candidate_pattern_count;
    YRX_RULE_CALLBACK callback;
    void *callback_data;
    size_t max_matches_per_pattern;
    bool fast_scan;
    bool block_mode;
    uint64_t timeout_seconds;
    /* Zero is a deadline only after yrx_scanner_set_timeout was called. */
    bool timeout_configured;
    yx_scan_deadline deadline;
    YRX_CONSOLE_CALLBACK console_callback;
    bool console_c_string;
    uint8_t *block_data;
    size_t block_size;
    yx_global *globals;
    size_t global_count;
    yx_scanner_module_data *module_data;
    size_t module_data_count;
    /* Narrow imported module boolean overrides, consumed by the next scan. */
    bool pe_output_present;
    bool pe_output_is_pe;
    uint32_t *pe_output_languages;
    size_t pe_output_language_count;
    bool lnk_output_present;
    bool lnk_output_is_lnk;
    bool crx_output_present;
    yx_crx_result crx_output;
    bool zip_output_present;
    yx_zip_result zip_output;
    yx_vt_record *vt_output;
    yx_mo_record *module_outputs[YX_MO_MODULE_COUNT];
    yx_mo_record *last_module_outputs[YX_MO_MODULE_COUNT];
    bool empty_module_outputs[3]; /* hash, math, magic: pending native-main bypass */
    yx_lnk_result native_lnk_output;
    yx_crx_result native_crx_output;
    yx_zip_result native_zip_output;
    bool native_lnk_output_present;
    bool native_crx_output_present;
    bool native_zip_output_present;
    uint8_t *native_module_scan_data;
    size_t native_module_scan_size;
    /* Whether a normal scan copies its input into native_module_scan_data
     * for later block evaluation; xxyara_scanner_retain_scan_data(). */
    bool retain_scan_data;
    bool dex_output_present;
    bool dex_output_is_dex;
    bool dex_output_header_present[27];
    uint32_t dex_output_header_values[27];
    bool dex_output_map_size_present;
    uint32_t dex_output_map_size;
    size_t dex_output_collection_counts[10];
    bool dex_output_map_list_present;
    uint8_t *dex_output_header_signature;
    size_t dex_output_header_signature_length;
    bool dex_output_header_signature_present;
    uint8_t *dex_output_data;
    size_t dex_output_data_size;
#ifdef XXYARA_ENABLE_PROFILING
    /* Indexed by the compiled rule's position; retained across scans. */
    yx_rule_profile *rule_profiles;
    /* Rule position of each candidate_patterns owner. */
    size_t *candidate_rule_index;
#endif
    /* Namespaces in the order a rule of theirs first matched, over every
     * scan of this scanner: YARA-X reports matching rules grouped in this
     * order (scanner/context.rs matching_rules_per_ns). */
    bool *namespace_seen;
    size_t *namespace_order;
    size_t namespace_order_count;
    size_t namespace_capacity;
};

/* The parser appends all successfully parsed rules to compiler->rules. */
YRX_RESULT yx_parse_source(YRX_COMPILER *compiler, const char *source, const char *origin);
YRX_RESULT yx_compiler_add_source_bytes(YRX_COMPILER *compiler,
                                        const uint8_t *source, size_t length,
                                        const char *origin);
/* Sources of `limit` bytes or more fail with "source file is too large"
 * (YARA-X: u32::MAX). Tests lower the limit; 0 restores the default. */
void yx_set_source_size_limit(size_t limit);
size_t yx_get_source_size_limit(void);
void yx_compiler_first_source_error(YRX_COMPILER *compiler, size_t start);
/* Relaxed regexp syntax (YRX_RELAXED_RE_SYNTAX) for the condition being
 * compiled, and the normalization it applies to a regexp body. */
extern _Thread_local bool yx_condition_relaxed_regexps;
extern _Thread_local bool yx_deserialize_error_detail;
char *yx_normalize_regexp_braces(const char *body, bool relaxed);
void yx_compiler_order_source_diagnostics(YRX_COMPILER *compiler,
                                          size_t start, const char *origin);
YRX_RESULT yx_include_source(YRX_COMPILER *compiler, const char *filename,
                             size_t filename_length, const char *source,
                             const char *origin, size_t include_line,
                             size_t include_start, size_t include_end);
/* Import policy: 0 means fatal error, 1 accepted, 2 ignored, 3 unknown. */
int yx_compiler_check_import(YRX_COMPILER *compiler, const char *module,
                             const char *source, const char *origin,
                             size_t start, size_t end);
int yx_compiler_unknown_identifier_error(YRX_COMPILER *compiler,
                                          const char *identifier,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end);
int yx_compiler_unknown_module_field_error(YRX_COMPILER *compiler,
                                            const char *field,
                                            const char *source,
                                            const char *origin,
                                            size_t start, size_t end);
int yx_compiler_custom_error(YRX_COMPILER *compiler,
                              const char *title, const char *label,
                              const char *source, const char *origin,
                              size_t start, size_t end);
int yx_compiler_vt_acl_error(YRX_COMPILER *compiler,
                              const char *field,
                              const char *source,
                              const char *origin,
                              size_t start, size_t end);
int yx_compiler_entrypoint_unsupported_error(YRX_COMPILER *compiler,
                                             const char *source,
                                             const char *origin,
                                             size_t start, size_t end);
int yx_compiler_duplicate_pattern_error(YRX_COMPILER *compiler,
                                        const char *identifier,
                                        const char *source,
                                        const char *origin,
                                        size_t duplicate_start,
                                        size_t duplicate_end,
                                        size_t existing_start,
                                        size_t existing_end);
int yx_compiler_duplicate_pattern_value_warning(
    YRX_COMPILER *compiler, const char *identifier,
    const char *source, const char *origin,
    size_t duplicate_start, size_t duplicate_end,
    size_t existing_start, size_t existing_end);
int yx_compiler_duplicate_import_warning(
    YRX_COMPILER *compiler, const char *module, const char *source,
    const char *origin, size_t first_start, size_t first_end,
    size_t duplicate_start, size_t duplicate_end);
int yx_compiler_too_many_patterns_error(YRX_COMPILER *compiler,
                                        const char *source,
                                        const char *origin,
                                        size_t start, size_t end);
int yx_compiler_include_error(YRX_COMPILER *compiler, const char *source,
                              const char *origin, size_t start, size_t end,
                              const char *error);
int yx_compiler_condition_too_large_error(YRX_COMPILER *compiler,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end);
int yx_compiler_mixed_greediness_error(YRX_COMPILER *compiler,
                                      const char *source,
                                      const char *origin,
                                      size_t greedy_start,
                                      size_t greedy_end,
                                      size_t lazy_start,
                                      size_t lazy_end);
int yx_compiler_duplicate_tag_error(YRX_COMPILER *compiler,
                                    const char *tag,
                                    const char *source,
                                    const char *origin,
                                    size_t start, size_t end);
int yx_compiler_unknown_pattern_error(YRX_COMPILER *compiler,
                                      const char *pattern,
                                      const char *source,
                                      const char *origin,
                                      size_t start, size_t end);
int yx_compiler_unused_pattern_error(YRX_COMPILER *compiler,
                                    const char *pattern,
                                    const char *source,
                                    const char *origin,
                                    size_t start, size_t end);
int yx_compiler_empty_pattern_set_error(YRX_COMPILER *compiler,
                                        const char *source,
                                        const char *origin,
                                        size_t start, size_t end,
                                        const char *note);
int yx_compiler_unexpected_negative_error(YRX_COMPILER *compiler,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end);
int yx_compiler_invalid_escape_error(YRX_COMPILER *compiler,
                                     const char *source,
                                     const char *origin,
                                     size_t start, size_t end,
                                     bool hexadecimal);
int yx_compiler_invalid_regexp_error(YRX_COMPILER *compiler,
                                     const char *source,
                                     const char *origin,
                                     size_t start, size_t end,
                                     const char *label,
                                     const char *note);
int yx_compiler_arbitrary_regexp_prefix_error(YRX_COMPILER *compiler,
                                              const char *source,
                                              const char *origin,
                                              size_t start, size_t end);
int yx_compiler_invalid_pattern_error(YRX_COMPILER *compiler,
                                      const char *identifier,
                                      const char *source,
                                      const char *origin,
                                      size_t start, size_t end,
                                      const char *label,
                                      const char *note);
int yx_compiler_invalid_integer_error(YRX_COMPILER *compiler,
                                      const char *source,
                                      const char *origin,
                                      size_t start, size_t end,
                                      const char *range);
int yx_compiler_number_out_of_range_error(YRX_COMPILER *compiler,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end,
                                          const char *range);
int yx_compiler_invalid_range_error(YRX_COMPILER *compiler,
                                    const char *source,
                                    const char *origin,
                                    size_t start, size_t end,
                                    int64_t lower, int64_t upper);
int yx_compiler_unexpected_escape_sequence_error(YRX_COMPILER *compiler,
                                                 const char *source,
                                                 const char *origin,
                                                 size_t start, size_t end);
int yx_compiler_invalid_base64_alphabet_error(YRX_COMPILER *compiler,
                                              const char *source,
                                              const char *origin,
                                              size_t start, size_t end,
                                              const char *label);
int yx_compiler_duplicate_modifier_error(YRX_COMPILER *compiler,
                                         const char *source,
                                         const char *origin,
                                         size_t start, size_t end);
int yx_compiler_invalid_modifier_error(YRX_COMPILER *compiler,
                                       const char *source,
                                       const char *origin,
                                       size_t start, size_t end,
                                       const char *label);
int yx_compiler_invalid_regexp_modifier_error(YRX_COMPILER *compiler,
                                              const char *source,
                                              const char *origin,
                                              size_t start, size_t end);
int yx_compiler_invalid_modifier_combination_error(
    YRX_COMPILER *compiler, const char *source, const char *origin,
    const char *first, size_t first_start, size_t first_end,
    const char *second, size_t second_start, size_t second_end);
int yx_compiler_wrong_type_error(YRX_COMPILER *compiler,
                                 const char *source,
                                 const char *origin,
                                 size_t start, size_t end,
                                 const char *expected,
                                 const char *actual);
int yx_compiler_wrong_type_help_error(YRX_COMPILER *compiler,
                                      const char *source,
                                      const char *origin,
                                      size_t start, size_t end,
                                      const char *expected,
                                      const char *actual,
                                      const char *help);
int yx_compiler_nonbool_function_warning(YRX_COMPILER *compiler,
                                         const char *source,
                                         const char *origin,
                                         size_t start, size_t end);
int yx_compiler_wrong_arguments_error(YRX_COMPILER *compiler,
                                      const char *source,
                                      const char *origin,
                                      size_t start, size_t end,
                                      const char *note);
int yx_compiler_mismatching_types_error(YRX_COMPILER *compiler,
                                       const char *source,
                                       const char *origin,
                                       size_t first_start, size_t first_end,
                                       const char *first_type,
                                       size_t second_start, size_t second_end,
                                       const char *second_type);
int yx_compiler_assignment_mismatch_error(YRX_COMPILER *compiler,
                                          const char *source,
                                          const char *origin,
                                          size_t binding_start,
                                          size_t binding_end,
                                          size_t binding_count,
                                          size_t iterable_start,
                                          size_t iterable_end,
                                          size_t iterable_count);
int yx_compiler_method_binding_error(YRX_COMPILER *compiler,
                                      const char *source,
                                      const char *origin,
                                      size_t start, size_t end);
int yx_compiler_syntax_error(YRX_COMPILER *compiler,
                             const char *source,
                             const char *origin,
                             size_t start, size_t end,
                             const char *label);
int yx_compiler_too_many_variables_error(YRX_COMPILER *compiler,
                                         const char *source,
                                         const char *origin,
                                         size_t start, size_t end);
int yx_compiler_warn_deprecated_before(YRX_COMPILER *compiler,
                                       const char *condition,
                                       const char *source, const char *origin,
                                       size_t condition_offset, size_t limit);
bool yx_compiler_json_span(const YRX_COMPILER *compiler, const char *span,
                           size_t *start, size_t *end);
bool yx_compiler_semantic_error_end(const YRX_COMPILER *compiler,
                                    size_t mark, size_t *end);
bool yx_compiler_semantic_error_span(const YRX_COMPILER *compiler,
                                     size_t mark, size_t *start, size_t *end);
void yx_compiler_drop_warnings_after(YRX_COMPILER *compiler, size_t first,
                                     size_t error_mark, size_t error_start,
                                     size_t error_end);
int yx_compiler_consecutive_jumps_warning(YRX_COMPILER *compiler,
                                          const char *identifier,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end,
                                          uint64_t lower, uint64_t upper,
                                          bool has_lower, bool has_upper);
int yx_compiler_text_as_hex_warning(YRX_COMPILER *compiler,
                                    const YRX_PATTERN *pattern,
                                    const char *source,
                                    const char *origin,
                                    size_t start, size_t end);
YRX_RESULT yx_compile_quiet(const char *source, YRX_RULES **out);
/* Between begin and end (nested, per thread), compiled and deserialized
 * rules are inspected only: their scanner programs and candidate plans are
 * not built. The loader brackets its internal loads with them. */
void yx_inspect_begin(void);
void yx_inspect_end(void);
/* Parallel loops of the loader. yx_parallel_threads gives the threads for
 * count independent items, at least per_thread items each: 1 inside a
 * parallel loop (nested loops run on their thread), else the logical
 * processors, or the positive RAYON_NUM_THREADS of the environment (the
 * knob that sets YARA-X's own thread count). yx_parallel_run calls
 * fn(i, context) once for each i in [0, count) on that many threads; the
 * calls must write only their own results. */
unsigned yx_parallel_threads(size_t count, size_t per_thread);
void yx_parallel_run(size_t count, unsigned threads, void (*fn)(size_t index, void *context), void *context);
/* As yx_parallel_run, with its own serial start (serial_ns) and measured
 * work per helper (thread_ns), for loops of a few milliseconds. */
void yx_parallel_run_ex(size_t count, unsigned threads, uint64_t serial_ns, uint64_t thread_ns,
                        void (*fn)(size_t index, void *context), void *context);
#ifdef XXYARA_VERIFY_LOAD
/* Verify builds: whether two compiled patterns agree in every field the
 * parser sets. */
bool yx_verify_pattern(const YRX_PATTERN *a, const YRX_PATTERN *b);
#endif
/* fn(context) on another thread while the caller goes on, when two threads
 * are available (yx_parallel_threads); otherwise it runs at once on the
 * caller and the result is NULL. yx_async_wait (NULL is a no-op) returns
 * after fn has returned; the caller then keeps fn's memoized results. */
typedef struct yx_async yx_async;
yx_async *yx_async_start(void (*fn)(void *context), void *context);
void yx_async_wait(yx_async *task);
/* `compiled` false: the literal check Compiler::c_rule runs over every
 * pattern; true: the c_regexp check of a regexp or hex pattern the rule
 * compiles. */
int yx_compiler_slow_pattern_warning(YRX_COMPILER *compiler,
                                     const YRX_RULE *rule,
                                     const YRX_PATTERN *pattern,
                                     const char *source,
                                     const char *origin,
                                     bool compiled);
int yx_compiler_potentially_slow_loop_warning(YRX_COMPILER *compiler,
                                              const char *source,
                                              const char *origin,
                                              size_t start, size_t end);
int yx_compiler_unused_identifier_warning(YRX_COMPILER *compiler,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end);
int yx_compiler_too_many_iterations_warning(YRX_COMPILER *compiler,
                                            const char *source,
                                            const char *origin,
                                            size_t start, size_t end,
                                            uint64_t iterations);
int yx_compiler_unsatisfiable_pattern_at_warning(
    YRX_COMPILER *compiler, const char *source, const char *origin,
    size_t quantifier_start, size_t quantifier_end,
    size_t at_start, size_t at_end);
int yx_compiler_unsatisfiable_pair_warning(
    YRX_COMPILER *compiler, const char *source, const char *origin,
    size_t first_start, size_t first_end, const char *first_label,
    size_t second_start, size_t second_end, const char *second_label);
/* `start`..`quantifier_end` is the zero quantifier the help replaces with
 * `none`; the label covers `start`..`end`. */
int yx_compiler_ambiguous_expr_warning(YRX_COMPILER *compiler,
                                       const char *source,
                                       const char *origin,
                                       size_t start, size_t quantifier_end,
                                       size_t end);
/* invariant_expr of `<n> of <items>` with n above the number of items,
 * raised at source position `raised`. */
int yx_compiler_excess_quantifier_warning(YRX_COMPILER *compiler,
                                          const char *source,
                                          const char *origin,
                                          size_t start, size_t end,
                                          size_t raised, int64_t required,
                                          size_t available);
/* Records that the warning added since `count` warnings was raised at
 * source position `raised`. */
bool yx_compiler_warning_raised_at(YRX_COMPILER *compiler, size_t count,
                                   size_t raised);
int yx_compiler_nonbool_integer_warning(YRX_COMPILER *compiler,
                                        const char *source,
                                        const char *origin,
                                        size_t start, size_t end);
int yx_compiler_unintended_pattern_in_set_warning(
    YRX_COMPILER *compiler, const char *source, const char *origin,
    const char *pattern_name, const char *set_name, size_t set_name_length,
    const char *first_name, size_t first_name_length, bool first_wildcard,
    size_t first_start, size_t first_end,
    const char *second_name, size_t second_name_length, bool second_wildcard,
    size_t second_start, size_t second_end);
int yx_compiler_redundant_case_modifier_warning(YRX_COMPILER *compiler,
                                                const char *source,
                                                const char *origin,
                                                size_t suffix_start,
                                                size_t nocase_start,
                                                size_t nocase_end);
int yx_compiler_conflicting_rule_error(YRX_COMPILER *compiler,
                                       const char *identifier,
                                       const char *source,
                                       const char *origin,
                                       size_t start, size_t end);
int yx_compiler_duplicate_rule_error(YRX_COMPILER *compiler,
                                     const YRX_RULE *duplicate,
                                     const YRX_RULE *existing,
                                     const char *source);
/* Returns 1 if the rule is skipped, 0 if it is compiled, -1 on error. */
int yx_compiler_skip_ignored_rule(YRX_COMPILER *compiler,
                                  const char *condition,
                                  const char *rule_name,
                                  const char *namespace_name,
                                  const char *source,
                                  const char *origin,
                                  size_t condition_offset);
/* Records warnings for conditions whose truth value is fixed at compile time. */
int yx_compiler_type_warning(YRX_COMPILER *compiler,
    const char *source, const char *origin, const char *kind,
    size_t start, size_t end, size_t other_start, size_t other_end,
    const char *type);
int yx_compiler_warn_invariant_condition(YRX_COMPILER *compiler,
                                         const char *condition,
                                         const YRX_RULE *rule,
                                         const char *source,
                                         const char *origin,
                                         size_t condition_offset,
                                         size_t first_type_warning);
void yx_free_rule(YRX_RULE *rule);
void yx_free_rules(YRX_RULES *rules);

/* The scanner stores matches in pattern. Exact literals use xxfclib search. */
YRX_RESULT yx_scan_pattern(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                           size_t max_matches, bool fast_scan);

/* Searches and verifies all three base64 alignment permutations. The
 * function appends matches to pattern->matches and returns 0 on failure. */
int yx_scan_base64(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                   size_t limit, bool first_only);

/* Returns 1 for a nonempty regex, 0 when it can match an empty input,
 * and -1 for an invalid regex or matcher failure. */
int yx_validate_regex(const YRX_PATTERN *pattern);
/* True when one repeated byte class alone disables the small Teddy path. */
bool yx_regex_many_single_byte_atoms(const YRX_PATTERN *pattern);
/* Shared YARA-X regex shape checks for pattern and condition regexes. */
int yx_regex_validate_shape(const char *regexp, bool dotall,
                            bool matches_expr);
/* YARA-X's E045 check for a /s regexp: true when its outermost
 * concatenation starts with an arbitrary-length run of any byte; the span
 * (offsets into regexp) is stored when requested. */
bool yx_regex_arbitrary_prefix(const char *regexp, size_t length, bool dotall,
                               size_t *start, size_t *end);
/* Condition regexes use a 50 MiB regex-automata NFA budget. */
bool yx_regex_automata_size_large(const char *body, size_t length,
                                  unsigned modifiers);
bool yx_regex_nesting_error(const char *body, size_t length,
                            size_t *start, size_t *width);
bool yx_regex_can_match_empty(const char *body, size_t length,
                              unsigned modifiers);
/* First syntax error of regex-syntax's AST parser (regex_ast_error.inc): a
 * label, a byte span in the body (empty when start == end) and a note. */
typedef struct {
    size_t start, end;
    const char *label;
    char note[128];
} yx_regex_ast_err;
bool yx_regex_ast_error(const char *body, size_t length,
                        yx_regex_ast_err *out);
/* Report syntax errors in inline flag groups containing the CRLF flag. */
int yx_regex_inline_r_flag_error(const char *regexp, size_t length,
                                 size_t *error_at, const char **error_label);
/* Alphabetic escapes rejected by regex-syntax in both pattern contexts. */
bool yx_regex_unrecognized_escape(unsigned char escaped);
/* Compile-only copy with valid x-mode hex escapes made contiguous. */
char *yx_regex_compact_extended_hex(const char *regexp);
/* Compile-only copy with quantified multi-byte UTF-8 literals grouped. */
char *yx_regex_group_utf8_literals(const char *regexp);

/* The native CLI preserves byte-counted logs and permits NULL to disable. */
YRX_RESULT yx_scanner_on_console_log_raw(YRX_SCANNER *scanner,
                                       YRX_CONSOLE_CALLBACK callback);

/* Per-thread memo of pure compile-time results (thread_storage.h; one table
 * per thread, in match.c). A tag names the function (YX_MEMO_TAG) and holds
 * its scalar inputs; the key is its text. Lookups return the stored value,
 * valid until the next store; values are at most 4 KiB. */
enum {
    YX_MEMO_VALIDATE_REGEX = 1,
    YX_MEMO_PIKE_SIZE = 2,
    YX_MEMO_SLOW_PATTERN = 3,
    YX_MEMO_MANY_SINGLE_BYTE_ATOMS = 4,
    YX_MEMO_REGEXP_LITERAL_ATOMS = 5
};
#define YX_MEMO_TAG(function, flags, modifiers) \
    (((uint64_t)(function) << 48) | ((uint64_t)(flags) << 32) | (uint64_t)(uint32_t)(modifiers))
const void *yx_compile_memo_find(uint64_t tag, const void *key, size_t key_length,
                                 size_t *value_length);
void yx_compile_memo_store(uint64_t tag, const void *key, size_t key_length,
                           const void *value, size_t value_length);
/* The calling thread's compile memo and memoized regexp compilations, moved
 * out (NULL without memory), and merged into another thread's memos there.
 * A parallel loop's helpers hand theirs to the calling thread. */
struct yx_compile_memos;
struct yx_compile_memos *yx_compile_memos_take(void);
void yx_compile_memos_merge(struct yx_compile_memos *taken);
/* The merge in two steps: the adoption by the calling thread, then the
 * release of what it did not keep, which touches `taken` only. */
void yx_compile_memos_adopt(struct yx_compile_memos *taken);
size_t yx_compile_memos_leftover(const struct yx_compile_memos *taken);
void yx_compile_memos_release(struct yx_compile_memos *taken);
/* match.c: a regexp plan copied for a pattern with the same plan inputs. */
struct yx_candidate_plan *yx_candidate_plan_clone(const struct yx_candidate_plan *plan,
                                                  const YRX_PATTERN *pattern);

#endif
