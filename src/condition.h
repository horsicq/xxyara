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

#ifndef XXYARA_CONDITION_H
#define XXYARA_CONDITION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/yara_x.h"
#include "module_crx.h"
#include "module_lnk.h"
#include "module_zip.h"
#include "module_vt.h"
#include "module_output.h"

#ifdef __cplusplus
extern "C" {
#endif

void yx_condition_module_cache_reset(const char *module);

/* Defined by the C API layer (xxyara.c), which is the only file built with
 * or without the test-only test_proto2/test_proto3 modules. */
extern const bool yx_test_proto_modules_enabled;

typedef struct yx_condition yx_condition;
typedef struct yx_global yx_global;
typedef struct yx_global_object yx_global_object;
typedef struct yx_eval_string_arena yx_eval_string_arena;
typedef struct yx_cuckoo_report yx_cuckoo_report;
typedef struct yx_scan_deadline yx_scan_deadline;
typedef bool (*yx_condition_identifier_resolver)(void *user_data,
                                                  const char *identifier);

typedef struct yx_eval_match_list {
    const YRX_MATCH *matches;
    size_t count;
    bool present;
} yx_eval_match_list;

typedef enum yx_eval_global_type {
    YX_EVAL_GLOBAL_BOOL,
    YX_EVAL_GLOBAL_INT,
    YX_EVAL_GLOBAL_FLOAT,
    YX_EVAL_GLOBAL_STRING,
    YX_EVAL_GLOBAL_ARRAY,
    YX_EVAL_GLOBAL_STRUCT
} yx_eval_global_type;

typedef struct yx_eval_global_array {
    int element_type;
    const void *items;
    size_t count;
} yx_eval_global_array;

typedef struct yx_eval_global {
    const char *name;
    yx_eval_global_type type;
    union {
        bool boolean;
        int64_t integer;
        double floating;
        struct {
            const char *data;
            size_t length;
        } string;
        yx_eval_global_array array;
        const yx_global_object *object;
    } value;
} yx_eval_global;

/* Pattern names omit the leading '$'. The parallel arrays each have
 * pattern_count entries. Rule values are used for references to earlier rules.
 * Globals are checked before rule names when resolving a bare identifier.
 */
typedef struct yx_eval_context {
    const uint8_t *data;
    size_t size;
    const char *test_proto2_metadata;
    size_t test_proto2_metadata_length;
    bool test_proto2_metadata_present;
    bool block_mode;
    const char *const *pattern_names;
    const yx_eval_match_list *patterns;
    const size_t *pattern_ids;
    size_t pattern_count;
    const char *const *rule_names;
    const bool *rule_values;
    size_t rule_count;
    const yx_eval_global *globals;
    size_t global_count;
    YRX_CONSOLE_CALLBACK console_callback;
    bool console_c_string;
    /* Parsed per-scan metadata. The scanner consumes it after evaluation. */
    const yx_cuckoo_report *cuckoo_report;
    bool pe_output_present;
    bool pe_output_is_pe;
    const uint32_t *pe_output_languages;
    size_t pe_output_language_count;
    bool lnk_output_present;
    bool lnk_output_is_lnk;
    const yx_lnk_result *lnk_output;
    bool crx_output_present;
    const yx_crx_result *crx_output;
    bool zip_output_present;
    const yx_zip_result *zip_output;
    const yx_vt_record *vt_output;
    const yx_mo_record *module_outputs[YX_MO_MODULE_COUNT];
    yx_mo_function_cache *module_function_cache;
    bool dex_output_present;
    bool dex_output_is_dex;
    bool dex_output_header_present[27];
    uint32_t dex_output_header_values[27];
    bool dex_output_map_size_present;
    uint32_t dex_output_map_size;
    size_t dex_output_collection_counts[10];
    bool dex_output_map_list_present;
    const uint8_t *dex_output_header_signature;
    size_t dex_output_header_signature_length;
    bool dex_output_header_signature_present;
    const uint8_t *dex_output_data;
    size_t dex_output_data_size;
    /* The scanner's deadline also covers nested condition loops. */
    yx_scan_deadline *deadline;
    /* Optional scanner-owned scratch. Evaluations reuse its instruction and
     * name-table storage, while temporary module/string results are reset. */
    yx_eval_string_arena *string_arena;
} yx_eval_context;

/* Byte length of the message currently passed to a console callback. The
 * CLI uses this to retain embedded NUL bytes in console output. */
size_t yx_console_current_log_length(void);

yx_condition *yx_condition_compile(const char *expression, char *error,
                                   size_t error_capacity);
/* Retains the partially folded tree for warnings preceding a fold error.
 * The caller owns *failed when non-NULL. Syntax failures leave it NULL. */
yx_condition *yx_condition_compile_diagnostics(const char *expression, char *error,
                                   size_t error_capacity, yx_condition **failed);
typedef bool (*yx_condition_type_warning_callback)(const char *kind,
    size_t start, size_t end, size_t other_start, size_t other_end,
    const char *type, void *user);
/* Earlier rule names of a namespace, cached across rules by the caller. */
typedef struct yx_rule_name_cache yx_rule_name_cache;
void yx_rule_name_cache_free(yx_rule_name_cache *cache);
/* Whether rules has a rule called name in namespace_index. */
bool yx_rule_name_cache_contains(yx_rule_name_cache **cache, const YRX_RULES *rules,
                                 size_t namespace_index, const char *name, bool *found);
bool yx_condition_visit_type_warnings(const yx_condition *condition,
    const char *const *imports, size_t import_count,
    const YRX_RULES *rules, size_t namespace_index, yx_rule_name_cache **cache,
    yx_condition_type_warning_callback callback, void *user);
/* Every `of` expression (not `for ... of`) whose quantifier folds to 0, in
 * YARA-X's warning order: the quantifier's span (inside parentheses) and
 * the end of the expression (its last item or anchor). */
typedef bool (*yx_condition_zero_quantifier_callback)(size_t quantifier_start,
    size_t quantifier_end, size_t end, void *user);
bool yx_condition_visit_zero_quantifiers(const yx_condition *condition,
    yx_condition_zero_quantifier_callback callback, void *user);
/* YARA-X's unintended_pattern_in_set: in each conjunctive branch of the
 * condition, a pattern a wildcard set item includes that the branch also
 * uses explicitly or through a more specific set. The set item, then both
 * uses in source order (a wildcard use is a set item ending with `*`). */
typedef bool (*yx_condition_pattern_set_callback)(const char *pattern,
    size_t set_start, size_t set_end,
    size_t first_start, size_t first_end, bool first_wildcard,
    size_t second_start, size_t second_end, bool second_wildcard, void *user);
bool yx_condition_visit_pattern_sets(const yx_condition *condition,
    const char *const *pattern_names, size_t pattern_count,
    yx_condition_pattern_set_callback callback, void *user);
bool yx_condition_validate(const yx_condition *condition,
                           const char *const *pattern_names, size_t pattern_count,
                           const char *const *imports, size_t import_count,
                           const char *const *features, size_t feature_count,
                           const yx_global *globals, size_t global_count,
                           yx_condition_identifier_resolver identifier_exists,
                           void *user_data, char *error, size_t error_capacity);
/* Instructions YARA-X 1.23.0 emits for the rule's condition, including the
 * code that records the result; above 100,000 the rule fails with E048.
 * Pattern names are in declaration order. 0 when it cannot be computed. */
uint64_t yx_condition_wasm_size(const yx_condition *condition,
                                bool global_rule,
                                const char *const *pattern_names,
                                size_t pattern_count,
                                const yx_global *globals,
                                size_t global_count);
/* True when a condition can inspect more than a pattern's mere existence. */
bool yx_condition_pattern_requires_all_matches(const yx_condition *condition,
                                                const char *pattern_name);
/* Whether YARA-X's optimized condition marks this pattern non-anchorable. */
bool yx_condition_pattern_nonanchorable(const yx_condition *condition,
                                        const char *pattern_name,
                                        bool fixed_at);
/* A simple `at` condition can only observe this pattern at one fixed offset. */
bool yx_condition_pattern_fixed_at(const yx_condition *condition,
                                   const char *pattern_name, size_t *offset);
/* The filesize bounds and header constraints YARA-X's Compiler::c_rule
 * derives from a rule's condition (IR::filesize_bounds and
 * IR::header_constraints). Bound kinds: 0 unbounded, 1 included, 2 excluded.
 * header_kind: 0 unconstrained, 1 unsatisfiable, 2 constrained (header owns
 * header_length bytes). */
typedef struct yx_rule_constraints {
    uint8_t lower_kind, upper_kind, header_kind;
    int64_t lower, upper;
    uint8_t *header;
    size_t header_length;
} yx_rule_constraints;
/* The constraints of the rule a bare identifier names, or NULL. */
typedef const yx_rule_constraints *(*yx_constraints_rule_lookup)(void *user, const char *name);
/* The literal bytes of a pattern that `$name at 0` constrains the header
 * with (false when the pattern is not eligible). */
typedef bool (*yx_constraints_pattern_lookup)(void *user, const char *name,
                                              const uint8_t **bytes, size_t *length);
/* The condition's own constraints, with those of the rules it requires.
 * False only when out of memory. */
bool yx_condition_rule_constraints(const yx_condition *condition,
                                   yx_constraints_rule_lookup rule_lookup,
                                   yx_constraints_pattern_lookup pattern_lookup,
                                   void *user, yx_rule_constraints *out);
/* FilesizeBounds::merge and HeaderConstraint::merge. False when out of memory. */
bool yx_rule_constraints_merge(yx_rule_constraints *into, const yx_rule_constraints *other);
bool yx_rule_constraints_equal(const yx_rule_constraints *a, const yx_rule_constraints *b);
/* Fast scans can stop tracking a root count comparison once it is true. */
bool yx_condition_pattern_fast_count(const yx_condition *condition,
                                     const char *pattern_name,
                                     size_t *minimum_count);
/* Whether every parsed reference to a module reads exactly one field. */
bool yx_condition_uses_only_module_field(const yx_condition *condition,
                                         const char *module,
                                         const char *field);
bool yx_condition_uses_module(const yx_condition *condition,
                              const char *module);
/* YARA-X folds an `and`/`or` decided by a constant operand (and `not` of
 * a Boolean constant) into a constant, so the console calls inside never
 * run. Turns those calls into the constant true they return; called once
 * every compile-time check of the rule is done. */
void yx_condition_drop_absorbed_console_calls(yx_condition *condition);
/* Whether a module path names a constant (an enumeration item and the
 * like); *floating tells a float constant from an integer one. */
bool yx_condition_module_constant(const char *path, bool *floating);
bool yx_condition_uses_only_pe_locale_fields(const yx_condition *condition);
bool yx_condition_uses_only_dex_scalar_fields(const yx_condition *condition);
bool yx_dex_output_root_string_at(const uint8_t *data, size_t size,
                                  unsigned field, uint64_t index,
                                  const uint8_t **bytes, size_t *length);
bool yx_dex_output_record_string_at(const uint8_t *data, size_t size,
                                    unsigned root_field, uint64_t index,
                                    unsigned record_field,
                                    const uint8_t **bytes, size_t *length);
bool yx_dex_output_record_numeric_at(const uint8_t *data, size_t size,
                                     unsigned root_field, uint64_t index,
                                     unsigned record_field, bool signed_enum,
                                     uint64_t *value);
bool yx_dex_output_map_item_numeric_at(const uint8_t *data, size_t size,
                                       uint64_t index, unsigned item_field,
                                       bool signed_enum, uint64_t *value);
void yx_condition_destroy(yx_condition *condition);
#ifdef XXYARA_VERIFY_LOAD
/* Whether two compiled conditions are the same tree, field by field. */
bool yx_condition_equal(const yx_condition *a, const yx_condition *b);
#endif
/* A scratch object is private to one scanner; do not evaluate it concurrently. */
yx_eval_string_arena *yx_condition_scratch_create(void);
void yx_condition_scratch_destroy(yx_eval_string_arena *scratch);
/* Call once per scan: drops caches derived from the previous scan's data. */
void yx_condition_scratch_new_scan(yx_eval_string_arena *scratch);
bool yx_condition_evaluate(const yx_condition *condition,
                           const yx_eval_context *context, bool *out);
/* Proves a regexp-with expression independent of scan data and globals,
 * then evaluates it for the archive's ordinary constant-condition codec. */
bool yx_condition_regexp_constant(const yx_condition *condition, bool *out);
/* The bytes a `matches` regexp (the text between its slashes) reduces to
 * when its HIR is one literal, which YARA-X compiles as `contains`, or as
 * `icontains` under a trailing i. The same analysis decides the condition
 * evaluator's rewrite. Returns 1 with a malloc'd NUL-terminated literal,
 * 0 for no literal and -1 on allocation failure. */
int yx_condition_regex_literal_bytes(const char *regexp, char **literal,
                                     size_t *length);

#ifdef __cplusplus
}
#endif

#endif
