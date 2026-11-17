#ifndef XXYARA_SCAN_CANDIDATES_H
#define XXYARA_SCAN_CANDIDATES_H

#include "internal.h"

/* Immutable, compiled-rules-owned candidate plans; scanner views share them. */
typedef struct yx_candidate_plan yx_candidate_plan;
typedef struct yx_candidate_atom {
    uint8_t bytes[8];
    size_t length;
    size_t backtrack;
    uint32_t tag;
    uint32_t variant;
    uint8_t xor_key;
    /* When tail_min is nonzero, a match that starts with this atom needs the
     * tail_min bytes after it to belong to tail_class (bit b of byte b / 8). */
    uint16_t tail_min;
    uint8_t tail_class[32];
    /* Hex anchors after a variable-length head: an occurrence at p allows
     * the starts p - backtrack - spread .. p - backtrack. */
    size_t spread;
} yx_candidate_atom;

yx_candidate_plan *yx_candidate_plan_build(const YRX_PATTERN *pattern);
void yx_candidate_plan_free(yx_candidate_plan *plan);
size_t yx_candidate_plan_atom_count(const yx_candidate_plan *plan);
const yx_candidate_atom *yx_candidate_plan_atom(const yx_candidate_plan *plan,
                                                size_t index);
YRX_RESULT yx_candidate_verify(YRX_PATTERN *pattern,
    const yx_candidate_plan *plan, uint32_t tag, size_t atom_position,
    const uint8_t *data, size_t size, size_t limit, bool fast_scan);
YRX_RESULT yx_candidate_finalize(YRX_PATTERN *pattern, const yx_candidate_plan *plan,
    const uint8_t *data, size_t size, size_t limit, bool fast_scan);

/* The base64 module retains the exact phase needles and verification ranges
 * used by its full scanner. Allocation occurs when the plan is built. */
typedef struct yx_base64_candidate {
    uint8_t *needle;
    size_t length;
    uint8_t *plain;
    size_t plain_length;
    const char *alphabet;
    size_t padding;
    bool wide;
} yx_base64_candidate;
yx_base64_candidate *yx_base64_candidates_build(const YRX_PATTERN *pattern,
                                                size_t *count);
void yx_base64_candidates_destroy(yx_base64_candidate *variants, size_t count);
int yx_base64_candidate_verify(const yx_base64_candidate *variant,
    const uint8_t *data, size_t size, size_t start, size_t *length);

#endif
