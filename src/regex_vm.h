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

/* Regular-expression sub-pattern execution with the semantics of YARA-X
 * v1.21.0: PikeVM and FastVM interpreters over the pinned bytecode, atom
 * verification (verify_regexp, verify_full_word) and the per-pattern match
 * list. */
#ifndef XXYARA_REGEX_VM_H
#define XXYARA_REGEX_VM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SubPatternFlags. */
enum {
    YX_RX_WIDE = 1u << 0,
    YX_RX_NOCASE = 1u << 1,
    YX_RX_FULLWORD_LEFT = 1u << 3,
    YX_RX_FULLWORD_RIGHT = 1u << 4,
    YX_RX_GREEDY = 1u << 5,
    YX_RX_FAST = 1u << 6
};

/* A necessary condition for a forward match from an atom position, inside
 * the forward scan window: the input from there on is a run of `run` bytes
 * (bitmap, bit b of byte b / 8) ended by one `stop` byte or, when
 * literal_length is not 0, `literal` starts at the latest where the run
 * ends. Built with the program by yx_ser_regexp_program; an atom without
 * one has guard NULL. */
typedef struct yx_rx_guard {
    uint8_t run[32], stop[32];
    uint8_t literal[16];
    uint8_t literal_length;
} yx_rx_guard;

/* A necessary condition for a PikeVM match from an atom position `at`: the
 * program reads a byte of `set` at one of the offsets low..high, counted
 * forward from at (data[at + d]) or, when backward, from the byte before it
 * (data[at - 1 - d]). Built by yx_rx_program_prepare (yx_rx_windows_build). */
typedef struct yx_rx_window {
    uint8_t set[32];
    uint32_t low, high;
    int16_t byte;   /* the only byte of set, or -1 */
    bool backward;
} yx_rx_window;

typedef struct yx_rx_atom {
    uint8_t bytes[8];
    uint8_t length;
    bool exact;
    bool has_fwd, has_bck; /* next to exact, so the guard adds no size */
    /* 1 + index in the program's windows, or 0; fills the padding before
     * backtrack. yx_rx_program_prepare sets both. */
    uint16_t fwd_window, bck_window;
    size_t backtrack;
    size_t fwd, bck;
    const yx_rx_guard *guard;
} yx_rx_atom;

typedef struct yx_rx_sub {
    unsigned flags;
    yx_rx_atom *atoms;
    size_t atom_count;
} yx_rx_sub;

/* A pattern's Regexp sub-patterns: the wide one, if any, precedes the raw one
 * as in the YARA-X compiler. Both share one code buffer. */
typedef struct yx_rx_program {
    uint8_t *code;
    size_t code_length;
    yx_rx_sub subs[2];
    size_t sub_count;
    /* Atom index for programs with many atoms; see yx_rx_program_prepare. */
    struct yx_rx_index *index;
    /* The atoms' guards (yx_rx_atom.guard points into this array). */
    yx_rx_guard *guards;
    size_t guard_count;
    /* The atoms' windows (yx_rx_atom.fwd_window / bck_window index them). */
    yx_rx_window *windows;
    size_t window_count;
} yx_rx_program;

typedef struct yx_rx_match {
    size_t start, end;
} yx_rx_match;

/* MatchList: at most one match per start offset, ordered by start. */
typedef struct yx_rx_match_list {
    yx_rx_match *items;
    size_t count, capacity, limit;
    bool limit_reached;
    /* When set, every verified match goes to each instead of the list, in
     * the order verify_regexp reports it, with the flags of the sub-pattern
     * that matched (chained sub-patterns need that order). False stops the
     * scan as an allocation failure does. */
    bool (*each)(void *context, unsigned flags, size_t start, size_t end);
    void *each_context;
} yx_rx_match_list;

void yx_rx_program_free(yx_rx_program *program);
/* Whether code that did not come from this library's own compiler (a
 * compiled-rules archive) is safe to run from the given entry offsets.
 * PikeVM code (fast false): every instruction reachable from an entry
 * decodes inside the code, no reachable instruction starts inside another
 * one, every jump, split and repeat target and every fall-through is inside
 * the code, and there is no cycle made only of jumps, repeats and zero-width
 * assertions (the epsilon closure marks splits and byte-consuming
 * instructions, and nothing else). FastVM code (fast true) has no jump
 * targets: every entry must decode in a line to its MATCH, alternations
 * hold literals only, and the exact jumps of one line add up to at most
 * YX_RX_FAST_EXACT_JUMP_LIMIT bytes (positions they produce are stored
 * without looking at the input). False also without memory. */
enum { YX_RX_FAST_EXACT_JUMP_LIMIT = 65536 };
bool yx_rx_archived_code_valid(const uint8_t *code, size_t code_length, const size_t *entries,
                               size_t entry_count, bool fast);
/* Builds the search index and the atoms' windows once the atoms are final.
 * False on allocation failure (a program without memory for windows just
 * has none). */
bool yx_rx_program_prepare(yx_rx_program *program);
/* Whether the atom index search jumps from one possible atom start to the
 * next (bytes of the atoms' first-byte set) instead of visiting every input
 * position. Prepare enables it when the program has no empty atom and the
 * set has fewer than 128 members; tests turn it off to compare with the
 * per-position search, or on for denser sets. Both give the same results.
 * Returns the previous setting; false without an index. */
bool yx_rx_program_set_index_skip(yx_rx_program *program, bool enable);
/* False when the windows of the atom with flattened index `index` (in
 * sub-pattern order) rule out a match from its occurrence at `position`:
 * verifying that occurrence cannot add a match. */
bool yx_rx_atom_possible(const yx_rx_program *program, size_t index, const uint8_t *data,
                         size_t size, size_t position);
void yx_rx_match_list_free(yx_rx_match_list *list);

/* Runs a condition regexp program over the entire input. The compiled
 * program includes its unanchored search prefix. Returns 1 for a match, 0
 * for no match, or -1 on allocation failure, invalid code or an expired
 * deadline (reported in deadline->expired). The program is read-only. */
int yx_rx_pike_search(const uint8_t *code, size_t code_length,
                      const uint8_t *data, size_t size, yx_scan_deadline *deadline);

/* Search every atom occurrence in the order of YARA-X's Aho-Corasick scan and
 * verify the sub-patterns. Returns false on allocation failure or when the
 * deadline expires. */
bool yx_rx_scan(const yx_rx_program *program, const uint8_t *data, size_t size,
                yx_scan_deadline *deadline, yx_rx_match_list *matches);

/* Atom occurrences collected by the ruleset-wide pass. The atom index is
 * flattened in sub-pattern order, as in yx_rx_scan_ordered. */
typedef struct yx_rx_candidate { size_t index, position; } yx_rx_candidate;

/* Atom order of the reference's search. With teddy, hits are ordered by
 * start, bucket and global atom id, for inputs of at least minimum_len
 * bytes; otherwise by Aho-Corasick order. ids and buckets are indexed by the
 * program's atoms in sub-pattern order. */
typedef struct yx_rx_order {
    bool teddy;
    size_t minimum_len;
    const size_t *ids, *buckets;
} yx_rx_order;
bool yx_rx_scan_ordered(const yx_rx_program *program, const uint8_t *data, size_t size,
                        yx_scan_deadline *deadline, yx_rx_match_list *matches,
                        const yx_rx_order *order);
/* Verifies the occurrences in candidates, which it reorders in place into
 * the verification order. */
bool yx_rx_scan_from_candidates(const yx_rx_program *program, const uint8_t *data, size_t size,
    yx_scan_deadline *deadline, yx_rx_match_list *matches, const yx_rx_order *order,
    yx_rx_candidate *candidates, size_t count);
void yx_rx_teddy_buckets(const yx_rx_atom *const *atoms, size_t count, size_t *buckets,
                         size_t *minimum_len);

/* The Literal sub-patterns of a pattern that is a whole-expression
 * alternation of literals (Compiler::c_alternation_literal): per branch the
 * raw literal, then the wide one, each with the atoms of its best atom
 * (sub.atoms: bytes, length, backtrack, exact). sub is the first member: a
 * hit's sub-pattern pointer is its literal. */
typedef struct yx_rx_literal {
    yx_rx_sub sub;
    uint8_t *bytes;
    size_t length;
} yx_rx_literal;
typedef struct yx_rx_literals {
    yx_rx_literal *items;
    size_t count;
} yx_rx_literals;
void yx_rx_literals_free(yx_rx_literals *set);
/* Searches every atom occurrence and verifies the literals
 * (handle_atom_match, verify_literal); a start keeps the match added first.
 * The order is that of the reference's search: Aho-Corasick's, or Teddy's
 * (by atom offset, then atom id). YX_RX_LITERALS_ANCHORED is for a pattern
 * anchored at an offset the caller filters by: each start gets the match
 * verify_anchored_patterns finds there, the first literal in sub-pattern
 * order, and starts are added in ascending order.
 * starts (may be NULL) lists, in ascending order, every offset where one of
 * the literals occurs (no literal is nocase then): the scan visits those
 * offsets instead of searching the atoms, with the same result. False on
 * allocation failure or when the deadline expires. */
enum { YX_RX_LITERALS_AUTOMATON, YX_RX_LITERALS_TEDDY, YX_RX_LITERALS_ANCHORED };
bool yx_rx_scan_literals(const yx_rx_literals *set, const uint8_t *data, size_t size,
                         yx_scan_deadline *deadline, yx_rx_match_list *matches, int order,
                         const yx_rx_candidate *starts, size_t start_count);

/* A set of short atoms, each owned by a pattern, searched in one pass to
 * learn which owners have at least one atom occurrence in the input. */
typedef struct yx_atom_set yx_atom_set;
yx_atom_set *yx_atom_set_new(void);
void yx_atom_set_free(yx_atom_set *set);
/* length 1..8. */
bool yx_atom_set_add(yx_atom_set *set, const uint8_t *bytes, size_t length, size_t owner);
/* Like add, with a caller tag retained for each occurrence. */
bool yx_atom_set_add_tagged(yx_atom_set *set, const uint8_t *bytes, size_t length, size_t owner, uint32_t tag);
/* Every occurrence, by increasing start position and then atom insertion order.
 * False when the deadline expires or fn requests a stop. */
typedef bool (*yx_atom_candidate_fn)(void *ctx, size_t owner, uint32_t tag, size_t position);
bool yx_atom_set_scan_candidates(const yx_atom_set *set, const uint8_t *data, size_t size,
                                 yx_scan_deadline *deadline, yx_atom_candidate_fn fn, void *ctx);

bool yx_atom_set_build(yx_atom_set *set);
size_t yx_atom_set_owner_count(const yx_atom_set *set);

/* Sets hit[owner] for every owner with an occurrence; hit has
 * yx_atom_set_owner_count entries and is cleared first. False when the
 * deadline expires. */
bool yx_atom_set_scan(const yx_atom_set *set, const uint8_t *data, size_t size, yx_scan_deadline *deadline,
                      bool *hit);

#ifdef __cplusplus
}
#endif

#endif
