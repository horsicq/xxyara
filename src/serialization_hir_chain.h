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

/* Chained patterns: Hir::split_at_large_gaps (lib/src/re/hir.rs) cuts the
 * top-level concatenation of a regexp or of a hex pattern's regexp form at
 * any-byte repetitions spanning more than 200 bytes, as in YARA-X 1.23.0,
 * Compiler::c_chain makes each piece a sub-pattern (a literal piece a
 * literal one, any other c_regexp: FastVM, else Thompson), and the scanner
 * joins their matches (handle_sub_pattern_match, verify_chain_of_matches,
 * lib/src/scanner/context.rs). Included at the end of serialization_engine.h. */
#ifndef XXYARA_SERIALIZATION_HIR_CHAIN_H
#define XXYARA_SERIALIZATION_HIR_CHAIN_H

typedef struct {
    size_t start, end;      /* children [start, end) of the root concatenation */
    const yx_tr_node *gap;  /* the gap in front of the piece, NULL for the head */
} yx_hc_piece;

static uint64_t yx_hc_minimum(const yx_tr_node *root, size_t start, size_t end)
{
    uint64_t total = 0;
    for (size_t i = start; i < end; ++i) {
        uint64_t length = yx_se_minimum_length(root->children[i]);
        total = length > UINT64_MAX - total ? UINT64_MAX : total + length;
    }
    return total;
}

/* Hir::split_at_large_gaps: the pieces of a top-level concatenation (at
 * most root->count of them), 0 when root is not one. A chunk shorter than
 * 2 bytes and its gap stay in the next chunk, a trailing gap is dropped and
 * a short last chunk rejoins the previous piece with its gap. */
static size_t yx_hc_split(const yx_tr_node *root, yx_hc_piece *pieces)
{
    size_t count = 0, chunk = 0;
    const yx_tr_node *gap = NULL;
    if (root->kind != YX_TR_CONCAT) return 0;
    for (size_t i = 0; i < root->count; ++i) {
        const yx_tr_node *item = root->children[i];
        if (item->kind == YX_TR_REPEAT && item->count && i > chunk &&
            (yx_tr_unbounded(item) ? UINT32_MAX : item->maximum) > 200 &&
            yx_se_any_byte(item->children[0]) && yx_hc_minimum(root, chunk, i) >= 2) {
            pieces[count++] = (yx_hc_piece){chunk, i, gap};
            gap = item;
            chunk = i + 1;
        }
    }
    if (chunk == root->count) return count;
    if (!count || yx_hc_minimum(root, chunk, root->count) >= 2)
        pieces[count++] = (yx_hc_piece){chunk, root->count, gap};
    else pieces[count - 1].end = root->count;
    return count;
}

/* c_regexp for a piece: FastVM when its splitter and compiler accept the
 * piece, else the Thompson compiler. Its sub-patterns as c_chain adds them:
 * the wide one first, then the raw one, each with the extra flags. Returns
 * 1, 0 when the piece cannot be built, -1 on allocation failure. */
static int yx_hc_program(const yx_tr_node *node, bool nocase, bool greedy, bool raw, bool wide, unsigned extra,
                         yx_rx_program *out)
{
    yx_fast_program *fast = calloc(1, sizeof(*fast));
    yx_tr_program thompson = {0};
    yx_archive_regexp_atom *atoms = NULL, *owned = NULL;
    size_t atom_count = 0;
    unsigned flags = 0, split = 0;
    int result = -1;
    memset(out, 0, sizeof(*out));
    if (!fast) return -1;
    fast->flags = 64;
    fast->nocase = nocase;
    bool parsed = yx_ft_regex(fast, node, greedy);
    fast->force_regexp = true;
    if (parsed && yx_fast_compile(fast)) {
        out->code = malloc(fast->code.used ? fast->code.used : 1);
        if (!out->code) goto done;
        if (fast->code.used) memcpy(out->code, fast->code.data, fast->code.used);
        out->code_length = fast->code.used;
        atoms = fast->atoms;
        atom_count = fast->atom_count;
        flags = YX_RX_FAST | ((fast->flags & 32u) ? YX_RX_GREEDY : 0);
    } else {
        if (!yx_tr_compile_node(node, &thompson, &split, 0, false, false) ||
            !yx_tr_fold_events(&thompson.events, &thompson.atoms)) { result = 0; goto done; }
        if (!thompson.atoms.count &&
            !yx_tr_atoms_add(&thompson.atoms, (yx_tr_atom_entry){.backward = thompson.backward.used})) goto done;
        if (!yx_tr_pair(&thompson, 0, &split, 0)) goto done;
        size_t total = thompson.forward.used + thompson.backward.used;
        out->code = malloc(total ? total : 1);
        owned = atoms = calloc(thompson.atoms.count ? thompson.atoms.count : 1, sizeof(*atoms));
        if (!out->code || !atoms) goto done;
        if (thompson.forward.used) memcpy(out->code, thompson.forward.data, thompson.forward.used);
        if (thompson.backward.used)
            memcpy(out->code + thompson.forward.used, thompson.backward.data, thompson.backward.used);
        out->code_length = total;
        atom_count = thompson.atoms.count;
        for (size_t i = 0; i < atom_count; ++i) {
            const yx_tr_atom_entry *from = &thompson.atoms.items[i];
            memcpy(atoms[i].bytes, from->bytes, from->length);
            atoms[i].length = from->length;
            atoms[i].exact = from->exact;
            atoms[i].has_forward = atoms[i].has_backward = true;
            atoms[i].forward = from->forward;
            atoms[i].backward = thompson.forward.used + from->backward;
        }
        flags = greedy ? YX_RX_GREEDY : 0;
    }
    if (nocase) flags |= YX_RX_NOCASE;
    flags |= extra;
    for (unsigned variant = 0; variant < 2; ++variant) {
        if (variant ? !raw : !wide) continue;
        yx_rx_sub *sub = &out->subs[out->sub_count++];
        sub->flags = flags | (variant ? 0 : YX_RX_WIDE);
        if (!yx_se_atoms(sub, atoms, atom_count, !variant)) goto done;
    }
    result = yx_rx_program_prepare(out) ? 1 : -1;
done:
    if (result != 1) yx_rx_program_free(out);
    free(owned);
    yx_fast_program_destroy(fast);
    yx_tr_program_free(&thompson);
    return result;
}

/* The pattern's HIR and its chain pieces, when split_at_large_gaps makes a
 * chain of at least two pieces. *root and *pieces belong to the caller.
 * *oom (when given) is set after an allocation failure. */
static size_t yx_hc_parse_status(const YRX_PATTERN *pattern, yx_tr_node **root, yx_hc_piece **pieces, bool *greedy,
                                 bool *oom)
{
    *root = NULL; *pieces = NULL;
    if (!pattern || pattern->kind != YX_PATTERN_REGEX || !pattern->regexp || pattern->gap_head_regexp) return 0;
    /* Without one of these there is no repetition above 200 bytes. */
    if (!strpbrk(pattern->regexp, "*+{")) return 0;
    yx_tr_parser parser = {.text = (const uint8_t *)pattern->regexp, .length = strlen(pattern->regexp),
                           .dotall = (pattern->modifiers & YX_MOD_DOTALL) != 0,
                           .nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0};
    *root = yx_tr_expression(&parser);
    size_t count = 0;
    if (*root && !parser.failed && !parser.oom && parser.at == parser.length &&
        (*root)->kind == YX_TR_CONCAT && (*pieces = malloc((*root)->count * sizeof(**pieces))) != NULL)
        count = yx_hc_split(*root, *pieces);
    else if (oom && (parser.oom || (*root && !parser.failed && parser.at == parser.length &&
                                    (*root)->kind == YX_TR_CONCAT))) *oom = true;
    if (greedy) *greedy = parser.saw_greedy && !parser.saw_lazy;
    if (count < 2) {
        yx_tr_destroy(*root); free(*pieces);
        *root = NULL; *pieces = NULL; count = 0;
    }
    return count;
}

static size_t yx_hc_parse(const YRX_PATTERN *pattern, yx_tr_node **root, yx_hc_piece **pieces, bool *greedy)
{
    return yx_hc_parse_status(pattern, root, pieces, greedy, NULL);
}

static bool yx_hc_is_chain(const YRX_PATTERN *pattern)
{
    yx_tr_node *root; yx_hc_piece *pieces;
    size_t count = yx_hc_parse(pattern, &root, &pieces, NULL);
    yx_tr_destroy(root); free(pieces);
    return count >= 2;
}

/* Hex chains: the hex form's top-level concatenation, cut the same way. A
 * literal-only chain ({ 11 22 [300-] 33 44 }) is one too. */

/* Whether yx_tr_hex_regex writes these atoms: its only other failure is an
 * allocation failure of the writer. */
static bool yx_hc_hex_text_supported(const yx_hex_atom *atoms, size_t count, size_t depth)
{
    if (depth > 250) return false;
    for (size_t i = 0; i < count; ++i) {
        const yx_hex_atom *a = &atoms[i];
        if (a->kind == YX_HEX_ALTERNATIVE) {
            for (size_t j = 0; j < a->branch_count; ++j)
                if (!yx_hc_hex_text_supported(a->branches[j].atoms, a->branches[j].count, depth + 1)) return false;
        } else if (a->kind == YX_HEX_JUMP) {
            uint64_t min = a->minimum, max = a->maximum == UINT32_MAX && !a->finite_maximum ? UINT64_MAX : a->maximum;
            while (i + 1 < count && atoms[i + 1].kind == YX_HEX_JUMP) {
                const yx_hex_atom *next = &atoms[++i];
                min += next->minimum;
                max = max == UINT64_MAX || (next->maximum == UINT32_MAX && !next->finite_maximum) ?
                    UINT64_MAX : max + next->maximum;
            }
            if (min > UINT32_MAX || (max != UINT64_MAX && max > UINT32_MAX)) return false;
        } else if (a->kind != YX_HEX_BYTE) return false;
    }
    return true;
}

/* The hex form's pieces when it is such a chain (at least two), else 0;
 * *oom (when given) is set after an allocation failure. */
static size_t yx_hc_hex_parse_status(const YRX_PATTERN *pattern, yx_tr_node **root, yx_hc_piece **pieces, bool *oom)
{
    yx_writer text = {0};
    size_t count = 0;
    *root = NULL; *pieces = NULL;
    if (!pattern || pattern->kind != YX_PATTERN_HEX || !pattern->hex_atoms || !pattern->hex_has_jump ||
        (pattern->modifiers & ~YX_MOD_PRIVATE)) return 0;
    /* Only a top-level jump above 200 bytes splits the hex form. */
    bool large = false;
    for (size_t i = 0; !large && i < pattern->hex_atom_count; ++i)
        large = pattern->hex_atoms[i].kind == YX_HEX_JUMP && pattern->hex_atoms[i].maximum > 200;
    if (!large) return 0;
    if (!yx_tr_hex_regex(&text, pattern->hex_atoms, pattern->hex_atom_count, 0) || !yx_put_u8(&text, 0)) {
        if (oom && yx_hc_hex_text_supported(pattern->hex_atoms, pattern->hex_atom_count, 0)) *oom = true;
        free(text.data);
        return 0;
    }
    yx_tr_parser parser = {.text = text.data, .length = text.used - 1};
    *root = yx_tr_expression(&parser);
    if (*root && !parser.failed && !parser.oom && parser.at == parser.length &&
        (*root)->kind == YX_TR_CONCAT && (*pieces = malloc((*root)->count * sizeof(**pieces))) != NULL)
        count = yx_hc_split(*root, *pieces);
    else if (oom && (parser.oom || (*root && !parser.failed && parser.at == parser.length &&
                                    (*root)->kind == YX_TR_CONCAT))) *oom = true;
    free(text.data);
    if (count < 2) {
        yx_tr_destroy(*root); free(*pieces);
        *root = NULL; *pieces = NULL; count = 0;
    }
    return count;
}

static size_t yx_hc_hex_parse(const YRX_PATTERN *pattern, yx_tr_node **root, yx_hc_piece **pieces)
{
    return yx_hc_hex_parse_status(pattern, root, pieces, NULL);
}

bool yx_ser_hex_chain(const YRX_PATTERN *pattern)
{
    yx_tr_node *root;
    yx_hc_piece *pieces;
    size_t count = yx_hc_hex_parse(pattern, &root, &pieces);
    yx_tr_destroy(root); free(pieces);
    return count >= 2;
}

bool yx_ser_regex_chain(const YRX_PATTERN *pattern)
{
    return yx_hc_is_chain(pattern);
}

/* 1 when the pattern is a chain, 0 when it is not, -1 when memory ran out
 * before that was known. */
static int yx_hc_chain_status(const YRX_PATTERN *pattern)
{
    yx_tr_node *root;
    yx_hc_piece *pieces;
    bool oom = false;
    size_t count = pattern && pattern->kind == YX_PATTERN_HEX ?
        yx_hc_hex_parse_status(pattern, &root, &pieces, &oom) :
        yx_hc_parse_status(pattern, &root, &pieces, NULL, &oom);
    yx_tr_destroy(root); free(pieces);
    return count >= 2 ? 1 : oom ? -1 : 0;
}

int yx_ser_hex_chain_status(const YRX_PATTERN *pattern)
{
    return pattern && pattern->kind == YX_PATTERN_HEX ? yx_hc_chain_status(pattern) : 0;
}

int yx_ser_regex_chain_status(const YRX_PATTERN *pattern)
{
    return pattern && pattern->kind == YX_PATTERN_REGEX ? yx_hc_chain_status(pattern) : 0;
}

/* Every match of such a chain starts with a head match, which YARA-X finds
 * only at an occurrence of the literal head or of one of the head
 * sub-pattern's atoms: those are the branches of its gate. */
int yx_ser_hex_chain_gate(const YRX_PATTERN *pattern, uint8_t **bytes, size_t **offsets)
{
    yx_tr_node *root;
    yx_hc_piece *pieces;
    yx_rx_program program;
    bool built = false;
    int result = 0;
    *bytes = NULL; *offsets = NULL;
    bool parse_oom = false;
    if ((pattern && pattern->kind == YX_PATTERN_REGEX ? yx_hc_parse_status(pattern, &root, &pieces, NULL, &parse_oom) :
         yx_hc_hex_parse_status(pattern, &root, &pieces, &parse_oom)) < 2) {
        yx_tr_destroy(root); free(pieces);
        return parse_oom ? -1 : 0;
    }
    yx_tr_node fragment = {.kind = YX_TR_CONCAT, .children = root->children + pieces[0].start,
                           .count = pieces[0].end - pieces[0].start};
    const yx_tr_node *node = fragment.count == 1 ? fragment.children[0] : &fragment;
    size_t branches = 1, total = 0;
    if (node->kind == YX_TR_LITERAL) total = node->length;
    else {
        int made = yx_hc_program(node, false, false, true, false, 0, &program);
        if (made != 1) { result = made ? -1 : 0; goto done; }
        built = true;
        branches = 0;
        for (size_t s = 0; s < program.sub_count; ++s)
            for (size_t a = 0; a < program.subs[s].atom_count; ++a) {
                if (!program.subs[s].atoms[a].length) goto done;
                total += program.subs[s].atoms[a].length;
                ++branches;
            }
    }
    if (!branches || !total || branches > INT_MAX - 1) goto done;
    *bytes = malloc(total);
    *offsets = malloc((branches + 1) * sizeof(**offsets));
    if (!*bytes || !*offsets) { result = -1; goto done; }
    (*offsets)[0] = 0;
    if (!built) {
        memcpy(*bytes, node->bytes, node->length);
        (*offsets)[1] = node->length;
    } else {
        size_t k = 0, used = 0;
        for (size_t s = 0; s < program.sub_count; ++s)
            for (size_t a = 0; a < program.subs[s].atom_count; ++a) {
                memcpy(*bytes + used, program.subs[s].atoms[a].bytes, program.subs[s].atoms[a].length);
                used += program.subs[s].atoms[a].length;
                (*offsets)[++k] = used;
            }
    }
    result = (int)branches;
done:
    if (result <= 0) {
        free(*bytes); free(*offsets);
        *bytes = NULL; *offsets = NULL;
    }
    if (built) yx_rx_program_free(&program);
    yx_tr_destroy(root); free(pieces);
    return result;
}

/* A chain (regexp or hex) as Compiler::c_chain (lib/src/compiler/mod.rs)
 * compiles it: per piece and width one sub-pattern, a literal piece a
 * Literal{ChainHead,ChainTail} whose atoms extract_atoms takes from the
 * literal in that width (best_atom_in_bytes, CaseCombinations with nocase),
 * any other a Regexp{ChainHead,ChainTail} (c_regexp: FastVM, else Thompson;
 * its atoms made wide). A literal head adds its raw sub-pattern first, every
 * other piece its wide one. All share the pattern's greediness (set_greedy,
 * GreedyRegexp; hex patterns are never greedy); the head has FullwordLeft and
 * the last piece FullwordRight when the pattern is fullword. The chain's
 * atoms, in that order, are the pattern's atoms in the reference's automaton
 * (yx_ser_pattern_reference_atoms, yx_view_atom_order). */
typedef struct {
    uint8_t bytes[8];
    size_t length, backtrack;
    bool wide;
} yx_hc_atom;

typedef struct {
    const yx_tr_node *node;
    yx_tr_node fragment;     /* holds the children of a piece of several */
    unsigned flags;          /* YX_RX_FULLWORD_LEFT / RIGHT of its sub-patterns */
    yx_rx_program program;   /* a regexp piece's sub-patterns, the wide one first */
    yx_hc_atom *atoms;       /* a literal piece's atoms */
    size_t atom_first, atom_count;
} yx_hc_part;

typedef struct yx_hc_chain {
    yx_tr_node *root;
    yx_hc_piece *pieces;
    yx_hc_part *parts;
    size_t count, atom_count;
    bool greedy, raw, wide, nocase;
} yx_hc_chain;

static void yx_hc_chain_free(yx_hc_chain *chain)
{
    for (size_t i = 0; chain->parts && i < chain->count; ++i) {
        yx_rx_program_free(&chain->parts[i].program);
        free(chain->parts[i].atoms);
    }
    free(chain->parts);
    free(chain->pieces);
    yx_tr_destroy(chain->root);
    memset(chain, 0, sizeof(*chain));
}

/* extract_atoms for a literal piece in one width: the atoms and the offset
 * of the best atom in the (wide) literal. */
static bool yx_hc_literal_atoms(yx_hc_part *part, bool wide, bool nocase)
{
    const yx_tr_node *node = part->node;
    YRX_PATTERN text;
    yx_rx_atom *items = NULL;
    size_t n = 0, length = node->length * (wide ? 2 : 1), offset = 0, width = 0;
    memset(&text, 0, sizeof(text));
    text.kind = YX_PATTERN_TEXT;
    text.bytes = node->bytes;
    text.length = node->length;
    text.modifiers = (wide ? YX_MOD_WIDE : 0) | (nocase ? YX_MOD_NOCASE : 0);
    uint8_t *bytes = malloc(length ? length : 1), *masks = malloc(length ? length : 1);
    bool ok = bytes && masks && length && yx_ser_pattern_reference_atoms(&text, &items, &n) && n;
    if (ok) {
        for (size_t i = 0; i < node->length; ++i) {
            if (wide) { bytes[2 * i] = node->bytes[i]; bytes[2 * i + 1] = 0; }
            else bytes[i] = node->bytes[i];
        }
        memset(masks, 255, length);
        yx_fast_literal literal = {bytes, masks, length, false};
        yx_fast_best_atom(&literal, &offset, &width);
        yx_hc_atom *atoms = realloc(part->atoms, (part->atom_count + n) * sizeof(*atoms));
        ok = atoms != NULL;
        if (ok) part->atoms = atoms;
        for (size_t k = 0; ok && k < n; ++k) {
            yx_hc_atom *atom = &part->atoms[part->atom_count++];
            memset(atom, 0, sizeof(*atom));
            memcpy(atom->bytes, items[k].bytes, items[k].length);
            atom->length = items[k].length;
            atom->backtrack = offset;
            atom->wide = wide;
        }
    }
    free(items); free(bytes); free(masks);
    return ok;
}

/* 1 with the chain, 0 when the pattern is not a chain, -2 when a piece
 * cannot be built, -1 on allocation failure. Free it in every case. */
static int yx_hc_chain_build(const YRX_PATTERN *pattern, yx_hc_chain *chain)
{
    bool oom = false;
    memset(chain, 0, sizeof(*chain));
    if (!pattern) return 0;
    size_t count = pattern->kind == YX_PATTERN_HEX ?
        yx_hc_hex_parse_status(pattern, &chain->root, &chain->pieces, &oom) :
        yx_hc_parse_status(pattern, &chain->root, &chain->pieces, &chain->greedy, &oom);
    if (count < 2) return oom ? -1 : 0;
    chain->count = count;
    chain->wide = (pattern->modifiers & YX_MOD_WIDE) != 0;
    chain->raw = !chain->wide || (pattern->modifiers & YX_MOD_ASCII);
    chain->nocase = (pattern->modifiers & YX_MOD_NOCASE) != 0;
    bool fullword = (pattern->modifiers & YX_MOD_FULLWORD) != 0;
    chain->parts = calloc(count, sizeof(*chain->parts));
    if (!chain->parts) return -1;
    for (size_t i = 0; i < count; ++i) {
        yx_hc_part *part = &chain->parts[i];
        part->fragment = (yx_tr_node){.kind = YX_TR_CONCAT, .children = chain->root->children + chain->pieces[i].start,
                                      .count = chain->pieces[i].end - chain->pieces[i].start};
        part->node = part->fragment.count == 1 ? part->fragment.children[0] : &part->fragment;
        for (size_t j = 0; part->fragment.count > 1 && j < part->fragment.count; ++j)
            part->fragment.has_look |= part->fragment.children[j]->has_look;
        if (fullword && !i) part->flags |= YX_RX_FULLWORD_LEFT;
        if (fullword && i + 1 == count) part->flags |= YX_RX_FULLWORD_RIGHT;
        part->atom_first = chain->atom_count;
        if (part->node->kind == YX_TR_LITERAL) {
            for (unsigned k = 0; k < 2; ++k) {
                bool wide = i ? k == 0 : k == 1;
                if ((wide ? chain->wide : chain->raw) && !yx_hc_literal_atoms(part, wide, chain->nocase)) return -1;
            }
        } else {
            int built = yx_hc_program(part->node, chain->nocase, chain->greedy, chain->raw, chain->wide, part->flags,
                                      &part->program);
            if (built != 1) return built ? -1 : -2;
            for (size_t s = 0; s < part->program.sub_count; ++s) part->atom_count += part->program.subs[s].atom_count;
        }
        chain->atom_count += part->atom_count;
    }
    return 1;
}

struct yx_hc_chain *yx_ser_chain_new(const YRX_PATTERN *pattern)
{
    yx_hc_chain *chain = malloc(sizeof(*chain));
    if (chain && yx_hc_chain_build(pattern, chain) == 1) return chain;
    if (chain) yx_hc_chain_free(chain);
    free(chain);
    return NULL;
}

void yx_ser_chain_free(struct yx_hc_chain *chain)
{
    if (!chain) return;
    yx_hc_chain_free(chain);
    free(chain);
}

/* The chain's atoms in the reference's insertion order. */
static int yx_hc_reference_atoms(const YRX_PATTERN *pattern, yx_rx_atom **atoms, size_t *count)
{
    yx_hc_chain local;
    const yx_hc_chain *chain = pattern->rx_chain;
    size_t capacity = 0;
    int built = chain ? 1 : yx_hc_chain_build(pattern, &local);
    bool ok = built == 1;
    if (!chain) chain = &local;
    *atoms = NULL;
    *count = 0;
    for (size_t i = 0; ok && i < chain->count; ++i) {
        const yx_hc_part *part = &chain->parts[i];
        for (size_t k = 0; ok && part->atoms && k < part->atom_count; ++k)
            ok = yx_se_push_atom(atoms, count, &capacity, part->atoms[k].bytes, part->atoms[k].length);
        for (size_t s = 0; ok && s < part->program.sub_count; ++s)
            for (size_t a = 0; ok && a < part->program.subs[s].atom_count; ++a)
                ok = yx_se_push_atom(atoms, count, &capacity, part->program.subs[s].atoms[a].bytes,
                                     part->program.subs[s].atoms[a].length);
    }
    if (chain == &local) yx_hc_chain_free(&local);
    if (!ok) {
        free(*atoms);
        *atoms = NULL;
        *count = 0;
    }
    /* A chain that was built fails only on an allocation. */
    return ok ? 1 : built == 1 || built == -1 ? -1 : 0;
}

/* k1, k2, k3: Aho-Corasick order (end, longer atoms first, atom order) or
 * Teddy order (start, bucket, atom id). */
typedef struct { size_t index, position, k1, k2, k3; } yx_hc_hit;

static int yx_hc_hit_compare(const void *left, const void *right)
{
    const yx_hc_hit *a = left, *b = right;
    if (a->k1 != b->k1) return a->k1 < b->k1 ? -1 : 1;
    if (a->k2 != b->k2) return a->k2 < b->k2 ? -1 : 1;
    return a->k3 < b->k3 ? -1 : a->k3 > b->k3;
}

/* A match and its place in the order handle_sub_pattern_match saw it. */
typedef struct { size_t start, end, index; } yx_hc_entry;
typedef struct { yx_hc_entry *items; size_t count, capacity; } yx_hc_entries;

static bool yx_hc_append(yx_hc_entries *list, size_t start, size_t end, size_t index)
{
    if (list->count == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2 : 64;
        yx_hc_entry *items = capacity <= SIZE_MAX / sizeof(*items) ?
            realloc(list->items, capacity * sizeof(*items)) : NULL;
        if (!items) return false;
        list->items = items;
        list->capacity = capacity;
    }
    list->items[list->count++] = (yx_hc_entry){start, end, index};
    return true;
}

/* An end per start: an open-addressing table keyed by start (start SIZE_MAX
 * marks a free slot; starts are offsets in the input). */
typedef struct {
    yx_rx_match *slots;
    size_t capacity, used;
} yx_hc_ends;

/* The slot of start, inserted (end SIZE_MAX) when absent; NULL on
 * allocation failure. */
static yx_rx_match *yx_hc_ends_slot(yx_hc_ends *t, size_t start)
{
    if (t->used * 2 >= t->capacity) {
        size_t capacity = t->capacity ? t->capacity * 2 : 1024;
        yx_rx_match *slots = capacity <= SIZE_MAX / sizeof(*slots) ? malloc(capacity * sizeof(*slots)) : NULL;
        if (!slots) return NULL;
        for (size_t k = 0; k < capacity; ++k) slots[k].start = SIZE_MAX;
        for (size_t i = 0; i < t->capacity; ++i) {
            if (t->slots[i].start == SIZE_MAX) continue;
            size_t k = (size_t)(((uint64_t)t->slots[i].start * 11400714819323198485ull) >> 20) & (capacity - 1);
            while (slots[k].start != SIZE_MAX) k = (k + 1) & (capacity - 1);
            slots[k] = t->slots[i];
        }
        free(t->slots);
        t->slots = slots;
        t->capacity = capacity;
    }
    size_t k = (size_t)(((uint64_t)start * 11400714819323198485ull) >> 20) & (t->capacity - 1);
    while (t->slots[k].start != SIZE_MAX && t->slots[k].start != start) k = (k + 1) & (t->capacity - 1);
    if (t->slots[k].start == SIZE_MAX) {
        t->slots[k] = (yx_rx_match){start, SIZE_MAX};
        ++t->used;
    }
    return &t->slots[k];
}

/* The unconfirmed matches of one piece in one width: items in the order
 * handle_sub_pattern_match tracked them, by_end the distinct spans ordered
 * by end, then start, then that order. A greedy chain marks the ones the
 * current verify_chain_of_matches reached (seen == generation); in another
 * every match is reached at most once (next[j]: the first unreached span of
 * by_end at or after j). Behind an unbounded gap, a match whose start has a
 * match with a smaller end tracked before it (greedy), or a smaller end at
 * all (not greedy), reaches nothing that one does not reach first. */
typedef struct {
    yx_hc_entries items;
    yx_hc_entry *by_end;
    size_t count, *next;
    uint32_t *seen, generation;
    bool ordered;          /* by_end is in tracking order */
    bool compress;         /* behind an unbounded gap */
    yx_hc_ends smallest;
} yx_hc_level;

static void yx_hc_level_free(yx_hc_level *level)
{
    free(level->items.items); free(level->by_end); free(level->next); free(level->seen);
    free(level->smallest.slots);
}

static bool yx_hc_level_add(yx_hc_level *level, size_t start, size_t end, bool greedy)
{
    if (level->compress) {
        yx_rx_match *slot = yx_hc_ends_slot(&level->smallest, start);
        if (!slot) return false;
        if (end >= slot->end) return true;
        slot->end = end;
        if (!greedy) return true; /* the table is the level */
    }
    return yx_hc_append(&level->items, start, end, level->items.count);
}

static int yx_hc_by_end_compare(const void *left, const void *right)
{
    const yx_hc_entry *a = left, *b = right;
    if (a->end != b->end) return a->end < b->end ? -1 : 1;
    if (a->start != b->start) return a->start < b->start ? -1 : 1;
    return a->index < b->index ? -1 : a->index > b->index;
}

static int yx_hc_index_compare(const void *left, const void *right)
{
    const yx_hc_entry *a = left, *b = right;
    return a->index < b->index ? -1 : a->index > b->index;
}

static bool yx_hc_level_finish(yx_hc_level *level, bool greedy)
{
    if (level->compress && !greedy)
        for (size_t k = 0; k < level->smallest.capacity; ++k)
            if (level->smallest.slots[k].start != SIZE_MAX &&
                !yx_hc_append(&level->items, level->smallest.slots[k].start, level->smallest.slots[k].end,
                              level->items.count)) return false;
    free(level->smallest.slots);
    level->smallest = (yx_hc_ends){0};
    size_t n = level->items.count;
    level->by_end = malloc((n ? n : 1) * sizeof(*level->by_end));
    if (!level->by_end) return false;
    if (n) memcpy(level->by_end, level->items.items, n * sizeof(*level->by_end));
    if (n > 1) qsort(level->by_end, n, sizeof(*level->by_end), yx_hc_by_end_compare);
    size_t unique = 0;
    level->ordered = true;
    for (size_t m = 0; m < n; ++m) {
        if (unique && level->by_end[unique - 1].start == level->by_end[m].start &&
            level->by_end[unique - 1].end == level->by_end[m].end) continue;
        if (unique && level->by_end[m].index < level->by_end[unique - 1].index) level->ordered = false;
        level->by_end[unique++] = level->by_end[m];
    }
    level->count = unique;
    if (greedy) {
        level->seen = calloc(n ? n : 1, sizeof(*level->seen));
        return level->seen != NULL;
    }
    level->next = malloc((unique + 1) * sizeof(*level->next));
    if (!level->next) return false;
    for (size_t m = 0; m <= unique; ++m) level->next[m] = m;
    return true;
}

static size_t yx_hc_first_end(const yx_hc_level *level, size_t bound)
{
    size_t low = 0, high = level->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (level->by_end[middle].end < bound) low = middle + 1;
        else high = middle;
    }
    return low;
}

/* [*first, *last): the spans of level whose end is a valid gap before a
 * match of the next piece starting at start (start - end in the gap). */
static void yx_hc_gap_range(const yx_hc_level *level, const yx_tr_node *gap, size_t start,
                            size_t *first, size_t *last)
{
    *first = *last = 0;
    if (start < gap->minimum) return;
    size_t high = start - gap->minimum;
    size_t low = yx_tr_unbounded(gap) || gap->maximum >= start ? 0 : start - gap->maximum;
    *first = yx_hc_first_end(level, low);
    *last = high == SIZE_MAX ? level->count : yx_hc_first_end(level, high + 1);
}

static size_t yx_hc_unused(size_t *next, size_t j)
{
    while (next[j] != j) {
        next[j] = next[next[j]];
        j = next[j];
    }
    return j;
}

/* MatchList::add (lib/src/scanner/matches.rs) for one pattern: a new start
 * is inserted; at the start of the list's last match a greedy chain sets
 * the end, at an earlier start it keeps the longer end; other chains keep
 * the first match at a start. */
typedef struct {
    yx_hc_ends ends;
    size_t last;
    bool any;
} yx_hc_list;

static bool yx_hc_track(yx_hc_list *list, size_t start, size_t end, bool greedy)
{
    yx_rx_match *slot = yx_hc_ends_slot(&list->ends, start);
    if (!slot) return false;
    if (slot->end == SIZE_MAX) {
        slot->end = end;
        if (!list->any || start > list->last) list->last = start;
        list->any = true;
    } else if (greedy && (start == list->last || slot->end < end)) slot->end = end;
    return true;
}

typedef struct {
    const yx_hc_chain *chain;
    YRX_PATTERN *pattern;
    const uint8_t *data;
    size_t size, piece, events, steps;
    yx_hc_level *levels;     /* [2 * piece + wide], every piece but the last */
    yx_hc_entries frontier, reached;
    yx_hc_list list;
    bool teddy;
} yx_hc_scan_state;

static bool yx_hc_poll(yx_hc_scan_state *s)
{
    return !(++s->steps & 65535u) && yx_scan_deadline_poll(s->pattern->deadline);
}

/* verify_chain_of_matches (lib/src/scanner/context.rs) for a match of the
 * last piece: breadth first from it through the unconfirmed matches whose
 * end is a valid gap before the start of the match that reaches them, each
 * piece's in tracking order, then track_match for every head reached, in
 * that order. A greedy chain resets every chain_length once a head is
 * reached, and every middle match reaches a head (within_valid_distance),
 * so each such search starts afresh; in another chain a match reached once
 * stays reached. */
static bool yx_hc_verify(yx_hc_scan_state *s, size_t wide, size_t start, size_t end)
{
    const yx_hc_chain *chain = s->chain;
    bool greedy = chain->greedy;
    s->frontier.count = 0;
    if (!yx_hc_append(&s->frontier, start, end, 0)) return false;
    for (size_t i = chain->count - 1; i-- > 0 && s->frontier.count;) {
        yx_hc_level *level = &s->levels[2 * i + wide];
        const yx_tr_node *gap = chain->pieces[i + 1].gap;
        s->reached.count = 0;
        if (greedy && ++level->generation == 0) {
            memset(level->seen, 0, (level->items.count ? level->items.count : 1) * sizeof(*level->seen));
            level->generation = 1;
        }
        for (size_t f = 0; f < s->frontier.count; ++f) {
            size_t first, last, mark = s->reached.count;
            yx_hc_gap_range(level, gap, s->frontier.items[f].start, &first, &last);
            if (!greedy) {
                for (size_t j = yx_hc_unused(level->next, first); j < last; j = yx_hc_unused(level->next, j + 1)) {
                    level->next[j] = j + 1;
                    if (!yx_hc_append(&s->reached, level->by_end[j].start, level->by_end[j].end, 0)) return false;
                }
                continue;
            }
            for (size_t j = first; j < last; ++j) {
                const yx_hc_entry *entry = &level->by_end[j];
                if (yx_hc_poll(s)) return false;
                if (level->seen[entry->index] == level->generation) continue;
                level->seen[entry->index] = level->generation;
                if (!yx_hc_append(&s->reached, entry->start, entry->end, entry->index)) return false;
            }
            if (!level->ordered && s->reached.count - mark > 1)
                qsort(s->reached.items + mark, s->reached.count - mark, sizeof(*s->reached.items),
                      yx_hc_index_compare);
        }
        yx_hc_entries swap = s->frontier; s->frontier = s->reached; s->reached = swap;
    }
    for (size_t f = 0; f < s->frontier.count; ++f)
        if (!yx_hc_track(&s->list, s->frontier.items[f].start, end, greedy)) return false;
    return true;
}

/* handle_sub_pattern_match for a match of the current piece. */
static bool yx_hc_event(void *context, unsigned flags, size_t start, size_t end)
{
    yx_hc_scan_state *s = context;
    size_t wide = (flags & YX_RX_WIDE) ? 1 : 0, i = s->piece;
    if (!(++s->events & 255u) && yx_scan_deadline_poll(s->pattern->deadline)) return false;
    if (i) {
        size_t first, last;
        yx_hc_gap_range(&s->levels[2 * (i - 1) + wide], s->chain->pieces[i].gap, start, &first, &last);
        if (first >= last) return true; /* within_valid_distance */
    }
    if (i + 1 == s->chain->count) return yx_hc_verify(s, wide, start, end);
    return yx_hc_level_add(&s->levels[2 * i + wide], start, end, s->chain->greedy);
}

typedef struct { yx_hc_hit *items; size_t used, capacity; } yx_hc_heap;

static bool yx_hc_heap_push(yx_hc_heap *h, yx_hc_hit hit)
{
    if (h->used == h->capacity) {
        size_t capacity = h->capacity ? h->capacity * 2 : 16;
        yx_hc_hit *items = capacity <= SIZE_MAX / sizeof(*items) ? realloc(h->items, capacity * sizeof(*items)) : NULL;
        if (!items) return false;
        h->items = items;
        h->capacity = capacity;
    }
    size_t i = h->used++;
    h->items[i] = hit;
    while (i && yx_hc_hit_compare(&h->items[i], &h->items[(i - 1) / 2]) < 0) {
        yx_hc_hit swap = h->items[i]; h->items[i] = h->items[(i - 1) / 2]; h->items[(i - 1) / 2] = swap;
        i = (i - 1) / 2;
    }
    return true;
}

static yx_hc_hit yx_hc_heap_pop(yx_hc_heap *h)
{
    yx_hc_hit top = h->items[0];
    h->items[0] = h->items[--h->used];
    for (size_t i = 0;;) {
        size_t left = 2 * i + 1, right = left + 1, best = i;
        if (left < h->used && yx_hc_hit_compare(&h->items[left], &h->items[best]) < 0) best = left;
        if (right < h->used && yx_hc_hit_compare(&h->items[right], &h->items[best]) < 0) best = right;
        if (best == i) break;
        yx_hc_hit swap = h->items[i]; h->items[i] = h->items[best]; h->items[best] = swap;
        i = best;
    }
    return top;
}

/* The next occurrence of a literal piece's atom at or after from, as a hit
 * in the reference's search order. */
static bool yx_hc_literal_hit(const yx_hc_scan_state *s, const yx_hc_part *part, size_t k, size_t from,
                              yx_hc_hit *hit)
{
    const yx_hc_atom *atom = &part->atoms[k];
    if (atom->length > s->size || from > s->size - atom->length) return false;
    int64_t found = xx_data_find_bytes_buffer_optimize(s->data, s->size, from, atom->bytes, atom->length, NULL);
    if (found < 0) return false;
    size_t id = part->atom_first + k, position = (size_t)found;
    *hit = s->teddy ?
        (yx_hc_hit){k, position, position, s->pattern->rx_order_buckets[id], s->pattern->rx_order_ids[id]} :
        (yx_hc_hit){k, position, position + atom->length, SIZE_MAX - atom->length, id};
    return true;
}

static bool yx_hc_word(uint8_t byte)
{
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z');
}

/* A literal piece's matches in the reference's order: every atom
 * occurrence, verify_literal at its start (nocase, fullword). */
static bool yx_hc_literal_events(yx_hc_scan_state *s, const yx_hc_part *part)
{
    const yx_tr_node *node = part->node;
    const uint8_t *data = s->data;
    size_t size = s->size;
    yx_hc_heap heap = {0};
    yx_hc_hit hit;
    bool ok = true;
    for (size_t k = 0; ok && k < part->atom_count; ++k)
        if (yx_hc_literal_hit(s, part, k, 0, &hit)) ok = yx_hc_heap_push(&heap, hit);
    while (ok && heap.used) {
        hit = yx_hc_heap_pop(&heap);
        const yx_hc_atom *atom = &part->atoms[hit.index];
        size_t step = atom->wide ? 2 : 1, length = node->length * step;
        if (hit.position >= atom->backtrack && length <= size - (hit.position - atom->backtrack)) {
            size_t at = hit.position - atom->backtrack, end = at + length;
            bool match = true;
            for (size_t i = 0; match && i < node->length; ++i) {
                uint8_t byte = data[at + i * step], want = node->bytes[i];
                if (s->chain->nocase && byte >= 'A' && byte <= 'Z') byte = (uint8_t)(byte + 32);
                if (s->chain->nocase && want >= 'A' && want <= 'Z') want = (uint8_t)(want + 32);
                match = byte == want && (!atom->wide || !data[at + i * step + 1]);
            }
            /* verify_full_word */
            if (match && atom->wide) {
                if ((part->flags & YX_RX_FULLWORD_LEFT) && at >= 2 && !data[at - 1] && yx_hc_word(data[at - 2]))
                    match = false;
                if ((part->flags & YX_RX_FULLWORD_RIGHT) && end + 1 < size && !data[end + 1] &&
                    yx_hc_word(data[end])) match = false;
            } else if (match) {
                if ((part->flags & YX_RX_FULLWORD_LEFT) && at >= 1 && yx_hc_word(data[at - 1])) match = false;
                if ((part->flags & YX_RX_FULLWORD_RIGHT) && end < size && yx_hc_word(data[end])) match = false;
            }
            if (match && !yx_hc_event(s, atom->wide ? YX_RX_WIDE : 0, at, end)) ok = false;
        }
        if (ok && yx_hc_literal_hit(s, part, hit.index, hit.position + 1, &hit)) ok = yx_hc_heap_push(&heap, hit);
    }
    free(heap.items);
    return ok;
}

static int yx_hc_match_compare(const void *left, const void *right)
{
    const yx_rx_match *a = left, *b = right;
    return a->start < b->start ? -1 : a->start > b->start;
}

/* Scans a chain: every sub-pattern's matches in the reference's search
 * order (Teddy's when the scanner view has one: the chain's atoms carry
 * their ids and buckets, yx_view_atom_order; else Aho-Corasick's), piece by
 * piece. An unconfirmed match can only be reached by a later piece's match
 * that YARA-X verifies after it, so the pieces before the last are complete
 * when the last one's matches stream through verify_chain_of_matches, as
 * they come: only the unconfirmed matches are kept. emit receives each match
 * by increasing offset. 1, 0 on failure or an expired deadline, -2 when the
 * pattern is not a chain or a piece cannot be built. */
static int yx_hc_join_scan(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                           bool (*emit)(size_t, size_t, void *), void *context)
{
    yx_hc_chain local;
    const yx_hc_chain *built_chain = pattern->rx_chain;
    if (!built_chain) {
        int built = yx_hc_chain_build(pattern, &local);
        if (built != 1) {
            yx_hc_chain_free(&local);
            return built == -1 ? 0 : -2;
        }
        built_chain = &local;
    }
    const yx_hc_chain chain = *built_chain;
    yx_hc_scan_state s;
    memset(&s, 0, sizeof(s));
    s.chain = built_chain;
    s.pattern = pattern;
    s.data = data;
    s.size = size;
    s.teddy = pattern->rx_teddy && pattern->rx_order_ids && pattern->rx_order_buckets &&
              size >= pattern->rx_teddy_minimum;
    s.levels = calloc(2 * (chain.count - 1), sizeof(*s.levels));
    yx_rx_match *matches = NULL;
    int result = 0;
    if (!s.levels) goto done;
    for (size_t i = 0; i + 1 < chain.count; ++i)
        s.levels[2 * i].compress = s.levels[2 * i + 1].compress = yx_tr_unbounded(chain.pieces[i + 1].gap);
    for (size_t i = 0; i < chain.count; ++i) {
        const yx_hc_part *part = &chain.parts[i];
        s.piece = i;
        if (part->atoms) {
            if (!yx_hc_literal_events(&s, part)) goto done;
        } else {
            yx_rx_match_list list = {0};
            yx_rx_order order = {true, pattern->rx_teddy_minimum, NULL, NULL};
            if (s.teddy) {
                order.ids = pattern->rx_order_ids + part->atom_first;
                order.buckets = pattern->rx_order_buckets + part->atom_first;
            }
            list.each = yx_hc_event;
            list.each_context = &s;
            if (!yx_rx_scan_ordered(&part->program, data, size, pattern->deadline, &list, s.teddy ? &order : NULL))
                goto done;
        }
        if (yx_scan_deadline_reached(pattern->deadline)) goto done;
        if (i + 1 < chain.count && (!yx_hc_level_finish(&s.levels[2 * i], chain.greedy) ||
                                    !yx_hc_level_finish(&s.levels[2 * i + 1], chain.greedy))) goto done;
        /* No unconfirmed match: no later match is within_valid_distance. */
        if (i + 1 < chain.count && !s.levels[2 * i].count && !s.levels[2 * i + 1].count) break;
    }
    /* track_match's list, by offset. */
    size_t count = 0;
    matches = malloc((s.list.ends.used ? s.list.ends.used : 1) * sizeof(*matches));
    if (!matches) goto done;
    for (size_t k = 0; k < s.list.ends.capacity; ++k)
        if (s.list.ends.slots[k].start != SIZE_MAX) matches[count++] = s.list.ends.slots[k];
    if (count > 1) qsort(matches, count, sizeof(*matches), yx_hc_match_compare);
    for (size_t m = 0; m < count; ++m)
        if (!emit(matches[m].start, matches[m].end - matches[m].start, context)) goto done;
    result = 1;
done:
    free(matches);
    for (size_t i = 0; s.levels && i < 2 * (chain.count - 1); ++i) yx_hc_level_free(&s.levels[i]);
    free(s.levels);
    free(s.frontier.items); free(s.reached.items);
    free(s.list.ends.slots);
    if (built_chain == &local) yx_hc_chain_free(&local);
    return result;
}

/* Chains of pieces FastVM's splitter does not describe, from
 * yx_ser_scan_large_fast_chain. Returns 1, or 0 on failure. */
static int yx_hc_scan(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                      bool (*emit)(size_t, size_t, void *), void *context)
{
    return yx_hc_join_scan(pattern, data, size, emit, context) == 1;
}

int yx_ser_scan_hex_chain(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                          bool (*emit)(size_t, size_t, void *), void *context)
{
    if (!pattern || pattern->kind != YX_PATTERN_HEX) return -2;
    return yx_hc_join_scan(pattern, data, size, emit, context);
}

int yx_ser_scan_regex_chain(YRX_PATTERN *pattern, const uint8_t *data, size_t size,
                            bool (*emit)(size_t, size_t, void *), void *context)
{
    if (!pattern || pattern->kind != YX_PATTERN_REGEX) return -2;
    return yx_hc_join_scan(pattern, data, size, emit, context);
}
#endif
