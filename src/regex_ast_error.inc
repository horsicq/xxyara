/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* A port of the error paths of regex-syntax 0.8.11's AST parser
 * (ast::parse::ParserI, with YARA-X's empty_min_range(true) and octal
 * escapes disabled). It builds no AST: it walks the pattern exactly like the
 * original, keeps only the state needed to reproduce which error is reported
 * first and with which span, and returns that error. The labels, spans and
 * notes are those of the upstream error kind's Display text and of YARA-X's
 * lib/src/re/parser.rs. Spans are byte offsets into the regexp body; an empty
 * span (start == end) is rendered one column wide. */

typedef struct {
    const char *s;
    size_t n, at;
    bool ws;
    yx_regex_ast_err *err;
    bool failed;
    size_t *stack;          /* open groups: start, saved ws, saved last */
    size_t stack_count, stack_capacity;
    size_t *classes;        /* open classes: set span start, end */
    size_t class_count, class_capacity;
    size_t *names;          /* capture names: start, end */
    size_t name_count, name_capacity;
} yx_rxa;

enum { YX_RXA_NONE = 0, YX_RXA_FLAGS = 1, YX_RXA_ITEM = 2 };
enum { YX_RXA_LIT = 1, YX_RXA_PERL, YX_RXA_UNI, YX_RXA_ASSERT };
typedef struct {
    int kind;
    size_t start, end;
    unsigned cp;
} yx_rxa_prim;

static bool yx_rxa_eof(const yx_rxa *p) { return p->at >= p->n; }

static size_t yx_rxa_len_at(const yx_rxa *p, size_t at)
{
    unsigned char c;
    size_t length;
    if (at >= p->n) return 0;
    c = (unsigned char)p->s[at];
    length = c < 0xC0 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
    return at + length <= p->n ? length : p->n - at;
}

static unsigned yx_rxa_cp_at(const yx_rxa *p, size_t at)
{
    size_t length = yx_rxa_len_at(p, at);
    unsigned c;
    if (!length) return 0;
    c = (unsigned char)p->s[at];
    if (length == 1) return c;
    c &= length == 2 ? 0x1Fu : length == 3 ? 0x0Fu : 0x07u;
    for (size_t i = 1; i < length; ++i)
        c = (c << 6) | ((unsigned char)p->s[at + i] & 0x3Fu);
    return c;
}

/* The current character as a code point (0 at the end of input). */
static unsigned yx_rxa_char(const yx_rxa *p) { return yx_rxa_cp_at(p, p->at); }

static bool yx_rxa_white(unsigned c)
{
    return (c >= 9 && c <= 13) || c == 32 || c == 0x85 || c == 0xA0 ||
           c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 ||
           c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000;
}

static bool yx_rxa_bump(yx_rxa *p)
{
    if (yx_rxa_eof(p)) return false;
    p->at += yx_rxa_len_at(p, p->at);
    return !yx_rxa_eof(p);
}

static void yx_rxa_bump_space(yx_rxa *p)
{
    if (!p->ws) return;
    while (!yx_rxa_eof(p)) {
        unsigned c = yx_rxa_char(p);
        if (yx_rxa_white(c)) yx_rxa_bump(p);
        else if (c == '#') {
            yx_rxa_bump(p);
            while (!yx_rxa_eof(p)) {
                c = yx_rxa_char(p);
                yx_rxa_bump(p);
                if (c == '\n') break;
            }
        } else break;
    }
}

static bool yx_rxa_bump_and_space(yx_rxa *p)
{
    if (!yx_rxa_bump(p)) return false;
    yx_rxa_bump_space(p);
    return !yx_rxa_eof(p);
}

static bool yx_rxa_bump_if(yx_rxa *p, const char *prefix)
{
    size_t length = strlen(prefix);
    if (p->n - p->at >= length && memcmp(p->s + p->at, prefix, length) == 0) {
        p->at += length;
        return true;
    }
    return false;
}

/* The character after the current one (0 when there is none). */
static unsigned yx_rxa_peek(const yx_rxa *p)
{
    if (yx_rxa_eof(p)) return 0;
    return yx_rxa_cp_at(p, p->at + yx_rxa_len_at(p, p->at));
}

static unsigned yx_rxa_peek_space(const yx_rxa *p)
{
    size_t start, i;
    bool in_comment = false;
    if (!p->ws) return yx_rxa_peek(p);
    if (yx_rxa_eof(p)) return 0;
    start = p->at + yx_rxa_len_at(p, p->at);
    for (i = start; i < p->n; i += yx_rxa_len_at(p, i)) {
        unsigned c = yx_rxa_cp_at(p, i);
        if (yx_rxa_white(c)) continue;
        if (!in_comment && c == '#') in_comment = true;
        else if (in_comment && c == '\n') in_comment = false;
        else { start = i; break; }
    }
    return start < p->n ? yx_rxa_cp_at(p, start) : 0;
}

static bool yx_rxa_error(yx_rxa *p, size_t start, size_t end,
                         const char *label, const char *note_format,
                         size_t note_a, size_t note_b)
{
    p->failed = true;
    p->err->start = start;
    p->err->end = end;
    p->err->label = label;
    p->err->note[0] = '\0';
    if (note_format)
        snprintf(p->err->note, sizeof(p->err->note), note_format,
                 (int)(note_b - note_a), p->s + note_a,
                 (int)(note_b - note_a), p->s + note_a);
    return false;
}

static bool yx_rxa_plain(yx_rxa *p, size_t start, size_t end,
                         const char *label)
{
    return yx_rxa_error(p, start, end, label, NULL, 0, 0);
}

/* "did you mean `\{x}` instead of `{x}`?" for the operator at `start`. */
static bool yx_rxa_missing(yx_rxa *p, size_t at)
{
    size_t length = yx_rxa_len_at(p, at);
    p->failed = true;
    p->err->start = at;
    p->err->end = at;
    p->err->label = "repetition operator missing expression";
    snprintf(p->err->note, sizeof(p->err->note),
             "did you mean `\\%.*s` instead of `%.*s`?",
             (int)length, p->s + at, (int)length, p->s + at);
    return false;
}

static bool yx_rxa_count_error(yx_rxa *p, size_t start, size_t end,
                               const char *label)
{
    p->failed = true;
    p->err->start = start;
    p->err->end = end;
    p->err->label = label;
    snprintf(p->err->note, sizeof(p->err->note),
             "did you mean `\\{` instead of `{`?");
    return false;
}

static bool yx_rxa_push(size_t **array, size_t *count, size_t *capacity,
                        size_t a, size_t b, size_t c, size_t width)
{
    if (*count + 1 > *capacity) {
        size_t grown = *capacity ? *capacity * 2 : 16;
        size_t *items = realloc(*array, grown * width * sizeof(size_t));
        if (!items) return false;
        *array = items;
        *capacity = grown;
    }
    (*array)[*count * width] = a;
    (*array)[*count * width + 1] = b;
    if (width > 2) (*array)[*count * width + 2] = c;
    ++*count;
    return true;
}

static bool yx_rxa_unclosed_class(yx_rxa *p)
{
    size_t start = 0, end = 0;
    if (p->class_count) {
        start = p->classes[(p->class_count - 1) * 2];
        end = p->classes[(p->class_count - 1) * 2 + 1];
    }
    return yx_rxa_plain(p, start, end, "unclosed character class");
}

static bool yx_rxa_is_hex(unsigned c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static bool yx_rxa_scalar(unsigned long value)
{
    return value <= 0x10FFFFul && !(value >= 0xD800ul && value <= 0xDFFFul);
}

/* parse_hex: the parser is at the `x`, `u` or `U` prefix. */
static bool yx_rxa_hex(yx_rxa *p, unsigned *cp)
{
    unsigned prefix = yx_rxa_char(p);
    unsigned digits = prefix == 'x' ? 2u : prefix == 'u' ? 4u : 8u;
    unsigned long value = 0;
    if (!yx_rxa_bump_and_space(p))
        return yx_rxa_plain(p, p->at, p->at,
            "incomplete escape sequence, reached end of pattern prematurely");
    if (yx_rxa_char(p) == '{') {
        size_t brace = p->at, start = p->at + 1, end, count = 0;
        bool overflow = false;
        while (yx_rxa_bump_and_space(p) && yx_rxa_char(p) != '}') {
            if (!yx_rxa_is_hex(yx_rxa_char(p)))
                return yx_rxa_plain(p, p->at, p->at + yx_rxa_len_at(p, p->at),
                                    "invalid hexadecimal digit");
            if (value > 0x0FFFFFFFul) overflow = true;
            else value = value * 16u + (unsigned long)(
                yx_rxa_char(p) <= '9' ? yx_rxa_char(p) - '0' :
                (yx_rxa_char(p) | 0x20u) - 'a' + 10);
            ++count;
        }
        if (yx_rxa_eof(p))
            return yx_rxa_plain(p, brace, p->at,
                "incomplete escape sequence, reached end of pattern "
                "prematurely");
        end = p->at;
        yx_rxa_bump_and_space(p);
        if (!count)
            return yx_rxa_plain(p, brace, p->at, "hexadecimal literal empty");
        if (overflow || !yx_rxa_scalar(value))
            return yx_rxa_plain(p, start, end,
                "hexadecimal literal is not a Unicode scalar value");
        *cp = (unsigned)value;
        return true;
    } else {
        size_t start = p->at, end;
        bool overflow = false;
        for (unsigned i = 0; i < digits; ++i) {
            if (i > 0 && !yx_rxa_bump_and_space(p))
                return yx_rxa_plain(p, p->at, p->at,
                    "incomplete escape sequence, reached end of pattern "
                    "prematurely");
            if (!yx_rxa_is_hex(yx_rxa_char(p)))
                return yx_rxa_plain(p, p->at, p->at + yx_rxa_len_at(p, p->at),
                                    "invalid hexadecimal digit");
            if (value > 0x0FFFFFFFul) overflow = true;
            else value = value * 16u + (unsigned long)(
                yx_rxa_char(p) <= '9' ? yx_rxa_char(p) - '0' :
                (yx_rxa_char(p) | 0x20u) - 'a' + 10);
        }
        yx_rxa_bump_and_space(p);
        end = p->at;
        if (overflow || !yx_rxa_scalar(value))
            return yx_rxa_plain(p, start, end,
                "hexadecimal literal is not a Unicode scalar value");
        *cp = (unsigned)value;
        return true;
    }
}

/* parse_unicode_class: the parser is at the `p` or `P`. */
static bool yx_rxa_unicode_class(yx_rxa *p)
{
    if (!yx_rxa_bump_and_space(p))
        return yx_rxa_plain(p, p->at, p->at,
            "incomplete escape sequence, reached end of pattern prematurely");
    if (yx_rxa_char(p) == '{') {
        while (yx_rxa_bump_and_space(p) && yx_rxa_char(p) != '}') {}
        if (yx_rxa_eof(p))
            return yx_rxa_plain(p, p->at, p->at,
                "incomplete escape sequence, reached end of pattern "
                "prematurely");
        yx_rxa_bump(p);
        return true;
    }
    if (yx_rxa_char(p) == '\\')
        return yx_rxa_plain(p, p->at, p->at + 1,
                            "invalid Unicode character class");
    yx_rxa_bump_and_space(p);
    return true;
}

static bool yx_rxa_special_word(yx_rxa *p, size_t wb_start)
{
    size_t start = p->at, contents, name_length = 0, end;
    char name[16];
    bool overflow = false;
    if (!yx_rxa_bump_and_space(p))
        return yx_rxa_plain(p, wb_start, p->at,
            "found either the beginning of a special word boundary or a "
            "bounded repetition on a \\b with an opening brace, but no "
            "closing brace");
    contents = p->at;
    {
        unsigned c = yx_rxa_char(p);
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-')) {
            p->at = start;
            return true;
        }
    }
    while (!yx_rxa_eof(p)) {
        unsigned c = yx_rxa_char(p);
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-'))
            break;
        if (name_length + 1 < sizeof(name)) name[name_length] = (char)c;
        else overflow = true;
        ++name_length;
        yx_rxa_bump_and_space(p);
    }
    if (yx_rxa_eof(p) || yx_rxa_char(p) != '}')
        return yx_rxa_plain(p, start, p->at,
            "special word boundary assertion is either unclosed or "
            "contains an invalid character");
    end = p->at;
    yx_rxa_bump(p);
    if (!overflow && name_length < sizeof(name)) {
        name[name_length] = '\0';
        if (!strcmp(name, "start") || !strcmp(name, "end") ||
            !strcmp(name, "start-half") || !strcmp(name, "end-half"))
            return true;
    }
    return yx_rxa_plain(p, contents, end,
        "unrecognized special word boundary assertion, valid choices are: "
        "start, end, start-half or end-half");
}

/* parse_escape: the parser is at the backslash. */
static bool yx_rxa_escape(yx_rxa *p, yx_rxa_prim *prim)
{
    size_t start = p->at;
    unsigned c;
    if (!yx_rxa_bump(p))
        return yx_rxa_plain(p, start, p->at,
            "incomplete escape sequence, reached end of pattern prematurely");
    c = yx_rxa_char(p);
    prim->start = start;
    if (c >= '0' && c <= '9')
        return yx_rxa_plain(p, start, p->at + yx_rxa_len_at(p, p->at),
                            "backreferences are not supported");
    if (c == 'x' || c == 'u' || c == 'U') {
        unsigned cp = 0;
        if (!yx_rxa_hex(p, &cp)) return false;
        prim->kind = YX_RXA_LIT;
        prim->cp = cp;
        prim->end = p->at;
        return true;
    }
    if (c == 'p' || c == 'P') {
        if (!yx_rxa_unicode_class(p)) return false;
        prim->kind = YX_RXA_UNI;
        prim->end = p->at;
        return true;
    }
    if (c == 'd' || c == 's' || c == 'w' || c == 'D' || c == 'S' ||
        c == 'W') {
        yx_rxa_bump(p);
        prim->kind = YX_RXA_PERL;
        prim->end = p->at;
        return true;
    }
    yx_rxa_bump(p);
    prim->end = p->at;
    prim->cp = c;
    if (c < 0x80 && strchr("\\.+*?()|[]{}^$#&-~", (int)c) && c) {
        prim->kind = YX_RXA_LIT;
        return true;
    }
    if (c < 0x80 && !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') &&
        !(c >= 'a' && c <= 'z') && c != '<' && c != '>') {
        prim->kind = YX_RXA_LIT;
        return true;
    }
    switch (c) {
    case 'a': prim->kind = YX_RXA_LIT; prim->cp = 7; return true;
    case 'f': prim->kind = YX_RXA_LIT; prim->cp = 12; return true;
    case 't': prim->kind = YX_RXA_LIT; prim->cp = 9; return true;
    case 'n': prim->kind = YX_RXA_LIT; prim->cp = 10; return true;
    case 'r': prim->kind = YX_RXA_LIT; prim->cp = 13; return true;
    case 'v': prim->kind = YX_RXA_LIT; prim->cp = 11; return true;
    case 'A': case 'z': case 'B': case '<': case '>':
        prim->kind = YX_RXA_ASSERT;
        return true;
    case 'b':
        prim->kind = YX_RXA_ASSERT;
        if (!yx_rxa_eof(p) && yx_rxa_char(p) == '{') {
            if (!yx_rxa_special_word(p, start)) return false;
            prim->end = p->at;
        }
        return true;
    default:
        break;
    }
    p->failed = true;
    p->err->start = start;
    p->err->end = prim->end;
    p->err->label = "unrecognized escape sequence";
    snprintf(p->err->note, sizeof(p->err->note),
             "did you mean `\\\\%.*s` instead of `\\%.*s`?",
             (int)(prim->end - start - 1), p->s + start + 1,
             (int)(prim->end - start - 1), p->s + start + 1);
    return false;
}

static bool yx_rxa_ascii_class(yx_rxa *p)
{
    static const char *const names[] = {
        "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph",
        "lower", "print", "punct", "space", "upper", "word", "xdigit"
    };
    size_t start = p->at, name_start, name_length;
    if (!yx_rxa_bump(p) || yx_rxa_char(p) != ':') { p->at = start; return false; }
    if (!yx_rxa_bump(p)) { p->at = start; return false; }
    if (yx_rxa_char(p) == '^' && !yx_rxa_bump(p)) { p->at = start; return false; }
    name_start = p->at;
    while (!yx_rxa_eof(p) && yx_rxa_char(p) != ':' && yx_rxa_bump(p)) {}
    if (yx_rxa_eof(p)) { p->at = start; return false; }
    name_length = p->at - name_start;
    if (!yx_rxa_bump_if(p, ":]")) { p->at = start; return false; }
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (strlen(names[i]) == name_length &&
            memcmp(names[i], p->s + name_start, name_length) == 0)
            return true;
    p->at = start;
    return false;
}

static bool yx_rxa_class_item(yx_rxa *p, yx_rxa_prim *prim)
{
    if (yx_rxa_char(p) == '\\') return yx_rxa_escape(p, prim);
    prim->kind = YX_RXA_LIT;
    prim->start = p->at;
    prim->cp = yx_rxa_char(p);
    yx_rxa_bump(p);
    prim->end = p->at;
    return true;
}

static bool yx_rxa_class_range(yx_rxa *p)
{
    yx_rxa_prim first, second;
    unsigned lookahead;
    if (!yx_rxa_class_item(p, &first)) return false;
    yx_rxa_bump_space(p);
    if (yx_rxa_eof(p)) return yx_rxa_unclosed_class(p);
    lookahead = yx_rxa_peek_space(p);
    if (yx_rxa_char(p) != '-' || lookahead == ']' || lookahead == '-') {
        if (first.kind == YX_RXA_ASSERT)
            return yx_rxa_plain(p, first.start, first.end,
                "invalid escape sequence found in character class");
        return true;
    }
    if (!yx_rxa_bump_and_space(p)) return yx_rxa_unclosed_class(p);
    if (!yx_rxa_class_item(p, &second)) return false;
    if (first.kind != YX_RXA_LIT)
        return yx_rxa_plain(p, first.start, first.end,
                            "invalid range boundary, must be a literal");
    if (second.kind != YX_RXA_LIT)
        return yx_rxa_plain(p, second.start, second.end,
                            "invalid range boundary, must be a literal");
    if (first.cp > second.cp)
        return yx_rxa_plain(p, first.start, second.end,
            "invalid character class range, the start must be <= the end");
    return true;
}

/* parse_set_class_open: the parser is at the `[`. */
static bool yx_rxa_class_open(yx_rxa *p)
{
    size_t start = p->at;
    bool items = false;
    if (!yx_rxa_bump_and_space(p))
        return yx_rxa_plain(p, start, p->at, "unclosed character class");
    if (yx_rxa_char(p) == '^' && !yx_rxa_bump_and_space(p))
        return yx_rxa_plain(p, start, p->at, "unclosed character class");
    while (yx_rxa_char(p) == '-') {
        items = true;
        if (!yx_rxa_bump_and_space(p))
            return yx_rxa_plain(p, start, start, "unclosed character class");
    }
    if (!items && yx_rxa_char(p) == ']' &&
        !yx_rxa_bump_and_space(p))
        return yx_rxa_plain(p, start, p->at, "unclosed character class");
    if (!yx_rxa_push(&p->classes, &p->class_count, &p->class_capacity,
                     start, p->at, 0, 2)) {
        p->failed = true;
        p->err->label = NULL;
        return false;
    }
    return true;
}

static bool yx_rxa_set_class(yx_rxa *p)
{
    p->class_count = 0;
    for (;;) {
        unsigned c;
        yx_rxa_bump_space(p);
        if (yx_rxa_eof(p)) return yx_rxa_unclosed_class(p);
        c = yx_rxa_char(p);
        if (c == '[') {
            if (p->class_count && yx_rxa_ascii_class(p)) continue;
            if (!yx_rxa_class_open(p)) return false;
        } else if (c == ']') {
            --p->class_count;
            yx_rxa_bump(p);
            if (!p->class_count) return true;
        } else if ((c == '&' || c == '-' || c == '~') &&
                   yx_rxa_peek(p) == c) {
            p->at += 2;
        } else if (!yx_rxa_class_range(p)) return false;
    }
}

static bool yx_rxa_capture_char(unsigned c, bool first)
{
    if (c == '_') return true;
    if (c < 0x80) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return true;
        return !first && (c == '.' || c == '[' || c == ']' ||
                          (c >= '0' && c <= '9'));
    }
    return true;
}

/* parse_group and the group bookkeeping of push_group. `last` is the kind
 * of the last item of the concatenation being built. */
static bool yx_rxa_group(yx_rxa *p, int *last)
{
    size_t open = p->at, inner;
    bool saved_ws = p->ws, new_ws = p->ws;
    yx_rxa_bump(p);
    yx_rxa_bump_space(p);
    {
        size_t after = p->at;
        if (yx_rxa_bump_if(p, "?=") || yx_rxa_bump_if(p, "?!") ||
            yx_rxa_bump_if(p, "?<=") || yx_rxa_bump_if(p, "?<!"))
            return yx_rxa_plain(p, open, p->at,
                "look-around, including look-ahead and look-behind, is not "
                "supported");
        p->at = after;
    }
    inner = p->at;
    if (yx_rxa_bump_if(p, "?P<") || yx_rxa_bump_if(p, "?<")) {
        size_t start;
        if (yx_rxa_eof(p))
            return yx_rxa_plain(p, p->at, p->at,
                                "unclosed capture group name");
        start = p->at;
        for (;;) {
            if (yx_rxa_char(p) == '>') break;
            if (!yx_rxa_capture_char(yx_rxa_char(p), p->at == start))
                return yx_rxa_plain(p, p->at, p->at + yx_rxa_len_at(p, p->at),
                                    "invalid capture group character");
            if (!yx_rxa_bump(p)) break;
        }
        if (yx_rxa_eof(p))
            return yx_rxa_plain(p, p->at, p->at,
                                "unclosed capture group name");
        if (p->at == start)
            return yx_rxa_plain(p, start, start, "empty capture group name");
        for (size_t i = 0; i < p->name_count; ++i)
            if (p->names[i * 2 + 1] - p->names[i * 2] == p->at - start &&
                memcmp(p->s + p->names[i * 2], p->s + start,
                       p->at - start) == 0)
                return yx_rxa_plain(p, start, p->at,
                                    "duplicate capture group name");
        if (!yx_rxa_push(&p->names, &p->name_count, &p->name_capacity,
                         start, p->at, 0, 2)) {
            p->failed = true;
            p->err->label = NULL;
            return false;
        }
        yx_rxa_bump(p);
    } else if (yx_rxa_bump_if(p, "?")) {
        bool negated = false, dangling = false, seen[256];
        unsigned flags_on = 0;
        int ignore_ws = -1;
        size_t negation = SIZE_MAX, second_negation = 0;
        (void)second_negation;
        if (yx_rxa_eof(p))
            return yx_rxa_plain(p, open, open + 1, "unclosed group");
        memset(seen, 0, sizeof(seen));
        while (yx_rxa_char(p) != ':' && yx_rxa_char(p) != ')') {
            unsigned c = yx_rxa_char(p);
            size_t char_end = p->at + yx_rxa_len_at(p, p->at);
            if (c == '-') {
                dangling = true;
                if (negation != SIZE_MAX)
                    return yx_rxa_plain(p, p->at, char_end,
                                        "flag negation operator repeated");
                negation = p->at;
                negated = true;
            } else {
                dangling = false;
                if (!(c == 'i' || c == 'm' || c == 's' || c == 'U' ||
                      c == 'u' || c == 'R' || c == 'x'))
                    return yx_rxa_plain(p, p->at, char_end,
                                        "unrecognized flag");
                if (seen[c])
                    return yx_rxa_plain(p, p->at, char_end, "duplicate flag");
                seen[c] = true;
                ++flags_on;
                if (c == 'x') ignore_ws = negated ? 0 : 1;
            }
            if (!yx_rxa_bump(p))
                return yx_rxa_plain(p, p->at, p->at,
                                    "expected flag but got end of regex");
        }
        if (dangling)
            return yx_rxa_plain(p, negation, negation + 1,
                                "dangling flag negation operator");
        if (yx_rxa_char(p) == ')') {
            yx_rxa_bump(p);
            if (!flags_on && negation == SIZE_MAX)
                return yx_rxa_missing(p, inner);
            if (ignore_ws >= 0) p->ws = ignore_ws != 0;
            *last = YX_RXA_FLAGS;
            return true;
        }
        yx_rxa_bump(p);
        if (ignore_ws >= 0) new_ws = ignore_ws != 0;
    }
    if (!yx_rxa_push(&p->stack, &p->stack_count, &p->stack_capacity, open,
                     saved_ws ? 1u : 0u, (size_t)*last, 3)) {
        p->failed = true;
        p->err->label = NULL;
        return false;
    }
    p->ws = new_ws;
    *last = YX_RXA_NONE;
    return true;
}

static bool yx_rxa_counted(yx_rxa *p, int *last)
{
    size_t start = p->at, digits_start, digits_end;
    unsigned long lower = 0, upper = 0;
    bool have_lower, have_upper = false, lower_empty = false;
    bool overflow;
    if (*last != YX_RXA_ITEM) return yx_rxa_missing(p, p->at);
    if (!yx_rxa_bump_and_space(p))
        return yx_rxa_count_error(p, start, p->at,
                                  "unclosed counted repetition");
    /* parse_decimal, specialised: an empty decimal is an error kind of
     * its own that only matters where its value is needed. */
#define YX_RXA_DECIMAL(value, have, bad_label, empty_start)                   \
    do {                                                                      \
        overflow = false;                                                     \
        while (!yx_rxa_eof(p) && yx_rxa_white(yx_rxa_char(p))) yx_rxa_bump(p);\
        digits_start = p->at;                                                 \
        (value) = 0;                                                          \
        while (!yx_rxa_eof(p) && yx_rxa_char(p) >= '0' &&                     \
               yx_rxa_char(p) <= '9') {                                       \
            if ((value) > 429496729ul ||                                      \
                ((value) == 429496729ul && yx_rxa_char(p) > '5'))             \
                overflow = true;                                              \
            else (value) = (value) * 10ul + (yx_rxa_char(p) - '0');           \
            yx_rxa_bump_and_space(p);                                         \
        }                                                                     \
        digits_end = p->at;                                                   \
        while (!yx_rxa_eof(p) && yx_rxa_white(yx_rxa_char(p)))                \
            yx_rxa_bump_and_space(p);                                         \
        (have) = digits_end != digits_start;                                  \
        (empty_start) = digits_start;                                         \
        (void)(bad_label);                                                    \
    } while (0)
    {
        size_t empty_at = 0, lower_overflow_start, lower_overflow_end;
        bool lower_overflow;
        YX_RXA_DECIMAL(lower, have_lower, 0, empty_at);
        lower_overflow = have_lower && overflow;
        lower_overflow_start = digits_start;
        lower_overflow_end = digits_end;
        if (!have_lower) lower_empty = true;
        if (yx_rxa_eof(p))
            return yx_rxa_count_error(p, start, p->at,
                                      "unclosed counted repetition");
        if (yx_rxa_char(p) == ',') {
            if (!yx_rxa_bump_and_space(p))
                return yx_rxa_count_error(p, start, p->at,
                                          "unclosed counted repetition");
            if (yx_rxa_char(p) != '}') {
                if (lower_overflow)
                    return yx_rxa_plain(p, lower_overflow_start,
                                        lower_overflow_end,
                                        "decimal literal invalid");
                YX_RXA_DECIMAL(upper, have_upper, 0, empty_at);
                if (!have_upper)
                    return yx_rxa_count_error(p, empty_at, empty_at,
                        "repetition quantifier expects a valid decimal");
                if (overflow)
                    return yx_rxa_plain(p, digits_start, digits_end,
                                        "decimal literal invalid");
                if (lower_empty) lower = 0;
            } else {
                if (lower_empty)
                    return yx_rxa_count_error(p, empty_at, empty_at,
                        "repetition quantifier expects a valid decimal");
                if (lower_overflow)
                    return yx_rxa_plain(p, lower_overflow_start,
                                        lower_overflow_end,
                                        "decimal literal invalid");
            }
        } else {
            if (lower_empty)
                return yx_rxa_count_error(p, empty_at, empty_at,
                    "repetition quantifier expects a valid decimal");
            if (lower_overflow)
                return yx_rxa_plain(p, lower_overflow_start,
                                    lower_overflow_end,
                                    "decimal literal invalid");
        }
    }
#undef YX_RXA_DECIMAL
    if (yx_rxa_eof(p) || yx_rxa_char(p) != '}')
        return yx_rxa_count_error(p, start, p->at,
                                  "unclosed counted repetition");
    if (yx_rxa_bump_and_space(p) && yx_rxa_char(p) == '?') yx_rxa_bump(p);
    if (have_upper && upper < lower)
        return yx_rxa_count_error(p, start, p->at,
            "invalid repetition count range, the start must be <= the end");
    return true;
}

/* Returns true when the body has an AST syntax error, describing the first
 * one regex-syntax would report. */
bool yx_regex_ast_error(const char *body, size_t length,
                        yx_regex_ast_err *out)
{
    yx_rxa p;
    int last = YX_RXA_NONE;
    bool ok = true;
    memset(&p, 0, sizeof(p));
    p.s = body;
    p.n = length;
    p.err = out;
    memset(out, 0, sizeof(*out));
    while (ok) {
        unsigned c;
        yx_rxa_bump_space(&p);
        if (yx_rxa_eof(&p)) break;
        c = yx_rxa_char(&p);
        switch (c) {
        case '(':
            ok = yx_rxa_group(&p, &last);
            break;
        case ')':
            if (!p.stack_count) {
                ok = yx_rxa_plain(&p, p.at, p.at + 1, "unopened group");
                break;
            }
            --p.stack_count;
            p.ws = p.stack[p.stack_count * 3 + 1] != 0;
            yx_rxa_bump(&p);
            last = YX_RXA_ITEM;
            break;
        case '|':
            yx_rxa_bump(&p);
            last = YX_RXA_NONE;
            break;
        case '[':
            ok = yx_rxa_set_class(&p);
            last = YX_RXA_ITEM;
            break;
        case '?': case '*': case '+':
            if (last != YX_RXA_ITEM) {
                ok = yx_rxa_missing(&p, p.at);
                break;
            }
            if (yx_rxa_bump(&p) && yx_rxa_char(&p) == '?') yx_rxa_bump(&p);
            break;
        case '{':
            ok = yx_rxa_counted(&p, &last);
            break;
        case '\\': {
            yx_rxa_prim prim;
            ok = yx_rxa_escape(&p, &prim);
            last = YX_RXA_ITEM;
            break;
        }
        default:
            yx_rxa_bump(&p);
            last = YX_RXA_ITEM;
            break;
        }
    }
    if (ok && p.stack_count) {
        size_t open = p.stack[(p.stack_count - 1) * 3];
        ok = yx_rxa_plain(&p, open, open + 1, "unclosed group");
    }
    free(p.stack);
    free(p.classes);
    free(p.names);
    return !ok && p.err->label != NULL;
}
