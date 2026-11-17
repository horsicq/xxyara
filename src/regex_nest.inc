/* Copyright (c) 2026 hors. SPDX-License-Identifier: MIT */
/* regex-syntax 0.8.11 ast::parse::NestLimiter counts AST operators, not
 * merely open delimiters. Build only that shape, with source spans, so the
 * same limit and label apply before either regexp backend lowers its AST. */
typedef struct {
    size_t start, end, first, next;
    unsigned depth;
} yx_regex_nest_node;

typedef struct {
    size_t start, content, first, last, prior, count;
    size_t alternatives, alternative_last, alternative_count;
    size_t binary;
    bool character_class, extended, first_item;
} yx_regex_nest_frame;

typedef struct {
    const char *body;
    size_t length, at, count, capacity, depth;
    yx_regex_nest_node *nodes;
    yx_regex_nest_frame *frames;
    bool valid, extended;
} yx_regex_nest_parser;

static size_t yx_regex_nest_new(yx_regex_nest_parser *p, size_t start,
                                size_t end, size_t first, bool composite)
{
    if (p->count == p->capacity) { p->valid = false; return 0; }
    size_t index = ++p->count;
    yx_regex_nest_node *node = &p->nodes[index];
    *node = (yx_regex_nest_node){start, end, first, 0, composite ? 1u : 0u};
    for (size_t child = first; child; child = p->nodes[child].next)
        if (p->nodes[child].depth + 1 > node->depth)
            node->depth = p->nodes[child].depth + 1;
    return index;
}

static void yx_regex_nest_append(yx_regex_nest_parser *p,
                                  yx_regex_nest_frame *f, size_t index)
{
    if (!index) return;
    if (f->last) p->nodes[f->last].next = index;
    else f->first = index;
    f->prior = f->last;
    f->last = index;
    ++f->count;
    f->first_item = false;
}

static size_t yx_regex_nest_union(yx_regex_nest_parser *p,
                                  yx_regex_nest_frame *f, size_t end)
{
    size_t result = f->count == 1 ? f->first :
        yx_regex_nest_new(p, f->first ? p->nodes[f->first].start : end,
            f->last ? p->nodes[f->last].end : end, f->first, f->count > 1);
    f->first = f->last = f->prior = f->count = 0;
    return result;
}

static size_t yx_regex_nest_finish(yx_regex_nest_parser *p,
                                   yx_regex_nest_frame *f, size_t end)
{
    size_t result = yx_regex_nest_union(p, f, end);
    if (f->binary) {
        p->nodes[f->binary].next = result;
        result = yx_regex_nest_new(p, p->nodes[f->binary].start,
            p->nodes[result].end, f->binary, true);
        f->binary = 0;
    }
    if (f->alternative_count) {
        p->nodes[f->alternative_last].next = result;
        result = yx_regex_nest_new(p, f->content, end,
                                   f->alternatives, true);
    }
    return result;
}

static void yx_regex_nest_space(yx_regex_nest_parser *p)
{
    while (p->extended && p->at < p->length) {
        unsigned char ch = (unsigned char)p->body[p->at];
        size_t remaining = p->length - p->at;
        size_t width = 0;
        if (ch == '\v' || ch == '\f') width = 1;
        else if (!((ch == 0xc2 && remaining < 2) ||
                   ((ch == 0xe1 || ch == 0xe2 || ch == 0xe3) && remaining < 3)))
            width = yx_space_bytes(p->body + p->at);
        if (width) p->at += width;
        else if (ch == '#')
            while (p->at < p->length && p->body[p->at] != '\n') ++p->at;
        else break;
    }
}

/* Advance a leaf escape. Braced Unicode properties and word assertions
 * contain punctuation that must never contribute AST operators. */
static bool yx_regex_nest_escape(yx_regex_nest_parser *p)
{
    if (++p->at == p->length) return false;
    char escaped = p->body[p->at++];
    if (p->at < p->length && p->body[p->at] == '{' &&
        strchr("pPbxuU", escaped)) {
        while (p->at < p->length && p->body[p->at] != '}') ++p->at;
        if (p->at == p->length) return false;
        ++p->at;
    } else if ((escaped == 'x' || escaped == 'u' || escaped == 'U') &&
               p->at < p->length) {
        size_t digits = escaped == 'x' ? 2 : escaped == 'u' ? 4 : 8;
        while (digits-- && p->at < p->length &&
               isxdigit((unsigned char)p->body[p->at])) ++p->at;
    }
    return true;
}

bool yx_regex_nesting_error(const char *body, size_t length,
                            size_t *start, size_t *width)
{
    if (!body || length < 251 || length > (SIZE_MAX / sizeof(yx_regex_nest_node) - 2) / 3)
        return false;
    yx_regex_nest_parser p = {0};
    p.body = body; p.length = length; p.capacity = length * 3 + 2; p.valid = true;
    p.nodes = calloc(p.capacity + 1, sizeof(*p.nodes));
    p.frames = calloc(length + 1, sizeof(*p.frames));
    if (!p.nodes || !p.frames) { free(p.nodes); free(p.frames); return false; }
    p.frames[0].first_item = true;
    while (p.valid && p.at < length) {
        yx_regex_nest_space(&p);
        if (p.at == length) break;
        yx_regex_nest_frame *f = &p.frames[p.depth];
        size_t begin = p.at;
        char ch = body[p.at];
        if (f->character_class) {
            if (f->first_item && ch == '^' && p.at == f->start + 1) {
                ++p.at; continue;
            }
            if (ch == ']' && !f->first_item) {
                size_t child = yx_regex_nest_finish(&p, f, p.at++);
                size_t atom = yx_regex_nest_new(&p, f->start, p.at, child, true);
                p.extended = f->extended;
                yx_regex_nest_append(&p, &p.frames[--p.depth], atom);
                continue;
            }
            if (p.at + 1 < length && (ch == '&' || ch == '-' || ch == '~') &&
                body[p.at + 1] == ch) {
                size_t left = yx_regex_nest_finish(&p, f, p.at);
                f->binary = left; p.at += 2; f->first_item = false;
                continue;
            }
            if (ch == '[') {
                /* A recognised POSIX class is an ASCII leaf, whereas an
                 * unknown [:name:] remains a nested literal class. */
                if (p.at + 2 < length && body[p.at + 1] == ':') {
                    size_t name = p.at + 2, end = name;
                    if (body[name] == '^') ++name;
                    end = name;
                    while (end < length && body[end] != ':') ++end;
                    static const char *const names[] = {
                        "alnum", "alpha", "ascii", "blank", "cntrl", "digit",
                        "graph", "lower", "print", "punct", "space", "upper",
                        "word", "xdigit"
                    };
                    bool ascii = false;
                    if (end + 1 < length && body[end + 1] == ']')
                        for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); ++n)
                            if (strlen(names[n]) == end - name &&
                                !memcmp(body + name, names[n], end - name)) ascii = true;
                    if (ascii) {
                        p.at = end + 2;
                        yx_regex_nest_append(&p, f,
                            yx_regex_nest_new(&p, begin, p.at, 0, false));
                        continue;
                    }
                }
                p.frames[++p.depth] = (yx_regex_nest_frame){.start=p.at,
                    .content=p.at + 1, .character_class=true,
                    .extended=p.extended, .first_item=true};
                ++p.at; continue;
            }
            if (ch == '\\') p.valid = yx_regex_nest_escape(&p);
            else {
                ++p.at;
                while (p.at < length && ((unsigned char)body[p.at] & 0xc0) == 0x80) ++p.at;
            }
            /* A single '-' is a range operator, which is a base AST item. */
            if (p.at < length && body[p.at] == '-' && p.at + 1 < length &&
                body[p.at + 1] != '-' && body[p.at + 1] != ']' &&
                body[p.at + 1] != '[') {
                ++p.at;
                if (body[p.at] == '\\') p.valid &= yx_regex_nest_escape(&p);
                else {
                    ++p.at;
                    while (p.at < length && ((unsigned char)body[p.at] & 0xc0) == 0x80) ++p.at;
                }
            }
            yx_regex_nest_append(&p, f, yx_regex_nest_new(&p, begin, p.at, 0, false));
            continue;
        }
        if (ch == '(' || ch == '[') {
            size_t header = p.at + 1;
            bool flags_only = false, next_extended = p.extended;
            if (ch == '(' && header < length && body[header] == '?') {
                ++header;
                if (header < length && body[header] == ':') ++header;
                else if (header < length &&
                         (body[header] == '<' || body[header] == 'P')) {
                    if (body[header] == '<' && header + 1 < length &&
                        (body[header + 1] == '=' || body[header + 1] == '!'))
                        p.valid = false;
                    while (header < length && body[header] != '>') ++header;
                    if (header < length) ++header; else p.valid = false;
                } else {
                    bool negated = false;
                    size_t flags = header;
                    while (header < length && strchr("imsuxUR-", body[header])) {
                        char flag = body[header++];
                        if (flag == '-') negated = true;
                        if (flag == 'x') next_extended = !negated;
                    }
                    if (header == flags || header == length ||
                        (body[header] != ':' && body[header] != ')')) p.valid = false;
                    else flags_only = body[header++] == ')';
                }
            }
            if (!p.valid) break;
            if (flags_only) {
                p.at = header; p.extended = next_extended;
                yx_regex_nest_append(&p, f, yx_regex_nest_new(&p, begin, p.at, 0, false));
            } else {
                p.frames[++p.depth] = (yx_regex_nest_frame){.start=begin,
                    .content=header, .character_class=ch == '[',
                    .extended=p.extended, .first_item=true};
                p.at = header; p.extended = next_extended;
            }
            continue;
        }
        if (ch == ')') {
            if (!p.depth) { p.valid = false; break; }
            size_t child = yx_regex_nest_finish(&p, f, p.at++);
            size_t atom = yx_regex_nest_new(&p, f->start, p.at, child, true);
            p.extended = f->extended;
            yx_regex_nest_append(&p, &p.frames[--p.depth], atom);
            continue;
        }
        if (ch == '|') {
            size_t branch = yx_regex_nest_union(&p, f, p.at++);
            if (f->alternative_last) p.nodes[f->alternative_last].next = branch;
            else f->alternatives = branch;
            f->alternative_last = branch; ++f->alternative_count;
            continue;
        }
        if (strchr("*+?{", ch)) {
            if (!f->last) { p.valid = false; break; }
            if (ch == '{') {
                while (p.at < length && body[p.at] != '}') ++p.at;
                if (p.at == length) { p.valid = false; break; }
            }
            ++p.at;
            if (p.at < length && body[p.at] == '?') ++p.at;
            size_t child = f->last;
            size_t atom = yx_regex_nest_new(&p, p.nodes[child].start, p.at, child, true);
            if (f->prior) p.nodes[f->prior].next = atom;
            else f->first = atom;
            f->last = atom;
            continue;
        }
        if (ch == '\\') p.valid = yx_regex_nest_escape(&p);
        else {
            ++p.at;
            while (p.at < length && ((unsigned char)body[p.at] & 0xc0) == 0x80) ++p.at;
        }
        yx_regex_nest_append(&p, f, yx_regex_nest_new(&p, begin, p.at, 0, false));
    }
    bool exceeded = false;
    if (p.valid && !p.depth) {
        size_t root = yx_regex_nest_finish(&p, &p.frames[0], length);
        if (p.nodes[root].depth > 250) {
            size_t node = root;
            unsigned depth = 1;
            /* Choose the first child whose subtree crosses the limit,
             * matching the AST visitor's left-to-right pre-order. */
            while (depth <= 250) {
                size_t child = p.nodes[node].first;
                while (child && depth + p.nodes[child].depth <= 250)
                    child = p.nodes[child].next;
                if (!child) break;
                node = child; ++depth;
            }
            exceeded = depth > 250;
            if (exceeded) {
                if (start) *start = p.nodes[node].start;
                if (width) *width = p.nodes[node].end - p.nodes[node].start;
            }
        }
    }
    free(p.nodes); free(p.frames);
    return exceeded;
}
