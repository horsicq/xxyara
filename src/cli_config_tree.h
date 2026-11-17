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

/* CLI-private schema conversion, included after configuration helpers. */
#include "xxfclib/strings/xx_string_escape_debug.h"
typedef enum yx_config_shape {
    YX_CFG_ROOT, YX_CFG_FMT, YX_CFG_FMT_RULE, YX_CFG_FMT_META,
    YX_CFG_FMT_PATTERNS, YX_CFG_CHECK, YX_CFG_RULE_NAME, YX_CFG_TAGS,
    YX_CFG_METADATA, YX_CFG_META_ENTRY, YX_CFG_WARNINGS, YX_CFG_WARNING,
    YX_CFG_BOOL, YX_CFG_STRING, YX_CFG_U8, YX_CFG_STRINGS, YX_CFG_META_TYPE
} yx_config_shape;
typedef struct yx_config_field {
    const char *name;
    yx_config_shape shape;
} yx_config_field;

static const yx_config_field yx_config_root_fields[] = {
    {"fmt", YX_CFG_FMT}, {"check", YX_CFG_CHECK}, {"warnings", YX_CFG_WARNINGS}
};
static const yx_config_field yx_config_fmt_fields[] = {
    {"rule", YX_CFG_FMT_RULE}, {"meta", YX_CFG_FMT_META}, {"patterns", YX_CFG_FMT_PATTERNS}
};
static const yx_config_field yx_config_rule_fields[] = {
    {"indent_section_headers", YX_CFG_BOOL}, {"indent_section_contents", YX_CFG_BOOL},
    {"indent_spaces", YX_CFG_U8}, {"newline_before_curly_brace", YX_CFG_BOOL},
    {"empty_line_before_section_header", YX_CFG_BOOL}, {"empty_line_after_section_header", YX_CFG_BOOL}
};
static const yx_config_field yx_config_align_fields[] = {{"align_values", YX_CFG_BOOL}};
static const yx_config_field yx_config_check_fields[] = {
    {"metadata", YX_CFG_METADATA}, {"rule_name", YX_CFG_RULE_NAME}, {"tags", YX_CFG_TAGS}
};
static const yx_config_field yx_config_rule_name_fields[] = {
    {"regexp", YX_CFG_STRING}, {"error", YX_CFG_BOOL}
};
static const yx_config_field yx_config_tag_fields[] = {
    {"allowed", YX_CFG_STRINGS}, {"regexp", YX_CFG_STRING}, {"error", YX_CFG_BOOL}
};
static const yx_config_field yx_config_meta_fields[] = {
    {"type", YX_CFG_META_TYPE}, {"regexp", YX_CFG_STRING},
    {"required", YX_CFG_BOOL}, {"error", YX_CFG_BOOL}
};
static const yx_config_field yx_config_warning_fields[] = {{"disabled", YX_CFG_BOOL}};

typedef struct yx_config_tree_context {
    const char *path;
    const char *keys[128];
    size_t key_lengths[128];
    const char *diagnostic_keys[128];
    size_t diagnostic_lengths[128];
    size_t depth;
    yx_cli_check_config *config;
} yx_config_tree_context;

static bool yx_config_debug_escaped(uint32_t scalar)
{
    return xx_string_scalar_debug_escaped(scalar);
}

/* Rust Debug strings escape Unicode format/space/unassigned characters and
   combining marks, in addition to ASCII controls and quotation delimiters. */
static void yx_config_debug_text(const char *text, size_t length)
{
    for (size_t i = 0; i < length;) {
        unsigned char first = (unsigned char)text[i];
        size_t count = first < 0x80 ? 1 : first < 0xe0 ? 2 : first < 0xf0 ? 3 : 4;
        uint32_t scalar = first & (count == 1 ? 0x7f : count == 2 ? 0x1f : count == 3 ? 0xf : 7);
        for (size_t j = 1; j < count; ++j) scalar = scalar << 6 | ((unsigned char)text[i + j] & 63);
        if (scalar == '\n') fputs("\\n", stderr);
        else if (scalar == '\r') fputs("\\r", stderr);
        else if (scalar == '\t') fputs("\\t", stderr);
        else if (scalar == 0) fputs("\\0", stderr);
        else if (scalar == '"' || scalar == '\\') fprintf(stderr, "\\%c", (char)scalar);
        else if (yx_config_debug_escaped(scalar)) fprintf(stderr, "\\u{%x}", scalar);
        else fwrite(text + i, 1, count, stderr);
        i += count;
    }
}

static void yx_config_diagnostic_push(yx_config_tree_context *ctx,
                                      const char *key, size_t length)
{
    ctx->diagnostic_keys[ctx->depth] = key;
    ctx->diagnostic_lengths[ctx->depth++] = length;
}

static void yx_config_error_end(yx_config_tree_context *ctx)
{
    fputs(" for key \"default", stderr);
    for (size_t i = 0; i < ctx->depth; ++i) {
        fputc('.', stderr);
        yx_config_debug_text(ctx->diagnostic_keys[i], ctx->diagnostic_lengths[i]);
    }
    fprintf(stderr, "\" in %s TOML file\n", ctx->path);
}

static void yx_config_found(const yx_toml_value *v)
{
    switch (v->kind) {
    case YX_TOML_TABLE: case YX_TOML_DATETIME: fputs("map", stderr); break;
    case YX_TOML_ARRAY: fputs("sequence", stderr); break;
    case YX_TOML_BOOLEAN: fprintf(stderr, "bool %s", v->boolean ? "true" : "false"); break;
    case YX_TOML_INTEGER: fprintf(stderr, "signed int `%" PRId64 "`", v->integer); break;
    case YX_TOML_FLOAT: {
        char number[384];
        if (isnan(v->floating)) strcpy(number, "NaN");
        else if (isinf(v->floating)) strcpy(number, v->floating < 0 ? "-inf" : "inf");
        else if (!yx_cli_check_float_display(v->floating, number, sizeof(number))) strcpy(number, "0");
        fprintf(stderr, "float `%s`", number); break;
    }
    case YX_TOML_STRING: {
        /* Figment's string Unexpected uses Rust's Debug representation. */
        fputs("string \"", stderr);
        yx_config_debug_text(v->string, v->string_length);
        fputc('"', stderr); break;
    }
    }
}

static bool yx_config_type_error(yx_config_tree_context *ctx,
                                   const yx_toml_value *v, const char *expected)
{
    fputs("error: invalid type: found ", stderr);
    yx_config_found(v); fprintf(stderr, ", expected %s", expected);
    yx_config_error_end(ctx); return false;
}

static yx_cli_check_meta *yx_config_current_meta(yx_config_tree_context *ctx)
{
    return ctx->depth == 4 && strcmp(ctx->keys[0], "check") == 0 &&
           strcmp(ctx->keys[1], "metadata") == 0 ?
        yx_cli_check_add_meta(ctx->config, ctx->keys[2], ctx->key_lengths[2]) : NULL;
}

static bool yx_config_store_string(yx_config_tree_context *ctx, const yx_toml_value *v)
{
    char *copy = yx_cli_copy((const uint8_t *)v->string, v->string_length);
    yx_cli_check_meta *meta;
    if (!copy) return false;
    if (ctx->depth == 3 && strcmp(ctx->keys[1], "rule_name") == 0) {
        ctx->config->rule_regexp = copy; ctx->config->rule_regexp_length = v->string_length;
    } else if (ctx->depth == 3 && strcmp(ctx->keys[1], "tags") == 0) {
        ctx->config->tags_regexp = copy; ctx->config->tags_regexp_length = v->string_length;
    } else if ((meta = yx_config_current_meta(ctx)) != NULL) {
        meta->regexp = copy; meta->regexp_length = v->string_length;
    } else { free(copy); return false; }
    return true;
}

static bool yx_config_store_bool(yx_config_tree_context *ctx, bool value)
{
    yx_cli_check_config *config = ctx->config;
    const char *key = ctx->keys[ctx->depth - 1];
    if (strcmp(ctx->keys[0], "warnings") == 0) {
        char *copy;
        size_t *lengths, count = config->disabled_warnings.count;
        if (!value) return true;
        lengths = (size_t *)realloc(config->disabled_warning_lengths,
                                    (count + 1) * sizeof(*lengths));
        if (!lengths) return false;
        config->disabled_warning_lengths = lengths;
        copy = yx_cli_copy((const uint8_t *)ctx->keys[1], ctx->key_lengths[1]);
        if (!copy || !yx_cli_paths_push(&config->disabled_warnings, copy)) {
            free(copy);
            return false;
        }
        lengths[count] = ctx->key_lengths[1];
        return true;
    }
    if (strcmp(ctx->keys[0], "fmt") == 0) {
        if (strcmp(ctx->keys[1], "meta") == 0) config->fmt.align_metadata = value;
        else if (strcmp(ctx->keys[1], "patterns") == 0) config->fmt.align_patterns = value;
        else if (strcmp(key, "indent_section_headers") == 0) config->fmt.indent_section_headers = value;
        else if (strcmp(key, "indent_section_contents") == 0) config->fmt.indent_section_contents = value;
        else if (strcmp(key, "newline_before_curly_brace") == 0) config->fmt.newline_before_curly_brace = value;
        else if (strcmp(key, "empty_line_before_section_header") == 0) config->fmt.empty_line_before_section_header = value;
        else if (strcmp(key, "empty_line_after_section_header") == 0) config->fmt.empty_line_after_section_header = value;
    } else if (ctx->depth == 3 && strcmp(ctx->keys[1], "rule_name") == 0) config->rule_error = value;
    else if (ctx->depth == 3 && strcmp(ctx->keys[1], "tags") == 0) config->tags_error = value;
    else {
        yx_cli_check_meta *meta = yx_config_current_meta(ctx);
        if (!meta) return false;
        if (strcmp(key, "required") == 0) meta->required = value;
        else meta->error = value;
    }
    return true;
}

static int yx_config_key_order(const void *left, const void *right)
{
    const yx_toml_value *a = *(const yx_toml_value *const *)left;
    const yx_toml_value *b = *(const yx_toml_value *const *)right;
    size_t length = a->key_length < b->key_length ? a->key_length : b->key_length;
    int order = memcmp(a->key, b->key, length);
    return order ? order : a->key_length < b->key_length ? -1 : a->key_length != b->key_length;
}

static bool yx_config_tree_visit(yx_config_tree_context *ctx,
                                   const yx_toml_value *v, yx_config_shape shape)
{
    if (v->kind == YX_TOML_DATETIME) {
        yx_toml_value item = {.kind = YX_TOML_STRING,
            .key = "$__toml_private_datetime", .key_length = 24,
            .string = v->string, .string_length = v->string_length};
        yx_toml_value *items[] = {&item};
        yx_toml_value table = {.kind = YX_TOML_TABLE, .children = items, .count = 1};
        return yx_config_tree_visit(ctx, &table, shape);
    }
    const yx_config_field *fields = NULL;
    size_t count = 0, mandatory = 0;
    const char *name = NULL;
    bool map = false;
    switch (shape) {
    case YX_CFG_ROOT: fields = yx_config_root_fields; count = 3; name = "Config"; break;
    case YX_CFG_FMT: fields = yx_config_fmt_fields; count = 3; name = "FormatConfig"; break;
    case YX_CFG_FMT_RULE: fields = yx_config_rule_fields; count = 6; name = "RuleFormatConfig"; break;
    case YX_CFG_FMT_META: case YX_CFG_FMT_PATTERNS:
        fields = yx_config_align_fields; count = 1;
        name = shape == YX_CFG_FMT_META ? "MetaFormatConfig" : "PatternsFormatConfig"; break;
    case YX_CFG_CHECK: fields = yx_config_check_fields; count = 3; name = "CheckConfig"; break;
    case YX_CFG_RULE_NAME: fields = yx_config_rule_name_fields; count = 2; mandatory = 1; name = "RuleNameConfig"; break;
    case YX_CFG_TAGS: fields = yx_config_tag_fields; count = 3; mandatory = 2; name = "TagConfig"; break;
    case YX_CFG_META_ENTRY: fields = yx_config_meta_fields; count = 4; mandatory = 2; name = "MetadataConfig"; break;
    case YX_CFG_WARNING: fields = yx_config_warning_fields; count = 1; name = "WarningConfig"; break;
    case YX_CFG_METADATA: case YX_CFG_WARNINGS: map = true; break;
    case YX_CFG_STRING:
        if (v->kind != YX_TOML_STRING) return yx_config_type_error(ctx, v, "a string");
        return yx_config_store_string(ctx, v);
    case YX_CFG_BOOL:
        if (v->kind != YX_TOML_BOOLEAN) return yx_config_type_error(ctx, v, "a boolean");
        return yx_config_store_bool(ctx, v->boolean);
    case YX_CFG_U8: {
        if (v->kind != YX_TOML_INTEGER) return yx_config_type_error(ctx, v, "u8");
        if (v->integer < 0 || v->integer > 255) {
            fputs("error: invalid value ", stderr); yx_config_found(v);
            fputs(", expected u8", stderr); yx_config_error_end(ctx); return false;
        }
        ctx->config->fmt.indent_spaces = (uint8_t)v->integer;
        return true;
    }
    case YX_CFG_STRINGS:
        if (v->kind != YX_TOML_ARRAY) return yx_config_type_error(ctx, v, "a sequence");
        for (size_t i = 0; i < v->count; ++i) {
            if (v->children[i]->kind != YX_TOML_STRING) {
                char index[32]; snprintf(index, sizeof(index), "%zu", i);
                yx_config_diagnostic_push(ctx, index, strlen(index));
                yx_config_type_error(ctx, v->children[i], "a string"); --ctx->depth; return false;
            }
            {
                size_t count = ctx->config->allowed_tags.count;
                size_t *lengths = (size_t *)realloc(ctx->config->allowed_tag_lengths, (count + 1) * sizeof(*lengths));
                char *copy;
                if (!lengths) return false;
                ctx->config->allowed_tag_lengths = lengths;
                copy = yx_cli_copy((const uint8_t *)v->children[i]->string, v->children[i]->string_length);
                if (!copy || !yx_cli_paths_push(&ctx->config->allowed_tags, copy)) { free(copy); return false; }
                lengths[count] = v->children[i]->string_length;
            }
        }
        return true;
    case YX_CFG_META_TYPE: {
        const char *variant = NULL;
        size_t variant_length = 0;
        bool known_variant = false;
        static const char *const variants[] = {"string", "integer", "float", "bool", "sha256", "sha1", "md5", "hash"};
        bool variant_map = v->kind == YX_TOML_TABLE && v->count != 0;
        const yx_toml_value *variant_value = NULL;
        if (v->kind == YX_TOML_STRING) { variant = v->string; variant_length = v->string_length; }
        else if (variant_map) {
            variant_value = v->children[0];
            for (size_t i = 1; i < v->count; ++i) {
                const yx_toml_value *child = v->children[i];
                if (yx_config_key_order(&child, &variant_value) < 0) variant_value = child;
            }
            variant = variant_value->key;
            variant_length = variant_value->key_length;
        }
        else return yx_config_type_error(ctx, v, v->kind == YX_TOML_TABLE ? "enum" : "enum MetaValueType");
        for (size_t i = 0; i < sizeof(variants) / sizeof(*variants); ++i)
            if (strlen(variants[i]) == variant_length && memcmp(variants[i], variant, variant_length) == 0) known_variant = true;
        if (!known_variant) {
            fputs("error: unknown variant: found `", stderr);
            fwrite(variant, 1, variant_length, stderr);
            fputs("`, expected `one of `string`, `integer`, `float`, `bool`, `sha256`, `sha1`, `md5`, `hash``", stderr);
            if (variant_map) yx_config_diagnostic_push(ctx, variant, variant_length);
            yx_config_error_end(ctx); if (variant_map) --ctx->depth; return false;
        }
        if (variant_map) {
            yx_config_diagnostic_push(ctx, variant, variant_length);
            yx_config_type_error(ctx, variant_value, "unit"); --ctx->depth; return false;
        }
        {
            yx_cli_check_meta *meta = yx_config_current_meta(ctx);
            if (!meta) return false;
            meta->type = strcmp(variant, "string") == 0 ? YX_CLI_META_STRING :
                strcmp(variant, "integer") == 0 ? YX_CLI_META_INTEGER :
                strcmp(variant, "float") == 0 ? YX_CLI_META_FLOAT :
                strcmp(variant, "bool") == 0 ? YX_CLI_META_BOOL :
                strcmp(variant, "sha256") == 0 ? YX_CLI_META_SHA256 :
                strcmp(variant, "sha1") == 0 ? YX_CLI_META_SHA1 :
                strcmp(variant, "md5") == 0 ? YX_CLI_META_MD5 : YX_CLI_META_HASH;
            return true;
        }
    }
    }
    if (ctx->depth + 1 >= 128) return false;
    if (v->kind != YX_TOML_TABLE && (map || v->kind != YX_TOML_ARRAY)) {
        char expected[64]; snprintf(expected, sizeof(expected), "struct %s", name ? name : "");
        return yx_config_type_error(ctx, v, map ? "a map" : expected);
    }
    if (v->kind == YX_TOML_ARRAY) {
        if (!mandatory) mandatory = count;
        for (size_t i = 0; i < count; ++i) {
            char index[32];
            if (i >= v->count) {
                if (i >= mandatory) break;
                fprintf(stderr, "error: invalid length %zu, expected struct %s with %zu %s", i, name, count, count == 1 ? "element" : "elements");
                yx_config_error_end(ctx); return false;
            }
            snprintf(index, sizeof(index), "%zu", i);
            ctx->key_lengths[ctx->depth] = strlen(fields[i].name);
            ctx->keys[ctx->depth] = fields[i].name; yx_config_diagnostic_push(ctx, index, strlen(index));
            if (!yx_config_tree_visit(ctx, v->children[i], fields[i].shape)) { --ctx->depth; return false; }
            --ctx->depth;
        }
        return true;
    }
    {
        yx_toml_value **ordered = NULL;
        if (v->count) {
            ordered = (yx_toml_value **)malloc(v->count * sizeof(*ordered));
            if (!ordered) return false;
            memcpy(ordered, v->children, v->count * sizeof(*ordered));
            qsort(ordered, v->count, sizeof(*ordered), yx_config_key_order);
        }
        for (size_t i = 0; i < v->count; ++i) {
            const yx_toml_value *child = ordered[i];
            yx_config_shape child_shape = shape == YX_CFG_METADATA ? YX_CFG_META_ENTRY : YX_CFG_WARNING;
            size_t field = 0;
            if (!map) {
                for (; field < count; ++field) if (strlen(fields[field].name) == child->key_length &&
                    memcmp(fields[field].name, child->key, child->key_length) == 0) break;
                if (field == count) {
                    yx_config_diagnostic_push(ctx, child->key, child->key_length);
                    fputs("error: unknown field: found `", stderr);
                    fwrite(child->key, 1, child->key_length, stderr);
                    fputs("`, expected `", stderr);
                    if (count > 2) fputs("one of ", stderr);
                    for (size_t j = 0; j < count; ++j) fprintf(stderr, "%s`%s`", j ? count == 2 ? " or " : ", " : "", fields[j].name);
                    fputc('`', stderr); yx_config_error_end(ctx); --ctx->depth; free(ordered); return false;
                }
                child_shape = fields[field].shape;
            }
            ctx->key_lengths[ctx->depth] = child->key_length;
            ctx->keys[ctx->depth] = child->key; yx_config_diagnostic_push(ctx, child->key, child->key_length);
            if (!yx_config_tree_visit(ctx, child, child_shape)) { --ctx->depth; free(ordered); return false; }
            --ctx->depth;
        }
        free(ordered);
    }
    if ((shape == YX_CFG_META_ENTRY && !yx_toml_get(v, "type")) ||
        (shape == YX_CFG_WARNING && !yx_toml_get(v, "disabled"))) {
        fprintf(stderr, "error: missing field `%s`", shape == YX_CFG_META_ENTRY ? "type" : "disabled");
        yx_config_error_end(ctx); return false;
    }
    return true;
}

static void yx_config_syntax_error(const char *path, const char *source,
                                    size_t length, const yx_toml_error *error)
{
    size_t offset = error->offset < length ? error->offset : length;
    size_t safe = offset < length ? offset : length ? length - 1 : 0;
    size_t line = 1, start = 0, end, column = offset - safe + 1, digits = 1;
    for (size_t i = 0; i < safe; ++i) if (source[i] == '\n') { ++line; start = i + 1; }
    column += safe - start;
    end = start; while (end < length && source[end] != '\n') ++end;
    for (size_t n = line; n >= 10; n /= 10) ++digits;
    fprintf(stderr, "error: TOML parse error at line %zu, column %zu\n%*s |\n%zu | ", line, column, (int)digits, "", line);
    fwrite(source + start, 1, end - start, stderr);
    fprintf(stderr, "\n%*s | %*s", (int)digits, "", (int)(column - 1), "");
    for (size_t i = 0; i < (error->length ? error->length : 1); ++i) fputc('^', stderr);
    fprintf(stderr, "\n%s\n in %s TOML file\n", error->message ? error->message : "out of memory", path);
}
