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

/* xxyara example in C: compile a rules file, scan a file, print every matching rule with its pattern matches.
 * The same source links against the static library (xxyara.lib, libxxyara.a) or the shared one (xxyara.dll,
 * libxxyara.so). usage: scan <rules.yar> <file> */
#include <stdio.h>
#include <stdlib.h>

#include <yara_x.h>

typedef struct pattern_name {
    const uint8_t *text;
    size_t length;
} pattern_name;

static char *read_text(const char *path)
{
    FILE *file = fopen(path, "rb");
    char *text = NULL;
    long size;
    if (!file)
        return NULL;
    if (fseek(file, 0, SEEK_END) == 0 && (size = ftell(file)) >= 0 && fseek(file, 0, SEEK_SET) == 0) {
        text = (char *)malloc((size_t)size + 1);
        if (text)
            text[fread(text, 1, (size_t)size, file)] = '\0';
    }
    fclose(file);
    return text;
}

static void on_match(const struct YRX_MATCH *match, void *user_data)
{
    const pattern_name *name = (const pattern_name *)user_data;
    printf("  %.*s at %zu, %zu bytes\n", (int)name->length, (const char *)name->text, match->offset,
           match->length);
}

static void on_pattern(const struct YRX_PATTERN *pattern, void *user_data)
{
    pattern_name name;
    (void)user_data;
    if (yrx_pattern_identifier(pattern, &name.text, &name.length) == YRX_SUCCESS)
        yrx_pattern_iter_matches(pattern, on_match, &name);
}

static void on_rule(const struct YRX_RULE *rule, void *user_data)
{
    const uint8_t *identifier;
    size_t length;
    (void)user_data;
    if (yrx_rule_identifier(rule, &identifier, &length) != YRX_SUCCESS)
        return;
    printf("%.*s\n", (int)length, (const char *)identifier);
    yrx_rule_iter_patterns(rule, on_pattern, NULL);
}

int main(int argc, char **argv)
{
    struct YRX_RULES *rules = NULL;
    struct YRX_SCANNER *scanner = NULL;
    char *source;
    int status = 1;
    if (argc != 3) {
        fprintf(stderr, "usage: %s <rules.yar> <file>\n", argv[0]);
        return 2;
    }
    source = read_text(argv[1]);
    if (!source) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    if (yrx_compile(source, &rules) != YRX_SUCCESS) {
        fprintf(stderr, "%s\n", yrx_last_error());
        free(source);
        return 1;
    }
    free(source);
    if (yrx_scanner_create(rules, &scanner) == YRX_SUCCESS &&
        yrx_scanner_on_matching_rule(scanner, on_rule, NULL) == YRX_SUCCESS &&
        yrx_scanner_scan_file(scanner, argv[2]) == YRX_SUCCESS)
        status = 0;
    else
        fprintf(stderr, "%s\n", yrx_last_error());
    if (scanner)
        yrx_scanner_destroy(scanner);
    yrx_rules_destroy(rules);
    return status;
}
