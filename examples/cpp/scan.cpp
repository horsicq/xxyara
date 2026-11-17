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

// xxyara example in C++: a small RAII wrapper over the C API (static or shared library).
// usage: scan <rules.yar> <file>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// yara_x.h is the plain C header of the YARA-X C API: give it C linkage.
extern "C" {
#include <yara_x.h>
}

namespace xxyara {

struct PatternMatch {
    std::string pattern;
    size_t offset;
    size_t length;
};

struct RuleMatch {
    std::string rule;
    std::vector<PatternMatch> matches;
};

class Rules {
public:
    explicit Rules(const std::string &source) : m_rules(NULL)
    {
        if (yrx_compile(source.c_str(), &m_rules) != YRX_SUCCESS)
            throw std::runtime_error(yrx_last_error());
    }
    ~Rules() { yrx_rules_destroy(m_rules); }
    const YRX_RULES *handle() const { return m_rules; }

private:
    Rules(const Rules &);
    Rules &operator=(const Rules &);
    YRX_RULES *m_rules;
};

class Scanner {
public:
    explicit Scanner(const Rules &rules) : m_scanner(NULL)
    {
        if (yrx_scanner_create(rules.handle(), &m_scanner) != YRX_SUCCESS)
            throw std::runtime_error(yrx_last_error());
    }
    ~Scanner() { yrx_scanner_destroy(m_scanner); }

    std::vector<RuleMatch> scanFile(const std::string &path)
    {
        std::vector<RuleMatch> result;
        yrx_scanner_on_matching_rule(m_scanner, onRule, &result);
        if (yrx_scanner_scan_file(m_scanner, path.c_str()) != YRX_SUCCESS)
            throw std::runtime_error(yrx_last_error());
        return result;
    }

private:
    struct PatternContext {
        std::string name;
        RuleMatch *rule;
    };

    // The callbacks are called from C code: they must not let an exception escape.
    static void onMatch(const YRX_MATCH *match, void *userData)
    {
        PatternContext *context = static_cast<PatternContext *>(userData);
        try {
            PatternMatch item = {context->name, match->offset, match->length};
            context->rule->matches.push_back(item);
        } catch (...) {
        }
    }

    static void onPattern(const YRX_PATTERN *pattern, void *userData)
    {
        const uint8_t *text = NULL;
        size_t length = 0;
        if (yrx_pattern_identifier(pattern, &text, &length) != YRX_SUCCESS)
            return;
        try {
            PatternContext context = {std::string(reinterpret_cast<const char *>(text), length),
                                      static_cast<RuleMatch *>(userData)};
            yrx_pattern_iter_matches(pattern, onMatch, &context);
        } catch (...) {
        }
    }

    static void onRule(const YRX_RULE *rule, void *userData)
    {
        std::vector<RuleMatch> *result = static_cast<std::vector<RuleMatch> *>(userData);
        const uint8_t *text = NULL;
        size_t length = 0;
        if (yrx_rule_identifier(rule, &text, &length) != YRX_SUCCESS)
            return;
        try {
            RuleMatch item;
            item.rule.assign(reinterpret_cast<const char *>(text), length);
            result->push_back(item);
            yrx_rule_iter_patterns(rule, onPattern, &result->back());
        } catch (...) {
        }
    }

    Scanner(const Scanner &);
    Scanner &operator=(const Scanner &);
    YRX_SCANNER *m_scanner;
};

}  // namespace xxyara

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <rules.yar> <file>\n";
        return 2;
    }
    try {
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) {
            std::cerr << "cannot read " << argv[1] << "\n";
            return 1;
        }
        std::ostringstream source;
        source << file.rdbuf();
        xxyara::Rules rules(source.str());
        xxyara::Scanner scanner(rules);
        std::vector<xxyara::RuleMatch> found = scanner.scanFile(argv[2]);
        for (size_t i = 0; i < found.size(); ++i) {
            std::printf("%s\n", found[i].rule.c_str());
            for (size_t j = 0; j < found[i].matches.size(); ++j) {
                const xxyara::PatternMatch &match = found[i].matches[j];
                std::printf("  %s at %zu, %zu bytes\n", match.pattern.c_str(), match.offset, match.length);
            }
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
    return 0;
}
