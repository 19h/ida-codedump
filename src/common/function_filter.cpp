#include "function_filter.h"

#include <ida/function.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace codedump {

namespace {

std::string lower_ascii(std::string_view text) {
    std::string out{text};
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool starts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size()
        && text.substr(0, prefix.size()) == prefix;
}

bool all_digits(std::string_view text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isdigit(c) != 0;
    });
}

std::string canonical_runtime_name(std::string_view raw_name) {
    std::string name = lower_ascii(raw_name);

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::string_view prefix : {"j_", "__imp_", "_imp_", "imp_", "."}) {
            if (starts_with(name, prefix)) {
                name.erase(0, prefix.size());
                changed = true;
            }
        }
        while (!name.empty() && name.front() == '_') {
            name.erase(name.begin());
            changed = true;
        }
    }

    if (size_t pos = name.find("@@"); pos != std::string::npos) {
        name.erase(pos);
    } else if (!name.empty() && name.front() != '?') {
        if (size_t pos = name.find('@'); pos != std::string::npos)
            name.erase(pos);
    }

    while (true) {
        size_t pos = name.find_last_of('_');
        if (pos == std::string::npos || pos + 1 >= name.size()) break;
        if (!all_digits(std::string_view{name}.substr(pos + 1))) break;
        name.erase(pos);
    }

    return name;
}

bool exact_runtime_name(std::string_view name) {
    static constexpr std::string_view names[] = {
        "abort", "abs", "accept", "acos", "aligned_alloc", "alloc",
        "alloca", "asin", "assert", "atan", "atexit", "atof", "atoi",
        "atol", "atoll", "bsearch", "calloc", "ceil", "cfree", "chkstk", "clock",
        "close", "connect", "cos", "exit", "exp", "fabs", "fclose",
        "fdopen", "fflush", "fgetc", "fgets", "floor", "fopen",
        "fprintf", "fputc", "fputs", "fread", "free", "freopen",
        "fscanf", "fseek", "fseeko", "ftell", "ftello", "fwrite",
        "getc", "getchar", "getenv", "gets", "isalnum", "isalpha",
        "isdigit", "islower", "isspace", "isupper", "labs", "ldexp",
        "libc_start_main", "log", "lseek", "maincrtstartup", "malloc",
        "memcmp", "memchr", "memcpy", "memmove", "memset", "mmap",
        "munmap", "nanosleep", "open", "operator delete", "operator new",
        "perror", "poll", "posix_memalign", "pow", "printf", "putc",
        "putchar", "puts", "qsort", "rand", "read", "realloc",
        "recv", "rewind", "scanf", "security_check_cookie", "select",
        "send", "setenv", "sin", "sleep", "snprintf", "socket",
        "sprintf", "srand", "sscanf", "stack_chk_fail", "strcasecmp",
        "strcat", "strchr", "strcmp", "strcpy", "strdup", "strerror",
        "strlen", "strncasecmp", "strncat", "strncmp", "strncpy",
        "strndup", "strnlen", "strrchr", "strstr", "strtod", "strtok",
        "strtol", "strtoll", "strtoul", "strtoull", "tan", "time",
        "tolower", "toupper", "unsetenv", "usleep", "vfprintf",
        "vfscanf", "vprintf", "vscanf", "vsnprintf", "vsprintf",
        "vsscanf", "winmaincrtstartup", "write"
    };

    for (std::string_view candidate : names)
        if (candidate == name) return true;
    return false;
}

bool runtime_name_prefix(std::string_view name) {
    static constexpr std::string_view prefixes[] = {
        "std::", "operator delete", "operator new", "pthread_",
        "dispatch_", "objc_", "cxa_", "asan_", "ubsan_", "tsan_",
        "msan_", "sanitizer_"
    };

    for (std::string_view prefix : prefixes)
        if (starts_with(name, prefix)) return true;
    return false;
}

bool looks_like_runtime_name(std::string_view raw_name) {
    if (raw_name.empty()) return false;

    std::string name = canonical_runtime_name(raw_name);
    if (name.empty()) return false;

    return exact_runtime_name(name) || runtime_name_prefix(name);
}

std::string strip_c_comments(std::string_view text) {
    enum class State {
        Normal,
        LineComment,
        BlockComment,
        StringLiteral,
        CharLiteral
    };

    std::string out;
    out.reserve(text.size());
    State state = State::Normal;
    bool escaped = false;

    for (std::size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        char n = (i + 1 < text.size()) ? text[i + 1] : '\0';

        switch (state) {
            case State::Normal:
                if (c == '/' && n == '/') {
                    state = State::LineComment;
                    ++i;
                } else if (c == '/' && n == '*') {
                    state = State::BlockComment;
                    ++i;
                } else {
                    out.push_back(c);
                    if (c == '"') {
                        state = State::StringLiteral;
                        escaped = false;
                    } else if (c == '\'') {
                        state = State::CharLiteral;
                        escaped = false;
                    }
                }
                break;

            case State::LineComment:
                if (c == '\n') {
                    out.push_back(c);
                    state = State::Normal;
                }
                break;

            case State::BlockComment:
                if (c == '*' && n == '/') {
                    state = State::Normal;
                    ++i;
                }
                break;

            case State::StringLiteral:
                out.push_back(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    state = State::Normal;
                }
                break;

            case State::CharLiteral:
                out.push_back(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '\'') {
                    state = State::Normal;
                }
                break;
        }
    }

    return out;
}

} // namespace

bool is_system_function(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (function) {
        if (function->is_library() || function->is_thunk()) return true;
        if (looks_like_runtime_name(function->name())) return true;
    }

    ida::Result<std::string> name = ida::function::name_at(ea);
    return name && looks_like_runtime_name(*name);
}

bool decompiled_function_is_empty(std::string_view code) {
    if (code.empty()) return false;

    std::size_t open = code.find('{');
    std::size_t close = code.rfind('}');
    if (open == std::string_view::npos
        || close == std::string_view::npos
        || close <= open)
        return false;

    std::string body = strip_c_comments(code.substr(open + 1, close - open - 1));
    std::string compact;
    compact.reserve(body.size());
    for (unsigned char c : body) {
        if (std::isspace(c) == 0)
            compact.push_back(static_cast<char>(c));
    }

    return compact.empty() || compact == ";";
}

std::set<ida::Address> prune_empty_functions(
    std::map<ida::Address, FunctionSummary> &summaries,
    std::vector<Edge> &edges
) {
    std::set<ida::Address> removed;
    for (const auto &[ea, summary] : summaries) {
        if (decompiled_function_is_empty(summary.decompiled_code))
            removed.insert(ea);
    }

    if (removed.empty()) return removed;

    for (ida::Address ea : removed)
        summaries.erase(ea);

    for (auto &[_, summary] : summaries) {
        auto &arg_uses = summary.arg_uses;
        arg_uses.erase(
            std::remove_if(arg_uses.begin(), arg_uses.end(),
                [&](const ArgUse &au) {
                    return au.callee_ea != ida::BadAddress
                        && removed.count(au.callee_ea) != 0;
                }),
            arg_uses.end());
    }

    edges.erase(
        std::remove_if(edges.begin(), edges.end(),
            [&](const Edge &edge) {
                return removed.count(edge.from) != 0
                    || removed.count(edge.to) != 0;
            }),
        edges.end());

    return removed;
}

} // namespace codedump
