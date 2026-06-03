#include "function_filter.h"

#include <ida/function.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

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

} // namespace codedump
