#pragma once

#include "common/types.h"

#include <ida/address.hpp>

#include <map>
#include <set>
#include <string_view>
#include <vector>

namespace codedump {

bool is_system_function(ida::Address ea);
bool decompiled_function_is_empty(std::string_view code);

// Removes empty decompiler stubs from summaries, removes all graph edges that
// touch them, and removes caller-side ArgUse records so PTN does not emit
// annotations pointing at functions that are no longer in the dump.
std::set<ida::Address> prune_empty_functions(
    std::map<ida::Address, FunctionSummary> &summaries,
    std::vector<Edge> &edges);

} // namespace codedump
