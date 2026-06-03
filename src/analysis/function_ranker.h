#pragma once

#include "common/types.h"

#include <set>
#include <vector>

namespace codedump {

std::vector<ida::Address> order_functions_by_address(
    const std::set<ida::Address> &functions);

std::vector<ida::Address> order_functions_by_entryness(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions);

std::vector<ida::Address> order_functions_by_centrality(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions);

std::vector<ida::Address> order_functions(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions,
    FunctionOrder order);

} // namespace codedump
