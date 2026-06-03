#pragma once

#include "common/types.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace codedump {

struct SubsystemCluster {
    int id = -1;
    std::string label;
    bool utility = false;
    std::vector<ida::Address> functions;
};

struct SubsystemClustering {
    std::vector<SubsystemCluster> clusters;
    std::map<ida::Address, int> cluster_by_function;
};

SubsystemClustering cluster_subsystems(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    double resolution = 1.0);

} // namespace codedump
