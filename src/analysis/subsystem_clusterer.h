#pragma once

#include "common/types.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace codedump {

struct SubsystemCluster {
    int id = -1;
    std::string label;             // granular, discriminative label (e.g. "dot-writer · graph")
    bool utility = false;
    std::string category;          // fixed palette slot for color (e.g. "graph","types","stl_util")
    std::string evidence;          // short "why" hint (e.g. a __FILE__ basename or top scope token)
    int func_count = 0;            // true subsystem mass incl. single-caller-collapsed children
    std::vector<ida::Address> functions;
};

struct SubsystemClusterEdge {
    int from = -1;
    int to = -1;
    std::set<RefType> types;
    int count = 0;
};

struct SubsystemClustering {
    std::vector<SubsystemCluster> clusters;
    std::map<ida::Address, int> cluster_by_function;
    std::vector<SubsystemClusterEdge> cluster_edges;
};

SubsystemClustering cluster_subsystems(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    double resolution = 1.0);

} // namespace codedump
