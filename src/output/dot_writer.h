#pragma once

#include "common/types.h"
#include <vector>
#include <set>
#include <string>

namespace codedump {

class DotWriter {
public:
    DotWriter() = default;

    // Build the DOT text. The file writer + clipboard path both consume this.
    std::string render(
        const std::set<ida::Address> &functions,
        const std::vector<Edge> &edges,
        const std::set<ida::Address> &start_functions,
        const DumpOptions &opts = DumpOptions{}
    );

    bool write(
        const std::string &path,
        const std::set<ida::Address> &functions,
        const std::vector<Edge> &edges,
        const std::set<ida::Address> &start_functions,
        const DumpOptions &opts = DumpOptions{}
    );

private:
    std::string get_edge_style(const std::set<RefType> &types, bool include_label);
    std::string get_edge_color(RefType type);
};

} // namespace codedump
