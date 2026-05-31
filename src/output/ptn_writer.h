#pragma once

#include "common/types.h"
#include "analysis/ptn_emitter.h"
#include <map>
#include <vector>
#include <set>
#include <string>

namespace codedump {

class PTNWriter {
public:
    PTNWriter() = default;

    // Build the PTN text. The file writer + clipboard path both consume this.
    std::string render(
        const std::map<ida::Address, FunctionSummary> &summaries,
        const std::set<ida::Address> &start_eas,
        int callee_depth,
        PTNEmitter &emitter
    );

    bool write(
        const std::string &path,
        const std::map<ida::Address, FunctionSummary> &summaries,
        const std::set<ida::Address> &start_eas,
        int callee_depth,
        PTNEmitter &emitter
    );
};

} // namespace codedump
