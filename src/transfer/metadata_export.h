#pragma once

#include "metadata.h"

#include <functional>
#include <string>

namespace codedump {

struct MetadataExportProgress {
    const char *phase = "";    // "graph" | "metadata" | "types" | "serialize"
    size_t processed = 0;
    size_t total = 0;
    uint64_t current_ea = 0;
    const char *current_name = "";
    size_t types_collected = 0;
    size_t comments_collected = 0;
    size_t lvars_collected = 0;
};

using MetadataExportCb = std::function<bool(const MetadataExportProgress &)>;

struct MetadataExportOptions {
    int callee_depth = 5;       // how deep to walk callees from the root
    bool include_types = true;
};

// Build a MetadataDocument starting from `root_ea`. Returns true if the
// document was populated (false on cancellation). The callback can return
// false to abort.
bool export_metadata(
    ida::Address root_ea,
    const MetadataExportOptions &opts,
    MetadataDocument *out,
    const MetadataExportCb &cb = nullptr);

} // namespace codedump
