#pragma once

#include "metadata.h"

#include <functional>
#include <string>
#include <vector>

namespace codedump {

struct MetadataApplyProgress {
    const char *phase = "";    // "verify" | "types" | "apply" | "done"
    size_t processed = 0;
    size_t total = 0;
    uint64_t current_source_ea = 0;
    uint64_t current_target_ea = 0;
    const char *current_name = "";
    size_t mismatches = 0;     // running count of fingerprint mismatches
    size_t applied_names = 0;
    size_t applied_protos = 0;
    size_t applied_cmts = 0;
    size_t applied_lvars = 0;
    size_t applied_types = 0;
};

using MetadataApplyCb = std::function<bool(const MetadataApplyProgress &)>;

struct MetadataApplyOptions {
    // If true, applying continues past functions whose fingerprint mismatched
    // (only the mismatching function and its subtree are skipped).
    bool continue_on_mismatch = true;
    // If true, names that already exist on the target are overwritten.
    bool overwrite_existing = true;
};

struct MetadataApplyReport {
    bool ok = false;
    std::string fatal_error;          // populated when ok=false
    size_t functions_matched = 0;     // fingerprint verified ok
    size_t functions_mismatched = 0;
    size_t names_applied = 0;
    size_t prototypes_applied = 0;
    size_t comments_applied = 0;
    size_t lvars_applied = 0;
    size_t types_applied = 0;
    // For each mismatched function we record one line of diagnosis.
    std::vector<std::string> mismatch_details;
};

// Apply a previously-exported document. `target_root_ea` is the ea in the
// current IDB that the dump's root function should be mapped onto.
bool apply_metadata(
    const MetadataDocument &doc,
    ida::Address target_root_ea,
    const MetadataApplyOptions &opts,
    MetadataApplyReport *report,
    const MetadataApplyCb &cb = nullptr);

} // namespace codedump
