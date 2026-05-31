#include "ptn_writer.h"

#include <fstream>

namespace codedump {

std::string PTNWriter::render(
    const std::map<ida::Address, FunctionSummary> &summaries,
    const std::set<ida::Address> &start_eas,
    int callee_depth,
    PTNEmitter &emitter
) {
    // Get all function EAs as the restrict set
    std::set<ida::Address> all_funcs;
    for (const auto &[ea, _] : summaries) {
        all_funcs.insert(ea);
    }
    return emitter.emit_ptn(start_eas, callee_depth, &all_funcs);
}

bool PTNWriter::write(
    const std::string &path,
    const std::map<ida::Address, FunctionSummary> &summaries,
    const std::set<ida::Address> &start_eas,
    int callee_depth,
    PTNEmitter &emitter
) {
    std::string text = render(summaries, start_eas, callee_depth, emitter);
    std::ofstream out(path);
    if (!out) return false;
    out << text;
    return (bool)out;
}

} // namespace codedump
