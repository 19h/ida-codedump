#pragma once

#include <ida/address.hpp>

#include <set>
#include <string>

namespace codedump {

struct RegisterSummary {
    std::set<std::string> incoming;  // read before being written along some path
    std::set<std::string> outgoing;  // ever written anywhere in the function
};

// Per-basic-block liveness analysis over the function's flow chart.
// Names are normalized to their parent register on x86 (al/ax/eax → rax,
// r8b/r8w/r8d → r8, ymmN/zmmN → xmmN). Uninformative always-live
// registers (rsp/rip/eflags) are filtered out.
RegisterSummary analyze_function_registers(ida::Address function_ea);

} // namespace codedump
