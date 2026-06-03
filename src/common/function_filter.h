#pragma once

#include <ida/address.hpp>

namespace codedump {

bool is_system_function(ida::Address ea);

} // namespace codedump
