/*
 * Net-SNMP headers are order-sensitive and must be included as shown below.
 * net-snmp-config.h defines mandatory build/configuration macros and must be
 * included before any other Net-SNMP headers.
 * net-snmp-includes.h provides core library types and typedefs (e.g.,
 * netsnmp_container) required by higher-level components.
 * net-snmp-agent-includes.h pulls in the SNMP agent framework and assumes
 * all configuration macros and core types are already defined.
 * Reordering these includes (e.g., by clang-format) will break the build.
 */
// clang-format off
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
// clang-format on

#include <boost/system/error_code.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/message/native_types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <regex>
#include <span>
#include <sstream>
#include <tuple>

#ifndef NETSNMPAMI_H
#define NETSNMPAMI_H

void init_netSnmpAMIScalars(void);

Netsnmp_Node_Handler handle_amiSnmpSMTPPriStatus;
Netsnmp_Node_Handler handle_amiSnmpSMTPSecStatus;
Netsnmp_Node_Handler handle_amiACD_DataArea;
Netsnmp_Node_Handler handle_amiACD_Trigger;
#endif /* NETSNMPAMI_H */
