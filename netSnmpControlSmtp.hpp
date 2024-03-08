#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <boost/system/error_code.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/message/native_types.hpp>


#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <regex>
#include <span>
#include <fstream>
#include <sstream>
#include <tuple>


#ifndef NETSNMPCONTROLSMTP_H
#define NETSNMPCONTROLSMTP_H
const std::string tempChassisFilepath = "/tmp/chassis.tmp";

void init_netSnmpControlSmtpScalars(void);

Netsnmp_Node_Handler handle_amiSnmpSMTPPriStatus;
Netsnmp_Node_Handler handle_amiSnmpSMTPSecStatus;

#endif /* NETSNMPCONTROLSMTP_H */

