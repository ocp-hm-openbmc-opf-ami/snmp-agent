#pragma once

#include "snmp.hpp"
#include "snmpModifyConf.hpp"
#include "snmp_notification.hpp"
#include "xyz/openbmc_project/Snmp/SnmpUtils/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>

#include <fstream>
#include <iostream>

namespace phosphor
{
namespace snmp
{
namespace SnmpUtils
{

using SNMPIface = sdbusplus::xyz::openbmc_project::Snmp::server::SnmpUtils;
using namespace phosphor::network::snmp;

class SnmpUtilsManager : public SNMPIface
{
  private:
    using sdbusplus::xyz::openbmc_project::Snmp::server::SnmpUtils::
        sendSNMPTrap;
    void writeBoolToFile(std::string& filename, bool value);
    bool isStringVectorStrings(const std::vector<std::string>& Strings,
                               const std::string& str);
    bool readBoolFromFile(std::string& filename);

  public:
    SnmpUtilsManager() = delete;
    SnmpUtilsManager(const SnmpUtilsManager&) = delete;
    SnmpUtilsManager& operator=(const SnmpUtilsManager&) = delete;
    SnmpUtilsManager(SnmpUtilsManager&&) = delete;
    SnmpUtilsManager& operator=(SnmpUtilsManager&&) = delete;
    virtual ~SnmpUtilsManager() = default;

    SnmpUtilsManager(sdbusplus::bus_t& bus, const char* path) :
        SNMPIface(bus, path)
    {}

    bool sendSNMPTrap() override;
    bool snmpTrapStatus(bool value) override;
    bool snmpTrapStatus() const override;
    bool enableSNMPV1(bool value) override;
    bool enableSNMPV1() const override;
    bool enableSNMPV2(bool value) override;
    bool enableSNMPV2() const override;
    bool enableSNMPV3(bool value) override;
    bool enableSNMPV3() const override;
    std::vector<std::string> listSNMPCommunityProfile() override;
};

} // namespace SnmpUtils
} // namespace snmp
} // namespace phosphor
