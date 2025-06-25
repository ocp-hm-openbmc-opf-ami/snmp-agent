#include "snmp_agent_client.hpp"

#include "snmp_agent_serialize.hpp"
#include "snmp_agent_util.hpp"
#include "snmp_conf_manager.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>
#include <grp.h>
#include <syslog.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>
#include <iostream>

#define DEFAULT_SNMPTRAP_PORT 162

namespace phosphor
{
namespace snmp
{
namespace communityStr
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace phosphor::network::snmp;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

CommunityStrManager::CommunityStrManager(
    sdbusplus::bus_t& bus, const char* objPath, ConfManager& parent,
    const std::string& communityString, const std::string& readWritePermission,
    const std::string& communityProfile) :
    Ifaces(bus, objPath, Ifaces::action::defer_emit), parent(parent)
{
    this->communityString(communityString);
    this->readWritePermission(readWritePermission);
    this->communityProfile(communityProfile);
}

std::string CommunityStrManager::communityString(std::string value)
{
    if (communityStringValidation(value))
    {
        if (value == Ifaces::communityString())
        {
            return value;
        }
        auto addr = Ifaces::communityString(value);
        serialize(value, *this, parent.dbusPersistentLocation);
        return addr;
    }
    else
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("communityString"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}
std::string CommunityStrManager::readWritePermission(std::string value)
{
    std ::string communityRef = Ifaces::communityString();
    if (communityStringPermission(value))
    {
        if (value == Ifaces::readWritePermission())
        {
            return value;
        }
        auto version = Ifaces::readWritePermission(value);
        serialize(communityRef, *this, parent.dbusPersistentLocation);
        return version;
    }
    else
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("communityString"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}

std::string CommunityStrManager::communityProfile(std::string value)
{
    std ::string communityRef = Ifaces::communityString();
    if (communityStringProfile(value))
    {
        if (value == Ifaces::communityProfile())
        {
            return value;
        }
        auto username = Ifaces::communityProfile(value);
        serialize(communityRef, *this, parent.dbusPersistentLocation);
        return username;
    }
    else
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("communityString"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}

void CommunityStrManager::delete_()
{
    parent.deleteSNMPClient(Ifaces::communityString());
}
} // namespace communityStr
} // namespace snmp
} // namespace phosphor
