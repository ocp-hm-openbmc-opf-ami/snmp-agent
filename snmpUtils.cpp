#include "snmpUtils.hpp"

#include "snmpModifyConf.hpp"
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
std::string SnmpTrapStatusFile = "/etc/snmp/SnmpTrapStatus";

namespace phosphor
{
namespace snmp
{
namespace SnmpUtils
{

void writeBoolToFile(std::string& filename, bool value)
{
    std::ofstream file(filename, std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Unable to open file for writing: " << filename
                  << std::endl;
        return;
    }

    file << std::boolalpha << value << std::endl;
    file.close();
    return;
}

bool readBoolFromFile(std::string& filename)
{
    bool value = false;

    std::ifstream file(filename, std::ios::in);
    if (!file.is_open())
    {
        std::cerr << "Unable to open file for reading: " << filename
                  << std::endl;
        return value;
    }

    file >> std::boolalpha >> value;
    file.close();
    return value;
}

bool SnmpUtilsManager::sendSNMPTrap()
{
    static auto bus = sdbusplus::bus::new_default();
    const std::string& service = "xyz.openbmc_project.User.Manager";
    const std::string& objPath = "/xyz/openbmc_project/user";
    bool result = false;

    ObjectValueTree interfaces;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");
    try
    {
        std::cerr << "buca call success" << std::endl;
        auto reply = bus.call(method);
        std::cerr << "buca call response" << std::endl;
        reply.read(interfaces);
        std::cerr << "buca call parse" << std::endl;
    }
    catch (const sdbusplus::exception_t& e)
    {
        std::cerr << "buca call fail" << std::endl;
        lg2::error("Failed to get managed objects: {PATH}", "PATH", objPath);
        elog<InternalFailure>();
    }

    std::cerr << "buca call success" << std::endl;

    std::time_t currentTime = std::time(nullptr);
    struct tm* timeInfo = std::localtime(&currentTime);
    char TrapGenerateTime[80];
    std::strftime(TrapGenerateTime, sizeof(TrapGenerateTime),
                  "%a %b %d %H:%M:%S %Z %Y", timeInfo);

    try
    {
        result = sendTrap<OBMCErrorNotification>(0, TrapGenerateTime, "NA",
                                                 "Test Alert");
        return result;
    }
    catch (const std::exception& e)
    {
        std::cerr << "sendTrap exception: " << e.what() << std::endl;
        return false;
    }
    catch (...)
    {
        std::cerr << "sendTrap unknown exception" << std::endl;
        return false;
    }
}

bool SnmpUtilsManager::snmpTrapStatus(bool value)
{
    bool val;
    if (value == snmpTrapStatus())
    {
        return value;
    }
    std::ofstream file(SnmpTrapStatusFile, std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Unable to open file for writing: " << SnmpTrapStatusFile
                  << std::endl;
        return false;
    }

    file << std::boolalpha << value << std::endl;
    file.close();
    val = snmpTrapStatus(value);
    return val;
}
bool SnmpUtilsManager::snmpTrapStatus() const
{
    bool value = false;
    std::ifstream file(SnmpTrapStatusFile, std::ios::in);
    if (!file.is_open())
    {
        value = false;
        std::cerr << "Unable to open file for reading: " << SnmpTrapStatusFile
                  << std::endl;
        return value;
    }

    file >> std::boolalpha >> value;
    file.close();
    return value;
}
bool SnmpUtilsManager::enableSNMPV1(bool value)
{
    bool currentValue = false;
    currentValue = getSnmpVersionStatus("disableSNMPv1");
    if (value != currentValue)
    {
        return true;
    }
    if (value == false)
    {
        SetSnmpVersionStatus("disableSNMPv1", true);
    }
    else
    {
        SetSnmpVersionStatus("disableSNMPv1", false);
    }
    return value;
}

bool SnmpUtilsManager::enableSNMPV1() const
{
    bool currentValue = false;
    currentValue = getSnmpVersionStatus("disableSNMPv1");
    return !currentValue;
}

bool SnmpUtilsManager::enableSNMPV2(bool value)
{
    bool currentValue = false;
    currentValue = getSnmpVersionStatus("disableSNMPv2c");
    if (value != currentValue)
    {
        return true;
    }
    if (value == false)
    {
        SetSnmpVersionStatus("disableSNMPv2c", true);
    }
    else
    {
        SetSnmpVersionStatus("disableSNMPv2c", false);
    }
    return value;
}

bool SnmpUtilsManager::enableSNMPV2() const
{
    bool currentValue = false;
    currentValue = getSnmpVersionStatus("disableSNMPv2c");
    return !currentValue;
}

bool SnmpUtilsManager::enableSNMPV3(bool value)
{
    bool currentValue = false;
    currentValue = getSnmpVersionStatus("disableSNMPv3");
    if (value != currentValue)
    {
        return true;
    }
    if (value == false)
    {
        SetSnmpVersionStatus("disableSNMPv3", true);
    }
    else
    {
        SetSnmpVersionStatus("disableSNMPv3", false);
    }
    return value;
}

bool SnmpUtilsManager::enableSNMPV3() const
{
    bool currentValue = false;
    currentValue = getSnmpVersionStatus("disableSNMPv3");
    return !currentValue;
}

std::vector<std::string> SnmpUtilsManager::listSNMPCommunityProfile()
{
    std::vector<std::string> viewAccessParameter;
    std::ifstream snmpdConfFileStream(snmpdConfFilepath);
    std::string line;

    if (!snmpdConfFileStream)
    {
        std::cerr << "Unable to open file:" << snmpdConfFilepath << std::endl;
        return viewAccessParameter;
    }

    while (std::getline(snmpdConfFileStream, line))
    {
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        size_t pos1 = line.find("view ");
        size_t pos2 = line.find(" included");

        if (pos1 != std::string::npos && pos2 != std::string::npos)
        {
            std::string viewName = line.substr(pos1 + 5, pos2 - (pos1 + 5));

            viewName.erase(
                std::remove_if(viewName.begin(), viewName.end(), ::isspace),
                viewName.end());

            if (!viewName.empty())
            {
                viewAccessParameter.push_back(viewName);
            }
        }
    }

    snmpdConfFileStream.close();
    return viewAccessParameter;
}

} // namespace SnmpUtils
} // namespace snmp
} // namespace phosphor
