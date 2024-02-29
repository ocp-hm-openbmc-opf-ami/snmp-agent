#pragma once

#include "snmp.hpp"
#include "snmp_notification.hpp"
#include <iostream>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include "xyz/openbmc_project/Snmp/SnmpUtils/server.hpp"

using SNMPIface = sdbusplus::xyz::openbmc_project::Snmp::server::SnmpUtils;
using namespace phosphor::network::snmp;

const std::string SnmpTrapStatusFile = "/etc/snmp/SnmpTrapStatus";

void writeBoolToFile(const std::string& filename, bool value) 
{
    std::ofstream file(filename, std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Unable to open file for writing: " << filename << std::endl;
        return ;
    }

    file << std::boolalpha << value << std::endl;
    file.close();
    return ;
}

void readBoolFromFile(const std::string& filename, bool& value) 
{

    std::ifstream file(filename, std::ios::in);
    if (!file.is_open()) {

        value = false;
        std::cerr << "Unable to open file for reading: " << filename << std::endl;
        return ;
    }

    file >> std::boolalpha >> value;
    file.close();
    return ;
}


class SnmpUtilsManager : public SNMPIface
{
    private:
        using sdbusplus::xyz::openbmc_project::Snmp::server::SnmpUtils::sendSNMPTrap;


    public:
        SnmpUtilsManager() = delete;
        SnmpUtilsManager(const SnmpUtilsManager&) = delete;
        SnmpUtilsManager& operator=(const SnmpUtilsManager&) = delete;
        SnmpUtilsManager(SnmpUtilsManager&&) = delete;
        SnmpUtilsManager& operator=(SnmpUtilsManager&&) = delete;
        virtual ~SnmpUtilsManager() = default;

        SnmpUtilsManager(sdbusplus::bus_t & bus, const char * path): SNMPIface(bus, path)
    {

    }

        bool sendSNMPTrap() override
        {
            std::time_t currentTime = std::time(nullptr);
            struct tm *timeInfo = std::localtime(&currentTime);

            char TrapGenerateTime[80];
            std::strftime(TrapGenerateTime, sizeof(TrapGenerateTime), "%a %b %d %H:%M:%S %Z %Y", timeInfo);

            sendTrap<OBMCErrorNotification>(0,TrapGenerateTime,"NA","Test Alert");
            return true;
        }

        bool snmpTrapStatus() const override
        {
            bool snmpstatus = false;

            readBoolFromFile(SnmpTrapStatusFile, snmpstatus);

            return snmpstatus;
        }

        bool snmpTrapStatus(bool value) override
        {
            bool val;

            if (value == snmpTrapStatus())
            {
                return value;
            }

            writeBoolToFile(SnmpTrapStatusFile, value);

            val = snmpTrapStatus(value);


            return val;
        }

};


