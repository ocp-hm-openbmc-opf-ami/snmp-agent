#pragma once

#include <sdbusplus/asio/object_server.hpp>
#include <string>

extern const std::string snmpConfFilepath;
extern const std::string snmpdConfFilepath;
extern const std::string snmpdConfExtFilepath;
extern const std::string snmpdConfExtFileDir;

std::vector<std::string> listCommunityString();
bool addCommunityString(const std::string &accessType,
                        const std::string &communityString,
                        const std::string &viewAccess);
void registerSnmpDbus(
    std::shared_ptr<sdbusplus::asio::dbus_interface> ifaceSnmpConf);

void registerSnmpdDbus(
    std::shared_ptr<sdbusplus::asio::dbus_interface> ifaceSnmpdConf);
