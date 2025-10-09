#pragma once

#include "snmp_agent_client.hpp"

#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sdbusplus/server.hpp>

#include <iostream>
#include <map>
#include <string>
#define MIN_PWD_LEN 8

std::vector<std::string> testing();

namespace phosphor
{

/* Need a custom deleter for freeing up addrinfo */
struct AddrDeleter
{
    void operator()(addrinfo* addrPtr) const
    {
        if (addrPtr != nullptr)
        {
            freeaddrinfo(addrPtr);
        }
    }
};

using AddrPtr = std::unique_ptr<addrinfo, AddrDeleter>;

using DbusInterface = std::string;
using DbusProperty = std::string;

using Value = std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t,
                           int64_t, uint64_t, std::string>;

using PropertyMap = std::map<DbusProperty, Value>;

using DbusInterfaceMap = std::map<DbusInterface, PropertyMap>;

using ObjectValueTree =
    std::map<sdbusplus::message::object_path, DbusInterfaceMap>;

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

namespace network
{

/** @brief Resolves the given address to IP address.
 *         Given address could be hostname or IP address.
 *         if given address is not valid then it throws an exception.
 *  @param[in] address - address which needs to be converted into IP address.
 *  @return the IP address.
 */
std::string resolveAddress(const std::string& address);

namespace snmp
{

struct mgrProperty
{
    std::string ipaddress;
    std::string version;
    std::string user;
    std::string password;
    bool readonlypermission;
    std::string algorithm;
    std::string encryption;
};

/** @brief Gets all the snmp manager info.
 *  @return the list of manager info in the format
 *          of ipaddress:port
 */

bool communityStringProfile(std::string value);
std::vector<std::string> testing();
bool communityStringPermission(std::string value);
bool communityStringValidation(std::string value);

bool userNameValidate(std::string value);
bool passwordValidate(std::string value);
bool encryptionValidate(std::string value);
bool algorithmValidate(std::string value);
bool ReadWritePermissionValidate(std::string value);

void createSNMPv3User(const std::string userName, const std::string password,
                      const std::string encryption, const std::string algorithm,
                      const std::string readWritePermission);

void deleteSNMPManager(const std::string& id);
bool updateFile(const std::string& filePath, const std::string& pattern);

} // namespace snmp
} // namespace network

} // namespace phosphor
