#include "snmp_user_create.hpp"
#include "Encryption.hpp"
#include "snmp_agent_serialize.hpp"
#include "snmp_agent_util.hpp"
#include "snmp_user_manager.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>
#include <grp.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#define DEFAULT_SNMPTRAP_PORT 162

namespace phosphor
{
namespace snmp
{
namespace user
{
using namespace phosphor::logging;
using namespace phosphor::network::snmp;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

UserManager::UserManager(
    sdbusplus::bus_t& bus, const char* objPath, ConfManager& parent,
    const std::string userName, const std::string password,
    const std::string encryption, const std::string algorithm,
    const std::string readWritePermission) :
    Ifaces(bus, objPath, Ifaces::action::defer_emit), parent(parent)
{
    this->userName(std::move(userName));
    this->password(std::move(password));
    this->encryption(std::move(encryption));
    this->algorithm(std::move(algorithm));
    this->readWritePermission(std::move(readWritePermission));
}

std::string UserManager::userName(std::string value)
{
    if (userNameValidate(value))
    {
        if (value == Ifaces::userName())
        {
            return value;
        }
        auto addr = Ifaces::userName(value);
        serialize(value, *this, parent.dbusPersistentLocation);
        return addr;
    }
    else
    {
        lg2::error("userName value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("userName"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}
std::string UserManager::password(std::string value)
{
    std ::string userRef = Ifaces::userName();
    if(passwordValidate(value))
    {
	    std::string EncPswd = encryptString(value);
	    Ifaces::password(EncPswd);
	    serialize(userRef, *this, parent.dbusPersistentLocation);
	    return EncPswd;
    }
    else
    {
        lg2::error("Password value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Password"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}

std::string UserManager::encryption(std::string value)
{
    std ::string userRef = Ifaces::userName();
    if (encryptionValidate(value))
    {
        if (value == Ifaces::encryption())
        {
            return value;
        }
        auto username = Ifaces::encryption(value);
        serialize(userRef, *this, parent.dbusPersistentLocation);
        return username;
    }
    else
    {
        lg2::error("Encryption value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Encryption"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}

std::string UserManager::algorithm(std::string value)
{
    std ::string userRef = Ifaces::userName();
    if (algorithmValidate(value))
    {
        if (value == Ifaces::algorithm())
        {
            return value;
        }
        auto comStr = Ifaces::algorithm(value);
        serialize(userRef, *this, parent.dbusPersistentLocation);
        return comStr;
    }
    else
    {
        lg2::error("algorithm value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("algorithm"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}

std::string UserManager::readWritePermission(std::string value)
{
    std ::string userRef = Ifaces::userName();
    if (ReadWritePermissionValidate(value))
    {
        if (value == Ifaces::readWritePermission())
        {
            return value;
        }
        auto algorithm = Ifaces::readWritePermission(value);
        serialize(userRef, *this, parent.dbusPersistentLocation);
        return algorithm;
    }
    else
    {
        lg2::error("ReadWritePermission value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ReadWritePermission"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
}
void UserManager::delete_()
{
    parent.deleteSNMPClient(Ifaces::userName());
}
} // namespace user
} // namespace snmp
} // namespace phosphor
