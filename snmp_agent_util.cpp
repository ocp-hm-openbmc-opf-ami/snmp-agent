#include "snmp_agent_util.hpp"

#include "netSnmpAmiHandle.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#include <string>

namespace phosphor
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using dbusPropVariant =
    std::variant<std::vector<std::string>, std::string, double, uint16_t, bool>;
namespace network
{

std::string resolveAddress(const std::string& address)
{
    addrinfo hints{};
    addrinfo* addr = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    auto result = getaddrinfo(address.c_str(), NULL, &hints, &addr);
    if (result)
    {
        lg2::error("getaddrinfo failed {ADDRESS}: {RC}", "ADDRESS", address,
                   "RC", result);
        elog<InternalFailure>();
    }

    AddrPtr addrPtr{addr};
    addr = nullptr;

    char ipaddress[INET6_ADDRSTRLEN]{0};
    result = getnameinfo(addrPtr->ai_addr, addrPtr->ai_addrlen, ipaddress,
                         sizeof(ipaddress), NULL, 0, NI_NUMERICHOST);
    if (result)
    {
        lg2::error("getnameinfo failed {ADDRESS}: {RC}", "ADDRESS", address,
                   "RC", result);
        elog<InternalFailure>();
    }

    unsigned char buf[sizeof(struct in6_addr)];
    int isValid = inet_pton(AF_INET, ipaddress, buf);
    if (isValid < 0)
    {
        lg2::error("Invalid address {ADDRESS}: {RC}", "ADDRESS", address, "RC",
                   isValid);
        elog<InternalFailure>();
    }
    if (isValid == 0)
    {
        int isValid6 = inet_pton(AF_INET6, ipaddress, buf);
        if (isValid6 < 1)
        {
            lg2::error("Invalid address {ADDRESS}: {RC}", "ADDRESS", address,
                       "RC", isValid);
            elog<InternalFailure>();
        }
        char ipTemp[INET6_ADDRSTRLEN]{0};
        strcat(ipTemp, "[");
        strcat(ipTemp, ipaddress);
        strcat(ipTemp, "]");
        strcpy(ipaddress, ipTemp);
    }

    return ipaddress;
}

namespace snmp
{

bool communityStringValidation(std::string value)
{
    constexpr std::array<std::string_view, 4> propertieNotAllowdValues = {
        "public", "private", "PUBLIC", "PRIVATE"};
    if (value.empty() || std::find(propertieNotAllowdValues.begin(),
                                   propertieNotAllowdValues.end(), value) !=
                             propertieNotAllowdValues.end())
    {
        lg2::error("communityString value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("communityString"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

bool communityStringPermission(std::string value)
{
    constexpr std::array<std::string_view, 2> propertieAllowdValues = {
        "rwcommunity", "rocommunity"};
    if (value.empty() ||
        std::find(propertieAllowdValues.begin(), propertieAllowdValues.end(),
                  value) == propertieAllowdValues.end())
    {
        lg2::error(" readWritePermission value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("readWritePermission"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

std::vector<std::string> testing()
{
    const std::string snmpdConfFile = "/etc/snmp/snmpd.conf";
    std::vector<std::string> viewAccessParameter;
    std::ifstream snmpdConfFileStream(snmpdConfFile);
    std::string line;

    if (!snmpdConfFileStream)
    {
        lg2::error("Unable to open file:");
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

bool communityStringProfile(std::string value)
{
    std::vector<std::string> propertieAllowdValues = testing();
    if (value.empty() ||
        std::find(propertieAllowdValues.begin(), propertieAllowdValues.end(),
                  value) == propertieAllowdValues.end())
    {
        lg2::error(" CommunityProfile value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("CommunityProfile"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

bool userNameValidate(std::string value)
{
    setpwent();
    bool UsernameExists = false, enableStatus = false;
    struct passwd* pw;
    const char* userManagerService = "xyz.openbmc_project.User.Manager";
    const char* userAttributeInterface = "xyz.openbmc_project.User.Attributes";
    const char* objpath = "/xyz/openbmc_project/user/";
    constexpr const char* snmpEnableStatus = "SNMPAccessEnableStatus";
    std::string userObjPath = objpath + value;

    enableStatus = std::get<bool>(
        getDbusProperty(userManagerService, userObjPath, userAttributeInterface,
                        snmpEnableStatus));
    while ((pw = getpwent()) != nullptr)
    {
        if (value == pw->pw_name)
        {
            UsernameExists = true; // Username already exists
            break;
        }
    }
    endpwent();
    if ((!enableStatus) || value.empty() || !UsernameExists)
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("userName"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

bool passwordValidate(std::string value)
{
    if (value.empty() || value.length() < MIN_PWD_LEN)
    {
        lg2::error("password value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("password"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}
bool encryptionValidate(std::string value)
{
    constexpr std::array<std::string_view, 1> propertieAllowdValues = {
        "AES"};
    if (value.empty() ||
        (std::find(propertieAllowdValues.begin(), propertieAllowdValues.end(),
                   value) == propertieAllowdValues.end()))
    {
        lg2::error("encryption value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("encryption"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

bool algorithmValidate(std::string value)
{
    constexpr std::array<std::string_view, 2> propertieAllowdValues = {
        "SHA-384", "SHA-512"};
    if (value.empty() ||
        std::find(propertieAllowdValues.begin(), propertieAllowdValues.end(),
                  value) == propertieAllowdValues.end())
    {
        lg2::error("algorithm value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("algorithm"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

bool ReadWritePermissionValidate(std::string value)
{
    constexpr std::array<std::string_view, 2> propertieAllowdValues = {
        "ro", "rw"};
    if (value.empty() ||
        std::find(propertieAllowdValues.begin(), propertieAllowdValues.end(),
                  value) == propertieAllowdValues.end())
    {
        lg2::error("readWritePermission value not supported");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("readWritePermission"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    return true;
}

void createSNMPv3User(const std::string userName, const std::string password,
                      const std::string encryption, const std::string algorithm,
                      const std::string readWritePermission)
{
    if (userName.empty())
    {
        lg2::error("Error: Username cannot be empty.");
        return;
    }

    std::string s_command = "AMI-snmp-create-v3-user ";
    if (readWritePermission == "ro")
    {
        s_command.append("-ro ");
    }
    s_command.append(" -A ");
    s_command.append(password);
    s_command.append(" -a ");
    s_command.append(algorithm);
    s_command.append(" -X ");
    s_command.append(password);
    s_command.append(" -x ");
    s_command.append(encryption);
    s_command.append(" ");
    s_command.append(userName);

    if (system("systemctl stop snmpd.service") == -1)
    {
        lg2::error("Stopping the snmpd.service Failed ..");
    }
    if (system(s_command.c_str()) == -1)
    {
        lg2::error("net-snmp-create-v3 command Failed ...");
    }
    if (system("systemctl start snmpd.service") == -1)
    {
        lg2::error("Restarting the snmpd.service Failed....");
    }
}

void deleteSNMPManager(const std::string& id)
{
    const std::string snmpService = "xyz.openbmc_project.Network.SNMP";
    const std::string snmpManagerPath =
        "/xyz/openbmc_project/network/snmp/manager";
    const std::string ifaceNetworkClient = "xyz.openbmc_project.Network.Client";
    try
    {
        auto bus = sdbusplus::bus::new_default();
        auto method = bus.new_method_call(
            snmpService.c_str(), snmpManagerPath.c_str(),
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
        auto reply = bus.call(method);

        std::map<sdbusplus::message::object_path,
                 std::map<std::string,
                          std::map<std::string,
                                   std::variant<std::string, uint16_t, bool>>>>
            managedObjects;
        reply.read(managedObjects);

        for (const auto& [path, interfaces] : managedObjects)
        {
            auto it = interfaces.find(ifaceNetworkClient);
            if (it == interfaces.end())
                continue;

            auto propIt = it->second.find("User");
            if (propIt == it->second.end())
                continue;

            std::string userVal = std::get<std::string>(propIt->second);
            if (userVal == id)
            {
                const std::string objPath = path;
                auto delMethod = bus.new_method_call(
                    snmpService.c_str(), objPath.c_str(),
                    "xyz.openbmc_project.Object.Delete", "Delete");
                bus.call(delMethod);
                lg2::info("Deleted SNMP Manager object: {OBJ}", "OBJ",
                          std::string(path));
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed during deleteSNMPManager: {ERR}", "ERR", e.what());
    }
}

bool updateFile(const std::string& filePath, const std::string& pattern)
{
    const std::string tmpFile = filePath + ".tmp";

    try
    {
        std::filesystem::copy_file(
            filePath, tmpFile,
            std::filesystem::copy_options::overwrite_existing);

        std::ifstream inFile(tmpFile);
        if (!inFile.is_open())
        {
            lg2::error("Unable to open temp file: {FILE}", "FILE", tmpFile);
            return false;
        }

        std::vector<std::string> filteredLines;
        std::string line;
        bool found = false;

        while (std::getline(inFile, line))
        {
            if (line.find(pattern) != std::string::npos)
            {
                lg2::info("Removed line containing: {PATTERN}", "PATTERN",
                          pattern);
                found = true;
                continue;
            }
            filteredLines.push_back(line);
        }
        inFile.close();

        std::ofstream outFile(tmpFile, std::ios::trunc);
        if (!outFile.is_open())
        {
            lg2::error("Unable to reopen temp file for writing: {FILE}", "FILE",
                       tmpFile);
            return false;
        }

        for (const auto& l : filteredLines)
            outFile << l << "\n";
        outFile.close();

        std::filesystem::rename(tmpFile, filePath);
        return found;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to update file: {ERR}", "ERR", e.what());
        return false;
    }
}

} // namespace snmp
} // namespace network
} // namespace phosphor
