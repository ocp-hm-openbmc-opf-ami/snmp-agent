// Redirect the hard-coded /etc/snmp/* path globals in snmpModifyConf.cpp
// and Encryption.cpp to /tmp/snmp-test/* before tests run, so tests do
// not require root write access to /etc.  The globals are `const std::string`
// or `const char*` objects that live in writable storage, so the casts are
// well-defined here.
#include "Encryption.hpp"
#include "snmpModifyConf.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

int main(int argc, char** argv)
{
    namespace fs = std::filesystem;

    // Redirect snmpModifyConf.cpp path globals to a writable temp tree.
    const_cast<std::string&>(snmpdConfFilepath) = "/tmp/snmp-test/snmpd.conf";
    const_cast<std::string&>(snmpdConfExtFilepath) =
        "/tmp/snmp-test/snmpd.conf.d/snmpd.conf";
    const_cast<std::string&>(snmpdConfExtFileDir) =
        "/tmp/snmp-test/snmpd.conf.d/";
    const_cast<std::string&>(snmpConfFilepath) = "/tmp/snmp-test/snmp.conf";

    // Redirect Encryption.cpp AES key file globals.
    aesKeyFile = "/tmp/snmp-test/AESKey";
    aesIVFile = "/tmp/snmp-test/AESIV";

    std::error_code ec;
    fs::create_directories("/tmp/snmp-test/snmpd.conf.d", ec);

    // removeCommunityString writes a hardcoded temp file at
    // /etc/snmp/snmpd.conf.d/snmpd_tmp.conf which is NOT redirected.
    // Best-effort sudo to make /etc/snmp writable inside the container.
    int rc = std::system(
        "sudo -n mkdir -p /etc/snmp/snmpd.conf.d 2>/dev/null && "
        "sudo -n chmod 0777 /etc/snmp /etc/snmp/snmpd.conf.d 2>/dev/null");
    (void)rc;

    // Seed /etc/snmp/snmpd.conf so functions that always read that path
    // (testing(), listViewAccess, communityStringProfile, etc.) see valid
    // content.
    {
        std::ofstream snmpd("/etc/snmp/snmpd.conf");
        if (snmpd.is_open())
        {
            snmpd << "# auto-seeded by tests/test_main.cpp\n"
                  << "view all included .1\n"
                  << "view systemonly included .1.3.6.1.2.1\n"
                  << "rocommunity public default -V all\n";
        }
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
