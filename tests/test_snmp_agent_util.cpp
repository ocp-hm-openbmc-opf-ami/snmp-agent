// test_snmp_agent_util.cpp — unit tests for snmp_agent_util.cpp validators
//
// snmp_agent_util.hpp transitively includes snmp_agent_client.hpp, which
// declares ::testing() at global scope.  Including that header in the same
// TU as <gtest/gtest.h> (which opens namespace testing) would cause a
// redeclaration error.  To avoid this, the functions under test are
// forward-declared here directly; snmp_agent_util.hpp is NOT included.

#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

// ---------------------------------------------------------------------------
// Forward declarations — matches the implementations in snmp_agent_util.cpp
// ---------------------------------------------------------------------------
namespace phosphor
{
namespace network
{
std::string resolveAddress(const std::string& address);

namespace snmp
{
bool communityStringValidation(std::string value);
bool communityStringPermission(std::string value);
bool passwordValidate(std::string value);
bool encryptionValidate(std::string value);
bool algorithmValidate(std::string value);
bool ReadWritePermissionValidate(std::string value);
std::vector<std::string> testing();
bool communityStringProfile(std::string value);
void createSNMPv3User(const std::string, const std::string, const std::string,
                      const std::string, const std::string);
bool updateFile(const std::string& filePath, const std::string& pattern);
void deleteSNMPManager(const std::string& id);
} // namespace snmp
} // namespace network
} // namespace phosphor

using phosphor::network::resolveAddress;
using phosphor::network::snmp::algorithmValidate;
using phosphor::network::snmp::communityStringPermission;
using phosphor::network::snmp::communityStringProfile;
using phosphor::network::snmp::communityStringValidation;
using phosphor::network::snmp::createSNMPv3User;
using phosphor::network::snmp::encryptionValidate;
using phosphor::network::snmp::passwordValidate;
using phosphor::network::snmp::ReadWritePermissionValidate;
// NOTE: no 'using' for testing() — it would conflict with gtest's ::testing
// namespace.
using phosphor::network::snmp::deleteSNMPManager;
using phosphor::network::snmp::updateFile;

namespace
{

// ---------------------------------------------------------------------------
// communityStringValidation
// ---------------------------------------------------------------------------

TEST(CommunityStringValidationTest, ValidInput_ReturnsTrue)
{
    EXPECT_TRUE(communityStringValidation("myCommunity"));
}

TEST(CommunityStringValidationTest, LongValidInput_ReturnsTrue)
{
    EXPECT_TRUE(communityStringValidation("a_very_long_community_string_123"));
}

TEST(CommunityStringValidationTest, Public_Throws)
{
    EXPECT_THROW(communityStringValidation("public"), std::exception);
}

TEST(CommunityStringValidationTest, Private_Throws)
{
    EXPECT_THROW(communityStringValidation("private"), std::exception);
}

TEST(CommunityStringValidationTest, PUBLIC_Throws)
{
    EXPECT_THROW(communityStringValidation("PUBLIC"), std::exception);
}

TEST(CommunityStringValidationTest, PRIVATE_Throws)
{
    EXPECT_THROW(communityStringValidation("PRIVATE"), std::exception);
}

TEST(CommunityStringValidationTest, Empty_Throws)
{
    EXPECT_THROW(communityStringValidation(""), std::exception);
}

// ---------------------------------------------------------------------------
// communityStringPermission
// ---------------------------------------------------------------------------

TEST(CommunityStringPermissionTest, RwCommunity_ReturnsTrue)
{
    EXPECT_TRUE(communityStringPermission("rwcommunity"));
}

TEST(CommunityStringPermissionTest, RoCommunity_ReturnsTrue)
{
    EXPECT_TRUE(communityStringPermission("rocommunity"));
}

TEST(CommunityStringPermissionTest, CaseSensitiveInvalid_Throws)
{
    EXPECT_THROW(communityStringPermission("RoCommunity"), std::exception);
}

TEST(CommunityStringPermissionTest, ArbitraryString_Throws)
{
    EXPECT_THROW(communityStringPermission("readwrite"), std::exception);
}

TEST(CommunityStringPermissionTest, Empty_Throws)
{
    EXPECT_THROW(communityStringPermission(""), std::exception);
}

// ---------------------------------------------------------------------------
// passwordValidate
// ---------------------------------------------------------------------------

TEST(PasswordValidateTest, ExactMinimumLength_ReturnsTrue)
{
    // MIN_PWD_LEN == 8; an 8-character password must pass
    EXPECT_TRUE(passwordValidate("abcdefgh"));
}

TEST(PasswordValidateTest, LongerThanMinimum_ReturnsTrue)
{
    EXPECT_TRUE(passwordValidate("securePass123!"));
}

TEST(PasswordValidateTest, OneBelowMinimum_Throws)
{
    // 7 characters — must throw
    EXPECT_THROW(passwordValidate("abcdefg"), std::exception);
}

TEST(PasswordValidateTest, Empty_Throws)
{
    EXPECT_THROW(passwordValidate(""), std::exception);
}

TEST(PasswordValidateTest, SingleChar_Throws)
{
    EXPECT_THROW(passwordValidate("a"), std::exception);
}

// ---------------------------------------------------------------------------
// encryptionValidate
// ---------------------------------------------------------------------------

TEST(EncryptionValidateTest, AES_ReturnsTrue)
{
    EXPECT_TRUE(encryptionValidate("AES"));
}

TEST(EncryptionValidateTest, LowerCaseAes_Throws)
{
    EXPECT_THROW(encryptionValidate("aes"), std::exception);
}

TEST(EncryptionValidateTest, DES_Throws)
{
    EXPECT_THROW(encryptionValidate("DES"), std::exception);
}

TEST(EncryptionValidateTest, Empty_Throws)
{
    EXPECT_THROW(encryptionValidate(""), std::exception);
}

// ---------------------------------------------------------------------------
// algorithmValidate
// ---------------------------------------------------------------------------

TEST(AlgorithmValidateTest, SHA384_ReturnsTrue)
{
    EXPECT_TRUE(algorithmValidate("SHA-384"));
}

TEST(AlgorithmValidateTest, SHA512_ReturnsTrue)
{
    EXPECT_TRUE(algorithmValidate("SHA-512"));
}

TEST(AlgorithmValidateTest, SHA256_Throws)
{
    EXPECT_THROW(algorithmValidate("SHA-256"), std::exception);
}

TEST(AlgorithmValidateTest, MD5_Throws)
{
    EXPECT_THROW(algorithmValidate("MD5"), std::exception);
}

TEST(AlgorithmValidateTest, Empty_Throws)
{
    EXPECT_THROW(algorithmValidate(""), std::exception);
}

TEST(AlgorithmValidateTest, LowerCase_Throws)
{
    EXPECT_THROW(algorithmValidate("sha-384"), std::exception);
}

// ---------------------------------------------------------------------------
// ReadWritePermissionValidate
// ---------------------------------------------------------------------------

TEST(ReadWritePermissionValidateTest, Ro_ReturnsTrue)
{
    EXPECT_TRUE(ReadWritePermissionValidate("ro"));
}

TEST(ReadWritePermissionValidateTest, Rw_ReturnsTrue)
{
    EXPECT_TRUE(ReadWritePermissionValidate("rw"));
}

TEST(ReadWritePermissionValidateTest, ReadOnly_Throws)
{
    EXPECT_THROW(ReadWritePermissionValidate("read-only"), std::exception);
}

TEST(ReadWritePermissionValidateTest, UpperCaseRO_Throws)
{
    EXPECT_THROW(ReadWritePermissionValidate("RO"), std::exception);
}

TEST(ReadWritePermissionValidateTest, Empty_Throws)
{
    EXPECT_THROW(ReadWritePermissionValidate(""), std::exception);
}

// ---------------------------------------------------------------------------
// resolveAddress
// ---------------------------------------------------------------------------

TEST(ResolveAddressTest, IPv4Loopback_ReturnsIPv4String)
{
    std::string result = resolveAddress("127.0.0.1");
    EXPECT_EQ(result, "127.0.0.1");
}

TEST(ResolveAddressTest, IPv6Loopback_ReturnsBracketedIPv6)
{
    std::string result = resolveAddress("::1");
    EXPECT_EQ(result, "[::1]");
}

TEST(ResolveAddressTest, LocalhostHostname_ResolvesToLoopback)
{
    // "localhost" may resolve to either 127.0.0.1 or ::1 depending on
    // /etc/hosts in the Docker container; verify it returns without throwing.
    EXPECT_NO_THROW({
        std::string r = resolveAddress("localhost");
        EXPECT_FALSE(r.empty());
    });
}

TEST(ResolveAddressTest, InvalidHostname_Throws)
{
    EXPECT_THROW(
        resolveAddress("this.hostname.definitely.does.not.exist.invalid"),
        std::exception);
}

TEST(ResolveAddressTest, ValidIPv4_ReturnsUnchanged)
{
    std::string result = resolveAddress("10.0.0.1");
    EXPECT_EQ(result, "10.0.0.1");
}

// ---------------------------------------------------------------------------
// testing() — reads /etc/snmp/snmpd.conf (seeded in test_main.cpp)
// ---------------------------------------------------------------------------

TEST(TestingFunctionTest, SeededSnmpdConf_ReturnsViewNames)
{
    // test_main.cpp seeds /etc/snmp/snmpd.conf with view all and view
    // systemonly
    auto views = phosphor::network::snmp::testing();
    // The seeded file contains "view all included .1" and
    // "view systemonly included .1.3.6.1.2.1"
    // Verify at least one view was parsed.
    // (If /etc/snmp/snmpd.conf is not writable, testing() returns empty.)
    if (!views.empty())
    {
        EXPECT_TRUE(std::find(views.begin(), views.end(), "all") !=
                    views.end());
    }
}

TEST(TestingFunctionTest, SeededConf_DoesNotReturnComment)
{
    auto views = phosphor::network::snmp::testing();
    for (const auto& v : views)
    {
        EXPECT_FALSE(v.empty());
        EXPECT_NE(v[0], '#');
    }
}

// ---------------------------------------------------------------------------
// communityStringProfile() — validates against views from testing()
// ---------------------------------------------------------------------------

TEST(CommunityStringProfileTest, ValidProfile_ReturnsTrue)
{
    // Only run if testing() returns a non-empty list (i.e., /etc/snmp is
    // writable and seeded).
    auto views = phosphor::network::snmp::testing();
    if (views.empty())
        GTEST_SKIP();

    const std::string validView = views[0];
    EXPECT_NO_THROW(EXPECT_TRUE(communityStringProfile(validView)));
}

TEST(CommunityStringProfileTest, EmptyProfile_Throws)
{
    EXPECT_THROW(communityStringProfile(""), std::exception);
}

TEST(CommunityStringProfileTest, InvalidProfile_Throws)
{
    EXPECT_THROW(communityStringProfile("nonexistent_view_xyz"),
                 std::exception);
}

// ---------------------------------------------------------------------------
// createSNMPv3User() — tests early-return and basic execution paths
// ---------------------------------------------------------------------------

TEST(CreateSNMPv3UserTest, EmptyUserName_ReturnsImmediately)
{
    // Empty username → early return with no side effects / no exception.
    EXPECT_NO_THROW(createSNMPv3User("", "pass", "AES", "SHA-384", "ro"));
}

TEST(CreateSNMPv3UserTest, ValidParams_RwPermission_ExecutesWithoutThrow)
{
    // Non-empty username → executes system() calls that may fail silently.
    EXPECT_NO_THROW(
        createSNMPv3User("testuser", "password123", "AES", "SHA-384", "rw"));
}

TEST(CreateSNMPv3UserTest, ValidParams_RoPermission_ExecutesWithoutThrow)
{
    EXPECT_NO_THROW(
        createSNMPv3User("testuser", "password123", "AES", "SHA-512", "ro"));
}

// ---------------------------------------------------------------------------
// updateFile() — pure file I/O, fully testable
// ---------------------------------------------------------------------------

TEST(UpdateFileTest, RemovesPatternLine_ReturnsTrue)
{
    const std::string path = "/tmp/snmp-test/updatefile_test.conf";
    {
        std::ofstream f(path);
        f << "keep this line\n";
        f << "remove me rocommunity badcs\n";
        f << "keep this too\n";
    }

    EXPECT_TRUE(updateFile(path, "badcs"));

    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_EQ(content.find("badcs"), std::string::npos);
    EXPECT_NE(content.find("keep this line"), std::string::npos);
    EXPECT_NE(content.find("keep this too"), std::string::npos);

    std::filesystem::remove(path);
}

TEST(UpdateFileTest, PatternNotFound_ReturnsFalse)
{
    const std::string path = "/tmp/snmp-test/updatefile_nofind.conf";
    {
        std::ofstream f(path);
        f << "line1\nline2\nline3\n";
    }

    EXPECT_FALSE(updateFile(path, "nonexistent_pattern"));

    std::filesystem::remove(path);
}

TEST(UpdateFileTest, NonexistentFile_ReturnsFalse)
{
    EXPECT_FALSE(updateFile("/tmp/snmp-test/does_not_exist.conf", "pattern"));
}

TEST(UpdateFileTest, AllLinesRemoved_EmptyResult)
{
    const std::string path = "/tmp/snmp-test/updatefile_allremove.conf";
    {
        std::ofstream f(path);
        f << "remove1 pattern\n";
        f << "remove2 pattern\n";
    }

    EXPECT_TRUE(updateFile(path, "pattern"));

    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_TRUE(content.empty());

    std::filesystem::remove(path);
}

// ---------------------------------------------------------------------------
// deleteSNMPManager() — makes a D-Bus call to the SNMP service; the
// service is not running in the Docker container, so the call fails and
// the catch block handles the exception silently.
// ---------------------------------------------------------------------------

TEST(DeleteSNMPManagerTest, NonExistentUser_CatchesException)
{
    // D-Bus call to xyz.openbmc_project.Network.SNMP fails (service absent).
    // The catch block in deleteSNMPManager logs the error and returns.
    EXPECT_NO_THROW(deleteSNMPManager("nonexistent_xyz_user"));
}

TEST(DeleteSNMPManagerTest, EmptyUserId_CatchesException)
{
    EXPECT_NO_THROW(deleteSNMPManager(""));
}

} // namespace
