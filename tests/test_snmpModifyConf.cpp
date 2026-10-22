// test_snmpModifyConf.cpp — unit tests for snmpModifyConf.cpp
//
// All functions that read/write config files use hardcoded paths under
// /etc/snmp/ (const std::string globals that cannot be overridden at
// link time).  Inside the Docker test container the process runs as root,
// so the fixture creates real files at those paths for each test and
// removes them in TearDown.
//
// controlSystemdService() is called at the end of several functions.
// It catches its own sdbusplus exception and logs to stderr; the test
// continues normally even when no systemd D-Bus endpoint is registered.

#include "snmpModifyConf.hpp"

#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

// Forward-declare helpers that live at global scope in snmpModifyConf.cpp
// but are not exposed through the header.
bool isValidAccessType(const std::string& accessType);
bool isStringVectorString(const std::vector<std::string>& vectorStr,
                          const std::string& str);
std::vector<std::string> listViewAccess();

namespace
{

namespace fs = std::filesystem;

// Paths match the redirected globals set in test_main.cpp.
constexpr const char* kExtConfFile = "/tmp/snmp-test/snmpd.conf.d/snmpd.conf";
constexpr const char* kMainConfFile = "/tmp/snmp-test/snmpd.conf";
constexpr const char* kSnmpConfFile = "/tmp/snmp-test/snmp.conf";
constexpr const char* kTmpConfFile = "/etc/snmp/snmpd.conf.d/snmpd_tmp.conf";
constexpr const char* kConfDir = "/tmp/snmp-test/snmpd.conf.d";

// ---------------------------------------------------------------------------
// Fixture — creates minimal /tmp/snmp-test structure for every test.
// ---------------------------------------------------------------------------
class SnmpModifyConfTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        std::error_code ec;
        fs::create_directories(kConfDir, ec);
        writeFile(kExtConfFile, "");
        writeFile(kMainConfFile, "");
        writeFile(kSnmpConfFile, "");
    }

    void TearDown() override
    {
        std::error_code ec;
        fs::remove(kExtConfFile, ec);
        fs::remove(kMainConfFile, ec);
        fs::remove(kSnmpConfFile, ec);
        fs::remove(kTmpConfFile, ec);
    }

    static void writeFile(const char* path, const std::string& content)
    {
        std::ofstream f(path);
        f << content;
    }

    static std::string readFile(const char* path)
    {
        std::ifstream f(path);
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }
};

// ---------------------------------------------------------------------------
// isValidAccessType
// ---------------------------------------------------------------------------

TEST(IsValidAccessTypeTest, RoCommunity_ReturnsTrue)
{
    EXPECT_TRUE(isValidAccessType("rocommunity"));
}

TEST(IsValidAccessTypeTest, RwCommunity_ReturnsTrue)
{
    EXPECT_TRUE(isValidAccessType("rwcommunity"));
}

TEST(IsValidAccessTypeTest, Invalid_ReturnsFalse)
{
    EXPECT_FALSE(isValidAccessType("community"));
}

TEST(IsValidAccessTypeTest, UpperCase_ReturnsFalse)
{
    EXPECT_FALSE(isValidAccessType("RoCommunity"));
}

TEST(IsValidAccessTypeTest, Empty_ReturnsFalse)
{
    EXPECT_FALSE(isValidAccessType(""));
}

// ---------------------------------------------------------------------------
// isStringVectorString
// ---------------------------------------------------------------------------

TEST(IsStringVectorStringTest, PresentElement_ReturnsTrue)
{
    const std::vector<std::string> v{"alpha", "beta", "gamma"};
    EXPECT_TRUE(isStringVectorString(v, "beta"));
}

TEST(IsStringVectorStringTest, AbsentElement_ReturnsFalse)
{
    const std::vector<std::string> v{"alpha", "beta"};
    EXPECT_FALSE(isStringVectorString(v, "delta"));
}

TEST(IsStringVectorStringTest, EmptyVector_ReturnsFalse)
{
    EXPECT_FALSE(isStringVectorString({}, "anything"));
}

TEST(IsStringVectorStringTest, ExactMatch_CaseSensitive_ReturnsTrue)
{
    const std::vector<std::string> v{"Alpha"};
    EXPECT_FALSE(isStringVectorString(v, "alpha"));
    EXPECT_TRUE(isStringVectorString(v, "Alpha"));
}

// ---------------------------------------------------------------------------
// listCommunityString
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest, ListCommunityString_EmptyFile_ReturnsEmpty)
{
    auto result = listCommunityString();
    EXPECT_TRUE(result.empty());
}

TEST_F(SnmpModifyConfTest, ListCommunityString_OneRoCommunity_ReturnsList)
{
    writeFile(kExtConfFile, "rocommunity testcs default -V testview\n");
    auto result = listCommunityString();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "testcs");
}

TEST_F(SnmpModifyConfTest, ListCommunityString_MultipleEntries_ReturnsAll)
{
    writeFile(kExtConfFile, "rocommunity cs1 default -V view1\n"
                            "rwcommunity cs2 default -V view2\n");
    auto result = listCommunityString();
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "cs1");
    EXPECT_EQ(result[1], "cs2");
}

TEST_F(SnmpModifyConfTest, ListCommunityString_CommentLines_Ignored)
{
    writeFile(kExtConfFile, "# comment line\n"
                            "rocommunity valid default -V view1\n");
    auto result = listCommunityString();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "valid");
}

// ---------------------------------------------------------------------------
// listViewAccess
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest, ListViewAccess_EmptyFile_ReturnsEmpty)
{
    auto result = listViewAccess();
    EXPECT_TRUE(result.empty());
}

TEST_F(SnmpModifyConfTest, ListViewAccess_SingleView_ReturnsViewName)
{
    writeFile(kMainConfFile, "view testview included .1\n");
    auto result = listViewAccess();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "testview");
}

TEST_F(SnmpModifyConfTest, ListViewAccess_MultipleViews_ReturnsAll)
{
    writeFile(kMainConfFile, "view view1 included .1\n"
                             "view view2 included .1.3.6\n");
    auto result = listViewAccess();
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "view1");
    EXPECT_EQ(result[1], "view2");
}

TEST_F(SnmpModifyConfTest, ListViewAccess_CommentLines_Ignored)
{
    writeFile(kMainConfFile, "# this is a comment\n"
                             "view goodview included .1\n");
    auto result = listViewAccess();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "goodview");
}

TEST_F(SnmpModifyConfTest, ListViewAccess_NonViewLines_Ignored)
{
    writeFile(kMainConfFile, "rocommunity public\n"
                             "view myview included .1\n"
                             "agentAddress udp:161\n");
    auto result = listViewAccess();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "myview");
}

// ---------------------------------------------------------------------------
// getSnmpVersionStatus
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest, GetSnmpVersionStatus_Present1_ReturnsTrue)
{
    writeFile(kSnmpConfFile, "disableSNMPv1 1\n");
    EXPECT_TRUE(getSnmpVersionStatus("disableSNMPv1"));
}

TEST_F(SnmpModifyConfTest, GetSnmpVersionStatus_Present0_ReturnsFalse)
{
    writeFile(kSnmpConfFile, "disableSNMPv1 0\n");
    EXPECT_FALSE(getSnmpVersionStatus("disableSNMPv1"));
}

TEST_F(SnmpModifyConfTest, GetSnmpVersionStatus_PresentTrue_ReturnsTrue)
{
    writeFile(kSnmpConfFile, "disableSNMPv2c true\n");
    EXPECT_TRUE(getSnmpVersionStatus("disableSNMPv2c"));
}

TEST_F(SnmpModifyConfTest, GetSnmpVersionStatus_VersionMissing_ReturnsFalse)
{
    writeFile(kSnmpConfFile, "otherKey 1\n");
    EXPECT_FALSE(getSnmpVersionStatus("disableSNMPv1"));
}

TEST_F(SnmpModifyConfTest, GetSnmpVersionStatus_EmptyFile_ReturnsFalse)
{
    EXPECT_FALSE(getSnmpVersionStatus("disableSNMPv1"));
}

// ---------------------------------------------------------------------------
// SetSnmpVersionStatus
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest, SetSnmpVersionStatus_NewEntry_WritesTo1)
{
    // File is empty; SetSnmpVersionStatus should append a new line.
    // controlSystemdService fails silently (no systemd in Docker).
    SetSnmpVersionStatus("disableSNMPv1", true);
    EXPECT_TRUE(getSnmpVersionStatus("disableSNMPv1"));
}

TEST_F(SnmpModifyConfTest, SetSnmpVersionStatus_ExistingEntry_Updates)
{
    writeFile(kSnmpConfFile, "disableSNMPv1 0\n");
    SetSnmpVersionStatus("disableSNMPv1", true);
    EXPECT_TRUE(getSnmpVersionStatus("disableSNMPv1"));
}

TEST_F(SnmpModifyConfTest, SetSnmpVersionStatus_SetFalse_WritesTo0)
{
    writeFile(kSnmpConfFile, "disableSNMPv1 1\n");
    SetSnmpVersionStatus("disableSNMPv1", false);
    EXPECT_FALSE(getSnmpVersionStatus("disableSNMPv1"));
}

// ---------------------------------------------------------------------------
// addCommunityString
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest, AddCommunityString_InvalidAccessType_ReturnsFalse)
{
    EXPECT_FALSE(addCommunityString("invalid_type", "mycs", "testview"));
}

TEST_F(SnmpModifyConfTest, AddCommunityString_PublicCommunity_ReturnsFalse)
{
    writeFile(kMainConfFile, "view testview included .1\n");
    EXPECT_FALSE(addCommunityString("rocommunity", "public", "testview"));
}

TEST_F(SnmpModifyConfTest, AddCommunityString_ViewNotInConfig_ReturnsFalse)
{
    // kMainConfFile is empty → listViewAccess returns {} → view not found
    EXPECT_FALSE(addCommunityString("rocommunity", "mycs", "nonexistentview"));
}

TEST_F(SnmpModifyConfTest, AddCommunityString_ValidParams_ReturnsTrue)
{
    writeFile(kMainConfFile, "view testview included .1\n");

    bool result = addCommunityString("rocommunity", "mycs", "testview");
    EXPECT_TRUE(result);

    // Verify the entry was written to the extended config file
    std::string content = readFile(kExtConfFile);
    EXPECT_NE(content.find("rocommunity"), std::string::npos);
    EXPECT_NE(content.find("mycs"), std::string::npos);
    EXPECT_NE(content.find("testview"), std::string::npos);
}

TEST_F(SnmpModifyConfTest, AddCommunityString_DuplicateCommunity_ReturnsFalse)
{
    writeFile(kMainConfFile, "view testview included .1\n");
    writeFile(kExtConfFile, "rocommunity mycs default -V testview\n");

    // "mycs" already exists → must return false
    EXPECT_FALSE(addCommunityString("rocommunity", "mycs", "testview"));
}

// ---------------------------------------------------------------------------
// removeCommunityString
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest, RemoveCommunityString_ExistingEntry_ReturnsTrue)
{
    writeFile(kExtConfFile, "rocommunity testcs default -V testview\n");

    EXPECT_TRUE(removeCommunityString("testcs"));

    std::string content = readFile(kExtConfFile);
    EXPECT_EQ(content.find("testcs"), std::string::npos);
}

TEST_F(SnmpModifyConfTest, RemoveCommunityString_NonExistent_ReturnsFalse)
{
    // File is empty; community string won't be found.
    EXPECT_FALSE(removeCommunityString("nonexistent"));
}

TEST_F(SnmpModifyConfTest, RemoveCommunityString_PreservesOtherEntries)
{
    writeFile(kExtConfFile, "rocommunity cs1 default -V view1\n"
                            "rwcommunity cs2 default -V view2\n");

    EXPECT_TRUE(removeCommunityString("cs1"));

    std::string content = readFile(kExtConfFile);
    EXPECT_EQ(content.find("cs1"), std::string::npos);
    EXPECT_NE(content.find("cs2"), std::string::npos);
}

// ---------------------------------------------------------------------------
// communityStringPropertyModify
// ---------------------------------------------------------------------------

TEST_F(SnmpModifyConfTest,
       CommunityStringPropertyModify_ReadWritePermission_TogglesAccessType)
{
    writeFile(kExtConfFile, "rocommunity mycs default -V testview\n");

    bool result =
        communityStringPropertyModify("mycs", "ReadWritePermission", "rw");
    EXPECT_TRUE(result);

    std::string content = readFile(kExtConfFile);
    EXPECT_NE(content.find("rwcommunity"), std::string::npos);
}

TEST_F(SnmpModifyConfTest,
       CommunityStringPropertyModify_CommunityProfile_UpdatesProfile)
{
    writeFile(kExtConfFile, "rocommunity mycs default -V oldview\n");

    bool result =
        communityStringPropertyModify("mycs", "CommunityProfile", "newview");
    EXPECT_TRUE(result);

    std::string content = readFile(kExtConfFile);
    EXPECT_NE(content.find("newview"), std::string::npos);
}

TEST_F(SnmpModifyConfTest,
       CommunityStringPropertyModify_NonExistentCommunity_ReturnsFalse)
{
    // kExtConfFile is empty; community string not found
    EXPECT_FALSE(
        communityStringPropertyModify("ghost", "ReadWritePermission", "rw"));
}

} // namespace
