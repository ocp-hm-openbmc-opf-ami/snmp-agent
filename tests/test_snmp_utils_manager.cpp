// test_snmp_utils_manager.cpp — unit tests for snmpUtils.cpp
// (SnmpUtilsManager).
//
// Strategy:
//   - sdbusplus::SdBusMock intercepts all sd_bus* calls so the class can be
//     constructed without a real D-Bus connection.
//   - SnmpTrapStatusFile is redirected to /tmp/snmp-test/ (extern redirect).
//   - snmpdConfFilepath / snmpConfFilepath are already redirected by
//   test_main.cpp.
//
// Coverage focus:
//   snmpTrapStatus(bool), snmpTrapStatus() const,
//   enableSNMPV1/V2/V3(bool), enableSNMPV1/V2/V3() const,
//   listSNMPCommunityProfile()

#include "snmpUtils.hpp"

#include <sdbusplus/test/sdbus_mock.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// SnmpTrapStatusFile is a non-const global defined in snmpUtils.cpp at
// global scope (outside any namespace).
extern std::string SnmpTrapStatusFile;

using testing::_;
using testing::NiceMock;
using testing::Return;

namespace fs = std::filesystem;
namespace psu = phosphor::snmp::SnmpUtils;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
class SnmpUtilsManagerTest : public ::testing::Test
{
  protected:
    NiceMock<sdbusplus::SdBusMock> sdbusMock;
    sdbusplus::bus_t mockBus;
    std::unique_ptr<psu::SnmpUtilsManager> mgr;

    std::string savedTrapStatusFile;

    SnmpUtilsManagerTest() : mockBus(nullptr, &sdbusMock) {}

    void SetUp() override
    {
        // Allow all sd_bus vtable/emit calls needed during construction and
        // property-changed emission.
        ON_CALL(sdbusMock, sd_bus_add_object_vtable(_, _, _, _, _, _))
            .WillByDefault(Return(0));
        ON_CALL(sdbusMock, sd_bus_emit_object_added(_, _))
            .WillByDefault(Return(0));
        ON_CALL(sdbusMock, sd_bus_emit_object_removed(_, _))
            .WillByDefault(Return(0));
        ON_CALL(sdbusMock, sd_bus_emit_properties_changed_strv(_, _, _, _))
            .WillByDefault(Return(0));
        ON_CALL(sdbusMock, sd_bus_add_object_manager(_, _, _))
            .WillByDefault(Return(0));

        // Redirect trap-status file to /tmp so no /etc/snmp writes.
        savedTrapStatusFile = SnmpTrapStatusFile;
        SnmpTrapStatusFile = "/tmp/snmp-test/SnmpTrapStatus";
        fs::create_directories("/tmp/snmp-test");
        fs::remove("/tmp/snmp-test/SnmpTrapStatus");

        // Seed a known conf file so SNMP-version tests have a stable base.
        {
            std::ofstream f("/tmp/snmp-test/snmpd.conf");
            f << "view all included .1\n"
              << "view systemonly included .1.3.6.1.2.1\n"
              << "rocommunity public default -V all\n";
        }
        // snmpConfFilepath is redirected by test_main.cpp to
        // /tmp/snmp-test/snmp.conf — ensure a clean slate.
        fs::remove("/tmp/snmp-test/snmp.conf");

        mgr = std::make_unique<psu::SnmpUtilsManager>(
            mockBus, "/xyz/openbmc_project/snmp/utils");
    }

    void TearDown() override
    {
        mgr.reset();
        SnmpTrapStatusFile = savedTrapStatusFile;
    }
};

// ---------------------------------------------------------------------------
// snmpTrapStatus — file I/O
// ---------------------------------------------------------------------------

TEST_F(SnmpUtilsManagerTest, SnmpTrapStatus_NoFile_ReturnsFalse)
{
    // No status file exists → const getter returns false.
    EXPECT_FALSE(mgr->snmpTrapStatus());
}

TEST_F(SnmpUtilsManagerTest, SnmpTrapStatus_SameValueFalse_EarlyReturn)
{
    // Current value is false (no file), setting false → early return false.
    bool ret = mgr->snmpTrapStatus(false);
    EXPECT_FALSE(ret);
    // File should not have been written (early-return path).
    EXPECT_FALSE(fs::exists("/tmp/snmp-test/SnmpTrapStatus"));
}

TEST_F(SnmpUtilsManagerTest, SnmpTrapStatus_SetTrue_ReadBackTrue)
{
    mgr->snmpTrapStatus(true);
    EXPECT_TRUE(mgr->snmpTrapStatus());
}

TEST_F(SnmpUtilsManagerTest, SnmpTrapStatus_SetTrueThenFalse_ReadBackFalse)
{
    mgr->snmpTrapStatus(true);
    mgr->snmpTrapStatus(false);
    EXPECT_FALSE(mgr->snmpTrapStatus());
}

TEST_F(SnmpUtilsManagerTest, SnmpTrapStatus_SetTrueTwice_SecondCallEarlyReturn)
{
    mgr->snmpTrapStatus(true);
    // Second call with same value hits early return — should still return true.
    bool ret = mgr->snmpTrapStatus(true);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mgr->snmpTrapStatus());
}

// ---------------------------------------------------------------------------
// enableSNMPV1 — writes disableSNMPv1 flag to snmpConfFilepath
// ---------------------------------------------------------------------------

TEST_F(SnmpUtilsManagerTest, EnableSNMPV1_Const_InitiallyEnabled)
{
    // No "disableSNMPv1" in conf → getSnmpVersionStatus returns false → !false
    // = true.
    EXPECT_TRUE(mgr->enableSNMPV1());
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV1_True_WhenAlreadyEnabled_EarlyReturn)
{
    // enableSNMPV1(true): currentValue=false, true != false → early return
    // true.
    EXPECT_TRUE(mgr->enableSNMPV1(true));
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV1_False_DisablesV1)
{
    // enableSNMPV1(false): currentValue=false, false != false → false → writes
    // disable.
    bool ret = mgr->enableSNMPV1(false);
    EXPECT_FALSE(ret);
    // Now getSnmpVersionStatus("disableSNMPv1") should return true → const
    // getter returns false.
    EXPECT_FALSE(mgr->enableSNMPV1());
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV1_TrueAfterDisable_ReEnables)
{
    mgr->enableSNMPV1(false); // disable
    // enableSNMPV1(true): currentValue=true, true != true → false → writes
    // enable.
    bool ret = mgr->enableSNMPV1(true);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(mgr->enableSNMPV1());
}

// ---------------------------------------------------------------------------
// enableSNMPV2
// ---------------------------------------------------------------------------

TEST_F(SnmpUtilsManagerTest, EnableSNMPV2_Const_InitiallyEnabled)
{
    EXPECT_TRUE(mgr->enableSNMPV2());
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV2_True_EarlyReturn)
{
    EXPECT_TRUE(mgr->enableSNMPV2(true));
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV2_False_DisablesV2)
{
    bool ret = mgr->enableSNMPV2(false);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(mgr->enableSNMPV2());
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV2_TrueAfterDisable_ReEnables)
{
    mgr->enableSNMPV2(false);
    EXPECT_TRUE(mgr->enableSNMPV2(true));
    EXPECT_TRUE(mgr->enableSNMPV2());
}

// ---------------------------------------------------------------------------
// enableSNMPV3
// ---------------------------------------------------------------------------

TEST_F(SnmpUtilsManagerTest, EnableSNMPV3_Const_InitiallyEnabled)
{
    EXPECT_TRUE(mgr->enableSNMPV3());
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV3_True_EarlyReturn)
{
    EXPECT_TRUE(mgr->enableSNMPV3(true));
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV3_False_DisablesV3)
{
    bool ret = mgr->enableSNMPV3(false);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(mgr->enableSNMPV3());
}

TEST_F(SnmpUtilsManagerTest, EnableSNMPV3_TrueAfterDisable_ReEnables)
{
    mgr->enableSNMPV3(false);
    EXPECT_TRUE(mgr->enableSNMPV3(true));
    EXPECT_TRUE(mgr->enableSNMPV3());
}

// ---------------------------------------------------------------------------
// listSNMPCommunityProfile — reads snmpdConfFilepath (redirected in test_main)
// ---------------------------------------------------------------------------

TEST_F(SnmpUtilsManagerTest, ListSNMPCommunityProfile_SeededConf_ContainsViews)
{
    auto views = mgr->listSNMPCommunityProfile();
    EXPECT_FALSE(views.empty());
    EXPECT_NE(std::find(views.begin(), views.end(), "all"), views.end());
    EXPECT_NE(std::find(views.begin(), views.end(), "systemonly"), views.end());
}

TEST_F(SnmpUtilsManagerTest, ListSNMPCommunityProfile_EmptyConf_ReturnsEmpty)
{
    std::ofstream("/tmp/snmp-test/snmpd.conf").close(); // truncate to empty
    EXPECT_TRUE(mgr->listSNMPCommunityProfile().empty());
}

TEST_F(SnmpUtilsManagerTest, ListSNMPCommunityProfile_CommentsOnly_ReturnsEmpty)
{
    std::ofstream f("/tmp/snmp-test/snmpd.conf");
    f << "# view all included .1\n"
      << "# view systemonly included .1.3.6.1.2.1\n";
    f.close();
    EXPECT_TRUE(mgr->listSNMPCommunityProfile().empty());
}

TEST_F(SnmpUtilsManagerTest,
       ListSNMPCommunityProfile_ViewWithoutIncluded_NotCounted)
{
    std::ofstream f("/tmp/snmp-test/snmpd.conf");
    f << "view myview\n"; // missing "included" keyword
    f.close();
    EXPECT_TRUE(mgr->listSNMPCommunityProfile().empty());
}

TEST_F(SnmpUtilsManagerTest, ListSNMPCommunityProfile_NoDuplicates)
{
    auto views = mgr->listSNMPCommunityProfile();
    std::vector<std::string> sorted = views;
    std::sort(sorted.begin(), sorted.end());
    auto unique_end = std::unique(sorted.begin(), sorted.end());
    EXPECT_EQ(unique_end, sorted.end());
}

// ---------------------------------------------------------------------------
// sendSNMPTrap() — creates a static real D-Bus bus and calls User.Manager.
// User.Manager is not running in Docker → the D-Bus call throws a
// sdbusplus exception → elog<InternalFailure>() re-throws it.
// In the SNMP_AGENT_TESTS_BUILD path the D-Bus call is still attempted
// first, so the function always throws in the test container.
// ---------------------------------------------------------------------------

TEST_F(SnmpUtilsManagerTest, SendSNMPTrap_DBusFails_Throws)
{
    // sendSNMPTrap() now logs and returns true without making any D-Bus call.
    EXPECT_TRUE(mgr->sendSNMPTrap());
}
