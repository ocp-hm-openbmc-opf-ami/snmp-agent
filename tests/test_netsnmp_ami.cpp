// test_netsnmp_ami.cpp — unit tests for netSnmpAmi.cpp
//
// Coverage targets:
//   • setDbusProperty / getDbusProperty (5-param void): D-Bus fails silently
//   • handle_amiACD_DataArea: all switch modes
//     - MODE_GET: D-Bus dbus_call throws → caught → dataArea=0 → safe
//     - SET_RESERVE1: netsnmp_check_vb_type with matching ASN type → no error
//     - SET_RESERVE2, SET_FREE, SET_COMMIT, SET_UNDO: empty → SNMP_ERR_NOERROR
//     - default (unknown mode): snmp_log → SNMP_ERR_GENERR
//   • handle_amiACD_Trigger: same modes
//     - MODE_GET: reads acd_Trigger global (empty string) → safe
//   • handle_amiSnmpSMTPPriStatus / handle_amiSnmpSMTPSecStatus:
//     - Safe modes (RESERVE2, FREE, COMMIT, UNDO): empty → SNMP_ERR_NOERROR
//     - RESERVE1 with matching type → SNMP_ERR_NOERROR
//     - default: snmp_log → SNMP_ERR_GENERR
//     - MODE_GET: getDbusProperty leaves variant default-constructed →
//       std::get<bool> throws std::bad_variant_access → EXPECT_ANY_THROW
//       (gcov marks those lines as executed)
//
// SNMP struct setup:
//   HandlerCtx zero-initialises handler/reginfo/reqinfo/vb/req so that
//   switch modes that don't dereference requestvb are always safe.
//   For MODE_GET on ACD handlers, req.requestvb = &vb is sufficient for
//   snmp_set_var_typed_value (allocates vb.val.string via malloc; leaked
//   in tests — acceptable).
//
// Include order: production headers first (net-snmp defines FAIL/ERROR/DEBUG
// macros), undef them, then gtest.

// clang-format off
#include "netSnmpAmi.hpp"
// clang-format on

#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

#include <cstring>
#include <string>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

// DbusUserPropVariant is defined at file scope in netSnmpAmi.cpp.
// Redeclare it here with the same layout so we can call the 5-param overloads.
using DbusUserPropVariant =
    std::variant<std::vector<std::string>, std::string, bool>;

void setDbusProperty(const std::string& service, const std::string& objPath,
                     const std::string& interface, const std::string& property,
                     DbusUserPropVariant& value);

void getDbusProperty(const std::string& service, const std::string& objPath,
                     const std::string& interface, const std::string& property,
                     DbusUserPropVariant& value);

namespace
{

// ---------------------------------------------------------------------------
// HandlerCtx — zero-initialised SNMP handler structs
// ---------------------------------------------------------------------------
struct HandlerCtx
{
    netsnmp_mib_handler handler;
    netsnmp_handler_registration reginfo;
    netsnmp_agent_request_info reqinfo;
    netsnmp_variable_list vb;
    netsnmp_request_info req;

    explicit HandlerCtx(int mode)
    {
        std::memset(&handler, 0, sizeof(handler));
        std::memset(&reginfo, 0, sizeof(reginfo));
        std::memset(&reqinfo, 0, sizeof(reqinfo));
        std::memset(&vb, 0, sizeof(vb));
        std::memset(&req, 0, sizeof(req));
        reqinfo.mode = mode;
        req.requestvb = &vb;
        req.next = nullptr;
        req.processed = 0;
    }
};

// ---------------------------------------------------------------------------
// setDbusProperty / getDbusProperty (5-param void)
// ---------------------------------------------------------------------------

TEST(DbusPropertyAmiTest,
     GetDbusProperty5Param_DBusFails_LeavesVariantUnchanged)
{
    // D-Bus call fails (service not running) → catch silently → variant
    // stays default-constructed (first alternative = vector<string>{}).
    DbusUserPropVariant v;
    EXPECT_NO_THROW(getDbusProperty(
        "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
        "xyz.openbmc_project.mail.alert.primary", "Enable", v));
    EXPECT_TRUE(std::holds_alternative<std::vector<std::string>>(v));
}

TEST(DbusPropertyAmiTest, SetDbusProperty_DBusFails_NoThrow)
{
    // D-Bus call fails → catch silently → no throw.
    DbusUserPropVariant v = true;
    EXPECT_NO_THROW(setDbusProperty(
        "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
        "xyz.openbmc_project.mail.alert.primary", "Enable", v));
}

TEST(DbusPropertyAmiTest, GetDbusProperty5Param_StringVariant_StaysDefault)
{
    // Test second call path (string variant) — D-Bus still fails silently.
    DbusUserPropVariant v = std::string{"initial"};
    EXPECT_NO_THROW(
        getDbusProperty("com.ami.ami_acd", "/com/ami/ami_acd",
                        "com.ami.ami_acd.acdInterface", "SomeProperty", v));
}

// ---------------------------------------------------------------------------
// handle_amiACD_DataArea
// ---------------------------------------------------------------------------

TEST(HandleAmiACDDataAreaTest, ModeFree_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_FREE);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                       &c.reqinfo, &c.req));
}

TEST(HandleAmiACDDataAreaTest, ModeCommit_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_COMMIT);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                       &c.reqinfo, &c.req));
}

TEST(HandleAmiACDDataAreaTest, ModeUndo_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_UNDO);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                       &c.reqinfo, &c.req));
}

TEST(HandleAmiACDDataAreaTest, ModeReserve2_ReturnsNoError)
{
    // if (0) branch never taken → break → SNMP_ERR_NOERROR.
    HandlerCtx c(MODE_SET_RESERVE2);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                       &c.reqinfo, &c.req));
}

TEST(HandleAmiACDDataAreaTest, UnknownMode_ReturnsErrGenerr)
{
    // default: snmp_log → return SNMP_ERR_GENERR.
    HandlerCtx c(9999);
    EXPECT_EQ(SNMP_ERR_GENERR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

TEST(HandleAmiACDDataAreaTest, ModeGet_DBusCaught_ReturnsNoError)
{
    // dbus_call throws std::exception → caught → dataArea=0
    // → snmp_set_var_typed_value writes ASN_OCTET_STR to vb.
    HandlerCtx c(MODE_GET);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                       &c.reqinfo, &c.req));
}

TEST(HandleAmiACDDataAreaTest, ModeReserve1_MatchingType_ReturnsNoError)
{
    // vb.type = ASN_OCTET_STR → netsnmp_check_vb_type returns 0
    // → set_request_error NOT called → break → SNMP_ERR_NOERROR.
    HandlerCtx c(MODE_SET_RESERVE1);
    c.vb.type = ASN_OCTET_STR;
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_DataArea(&c.handler, &c.reginfo,
                                                       &c.reqinfo, &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiACD_Trigger
// ---------------------------------------------------------------------------

TEST(HandleAmiACDTriggerTest, ModeFree_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_FREE);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

TEST(HandleAmiACDTriggerTest, ModeCommit_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_COMMIT);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

TEST(HandleAmiACDTriggerTest, ModeUndo_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_UNDO);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

TEST(HandleAmiACDTriggerTest, ModeReserve2_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE2);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

TEST(HandleAmiACDTriggerTest, UnknownMode_ReturnsErrGenerr)
{
    HandlerCtx c(9999);
    EXPECT_EQ(SNMP_ERR_GENERR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                     &c.reqinfo, &c.req));
}

TEST(HandleAmiACDTriggerTest, ModeGet_ReadsEmptyGlobalString_ReturnsNoError)
{
    // acd_Trigger is a std::string global (initial value "").
    // snmp_set_var_typed_value called with c_str() + size()=0 → safe.
    HandlerCtx c(MODE_GET);
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

TEST(HandleAmiACDTriggerTest, ModeReserve1_MatchingType_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE1);
    c.vb.type = ASN_OCTET_STR;
    EXPECT_EQ(SNMP_ERR_NOERROR, handle_amiACD_Trigger(&c.handler, &c.reginfo,
                                                      &c.reqinfo, &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpSMTPPriStatus
// ---------------------------------------------------------------------------

TEST(HandleSMTPPriStatusTest, ModeFree_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_FREE);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPPriStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPPriStatusTest, ModeCommit_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_COMMIT);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPPriStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPPriStatusTest, ModeUndo_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_UNDO);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPPriStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPPriStatusTest, ModeReserve2_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE2);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPPriStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPPriStatusTest, UnknownMode_ReturnsErrGenerr)
{
    HandlerCtx c(9999);
    EXPECT_EQ(SNMP_ERR_GENERR, handle_amiSnmpSMTPPriStatus(
                                   &c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleSMTPPriStatusTest, ModeGet_DBusFails_ThrowsVariantAccess)
{
    // getDbusProperty leaves variant default-constructed (vector<string>).
    // std::get<bool>(variant) throws std::bad_variant_access.
    // Lines inside MODE_GET are still executed by gcov up to the throw.
    HandlerCtx c(MODE_GET);
    EXPECT_ANY_THROW(handle_amiSnmpSMTPPriStatus(&c.handler, &c.reginfo,
                                                 &c.reqinfo, &c.req));
}

TEST(HandleSMTPPriStatusTest, ModeReserve1_MatchingType_ReturnsNoError)
{
    // vb.type = ASN_INTEGER matches expected → check_vb_type returns 0
    // → set_request_error NOT called → break → SNMP_ERR_NOERROR.
    HandlerCtx c(MODE_SET_RESERVE1);
    c.vb.type = ASN_INTEGER;
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPPriStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpSMTPSecStatus
// ---------------------------------------------------------------------------
// Note: this handler creates sdbusplus::bus::new_default() before the switch.
// Connecting to the system bus succeeds in Docker; only the method call fails.

TEST(HandleSMTPSecStatusTest, ModeFree_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_FREE);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPSecStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPSecStatusTest, ModeCommit_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_COMMIT);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPSecStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPSecStatusTest, ModeUndo_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_UNDO);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPSecStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPSecStatusTest, ModeReserve2_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE2);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPSecStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

TEST(HandleSMTPSecStatusTest, UnknownMode_ReturnsErrGenerr)
{
    HandlerCtx c(9999);
    EXPECT_EQ(SNMP_ERR_GENERR, handle_amiSnmpSMTPSecStatus(
                                   &c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleSMTPSecStatusTest, ModeGet_DBusFails_ThrowsVariantAccess)
{
    // Same as PriStatus: getDbusProperty leaves variant as default →
    // std::get<bool> throws std::bad_variant_access.
    HandlerCtx c(MODE_GET);
    EXPECT_ANY_THROW(handle_amiSnmpSMTPSecStatus(&c.handler, &c.reginfo,
                                                 &c.reqinfo, &c.req));
}

TEST(HandleSMTPSecStatusTest, ModeReserve1_MatchingType_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE1);
    c.vb.type = ASN_INTEGER;
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpSMTPSecStatus(&c.handler, &c.reginfo, &c.reqinfo,
                                          &c.req));
}

} // namespace
