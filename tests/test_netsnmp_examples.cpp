// test_netsnmp_examples.cpp — unit tests for netSnmpExamples.cpp
//
// Coverage targets:
//   • getMapperObject / getServiceName / getSensorInfo: D-Bus fails → throw
//   • handle_amiSnmpInteger: body calls getMapperObject (throws) →
//   EXPECT_ANY_THROW • handle_amiSnmpSleeper / handle_amiSnmpFloat /
//   handle_amiSnmpInlet_BRD_Temp:
//     body calls getSensorInfo → getMapperObject throws → EXPECT_ANY_THROW
//   • handle_amiSnmpString: no D-Bus call in body → full switch coverage:
//     MODE_GET, SET_RESERVE1, SET_RESERVE2, SET_FREE, SET_ACTION, SET_COMMIT,
//     SET_UNDO, default (unknown mode)
//
// Include order: production header first (defines net-snmp macros
// FAIL/ERROR/DEBUG), undef those macros, then gtest.

// clang-format off
#include "netSnmpExamples.hpp"
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

#include <gtest/gtest.h>

namespace
{

// ---------------------------------------------------------------------------
// HandlerCtx — zero-initialised SNMP handler structs with a valid requestvb.
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
// getMapperObject — D-Bus call fails → sdbusplus::exception thrown (re-thrown
// by the catch block in getMapperObject).
// ---------------------------------------------------------------------------

TEST(GetMapperObjectTest, DBusFails_Throws)
{
    // getMapperObject calls getServiceName which calls ObjectMapper.GetObject →
    // service not running → sdbusplus::exception → re-thrown.
    EXPECT_ANY_THROW(
        getMapperObject("/xyz/openbmc_project/sensors/temperature/BMC_Temp",
                        "xyz.openbmc_project.Sensor.Value"));
}

// ---------------------------------------------------------------------------
// getSensorInfo — calls getMapperObject which throws; exception propagates.
// ---------------------------------------------------------------------------

TEST(GetSensorInfoTest, DBusFails_Throws)
{
    EXPECT_ANY_THROW(
        getSensorInfo("/xyz/openbmc_project/sensors/temperature/BMC_Temp",
                      "xyz.openbmc_project.Sensor.Value"));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpInteger — calls getMapperObject in function body → throws.
// Lines up to the throw are counted as covered by gcov.
// ---------------------------------------------------------------------------

TEST(HandleAmiSnmpIntegerTest, AnyMode_DBusFails_Throws)
{
    HandlerCtx c(MODE_GET);
    EXPECT_ANY_THROW(
        handle_amiSnmpInteger(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpSleeper — calls getSensorInfo → getMapperObject throws.
// ---------------------------------------------------------------------------

TEST(HandleAmiSnmpSleeperTest, AnyMode_DBusFails_Throws)
{
    HandlerCtx c(MODE_GET);
    EXPECT_ANY_THROW(
        handle_amiSnmpSleeper(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpFloat — calls getSensorInfo → getMapperObject throws.
// ---------------------------------------------------------------------------

TEST(HandleAmiSnmpFloatTest, AnyMode_DBusFails_Throws)
{
    HandlerCtx c(MODE_GET);
    EXPECT_ANY_THROW(
        handle_amiSnmpFloat(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpInlet_BRD_Temp — calls getSensorInfo → throws.
// ---------------------------------------------------------------------------

TEST(HandleAmiSnmpInletBRDTempTest, AnyMode_DBusFails_Throws)
{
    HandlerCtx c(MODE_GET);
    EXPECT_ANY_THROW(handle_amiSnmpInlet_BRD_Temp(&c.handler, &c.reginfo,
                                                  &c.reqinfo, &c.req));
}

// ---------------------------------------------------------------------------
// handle_amiSnmpString — no D-Bus calls in function body; all switch paths
// are directly exercisable.
//
//   MODE_GET:        snmp_set_var_typed_value with empty amiString (len=0)
//   SET_RESERVE1:    netsnmp_check_vb_type with vb.type=ASN_OCTET_STR → 0
//   SET_RESERVE2:    empty break
//   SET_FREE:        empty break
//   SET_ACTION:      empty break (no-op stub)
//   SET_COMMIT:      empty break
//   SET_UNDO:        empty break
//   default (9999):  snmp_log → SNMP_ERR_GENERR
// ---------------------------------------------------------------------------

TEST(HandleAmiSnmpStringTest, ModeGet_EmptyString_ReturnsNoError)
{
    // amiString is a local empty string; snmp_set_var_typed_value copies 0
    // bytes — safe even with zero-init vb.
    HandlerCtx c(MODE_GET);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, ModeReserve1_MatchingType_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE1);
    c.vb.type = ASN_OCTET_STR;
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, ModeReserve2_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_RESERVE2);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, ModeFree_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_FREE);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, ModeAction_ReturnsNoError)
{
    // SET_ACTION body is empty (stub placeholder) → break → SNMP_ERR_NOERROR.
    HandlerCtx c(MODE_SET_ACTION);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, ModeCommit_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_COMMIT);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, ModeUndo_ReturnsNoError)
{
    HandlerCtx c(MODE_SET_UNDO);
    EXPECT_EQ(SNMP_ERR_NOERROR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

TEST(HandleAmiSnmpStringTest, UnknownMode_ReturnsErrGenerr)
{
    // default: snmp_log(LOG_ERR, ...) → return SNMP_ERR_GENERR.
    HandlerCtx c(9999);
    EXPECT_EQ(SNMP_ERR_GENERR,
              handle_amiSnmpString(&c.handler, &c.reginfo, &c.reqinfo, &c.req));
}

} // namespace
