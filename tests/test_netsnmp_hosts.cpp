// test_netsnmp_hosts.cpp — unit tests for netSnmpHostsTable.cpp
//
// Coverage targets:
//   • netSnmpHostsTable_removeEntry: null row → early return (line 1 of body)
//   • netSnmpHostsTable_createEntry: null table_data → null check triggered
//     → SNMP_FREE(entry) + netsnmp_tdata_delete_row(row) → return NULL
//   • netSnmpHostsTable_handler: MODE_GET with null requests → for loop not
//     entered → SNMP_ERR_NOERROR.  MODE_SET_RESERVE1, MODE_SET_FREE,
//     MODE_SET_ACTION, MODE_SET_COMMIT, MODE_SET_UNDO with null requests →
//     same (each for loop body skipped).
//
// Safety notes:
//   • netSnmpHostsTable_createEntry uses SNMP_MALLOC_TYPEDEF (=calloc),
//     netsnmp_tdata_create_row() (=calloc), and netsnmp_tdata_row_add_index()
//     (allocates via snmp_varlist_add_variable → malloc).  All three are pure
//     memory operations that do not require SNMP agent initialisation.
//   • When table_data is NULL the function hits the null check BEFORE calling
//     netsnmp_tdata_add_row, so the container is never touched.
//   • netSnmpHostsTable_handler's for loops iterate over requests; passing
//     nullptr skips all loops, giving safe coverage of the case labels.

// clang-format off
#include "netSnmpHostsTable.hpp"
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

#include <cstdint>
#include <cstring>
#include <string>

#include <gtest/gtest.h>

// netSnmpHostsTable_createEntry and netSnmpHostsTable_removeEntry are defined
// in netSnmpHostsTable.cpp but not declared in the header.
netsnmp_tdata_row* netSnmpHostsTable_createEntry(
    netsnmp_tdata* table_data, uint8_t* netSnmpRowIndex,
    size_t netSnmpRowIndex_len, std::string amiSensorName,
    double amiSensorValue);

void netSnmpHostsTable_removeEntry(netsnmp_tdata* table_data,
                                   netsnmp_tdata_row* row);

namespace
{

// ---------------------------------------------------------------------------
// netSnmpHostsTable_removeEntry
// ---------------------------------------------------------------------------

TEST(HostsTableRemoveEntryTest, NullRow_EarlyReturn_NoOp)
{
    // if (!row) return — no dereferences.
    EXPECT_NO_THROW(netSnmpHostsTable_removeEntry(nullptr, nullptr));
}

TEST(HostsTableRemoveEntryTest, NullRow_WithNonNullTable_EarlyReturn)
{
    // row is still null → early return regardless of table_data.
    netsnmp_tdata table{};
    EXPECT_NO_THROW(netSnmpHostsTable_removeEntry(&table, nullptr));
}

// ---------------------------------------------------------------------------
// netSnmpHostsTable_createEntry
// ---------------------------------------------------------------------------

TEST(HostsTableCreateEntryTest, NullTableData_ReturnsNull)
{
    // SNMP_MALLOC_TYPEDEF(entry) → calloc ✓
    // netsnmp_tdata_create_row() → calloc ✓
    // netsnmp_tdata_row_add_index() → snmp_varlist_add_variable (malloc) ✓
    // if (!table_data) → true → SNMP_FREE(entry) + delete_row → return NULL.
    uint8_t index[2] = {0, 0};
    auto* row = netSnmpHostsTable_createEntry(nullptr, index, sizeof(index),
                                              "test_sensor", 1.0);
    EXPECT_EQ(row, nullptr);
}

TEST(HostsTableCreateEntryTest, NullTableData_ZeroLenIndex_ReturnsNull)
{
    // Zero-length index — tests boundary of netsnmp_tdata_row_add_index.
    uint8_t index[1] = {0};
    auto* row =
        netSnmpHostsTable_createEntry(nullptr, index, 0, "zero_index", 0.0);
    EXPECT_EQ(row, nullptr);
}

// ---------------------------------------------------------------------------
// netSnmpHostsTable_handler — each mode with requests == nullptr
// For each case the for loops over requests are immediately skipped.
// ---------------------------------------------------------------------------

TEST(HostsTableHandlerTest, ModeGet_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_GET;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

TEST(HostsTableHandlerTest, ModeSetReserve1_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_RESERVE1;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

TEST(HostsTableHandlerTest, ModeSetReserve2_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_RESERVE2;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

TEST(HostsTableHandlerTest, ModeSetFree_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_FREE;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

TEST(HostsTableHandlerTest, ModeSetAction_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_ACTION;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

TEST(HostsTableHandlerTest, ModeSetCommit_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_COMMIT;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

TEST(HostsTableHandlerTest, ModeSetUndo_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_UNDO;

    EXPECT_EQ(SNMP_ERR_NOERROR,
              netSnmpHostsTable_handler(&handler, &reginfo, &reqinfo, nullptr));
}

} // namespace
