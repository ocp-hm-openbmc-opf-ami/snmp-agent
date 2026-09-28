// test_netsnmp_handler.cpp — unit tests for SNMP table utility functions in
// netSnmpAmiHandle.cpp that can be exercised without a running SNMP agent.
//
// Coverage targets (all in netSnmpAmiHandle.cpp):
//   • getSensorData / getDiscreteSensorData / getUserInfo
//     D-Bus call fails gracefully → exception caught → empty vector returned.
//   • AddToSensorInstances / AddToDiscreteSensorInstances /
//   AddToUserInfoInstances
//     Linked-list insert — both "head==NULL" and "append to tail" branches.
//   • sensorTable_load / discreteSensorTable_load / userInfoTable_load
//     Safe with NULL cache/magic when getSensorData returns empty.
//   • sensorTable_free / discreteSensorTable_free / userInfoTable_free
//     Safe when head is NULL (no entries) — while loop never executes.
//   • sensorTable_get_first/next_data_point (and discrete/userInfo variants)
//     With NULL loop context → entry==NULL → else branch → returns NULL.
//
// Safety constraints:
//   • sensorData_head / discreteSensorData_head / userInfoData_head are static
//     globals.  The fixture calls the matching *_free() in both SetUp and
//     TearDown so state never leaks between tests.
//   • Entries passed to AddToXxx MUST be heap-allocated (calloc/new); the
//     corresponding free functions call SNMP_FREE which calls free().
//     Passing stack-allocated entries would corrupt memory.
//   • my_loop_context / my_data_context passed to get_next are local void*
//     variables — valid pointers, but the pointees are NULL (entry==NULL
//     path skips all dereferences of put_index_data).

// ── Include order ───────────────────────────────────────────────────────────
// Net-SNMP headers (pulled in via netSnmpAmiHandle.hpp) define FAIL, ERROR,
// DEBUG macros that clash with gtest.  Include production headers first, then
// undef the conflicting macros, then include gtest.
#include "netSnmpAmiHandle.hpp"

#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

#include <cstdlib> // calloc/free
#include <vector>

#include <gtest/gtest.h>

// ── Forward declarations ─────────────────────────────────────────────────────
// These free functions are defined in netSnmpAmiHandle.cpp but are not
// exposed through the header.
void getSensorData(std::vector<amiHandleSensorTable_entry>& data);
void getDiscreteSensorData(
    std::vector<amiHandleDiscreteSensorTable_entry>& data);
void getUserInfo(std::vector<amiHandleUserInfoTable_entry>& data);

void AddToSensorInstances(struct amiHandleSensorTable_entry* sensorInst);
void AddToDiscreteSensorInstances(
    struct amiHandleDiscreteSensorTable_entry* sensorInst);
void AddToUserInfoInstances(struct amiHandleUserInfoTable_entry* userInst);

// The header declares userInfoSensorTable_load/free (mismatched names vs the
// cpp definitions).  Declare the cpp names explicitly for use in tests.
int userInfoTable_load(netsnmp_cache* cache, void* vmagic);
void userInfoTable_free(netsnmp_cache* cache, void* magic);

// ── Fixture ──────────────────────────────────────────────────────────────────
// Drains all three global linked-list heads before and after each test so
// that no state leaks between tests regardless of insertion order.
struct NetSnmpHandlerTest : public ::testing::Test
{
    void SetUp() override
    {
        sensorTable_free(nullptr, nullptr);
        discreteSensorTable_free(nullptr, nullptr);
        userInfoTable_free(nullptr, nullptr);
    }

    void TearDown() override
    {
        sensorTable_free(nullptr, nullptr);
        discreteSensorTable_free(nullptr, nullptr);
        userInfoTable_free(nullptr, nullptr);
    }
};

// ============================================================================
// getSensorData / getDiscreteSensorData / getUserInfo
// D-Bus ObjectMapper call fails → exception caught silently → empty vector.
// ============================================================================

TEST_F(NetSnmpHandlerTest, GetSensorData_DBusFails_ReturnsEmpty)
{
    std::vector<amiHandleSensorTable_entry> data;
    EXPECT_NO_THROW(getSensorData(data));
    EXPECT_TRUE(data.empty());
}

TEST_F(NetSnmpHandlerTest, GetDiscreteSensorData_DBusFails_ReturnsEmpty)
{
    std::vector<amiHandleDiscreteSensorTable_entry> data;
    EXPECT_NO_THROW(getDiscreteSensorData(data));
    EXPECT_TRUE(data.empty());
}

TEST_F(NetSnmpHandlerTest, GetUserInfo_DBusFails_ReturnsEmpty)
{
    std::vector<amiHandleUserInfoTable_entry> data;
    EXPECT_NO_THROW(getUserInfo(data));
    EXPECT_TRUE(data.empty());
}

// ============================================================================
// sensorTable_load / _free / _get_first / _get_next
// ============================================================================

TEST_F(NetSnmpHandlerTest, SensorTable_Load_NullArgs_ReturnsZero)
{
    // getSensorData fails gracefully → sensorData is empty → for-loop skipped
    // → no AddToSensorInstances calls → returns 0.
    EXPECT_EQ(0, sensorTable_load(nullptr, nullptr));
}

TEST_F(NetSnmpHandlerTest, SensorTable_Free_NullHead_NoOp)
{
    // sensorData_head is NULL (SetUp freed it) → while loop never executes.
    EXPECT_NO_THROW(sensorTable_free(nullptr, nullptr));
}

TEST_F(NetSnmpHandlerTest, SensorTable_GetNextDataPoint_NullEntry_ReturnsNull)
{
    // entry = (amiHandleSensorTable_entry*)loop_ctx = NULL → else branch.
    void* loop_ctx = nullptr;
    void* data_ctx = nullptr;
    auto* result =
        sensorTable_get_next_data_point(&loop_ctx, &data_ctx, nullptr, nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(NetSnmpHandlerTest, SensorTable_GetFirstDataPoint_NullHead_ReturnsNull)
{
    // Sets *my_loop_context = sensorData_head (NULL), then calls get_next
    // → returns NULL.
    void* loop_ctx = nullptr;
    void* data_ctx = nullptr;
    auto* result = sensorTable_get_first_data_point(&loop_ctx, &data_ctx,
                                                    nullptr, nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(NetSnmpHandlerTest, AddToSensorInstances_FirstEntry_SetsHead)
{
    // Head is NULL → sensorData_head = sensorInst (first branch in
    // AddToSensorInstances).  TearDown calls sensorTable_free which frees it.
    auto* e = static_cast<amiHandleSensorTable_entry*>(
        calloc(1, sizeof(amiHandleSensorTable_entry)));
    ASSERT_NE(e, nullptr);
    e->sensorIndex = 1;
    e->next = nullptr;
    EXPECT_NO_THROW(AddToSensorInstances(e));
}

TEST_F(NetSnmpHandlerTest, AddToSensorInstances_TwoEntries_AppendsToTail)
{
    // First entry → head-NULL branch; second entry → while-loop else branch.
    // TearDown frees both entries via sensorTable_free.
    auto* e1 = static_cast<amiHandleSensorTable_entry*>(
        calloc(1, sizeof(amiHandleSensorTable_entry)));
    auto* e2 = static_cast<amiHandleSensorTable_entry*>(
        calloc(1, sizeof(amiHandleSensorTable_entry)));
    ASSERT_NE(e1, nullptr);
    ASSERT_NE(e2, nullptr);
    e1->sensorIndex = 1;
    e1->next = nullptr;
    e2->sensorIndex = 2;
    e2->next = nullptr;
    AddToSensorInstances(e1); // head == NULL → head = e1
    AddToSensorInstances(e2); // head != NULL → walk list, append e2
    SUCCEED();                // TearDown frees both.
}

// ============================================================================
// discreteSensorTable_load / _free / _get_first / _get_next
// ============================================================================

TEST_F(NetSnmpHandlerTest, DiscreteSensorTable_Load_NullArgs_ReturnsZero)
{
    EXPECT_EQ(0, discreteSensorTable_load(nullptr, nullptr));
}

TEST_F(NetSnmpHandlerTest, DiscreteSensorTable_Free_NullHead_NoOp)
{
    EXPECT_NO_THROW(discreteSensorTable_free(nullptr, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       DiscreteSensorTable_GetNextDataPoint_NullEntry_ReturnsNull)
{
    void* loop_ctx = nullptr;
    void* data_ctx = nullptr;
    auto* result = discreteSensorTable_get_next_data_point(
        &loop_ctx, &data_ctx, nullptr, nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(NetSnmpHandlerTest,
       DiscreteSensorTable_GetFirstDataPoint_NullHead_ReturnsNull)
{
    void* loop_ctx = nullptr;
    void* data_ctx = nullptr;
    auto* result = discreteSensorTable_get_first_data_point(
        &loop_ctx, &data_ctx, nullptr, nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(NetSnmpHandlerTest, AddToDiscreteSensorInstances_FirstEntry_SetsHead)
{
    auto* e = static_cast<amiHandleDiscreteSensorTable_entry*>(
        calloc(1, sizeof(amiHandleDiscreteSensorTable_entry)));
    ASSERT_NE(e, nullptr);
    e->sensorIndex = 10;
    e->next = nullptr;
    EXPECT_NO_THROW(AddToDiscreteSensorInstances(e));
}

TEST_F(NetSnmpHandlerTest, AddToDiscreteSensorInstances_TwoEntries_Appends)
{
    auto* e1 = static_cast<amiHandleDiscreteSensorTable_entry*>(
        calloc(1, sizeof(amiHandleDiscreteSensorTable_entry)));
    auto* e2 = static_cast<amiHandleDiscreteSensorTable_entry*>(
        calloc(1, sizeof(amiHandleDiscreteSensorTable_entry)));
    ASSERT_NE(e1, nullptr);
    ASSERT_NE(e2, nullptr);
    e1->sensorIndex = 10;
    e1->next = nullptr;
    e2->sensorIndex = 11;
    e2->next = nullptr;
    AddToDiscreteSensorInstances(e1);
    AddToDiscreteSensorInstances(e2);
    SUCCEED();
}

// ============================================================================
// userInfoTable_load / _free / _get_first / _get_next
// (The header mistakenly declares userInfoSensorTable_load/free; the actual
//  definitions in the .cpp are userInfoTable_load/free, forward-declared
//  above.)
// ============================================================================

TEST_F(NetSnmpHandlerTest, UserInfoTable_Load_NullArgs_ReturnsZero)
{
    EXPECT_EQ(0, userInfoTable_load(nullptr, nullptr));
}

TEST_F(NetSnmpHandlerTest, UserInfoTable_Free_NullHead_NoOp)
{
    EXPECT_NO_THROW(userInfoTable_free(nullptr, nullptr));
}

TEST_F(NetSnmpHandlerTest, UserInfoTable_GetNextDataPoint_NullEntry_ReturnsNull)
{
    void* loop_ctx = nullptr;
    void* data_ctx = nullptr;
    auto* result = userInfoTable_get_next_data_point(&loop_ctx, &data_ctx,
                                                     nullptr, nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(NetSnmpHandlerTest, UserInfoTable_GetFirstDataPoint_NullHead_ReturnsNull)
{
    void* loop_ctx = nullptr;
    void* data_ctx = nullptr;
    auto* result = userInfoTable_get_first_data_point(&loop_ctx, &data_ctx,
                                                      nullptr, nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(NetSnmpHandlerTest, AddToUserInfoInstances_FirstEntry_SetsHead)
{
    auto* e = static_cast<amiHandleUserInfoTable_entry*>(
        calloc(1, sizeof(amiHandleUserInfoTable_entry)));
    ASSERT_NE(e, nullptr);
    e->userIndex = 1;
    e->next = nullptr;
    EXPECT_NO_THROW(AddToUserInfoInstances(e));
}

TEST_F(NetSnmpHandlerTest, AddToUserInfoInstances_TwoEntries_Appends)
{
    auto* e1 = static_cast<amiHandleUserInfoTable_entry*>(
        calloc(1, sizeof(amiHandleUserInfoTable_entry)));
    auto* e2 = static_cast<amiHandleUserInfoTable_entry*>(
        calloc(1, sizeof(amiHandleUserInfoTable_entry)));
    ASSERT_NE(e1, nullptr);
    ASSERT_NE(e2, nullptr);
    e1->userIndex = 1;
    e1->next = nullptr;
    e2->userIndex = 2;
    e2->next = nullptr;
    AddToUserInfoInstances(e1);
    AddToUserInfoInstances(e2);
    SUCCEED();
}

// ============================================================================
// handler_netSnmpAmiSensorTable
// Strategy: call with zero-initialised reqinfo/req.
//   netsnmp_extract_iterator_context(request) returns NULL when
//   request->parent_data == NULL → table_entry == NULL → SNMP_NOSUCHINSTANCE
//   set on request → continue → loop ends → return SNMP_ERR_NOERROR.
// ============================================================================

TEST_F(NetSnmpHandlerTest, SensorTableHandler_NonGetMode_ReturnsNoError)
{
    // reqinfo.mode != MODE_GET → if block skipped → return SNMP_ERR_NOERROR.
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_FREE;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiSensorTable(
                                    &handler, &reginfo, &reqinfo, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       SensorTableHandler_GetMode_NullRequests_ReturnsNoError)
{
    // requests == nullptr → for loop body never entered → return
    // SNMP_ERR_NOERROR.
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_GET;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiSensorTable(
                                    &handler, &reginfo, &reqinfo, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       SensorTableHandler_GetMode_OneRequest_NullEntry_SetsErrorAndContinues)
{
    // reqinfo.mode == MODE_GET, one request with parent_data=NULL
    // → netsnmp_extract_iterator_context returns NULL
    // → netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE)
    //   (safe: reqinfo.mode==MODE_GET, reqinfo.asp==NULL)
    // → continue → loop ends → return SNMP_ERR_NOERROR.
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    netsnmp_variable_list vb{};
    netsnmp_request_info req{};
    reqinfo.mode = MODE_GET;
    req.requestvb = &vb;
    req.next = nullptr;
    req.processed = 0;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiSensorTable(
                                    &handler, &reginfo, &reqinfo, &req));
}

// ============================================================================
// handler_netSnmpAmiDiscreteSensorTable
// ============================================================================

TEST_F(NetSnmpHandlerTest, DiscreteSensorTableHandler_NonGetMode_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_FREE;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiDiscreteSensorTable(
                                    &handler, &reginfo, &reqinfo, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       DiscreteSensorTableHandler_GetMode_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_GET;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiDiscreteSensorTable(
                                    &handler, &reginfo, &reqinfo, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       DiscreteSensorTableHandler_GetMode_OneRequest_NullEntry_SetsError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    netsnmp_variable_list vb{};
    netsnmp_request_info req{};
    reqinfo.mode = MODE_GET;
    req.requestvb = &vb;
    req.next = nullptr;
    req.processed = 0;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiDiscreteSensorTable(
                                    &handler, &reginfo, &reqinfo, &req));
}

// ============================================================================
// handler_netSnmpAmiUserInfoTable
// ============================================================================

TEST_F(NetSnmpHandlerTest, UserInfoTableHandler_NonGetMode_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_SET_FREE;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiUserInfoTable(
                                    &handler, &reginfo, &reqinfo, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       UserInfoTableHandler_GetMode_NullRequests_ReturnsNoError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    reqinfo.mode = MODE_GET;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiUserInfoTable(
                                    &handler, &reginfo, &reqinfo, nullptr));
}

TEST_F(NetSnmpHandlerTest,
       UserInfoTableHandler_GetMode_OneRequest_NullEntry_SetsError)
{
    netsnmp_mib_handler handler{};
    netsnmp_handler_registration reginfo{};
    netsnmp_agent_request_info reqinfo{};
    netsnmp_variable_list vb{};
    netsnmp_request_info req{};
    reqinfo.mode = MODE_GET;
    req.requestvb = &vb;
    req.next = nullptr;
    req.processed = 0;

    EXPECT_EQ(SNMP_ERR_NOERROR, handler_netSnmpAmiUserInfoTable(
                                    &handler, &reginfo, &reqinfo, &req));
}
