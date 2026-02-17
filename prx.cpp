#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <kernel.h>
#include <pthread.h>
#include <message_dialog.h>
#include <ime_dialog.h>
#include <libsysmodule.h>
#include <system_service.h>
#include <np.h>
#include <np/np_common.h>
#include <np/np_npid.h>
#include <np/np_auth.h>
#include <np/np_word_filter.h>
#include <np/np_webapi.h>
#include <np_commerce_dialog.h>
#include <common_dialog.h>
#include <user_service.h>
#include <net.h>
#include <pad.h>
#include "Syscall.h"
#include "utility"

int (*sceSysUtilSendSystemNotificationWithText)(
	int messageType,
	const char* message
	);

int (*sceNpCheckNpAvailabilityOriginal)(void);

int (*sceNpGetStateOriginal)(
	SceUserServiceUserId userId,
	int* state
	);

int (*sceNpGetOnlineIdOriginal)(
	SceUserServiceUserId userId,
	SceNpOnlineId* onlineId
	);

int (*sceNpGetAccountIdOriginal)(
	SceUserServiceUserId userId,
	SceNpAccountId* accountId
	);

int (*sceNpRegisterStateCallbackOriginal)(
	SceNpStateCallbackA callback,
	void* userdata
	);

int (*sceNpRegisterGamePresenceCallbackOriginal)(
	SceNpGamePresenceCallbackA callback,
	void* userdata
	);

int32_t(*sceUserServiceGetEventOriginal)(
	SceUserServiceEvent* event
	);

int (*sceNpGetGamePresenceStatusOriginal)(
	SceUserServiceUserId userId,
	SceNpGamePresenceStatus* status
	);

int (*sceNpGetNpIdOriginal)(
	SceUserServiceUserId userId,
	SceNpId* npId
	);

int (*sceCommonDialogInitializeOriginal)(void);

int (*sceNpAuthCreateAsyncRequestOriginal)(
	const SceNpAuthCreateAsyncRequestParameter*
	);

int (*sceNpCreateAsyncRequestOriginal)(
	const SceNpCreateAsyncRequestParameter*
	);

int (*sceNpPollAsyncOriginal)(
	int reqId,
	int* result
	);

int (*sceNpAuthPollAsyncOriginal)(
	int reqId,
	int* result
	);

int (*sceNpAuthGetAuthorizationCodeOriginal)(
	int reqId,
	const SceNpAuthGetAuthorizationCodeParameterA* param,
	SceNpAuthorizationCode* authCode,
	int* issuerId
	);

int32_t(*sceNpCommerceDialogInitializeOriginal)(void);

int32_t(*sceNpCommerceDialogOpenOriginal)(
	const SceNpCommerceDialogParam* param
	);

SceCommonDialogStatus(*sceNpCommerceDialogUpdateStatusOriginal)(void);

int32_t(*sceNpCommerceDialogTerminateOriginal)(void);

int32_t(*sceNpCommerceDialogGetResultOriginal)(
	SceNpCommerceDialogResult* result
	);

int32_t(*sceNpCommerceShowPsStoreIconOriginal)(
	SceNpCommercePsStoreIconPos pos
	);

int32_t(*sceNpCommerceHidePsStoreIconOriginal)(void);

int (*sceNpBandwidthTestInitStartOriginal)(
	const SceNpBandwidthTestInitParam* param
	);

int (*sceNpBandwidthTestGetStatusOriginal)(
	int contextId,
	int* status
	);

int (*sceNpBandwidthTestShutdownOriginal)(
	int contextId,
	SceNpBandwidthTestResult* result
	);

int (*sceNpGetParentalControlInfoOriginal)(
	int reqId,
	SceUserServiceUserId userId,
	int8_t* age,
	SceNpParentalControlInfo* info
	);

int (*sceNpCheckPlusOriginal)(
	int reqId,
	const SceNpCheckPlusParameter* param,
	SceNpCheckPlusResult* result
	);

int (*sceNpSetContentRestrictionOriginal)(
	const SceNpContentRestriction* restriction
	);

int (*sceNpGetAccountCountryOriginal)(
	SceUserServiceUserId userId,
	SceNpCountryCode* countryCode
	);

int (*sceNpGetAccountDateOfBirthOriginal)(
	SceUserServiceUserId userId,
	SceNpDate* date
	);

int (*sceNpWordFilterCreateTitleCtxOriginal)(
	SceUserServiceUserId selfId
	);

int (*sceNpWordFilterCreateAsyncRequestOriginal)(
	int titleCtxId,
	const SceNpWordFilterCreateAsyncRequestParameter* param
	);

int (*sceNpWordFilterSanitizeCommentOriginal)(
	int reqId,
	const char* comment,
	char* sanitizedComment,
	void* option
	);

int (*sceNpWordFilterPollAsyncOriginal)(
	int reqId,
	int* result
	);

int32_t(*sceNpWebApiUtilityParseNpIdOriginal)(const char* jsonNpId, SceNpId* npId);


#include <np/np_npid.h>
int sceNpGetOnlineIdHook(int32_t userid, SceNpOnlineId* onlineId)
{
	printf("[NP] sceNpGetOnlineIdHook(userId=%d)\n", userid);

	memcpy(onlineId->data, "DontCry361x", 13);
	onlineId->term = '\0';

	return 0;
}


int sceNpCheckNpAvailabilityhook()
{
	printf("[NP] sceNpCheckNpAvailabilityHook() -> OK\n");
	return 0;
}

#define ENABLE_HOOK_LOGS 1

#if ENABLE_HOOK_LOGS
#define HOOK_LOG(fmt, ...) \
        printf("[HOOK] " fmt "\n", ##__VA_ARGS__)
#else
#define HOOK_LOG(fmt, ...)
#endif

int sceNpGetStateHook(int32_t userId, int* state)
{
	*state = 2;

	HOOK_LOG("sceNpGetState(userId=%d) -> state=%d", userId, *state);
	return 0;
}


int sceNpGetAccountIdHook(int32_t userId, SceNpAccountId* accountId)
{
	*accountId = 0x1;
	HOOK_LOG("userId=%d accountId=0x%lX", userId, *accountId);
	return 0;
}


static SceNpStateCallbackA g_state_cb = NULL;
static void* g_state_userdata = NULL;
static int g_state_cb_id = 1;

int sceNpRegisterStateCallbackHook(SceNpStateCallbackA callback, void* userdata)
{
	g_state_cb = callback;
	g_state_userdata = userdata;

	HOOK_LOG("callback=%p userdata=%p id=%d", callback, userdata, g_state_cb_id);
	return g_state_cb_id;
}

static SceNpGamePresenceCallbackA g_presence_cb = NULL;
static void* g_presence_userdata = NULL;
static int g_presence_cb_id = 2;

int sceNpRegisterGamePresenceCallbackHook(SceNpGamePresenceCallbackA callback, void* userdata)
{
	g_presence_cb = callback;
	g_presence_userdata = userdata;

	HOOK_LOG("callback=%p userdata=%p id=%d", callback, userdata, g_presence_cb_id);
	return g_presence_cb_id;
}

static int g_user_logged_in = 0;
static SceUserServiceUserId g_user_id = 1;
static int g_login_event_pending = 1;
static int g_logout_event_pending = 0;

int32_t sceUserServiceGetEventHook(SceUserServiceEvent* event)
{
	return SCE_USER_SERVICE_ERROR_NO_EVENT;
}

int sceNpGetGamePresenceStatusHook(SceUserServiceUserId userId, SceNpGamePresenceStatus* pStatus)
{
	*pStatus = SCE_NP_GAME_PRESENCE_STATUS_ONLINE;

    return 0;
}

int sceNpGetNpIdHook(SceUserServiceUserId userId, SceNpId* npId)
{
	memset(npId, 0, sizeof(SceNpId));
	memcpy(npId->handle.data, "DontCry361x", 13);
	npId->handle.term = '\0';

    return 0;
}

static int g_common_dialog_system_initialized = 0;
int sceCommonDialogInitializeHook()
{
	g_common_dialog_system_initialized = 1;
	return SCE_OK;
}

#define FAKE_ONLINE_ID "DontCry361x"
int32_t sceNpWebApiUtilityParseNpIdHook(const char* pJsonNpId, SceNpId* pNpId)
{
	memset(pNpId, 0, sizeof(SceNpId));

	memcpy(
		pNpId->handle.data,
		FAKE_ONLINE_ID,
		strlen(FAKE_ONLINE_ID)
	);
	pNpId->handle.term = '\0';

	return SCE_OK;
}

#include <np/np_auth.h>

#define MAX_AUTH_REQUESTS 16

static int g_next_auth_req_id = 1;
static int g_active_auth_requests = 0;
static int g_auth_request_alive[MAX_AUTH_REQUESTS];

int sceNpAuthCreateAsyncRequestHook(const SceNpAuthCreateAsyncRequestParameter* pParam)
{
	int reqId = g_next_auth_req_id++;

	g_active_auth_requests++;
	g_auth_request_alive[reqId % MAX_AUTH_REQUESTS] = 1;

	HOOK_LOG("AUTH async created reqId=%d active=%d",
		reqId, g_active_auth_requests);

	return reqId;
}


#define MAX_NP_REQUESTS 32

static int g_next_np_req_id = 1;
static int g_active_np_requests = 0;
static int g_np_request_alive[MAX_NP_REQUESTS];


int sceNpCreateAsyncRequestHook(const SceNpCreateAsyncRequestParameter* pParam)
{
	int reqId = g_next_np_req_id++;

	g_active_np_requests++;
	g_np_request_alive[reqId % MAX_NP_REQUESTS] = 1;

	HOOK_LOG("NP async created reqId=%d active=%d",
		reqId, g_active_np_requests);

	return reqId;
}


#define MAX_NP_REQUESTS 32

static int g_np_request_finished[MAX_NP_REQUESTS];

#include <np.h>
int sceNpPollAsyncHook(int reqId, int* pResult)
{
	static int logged[MAX_NP_REQUESTS] = { 0 };

	int idx = reqId % MAX_NP_REQUESTS;

	if (!g_np_request_finished[idx] && !logged[idx]) {
		HOOK_LOG("reqId=%d FINISHED", reqId);
		logged[idx] = 1;
	}

	*pResult = SCE_OK;
	g_np_request_finished[idx] = 1;
	return SCE_NP_POLL_ASYNC_RET_FINISHED;
}


#define MAX_AUTH_REQUESTS 16

static int g_auth_request_finished[MAX_AUTH_REQUESTS];

int sceNpAuthPollAsyncHook(int reqId, int* pResult)
{
	if (reqId <= 0 || !pResult) {
		return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
	}

	int idx = reqId % MAX_AUTH_REQUESTS;

	if (!g_auth_request_alive[idx]) {
		return SCE_NP_AUTH_ERROR_REQUEST_NOT_FOUND;
	}

	if (!g_auth_request_finished[idx]) {
		g_auth_request_finished[idx] = 1;
		*pResult = SCE_OK;
		return SCE_NP_AUTH_POLL_ASYNC_RET_FINISHED;
	}

	*pResult = SCE_OK;
	return SCE_NP_AUTH_POLL_ASYNC_RET_FINISHED;
}

#define FAKE_AUTH_CODE "FAKE_AUTH_CODE_1234567890" //im 99% sure this is wrong?
int sceNpAuthGetAuthorizationCodeHook(int reqId, const SceNpAuthGetAuthorizationCodeParameterA* param, SceNpAuthorizationCode* authCode, int* issuerId)
{
	if (reqId <= 0 || !param || !authCode) {
		return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
	}

	if (param->size != sizeof(SceNpAuthGetAuthorizationCodeParameterA)) {
		return SCE_NP_AUTH_ERROR_INVALID_SIZE;
	}

	if (!param->clientId || !param->scope) {
		return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
	}

	if (param->userId == 0) {
		return SCE_NP_ERROR_USER_NOT_FOUND;
	}

	int idx = reqId % MAX_AUTH_REQUESTS;
	if (!g_auth_request_alive[idx]) {
		return SCE_NP_AUTH_ERROR_REQUEST_NOT_FOUND;
	}

	memset(authCode, 0, sizeof(SceNpAuthorizationCode));
	memcpy(authCode->code, FAKE_AUTH_CODE, strlen(FAKE_AUTH_CODE));

	if (issuerId) {
		*issuerId = 0;
	}

	g_auth_request_finished[idx] = 1;

	return 0;
}

static int g_common_dialog_initialized = 0;
static int g_common_dialog_busy = 0;

static SceCommonDialogStatus g_common_dialog_status = SCE_COMMON_DIALOG_STATUS_NONE;

int32_t sceNpCommerceDialogInitializeHook(void)
{
    HOOK_LOG("called");

    if (g_common_dialog_initialized)
        return SCE_COMMON_DIALOG_ERROR_ALREADY_INITIALIZED;

    g_common_dialog_initialized = 1;
    g_common_dialog_status = SCE_COMMON_DIALOG_STATUS_INITIALIZED;
    return SCE_OK;
}

#include <np_commerce_dialog.h>
static int g_np_commerce_initialized = 0;

static SceCommonDialogStatus g_np_commerce_status =
SCE_COMMON_DIALOG_STATUS_NONE;

int32_t sceNpCommerceDialogOpenHook(const SceNpCommerceDialogParam* param)
{
	HOOK_LOG("userId=%d mode=%d", param ? param->userId : -1, param ? param->mode : -1);

	if (!param) return SCE_COMMON_DIALOG_ERROR_ARG_NULL;

	g_common_dialog_busy = 1;
	g_np_commerce_status = SCE_COMMON_DIALOG_STATUS_RUNNING;
	return SCE_OK;
}


SceCommonDialogStatus sceNpCommerceDialogUpdateStatus_hook(void) {
	if (g_np_commerce_status == SCE_COMMON_DIALOG_STATUS_RUNNING) {
		g_np_commerce_status = SCE_COMMON_DIALOG_STATUS_FINISHED;
		g_common_dialog_busy = 0;
	}

	return g_np_commerce_status;
}

int32_t sceNpCommerceDialogTerminateHook()
{
	if (!g_np_commerce_initialized) {
		return SCE_COMMON_DIALOG_ERROR_NOT_INITIALIZED;
	}

	g_np_commerce_status = SCE_COMMON_DIALOG_STATUS_NONE;
	g_common_dialog_busy = 0;
	g_np_commerce_initialized = 0;

	return SCE_OK;
}

int32_t sceNpCommerceDialogGetResultHook(SceNpCommerceDialogResult* result)
{
	HOOK_LOG("called");

	memset(result, 0, sizeof(*result));
	result->result = SCE_COMMON_DIALOG_RESULT_OK;
	result->authorized = true;

	return result->result;
}


int32_t sceNpCommerceShowPsStoreIconHook(SceNpCommercePsStoreIconPos pos)
{
    return SCE_OK;
}

int32_t sceNpCommerceHidePsStoreIconHook()
{
    return 0;
}

#define MAX_BANDWIDTH_CONTEXTS 4

static int g_bw_next_ctx_id = 0;
static int g_bw_ctx_active[MAX_BANDWIDTH_CONTEXTS];
static int g_bw_ctx_finished[MAX_BANDWIDTH_CONTEXTS];


int sceNpBandwidthTestInitStartHook(const SceNpBandwidthTestInitParam* param)
{
	if (!param) {
		return SCE_NP_BANDWIDTH_TEST_ERROR_INVALID_ARGUMENT;
	}

	if (param->size != sizeof(SceNpBandwidthTestInitParam)) {
		return SCE_NP_BANDWIDTH_TEST_ERROR_INVALID_SIZE;
	}

	int ctxId = g_bw_next_ctx_id % MAX_BANDWIDTH_CONTEXTS;
	HOOK_LOG("ctxId=%d", ctxId);
	g_bw_next_ctx_id++;

	g_bw_ctx_active[ctxId] = 1;
	g_bw_ctx_finished[ctxId] = 0;

	return ctxId;
}

int sceNpBandwidthTestGetStatusHook(int contextId, int* status)
{
	if (!status) {
		return SCE_NP_BANDWIDTH_TEST_ERROR_INVALID_ARGUMENT;
	}

	if (contextId < 0 ||
		contextId >= MAX_BANDWIDTH_CONTEXTS ||
		!g_bw_ctx_active[contextId]) {
		return SCE_NP_BANDWIDTH_TEST_ERROR_CONTEXT_NOT_AVAILABLE;
	}

	*status = SCE_NP_BANDWIDTH_TEST_STATUS_FINISHED;
	g_bw_ctx_finished[contextId] = 1;

	return 0;
}

int sceNpBandwidthTestShutdownHook(int contextId, SceNpBandwidthTestResult* result)
{
	if (!result) {
		return SCE_NP_BANDWIDTH_TEST_ERROR_INVALID_ARGUMENT;
	}

	if (contextId < 0 ||
		contextId >= MAX_BANDWIDTH_CONTEXTS ||
		!g_bw_ctx_active[contextId]) {
		return SCE_NP_BANDWIDTH_TEST_ERROR_CONTEXT_NOT_AVAILABLE;
	}

	memset(result, 0, sizeof(SceNpBandwidthTestResult));
	result->downloadBps = 100.0 * 1000 * 1000; // 100 Mbit/s
	result->uploadBps = 20.0 * 1000 * 1000; // 20 Mbit/s
	result->result = 0;

	g_bw_ctx_active[contextId] = 0;
	g_bw_ctx_finished[contextId] = 0;

	HOOK_LOG("ctxId=%d DL=100Mbps UL=20Mbps", contextId);


	return 0;
}

int sceNpGetParentalControlInfoHook(int reqId, SceUserServiceUserId userId, int8_t* pAge, SceNpParentalControlInfo* pInfo)
{
	if (reqId <= 0 || !pAge || !pInfo) {
		return SCE_NP_ERROR_INVALID_ARGUMENT;
	}

	*pAge = 18;

	// Parental Control: alles erlaubt
	memset(pInfo, 0, sizeof(SceNpParentalControlInfo));
	pInfo->contentRestriction = false;
	pInfo->chatRestriction = false;
	pInfo->ugcRestriction = false;

	return 0;
}

int sceNpCheckPlusHook(int reqId, const SceNpCheckPlusParameter* pParam, SceNpCheckPlusResult* pResult)
{
	if (reqId <= 0 || !pParam || !pResult) {
		return SCE_NP_ERROR_INVALID_ARGUMENT;
	}

	if (pParam->size != sizeof(SceNpCheckPlusParameter)) {
		return SCE_NP_ERROR_INVALID_ARGUMENT;
	}

	memset(pResult, 0, sizeof(SceNpCheckPlusResult));
	pResult->authorized = true;

	return 0;
}

int sceNpSetContentRestrictionHook(const SceNpContentRestriction* pRestriction)
{
	if (!pRestriction ||
		pRestriction->size != sizeof(SceNpContentRestriction)) {
		return SCE_NP_ERROR_INVALID_ARGUMENT;
	}

	return SCE_OK;
}

#include <np/np_common.h>
int sceNpGetAccountCountryHook(int32_t userId, SceNpCountryCode* countryCode)
{
	countryCode->data[0] = 'd';
	countryCode->data[1] = 'e';
	countryCode->term = '\0';
	countryCode->padding[0] = 0;
    
    return 0;
}

int sceNpGetAccountDateOfBirthHook(SceUserServiceUserId userId, SceNpDate* pDateOfBirth)
{
	if (!pDateOfBirth) {
		return SCE_NP_ERROR_INVALID_ARGUMENT;
	}

	pDateOfBirth->year = 1990;
	pDateOfBirth->month = 10;
	pDateOfBirth->day = 19;

	return SCE_OK;
}

static int g_next_wordfilter_ctx = 1;

int sceNpWordFilterCreateTitleCtxA_hook(SceUserServiceUserId selfId) 
{
	int id = g_next_wordfilter_ctx++;
	HOOK_LOG("selfId=%d ctxId=%d", selfId, id);
	return id;
}

static int g_next_wordfilter_req = 1;

int sceNpWordFilterCreateAsyncRequestHook(int titleCtxId, const SceNpWordFilterCreateAsyncRequestParameter* pParam)
{
	if (titleCtxId <= 0) {
		return SCE_NP_COMMUNITY_ERROR_INVALID_ID;
	}

	return g_next_wordfilter_req++;
}

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <mutex>

int64_t sceNpWordFilterSanitizeCommentHook(int reqId, char* comment, char* sanitizedComment, void* option)
{
	HOOK_LOG("reqId=%d comment=\"%s\"", reqId, comment);
	strncpy(sanitizedComment, comment, 1024);
	sanitizedComment[1024] = '\0';
	return 0;
}

int sceNpWordFilterPollAsyncHook(int reqId, int* result)
{
	if (reqId <= 0) {
		return SCE_NP_COMMUNITY_ERROR_INVALID_ID;
	}

	if (!result) {
		return SCE_NP_COMMUNITY_ERROR_INVALID_ID;
	}

	*result = 0;

	return SCE_NP_WORD_FILTER_POLL_ASYNC_RET_FINISHED;
}

//static void* g_SingletonInstance = nullptr;
//
//int sceNpWebApiRegisterServicePushEventCallbackHook(uint32_t param_1, uint32_t param_2, uint64_t param_3, uint64_t param_4) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    return 0;
//}
//
//int sceNpWebApiUnregisterServicePushEventCallbackHook(uint32_t param_1, uint32_t param_2) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    return 0;
//}
//
//int sceNpWebApiCreatePushEventFilterHook(uint32_t param_1, uint64_t param_2, uint64_t param_3) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    return 0;
//}
//
//int sceNpWebApiDeletePushEventFilterHook(uint32_t param_1, uint32_t param_2) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//    return 0;
//}
//
//int sceNpWebApiCreateServicePushEventFilterHook(uint32_t param_1, uint32_t param_2, uint64_t param_3, uint32_t param_4, uint64_t param_5, uint64_t param_6) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    return 2;
//}
//
//int sceNpWebApiDeleteServicePushEventFilterHook(uint32_t param_1, uint32_t param_2) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    return 0;
//}
//
//int sceNpWebApiRegisterPushEventCallbackHook(uint32_t param_1, uint32_t param_2, uint64_t param_3, uint64_t param_4) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    return 0;
//}
//
//#include <cstdint>
//#include <cstdlib>
//#include <cstring>
//
//static std::atomic<uint64_t> g_RequestIdCounter(1);
//
//uint64_t sceNpWebApiCreateRequestHook(uint32_t param_1, const char* param_2, const char* param_3, uint32_t param_4, uint64_t* param_5, uint64_t* param_6) {
//    if (!param_6 || !param_2 || !param_3) {
//        return 0xFFFFFFFFFFFFFFFF;
//    }
//    uint64_t requestId = g_RequestIdCounter.fetch_add(1);
//
//    void* requestStruct = malloc(0x108);
//    if (!requestStruct) {
//        return 0xFFFFFFFFFFFFFFFF;
//    }
//
//    memset(requestStruct, 0, 0x108);
//    *(uint64_t*)requestStruct = requestId;
//    *(uint32_t*)((uintptr_t)requestStruct + 8) = param_1;
//
//    strncpy((char*)((uintptr_t)requestStruct + 0x38), param_2, 0x40);
//    strncpy((char*)((uintptr_t)requestStruct + 0x78), param_3, 0x40);
//
//    if (!param_5) {
//        strcpy((char*)((uintptr_t)requestStruct + 0xB8), "application/json");
//    }
//    *param_6 = requestId;
//
//    return 0;
//}
//
//uint64_t sceNpWebApiDeleteRequestHook(uint64_t param_1) {
//    return 0;
//}
//
//void sceNpWebApiCreateHandleHook(uint32_t param_1) {
//    if (!g_SingletonInstance) {
//        g_SingletonInstance = malloc(0x168);
//        memset(g_SingletonInstance, 0, 0x168);
//
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x38) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x40) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x88) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x90) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xD8) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0xE0) = 8;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x128) = 7;
//        *(uint64_t*)((uintptr_t)g_SingletonInstance + 0x130) = 8;
//
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x140), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x144), uint32_t(1));
//        std::atomic_store((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), uint32_t(1));
//    }
//
//    std::atomic_fetch_add((std::atomic<uint32_t>*)((uintptr_t)g_SingletonInstance + 0x148), 1);
//
//    return;
//}
//
//int sceNpWebApiSendRequestHook(uint64_t param_1, int64_t param_2, int64_t param_3) {
//    return 0;
//}
//
//uint64_t sceNpWebApiGetHttpStatusCodeHook(uint64_t param_1, uint32_t* param_2) {
//    if (param_2 != nullptr) {
//        *param_2 = 200;
//        return 0;
//    }
//
//    return 0xFFFFFFFFFFFFFFFF;
//}
//
//uint64_t sceNpWebApiReadDataHook(uint64_t param_1, void* param_2, uint64_t param_3) {
//
//    if (param_2 == nullptr || param_3 == 0) {
//        return 0;
//    }
//    memset(param_2, 0, param_3);
//
//    return param_3;
//}

void memcpy_p(unsigned long Address, const void* Data, unsigned long Length)
{
    if (!Address || !Length)
    {
        printf("No target (0x%lx) or length (%li) provided!\n", Address, Length);
        return;
    }
    sceKernelMprotect((void*)Address, Length, 0x7);
    memcpy((void*)Address, Data, Length);
}

void WriteJump(void* target, void* replacement)
{
    unsigned char jump[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    *(uint64_t*)(jump + 6) = (uint64_t)replacement;

    memcpy_p((unsigned long)target, jump, sizeof(jump));
}

bool ApplyDirectHooks()
{
    struct DirectHook {
        unsigned long address;
        void* hookFunction;
        void** originalFunction;
        const char* description;
    };

    DirectHook directHooks[] = {
		{0x2B41240, (void*)sceNpCheckNpAvailabilityhook, (void**)&sceNpCheckNpAvailabilityOriginal, "sceNpCheckNpAvailability"},
		{0x2B40ED0, (void*)sceNpGetStateHook, (void**)&sceNpGetStateOriginal, "sceNpGetState"},
		{0x2B40EE0, (void*)sceNpGetOnlineIdHook, (void**)&sceNpGetOnlineIdOriginal, "sceNpGetOnlineId"},
		{0x2B40ef0, (void*)sceNpGetAccountIdHook, (void**)&sceNpGetAccountIdOriginal, "sceNpGetAccountId"},
		{0x2B410a0, (void*)sceNpRegisterStateCallbackHook, (void**)&sceNpRegisterStateCallbackOriginal, "sceNpRegisterStateCallback"},
		{0x2B410b0, (void*)sceNpRegisterGamePresenceCallbackHook, (void**)&sceNpRegisterGamePresenceCallbackOriginal, "sceNpRegisterGamePresenceCallback"},
		{0x2B410d0, (void*)sceUserServiceGetEventHook, (void**)&sceUserServiceGetEventOriginal, "sceUserServiceGetEvent"},
		{0x2B41230, (void*)sceNpGetGamePresenceStatusHook, (void**)&sceNpGetGamePresenceStatusOriginal, "sceNpGetGamePresenceStatus"},
		{0x2B41360, (void*)sceCommonDialogInitializeHook, (void**)&sceCommonDialogInitializeOriginal, "sceCommonDialogInitialize"},
		{0x2B41640, (void*)sceNpGetNpIdHook, (void**)&sceNpGetNpIdOriginal, "sceNpGetNpId"},
		//{0x2B41610, (void*)sceNpWebApiUtilityParseNpIdHook, (void**)&sceNpWebApiUtilityParseNpIdOriginal, "sceNpWebApiUtilityParseNpId"},
		{0x2B41250, (void*)sceNpAuthCreateAsyncRequestHook, (void**)&sceNpAuthCreateAsyncRequestOriginal, "sceNpAuthCreateAsyncRequest"},
		{0x2B41200, (void*)sceNpCreateAsyncRequestHook, (void**)&sceNpCreateAsyncRequestOriginal, "sceNpCreateAsyncRequest"},
		{0x2B412B0, (void*)sceNpPollAsyncHook, (void**)&sceNpPollAsyncOriginal, "sceNpPollAsync"},
		{0x2B412C0, (void*)sceNpAuthPollAsyncHook, (void**)&sceNpAuthPollAsyncOriginal, "sceNpAuthPollAsync"},
		{0x2B41260, (void*)sceNpAuthGetAuthorizationCodeHook, (void**)&sceNpAuthGetAuthorizationCodeOriginal, "sceNpAuthGetAuthorizationCode"},
		{0x2B41070, (void*)sceNpCommerceDialogInitializeHook, (void**)&sceNpCommerceDialogInitializeOriginal, "sceNpCommerceDialogInitialize"},
		{0x2B41080, (void*)sceNpCommerceDialogOpenHook, (void**)&sceNpCommerceDialogOpenOriginal, "sceNpCommerceDialogOpen"},
		{0x2B412F0, (void*)sceNpCommerceDialogUpdateStatus_hook, (void**)&sceNpCommerceDialogUpdateStatusOriginal, "sceNpCommerceDialogUpdateStatus"},
		{0x2B41380, (void*)sceNpCommerceDialogTerminateHook, (void**)&sceNpCommerceDialogTerminateOriginal, "sceNpCommerceDialogTerminate"},
		{0x2B41300, (void*)sceNpCommerceDialogGetResultHook, (void**)&sceNpCommerceDialogGetResultOriginal, "sceNpCommerceDialogGetResult"},
		{0x2B41390, (void*)sceNpCommerceShowPsStoreIconHook, (void**)&sceNpCommerceShowPsStoreIconOriginal, "sceNpCommerceShowPsStoreIcon"},
		{0x2B413A0, (void*)sceNpCommerceHidePsStoreIconHook, (void**)&sceNpCommerceHidePsStoreIconOriginal, "sceNpCommerceHidePsStoreIcon"},
		{0x2B41320, (void*)sceNpBandwidthTestInitStartHook, (void**)&sceNpBandwidthTestInitStartOriginal, "sceNpBandwidthTestInitStart"},
		{0x2B41310, (void*)sceNpBandwidthTestGetStatusHook, (void**)&sceNpBandwidthTestGetStatusOriginal, "sceNpBandwidthTestGetStatus"},
		{0x2B40F70, (void*)sceNpBandwidthTestShutdownHook, (void**)&sceNpBandwidthTestShutdownOriginal, "sceNpBandwidthTestShutdown"},
		{0x2B41210, (void*)sceNpGetParentalControlInfoHook, (void**)&sceNpGetParentalControlInfoOriginal, "sceNpGetParentalControlInfo"},
		{0x2B412A0, (void*)sceNpCheckPlusHook, (void**)&sceNpCheckPlusOriginal, "sceNpCheckPlus"},
		{0x2B40EB0, (void*)sceNpSetContentRestrictionHook, (void**)&sceNpSetContentRestrictionOriginal, "sceNpSetContentRestriction"},
		{0x2B41280, (void*)sceNpGetAccountCountryHook, (void**)&sceNpGetAccountCountryOriginal, "sceNpGetAccountCountry"},
		{0x2B41290, (void*)sceNpGetAccountDateOfBirthHook, (void**)&sceNpGetAccountDateOfBirthOriginal, "sceNpGetAccountDateOfBirth"},
		{0x2B41650, (void*)sceNpWordFilterCreateTitleCtxA_hook, (void**)&sceNpWordFilterCreateTitleCtxOriginal, "sceNpWordFilterCreateTitleCtx"},
		{0x2B41660, (void*)sceNpWordFilterCreateAsyncRequestHook, (void**)&sceNpWordFilterCreateAsyncRequestOriginal, "sceNpWordFilterCreateAsyncRequest"},
		{0x2B41670, (void*)sceNpWordFilterSanitizeCommentHook, (void**)&sceNpWordFilterSanitizeCommentOriginal, "sceNpWordFilterSanitizeComment"},
		{0x2B41680, (void*)sceNpWordFilterPollAsyncHook, (void**)&sceNpWordFilterPollAsyncOriginal, "sceNpWordFilterPollAsync"},
		//{0x2B415C0, (void*)sceNpWebApiRegisterServicePushEventCallbackHook, (void**)&sceNpWebApiRegisterServicePushEventCallbackOriginal, "sceNpWebApiRegisterServicePushEventCallback"},
		//{0x2B41000, (void*)sceNpWebApiUnregisterServicePushEventCallbackHook, (void**)&sceNpWebApiUnregisterServicePushEventCallbackOriginal, "sceNpWebApiUnregisterServicePushEventCallback"},
		//{0x2B41560, (void*)sceNpWebApiCreatePushEventFilterHook, (void**)&sceNpWebApiCreatePushEventFilterOriginal, "sceNpWebApiCreatePushEventFilter"},
		//{0x2B41010, (void*)sceNpWebApiDeletePushEventFilterHook, (void**)&sceNpWebApiDeletePushEventFilterOriginal, "sceNpWebApiDeletePushEventFilter"},
		//{0x2B415B0, (void*)sceNpWebApiCreateServicePushEventFilterHook, (void**)&sceNpWebApiCreateServicePushEventFilterOriginal, "sceNpWebApiCreateServicePushEventFilter"},
		//{0x2B41590, (void*)sceNpWebApiDeleteServicePushEventFilterHook, (void**)&sceNpWebApiDeleteServicePushEventFilterOriginal, "sceNpWebApiDeleteServicePushEventFilter"},
		//{0x2B41570, (void*)sceNpWebApiRegisterPushEventCallbackHook, (void**)&sceNpWebApiRegisterPushEventCallbackOriginal, "sceNpWebApiRegisterPushEventCallback"},
		//{0x2B41580, (void*)sceNpWebApiCreateRequestHook, (void**)&sceNpWebApiCreateRequestOriginal, "sceNpWebApiCreateRequest"},
		//{0x2B415D0, (void*)sceNpWebApiDeleteRequestHook, (void**)&sceNpWebApiDeleteRequestOriginal, "sceNpWebApiDeleteRequest"},
		//{0x2B415A0, (void*)sceNpWebApiCreateHandleHook, (void**)&sceNpWebApiCreateHandleOriginal, "sceNpWebApiCreateHandle"},
		//{0x2B415E0, (void*)sceNpWebApiSendRequestHook, (void**)&sceNpWebApiSendRequestOriginal, "sceNpWebApiSendRequest"},
		//{0x2B415F0, (void*)sceNpWebApiGetHttpStatusCodeHook, (void**)&sceNpWebApiGetHttpStatusCodeOriginal, "sceNpWebApiGetHttpStatusCode"},
		//{0x2B41600, (void*)sceNpWebApiReadDataHook, (void**)&sceNpWebApiReadDataOriginal, "sceNpWebApiReadData"},
	};


    for (auto& hook : directHooks) {
        if (hook.address != 0) {
            WriteJump((void*)hook.address, hook.hookFunction);
            printf("Direct hook applied to 0x%lx: %s\n", hook.address, hook.description);
        }
    }

    return true;
}

void* main_thread(void*)
{
    sceKernelUsleep(10 * 1000);

    //https patches
    //memcpy_p(0x2C045B4, "\x68\x74\x74\x70\x00\x00", 6);
    //memcpy_p(0x2C0D09B, "\x68\x74\x74\x70\x00\x00", 6);
    //memcpy_p(0x2C0D7FE, "\x68\x74\x74\x70\x3A\x2F\x2F\x00\x00", 9);
    //memcpy_p(0x2C3889C, "\x68\x74\x74\x70\x3A\x2F\x2F\x00\x00", 9);
    //memcpy_p(0x2C1047E, "\x68\x74\x74\x70\x3A\x2F\x2F\x25\x73\x00\x00", 11);
    //memcpy_p(0x2C0EFC6, "\x68\x74\x74\x70\x3A\x2F\x2F\x25\x73\x2F\x25\x73\x00\x00", 14);
    //memcpy_p(0x2C0DF11, "\x68\x74\x74\x70\x3A\x2F\x2F\x00\x00", 9);
    //memcpy_p(0x2C0D7FE, "\x68\x74\x74\x70\x3A\x2F\x2F\x00\x00", 9);
    //memcpy_p(0x2C0EF9B, "\x68\x74\x74\x70\x3A\x2F\x2F\x70\x72\x6F\x64\x2E\x25\x73\x2F\x25\x73\x00\x00", 19);
    //memcpy_p(0x2C131F2, "\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E\x00\x00", 13);

    ////remove auth-
    //memcpy_p(0x2C0F8D4, "\x25\x73\x00\x00\x00\x00\x00\x00", 8);

    //memcpy_p(0x2C0FA32, "\x72\x6F\x73\x2E\x70\x61\x72\x61\x64\x69\x73\x65\x73\x70\x72\x78\x2E\x65\x73\x00\x00\x00", 22);
    //memcpy_p(0x1E85A85, "\xBE\x00\x00\x00\x00", 5); //0000000001A85A85
    //memcpy_p(0x19314C8, "\x41\xB8\x43\x03\x00\x00", 6); //15314C8

	//memcpy_p(0x2C39CD4, "\x25\x73\x2D\x25\x73\x00\x00\x00\x00\x00\x00", 11);
	//memcpy_p(0x190B8A0, "\xB0\x01\xC3", 3);

    if (ApplyDirectHooks()) {
        sceSysUtilSendSystemNotificationWithText(222, "hooked successfully!");
    }
    else {
		sceSysUtilSendSystemNotificationWithText(222, "hooking failed!");
    }

    scePthreadExit(0);
    return nullptr;
}

pthread_t threadid;
extern "C" int module_start(size_t args, const void* argp)
{
    int sysutil = sceKernelLoadStartModule("libSceSysUtil.sprx", 0, NULL, 0, 0, 0);
    orbis_syscall(591, sysutil, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0);
    pthread_create(&threadid, NULL, main_thread, NULL);

    return SCE_OK;
}

extern "C" int module_stop(size_t args, const void* argp)
{
    return SCE_OK;
}