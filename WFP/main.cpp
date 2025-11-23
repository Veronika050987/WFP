#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <AccCtrl.h>
#include <AclAPI.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "advapi32.lib")


#define EXIT_ON_ERROR(fnName)\
	if(result != ERROR_SUCCESS)\
	{\
		printf(#fnName " = 0x%08x\n", result);\
		goto CLEANUP;\
	}

// 5fb216a8-e2e8-4024-b853-391a4168641e
const GUID PROVIDER_KEY =
{
    0x5fb216a8,
    0xe2e8,
    0x4024,
    {0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

#define SESSION_NAME "SDK Examples"

// GUIDs for the sublayers (you can generate your own or use placeholders)
const GUID SUBLAYER_NAT_4500_TO_450_KEY = { 0x12345678, 0x1111, 0x2222, {0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA} };
const GUID SUBLAYER_NAT_500_TO_50_KEY = { 0xABCD1234, 0x5555, 0x6666, {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE} };


DWORD Install
(
    __in const GUID* providerKey,
    __in PCWSTR providerName,
    __in const GUID* subLayerKey,
    __in PCWSTR subLayerName
)
{
    DWORD result = ERROR_SUCCESS;
    HANDLE engine = NULL;
    FWPM_SESSION0 session;
    FWPM_PROVIDER0 provider;
    FWPM_SUBLAYER0 sublayer;

    memset(&session, 0, sizeof(session));
    session.displayData.name = (wchar_t*)SESSION_NAME;
    session.txnWaitTimeoutInMSec = INFINITE;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_CLOUD_AP, NULL, &session, &engine);
    EXIT_ON_ERROR(FwpmEngineOpen0);

    result = FwpmTransactionBegin0(engine, 0);
    EXIT_ON_ERROR(FwpmTransactionBegin0);

    memset(&provider, 0, sizeof(provider));
    provider.providerKey = *providerKey;
    provider.displayData.name = (PWSTR)providerName;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    result = FwpmProviderAdd0(engine, &provider, NULL);
    if (result != FWP_E_ALREADY_EXISTS)EXIT_ON_ERROR(FwpmProviderAdd0);

    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = *subLayerKey;
    sublayer.displayData.name = (PWSTR)subLayerName;
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = (GUID*)providerKey;
    sublayer.weight = 0x8000; // Example weight, adjust as needed

    result = FwpmSubLayerAdd0(engine, &sublayer, NULL);
    if (result != FWP_E_ALREADY_EXISTS)EXIT_ON_ERROR(FwpmSubLayerAdd0);
    result = FwpmTransactionCommit0(engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
    FwpmEngineClose0(engine);

    return result;
}

DWORD Uninstall
(
    __in const GUID* providerKey,
    __in const GUID* subLayerKey
)
{
    DWORD result = ERROR_SUCCESS;
    HANDLE engine = NULL;
    FWPM_SESSION session;

    memset(&session, 0, sizeof(session));
    session.displayData.name = (wchar_t*)SESSION_NAME;
    session.txnWaitTimeoutInMSec = INFINITE;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &engine);
    EXIT_ON_ERROR(FwpmEngineOpen0);

    result = FwpmTransactionBegin0(engine, 0);
    EXIT_ON_ERROR(FwpmTransactionBegin0);

    result = FwpmSubLayerDeleteByKey0(engine, subLayerKey);
    if (result != FWP_E_SUBLAYER_NOT_FOUND)EXIT_ON_ERROR(FwpmSubLayerDeleteByKey);

    result = FwpmProviderDeleteByKey0(engine, providerKey);
    if (result != FWP_E_PROVIDER_NOT_FOUND)EXIT_ON_ERROR(FwpmProviderDeleteByKey0);

    result = FwpmTransactionCommit0(engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
    FwpmEngineClose0(engine);

    return result;
}

// Function to add NAT rules for port translation
DWORD AddNatRule(
    __in HANDLE engine,
    __in const GUID* subLayerKey,
    __in UINT16 portToTranslate,
    __in UINT16 translatedPort,
    __in PCWSTR ruleName
)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_FILTER0 filter;
    FWPM_ACTION0 action;
    FWPM_CONDITION0 condition; // Корректно объявлена здесь
    // FWPM_IP_VERSION_KEYWORD_VALUE ipVersion = FWPM_IP_VERSION_ANY; // Удалено
    // FWPM_SERVICE_MAIN_MENU_KEYWORD_VALUE service = FWPM_SERVICE_TCP; // Удалено

    memset(&filter, 0, sizeof(filter));
    filter.subLayerKey = *subLayerKey;
    filter.displayData.name = (PWSTR)ruleName;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // Для исходящих TCP-подключений.
    // Для UDP может потребоваться другой слой.
    filter.action.type = FWPM_ACTION_PERMIT; // Будет переопределено NAT

    // Condition for the specific port
    memset(&condition, 0, sizeof(condition));
    condition.fieldKey = FWPM_CONDITION_PORT;
    condition.op = FWPM_CONDITION_OP_EQUAL;
    condition.type = FWPM_CONDITION_TYPE_UINT16;
    condition.value.uint16 = portToTranslate;
    filter.numConditions = 1;
    filter.conditions = &condition;

    // NAT Action
    memset(&action, 0, sizeof(action));
    action.type = FWPM_ACTION_NAT;
    FWPM_NAT_TRAVERSAL0 natTraversal;
    memset(&natTraversal, 0, sizeof(natTraversal));
    natTraversal.natDirection = FWPM_NAT_DIRECTION_OUTBOUND;
    natTraversal.localAddress.type = FWPM_IP_ADDRESS_TYPE_UNSPECIFIED;
    natTraversal.remoteAddress.type = FWPM_IP_ADDRESS_TYPE_UNSPECIFIED;
    natTraversal.localPort = translatedPort;
    natTraversal.remotePort = translatedPort;

    action.nat = &natTraversal;
    filter.action = action;

    result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS)
    {
        printf("Failed to add NAT rule for port %u to %u: 0x%08x\n", portToTranslate, translatedPort, result);
    }
    else if (result == FWP_E_ALREADY_EXISTS)
    {
        printf("NAT rule for port %u to %u already exists.\n", portToTranslate, translatedPort);
    }
    else
    {
        printf("Successfully added NAT rule for port %u to %u.\n", portToTranslate, translatedPort);
    }
    return result;
}

// Function to delete NAT rules for port translation
DWORD DeleteNatRule(
    __in HANDLE engine,
    __in const GUID* subLayerKey,
    __in UINT16 portToTranslate,
    __in PCWSTR ruleName
)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate;
    FWPM_FILTER0* filters = NULL;
    UINT32 numFilters = 0;

    memset(&enumTemplate, 0, sizeof(enumTemplate));
    enumTemplate.layerKey.age = 0; // Match any layer
    enumTemplate.layerKey.id = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // Specific layer for outbound NAT
    enumTemplate.subLayerKey = subLayerKey;
    enumTemplate.displayData.name = (PWSTR)ruleName;

    result = FwpmFilterEnumSummary0(engine, &enumTemplate, &filters, &numFilters);
    if (result == ERROR_SUCCESS && numFilters > 0)
    {
        for (UINT32 i = 0; i < numFilters; ++i)
        {
            // Find the filter that matches the port
            bool portMatch = false;
            for (UINT32 j = 0; j < filters[i].numConditions; ++j)
            {
                if (filters[i].conditions[j].fieldKey == FWPM_CONDITION_PORT &&
                    filters[i].conditions[j].type == FWPM_CONDITION_TYPE_UINT16 &&
                    filters[i].conditions[j].value.uint16 == portToTranslate)
                {
                    portMatch = true;
                    break;
                }
            }

            if (portMatch)
            {
                result = FwpmFilterDeleteById0(engine, filters[i].filterId);
                if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND)
                {
                    printf("Failed to delete NAT rule for port %u: 0x%08x\n", portToTranslate, result);
                }
                else if (result == FWP_E_FILTER_NOT_FOUND)
                {
                    printf("NAT rule for port %u not found for deletion.\n", portToTranslate);
                }
                else
                {
                    printf("Successfully deleted NAT rule for port %u.\n", portToTranslate);
                }
            }
        }
    }
    else if (result == FWP_E_NO_MORE_ITEMS)
    {
        printf("No NAT rules found for port %u.\n", portToTranslate);
    }
    else if (result != ERROR_SUCCESS)
    {
        printf("Error enumerating NAT filters: 0x%08x\n", result);
    }


    if (filters)
    {
        FwpmFreeMemory0((void**)&filters);
    }

    return result;
}

// Helper to create a display name for NAT rules
PCWSTR GetNatRuleName(UINT16 port, UINT16 translatedPort, LPWSTR buffer, SIZE_T bufferSize)
{
    swprintf_s(buffer, bufferSize, L"NAT %u to %u", port, translatedPort);
    return buffer;
}

void main()
{
    using namespace std;
    setlocale(LC_ALL, "");

    DWORD result = ERROR_SUCCESS;
    HANDLE engine = NULL;
    FWPM_SESSION0 session;

    // Initialize FWP engine
    memset(&session, 0, sizeof(session));
    session.displayData.name = (wchar_t*)SESSION_NAME;
    session.txnWaitTimeoutInMSec = INFINITE;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_CLOUD_AP, NULL, &session, &engine);
    EXIT_ON_ERROR(FwpmEngineOpen0);

    // --- Install Sublayers for NAT ---
    // Sublayer for translating port 4500 to 450
    result = Install(&PROVIDER_KEY, L"SDK Provider", &SUBLAYER_NAT_4500_TO_450_KEY, L"SDK NAT Sublayer 4500->450");
    EXIT_ON_ERROR(Install);

    // Sublayer for translating port 500 to 50
    result = Install(&PROVIDER_KEY, L"SDK Provider", &SUBLAYER_NAT_500_TO_50_KEY, L"SDK NAT Sublayer 500->50");
    EXIT_ON_ERROR(Install);

    // --- Add NAT Rules ---
    // Translate port 4500 to 450 (TCP)
    LPWSTR natRuleName1 = L"NAT Rule 4500 to 450 TCP";
    result = AddNatRule(engine, &SUBLAYER_NAT_4500_TO_450_KEY, 4500, 450, natRuleName1);
    EXIT_ON_ERROR(AddNatRule);

    // Translate port 4500 to 450 (UDP) - If needed, you'd need to create a separate sublayer or filter for UDP
    // For simplicity, we'll assume TCP here. You might need to adjust the FWPM_SERVICE_MAIN_MENU_KEYWORD_VALUE in AddNatRule.

    // Translate port 500 to 50 (TCP)
    LPWSTR natRuleName2 = L"NAT Rule 500 to 50 TCP";
    result = AddNatRule(engine, &SUBLAYER_NAT_500_TO_50_KEY, 500, 50, natRuleName2);
    EXIT_ON_ERROR(AddNatRule);

    // --- Keep the engine open for demonstration purposes ---
    // In a real application, you might have logic to handle when to uninstall.
    printf("NAT rules installed. Press Enter to uninstall...\n");
    cin.get();

    // --- Uninstall Sublayers and Rules ---
    // Delete NAT rules first
    printf("Deleting NAT rules...\n");

    // Delete rule for 4500 to 450
    result = DeleteNatRule(engine, &SUBLAYER_NAT_4500_TO_450_KEY, 4500, natRuleName1);
    if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
        printf("Error deleting NAT rule for 4500->450: 0x%08x\n", result);
    }
    else {
        printf("NAT rule for 4500->450 deleted or not found.\n");
    }

    // Delete rule for 500 to 50
    result = DeleteNatRule(engine, &SUBLAYER_NAT_500_TO_50_KEY, 500, natRuleName2);
    if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
        printf("Error deleting NAT rule for 500->50: 0x%08x\n", result);
    }
    else {
        printf("NAT rule for 500->50 deleted or not found.\n");
    }

    // Uninstall sublayers
    result = Uninstall(&PROVIDER_KEY, &SUBLAYER_NAT_4500_TO_450_KEY);
    EXIT_ON_ERROR(Uninstall);

    result = Uninstall(&PROVIDER_KEY, &SUBLAYER_NAT_500_TO_50_KEY);
    EXIT_ON_ERROR(Uninstall);

    printf("NAT rules and sublayers uninstalled successfully.\n");

CLEANUP:
    if (engine)
    {
        FwpmEngineClose0(engine);
    }
}