#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
// Filtering traffic
#include <AccCtrl.h>
#include <AclAPI.h>

#pragma comment(lib, "fwpuclnt.lib")
// Filtering traffic
#pragma comment(lib, "advapi32.lib")

#define EXIT_ON_ERROR(fnName)\
    if(result != ERROR_SUCCESS)\
    {\
        printf(#fnName " = 0x%08x\n", result);\
        goto CLEANUP;\
    }

// GUID для провайдера
// 5fb216a8-e2e8-4024-b853-391a4168641e
const GUID PROVIDER_KEY =
{
    0x5fb216a8,
    0xe2e8,
    0x4024,
    {0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

// GUID для подслоя
// {A1B2C3D4-E5F6-7890-1234-567890ABCDEF}
const GUID REDIRECT_SUBLAYER_KEY =
{
    0xA1B2C3D4,
    0xE5F6,
    0x7890,
    {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}
};

#define SESSION_NAME L"SDK Examples"
#define PROVIDER_NAME L"MyPortRedirectProvider"
#define REDIRECT_SUBLAYER_NAME L"PortRedirectSublayer"

// Функция для добавления фильтра перенаправления (без FWPM_INSTRUCTION0)
DWORD AddRedirectFilter(
    __in HANDLE engine,
    __in const GUID* filterKey,
    __in UINT16 remotePort,
    __in UINT16 newPort,
    __in const GUID* subLayerKey,
    __in const GUID* layerKey // Добавляем параметр для слоя
)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_FILTER0 filter;
    FWPM_ACTION0 action;
    FWPM_IP_TRANSACTION_SETTINGS0 ipTransactionSettings;
    FWPM_SRVC_OFFSET_INFO0 svcOffsetInfo;
    FWPM_FILTER_CONDITION0 condition;

    ZeroMemory(&filter, sizeof(filter));
    filter.filterKey = *filterKey;
    filter.layerKey = *layerKey; // Используем переданный слой
    filter.displayData.name = (PWSTR)L"Port Redirect Filter";
    filter.subLayerKey = *subLayerKey;
    filter.weight = 0; // Низший вес
    filter.action.type = FWPM_ACTION_PERMIT; // Разрешаем трафик после перенаправления

    // Настройка действия: перенаправление
    ZeroMemory(&action, sizeof(action));
    action.type = FWPM_ACTION_REDIRECT;

    // Структура для перенаправления TCP/UDP порта
    ZeroMemory(&ipTransactionSettings, sizeof(ipTransactionSettings));
    ipTransactionSettings.direction = FWPM_IP_TRANSACTION_DIRECTION_INBOUND; // Входящий трафик

    // Перенаправление UDP
    ZeroMemory(&svcOffsetInfo, sizeof(svcOffsetInfo));
    // Для UDP, мы можем указать порт назначения.
    svcOffsetInfo.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // Этот слой часто используется для UDP
    svcOffsetInfo.offset.type = FWPM_OFFSET_TYPE_PORT;
    svcOffsetInfo.offset.port.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // Для UDP
    svcOffsetInfo.offset.port.remotePort = remotePort;
    svcOffsetInfo.offset.port.newRemotePort = newPort;
    ipTransactionSettings.svcOffsetInfo = &svcOffsetInfo;
    ipTransactionSettings.numSvcOffsetInfo = 1;

    action.redirect.ipTransactionSettings = &ipTransactionSettings;
    // action.redirect.classifyOptions = NULL; // Нет необходимости в classifyOptions для простого перенаправления

    filter.action = action;

    // Условие: трафик на определенный удаленный порт
    ZeroMemory(&condition, sizeof(condition));
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition.op = FWPM_CONDITION_OP_EQUAL;
    condition.type = FWPM_CONDITION_TYPE_UINT16;
    condition.val.uint16 = remotePort;
    filter.numFilterConditions = 1;
    filter.filterConditions = &condition;

    // Добавляем фильтр
    result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    if (result != FWP_E_ALREADY_EXISTS)
    {
        EXIT_ON_ERROR(FwpmFilterAdd0);
    }

CLEANUP:
    return result;
}

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
    if (result != FWP_E_ALREADY_EXISTS) EXIT_ON_ERROR(FwpmProviderAdd0);

    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = *subLayerKey;
    sublayer.displayData.name = (PWSTR)subLayerName;
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = (GUID*)providerKey;
    sublayer.weight = 0x8000;

    result = FwpmSubLayerAdd0(engine, &sublayer, NULL);
    if (result != FWP_E_ALREADY_EXISTS) EXIT_ON_ERROR(FwpmSubLayerAdd0);
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
    if (result != FWP_E_SUBLAYER_NOT_FOUND) EXIT_ON_ERROR(FwpmSubLayerDeleteByKey);

    result = FwpmProviderDeleteByKey0(engine, providerKey);
    if (result != FWP_E_PROVIDER_NOT_FOUND) EXIT_ON_ERROR(FwpmProviderDeleteByKey0);

    result = FwpmTransactionCommit0(engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
    FwpmEngineClose0(engine);

    return result;
}

void main()
{
    using namespace std;
    setlocale(LC_ALL, "");

    DWORD result = ERROR_SUCCESS;
    HANDLE engine = NULL;
    FWPM_SESSION0 session;

    // Открываем WFP-движок
    memset(&session, 0, sizeof(session));
    session.displayData.name = (wchar_t*)SESSION_NAME;
    session.txnWaitTimeoutInMSec = INFINITE;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_CLOUD_AP, NULL, &session, &engine);
    EXIT_ON_ERROR(FwpmEngineOpen0);

    // Устанавливаем провайдер и подслой (если они еще не существуют)
    result = Install(&PROVIDER_KEY, PROVIDER_NAME, &REDIRECT_SUBLAYER_KEY, REDIRECT_SUBLAYER_NAME);
    EXIT_ON_ERROR(Install);

    // GUID для фильтров (нужно сгенерировать уникальные GUIDы для каждого фильтра)
    // {11111111-2222-3333-4444-555555555555}
    const GUID FILTER_REDIRECT_4500_TO_450_KEY =
    {
        0x11111111,
        0x2222,
        0x3333,
        {0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
    };

    // {22222222-3333-4444-5555-666666666666}
    const GUID FILTER_REDIRECT_500_TO_50_KEY =
    {
        0x22222222,
        0x3333,
        0x4444,
        {0x55, 0x55, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}
    };

    // Определяем слои для перенаправления.
    // FWPM_LAYER_ALE_AUTH_CONNECT_V4 - для исходящих подключений, которые авторизуются.
    // FWPM_LAYER_INBOUND_TRANSPORT_V4 - для входящего транспорта (TCP/UDP).
    // Для перенаправления ВХОДЯЩЕГО трафика, FWPM_LAYER_INBOUND_TRANSPORT_V4 является более подходящим.
    const GUID INBOUND_TRANSPORT_LAYER_V4 = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    const GUID INBOUND_TRANSPORT_LAYER_V6 = FWPM_LAYER_INBOUND_TRANSPORT_V6; // Если нужно для IPv6

    // Добавляем фильтры для перенаправления портов
    // Перенаправление 4500 -> 450
    result = AddRedirectFilter(engine, &FILTER_REDIRECT_4500_TO_450_KEY, 4500, 450, &REDIRECT_SUBLAYER_KEY, &INBOUND_TRANSPORT_LAYER_V4);
    EXIT_ON_ERROR(AddRedirectFilter);

    // Перенаправление 500 -> 50
    result = AddRedirectFilter(engine, &FILTER_REDIRECT_500_TO_50_KEY, 500, 50, &REDIRECT_SUBLAYER_KEY, &INBOUND_TRANSPORT_LAYER_V4);
    EXIT_ON_ERROR(AddRedirectFilter);

    printf("Port redirection rules installed successfully.\n");

CLEANUP:
    FwpmEngineClose0(engine);
}