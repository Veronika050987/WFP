#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <locale.h>

#pragma comment(lib, "fwpuclnt.lib")

#define EXIT_ON_ERROR(fnName)\
	if(result != ERROR_SUCCESS)\
	{\
		printf(#fnName " = 0x%08x\n", result);\
		goto CLEANUP;\
	}

// GUID для провайдера.
const GUID PROVIDER_KEY =
{
    0x5fb216a8,
    0xe2e8,
    0x4024,
    {0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

// GUID для подслоя.
const GUID SUBLAYER_KEY_PORT_REDIRECT =
{
    0xc551d347,
    0xf563,
    0x4b7f,
    {0xb7, 0x41, 0x77, 0x96, 0xe7, 0x24, 0x4f, 0x20 }
};

#define SESSION_NAME L"SDK Examples Port Redirect"

// GUIDs для правил NAT
const GUID NAT_RULE_KEY_4500_TO_450 =
{
    0x11111111, 0x2222, 0x3333, {0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
};

const GUID NAT_RULE_KEY_500_TO_50 =
{
    0xcccccccc, 0xdddd, 0xeeee, {0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
};

// GUIDs для фильтров, которые будут использовать правила NAT
const GUID FILTER_KEY_4500_TO_450 =
{
    0xc0e1d2f3,
    0xa4b5,
    0x6c7d,
    {0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f}
};

const GUID FILTER_KEY_500_TO_50 =
{
    0x12345678,
    0xabcd,
    0xef01,
    {0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf0}
};

DWORD InstallProviderAndSublayer
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
    sublayer.weight = 0x8000;

    result = FwpmSubLayerAdd0(engine, &sublayer, NULL);
    if (result != FWP_E_ALREADY_EXISTS)EXIT_ON_ERROR(FwpmSubLayerAdd0);

    result = FwpmTransactionCommit0(engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
    FwpmEngineClose0(engine);

    return result;
}

DWORD UninstallProviderAndSublayer
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

DWORD AddPortRedirectNATRule
(
    __in HANDLE engine,
    __in const GUID* natRuleKey,
    __in UINT16 currentPort,
    __in UINT16 redirectPort,
    __in const GUID* subLayerKey
)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_NAT_ENTRY2 natEntry; // Используем FWPM_NAT_ENTRY2
    FWPM_NAT_TRANSFORM_V4 transform;

    memset(&natEntry, 0, sizeof(natEntry));
    natEntry.natEntryKey = *natRuleKey;
    natEntry.providerKey = PROVIDER_KEY;
    natEntry.subLayerKey = *subLayerKey;
    natEntry.flags = FWPM_NAT_ENTRY_FLAG_ENABLE;

    // Указываем тип NAT: FWPM_NAT_TYPE_INBOUND для перенаправления входящего трафика
    natEntry.natType = FWPM_NAT_TYPE_INBOUND;

    // Настройка оригинальной информации
    memset(&transform, 0, sizeof(transform));
    transform.port = currentPort;
    transform.address.type = FWPM_IP_TYPE_V4; // IPv4
    // transform.address.addrV4.value = 0; // 0 означает использовать исходный IP-адрес

    natEntry.originalTransform = transform;

    // Настройка переведенной информации
    memset(&transform, 0, sizeof(transform));
    transform.port = redirectPort;
    transform.address.type = FWPM_IP_TYPE_V4; // IPv4
    transform.address.addrV4.value = 0; // 0 означает использовать исходный IP-адрес

    natEntry.translatedTransform = transform;

    result = FwpmNatAdd2(engine, &natEntry, NULL); // Используем FwpmNatAdd2
    if (result != FWP_E_ALREADY_EXISTS)
    {
        EXIT_ON_ERROR(FwpmNatAdd2);
    }

    return result;
}

DWORD RemovePortRedirectNATRule
(
    __in HANDLE engine,
    __in const GUID* natRuleKey
)
{
    DWORD result = ERROR_SUCCESS;

    result = FwpmNatDeleteByKey0(engine, natRuleKey);
    if (result != FWP_E_NAT_ENTRY_NOT_FOUND)
    {
        EXIT_ON_ERROR(FwpmNatDeleteByKey0);
    }

    return result;
}

DWORD AddFilterForNATRule
(
    __in HANDLE engine,
    __in const GUID* filterKey,
    __in UINT16 portToFilter,
    __in const GUID* natRuleKey, // Не используется напрямую для связи, но полезно для идентификации
    __in const GUID* subLayerKey
)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 condition;

    memset(&filter, 0, sizeof(filter));
    filter.filterKey = *filterKey;
    filter.displayData.name = (PWSTR)L"Filter for NAT";
    filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4; // Слой для входящих транспортных пакетов
    filter.subLayerKey = *subLayerKey;
    filter.weight = 100;

    // Настройка условия: пакеты, идущие на конкретный порт
    memset(&condition, 0, sizeof(condition));
    condition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT; // Проверяем локальный порт
    condition.matchType = FWPM_MATCH_EQUAL;
    condition.u.port.range.start = portToFilter;
    condition.u.port.range.end = portToFilter;

    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;

    // Действие фильтра - разрешить пакету пройти, чтобы WFP мог применить NAT правило
    filter.action.type = FWPM_ACTION_PERMIT;

    result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    if (result != FWP_E_ALREADY_EXISTS)
    {
        EXIT_ON_ERROR(FwpmFilterAdd0);
    }

    return result;
}

DWORD RemoveFilterForNATRule
(
    __in HANDLE engine,
    __in const GUID* filterKey
)
{
    DWORD result = ERROR_SUCCESS;

    result = FwpmFilterDeleteByKey0(engine, filterKey);
    if (result != FWP_E_FILTER_NOT_FOUND)
    {
        EXIT_ON_ERROR(FwpmFilterDeleteByKey0);
    }

    return result;
}


void main()
{
    using namespace std;
    setlocale(LC_ALL, "");

    DWORD result = ERROR_SUCCESS;
    HANDLE engine = NULL;
    FWPM_SESSION0 session;

    // 1. Установка провайдера и подслоя
    wcout << L"Установка провайдера и подслоя..." << endl;
    result = InstallProviderAndSublayer(
        &PROVIDER_KEY,
        L"Port Redirect Provider",
        &SUBLAYER_KEY_PORT_REDIRECT,
        L"Port Redirect Sublayer"
    );
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        wcout << L"Ошибка при установке провайдера/подслоя: 0x" << hex << result << endl;
        return;
    }
    wcout << L"Провайдер и подслой установлены." << endl;

    // Открытие движка WFP для добавления правил
    memset(&session, 0, sizeof(session));
    session.displayData.name = (wchar_t*)SESSION_NAME;
    session.txnWaitTimeoutInMSec = INFINITE;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_CLOUD_AP, NULL, &session, &engine);
    EXIT_ON_ERROR(FwpmEngineOpen0);

    // 2. Добавление правил NAT и соответствующих фильтров
    wcout << L"Добавление правил NAT и фильтров..." << endl;

    // --- Перенаправление 4500 -> 450 ---
    // Правило NAT
    result = AddPortRedirectNATRule(
        engine,
        &NAT_RULE_KEY_4500_TO_450,
        4500, // Текущий порт
        450,  // Порт назначения
        &SUBLAYER_KEY_PORT_REDIRECT
    );
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        wcout << L"Ошибка при добавлении правила NAT 4500->450: 0x" << hex << result << endl;
        goto CLEANUP;
    }
    wcout << L"Правило NAT 4500->450 добавлено." << endl;

    // Фильтр для этого правила NAT
    result = AddFilterForNATRule(
        engine,
        &FILTER_KEY_4500_TO_450,
        4500, // Порт, который будет проверять фильтр
        &NAT_RULE_KEY_4500_TO_450,
        &SUBLAYER_KEY_PORT_REDIRECT
    );
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        wcout << L"Ошибка при добавлении фильтра для NAT 4500->450: 0x" << hex << result << endl;
        goto CLEANUP;
    }
    wcout << L"Фильтр для NAT 4500->450 добавлен." << endl;


    // --- Перенаправление 500 -> 50 ---
    // Правило NAT
    result = AddPortRedirectNATRule(
        engine,
        &NAT_RULE_KEY_500_TO_50,
        500,  // Текущий порт
        50,   // Порт назначения
        &SUBLAYER_KEY_PORT_REDIRECT
    );
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        wcout << L"Ошибка при добавлении правила NAT 500->50: 0x" << hex << result << endl;
        goto CLEANUP;
    }
    wcout << L"Правило NAT 500->50 добавлено." << endl;

    // Фильтр для этого правила NAT
    result = AddFilterForNATRule(
        engine,
        &FILTER_KEY_500_TO_50,
        500, // Порт, который будет проверять фильтр
        &NAT_RULE_KEY_500_TO_50,
        &SUBLAYER_KEY_PORT_REDIRECT
    );
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        wcout << L"Ошибка при добавлении фильтра для NAT 500->50: 0x" << hex << result << endl;
        goto CLEANUP;
    }
    wcout << L"Фильтр для NAT 500->50 добавлен." << endl;


    wcout << L"Перенаправление портов успешно настроено." << endl;

    // Здесь можно добавить код для ожидания, если нужно, чтобы правила действовали
    // Например, cin.get();

    // 3. Удаление правил NAT и фильтров (если нужно)
    // Раскомментируйте следующий блок, если хотите удалить правила при завершении.
    /*
    wcout << L"Удаление правил NAT и фильтров..." << endl;

    result = RemoveFilterForNATRule(engine, &FILTER_KEY_4500_TO_450);
    if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
        wcout << L"Ошибка при удалении фильтра для NAT 4500->450: 0x" << hex << result << endl;
    } else {
        wcout << L"Фильтр для NAT 4500->450 удален." << endl;
    }

    result = RemovePortRedirectNATRule(engine, &NAT_RULE_KEY_4500_TO_450);
    if (result != ERROR_SUCCESS && result != FWP_E_NAT_ENTRY_NOT_FOUND) {
        wcout << L"Ошибка при удалении правила NAT 4500->450: 0x" << hex << result << endl;
    } else {
        wcout << L"Правило NAT 4500->450 удалено." << endl;
    }

    result = RemoveFilterForNATRule(engine, &FILTER_KEY_500_TO_50);
    if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
        wcout << L"Ошибка при удалении фильтра для NAT 500->50: 0x" << hex << result << endl;
    } else {
        wcout << L"Фильтр для NAT 500->50 удален." << endl;
    }

    result = RemovePortRedirectNATRule(engine, &NAT_RULE_KEY_500_TO_50);
    if (result != ERROR_SUCCESS && result != FWP_E_NAT_ENTRY_NOT_FOUND) {
        wcout << L"Ошибка при удалении правила NAT 500->50: 0x" << hex << result << endl;
    } else {
        wcout << L"Правило NAT 500->50 удалено." << endl;
    }

    wcout << L"Перенаправление портов удалено." << endl;
    */

    // 4. Удаление провайдера и подслоя (если нужно)
    // Раскомментируйте следующий блок, если хотите удалить провайдер/подслой.
    /*
    wcout << L"Удаление провайдера и подслоя..." << endl;
    result = UninstallProviderAndSublayer(
        &PROVIDER_KEY,
        &SUBLAYER_KEY_PORT_REDIRECT
    );
    if (result != ERROR_SUCCESS && result != FWP_E_PROVIDER_NOT_FOUND && result != FWP_E_SUBLAYER_NOT_FOUND) {
        wcout << L"Ошибка при удалении провайдера/подслоя: 0x" << hex << result << endl;
    } else {
        wcout << L"Провайдер и подслой удалены." << endl;
    }
    */

CLEANUP:
    if (engine) {
        FwpmEngineClose0(engine);
    }
}