#include<iostream>
#include<Windows.h>
#include<fwpmu.h>
#include<stdio.h>
//Filtering traffic
#include<AccCtrl.h>
#include<AclAPI.h>

#pragma comment(lib, "fwpuclnt.lib")
//Filtering traffic
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
	sublayer.weight = 0x8000;

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

void main()
{
	using namespace std;
	setlocale(LC_ALL, "");
}