#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      goto CLEANUP; \
   }

DWORD EnableLooseSourceMapping(
    __in HANDLE engine,
    __in PCWSTR provCtxtName,
    __in PCWSTR filterName,
    __in_opt const GUID* providerKey,
    __in_opt const GUID* subLayerKey,
    __in UINT16 port
)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_CLASSIFY_OPTION0 option;
    FWPM_CLASSIFY_OPTIONS0 options;
    FWPM_PROVIDER_CONTEXT0 provCtxt;
    FWPM_FILTER_CONDITION0 conds[2];
    FWPM_FILTER0 filter;
    BOOL txnInProgress = FALSE;

    //////////
    // Loose source mapping is controlled through classify options, so first
    // you add a provider context with the desired option value.
    //////////

    option.type = FWP_CLASSIFY_OPTION_LOOSE_SOURCE_MAPPING;
    option.value.type = FWP_UINT32;
    option.value.uint32 = FWP_OPTION_VALUE_ENABLE_LOOSE_SOURCE;

    options.numOptions = 1;
    options.options = &option;

    memset(&provCtxt, 0, sizeof(provCtxt));
    // You have to assign the key yourself since you'll need it when adding 
    // the filters that reference this provider context.
    result = UuidCreate(&(provCtxt.providerContextKey));
    EXIT_ON_ERROR(UuidCreate);
    // For MUI compatibility, object names should be indirect strings. See
    // SHLoadIndirectString for details.
    provCtxt.displayData.name = (PWSTR)provCtxtName;
    // Link all objects to your provider. When multiple providers are
    // installed on a computer, this makes it easy to determine who added what.
    provCtxt.providerKey = (GUID*)providerKey;
    provCtxt.type = FWPM_CLASSIFY_OPTIONS_CONTEXT;
    provCtxt.classifyOptions = &options;

    // Add all the objects from within a single transaction to make it easy
    // to clean up partial results in error paths.
    result = FwpmTransactionBegin0(engine, 0);
    EXIT_ON_ERROR(FwpmTransactionBegin0);
    txnInProgress = TRUE;

    result = FwpmProviderContextAdd0(engine, &provCtxt, NULL, NULL);
    EXIT_ON_ERROR(FwpmProviderContextAdd0);

    //////////
    // Next, add filters at the ALE_AUTH_CONNECT layers that reference the
    // provider context.
    //////////

    // First condition matches UDP traffic only.
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint16 = IPPROTO_UDP;

    // Second condition matches the remote port.
    conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = port;

    // Fill in the common fields shared by all filters.
    memset(&filter, 0, sizeof(filter));
    filter.displayData.name = (PWSTR)filterName;
    // Filters can have either a raw context (which is a UINT64) or a
    // provider context. If using the latter, you have to set the
    // appropriate flag.
    filter.flags = FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
    filter.providerKey = (GUID*)providerKey;
    // Generally, it's best to add filters to your own sublayer, so you don't have
    // to worry about being overridden by filters added by another provider.
    if (subLayerKey != NULL)
    {
        filter.subLayerKey = *subLayerKey;
    }
    filter.numFilterConditions = 2;
    filter.filterCondition = conds;
    // The set options callouts never return permit or block, so they're
    // inspection callouts.
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    // Link the filter to the provider context we just added. Note that multiple
    // filters can reference a single provider context, so once you've added a
    // provider context to enable LSM, you can use it over and over again.
    filter.providerContextKey = provCtxt.providerContextKey;

    // Add the IPv4 filter.
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.calloutKey = FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4;
    result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    EXIT_ON_ERROR(FwpmFilterAdd0);

    // Add the IPv6 filter.
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.action.calloutKey = FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6;
    result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    EXIT_ON_ERROR(FwpmFilterAdd0);

    // Once all the adds have succeeded, commit the transaction to atomically
    // add all the new objects.
    result = FwpmTransactionCommit0(engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);
    txnInProgress = FALSE;

CLEANUP:
    if (txnInProgress)
    {
        // Abort any transaction still in progress to clean up partial results.
        FwpmTransactionAbort0(engine);
    }
    return result;
}