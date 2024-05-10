#include "LibGlassboxie.h"
#include <windows.h>
#include <bcrypt.h>
#include <Userenv.h>
#include <strsafe.h>


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Userenv.lib")


static BOOL GetExtendHashName(
    _In_ const WCHAR SandboxName[],
    _Out_writes_(cchExtendHashName) WCHAR ExtendHashName[],
    _In_ SIZE_T cchExtendHashName)
{
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0,
        cbHash = 0,
        cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL;

    BOOL bSuccess = FALSE;
    __try
    {
        //open an algorithm handle
        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0)))
        {
            __leave;
        }

        //calculate the size of the buffer to hold the hash object
        if (!NT_SUCCESS(status = BCryptGetProperty(
            hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject,
            sizeof(DWORD),
            &cbData,
            0)))
        {
            __leave;
        }

        //allocate the hash object on the heap
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        if (NULL == pbHashObject)
        {
            __leave;
        }

        //calculate the length of the hash
        if (!NT_SUCCESS(status = BCryptGetProperty(
            hAlg,
            BCRYPT_HASH_LENGTH,
            (PBYTE)&cbHash,
            sizeof(DWORD),
            &cbData,
            0)))
        {
            __leave;
        }

        //allocate the hash buffer on the heap
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (NULL == pbHash)
        {
            __leave;
        }

        //create a hash
        if (!NT_SUCCESS(status = BCryptCreateHash(
            hAlg,
            &hHash,
            pbHashObject,
            cbHashObject,
            NULL,
            0,
            0)))
        {
            __leave;
        }


        //hash some data
        DWORD SandboxNameLength = (DWORD)wcslen(SandboxName);
        DWORD GlassboxieVersion = GLASSBOXIE_VERSION;

        if (!NT_SUCCESS(status = BCryptHashData(
            hHash,
            (PBYTE)&GlassboxieVersion,
            sizeof(DWORD),
            0)))
        {
            __leave;
        }

        if (!NT_SUCCESS(status = BCryptHashData(
            hHash,
            (PBYTE)&SandboxNameLength,
            sizeof(DWORD),
            0)))
        {
            __leave;
        }

        if (!NT_SUCCESS(status = BCryptHashData(
            hHash,
            (PBYTE)SandboxName,
            sizeof(WCHAR) * SandboxNameLength,
            0)))
        {
            __leave;
        }

        //close the hash
        if (!NT_SUCCESS(status = BCryptFinishHash(
            hHash,
            pbHash,
            cbHash,
            0)))
        {
            __leave;
        }

        for (SIZE_T i = 0; i < cchExtendHashName; i++)
        {
            const WCHAR HexChar[16] = {
                L'0', L'1', L'2', L'3',
                L'4', L'5', L'6', L'7',
                L'8', L'9', L'A', L'B',
                L'C', L'D', L'E', L'F' };
            if (i & 1)
            {
                ExtendHashName[i] = HexChar[pbHash[(i >> 1) % cbHash] & 0x0F];
            }
            else
            {
                ExtendHashName[i] = HexChar[pbHash[(i >> 1) % cbHash] >> 4];
            }
        }
        bSuccess = TRUE;
    }
    __finally
    {
        if (hAlg)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        if (hHash)
        {
            BCryptDestroyHash(hHash);
        }

        if (pbHashObject)
        {
            HeapFree(GetProcessHeap(), 0, pbHashObject);
        }

        if (pbHash)
        {
            HeapFree(GetProcessHeap(), 0, pbHash);
        }
    }
    return bSuccess;
}

static BOOL AllocateEnabledSecurityCapabilities(
    _Inout_ PSID_AND_ATTRIBUTES* pSecurityCapabilities,
    _In_reads_(CntCapabilities) WELL_KNOWN_SID_TYPE* EnabledCapabilities,
    _In_ SIZE_T CntCapabilities)
{
    PSID_AND_ATTRIBUTES SecurityCapabilities = NULL;
    BOOL bSuccess = FALSE;
    SecurityCapabilities = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(SID_AND_ATTRIBUTES) * CntCapabilities);

    if (!SecurityCapabilities)
        return FALSE;

    __try
    {
        for (SIZE_T i = 0; i < CntCapabilities; i++)
        {
            DWORD SidSize = SECURITY_MAX_SID_SIZE;
            SecurityCapabilities[i].Sid =
                HeapAlloc(GetProcessHeap(), 0, SECURITY_MAX_SID_SIZE);
            if (!SecurityCapabilities[i].Sid)
                __leave;
            if (!CreateWellKnownSid(
                EnabledCapabilities[i],
                NULL,
                SecurityCapabilities[i].Sid,
                &SidSize))
                __leave;
            SecurityCapabilities[i].Attributes = SE_GROUP_ENABLED;
        }

        *pSecurityCapabilities = SecurityCapabilities;
        bSuccess = TRUE;
    }
    __finally
    {
        if (!bSuccess)
        {
            for (SIZE_T i = 0; i < CntCapabilities; i++)
            {
                if (SecurityCapabilities[i].Sid)
                    HeapFree(GetProcessHeap(),
                        0,
                        SecurityCapabilities[i].Sid);
            }
            HeapFree(GetProcessHeap(), 0, SecurityCapabilities);
        }
    }
    return bSuccess;
}

static BOOL FreeSecurityCapabilities(
    _In_ _Frees_ptr_ PSID_AND_ATTRIBUTES SecurityCapabilities,
    _In_ SIZE_T CntCapabilities)
{
    BOOL bSuccess = TRUE;
    for (SIZE_T i = 0; i < CntCapabilities; i++)
    {
        if (SecurityCapabilities[i].Sid)
            bSuccess &= HeapFree(
                GetProcessHeap(), 0,
                SecurityCapabilities[i].Sid);
    }
    bSuccess &= HeapFree(GetProcessHeap(), 0, SecurityCapabilities);

    return bSuccess;
}

_Use_decl_annotations_
PGBIE GbieCreateSandbox(
    _In_ const WCHAR SandboxName[],
    DWORD dwCreationDisposition)
{

    BOOL bSuccess = FALSE;
    PGBIE pGbie = NULL;
    PSID pAppContainerSID = NULL;
    HANDLE hJobObject = NULL;

    WCHAR ExtendHashName[32];
    GetExtendHashName(SandboxName, ExtendHashName, _countof(ExtendHashName));

    // AppContainerName can be up to 64 characters in length. 
    WCHAR AppContainerName[APPCONTAINER_NAME_MAX] = L"Glassboxie - ";
    WCHAR AppContainerDisplayName[512] = L"Glassboxie - ";
    WCHAR JobObjectName[512] = L"Glassboxie JobObject - ";

    if (FAILED(StringCchCatNW(
        AppContainerName,
        _countof(AppContainerName),
        ExtendHashName,
        _countof(ExtendHashName))))
        return FALSE;

    if (FAILED(StringCchCatW(
        AppContainerDisplayName,
        _countof(AppContainerDisplayName),
        SandboxName)))
        return FALSE;

    if (FAILED(StringCchCatNW(
        JobObjectName,
        _countof(JobObjectName),
        ExtendHashName,
        _countof(ExtendHashName))))
        return FALSE;

    pGbie = (PGBIE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(GBIE));
    if (!pGbie)
        return FALSE;

    __try
    {
        HRESULT hresult = CreateAppContainerProfile(
            AppContainerName,
            AppContainerDisplayName,
            L"AppContainer created for Glassboxie.",
            NULL,
            0,
            &pAppContainerSID);

        if (FAILED(hresult))
        {
            if (HRESULT_CODE(hresult) != ERROR_ALREADY_EXISTS)
                __leave;

            // already exist

            if (dwCreationDisposition == CREATE_ALWAYS ||
                dwCreationDisposition == TRUNCATE_EXISTING)
            {
                // "truncate" by deleting and re-creating
                if (FAILED(DeleteAppContainerProfile(AppContainerName)))
                    __leave;
                // TODO: also revoke all granted access to files...

                hresult = CreateAppContainerProfile(
                    AppContainerName,
                    AppContainerDisplayName,
                    L"AppContainer created for Glassboxie.",
                    NULL,
                    0,
                    &pAppContainerSID);
                if (FAILED(hresult))
                    __leave;
            }
            else if (dwCreationDisposition == CREATE_NEW)
            {
                __leave;
            }
            else if (
                dwCreationDisposition == OPEN_ALWAYS ||
                dwCreationDisposition == OPEN_EXISTING)
            {
                // then just get the SID...
                if (FAILED(DeriveAppContainerSidFromAppContainerName(
                    AppContainerName,
                    &pAppContainerSID)))
                {
                    __leave;
                }
            }
            else
            {
                __leave;
            }
        }
        else
        {
            // does not exist and created now...
            if (dwCreationDisposition == CREATE_ALWAYS ||
                dwCreationDisposition == CREATE_NEW ||
                dwCreationDisposition == OPEN_ALWAYS)
            {
                // OK
                // TODO: grant access to objects...
            }
            else if (dwCreationDisposition == OPEN_EXISTING)
            {
                DeleteAppContainerProfile(AppContainerName);
                __leave;
            }
            else if (dwCreationDisposition == TRUNCATE_EXISTING)
            {
                DeleteAppContainerProfile(AppContainerName);
                __leave;
            }
            else
            {
                DeleteAppContainerProfile(AppContainerName);
                __leave;
            }
        }

        // TODO: better to be created in private namespace...?
        // see CreatePrivateNamespaceW
        hJobObject = CreateJobObjectW(NULL, JobObjectName);
        if (!hJobObject)
        {
            __leave;
        }

        // Copy information into pGbie
        StringCchCopyW(
            pGbie->Name,
            _countof(pGbie->Name),
            SandboxName);
        StringCchCopyW(
            pGbie->AppContainerName,
            _countof(pGbie->AppContainerName),
            AppContainerName);
        pGbie->AppContainerSID = pAppContainerSID;
        pGbie->hJobObject = hJobObject;
        bSuccess = TRUE;
    }
    __finally
    {
        if (!bSuccess)
        {
            if (hJobObject)
                CloseHandle(hJobObject);
            if (pAppContainerSID)
                FreeSid(pAppContainerSID);

            HeapFree(GetProcessHeap(), 0, (LPVOID)pGbie);
            pGbie = NULL;
        }
    }
    return pGbie;
}

_Use_decl_annotations_
BOOL GbieCreateProcess(
    PGBIE pGbie,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    DWORD CreationFlags,
    LPCWSTR lpCurrentDirectory,
    HANDLE* hProcess,
    HANDLE* hThread
)
{
    BOOL bSuccess = FALSE;
    STARTUPINFOEXW StartupInfoEx = { 0 };
    PROCESS_INFORMATION ProcessInfo = { 0 };

    __try
    {
        StartupInfoEx.StartupInfo.cb = sizeof(StartupInfoEx);

        SIZE_T ProcThreadAttrListSize = 0;

        // AppContainer SecurityCapabilities
        SECURITY_CAPABILITIES SecurityCapabilities = { 0 };

        WELL_KNOWN_SID_TYPE EnabledCapabilities[] = {
            WinCapabilityPrivateNetworkClientServerSid
        };
        SIZE_T CntEnabledCapabilities = _countof(EnabledCapabilities);

        // Allocate and initialize ProcThreadAttributeList
        // Then update information for it.
        InitializeProcThreadAttributeList(
            NULL,
            2,
            0,
            &ProcThreadAttrListSize);

        StartupInfoEx.lpAttributeList =
            HeapAlloc(GetProcessHeap(), 0, ProcThreadAttrListSize);

        if (!StartupInfoEx.lpAttributeList)
            __leave;

        if (!InitializeProcThreadAttributeList(
            StartupInfoEx.lpAttributeList,
            2,
            0,
            &ProcThreadAttrListSize))
            __leave;

        __try
        {
            if (!AllocateEnabledSecurityCapabilities(
                &SecurityCapabilities.Capabilities,
                EnabledCapabilities,
                CntEnabledCapabilities))
                __leave;
            SecurityCapabilities.CapabilityCount = (DWORD)CntEnabledCapabilities;
            SecurityCapabilities.AppContainerSid = pGbie->AppContainerSID;

            if (!UpdateProcThreadAttribute(
                StartupInfoEx.lpAttributeList,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                &SecurityCapabilities,
                sizeof(SecurityCapabilities),
                NULL,
                NULL))
                __leave;

            if (!UpdateProcThreadAttribute(
                StartupInfoEx.lpAttributeList,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                &pGbie->hJobObject,
                sizeof(HANDLE),
                NULL,
                NULL))
                __leave;

            if (!CreateProcessW(
                lpApplicationName,
                lpCommandLine,
                NULL,
                NULL,
                FALSE,
                CreationFlags | EXTENDED_STARTUPINFO_PRESENT,
                NULL,
                lpCurrentDirectory,
                (LPSTARTUPINFOW)&StartupInfoEx,
                &ProcessInfo))
            {
                __leave;
            }
            *hProcess = ProcessInfo.hProcess;
            *hThread = ProcessInfo.hThread;
            bSuccess = TRUE;
        }
        __finally
        {
            if (SecurityCapabilities.Capabilities)
            {
                FreeSecurityCapabilities(
                    SecurityCapabilities.Capabilities,
                    CntEnabledCapabilities);
            }
            DeleteProcThreadAttributeList(StartupInfoEx.lpAttributeList);
        }
    }
    __finally
    {
        if (StartupInfoEx.lpAttributeList)
        {
            HeapFree(GetProcessHeap(), 0, StartupInfoEx.lpAttributeList);
        }
    }
    return bSuccess;
}

_Use_decl_annotations_
BOOL GbieCloseSandbox(
    PGBIE pGbie
)
{
    BOOL bSuccess = TRUE;
    if (pGbie->hJobObject)
        bSuccess &= CloseHandle(pGbie->hJobObject);
    if (pGbie->AppContainerSID)
        bSuccess &= (FreeSid(pGbie->AppContainerSID) == NULL);

    HeapFree(GetProcessHeap(), 0, (LPVOID)pGbie);
    return bSuccess;
}

_Use_decl_annotations_
BOOL GbieDestroySandbox(
    PGBIE pGbie
)
{
    BOOL bSuccess = TRUE;
    if (pGbie->hJobObject)
    {
        bSuccess &= TerminateJobObject(pGbie->hJobObject, EXIT_SUCCESS);
    }
    bSuccess &= SUCCEEDED(DeleteAppContainerProfile(pGbie->AppContainerName));
    bSuccess &= GbieCloseSandbox(pGbie);
    return bSuccess;
}
