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

_Use_decl_annotations_
PGBIE GbieCreateSandbox(
    const WCHAR SandboxName[],
    BOOL bOpenExisting)
{
    BOOL bSuccess = FALSE;
    PGBIE pGbie = NULL;
    PSID pAppContainerSID = NULL;
    HANDLE hJobObject = NULL;

    WCHAR ExtendHashName[32];
    GetExtendHashName(SandboxName, ExtendHashName, _countof(ExtendHashName));

    // AppContainerName can be up to 64 characters in length. 
    WCHAR AppContainerName[64] = L"Glassboxie - ";
    WCHAR AppContainerDisplayName[512] = L"Glassboxie - ";

    if (FAILED(StringCchCatNW(AppContainerName, _countof(AppContainerName), ExtendHashName, _countof(ExtendHashName))))
        return FALSE;

    if (FAILED(StringCchCatW(AppContainerDisplayName, _countof(AppContainerDisplayName), SandboxName)))
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
            // Try open existing one
            if (HRESULT_CODE(hresult) == ERROR_ALREADY_EXISTS && bOpenExisting)
            {
                if (FAILED(DeriveAppContainerSidFromAppContainerName(AppContainerName, &pAppContainerSID)))
                {
                    __leave;
                }
            }
            else
            {
                __leave;
            }
        }

        WCHAR JobObjectName[512] = L"Glassboxie JobObject - ";
        if (FAILED(StringCchCatNW(JobObjectName, _countof(JobObjectName), ExtendHashName, _countof(ExtendHashName))))
        {
            __leave;
        }
        // TODO: better to be created in private namespace...?
        // see CreatePrivateNamespaceW
        hJobObject = CreateJobObjectW(NULL, JobObjectName);

        // Copy information into pGbie
        StringCchCopyW(pGbie->Name, _countof(pGbie->Name), SandboxName);
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
