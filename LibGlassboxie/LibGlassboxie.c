#include "LibGlassboxie.h"
#include <windows.h>
#include <bcrypt.h>


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")


static BOOL GetExtendHashName(const WCHAR SandboxName[], WCHAR ExtendHashName[], int cchExtendHashName)
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
        DWORD SandboxNameLength = wcslen(SandboxName);
        DWORD GlassboxieVersion = GLASSBOXIE_VERSION;

        //if (!NT_SUCCESS(status = BCryptHashData(
        //    hHash,
        //    (PBYTE)&GlassboxieVersion,
        //    sizeof(DWORD),
        //    0)))
        //{
        //    __leave;
        //}

        //if (!NT_SUCCESS(status = BCryptHashData(
        //    hHash,
        //    (PBYTE)&SandboxNameLength,
        //    sizeof(DWORD),
        //    0)))
        //{
        //    __leave;
        //}

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

BOOL GbieCreateSandbox(const WCHAR SandboxName[], BOOL bOpenExisting)
{
    WCHAR ExtendHashName[128];
    GetExtendHashName(SandboxName, ExtendHashName, _countof(ExtendHashName));

    Sleep(0);
}
