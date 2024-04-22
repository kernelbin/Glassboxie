#ifndef LIBGLASSBOXIE_H_
#define LIBGLASSBOXIE_H_

#include <Windows.h>

EXTERN_C_START

#define GLASSBOXIE_VERSION 1

// see https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile
#define APPCONTAINER_NAME_MAX               64
#define APPCONTAINER_DISPLAY_NAME_MAXLEN    512
#define APPCONTAINER_DESCRIPTION_MAXLEN     2048

typedef struct GLASSBOXIE {
    WCHAR Name[APPCONTAINER_NAME_MAX + 1];
    WCHAR AppContainerName[APPCONTAINER_NAME_MAX + 1];
    PSID AppContainerSID;
    HANDLE hJobObject;

} GLASSBOXIE, GBIE, *PGBIE;

PGBIE GbieCreateSandbox(
    _In_ const WCHAR SandboxName[],
    _In_ BOOL bOpenExisting);

_Success_(return)
BOOL GbieCreateProcess(
    _In_ PGBIE pGbie,
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_ DWORD CreationFlags,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _Out_ HANDLE* hProcess,
    _Out_ HANDLE* hThread
);

BOOL GbieCloseSandbox(
    _In_ _Frees_ptr_ PGBIE pGbie
);

BOOL GbieDestroySandbox(
    _In_ _Frees_ptr_ PGBIE pGbie
);

EXTERN_C_END

#endif // LIBGLASSBOXIE_H_
