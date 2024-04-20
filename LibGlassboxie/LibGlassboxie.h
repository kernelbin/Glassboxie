#ifndef LIBGLASSBOXIE_H_
#define LIBGLASSBOXIE_H_

#include <Windows.h>

EXTERN_C_START

#define GLASSBOXIE_VERSION 1

typedef struct GLASSBOXIE {
    WCHAR Name[64];
    PSID AppContainerSID;
    HANDLE hJobObject;

} GLASSBOXIE, GBIE, *PGBIE;

PGBIE GbieCreateSandbox(
    _In_ const WCHAR SandboxName[],
    _In_ BOOL bOpenExisting);

EXTERN_C_END

#endif // LIBGLASSBOXIE_H_
