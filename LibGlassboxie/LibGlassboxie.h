#ifndef LIBGLASSBOXIE_H_
#define LIBGLASSBOXIE_H_

#include <Windows.h>

EXTERN_C_START

#define GLASSBOXIE_VERSION 1

BOOL GbieCreateSandbox(const WCHAR SandboxName[], BOOL bOpenExisting);

EXTERN_C_END

#endif // LIBGLASSBOXIE_H_
