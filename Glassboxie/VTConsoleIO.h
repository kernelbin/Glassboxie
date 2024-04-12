#ifndef VTCONSOLEIO_H_
#define VTCONSOLEIO_H_

#include <Windows.h>

#define VT_ESC L"\x1b"

#define VT_BLACK(string)   L"" VT_ESC "[30m" string VT_ESC "[39m"
#define VT_RED(string)     L"" VT_ESC "[31m" string VT_ESC "[39m"
#define VT_GREEN(string)   L"" VT_ESC "[32m" string VT_ESC "[39m"
#define VT_YELLOW(string)  L"" VT_ESC "[33m" string VT_ESC "[39m"
#define VT_BLUE(string)    L"" VT_ESC "[34m" string VT_ESC "[39m"
#define VT_MAGENTA(string) L"" VT_ESC "[35m" string VT_ESC "[39m"
#define VT_CYAN(string)    L"" VT_ESC "[36m" string VT_ESC "[39m"
#define VT_WHITE(string)   L"" VT_ESC "[37m" string VT_ESC "[39m"


BOOL ConsolePrint(const WCHAR lpFormat[], ...);

#endif // LIBGLASSBOXIE_H_
