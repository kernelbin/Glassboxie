#include "VTConsoleIO.h"

#include <strsafe.h>

BOOL ConsolePrint(const WCHAR lpFormat[], ...)
{
    va_list ArgList;
    va_start(ArgList, lpFormat);

    LPCWSTR FormattedString = NULL;
    DWORD cchFormatted = 0, cchWritten = 0;
    cchFormatted = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING, lpFormat, 0, 0, (LPWSTR)&FormattedString, 0, &ArgList);

    if (cchFormatted == 0)
    {
        return FALSE;
    }

    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), FormattedString, cchFormatted, &cchWritten, NULL);
    LocalFree((HLOCAL)FormattedString);
    va_end(ArgList);
    return cchFormatted == cchWritten;
}
