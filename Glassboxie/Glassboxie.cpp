#include "LibGlassboxie.h"
#include "VTConsoleIO.h"
#include <Windows.h>
#include <strsafe.h>
#include <atlcoll.h>
#include <atlfile.h>
#include <vector>
#include <string>
#include "yyjson.h"

#ifndef UNICODE
#error must be compiled with UNICODE enabled.
#endif


struct GBIE_CONFIG
{
    std::wstring Name;
    std::wstring Version;
};

static void MultiByteToWString(UINT CodePage, const char* string, std::wstring &wstring)
{
    int cchLen = MultiByteToWideChar(CodePage, NULL, string, -1, NULL, 0);
    LPCWSTR WideString = (LPCWSTR)HeapAlloc(GetProcessHeap(), 0, cchLen * sizeof(WCHAR));
    wstring = std::wstring(WideString);
    HeapFree(GetProcessHeap(), 0, (LPVOID)WideString);
}
static BOOL ParseConfigFile(const PBYTE Buffer, SIZE_T BufferLength,  GBIE_CONFIG& Config)
{
    BOOL bSuccess = FALSE;
    yyjson_doc* JsonDoc = yyjson_read((const char *)Buffer, BufferLength, 0);
    if (!JsonDoc)
        return FALSE;
    __try
    {
        yyjson_val* JsonRoot = yyjson_doc_get_root(JsonDoc);

        yyjson_val* JsonName = yyjson_obj_get(JsonRoot, "name");
        yyjson_val* JsonVersion = yyjson_obj_get(JsonRoot, "version");
        if (!JsonName || !JsonVersion)
            __leave;
        const char* NameStr = yyjson_get_str(JsonName);
        const char* VersionStr = yyjson_get_str(JsonVersion);
        if (!NameStr || !VersionStr)
            __leave;


        MultiByteToWString(CP_UTF8, NameStr, Config.Name);
        MultiByteToWString(CP_UTF8, VersionStr, Config.Version);

        bSuccess = TRUE;
    }
    __finally
    {
        yyjson_doc_free(JsonDoc);
    }
    return bSuccess;
}

BOOL HandleCreateCommand(int argc, WCHAR** argv)
{
    if (argc < 1)
    {
        ConsolePrint(VT_RED("Error: missing config file\n"));
        return FALSE;
    }

    for (SIZE_T i = 0; i < argc; i++)
    {
        ATL::CAtlFile ConfigFile;
        if (FAILED(ConfigFile.Create(argv[i], GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING)))
        {
            ConsolePrint(VT_YELLOW("Warning: failed to open file: %1\n"), argv[i]);
            continue;
        }
        ULONGLONG FileSize = 0;
        if (FAILED(ConfigFile.GetSize(FileSize)))
        {
            ConsolePrint(VT_YELLOW("Warning: failed to open file: %1\n"), argv[i]);
            continue;
        }
        CSimpleArray<BYTE> A;
        std::vector<BYTE> Buffer(FileSize);

        ConfigFile.Read(Buffer.data(), (DWORD)FileSize);

        GBIE_CONFIG Config;
        if (!ParseConfigFile(Buffer.data(), Buffer.size(), Config))
        {
            ConsolePrint(VT_YELLOW("Warning: failed to parse config file: %1\n"), argv[i]);
            continue;
        }
    }

    return TRUE;
}

BOOL HandleDeleteCommand(int argc, WCHAR** argv)
{
    return TRUE;
}

BOOL HandleRunCommand(int argc, WCHAR** argv)
{
    return TRUE;
}

BOOL HandleCommandLine(int argc, WCHAR** argv)
{
    // supported command
    // create
    //    create config_file
    // delete
    //    delete sandbox_name
    // run
    //    run sandbox_name executable

    if (argc <= 0)
    {
        ConsolePrint(VT_RED("Error: too less argument.\n"));
        return FALSE;
    }
    if (_wcsicmp(argv[1], L"create"))
    {
        return HandleCreateCommand(argc - 1, argv + 1);
    }
    if (_wcsicmp(argv[1], L"delete"))
    {
        return HandleDeleteCommand(argc - 1, argv + 1);
    }
    if (_wcsicmp(argv[1], L"run"))
    {
        return HandleRunCommand(argc - 1, argv + 1);
    }


    ConsolePrint(L"Unknown command: %1\n", argv[0]);
    return FALSE;
}

int wmain(int argc, WCHAR** argv)
{
    GbieCreateSandbox(L"aa", 1);
    if (!HandleCommandLine(argc - 1, argv + 1))
    {
        ConsolePrint(
            L"Usage:\n"
            L"    %1 [ CREATE | DELETE | RUN ] [<args>]\n", argv[0]);
    }
    return 0;
}
