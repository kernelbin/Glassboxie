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

struct GBIE_STORAGE_SETTINGS
{
    std::wstring Path;
    DWORD Permissions;
};
struct GBIE_CONFIG
{
    std::wstring Name;
    std::wstring Version;
    std::vector<GBIE_STORAGE_SETTINGS> StorageSettingsList;

    BOOL bHasMaxCPURate;
    WORD MaxCPURate;

    BOOL bHasMemoryLimit;
    SIZE_T MemoryLimit;
};

_Success_(return)
static BOOL MultiByteToWString(
    _In_ UINT CodePage,
    _In_z_ const char* string,
    _Out_ std::wstring & wstring)
{
    int cchLen = MultiByteToWideChar(CodePage, NULL, string, -1, NULL, 0);
    LPWSTR WideString = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cchLen * sizeof(WCHAR));
    if (!WideString)
        return FALSE;
    MultiByteToWideChar(CodePage, NULL, string, -1, WideString, cchLen);
    wstring = std::wstring(WideString);
    HeapFree(GetProcessHeap(), 0, (LPVOID)WideString);
    return TRUE;
}

_Success_(return)
static BOOL ParseConfigFile(
    _In_reads_(BufferLength) const PBYTE Buffer,
    _In_ SIZE_T BufferLength,
    _Out_ GBIE_CONFIG & Config)
{
    BOOL bSuccess = FALSE;
    yyjson_doc* JsonDoc = yyjson_read((const char*)Buffer, BufferLength, 0);
    if (!JsonDoc)
        return FALSE;
    __try
    {
        yyjson_val* JsonRoot = yyjson_doc_get_root(JsonDoc);

        yyjson_val* JsonName =
            yyjson_obj_get(JsonRoot, "name");
        yyjson_val* JsonVersion =
            yyjson_obj_get(JsonRoot, "version");
        yyjson_val* JsonStorageSettings =
            yyjson_obj_get(JsonRoot, "storage_settings");
        yyjson_val* JsonResourcesLimits =
            yyjson_obj_get(JsonRoot, "resource_limits");

        if (!JsonName || !JsonVersion)
            __leave;
        const char* NameStr = yyjson_get_str(JsonName);
        const char* VersionStr = yyjson_get_str(JsonVersion);
        if (!NameStr || !VersionStr)
            __leave;

        if (JsonStorageSettings)
        {
            if (yyjson_is_arr(JsonStorageSettings))
            {
                size_t StorageSettingsSize = yyjson_arr_size(JsonStorageSettings);
                yyjson_val* StorageSettingsEntry = yyjson_arr_get_first(JsonStorageSettings);

                for (SIZE_T i = 0; i < StorageSettingsSize; i++)
                {
                    // use lambda to avoid C++ object initialization (which can't use alongside with SEH
                    [](GBIE_CONFIG& Config, yyjson_val* StorageSettingsEntry) {

                        yyjson_val* PathVal;
                        yyjson_val* PermissionsVal;
                        PathVal = yyjson_obj_get(StorageSettingsEntry, "path");
                        PermissionsVal = yyjson_obj_get(StorageSettingsEntry, "permissions");

                        if (PathVal && PermissionsVal)
                        {
                            if (yyjson_is_str(PathVal) && yyjson_is_uint(PermissionsVal))
                            {
                                GBIE_STORAGE_SETTINGS StorageSettings;

                                const char* Path = yyjson_get_str(PathVal);
                                DWORD Permissions = yyjson_get_uint(PermissionsVal);

                                MultiByteToWString(CP_UTF8, Path, StorageSettings.Path);
                                StorageSettings.Permissions = Permissions;
                                Config.StorageSettingsList.push_back(StorageSettings);
                            }
                        }
                        }(Config, StorageSettingsEntry);

                        StorageSettingsEntry = unsafe_yyjson_get_next(StorageSettingsEntry);
                }
            }
        }

        Config.bHasMaxCPURate = FALSE;
        Config.bHasMemoryLimit = FALSE;
        if (JsonResourcesLimits)
        {
            if (yyjson_is_obj(JsonResourcesLimits))
            {
                yyjson_val* JsonCPURate =
                    yyjson_obj_get(JsonResourcesLimits, "cpu");
                yyjson_val* JsonMemeoryLimit =
                    yyjson_obj_get(JsonResourcesLimits, "memory");

                if (yyjson_is_uint(JsonCPURate))
                {
                    Config.MaxCPURate = yyjson_get_uint(JsonCPURate);
                    Config.bHasMaxCPURate = TRUE;
                }
                if (yyjson_is_uint(JsonMemeoryLimit))
                {
                    Config.MemoryLimit = yyjson_get_uint(JsonMemeoryLimit);
                    Config.bHasMemoryLimit = TRUE;
                }
            }
        }

        if (!MultiByteToWString(CP_UTF8, NameStr, Config.Name))
            __leave;
        if (!MultiByteToWString(CP_UTF8, VersionStr, Config.Version))
            __leave;

        bSuccess = TRUE;
    }
    __finally
    {
        yyjson_doc_free(JsonDoc);
    }
    return bSuccess;
}

BOOL HandleCreateCommand(int argc, WCHAR * *argv)
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

        GBIE_JOBLIMITS JobLimits;
        JobLimits.bHasMaxCPURate = Config.bHasMaxCPURate;
        JobLimits.MaxCPURate = Config.MaxCPURate;
        JobLimits.bHasMemoryLimit = Config.bHasMemoryLimit;
        JobLimits.MemoryLimit = Config.MemoryLimit;

        PGBIE pGbie = GbieCreateSandbox(Config.Name.c_str(), CREATE_ALWAYS, &JobLimits);
        if (!pGbie)
        {
            ConsolePrint(
                VT_YELLOW("Warning: failed to create sandbox %1 specified by file: %2\n"),
                Config.Name.c_str(), argv[i]);
            continue;
        }

        // Also set storage settings
        for (auto& StorageSetting : Config.StorageSettingsList)
        {
            GBIE_OBJECT_ACCESS ObjectAccess = { 0 };
            ObjectAccess.AccessPermissions = StorageSetting.Permissions;
            ObjectAccess.AccessMode = GRANT_ACCESS;
            ObjectAccess.ObjectType = SE_FILE_OBJECT;
            ObjectAccess.pObjectName = StorageSetting.Path.c_str();
            ObjectAccess.hObject = NULL;

            if (!GbieSandboxSetNamedObjectAccess(pGbie, &ObjectAccess))
            {
                ConsolePrint(
                    VT_YELLOW("Warning: failed to grant file access to sandbox %1. file: %2\n"),
                    Config.Name.c_str(),
                    StorageSetting.Path.c_str()
                );
            }
        }

        GbieCloseSandbox(pGbie);
    }

    return TRUE;
}

BOOL HandleDeleteCommand(int argc, WCHAR * *argv)
{
    return TRUE;
}

BOOL HandleRunCommand(int argc, WCHAR * *argv)
{
    LPCWSTR RunSandboxName = NULL;
    LPWSTR RunCommandLine = NULL;
    LPCWSTR RunCurrentDirectory = NULL;

    for (SIZE_T i = 0; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"-D") == 0)
        {
            if (i + 1 >= argc)
            {
                ConsolePrint(VT_RED("Error: missing arguments after option -D.\n"));
                return FALSE;
            }
            else
            {
                i++;
                RunCurrentDirectory = argv[i];
            }
        }
        else
        {
            if (!RunSandboxName)
            {
                RunSandboxName = argv[i];
            }
            else if (!RunCommandLine)
            {
                RunCommandLine = argv[i];
            }
            else
            {
                ConsolePrint(VT_RED("Error: too much arguments.\n"));
                return FALSE;
            }
        }
    }

    if (!RunSandboxName || !RunCommandLine)
    {
        ConsolePrint(VT_RED("Error: too less arguments.\n"));
        return FALSE;
    }

    PGBIE pGbie = GbieCreateSandbox(RunSandboxName, OPEN_EXISTING, NULL);
    if (!pGbie)
    {
        ConsolePrint(VT_RED("Error: sandbox %1 not found.\n"), argv[0]);
        return FALSE;
    }

    HANDLE hProcess = NULL, hThread = NULL;
    if (!GbieCreateProcess(
        pGbie,
        NULL,
        RunCommandLine,
        CREATE_NEW_CONSOLE,
        RunCurrentDirectory,
        &hProcess,
        &hThread))
    {
        ConsolePrint(
            VT_RED("Error: failed to create process in sandbox %1.\n"),
            argv[0]);
        return FALSE;
    }
    return TRUE;
}

BOOL HandleHelpCommand(int argc, WCHAR * *argv)
{
    ConsolePrint(
        L"Usage:\n"
        L"    %1 [ CREATE | DELETE | RUN | HELP ] [<args>]\n", argv[0]);

    ConsolePrint(
        L"\n"
        L"    CREATE\n"
        L"        Create a sandbox specified by the configuration file.\n"
        L"    DELETE\n"
        L"        Delete specified sandbox, and terminate all process within it.\n"
        L"    RUN\n"
        L"        Run a process in specified sandbox.\n"
        L"    HELP\n"
        L"        Show this help message.\n");
    return TRUE;
}


BOOL HandleCommandLine(int argc, WCHAR * *argv)
{
    // supported command
    // create
    //    create config_file
    // delete
    //    delete sandbox_name
    // run
    //    run sandbox_name executable

    if (argc <= 1)
    {
        ConsolePrint(VT_RED("Error: too less argument.\n"));
        return FALSE;
    }
    if (_wcsicmp(argv[1], L"create") == 0)
    {
        return HandleCreateCommand(argc - 2, argv + 2);
    }
    if (_wcsicmp(argv[1], L"delete") == 0)
    {
        return HandleDeleteCommand(argc - 2, argv + 2);
    }
    if (_wcsicmp(argv[1], L"run") == 0)
    {
        return HandleRunCommand(argc - 2, argv + 2);
    }
    if (_wcsicmp(argv[1], L"help") == 0)
    {
        return HandleHelpCommand(argc, argv);
    }

    ConsolePrint(L"Unknown command: %1\n", argv[0]);
    return FALSE;
}

int wmain(int argc, WCHAR * *argv)
{
    if (!HandleCommandLine(argc, argv))
    {
        ConsolePrint(
            L"Usage:\n"
            L"    %1 [ CREATE | DELETE | RUN | HELP ] [<args>]\n", argv[0]);
    }
    return 0;
}
