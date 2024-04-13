#include "LibGlassboxie.h"
#include "VTConsoleIO.h"
#include <Windows.h>
#include <strsafe.h>
#include <atlcoll.h>
#include <atlfile.h>

#ifndef UNICODE
#error must be compiled with UNICODE enabled.
#endif

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
            ConsolePrint(VT_YELLOW("Warning: failed to open file: %1\n"), argv[1]);
            continue;
        }
        ULONGLONG FileSize = 0;
        if (FAILED(ConfigFile.GetSize(FileSize)))
        {
            ConsolePrint(VT_YELLOW("Warning: failed to open file: %1\n"), argv[1]);
            continue;
        }
        // continue here: 判断大小并读取配置文件
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
    //    deleet sandbox_name
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
    if (!HandleCommandLine(argc - 1, argv + 1))
    {
        ConsolePrint(
            L"Usage:\n"
            L"    %1 [ CREATE | DELETE | RUN ] [<args>]\n", argv[0]);
    }
    return 0;
}
