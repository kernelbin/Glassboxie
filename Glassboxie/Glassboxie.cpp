#include "LibGlassboxie.h"
#include "VTConsoleIO.h"
#include <Windows.h>
#include <strsafe.h>

BOOL HandleCreateCommand(int argc, WCHAR** argv)
{
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
        ConsolePrint(L"too less argument.\n");
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


    ConsolePrint(L"unknown command: %1\n", argv[0]);
    return FALSE;
}

int wmain(int argc, WCHAR** argv)
{
    if (!HandleCommandLine(argc - 1, argv + 1))
    {
        ConsolePrint(VT_RED("sdsdqwq"));
    }
    return 0;
}
