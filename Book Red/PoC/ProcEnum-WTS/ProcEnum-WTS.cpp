#include <Windows.h>
#include <iostream>
#include <string>
#include <WtsApi32.h>
#include <sddl.h>
#include <fstream>
#include <vector>
#pragma comment(lib, "Wtsapi32.lib")

// Convert SID to a string for logging
std::wstring SidToStringSid(PSID sid) {
    PWSTR ssid;
    if (ConvertSidToStringSid(sid, &ssid)) {
        std::wstring result(ssid);
        LocalFree(ssid);
        return result;
    }
    return L"";
}

// Filter target processes by name
bool IsTargetProcess(const std::wstring& processName, const std::vector<std::wstring>& targetProcesses) {
    for (const auto& proc : targetProcesses) {
        if (_wcsicmp(processName.c_str(), proc.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

int main() {
    DWORD level = 1;
    PWTS_PROCESS_INFO_EX processInfo;
    DWORD count = 0;

    // List of names of processes of interest (security software)
    std::vector<std::wstring> targetProcesses = {
        L"Discord.exe", L"msmpeng.exe", L"avguard.exe", L"ccSvcHst.exe",
        L"mcshield.exe", L"savservice.exe", L"mbamservice.exe", L"f-secure.exe",
        L"cylancesvc.exe", L"carbonblack.exe", L"edrsvc.exe", L"sentinelagent.exe",
        L"taniumclient.exe", L"esensor.exe", L"splunkd.exe", L"tripwire.exe",
        L"pfsvc.exe", L"zemana.exe", L"comodo.exe", L"zonealarm.exe",
        L"snort.exe", L"wireshark.exe", L"networkminer.exe", L"tssvcs.exe",
        L"qradar.exe", L"arcsight.exe", L"logrhythm.exe", L"alienvault.exe",
        L"graylog.exe", L"sysmon.exe", L"autoruns.exe", L"procexp.exe",
        L"processhacker.exe"
    };

    std::wstring adminSID = L"S-1-5-18"; // SID of the SYSTEM account

    // Get the current directory to save the log file there
    wchar_t currentDir[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, currentDir);
    std::wstring logFilePath = std::wstring(currentDir) + L"\\process_report.txt";

    // Open the log file for writing
    std::wofstream logfile(logFilePath);
    if (!logfile.is_open()) {
        std::cerr << "Failed to open log file for writing." << std::endl;
        return 1;
    }

    BOOL WTSProcess = WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION, (LPWSTR*)&processInfo, &count);

    if (WTSProcess == FALSE) {
        std::cerr << "Failed to enumerate processes. Error code: " << GetLastError() << std::endl;
        logfile.close();
        return GetLastError();
    }

    // Write header to the log file
    logfile << L"Process Enumeration Report\n";
    logfile << L"--------------------------\n";

    // Display and log process information for target processes only
    for (DWORD i = 0; i < count; i++) {
        auto& pInfo = processInfo[i];
        std::wstring processName = pInfo.pProcessName ? pInfo.pProcessName : L"";
        std::wstring userSID = SidToStringSid(pInfo.pUserSid);

        // Check if the current process is in the target processes list
        if (IsTargetProcess(processName, targetProcesses)) {
            std::wcout << L"PID: " << pInfo.ProcessId << L"\t"
                << L"Session: " << pInfo.SessionId << L"\t"
                << L"Threads: " << pInfo.NumberOfThreads << L"\t"
                << L"Handles: " << pInfo.HandleCount << L"\t"
                << L"Name: " << processName << L"\t"
                << L"SID: " << userSID << L"\n";

            logfile << L"PID: " << pInfo.ProcessId << L"\t"
                << L"Session: " << pInfo.SessionId << L"\t"
                << L"Threads: " << pInfo.NumberOfThreads << L"\t"
                << L"Handles: " << pInfo.HandleCount << L"\t"
                << L"Name: " << processName << L"\t"
                << L"SID: " << userSID << L"\n";
        }
    }

    // Close the log file and free memory
    logfile.close();
    WTSFreeMemory(processInfo);

    return 0;
}