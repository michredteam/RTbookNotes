# Detecting Hooked Syscalls

It's possible to enumerate which Windows API calls are hooked by an EDR using inline patching technique, where a `jmp` instruction is inserted at the beginning of the syscall stub to be hooked.

## Related Notes

{% content-ref url="../code-injection-process-injection/how-to-hook-windows-api-using-c++.md" %}
[how-to-hook-windows-api-using-c++.md](../code-injection-process-injection/how-to-hook-windows-api-using-c++.md)
{% endcontent-ref %}

{% content-ref url="bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis.md" %}
[bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis.md](bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis.md)
{% endcontent-ref %}

{% content-ref url="../code-injection-process-injection/api-monitoring-and-hooking-for-offensive-tooling.md" %}
[api-monitoring-and-hooking-for-offensive-tooling.md](../code-injection-process-injection/api-monitoring-and-hooking-for-offensive-tooling.md)
{% endcontent-ref %}

## Walkthrough

### Function before Hooking

Below shows the stub for for `NtReadVirtualMemory` on a system with no EDR present, meaning the syscall `NtReadVirtualMemory` is not hooked:

![](<../../.gitbook/assets/image (712).png>)

We can see the `NtReadVirtualMemory` syscall stub starts with instructions:

```
00007ffc`d6dcc780 4c8bd1          mov     r10,rcx
00007ffc`d6dcc783 b83f000000      mov     eax,3Fh
...
```

{% hint style="info" %}
The above applies to most routines starting with `Zw`, i.e `ZwReadVirtualMemory` too.
{% endhint %}

...which translates to the following 4 opcodes:

```
4c 8b d1 b8
```

![](<../../.gitbook/assets/image (713).png>)

`4c 8b d1 b8` - are important for this lab - we will come back to this in a moment in a section [Checking for Hooks](detecting-hooked-syscall-functions.md#checking-for-hooks).

### Function after Hooking

Below shows an example of how `NtReadVirtualMemory` syscall stub looks like when it's hooked by an EDR:

![](<../../.gitbook/assets/image (711).png>)

Note that in this case, the first instruction is a `jmp` instruction, redirecting the code execution somewhere else (another module in the process's memory):

```
jmp 0000000047980084
```

...which translates to the following 5 opcodes:

```
e9 0f 64 f8 c7
```

{% hint style="info" %}
`e9` - opcode for near jump\
`0f64f8c7`- offset, which is relative to the address of the current instruction, where the code will jump to
{% endhint %}

### Checking for Hooks

Knowing that interesting functions/syscalls (that are often used in malware), starting with `Nt` | `Zw`, before hooking, start with opcodes: `4c 8b d1 b8`, we can determine if a given function is hooked or not by following this process:

1. Iterate through all the exported functions of the ntdll.dll
2. Read the first 4 bytes of the the syscall stub and check if they start with `4c 8b d1 b8`
   1. If yes, the function is not hooked
   2. If no, the function is most likely hooked (with a couple of exceptions mentioned in the False Positives callout).

Below is a simplified visual example attempting to further explain the above process:

1. `NtReadVirtualMemory` starts with opcodes `e9 0f 64 f8` rather than `4c 8b d1 b8`, meaning it's most likely hooked
2. `NtWriteVirtualMemory` starts with opcodes `4c 8b d1 b8`, meaning it has not been hooked

![Hooked and unhooked functions](<../../.gitbook/assets/image (714).png>)

### Detecting who placed the Hook

As additional verification for a function really being hooked by a different DLL, we can resolve the jump target and check which module it belongs to using GetMappedFileName.

This can also help detect false-positives. If the jump leads into ntdll.dll itself, it is either supposed to be there, or it could be a more sophisticated hook trying to disguise itself against this technique.

```cpp
if (*((unsigned char*)targetFunction) == 0xE9) // first byte is a jmp instruction, where does it jump to?
{
	// E9 jump instruction has 32bit offset, relative to the address of the first instruction AFTER our jump instruction.
	DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
	// Its possible for target to be 0x000025FF, which is jmp QWORD PTR [rip+0x0], or similar variants, this is not handled in this example
	PDWORD jumpTarget = targetFunction + 5 /*Instruction pointer after our jmp instruction*/ + jumpTargetRelative;  
	char moduleNameBuffer[512];
	GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
}
```

{% hint style="warning" %}
**False Positives**\
\*\*\*\*Although highly effective at detecting functions hooked with inline patching, this method returns a few false positives when enumerating hooked functions inside ntdll.dll, such as:\
\
`NtGetTickCount`\
`NtQuerySystemTime`\
`NtdllDefWindowProc_A`\
`NtdllDefWindowProc_W`\
`NtdllDialogWndProc_A`\
`NtdllDialogWndProc_W`\
`ZwQuerySystemTime`

The above functions are not hooked.
{% endhint %}

## Code

Below is the code that we can compile and run on an endpoint running an AV/EDR to see enumerate APIs that were most likely hooked:

```cpp
#include <iostream>
#include <Windows.h>
#include <psapi.h>

int main()
{
	PDWORD functionAddress = (PDWORD)0;
	
	// Get ntdll base address
	HMODULE libraryBase = LoadLibraryA("ntdll");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	// Locate export address table
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Offsets to list of exported functions and their names
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions of ntdll
	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		// Resolve exported function name
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		
		// Resolve exported function address
		DWORD_PTR functionAddressRVA = 0;
		functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

		// Syscall stubs start with these bytes
		unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

		// Only interested in Nt|Zw functions
		if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
		{
			// Check if the first 4 instructions of the exported function are the same as the sycall's prologue
			if (memcmp(functionAddress, syscallPrologue, 4) != 0) {
			
				if (*((unsigned char*)functionAddress) == 0xE9) // first byte is a jmp instruction, where does it jump to?
				{
					DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
					PDWORD jumpTarget = functionAddress + 5 /*Instruction pointer after our jmp instruction*/ + jumpTargetRelative;  
					char moduleNameBuffer[512];
					GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
					
					printf("Hooked: %s : %p into module %s\n", functionName, functionAddress, moduleNameBuffer);
				}
				else
				{
					printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
				}
			
			
				
			}
		}
	}

	return 0;
}
```

## Demo

Below is a snippet of the output of the program compiled from the above source code and run on a system with an EDR present. It shows some of the interesting functions (not all displayed) that are most likely hooked, with an exception of `NtGetTickCount`, which is a false positive, as mentioned earlier:

![Usual suspects hooked + some false positives](<../../.gitbook/assets/image (717).png>)

## Updates

After I've posted this note on my twitter, I got a message from someone who is smarter than I am suggesting to check if the `syscall` instruction itself is not hooked. The `syscall` handler routine (responsible for locating functions in the [SSDT](../../miscellaneous-reversing-forensics/windows-kernel-internals/glimpse-into-ssdt-in-windows-x64-kernel.md) based on a syscall number) location can be found by reading the Model Specific Register (MSR) at location `0xc0000082` and confirming that the address stored there points to `nt!KiSystemCall64Shadow`.

Below shows how this could be done manually in WinBDG:

```
lkd> rdmsr c0000082
msr[c0000082] = fffff803`24a13180

lkd> u fffff803`24a13180
nt!KiSystemCall64Shadow:
fffff803`24a13180 0f01f8          swapgs
fffff803`24a13183 654889242510900000 mov   qword ptr gs:[9010h],rsp
```

![](<../../.gitbook/assets/image (719).png>)

## References

{% embed url="https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa" %}

{% embed url="https://rayanfam.com/topics/hypervisor-from-scratch-part-8/" %}
