// Uriel Dolev 215676560
// OS - Final Project
// IAT Hooking DLL Injector

#include <windows.h>
#include <iostream>
#include <tlhelp32.h> 

#define DLL_NAME "FinalProjectDLL.dll" // short dll name for getFullPathNameA
#define PROCESS_NAME L"notepad++.exe"

// Finds a running process' pid (based on StackOverFlow's documantation)
DWORD FindProcessId(const std::wstring& processName);

int main()
{
	// Get PID of wanted process
	DWORD pid;
	do
	{
		pid = FindProcessId(PROCESS_NAME);
	} while (!pid); // Wait until there's an open process

	// Get full path of DLL to inject
	CHAR fullPath[MAX_PATH];
	DWORD pathLen = GetFullPathNameA(DLL_NAME, MAX_PATH, fullPath, NULL);
	// Check if we got the full path as expected
	if (!pathLen)
	{
		DWORD err = GetLastError();
		printf("ERROR: can't get DLL's full path\nError number: %d", err);
		return -1;
	}

	// Get LoadLibrary function address –
	// the address doesn't change at remote process, it will always be in "kernel32.dll" as checked
	PVOID addrLoadLibrary = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	// Check if we got the adress as expected
	if (addrLoadLibrary == NULL)
	{
		DWORD err = GetLastError();
		printf("ERROR: can't get LoadLibraryA's adress\nError number: %d", err);
		return -1;
	}

	// Open remote process
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, // desired access
		FALSE,  // inheritans for created process, not needed
		pid); // desired process id
	// Check if the opening ended succesfuly
	if (proc == NULL)
	{
		DWORD err = GetLastError();
		printf("ERROR: can't open process %d\nError number: %d", pid, err);
		return -1;
	}

	// Get a pointer to memory location in remote process,
	// big enough to store DLL path
	PVOID memAddr = (PVOID)VirtualAllocEx(proc, // desired process to allocate memory in (handle) 
		NULL, // where to start the memory region, NULL means 
			  // the function determines where to allocate the region.
		strlen(fullPath) + 1, // size of memory to allocate (bytes)
		MEM_COMMIT | MEM_RESERVE, // memory allocation type
		PAGE_READWRITE); // desired access to the memory
	// Check if the memory was allocated successfuly
	if (memAddr == NULL) {
		DWORD err = GetLastError();
		printf("ERROR: couldn't allocate memory in process %d\nError number: %d\n", pid, err);
		return -1;
	}

	// Write DLL name to remote process memory
	BOOL check = WriteProcessMemory(proc, // desired process to write to (handle)
		memAddr, // pointer to the memory to check if we can write to it
		fullPath, // pointer to the buffer that we want to write from
		strlen(fullPath) + 1, // number of bytes we want to write
		NULL); // NULL means this parameter is ignored
	// Check if we wrote successfuly
	if (check == FALSE) {
		DWORD err = GetLastError();
		printf("ERROR: couldn't write to process %d memory\n Error number: %d\n", pid, err);
		return -1;
	}

	// Open remote thread, while executing LoadLibrary
	// with parameter DLL name, will trigger DLLMain
	HANDLE hRemote = CreateRemoteThread(proc, // desired process to create thred in (handle)
		NULL, // security attirbutes, NULL - defulat
		0,    // stack size, 0 means default executable stack size
		(LPTHREAD_START_ROUTINE)addrLoadLibrary, // represents LoadLibraryA, the function we want to use
		memAddr, // the library we want to load
		0,	  // not important
		NULL); // not important
	// Check if we opperated succussfuly in the process
	if (hRemote == NULL) {
		DWORD err = GetLastError();
		printf("ERROR: couldn't load from process %d memory\nError number: %d\n", pid, err);
		return -1;
	}

	WaitForSingleObject(hRemote, INFINITE);
	check = CloseHandle(hRemote);
	return 0;
}

DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}