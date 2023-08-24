// Uriel Dolev 215676560
// OS - Final Project
// IAT Hooking DLL

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#define DEFAULT_IPv4_ADRESS "127.0.0.1"

DWORD saved_hooked_func_addr;


extern "C"
{
	// hook function, based on Barak Gonen's book
	int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_address) {
		PIMAGE_DOS_HEADER dosHeader;
		PIMAGE_NT_HEADERS NTHeader;
		PIMAGE_OPTIONAL_HEADER32 optionalHeader;
		IMAGE_DATA_DIRECTORY importDirectory;
		DWORD descriptorStartRVA;
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
		int index;

		// Get base address of currently running .exe
		DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

		// Get the import directory address
		dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);

		if (((*dosHeader).e_magic) != IMAGE_DOS_SIGNATURE) {
			return 0;
		}

		// Locate NT header
		NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + (*dosHeader).e_lfanew);
		if (((*NTHeader).Signature) != IMAGE_NT_SIGNATURE) {
			return 0;
		}

		// Locate optional header
		optionalHeader = &(*NTHeader).OptionalHeader;
		if (((*optionalHeader).Magic) != 0x10B) {
			return 0;
		}

		importDirectory = (*optionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		descriptorStartRVA = importDirectory.VirtualAddress;
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + descriptorStartRVA);

		index = 0;
		char* DLL_name;
		// Look for the DLL which includes the function for hooking
		while (importDescriptor[index].Characteristics != 0) {
			DLL_name = (char*)(baseAddress + importDescriptor[index].Name);
			printf("DLL name: %s\n", DLL_name);
			if (!strcmp(DLL_to_hook, DLL_name))
				break;
			index++;
		}

		// exit if the DLL is not found in import directory
		if (importDescriptor[index].Characteristics == 0) {
			printf("DLL was not found");
			return 0;
		}

		// Search for requested function in the DLL
		PIMAGE_THUNK_DATA thunkILT; // Import Lookup Table - names
		PIMAGE_THUNK_DATA thunkIAT; // Import Address Table - addresses
		PIMAGE_IMPORT_BY_NAME nameData;

		thunkILT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].OriginalFirstThunk);
		thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].FirstThunk);
		if ((thunkIAT == NULL) or (thunkILT == NULL)) {
			return 0;
		}

		while (((*thunkILT).u1.AddressOfData != 0) & (!((*thunkILT).u1.Ordinal & IMAGE_ORDINAL_FLAG))) {
			nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + (*thunkILT).u1.AddressOfData);
			if (!strcmp(func_to_hook, (char*)(*nameData).Name))
				break;
			thunkIAT++;
			thunkILT++;
		}

		// Hook IAT: Write over function pointer
		DWORD dwOld = NULL;
		saved_hooked_func_addr = (*thunkIAT).u1.Function;
		VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
		(*thunkIAT).u1.Function = new_func_address;
		VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), dwOld, NULL);

		return 1;
	};

	// Client (based on msdn's documentation)
	// The Client will send a message to the Server everytime CreateFile is being called in Notepad
	int SendMsg()
	{
		WSADATA wsaData;
		SOCKET ConnectSocket = INVALID_SOCKET;
		struct addrinfo* result = NULL,
			* ptr = NULL,
			hints;
		const char* sendbuf = "Hooked successfuly!\n";
		char recvbuf[DEFAULT_BUFLEN];
		int iResult;
		int recvbuflen = DEFAULT_BUFLEN;

		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			printf("WSAStartup failed with error: %d\n", iResult);
			return 1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// Resolve the server address and port
		iResult = getaddrinfo(DEFAULT_IPv4_ADRESS, DEFAULT_PORT, &hints, &result);
		if (iResult != 0) {
			printf("getaddrinfo failed with error: %d\n", iResult);
			WSACleanup();
			return 1;
		}

		// Attempt to connect to an address until one succeeds
		for (ptr = result; ptr != NULL;ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
				ptr->ai_protocol);
			if (ConnectSocket == INVALID_SOCKET) {
				printf("socket failed with error: %ld\n", WSAGetLastError());
				WSACleanup();
				return 1;
			}

			// Connect to server.
			iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				closesocket(ConnectSocket);
				ConnectSocket = INVALID_SOCKET;
				continue;
			}
			break;
		}

		freeaddrinfo(result);

		if (ConnectSocket == INVALID_SOCKET) {
			printf("Unable to connect to server!\n");
			WSACleanup();
			return 1;
		}

		// Send an initial buffer
		iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
		if (iResult == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}

		printf("Bytes Sent: %ld\n", iResult); // won't happen in our programm, used for Echo

		// shutdown the connection since no more data will be sent
		iResult = shutdown(ConnectSocket, SD_SEND);
		if (iResult == SOCKET_ERROR) {
			printf("shutdown failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}

		// Receive until the peer closes the connection
		// won't happen in our programm, used for Echo
		do {

			iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
			if (iResult > 0)
				printf("Bytes received: %d\n", iResult); 
			else if (iResult == 0)
				printf("Connection closed\n");
			else
				printf("recv failed with error: %d\n", WSAGetLastError());

		} while (iResult > 0);

		// cleanup
		closesocket(ConnectSocket);
		WSACleanup();

		// Clear stack to keep the program from collapsing
		_asm {
			pop     edi; Restore Registers
			pop     esi
			pop     ebx
			add     esp, 0C0h; Clear Local Variables
			mov     esp, ebp; Restore ESP
			pop     ebp; Restore EBP
			jmp     saved_hooked_func_addr; Jump Back To CreateFileW
		}

		return 0;
	}
}

BOOL APIENTRY DllMain(
	HANDLE hModule, // Handle to DLL module
	DWORD ul_reason_for_call,
	LPVOID lpReserved) // Reserved
{
	PCSTR func_to_hook = "CreateFileW";
	PCSTR DLL_to_hook = "KERNEL32.dll";
	DWORD new_func_address = (DWORD)&SendMsg;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// A process is loading the DLL.
		hook(func_to_hook, DLL_to_hook, new_func_address);
		break;
	case DLL_THREAD_ATTACH:
		// A process is creating a new thread.
		break;
	case DLL_THREAD_DETACH:
		// A thread exits normally.
		break;
	case DLL_PROCESS_DETACH:
		// A process unloads the DLL.
		break;
	}
	return TRUE;
}