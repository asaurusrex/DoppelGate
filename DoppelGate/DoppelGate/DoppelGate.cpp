
#include "Header.h"
#include "Syswhispers.h"




extern "C" VOID DoppelGate(DWORD wSystemCall); //these extern functions work with compilation.asm to use DoppelGate to replace nt function bytes to userland unhook

extern "C" NTSTATUS DoppelDescent();


//This project is a Windows App - if you want to see the print statements, you need to make it a console application.  This was to prevent api calls that were from printing to console from being monitored.



DWORD RVAToOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD dwRVA)
{
	//This code will correctly calculate RVA offsets based on the fact that ntdll bytes are not mapped into memory - it makes sure the Section Header is correct for each nt function and each OS

	int nSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	nSections = pNtHeaders->FileHeader.NumberOfSections;
	for (int i = 0; i < nSections; i++)
	{
		if (pSectionHeader->VirtualAddress <= dwRVA)
			if ((pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) > dwRVA)
			{
				dwRVA -= pSectionHeader->VirtualAddress;
				dwRVA += pSectionHeader->PointerToRawData;
				return dwRVA;
			}
		pSectionHeader++;
	}
	return 0;
}


int retrieve_syscall(LPVOID fileData, PVX_TABLE_ENTRY pVxTableEntry, const char* FunctionName) //this function retrieve the syscall for any Nt Function from our ntdll data read into memory
{

	//most of this code is borrowed from the ired.team post on PE parsing  - I kept in all of these print statements for debugging purposes, as well as to demonstrate the different parts of the PE
	//as we parse it

	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;
	PIMAGE_SECTION_HEADER exportSection = {};


	//parse the DLL into PE format:


	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	printf("******* DOS HEADER *******\n");
	printf("\t0x%x\t\tMagic number\n", dosHeader->e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t0x%x\t\tPages in file\n", dosHeader->e_cp);
	printf("\t0x%x\t\tRelocations\n", dosHeader->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tChecksum\n", dosHeader->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", dosHeader->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", dosHeader->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", dosHeader->e_lfanew);

	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((PBYTE)fileData + (DWORD)dosHeader->e_lfanew);
	printf("\n******* NT HEADERS *******\n");
	printf("\t%x\t\tSignature\n", imageNTHeaders->Signature);

	// FILE_HEADER
	printf("\n******* FILE HEADER *******\n");
	printf("\t0x%x\t\tMachine\n", imageNTHeaders->FileHeader.Machine);
	printf("\t0x%x\t\tNumber of Sections\n", imageNTHeaders->FileHeader.NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", imageNTHeaders->FileHeader.TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", imageNTHeaders->FileHeader.PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", imageNTHeaders->FileHeader.NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", imageNTHeaders->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	printf("\n******* OPTIONAL HEADER *******\n");
	printf("\t0x%x\t\tMagic\n", imageNTHeaders->OptionalHeader.Magic);
	printf("\t0x%x\t\tMajor Linker Version\n", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
	printf("\t0x%x\t\tMinor Linker Version\n", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
	printf("\t0x%x\t\tSize Of Code\n", imageNTHeaders->OptionalHeader.SizeOfCode);
	printf("\t0x%x\t\tSize Of Initialized Data\n", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
	printf("\t0x%x\t\tSize Of UnInitialized Data\n", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t0x%x\t\tBase Of Code\n", imageNTHeaders->OptionalHeader.BaseOfCode);
	//printf("\t0x%x\t\tBase Of Data\n", imageNTHeaders->OptionalHeader.BaseOfData);
	printf("\t0x%x\t\tImage Base\n", imageNTHeaders->OptionalHeader.ImageBase);
	printf("\t0x%x\t\tSection Alignment\n", imageNTHeaders->OptionalHeader.SectionAlignment);
	printf("\t0x%x\t\tFile Alignment\n", imageNTHeaders->OptionalHeader.FileAlignment);
	printf("\t0x%x\t\tMajor Operating System Version\n", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinor Operating System Version\n", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajor Image Version\n", imageNTHeaders->OptionalHeader.MajorImageVersion);
	printf("\t0x%x\t\tMinor Image Version\n", imageNTHeaders->OptionalHeader.MinorImageVersion);
	printf("\t0x%x\t\tMajor Subsystem Version\n", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
	printf("\t0x%x\t\tMinor Subsystem Version\n", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32 Version Value\n", imageNTHeaders->OptionalHeader.Win32VersionValue);
	printf("\t0x%x\t\tSize Of Image\n", imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("\t0x%x\t\tSize Of Headers\n", imageNTHeaders->OptionalHeader.SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", imageNTHeaders->OptionalHeader.CheckSum);
	printf("\t0x%x\t\tSubsystem\n", imageNTHeaders->OptionalHeader.Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", imageNTHeaders->OptionalHeader.DllCharacteristics);
	printf("\t0x%x\t\tSize Of Stack Reserve\n", imageNTHeaders->OptionalHeader.SizeOfStackReserve);
	printf("\t0x%x\t\tSize Of Stack Commit\n", imageNTHeaders->OptionalHeader.SizeOfStackCommit);
	printf("\t0x%x\t\tSize Of Heap Reserve\n", imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
	printf("\t0x%x\t\tSize Of Heap Commit\n", imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
	printf("\t0x%x\t\tLoader Flags\n", imageNTHeaders->OptionalHeader.LoaderFlags);
	printf("\t0x%x\t\tNumber Of Rva And Sizes\n", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	printf("\n******* DATA DIRECTORIES *******\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[1].Size);

	// SECTION_HEADERS
	printf("\n******* SECTION HEADERS *******\n");
	// get offset to first section headeer
	LPBYTE sectionLocation = (LPBYTE)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD exportDirectoryRVA = (DWORD)imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	// print section data
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
		printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}

		//we are more interested in the export section, as we want to find all of the functions that ntdll is exporting.  This is where our code diverges from the ired.team code 
		if (exportDirectoryRVA >= sectionHeader->VirtualAddress && exportDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			exportSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}
	// get file offset to export table
	/*  Check if there is an export section - if there is not, this will prevent an error.  ntdll should always have an export section, but not every dll will. */
	if (exportSection != NULL)
	{
		printf("[*] Exports exist, parsing them now\n");
		printf("[*] pExportSection 0x%p\n", exportSection);

		//rawOffset = (PBYTE)fileData + exportSection->PointerToRawData;
		//PBYTE rawOffset = (PBYTE)fileData + exportSection->PointerToRawData;

		PIMAGE_EXPORT_DIRECTORY exportDescriptor = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)fileData + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - exportSection->VirtualAddress + exportSection->PointerToRawData));
		printf("\n******* DLL EXPORTS *******\n");

		//DEFINE FUNCTION HERE



		PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)fileData + (DWORD)RVAToOffset(imageNTHeaders, exportDescriptor->AddressOfFunctions));
		PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)fileData + exportDescriptor->AddressOfNames - exportSection->VirtualAddress + exportSection->PointerToRawData);
		PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)fileData + exportDescriptor->AddressOfNameOrdinals - exportSection->VirtualAddress + exportSection->PointerToRawData);



		for (WORD cx = 0; cx < exportDescriptor->NumberOfNames; cx++) {

			//This should work for all versions of Windows

			char* pczFunctionName = (char*)((PBYTE)fileData + pdwAddressOfNames[cx] - exportSection->VirtualAddress + exportSection->PointerToRawData); //points to Function Name

			PVOID pFunctionAddress = (PVOID)((PBYTE)fileData + RVAToOffset(imageNTHeaders, pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]])); //points to actual Function Address

			//windows 10 the symbolFileOffset is needed - for Windows 7-8 the offset value wasn't needed.  If someone can explain this, please reach out.  RVAToOffset function takes care of this for us
			//so seems to be a section header problem.
			// char* pczFunctionName = (char*)((PBYTE)fileData + pdwAddressOfNames[cx] - exportSection->VirtualAddress + exportSection->PointerToRawData);
			// DWORD symbolFileOffset = (pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]] - exportSection->VirtualAddress) + exportSection->PointerToRawData;
			// symbolFileOffset += 0x1a00;

			// PVOID pFunctionAddress = (PVOID)((PBYTE)fileData + symbolFileOffset);



			if (strcmp(pczFunctionName, FunctionName) == 0)  //you opsec purposes, you probably would want to obfuscate the function names so they are not in plaintext in the code
			{
				printf("Ordinal: %d\n", pwAddressOfNameOrdinales[cx]);
				printf("%02X\n", pFunctionAddress);

				//follow the same approach as Hell's Gate to actually fetch the syscall and patch it
				WORD i = 0;
				while (TRUE) {
					// check if syscall, in this case we are too far
					if (*((PBYTE)pFunctionAddress + i) == 0x0f && *((PBYTE)pFunctionAddress + i + 1) == 0x05)
					{
						return FALSE;
					}
					// check if ret, in this case we are also probaly too far
					if (*((PBYTE)pFunctionAddress + i) == 0xc3)
					{
						return FALSE;
					}
					// First opcodes should be :
					//    MOV R10, RCX
					//    MOV RCX, <syscall>

					//print first 8 bytes of function
					printf("1st byte: 0x%x\n", *((PBYTE)pFunctionAddress + i));
					printf("2nd byte: 0x%x\n", *((PBYTE)pFunctionAddress + 1 + i));
					printf("3rd byte: 0x%x\n", *((PBYTE)pFunctionAddress + 2 + i));
					printf("4th byte: 0x%x\n", *((PBYTE)pFunctionAddress + 3 + i));
					printf("5th byte: 0x%x\n", *((PBYTE)pFunctionAddress + 4 + i));
					printf("6th byte: 0x%x\n", *((PBYTE)pFunctionAddress + 5 + i));
					printf("7th byte: 0x%x\n", *((PBYTE)pFunctionAddress + 6 + i));
					printf("8th byte: 0x%x\n", *((PBYTE)pFunctionAddress + 7 + i));

					

					if (*((PBYTE)pFunctionAddress + i) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + i) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + i) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + i) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + i) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + i) == 0x00) {
						
						//these bytes are both needed, as some syscalls are functionally more than 1 byte in length: think 0x03d (NtQueryAttributesFile)  vs 0x013d (NtQueryAuxiliaryCounterFrequency)
						BYTE high = *((PBYTE)pFunctionAddress + 5 + i);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + i);

						pVxTableEntry->wSystemCall = (high << 8) | low; //this will put the correct syscall in place
						printf("Syscall for %s is: %X", pczFunctionName, pVxTableEntry->wSystemCall);  //print the syscall
						break; //break the while loop once conditions are met
					}

					i++;

				}
			}
		}
	}
	else {
		printf("\nNo export section detected, exiting...");
		exit(EXIT_FAILURE);
	}
	return pVxTableEntry->wSystemCall;  //this is for debugging, this can be changed to any int
}

int main(int argc, char** argv) {

	// This section is to define x86/x64 requirements, following Hell's Gate model

	unsigned char __readgsbyte(
		unsigned long Offset
	);
	unsigned short __readgsword(
		unsigned long Offset
	);
	unsigned long __readgsdword(
		unsigned long Offset
	);
	unsigned __int64 __readgsqword(
		unsigned long Offset
	);

	//x64
	PPEB Peb = (PPEB)__readgsqword(0x60);

	//x86
	//PPEB Peb = (PPEB)__readgsqword(0x30);

	PLDR_MODULE pLoadModule1;
	PBYTE ImageBase;
	PIMAGE_DOS_HEADER Dos = NULL;
	PIMAGE_NT_HEADERS Nt = NULL;
	PIMAGE_FILE_HEADER File = NULL;
	PIMAGE_OPTIONAL_HEADER Optional = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportTable = NULL;
	HANDLE hTransaction;

	//create a transaction
	NTSTATUS status = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, NULL, NULL, NULL, NULL, 0, 0, NULL, NULL);

	printf("status is %X\n", status);
	//we will use this transaction handle to get a handle to ntdll


	HANDLE hFile;
	
	//Two techniques are presented below: Copy ntdll bytes into a new dll of your choice, or call NtCreateFile on ntdll.dll directly with CreateFileTransacted from the Transaction Handle
	
	//Technique 1: to copy ntdll to a new file, and then read from that file.  Generally louder, as more calls to ReadFile for ntdll, but an alternate technique that does work.

	
	 //Uncomment this for copy method - this copies ntdll bytes into test.dll, from which you can then pull syscalls.
	/*
	BOOL copy_success = FALSE;
	LPPROGRESS_ROUTINE LpprogressRoutine = NULL;
	copy_success = CopyFileTransactedA("C:\\Windows\\System32\\ntdll.dll", "C:\\Users\\Public\\test.dll", LpprogressRoutine, NULL, FALSE, COPY_FILE_COPY_SYMLINK, hTransaction);

	hFile = CreateFileTransactedA("C:\\Users\\Public\\test.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL, hTransaction, NULL, NULL);
	printf("Error is %d\n", GetLastError());
	*/


	//Get size from above as an alternative to using GetFileSizeEx

	
	
	

	//Technique 2: Create transacted file from ntdll to get a file handle to use for ReadFile - this avoids OpenFile on ntdll. It does NOT avoid NtCreateFile


	  //Uncomment this for direct CreateFile method, no copy.  Tends to be quieter.
	hFile = CreateFileTransactedA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL, hTransaction, NULL, NULL);

	printf("Error is %d\n", GetLastError());
	
	//If you wanted to bypass transactions altogether, you could use NtOpenFile or NtCreateFile directly to fetch a handle to ntdll.dll

	//fetch your file_size
	SIZE_T file_size = 0;

	GetFileSizeEx(hFile, (PLARGE_INTEGER)&file_size);  //this is the easy way to get the file size, but you could fetch it with other methods that don't rely on the api.

	LPVOID fileData = malloc(file_size);  //carve out space for our file bytes
	DWORD bytes_to_read = file_size;

	IO_STATUS_BLOCK ol;
	status = NtReadFile(hFile, NULL, NULL, NULL, &ol, fileData, bytes_to_read, NULL, NULL); //read the bytes from our CreateFileTransacted Handle

	//this is totally optional, but we can close our old file handle now as we have all the bytes we need to parse.
	status = NtClose(hFile);

	printf("status is %X\n", status);


	//DoppelGate example of calling NtRollbackTransaction to rollback our transaction

	const char* function;
	VX_TABLE Table = { 0 }; //initialize VX_TABLE - this follows Hell's Gate Method


	function = "NtRollbackTransaction";  //name our function, and then fetch the appropriate bytes for our function with the retrieve_syscall function
	retrieve_syscall(fileData, &Table.NtRollbackTransaction, function);

	//example of calling NtRollbackTransaction with DoppelGate
	
	PVX_TABLE pVxTable = &Table;

	DoppelGate(pVxTable->NtRollbackTransaction.wSystemCall);
	NtRollbackTransactionDelegate NtRollbackTransaction = (NtRollbackTransactionDelegate)DoppelDescent;
	status = NtRollbackTransaction(hTransaction, TRUE);
	wprintf(L"Status is %X", status);
	

	
	
	
	//NTSTATUS status;
	//PVX_TABLE pVxTable = &Table;

	// DoppelGate example of calling NtAllocateVirtualMemory

	function = "NtAllocateVirtualMemory"; //name our function, and then fetch the appropriate bytes for our function
	retrieve_syscall(fileData, &Table.NtAllocateVirtualMemory, function);

	DoppelGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);

	LPVOID baseaddr = NULL;
	SIZE_T size = 40000;
	NtAllocateVirtualMemoryDelegate NtAllocateVirtualMemory = (NtAllocateVirtualMemoryDelegate)DoppelDescent;
	status = NtAllocateVirtualMemory(GetCurrentProcess(), &baseaddr, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	wprintf(L"\nStatus is %X", status);
	
	//free(baseaddr);
	free(fileData);
	//Sleep(600000000000000000);  this is for debug purposes with API Monitor
	return 0;
}




