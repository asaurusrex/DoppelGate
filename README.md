# DoppelGate

## Disclaimer
DO NOT use this project for purposes other than legitimate red teaming/pentesting jobs, or research.  DO NOT use this for illegal activity of any kind, and know that this project is intended for research purposes and to help advance the missions of both red and blue teams.  

## Purpose 
This project is designed to provide a method of extracting syscalls dynamically directly from on-disk ntdll.  Userland hooks have become prevalent in many security products these days, and bypassing these hooks is a great way for red teamers/pentesters to bypass these defenses.   

## Methodology
The reason that this project is named DoppelGate is due to the borrowing of ideas/techniques used in Process Doppelganging and Hell's Gate.  There was a technique called Process Doppelganging which came out in 2017, and relied on making use of Microsoft NTFS Transactions (TxF) to perform remote process injection (see https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf).  The idea was that code could be written to a process memory space, mapped, and then removed before any changes were "committed" - in essence malicious code would never touch disk.  Although this technique has been around for several years, I wondered if NTFS Transactions could be abused in other ways.  After some experimentation, I found that TxF can be used to grab the file handle for ntdll while avoiding NtOpenFile (it does rely on NtCreateFile).  I tested out and have included two generalized approaches for this method to work, combining this with the way that Hell's Gate does its dynamic patching of the system calls.    Three overall approaches could be utilized for this method. 

1.  Read the handle for ntdll.dll directly using CreateFileTransactedA, and then call NtReadFile on that handle.  Parse the bytes from NtReadFile directly.

2.  Copy ntdll to an arbitrary dll in an arbitrary directory you will have write access to using CopyFileTransactedA on ntdll.  Use NtReadFile on your arbitrary dll vs ntdll.  This approach tends to be much louder, as many calls to NtReadFile, NtCreateFile, and NtWriteFile will be made in order to copy the data from ntdll to your arbitary dll.  However, assuming you don't commit the transaction, your arbitrary dll never actually exists on disk, which was an interesting discovery.  

3.  You could always call NtCreateFile on ntdll directly and then use NtReadFile on the resulting handle, and then parse these bytes in memory. 


## Opsec Concerns
As pointed out by others in their various blog posts/projects, the problem with all of these approaches is that if a defensive product hooks NtReadFile, and catches that you are reading ntdll.dll, they can block you.   This is true, and these approaches DO NOT solve this problem.  I was curious if Transactions could be used to slightly obfuscate the technique, but it appears not to be the case.  However, if you have any ideas/suggestions of how to get around this using Transactions, let me know!  I recommend that if you want to utilize this technique, you combine it with another technique to unhook functions first, preferably hard-coded syscalls or Hell's Gate.  Hell's Gate -> DoppelGate would likely give you the most robust solution with little possibility of error, since all syscalls would be fetched dynamically for you. Hard-coded syscalls -> DoppelGate might be slightly safer from an opsec perspective, but more prone to failure if your initial hard-coded syscalls are wrong for the operating system.  You need to obfuscate 2 (or 3 at most) functions to use DoppelGate with lower (never say never) rates of detection, and these functions are: NtCreateTransaction, NtReadFile, and optionally NtCreateFile (if using the 3rd approach listed in Methodology).  In the code sample I have included ways to both only use DoppelGate as well as to combine SysWhispers with DoppelGate as an example (to use SysWhispers comment out the ntdll.lib line in Header.h, and include SysWhispers.h and SysWhispers.asm in the compilation of DoppelGate).  Only the first two approaches listed in Methodology exist in the code, but the third could easily be introduced.  

Additionally, when calling functions with DoppelGate, leaving the desired functions in plaintext is not ideal from an opsec perspective.  If you can provide some custom encoding/encryption method for the function names, it would greatly help with anti-forensics/potentially EDR evasion. 

NOTE:  DoppelGate does not rely on CreateFileMapping to map the bytes from ntdll into memory, but parses through the PE in memory directly.  This requires slightly more work, and was definitely a fun challenge.  This enables us to avoid calling NtCreateSection and NtMapViewofSection, and only rely on NtReadFile.  

If you are interested in the technical details, please proceed to the Technical Nitty Gritty section below.


## Detection/Prevention
If defense products are tuned to prevent NTFS Transactions or flag on them (similar to Process Doppelganging, especially on CreateFileTransacted and CopyFileTranscated), that would provide insight into/prevent this method (at least the first two approaches) being used.  As mentioned previously, hooks on NtReadFile will also prevent this technique, unless other obfuscation is used, as it is odd to load ntdll directly from disk.

Other defenses would need to rely on detecting userland unhooking via kernel hooks, such as discussed on https://www.crummie5.club/freshycalls/#and-finally-our-library regarding the ScyllaHide repo, or some other kernel hooks.  

## Testing 
This technique has mostly been tested on various versions of Windows 10, please feel free to test on any version of Windows >= Windows Vista (Transactions were not introduced until Windows Vista).  This approach SHOULD work on x86 and x64.  Let me know if you have any errors.


## Technical Nitty Gritty
Using whichever method you wish to use, you will eventually get access to the bytes in ntdll.dll.  We will allocate memory for these bytes, and then parse these bytes as a PE, following https://www.ired.team/miscellaneous-reversing-forensics/pe-file-header-parser-in-c++ exactly, until we reach the PIMAGE_IMPORT_DESCRIPTOR.  For our purposes, we are not interested in imports, but the exports of ntdll (this is where the nt functions, or at least most of them, will live within ntdll).  We will check the exportDirectoryRVA and use it to find the export section, making sure it is not null (that there ARE exported functions)

We will then set up our IMAGE_EXPORT_DIRECTORY based on our export section and the IMAGE_DIRECTORY_ENTRY_EXPORT of our OptionalHeader (this will all be shown in code below, don't worry).  Once we have our IMAGE_EXPORT_DIRECTORY set up, we use it to retrieve pointers to our Address of Functions (array containing actual addresses of the functions), Address of Names (array containing function names), and Address of NameOrdinales (array that acts an index for the FunctionAddress Array).  We need to make sure that because our PE is not mapped with CreateFileMapping that the proper RVA offsets are calculated.  I have included a function to take care of this called RVAToOffset.  

The general formula for this offset is (we will use AddressofNameOrdinals as an example): start_address of bytes + EXPORT_DIRECTORY->AddressofNames - exportsection->VirtualAddress + exportsection->PointerToRawData.  This formula did not quite work for AddressofFunctions (only in Windows 10, it worked in Win7-8), although the RVAToOffset function fixes this issue - it seems that the section headers need to be recalculated repeatedly to make this work, still not entirely sure why.  If someone looks at the code and something immediately sticks out, please feel to let me know.     

We will cycle through each function in our bytes until we find our desired function name, such as NtAllocateVirtualMemory.  We will then fetch the function address from our AddressofFunctions and AddressofNameOrdinales.
If all has gone well, the first six bytes should contain our syscall, specifically the fifth and sixth bytes.  

You can read more about the EXPORT DIRECTORY at https://resources.infosecinstitute.com/topic/the-export-directory/.

If you are lost at this point, don't worry!  It often helps to see examples.  Here is the relevant code for what we have described:


```
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
```

I have tried to comment my code as much as I can, so hopefully that will help with following it.  If you have any questions, please feel free to give me a shout.  

## API Monitor Results:
NOTE: Approach 1 = Approach 1 in Methodology section, etc.

If you're still reading, I ran some tests with API Monitor to see which calls would be activated by this method.  As expected, if obfuscating your initial functions (like NtReadFile) with other methods, the only call detected for Approach #1 is one call to CreateFile (from CreateFileTransacted on ntdll).  Without using any obfuscation, calls to NtCreateTransaction, NtCreateFile, and NtReadfile are triggered, but only once each (3 total!).  That is pretty small.

If you obfuscate your calls but use Approach #2, you will trigger various calls to NtCreateFile, NtReadFile, and NtWriteFile (21 calls in all - not nearly as good, but if undetected your evidence might be less -> the defensive products might get hung up on what your arbitrary dll is, especially since it does not exist on disk.)  If you do no obfuscation, the same calls are generated, and it appears to be about 22 separate triggers (obfuscation does not help a lot since most of the calls come directly from CopyFileTransacted).   

I did not test Approach 3, but with proper obfuscation I expect it would generate 0 triggers.  Without obfuscation, it would create at least 2.   

I will try to upload photos of these results later.

## Contributions/Comments/Criticisms
I am very open to receiving comments and to collaboration!  Hopefully this helps generate useful discussion around the topic of userland unhooking, or provides researchers some new insights.  

## Acknowledgements

Many great projects have recently covered this topic, including the Hell's Gate Project (https://github.com/am0nsec/HellsGate), Freshycalls (https://github.com/Crummie5/Freshycalls_PoC/, https://www.crummie5.club/freshycalls/#and-finally-our-library), ShellyCoat (https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/README.md), and the SysWhispers project (https://github.com/jthuraisamy/SysWhispers).  A great explanation of unhooking based on mapping a clean copy of ntdll over a hooked one can be found at (https://www.solomonsklash.io/pe-parsing-defeating-hooking.html).  This, as well as the Hell's Gate paper, does a great job at walking users through PE parsing and what it will accomplish - a lot of DoppelGate code is borrowed directly from Hell's Gate.    

In addition, a lot of this code came directly from https://www.ired.team/miscellaneous-reversing-forensics/pe-file-header-parser-in-c++, which gave an amazing demonstration of how to parse a PE directly in memory, with no CreateFileMapping calls.  Ired.team has a TON of great content, and I highly highly recommend them as a resource on learning various offensive techniques.  

Special thanks to:

**Solomon Sklash** who has a great blog with lots of great info, located here: https://www.solomonsklash.io) who helped me understand many pieces of this puzzle, especially RVA offsets, and who brought NTFS transactions to my attention in the first place

**am0nsec** who helped me digest and understand Hell's Gate, as well as helping explain RVA offsets when parsing a PE directly in memory

**thewover** who always answers my millions of questions with the utmost patience 

## Social Media
Feel free to message me with questions about DoppelGate on the BloodHoundGang slack, my handle is AsaurusRex


## Future Ideas
The quest continues to find a way to dynamically fetch syscalls from ntdll on-disk without calling NtReadFile, NtMapViewofSection, NtCreateSection, or NtCreateFile.  If someone comes up with an alternate way to do this, please let me know!
