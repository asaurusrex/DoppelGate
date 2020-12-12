/*
BSD 4-Clause License

Copyright (c) 2020, asaurusrex
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
   
3. All advertising materials mentioning features or use of this software must display the following acknowledgement:
   This product includes software developed by AsaurusRex.

4. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
*/

#pragma once
#include <stdio.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <time.h> 
#include <windows.h>
#include <stdint.h>
#include <string>

//#include "winternl.h"
#pragma comment(lib, "ntdll.lib") //this is included to call our earlier nt functions, such as NtReadFile, NtCreateTransaction, etc.  For opsec you should use some other unhooking method to unhook these functions before you call them.


typedef struct _LSA_UNICODE_STRING { USHORT Length;     USHORT MaximumLength;     PWSTR  Buffer; } LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_MODULE { LIST_ENTRY              InLoadOrderModuleList;     LIST_ENTRY              InMemoryOrderModuleList;     LIST_ENTRY              InInitializationOrderModuleList;     PVOID                   BaseAddress;     PVOID                   EntryPoint;     ULONG                   SizeOfImage;     UNICODE_STRING          FullDllName;     UNICODE_STRING          BaseDllName;     ULONG                   Flags;     SHORT                   LoadCount;     SHORT                   TlsIndex;     LIST_ENTRY              HashTableEntry;     ULONG                   TimeDateStamp; } LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA { ULONG                   Length;     ULONG                   Initialized;     PVOID                   SsHandle;     LIST_ENTRY              InLoadOrderModuleList;     LIST_ENTRY              InMemoryOrderModuleList;     LIST_ENTRY              InInitializationOrderModuleList; } PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;     BOOLEAN                 ReadImageFileExecOptions;     BOOLEAN                 BeingDebugged;     BOOLEAN                 Spare;     HANDLE                  Mutant;     PVOID                   ImageBase;     PPEB_LDR_DATA           LoaderData;     PVOID                   ProcessParameters;     PVOID                   SubSystemData;     PVOID                   ProcessHeap;     PVOID                   FastPebLock;     PVOID                   FastPebLockRoutine;     PVOID                   FastPebUnlockRoutine;     ULONG                   EnvironmentUpdateCount;     PVOID* KernelCallbackTable;     PVOID                   EventLogSection;     PVOID                   EventLog;     PVOID                   FreeList;     ULONG                   TlsExpansionCounter;     PVOID                   TlsBitmap;     ULONG                   TlsBitmapBits[0x2];     PVOID                   ReadOnlySharedMemoryBase;     PVOID                   ReadOnlySharedMemoryHeap;     PVOID* ReadOnlyStaticServerData;     PVOID                   AnsiCodePageData;     PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;     ULONG                   NumberOfProcessors;     ULONG                   NtGlobalFlag;     BYTE                    Spare2[0x4];     LARGE_INTEGER           CriticalSectionTimeout;     ULONG                   HeapSegmentReserve;     ULONG                   HeapSegmentCommit;     ULONG                   HeapDeCommitTotalFreeThreshold;     ULONG                   HeapDeCommitFreeBlockThreshold;     ULONG                   NumberOfHeaps;     ULONG                   MaximumNumberOfHeaps;     PVOID** ProcessHeaps;     PVOID                   GdiSharedHandleTable;     PVOID                   ProcessStarterHelper;     PVOID                   GdiDCAttributeList;     PVOID                   LoaderLock;     ULONG                   OSMajorVersion;     ULONG                   OSMinorVersion;     ULONG                   OSBuildNumber;     ULONG                   OSPlatformId;     ULONG                   ImageSubSystem;     ULONG                   ImageSubSystemMajorVersion;     ULONG                   ImageSubSystemMinorVersion;     ULONG                   GdiHandleBuffer[0x22];     ULONG                   PostProcessInitRoutine;     ULONG                   TlsExpansionBitmap;     BYTE                    TlsExpansionBitmapBits[0x80];     ULONG                   SessionId;
} PEB, * PPEB;

typedef struct _VX_TABLE_ENTRY { PVOID   pAddress;     DWORD64 dwHash;     WORD    wSystemCall; } VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {  VX_TABLE_ENTRY NtAllocateVirtualMemory; VX_TABLE_ENTRY NtRollbackTransaction; } VX_TABLE, * PVX_TABLE; //I left an extra function in here on purpose, so that it is easy to see how to add any nt function

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks; /* 0x00 */
	LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
	LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
	PVOID DllBase; /* 0x18 */
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName; /* 0x24 */
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef NTSTATUS(NTAPI* NtRollbackTransactionDelegate)(
	HANDLE  TransactionHandle,
	BOOLEAN Wait
	);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryDelegate)(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
	);

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID* Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;



#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

EXTERN_C NTSTATUS NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtClose(
	HANDLE handle
);