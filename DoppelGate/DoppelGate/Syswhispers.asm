.code

NtReadFile PROC
	mov rax, gs:[60h]                    ; Load PEB into RAX.
NtReadFile_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtReadFile_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtReadFile_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtReadFile_Check_10_0_XXXX
	jmp NtReadFile_SystemCall_Unknown
NtReadFile_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtReadFile_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtReadFile_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtReadFile_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtReadFile_SystemCall_6_3_XXXX
	jmp NtReadFile_SystemCall_Unknown
NtReadFile_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtReadFile_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtReadFile_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtReadFile_SystemCall_6_0_6002
	jmp NtReadFile_SystemCall_Unknown
NtReadFile_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtReadFile_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtReadFile_SystemCall_6_1_7601
	jmp NtReadFile_SystemCall_Unknown
NtReadFile_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtReadFile_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtReadFile_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtReadFile_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtReadFile_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtReadFile_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtReadFile_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtReadFile_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtReadFile_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtReadFile_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtReadFile_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtReadFile_SystemCall_10_0_19042
	jmp NtReadFile_SystemCall_Unknown
NtReadFile_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 0003h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 0003h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 0003h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 0003h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0003h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0003h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0004h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0005h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 0006h
	jmp NtReadFile_Epilogue
NtReadFile_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtReadFile_Epilogue:
	mov r10, rcx
	syscall
	ret
NtReadFile ENDP

NtCreateTransaction PROC
	mov rax, gs:[60h]                             ; Load PEB into RAX.
NtCreateTransaction_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtCreateTransaction_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtCreateTransaction_Check_10_0_XXXX
	jmp NtCreateTransaction_SystemCall_Unknown
NtCreateTransaction_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtCreateTransaction_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtCreateTransaction_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateTransaction_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtCreateTransaction_SystemCall_6_3_XXXX
	jmp NtCreateTransaction_SystemCall_Unknown
NtCreateTransaction_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtCreateTransaction_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtCreateTransaction_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtCreateTransaction_SystemCall_6_0_6002
	jmp NtCreateTransaction_SystemCall_Unknown
NtCreateTransaction_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtCreateTransaction_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtCreateTransaction_SystemCall_6_1_7601
	jmp NtCreateTransaction_SystemCall_Unknown
NtCreateTransaction_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtCreateTransaction_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtCreateTransaction_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtCreateTransaction_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtCreateTransaction_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtCreateTransaction_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtCreateTransaction_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtCreateTransaction_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtCreateTransaction_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtCreateTransaction_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtCreateTransaction_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtCreateTransaction_SystemCall_10_0_19042
	jmp NtCreateTransaction_SystemCall_Unknown
NtCreateTransaction_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 00aah
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 00a8h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 00a8h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 00a8h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 00a8h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 00b3h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 00b5h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 00b8h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 00b9h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 00bbh
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 00beh
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 00bfh
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 00c0h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 00c1h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 00c2h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 00c2h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 00c6h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 00c6h
	jmp NtCreateTransaction_Epilogue
NtCreateTransaction_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtCreateTransaction_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateTransaction ENDP
NtClose PROC
	mov rax, gs:[60h]                 ; Load PEB into RAX.
NtClose_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtClose_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtClose_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtClose_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtClose_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtClose_SystemCall_6_0_6002
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtClose_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtClose_SystemCall_10_0_19041
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 000dh
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 000eh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
NtClose ENDP

end