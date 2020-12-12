.data    
	wSystemCall DWORD 000h 
 
.code    
	DoppelGate PROC        
		mov wSystemCall, 000h         
		mov wSystemCall, ecx        
		ret     
	DoppelGate ENDP 
 
    DoppelDescent PROC        
		mov r10, rcx         
		mov eax, wSystemCall 
        syscall         
		ret
	DoppelDescent ENDP 

	

end 