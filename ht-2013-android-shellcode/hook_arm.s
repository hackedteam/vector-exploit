.globl _start
_start:
	mov ip, pc
	ldr pc, [pc, #-4]
goto:	mov ip, ip
	