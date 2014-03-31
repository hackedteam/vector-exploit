.globl _start
_start:
	.thumb

	mov ip, r5
	
	add r5, pc, #12

	ldr r5, [r5]
	
	push {r5}
	
	mov r5, ip

	mov ip, pc

	mov ip, ip
	
	pop {pc}

	