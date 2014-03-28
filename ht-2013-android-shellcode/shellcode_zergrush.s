.globl _start
_start:
	.code 16

	mov	r1, #1
	mov	r2, #1
	adr	r0, socket_name
	adr	r3, socket_local_client
	ldr	r3, [r3]
	blx	r3


socket_local_client:
	.word 0xaf9052c5
	
socket_name:
	.ascii "vold\0"
	