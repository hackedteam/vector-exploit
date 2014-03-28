	.globl _start
_start:
	.thumb
	mov	ip, r5
	adr	r5, jump_va
	ldr	r5, [r5]
	push	{r5}
	mov	r5, ip
	mov 	ip, pc
	pop	{pc}
	mov	ip, ip

jump_va:.word  0xaabbccdd
