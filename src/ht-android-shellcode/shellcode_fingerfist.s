.globl _start
_start:
	.code 16

	adr	r0, soname
	mov	r1, #1	 	/* RTLD_NOW */
	adr	r3, dlopen
	ldr	r3, [r3]
	blx	r3

	adr	r1, export
	adr	r3, dlsym
	ldr	r3, [r3]
	blx	r3

	blx	r0

dlopen:
	.word 0xafd0af18

dlsym:
	.word 0xafd0af24

export:
	.ascii "start\0"
	
soaname:
	.ascii ""