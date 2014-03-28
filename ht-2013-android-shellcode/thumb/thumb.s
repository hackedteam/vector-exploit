.globl _start
_start:
	    b   reset

reset:

	.arm

	.globl one
one:
	    add r0,r0,#1
	    bx lr

	.thumb

	.globl two
two:
	    add r0,r0,#2
	    bx lr

	.thumb_func
	.globl three
three:
	    add r0,r0,#3
	    bx lr

	.globl prologue
prologue:
	push {r0-r7,lr}
	pop  {r0-r7,pc}
	bx lr
	

	.word two
	.word three
	