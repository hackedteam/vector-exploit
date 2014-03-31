	.thumb
	.global _start

_start:
	  mov r12, r5
	  mov r5, pc
	  add r5, r5, #12
	  ldr r5,[r5]
	  push {r5}
	  mov r5, r12
	  mov r12, pc
	  pop {pc}
	  mov r12, r12
target:	  .word 0xddccbbaa
	