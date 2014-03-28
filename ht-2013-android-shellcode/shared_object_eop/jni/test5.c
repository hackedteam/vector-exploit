#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


void _ZN17FrameworkListener11registerCmdEP16FrameworkCommand(void *a) {

  char cmd[64];
  
  int r0, r1, r2 = 0;
  __asm __volatile (
		    "mov %0, r0\n"
		    "mov %1, r1\n"
		    "mov %2, r2\n"
		    :   "=r" (r0), "=r" (r1), "=r" (r2)
		    : :
		    );
  
  printf("0x%08x\n", r1);
  snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", getpid());
  system(cmd);
  exit(0);

  }



