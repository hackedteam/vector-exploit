#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/user.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
  pid_t p;
  struct user_ asd;
  int status;
  int s;

  p = fork();
  if (p == -1) {
    exit(-1);
  }else if (p == 0) { /* In Child */
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    /* Execute the given process */
    argv[argc] = 0;
    execvp(argv[1], argv+1);
    /* The success of execve will cause a SIGTRAP to be sent to this child process. */
  }
  /* In parent */
  /* Wait for execve to finish*/
  wait(&status);
  /* Start to trace system calls */
  //ptrace(PTRACE_SYSCALL, p, 0, 0);
  /* Wait until the entry to a sys call */
  while(wait_val == 1407) {
    wait(&status);
    //ptrace(PTRACE_GETREGS, p, NULL, &regs);
    //s = ptrace(PTRACE_PEEKTEXT, p, (void *)(regs.ARM_pc - 4), NULL);
    printf("Syscall %d\n",s);
    ptrace(PTRACE_CONT, p, NULL, NULL);
  }

  /* Check the GP register and get the system call number*/
  // int syscall;
  //struct user_regs_struct u_in; /* #include <linux/user.h> */
  //ptrace(PTRACE_GETREGS, p, 0, &u_in);
  //syscall = u_in.orig_eax;

}


