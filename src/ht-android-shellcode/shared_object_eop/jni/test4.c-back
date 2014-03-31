#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/user.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
  int child_argv_start;
  int status;
  pid_t child;
  int i = 0;
  char cmd[64];
  char *vold_bin = "/system/bin/vold";

  child = fork();
  if(child == 0) {
    child_argv_start = 1;
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    //execve("/system/bin/vold", "vold", NULL);
    execvp(argv[child_argv_start], &argv[child_argv_start]);
    //system("cat /proc/self/maps > asd");
  }
  else {
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps > asd", child);
    wait(&status);
    // Check if child called exit before we even got started.
    if(WIFEXITED(status))
      _exit (WEXITSTATUS(status));
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    wait(&status);
    while (1) {
      i++;
      if(i==1000) {
	system(cmd);
	exit(0);
      }
      // I should probably check if the child got terminated by a signal.
      if(WIFEXITED(status))
	break;
      //sleep(1); // in microseconds (millionths of a second)
      ptrace(PTRACE_SYSCALL, child, NULL, NULL);
      //ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
      wait(&status);
    }
  }
  _exit (WEXITSTATUS(status));
}

/*
 * This returns the length of a NULL-terminated argv array.
 */
int argv_length(char **argv) {
  int count;
  char **p;

  if (argv == NULL)
    return 0;

  for (count = 0, p = argv; *p; count++, p++)
    ;

  return count;
}
