#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <dirent.h>

#include <dlfcn.h>

#include <sys/system_properties.h>
#include "sockets.h"
#include "android_filesystem_config.h"



int main() {
  int sock;

  if((sock = socket_local_client("vold", ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM)) < 0) {
    printf("Socket failed\n");
    exit(-1);
 }

}
