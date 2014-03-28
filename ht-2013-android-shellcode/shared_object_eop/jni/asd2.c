#include "sockets.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <stdio.h>

int main() {

  struct sockaddr_un addr;
  socklen_t alen;
  size_t namelen;

  int s;

  s = socket(AF_LOCAL, 1, 0);
  if(s < 0)
    printf("Unable!!!");
  else printf("OKOKOKOKOKOK!!!");


  strcpy(&addr->sun_path, "vold");
  

}
