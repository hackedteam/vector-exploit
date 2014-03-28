#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {

  struct timeval tv;
  fd_set readfs;
  int STDIN =  atoi(argv[1]);

  tv.tv_sec = 2;
  tv.tv_usec = 0;

  FD_ZERO(&readfs);
  FD_SET(STDIN ,&readfs);

  //*ptr =  1 <<  (STDIN % 32);

  select(STDIN+1, &readfs, NULL, NULL, NULL);

  if (FD_ISSET(STDIN, &readfs) )
    printf("Something pressed\n");
  else
    printf("Time out\n");

  printf("%tv %d\n", sizeof(tv) );
  printf("readfs %d\n", sizeof(fd_set));

  return 0;
}

















