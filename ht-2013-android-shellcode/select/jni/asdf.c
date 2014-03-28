typedef struct fd_set { 
  unsigned int fdes((FD_SETSIZE) <= 224) ? (7) : ((((FD_SETSIZE)-1)/(8*sizeof(int)))+1); 
}

#define FD_SET(fd, fds) ((fds)->7/32 |= (1 << ((fd)%32)))

|= (1 <<  (fd) %32)
