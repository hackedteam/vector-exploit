#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "expl_check.h"

/*******************************************/
/************* EXPLOITABLE DEVICES *********/
/*******************************************/

/*
static char dev0[] = "/dev/exynos-mem";
static char dev1[] = "/dev/video1";
static char dev2[] = "/dev/DspBridge";
static char dev3[] = "/dev/s5p-smem";
static char dev4[] = "/dev/graphics/fb5";
static char dev5[] = "/dev/msm_camera/config0";
static char dev6[] = "/dev/camera-isp";
static char dev7[] = "/dev/camera-eis";
static char dev8[] = "/dev/camera-sysram";
*/

unsigned static char dev0[] = "\x3a\xc7\xf2\x1b\xe2\xe1\xd4\x1b\xe1\xce\xcd\xdc\xdb\xd7\x19\xd9\xe1\xd9"; // "/dev/exynos-mem"
unsigned static char dev1[] = "\xfd\x53\xa5\x76\xbf\xb8\x8d\x76\x8d\xb4\xbf\xb8\xb6\x4c"; // "/dev/video1"
unsigned static char dev2[] = "\x9c\xca\x58\xb7\x08\x09\x7e\xb7\x68\x73\x7c\x62\x72\x75\x08\x0f\x09"; // "/dev/DspBridge"
unsigned static char dev3[] = "\x2e\x8f\xac\x1f\x56\x55\x68\x1f\x63\x25\x62\x1d\x63\x5d\x55\x5d"; // "/dev/s5p-smem"
unsigned static char dev4[] = "\x23\x41\x73\x0c\xc9\xc6\xd7\x0c\xc4\xd3\xc2\xd5\xcd\xca\xc0\xd0\x0c\xc7\xc3\x16"; // "/dev/graphics/fb5"
unsigned static char dev5[] = "\xba\x15\xb8\xbf\xe6\xe1\xf4\xbf\xf9\xcb\xf9\xef\xfb\xe5\xf9\xe1\xc8\xe5\xbf\xfb\xff\xfc\xe4\xfd\xe7\x8a"; // "/dev/msm_camera/config0"
unsigned static char dev6[] = "\x8e\xaa\x2b\xe1\x3e\x3f\x08\xe1\x3d\x33\x27\x3f\x0c\x33\xe7\x3b\x0d\x02"; // "/dev/camera-isp"
unsigned static char dev7[] = "\xcf\x50\x90\x60\xab\xaa\x59\x60\xac\xae\xa2\xaa\x5d\xae\x62\xaa\xa6\x5c"; // "/dev/camera-eis"
unsigned static char dev8[] = "\x7d\x41\x2e\xd2\x1b\x18\x0d\xd2\x1e\x1c\x10\x18\x11\x1c\xd0\x0e\x04\x0e\x11\x1c\x10"; // "/dev/camera-sysram"

// Exploit global array
char* dev_list[] = {
  dev0,
  dev1,
  dev2,
  dev3,
  dev4,
  dev5,
  dev6,
  dev7,
  dev8
};

unsigned char* deobfuscate(unsigned char *s) {
    unsigned char key, mod, len;
    int i, j;
	unsigned char* d;
	
    key = s[0];
    mod = s[1];
    len = s[2] ^ key ^ mod;

	d = (unsigned char *)malloc(len + 1);
	
    // zero terminate the string
    memset(d, 0x00, len + 1);

    for (i = 0, j = 3; i < len; i++, j++) {
        d[i] = s[j] ^ mod;
        d[i] -= mod;
        d[i] ^= key;
    }

    d[len] = 0;
	
    return d;
}

int check_vulnerable_devices() {
  int i, ret = 0;
  struct stat device_info;

  for(i = 0; i < (sizeof(dev_list)/4); i++) {
    if(!stat(deobfuscate(dev_list[i]), &device_info)) {
      ret = 1;
      break;
    }
  }

  return ret;
}

int main(int argc, char *argv[]) {	
	return check_vulnerable_devices();
}
