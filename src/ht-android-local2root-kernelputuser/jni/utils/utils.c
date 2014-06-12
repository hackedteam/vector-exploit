/*
** Copyright 2012, The CyanogenMod Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <errno.h>

#include "utils.h"
#include "log.h"
#include "deobfuscate.h"

/* reads a file, making sure it is terminated with \n \0 */
char* read_file(const char *fn)
{
    struct stat st;
    char *data = NULL;

    int fd = open(fn, O_RDONLY);
    if (fd < 0) return data;

    if (fstat(fd, &st)) goto oops;

    data = malloc(st.st_size + 2);
    if (!data) goto oops;

    if (read(fd, data, st.st_size) != st.st_size) goto oops;
    close(fd);
    data[st.st_size] = '\n';
    data[st.st_size + 1] = 0;
    return data;

oops:
    close(fd);
    if (data) free(data);
    return NULL;
}

int get_property(const char *data, char *found, const char *searchkey, const char *not_found)
{
    char *key, *value, *eol, *sol, *tmp;
    if (data == NULL) goto defval;
    int matched = 0;
    sol = strdup(data);
    while((eol = strchr(sol, '\n'))) {
        key = sol;
        *eol++ = 0;
        sol = eol;

        value = strchr(key, '=');
        if(value == 0) continue;
        *value++ = 0;

        while(isspace(*key)) key++;
        if(*key == '#') continue;
        tmp = value - 2;
        while((tmp > key) && isspace(*tmp)) *tmp-- = 0;

        while(isspace(*value)) value++;
        tmp = eol - 2;
        while((tmp > value) && isspace(*tmp)) *tmp-- = 0;

        if (strncmp(searchkey, key, strlen(searchkey)) == 0) {
            matched = 1;
            break;
        }
    }
    int len;
    if (matched) {
        len = strlen(value);
        if (len >= PROPERTY_VALUE_MAX)
            return -1;
        memcpy(found, value, len + 1);
    } else goto defval;
    return len;

defval:
    len = strlen(not_found);
    memcpy(found, not_found, len + 1);
    return len;
}

/*
 * Fast version of get_property which purpose is to check
 * whether the property with given prefix exists.
 *
 * Assume nobody is stupid enough to put a propery with prefix ro.cm.version
 * in his build.prop on a non-CM ROM and comment it out.
 */
int check_property(const char *data, const char *prefix)
{
    if (!data)
        return 0;
    return strstr(data, prefix) != NULL;
}



int append_content(const char *content, const char *file) {
	FILE *fd;
	char *data = NULL;
	int size = 0;
	char *newline = "\n";

	if ((fd = fopen(file, "r+")) == NULL) {
		LOGD("Unable to open source file in r+ mode\n");
		return -1;
	}

	fseek(fd, 0L, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0L, SEEK_SET);

	data = (char *)malloc(size + 1);
	memset(data, 0x00, size + 1);

	LOGD("Reading %d bytes\n", size);

	fread(data, size, 1, fd);

	if (strcasestr(data, content) != NULL) {
		LOGD("Needle already present\n");

		fclose(fd);
		free(data);
		return -1;
	}

	fseek(fd, 0L, SEEK_END);

	if (fwrite(content, strlen(content), 1, fd) > 0) {
		LOGD("Content successfully written to file\n");
	} else {
		LOGD("Unable to write content to file\n");
	}

	fwrite(newline, strlen(newline), 1, fd);

	fclose(fd);
	free(data);
	sync();

	return 0;
}


// Copy a file
int fcopy(FILE *f1, FILE *f2){
  char buffer[512];
  size_t n;

  while ((n = fread(buffer, sizeof(char), sizeof(buffer), f1)) > 0){
    if (fwrite(buffer, sizeof(char), n, f2) != n)
      return -1;
  }

  return 1;
}


// Remount a partition
int remount(const char *mntpoint, int flags) {
  unsigned char mounts[] = "\x84\xe0\x68\x6b\x34\x36\x2b\x27\x6b\x29\x2b\x31\x2a\x30\x37"; // "/proc/mounts"
  unsigned char r[] = "\x19\xfe\xe6\x97"; // "r"
  unsigned char t1[] = "\x39\x8e\xb5\x29\x30"; // " \t"
  unsigned char t2[] = "\xd4\x35\xe3\x1c\x27"; // " \t"
  unsigned char t3[] = "\xa8\xbd\x17\xf8\xe3"; // " \t"  
  unsigned char bin_mount[] = "\xf8\xab\x42\x29\x9d\x87\x9d\x9c\xe3\xeb\x29\xee\x97\xea\x29\xeb\xe9\x93\xea\x9c"; // "/system/bin/mount"
  unsigned char mount_cmd[] = "\xc9\x25\xf0\x34\xfa\x2b\x2c\xc7\x2b\x34\xfa\x2b\x2c\xee\x2b\x34\xfa\x2f\xc5\xf4\xec\xee\xc4\xe9\xc7\x2b\x34\xfa\x2b\x34\xfa"; // "%s -t %s -o %s,remount %s %s"

  FILE *f = NULL;
  int found = 0;
  char buf[1024], *dev = NULL, *fstype = NULL;
  char mount_str[2048];

  if ((f = fopen(deobfuscate(mounts), deobfuscate(r))) == NULL) {
    LOGD("Unable to open /proc/mounts\n");
    return -1;
  }

  memset(buf, 0, sizeof(buf));
  
  for (;!feof(f);) {
    if (fgets(buf, sizeof(buf), f) == NULL)
      break;
    
    if (strstr(buf, mntpoint)) {
      found = 1;
      break;
    }
  }

  fclose(f);

  if (!found) {
    LOGD("Cannot find mountpoint: %s\n", mntpoint);
		
    return -1;
  }

  if ((dev = strtok(buf, deobfuscate(t1))) == NULL) {
    LOGD("Cannot find first mount entry\n");
    return -1;
  }

  if (strtok(NULL, deobfuscate(t2)) == NULL) {
    LOGD("Cannot find second mount entry\n");
    return -1;
  }

  if ((fstype = strtok(NULL, deobfuscate(t3))) == NULL) {
    LOGD("Cannot find third mount entry\n");
    return -1;
  }

  // Sometime mount can fail (ie: cyanogen mod).
  // If it fails try to use the /system/bin/mount command
  int t = mount(dev, mntpoint, fstype, flags | MS_REMOUNT, 0);
  LOGD("Mount: %d\n", t);
  if(t < 0 && errno != 16) {
    LOGD("ERRNO: %s %d\n", strerror(errno), errno);
    LOGD("Using system for mounting\n");
    memset(&mount_str, 0, sizeof(mount_str));

    // Remount in read-write
    if(flags == 0)
      snprintf(mount_str, sizeof(mount_str), deobfuscate(mount_cmd), deobfuscate(bin_mount), fstype, "rw", dev, mntpoint);
    // remount in read-only
    else if(flags == MS_RDONLY)
      snprintf(mount_str, sizeof(mount_str), deobfuscate(mount_cmd), deobfuscate(bin_mount), fstype, "ro", dev, mntpoint);
    else return -1;

    return system(mount_str);
  }

  return 0;
    
}
