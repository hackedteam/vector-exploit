#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "kallsyms.h"
#include "deobfuscate.h"

static unsigned char proc_kallsyms[] = "\xa2\x97\x3b\xb3\xfe\xf0\xf3\xcf\xb3\xf7\xcd\xf2\xf2\xff\xe5\xf1\xff"; // "/proc/kallsyms"
static unsigned char stext[] = "\xe4\x39\xdb\xcd\xe9\xf0\x83\xec\xf0"; // "_stext"

bool
kallsyms_exist(void)
{
  struct stat st;

  if (stat(deobfuscate(proc_kallsyms), &st) < 0) {
    return false;
  }

  if  (st.st_mode & S_IROTH) {
    return kallsyms_get_symbol_address(deobfuscate(stext)) != 0;
  }

  return false;
}

void *
kallsyms_get_symbol_address(const char *symbol_name)
{
  FILE *fp;
  char function[BUFSIZ];
  char symbol;
  void *address;
  int ret;

  fp = fopen(deobfuscate(proc_kallsyms), "r");
  if (!fp) {
    return 0;
  }

  while(!feof(fp)) {
    ret = fscanf(fp, "%p %c %s", &address, &symbol, function);
    if (ret != 3) {
      break;
    }

    if (!strcmp(function, symbol_name)) {
      fclose(fp);
      return address;
    }
  }
  fclose(fp);

  return NULL;
}

