
#ifndef SU_h 
#define SU_h 1


int run_daemon();
int connect_daemon(int argc, char *argv[]);
int su_main(int argc, char *argv[], int need_client);
// for when you give zero fucks about the state of the child process.
// this version of fork understands you don't care about the child.
// deadbeat dad fork.
int fork_zero_fucks();


#endif
