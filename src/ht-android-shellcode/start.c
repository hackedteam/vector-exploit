#include <stdlib.h>
extern int main(int argc, char **argv);
        
void _start(int argc, char **argv)
{
  exit (main (argc, argv));
}
