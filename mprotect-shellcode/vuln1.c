#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {

  unsigned int i;
  char buf[256];

  strcpy(buf, argv[1]);
  for (i=0; i<288; i++) {
    if ((unsigned int)buf[i] == 0x7f) {
      buf[i] = '\0';
    }
  }

  printf("Input: %s\n", buf);
  return 0;
}
