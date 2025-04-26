#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  if (argc < 2)
    return -1;
  int v[12][12] = {0};
  int a = atoi(argv[1]), b = atoi(argv[2]);
  printf("[%d][%d] = %p\n",
      a, b, v[a][b]);
  return 0;
}