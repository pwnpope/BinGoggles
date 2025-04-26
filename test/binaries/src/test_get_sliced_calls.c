#include <stdio.h>


int do_add(int a, int b) {
      return a + b;
}


int main() {
      int a = 0, b = 0;
      printf("Welcome, submit two numbers for addition\n");
      
      printf("A: ");
      scanf("%d", &a);

      printf("B: ");
      scanf("%d", &b);

      int c = do_add(a, b);
      printf("%d", c);

      return 0;
}