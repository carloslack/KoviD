/*
 *
 *      Filename:  test_fork.c
 *
 *      Description:
 *
 *      Created:  01/04/21 06:18:13
 *      Author:
 *
 */
#include <stdio.h>
#include <unistd.h>
int main() {
   int n = fork(); //subdivide process
   if (n > 0) { //when n is not 0, then it is parent process
       int a = 0;
      printf("Parent process \n");
      while((a++)<30) sleep(1);
   } else { //when n is 0, then it is child process
       int a = 0;
      printf("Child process \n");
      while((a++)<35) sleep(1);
   }
   return 0;
}


