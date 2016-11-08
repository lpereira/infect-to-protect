#include <stdio.h>
#include <sys/socket.h>

int main(int argc, char *argv[] __attribute__((unused)))
{
  if (argc < 2) { 
    printf("no socket created\n");
  } else {
    int fd = socket(AF_INET, SOCK_STREAM, 6);
    printf("created socket, fd = %d\n", fd);
  }

  return 0;
}