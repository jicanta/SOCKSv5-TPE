#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10

struct users {
  char* name;
  char* pass;
  bool from_cmd;
};

struct socks5args {
  char* socks_addr;
  unsigned short socks_port;

  char* mng_addr;
  unsigned short mng_port;

  bool disectors_enabled;
  bool auth_required;

  struct users users[MAX_USERS];
  int user_count;
};

extern struct socks5args socks5args;

void parse_args(const int argc, char** argv, struct socks5args* args);

#endif
