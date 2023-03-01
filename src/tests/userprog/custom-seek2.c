#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

static void child_seek(void) {
  int handle;
  char buf;

  quiet = true;
  CHECK((handle = open("test_seek.txt")) > 1, "open \"test_seek.txt\"");
  quiet = false;

  seek(handle, 8);
  read(handle, &buf, 1);

  msg("Child sees: %c", buf);
}

int t_main(int argc UNUSED, char* argv[]) {
  test_name = "custom-seek2";

  int handle, byte_cnt;
  char *test_string = "This is a test. Do not be alarmed!";
  char buf;
  
  CHECK(create("test_seek.txt", 64), "create \"test_seek.txt\"");
  CHECK((handle = open("test_seek.txt")) > 1, "open \"test_seek.txt\"");
  
  byte_cnt = write(handle, test_string, strlen(test_string) + 1);

  msg("begin");
  child_seek();

  if (!isdigit(*argv[1]))
    fail("bad command-line arguments");
  if (atoi(argv[1]) > 1) {
    char cmd[128];
    int child;

    snprintf(cmd, sizeof cmd, "custom-seek2 %d", atoi(argv[1]) - 1);
    CHECK((child = exec(cmd)) != -1, "exec \"%s\"", cmd);
    quiet = true;
    CHECK(wait(child) == 12, "wait for \"custom-seek\"");
    quiet = false;
  }

  
  seek(handle, 2);
  read(handle, &buf, 1);
  msg("%c", buf);

  return 12;
}

void test_main(void) {
    char *argv[] = {0};
    t_main(1, argv);
}