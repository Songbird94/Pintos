/* Tests whether seek() actually moves the position pointer.
   Then checks whether tell() returns the right position shifted by seek().
   THIS IS A CUSTOM TEST ADDED. */

#include <string.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt;
  char *test_string = "This is a test. Do not worry!";

  CHECK(create("tell-seek.txt", sizeof(char) * (strlen(test_string) + 1)), "create \"tell-seek.txt\"");
  CHECK((handle = open("tell-seek.txt")) > 1, "open \"tell-seek.txt\"");

  byte_cnt = write(handle, test_string, sizeof(char) * (strlen(test_string) + 1));
  if (byte_cnt != sizeof(char) * (strlen(test_string) + 1)) {
    fail("write() did not write all the bytes in test_string!");
  }

  seek(handle, 8);
  msg("seek \"tell-seek.txt\"");
  CHECK((tell(handle)) == 8, "seek() moved the position 8 bytes, and tell() returned the correct position!");
}