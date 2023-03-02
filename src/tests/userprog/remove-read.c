/* Create a file, open it and save a file descriptor, write text into it, remove the file, and attempt to read from the file.
   Standard Unix semantics requires the process to still read from the removed file. */

#include <string.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt, byte_cnt2;
  char *test_string = "This is a test. Do not worry!";
  char buf;
  CHECK(create("ghost.txt", strlen(test_string)), "create \"ghost.txt\"");
  CHECK((handle = open("ghost.txt")) > 1, "open \"ghost.txt\"");
  CHECK(remove("ghost.txt"), "Removed file \"ghost.txt\"");
  CHECK((byte_cnt = write(handle, test_string, strlen(test_string))) > 0, "Wrote test_string to \"ghost.txt\"");
  CHECK(byte_cnt == strlen(test_string), "Mysterious file still open and can be written to!");
  seek(handle, 2);
  msg("seek file \"ghost.txt\"");
  byte_cnt2 = read(handle, &buf, 1);
  CHECK(buf == 'i', "The third character is correctly read as 'i'");
}