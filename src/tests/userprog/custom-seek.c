/* Tests whether seeking a file actually moves the position pointer.
   THIS IS A CUSTOM TEST ADDED ALONG. */

#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    int handle, byte_cnt;
    char *test_string = "This is a test. Do not be alarmed!";
    char buf;

    CHECK(create("test_seek.txt", strlen(test_string) + 1), "create \"test_seek.txt\"");
    CHECK((handle = open("test_seek.txt")) > 1, "open \"test_seek.txt\"");

    byte_cnt = write(handle, test_string, strlen(test_string) + 1);

    seek(handle, 8);
    read(handle, &buf, 1);
    msg("%c", buf);
}