# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(remove-read) begin
(remove-read) create "ghost.txt"
(remove-read) open "ghost.txt"
(remove-read) Removed file "ghost.txt"
(remove-read) Wrote test_string to "ghost.txt"
(remove-read) Mysterious file still open and can be written to!
(remove-read) seek file "ghost.txt"
(remove-read) The third character is correctly read as 'i'
(remove-read) end
remove-read: exit(0)
EOF
pass;