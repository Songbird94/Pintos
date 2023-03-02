# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(custom-tell) begin
(custom-tell) create "tell-seek.txt"
(custom-tell) open "tell-seek.txt"
(custom-tell) seek "tell-seek.txt"
(custom-tell) seek() moved the position 8 bytes, and tell() returned the correct position!
(custom-tell) end
custom-tell: exit(0)
EOF
pass;