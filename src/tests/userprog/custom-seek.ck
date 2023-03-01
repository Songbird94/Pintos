# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(custom-seek) begin
(custom-seek) create "test_seek.txt"
(custom-seek) open "test_seek.txt"
(custom-seek) a
(custom-seek) end
custom-seek: exit(0)
EOF
pass;