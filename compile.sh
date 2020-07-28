#
# simple compile for mimysql
#

CFLAGS="-g -Wall"

CC=cc

$CC -c $CFLAGS  mimysql-client.c  || exit 1
$CC -c $CFLAGS  mimysql-unix.c || exit 1
$CC -c $CFLAGS  mimysql-test1.c || exit 1
$CC -c $CFLAGS  mimysql-test-client.c  || exit 1
$CC -c $CFLAGS  sha1.c  || exit 1

$CC -o mimysql-test1 $CFLAGS mimysql-client.o mimysql-test1.c sha1.o || exit 1
$CC -o mimysql-test-client $CFLAGS mimysql-test-client.o mimysql-client.o mimysql-unix.o   sha1.o || exit 1
