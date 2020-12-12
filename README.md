# mimysql - Small MySQL/MariaDB client lib in C

Small MySQL/MariaDB client library in C made 
to embedded to projects which have their own
io + memory-handling libraries.

## Limitations

* No mysql_store_result, only mysql_use_result
* Currently only UNIX domain sockets..
* Only unix io supported.
* No makefile ...
* Only mysql_native_authentication/old password are supported.

## Features

* API mostly compatible with standard MySQL C connector api
* Plugable alloc/free, socket handling, sha1 in separate file.
* Few .c-files, one .h-file + your file env. 

## Usage

  ./compile.sh

  ./mimysql-test-client  -S /tmp/mysql.sock -e 'select now()' -u myuser -p mypass -D mydb
    

