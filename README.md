# File-Librarian
A C++ program to recursively catalog a directory into MySQL.


## Purpose

Cataloging the contents of a given path, de-duplicating data, making it searchable, managing multiple copies of the data, and performing integrity checks.

All of the tools I've tried for this task were inadequate in some critical way.

## Building
File-Librarian depends on mbedTLS (for cryptography), [CppPotpourri](https://github.com/jspark311/CppPotpourri), and the Linux version of [ManuvrPlatform](https://github.com/jspark311/ManuvrPlatforms).

These things can all be obtained and put in the proper place by running...

    ./downloadDeps.sh

The program can then be built with `make`, and invoked with `./librarian`.


## Out-of-band requirements

You need a MySQL database, and a user with write permissions to it. And then you need to put that information into a config file, like this...

    $ cat db.conf
    dbhost=1.2.3.4
    dbport=3306
    dbname=librarian
    dbuser-librarian-usr
    dbpass=librarian-pass


## Usage
