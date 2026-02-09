**NOTICE: This project has been migrated to [Codeberg](https://codeberg.org/zpuskas/oath-uri)!
This repository has been archived, will receive no further updates, and will be deleted
on 2026-09-01!**

# oath-uri

**oath-uri** is an open source C/C++ library and command line tool to generate
OATH TOTP/HOTP key sharing URI for soft tokens, also known as one-time password
authentication applications.

When setting up two-factor authentication a secret must be shared with the user
to set up their soft token (typically a smartphone authenticator app). This
information is usually delivered via QR codes, which use a [special key URI
format]( https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

The `oathuri` command line tool is intended to be used in tandem with
[qrencode](https://fukuchi.org/works/qrencode/) to provide an easy way to
generate authenticator application key sharing URIs and associated QR codes.
Find out how to use it by reading the
[oathuri(1)](https://sinustrom.info/man/1/oathuri/) man page.

`liboathuri` is used under the hood for this and it's also available to be used
by your C/C++ software. To learn the API read the
[oathuri.h(3)](https://sinustrom.info/man/3/oathuri_h/) man page.

The code is made available in the hopes of making two-factor authentication
available to wider audiences in a more user friendly (plus yet another) way and
contribute to increasing security across the Internet.

## Dependencies

### Build time

- [GNU GCC](https://gcc.gnu.org/) v5 or later
- [cmake](https://cmake.org) v3.6 or later

### Run time

- [libcurl](https://curl.haxx.se/) v7.15.4 or later

## Installing

### Distros

- Gentoo
  ```
  # layman -a sinustrom
  # emerge -a oath-uri
  ```

### From Source

To build and install `oath-uri` tool and library after extracting sources run:

```
$ cmake .
$ make
$ make install
```

## Links

- Webpage and documentation: https://sinustrom.info/projects/oath-uri/
- Source repository: https://github.com/zpuskas/oath-uri
- Issues: https://github.com/zpuskas/oath-uri/issues

## License and Copyright

Copyright (C) 2017-2020 Zoltan Puskas  
The library is licensed under GNU LGPLv2.1 or later  
The command line tool is licensed under GNU GPLv3 or later
