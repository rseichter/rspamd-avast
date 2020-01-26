# avast.lua

Copyright © 2020 Ralph Seichter

## Description

[Rspamd](https://www.rspamd.com/) antivirus extension for the [Avast](https://www.avast.com/de-de/index#mac)
virus scanner. Tested with Rspamd 2.2 and Avast 3.0.3.

## License

Apache License 2.0, see license file for [details](LICENSE).

## Prerequisites

avast.lua requires [lua-socket](http://w3.impa.br/~diego/software/luasocket/home.html) version 3, which is expected
to be found in `/usr/lib/x86_64-linux-gnu/lua/5.1/`. For Debian 10 you can use `apt install lua-socket` to install
the necessary package.

Avast is expected to listen on the UNIX Domain Socket `/run/avast/scan.sock`. As Avast currently does not support
network sockets, the virus scanner must run on the same machine as Rspamd. Ensure that the domain socket allows R/W
access for the Rspamd process.

## Installation

*  Place a copy of `avast.lua` in your `/usr/share/rspamd/lualib/lua_scanners` directory.
*  Add the line `require_scanner('avast')` to `lua_scanners/init.lua`.
*  Add a section to your `local.d/antivirus.conf`:
```
avast {
  type = 'avast';
  # Force this action if any virus is found (default unset: no action is forced)
  action = 'reject';
}
```
*  Restart Rspamd.
