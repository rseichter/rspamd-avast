# avast.lua

Copyright © 2020 Ralph Seichter. Sponsored by [sys4 AG](https://sys4.de/).

## Description

[avast.lua](https://github.com/rseichter/rspamd-avast) is a [Rspamd](https://www.rspamd.com/) antivirus extension
module for the [Avast](https://www.avast.com/de-de/index#mac) virus scanner, written in [Lua](https://www.lua.org).
The module was tested with Rspamd 2.2 and Avast 3.0.3.

## License

Apache License 2.0, see license file for [details](LICENSE).

## Prerequisites

avast.lua requires [lua-socket](http://w3.impa.br/~diego/software/luasocket/home.html) version 3, which is expected
to be found in `/usr/lib/x86_64-linux-gnu/lua/5.1/`. For Debian 10 you can use `apt install lua-socket` to install
the necessary package.

Avast is expected to listen on the UNIX Domain Socket `/run/avast/scan.sock`. As Avast does not support network
sockets as of January 2020, the virus scanner must run on the same machine as Rspamd. Please ensure that the domain
socket allows R/W access for the Rspamd process.

## Installation

*  Place a copy of `avast.lua` in your `/usr/share/rspamd/lualib/lua_scanners` directory.
*  Add the line `require_scanner('avast')` to `lua_scanners/init.lua`.
*  Add a section to your `local.d/antivirus.conf`:
```
avast {
  type = 'avast';
  # Avast socket path
  #socket = '/run/avast/scan.sock';
  # Log clean files?
  #log_clean = false;
  # Force this action if any virus is found (default: unset)
  action = 'reject';
}
```
*  Restart Rspamd.
