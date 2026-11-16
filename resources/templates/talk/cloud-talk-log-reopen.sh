#!/bin/sh
# newsyslog R hook: never let root signal a service-writable PID value.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
/usr/bin/env -i PATH="$PATH" /usr/bin/mdo -u cloudjanus /usr/local/bin/python3 -I -B /usr/local/libexec/cloud-talk-runtime.py reopen-janus
/usr/bin/env -i PATH="$PATH" /usr/bin/mdo -u _turnserver /usr/local/bin/python3 -I -B /usr/local/libexec/cloud-talk-runtime.py reopen-turnserver
