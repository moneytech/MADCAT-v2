Sirko's solution for linking problems (many thanks!):

In case you get problems with linking the pthread library
cannot find /lib/arm-linux-gnueabihf/libpthread.so.0
cannot find /usr/lib/arm-linux-gnueabihf/libpthread_nonshared.a
or something similar in connection with libc.so.6
then you have to do the following:

open /usr/arm-linux-gnueabihf/lib/libpthread.so:
Change

/ * GNU ld script
Use the shared library, but some functions are only in
the static library, so try that secondarily. * /
OUTPUT_FORMAT (elf32-littlearm)
GROUP (/lib/arm-linux-gnueabihf/libpthread.so.0 /usr/lib/arm-linux-gnueabihf/libpthread_nonshared.a)

to

/ * GNU ld script
Use the shared library, but some functions are only in
the static library, so try that secondarily. * /
OUTPUT_FORMAT (elf32-littlearm)
GROUP (libpthread.so.0 libpthread_nonshared.a)

open /usr/arm-linux-gnueabihf/lib/libc.so and change to:

/ * GNU ld script
   Use the shared library, but some functions are only in
   the static library, so try that secondarily. * /
OUTPUT_FORMAT (elf32-littlearm)
GROUP (libc.so.6 libc_nonshared.a AS_NEEDED (ld-linux-armhf.so.3))