Steps:

1 - Build KoviD

    $ export PROCNAME=kovid

    $ make

    $ make strip

2 - Build assembly code

    $ ./update.sh && make

3 - Test it

    $ sudo ./kv_embed

4 - Check dmesg for KoviD if it's been loaded
