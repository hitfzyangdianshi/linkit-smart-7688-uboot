#gcc ecdsa_main.c ecdsa_f.c -L /usr/lib/x86_64-linux-gnu/ -l crypto -l ssl

gcc -m32 ecdsa_main.c ecdsa_f.c -I /home/qwertyu/openssl32/include/ -L /home/qwertyu/openssl32/lib/ -l crypto -l ssl 