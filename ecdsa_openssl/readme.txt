export LD_LIBRARY_PATH=/home/qwertyu/openssl32/lib:$LD_LIBRARY_PATH

gcc -m32 ecdsa_main.c ecdsa_f.c -I/home/qwertyu/openssl32/include/ -L/home/qwertyu/openssl32/lib/ -lcrypto -lssl 
