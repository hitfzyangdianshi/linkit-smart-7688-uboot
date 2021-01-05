export LD_LIBRARY_PATH=/home/qwertyu/openssl32/lib:$LD_LIBRARY_PATH

gcc -m32 ecdsa_main.c ecdsa_f.c -I/home/qwertyu/openssl32/include/ -L/home/qwertyu/openssl32/lib/ -lcrypto -lssl 

***
Please note that for now I have not got a method to use openssl library on linkit-smart-7688-uboot due to the fact that this outdated buildroot gcc version does not support some syntax in openssl src files. Also, for I have bee using a ligntweight version ecdsa that works well with uboot, this openssl version has been discarded. If you know how to integrate openssl with linkit-smart-7688-uboot, you may have a try...... 
