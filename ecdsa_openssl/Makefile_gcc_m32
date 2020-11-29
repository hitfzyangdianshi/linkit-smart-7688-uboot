CC = gcc -m32

CFLAGS = -g 

INCLUDES = -I/home/qwertyu/openssl32/include

LFLAGS = -L/home/qwertyu/openssl32/lib

LIBS = -lcrypto -lssl

SRCS = ecdsa_main.c ecdsa_f.c 

OBJS = $(SRCS:.c=.o)

MAIN = ecdsa_test01

.PHONY: clean

all:	$(SRCS)
	$(CC) $(SRCS) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o $(MAIN) 

clean:
	$(RM) *.o *~ 


