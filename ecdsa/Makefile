CC = gcc -m32

CFLAGS  = -g -Wall

INCLUDES = -I /home/qwertyu/openssl32/include

LFLAGS = -L /home/qwertyu/openssl32/lib

LIBS = -l crypto -l ssl

SRCS = ecdsa_main.c ecdsa_f.c 

OBJS = $(SRCS:.c=.o)

MAIN = ecdsa_test01

all:	$(MAIN)
	@echo  Simple compiler named $(MAIN) has been compiled

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

