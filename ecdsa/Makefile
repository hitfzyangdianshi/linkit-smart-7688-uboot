CC = gcc

LFLAGS = -L /usr/lib/x86_64-linux-gnu/

LIBS = -l crypto -l ssl

SRCS = ecdsa_main.c ecdsa_f.c 

OBJS = $(SRCS:.c=.o)

MAIN = ecdsa_test01

all:	$(MAIN)
	@echo  Simple compiler named mycc has been compiled

$(MAIN): $(OBJS) 
	$(CC)  $(LFLAGS) $(LIBS)

