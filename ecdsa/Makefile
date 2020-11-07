CC = gcc -m32

CFLAGS = -g -Wall 

INCLUDES = -I/home/qwertyu/openssl32/include

LFLAGS = -L/home/qwertyu/openssl32/lib

LIBS = -lcrypto -lssl

SRCS = ecdsa_main.c ecdsa_f.c 

OBJS = $(SRCS:.c=.o)

MAIN = ecdsa_test01

.PHONY: depend clean

all:	$(MAIN)
	@echo  Simple compiler named $(MAIN) has been compiled

$(MAIN):	$(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o $(MAIN) $(OBJS) 

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it