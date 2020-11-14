include $(TOPDIR)/config.mk

ECDSA_INCLUDES = -I/home/qwertyu/openssl_crosscompile_342/include -I/opt/buildroot-gcc342/include	

ECDSA_LFLAGS = -L/home/qwertyu/openssl_crosscompile_342/lib -L/opt/buildroot-gcc342/lib		

ECDSA_LIBS = -lcrypto -lssl 
#-lpthread -ldl	

LIB	= ecdsa_f.a

AOBJS	=

COBJS	= ecdsa_f.o


OBJS	= $(AOBJS) $(COBJS)

$(LIB):	.depend $(OBJS)
	$(AR) crv $@ $(OBJS)

#########################################################################

.depend:	Makefile $(AOBJS:.o=.S) $(COBJS:.o=.c)
		$(CC) $(ECDSA_LFLAGS) $(ECDSA_LIBS) $(ECDSA_INCLUDES) -M $(CFLAGS) $(AOBJS:.o=.S) $(COBJS:.o=.c) > $@

sinclude .depend

#########################################################################