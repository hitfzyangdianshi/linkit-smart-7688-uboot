#
# (C) Copyright 2003
# Wolfgang Denk, DENX Software Engineering, wd@denx.de.
#
# See file CREDITS for list of people who contributed to this
# project.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA
#

include $(TOPDIR)/config.mk

LIB	= lib$(ARCH).a

ECDSA_INCLUDES = -I/home/qwertyu/openssl_crosscompile_342/include #ecdsa

ECDSA_LFLAGS = -L/home/qwertyu/openssl_crosscompile_342/lib #ecdsa

ECDSA_LIBS = -lcrypto -lssl -lpthread -ldl #ecdsa

AOBJS	=

COBJS	= board.o time.o mips_linux.o
ifeq ($(MT7621_MP), y)
COBJS	+= ashldi3.o ashrdi3.o lshrdi3.o
ifeq ($(MT7621_FPGA_BOARD), y)
COBJS	+= ddr_init.o
endif
endif

OBJS	= $(AOBJS) $(COBJS)

$(LIB):	.depend $(OBJS)
	$(AR) crv $@ $(OBJS)

#########################################################################

.depend:	Makefile $(AOBJS:.o=.S) $(COBJS:.o=.c)
		$(CC) $(ECDSA_INCLUDES)  -M $(CFLAGS) $(AOBJS:.o=.S) $(COBJS:.o=.c) > $@     # $(ECDSA_LFLAGS) $(ECDSA_LIBS)

sinclude .depend

#########################################################################
