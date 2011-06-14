#
# Copyright (C) 2011, deadcafe.beef@gmail.com
# All rights reserved.
#

TARGET = cipher.lib

SRCS	=		\
	cipher.c	\
	digest.c	\
	encrypt.c	\
	prf.c		\
	integrity.c	\
	diffiehellman.c

TOPDIR = ../..
LIBS = -lcrypto
COPTFLAGS = -O0
CFLAGS_EXTRA = -pthread
LD_FLAGS_EXTRA = -pthread

-include $(TOPDIR)/makefiles/Makefile.lib
