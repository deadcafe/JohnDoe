CC = gcc
AR = ar
RANLIB = ranlib

CFLAGS = -g -fPIC -std=gnu99 -fno-strict-aliasing -Werror -Wall -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wfloat-equal -Wpointer-arith 

VPATH = $(TREMA_ROOT)/src/lib
CPPFLAGS = -c -D_GNU_SOURCE -I$(VPATH) -I$(VPATH)/compat

TARGET = libtrema.a

SRCS = 						\
	libevent_wrapper.c			\
	async.c					\
	async_lock.c				\
	async_util.c				\
	buffer.c				\
	byteorder.c				\
	daemon.c				\
	doubly_linked_list.c			\
	ether.c					\
	event_handler.c				\
	hash_table.c				\
	linked_list.c				\
	log.c					\
	match_table.c				\
	message_queue.c				\
	messenger.c				\
	openflow_application_interface.c	\
	openflow_message.c			\
	openflow_switch_interface.c		\
	oxm_byteorder.c				\
	oxm_match.c				\
	packet_info.c				\
	packet_parser.c				\
	packetin_filter_interface.c		\
	persistent_storage.c			\
	safe_event_handler.c			\
	safe_timer.c				\
	secure_channel.c			\
	stat.c					\
	timer.c					\
	trema.c					\
	trema_private.c				\
	trema_wrapper.c				\
	utility.c				\
	wrapper.c

OBJS = $(patsubst %.c,%.o,$(SRCS:%.c=%.o))
DEPENDS = .depend

.SUFFIXES:	.o .c
.PHONY: all clean

all	:	$(TARGET)

clean	:
	rm -f $(OBJS) $(TARGET)

.c.o	:
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(TARGET)	:	$(OBJS)
	$(AR) -cq $(TARGET) $(OBJS)
	$(RANLIB) $(TARGET)
