EXEC1 = udhcpd
OBJS1 = dhcpd.o arpping.o files.o leases.o options.o socket.o

EXEC2 = dumpleases
OBJS2 = dumpleases.o

DEBUG=1
#CFLAGS += -DSYSLOG

VER := 0.9.0

CROSS_COMPILE=arm-uclibc-
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)gcc

CFLAGS += -W -Wall -Wstrict-prototypes -DVERSION='"$(VER)"'

ifdef DEBUG
CFLAGS += -g -DDEBUG
else
CFLAGS += -Os -fomit-frame-pointer
endif

all: $(EXEC1) $(EXEC2) $(EXEC3)

.c.o:
	$(CC) -c $(CFLAGS) $<
	
$(EXEC1): $(OBJS1)
	$(LD) $(LDFLAGS) $(OBJS1) -o $(EXEC1)

$(EXEC2): $(OBJS2)
	$(LD) $(LDFLAGS) $(OBJS2) -o $(EXEC2)


clean:
	-rm -f $(EXEC1) $(EXEC2) *.elf *.o core

$(OBJS1): files.h debug.h options.h socket.h leases.h dhcpd.h arpping.h
