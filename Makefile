
EXEC = dhcpd
OBJS = dhcpd.o arpping.o socket.o options.o files.o debug.o nettel.o

ifdef BUILD_NETtel
CFLAGS += -DCONFIG_NETtel
endif
ifdef BUILD_NETtel1500
CFLAGS += -DCONFIG_NETtel
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(LD) $(LDFLAGS) -o $@.elf $(OBJS) $(LDLIBS)
	$(CONVERT)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): dhcpd.h socket.h options.h files.h debug.h nettel.h

