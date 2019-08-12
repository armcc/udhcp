# -------------------------------------------------------------------------------------
# Copyright 2006, Texas Instruments Incorporated
#
# This program has been modified from its original operation by Texas Instruments
# to do the following:
#	Customisation to build with rgdk framework
#
#  THIS MODIFIED SOFTWARE AND DOCUMENTATION ARE PROVIDED
#  "AS IS," AND TEXAS INSTRUMENTS MAKES NO REPRESENTATIONS
#  OR WARRENTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
#  TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY
#  PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE OR
#  DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY PATENTS,
#  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
#  
#  These changes are covered as per original license.
# -------------------------------------------------------------------------------------

# udhcp makefile
# -include $(TARGET_HOME)/.config
# -include $(TARGET_HOME)/TI_Build.make

prefix=/usr
SBINDIR=/sbin
USRSBINDIR=${prefix}/sbin
USRBINDIR=${prefix}/bin
USRSHAREDIR=${prefix}/share

# Uncomment this to get a shared binary. Call as udhcpd for the server,
# and udhcpc for the client

ifeq ($(CONFIG_TI_UDHCP_CLIENT),y) 
ifeq ($(CONFIG_TI_UDHCP_SERVER),y)
COMBINED_BINARY=1
endif
endif

# Uncomment this for extra output and to compile with debugging symbols
#DEBUG=1

# Uncomment this to output messages to syslog, otherwise, messages go to stdout
CFLAGS += -Os

#CROSS_COMPILE=arm-uclibc-
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)gcc
INSTALL = install

VER := 0.9.7


OBJS_SHARED = options.o socket.o packet.o pidfile.o
DHCPD_OBJS = dhcpd.o arpping.o files.o leases.o serverpacket.o dhcpd_plugin_internal.o
DHCPC_OBJS = dhcpc.o clientpacket.o script.o

ifdef COMBINED_BINARY
EXEC1 = udhcpd
OBJS1 = $(DHCPD_OBJS) $(DHCPC_OBJS) $(OBJS_SHARED) frontend.o
CFLAGS += -DCOMBINED_BINARY
else
EXEC1 = udhcpd
OBJS1 = $(DHCPD_OBJS) $(OBJS_SHARED)

EXEC2 = udhcpc
OBJS2 = $(DHCPC_OBJS) $(OBJS_SHARED)
endif

EXEC3 = dumpleases
OBJS3 = dumpleases.o

BOOT_PROGRAMS = udhcpc
DAEMONS = udhcpd
COMMANDS = dumpleases

ifdef SYSLOG
CFLAGS += -DSYSLOG
endif

CFLAGS += -W -Wall -Wstrict-prototypes -DVERSION='"$(VER)"' -D_GNU_SOURCE

ifdef DEBUG
CFLAGS += -g -DDEBUG
else
CFLAGS += -Os -fomit-frame-pointer
#STRIP=-s
STRIP=
endif

LDFLAGS += -lresolv
all: $(EXEC1) $(EXEC2) $(EXEC3)

$(OBJS1) $(OBJS2) $(OBJS3): *.h Makefile
$(EXEC1) $(EXEC2) $(EXEC3): Makefile

.c.o:
	$(CC) -c $(CFLAGS) $<
	
$(EXEC1): $(OBJS1)
	$(LD) $(LDFLAGS) $(OBJS1) -o $(EXEC1)

$(EXEC2): $(OBJS2)
	$(LD) $(LDFLAGS) $(OBJS2) -o $(EXEC2)

$(EXEC3): $(OBJS3)
	$(LD) $(LDFLAGS) $(OBJS3) -o $(EXEC3)


install: all

	$(INSTALL) $(STRIP) $(DAEMONS) $(USRSBINDIR)
	$(INSTALL) -m 0644 dhcpd_plugin.h $(TI_include)
ifdef COMBINED_BINARY
	(cd $(USRSBINDIR) ; ln -sf ./$(DAEMONS) $(BOOT_PROGRAMS))
else
ifeq ($(CONFIG_TI_UDHCP_CLIENT),y) 
	$(INSTALL) $(STRIP) $(BOOT_PROGRAMS) $(USRSBINDIR)
endif
endif

ifeq ($(CONFIG_TI_UDHCP_CLIENT),y) 
	mkdir -p $(USRSHAREDIR)/udhcpc
	for name in bound deconfig renew script altbound; do \
		$(INSTALL) samples/sample.$$name \
			$(USRSHAREDIR)/udhcpc/default.$$name ; \
	done
endif

clean:
	-rm -f udhcpd udhcpc dumpleases *.o core

#	-rm -f $(USRSBINDIR)/udhcpd
#	-rm -f $(USRSBINDIR)/udhcpc
#ifeq ($(CONFIG_TI_UDHCP_CLIENT),y)
#	for name in bound deconfig renew script altbound; do \
#	$(RM) $(USRSHAREDIR)/udhcpc/default.$$name ; \
#	done
#endif

