#
# Configuration parameters, can be overridden in config file
#
LDAPSRC		= ../..
CONFIG_DIRECTORY	=	$(ETCDIR)/whois++
HELP_DIRECTORY	=	/usr/local/isode/help/whois++
LDAPHOST	= "localhost"
#
# Where to stuff the man page
MANDIR		= /usr/local/isode/man
MANSEC		= 8
#
# Syslog facility to log queries under, using info serverity level
#
FACILITY	= LOG_LOCAL3
#
# Additional system libraries
# Under Ultrix I use the 4.3 syslog, hence the additional syslog library
#
#SYSLIBS	= -li -lsyslog
#
# If you want POSIX international support (format of dates), on ultrix
#
#INTERNATIONAL	= -DINTERNATIONAL
#
# If you want RFC931 logging you must have log_tcp source available
#
#RFC931DEF 	= -DRFC931
#RFC931SRC	= /local/src/log_tcp/rfc931.c

SRCS	= whois++.c command.c config.c describe.c help.c output.c template.c \
	  util.c version.c $(RFC931SRC)
HDRS	= whois++.h
OBJS	= ${SRCS:.c=.o}
HOST	= `hostname`
# This returns a date such as "26 April 1993", unfortunately SunOS doesn't
# understand the %B abd %Y macros so you may need to change this.
#DATE	= `date +'%d %B %Y'`
DATE	= `date +'%D'`	# this gives 4/26/93 format
REVISION	= 2

DEFINES = -DETCDIR=\"$(ETCDIR)\" -DBUILD="\"$(USER)@$(HOST) on $(DATE)\"" \
	  -DCONFIG_DIRECTORY=\"$(CONFIG_DIRECTORY)\" -DMAIN \
	  -DHELP_DIRECTORY=\"$(HELP_DIRECTORY)\" -DREVISION="$(REVISION)" \
	  -DPROTOCOL="\"[FIRST DRAFT - 15 April 1993]\"" -DRELEASE=\"BETA\" \
	  -DFACILITY=$(FACILITY) -DDEFAULT_LDAPHOST=\"$(LDAPHOST)\" \
	  $(INTERNATIONAL) $(RFC931DEF)

CFLAGS	= -I$(LDAPSRC)/include -I/usr/local/include $(ACFLAGS)
LIBS	= -L$(LDAPSRC)/libraries/libldap -lldap -L$(LDAPSRC)/libraries/liblber \
	 -llber $(SYSLIBS) $(KRBLIBFLAG) $(KRBLIBS)

all:	whois++d

whois++d:	$(OBJS) $(LDAPSRC)/libraries/libldap/libldap.a
	$(CC) $(ALDFLAGS) -o $@ $(OBJS) $(LIBS)

whois++.o:	whois++.c $(HDRS)
	$(CC) $(CFLAGS) $(DEFINES) -c whois++.c

install:	inst-whois++

inst-whois++: $(DESTDIR)$(ETCDIR)/whois++d
	-$(MKDIR) $(DESTDIR)$(CONFIG_DIRECTORY)
	cp -r templates $(DESTDIR)$(CONFIG_DIRECTORY)
	-$(MKDIR) $(DESTDIR)$(HELP_DIRECTORY)
	cp -r helpfiles/* $(DESTDIR)$(HELP_DIRECTORY)
	-$(MKDIR) $(DESTDIR)$(DESTDIR)$(MANDIR)/man$(MANSEC)
	sed -e 's#ETCDIR#$(ETCDIR)#' whois++d.man > $(DESTDIR)$(MANDIR)/man$(MANSEC)/whois++d.$(MANSEC)
	@echo "Don't forget to modify and install the tailor file"

$(DESTDIR)$(ETCDIR)/whois++d: whois++d
	install -c -m 755 whois++d $(DESTDIR)$(ETCDIR)

lint:;
	lint $(SRCS)

5lint:;
	/usr/5bin/lint $(SRCS)

clean:;
	rm -f *.o core a.out whois++d

depend:;
	../mkdep $(CFLAGS) $(SRCS)

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
