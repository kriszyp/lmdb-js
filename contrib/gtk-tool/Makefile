HOME_LOCATION=$(shell pwd)
CPLUS=	g++
OPTS=-g #-DDEBUG
INCLUDES=`gtkmm-config --cflags` -I.
GTKMMLIBS=`gtkmm-config --libs`
LDFLAGS=-L/usr/lib -L/usr/X11/lib -L/usr/local/ldap/lib -lldap -llber -L/usr/local/kerberos/lib -lkrb5 -lkrb4 `gtkmm-config --libs`
LIBS=-lXext -lgtkmm -lX11 -lXt -lXxf86dga

.EXPORT_ALL_VARIABLES:

SOURCES=My_Window.cc Gtk_LdapTree.cc Gtk_LdapTreeItem.cc Gtk_LdapServer.cc utils.cc main.o
OBJECTS=My_Window.o Gtk_LdapTree.o Gtk_LdapTreeItem.o Gtk_LdapServer.o utils.o main.o

################################################################################

all: main
main:	$(OBJECTS)
	$(CPLUS) $(OBJECTS) -o main $(LDFLAGS) $(GTKMMLIBS)
	exec

main.o: main.cc
	$(CPLUS) -c $(OPTS) $(INCLUDES) $<

exec:	all
	chmod a+x main
	ls -al main

%.o: %.cc %.h
	$(CPLUS) -c $(OPTS) $(INCLUDES) $<

clean:	
	rm -f main a.out *.o straced core
