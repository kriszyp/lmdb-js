HOME_LOCATION=$(shell pwd)
CC=	gcc
CPLUS=	g++
OPTS=-g -DmyDEBUG
INCLUDES=`gtkmm-config --cflags` -I.
LDFLAGS=`gtkmm-config --libs` -L/usr/lib -L/usr/X11/lib -L/usr/local/gnome/lib -L/usr/local/ldap/lib -lldap -llber -L/usr/local/kerberos/lib -lkrb5 -lkrb4
LIBS=-lXext -lgtkmm -lX11 -lXt -lXxf86dga

.EXPORT_ALL_VARIABLES:

SOURCES=	My_Window.cc Gtk_LdapTreeItem.cc Gtk_LdapServer.cc main.cc
OBJECTS=	My_Window.o Gtk_LdapTreeItem.o Gtk_LdapServer.o main.o

################################################################################

all:	$(OBJECTS) $(SOURCES)
	$(CPLUS) $(OBJECTS) -o main $(LDFLAGS)
	exec

exec:	all
	chmod a+x main
	ls -al main

%.o: %.c
	$(CC) -c $(OPTS) $(INCLUDES) $<

%.o: %.cc
	$(CPLUS) -c $(OPTS) $(INCLUDES) $<

clean:	
	rm -f main a.out *.o straced core
