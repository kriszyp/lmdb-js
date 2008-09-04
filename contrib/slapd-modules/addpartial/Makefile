# $OpenLDAP$
OPENLDAP_SRC=../../..
CPPFLAGS+=-I${OPENLDAP_SRC}/include -I${OPENLDAP_SRC}/servers/slapd
CC=gcc

all: addpartial-overlay.so

addpartial-overlay.so: addpartial-overlay.c
	$(CC) -shared $(CPPFLAGS) $(LDFLAGS) -Wall -o $@ $?

clean:
	rm addpartial-overlay.so
