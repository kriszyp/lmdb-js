#
# This file used under Irix (SGI) - please modify for your needs
#

#CC = cc -signed

#For Optimization
CFLAGS= -O2 $(CPPFLAGS)

#For debugging
#CFLAGS= -g $(CPPFLAGS)

PREFIX=../..
# PREFIX=/usr/local

CPPFLAGS= -I$(PREFIX)/include
LDFLAGS= -L$(PREFIX)/libraries

# CC = cc $(CFLAGS) $(CPPFLAGS)

#
# Create Executables
#
web_ldap: web_ldap.o util.o
	$(CC) -o web_ldap web_ldap.o util.o $(LDFLAGS) -lldap -llber

clean:
	rm -f *.o a.out core web_ldap
