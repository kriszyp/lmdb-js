#
# This file used under Irix (SGI) - please modify for your needs
#
CC = cc -signed

#For Optimization
CFLAGS= -O2
#For debugging
#CFLAGS= -g

#
# Create Executables
#
web_ldap: web_ldap.o util.o
	$(CC) -o web_ldap web_ldap.o util.o \
	libldap.a liblber.a

#
# Create Objects
#
web_ldap.o: web_ldap.c
	$(CC) -c web_ldap.c

util.o: util.c
	$(CC) -c util.c
#
# all done
#
