# $OpenLDAP$

OPENLDAP := ../../../..

#CCFLAGS = -Wall -g -DSLAPD_SHA2_DEBUG
CCFLAGS = -Wall -g

slapd-sha2.so: slapd-sha2.o sha2.o
	$(CC) -I$(OPENLDAP)/include -shared -Wall -g $^ -o $@

%.o: %.c
	$(CC) -I$(OPENLDAP)/include $(CCFLAGS) -c $<

clean:
	@rm -f slapd-sha2.so *.o
