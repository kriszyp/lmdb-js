#
# Build TimesTen ODBC Sample Programs for Solaris 2.5.1.
# (c) Copyright 1996-1998, TimesTen Performance Software.
# All rights reserved.
#
# $Revision: 1.1 $
#

CPLUSPLUS = CC
TTCLASSES = ../../../../../../../../../cs/classes
ODBC	=	/opt/TimesTen4.1/32
CFLAGS	=	-g -I$(ODBC)/include -I. -I$(TTCLASSES) -DUNIX
LDFLAGS	=	-g
DIRLIBS	=	$(TTCLASSES)/ttclasses.a -L $(ODBC)/lib -R $(ODBC)/lib -ltten -lpthread -lm -lrt
XLALIB  =       -L $(ODBC)/lib -lxla

DIRPROGS=	dnreverse 

DNREVERSE=	dnreverse.o

#
#	Top-level targets
#

all:		$(DIRPROGS)

direct:		$(DIRPROGS)

clean:          
		rm -rf $(DIRPROGS) *.o


#
#	Direct-linked programs
#

dnreverse:	$(DNREVERSE)
		$(CPLUSPLUS) -o dnreverse $(LDFLAGS) $(DNREVERSE) $(DIRLIBS) $(XLALIB)

#
#	.o files
#

dnreverse.o:	dnreverse.cpp
		$(CPLUSPLUS) $(CFLAGS) -c dnreverse.cpp
