# @(#) Makefile 1.6 93/06/18 22:29:40

## BEGIN CONFIGURATION STUFF

# In the unlikely case that your compiler has no hooks for alternate
# compiler passes, use a "cc cflags -E file.c | unproto >file.i"
# pipeline, then "cc cflags -c file.i" to compile the resulting
# intermediate file.
# 
# Otherwise, the "/lib/cpp | unproto" pipeline can be packaged as an
# executable shell script (see the provided "cpp.sh" script) that should
# be installed as "/whatever/cpp". This script should then be specified
# to the C compiler as a non-default preprocessor.
#
# PROG	= unproto
# PIPE	=

# The overhead and problems of shell script interpretation can be
# eliminated by having the unprototyper program itself open the pipe to
# the preprocessor.  In that case, define the PIPE_THROUGH_CPP macro as
# the path name of the default C preprocessor (usually "/lib/cpp"),
# install the unprototyper as "/whatever/cpp" and specify that to the C
# compiler as a non-default preprocessor.
#
PROG	= cpp
PIPE	= -DPIPE_THROUGH_CPP=\"/lib/cpp\"

# Some compilers complain about some #directives. The following is only a
# partial solution, because the directives are still seen by /lib/cpp.
# Be careful with filtering out #pragma, because some pre-ANSI compilers
# (SunOS) rely on its use.
#
# SKIP	= -DIGNORE_DIRECTIVES=\"pragma\",\"foo\",\"bar\"
#
SKIP	=

# The bell character code depends on the character set. With ASCII, it is
# 7. Specify a string constant with exactly three octal digits. If you
# change this definition, you will have to update the example.out file.
#
BELL	= -DBELL=\"007\"

# Some C compilers have problems with "void".  The nature of the problems
# depends on the age of the compiler.
#
# If your compiler does not understand "void" at all, compile with
# -DMAP_VOID. The unprototyper will replace "void *" by "char *", a
# (void) argument list by an empty one, and will replace all other
# instances of "void" by "int".
#
# If your compiler has problems with "void *" only, compile with
# -DMAP_VOID_STAR. The unprototyper will replace "void *" by "char *",
# and will replace a (void) argument list by an empty one. All other
# instances of "void" will be left alone.
#
# If neither of these are defined, (void) argument lists will be replaced
# by empty ones.
#
# MAP	= -DMAP_VOID_STAR

# Now that we have brought up the subject of antique C compilers, here's
# a couple of aliases that may be useful, too.
#
# ALIAS	= -Dstrchr=index

# If you need support for functions that implement ANSI-style variable
# length argument lists, edit the stdarg.h file provided with this
# package so that it contains the proper definitions for your machine.

## END CONFIGURATION STUFF

SHELL	= /bin/sh

CFILES	= unproto.c tok_io.c tok_class.c tok_pool.c vstring.c symbol.c error.c \
	hash.c strsave.c
HFILES	= error.h token.h vstring.h symbol.h
SCRIPTS	= cpp.sh acc.sh
SAMPLES	= stdarg.h stddef.h stdlib.h varargs.c example.c example.out
SOURCES	= README $(CFILES) $(HFILES) Makefile $(SCRIPTS) $(SAMPLES)
FILES	= $(SOURCES) unproto.1
OBJECTS	= tok_io.o tok_class.o tok_pool.o unproto.o vstring.o symbol.o error.o \
	hash.o strsave.o

CFLAGS	= -O $(PIPE) $(SKIP) $(BELL) $(MAP) $(ALIAS)
#CFLAGS	= -O $(PIPE) $(SKIP) $(BELL) $(MAP) $(ALIAS) -p -Dstatic=
#CFLAGS	= -g $(PIPE) $(SKIP) $(BELL) $(MAP) $(ALIAS) -DDEBUG

$(PROG): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(MALLOC)

# For linting, enable all bells and whistles.

lint:
	lint -DPIPE_THROUGH_CPP=\"foo\" -DIGNORE_DIRECTIVES=\"foo\",\"bar\" \
	$(BELL) -DMAP_VOID $(ALIAS) $(CFILES)

# Testing requires that the program is compiled with -DDEBUG.

test:	$(PROG) cpp example.c example.out
	./cpp example.c >example.tmp
	@echo the following diff command should produce no output
	diff -b example.out example.tmp
	rm -f example.tmp

shar:	$(FILES)
	@shar $(FILES)

archive:
	$(ARCHIVE) $(SOURCES)

clean:
	rm -f *.o core cpp unproto mon.out varargs.o varargs example.tmp

error.o : error.c token.h error.h Makefile
hash.o : hash.c Makefile
strsave.o : strsave.c error.h Makefile
symbol.o : symbol.c error.h token.h symbol.h Makefile
tok_class.o : tok_class.c error.h vstring.h token.h symbol.h Makefile
tok_io.o : tok_io.c token.h vstring.h error.h Makefile
tok_pool.o : tok_pool.c token.h vstring.h error.h Makefile
unproto.o : unproto.c vstring.h stdarg.h token.h error.h symbol.h Makefile
varargs.o : varargs.c stdarg.h Makefile
vstring.o : vstring.c vstring.h Makefile
