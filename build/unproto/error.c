/*++
/* NAME
/*	error 3
/* SUMMARY
/*	diagnostics
/* PACKAGE
/*	unproto
/* SYNOPSIS
/*	#include "error.h"
/*
/*	int errcount;
/*
/*	void error(text)
/*	char *text;
/*
/*	void error_where(path, line, text)
/*	char *path;
/*	int line;
/*	char *text;
/*
/*	void fatal(text)
/*	char *text;
/* DESCRIPTION
/*	The routines in this file print a diagnostic (text). Some also
/*	terminate the program. Upon each error*() call, the errcount variable
/*	is incremented.
/*
/*	error() provides a default context, i.e. the source-file
/*	coordinate of the last read token.
/*
/*	error_where() allows the caller to explicitly specify context: path
/*	is a source-file name, and line is a line number.
/*
/*	fatal() is like error() but terminates the program with a non-zero
/*	exit status.
/*
/*	context is ignored if the line number is zero or if the path
/*	is an empty string.
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	92/01/15 21:53:10
/* VERSION/RELEASE
/*	1.2
/*--*/

static char error_sccsid[] = "@(#) error.c 1.2 92/01/15 21:53:10";

/* C library */

#include <stdio.h>

extern void exit();

/* Application-specific stuff */

#include "token.h"
#include "error.h"

int     errcount = 0;			/* error counter */

/* error - report problem (implicit context) */

void    error(text)
char   *text;
{
    error_where(in_path, in_line, text);
}

/* error_where - report problem (explicit context) */

void    error_where(path, line, text)
char   *path;
int     line;
char   *text;
{
    errcount++;

    /* Suppress context info if there is none. */

    if (line && path[0])
	fprintf(stderr, "%s, line %d: ", path, line);

    fprintf(stderr, "%s\n", text);
}

/* fatal - report problem and terminate unsuccessfully */

void    fatal(text)
char   *text;
{
    error(text);
    exit(1);
}
