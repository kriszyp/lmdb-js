/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
	getopt.c

	modified public-domain AT&T getopt(3)
	modified by Kurt Zeilenga for inclusion into OpenLDAP
*/

#include "portable.h"

#ifndef HAVE_GETOPT

#include <stdio.h>

#include <ac/string.h>
#include <ac/unistd.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

int opterr = 1;
int optind = 1;
int optopt;
char * optarg;

static void ERR (char * const argv[], const char * s, char c)
{
	char errbuf[2];

#ifdef DF_TRACE_DEBUG
printf("DF_TRACE_DEBUG: 	static void ERR () in getopt.c\n");
#endif
	if (opterr)
	{
		errbuf[0] = c;
		errbuf[1] = '\n';
		(void) write(STDERR_FILENO,argv[0],strlen(argv[0]));
		(void) write(STDERR_FILENO,s,strlen(s));
		(void) write(STDERR_FILENO,errbuf,sizeof errbuf);
	}
}

int getopt (int argc, char * const argv [], const char * opts)
{
	static int sp = 1, error = (int) '?';
	static char sw = '-', eos = '\0', arg = ':';
	register char c, * cp;

#ifdef DF_TRACE_DEBUG
printf("DF_TRACE_DEBUG: 	int getopt () in getopt.c\n");
#endif
	if (sp == 1)
		if (optind >= argc || argv[optind][0] != sw
		|| argv[optind][1] == eos)
			return EOF;
		else if (strcmp(argv[optind],"--") == 0)
		{
			optind++;
			return EOF;
		}
	c = argv[optind][sp];
	optopt = (int) c;
	if (c == arg || (cp = strchr(opts,c)) == NULL)
	{
		ERR(argv,": illegal option--",c);
		if (argv[optind][++sp] == eos)
		{
			optind++;
			sp = 1;
		}
		return error;
	}
	else if (*++cp == arg)
	{
		if (argv[optind][sp + 1] != eos)
			optarg = &argv[optind++][sp + 1];
		else if (++optind >= argc)
		{
			ERR(argv,": option requires an argument--",c);
			sp = 1;
			return error;
		}
		else
			optarg = argv[optind++];
		sp = 1;
	}
	else
	{
		if (argv[optind][++sp] == eos)
		{
			sp = 1;
			optind++;
		}
		optarg = NULL;
	}
	return (int) c;
}
#endif /* HAVE_GETOPT */
