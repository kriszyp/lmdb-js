/*  -------------------------------------------------------------
    lp.c

    Routines common to lpr, lpq, and lprm.

    Paul Hilchey    May 1989

    Copyright (C) 1989	The University of British Columbia
    All rights reserved.

	 history
	 -------
	 1/6/89   Microsoft C port by Heeren Pathak (NCSA)
    -------------------------------------------------------------
*/

#ifdef DOS
#ifndef PCNFS

#define LPR

#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef MEMORY_DEBUG
#include "memdebug.h"
#endif
#include "netevent.h"
#include "hostform.h"
#include "lp.h"
#include "externs.h"

#ifdef MSC
#define EXIT_FAILURE 1
#endif

void checkerr( void );

/****************************************************************
 * lookup							*
 * Try to find the remote host in the local cache or from a	*
 * domain name server.						*
 * parameters: null terminated string containing the name or	*
 *		  ip address of the host			*
 * return value: pointer to machine info record, or 0 if the	*
 *		 lookup failed					*
 ****************************************************************/
struct machinfo *lookup(char *host)
{
	int what,dat;
	int machine_number;     /* used to identify domain lookup events */
	struct machinfo *machine_info;

	machine_info = Sgethost(host);  /* look up in hosts cache */

	if (!machine_info) {
		if ((machine_number = Sdomain(host)) < 0)
			return(0);  /* initiate domain name lookup */

		/* wait for DOMOK or DOMFAIL event */
		while (machine_info==NULL) {
			switch(lgetevent(USERCLASS,&what,&dat)) {
			case DOMFAIL:
				/* lookup failed, return 0 */
				return(0);
			case DOMOK:
				/* get pointer to machine record */
				machine_info=Slooknum(machine_number);
			default: 
				break;
			}
		}
		if (debug) puts("Domain lookup worked");
	}
	return(machine_info);
}

/*****************************************************************
 *  open_connection						 *
 *  Open the TCP connection.					 *
 *  parameters: pointer to machine info record			 *
 *		source port number				 *
 *		destination port number 			 *
 *  return value: connection identifier (port number), or -1 if  *
 *		  connection could not be opened		 *
 *****************************************************************/
int open_connection(struct machinfo *machine_record, int source_port,
int dest_port)
{
	int ev,what,dat;  /* parameters for lgetevent */
	int conid;	  /* connection identifier */

	/* set the source port */
	netfromport(source_port);

	/* initiate connection open */
	if (0 > (conid = Snetopen(machine_record,dest_port)))
		return(-1);

	if (debug) puts("snetopen ok");

	/* wait for connection to open or for attempt to fail */
	while(1) {
		if (0 != (ev = lgetevent(CONCLASS,&what,&dat))) {
			if (dat != conid) {     /* not for us */
				/*		netputevent(what,ev,dat); */
				continue;
			}
			if (ev == CONOPEN)
				break;
			else
				return(-1);
		}
	}
	if (debug) puts("Conopen");
	return(conid);
}


/*******************************************************************
 * crash							   *
 * Shut down all network stuff, print an error message to stderr,  *
 * and abort.							   *
 * parameters: variable length argument list for the error	   *
 *		  message (a la printf) 			   *
 *******************************************************************/
void crash(char *msg,...)
{
	va_list argptr;

	fprintf(stderr,"\nError: ");
	va_start(argptr,msg);
	vfprintf(stderr,msg,argptr);
	va_end(argptr);
	fprintf(stderr,"\n");

	/* shut everything down */
	netshut();
	exit(EXIT_FAILURE);
}

/*********************************************************************
 * Check for any error events that may have occured.  Either print   *
 * the message on stderr or just ignore it if it is probably not     *
 * serious.  Set debug on to see all error messages.		     *
 *********************************************************************/
void checkerr(void )
{
	char *errmsg;
	int i,j;

	while (ERR1 == Sgetevent(ERRCLASS,&i,&j)) {
		if ((!debug) &&
		    ((300 <= j && j <= 399) ||	/* IP messages */
		(400 <= j && j <= 499) ||  	/* TCP messages */
		(600 <= j && j <= 699) ||  	/* ICMP messages */
		j == 801  || j == 805  ||  	/* misc. domain stuff */
		j == 806))
			continue;	       /* just ignore them */
		errmsg = neterrstring(j);
		fprintf(stderr,"%s\n",errmsg);
	}
}

/*********************************************************************
 * lgetevent							     *
 * Check for network events. The next pending non-error event is     *
 * returned (if any).						     *
 * Takes the same parameters as sgetevent.			     *
 *********************************************************************/
int lgetevent(int class, int *what, int *datp)
{
	checkerr();
	return(Sgetevent(class, what, datp));
}

/******************************************************************
 * nprintf							  *
 * Formatted write to an open TCP conection.  Like fprintf, but   *
 * use a connection id returned from snteopen instead of a file   *
 * handle.  The formatted string must not exceed 1023 bytes.	  *
 * Returns EOF if an error occurs				  *
 ******************************************************************/
int nprintf(int connection_id, char *format,...)
#define BUFF_SIZE 1024
{
	va_list argptr;
	char    buff[BUFF_SIZE], *buff_ptr;
	int     len1, len2;

	va_start(argptr,format);
	len1 = vsprintf(buff,format,argptr);
	va_end(argptr);
	if ((len1 == EOF) || len1+1 >= BUFF_SIZE) return(EOF);
	buff_ptr = buff;
	while (buff_ptr < (buff + len1)) {
		len2 = netwrite(connection_id, buff_ptr,
		    len1-(buff_ptr - buff));
		checkerr();
		Stask();
		if (len2 < 0) return(EOF);
		buff_ptr += len2;
	}
	if (debug) puts(buff);
	return (len1);
}

/******************************************************************
 * nread							  *
 * Read from an open TCP connection.  Waits for incoming data if  *
 * there is none in the queue.	Returns EOF if the connection	  *
 * closes and there is no more data.				  *
 *								  *
 * parameters: connection id returned by Snetopen		  *
 *	       buffer for returned data 			  *
 *	       size of buffer					  *
 * returned value: number of characters read into the buffer	  *
 ******************************************************************/

int nread(int connection_id, char *buff, int buff_size)
{
	int class,data,ev;
	int len;

	netpush(connection_id);  /* flush buffer */

	while (0 == netest(connection_id)) {
		ev = lgetevent(CONCLASS, &class, &data);
		if (!ev) continue;
		if (data != connection_id) {   /* not for us; throw away */
			/*	   netputevent(class, ev, data); */
			continue;
		}
		if (debug) printf("nread %d %d\n",class,ev);
		if (ev == CONDATA) {
			len = netread(connection_id,buff,buff_size);
			if (len == 0) continue;
			return (len);
		}
	}
	/* throw away other events.  getevent should be changed so we
       can retrieve events for a selected port only  */
	while (lgetevent(USERCLASS | CONCLASS, &class, &data));
	return (EOF);    /* connection is closed and no data in queue */
}

#ifdef MSC
#else
#pragma warn .par
#endif

/******************************************************************
 * breakstop							  *
 * Handle break interrupts by shutting down the network stuff and *
 * aborting.							  *
 ******************************************************************/
int breakstop(void )
{
	netshut();
	return(0);
}

#endif PCNFS
#endif /* DOS */
