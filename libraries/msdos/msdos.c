#ifndef PCNFS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dos.h>
#include <stdarg.h>
#include <io.h>
#include <time.h>
#define ffblk find_t
#define ff_name name
#include <signal.h>
#include <direct.h>
#include <malloc.h>

#define WINMASTER
#define LPR

#ifdef MEMORY_DEBUG
#include "memdebug.h"
#endif
#include "whatami.h"
#include "hostform.h"
#include "windat.h"
#include "lp.h"
#include "externs.h"
#include "msdos.h"

/*  Function prototypes  */

int	netup = 0;
int	connection_id;
int	cf_length = 0;	    /* current length of control_file */
int	sequence_number;    /* sequence number for spooled file names */
struct config *cp;	    /* configuration information */
char	username[9];	    /* name of user */
int	debug = 0;	    /* 1 = print debugging info; set with -D option */

int	ftppassword,	    /* not used; just to avoid unresolved external */
bypass_passwd=0;	/* whether to bypass the password check */

unsigned char path_name[_MAX_DRIVE+_MAX_DIR],		/* character storage for the path name */
temp_str[20],s[_MAX_DIR],temp_data[30];

/* Do session initialization.  Snetinit reads config file. */
ncsainit()
{
	char *ptr;
	int i;
	if (netup) return;
	ptr = getenv("CONFIG.TEL");
	if (ptr != NULL) Shostfile(ptr);
	if(i=Snetinit()) {
		if(i==-2)		/* BOOTP server not responding */
			netshut();	/* release network */
		crash("network initialization failed.");
	}	/* end if */
	netup = 1;
}


int ncsaopen( address, port )
unsigned long	 address;
short	  port;
{
	unsigned char  *bob;
	struct machinfo *mr;
	short source_port;
	short handle;
	char s[256];

	bob = (unsigned char *) &address;
	sprintf(s,"%u.%u.%u.%u\n",bob[0],bob[1],bob[2],bob[3]);
	mr = lookup(s);

	/* open connection */
	/* pick a source port at random from the set of privileged ports */

	srand((unsigned)time(NULL));

	source_port = rand() % MAX_PRIV_PORT;
	handle = open_connection(mr, source_port, port);
	return(handle);
}
#endif /* PCNFS */
