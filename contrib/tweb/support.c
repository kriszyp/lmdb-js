/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* support.c..                                                              *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway - Supporting Routines              *
*            Based on web500gw.c 1.3 written by Frank Richter, TU Chemmniz *
*            which is based on go500gw by Tim Howes, University of         *
*            Michigan  - All rights reserved                               *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            August 16 1995               Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            September 7 1999           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: support.c,v 1.6 1999/09/10 15:01:20 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"
#include "init_exp.h"
#include "support.h"

/*
 *  Utilities for dealing with HTML junk
 */

char hex[17] = "0123456789abcdef";
char buffer[1024];

PUBLIC char * hex_decode (in)
char *in;
{
        char b, c;
        int q = 0;
        char *out = in;

        while (*in) {
        if (*in == '?')        /* start search */
            q = 1;
                if (*in == '%') {    /* Hex escape */
                        in++;
                        if(!(c = *in++)) break;
                        b = from_hex(c);
                        if(!(c = *in++)) break;
                        *out++ = (b<<4) + from_hex(c);
                } else if (q && *in == '+') {
            /* '+' is legal in path, in search it's a ' ' */
            *out++ = ' ';
            in++;
        } else {
                        *out++ = *in++;
                }
        }
        *out = '\0';
        return (out);
}
/* end of function: hex_decode */

/* decode in search (for do_modify) */

PUBLIC char * hex_qdecode (in)
char *in;
{
        char b, c;
        char *out = in;

        while (*in) {
                if (*in == '%') {     /* Hex escape */
                        in++;
                        if(!(c = *in++)) break;
                        b = from_hex(c);
                        if(!(c = *in++)) break;
                        *out++ = (b<<4) + from_hex(c);
                } else if (*in == '+') { /* we are in search, so: '+' -> ' ' */
                        *out++ = ' ';
                        in++;
                } else {
                        *out++ = *in++;
                }
        }
        *out = '\0';
        return (out);
}
/* end of function: hex_qdecode */

PUBLIC char * form_encode (in)
char *in;
{
    char *out = buffer;
    
    /* bzero(out, 1024); */
    while (*in) {
            if (*in == '"' || *in == '>' ) {
            *out++ = '\\';
        }
                   *out++ = *in++;
    }
         *out = '\0';

     /* fprintf( stderr, "returning - esc: %s.\n", buffer); */
    return (buffer);
}
/* end of function: form_encode */

/* gtime(): the inverse of localtime().
    This routine was supplied by Mike Accetta at CMU many years ago.
 */

int    dmsize[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

#define    dysize(y)    \
    (((y) % 4) ? 365 : (((y) % 100) ? 366 : (((y) % 400) ? 365 : 366)))

#define    YEAR(y)        ((y) >= 100 ? (y) : (y) + 1900)

PRIVATE time_t gtime (tm)
struct tm *tm;
{
    register int    i,
                    sec,
                    mins,
                    hour,
                    mday,
                    mon,
                    year;
    register long   result;

    if ((sec = tm -> tm_sec) < 0 || sec > 59
        || (mins = tm -> tm_min) < 0 || mins > 59
        || (hour = tm -> tm_hour) < 0 || hour > 24
        || (mday = tm -> tm_mday) < 1 || mday > 31
        || (mon = tm -> tm_mon + 1) < 1 || mon > 12)
    return ((long) -1);
    if (hour == 24) {
    hour = 0;
    mday++;
    }
    year = YEAR (tm -> tm_year);
    result = 0L;
    for (i = 1970; i < year; i++)
    result += dysize (i);
    if (dysize (year) == 366 && mon >= 3)
    result++;
    while (--mon)
    result += dmsize[mon - 1];
    result += mday - 1;
    result = 24 * result + hour;
    result = 60 * result + mins;
    result = 60 * result + sec;
    return result;
}
/* end of function: gtime */

PUBLIC char * format_date (s, format)
char **s;
char *format;
{
/*  PATCHED by /KSp, 94/04/29  */
    static char    date[256];
/*      ^^^^^^ */
/*  END PATCH  */

    struct tm       tm, *ntm;
    time_t        t;


    tm.tm_year = 10*((*s)[0] - '0') + ((*s)[1] - '0');
    tm.tm_mon  = 10*((*s)[2] - '0') + ((*s)[3] - '0') - 1;
    tm.tm_mday = 10*((*s)[4] - '0') + ((*s)[5] - '0');
    tm.tm_hour = 10*((*s)[6] - '0') + ((*s)[7] - '0');
    tm.tm_min  = 10*((*s)[8] - '0') + ((*s)[9] - '0');
    tm.tm_sec  = 10*((*s)[10] - '0') + ((*s)[11] - '0');

/*  PATCHED for HPUX by /KSp, 94/04/28  */

    tm.tm_isdst = 0;

#if !defined(__hpux) && !defined(__linux__)  && !defined(__sun)
    tm.tm_gmtoff = 0;
#endif

/*  END PATCH  */

    t = gtime(&tm);
    ntm = gmtime(&t);
    strftime(date, 256, format, ntm);
    return (date);
}
/* end of function: format_date */

PUBLIC char * friendly_dn (dn, glob)
char *dn;
GLOB_STRUCT *glob;
{
/*  PATCHED BY /KSp, 94/04/29  */
    /* static char    fufn[1024], **s; */
/*      ^^^^^^  */
/*  END PATCH  */

/*  Again patched by /KSp, 97/01/25: dynamic mem-allocation  */
	char  *fufn;

	if ( ( fufn = calloc( 1, BUFSIZ )) ) {

		if (strlen(dn) == 0) {
			strcpy( fufn, glob->la[77] );
		} else {

			int    i = 0;
			char   **s;

			s = ldap_explode_dn( dn, 1 );
			while (s[i+1]) {
				strcat( fufn, s[i++] );
				strcat( fufn, ", " );
			}
			strcat( fufn, ldap_friendly_name( glob->friendlyfile, s[i], &fm ));
		}
	}

    return (fufn);
}
/* end of function: friendly_dn */


PUBLIC char * format_time (whatTime)
time_t  whatTime;
{
           time_t    timer;
    static char      theTime[_TIMEOUT_LEN+1];

    timer = whatTime ? whatTime : time (&timer);
    strftime (theTime, (_TIMEOUT_LEN + 1), _LOG_TIME, localtime (&timer));

    return (theTime);

} /* end of function: format_time */

PUBLIC char * strQuoteChr(string, c)
char *string;
char c;
{
    char *cPtr;
    int inQuote = FALSE;

    cPtr = string;
    while(*cPtr) {
        if( *cPtr == '\"')
            inQuote = ( (inQuote == TRUE) ? FALSE : TRUE );
        if( (*cPtr == c) && (inQuote == FALSE) )
            return(cPtr);
        cPtr++;
        }

    return(NULL);
}
/* end of function: strQuoteChr */

PUBLIC char * strrQuoteChr(string, c)
char *string;
char c;
{
    char *cPtr;
    int inQuote = FALSE;

    cPtr = string + strlen(string) - 1;
    while(cPtr >= string) {
        if( *cPtr == '\"')
            inQuote = ( (inQuote == TRUE) ? FALSE : TRUE );
        if( (*cPtr == c) && (inQuote == FALSE) )
            return(cPtr);
        cPtr--;
        }

    return(NULL);
}
/* end of function: strrQuoteChr */


PUBLIC void disp_file(glob, filename, fp)
GLOB_STRUCT *glob;
char *filename;
FILE *fp;
{
char buf[4096];
FILE *fp2;
    if(filename && (fp2 = fopen(filename, "r" ))) {
        while ( fgets(buf, 4095, fp2) != NULL )
            fprintf( fp, "%s",buf);
        fclose(fp2);
    }

    /* Copyright-Zeile */
    if(filename == glob->footer ||
       (glob->basedn && filename == glob->basedn->foot))
        fprintf( fp, glob->la[99],glob->la[101], copyright );
}
/* end of function: disp_file */


PUBLIC int dn_cmp(dn1, dn2)
char *dn1, *dn2;
{
        do {
                while(*dn1 == ' ' || *dn1 == '"')
                        dn1++;
                while(*dn2 == ' ' || *dn2 == '"')
                        dn2++;
                if(!*dn1 && !*dn2)
                        return(FALSE); /* equality */
        } while(tolower(*dn1++) == tolower(*dn2++));
        return(TRUE);
}
/* end of function: dn_cmp */


/*
 *  dn_cmp_parts()
 *
 *    comparison of dns by rdn parts. in case of unmatched the part(s) which
 *    matched can be returned (matched not NULL)
 *
 *  input:
 *
 *    - dn1 (in url format)
 *    - dn2 (     "       )
 *    - matched (pointer to dynamically allocatable string, or NULL)
 *
 *  output:
 *
 *    - DN_EQUAL | DN_LESS | DN_GREATER | DN_UNMATCHED (with matched allocated)
 */

PUBLIC int
dn_cmp_parts( dn1, dn2, matched )
char  *dn1;
char  *dn2;
char **matched;
{
	char   **dn1arr = dn2charray( dn1 );
	char   **dn2arr = dn2charray( dn2 );
	int    idx;
	int    domatch  = TRUE;
	int    result   = DN_EQUAL;

	for ( idx = 0; dn1arr[idx] && dn2arr[idx]; idx++ ) {

		if ( strcasecmp( dn1arr[idx], dn2arr[idx] )) {

			domatch = FALSE;
			break;

		}
	}

	/*  what was the result  */

	if ( !domatch ) {

		if ( matched ) {
			char buf[BUFSIZ];
			char buf2[BUFSIZ];
			int  idx2;

			*buf = '\0';

			for ( idx2 = 0; idx2 < idx; idx2++ ) {

				strcpy( buf2, buf );
				sprintf( buf, "%s,%s", dn1arr[idx2], buf2 );

			}
			trimright( buf, "," );

			*matched = strdup( buf );

		}

		result = DN_UNMATCHED;

	} else if ( dn1arr[idx] ) result = DN_GREATER;
	else if ( dn2arr[idx] ) result = DN_LESS;

	charray_free( dn1arr ); charray_free( dn2arr );

	return( result );

}  /*  dn_cmp_parts  */



/*
 *  Comparison of substring lists
 */

PUBLIC int strlstcmp (s1, s2, sep)
char  *s1, *s2;
char   sep;
{
    int   retCode = FALSE;
    char *target;
    char *source;
    char *idx, *idx2;
    char  tmpChar;

    if ( !s1 || !s2 )
        return( FALSE );

    target = str_tolower (strdup (s1));
    source = str_tolower (strdup (s2));
    idx    = source;

    while (idx && (idx2 = strchr (idx+1, sep))) {

        tmpChar = *(++idx2); *idx2 = '\0';
        if (strstr (target, idx)) {

            retCode = TRUE;
            break;

        }

        *(idx2) = tmpChar;
        idx = --idx2;

    }

    free (source);
    free (target);
    return (retCode);

}
/* end of function: strlstcmp */

PUBLIC char *hex_html_encode(string, flag)
char *string;
int flag; /* 0->hex 1->html */
{
	static char strbuf[10*BUFSIZ];
	char *strptr;

	*strbuf = '\0';
	for(strptr = string; *strptr; strptr++){
		/* 200 a -> &auml; fuer aouAOU */
		if((flag==1) && (((int)*strptr&255)==200)) {
			if(strchr("aouAOU", *(strptr+1))) {
				sprintf(strbuf, "%s&%cuml;", strbuf, *++strptr);
				continue;
			}
		}

		/* &#xxx; Handling-Patch */
		if((flag==1) && (((int)*strptr&255)>=160)) {
			sprintf(strbuf, "%s&#%d;", strbuf, ((int)*strptr&255));
			continue;
		}
		/* end Patch */

		if(!encoding_tbl[(int)*strptr&255][flag]) {
			sprintf(strbuf, "%s%c", strbuf, *strptr);
		} else {
			strcat(strbuf, encoding_tbl[(int)*strptr&255][flag]);
		}
	}
	return(strbuf);
}
/* end of function: hex_html_encode */

/* Strips basecount+1 characters of type target at the end of an RDN */
PUBLIC char *dnrcut(rdn, target, basecount) 
char *rdn;
char *target;
int basecount;
{
	static char buf[BUFSIZ];
	char *strptr;
	int rdncount, morecount;

	rdncount = chrcnt(rdn, target);
	if( (morecount = (rdncount - basecount)) > 0) {
		strcpy(buf, rdn);
		strptr = buf-1;
		while(morecount--) {
			strptr = strpbrk(strptr+1, target);
		}
		*strptr = '\0';
	} else *buf = '\0';
	return(buf);
}
/* end of function: dnrcut */

PUBLIC char **dn2charray(dn)
char *dn;
{
    char *dnbuf, *strptr, **a=NULL;

	if ( !dn || !*dn ) {

		a = (char **) ch_calloc( 1, sizeof( char ** ));
		return( a );

	}

    dnbuf = strdup(dn);
    do {
        strptr = strrQuoteChr(dnbuf, ',');
        if(strptr) {
            *strptr++ = '\0';
/*
            while(*strptr == ' ') 
                strptr++;
*/
			strptr = trim( strptr, " " );
        }
        charray_add( &a, strptr ? strptr : trim( dnbuf, " " ));
    } while(strptr);
    free(dnbuf);
    return(a);
}
/* end of function: dn2charray */


/* get the parent DN for a given one */
PUBLIC char *
get_parentDN( dn )
char  *dn;
{
	char  **a   = NULL;
	char    tmp[BUFSIZ];

	a = dn2charray( dn );
	*tmp = *(tmp + 1) = '\0';

	if ( a ) {
		char **rdnH;

		/*  we have to re-build the DN beginning at the last array element  */
		for ( rdnH = a; *rdnH; rdnH++ )
			;

		/*  re-build DN from it's parts  */
		rdnH--; rdnH--;
		for ( ; rdnH >= a; rdnH-- ) {

			sprintf( tmp, "%s,%s", tmp, *rdnH );

		}

		charray_free( a );

	}

	/*  ignore a leading ','  */
	return( strdup( tmp + 1 ));

}  /* get_parentDN */


PUBLIC char *elapsed(firsttime, secondtime)
struct timeval firsttime;
struct timeval secondtime;
{
    long int elapsedmicrosec, elapsedsec;
    char elapsed_string[BUFSIZ];
    
    elapsedsec = secondtime.tv_sec - firsttime.tv_sec;
    elapsedmicrosec = secondtime.tv_usec - firsttime.tv_usec;
    if(elapsedmicrosec < 0) {
        elapsedmicrosec += 1000000;
        elapsedsec -= 1;
    }
    if(elapsedsec > 1000){
        elapsedsec = 0;
        elapsedmicrosec = 0;
    }
    sprintf(elapsed_string, "%ld.%.6ld", elapsedsec, elapsedmicrosec);
    return(strdup(elapsed_string));
}
/* end of function: elapsed */


/* performance-log on exit */
PUBLIC int exit_tweb(rc)
int rc;
{
    struct timeval secondtime;

    gettimeofday(&secondtime, NULL);
    if(!secondtime.tv_sec || !timestore[0].tv_sec) exit(rc);

    if (dosyslog)
		 syslog (LOG_INFO, "performance: %s#%s#%s#%s#%s#%s#%d seconds <%08d>",
        	elapsed(timestore[0], secondtime), elapsed(timestore[0],
			timestore[1]), elapsed(timestore[1], timestore[2]),
        	elapsed(timestore[2], timestore[3]),
        	elapsed(timestore[3], items_displayed ? timestore[4] : secondtime),
        	items_displayed ? elapsed(timestore[4], secondtime) : "",
        	items_displayed, globP->svc_cnt);
    exit(rc);
}
/* end of function: exit_tweb */

