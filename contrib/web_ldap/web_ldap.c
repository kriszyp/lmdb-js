/* web_ldap.c
 * Form Processing Web application that returns html based
 * LDAP data with definitions from a configuration file.
 *
 * Jens Moller - Dec 11, 1998
 */

#include "portable.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>
#include "ldif.h"
#include "maint_form.h" /* for HTML Form manipulations */

/* default values */
#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif
#ifndef SERVER
#define SERVER "ldap.bigfoot.com"
#endif
#ifndef CONFIG
#define CONFIG "web_ldap.cfg"
#endif

#define MAX_ATTRIB 100
#define MAX_CHARS  256
#define version "v 1.1"

entry entries[MAX_ENTRIES];

typedef struct {
   char servername[MAX_CHARS];
   char query[MAX_CHARS];
   char searchbase[MAX_CHARS];
   char htmlfile[MAX_CHARS];
   int  ldap_port_num;
   int  num_of_attrib;
   int  debug; /* if zero, no debug text displayed */
} LDAP_INFO;

typedef struct {
   char  title[40];
} ATTRIB_TITLE; 

/* function Prototypes */
void process_cfg(char *config, 
		 LDAP_INFO *ldap_data,
		 char *attribute_array[],
		 ATTRIB_TITLE *disp_attrib);

int  strscn(char *istring, 
	    char *tstring);

void upcase_string(char *array, 
		   char *uparray);

int  find_comma(char *array);

int find_colon(char *array);

void squeeze_blanks(char *array);

/* Pass in nothing and use the default config file, or
 * pass in the config file to use */

main(int argc, char ** argv) {
   LDAP         *ld;
   LDAPMessage  *res, *e;
   int          i, j, cl, x, how_many;
   char         *a, *dn, *value;
   BerElement   *ptr;
   char         **vals;
   char         *read_attrs[MAX_ATTRIB]; /* up to MAX_ATTRIB attribs returned */
   struct       berval **bvals;
   char         attrs_name[MAX_CHARS];
   char         config_file[MAX_CHARS];
   char         temp[MAX_CHARS];
   char         passed_in[MAX_CHARS];
   LDAP_INFO    ldap_data;
   ATTRIB_TITLE attribute[MAX_ATTRIB];
   time_t       now;
   FILE         *logfp;
   
   
   /* html initialization */
   printf("Content-type: text/html\n\n");
   printf("<html>\n<head>\n<title>Web Ldap Results</title>\n");
   printf("</head>\n");
   printf("<body text=\"#000000\" bgcolor=\"#FFFFFF\">\n");
   printf("<h2>Web LDAP Results</h2>\n");
   
   /* initialize ldap_data structure */
   memset(ldap_data.servername,0,MAX_CHARS);
   memset(ldap_data.query,0,MAX_CHARS);
   memset(ldap_data.searchbase,0,MAX_CHARS);
   memset(ldap_data.htmlfile,0,MAX_CHARS);
   ldap_data.ldap_port_num  = 0;
   ldap_data.num_of_attrib  = 0;
   ldap_data.debug          = 0;
   
   memset(passed_in,0,MAX_CHARS);

   if (argc > 1) { /* interactive mode */
      
      /* To use in this fashion when run from a Unix command line:
       * 
       * > web_ldap DEF "cn=j*moller"
       * > web_ldap DEF cn=jens moller
       *
       * NOTE: The quotes are required if a special
       * character is a part of the LDAP request such
       * as the asterix (*) in the above example.
       */
      
      /* Parameters passed in are
       * 
       * argv[0] = Program Name     (argc =  1)
       * argv[1] = Config File Name (argc =  2)
       * argv[2] = Ldap Request     (argc => 3)
       */
      
      /* do we use a different config file ? */
      strcpy(config_file, CONFIG);
   
      if (argc == 2){
	 if ((strcmp(argv[1],"DEF")) == 0) {
	    strcpy(config_file, CONFIG);
	 }
	 else {
	    strcpy(config_file, argv[1]);
	 }
      }
   
      /* is there an LDAP request?   
       * if so, it may take up to 3 argv[x] values */
      
      if (argc >= 3) {
	 if (argc == 3) {
	    strcpy(temp, argv[2]);
	 }
	 
	 if (argc == 4) {
	    strcpy(temp, argv[2]);
	    strcat(temp, " ");
	    strcat(temp, argv[3]);
	 }
	 
	 if (argc == 5) {
	    strcpy(temp, argv[2]);
	    strcat(temp, " ");
	    strcat(temp, argv[3]);
	    strcat(temp, " ");
	    strcat(temp, argv[4]);
	 }
	 
	 j = 0;
	 for (i=0; i<strlen(temp);i++) {
	    if ((temp[i] != '"') &&
		(temp[i] != '\\')){
	       passed_in[j] = temp[i];
	       j++;
	    }
	 }
      }
   }
   else { /* Non Interactive Mode - read from a form */
      if (strcompare(getenv("REQUEST_METHOD"),"POST"))
	{
	   printf("<p>++ Error - This script should be referenced with a METHOD of POST.\n");
	   exit( EXIT_FAILURE );
	}
      if (strcompare(getenv("CONTENT_TYPE"),"application/x-www-form-urlencoded"))
	{
	   printf("<p>++ Error - This script can only be used to decode form results. \n");
	   exit( EXIT_FAILURE );
	}
      cl = atoi(getenv("CONTENT_LENGTH"));
      
      for(x=0; cl && (!feof(stdin));x++)
	{
	   entries[x].val = fmakeword(stdin,'&',&cl);
	   plustospace(entries[x].val);
	   unescape_url(entries[x].val);
	   entries[x].name = makeword(entries[x].val,'=');
	   how_many = x; /* keep track of how many we got */
	   
#ifdef DEBUG_TEXT
	   printf("entries[%d].name=%s - ",x,entries[x].name);
	   printf("entries[%d].val =%s<br>\n",x,entries[x].val);
#endif
	}
      
      entries[x].name = NULL;    /* entry after last valid one */
      entries[x].val = NULL;     /* is set to NULL */
      
      if(!getvalue(entries, "FORM", &value))
	{
	   printf("%s%s%s", "This script expected a 'FORM' value returned ",
		  "and did not get one.  Make sure the HTML used for this ",
		  "script is correct.");
	   exit( EXIT_FAILURE );
	} 
      
      /* Looking for:
       * LDAP_REQUEST - actual LDAP request, ie 'cn=j*moller'
       * CONFIG       = Configuration file
       */

      strcpy(config_file, CONFIG);
      
      if(getvalue(entries, "LDAP_REQUEST", &value)) {
	        strcpy(passed_in,value);
      }
      
      if(getvalue(entries, "CONFIG", &value)) {
	 if ((strcmp("DEF",value)) == 0) {
      	    strcpy(config_file, CONFIG);
	 }
	 else {
	    strcpy(config_file, value);
	 }
      }
      
   }
   
   /* zero out the attribute pointers/data area */
   for (i = 0; i < MAX_ATTRIB; i++) {
      read_attrs[i] = NULL;
      memset(attribute[i].title,0,40);
   } 
   
   /* read in the config file */
   process_cfg(config_file, &ldap_data, read_attrs, attribute);
   
   if (passed_in[0] != 0) {
      strcpy(ldap_data.query,passed_in);
   }
   
   if (ldap_data.debug != 0) {
      if ((logfp = fopen("web_ldap.log","w")) == 0) {
	 printf("<font color=red size=5>\n");
	 printf("<p>Unable to open requested log file: web_ldap.log<p>\n");
	 printf("</font>\n");
      }
      else { 
	 time(&now);
	 sprintf(temp,"==> web_ldap request made at: %s\n",ctime(&now));
	 fputs(temp,logfp);
	 if (argc > 1) {
	    sprintf(temp," Interactive Unix Command Line Request:\n\n");
	 }
	 else {
	    sprintf(temp," Browser/Form Request:\n\n");
	 }
	 fputs(temp,logfp);
	 sprintf(temp," Server Name: %s\n", ldap_data.servername);
	 fputs(temp,logfp);
	 sprintf(temp," Query: %s\n", ldap_data.query);
	 fputs(temp,logfp);
	 sprintf(temp," Passed In: %s\n", passed_in);
	 fputs(temp,logfp);
	 sprintf(temp," Searchbase: %s\n",ldap_data.searchbase);
	 fputs(temp,logfp);
	 if (ldap_data.htmlfile[0] != 0) {
	    sprintf(temp," HTML File: %s\n",ldap_data.htmlfile);
	 }
	 else {
	    sprintf(temp," HTML File: Non Provided - Use Default Processing\n");
	 }
	 fputs(temp,logfp);
	 sprintf(temp," LDAP Port: %d\n",ldap_data.ldap_port_num);
	 fputs(temp,logfp);
	 sprintf(temp," Number of Attributes: %d\n",ldap_data.num_of_attrib);
	 fputs(temp,logfp);
	 if (ldap_data.num_of_attrib > 0) {
	    for (i = 0; i < ldap_data.num_of_attrib; i++) {
	       sprintf(temp," - %s\n",read_attrs[i]);
	       fputs(temp,logfp);
	    }
	 }
	 
	 sprintf(temp,"\n==< Process Arguments: %d >==\n\n argv[0]: %s\n",
		 argc, argv[0]);
	 fputs(temp,logfp);
	 if (argc >= 2) {
	   sprintf(temp," argv[1]: %s\n",argv[1]);
	    fputs(temp,logfp);
	 }
	 if (argc >= 3) {
	    sprintf(temp," argv[2]: %s\n",argv[2]);
	    fputs(temp,logfp);
	 }
	 if (argc >= 4) {
	    sprintf(temp," argv[3]: %s\n",argv[3]);
	    fputs(temp,logfp);
	 }
	 if (argc >= 5) {
	    sprintf(temp," argv[4]: %s\n",argv[4]);
	    fputs(temp,logfp);
	 }
	 fflush(logfp);
	 fclose(logfp);
      }
   }
   
   if (ldap_data.debug != 0) {
      if ((logfp = fopen("web_ldap.log","a")) == 0) {
      }
      else {
	 time(&now);
	 sprintf(temp,"\n==< Results >==\n\n");
	 fputs(temp,logfp);
	 sprintf(temp,"** performing ldap_init at %s\n", ctime(&now));
	 fputs(temp,logfp);
	 fflush(logfp);
	 fclose(logfp);
      }
   }
   if ( (ld = ldap_init(ldap_data.servername, ldap_data.ldap_port_num) ) == NULL)
     {
	printf("<font color=red><b>ldap_init error</b></font>\n");
	if (ldap_data.debug != 0) {
	   if ((logfp = fopen("web_ldap.log","a")) == 0) {
	   }
	   else {
	      sprintf(temp,"++ ldap_init error\n");
	      fputs(temp,logfp);
	      fflush(logfp);
	      fclose(logfp);
	   }
	}
	printf("</body>\n</html>\n");
	exit( EXIT_FAILURE );
     }
   
   /*authenticate as nobody */
   if (ldap_data.debug != 0) {
      if ((logfp = fopen("web_ldap.log","a")) == 0) {
      }
      else {
	 time(&now);
	 sprintf(temp,"** performing ldap_bind_s at %s\n",ctime(&now));
	 fputs(temp,logfp);
	 fflush(logfp);
	 fclose(logfp);
      }   
   }   
   if(ldap_bind_s(ld, "", "", LDAP_AUTH_SIMPLE) != 0)
     {
	printf("<font color=red><b>");
	ldap_perror (ld, "ldap_simple_bind_s");
	printf("</b></font>\n");

	if (ldap_data.debug != 0) {
	   if ((logfp = fopen("web_ldap.log","a")) == 0) {
	   }
	   else {
	      sprintf(temp,"++ ldap_bind_s error\n");
	      fputs(temp,logfp);
	      fflush(logfp);
	      fclose(logfp);
	   }
	}
	printf("</body>\n</html>\n");
	exit( EXIT_FAILURE );
     }
   
   printf("<b>Directory Lookup Results</b>\n<pre>\n");
   printf("<hr><p>\n<pre>\n");
   
   /* Get data */
   if (ldap_data.debug != 0) {
      if ((logfp = fopen("web_ldap.log","a")) == 0) {
      }
      else {
	 time(&now);
	 sprintf(temp,"** performing ldap_search_s at %s\n",ctime(&now));
	 fputs(temp,logfp);
	 fflush(logfp);
	 fclose(logfp);
      }
   }
   if(ldap_search_s(ld, ldap_data.searchbase, LDAP_SCOPE_SUBTREE,
		    ldap_data.query, read_attrs, 0, &res)
      != LDAP_SUCCESS)
     {
	ldap_perror(ld, "ldap_search_s");
     }
   
   for (e=ldap_first_entry(ld, res); e != NULL; e=ldap_next_entry(ld, e))
     {
	dn = ldap_get_dn(ld, e);
	
	if (ldap_data.debug != 0) {	
	   if ((logfp = fopen("web_ldap.log","a")) == 0) {
	   }
	   else {
	      sprintf(temp," dn=%s\n", dn);
	      fputs(temp,logfp);
	      fflush(logfp);
	      fclose(logfp);
	   }
	}
	
	/*print each attribute */
	for (a = ldap_first_attribute(ld, e, &ptr);
	     a != NULL;
	     a = ldap_next_attribute(ld, e, ptr) )
	  {
	     strcpy(attrs_name, a);
	     /* print attribute name */
	     printf("%s: ", attrs_name);
	     
	     /*print each value */
	     
	     vals = ldap_get_values(ld, e, a);
	     
	     for(i=0; vals[i] != NULL; i++)
	       /* print value of attribute */
	       printf("%s\n", vals[i],strlen(vals[i]));
	   
	     ldap_value_free(vals);
	  } /*end for*/
	free(a);
	free(dn);
	printf("<p>\n");
     }
   /*free the search results */
   ldap_msgfree (res);
   
   printf("</pre>\n");

   ldap_unbind(ld);
   
   if (ldap_data.debug != 0) {
      if ((logfp = fopen("web_ldap.log","a")) == 0) {
      }
      else {
	 time(&now);
	 sprintf(temp,"\nFinished gathering results at %s\n",ctime(&now));
	 fputs(temp,logfp);
	 sprintf(temp,"==< Done >==\n");
	 fputs(temp,logfp);
	 fflush(logfp);
	 fclose(logfp);
      }
   }
   printf("</body>\n</html>\n");
}
   
/* Process the user passed in configuration file */
void process_cfg(char *config, 
		 LDAP_INFO *ldap_data,
		 char *attribute_array[],
		 ATTRIB_TITLE *disp_attrib) {
   
   char   file_data[1024];
   char   upfile_data[1024];
   char   temp[1024];
   int    lcomma, lcolon, attrib_pos;
   FILE * fp;
   
   strcpy(ldap_data->servername,SERVER);
   ldap_data->ldap_port_num = LDAP_PORT;
   strcpy(ldap_data->query,"cn=jens*moller");
   
   /* config file needs to be in the cgi-bin directory */
   if ((fp = fopen(config,"r")) == 0) {
      return;
   }
   
   attrib_pos = 0;
   
   for (;;) { /* read until eof */
      fgets (file_data,1024,fp);
      if (feof(fp)) break;
      if (file_data[0] != '#') { /* skip commented lines */
	 upcase_string(file_data,upfile_data);

	 /* get the server specific data */
	 if (strscn(upfile_data,"SERVER:") == 0) {
	    lcolon = find_colon(file_data) + 1;
	    lcomma = find_comma(file_data);
	    if (lcomma > 0) {
	       memset(ldap_data->servername,0,MAX_CHARS);
	       strncpy(ldap_data->servername,&file_data[lcolon],
		       lcomma - lcolon);
	       ldap_data->ldap_port_num = atoi(&file_data[lcomma + 1]);
	    }
	    else {
	       strcpy(ldap_data->servername,&file_data[lcolon]);
	    }
	    squeeze_blanks(ldap_data->servername);
	 }
	 else if (strscn(upfile_data,"SEARCHBASE:") == 0) {
	    lcolon = find_colon(file_data) + 1;
	    strcpy(ldap_data->searchbase,&file_data[lcolon]);
	    squeeze_blanks(ldap_data->searchbase);
	 }
	 else if (strscn(upfile_data,"HTMLFILE:") == 0) {
	    lcolon = find_colon(file_data) + 1;
	    strcpy(ldap_data->htmlfile,&file_data[lcolon]);
	 }
	 else if (strscn(upfile_data,"DEBUG:") == 0) {
	    lcolon = find_colon(file_data) + 1;
	    ldap_data->debug = atoi(&file_data[lcolon]);
	 }
	 
	 /* get the attribute list */
	 else if ((file_data[0] != ' ') && (file_data[0] != 0)) {
	    memset(temp,0,1024);
	    /* data appears as a comma delimited list, where:
	     * 
	     * attrib_name (char),display_length (int)
	     *
	     * (default length = 20 if display_length undefined)
	     * 
	     * is how each record is defined */
	    lcomma = find_comma(file_data);
	    if (lcomma < 0) {
	       strcpy(temp,file_data);
	       squeeze_blanks(temp);
	    }
	    else {
	       strncpy(temp,file_data,lcomma);
	       squeeze_blanks(temp);
	    }
	    attribute_array[attrib_pos] = malloc(strlen(temp));
	    strcpy(attribute_array[attrib_pos],temp);
	    attrib_pos++;
	    ldap_data->num_of_attrib = attrib_pos;
	 }
      }
   }
}

/* find character substring matches */
int strscn(char * istring, 
	   char * tstring) {
   int  i, status, icmp, len;
   status = -1;
   len = (strlen(istring) + 1) - strlen(tstring);
   if (len < 1) len = 1;
   for (i=0;i<len ;i++) {
      icmp = memcmp(&istring[i],tstring,strlen(tstring));
      if (icmp == 0) {
	 status = i;
	 break;
      }
   }
   return status;
}

/* convert the array to uparray, where uparray contains upper
 * case characters */
void upcase_string(char *array, 
		   char *uparray) {
   int  i;
   for (i=0; i < strlen(array); i++) {
      uparray[i] = toupper((unsigned char) array[i]);
      uparray[i + 1] = 0;
   }
   return;
}

/* return the position of the first comma - ',' - from within a string */
int find_comma(char *array){
   int  i;
   for (i = 0; i < strlen(array); i++) {
      if (array[i] == ',') return(i);
   }
   return -1;
}

/* return the position of the first colon - '.' - from within a string */
int find_colon(char *array){
   int  i;
   for (i = 0; i < strlen(array); i++) {
      if (array[i] == ':') return(i);
   }
   return -1;
}

/* Remove unneeded blanks from a character array. Don't leave 
 * any at the end & throw away any newline characters  */
void squeeze_blanks(char *array){
   int  i, pos, blank;
   char temp[1024];
   memset(temp,0,1024);
   
   pos   = 0; /* location within temp array */
   blank = 0; /* # of blanks written in a row */
 
   for (i = 0; i < strlen(array); i++) {
      if (array[i] != ' ') {
	 temp[pos] = array[i];
	 blank = 0;
	 pos++;
      }
      else if ((blank == 0) && 
	       (array[i] == ' ') &&
	       (pos != 0)) {
	 temp[pos] = array[i];
	 blank += 1;
	 pos++;
      }
   }
   strcpy(array,temp);
   if (array[strlen(array) - 1] <= ' ') 
     array[strlen(array) - 1] = 0;
}
