/* util.c 
 *
 * This code module originates from NCSA 
 * See: http://hoohoo.ncsa.uiuc.edu/cgi/
 * and: ftp://ftp.ncsa.uiuc.edu/Web/httpd/Unix/ncsa_httpd/cgi/cgi-src/
 * 
 * Most of the above listed programs were combined into a single
 * file (this one) - everything here is public domain and free for
 * use in any form..
 *
 * Corrections made for SGI systems (Irix) and
 * time/date functions added - R. Scott Guthrie 
 */ 

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/time.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/unistd.h>

#include "process_form.h"

/*--------------*/
/*  strcompare  */
/*--------------*/
/* This fixes the SGI strcmp function which aborts when passed
 * a NULL in place of a NULL TERMINATED STRING.
 * (The code that depended on it was ported from SUN which considered
 * a NULL to be a NULL terminated string. The standard says strcmp
 * action is undefined when passed a NULL. SGI abends.)
 */
int strcompare(char* a, char* b)
{
  if(a && b)
    return(strcmp(a, b));  /* neither char* is NULL */
  return(1);    /* different if either (or both) char* are NULL */
}


/*------------*/
/*  getvalue  */
/*------------*/
/* put a pointer to the value in 'value' for the key specified.
 */
int getvalue(entry* list, char* key, char** value)
{
  int index = 0;

  *value = NULL;    /* initialize value to NULL */

  while(list[index].name)
  {
    if(strcmp(list[index].name, key) == 0)
    {
      *value = list[index].val;
      return(1);  /* success */
    }
    index++;
  }
  return(0);  /* no key value found in list */
}


/*------------------*/
/*  append_to_list  */
/*------------------*/
/* Append name/value pair to end of list */
int append_to_list(entry* list, char* key, char* value)
{
  int index = 0;
  char* newname;
  char* newvalue;

  /* go to end of list */
  while(list[index].name)
    index++;

  if(index > MAX_ENTRIES)
    return(0); /* out of room */

  newname = (char *) malloc(sizeof(char) * (strlen(key) + 1));
  strcpy(newname, key);
  list[index].name = newname;

  newvalue = (char *) malloc(sizeof(char) * (strlen(value) + 1));
  strcpy(newvalue, value);
  list[index].val = newvalue;

  /* put new nulls at end. */
  index++;
  list[index].name = NULL;
  list[index].val = NULL;
  return(1);  /* success */
}

/*----------------------*/
/*  remove_table_entry  */
/*----------------------*/
/* replaces table entry 'name' name field with '~' */
int remove_table_entry(entry* list, char* name)
{
  int index = 0;

  /* search table for matching name entry */
  while(1)  /* FOREVER  - breaks out with return */
  {
    if(list[index].name == NULL)
      return(0);   /* not in list */

    if(strcmp(list[index].name, name) == 0)
    {
      /* found match.  remove name */
      free(list[index].name);

      /* allocate space for deleted name */
      if((list[index].name = (char*)malloc(2 * sizeof(char))) == NULL)
        return(0);  /* malloc error */
      else
        strcpy(list[index].name, "~");    /* DELETE INDICATOR */
      return(1);  /* replacement successful */
    }
    index++;  /* try next name */
  }
  return(0);  /* cannot get here */
}  /* remove_table_entry */


/*------------*/
/*  makeword  */
/*------------*/
char* makeword(char *line, char stop) 
{
  int x = 0,y;
  char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

  for(x=0;((line[x]) && (line[x] != stop));x++)
    word[x] = line[x];

  word[x] = '\0';
  if(line[x]) ++x;
  y=0;

  while(line[y++] = line[x++]);
  return word;
}


/*-------------*/
/*  fmakeword  */
/*-------------*/
char* fmakeword(FILE *f, char stop, int *cl)
{
  int wsize;
  char *word;
  int ll;

  wsize = 102400;
  ll=0;
  word = (char *) malloc(sizeof(char) * (wsize + 1));

  while(1)
  {
    word[ll] = (char)fgetc(f);
    if(ll==wsize)
    {
      word[ll+1] = '\0';
      wsize+=102400;
      word = (char *)realloc(word,sizeof(char)*(wsize+1));
    }
    --(*cl);

    if((word[ll] == stop) || (feof(f)) || (!(*cl)))
    {
      if(word[ll] != stop) ll++;
      word[ll] = '\0';
      return word;
    }
    ++ll;
  }
  return(NULL);
}


/*-------*/
/*  x2c  */
/*-------*/
char x2c(char *what) 
{
  register char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return(digit);
}

/*----------------*/
/*  unescape_url  */
/*----------------*/
void unescape_url(char *url)
{
  register int x,y;

  for(x=0,y=0;url[y];++x,++y)
  {
    if((url[x] = url[y]) == '%')
    {
      url[x] = x2c(&url[y+1]);
      y+=2;
    }
  }
  url[x] = '\0';
}


/*---------------*/
/*  plustospace  */
/*---------------*/
void plustospace(char *str) 
{
  register int x;

  for(x=0;str[x];x++) if(str[x] == '+') str[x] = ' ';
}


/*-------------------------*/
/*  remove_leading_blanks  */
/*-------------------------*/
void remove_leading_blanks(char* str)
{
  int i;
  while(str[0] == ' ')
  {
    i = 1;
    do
    {
      str[i-1] = str[i];
    } while(str[i++]);
  }
} /* end 'remove_leading_blanks()' */


/*-------------------------*/
/* remove_trailing_blanks  */
/*-------------------------*/
void remove_trailing_blanks(char* str)
{
  while(str[strlen(str) - 1] == ' ')
    str[strlen(str) - 1] = '\0';
} /* end 'remove_trailing_blanks()' */


/*-----------------*/
/*  pad_with_char  */
/*-----------------*/
void pad_with_char(char* buffer, int length, char padchar)
{
  /* if the 'buffer' is >= then 'length', return.
   * Pad the 'buffer' with 'padchar' until = 'length'
   */
  int pos;
  while((pos = strlen(buffer)) < length)
  {
    buffer[pos] = padchar;
    buffer[pos+1] = '\0';
  }
} /* end pad_with_char */


/*---------------------*/
/*  lower_case_string  */
/*---------------------*/
char* lower_case_string(char* inputbuf)
{
  int pos = 0;

  while(inputbuf[pos])
  {
    inputbuf[pos] = (char)tolower((unsigned char) inputbuf[pos]);
    pos++;
  }
  return(inputbuf);
}  /* lower_case_string */


/*---------------------*/
/*  upper_case_string  */
/*---------------------*/
char* upper_case_string(char* inputbuf)
{
  int pos = 0;

  while(inputbuf[pos])
  {
    inputbuf[pos] = (char)toupper((unsigned char) inputbuf[pos]);
    pos++;
  }
  return(inputbuf);
}  /* upper_case_string */


/*------------*/
/*  strip_CR  */
/*------------*/
void strip_CR(char* buffer)
{
  char* bufferptr;
  char* newptr;

  bufferptr = buffer;
  newptr = buffer;

  while(*bufferptr)
  {
    if(*bufferptr != '\r')
    {
      *newptr = *bufferptr;
      newptr++;
    }
    bufferptr++; 
  }
  *newptr = '\0';

  return;
}

/*------------------*/
/*  show_form_data  */
/*------------------*/
/* THIS ROUTINE IS USED FOR DEBUGGING and will not be called in production */
void show_form_data(entry* entries)
{
  int x = 0;

  printf("<HR><H1>Form Data</H1>");
  printf("The following Name Value pairs currently exist:<p>%c",10);
  printf("<ul><pre>%c",10);

  while(entries[x].name)
  {
    printf("<li> <code>%s = [%s]</code>%c",entries[x].name,
            entries[x].val,10);
    x++;
  }
  printf("</pre></ul>%c",10);
}

/*------------------------*/
/*  maint_show_form_data  */
/*------------------------*/
/* THIS ROUTINE IS USED FOR DEBUGGING and will not be called in production */
void maint_show_form_data(entry* entries)
{
  int x = 0;

  printf("Content-type: text/html\n\n");
  printf("<HR><H1>Form Data</H1>");
  printf("The following Name Value pairs currently exist:<p>%c",10);
  printf("<ul><pre>%c",10);

  while(entries[x].name)
  {
    printf("<li> <code>%s = [%s]</code>%c",entries[x].name,
            entries[x].val,10);
    x++;
  }
  printf("</pre></ul>%c",10);
}

/*---------------------*/
/*  display_html_text  */
/*---------------------*/
/* display the text found in the indicated file */
void display_html_text(char* filename)
{
  FILE *fp;
  char buffer[256];

  if((fp = fopen(filename, "r")) == NULL)
  {
    printf("%s%s%s",
      "<p><b>(OOPS... We are unable to open file ",
      filename,
      " for reading)</b><p>\n");
  }
  while(fgets(buffer, 256, fp) != NULL)
  {
    if(buffer[strlen(buffer) - 1] == '\n')
      buffer[strlen(buffer) - 1] = '\0';
    printf("%s\n", buffer);
  }
  fclose(fp);
  return ;
}  /* display_html_text */


/*-----------------*/
/*  unformat_cost  */
/*-----------------*/
/* this routine converts a string value and
 * converts it to an integer.
 */
long unformat_cost(char* cost)
{
  char buf[100];
  int buf_siz = 0;

  char* spos = cost;
  char* dpos = buf;

  /* Make sure a string was passed */
  if(!spos)
    return(0L);

  /* while in the string */
  while(*spos)
  {
    if(*spos == '.')
      break;
    if(isdigit((unsigned char) *spos))
      *dpos++ = *spos;
    spos++;
    if(buf_siz++ == 98) /* make sure we don't overrun buf */
      break;
  }
  *spos = '\n';
  return(atol(buf));
}

/*---------------*/
/*  digits_only  */
/*---------------*/
int digits_only(char* str)
{
  char* pos;

  pos = str;
  while(*pos)
  {
    if(!isdigit((unsigned char) *pos))
      return(0);    /* non-digit found */
    pos++;
  } 
  return(1);
}

/*-------------*/
/*  util_year  */
/*-------------*/
/* return current year -> 0 thru 99 */
int util_year()
{
   time_t  t;
   struct  tm *tptr;
   int     ret_val;
   time(&t);
   tptr    = localtime(&t);
   ret_val = tptr->tm_year;
   return(ret_val);
}

/*--------------*/
/*  util_month  */
/*--------------*/
/* return Month of current year -> 1 thru 12 */
int util_month()
{
   time_t  t;
   struct  tm *tptr;
   int     ret_val;
   time(&t);
   tptr    = localtime(&t);
   ret_val = tptr->tm_mon;
   return(ret_val + 1);
}

/*------------*/
/*  util_day  */
/*------------*/
/* return day of Month -> 1 thru 31 */
int util_day()
{
   time_t  t;
   struct  tm *tptr;
   int     ret_val;
   time(&t);
   tptr    = localtime(&t);
   ret_val = tptr->tm_mday;
   return(ret_val);
}

/*-------------*/
/*  util_hour  */
/*-------------*/
/* return hour of day -> 0 thru 23 */
int util_hour()
{
   time_t  t;
   struct  tm *tptr;
   int     ret_val;
   time(&t);
   tptr    = localtime(&t);
   ret_val = tptr->tm_hour;
   return(ret_val);
}

/*---------------*/
/*  util_minute  */
/*---------------*/
/* return minute of day -> 0 thru 59 */
int util_minute()
{
   time_t  t;
   struct  tm *tptr;
   int     ret_val;
   time(&t);
   tptr    = localtime(&t);
   ret_val = tptr->tm_min;
   return(ret_val);
}

/*---------------*/
/*  util_second  */
/*---------------*/
/* return second of day -> 0 thru 59 */
int util_second()
{
   time_t  t;
   struct  tm *tptr;
   int     ret_val;
   time(&t);
   tptr    = localtime(&t);
   ret_val = tptr->tm_sec;
   return(ret_val);
}

/* end file 'util.c' */
