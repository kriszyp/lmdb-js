/* testavl.c - Test Tim Howes AVL code */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/string.h>

#include "avl.h"

static void ravl_print LDAP_P(( Avlnode *root, int depth ));
static void myprint LDAP_P(( Avlnode *root ));

int
main( int argc, char **argv )
{
	Avlnode	*tree = NULLAVL;
	char	command[ 10 ];
	char	name[ 80 ];
	char	*p;

	printf( "> " );
	while ( fgets( command, sizeof( command ), stdin ) != NULL ) {
		switch( *command ) {
		case 'n':	/* new tree */
			( void ) avl_free( tree, (AVL_FREE) free );
			tree = NULLAVL;
			break;
		case 'p':	/* print */
			( void ) myprint( tree );
			break;
		case 't':	/* traverse with first, next */
			printf( "***\n" );
			for ( p = (char * ) avl_getfirst( tree );
			    p != NULL; p = (char *) avl_getnext( /* tree, p */ ) )
				printf( "%s\n", p );
			printf( "***\n" );
			break;
		case 'f':	/* find */
			printf( "data? " );
			if ( fgets( name, sizeof( name ), stdin ) == NULL )
				exit( 0 );
			name[ strlen( name ) - 1 ] = '\0';
			if ( (p = (char *) avl_find( tree, name, (AVL_CMP) strcmp ))
			    == NULL )
				printf( "Not found.\n\n" );
			else
				printf( "%s\n\n", p );
			break;
		case 'i':	/* insert */
			printf( "data? " );
			if ( fgets( name, sizeof( name ), stdin ) == NULL )
				exit( 0 );
			name[ strlen( name ) - 1 ] = '\0';
			if ( avl_insert( &tree, strdup( name ), (AVL_CMP) strcmp, 
			    avl_dup_error ) != 0 )
				printf( "\nNot inserted!\n" );
			break;
		case 'd':	/* delete */
			printf( "data? " );
			if ( fgets( name, sizeof( name ), stdin ) == NULL )
				exit( 0 );
			name[ strlen( name ) - 1 ] = '\0';
			if ( avl_delete( &tree, name, (AVL_CMP) strcmp ) == NULL )
				printf( "\nNot found!\n" );
			break;
		case 'q':	/* quit */
			exit( 0 );
			break;
		case '\n':
			break;
		default:
			printf("Commands: insert, delete, print, new, quit\n");
		}

		printf( "> " );
	}

	return( 0 );
}

static void ravl_print( Avlnode *root, int depth )
{
	int	i;

	if ( root == 0 )
		return;

	ravl_print( root->avl_right, depth+1 );

	for ( i = 0; i < depth; i++ )
		printf( "   " );
	printf( "%s %d\n", (char *) root->avl_data, root->avl_bf );

	ravl_print( root->avl_left, depth+1 );
}

static void myprint( Avlnode *root )
{
	printf( "********\n" );

	if ( root == 0 )
		printf( "\tNULL\n" );
	else
		ravl_print( root, 0 );

	printf( "********\n" );
}
