/*++
/* NAME
/*	hash 3
/* SUMMARY
/*	compute hash value for string
/* SYNOPSIS
/*	int hash(string, size)
/*	char *string;
/*	int size;
/* DESCRIPTION
/*	This function computes for the given null-terminated string an
/*	integer hash value in the range 0..size-1.
/* SEE ALSO
/* .fi
/*	Alfred V. Aho, Ravi Sethi and Jeffrey D. Ullman: Compilers: 
/*	principles, techniques and tools; Addison-Wesley, Amsterdam, 1986.
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/*
/*	Originally written by: P. J. Weinberger at Bell Labs.
/* LAST MODIFICATION
/*	92/01/15 21:53:12
/* VERSION/RELEASE
/*	%I
/*--*/

static char hash_sccsid[] = "@(#) hash.c 1.1 92/01/15 21:53:12";

/* hash - hash a string; original author: P. J. Weinberger at Bell Labs. */

int     hash(s, size)
register char *s;
unsigned size;
{
    register unsigned long h = 0;
    register unsigned long g;

    /*
     * For a performance comparison with the hash function presented in K&R,
     * first edition, see the "Dragon" book by Aho, Sethi and Ullman.
     */

    while (*s) {
	h = (h << 4) + *s++;
	if (g = (h & 0xf0000000)) {
	    h ^= (g >> 24);
	    h ^= g;
	}
    }
    return (h % size);
}
