 /*
  * @(#) example.c 1.5 93/06/18 22:29:46
  * 
  * Examples of things that can be done with the unproto package
  */

typedef char *charstar;

 /*
  * New-style argument list with structured argument, one field being pointer
  * to function returning pointer to function with function-pointer argument
  */

x(struct {
    struct {
	int (*(*foo) (int (*arg1) (double))) (float arg2);
    } foo;
} baz) {
    return (0);
}

 /* New-style function-pointer declaration. */

int (*(*bar0) (float)) (int);

 /* Old-style argument list with new-style argument type. */

baz0(bar)
int (*(*bar) (float)) (int);
{}

 /*
  * New-style argument list with new-style argument type, declaration
  * embedded within block. Plus a couple assignments with function calls that
  * look like casts.
  */

foo(int (*(*bar) (float)) (int))
{
    int     (*baz) (int) = (int (*) (int)) 0,
	    y = (y * (*baz) (y)),
	    *(*z) (int) = (int *(*) (int)) 0;

    struct { int (*foo)(int); } *(*s)(int) = 
	(struct { int (*foo)(int); } *(*)(int)) 0;

    {
	y = (y * (*baz) (y));
    }
    {
	z = (int *(*) (int)) 0;
    }
    {
	s = (struct { int (*foo)(int); } *(*)(int)) 0;
    }

    return (0);
}

/* Multiple declarations in one statement */

test1()
{
	int foo2,*(*(*bar)(int))(float),*baz(double);
}

/* Discriminate declarations from executable statements */

test2(charstar y)
{
	int foo = 5,atoi(charstar);

	foo = 5,atoi(y);
}

/* Declarations without explicit type */

test3,test4(int);

test5(int y)
{
	{
		test3;
	}
	{
		test4(y);
	}
}

test6[1],test7(int);

test7(int x)
{
	{
		test6[1];
	}
	{
		test7(x);
	}
}

/* Checking a complicated cast */

struct {
    struct {
	int (*f)(int), o;
    } bar;
} (*baz2)(int) = (struct { struct { int (*f)(int), o; } bar; } (*)(int)) 0;

/* Distinguish things with the same shape but with different meaning */

test8(x)
{
    {
	struct {
	    int     foo;
	} bar(charstar);
    }
    {
	do {
	    int     foo;
	} while (x);
    }
}

/* Do not think foo(*bar) is a function pointer declaration */

test9(char *bar)
{
    foo(*bar);
}

/* another couple of special-cased words. */

test10(int x)
{
    {
	int test10(int);
	do  test10(x);
	while (x);
    }
    {
	return test10(x);
    }
}

test11(int *x)
{
	while (*x)
	    (putchar(*x++));
}

test11a(int *x)
{
	for (*x;;)
	    (putchar(*x++));
}

/* #include directive between stuff that requires lookahead */

test12()
{
	char *x = "\xf\0002\002\02\2" /* foo */
#include "/dev/null"
		"\abar";

	printf("foo" /* 1 */ "bar" /* 2 */ "baz");

	*x = '\a';
	*x = '\xff';
}

int test13(void);

/* line continuations in the middle of tokens */

te\
st14();
charstar test15 = "foo\
bar";
char test16 = "foo\\
abar";

/* Array dimensions with unexpanded macros */

test17(charstar foo[bar]){}

int (*(*test18[bar])(charstar))(charstar) = \
	(int (*(*[bar])(charstar))(charstar)) 0;

/* Function returning pointer to function */

int (*(*test19(long))(int))(double);

/* GCC accepts the following stuff, K&R C does not... */

void test20(int test21(double)) {}

void test22(struct { int foo; } test23(short)) {}

/* Do not blindly rewrite (*name(stuff))(otherstuff) */

void    test23()
{
    int     (*test24(int)) (int),
            y = (*test24(2)) (3),
            z = ((*test24(2)) (3));
}

/* Function returning pointer to function */

int (*(*test25(long foo))(int bar))(double baz){ /* body */ }

int (*(*test26(foo))())()
long foo;
{ /* body */ }

#define ARGSTR()   struct {int l; char c[1];}

void functie(ARGSTR() *cmdlin, ARGSTR() *c1)
{
}
