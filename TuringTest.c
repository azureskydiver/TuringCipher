/* @(#)TuringTest.c	1.6 (QUALCOMM Turing) 02/11/28 */
/*
 * Test harness for Turing
 *
 * Copyright C 2002, Qualcomm Inc. Written by Greg Rose
 */

/*
This software is free for evaluation and testing use and
applications subject to the following conditions.

Copyright remains vested in QUALCOMM Incorporated, and Copyright
notices in the code are not to be removed.  If this package is used in
a product, QUALCOMM should be given attribution as the author.  This
can be in the form of a textual message at program startup or in
documentation (online or textual) provided with the package.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

3. All advertising materials mentioning features or use of this
   software must display the following acknowledgement:  This product
   includes software developed by QUALCOMM Incorporated.

4. The software is not to be used for commercial or production purposes.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

The license and distribution terms for any publically available version
or derivative of this code cannot be changed, that is, this code cannot
simply be copied and put under another distribution license including
the GNU Public License.
*/

#include "Turing.h"		/* interface definitions */

/* testing and timing harness */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "hexlib.h"

/* mostly for debugging, print the LFSR contents. */
int	v = 2; /* disables debug stuff */
void
printLFSR(const char *s)
{
    register int	i;
    extern WORD		R[];

    if (v < 2) return;
    printf("%s\n", s);
    for (i = 0; i < LFSRLEN; ++i) {
	printf("%*s%08lx\n", i*4, "", R[i]);
    }
}

void
bzero(unsigned char *b, int n)
{
	while (--n >= 0)
		*b++ = 0;
}

/* test vectors */
BYTE	*testkey = (BYTE *)"test key 128bits";
BYTE	*testframe = (BYTE *)"\0\0\0\0";

#define TESTSIZE 20
char    *testout1 =
	"69 66 26 bb 1f b7 9b 0b b6 ff 82 b3 8a be 44 f2 71 49 50 f0";

#define STREAMTEST 9999
char	*streamout =
	"9a a6 8e 08 e4 84 1d a7 f9 8e 7c 0a b5 79 46 96 eb d2 8c 97";

#define ITERATIONS 999999
char    *iterout =
	"64 d0 07 95 5b c6 ff 4b 73 7c 9f e9 85 72 ad 89 5a 11 7f ca";
char	*ivout = 
	"7e 37 ee 34 65 09 00 93 69 8d 35 90 c7 2d f6 3b 9b 12 47 a7";

BYTE	testbuf[STREAMTEST + MAXSTREAM + TESTSIZE];
BYTE	bigbuf[MAXSTREAM];

void
test_turing(int quick)
{
    int		i, n;
    extern WORD	K[MAXKEY/4];
    extern int	keylen;

    /* basic test */
    bzero(testbuf, sizeof testbuf);
    TuringKey(testkey, strlen((char *)testkey));
    printf("Scheduled key:");
    for (i = 0; i < keylen; ++i)
	printf(" 0x%08lx", K[i]);
    printf("\n");
    TuringIV(testframe, 4);
    printLFSR("Initial LFSR");
    n = TuringGen(testbuf);
    hexprint("one chunk", testbuf, TESTSIZE);
    hexcheck(testbuf, testout1, TESTSIZE);

    /* generate and test more of the same stream */
    while (n < STREAMTEST + TESTSIZE)
	n += TuringGen(testbuf + n);
    hexprint("STREAMTEST", testbuf + STREAMTEST, TESTSIZE);
    hexcheck(testbuf + STREAMTEST, streamout, TESTSIZE);

    if (quick)
	return;

    /* test many times iterated */
    for (i = 0; i < ITERATIONS; ++i) {
	if (i % 500 == 0)
	    printf("%6d\r", i), fflush(stdout);
	TuringKey(testbuf, TESTSIZE);
	TuringIV(NULL, 0);
	TuringGen(testbuf);
    }
    printf("1000000\n");
    hexprint("iterated", testbuf, TESTSIZE);
    hexcheck(testbuf, iterout, TESTSIZE);

    /* test many times iterated through the IV */
    TuringKey(testkey, strlen((char *)testkey));
    TuringIV(NULL, 0);
    bzero(testbuf, sizeof testbuf); TuringGen(testbuf);
    for (i = 0; i < ITERATIONS; ++i) {
	if (i % 500 == 0)
	    printf("%6d\r", i), fflush(stdout);
	TuringIV(testbuf, 4);
	TuringGen(testbuf);
    }
    printf("1000000\n");
    hexprint("IV test", testbuf, TESTSIZE);
    hexcheck(testbuf, ivout, TESTSIZE);
}

void
time_turing(void)
{
    long	i;
    clock_t	t;
    WORD	k[4] = { 0, 0, 0, 0 };

    test_turing(1);
    TuringKey(testkey, strlen((char *)testkey));
    TuringIV((unsigned char *)"", 0);
    /* test stream generation speed */
    t = clock();
    for (i = 0; i < 200000000; )
	i += TuringGen(bigbuf);
    t = clock() - t;
    printf("%f Mbyte per second\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0);

    /* test key setup time */
    t = clock();
    for (i = 0; i < 1000000; ++i) {
	k[3] = i;
	TuringKey((BYTE *)k, 16);
    }
    t = clock() - t;
    printf("%f million 128-bit keys per second\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0);

    /* test IV setup time */
    t = clock();
    for (i = 0; i < 1000000; ++i) {
	k[3] = i;
	TuringIV((BYTE *)k, 16);
    }
    t = clock() - t;
    printf("%f million IVs per second\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0);
}

int
main(int ac, char **av)
{
    int         n, i;
    int		vflag = 0;
    BYTE	key[32], IV[32];
    int         keysz, IVsz;
    extern int	keylen;
    extern WORD	K[];

    if (ac == 2 && strcmp(av[1], "-test") == 0) {
        test_turing(0);
        return nerrors;
    }
    if (ac == 2 && strcmp(av[1], "-time") == 0) {
        time_turing();
        return 0;
    }

    if (ac >= 2 && strcmp(av[1], "-verbose") == 0) {
	vflag = 1;
	++av, --ac;
    }
    if (ac >= 2)
        hexread(key, av[1], keysz = strlen(av[1]) / 2);
    else
        hexread(key, "0000000000000000", keysz = 8);
    if (ac >= 3)
        hexread(IV, av[2], IVsz = strlen(av[2]) / 2);
    else
        IVsz = 0;
    sscanf(ac >= 4 ? av[3] : "1000000", "%d", &n);

    TuringKey(key, keysz);
    TuringIV(IV, IVsz);
    if (vflag) {
	printf("Scheduled key:");
	for (i = 0; i < keylen; ++i)
	    printf(" 0x%08lx", K[i]);
	printf("\n");
	printLFSR("Initial LFSR");
    }
    while (n > 0) {
	i = TuringGen(bigbuf);
	i = n > i ? i : n;
	hexbulk(bigbuf, i);
	n -= i;
    }
    return 0;
}
