/* @(#)TuringTest.c	1.9 (QUALCOMM Turing) 03/02/24 */
/*
 * Test harness for Turing
 *
 * Copyright C 2002, Qualcomm Inc. Written by Greg Rose
 */

/*
This software is free for commercial and non-commercial use subject to
the following conditions:

1.  Copyright remains vested in QUALCOMM Incorporated, and Copyright
notices in the code are not to be removed.  If this package is used in
a product, QUALCOMM should be given attribution as the author of the
Turing encryption algorithm. This can be in the form of a textual
message at program startup or in documentation (online or textual)
provided with the package.

2.  Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

a. Redistributions of source code must retain the copyright notice,
   this list of conditions and the following disclaimer.

b. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

c. All advertising materials mentioning features or use of this
   software must display the following acknowledgement:  This product
   includes software developed by QUALCOMM Incorporated.

3.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND AGAINST
INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

4.  The license and distribution terms for any publically available version
or derivative of this code cannot be changed, that is, this code cannot
simply be copied and put under another distribution license including
the GNU Public License.

5.  The Turing family of encryption algorithms are covered by patents in
the United States of America and other countries. A free and
irrevocable license is hereby granted for the use of such patents to
the extent required to utilize the Turing family of encryption
algorithms for any purpose, subject to the condition that any
commercial product utilising any of the Turing family of encryption
algorithms should show the words "Encryption by QUALCOMM" either on the
product or in the associated documentation.
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
	"69 66 26 bb dc 6e 09 f6 da 9a ba b5 b5 6c 14 87 82 46 df 18";

#define STREAMTEST 9999
char	*streamout =
	"5d a8 8c ed 8a a6 55 ba 78 08 ef f8 cf 32 63 c0 75 e4 40 3c";

#define ITERATIONS 999999
char    *iterout =
	"62 a4 e8 a7 b0 49 6d 45 9e 00 d5 5e 98 21 41 55 f9 68 81 8c";
char	*ivout = 
	"7e 37 ee 34 9c 06 14 72 20 cb b9 d3 f1 db c5 d0 ac 0f d5 cf";

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

    if ((keysz | IVsz) & 0x3) {
	fprintf(stderr, "Key and IV must be multiple of 4 bytes\n");
	return 1;
    }
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
