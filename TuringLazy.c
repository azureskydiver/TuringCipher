/* @(#)TuringLazy.c	1.2 (QUALCOMM Turing) 02/11/28 */
/*
 * Table-lookup/Lazy evaluation implementation of Turing
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

#include <stdlib.h>
#include "Turing.h"		/* interface definitions */
#include "TuringSbox.h"
#include "QUTsbox.h"
#include "TuringMultab.h"

int	keylen;		/* adjusted to count WORDs */
WORD	K[MAXKEY/4];	/* storage for mixed key */
WORD	R[LFSRLEN];	/* the shift register */
/* precalculated S-boxes */
WORD	S0[256], S1[256], S2[256], S3[256];
int	bingo;		/* an Sbox has a real 0 value! */	

/* step the LFSR */
void
step(void)
{
    register int	i;
    register WORD	w;

    w = R[15] ^ R[4] ^ (R[0] << 8) ^ Multab[(R[0] >> 24) & 0xFF];
    for (i = 1; i < LFSRLEN; ++i)
	R[i-1] = R[i];
    R[LFSRLEN-1] = w;
}

/*
 * This does a reversible transformation of a word, based on the S-boxes.
 * The reversibility isn't used, but it guarantees no loss of information,
 * and hence no equivalent keys or IVs.
 */
static WORD
fixedS(WORD w)
{
    WORD    b;

    b = Sbox[B(w, 0)]; w = ((w ^      Qbox[b])     & 0x00FFFFFF) | (b << 24);
    b = Sbox[B(w, 1)]; w = ((w ^ ROTL(Qbox[b],8))  & 0xFF00FFFF) | (b << 16);
    b = Sbox[B(w, 2)]; w = ((w ^ ROTL(Qbox[b],16)) & 0xFFFF00FF) | (b << 8);
    b = Sbox[B(w, 3)]; w = ((w ^ ROTL(Qbox[b],24)) & 0xFFFFFF00) | b;
    return w;
}

/*
 * Calculate a single S-box entry if required
 */
#define BINGO 0
static WORD
lazyS(BYTE b, int pos)
{
    static WORD *tab[4] = {S0, S1, S2, S3};
    int		i;
    WORD	w;
    BYTE	k;

    w = 0;
    k = b;
    for (i = 0; i < keylen; ++i) {
	k = Sbox[B(K[i], pos) ^ k];
	w ^= ROTL(Qbox[k], i + 8*pos);
    }
    w = (w & ~(0xFFUL << (24 - 8*pos))) | (k << (24 - 8*pos));
    tab[pos][b] = w;
#if BINGO
    if (w == 0) {
	printf("Bingo! S%d[0x%02x] == 0\n", pos, b);
    }
#endif
    return w;
}

#define LS0(x) (S0[x] != 0 ? S0[x] : lazyS((x), 0))
#define LS1(x) (S1[x] != 0 ? S1[x] : lazyS((x), 1))
#define LS2(x) (S2[x] != 0 ? S2[x] : lazyS((x), 2))
#define LS3(x) (S3[x] != 0 ? S3[x] : lazyS((x), 3))
/*
 * Push a word through the keyed S-boxes.
 * As the bytes bounce around the permutation table, they are used
 * to build up a word from the Qbox entries.
 */
static WORD
S(WORD w, int r)
{
    w = ROTL(w, r);
    return LS0(B(w, 0)) ^ LS1(B(w, 1)) ^ LS2(B(w, 2)) ^ LS3(B(w, 3));
}

/* two variants of the Pseudo-Hadamard Transform */

/* Mix 5 words in place */
#define PHT(A,B,C,D,E) { \
	(E) += (A) + (B) + (C) + (D); \
	(A) += (E); \
	(B) += (E); \
	(C) += (E); \
	(D) += (E); \
}

/* General word-wide n-PHT */
void
mixwords(WORD w[], int n)
{
    register WORD	sum;
    register int	i;

    for (sum = i = 0; i < n-1; ++i)
	sum += w[i];
    w[n-1] += sum;
    sum = w[n-1];
    for (i = 0; i < n-1; ++i)
	w[i] += sum;
}

/*
 * Key the cipher.
 * Table version; gathers words, mixes them, saves them.
 * Then compiles lookup tables for the keyed S-boxes.
 */
void
TuringKey(const BYTE key[], const int keylength)
{
    register int	i, j;

    if ((keylength & 0x03) != 0 || keylength > MAXKEY)
	abort();
    keylen = 0;
    for (i = 0; i < keylength; i += 4)
	K[keylen++] = fixedS(BYTE2WORD(&key[i]));
    mixwords(K, keylen);
    /* initialise S-box lookup tables to zero, let lazyS fill them in */
    for (j = 0; j < 256; ++j)
	S0[j] = S1[j] = S2[j] = S3[j] = 0;
}

/*
 * Load the Initialization Vector.
 * Actually, this fills the LFSR, with IV, key, length, and more.
 * IV goes through the fixed S-box, key is premixed, the rest go through
 * the keyed S-boxes. The reason for this is to avoid nasty interactions
 * between the mixed key and the S-boxes that depend on them, and also
 * to avoid any "chosen-IV" interactions with the keyed S-boxes, not that I
 * can think of any.
 */
void
TuringIV(const BYTE iv[], const int ivlength)
{
    register int	i, j;

    /* check args */
    if ((ivlength & 0x03) != 0 || (ivlength + 4*keylen) > MAXKIV)
	abort();
    /* first copy in the IV, mixing as we go */
    for (i = j = 0; j < ivlength; j +=4)
	R[i++] = fixedS(BYTE2WORD(&iv[j]));
    /* now continue with the premixed key */
    for (j = 0 /* i continues */; j < keylen; ++j)
	R[i++] = K[j];
    /* now the length-dependent word */
    R[i++] = (keylen << 4) | (ivlength >> 2) | 0x01020300UL;
    /* ... and fill the rest of the register */
    for (j = 0 /* i continues */; i < LFSRLEN; ++i, ++j)
	R[i] = S(R[j] + R[i-1], 0);
    /* finally mix all the words */
    mixwords(R, LFSRLEN);
}

/*
 * Generate a 5-word block of output.
 * Buffering issues are outside the scope of this implementation.
 * Returns the number of bytes of stream generated.
 */
int
TuringGen(BYTE *buf)
{
    register WORD	A, B, C, D, E;

    step();
    A = R[16];	B = R[13];	C = R[6];	D = R[1];	E = R[0];
    PHT(A,	B,		C,		D,		E);
    A = S(A,0);	B = S(B,8);	C = S(C,16);	D = S(D,24);	E = S(E,0);
    PHT(A,	B,		C,		D,		E);
    step();
    A += R[16];	B += R[13];	C += R[6];	D += R[1];	E += R[0];
    WORD2BYTE(A, buf);
		WORD2BYTE(B, buf+4);
				WORD2BYTE(C, buf+8);
						WORD2BYTE(D, buf+12);
							WORD2BYTE(E, buf+16);
    return 20;
}
