/* @(#)TuringRef.c	1.7 (QUALCOMM Turing) 02/11/28 */
/*
 * Reference implementation of Turing
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
 * Push a word through the keyed S-boxes.
 * As the bytes bounce around the permutation table, they are used
 * to build up words from the Qbox entries. Then the byte position
 * corresponding to the input byte is replaced with the result of
 * the S-box, which is a permutation of the input and guarantees
 * a balanced function.
 * Also added a rotation of the input word, to combat a differential
 * trail allowed by the PHT.
 */
static WORD
S(WORD w, int r)
{
    register int	i;
    BYTE		b[4];
    WORD		ws[4];

    w = ROTL(w, r);
    WORD2BYTE(w, b);
    ws[0] = ws[1] = ws[2] = ws[3] = 0;
    for (i = 0; i < keylen; ++i) {
	b[0] = Sbox[B(K[i], 0) ^ b[0]]; ws[0] ^= ROTL(Qbox[b[0]], i + 0);
	b[1] = Sbox[B(K[i], 1) ^ b[1]]; ws[1] ^= ROTL(Qbox[b[1]], i + 8);
	b[2] = Sbox[B(K[i], 2) ^ b[2]]; ws[2] ^= ROTL(Qbox[b[2]], i + 16);
	b[3] = Sbox[B(K[i], 3) ^ b[3]]; ws[3] ^= ROTL(Qbox[b[3]], i + 24);
    }
    w  = (ws[0] & 0x00FFFFFFUL) | (b[0] << 24);
    w ^= (ws[1] & 0xFF00FFFFUL) | (b[1] << 16);
    w ^= (ws[2] & 0xFFFF00FFUL) | (b[2] << 8);
    w ^= (ws[3] & 0xFFFFFF00UL) | b[3];

    return w;
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
 * Reference version; merely gathers words, mixes them, saves them.
 */
void
TuringKey(const BYTE key[], const int keylength)
{
    register int	i;

    if ((keylength & 0x03) != 0 || keylength > MAXKEY)
	abort();
    keylen = 0;
    for (i = 0; i < keylength; i += 4)
	K[keylen++] = fixedS(BYTE2WORD(&key[i]));
    mixwords(K, keylen);
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
