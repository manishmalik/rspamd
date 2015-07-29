/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "config.h"
#include "main.h"
#include "shingles.h"
#include "fstring.h"
#include "ottery.h"
#include "cryptobox.h"

static const int mapping_size = 64 * 8192 + 1;
static const int max_seg = 32;
static const int random_fuzz_cnt = 10000;

static void *
create_mapping (int mapping_len, guchar **beg, guchar **end)
{
	void *map;
	int psize = getpagesize ();

	map = mmap (NULL, mapping_len + psize * 3, PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_SHARED, -1, 0);
	g_assert (map != 0);
	memset (map, 0, mapping_len + psize * 3);
	mprotect (map, psize, PROT_NONE);
	/* Misalign pointer */
	*beg = ((guchar *)map) + psize + 1;
	*end = *beg + mapping_len;
	mprotect (*beg + mapping_len - 1 + psize, psize, PROT_NONE);

	return map;
}

static void
check_result (const rspamd_nm_t key, const rspamd_nonce_t nonce,
		const rspamd_sig_t mac, guchar *begin, guchar *end)
{
	guint64 *t = (guint64 *)begin;

	g_assert (rspamd_cryptobox_decrypt_nm_inplace (begin, end - begin, nonce, key,
			mac));

	while (t < (guint64 *)end) {
		g_assert (*t == 0);
		t ++;
	}
}

static int
create_random_split (struct rspamd_cryptobox_segment *seg, int mseg,
		guchar *begin, guchar *end)
{
	gsize remain = end - begin;
	gint used = 0;

	while (remain > 0 && used < mseg - 1) {
		seg->data = begin;
		seg->len = ottery_rand_range (remain - 1) + 1;

		begin += seg->len;
		remain -= seg->len;
		used ++;
		seg ++;
	}

	if (remain > 0) {
		seg->data = begin;
		seg->len = remain;
		used ++;
	}

	return used;
}

static int
create_realistic_split (struct rspamd_cryptobox_segment *seg, int mseg,
		guchar *begin, guchar *end)
{
	gsize remain = end - begin;
	gint used = 0;
	static const int small_seg = 512, medium_seg = 2048;

	while (remain > 0 && used < mseg - 1) {
		seg->data = begin;

		if (ottery_rand_uint32 () % 2 == 0) {
			seg->len = ottery_rand_range (small_seg) + 1;
		}
		else {
			seg->len = ottery_rand_range (medium_seg) +
					small_seg;
		}
		if (seg->len > remain) {
			seg->len = remain;
		}

		begin += seg->len;
		remain -= seg->len;
		used ++;
		seg ++;
	}

	if (remain > 0) {
		seg->data = begin;
		seg->len = remain;
		used ++;
	}

	return used;
}

static int
create_constrainted_split (struct rspamd_cryptobox_segment *seg, int mseg,
		int constraint,
		guchar *begin, guchar *end)
{
	gsize remain = end - begin;
	gint used = 0;

	while (remain > 0 && used < mseg - 1) {
		seg->data = begin;
		seg->len = constraint;
		if (seg->len > remain) {
			seg->len = remain;
		}
		begin += seg->len;
		remain -= seg->len;
		used ++;
		seg ++;
	}

	if (remain > 0) {
		seg->data = begin;
		seg->len = remain;
		used ++;
	}

	return used;
}
void test_predifined_case(void)
{
	guchar nonce[] = {227,151,41,137,191,238,172,191,15,194,173,236,31,251,122,91,69,177,81,65,178,202,244,184};
	guchar ctx1[] = {71,44,215,255,50,46,219,43,139,247,159,106,250,94,213,71};
	guchar mac[] = {59,255,197,155,66,151,167,219,3,134,67,197,191,78,111,232};
	guchar pk12[] = {231,181,65,201,223,177,84,124,46,188,67,15,210,142,112,21,197,86,73,118,225,254,88,148,244,101,68,230,184,158,87,4};
	guchar sk12[] = {104,17,235,221,214,25,30,219,122,129,252,117,191,31,70,55,202,222,235,189,82,37,209,177,173,66,22,58,132,113,97,115};
	guchar pk21[] = {93,85,4,76,136,253,180,212,246,186,173,91,7,136,111,161,134,247,14,107,167,45,250,5,214,247,193,69,18,129,255,71};
	guchar sk21[] = {6, 233, 12, 252, 46, 153, 223, 121, 177, 65, 100, 99, 165, 136, 0, 8, 160, 83, 81, 19, 49, 154, 40, 131, 227, 41, 214, 214, 127, 13, 80, 81};
	guchar pt[] = {77, 97, 110, 105, 115, 104, 32, 77, 97, 108, 105, 107, 33, 32, 59, 41};
	guchar nm[rspamd_cryptobox_NMBYTES];
	guchar s[rspamd_cryptobox_PKBYTES];
	guchar sig[rspamd_cryptobox_MACBYTES];
	guchar subkey[64];
	gint i;

	//rspamd_cryptobox_encrypt_inplace(pt,strlen(pt),nonce,pk12,sk21,sig);
	msg_info("CTX: ");
	for(i=0;i<sizeof(ctx1);i++)
		msg_info("%d",ctx1[i]);
	msg_info("MAC: ");
	for(i=0;i<rspamd_cryptobox_MACBYTES;i++)
		msg_info("%d",mac[i]);
	/*subkey = rspamd_temporary(pt,sizeof(pt),nonce,pk12,sk21);
	msg_info("Subkey :");
	for (i = 0; i < 64; i++)
	{
		msg_info("%d",subkey[i]);
	}*/
	rspamd_cryptobox_nm (nm, pk21, sk12);
	/*curve25519 (s, sk12, pk21);
	msg_info("curve25519 : ");
	for(i=0;i<rspamd_cryptobox_PKBYTES;i++)
		msg_info("%d",s[i]);*/

	msg_info("Nm : ");
	for(i=0;i<rspamd_cryptobox_NMBYTES;i++)
		msg_info("%d",nm[i]);

	if(rspamd_cryptobox_decrypt_inplace(ctx1,sizeof(ctx1),nonce,pk21,sk12,mac)==true)
		msg_info("Passed");
	else
		msg_info("Failed");
}
void
rspamd_cryptobox_test_func (void)
{
	void *map;
	guchar *begin, *end;
	rspamd_nm_t key;
	rspamd_nonce_t nonce;
	rspamd_sig_t mac;
	struct rspamd_cryptobox_segment *seg;
	double t1, t2;
	gint i, cnt, ms;

	map = create_mapping (mapping_size, &begin, &end);

	ottery_rand_bytes (key, sizeof (key));
	ottery_rand_bytes (nonce, sizeof (nonce));

	memset (mac, 0, sizeof (mac));
	seg = g_slice_alloc0 (sizeof (*seg) * max_seg * 10);

	/* Test baseline */
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encrypt_nm_inplace (begin, end - begin, nonce, key, mac);
	t2 = rspamd_get_ticks ();
	check_result (key, nonce, mac, begin, end);

	test_predifined_case();
	return 0;
	msg_info ("baseline encryption: %.6f", t2 - t1);
	/* A single chunk as vector */
	seg[0].data = begin;
	seg[0].len = end - begin;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 1, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("bulk encryption: %.6f", t2 - t1);

	/* Two chunks as vector */
	seg[0].data = begin;
	seg[0].len = (end - begin) / 2;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("2 equal chunks encryption: %.6f", t2 - t1);

	seg[0].data = begin;
	seg[0].len = 1;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("small and large chunks encryption: %.6f", t2 - t1);

	seg[0].data = begin;
	seg[0].len = (end - begin) - 3;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("large and small chunks encryption: %.6f", t2 - t1);

	/* Random two chunks as vector */
	seg[0].data = begin;
	seg[0].len = ottery_rand_range (end - begin - 1) + 1;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("random 2 chunks encryption: %.6f", t2 - t1);

	/* 3 specific chunks */
	seg[0].data = begin;
	seg[0].len = 2;
	seg[1].data = begin + seg[0].len;
	seg[1].len = 2049;
	seg[2].data = begin + seg[0].len + seg[1].len;
	seg[2].len = (end - begin) - seg[0].len - seg[1].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 3, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("small, medium and large chunks encryption: %.6f", t2 - t1);

	cnt = create_random_split (seg, max_seg, begin, end);
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("random split of %d chunks encryption: %.6f", cnt, t2 - t1);

	cnt = create_realistic_split (seg, max_seg, begin, end);
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("realistic split of %d chunks encryption: %.6f", cnt, t2 - t1);

	cnt = create_constrainted_split (seg, max_seg + 1, 32, begin, end);
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("constrainted split of %d chunks encryption: %.6f", cnt, t2 - t1);

	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 2) + 1;
		cnt = create_random_split (seg, ms, begin, end);
		t1 = rspamd_get_ticks ();
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
		t2 = rspamd_get_ticks ();

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("random fuzz iterations: %d", i);
		}
	}
	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 2) + 1;
		cnt = create_realistic_split (seg, ms, begin, end);
		t1 = rspamd_get_ticks ();
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
		t2 = rspamd_get_ticks ();

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("realistic fuzz iterations: %d", i);
		}
	}
	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 10) + 1;
		cnt = create_constrainted_split (seg, ms, i, begin, end);
		t1 = rspamd_get_ticks ();
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
		t2 = rspamd_get_ticks ();

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("constrainted fuzz iterations: %d", i);
		}
	}
}
