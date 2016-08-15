#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"
#include "sha3/sph_gost.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_shabal.h"

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
void sibhash(void *output, const void *input)
{
	sph_skein512_context	ctx_skein;
	sph_gost512_context 	ctx_gost;
	sph_shabal512_context ctx_shabal;
	sph_shavite512_context     ctx_shavite;

	//these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(64) hashA[16], hashB[16];

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, hashA);

        sph_shavite512_init(&ctx_shavite);
        sph_shavite512(&ctx_shavite, hashA, 64);
        sph_shavite512_close(&ctx_shavite, hashB);

        sph_shabal512_init(&ctx_shabal);
        sph_shabal512(&ctx_shabal, hashB, 64);
        sph_shabal512_close(&ctx_shabal, hashA);

	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx_gost, hashA, 64);
	sph_gost512_close(&ctx_gost, hashB);

	memcpy(output, hashB, 32);
}

int scanhash_sib(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	// we need bigendian data...
	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}
	do {
		be32enc(&endiandata[19], nonce);
		sibhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
