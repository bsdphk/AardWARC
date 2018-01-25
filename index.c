/*-
 * Copyright (c) 2016 Poul-Henning Kamp
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * About the index files in general
 * --------------------------------
 *
 * Entries in the index file are 32 bytes, used as follows:
 *
 *	12 bytes	WARC-id prefix
 *	 4 bytes	flags
 *	 4 bytes	silo number
 *	 8 bytes	offset in silo
 *	 4 bytes	Next segment WARC-id prefix
 *
 * With 96 bits of the WARC-id, we have pretty good "birthday paradox"
 * resistance, and can reasonably assume that a match in the index file
 * is genuine:  With 13 billion objects, there is one chance in a billion
 * of a collision.
 *
 * The next segment WARC-id is much smaller, because it just have to steer
 * us in the right range to find the successor, and having to examine a
 * few headers before finding the right, likely multi gigabyte, segment,
 * does not matter.
 *
 * About sorted index files
 * ------------------------
 *
 * Think of SHA256 is binary fractions between zero and one, such that
 * 000000... is zero and fffff... is almost one, we will call such a
 * number a "sha-fraction".
 *
 * Since the output of SHA256 are statistically indistinguishable from
 * random bits the distribution of sha-fractions in a set of SHA256
 * outputs will a nearly perfect uniform distribution.  If you have a
 * million sha-fractions, approximately half of them will be less than
 * 0.5 and approximately a tenth of them will lie between 0.6 and 0.7.
 *
 * Therefore when we sort an indexfile by SHA256, the sha-fractions in
 * it grow almost linearly from zero to one along the file.
 *
 * It is therefore obvious that to find any particular SHA256 in the
 * file, we should look close to its sha_fraction times the filesize.
 *
 * The entry may be ahead or behind that point in the file, and since
 * the [f]read(2) function only reads forwards, it is desirable to find
 * some way to offset the calculation so the result is always before the
 * record we are looking for.
 *
 * The offsets is the result of the accumulated random walk of the
 * residual randomness in the sha_fractions and we know how to bound
 * that function mathematically.  Unfortunately these bounds have to
 * be very conservative to always work, leading to very pessimistic
 * offsets, which cause us to read a lot of records (0.1% of the total)
 * before we find the right one.
 *
 * A better strategy is to build an tiny index which gives us the offset
 * necessary for that area of the index file.
 *
 * Divide the range from zero to one into 512 buckets, in each of these
 * buckets we put the largest offset necessary for all records therein.
 *
 * Now the lookup strategy is:
 *
 *	a = sha_fraction(key)
 *	o = bucket[int(a * 512)]
 *	l = a * total_records(index_file) + o
 *	lseek(index_file, l)
 *
 * In terms of disk-access that means we read the first block where
 * the buckets live, and then immediately go and read one or two
 * sequential blocks where the entry lives.
 *
 * The bucket-index can be built on the fly during the merge phase,
 * provided we estimate 'total_records' up front.
 *
 * There are a couple of important footnotes.
 *
 * The most important footnote is the degenerate case where we merge
 * two identical index files and throw half the records away, our
 * total_records estimate too large by a factor of two.
 *
 * In that case the numbers in the buckets grow with the total number
 * of records and it follows directly that 32 bits per bucket would
 * limit us to 4 billion records which is not OK.
 *
 * The other footnote is that computers are not good at 256 bit
 * arithmetic and it would be surplus to our requirements anyway.
 * However, if we truncate the fraction it too much, the fractional
 * "noise" added causes us to read more records to find our key.
 *
 * Ideally we want to be able to multiply the sha_fraction with the
 * filesize in 64 bits.  Allocating 24 bits for the sha_fraction and
 * 40 bits for the number of records gives us a capacity of a thousand
 * billion records.  That should be enough for everybody.
 *
 * The final detail is how many buckets we want to use.  The more
 * buckets the smaller the residual becomes inside each bucket, but
 * having too many buckets just wastes space.
 *
 * One bucket for every 4k records is a good place to start.
 *
 * We put the total_records estimate in the first bucket, and having
 * already limited it to 40 bits, we can use two bytes for Id ("Aa")
 * and one for the number of buckets and other param/versioning.
 */

#include "vdef.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sys/endian.h>

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

#define SUFF_HOLD	"hold"
#define SUFF_SORTED	"sorted"
#define SUFF_APPENDIX	"appendix"
#define SUFF_HOUSEKEEP	"housekeep"

#define KEYSUMM		12

const char *
IDX_Valid_Id(const struct aardwarc *aa, const char *id, const char **nid)
{
	size_t l;

	AN(aa);
	AN(id);
	if (!strncasecmp(id, aa->prefix, strlen(aa->prefix)))
		id += strlen(aa->prefix);

	l = strlen(id);
	if (l != strcspn(id, ":/"))
		return ("ID is invalid (wrong prefix?)");
	if (l != strspn(id, "0123456789abcdefABCDEF"))
		return ("ID is invalid (non-hex characters)");
	if (strlen(id) < aa->id_size)
		return ("ID is invalid (too short)");
	if (strlen(id) > aa->id_size)
		return ("ID is invalid (too long)");
	if (nid != NULL)
		*nid = id;
	return (NULL);
}

static struct vsb *
idx_filename(const struct aardwarc *aa, const char *suff)
{
	struct vsb *vsb;

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s/index", aa->silo_dirname);
	if (suff != NULL)
		VSB_printf(vsb, ".%s", suff);
	AZ(VSB_finish(vsb));
	return (vsb);
}

static uint8_t
idx_hex_digit(const char key)
{
	if (key >= '0' && key <= '9')
		return (key - '0');
	if (key >= 'a' && key <= 'f')
		return (10 + key - 'a');
	if (key >= 'A' && key <= 'F')
		return (10 + key - 'A');
	WRONG("Non-hexadecimal in record id");
}

static void
idx_key_bin(uint8_t *dst, const char *key, int keylen)
{
	int i;
	uint8_t j;

	for (i = 0; i < keylen; i++, dst++) {
		*dst = 0;
		if (*key != '\0') {
			j = idx_hex_digit(*key++);
			*dst |= (uint8_t)(j << 4);
		}
		if (*key != '\0') {
			j = idx_hex_digit(*key++);
			*dst |= j;
		}
	}
}

void
IDX_Insert(const struct aardwarc *aa, const char *key, uint32_t flags,
uint32_t silo, uint64_t offset, const char *cont)
{
	uint8_t rec[32];
	int fd, i;
	struct vsb *vsb;

	assert(aa->id_size >= 16);

	memset(rec, 0, sizeof rec);
	idx_key_bin(rec, key, KEYSUMM);
	be32enc(rec + 12, flags);
	be32enc(rec + 16, silo);
	be64enc(rec + 20, offset);
	if (cont != NULL)
		idx_key_bin(rec + 28, cont, 4);

	vsb = idx_filename(aa, "appendix");
	fd = open(VSB_data(vsb), O_WRONLY | O_CREAT | O_APPEND, 0644);
	assert(fd >= 0);
	i = write(fd, rec, sizeof rec);
	assert(i == (int)sizeof rec);
	assert(close(fd) == 0);
	VSB_delete(vsb);
}

/**********************************************************************/

#define INDEX_ID	0x4161L

struct bucket {
	unsigned		magic;
#define BUCKET_MAGIC		0x62759ee1
	unsigned		bbucket;
	uint64_t		nrec;
	uint64_t		nbucket;
	int64_t			*buckets;
};

static void
bucket_skip(FILE *f)
{
	char buf[8];
	uint64_t id;
	unsigned bb;

	AN(f);
	AZ(fseeko(f, 0, SEEK_SET));
	assert(1 == fread(buf, sizeof buf, 1, f));
	id = be64dec(buf);
	assert((id >> 48) == INDEX_ID);
	bb = (id >> 40) & 0xff;
	AZ(fseeko(f, 1L << (bb + 3), SEEK_SET));
}

static struct bucket *
bucket_new(off_t nrec_estimate)
{
	struct bucket *bp;

	AZ(nrec_estimate & ~0xffffffffff);

	ALLOC_OBJ(bp, BUCKET_MAGIC);
	AN(bp);

	bp->nrec = nrec_estimate;

	/*
	 * We want a minimum of four buckets in order to align
	 * with the 32 byte record size
	 */
	for (bp->bbucket = 14;
	    (1L << bp->bbucket) < nrec_estimate; bp->bbucket++)
		continue;
	bp->bbucket -= 12;

	bp->nbucket = 1UL << bp->bbucket;

	bp->buckets = calloc(sizeof *bp->buckets, bp->nbucket);
	memset(bp->buckets, 0, sizeof *bp->buckets * bp->nbucket);
	AN(bp->buckets);

	return (bp);
}

static void
bucket_update(const struct bucket *bp, uint64_t n, const void *rec)
{
	uint64_t u;
	uint64_t b;

	CHECK_OBJ_NOTNULL(bp, BUCKET_MAGIC);
	(void)n;
	AN(rec);
	u = be64dec(rec);
	b = u >> (64 - bp->bbucket);
	u >>= 40;
	u *= bp->nrec;
	u >>= 24;
	if (b > 0 && u + bp->buckets[b] > n) {
		bp->buckets[b] = (int64_t)n - (int64_t)u;
	}
}

static void
bucket_write(const struct bucket *bp, FILE *f)
{
	char buf[8];
	unsigned i;
	CHECK_OBJ_NOTNULL(bp, BUCKET_MAGIC);

	bp->buckets[0] =
		((int64_t)INDEX_ID << 48) |
		((int64_t)bp->bbucket << 40) |
		(int64_t)bp->nrec;

	fflush(f);
	AZ(fseeko(f, 0, SEEK_SET));
	for (i = 0; i < bp->nbucket; i++) {
		be64enc(buf, bp->buckets[i]);
		assert(1 == fwrite(buf, 8, 1, f));
	}
	fflush(f);
}

static void
bucket_seek(const void *rec, FILE *f)
{
	char buf[8];
	uint64_t frac;
	long bucket;
	uint64_t id;
	unsigned nbucket;
	unsigned nrec;
	int64_t off;

	AN(rec);
	AN(f);
	AZ(fseeko(f, 0, SEEK_SET));
	assert(1 == fread(buf, sizeof buf, 1, f));
	id = be64dec(buf);
	assert((id >> 48) == INDEX_ID);
	nbucket = (id >> 40) & 0xff;
	nrec = id & 0xffffffffff;

	frac = be64dec(rec);
	bucket = (long)(frac >> (64 - nbucket));
	if (bucket > 0) {
		frac >>= 40;	// top 24 bits
		frac *= nrec;	// full 64 bit fraction
		frac >>= 24;	// predicted record number
		AZ(fseeko(f, bucket * 8, SEEK_SET));
		assert(1 == fread(buf, sizeof buf, 1, f));
		off = (int64_t)be64dec(buf);
		frac += off;
		AZ(fseeko(f, (long)frac * 32, SEEK_SET));
	} else {
		AZ(fseeko(f, 1L << (nbucket + 3), SEEK_SET));
	}
}

/*
 * Since the index is small enough that we have a risk of collisions,
 * the only way to lookup is to iterate all possible matches.
 */

static const struct idxfiles {
	const char	*suff;
	int		sorted;
} idxfiles[] = {
	{ SUFF_SORTED,		1 },
	{ SUFF_APPENDIX,	0 },
	{ SUFF_HOUSEKEEP,	0 },
	{ NULL, 0}
};

int
IDX_Iter(const struct aardwarc *aa, const char *key_part,
    idx_iter_f *func, void *priv)
{
	FILE *f;
	const struct idxfiles *idf;
	uint8_t key_p[KEYSUMM];
	uint8_t rec[32];
	char key[25];
	char cont[9];
	int i, j;
	struct vsb *vsb;
	int cl;

	AN(func);

	if (key_part != NULL) {
		assert(strspn(key_part, "0123456789abcdefABCDEF") ==
		   strlen(key_part));
		idx_key_bin(key_p, key_part, sizeof key_p);
		cl = strlen(key_part);
		if (cl > KEYSUMM * 2)
			cl = KEYSUMM * 2;
	} else {
		memset(key_p, 0, sizeof key_p);
		cl = 0;
	}

	i = -1;
	for (idf = idxfiles; idf->suff != NULL; idf++) {
		vsb = idx_filename(aa, idf->suff);
		f = fopen(VSB_data(vsb), "r");
		if (f == NULL)
			continue;
		VSB_delete(vsb);
		if (idf->sorted)
			bucket_seek(key_p, f);
		do {
			i = fread(rec, 1, sizeof rec, f);
			if (i == 0)
				break;
			assert(i == (int)sizeof rec);
			i = 0;

			if (cl >= 2) {
				j = memcmp(rec, key_p, cl / 2);
				if (idf->sorted && j > 0)
					break;
				if (j)
					continue;
			}

			bprintf(key, "%016jx%08x",
			    be64dec(rec), be32dec(rec + 8));
			if (key_part != NULL && strncasecmp(key, key_part, cl))
				continue;

			bprintf(cont, "%08x", be32dec(rec + 28));

			i = func(priv, key, be32dec(rec + 12),
			    be32dec(rec + 16), be64dec(rec + 20), cont);
		} while (i == 0);
		AZ(fclose(f));
		if (i)
			break;
	}
	return (i);
}

static void
idx_merge(const struct aardwarc *aa, const uint8_t *ptr, ssize_t len)
{
	int i;
	struct vsb *vsb1;
	struct vsb *vsb2;
	char buf[32];
	uint8_t rec[32];
	uint8_t recl[32];
	FILE *f1, *f2;
	size_t sz;
	off_t nrec;
	int64_t n;
	struct bucket *bp;

	assert(len > 0);
	AZ(len & 0x1f);

	vsb1 = idx_filename(aa, SUFF_SORTED);
	f1 = fopen(VSB_data(vsb1), "r");

	bprintf(buf, "tmp.%jd", (intmax_t)getpid());
	vsb2 = idx_filename(aa, buf);
	f2 = fopen(VSB_data(vsb2), "w");
	assert(f2 != NULL);
	memset(recl, 0, sizeof recl);

	nrec = len / 32;
	if (f1 != NULL) {
		(void)fseeko(f1, 0, SEEK_END);
		nrec += ftello(f1) / 32;
		(void)fseeko(f1, 0, SEEK_SET);
	}

	bp = bucket_new(nrec);
	bucket_write(bp, f2);

	n = 0;
	if (f1 != NULL) {
		bucket_skip(f1);
		while (1) {
			sz = fread(rec, 32, 1, f1);
			if (sz == 0)
				break;
			assert(memcmp(rec, recl, 32) >= 0);
			memcpy(recl, rec, 32);
			assert(sz == 1);
			while (len > 0 && memcmp(rec, ptr, 32) > 0) {
				bucket_update(bp, n++, ptr);
				sz = fwrite(ptr, 32, 1, f2);
				assert(sz == 1);
				ptr += 32;
				len -= 32;
			}
			while (len > 0 && memcmp(rec, ptr, 32) == 0) {
				ptr += 32;
				len -= 32;
			}
			bucket_update(bp, n++, rec);
			sz = fwrite(rec, 32, 1, f2);
			assert(sz == 1);
		}
		AZ(fclose(f1));
	}
	while (len > 0)  {
		bucket_update(bp, n++, ptr);
		assert(1 == fwrite(ptr, 32, 1, f2));
		ptr += 32;
		len -= 32;
	}
	bucket_write(bp, f2);
	AZ(fclose(f2));
	i = rename(VSB_data(vsb2), VSB_data(vsb1));
	AZ(i);
	VSB_delete(vsb1);
	VSB_delete(vsb2);
}

static int
idx_cmp(const void *p1, const void *p2)
{
	return (memcmp(p1, p2, 32));
}

static int
idx_attempt_merge(const struct aardwarc *aa, uint8_t *spc,
    const struct vsb *vsba, const struct vsb *vsbh)
{
	int retval = 0;
	int fd;
	ssize_t sz;
	int i;

	i = link(VSB_data(vsba), VSB_data(vsbh));
	if (i == 0) {
		AZ(unlink(VSB_data(vsba)));
	} else if (errno == ENOENT) {
		fprintf(stderr, "No appendix to housekeep\n");
		return (0);
	} else if (errno == EEXIST) {
		fprintf(stderr,
		    "Found existing housekeeping snapshot\n");
		fprintf(stderr,
		    "Merging that first...\n");
		retval = 1;
	} else {
		fprintf(stderr,
		    "Error linking housekeeping snapshot: %s\n",
		    strerror(errno));
		return (-1);
	}

	fd = open(VSB_data(vsbh), O_RDONLY);
	if (fd < 0) {
		fprintf(stderr,
		    "Error opening housekeeping snapshot: %s\n",
		    strerror(errno));
		free(spc);
		return (-1);
	}

	do {
		sz = read(fd, spc, aa->index_sort_size);
		if (sz < 0) {
			fprintf(stderr,
			    "Read error on housekeeping snapshot: %s",
			    strerror(errno));
			AZ(close(fd));
			return (-1);
		}
		if (sz == 0)
			break;
		AZ(sz & 0x1f);
		qsort(spc, ((size_t)sz) >> 5, 32, idx_cmp);
		idx_merge(aa, spc, sz);
	} while (sz == (ssize_t)aa->index_sort_size);
	AZ(close(fd));
	AZ(unlink(VSB_data(vsbh)));
	return (retval);
}

void
IDX_Resort(const struct aardwarc *aa)
{

	struct vsb *vsba, *vsbh, *vsb4;
	uint8_t	*spc;
	int fdh;

	vsb4 = idx_filename(aa, SUFF_HOLD);

	fdh = open(VSB_data(vsb4), O_RDWR | O_CREAT | O_EXCL, 0640);
	if (fdh < 0 && errno == EEXIST) {
		fprintf(stderr,
		    "Housekeeping 'hold' already file exists (%s)\n",
		    VSB_data(vsb4));
		VSB_delete(vsb4);
		return;
	}

	spc = malloc(aa->index_sort_size);
	if (spc == NULL) {
		fprintf(stderr,
		    "Could not allocate index.sort_size %ju bytes\n",
		    (uintmax_t)aa->index_sort_size);
	} else {
		vsba = idx_filename(aa, SUFF_APPENDIX);
		vsbh = idx_filename(aa, SUFF_HOUSEKEEP);

		while(idx_attempt_merge(aa, spc, vsba, vsbh) > 0)
			continue;

		VSB_delete(vsba);
		VSB_delete(vsbh);
		free(spc);
	}
	AZ(unlink(VSB_data(vsb4)));
	AZ(close(fdh));
}
