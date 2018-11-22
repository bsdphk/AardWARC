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
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vdef.h"

#include "vas.h"
#include "miniobj.h"

#include "aardwarc.h"

struct cand {
	unsigned		magic;
#define CAND_MAGIC		0x882a5fd4
	int			found;
	char			*id;
	char			*line;
	VTAILQ_ENTRY(cand)	list;
	VTAILQ_ENTRY(cand)	sortlist;
};

VTAILQ_HEAD(candhead,cand);

static struct candhead		candidates =
    VTAILQ_HEAD_INITIALIZER(candidates);
static struct candhead		sorted =
    VTAILQ_HEAD_INITIALIZER(sorted);
static int			ncand;
static struct cand		*next_cand;

static int			s_flag;

struct filt {
	unsigned		magic;
#define FILT_MAGIC		0xc4b794e6
	struct aardwarc		*aa;
	char			last[65];
};

static
void
usage_filter(const char *a0, const char *a00, const char *err)
{
	usage(a0, err);
	fprintf(stderr, "Usage for this operation:\n");
	fprintf(stderr,
	    "\t%s [global options] %s [options] [id-list-file]...\n",
	    a0, a00);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-s Check the silo headers\n");
	fprintf(stderr, "\t-r Report found (rather than missing) objects\n");
	fprintf(stderr, "\t-v Report precense status on each line of output\n");
}

static int
filter_s_check(const struct filt *fp, uint32_t silo, uint64_t offset,
    const char *key)
{
	struct rsilo *rs;
	struct header *hdr;
	const char *p;
	int retval = 0;

	rs = Rsilo_Open(fp->aa, NULL, silo);
	AN(rs);
	Rsilo_Seek(rs, offset);
	hdr = Rsilo_ReadHeader(rs);
	AN(hdr);
	p = Header_Get_Id(hdr);
	AN(p);
	if (strcasecmp(p, key))
		retval = 1;
	Header_Destroy(&hdr);
	Rsilo_Close(&rs);
	return (retval);
}

static int v_matchproto_(idx_iter_f)
filter_iter(void *priv, const char *key,
    uint32_t flag, uint32_t silo, uint64_t offset, const char *cont)
{
	struct cand *c;
	struct filt *fp;

	CAST_OBJ_NOTNULL(fp, priv, FILT_MAGIC);
	(void)flag;
	(void)cont;

	if (VTAILQ_EMPTY(&sorted))
		return (1);
	if (next_cand == NULL || strcmp(key, fp->last) < 0)
		next_cand = VTAILQ_FIRST(&sorted);
	strlcpy(fp->last, key, sizeof fp->last);
	while (next_cand != NULL && strcmp(next_cand->id, key) < 0)
		next_cand = VTAILQ_NEXT(next_cand, sortlist);
	while (next_cand != NULL &&
	    !strncmp(key, next_cand->id, strlen(key))) {
		c = next_cand;
		next_cand = VTAILQ_NEXT(c, sortlist);
		if (!s_flag || !filter_s_check(fp, silo, offset, c->id)) {
			c->found = 1;
			VTAILQ_REMOVE(&sorted, c, sortlist);
		}
	}
	return(0);
}

static int
read_file(const struct aardwarc *aa, FILE *fi)
{
	char buf[1024], *p;
	struct cand *c1, *c2;
	int retval = 0;
	size_t sl;

	while (fgets(buf, sizeof buf, fi) != NULL) {
		sl = strlen(buf);
		AN(sl);
		if (buf[sl - 1] != '\n') {
			fprintf(stderr, "Over long line \"%.40s...\"\n",
			    buf);
			exit(1);
		}
		buf[--sl] = '\0';
		if (sl == 0)
			continue;
		ALLOC_OBJ(c1, CAND_MAGIC);
		AN(c1);
		REPLACE(c1->line, buf);
		AN(c1->line);
		p = buf;
		if (!strncasecmp(p, aa->prefix, strlen(aa->prefix)))
			p += strlen(aa->prefix);
		if (strlen(p) < aa->id_size) {
			fprintf(stderr, "ID too short: \"%s\"\n", buf);
			exit(1);
		}
		p[aa->id_size] = '\0';
		if (strspn(p, "0123456789abcdefABCDEF") != strlen(p)) {
			fprintf(stderr, "Non-hex characters in id: \"%s\"\n",
			    buf);
			exit(1);
		}
		REPLACE(c1->id, p);
		AN(c1->id);
		c2 = VTAILQ_LAST(&candidates, candhead);
		ncand++;
		VTAILQ_INSERT_TAIL(&candidates, c1, list);
		VTAILQ_INSERT_TAIL(&sorted, c1, sortlist);
		if (c2 != NULL && strcmp(c2->id, c1->id) > 0)
			retval = 1;
	}
	return (retval);
}

static int
cand_cmp(const void *p1, const void *p2)
{
	const struct cand *c1, *c2;

	CAST_OBJ_NOTNULL(c1, *(const struct cand * const*)p1, CAND_MAGIC);
	CAST_OBJ_NOTNULL(c2, *(const struct cand * const*)p2, CAND_MAGIC);
	return (strcmp(c1->id, c2->id));
}

int v_matchproto_(main_f)
main_filter(const char *a0, struct aardwarc *aa, int argc, char **argv)
{
	int ch;
	const char *a00 = *argv;
	FILE *fi, *fo = stdout;
	const char *ofile = NULL;
	int stdin_done = 0;
	int needs_sort = 0;
	int r_flag = 0;
	int v_flag = 0;
	struct cand *c;
	struct cand **cp;
	struct filt *fp;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	ALLOC_OBJ(fp, FILT_MAGIC);
	AN(fp);
	fp->aa = aa;

	while ((ch = getopt(argc, argv, "ho:rsv")) != -1) {
		switch (ch) {
		case 'h':
			usage_filter(a0, a00, NULL);
			exit(1);
		case 'o':
			ofile = optarg;
			break;
		case 'r':
			r_flag = 1 - r_flag;
			break;
		case 's':
			s_flag = 1 - s_flag;
			break;
		case 'v':
			v_flag = 1 - v_flag;
			break;
		default:
			usage_filter(a0, a00, "Unknown option error.");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		needs_sort |= read_file(aa, stdin);

	if (ofile != NULL) {
		fo = fopen(ofile, "w");
		if (fo == NULL) {
			fprintf(stderr, "Cannot open %s: %s\n",
			    ofile, strerror(errno));
			exit (1);
		}
	}

	for (;argc > 0; argc--, argv++) {
		if (!strcmp(*argv, "-")) {
			if (stdin_done++) {
				fprintf(stderr, "STDIN already processed\n");
				exit(1);
			}
			needs_sort |= read_file(aa, stdin);
		} else {
			fi = fopen(*argv, "r");
			if (fi == NULL) {
				fprintf(stderr, "Cannot open %s: %s\n",
				    *argv, strerror(errno));
				exit(1);
			}
			needs_sort |= read_file(aa, fi);
			AZ(fclose(fi));
		}
	}
	if (needs_sort) {
		cp = calloc(ncand, sizeof *cp);
		AN(cp);
		ch = 0;
		VTAILQ_FOREACH(c, &candidates, list)
			cp[ch++] = c;
		assert(ch == ncand);
		qsort(cp, ncand, sizeof *cp, cand_cmp);
		VTAILQ_INIT(&sorted);
		for(ch = 0; ch < ncand; ch++)
			VTAILQ_INSERT_TAIL(&sorted, cp[ch], sortlist);
		free(cp);
	}
	(void)IDX_Iter(aa, NULL, filter_iter, fp);
	while (1) {
		c = VTAILQ_FIRST(&candidates);
		if (c == NULL)
			break;
		VTAILQ_REMOVE(&candidates, c, list);
		if (v_flag)
			fprintf(fo, "%d %s\n", c->found, c->line);
		else if (r_flag == c->found)
			fprintf(fo, "%s\n", c->line);
		REPLACE(c->id, NULL);
		FREE_OBJ(c);
	}
	FREE_OBJ(fp);
	return (0);
}
