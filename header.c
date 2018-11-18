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

#include "vdef.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "miniobj.h"
#include "vas.h"
#include "vsb.h"

#include "aardwarc.h"

struct hfield {
	unsigned		magic;
#define HFIELD_MAGIC		0x10b9767d
	char			*name;
	char			*val;
	VTAILQ_ENTRY(hfield)	list;
};

struct header {
	unsigned		magic;
#define HEADER_MAGIC		0x5bf750ab
	const struct aardwarc	*aa;
	VTAILQ_HEAD(, hfield)	hfields;
	char			*warc_record_id;
};

struct header *
Header_New(const struct aardwarc *aa)
{
	struct header *hdr;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	ALLOC_OBJ(hdr, HEADER_MAGIC);
	AN(hdr);
	VTAILQ_INIT(&hdr->hfields);
	hdr->aa = aa;
	hdr->warc_record_id = calloc(1, hdr->aa->id_size + 1L);
	AN(hdr->warc_record_id);
	memset(hdr->warc_record_id, '_', hdr->aa->id_size);
	hdr->warc_record_id[hdr->aa->id_size] = '\0';
	return (hdr);
}

void
Header_Delete(struct header **hdp)
{
	struct header *hdr;
	struct hfield *hf;

	AN(hdp);
	hdr = *hdp;
	*hdp = NULL;
	CHECK_OBJ_NOTNULL(hdr, HEADER_MAGIC);

	REPLACE(hdr->warc_record_id, NULL);
	while (1) {
		hf = VTAILQ_FIRST(&hdr->hfields);
		if (hf == NULL)
			break;
		REPLACE(hf->name, NULL);
		REPLACE(hf->val, NULL);
		VTAILQ_REMOVE(&hdr->hfields, hf, list);
		FREE_OBJ(hf);
	}
	FREE_OBJ(hdr);
}

struct header *
Header_Clone(const struct header *hd)
{
	struct header *hdn;
	struct hfield *hf, *hfn;

	hdn = Header_New(hd->aa);
	AN(hdn);
	if (hd->warc_record_id != NULL) {
		hdn->warc_record_id = strdup(hd->warc_record_id);
		AN(hdn->warc_record_id);
	}
	VTAILQ_FOREACH(hf, &hd->hfields, list) {
		ALLOC_OBJ(hfn, HFIELD_MAGIC);
		AN(hfn);
		hfn->name = strdup(hf->name);
		AN(hfn->name);
		hfn->val = strdup(hf->val);
		AN(hfn->val);
		VTAILQ_INSERT_TAIL(&hdn->hfields, hfn, list);
	}
	return (hdn);
}

void
Header_Set(struct header *hd, const char *name, const char *val, ...)
{
	struct hfield *hf, *hf2;
	int i;
	va_list ap;

	CHECK_OBJ_NOTNULL(hd, HEADER_MAGIC);
	AN(name);
	assert(strchr(name, ':') == NULL);
	AN(strcasecmp(name, "WARC-Record-ID"));
	AN(val);

	VTAILQ_FOREACH(hf, &hd->hfields, list)
		if (!strcasecmp(name, hf->name))
			break;
	if (hf == NULL) {
		ALLOC_OBJ(hf, HFIELD_MAGIC);
		AN(hf);
		hf->name = strdup(name);
		AN(hf->name);
	} else {
		VTAILQ_REMOVE(&hd->hfields, hf, list);
		REPLACE(hf->val, NULL);
	}
	va_start(ap, val);
	(void)vasprintf(&hf->val, val, ap);
	va_end(ap);
	AN(hf->val);
	VTAILQ_FOREACH(hf2, &hd->hfields, list) {
		CHECK_OBJ_NOTNULL(hf2, HFIELD_MAGIC);
		i = strcasecmp(name, hf2->name);
		if (i < 0) {
			VTAILQ_INSERT_BEFORE(hf2, hf, list);
			return;
		}
		if (i == 0)
			WRONG("Multiple headers with same name");
	}
	VTAILQ_INSERT_TAIL(&hd->hfields, hf, list);
}

const char *
Header_Get(const struct header *hd, const char *name)
{
	struct hfield *hf;

	CHECK_OBJ_NOTNULL(hd, HEADER_MAGIC);
	AN(name);
	VTAILQ_FOREACH(hf, &hd->hfields, list)
		if (!strcasecmp(name, hf->name))
			return (hf->val);
	return (NULL);
}

intmax_t
Header_Get_Number(const struct header *hd, const char *name)
{
	intmax_t r = 0;
	const char *p;

	CHECK_OBJ_NOTNULL(hd, HEADER_MAGIC);
	AN(name);
	p = Header_Get(hd, name);
	if (p == NULL)
		return (-1);
	for (; *p != '\0'; p++) {
		if (*p < '0' || *p > '9')
			return (-1);
		r *= 10;
		r += *p - '0';
	}
	return (r);
}

struct vsb *
Header_Serialize(const struct header *hdr, int level)
{
	struct vsb *vsb;
	struct hfield *hf;

	CHECK_OBJ_NOTNULL(hdr, HEADER_MAGIC);
	AN(hdr->warc_record_id);

	vsb = VSB_new_auto();
	AN(vsb);

	VSB_cat(vsb, "WARC/1.1\r\n");

	VSB_cat(vsb, "WARC-Record-ID: <");
	VSB_cat(vsb, hdr->aa->prefix);
	VSB_cat(vsb, hdr->warc_record_id);
	VSB_cat(vsb, ">\r\n");

	VTAILQ_FOREACH(hf, &hdr->hfields, list) {
		CHECK_OBJ_NOTNULL(hf, HFIELD_MAGIC);
		AN(hf->name);
		AN(hf->val);
		VSB_cat(vsb, hf->name);
		VSB_cat(vsb, ": ");
		VSB_cat(vsb, hf->val);
		VSB_cat(vsb, "\r\n");
	}
	VSB_cat(vsb, "\r\n");

	if (level == -1)
		return (vsb);		// NB: No VSB_finish() call

	AZ(VSB_finish(vsb));
	Gzip_Vsb(&vsb, level);
	return (vsb);
}

const char *
Header_Get_Id(const struct header *hdr)
{

	CHECK_OBJ_NOTNULL(hdr, HEADER_MAGIC);

	AN(hdr->warc_record_id);
	return (hdr->warc_record_id);
}

void
Header_Set_Id(struct header *hdr, const char *id)
{
	size_t i;

	CHECK_OBJ_NOTNULL(hdr, HEADER_MAGIC);
	for (i = 0; id[i] != '\0'; i++)
		assert(isgraph(id[i]));
	REPLACE(hdr->warc_record_id, id);
	assert(i >= hdr->aa->id_size);
	hdr->warc_record_id[hdr->aa->id_size] = '\0';
}

void
Header_Set_Date(struct header *hdr)
{
	struct tm tm;
	time_t t;
	char buf[100];

	CHECK_OBJ_NOTNULL(hdr, HEADER_MAGIC);

	(void)time(&t);

	AN(gmtime_r(&t, &tm));
	assert(strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm) == 20);
	Header_Set(hdr, "WARC-Date", "%s", buf);
}

void
Header_Set_Ref(struct header *hdr, const char *name, const char *ref)
{

	CHECK_OBJ_NOTNULL(hdr, HEADER_MAGIC);
	AN(name);
	AN(ref);
	assert(strlen(ref) >= hdr->aa->id_size);

	Header_Set(hdr, name, "<%s%.*s>",
	    hdr->aa->prefix, hdr->aa->id_size, ref);
}

/* Parse one of our own WARC headers ----------------------------------
 *
 * NB: This is *not* a general purpose WARC header parser.
 */

// Flexelint bug:
//lint -efunc(818, Header_Parse)

struct header *
Header_Parse(const struct aardwarc *aa, char *p)
{
	const char *q0 = "WARC/1.1\r\nWARC-Record-ID: <";
	char *q, *r, *s;
	struct header *hdr;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(p);

	ALLOC_OBJ(hdr, HEADER_MAGIC);
	AN(hdr);
	VTAILQ_INIT(&hdr->hfields);
	hdr->aa = aa;

	AZ(memcmp(p, q0, strlen(q0)));
	p = strchr(p, '\n');
	AN(p);
	for (p++; *p != '\0'; p = q) {
		q = strchr(p, '\r');
		AN(q);
		*q++ = '\0';
		assert(*q == '\n');
		*q++ = '\0';
		if (*p == '\0') {
			assert(*q == '\0');
			break;
		}
		r = strchr(p, ':');
		AN(r);
		*r++ = '\0';
		assert(*r == ' ');
		*r++ = '\0';
		if (strcmp(p, "WARC-Record-ID")) {
			Header_Set(hdr, p, "%s", r);
			continue;
		}
		assert(*r == '<');
		r++;
		s = strchr(r, '>');
		AN(s);
		AZ(s[1]);
		s[0] = '\0';
		s = strrchr(r, '/');
		AN(s);
		REPLACE(hdr->warc_record_id, s + 1);
		s[1] = '\0';
		assert(!strcmp(r, aa->prefix));
	}
	return (hdr);
}
