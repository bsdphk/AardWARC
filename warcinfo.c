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

#include <stdlib.h>
#include <string.h>
#include <sha256.h>

#include "vdef.h"

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

struct warcinfo {
	unsigned		magic;
#define WARCINFO_MAGIC		0x9bef8242

	int			sw_flag;
	struct header		*hdr;
	struct vsb		*body;
};

static int v_matchproto_(config_f)
c_iter(void *priv, const char *name, const char *arg)
{
	struct warcinfo *wi;

	CAST_OBJ_NOTNULL(wi, priv, WARCINFO_MAGIC);
	AN(wi->body);
	VSB_cat(wi->body, name);
	VSB_cat(wi->body, " ");
	VSB_cat(wi->body, arg);
	VSB_cat(wi->body, "\r\n");
	if (!strcasecmp(name, "software:"))
		wi->sw_flag = 1;
	return (0);
}

char *
Warcinfo_New(const struct aardwarc *aa, struct wsilo *wsl, uint32_t silono)
{
	struct warcinfo *wi;
	char *p, *q;
	const char *r;
	struct vsb *vsb;
	void *ptr;
	ssize_t len, len2;
	struct SHA256Context sha256[1];

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(wsl);
	ALLOC_OBJ(wi, WARCINFO_MAGIC);
	AN(wi);

	/* Assemble Body first, we need it's len & digest for the header */

	wi->body = VSB_new_auto();
	AN(wi->body);
	AZ(Config_Iter(aa->cfg, "warcinfo.body", wi, c_iter));
	if (!wi->sw_flag) {
		VSB_printf(wi->body, "software: %s",
		    "https://github.com/bsdphk/AardWARC");
#ifdef GITREV
		VSB_printf(wi->body, " (%s)", GITREV);
#endif
		VSB_printf(wi->body, "\r\n");
	}
	AZ(VSB_finish(wi->body));

	/* Assemble headers, now we know C-L from body */

	wi->hdr = Header_New(aa);
	AN(wi->hdr);
	Header_Set_Date(wi->hdr);
	Header_Set(wi->hdr, "WARC-Type", "warcinfo");
	Header_Set(wi->hdr, "Content-Type", "application/warc-fields");
	Header_Set(wi->hdr, "Content-Length", "%zd", VSB_len(wi->body));

	p = SHA256_Data(VSB_data(wi->body), VSB_len(wi->body) - 4, NULL);
	Header_Set(wi->hdr, "WARC-Block-Digest", "sha256:%s", p);

	Header_Set(wi->hdr, "WARC-Filename", aa->silo_basename, silono);
	r = Header_Get(wi->hdr, "WARC-Filename");
	AN(r);

	SHA256_Init(sha256);
	SHA256_Update(sha256, p, strlen(p));
	SHA256_Update(sha256, "\n", 1);
	SHA256_Update(sha256, r, strlen(r));
	SHA256_Update(sha256, "\n", 1);
	q = SHA256_End(sha256, NULL);
	AN(q);
	Header_Set_Id(wi->hdr, q);

	REPLACE(p, NULL);
	REPLACE(q, NULL);

	Gzip_Vsb(&wi->body, 0);
	Header_Set(wi->hdr, "Content-Length-GZIP", "%zd", VSB_len(wi->body));

	vsb = Header_Serialize(wi->hdr, 0);
	AN(vsb);
	len2 = VSB_len(vsb);
	assert(len2 > 0);

	Wsilo_GetSpace(wsl, &ptr, &len);
	assert(len2 <= len);
	memcpy(ptr, VSB_data(vsb), len2);
	AZ(Wsilo_Store(wsl, len2));

	p = strdup(Header_Get_Id(wi->hdr));
	AN(p);

	VSB_delete(vsb);
	Header_Delete(&wi->hdr);

	len2 = VSB_len(wi->body);
	assert(len2 > 0);

	Wsilo_GetSpace(wsl, &ptr, &len);
	assert(len2 <= len);
	memcpy(ptr, VSB_data(wi->body), len2);
	AZ(Wsilo_Store(wsl, len2));

	len2 = sizeof Gzip_crnlcrnl;
	Wsilo_GetSpace(wsl, &ptr, &len);
	assert(len2 <= len);
	memcpy(ptr, Gzip_crnlcrnl, len2);
	AZ(Wsilo_Store(wsl, len2));

	VSB_delete(wi->body);

	FREE_OBJ(wi);
	return (p);
}
