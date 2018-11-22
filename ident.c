/*-
 * Copyright (c) 2018 Poul-Henning Kamp
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


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vdef.h"
#include "miniobj.h"
#include "vas.h"
#include "vsb.h"
#include "sha256.h"

#include "aardwarc.h"

void
Ident_Create(const struct aardwarc *aa, const struct header *hdr,
    const char *payload_digest, char *ident)
{
	const char *typ, *ref;
	struct SHA256Context sha256[1];

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(hdr);
	AN(payload_digest);
	typ = Header_Get(hdr, "WARC-Type");
	AN(typ);
	if (!strcmp(typ, "resource")) {
		/* We use the payload digest as ID */
		strcpy(ident, payload_digest);
	} else if (!strcmp(typ, "continuation")) {
		/* We use the payload digest as ID */
		strcpy(ident, payload_digest);
	} else if (!strcmp(typ, "warcinfo")) {
		/* We use the payload digest as ID */
		strcpy(ident, payload_digest);
	} else if (!strcmp(typ, "metadata")) {
		/* ID=SHA256(reference_id + "\n" + SHA256(body) + "\n") */
		SHA256_Init(sha256);
		ref = Header_Get(hdr, "WARC-Refers-To");
		AN(ref);
		SHA256_Update(sha256, ref, strlen(ref));
		SHA256_Update(sha256, "\n", 1);
		SHA256_Update(sha256, payload_digest, strlen(payload_digest));
		SHA256_Update(sha256, "\n", 1);
		AN(SHA256_End(sha256, ident));
	} else {
		fprintf(stderr, "XXX %s\n", typ);
		WRONG("Unknown WARC-Type");
	}

	ident[aa->id_size] = '\0';
}

void
Ident_Set(const struct aardwarc *aa, struct header *hdr,
    const char *payload_digest)
{
	char id[SHA256_DIGEST_STRING_LENGTH];

	Ident_Create(aa, hdr, payload_digest, id);
	Header_Set_Id(hdr, id);
}

char *
Digest2Ident(const struct aardwarc *aa, const char *digest)
{
	struct vsb *vsb;
	char *id;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(digest);

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s%s", aa->prefix, digest);
	AZ(VSB_finish(vsb));
	AZ(IDX_Valid_Id(aa, VSB_data(vsb), NULL));
	id = strdup(VSB_data(vsb));
	AN(id);
	VSB_destroy(&vsb);
	return (id);
}
