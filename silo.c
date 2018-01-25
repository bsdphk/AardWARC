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

#include <errno.h>
#include <sys/stat.h>

#include "vas.h"
#include "vsb.h"
#include "miniobj.h"

#include "aardwarc.h"

/* Construct a silo filename ------------------------------------------
 *
 * We want to limit the number of silos in each directory for any
 * number of reasons, but we don't want to commit to a particular
 * depth up front.
 *
 * This code build an adaptive hierarchy:
 *	prefix/0/{100 silos}
 *	prefix/1/{100 subdirs}/{100 silos}
 *	prefix/2/{100 subdirs}/{100 subdirs}/{100 silos}
 *	...
 *
 * A directory with 100 silos is approx 4K large.
 *
 */

static void
numpart(struct vsb *vsb, int lvl, unsigned num)
{
	if (num >= 100U)
		numpart(vsb, lvl + 1, num / 100U);
	else
		VSB_printf(vsb, "%d/", lvl);
	if (lvl > 0)
		VSB_printf(vsb, "%02u/", num % 100U);
}

struct vsb *
Silo_Filename(const struct aardwarc *aa, unsigned number, int hold)
{
	struct vsb *vsb;
	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_cat(vsb, aa->silo_dirname);
	numpart(vsb, 0, number);
	VSB_printf(vsb, aa->silo_basename, number);
	if (hold)
		VSB_cat(vsb, ".hold");
	AZ(VSB_finish(vsb));
	return (vsb);
}

int
Silo_Iter(const struct aardwarc *aa, byte_iter_f *func, void *priv)
{
	struct vsb *vsb;
	uint32_t u;
	struct stat st;
	int i, retval = 0;

	CHECK_OBJ_NOTNULL(aa, AARDWARC_MAGIC);
	AN(func);

	for (u = 0; retval == 0; u++) {
		vsb = VSB_new_auto();
		AN(vsb);
		VSB_cat(vsb, aa->silo_dirname);
		numpart(vsb, 0, u);
		AZ(VSB_finish(vsb));
		i = stat(VSB_data(vsb), &st);
		if (i && errno == ENOENT)
			break;
		VSB_delete(vsb);
		vsb = Silo_Filename(aa, u, 0);
		i = stat(VSB_data(vsb), &st);
		if (!i && S_ISREG(st.st_mode))
			retval = func(priv, VSB_data(vsb), u);
		VSB_delete(vsb);
	}
	return (0);
}
