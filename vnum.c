/*-
 * Copyright (c) 2008-2009 Varnish Software AS
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
 * Deal with numbers with data storage suffix scaling
 */

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "vdef.h"

#include "aardwarc.h"
#include "vas.h"

static const char err_miss_num[] = "Missing number";
static const char err_invalid_num[] = "Invalid number";
static const char err_abs_req[] = "Absolute number required";
static const char err_invalid_suff[] = "Invalid suffix";

/**********************************************************************
 * Convert (all of!) a string to a floating point number, and if we can
 * not, return NAN.
 */

static double
VNUMpfx(const char *p, const char **t)
{
	double m = 0., ee = 0.;
	double ms = 1.0;
	double es = 1.0, e = 1.0, ne = 0.0;

	AN(p);
	AN(t);
	*t = NULL;
	while (isspace(*p))
		p++;

	if (*p == '-' || *p == '+')
		ms = (*p++ == '-' ? -1.0 : 1.0);

	for (; *p != '\0'; p++) {
		if (isdigit(*p)) {
			m = m * 10. + *p - '0';
			e = ne;
			if (e)
				ne = e - 1.0;
		} else if (*p == '.' && ne == 0.0) {
			ne = -1.0;
		} else
			break;
	}
	if (e > 0.0)
		return(nan(""));		// No digits
	if (*p == 'e' || *p == 'E') {
		p++;
		if (*p == '-' || *p == '+')
			es = (*p++ == '-' ? -1.0 : 1.0);
		if (!isdigit(*p))
			return (nan(""));
		for (; isdigit(*p); p++)
			ee = ee * 10. + *p - '0';
	}
	while (isspace(*p))
		p++;
	if (*p != '\0')
		*t = p;
	return (ms * m * pow(10., e + es * ee));
}

/**********************************************************************/

const char *
VNUM_2bytes(const char *p, uintmax_t *r, uintmax_t rel)
{
	double fval;
	const char *end;

	if (p == NULL || *p == '\0')
		return (err_miss_num);

	fval = VNUMpfx(p, &end);
	if (isnan(fval))
		return (err_invalid_num);

	if (end == NULL) {
		*r = (uintmax_t)fval;
		return (NULL);
	}

	if (end[0] == '%' && end[1] == '\0') {
		if (rel == 0)
			return (err_abs_req);
		fval *= rel / 100.0;
	} else {
		/* accept a space before the multiplier */
		if (end[0] == ' ' && end[1] != '\0')
			++end;

		switch (end[0]) {
		case 'k': case 'K':
			fval *= (uintmax_t)1 << 10;
			++end;
			break;
		case 'm': case 'M':
			fval *= (uintmax_t)1 << 20;
			++end;
			break;
		case 'g': case 'G':
			fval *= (uintmax_t)1 << 30;
			++end;
			break;
		case 't': case 'T':
			fval *= (uintmax_t)1 << 40;
			++end;
			break;
		case 'p': case 'P':
			fval *= (uintmax_t)1 << 50;
			++end;
			break;
		default:
			break;
		}

		/* [bB] is a generic suffix of no effect */
		if (end[0] == 'b' || end[0] == 'B')
			end++;

		if (end[0] != '\0')
			return (err_invalid_suff);
	}

	*r = (uintmax_t)round(fval);
	return (NULL);
}
