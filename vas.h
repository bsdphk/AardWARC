/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * SPDX-License-Identifier: BSD-2-Clause
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
 * assert(), AN() and AZ() are static checks that should not happen.
 *	In general asserts should be cheap, such as checking return
 *	values and similar.
 * diagnostic() are asserts which are so expensive that we may want
 *	to compile them out for performance at a later date.
 * xxxassert(), XXXAN() and XXXAZ() marks conditions we ought to
 *	handle gracefully, such as malloc failure.
 */

#ifndef VAS_H_INCLUDED
#define VAS_H_INCLUDED

#include <errno.h>

enum vas_e {
	VAS_WRONG,
	VAS_MISSING,
	VAS_ASSERT,
	VAS_INCOMPLETE,
	VAS_VCL,
};

typedef void vas_f(const char *, const char *, int, const char *, enum vas_e);

extern vas_f *VAS_Fail_Func v_noreturn_;
extern vas_f VAS_Fail v_noreturn_;

#ifdef WITHOUT_ASSERTS
#define assert(e)	((void)(e))
#else /* WITH_ASSERTS */
#define assert(e)							\
do {									\
	if (!(e)) {							\
		VAS_Fail(__func__, __FILE__, __LINE__,			\
		    #e, VAS_ASSERT);					\
	}								\
} while (0)
#endif

#define xxxassert(e)							\
do {									\
	if (!(e)) {							\
		VAS_Fail(__func__, __FILE__, __LINE__,			\
		    #e, VAS_MISSING);					\
	}								\
} while (0)

/* Assert zero return value */
#define AZ(foo)		do { assert((foo) == 0); } while (0)
#define AN(foo)		do { assert((foo) != 0); } while (0)
#define XXXAZ(foo)	do { xxxassert((foo) == 0); } while (0)
#define XXXAN(foo)	do { xxxassert((foo) != 0); } while (0)
#define diagnostic(foo)	assert(foo)
#define WRONG(expl)							\
do {									\
	VAS_Fail(__func__, __FILE__, __LINE__, expl, VAS_WRONG);	\
} while (0)

#define INCOMPL()							\
do {									\
	VAS_Fail(__func__, __FILE__, __LINE__,				\
	    "", VAS_INCOMPLETE);					\
} while (0)

/*
 * Most of this nightmare is stolen from FreeBSD's <cdefs.h>
 */
#ifndef __has_extension
#  define __has_extension(x)	0
#endif

#if __has_extension(c_static_assert)
#   define v_static_assert _Static_assert
#elif __GNUC_PREREQ__(4,6) && !defined(__cplusplus)
#   define v_static_assert _Static_assert
#else
#   if defined(__COUNTER__)
#	define v_static_assert(x, y)	__v_static_assert(x, __COUNTER__)
#   else
#	define v_static_assert(x, y)	__v_static_assert(x, __LINE__)
#   endif
#   define __v_static_assert(x, y)	___v_static_assert(x, y)
#   define ___v_static_assert(x, y) \
		typedef char __vassert_## y[(x) ? 1 : -1] v_unused_
#endif

#endif
