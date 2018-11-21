/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2012 Fastly Inc
 * Copyright (c) 2006-2014 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 * Author: Rogier 'DocWilco' Mulhuijzen <rogier@fastly.com>
 *
 * Inspired by FreeBSD's <sys/cdefs.h>
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

#ifndef VDEF_H_INCLUDED
#define VDEF_H_INCLUDED

#include <stdint.h>		// To get __printflike and [u]int%d_t

#ifndef __GNUC_PREREQ
# if defined __GNUC__ && defined __GNUC_MINOR__
#  define __GNUC_PREREQ(maj, min) \
	(__GNUC__ > (maj) || (__GNUC__ == (maj) && __GNUC_MINOR__ >= (min)))
# else
#  define __GNUC_PREREQ(maj, min) 0
# endif
#endif

#ifdef __printflike
#  define v_printflike_(f,a) __printflike(f,a)
#elif __GNUC_PREREQ(2, 95) || defined(__INTEL_COMPILER)
#  define v_printflike_(f,a) __attribute__((format(printf, f, a)))
#else
#  define v_printflike_(f,a)
#endif

/* Safe printf into a fixed-size buffer */
#define bprintf(buf, fmt, ...)						\
	do {								\
		assert(snprintf(buf, sizeof buf, fmt, __VA_ARGS__)	\
		    < (int)sizeof buf);					\
	} while (0)

/**********************************************************************
 * FlexeLint and compiler shutuppery
 */

/*
 * In OO-light situations, functions have to match their prototype
 * even if that means not const'ing a const'able argument.
 * The typedef should be specified as argument to the macro.
 */
#define v_matchproto_(xxx)		/*lint -e{818} */

#define NEEDLESS_RETURN(foo)	return (foo)

#endif /* VDEF_H_INCLUDED */
