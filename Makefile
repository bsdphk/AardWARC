SRCS	+=	aardwarc.c
SRCS	+=	config.c
SRCS	+=	getjob.c
SRCS	+=	gzip.c
SRCS	+=	header.c
SRCS	+=	index.c
SRCS	+=	main.c
SRCS	+=	main_audit.c
SRCS	+=	main_byid.c
SRCS	+=	main_cgi.c
SRCS	+=	main_dumpindex.c
SRCS	+=	main_filter.c
SRCS	+=	main_get.c
SRCS	+=	main_housekeeping.c
SRCS	+=	main_info.c
SRCS	+=	main_reindex.c
SRCS	+=	main_stevedore.c
SRCS	+=	main_store.c
SRCS	+=	main_stow.c
SRCS	+=	main_testbytes.c
SRCS	+=	proto.c
SRCS	+=	rsilo.c
SRCS	+=	segjob.c
SRCS	+=	silo.c
SRCS	+=	vlu.c
SRCS	+=	vnum.c
SRCS	+=	vsb.c
SRCS	+=	warcinfo.c
SRCS	+=	wsilo.c

PROG	=	aardwarc

LDADD	+=	-lmd
LDADD	+=	-lm
LDADD	+=	-lz

CFLAGS	+=	-O0 -g

WARNS	?=	6

CLEANFILES	+=	*.gcov *.gcda *.gcno

MK_MAN	=	no

.include <bsd.prog.mk>

flint:
	flexelint \
		-I. \
		-I/usr/include \
		flint.lnt \
		${SRCS}

