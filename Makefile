SRCS	+=	aardwarc.c
SRCS	+=	config.c
SRCS	+=	getjob.c
SRCS	+=	gzip.c
SRCS	+=	header.c
SRCS	+=	ident.c
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
SRCS	+=	main_rebuild.c
SRCS	+=	main_reindex.c
SRCS	+=	main_stevedore.c
SRCS	+=	main_store.c
SRCS	+=	main_stow.c
SRCS	+=	main_testbytes.c
SRCS	+=	proto.c
SRCS	+=	rsilo.c
SRCS	+=	segjob.c
SRCS	+=	silo.c
SRCS	+=	vas.c
SRCS	+=	vlu.c
SRCS	+=	vnum.c
SRCS	+=	vsb.c
SRCS	+=	warcinfo.c
SRCS	+=	wsilo.c

PROG	=	aardwarc

LDADD	+=	-lmd
LDADD	+=	-lm
LDADD	+=	-lz

CFLAGS	+=	-DGITREV=`cd ${.CURDIR} && git log -n 1 '--format=format:"%h"'`
CFLAGS	+=	${COVERAGE_FLAGS}

COVFILES =	*.gcov *.gcda *.gcno _.coverage.txt _.coverage.raw
CLEANFILES +=	${COVFILES}

WARNS	?=	6

MK_MAN	=	no

DESTDIR	?=	/usr/local/bin

.include <bsd.prog.mk>

coverage:
	make cleandir
	rm -rf ${COVFILES} _.coverage
	make depend
	make COVERAGE_FLAGS="-O0 -g --coverage"
	make runtest
	llvm-cov gcov -f ${SRCS} | tee _.coverage.raw | \
	    python3 tests/gcov_report.py > _.coverage.txt
	mkdir -p _.coverage
	mv ${COVFILES} _.coverage
	make clean all
	tail -4 _.coverage/_.coverage.txt

flint:
	cd ${.CURDIR} && flexelint \
		-I. \
		-I/usr/include \
		flint.lnt \
		${SRCS}

test:	${PROG} runtest

runtest:
	cd ${.CURDIR}/tests && env AA=${.OBJDIR}/aardwarc sh alltest.sh

t2:	${PROG}

	./aardwarc -c mnt.conf audit /mnt/AA/0/00000000.warc.gz

t3:
	./aardwarc -c mnt.conf audit 
