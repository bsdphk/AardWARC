#!/bin/sh
#
# Index housekeeping & rebuild

set -e

. test.rc

LN_I1=`${AXEC} dumpindex | sort -u | wc -l`
LN_M1=`${AXEC} dumpindex | sort -u | md5`

echo "#### $0 Housekeeping"
${AXEC} housekeeping

LN_I2=`${AXEC} dumpindex | sort -u | wc -l`
LN_M2=`${AXEC} dumpindex | sort -u | md5`

if [ ${LN_I1} != ${LN_I2} ] ; then
	echo "Index changed length on housekeeping"
	exit 1
fi
if [ ${LN_M1} != ${LN_M2} ] ; then
	echo "Index changed content on housekeeping"
	exit 1
fi

echo "#### $0 Reindex"
rm -f ${ADIR}/index.sorted ${ADIR}/index.appendix
${AXEC} reindex

LN_I3=`${AXEC} dumpindex | sort -u | wc -l`
LN_M3=`${AXEC} dumpindex | sort -u | md5`

if [ ${LN_I1} != ${LN_I3} ] ; then
	echo "Index changed length on reindex"
	exit 1
fi
if [ ${LN_M1} != ${LN_M3} ] ; then
	echo "Index changed content on reindex"
	exit 1
fi
