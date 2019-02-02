#!/bin/sh
#
# Coverage tests

set -e

. test.rc

sed -i '' '/^stow.test04/,$d' ${ADIR}/aardwarc.conf

(
echo "stow.test04_a:"
echo "          exclude `pwd`/stow.exclude"
echo "          cmd `pwd`/${AXEC} stevedore"
echo ""
echo "stow.test04_b:"
echo "          exclude `pwd`/stow.exclude"
echo "		directory /nonexistent"
echo "          cmd `pwd`/${AXEC} stevedore"
echo ""
echo "stow.test04_c:"
echo "          exclude `pwd`/stow.exclude"
echo "		mumble"
echo "          cmd `pwd`/${AXEC} stevedore"
echo ""
) >> ${ADIR}/aardwarc.conf

echo "#### $0 top usage"

fail 1 'Usage' ${AXEC} -h
fail 1 'Unknown global option' ${AXEC} $p -x
fail 1 'Need command argument' ${AXEC}
fail 1 'Unknown operation' ${AXEC} xyzzy

echo "#### $0 util usage"
for p in \
	audit \
	byid \
	cgi \
	dumpindex \
	filter \
	get \
	housekeeping \
	info \
	reindex \
	stevedore \
	store \
	stow \
	_testbytes
do
	fail 1 'Usage' ${AXEC} $p -h
	fail 1 'Unknown option' ${AXEC} $p -x
done


echo "#### $0 stow Argument and Usage code"
fail 1 'Must specify' ${AXEC} stow 
fail 1 'Cannot find stow.blah' ${AXEC} stow blah
fail 1 'have no directory' ${AXEC} stow test04_a
fail 1 'Cannot open target directory' ${AXEC} stow test04_b
fail 1 'has unknown config' ${AXEC} stow test04_c

echo "#### $0 stevedore Argument and Usage code"
fail 1 'Usage' ${AXEC} stevedore xyz
