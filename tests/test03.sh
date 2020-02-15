#!/bin/sh
#
# Stow

set -e

. test.rc

if [ -f ${ADIR}/aardwarc.conf ] ; then
	sed -i '' '/^stow.test03/,$d' ${ADIR}/aardwarc.conf 
else
	new_aardwarc
fi

(
echo '.git'
echo '*.gcda'
) > ${ADIR}/_stow.exclude

(
echo "stow.test03:"
echo "          directory `pwd`/.."
echo "          exclude ${ADIR}/_stow.exclude"
echo "          cmd ${AXEC} stevedore"
echo ""
echo "stow.test03a:"
echo "          directory `pwd`/.."
echo "          cmd sleep 1 ; exit 2"
echo ""
echo "stow.test03b:"
echo "          directory ${ADIR}/test3b"
echo "          cmd ${AXEC} stevedore"
echo ""
) >> ${ADIR}/aardwarc.conf

echo "#### $0 Stow"
#fail 0 'Done job test03' ${AXEC} stow test03
#fail 2 '(Remote) command failed' ${AXEC} stow test03a

# Test 3b is a file which changed underway

rm -rf ${ADIR}/test3b
mkdir ${ADIR}/test3b
for s in d1 d2 d3
do
	mkdir -p ${ADIR}/test3b/$s
	date > ${ADIR}/test3b/$s/file
done

echo 'abcdefghij' > ${ADIR}/test3b/_stow_canary1
echo '0123456789' > ${ADIR}/test3b/_stow_canary2

fail 0 'Done job test03b' ${AXEC} stow test03b

echo 'IIIIIIIVV' > ${ADIR}/test3b/_stow_canary3
echo 'yksikaksi' > ${ADIR}/test3b/_stow_canary4

(
echo '#!'
echo "ADIR=${ADIR}"

echo '

/usr/sbin/mtree $* > ${ADIR}/_mt
echo 'ABCDEfghij' > ${ADIR}/test3b/_stow_canary3

# XXX: Fails with panic
# rm ${ADIR}/test3b/_stow_canary4

cat ${ADIR}/_mt
'
) > ${ADIR}/mtree

chmod +x ${ADIR}/mtree

P0=${PATH}
export PATH=${ADIR}:${PATH}
fail 0 'Done job test03b' ${AXEC} stow test03b
export PATH=${P0}
