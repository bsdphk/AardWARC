#!/bin/sh
#
# Stow

set -e

. test.rc

sed -i '' '/^stow.test03/,$d' ${ADIR}/aardwarc.conf

(
echo '.git'
echo '*.gcda'
) > ${ADIR}/_stow.exclude

(
echo "stow.test03:"
echo "          directory `pwd`/.."
echo "          exclude ${ADIR}/_stow.exclude"
echo "          cmd `pwd`/${AXEC} stevedore"
echo ""
echo "stow.test03a:"
echo "          directory `pwd`/.."
echo "          cmd sleep 1 ; exit 2"
echo ""
) >> ${ADIR}/aardwarc.conf

echo "#### $0 Stow"
fail 0 'Done job test03' ${AXEC} stow test03
fail 2 '(Remote) command failed' ${AXEC} stow test03a
