#!/bin/bash -eux

DEBUG_URL=http://cdn-fastly.deb.debian.org/debian-debug/pool/main/$1
MAIN_URL=${DEBUG_URL/-debug\//\/}
MAIN_URL=${MAIN_URL/-dbgsym_/_}

wget -c $DEBUG_URL
wget -c $MAIN_URL

MAIN_DEB=$(basename $MAIN_URL)
DEBUG_DEB=$(basename $DEBUG_URL)

FILES=$(dpkg --vextract $MAIN_DEB .)
dpkg -x $DEBUG_DEB .

for FILE in $FILES
do
	file $FILE | grep -q ELF || continue
	ELF=$FILE
	#[ -e $ELF ] || continue
	BUG=./usr/lib/debug/.build-id/$(file $ELF | sed -e "s/.*=//" -e "s/,.*//" -e "s/^\(..\)/\1\//").debug
	[ -e $BUG ] || continue
	~/.virtualenvs/angr/bin/python ./analyze_binary.py $MAIN_URL $ELF $BUG
done
