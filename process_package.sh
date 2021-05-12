#!/bin/bash -eux

#MAIN_URL=$1
##if ! [[ $MAIN_URL =~ ^http.* ]]
##then
##	PREFIX=${MAIN_URL:0:1}
##	[[ $MAIN_URL =~ ^lib.* ]] && PREFIX=${MAIN_URL:0:4}
##	PACKAGE=${MAIN_URL//_*/}
##	MAIN_URL=http://cdn-fastly.deb.debian.org/debian/pool/main/$PREFIX/$PACKAGE/$MAIN_URL
##fi
#DEBUG_URL=${MAIN_URL/\/debian\//\/debian-debug\/}
#DEBUG_URL=${DEBUG_URL/_/-dbgsym_}

SCRIPT_BASE=$(dirname "$0")

DEBUG_URL=http://cdn-fastly.deb.debian.org/debian-debug/pool/main/$1
MAIN_URL=${DEBUG_URL/-debug\//\/}
MAIN_URL=${MAIN_URL/-dbgsym_/_}

#cd $(mktemp -d)
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
	${VIRTUAL_ENV-~/.virtualenvs/angr}/bin/python $SCRIPT_BASE/analyze_binary.py $ELF --package=$MAIN_URL --debug=$BUG --cc-timeout=60 --dec-timeout=30
done
