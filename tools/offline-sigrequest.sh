#!/bin/bash

set -o errexit

if ! `which festival > /dev/null` ; then
    echo Please install \'festival\'!
    exit 1
fi

function sayhash { # $1 <-- HASH ; $2 <---SIGFILEBALL
  while read -p "Press Enter to read the hash aloud or type 'done':  " INP && [ "$INP" = "" ] ; do
    cat $1 | (echo "(Parameter.set 'Duration_Stretch 1.8)"; \
                echo -n '(SayText "'; \
                sha256sum | cut -c1-64 | fold -1 | sed 's/^a$/alpha/; s/^b$/bravo/; s/^c$/charlie/; s/^d$/delta/; s/^e$/echo/; s/^f$/foxtrot/'; \
                echo '")' ) | festival
  done

  echo 'Paste in the data from the QR code, then type Ctrl-D:'
  cat > $2
}

function offlinesign {  # $1 <-- INPFILE ; $2 <---SIGFILE
  echo HASH FOR SIGNING:
  SIGFILEBALL="$2.lzma.base64"
  #echo "(place the resulting raw binary signature in $SIGFILEBALL)"
  sha256sum $1
  echo metahash for confirmation only $(sha256sum $1   |cut -d' ' -f1 | tr -d '\n' | sha256sum  | cut -c1-6) ...
  echo
  sayhash $1 $SIGFILEBALL
}

function oncesigned { # $1 <-- INPFILE ; $2 <--SIGFILE
  SIGFILEBALL="$2.lzma.base64"
  cat $SIGFILEBALL | tr -d '\r' | base64 -d | unlzma -c > $2 || exit 1
  if ! [ -f $2 ] ; then
    echo "Failed to find $2"'!'
    exit 1
  fi

  if file $2 | grep -qv " data" ; then
    echo "WARNING WARNING $2 does not look like a binary signature:"
    echo `file $2`
    exit 1
  fi
}

HERE=`dirname $0`
LEAUTO="`realpath $HERE`/../letsencrypt-auto-source/letsencrypt-auto"
SIGFILE="$LEAUTO".sig
offlinesign $LEAUTO $SIGFILE
oncesigned $LEAUTO $SIGFILE
