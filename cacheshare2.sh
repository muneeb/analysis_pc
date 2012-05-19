#!/bin/bash

CACHESHARE="$HOME/uu/uart-trunk/analysis/cacheshare2.py"

function print_and_exit {
	echo $1
	exit 1
}

[ $# -eq 2 ] || print_and_exit "Usage: $0 <mix> <window>"

MIX=$1
WIN=$2

MIXPATH="$HOME/uu/workspace/data/$MIX/"

[ -d "$MIXPATH" ] || print_and_exit "$MIXPATH not a dir"

HIST1=$MIXPATH/sample0.${WIN}.hist
HIST2=$MIXPATH/sample1.${WIN}.hist

MIX1=$MIXPATH/mix0.${WIN}
MIX2=$MIXPATH/mix1.${WIN}

CPI1=$MIXPATH/cpi0.${WIN}
CPI2=$MIXPATH/cpi1.${WIN}

$CACHESHARE $HIST1 $HIST2 `cat $CPI1` `cat $CPI2` `cat $MIX1` `cat $MIX2`

#echo
#echo "===================="
#echo "CPI1: `cat $CPI1`, CPI2: `cat $CPI2`"
#echo "===================="
#echo
