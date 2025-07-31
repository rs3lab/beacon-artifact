#!/bin/bash

display_help() {
	echo "Usage: $0 [options]"
	echo "Options:"
	echo "  -h, --help       Display this help message"
	echo "  --original       Draw Figure 9 in the paper with the original data."
	echo "  --regenerated    Draw Figure 9 in the paer with the newly collected data."
	echo "	--fig9a		 Draw Figure 9a"
	echo "	--fig9b		 Draw Figure 9b"
}

if [ ! -d $PWD/data ]; then
	echo "please chdir to the top level of the repo and re-execute the script"
	exit
fi

if [[ "$1" == "--original" ]]; then
	if [[ "$2" == "--fig9a" ]]; then
		OUT=$PWD/data/fig-9a.pdf TARGET=pdf gnuplot $PWD/data/perf1-9a.gp
	else
		OUT=$PWD/data/fig-9b.pdf TARGET=pdf gnuplot $PWD/data/perf1-9b.gp
	fi
elif [[ "$1" == "--regenerated" ]]; then
	if [[ "$2" == "--fig9a" ]]; then
		python perf.py -regen -time workdir/verify-per.csv
		OUT=$PWD/data/fig9a-regen.pdf TARGET=pdf gnuplot $PWD/data/perf2-9a.gp
	else
		python perf.py -regen -impv workdir-impv/verify-per.csv
		OUT=$PWD/data/fig9b-regen.pdf TARGET=pdf gnuplot $PWD/data/perf2-9b.gp
	fi

else
	display_help
	exit
fi
