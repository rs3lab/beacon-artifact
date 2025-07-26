#!/bin/bash

display_help() {
	echo "Usage: $0 [options]"
	echo "Options:"
	echo "  -h, --help       Display this help message"
	echo "  --original       Draw Figure 9 in the paper with the original data."
	echo "  --regenerated    Draw Figure 9 in the paer with the newly collected data."
}

if [ ! -d $PWD/data ]; then
	echo "please chdir to the top level of the repo and re-execute the script"
	exit
fi

if [[ "$1" == "--original" ]]; then
	OUT=$PWD/data/fig9.pdf TARGET=pdf gnuplot $PWD/data/perf1.gp
elif [[ "$1" == "--regenerated" ]]; then
	python perf.py -regen -time workdir-impv/verify-per.csv -impv workdir-impv/verify-per.csv
	OUT=$PWD/data/fig9-regen.pdf TARGET=pdf gnuplot $PWD/data/perf2.gp
else
	display_help
	exit
fi
