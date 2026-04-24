#!/bin/bash

LINE_LENGTH=149

params="*.py plugins/ tests/"

if [ "$1" != "" ] ; then
	params="$1"
fi

for i in ${params} ; do
	echo "--> $i"
	isort --check --diff --color $i
	flake8 $i
	black --check --diff --color $i
	echo ""
done

