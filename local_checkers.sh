#!/bin/bash

LINE_LENGTH=149

params="*.py plugins/ tests/"

if [ "$1" != "" ] ; then
	params="$1"
fi

for i in ${params} ; do
	echo "--> $i"
	isort --color $i
	flake8 $i
	black --color $i
	echo ""
done

echo "--> mypy"
mypy .

