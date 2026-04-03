#!/bin/bash

LINE_LENGTH=149

params="*.py plugins/"

if [ "$1" != "" ] ; then
	params="$1"
fi

for i in ${params} ; do
	isort --profile black --check --diff --color --line-length ${LINE_LENGTH} $i
	flake8 --max-line-length=${LINE_LENGTH} $i
	black --line-length ${LINE_LENGTH} --check --diff --color $i
done

