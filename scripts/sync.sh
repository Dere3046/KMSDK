#!/bin/sh
# clone libs.lst into libs/ (gitignored) for local browsing
set -e

cd "$(dirname "$0")/.."

while read -r name url rev desc; do
	[ -z "$name" ] && continue
	case $name in \#*) continue ;; esac
	if [ -d "libs/$name" ]; then
		echo "skip $name"
	else
		git clone "$url" "libs/$name"
	fi
done < libs.lst
