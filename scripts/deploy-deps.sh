#!/bin/sh
# deploy deps declared in a module deps.lst
# usage: deploy-deps.sh <module dir>
# deps.lst line format: <name> <rev>, url comes from the registry
# builtin entries have url "builtin", they live in the SDK itself
# closure walked from the libs deps.lst declares plus their recursive
# DEPS_LIB_DEPS, an unused builtin never pulls its deps in, dedup by name
set -e

SDKDIR=$(cd "$(dirname "$0")/.." && pwd)
MODDIR=$1
REGLIST=$SDKDIR/libs.lst

[ -f "$MODDIR/deps.lst" ] || { echo "no deps.lst in $MODDIR"; exit 1; }

deploy_one() {
	name=$1
	rev=$2

	[ -d "$MODDIR/deps/$name" ] && return 0

	line=$(awk -v n="$name" '$1==n {print $2" "$3; exit}' "$REGLIST")
	[ -z "$line" ] && { echo "unknown lib in registry: $name"; exit 1; }
	url=${line% *}
	reg_rev=${line#* }

	if [ "$url" = "builtin" ]; then
		[ -d "$SDKDIR/builtin/$name" ] || { echo "builtin lib missing: $name"; exit 1; }
		echo "builtin $name"
		return 0
	fi

	[ -z "$rev" ] && rev=$reg_rev
	echo "fetch $name @ $rev"
	git clone "$url" "$MODDIR/deps/$name"
	git -C "$MODDIR/deps/$name" checkout "$rev"

	meta="$MODDIR/deps/$name/deps.mk"
	[ -f "$meta" ] || { echo "lib $name has no deps.mk, push it first"; exit 1; }
	libid=$(sed -n 's/^DEPS_LIB_NAME := \(.*\)$/\1/p' "$meta")
	[ "$libid" = "$name" ] || { echo "id mismatch: declared $name vs $libid"; exit 1; }
}

enqueue() {
	case " $seen " in
	*" $1 "*) return 0 ;;
	esac

	seen="$seen $1"
	queue="$queue $1"
	return 0
}

walk_one() {
	name=$1
	meta=

	if [ -f "$MODDIR/deps/$name/deps.mk" ]; then
		meta=$MODDIR/deps/$name/deps.mk
	elif [ -f "$SDKDIR/builtin/$name/deps.mk" ]; then
		meta=$SDKDIR/builtin/$name/deps.mk
	else
		return 0
	fi

	for dep in $(sed -n 's/^DEPS_LIB_DEPS := \(.*\)$/\1/p' "$meta"); do
		deploy_one "$dep" ""
		enqueue "$dep"
	done

	return 0
}

queue=
seen=

while read -r name rev; do
	[ -z "$name" ] && continue
	case $name in \#*) continue ;; esac
	deploy_one "$name" "$rev"
	enqueue "$name"
done < "$MODDIR/deps.lst"

while [ -n "$queue" ]; do
	name=${queue%% *}
	case $queue in
	*" "*) queue=${queue#* } ;;
	*) queue= ;;
	esac
	walk_one "$name"
done

echo "deps ok"
