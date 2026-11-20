#!/bin/sh
set -eu

arch=${1:?specify amd64, arm64, or armv7}
output=${2:-dist}
version=${MARCO_BUILD_VERSION:-dev}
case "$version" in
    *[!a-zA-Z0-9._+-]*) printf '%s\n' "Invalid MARCO_BUILD_VERSION" >&2; exit 1 ;;
esac
case "$arch" in
    amd64|arm64) GOARCH=$arch; unset GOARM ;;
    armv7) GOARCH=arm; GOARM=7; export GOARM ;;
    *) printf '%s\n' "Unsupported Linux architecture: $arch" >&2; exit 1 ;;
esac
export GOOS=linux CGO_ENABLED=0 GOARCH

mkdir -p "$output"
output=$(cd "$output" && pwd)
cd "$(dirname "$0")/.."
staging=$(mktemp -d "${TMPDIR:-/tmp}/marco-package.XXXXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM
package="$staging/package"
mkdir -p "$package/examples" "$package/docs"
go build -trimpath -ldflags="-X main.version=$version" -o "$package/marco" ./cmd/marco
cp README.md SPEC.md "$package/"
cp examples/marco*.json "$package/examples/"
cp -R examples/lists "$package/examples/"
cp docs/*.md "$package/docs/"
cp -R catalog "$package/"

go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' ./cmd/marco > "$staging/modules"
sort -u "$staging/modules" > "$staging/unique"
{
    printf 'Go runtime\n\n'
    goroot=$(go env GOROOT)
    license="$goroot/LICENSE"
    if [ ! -f "$license" ]; then
        license="$goroot/../LICENSE"
    fi
    cat "$license"
    while IFS= read -r module; do
        [ -n "$module" ] || continue
        directory=$(go list -m -f '{{.Dir}}' "$module")
        for notice in "$directory"/LICENSE* "$directory"/COPYING* "$directory"/NOTICE*; do
            [ -f "$notice" ] || continue
            printf '\n\n%s / %s\n\n' "$module" "${notice##*/}"
            cat "$notice"
        done
    done < "$staging/unique"
} > "$package/THIRD_PARTY_NOTICES.txt"

archive="$output/marco-linux-$arch.tar.gz"
tar -C "$package" -czf "$archive" .
printf '%s\n' "$archive"
