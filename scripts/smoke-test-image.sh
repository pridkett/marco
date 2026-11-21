#!/bin/sh
set -eu

image=${1:?provide the Marco image tag}
platform=${2:?provide the image platform}
container=$(docker create --platform "$platform" "$image")
trap 'docker rm "$container" >/dev/null' EXIT

mode=$(docker export "$container" | tar -tvf - | awk '$NF == "tmp/" {print $1}')
if [ "$mode" != "drwxrwxrwt" ]; then
    echo "The Marco image requires /tmp with mode 1777 for SQLite history sorts." >&2
    exit 1
fi

docker run --rm --platform "$platform" "$image" version
