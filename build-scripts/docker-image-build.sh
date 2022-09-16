#!/usr/bin/env bash
#
# This is a wrapper for building our Docker images.
# It aims to be syntax compatible with builder/build.sh as much as possible.

usage() {
    echo "USAGE:  $0 [OPTIONS] <target>"
    echo
    echo "The only valid <target> is docker."

    echo "Options:"
    echo "  -m MODULE  - Build this module. Mandatory, naming exactly one module."
    echo "               Valid values are auth, authoritative, recursor, dnsdist."
    echo "  -V VERSION - Use this version number to generate a tag. Optional."
    echo "               Will strip rec-/auth-/dnsdist- prefix if necessary."
    echo
    exit 1
}

module=""
version=""

while getopts "m:V:" opt; do
    case $opt in
        m)  module="$OPTARG"
            ;;
        V)  version="$OPTARG"
    esac
done

shift $((OPTIND-1))

target=$1

[ "$#" != 1 ] && usage
[ "$module" = "" ] && usage
[ "$target" != "docker" ] && echo "invalid target: $target" && echo && usage

if [ "$module" = "authoritative" ]; then
    module=auth
fi

case $module in
    auth)           ;;
    rec)            ;;
    dnsdist)        ;;
    authoritative)  module=auth
                    ;;
    *)              echo "invalid module: $module"
                    echo
                    usage
                    ;;
esac
buildarg=""
tag="latest"

if [ "$IS_RELEASE" = "YES" ]; then
    buildarg="--build-arg DOCKER_FAKE_RELEASE=YES"
fi

if [ "$version" != "" ]; then
    version=${version#auth-}
    version=${version#rec-}
    version=${version#dnsdist-}
    reposuffix=${version:0:1}${version:2:1}
else
    version=unknown
    reposuffix=unknown
fi

imagename=powerdns/pdns-${module}-${reposuffix}:${version}

docker build --no-cache --pull $buildarg -t $imagename -f Dockerfile-${module} .