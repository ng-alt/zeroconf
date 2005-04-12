#!/bin/sh
#
# This script is invoked by zeroconf
# during three phases of it setup:
# init, config, deconfig
# the phase will be the first argument
#
# init might be used for 'plumbing' or
# modprobing the interface
#
# config is used to assign an IP address
# to an interface
#
# deconfig is used to remove an IP address
# from an interface

if [ $# -lt 2 ]; then
    /usr/bin/printf "$0: error. insufficient arguments\n"
    /usr/bin/printf "usage: $0 <phase> <interface>\n"
    /usr/bin/printf "\tphase    \tis one of init, config or deconfig\n"
    /usr/bin/printf "\tinterface\tis the network device to add or delete\n"
    /usr/bin/printf "\t         \tIPv4 Link-Local addresses from / to \n"
    exit 1
fi

PHASE=$1
IFACE=$2

case $PHASE in
    init)
	/bin/ip link set $IFACE up
	exit 0
	;;
    config)
	/bin/ip addr del $ip/16 dev $IFACE
	/bin/ip addr add $ip/16 dev $IFACE
	exit 0
	;;
    deconfig)
	/bin/ip addr del $ip/16 dev $IFACE
	exit 0
    ;;
esac

exit 0