#!/bin/bash

[ -f /tmp/regvpn.run ] && exit
[ ! -f /tmp/regvpn.pid ] && echo 0 >/tmp/regvpn.pid
[ "$(cat /tmp/regvpn.pid)" != 0 ] && exit

touch /tmp/regvpn.run
NAME=sysmonitor
APP_PATH=/usr/share/$NAME
SYSLOG='/var/log/sysmonitor.log'

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$SYSLOG
	number=$(cat $SYSLOG|wc -l)
	[ $number -gt 25 ] && sed -i '1,10d' $SYSLOG
}

uci_get_by_name() {
	local ret=$(uci get $1.$2.$3 2>/dev/null)
	echo ${ret:=$4}
}

uci_set_by_name() {
	uci set $1.$2.$3=$4 2>/dev/null
	uci commit $1
}

sys_exit() {
	#echolog "regVPN is off."
	[ -f /tmp/regvpn.run ] && rm -rf /tmp/regvpn.run
	syspid=$(cat /tmp/regvpn.pid)
	syspid=$((syspid-1))
	echo $syspid > /tmp/regvpn.pid
	exit 0
}

#echolog "regVPN is on."
syspid=$(cat /tmp/regvpn.pid)
syspid=$((syspid+1))
echo $syspid > /tmp/regvpn.pid
file='/tmp/regvpn'
while [ "1" == "1" ]; do
	regvpn=$(netcat -lnp 55555)
	func=${regvpn:0:1}
	regvpn=${regvpn:1}
	case $func in
		1)
			name=$(echo $regvpn|cut -d'-' -f2)
			ip=$(echo $regvpn|cut -d'-' -f1)
			reghost=$(uci_get_by_name $NAME $NAME reghost 3)
			cat $file | grep $name >/dev/null
			if [ ! $? -eq 0 ];then
				touch /tmp/regvpn.sign
			fi
			sed -i /$name/d $file
			echo $reghost$regvpn >> $file
#			sed -i '/^\s*$/d' $file
			;;
		*)
			echo $regvpn >/tmp/test.regvpn
			;;
	esac
 	[ ! -f /tmp/regvpn.run ] && sys_exit
 	[ "$(cat /tmp/regvpn.pid)" -gt 1 ] && sys_exit
done
