#!/bin/bash

[ -f /tmp/sysmonitor.run ] && exit
[ ! -f /tmp/sysmonitor.pid ] && echo 0 >/tmp/sysmonitor.pid
[ "$(cat /tmp/sysmonitor.pid)" != 0 ] && exit

NAME=sysmonitor
APP_PATH=/usr/share/$NAME
SYSLOG='/var/log/sysmonitor.log'
touch /tmp/sysmonitor.run
	
echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$SYSLOG
#	number=$(cat $SYSLOG|wc -l)
#	[ $number -gt 25 ] && sed -i '1,10d' $SYSLOG
}

uci_get_by_name() {
	local ret=$(uci get $1.$2.$3 2>/dev/null)
	echo ${ret:=$4}
}

uci_set_by_name() {
	uci set $1.$2.$3=$4 2>/dev/null
	uci commit $1
}

ping_url() {
	for i in $( seq 1 2 ); do
		status=$(ping -c 1 -W 1 $1 | grep -o 'time=[0-9]*.*' | awk -F '=' '{print$2}'|cut -d ' ' -f 1)
		[ "$status" == "" ] && status=0
		[ "$status" != 0 ] && break
	done
	[ "$status" != 0 ] && status=1
	echo $status
}

curl_url() {
	for i in $( seq 1 2 ); do
		result=$(curl -s --connect-timeout 1 $1|grep google|wc -l)
		[ "$result" != 0 ] && break
	done
	echo $result
}

mask() {
    num=$((4294967296 - 2 ** (32 - $1)))
    for i in $(seq 3 -1 0); do
        echo -n $((num / 256 ** i))
        num=$((num % 256 ** i))
        if [ "$i" -eq "0" ]; then
            echo
        else
            echo -n .
        fi
    done
}

check_ip() {
	if [ ! -n "$1" ]; then
		#echo "NO IP!"
		echo ""
	else
 		IP=$1
    		VALID_CHECK=$(echo $IP|awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print "yes"}')
		if echo $IP|grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$">/dev/null; then
			if [ ${VALID_CHECK:-no} == "yes" ]; then
				# echo "IP $IP available."
				echo $IP
			else
				#echo "IP $IP not available!"
				echo ""
			fi
		else
			#echo "IP is name convert ip!"
			dnsip=$(nslookup $IP|grep Address|sed -n '2,2p'|cut -d' ' -f2)
			if [ ! -n "$dnsip" ]; then
				#echo "Inull"
				echo $test
			else
				#echo "again check"
				echo $(check_ip $dnsip)
			fi
		fi
	fi
}

set_static() {
	ip=$(ip -o -4 addr list br-wan| cut -d ' ' -f7)
	wanip=$(echo $ip|cut -d'/' -f1)
	netmask=$(mask $(echo $ip|cut -d'/' -f2))
	gateway=$(check_ip $(ip route|grep default|cut -d' ' -f3))
	if [ -n "$gateway" ]; then
		uci set sysmonitor.sysmonitor.netmask=$netmask
		uci set sysmonitor.sysmonitor.gatewayip=$gateway
		uci commit sysmonitor	
		setdns
	fi
}

setdns() {
	dnslist=$(uci_get_by_name $NAME $NAME dnslist '192.168.1.1')
	gatewayip=$(uci_get_by_name $NAME $NAME gatewayip '192.168.1.1')
	netmask=$(uci_get_by_name $NAME $NAME netmask '255.255.255.0')
	homeip=$(uci_get_by_name $NAME $NAME homeip '192.168.1.120')
	uci set network.wan.proto='static'
	uci set network.wan.ipaddr=$homeip
	uci set network.wan.gateway=$gatewayip
	uci set network.wan.netmask=$netmask
	uci del network.wan.dns
	for n in $dnslist
	do 		
		uci add_list network.wan.dns=$n
	done
	if [ "$(uci get network.lan.dns)" != $homeip ]; then
		uci set network.lan.dns=$homeip
		uci commit network
		ifup lan
	else
		uci commit network
	fi
	ifup wan
	ifup wan6
	/etc/init.d/odhcpd restart
}

setvpn() {
	uci set network.wan.gateway=$vpnip
	uci del network.wan.dns
	uci add_list network.wan.dns=$vpnip
	dnslist=$(uci_get_by_name $NAME $NAME dnslist '192.168.1.1')
	for n in $dnslist
	do 		
		uci add_list network.wan.dns=$n
	done
	[ "$(uci_get_by_name $NAME $NAME syslog)" == 1 ] && echolog "WAN-DNS="$vpnip
	uci commit network
	ifup wan
	ifup wan6
	/etc/init.d/odhcpd restart
}

selvpn() {
	vpnlist=$(uci_get_by_name $NAME $NAME vpn '')
	if [ ! -n "$vpnlist" ]; then
		uci set sysmonitor.sysmonitor.vpn='192.168.1.1'
		uci commit sysmonitor
		vpnlist='192.168.1.1'
	fi
	vpnip=$1
	[ "$(echo $vpnlist|grep $vpnip|wc -l)" == 0 ] && vpnip=$(echo $vpnlist|cut -d' ' -f1)
	k=0
	for n in $vpnlist
	do
		if [ "$k" == 1 ]; then
			vpnip=$n
			break
		fi
		[ "$vpnip" == "$n" ] && {
			k=1
			vpnip=$(echo $vpnlist|cut -d' ' -f1)
		}
	done
	echo $vpnip
}

chk_vpnip() {
	vpnip=$1
	if [ "$(cat /tmp/regvpn|wc -l)" != 0 ]; then
		if [ "$(cat /tmp/regvpn|grep $1|wc -l)" == 0 ]; then
			vpnip=$(selvpn $1)
			uci set sysmonitor.sysmonitor.vpnip=$vpnip
			uci commit sysmonitor
		fi
	fi
	echo $vpnip
}

chk_vpn() {
	status=$(ping_url $1)
	if [ "status" == 0 ]; then
		file='/tmp/regvpn'
		vpn=$(cat $file|grep $i)
		vpn1=$(echo $vpn|sed "s|-1-|-0-|g")
		vpn1='0'${vpn1:1}
		sed -i "s|$vpn|$vpn1|g" $file
	else
		status=$(cat /tmp/regvpn|grep $1|cut -d'-' -f3)
	fi
	echo $status
}

sys_exit() {
	setdns
	echolog "Sysmonitor is off."
	[ -f /tmp/sysmonitor.run ] && rm -rf /tmp/sysmonitor.run
	syspid=$(cat /tmp/sysmonitor.pid)
	syspid=$((syspid-1))
	echo $syspid > /tmp/sysmonitor.pid
	exit 0
}

[ ! $(uci get dhcp.lan.ra) == "relay" ] && touch /tmp/relay
[ ! $(uci get dhcp.lan.ndp) == "relay" ] && touch /tmp/relay
[ ! $(uci get dhcp.lan.dhcpv6) == "relay" ] && touch /tmp/relay
[ -f /tmp/relay ] && {
	uci set dhcp.lan.ra='relay'
	uci set dhcp.lan.dhcpv6='relay'
	uci set dhcp.lan.ndp='relay'
	uci commit dhcp
	/etc/init.d/odhcpd restart &
}

sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
echolog "Sysmonitor is on."
syspid=$(cat /tmp/sysmonitor.pid)
syspid=$((syspid+1))
echo $syspid > /tmp/sysmonitor.pid
while [ "1" == "1" ]; do
	proto=$(uci get network.wan.proto)
	case $proto in
		static)
			gatewayip=$(uci_get_by_name $NAME $NAME gatewayip '192.168.1.1')
			vpnip=$(uci_get_by_name $NAME $NAME vpnip '192.168.1.1')
			vpnip=$(chk_vpnip $vpnip)
			gateway=$(uci get network.wan.gateway)
			VPNenable=$(uci_get_by_name $NAME $NAME vpnenable 0)
			status='1'
			[ "$(uci_get_by_name $NAME $NAME dhcp 0)" == 1 ] && status=$(ping_url $gatewayip)
			if [ ${status:0:1} == 0 ]; then
				uci del network.wan.ipaddr
				uci del network.wan.netmask
				uci del network.wan.gateway
				uci set network.wan.proto='dhcp'
				uci commit network
				ifup wan
				ifup wan6
				/etc/init.d/odhcpd restart
				echolog "WAN set to dhcp."
			else
			case $VPNenable in
				1)
					status=0
					[ ! -f /tmp/chkvpn.skip ] && status=$(chk_vpn $vpnip)
					[ -f /tmp/chkvpn.skip ] && rm /tmp/chkvpn.skip
					case $status in
						0)
							vpnip=$(selvpn $(uci_get_by_name $NAME $NAME vpnip '192.168.1.1'))
							status=$(ping_url $vpnip)
							if [ ${status:0:1} == 0 ];then
								[ "$gateway" != $gatewayip ] && setdns
							else
								uci set sysmonitor.sysmonitor.vpnip=$vpnip
								uci commit sysmonitor
								status=$(chk_vpn $vpnip)
								if [ ${status:0:1} == 0 ]; then
									[ "$gateway" != $gatewayip ] && setdns
								else
									[ "$gateway" != $vpnip ] && setvpn
								fi
							fi
							;;
						*)
							if [ "$gateway" != $vpnip ]; then
								setvpn
							#elif [ "$(uci get network.wan.dns)" != $vpnip ]; then
							#	setvpn
							fi
							;;
					esac
					;;
				*)
					[ "$gateway" != $gatewayip ] && setdns
					;;
			esac
			fi
			;;
	esac
	num=0
	check_time=$(uci_get_by_name $NAME $NAME vpnsw 10)
	[ "$check_time" -le 3 ] && check_time=3
	chktime=$((check_time-1))
	while [ $num -le $check_time ]; do
		[ ! -f /tmp/test.$NAME ] && touch /tmp/test.$NAME
		prog='regvpn chkvpn'
		for i in $prog
		do
			progsh=$i'.sh'
			progpid='/tmp/'$i'.pid'
			[ "$(pgrep -f $progsh|wc -l)" == 0 ] && echo 0 > $progpid
			[ ! -f $progpid ] && echo 0 > $progpid
			arg=$(cat $progpid)
			case $arg in
				0)
					[ "$(pgrep -f $progsh|wc -l)" != 0 ] && killall $progsh
					progrun='/tmp/'$i'.run'
					[ -f $progrun ] && rm $progrun
					[ -f $progpid ] && rm $progpid
					$APP_PATH/$progsh &
					;;
				1)
					if [ "$i" == "regvpn" ]; then
						case $num in
							2)
							[ -f /tmp/test.$i ] && rm /tmp/test.$i
							ip=$(ip -o -4 addr list br-wan| cut -d ' ' -f7)
							wanip=$(echo $ip|cut -d'/' -f1)
							echo '9test-'$i |netcat -nc $wanip 55555
							;;
						$chktime)
							[ ! -f /tmp/test.$i ] && killall $progsh
							;;
						esac
					fi
					if [ "$i" == "chkvpn" ] && [ "$num" == $chktime ]; then
						if [ ! -f /tmp/test.$i ]; then	
							killall $progsh
						else
							rm /tmp/test.$i
						fi
					fi
					;;
				*)
					killall $progsh
					echo 0 > $progpid
					;;
			esac	
		done
		if [ -f /tmp/wan6.sign ]; then
			rm /tmp/wan6.sign
			ipv6=$(ip -o -6 addr list br-wan|cut -d ' ' -f7)
			cat /www/ip6.html | grep $(echo $ipv6|cut -d'/' -f1 |head -n1) > /dev/null
			[  $? -ne 0 ] && {
				[ "$(uci_get_by_name $NAME $NAME syslog)" == 1 ] && echolog "ip6="$ipv6
				echo $ipv6|cut -d'/' -f1|head -n1 >/www/ip6.html
				[ $(uci_get_by_name $NAME $NAME ddns 0) == 1 ] && $APP_PATH/sysapp.sh update_ddns &
			}
		fi	
		if [ -f /tmp/wan.sign ]; then
			rm /tmp/wan.sign
			[ "$(uci get network.wan.proto)" == 'dhcp' ] && set_static
		fi
		if [ -f /tmp/network.sign ]; then
			rm /tmp/network.sign
			[ "$(uci get network.wan.proto)" == 'static' ] && setdns
		fi
		[ ! -f /tmp/sysmonitor.run ] && sys_exit
		[ "$(uci_get_by_name $NAME $NAME enable 0)" == 0 ] && sys_exit
		[ "$(cat /tmp/sysmonitor.pid)" -gt 1 ] && sys_exit
		sleep 1
		num=$((num+1))
		if [ -f "/tmp/sysmonitor" ]; then
			rm /tmp/sysmonitor
			break
		fi
	done
done
