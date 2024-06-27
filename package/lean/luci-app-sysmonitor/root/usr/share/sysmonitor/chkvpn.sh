#!/bin/bash

[ -f /tmp/chkvpn.run ] && exit
[ ! -f /tmp/chkvpn.pid ] && echo 0 >/tmp/chkvpn.pid
[ "$(cat /tmp/chkvpn.pid)" != 0 ] && exit

touch /tmp/chkvpn.run
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
	#echolog "chkVPN is off."
	[ -f /tmp/chkvpn.run ] && rm -rf /tmp/chkvpn.run
	syspid=$(cat /tmp/chkvpn.pid)
	syspid=$((syspid-1))
	echo $syspid > /tmp/chkvpn.pid
	exit 0
}

chk_sign() {
	if [ -f /tmp/$1 ]; then
		rm -rf /tmp/$1
		$APP_PATH/sysapp.sh $2 &
	fi
}

if [ -f /tmp/firstrun ]; then
	echo "300=ntpd -n -q -p ntp.aliyun.com" >> /tmp/delay.sign
	rm /tmp/firstrun
fi

#echolog "chkVPN is on."
syspid=$(cat /tmp/chkvpn.pid)
syspid=$((syspid+1))
echo $syspid > /tmp/chkvpn.pid
chknum=0
chksys=0
while [ "1" == "1" ]; do
	chknum=$((chknum+1))
	[ ! -f /tmp/test.chkvpn ] && touch /tmp/test.chkvpn
	prog='sysmonitor'
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
				#if [ "$i" == "sysmonitor" ] && [ "$chknum" -ge 60 ]; then
				if [ "$chknum" -ge 60 ]; then
					chknum=0
					if [ ! -f /tmp/test.$i ]; then	
						killall $progsh
					else
						rm /tmp/test.$i
						if [ "$(pgrep -f $progsh|wc -l)" -gt 1 ]; then
							chksys=$((chksys+1))
						else
							chksys=0
						fi
						[ "$chksys" -ge 30 ] && killall $progsh	
					fi
				fi
				;;
			*)
				killall $progsh
				echo 0 > $progpid
				;;
		esac	
	done
	[ $(cat /tmp/delay.list|grep chkprog|wc -l) == 0 ] && $APP_PATH/sysapp.sh chkprog
	if [ -f /tmp/delay.sign ]; then
		while read i
		do
			prog=$(echo $i|cut -d'=' -f2)
			[ -n $(echo $prog|cut -d' ' -f2) ] && prog=$(echo $prog|cut -d' ' -f2)
			sed -i "/$prog/d" /tmp/delay.list
			echo $i >> /tmp/delay.list
		done < /tmp/delay.sign
		rm /tmp/delay.sign
	fi
	if [ -f /tmp/delay.list ]; then
		touch /tmp/delay.tmp
		while read line
		do
   			num=$(echo $line|cut -d'=' -f1)
			prog=$(echo $line|cut -d'=' -f2-)
			if [ "$num" -gt 0 ];  then
				num=$((num-1))
				tmp=$num'='$prog
				echo $tmp >> /tmp/delay.tmp
			else
			[ "$num" == 0 ] && $prog &
			fi
		done < /tmp/delay.list
		mv /tmp/delay.tmp /tmp/delay.list	
	fi
	[ ! -n "$(pgrep -f next_vpn)" ] && [ -f /tmp/next_vpn.run ] && rm /tmp/next_vpn.run
	[ -f /etc/init.d/lighttpd ] && [ ! -n "$(pgrep -f lighttpd)" ] && {
		/etc/init.d/uhttpd stop
		echo '1-/etc/init.d/lighttpd start' >> /tmp/delay.sign
		echo '2-/etc/init.d/uhttpd start' >> /tmp/delay.sign
		}
	chk_sign regvpn.sign reg_vpn
	[ ! -f /tmp/chkvpn.run ] && sys_exit
	[ "$(cat /tmp/chkvpn.pid)" -gt 1 ] && sys_exit
	sleep 1
done
