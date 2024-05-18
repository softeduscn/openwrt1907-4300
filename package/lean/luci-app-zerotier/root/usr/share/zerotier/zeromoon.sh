#!/bin/sh

[ $(uci get zerotier.sample_config.enabled) == 0 ] && exit
if [ "$(ps -w | grep -v grep | grep zeromoon.sh | wc -l)" -gt 2 ]; then
	exit 1
fi
while [ "1" == "1" ]; do #死循环
	sleep 3
	if [ $(ps -w|grep zerotier-one|grep -v grep|wc -l) -gt 0 ]; then
		zeromoon=$(uci get zerotier.sample_config.moon)
		for i in $zeromoon
		do
			zerotier-cli orbit "$i" "$i"
		done
		exit
	fi
done

