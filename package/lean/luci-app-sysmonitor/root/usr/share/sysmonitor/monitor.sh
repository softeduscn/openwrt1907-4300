#!/bin/bash

[ "$(uci get sysmonitor.sysmonitor.enable)" == 0 ] && exit
[ -n "$(pgrep -f sysmonitor.sh)" ] && exit
[ -f /tmp/sysmonitor.run ] && exit
[ "$(cat /tmp/sysmonitor.pid)" != 0 ] && exit

NAME=sysmonitor
APP_PATH=/usr/share/$NAME
$APP_PATH/sysmonitor.sh &

