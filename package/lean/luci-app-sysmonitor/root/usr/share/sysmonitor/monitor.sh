#!/bin/bash

[ "$(uci get sysmonitor.sysmonitor.enable)" == 0 ] && exit
[ "$(pgrep -f sysmonitor.sh|wc -l)" == 0 ] && echo 0 > /tmp/sysmonitor.pid
[ -f /tmp/sysmonitor.run ] && exit

NAME=sysmonitor
APP_PATH=/usr/share/$NAME
$APP_PATH/sysmonitor.sh &

