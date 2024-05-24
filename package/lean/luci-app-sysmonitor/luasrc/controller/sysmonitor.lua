-- Copyright (C) 2017
-- Licensed to the public under the GNU General Public License v3.

module("luci.controller.sysmonitor", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/sysmonitor") then
		return
	end
	entry({"admin", "sys"}, firstchild(), "SYS", 10).dependent = false
   	entry({"admin", "sys","sysmonitor"}, alias("admin", "sys","sysmonitor", "settings"),_("SYSMonitor"), 20).dependent = false
	entry({"admin", "sys", "sysmonitor","settings"}, cbi("sysmonitor/setup"), _("System Settings"), 30).dependent = false
	entry({"admin", "sys", "sysmonitor", "general"}, cbi("sysmonitor/general"),_("General Settings"), 40).leaf = true
	entry({"admin", "sys", "sysmonitor", "host"},cbi("sysmonitor/host"),_("Host"), 50).leaf = true
	entry({"admin", "sys", "sysmonitor", "ddns"}, cbi("/sysmonitor/ddns"), _("DDNS"), 60).leaf = true
	entry({"admin", "sys", "sysmonitor", "wgusers"},form("sysmonitor/wgusers"),_("WGusers"), 70).leaf = false
	entry({"admin", "sys", "sysmonitor", "update"}, form("sysmonitor/filetransfer"),_("Upload"), 80).leaf = false
	entry({"admin", "sys", "sysmonitor", "log"},form("sysmonitor/log"),_("Log"), 90).leaf = true

	entry({"admin", "sys", "sysmonitor", "wanip_status"}, call("action_wanip_status"))
	entry({"admin", "sys", "sysmonitor", "lanip_status"}, call("action_lanip_status"))
	entry({"admin", "sys", "sysmonitor", "wireguard_status"}, call("action_wireguard_status"))
	entry({"admin", "sys", "sysmonitor", "vpn_status"}, call("action_vpn_status"))
	entry({"admin", "sys", "sysmonitor", "prog_status"}, call("action_prog_status"))
	entry({"admin", "sys", "sysmonitor", "service_button"}, call("service_button"))
	entry({"admin", "sys", "sysmonitor", "hosts"}, call("hosts"))
	entry({"admin", "sys", "sysmonitor", "sysmenu"}, call("sysmenu"))
	entry({"admin", "sys", "sysmonitor", "sysmenu1"}, call("sysmenu1"))

	entry({"admin", "sys", "sysmonitor", "get_log"}, call("get_log"))
	entry({"admin", "sys", "sysmonitor", "clear_log"}, call("clear_log"))
	entry({"admin", "sys", "sysmonitor", "wg_users"}, call("wg_users"))
	entry({"admin", "sys", "sysmonitor", "vpnlist"}, call("vpnlist"))
	entry({"admin", "sys", "sysmonitor", "proglist"}, call("proglist"))
end

function action_vpn_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		vpn_title = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton vpnstitle");
		vpn_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton vpns")
	})
end

function action_wanip_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
	wanip_title=luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton wantitle");
	wanip_state=luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton wan")
	})
end

function action_lanip_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		lanip_title = '';
		lanip_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton lan")
	})
end

function action_prog_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		prog_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton prog")
	})
end

function proglist()
	luci.http.write(luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton prog_list"))
end

function action_wireguard_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		wireguard_title = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton wg_title");
		wireguard_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton wg_state")
	})
end

function get_log()
	luci.http.write(luci.sys.exec("[ -f '/var/log/sysmonitor.log' ] && cat /var/log/sysmonitor.log"))
end

function clear_log()
	luci.sys.exec("echo '' > /var/log/sysmonitor.log")
	luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor","log"))
end

function wg_users()
	luci.http.write(luci.sys.exec("[ -f '/var/log/wg_users' ] && cat /var/log/wg_users"))
end

function get_users()
    luci.http.write(luci.sys.exec(
                        "[ -f '/var/log/ipsec_users' ] && cat /var/log/ipsec_users"))
end

function vpnlist()
	luci.http.write(luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton vpn_list"))
end

function hosts()
	luci.http.redirect(luci.dispatcher.build_url("admin", "network", "hosts"))
end

function sysmenu()
	sys=luci.http.formvalue("sys")
	redir=luci.http.formvalue("redir")
	luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor", redir))
	luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysmenu "..sys)
end

function sysmenu1()
	sys=luci.http.formvalue("sys")
	sys1=luci.http.formvalue("sys1")
	redir=luci.http.formvalue("redir")
	luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor", redir))
	luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysmenu "..sys.." "..sys1)
end