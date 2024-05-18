module("luci.controller.zerotier",package.seeall)

function index()
	if not nixio.fs.access("/etc/config/zerotier") then
		return
	end

	entry({"admin","vpn"}, firstchild(), "VPN", 45).dependent = false

	entry({"admin", "vpn", "zerotier"},firstchild(), _("ZeroTier")).dependent = false

	entry({"admin", "vpn", "zerotier", "general"}, cbi("zerotier/settings"), _("Base Setting"), 1)
	entry({"admin", "vpn", "zerotier", "log"}, form("zerotier/info"), _("Interface Info"), 2)

	entry({"admin", "vpn", "zerotier", "status"}, call("act_status"))
	entry({"admin", "vpn", "zerotier", "moonstatus"}, call("act_moonstatus"))
	entry({"admin", "vpn", "zerotier", "moon"}, call("act_moon"))
end

function act_status()
	local e={}
	e.running=luci.sys.call("pgrep /usr/bin/zerotier-one >/dev/null")==0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
function act_moonstatus()
	local e={}
	e.running=luci.sys.exec("zerotier-cli peers|grep MOON")
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
function act_moon()
	luci.http.redirect(luci.dispatcher.build_url("admin", "vpn", "zerotier","general"))
	luci.sys.exec("uci set zerotier.sample_config.enabled=1 && uci commit zerotier")
	luci.sys.exec("/etc/init.d/zerotier reload")
end