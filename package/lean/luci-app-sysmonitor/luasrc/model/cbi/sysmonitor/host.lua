
local appname = "sysmonitor"
bin = require "nixio".bin
fs = require "nixio.fs"
sys = require "luci.sys"
uci = require"luci.model.uci".cursor()
util = require "luci.util"
datatypes = require "luci.cbi.datatypes"
jsonc = require "luci.jsonc"
i18n = require "luci.i18n"

function url(...)
	local url = string.format("admin/sys/%s", appname)
	local args = { ... }
	for i, v in pairs(args) do
		if v ~= "" then
			url = url .. "/" .. v
		end
	end
	return require "luci.dispatcher".build_url(url)
end

function is_js_luci()
	return sys.call('[ -f "/www/luci-static/resources/uci.js" ]') == 0
end

function set_apply_on_parse(map)
	if is_js_luci() == true then
		map.apply_on_parse = false
		map.on_after_apply = function(self)
			if self.redirect then
				os.execute("sleep 1")
				luci.http.redirect(self.redirect)
			end
		end
	end
end
n = Map(appname,translate("VPN Nodes"))
n:append(Template("sysmonitor/vpn"))

m = Map(appname,translate("HOST Settings"))
set_apply_on_parse(m)

s = m:section(TypedSection, "sysmonitor", "")
s.description = '<table><style>.button1 {-webkit-transition-duration: 0.4s;transition-duration: 0.4s;padding: 1px 3px;text-align: center;background-color: white;color: black;border: 2px solid #4CAF50;border-radius:5px;}.button1:hover {background-color: #4CAF50;color: white;}.button1 {font-size: 11px;}</style><tr><td><button class="button1"  title="Update Hostnames"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=UpdateHOST&sys1=&redir=hosts" target="_blank">'..translate("UpdateHOST")..'</a></button> <button class="button1"  title="Goto Hostnames"><a href="/cgi-bin/luci/admin/network/hosts" target="_blank"> ' .. translate("Hostnames") .. ' </a></button></td></tr></table>'
s.anonymous = true

s = m:section(TypedSection, "host_list", "", translate(""))
s.addremove = true
s.anonymous = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = url("host", "%s")
function s.create(e, t)
	local id = TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(id))
end

o = s:option(Value, "hostname", translate("Hostname"))
o.width = "auto"
o.rmempty = false

o = s:option(Value, "hostip", translate("HOST ip"))
o.datatype = "or(host)"
o.width = "auto"
o.rmempty = true


local apply = luci.http.formvalue("cbi.apply")
if apply then
    luci.sys.exec("touch /tmp/regvpn.sign")
end
return n,m
