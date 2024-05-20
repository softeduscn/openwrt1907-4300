luci.sys.exec("/usr/share/sysmonitor/sysapp.sh getddnsip")
local appname = "sysmonitor"
bin = require "nixio".bin
fs = require "nixio.fs"
sys = require "luci.sys"
uci = require"luci.model.uci".cursor()
util = require "luci.util"
datatypes = require "luci.cbi.datatypes"
jsonc = require "luci.jsonc"
i18n = require "luci.i18n"

ddns = luci.sys.exec("uci get sysmonitor.sysmonitor.ddns")

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


m = Map(appname,translate("DDNS Settings"))
set_apply_on_parse(m)

s = m:section(TypedSection, "sysmonitor", "")
s.description ="<font color='red'>" .. translate("DDNS set ip6 first,then set ip4, otherwise the ip4 is replaced by vpn address") .. "</font>"
s.anonymous = true

o=s:option(Flag,"ddns", translate("DDNS Enable"))
o.rmempty=false

o=s:option(Flag,"ddnslog", translate("DDNSLOG Enable"))
o.rmempty=false

s = m:section(TypedSection, "ddns_list", "", "")
if tonumber(ddns) == 1 then
s.description = '<table><style>.button1 {-webkit-transition-duration: 0.4s;transition-duration: 0.4s;padding: 1px 3px;text-align: center;background-color: white;color: black;border: 2px solid #4CAF50;border-radius:5px;}.button1:hover {background-color: #4CAF50;color: white;}.button1 {font-size: 11px;}</style><tr><td title="Update DDNS"><button class="button1"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sys?sys=UpdateDDNS&redir=ddns">' .. translate("UpdateDDNS") .. '</a></button></td></tr></table>'
end
s.addremove = true
s.anonymous = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = url("ddns", "%s")
function s.create(e, t)
	local id = TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(id))
end

o = s:option(Value, "hostname", translate("Hostname"))
o.default = "ddnsfree.com"
o.width = "auto"
o.rmempty = false
--o.validate = function(self, value, t)
--	if value then
--		local count = 0
--		m.uci:foreach(appname, "ddns_list", function(e)
--			if e[".name"] ~= t and e["hostname"] == value then
--				count = count + 1
--			end
--		end)
--		if count > 0 then
--			return nil, translate("This hostname already exists, please change a new hostname.")
--		end
--		return value
--	end
--end

o = s:option(Value, "iptype", translate("ip4/ip6"))
o.default = "ip6"
o.width = 10
o.rmempty = false


o = s:option(Value, "url", translate("DDNS update URL"))
o.default = "http://api.dynu.com/nic/update"
o.width = "auto"
o.rmempty = false

o = s:option(Value, "getip", translate("Get ip address"))
o.width = "auto"
o.rmempty = false


o = s:option(Value, "username", translate("Username"))
o.default = "sqmshcn"
o.width = "auto"
o.rmempty = false

o = s:option(Value, "password", translate("Password"))
o.default = "dynuddns"
o.width = "auto"
o.rmempty = false

o = s:option(Value, "ipaddr", translate("IPaddress"))
o.width = "auto"
o.rmempty = true

return m
