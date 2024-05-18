
local m, s
local global = 'sysmonitor'
local uci = luci.model.uci.cursor()
ip = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh getip")
m = Map("sysmonitor",translate("System Status"))
m:append(Template("sysmonitor/status"))

n = Map("sysmonitor",translate("VPN Nodes"))
n:append(Template("sysmonitor/service"))

s = n:section(TypedSection, "sysmonitor", translate("System Settings"))
s.anonymous = true

--o=s:option(Flag,"enable", translate("Enable"))
--o.rmempty=false

--o=s:option(Flag,"vpnenable", translate("VPN Enable"))
--o.rmempty=false

if nixio.fs.access("/etc/init.d/ddns") then
o=s:option(Flag,"ddns", translate("DDNS Enable"))
o.rmempty=false
end

if ( nixio.fs.access("/etc/init.d/mosdns") or nixio.fs.access("/etc/init.d/smartdns") ) then
o = s:option(Value, "dns", translate("Select DNS"))
if nixio.fs.access("/etc/init.d/mosdns") then
o:value("MosDNS")
end
if nixio.fs.access("/etc/init.d/smartdns") then
o:value("SmartDNS")
end
o:value("NULL", translate("NULL"))
o.default = "MosDNS"
o.rmempty = false
end

if nixio.fs.access("/etc/init.d/ipsec") then
o=s:option(Flag,"ipsec", translate("IPSEC Enable"))
o.rmempty=false
end

if nixio.fs.access("/etc/init.d/luci-app-pptp-server") then
o=s:option(Flag,"pptp", translate("PPTP Enable"))
o.rmempty=false
end

o = s:option(Value, "gatewayip", translate("Home IP Address"))
--o.description = translate("IP for Home(192.168.1.1)")
o.default = "192.168.1.1"
o.datatype = "or(host)"
o.rmempty = false

--o = s:option(Value, translate("firmware"), translate("Firmware Address"))
--o.description = translate("Firmeware download Address)")
--o.default = "https://github.com/softeduscn/Actions-openwrt1907-4300/releases/download/WNDR-4300/openwrt-ar71xx-nand-wndr4300-squashfs-sysupgrade.tar"
--o.rmempty = false

o = s:option(DynamicList, "dnslist", translate("DNS List"))
o.datatype = "or(host)"
o.rmempty = true

--o = s:option(DynamicList, "vpn", translate("VPN List"))
--o.datatype = "or(host)"
--o.rmempty = false

local apply = luci.http.formvalue("cbi.apply")
if apply then
	luci.sys.exec("touch /tmp/network.sign")
end

return m, n