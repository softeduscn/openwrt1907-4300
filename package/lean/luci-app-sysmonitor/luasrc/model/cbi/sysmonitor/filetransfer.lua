local fs = require "luci.fs"
local http = luci.http
local ip = luci.sys.exec("uci get sysmonitor.sysmonitor.firmware|cut -d'/' -f1-5")

ful = SimpleForm("upload", translate("Upload"), nil)
ful.reset = false
ful.submit = false

sul = ful:section(SimpleSection, "", translate("Upload file to '/tmp/upload/'"))
fu = sul:option(FileUpload, "")
fu.template = "sysmonitor/other_upload"
um = sul:option(DummyValue, "", nil)
um.template = "sysmonitor/other_dvalue"

local dir, fd
dir = "/tmp/upload/"
nixio.fs.mkdir(dir)
http.setfilehandler(
	function(meta, chunk, eof)
		if not fd then
			if not meta then return end

			if	meta and chunk then fd = nixio.open(dir .. meta.file, "w") end

			if not fd then
				um.value = translate("Create upload file error.")
				return
			end
		end
		if chunk and fd then
			fd:write(chunk)
		end
		if eof and fd then
			fd:close()
			fd = nil
			um.value = translate("File saved to") .. ' "/tmp/upload/' .. meta.file .. '"'
		end
	end
)

if luci.http.formvalue("upload") then
	local f = luci.http.formvalue("ulfile")
	if #f <= 0 then
		um.value = translate("No specify upload file.")
	end
end

local function getSizeStr(size)
	local i = 0
	local byteUnits = {' kB', ' MB', ' GB', ' TB'}
	repeat
		size = size / 1024
		i = i + 1
	until(size <= 1024)
    return string.format("%.1f", size) .. byteUnits[i]
end

local inits, attr = {}
for i, f in ipairs(fs.glob("/tmp/upload/*")) do
	attr = fs.stat(f)
	if attr then
		inits[i] = {}
		inits[i].name = fs.basename(f)
		inits[i].mtime = os.date("%Y-%m-%d %H:%M:%S", attr.mtime)
		inits[i].modestr = attr.modestr
		inits[i].size = getSizeStr(attr.size)
		inits[i].remove = 0
		inits[i].install = false
		inits[i].keeps = true
	end
end

--form1 = SimpleForm("firmware", translate("Firmware"), nil)
--form1.reset = false
--form1.submit = false
--form1.description ='<table width="70%" cellspacing="10"><style>.button1 {-webkit-transition-duration: 0.4s;transition-duration: 0.4s;padding: 1px 3px;text-align: center;background-color: white;color: black;border: 2px solid #4CAF50;border-radius:5px;}.button1:hover {background-color: #4CAF50;color: white;}.button1 {font-size: 11px;}</style><tr><td width="21%" title="Firmware"><b>'.. translate("Download & Upgrade") ..'</b></td><td><b><button class="button1"><a href="firmware">' .. translate("Download Firmware") .. '</a></button></b></td></tr></table>'

form = SimpleForm("filelist", translate("Upload file list"), nil)
form.reset = false
form.submit = false

tb = form:section(Table, inits)
nm = tb:option(DummyValue, "name", translate("File name"))
mt = tb:option(DummyValue, "mtime", translate("Modify time"))
ms = tb:option(DummyValue, "modestr", translate("Attributes"))
sz = tb:option(DummyValue, "size", translate("Size"))
btnrm = tb:option(Button, "remove", translate("Remove"))
btnrm.render = function(self, section, scope)
	self.inputstyle = "remove"
	Button.render(self, section, scope)
end

btnrm.write = function(self, section)
	local v = luci.fs.unlink("/tmp/upload/" .. luci.fs.basename(inits[section].name))
	if v then 
		table.remove(inits, section)
		luci.sys.exec("/usr/share/sysmonitor/sysapp.sh stopdl")
	end
	return v
end

function Ispasswall(name)
	return name == "passwall"
end

function Isshadowsocksr(name)
	return name == "shadowsocksr"
end

function IsUpdateFile(name)
	name = name or ""
	local ext = string.lower(string.sub(name, -14, -1))
	if ( ext == "sysupgrade.bin" ) then
	return ext == "sysupgrade.bin"
	end
	if ( ext == "sysupgrade.tar" ) then
	return ext == "sysupgrade.tar"
	end
end

btnis = tb:option(Button, "install", translate("Update"))
btnis.template = "sysmonitor/other_button"
btnis.render = function(self, section, scope)
	if not inits[section] then return false end
	if Ispasswall(inits[section].name) or  Isshadowsocksr(inits[section].name)  then
		scope.display = ""
	elseif IsUpdateFile(inits[section].name) then
		scope.display = ""
	else
		scope.display = "none"
	end
	self.inputstyle = "apply"
	Button.render(self, section, scope)
end

btnis.write = function(self, section)
	if Ispasswall(inits[section].name) or Isshadowsocksr(inits[section].name) then
		luci.sys.exec("echo 'Update "..inits[section].name.." to /etc/config' >/var/log/sysmonitor.log")
		luci.sys.exec("mv /tmp/upload/"..inits[section].name.." /etc/config")
		luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor","log"))
	else
		luci.sys.exec("echo 'Upgrade Firmware' >/var/log/sysmonitor.log")
		luci.sys.exec("echo '------------------------------------------------------------------------------------------------------' >>/var/log/sysmonitor.log")
		luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor","log"))
		tmp="cbid.table."..section..".keeps"
		local sysupgrade  = luci.http.formvalue(tmp)	
		if sysupgrade then
			sysupgrade='sysupgrade -c /tmp/upload/'..inits[section].name
		else
			sysupgrade='sysupgrade -n /tmp/upload/'..inits[section].name
			
		end
		luci.sys.exec("echo "..sysupgrade.." >>/var/log/sysmonitor.log")
		luci.sys.exec(sysupgrade)
	end
end

kp = tb:option(Flag, "keeps", translate("Keeps"))
kp.template = "sysmonitor/other_keeps"
kp.render = function(self, section, scope)
	if not inits[section] then return false end
	if Ispasswall(inits[section].name) or  Isshadowsocksr(inits[section].name)  then
		scope.display = ""
	elseif IsUpdateFile(inits[section].name) then
		scope.display = ""
	else
		scope.display = "none"
	end
	Flag.render(self, section, scope)
end

return ful, form
