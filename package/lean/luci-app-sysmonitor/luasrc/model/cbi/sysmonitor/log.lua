luci.sys.exec("/usr/share/sysmonitor/sysapp.sh logup")
f = SimpleForm("sysmonitor")
f.reset = false
f.submit = false
f:append(Template("sysmonitor/log"))
return f
