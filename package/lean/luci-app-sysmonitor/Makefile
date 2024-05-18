# Copyright (C) 2016 Openwrt.org
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for luci-app-sysmonitor
LUCI_DEPENDS:=+ttyd +kmod-tcp-bbr +qrencode +luci-lib-fs +luci-proto-ipv6 +wget +ip6tables +libip6tc +kmod-ipt-nat6 +odhcp6c +bind-dig
LUCI_PKGARCH:=all
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
