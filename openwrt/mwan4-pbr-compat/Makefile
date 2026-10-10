include $(TOPDIR)/rules.mk

PKG_NAME:=mwan4-pbr-compat
PKG_VERSION:=0.2.2
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=MWAN4 Community

include $(INCLUDE_DIR)/package.mk

define Package/mwan4-pbr-compat
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Optional PBR diagnostics and strategy adapter for Rust mwan4 ECMP
  DEPENDS:=+mwan4 +pbr +ip-full +nftables-json +ucode +ucode-mod-fs +ucode-mod-uci +ucode-mod-ubus
  PKGARCH:=all
endef

define Package/mwan4-pbr-compat/description
  Standalone PBR diagnostics and an opt-in PBR 1.2.3 strategy consumer API.
  No PBR package, services, or rules are enabled by the core mwan4 package.
endef

define Package/mwan4-pbr-compat/install
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/usr/libexec/mwan4-pbr-compat $(1)/usr/libexec/mwan4-pbr-compat
	$(INSTALL_DIR) $(1)/lib/mwan4
	$(INSTALL_DATA) ./files/lib/mwan4/*.uc $(1)/lib/mwan4/
endef

$(eval $(call BuildPackage,mwan4-pbr-compat))
