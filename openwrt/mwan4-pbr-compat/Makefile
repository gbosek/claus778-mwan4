include $(TOPDIR)/rules.mk

PKG_NAME:=mwan4-pbr-compat
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=MWAN4 Community

include $(INCLUDE_DIR)/package.mk

define Package/mwan4-pbr-compat
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Optional PBR compatibility diagnostics for Rust mwan4 ECMP
  DEPENDS:=+pbr +ip-full +nftables-json
  PKGARCH:=all
endef

define Package/mwan4-pbr-compat/description
  Read-only checks for standalone PBR with the Rust ECMP backend.
  No PBR package, services, or rules are enabled by the core mwan4 package.
endef

define Package/mwan4-pbr-compat/install
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/usr/libexec/mwan4-pbr-compat $(1)/usr/libexec/mwan4-pbr-compat
endef

$(eval $(call BuildPackage,mwan4-pbr-compat))
