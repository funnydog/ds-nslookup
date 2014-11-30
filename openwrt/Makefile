include $(TOPDIR)/rules.mk

PKG_NAME:=ds-nslookup
PKG_VERSION:=0.0.1
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/funnydog/ds-nslookup.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=HEAD
PKG_MAINTAINER:=funnydog
PKG_LICENSE:=MIT

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ds-nslookup
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Dead Simple nslookup
endef

define Build/compile
	make
endef

define Package/ds-nslookup/description
	Dead Simple nslookup that queries the dns using libresolv
endef

define Package/ds-nslookup/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nslookup $(1)/usr/bin/
endef

$(eval $(call BuildPackage,ds-nslookup))
