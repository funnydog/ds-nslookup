include $(TOPDIR)/rules.mk

PKG_NAME:=ds-nslookup
PKG_VERSION:=0.0.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/funnydog/ds-nslookup.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_SOURCE)
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_MAINTAINER:=funnydog
PKG_LICENSE:=GPL-2.0

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ds-nslookup
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Dead Simple nslookup which aims to do things in the right way (tm)
endef

define Package/ds-nslookup/description
	Dead Simple nslookup which queries the dns using libresolv
endef

define Package/ds-nslookup/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nslookup $(1)/usr/bin/
endef

$(eval $(call BuildPackage,ds-nslookup))
