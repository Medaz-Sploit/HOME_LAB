include $(TOPDIR)/rules.mk

PKG_NAME:=packet-interceptor
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/packet-interceptor
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Educational Packet Interceptor
  DEPENDS:=+libpcap +libnetfilter-queue +iptables-mod-nfqueue +kmod-nfnetlink-queue
endef

define Package/packet-interceptor/description
  Educational packet interception tool for network analysis in lab environments
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/packet-interceptor/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packet-interceptor $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/packet-interceptor.init $(1)/etc/init.d/packet-interceptor
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/packet-interceptor.config $(1)/etc/config/packet-interceptor
endef

$(eval $(call BuildPackage,packet-interceptor))