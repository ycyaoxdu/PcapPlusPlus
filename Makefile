ifeq ($(wildcard mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include mk/platform.mk

COMMONPP_HOME        := Common++
PACKETPP_HOME        := Packet++
PCAPPP_HOME          := Pcap++
EXAMPLE_DPDK1        := Examples/DpdkExample-FilterTraffic
EXAMPLE_PF_RING1     := Examples/PfRingExample-FilterTraffic
EXAMPLE_PROTOCOL_ANALYSIS    := Examples/ProtocolAnalysis
EXAMPLE_DPDK2        := Examples/DpdkBridge
EXAMPLE_KNI_PONG     := Examples/KniPong
EXAMPLE_PCAP_PRINT   := Examples/PcapPrinter
EXAMPLE_PCAPSPLITTER := Examples/PcapSplitter
EXAMPLE_PCAPSEARCH   := Examples/PcapSearch


UNAME := $(shell uname)

.SILENT:

all: libs
	@cd $(EXAMPLE_PROTOCOL_ANALYSIS)         && $(MAKE) ProtocolAnalysis
	@cd $(EXAMPLE_PCAP_PRINT)        && $(MAKE) PcapPrinter
	@cd $(EXAMPLE_PCAPSPLITTER)      && $(MAKE) PcapSplitter
	@cd $(EXAMPLE_PCAPSEARCH)        && $(MAKE) PcapSearch
ifdef USE_DPDK
	@cd $(EXAMPLE_DPDK1)             && $(MAKE) DpdkTrafficFilter
	@cd $(EXAMPLE_DPDK2)             && $(MAKE) DpdkBridge
	@cd $(EXAMPLE_KNI_PONG)          && $(MAKE) KniPong
endif
ifdef PF_RING_HOME
	@cd $(EXAMPLE_PF_RING1)          && $(MAKE) PfRingTrafficFilter
endif

	@$(MKDIR) -p Dist/examples
	$(CP) $(EXAMPLE_PROTOCOL_ANALYSIS)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAP_PRINT)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAPSPLITTER)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAPSEARCH)/Bin/* ./Dist/examples
ifdef USE_DPDK
	$(CP) $(EXAMPLE_DPDK1)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_DPDK2)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_KNI_PONG)/Bin/* ./Dist/examples
endif
ifdef PF_RING_HOME
	$(CP) $(EXAMPLE_PF_RING1)/Bin/* ./Dist/examples
endif
	@echo Finished successfully building PcapPlusPlus

# PcapPlusPlus libs only
libs:
	@$(RM) -rf Dist
	@cd $(COMMONPP_HOME)             && $(MAKE) all
	@cd $(PACKETPP_HOME)             && $(MAKE) all
	@cd $(PCAPPP_HOME)               && $(MAKE) all
	@$(MKDIR) -p Dist
	@$(MKDIR) -p Dist/header
	@$(CP) $(COMMONPP_HOME)/Lib/Release/* ./Dist
	@$(CP) $(PACKETPP_HOME)/Lib/* ./Dist
	@$(CP) $(PCAPPP_HOME)/Lib/* ./Dist
	@$(CP) $(COMMONPP_HOME)/header/* ./Dist/header
	@$(CP) $(PACKETPP_HOME)/header/* ./Dist/header
	@$(CP) $(PCAPPP_HOME)/header/* ./Dist/header
	@$(MKDIR) -p Dist/mk
	$(CP) mk/PcapPlusPlus.mk ./Dist/mk
	@echo Finished successfully building PcapPlusPlus libs
	@echo ' '


# Clean
clean:
	@cd $(COMMONPP_HOME)             && $(MAKE) clean
	@cd $(PACKETPP_HOME)             && $(MAKE) clean
	@cd $(PCAPPP_HOME)               && $(MAKE) clean
	@cd $(EXAMPLE_PROTOCOL_ANALYSIS)         && $(MAKE) clean
	@cd $(EXAMPLE_PCAP_PRINT)        && $(MAKE) clean
	@cd $(EXAMPLE_PCAPSPLITTER)      && $(MAKE) clean
	@cd $(EXAMPLE_PCAPSEARCH)        && $(MAKE) clean
ifdef USE_DPDK
	@cd $(EXAMPLE_DPDK1)             && $(MAKE) clean
	@cd $(EXAMPLE_DPDK2)             && $(MAKE) clean
	@cd $(EXAMPLE_KNI_PONG)          && $(MAKE) clean
endif
ifdef PF_RING_HOME
	@cd $(EXAMPLE_PF_RING1)          && $(MAKE) clean
endif

	@$(RM) -rf Dist
	@echo Finished successfully cleaning PcapPlusPlus

ifndef WIN32
INSTALL_DIR=Dist

# Install
install: | $(INSTALL_DIR)
	@cd Dist && ../mk/$(INSTALL_SCRIPT)
	@echo 'Installation complete!'

# Uninstall
uninstall: | $(INSTALL_DIR)
	@cd Dist && ../mk/$(UNINSTALL_SCRIPT)
	@echo 'Uninstallation complete!'

$(INSTALL_DIR):
	@echo 'Please run make all first' && exit 1

endif
