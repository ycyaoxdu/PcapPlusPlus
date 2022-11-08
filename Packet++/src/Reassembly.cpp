#define LOG_MODULE PacketLogModuleReassembly

#include "Reassembly.h"
#include "BgpLayer.h"
#include "GreLayer.h"
#include "GtpLayer.h"
#include "HttpLayer.h"
#include "IPReassembly.h"
#include "IPSecLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "IpAddress.h"
#include "L2tpLayer.h"
#include "LRUList.h"
#include "Layer.h"
#include "Logger.h"
#include "OspfLayer.h"
#include "Packet.h"
#include "PcapPlusPlusVersion.h"
#include "ProtocolType.h"
#include "RipLayer.h"
#include "SSLLayer.h"
#include "SctpLayer.h"
#include "SystemUtils.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "getopt.h"
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stack>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <unistd.h>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

// add the object of tcpReassembly
ReassemblyStatus Reassemble(IPReassembly *ipReassembly, IPReassembly::ReassemblyStatus *statusPtr,
							std::queue<pcpp::RawPacket> *quePointer, Packet *parsedPacket, void *UserCookie,
							OnMessageHandled OnMessageReadyCallback, TcpReassembly &tcpReassembly)
{
	PCPP_LOG_DEBUG("stage reassemble: start packet reassemble and analysis");

	bool isIPv4Packet = false;
	bool isIPv6Packet = false;

	if (parsedPacket == NULL)
	{
		PCPP_LOG_DEBUG("stage reassemble: Input empty pointer to Packet");
		return Invalid;
	}

	Layer *next = findLayer(parsedPacket);
	if (next == NULL)
	{
		PCPP_LOG_DEBUG("stage reassemble: non-ip packet!");
		return Invalid;
	}

	if (findLayer(parsedPacket)->getProtocol() == IPv4)
	{
		PCPP_LOG_DEBUG("stage reassemble: IPv4 parsed");
		isIPv4Packet = true;
	}
	else if (findLayer(parsedPacket)->getProtocol() == IPv6)
	{
		PCPP_LOG_DEBUG("stage reassemble: IPv6 parsed");
		isIPv6Packet = true;
	}
	else
	{
		// non-ip packet should not be passed in
		PCPP_LOG_DEBUG("stage reassemble: not-ip packet!");
		return Invalid;
	}

	// process the packet in the IP reassembly mechanism
	IPReassembly::ReassemblyStatus status = *statusPtr;

	PCPP_LOG_DEBUG("stage ip reassembly:start reassemble ip packet");
	Packet *result = ipReassembly->processPacket(parsedPacket, status);
	PCPP_LOG_DEBUG("stage ip reassembly:finish reassemble ip packet");

	// write fragment/packet to file if:
	// - packet is fully reassembled (status of REASSEMBLED)
	// - packet isn't a fragment or isn't an IP packet and the user asked to write all packets to output
	if (status == pcpp::IPReassembly::REASSEMBLED ||
		((status == pcpp::IPReassembly::NON_IP_PACKET || status == pcpp::IPReassembly::NON_FRAGMENT)))
	{
		PCPP_LOG_DEBUG("stage ip analysis: start to analysis complete ip packet(de-fragmented)");

		// TupleName is used to identify which file the packet will store in
		std::string TupleName = "";
		// the protocol name of "current" layer
		std::string protoname = "ip";
		// define ip
		pcpp::IPAddress IpSrc, IpDst;

		pcpp::Layer *ipLayer = NULL;

		if (isIPv4Packet)
		{
			pcpp::IPv4Layer *ipv4Layer = getv4(result);
			IpSrc = ipv4Layer->getSrcIPAddress();
			IpDst = ipv4Layer->getDstIPAddress();
			ipv4Layer->parseNextLayer();
			ipLayer = ipv4Layer;
		}
		else if (isIPv6Packet)
		{
			pcpp::IPv6Layer *ipv6Layer = getv6(result);
			IpSrc = ipv6Layer->getSrcIPAddress();
			IpDst = ipv6Layer->getDstIPAddress();
			ipv6Layer->parseNextLayer();
			ipLayer = ipv6Layer;
		}

		// parse next layer
		// any unknow protocol is payload
		Layer *nextLayer = ipLayer->getNextLayer();
		if (nextLayer == NULL)
		{
			PCPP_LOG_DEBUG("stage ip analysis: get nextlayer of nullptr");
			// invalid data
			return Invalid;
		}

		// switch statement
		switch (nextLayer->getProtocol())
		{
		case pcpp::OSPF: {
			// ospf have no payload
			protoname = "ospf";
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

			HandleOspfPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			break;
		}
		case pcpp::AuthenticationHeader: {
			protoname = "authenticationHeader";
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

			AuthenticationHeaderLayer ahlayer(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);
			ahlayer.parseNextLayer();
			nextLayer = ahlayer.getNextLayer();

			// esp handle
			if (nextLayer->getProtocol() == pcpp::ESP)
			{
				protoname = "esp";
				TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

				HandleEspPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			}
			else
			{
				HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			}

			break;
		}
		case pcpp::ESP: {
			// esp handle
			protoname = "esp";
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

			HandleEspPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			break;
		}
		case pcpp::GREv0:
		case pcpp::GREv1:
		case pcpp::GRE: {
			protoname = "gre";
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);
			HandleGrePayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback, quePointer);
			break;
		}
		case pcpp::TCP: {
			// tcp handle

			tcpReassembly.reassemblePacket(result, nextLayer, &IpSrc, &IpDst);
			// HandleTcpPayload(nextLayer, IpSrc, IpDst, result, UserCookie, OnMessageReadyCallback, quePointer);
			break;
		}
		case pcpp::UDP: {
			// udp handle
			HandleUdpPayload(nextLayer, IpSrc, IpDst, result, UserCookie, OnMessageReadyCallback, quePointer);
			break;
		}
		case pcpp::SCTP: {
			// SCTP handle
			HandleSctpPayload(nextLayer, IpSrc, IpDst, result, UserCookie, OnMessageReadyCallback, quePointer);
			break;
		}
		case pcpp::GenericPayload: {
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

			HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			break;
		}
		default: {
			// do nothing, actually every unknow packet is recognized as payload. No packet will go into this
			// branch.
			break;
		}
		}

		PCPP_LOG_DEBUG("stage ip analysis: finished analysis ip packet");
	}
	// update statistics if packet is fully reassembled (status of REASSEMBLED) and
	if (status == pcpp::IPReassembly::REASSEMBLED)
	{
		// free packet
		delete result;
	}

	*statusPtr = status;
	PCPP_LOG_DEBUG("stage reassemble: finished packet reassemble and analysis");
	return Handled;
}

void HandleOspfPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleOspfPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleOspfPayload: passing layer of nullptr to function");
		return;
	}
	OspfLayer ospf(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
	ReassembleMessage(&ospf, tuplename, cookie, OnMessageReadyCallback);
}

void HandleEspPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleEspPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleEspPayload: passing layer of nullptr to function");
		return;
	}
	ESPLayer esp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	esp.parseNextLayer();
	Layer *nextLayer = esp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleEspPayload: nextlayer of nullptr");
		return;
	}

	// ESP层的负载是被加密的，因此next layer都为generic payload
	HandleGenericPayload(nextLayer, tuplename, packet, cookie, OnMessageReadyCallback);
}

void HandleGrePayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	PCPP_LOG_DEBUG("HandleGrePayload: tuplename: " << tuplename);

	// gre : ipv4 ipv6 ppp payload
	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleGrePayload: passing layer of nullptr to function");
		return;
	}

	Layer *nextLayer;
	if (layer->getProtocol() == GREv0)
	{
		GREv0Layer grev0(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		grev0.parseNextLayer();
		nextLayer = grev0.getNextLayer();
	}
	else if (layer->getProtocol() == GREv1)
	{
		GREv1Layer grev1(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		grev1.parseNextLayer();
		nextLayer = grev1.getNextLayer();
	}
	else
	{
		PCPP_LOG_DEBUG("HandleGrePayload: non-gre packet!");
		return;
	}

	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleGrePayload: nextlayer of nullptr");
		return;
	}

	if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
	{
		bool ok = HandleIPPacket(packet, nextLayer, tuplename, quePointer);
		if (!ok)
		{
			PCPP_LOG_DEBUG("HandleGrePayload: HandleIPPacket: failed");
		}
	}
	else if (nextLayer->getProtocol() == pcpp::PPP_PPTP)
	{
		HandlePppPayload(nextLayer, tuplename, packet, cookie, OnMessageReadyCallback, quePointer);
	}
	else if (nextLayer->getProtocol() == pcpp::GenericPayload)
	{
		HandleGenericPayload(nextLayer, tuplename, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleUdpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleUdpPayload: passing layer of nullptr to function");
		return;
	}
	UdpLayer udp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	// calculate 5-tuple name
	std::string protoname = "udp";
	uint16_t PortSrc = udp.getSrcPort();
	uint16_t PortDst = udp.getDstPort();
	std::string TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

	// next layer
	udp.parseNextLayer();
	Layer *nextLayer = udp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleUdpPayload: nextlayer of nullptr");
		return;
	}

	if (nextLayer->getProtocol() == pcpp::L2TP)
	{
		protoname = "l2tp";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleL2tpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback, quePointer);
	}
	else if (nextLayer->getProtocol() == pcpp::RIP)
	{
		// RIP have no next layer.
		protoname = "rip";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleRipPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::GTP)
	{
		protoname = "gtp";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleGtpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback, quePointer);
	}
	else
	{
		PCPP_LOG_DEBUG("HandleUdpPayload: TupleName: " << TupleName);
		HandleGenericPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleTcpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleTcpPayload: passing layer of nullptr to function");
		return;
	}
	TcpLayer tcp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	// calculate 5-tuple name
	std::string protoname = "tcp";
	uint16_t PortSrc = tcp.getSrcPort();
	uint16_t PortDst = tcp.getDstPort();
	std::string TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

	// next layer
	tcp.parseNextLayer();
	Layer *nextLayer = tcp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleTcpPayload: nextlayer of nullptr");
		return;
	}

	if (nextLayer->getProtocol() == pcpp::HTTPRequest || nextLayer->getProtocol() == pcpp::HTTPResponse)
	{
		protoname = "http";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleHttpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::SSL)
	{
		protoname = "ssl";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleSslPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::BGP)
	{
		protoname = "bgp";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleBgpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::GTP)
	{
		protoname = "gtp";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleGtpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback, quePointer);
	}
	else if (nextLayer->getProtocol() == pcpp::GenericPayload)
	{
		PCPP_LOG_DEBUG("HandleTcpPayload: TupleName: " << TupleName);
		HandleGenericPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleSctpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleSctpPayload: passing layer of nullptr to function");
		return;
	}
	SctpLayer sctp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	// calculate 5-tuple name
	std::string protoname = "sctp";
	uint16_t PortSrc = sctp.getSrcPort();
	uint16_t PortDst = sctp.getDstPort();
	std::string TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

	// next layer
	sctp.parseNextLayer();
	Layer *nextLayer = sctp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleSctpPayload: nextlayer of nullptr");
		return;
	}

	if (nextLayer->getProtocol() == pcpp::HTTPRequest || nextLayer->getProtocol() == pcpp::HTTPResponse)
	{
		protoname = "http";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleHttpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::SSL)
	{
		protoname = "ssl";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleSslPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::BGP)
	{
		protoname = "bgp";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleBgpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
	else if (nextLayer->getProtocol() == pcpp::GTP)
	{
		protoname = "gtp";
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

		HandleGtpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback, quePointer);
	}
	else if (nextLayer->getProtocol() == pcpp::GenericPayload)
	{
		PCPP_LOG_DEBUG("HandleSctpPayload: TupleName: " << TupleName);
		HandleGenericPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleRipPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleRipPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleRipPayload: passing layer of nullptr to function");
		return;
	}
	RipLayer rip(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	ReassembleMessage(&rip, tuplename, cookie, OnMessageReadyCallback);
}

void HandleGtpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	PCPP_LOG_DEBUG("HandleGtpPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleGtpPayload: passing layer of nullptr to function");
		return;
	}

	pcpp::GtpV1Layer gtp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	gtp.parseNextLayer();
	Layer *nextLayer = gtp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleGtpPayload: nextlayer of nullptr");
		return;
	}

	if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
	{
		bool ok = HandleIPPacket(packet, nextLayer, tuplename, quePointer);
		if (!ok)
		{
			PCPP_LOG_DEBUG("HandleGtpPayload: HandleIPPacket: failed");
		}
	}
}

void HandlePppPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	PCPP_LOG_DEBUG("HandlePppPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandlePppPayload: passing layer of nullptr to function");
		return;
	}

	pcpp::PPP_PPTPLayer ppp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	ppp.parseNextLayer();
	Layer *nextLayer = ppp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandlePppPayload: nextlayer of nullptr");
		return;
	}

	if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
	{
		bool ok = HandleIPPacket(packet, nextLayer, tuplename, quePointer);
		if (!ok)
		{
			PCPP_LOG_DEBUG("HandlePppPayload: HandleIPPacket: failed");
		}
	}
	else
	{
		HandleGenericPayload(nextLayer, tuplename, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleL2tpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback, std::queue<pcpp::RawPacket> *quePointer)
{
	PCPP_LOG_DEBUG("HandleL2tpPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleL2tpPayload: passing layer of nullptr to function");
		return;
	}
	pcpp::L2tpLayer l2tp(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	l2tp.parseNextLayer();
	Layer *nextLayer = l2tp.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleL2tpPayload: nextlayer of nullptr");
		return;
	}

	HandlePppPayload(nextLayer, tuplename, packet, cookie, OnMessageReadyCallback, quePointer);
}

void HandleBgpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleBgpPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleBgpPayload: passing layer of nullptr to function");
		return;
	}

	BgpLayer *bgp = BgpLayer::parseBgpLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
	ReassembleMessage(&(*bgp), tuplename, cookie, OnMessageReadyCallback);

	switch (bgp->getBgpMessageType())
	{
	case pcpp::BgpLayer::Open: {
		pcpp::BgpOpenMessageLayer bgpOpen =
			pcpp::BgpOpenMessageLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		ReassembleMessage(&bgpOpen, tuplename, cookie, OnMessageReadyCallback);

		break;
	}
	case pcpp::BgpLayer::Update: {
		pcpp::BgpUpdateMessageLayer bgpUpdate =
			pcpp::BgpUpdateMessageLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		ReassembleMessage(&bgpUpdate, tuplename, cookie, OnMessageReadyCallback);

		break;
	}
	case pcpp::BgpLayer::Notification: {
		pcpp::BgpNotificationMessageLayer bgpNotification =
			pcpp::BgpNotificationMessageLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		ReassembleMessage(&bgpNotification, tuplename, cookie, OnMessageReadyCallback);

		break;
	}
	case pcpp::BgpLayer::Keepalive: {
		pcpp::BgpKeepaliveMessageLayer bgpKA =
			pcpp::BgpKeepaliveMessageLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		ReassembleMessage(&bgpKA, tuplename, cookie, OnMessageReadyCallback);

		break;
	}
	case pcpp::BgpLayer::RouteRefresh: {
		pcpp::BgpRouteRefreshMessageLayer bgpRR =
			pcpp::BgpRouteRefreshMessageLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
		ReassembleMessage(&bgpRR, tuplename, cookie, OnMessageReadyCallback);

		break;
	}
	}

	//与SSL类似，单个包中可能包含多条BGP消息，所以需要检查这个BGP包。
	//如果存在，就创建一个新的BGP消息作为下一层，然后继续检查
	//否则就退出

	while (1)
	{
		size_t bgp_header_len = bgp->getHeaderLen();
		size_t bgp_data_len = bgp->getDataLen();
		uint8_t *bgp_data = bgp->getData();

		bgp->parseNextLayer();
		Layer *nextLayer = bgp->getNextLayer();

		if (nextLayer == NULL) //该数据包中不再有BGP消息
		{
			break;
		}
		else //存在BGP消息
		{
			bgp = BgpLayer::parseBgpLayer(bgp_data + bgp_header_len, bgp_data_len - bgp_header_len,
										  layer->getPrevLayer(), packet);
			ReassembleMessage(&(*bgp), tuplename, cookie, OnMessageReadyCallback);
		}
	}
}

void HandleSslPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleSslPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleSslPayload: passing layer of nullptr to function");
		return;
	}

	SSLLayer *ssl = SSLLayer::createSSLMessage(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
	ReassembleMessage(&(*ssl), tuplename, cookie, OnMessageReadyCallback);

	//单个包中可能包含多条SSL记录，所以需要检查这个SSL包。
	//如果存在，就创建一个新的SSL记录，然后继续检查
	//否则就退出

	while (1)
	{
		size_t ssl_header_len = ssl->getHeaderLen();
		size_t ssl_data_len = ssl->getDataLen();
		uint8_t *ssl_data = ssl->getData();

		ssl->parseNextLayer();
		Layer *nextLayer = ssl->getNextLayer();

		if (nextLayer == NULL) //该数据包中不再有SSL记录
		{
			break;
		}
		else //存在SSL记录
		{
			ssl = SSLLayer::createSSLMessage(ssl_data + ssl_header_len, ssl_data_len - ssl_header_len,
											 ssl->getPrevLayer(), packet);
			ReassembleMessage(&(*ssl), tuplename, cookie, OnMessageReadyCallback);
		}
	}
}

void HandleHttpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleHttpPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleHttpPayload: passing layer of nullptr to function");
		return;
	}

	HttpRequestLayer *httpRequest = packet->getLayerOfType<HttpRequestLayer>();
	if (httpRequest != NULL)
	{
		ReassembleMessage(httpRequest, tuplename, cookie, OnMessageReadyCallback);
	}
	else
	{
		HttpResponseLayer *httpResponse = packet->getLayerOfType<HttpResponseLayer>();
		if (httpResponse != NULL)
		{
			ReassembleMessage(httpResponse, tuplename, cookie, OnMessageReadyCallback);
		}
		else
		{
			HandleGenericPayload(layer, tuplename, packet, cookie, OnMessageReadyCallback);
		}
	}
}

void HandleGenericPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
						  OnMessageHandled OnMessageReadyCallback)
{
	PCPP_LOG_DEBUG("HandleGenericPayload: tuplename: " << tuplename);

	if (layer == NULL || packet == NULL)
	{
		PCPP_LOG_DEBUG("HandleGenericPayload: passing layer of nullptr to function");
		return;
	}

	PayloadLayer *payload = new PayloadLayer(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
	ReassemblePayload(payload, tuplename, cookie, OnMessageReadyCallback);
}

bool HandleIPPacket(Packet *packet, Layer *iplayer, std::string tuple, std::queue<pcpp::RawPacket> *quePointer)
{
	PCPP_LOG_DEBUG("HandleIPPacket: tuplename: " << tuple);

	packet->SetTuplename(tuple);

	if (iplayer->getProtocol() == IPv4 || iplayer->getProtocol() == IPv6)
	{
		packet->CountIP();
	}
	else
	{
		PCPP_LOG_DEBUG("HandleIPPacket: accepted a non ip packet");
		return false;
	}

	quePointer->push(*packet->getRawPacket());
	return true;
}

ReassemblyStatus ReassemblePayload(PayloadLayer *payloadlayer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback)
{

	if (payloadlayer == NULL)
	{
		PCPP_LOG_DEBUG("ReassemblePayload: passing layer of nullptr to function");
		return Invalid;
	}

	ReassemblyStatus response = Handled;
	std::string result;
	payloadlayer->packet()->SetTuplename(tuple);

	Layer *layer = payloadlayer;
	layer->setPacket(payloadlayer->packet());
	// use stack to store messages;
	// print from back to front
	// then pop
	std::stack<std::string> stk;
	std::string temp = "";

	// parse to datalink layer
	while (layer != NULL)
	{

		PCPP_LOG_DEBUG("!" << layer->getOsiModelLayer() << "!" << std::hex << layer->getProtocol() << std::oct << "!");

		temp = layer->toString();
		stk.push(temp);
		if (layer->getProtocol() == pcpp::IPv4 || layer->getProtocol() == pcpp::IPv6)
		{
			if (layer->packet()->getIPLayerCount() < 1)
			{
				PCPP_LOG_DEBUG("ReassemblePayload: 我要出来了");
				break;
			}
			layer->packet()->DecreaseIP();
		}
		layer = layer->getPrevLayer();

		PCPP_LOG_DEBUG("dsadasdas!" << layer->getOsiModelLayer() << "!" << std::hex << layer->getProtocol()
									<< std::oct);
	}

	PCPP_LOG_DEBUG("ReassemblePayload: 我出来了");

	while (!stk.empty())
	{
		temp = stk.top();
		stk.pop();

		result += temp;
	}

	PCPP_LOG_DEBUG("ReassemblePayload: 我读完了");

	if (response == Handled)
	{
		// call the callback to write result
		OnMessageHandledCallback(&result, payloadlayer->packet()->GetTuplename(), cookie);
		PCPP_LOG_DEBUG("ReassemblePayload: 我写入完了");
	}

	return response;
}

ReassemblyStatus ReassembleMessage(Layer *layer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback)
{
	ReassemblyStatus response = Handled;
	std::string result = "";

	// use stack to store messages;
	// print from back to front
	// then pop and <<
	std::stack<std::string> stk;
	std::string temp = "";

	// parse to datalink layer
	while (layer != NULL)
	{
		temp = layer->toString();
		stk.push(temp);
		if (layer->getProtocol() == pcpp::IPv4 || layer->getProtocol() == pcpp::IPv6)
		{
			if (layer->packet()->getIPLayerCount() < 1)
			{
				break;
			}
			layer->packet()->DecreaseIP();
		}
		layer = layer->getPrevLayer();
	}

	while (!stk.empty())
	{
		temp = stk.top();
		stk.pop();

		result += temp;
	}

	if (response == Handled)
	{
		// call the callback to write result
		OnMessageHandledCallback(&result, tuple, cookie);
	}

	return response;
}

std::string getTupleName(pcpp::IPAddress src, pcpp::IPAddress dst, uint16_t srcPort, uint16_t dstPort,
						 std::string protocol_name)
{
	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol_name;

	// return the name
	return stream.str();
}

} // namespace pcpp
