#define LOG_MODULE PacketLogModuleReassembly

#include "Reassembly.h"
#include "BgpLayer.h"
#include "ConcurrentQueue.h"
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

ReassemblyStatus Reassemble(IPReassembly *ipReassembly, IPReassembly::ReassemblyStatus *statusPtr, DefragStats *stats,
							moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer, Packet *parsedPacket,
							void *UserCookie, OnMessageHandled OnMessageReadyCallback)
{
	bool isIPv4Packet = false;
	bool isIPv6Packet = false;

	// TODO(ycyaoxdu): should modify
	if (parsedPacket->isFirst())
	{
		if (findLayer(parsedPacket)->getProtocol() == IPv4)
		{
			isIPv4Packet = true;
		}
		else if (findLayer(parsedPacket)->getProtocol() == IPv6)
		{
			isIPv6Packet = true;
		}

		parsedPacket->UnsetFirst();
	}
	else if (findLayer(parsedPacket)->getProtocol() == IPv4)
	{

		isIPv4Packet = true;
	}
	else if (findLayer(parsedPacket)->getProtocol() == IPv4)
	{

		isIPv6Packet = true;
	}
	else
	{
		// non-ip packet should not be passed in
	}

	// process the packet in the IP reassembly mechanism
	IPReassembly::ReassemblyStatus status = *statusPtr;

	// TODO(ycyaoxdu):remove this line
	std::cout << "\nstart reassemble ip packet...\n" << std::endl;

	Packet *result = ipReassembly->processPacket(parsedPacket, status);

	// TODO(ycyaoxdu):remove this line
	std::cout << "end reassemble ip packet...\n" << std::endl;

	// write fragment/packet to file if:
	// - packet is fully reassembled (status of REASSEMBLED)
	// - packet isn't a fragment or isn't an IP packet and the user asked to write all packets to output
	if (status == pcpp::IPReassembly::REASSEMBLED ||
		((status == pcpp::IPReassembly::NON_IP_PACKET || status == pcpp::IPReassembly::NON_FRAGMENT)))
	{
		// TODO(ycyaoxdu):remove this line
		std::cout << "\nprocess de-fraged ip packet..." << std::endl;

		// TupleName is used to identify which file the packet will store in
		std::string TupleName = "";
		// the protocol name of "current" layer
		std::string protoname = "ip";
		// define ip
		pcpp::IPAddress IpSrc, IpDst;

		pcpp::Layer *ipLayer;

		std::cout << "this isIPv4Packet:" << isIPv4Packet << "\tthis isIPv6Packet:" << isIPv6Packet << std::endl;

		// TODO(ycyaoxdu):need to handle this, get the correct layer
		if (isIPv4Packet)
		{
			pcpp::IPv4Layer *ipv4Layer = getv4(result) /* result->getLayerOfType<pcpp::IPv4Layer>() */;
			IpSrc = ipv4Layer->getSrcIPAddress();
			IpDst = ipv4Layer->getDstIPAddress();
			ipLayer = ipv4Layer;
		}
		else
		{
			pcpp::IPv6Layer *ipv6Layer = getv6(result) /* result->getLayerOfType<pcpp::IPv6Layer>() */;
			IpSrc = ipv6Layer->getSrcIPAddress();
			IpDst = ipv6Layer->getDstIPAddress();
			ipLayer = ipv6Layer;
		}

		std::cout << "this protocol:" << std::hex << ipLayer->getProtocol() << std::oct << std::endl;

		// parse next layer
		// any unknow protocol is payload
		ipLayer->parseNextLayer();
		auto nextLayer = ipLayer->getNextLayer();
		if (nextLayer == NULL)
		{
			std::cout << "IP: passing layer of nullptr to function..." << std::endl;

			PCPP_LOG_DEBUG("IP: passing layer of nullptr to function");
			return Invalid;
		}

		// code logic:
		// if next layer is payload layer, just print all messages.
		// else parseNextLayer and call next module

		std::cout << "next protocol:" << std::hex << nextLayer->getProtocol() << std::oct << std::endl;

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
			HandleTcpPayload(nextLayer, IpSrc, IpDst, result, UserCookie, OnMessageReadyCallback, quePointer);
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
	}
	// update statistics if packet is fully reassembled (status of REASSEMBLED) and
	if (status == pcpp::IPReassembly::REASSEMBLED)
	{
		if (isIPv4Packet)
			stats->ipv4PacketsDefragmented++;
		else if (isIPv6Packet)
			stats->ipv6PacketsDefragmented++;

		// free packet
		delete result;
	}

	*statusPtr = status;
	return Handled;
}

void HandleOspfPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback)
{
	if (layer == NULL)
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
	if (layer == NULL)
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
					  OnMessageHandled OnMessageReadyCallback, moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	// gre : ipv4 ipv6 ppp payload
	if (layer == NULL)
	{
		PCPP_LOG_DEBUG("HandleGrePayload: passing layer of nullptr to function");
		return;
	}

	Layer *nextLayer;
	GREv0Layer *grev0 = packet->getLayerOfType<GREv0Layer>();
	if (grev0 != NULL)
	{
		grev0->parseNextLayer();
		nextLayer = grev0->getNextLayer();
	}
	else
	{
		GREv1Layer *grev1 = packet->getLayerOfType<GREv1Layer>();
		grev1->parseNextLayer();
		nextLayer = grev1->getNextLayer();
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
					  OnMessageHandled OnMessageReadyCallback, moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL)
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

		std::cout << "gtp tuplename:" << TupleName << std::endl;

		HandleGtpPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback, quePointer);
	}
	else
	{
		HandleGenericPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleTcpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL)
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
		HandleGenericPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleSctpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback,
					   moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL)
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
		TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
		HandleGenericPayload(nextLayer, TupleName, packet, cookie, OnMessageReadyCallback);
	}
}

void HandleRipPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback)
{
	if (layer == NULL)
	{
		PCPP_LOG_DEBUG("HandleRipPayload: passing layer of nullptr to function");
		return;
	}
	RipLayer rip(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);

	rip.parseNextLayer();
	Layer *nextLayer = rip.getNextLayer();
	if (nextLayer == NULL)
	{
		PCPP_LOG_DEBUG("HandleRipPayload: nextlayer of nullptr");
		return;
	}
	// TODO(): handle this
	ReassembleMessage(&rip, tuplename, cookie, OnMessageReadyCallback);

	// HandleGenericPayload(nextLayer, tuplename, packet, cookie, OnMessageReadyCallback);
}

void HandleGtpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback, moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL)
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
					  OnMessageHandled OnMessageReadyCallback, moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL)
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
					   OnMessageHandled OnMessageReadyCallback,
					   moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{
	if (layer == NULL)
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
	if (layer == NULL)
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
	if (layer == NULL)
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
		ReassembleMessage(httpResponse, tuplename, cookie, OnMessageReadyCallback);
	}
}

void HandleGenericPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
						  OnMessageHandled OnMessageReadyCallback)
{
	if (layer == NULL)
	{
		PCPP_LOG_DEBUG("HandleGenericPayload: passing layer of nullptr to function");
		return;
	}
	PayloadLayer payload(layer->getData(), layer->getDataLen(), layer->getPrevLayer(), packet);
	ReassemblePayload(&payload, tuplename, cookie, OnMessageReadyCallback);
}

// TODO: error handling
bool HandleIPPacket(Packet *packet, Layer *iplayer, std::string tuple,
					moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer)
{

	// TODO(ycyaoxdu): remove this line
	std::cout << "handle ip layer" << std::endl;

	packet->SetTuplename(tuple);

	if (iplayer->getProtocol() == IPv4 || iplayer->getProtocol() == IPv6)
	{
		packet->CountV4();
	}

	// while (iplayer != NULL)
	// {
	// 	if (iplayer->getProtocol() == IPv4)
	// 	{
	// 		packet->setNextLayerV4();
	// 		break;
	// 	}
	// 	else if (iplayer->getProtocol() == IPv6)
	// 	{
	// 		packet->setNextLayerV6();
	// 		break;
	// 	}
	// 	iplayer->parseNextLayer();
	// 	iplayer = iplayer->getNextLayer();
	// }

	return quePointer->try_enqueue(*packet->getRawPacket());
}

// TODO: error handling
ReassemblyStatus ReassemblePayload(PayloadLayer *payloadlayer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback)
{

	ReassemblyStatus response = Handled;
	std::string result = payloadlayer->GetResult();

	Layer *layer = payloadlayer;
	// use stack to store messages;
	// print from back to front
	// then pop and <<
	std::stack<std::string> stk;
	std::string temp = "";

	// parse to datalink layer
	while (layer != NULL && (layer->getOsiModelLayer() > OsiModelDataLinkLayer ||
							 layer->getProtocol() == pcpp::PPP_PPTP || layer->getProtocol() == pcpp::L2TP))
	{
		// TODO(ycyaoxdu): this line is use to debug, need to remove
		std::cout << "!" << layer->getOsiModelLayer() << "!" << std::hex << layer->getProtocol() << std::oct << "!"
				  << std::endl;

		temp = layer->toString();
		stk.push(temp);
		layer = layer->getPrevLayer();
	}
	std::cout << std::endl;

	while (!stk.empty())
	{
		temp = stk.top();
		stk.pop();

		result += temp;
	}

	if (response == Handled)
	{
		// call the callback to write result
		OnMessageHandledCallback(&result, payloadlayer->packet()->GetTuplename(), cookie);
	}

	return response;
}

// TODO: error handling
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
	while (layer != NULL && (layer->getOsiModelLayer() > OsiModelDataLinkLayer ||
							 layer->getProtocol() == pcpp::PPP_PPTP || layer->getProtocol() == pcpp::L2TP))
	{
		// TODO(ycyaoxdu): this line is use to debug, need to remove
		std::cout << "!" << layer->getOsiModelLayer() << "!" << std::hex << layer->getProtocol() << std::oct << "!"
				  << std::endl;

		temp = layer->toString();
		stk.push(temp);
		layer = layer->getPrevLayer();
	}
	std::cout << std::endl;

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
