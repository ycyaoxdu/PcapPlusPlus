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
#include "OspfLayer.h"
#include "Packet.h"
#include "PcapPlusPlusVersion.h"
#include "ProtocolType.h"
#include "Reassembly.h"
#include "RipLayer.h"
#include "SSLLayer.h"
#include "SctpLayer.h"
#include "Logger.h"
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
	// TODO(ycyaoxdu): we need to set a timer to expire

	bool isIPv4Packet = false;
	bool isIPv6Packet = false;
	if (parsedPacket->isPacketOfType(pcpp::IPv4))
	{
		isIPv4Packet = true;
	}
	else if (parsedPacket->isPacketOfType(pcpp::IPv6))
	{
		isIPv6Packet = true;
	}

	// process the packet in the IP reassembly mechanism
	IPReassembly::ReassemblyStatus status = *statusPtr;

	// TODO(ycyaoxdu):remove this line
	std::cout << "start reassemble ip packet..." << std::endl;

	pcpp::Packet *result = ipReassembly->processPacket(parsedPacket, status);

	// TODO(ycyaoxdu):remove this line
	std::cout << "end reassemble ip packet..." << std::endl;

	// write fragment/packet to file if:
	// - packet is fully reassembled (status of REASSEMBLED)
	// - packet isn't a fragment or isn't an IP packet and the user asked to write all packets to output
	if (status == pcpp::IPReassembly::REASSEMBLED ||
		((status == pcpp::IPReassembly::NON_IP_PACKET || status == pcpp::IPReassembly::NON_FRAGMENT)))
	{
		// TODO(ycyaoxdu):remove this line
		std::cout << "process de-fraged ip packet..." << std::endl;

		// @ycyaoxdu:
		// we do not write it here, we parse next layer in loop until Payload Layer is parsed.

		// TupleName is used to identify which file the packet will store in
		std::string TupleName = "";
		// the protocol name of "current" layer
		std::string protoname = "ip";
		// define ip and port
		pcpp::IPAddress IpSrc, IpDst;
		uint16_t PortSrc, PortDst;

		pcpp::Layer *ipLayer;

		if (isIPv4Packet)
		{
			pcpp::IPv4Layer *ipv4Layer = result->getLayerOfType<pcpp::IPv4Layer>();
			IpSrc = ipv4Layer->getSrcIPAddress();
			IpDst = ipv4Layer->getDstIPAddress();
			ipLayer = ipv4Layer;
		}
		else
		{
			pcpp::IPv6Layer *ipv6Layer = result->getLayerOfType<pcpp::IPv6Layer>();
			IpSrc = ipv6Layer->getSrcIPAddress();
			IpDst = ipv6Layer->getDstIPAddress();
			ipLayer = ipv6Layer;
		}

		std::cout << "this protocol:" << std::hex << ipLayer->getProtocol() << std::oct << std::endl;

		// parse next layer
		// any unknow protocol is payload
		ipLayer->parseNextLayer();
		auto nextLayer = ipLayer->getNextLayer();
		// code logic:
		// if next layer is payload layer, just print all messages.
		// else parseNextLayer and call next module

		std::cout << "next protocol:" << std::hex << nextLayer->getProtocol() << std::oct << std::endl;

		// switch statement
		switch (nextLayer->getProtocol())
		{
		case pcpp::OSPF: {
			// ospf handle
			// ospf have no payload
			protoname = "ospf";
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

			pcpp::OspfLayer ospf(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);
			ReassembleMessage(&ospf, TupleName, UserCookie, OnMessageReadyCallback);

			break;
		}
		case pcpp::GRE:
		case pcpp::GREv0:
		case pcpp::GREv1: {
			// TODO(ycyaoxdu): remove this line
			std::cout << "get gre after ip" << std::endl;

			// gre handle
			// ipv4 ipv6 ppp payload
			protoname = "gre";

			Layer *gre = nextLayer;
			gre->parseNextLayer();
			// TODO(ycyaoxdu): remove this line
			std::cout << "parsed gre next layer" << std::endl;

			nextLayer = gre->getNextLayer();
			if (nextLayer == NULL)
			{
				std::cout << "incomplete packet received... discard it" << std::endl;
				break;
			}

			// TODO(ycyaoxdu): remove this line
			std::cout << "get gre next layer: " << std::hex << nextLayer->getProtocol() << std::oct << std::endl;

			if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
			{
				// TODO(ycyaoxdu): remove this
				std::cout << "get ip after gre..." << std::endl;

				TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);
				bool ok = HandleIPPacket(result, nextLayer, TupleName, quePointer);
				if (!ok)
				{
					std::cout << "error" << std::endl;
				}
				// TODO(ycyaoxdu): handle
			}
			else if (nextLayer->getProtocol() == pcpp::PPP_PPTP)
			{
				// TODO(ycyaoxdu): remove this
				std::cout << "get ppp after gre..." << std::endl;

				pcpp::PPP_PPTPLayer ppp(nextLayer->getData(), nextLayer->getDataLen(), gre, result);

				ppp.parseNextLayer();
				nextLayer = ppp.getNextLayer();

				if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
				{
					bool ok = HandleIPPacket(result, nextLayer, TupleName, quePointer);
					if (!ok)
					{
						std::cout << "error" << std::endl;
					}
					// TODO(ycyaoxdu): handle
				}
				else if (nextLayer->getProtocol() == pcpp::GenericPayload)
				{
					TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);
					HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
				}
			}
			else if (nextLayer->getProtocol() == pcpp::GenericPayload)
			{
				// TODO(ycyaoxdu): remove this
				std::cout << "get payload after gre..." << std::endl;

				TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);
				HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			}

			break;
		}
		// esp
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

				pcpp::ESPLayer esp(nextLayer->getData(), nextLayer->getDataLen(), &ahlayer, result);

				// ESP层的负载是被加密的，因此next layer都为generic payload
				esp.parseNextLayer();
				Layer *payload = esp.getNextLayer();

				ReassembleMessage(payload, TupleName, UserCookie, OnMessageReadyCallback);
			}

			break;
		}
		case pcpp::ESP: {
			// esp handle
			protoname = "esp";
			TupleName = getTupleName(IpSrc, IpDst, 0, 0, protoname);

			pcpp::ESPLayer esp(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);

			// ESP层的负载是被加密的，因此next layer都为generic payload
			esp.parseNextLayer();
			auto payload = esp.getNextLayer();

			ReassembleMessage(payload, TupleName, UserCookie, OnMessageReadyCallback);

			break;
		}
		case pcpp::TCP: {
			// tcp handle
			protoname = "tcp";

			pcpp::TcpLayer tcp(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);

			uint16_t PortSrc = tcp.getSrcPort();
			uint16_t PortDst = tcp.getDstPort();

			// next layer
			tcp.parseNextLayer();
			nextLayer = tcp.getNextLayer();

			if (nextLayer->getProtocol() == pcpp::HTTPRequest)
			{
				protoname = "http";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::HttpRequestLayer httpRequest(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
				ReassembleMessage(&httpRequest, TupleName, UserCookie, OnMessageReadyCallback);
			}
			else if (nextLayer->getProtocol() == pcpp::HTTPResponse)
			{
				protoname = "http";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::HttpResponseLayer httpResponse(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
				ReassembleMessage(&httpResponse, TupleName, UserCookie, OnMessageReadyCallback);
			}
			else if (nextLayer->getProtocol() == pcpp::SSL)
			{
				protoname = "ssl";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::SSLLayer *ssl =
					pcpp::SSLLayer::createSSLMessage(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
				ReassembleMessage(&(*ssl), TupleName, UserCookie, OnMessageReadyCallback);

				//单个包中可能包含多条SSL记录，所以需要检查这个SSL包。
				//如果存在，就创建一个新的SSL记录，然后继续检查
				//否则就退出

				while (1)
				{
					size_t ssl_header_len = ssl->getHeaderLen();
					size_t ssl_data_len = ssl->getDataLen();
					uint8_t *ssl_data = ssl->getData();

					ssl->parseNextLayer();
					nextLayer = ssl->getNextLayer();

					if (nextLayer == NULL) //该数据包中不再有SSL记录
					{
						break;
					}
					else //存在SSL记录
					{
						ssl = pcpp::SSLLayer::createSSLMessage(ssl_data + ssl_header_len, ssl_data_len - ssl_header_len,
															   &tcp, result);
						ReassembleMessage(&(*ssl), TupleName, UserCookie, OnMessageReadyCallback);
					}
				}
			}
			else if (nextLayer->getProtocol() == pcpp::BGP)
			{
				protoname = "bgp";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::BgpLayer *bgp =
					pcpp::BgpLayer::parseBgpLayer(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
				ReassembleMessage(&(*bgp), TupleName, UserCookie, OnMessageReadyCallback);

				switch (bgp->getBgpMessageType())
				{
				case pcpp::BgpLayer::Open: {
					pcpp::BgpOpenMessageLayer bgpOpen =
						pcpp::BgpOpenMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
					ReassembleMessage(&bgpOpen, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::Update: {
					pcpp::BgpUpdateMessageLayer bgpUpdate =
						pcpp::BgpUpdateMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
					ReassembleMessage(&bgpUpdate, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::Notification: {
					pcpp::BgpNotificationMessageLayer bgpNotification =
						pcpp::BgpNotificationMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
					ReassembleMessage(&bgpNotification, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::Keepalive: {
					pcpp::BgpKeepaliveMessageLayer bgpKA =
						pcpp::BgpKeepaliveMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
					ReassembleMessage(&bgpKA, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::RouteRefresh: {
					pcpp::BgpRouteRefreshMessageLayer bgpRR =
						pcpp::BgpRouteRefreshMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);
					ReassembleMessage(&bgpRR, TupleName, UserCookie, OnMessageReadyCallback);

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
					nextLayer = bgp->getNextLayer();

					if (nextLayer == NULL) //该数据包中不再有BGP消息
					{
						break;
					}
					else //存在BGP消息
					{
						bgp = pcpp::BgpLayer::parseBgpLayer(bgp_data + bgp_header_len, bgp_data_len - bgp_header_len,
															&tcp, result);
						ReassembleMessage(&(*bgp), TupleName, UserCookie, OnMessageReadyCallback);
					}
				}
			}
			else if (nextLayer->getProtocol() == pcpp::GTP)
			{
				protoname = "gtp";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::GtpV1Layer gtp(nextLayer->getData(), nextLayer->getDataLen(), &tcp, result);

				gtp.parseNextLayer();
				nextLayer = gtp.getNextLayer();

				if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
				{
					bool ok = HandleIPPacket(result, nextLayer, TupleName, quePointer);
					if (!ok)
					{
						std::cout << "error" << std::endl;
					}
					// TODO(ycyaoxdu): handle
				}
				else if (nextLayer->getProtocol() == pcpp::GenericPayload)
				{
					TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
					HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
				}
			}
			else if (nextLayer->getProtocol() == pcpp::GenericPayload)
			{
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			}

			break;
		}
		case pcpp::UDP: {
			// udp handle
			protoname = "udp";

			pcpp::UdpLayer udp(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);

			PortSrc = udp.getSrcPort();
			PortDst = udp.getDstPort();

			// next layer
			udp.parseNextLayer();
			nextLayer = udp.getNextLayer();

			if (nextLayer->getProtocol() == pcpp::L2TP)
			{
				protoname = "l2tp";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

				pcpp::L2tpLayer l2tp(nextLayer->getData(), nextLayer->getDataLen(), &udp, result);

				l2tp.parseNextLayer();
				nextLayer = l2tp.getNextLayer();

				pcpp::PPP_PPTPLayer ppp(nextLayer->getData(), nextLayer->getDataLen(), &l2tp, result);

				ppp.parseNextLayer();
				nextLayer = ppp.getNextLayer();

				if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
				{
					bool ok = HandleIPPacket(result, nextLayer, TupleName, quePointer);
					if (!ok)
					{
						std::cout << "error" << std::endl;
					}
					// TODO(ycyaoxdu): handle
				}
				else if (nextLayer->getProtocol() == pcpp::GenericPayload)
				{
					TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
					HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
				}
			}
			else if (nextLayer->getProtocol() == pcpp::RIP)
			{
				// RIP have no next layer.
				protoname = "rip";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::RipLayer rip(nextLayer->getData(), nextLayer->getDataLen(), &udp, result);
				ReassembleMessage(&rip, TupleName, UserCookie, OnMessageReadyCallback);
			}
			else if (nextLayer->getProtocol() == pcpp::GTP)
			{
				protoname = "gtp";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::GtpV1Layer gtp(nextLayer->getData(), nextLayer->getDataLen(), &udp, result);

				gtp.parseNextLayer();
				nextLayer = gtp.getNextLayer();

				if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
				{
					bool ok = HandleIPPacket(result, nextLayer, TupleName, quePointer);
					if (!ok)
					{
						std::cout << "error" << std::endl;
					}
					// TODO(ycyaoxdu): handle
				}
				else if (nextLayer->getProtocol() == pcpp::GenericPayload)
				{
					TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
					HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
				}
			}
			else if (nextLayer->getProtocol() == pcpp::GenericPayload)
			{
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			}

			break;
		}
		case pcpp::SCTP: {
			// SCTP handle
			protoname = "sctp";
			pcpp::SctpLayer sctp(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);
			uint16_t PortSrc = sctp.getSrcPort();
			uint16_t PortDst = sctp.getDstPort();

			// next layer
			sctp.parseNextLayer();
			nextLayer = sctp.getNextLayer();

			if (nextLayer->getProtocol() == pcpp::HTTPRequest)
			{
				protoname = "http";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::HttpRequestLayer httpRequest(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
				ReassembleMessage(&httpRequest, TupleName, UserCookie, OnMessageReadyCallback);
			}
			else if (nextLayer->getProtocol() == pcpp::HTTPResponse)
			{
				protoname = "http";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::HttpResponseLayer httpResponse(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
				ReassembleMessage(&httpResponse, TupleName, UserCookie, OnMessageReadyCallback);
			}
			else if (nextLayer->getProtocol() == pcpp::SSL)
			{
				protoname = "ssl";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::SSLLayer *ssl =
					pcpp::SSLLayer::createSSLMessage(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
				ReassembleMessage(&(*ssl), TupleName, UserCookie, OnMessageReadyCallback);

				//单个包中可能包含多条SSL记录，所以需要检查这个SSL包。
				//如果存在，就创建一个新的SSL记录，然后继续检查
				//否则就退出

				while (1)
				{
					size_t ssl_header_len = ssl->getHeaderLen();
					size_t ssl_data_len = ssl->getDataLen();
					uint8_t *ssl_data = ssl->getData();

					ssl->parseNextLayer();
					nextLayer = ssl->getNextLayer();

					if (nextLayer == NULL) //该数据包中不再有SSL记录
					{
						break;
					}
					else //存在SSL记录
					{
						ssl = pcpp::SSLLayer::createSSLMessage(ssl_data + ssl_header_len, ssl_data_len - ssl_header_len,
															   &sctp, result);
						ReassembleMessage(&(*ssl), TupleName, UserCookie, OnMessageReadyCallback);
					}
				}
			}
			else if (nextLayer->getProtocol() == pcpp::BGP)
			{
				protoname = "bgp";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::BgpLayer *bgp =
					pcpp::BgpLayer::parseBgpLayer(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
				ReassembleMessage(&(*bgp), TupleName, UserCookie, OnMessageReadyCallback);

				switch (bgp->getBgpMessageType())
				{
				case pcpp::BgpLayer::Open: {
					pcpp::BgpOpenMessageLayer bgpOpen =
						pcpp::BgpOpenMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
					ReassembleMessage(&bgpOpen, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::Update: {
					pcpp::BgpUpdateMessageLayer bgpUpdate =
						pcpp::BgpUpdateMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
					ReassembleMessage(&bgpUpdate, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::Notification: {
					pcpp::BgpNotificationMessageLayer bgpNotification =
						pcpp::BgpNotificationMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
					ReassembleMessage(&bgpNotification, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::Keepalive: {
					pcpp::BgpKeepaliveMessageLayer bgpKA =
						pcpp::BgpKeepaliveMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
					ReassembleMessage(&bgpKA, TupleName, UserCookie, OnMessageReadyCallback);

					break;
				}
				case pcpp::BgpLayer::RouteRefresh: {
					pcpp::BgpRouteRefreshMessageLayer bgpRR =
						pcpp::BgpRouteRefreshMessageLayer(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);
					ReassembleMessage(&bgpRR, TupleName, UserCookie, OnMessageReadyCallback);

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
					nextLayer = bgp->getNextLayer();

					if (nextLayer == NULL) //该数据包中不再有BGP消息
					{
						break;
					}
					else //存在BGP消息
					{
						bgp = pcpp::BgpLayer::parseBgpLayer(bgp_data + bgp_header_len, bgp_data_len - bgp_header_len,
															&sctp, result);
						ReassembleMessage(&(*bgp), TupleName, UserCookie, OnMessageReadyCallback);
					}
				}
			}
			else if (nextLayer->getProtocol() == pcpp::GTP)
			{
				protoname = "gtp";
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				pcpp::GtpV1Layer gtp(nextLayer->getData(), nextLayer->getDataLen(), &sctp, result);

				gtp.parseNextLayer();
				nextLayer = gtp.getNextLayer();

				if (nextLayer->getProtocol() == pcpp::IPv4 || nextLayer->getProtocol() == pcpp::IPv6)
				{
					bool ok = HandleIPPacket(result, nextLayer, TupleName, quePointer);
					if (!ok)
					{
						std::cout << "error" << std::endl;
					}
					// TODO(ycyaoxdu): handle
				}
				else if (nextLayer->getProtocol() == pcpp::GenericPayload)
				{
					TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
					HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
				}
			}
			else if (nextLayer->getProtocol() == pcpp::GenericPayload)
			{
				TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);
				HandleGenericPayload(nextLayer, TupleName, result, UserCookie, OnMessageReadyCallback);
			}

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

void HandleGenericPayload(Layer *layer, std::string tuplename, pcpp::Packet *packet, void *cookie,
						  OnMessageHandled OnMessageReadyCallback)
{
	if (layer == NULL)
	{
		PCPP_LOG_DEBUG("passing nextlayer of nullptr to function HandleGenericPayload");
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
	std::cout << "started handle ip" << std::endl;

	std::string result = "";
	// use stack to store messages;
	// print from back to front
	// then pop and <<
	std::stack<std::string> stk;
	std::string temp = "";

	Layer *layer = iplayer->getPrevLayer();
	// parse to datalink layer
	while (layer != NULL && (layer->getOsiModelLayer() > OsiModelDataLinkLayer ||
							 layer->getProtocol() == pcpp::PPP_PPTP || layer->getProtocol() == pcpp::L2TP))
	{
		// TODO(ycyaoxdu): this line is use to debug, need to remove
		std::cout << "!" << layer->getOsiModelLayer() << "!" << std::hex << layer->getProtocol() << std::oct << "!"
				  << std::endl;

		ProtocolType layertype = layer->getProtocol();
		temp = layer->toString();
		stk.push(temp);
		layer = layer->getPrevLayer();

		// remove the parsed layer
		packet->removeLayer(layertype);

		// TODO(ycyaoxdu): remove this line
		std::cout << "!removed layer:" << layertype << std::endl;
	}

	while (!stk.empty())
	{
		temp = stk.top();
		stk.pop();

		result += temp;
	}

	// v4 v6 enqueue
	IPv4Layer *ipv4 = packet->getLayerOfType<IPv4Layer>();
	if (ipv4 != NULL)
	{
		ipv4->SetTuplename(tuple);
		ipv4->AppendResult(std::move(result));

		// TODO(ycyaoxdu): remove this line
		std::cout << "!enqueue ipv4" << std::endl;
		return quePointer->try_enqueue(*packet->getRawPacket());
	}
	else
	{
		IPv6Layer *ipv6 = packet->getLayerOfType<IPv6Layer>();
		ipv6->SetTuplename(tuple);
		ipv6->AppendResult(std::move(result));

		// TODO(ycyaoxdu): remove this line
		std::cout << "!enqueue ipv6" << std::endl;
		return quePointer->try_enqueue(*packet->getRawPacket());
	}
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
		OnMessageHandledCallback(&result, tuple, cookie);
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
