#ifndef PACKETPP_REASSEMBLY
#define PACKETPP_REASSEMBLY

#include "ConcurrentQueue.h"
#include "IPReassembly.h"
#include "Layer.h"
#include "PayloadLayer.h"
#include "ProtocolType.h"

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
enum ReassemblyStatus
{
	Invalid,
	Handled,
};

/**
 * A struct for collecting stats during the de-fragmentation process
 */
struct DefragStats
{
	int totalPacketsRead;
	int ipv4Packets;
	int ipv6Packets;
	int ipv4PacketsMatchIpIDs;
	int ipv6PacketsMatchFragIDs;
	int ipPacketsMatchBpfFilter;
	int ipv4FragmentsMatched;
	int ipv6FragmentsMatched;
	int ipv4PacketsDefragmented;
	int ipv6PacketsDefragmented;
	int totalPacketsWritten;

	void clear()
	{
		memset(this, 0, sizeof(DefragStats));
	}
	DefragStats()
	{
		clear();
	}
};

typedef void (*OnMessageHandled)(std::string *data, std::string tuplename, void *userCookie);

ReassemblyStatus Reassemble(IPReassembly *ipReassembly, IPReassembly::ReassemblyStatus *statusPtr, DefragStats *stats,
							moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer, Packet *parsedPacket,
							void *UserCookie, OnMessageHandled OnMessageReadyCallback);

void HandleOspfPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback);

void HandleEspPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback);

void HandleGrePayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback,
					  moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleUdpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback,
					  moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleTcpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback,
					  moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleSctpPayload(Layer *layer, IPAddress IpSrc, IPAddress IpDst, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback,
					   moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleRipPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback);

void HandleGtpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback,
					  moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleL2tpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback,
					   moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleBgpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback);

void HandleSslPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback);

void HandleHttpPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					   OnMessageHandled OnMessageReadyCallback);

void HandlePppPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
					  OnMessageHandled OnMessageReadyCallback,
					  moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

void HandleGenericPayload(Layer *layer, std::string tuplename, Packet *packet, void *cookie,
						  OnMessageHandled OnMessageReadyCallback);

bool HandleIPPacket(Packet *packet, Layer *iplayer, std::string tuple,
					moodycamel::ConcurrentQueue<pcpp::RawPacket> *quePointer);

ReassemblyStatus ReassemblePayload(PayloadLayer *payloadlayer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback);

// this function should handle whether the next layer is payload or ip
ReassemblyStatus ReassembleMessage(Layer *layer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback);

std::string getTupleName(pcpp::IPAddress src, pcpp::IPAddress dst, uint16_t srcPort, uint16_t dstPort,
						 std::string protocol_name);

} // namespace pcpp

#endif // PACKETPP_UDP_REASSEMBLY
