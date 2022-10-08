#ifndef PACKETPP_SCTP_REASSEMBLY
#define PACKETPP_SCTP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class SctpPacketData
{
  public:
	SctpPacketData(const uint8_t *sctpData, size_t sctpDataLength, std::string tupleName)
		: m_Data(sctpData), m_DataLen(sctpDataLength), m_TupleName(tupleName)
	{
	}

	const uint8_t *getData() const
	{
		return m_Data;
	}

	size_t getDataLength() const
	{
		return m_DataLen;
	}

	std::string getTupleName()
	{
		return m_TupleName;
	}

  private:
	const uint8_t *m_Data;
	size_t m_DataLen;
	std::string m_TupleName;
};

class SCTPReassembly
{
  public:
	/**
	 * @typedef OnSctpMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnSctpMessageReady)(pcpp::SctpPacketData *sctpData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonSctpPacket,
		SctpMessageHandled,
	};

	SCTPReassembly(OnSctpMessageReady onSctpMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnSctpMessageReadyCallback(onSctpMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &sctpData);

	ReassemblyStatus reassemblePacket(RawPacket *sctpRawData);

	std::string getTupleName(IPAddress src, IPAddress dst,uint16_t srcPort, uint16_t dstPort);

  private:
	struct SCTPReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		uint16_t srcPort;
		uint16_t dstPort;
		std::string tupleName;
		uint16_t number;

		SCTPReassemblyData()
		{
		}
		SCTPReassemblyData(IPAddress src, IPAddress dst, uint16_t srcP, uint16_t dstP, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), srcPort(srcP), dstPort(dstP), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, SCTPReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnSctpMessageReady m_OnSctpMessageReadyCallback;
	void *m_CallbackUserCookie;
};

}// namespace pcpp

#endif /* PACKETPP_SCTP_REASSEMBLY */