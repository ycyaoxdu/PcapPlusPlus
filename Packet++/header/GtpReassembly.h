#ifndef PACKETPP_GTP_REASSEMBLY
#define PACKETPP_GTP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class GtpPacketData
{
  public:
	GtpPacketData(const uint8_t *gtpData, size_t gtpDataLength, std::string tupleName)
		: m_Data(gtpData), m_DataLen(gtpDataLength), m_TupleName(tupleName)
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

class GTPReassembly
{
  public:
	/**
	 * @typedef OnGtpMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnGtpMessageReady)(pcpp::GtpPacketData *gtpData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonGtpPacket,
		GtpMessageHandled,
		NonUdpPacket,
	};

	GTPReassembly(OnGtpMessageReady onGtpMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnGtpMessageReadyCallback(onGtpMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &gtpData);

	ReassemblyStatus reassemblePacket(RawPacket *gtpRawData);

	std::string getTupleName(IPAddress src, IPAddress dst,uint16_t srcPort, uint16_t dstPort);

  private:
	struct GTPReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		uint16_t srcPort;
		uint16_t dstPort;
		std::string tupleName;
		uint16_t number;

		GTPReassemblyData()
		{
		}
		GTPReassemblyData(IPAddress src, IPAddress dst, uint16_t srcP, uint16_t dstP, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), srcPort(srcP), dstPort(dstP), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, GTPReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnGtpMessageReady m_OnGtpMessageReadyCallback;
	void *m_CallbackUserCookie;
};

}// namespace pcpp

#endif /* PACKETPP_GTP_REASSEMBLY */