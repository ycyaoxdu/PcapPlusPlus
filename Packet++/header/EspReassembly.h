#ifndef PACKETPP_ESP_REASSEMBLY
#define PACKETPP_ESP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

//ESP数据包类
class EspPacketData
{
  public:
	//构造函数
	EspPacketData(const uint8_t *EspData, size_t EspDataLength, std::string tupleName)
        : m_Data(EspData), m_DataLen(EspDataLength), m_TupleName(tupleName)
	{
	}
	  
	//获取包数据的指针
	const uint8_t *getData() const
	{
		return m_Data;
	}

	//获取数据长度
	size_t getDataLength() const
	{
		return m_DataLen;
	}

	//获取五元组名称
	std::string getTupleName()
	{
		return m_TupleName;
    }

  private:
	const uint8_t *m_Data;     //数据指针
	size_t m_DataLen;          //数据长度
	std::string m_TupleName;   //五元组名称
};

//ESP重组类
class EspReassembly
{
  public:
    /**
	 * @typedef OnEspMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnEspMessageReady)(pcpp::EspPacketData *espData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonEspPacket,
		EspMessageHandled,
	};

	EspReassembly(OnEspMessageReady onEspMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnEspMessageReadyCallback(onEspMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}

	ReassemblyStatus reassemblePacket(Packet &espData);
	ReassemblyStatus reassemblePacket(RawPacket *espRawData);
	std::string getTupleName(IPAddress src, IPAddress dst);

  private:
	struct EspReassemblyData
	{
	  IPAddress srcIP;
	  IPAddress dstIP;
	  std::string tupleName;
	  uint16_t number;

	  EspReassemblyData()
	  {
	  }

	  EspReassemblyData(IPAddress src, IPAddress dst, std::string tName, uint16_t n)
		  : srcIP(src), dstIP(dst), tupleName(tName), number(n)
	  {
	  }

	};

	typedef std::map<std::string, EspReassemblyData> FragmentList;
	FragmentList m_FragmentList;
	OnEspMessageReady m_OnEspMessageReadyCallback;
    void *m_CallbackUserCookie;
};

} // namespace pcpp

#endif // PACKETPP_ESP_REASSEMBLY