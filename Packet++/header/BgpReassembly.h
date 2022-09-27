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
//BGP数据包类
class BgpPacketData
{
  public:
	//构造函数
	BgpPacketData(const uint8_t *BgpData, size_t BgpDataLength, std::string tupleName, std::string type)
        : m_Data(BgpData), m_DataLen(BgpDataLength), m_TupleName(tupleName), m_Type(type)
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

	//获取消息类型
    std::string getType()
	{
		return m_Type;
	}


  private:
	const uint8_t *m_Data;     //数据指针
	size_t m_DataLen;          //数据长度
	std::string m_TupleName;   //五元组名称
	std::string m_Type;        //消息的类型 
};

//BGP重组类
class BgpReassembly
{
  public:
    /**
	 * @typedef OnBgpMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnBgpMessageReady)(pcpp::BgpPacketData *bgpData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonBgpPacket,
		BgpMessageHandled,
	};

	BgpReassembly(OnBgpMessageReady onBgpMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnBgpMessageReadyCallback(onBgpMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}

	ReassemblyStatus reassemblePacket(Packet &bgpData);

	ReassemblyStatus reassemblePacket(RawPacket *bgpRawData);

	std::string getTupleName(IPAddress src, IPAddress dst);

  private:
	struct BgpReassemblyData
	{
	  IPAddress srcIP;
	  IPAddress dstIP;
	  std::string tupleName;
	  uint16_t number;

	  BgpReassemblyData()
	  {
	  }

	  BgpReassemblyData(IPAddress src, IPAddress dst, std::string tName, uint16_t n)
		  : srcIP(src), dstIP(dst), tupleName(tName), number(n)
	  {
	  }
	};

	typedef std::map<std::string, BgpReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnBgpMessageReady m_OnBgpMessageReadyCallback;
    void *m_CallbackUserCookie;
};

} // namespace pcpp

#endif // PACKETPP_BGP_REASSEMBLY