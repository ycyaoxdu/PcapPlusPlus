#define LOG_MODULE PacketLogModuleGreReassembly

#include "EspReassembly.h"
#include "EndianPortable.h"
#include "IPSecLayer.h"
#include "IPLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include <sstream>
#include <vector>

namespace pcpp
{

//获取元组名称
std::string EspReassembly::getTupleName(IPAddress src, IPAddress dst)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("esp");
    stream << sourceIP << '-' << destIP << '-' << protocol;

	// return the name
	return stream.str();
}

//处理原始数据包
EspReassembly::ReassemblyStatus EspReassembly::reassemblePacket(RawPacket *espRawData)
{
	Packet parsedPacket(espRawData, false);
	return reassemblePacket(parsedPacket);
}

EspReassembly::ReassemblyStatus EspReassembly::reassemblePacket(Packet &espData)
{
	// 1.判断包的类型

	IPAddress srcIP, dstIP;
	if (espData.isPacketOfType(IP))
	{
	  //不确定是否要按照颠倒顺序获取
	  //const IPLayer *ipLayer = espData.getLayerOfType<IPLayer>(true);
	  const IPLayer *ipLayer = espData.getLayerOfType<IPLayer>();
	  srcIP = ipLayer->getSrcIPAddress();
	  dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-Esp packets
	EspLayer *espLayer = espData.getLayerOfType<EspLayer>(true); // lookup in reverse order
	if (espLayer == NULL)
	{
		return NonEspPacket;
	}

	// 2.
	//标记状态
	ReassemblyStatus status = EspMessageHandled;

	// 3.进行重组操作
	EspReassemblyData *espReassemblyData = NULL;

	std::string tupleName = getTupleName(srcIP, dstIP);

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, EspReassemblyData()));
		espReassemblyData = &pair.first->second;
		espReassemblyData->srcIP = srcIP;
		espReassemblyData->dstIP = dstIP;
		espReassemblyData->tupleName = tupleName;
		espReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = espLayer->getData();
	size_t len = espLayer->getDataLen();
	EspPacketData packetdata(data, len, tupleName);

	// 4.处理信息

	// send the data to the callback
	if (m_OnEspMessageReadyCallback != NULL)
	{
		m_OnEspMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp