#define LOG_MODULE PacketLogModuleGreReassembly

#include "BgpReassembly.h"
#include "EndianPortable.h"
#include "BgpLayer.h"
#include "IPLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include <sstream>
#include <vector>

namespace pcpp
{
//获取元组名称
std::string BgpReassembly::getTupleName(IPAddress src, IPAddress dst)
{
	std::stringstream stream;
	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("bgp");
    stream << sourceIP << '-' << destIP << '-' << protocol;

	// return the name
	return stream.str();
}

//处理原始数据包
BgpReassembly::ReassemblyStatus BgpReassembly::reassemblePacket(RawPacket *bgpRawData)
{
	Packet parsedPacket(bgpRawData, false);
	return reassemblePacket(parsedPacket);
}

BgpReassembly::ReassemblyStatus BgpReassembly::reassemblePacket(Packet &bgpData)
{

	// 1.判断包的类型
	IPAddress srcIP, dstIP;
	if (bgpData.isPacketOfType(IP))
	{
	  //不确定是否要按照颠倒顺序获取
	  //const IPLayer *ipLayer = bgpData.getLayerOfType<IPLayer>(true);
	  const IPLayer *ipLayer = bgpData.getLayerOfType<IPLayer>();
	  srcIP = ipLayer->getSrcIPAddress();
	  dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-Bgp packets
	BgpLayer *bgpLayer = bgpData.getLayerOfType<BgpLayer>(true); // lookup in reverse order
	if (bgpLayer == NULL)
	{
		return NonBgpPacket;
	}

	// 2.
	//标记状态
	ReassemblyStatus status = BgpMessageHandled;

	// 3.进行重组操作
	BgpReassemblyData *bgpReassemblyData = NULL;

	std::string tupleName = getTupleName(srcIP, dstIP);

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, BgpReassemblyData()));
		bgpReassemblyData = &pair.first->second;
		bgpReassemblyData->srcIP = srcIP;
		bgpReassemblyData->dstIP = dstIP;
		bgpReassemblyData->tupleName = tupleName;
		bgpReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = bgpLayer->getData();
	size_t len = bgpLayer->getDataLen();
	std::string type = bgpLayer->getMessageTypeAsString();
	BgpPacketData packetdata(data, len, tupleName, type);

	// 4.处理信息
	// send the data to the callback
	if (m_OnBgpMessageReadyCallback != NULL)
	{
		m_OnBgpMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp