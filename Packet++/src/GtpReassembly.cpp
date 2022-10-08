#define LOG_MODULE PacketLogModuleGtpReassembly

#include "GtpReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "UdpLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "GtpLayer.h"
#include <sstream>
#include <vector>
#include "Packet.h"

namespace pcpp
{

std::string GTPReassembly::getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("gtp");
	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol;

	// return the name
	return stream.str();
}

GTPReassembly::ReassemblyStatus GTPReassembly::reassemblePacket(RawPacket *gtpRawData)
{
	Packet parsedPacket(gtpRawData, false);
	return reassemblePacket(parsedPacket);
}

GTPReassembly::ReassemblyStatus GTPReassembly::reassemblePacket(Packet &gtpData)
{

    // connection list -》 tuple list
/* 	
    1. 获取目标包的内层的源IP、端口号和目的IP、端口号， 过滤非目标包
	2. 更新状态（返回值）
	3. 设置GTPReassemblyData
	   计算链接tupleName，在fragment list找目标fragment，若不存在则添加
	   再更新GTPReassemblyData 里的fragment信息
	4. 如果已经设置过回调函数，data调用该函数进行处理 
*/

    // 1. 
	IPAddress srcIP, dstIP;
	if (gtpData.isPacketOfType(IP))
	{
		//getLayerOfType(bool reverseOrder = false)将reverseOrder设置为true表示倒序获取ip层，
		//从而获取gtp包内层的IP层
		const IPLayer *ipLayer = gtpData.getLayerOfType<IPLayer>(true);
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	    //PCPP_LOG_ERROR(srcIP);
	}
	else
		return NonIpPacket;

		//UDP层与IP层相同，通过将reverseOrder设置为true，
		//获取gtp包内层的UDP层
	uint16_t srcPort,dstPort;
	if (gtpData.isPacketOfType(UDP))
	{
		const UdpLayer *udpLayer = gtpData.getLayerOfType<UdpLayer>(true);
		srcPort = udpLayer->getSrcPort();
	    dstPort = udpLayer->getDstPort();
	}
   else
		return NonUdpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-GTP packets
	GtpV1Layer *gtpLayer = gtpData.getLayerOfType<GtpV1Layer>(true); // lookup in reverse order
	if (gtpLayer == NULL)
	{
		return NonGtpPacket;
	}
    

    // 2.
	//标记状态
	ReassemblyStatus status = GtpMessageHandled;

    // 3.

	GTPReassemblyData *gtpReassemblyData = NULL;
	std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);
	

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, GTPReassemblyData()));
		gtpReassemblyData = &pair.first->second;
		gtpReassemblyData->srcIP = srcIP;
		gtpReassemblyData->dstIP = dstIP;
		gtpReassemblyData->srcPort = srcPort;
		gtpReassemblyData->dstPort = dstPort;
		gtpReassemblyData->tupleName = tupleName;
        gtpReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = gtpLayer->getData();
	size_t len = gtpLayer->getDataLen();
	GtpPacketData packetdata(data, len, tupleName);


    // 4.

	// send the data to the callback
	if (m_OnGtpMessageReadyCallback != NULL)
	{
		m_OnGtpMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp