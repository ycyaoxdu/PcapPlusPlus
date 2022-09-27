#define LOG_MODULE PacketLogModuleSctpReassembly

#include "SctpReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "UdpLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "SctpLayer.h"
#include <sstream>
#include <vector>
#include "Packet.h"

namespace pcpp
{

std::string SCTPReassembly::getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("sctp");
	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol;

	// return the name
	return stream.str();
}

SCTPReassembly::ReassemblyStatus SCTPReassembly::reassemblePacket(RawPacket *sctpRawData)
{
	Packet parsedPacket(sctpRawData, false);
	return reassemblePacket(parsedPacket);
}

SCTPReassembly::ReassemblyStatus SCTPReassembly::reassemblePacket(Packet &sctpData)
{

    // connection list -》 tuple list
/* 	
    1. 获取目标包的内层的源IP、端口号和目的IP、端口号， 过滤非目标包
	2. 更新状态（返回值）
	3. 设置SCTPReassemblyData
	   计算链接tupleName，在fragment list找目标fragment，若不存在则添加
	   再更新SCTPReassemblyData 里的fragment信息
	4. 如果已经设置过回调函数，data调用该函数进行处理 
*/

    // 1. 
	IPAddress srcIP, dstIP;
	if (sctpData.isPacketOfType(IP))
	{
		//getLayerOfType(bool reverseOrder = false)将reverseOrder设置为true表示倒序获取ip层，
		//从而获取sctp包内层的IP层
		const IPLayer *ipLayer = sctpData.getLayerOfType<IPLayer>(true);
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	    //PCPP_LOG_ERROR(srcIP);
	}
	else
		return NonIpPacket;

		//UDP层与IP层相同，通过将reverseOrder设置为true，
		//获取sctp包内层的UDP层
	//uint16_t srcPort,dstPort;
	//if (sctpData.isPacketOfType(SCTP))
	//{
	//	const SctpLayer *sctpLayer = sctpData.getLayerOfType<SctpLayer>(true);
	//	srcPort = sctpLayer->getSrcPort();
	  //  dstPort = sctpLayer->getDstPort();
	//}
   //else
	//	return NonSctpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	//Ignore non-SCTP packets
	SctpLayer *sctpLayer = sctpData.getLayerOfType<SctpLayer>(true); // lookup in reverse order
	if (sctpLayer == NULL)
     {
   	   return NonSctpPacket;
     }
    

    // 2.
	//标记状态
	ReassemblyStatus status = SctpMessageHandled;

    // 3.

	SCTPReassemblyData *sctpReassemblyData = NULL;
	uint16_t srcPort = sctpLayer->getSrcPort();
	uint16_t dstPort = sctpLayer->getDstPort();
	std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);
	

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, SCTPReassemblyData()));
		sctpReassemblyData = &pair.first->second;
		sctpReassemblyData->srcIP = srcIP;
		sctpReassemblyData->dstIP = dstIP;
		sctpReassemblyData->srcPort = srcPort;
		sctpReassemblyData->dstPort = dstPort;
		sctpReassemblyData->tupleName = tupleName;
        sctpReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = sctpLayer->getData();
	size_t len = sctpLayer->getDataLen();
	SctpPacketData packetdata(data, len, tupleName);


    // 4.

	// send the data to the callback
	if (m_OnSctpMessageReadyCallback != NULL)
	{
		m_OnSctpMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp