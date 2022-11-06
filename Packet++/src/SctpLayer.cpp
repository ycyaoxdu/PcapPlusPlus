#define LOG_MODULE PacketLogModuleSctpLayer

#include "EndianPortable.h"
#include "SctpLayer.h"
#include "PayloadLayer.h"
#include "GtpLayer.h"
#include "EndianPortable.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "BgpLayer.h"
#include "TelnetLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{
void SctpLayer::ToStructuredOutput(std::ostream &os) const
{

	os << "Sctp Header:" << '\n';
	os << "\t"
	   << "Source port: " << getSrcPort() << '\n';		
	os << "\t"
	   << "Destination port: " << getDstPort() << '\n';
	os << "\t"
	   << "Verification Tag: " << getTag() << '\n';
	os << "\t"
	   << "Checksum: " << calculateChecksum(true) << '\n';
}
SctpLayer::SctpLayer(uint16_t portSrc, uint16_t portDst)
{
	const size_t headerLen = sizeof(sctphdr);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	sctphdr* sctpHdr = (sctphdr*)m_Data;
	sctpHdr->portDst = htobe16(portDst);
	sctpHdr->portSrc = htobe16(portSrc);
	m_Protocol = SCTP;
}

uint16_t SctpLayer::getSrcPort() const
{
	return be16toh(getSctpHeader()->portSrc);
}

uint16_t SctpLayer::getDstPort() const
{
	return be16toh(getSctpHeader()->portDst);
}

uint32_t SctpLayer::getTag() const
{
	return getSctpHeader()->tag;
}
	
uint16_t SctpLayer::calculateChecksum(bool writeResultToPacket) const
{
	sctphdr* sctpHdr = (sctphdr*)m_Data;
	uint16_t checksumRes = 0;
	uint16_t currChecksumValue = sctpHdr->Checksum;

	if (m_PrevLayer != NULL)
	{
		sctpHdr->Checksum = 0;
		ScalarBuffer<uint16_t> vec[2];
		PCPP_LOG_DEBUG("data len =  " << m_DataLen);
		vec[0].buffer = (uint16_t*)m_Data;
		vec[0].len = m_DataLen;

		if (m_PrevLayer->getProtocol() == IPv4)
		{
			uint32_t srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIPv4Address().toInt();
			uint32_t dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIPv4Address().toInt();
			uint16_t pseudoHeader[6];
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & len;
			pseudoHeader[5] = htobe16(0x00ff & PACKETPP_IPPROTO_SCTP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			checksumRes = computeChecksum(vec, 2);
			PCPP_LOG_DEBUG("calculated checksum = 0x" << std::uppercase << std::hex << checksumRes);
		}
		else if (m_PrevLayer->getProtocol() == IPv6)
		{
			uint16_t pseudoHeader[18];
			((IPv6Layer*)m_PrevLayer)->getSrcIPv6Address().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIPv6Address().copyTo((uint8_t*)(pseudoHeader+8));
			pseudoHeader[16] = 0xffff & len;
			pseudoHeader[17] = htobe16(0x00ff & PACKETPP_IPPROTO_SCTP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = computeChecksum(vec, 2);
			PCPP_LOG_DEBUG("calculated checksum = 0x" << std::uppercase << std::hex << checksumRes);
		}
	}

	if (checksumRes == 0)
		checksumRes = 0xffff;

	if(writeResultToPacket)
		sctpHdr->Checksum = htobe16(checksumRes);
	else
		sctpHdr->Checksum = currChecksumValue;

	return checksumRes;
}

void SctpLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(sctphdr))
		return;

	uint16_t portDst = getDstPort();
	uint16_t portSrc = getSrcPort();

	uint8_t* sctpData = m_Data + sizeof(sctphdr);
	size_t sctpDataLen = m_DataLen - sizeof(sctphdr);

	if (HttpMessage::isHttpPort(portDst) && HttpRequestFirstLine::parseMethod((char*)sctpData, sctpDataLen) != HttpRequestLayer::HttpMethodUnknown)
		m_NextLayer = new HttpRequestLayer(sctpData, sctpDataLen, this, m_Packet);
	else if (HttpMessage::isHttpPort(portSrc) && HttpResponseFirstLine::parseStatusCode((char*)sctpData, sctpDataLen) != HttpResponseLayer::HttpStatusCodeUnknown)
		m_NextLayer = new HttpResponseLayer(sctpData, sctpDataLen, this, m_Packet);
	if ((GtpV1Layer::isGTPv1Port(portDst) || GtpV1Layer::isGTPv1Port(portSrc)) &&
		GtpV1Layer::isGTPv1(sctpData, sctpDataLen))
		m_NextLayer = new GtpV1Layer(sctpData, sctpDataLen, this, m_Packet);
	else if (SSLLayer::IsSSLMessage(portSrc, portDst, sctpData, sctpDataLen))
		m_NextLayer = SSLLayer::createSSLMessage(sctpData, sctpDataLen, this, m_Packet);
	else if (BgpLayer::isBgpPort(portSrc, portDst))
		m_NextLayer = BgpLayer::parseBgpLayer(sctpData, sctpDataLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(sctpData, sctpDataLen, this, m_Packet);
}

void SctpLayer::computeCalculateFields()
{
	calculateChecksum(true);
}

/* std::string SctpLayer::toString() const
{
	std::ostringstream srcPortStream;
	srcPortStream << getSrcPort();
	std::ostringstream dstPortStream;
	dstPortStream << getDstPort();

	return "SCTP Layer, Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();
} */

std::string SctpLayer::toString() const
{
	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}



} // namespace pcpp
