#define LOG_MODULE PacketLogModuleSctpLayer

#include "EndianPortable.h"
#include "SctpLayer.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "DhcpV6Layer.h"
#include "VxlanLayer.h"
#include "SipLayer.h"
#include "RadiusLayer.h"
#include "GtpLayer.h"
#include "NtpLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

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

uint16_t SctpLayer::calculateChecksum(bool writeResultToPacket)
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

	if ((portSrc == 68 && portDst == 67) || (portSrc == 67 && portDst == 68) || (portSrc == 67 && portDst == 67))
		m_NextLayer = new DhcpLayer(sctpData, sctpDataLen, this, m_Packet);
	else if (VxlanLayer::isVxlanPort(portDst))
		m_NextLayer = new VxlanLayer(sctpData, sctpDataLen, this, m_Packet);
	else if (DnsLayer::isDataValid(sctpData, sctpDataLen) && (DnsLayer::isDnsPort(portDst) || DnsLayer::isDnsPort(portSrc)))
		m_NextLayer = new DnsLayer(sctpData, sctpDataLen, this, m_Packet);
	else if(SipLayer::isSipPort(portDst) || SipLayer::isSipPort(portSrc))
	{
		if (SipRequestFirstLine::parseMethod((char*)sctpData, sctpDataLen) != SipRequestLayer::SipMethodUnknown)
			m_NextLayer = new SipRequestLayer(sctpData, sctpDataLen, this, m_Packet);
		else if (SipResponseFirstLine::parseStatusCode((char*)sctpData, sctpDataLen) != SipResponseLayer::SipStatusCodeUnknown
						&& SipResponseFirstLine::parseVersion((char*)sctpData, sctpDataLen) != "")
			m_NextLayer = new SipResponseLayer(sctpData, sctpDataLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(sctpData, sctpDataLen, this, m_Packet);
	}
	else if ((RadiusLayer::isRadiusPort(portDst) || RadiusLayer::isRadiusPort(portSrc)) && RadiusLayer::isDataValid(sctpData, sctpDataLen))
		m_NextLayer = new RadiusLayer(sctpData, sctpDataLen, this, m_Packet);
	else if ((GtpV1Layer::isGTPv1Port(portDst) || GtpV1Layer::isGTPv1Port(portSrc)) && GtpV1Layer::isGTPv1(sctpData, sctpDataLen))
		m_NextLayer = new GtpV1Layer(sctpData, sctpDataLen, this, m_Packet);
	else if ((DhcpV6Layer::isDhcpV6Port(portSrc) || DhcpV6Layer::isDhcpV6Port(portDst)) && (DhcpV6Layer::isDataValid(sctpData, sctpDataLen)))
		m_NextLayer = new DhcpV6Layer(sctpData, sctpDataLen, this, m_Packet);
	else if ((NtpLayer::isNTPPort(portSrc) || NtpLayer::isNTPPort(portDst)) && NtpLayer::isDataValid(sctpData, sctpDataLen))
		m_NextLayer = new NtpLayer(sctpData, sctpDataLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(sctpData, sctpDataLen, this, m_Packet);
}

void SctpLayer::computeCalculateFields()
{
	sctphdr* sctpHdr = (sctphdr*)m_Data;
	len = htobe16(m_DataLen);
	calculateChecksum(true);
}

std::string SctpLayer::toString() const
{
	std::ostringstream srcPortStream;
	srcPortStream << getSrcPort();
	std::ostringstream dstPortStream;
	dstPortStream << getDstPort();

	return "SCTP Layer, Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();
}

} // namespace pcpp
