#define LOG_MODULE PacketLogModuleRipLayer

#include "RipLayer.h"
#include "EndianPortable.h"
#include "GeneralUtils.h"
#include "Logger.h"
#include "PacketUtils.h"
#include <sstream>
#include <string.h>

namespace pcpp
{
//--------------------------------RipTableEntry---------------------------------
RipTableEntry::RipTableEntry(std::istream &is)
{
	is.read((char *)&re, sizeof(RipEntry));
	prefix = arr2num(re.prefix, 4);
	mask = arr2num(re.mask, 4);
	nexthop = arr2num(re.nexthop, 4);
	metric = ntohl(re.metric);
}

void RipTableEntry::ToV1StructuredOutput(std::ostream &os)
{
	os << "RipTableEntry:" << '\n';
	os << "address family identifier: " << get_family() << '\n';
	os << "route tag: " << get_tag() << '\n';
	os << "ip address: " << num2ip(get_prefix()) << '\n';
	os << "metric: " << get_metric() << '\n';
}

void RipTableEntry::ToV2StructuredOutput(std::ostream &os)
{
	os << "RipTableEntry:" << '\n';
	os << "address family identifier: " << get_family() << '\n';
	os << "route tag: " << get_tag() << '\n';
	os << "ip address: " << num2ip(get_prefix()) << '\n';
	os << "netmask: " << num2ip(get_mask()) << '\n';
	os << "nexthop: " << num2ip(get_nexthop()) << '\n';
	os << "metric: " << get_metric() << '\n';
}

uint16_t RipTableEntry::get_family()
{
	return family;
}
uint16_t RipTableEntry::get_tag()
{
	return tag;
}
uint32_t RipTableEntry::get_prefix()
{
	return prefix;
}
uint32_t RipTableEntry::get_mask()
{
	return mask;
}
uint32_t RipTableEntry::get_nexthop()
{
	return nexthop;
}
uint32_t RipTableEntry::get_metric()
{
	return metric;
}

//--------------------------------RipLayer---------------------------------
uint8_t RipLayer::getCommand() const
{
	return getRipHeader()->command;
}

uint8_t RipLayer::getVersion() const
{
	return getRipHeader()->version;
}

uint32_t RipLayer::getRteSize() const
{
	return rtes.size();
}

std::shared_ptr<RipTableEntry> RipLayer::getRte(uint32_t index)
{
	return rtes[index];
}

void RipLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "PROTOCOLTYPE: RIP" << '\n';
	os << "command: " << (uint32_t)getCommand() << '\n'; // uint8_t有些值是不可见字符
	os << "version: " << (uint32_t)getVersion() << '\n';
	os << "total length: " << getDataLen() << '\n';
	for (auto &var : rtes)
	{
		if (getVersion() == uint8_t(1))
		{
			var->ToV1StructuredOutput(os);
		}
		else if (getVersion() == uint8_t(2))
		{
			var->ToV2StructuredOutput(os);
		}
	}
	os << std::endl;
}

void RipLayer::computeCalculateFields()
{
}

std::string RipLayer::toString() const
{

	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}

} // namespace pcpp
