#ifndef PACKETPP_REASSEMBLY
#define PACKETPP_REASSEMBLY

#include "Layer.h"
#include "ProtocolType.h"

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
enum ReassemblyStatus
{
	Invalid,
	Handled,
};

typedef void (*OnMessageHandled)(std::string *data, std::string tuplename, void *userCookie);

ReassemblyStatus ReassembleMessage(Layer *layer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback);

// ParsedResult is used to store results
class ParsedResult
{
	std::string m_result;

	bool m_tuplenameSet = false;
	std::string m_tuplename;
  public:
	ParsedResult()
	{
	}

	ParsedResult(std::string s) : m_result(s)
	{
	}

	void Append(std::string s)
	{
		m_result += s;
	}

	std::string GetResult()
	{
		return m_result;
	}

	bool IsTuplenameSet() {
		return m_tuplenameSet;
	}
	bool SetTuplename(std::string s) {
		if (m_tuplenameSet){
			return false;
		}
		m_tuplename = s;
		m_tuplenameSet = true;
		return true;
	}
};

} // namespace pcpp

#endif // PACKETPP_UDP_REASSEMBLY
