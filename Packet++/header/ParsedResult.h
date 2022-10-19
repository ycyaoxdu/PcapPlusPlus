#ifndef PACKETPP_PARSEDRESULT
#define PACKETPP_PARSEDRESULT

#include <string>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

// ParsedResult is used to store results
class ParsedResult
{
	std::string m_result;

	bool m_tuplenameSet;
	std::string m_tuplename;

  public:
	ParsedResult()
	{
		m_tuplenameSet = false;
	}

	ParsedResult(std::string s) : m_result(s)
	{
		m_tuplenameSet = false;
	}

	void AppendResult(std::string s)
	{
		m_result += s;
	}

	std::string GetResult()
	{
		return m_result;
	}

	bool IsTuplenameSet()
	{
		return m_tuplenameSet;
	}
	void SetTuplename(std::string s)
	{
		if (m_tuplenameSet)
		{
			return;
		}
		m_tuplename = s;
		m_tuplenameSet = true;
		return;
	}
};

} // namespace pcpp

#endif
