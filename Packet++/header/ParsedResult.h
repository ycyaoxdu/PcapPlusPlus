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

	int IpLayerCount;
	int v4LayerCount;
	int v6LayerCount;
	bool notFirstIPLayer;
	bool isLastIPLayer;
	bool isNextV4;
	bool isNextV6;

  public:
	ParsedResult() : m_tuplenameSet(false), IpLayerCount(0)
	{
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
	std::string GetTuplename()
	{
		return m_tuplename;
	}

	void CountV4()
	{
		v4LayerCount++;
		IpLayerCount++;
	}
	void CountV6()
	{
		v6LayerCount++;
		IpLayerCount++;
	}
	void UnsetFirst()
	{
		notFirstIPLayer = true;
	}
	void SetLast()
	{
		isLastIPLayer = true;
	}

	int getIPLayerCount()
	{
		return IpLayerCount;
	}
	int getV4LayerCount()
	{
		return v4LayerCount;
	}
	int getV6LayerCount()
	{
		return v6LayerCount;
	}
	bool isFirst()
	{
		return !notFirstIPLayer;
	}
	bool isLast()
	{
		return isLastIPLayer;
	}

	void setNextLayerV4()
	{
		isNextV4 = true;
		isNextV6 = false;
	}
	void setNextLayerV6()
	{
		isNextV4 = false;
		isNextV6 = true;
	}
	bool isNextLayerV4()
	{
		return isNextV4;
	}
	bool isNextLayerV6()
	{
		return isNextV6;
	}
};

} // namespace pcpp

#endif
