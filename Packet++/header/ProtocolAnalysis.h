#ifndef PCAPPP_PROTOCOL_ANALYSIS
#define PCAPPP_PROTOCOL_ANALYSIS

#ifndef LOG_MODULE
#define LOG_MODULE pcpp::ProtocolAnalysis
#endif

#include "BgpLayer.h"
#include "GreLayer.h"
#include "GtpLayer.h"
#include "HttpLayer.h"
#include "IPReassembly.h"
#include "IPSecLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "IpAddress.h"
#include "L2tpLayer.h"
#include "LRUList.h"
#include "Logger.h"
#include "OspfLayer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PcapPlusPlusVersion.h"
#include "ProtocolType.h"
#include "Reassembly.h"
#include "RipLayer.h"
#include "SSLLayer.h"
#include "SctpLayer.h"
#include "SystemUtils.h"
#include "TcpLayer.h"
#include "TcpReassembly.h"
#include "UdpLayer.h"
#include "getopt.h"
#include <algorithm>
#include <getopt.h>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <unistd.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#if defined(_WIN32)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif

// unless the user chooses otherwise - default number of concurrent used file descl2tptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 50000

/**
 * Print application usage
 */
void printUsage()
{
	std::cout
		<< std::endl
		<< "Usage:" << std::endl
		<< "------" << std::endl
		<< pcpp::AppName::get()
		<< " input_file -o output_file [-p max-packet-number] [-d frag_ids] [-f bpf_filter][-b] [-a] [-h] [-v]"
		<< std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    input_file      	: Input pcap/pcapng file" << std::endl
		<< "    -o output_file  	: Output file. Output file type (pcap/pcapng) will match the input file type"
		<< std::endl
		<< "    -p max-packet-number: Number of ip packets to store, Default to 500000" << std::endl
		<< "    -d frag_ids     	: De-fragment only fragments that match this comma-separated list of IP IDs (for "
		   "IPv4) or"
		<< std::endl
		<< "                      fragment IDs (for IPv6) in decimal format" << std::endl
		<< "    -f bpf_filter   	: De-fragment only fragments that match bpf_filter. Filter should be provided in "
		   "Berkeley Packet Filter (BPF)"
		<< std::endl
		<< "                      syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'" << std::endl
		<< "	-b 					: Run with debug mode if flag is set" << std::endl
		<< "    -v              	: Displays the current version and exits" << std::endl
		<< "    -h              	: Displays this help message and exits" << std::endl
		<< std::endl;
}

/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the
 * application
 */
class GlobalConfig
{
  private:
	/**
	 * A private c'tor (as this is a singleton)
	 */
	GlobalConfig()
	{
		writeMetadata = false;
		writeToConsole = false;
		maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
		m_RecentFilesWithActivity = NULL;
	}

	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key.
	// This LRU list is used to decide which connection was seen least recently in case we reached max number of open
	// file descl2tptors and we need to decide which files to close
	pcpp::LRUList<std::string> *m_RecentFilesWithActivity;

  public:
	// calculate processed packet numbers
	int PacketNum;

	// a flag indicating whether to write a metadata file for each connection (containing several stats)
	bool writeMetadata;

	// the directory to write files to (default is current directory)
	std::string outputDir;

	// a flag indicating whether to write L2TP data to actual files or to console
	bool writeToConsole;

	// max number of allowed open files in each point in time
	size_t maxOpenFiles;

	std::string getFileName(std::string name)
	{
		std::stringstream stream;

		// if user chooses to write to a directory other than the current directory - add the dir path to the return
		// value
		if (!outputDir.empty())
			stream << outputDir << SEPARATOR;

		stream << name;

		// return the file path
		return stream.str();
	}

	/**
	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file
	 * or overwrite it. Return value is a pointer to the new file stream
	 */
	std::ostream *openFileStream(std::string fileName, bool reopen)
	{
		// if the user chooses to write only to console, don't open anything and return std::cout
		if (writeToConsole)
			return &std::cout;

		// open the file on the disk (with append or overwrite mode)
		if (reopen)
			return new std::ofstream(fileName.c_str(), std::ios_base::binary | std::ios_base::app);
		else
			return new std::ofstream(fileName.c_str(), std::ios_base::binary);
	}

	/**
	 * Close a file stream
	 */
	void closeFileSteam(std::ostream *fileStream)
	{
		// if the user chooses to write only to console - do nothing and return
		if (!writeToConsole)
		{
			// close the file stream
			std::ofstream *fstream = (std::ofstream *)fileStream;
			fstream->close();

			// free the memory of the file stream
			delete fstream;
		}
	}

	pcpp::LRUList<std::string> *getRecentFilesWithActivity()
	{
		// This is a lazy implementation - the instance isn't created until the user requests it for the first time.
		// the side of the LRU list is determined by the max number of allowed open files at any point in time. Default
		// is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES but the user can choose another number
		if (m_RecentFilesWithActivity == NULL)
			m_RecentFilesWithActivity = new pcpp::LRUList<std::string>(maxOpenFiles);

		// return the pointer
		return m_RecentFilesWithActivity;
	}

	/**
	 * The singleton implementation of this class
	 */
	static GlobalConfig &getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
};

// 存储某一五元组的数据包
/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats
 * data on the connection
 */
struct ReassemblyData
{
	std::ostream *fileStream;

	// flags indicating whether the file was already opened before. If the answer is yes, next time it'll
	// be opened in append mode (and not in overwrite mode)
	bool reopenFileStream;

	// stats data: num of data packets, bytes
	int numOfDataPackets;
	int bytes;

	/**
	 * the default c'tor
	 */
	ReassemblyData()
	{
		fileStream = NULL;
		clear();
	}

	/**
	 * The default d'tor
	 */
	~ReassemblyData()
	{
		// close files on both sides if open
		if (fileStream != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStream);
	}

	/**
	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
	 */
	void clear()
	{
		// for the file stream - close them if they're not null
		if (fileStream != NULL)
		{
			GlobalConfig::getInstance().closeFileSteam(fileStream);
			fileStream = NULL;
		}

		reopenFileStream = false;
		numOfDataPackets = 0;
		bytes = 0;
	}
};

/**
 * A struct to contain all data save on a specific connection.
 */
struct TcpReassemblyData
{
	// a flag indicating on which side was the latest message on this connection
	int8_t curSide;

	// stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
	int numOfDataPackets[2];
	int numOfMessagesFromSide[2];
	int bytesFromSide[2];

	/**
	 * the default c'tor
	 */
	TcpReassemblyData()
	{
		clear();
	}

	/**
	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
	 */
	void clear()
	{
		numOfDataPackets[0] = 0;
		numOfDataPackets[1] = 0;
		numOfMessagesFromSide[0] = 0;
		numOfMessagesFromSide[1] = 0;
		bytesFromSide[0] = 0;
		bytesFromSide[1] = 0;
		curSide = -1;
	}
};

// 五元组->数据统计的map
// typedef representing the manager and its iterator
typedef std::map<std::string, ReassemblyData> ReassemblyMgr;
typedef std::map<std::string, ReassemblyData>::iterator ReassemblyMgrIter;

// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;
typedef std::map<uint32_t, TcpReassemblyData>::iterator TcpReassemblyConnMgrIter;

static void OnMessageReadyCallback(std::string *data, std::string tuplename, void *userCookie)
{
	/* 	1. manager 存 ReassemblyData   									yes
		2. manager 的指定 ReassemblyData 里边fileStream 是否为NULL
			2.1 将当前（指传入的参数）的名称加入opened列表
			2.2 如果打开的文件已达上限，关闭目前的
			2.3 设置文件名
			2.4 打开文件， 模式由之前2.2设置的reopenFileStreams决定
		3. 更改ReassemblyData里的统计值
		4. 将数据写入打开的文件里
	 */

	// 1.

	// extract the manager from the user cookie
	ReassemblyMgr *mgr = (ReassemblyMgr *)userCookie;

	// check if this tuple already appears in the manager. If not add it
	ReassemblyMgrIter iter = mgr->find(tuplename);
	if (iter == mgr->end())
	{
		mgr->insert(std::make_pair(tuplename, ReassemblyData()));
		iter = mgr->find(tuplename);
	}

	// 2.

	//  if filestream isn't open yet
	if (iter->second.fileStream == NULL)
	{
		// 2.1

		std::string nameToCloseFile;
		int result = GlobalConfig::getInstance().getRecentFilesWithActivity()->put(tuplename, &nameToCloseFile);

		// 2.2

		// 等于1，需要关闭最近未使用
		if (result == 1)
		{
			ReassemblyMgrIter iter2 = mgr->find(nameToCloseFile);
			if (iter2 != mgr->end())
			{
				if (iter2->second.fileStream != NULL)
				{
					// close the file
					GlobalConfig::getInstance().closeFileSteam(iter2->second.fileStream);
					iter2->second.fileStream = NULL;

					// set the reopen flag to true to indicate that next time this file will be opened it will be opened
					// in append mode (and not overwrite mode)
					iter2->second.reopenFileStream = true;
				}
			}
		}

		// 2.3

		// get the file name according to the 5-tuple etc.
		std::string name = tuplename + ".txt";
		std::string fileName = GlobalConfig::getInstance().getFileName(name);

		// 2.4

		// open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was
		// already opened before)
		iter->second.fileStream = GlobalConfig::getInstance().openFileStream(fileName, iter->second.reopenFileStream);
	}

	// 3.

	// count number of packets and bytes
	iter->second.numOfDataPackets++;

	// set new processed packet number
	GlobalConfig::getInstance().PacketNum++;

	// 4.

	// write the new data to the file
	*iter->second.fileStream << *data << std::endl;
}

/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie,
										  pcpp::Packet *tcpPacket, pcpp::Layer *nextLayer, pcpp::IPAddress *IpSrc,
										  pcpp::IPAddress *IpDst, void *UserCookie,
										  std::queue<pcpp::RawPacket> *quePointer)
{
	// extract the connection manager from the user cookie
	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

	// check if this flow already appears in the connection manager. If not add it
	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
	}

	// if this messages comes on a different side than previous message seen on this connection
	if (sideIndex != iter->second.curSide)
	{
		// count number of message in each side
		iter->second.numOfMessagesFromSide[sideIndex]++;

		// set side index as the current active side
		iter->second.curSide = sideIndex;
	}

	// count number of packets and bytes in each side of the connection
	iter->second.numOfDataPackets[sideIndex]++;
	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

	// handle the tcp packet
	HandleTcpPayload(nextLayer, *IpSrc, *IpDst, tcpPacket, UserCookie, OnMessageReadyCallback, quePointer);
}

/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the
 * connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData &connectionData, void *userCookie)
{
	// get a pointer to the connection manager
	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

	// look for the connection in the connection manager
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// assuming it's a new connection
	if (iter == connMgr->end())
	{
		// add it to the connection manager
		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
	}
}

/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the
 * connection from the connection manager and writes the metadata file if requested by the user
 */
static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData &connectionData,
											   pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie)
{
	// get a pointer to the connection manager
	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

	// find the connection in the connection manager by the flow key
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// connection wasn't found - shouldn't get here
	if (iter == connMgr->end())
		return;

	// remove the connection from the connection manager
	connMgr->erase(iter);
}

/**
 * This method reads packets from the input file, decided which fragments pass the filters set by the user, de-fragment
 * the fragments who pass them, and writes the result packets to the output file
 */

void processPackets(size_t maxPacketsToStore, pcpp::IFileReaderDevice *reader, bool filterByBpf, std::string bpfFilter,
					bool filterByIpID, std::map<uint32_t, bool> fragIDs, pcpp::DefragStats *stats, void *UserCookie,
					pcpp::TcpReassembly &tcpReassembly, std::queue<pcpp::RawPacket> *quePointer)
{
	PCPP_LOG_DEBUG("ip packet process started");

	pcpp::RawPacket rawPacket;
	pcpp::BPFStringFilter filter(bpfFilter);

	// create an instance of IPReassembly
	pcpp::IPReassembly ipReassembly(NULL, NULL, maxPacketsToStore);
	pcpp::IPReassembly::ReassemblyStatus status;

	while (!quePointer->empty() || reader->getNextPacket(rawPacket))
	{
		PCPP_LOG_DEBUG("read a ip packet from queue");

		if (!quePointer->empty())
		{
			rawPacket = quePointer->front();
			quePointer->pop();
		}

		bool defragPacket = true;

		stats->totalPacketsRead++;

		// if user requested to filter by BPF
		if (filterByBpf)
		{
			// check if packet matches the BPF filter supplied by the user
			if (pcpp::IPcapDevice::matchPacketWithFilter(filter, &rawPacket))
			{
				stats->ipPacketsMatchBpfFilter++;
			}
			else // if not - set the packet as not marked for de-fragmentation
			{
				defragPacket = false;
			}
		}

		// check if packet is of type IPv4 or IPv6
		pcpp::Packet parsedPacket(&rawPacket);
		if (parsedPacket.isPacketOfType(pcpp::IPv4))
		{
			stats->ipv4Packets++;
		}
		else if (parsedPacket.isPacketOfType(pcpp::IPv6))
		{
			stats->ipv6Packets++;
		}
		else // if not - set the packet as not marked for de-fragmentation
		{
			defragPacket = false;
		}

		// if user requested to filter by IP ID
		if (filterByIpID)
		{
			// get the IPv4 layer
			pcpp::IPv4Layer *ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if (ipv4Layer != NULL)
			{
				// check if packet ID matches one of the IP IDs requested by the user
				if (fragIDs.find((uint32_t)pcpp::netToHost16(ipv4Layer->getIPv4Header()->ipId)) != fragIDs.end())
				{
					stats->ipv4PacketsMatchIpIDs++;
				}
				else // if not - set the packet as not marked for de-fragmentation
				{
					defragPacket = false;
				}
			}

			// get the IPv6 layer
			pcpp::IPv6Layer *ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
			if (ipv6Layer != NULL && ipv6Layer->isFragment())
			{
				// if this packet is a fragment, get the fragmentation header
				pcpp::IPv6FragmentationHeader *fragHdr = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();

				// check if fragment ID matches one of the fragment IDs requested by the user
				if (fragIDs.find(pcpp::netToHost32(fragHdr->getFragHeader()->id)) != fragIDs.end())
				{
					stats->ipv6PacketsMatchFragIDs++;
				}
				else // if not - set the packet as not marked for de-fragmentation
				{
					defragPacket = false;
				}
			}
		}

		// if fragment is marked for de-fragmentation
		if (defragPacket)
		{
			stats->totalPacketsWritten++;

			pcpp::ReassemblyStatus reassemblePacketStatus = Reassemble(
				&ipReassembly, &status, quePointer, &parsedPacket, UserCookie, OnMessageReadyCallback, tcpReassembly);

			// TODO(ycyaoxdu): handle status
			PCPP_LOG_DEBUG("got reassemble status: " << reassemblePacketStatus);
		}
		// if packet isn't marked for de-fragmentation but the user asked to write all packets to output file
		else
		{
			stats->totalPacketsWritten++;
		}
	}

	PCPP_LOG_DEBUG("finished process ip packet");
}

#endif