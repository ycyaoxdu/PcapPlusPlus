
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

#include "ProtocolAnalysis.h"

#define DEFAULT_MAX_PACKETS_TO_STORE 500000

// queue to cache ip packets
std::queue<pcpp::RawPacket> q;
std::queue<pcpp::RawPacket> *quePointer = &q;

static struct option DefragUtilOptions[] = {{"output-file", required_argument, 0, 'o'},
											{"max-packet-number", required_argument, 0, 'p'},
											{"filter-by-ipid", required_argument, 0, 'd'},
											{"bpf-filter", required_argument, 0, 'f'},
											{"debug-mode", no_argument, 0, 'b'},
											{"help", no_argument, 0, 'h'},
											{"version", no_argument, 0, 'v'},
											{0, 0, 0, 0}};

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
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
			  << "Built: " << pcpp::getBuildDateTime() << std::endl
			  << "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}

/**
 * A method for printing fragmentation process stats
 */
void printStats(const pcpp::DefragStats &stats, bool filterByIpID, bool filterByBpf)
{
	std::ostringstream stream;
	stream << "Summary:\n";
	stream << "========\n";
	stream << "Total packets read:                      " << stats.totalPacketsRead << std::endl;
	stream << "IPv4 packets read:                       " << stats.ipv4Packets << std::endl;
	stream << "IPv6 packets read:                       " << stats.ipv6Packets << std::endl;
	if (filterByIpID)
	{
		stream << "IPv4 packets match fragment ID list:     " << stats.ipv4PacketsMatchIpIDs << std::endl;
		stream << "IPv6 packets match fragment ID list:     " << stats.ipv6PacketsMatchFragIDs << std::endl;
	}
	if (filterByBpf)
		stream << "IP packets match BPF filter:             " << stats.ipPacketsMatchBpfFilter << std::endl;
	stream << "Total packets written to output file:    " << stats.totalPacketsWritten << std::endl;

	std::cout << stream.str();
}

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	bool debug = false;
	size_t maxPacketsToStore = DEFAULT_MAX_PACKETS_TO_STORE;
	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
	std::string outputDir = "";

	bool filterByBpfFilter = false;
	std::string bpfFilter = "";
	bool filterByFragID = false;
	std::map<uint32_t, bool> fragIDMap;

	while ((opt = getopt_long(argc, argv, "o:p:d:f:bhv", DefragUtilOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0: {
			break;
		}
		case 'o': {
			outputDir = optarg;
			break;
		}
		case 'p': {
			maxOpenFiles = (size_t)atoi(optarg);
			break;
		}
		case 'd': {
			filterByFragID = true;
			// read the IP ID / Frag ID list into the map
			fragIDMap.clear();
			std::string ipIDsAsString = std::string(optarg);
			std::stringstream stream(ipIDsAsString);
			std::string ipIDStr;
			// break comma-separated string into string list
			while (std::getline(stream, ipIDStr, ','))
			{
				// convert the IP ID to uint16_t
				uint32_t fragID = (uint32_t)atoi(ipIDStr.c_str());
				// add the frag ID into the map if it doesn't already exist
				if (fragIDMap.find(fragID) == fragIDMap.end())
					fragIDMap[fragID] = true;
			}

			// verify list is not empty
			if (fragIDMap.empty())
			{
				EXIT_WITH_ERROR("Couldn't parse fragment ID list");
			}
			break;
		}
		case 'f': {
			filterByBpfFilter = true;
			bpfFilter = optarg;
			pcpp::BPFStringFilter filter(bpfFilter);
			if (!filter.verifyFilter())
				EXIT_WITH_ERROR("Illegal BPF filter");
			break;
		}
		case 'b': {
			debug = true;
			break;
		}
		case 'h': {
			printUsage();
			exit(0);
		}
		case 'v': {
			printAppVersion();
			break;
		}
		}
	}

	std::string inputFile = "";

	int expectedParams = 1;
	int paramIndex = -1;

	for (int i = optind; i < argc; i++)
	{
		paramIndex++;
		if (paramIndex > expectedParams)
			EXIT_WITH_ERROR("Unexpected parameter: " << argv[i]);

		switch (paramIndex)
		{
		case 0: {
			inputFile = argv[i];
			break;
		}

		default:
			EXIT_WITH_ERROR("Unexpected parameter: " << argv[i]);
		}
	}

	if (inputFile == "")
	{
		EXIT_WITH_ERROR("Input file name was not given");
	}

	// verify output dir exists
	if (!outputDir.empty() && !pcpp::directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

	// create the object which manages info
	ReassemblyMgr mgr;

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;

	// create the TCP reassembly instance
	pcpp::TcpReassembly tcpReassembly(q, tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback,
									  tcpReassemblyConnectionEndCallback);

	// set the info manager for tcpReassembly
	tcpReassembly.SetHandleCookie(&mgr);

	// create a reader device from input file
	pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(inputFile);

	if (!reader->open())
	{
		EXIT_WITH_ERROR("Error opening input file");
	}

	// enable debug if flag is set
	if (debug)
	{
		pcpp::Logger::getInstance().setAllModlesToLogLevel(pcpp::Logger::Debug);
		PCPP_LOG_DEBUG("Debug mode enabled");
	}

	// run the de-fragmentation process
	pcpp::DefragStats stats;

	processPackets(maxPacketsToStore, reader, filterByBpfFilter, bpfFilter, filterByFragID, fragIDMap, &stats, &mgr,
				   tcpReassembly, quePointer);

	std::cout << "closing......" << std::endl;
	// close all tcp connections
	tcpReassembly.closeAllConnections();
	std::cout << "closed......" << std::endl;

	// close files
	reader->close();

	// print summary stats to console
	printStats(stats, filterByFragID, filterByBpfFilter);

	delete reader;
}
