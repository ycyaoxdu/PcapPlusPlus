#ifdef USE_DPDK

#define LOG_MODULE PcapLogModuleDpdkDevice

#define __STDC_LIMIT_MACROS
#define __STDC_FORMAT_MACROS

#include "DpdkDeviceList.h"
#include "Logger.h"

#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include <sstream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <unistd.h>

#include <ctime>
#include <time.h>

#include <arpa/inet.h>
#include <bitset>
namespace pcpp
{

bool DpdkDeviceList::m_IsDpdkInitialized = false;
CoreMask DpdkDeviceList::m_CoreMask = 0;
uint32_t DpdkDeviceList::m_MBufPoolSizePerDevice = 0;

DpdkDeviceList::DpdkDeviceList()
{
	m_IsInitialized = false;
	dz_global_Bytes_num = 0;
	dz_global_packets_num = 0;
}

DpdkDeviceList::~DpdkDeviceList()
{
	for (std::vector<DpdkDevice*>::iterator iter = m_DpdkDeviceList.begin(); iter != m_DpdkDeviceList.end(); iter++)
	{
		delete (*iter);
	}

	m_DpdkDeviceList.clear();
}

bool DpdkDeviceList::initDpdk(CoreMask coreMask, uint32_t mBufPoolSizePerDevice, uint8_t masterCore, uint32_t initDpdkArgc, char **initDpdkArgv)
{
	char **initDpdkArgvBuffer;

	if (m_IsDpdkInitialized)
	{
		if (coreMask == m_CoreMask)
			return true;
		else
		{
			PCPP_LOG_ERROR("Trying to re-initialize DPDK with a different core mask");
			RTE_LOG(ERR,APPLICATION,"Trying to re-initialize DPDK with a different core mask\n");
			return false;
		}
	}

	if (!verifyHugePagesAndDpdkDriver())
	{
		return false;
	}

	// verify mBufPoolSizePerDevice is power of 2 minus 1
	bool isPoolSizePowerOfTwoMinusOne = !(mBufPoolSizePerDevice == 0) && !((mBufPoolSizePerDevice+1) & (mBufPoolSizePerDevice));
	if (!isPoolSizePowerOfTwoMinusOne)
	{
		PCPP_LOG_ERROR("mBuf pool size must be a power of two minus one: n = (2^q - 1). It's currently: " << mBufPoolSizePerDevice);
		RTE_LOG(ERR,APPLICATION,"mBuf pool size must be a power of two minus one: n = (2^q - 1). It's currently: %d \n",mBufPoolSizePerDevice);
		return false;
	}


	std::stringstream dpdkParamsStream;
	dpdkParamsStream << "pcapplusplusapp ";
	dpdkParamsStream << "-n ";
	dpdkParamsStream << "2 ";
	dpdkParamsStream << "-c ";
	dpdkParamsStream << "0x" << std::hex << std::setw(2) << std::setfill('0') << coreMask << " ";
	dpdkParamsStream << "--master-lcore ";
	dpdkParamsStream << (int)masterCore << " ";

	uint32_t i = 0;
	while (i < initDpdkArgc && initDpdkArgv[i] != NULL)
	{
		dpdkParamsStream << initDpdkArgv[i] << " ";
		i++;
	}

	// Should be equal to the number of static params
	initDpdkArgc += 7;
	std::string dpdkParamsArray[initDpdkArgc];
	initDpdkArgvBuffer = new char*[initDpdkArgc];
	i = 0;
	while (dpdkParamsStream.good() && i < initDpdkArgc)
	{
		dpdkParamsStream >> dpdkParamsArray[i];
		initDpdkArgvBuffer[i] = new char[dpdkParamsArray[i].length()];
		strcpy(initDpdkArgvBuffer[i], dpdkParamsArray[i].c_str());
		i++;
	}

	char* lastParam = initDpdkArgvBuffer[i-1];

	for (i = 0; i < initDpdkArgc; i++)
	{
		PCPP_LOG_DEBUG("DPDK initialization params: " << initDpdkArgvBuffer[i]);
		RTE_LOG(DEBUG,APPLICATION,"DPDK initialization params: %d\n",initDpdkArgvBuffer[i]);
	}

	optind = 1;
	// init the EAL
	int ret = rte_eal_init(initDpdkArgc, (char**)initDpdkArgvBuffer);
	if (ret < 0)
	{
		PCPP_LOG_ERROR("failed to init the DPDK EAL");
		RTE_LOG(ERR,APPLICATION,"failed to init the DPDK EAL\n");
		return false;
	}

	for (i = 0; i < initDpdkArgc-1; i++)
	{
		delete [] initDpdkArgvBuffer[i];
	}
	delete [] lastParam;

	delete [] initDpdkArgvBuffer;

	m_CoreMask = coreMask;
	m_IsDpdkInitialized = true;

	m_MBufPoolSizePerDevice = mBufPoolSizePerDevice;
	// DpdkDeviceList::getInstance().setDpdkLogLevel(Logger::Info);
	return DpdkDeviceList::getInstance().initDpdkDevices(m_MBufPoolSizePerDevice);
}

bool DpdkDeviceList::initDpdkDevices(uint32_t mBufPoolSizePerDevice)
{
	if (!m_IsDpdkInitialized)
	{
		PCPP_LOG_ERROR("DPDK is not initialized!! Please call DpdkDeviceList::initDpdk(coreMask, mBufPoolSizePerDevice) before start using DPDK devices");
		RTE_LOG(ERR,APPLICATION,"DPDK is not initialized!! Please call DpdkDeviceList::initDpdk(coreMask, mBufPoolSizePerDevice) before start using DPDK devices");
		return false;
	}

	if (m_IsInitialized)
		return true;

#if (RTE_VER_YEAR < 18) || (RTE_VER_YEAR == 18 && RTE_VER_MONTH < 5)
	int numOfPorts = (int)rte_eth_dev_count();
#else
	int numOfPorts = (int)rte_eth_dev_count_avail();
#endif

	if (numOfPorts <= 0)
	{
		PCPP_LOG_ERROR("Zero DPDK ports are initialized. Something went wrong while initializing DPDK");
		RTE_LOG(ERR,APPLICATION,"Zero DPDK ports are initialized. Something went wrong while initializing DPDK");
		return false;
	}

	PCPP_LOG_DEBUG("Found " << numOfPorts << " DPDK ports. Constructing DpdkDevice for each one");
	RTE_LOG(DEBUG,APPLICATION,"Found %d DPDK ports. Constructing DpdkDevice for each one",numOfPorts);

	// Initialize a DpdkDevice per port
	for (int i = 0; i < numOfPorts; i++)
	{
		DpdkDevice* newDevice = new DpdkDevice(i, mBufPoolSizePerDevice);
		PCPP_LOG_DEBUG("DpdkDevice #" << i << ": Name='" << newDevice->getDeviceName() << "', PCI-slot='" << newDevice->getPciAddress() << "', PMD='" << newDevice->getPMDName() << "', MAC Addr='" << newDevice->getMacAddress() << "'");
		RTE_LOG(DEBUG,APPLICATION,"DpdkDevice # %d: Name='%s', PCI-slot='%s', PMD='%s', MAC Addr='%s'",i,newDevice->getDeviceName(),newDevice->getPciAddress(),newDevice->getPMDName(),newDevice->getMacAddress());
		m_DpdkDeviceList.push_back(newDevice);
	}

	m_IsInitialized = true;
	return true;
}

DpdkDevice* DpdkDeviceList::getDeviceByPort(int portId) const
{
	if (!isInitialized())
	{
		PCPP_LOG_ERROR("DpdkDeviceList not initialized");
		RTE_LOG(ERR,APPLICATION,"DpdkDeviceList not initialized");
		return NULL;
	}

	if ((uint32_t)portId >= m_DpdkDeviceList.size())
	{
		return NULL;
	}

	return m_DpdkDeviceList.at(portId);
}

DpdkDevice* DpdkDeviceList::getDeviceByPciAddress(const std::string& pciAddr) const
{
	if (!isInitialized())
	{
		PCPP_LOG_ERROR("DpdkDeviceList not initialized");
		RTE_LOG(ERR,APPLICATION,"DpdkDeviceList not initialized");
		return NULL;
	}

	for (std::vector<DpdkDevice*>::const_iterator iter = m_DpdkDeviceList.begin(); iter != m_DpdkDeviceList.end(); iter++)
	{
		if ((*iter)->getPciAddress() == pciAddr)
			return (*iter);
	}

	return NULL;
}

bool DpdkDeviceList::verifyHugePagesAndDpdkDriver()
{
	std::string execResult = executeShellCommand("cat /proc/meminfo | grep -s HugePages_Total | awk '{print $2}'");
	// trim '\n' at the end
	execResult.erase(std::remove(execResult.begin(), execResult.end(), '\n'), execResult.end());

	// convert the result to long
	char* endPtr;
	long totalHugePages = strtol(execResult.c_str(), &endPtr, 10);

	PCPP_LOG_DEBUG("Total number of huge-pages is " << totalHugePages);
	RTE_LOG(DEBUG,APPLICATION,"Total number of huge-pages is\n",totalHugePages);

	if (totalHugePages <= 0)
	{
		PCPP_LOG_ERROR("Huge pages aren't set, DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
		RTE_LOG(ERR,APPLICATION,"Huge pages aren't set, DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
		return false;
	}

	execResult = executeShellCommand("lsmod | grep -s igb_uio");
	if (execResult == "")
	{
		execResult = executeShellCommand("modinfo -d uio_pci_generic");
		if (execResult.find("ERROR") != std::string::npos)
		{
			execResult = executeShellCommand("modinfo -d vfio-pci");
			if (execResult.find("ERROR") != std::string::npos)
			{
				PCPP_LOG_ERROR("None of igb_uio, uio_pci_generic, vfio-pci kernel modules are loaded so DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
				RTE_LOG(ERR,APPLICATION,"None of igb_uio, uio_pci_generic, vfio-pci kernel modules are loaded so DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
				return false;
			}
			else
			{
				PCPP_LOG_DEBUG("vfio-pci module is loaded");
				RTE_LOG(DEBUG,APPLICATION,"vfio-pci module is loaded\n");
			}
		}
		else
		{
			PCPP_LOG_DEBUG("uio_pci_generic module is loaded");
			RTE_LOG(DEBUG,APPLICATION,"uio_pci_generic module is loaded\n");
		}
	}
	else
		PCPP_LOG_DEBUG("igb_uio driver is loaded");
		RTE_LOG(DEBUG,APPLICATION,"igb_uio driver is loaded\n");

	return true;
}

SystemCore DpdkDeviceList::getDpdkMasterCore() const
{
	return SystemCores::IdToSystemCore[rte_get_master_lcore()];
}

void DpdkDeviceList::setDpdkLogLevel(Logger::LogLevel logLevel)
{
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
	if (logLevel == Logger::Info)
		rte_log_set_global_level(RTE_LOG_NOTICE);
	else // logLevel == Logger::Debug
		rte_log_set_global_level(RTE_LOG_DEBUG);
#else
	if (logLevel == Logger::Info)
		rte_set_log_level(RTE_LOG_NOTICE);
	else // logLevel == Logger::Debug
		rte_set_log_level(RTE_LOG_DEBUG);
#endif
}

Logger::LogLevel DpdkDeviceList::getDpdkLogLevel() const
{
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
	if (rte_log_get_global_level() <= RTE_LOG_NOTICE)
#else
	if (rte_get_log_level() <= RTE_LOG_NOTICE)
#endif
		return Logger::Info;
	else
		return Logger::Debug;
}

bool DpdkDeviceList::writeDpdkLogToFile(FILE* logFile)
{
	return (rte_openlog_stream(logFile) == 0);
}

int DpdkDeviceList::dpdkWorkerThreadStart(void *ptr)
{
	DpdkWorkerThread* workerThread = (DpdkWorkerThread*)ptr;
	workerThread->run(rte_lcore_id());
	return 0;
}

bool DpdkDeviceList::startDpdkWorkerThreads(CoreMask coreMask, std::vector<DpdkWorkerThread*>& workerThreadsVec)
{
	if (!isInitialized())
	{
		PCPP_LOG_ERROR("DpdkDeviceList not initialized");
		RTE_LOG(ERR,APPLICATION,"DpdkDeviceList not initialized\n");
		return false;
	}

	CoreMask tempCoreMask = coreMask;
	size_t numOfCoresInMask = 0;
	int coreNum = 0;
	while (tempCoreMask > 0)
	{
		std::cout<<"tempCoreMask "<<tempCoreMask<<std::endl; 
		if (tempCoreMask & 1)
		{
			if (!rte_lcore_is_enabled(coreNum))
			{
				PCPP_LOG_ERROR("Trying to use core #" << coreNum << " which isn't initialized by DPDK");
				RTE_LOG(ERR,APPLICATION,"Trying to use core # %d which isn't initialized by DPDK",coreNum);
				return false;
			}

			numOfCoresInMask++;
		}
		tempCoreMask = tempCoreMask >> 1;
		coreNum++;
	}

	if (numOfCoresInMask == 0)
	{
		PCPP_LOG_ERROR("Number of cores in mask is 0");
		RTE_LOG(ERR,APPLICATION,"Number of cores in mask is 0\n");
		return false;
	}

	if (numOfCoresInMask != workerThreadsVec.size())
	{
		std::cout<<numOfCoresInMask<<" "<<workerThreadsVec.size()<<std::endl;
		PCPP_LOG_ERROR("Number of cores in core mask different from workerThreadsVec size");
		RTE_LOG(ERR,APPLICATION,"Number of cores in core mask different from workerThreadsVec size\n");
		return false;
	}

	if (coreMask & getDpdkMasterCore().Mask)
	{
		PCPP_LOG_ERROR("Cannot run worker thread on DPDK master core");
		RTE_LOG(ERR,APPLICATION,"Cannot run worker thread on DPDK master core\n");
		return false;
	}

	m_WorkerThreads.clear();
	uint32_t index = 0;
	std::vector<DpdkWorkerThread*>::iterator iter = workerThreadsVec.begin();
	while (iter != workerThreadsVec.end())
	{
		SystemCore core = SystemCores::IdToSystemCore[index];
		if (!(coreMask & core.Mask))
		{
			index++;
			continue;
		}
		std::cout<< "In DpdkDeviceList::startDpdkWorkerThreads: core "<< core.Id <<" 启动"<<std::endl;
		RTE_LOG(INFO,APPLICATION,"In DpdkDeviceList::startDpdkWorkerThreads: core %d 启动",core.Id);
		int err = rte_eal_remote_launch(dpdkWorkerThreadStart, *iter, core.Id);
		if (err != 0)
		{
			for (std::vector<DpdkWorkerThread*>::iterator iter2 = workerThreadsVec.begin(); iter2 != iter; iter2++)
			{
				(*iter)->stop();
				rte_eal_wait_lcore((*iter)->getCoreId());
				PCPP_LOG_DEBUG("Thread on core [" << (*iter)->getCoreId() << "] stopped");
				RTE_LOG(DEBUG,APPLICATION,"Thread on core [ %d ] stopped\n",(*iter)->getCoreId());
			}
			PCPP_LOG_ERROR("Cannot create worker thread #" << core.Id << ". Error was: [" << strerror(err) << "]");
			RTE_LOG(ERR,APPLICATION,"Cannot create worker thread #  %d . Error was: [ %s ]",core.Id,strerror(err));
			return false;
		}
		m_WorkerThreads.push_back(*iter);

		index++;
		iter++;
	}

	

	return true;
}

void DpdkDeviceList::Collect_Application_status()
{
	for (std::vector<DpdkWorkerThread*>::iterator iter = m_WorkerThreads.begin(); iter != m_WorkerThreads.end(); iter++)
	{
		uint64_t temp_local_packets_num =(*iter)->dz_get_local_packets_num();
		uint128_t temp_local_Bytes_num = (*iter)->dz_get_local_Bytes_num();
		// RTE_LOG(INFO,APPLICATION,"core %d received %d  packets %lld  bytes.\n",(*iter)->getCoreId(),temp_local_packets_num, temp_local_Bytes_num);
		dz_global_packets_num += temp_local_packets_num;
		dz_global_Bytes_num += temp_local_Bytes_num;		
	} 
}

void DpdkDeviceList::Reset_Application_status()
{
	for (std::vector<DpdkWorkerThread*>::iterator iter = m_WorkerThreads.begin(); iter != m_WorkerThreads.end(); iter++)
	{
		(*iter)->dz_reset_local_status();
		
		// RTE_LOG(INFO,APPLICATION,"core %d received %d  packets %lld  bytes.\n",(*iter)->getCoreId(),temp_local_packets_num, temp_local_Bytes_num);
		dz_global_packets_num =0;
		dz_global_Bytes_num =0;		
	} 
}

void DpdkDeviceList::stopDpdkWorkerThreads()
{
	if (m_WorkerThreads.empty())
	{
		PCPP_LOG_ERROR("No worker threads were set");
		RTE_LOG(ERR,APPLICATION,"No worker threads were set\n");
		return;
	}

	
	for (std::vector<DpdkWorkerThread*>::iterator iter = m_WorkerThreads.begin(); iter != m_WorkerThreads.end(); iter++)
	{
		// int temp_local_packets_num =(*iter)->dz_get_local_packets_num();
		// long long temp_local_Bytes_num = (*iter)->dz_get_local_Bytes_num();
		// RTE_LOG(INFO,APPLICATION,"core %d received %d  packets %lld  bytes.\n",(*iter)->getCoreId(),temp_local_packets_num, temp_local_Bytes_num);
		// dz_global_packets_num += temp_local_packets_num;
		// dz_global_Bytes_num += temp_local_Bytes_num;
		 
		(*iter)->stop();
		rte_eal_wait_lcore((*iter)->getCoreId());
		PCPP_LOG_DEBUG("Thread on core [" << (*iter)->getCoreId() << "] stopped");
		RTE_LOG(DEBUG,APPLICATION,"Thread on core [ %d ] stopped",(*iter)->getCoreId());
	} 

	m_WorkerThreads.clear();
	std::vector<DpdkWorkerThread*>(m_WorkerThreads).swap(m_WorkerThreads);
    
	
	PCPP_LOG_DEBUG("All worker threads stopped");
}

} // namespace pcpp

#endif /* USE_DPDK */
