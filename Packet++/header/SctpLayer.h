#ifndef PACKETPP_SCTP_LAYER
#define PACKETPP_SCTP_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct sctphdr
	 * Represents an SCTP protocol header
	 */
#pragma pack(push,1)
	struct sctphdr
	{
		/** Source port */
		uint16_t portSrc;
		/** Destination port */
		uint16_t portDst;
		/** Verification Tag */
		uint32_t tag;
		/**  Checksum */
		uint32_t Checksum;
	};
#pragma pack(pop)

	/**
	 * @class SctpLayer
	 * Represents an SCTP (User Datagram Protocol) protocol layer
	 */
	class SctpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref sctphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = SCTP; }
        size_t len = Layer::getLayerPayloadSize();
	    uint8_t *dt = Layer::getLayerPayload();
		/**
		 * A constructor that allocates a new SCTP header with source and destination ports
		 * @param[in] portSrc Source SCTP port address
		 * @param[in] portDst Destination SCTP port
		 */
		SctpLayer(uint16_t portSrc, uint16_t portDst);

		/**
		 * Get a pointer to the SCTP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref sctphdr
		 */
		sctphdr* getSctpHeader() const { return (sctphdr*)m_Data; }

		/**
		 * @return SCTP source port
		 */
		uint16_t getSrcPort() const;

		/**
		 * @return SCTP destination port
		 */
		uint16_t getDstPort() const;

		/**
		 * Calculate the checksum from header and data and possibly write the result to @ref sctphdr#headerChecksum
		 * @param[in] writeResultToPacket If set to true then checksum result will be written to @ref sctphdr#headerChecksum
		 * @return The checksum result
		 */
		uint16_t calculateChecksum(bool writeResultToPacket);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer, SipResponseLayer,
		 * RadiusLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref sctphdr
		 */
		size_t getHeaderLen() const { return sizeof(sctphdr); }

		/**
		 * Calculate @ref sctphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelTransportLayer; }
	    static bool isDataValid(const uint8_t *data, size_t dataLen)
	   {
		 return dataLen >= sizeof(sctphdr);
	   }
	};

} // namespace pcpp

#endif /* PACKETPP_SCTP_LAYER */