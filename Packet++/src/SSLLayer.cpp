#define LOG_MODULE PacketLogModuleSSLLayer

#include "SSLLayer.h"
#include "EndianPortable.h"
#include "Logger.h"
#include <sstream>

namespace pcpp
{

// ----------------
// SSLLayer methods
// ----------------

bool SSLLayer::IsSSLMessage(uint16_t srcPort, uint16_t dstPort, uint8_t *data, size_t dataLen, bool ignorePorts)
{
	// check the port map first
	if (!ignorePorts && !isSSLPort(srcPort) && !isSSLPort(dstPort))
		return false;

	if (dataLen < sizeof(ssl_tls_record_layer))
		return false;

	ssl_tls_record_layer *recordLayer = (ssl_tls_record_layer *)data;

	// there is no SSL message with length 0
	if (recordLayer->length == 0)
		return false;

	if (recordLayer->recordType < 20 || recordLayer->recordType > 23)
		return false;

	SSLVersion::SSLVersionEnum recordVersion = SSLVersion(be16toh(recordLayer->recordVersion)).asEnum(true);

	if (recordVersion == SSLVersion::TLS1_3 || recordVersion == SSLVersion::TLS1_2 ||
		recordVersion == SSLVersion::TLS1_1 || recordVersion == SSLVersion::TLS1_0 || recordVersion == SSLVersion::SSL3)
		return true;
	else
		return false;
}

SSLLayer *SSLLayer::createSSLMessage(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
{
	ssl_tls_record_layer *recordLayer = (ssl_tls_record_layer *)data;
	switch (recordLayer->recordType)
	{
	case SSL_HANDSHAKE: {
		return new SSLHandshakeLayer(data, dataLen, prevLayer, packet);
	}

	case SSL_ALERT: {
		return new SSLAlertLayer(data, dataLen, prevLayer, packet);
	}

	case SSL_CHANGE_CIPHER_SPEC: {
		return new SSLChangeCipherSpecLayer(data, dataLen, prevLayer, packet);
	}

	case SSL_APPLICATION_DATA: {
		return new SSLApplicationDataLayer(data, dataLen, prevLayer, packet);
	}

	default:
		return NULL;
	}
}

SSLVersion SSLLayer::getRecordVersion() const
{
	uint16_t recordVersion = be16toh(getRecordLayer()->recordVersion);
	return SSLVersion(recordVersion);
}

SSLRecordType SSLLayer::getRecordType() const
{
	return (SSLRecordType)(getRecordLayer()->recordType);
}

size_t SSLLayer::getHeaderLen() const
{
	size_t len = sizeof(ssl_tls_record_layer) + be16toh(getRecordLayer()->length);
	if (len > m_DataLen)
		return m_DataLen;
	return len;
}

void SSLLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	if (SSLLayer::IsSSLMessage(0, 0, m_Data + headerLen, m_DataLen - headerLen, true))
		m_NextLayer = SSLLayer::createSSLMessage(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
}

// -------------------------
// SSLHandshakeLayer methods
// -------------------------

void SSLHandshakeLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "PROTOCOLTYPE: SSL" << '\n';
	os << "Type: "
	   << "Handshake" << '\n';
	os << "Version: " << getRecordVersion().toString(true) << '\n';
	os << "Length: " << getHeaderLen() << '\n';
	for (size_t i = 0; i < m_MessageList.size(); i++)
	{
		os << "Handshake Message: " << m_MessageList.at(i)->toString() << '\n';
	}
}

std::string SSLHandshakeLayer::toString() const
{
	/*
	std::stringstream result;
	result << getRecordVersion().toString(true) << " Layer, Handshake:";
	for(size_t i = 0; i < m_MessageList.size(); i++)
	{
		if (i == 0)
			result << " " << m_MessageList.at(i)->toString();
		else
			result << ", " << m_MessageList.at(i)->toString();
	}
	return result.str();
	*/
	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}

SSLHandshakeLayer::SSLHandshakeLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
	: SSLLayer(data, dataLen, prevLayer, packet)
{
	uint8_t *curPos = m_Data + sizeof(ssl_tls_record_layer);
	size_t recordDataLen = be16toh(getRecordLayer()->length);
	if (recordDataLen > m_DataLen - sizeof(ssl_tls_record_layer))
		recordDataLen = m_DataLen - sizeof(ssl_tls_record_layer);

	size_t curPosIndex = 0;
	while (true)
	{
		SSLHandshakeMessage *message =
			SSLHandshakeMessage::createHandshakeMessage(curPos, recordDataLen - curPosIndex, this);
		if (message == NULL)
			break;

		m_MessageList.pushBack(message);
		curPos += message->getMessageLength();
		curPosIndex += message->getMessageLength();
	}
}

SSLHandshakeMessage *SSLHandshakeLayer::getHandshakeMessageAt(int index) const
{
	if (index < 0 || index >= (int)(m_MessageList.size()))
		return NULL;

	return const_cast<SSLHandshakeMessage *>(m_MessageList.at(index));
}

// --------------------------------
// SSLChangeCipherSpecLayer methods
// --------------------------------

void SSLChangeCipherSpecLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "PROTOCOLTYPE: SSL" << '\n';
	os << "Type: "
	   << "Change Cipher Spec" << '\n';
	os << "Version: " << getRecordVersion().toString(true) << '\n';
	os << "Length: " << getHeaderLen() << '\n';
}

std::string SSLChangeCipherSpecLayer::toString() const
{
	/*
	std::stringstream result;
	result << getRecordVersion().toString(true) << " Layer, Change Cipher Spec";
	return result.str();
	*/
	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}

// ---------------------
// SSLAlertLayer methods
// ---------------------

SSLAlertLevel SSLAlertLayer::getAlertLevel() const
{
	uint8_t *pos = m_Data + sizeof(ssl_tls_record_layer);
	uint8_t alertLevel = *pos;
	if (alertLevel == SSL_ALERT_LEVEL_WARNING || alertLevel == SSL_ALERT_LEVEL_FATAL)
		return (SSLAlertLevel)alertLevel;
	else
		return SSL_ALERT_LEVEL_ENCRYPTED;
}

SSLAlertDescription SSLAlertLayer::getAlertDescription() const
{
	if (getAlertLevel() == SSL_ALERT_LEVEL_ENCRYPTED)
		return SSL_ALERT_ENCRYPTED;

	uint8_t *pos = m_Data + sizeof(ssl_tls_record_layer) + sizeof(uint8_t);
	uint8_t alertDesc = *pos;

	switch (alertDesc)
	{
	case SSL_ALERT_CLOSE_NOTIFY:
	case SSL_ALERT_UNEXPECTED_MESSAGE:
	case SSL_ALERT_BAD_RECORD_MAC:
	case SSL_ALERT_DECRYPTION_FAILED:
	case SSL_ALERT_RECORD_OVERFLOW:
	case SSL_ALERT_DECOMPRESSION_FAILURE:
	case SSL_ALERT_HANDSHAKE_FAILURE:
	case SSL_ALERT_NO_CERTIFICATE:
	case SSL_ALERT_BAD_CERTIFICATE:
	case SSL_ALERT_UNSUPPORTED_CERTIFICATE:
	case SSL_ALERT_CERTIFICATE_REVOKED:
	case SSL_ALERT_CERTIFICATE_EXPIRED:
	case SSL_ALERT_CERTIFICATE_UNKNOWN:
	case SSL_ALERT_ILLEGAL_PARAMETER:
	case SSL_ALERT_UNKNOWN_CA:
	case SSL_ALERT_ACCESS_DENIED:
	case SSL_ALERT_DECODE_ERROR:
	case SSL_ALERT_DECRYPT_ERROR:
	case SSL_ALERT_EXPORT_RESTRICTION:
	case SSL_ALERT_PROTOCOL_VERSION:
	case SSL_ALERT_INSUFFICIENT_SECURITY:
	case SSL_ALERT_INTERNAL_ERROR:
	case SSL_ALERT_USER_CANCELLED:
	case SSL_ALERT_NO_RENEGOTIATION:
		return (SSLAlertDescription)alertDesc;
		break;
	default:
		return SSL_ALERT_ENCRYPTED;
	}
}

void SSLAlertLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "PROTOCOLTYPE: SSL" << '\n';
	os << "Type: "
	   << "Alert" << '\n';
	os << "Version: " << getRecordVersion().toString(true) << '\n';
	os << "Length: " << getHeaderLen() << '\n';

	if (getAlertLevel() == SSL_ALERT_LEVEL_ENCRYPTED)
	{
		os << "Alert Level: "
		   << "Encrypted" << '\n';
	}
	else
	{
		std::string level;
		std::string description;
		switch (getAlertLevel())
		{
		case SSL_ALERT_LEVEL_WARNING:
			level = "Warning";
		case SSL_ALERT_LEVEL_FATAL:
			level = "Fatal";
		default:
			level = "Unknown";
		}
		switch (getAlertDescription())
		{
		case SSL_ALERT_CLOSE_NOTIFY:
			description = "Close Notify";
		case SSL_ALERT_UNEXPECTED_MESSAGE:
			description = "Unexpected Message";
		case SSL_ALERT_BAD_RECORD_MAC:
			description = "Bad Record Mac";
		case SSL_ALERT_DECRYPTION_FAILED:
			description = "Decryption Failed";
		case SSL_ALERT_RECORD_OVERFLOW:
			description = "Record OverFlow";
		case SSL_ALERT_DECOMPRESSION_FAILURE:
			description = "Decompression Failure";
		case SSL_ALERT_HANDSHAKE_FAILURE:
			description = "HandShake Failure";
		case SSL_ALERT_NO_CERTIFICATE:
			description = "No Certificate";
		case SSL_ALERT_BAD_CERTIFICATE:
			description = "Bad Certificate";
		case SSL_ALERT_UNSUPPORTED_CERTIFICATE:
			description = "Unsupported Cretificate";
		case SSL_ALERT_CERTIFICATE_REVOKED:
			description = "Certificate Revoked";
		case SSL_ALERT_CERTIFICATE_EXPIRED:
			description = "Certificate Expired";
		case SSL_ALERT_CERTIFICATE_UNKNOWN:
			description = "Certiificate Unknown";
		case SSL_ALERT_ILLEGAL_PARAMETER:
			description = "Illegal Parameter";
		case SSL_ALERT_UNKNOWN_CA:
			description = "Unknown CA";
		case SSL_ALERT_ACCESS_DENIED:
			description = "Access Denied";
		case SSL_ALERT_DECODE_ERROR:
			description = "Decode Error";
		case SSL_ALERT_DECRYPT_ERROR:
			description = "Decrypt Error";
		case SSL_ALERT_EXPORT_RESTRICTION:
			description = "Export Restriction";
		case SSL_ALERT_PROTOCOL_VERSION:
			description = "Protocol Version";
		case SSL_ALERT_INSUFFICIENT_SECURITY:
			description = "Insufficient Security";
		case SSL_ALERT_INTERNAL_ERROR:
			description = "Internal Error";
		case SSL_ALERT_USER_CANCELLED:
			description = "User Cancelled";
		case SSL_ALERT_NO_RENEGOTIATION:
			description = "No Renegotiation";
		default:
			description = "Encrypted";
		}
		os << "Alert Level: \t" << level << '\n';
		os << "Alert Description: \t" << description << '\n';
	}
}

std::string SSLAlertLayer::toString() const
{
	/*
	std::stringstream result;
	result << getRecordVersion().toString(true) << " Layer, ";
	if (getAlertLevel() == SSL_ALERT_LEVEL_ENCRYPTED)
		result << "Encrypted Alert";
	else
		//TODO: add alert level and description here
		result << "Alert";
	return  result.str();
	*/
	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}

// -------------------------------
// SSLApplicationDataLayer methods
// -------------------------------

uint8_t *SSLApplicationDataLayer::getEncryptedData() const
{
	if (getHeaderLen() <= sizeof(ssl_tls_record_layer))
		return NULL;

	return m_Data + sizeof(ssl_tls_record_layer);
}

size_t SSLApplicationDataLayer::getEncryptedDataLen() const
{
	int result = (int)getHeaderLen() - (int)sizeof(ssl_tls_record_layer);
	if (result < 0)
		return 0;

	return (size_t)result;
}

void SSLApplicationDataLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "PROTOCOLTYPE: SSL" << '\n';
	os << "Type: "
	   << "Application Data" << '\n';
	os << "Version: " << getRecordVersion().toString(true) << '\n';
	os << "Length: " << getHeaderLen() << '\n';
	os << "Encrypted Application Data Length: " << getEncryptedDataLen() << '\n';
	os << "Encrypted Application Data: " << (unsigned int *)getEncryptedData() << '\n';
}

std::string SSLApplicationDataLayer::toString() const
{
	/*
	return getRecordVersion().toString(true) + " Layer, Application Data";
	*/
	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}

} // namespace pcpp
