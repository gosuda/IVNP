package foundation

import (
	"gosuda.org/ivnp/foundation/internal/i2np"
	"gosuda.org/ivnp/foundation/internal/netdb"
)

type (
	I2NPBuildRecords                     = i2np.BuildRecords
	I2NPDataMessage                      = i2np.DataMessage
	I2NPDatabaseLookupMessage            = i2np.DatabaseLookupMessage
	I2NPDatabaseSearchReplyMessage       = i2np.DatabaseSearchReplyMessage
	I2NPDatabaseStoreMessage             = i2np.DatabaseStoreMessage
	I2NPDeliveryStatusMessage            = i2np.DeliveryStatusMessage
	I2NPGarlicMessage                    = i2np.GarlicMessage
	I2NPHeader                           = i2np.Header
	I2NPMessage                          = i2np.Message
	I2NPMessageType                      = i2np.MessageType
	I2NPShortHeader                      = i2np.ShortHeader
	I2NPStoreType                        = i2np.StoreType
	I2NPTransportHeader                  = i2np.TransportHeader
	I2NPTunnelDataMessage                = i2np.TunnelDataMessage
	I2NPTunnelGatewayMessage             = i2np.TunnelGatewayMessage
	NetworkDatabaseEncryptedLeaseSet     = netdb.EncryptedLeaseSet
	NetworkDatabaseEncryptionKey         = netdb.EncryptionKey
	NetworkDatabaseEncryptionKeyIterator = netdb.EncryptionKeyIterator
	NetworkDatabaseLease                 = netdb.Lease
	NetworkDatabaseLease2                = netdb.Lease2
	NetworkDatabaseLease2Iterator        = netdb.Lease2Iterator
	NetworkDatabaseLeaseIterator         = netdb.LeaseIterator
	NetworkDatabaseLeaseSet              = netdb.LeaseSet
	NetworkDatabaseLeaseSet2             = netdb.LeaseSet2
	NetworkDatabaseLeaseSet2Header       = netdb.LeaseSet2Header
	NetworkDatabaseMetaLease             = netdb.MetaLease
	NetworkDatabaseMetaLeaseIterator     = netdb.MetaLeaseIterator
	NetworkDatabaseMetaLeaseSet          = netdb.MetaLeaseSet
	NetworkDatabaseOfflineSignature      = netdb.OfflineSignature
	NetworkDatabaseRouterAddress         = netdb.RouterAddress
	NetworkDatabaseRouterAddressIterator = netdb.RouterAddressIterator
	NetworkDatabaseRouterInfo            = netdb.RouterInfo
)

const (
	I2NPBuildRecordLen                           = i2np.BuildRecordLen
	I2NPData                                     = i2np.Data
	I2NPDatabaseLookup                           = i2np.DatabaseLookup
	I2NPDatabaseSearchReply                      = i2np.DatabaseSearchReply
	I2NPDatabaseStore                            = i2np.DatabaseStore
	I2NPDeliveryStatus                           = i2np.DeliveryStatus
	I2NPFixedBuildRecords                        = i2np.FixedBuildRecords
	I2NPGarlic                                   = i2np.Garlic
	I2NPI2PDMaxFrame                             = i2np.I2PDMaxFrame
	I2NPI2PDMaxPayload                           = i2np.I2PDMaxPayload
	I2NPI2PDMessageBufferBytes                   = i2np.I2PDMessageBufferBytes
	I2NPI2PDReservedPrefix                       = i2np.I2PDReservedPrefix
	I2NPLegacyShortHeaderLen                     = i2np.LegacyShortHeaderLen
	I2NPMaxDatabaseLookupExcluded                = i2np.MaxDatabaseLookupExcluded
	I2NPMaxDatabaseLookupPayload                 = i2np.MaxDatabaseLookupPayload
	I2NPMaxDatabaseReplyTags                     = i2np.MaxDatabaseReplyTags
	I2NPMaxDatabaseSearchPeers                   = i2np.MaxDatabaseSearchPeers
	I2NPMaxDatabaseSearchReplyPayload            = i2np.MaxDatabaseSearchReplyPayload
	I2NPMaxRouterInfoBytes                       = i2np.MaxRouterInfoBytes
	I2NPMaxTunnelGatewayEmbedded                 = i2np.MaxTunnelGatewayEmbedded
	I2NPMaxVariableBuildRecords                  = i2np.MaxVariableBuildRecords
	I2NPMaxWireFrame                             = i2np.MaxWireFrame
	I2NPMaxWirePayload                           = i2np.MaxWirePayload
	I2NPOutboundTunnelBuildReply                 = i2np.OutboundTunnelBuildReply
	I2NPShortBuildRecordLen                      = i2np.ShortBuildRecordLen
	I2NPShortTunnelBuild                         = i2np.ShortTunnelBuild
	I2NPStandardHeaderLen                        = i2np.StandardHeaderLen
	I2NPStoreEncryptedLeaseSet                   = i2np.StoreEncryptedLeaseSet
	I2NPStoreLeaseSet                            = i2np.StoreLeaseSet
	I2NPStoreLeaseSet2                           = i2np.StoreLeaseSet2
	I2NPStoreMetaLeaseSet                        = i2np.StoreMetaLeaseSet
	I2NPStoreRouterInfo                          = i2np.StoreRouterInfo
	I2NPTransportHeaderLen                       = i2np.TransportHeaderLen
	I2NPTunnelBuild                              = i2np.TunnelBuild
	I2NPTunnelBuildReply                         = i2np.TunnelBuildReply
	I2NPTunnelData                               = i2np.TunnelData
	I2NPTunnelDataMessageLen                     = i2np.TunnelDataMessageLen
	I2NPTunnelDataPayloadLen                     = i2np.TunnelDataPayloadLen
	I2NPTunnelGateway                            = i2np.TunnelGateway
	I2NPTunnelGatewayHeaderLen                   = i2np.TunnelGatewayHeaderLen
	I2NPTunnelTest                               = i2np.TunnelTest
	I2NPVariableTunnelBuild                      = i2np.VariableTunnelBuild
	I2NPVariableTunnelBuildReply                 = i2np.VariableTunnelBuildReply
	NetworkDatabaseLeaseSetOfflineFlag           = netdb.LeaseSetOfflineFlag
	NetworkDatabaseMaxEncryptedLeaseSetDataBytes = netdb.MaxEncryptedLeaseSetDataBytes
	NetworkDatabaseMaxLeaseSet2Keys              = netdb.MaxLeaseSet2Keys
	NetworkDatabaseMaxLeaseSetBytes              = netdb.MaxLeaseSetBytes
	NetworkDatabaseMaxLeases                     = netdb.MaxLeases
	NetworkDatabaseMaxMetaLeases                 = netdb.MaxMetaLeases
	NetworkDatabaseMaxRevocations                = netdb.MaxRevocations
	NetworkDatabaseMaxRouterAddresses            = netdb.MaxRouterAddresses
	NetworkDatabaseMaxRouterInfoBytes            = netdb.MaxRouterInfoBytes
	NetworkDatabaseMaxRouterPeers                = netdb.MaxRouterPeers
	NetworkDatabaseMinEncryptedLeaseSetDataBytes = netdb.MinEncryptedLeaseSetDataBytes
)

var (
	I2NPErrChecksum         = i2np.ErrChecksum
	I2NPErrInvalidTunnelID  = i2np.ErrInvalidTunnelID
	I2NPErrMalformed        = i2np.ErrMalformed
	I2NPErrPayloadTooLarge  = i2np.ErrPayloadTooLarge
	I2NPErrUnknownStoreType = i2np.ErrUnknownStoreType

	NetworkDatabaseErrELSExpired               = netdb.ErrELSExpired
	NetworkDatabaseErrInvalidDatabaseStore     = netdb.ErrInvalidDatabaseStore
	NetworkDatabaseErrInvalidKeyLength         = netdb.ErrInvalidKeyLength
	NetworkDatabaseErrMalformed                = netdb.ErrMalformed
	NetworkDatabaseErrNoSupportedEncryptionKey = netdb.ErrNoSupportedEncryptionKey
	NetworkDatabaseErrStructureTooLarge        = netdb.ErrStructureTooLarge
	NetworkDatabaseErrTooManyItems             = netdb.ErrTooManyItems
)

func I2NPDecodeTransportExpiration(seconds uint32) uint64 {
	return i2np.DecodeTransportExpiration(seconds)
}

func I2NPEncodeTransportExpiration(milliseconds uint64) (uint32, bool) {
	return i2np.EncodeTransportExpiration(milliseconds)
}

func I2NPParse(src []byte) (I2NPMessage, int, error) {
	return i2np.Parse(src)
}

func I2NPParseBuildRecords(kind I2NPMessageType, payload []byte) (I2NPBuildRecords, error) {
	return i2np.ParseBuildRecords(kind, payload)
}

func I2NPParseData(payload []byte) (I2NPDataMessage, error) {
	return i2np.ParseData(payload)
}

func I2NPParseDatabaseLookup(payload []byte) (I2NPDatabaseLookupMessage, error) {
	return i2np.ParseDatabaseLookup(payload)
}

func I2NPParseDatabaseSearchReply(payload []byte) (I2NPDatabaseSearchReplyMessage, error) {
	return i2np.ParseDatabaseSearchReply(payload)
}

func I2NPParseDatabaseStore(payload []byte) (I2NPDatabaseStoreMessage, error) {
	return i2np.ParseDatabaseStore(payload)
}

func I2NPParseDeliveryStatus(payload []byte) (I2NPDeliveryStatusMessage, error) {
	return i2np.ParseDeliveryStatus(payload)
}

func I2NPParseGarlic(payload []byte) (I2NPGarlicMessage, error) {
	return i2np.ParseGarlic(payload)
}

func I2NPParseLegacyShortHeader(src []byte) (I2NPShortHeader, error) {
	return i2np.ParseLegacyShortHeader(src)
}

func I2NPParseTransportHeader(src []byte) (I2NPTransportHeader, error) {
	return i2np.ParseTransportHeader(src)
}

func I2NPParseTunnelData(payload []byte) (I2NPTunnelDataMessage, error) {
	return i2np.ParseTunnelData(payload)
}

func I2NPParseTunnelGateway(payload []byte) (I2NPTunnelGatewayMessage, error) {
	return i2np.ParseTunnelGateway(payload)
}

func I2NPParseTunnelTest(payload []byte) (I2NPDeliveryStatusMessage, error) {
	return i2np.ParseTunnelTest(payload)
}

func I2NPParseUnchecked(src []byte) (I2NPMessage, int, error) {
	return i2np.ParseUnchecked(src)
}

func I2NPParseWire(src []byte) (I2NPMessage, int, error) {
	return i2np.ParseWire(src)
}

func I2NPValidatePayload(kind I2NPMessageType, payload []byte) error {
	return i2np.ValidatePayload(kind, payload)
}

func NetworkDatabaseCompressRouterInfo(raw []byte) ([]byte, error) {
	return netdb.CompressRouterInfo(raw)
}

func NetworkDatabaseIsFloodfill(r NetworkDatabaseRouterInfo) bool {
	return netdb.IsFloodfill(r)
}

func NetworkDatabaseMarshalDatabaseStore(key Hash, typeID I2NPStoreType, data []byte, token uint32, gateway Hash, tunnelID uint32) ([]byte, error) {
	return netdb.MarshalDatabaseStore(key, typeID, data, token, gateway, tunnelID)
}

func NetworkDatabaseParseEncryptedLeaseSet(src []byte) (NetworkDatabaseEncryptedLeaseSet, error) {
	return netdb.ParseEncryptedLeaseSet(src)
}

func NetworkDatabaseParseLeaseSet(src []byte) (NetworkDatabaseLeaseSet, error) {
	return netdb.ParseLeaseSet(src)
}

func NetworkDatabaseParseLeaseSet2(src []byte) (NetworkDatabaseLeaseSet2, error) {
	return netdb.ParseLeaseSet2(src)
}

func NetworkDatabaseParseMetaLeaseSet(src []byte) (NetworkDatabaseMetaLeaseSet, error) {
	return netdb.ParseMetaLeaseSet(src)
}

func NetworkDatabaseParseRouterAddress(src []byte) (NetworkDatabaseRouterAddress, int, error) {
	return netdb.ParseRouterAddress(src)
}

func NetworkDatabaseParseRouterInfo(src []byte) (NetworkDatabaseRouterInfo, error) {
	return netdb.ParseRouterInfo(src)
}
