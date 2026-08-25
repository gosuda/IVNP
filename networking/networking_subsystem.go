// Package networking is the only public entry point for IVNP networking implementations.
package networking

import (
	datagraminternal "gosuda.org/ivnp/networking/internal/datagram"
	garlicinternal "gosuda.org/ivnp/networking/internal/garlic"
	garliceciesinternal "gosuda.org/ivnp/networking/internal/garlic/ecies"
	i2npinternal "gosuda.org/ivnp/networking/internal/i2np"
	natpmpinternal "gosuda.org/ivnp/networking/internal/network_address_translation/natpmp"
	upnpinternal "gosuda.org/ivnp/networking/internal/network_address_translation/upnp"
	networkdatabaseinternal "gosuda.org/ivnp/networking/internal/network_database"
	reseedinternal "gosuda.org/ivnp/networking/internal/reseed"
	routerinternal "gosuda.org/ivnp/networking/internal/router"
	streaminginternal "gosuda.org/ivnp/networking/internal/streaming"
	streamingtunnelinternal "gosuda.org/ivnp/networking/internal/streaming/tunnel"
	tunnelinternal "gosuda.org/ivnp/networking/internal/tunnel"
)

type (
	GarlicDatabaseLookupReplyWrapper                   = garlicinternal.DatabaseLookupReplyWrapper
	GarlicRatchetConfig                                = garlicinternal.RatchetConfig
	GarlicRatchetManager                               = garlicinternal.RatchetManager
	GarlicReplyKey                                     = garlicinternal.GarlicReplyKey
	GarlicReplyKeyRegistry                             = garlicinternal.ReplyKeyRegistry
	GarlicReplyKeyRegistryContract                     = garlicinternal.GarlicReplyKeyRegistry
	GarlicSessionManager                               = garlicinternal.SessionManager
	I2NPDataMessage                                    = i2npinternal.DataMessage
	I2NPDatabaseLookupMessage                          = i2npinternal.DatabaseLookupMessage
	I2NPDatabaseSearchReplyMessage                     = i2npinternal.DatabaseSearchReplyMessage
	I2NPDatabaseStoreMessage                           = i2npinternal.DatabaseStoreMessage
	I2NPDeliveryStatusMessage                          = i2npinternal.DeliveryStatusMessage
	I2NPGarlicMessage                                  = i2npinternal.GarlicMessage
	I2NPHeader                                         = i2npinternal.Header
	I2NPMessage                                        = i2npinternal.Message
	I2NPMessageType                                    = i2npinternal.MessageType
	I2NPShortHeader                                    = i2npinternal.ShortHeader
	I2NPStoreType                                      = i2npinternal.StoreType
	I2NPTransportHeader                                = i2npinternal.TransportHeader
	I2NPTunnelDataMessage                              = i2npinternal.TunnelDataMessage
	I2NPTunnelGatewayMessage                           = i2npinternal.TunnelGatewayMessage
	NetworkAddressTranslationPortMappingMapping        = natpmpinternal.Mapping
	NetworkAddressTranslationPortMappingMappingRequest = natpmpinternal.MappingRequest
	NetworkAddressTranslationPortMappingPublicAddress  = natpmpinternal.PublicAddress
	NetworkDatabase                                    = networkdatabaseinternal.Database
	NetworkDatabaseConfirmedPublisher                  = networkdatabaseinternal.ConfirmedPublisher
	NetworkDatabaseELSClientAuthorization              = networkdatabaseinternal.ELSClientAuthorization
	NetworkDatabaseEncryptedLeaseSet                   = networkdatabaseinternal.EncryptedLeaseSet
	NetworkDatabaseEncryptedLeaseSetAuthorization      = networkdatabaseinternal.EncryptedLeaseSetAuthorization
	NetworkDatabaseExplorer                            = networkdatabaseinternal.Explorer
	NetworkDatabaseExplorerConfig                      = networkdatabaseinternal.ExplorerConfig
	NetworkDatabaseLease                               = networkdatabaseinternal.Lease
	NetworkDatabaseLeaseSet                            = networkdatabaseinternal.LeaseSet
	NetworkDatabaseLeaseSet2                           = networkdatabaseinternal.LeaseSet2
	NetworkDatabaseLeaseSetPublisherConfig             = networkdatabaseinternal.LeaseSetPublisherConfig
	NetworkDatabaseLocalEncryptedLeaseSet              = networkdatabaseinternal.LocalEncryptedLeaseSet
	NetworkDatabaseLookupResponderConfig               = networkdatabaseinternal.LookupResponderConfig
	NetworkDatabaseLookupResult                        = networkdatabaseinternal.LookupResult
	NetworkDatabaseMetaLeaseSet                        = networkdatabaseinternal.MetaLeaseSet
	NetworkDatabasePublicationTokenRegistry            = networkdatabaseinternal.PublicationTokenRegistry
	NetworkDatabaseRequestManager                      = networkdatabaseinternal.RequestManager
	NetworkDatabaseRequestManagerConfig                = networkdatabaseinternal.RequestManagerConfig
	NetworkDatabaseResponderProfiles                   = networkdatabaseinternal.ResponderProfiles
	NetworkDatabaseRouterAddress                       = networkdatabaseinternal.RouterAddress
	NetworkDatabaseRouterInfo                          = networkdatabaseinternal.RouterInfo
	NetworkDatabaseRouterInfoPublisherConfig           = networkdatabaseinternal.RouterInfoPublisherConfig
	NetworkDatabaseRouterInfoStore                     = networkdatabaseinternal.RouterInfoStore
	NetworkDatabaseRouterInfoStoreConfig               = networkdatabaseinternal.RouterInfoStoreConfig
	NetworkDatabaseRouterRef                           = networkdatabaseinternal.RouterRef
	ReseedClient                                       = reseedinternal.Client
	Router                                             = routerinternal.Router
	RouterAddressPublisher                             = routerinternal.AddressPublisher
	RouterAddressPublisherCloser                       = routerinternal.AddressPublisherCloser
	RouterBuildReplySender                             = routerinternal.BuildReplySender
	RouterBuildReplySenderConfig                       = routerinternal.BuildReplySenderConfig
	RouterClock                                        = routerinternal.Clock
	RouterConfig                                       = routerinternal.Config
	RouterDeliveryStatusHandler                        = routerinternal.DeliveryStatusHandler
	RouterDeliveryStatusMux                            = routerinternal.DeliveryStatusMux
	RouterDependencies                                 = routerinternal.Dependencies
	RouterDestinationBandwidthConfig                   = routerinternal.DestinationBandwidthConfig
	RouterDestinationBandwidthLimiter                  = routerinternal.DestinationBandwidthLimiter
	RouterDestinationBandwidthSnapshot                 = routerinternal.DestinationBandwidthSnapshot
	RouterDestinationManager                           = routerinternal.DestinationManager
	RouterDestinationSession                           = routerinternal.DestinationSession
	RouterDestinationSessionConfig                     = routerinternal.DestinationSessionConfig
	RouterEndpoint                                     = routerinternal.Endpoint
	RouterGarlicDestination                            = routerinternal.GarlicDestination
	RouterGarlicReceiver                               = routerinternal.GarlicReceiver
	RouterGarlicReceiverConfig                         = routerinternal.GarlicReceiverConfig
	RouterLocalRouterInfo                              = routerinternal.LocalRouterInfo
	RouterLocalRouterInfoConfig                        = routerinternal.LocalRouterInfoConfig
	RouterMappingOption                                = routerinternal.MappingOption
	RouterNTCP2ManagerConfig                           = routerinternal.NTCP2ManagerConfig
	RouterNativeSocketRuntime                          = routerinternal.NativeSocketRuntime
	RouterNetDBRequestHandler                          = routerinternal.NetDBRequestHandler
	RouterPublicationMaintenance                       = routerinternal.PublicationMaintenance
	RouterPublicationMaintenanceConfig                 = routerinternal.PublicationMaintenanceConfig
	RouterPublishedAddress                             = routerinternal.PublishedAddress
	RouterReachability                                 = routerinternal.Reachability
	RouterRemoteELSContext                             = routerinternal.RemoteELSContext
	RouterReseedRunner                                 = routerinternal.ReseedRunner
	RouterSSU2ManagerConfig                            = routerinternal.SSU2ManagerConfig
	RouterService                                      = routerinternal.Service
	RouterSocketAddressPublisher                       = routerinternal.SocketAddressPublisher
	RouterSocketRuntime                                = routerinternal.SocketRuntime
	RouterState                                        = routerinternal.State
	RouterStatus                                       = routerinternal.Status
	RouterStreamingTunnelSender                        = routerinternal.StreamingTunnelSender
	RouterStreamingTunnelSenderConfig                  = routerinternal.StreamingTunnelSenderConfig
	RouterTransportBindings                            = routerinternal.TransportBindings
	RouterTransportManager                             = routerinternal.TransportManager
	RouterTransportMuxConfig                           = routerinternal.TransportMuxConfig
	RouterTransportStatus                              = routerinternal.TransportStatus
	RouterTunnelBuildReplyHandler                      = routerinternal.TunnelBuildReplyHandler
	RouterWallClock                                    = routerinternal.WallClock
	StreamingTunnelDelivery                            = streamingtunnelinternal.Delivery
	StreamingTunnelTunnelNetworkConfig                 = streamingtunnelinternal.TunnelNetworkConfig
	TunnelBlock                                        = tunnelinternal.Block
	TunnelBuildManager                                 = tunnelinternal.BuildManager
	TunnelBuildManagerConfig                           = tunnelinternal.BuildManagerConfig
	TunnelBuildStaticKeyLookup                         = tunnelinternal.BuildStaticKeyLookup
	TunnelCircuitPair                                  = tunnelinternal.CircuitPair
	TunnelDirection                                    = tunnelinternal.Direction
	TunnelEntry                                        = tunnelinternal.Entry
	TunnelGarlicReplyKey                               = tunnelinternal.GarlicReplyKey
	TunnelHealth                                       = tunnelinternal.Health
	TunnelHealthConfig                                 = tunnelinternal.HealthConfig
	TunnelNetDBInboundBuildSourceConfig                = tunnelinternal.NetDBInboundBuildSourceConfig
	TunnelNetDBOutboundBuildSourceConfig               = tunnelinternal.NetDBOutboundBuildSourceConfig
	TunnelPairedPoolMaintainer                         = tunnelinternal.PairedPoolMaintainer
	TunnelPairedPoolMaintainerConfig                   = tunnelinternal.PairedPoolMaintainerConfig
	TunnelPeerProfiles                                 = tunnelinternal.PeerProfiles
	TunnelPeerProfilesConfig                           = tunnelinternal.PeerProfilesConfig
	TunnelPool                                         = tunnelinternal.Pool
	TunnelReplyRouterInfoSeeder                        = tunnelinternal.ReplyRouterInfoSeeder
	TunnelRuntime                                      = tunnelinternal.Runtime
	TunnelRuntimeConfig                                = tunnelinternal.RuntimeConfig
	TunnelSender                                       = tunnelinternal.Sender
	TunnelShortBuildRequest                            = tunnelinternal.ShortBuildRequest
	UniversalPlugAndPlayClient                         = upnpinternal.Client
	UniversalPlugAndPlayDiscoveryResponse              = upnpinternal.DiscoveryResponse
	UniversalPlugAndPlayGateway                        = upnpinternal.Gateway
	UniversalPlugAndPlayPortMapping                    = upnpinternal.PortMapping
)

const (
	DatagramProtocolDatagram1                       = datagraminternal.ProtocolDatagram1
	DatagramProtocolRaw                             = datagraminternal.ProtocolRaw
	I2NPDatabaseLookup                              = i2npinternal.DatabaseLookup
	I2NPDatabaseStore                               = i2npinternal.DatabaseStore
	I2NPDeliveryStatus                              = i2npinternal.DeliveryStatus
	I2NPGarlic                                      = i2npinternal.Garlic
	I2NPShortTunnelBuild                            = i2npinternal.ShortTunnelBuild
	I2NPStoreEncryptedLeaseSet                      = i2npinternal.StoreEncryptedLeaseSet
	I2NPStoreLeaseSet2                              = i2npinternal.StoreLeaseSet2
	I2NPStoreRouterInfo                             = i2npinternal.StoreRouterInfo
	I2NPTunnelGateway                               = i2npinternal.TunnelGateway
	I2NPTunnelGatewayHeaderLen                      = i2npinternal.TunnelGatewayHeaderLen
	NetworkAddressTranslationPortMappingDefaultPort = natpmpinternal.DefaultPort
	NetworkAddressTranslationPortMappingTCP         = natpmpinternal.TCP
	NetworkAddressTranslationPortMappingUDP         = natpmpinternal.UDP
	NetworkDatabaseDefaultBucketCapacity            = networkdatabaseinternal.DefaultBucketCapacity
	NetworkDatabaseLeaseSetLookup                   = networkdatabaseinternal.LeaseSetLookup
	NetworkDatabaseMaxLeaseSetBytes                 = networkdatabaseinternal.MaxLeaseSetBytes
	NetworkDatabasePublicationFloodfillK            = networkdatabaseinternal.PublicationFloodfillK
	NetworkDatabaseReseedRouterInfoMaxAgeMillis     = networkdatabaseinternal.ReseedRouterInfoMaxAgeMillis
	RouterReachabilityFirewalled                    = routerinternal.ReachabilityFirewalled
	RouterReachabilityReachable                     = routerinternal.ReachabilityReachable
	RouterStateFailed                               = routerinternal.StateFailed
	RouterStateNew                                  = routerinternal.StateNew
	RouterStateRunning                              = routerinternal.StateRunning
	RouterStateStarting                             = routerinternal.StateStarting
	RouterStateStopped                              = routerinternal.StateStopped
	RouterStateStopping                             = routerinternal.StateStopping
	TunnelDeliveryRouter                            = tunnelinternal.DeliveryRouter
	TunnelDeliveryTunnel                            = tunnelinternal.DeliveryTunnel
	TunnelInbound                                   = tunnelinternal.Inbound
	TunnelOutbound                                  = tunnelinternal.Outbound
)

var (
	DatagramMarshalV1To                           = datagraminternal.MarshalV1To
	DatagramParsePacket                           = datagraminternal.ParsePacket
	GarlicECIESOpenRouterMessage                  = garliceciesinternal.OpenRouterMessage
	GarlicECIESSealRouterMessage                  = garliceciesinternal.SealRouterMessage
	GarlicNewRatchetManager                       = garlicinternal.NewRatchetManager
	GarlicNewReplyKeyRegistry                     = garlicinternal.NewReplyKeyRegistry
	I2NPParse                                     = i2npinternal.Parse
	I2NPParseBuildRecords                         = i2npinternal.ParseBuildRecords
	I2NPParseData                                 = i2npinternal.ParseData
	I2NPParseDatabaseLookup                       = i2npinternal.ParseDatabaseLookup
	I2NPParseDatabaseStore                        = i2npinternal.ParseDatabaseStore
	I2NPParseGarlic                               = i2npinternal.ParseGarlic
	I2NPParseTunnelData                           = i2npinternal.ParseTunnelData
	I2NPParseTunnelGateway                        = i2npinternal.ParseTunnelGateway
	I2NPParseWire                                 = i2npinternal.ParseWire
	NetworkAddressTranslationPortMappingNewClient = natpmpinternal.NewClient
	NetworkDatabaseBuildDatabaseLookup            = networkdatabaseinternal.BuildDatabaseLookup
	NetworkDatabaseCompressRouterInfo             = networkdatabaseinternal.CompressRouterInfo
	NetworkDatabaseErrNoFloodfill                 = networkdatabaseinternal.ErrNoFloodfill
	NetworkDatabaseErrRequestManagerClosed        = networkdatabaseinternal.ErrRequestManagerClosed
	NetworkDatabaseLoadStaticRouterInfos          = networkdatabaseinternal.LoadStaticRouterInfos
	NetworkDatabaseMarshalDatabaseStore           = networkdatabaseinternal.MarshalDatabaseStore
	NetworkDatabaseNewDatabase                    = networkdatabaseinternal.NewDatabase
	NetworkDatabaseNewExplorer                    = networkdatabaseinternal.NewExplorer
	NetworkDatabaseNewLeaseSetPublisher           = networkdatabaseinternal.NewLeaseSetPublisher
	NetworkDatabaseNewLocalEncryptedLeaseSet      = networkdatabaseinternal.NewLocalEncryptedLeaseSet
	NetworkDatabaseNewLocalLeaseSet2WithTypes     = networkdatabaseinternal.NewLocalLeaseSet2WithTypes
	NetworkDatabaseNewLookupResponder             = networkdatabaseinternal.NewLookupResponder
	NetworkDatabaseNewPublicationTokenRegistry    = networkdatabaseinternal.NewPublicationTokenRegistry
	NetworkDatabaseNewRequestManager              = networkdatabaseinternal.NewRequestManager
	NetworkDatabaseNewResponderProfiles           = networkdatabaseinternal.NewResponderProfiles
	NetworkDatabaseNewRouterInfoPublisher         = networkdatabaseinternal.NewRouterInfoPublisher
	NetworkDatabaseNewRouterInfoStore             = networkdatabaseinternal.NewRouterInfoStore
	NetworkDatabaseParseEncryptedLeaseSet         = networkdatabaseinternal.ParseEncryptedLeaseSet
	NetworkDatabaseParseLeaseSet                  = networkdatabaseinternal.ParseLeaseSet
	NetworkDatabaseParseLeaseSet2                 = networkdatabaseinternal.ParseLeaseSet2
	NetworkDatabaseParseMetaLeaseSet              = networkdatabaseinternal.ParseMetaLeaseSet
	NetworkDatabaseParseRouterAddress             = networkdatabaseinternal.ParseRouterAddress
	NetworkDatabaseParseRouterInfo                = networkdatabaseinternal.ParseRouterInfo
	ReseedDefaultSU3SignersAt                     = reseedinternal.DefaultSU3SignersAt
	RouterErrDataPlaneConfig                      = routerinternal.ErrDataPlaneConfig
	RouterErrDefaultDestination                   = routerinternal.ErrDefaultDestination
	RouterErrDestinationNotFound                  = routerinternal.ErrDestinationNotFound
	RouterErrTransportUnavailable                 = routerinternal.ErrTransportUnavailable
	RouterIsRetryableTransportError               = routerinternal.IsRetryableTransportError
	RouterNew                                     = routerinternal.New
	RouterNewBuildReplySender                     = routerinternal.NewBuildReplySender
	RouterNewDeliveryStatusMux                    = routerinternal.NewDeliveryStatusMux
	RouterNewDestinationBandwidthLimiter          = routerinternal.NewDestinationBandwidthLimiter
	RouterNewDestinationManager                   = routerinternal.NewDestinationManager
	RouterNewGarlicReceiver                       = routerinternal.NewGarlicReceiver
	RouterNewLocalRouterInfo                      = routerinternal.NewLocalRouterInfo
	RouterNewNTCP2Manager                         = routerinternal.NewNTCP2Manager
	RouterNewPublicationMaintenance               = routerinternal.NewPublicationMaintenance
	RouterNewSSU2Manager                          = routerinternal.NewSSU2Manager
	RouterNewService                              = routerinternal.NewService
	RouterNewStreamingTunnelSender                = routerinternal.NewStreamingTunnelSender
	RouterNewTransportMux                         = routerinternal.NewTransportMux
	RouterValidateRemoteELSContexts               = routerinternal.ValidateRemoteELSContexts
	StreamingProtocolNewConn                      = streaminginternal.NewConn
	StreamingProtocolNewState                     = streaminginternal.NewState
	TunnelErrBuildPending                         = tunnelinternal.ErrBuildPending
	TunnelErrCircuitNotFound                      = tunnelinternal.ErrCircuitNotFound
	TunnelErrHealthClosed                         = tunnelinternal.ErrHealthClosed
	TunnelErrNoEligiblePeers                      = tunnelinternal.ErrNoEligiblePeers
	TunnelErrPairedMaintenanceClosed              = tunnelinternal.ErrPairedMaintenanceClosed
	TunnelErrProbeNotReady                        = tunnelinternal.ErrProbeNotReady
	TunnelErrProbePending                         = tunnelinternal.ErrProbePending
	TunnelNewBuildManager                         = tunnelinternal.NewBuildManager
	TunnelNewHealth                               = tunnelinternal.NewHealth
	TunnelNewNetDBBuildStaticKeyLookup            = tunnelinternal.NewNetDBBuildStaticKeyLookup
	TunnelNewNetDBInboundBuildSource              = tunnelinternal.NewNetDBInboundBuildSource
	TunnelNewNetDBOutboundBuildSource             = tunnelinternal.NewNetDBOutboundBuildSource
	TunnelNewOwnedPool                            = tunnelinternal.NewOwnedPool
	TunnelNewPairedPoolMaintainer                 = tunnelinternal.NewPairedPoolMaintainer
	TunnelNewPeerProfiles                         = tunnelinternal.NewPeerProfiles
	TunnelNewPool                                 = tunnelinternal.NewPool
	TunnelNewRuntime                              = tunnelinternal.NewRuntime
)
