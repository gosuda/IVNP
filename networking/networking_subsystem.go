// Package networking is the only public entry point for IVNP networking implementations.
package networking

import (
	"gosuda.org/ivnp/networking/internal/datagram"
	"gosuda.org/ivnp/networking/internal/garlic"
	garlicecies "gosuda.org/ivnp/networking/internal/garlic/ecies"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/nat/natpmp"
	"gosuda.org/ivnp/networking/internal/nat/upnp"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/reseed"
	"gosuda.org/ivnp/networking/internal/router"
	"gosuda.org/ivnp/networking/internal/streaming"
	streamingtunnel "gosuda.org/ivnp/networking/internal/streaming/tunnel"
	"gosuda.org/ivnp/networking/internal/tunnel"
)

type (
	GarlicDatabaseLookupReplyWrapper                   = garlic.DatabaseLookupReplyWrapper
	GarlicRatchetConfig                                = garlic.RatchetConfig
	GarlicRatchetManager                               = garlic.RatchetManager
	GarlicReplyKey                                     = garlic.GarlicReplyKey
	GarlicReplyKeyRegistry                             = garlic.ReplyKeyRegistry
	GarlicReplyKeyRegistryContract                     = garlic.GarlicReplyKeyRegistry
	GarlicSessionManager                               = garlic.SessionManager
	I2NPDataMessage                                    = i2np.DataMessage
	I2NPDatabaseLookupMessage                          = i2np.DatabaseLookupMessage
	I2NPDatabaseSearchReplyMessage                     = i2np.DatabaseSearchReplyMessage
	I2NPDatabaseStoreMessage                           = i2np.DatabaseStoreMessage
	I2NPDeliveryStatusMessage                          = i2np.DeliveryStatusMessage
	I2NPGarlicMessage                                  = i2np.GarlicMessage
	I2NPHeader                                         = i2np.Header
	I2NPMessage                                        = i2np.Message
	I2NPMessageType                                    = i2np.MessageType
	I2NPShortHeader                                    = i2np.ShortHeader
	I2NPStoreType                                      = i2np.StoreType
	I2NPTransportHeader                                = i2np.TransportHeader
	I2NPTunnelDataMessage                              = i2np.TunnelDataMessage
	I2NPTunnelGatewayMessage                           = i2np.TunnelGatewayMessage
	NetworkAddressTranslationPortMappingMapping        = natpmp.Mapping
	NetworkAddressTranslationPortMappingMappingRequest = natpmp.MappingRequest
	NetworkAddressTranslationPortMappingPublicAddress  = natpmp.PublicAddress
	NetworkDatabase                                    = netdb.Database
	NetworkDatabaseConfirmedPublisher                  = netdb.ConfirmedPublisher
	NetworkDatabaseELSClientAuthorization              = netdb.ELSClientAuthorization
	NetworkDatabaseEncryptedLeaseSet                   = netdb.EncryptedLeaseSet
	NetworkDatabaseEncryptedLeaseSetAuthorization      = netdb.EncryptedLeaseSetAuthorization
	NetworkDatabaseExplorer                            = netdb.Explorer
	NetworkDatabaseExplorerConfig                      = netdb.ExplorerConfig
	NetworkDatabaseLease                               = netdb.Lease
	NetworkDatabaseLeaseSet                            = netdb.LeaseSet
	NetworkDatabaseLeaseSet2                           = netdb.LeaseSet2
	NetworkDatabaseLeaseSetPublisherConfig             = netdb.LeaseSetPublisherConfig
	NetworkDatabaseLocalEncryptedLeaseSet              = netdb.LocalEncryptedLeaseSet
	NetworkDatabaseLookupResponderConfig               = netdb.LookupResponderConfig
	NetworkDatabaseLookupResponder                     = netdb.LookupResponder
	NetworkDatabaseLookupResult                        = netdb.LookupResult
	NetworkDatabaseMetaLeaseSet                        = netdb.MetaLeaseSet
	NetworkDatabasePublicationTokenRegistry            = netdb.PublicationTokenRegistry
	NetworkDatabaseRequestManager                      = netdb.RequestManager
	NetworkDatabaseRequestManagerConfig                = netdb.RequestManagerConfig
	NetworkDatabaseResponderProfiles                   = netdb.ResponderProfiles
	NetworkDatabaseRouterAddress                       = netdb.RouterAddress
	NetworkDatabaseRouterInfo                          = netdb.RouterInfo
	NetworkDatabaseRouterInfoPublisherConfig           = netdb.RouterInfoPublisherConfig
	NetworkDatabaseRouterInfoStore                     = netdb.RouterInfoStore
	NetworkDatabaseRouterInfoStoreConfig               = netdb.RouterInfoStoreConfig
	NetworkDatabaseStoreFlooder                        = netdb.StoreFlooder
	NetworkDatabaseStoreFlooderConfig                  = netdb.StoreFlooderConfig
	NetworkDatabaseRouterRef                           = netdb.RouterRef
	ReseedClient                                       = reseed.Client
	Router                                             = router.Router
	RouterAddressPublisher                             = router.AddressPublisher
	RouterAddressPublisherCloser                       = router.AddressPublisherCloser
	RouterBuildReplySender                             = router.BuildReplySender
	RouterBuildReplySenderConfig                       = router.BuildReplySenderConfig
	RouterClock                                        = router.Clock
	RouterConfig                                       = router.Config
	RouterDeliveryStatusHandler                        = router.DeliveryStatusHandler
	RouterDeliveryStatusMux                            = router.DeliveryStatusMux
	RouterDependencies                                 = router.Dependencies
	RouterDestinationBandwidthConfig                   = router.DestinationBandwidthConfig
	RouterDestinationBandwidthLimiter                  = router.DestinationBandwidthLimiter
	RouterDestinationBandwidthSnapshot                 = router.DestinationBandwidthSnapshot
	RouterDestinationManager                           = router.DestinationManager
	RouterDestinationSession                           = router.DestinationSession
	RouterDestinationSessionConfig                     = router.DestinationSessionConfig
	RouterEndpoint                                     = router.Endpoint
	RouterGarlicDestination                            = router.GarlicDestination
	RouterGarlicReceiver                               = router.GarlicReceiver
	RouterGarlicReceiverConfig                         = router.GarlicReceiverConfig
	RouterLocalRouterInfo                              = router.LocalRouterInfo
	RouterLocalRouterInfoConfig                        = router.LocalRouterInfoConfig
	RouterMappingOption                                = router.MappingOption
	RouterNTCP2ManagerConfig                           = router.NTCP2ManagerConfig
	RouterNativeSocketRuntime                          = router.NativeSocketRuntime
	RouterNetDBRequestHandler                          = router.NetDBRequestHandler
	RouterPublicationMaintenance                       = router.PublicationMaintenance
	RouterPublicationMaintenanceConfig                 = router.PublicationMaintenanceConfig
	RouterPublishedAddress                             = router.PublishedAddress
	RouterReachability                                 = router.Reachability
	RouterRemoteELSContext                             = router.RemoteELSContext
	RouterReseedRunner                                 = router.ReseedRunner
	RouterSSU2ManagerConfig                            = router.SSU2ManagerConfig
	RouterService                                      = router.Service
	RouterSocketAddressPublisher                       = router.SocketAddressPublisher
	RouterSocketRuntime                                = router.SocketRuntime
	RouterState                                        = router.State
	RouterStatus                                       = router.Status
	RouterStreamingTunnelSender                        = router.StreamingTunnelSender
	RouterStreamingTunnelSenderConfig                  = router.StreamingTunnelSenderConfig
	RouterTransportBindings                            = router.TransportBindings
	RouterTransportManager                             = router.TransportManager
	RouterTransportMuxConfig                           = router.TransportMuxConfig
	RouterTransportStatus                              = router.TransportStatus
	RouterTunnelBuildReplyHandler                      = router.TunnelBuildReplyHandler
	RouterWallClock                                    = router.WallClock
	StreamingTunnelDelivery                            = streamingtunnel.Delivery
	StreamingTunnelTunnelNetworkConfig                 = streamingtunnel.TunnelNetworkConfig
	TunnelBlock                                        = tunnel.Block
	TunnelBuildManager                                 = tunnel.BuildManager
	TunnelBuildManagerConfig                           = tunnel.BuildManagerConfig
	TunnelBuildReservations                            = tunnel.BuildReservations
	TunnelBuildStaticKeyLookup                         = tunnel.BuildStaticKeyLookup
	TunnelCircuitPair                                  = tunnel.CircuitPair
	TunnelDirection                                    = tunnel.Direction
	TunnelEntry                                        = tunnel.Entry
	TunnelGarlicReplyKey                               = tunnel.GarlicReplyKey
	TunnelHealth                                       = tunnel.Health
	TunnelHealthConfig                                 = tunnel.HealthConfig
	TunnelNetDBInboundBuildSourceConfig                = tunnel.NetDBInboundBuildSourceConfig
	TunnelNetDBOutboundBuildSourceConfig               = tunnel.NetDBOutboundBuildSourceConfig
	TunnelPairedPoolMaintainer                         = tunnel.PairedPoolMaintainer
	TunnelPairedPoolMaintainerConfig                   = tunnel.PairedPoolMaintainerConfig
	TunnelPeerProfiles                                 = tunnel.PeerProfiles
	TunnelPeerProfilesConfig                           = tunnel.PeerProfilesConfig
	TunnelPool                                         = tunnel.Pool
	TunnelReplyRouterInfoSeeder                        = tunnel.ReplyRouterInfoSeeder
	TunnelRuntime                                      = tunnel.Runtime
	TunnelRuntimeConfig                                = tunnel.RuntimeConfig
	TunnelSender                                       = tunnel.Sender
	TunnelShortBuildRequest                            = tunnel.ShortBuildRequest
	UniversalPlugAndPlayClient                         = upnp.Client
	UniversalPlugAndPlayDiscoveryResponse              = upnp.DiscoveryResponse
	UniversalPlugAndPlayGateway                        = upnp.Gateway
	UniversalPlugAndPlayPortMapping                    = upnp.PortMapping
)

const (
	DatagramProtocolDatagram1                       = datagram.ProtocolDatagram1
	DatagramProtocolRaw                             = datagram.ProtocolRaw
	I2NPDatabaseLookup                              = i2np.DatabaseLookup
	I2NPDatabaseStore                               = i2np.DatabaseStore
	I2NPDeliveryStatus                              = i2np.DeliveryStatus
	I2NPGarlic                                      = i2np.Garlic
	I2NPShortTunnelBuild                            = i2np.ShortTunnelBuild
	I2NPStoreEncryptedLeaseSet                      = i2np.StoreEncryptedLeaseSet
	I2NPStoreLeaseSet2                              = i2np.StoreLeaseSet2
	I2NPStoreRouterInfo                             = i2np.StoreRouterInfo
	I2NPTunnelGateway                               = i2np.TunnelGateway
	I2NPTunnelGatewayHeaderLen                      = i2np.TunnelGatewayHeaderLen
	NetworkAddressTranslationPortMappingDefaultPort = natpmp.DefaultPort
	NetworkAddressTranslationPortMappingTCP         = natpmp.TCP
	NetworkAddressTranslationPortMappingUDP         = natpmp.UDP
	NetworkDatabaseDefaultBucketCapacity            = netdb.DefaultBucketCapacity
	NetworkDatabaseLeaseSetLookup                   = netdb.LeaseSetLookup
	NetworkDatabaseMaxLeaseSetBytes                 = netdb.MaxLeaseSetBytes
	NetworkDatabasePublicationFloodfillK            = netdb.PublicationFloodfillK
	NetworkDatabaseReseedRouterInfoMaxAgeMillis     = netdb.ReseedRouterInfoMaxAgeMillis
	RouterReachabilityFirewalled                    = router.ReachabilityFirewalled
	RouterReachabilityReachable                     = router.ReachabilityReachable
	RouterStateFailed                               = router.StateFailed
	RouterStateNew                                  = router.StateNew
	RouterStateRunning                              = router.StateRunning
	RouterStateStarting                             = router.StateStarting
	RouterStateStopped                              = router.StateStopped
	RouterStateStopping                             = router.StateStopping
	TunnelDeliveryRouter                            = tunnel.DeliveryRouter
	TunnelDeliveryTunnel                            = tunnel.DeliveryTunnel
	TunnelInbound                                   = tunnel.Inbound
	TunnelOutbound                                  = tunnel.Outbound
)

var (
	DatagramMarshalV1To                           = datagram.MarshalV1To
	DatagramParsePacket                           = datagram.ParsePacket
	GarlicECIESOpenRouterMessage                  = garlicecies.OpenRouterMessage
	GarlicECIESSealRouterMessage                  = garlicecies.SealRouterMessage
	GarlicNewRatchetManager                       = garlic.NewRatchetManager
	GarlicNewReplyKeyRegistry                     = garlic.NewReplyKeyRegistry
	I2NPParse                                     = i2np.Parse
	I2NPParseBuildRecords                         = i2np.ParseBuildRecords
	I2NPParseData                                 = i2np.ParseData
	I2NPParseDatabaseLookup                       = i2np.ParseDatabaseLookup
	I2NPParseDatabaseStore                        = i2np.ParseDatabaseStore
	I2NPParseGarlic                               = i2np.ParseGarlic
	I2NPParseTunnelData                           = i2np.ParseTunnelData
	I2NPParseTunnelGateway                        = i2np.ParseTunnelGateway
	I2NPParseWire                                 = i2np.ParseWire
	NetworkAddressTranslationPortMappingNewClient = natpmp.NewClient
	NetworkDatabaseBuildDatabaseLookup            = netdb.BuildDatabaseLookup
	NetworkDatabaseCompressRouterInfo             = netdb.CompressRouterInfo
	NetworkDatabaseErrNoFloodfill                 = netdb.ErrNoFloodfill
	NetworkDatabaseErrRequestManagerClosed        = netdb.ErrRequestManagerClosed
	NetworkDatabaseIsFloodfill                    = netdb.IsFloodfill
	NetworkDatabaseLoadStaticRouterInfos          = netdb.LoadStaticRouterInfos
	NetworkDatabaseMarshalDatabaseStore           = netdb.MarshalDatabaseStore
	NetworkDatabaseNewDatabase                    = netdb.NewDatabase
	NetworkDatabaseNewExplorer                    = netdb.NewExplorer
	NetworkDatabaseNewLeaseSetPublisher           = netdb.NewLeaseSetPublisher
	NetworkDatabaseNewLocalEncryptedLeaseSet      = netdb.NewLocalEncryptedLeaseSet
	NetworkDatabaseNewLocalLeaseSet2WithTypes     = netdb.NewLocalLeaseSet2WithTypes
	NetworkDatabaseNewLookupResponder             = netdb.NewLookupResponder
	NetworkDatabaseNewPublicationTokenRegistry    = netdb.NewPublicationTokenRegistry
	NetworkDatabaseNewRequestManager              = netdb.NewRequestManager
	NetworkDatabaseNewResponderProfiles           = netdb.NewResponderProfiles
	NetworkDatabaseNewRouterInfoPublisher         = netdb.NewRouterInfoPublisher
	NetworkDatabaseNewRouterInfoStore             = netdb.NewRouterInfoStore
	NetworkDatabaseNewStoreFlooder                = netdb.NewStoreFlooder
	NetworkDatabaseParseEncryptedLeaseSet         = netdb.ParseEncryptedLeaseSet
	NetworkDatabaseParseLeaseSet                  = netdb.ParseLeaseSet
	NetworkDatabaseParseLeaseSet2                 = netdb.ParseLeaseSet2
	NetworkDatabaseParseMetaLeaseSet              = netdb.ParseMetaLeaseSet
	NetworkDatabaseParseRouterAddress             = netdb.ParseRouterAddress
	NetworkDatabaseParseRouterInfo                = netdb.ParseRouterInfo
	ReseedDefaultSU3SignersAt                     = reseed.DefaultSU3SignersAt
	RouterErrDataPlaneConfig                      = router.ErrDataPlaneConfig
	RouterErrDefaultDestination                   = router.ErrDefaultDestination
	RouterErrDestinationNotFound                  = router.ErrDestinationNotFound
	RouterErrUnhandledI2NP                        = router.ErrUnhandledI2NP
	RouterErrTransportUnavailable                 = router.ErrTransportUnavailable
	RouterIsRetryableTransportError               = router.IsRetryableTransportError
	RouterNew                                     = router.New
	RouterNewBuildReplySender                     = router.NewBuildReplySender
	RouterNewDeliveryStatusMux                    = router.NewDeliveryStatusMux
	RouterNewDestinationBandwidthLimiter          = router.NewDestinationBandwidthLimiter
	RouterNewDestinationManager                   = router.NewDestinationManager
	RouterNewGarlicReceiver                       = router.NewGarlicReceiver
	RouterNewLocalRouterInfo                      = router.NewLocalRouterInfo
	RouterNewNTCP2Manager                         = router.NewNTCP2Manager
	RouterNewPublicationMaintenance               = router.NewPublicationMaintenance
	RouterNewSSU2Manager                          = router.NewSSU2Manager
	RouterNewService                              = router.NewService
	RouterNewStreamingTunnelSender                = router.NewStreamingTunnelSender
	RouterNewTransportMux                         = router.NewTransportMux
	RouterValidateRemoteELSContexts               = router.ValidateRemoteELSContexts
	StreamingProtocolNewConn                      = streaming.NewConn
	StreamingProtocolNewState                     = streaming.NewState
	TunnelErrBuildPending                         = tunnel.ErrBuildPending
	TunnelErrCircuitNotFound                      = tunnel.ErrCircuitNotFound
	TunnelErrHealthClosed                         = tunnel.ErrHealthClosed
	TunnelErrNoEligiblePeers                      = tunnel.ErrNoEligiblePeers
	TunnelErrPairedMaintenanceClosed              = tunnel.ErrPairedMaintenanceClosed
	TunnelErrProbeNotReady                        = tunnel.ErrProbeNotReady
	TunnelErrProbePending                         = tunnel.ErrProbePending
	TunnelNewBuildManager                         = tunnel.NewBuildManager
	TunnelNewBuildReservations                    = tunnel.NewBuildReservations
	TunnelNewHealth                               = tunnel.NewHealth
	TunnelNewNetDBBuildStaticKeyLookup            = tunnel.NewNetDBBuildStaticKeyLookup
	TunnelNewNetDBInboundBuildSource              = tunnel.NewNetDBInboundBuildSource
	TunnelNewNetDBOutboundBuildSource             = tunnel.NewNetDBOutboundBuildSource
	TunnelNewOwnedPool                            = tunnel.NewOwnedPool
	TunnelNewPairedPoolMaintainer                 = tunnel.NewPairedPoolMaintainer
	TunnelNewPeerProfiles                         = tunnel.NewPeerProfiles
	TunnelNewPool                                 = tunnel.NewPool
	TunnelNewRuntime                              = tunnel.NewRuntime
)
