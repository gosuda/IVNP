// Package state is the only public entry point for IVNP configuration and durable state.
package state

import (
	"gosuda.org/ivnp/state/internal/configuration"
	filesystemstore "gosuda.org/ivnp/state/internal/filesystem_store"
	securestore "gosuda.org/ivnp/state/internal/secure_store"
)

type (
	ConfigurationAddressBook              = configuration.AddressBook
	ConfigurationEndpoint                 = configuration.Endpoint
	ConfigurationListener                 = configuration.Listener
	ConfigurationHTTPProxy                = configuration.HTTPProxy
	ConfigurationLog                      = configuration.Log
	ConfigurationNetDB                    = configuration.NetDB
	ConfigurationNetwork                  = configuration.Network
	ConfigurationOperating                = configuration.Operating
	ConfigurationReseed                   = configuration.Reseed
	ConfigurationRouter                   = configuration.Router
	ConfigurationState                    = configuration.State
	ConfigurationTransport                = configuration.Transport
	ConfigurationTunnel                   = configuration.Tunnel
	SecureStateBundle                     = securestore.Bundle
	SecureStateEncryptedLeaseSetPolicy    = securestore.EncryptedLeaseSetPolicy
	SecureStateLock                       = securestore.Lock
	SecureStateRemoteELSAuthorization     = securestore.RemoteELSAuthorization
	SecureStateRemoteELSAuthorizationKind = securestore.RemoteELSAuthorizationKind
	SecureStateStore                      = securestore.Store
)

const (
	SecureStateRemoteELSAuthorizationDH   = securestore.RemoteELSAuthorizationDH
	SecureStateRemoteELSAuthorizationNone = securestore.RemoteELSAuthorizationNone
	SecureStateRemoteELSAuthorizationPSK  = securestore.RemoteELSAuthorizationPSK
)

var (
	ConfigurationErrInvalidOperating   = configuration.ErrInvalidOperating
	ConfigurationLoadOperating         = configuration.LoadOperating
	ConfigurationLoadOrCreateOperating = configuration.LoadOrCreateOperating
	ConfigurationParseOperating        = configuration.ParseOperating
	FilesystemStoreOpenRegular         = filesystemstore.OpenRegular
	FilesystemStoreReadBoundedFile     = filesystemstore.ReadBoundedFile
	FilesystemStoreWriteAtomic         = filesystemstore.WriteAtomic
	SecureStateErrStateLocked          = securestore.ErrStateLocked
	SecureStateNewStore                = securestore.NewStore
)
