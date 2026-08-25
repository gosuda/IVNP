// Package state is the only public entry point for IVNP configuration and durable state.
package state

import (
	configurationinternal "gosuda.org/ivnp/state/internal/configuration"
	filesystemstoreinternal "gosuda.org/ivnp/state/internal/filesystem_store"
	securestateinternal "gosuda.org/ivnp/state/internal/secure_store"
)

type (
	ConfigurationAddressBook              = configurationinternal.AddressBook
	ConfigurationEndpoint                 = configurationinternal.Endpoint
	ConfigurationListener                 = configurationinternal.Listener
	ConfigurationLog                      = configurationinternal.Log
	ConfigurationNetDB                    = configurationinternal.NetDB
	ConfigurationNetwork                  = configurationinternal.Network
	ConfigurationOperating                = configurationinternal.Operating
	ConfigurationReseed                   = configurationinternal.Reseed
	ConfigurationRouter                   = configurationinternal.Router
	ConfigurationState                    = configurationinternal.State
	ConfigurationTransport                = configurationinternal.Transport
	ConfigurationTunnel                   = configurationinternal.Tunnel
	SecureStateBundle                     = securestateinternal.Bundle
	SecureStateEncryptedLeaseSetPolicy    = securestateinternal.EncryptedLeaseSetPolicy
	SecureStateLock                       = securestateinternal.Lock
	SecureStateRemoteELSAuthorization     = securestateinternal.RemoteELSAuthorization
	SecureStateRemoteELSAuthorizationKind = securestateinternal.RemoteELSAuthorizationKind
	SecureStateStore                      = securestateinternal.Store
)

const (
	SecureStateRemoteELSAuthorizationDH   = securestateinternal.RemoteELSAuthorizationDH
	SecureStateRemoteELSAuthorizationNone = securestateinternal.RemoteELSAuthorizationNone
	SecureStateRemoteELSAuthorizationPSK  = securestateinternal.RemoteELSAuthorizationPSK
)

var (
	ConfigurationErrInvalidOperating   = configurationinternal.ErrInvalidOperating
	ConfigurationLoadOperating         = configurationinternal.LoadOperating
	ConfigurationLoadOrCreateOperating = configurationinternal.LoadOrCreateOperating
	ConfigurationParseOperating        = configurationinternal.ParseOperating
	FilesystemStoreOpenRegular         = filesystemstoreinternal.OpenRegular
	FilesystemStoreReadBoundedFile     = filesystemstoreinternal.ReadBoundedFile
	FilesystemStoreWriteAtomic         = filesystemstoreinternal.WriteAtomic
	SecureStateErrStateLocked          = securestateinternal.ErrStateLocked
	SecureStateNewStore                = securestateinternal.NewStore
)
