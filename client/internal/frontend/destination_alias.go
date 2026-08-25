package clientapi

import destinationapi "gosuda.org/ivnp/contracts/destination"

type (
	DestinationResolver           = destinationapi.DestinationResolver
	LeaseSetPolicy                = destinationapi.LeaseSetPolicy
	DestinationSpec               = destinationapi.DestinationSpec
	DestinationRoute              = destinationapi.DestinationRoute
	Delivery                      = destinationapi.Delivery
	ReceivedMessage               = destinationapi.ReceivedMessage
	ByteBudget                    = destinationapi.ByteBudget
	MessageSubscription           = destinationapi.MessageSubscription
	DestinationEndpoint           = destinationapi.DestinationEndpoint
	SourcePortDestinationEndpoint = destinationapi.SourcePortDestinationEndpoint
	BoundedDestinationEndpoint    = destinationapi.BoundedDestinationEndpoint
	ReadyDestinationEndpoint      = destinationapi.ReadyDestinationEndpoint
	DestinationController         = destinationapi.DestinationController
)

func NewReceivedMessage(delivery destinationapi.Delivery, release func(int)) *ReceivedMessage {
	return destinationapi.NewReceivedMessage(delivery, release)
}
