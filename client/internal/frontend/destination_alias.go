package frontend

import "gosuda.org/ivnp/interfaces/destination"

type (
	DestinationResolver           = destination.DestinationResolver
	LeaseSetPolicy                = destination.LeaseSetPolicy
	DestinationSpec               = destination.DestinationSpec
	DestinationRoute              = destination.DestinationRoute
	Delivery                      = destination.Delivery
	ReceivedMessage               = destination.ReceivedMessage
	ByteBudget                    = destination.ByteBudget
	MessageSubscription           = destination.MessageSubscription
	DestinationEndpoint           = destination.DestinationEndpoint
	SourcePortDestinationEndpoint = destination.SourcePortDestinationEndpoint
	BoundedDestinationEndpoint    = destination.BoundedDestinationEndpoint
	ReadyDestinationEndpoint      = destination.ReadyDestinationEndpoint
	DestinationController         = destination.DestinationController
)

func NewReceivedMessage(delivery destination.Delivery, release func(int)) *ReceivedMessage {
	return destination.NewReceivedMessage(delivery, release)
}
