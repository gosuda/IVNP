package garlic

// ReceiveExisting consumes the leading one-use SessionTag from packet, looks
// up its session key, and decrypts the following AES block into dst.
func ReceiveExisting(dst, packet []byte, tags *TagStore, now uint64) (payload, deliveredTags []byte, err error) {
	if tags == nil || len(packet) < 32 {
		return nil, nil, ErrSession
	}
	key, ok := tags.Take(packet[:32], now)
	if !ok {
		return nil, nil, ErrSession
	}
	return DecryptExisting(dst, packet[:32], key[:], packet[32:])
}
