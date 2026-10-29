// Package concatkdf implements the single-step key derivation function of NIST SP
// 800-56A section 5.8.1 with SHA-256, as RFC 7518 section 4.6.2 uses it for
// ECDH-ES.
package concatkdf

import (
	"crypto/sha256"
	"encoding/binary"
)

// Derive returns keyDataLenBits bits derived from the shared secret z. The
// OtherInfo is AlgorithmID, PartyUInfo and PartyVInfo, each prefixed with its
// 32-bit big-endian length, then keyDataLenBits as SuppPubInfo, with an empty
// SuppPrivInfo, as RFC 7518 section 4.6.2 lays it out.
func Derive(z []byte, keyDataLenBits int, algorithmID, partyUInfo, partyVInfo []byte) []byte {
	info := otherInfo(keyDataLenBits, algorithmID, partyUInfo, partyVInfo)
	size := keyDataLenBits / 8
	out := make([]byte, 0, size+sha256.Size)
	counter := make([]byte, 4)
	for round := uint32(1); len(out) < size; round++ {
		binary.BigEndian.PutUint32(counter, round)
		h := sha256.New()
		h.Write(counter)
		h.Write(z)
		h.Write(info)
		out = h.Sum(out)
	}
	return out[:size]
}

func otherInfo(keyDataLenBits int, algorithmID, partyUInfo, partyVInfo []byte) []byte {
	var info []byte
	for _, field := range [][]byte{algorithmID, partyUInfo, partyVInfo} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	return binary.BigEndian.AppendUint32(info, uint32(keyDataLenBits))
}
