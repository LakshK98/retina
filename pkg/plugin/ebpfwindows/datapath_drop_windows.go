// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ebpfwindows

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
)

const (
	DropNotifyVersion0 = iota
	DropNotifyVersion1
	DropNotifyVersion2
)

const (
	// dropNotifyV1Len is the amount of packet data provided in a v0/v1 drop notification.
	dropNotifyV1Len = 36
)

var dropNotifyLengthFromVersion = map[uint16]uint{
	DropNotifyVersion0: dropNotifyV1Len, // retain backwards compatibility for testing.
	DropNotifyVersion1: dropNotifyV1Len,
}

var (
	errUnexpectedDropNotifyLength = errors.New("unexpected DropNotify data length")
	errInvalidDropNotifyVersion   = errors.New("invalid DropNotify version")
)

// DropNotify is the message format of a drop notification in the BPF ring buffer
type DropNotify struct {
	Type     uint8
	SubType  uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint16
	Version  uint16
	SrcLabel identity.NumericIdentity
	DstLabel identity.NumericIdentity
	DstID    uint32
	Line     uint16
	File     uint8
	ExtError int8
	Ifindex  uint32
}

type PktmonDropNotify struct {
	Type     uint8
	Version  uint16
	SubType  uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint16
	SrcLabel identity.NumericIdentity
	DstLabel identity.NumericIdentity
	DstID    uint32
	Line     uint16
	File     uint8
	ExtError int8
	Ifindex  uint32
}

// DecodeDropNotify will decode 'data' into the provided DropNotify structure
func DecodePktmonDrop(data []byte, dn *DropNotify) error {
	pdn := &PktmonDropNotify{}
	if err := pdn.decodePktmonDrop(data); err != nil {
		return err
	}
	pdn.Type = 1
	dn.Type = pdn.Type
	dn.SubType = pdn.SubType
	dn.Source = pdn.Source
	dn.Hash = pdn.Hash
	dn.OrigLen = pdn.OrigLen
	dn.CapLen = pdn.CapLen
	dn.Version = pdn.Version
	dn.SrcLabel = pdn.SrcLabel
	dn.DstLabel = pdn.DstLabel
	dn.DstID = pdn.DstID
	dn.Line = pdn.Line
	dn.File = pdn.File
	dn.ExtError = pdn.ExtError
	dn.Ifindex = pdn.Ifindex
	return nil
}

func (n *PktmonDropNotify) decodePktmonDrop(data []byte) error {
	if l := len(data); l < dropNotifyV1Len {
		return fmt.Errorf("%w: expected at least %d but got %d", errUnexpectedDropNotifyLength, dropNotifyV1Len, l)
	}
	version := byteorder.Native.Uint16(data[1:3])

	// Check against max version.
	if version > DropNotifyVersion1 {
		return fmt.Errorf("%w: Unrecognized pktmon drop event version %d\nRaw data bytes: %v\nType: %d\nVersion (bytes 1-2): %v (uint16: %d)\nSubType: %d\nSource (bytes 4-5): %v (uint16: %d)\nHash (bytes 6-9): %v (uint32: %d)\nOrigLen (bytes 10-13): %v (uint32: %d)\nCapLen (bytes 14-15): %v (uint16: %d)\nSrcLabel (bytes 16-19): %v (uint32: %d)\nDstLabel (bytes 20-23): %v (uint32: %d)\nDstID (bytes 24-27): %v (uint32: %d)\nLine (bytes 28-29): %v (uint16: %d)\nFile (byte 30): %d\nExtError (byte 31): %d\nIfindex (bytes 32-35): %v (uint32: %d)",
			errInvalidDropNotifyVersion, version,
			data,
			data[0],
			data[1:3], version,
			data[4:6],
			data[6:8], byteorder.Native.Uint16(data[6:8]),
			data[8:12], byteorder.Native.Uint32(data[8:12]),
			data[12:16], byteorder.Native.Uint32(data[12:16]),
			data[16:18], byteorder.Native.Uint16(data[16:18]),
			data[18:22], byteorder.Native.Uint32(data[18:22]),
			data[22:26], byteorder.Native.Uint32(data[22:26]),
			data[24:28], byteorder.Native.Uint32(data[24:28]),
			data[28:30], byteorder.Native.Uint16(data[28:30]),
			data[30],
			int8(data[31]),
			data[32:36], byteorder.Native.Uint32(data[32:36]),
		)
	}

	// Decode logic for version >= v0/v1.
	n.Type = data[0]
	n.SubType = data[3]
	n.Source = byteorder.Native.Uint16(data[4:6])
	n.Hash = byteorder.Native.Uint32(data[6:10])
	n.OrigLen = byteorder.Native.Uint32(data[10:14])
	n.CapLen = byteorder.Native.Uint16(data[14:16])
	n.Version = version
	n.SrcLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[16:20]))
	n.DstLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[20:24]))
	n.DstID = byteorder.Native.Uint32(data[24:28])
	n.Line = byteorder.Native.Uint16(data[28:30])
	n.File = data[30]
	n.ExtError = int8(data[31])
	n.Ifindex = byteorder.Native.Uint32(data[32:36])

	return nil
}

// DecodeDropNotify will decode 'data' into the provided DropNotify structure
func DecodeDropNotify(data []byte, dn *DropNotify) error {
	return dn.decodeDropNotify(data)
}

func (n *DropNotify) decodeDropNotify(data []byte) error {
	if l := len(data); l < dropNotifyV1Len {
		return fmt.Errorf("%w: expected at least %d but got %d", errUnexpectedDropNotifyLength, dropNotifyV1Len, l)
	}

	version := byteorder.Native.Uint16(data[14:16])

	// Check against max version.
	if version > DropNotifyVersion1 {
		return fmt.Errorf("%w: Unrecognized drop event version %d", errInvalidDropNotifyVersion, version)
	}

	// Decode logic for version >= v0/v1.
	n.Type = data[0]
	n.SubType = data[1]
	n.Source = byteorder.Native.Uint16(data[2:4])
	n.Hash = byteorder.Native.Uint32(data[4:8])
	n.OrigLen = byteorder.Native.Uint32(data[8:12])
	n.CapLen = byteorder.Native.Uint16(data[12:14])
	n.Version = version
	n.SrcLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[16:20]))
	n.DstLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[20:24]))
	n.DstID = byteorder.Native.Uint32(data[24:28])
	n.Line = byteorder.Native.Uint16(data[28:30])
	n.File = data[30]
	n.ExtError = int8(data[31])
	n.Ifindex = byteorder.Native.Uint32(data[32:36])

	return nil
}

// IsL3Device returns true if the trace comes from an L3 device.
func (n *DropNotify) IsL3Device() bool {
	return false
}

// IsIPv6 returns true if the trace refers to an IPv6 packet.
func (n *DropNotify) IsIPv6() bool {
	return false
}

// DataOffset returns the offset from the beginning of DropNotify where the
// notification data begins.
//
// Returns zero for invalid or unknown DropNotify messages.
func (n *DropNotify) DataOffset() uint {
	return dropNotifyLengthFromVersion[n.Version]
}
