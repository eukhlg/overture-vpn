/* SPDX-License-Identifier: MIT
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Adapted from wireguard-go b3bc704ef0ee: split in reverse so input can
 * alias output buffer zero, preserving headers until all later segments exist.
 */

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"unsafe"
)

const (
	ipv4SrcAddrOffset      = 12
	ipv6SrcAddrOffset      = 8
	tcpFlagFIN        byte = 1
	tcpFlagPSH        byte = 8
	tcpFlagsOffset         = 13
)

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

const (
	// virtioNetHdrLen is the length in bytes of virtioNetHdr. This matches the
	// shape of the C ABI for its kernel counterpart -- sizeof(virtio_net_hdr).
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
)

func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return 0, err
	}
	in = in[virtioNetHdrLen:]
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// This means CHECKSUM_PARTIAL in skb context. We are responsible
			// for computing the checksum starting at hdr.csumStart and placing
			// at hdr.csumOffset.
			err = gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset)
			if err != nil {
				return 0, err
			}
		}
		if len(in) > len(bufs[0][offset:]) {
			return 0, fmt.Errorf("read len %d overflows bufs element len %d", len(in), len(bufs[0][offset:]))
		}
		sizes[0] = len(in)
		return 1, nil
	}
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}

	if len(in) == 0 || hdr.gsoSize == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		if len(in) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	if len(in) < int(hdr.hdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}

	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	cSumAt := int(hdr.csumStart + hdr.csumOffset)
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	return gsoSplit(in, hdr, bufs, sizes, offset, ipVersion == 6)
}

func gsoSplit(in []byte, hdr virtioNetHdr, outBuffs [][]byte, sizes []int, outOffset int, isV6 bool) (int, error) {
	iphLen := int(hdr.csumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if !isV6 {
		in[10], in[11] = 0, 0 // clear ipv4 header checksum
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	transportCsumAt := int(hdr.csumStart + hdr.csumOffset)
	in[transportCsumAt], in[transportCsumAt+1] = 0, 0 // clear tcp/udp checksum
	var firstTCPSeqNum uint32
	var protocol uint8
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 || hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		protocol = unix.IPPROTO_TCP
		firstTCPSeqNum = binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	} else {
		protocol = unix.IPPROTO_UDP
	}
	count := (len(in) - int(hdr.hdrLen) + int(hdr.gsoSize) - 1) / int(hdr.gsoSize)
	if count > len(outBuffs) || count > len(sizes) {
		return 0, errors.New("tun: too many GSO segments")
	}
	for i := 0; i < count; i++ {
		if outOffset < 0 || outOffset+int(hdr.hdrLen)+int(hdr.gsoSize) > len(outBuffs[i]) {
			return 0, io.ErrShortBuffer
		}
	}
	for i := count - 1; i >= 0; i-- {
		nextSegmentDataAt := int(hdr.hdrLen) + i*int(hdr.gsoSize)
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(hdr.hdrLen) + segmentDataLen
		sizes[i] = totalLen
		out := outBuffs[i][outOffset:]

		copy(out, in[:iphLen])
		if !isV6 {
			// For IPv4 we are responsible for incrementing the ID field,
			// updating the total len field, and recalculating the header
			// checksum.
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// For IPv6 we are responsible for updating the payload length field.
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		// copy transport header
		copy(out[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])

		if protocol == unix.IPPROTO_TCP {
			// set TCP seq and adjust TCP flags
			tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(out[hdr.csumStart+4:], tcpSeq)
			if nextSegmentEnd != len(in) {
				// FIN and PSH should only be set on last segment
				clearFlags := tcpFlagFIN | tcpFlagPSH
				out[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
			}
		} else {
			// set UDP header len
			binary.BigEndian.PutUint16(out[hdr.csumStart+4:], uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart))
		}

		// payload
		copy(out[hdr.hdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		// transport checksum
		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportCSumNoFold := pseudoHeaderChecksumNoFold(protocol, in[srcAddrOffset:srcAddrOffset+addrLen], in[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2], lenForPseudo)
		transportCSum := ^checksum(out[hdr.csumStart:totalLen], transportCSumNoFold)
		binary.BigEndian.PutUint16(out[hdr.csumStart+hdr.csumOffset:], transportCSum)

	}
	return count, nil
}

func gsoNoneChecksum(in []byte, cSumStart, cSumOffset uint16) error {
	cSumAt := int(cSumStart) + int(cSumOffset)
	if int(cSumStart) > len(in) || cSumAt+2 > len(in) {
		return io.ErrUnexpectedEOF
	}
	// The initial value at the checksum offset should be summed with the
	// checksum we compute. This is typically the pseudo-header checksum.
	initial := binary.BigEndian.Uint16(in[cSumAt:])
	in[cSumAt], in[cSumAt+1] = 0, 0
	binary.BigEndian.PutUint16(in[cSumAt:], ^checksum(in[cSumStart:], uint64(initial)))
	return nil
}
