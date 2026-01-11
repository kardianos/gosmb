package smbsys

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func makeAttribute(attrType uint16, data []byte) []byte {
	buf := new(bytes.Buffer)
	attrLen := 4 + len(data)
	binary.Write(buf, binary.LittleEndian, uint16(attrLen))
	binary.Write(buf, binary.LittleEndian, attrType)
	buf.Write(data)

	// Pad to 4 bytes
	pad := (4 - (len(data) % 4)) % 4
	buf.Write(make([]byte, pad))

	return buf.Bytes()
}
func getAttributes(data []byte) (map[uint16][]byte, error) {
	attrs := make(map[uint16][]byte)
	for len(data) >= 4 {
		length := binary.LittleEndian.Uint16(data[0:2])
		attrType := binary.LittleEndian.Uint16(data[2:4])
		if int(length) > len(data) || length < 4 {
			return attrs, fmt.Errorf("getAttributes: break due to len mismatch or too short")
		}
		attrs[attrType] = data[4:length]

		// Advance to next 4-byte boundary
		paddedLen := (int(length) + 3) &^ 3
		if paddedLen > len(data) {
			break
		}
		data = data[paddedLen:]
	}
	return attrs, nil
}
