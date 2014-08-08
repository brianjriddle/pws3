package main

import "encoding/binary"
import "fmt"

type Header struct {
    Version int
    UUID string
    NonDefaultPreference string
}

func (header *Header) mapField(field *Field) {
    header.Version = 0
    if (field.raw_type == 0x01){
        header.Version = int(binary.LittleEndian.Uint16(field.raw_value[0:4]))
    }
    if (field.raw_type == 0x01) {
        header.UUID = fmt.Sprintf("%x-%x-%x-%x-%x", field.raw_value[0:4], field.raw_value[4:6], field.raw_value[6:8], field.raw_value[8:10], field.raw_value[10:])
    }
    if (field.raw_type == 0x02){
        header.NonDefaultPreference = string(field.raw_value[:field.raw_length]) 
    }
}

func(header *Header)dumpHeader(){
    fmt.Printf("version = %x\n", header.Version)
    fmt.Printf("uuid = %s\n", header.UUID)
    fmt.Printf("non default preference = %s\n", header.NonDefaultPreference)
}


