package main

import "fmt"

type Record struct {
    UUID,Group,Title,UserName,Notes,CreationTime,PasswordModificationTime,URL,Username,Password string
}
func (record *Record) mapField(field *Field) {
    if (field.raw_type == 0x01) {
        record.UUID = fmt.Sprintf("%x-%x-%x-%x-%x", field.raw_value[0:4], field.raw_value[4:6], field.raw_value[6:8], field.raw_value[8:10], field.raw_value[10:])
    }
    if (field.raw_type == 0x02) {
        record.Group = string(field.raw_value)
    }
    if (field.raw_type == 0x03) {
        record.Title = string(field.raw_value[:field.raw_length])
    }
    if (field.raw_type == 0x04) {
        fmt.Printf("-%s-\n", string(field.raw_value))
        record.UserName = string(field.raw_value)
    }
    if (field.raw_type == 0x05) {
        record.Notes = string(field.raw_value[:field.raw_length])
    }
    if (field.raw_type == 0x06) {
        record.Password = string(field.raw_value[:field.raw_length])
    }
    if (field.raw_type == 0x07) {
        record.CreationTime = string(field.raw_value[:field.raw_length])
    }
    if (field.raw_type == 0x08) {
        record.PasswordModificationTime = string(field.raw_value[:field.raw_length])
    }
}

func (record *Record) dumpRecord() {
    fmt.Printf("%s\n", record.Group)
    fmt.Printf("%s\n", record.Title)
    fmt.Printf("len(records) = %d\n", len(records))
    fmt.Printf("%s\n", record.UserName)
    fmt.Printf("%s\n", record.Notes)
    fmt.Printf("%s\n", record.Password)
    fmt.Printf("%s\n", record.CreationTime)
    fmt.Printf("%s\n", record.PasswordModificationTime)
}