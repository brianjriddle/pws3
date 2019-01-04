package main

import "bytes"
import "golang.org/x/crypto/twofish"
import "crypto/cipher"
import "crypto/sha256"
import "encoding/binary"
import "errors"
import "fmt"
import "io"
import "os"

type Vault struct {
    PasswordFile *os.File
    Password string
    Salt []byte
    Iter int
    Header Header
    Records []Record
}

func (vault *Vault) readChunk(size int) (chunk []byte){
    chunk = make([]byte, size)
    bytesRead, err := vault.PasswordFile.Read(chunk)    
    if err != nil && err != io.EOF {
        panic(err)
    }
    if bytesRead == 0 {
        //no bytes read 
    }
    return 
}

func (vault *Vault) stretchPassword(password string) []byte {
    stretched := sha256.Sum256(append([]byte(password), vault.Salt[:]...))
    for i:= 0; i < vault.Iter ;  i++ {
        stretched = sha256.Sum256(stretched[:])
    }
    return stretched[:] 
}
func (vault *Vault) verifyTag(){
    passwordSafe3Tag := vault.readChunk(4)
    if (string(passwordSafe3Tag) != "PWS3") {
        fmt.Printf("%s is not a password safe version 3 file.", vault.PasswordFile.Name())
        os.Exit(1)
    }
}

func OpenVault(fileName, password string) *Vault {
    var err error
    vault := Vault{}
    passwordFile, err := os.Open(fileName)
    if err != nil {
        panic(err)
    }
    vault.PasswordFile = passwordFile
    vault.verifyTag()
    vault.Salt = vault.readChunk(32)
    vault.Iter = int(binary.LittleEndian.Uint32(vault.readChunk(4)))

    storedPassword := vault.readChunk(32)
    stretchedPassword := vault.stretchPassword(password)

    shaps := sha256.Sum256(stretchedPassword[:])
    if !bytes.Equal(storedPassword, shaps[:]) {
        fmt.Println("Passwords do not match")
        os.Exit(1)
    }
    b1 := vault.readChunk(16)
    b2 := vault.readChunk(16)
    b3 := vault.readChunk(16)
    b4 := vault.readChunk(16)

    block, err := twofish.NewCipher(stretchedPassword)
    if err != nil {
        panic(err) 
    }

    block.Decrypt(b1,b1)
    block.Decrypt(b2,b2)
    block.Decrypt(b3,b3)
    block.Decrypt(b4,b4)
    keyk := append(b1, b2...)
    //keyl := append(b3, b4...)
    iv := vault.readChunk(16)

    block, err = twofish.NewCipher(keyk)
    if err != nil {
        panic(err) 
    }
    mode := cipher.NewCBCDecrypter(block, iv)
    vault.Header = Header{}
    for {
        field, _ := vault.readFieldInfo(mode)
        if field != nil {
            vault.Header.mapField(field) 
        }
        if (field.raw_type == 0xff){
            break
        }
    }

    current_record := Record{}
    for{
        field, _ := vault.readFieldInfo(mode)
        if field == nil {
            break
        }
        current_record.mapField(field)
        if (field.raw_type == 0xff){
            vault.Records = append(vault.Records, current_record)
            current_record = Record{}
        }
    }
    return &vault
}

func (vault *Vault) readFieldInfo(mode cipher.BlockMode) (*Field, error) {
    data := vault.readChunk(16); 

    if len(data) < 16 {
        return nil, errors.New("EOF encountered when parsing record field")
    }

    if string(data) == "PWS3-EOFPWS3-EOF" {
        return nil, nil
    }

    mode.CryptBlocks(data, data)
    raw_length := int(binary.LittleEndian.Uint32(data[0:4]))
    raw_type := data[4]
    raw_value := data[5:]
    if (raw_length > 11){
        for i := 0; i < ((raw_length + 4)/16); i++{
            data = vault.readChunk(16)
            if len(data) < 16 {
                return nil, errors.New("EOF encountered when parsing record field")
            }
            mode.CryptBlocks(data,data)
            raw_value = append(raw_value, data...)
        }
        raw_value = raw_value[:raw_length]
    }
    return &Field{raw_length, raw_type, raw_value[:raw_length]}, nil
}

func (vault *Vault) DumpVault() {
    fmt.Printf("version = %x\n", vault.Header.Version)
    fmt.Printf("uuid = %s\n", vault.Header.UUID)
    fmt.Printf("non default preference = %s\n", vault.Header.NonDefaultPreference)
    fmt.Printf("password file = %s\n", vault.PasswordFile.Name())
    fmt.Printf("salt = %x\n", vault.Salt)
    fmt.Printf("iter = %d\n", vault.Iter)
    fmt.Printf("number of records = %d\n", len(vault.Records))
}
