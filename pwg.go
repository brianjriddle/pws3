package main

import "bytes"
import "crypto/sha256"
import "encoding/binary"
import "flag"
import "fmt"
import "io"
import "os"

var passwordFile *os.File
var salt []byte
var iter int

func readChunk(size int) (chunk []byte){
    chunk = make([]byte, size)
    bytesRead, err := passwordFile.Read(chunk)    
    if err != nil && err != io.EOF {
        panic(err)
    }
    if bytesRead == 0 {
      //no bytes read 
    }
    return 
}

func openPasswordFile(fileName string){
    var err error
    passwordFile, err = os.Open(fileName)
    if err != nil {
        panic(err)
    }
}

func stretchPassword(password string) []byte {
    stretched := sha256.Sum256(append([]byte(password), salt[:]...))
    for i:= 0; i <= iter ;  i++ {
        stretched = sha256.Sum256(stretched[:])
    }
    return stretched[:] 
}

func verifyHeader(){
    passwordSafe3Header := readChunk(4)
    if (string(passwordSafe3Header) != "PWS3") {
        fmt.Printf("%s is not a password safe version 3 file.", passwordFile.Name())
        os.Exit(1)
    }
}

func main() {
    flag.Parse()
    fileName := flag.Args()[0]
    password := flag.Args()[1]
    openPasswordFile(fileName)
    verifyHeader()
    salt = readChunk(32)
    iter = int(binary.LittleEndian.Uint32(readChunk(4)))

    storedPassword := readChunk(32)
    stretchedPassword := stretchPassword(password)

    if !bytes.Equal(storedPassword, stretchedPassword) {
        fmt.Println("Passwords do not match")
        os.Exit(1)
    }
}
