package main

import "bytes"
import "crypto/sha256"
import "encoding/binary"
import "flag"
import "fmt"
import "io"
import "os"

var passwordFile *os.File

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

func main(){
    flag.Parse()
    fileName := flag.Args()[0]
    password := flag.Args()[1]
    openPasswordFile(fileName)
    passwordSafe3Header := readChunk(4)

    fmt.Printf("header = %s\n", string(passwordSafe3Header))
    salt := readChunk(32)
    iterBytes := readChunk(4)
    iter := int(binary.LittleEndian.Uint32(iterBytes))

    storedPassword := readChunk(32)
    stretched := sha256.Sum256(append([]byte(password), salt[:]...))
    for i:= 0; i <= iter ;  i++ {
        stretched = sha256.Sum256(stretched[:])
    }
    if !bytes.Equal(storedPassword, stretched[:]) {
        fmt.Println("Passwords do not match")
        os.Exit(1)
    }
//}
