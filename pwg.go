package main

import "crypto/sha256"
import "flag"
import "fmt"
import "os"

func main(){
    flag.Parse()
    fileName := flag.Args()[0]
    password := flag.Args()[1]
    passwordFile, err := os.Open(fileName)
    if err != nil {
        panic(err)
    }
    passwordSafe3Header := make([]byte, 4)
    bytesRead, err := passwordFile.Read(passwordSafe3Header)    
    fmt.Printf("%d bytes: '%s'\n", bytesRead, string(passwordSafe3Header))
    salt := make([]byte, 32)
    bytesRead, err = passwordFile.Read(salt)    
    fmt.Printf("%d bytes\n", bytesRead)
    iter := make([]byte, 4)
    bytesRead, err = passwordFile.Read(iter)
    fmt.Printf("%x \n", iter)

    storedPassword := make([]byte, 32)
    bytesRead, err = passwordFile.Read(storedPassword)    
    fmt.Printf("%d bytes\n", bytesRead)
    fmt.Printf("%x \n", storedPassword)
    hash := sha256.New()
    stretched := sha256.Sum256([]byte(password))
    fmt.Printf("%x\n", hash.Sum([]byte(password)))
    for i:= 0; i < 524288 ;  i++ {
        stretched = sha256.Sum256(stretched)
    }
    fmt.Printf("%x\n", hash.Sum([]byte(password)))
}
