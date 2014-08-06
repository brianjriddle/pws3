package main

import "bytes"
import "code.google.com/p/go.crypto/twofish"
import "crypto/cipher"
import "crypto/sha256"
import "encoding/binary"
import "flag"
import "fmt"
import "io"
import "os"

var passwordFile *os.File
var salt []byte
var iter int

/**
* Inspired from https://metacpan.org/source/TLINDEN/Crypt-PWSafe3-1.14/lib/Crypt/PWSafe3.pm
* ,http://sourceforge.net/p/passwordsafe/code/HEAD/tree/trunk/pwsafe/pwsafe/docs/formatV3.txt,
* https://github.com/sommer/loxodo
*/
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
    for i:= 0; i < iter ;  i++ {
        stretched = sha256.Sum256(stretched[:])
    }
    return stretched[:] 
}

func verifyTag(){
    passwordSafe3Tag := readChunk(4)
    if (string(passwordSafe3Tag) != "PWS3") {
        fmt.Printf("%s is not a password safe version 3 file.", passwordFile.Name())
        os.Exit(1)
    }
}

func main() {
    flag.Parse()
    fileName := flag.Args()[0]
    password := flag.Args()[1]
    openPasswordFile(fileName)
    verifyTag()
    salt = readChunk(32)
    iter = int(binary.LittleEndian.Uint32(readChunk(4)))

    storedPassword := readChunk(32)
    stretchedPassword := stretchPassword(password)

    shaps := sha256.Sum256(stretchedPassword[:])
    if !bytes.Equal(storedPassword, shaps[:]) {
        fmt.Println("Passwords do not match")
        os.Exit(1)
    }
    b1 := readChunk(16)
    b2 := readChunk(16)
    b3 := readChunk(16)
    b4 := readChunk(16)

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
    iv := readChunk(16)

    block, err = twofish.NewCipher(keyk)
    if err != nil {
        panic(err) 
    }
    mode := cipher.NewCBCDecrypter(block, iv)
    data := readChunk(16); 

    if len(data) < 16 {
        panic("EOF encountered when parsing record field")
    }

    if string(data) == "PWS3-EOFPWS3-EOF" {
        //return 0
    }

    mode.CryptBlocks(data, data)
    raw_length := binary.LittleEndian.Uint32(data[0:4])
    raw_type := data[4]
    raw_data := data[5:]
    fmt.Printf("%d\n", raw_length)
    fmt.Printf("%d\n", raw_type)
    fmt.Printf("%x\n", binary.LittleEndian.Uint16(raw_data[:raw_length]))
}
