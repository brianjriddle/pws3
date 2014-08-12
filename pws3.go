package main

import "crypto/md5"
import "flag"
import "fmt"
import "github.com/brianjriddle/pws3/gpgagent"
import "log"
import "os"
import "path/filepath"

/**
* Inspired from https://metacpan.org/source/TLINDEN/Crypt-PWSafe3-1.14/lib/Crypt/PWSafe3.pm
* ,http://sourceforge.net/p/passwordsafe/code/HEAD/tree/trunk/pwsafe/pwsafe/docs/formatV3.txt,
* https://github.com/sommer/loxodo
*/

func makeCacheId(fileName string) string {
    fullpath, _ := filepath.Abs(fileName)
    cacheid := fmt.Sprintf("%x", md5.Sum([]byte(fullpath)))
    return cacheid
}

func main() {
    forget := flag.Bool("forget", false, "Forgets the password for given file")
    flag.Parse()
    if (len(flag.Args()) == 0 ) {
        flag.Usage()
        log.Fatal("No file given")
    }
    fileName := flag.Args()[0]
    if(*forget == true){
        gpgagent.ClearPassphrase(makeCacheId(fileName))
        os.Exit(0)
    }
    password := gpgagent.GetPassphrase(makeCacheId(fileName), "X", "X", "X")
    v := OpenVault(fileName, password)
    v.DumpVault()
}
