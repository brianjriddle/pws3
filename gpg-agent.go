package main

import "bufio"
import "fmt"
import "log"
import "os/exec"
import "strings"

//Name of gpg-connect-agent

const GPG_AGENT_CONNECT = "gpg-connect-agent"

//Clears the password from gpg-agent for the given cacheid.
//Even if the 
func ClearPassphrase(cacheid string) bool {
    clearPassphrase := fmt.Sprintf("CLEAR_PASSPHRASE %s", cacheid)
    cmd := exec.Command(GPG_AGENT_CONNECT, clearPassphrase,  "/bye")
    out, err := cmd.StdoutPipe()
    if err != nil {
        log.Fatal(err)
    }
    rd := bufio.NewReader(out)
    err = cmd.Start()
    if err != nil {
        log.Fatal(err)
    }
    var success bool
    for {
        str, err := rd.ReadString('\n')
        if err != nil {
            fmt.Println("Read Error:", err)
            success = false
            break
        }
        if strings.HasPrefix(str, "OK"){
            success = true
            break 
        }
    }
    err = cmd.Wait()
    return success
}

//Uses gpg-agent-connect to get user password from a user.
//cacheid is a unique id that should be less than 50 bytes
//errorMessage is the message that will be shown as an error.
//prompt what should be shown for the password prompt
//description is the text shown above the entry field
//
//If an 'X' is given as the parameter for cacheid the cache is bypassed.
//
//If an 'X' is given as the parameter for errorMessage, prompt, description
//the default values for those are used.
func GetPassphrase(cacheid, errorMessage, prompt, description string)(password string){
    getPassPhraseCmd := fmt.Sprintf("GET_PASSPHRASE --data %s %s %s %s", cacheid, errorMessage, prompt, description)

    cmd := exec.Command(GPG_AGENT_CONNECT, getPassPhraseCmd, "/bye")
    out, err := cmd.StdoutPipe()
    rd := bufio.NewReader(out)
    if err != nil {
        log.Fatal(err)
    }
    err = cmd.Start()
    if err != nil {
        log.Fatal(err)
    }
    for {
        str, err := rd.ReadString('\n')
        if err != nil {
            fmt.Println("Read Error:", err)
            break
        }
        if strings.HasPrefix(str, "D "){
            password = strings.TrimSuffix(strings.TrimPrefix(str, "D "), "\n")
        } else if strings.HasPrefix(str, "OK"){
            break 
        } else if strings.HasPrefix(str, "OK"){
            continue
        }
    }
    err = cmd.Wait()
    return password
}
